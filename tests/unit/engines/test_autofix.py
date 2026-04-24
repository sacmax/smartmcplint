"""Unit tests for the Auto-Fix Engine.

Strategy:
- _build_prompt is a pure function — test directly, no mocking.
- generate() and _generate_fix() use AsyncMock to simulate LLM responses
  without a real API call.
- Patch at the import site: smartmcplint.engines.autofix.call_llm_judge
"""

from unittest.mock import AsyncMock, patch

import pytest

from smartmcplint.engines.autofix import AutoFixEngine
from smartmcplint.models.config import ScanConfig
from smartmcplint.models.enums import EngineType, FindingSeverity
from smartmcplint.models.findings import Finding

LLM_PATCH = "smartmcplint.engines.autofix.call_llm_judge"

VALID_LLM_RESULT = {
    "title": "Add a meaningful description to your tool",
    "description": "Tool descriptions tell AI agents when and how to use the tool.",
    "original": '"description": ""',
    "suggested": '"description": "Returns the current weather for a given city."',
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> AutoFixEngine:
    return AutoFixEngine(config=ScanConfig(transport="stdio"))


@pytest.fixture
def engine_skip_llm() -> AutoFixEngine:
    return AutoFixEngine(config=ScanConfig(transport="stdio", skip_llm=True))


def make_finding(
    rule_id: str = "QUAL-010",
    severity: FindingSeverity = FindingSeverity.WARNING,
    title: str = "Tool has no description",
    message: str = "Tool is missing a description.",
    tool_name: str | None = "get_weather",
    spec_ref: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        engine=EngineType.QUALITY,
        severity=severity,
        title=title,
        message=message,
        tool_name=tool_name,
        spec_ref=spec_ref,
    )


# ---------------------------------------------------------------------------
# generate() — top-level entry point
# ---------------------------------------------------------------------------

class TestGenerate:

    @pytest.mark.asyncio
    async def test_skip_llm_returns_empty(self, engine_skip_llm: AutoFixEngine) -> None:
        findings = [make_finding()]
        result = await engine_skip_llm.generate(findings)
        assert result == []

    @pytest.mark.asyncio
    async def test_no_findings_returns_empty(self, engine: AutoFixEngine) -> None:
        result = await engine.generate([])
        assert result == []

    @pytest.mark.asyncio
    async def test_info_findings_skipped(self, engine: AutoFixEngine) -> None:
        findings = [make_finding(severity=FindingSeverity.INFO)]
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            result = await engine.generate(findings)
        assert result == []
        mock_llm.assert_not_called()

    @pytest.mark.asyncio
    async def test_warning_finding_triggers_llm(self, engine: AutoFixEngine) -> None:
        findings = [make_finding(severity=FindingSeverity.WARNING)]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=VALID_LLM_RESULT):
            result = await engine.generate(findings)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_critical_finding_triggers_llm(self, engine: AutoFixEngine) -> None:
        findings = [make_finding(rule_id="CONF-001", severity=FindingSeverity.CRITICAL)]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=VALID_LLM_RESULT):
            result = await engine.generate(findings)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_same_rule_id_produces_one_suggestion(self, engine: AutoFixEngine) -> None:
        # Three tools all missing descriptions → same rule → one LLM call, one suggestion
        findings = [
            make_finding(rule_id="QUAL-010", tool_name="get_weather"),
            make_finding(rule_id="QUAL-010", tool_name="list_files"),
            make_finding(rule_id="QUAL-010", tool_name="search_records"),
        ]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=VALID_LLM_RESULT) as mock_llm:
            result = await engine.generate(findings)
        assert len(result) == 1
        mock_llm.assert_called_once()

    @pytest.mark.asyncio
    async def test_different_rule_ids_produce_separate_suggestions(
        self, engine: AutoFixEngine
    ) -> None:
        findings = [
            make_finding(rule_id="QUAL-010"),
            make_finding(rule_id="SEC-010", severity=FindingSeverity.CRITICAL, tool_name=None),
        ]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=VALID_LLM_RESULT) as mock_llm:
            result = await engine.generate(findings)
        assert len(result) == 2
        assert mock_llm.call_count == 2

    @pytest.mark.asyncio
    async def test_llm_failure_returns_no_suggestion_for_that_rule(
        self, engine: AutoFixEngine
    ) -> None:
        findings = [make_finding()]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=None):
            result = await engine.generate(findings)
        assert result == []

    @pytest.mark.asyncio
    async def test_suggestion_carries_correct_rule_id(self, engine: AutoFixEngine) -> None:
        findings = [make_finding(rule_id="SEC-020")]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=VALID_LLM_RESULT):
            result = await engine.generate(findings)
        assert result[0].finding_rule_id == "SEC-020"

    @pytest.mark.asyncio
    async def test_suggestion_engine_is_autofix(self, engine: AutoFixEngine) -> None:
        findings = [make_finding()]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=VALID_LLM_RESULT):
            result = await engine.generate(findings)
        assert result[0].engine == EngineType.AUTOFIX

    @pytest.mark.asyncio
    async def test_affected_tools_joined_in_tool_name(self, engine: AutoFixEngine) -> None:
        findings = [
            make_finding(rule_id="QUAL-010", tool_name="get_weather"),
            make_finding(rule_id="QUAL-010", tool_name="list_files"),
        ]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=VALID_LLM_RESULT):
            result = await engine.generate(findings)
        assert result[0].tool_name is not None
        assert "get_weather" in result[0].tool_name
        assert "list_files" in result[0].tool_name

    @pytest.mark.asyncio
    async def test_no_tool_name_findings_produce_none_tool_name(
        self, engine: AutoFixEngine
    ) -> None:
        findings = [make_finding(tool_name=None)]
        with patch(LLM_PATCH, new_callable=AsyncMock, return_value=VALID_LLM_RESULT):
            result = await engine.generate(findings)
        assert result[0].tool_name is None


# ---------------------------------------------------------------------------
# _build_prompt — pure function
# ---------------------------------------------------------------------------

class TestBuildPrompt:

    def test_contains_rule_id(self, engine: AutoFixEngine) -> None:
        finding = make_finding(rule_id="QUAL-013")
        prompt = engine._build_prompt("QUAL-013", finding, [])
        assert "QUAL-013" in prompt

    def test_contains_severity(self, engine: AutoFixEngine) -> None:
        finding = make_finding(severity=FindingSeverity.CRITICAL)
        prompt = engine._build_prompt("CONF-001", finding, [])
        assert "critical" in prompt.lower()

    def test_contains_title(self, engine: AutoFixEngine) -> None:
        finding = make_finding(title="Tool is missing a description")
        prompt = engine._build_prompt("QUAL-010", finding, [])
        assert "Tool is missing a description" in prompt

    def test_contains_message(self, engine: AutoFixEngine) -> None:
        finding = make_finding(message="Add a description that explains the tool purpose.")
        prompt = engine._build_prompt("QUAL-010", finding, [])
        assert "Add a description that explains the tool purpose." in prompt

    def test_spec_ref_included_when_present(self, engine: AutoFixEngine) -> None:
        finding = make_finding(spec_ref="MCP Spec §6.1 — Tool Definition")
        prompt = engine._build_prompt("QUAL-010", finding, [])
        assert "MCP Spec §6.1" in prompt

    def test_spec_ref_absent_when_none(self, engine: AutoFixEngine) -> None:
        finding = make_finding(spec_ref=None)
        prompt = engine._build_prompt("QUAL-010", finding, [])
        assert "Spec ref" not in prompt

    def test_affected_tools_listed(self, engine: AutoFixEngine) -> None:
        finding = make_finding()
        prompt = engine._build_prompt("QUAL-010", finding, ["get_weather", "list_files"])
        assert "get_weather" in prompt
        assert "list_files" in prompt

    def test_no_affected_tools_no_tools_line(self, engine: AutoFixEngine) -> None:
        finding = make_finding()
        prompt = engine._build_prompt("SEC-010", finding, [])
        assert "Affected tools" not in prompt
