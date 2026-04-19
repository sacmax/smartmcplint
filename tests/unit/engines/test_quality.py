"""Unit tests for the Quality Engine.

Strategy:
- Pure helpers (_normalize_words, _compute_word_overlap, _format_tool_for_prompt)
  tested directly — no mocking needed.
- Rule-based checks (_check_schema_completeness) are synchronous — tested with
  a mock client carrying preset tool lists.
- LLM checks (_check_tool_quality, _check_tool_disambiguation) use
  unittest.mock.patch to replace call_llm_judge at its import site in
  smartmcplint.engines.quality — not at its definition in utils.llm.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from smartmcplint.engines.quality import (
    MIN_DESCRIPTION_LENGTH,
    WORD_OVERLAP_THRESHOLD,
    QualityEngine,
)
from smartmcplint.models.config import ScanConfig
from smartmcplint.models.mcp import ToolInfo

# Patch target — always the import site, not the definition site
LLM_PATCH = "smartmcplint.engines.quality.call_llm_judge"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> QualityEngine:
    return QualityEngine(config=ScanConfig(transport="stdio"))


@pytest.fixture
def engine_skip_llm() -> QualityEngine:
    return QualityEngine(config=ScanConfig(transport="stdio", skip_llm=True))


def make_tool(
    name: str,
    description: str | None = "A well described tool.",
    properties: dict | None = None,
    required: list[str] | None = None,
) -> ToolInfo:
    schema: dict = {"type": "object", "properties": properties or {}}
    if required:
        schema["required"] = required
    return ToolInfo(name=name, description=description, input_schema=schema)


def make_client(tools: list[ToolInfo]) -> MagicMock:
    client = MagicMock()
    client.tools = tools
    return client


# All LLM criteria pass — nothing to flag
ALL_PASS_RESULT = {
    "when_to_use": True,
    "what_it_does": True,
    "side_effects_clear": True,
    "no_jargon": True,
    "params_clear": True,
    "return_documented": True,
    "explanation": "No issues",
}


# ---------------------------------------------------------------------------
# _normalize_words
# ---------------------------------------------------------------------------

class TestNormalizeWords:

    def test_synonym_canonicalization(self, engine: QualityEngine) -> None:
        # "delete" should map to "remove" via ACTION_SYNONYMS
        result = engine._normalize_words("delete user")
        assert "remove" in result
        assert "delete" not in result

    def test_lowercases_all_words(self, engine: QualityEngine) -> None:
        result = engine._normalize_words("GET Weather")
        assert "weather" in result
        # "get" maps to "fetch"
        assert "fetch" in result

    def test_strips_punctuation(self, engine: QualityEngine) -> None:
        result = engine._normalize_words("hello, world!")
        assert "hello" in result
        assert "world" in result

    def test_empty_string_returns_empty_set(self, engine: QualityEngine) -> None:
        assert engine._normalize_words("") == set()

    def test_unknown_words_pass_through_unchanged(self, engine: QualityEngine) -> None:
        result = engine._normalize_words("temperature forecast")
        assert "temperature" in result
        assert "forecast" in result


# ---------------------------------------------------------------------------
# _compute_word_overlap
# ---------------------------------------------------------------------------

class TestComputeWordOverlap:

    def test_identical_texts_return_1(self, engine: QualityEngine) -> None:
        assert engine._compute_word_overlap("get weather", "get weather") == 1.0

    def test_completely_different_texts_return_0(self, engine: QualityEngine) -> None:
        assert engine._compute_word_overlap("fetch temperature", "purge logs") == 0.0

    def test_synonym_overlap_detected(self, engine: QualityEngine) -> None:
        # "delete" and "remove" are synonyms — should count as overlap
        score = engine._compute_word_overlap("delete user records", "remove user records")
        assert score > WORD_OVERLAP_THRESHOLD

    def test_empty_string_returns_0(self, engine: QualityEngine) -> None:
        assert engine._compute_word_overlap("", "get weather") == 0.0
        assert engine._compute_word_overlap("get weather", "") == 0.0

    def test_normalizes_by_smaller_set(self, engine: QualityEngine) -> None:
        # Short text is the denominator — long additional words don't dilute score
        score = engine._compute_word_overlap("get user", "get the current user from the system")
        assert score == 1.0  # Both words of the short text appear in the long one


# ---------------------------------------------------------------------------
# _check_schema_completeness (QUAL-010, 011, 012, 013)
# ---------------------------------------------------------------------------

class TestCheckSchemaCompleteness:

    def test_no_description_produces_qual010_critical(
        self, engine: QualityEngine
    ) -> None:
        tool = make_tool("get_weather", description=None)
        client = make_client([tool])
        findings = engine._check_schema_completeness(client)
        assert any(
            f.rule_id == "QUAL-010" and f.severity == "critical"
            for f in findings
        )

    def test_short_description_produces_qual010_warning(
        self, engine: QualityEngine
    ) -> None:
        short = "x" * (MIN_DESCRIPTION_LENGTH - 1)
        tool = make_tool("get_weather", description=short)
        client = make_client([tool])
        findings = engine._check_schema_completeness(client)
        assert any(
            f.rule_id == "QUAL-010" and f.severity == "warning"
            for f in findings
        )

    def test_good_description_produces_no_qual010(
        self, engine: QualityEngine
    ) -> None:
        tool = make_tool("get_weather", description="Gets current weather for a city.")
        client = make_client([tool])
        findings = engine._check_schema_completeness(client)
        assert not any(f.rule_id == "QUAL-010" for f in findings)

    def test_param_without_description_produces_qual011(
        self, engine: QualityEngine
    ) -> None:
        tool = make_tool(
            "get_weather",
            properties={"city": {"type": "string"}},  # no "description" key
        )
        client = make_client([tool])
        findings = engine._check_schema_completeness(client)
        assert any(f.rule_id == "QUAL-011" for f in findings)

    def test_param_with_description_no_qual011(
        self, engine: QualityEngine
    ) -> None:
        tool = make_tool(
            "get_weather",
            properties={"city": {"type": "string", "description": "City name"}},
        )
        client = make_client([tool])
        findings = engine._check_schema_completeness(client)
        assert not any(f.rule_id == "QUAL-011" for f in findings)

    def test_param_without_type_produces_qual012(
        self, engine: QualityEngine
    ) -> None:
        tool = make_tool(
            "get_weather",
            properties={"city": {"description": "City name"}},  # no "type" key
        )
        client = make_client([tool])
        findings = engine._check_schema_completeness(client)
        assert any(f.rule_id == "QUAL-012" for f in findings)

    def test_no_schema_produces_qual013(self, engine: QualityEngine) -> None:
        tool = ToolInfo(name="ping", description="Ping the server.", input_schema={})
        client = make_client([tool])
        findings = engine._check_schema_completeness(client)
        assert any(f.rule_id == "QUAL-013" for f in findings)

    def test_schema_type_not_object_produces_qual013(
        self, engine: QualityEngine
    ) -> None:
        tool = ToolInfo(
            name="ping",
            description="Ping the server.",
            input_schema={"type": "array"},
        )
        client = make_client([tool])
        findings = engine._check_schema_completeness(client)
        assert any(f.rule_id == "QUAL-013" for f in findings)

    def test_empty_tools_list_produces_no_findings(
        self, engine: QualityEngine
    ) -> None:
        assert engine._check_schema_completeness(make_client([])) == []


# ---------------------------------------------------------------------------
# _check_tool_quality (QUAL-020, 022, 023) — LLM mocked
# ---------------------------------------------------------------------------

class TestCheckToolQuality:

    @pytest.mark.asyncio
    async def test_all_criteria_pass_no_findings(
        self, engine: QualityEngine
    ) -> None:
        client = make_client([make_tool("get_weather")])
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = ALL_PASS_RESULT
            findings = await engine._check_tool_quality(client)
        assert findings == []

    @pytest.mark.asyncio
    async def test_failed_clarity_produces_qual020(
        self, engine: QualityEngine
    ) -> None:
        client = make_client([make_tool("get_weather")])
        result = {**ALL_PASS_RESULT, "when_to_use": False, "side_effects_clear": False}
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = result
            findings = await engine._check_tool_quality(client)
        assert any(f.rule_id == "QUAL-020" for f in findings)

    @pytest.mark.asyncio
    async def test_failed_params_clear_produces_qual022(
        self, engine: QualityEngine
    ) -> None:
        client = make_client([make_tool("get_weather")])
        result = {**ALL_PASS_RESULT, "params_clear": False}
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = result
            findings = await engine._check_tool_quality(client)
        assert any(f.rule_id == "QUAL-022" for f in findings)

    @pytest.mark.asyncio
    async def test_failed_return_documented_produces_qual023_info(
        self, engine: QualityEngine
    ) -> None:
        client = make_client([make_tool("get_weather")])
        result = {**ALL_PASS_RESULT, "return_documented": False}
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = result
            findings = await engine._check_tool_quality(client)
        assert any(
            f.rule_id == "QUAL-023" and f.severity == "info"
            for f in findings
        )

    @pytest.mark.asyncio
    async def test_llm_returns_none_no_crash(
        self, engine: QualityEngine
    ) -> None:
        client = make_client([make_tool("get_weather")])
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = None
            findings = await engine._check_tool_quality(client)
        # Should silently skip — not crash, not produce findings
        assert findings == []

    @pytest.mark.asyncio
    async def test_tool_without_description_skipped(
        self, engine: QualityEngine
    ) -> None:
        tool = make_tool("get_weather", description=None)
        client = make_client([tool])
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            await engine._check_tool_quality(client)
        # QUAL-010 already handles no-description tools — LLM should not be called
        mock_llm.assert_not_called()


# ---------------------------------------------------------------------------
# _check_tool_disambiguation (QUAL-021) — LLM mocked
# ---------------------------------------------------------------------------

class TestCheckToolDisambiguation:

    @pytest.mark.asyncio
    async def test_single_tool_no_pairs_checked(
        self, engine: QualityEngine
    ) -> None:
        client = make_client([make_tool("get_weather")])
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            findings = await engine._check_tool_disambiguation(client)
        assert findings == []
        mock_llm.assert_not_called()

    @pytest.mark.asyncio
    async def test_low_overlap_pair_skips_llm(
        self, engine: QualityEngine
    ) -> None:
        # Two completely unrelated tools — word overlap below threshold
        tools = [
            make_tool("get_weather", description="Returns current temperature."),
            make_tool("purge_logs", description="Deletes old system audit logs."),
        ]
        client = make_client(tools)
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            await engine._check_tool_disambiguation(client)
        mock_llm.assert_not_called()

    @pytest.mark.asyncio
    async def test_high_overlap_pair_triggers_llm(
        self, engine: QualityEngine
    ) -> None:
        # Two similar tools — high word overlap should trigger LLM call
        tools = [
            make_tool("send_message",  description="Sends a message to a user via email."),
            make_tool("notify_user",   description="Sends a notification to a user via SMS."),
        ]
        client = make_client(tools)
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = {
                "confusable": False, "overlap": "", "suggestion": "",
            }
            await engine._check_tool_disambiguation(client)
        mock_llm.assert_called_once()

    @pytest.mark.asyncio
    async def test_confusable_pair_produces_qual021(
        self, engine: QualityEngine
    ) -> None:
        tools = [
            make_tool("send_message",  description="Sends a message to a user via email."),
            make_tool("notify_user",   description="Sends a notification to a user via SMS."),
        ]
        client = make_client(tools)
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = {
                "confusable": True,
                "overlap": "Both send messages to users",
                "suggestion": "Clarify channel differences in descriptions",
            }
            findings = await engine._check_tool_disambiguation(client)
        assert any(f.rule_id == "QUAL-021" for f in findings)

    @pytest.mark.asyncio
    async def test_not_confusable_no_findings(
        self, engine: QualityEngine
    ) -> None:
        tools = [
            make_tool("send_message",  description="Sends a message to a user via email."),
            make_tool("notify_user",   description="Sends a notification to a user via SMS."),
        ]
        client = make_client(tools)
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = {
                "confusable": False, "overlap": "", "suggestion": "",
            }
            findings = await engine._check_tool_disambiguation(client)
        assert not any(f.rule_id == "QUAL-021" for f in findings)


# ---------------------------------------------------------------------------
# _run_checks: skip_llm gate
# ---------------------------------------------------------------------------

class TestRunChecks:

    @pytest.mark.asyncio
    async def test_skip_llm_skips_llm_checks(
        self, engine_skip_llm: QualityEngine
    ) -> None:
        client = make_client([make_tool("get_weather")])
        with patch(LLM_PATCH, new_callable=AsyncMock) as mock_llm:
            await engine_skip_llm._run_checks(client)
        mock_llm.assert_not_called()

    @pytest.mark.asyncio
    async def test_skip_llm_still_runs_rule_based(
        self, engine_skip_llm: QualityEngine
    ) -> None:
        tool = make_tool("get_weather", description=None)
        client = make_client([tool])
        findings = await engine_skip_llm._run_checks(client)
        # QUAL-010 is rule-based — must fire even with skip_llm=True
        assert any(f.rule_id == "QUAL-010" for f in findings)
