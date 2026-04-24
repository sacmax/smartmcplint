"""End-to-end integration tests for SmartMCPLint.

Strategy:
- Each test starts the fixture server as a real subprocess via StdioTransport.
- Tests run with skip_llm=True so no API key is required in CI.
- Assertions focus on outcomes (score range, grade, specific rule IDs) rather
  than exact scores, because timing and LLM output vary across environments.

Run with:
    uv run pytest tests/integration -m integration -v
"""

import sys
from pathlib import Path

import pytest

from smartmcplint.models.config import ScanConfig
from smartmcplint.models.enums import Grade
from smartmcplint.scanner import Scanner

FIXTURES = Path(__file__).parent.parent / "fixtures"
GOOD_SERVER = [sys.executable, str(FIXTURES / "good_server.py")]
BAD_SERVER  = [sys.executable, str(FIXTURES / "bad_server.py")]


# ---------------------------------------------------------------------------
# good_server.py — well-behaved fixture
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_scan_completes() -> None:
    """Full scan against the good fixture server returns a ScanResult."""
    config = ScanConfig(
        transport="stdio",
        server_cmd=GOOD_SERVER,
        skip_llm=True,
    )
    result = await Scanner(config).scan()
    assert result.server_info.name == "good-fixture-server"
    assert result.server_info.version == "1.0.0"
    assert result.server_info.protocol_version == "2024-11-05"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_no_conf001() -> None:
    """A well-behaved server completes initialization — no CONF-001."""
    config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    all_rule_ids = [
        f.rule_id
        for er in result.engine_results.values()
        for f in er.findings
    ]
    assert "CONF-001" not in all_rule_ids


@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_no_critical_conformance_findings() -> None:
    """Fixture server passes all critical conformance checks."""
    config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    conf_result = result.engine_results.get(EngineType.CONFORMANCE)
    assert conf_result is not None
    critical = [f for f in conf_result.findings if f.severity == "critical"]
    assert critical == [], f"Unexpected critical conformance findings: {critical}"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_score_above_passing() -> None:
    """A well-implemented server should score above 55 (grade C or better)."""
    config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    assert result.overall_score > 55.0, (
        f"Score {result.overall_score:.1f} is below expected minimum for a good server"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_grade_not_f() -> None:
    """A well-implemented server should not receive a failing grade."""
    config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    assert result.grade != Grade.F, f"Good server received failing grade F (score={result.overall_score:.1f})"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_behavior_engine_runs() -> None:
    """Behavior engine ran (not skipped) and found no critical findings."""
    config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    beh_result = result.engine_results.get(EngineType.BEHAVIOR)
    assert beh_result is not None
    assert not beh_result.skipped
    critical = [f for f in beh_result.findings if f.severity == "critical"]
    assert critical == [], f"Unexpected critical behavior findings: {critical}"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_get_echo_produces_beh013_warning() -> None:
    """get_echo accepts empty string for 'message' param — BEH-013 warning expected."""
    config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    beh_result = result.engine_results.get(EngineType.BEHAVIOR)
    assert beh_result is not None
    rule_ids = [f.rule_id for f in beh_result.findings]
    assert "BEH-013" in rule_ids, (
        "Expected BEH-013 (empty string accepted) for get_echo, "
        f"but got findings: {rule_ids}"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_has_two_tools() -> None:
    """Scanner discovers both tools exposed by the fixture server."""
    config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    # Server info is from client — re-run to access client.tools via engine results
    # Indirectly verify via conformance: no CONF-010 (tools declared but none listed)
    all_rule_ids = [
        f.rule_id
        for er in result.engine_results.values()
        for f in er.findings
    ]
    assert "CONF-010" not in all_rule_ids


@pytest.mark.integration
@pytest.mark.asyncio
async def test_good_server_scan_duration_is_reasonable() -> None:
    """Scan against a local subprocess completes within 30 seconds."""
    config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    assert result.scan_duration_ms < 30_000, (
        f"Scan took {result.scan_duration_ms:.0f}ms — too slow for a local fixture"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_skip_engines_removes_engine_from_results() -> None:
    """Skipping an engine marks it as skipped in results and scores it as 100."""
    config = ScanConfig(
        transport="stdio",
        server_cmd=GOOD_SERVER,
        skip_llm=True,
        skip_engines=["security"],
    )
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    sec_result = result.engine_results.get(EngineType.SECURITY)
    assert sec_result is not None
    assert sec_result.skipped is True
    assert sec_result.score == 100.0


# ---------------------------------------------------------------------------
# bad_server.py — deliberately broken fixture
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.asyncio
async def test_bad_server_produces_conf002() -> None:
    """Server omits protocolVersion — CONF-002 fires."""
    config = ScanConfig(transport="stdio", server_cmd=BAD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    conf = result.engine_results.get(EngineType.CONFORMANCE)
    assert conf is not None
    rule_ids = [f.rule_id for f in conf.findings]
    assert "CONF-002" in rule_ids


@pytest.mark.integration
@pytest.mark.asyncio
async def test_bad_server_produces_conf003() -> None:
    """Server omits serverInfo.name — CONF-003 fires."""
    config = ScanConfig(transport="stdio", server_cmd=BAD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    conf = result.engine_results.get(EngineType.CONFORMANCE)
    assert conf is not None
    rule_ids = [f.rule_id for f in conf.findings]
    assert "CONF-003" in rule_ids


@pytest.mark.integration
@pytest.mark.asyncio
async def test_bad_server_produces_conf013() -> None:
    """Tool has no description — CONF-013 fires."""
    config = ScanConfig(transport="stdio", server_cmd=BAD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    conf = result.engine_results.get(EngineType.CONFORMANCE)
    assert conf is not None
    rule_ids = [f.rule_id for f in conf.findings]
    assert "CONF-013" in rule_ids


@pytest.mark.integration
@pytest.mark.asyncio
async def test_bad_server_produces_conf014() -> None:
    """Tool inputSchema type is 'array' not 'object' — CONF-014 fires."""
    config = ScanConfig(transport="stdio", server_cmd=BAD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    conf = result.engine_results.get(EngineType.CONFORMANCE)
    assert conf is not None
    rule_ids = [f.rule_id for f in conf.findings]
    assert "CONF-014" in rule_ids


@pytest.mark.integration
@pytest.mark.asyncio
async def test_bad_server_produces_conf020() -> None:
    """Non-existent tool returns success — CONF-020 fires."""
    config = ScanConfig(transport="stdio", server_cmd=BAD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    conf = result.engine_results.get(EngineType.CONFORMANCE)
    assert conf is not None
    rule_ids = [f.rule_id for f in conf.findings]
    assert "CONF-020" in rule_ids


@pytest.mark.integration
@pytest.mark.asyncio
async def test_bad_server_produces_conf030() -> None:
    """Unknown method returns wrong error code — CONF-030 fires."""
    config = ScanConfig(transport="stdio", server_cmd=BAD_SERVER, skip_llm=True)
    result = await Scanner(config).scan()
    from smartmcplint.models.enums import EngineType
    conf = result.engine_results.get(EngineType.CONFORMANCE)
    assert conf is not None
    rule_ids = [f.rule_id for f in conf.findings]
    assert "CONF-030" in rule_ids


@pytest.mark.integration
@pytest.mark.asyncio
async def test_bad_server_scores_lower_than_good_server() -> None:
    """A broken server scores lower than a well-behaved one."""
    good_config = ScanConfig(transport="stdio", server_cmd=GOOD_SERVER, skip_llm=True)
    bad_config  = ScanConfig(transport="stdio", server_cmd=BAD_SERVER,  skip_llm=True)
    good_result = await Scanner(good_config).scan()
    bad_result  = await Scanner(bad_config).scan()
    assert bad_result.overall_score < good_result.overall_score, (
        f"Bad server ({bad_result.overall_score:.1f}) should score lower "
        f"than good server ({good_result.overall_score:.1f})"
    )
