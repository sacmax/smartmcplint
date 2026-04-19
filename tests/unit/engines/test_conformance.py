"""Unit tests for the Conformance Engine.

Strategy:
- _check_initialization, _check_tool_listing, _check_resources are sync — mock client
  attributes directly, no AsyncMock needed.
- _check_tool_invocation and _check_error_handling are async — use AsyncMock for
  client.call_tool and client.send_raw.
- Tests are grouped by check method, matching the engine's internal structure.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from smartmcplint.engines.conformance import ConformanceEngine
from smartmcplint.models.mcp import ResourceInfo, ServerCapabilities, ServerInfo, ToolInfo
from smartmcplint.client import MCPError
from smartmcplint.transport import TransportError


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> ConformanceEngine:
    return ConformanceEngine()


def make_server_info(
    name: str = "test-server",
    version: str = "1.0",
    protocol_version: str = "2024-11-05",
    tools: bool = True,
    resources: bool = False,
    prompts: bool = False,
) -> ServerInfo:
    return ServerInfo(
        name=name,
        version=version,
        protocol_version=protocol_version,
        capabilities=ServerCapabilities(tools=tools, resources=resources, prompts=prompts),
    )


def make_tool(
    name: str = "get_weather",
    description: str | None = "Returns weather for a city.",
    input_schema: dict | None = None,
) -> ToolInfo:
    return ToolInfo(
        name=name,
        description=description,
        input_schema=input_schema if input_schema is not None else {"type": "object", "properties": {}},
    )


def make_client(
    server_info: ServerInfo | None = None,
    tools: list[ToolInfo] | None = None,
    resources: list[ResourceInfo] | None = None,
) -> MagicMock:
    client = MagicMock()
    client.server_info = server_info
    client.tools = tools or []
    client.resources = resources or []
    client.call_tool = AsyncMock(return_value={})
    client.send_raw = AsyncMock(return_value={})
    return client


# ---------------------------------------------------------------------------
# _check_initialization
# ---------------------------------------------------------------------------

class TestCheckInitialization:

    def test_none_server_info_produces_conf001_critical(self, engine: ConformanceEngine) -> None:
        client = make_client(server_info=None)
        findings = engine._check_initialization(client)
        assert len(findings) == 1
        assert findings[0].rule_id == "CONF-001"
        assert findings[0].severity == "critical"

    def test_none_server_info_returns_early_no_other_findings(self, engine: ConformanceEngine) -> None:
        # Even though name/version/capabilities are all "unknown"/empty, CONF-001 short-circuits
        client = make_client(server_info=None)
        findings = engine._check_initialization(client)
        rule_ids = [f.rule_id for f in findings]
        assert "CONF-002" not in rule_ids
        assert "CONF-003" not in rule_ids

    def test_unknown_protocol_version_produces_conf002(self, engine: ConformanceEngine) -> None:
        info = make_server_info(protocol_version="unknown")
        client = make_client(server_info=info)
        findings = engine._check_initialization(client)
        assert any(f.rule_id == "CONF-002" for f in findings)

    def test_unknown_name_produces_conf003_warning(self, engine: ConformanceEngine) -> None:
        info = make_server_info(name="unknown")
        client = make_client(server_info=info)
        findings = engine._check_initialization(client)
        match = next(f for f in findings if f.rule_id == "CONF-003")
        assert match.severity == "warning"

    def test_unknown_version_produces_conf004_warning(self, engine: ConformanceEngine) -> None:
        info = make_server_info(version="unknown")
        client = make_client(server_info=info)
        findings = engine._check_initialization(client)
        assert any(f.rule_id == "CONF-004" for f in findings)

    def test_no_capabilities_produces_conf005(self, engine: ConformanceEngine) -> None:
        info = make_server_info(tools=False, resources=False, prompts=False)
        client = make_client(server_info=info)
        findings = engine._check_initialization(client)
        assert any(f.rule_id == "CONF-005" for f in findings)

    def test_fully_valid_server_info_produces_no_findings(self, engine: ConformanceEngine) -> None:
        info = make_server_info()
        client = make_client(server_info=info)
        findings = engine._check_initialization(client)
        assert findings == []

    def test_at_least_one_capability_satisfies_conf005(self, engine: ConformanceEngine) -> None:
        # Only prompts enabled — still satisfies the "has some capability" requirement
        info = make_server_info(tools=False, resources=False, prompts=True)
        client = make_client(server_info=info)
        findings = engine._check_initialization(client)
        assert not any(f.rule_id == "CONF-005" for f in findings)


# ---------------------------------------------------------------------------
# _check_tool_listing
# ---------------------------------------------------------------------------

class TestCheckToolListing:

    def test_empty_tools_with_tools_capability_produces_conf010(self, engine: ConformanceEngine) -> None:
        info = make_server_info(tools=True)
        client = make_client(server_info=info, tools=[])
        findings = engine._check_tool_listing(client)
        assert any(f.rule_id == "CONF-010" for f in findings)

    def test_empty_tools_without_capability_produces_no_findings(self, engine: ConformanceEngine) -> None:
        info = make_server_info(tools=False)
        client = make_client(server_info=info, tools=[])
        findings = engine._check_tool_listing(client)
        assert findings == []

    def test_unnamed_tool_produces_conf011_critical(self, engine: ConformanceEngine) -> None:
        tool = make_tool(name="unnamed")
        client = make_client(server_info=make_server_info(), tools=[tool])
        findings = engine._check_tool_listing(client)
        assert any(f.rule_id == "CONF-011" and f.severity == "critical" for f in findings)

    def test_tool_with_no_input_schema_produces_conf012(self, engine: ConformanceEngine) -> None:
        tool = ToolInfo(name="get_weather", description="Gets weather.", input_schema={})
        client = make_client(server_info=make_server_info(), tools=[tool])
        findings = engine._check_tool_listing(client)
        assert any(f.rule_id == "CONF-012" for f in findings)

    def test_tool_with_no_description_produces_conf013(self, engine: ConformanceEngine) -> None:
        tool = make_tool(description=None)
        client = make_client(server_info=make_server_info(), tools=[tool])
        findings = engine._check_tool_listing(client)
        assert any(f.rule_id == "CONF-013" for f in findings)

    def test_tool_with_empty_description_produces_conf013(self, engine: ConformanceEngine) -> None:
        tool = make_tool(description="   ")
        client = make_client(server_info=make_server_info(), tools=[tool])
        findings = engine._check_tool_listing(client)
        assert any(f.rule_id == "CONF-013" for f in findings)

    def test_schema_type_not_object_produces_conf014(self, engine: ConformanceEngine) -> None:
        tool = make_tool(input_schema={"type": "array"})
        client = make_client(server_info=make_server_info(), tools=[tool])
        findings = engine._check_tool_listing(client)
        assert any(f.rule_id == "CONF-014" for f in findings)

    def test_object_schema_without_properties_produces_conf015_info(self, engine: ConformanceEngine) -> None:
        tool = make_tool(input_schema={"type": "object"})
        client = make_client(server_info=make_server_info(), tools=[tool])
        findings = engine._check_tool_listing(client)
        match = next((f for f in findings if f.rule_id == "CONF-015"), None)
        assert match is not None
        assert match.severity == "info"

    def test_well_formed_tool_produces_no_findings(self, engine: ConformanceEngine) -> None:
        tool = make_tool()  # name, description, valid schema
        client = make_client(server_info=make_server_info(), tools=[tool])
        findings = engine._check_tool_listing(client)
        assert findings == []

    def test_finding_carries_tool_name(self, engine: ConformanceEngine) -> None:
        tool = make_tool(name="broken_tool", description=None)
        client = make_client(server_info=make_server_info(), tools=[tool])
        findings = engine._check_tool_listing(client)
        conf013 = next(f for f in findings if f.rule_id == "CONF-013")
        assert conf013.tool_name == "broken_tool"


# ---------------------------------------------------------------------------
# _check_tool_invocation
# ---------------------------------------------------------------------------

class TestCheckToolInvocation:

    @pytest.mark.asyncio
    async def test_mcp_error_on_fake_tool_produces_no_findings(self, engine: ConformanceEngine) -> None:
        client = make_client()
        client.call_tool = AsyncMock(side_effect=MCPError(code=-32601, message="Method not found"))
        findings = await engine._check_tool_invocation(client)
        assert findings == []

    @pytest.mark.asyncio
    async def test_success_on_fake_tool_produces_conf020_warning(self, engine: ConformanceEngine) -> None:
        client = make_client()
        client.call_tool = AsyncMock(return_value={"result": "somehow worked"})
        findings = await engine._check_tool_invocation(client)
        assert any(f.rule_id == "CONF-020" and f.severity == "warning" for f in findings)

    @pytest.mark.asyncio
    async def test_transport_error_on_fake_tool_produces_conf021_critical(self, engine: ConformanceEngine) -> None:
        client = make_client()
        client.call_tool = AsyncMock(side_effect=TransportError("server crashed"))
        findings = await engine._check_tool_invocation(client)
        assert any(f.rule_id == "CONF-021" and f.severity == "critical" for f in findings)


# ---------------------------------------------------------------------------
# _check_error_handling
# ---------------------------------------------------------------------------

class TestCheckErrorHandling:

    @pytest.mark.asyncio
    async def test_correct_minus32601_produces_no_findings(self, engine: ConformanceEngine) -> None:
        client = make_client()
        client.send_raw = AsyncMock(return_value={"error": {"code": -32601, "message": "Method not found"}})
        findings = await engine._check_error_handling(client)
        assert not any(f.rule_id in ("CONF-030", "CONF-031", "CONF-032") for f in findings)

    @pytest.mark.asyncio
    async def test_wrong_error_code_produces_conf030(self, engine: ConformanceEngine) -> None:
        # First call: unknown method → wrong error code
        # Second call: missing jsonrpc field → has error, so no CONF-033
        client = make_client()
        client.send_raw = AsyncMock(side_effect=[
            {"error": {"code": -32000, "message": "Server error"}},
            {"error": {"code": -32601}},
        ])
        findings = await engine._check_error_handling(client)
        assert any(f.rule_id == "CONF-030" for f in findings)

    @pytest.mark.asyncio
    async def test_success_for_unknown_method_produces_conf031(self, engine: ConformanceEngine) -> None:
        client = make_client()
        client.send_raw = AsyncMock(side_effect=[
            {"result": {}},
            {"error": {"code": -32601}},
        ])
        findings = await engine._check_error_handling(client)
        assert any(f.rule_id == "CONF-031" for f in findings)

    @pytest.mark.asyncio
    async def test_no_response_for_unknown_method_produces_conf032(self, engine: ConformanceEngine) -> None:
        client = make_client()
        client.send_raw = AsyncMock(side_effect=[
            None,
            {"error": {"code": -32601}},
        ])
        findings = await engine._check_error_handling(client)
        assert any(f.rule_id == "CONF-032" for f in findings)

    @pytest.mark.asyncio
    async def test_missing_jsonrpc_field_accepted_produces_conf033(self, engine: ConformanceEngine) -> None:
        client = make_client()
        client.send_raw = AsyncMock(side_effect=[
            {"error": {"code": -32601}},   # first call: correct unknown-method error
            {"result": {"tools": []}},     # second call: server accepted missing jsonrpc
        ])
        findings = await engine._check_error_handling(client)
        assert any(f.rule_id == "CONF-033" for f in findings)

    @pytest.mark.asyncio
    async def test_strict_server_rejects_missing_jsonrpc_produces_no_conf033(self, engine: ConformanceEngine) -> None:
        client = make_client()
        client.send_raw = AsyncMock(side_effect=[
            {"error": {"code": -32601}},
            {"error": {"code": -32600, "message": "Invalid Request"}},
        ])
        findings = await engine._check_error_handling(client)
        assert not any(f.rule_id == "CONF-033" for f in findings)


# ---------------------------------------------------------------------------
# _check_resources
# ---------------------------------------------------------------------------

class TestCheckResources:

    def test_no_resource_capability_produces_no_findings(self, engine: ConformanceEngine) -> None:
        info = make_server_info(resources=False)
        client = make_client(server_info=info)
        findings = engine._check_resources(client)
        assert findings == []

    def test_none_server_info_produces_no_findings(self, engine: ConformanceEngine) -> None:
        client = make_client(server_info=None)
        findings = engine._check_resources(client)
        assert findings == []

    def test_resource_capability_but_empty_list_produces_conf040(self, engine: ConformanceEngine) -> None:
        info = make_server_info(resources=True)
        client = make_client(server_info=info, resources=[])
        findings = engine._check_resources(client)
        assert any(f.rule_id == "CONF-040" for f in findings)

    def test_resource_with_uri_produces_no_findings(self, engine: ConformanceEngine) -> None:
        info = make_server_info(resources=True)
        resource = ResourceInfo(uri="file:///data/report.csv", name="Sales Report")
        client = make_client(server_info=info, resources=[resource])
        findings = engine._check_resources(client)
        assert findings == []

    def test_resource_without_uri_produces_conf041_critical(self, engine: ConformanceEngine) -> None:
        info = make_server_info(resources=True)
        # URI is required by schema — bypass validation to simulate broken server
        resource = ResourceInfo.model_construct(uri="", name="Broken Resource")
        client = make_client(server_info=info, resources=[resource])
        findings = engine._check_resources(client)
        assert any(f.rule_id == "CONF-041" and f.severity == "critical" for f in findings)
