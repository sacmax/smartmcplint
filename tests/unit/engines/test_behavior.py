"""Unit tests for the Behavior Engine.

Strategy:
- Pure helpers (_classify_tool, _generate_*_inputs, _extract_structure) are
  tested directly — no mocking needed, just input → expected output.
- Async check methods (_check_valid_call, _check_bad_inputs) use AsyncMock to
  simulate server responses without a real MCP connection.
- Each test verifies a specific rule fires (or doesn't) under controlled conditions.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from smartmcplint.engines.behavior import PROBE_STRING, BehaviorEngine
from smartmcplint.models.config import ScanConfig
from smartmcplint.models.mcp import ToolInfo


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> BehaviorEngine:
    return BehaviorEngine(config=ScanConfig(transport="stdio"))


def make_tool(
    name: str,
    description: str = "A test tool.",
    properties: dict | None = None,
    required: list[str] | None = None,
) -> ToolInfo:
    """Build a ToolInfo with an input_schema from kwargs."""
    schema: dict = {"type": "object", "properties": properties or {}}
    if required:
        schema["required"] = required
    return ToolInfo(name=name, description=description, input_schema=schema)


def make_client(tools: list[ToolInfo] | None = None) -> MagicMock:
    """Build a mock MCPClient with a preset tools list."""
    client = MagicMock()
    client.tools = tools or []
    return client


# ---------------------------------------------------------------------------
# _classify_tool
# ---------------------------------------------------------------------------

class TestClassifyTool:

    def test_write_keyword_returns_write(self, engine: BehaviorEngine) -> None:
        tool = make_tool("delete_user")
        assert engine._classify_tool(tool) == "write"

    def test_read_keyword_returns_safe(self, engine: BehaviorEngine) -> None:
        tool = make_tool("get_weather")
        assert engine._classify_tool(tool) == "safe"

    def test_ambiguous_name_returns_unknown(self, engine: BehaviorEngine) -> None:
        tool = make_tool("process_data")
        assert engine._classify_tool(tool) == "unknown"

    def test_write_takes_priority_over_read(self, engine: BehaviorEngine) -> None:
        # 'get' is READ, 'delete' is WRITE — write must win
        tool = make_tool("get_deleted_records")
        assert engine._classify_tool(tool) == "write"

    def test_case_insensitive(self, engine: BehaviorEngine) -> None:
        assert engine._classify_tool(make_tool("GET_USERS")) == "safe"
        assert engine._classify_tool(make_tool("DELETE_USER")) == "write"

    def test_keyword_anywhere_in_name(self, engine: BehaviorEngine) -> None:
        # 'create' appears in the middle of the name
        assert engine._classify_tool(make_tool("batch_create_records")) == "write"


# ---------------------------------------------------------------------------
# _generate_valid_inputs
# ---------------------------------------------------------------------------

class TestGenerateValidInputs:

    def test_required_string_gets_probe_string(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_weather",
            properties={"city": {"type": "string"}},
            required=["city"],
        )
        result = engine._generate_valid_inputs(tool)
        assert result == {"city": PROBE_STRING}

    def test_optional_params_omitted(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_weather",
            properties={
                "city":  {"type": "string"},
                "units": {"type": "string"},
            },
            required=["city"],  # units is optional
        )
        result = engine._generate_valid_inputs(tool)
        assert "units" not in result

    def test_enum_field_uses_first_value(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_weather",
            properties={
                "city":  {"type": "string"},
                "units": {"type": "string", "enum": ["metric", "imperial"]},
            },
            required=["city", "units"],
        )
        result = engine._generate_valid_inputs(tool)
        assert result["units"] == "metric"

    def test_integer_field_gets_zero(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_items",
            properties={"limit": {"type": "integer"}},
            required=["limit"],
        )
        assert engine._generate_valid_inputs(tool) == {"limit": 0}

    def test_boolean_field_gets_false(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "search",
            properties={"verbose": {"type": "boolean"}},
            required=["verbose"],
        )
        assert engine._generate_valid_inputs(tool) == {"verbose": False}

    def test_no_required_params_returns_empty(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "list_users",
            properties={"limit": {"type": "integer"}},
            required=[],
        )
        assert engine._generate_valid_inputs(tool) == {}

    def test_no_schema_returns_empty(self, engine: BehaviorEngine) -> None:
        tool = ToolInfo(name="ping", description="Ping the server.", input_schema={})
        assert engine._generate_valid_inputs(tool) == {}


# ---------------------------------------------------------------------------
# _generate_wrong_type_inputs
# ---------------------------------------------------------------------------

class TestGenerateWrongTypeInputs:

    def test_string_param_gets_integer(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_weather",
            properties={"city": {"type": "string"}},
            required=["city"],
        )
        result = engine._generate_wrong_type_inputs(tool)
        assert result is not None
        inputs, param_name = result
        assert param_name == "city"
        assert isinstance(inputs["city"], int)

    def test_integer_param_gets_string(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_items",
            properties={"limit": {"type": "integer"}},
            required=["limit"],
        )
        result = engine._generate_wrong_type_inputs(tool)
        assert result is not None
        inputs, param_name = result
        assert isinstance(inputs["limit"], str)

    def test_enum_param_gets_invalid_value(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_weather",
            properties={"units": {"type": "string", "enum": ["metric", "imperial"]}},
            required=["units"],
        )
        result = engine._generate_wrong_type_inputs(tool)
        assert result is not None
        inputs, _ = result
        assert inputs["units"] not in ("metric", "imperial")

    def test_no_required_params_returns_none(self, engine: BehaviorEngine) -> None:
        tool = make_tool("list_users", properties={}, required=[])
        assert engine._generate_wrong_type_inputs(tool) == None  # noqa: E711

    def test_other_valid_params_preserved(self, engine: BehaviorEngine) -> None:
        # When flipping one param's type, others should keep their valid probe values
        tool = make_tool(
            "search",
            properties={
                "query":  {"type": "string"},
                "limit":  {"type": "integer"},
            },
            required=["query", "limit"],
        )
        result = engine._generate_wrong_type_inputs(tool)
        assert result is not None
        inputs, param_name = result
        # One param has wrong type, the other retains valid value
        other_param = "limit" if param_name == "query" else "query"
        assert other_param in inputs


# ---------------------------------------------------------------------------
# _generate_empty_string_inputs
# ---------------------------------------------------------------------------

class TestGenerateEmptyStringInputs:

    def test_required_string_gets_empty(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_weather",
            properties={"city": {"type": "string"}},
            required=["city"],
        )
        result = engine._generate_empty_string_inputs(tool)
        assert result is not None
        inputs, param_name = result
        assert param_name == "city"
        assert inputs["city"] == ""

    def test_enum_param_skipped(self, engine: BehaviorEngine) -> None:
        # Enum-constrained params are skipped — empty string is a type violation, not "empty"
        tool = make_tool(
            "get_weather",
            properties={"units": {"type": "string", "enum": ["metric", "imperial"]}},
            required=["units"],
        )
        assert engine._generate_empty_string_inputs(tool) is None

    def test_no_string_params_returns_none(self, engine: BehaviorEngine) -> None:
        tool = make_tool(
            "get_items",
            properties={"limit": {"type": "integer"}},
            required=["limit"],
        )
        assert engine._generate_empty_string_inputs(tool) is None


# ---------------------------------------------------------------------------
# _extract_structure
# ---------------------------------------------------------------------------

class TestExtractStructure:

    def test_dict_returns_top_level_keys(self, engine: BehaviorEngine) -> None:
        response = {"id": 1, "name": "foo", "meta": {"created": "2024-01-01"}}
        assert engine._extract_structure(response) == frozenset({"id", "name", "meta"})

    def test_empty_dict_returns_empty_frozenset(self, engine: BehaviorEngine) -> None:
        assert engine._extract_structure({}) == frozenset()

    def test_non_dict_returns_empty_frozenset(self, engine: BehaviorEngine) -> None:
        assert engine._extract_structure("a string") == frozenset()
        assert engine._extract_structure([1, 2, 3]) == frozenset()
        assert engine._extract_structure(42) == frozenset()


# ---------------------------------------------------------------------------
# _check_valid_call (BEH-010 + BEH-021)
# ---------------------------------------------------------------------------

class TestCheckValidCall:

    @pytest.mark.asyncio
    async def test_successful_call_produces_no_findings(
        self, engine: BehaviorEngine
    ) -> None:
        tool = make_tool("get_weather", properties={"city": {"type": "string"}}, required=["city"])
        client = make_client()
        client.call_tool = AsyncMock(return_value={"temperature": 22})

        findings = await engine._check_valid_call(client, tool)
        assert findings == []

    @pytest.mark.asyncio
    async def test_mcp_error_is_not_a_finding(self, engine: BehaviorEngine) -> None:
        from smartmcplint.client import MCPError
        tool = make_tool("get_weather", properties={"city": {"type": "string"}}, required=["city"])
        client = make_client()
        client.call_tool = AsyncMock(side_effect=MCPError(code=-32602, message="Invalid params"))

        findings = await engine._check_valid_call(client, tool)
        assert findings == []

    @pytest.mark.asyncio
    async def test_transport_error_produces_beh010_critical(
        self, engine: BehaviorEngine
    ) -> None:
        from smartmcplint.transport import TransportError
        tool = make_tool("get_weather")
        client = make_client()
        client.call_tool = AsyncMock(side_effect=TransportError("connection dropped"))

        findings = await engine._check_valid_call(client, tool)
        assert len(findings) == 1
        assert findings[0].rule_id == "BEH-010"
        assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_timeout_produces_beh010_critical(self, engine: BehaviorEngine) -> None:
        tool = make_tool("get_weather")
        client = make_client()
        client.call_tool = AsyncMock(side_effect=TimeoutError())

        findings = await engine._check_valid_call(client, tool)
        assert len(findings) == 1
        assert findings[0].rule_id == "BEH-010"
        assert findings[0].severity == "critical"


# ---------------------------------------------------------------------------
# _run_checks: integration of classification + skipping
# ---------------------------------------------------------------------------

class TestRunChecks:

    @pytest.mark.asyncio
    async def test_empty_tools_returns_no_findings(self, engine: BehaviorEngine) -> None:
        client = make_client(tools=[])
        findings = await engine._run_checks(client)
        assert findings == []

    @pytest.mark.asyncio
    async def test_write_tools_produce_beh030(self, engine: BehaviorEngine) -> None:
        client = make_client(tools=[make_tool("delete_user")])
        # No call_tool needed — write tools are never invoked
        findings = await engine._run_checks(client)
        assert any(f.rule_id == "BEH-030" for f in findings)

    @pytest.mark.asyncio
    async def test_write_tools_never_invoked(self, engine: BehaviorEngine) -> None:
        client = make_client(tools=[make_tool("delete_user")])
        client.call_tool = AsyncMock()
        await engine._run_checks(client)
        client.call_tool.assert_not_called()
