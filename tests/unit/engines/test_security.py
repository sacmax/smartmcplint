"""Unit tests for the Security Engine.

Strategy:
- Pure helpers (_scan_for_sensitive_data, _find_injection_target) tested directly.
- Async check groups use AsyncMock for client.send_raw and client.call_tool.
- HTTP-making checks (SEC-051 TLS downgrade, SEC-052 cert validation) require
  mocking httpx.AsyncClient — those belong in integration tests, not here.
- Transport security logic (SEC-050 plain HTTP, SEC-053 stdio advisory) is
  testable without HTTP calls because it's purely config-driven.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from smartmcplint.engines.security import INJECTION_CANARY, SecurityEngine
from smartmcplint.models.config import ScanConfig
from smartmcplint.models.mcp import ServerCapabilities, ServerInfo, ToolInfo


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def make_engine(transport: str = "stdio", server_cmd: list[str] | None = None, server_url: str | None = None) -> SecurityEngine:
    return SecurityEngine(config=ScanConfig(
        transport=transport,
        server_cmd=server_cmd or [],
        server_url=server_url,
    ))


def make_tool(
    name: str,
    properties: dict | None = None,
) -> ToolInfo:
    schema: dict = {"type": "object", "properties": properties or {}}
    return ToolInfo(name=name, description="A tool.", input_schema=schema)


def make_server_info(name: str = "test-server", version: str = "1.0") -> ServerInfo:
    return ServerInfo(
        name=name,
        version=version,
        protocol_version="2024-11-05",
        capabilities=ServerCapabilities(),
    )


def make_client(
    tools: list[ToolInfo] | None = None,
    server_info: ServerInfo | None = None,
) -> MagicMock:
    client = MagicMock()
    client.tools = tools or []
    client.server_info = server_info or make_server_info()
    client.send_raw = AsyncMock(return_value={})
    client.call_tool = AsyncMock(return_value={})
    return client


# ---------------------------------------------------------------------------
# _scan_for_sensitive_data
# ---------------------------------------------------------------------------

class TestScanForSensitiveData:

    def test_detects_database_url(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("postgresql://user:pass@localhost/db")
        assert "database_url" in result

    def test_detects_password_field(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("password=supersecret123")
        assert "password_field" in result

    def test_detects_api_key(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("api_key=sk-abc123xyz")
        assert "api_key" in result

    def test_detects_bearer_token(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        assert "bearer_token" in result

    def test_detects_private_ip(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("connecting to 192.168.1.100")
        assert "private_ip" in result

    def test_detects_aws_key(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("key: AKIAIOSFODNN7EXAMPLE12")
        assert "aws_key" in result

    def test_detects_stack_trace(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("Traceback (most recent call last):\n  File 'app.py'")
        assert "stack_trace" in result

    def test_detects_file_path(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("reading /home/ubuntu/.ssh/id_rsa")
        assert "file_path" in result

    def test_clean_text_returns_empty(self) -> None:
        engine = make_engine()
        result = engine._scan_for_sensitive_data("The weather in Toronto is 22 degrees.")
        assert result == []

    def test_multiple_patterns_all_detected(self) -> None:
        engine = make_engine()
        text = "postgresql://admin:pass@192.168.1.1/db"
        result = engine._scan_for_sensitive_data(text)
        assert len(result) >= 2  # At least database_url and private_ip


# ---------------------------------------------------------------------------
# _find_injection_target
# ---------------------------------------------------------------------------

class TestFindInjectionTarget:

    def test_finds_first_string_param(self) -> None:
        engine = make_engine()
        tool = make_tool("get_weather", properties={"city": {"type": "string"}})
        client = make_client(tools=[tool])
        result = engine._find_injection_target(client)
        assert result == ("get_weather", "city")

    def test_skips_destructive_tool_names(self) -> None:
        engine = make_engine()
        dangerous = make_tool("delete_user", properties={"id": {"type": "string"}})
        safe = make_tool("get_status", properties={"env": {"type": "string"}})
        client = make_client(tools=[dangerous, safe])
        result = engine._find_injection_target(client)
        assert result is not None
        assert result[0] == "get_status"

    def test_returns_none_when_no_string_params(self) -> None:
        engine = make_engine()
        tool = make_tool("get_count", properties={"limit": {"type": "integer"}})
        client = make_client(tools=[tool])
        assert engine._find_injection_target(client) is None

    def test_returns_none_when_no_tools(self) -> None:
        engine = make_engine()
        assert engine._find_injection_target(make_client(tools=[])) is None

    def test_returns_none_when_tool_has_no_schema(self) -> None:
        engine = make_engine()
        tool = ToolInfo(name="ping", description="Ping.", input_schema={})
        client = make_client(tools=[tool])
        assert engine._find_injection_target(client) is None


# ---------------------------------------------------------------------------
# _check_authentication
# ---------------------------------------------------------------------------

class TestCheckAuthentication:

    @pytest.mark.asyncio
    async def test_http_transport_produces_sec010_critical(self) -> None:
        engine = make_engine(transport="http", server_url="http://localhost:8080")
        client = make_client()
        findings = await engine._check_authentication(client)
        assert any(
            f.rule_id == "SEC-010" and f.severity == "critical"
            for f in findings
        )

    @pytest.mark.asyncio
    async def test_stdio_transport_produces_sec010_info(self) -> None:
        engine = make_engine(transport="stdio")
        client = make_client()
        findings = await engine._check_authentication(client)
        assert any(
            f.rule_id == "SEC-010" and f.severity == "info"
            for f in findings
        )

    @pytest.mark.asyncio
    async def test_secrets_in_server_cmd_produces_sec014(self) -> None:
        engine = make_engine(
            server_cmd=["python", "server.py", "--api-key=sk-supersecret123"]
        )
        client = make_client()
        findings = await engine._check_authentication(client)
        assert any(f.rule_id == "SEC-014" and f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_clean_server_cmd_no_sec014(self) -> None:
        engine = make_engine(server_cmd=["python", "server.py"])
        client = make_client()
        findings = await engine._check_authentication(client)
        assert not any(f.rule_id == "SEC-014" for f in findings)

    @pytest.mark.asyncio
    async def test_dangerous_tool_produces_sec016_warning(self) -> None:
        engine = make_engine()
        tool = make_tool("delete_all_users")
        client = make_client(tools=[tool])
        findings = await engine._check_authentication(client)
        assert any(f.rule_id == "SEC-016" and f.severity == "warning" for f in findings)

    @pytest.mark.asyncio
    async def test_safe_tool_no_sec016(self) -> None:
        engine = make_engine()
        tool = make_tool("get_weather", properties={"city": {"type": "string"}})
        client = make_client(tools=[tool])
        findings = await engine._check_authentication(client)
        assert not any(f.rule_id == "SEC-016" for f in findings)

    @pytest.mark.asyncio
    async def test_error_response_with_secrets_produces_sec015(self) -> None:
        engine = make_engine()
        client = make_client()
        # Mock send_raw to return an error containing a password
        client.send_raw = AsyncMock(return_value={
            "error": {"code": -32601, "message": "Error: password=admin123 not accepted"}
        })
        findings = await engine._check_authentication(client)
        assert any(f.rule_id == "SEC-015" and f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_clean_error_response_no_sec015(self) -> None:
        engine = make_engine()
        client = make_client()
        client.send_raw = AsyncMock(return_value={
            "error": {"code": -32601, "message": "Method not found"}
        })
        findings = await engine._check_authentication(client)
        assert not any(f.rule_id == "SEC-015" for f in findings)


# ---------------------------------------------------------------------------
# _check_input_validation
# ---------------------------------------------------------------------------

class TestCheckInputValidation:

    @pytest.mark.asyncio
    async def test_no_injection_target_skips_checks(self) -> None:
        engine = make_engine()
        # Tool with no string params — no injection target
        tool = make_tool("get_count", properties={"limit": {"type": "integer"}})
        client = make_client(tools=[tool])
        findings = await engine._check_input_validation(client)
        assert findings == []

    @pytest.mark.asyncio
    async def test_command_injection_canary_in_response_produces_sec020(self) -> None:
        engine = make_engine()
        tool = make_tool("get_weather", properties={"city": {"type": "string"}})
        client = make_client(tools=[tool])
        # Server echoes back our canary — it executed the injected command
        client.call_tool = AsyncMock(return_value={"output": INJECTION_CANARY})
        findings = await engine._check_input_validation(client)
        assert any(f.rule_id == "SEC-020" and f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_no_canary_in_response_no_sec020(self) -> None:
        engine = make_engine()
        tool = make_tool("get_weather", properties={"city": {"type": "string"}})
        client = make_client(tools=[tool])
        client.call_tool = AsyncMock(return_value={"temperature": 22})
        findings = await engine._check_input_validation(client)
        assert not any(f.rule_id == "SEC-020" for f in findings)

    @pytest.mark.asyncio
    async def test_prompt_injection_canary_produces_sec022(self) -> None:
        engine = make_engine()
        tool = make_tool("summarize", properties={"text": {"type": "string"}})
        client = make_client(tools=[tool])

        # Return canary only for the prompt injection payload (third call)
        call_count = 0

        async def call_tool_side_effect(name: str, args: dict) -> dict:
            nonlocal call_count
            call_count += 1
            if call_count == 3:  # Third call is the prompt injection probe
                return {"response": INJECTION_CANARY}
            return {"result": "ok"}

        client.call_tool = call_tool_side_effect
        findings = await engine._check_input_validation(client)
        assert any(f.rule_id == "SEC-022" for f in findings)


# ---------------------------------------------------------------------------
# _check_data_exposure
# ---------------------------------------------------------------------------

class TestCheckDataExposure:

    @pytest.mark.asyncio
    async def test_error_with_sensitive_data_produces_sec040(self) -> None:
        engine = make_engine()
        tool = make_tool("get_weather")
        client = make_client(tools=[tool])
        client.send_raw = AsyncMock(return_value={
            "error": "postgresql://admin:secret@db.internal/prod"
        })
        findings = await engine._check_data_exposure(client)
        assert any(f.rule_id == "SEC-040" and f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_tool_response_with_sensitive_data_produces_sec041(self) -> None:
        engine = make_engine()
        tool = make_tool("get_config")
        client = make_client(tools=[tool])
        client.send_raw = AsyncMock(return_value={})
        client.call_tool = AsyncMock(
            return_value={"config": "api_key=sk-super-secret-value"}
        )
        findings = await engine._check_data_exposure(client)
        assert any(f.rule_id == "SEC-041" and f.severity == "warning" for f in findings)

    @pytest.mark.asyncio
    async def test_detailed_version_produces_sec042_info(self) -> None:
        engine = make_engine()
        server_info = make_server_info(version="1.2.3-beta.4")  # 3+ segments
        client = make_client(server_info=server_info)
        client.send_raw = AsyncMock(return_value={})
        client.call_tool = AsyncMock(return_value={})
        findings = await engine._check_data_exposure(client)
        assert any(f.rule_id == "SEC-042" and f.severity == "info" for f in findings)

    @pytest.mark.asyncio
    async def test_simple_version_no_sec042(self) -> None:
        engine = make_engine()
        server_info = make_server_info(version="1.0")  # Only 2 segments
        client = make_client(server_info=server_info)
        client.send_raw = AsyncMock(return_value={})
        client.call_tool = AsyncMock(return_value={})
        findings = await engine._check_data_exposure(client)
        assert not any(
            f.rule_id == "SEC-042" and f.severity == "info"
            for f in findings
        )

    @pytest.mark.asyncio
    async def test_debug_in_server_name_produces_sec042_warning(self) -> None:
        engine = make_engine()
        server_info = make_server_info(name="my-server-debug")
        client = make_client(server_info=server_info)
        client.send_raw = AsyncMock(return_value={})
        client.call_tool = AsyncMock(return_value={})
        findings = await engine._check_data_exposure(client)
        assert any(f.rule_id == "SEC-042" and f.severity == "warning" for f in findings)

    @pytest.mark.asyncio
    async def test_stdio_transport_always_produces_sec043(self) -> None:
        engine = make_engine(transport="stdio")
        client = make_client()
        client.send_raw = AsyncMock(return_value={})
        client.call_tool = AsyncMock(return_value={})
        findings = await engine._check_data_exposure(client)
        assert any(f.rule_id == "SEC-043" and f.severity == "info" for f in findings)


# ---------------------------------------------------------------------------
# _check_transport_security
# ---------------------------------------------------------------------------

class TestCheckTransportSecurity:

    @pytest.mark.asyncio
    async def test_stdio_produces_sec053_and_no_other_transport_checks(self) -> None:
        engine = make_engine(transport="stdio")
        findings = await engine._check_transport_security()
        assert any(f.rule_id == "SEC-053" for f in findings)
        # No HTTP-specific findings on stdio
        assert not any(f.rule_id in ("SEC-050", "SEC-051", "SEC-052") for f in findings)

    @pytest.mark.asyncio
    async def test_plain_http_url_produces_sec050_critical(self) -> None:
        engine = make_engine(transport="http", server_url="http://api.example.com")
        findings = await engine._check_transport_security()
        assert any(f.rule_id == "SEC-050" and f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_https_url_no_sec050(self) -> None:
        # SEC-050 only fires for plain http:// — https:// is fine at this check
        engine = make_engine(transport="http", server_url="https://api.example.com")
        # SEC-051 and SEC-052 make real HTTP calls — they'll fail gracefully (no findings)
        findings = await engine._check_transport_security()
        assert not any(f.rule_id == "SEC-050" for f in findings)
