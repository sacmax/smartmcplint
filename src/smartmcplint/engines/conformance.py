"""Conformance Engine — validates MCP spec compliance.

- Checks are grouped by category (initialization, tool listing, tool invocation,
  error handling, resources) rather than one-per-method, for navigability.
- Each group method returns a list of findings — the main _run_checks() collects them all.
- Uses client.send_raw() for error handling tests because we need to send
  intentionally malformed messages that the typed client methods wouldn't allow.
- Rule IDs follow CONF-XXX pattern for traceability.
"""

import logging

from smartmcplint.client import MCPClient, MCPError
from smartmcplint.engines.base import BaseEngine
from smartmcplint.models.enums import EngineType, FindingSeverity
from smartmcplint.models.findings import Finding
from smartmcplint.transport import TransportError

logger = logging.getLogger(__name__)


class ConformanceEngine(BaseEngine):
    """Tests whether an MCP server implements the protocol spec correctly."""

    @property
    def engine_type(self) -> EngineType:
        return EngineType.CONFORMANCE

    async def _run_checks(self, client: MCPClient) -> list[Finding]:
        """Run all conformance check groups in order.

        Order matters slightly: initialization checks run first because
        later checks depend on having valid server_info and tools.
        But we don't short-circuit — even if initialization has issues,
        we still run other checks to give a complete picture.
        """
        findings: list[Finding] = []
        findings.extend(self._check_initialization(client))
        findings.extend(self._check_tool_listing(client))
        findings.extend(await self._check_tool_invocation(client))
        findings.extend(await self._check_error_handling(client))
        findings.extend(self._check_resources(client))
        return findings

    def _check_initialization(self, client: MCPClient) -> list[Finding]:
        """Check that the initialize response contains all required fields.

        MCP spec requires: protocolVersion, serverInfo (with name), capabilities.
        We check against what the client stored during initialize().
        These are sync checks — no server communication, just inspecting cached data.
        """
        findings: list[Finding] = []
        info = client.server_info

        if info is None:
            findings.append(Finding(
                rule_id="CONF-001",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.CRITICAL,
                title="Server did not complete initialization",
                message="The initialize handshake did not produce a valid server_info. "
                        "The server either didn't respond or returned an unparseable response.",
                spec_ref="MCP Spec §5.1 — Initialization",
            ))
            return findings

        if info.protocol_version == "unknown":
            findings.append(Finding(
                rule_id="CONF-002",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.CRITICAL,
                title="Missing protocolVersion in initialize response",
                message="Server did not return a protocolVersion field. "
                        "Clients use this to determine compatibility.",
                spec_ref="MCP Spec §5.1 — Initialization",
            ))

        if info.name == "unknown":
            findings.append(Finding(
                rule_id="CONF-003",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.WARNING,
                title="Missing serverInfo.name in initialize response",
                message="Server did not identify itself with a name. "
                        "Clients use this for logging and user-facing display.",
                spec_ref="MCP Spec §5.1 — Initialization",
            ))

        if info.version == "unknown":
            findings.append(Finding(
                rule_id="CONF-004",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.WARNING,
                title="Missing serverInfo.version in initialize response",
                message="Server did not report its version. "
                        "Useful for debugging and compatibility tracking.",
                spec_ref="MCP Spec §5.1 — Initialization",
            ))

        caps = info.capabilities
        if not caps.tools and not caps.resources and not caps.prompts:
            findings.append(Finding(
                rule_id="CONF-005",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.WARNING,
                title="Server declares no capabilities",
                message="Server did not declare support for tools, resources, or prompts. "
                        "A server with no capabilities has nothing for clients to use.",
                spec_ref="MCP Spec §5.1 — Capabilities",
            ))

        return findings

    def _check_tool_listing(self, client: MCPClient) -> list[Finding]:
        """Check that tools returned by tools/list are well-formed.

        Each tool must have a name and inputSchema (per spec).
        Description is technically optional but practically essential.
        """
        findings: list[Finding] = []

        if not client.tools:
            # Not a conformance issue — server might legitimately have no tools.
            # But worth noting as info.
            if client.server_info and client.server_info.capabilities.tools:
                findings.append(Finding(
                    rule_id="CONF-010",
                    engine=EngineType.CONFORMANCE,
                    severity=FindingSeverity.WARNING,
                    title="Server declares tools capability but lists no tools",
                    message="Server said it supports tools in capabilities, "
                            "but tools/list returned an empty list.",
                    spec_ref="MCP Spec §6.1 — Tool Listing",
                ))
            return findings

        for tool in client.tools:
            if not tool.name or tool.name == "unnamed":
                findings.append(Finding(
                    rule_id="CONF-011",
                    engine=EngineType.CONFORMANCE,
                    severity=FindingSeverity.CRITICAL,
                    title="Tool is missing a name",
                    message="A tool was returned without a name field. "
                            "Clients cannot invoke a tool without a name.",
                    spec_ref="MCP Spec §6.1 — Tool Definition",
                    tool_name=tool.name,
                ))

            if not tool.input_schema:
                findings.append(Finding(
                    rule_id="CONF-012",
                    engine=EngineType.CONFORMANCE,
                    severity=FindingSeverity.WARNING,
                    title=f"Tool '{tool.name}' has no inputSchema",
                    message="Tool does not define its expected parameters. "
                            "Clients cannot know what arguments to pass.",
                    spec_ref="MCP Spec §6.1 — Tool Definition",
                    tool_name=tool.name,
                ))

            if tool.description is None or tool.description.strip() == "":
                findings.append(Finding(
                    rule_id="CONF-013",
                    engine=EngineType.CONFORMANCE,
                    severity=FindingSeverity.WARNING,
                    title=f"Tool '{tool.name}' has no description",
                    message="Tool has no description. While technically optional in the spec, "
                            "AI agents rely on descriptions to select the right tool.",
                    spec_ref="MCP Spec §6.1 — Tool Definition",
                    tool_name=tool.name,
                ))

            # Check inputSchema structure — should be a valid JSON Schema object
            if tool.input_schema:
                schema = tool.input_schema
                if schema.get("type") != "object":
                    findings.append(Finding(
                        rule_id="CONF-014",
                        engine=EngineType.CONFORMANCE,
                        severity=FindingSeverity.WARNING,
                        title=f"Tool '{tool.name}' inputSchema type is not 'object'",
                        message=(
                            f"inputSchema.type is '{schema.get('type')}' but should be 'object'. "
                            "MCP tool parameters are passed as a JSON object."
                        ),
                        spec_ref="MCP Spec §6.1 — Tool Definition",
                        tool_name=tool.name,
                    ))

                if "properties" not in schema and schema.get("type") == "object":
                    findings.append(Finding(
                        rule_id="CONF-015",
                        engine=EngineType.CONFORMANCE,
                        severity=FindingSeverity.INFO,
                        title=f"Tool '{tool.name}' inputSchema has no properties",
                        message="inputSchema is type 'object' but defines no properties. "
                                "Either this tool takes no parameters (consider documenting that) "
                                "or the properties are missing.",
                        spec_ref="MCP Spec §6.1 — Tool Definition",
                        tool_name=tool.name,
                    ))

        return findings

    async def _check_tool_invocation(self, client: MCPClient) -> list[Finding]:
        """Check tool invocation behavior — calling tools that don't exist.

        We don't call real tools here (that's the Behavior Engine's job).
        We test: does the server correctly reject calls to non-existent tools?
        """
        findings: list[Finding] = []

        # Test: calling a non-existent tool should return an error, not crash
        try:
            await client.call_tool("__nonexistent_tool_smartmcplint_test__", {})
            # If we get here, the server accepted a call to a fake tool — that's wrong
            findings.append(Finding(
                rule_id="CONF-020",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.WARNING,
                title="Server accepts calls to non-existent tools",
                message="Calling a tool that doesn't exist should return an error response, "
                        "but the server returned a success. This may indicate the server "
                        "doesn't validate tool names.",
                spec_ref="MCP Spec §6.2 — Tool Invocation",
            ))
        except MCPError:
            # Good — server correctly rejected the invalid tool call
            pass
        except TransportError as e:
            # Bad — server crashed instead of returning an error
            findings.append(Finding(
                rule_id="CONF-021",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.CRITICAL,
                title="Server crashed when called with non-existent tool",
                message=f"Instead of returning an error response, the server crashed: {e}. "
                        "Servers must handle invalid tool names gracefully.",
                spec_ref="MCP Spec §6.2 — Tool Invocation",
            ))

        return findings

    async def _check_error_handling(self, client: MCPClient) -> list[Finding]:
        """Check how the server handles invalid JSON-RPC messages.

        Uses send_raw() because we need to send intentionally malformed messages
        that the typed client methods wouldn't allow.
        """
        findings: list[Finding] = []

        # Test: unknown method should return error code -32601 (Method not found)
        response = await client.send_raw({
            "jsonrpc": "2.0",
            "id": 9901,
            "method": "__unknown_method_smartmcplint_test__",
        })

        if response:
            if "error" in response:
                error_code = response["error"].get("code")
                if error_code != -32601:
                    findings.append(Finding(
                        rule_id="CONF-030",
                        engine=EngineType.CONFORMANCE,
                        severity=FindingSeverity.WARNING,
                        title="Wrong error code for unknown method",
                        message=f"Server returned error code {error_code} for an unknown method. "
                                "JSON-RPC spec requires -32601 (Method not found).",
                        spec_ref="JSON-RPC 2.0 §5.1 — Error Codes",
                    ))
            elif "result" in response:
                findings.append(Finding(
                    rule_id="CONF-031",
                    engine=EngineType.CONFORMANCE,
                    severity=FindingSeverity.WARNING,
                    title="Server returned success for unknown method",
                    message="Server returned a result for a method that doesn't exist. "
                            "Unknown methods should return an error.",
                    spec_ref="JSON-RPC 2.0 §5.1 — Error Codes",
                ))
        else:
            findings.append(Finding(
                rule_id="CONF-032",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.WARNING,
                title="Server did not respond to unknown method",
                message=(
                    "Server produced no response for an unknown method request. "
                    "JSON-RPC requires a response (with an error) for every request with an id."
                ),
                spec_ref="JSON-RPC 2.0 §4 — Request",
            ))

        # Test: missing jsonrpc field
        response = await client.send_raw({
            "id": 9902,
            "method": "tools/list",
        })

        if response and "error" not in response:
            findings.append(Finding(
                rule_id="CONF-033",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.INFO,
                title="Server accepts request without jsonrpc field",
                message="Server processed a request missing the required 'jsonrpc': '2.0' field. "
                        "Strictly, this should be rejected, though many servers are lenient.",
                spec_ref="JSON-RPC 2.0 §4 — Request Object",
            ))

        return findings

    def _check_resources(self, client: MCPClient) -> list[Finding]:
        """Check resource-related conformance.

        Only runs meaningful checks if the server declared resource support.
        """
        findings: list[Finding] = []

        if client.server_info is None:
            return findings

        if not client.server_info.capabilities.resources:
            # Server doesn't claim resource support — nothing to check
            return findings

        if not client.resources:
            findings.append(Finding(
                rule_id="CONF-040",
                engine=EngineType.CONFORMANCE,
                severity=FindingSeverity.WARNING,
                title="Server declares resources capability but lists no resources",
                message="Server said it supports resources in capabilities, "
                        "but resources/list returned an empty list.",
                spec_ref="MCP Spec §7.1 — Resource Listing",
            ))
            return findings

        for resource in client.resources:
            if not resource.uri:
                findings.append(Finding(
                    rule_id="CONF-041",
                    engine=EngineType.CONFORMANCE,
                    severity=FindingSeverity.CRITICAL,
                    title="Resource is missing a URI",
                    message="A resource was returned without a URI. "
                            "Clients cannot access a resource without its URI.",
                    spec_ref="MCP Spec §7.1 — Resource Definition",
                ))

        return findings
