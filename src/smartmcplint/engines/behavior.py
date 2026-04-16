"""Behavior Engine — runtime tool invocation testing.

Tests MCP tools by actually calling them with controlled inputs:
- Does the tool accept valid inputs without crashing?
- Does it return proper errors (not crashes) for invalid inputs?
- Is the response structure consistent across calls?
- Does it complete within acceptable latency?

Safety-first approach: write operations (create/update/delete/send/...) are
never invoked. Only read-like tools (get/list/search/...) are tested.
Ambiguous tool names that match neither list are also skipped.
"""

import asyncio
import logging
import time
from typing import Any, Literal

from smartmcplint.client import MCPClient, MCPError
from smartmcplint.engines.base import BaseEngine
from smartmcplint.models.config import ScanConfig
from smartmcplint.models.enums import EngineType, FindingSeverity
from smartmcplint.models.findings import Finding
from smartmcplint.models.mcp import ToolInfo
from smartmcplint.transport import TransportError

logger = logging.getLogger(__name__)

# Keywords that indicate a tool performs write operations — never invoke these.
# Conservative set: when in doubt, skip the tool.
WRITE_KEYWORDS: frozenset[str] = frozenset({
    "create", "update", "delete", "remove", "modify", "write",
    "send", "post", "put", "patch", "insert", "edit", "set",
    "reset", "clear", "purge", "destroy", "drop", "truncate",
    "upload", "save", "store", "add", "append", "push",
})

# Keywords that indicate a tool is safe to call (read-only operations).
READ_KEYWORDS: frozenset[str] = frozenset({
    "get", "list", "search", "fetch", "read", "query",
    "find", "show", "describe", "check", "validate", "ping",
    "status", "health", "info", "count", "inspect", "view",
    "lookup", "scan", "analyze", "summary", "report",
})

# Maximum acceptable end-to-end response time. Tools slower than this get a
# warning — 5 seconds is generous for a local or well-connected remote server.
LATENCY_THRESHOLD_MS: int = 5_000

# Per-probe call timeout. Shorter than ScanConfig.timeout because we're
# testing individual tool invocations, not the whole session.
CALL_TIMEOUT_S: int = 10

# Recognizable marker used as a synthetic value for string parameters.
# Semantically meaningless to the server — won't accidentally trigger real logic.
PROBE_STRING: str = "smartmcplint_probe_7f3a"

# Deliberately invalid values for wrong-type probes (BEH-012)
PROBE_WRONG_STRING: str = "smartmcplint_not_a_number"
PROBE_WRONG_INT: int = 42
PROBE_INVALID_ENUM: str = "smartmcplint_invalid_enum"


class BehaviorEngine(BaseEngine):
    """Tests MCP tools by actually invoking them with controlled inputs.

    Only calls tools classified as read-like (safe). Write operations and
    ambiguous tool names are skipped and surfaced as BEH-030 (INFO).
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    @property
    def engine_type(self) -> EngineType:
        return EngineType.BEHAVIOR

    # -------------------------------------------------------------------------
    # Tool classification
    # -------------------------------------------------------------------------

    def _classify_tool(self, tool: ToolInfo) -> Literal["safe", "write", "unknown"]:
        """Classify a tool based on its name.

        Name is the most reliable signal — descriptions often reference write
        operations in context without being write operations themselves
        (e.g., "returns a list of recently deleted files" is still a read).

        Ordering matters: check WRITE_KEYWORDS first so a tool named
        'get_deleted_records' hits 'get' (safe) before 'deleted' isn't checked
        as a keyword, while 'delete_records' correctly hits 'delete' (write).
        """
        name_lower = tool.name.lower()

        if any(kw in name_lower for kw in WRITE_KEYWORDS):
            return "write"

        if any(kw in name_lower for kw in READ_KEYWORDS):
            return "safe"

        return "unknown"

    # -------------------------------------------------------------------------
    # Input generation
    # -------------------------------------------------------------------------

    def _generate_valid_inputs(self, tool: ToolInfo) -> dict[str, Any]:
        """Generate minimum valid inputs from the tool's input_schema.

        Only includes required parameters — optional params are omitted to keep
        the probe minimal. Uses PROBE_STRING for strings, the first enum value
        for enum-constrained fields, and zero-values for other types.
        """
        schema = tool.input_schema
        properties: dict[str, Any] = schema.get("properties", {})
        required: set[str] = set(schema.get("required", []))

        inputs: dict[str, Any] = {}

        for param_name, param_schema in properties.items():
            if param_name not in required:
                continue  # omit optional params — minimum valid footprint

            # Enum-constrained field: first enum value is always valid
            enum_values: list[Any] | None = param_schema.get("enum")
            if enum_values:
                inputs[param_name] = enum_values[0]
                continue

            param_type: str = param_schema.get("type", "string")
            if param_type == "string":
                inputs[param_name] = PROBE_STRING
            elif param_type == "integer":
                inputs[param_name] = 0
            elif param_type == "number":
                inputs[param_name] = 0.0
            elif param_type == "boolean":
                inputs[param_name] = False
            elif param_type == "array":
                inputs[param_name] = []
            elif param_type == "object":
                inputs[param_name] = {}
            else:
                inputs[param_name] = PROBE_STRING  # fallback for unknown types

        return inputs

    def _generate_wrong_type_inputs(
        self, tool: ToolInfo
    ) -> tuple[dict[str, Any], str] | None:
        """Generate inputs where one required param has the wrong type.

        Returns (inputs_dict, param_name) for the first type-testable required
        param, or None if no such param exists. All other required params keep
        their valid probe values so the server rejects specifically because of
        the type violation, not because of missing params.
        """
        schema = tool.input_schema
        properties: dict[str, Any] = schema.get("properties", {})
        required: set[str] = set(schema.get("required", []))

        valid = self._generate_valid_inputs(tool)

        for param_name, param_schema in properties.items():
            if param_name not in required:
                continue

            enum_values: list[Any] | None = param_schema.get("enum")
            param_type: str = param_schema.get("type", "string")

            wrong_value: Any
            if enum_values:
                wrong_value = PROBE_INVALID_ENUM
            elif param_type == "string":
                wrong_value = PROBE_WRONG_INT
            elif param_type in ("integer", "number"):
                wrong_value = PROBE_WRONG_STRING
            elif param_type == "boolean":
                wrong_value = PROBE_WRONG_STRING
            elif param_type == "array":
                wrong_value = PROBE_WRONG_STRING
            elif param_type == "object":
                wrong_value = PROBE_WRONG_STRING
            else:
                continue  # No meaningful wrong type for this param

            return {**valid, param_name: wrong_value}, param_name

        return None

    def _generate_empty_string_inputs(
        self, tool: ToolInfo
    ) -> tuple[dict[str, Any], str] | None:
        """Generate inputs where the first required string param is set to "".

        Returns (inputs_dict, param_name) or None if no required string param
        exists. All other required params keep their valid probe values.
        """
        schema = tool.input_schema
        properties: dict[str, Any] = schema.get("properties", {})
        required: set[str] = set(schema.get("required", []))

        valid = self._generate_valid_inputs(tool)

        for param_name, param_schema in properties.items():
            if param_name not in required:
                continue
            if param_schema.get("enum"):
                continue  # Enum-constrained — empty string is a type violation, not "empty"
            if param_schema.get("type", "string") != "string":
                continue

            return {**valid, param_name: ""}, param_name

        return None

    # -------------------------------------------------------------------------
    # Liveness probe
    # -------------------------------------------------------------------------

    async def _liveness_probe(self, client: MCPClient) -> bool:
        """Check if the server is still responsive after a bad-input probe.

        Re-issues tools/list — a standard read request that any live server
        must be able to answer. Returns False if the server doesn't respond
        within CALL_TIMEOUT_S, indicating it may have crashed.
        """
        try:
            await asyncio.wait_for(
                client.list_tools(),
                timeout=CALL_TIMEOUT_S,
            )
            return True
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # BEH-010 + BEH-021: valid call and latency
    # -------------------------------------------------------------------------

    async def _check_valid_call(
        self, client: MCPClient, tool: ToolInfo
    ) -> list[Finding]:
        """BEH-010: tool responds without crashing on valid inputs.
        BEH-021: response time stays within LATENCY_THRESHOLD_MS.

        MCPError (proper JSON-RPC error) is a passing outcome — the server
        handled the probe correctly even if our synthetic values were rejected.
        Only TimeoutError or TransportError indicate a real problem.
        """
        findings: list[Finding] = []
        valid_inputs = self._generate_valid_inputs(tool)

        start = time.perf_counter()
        try:
            await asyncio.wait_for(
                client.call_tool(tool.name, valid_inputs),
                timeout=CALL_TIMEOUT_S,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.debug(f"BEH-010 pass: '{tool.name}' responded in {elapsed_ms:.0f}ms")

        except MCPError as e:
            # A proper JSON-RPC error response — server is alive and speaking protocol.
            # Probe values may not be semantically valid so errors are expected.
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.debug(
                f"BEH-010 pass (error response): '{tool.name}' "
                f"returned MCPError {e.code}: {e.error_message}"
            )

        except TimeoutError:
            findings.append(Finding(
                rule_id="BEH-010",
                engine=EngineType.BEHAVIOR,
                severity=FindingSeverity.CRITICAL,
                title=f"Tool '{tool.name}' timed out after {CALL_TIMEOUT_S}s",
                message=(
                    f"The tool did not respond within {CALL_TIMEOUT_S} seconds when "
                    "called with valid inputs. The server may be hanging or "
                    "computationally blocked. Agent frameworks abandon tools that "
                    "don't respond promptly."
                ),
                tool_name=tool.name,
            ))
            return findings  # Already over timeout — latency check meaningless

        except TransportError:
            findings.append(Finding(
                rule_id="BEH-010",
                engine=EngineType.BEHAVIOR,
                severity=FindingSeverity.CRITICAL,
                title=f"Tool '{tool.name}' crashed the server connection",
                message=(
                    "The server connection dropped while invoking this tool with valid "
                    "inputs. The server process may have crashed. Subsequent tool "
                    "calls on this session will fail."
                ),
                tool_name=tool.name,
            ))
            return findings

        # BEH-021: latency check — runs for both success and MCPError paths
        if elapsed_ms > LATENCY_THRESHOLD_MS:
            findings.append(Finding(
                rule_id="BEH-021",
                engine=EngineType.BEHAVIOR,
                severity=FindingSeverity.WARNING,
                title=f"Tool '{tool.name}' responded slowly ({elapsed_ms:.0f}ms)",
                message=(
                    f"Response time of {elapsed_ms:.0f}ms exceeds the "
                    f"{LATENCY_THRESHOLD_MS}ms threshold. Slow tools degrade "
                    "user experience when chained in agent workflows."
                ),
                tool_name=tool.name,
            ))

        return findings

    # -------------------------------------------------------------------------
    # BEH-011 / BEH-012 / BEH-013: bad input resilience
    # -------------------------------------------------------------------------

    async def _probe_bad_input(
        self,
        client: MCPClient,
        tool: ToolInfo,
        inputs: dict[str, Any],
        rule_id: str,
        accepted_title: str,
        accepted_message: str,
        crash_title: str,
        crash_message: str,
    ) -> tuple[list[Finding], bool]:
        """Call a tool with bad inputs and classify the response.

        Returns (findings, server_still_alive).
        - MCPError  → pass (server validated correctly), alive=True
        - success   → WARNING (missing validation), alive=True
        - Timeout   → CRITICAL, alive=False
        - Transport → CRITICAL, alive=False
        """
        try:
            await asyncio.wait_for(
                client.call_tool(tool.name, inputs),
                timeout=CALL_TIMEOUT_S,
            )
            # Server accepted bad inputs — input validation is missing
            return [Finding(
                rule_id=rule_id,
                engine=EngineType.BEHAVIOR,
                severity=FindingSeverity.WARNING,
                title=accepted_title,
                message=accepted_message,
                tool_name=tool.name,
            )], True

        except MCPError:
            logger.debug(f"{rule_id} pass: '{tool.name}' correctly rejected bad inputs")
            return [], True

        except TimeoutError:
            return [Finding(
                rule_id=rule_id,
                engine=EngineType.BEHAVIOR,
                severity=FindingSeverity.CRITICAL,
                title=crash_title,
                message=crash_message,
                tool_name=tool.name,
            )], False

        except TransportError:
            return [Finding(
                rule_id=rule_id,
                engine=EngineType.BEHAVIOR,
                severity=FindingSeverity.CRITICAL,
                title=crash_title,
                message=crash_message,
                tool_name=tool.name,
            )], False

    async def _check_bad_inputs(
        self, client: MCPClient, tool: ToolInfo
    ) -> list[Finding]:
        """BEH-011, BEH-012, BEH-013: test server resilience to invalid inputs.

        Short-circuits on server crash — no point sending more bad inputs to
        a dead connection.
        """
        findings: list[Finding] = []
        required: set[str] = set(tool.input_schema.get("required", []))

        # BEH-011: call with ALL required params missing (empty dict)
        if required:
            f, alive = await self._probe_bad_input(
                client=client,
                tool=tool,
                inputs={},
                rule_id="BEH-011",
                accepted_title=(
                    f"Tool '{tool.name}' accepted a call with no required parameters"
                ),
                accepted_message=(
                    "The tool returned success when called without any required "
                    "parameters. This suggests required parameter validation is not "
                    "enforced, which may cause unpredictable behavior or silent failures."
                ),
                crash_title=(
                    f"Tool '{tool.name}' crashed when called without required parameters"
                ),
                crash_message=(
                    "The server hung or dropped the connection when called without "
                    "required parameters. Well-behaved servers return a JSON-RPC "
                    "validation error. This indicates missing error handling that can "
                    "crash agent workflows."
                ),
            )
            findings.extend(f)
            if not alive:
                return findings  # Server dead — skip remaining tests

        # BEH-012: call with wrong type for one required param
        wrong_type_result = self._generate_wrong_type_inputs(tool)
        if wrong_type_result is not None:
            wrong_inputs, param_name = wrong_type_result
            f, alive = await self._probe_bad_input(
                client=client,
                tool=tool,
                inputs=wrong_inputs,
                rule_id="BEH-012",
                accepted_title=(
                    f"Tool '{tool.name}' accepted a wrong-type value for '{param_name}'"
                ),
                accepted_message=(
                    f"The tool returned success when '{param_name}' was given a "
                    "deliberately wrong type. Type constraints in the input_schema are "
                    "not being enforced at runtime."
                ),
                crash_title=(
                    f"Tool '{tool.name}' crashed on a wrong-type value for '{param_name}'"
                ),
                crash_message=(
                    f"The server hung or dropped the connection when '{param_name}' "
                    "received a wrong-type value. Servers should return a validation "
                    "error rather than crashing."
                ),
            )
            findings.extend(f)
            if not alive:
                return findings

        # BEH-013: call with empty string for a required string param
        empty_result = self._generate_empty_string_inputs(tool)
        if empty_result is not None:
            empty_inputs, param_name = empty_result
            f, _ = await self._probe_bad_input(
                client=client,
                tool=tool,
                inputs=empty_inputs,
                rule_id="BEH-013",
                accepted_title=(
                    f"Tool '{tool.name}' accepted an empty string for '{param_name}'"
                ),
                accepted_message=(
                    f"The tool returned success when the required string parameter "
                    f"'{param_name}' was set to \"\". Empty required strings often "
                    "indicate missing input validation and may cause silent failures."
                ),
                crash_title=(
                    f"Tool '{tool.name}' crashed on empty string for '{param_name}'"
                ),
                crash_message=(
                    f"The server hung or dropped the connection when '{param_name}' "
                    "was set to an empty string. Servers should return a validation "
                    "error rather than crashing."
                ),
            )
            findings.extend(f)

        return findings

    # -------------------------------------------------------------------------
    # BEH-020: response structure consistency
    # -------------------------------------------------------------------------

    def _extract_structure(self, response: Any) -> frozenset[str]:
        """Extract the set of top-level keys from a dict response.

        Returns an empty frozenset for non-dict responses (lists, strings,
        primitives) — those have no key structure to compare.
        """
        if isinstance(response, dict):
            return frozenset(response.keys())
        return frozenset()

    async def _check_response_consistency(
        self, client: MCPClient, tool: ToolInfo
    ) -> list[Finding]:
        """BEH-020: two identical calls should return the same response structure.

        Checks for two forms of inconsistency:
        - Structural: same inputs, different top-level keys in the response
        - Outcome: one call succeeds, the other returns MCPError (flapping)
        """
        valid_inputs = self._generate_valid_inputs(tool)

        # First call
        r1: Any = None
        r1_is_error = False
        try:
            r1 = await asyncio.wait_for(
                client.call_tool(tool.name, valid_inputs),
                timeout=CALL_TIMEOUT_S,
            )
        except MCPError:
            r1_is_error = True
        except (TimeoutError, TransportError):
            return []  # Server unhealthy — skip consistency test

        # Second call
        r2: Any = None
        r2_is_error = False
        try:
            r2 = await asyncio.wait_for(
                client.call_tool(tool.name, valid_inputs),
                timeout=CALL_TIMEOUT_S,
            )
        except MCPError:
            r2_is_error = True
        except (TimeoutError, TransportError):
            return []

        # Both errored — no structure to compare
        if r1_is_error and r2_is_error:
            return []

        # One succeeded, one errored — non-deterministic outcome
        if r1_is_error != r2_is_error:
            return [Finding(
                rule_id="BEH-020",
                engine=EngineType.BEHAVIOR,
                severity=FindingSeverity.WARNING,
                title=f"Tool '{tool.name}' returned inconsistent success/error outcomes",
                message=(
                    "Two identical calls to the tool returned different outcomes — one "
                    "succeeded and one returned an error. Non-deterministic tool behavior "
                    "makes agent workflows unreliable."
                ),
                tool_name=tool.name,
            )]

        # Both succeeded — compare top-level key structure
        struct1 = self._extract_structure(r1)
        struct2 = self._extract_structure(r2)

        if struct1 != struct2:
            missing = struct1 - struct2
            added = struct2 - struct1
            parts: list[str] = []
            if missing:
                parts.append(f"Keys missing in second call: {', '.join(sorted(missing))}")
            if added:
                parts.append(f"Keys added in second call: {', '.join(sorted(added))}")

            return [Finding(
                rule_id="BEH-020",
                engine=EngineType.BEHAVIOR,
                severity=FindingSeverity.WARNING,
                title=f"Tool '{tool.name}' returned inconsistent response structure",
                message=(
                    "Two identical calls returned different top-level response keys. "
                    "LLM agent frameworks rely on consistent schemas to parse tool "
                    "outputs reliably.\n" + "\n".join(parts)
                ),
                tool_name=tool.name,
            )]

        return []

    # -------------------------------------------------------------------------
    # Per-tool behavioral checks
    # -------------------------------------------------------------------------

    async def _check_tool_behavior(
        self, client: MCPClient, tool: ToolInfo
    ) -> list[Finding]:
        """Run all applicable behavioral checks against a single safe tool."""
        findings: list[Finding] = []

        valid_call_findings = await self._check_valid_call(client, tool)
        findings.extend(valid_call_findings)

        # Don't run further checks against an already-unresponsive server —
        # findings from those calls would be TransportError false positives.
        server_crashed_on_valid = any(
            f.rule_id == "BEH-010" and f.severity == FindingSeverity.CRITICAL
            for f in valid_call_findings
        )
        if not server_crashed_on_valid:
            findings.extend(await self._check_bad_inputs(client, tool))
            findings.extend(await self._check_response_consistency(client, tool))

        return findings

    # -------------------------------------------------------------------------
    # BEH-030: skipped tools report
    # -------------------------------------------------------------------------

    def _report_skipped_tools(
        self,
        write_tools: list[ToolInfo],
        unknown_tools: list[ToolInfo],
    ) -> Finding:
        """BEH-030: Report which tools were not behaviorally tested and why."""
        parts: list[str] = []
        if write_tools:
            names = ", ".join(t.name for t in write_tools)
            parts.append(f"Write operations skipped ({len(write_tools)}): {names}")
        if unknown_tools:
            names = ", ".join(t.name for t in unknown_tools)
            parts.append(f"Ambiguous tools skipped ({len(unknown_tools)}): {names}")

        total = len(write_tools) + len(unknown_tools)

        return Finding(
            rule_id="BEH-030",
            engine=EngineType.BEHAVIOR,
            severity=FindingSeverity.INFO,
            title=f"{total} tool(s) skipped — write or ambiguous names",
            message=(
                "Behavioral testing only invokes read-like tools to avoid unintended "
                "side effects. Write operations and ambiguous tool names are skipped.\n"
                + "\n".join(parts)
            ),
        )

    # -------------------------------------------------------------------------
    # Engine entry point
    # -------------------------------------------------------------------------

    async def _run_checks(self, client: MCPClient) -> list[Finding]:
        """Classify all tools, skip unsafe ones, test the rest."""
        findings: list[Finding] = []
        tools = client.tools

        if not tools:
            return findings

        safe_tools: list[ToolInfo] = []
        write_tools: list[ToolInfo] = []
        unknown_tools: list[ToolInfo] = []

        for tool in tools:
            classification = self._classify_tool(tool)
            if classification == "safe":
                safe_tools.append(tool)
            elif classification == "write":
                write_tools.append(tool)
            else:
                unknown_tools.append(tool)

        logger.debug(
            f"Tool classification: {len(safe_tools)} safe, "
            f"{len(write_tools)} write, {len(unknown_tools)} unknown"
        )

        # BEH-030: always report what was skipped so users know coverage
        if write_tools or unknown_tools:
            findings.append(self._report_skipped_tools(write_tools, unknown_tools))

        # Run behavioral checks on safe tools only
        for tool in safe_tools:
            tool_findings = await self._check_tool_behavior(client, tool)
            findings.extend(tool_findings)

        return findings
