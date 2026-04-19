"""MCP protocol client — sits between transport (raw JSON) and engines (business logic).

- Single file because it's one class with one job: speak MCP protocol.
- Engines call high-level methods (list_tools, call_tool), never touch JSON-RPC directly.
- Lenient parsing: bad server responses become sensible defaults, not crashes.
  The Conformance Engine separately checks whether responses are spec-compliant.
- send_raw() exists as an escape hatch for the Conformance Engine to test
  how servers handle intentionally malformed messages.
"""

import asyncio
import logging
from typing import Any

from smartmcplint.models.mcp import ResourceInfo, ServerCapabilities, ServerInfo, ToolInfo
from smartmcplint.transport import BaseTransport, TransportError

logger = logging.getLogger(__name__)


class MCPError(Exception):
    """Raised when the server returns a JSON-RPC error response.

    Different from TransportError:
    - TransportError = can't talk to the server at all (crashed, network down)
    - MCPError = server responded, but said "error" (method not found, invalid params)
    Engines need this distinction to decide: stop scanning vs. record a finding.
    """

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.error_message = message
        self.data = data
        super().__init__(f"MCP error {code}: {message}")


class MCPClient:
    """High-level MCP protocol client.

    - Takes a transport (stdio or HTTP) and provides typed methods.
    - Manages the JSON-RPC request ID counter.
    - Handles the initialization handshake.
    - Stores server_info after initialization for engines to access.
    """

    def __init__(self, transport: BaseTransport) -> None:
        self._transport = transport
        self._request_id = 0
        # Serializes concurrent engine requests through the single stdio pipe.
        # asyncio.gather runs all engines as concurrent tasks — without this lock,
        # two engines calling call_tool simultaneously would both await readline()
        # on the same stream, raising "readuntil() called while another coroutine
        # is already waiting for incoming data".
        self._lock = asyncio.Lock()
        # Populated after initialize() — engines read these directly.
        self.server_info: ServerInfo | None = None
        self.tools: list[ToolInfo] = []
        self.resources: list[ResourceInfo] = []

    def _next_id(self) -> int:
        """Generate the next request ID."""
        self._request_id += 1
        return self._request_id

    async def _send_request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send a JSON-RPC request and return the result.

        - Constructs the JSON-RPC envelope (jsonrpc, id, method, params).
        - Sends via transport, reads response, checks for errors.
        - Returns just the "result" field — callers don't deal with JSON-RPC framing.
        """
        async with self._lock:
            request = {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": method,
            }
            if params is not None:
                request["params"] = params

            logger.debug(f"Sending MCP request: method={method}, id={request['id']}")
            await self._transport.send(request)
            response = await self._transport.receive()

        # JSON-RPC error response — server understood us but rejected the request
        if "error" in response:
            error = response["error"]
            raise MCPError(
                code=error.get("code", -1),
                message=error.get("message", "Unknown error"),
                data=error.get("data"),
            )

        return response.get("result", {})

    async def _send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no response expected).

        Notifications have no "id" field — the server doesn't respond.
        Used for things like "initialized" where we're just informing the server.
        """
        notification: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            notification["params"] = params

        logger.debug(f"Sending MCP notification: method={method}")
        await self._transport.send(notification)

    async def initialize(self) -> ServerInfo:
        """Perform the MCP initialization handshake.

        MCP spec requires this sequence:
        1. Client sends "initialize" with client info and supported protocol version
        2. Server responds with its info, capabilities, and protocol version
        3. Client sends "notifications/initialized" to confirm

        After this, the session is ready for tool/resource discovery.
        """
        result = await self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "smartmcplint",
                "version": "0.1.0",
            },
        })

        # Lenient parsing: extract what we can, default what's missing.
        # A strict client would reject bad responses — we record them as findings later.
        server_info_raw = result.get("serverInfo", {})
        capabilities_raw = result.get("capabilities", {})

        self.server_info = ServerInfo(
            name=server_info_raw.get("name", "unknown"),
            version=server_info_raw.get("version", "unknown"),
            protocol_version=result.get("protocolVersion", "unknown"),
            capabilities=ServerCapabilities(
                tools="tools" in capabilities_raw,
                resources="resources" in capabilities_raw,
                prompts="prompts" in capabilities_raw,
            ),
        )

        # Step 3: confirm initialization
        await self._send_notification("notifications/initialized")

        logger.debug(
            f"MCP session initialized: server={self.server_info.name} "
            f"version={self.server_info.version} "
            f"protocol={self.server_info.protocol_version}"
        )
        return self.server_info

    async def list_tools(self) -> list[ToolInfo]:
        """Discover all tools the server exposes.

        Returns a list of ToolInfo models. Stores them on self.tools
        so engines can access them without re-fetching.
        """
        result = await self._send_request("tools/list")

        raw_tools = result.get("tools", [])
        self.tools = []
        for raw in raw_tools:
            # Lenient: if a tool is missing fields, use defaults rather than crashing
            self.tools.append(ToolInfo(
                name=raw.get("name", "unnamed"),
                description=raw.get("description"),
                input_schema=raw.get("inputSchema", {}),
            ))

        logger.debug(f"Discovered {len(self.tools)} tools")
        return self.tools

    async def list_resources(self) -> list[ResourceInfo]:
        """Discover all resources the server exposes.

        Not all servers support resources — if the capability isn't declared,
        engines should skip this. But we don't enforce that here; the engine decides.
        """
        result = await self._send_request("resources/list")

        raw_resources = result.get("resources", [])
        self.resources = []
        for raw in raw_resources:
            self.resources.append(ResourceInfo(
                uri=raw.get("uri", ""),
                name=raw.get("name"),
                description=raw.get("description"),
                mime_type=raw.get("mimeType"),
            ))

        logger.debug(f"Discovered {len(self.resources)} resources")
        return self.resources

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Invoke a tool on the server and return the result.

        Used by the Behavior Engine to test tools with various inputs.
        Returns the raw result — the engine interprets what it means.
        """
        result = await self._send_request("tools/call", {
            "name": name,
            "arguments": arguments or {},
        })
        return result

    async def send_raw(self, message: dict[str, Any]) -> dict[str, Any]:
        """Send an arbitrary JSON-RPC message and return the raw response.

        Escape hatch for the Conformance Engine. Normal engines should never
        use this — they use the typed methods above. This exists because
        conformance testing requires sending intentionally invalid messages
        (missing fields, wrong types, unknown methods) to see how the server reacts.
        """
        async with self._lock:
            await self._transport.send(message)
            try:
                return await self._transport.receive()
            except TransportError:
                # Server might not respond to invalid messages — that's a valid test outcome
                return {}
