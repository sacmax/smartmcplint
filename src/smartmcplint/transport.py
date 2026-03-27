"""Transport abstraction for MCP server communication.

- Abstract base class (not Protocol) because we own both implementations
  and they share lifecycle concerns (connect/disconnect/context manager).
- Single file because two classes serve one purpose — splitting would
  mean navigating between files to compare implementations.
- Async throughout because both stdio (subprocess pipes) and HTTP (network I/O)
  are naturally async operations. Sync wrappers would block the event loop.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class TransportError(Exception):
    """Raised when transport-level communication fails.

    Separate from MCP protocol errors — this is "can't talk to the server at all"
    vs. "server responded with an error."
    """


class BaseTransport(ABC):
    """Abstract transport layer for MCP server communication.

    - connect()/disconnect() manage the lifecycle.
    - send()/receive() handle individual messages.
    - Context manager ensures cleanup even if engines crash mid-scan.
    """

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the MCP server."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection and clean up resources."""

    @abstractmethod
    async def send(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC message to the server."""

    @abstractmethod
    async def receive(self) -> dict[str, Any]:
        """Receive a JSON-RPC response from the server."""

    async def __aenter__(self) -> "BaseTransport":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.disconnect()


class StdioTransport(BaseTransport):
    """Communicates with an MCP server via subprocess stdin/stdout.

    - Spawns the server as a child process.
    - Writes JSON lines to stdin, reads JSON lines from stdout.
    - MCP stdio protocol: one JSON object per line, delimited by newlines.
    - Stderr is captured separately for error reporting if the server crashes.
    """

    def __init__(self, command: list[str], timeout: int = 30) -> None:
        # command is the full argv to spawn, e.g. ["python", "my_server.py"]
        self._command = command
        self._timeout = timeout
        self._process: asyncio.subprocess.Process | None = None

    async def connect(self) -> None:
        """Spawn the server subprocess and attach to its pipes."""
        try:
            self._process = await asyncio.create_subprocess_exec(
                *self._command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            logger.debug(f"Started MCP server process: {' '.join(self._command)} (pid={self._process.pid})")
        except FileNotFoundError as e:
            raise TransportError(f"Server command not found: {self._command[0]}") from e
        except OSError as e:
            raise TransportError(f"Failed to start server process: {e}") from e

    async def disconnect(self) -> None:
        """Terminate the server subprocess and clean up."""
        if self._process is None:
            return

        if self._process.returncode is None:
            # Process still running — terminate gracefully, then force kill
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
            logger.debug(f"Stopped MCP server process (pid={self._process.pid})")

    async def send(self, message: dict[str, Any]) -> None:
        """Write a JSON-RPC message to the server's stdin."""
        if self._process is None or self._process.stdin is None:
            raise TransportError("Not connected — call connect() first")

        # MCP stdio: one JSON object per line
        line = json.dumps(message) + "\n"
        try:
            self._process.stdin.write(line.encode())
            await self._process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as e:
            stderr = await self._read_stderr()
            raise TransportError(f"Server process crashed. Stderr: {stderr}") from e

    async def receive(self) -> dict[str, Any]:
        """Read a JSON-RPC response from the server's stdout."""
        if self._process is None or self._process.stdout is None:
            raise TransportError("Not connected — call connect() first")

        try:
            line = await asyncio.wait_for(
                self._process.stdout.readline(),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as e:
            raise TransportError(
                f"Server did not respond within {self._timeout}s"
            ) from e

        if not line:
            # Empty read means the process exited
            stderr = await self._read_stderr()
            raise TransportError(f"Server process exited unexpectedly. Stderr: {stderr}")

        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            raise TransportError(f"Server sent invalid JSON: {line.decode().strip()!r}") from e

    async def _read_stderr(self) -> str:
        """Read whatever the server wrote to stderr — useful for crash diagnostics."""
        if self._process is None or self._process.stderr is None:
            return "(no stderr available)"
        try:
            stderr = await asyncio.wait_for(self._process.stderr.read(), timeout=2)
            return stderr.decode().strip() or "(empty stderr)"
        except asyncio.TimeoutError:
            return "(stderr read timed out)"


class HttpTransport(BaseTransport):
    """Communicates with an MCP server via HTTP POST requests.

    - Uses httpx for async HTTP.
    - Each send() is a POST with JSON body, receive() reads the response.
    - MCP over HTTP: POST JSON-RPC to a single endpoint.
    - Stateless per-request, but we maintain a client for connection pooling.
    """

    def __init__(self, url: str, timeout: int = 30) -> None:
        self._url = url
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        # Buffer for the last response — HTTP is request/response,
        # so receive() returns what the last send() got back.
        self._last_response: dict[str, Any] | None = None

    async def connect(self) -> None:
        """Create the HTTP client (connection pool)."""
        self._client = httpx.AsyncClient(timeout=self._timeout)
        # Verify the server is reachable
        try:
            response = await self._client.get(self._url)
            logger.debug(f"Connected to MCP server at {self._url} (status={response.status_code})")
        except httpx.ConnectError as e:
            raise TransportError(f"Cannot connect to {self._url}: {e}") from e

    async def disconnect(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            logger.debug(f"Disconnected from {self._url}")

    async def send(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC message via HTTP POST."""
        if self._client is None:
            raise TransportError("Not connected — call connect() first")

        try:
            response = await self._client.post(self._url, json=message)
            response.raise_for_status()
            self._last_response = response.json()
        except httpx.ConnectError as e:
            raise TransportError(f"Connection lost to {self._url}: {e}") from e
        except httpx.TimeoutException as e:
            raise TransportError(f"Server at {self._url} did not respond within {self._timeout}s") from e
        except httpx.HTTPStatusError as e:
            raise TransportError(f"Server returned HTTP {e.response.status_code}: {e.response.text}") from e

    async def receive(self) -> dict[str, Any]:
        """Return the response from the last send().

        HTTP is request/response — unlike stdio where send and receive are separate
        streams, here the response comes back from the same POST request.
        """
        if self._last_response is None:
            raise TransportError("No response available — call send() first")
        response = self._last_response
        self._last_response = None
        return response


def create_transport(
    transport_type: str,
    server_cmd: list[str] | None = None,
    server_url: str | None = None,
    timeout: int = 30,
) -> BaseTransport:
    """Factory function to create the right transport based on config.

    - Factory pattern (not if/else in the caller) because transport creation
      involves validation that belongs here, not in the CLI or orchestrator.
    - Returns BaseTransport so the caller doesn't know the concrete type.
    """
    if transport_type == "stdio":
        if not server_cmd:
            raise TransportError("stdio transport requires a server command")
        return StdioTransport(command=server_cmd, timeout=timeout)
    elif transport_type == "http":
        if not server_url:
            raise TransportError("HTTP transport requires a server URL")
        return HttpTransport(url=server_url, timeout=timeout)
    else:
        raise TransportError(f"Unknown transport type: {transport_type!r}")
