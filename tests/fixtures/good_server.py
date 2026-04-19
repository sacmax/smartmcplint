#!/usr/bin/env python3
"""Well-behaved MCP fixture server for integration tests.

Speaks the MCP JSON-RPC protocol over stdio. Uses only stdlib.
Tools exposed:
  - get_time     : no required params — safe for behavior engine probing
  - echo_message : one required string param — exercises type/empty probes
"""

import json
import sys
from datetime import datetime, timezone

TOOLS = [
    {
        "name": "get_time",
        "description": (
            "Returns the current UTC time as an ISO 8601 string. "
            "Use this when the user wants to know what time it is."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "get_echo",
        "description": (
            "Returns the input message back to the caller unchanged. "
            "Use this to verify that the server can process string inputs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "The message to echo back.",
                },
            },
            "required": ["message"],
        },
    },
]

_TOOL_NAMES = {t["name"] for t in TOOLS}


def _send(response: dict) -> None:
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def _error(req_id: int, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def _handle(request: dict) -> None:
    method = request.get("method", "")
    req_id = request.get("id")

    # Notifications (no id) — no response required
    if req_id is None:
        return

    if method == "initialize":
        _send({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "good-fixture-server", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        })

    elif method == "tools/list":
        _send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

    elif method == "tools/call":
        params = request.get("params", {})
        name = params.get("name", "")
        arguments = params.get("arguments", {})

        if name not in _TOOL_NAMES:
            _error(req_id, -32602, f"Unknown tool: {name!r}")
            return

        if name == "get_time":
            now = datetime.now(timezone.utc).isoformat()
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": now}]},
            })

        elif name == "get_echo":
            message = arguments.get("message", "")
            if not isinstance(message, str):
                _error(req_id, -32602, "message must be a string")
                return
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": message}]},
            })

    else:
        _error(req_id, -32601, "Method not found")


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        _handle(request)


if __name__ == "__main__":
    main()
