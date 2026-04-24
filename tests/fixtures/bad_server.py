#!/usr/bin/env python3
"""Deliberately broken MCP fixture server for integration tests.

Each violation is intentional and maps to a specific conformance rule:
  CONF-002 — initialize response omits protocolVersion
  CONF-003 — initialize response omits serverInfo.name
  CONF-013 — tool has no description
  CONF-014 — tool inputSchema.type is "array" instead of "object"
  CONF-020 — calling a non-existent tool returns success instead of error
  CONF-030 — unknown method returns wrong error code (-32000, not -32601)
"""

import json
import sys

TOOLS = [
    {
        "name": "get_data",
        # No description — violates CONF-013
        "inputSchema": {
            "type": "array",  # Wrong type — violates CONF-014
            "items": {"type": "string"},
        },
    },
]

_TOOL_NAMES = {t["name"] for t in TOOLS}


def _send(response: dict) -> None:
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def _handle(request: dict) -> None:
    method = request.get("method", "")
    req_id = request.get("id")

    if req_id is None:
        return

    if method == "initialize":
        _send({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                # protocolVersion omitted — violates CONF-002
                "serverInfo": {
                    # name omitted — violates CONF-003
                    "version": "0.0.1",
                },
                "capabilities": {"tools": {}},
            },
        })

    elif method == "tools/list":
        _send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

    elif method == "tools/call":
        params = request.get("params", {})
        name = params.get("name", "")

        if name == "get_data":
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": "data"}]},
            })
        else:
            # Non-existent tool — should error, instead returns success (CONF-020)
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": "ok"}]},
            })

    else:
        # Wrong error code: -32000 instead of -32601 — violates CONF-030
        _send({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32000, "message": "Server error"},
        })


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
