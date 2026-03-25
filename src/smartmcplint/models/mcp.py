"""Models representing MCP server data.

These are our internal representations of what we get back from MCP servers.
They are NOT used for strict validation of server responses — a broken server
response should become a Finding, not a crash.
"""

from typing import Any

from pydantic import BaseModel, Field


class ToolInfo(BaseModel):
    """An MCP tool as reported by the server."""

    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)


class ResourceInfo(BaseModel):
    """An MCP resource as reported by the server."""

    uri: str
    name: str | None = None
    description: str | None = None
    mime_type: str | None = None


class ServerCapabilities(BaseModel):
    """Server capabilities from the initialize response."""

    tools: bool = False
    resources: bool = False
    prompts: bool = False


class ServerInfo(BaseModel):
    """Metadata about the MCP server from initialization."""

    name: str = "unknown"
    version: str = "unknown"
    protocol_version: str = "unknown"
    capabilities: ServerCapabilities = Field(default_factory=ServerCapabilities)
