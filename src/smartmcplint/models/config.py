"""Configuration models."""

from pydantic import BaseModel, Field


class EngineWeights(BaseModel):
    """Scoring weights for each engine. Must sum to 1.0 (excluding autofix bonus)."""

    conformance: float = 0.25
    security: float = 0.30
    quality: float = 0.25
    behavior: float = 0.15
    autofix_bonus: float = 0.05


class ScanConfig(BaseModel):
    """Configuration for a scan run, merged from CLI args + YAML + defaults."""

    transport: str = "stdio"
    server_cmd: list[str] = Field(default_factory=list, description="Command to start MCP server")
    server_url: str | None = Field(default=None, description="URL for HTTP transport")
    skip_llm: bool = False
    skip_engines: list[str] = Field(default_factory=list)
    min_score: int = 0
    output_format: str = "terminal"
    llm_model: str = "gpt-4o-mini"
    timeout: int = Field(default=30, description="Per-request timeout in seconds")
    weights: EngineWeights = Field(default_factory=EngineWeights)
    verbose: bool = False
