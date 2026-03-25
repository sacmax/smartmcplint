"""Engine result and scan result models."""

from datetime import datetime

from pydantic import BaseModel, Field

from smartmcplint.models.enums import EngineType, Grade
from smartmcplint.models.findings import Finding, FixSuggestion
from smartmcplint.models.mcp import ServerInfo


class EngineResult(BaseModel):
    """Output from a single scanning engine."""

    engine: EngineType
    score: float = Field(ge=0, le=100, description="Engine score 0-100")
    findings: list[Finding] = Field(default_factory=list)
    skipped: bool = Field(default=False, description="True if engine was skipped")
    skip_reason: str | None = None
    duration_ms: float = Field(default=0, description="How long the engine took")


class ScanResult(BaseModel):
    """The complete output of a SmartMCPLint scan."""

    server_info: ServerInfo
    engine_results: dict[EngineType, EngineResult] = Field(default_factory=dict)
    fix_suggestions: list[FixSuggestion] = Field(default_factory=list)
    overall_score: float = Field(ge=0, le=100)
    grade: Grade
    scan_timestamp: datetime = Field(default_factory=datetime.now)
    scan_duration_ms: float = 0
    smartmcplint_version: str = "0.1.0"
