"""Finding and fix suggestion models."""

from pydantic import BaseModel, Field

from smartmcplint.models.enums import EngineType, FindingSeverity


class Finding(BaseModel):
    """A single issue found by any engine.

    This is the universal output type — every engine produces Findings.
    The scorer, reporter, and auto-fix engine all consume them.
    """

    rule_id: str = Field(description="Unique rule identifier, e.g. 'CONF-001', 'SEC-010'")
    engine: EngineType
    severity: FindingSeverity
    title: str = Field(description="Short one-line summary")
    message: str = Field(description="Detailed explanation of the issue")
    spec_ref: str | None = Field(default=None, description="MCP spec section reference")
    cwe_id: str | None = Field(default=None, description="CWE ID for security findings")
    tool_name: str | None = Field(default=None, description="Which tool this finding relates to")


class FixSuggestion(BaseModel):
    """A concrete fix suggestion from the Auto-Fix Engine."""

    finding_rule_id: str = Field(description="The rule_id of the finding this fixes")
    engine: EngineType
    title: str
    description: str = Field(description="Explanation of what the fix does and why")
    original: str | None = Field(default=None, description="Original code or config snippet")
    suggested: str = Field(description="The suggested replacement code or config")
    tool_name: str | None = Field(default=None, description="Which tool this fix targets")
