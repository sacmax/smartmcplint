"""Auto-Fix Engine — generates LLM-powered fix suggestions for scan findings.

Unlike the other four engines, this engine:
- Does NOT talk to the MCP server (no client parameter)
- Runs in Phase 2, after all other engines have produced findings
- Groups findings by rule_id — one LLM call per unique rule, not per finding instance
- Returns FixSuggestion objects, not Finding objects

Skipped entirely when skip_llm=True — all fixes require LLM calls.
"""

import logging
from collections import defaultdict
from typing import Any

from smartmcplint.models.config import ScanConfig
from smartmcplint.models.enums import EngineType, FindingSeverity
from smartmcplint.models.findings import Finding, FixSuggestion
from smartmcplint.utils.llm import call_llm_judge

logger = logging.getLogger(__name__)

# Only generate fixes for findings that matter — info is informational, not actionable.
_FIXABLE_SEVERITIES: frozenset[FindingSeverity] = frozenset({
    FindingSeverity.CRITICAL,
    FindingSeverity.WARNING,
})

# LLM tool schema for structured fix output.
_FIX_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "submit_fix",
        "description": "Submit a concrete fix suggestion for the reported issue.",
        "parameters": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short one-line title for the fix (max 80 chars).",
                },
                "description": {
                    "type": "string",
                    "description": (
                        "Explanation of why this is an issue and what the fix achieves. "
                        "2-4 sentences."
                    ),
                },
                "original": {
                    "type": "string",
                    "description": (
                        "Example of the problematic code, schema, or config as it currently is. "
                        "Omit if not applicable."
                    ),
                },
                "suggested": {
                    "type": "string",
                    "description": (
                        "The concrete fix: corrected code, schema, or config. "
                        "Be specific — not 'add a description' but the actual improved text."
                    ),
                },
            },
            "required": ["title", "description", "suggested"],
        },
    },
}


class AutoFixEngine:
    """Generates LLM-powered fix suggestions for findings from Phase 1 engines."""

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    async def generate(self, findings: list[Finding]) -> list[FixSuggestion]:
        """Generate fix suggestions for all fixable findings.

        Groups by rule_id so one LLM call covers all instances of the same issue.
        Returns an empty list when skip_llm=True.
        """
        if self._config.skip_llm:
            logger.info("skip_llm=True — skipping all Auto-Fix suggestions")
            return []

        fixable = [f for f in findings if f.severity in _FIXABLE_SEVERITIES]
        if not fixable:
            return []

        # Group findings by rule_id: one LLM call per unique rule
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in fixable:
            groups[finding.rule_id].append(finding)

        logger.info(
            f"Auto-Fix: generating suggestions for {len(groups)} unique rule(s) "
            f"across {len(fixable)} finding(s)"
        )

        suggestions: list[FixSuggestion] = []
        for rule_id, group in groups.items():
            suggestion = await self._generate_fix(rule_id, group)
            if suggestion is not None:
                suggestions.append(suggestion)

        return suggestions

    async def _generate_fix(
        self, rule_id: str, findings: list[Finding]
    ) -> FixSuggestion | None:
        """Call the LLM to generate a fix suggestion for one rule group."""
        representative = findings[0]
        affected_tools = sorted({f.tool_name for f in findings if f.tool_name})

        messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert on the Model Context Protocol (MCP). "
                    "You review MCP server scan findings and provide concrete, "
                    "actionable fix suggestions. Your fixes should be specific — "
                    "include example code, schema snippets, or config changes, "
                    "not vague advice."
                ),
            },
            {
                "role": "user",
                "content": self._build_prompt(rule_id, representative, affected_tools),
            },
        ]

        result = await call_llm_judge(
            model=self._config.llm_model,
            messages=messages,
            eval_tool=_FIX_TOOL,
            timeout=self._config.timeout,
        )

        if result is None:
            logger.warning(f"Auto-Fix: LLM call failed for rule {rule_id}, skipping")
            return None

        return FixSuggestion(
            finding_rule_id=rule_id,
            engine=EngineType.AUTOFIX,
            title=result.get("title", f"Fix for {rule_id}"),
            description=result.get("description", ""),
            original=result.get("original") or None,
            suggested=result.get("suggested", ""),
            tool_name=", ".join(affected_tools) if affected_tools else None,
        )

    def _build_prompt(
        self,
        rule_id: str,
        finding: Finding,
        affected_tools: list[str],
    ) -> str:
        """Build the user prompt for a fix suggestion LLM call."""
        lines = [
            "An MCP server scan found the following issue:",
            "",
            f"Rule ID:  {rule_id}",
            f"Severity: {finding.severity}",
            f"Title:    {finding.title}",
            f"Detail:   {finding.message}",
        ]

        if finding.spec_ref:
            lines.append(f"Spec ref: {finding.spec_ref}")

        if affected_tools:
            tools_str = ", ".join(affected_tools)
            lines.append(f"Affected tools: {tools_str}")

        lines += [
            "",
            "Provide a concrete fix suggestion. Include a specific code or schema "
            "example in your 'suggested' field — not general advice.",
        ]

        return "\n".join(lines)
