"""Quality Engine — LLM-as-Judge evaluation of MCP tool quality.

- Hybrid approach: rule-based checks run first (free, instant), then
  LLM judge checks run second (costs money, slower).
- Rule-based checks catch structural issues: missing descriptions,
  missing parameter types, invalid schemas.
- LLM checks evaluate semantic quality: clarity, disambiguation,
  parameter naming, return documentation.
- Tool disambiguation uses a funnel pattern: cheap word overlap filter
  narrows candidates, then LLM evaluates only suspicious pairs.
- All LLM calls go through utils/llm.py — never litellm directly.
- Skippable via config.skip_llm for environments without API keys.
"""

import logging
from itertools import combinations
from typing import Any

from smartmcplint.client import MCPClient
from smartmcplint.engines.base import BaseEngine
from smartmcplint.models.config import ScanConfig
from smartmcplint.models.enums import EngineType, FindingSeverity
from smartmcplint.models.findings import Finding
from smartmcplint.models.mcp import ToolInfo
from smartmcplint.utils.llm import call_llm_judge

logger = logging.getLogger(__name__)

# -- Constants --

MIN_DESCRIPTION_LENGTH = 10
WORD_OVERLAP_THRESHOLD = 0.3  # 30% shared words triggers LLM comparison

# Synonym map for disambiguation funnel — catches "delete" ↔ "remove" etc.
# Maps variants to a canonical form so word overlap detects semantic similarity.
ACTION_SYNONYMS: dict[str, str] = {
    "delete": "remove", "remove": "remove", "erase": "remove",
    "get": "fetch", "fetch": "fetch", "retrieve": "fetch",
    "read": "fetch", "load": "fetch",
    "send": "notify", "notify": "notify", "alert": "notify",
    "post": "notify", "emit": "notify",
    "create": "make", "make": "make", "add": "make",
    "insert": "make", "new": "make",
    "update": "modify", "modify": "modify", "edit": "modify",
    "change": "modify", "patch": "modify", "set": "modify",
    "list": "enumerate", "enumerate": "enumerate",
    "search": "find", "find": "find", "query": "find",
    "lookup": "find", "filter": "find",
}

# LLM evaluation tool schema — per-tool quality assessment.
# 6 yes/no questions covering QUAL-020, QUAL-022, and QUAL-023.
# The LLM "calls" this function to submit its structured evaluation.
TOOL_QUALITY_EVAL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "submit_tool_evaluation",
        "description": "Submit your evaluation of an MCP tool's quality.",
        "parameters": {
            "type": "object",
            "properties": {
                "when_to_use": {
                    "type": "boolean",
                    "description": (
                        "Can you determine WHEN to use this tool "
                        "(in what situation or context)?"
                    ),
                },
                "what_it_does": {
                    "type": "boolean",
                    "description": (
                        "Can you determine WHAT this tool does "
                        "(the specific action it performs)?"
                    ),
                },
                "side_effects_clear": {
                    "type": "boolean",
                    "description": (
                        "Are the tool's SIDE EFFECTS documented "
                        "(data modifications, external calls, etc.)?"
                    ),
                },
                "no_jargon": {
                    "type": "boolean",
                    "description": (
                        "Is the description free of unexplained "
                        "jargon or ambiguous terms?"
                    ),
                },
                "params_clear": {
                    "type": "boolean",
                    "description": (
                        "Are parameter names and descriptions clear "
                        "enough to construct valid arguments?"
                    ),
                },
                "return_documented": {
                    "type": "boolean",
                    "description": (
                        "Does the description explain what the tool "
                        "returns on success and failure?"
                    ),
                },
                "explanation": {
                    "type": "string",
                    "description": (
                        "Brief explanation of the most significant "
                        "quality issue, or 'No issues' if all pass."
                    ),
                },
            },
            "required": [
                "when_to_use", "what_it_does", "side_effects_clear",
                "no_jargon", "params_clear", "return_documented",
                "explanation",
            ],
        },
    },
}

# LLM evaluation tool schema — pairwise disambiguation.
DISAMBIGUATION_EVAL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "submit_disambiguation_evaluation",
        "description": (
            "Submit your evaluation of whether two MCP tools "
            "are confusable."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "confusable": {
                    "type": "boolean",
                    "description": (
                        "Could an AI agent reasonably confuse "
                        "these two tools?"
                    ),
                },
                "overlap": {
                    "type": "string",
                    "description": (
                        "What functionality or purpose overlaps "
                        "between the tools?"
                    ),
                },
                "suggestion": {
                    "type": "string",
                    "description": (
                        "How to better distinguish the tools "
                        "(rename, improve descriptions, merge, etc.)"
                    ),
                },
            },
            "required": ["confusable", "overlap", "suggestion"],
        },
    },
}


class QualityEngine(BaseEngine):
    """Evaluates MCP tool quality using rule-based checks and LLM judge.

    Like SecurityEngine, uses constructor injection for ScanConfig — needs
    skip_llm flag, llm_model, and timeout for LLM calls.
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    @property
    def engine_type(self) -> EngineType:
        return EngineType.QUALITY

    async def _run_checks(self, client: MCPClient) -> list[Finding]:
        """Run rule-based checks first, then LLM checks if enabled.

        Rule-based checks are free and instant — always run.
        LLM checks cost money and take time — skip if skip_llm is set.
        """
        findings: list[Finding] = []

        # Rule-based checks — always run
        findings.extend(self._check_schema_completeness(client))

        # LLM-based checks — only if enabled
        if self._config.skip_llm:
            logger.info("LLM quality checks skipped (skip_llm=True)")
            return findings

        findings.extend(await self._check_tool_quality(client))
        findings.extend(await self._check_tool_disambiguation(client))
        return findings

    # -- Helpers --

    def _normalize_words(self, text: str) -> set[str]:
        """Split text into words and normalize with synonym map.

        'Deletes a user' → {'remove', 'a', 'user'}
        Used by the disambiguation funnel to detect semantic overlap
        without an LLM call.
        """
        words = set()
        for word in text.lower().split():
            # Strip punctuation
            cleaned = word.strip(".,;:!?()[]{}\"'")
            if cleaned:
                # Replace with canonical synonym if one exists
                words.add(ACTION_SYNONYMS.get(cleaned, cleaned))
        return words

    def _compute_word_overlap(
        self,
        text_a: str,
        text_b: str,
    ) -> float:
        """Compute normalized word overlap between two texts.

        Returns a float 0.0 to 1.0. Uses synonym normalization so
        'delete' and 'remove' count as the same word.
        Divides by the smaller set to avoid penalizing longer descriptions.
        """
        words_a = self._normalize_words(text_a)
        words_b = self._normalize_words(text_b)
        if not words_a or not words_b:
            return 0.0
        intersection = words_a & words_b
        return len(intersection) / min(len(words_a), len(words_b))

    def _format_tool_for_prompt(self, tool: ToolInfo) -> str:
        """Format a tool's info into readable text for the LLM prompt.

        Produces a structured summary the LLM can evaluate. Includes
        parameter names, types, and descriptions — or flags them as
        missing so the LLM can factor that into its assessment.
        """
        lines = [
            f"Name: {tool.name}",
            f"Description: {tool.description or '[MISSING]'}",
        ]

        schema = tool.input_schema
        props = schema.get("properties", {}) if schema else {}

        if props:
            lines.append("Parameters:")
            for pname, pdef in props.items():
                if not isinstance(pdef, dict):
                    lines.append(f"  - {pname}: [invalid schema]")
                    continue
                ptype = pdef.get("type", "unspecified")
                pdesc = pdef.get("description", "")
                if pdesc:
                    lines.append(f"  - {pname} ({ptype}): {pdesc}")
                else:
                    lines.append(
                        f"  - {pname} ({ptype}): [no description]"
                    )
        else:
            lines.append("Parameters: none")

        return "\n".join(lines)

    # -- Check groups --

    def _check_schema_completeness(
        self, client: MCPClient,
    ) -> list[Finding]:
        """Rule-based quality checks. QUAL-010 to QUAL-013.

        Structural checks that don't need an LLM — missing fields,
        insufficient length, invalid schemas. These run even when
        skip_llm is True, so users always get basic quality feedback.
        """
        findings: list[Finding] = []

        for tool in client.tools:

            # QUAL-010: Description exists and meets minimum length
            # No description = critical (AI is completely blind).
            # Short description = warning (probably not enough context).
            if not tool.description:
                findings.append(Finding(
                    rule_id="QUAL-010",
                    engine=EngineType.QUALITY,
                    severity=FindingSeverity.CRITICAL,
                    title=f"Tool '{tool.name}' has no description",
                    message=(
                        "Tool has no description at all. An AI agent "
                        "cannot determine when or how to use this tool."
                    ),
                    tool_name=tool.name,
                ))
            elif len(tool.description.strip()) < MIN_DESCRIPTION_LENGTH:
                findings.append(Finding(
                    rule_id="QUAL-010",
                    engine=EngineType.QUALITY,
                    severity=FindingSeverity.WARNING,
                    title=(
                        f"Tool '{tool.name}' has a very short "
                        f"description ({len(tool.description.strip())} "
                        f"chars)"
                    ),
                    message=(
                        f"Description is only "
                        f"{len(tool.description.strip())} characters. "
                        f"Short descriptions often lack the context "
                        f"an AI agent needs to use the tool correctly."
                    ),
                    tool_name=tool.name,
                ))

            # QUAL-013: Input schema is a valid JSON Schema object
            # Must exist and have "type": "object". If the schema itself
            # is missing or malformed, skip parameter checks for this
            # tool — there are no parameters to inspect.
            schema = tool.input_schema
            if not schema:
                findings.append(Finding(
                    rule_id="QUAL-013",
                    engine=EngineType.QUALITY,
                    severity=FindingSeverity.WARNING,
                    title=f"Tool '{tool.name}' has no input schema",
                    message=(
                        "Tool has no input schema. An AI agent cannot "
                        "determine what arguments to provide."
                    ),
                    tool_name=tool.name,
                ))
                continue  # No schema → skip param checks

            if schema.get("type") != "object":
                findings.append(Finding(
                    rule_id="QUAL-013",
                    engine=EngineType.QUALITY,
                    severity=FindingSeverity.WARNING,
                    title=(
                        f"Tool '{tool.name}' input schema type "
                        f"is not 'object'"
                    ),
                    message=(
                        f"Input schema type is "
                        f"'{schema.get('type', 'missing')}' instead "
                        f"of 'object'. MCP tool parameters should be "
                        f"defined as a JSON Schema object."
                    ),
                    tool_name=tool.name,
                ))

            # Get properties for QUAL-011 and QUAL-012 checks
            properties = schema.get("properties", {})
            if not properties:
                continue  # No parameters declared — nothing to check

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                # QUAL-011: Parameter has a description
                # Without a description, the AI has only the name to
                # guess what value to provide. Names like "q" or "id"
                # are ambiguous without context.
                if not param_def.get("description"):
                    findings.append(Finding(
                        rule_id="QUAL-011",
                        engine=EngineType.QUALITY,
                        severity=FindingSeverity.WARNING,
                        title=(
                            f"Parameter '{param_name}' in tool "
                            f"'{tool.name}' has no description"
                        ),
                        message=(
                            f"Parameter '{param_name}' lacks a "
                            f"description. The AI agent must guess "
                            f"the expected value from the name alone."
                        ),
                        tool_name=tool.name,
                    ))

                # QUAL-012: Parameter has a type
                # Without a type, the AI doesn't know if the value
                # should be a string, number, boolean, or object.
                if not param_def.get("type"):
                    findings.append(Finding(
                        rule_id="QUAL-012",
                        engine=EngineType.QUALITY,
                        severity=FindingSeverity.WARNING,
                        title=(
                            f"Parameter '{param_name}' in tool "
                            f"'{tool.name}' has no type"
                        ),
                        message=(
                            f"Parameter '{param_name}' has no type "
                            f"specified. The AI agent cannot determine "
                            f"whether to send a string, number, "
                            f"boolean, or object."
                        ),
                        tool_name=tool.name,
                    ))

        return findings

    async def _check_tool_quality(
        self, client: MCPClient,
    ) -> list[Finding]:
        """LLM-judge per-tool quality. QUAL-020, QUAL-022, QUAL-023.

        One LLM call per tool — asks 6 yes/no questions covering
        description clarity, parameter quality, and return documentation.
        Skips tools with no description — they already got QUAL-010
        critical from rule-based checks.
        """
        findings: list[Finding] = []

        system_msg = (
            "You are an AI tool quality evaluator. You assess MCP "
            "server tools from the perspective of an AI agent that "
            "needs to decide which tool to call and how to call it. "
            "Be strict: if information is ambiguous or missing, "
            "answer the criterion as false."
        )

        for tool in client.tools:
            # Skip tools with no description — already flagged by
            # QUAL-010. The LLM would just confirm what we know.
            if not tool.description:
                continue

            tool_text = self._format_tool_for_prompt(tool)

            result = await call_llm_judge(
                model=self._config.llm_model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {
                        "role": "user",
                        "content": (
                            "Evaluate this MCP tool:\n\n"
                            f"{tool_text}\n\n"
                            "Answer each evaluation criterion based "
                            "on the tool's description and parameter "
                            "definitions."
                        ),
                    },
                ],
                eval_tool=TOOL_QUALITY_EVAL,
                timeout=self._config.timeout,
            )

            if result is None:
                logger.warning(
                    f"LLM judge failed for tool '{tool.name}' — "
                    f"skipping quality assessment"
                )
                continue

            # QUAL-020: Description clarity
            # Combine the 4 clarity criteria into one finding that
            # lists which aspects are missing. More actionable than
            # 4 separate findings for the same tool.
            failed_clarity = []
            if not result.get("when_to_use"):
                failed_clarity.append("when to use it")
            if not result.get("what_it_does"):
                failed_clarity.append("what it does")
            if not result.get("side_effects_clear"):
                failed_clarity.append("side effects")
            if not result.get("no_jargon"):
                failed_clarity.append("jargon-free language")

            if failed_clarity:
                explanation = result.get("explanation", "")
                findings.append(Finding(
                    rule_id="QUAL-020",
                    engine=EngineType.QUALITY,
                    severity=FindingSeverity.WARNING,
                    title=(
                        f"Tool '{tool.name}' description lacks "
                        f"clarity"
                    ),
                    message=(
                        f"Description is unclear on: "
                        f"{', '.join(failed_clarity)}. "
                        f"LLM assessment: {explanation}"
                    ),
                    tool_name=tool.name,
                ))

            # QUAL-022: Parameter naming quality
            if not result.get("params_clear"):
                explanation = result.get("explanation", "")
                findings.append(Finding(
                    rule_id="QUAL-022",
                    engine=EngineType.QUALITY,
                    severity=FindingSeverity.WARNING,
                    title=(
                        f"Tool '{tool.name}' has unclear parameter "
                        f"names or descriptions"
                    ),
                    message=(
                        f"Parameter names and descriptions are not "
                        f"clear enough for an AI agent to construct "
                        f"valid arguments. LLM assessment: "
                        f"{explanation}"
                    ),
                    tool_name=tool.name,
                ))

            # QUAL-023: Return/error documentation
            if not result.get("return_documented"):
                findings.append(Finding(
                    rule_id="QUAL-023",
                    engine=EngineType.QUALITY,
                    severity=FindingSeverity.INFO,
                    title=(
                        f"Tool '{tool.name}' does not document "
                        f"return values or error behavior"
                    ),
                    message=(
                        "Description does not explain what the tool "
                        "returns on success or failure. An AI agent "
                        "cannot anticipate or handle errors from "
                        "this tool."
                    ),
                    tool_name=tool.name,
                ))

        return findings

    async def _check_tool_disambiguation(
        self, client: MCPClient,
    ) -> list[Finding]:
        """LLM-judge pairwise disambiguation. QUAL-021.

        Funnel pattern:
        1. Generate all tool pairs (n choose 2)
        2. Cheap word overlap filter — keep pairs above threshold
        3. LLM evaluates only the suspicious pairs

        Example: 30 tools = 435 pairs. If 12 pass the filter,
        we make 12 LLM calls instead of 435.
        """
        findings: list[Finding] = []

        # Need at least 2 tools to compare
        if len(client.tools) < 2:
            return findings

        # Stage 1: Word overlap filter
        # Combine tool name + description for richer comparison.
        # Name alone might miss overlap ("send_message" vs "notify_user"
        # share no name words, but descriptions overlap).
        suspicious_pairs = []
        for tool_a, tool_b in combinations(client.tools, 2):
            text_a = f"{tool_a.name} {tool_a.description or ''}"
            text_b = f"{tool_b.name} {tool_b.description or ''}"
            overlap = self._compute_word_overlap(text_a, text_b)
            if overlap > WORD_OVERLAP_THRESHOLD:
                suspicious_pairs.append((tool_a, tool_b, overlap))

        if not suspicious_pairs:
            logger.debug(
                f"Disambiguation: no suspicious pairs among "
                f"{len(client.tools)} tools"
            )
            return findings

        logger.debug(
            f"Disambiguation: {len(suspicious_pairs)} suspicious "
            f"pairs from {len(client.tools)} tools"
        )

        # Stage 2: LLM comparison for suspicious pairs only
        system_msg = (
            "You are evaluating whether two MCP tools could be "
            "confused by an AI agent trying to pick the right tool. "
            "Two tools are confusable if an AI agent, given a user "
            "request, might reasonably call either one. Consider "
            "their names, descriptions, and parameter schemas."
        )

        for tool_a, tool_b, overlap in suspicious_pairs:
            tool_a_text = self._format_tool_for_prompt(tool_a)
            tool_b_text = self._format_tool_for_prompt(tool_b)

            result = await call_llm_judge(
                model=self._config.llm_model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {
                        "role": "user",
                        "content": (
                            "Could an AI agent confuse these two "
                            "tools?\n\n"
                            f"--- Tool A ---\n{tool_a_text}\n\n"
                            f"--- Tool B ---\n{tool_b_text}"
                        ),
                    },
                ],
                eval_tool=DISAMBIGUATION_EVAL,
                timeout=self._config.timeout,
            )

            if result is None:
                logger.warning(
                    f"LLM judge failed for pair "
                    f"'{tool_a.name}' / '{tool_b.name}' — skipping"
                )
                continue

            if result.get("confusable"):
                overlap_desc = result.get("overlap", "")
                suggestion = result.get("suggestion", "")
                findings.append(Finding(
                    rule_id="QUAL-021",
                    engine=EngineType.QUALITY,
                    severity=FindingSeverity.WARNING,
                    title=(
                        f"Tools '{tool_a.name}' and "
                        f"'{tool_b.name}' may be confused"
                    ),
                    message=(
                        f"An AI agent could confuse these tools. "
                        f"Overlap: {overlap_desc}. "
                        f"Suggestion: {suggestion}"
                    ),
                    tool_name=f"{tool_a.name}, {tool_b.name}",
                ))

        return findings
