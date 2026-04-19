"""LLM helper — single entry point for all LLM calls in SmartMCPLint.

- All engines call this module, never litellm directly.
- Uses tool/function calling for structured output — the LLM fills in
  a schema-enforced JSON response, not free-form text.
- Temperature locked to 0.0 for reproducible evaluations.
- Centralized error handling: if the LLM is unreachable, returns None
  so engines can skip LLM checks gracefully instead of crashing.
"""

import json
import logging
from typing import Any

import litellm

logger = logging.getLogger(__name__)

# Suppress litellm's verbose logging — we handle our own logging
litellm.suppress_debug_info = True


async def call_llm_judge(
    model: str,
    messages: list[dict[str, str]],
    eval_tool: dict[str, Any],
    timeout: int = 30,
) -> dict[str, Any] | None:
    """Call an LLM with tool calling to get structured evaluation output.

    Args:
        model: LiteLLM model identifier (e.g., "gpt-4o-mini", "claude-sonnet-4-20250514").
        messages: Chat messages (system + user) describing what to evaluate.
        eval_tool: Tool/function schema the LLM must call with its response.
        timeout: Request timeout in seconds.

    Returns:
        Parsed tool call arguments as a dict, or None if the call failed.
        Engines should handle None gracefully (skip the check, log a warning).
    """
    tool_name = eval_tool["function"]["name"]

    try:
        response = await litellm.acompletion(
            model=model,
            messages=messages,
            tools=[eval_tool],
            tool_choice={
                "type": "function",
                "function": {"name": tool_name},
            },
            temperature=0.0,
            timeout=timeout,
        )

        # Extract the tool call from the response
        message = response.choices[0].message
        if not message.tool_calls:
            logger.warning("LLM returned no tool calls")
            return None

        tool_call = message.tool_calls[0]
        arguments: dict[str, Any] = json.loads(tool_call.function.arguments)

        logger.debug(
            f"LLM judge responded via {tool_name}: "
            f"{json.dumps(arguments, indent=2)[:200]}"
        )
        return arguments

    except json.JSONDecodeError as e:
        logger.warning(f"LLM returned invalid JSON: {e}")
        return None
    except litellm.exceptions.AuthenticationError:
        logger.error(
            "LLM authentication failed — check your API key. "
            "Use --skip-llm to bypass LLM checks."
        )
        return None
    except litellm.exceptions.RateLimitError:
        logger.warning("LLM rate limit hit — skipping this check")
        return None
    except litellm.exceptions.Timeout:
        logger.warning(
            f"LLM call timed out after {timeout}s — skipping this check"
        )
        return None
    except Exception as e:
        logger.warning(f"LLM call failed: {e}")
        return None
