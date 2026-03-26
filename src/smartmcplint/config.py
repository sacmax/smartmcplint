"""Configuration loading and merging.

- Single file (not a config/ package) because we only need scan config loading right now.
  Rule loading (conformance.yaml, security.yaml) will come later as a separate concern.
- Three functions, each handling one source — testable independently, each has
  different failure modes (file not found vs. malformed env var).
- Merge priority: CLI > YAML > env vars > model defaults.
  CLI = "this run", YAML = "this project", env = "this machine", defaults = "safe fallback".
"""

import logging
import os
from pathlib import Path
from typing import Any

import yaml

from smartmcplint.models.config import EngineWeights, ScanConfig

logger = logging.getLogger(__name__)

# Only a subset of fields make sense as env vars — things that vary by machine/environment,
# not by invocation. Transport and server_cmd change every run, so CLI-only.
# LLM model and timeout are often set once per environment (dev vs CI).
ENV_VAR_MAP: dict[str, str] = {
    "SMARTMCPLINT_LLM_MODEL": "llm_model",
    "SMARTMCPLINT_TIMEOUT": "timeout",
    "SMARTMCPLINT_MIN_SCORE": "min_score",
    "SMARTMCPLINT_OUTPUT_FORMAT": "output_format",
    "SMARTMCPLINT_SKIP_LLM": "skip_llm",
    "SMARTMCPLINT_VERBOSE": "verbose",
}

# Fields that should be parsed as integers, not left as strings.
# Without this, os.environ gives us "30" (str) but ScanConfig expects 30 (int).
INT_FIELDS: set[str] = {"timeout", "min_score"}

# Fields that should be parsed as booleans.
# "true"/"1"/"yes" → True, everything else → False.
BOOL_FIELDS: set[str] = {"skip_llm", "verbose"}

# Default config file name — looked for in current directory.
DEFAULT_CONFIG_FILENAME = "smartmcplint.yaml"


def load_yaml_config(path: Path | None = None) -> dict[str, Any]:
    """Load configuration from a YAML file.

    If no path is given, looks for smartmcplint.yaml in the current directory.
    Returns an empty dict if the file doesn't exist — missing config file is not an error,
    it just means "use other sources."
    """
    if path is None:
        path = Path.cwd() / DEFAULT_CONFIG_FILENAME

    if not path.exists():
        logger.debug(f"No config file found at {path}, using defaults")
        return {}

    logger.debug(f"Loading config from {path}")
    with open(path) as f:
        data = yaml.safe_load(f)

    # yaml.safe_load returns None for empty files
    if data is None:
        return {}

    if not isinstance(data, dict):
        logger.warning(f"Config file {path} is not a YAML mapping, ignoring")
        return {}

    return data


def load_env_config() -> dict[str, Any]:
    """Load configuration from SMARTMCPLINT_* environment variables.

    Only reads the specific env vars in ENV_VAR_MAP — we don't blindly
    read all SMARTMCPLINT_* vars because that would make the config
    surface area unpredictable.
    """
    config: dict[str, Any] = {}

    for env_var, field_name in ENV_VAR_MAP.items():
        value = os.environ.get(env_var)
        if value is None:
            continue

        # Convert types — env vars are always strings, but ScanConfig expects int/bool
        if field_name in INT_FIELDS:
            try:
                config[field_name] = int(value)
            except ValueError:
                logger.warning(f"Env var {env_var}={value!r} is not a valid integer, ignoring")
        elif field_name in BOOL_FIELDS:
            config[field_name] = value.lower() in ("true", "1", "yes")
        else:
            config[field_name] = value

    return config


def build_scan_config(
    cli_args: dict[str, Any] | None = None,
    config_path: Path | None = None,
) -> ScanConfig:
    """Merge all config sources into a validated ScanConfig.

    Priority: CLI args > YAML file > env vars > model defaults.

    - Start with defaults (ScanConfig's field defaults handle this).
    - Layer env vars on top (machine-level settings).
    - Layer YAML on top (project-level settings).
    - Layer CLI on top (this-run overrides).
    - We build a single merged dict, then validate once through Pydantic.
      This is simpler than creating a ScanConfig and then overriding fields,
      because Pydantic validates the whole object at construction time.
    """
    # Gather from each source — each returns only the fields it explicitly sets
    env_config = load_env_config()
    yaml_config = load_yaml_config(config_path)
    cli_config = cli_args or {}

    # Remove None values from CLI args — Click sets unspecified options to None,
    # and we don't want None to override a YAML or env var value.
    cli_config = {k: v for k, v in cli_config.items() if v is not None}

    # Merge in priority order: later dict.update() calls win
    merged: dict[str, Any] = {}
    merged.update(env_config)
    merged.update(yaml_config)
    merged.update(cli_config)

    # Handle nested 'weights' — YAML might specify partial weights like {security: 0.40}.
    # We merge with defaults rather than requiring all weights to be specified.
    if "weights" in merged and isinstance(merged["weights"], dict):
        merged["weights"] = EngineWeights(**merged["weights"])

    return ScanConfig(**merged)
