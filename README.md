# SmartMCPLint

**Intelligent MCP Server Quality & Compliance Scanner**

SmartMCPLint audits [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers across five dimensions: protocol conformance, security, tool quality, runtime behavior, and auto-fix suggestions. It gives your MCP server a score, a letter grade, and actionable findings — so you know exactly what to fix before agents rely on it in production.

---

## Why

MCP is becoming the standard for connecting AI agents to external tools. But there is no quality bar for MCP servers — anyone can publish one. A poorly designed server causes silent failures in agent workflows: tools that crash, schemas that confuse LLMs, and inputs that go unvalidated. SmartMCPLint acts as a **black-box auditor**: it connects to your server the same way an agent would, and systematically probes it for issues.

---

## Features

- **Five scanning engines** — each targeting a different failure mode
- **Hybrid rule-based + LLM evaluation** — fast static checks first, expensive LLM checks only when needed
- **Transport-agnostic** — supports both `stdio` (local process) and `HTTP` servers
- **No source code required** — black-box auditing: SmartMCPLint only needs to connect to your server
- **`--skip-llm` flag** — run all rule-based checks instantly, no API key required
- **Configurable scoring weights** — tune what matters most for your use case
- **CI/CD integration** — exit code 1 when score falls below `--min-score`
- **Multiple output formats** — rich terminal display and JSON for programmatic use

---

## Scanning Engines

### Conformance Engine (`CONF-*`)
Validates that the server correctly implements the MCP specification: initialization handshake, tool schema structure, JSON-RPC framing, error response format, and protocol version negotiation.

### Security Engine (`SEC-*`)
Probes for common vulnerabilities without requiring server source code:
- **Authentication** — missing auth, API keys hardcoded in schemas, unauthorized access
- **Input validation** — command injection, path traversal, prompt injection via tool arguments
- **Data exposure** — sensitive data in error messages, tool responses returning excess fields, verbose server info at initialization
- **Transport security** — HTTP-to-HTTPS downgrade detection, self-signed certificate detection

### Quality Engine (`QUAL-*`)
Uses an LLM-as-judge to evaluate whether tool descriptions are actually useful to an AI agent:
- Missing or too-short descriptions
- Descriptions that don't explain when to use the tool or what side effects it has
- Parameters with unclear names or no documentation
- Ambiguous tools that an LLM could confuse with each other

### Behavior Engine (`BEH-*`)
Invokes tools with controlled inputs and tests their runtime behavior:
- Does the tool respond without crashing on valid inputs?
- Does it return proper errors (not silent failures or crashes) for missing required params, wrong types, and empty strings?
- Is the response structure consistent across identical calls?
- Does it respond within acceptable latency bounds?

> **Safety:** The Behavior Engine never invokes write operations (`create`, `update`, `delete`, etc.). Only read-like tools are tested.

### Auto-Fix Engine (`FIX-*`)
Generates concrete, LLM-powered fix suggestions for each finding — including improved descriptions, corrected schemas, and recommended validation logic. Runs after all other engines as a second pass, grouping findings by rule to minimize LLM calls. Skipped automatically when `--skip-llm` is set.

---

## Installation

**Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).**

```bash
git clone https://github.com/sacmax/smartmcplint
cd smartmcplint
uv sync
```

For development (includes linting, type checking, and test tools):

```bash
uv sync --group dev
```

---

## Quick Start

**Scan a local stdio server:**

```bash
uv run smartmcplint scan --transport stdio -- python my_server.py
```

**Scan a remote HTTP server:**

```bash
uv run smartmcplint scan --transport http http://localhost:8080
```

**Skip LLM checks (no API key needed):**

```bash
uv run smartmcplint scan --transport stdio --skip-llm -- python my_server.py
```

**Fail in CI if score drops below 80:**

```bash
uv run smartmcplint scan --transport stdio --min-score 80 -- python my_server.py
```

**Output as JSON (for programmatic use):**

```bash
uv run smartmcplint scan --transport stdio --format json -- python my_server.py
```

---

## Configuration

Settings are resolved in order: **CLI flags → `smartmcplint.yaml` → defaults**.

Copy the example config to get started:

```bash
cp smartmcplint.example.yaml smartmcplint.yaml
```

```yaml
# smartmcplint.yaml
min_score: 70
skip_llm: false
llm_model: gpt-4o-mini        # any LiteLLM-supported model
output_format: terminal        # terminal | json
timeout: 30

weights:
  conformance: 0.25
  security: 0.30
  quality: 0.25
  behavior: 0.15
  autofix_bonus: 0.05
```

### LLM API Keys

SmartMCPLint uses [LiteLLM](https://github.com/BerriAI/litellm) to support any LLM provider. Set the relevant environment variable for your chosen model:

```bash
# OpenAI
export OPENAI_API_KEY=sk-...

# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

API keys are read from environment variables only — never from config files.

---

## Check IDs

| Engine | Prefix | Categories |
|---|---|---|
| Conformance | `CONF-` | Initialization, tool schema, resource schema, error handling |
| Security | `SEC-` | Authentication, input validation, data exposure, transport |
| Quality | `QUAL-` | Schema completeness, description clarity, disambiguation, param docs |
| Behavior | `BEH-` | Valid call, bad input resilience, response consistency, latency |
| Auto-Fix | — | LLM-generated fix suggestions (grouped by rule, one per unique finding type) |

---

## Development

```bash
uv run ruff check src/     # Lint
uv run ruff format src/    # Format
uv run mypy src/           # Type check
uv run pytest              # All tests
uv run pytest tests/unit   # Unit tests only
uv run pytest tests/integration -m integration  # Integration tests (requires no API key)
```

### Project Structure

```
src/smartmcplint/
├── cli.py                 # CLI entry point (click)
├── client.py              # MCP protocol client
├── transport.py           # stdio and HTTP transports
├── config.py              # Config resolution (CLI > YAML > defaults)
├── scanner.py             # Scan orchestrator — wires all engines together
├── engines/
│   ├── conformance.py     # Protocol compliance checks
│   ├── security.py        # Security vulnerability probes
│   ├── quality.py         # LLM-as-judge tool quality evaluation
│   ├── behavior.py        # Runtime invocation testing
│   └── autofix.py         # LLM-powered fix suggestions (Phase 2)
├── models/                # Pydantic data models
└── utils/llm.py           # Centralized LLM calls via LiteLLM

tests/
├── unit/engines/          # Per-engine unit tests (153 tests)
├── unit/test_scanner.py   # Scoring and grade threshold tests
├── integration/           # End-to-end tests against fixture servers
└── fixtures/              # good_server.py, bad_server.py
```

---

## Requirements

- Python 3.12+
- An MCP server reachable via `stdio` or `HTTP`
- An LLM API key (optional — use `--skip-llm` to run without one)

---

## License

MIT
