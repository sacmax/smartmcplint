"""CLI entry point for SmartMCPLint."""

import asyncio
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from smartmcplint import __version__
from smartmcplint.config import build_scan_config
from smartmcplint.models.findings import Finding
from smartmcplint.models.results import ScanResult
from smartmcplint.scanner import Scanner
from smartmcplint.transport import TransportError

console = Console()

_SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "warning":  "yellow",
    "info":     "dim",
}

_GRADE_STYLE: dict[str, str] = {
    "A+": "bold green",
    "A":  "green",
    "B":  "cyan",
    "C":  "yellow",
    "D":  "red",
    "F":  "bold red",
}


@click.group()
@click.version_option(version=__version__, prog_name="smartmcplint")
def main() -> None:
    """SmartMCPLint — Intelligent MCP Server Quality & Compliance Scanner."""


@main.command()
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http"]),
    required=True,
    help="Transport type to connect to the MCP server.",
)
@click.option(
    "--min-score",
    type=int,
    default=None,
    help="Minimum passing score (0-100). Exit 1 if below.",
)
@click.option(
    "--skip-llm",
    is_flag=True,
    default=None,
    help="Skip LLM-powered checks (Quality engine).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json"]),
    default=None,
    help="Output format.",
)
@click.option(
    "--verbose",
    is_flag=True,
    default=None,
    help="Show all findings including INFO severity.",
)
@click.argument("server_args", nargs=-1, required=True)
def scan(
    transport: str,
    min_score: int | None,
    skip_llm: bool | None,
    output_format: str | None,
    verbose: bool | None,
    server_args: tuple[str, ...],
) -> None:
    """Scan an MCP server for quality and compliance issues.

    For stdio servers:   smartmcplint scan --transport stdio -- python server.py
    For HTTP servers:    smartmcplint scan --transport http http://localhost:8080
    """
    # Resolve server command vs URL from positional args
    if transport == "stdio":
        server_cmd = list(server_args)
        server_url = None
    else:
        server_url = server_args[0] if server_args else None
        server_cmd = []

    config = build_scan_config(cli_args={
        "transport":     transport,
        "server_cmd":    server_cmd,
        "server_url":    server_url,
        "min_score":     min_score,
        "skip_llm":      skip_llm,
        "output_format": output_format,
        "verbose":       verbose,
    })

    try:
        result = asyncio.run(Scanner(config).scan())
    except TransportError as e:
        console.print(f"[bold red]Connection failed:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        sys.exit(1)

    if config.output_format == "json":
        console.print(result.model_dump_json(indent=2))
    else:
        _print_terminal(result, verbose=config.verbose)

    if result.overall_score < config.min_score:
        console.print(
            f"\n[bold red]FAIL[/bold red] Score {result.overall_score:.1f} "
            f"is below minimum {config.min_score}"
        )
        sys.exit(1)


def _print_terminal(result: ScanResult, verbose: bool = False) -> None:
    """Render scan results as a rich terminal report."""
    grade_style = _GRADE_STYLE.get(result.grade.value, "white")

    console.print()
    console.rule("[bold]SmartMCPLint Scan Report[/bold]")
    console.print(
        f"  Server:  [bold]{result.server_info.name}[/bold] "
        f"v{result.server_info.version}  |  "
        f"Protocol: {result.server_info.protocol_version}"
    )
    console.print(
        f"  Score:   [bold]{result.overall_score:.1f}[/bold] / 100  |  "
        f"Grade: [{grade_style}]{result.grade.value}[/{grade_style}]  |  "
        f"Duration: {result.scan_duration_ms:.0f}ms"
    )
    console.print()

    # Engine summary table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Engine",   style="bold")
    table.add_column("Score",    justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Status")

    for engine_type, engine_result in result.engine_results.items():
        if engine_result.skipped:
            table.add_row(
                engine_type.value,
                "—",
                "—",
                Text("skipped", style="dim"),
            )
        else:
            finding_counts = _count_findings(engine_result.findings)
            table.add_row(
                engine_type.value,
                f"{engine_result.score:.1f}",
                finding_counts,
                Text("✓", style="green"),
            )

    console.print(table)

    # Findings list
    all_findings = [
        f for er in result.engine_results.values()
        for f in er.findings
        if verbose or f.severity in ("critical", "warning")
    ]

    # Sort: critical first, then warning, then info
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 3))

    if all_findings:
        console.print()
        console.rule("[bold]Findings[/bold]")
        for finding in all_findings:
            style = _SEVERITY_STYLE.get(finding.severity, "white")
            tool_suffix = f" [dim]({finding.tool_name})[/dim]" if finding.tool_name else ""
            console.print(
                f"  [{style}]{finding.severity.upper():8s}[/{style}]  "
                f"[bold]{finding.rule_id}[/bold]  {finding.title}{tool_suffix}"
            )
            if verbose:
                console.print(f"           {finding.message}", style="dim")
    else:
        console.print("\n  [green]No findings.[/green]")

    console.print()


def _count_findings(findings: list[Finding]) -> str:
    """Summarize finding counts as 'Nc Nw Ni' (critical/warning/info)."""
    c = sum(1 for f in findings if f.severity == "critical")
    w = sum(1 for f in findings if f.severity == "warning")
    i = sum(1 for f in findings if f.severity == "info")
    parts = []
    if c:
        parts.append(f"[red]{c}c[/red]")
    if w:
        parts.append(f"[yellow]{w}w[/yellow]")
    if i:
        parts.append(f"[dim]{i}i[/dim]")
    return " ".join(parts) if parts else "[green]0[/green]"
