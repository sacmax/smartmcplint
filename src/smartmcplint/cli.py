"""CLI entry point for SmartMCPLint."""

import click

from smartmcplint import __version__


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
    default=0,
    help="Minimum passing score (0-100). Exit 1 if below.",
)
@click.option(
    "--skip-llm",
    is_flag=True,
    default=False,
    help="Skip LLM-powered engines (Quality, Auto-Fix).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json", "markdown"]),
    default="terminal",
    help="Output format.",
)
@click.argument("server_args", nargs=-1, required=True)
def scan(
    transport: str,
    min_score: int,
    skip_llm: bool,
    output_format: str,
    server_args: tuple[str, ...],
) -> None:
    """Scan an MCP server for quality and compliance issues."""
    click.echo(f"Scanning with transport={transport}, args={server_args}")
    click.echo("(Not yet implemented)")
