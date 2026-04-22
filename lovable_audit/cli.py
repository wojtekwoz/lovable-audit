from __future__ import annotations

import asyncio
import json as jsonlib
import sys
from dataclasses import asdict
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.console import Console

from . import __version__
from .models import ScanContext
from .report import render_markdown
from .scanner import scan

console = Console()


def _normalize_url(raw: str) -> str:
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw.rstrip("/")


def _symbol(cr) -> str:
    if cr.error:
        return "[red]![/red]"
    if cr.skipped:
        return "[dim]—[/dim]"
    if cr.findings:
        return "[yellow]✗[/yellow]"
    return "[green]✓[/green]"


def _summary_line(cr) -> str:
    if cr.error:
        return f"error: {cr.error}"
    if cr.skipped:
        return f"skipped — {cr.skip_reason}"
    if not cr.findings:
        return "OK"
    by_sev: dict[str, int] = {}
    for f in cr.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return ", ".join(f"{v} {k}" for k, v in by_sev.items())


@click.command()
@click.version_option(__version__)
@click.argument("url")
@click.option("--output", "-o", type=click.Path(dir_okay=False, path_type=Path), help="Output path for markdown report.")
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON to stdout instead of running the TUI.")
@click.option("--verbose", "-v", is_flag=True, help="Print full evidence in the terminal summary.")
@click.option("--credentials", help="Test account for active checks, format: email:password")
@click.option("--supabase-key", help="Override the Supabase anon key (if auto-detection fails).")
@click.option("--aggressive", "-A", is_flag=True, help="Enable destructive active checks (brute-force, stored XSS).")
@click.option("--skip", multiple=True, help="Skip a check by name. Repeatable.")
def main(
    url: str,
    output: Path | None,
    as_json: bool,
    verbose: bool,
    credentials: str | None,
    supabase_key: str | None,
    aggressive: bool,
    skip: tuple[str, ...],
) -> None:
    """Black-box + active security scan for apps built with Lovable.

    URL: full URL of the app to scan (https:// auto-added).
    """
    url = _normalize_url(url)
    host = urlparse(url).hostname or "unknown"

    creds: tuple[str, str] | None = None
    if credentials:
        if ":" not in credentials:
            raise click.BadParameter("--credentials must be email:password")
        email, _, password = credentials.partition(":")
        creds = (email, password)

    ctx = ScanContext(
        url=url,
        credentials=creds,
        supabase_key_override=supabase_key,
        aggressive=aggressive,
        skip=set(skip),
    )

    if as_json:
        result = asyncio.run(scan(ctx))
        payload = {
            "url": result.url,
            "date": date.today().isoformat(),
            "checks": [
                {
                    "name": c.name,
                    "skipped": c.skipped,
                    "skip_reason": c.skip_reason,
                    "error": c.error,
                    "findings": [asdict(f) for f in c.findings],
                }
                for c in result.checks
            ],
        }
        click.echo(jsonlib.dumps(payload, indent=2, ensure_ascii=False))
        return

    console.print(f"[bold]🔍 Scanning[/bold] {url}\n")

    def on_progress(cr):
        console.print(f"  {_symbol(cr)} {cr.name} [dim]— {_summary_line(cr)}[/dim]")

    result = asyncio.run(scan(ctx, on_progress=on_progress))

    # Render report
    md = render_markdown(result)
    if output is None:
        output = Path.cwd() / f"AUDIT_{host}_{date.today().isoformat()}.md"
    output.write_text(md, encoding="utf-8")

    console.print()
    console.print(f"[bold]Report written to:[/bold] {output}")
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = result.count(sev)
        if n:
            color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}[sev]
            parts.append(f"[{color}]{n} {sev}[/{color}]")
    summary = ", ".join(parts) if parts else "[green]nothing found[/green]"
    console.print(f"[bold]Summary:[/bold] {summary}")

    if verbose:
        for f in result.findings:
            console.print(f"\n  [bold]{f.id}[/bold] [{f.severity}] {f.title}")
            console.print(f"    evidence: {f.evidence}")
            console.print(f"    fix: {f.recommendation}")

    if result.count("CRITICAL") > 0:
        sys.exit(2)
    if result.count("HIGH") > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
