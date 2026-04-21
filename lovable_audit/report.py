from __future__ import annotations

from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import ScanResult

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(disabled_extensions=("j2",), default=False),
    trim_blocks=True,
    lstrip_blocks=True,
)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_PL = {
    "CRITICAL": "Krytyczne",
    "HIGH": "Wysokie",
    "MEDIUM": "Średnie",
    "LOW": "Niskie",
    "INFO": "Informacyjne",
}


def render_markdown(result: ScanResult) -> str:
    tpl = _env.get_template("report.md.j2")
    grouped: dict[str, list] = {s: [] for s in SEVERITY_ORDER}
    for f in result.findings:
        grouped.setdefault(f.severity, []).append(f)
    return tpl.render(
        url=result.url,
        date=date.today().isoformat(),
        result=result,
        grouped=grouped,
        severity_order=SEVERITY_ORDER,
        severity_pl=SEVERITY_PL,
    )
