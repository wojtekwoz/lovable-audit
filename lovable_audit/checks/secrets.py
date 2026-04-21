from __future__ import annotations

import base64
import json
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..models import Finding

PATTERNS = [
    ("OpenAI API key", r"sk-(?!ant-)[A-Za-z0-9_\-]{20,}", "CRITICAL", 9.8),
    ("Anthropic API key", r"sk-ant-[A-Za-z0-9\-_]{20,}", "CRITICAL", 9.8),
    ("Stripe live secret key", r"sk_live_[A-Za-z0-9]{20,}", "CRITICAL", 9.8),
    ("Stripe test secret key", r"sk_test_[A-Za-z0-9]{20,}", "HIGH", 7.5),
    ("AWS access key", r"AKIA[0-9A-Z]{16}", "CRITICAL", 9.1),
    ("Google API key", r"AIza[0-9A-Za-z\-_]{35}", "HIGH", 6.5),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36}", "HIGH", 7.5),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9\-]{10,}", "HIGH", 7.5),
]

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _scan_text(text: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for name, pattern, sev, cvss in PATTERNS:
        for m in re.finditer(pattern, text):
            value = m.group(0)
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id=f"SEC-{len(findings) + 1:02d}",
                    severity=sev,  # type: ignore[arg-type]
                    title=f"Wyeksponowany klucz: {name}",
                    evidence=f"Znaleziono w {source}: `{value[:12]}...{value[-4:]}` (długość {len(value)}).",
                    recommendation=f"Natychmiast unieważnij klucz i przenieś wywołania {name} na backend (Supabase Edge Function / API route).",
                    cvss=cvss,
                )
            )
    # Supabase service_role JWT
    for m in JWT_RE.finditer(text):
        token = m.group(0)
        try:
            header_b64, payload_b64, _ = token.split(".")
            payload = json.loads(_b64url_decode(payload_b64))
        except Exception:
            continue
        role = payload.get("role", "")
        if role == "service_role":
            findings.append(
                Finding(
                    id=f"SEC-SRV-{len(findings) + 1:02d}",
                    severity="CRITICAL",
                    title="Wyeksponowany Supabase service_role JWT",
                    evidence=f"Znaleziono w {source} JWT z polem `role: service_role` (iss={payload.get('iss', '?')}). Ten klucz omija Row Level Security.",
                    recommendation="NATYCHMIAST zrotuj service_role key w Supabase. Używaj go tylko po stronie serwera (Edge Functions). W przeglądarce używaj wyłącznie anon key.",
                    cvss=10.0,
                )
            )
    return findings


async def run(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    r = await client.get(url)
    html = r.text
    findings += _scan_text(html, "HTML strony")

    soup = BeautifulSoup(html, "html.parser")
    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    # Absolute URLs
    script_urls = [urljoin(str(r.url), s) for s in scripts]
    # Only same-origin or same-site JS, skip obvious third parties
    base_host = urlparse(str(r.url)).hostname or ""
    own = [
        u for u in script_urls
        if (urlparse(u).hostname or "").endswith(base_host.split(".", 1)[-1] if "." in base_host else base_host)
        or urlparse(u).hostname == base_host
    ]
    # Limit to first 15 bundles to avoid runaway scans
    for js_url in own[:15]:
        try:
            jr = await client.get(js_url)
            if jr.status_code == 200:
                findings += _scan_text(jr.text, f"`{js_url.rsplit('/', 1)[-1]}`")
        except httpx.HTTPError:
            continue
    # Renumber IDs
    for i, f in enumerate(findings, start=1):
        f.id = f"SEC-{i:02d}"
    return findings
