"""Detect client-side quota enforcement by probing gated endpoints."""

from __future__ import annotations

import re

import httpx

from ...active.auth import authed_headers
from ...models import Finding, ScanContext

QUOTA_HINTS = re.compile(
    r"""(freeGenerations|credits|quota|remaining|isPro|tier\s*[:=]|limit\s*[:=]|usageCount|free_tier|plan\s*[:=])""",
    re.IGNORECASE,
)


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> tuple[list[Finding], str | None]:
    if not ctx.session_jwt:
        return [], "wymaga zalogowanego użytkownika (--credentials)"
    if not ctx.js_bundles:
        return [], "brak bundle'ów do analizy"

    # Detect client-side quota variables
    hints: list[str] = []
    for name, text in ctx.js_bundles:
        for m in QUOTA_HINTS.finditer(text):
            hints.append(m.group(0))
        if len(hints) >= 10:
            break

    if not hints:
        return [], "brak sygnałów client-side quota enforcement w bundle'ach"

    # Pick a gated-looking endpoint (AI or /api/generate)
    candidates = [
        e for e in ctx.discovered_endpoints
        if e["kind"] in ("ai", "function", "api")
        and any(k in e["url"].lower() for k in ("generate", "create", "submit", "render", "render", "process"))
    ]
    if not candidates:
        candidates = [e for e in ctx.discovered_endpoints if e["kind"] == "ai"]
    if not candidates:
        return [
            Finding(
                id="MB-01",
                severity="LOW",
                title="Wykryte client-side quota variables (tylko statyczna detekcja)",
                evidence=f"Bundle zawiera: {list(set(hints))[:6]}.",
                recommendation="Upewnij się, że limity są egzekwowane na backendzie — nie ufaj tylko zmiennym w JS.",
                cvss=3.1,
                source="active",
            )
        ], None

    target = candidates[0]["url"]
    headers = authed_headers(ctx)
    headers.setdefault("Content-Type", "application/json")

    # Fire 5 minimal requests — honest cap, not a fuzzer
    ok_count = 0
    last_status = 0
    for _ in range(5):
        try:
            r = await client.post(target, headers=headers, json={"prompt": "test"}, timeout=10.0)
            last_status = r.status_code
            if r.status_code < 400:
                ok_count += 1
        except httpx.HTTPError:
            continue

    if ok_count >= 4:
        return [
            Finding(
                id="MB-01",
                severity="HIGH",
                title="Quota egzekwowane tylko po stronie klienta",
                evidence=(
                    f"Bundle zawiera markers: {list(set(hints))[:4]}. "
                    f"POST {target} przyjął {ok_count}/5 wywołań bezpośrednich z zalogowanego konta (ostatni status {last_status})."
                ),
                recommendation="Licznik użycia musi być przechowywany i sprawdzany w bazie po stronie serwera. Dodaj Edge Function / RLS policy sprawdzającą quota przed wykonaniem operacji.",
                cvss=7.1,
                source="active",
            )
        ], None
    return [], None
