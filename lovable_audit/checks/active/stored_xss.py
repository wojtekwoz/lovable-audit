"""Inject XSS canaries into Supabase tables and check for unescaped reflection."""

from __future__ import annotations

import httpx

from ...active.auth import authed_headers
from ...active.payloads import XSS_PAYLOADS, make_canary
from ...models import Finding, ScanContext


WRITABLE_TABLES = ("profiles", "messages", "prompts", "posts", "comments", "projects")
STRING_FIELDS = ("name", "display_name", "bio", "title", "content", "body", "message", "description")


async def _try_insert(
    client: httpx.AsyncClient, ctx: ScanContext, table: str, payload_value: str
) -> tuple[bool, str]:
    """Try to insert a row with the payload in a common string field. Returns (ok, row_id)."""
    headers = {
        **authed_headers(ctx),
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    for field in STRING_FIELDS:
        body = {field: payload_value}
        try:
            r = await client.post(
                f"{ctx.supabase_url}/rest/v1/{table}",
                headers=headers,
                json=body,
            )
        except httpx.HTTPError:
            continue
        if r.status_code in (200, 201):
            try:
                rows = r.json()
                if isinstance(rows, list) and rows:
                    return True, str(rows[0].get("id", "?"))
            except Exception:
                pass
            return True, "?"
    return False, ""


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> tuple[list[Finding], str | None]:
    if not ctx.aggressive:
        return [], "wymaga --aggressive (pisze do bazy)"
    if not ctx.session_jwt:
        return [], "wymaga zalogowanego użytkownika (--credentials)"
    if not ctx.supabase_url:
        return [], "nie wykryto Supabase URL"

    findings: list[Finding] = []
    injected: list[tuple[str, str, str]] = []  # (table, row_id, canary)

    # 1) Inject canary payloads
    for table in WRITABLE_TABLES:
        canary = make_canary("XSS")
        payload = f'{XSS_PAYLOADS[0]}{canary}'
        ok, row_id = await _try_insert(client, ctx, table, payload)
        if ok:
            injected.append((table, row_id, canary))

    if not injected:
        return [], "nie udało się wstawić żadnego payloadu (tabele zablokowane / pola niezgodne)"

    # 2) Fetch app root, look for unescaped canary
    try:
        r = await client.get(ctx.url)
        page = r.text
    except httpx.HTTPError:
        page = ""

    for table, row_id, canary in injected:
        if canary in page and "<svg" in page.lower():
            findings.append(
                Finding(
                    id=f"XSS-{len(findings) + 1:02d}",
                    severity="CRITICAL",
                    title=f"Stored XSS w tabeli `{table}`",
                    evidence=f"Wstrzyknięty payload (canary {canary}) pojawia się w HTML strony jako niezaescape'owany `<svg>`. Row id: {row_id}.",
                    recommendation="Escape'uj user input po stronie renderingu (React auto-escapuje string, ale NIE dangerouslySetInnerHTML). Dodaj CSP: script-src 'self'.",
                    cvss=8.8,
                    source="active",
                )
            )
        elif canary in page:
            findings.append(
                Finding(
                    id=f"XSS-{len(findings) + 1:02d}",
                    severity="MEDIUM",
                    title=f"Niezaescape'owany input z `{table}` w HTML",
                    evidence=f"Canary {canary} widoczny w odpowiedzi (row id: {row_id}), ale znaczniki HTML są zaescape'owane.",
                    recommendation="Sprawdź, czy w innych kontekstach (SSR, email, PDF) payload nie jest interpretowany.",
                    cvss=4.3,
                    source="active",
                )
            )

    # 3) Always emit a cleanup note when we injected
    cleanup_note = "\n".join(
        f"- DELETE FROM {t} WHERE id = '{rid}';  -- canary {c}"
        for t, rid, c in injected
    )
    findings.append(
        Finding(
            id="XSS-CLEANUP",
            severity="INFO",
            title="Wstawiłem testowe wiersze — usuń po audycie",
            evidence=f"Wstawione payloady (tabela/id/canary):\n{cleanup_note}",
            recommendation="Ręcznie usuń powyższe wiersze. Skaner nie usuwa danych automatycznie.",
            source="active",
        )
    )
    return findings, None
