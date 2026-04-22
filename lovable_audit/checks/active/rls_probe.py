"""Probe common Supabase tables via REST API with anon key only."""

from __future__ import annotations

import httpx

from ...active.auth import authed_headers
from ...active.safety import WAFDetector
from ...models import Finding, ScanContext

COMMON_TABLES = [
    "profiles",
    "users",
    "messages",
    "subscriptions",
    "orders",
    "api_keys",
    "prompts",
    "generations",
    "projects",
    "posts",
    "comments",
    "payments",
]
SENSITIVE_COLUMNS = (
    "email",
    "stripe_customer",
    "stripe_customer_id",
    "api_key",
    "api_token",
    "password",
    "phone",
    "secret",
    "credit",
)


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> tuple[list[Finding], str | None]:
    if not ctx.supabase_url or not ctx.supabase_anon_key:
        return [], "nie wykryto Supabase URL/klucza"

    waf = WAFDetector()
    findings: list[Finding] = []
    anon_headers = {
        "apikey": ctx.supabase_anon_key,
        "Authorization": f"Bearer {ctx.supabase_anon_key}",
    }

    for i, table in enumerate(COMMON_TABLES, start=1):
        try:
            r = await client.get(
                f"{ctx.supabase_url}/rest/v1/{table}",
                params={"select": "*", "limit": 3},
                headers=anon_headers,
            )
            waf.observe(r.status_code, r.text[:500])
        except httpx.HTTPError:
            continue

        if r.status_code != 200:
            continue
        try:
            rows = r.json()
        except Exception:
            continue
        if not isinstance(rows, list) or not rows:
            continue

        # at least one row came back to an anon caller
        columns = set()
        for row in rows:
            if isinstance(row, dict):
                columns.update(row.keys())
        leaking = [c for c in columns if any(s in c.lower() for s in SENSITIVE_COLUMNS)]

        if leaking:
            findings.append(
                Finding(
                    id=f"RLS-{i:02d}",
                    severity="CRITICAL",
                    title=f"Tabela `{table}` — anon czyta wrażliwe pola",
                    evidence=f"GET /rest/v1/{table} jako anon zwróciło {len(rows)} wierszy z kolumnami: {sorted(leaking)}.",
                    recommendation=f"Włącz RLS na tabeli `{table}` i stwórz policy ograniczającą `select` do właściciela rekordu (np. `auth.uid() = user_id`).",
                    cvss=9.1,
                    source="active",
                )
            )
        else:
            findings.append(
                Finding(
                    id=f"RLS-{i:02d}",
                    severity="HIGH",
                    title=f"Tabela `{table}` — anon odczyt zwraca wiersze",
                    evidence=f"GET /rest/v1/{table} jako anon zwróciło {len(rows)} wierszy (kolumny: {sorted(columns)[:6]}).",
                    recommendation=f"Włącz Row Level Security na tabeli `{table}` i zdefiniuj policy dla roli anon.",
                    cvss=7.5,
                    source="active",
                )
            )

    # cross-tenant check when logged in
    if ctx.session_jwt and ctx.session_user_id:
        jwt_headers = authed_headers(ctx)
        for table in ("profiles", "users", "projects"):
            try:
                r = await client.get(
                    f"{ctx.supabase_url}/rest/v1/{table}",
                    params={"select": "*", "limit": 20},
                    headers=jwt_headers,
                )
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            try:
                rows = r.json()
            except Exception:
                continue
            if not isinstance(rows, list):
                continue
            foreign = [
                row
                for row in rows
                if isinstance(row, dict)
                and row.get("user_id")
                and row.get("user_id") != ctx.session_user_id
            ]
            if foreign:
                findings.append(
                    Finding(
                        id=f"RLS-XT-{table}",
                        severity="CRITICAL",
                        title=f"Cross-tenant leak w `{table}`",
                        evidence=f"Zalogowany user {ctx.session_user_id} odczytał {len(foreign)} wierszy innych użytkowników.",
                        recommendation="RLS policy na tej tabeli musi filtrować `auth.uid() = user_id`.",
                        cvss=9.8,
                        source="active",
                    )
                )
    return findings, None
