"""Brute-force rate limit probe on Supabase auth."""

from __future__ import annotations

import asyncio
import secrets

import httpx

from ...models import Finding, ScanContext


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> tuple[list[Finding], str | None]:
    if not ctx.aggressive:
        return [], "wymaga --aggressive (destrukcyjne)"
    if not ctx.credentials:
        return [], "wymaga --credentials (email użytkownika)"
    if not ctx.supabase_url or not ctx.supabase_anon_key:
        return [], "nie wykryto Supabase URL/klucza"

    email, _ = ctx.credentials
    endpoint = f"{ctx.supabase_url}/auth/v1/token?grant_type=password"
    headers = {
        "apikey": ctx.supabase_anon_key,
        "Content-Type": "application/json",
    }

    attempts = 12
    results: list[tuple[int, float]] = []
    for i in range(attempts):
        wrong_pw = f"wrong-{secrets.token_hex(4)}"
        try:
            r = await client.post(
                endpoint,
                headers=headers,
                json={"email": email, "password": wrong_pw},
            )
            results.append((r.status_code, 0.0))
        except httpx.HTTPError:
            results.append((0, 0.0))
        await asyncio.sleep(0.15)

    codes = [s for s, _ in results]
    got_429 = any(s == 429 for s in codes)
    all_400 = all(s == 400 for s in codes)

    if got_429:
        return [
            Finding(
                id="RL-01",
                severity="INFO",
                title="Rate limiting wykryte na loginie",
                evidence=f"{attempts} prób błędnych haseł: {codes.count(429)} × 429.",
                recommendation="OK — Supabase GoTrue rate-limit działa.",
                source="active",
            )
        ], None

    if all_400:
        return [
            Finding(
                id="RL-01",
                severity="HIGH",
                title="Brak rate-limitingu na endpointzie loginu",
                evidence=f"{attempts} błędnych haseł pod rząd → wszystkie 400, żadnego 429.",
                recommendation="Włącz rate-limit w Supabase Auth Settings lub dodaj middleware (Cloudflare rate-limit rule, hCaptcha).",
                cvss=6.5,
                source="active",
            )
        ], None

    return [
        Finding(
            id="RL-01",
            severity="LOW",
            title="Rate limit niejednoznaczny",
            evidence=f"kody odpowiedzi: {codes}",
            recommendation="Sprawdź ręcznie — mix odpowiedzi może oznaczać częściową ochronę.",
            source="active",
        )
    ], None
