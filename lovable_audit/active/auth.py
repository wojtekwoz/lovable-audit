"""Supabase GoTrue password login."""

from __future__ import annotations

import base64
import json

import httpx

from ..models import ScanContext


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


async def login(ctx: ScanContext, client: httpx.AsyncClient) -> tuple[bool, str | None]:
    """Log in via Supabase auth. Returns (ok, error_reason)."""
    if not ctx.credentials:
        return False, "brak --credentials"
    if not ctx.supabase_url or not ctx.supabase_anon_key:
        return False, "nie wykryto Supabase URL/klucza"

    email, password = ctx.credentials
    endpoint = f"{ctx.supabase_url}/auth/v1/token?grant_type=password"
    try:
        r = await client.post(
            endpoint,
            headers={
                "apikey": ctx.supabase_anon_key,
                "Content-Type": "application/json",
            },
            json={"email": email, "password": password},
        )
    except httpx.HTTPError as e:
        return False, f"błąd sieci: {e}"

    if r.status_code != 200:
        snippet = r.text[:200].replace("\n", " ")
        return False, f"HTTP {r.status_code}: {snippet}"

    data = r.json()
    token = data.get("access_token")
    user = data.get("user") or {}
    if not token:
        return False, "odpowiedź nie zawiera access_token"

    ctx.session_jwt = token
    ctx.session_user_id = user.get("id")
    return True, None


def authed_headers(ctx: ScanContext) -> dict[str, str]:
    headers = {}
    if ctx.supabase_anon_key:
        headers["apikey"] = ctx.supabase_anon_key
    if ctx.session_jwt:
        headers["Authorization"] = f"Bearer {ctx.session_jwt}"
    return headers


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    try:
        header_b64, payload_b64, _ = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        return header, payload
    except Exception:
        return None


def encode_unsigned_jwt(header: dict, payload: dict) -> str:
    """Build an unsigned JWT (alg:none). For privilege-escalation probing only."""
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}."
