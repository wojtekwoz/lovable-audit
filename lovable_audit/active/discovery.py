"""Detect Supabase URL + anon key + fetch JS bundles from the target."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..models import ScanContext

SUPABASE_URL_RE = re.compile(r"https://[a-z0-9]{8,}\.supabase\.co")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _is_anon_jwt(token: str) -> bool:
    try:
        _, payload_b64, _ = token.split(".")
        payload = json.loads(_b64url_decode(payload_b64))
        return payload.get("role") == "anon"
    except Exception:
        return False


async def discover(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    """Populate ctx.supabase_url, ctx.supabase_anon_key, ctx.js_bundles."""
    r = await client.get(ctx.url)
    html = r.text

    texts: list[tuple[str, str]] = [("html", html)]

    # Fetch same-origin JS bundles once, share across checks
    soup = BeautifulSoup(html, "html.parser")
    base_host = urlparse(str(r.url)).hostname or ""
    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    script_urls = [urljoin(str(r.url), s) for s in scripts]
    own = [u for u in script_urls if (urlparse(u).hostname or "") == base_host][:15]
    for js_url in own:
        try:
            jr = await client.get(js_url)
            if jr.status_code == 200:
                ctx.js_bundles.append((js_url, jr.text))
                texts.append((js_url.rsplit("/", 1)[-1], jr.text))
        except httpx.HTTPError:
            continue

    # Search all text for Supabase URL + anon key
    for _, text in texts:
        if ctx.supabase_url is None:
            m = SUPABASE_URL_RE.search(text)
            if m:
                ctx.supabase_url = m.group(0)
        if ctx.supabase_anon_key is None:
            for m in JWT_RE.finditer(text):
                if _is_anon_jwt(m.group(0)):
                    ctx.supabase_anon_key = m.group(0)
                    break
        if ctx.supabase_url and ctx.supabase_anon_key:
            break

    if ctx.supabase_key_override:
        ctx.supabase_anon_key = ctx.supabase_key_override
