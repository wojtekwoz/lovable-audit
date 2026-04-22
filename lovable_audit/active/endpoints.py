"""Discover API endpoints (fetch/axios calls) from frontend JS."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..models import ScanContext

# fetch("..."), fetch('...'), fetch(`...`) + axios.get/post/put/delete
FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
# absolute URLs that look like API routes
URL_RE = re.compile(r"""['"`](/(?:api|rest|functions)/v?\d*/[^'"`\s?]{1,200})['"`]""")

AI_MARKERS = ("openai", "anthropic", "/chat", "/generate", "/ai/", "/completion", "/llm", "/prompt")
AUTH_MARKERS = ("/auth/", "/signin", "/login", "/token", "/signup")


def _classify(url: str) -> str:
    lower = url.lower()
    if any(m in lower for m in AI_MARKERS):
        return "ai"
    if any(m in lower for m in AUTH_MARKERS):
        return "auth"
    if "/rest/v1/" in lower:
        return "rest"
    if "/functions/" in lower:
        return "function"
    if "/api/" in lower:
        return "api"
    return "generic"


def discover_endpoints(ctx: ScanContext) -> None:
    """Parse ctx.js_bundles, populate ctx.discovered_endpoints with deduped entries."""
    base = urlparse(ctx.url)
    seen: set[str] = set()

    for _, text in ctx.js_bundles:
        candidates: list[str] = []
        candidates += FETCH_RE.findall(text)
        candidates += URL_RE.findall(text)
        for raw in candidates:
            if raw.startswith(("http://", "https://")):
                url = raw
            elif raw.startswith("/"):
                url = f"{base.scheme}://{base.netloc}{raw}"
            else:
                url = urljoin(ctx.url + "/", raw)
            if url in seen:
                continue
            seen.add(url)
            ctx.discovered_endpoints.append({"url": url, "kind": _classify(url)})
