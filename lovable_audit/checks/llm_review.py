"""Optional Claude-powered review of the app's JS bundles.

Skipped unless `ANTHROPIC_API_KEY` is set in the environment.
Claude reads a sample of the bundles and flags insecure patterns that
regex-based scanning cannot catch — e.g. client-side role checks, API
routes embedded in JS, suspicious eval/innerHTML usage, leaked system
prompts for AI features.
"""

from __future__ import annotations

import json
import os
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..models import Finding

MODEL = "claude-sonnet-4-6"


def _extract_json_array(text: str):
    """Extract a JSON array from mixed output (prose, code fences, etc.)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip code fences
    if "```" in text:
        inside = text.split("```", 2)
        if len(inside) >= 2:
            candidate = inside[1]
            if candidate.startswith("json"):
                candidate = candidate[4:]
            try:
                return json.loads(candidate.strip())
            except json.JSONDecodeError:
                pass
    # Find first `[` / last `]`
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None
MAX_BUNDLES = 5
MAX_CHARS_PER_BUNDLE = 40_000  # keep prompt bounded
SYSTEM_PROMPT = """You review JavaScript bundles from web apps for security issues a regex scanner would miss.

Focus on these categories:
1. Client-side authorization checks (role === 'admin' in JS)
2. Hardcoded API endpoints that look privileged (admin routes, internal APIs)
3. Leaked AI system prompts or model configuration
4. Dangerous sinks: eval, new Function, innerHTML with user input, dangerouslySetInnerHTML
5. Client-enforced business logic (payment validation, feature flags, quota checks)

Do NOT flag:
- Supabase anon keys (expected in frontend)
- Public config (e.g. Stripe publishable key pk_*)
- Normal React/framework code

Return ONLY a raw JSON array. No prose before or after. No markdown code fences. The first character of your response MUST be `[` and the last `]`.

Each finding in the array:
{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "title": "short Polish title",
  "evidence": "the snippet or pattern you found, in Polish",
  "recommendation": "how to fix, in Polish",
  "cvss": number between 0 and 10
}

If nothing concerning, return [].
"""


async def run(url: str, client: httpx.AsyncClient) -> tuple[list[Finding], str | None]:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return [], "ANTHROPIC_API_KEY nie ustawiony (check opcjonalny)"

    try:
        from anthropic import AsyncAnthropic
    except ImportError:
        return [], "pakiet `anthropic` nie zainstalowany (pip install anthropic)"

    # Fetch bundles (reuses same logic as secrets check)
    r = await client.get(url)
    soup = BeautifulSoup(r.text, "html.parser")
    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    script_urls = [urljoin(str(r.url), s) for s in scripts]
    base_host = urlparse(str(r.url)).hostname or ""

    own = [u for u in script_urls if (urlparse(u).hostname or "") == base_host][:MAX_BUNDLES]
    if not own:
        return [], "nie znaleziono same-origin JS bundles do analizy"

    bundles = []
    for js_url in own:
        try:
            jr = await client.get(js_url)
            if jr.status_code == 200:
                content = jr.text[:MAX_CHARS_PER_BUNDLE]
                bundles.append((js_url.rsplit("/", 1)[-1], content))
        except httpx.HTTPError:
            continue

    if not bundles:
        return [], "żaden bundle nie zwrócił 200"

    # Build prompt
    parts = [f"Reviewing {len(bundles)} JS bundle(s) from {url}.\n"]
    for name, content in bundles:
        parts.append(f"\n--- {name} ---\n{content}\n")
    user_msg = "".join(parts)

    anth = AsyncAnthropic(api_key=api_key)
    try:
        resp = await anth.messages.create(
            model=MODEL,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
    except Exception as e:
        return [], f"Claude API error: {type(e).__name__}: {e}"

    text = "".join(
        block.text for block in resp.content if getattr(block, "type", None) == "text"
    ).strip()

    parsed = _extract_json_array(text)
    if parsed is None:
        return [], f"Claude zwrócił nieparsowany JSON ({len(text)} znaków)"

    if not isinstance(parsed, list):
        return [], "Claude nie zwrócił listy"

    findings: list[Finding] = []
    for i, item in enumerate(parsed, start=1):
        if not isinstance(item, dict):
            continue
        sev = item.get("severity", "MEDIUM")
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev = "MEDIUM"
        findings.append(
            Finding(
                id=f"LLM-{i:02d}",
                severity=sev,  # type: ignore[arg-type]
                title=item.get("title", "Nieokreślony problem"),
                evidence=item.get("evidence", ""),
                recommendation=item.get("recommendation", ""),
                cvss=item.get("cvss"),
            )
        )
    return findings, None
