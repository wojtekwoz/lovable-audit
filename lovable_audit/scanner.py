from __future__ import annotations

import asyncio
import inspect

import httpx

from .active import auth as active_auth
from .active import discovery as active_discovery
from .active import endpoints as active_endpoints
from .active.safety import WAFBlocked
from .checks import cors, dns, headers, llm_review, secrets, tls
from .checks.active import (
    monetization_bypass,
    privilege_escalation,
    prompt_injection,
    rate_limit,
    rls_probe,
    stored_xss,
)
from .models import CheckResult, Finding, ScanContext, ScanResult, Severity

__all__ = ["CheckResult", "Finding", "ScanContext", "ScanResult", "Severity", "scan"]


# (name, run_fn, source)
PASSIVE_CHECKS = [
    ("Security headers", headers.run, "passive"),
    ("CORS configuration", cors.run, "passive"),
    ("Exposed secrets", secrets.run, "passive"),
    ("TLS/HSTS", tls.run, "passive"),
    ("DNS hygiene", dns.run, "passive"),
    ("Claude review", llm_review.run, "passive"),
]

ACTIVE_CHECKS = [
    ("RLS probing", rls_probe.run),
    ("Brute-force rate limit", rate_limit.run),
    ("Prompt injection", prompt_injection.run),
    ("Privilege escalation", privilege_escalation.run),
    ("Monetization bypass", monetization_bypass.run),
    ("Stored XSS", stored_xss.run),
]


async def scan(ctx: ScanContext | str, on_progress=None) -> ScanResult:
    """Run all checks. Accepts either a ScanContext or a bare URL string for backwards compat."""
    if isinstance(ctx, str):
        ctx = ScanContext(url=ctx)

    result = ScanResult(url=ctx.url)
    timeout = httpx.Timeout(15.0, connect=5.0)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "lovable-audit/0.3"},
    ) as client:
        # Phase 1: passive checks (parallel)
        tasks = [
            _run_passive(name, fn, source, ctx, client)
            for name, fn, source in PASSIVE_CHECKS
            if name not in ctx.skip
        ]
        for coro in asyncio.as_completed(tasks):
            cr = await coro
            result.checks.append(cr)
            if on_progress:
                on_progress(cr)

        # Phase 2: discovery (runs once, feeds active checks)
        try:
            await active_discovery.discover(ctx, client)
            active_endpoints.discover_endpoints(ctx)
        except Exception as e:
            result.checks.append(
                CheckResult(
                    name="Discovery",
                    source="active",
                    error=f"{type(e).__name__}: {e}",
                )
            )
        result.supabase_url = ctx.supabase_url
        result.supabase_anon_key_found = ctx.supabase_anon_key is not None
        result.discovered_endpoints_count = len(ctx.discovered_endpoints)

        # Phase 3: auth (if creds provided)
        if ctx.credentials:
            ok, reason = await active_auth.login(ctx, client)
            result.authenticated = ok
            result.checks.append(
                CheckResult(
                    name="Authentication",
                    source="active",
                    findings=[],
                    skipped=not ok,
                    skip_reason=None if ok else f"logowanie nieudane: {reason}",
                    attempted=True,
                )
            )
            if on_progress:
                on_progress(result.checks[-1])

        # Phase 4: active checks (sequential)
        for name, fn in ACTIVE_CHECKS:
            if name in ctx.skip:
                continue
            if ctx.waf_blocked:
                cr = CheckResult(
                    name=name,
                    source="active",
                    skipped=True,
                    skip_reason="WAF zablokował dalsze skanowanie",
                    attempted=False,
                )
            else:
                cr = await _run_active(name, fn, ctx, client)
            result.checks.append(cr)
            if on_progress:
                on_progress(cr)

    # Preserve display order
    order_map = {}
    for i, (n, _, _) in enumerate(PASSIVE_CHECKS):
        order_map[n] = i
    order_map["Discovery"] = 100
    order_map["Authentication"] = 101
    for i, (n, _) in enumerate(ACTIVE_CHECKS):
        order_map[n] = 200 + i
    result.checks.sort(key=lambda c: order_map.get(c.name, 999))
    return result


async def _run_passive(name, fn, source, ctx: ScanContext, client) -> CheckResult:
    cr = CheckResult(name=name, source=source)
    try:
        out = await _invoke(fn, ctx, client)
        cr.findings, cr.skipped, cr.skip_reason = _normalize(out)
        for f in cr.findings:
            f.source = source
    except Exception as e:
        cr.error = f"{type(e).__name__}: {e}"
    return cr


async def _run_active(name, fn, ctx: ScanContext, client) -> CheckResult:
    cr = CheckResult(name=name, source="active")
    try:
        out = await fn(ctx, client)
        cr.findings, cr.skipped, cr.skip_reason = _normalize(out)
        for f in cr.findings:
            f.source = "active"
    except WAFBlocked as e:
        ctx.waf_blocked = True
        cr.skipped = True
        cr.skip_reason = str(e)
    except Exception as e:
        cr.error = f"{type(e).__name__}: {e}"
    return cr


async def _invoke(fn, ctx: ScanContext, client):
    """Invoke a check whether it takes (url, client) or (ctx, client)."""
    sig = inspect.signature(fn)
    first_param = next(iter(sig.parameters), None)
    if first_param in ("ctx", "context"):
        return await fn(ctx, client)
    return await fn(ctx.url, client)


def _normalize(out) -> tuple[list[Finding], bool, str | None]:
    if isinstance(out, tuple):
        findings, skip_reason = out
        return findings or [], bool(skip_reason), skip_reason
    return out or [], False, None
