from __future__ import annotations

import asyncio

import httpx

from .checks import cors, dns, headers, llm_review, secrets, tls
from .models import CheckResult, Finding, ScanResult, Severity

__all__ = ["CheckResult", "Finding", "ScanResult", "Severity", "scan"]


CHECKS = [
    ("Security headers", headers.run),
    ("CORS configuration", cors.run),
    ("Exposed secrets", secrets.run),
    ("TLS/HSTS", tls.run),
    ("DNS hygiene", dns.run),
    ("Claude review", llm_review.run),
]


async def scan(url: str, on_progress=None) -> ScanResult:
    result = ScanResult(url=url)
    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "lovable-audit/0.1"},
    ) as client:
        tasks = [_run_check(name, fn, url, client) for name, fn in CHECKS]
        for coro in asyncio.as_completed(tasks):
            cr = await coro
            result.checks.append(cr)
            if on_progress:
                on_progress(cr)
    # preserve display order
    order = {name: i for i, (name, _) in enumerate(CHECKS)}
    result.checks.sort(key=lambda c: order.get(c.name, 99))
    return result


async def _run_check(name, fn, url, client) -> CheckResult:
    cr = CheckResult(name=name)
    try:
        out = await fn(url, client)
        if isinstance(out, tuple):
            findings, skip_reason = out
            if skip_reason:
                cr.skipped = True
                cr.skip_reason = skip_reason
            cr.findings = findings
        else:
            cr.findings = out or []
    except Exception as e:
        cr.error = f"{type(e).__name__}: {e}"
    return cr
