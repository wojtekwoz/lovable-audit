from __future__ import annotations

from urllib.parse import urlparse

import httpx
import dns.asyncresolver
import dns.exception

from ..models import Finding


async def _txt(name: str) -> list[str]:
    try:
        answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=5.0)
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer]
    except (dns.exception.DNSException, Exception):
        return []


async def _has_mx(name: str) -> bool:
    try:
        await dns.asyncresolver.resolve(name, "MX", lifetime=5.0)
        return True
    except (dns.exception.DNSException, Exception):
        return False


async def run(url: str, client: httpx.AsyncClient) -> tuple[list[Finding], str | None]:
    host = urlparse(url).hostname or ""
    # Strip leading www.
    apex = host[4:] if host.startswith("www.") else host
    # Skip for non-apex hosts (e.g. myapp.lovable.app — subdomain of provider)
    parts = apex.split(".")
    if len(parts) > 2 and apex.endswith((".lovable.app", ".vercel.app", ".netlify.app", ".pages.dev")):
        return [], f"host {apex} to subdomena providera (platformy), DNS poza kontrolą właściciela"
    if not apex or len(parts) < 2:
        return [], "brak domeny apex do sprawdzenia"

    findings: list[Finding] = []
    has_mx = await _has_mx(apex)

    if has_mx:
        # Only check SPF/DMARC if there's actual mail infrastructure
        spf_records = await _txt(apex)
        has_spf = any(t.lower().startswith("v=spf1") for t in spf_records)
        if not has_spf:
            findings.append(
                Finding(
                    id="DNS-01",
                    severity="LOW",
                    title="Brak rekordu SPF",
                    evidence=f"Domena {apex} ma MX ale brak TXT z `v=spf1`.",
                    recommendation="Dodaj SPF TXT, np.: `v=spf1 include:_spf.google.com ~all`",
                    cvss=3.1,
                )
            )
        dmarc = await _txt(f"_dmarc.{apex}")
        has_dmarc = any(t.lower().startswith("v=dmarc1") for t in dmarc)
        if not has_dmarc:
            findings.append(
                Finding(
                    id="DNS-02",
                    severity="LOW",
                    title="Brak rekordu DMARC",
                    evidence=f"Brak TXT w `_dmarc.{apex}`.",
                    recommendation="Dodaj DMARC: `_dmarc.{apex} TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{apex}\"`".replace("{apex}", apex),
                    cvss=3.1,
                )
            )
    return findings, None if has_mx else f"domena {apex} nie ma rekordów MX — pominięto SPF/DMARC"
