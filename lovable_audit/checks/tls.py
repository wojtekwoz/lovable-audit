from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ..models import Finding


async def run(url: str, client: httpx.AsyncClient) -> tuple[list[Finding], str | None]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return (
            [
                Finding(
                    id="TLS-01",
                    severity="HIGH",
                    title="Strona nie używa HTTPS",
                    evidence=f"URL: {url}",
                    recommendation="Wymuś HTTPS. Ustaw redirect 301 z http → https i skonfiguruj HSTS.",
                    cvss=7.4,
                )
            ],
            None,
        )
    host = parsed.hostname
    if not host:
        return [], "nie udało się odczytać hosta z URL"

    findings: list[Finding] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        return [
            Finding(
                id="TLS-02",
                severity="HIGH",
                title="Problem z certyfikatem TLS",
                evidence=f"Błąd podczas handshake: {type(e).__name__}: {e}",
                recommendation="Zweryfikuj certyfikat (Let's Encrypt / CloudFlare) i poprawność chain.",
                cvss=7.0,
            )
        ], None

    # Check expiry
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
            if days_left < 14:
                findings.append(
                    Finding(
                        id="TLS-03",
                        severity="MEDIUM" if days_left > 0 else "HIGH",
                        title=f"Certyfikat wygasa za {days_left} dni",
                        evidence=f"notAfter: {not_after}",
                        recommendation="Skonfiguruj auto-renewal (Let's Encrypt / ACME).",
                        cvss=5.0 if days_left > 0 else 7.5,
                    )
                )
        except ValueError:
            pass
    return findings, None
