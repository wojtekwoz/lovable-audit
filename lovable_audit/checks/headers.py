from __future__ import annotations

import httpx

from ..models import Finding

EXPECTED = {
    "content-security-policy": {
        "severity": "HIGH",
        "title": "Brak nagłówka Content-Security-Policy",
        "cvss": 6.1,
        "recommendation": "Dodaj CSP blokujący inline scripts i zewnętrzne źródła. Minimum: default-src 'self'.",
    },
    "x-frame-options": {
        "severity": "MEDIUM",
        "title": "Brak nagłówka X-Frame-Options",
        "cvss": 4.3,
        "recommendation": "Ustaw X-Frame-Options: DENY (lub CSP frame-ancestors) aby zablokować clickjacking.",
    },
    "x-content-type-options": {
        "severity": "LOW",
        "title": "Brak nagłówka X-Content-Type-Options",
        "cvss": 3.1,
        "recommendation": "Ustaw X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "severity": "LOW",
        "title": "Brak nagłówka Referrer-Policy",
        "cvss": 2.6,
        "recommendation": "Ustaw Referrer-Policy: strict-origin-when-cross-origin.",
    },
    "strict-transport-security": {
        "severity": "HIGH",
        "title": "Brak nagłówka HSTS",
        "cvss": 5.3,
        "recommendation": "Ustaw Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    },
    "permissions-policy": {
        "severity": "LOW",
        "title": "Brak nagłówka Permissions-Policy",
        "cvss": 2.0,
        "recommendation": "Ustaw Permissions-Policy ograniczający dostęp do geolocation, camera, microphone itp.",
    },
}


async def run(url: str, client: httpx.AsyncClient) -> list[Finding]:
    r = await client.get(url)
    present = {k.lower(): v for k, v in r.headers.items()}
    findings: list[Finding] = []
    for i, (name, meta) in enumerate(EXPECTED.items(), start=1):
        if name not in present:
            findings.append(
                Finding(
                    id=f"HDR-{i:02d}",
                    severity=meta["severity"],  # type: ignore[arg-type]
                    title=meta["title"],
                    evidence=f"Odpowiedź {r.status_code} na {url} nie zawiera nagłówka `{name}`.",
                    recommendation=meta["recommendation"],
                    cvss=meta["cvss"],
                )
            )
    # HSTS present but weak
    hsts = present.get("strict-transport-security", "")
    if hsts:
        try:
            parts = [p.strip() for p in hsts.split(";")]
            max_age = next((int(p.split("=")[1]) for p in parts if p.startswith("max-age=")), 0)
            if max_age < 15552000:
                findings.append(
                    Finding(
                        id="HDR-HSTS-WEAK",
                        severity="MEDIUM",
                        title="Słaby HSTS max-age",
                        evidence=f"HSTS header: `{hsts}` — max-age={max_age}s, zalecane >= 15552000 (6 miesięcy).",
                        recommendation="Zwiększ max-age do minimum 15552000 (6 miesięcy), idealnie 31536000 (rok).",
                        cvss=3.7,
                    )
                )
        except (ValueError, IndexError):
            pass
    return findings
