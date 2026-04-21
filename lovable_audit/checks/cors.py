from __future__ import annotations

import httpx

from ..models import Finding

EVIL_ORIGIN = "https://evil.example.com"


async def run(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    # Preflight to root
    try:
        r = await client.request(
            "OPTIONS",
            url,
            headers={
                "Origin": EVIL_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
    except httpx.HTTPError:
        # Fall back to GET — some servers don't answer OPTIONS on root
        r = await client.get(url, headers={"Origin": EVIL_ORIGIN})

    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()

    if acao == "*":
        severity = "HIGH" if acac == "true" else "MEDIUM"
        findings.append(
            Finding(
                id="CORS-01",
                severity=severity,
                title="CORS akceptuje dowolne źródło (wildcard)",
                evidence=f"`Access-Control-Allow-Origin: *`"
                + (f" + `Access-Control-Allow-Credentials: true` (krytyczne!)" if acac == "true" else ""),
                recommendation="Zdefiniuj explicitną listę dozwolonych originów. Nigdy nie łącz `*` z `Allow-Credentials: true`.",
                cvss=6.5 if acac == "true" else 5.3,
            )
        )
    elif acao and acao == EVIL_ORIGIN:
        findings.append(
            Finding(
                id="CORS-02",
                severity="HIGH",
                title="CORS odbija dowolne źródło (reflected origin)",
                evidence=f"Wysłano `Origin: {EVIL_ORIGIN}`, serwer odpowiedział `Access-Control-Allow-Origin: {acao}`.",
                recommendation="Waliduj Origin przeciwko whitelist. Zwracaj ACAO tylko dla znanych domen.",
                cvss=6.1,
            )
        )
    return findings
