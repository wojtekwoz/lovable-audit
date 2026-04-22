from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Source = Literal["passive", "active"]


@dataclass
class Finding:
    id: str
    severity: Severity
    title: str
    evidence: str
    recommendation: str
    cvss: float | None = None
    source: Source = "passive"


@dataclass
class CheckResult:
    name: str
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    error: str | None = None
    source: Source = "passive"
    attempted: bool = True


@dataclass
class ScanResult:
    url: str
    checks: list[CheckResult] = field(default_factory=list)
    # populated by discovery so the report can show what we learned
    supabase_url: str | None = None
    supabase_anon_key_found: bool = False
    authenticated: bool = False
    discovered_endpoints_count: int = 0

    @property
    def findings(self) -> list[Finding]:
        return [f for c in self.checks for f in c.findings]

    def count(self, severity: Severity, source: Source | None = None) -> int:
        return sum(
            1
            for f in self.findings
            if f.severity == severity and (source is None or f.source == source)
        )


@dataclass
class ScanContext:
    url: str
    credentials: tuple[str, str] | None = None
    supabase_key_override: str | None = None
    aggressive: bool = False
    skip: set[str] = field(default_factory=set)
    # populated at runtime by discovery/auth
    supabase_url: str | None = None
    supabase_anon_key: str | None = None
    session_jwt: str | None = None
    session_user_id: str | None = None
    discovered_endpoints: list[dict] = field(default_factory=list)
    js_bundles: list[tuple[str, str]] = field(default_factory=list)  # (url, content)
    waf_blocked: bool = False
