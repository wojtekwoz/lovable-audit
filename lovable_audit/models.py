from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class Finding:
    id: str
    severity: Severity
    title: str
    evidence: str
    recommendation: str
    cvss: float | None = None


@dataclass
class CheckResult:
    name: str
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    error: str | None = None


@dataclass
class ScanResult:
    url: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [f for c in self.checks for f in c.findings]

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)
