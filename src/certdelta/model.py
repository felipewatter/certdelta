"""Stable, structured security report records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = {"note": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    service: str
    message: str
    file: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    operation: str
    findings: list[Finding] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def sort(self) -> None:
        self.findings.sort(key=lambda f: (-SEVERITIES[f.severity], f.service, f.rule_id, f.file, f.message))
        self.services.sort(key=lambda s: s["id"])

    def to_dict(self) -> dict[str, Any]:
        self.sort()
        return {
            "schema_version": "1.0",
            "tool": "certdelta",
            "operation": self.operation,
            "metadata": self.metadata,
            "services": self.services,
            "summary": {
                "services": len(self.services),
                "findings": len(self.findings),
                "by_severity": {
                    s: sum(f.severity == s for f in self.findings) for s in SEVERITIES
                },
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def fails(self, threshold: str) -> bool:
        return threshold != "none" and any(
            SEVERITIES[f.severity] >= SEVERITIES[threshold] for f in self.findings
        )
