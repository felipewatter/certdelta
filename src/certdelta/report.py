"""Human-readable, JSON, and GitHub Code Scanning SARIF 2.1.0 reports."""

from __future__ import annotations

import json

from certdelta.model import Report


def to_sarif(report: Report) -> dict:
    report.sort()
    ids = sorted({f.rule_id for f in report.findings})
    details = {f.rule_id: f.remediation for f in report.findings}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CertDelta", "version": "0.1.0",
                                "informationUri": "https://github.com/felipewatter/certdelta",
                                "rules": [{"id": rule, "name": rule, "shortDescription": {"text": rule},
                                           "help": {"text": details[rule]}} for rule in ids]}},
            "results": [{
                "ruleId": f.rule_id,
                "level": "error" if f.severity in ("high", "critical") else
                         "warning" if f.severity in ("medium", "low") else "note",
                "message": {"text": f"[{f.service}] {f.message} Suggested remediation: {f.remediation}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}}}],
                "properties": {"severity": f.severity, "service": f.service, "evidence": f.evidence},
            } for f in report.findings],
            "invocations": [{"executionSuccessful": True}],
        }],
    }


def render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n"
    if fmt == "sarif":
        return json.dumps(to_sarif(report), ensure_ascii=False, indent=2) + "\n"
    report.sort()
    lines = [f"CertDelta {report.operation.upper()} | services: {len(report.services)} | findings: {len(report.findings)}"]
    for service in report.services:
        lines.append(f"  {service['id']}: trust={service['trust']} expires={service['valid_until']} "
                     f"key={service['key_type']}/{service['key_bits']}")
    if not report.findings:
        lines.append("  No findings for the supplied policy and snapshot.")
    for f in report.findings:
        lines.append(f"  [{f.severity.upper():8}] {f.rule_id} | {f.service} | {f.message}")
        lines.append(f"    Fix: {f.remediation}")
    return "\n".join(lines) + "\n"
