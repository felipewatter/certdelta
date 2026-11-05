"""Review certificate identity changes between two versioned manifest snapshots."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from certdelta.inspector import scan
from certdelta.model import Finding, Report


def diff(before: str | Path, after: str | Path, now: datetime | None = None) -> Report:
    old = scan(before, now)
    new = scan(after, now)
    previous = {s["id"]: s for s in old.services}
    updated = {s["id"]: s for s in new.services}
    report = Report(
        operation="diff", services=new.services.copy(), findings=new.findings.copy(),
        metadata={"before": Path(before).name, "after": Path(after).name,
                  "evaluation_time": new.metadata["evaluation_time"]},
    )

    def add(rule: str, sev: str, sid: str, msg: str, file: str, fix: str, **evidence: object) -> None:
        report.findings.append(Finding(rule, sev, sid, msg, file, fix, evidence))

    for sid in sorted(previous.keys() - updated.keys()):
        add("SERVICE_REMOVED", "medium", sid, "Service removed from the managed inventory.",
            previous[sid]["file"], "Confirm this service was deliberately retired.")
    for sid in sorted(updated.keys() - previous.keys()):
        add("SERVICE_ADDED", "note", sid, "New service registered in certificate inventory.",
            updated[sid]["file"], "Review the service owner, hostname, and CA policy.")
    for sid in sorted(previous.keys() & updated.keys()):
        a, b = previous[sid], updated[sid]
        file = b["file"]
        extra = sorted(set(b["dns_names"]) - set(a["dns_names"]))
        lost = sorted(set(a["dns_names"]) - set(b["dns_names"]))
        if extra:
            level = "high" if any(n.startswith("*.") for n in extra) else "medium"
            add("SAN_SCOPE_EXPANDED", level, sid, "Issued identity scope expanded with new SAN entries.",
                file, "Approve added hostnames and verify ownership before deployment.", added=extra)
        if lost:
            add("SAN_SCOPE_REDUCED", "low", sid, "SAN entries were removed.", file,
                "Check that removed DNS names are not used by existing clients.", removed=lost)
        if a["issuer"] != b["issuer"]:
            add("ISSUER_CHANGED", "medium", sid, "The certificate issuer changed.", file,
                "Confirm the new CA is authorized and client trust stores support the transition.",
                before=a["issuer"], after=b["issuer"])
        if a["key_type"] != b["key_type"]:
            add("KEY_TYPE_CHANGED", "note", sid, "Certificate public-key algorithm changed.", file,
                "Confirm the new algorithm is approved for the target TLS clients.",
                before=a["key_type"], after=b["key_type"])
        elif b["key_bits"] < a["key_bits"]:
            add("KEY_STRENGTH_REDUCED", "high", sid, "Certificate key size decreased.", file,
                "Review crypto agility and reject unapproved key-strength regressions.",
                before=a["key_bits"], after=b["key_bits"])
        if a["spki_pin"] != b["spki_pin"]:
            add("PUBLIC_KEY_ROTATED", "note", sid, "SubjectPublicKeyInfo changed.", file,
                "Update approved SPKI pins in a staged rollout if pinning is in use.")
        if a["trust"] == "verified" and b["trust"] != "verified":
            add("TRUST_REGRESSION", "critical", sid,
                "Previously verified certificate is no longer verified by current policy.",
                file, "Block rollout until explicit path and hostname verification succeeds.",
                before=a["trust"], after=b["trust"])
        if a["sha256_fingerprint"] != b["sha256_fingerprint"]:
            add("CERTIFICATE_REPLACED", "note", sid, "The leaf certificate changed.", file,
                "Check change approval, renewal records and post-deployment monitoring.")
    report.sort()
    return report
