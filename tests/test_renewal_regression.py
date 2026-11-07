"""Deterministic certificate lifetime boundaries and identity drift regressions."""
from datetime import timedelta

from certdelta.inspector import scan
from certdelta.drift import diff


def rules(report):
    return {finding.rule_id for finding in report.findings}


def test_expiration_transition_never_reports_expired_certificate_as_healthy(tmp_path, pki_factory):
    manifest, certificate, _ = pki_factory(tmp_path, expiry_days=60)
    expires = certificate.not_valid_after_utc
    warning = scan(manifest, expires - timedelta(days=2))
    assert "CERT_EXPIRING" in rules(warning)
    assert "CERT_EXPIRED" not in rules(warning)
    expired = scan(manifest, expires)
    assert "CERT_EXPIRED" in rules(expired)
    assert expired.fails("critical")


def test_same_san_renewal_detects_cert_and_key_rotation_without_scope_change(tmp_path, pki_factory):
    before, _, _ = pki_factory(tmp_path / "before", alt_names=["api.example.test"])
    after, _, _ = pki_factory(tmp_path / "after", alt_names=["api.example.test"])
    changes = rules(diff(before, after))
    assert "CERTIFICATE_REPLACED" in changes
    assert "PUBLIC_KEY_ROTATED" in changes
    assert "SAN_SCOPE_EXPANDED" not in changes
    assert "SAN_SCOPE_REDUCED" not in changes


def test_wildcard_identity_expansion_is_high_risk(tmp_path, pki_factory):
    before, _, _ = pki_factory(tmp_path / "before")
    after, _, _ = pki_factory(tmp_path / "after",
                              alt_names=["api.example.test", "*.example.test"])
    report = diff(before, after)
    scope = next(f for f in report.findings if f.rule_id == "SAN_SCOPE_EXPANDED")
    assert scope.severity == "high"
    assert "*.example.test" in scope.evidence["added"]
