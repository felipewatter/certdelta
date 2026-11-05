from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import yaml
from cryptography.hazmat.primitives import serialization

from certdelta.cli import main
from certdelta.drift import diff
from certdelta.inspector import scan
from certdelta.loader import InputError, load_manifest
from certdelta.report import render, to_sarif


def rule_ids(report):
    return {f.rule_id for f in report.findings}


def test_happy_path_trusted(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path)
    result = scan(manifest)
    assert result.services[0]["trust"] == "verified"
    assert not result.findings
    assert not result.fails("high")


def test_reproducible_report(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path)
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    assert render(scan(manifest, now), "json") == render(scan(manifest, now), "json")


def test_expiry_risk(tmp_path, pki_factory):
    path, _, _ = pki_factory(tmp_path, expiry_days=4)
    result = scan(path)
    assert "CERT_EXPIRING" in rule_ids(result)
    assert result.fails("medium")
    assert not result.fails("high")


def test_expired_is_blocked(tmp_path, pki_factory):
    path, _, _ = pki_factory(tmp_path, expiry_days=-2, valid_from_days=-10)
    result = scan(path)
    assert {"CERT_EXPIRED", "PKIX_VERIFICATION_FAILED"} <= rule_ids(result)
    assert result.fails("high")


def test_future_validity(tmp_path, pki_factory):
    path, _, _ = pki_factory(tmp_path, valid_from_days=5)
    assert "CERT_NOT_YET_VALID" in rule_ids(scan(path))


def test_wrong_dns_name_rejected(tmp_path, pki_factory):
    path, _, _ = pki_factory(tmp_path, alt_names=["wrong.example.test"])
    assert "PKIX_VERIFICATION_FAILED" in rule_ids(scan(path))


def test_wrong_trust_root(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path / "a")
    _, _, other = pki_factory(tmp_path / "b")
    (tmp_path / "a" / "root.pem").write_bytes(other.public_bytes(serialization.Encoding.PEM))
    assert "PKIX_VERIFICATION_FAILED" in rule_ids(scan(manifest))


def test_explicit_trust_required(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, trust=False)
    result = scan(manifest)
    assert "TRUST_NOT_CONFIGURED" in rule_ids(result)
    assert result.services[0]["trust"] == "unchecked"


def test_trust_optout_is_explicit(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, trust=False, policy={"require_trust": False})
    report = scan(manifest)
    assert not report.findings
    assert report.services[0]["trust"] == "unchecked"


def test_reject_weak_rsa(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, key_size=1024, trust=False)
    assert "WEAK_RSA_KEY" in rule_ids(scan(manifest))


def test_server_auth_eku(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, eku=False)
    result = scan(manifest)
    assert "MISSING_SERVER_AUTH_EKU" in rule_ids(result)
    assert "PKIX_VERIFICATION_FAILED" in rule_ids(result)


def test_ca_marked_leaf(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, is_ca=True)
    assert "CA_AS_TLS_LEAF" in rule_ids(scan(manifest))


def test_dns_allowlist(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, policy={"allowed_dns_suffixes": [".other.test"]})
    assert "DNS_OUTSIDE_POLICY" in rule_ids(scan(manifest))


def test_dns_allowlist_allows_exact_and_suffix(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, policy={"allowed_dns_suffixes": [".example.test"]})
    assert "DNS_OUTSIDE_POLICY" not in rule_ids(scan(manifest))


def test_issuer_allowlist(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, policy={"allowed_issuer_names": ["CN=Another CA"]})
    assert "UNAPPROVED_ISSUER" in rule_ids(scan(manifest))


def test_lifetime_policy(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, expiry_days=400, trust=False)
    assert "CERT_LIFETIME" in rule_ids(scan(manifest))


def test_valid_sarif_shape(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, trust=False)
    result = to_sarif(scan(manifest))
    assert result["version"] == "2.1.0"
    assert result["runs"][0]["results"][0]["ruleId"] == "TRUST_NOT_CONFIGURED"
    assert result["runs"][0]["tool"]["driver"]["rules"]


def test_json_includes_fix_guidance(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, trust=False)
    report = json.loads(render(scan(manifest), "json"))
    assert report["findings"][0]["remediation"]
    assert report["summary"]["services"] == 1


def test_symlink_rejected(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path)
    (tmp_path / "link.pem").symlink_to(tmp_path / "leaf.pem")
    data = yaml.safe_load(manifest.read_text())
    data["services"][0]["leaf"] = "link.pem"
    manifest.write_text(yaml.safe_dump(data))
    with pytest.raises(InputError):
        load_manifest(manifest)


def test_escape_rejected(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path / "inside")
    data = yaml.safe_load(manifest.read_text())
    data["services"][0]["leaf"] = "../../outside.pem"
    manifest.write_text(yaml.safe_dump(data))
    with pytest.raises(InputError):
        load_manifest(manifest)


def test_duplicate_yaml_key_rejected(tmp_path):
    path = tmp_path / "manifest.yaml"
    path.write_text('version: 1\nversion: 1\nservices: []\n')
    with pytest.raises(InputError, match="Duplicate"):
        load_manifest(path)


def test_invalid_policy_fails(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, policy={"min_rsa_bits": "two thousand"})
    with pytest.raises(InputError, match="min_rsa_bits"):
        load_manifest(manifest)


def test_unknown_policy_fails(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path, policy={"accept_any_ca": True})
    with pytest.raises(InputError, match="unknown policy"):
        load_manifest(manifest)


def test_duplicate_certificate_rejected(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path)
    data = yaml.safe_load(manifest.read_text())
    data["services"][0]["intermediates"] = ["root.pem"]
    manifest.write_text(yaml.safe_dump(data))
    with pytest.raises(InputError, match="duplicate certificate"):
        scan(manifest)


def test_diff_detects_dns_expansion(tmp_path, pki_factory):
    before, _, _ = pki_factory(tmp_path / "before", alt_names=["api.example.test"])
    after, _, _ = pki_factory(tmp_path / "after", alt_names=["api.example.test", "new.example.test"])
    report = diff(before, after)
    assert "SAN_SCOPE_EXPANDED" in rule_ids(report)
    assert "PUBLIC_KEY_ROTATED" in rule_ids(report)
    assert "CERTIFICATE_REPLACED" in rule_ids(report)


def test_diff_detects_wildcard_critical_scope(tmp_path, pki_factory):
    before, _, _ = pki_factory(tmp_path / "before")
    after, _, _ = pki_factory(tmp_path / "after", alt_names=["api.example.test", "*.example.test"])
    finding = next(f for f in diff(before, after).findings if f.rule_id == "SAN_SCOPE_EXPANDED")
    assert finding.severity == "high"


def test_diff_detects_issuer_change(tmp_path, pki_factory):
    before, _, _ = pki_factory(tmp_path / "before")
    after, _, _ = pki_factory(tmp_path / "after", issuer_name="New CA")
    assert "ISSUER_CHANGED" in rule_ids(diff(before, after))


def test_diff_trust_regression(tmp_path, pki_factory):
    before, _, _ = pki_factory(tmp_path / "before")
    after, _, _ = pki_factory(tmp_path / "after", trust=False, policy={"require_trust": False})
    assert "TRUST_REGRESSION" in rule_ids(diff(before, after))


def test_diff_detects_key_size_reduction(tmp_path, pki_factory):
    before, _, _ = pki_factory(tmp_path / "before", key_size=2048)
    after, _, _ = pki_factory(tmp_path / "after", key_size=1024)
    assert "KEY_STRENGTH_REDUCED" in rule_ids(diff(before, after))


def test_cli_exit_status(tmp_path, pki_factory, capsys):
    manifest, _, _ = pki_factory(tmp_path, trust=False)
    assert main(["scan", str(manifest), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["operation"] == "scan"
    assert main(["scan", str(manifest), "--fail-on", "critical"]) == 0


def test_cli_output_and_no_symlink(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path / "bundle", trust=False)
    target = tmp_path / "report.sarif"
    assert main(["scan", str(manifest), "--output", str(target), "--format", "sarif"]) == 1
    assert json.loads(target.read_text())["version"] == "2.1.0"
    link = tmp_path / "link.sarif"
    link.symlink_to(target)
    assert main(["scan", str(manifest), "--output", str(link)]) == 2


def test_cli_invalid_timestamp(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path)
    assert main(["scan", str(manifest), "--at", "2026-11-05"]) == 2
    assert main(["scan", str(manifest), "--at", "invalid"]) == 2


def test_cli_diff(tmp_path, pki_factory, capsys):
    before, _, _ = pki_factory(tmp_path / "old")
    after, _, _ = pki_factory(tmp_path / "new", alt_names=["api.example.test", "new.example.test"])
    assert main(["diff", "--before", str(before), "--after", str(after), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["operation"] == "diff"


def test_multiple_services(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path)
    other, _, _ = pki_factory(tmp_path / "second", hostname="other.example.test")
    # Both sets must be inside the main manifest directory.
    payload = yaml.safe_load(manifest.read_text())
    payload["services"].append({"id": "other", "leaf": "second/leaf.pem",
                                "hostname": "other.example.test", "trust_roots": "second/root.pem"})
    manifest.write_text(yaml.safe_dump(payload))
    report = scan(manifest)
    assert len(report.services) == 2
    assert all(x["trust"] == "verified" for x in report.services)


def test_der_leaf(tmp_path, pki_factory):
    manifest, cert, _ = pki_factory(tmp_path)
    (tmp_path / "leaf.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    data = yaml.safe_load(manifest.read_text())
    data["services"][0]["leaf"] = "leaf.der"
    manifest.write_text(yaml.safe_dump(data))
    assert scan(manifest).services[0]["trust"] == "verified"


def test_reject_json_duplicate_key(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"version": 1, "version": 1, "services": []}')
    with pytest.raises(InputError, match="Duplicate JSON"):
        load_manifest(manifest)


def test_reject_bool_version(tmp_path):
    manifest = tmp_path / "manifest.yml"
    manifest.write_text('version: true\nservices: []\n')
    with pytest.raises(InputError, match="version: 1"):
        load_manifest(manifest)


def test_reject_yaml_anchors(tmp_path):
    manifest = tmp_path / "manifest.yml"
    manifest.write_text('version: 1\npolicy: &foo {min_rsa_bits: 2048}\nservices: []\n')
    with pytest.raises(InputError, match="anchors"):
        load_manifest(manifest)


def test_reject_service_field_typo(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path)
    data = yaml.safe_load(manifest.read_text())
    data["services"][0]["trusted_roots"] = "root.pem"
    manifest.write_text(yaml.safe_dump(data))
    with pytest.raises(InputError, match="Unknown service"):
        load_manifest(manifest)


def test_reject_private_key_in_cert_file(tmp_path, pki_factory):
    manifest, _, _ = pki_factory(tmp_path)
    with (tmp_path / "leaf.pem").open("ab") as output:
        output.write(b"\n-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----")
    with pytest.raises(InputError, match="Private-key"):
        scan(manifest)
