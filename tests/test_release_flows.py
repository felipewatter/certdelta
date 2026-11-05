"""Integration regression scenarios for the installable CLI and untrusted inputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from certdelta.cli import main
from certdelta.drift import diff
from certdelta.loader import InputError, load_manifest
from certdelta.report import to_sarif


def _rewrite_manifest(path: Path, transform) -> None:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    transform(payload)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")


@pytest.mark.parametrize("threshold,expected", [
    ("none", 0), ("note", 1), ("low", 1), ("medium", 1),
    ("high", 0), ("critical", 0),
])
def test_scan_exit_threshold_matrix(tmp_path, pki_factory, threshold, expected, capsys):
    manifest, _, _ = pki_factory(tmp_path, expiry_days=6)
    assert main(["scan", str(manifest), "--fail-on", threshold]) == expected
    assert "CERT_EXPIRING" in capsys.readouterr().out


def test_diff_exit_status_with_expansion(tmp_path, pki_factory, capsys):
    a, _, _ = pki_factory(tmp_path / "old")
    b, _, _ = pki_factory(tmp_path / "new", alt_names=["api.example.test", "new.example.test"])
    args = ["diff", "--before", str(a), "--after", str(b)]
    assert main([*args, "--fail-on", "medium"]) == 1
    assert "SAN_SCOPE_EXPANDED" in capsys.readouterr().out
    assert main([*args, "--fail-on", "high"]) == 0
    capsys.readouterr()


def test_diff_inventory_add_remove(tmp_path, pki_factory):
    before, _, _ = pki_factory(tmp_path / "before")
    after, _, _ = pki_factory(tmp_path / "after")
    _rewrite_manifest(after, lambda data: data["services"][0].update(id="replacement"))
    results = {finding.rule_id for finding in diff(before, after).findings}
    assert "SERVICE_REMOVED" in results
    assert "SERVICE_ADDED" in results


def test_scan_json_and_sarif_round_trip(tmp_path, pki_factory, capsys):
    path, _, _ = pki_factory(tmp_path / "input", trust=False)
    for fmt in ("text", "json", "sarif"):
        target = tmp_path / f"output-{fmt}.txt"
        assert main(["scan", str(path), "--format", fmt, "--output", str(target)]) == 1
        output = target.read_text(encoding="utf-8")
        assert "TRUST_NOT_CONFIGURED" in output
        if fmt in ("json", "sarif"):
            data = json.loads(output)
            assert data["version"] == "2.1.0" if fmt == "sarif" else data["schema_version"] == "1.0"
        capsys.readouterr()


def test_timestamp_determinism(tmp_path, pki_factory, capsys):
    manifest, _, _ = pki_factory(tmp_path)
    args = ["scan", str(manifest), "--format", "json", "--at", "2026-11-05T10:00:00Z"]
    assert main(args) == 0
    first = capsys.readouterr().out
    assert main(args) == 0
    second = capsys.readouterr().out
    assert first == second


def test_invalid_cert_returns_error_code(tmp_path, pki_factory, capsys):
    manifest, _, _ = pki_factory(tmp_path)
    (tmp_path / "leaf.pem").write_text("-----BEGIN CERTIFICATE-----\nnot-valid\n-----END CERTIFICATE-----\n")
    assert main(["scan", str(manifest)]) == 2
    assert "input error" in capsys.readouterr().err


def test_nonexistent_manifest_returns_error_code(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "absent.yml")]) == 2
    assert "input error" in capsys.readouterr().err


def test_nonexistent_report_parent_returns_error_code(tmp_path, pki_factory, capsys):
    manifest, _, _ = pki_factory(tmp_path)
    assert main(["scan", str(manifest), "--output", str(tmp_path / "missing" / "report.json")]) == 2
    assert "input error" in capsys.readouterr().err


def test_yaml_rejects_non_string_keys(tmp_path, capsys):
    manifest = tmp_path / "manifest.yml"
    manifest.write_text('version: 1\n1: integer-key\nservices: []\n', encoding="utf-8")
    with pytest.raises(InputError, match="mapping keys must be strings"):
        load_manifest(manifest)
    assert main(["scan", str(manifest)]) == 2
    assert "input error" in capsys.readouterr().err


def test_sarif_findings_have_rule_definition(tmp_path, pki_factory):
    from certdelta.inspector import scan
    manifest, _, _ = pki_factory(tmp_path, trust=False)
    data = to_sarif(scan(manifest))
    run = data["runs"][0]
    declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert declared
    for result in run["results"]:
        assert result["ruleId"] in declared
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
