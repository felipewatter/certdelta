"""Defensive, local-only manifest and PEM/DER handling."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm

MAX_MANIFEST = 1_000_000
MAX_CERT_FILE = 2_000_000
MAX_SERVICES = 500
MAX_CA_CERTS = 100


class InputError(ValueError):
    """Invalid user-supplied configuration or certificate."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _unique_map(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict:
    pairs = loader.construct_pairs(node, deep=True)
    out: dict = {}
    for k, v in pairs:
        if not isinstance(k, str):
            raise InputError("YAML mapping keys must be strings")
        if k in out:
            raise InputError(f"Duplicate YAML key: {k}")
        out[k] = v
    return out


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_map)


@dataclass(frozen=True)
class ServiceSpec:
    id: str
    leaf: Path
    intermediates: tuple[Path, ...]
    trust_roots: Path | None
    hostname: str | None
    policy: dict[str, Any]
    manifest: Path


def _local_file(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise InputError("File paths must be non-empty strings")
    raw = root / name
    try:
        resolved = raw.resolve(strict=True)
        resolved.relative_to(root)
        # Avoid symlinked files or parent directories as an explicit security boundary.
        cursor = raw
        while cursor != root:
            if cursor.is_symlink():
                raise InputError(f"Symbolic links are not allowed: {name}")
            cursor = cursor.parent
        if not resolved.is_file():
            raise InputError(f"Not a regular file: {name}")
    except (OSError, RuntimeError, ValueError) as exc:
        raise InputError(f"Cannot load a file outside the manifest directory: {name}") from exc
    return resolved


def _read_bounded(file: Path, max_bytes: int) -> bytes:
    if file.stat().st_size > max_bytes:
        raise InputError(f"Input exceeds {max_bytes} bytes: {file.name}")
    with file.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise InputError(f"Input exceeds {max_bytes} bytes: {file.name}")
    return data


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path: str | Path) -> list[ServiceSpec]:
    target = Path(path).resolve(strict=True)
    if not target.is_file():
        raise InputError("Manifest is not a regular file")
    root = target.parent
    data = _read_bounded(target, MAX_MANIFEST)
    try:
        if target.suffix.lower() != ".json":
            if any(isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken))
                   for token in yaml.scan(data)):
                raise InputError("YAML anchors and aliases are not allowed")
        if target.suffix.lower() == ".json":
            raw = json.loads(data, object_pairs_hook=_unique_json_pairs)
        else:
            raw = yaml.load(data, Loader=_UniqueKeyLoader)  # SafeLoader subclass prevents unsafe object construction
    except (yaml.YAMLError, json.JSONDecodeError, UnicodeError) as exc:
        raise InputError(f"Invalid manifest format: {exc}") from exc
    if not isinstance(raw, dict) or type(raw.get("version")) is not int or raw["version"] != 1:
        raise InputError("Manifest must be an object with version: 1")
    services = raw.get("services")
    if not isinstance(services, list) or not 1 <= len(services) <= MAX_SERVICES:
        raise InputError(f"services must contain 1..{MAX_SERVICES} entries")
    defaults = raw.get("policy", {})
    if not isinstance(defaults, dict):
        raise InputError("policy must be a mapping")
    out: list[ServiceSpec] = []
    seen: set[str] = set()
    allowed_policy = {
        "expiry_warning_days", "min_rsa_bits", "min_ec_bits", "max_validity_days",
        "allowed_dns_suffixes", "allowed_issuer_names", "require_trust",
    }
    for idx, item in enumerate(services):
        if not isinstance(item, dict):
            raise InputError(f"services[{idx}] must be a mapping")
        allowed_fields = {"id", "leaf", "hostname", "trust_roots", "intermediates", "policy"}
        if set(item) - allowed_fields:
            raise InputError(f"Unknown service fields: {sorted(set(item) - allowed_fields)}")
        sid = item.get("id")
        if not isinstance(sid, str) or not sid or len(sid) > 128 or sid in seen:
            raise InputError(f"Invalid or duplicate service id: {sid}")
        seen.add(sid)
        local_policy = item.get("policy", {})
        if not isinstance(local_policy, dict):
            raise InputError(f"Service {sid}: policy must be a mapping")
        policy = {**defaults, **local_policy}
        if set(policy) - allowed_policy:
            raise InputError(f"Service {sid}: unknown policy keys: {sorted(set(policy)-allowed_policy)}")
        for key, default in (
            ("expiry_warning_days", 30), ("min_rsa_bits", 2048),
            ("min_ec_bits", 256), ("max_validity_days", 398),
        ):
            n = policy.setdefault(key, default)
            if type(n) is not int or n < 0 or n > 100000:
                raise InputError(f"Service {sid}: {key} must be a nonnegative integer")
        policy.setdefault("require_trust", True)
        if type(policy["require_trust"]) is not bool:
            raise InputError(f"Service {sid}: require_trust must be boolean")
        for key in ("allowed_dns_suffixes", "allowed_issuer_names"):
            if key in policy and (
                not isinstance(policy[key], list)
                or not all(isinstance(x, str) and x for x in policy[key])
            ):
                raise InputError(f"Service {sid}: {key} must be a string list")
        mids = item.get("intermediates", [])
        if not isinstance(mids, list) or len(mids) > MAX_CA_CERTS:
            raise InputError(f"Service {sid}: intermediates must be a list")
        trust = item.get("trust_roots")
        host = item.get("hostname")
        if host is not None and (not isinstance(host, str) or not host or len(host) > 253):
            raise InputError(f"Service {sid}: invalid hostname")
        if trust is not None and host is None:
            raise InputError(f"Service {sid}: hostname required for trusted TLS verification")
        out.append(ServiceSpec(
            sid, _local_file(root, item.get("leaf")),
            tuple(_local_file(root, p) for p in mids),
            _local_file(root, trust) if trust else None,
            host, policy, target,
        ))
    return out


def load_certificates(path: Path) -> list[x509.Certificate]:
    data = _read_bounded(path, MAX_CERT_FILE)
    # Combined certificate/key PEM files are deliberately unsupported.
    if any(marker in data for marker in (
        b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----",
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
    )):
        raise InputError(f"Private-key material is not accepted: {path.name}")
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            certificates = x509.load_pem_x509_certificates(data)
        else:
            certificates = [x509.load_der_x509_certificate(data)]
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise InputError(f"Invalid X.509 certificate in {path.name}: {exc}") from exc
    if not certificates or len(certificates) > MAX_CA_CERTS:
        raise InputError(f"Bad certificate count in {path.name}")
    return certificates
