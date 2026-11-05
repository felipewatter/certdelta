"""Certificate inspection; PKIX trust decisions delegated to cryptography's verifier."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from certdelta.loader import InputError, ServiceSpec, load_certificates, load_manifest
from certdelta.model import Finding, Report


def _pubkey_info(cert: x509.Certificate) -> tuple[str, int]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name}", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 456
    return "unknown", 0


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(s) for s in san.get_values_for_type(x509.DNSName)]
        names += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        return sorted(set(names))
    except x509.ExtensionNotFound:
        return []


def _key_pin(cert: x509.Certificate) -> str:
    import base64
    import hashlib

    key_der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256/" + base64.b64encode(hashlib.sha256(key_der).digest()).decode("ascii")


def _matches_allowed(name: str, allowed: list[str]) -> bool:
    normalized = name.lower().rstrip(".")
    return any(
        normalized == pattern.lower().rstrip(".")
        or (pattern.startswith(".") and normalized.endswith(pattern.lower().rstrip(".")))
        for pattern in allowed
    )


def inspect_service(spec: ServiceSpec, now: datetime) -> tuple[dict[str, Any], list[Finding]]:
    leafs = load_certificates(spec.leaf)
    if len(leafs) != 1:
        raise InputError(f"Service {spec.id}: leaf must contain exactly one certificate")
    leaf = leafs[0]
    intermediates = [c for path in spec.intermediates for c in load_certificates(path)]
    roots = load_certificates(spec.trust_roots) if spec.trust_roots else []
    if len(intermediates) > 100 or len(roots) > 100:
        raise InputError(f"Service {spec.id}: too many CA certificates")
    # Explicit duplicate rejection bounds the path builder's search and makes inputs deterministic.
    fingerprints = [c.fingerprint(hashes.SHA256()) for c in [leaf, *intermediates, *roots]]
    if len(set(fingerprints)) != len(fingerprints):
        raise InputError(f"Service {spec.id}: duplicate certificate across chain/trust files")
    kind, bits = _pubkey_info(leaf)
    expiry_days = (leaf.not_valid_after_utc - now).total_seconds() / 86400
    lifetime_days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds() / 86400
    leafpath = str(spec.leaf.relative_to(spec.manifest.parent))
    try:
        signature_hash = leaf.signature_hash_algorithm
        signature_name = signature_hash.name if signature_hash else "intrinsic"
    except UnsupportedAlgorithm:
        signature_name = "unknown"
    record = {
        "id": spec.id,
        "file": leafpath,
        "hostname": spec.hostname,
        "serial_hex": format(leaf.serial_number, "x"),
        "sha256_fingerprint": leaf.fingerprint(hashes.SHA256()).hex(),
        "spki_pin": _key_pin(leaf),
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "dns_names": _sans(leaf),
        "key_type": kind,
        "key_bits": bits,
        "signature_hash": signature_name,
        "valid_from": leaf.not_valid_before_utc.isoformat(),
        "valid_until": leaf.not_valid_after_utc.isoformat(),
        "days_remaining": round(expiry_days, 2),
        "lifetime_days": round(lifetime_days, 2),
        "trust": "unchecked",
    }
    findings: list[Finding] = []

    def add(rule: str, sev: str, msg: str, fix: str, **evidence: Any) -> None:
        findings.append(Finding(rule, sev, spec.id, msg, leafpath, fix, evidence))

    if now < leaf.not_valid_before_utc:
        add("CERT_NOT_YET_VALID", "high", "Certificate validity has not started.",
            "Issue a certificate with a correct validity window and check clock synchronization.")
    if now >= leaf.not_valid_after_utc:
        add("CERT_EXPIRED", "critical", "The certificate is expired.",
            "Renew and deploy the certificate before its expiration.")
    elif expiry_days <= spec.policy["expiry_warning_days"]:
        add("CERT_EXPIRING", "medium", f"Certificate expires in {expiry_days:.1f} days.",
            "Schedule certificate renewal and verify deployment.", days_remaining=round(expiry_days, 2))
    if lifetime_days > spec.policy["max_validity_days"]:
        add("CERT_LIFETIME", "medium", "Certificate validity exceeds policy maximum.",
            "Reissue with the configured maximum lifetime.", lifetime_days=round(lifetime_days, 2))
    if kind == "RSA" and bits < spec.policy["min_rsa_bits"]:
        add("WEAK_RSA_KEY", "high", f"RSA public key has only {bits} bits.",
            "Reissue using an RSA key satisfying the policy, or an approved EC/EdDSA key.", bits=bits)
    if kind.startswith("EC-") and bits < spec.policy["min_ec_bits"]:
        add("WEAK_EC_KEY", "high", f"EC public key has only {bits} bits.",
            "Reissue using an approved elliptic curve.", bits=bits)
    if kind in ("DSA", "unknown"):
        add("UNSUPPORTED_KEY_TYPE", "high", f"Key algorithm {kind} is not approved for TLS.",
            "Replace with an approved RSA, ECDSA or EdDSA certificate.")
    if record["signature_hash"] == "unknown":
        add("UNKNOWN_SIGNATURE_HASH", "high", "Certificate signature hash is unsupported.",
            "Reissue using a well-supported and approved signature algorithm.")
    if record["signature_hash"].lower() in ("sha1", "md5"):
        add("WEAK_SIGNATURE_HASH", "high", "Certificate signature uses a legacy hash algorithm.",
            "Replace with a certificate signed using a modern approved algorithm.")
    if not record["dns_names"]:
        add("NO_SAN", "high", "Certificate has no DNS/IP Subject Alternative Names.",
            "Reissue with a SAN matching the intended hostname.")
    try:
        basic = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        if basic.ca:
            add("CA_AS_TLS_LEAF", "high", "Certificate is marked as a CA, not a TLS leaf.",
                "Use a separate end-entity certificate with CA=false.")
    except x509.ExtensionNotFound:
        pass
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku and x509.ObjectIdentifier("2.5.29.37.0") not in eku:
            add("MISSING_SERVER_AUTH_EKU", "high", "EKU excludes TLS server authentication.",
                "Issue a certificate authorized for TLS server authentication.")
    except x509.ExtensionNotFound:
        pass
    if "allowed_dns_suffixes" in spec.policy:
        for san in record["dns_names"]:
            if not _matches_allowed(san, spec.policy["allowed_dns_suffixes"]):
                add("DNS_OUTSIDE_POLICY", "high", "SAN is outside the allowed DNS/IP names.",
                    "Remove unauthorized SANs or explicitly approve the intended DNS scope.", name=san)
    if "allowed_issuer_names" in spec.policy:
        if record["issuer"] not in spec.policy["allowed_issuer_names"]:
            add("UNAPPROVED_ISSUER", "high", "Issuer is not listed in the local policy.",
                "Use an approved issuer or update the issuer policy through change control.")

    if not roots:
        if spec.policy["require_trust"]:
            add("TRUST_NOT_CONFIGURED", "high", "No explicit trusted root bundle was supplied.",
                "Provide trust_roots and hostname for verifiable PKIX path validation.")
    else:
        try:
            host = spec.hostname or ""
            try:
                subject = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError:
                subject = x509.DNSName(host)
            verifier = PolicyBuilder().store(Store(roots)).time(now).build_server_verifier(subject)
            verifier.verify(leaf, intermediates)
            record["trust"] = "verified"
        except (VerificationError, ValueError) as exc:
            record["trust"] = "invalid"
            add("PKIX_VERIFICATION_FAILED", "critical", "X.509 path/hostname validation failed.",
                "Check the configured trust root, intermediate chain, SAN, validity and CA constraints.",
                reason=str(exc)[:500])

    return record, findings


def scan(path: str | Path, now: datetime | None = None) -> Report:
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    report = Report(operation="scan", metadata={"manifest": str(Path(path).name),
                                               "evaluation_time": timestamp.isoformat()})
    for service in load_manifest(path):
        record, findings = inspect_service(service, timestamp)
        report.services.append(record)
        report.findings.extend(findings)
    report.sort()
    return report
