"""Generate synthetic demo PKI: no private keys are ever persisted."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def make_demo(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CertDelta Synthetic Demo CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=True, crl_sign=True,
                        encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    for label, names in (
        ("before", ["api.example.test"]),
        ("after", ["api.example.test", "admin.example.test"]),
    ):
        target = out / label
        target.mkdir(parents=True, exist_ok=True)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.example.test")]))
            .issuer_name(name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                            key_encipherment=True, data_encipherment=False,
                            key_agreement=False, key_cert_sign=False, crl_sign=False,
                            encipher_only=False, decipher_only=False), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        (target / "root.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (target / "leaf.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        manifest = {
            "version": 1,
            "policy": {"require_trust": True, "allowed_dns_suffixes": [".example.test"]},
            "services": [{"id": "api", "leaf": "leaf.pem", "trust_roots": "root.pem",
                          "hostname": "api.example.test"}],
        }
        (target / "manifest.yml").write_text(
            yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8",
        )
    print(f"Synthetic before/after demo written to {out.resolve()}")
    print("The private signing keys were kept in memory and not written to disk.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, default=Path("demo-local"))
    make_demo(ap.parse_args().output)
