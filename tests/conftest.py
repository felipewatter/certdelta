from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@pytest.fixture
def pki_factory():
    def make(folder: Path, *, hostname="api.example.test", alt_names=None,
             expiry_days=60, is_ca=False, key_size=2048, eku=True, issuer_name="CertDelta Test CA",
             trust=True, policy=None, valid_from_days=-1):
        folder.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
        root = (x509.CertificateBuilder().subject_name(root_dn).issuer_name(root_dn)
                .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=365))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                   key_cert_sign=True, crl_sign=True, content_commitment=False, data_encipherment=False,
                   key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(root_key, hashes.SHA256()))
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        names = alt_names if alt_names is not None else [hostname]
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
                   .issuer_name(root_dn).public_key(leaf_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now + timedelta(days=valid_from_days))
                   .not_valid_after(now + timedelta(days=expiry_days))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(x) for x in names]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                       key_cert_sign=is_ca, crl_sign=is_ca, content_commitment=False,
                       data_encipherment=False, key_agreement=False, encipher_only=False,
                       decipher_only=False), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if eku else
                                                         ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
        cert = builder.sign(root_key, hashes.SHA256())
        (folder / "leaf.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (folder / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
        manifest = {"version": 1, "policy": policy or {},
                    "services": [{"id": "api", "leaf": "leaf.pem",
                                  "hostname": hostname, "trust_roots": "root.pem" if trust else None}]}
        (folder / "manifest.yml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
        return folder / "manifest.yml", cert, root
    return make
