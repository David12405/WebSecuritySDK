"""Shared fixtures.

House rule: the test suite runs with no network and no model. Anything that
needs either belongs in `examples/`, not here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID


def _certificate(*, days_until_expiry: int) -> bytes:
    """A self-signed certificate, in DER.

    Generated rather than checked in: a fixture file would itself expire,
    and a test suite that starts failing on a calendar date is worse than
    no test at all.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "myapp.com")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=days_until_expiry))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("myapp.com"), x509.DNSName("www.myapp.com")]),
            critical=False,
        )
        .sign(key, None)
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="session")
def self_signed_cert() -> bytes:
    """Valid, with 29 full days left - inside the "expires soon" range a check cares about."""
    return _certificate(days_until_expiry=30)


@pytest.fixture(scope="session")
def expired_cert() -> bytes:
    return _certificate(days_until_expiry=-5)
