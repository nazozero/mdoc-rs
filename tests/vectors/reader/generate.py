#!/usr/bin/env python3
"""Generate project-owned ReaderAuth bytes independently with cryptography/OpenSSL.

Run with Python cryptography >=45. All private scalars are public test fixtures.
The fixture and this generator use the repository's BSD-2-Clause license.
"""
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID, ObjectIdentifier


def head(major, count):
    if count < 24:
        return bytes([(major << 5) | count])
    width = next(width for width in (1, 2, 4, 8) if count < 1 << (8 * width))
    return bytes([(major << 5) | {1: 24, 2: 25, 4: 26, 8: 27}[width]]) + count.to_bytes(width, "big")


def cbor(value):
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, str):
        encoded = value.encode()
        return head(3, len(encoded)) + encoded
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(key) + cbor(item) for key, item in value.items())
    raise TypeError(type(value))


def embedded(encoded):
    return b"\xd8\x18" + cbor(encoded)


def public_key(scalar):
    public = ec.derive_private_key(scalar, ec.SECP256R1()).public_key().public_numbers()
    return cbor({1: 2, -1: 1, -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")})


key = ec.derive_private_key(17, ec.SECP256R1())
ca = ec.derive_private_key(18, ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ReaderAuth test reader")])
issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ReaderAuth test CA")])
certificate = (
    x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
    .public_key(key.public_key()).serial_number(1)
    .not_valid_before(datetime(2026, 11, 19, tzinfo=timezone.utc))
    .not_valid_after(datetime(2027, 11, 19, tzinfo=timezone.utc))
    .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("1.0.18013.5.1.6")]), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
    .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier("https://reader.example/crl")],
        relative_name=None, reasons=None, crl_issuer=None)]), critical=False)
    .sign(ca, hashes.SHA256(), ecdsa_deterministic=True)
    .public_bytes(serialization.Encoding.DER)
)
items = embedded(cbor({
    "requestInfo": {"application.example": [1, True]},
    "nameSpaces": {"org.iso.18013.5.1": {"family_name": False, "age_over_18": True}},
    "docType": "org.iso.18013.5.1.mDL",
}))
device = embedded(public_key(19))
engagement = head(5, 3) + cbor(0) + cbor("1.0") + cbor(1) + b"\x82\x01" + device + cbor(2) + cbor([[2, 1, {0: False, 1: True}]])
transcript = b"\x83" + embedded(engagement) + embedded(public_key(20)) + b"\xf6"
payload = embedded(b"\x83" + cbor("ReaderAuthentication") + transcript + items)
protected = cbor({1: -7})
signing_input = cbor(["Signature1", protected, b"", payload])
signature_der = key.sign(signing_input, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
r, s = utils.decode_dss_signature(signature_der)
signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
key.public_key().verify(signature_der, signing_input, ec.ECDSA(hashes.SHA256()))
output = {"items": items, "transcript": transcript, "certificate": certificate,
          "signing_input": signing_input, "signature": signature}
Path(__file__).with_name("reader_authentication.tsv").write_text(
    "".join(name + "\t" + value.hex() + "\n" for name, value in output.items())
)
