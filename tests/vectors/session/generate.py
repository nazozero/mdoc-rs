"""Independent ISO 2021 reader-session vectors (project BSD-2-Clause).

Python cryptography performs ECDH/ECDSA/AES-GCM; hashlib/hmac perform HKDF/MAC.
No nazo-mdoc encoder, parser or crypto implementation is invoked. All private
scalars in this file are public test material. Run from any working directory.
"""
from pathlib import Path
import copy
import hashlib
import hmac
import re
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Tag:
    def __init__(self, number, value):
        self.number, self.value = number, value


def head(major, size):
    if size < 24:
        return bytes([major * 32 + size])
    for width, marker in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if size < 1 << (width * 8):
            return bytes([major * 32 + marker]) + size.to_bytes(width, "big")
    raise ValueError(size)


def cbor(value):
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(cbor, value))
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    if isinstance(value, Tag):
        return head(6, value.number) + cbor(value.value)
    raise TypeError(value)


def public(key, compressed=False):
    numbers = key.public_key().public_numbers()
    width = (key.curve.key_size + 7) // 8
    return {1: 2, -1: {256: 1, 384: 2, 521: 3}[key.curve.key_size],
            -2: numbers.x.to_bytes(width, "big"),
            -3: bool(numbers.y & 1) if compressed else numbers.y.to_bytes(width, "big")}


def hkdf(secret, salt, info):
    prk = hmac.digest(salt, secret, "sha256")
    return hmac.digest(prk, info + b"\x01", "sha256")


def sign(key, encoded):
    der = key.sign(encoded, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


out = Path(__file__).parent
common = (out.parent.parent / "common/mod.rs").read_text()
cert = bytes.fromhex(re.search(r'GENUINE_CERT_HEX: &str = "([0-9a-f]+)"', common).group(1))
issuer_scalar = int(re.search(r'GENUINE_PRIV_HEX: &str =\s*"([0-9a-f]+)"', common).group(1), 16)
issuer = ec.derive_private_key(issuer_scalar, ec.SECP256R1())
device_ephemeral = ec.derive_private_key(17, ec.SECP256R1())
reader = ec.derive_private_key(19, ec.SECP256R1())
device_static = ec.derive_private_key(23, ec.SECP256R1())
device_signer = ec.derive_private_key(29, ec.SECP256R1())

engagement = {0: "1.0", 1: [1, Tag(24, cbor(public(device_ephemeral)))],
              2: [[2, 1, {0: True, 1: False, 10: bytes(range(16))}]]}
transcript = [Tag(24, cbor(engagement)), Tag(24, cbor(public(reader))), None]
salt = hashlib.sha256(cbor(Tag(24, cbor(transcript)))).digest()
shared = reader.exchange(ec.ECDH(), device_ephemeral.public_key())
sk_reader = hkdf(shared, salt, b"SKReader")
sk_device = hkdf(shared, salt, b"SKDevice")
mac_secret = reader.exchange(ec.ECDH(), device_static.public_key())
emac = hkdf(mac_secret, salt, b"EMacKey")

items_request = Tag(24, cbor({"docType": "example.session", "nameSpaces": {"example": {"name": False}}}))
request = cbor({"version": "1.0", "docRequests": [{"itemsRequest": items_request}]})
item = Tag(24, cbor({"digestID": 0, "random": bytes(range(16)), "elementIdentifier": "name", "elementValue": "Ada"}))
mso = {"version": "1.0", "digestAlgorithm": "SHA-256",
       "valueDigests": {"example": {0: hashlib.sha256(cbor(item)).digest()}},
       "deviceKeyInfo": {"deviceKey": public(device_static)}, "docType": "example.session",
       "validityInfo": {"signed": Tag(0, "2026-11-17T12:00:00Z"),
                        "validFrom": Tag(0, "2026-11-17T12:00:00Z"),
                        "validUntil": Tag(0, "2026-12-17T12:00:00Z")}}


def document(mso_value=None, *, mechanism="mac", namespaces=None, mac_key=emac,
             mac_protected=None, attached=False, transcript_value=None):
    value = copy.deepcopy(mso if mso_value is None else mso_value)
    if mechanism == "signature":
        value["deviceKeyInfo"]["deviceKey"] = public(device_signer)
    mso_bytes = cbor(Tag(24, cbor(value)))
    issuer_protected = cbor({1: -7})
    issuer_auth = [issuer_protected, {33: cert}, mso_bytes,
                   sign(issuer, cbor(["Signature1", issuer_protected, b"", mso_bytes]))]
    namespace_bytes = Tag(24, cbor({} if namespaces is None else namespaces))
    payload = cbor(Tag(24, cbor(["DeviceAuthentication", transcript if transcript_value is None else transcript_value,
                               "example.session", namespace_bytes])))
    if mechanism == "mac":
        protected = cbor({1: 5} if mac_protected is None else mac_protected)
        tag = hmac.digest(mac_key, cbor(["MAC0", protected, b"", payload]), "sha256")
        auth = {"deviceMac": [protected, {}, payload if attached else None, tag]}
    else:
        protected = cbor({1: -7})
        signature = sign(device_signer, cbor(["Signature1", protected, b"", payload]))
        auth = {"deviceSignature": [protected, {}, None, signature]}
    return {"docType": "example.session", "issuerSigned": {"nameSpaces": {"example": [item]}, "issuerAuth": issuer_auth},
            "deviceSigned": {"nameSpaces": namespace_bytes, "deviceAuth": auth}}


def response(doc):
    return {"version": "1.0", "documents": [doc], "status": 0}


def encrypted(value, count=1, status=None, *, key=sk_device, device_direction=True):
    nonce = (int(device_direction)).to_bytes(8, "big") + count.to_bytes(4, "big")
    result = {"data": AESGCM(key).encrypt(nonce, cbor(value), b"")}
    if status is not None:
        result["status"] = status
    return cbor(result)


valid = response(document())
vectors = {
    "reader_public": cbor(public(reader)),
    "engagement": cbor(engagement),
    "transcript": cbor(transcript),
    "items_request": cbor(items_request),
    "request": request,
    "zab": shared,
    "sk_reader": sk_reader,
    "sk_device": sk_device,
    "emac": emac,
    "response_plaintext": cbor(valid),
    "response_mac": encrypted(valid),
    "response_second": encrypted(valid, count=2),
    "response_termination": encrypted(valid, status=20),
    "response_signature": encrypted(response(document(mechanism="signature"))),
    "response_wrong_direction": encrypted(valid, device_direction=False),
    "response_wrong_key": encrypted(valid, key=sk_reader),
    "response_bare_transcript_salt": encrypted(response(document(mac_key=hkdf(mac_secret, hashlib.sha256(cbor(transcript)).digest(), b"EMacKey")))),
    "response_wrong_derivation_info": encrypted(response(document(mac_key=hkdf(mac_secret, salt, b"SKDevice")))),
    "response_attached_mac": encrypted(response(document(attached=True))),
    "response_mac_missing_alg": encrypted(response(document(mac_protected={}))),
    "response_mac_wrong_alg": encrypted(response(document(mac_protected={1: -7}))),
}
for count in [1, 2]:
    value = {"data": AESGCM(sk_reader).encrypt(bytes(8) + count.to_bytes(4, "big"), request, b"")}
    if count == 1:
        value = {"eReaderKey": Tag(24, cbor(public(reader))), **value}
    vectors[f"request_{count}"] = cbor(value)

for name, mutation in [
    ("bad_digest", lambda m: m["valueDigests"]["example"].update({0: bytes(32)})),
    ("expired", lambda m: m["validityInfo"].update({"validUntil": Tag(0, "2026-11-17T12:00:00Z")})),
    ("wrong_mso_doc_type", lambda m: m.update({"docType": "example.other"})),
    ("wrong_curve", lambda m: m["deviceKeyInfo"].update({"deviceKey": public(ec.derive_private_key(23, ec.SECP384R1()))})),
]:
    changed = copy.deepcopy(mso)
    mutation(changed)
    vectors[f"response_{name}"] = encrypted(response(document(changed)))

authorized = copy.deepcopy(mso)
authorized["deviceKeyInfo"]["keyAuthorizations"] = {"dataElements": {"example": ["session_value"]}}
device_namespaces = {"example": {"session_value": "checked"}}
vectors["response_authorized_namespace"] = encrypted(response(document(authorized, namespaces=device_namespaces)))
vectors["response_unauthorized_namespace"] = encrypted(response(document(namespaces=device_namespaces)))

for name, update in [
    ("bad_mac", lambda mac: mac.__setitem__(3, bytes(32))),
    ("short_mac", lambda mac: mac.__setitem__(3, mac[3][:-1])),
    ("long_mac", lambda mac: mac.__setitem__(3, mac[3] + b"\0")),
    ("unprotected_alg", lambda mac: mac[1].update({1: 5})),
    ("changed_protected", lambda mac: mac.__setitem__(0, cbor({1: 5, 4: b"kid"}))),
]:
    changed = copy.deepcopy(valid)
    update(changed["documents"][0]["deviceSigned"]["deviceAuth"]["deviceMac"])
    vectors[f"response_{name}"] = encrypted(changed)

changed = copy.deepcopy(valid)
changed["documents"][0]["issuerSigned"]["issuerAuth"][3] = bytes(64)
vectors["response_bad_issuer"] = encrypted(changed)
mixed = copy.deepcopy(valid)
mixed["documentErrors"] = [{"example.denied": 0}]
vectors["response_mixed_errors"] = encrypted(mixed)
vectors["response_protocol_error"] = encrypted({"version": "1.0", "status": 11})

for name, value in vectors.items():
    assert isinstance(value, bytes), name
(out / "vectors.tsv").write_text("# name\thex; independent Python cryptography 50.0.0 vectors\n" +
    "".join(name + "\t" + value.hex() + "\n" for name, value in vectors.items()))
print(f"wrote {len(vectors)} vectors")


def der_tlv(tag, value):
    length = bytes([len(value)]) if len(value) < 128 else b"\x81" + bytes([len(value)])
    return bytes([tag]) + length + value


def agreement_key(curve_id, curve, scalar, compressed=False):
    if curve_id == 257:
        # RFC 5915 ECPrivateKey using the named RFC 5639 Brainpool P320 curve.
        # OpenSSL computes the public point; no curve arithmetic lives here.
        der = der_tlv(0x30, der_tlv(2, b"\x01") + der_tlv(4, scalar.to_bytes(40, "big"))
                      + der_tlv(0xa0, bytes.fromhex("06092b2403030208010109")))
        spki = subprocess.check_output(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=der)
        point = spki[-81:]
        assert point[0] == 4
        return der, spki, {1: 2, -1: curve_id, -2: point[1:41],
                           -3: bool(point[-1] & 1) if compressed else point[41:]}
    if curve_id in (4, 5):
        width = 32 if curve_id == 4 else 56
        key = curve.from_private_bytes(bytes([scalar]) * width)
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        cose = {1: 1, -1: curve_id, -2: raw}
    else:
        key = ec.derive_private_key(scalar, curve())
        numbers = key.public_key().public_numbers()
        width = (key.curve.key_size + 7) // 8
        cose = {1: 2, -1: curve_id, -2: numbers.x.to_bytes(width, "big"),
                -3: bool(numbers.y & 1) if compressed else numbers.y.to_bytes(width, "big")}
    return (key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), cose)


def openssl_agreement(private_der, peer_spki):
    with tempfile.TemporaryDirectory() as directory:
        private = Path(directory) / "private.der"
        peer = Path(directory) / "peer.der"
        private.write_bytes(private_der)
        peer.write_bytes(peer_spki)
        return subprocess.check_output(["openssl", "pkeyutl", "-derive", "-inkey", str(private),
                                        "-keyform", "DER", "-peerkey", str(peer), "-peerform", "DER"])


agreement_rows = []
for curve_id, curve in [(1, ec.SECP256R1), (2, ec.SECP384R1), (3, ec.SECP521R1),
                        (4, x25519.X25519PrivateKey), (5, x448.X448PrivateKey),
                        (256, ec.BrainpoolP256R1), (257, None),
                        (258, ec.BrainpoolP384R1), (259, ec.BrainpoolP512R1)]:
    _, device_spki, device_cose = agreement_key(curve_id, curve, 17, compressed=True)
    reader_der, _, reader_cose = agreement_key(curve_id, curve, 19)
    _, static_spki, static_cose = agreement_key(curve_id, curve, 23, compressed=True)
    curve_engagement = {0: "1.0", 1: [1, Tag(24, cbor(device_cose))], 2: engagement[2]}
    curve_transcript = [Tag(24, cbor(curve_engagement)), Tag(24, cbor(reader_cose)), None]
    curve_salt = hashlib.sha256(cbor(Tag(24, cbor(curve_transcript)))).digest()
    curve_shared = openssl_agreement(reader_der, device_spki)
    curve_reader_key = hkdf(curve_shared, curve_salt, b"SKReader")
    curve_device_key = hkdf(curve_shared, curve_salt, b"SKDevice")
    curve_emac = hkdf(openssl_agreement(reader_der, static_spki), curve_salt, b"EMacKey")
    curve_mso = copy.deepcopy(mso)
    curve_mso["deviceKeyInfo"]["deviceKey"] = static_cose
    curve_response = response(document(curve_mso, mac_key=curve_emac, transcript_value=curve_transcript))
    curve_request = cbor({"eReaderKey": Tag(24, cbor(reader_cose)),
                          "data": AESGCM(curve_reader_key).encrypt(bytes(11) + b"\x01", request, b"")})
    row = [str(curve_id), reader_der.hex(), cbor(reader_cose).hex(), cbor(curve_engagement).hex(),
           cbor(curve_transcript).hex(), curve_request.hex(), encrypted(curve_response, key=curve_device_key).hex()]
    agreement_rows.append("\t".join(row))
(out / "agreement.tsv").write_text("# curve\treader_private_der\treader_public\tengagement\ttranscript\trequest\tresponse\n" +
                                   "\n".join(agreement_rows) + "\n")
print(f"wrote {len(agreement_rows)} full-session agreement vectors")
