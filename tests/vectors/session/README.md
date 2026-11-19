# Reader session vectors

These project-owned fixtures are distributed under the repository's
BSD-2-Clause license. All private keys are public test material.

Run `python tests/vectors/session/generate.py` to reproduce both tables.
Generation uses Python `cryptography 50.0.0`, Python `hashlib`/`hmac`, and
OpenSSL CLI 3.5.7. The generator does not invoke nazo-mdoc or a Rust encoder.
Its small CBOR and DER framing helpers produce test inputs only.

`vectors.tsv` contains 37 P-256 session inputs and expected messages. The
independent generator covers ECDH, the Tag 24 transcript salt, three HKDF
contexts, AES-256-GCM directions/counters, issuer ECDSA signatures, and detached
DeviceMAC and DeviceSignature. Negative messages have valid session encryption
so they exercise the holder, issuer, disclosure, validity, and authorization
boundaries after decryption. The Document Signer certificate/private key comes
from the existing `tests/common/mod.rs` fixture. Device-signature and DeviceMAC
fixtures use different static device keys.

`agreement.tsv` contains nine full sessions, one for every ECDH curve in ISO/IEC
18013-5:2021 Table 22: P-256/P-384/P-521, X25519/X448, and Brainpool
P256r1/P320r1/P384r1/P512r1. OpenSSL CLI performs both ephemeral and static ECDH;
Python produces HKDF/MAC and AES-GCM expectations. Brainpool P320r1 key
generation starts from a named-curve RFC 5915 private-key structure because
Python's `cryptography` API does not expose that curve. No curve arithmetic is
implemented by the generator. EC2 device engagement and static device keys use
compressed COSE points; reader keys use uncompressed points.

`session_reader.rs` uses RustCrypto P-256 for the external private-key operation
and checks the independent encrypted messages. `session_agreement_curves.rs`
uses an OpenSSL-backed external key provider and verifies both the exact first
encrypted request and the issuer-authenticated DeviceMAC response for all nine
curves. The issuer certificate/signature in this table uses P-256; signature
algorithm coverage is recorded separately in `reader_crypto`.

These are reproducible protocol/crypto integration vectors. Device hardware,
NFC/BLE execution, and the official ISO/IEC TS 18013-6 test methods retain their
separate evidence requirements.
