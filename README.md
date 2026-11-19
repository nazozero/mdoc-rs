# nazo-mdoc

A Rust library for issuing, parsing and authenticating ISO mdoc credentials.
It provides CBOR/COSE processing, selective disclosure, external signing and
OpenID4VP 1.0 Final session binding. Optional reader features add ISO device
retrieval sessions and portable cipher-suite-1 signature curves.

The package is `nazo-mdoc`; the Rust crate is `nazo_mdoc`. Rust 1.100 or later
is required. For a Git dependency, pin the full commit revision you have tested.

## Presentation verification

```rust,ignore
use nazo_mdoc::{verify_presentation_borrowed, VerificationOptions};
use nazo_mdoc::session::{RedirectHandover, SessionTranscript};

let transcript = SessionTranscript::validate_redirect(raw_transcript, RedirectHandover {
    client_id: full_client_id,
    nonce: request_nonce,
    jwk_thumbprint: response_encryption_key_thumbprint,
    response_uri,
})?;
let documents = verify_presentation_borrowed(response, &transcript, &VerificationOptions {
    now: verification_time,
    max_documents: 1,
})?;
for document in documents {
    application.check_trust_and_policy(document).await?;
}
```

`verify_presentation_borrowed` authenticates issuer and holder signatures, disclosure
digests, document type, device-key authorizations and MSO validity. It returns
`PendingTrustDocumentRef`, whose document, MSO and certificate bytes borrow the
response buffer. Keep that buffer alive while using the evidence. The application completes:

- X.509 path validation against its trusted issuers and certificate revocation.
- Path-dependent ISO certificate bindings using `certificate` helpers when
  `certificate-profile` is enabled; otherwise all certificate profile checks
  remain pending with the caller.
- Credential status checks using the authenticated MSO `status` extension.
- Request freshness, nonce consumption, requested claims and authorization.

`SessionTranscript::redirect` and `dc_api` construct Final handovers. Their
`validate_*` counterparts bind received bytes to the supplied request context
and borrow the validated buffer. `from_cbor` provides structural validation for
other transcript profiles; request binding remains the caller's responsibility.

The generic parser allows up to 16 documents. `VerificationOptions` sets the
presentation limit; HAIP callers use 1. A verification error rejects the whole
response.

## Borrowed data

`parse_borrowed` and `parser::parse_issued_borrowed` retain text, byte strings,
claims, signed envelopes and COSE fields as views of the input. `CborValueRef`
reads scalar values and traverses arrays, maps and tags without constructing an
owned value tree. `MsoRef` borrows digests, device-key parameters and status data.

`verify_presentation_borrowed` and `verify_issued_borrowed` preserve these views
through authentication. Their `into_parts` methods move the metadata indexes;
`into_owned` creates independent storage when the input buffer must be released.
The existing `parse`, `verify_presentation` and `verify_issued` APIs perform this
owned conversion after the same parsing or verification path.

With `issue`, the borrowed encoders write directly from those views into the
output buffer. Holder signing can use
`response_builder::prepare_device_authentication_borrowed`: select the issuer
items in a borrowed document, prepare the signing input, and pass the external
signature to `finish` to obtain a DeviceResponse. Issuer attributes and certificate
bytes remain borrowed until they are written into that response.

ECDSA and HMAC verification consume message fragments directly. Strict Ed25519
verification uses a contiguous message, and X.509 decoding uses the upstream
certificate model. Namespace and digest indexes store references in collections.
New wire output and external signing inputs have their own buffers. Brainpool
verification hashes borrowed fragments; Ed448 assembles a contiguous message
only when multiple fragments are supplied.

## Issuance

Enable the `issue` feature. Signing uses the application's local key, remote
signer or HSM through a prepare/sign/finish sequence:

```rust,ignore
use nazo_mdoc::{builder::DocumentBuilder, model::CoseAlgorithm};

let prepared = DocumentBuilder::new(doc_type)
    .add_namespace(namespace, attributes)
    .device_key(device_public_key)
    .validity(validity)
    .prepare(CoseAlgorithm::ES256, document_signer_chain)?;
let signature = signer.sign(prepared.signing_input()).await?;
let document = prepared.finish(signature)?;
let issuer_signed = document.to_issuer_signed_cbor()?;
```

`prepare` validates the inputs and produces immutable COSE signing bytes.
`finish` verifies the returned signature against the leaf certificate key.
The result encodes the `IssuerSigned` object used by OpenID4VCI 1.0 Final A.2.4.
`response_builder` provides the same workflow for holder signatures.

Attributes are explicit CBOR values. Applications choose date tags and other
schema types for their namespaces. The `mdl` module enforces the encodings of
supplied ISO mDL fields, issue-date bounds and issuer-only Table 5 claims.
Partial disclosure does not require every mandatory licence field. It does not
decode portrait/biometric payload formats or validate domestic schemas.
Status references are supplied by the issuer;
the application manages their allocation and publication.

## ISO certificate profiles

Enable `certificate-profile` to enforce ISO/IEC 18013-5:2021 Annex B Document
Signer constraints automatically in issuance and both verification APIs.
`PendingTrustDocumentRef::leaf_certificate()` and its issuer-only counterpart
expose the borrowed parsed leaf for the application's existing X.509 engine.

`certificate::check_iaca_profile`, `check_issuer_binding` and
`check_iaca_link_profile(link, old_root, new_root)` check the corresponding
profile fields. The caller supplies the actual authenticated path and both
rollover root certificates; a link alone cannot prove the old root's expiry.
Check each root's profile and self-signature separately. After path selection,
`check_x5chain_root_exclusion` rejects a transmitted trust root as Annex B.1.1
requires. These functions do not select trust anchors, verify certificate
signatures, fetch CRLs or construct certification paths.

The profile feature retains strict `x509-cert` DER decoding and adds borrowed
`x509-parser` extension views. The latter accepts some non-DER inputs and cannot
replace the strict decoder safely. This retained parse cost preserves the
existing input boundary. No X.509 path engine or application dependency is added.

## Device-retrieval reader

`reader::ItemsRequest` checks and borrows the original Tag 24 request. Use
`unsigned()` for a request without reader authentication, or
`prepare_reader_authentication` / `finish` with an external signer. Reader
certificate identity, path and retention policy belong to the application.
The returned signature is checked against the supplied certificate public key.

Enable `reader-session` for ISO/IEC 18013-5:2021 cipher-suite-1 sessions:

```rust,ignore
use nazo_mdoc::reader::{ItemsRequest, encode_device_request};
use nazo_mdoc::session::reader::{Handover, ReaderResponse, ReaderSession};

let mut reader = ReaderSession::new(
    received_device_engagement,
    Handover::Qr,
    fresh_reader_ephemeral_key, // Implements ReaderKeyAgreement; private key stays in the adapter.
)?;
let items = ItemsRequest::from_bytes(items_request_bytes)?;
let request = encode_device_request(&[items.unsigned()])?;
let outgoing = reader.encrypt_request(&request)?;
transport.send(&outgoing).await?;
let mut incoming = transport.receive().await?;
match reader.receive_response(&mut incoming, &verification_options)? {
    ReaderResponse::Authenticated { documents, .. } => {
        for document in documents {
            application.check_trust_and_policy(document).await?;
        }
    }
    ReaderResponse::Protocol { response, .. } => application.handle_protocol_response(response)?,
    ReaderResponse::Status(status) => application.handle_session_status(status)?,
}
```

The executable consumer flows in [session_reader.rs](tests/session_reader.rs)
and [session_agreement_curves.rs](tests/session_agreement_curves.rs) supply
private-key adapters and independent full-session inputs. Their fixed private
keys are public test material; deployed adapters generate fresh keys.

`ReaderKeyAgreement` owns one fresh ephemeral private key and performs ECDH with
the validated peer selected by the core. The session binds the original
engagement, reader key and QR/NFC handover; derives separate encryption/MAC keys;
and owns the two message counters. Encryption writes its wire output directly;
decryption is in place and verified claims borrow the received buffer.

DeviceSignature and DeviceMAC share issuer, MSO, disclosure, authorization and
pending-trust checks. Verification never falls back after a failed proof.
Protocol errors return an untrusted `ResponseEnvelope`; mixed or error-bearing
responses do not yield partial authenticated documents. Each session needs
exclusive mutable access; independent sessions have no shared counters or lock.

Adapters implement NFC/BLE/QR acquisition, retrieval options, channel closure,
timeouts and destruction of the ephemeral private key. Call `close()` on a
transport failure or timeout. Use `terminate()` to close locally and send the
session-termination status. The adapter sends termination/error statuses and
closes its channel; a received terminal status closes the channel after any
authenticated data is processed. A closed session cannot restart. The session
also enforces the two-age-attestation limit across its requests; the application
enforces each element's retention intent.

The existing `verify_presentation*` entry points remain DeviceSignature-only.
Enabling a library feature does not provision a reader transport or opt an
application into MAC authentication.

## Protocol support

| Area | Support |
| --- | --- |
| Issuer and holder signatures | ES256/P-256, ES384/P-384, ES512/P-521 and EdDSA/Ed25519; fixed-width COSE ECDSA signatures and strict Ed25519 verification |
| Portable reader signatures (`reader-crypto`) | Brainpool P256/P384 and Ed448 via pure Rust, including WASM |
| Reader algorithm gaps | Brainpool P320/P512 are rejected until a suitable reviewed implementation is available |
| MSO digests | SHA-256, SHA-384 and SHA-512 with matching digest lengths |
| Versions | Emit `1.0`; receive numeric minor versions of major version 1 |
| Session binding | OpenID4VP 1.0 Final Redirect and DC API handovers; original QR/NFC device-retrieval handovers with `reader-session` |
| Device authentication | DeviceSignature in the presentation verifier; session-bound DeviceSignature/DeviceMAC with `reader-session`; separate low-level DeviceMAC/HKDF primitives |
| Reader protocol | Borrowed ItemsRequest, external reader authentication, DeviceRequest encoding and untrusted response/error inspection |
| Session encryption (`reader-session`) | External ECDH, HKDF-SHA-256, AES-256-GCM, ordered directional counters and termination |
| Authenticated bytes | Preserve received Tag 24 envelopes, protected headers and payloads |
| CBOR input | Definite lengths, shortest integer/length encodings, unique integer/text/byte-string map keys, valid UTF-8 and preserved tags; false, true, null and IEEE floats |
| CBOR limits | 1 MiB per envelope, depth 32, 65,536 items and 4,096 entries per collection; configurable through `parse_with_limits` |
| Time | Explicit `Timestamp`, UTC whole-second MSO encoding and preserved leap-second ordering |
| mDL data | Supplied Table 5 field types, date tags, driving privileges, age/biometric field families, issuer-only placement and country/jurisdiction bindings |
| Certificate profiles (`certificate-profile`) | 2021 Annex B DS, IACA and rollover-link fields; authenticated path/root evidence supplied by the caller |

Unsupported MSO and DeviceKeyInfo security fields are rejected during verification. Positive RFU
`keyInfo` labels are preserved and ignored as required by ISO. The complete
authenticated `status` value is retained for application policy.

The [protocol matrix](docs/protocol-matrix.md) maps requirements to code and
tests. The [edition-specific reader inventory](docs/iso-reader-conformance.md)
records each role, native/WASM limits and remaining adapter, interoperability
and official-test evidence for [issue #3](https://github.com/nazozero/nazo-mdoc/issues/3).
Ed448 public-point decoding checks subgroup membership and rejects identity,
so standalone device-key validation and complete signature verification are supported.

## Features

| Feature | Effect |
| --- | --- |
| Default | Parsing and verification; empty feature set |
| `issue` | Credential and response builders, encoding, OS entropy for salts |
| `debug` | CBOR diagnostic formatting |
| `wasm-js` | JavaScript entropy integration for issuance on `wasm32-unknown-unknown` |
| `certificate-profile` | Automatic ISO DS profile enforcement, borrowed leaf access and IACA/rollover evidence helpers; optional `x509-parser` and `sha1` |
| `reader-session` | ISO device-retrieval reader state, external ECDH, AES-GCM and secret-buffer cleanup; no transport or private-key implementation |
| `reader-crypto` | Portable Brainpool P256/P384 and Ed448 signature and point validation on native/WASM |
| `aws-lc` | Use AWS-LC 1.19 native AES-GCM for reader sessions; WASM retains RustCrypto |

Verification accepts an explicit time and runs without a network client or
platform clock. See [architecture](docs/architecture.md) for the data flow and
[migration](docs/migration.md) for the 0.4 changes and migration from `mdoc-rs 0.2.0`.

## Development

```sh
cargo fmt --check
cargo test --locked --no-default-features
cargo test --locked --no-default-features --features issue
cargo test --locked --no-default-features --features reader-session
cargo test --locked --no-default-features --features reader-session,reader-crypto
cargo test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo audit --deny warnings
cargo build --locked --target wasm32-unknown-unknown --no-default-features
cargo build --locked --target wasm32-unknown-unknown --no-default-features --features issue,wasm-js,certificate-profile
cargo build --locked --target wasm32-wasip2 --no-default-features --features issue,certificate-profile
cargo build --locked --target wasm32-wasip2 --no-default-features --features reader-session
cargo +nightly fuzz run decode -- -max_total_time=120
cargo +nightly fuzz run certificate -- -max_total_time=60
```

Tests include ISO Annex D, official Final handover examples, independent
signature/MAC vectors, malformed-input tests and property tests. The
[0.4 boundary review](docs/protocol-boundaries-2026-11-19.md) records profile
fixtures, migration decisions and the separately assessed second-edition DIS.
The
[core benchmark](benchmarks/core/README.md) records CPU, elapsed time, allocation
stacks and linked consumer sizes. See the
[borrowed-data and dependency review](docs/borrowed-dependencies-2026-11-18.md),
[preceding merge review](docs/review-2026-11-18.md) and
[performance report](docs/performance-2026-11-18-final.md) for results and raw evidence.
Historical measurements are in the
[2026-11-17 validation record](docs/validation-2026-11-17.md).

## License and origin

BSD-2-Clause. Derived from [mdoc-rs](https://github.com/kushaldas/mdoc-rs) by
Kushal Das. See [LICENSE](LICENSE) and [source provenance](UPSTREAM_PROVENANCE.md).
