# nazo-mdoc

A Rust library for issuing, parsing and authenticating ISO mdoc credentials.
It provides CBOR/COSE processing, selective disclosure, external signing and
OpenID4VP 1.0 Final session binding.

The package is `nazo-mdoc`; the Rust crate is `nazo_mdoc`. Rust 1.100 or later
is required. For a Git dependency, pin the full commit revision you have tested.

## Presentation verification

```rust,ignore
use nazo_mdoc::{verify_presentation, VerificationOptions};
use nazo_mdoc::session::{RedirectHandover, SessionTranscript};

let transcript = SessionTranscript::validate_redirect(raw_transcript, RedirectHandover {
    client_id: full_client_id,
    nonce: request_nonce,
    jwk_thumbprint: response_encryption_key_thumbprint,
    response_uri,
})?;
let documents = verify_presentation(response, &transcript, &VerificationOptions {
    now: verification_time,
    max_documents: 1,
})?;
for document in documents {
    application.check_trust_and_policy(document).await?;
}
```

`verify_presentation` authenticates issuer and holder signatures, disclosure
digests, document type, device-key authorizations and MSO validity. It returns
`PendingTrustDocument`, containing the authenticated document, MSO and certificate
chain. The application completes:

- X.509 path validation against its trusted issuers, including the document
  signer profile and certificate revocation.
- Credential status checks using the authenticated MSO `status` extension.
- Request freshness, nonce consumption, requested claims and authorization.

`SessionTranscript::redirect` and `dc_api` construct Final handovers. Their
`validate_*` counterparts bind received bytes to the supplied request context
and borrow the validated buffer. `from_cbor` provides structural validation for
other transcript profiles; request binding remains the caller's responsibility.

The generic parser allows up to 16 documents. `VerificationOptions` sets the
presentation limit; HAIP callers use 1. A verification error rejects the whole
response.

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
schema types for their namespaces. Status references are supplied by the issuer;
the application manages their allocation and publication.

## Protocol support

| Area | Support |
| --- | --- |
| Issuer and holder signatures | ES256/P-256, ES384/P-384, ES512/P-521 and EdDSA/Ed25519; fixed-width COSE ECDSA signatures and strict Ed25519 verification |
| MSO digests | SHA-256, SHA-384 and SHA-512 with matching digest lengths |
| Versions | Emit `1.0`; receive numeric minor versions of major version 1 |
| Session binding | OpenID4VP 1.0 Final Redirect and DC API handovers |
| Device authentication | DeviceSignature in `verify_presentation`; separate DeviceMAC and HKDF primitives for caller-established sessions |
| Authenticated bytes | Preserve received Tag 24 envelopes, protected headers and payloads |
| CBOR input | Definite lengths, shortest integer/length encodings, unique integer/text/byte-string map keys, valid UTF-8 and preserved tags; false, true, null and IEEE floats |
| CBOR limits | 1 MiB per envelope, depth 32, 65,536 items and 4,096 entries per collection; configurable through `parse_with_limits` |
| Time | Explicit `Timestamp`, UTC whole-second MSO encoding and preserved leap-second ordering |

Unsupported MSO and DeviceKeyInfo security fields are rejected during verification. Positive RFU
`keyInfo` labels are preserved and ignored as required by ISO. The complete
authenticated `status` value is retained for application policy.

The [protocol matrix](docs/protocol-matrix.md) maps requirements to code and
tests. Full ISO reader support, including Brainpool/Ed448, proximity engagement,
reader authentication and complete MAC session setup, is tracked in
[issue #3](https://github.com/nazozero/mdoc-rs/issues/3).

## Features

| Feature | Effect |
| --- | --- |
| Default | Parsing and verification; empty feature set |
| `issue` | Credential and response builders, encoding, OS entropy for salts |
| `debug` | CBOR diagnostic formatting |
| `wasm-js` | JavaScript entropy integration for issuance on `wasm32-unknown-unknown` |

Verification accepts an explicit time and runs without a network client or
platform clock. See [architecture](docs/architecture.md) for the data flow and
[migration](docs/migration.md) for changes from `mdoc-rs 0.2.0`.

## Development

```sh
cargo fmt --check
cargo test --locked --no-default-features
cargo test --locked --no-default-features --features issue
cargo test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo audit --deny warnings
cargo build --locked --target wasm32-unknown-unknown --no-default-features
cargo build --locked --target wasm32-unknown-unknown --no-default-features --features issue,wasm-js
cargo build --locked --target wasm32-wasip2 --no-default-features --features issue
cargo +nightly fuzz run decode -- -max_total_time=120
```

Tests include ISO Annex D, official Final handover examples, independent
signature/MAC vectors, malformed-input tests and property tests. The
[core benchmark](benchmarks/core/README.md) records CPU, elapsed time, allocation
stacks and linked consumer sizes. See the
[performance report](docs/performance-2026-11-18.md) for results and raw evidence.
Historical measurements are in the
[2026-11-17 validation record](docs/validation-2026-11-17.md).

## License and origin

BSD-2-Clause. Derived from [mdoc-rs](https://github.com/kushaldas/mdoc-rs) by
Kushal Das. See [LICENSE](LICENSE) and [source provenance](UPSTREAM_PROVENANCE.md).
