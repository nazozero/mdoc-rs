# nazo-mdoc

A Rust protocol core for ISO mdoc credentials and OpenID4VP 1.0 Final holder
binding. This is the maintained continuation of the BSD-2-Clause `mdoc-rs`
codebase used by NazoAuth, with a deliberately smaller responsibility boundary.

The package is `nazo-mdoc` (`nazo_mdoc` in Rust), version 0.3.0. The repository
remains `nazozero/mdoc-rs`; the imported source, license records and production
revision remain in this repository's Git history. The original upstream's full
Git history was unavailable; the recorded crates.io source archive is the import
origin. The package has not been published merely by changing
its manifest. Until a release is explicitly published, depend on an immutable
Git revision containing this package.

## Responsibility boundary

The core handles bounded CBOR/COSE decoding, original Tag 24 byte preservation,
MSO validation, selective disclosure, issuer signature verification, holder
signatures, Final SessionTranscript construction and external signing inputs.
It never fetches a URL, owns a trust store, installs a certificate as a root,
opens a database, manages private signing keys, or implements OpenID endpoints.

`verify_presentation` returns `PendingTrustDocument`, **not a final valid
credential**. The host must still finish all of the following:

- Anchor the issuer certificate chain using its X.509 profile and trusted IACAs.
- Enforce certificate revocation and current issuer policy.
- Inspect the authenticated MSO `status`, including unknown mechanisms, and run
  its credential status policy. An unknown mechanism is never converted to absence.
- Bind the supplied transcript to the authenticated request, enforce nonce
  freshness/consumption, requested claims and business authorization.

NazoAuth supplies these responsibilities through its existing crypto, credential
status, OpenID4VCI, OpenID4VP and HAIP modules. See [the protocol matrix](docs/protocol-matrix.md)
and [the migration guide](docs/migration.md).

## Small, explicit API

```rust,ignore
use nazo_mdoc::{verify_presentation, VerificationOptions};
use nazo_mdoc::session::{SessionTranscript, RedirectHandover};

let transcript = SessionTranscript::validate_redirect(raw_transcript, RedirectHandover {
    client_id: full_client_id,
    nonce: request_nonce,
    jwk_thumbprint: response_encryption_key_thumbprint,
    response_uri: response_uri_or_redirect_uri,
})?;
let documents = verify_presentation(response, &transcript, &VerificationOptions {
    now: verification_time,
    max_documents: 1, // HAIP policy; generic ISO responses can permit more
})?;
for document in documents {
    host.finish_trust_and_status(document).await?;
}
```

Use `SessionTranscript::redirect` or `dc_api` to construct Final transcripts.
`from_cbor` is a bounded structural check for an already constructed transcript;
it is **not** proof that its contents match a request. The private fields and
`binding()` distinguish this state. Validated raw transcripts borrow their input.
The device signature input embeds transcript and DeviceNameSpacesBytes exactly
as supplied. It never round-trips signed byte strings through a decoded map.

Issuance is a three-step external signature operation:

```rust,ignore
use nazo_mdoc::{builder::DocumentBuilder, model::CoseAlgorithm};

let prepared = DocumentBuilder::new(doc_type)
    .add_namespace(namespace, attributes)
    .device_key(device_public_key)
    .validity(validity)
    .prepare(CoseAlgorithm::ES256, document_signer_chain)?;
let signature = key_lease.sign(prepared.signing_input()).await?;
let document = prepared.finish(signature)?;
let issuer_signed = document.to_issuer_signed_cbor()?; // OpenID4VCI A.2.4
```

`finish` checks the external signature against the leaf certificate's public
key. It does not establish issuer chain trust. `response_builder` offers the
same prepare/sign/finish pattern for a holder signature; no private key enters
that builder either. Applications supply explicit CBOR tags according to their
namespace and schema; the generic builder never infers schema from attribute names.

## Supported profile

- Issuer and holder signatures: ES256/P-256, ES384/P-384, ES512/P-521, and
  EdDSA/Ed25519. Declared algorithm, key type, curve and operation must agree.
  ECDSA requires fixed-width COSE r||s; Ed25519 uses strict verification.
- MSO digest algorithms: SHA-256, SHA-384, SHA-512 with exact digest lengths.
- Issuance emits version `1.0`. Reception accepts unknown numeric minor versions
  of major version 1 for DeviceResponse and MSO, as required by ISO 18013-5 §8.1;
  changing a minor version does not bypass signature or schema validation.
- CBOR: definite lengths, shortest integer/length encodings, no duplicate keys
  or trailing items, valid UTF-8, bounded embedded Tag 24 items. Protocol map
  keys are integers/text/byte strings; compound and floating-point keys are
  rejected. Tags are preserved even for small bignums; protocol integer fields
  require native integers. Undefined and unsupported simple values are rejected.
  Input map order is preserved; issuance uses core deterministic CBOR, requiring
  preferred bignum representation without rewriting opaque Tag 24 contents.
- Default limits: 1 MiB input, depth 32, 65,536 items per decoded CBOR envelope,
  4,096 entries per collection, at most 16 documents for generic parsing.
  Embedded Tag 24 shares its envelope budget; opaque COSE protected headers and
  MSO payloads are checked separately with the same limits. `parse_with_limits`
  accepts explicit limits; HAIP verification sets `max_documents: 1`.
- Presentation authentication requires a holder signature. DeviceMAC is an
  explicit HMAC primitive using an externally derived key, not enabled by the
  server presentation verifier. The HKDF helper hashes SessionTranscriptBytes.
- Unsupported critical headers, header extensions, ambiguous auth mechanisms,
  unknown MSO/DeviceKeyInfo security extensions and proprietary keyInfo semantics
  are rejected by the server profile. Positive keyInfo labels reserved for future
  use are preserved and ignored as required by ISO; they grant no authorization.
  `status` is preserved for explicit host policy.

This is not a complete ISO proximity reader/wallet or a claim of full ISO,
OpenID or HAIP certification. Unsupported Brainpool/Ed448 algorithms, transport
engagement, reader authentication and legacy handover profiles are listed in the
matrix. Old certification and old test results do not certify this implementation.

## Features and validation

Default features are empty. `issue` adds preparation/encoding and OS entropy for
salts. `debug` provides CBOR diagnostic formatting. `wasm-js` selects the JS
entropy integration when issuance is built for `wasm32-unknown-unknown` (the host
must provide the corresponding JS environment). Verification requires an explicit
time, and has no network or clock service dependency.

Validity and verification time use `Timestamp`, backed by the maintained `time`
crate. It preserves UTC leap-second ordering and refuses a lossy Unix-time
projection of a leap second. The production core does not depend on Chrono.

```sh
cargo fmt --check
cargo check --locked --no-default-features
cargo test --locked --no-default-features
cargo test --locked --no-default-features --features issue
cargo test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo audit --deny warnings
cargo build --locked --no-default-features
cargo build --locked --all-features
cargo build --locked --target wasm32-unknown-unknown --no-default-features
cargo build --locked --target wasm32-unknown-unknown --no-default-features --features issue,wasm-js
cargo build --locked --target wasm32-wasip2 --no-default-features --features issue
cargo +nightly fuzz run decode -- -max_total_time=120
cargo run --release --manifest-path benchmarks/compare/Cargo.toml
```

Protocol tests include the inherited ISO Annex D fixture, official Final
Redirect/DC API example vectors, external signing round trips, mutation tests
and property-based malformed-input tests. See the benchmark's methodology for
comparison scope; strict parsing and new security checks are measured rather
than described as free or allocation-free.

The [validation record](docs/validation-2026-11-17.md) identifies the exact tested
runtime, CI results, advisory findings and measured performance, including
regressions and comparison limits. It separately retains the scope of historical
checkpoints; earlier test results do not stand in for current runtime evidence.

## Authorship, maintenance and source

NazoZero Contributors maintain the `nazo-mdoc` continuation and its NazoAuth
integration. Kushal Das authored the original `mdoc-rs` codebase. Both are
credited in Cargo's `authors` metadata; this does not imply that the original
author maintains or endorses this continuation. The source import and subsequent
maintenance changes are recorded separately in the provenance documents.

Read the [migration guide](docs/migration.md) before deploying the new verifier.
Some credentials produced by the old unrestricted-u32 digest-ID generator need
authorized reissuance. Passing tests on an in-range historical credential does
not establish compatibility with every credential previously issued.

BSD-2-Clause. See [LICENSE](LICENSE), [UPSTREAM_PROVENANCE.md](UPSTREAM_PROVENANCE.md)
and [MIGRATION_PROVENANCE.md](MIGRATION_PROVENANCE.md). Original author attribution
and the existing copyright notice are retained. The source-import record explains
that the archive did not contain a standalone license file and how this mirror's
license notice was established. No ISO standard full text is redistributed here.
