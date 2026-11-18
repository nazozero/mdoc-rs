# Borrowed data and dependency review — 2026-11-18

This follow-up to [PR #5](https://github.com/nazozero/nazo-mdoc/pull/5) makes
zero-copy a property of the credential data flow. The `zerocopy` package is not
the implementation strategy. The public borrowed APIs retain views of the
received buffer through parsing, authentication, disclosure selection and holder
response preparation. Encoding writes those views into the final wire buffer.

The preceding main revision is
`752b402e2d4e29407eb1e9ad81eeca5c085b235e`.

## Data flow and ownership

| Operation | Borrowed representation | Allocation or ownership boundary |
| --- | --- | --- |
| Parse DeviceResponse or IssuerSigned | Names, claims, salts, signed envelopes, protected headers, payloads and signatures refer to the input | Collections hold indexes and references |
| Read MSO | Digest bytes, key parameters, authorizations and status values refer to the authenticated payload | Index collections; scalar timestamps and algorithm values |
| Verify presentation or issued credential | Return `PendingTrustDocumentRef` or `PendingIssuerTrustDocumentRef` with borrowed document, MSO and certificate bytes | Upstream X.509 decoding uses its owned certificate model |
| Select disclosure | Retain or move the selected item views | No attribute-byte copy |
| Prepare holder authentication | Consume the selected borrowed document and borrow device namespaces | One contiguous external signing input, required by the signing API |
| Finish holder response | Verify the external signature and encode directly from the views | One new wire output; original signed bytes are preserved |
| Retain data beyond the input lifetime | Call `into_owned` explicitly | Owned strings, byte vectors and CBOR values are created here |

`CborValueRef` wraps a validated, private CBOR item. Scalars and array/map/tag
iteration do not construct an owned `ciborium::Value` tree. The existing owned
parser and verification functions use the borrowed implementation and convert at
their return boundary. They remain available for callers that need independent
storage. This is a zero-copy input model, not a claim of zero heap allocations.

The holder flow is:

```rust,ignore
let verified = nazo_mdoc::verify_issued_borrowed(issued, expected_doc_type, now)?;
let (mut document, mso, certificate_chain) = verified.into_parts();
// Apply application trust/status policy, then select the required issuer items.
let prepared = nazo_mdoc::response_builder::prepare_device_authentication_borrowed(
    document,
    &transcript,
    device_namespaces,
    -7, // ES256
)?;
let signature = external_signer.sign(prepared.signing_input()).await?;
let response = prepared.finish(&signature)?;
```

The input buffers must outlive the borrowed result and prepared operation.
`tests/borrowed_verification.rs` exercises this flow with a 65 KiB issuer attribute
and a 16 KiB authorized device attribute, including signature and authorization
failures. Parser tests check that views point inside the original allocation;
encoder tests compare owned and borrowed wire output and mutate public fields.

## Simplification and cryptography

The implementation shares one parser schema and one verification path. There is
no generic ownership mode, `Cow` value tree, retained encoding cache or second
untrusted-input parser. A private validated-MSO proof can be reused only while the
payload address and length are unchanged and the original parsing limits were
no wider than the defaults. Public mutable models and wider custom limits return
through the normal boundary checks.

ECDSA verification uses RustCrypto's multipart verifier; HMAC updates the message
fragments directly. Key coordinates use a fixed stack buffer, and certificate
SPKI verification creates the verification key directly. Prepared operations
retain that key for checking the external signature.

Ed25519 retains `verify_strict`. The upstream multipart interface does not provide
the same small-order-point rejection, so a fragmented Ed25519 message is joined
for the strict operation. The regression test demonstrates a weak-key forgery
accepted by the non-strict multipart interface and rejected by this library.
Replacing that check to remove a buffer would weaken the signature contract.

The latest `x509-cert` model owns its decoded fields. Certificate bytes exposed
to the caller still borrow the input; internal DER decoding remains an explicit
upstream allocation boundary. This change does not introduce a custom DER or
signature implementation to avoid those bounded allocations.

Issuance writes the MSO and issuer-item Tag 24 envelopes directly into their final
buffers. Digest values are hashed into the output without an intermediate
digest-map/value tree. Length calculation rejects excessive nesting before
recursing through an owned value. Shared namespace schema checks and protected
header writers replace duplicate validation and whole-header cloning.

## Dependencies

Every direct dependency in the current library, tests, fuzz harness and benchmark
harness was checked against the official crates.io registry on 2026-11-18 and
updated to the latest non-yanked stable release. Compatible transitive packages
were refreshed in all six current lockfiles. Historical benchmark dependencies
that deliberately pin earlier library revisions remain fixed.

| Package | Current version |
| --- | --- |
| `ciborium`, `coset` | 0.2.2, 0.4.2 |
| `const-oid`, `der`, `x509-cert` | 0.10.3, 0.8.3, 0.3.0 |
| `ed25519-dalek` | 3.0.0 |
| `p256`, `p384`, `p521` | 0.14.0 |
| `signature`, `sha2` | 3.0.0, 0.11.1 |
| `hkdf`, `hmac`, `getrandom` | 0.13.0, 0.13.0, 0.4.3 |
| `serde`, `thiserror`, `time`, `iri-string` | 1.0.229, 2.0.21, 0.3.55, 0.7.14 |
| `hex`, `proptest` | 0.4.3, 1.12.0 |
| Benchmark `chrono`, `libc` | 0.4.45, 0.2.191 |
| Fuzz `libfuzzer-sys` | 0.4.13 |

The [registry comparison](../benchmarks/core/results/2026-11-18-borrowed-dependencies/dependency-versions.json)
records each root-lockfile package's resolved versions, latest stable release,
MSRV and official registry URL. Remaining older major versions are constrained
by the latest upstream dependencies: `syn` 2 accompanies 3 for derive crates;
`r-efi` 6 is required by `getrandom`'s UEFI backend; `tls_codec` and its derive
package remain 0.4.2 in resolution for an inactive optional X.509 feature.
They cannot be replaced with incompatible majors by `cargo update`.

Unused property-test fork, timeout and bit-set features were removed. Existing
property tests retain the standard runner, shrinking and failure persistence.
This removes 27 packages from the intermediate updated root lockfile. Relative
to the preceding main revision, the final root lockfile has 98 registry package
entries instead of 141. `zerocopy` remains a compatible transitive dependency of
upstream packages; its presence does not determine this library's borrowing.

Rust 1.100.0 remains the current stable toolchain. CI uses the current pinned
toolchain action; its audit and fuzz tools remain on their checked latest stable
releases. X.509 certificate builder and PKCS#8 fixture features are test-only.

## Validation

Local locked tests pass with no failures or ignored tests:

| Configuration | Passed |
| --- | ---: |
| No default features | 159 |
| `issue` | 240 |
| All features | 247 |

These configurations overlap. Formatting, strict all-target Clippy, rustdoc,
native builds, three WASM build configurations and fuzz-target compilation pass.
Regressions cover pointer provenance, owned conversion, selected disclosure,
borrowed encoding, strict Ed25519, custom CBOR budgets, mutable public models and
canonical MSO/item output. The existing protocol tests continue to run.

The [architecture](architecture.md), [migration guide](migration.md) and
[protocol matrix](protocol-matrix.md) describe the public contract and its tests.
