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
| Read MSO | Digest bytes, key parameters, authorizations and status values refer to the original MSO payload; the verifier establishes authentication | Index collections; scalar timestamps and algorithm values |
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
`tests/borrowed_verification.rs` exercises this flow with a 64 KiB issuer attribute
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

The latest `x509-cert` model owns its decoded fields. Certificate DER slices
exposed by borrowed verification results still refer to the input. The owned
compatibility APIs materialize independent storage. Internal DER decoding remains
an explicit upstream allocation boundary. This change does not introduce a custom
DER or signature implementation to avoid those bounded allocations.

Issuance writes the MSO and issuer-item Tag 24 envelopes directly into their final
buffers. Item digests are computed from the original encoded items and written
directly to the MSO output, without an intermediate digest map or Value tree.
Length calculation rejects excessive nesting before
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

[Source CI](https://github.com/nazozero/nazo-mdoc/actions/runs/44250617528)
passes all four jobs on `27c68b248260c7c0c0c4268b1cf9f44413241eb0`.
The advisory gate scans 99 lockfile packages including this crate against 1,527
advisories with warnings denied. Seeded sanitizer fuzzing completes 394,639
executions in 121 seconds. Local logs retain an initial Clippy failure for a
needlessly borrowed test expression and the successful final run after its fix.

## Measurements

| Component | Identity |
| --- | --- |
| Previous main | `752b402e2d4e29407eb1e9ad81eeca5c085b235e` |
| Retained previous executable build | `de10f77447a4e09563589bc71fdc94eb15bb2539`; its 28 library source/manifest hashes match previous main |
| Current source and executable build | `27c68b248260c7c0c0c4268b1cf9f44413241eb0` |
| Previous executable SHA-256 | `eb4d481e65ea2db5d64492f460392c9932bfea94f9a24cb215d8a644c9384e65` |
| Current executable SHA-256 | `d94df1e8e05d9efed574d9f18fae82ad8a87d2254ba4dd0e4de2040252141633` |

Both executables use Rust 1.100.0, `issue`, opt-level 3, thin LTO, one codegen
unit, debug level 1 and panic unwinding on the same host. The retained executable
keeps the preceding dependency graph; the current one uses the updated graph.
The runner labels identify the experiment, independently of the build's internal
`candidate` feature name. The older harness's `baseline_revision=070e...` field
is historical configuration, not the baseline used in this experiment.

Each process runs on CPU 0 of the shared AMD EPYC 9V74 host. Compilation finishes
before measurement, and source remains frozen during all runs. Four alternating
AB/BA rounds use 100 warmups and 1,000 observations per operation. Two more rounds
run the identical previous executable under both labels as a control. Three
additional four-round experiments compare owned and borrowed operations in the
same current executable. The response, transcript, MSO and deterministic signing
inputs have identical hashes throughout.

Timing and allocator counting use separate invocations, and output destruction
is included. No samples or tails are removed. Requested bytes count allocation
requests, including the full capacity of reallocations; they are not resident
memory. Parse/MSO cases use ISO Annex D; full verification uses the same saved
Final presentation with one issuer and one holder signature. The full verifier
returns pending-trust evidence and excludes application trust/network policy.

### Owned and borrowed APIs in the same current executable

CPU values are the median of four per-round thread CPU P50 values, in microseconds.
Allocation values are per-operation medians and agree across all four rounds.

| Operation | Owned CPU | Borrowed CPU | CPU change | Allocation calls, owned → borrowed | Requested bytes, owned → borrowed |
| --- | ---: | ---: | ---: | ---: | ---: |
| DeviceResponse parsing | 14.591 | 11.682 | -19.94% | 100 → 41 | 13,570 → 5,396 |
| MSO parsing | 7.005 | 5.683 | -18.87% | 43 → 16 | 4,577 → 2,520 |
| Full verification | 770.953 | 767.729 | -0.42% | 83 → 51 | 11,734 → 6,714 |

The parse/MSO experiments show the cost of explicit owned conversion. Full
verification's 0.42% CPU difference is too small to support an overall speedup
claim on this host; the allocation reduction is the clearer result. The strict
Ed25519 exception is covered by tests, but these timing fixtures use ES256.

### Previous main versus current owned compatibility APIs

This comparison includes both implementation and dependency changes. It does
not isolate a specific dependency's effect. It retains the same owned return
contracts for both revisions.

| Operation | Previous CPU | Current CPU | CPU change | Allocation calls, previous → current | Requested bytes, previous → current |
| --- | ---: | ---: | ---: | ---: | ---: |
| Measurement floor | 0.220 | 0.220 | +0.00% | 0 → 0 | 0 → 0 |
| DeviceResponse parsing | 14.491 | 14.546 | +0.38% | 102 → 100 | 12,910 → 13,570 |
| MSO parsing | 5.934 | 6.955 | +17.21% | 64 → 43 | 6,196 → 4,577 |
| Inner MSO decoding | 4.692 | 4.722 | +0.64% | 59 → 59 | 4,528 → 4,528 |
| Canonical MSO encoding | 4.096 | 4.407 | +7.58% | 30 → 30 | 6,404 → 6,404 |
| Disclosure verification | 2.664 | 2.674 | +0.38% | 6 → 6 | 564 → 564 |
| coset constructor control | 0.626 | 0.555 | -11.26% | 9 → 9 | 2,141 → 2,141 |
| Certificate decoding | 4.487 | 2.829 | -36.94% | 22 → 22 | 2,497 → 2,497 |
| Certificate key conversion | 0.446 | 0.421 | -5.61% | 3 → 3 | 256 → 256 |
| Issuer ES256 verification | 354.598 | 347.918 | -1.88% | 0 → 0 | 0 → 0 |
| Holder ES256 verification | 344.303 | 345.534 | +0.36% | 5 → 2 | 575 → 89 |
| Issuance preparation | 10.796 | 8.462 | -21.62% | 98 → 53 | 11,596 → 6,170 |
| External ES256 signing control | 342.961 | 333.808 | -2.67% | 1 → 1 | 64 → 64 |
| Signature completion | 356.952 | 357.087 | +0.04% | 0 → 0 | 0 → 0 |
| Complete issuance | 718.060 | 729.087 | +1.54% | 112 → 67 | 12,989 → 7,563 |
| IssuerSigned encoding | 4.222 | 3.966 | -6.06% | 31 → 25 | 10,837 → 9,291 |
| Full verification | 762.851 | 747.003 | -2.08% | 121 → 83 | 14,591 → 11,734 |
| Redirect transcript validation | 0.411 | 0.431 | +4.87% | 0 → 0 | 0 → 0 |

Owned MSO parsing increases 17.21% in CPU P50 even though it allocates less. It
now builds borrowed indexes and explicitly converts to independent storage. The
shared schema is retained instead of maintaining a second owned parser. Owned
response parsing requests 5.11% more allocator bytes (13,570 versus 12,910),
with almost unchanged CPU P50. Callers that can keep the input alive use the
borrowed API to avoid that conversion.

Canonical encoding's 7.58% and transcript validation's 4.87% CPU increases are
also retained. The direct issuance preparation path reduces CPU P50 by 21.62%
and allocation calls from 98 to 53; complete issuance is 1.54% slower in this
run and should not be described as a measured overall speedup. Cryptographic
cases and tails vary on this shared host. All rounds and the unchanged control
are published rather than selecting the fastest run.

The identical-binary control's median-of-round CPU P50 changes across cases
range from −11.75% to +3.21%; full verification changes +3.21%. Its CPU P99
changes range from −71.00% to +29.94%, with full verification at +14.53%.
Tails also regress in the main comparison: owned full verification CPU P99
increases from 1,825.170 to 1,950.977 µs (+6.89%), and complete issuance from
1,887.811 to 2,463.776 µs (+30.51%). External signing control P99 increases
29.71%, and IssuerSigned encoding P99 increases 32.12%. These are the medians
of per-round P99 values, not pooled quantiles. The evidence retains both CPU
and elapsed P50/P95/P99, means and every original observation.

### Reproduction and evidence

The 36 measurement processes produced 252,000 observations in 252 case/process
groups. Independent recalculation exactly matched all 4,032 reported quantiles
and means. Observation IDs cover 0–999 in every group, all processes succeeded,
and all seven input/deterministic-output hashes agree. Two one-sample preflight
processes are retained separately and excluded from these performance totals.

A separate provenance review recomputed both executable hashes, checked all
1,424 per-process source-manifest entries against their Git objects and confirmed
that the old executable's complete library source and root manifests match
previous main. It also checked actual fixture/transcript bytes. This establishes
the recorded binary/source/input correspondence; it does not claim a second
independent implementation of the derived CBOR bytes or a bit-reproducible rebuild.

- [Previous main versus current, every round](../benchmarks/core/results/2026-11-18-borrowed-dependencies/summary.csv)
- [Identical-binary control](../benchmarks/core/results/2026-11-18-borrowed-dependencies/control-summary.csv)
- Same-executable API comparisons: [response parsing](../benchmarks/core/results/2026-11-18-borrowed-dependencies/borrowed-response-parse.csv), [MSO parsing](../benchmarks/core/results/2026-11-18-borrowed-dependencies/borrowed-mso-parse.csv), [full verification](../benchmarks/core/results/2026-11-18-borrowed-dependencies/borrowed-verification.csv)
- [Exact commands](../benchmarks/core/results/2026-11-18-borrowed-dependencies/experiments.json), [independent recalculation](../benchmarks/core/results/2026-11-18-borrowed-dependencies/independent-recalculation.json) and [source CI record](../benchmarks/core/results/2026-11-18-borrowed-dependencies/validation.json)
- [Raw samples, inputs, source manifests and validation logs](../benchmarks/core/results/2026-11-18-borrowed-dependencies/evidence.tar.gz) and [file hashes](../benchmarks/core/results/2026-11-18-borrowed-dependencies/evidence-manifest.sha256)

To reproduce the preceding-main comparison, check out `de10f774...` and
`27c68b24...` in separate worktrees and build **both** harnesses with
`--no-default-features --features candidate`. Each harness then links its own
checkout and locked dependencies. Use the current `run.py`, pass the preceding
executable as `--baseline`, and reuse `fixture/final-response.cbor` from the
archive. The core README's `--features baseline` command instead builds the
older `070e9cf...` historical baseline; it is a different comparison. The same
README documents the three current owned/borrowed case pairs and measurement
controls.
