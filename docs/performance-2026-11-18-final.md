# Core performance — final review, 2026-11-18

This records the final implementation for [Issue #4](https://github.com/nazozero/nazo-mdoc/issues/4).
The [first measurement](performance-2026-11-18.md) retains the earlier implementation and profiles.

## Final changes

- Borrow embedded Tag 24 bytes and move newly encoded buffers. Reserve parser containers from validated map lengths.
- Reuse validated CBOR and protected headers inside immutable parsing and verification paths. Public mutable-model APIs retain their input checks.
- Build the MSO once during issuance, validate caller-supplied status, and check the completed Tag 24 envelope. Prepared signing operations reuse key metadata and still verify every returned signature.
- Store timestamps as UTC values. Keep the existing historical `:60` representation and ordering; calendar parsing remains with `time`.

Two correctness fixes accompany the simplification. The public DeviceAuthentication
constructor now rejects an empty namespace name, empty element identifier, or a
present namespace containing no elements. An empty outer namespace map remains
valid. Debug diagnostic output now escapes control characters and preserves
floating-point types, signed zero and RFC 8949 nonfinite names.

## Revisions and method

| Component | Revision |
| --- | --- |
| Baseline library | `070e9cf727a31a8ee23ffd372d7dc9e378cbfdfc` |
| Final library and harness checkout | `bd18332dc2735c7a0784118fae91a8d5f414dc0d` |

Both benchmark executables were rebuilt with Rust 1.100.0, the same lockfile,
`issue`, opt-level 3, thin LTO and one codegen unit. Each process ran on CPU 0
of the shared AMD EPYC 9V74 host after local compilation and profiling finished.
Four AB/BA/AB/BA rounds used 100 warmups and 1,000 observations per operation.
A further two rounds used the identical baseline executable under both labels.
Timing and allocation counting use separate invocations.

All 12 processes succeeded. The 216,000 observations, input and deterministic-output
hashes, source manifests, binary identities and allocation stacks are retained.
Independent recalculation matched all 3,456 recorded quantiles and means.

- [Every round's CPU, elapsed and allocation results](../benchmarks/core/results/2026-11-18-final/summary.csv)
- [Identical-binary control](../benchmarks/core/results/2026-11-18-final/control-summary.csv)
- [Execution order and binary hashes](../benchmarks/core/results/2026-11-18-final/runs.json)
- [Raw evidence](../benchmarks/core/results/2026-11-18-final/evidence.tar.gz) and [file hashes](../benchmarks/core/results/2026-11-18-final/evidence-manifest.sha256)
- [Build and reproduction instructions](../benchmarks/core/README.md)

## CPU results

Values are the median of four per-round thread CPU P50 values, in microseconds.
The linked CSV retains each round's P50/P95/P99 and means for both clocks.

| Operation | Baseline | Final | Change |
| --- | ---: | ---: | ---: |
| Measurement floor | 0.220 | 0.220 | +0.00% |
| DeviceResponse parsing | 18.523 | 14.476 | -21.85% |
| MSO parsing | 14.892 | 5.959 | -59.99% |
| Inner MSO decoding | 13.425 | 4.792 | -64.31% |
| Canonical MSO encoding | 7.957 | 4.157 | -47.76% |
| Public disclosure verification | 2.664 | 2.659 | -0.19% |
| coset Sig_structure control | 0.606 | 0.621 | +2.56% |
| Certificate decoding | 4.602 | 4.582 | -0.45% |
| Certificate key conversion | 0.551 | 0.436 | -20.87% |
| Issuer ES256 verification | 367.031 | 373.692 | +1.81% |
| Holder ES256 verification | 375.369 | 399.340 | +6.39% |
| Issuance preparation | 19.674 | 10.961 | -44.29% |
| External ES256 signing control | 349.656 | 361.313 | +3.33% |
| Signature completion | 390.236 | 397.642 | +1.90% |
| Complete issuance | 871.463 | 816.412 | -6.32% |
| IssuerSigned encoding | 7.165 | 7.221 | +0.77% |
| Full protocol verification | 817.162 | 876.981 | +7.32% |
| Redirect transcript validation | 0.411 | 0.411 | +0.00% |

Parsing, MSO decoding, canonical encoding, key conversion and issuance preparation
have lower CPU P50 in every round. Complete issuance improves in three rounds
and increases 12.95% in round 2.

Full verification's aggregate P50 increases 7.32%; its per-round changes are
+8.00%, +35.69%, −5.82% and −1.96%. The same-binary control changes +0.97% and
−1.59%, so the measured regression exceeds that control. Holder verification
increases 6.39% overall. Signature completion increases 1.90%, with mixed results
across both execution orders. Their causes remain unresolved. The cryptographic
implementations and features are unchanged; full verification still performs one
issuer and one holder signature verification.

Tails remain mixed. Preparation CPU P99 in round 1 increases from 175.682 to
1,026.309 µs; full verification in round 2 increases from 1,628.486 to 3,686.974 µs.
Inner MSO decoding P99 in round 2 increases from 160.860 to 232.918 µs.
The maximum elapsed samples are 100.008 ms in the comparison and 23.703 ms in
the control. All samples remain in the archive.

## Allocation traffic

Counts below agree with the profiles and per-run allocation medians. Requested
bytes include each successful allocation request and the full new capacity of
reallocations.

| Operation | Calls, baseline → final | Requested bytes, baseline → final |
| --- | ---: | ---: |
| DeviceResponse parsing | 105 → 102 | 13,114 → 12,910 |
| Canonical MSO encoding | 112 → 30 | 9,575 → 6,404 |
| Issuance preparation | 237 → 98 | 18,289 → 11,596 |
| Complete issuance | 254 → 112 | 19,979 → 12,989 |
| Issuer ES256 verification | 2 → 0 | 169 → 0 |
| Signature completion | 2 → 0 | 169 → 0 |
| Holder ES256 verification | 15 → 5 | 1,098 → 575 |
| Full protocol verification | 155 → 121 | 17,338 → 14,591 |
| Certificate key conversion | 6 → 3 | 312 → 256 |

The other allocation counts remain unchanged. The standalone coset constructor
remains at 9 calls and 2,141 bytes; production authentication inputs use the
borrowed-input encoder.

## Linked consumer sizes

The [independent consumer](../benchmarks/core/consumer/README.md) links parsing
and full verification with issuance disabled. Both native executables passed
parsing and verification on the saved inputs. WASI components were built;
execution was checked on native. [Artifact identities](../benchmarks/core/results/2026-11-18-final/artifact-sizes.json)
record exact features, flags, sizes and hashes.

| Artifact | Baseline bytes | Final bytes | Change |
| --- | ---: | ---: | ---: |
| Native executable | 1,270,808 | 1,189,272 | -6.42% |
| Stripped native executable | 1,065,784 | 990,952 | -7.02% |
| Native rlib, including IR and metadata | 2,323,872 | 2,274,784 | -2.11% |
| WASI component | 853,631 | 774,043 | -9.32% |
| WASI rlib, including IR and metadata | 2,252,832 | 2,212,242 | -1.80% |

## Validation

[Source CI](https://github.com/nazozero/nazo-mdoc/actions/runs/44233690664) passed
all four jobs on the final source revision. Its merge tree equals the measured
tree. Minimum, `issue` and all-feature configurations passed **149 / 212 / 219**
tests, respectively, with zero failures or ignored tests. These configurations overlap.

Formatting, strict Clippy and rustdoc, three WASM builds and the advisory gate
passed. The advisory scan covered 142 dependencies and 1,527 advisories. Seeded
sanitizer fuzzing completed 236,037 executions in 121 seconds.

Regressions cover public-model mutation, duplicate MSO maps, critical headers,
x5chain placement, status validation, namespace cardinality, full-date syntax and
diagnostic output. The archive includes the constructor's failing old-version
run and both new-version attempts; the first attempt reused a stale shared-target
binary, and a forced rebuild passed. Received authenticated bytes, parser budgets,
algorithm/key binding, Final request binding, both signatures, returned-signature
confirmation and authenticated status remain checked. Verification returns
`PendingTrustDocument` for the caller's trust decision.
