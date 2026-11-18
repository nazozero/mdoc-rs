# Core performance — 2026-11-18

[Issue #4](https://github.com/nazozero/mdoc-rs/issues/4) covers parsing, issuance
and verification costs. This change shortens CBOR processing and removes
temporary allocations while retaining the public API and authentication checks.

## Revisions and evidence

| Component | Revision |
| --- | --- |
| Baseline library | `070e9cf727a31a8ee23ffd372d7dc9e378cbfdfc` |
| Candidate library and measured Rust harness | `a283838001cdee39f3608b935e88373190c5e3d9` |

Both executables use Rust 1.100.0, the committed benchmark lockfile, empty
default features plus `issue`, opt-level 3, thin LTO and one codegen unit. Each
links one library revision. The host was AMD EPYC 9V74, Linux 6.18.57, glibc 2.41;
each process ran on CPU 0. Local builds, tests and profilers had finished before
timing. The CPU was shared with the host.

There are four rounds in AB/BA/AB/BA order, with 100 warmups and 1,000
observations for each of 18 operations. A second AB/BA run executes the identical
baseline binary under both labels. Thread CPU time, elapsed time and allocation
traffic are recorded separately. All 216,000 timing observations and their
separate allocation invocations are retained; all 12 processes exited with 0.

- [Per-round CPU, elapsed and allocation quantiles](../benchmarks/core/results/2026-11-18/summary.csv)
- [Same-binary control quantiles](../benchmarks/core/results/2026-11-18/control-summary.csv)
- [Execution order and binary hashes](../benchmarks/core/results/2026-11-18/runs.json)
- [Raw samples, profiles, public inputs and validation logs](../benchmarks/core/results/2026-11-18/evidence.tar.gz)
- [Archive file hashes](../benchmarks/core/results/2026-11-18/evidence-manifest.sha256)
- [Build and run instructions](../benchmarks/core/README.md)

The archive includes the exact 1,353-byte presentation and transcript. Both
versions authenticate its issuer and holder signatures and return one
pending-trust document. Annex D supplies the larger parsing and MSO workloads.
Input and deterministic-output hashes agree across every run. Complete issuance
generates fresh salts and digest IDs for the same two attributes.

## Identified costs and changes

Allocation stacks were captured against the baseline before runtime edits. That
initial diagnostic build used its then-resolved compatible dependencies; the
final profiles and timing builds use the committed, matched lockfile. Both sets
of raw stacks, binary identities and source manifests are archived. Symbolized
stacks include inlined frames.

| Cost | Change |
| --- | --- |
| `Item::value` repeatedly located nested item boundaries and initialized scalar deserializers | Project the already validated immutable item through one cursor. Preserve tags and opaque Tag 24 bytes. |
| Canonical encoding cloned the value tree and serialized individual map keys into temporary buffers | Sort borrowed key references and write values into one output buffer. |
| Issuance cloned owned attributes, salts, keys, digests and status values | Move owned data into the result; encode the fixed item schema directly. |
| COSE authentication inputs cloned protected headers and payloads through generic value construction | Encode the four-element structure into one owned buffer, borrowing original protected bytes. |
| Key validation and SEC1 conversion allocated a set and point vector | Track supported labels in a bitset and use fixed-width point buffers after coordinate validation. |
| The private verifier repeated uniqueness checks established by parsing | Reuse the parsed result on that private path; keep all checks on the public disclosure API. |

The canonical writer follows [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1).
The COSE helpers follow [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
§4.4 and §6.3. Independent byte comparisons cover map-key and payload length
boundaries, original protected-header order, empty protected bytes and opaque
Tag 24 values.

The existing RustCrypto implementation and features are retained. Source review
of `ecdsa 0.17.0`, `p256 0.14.0` and `primeorder 0.14.0` found that the available
P-256 precomputed-table backend changes generator-only multiplication while
inheriting the combined operation used by verification. Dependency source
hashes and the reviewed call chain are in `validation/crypto-review.json` in the
archive.

## CPU results

Values below are the median of the four per-round CPU P50 values, in
microseconds. The linked CSV retains every round's P50/P95/P99 for both clocks.

| Operation | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| DeviceResponse parsing | 18.49 | 14.97 | −19.04% |
| MSO parsing | 14.80 | 6.01 | −59.39% |
| Inner MSO decoding | 13.52 | 4.70 | −65.26% |
| Canonical MSO encoding | 7.55 | 4.12 | −45.39% |
| Issuance preparation | 18.58 | 13.46 | −27.55% |
| Signature completion (`finish`) | 395.78 | 430.33 | +8.73% |
| Holder verification | 391.29 | 405.06 | +3.52% |
| Complete issuance | 870.21 | 869.76 | −0.05% |
| Full protocol verification | 940.92 | 876.73 | −6.82% |

CPU P50 decreases for the first five operations in every round. MSO decoding keeps its
59 allocations; its CPU improvement comes from the shorter traversal and
projection path. Preparation excludes building the input. Completion excludes
preparation and external signing. Complete issuance includes all three stages,
OS entropy and confirmation of the returned signature.

### Regressions and tails

Completion CPU P50 and P95 increase in all four rounds, across both execution
orders. Its P50 increases by 0.65%, 11.81%, 16.68% and 13.16%; the cause remains
unresolved. Holder verification P50 increases in three rounds. Complete issuance
P50 is effectively unchanged overall, with three rounds slower by 0.68–4.65%.

Some tails also increase: preparation CPU P99 reaches 375.34 µs against
136.96 µs in round 3; complete issuance reaches 7.75 ms against 4.52 ms in that
round. MSO parsing P99 increases in round 2, and canonical encoding P99 increases
in three rounds. MSO decoding P50, P95 and P99 decrease in every round.

Full-verification P50 varies by +11.2% and +3.8% between labels in the same-binary
control. Its observed −6.82% change above is within that variation. The control
also shows several-fold P99 differences for small operations. The largest
elapsed samples, 57.53 ms in the comparison and 102.40 ms in the control, remain
in the raw data. These runs establish the local parsing and preparation gains;
complete issuance and verification latency and their remaining regressions need
further investigation.

## Allocation traffic

These counts match the standalone allocation profiles and each timing run's
allocation P50. Requested bytes count successful allocation requests, including
the full new capacity on reallocation. They measure allocator traffic.

| Operation | Calls, baseline → candidate | Requested bytes, baseline → candidate |
| --- | ---: | ---: |
| Canonical MSO encoding | 112 → 30 | 9,575 → 6,404 |
| Issuance preparation | 237 → 110 | 18,289 → 13,396 |
| Complete issuance | 254 → 124 | 19,979 → 14,789 |
| Issuer signature verification | 2 → 0 | 169 → 0 |
| Signature completion | 2 → 0 | 169 → 0 |
| Holder verification | 15 → 5 | 1,098 → 575 |
| Full protocol verification | 155 → 128 | 17,338 → 15,468 |
| Certificate key conversion | 6 → 3 | 312 → 256 |

All other allocation counts remain unchanged. The independent coset
Sig_structure control remains at 9 calls and 2,141 bytes; production library
paths use the new borrowed-input encoder.

## Linked consumer sizes

The separate [consumer](../benchmarks/core/consumer/README.md) links parsing and
full protocol verification with issuance disabled. Both native executables ran
the same parse and verification commands successfully. WASI components were
built and measured. Exact hashes, features and flags are in
[artifact-sizes.json](../benchmarks/core/results/2026-11-18/artifact-sizes.json).

| Artifact | Baseline bytes | Candidate bytes | Change |
| --- | ---: | ---: | ---: |
| Native executable | 1,270,808 | 1,209,848 | −4.80% |
| Stripped native executable | 1,065,784 | 1,008,336 | −5.39% |
| Native library rlib, including IR and metadata | 2,323,872 | 2,294,854 | −1.25% |
| WASI component | 853,631 | 791,349 | −7.30% |
| WASI library rlib, including IR and metadata | 2,252,832 | 2,231,178 | −0.96% |

## Validation

The [source CI run](https://github.com/nazozero/mdoc-rs/actions/runs/44224722403)
passed Rust, target, advisory and fuzz jobs. Local tests passed with no default
features (146), `issue` (204) and all features (209), together with formatting,
Clippy, documentation, three WASM configurations and `cargo audit --deny warnings`.

New regression tests cover canonical-key ordering, integer and float boundaries,
tag preservation, COSE byte equivalence, coordinate widths and mutation of
publicly decoded disclosure models. The fuzz target also exercises canonical
encoding after successful arbitrary CBOR decoding. Received authenticated bytes,
parser budgets, duplicate rejection, algorithm/key binding, Final request
binding, both signatures, completion checks and authenticated status values
remain enforced. Verification still returns `PendingTrustDocument`.

The local ASan run completed 120,471 executions in 121 seconds. Leak detection
was disabled for that run after the runner's ptrace restriction stopped
LeakSanitizer at shutdown; CI passed with the default sanitizer configuration.
The validation archive retains that failure and the earlier disk-full build
failure, followed by successful retries.
