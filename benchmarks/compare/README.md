# Historical baseline comparison

The harness compares `mdoc-rs` revision
`9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc` with the current `nazo-mdoc` checkout.
Both use `default-features = false, features = ["issue"]` in one release binary
on a pinned Linux thread. The separate workspace keeps benchmark dependencies
out of the library.

## Run

Build before measuring:

```sh
CARGO_BUILD_JOBS=2 cargo build --release --manifest-path benchmarks/compare/Cargo.toml --target-dir /absolute/path/target-mdoc-perf
```

Check operations, fixture signatures, known legacy output differences and
allocator instrumentation:

```sh
/absolute/path/target-mdoc-perf/release/nazo-mdoc-production-comparison --check
```

Freeze source changes, finish compiler/test jobs, then measure:

```sh
/absolute/path/target-mdoc-perf/release/nazo-mdoc-production-comparison --out /absolute/path/outside-repositories/mdoc-performance --samples 1000 --warmup 100
python3 benchmarks/compare/summarize.py /absolute/path/outside-repositories/mdoc-performance
```

`--cpu N` selects a permitted logical CPU; the default is the first allowed CPU.
Record host load alongside the saved hardware and affinity metadata. Use at
least 1,000 observations per variant and 100 warmups for release evidence.

The output directory contains:

- `samples.csv`: every observation, its units and actual AB/BA order.
- `summary.csv`: nearest-rank P50/P95/P99 for elapsed and thread CPU nanoseconds,
  plus allocation medians and means.
- `metadata.txt`: revisions, dirty state, toolchain, source/binary/input hashes,
  hardware, affinity and workload sizes.
- `source-manifest.txt`: candidate and harness Rust/Cargo input hashes.
- `annex-d-response.cbor` and `synthetic-final-response.cbor`: measured public
  verification fixtures.
- `report.md`: values rendered by the summarizer, which requires at least
  1,000 observations per variant.

Rebuild after source changes. Keep source frozen from build through measurement:
the manifest is collected at the end of the run. Publish the exact committed
source identity with the binary and input hashes.

## Measurement method

Warmups alternate both paths. Measured even rounds run baseline first; odd
rounds run candidate first. Each observation invokes the operation once for
timing and once separately for allocation counting. Counters are disabled during
timing; the allocator wrapper's enabled-flag branch is shared by both variants.

`Instant` records elapsed time and `CLOCK_THREAD_CPUTIME_ID` records thread CPU
time. An empty control exposes timer-call overhead. Output destruction is inside
the measured region. Fixture setup, verification-fixture signatures, preflight
assertions, measurement buffers and file output are outside it. Verification
operations assert success.

The allocator counts successful `alloc`, `alloc_zeroed` and `realloc` calls.
Requested bytes include the entire new capacity of each reallocation. Peak heap,
retained memory, RSS and copied bytes require separate measurements. The
allocator self-check checks one 1,024-byte allocation and a zero-allocation path.

Issuance includes real local signing and runtime randomness. Both variants use
the same logical attributes, times, certificate and holder key. Their concrete
validity values are constructed before timing and cloned into each builder.
The measured operation uses each issuer's original salt and digest-ID generation.

The shared binary unifies common Cargo versions and features. Independent
lockfiles, dependency graphs and artifact sizes are measured by the consumers
below. Report both elapsed and CPU quantiles and preserve every sample.

## Workloads

Annex D comes from `tests/vectors/iso_18013_5_annex_d_mdl.hex`. The synthetic
issuer and holder fixtures come from `tests/common/mod.rs`. Full verification
returns pending external trust.

| Case | Same inputs / material difference |
| --- | --- |
| `annex_d_device_response_parse` | Same complete DeviceResponse. Candidate adds bounded CBOR validation and stricter shape checks and retains original envelopes. |
| `annex_d_mso_parse` | Same signed MSO payload. Candidate enforces required members, schema, lengths, time and extension rules. |
| `annex_d_cbor_mso_decode` | Same inner MSO CBOR. Candidate validates the strict encoding/resource profile before decoding. |
| `annex_d_disclosure_verify` | Same disclosures/digests. Candidate adds duplicate/random constraints and no longer allocates the old per-attribute report. |
| `annex_d_cose_sig_structure` | Identical shared coset operation and byte-identical result; a useful unchanged-code control. |
| `annex_d_cose_es256_verify` | Identical Sig_structure/signature/public key. Candidate adds algorithm/key-usage validation. |
| `annex_d_leaf_certificate_access` | Baseline returns owned DER; candidate borrows DER after checking the full container. |
| `device_authentication_construct_raw_api` | Same transcript and logical empty namespaces. Baseline output lacks outer Tag 24; candidate output has the required wrapper and checks. **Different protocol outputs.** |
| `device_authentication_construct_validated_api` | Same distinction; candidate consumes the transcript already validated outside measurement through its borrowed API. |
| `final_device_signature_verify` | Both verify the exact same valid Final Tag 24 detached payload/signature. Baseline decodes an encoded COSE key; candidate borrows a parsed key and adds header/detached-mode constraints. |
| `issue_two_attributes_es256` | Same logical issuance task and real local fixture signer. Candidate also validates certificate/schema, limits digest IDs to 31 bits, keeps complete Tag 24 envelopes and verifies the returned signature against the leaf certificate's public key. Baseline `sign` has no equivalent post-signing confirmation. |
| `final_full_protocol_verification_pending_external_trust` | Candidate-only successful parse + issuer signature + digests + MSO/time + holder proof. No comparable baseline full-verifier number is reported. X.509 trust, certificate revocation, MSO-status HTTP and application admission are excluded. |
| `final_redirect_transcript_validate_and_borrow` | Candidate-only Final redirect context hashing and exact-byte validation, with pointer identity asserted. Input and context construction occur before timing. |
| `final_dc_api_transcript_validate_and_borrow` | The corresponding Final DC API validation, including the encryption-key thumbprint. The baseline has no equivalent Final context validator. |


Preflight confirms that the unchanged baseline full verifier fails holder
verification of the Final fixture. The old DeviceAuthentication encoding matches
the inner bytes of the candidate's complete Tag 24 envelope for the chosen empty
namespaces. These rows have different output or acceptance contracts and must
be reported separately.

Issuance includes signature confirmation against the certificate key. External
signers may additionally validate their own key-lease contract; integration
measurements identify their actual signer path and those checks.

## Independent dependency and size measurements

The two workspaces under `consumers/` compile the same `minimal_consumer.rs`.
They parse an input path supplied at runtime and resolve dependencies separately.

```sh
python3 benchmarks/compare/collect_structure.py --evidence /absolute/path/outside-repositories/mdoc-performance --target /absolute/path/target-mdoc-size
```

`--cargo /path/to/cargo --rustc /path/to/rustc` selects explicit executables.
The collector builds baseline `issue`, candidate minimum, candidate `issue` and
candidate all-features sequentially with one job. Release opt-level, LTO and
codegen settings match. It records actual compiler-artifact paths/sizes, binary
hashes, source counts, build logs, normal dependency graphs and successful Annex
D consumer runs.

All consumers disable default features. Candidate all-features enables `issue`,
`debug` and `wasm-js`. Dependency traversal uses the actual target and excludes
the core, dev/build edges and inactive target edges; distinct versions/sources
and reachable proc macros count separately.

`structure.csv` and `structure.md` distinguish Rust lines, rlib bytes and linked
parser-binary bytes. Source lines include comments and inline tests. Rlibs contain
code, IR and metadata. The combined timing binary has a unified graph and is
recorded separately from these standalone artifacts.

## Advisory checks

Audit the library, comparison, both consumer and fuzz lockfiles independently.
The comparison and baseline consumer retain the exact historical dependency
revision; report their advisories separately from the current library. Record
the advisory database revision, command, findings, warnings and yank status.
Benchmark and fuzz workspaces are unpublished and excluded from the package.

## Reading results

These measurements describe the named library operations on the recorded host.
Service throughput and endpoint latency require an integration workload.
Compare ratios only for equivalent successful operations; retain rows with
additional validation or different outputs under their actual contracts.
Report remaining CPU, allocation, size and tail regressions with improvements.
