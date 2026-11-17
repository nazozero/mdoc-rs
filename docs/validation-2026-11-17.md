# Validation checkpoint: 2026-11-17

This checkpoint records the final runtime `2492f361`: CBOR Tag 2/3 is
preserved through every protocol projection, undefined is rejected instead of
being mapped to null, and canonical issuance rejects nonpreferred bignum inputs.
The same eleven wire regressions fail on the exact previous `d52cfca` checkpoint
and pass on this runtime, including independently authenticated invalid COSE
header types. RFC 8949 permits extended numeric equivalence; the correction
enforces this application's native-wire-type and extension-preservation contract,
not a claim that the general-purpose decoder violates RFC 8949.

This is implementation evidence, not an ISO/OpenID certification claim. The
normative scope, unavailable licensed text and unsupported capabilities are in
[protocol-matrix.md](protocol-matrix.md). Historical evidence must not be
relabelled as evidence for a later runtime.

## Source identities

| Object | Exact identity |
| --- | --- |
| Production baseline | `9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`, `mdoc-rs 0.2.0`, no default features, `issue` |
| Candidate runtime | `2492f3610dbb2b0bf37c56abd88fade61753f017`, `nazo-mdoc 0.3.0` |
| NazoAuth integration base | `9560ea04bbc01a2da7b002eeeeb0ebe2e7dffbe9` |
| Core review | [mdoc-rs PR 2](https://github.com/nazozero/mdoc-rs/pull/2) |
| Application review | [NazoAuth PR 286](https://github.com/nazozero/NazoAuth/pull/286) |
| Toolchain | Rust 1.100.0, `0ef1bc386059596dada8fb65b50425aab2ea637a`, LLVM 23.1.5 |

The application pins the runtime revision. Subsequent documentation-only
commits do not require an artificial production dependency update.

## Executed core gates

The [runtime CI run](https://github.com/nazozero/mdoc-rs/actions/runs/44073085030)
completed all four jobs successfully: Rust, targets, fuzz and advisories.

* Formatting, minimum/issue checks, tests, all-target Clippy with warnings denied,
  and rustdoc with warnings denied passed.
* All-features executed 187 tests; no-default-features executed 128. The production
  baseline executed 49 issue-feature and 63 all-feature tests. Some old ISO test
  files were gated by TSP and executed no tests in the production configuration.
* The runtime CI executed successful `cargo check` for `wasm32-unknown-unknown`
  minimum and issue plus `wasm-js`, and `wasm32-wasip2` issue. These are cross-target
  checks, not linked/running WASM programs. The follow-up workflow additionally
  requires explicit native and WASM `cargo build`; its job results must be
  recorded separately instead of reclassifying the earlier check logs.
* The final seeded CI fuzz campaign completed **444,990 runs in 121 seconds**,
  with successful process exit and ASan/LSan enabled. It reaches bounded CBOR,
  COSE, MSO, issued/presentation verification, Timestamp and FullDate. This
  finite campaign is not proof that every malformed input has been explored.
* Property tests cover malformed bytes without panic, duplicate keys, status
  presence/unknown mechanisms/index bounds, and Final transcript binding.
* ISO Annex D, the Final Redirect/DC API examples, RFC 6979 P-384 and RFC 8032
  Ed25519 vectors have explicitly recorded provenance. MAC/HKDF fixtures are
  independent synthetic vectors, not mislabelled as official test vectors.

An earlier local fuzz invocation completed its mutation phase but failed at
LeakSanitizer teardown in the restricted process environment. It remains a
failed invocation. A later local ASan run disabled leak detection explicitly;
the final GitHub run above does not depend on that local exception.

## Advisory snapshot and maintenance scope

At database `233155b4025b854c68a4b199c0e32d7fd53291a2` (1,527 advisories), the
candidate root lockfile has **142 packages, zero vulnerabilities and zero
warnings** under `cargo audit --deny warnings`. The independent candidate
consumer and fuzz lockfiles also pass.

The Chrono unmaintained advisory
[RUSTSEC-2026-0543](https://github.com/rustsec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md)
was merged during this work. The core and its tests were migrated to maintained
`time` with explicit, tested leap-second and precision handling. This is a
maintenance advisory, not a newly demonstrated memory-safety exploit. Earlier
clean scans against 1,509 advisories are historical results only.

The comparison and baseline consumer intentionally keep the real baseline's
Chrono dependency. Their strict audits report that maintenance warning and fail;
we neither suppress it nor change the historical source to improve a comparison.
The old complete library lockfile also has 15 vulnerability advisories in optional
components removed from the new core. None of those 15 is in the baseline's
production `issue` normal dependency graph; the lockfile finding must not be
reported as 15 reachable production vulnerabilities.

Removing Chrono from this core does not remove it from NazoAuth's unrelated
application APIs, persistence models and other workspace crates. The application
PR records that separate strict-gate issue and its targeted Actix security update.
Core CI passing does not establish that every host release gate passes.

## Final runtime performance run

The `run-03` evidence was collected from the runtime above on Linux x86-64,
AMD EPYC 9V74, pinned to the one permitted CPU. Both variants use the same
release executable, 100 warmups and 1,000 observations per case in alternating
AB/BA order. Both enable only production `issue` features. Shared Cargo
dependencies/features are unified in this microbenchmark; independent artifact
measurements below use separate consumer workspaces.

Times below are **thread CPU microseconds**, with nearest-rank P50/P95/P99.
Elapsed samples are retained separately. Output destruction is included; fixture
setup and file output are excluded. Allocation measurements use a separate
execution of each operation with counting disabled during timing.

| Operation | Baseline CPU P50/P95/P99 | Candidate CPU P50/P95/P99 | P50 change |
| --- | --- | --- | --- |
| DeviceResponse parse | 25.147 / 30.726 / 126.559 | 25.107 / 47.430 / 62.332 | -0.16% |
| MSO parse | 14.291 / 18.387 / 48.041 | 19.489 / 27.380 / 161.531 | +36.37% |
| Inner MSO CBOR decode | 9.194 / 10.345 / 39.719 | 16.344 / 19.129 / 48.933 | +77.77% |
| Disclosure verification | 3.686 / 4.096 / 5.779 | 3.235 / 3.505 / 6.439 | -12.24% |
| COSE Sig_structure | 0.751 / 0.932 / 1.212 | 0.751 / 0.881 / 0.981 | +0.00% |
| Issuer ES256 verification | 405.885 / 567.766 / 1,375.340 | 408.729 / 566.084 / 1,148.912 | +0.70% |
| Final holder verification | 423.050 / 676.568 / 5,578.482 | 418.343 / 613.805 / 4,031.877 | -1.11% |
| Two-attribute issuance | 134.771 / 284.884 / 7,899.370 | 573.244 / 962.173 / 10,831.759 | +325.35% |
| Full protocol verification, pending external trust | No equivalent successful legacy operation | 880.852 / 1,204.615 / 3,509.419 | Not a paired comparison |

The identical coset operation is an unchanged-code control, not evidence of a
code optimization. Shared-host scheduling/cache effects remain visible even in
thread CPU tails; one run of 1,000 samples is not a statistical service SLA.

| Operation | Baseline allocation calls / requested bytes | Candidate allocation calls / requested bytes |
| --- | ---: | ---: |
| DeviceResponse parse | 203 / 24,102 | 117 / 13,571 |
| MSO parse | 91 / 9,066 | 88 / 7,121 |
| Inner MSO CBOR decode | 53 / 4,802 | 59 / 4,528 |
| Disclosure verification | 40 / 5,077 | 6 / 564 |
| Final holder verification | 19 / 1,747 | 13 / 931 |
| Two-attribute issuance | 213 / 15,798 | 262 / 20,404 |
| Full candidate protocol verification | — | 167 / 17,913 |

Allocation bytes count successful requested capacities, including the full new
size of reallocations. They do not measure peak heap, retained bytes or copied
bytes. Parsing makes 42.36% fewer allocations and requests 43.69% fewer bytes;
full verification remains an allocating operation.

The issuance regression is real. Candidate issuance additionally validates
schema, public keys and certificate context and verifies the completed signature
against the certificate key. Baseline issuance has no equivalent post-signing
verification. The benchmark uses the same real local fixture signer; no required
check is removed to make the result faster. NazoAuth's external signer separately
checks its leased JWK, which is a different binding from the certificate key.

The old DeviceAuthentication constructor omits the required outer Tag 24, so its
construction timing is retained but excluded from equivalent-output speedup
claims. The old full verifier rejects the valid Final fixture; timing that failure
would not be a successful legacy verification baseline. NazoAuth's previous
integration already compensated for this and is measured separately in its PR.

`run-01` predates the maintained time backend; `run-02` measured `d52cfca`
before the tag-preservation correction. Both remain historical. Before the
published final runs, fixture time construction was moved outside both timed
issuance closures and logical dates were checked for equality. No timing value
was edited or manually adjusted after measurement.

## Independent structure measurements

These consumers parse the same runtime-provided Annex D bytes, with independent
lockfiles and identical release opt-level 3, thin LTO and one codegen unit.
Normal dependencies exclude the core itself, dev/build edges and inactive
targets; reachable proc macros remain included. Source lines include comments
and inline tests and are not semantic SLOC.

| Configuration | Normal packages | Rust files / lines | Release rlib bytes | Parser binary bytes |
| --- | ---: | ---: | ---: | ---: |
| Baseline issue | 96 | 24 / 5,051 | 2,446,846 | 643,160 |
| Candidate minimum | 88 | 26 / 5,227 | 2,352,786 | 659,928 |
| Candidate issue | 89 | 26 / 5,227 | 2,574,006 | 661,448 |
| Candidate all features, host | 89 | 26 / 5,227 | 2,587,236 | 661,472 |

For production `issue`, dependencies decrease 7.29%, rlib size increases 5.20%,
and the parser binary increases 2.84%. The new source has 3.48% more lines by this
definition. There is no claim that all code or artifacts became smaller.

## Reproduction and raw evidence

[benchmarks/compare](../benchmarks/compare/README.md) contains the executable,
allocator self-check, independent consumers, structure collector and CSV
summarizer. Evidence retains all 25,000 raw observations, quantiles, hashes,
Cargo artifacts, commands, build logs, audit JSON and failed/historical runs.

The final comparison executable SHA-256 is
`b091cb5e2967ec9c9940e3ce64bcc0050f5ed19f4d814eaeade5ae521c5a37b7`.
The source-manifest aggregate is
`06ef1b53c5f5bac13fbad50841c8613fa221f99c8f4056c59c34d1886e06abd1`.
The raw metadata identifies the clean `2492f361` checkout, exact rustc/LLVM,
fixture hashes, shared lockfile and binary. This run was made after our local
compiler processes exited, but the shared virtual host is not a dedicated
benchmark machine; noisy tails remain visible and are reported without trimming.
No outliers were deleted or baseline runtime sources edited. The measured full
protocol row excludes transcript creation/context binding, completed before the
timer, as well as all external trust work listed below.

Raw evidence and the full application results are supplied with the delivery
report. The core measurements do not include X.509 path trust, certificate
revocation, credential-status HTTP, application admission or endpoint latency.
