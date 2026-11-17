# Validation record: 2026-11-17–18

This record applies to runtime `d2f653d262da4c783ca6c430ef1f056f40baa25f`.
It replaces the historical `2492f361` checkpoint previously recorded at this
path. The raw evidence for earlier revisions remains separate and unchanged.
This is implementation evidence, not an ISO/OpenID certification. The selected
profile, unavailable licensed text and unsupported capabilities are described in
[protocol-matrix.md](protocol-matrix.md).

## Source identities

| Object | Exact identity |
| --- | --- |
| Production baseline | `9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`, `mdoc-rs 0.2.0`, no default features, `issue` |
| Candidate runtime | `d2f653d262da4c783ca6c430ef1f056f40baa25f`, `nazo-mdoc 0.3.0` |
| Candidate tree | `e04bdf111f1a849ed11082548207cb63987eb25d` |
| CI merge commit | `051adc3f791a1e063511231be0a116267f7d2b3e`; its tree exactly equals the candidate tree |
| NazoAuth integration base | `9560ea04bbc01a2da7b002eeeeb0ebe2e7dffbe9` |
| Core review | [mdoc-rs PR 2](https://github.com/nazozero/mdoc-rs/pull/2) |
| Application review | [NazoAuth PR 286](https://github.com/nazozero/NazoAuth/pull/286) |
| Toolchain | Rust 1.100.0, `0ef1bc386059596dada8fb65b50425aab2ea637a`, LLVM 23.1.5 |

Application dependencies pin a runtime revision. Later documentation-only
commits do not require an artificial production dependency update.

## Executed core gates

The [runtime CI run](https://github.com/nazozero/mdoc-rs/actions/runs/44124404106)
completed all four jobs successfully: Rust, targets, fuzz and advisories.

- Formatting, minimum/issue checks, all-target Clippy with warnings denied and
  rustdoc with warnings denied passed.
- No-default-features executed **131 tests**, `issue` executed **188**, and
  all-features executed **193**, with zero failures and zero ignored tests in
  each configuration. These configurations overlap; their counts are not added.
- Explicit native builds succeeded for minimum and all features. Actual library
  builds also succeeded for `wasm32-unknown-unknown` minimum and `issue,wasm-js`,
  and `wasm32-wasip2` issue. These are artifact builds, not browser/WASM-runtime
  execution tests. The application records its own actual WASM test executions.
- The seeded CI fuzz campaign completed **445,893 runs in 121 seconds**, starting
  with five seeds, with successful process exit and ASan/LSan enabled. It reaches
  bounded CBOR, COSE, MSO, issued/presentation verification, Timestamp and
  FullDate. This finite campaign does not establish exhaustive input coverage.
- Property tests cover malformed bytes without panic, duplicate keys, status
  presence/unknown mechanisms/index bounds, and Final transcript binding.
- ISO Annex D, the Final Redirect/DC API examples, RFC 6979 P-384 and RFC 8032
  Ed25519 vectors have recorded provenance. MAC/HKDF fixtures are independent
  synthetic vectors, not mislabelled as official test vectors.

The production baseline executed 49 issue-feature and 63 all-feature tests.
Some inherited ISO test files were gated by TSP and executed no tests in the
production configuration; a file's existence is not execution evidence.

### Regressions demonstrated before and after the corrections

The same eleven wire-type regressions fail on the exact `d52cfca` checkpoint
and pass in the current suite. CBOR Tag 2/3 is preserved through protocol
projection; undefined is rejected instead of becoming null; canonical issuance
rejects nonpreferred bignum inputs. Some negative cases use independently valid
signatures/MACs over invalid COSE header types. RFC 8949 allows extended numeric
equivalence: this correction enforces the application's native-wire-type and
extension-preservation contract, rather than alleging that a general-purpose
CBOR decoder violates RFC 8949.

Six additional tests were compiled and executed against the preceding `e9309b7d`
checkpoint. All six failed actual assertions and pass on this runtime:

- Unknown numeric minor MSO versions are accepted and preserved.
- Unknown minor DeviceResponse versions reach authentication.
- Compatible minor versions retain both issuer and holder authentication.
- Positive RFU keyInfo is preserved without creating device authorization.
- A present device namespace cannot contain an empty DeviceSignedItems map.
- External holder preparation rejects the same invalid empty namespace.

ISO 18013-5 §§8.1 and 9.1.2.4 require the minor-version and positive-RFU behavior;
§8.3.2.1.2.2 defines the device namespace cardinality. Unknown security semantics
outside those designated RFU labels remain subject to explicit profile support.
The supported CBOR data model still limits retained extension values; this is
not a claim to accept every possible CBOR value.

An earlier local fuzz invocation completed its mutation phase but failed at
LeakSanitizer teardown in the restricted process environment. It remains a
failed invocation. A later local ASan run explicitly disabled leak detection;
the GitHub campaign above does not depend on that local exception. Earlier
campaigns are retained under their own revisions, not added to this run.

## Advisory snapshot and maintenance scope

The runtime CI audited 142 packages against 1,527 advisories and passed
`cargo audit --deny warnings`. Independent local scans used the clean RustSec
snapshot `233155b4025b854c68a4b199c0e32d7fd53291a2`: the candidate root lockfile has
**zero vulnerabilities and zero warnings**; the candidate consumer and fuzz
lockfiles also pass. The ownership/cardinality follow-up changes no dependencies.

The Chrono maintenance advisory
[RUSTSEC-2026-0543](https://github.com/rustsec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md)
was published during this work. The core and its tests were migrated to maintained
`time`, with explicit, tested leap-second and precision handling. This is a
maintenance advisory, not a newly demonstrated memory-safety exploit. Earlier
clean scans against 1,509 advisories are historical results only.

The comparison and baseline consumers intentionally keep the real baseline's
Chrono dependency. Their strict audits report that warning and fail; it is not
suppressed and the baseline source is not changed. The old complete library
lockfile also has 15 vulnerability advisories in optional components removed
from the core. None of those 15 is in the baseline production `issue` normal
dependency graph; they are not 15 demonstrated reachable production flaws.

NazoAuth still uses Chrono in unrelated application APIs, persistence models and
workspace crates. Its application PR records that strict-gate issue and a
separate targeted Actix security update. Core CI success does not establish
that every host release gate passes.

## Recorded runtime performance: run-04

Both variants were measured on Linux x86-64, AMD EPYC 9V74, in one release
executable pinned to permitted CPU 0. Each case uses 100 warmups and 1,000
observations in alternating AB/BA order. Both enable only production `issue`
features. Cargo dependencies/features are unified in this microbenchmark;
independent artifact measurements below use separate consumers and lockfiles.

Times below are **thread CPU microseconds**, with nearest-rank P50/P95/P99.
Elapsed samples are retained separately. Output destruction is included;
fixture setup and file output are excluded. Allocation measurements use a
separate invocation with counters disabled during timing.

| Operation | Baseline CPU P50/P95/P99 | Candidate CPU P50/P95/P99 |
| --- | --- | --- |
| DeviceResponse parse | 23.134 / 156.373 / 576.879 | 21.031 / 130.835 / 416.801 |
| MSO parse | 12.589 / 69.474 / 153.158 | 15.192 / 76.925 / 178.025 |
| Inner MSO CBOR decode | 8.142 / 11.998 / 101.111 | 13.831 / 36.685 / 117.615 |
| Disclosure verification | 3.004 / 4.276 / 60.931 | 2.724 / 3.535 / 39.229 |
| COSE Sig_structure | 0.561 / 0.731 / 1.232 | 0.561 / 0.671 / 1.091 |
| Issuer ES256 verification | 413.877 / 975.804 / 1,890.127 | 432.655 / 990.782 / 2,415.088 |
| Final holder verification | 407.297 / 733.593 / 1,273.738 | 407.257 / 762.917 / 1,290.503 |
| Two-attribute issuance | 112.868 / 316.151 / 521.677 | 573.976 / 1,012.723 / 1,610.489 |
| Full protocol verification, pending external trust | No equivalent successful legacy operation | 859.240 / 1,561.396 / 2,512.694 |
| Final Redirect transcript validation/borrow | No equivalent baseline API | 0.430 / 0.461 / 0.560 |
| Final DC API transcript validation/borrow | No equivalent baseline API | 0.391 / 0.501 / 0.661 |

The identical coset operation is an unchanged-code control. Shared-host cache
and scheduling effects remain visible even in thread CPU tails; one run of
1,000 samples per case is not a statistical service SLA. No outliers were removed.

| Operation | Baseline allocation calls / requested bytes | Candidate allocation calls / requested bytes |
| --- | ---: | ---: |
| DeviceResponse parse | 203 / 24,102 | 105 / 13,114 |
| MSO parse | 91 / 9,066 | 64 / 6,196 |
| Inner MSO CBOR decode | 53 / 4,802 | 59 / 4,528 |
| Disclosure verification | 40 / 5,077 | 6 / 564 |
| Final holder verification | 19 / 1,747 | 13 / 931 |
| Two-attribute issuance | 213 / 15,798 | 254 / 19,979 |
| Full candidate protocol verification | — | 155 / 17,338 |
| Leaf-certificate access | 1 / 466 | 0 / 0 |
| Final Redirect transcript validation/borrow | — | 0 / 0 |
| Final DC API transcript validation/borrow | — | 0 / 0 |

Allocation bytes count successful requested capacities, including the full new
size of reallocations; they are not peak heap, retained bytes or copied bytes.
DeviceResponse parsing makes 48.28% fewer allocations and requests 45.59% fewer
bytes. MSO parsing makes 29.67% fewer allocations and requests 31.66% fewer bytes.
The two transcript validators retain pointer identity and recorded zero
allocation calls/bytes in all 1,000 samples each. That narrow zero-copy/zero-
allocation result does not describe the complete parser or verifier.

MSO projection now consumes owned intermediate values; uniqueness checks borrow
local strings/byte slices. One public DeviceResponse model replaces redundant
response/request placeholders. No extra public lifetime or unsafe access path
was introduced to obtain these reductions. Authenticated raw bytes remain intact.

Issuance's approximately **5.09x** median CPU cost is a real regression. Candidate
issuance additionally validates schema, key and certificate context and confirms
the completed signature against the leaf certificate key. The same real local
fixture signer is used for both variants. NazoAuth's external signer checks its
leased JWK, a different binding from the certificate key. Required checks were
not removed to improve timing. Successful old API returns do not establish that
old random digest IDs always satisfy ISO's range; see [migration.md](migration.md).

The old DeviceAuthentication constructor omits the required outer Tag 24; its
construction timing is retained but excluded from equivalent-output speedup
claims. The old full verifier rejects the valid Final fixture; timing that
failure would not measure successful verification. NazoAuth's previous adapter
already compensated for this and is measured separately in its integration PR.

## Independent structure measurements

These consumers parse the same runtime-provided Annex D bytes, using separate
lockfiles and identical release opt-level 3, thin LTO and one codegen unit.
Normal dependencies exclude the core itself, dev/build edges and inactive
targets; reachable proc macros remain included. Source lines include comments
and inline tests and are not semantic SLOC.

| Configuration | Normal packages | Rust files / lines | Release rlib bytes | Parser binary bytes |
| --- | ---: | ---: | ---: | ---: |
| Baseline issue | 96 | 24 / 5,051 | 2,446,846 | 643,160 |
| Candidate minimum | 88 | 25 / 5,228 | 2,322,692 | 655,552 |
| Candidate issue | 89 | 25 / 5,228 | 2,557,204 | 656,736 |
| Candidate all features, host | 89 | 25 / 5,228 | 2,570,430 | 656,760 |

For production `issue`, dependencies decrease 7.29%, rlib size increases 4.51%,
and the parser binary increases 2.11%. Source has 3.50% more lines by this
definition. There is no claim that all code or artifacts became smaller.

## Reproduction and raw evidence

[benchmarks/compare](../benchmarks/compare/README.md) contains the executable,
allocator self-check, independent consumers, collector and CSV summarizer.
Evidence retains all **27,000 raw observations**, quantiles, hashes, actual
public CBOR inputs, Cargo artifacts, commands, build logs, audit JSON and failed
or historical runs. An independent replay of the summarizer and source/input
hash checks matched the recorded results.

| Recorded object | SHA-256 |
| --- | --- |
| Comparison executable | `41111b0cad409a75508bebb067b746a321adf3efe73430b3ad45a44483733a98` |
| Source-manifest aggregate | `bde83a8c8a27560bab1cc2fd7941bf7d46079cf5478677e1ab245796669b6c34` |
| Annex D input, 3,529 bytes | `3908aabd02e0605e7549913f5f14a8bb24155325584d5097a5ad7161e8549919` |
| Synthetic Final response, 1,353 bytes | `559c35ebd5260f08ba6b63e507f93da4a021657efaaa7d58f93da75b70661a69` |

The executable was built before publication and its complete 32-file source
manifest was independently matched to the published runtime's exact bytes.
Our local compilers and large I/O operations were paused for sampling; the
shared virtual host was not a dedicated physical benchmark machine.

`run-01` predates the maintained time backend; `run-02` measured `d52cfca` before
tag preservation; `run-03` measured `2492f361` before the minor-version/RFU/
namespace and ownership follow-up. Their raw evidence remains historical.
No timing value was edited and no baseline runtime source was modified.

The full protocol row excludes transcript creation/context binding completed
before the timer, X.509 path trust, certificate revocation, credential-status
HTTP, final application admission and endpoint latency. Those are separately
reported application responsibilities, not missing costs hidden inside this row.
