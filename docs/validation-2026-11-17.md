# Validation record: 2026-11-17–18

Historical results for runtime `d2f653d262da4c783ca6c430ef1f056f40baa25f`.
This record preserves the source identities and measured results preceding
issue #4. The [protocol matrix](protocol-matrix.md) describes the covered API.

## Source identities

| Object | Exact identity |
| --- | --- |
| Baseline | `9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`, `mdoc-rs 0.2.0`, no default features, `issue` |
| Candidate runtime | `d2f653d262da4c783ca6c430ef1f056f40baa25f`, `nazo-mdoc 0.3.0` |
| Candidate tree | `e04bdf111f1a849ed11082548207cb63987eb25d` |
| CI merge commit | `051adc3f791a1e063511231be0a116267f7d2b3e`, with the same tree |
| Review | [PR #2](https://github.com/nazozero/mdoc-rs/pull/2) |
| Toolchain | Rust 1.100.0, `0ef1bc386059596dada8fb65b50425aab2ea637a`, LLVM 23.1.5 |

## Executed core gates

The [runtime CI run](https://github.com/nazozero/mdoc-rs/actions/runs/44124404106)
passed all four jobs: Rust, targets, fuzz and advisories.

- Formatting, minimum/issue checks, all-target Clippy and rustdoc passed with
  warnings denied.
- No-default-features ran **131 tests**, `issue` ran **188**, and all-features ran
  **193**, each with zero failures or ignored tests.
- Native minimum/all-feature builds and WASM builds passed:
  `wasm32-unknown-unknown` minimum and `issue,wasm-js`; `wasm32-wasip2` issue.
  These checks built artifacts; they did not execute a WASM runtime.
- The seeded CI fuzz campaign completed **445,893 runs in 121 seconds**, starting
  with five seeds, with ASan/LSan enabled. It covered CBOR, COSE, MSO, issued and
  presentation verification, Timestamp and FullDate.
- Property tests covered malformed bytes, duplicate keys, status preservation,
  index bounds and Final transcript binding. Fixed vectors covered ISO Annex D,
  official Final handovers, RFC 6979 P-384 and RFC 8032 Ed25519. Independent
  synthetic vectors covered MAC/HKDF.

The baseline ran 49 issue-feature and 63 all-feature tests. Its TSP-gated ISO
tests were inactive under the issue-only configuration.

Eleven wire-type regressions failed on `d52cfca` and passed on this runtime:
Tag 2/3 preservation, rejection of undefined, native integer fields and preferred
bignum issuance. Six further regressions failed on `e9309b7d` and passed here:
minor-version compatibility in MSO and DeviceResponse, authenticated minor
versions, positive RFU keyInfo preservation and device namespace cardinality on
both receive and holder-preparation paths.

An earlier local fuzz invocation failed at LeakSanitizer teardown. A subsequent
local ASan run disabled leak detection; the successful CI campaign above used
both ASan and LSan. Earlier results remain attached to their own revisions.

## Advisory snapshot

CI audited 142 packages against 1,527 advisories and passed
`cargo audit --deny warnings`. Independent scans against RustSec revision
`233155b4025b854c68a4b199c0e32d7fd53291a2` found zero vulnerabilities and warnings
in the root, candidate consumer and fuzz lockfiles.

The core and tests migrated to `time` after the Chrono maintenance advisory
[RUSTSEC-2026-0543](https://github.com/rustsec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md).
The historical comparison and baseline consumer retain Chrono; their strict
audits report the warning and fail. The old complete lockfile also contains 15
vulnerability advisories in optional components, all outside its issue-only
normal dependency graph.

## Recorded runtime performance: run-04

Linux x86-64, AMD EPYC 9V74, one release executable pinned to permitted CPU 0.
Each case used 100 warmups and 1,000 observations in alternating AB/BA order,
with `issue` features. Shared Cargo dependencies/features were unified.

The table records **thread CPU microseconds** at nearest-rank P50/P95/P99.
Elapsed samples were recorded separately. Timing includes result destruction
and excludes fixture setup and file output. Allocations were measured in a
separate invocation, with counters disabled during timing.

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


The identical coset operation serves as an unchanged-code control. Sampling ran
on a shared virtual host after local compilation and large I/O were paused.
All observations were retained, including scheduling and cache variability.

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


Requested bytes count successful allocation capacities, including each full
reallocation size. DeviceResponse parsing reduced allocation calls by 48.28%
and requested bytes by 45.59%; MSO parsing reduced them by 29.67% and 31.66%.
The two borrowed transcript validators preserved pointer identity and recorded
zero allocations in each sample.

Issuance increased median CPU cost by **5.09×**. Added work includes schema,
key/certificate validation and signature confirmation against the certificate
key. MSO parsing and inner CBOR decoding also increased CPU time. These costs
are the starting point for [issue #4](https://github.com/nazozero/mdoc-rs/issues/4).

Two legacy operations have different contracts: the old DeviceAuthentication
constructor omits outer Tag 24, and the old full verifier rejects the valid
Final fixture. Their timings remain distinct from successful equivalent-output
comparisons. The full protocol row returns pending external trust and excludes
transcript construction, X.509 path validation, revocation, status fetching and
application admission.

## Independent structure measurements

Separate consumers parsed the same runtime-provided Annex D bytes, with
independent lockfiles and release opt-level 3, thin LTO and one codegen unit.
Normal package counts exclude the core, dev/build edges and inactive targets;
reachable proc macros are included. Rust line counts include comments and tests.
Rlib bytes include code, IR and metadata; parser binaries represent that linked
use case.

| Configuration | Normal packages | Rust files / lines | Release rlib bytes | Parser binary bytes |
| --- | ---: | ---: | ---: | ---: |
| Baseline issue | 96 | 24 / 5,051 | 2,446,846 | 643,160 |
| Candidate minimum | 88 | 25 / 5,228 | 2,322,692 | 655,552 |
| Candidate issue | 89 | 25 / 5,228 | 2,557,204 | 656,736 |
| Candidate all features, host | 89 | 25 / 5,228 | 2,570,430 | 656,760 |


For `issue`, normal packages decreased 7.29%, rlib bytes increased 4.51%,
parser binary bytes increased 2.11%, and counted source lines increased 3.50%.

## Reproduction and evidence

[benchmarks/compare](../benchmarks/compare/README.md) contains the harness,
allocator self-check, independent consumers, collector and summarizer. Recorded
evidence includes 27,000 observations, quantiles, public inputs, hashes, Cargo
artifacts, build logs, audit JSON and failed/historical runs. The recorded
summarizer replay and source/input hash checks matched.

| Recorded object | SHA-256 |
| --- | --- |
| Comparison executable | `41111b0cad409a75508bebb067b746a321adf3efe73430b3ad45a44483733a98` |
| Source-manifest aggregate | `bde83a8c8a27560bab1cc2fd7941bf7d46079cf5478677e1ab245796669b6c34` |
| Annex D input, 3,529 bytes | `3908aabd02e0605e7549913f5f14a8bb24155325584d5097a5ad7161e8549919` |
| Synthetic Final response, 1,353 bytes | `559c35ebd5260f08ba6b63e507f93da4a021657efaaa7d58f93da75b70661a69` |


The executable's 32-file source manifest matched the published runtime.
`run-01` preceded the time backend, `run-02` used `d52cfca` before tag
preservation, and `run-03` used `2492f361` before the version, RFU, namespace and
ownership corrections.

The original record is preserved in
[Git history](https://github.com/nazozero/mdoc-rs/blob/209093017917eb389b37b1e54a542b201c1c5467/docs/validation-2026-11-17.md).
