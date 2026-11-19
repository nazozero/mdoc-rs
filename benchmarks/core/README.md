# Core performance measurements

The baseline is `920b717f9916a7dda1ecacd6bacf3bde84d75495`. The candidate is the
current checkout. Each executable links one revision with the `issue` feature.
Separate executables preserve each revision's dependency features. The lockfile
records the resolved dependency graph, including separate versions where the
historical library and current checkout require different dependency types.
Historical reports retain their own pinned baselines and archived source manifests.

## Build and preflight

Run from the repository root. Keep build directories outside the checkout.

```sh
cargo build --locked --release --manifest-path benchmarks/core/Cargo.toml --no-default-features --features baseline --target-dir /tmp/mdoc-baseline
cargo build --locked --release --manifest-path benchmarks/core/Cargo.toml --no-default-features --features candidate --target-dir /tmp/mdoc-candidate
/tmp/mdoc-baseline/release/mdoc-core-benchmark --check --create-fixture --fixture /tmp/mdoc-input --out /tmp/mdoc-check-baseline
/tmp/mdoc-candidate/release/mdoc-core-benchmark --check --fixture /tmp/mdoc-input --out /tmp/mdoc-check-candidate
diff /tmp/mdoc-check-baseline/inputs.txt /tmp/mdoc-check-candidate/inputs.txt
```

The fixture uses the repository's public test keys. It contains two issuer
attributes, a Final Redirect transcript, and a holder signature. Both revisions
authenticate the same saved presentation. The ISO Annex D fixture supplies the
larger parsing, MSO, disclosure, and issuer-signature cases.

Preflight checks successful issuer/holder authentication and full protocol
verification. The two builds record hashes for the received inputs and the
deterministic MSO, Sig_structure, and DeviceAuthentication outputs. The runner
requires all hashes to agree. Full verification returns pending-trust documents;
the workload contains no application trust store, network, or database.

## Profile before editing

```sh
/tmp/mdoc-baseline/release/mdoc-core-benchmark --profile --fixture /tmp/mdoc-input --out /tmp/mdoc-profile-baseline
python3 benchmarks/core/symbolize.py /tmp/mdoc-profile-baseline
```

The allocation profiler records one successful operation per case. It stores
stacks in a fixed array and disables allocation counting during unwinding. The
output includes raw ELF offsets, complete symbolized stacks, and call-site
summaries. `addr2line` expands inlined frames from the release binary's debug
information. Retain that executable until symbolization finishes. A relocated
copy can be passed with `symbolize.py DIRECTORY --executable PATH`; its hash must
match the recorded binary. Tracing records allocations separately from timing.

`--case NAME` selects an operation. `--iterations N` repeats it under an external
CPU profiler; the first operation also records allocation stacks. Preparation
outside the named operation still appears in an external whole-process profile.

## Measure

Commit the candidate, rebuild both binaries, finish other compiler/test work,
then freeze source until measurement completes.

```sh
python3 benchmarks/core/run.py --baseline /tmp/mdoc-baseline/release/mdoc-core-benchmark --candidate /tmp/mdoc-candidate/release/mdoc-core-benchmark --fixture /tmp/mdoc-input --out /tmp/mdoc-results --rounds 4 --samples 1000 --warmup 100
python3 benchmarks/core/run.py --baseline /tmp/mdoc-baseline/release/mdoc-core-benchmark --candidate /tmp/mdoc-baseline/release/mdoc-core-benchmark --unchanged-control --fixture /tmp/mdoc-input --out /tmp/mdoc-control --rounds 2 --samples 1000 --warmup 100
```

Each process pins its only thread to the first allowed CPU, or to `--cpu N`.
Odd rounds run baseline then candidate; even rounds reverse that order. The
unchanged control executes the identical binary under both labels. Each process
warms every case independently. No samples or tails are removed.

Each observation has two separate invocations: elapsed/thread CPU timing, then
allocation counting. Allocator counters stay disabled in the timing pass.
Returned output destruction is included. Input preparation for consuming APIs
is excluded from both passes. For `issuance_finish`, preparation and external
signing happen before the measured call. `issuance_complete` includes the
builder, OS entropy, preparation, signing, and signature confirmation.

`external_es256_sign_control` signs a fixed Sig_structure. The complete issuance
case generates fresh salts and digest IDs normally. Issuance samples therefore
compare the same logical claims and validation rules with fresh wire bytes.

### Compare owned and borrowed APIs in the same executable

Both builds include three cases that return models borrowing the
input. Use the candidate executable for both runner labels and select the
operations with `--baseline-case` and `--candidate-case`. This compares the two
API contracts under the same library revision, dependency versions, compiler
and executable, separately from a comparison with the historical revision.

| Owned case (`--baseline-case`) | Borrowed case (`--candidate-case`) | Input and measured scope |
| --- | --- | --- |
| `response_parse` | `response_parse_borrowed` | Complete Annex D DeviceResponse parsing |
| `mso_parse` | `mso_parse_borrowed` | Complete Tag 24 MSO payload validation and schema parsing |
| `full_protocol_verify` | `full_protocol_verify_borrowed` | Parsing and issuer/holder authentication of the saved Final presentation |

For example, compare the two DeviceResponse parsing APIs:

```sh
python3 benchmarks/core/run.py \
  --baseline /tmp/mdoc-candidate/release/mdoc-core-benchmark \
  --candidate /tmp/mdoc-candidate/release/mdoc-core-benchmark \
  --baseline-case response_parse \
  --candidate-case response_parse_borrowed \
  --fixture /tmp/mdoc-input --out /tmp/mdoc-borrowed-parse \
  --rounds 4 --samples 1000 --warmup 100
```

Use the other case pairs with separate output directories. Both case options
are required together and cannot be combined with `--case`. These runs compare
different operations, so `--unchanged-control` does not apply; that option
requires the same operation as well as the same executable. The `baseline` and
`candidate` output labels identify the owned and borrowed operations in this
experiment; both metadata files identify the candidate build.

All three pairs start from the same prepared input buffers. No parsed borrowed
model is prepared outside the measured operation. The standalone MSO cases
borrow the same payload buffer extracted during fixture setup; they exclude
DeviceResponse parsing and both validate the complete payload on each call.
The full verification cases start from the saved response bytes and include
parsing and authentication on every invocation. Input loading, fixture setup
and preflight are outside timing and allocation counting. Result destruction
is included for both API contracts. Borrowed models still allocate collection
metadata; allocation measurements do not imply that an operation copies no
bytes or allocates nothing.

### Optional certificate profile comparison

The current baseline is the main revision before the 0.4 protocol-boundary
change. Both revisions expose borrowed verification and the same SPKI types.
Build the candidate with `--features certificate-profile` to measure automatic
Annex B validation, or `--features candidate` for the empty-default core.
Copy each executable before building the next feature set in a shared target
directory. Metadata distinguishes `candidate-profile` from `candidate`.

The profile build performs additional required work, including strict DER plus
borrowed certificate views. Compare it separately from the default build; a
baseline without profiles is not an equivalent security workload. The workload
returns pending-trust evidence and does not measure a host X.509 path engine.

### Recorded outputs

The outputs are:

- `runs.json`: command, execution order, exit status, and binary hash for every run.
- `round-NN/VARIANT/samples.csv`: every observation in its original order.
- `summary.csv`: each run's nearest-rank P50/P95/P99 and means; rounds stay separate.
- `inputs.txt`: exact input and deterministic-output hashes.
- `transcript.cbor`: the public transcript used by the verification consumer.
- `metadata.txt` and `build-source-manifest.txt`: toolchain, revision, build-time
  source hashes, flags, binary identity, affinity, and measurement definitions.
- `execution.log`: successful and failed process output. A failed run is retained
  and stops the runner.

Requested bytes count successful allocation requests, including the full new
capacity of each reallocation. They describe allocator traffic. Executable
sizes include fixtures, instrumentation, and all benchmark cases; measure a
separate minimal consumer when reporting library size.

The [borrowed APIs and dependency upgrade report](../../docs/borrowed-dependencies-2026-11-18.md)
documents the current 2026-11-18 round. The earlier
[performance report](../../docs/performance-2026-11-18-final.md) retains the
historical revisions, per-round quantiles and archived raw evidence for that
measurement round.

## Cases

| Case | Measured operation |
| --- | --- |
| `measurement_control` | Clock and harness floor |
| `response_parse` | Annex D DeviceResponse parsing into owned models |
| `response_parse_borrowed` | Annex D parsing with borrowed values |
| `mso_parse` | Tag 24 MSO decoding and owned model construction |
| `mso_parse_borrowed` | Tag 24 MSO validation and borrowed model construction |
| `mso_decode` | Bounded inner MSO decoding with preserved tags |
| `canonical_mso_encode` | Deterministic MSO encoding |
| `disclosure_verify` | Issuer item digests and disclosure checks |
| `coset_sig_structure_control` | Unchanged coset Sig_structure constructor |
| `certificate_decode` | Leaf DER decoding |
| `certificate_key_convert` | SPKI to COSE key conversion |
| `issuer_es256_verify` | Issuer key checks and signature verification |
| `holder_es256_verify` | Holder authentication |
| `issuance_prepare` | Two-attribute issuance preparation |
| `external_es256_sign_control` | Existing RustCrypto signing implementation |
| `issuance_finish` | External signature confirmation and document completion |
| `issuance_complete` | Complete two-attribute issuance |
| `issuer_signed_encode` | IssuerSigned wire encoding |
| `full_protocol_verify` | Final presentation authentication returning owned evidence |
| `full_protocol_verify_borrowed` | Final presentation authentication returning borrowed evidence |
| `redirect_transcript_validate` | Borrowed transcript/request binding |
