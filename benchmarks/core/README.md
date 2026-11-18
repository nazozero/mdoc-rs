# Core performance measurements

The baseline is `070e9cf727a31a8ee23ffd372d7dc9e378cbfdfc`. The candidate is the
current checkout. Each executable links one revision with the `issue` feature.
Separate executables preserve each revision's dependency features. The lockfile
pins the baseline's dependency versions for both builds.

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
summaries. `addr2line` resolves the release binary's debug information. Retain
that executable until symbolization finishes. Tracing has no timing claims.

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

The outputs are:

- `runs.json`: command, execution order, exit status, and binary hash for every run.
- `round-NN/VARIANT/samples.csv`: every observation in its original order.
- `summary.csv`: each run's nearest-rank P50/P95/P99 and means; rounds stay separate.
- `inputs.txt`: exact input and deterministic-output hashes.
- `metadata.txt` and `build-source-manifest.txt`: toolchain, revision, build-time
  source hashes, flags, binary identity, affinity, and measurement definitions.
- `execution.log`: successful and failed process output. A failed run is retained
  and stops the runner.

Requested bytes count successful allocation requests, including the full new
capacity of each reallocation. They describe allocator traffic. Executable
sizes include fixtures, instrumentation, and all benchmark cases; measure a
separate minimal consumer when reporting library size.

## Cases

| Case | Measured operation |
| --- | --- |
| `measurement_control` | Clock and harness floor |
| `response_parse` | Annex D DeviceResponse parsing |
| `mso_parse` | Tag 24 MSO decoding and model construction |
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
| `full_protocol_verify` | Final presentation authentication |
| `redirect_transcript_validate` | Borrowed transcript/request binding |
