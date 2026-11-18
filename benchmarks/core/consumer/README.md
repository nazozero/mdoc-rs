# Linked parser and verifier consumer

This independent workspace builds the same executable against either the
baseline revision `070e9cf727a31a8ee23ffd372d7dc9e378cbfdfc` or the current
checkout. Enable exactly one of `baseline` and `candidate`. Both library
variants use an empty default feature set. The consumer has no additional
dependencies, embedded credentials or benchmark instrumentation.

## Build

Run from the repository root, using separate target directories:

```sh
cargo build --locked --release --manifest-path benchmarks/core/consumer/Cargo.toml --no-default-features --features baseline --target-dir /tmp/mdoc-size-baseline
cargo build --locked --release --manifest-path benchmarks/core/consumer/Cargo.toml --no-default-features --features candidate --target-dir /tmp/mdoc-size-candidate
```

For executable WASM artifacts, repeat both commands with
`--target wasm32-wasip2`. Release builds use opt-level 3, thin LTO and one codegen
unit, with the same panic and debug defaults. Keep target, toolchain and flags
identical within each comparison.

## Run

All inputs come from runtime files and arguments:

```sh
mdoc-core-consumer parse RESPONSE_CBOR
mdoc-core-consumer verify RESPONSE_CBOR TRANSCRIPT_CBOR 2026-11-17T12:00:00Z 1
```

`parse` decodes a DeviceResponse and prints its document count. `verify`
structurally validates the supplied transcript, runs issuer/holder protocol
authentication at the explicit time, and prints the pending-trust document
count. Use the same response, transcript, time and document limit for both builds.
The caller provides a transcript bound to its request and completes application
trust and status policy.

The WASI executable uses the same CLI and requires the runtime to grant access
to the input files. Record whether a WASM artifact was built or also executed.

## Size definitions

The native executable and WASM component include the CLI, parser and full
protocol verifier with their reachable dependencies. Cargo's `nazo-mdoc` rlib
artifact includes compiled library code, IR and metadata. Report each artifact
separately, with its exact byte size, SHA-256, target, feature set and source
revision. These figures represent the linked verification workload; issuance is
disabled in this consumer.
