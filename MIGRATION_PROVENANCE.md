# NazoAuth coset 0.4 migration provenance

This branch is maintained for NazoAuth and is not an upstream `mdoc-rs`
release. Its parent is the controlled crates.io baseline tagged
`upstream-crates-io-v0.2.0`.

## Migration input

- Dependency: `coset 0.4.2`
- crates.io archive SHA-256/checksum:
  `1eb98d5e9155e2cf7cd942c8b3033097d4563b6fb0a00b9caecb74669555c058`
- Upstream repository: `https://github.com/google/coset`
- Declared MSRV: Rust `1.81`

## Changes from the baseline

- Require `coset = "0.4.2"` and raise the declared MSRV from Rust 1.75 to
  Rust 1.81 in both manifests and the README.
- Validate the COSE critical-header contract before issuer-signature,
  device-signature, and device-MAC verification. Only a present protected
  `alg` header is currently understood; all other critical labels fail closed.
- Require device MACs to declare protected `HMAC_256_256`; missing, wrong, and
  private-use algorithms fail closed.
- Add regressions for supported and rejected critical headers and for valid,
  missing, wrong, and private-use device-MAC algorithms.

## Proof boundary

The isolated migration proof of concept completed these checks before this
source branch was published:

- `cargo check --locked --jobs 1`: exit 0
- `cargo test --locked --jobs 1 -- --test-threads=1`: exit 0, 56 passed
- `cargo fmt --check`: exit 0
- `cargo tree --locked -i coset@0.4.2`: exit 0, one coset 0.4.2 instance

`cargo audit` reported `RUSTSEC-2023-0071` through the proof-of-concept lockfile;
that advisory has no patched `rsa` release. This record does not waive or hide
the advisory. Consumer acceptance requires exact-commit resolution and full
NazoAuth validation on the Hostinger build environment.

## Maintained protocol core

`nazo-mdoc 0.3.0` continues from the exact production revision
`9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`. The bounded wire decoder, pending-trust
verification pipeline and external-signature preparation replace the former
lenient Value parser, assessment aggregator and private-key response builder.
MSO/status and COSE primitives retain and strengthen inherited behavior; original
licenses, authorship records and independent fixture provenance remain intact.
The package rename is accompanied by this architectural change and a separate
NazoAuth migration. It is not a claim of a clean-room implementation or inherited
certification. See `docs/migration.md` and `docs/protocol-matrix.md`.
