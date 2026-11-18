# Review of the 0.2 baseline

Baseline: `9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`, `mdoc-rs 0.2.0`.
The 0.3 refactor retained its coset 0.4 migration, RustCrypto implementations,
borrowed transcript support and COSE security checks.

## Changes carried into 0.3

| Area | Baseline behavior | Current contract |
| --- | --- | --- |
| OpenID handover | Historical draft layout | Final Redirect and DC API handovers |
| DeviceAuthentication | Missing outer Tag 24 | Complete DeviceAuthenticationBytes, checked against independent encoding |
| Device namespaces | Decoding/re-encoding could change authenticated bytes | Preserve complete received DeviceNameSpacesBytes |
| Item digests | Envelope reconstructed from inner bytes | Hash received IssuerSignedItemBytes |
| Digest IDs | Full `u32` range | Generate and accept IDs below `2^31` |
| CBOR parser | Permissive Value-tree lookups | Bounded decoding, duplicate rejection and explicit field/extension rules |
| COSE headers | Existing critical-header checks | Retain checks; validate original bytes, native types and bucket rules |
| COSE keys | Loose algorithm/key interpretation | Bind algorithm, key type, curve and operations; require public points |
| ECDSA and Ed25519 | Raw ECDSA checks; ordinary Ed25519 verification | Fixed-width ECDSA and strict Ed25519 verification |
| Device payload | Embedded payload accepted | Detached holder authentication |
| MAC derivation | Transcript hash lacked complete wrapper | HKDF salt hashes Tag 24 SessionTranscriptBytes |
| DeviceKeyInfo | Optional model and permissive authorizations | Required key information, disjoint authorization forms and retained extensions |
| MSO dates | Tag 1 accepted; normalization could hide reversed input | Tag 0 UTC whole seconds; ordering checked before and after normalization |
| Signer time | Part of the former verifier | Explicit signed-time containment, including leap-second boundaries |
| Status | Existing extension preservation | Preserve absent, known and unknown values through authentication |
| Trust | Library trust store and assessment overrides | Protocol authentication result followed by application trust policy |
| Signing | Synchronous signer interface and private-key response builder | External prepare/sign/finish |
| Attribute types | Date inference from field names | Caller-supplied typed CBOR |
| Tests | Some ISO tests gated by TSP | Protocol tests run in minimum and issuance configurations |
| Dependencies | Optional TSP, HTTP and PKCS11 components | Protocol-library dependency graph |

Regression evidence includes ISO Annex D, official Final handover examples,
independent signature/MAC vectors, byte mutations and malformed-input properties.
The [protocol matrix](protocol-matrix.md) maps current contracts to tests.

Existing credentials with out-of-range digest IDs require reissuance; see
[migration](migration.md). Historical benchmark workloads with different output
contracts are identified in the [comparison method](../benchmarks/compare/README.md).
The [validation record](validation-2026-11-17.md) retains the measured baseline
and 0.3 results. The original review remains in
[Git history](https://github.com/nazozero/mdoc-rs/blob/209093017917eb389b37b1e54a542b201c1c5467/docs/production-baseline-review.md).
