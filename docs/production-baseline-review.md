# Review of the deployed baseline

Scope: complete source and test tree, manifest/lockfile, all available repository
history and the diff to `main`, plus the NazoAuth signing/verification/status and
OpenID4VP call paths. The input is production commit
`9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`, not crates.io 0.2.0.
NazoAuth integration starts from main
`9560ea04bbc01a2da7b002eeeeb0ebe2e7dffbe9` in a separate checkout/branch.

The source import and original BSD-2-Clause authorship remain recorded in
`UPSTREAM_PROVENANCE.md`, `UPSTREAM_FILES.sha256`, `LICENSE` and Git history.
The production branch's coset 0.4, RustCrypto, borrowed transcript and COSE
security repairs are requirements for this continuation, not changes to discard
when choosing a cleaner upstream starting point.

## Findings and disposition

| Area | Baseline behavior / risk | New contract and evidence location |
| --- | --- | --- |
| Dependency baseline | Main and crates.io are not the deployed security-patched source. | Branch begins at the exact production SHA; benchmark dependency pins that SHA. |
| OpenID handover | Library's typed OID4VP variant models a historical draft, while NazoAuth separately builds Final handovers. | Final Redirect/DC API contexts in `session`; official examples and context/byte mutation tests. |
| DeviceAuthentication | Historical helper's constructed signature input did not have the correct complete outer Tag 24 contract; self-generated tests could agree with the same mistake. | Independent encoding tests and Final holder-signature interop; old/new whole verification is not represented as an equivalent workload. |
| Raw transcript | Production borrowed raw path is valuable but raw syntax/context were not separately represented. | Bounded `SessionTranscript`, binding state, borrowed Final validation; host retains request context ownership. |
| Device namespaces | Decoding/re-encoding namespace values could replace originally authenticated bytes. | Preserve complete received DeviceNameSpacesBytes and embed them verbatim. |
| Item digests | Recreating Tag24 from decoded/inner bytes obscures the wire-byte contract. | Store/hash complete received IssuerSignedItemBytes; raw-order and tamper tests. |
| Parser | Whole Value trees and permissive lookups do not establish absence of duplicate keys, trailing data or unknown semantic members. | Bounded raw scan plus explicit shape/extension rules, fuzz and adversarial/property tests. |
| COSE headers | Prior critical/algorithm fixes must remain. A raw-label guard makes the selected header profile explicit before decoding. coset 0.4.2 already rejects empty kid/IV fields; this is defense in depth, not a demonstrated bypass. | Retained negative tests plus raw label whitelist and cross-bucket duplicate tests, including empty IV/kid. |
| COSE keys | Algorithm inference/loose key interpretation can confuse curve/key usage. | Algorithm/kty/curve/operation binding, coordinate completeness and raw ECDSA signatures. Device issuance rejects private parameters and invalid points. |
| Ed25519 | Ordinary verification is a weaker acceptance contract for malformed/weak inputs. | RustCrypto strict verification; no custom cryptographic implementation. |
| Device payload | COSE Sign1 can contain an embedded payload while the mdoc profile requires detached authentication. | Reject embedded device payload and ambiguous Signature/MAC choice. |
| MAC salt | HKDF input needs the hash of SessionTranscriptBytes, including its Tag24 wrapper. | Independent HKDF vector; MAC remains explicit and disabled in the NazoAuth profile. |
| Device key info | Optional/permissive parsing and filtering can discard malformed authorizations or key information. | Mandatory DeviceKeyInfo, strict disjoint authorization forms, retained unknown fields and explicit rejection by the server profile. |
| MSO dates | Tag1 epoch accepted; optional expectedUpdate could be omitted when issuing; timestamp formatting could hide invalid input order. | Tag0/UTC/whole seconds only, expectedUpdate signed and retained, order checked before/after conversion. |
| MSO certificate time | Leaf signing-time containment must remain after trust moves to the host. | Core verifies signed-time containment separately from host current-chain trust, without truncating leap seconds. |
| Status parsing | Preservation already exists on the production branch and is security-critical to NazoAuth. | Absent/known/unknown remain distinct; raw extension preserved; signature and malformed/unknown-presence regressions. |
| Status issuance | `CredentialSignInput.status` was not passed to DocumentBuilder. | NazoAuth rejects unauthorized status issuance by default; explicit policy requires a real validated published list and active index. |
| Status projection | A generic CBOR-to-JSON helper may lose tagged/unknown mechanisms. | NazoAuth uses a strict authenticated status projection and rejects unsupported semantics. |
| Trust duplication | Library verifier and NazoAuth both parse/check signatures/trust, and assessment overrides compensate for mismatched responsibilities. | One protocol authentication result, then existing chain/revocation/status policy; no final-valid core result or skip-trust switch. |
| Signing adapter | A synchronous signer port required a Tokio bridge around an already asynchronous external signer/key lease. | Prepare/sign/finish directly invokes the existing async lease; no private key enters the core. |
| Certificate chain | Integration signing material could retain only the leaf. | Preserve the validated non-root chain for x5chain and host path building. |
| Schema inference | Generic attribute names trigger automatic date tags even in custom namespaces. | Explicit NazoAuth mDL schema mapping; core preserves supplied CBOR types. |
| Test feature gates | Minimal production-feature run passes, but inherited ISO/verifier files execute zero tests because they require `tsp`. | Protocol tests no longer depend on unrelated TSP; minimum and all-feature CI are separate gates. |
| Optional components | TSP/PKCS11/HTTP and their transitive graph are unrelated to a server protocol core and expand advisory exposure. | Remove those components; preserve baseline audit output separately and audit all new locked dependencies. |
| Naming | Original API is not a sensible long-term compatibility promise. | One `nazo-mdoc` 0.3 package; unchanged repository, immutable downstream Git pin, no wrapper and no production merge. |

## Security regression accounting

Existing COSE critical-header, fixed-width signature and MAC tests remain, with
new raw-header cases. Borrowed SessionTranscript behavior is retained and tested.
ISO Annex D digest and issuer signatures remain an independent fixture. Old
verifier trust tests are replaced at their new responsibility boundary: core
cryptographic failures stay core tests; trust-anchor, certificate-revocation and
credential-status failures are NazoAuth tests. Removal of a trust store is not
removal of the admission check.

Automatic date-inference tests describe a removed application policy, not a core
security guarantee; corresponding explicit schema tests live in NazoAuth. Old
self-generated holder tests are not accepted as evidence for the corrected Final
wire format. Benchmarks explicitly identify this non-equivalence.

The protocol matrix distinguishes requirements, optional capabilities, enabled
NazoAuth profiles, unsupported mechanisms and server-inapplicable features. Its
ISO -7/23220 evidence limits are intentional: inaccessible licensed full text is
not substituted with guessed compliance. Runtime results and measurements must
identify tested revisions separately from this design/review record.
