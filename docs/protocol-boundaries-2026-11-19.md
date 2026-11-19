# Protocol boundary review: 0.4

Baseline: `920b717f9916a7dda1ecacd6bacf3bde84d75495` (0.3.0).
This review covers the supported issuance and signature-verification core,
its optional certificate profiles, and the NazoAuth integration boundary.
It does not close [full reader issue #3](https://github.com/nazozero/nazo-mdoc/issues/3).

## Responsibility and changes

The [protocol matrix](protocol-matrix.md) gives individual clauses and tests.
All source modules were included in the boundary review; the grouping below
records which implementation remains authoritative.

| Capability / source modules | Responsibility and change | Application responsibility |
| --- | --- | --- |
| CBOR (`cbor/raw`, `cbor/data_item`, `model/borrowed`, `diagnostic`) | Existing bounded borrowed parser, duplicate-key rules, tag preservation and direct canonical output remain shared by all higher APIs. | Choosing domestic schemas and JSON mappings; no duplicate CBOR validator. |
| COSE (`cose/*`, `device_auth`) | Existing algorithm/key binding, original authenticated bytes, multipart ECDSA/HMAC and strict Ed25519 remain here. The SPKI adapter now accepts a borrowed view of the same key rules. | External key custody; explicitly established MAC session keys. |
| MSO and issuer items (`model/issuer_auth`, `model/issuer_signed_item`, `model/types`) | Digest lengths/IDs, versions, validity, status structure and signed original data remain here. MSO and mDL timestamp parsing share one helper. | Credential status network fetch, authentication, freshness and policy. |
| Disclosure and response (`disclosure`, `parser`, `encoder*`, document/response models) | Existing original-byte hashing, uniqueness and borrowed encoding remain here. | Selecting requested/authorized disclosures. |
| Session (`session`) | Existing Final Redirect/DC API construction and supplied-context binding remain here. | Authentic request context, nonce consumption, HTTP and session state. |
| Signing (`builder`, `response_builder`) | Prepare/sign/finish remains external-signer compatible. New DS profile and mDL data checks run before preparation; returned signatures are still checked. | HSM, key leases, rotation, permissions and issuance cohorts. |
| Verification (`verifier`, `time`, `error`) | Existing issuer/holder/digest/validity verification remains here. Optional DS profile and supplied mDL fields now run before pending evidence is returned. | Path signatures/validity/revocation, trust anchors and admission decisions. |
| Annex B profiles (`certificate`, new optional feature) | Generic rules formerly in NazoAuth `mdoc_certificate.rs` now belong here. DS checks are automatic; IACA, link and actual issuer relationships use explicit certificate evidence. | Resolve authenticated paths and old/new roots; validate signatures, trust and current status. |
| mDL values (`mdl`, `cbor/date`) | Standard field encodings, dates, issuer-only Table 5 placement and C/ST bindings belong here. Borrowed date helpers replace allocating adapter checks. | Map JSON to explicit CBOR, manage datasets and require complete issuance claims according to supported product profile. |

No NazoAuth crate, tenant/account type, database, HTTP client or X.509 path engine
is imported. Only `x509-parser` and `sha1` are added as optional dependencies;
existing URI/calendar crates are reused. SHA-1 is used only for Annex B's SKI
construction, not credential or certificate signatures.

## Corrections and evidence

- Annex B.1.3 needs both the old root and corresponding new root. An actual
  issuer link alone does not establish the old root's expiry or new root's
  self-issued identity. Link subject/SPKI, issuer/AKI, expiry and renamed-root
  SAN are checked against supplied root evidence. Root profile and self-signature
  validation are separate prerequisites; a self-issued name is not a signature.
- Annex B.1.1 excludes the IACA root from x5chain. The helper compares the
  authenticated anchor's bytes and does not reject same-name rollover links
  merely because their subject and issuer names are equal.
- IACA duration uses 20 calendar years, including the February month-end
  boundary; DS duration uses the prescribed 457-day bound. Certificate
  AlgorithmIdentifier parameters and inner/outer signature identifiers are
  checked alongside the Annex B extension and key constraints.
- ISO §7.2 data checks previously depended on application JSON adapters. Supplied
  date tags, known field types, driving privileges, age attestations and the
  biometric marker now validate in both issuing and reading paths. Issue date
  is bounded by the MSO, and jurisdiction country binding holds even when the
  DS omits ST. Image/biometric payload formats are not decoded by this module.
- ISO §7.2.1 does not permit a device to supply Table 5 claims, even if an
  authenticated MSO authorizes that namespace. Both holder preparation and
  verification enforce this rule while allowing separately authorized domestic
  and future fields.

`tests/vectors/certificates/generate.py` deterministically generates 58 public
test certificates with Python `cryptography`. Rust verifies every ECDSA
signature over the actual TBS before checking the expected profile result.
Negative cases include validly signed wrong/missing extensions, lifetime and
rollover bindings, and a re-signed non-DER critical BOOLEAN. A certificate with
an extra outer sequence field retains its exact signed TBS/signature.

The profile test also substitutes a genuinely signed certificate for the same
MSO signing key: issuer authentication stays valid while issuance and reading
reject the wrong KU. `mdl_data` re-signs the MSO after deliberately changing the
document type to mDL, so malformed claims are rejected independently of valid
signatures/digests. The device-placement test verifies issuer and holder
signatures before asserting rejection.

The inherited Annex D sample remains a signature/digest/encoding vector. Its
sample DS lacks AKI and uses a DNS-name CRLDP, so it is not a positive Annex B
profile fixture. Tests do not exempt it from production profile checks.

## Ownership and retained parsing

Certificate-chain bytes remain borrowed in pending results. The optional
`leaf_certificate()` accessor lets the application reuse the parsed leaf rather
than decoding it again for profile/path integration. The public owned APIs
still copy on explicit owned conversion. The `issue` preparation path retains
its validated cryptographic key and exact signing input.

Strict `x509-cert` decoding is deliberately retained before `x509-parser`
profile checks. Independent probes confirmed that the latter accepts a BER
BOOLEAN and ignores an extra outer sequence field. Its borrowed views cannot
safely replace the existing strict decoder. This is a known parse/allocation
cost; no new ASN.1 decoder or duplicate path engine was introduced to hide it.
An application's earlier leaf parse for key/issuance-cohort selection is also a
separate input boundary. No performance improvement is claimed without a
matched measurement.

## Local validation

Rust 1.100.0 on Linux, two build jobs per Cargo process:

| Gate | Result |
| --- | --- |
| `cargo test --no-default-features` | 159 passed |
| `cargo test --no-default-features --features issue` | 243 passed |
| `cargo test --all-features` | 256 passed |
| `cargo clippy --all-features --all-targets -- -D warnings` | Passed |
| `cargo fmt --all --check`; rustdoc with `-D warnings` | Passed |
| `wasm32-unknown-unknown`, no default features | Built |
| `wasm32-unknown-unknown`, `issue,wasm-js,certificate-profile` | Built |
| `wasm32-wasip2`, `issue,certificate-profile` | Built |

These are library gates. Application trust, database, HSM and HTTP integration
tests belong to the consuming application; they are not implied by these counts.
The CI configuration also runs the seeded decode and certificate fuzz targets.

## Second edition: separately assessed, not enforced

On 2026-11-19, ISO's [project page](https://www.iso.org/standard/91081.html)
and [committee catalogue](https://www.iso.org/committee/45144/x/catalogue/)
identify edition 2 as DIS, stage 40.60, under development; the project has 176
pages and is intended to replace the published 2021 edition.
The [official OBP preview](https://www.iso.org/obp/ui?_escaped_fragment_=iso%3Astd%3Aiso-iec%3A18013%3A-5%3Adis%3Aed-2%3Av1%3Aen)
confirms a reorganized structure: §6 edition introduction, §7 mDL overview,
§8 general mdoc mechanisms, §9 engagement, §10 retrieval messages and §11
transport. Clause numbers therefore cannot be transferred from 2021.

The full current DIS text was not available in this review. The following is a
change inventory from implementers' own documentation, not a claim that its
exact CDDL or mandatory requirements have been independently verified:

| Reported DIS area | Primary implementation source | Treatment in this release |
| --- | --- | --- |
| Extended request information, alternative elements, issuer identifiers, document sets and response-size limits; `deviceRequestInfo` | [MATTR's explicit DIS feature table](https://learn.mattr.global/docs/verification/iso-18013-5-feature-support), §§10.2.4–10.2.5; [Multipaz release notes](https://developer.multipaz.org/blog/) | Inventory only; no new request protocol claimed. |
| ZKP requests/responses, encrypted documents and `readerAuthAll` | MATTR §§10.2.6–10.3.5/12.6; Multipaz notes | Not implemented or required of 2021 inputs. |
| Revocation/status and identifier lists | MATTR §12.3.6 | Existing explicitly versioned Token Status List extension remains separate. Exact DIS status schema awaits full text. |
| Updated NFC engagement and broader document formats | Multipaz release notes; official preview's engagement/transport reorganization | No proximity reader or SD-JWT support added by this change. |

The normative baseline for these corrections remains the published
[ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html), checked against
the [public IBR text](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf),
and the separately versioned Final OpenID4VC profiles listed in the protocol
matrix. Exact second-edition Annex B/digest/CDDL changes require the actual
draft or final text; historical discussions are not sufficient evidence.
