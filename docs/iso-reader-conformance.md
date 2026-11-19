# ISO reader scope and conformance evidence

The reader target is **ISO/IEC 18013-5:2021, device retrieval, cipher suite 1**.
The implementation under review starts at `nazo-mdoc` main
`fa8235420699ff6135e892a04798e4ba2f667a93` (package 0.4.0). This baseline
already includes the borrowed verification path, mDL data validation, optional
Annex B certificate profiles and the application signer adapter. The historical
starting point in [issue #3](https://github.com/nazozero/nazo-mdoc/issues/3)
does not describe the current code.

The added core source and tests are frozen at
`c9ab149d9ea5fc2defe21fe6c6e84400cf641f34`. This document's source references
describe that revision; execution evidence must additionally identify its build
target, features and external backend version.

`nazo-mdoc` supplies protocol operations. An assembled reader additionally
includes transport adapters, key custody, trust configuration, a clock, data
retention policy and a user interface. No assembled physical reader, device
model, NFC/BLE adapter revision or external assessment is identified by this
crate. The complete-reader acceptance gate remains open for those components.

## Editions and source access

Checked on 2026-11-19. A catalogue establishes publication status; it does not
establish that implementation requirements or test cases were reviewed.

| Source | Selected edition and evidence |
| --- | --- |
| [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) | 2021, edition 1, published. The [public IBR copy](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf) supplied the reviewed protocol clauses and Annex B. Copyrighted standard text is not stored in this repository. |
| [18013-5 successor](https://committee.iso.org/standard/91081.html?browse=ics) | DIS, edition 2, under development, stage 40.60. No final-edition claim or draft status mechanism is selected. Its reorganized clause numbers cannot be applied to the 2021 edition. |
| [ISO/IEC TS 18013-6](https://www.iso.org/standard/91153.html) | 2025, edition 2, published. The official full test specification and executable suite have not been obtained or run for this implementation. |
| [ISO/IEC TS 18013-7](https://www.iso.org/standard/91154.html) | 2025, edition 2, published. The [DS/ANSI preview](https://webstore.ansi.org/preview-pages/DS/preview_M390700CURES.pdf) references OpenID4VP Draft 18 and identifies separate website, OID4VP and Digital Credentials API annexes. Full-text mapping remains open. |
| [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.2) | Separate selected profile. Final Redirect and DC API handovers have their own context-binding tests; they do not select TS 18013-7's edition or normative references. |
| [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) | Revision 21 remains an Internet-Draft in the RFC publication process. The selected MSO extension is [draft-21 §6.3](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-6.3). |

ISO announced a [sponsored read-only standards portal](https://www.iso.org/news/2026/09/digital-identity-standards-freely-accessible-worldwide).
The [DIN portal](https://dinmedia.mdoc.online/en) requires registration. Its
public list includes 18013-5:2021 and TS 18013-7:2025, but does not list
TS 18013-6:2025. No authenticated portal access was available for this review.
The portal's older 23220 listings do not replace the current ISO catalogue.

### Dated references and remaining reference review

The 2021 target retains its cited editions: BSI TR-03111 v2.10 (June 2018),
FIPS 186-4:2013, NIST SP 800-38D (November 2007), NFC Connection Handover
v1.5, Wi-Fi NAN v3.1, ISO/IEC 7816-4:2020, 18013-1:2018,
18013-2:2020, 19785-3:2020 and ISO 3166-2:2020. Its named RFCs include
7049/8152 for CBOR/COSE and 5280/5639/5869/7748/8032/8410 for the relevant
security formats and operations. Modern RFC 8949/9052/9053 references in the
[protocol matrix](protocol-matrix.md) describe the implementation; they do not
silently revise the edition-specific ISO contract.

No amendment or corrigendum is selected in this target. Before a complete-reader
release, the assessment owner must verify the publication's amendment/corrigendum
record and resolve all applicable dated and undated references. In particular,
the NFC, BLE, QR, image and biometric reference requirements need the respective
adapter or inspection implementation and its own clause-level evidence.

## Classification

**M** means mandatory for the reader target; **C** means mandatory when the
stated condition applies; **R** means a recommendation; **O** means optional.
These classifications describe the standard, independently of Cargo features.
**Core** identifies an implemented contract and source tests. **Host** or
**Adapter** identifies the component that must supply the remaining evidence.
An external owner does not remove a mandatory requirement.

Source-test references below identify executable regression contracts. Run
results must identify the tested commit, target, feature set and fixture hashes;
the presence of a test file alone is not a passing test result. Baseline entries
refer to the exact main revision above. Change-specific execution evidence is
attached to the implementing pull request and its commit-specific CI runs.

## 2021 reader requirement inventory

### Functional, data and representation contracts

| ID | Clause / strength / trigger | Owner and contract | Evidence or remaining gate |
| --- | --- | --- | --- |
| F-01 | §5; M, complete reader | Assembled-reader owner: identify interfaces, hardware, software, options and every applicable normative reference. | Open: no physical reader configuration or external assessment is supplied. |
| F-02 | §6.2(a–b); M | Host + adapters: offline retrieval and verification, including issuers outside the reader operator. | Pure core operations have no network requirement; offline transport and trust-store tests remain external. |
| F-03 | §6.2(c); M | Host inspection/UI: associate the presenting person with the authenticated mDL holder. | Device possession proof authenticates a device key. Human/biometric holder inspection needs separate evidence. |
| F-04 | §6.2(d), §6.3.1; M | Core + host: selective disclosure and independent element requests. | `disclosure_boundary`; `iso_boundaries::selective_disclosure_can_omit_one_item_or_the_complete_issuer_namespaces`; request/response inspection belongs to the consumer. |
| D-01 | §7.1, §7.2.1/Table 5; C, standard mDL fields supplied | Core `mdl`: types, identifiers, country/jurisdiction, dates and issuer-signed placement. Host issuer owns complete dataset contents. | `mdl_data`; `response_external::table_five_elements_cannot_be_device_signed_even_with_issuer_authorization`. |
| D-02 | §§7.2.2, 7.2.6–7.2.7; C, image/biometric field used | Image/inspection adapter: JPEG/JPEG2000 and biometric payload semantics. Core retains byte strings and checks the applicable biometric marker. | Full image/template decoding and person-binding evidence remain open. |
| D-03 | §7.2.4; C, driving privileges supplied | Core `mdl`: structured privilege/code/date values. | `mdl_data::mdl_data_types_are_authoritative_for_issuance_and_signed_verification`; referenced domestic/legal privilege interpretation remains host-owned. |
| D-04 | §7.2.5; C, age attestation requested | Core request/session: no more than two age-attestation requests per retrieval phase. Holder selects the nearest applicable attestation. | `reader_requests::age_attestation_limit_applies_to_the_complete_request`; `session_reader::age_limit_spans_requests_and_failed_send_does_not_consume_budget`. Host result policy must allow the specified nearest attestation; a different qualifying age identifier is not automatically an unsolicited claim. |
| D-05 | §§7.2.8, 7.3; C, domestic fields/country codes used | Host schema owner: domestic definitions and code assignment; core preserves authenticated values. | Domestic schema conformance and current undated code-list review remain external. |
| W-01 | §8.1; M | Core `cbor::raw`: minimal integer/length encoding, definite lengths, duplicate rejection, exact Tag 24 data. | `cbor_security`, `mso_security`, `tag_semantics`; input budgets are a local resource policy. |
| W-02 | §8.1; M | Core: retain received map order and bytes used in authentication. | `borrowed_verification`; `session_final::device_authentication_retains_original_transcript_and_namespace_order`; `interop_test`. |
| W-03 | §8.1; M | Core: accept known major version with unknown numeric minor version; ignore designated RFU values in their defined role. | `iso_boundaries::compatible_minor_versions_preserve_issuer_and_holder_authentication`; `authenticated_rfu_key_information_is_preserved_without_extra_authority`. Unknown security semantics remain explicit profile gaps. |
| W-04 | §8.1 and role-specific CDDL; M | Core: preserve lossless values allowed by each selected structure. | Existing generic value decoding restricts map-key shapes and simple values. `tag_semantics` records those restrictions; unrestricted `any` interoperability is not established. |

### Engagement, requests, responses and transport

| ID | Clause / strength / trigger | Owner and contract | Evidence or remaining gate |
| --- | --- | --- | --- |
| E-01 | §6.3.2.3/Table 1; M | Adapter: both QR and NFC engagement. | Open: camera/NFC adapter and actual-device results. |
| E-02 | §6.3.2.3, §8.2.2.1; M | NFC adapter: static and negotiated handover, NDEF/Alternative Carrier processing, exact handover messages. | Open: NFC Forum CH v1.5 implementation and hardware evidence. |
| E-03 | §8.2.1.1; M | Core + adapter: DeviceEngagement version, cipher suite, public key, transport-specific retrieval methods, RFU/extension processing. | `session_reader::agreement_roles_optional_parameters_and_invalid_points_are_checked_once`; `handover_roles_and_bounded_transcript_are_enforced`. Acquisition and retrieval-option processing belong to the adapter. |
| E-04 | §8.2.2.3; M | QR adapter: `mdoc:` URI and unpadded base64url, supported retrieval options. | Open: acquisition/decoding and transport-option interoperability. |
| E-05 | §8.2.3; R if engagement timer implemented | Host: initialization/establishment timeout policy, normally at least 30 seconds. | No clock or timeout loop in the protocol core. |
| Q-01 | §8.3.2.1.2.1; M | Core: DeviceRequest/DocRequest and exact ItemsRequestBytes, booleans for retention intent, nonempty requested namespaces/elements. | `reader::ItemsRequest`, `encode_device_request`; `reader_requests::request_schema_rejects_ambiguous_or_empty_requested_elements`; `session_reader::independent_full_session_mac_signature_and_directional_keys` includes expected request wire bytes. |
| Q-02 | §8.3.2.1.2.1; C, requestInfo supplied | Core + holder: preserve string-keyed requestInfo and ignore unrecognized values. | `reader_requests::unsigned_requests_retain_exact_items_and_unknown_request_info`. No extra authority is inferred; generic `any` value restrictions are recorded under W-04. |
| Q-03 | §8.3.2.1.2.1; M | Host: enforce intentToRetain for elements and derived material, including stored signatures/digests. | Open: consumer storage/logging and retention-policy tests. |
| Q-04 | §8.3.2.1.2.2–3; M | Core reader envelope: success/errors, optional documents, document/element errors and status inspection. | `reader_requests::status_only_and_document_errors_are_available_without_claims`; `mixed_document_errors_never_relax_atomic_presentation_verification`; `response_errors_reject_invalid_shapes_duplicates_and_trailing_bytes`. `ResponseEnvelope` retains untrusted raw fields; credential verification remains atomic. |
| Q-05 | §8.3.2.1.2.2; M for returned documents | Core: docType, namespace uniqueness, signed envelope shape and one device-authentication mechanism per document. | `response_structure`, `namespace_cardinality`, `verifier_test`; current verification returns all documents atomically or an error. |
| T-01 | §6.3.2.5/Table 2, §8.3.3.1.1; M | BLE adapter: central-client and peripheral-server modes, service/characteristic/ident/fragmentation/start/end handling. | Open: independently versioned adapter, BLE platform and real-device matrix. |
| T-02 | §6.3.2.5/Table 2, §8.3.3.1.2; M | NFC adapter: APDU selection, ENVELOPE/response transport, negotiated length bounds and channel termination. | Open: ISO/IEC 7816-4:2020 and hardware tests. |
| T-03 | §6.3.2.5, §8.3.3.1.3; R | Wi-Fi Aware adapter when selected. | No adapter or interoperability claim. |
| T-04 | Annex A; O | BLE L2CAP adapter when selected. | No adapter or interoperability claim. |
| T-05 | §6.3.2.5, §§8.3.2.2, 8.3.3.2; R to support, C once selected | Server-retrieval host: WebAPI/OIDC, server retrieval token, TLS/JWS and data model. | NazoAuth's OpenID4VP/VCI endpoints are different interfaces. ISO server retrieval is not selected or implemented here. |

### Security and inspection

| ID | Clause / strength / trigger | Owner and contract | Evidence or remaining gate |
| --- | --- | --- | --- |
| S-01 | §§6.3.3, 9.1.1; M for device retrieval | Core + key adapter: session ECDH, HKDF contexts, AES-256-GCM and ordered directional state. | `session_reader::independent_full_session_mac_signature_and_directional_keys` checks independently generated encrypted requests/responses. `ReaderKeyAgreement` owns external private-key operations. |
| S-02 | §9.1.1.4; M | Core + host: establishment/data/error/termination transitions; terminate on encryption/decoding errors; erase secrets and close channel. | `session_reader::terminal_data_is_authenticated_before_external_key_destruction`; `authentication_failures_close_and_release_without_partial_claims`. Sending the appropriate error status, channel closure, actual private-key destruction and inactivity scheduling need consumer evidence. Inactivity recommendation is at least 300 seconds. |
| S-03 | §9.1.1.5; M | Core: counters begin at 1 independently in each direction; distinct direction identifier; no counter reuse/wrap; complete GCM tag. | `session_reader::replay_order_and_wrong_session_fail_closed`; `authentication_failures_close_and_release_without_partial_claims`; `parallel_sessions_keep_counters_and_authentication_independent`; unit `directional_counter_exhaustion_terminates_without_wrap_or_reuse`. |
| S-04 | §9.1.2.4; M | Core: issuer signature combinations in the algorithm table below; original MSO payload; x5chain leaf key; algorithm/key binding. | `cose_vectors`, `interop_test`, `verification_boundaries`; `reader_crypto::independent_extended_curve_presentations_follow_the_compiled_capability`; native RFC/Wycheproof COSE tests. |
| S-05 | §§9.1.2.4–5, 9.3.1; M | Core: MSO structure, digest IDs/lengths, original disclosed-item hashes, docType, validity ordering/current time and certificate signing-time containment. | `mso_security`, `iso_boundaries`, `disclosure_boundary`, `verifier_test`. A current-time certificate path check remains a different host operation. |
| S-06 | §§9.1.3.4, 9.1.3.6; M | Core: DeviceSignature verification against the issuer-authenticated device key and session/namespace bytes. | `verifier_test::incorrect_session_binding_is_rejected`; `embedded_device_payload_is_rejected`; `borrowed_verification`. |
| S-07 | §§9.1.3.4–5; M | Core + key adapter: DeviceMAC using SDevice public key from authenticated MSO and the session's reader ephemeral private key. | `session_reader::independent_full_session_mac_signature_and_directional_keys`; `authentication_failures_close_and_release_without_partial_claims` covers issuer, curve, derivation, detached-mode, tag and authorization failures. Standalone `cose_mac_boundaries` and HKDF tests remain separate primitive evidence. |
| S-08 | §9.1.3.4; M | Issuer/wallet key owner: one device authentication key has one lifetime use, signature or MAC. Core: apply the same MSO authorization rules to either mechanism. | Key purpose/provisioning history is external; `verifier_test::nonempty_device_data_requires_key_authorizations` covers authorization enforcement. |
| S-09 | §§6.3.3, 9.1.4; O, conditional requirements when selected | Core reader signing: immutable ReaderAuthenticationBytes, detached COSE Sign1, protected alg, unprotected nonempty x5chain. Host owns reader identity/certificate trust. | `reader_requests::independently_generated_reader_authentication_vector`; `reader_signature_binds_exact_request_transcript_and_certificate`; `external_completion_rejects_wrong_key_input_der_and_algorithm`. The DS checker is not applied to reader certificates. |
| S-10 | §9.1.5.1; M | Core + engagement adapter: exact DeviceEngagementBytes, EReaderKeyBytes, QR null handover or exact NFC Select/Request messages. | `session_reader::handover_roles_and_bounded_transcript_are_enforced`; `replay_order_and_wrong_session_fail_closed`. Acquisition/channel identity remains external; SessionTranscript and its Tag 24 wrapper are distinct bytes. |
| S-11 | §9.1.5.2/Table 22; M | Core + key backend: every listed curve in its defined purpose. Reader ephemeral EC2 key is uncompressed; device ephemeral EC2 key permits compressed form. | `session_agreement_curves::supported_table22_agreement_curves_match_independent_full_session_vectors` checks seven supported ECDH curves with an external OpenSSL CLI test oracle and independent complete session fixtures; Brainpool P320/P512 are explicitly rejected. Deployed adapters still need their own operation/lifecycle evidence. |
| S-12 | §§9.2.1–2, 9.3.2; C, ISO server retrieval selected | Host: TLS/JWS algorithms, certificate roles, JWT inspection/time/issuer/token binding. | Outside this crate's selected device-retrieval and OpenID Final contracts; no conformance evidence. |
| X-01 | §9.3.3; M | Host: RFC 5280 path signatures/constraints/current time, authenticated available anchors and certificate revocation access. | `PendingTrustDocumentRef` requires host completion. NazoAuth integration tests are listed below. |
| X-02 | Annex B.1.1–4; M for corresponding issuer certificate role | Core `certificate-profile`: DER/DS/IACA/link profiles, authenticated issuer bindings, transmitted-root exclusion. Host: anchor/path evidence and signatures. | `certificate_profiles` signed positive/negative fixtures; `check_iaca_link_profile` requires both old and corresponding new-root evidence. |
| X-03 | Annex B.1.7; R when reader authentication selected | Host reader certificate policy: Table B.6 profile. The profile recommendation is distinct from §9.1.4's mandatory signature envelope. | No reader-certificate profile claim. Identity policy and path validation remain outside the prepared signature operation. |
| X-04 | Annex B.1.5–6, B.1.8–9, B.2; C, corresponding mechanism used | Host certificate/CRL/OCSP roles for JWS, TLS and revocation infrastructure. | Core DS/IACA tests do not cover these profiles. Record dedicated host/adaptor tests before selecting them. |
| X-05 | Annex C; O | Trust-list provider/host: VICAL selection and validation if used. | No VICAL implementation claim. Anchor selection is not inferred from a supplied certificate. |

## Algorithm and role inventory

All rows are mandatory for an assembled cipher-suite-1 reader in their indicated
roles. A feature flag controls artifact cost; it does not make a mandatory
reader algorithm optional in the standard.

| Curve | Signature verification | Agreement public-key handling with `reader-session` |
| --- | --- | --- |
| P-256 | ES256, default RustCrypto | ECDH; RustCrypto point validation |
| P-384 | ES384, default RustCrypto | ECDH; RustCrypto point validation |
| P-521 | ES512, default RustCrypto | ECDH; RustCrypto point validation |
| brainpoolP256r1 | ES256, portable `reader-crypto` | ECDH; portable point validation |
| brainpoolP320r1 | Unsupported, implementation required | Unsupported, implementation required |
| brainpoolP384r1 | ES384, portable `reader-crypto` | ECDH; portable point validation |
| brainpoolP512r1 | Unsupported, implementation required | Unsupported, implementation required |
| Ed25519 | EdDSA, default strict RustCrypto | Not an ECDH curve |
| Ed448 | EdDSA, portable `reader-crypto` with standalone point validation | Not an ECDH curve |
| X25519 | Not a signature curve | RFC 7748 public bytes; agreement output width/all-zero check |
| X448 | Not a signature curve | RFC 7748 public bytes; agreement output width/all-zero check |

Every actual ECDH operation and private-key lifetime belongs to the selected
`ReaderKeyAgreement` provider. The core does not provide or generate a private
ECDH key. NIST and Brainpool SDevice EC2 verification supports full coordinates
and the RFC 8152 compressed `y` boolean; EReader EC2 remains uncompressed.

### Added backend and operation boundaries

The optional `reader-crypto` feature uses RustCrypto `bp256`/`bp384` and
`crrl` (MIT) for Ed448. These algorithms work on native and WASM targets
without OpenSSL. Ed448 public-point decoding is canonical and the protocol
boundary checks the prime-order subgroup and excludes the identity.

`aws-lc` selects `aws-lc-rs` 1.19 for reader-session AES-256-GCM on supported
native targets. The default and WASM session implementation uses RustCrypto
`aes-gcm`. Both decrypt in place with identical authenticated nonce, counter
and byte contracts. The external `ReaderKeyAgreement` provider continues to
own ECDH operations and ephemeral private-key lifetime.

Brainpool P320r1 and P512r1 are currently rejected for signature and ECDH
roles. Both remain mandatory for the selected complete-reader target.
Known alternative implementations have not met this repository's production
security and licensing criteria; complete-reader conformance remains open.

The core validates NIST and supported Brainpool compressed/full EC points
and X25519/X448 input lengths; the external adapter supplies ECDH and the
result-length/all-zero checks are enforced here. No private-key arithmetic
is implemented in this project. OpenSSL is used solely by independently
generated offline fixtures and a Linux test oracle, not as a crate dependency.

The existing signature-key profile still enforces optional `alg`, `key_ops` and
`base_iv` restrictions. ISO §9.1.5.2 recommends ignoring optional key parameters;
this stricter compatibility profile is an explicit remaining restriction.
EReader/EDevice parsing follows the optional-parameter ignore rule. The SDevice
MAC role validator ignores their semantics, but its MSO key still passes the
common COSE metadata syntax/profile checks before dispatch.

`tests/reader_requests.rs`, `tests/session_reader.rs`,
`tests/session_agreement_curves.rs` and `tests/reader_crypto.rs` map the added
operations. Reader/session fixtures use independent Python framing, Python
cryptography/OpenSSL and standard-library HKDF/HMAC. The
[cryptography fixture inventory](../tests/vectors/reader_crypto/README.md) records
RFC 8032 Ed448 vectors, the selected Wycheproof revision/cases and independent
full Brainpool/Ed448 presentations. Fixture independence and mutation coverage
do not substitute for official test-method execution.

Dependency advisory results, selected backend versions and native/WASM artifact
costs belong in the exact tested revision's build evidence.

## Application integration

NazoAuth main `3496f4200f414900e40028438986265600dbdf54` is the
application baseline. Its OpenID4VP/HAIP path remains DeviceSignature-only.
The core reader APIs do not change that admission policy or provision reader
ephemeral keys, transports, sessions or status publishers for the application.

Existing application tests in
`crates/authorization-server/tests/unit/domain/openid4vc_credential_crypto.rs`
cover `mdoc_verification_rejects_expired_ds_even_when_mso_is_current`,
`mdoc_verification_rejects_signing_before_certificate_validity`,
`mdoc_required_unknown_status_uses_authenticated_anchor_not_loaded_scope`,
`verifier_requires_status_resolver_for_mdoc`,
`authenticated_unknown_mdoc_status_cannot_become_absent` and
`mdoc_status_tampering_or_removal_fails_before_status_resolution`.
Its `credential_crypto/status.rs` tests cover presence-preserving projection and
status signer/IACA binding. These are source evidence at the frozen revision;
this change's application run must use the final pinned core revision.

The integration regression
`mdoc_requires_device_signature_even_for_a_valid_mac_primitive` additionally
checks that enabling both reader features does not admit a MAC through the
application's existing OpenID4VP policy.

Credential status, certificate revocation and authorization of the status signer
remain separate obligations. No status reference is created without an actual
authorized status publisher. The draft-21 raw authenticated extension remains
available to host policy even for an unsupported mechanism.

## Other ISO profiles

| Specification | Publication checked | Applicable work and evidence boundary |
| --- | --- | --- |
| [23220-1:2023](https://www.iso.org/standard/74910.html) | Published, edition 1 | System architecture/lifecycle profile must be selected by the system owner. |
| [TS 23220-2:2026](https://www.iso.org/standard/91155.html) | Published, edition 2; replaces 2024 | Full data-model and encoding mapping needed for any claim. |
| [TS 23220-3:2026](https://www.iso.org/standard/86783.html) | Published, edition 1 | Installation/issuance interfaces and secure-area evidence need their own implementation scope. |
| [TS 23220-4:2026](https://www.iso.org/standard/86785.html) | Published, edition 1 | Operational protocols/transport/verification profile must be mapped independently. |
| [DTS 23220-5](https://www.iso.org/standard/86786.html) | Under development; current [committee catalogue](https://www.iso.org/committee/45144/x/catalogue/) shows 50.20 | No final trust-model/conformity claim. Older cached project pages show 50.00. |
| [TS 23220-6:2025](https://www.iso.org/standard/86787.html) | Published, edition 1 | Secure-area assessment evidence belongs to the wallet/secure-area and attestation owners. |

The catalogue also lists developing parts 7, 8 and 9. They do not silently extend
the selected 2021 target. Generic mdoc data structures and OpenID issuance do not
establish any of these system-level profiles.

## Acceptance evidence still required

| Gate | Owner | Evidence needed |
| --- | --- | --- |
| Official test methods | Conformance/assessment owner | Licensed TS 18013-6:2025 cases, IUT declaration, exact revisions, executed results and uncovered requirements. Its catalogue excludes issuing-authority infrastructure tests, OIDC server-retrieval tests, internal implementation and non-functional properties. |
| Physical reader | NFC/BLE/QR adapter owner | Identified hardware/OS/adapter versions, both BLE modes, both NFC handovers, NFC and BLE retrieval, disconnect/restart/error tests and independent wallets. |
| Private-key operation | Key-management owner | Generation, curve/role binding, fresh ephemeral lifetime, actual ECDH behavior, destruction and failed-operation tests for each selected backend. |
| Trust and holder inspection | Assembled-reader owner | Anchor provisioning, current-time path and revocation tests, offline behavior, person/holder binding and retention policy. |
| Interoperability | Reader/integration owner | Independent issuer/holder/reader implementations for each claimed algorithm/mechanism/interface; source/build/fixture hashes and test commands. |
| Core build and robustness | Core maintainer | Exact revision and features; native/WASM gates; advisory check; negative/property/fuzz corpus results. Baseline test counts are not evidence for a new revision. |
| Performance | Core and application maintainers | Matched production-baseline and candidate CPU/allocation/concurrency/artifact measurements, separate from protocol conformance. |

Annex D examples and independent cryptographic fixtures substantiate their
specific inputs. The complete-reader milestone closes only when the assembled
implementation and all applicable mandatory evidence gates are accounted for.
