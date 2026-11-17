# Protocol profile, evidence and responsibility matrix

Review dates: **2026-11-17–18 (Asia/Shanghai)**. Production comparison point:
`nazozero/mdoc-rs`, branch `nazoauth/patched-rustcrypto`, commit
`9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc` (`mdoc-rs` 0.2.0,
`default-features = false`, `features = ["issue"]`).

This document describes the selected server-side protocol profile and its
verification boundaries. It is not an ISO certification, a claim that every
reader/wallet feature is implemented, or a transfer of earlier certification to
new code. Test names identify executable contracts; an entry does not by itself
assert that the test passed on a particular target. Release evidence must record
the tested revision, command, target, inputs and result.

## Sources and evidence limits

The [OpenID specifications catalogue](https://openid.net/sg/openid4vc/specifications/)
and explicitly versioned Final specifications govern the OpenID profile.
Earlier drafts and old test fixtures do not override them.

| Document | Reviewed source and edition | Applicability and evidence boundary |
| --- | --- | --- |
| ISO/IEC 18013-5 | [ISO catalogue, 2021 edition](https://www.iso.org/standard/69084.html); [public incorporation-by-reference copy](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf) | Selected data structures, authentication and validation clauses were inspected. The latter is a Public.Resource.Org delivery of the ISO text, not an ISO-owned publication service. Its copyright remains with ISO/IEC; no standard text is vendored here. Proximity transport, full mDL reader conformance and certification are outside this core. |
| ISO/IEC TS 18013-7 | [ISO catalogue, 2025 edition](https://www.iso.org/standard/91154.html); [ANSI/DS preview](https://webstore.ansi.org/preview-pages/DS/preview_M390700CURES.pdf) | The 2025 edition supersedes 2024. Its preview's normative references include OpenID4VP Draft 18. Complete licensed text was not obtained. Do not equate that draft-dependent profile with OpenID4VP Final or claim a complete clause audit. |
| ISO/IEC 23220-1 | [2023 catalogue](https://www.iso.org/standard/74910.html) | General architecture context. Public catalogue evidence only; no whole-standard compliance claim. |
| ISO/IEC TS 23220-2 | [2026 edition catalogue](https://www.iso.org/standard/91155.html) | Supersedes 2024. Data-object profiles can be layered above the generic core; complete licensed clauses were unavailable. |
| ISO/IEC TS 23220-3 | [2026 catalogue](https://www.iso.org/standard/86783.html) | Installation/issuance protocol scope; not evidence that the OpenID4VCI service implements this separate protocol. Full-text review remains outstanding. |
| ISO/IEC TS 23220-4 | [2026 catalogue](https://www.iso.org/standard/86785.html), [official OBP preview](https://www.iso.org/obp/ui?_escaped_fragment_=iso%3Astd%3Aiso-iec%3Ats%3A23220%3A-4%3Aed-1%3Av1%3Aen) | The public preview exposes encoding, device/server retrieval and browser/app scope, but withholds normative sections. Selected 18013-5 building blocks are not complete 23220-4 conformance. |
| ISO/IEC DTS 23220-5 | [project catalogue](https://www.iso.org/standard/86786.html) | Trust-model work remained under development at review. Trust belongs to NazoAuth; do not cite this project as a published Final standard. |
| ISO/IEC TS 23220-6 | [2025 catalogue](https://www.iso.org/standard/86787.html) | Secure-area certification is a wallet/hardware concern; the server core does not certify hardware. |
| OpenID4VCI | [1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html), Appendix A.2 | Core IssuerSigned preparation; NazoAuth owns endpoints, proof, authorization, encryption, metadata and key leases. |
| OpenID4VP | [1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html), Appendix B.2 | Final Redirect and DC API Handover are separate constructors. NazoAuth enables `direct_post` and `direct_post.jwt`, not DC API transport. |
| OpenID4VC HAIP | [1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html), §§5.3.1, 7, 8 | NazoAuth selects one mdoc per DeviceResponse and its algorithm policy. §6.1 concerns SD-JWT status; it is not an mdoc status requirement. |
| COSE structures | [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), §§3, 4, 6, 7, 9, 10 | Signature/MAC structures, headers and key representation, with ISO/OpenID profile restrictions. |
| COSE algorithms | [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html), §§2, 7 | Primitive selection and key/algorithm binding. Unsupported curves are rejected. |
| Independent signature known answers | [RFC 6979 A.2.6](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.6); [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1) | P-384/SHA-384 `sample` and `test`, and Ed25519 TEST 1 (empty message), with published public keys and fixed signatures. These are primitive vectors, not full COSE/ISO certification. |
| COSE X.509 headers | [RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html), §§2–3 | Supplemental review. ISO 2021's unprotected `x5chain` profile predates this final RFC; see the compatibility boundary below. |
| CBOR | [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html), §§3.4.5.1, 4, 5.6, 10 | Data validity, embedded CBOR, encoding profiles and resource limits. Generic validity and a chosen deterministic encoding are distinct. |
| Date tags | [RFC 8943](https://www.rfc-editor.org/rfc/rfc8943.html); [RFC 9581](https://www.rfc-editor.org/rfc/rfc9581.html) | Tag 1004 is full-date and Tag 100 is epoch-date. Extended time/period tags do not replace the MSO's Tag 0 profile. Values remain typed CBOR for application schemas. |
| UTC representation and maintenance | [RFC 3339 §§5.6–5.7](https://www.rfc-editor.org/rfc/rfc3339.html); [time 0.3.55 source](https://docs.rs/time/0.3.55/src/time/parsing/parsable.rs.html); [RUSTSEC-2026-0543](https://github.com/rustsec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md) | Chrono was removed from the core and its tests after the all-versions maintenance advisory. `Timestamp` delegates calendar/format validation to `time` while preserving whole leap seconds and rejecting precision-losing input. See the timestamp boundary below. |
| URI syntax | [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html); [iri-string `UriStr`](https://docs.rs/iri-string/latest/iri_string/types/type.UriStr.html) | Borrowed URI syntax validation. Syntax acceptance does not authorize fetching a target. |
| Token Status List | [draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html); [IETF history](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/history/) | Revision 21, dated 2026-06-21, remains the compatibility baseline. Latest recorded RPC update at review: 2026-11-12, “Awaiting Second editor”. Still in the RFC Editor queue, not a published RFC. |

### Capability classifications

* **Required core**: needed to parse/authenticate the selected profile; failures
  reject the affected operation without a silent downgrade.
* **Optional core**: explicitly selected capability with its own contract.
* **NazoAuth enabled**: exercised by the integration's selected policy.
* **Not implemented**: rejected or unavailable, never advertised as supported.
* **Not a server-core responsibility**: delegated to a named owner; delegation
  does not remove the security requirement.

This component does not implement all Brainpool/Ed448 combinations, proximity
transport, secure-area lifecycle, wallet UI or a trust-list service. Selected
P-256/P-384/P-521 and Ed25519 primitives do not imply general reader conformance.
NazoAuth currently rejects DeviceMAC and selects DeviceSignature.

“Optional core” describes this library's selectable API, not a relaxation of a
mandatory ISO reader requirement. ISO/IEC 18013-5:2021 §9.1.2.4 requires a full
mdoc reader to verify every signature/curve combination listed there, including
Brainpool and Ed448; this implementation does not meet that complete-reader
requirement. Section 9.1.3.4 likewise requires a full reader to support both MAC
and signature authentication. The library's externally keyed MAC primitive and
NazoAuth's signature-only OpenID profile do not implement a complete ISO MAC
session. Unsupported combinations fail closed and must not be advertised as
supported. These are explicit capability limits, not certification claims.

## Core requirement-to-code/test map

Paths are relative to this repository. Structural tests are separate from
signature verification and final trust decisions. Entries naming a test category
rather than a concrete test name remain release-evidence work for that owner.

| ID | Basis / classification | Core contract | Implementation | Regression contract |
| --- | --- | --- | --- | --- |
| CBOR-01 | RFC 8949 §§4, 5.6; required | Reject duplicate keys, trailing data, invalid UTF-8, unsupported map-key shapes and non-shortest/indefinite profile encodings before decoded allocation. | `src/cbor/raw.rs` | `cbor_security::malformed_encodings_fail_closed`; `duplicate_text_keys_always_rejected`; `arbitrary_input_never_panics`; `mso_security::embedded_duplicates_nonshortest_and_indefinite_lengths_are_rejected` |
| CBOR-02 | RFC 8949 §10; required | Bound bytes, nesting, item counts and collection sizes; embedded Tag 24 shares its enclosing budget. Limits propagate to separately encoded COSE protected headers/MSO payloads, per envelope rather than as a whole-response global item count. | `src/cbor/raw.rs::Limits`; `src/parser.rs` | `parser_security::custom_collection_limits_reach_protected_headers_in_all_cose_roles`; `custom_depth_and_item_limits_reach_protected_headers`; `custom_limits_reach_mso_cbor_inside_the_cose_payload_byte_string`; fuzz target |
| CBOR-03 | RFC 8949 §3.4.5.1; required | Tag 24 contains exactly one embedded CBOR item. | `src/cbor/raw.rs::tag24_inner` | `mso_security::mso_requires_exactly_one_tag24_embedded_map` |
| CBOR-04 | ISO §8.1; required | Retain received ordering and authenticated bytes; sorting is not required for acceptance. | Raw envelopes in parser/models | `mso_security::original_mso_bytes_and_unsorted_map_order_are_preserved` |
| CBOR-05 | RFC 8949 §§2, 3.4.3, 5.3; required selected data model | Preserve all received tags, including Tag 2/3, in claims/status/extensions. Fields requiring native integers cannot accept tagged bignums through decoder normalization. | `raw::Item::value`; `decode_cbor`; `IssuerAuth::mso`; COSE header decoding | `tag_semantics::bignum_tags_survive_direct_arrays_maps_and_tag24_at_integer_boundaries`; `nested_unknown_tags_do_not_erase_positive_or_negative_bignums`; `unknown_status_mechanism_retains_its_entire_tagged_value_and_payload_bytes`; `status_list_index_requires_a_native_unsigned_integer`; `device_key_kty_curve_and_declared_algorithm_cannot_be_tagged_integers`; `issuer_item_retains_tagged_claim_value_and_original_tag24_bytes` |
| CBOR-06 | RFC 8949 §§3.3, 5.7; required selected simple-value profile | Accept false/true/null and IEEE floats; reject undefined and other unsupported simple values before a decoder can map them to null. | `src/cbor/raw.rs`; strict diagnostic decoder | `tag_semantics::undefined_and_unsupported_simple_values_fail_before_value_projection`; `undefined_cannot_be_accepted_as_a_detached_null_payload`; diagnostic unit test |
| CBOR-07 | RFC 8949 §§3.4.3, 4.2.1–4.2.2; issuance | Canonical encoding requires native small integers or minimally represented large bignums. Reject nonpreferred Tag 2/3 inputs instead of silently dropping tags. Pre-encoded Tag 24 bstr contents remain opaque and unchanged. | `data_item::canonicalize` | `canonical_bignum_inputs_must_already_use_preferred_representation`; `canonical_integer_boundaries_preserve_native_and_large_bignum_types` |
| COSE-01 | RFC 9052 §§3, 3.1 plus the selected header profile | Duplicate labels and unprocessed/misplaced critical semantics reject. Cross-bucket duplicates and headers outside alg/crit/kid/x5chain also reject under this profile; those extra restrictions are not generic RFC requirements to reject every unknown noncritical header. | `src/cose/mod.rs`; `src/parser.rs` | `parser_security::empty_security_headers_cannot_disappear_during_cose_decoding`; `duplicate_header_labels_are_rejected_across_buckets_even_for_empty_kid`; `unknown_text_private_and_unsigned_header_labels_fail_closed`; unit `rejects_private_use_critical_header`, `rejects_critical_header_from_unprotected_bucket`, `rejects_critical_alg_when_alg_header_is_absent`, `serialized_empty_critical_array_is_rejected_during_cose_parse` |
| COSE-02 | RFC 9052 §§4.2, 4.4, 9; required | Sig_structure uses original protected bytes/payload and empty external AAD; detached mode is explicit. | `src/cose/verify.rs`; `src/device_auth.rs` | `interop_test::annex_d_original_bytes_digests_and_issuer_signature`; `response_external::external_holder_signs_sig_structure_and_finishes_a_detached_proof`; `encoder_preserves_original_protected_header_bytes`; `verifier_test::embedded_device_payload_is_rejected`; unit `signed_protected_bytes_must_match_decoded_header_fields` |
| COSE-03 | RFC 9053 §§2, 7; required | Bind key type, curve, algorithm and operations; reject invalid points, private material and unsupported combinations. Fixed-width ECDSA R\|\|S. | `src/cose/key.rs`; `src/cose/verify.rs` | COSE-06 substitution tests; `roundtrip_test::device_key_must_be_public_complete_and_on_a_supported_curve`; `iso_boundaries::device_verification_key_requires_verification_use_and_no_base_iv`; unit `der_encoded_es256_signature_is_rejected`, `raw_rs_length_is_required`, `ec2_verification_keys_require_both_coordinates_before_signing_preparation`, `okp_verification_keys_require_x_but_reject_y` |
| COSE-04 | RFC 9052 §§6.2–6.3; optional core API | Mac0 requires the supported algorithm, empty AAD and caller-authorized session key. Detached payload and original protected bytes are authenticated. NazoAuth rejects MAC. | `src/device_auth.rs` | Four algorithm unit tests plus `tests/cose_mac_boundaries.rs`: `python_hmac_sha256_vector_verifies_detached_mac0`, `device_mac_rejects_modified_and_wrong_length_tags`, `device_mac_requires_the_supplied_external_key`, `device_mac_authenticates_the_complete_original_payload`, `device_mac_requires_empty_external_aad`, `device_mac_rejects_embedded_payloads`, `device_mac_authenticates_original_protected_header_bytes`, `device_mac_rejects_protected_header_metadata_mismatches`, `device_mac_rejects_unsupported_or_unprotected_critical_headers`. The fixed tags come from Python's standard-library HMAC with a manually encoded MAC_structure; they are independent vectors, not official RFC test vectors. |
| COSE-05 | Original protected-header evidence; required | Reject malformed/nonminimal/trailing protected CBOR and disagreement with the decoded header. Empty protected bytes may decode but do not authenticate an algorithm. | `src/cose/mod.rs`; `src/parser.rs` | `parser_security::protected_headers_reject_duplicate_nonminimal_or_trailing_cbor`; `empty_protected_bstr_is_decodable_but_does_not_claim_authentication`; `a_single_nonempty_kid_is_accepted_and_an_empty_kid_fails_closed` |
| COSE-06 | RFC 6979 A.2.6; RFC 8032 §7.1; independent primitive vectors | Fixed P-384/SHA-384 `sample`/`test` and Ed25519 TEST 1 exercise verification without using the library signer to derive expectations. | `src/cose/verify.rs`; `src/cose/key.rs` | All nine `tests/cose_vectors.rs` tests: `rfc6979_p384_sha384_sample_and_test_verify`, `rfc6979_p384_rejects_modified_signature_and_message`, `rfc6979_p384_rejects_algorithm_substitution`, `rfc6979_p384_rejects_curve_and_key_type_substitution`, `rfc8032_ed25519_empty_message_verifies`, `rfc8032_ed25519_rejects_modified_signature_and_message`, `rfc8032_ed25519_rejects_algorithm_substitution`, `rfc8032_ed25519_rejects_curve_and_key_type_substitution`, `official_vectors_require_exact_cose_signature_lengths` |
| COSE-07 | RFC 9052 §§3, 4.2, 6.2; required native field types | Construct Sign1/Mac0 from exactly four typed wire fields, retaining original protected bytes. Decode header values through the tag-preserving path; direct primitives apply the same contract to original_data. | `parser::parse_cose`; `cose::parse_header`; `validate_headers` | `tag_semantics::cose_alg_and_critical_labels_reject_bignums_in_every_wire_role`; `direct_sign1_verification_rejects_signed_bignum_header_types`; `direct_mac0_verification_rejects_authenticated_bignum_header_types`. Direct vectors authenticate the deliberately invalid header using independent valid signatures/MACs. |
| X509-01 | ISO §9.1.2.4; required | `x5chain` uses the designated bucket; every chain member must be a nonempty byte string (no filtered entries); full DER/path validation belongs to the host. | `src/model/issuer_auth.rs` | `x5chain_checks_every_entry_and_borrows_the_leaf`; `missing_duplicate_or_protected_x5chain_is_rejected` |
| X509-02 | RFC 9360; boundary | Extraction returns untrusted DER, not trust anchors. | `src/model/issuer_auth.rs`; pending-trust API | `mso_security::x5chain_checks_every_entry_and_borrows_the_leaf`; `verifier_test::wrong_leaf_key_is_not_an_issuer_signature`; `roundtrip_test::issuer_and_holder_roundtrip_has_pending_trust_not_a_final_valid_flag`; NazoAuth path-policy evidence |
| MSO-01 | ISO §§8.1, 9.1.2.4; required | Emit version 1.0; accept unknown numeric minor versions of known major 1. Mandatory members include DeviceKeyInfo. | `parse_mso_value` in `src/model/issuer_auth.rs`; `types::supports_version` | `mandatory_mso_fields_and_version_are_enforced`; `unknown_minor_mso_versions_are_accepted_and_preserved`; `iso_boundaries::compatible_minor_versions_preserve_issuer_and_holder_authentication`; `device_key_is_required_and_information_extensions_are_preserved` |
| MSO-02 | ISO §9.1.2.4; required | Require Tag 24; decode borrowed inner bytes once. | `IssuerAuth::mso` | `mso_requires_exactly_one_tag24_embedded_map`; `parser_security::present_mso_payload_must_be_one_tag24_wrapped_map`; `mso_security::original_mso_bytes_and_unsorted_map_order_are_preserved` |
| MSO-03 | ISO §§9.1.2.4–9.1.2.5; required; the upper bound is in §9.1.2.4 prose, printed p. 51, in addition to CDDL `uint` | Digest name/length and `0 <= digestID < 2^31` checked together, including undisclosed MSO entries. Historical unrestricted-u32 issuer output can be rejected; see the migration inventory/reissuance requirement. | `parse_value_digests`; `src/builder.rs` | `digest_algorithms_and_output_lengths_are_bound`; `digest_identifiers_and_namespace_shapes_are_strict`; `digest_id_range_boundary_is_enforced`; `random_digest_ids_are_unique_and_31_bit` |
| MSO-04 | ISO §9.1.2.4; required | Tag 0, UTC `Z`, whole seconds; `signed <= validFrom < validUntil`. | `parse_datetime`; `ValidityInfo::validate` | `timestamp_tag_and_iso_utc_whole_second_profile_are_required`; `validity_order_and_required_members_are_enforced` |
| TIME-01 | RFC 3339 §§5.6–5.7; required precision boundary | A whole second labelled `60` remains distinct: ordinary `59.999999999 < 60 < next second`. Unix conversion returns `None` for leap seconds. No self-written calendar or timezone rules. | `src/time.rs::Timestamp`; `src/verifier.rs` | Unit `leap_second_has_exact_order_beyond_the_last_ordinary_nanosecond`; `utc_normalization_retains_leap_seconds_and_ordinary_fractional_precision`; `iso_boundaries::whole_leap_second_is_not_truncated_to_the_certificate_last_regular_second` |
| TIME-02 | Selected API/encoding profile; required | Require uppercase `T`; MSO requires exactly 20-byte UTC `Z` form. General issuance input has at most nine fractional digits; longer input rejects before any interval comparison. Fractional leap seconds reject. | `src/time.rs`; MSO parser; builder | Unit `calendar_and_unsupported_leap_inputs_fail_closed`; `roundtrip_test::normalization_cannot_hide_reversed_order_or_create_an_empty_interval`; `subsecond_clock_input_is_normalized_only_after_order_validation` |
| TIME-03 | Range/conversion integrity; required | Four-digit UTC years, exact ordinary nanoseconds, checked offset conversion and consistent equality/order/hash. No silent projection of leap seconds into POSIX time. | `src/time.rs` | Unit `unix_conversion_preserves_negative_and_subsecond_instants`; `utc_offsets_preserve_identity_and_four_digit_year_bounds_are_checked` |
| MSO-05 | ISO §9.1.2.4; required when present | Nonempty, typed, disjoint KeyAuthorizations; no filtering malformed items. | `parse_key_authorizations` | `key_authorizations_preserve_both_disjoint_forms`; `malformed_or_overlapping_key_authorizations_are_rejected_without_filtering` |
| MSO-06 | ISO §§8.1, 9.1.2.4 and selected extension policy | Preserve MSO/DeviceKeyInfo extensions and integer keyInfo. Positive RFU keyInfo labels are ignored for admission without discarding their values; an empty keyInfo map is permitted. Proprietary negative or undesignated zero labels and unknown security extensions require profile support. | `src/model/types.rs`; MSO parser; `src/verifier.rs` | `device_key_is_required_and_information_extensions_are_preserved`; `iso_boundaries::authenticated_rfu_key_information_is_preserved_without_extra_authority`; `unknown_authenticated_device_key_information_requires_explicit_profile_support`; `verifier_test::unauthenticated_future_mso_extension_is_not_silently_dropped` (the test re-signs the modified MSO); `validity_order_and_required_members_are_enforced`; `malformed_or_overlapping_key_authorizations_are_rejected_without_filtering` |
| ITEMS-01 | ISO §9.1.2.5; required | Hash received IssuerSignedItemBytes; require random salts of at least 16 bytes without reuse and authenticated namespace/digest references. | `src/model/issuer_signed_item.rs`; parser/verifier | `interop_test::annex_d_original_bytes_digests_and_issuer_signature`; `verifier_test::tampered_attribute_original_bytes_fail_digest`; `iso_boundaries::received_short_random_is_rejected_even_with_matching_authenticated_digests`; `received_random_reuse_is_rejected_within_and_across_namespaces`; `disclosed_namespace_and_digest_id_must_exist_in_the_authenticated_mso` |
| ITEMS-02 | Selective disclosure; required | Missing undisclosed values are permitted; supplied values must match authenticated digests without identifier collisions. | `src/verifier.rs`; `src/disclosure.rs` | `parser_security::issuer_namespaces_may_be_absent_but_cannot_be_an_explicit_empty_map`; `iso_boundaries::selective_disclosure_can_omit_one_item_or_the_complete_issuer_namespaces`; `received_duplicate_digest_ids_reject_even_identical_authenticated_items`; `received_duplicate_identifiers_reject_distinct_authenticated_digest_ids` |
| ITEMS-03 | Security extension boundary; required | Unknown item/issuer/device security fields cannot disappear during parsing. | `src/parser.rs` | `iso_boundaries::unknown_authenticated_item_semantics_cannot_be_dropped`; `unknown_issuer_and_device_security_fields_fail_closed`; `response_structure::unknown_or_duplicate_response_and_document_fields_fail_closed` |
| DEVICE-01 | ISO §§9.1.3.4, 9.1.3.6; required | Tag 24 DeviceAuthenticationBytes binds docType, transcript, received namespaces. | `src/session.rs`; `src/device_auth.rs` | `session_final::device_authentication_has_outer_tag24_and_exact_independent_encoding`; `device_authentication_retains_original_transcript_and_namespace_order`; `verifier_test::incorrect_session_binding_is_rejected`; `doc_type_is_bound_to_mso_and_holder_signature` |
| DEVICE-02 | ISO §9.1.3.4; required | Authenticated MSO key and explicit device-element authorization. | `src/verifier.rs`; `src/cose/key.rs`; `src/response_builder.rs` | `response_external::preparing_rejects_unauthorized_device_namespaces`; `element_authorizations_do_not_authorize_other_elements_in_same_namespace`; wrong-holder/docType regressions |
| DEVICE-03 | ISO §§9.1.3.5, 9.1.5.1; optional core API | EMacKey salt hashes Tag 24 SessionTranscriptBytes. | `src/session.rs` | `emac_key_matches_independent_hkdf_vector_with_tag24_salt` |
| DEVICE-04 | ISO §8.3.2.1.2.2; required | DeviceNameSpaces may be empty, but each namespace that occurs must contain at least one DeviceSignedItems entry. Check both received and externally signed output paths. | `src/parser.rs`; `src/response_builder.rs` | `namespace_cardinality::device_namespace_cardinality_is_checked_before_authentication`; `response_external::preparing_rejects_empty_device_items_even_for_an_authorized_namespace` |
| RESPONSE-01 | ISO §§8.1, 8.3.2.1.2.2; required | Parser validates shape/known status/count and preserves textual version and known error status; presentation authentication requires major version 1 and status 0, accepting numeric unknown minor versions. | `src/parser.rs`; `src/verifier.rs` | `response_structure::device_response_root_must_be_a_map`; `device_response_version_is_required_text_and_supported_for_verification`; `unknown_minor_response_version_reaches_authentication`; `device_response_status_is_required_unsigned_known_and_successful_for_verification`; `device_response_documents_are_required_nonempty_arrays`; `device_response_document_count_limits_apply_before_document_decoding`; `document_required_fields_reject_missing_empty_and_wrong_types`; `missing_device_signed_cannot_be_a_verified_presentation` |
| RESPONSE-02 | HAIP §5.3.1; NazoAuth enabled | `max_documents = 1`; separate credentials use separate responses. A generic larger bound still returns no partial successes if any document fails. | Caller profile; parser/verifier | `verifier_test::haip_multiple_documents_are_rejected_before_partial_verification` tests both max 1 and max 2 with a damaged second signature |
| VERIFY-01 | ISO §9.3.1; required | Match docTypes; check current MSO validity and signed-time leaf-certificate interval, with inclusive endpoints and no loss of leap-second precision. | `src/verifier.rs` | `iso_boundaries::issued_doc_type_must_match_the_authenticated_mso_without_a_holder_proof`; `current_validity_includes_both_endpoints_and_rejects_adjacent_times`; `authenticated_mso_signed_time_is_contained_by_inclusive_leaf_certificate_bounds`; `whole_leap_second_is_not_truncated_to_the_certificate_last_regular_second` |
| VERIFY-02 | Trust boundary; required | Protocol-authenticated output remains pending external trust and revocation. | `src/verifier.rs` | `roundtrip_test::issuer_and_holder_roundtrip_has_pending_trust_not_a_final_valid_flag`; NazoAuth `credential_verifier_resolves_signed_status_after_authentication`, `verifier_requires_status_resolver_for_mdoc`, `mdoc_status_signer_must_belong_to_the_credential_iaca` |
| ISSUE-01 | OID4VCI A.2.4; NazoAuth enabled | External signing input; verified completion; IssuerSigned assembly without key custody. | `src/builder.rs`; `src/encoder.rs::encode_issuer_signed` | `roundtrip_test::issue_and_verify_disclosure`; `signer_with_wrong_key_cannot_complete`; `state_reference_is_covered_by_issuer_signature`; `response_external::official_annex_d_signed_items_and_payloads_survive_encoding_exactly` |
| ISSUE-02 | Profile contract; required | Reuse schema validation during issuance, including final CBOR bounds. | Builder; `parse_mso_value` | `roundtrip_test::invalid_validity_order_cannot_be_issued`; `duplicate_attributes_cannot_be_issued`; `device_key_must_be_public_complete_and_on_a_supported_curve`; `ambiguous_element_value_is_rejected_before_external_signing`; `subsecond_clock_input_is_normalized_only_after_order_validation`; `normalization_cannot_hide_reversed_order_or_create_an_empty_interval` |
| ISSUE-03 | External holder signing; optional | Prepare Sig_structure; verify returned signature; emit detached DeviceSignature without key custody. | `src/response_builder.rs` | `response_external::external_holder_signs_sig_structure_and_finishes_a_detached_proof`; `external_holder_wrong_key_altered_input_and_der_signatures_are_rejected`; `preparing_rejects_algorithm_curve_mismatch_and_unsupported_algorithms` |
| ENCODE-01 | Original signed-byte integrity; required | Encoding retains raw protected headers, disclosures and namespaces; attaching a device payload is rejected. | `src/encoder.rs` | `response_external::encoder_preserves_original_protected_header_bytes`; `encoder_never_substitutes_decoded_attributes_for_signed_item_bytes`; `encoder_cannot_silently_attach_a_device_signature_payload`; `official_annex_d_signed_items_and_payloads_survive_encoding_exactly` |

The old parser accepted Tag 1 epoch time in MSO ValidityInfo. The current test
explicitly rejects it because this profile uses Tag 0. This is a deliberate
acceptance-boundary correction. Empty `docType` is also rejected as an application
profile restriction, not because generic `tstr` grammar alone forbids it.

### Requirements and selected profile restrictions

The server API authenticates successful credential presentations; it does not
serve as a general error-response processor. A bare ISO error response without
documents is consequently outside this API. Multi-document failure is atomic
because no independently authorized partial-admission contract exists here.

Generic CBOR permits more map-key and simple-value types than the selected data
model. Compound/float keys and undefined are rejected to avoid ambiguous key
equality or lossy projection into the exposed value model. This is an explicit
interoperability limit, not a claim that these inputs are malformed under all
CBOR applications. Unknown MSO/DeviceKeyInfo members remain available in parsed
data but require a defined verification policy before admission. Explicitly
reserved positive keyInfo labels are an exception required by ISO: retain them
without treating them as authorization or rejecting their presence. Unknown status
is passed to the host intact so the host can enforce its supported-mechanism
policy. COSE headers have a documented allowlist because this implementation
does not process the semantics of the other headers; unsupported critical
headers always reject.

Issuer signature validity, `signed` containment within the leaf certificate,
current MSO validity, current X.509 path validity, certificate revocation and MSO
status are separate checks. ISO §9.3.1's signed-time check does not replace
§9.3.3's RFC 5280 path validation. The latter belongs to the host, using the
current presentation verification time (see ISO B.3.1 and RFC 5280 §6.1.1).

### Wire types and numeric data models

RFC 8949 permits an extended numeric data model to treat bignums and native
integers as numerically equivalent. Ciborium's normalization is therefore not
itself an RFC violation or proof of a signature forgery. This core's specific
wire profile requires native integer fields and preserves tags for host extension
policy, so using that normalization at the protocol boundary was inconsistent
with its contract. An authenticated NazoAuth claim regression exposed the issue.
The same eleven concrete regressions fail on checkpoint `d52cfca` and pass after
the tag-preserving change, including valid signatures over invalid header types.

The scanner still applies its resource/duplicate-key checks before value
allocation. Containers/tags are projected without semantic coercion; primitive
scalar decoding stays delegated to ciborium. Undefined has no distinct variant
in the selected Value model and is explicitly rejected instead of becoming null.
This is a restricted application profile, not support for every legal CBOR value.
Canonical issuance acts on the explicit Value tree; it does not rewrite opaque
Tag 24 content or invent semantic equivalence for unknown tags.

### Timestamp boundary and advisory update

The Chrono maintenance advisory was merged through
[RustSec PR 3214](https://github.com/rustsec/advisory-db/pull/3214) on the review
date. It is an all-versions **unmaintained** advisory, not a report of a newly
demonstrated memory-safety vulnerability in this core. Earlier audit evidence
against the 1,509-advisory snapshot does not override a later database finding.
The core, its test dependencies and the candidate consumer now use `time`
instead; historical baseline benchmark graphs retain their original dependency.
Removing the core dependency does not remediate every host workspace dependency.

`time` is responsible for the calendar and RFC 3339 offset interpretation. Its
parser's permitted separators, leap-second stand-in and excess fractional digits
are broader or lossy relative to this protocol's needs. The small `Timestamp`
type therefore checks the bounded input precision/separator first, retains a
separate whole-leap-second flag and orders it after every nanosecond of the
preceding regular second. Formatting restores the original `60` label. Signed
MSO payload bytes are still retained unchanged and never replaced with that
formatted value during authentication. The type does not implement calendar
arithmetic or claim to validate a leap occurrence against an IERS schedule.

Uppercase `T`, whole MSO seconds and rejection of fractional leap seconds are
explicit acceptance-profile choices. Borrowing `time`'s clamped result directly
would not establish the same representation and ordering contract. Comparison,
certificate boundaries, issuer normalization and date tags are re-tested after
this dependency change; older performance/artifact data must remain labelled
with its earlier runtime revision.

COSE empty-header regressions make the admission boundary explicit. The pinned
production dependency, coset 0.4.2, already rejects empty `kid`, IV, partial-IV
and countersignature forms during decoding. Their additional raw checks must not
be presented as proof that those inputs bypassed the production verifier.

### MSO regression continuity

The production commit's seven module-local MSO tests are carried forward through
the public API in `tests/mso_security.rs`; they are not treated as certification.

| Production test | Replacement evidence / deliberate change |
| --- | --- |
| `status_list_is_parsed` | `absence_is_distinct_from_unknown_or_known_status` checks index, URI and complete retained status. |
| `unknown_status_shape_is_preserved_raw` | Same public test plus `unknown_status_payloads_cannot_be_silently_discarded` property test. |
| `malformed_status_list_is_rejected` | `malformed_status_is_never_treated_as_absence` extends the old malformed-index case. |
| `tag0_tdate_is_accepted` | Valid fixture admission and `validity_order_and_required_members_are_enforced`. |
| `tag1_epoch_is_accepted` | Corrected to rejection in `timestamp_tag_and_iso_utc_whole_second_profile_are_required`, for the Tag 0 profile described above. |
| `untagged_text_is_rejected`, `tag6_is_not_a_datetime` | Explicit negative cases in the same timestamp regression. |

### X.509 header compatibility boundary

ISO 18013-5:2021 specifies unprotected `x5chain` using its then-current X.509 COSE
reference. RFC 9360 later formalized additional certificate-integrity requirements
and a single-certificate `bstr` / multiple-certificate array encoding. This core
retains the deployed ISO interpretation, including a one-element array, while
rejecting empty or partly malformed chains. It does not claim every generic RFC
9360 application profile. NazoAuth's authenticated path and scoped-IACA policy
still govern certificate identity; no incoming self-signed certificate becomes
trusted merely by being included.

## Final SessionTranscript profile

Final handovers are distinct from historical draft layouts. Constructors bind a
trusted request context; validation compares its complete expected encoding with
the supplied original bytes. Syntax alone is not request binding.

| Requirement | Source / capability | Implementation | Tests in `tests/session_final.rs` unless noted |
| --- | --- | --- | --- |
| Redirect binds full Client ID, nonce, optional encryption-key JWK thumbprint and Response URI through HandoverInfo's hash | OID4VP Final B.2.6.1; NazoAuth enabled | `src/session.rs`; NazoAuth service | `final_redirect_matches_official_vector_and_borrows_validated_bytes`; `every_redirect_context_parameter_is_bound` |
| DC API binds its distinct handover/origin | OID4VP Final B.2.6.2; optional core, NazoAuth transport disabled | `src/session.rs` | `final_dc_api_matches_official_vector_and_borrows_validated_bytes`; `every_dc_api_context_parameter_and_transport_is_bound` |
| JWK thumbprint uses required members and canonical JSON | [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html); with encryption | `src/session.rs` | `official_thumbprint_excludes_optional_jwk_members` |
| Unencrypted mode binds null, not a placeholder | OID4VP Final B.2.6 | `src/session.rs` | `unencrypted_modes_bind_null_instead_of_empty_or_text_thumbprint` |
| Exact original-byte and context integrity | OID4VP Final B.2.6; required | `src/session.rs` | `every_byte_of_the_official_transcript_is_authenticated_by_context`; `rejects_old_draft_handover_as_final`; `structural_validation_rejects_malformed_nonminimal_or_trailing_cbor` |
| Actual JWE decryption key matches advertised transcript-bound key | NazoAuth endpoint | Response processing | NazoAuth `encrypted_response_key_matches_the_key_bound_by_the_handover` |
| Generated/borrowed paths agree across contexts | Property test, not certification | `src/session.rs` | `arbitrary_context_roundtrips_bind_and_match_ciborium` |

The ISO -7:2025 preview's Draft 18 dependency is an evidence boundary. Final
support does not establish every mechanism/transport in that separate ISO profile.

## MSO status: presence, authentication and ownership

The original 2021 MSO schema has no status extension. This project explicitly
selects draft-21 §6.3 for that extension. The parser retains the whole CBOR value
and validates the known reference's shape. NazoAuth applies a stricter supported
mechanism policy after authentication. Unknown presence never becomes absence.

| ID | Contract / classification | Owner | Executable evidence |
| --- | --- | --- | --- |
| STATUS-01 | Absent/known/unknown distinct; preserve decoded members and signed payload. Required. | Core `MsoStatus` | `absence_is_distinct_from_unknown_or_known_status`; `unknown_status_payloads_cannot_be_silently_discarded` |
| STATUS-02 | Invalid structure, non-unsigned index and duplicates reject. Required. | MSO/CBOR parsers | `malformed_status_is_never_treated_as_absence`; `all_unsigned_status_indices_are_preserved` |
| STATUS-03 | URI syntax and original spelling. HTTPS, network/DNS/redirect policy are upper-owned. | Core `UriStr`; NazoAuth resolver | `status_uri_uses_rfc3986_without_normalizing_or_authorizing_fetch`; NazoAuth `mdoc_issuance_requires_explicit_policy_and_an_authenticated_published_list` includes disallowed scheme, userinfo and fragment references |
| STATUS-04 | Unsupported mechanisms/members and lossy CBOR projection reject. NazoAuth enabled. | Status projection | `mdoc_status_projection_preserves_presence_and_rejects_unknown_semantics`; `authenticated_unknown_mdoc_status_cannot_become_absent` |
| STATUS-05 | Authenticate credential before resolving status. Required. | Core result; NazoAuth verifier | `credential_verifier_resolves_signed_status_after_authentication`; `verifier_requires_status_resolver_for_mdoc` |
| STATUS-06 | Validate list signature, authorized signer, URI, time and index. NazoAuth enabled. | Existing draft-21 validator | `signed_cwt_lists_validate_cose_and_fail_closed`; `mdoc_status_signer_must_belong_to_the_credential_iaca` |
| STATUS-07 | Revoked/suspended/unknown/unavailable status fails closed. NazoAuth policy. | Status verifier/resolver | `credential_verifier_resolves_signed_status_after_authentication` exercises mdoc values 0/1/2/3, out-of-range index and an unreachable resolver; `specification_bit_order_bounds_and_compression_are_enforced` uses the draft-21 published two-bit vector and malformed/bounded compression cases |
| STATUS-08 | Never omit a signing input status. Default rejects; explicit policy needs a real authenticated published list and status-zero entry. | NazoAuth signer | `mdoc_issuance_requires_explicit_policy_and_an_authenticated_published_list` |
| STATUS-09 | Index allocation/publication maintenance is embedding-owned; ordinary endpoints do not supply it. Not implemented by shipped endpoints. | Application publisher | Missing resolver/list rejects; no invented URI/list |
| STATUS-10 | Editing or removing an issuer-signed status invalidates the credential before any list resolution. Required. | Core issuer-signature check; NazoAuth ordering | `mdoc_status_tampering_or_removal_fails_before_status_resolution` |

Draft-21 §8.3 governs processing and §11.3 status-issuer authorization. Issuer
certificate revocation, credential status and authorization of a status signer
remain separate decisions. A trusted signer under a different IACA is insufficient
for NazoAuth's policy. The core adds no second HTTP/status client.

## Security responsibilities across the boundary

| Check | Protocol core output | NazoAuth completion requirement |
| --- | --- | --- |
| CBOR/COSE/digests/MSO/current validity/signed-time containment/holder proof | Fail-closed protocol authentication or a typed pending-trust document | Cannot override core failures |
| X.509 path/document-signing profile | Original untrusted DER chain in a checked container | Path, anchor scope, CA constraints, critical extensions, EKU/profile and issuer identity |
| Certificate revocation | No CRL/snapshot freshness claim | Existing authenticated-path revocation policy |
| Credential status | Complete authenticated extension | Supported mechanism, availability, signature, issuer/IACA, URI, time, index and state |
| Final request binding | Constructor/validator bound to supplied context | Retained transaction context and actual response-encryption key |
| Final admission | No shortcut implying external trust | `VerifiedCredential` only after every applicable check |
| External signing | Exact signing bytes, checked completion; no custody | One pinned lease, authorized issuance/status policy, publication responsibilities |

Integration evidence is documented in NazoAuth's
`docs/protocol/openid4vc-validation.md`, OpenID4VP service-contract tests and
`crates/authorization-server/tests/unit/domain/openid4vc/credential_crypto/status.rs`.
Migration must execute those tests, not merely compile a replacement dependency.

## Deliberate limitations and remaining evidence gates

* Full-text clause review remains incomplete for ISO -7 and the 23220 series;
  public abstracts/previews do not justify complete-conformance claims.
* Full ISO reader curve coverage and the complete DeviceMAC session are not
  implemented. NazoAuth enables a selected signature-based OpenID profile.
  Proximity/device transport, secure-area certification and wallet behavior
  are outside this server core.
* Compound/floating-point CBOR map keys are rejected. Arbitrary value retention
  does not imply support for every CBOR extension.
* Unknown MSO/DeviceKeyInfo/status information requires explicit profile handling.
  Unknown security semantics are never harmless absence.
* URI syntax cannot prove a host safe or an index allocated. NazoAuth owns fetch
  policy and the embedding owns allocation/publication.
* Annex D/Final vectors establish specific interoperability evidence, not
  certification or coverage of every algorithm, wallet, issuer and transport.
* Release evidence must separately record minimum/all-feature builds, target/WASM
  checks, fuzz duration/corpus, advisories, comparable CPU/allocation measurements
  and end-to-end latency. Source mappings are not those measurements.
