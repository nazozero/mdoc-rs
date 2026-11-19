# Protocol profile and test map

This document maps the library's supported wire formats and authentication
rules to source and regression tests. Test execution, target coverage and
performance measurements are recorded separately for each revision.

## Sources

| Specification | Library scope |
| --- | --- |
| [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) | Device engagement/session framing, requests, responses, issuer/reader/device authentication, MSO and disclosure digests. Protocol clauses were reviewed using the [public IBR copy](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf). |
| [OpenID4VCI 1.0 Final, A.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html) | IssuerSigned preparation and encoding |
| [OpenID4VP 1.0 Final, B.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html) | Redirect and DC API SessionTranscript handovers |
| [OpenID4VC HAIP 1.0 Final, §5.3.1](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) | Caller-selected limit of one mdoc per DeviceResponse |
| [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html) | COSE structures, headers, algorithms and key binding |
| [RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html) | X.509 COSE header reference; ISO 2021 x5chain compatibility is described below |
| [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) | CBOR validity, tags, deterministic encoding and resource limits |
| [RFC 8943](https://www.rfc-editor.org/rfc/rfc8943.html), [RFC 9581](https://www.rfc-editor.org/rfc/rfc9581.html) | Full-date and extended time tags for caller-selected schemas |
| [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html) | Timestamp representation and leap seconds |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html) | Status-reference URI syntax |
| [Token Status List draft-21, §6.3](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html) | Selected MSO status extension revision |
| [RFC 6979 A.2.6](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.6), [RFC 8032 §§7.1, 7.4](https://www.rfc-editor.org/rfc/rfc8032.html#section-7) | Independent P-384, Ed25519 and Ed448 signature vectors |

Default signature verification supports P-256, P-384, P-521 and Ed25519.
The portable `reader-crypto` feature adds Brainpool P256/P384 and Ed448,
including standalone public-point validation on WASM. Brainpool P320/P512
remain unsupported; the complete ISO reader algorithm target is not met.
On native targets `aws-lc` selects AWS-LC session AES-GCM without changing
the signature verifier or external ECDH contracts.

`verify_presentation*` selects DeviceSignature. The optional `reader-session`
path verifies either DeviceSignature or session-bound DeviceMAC through the
same issuer, disclosure and authorization checks. The private ECDH operation
belongs to a `ReaderKeyAgreement` provider; transport adapters remain external.
Low-level DeviceMAC/HKDF functions retain their externally established-key
contract. The [edition-specific inventory](iso-reader-conformance.md) records
mandatory reader roles separately from Cargo features and identifies the
remaining physical-reader, trust and official-test evidence for
[issue #3](https://github.com/nazozero/nazo-mdoc/issues/3).

[ISO/IEC TS 18013-7:2025](https://www.iso.org/standard/91154.html) and the
ISO/IEC 23220 series require further full-text review. The reviewed
[18013-7 preview](https://webstore.ansi.org/preview-pages/DS/preview_M390700CURES.pdf)
references OpenID4VP Draft 18; this library implements the separately versioned
OpenID4VP 1.0 Final handovers.

## Core requirements

**Required** identifies checks enforced by the supported profile. **Optional**
identifies a callable feature or a policy selected by the application. Paths and
tests below are relative to this repository.

| ID | Basis / classification | Core contract | Implementation | Regression contract |
| --- | --- | --- | --- | --- |
| CBOR-01 | RFC 8949 §§4, 5.6; required | Reject duplicate keys, trailing data, invalid UTF-8, unsupported map-key shapes and non-shortest/indefinite profile encodings before decoded allocation. | `src/cbor/raw.rs` | `cbor_security::malformed_encodings_fail_closed`; `duplicate_text_keys_always_rejected`; `arbitrary_input_never_panics`; `mso_security::embedded_duplicates_nonshortest_and_indefinite_lengths_are_rejected` |
| CBOR-02 | RFC 8949 §10; required | Bound bytes, nesting, item counts and collection sizes; embedded Tag 24 shares its enclosing budget. Limits propagate to separately encoded COSE protected headers/MSO payloads, per envelope rather than as a whole-response global item count. | `src/cbor/raw.rs::Limits`; `src/parser.rs` | `parser_security::custom_collection_limits_reach_protected_headers_in_all_cose_roles`; `custom_depth_and_item_limits_reach_protected_headers`; `custom_limits_reach_mso_cbor_inside_the_cose_payload_byte_string`; fuzz target |
| CBOR-03 | RFC 8949 §3.4.5.1; required | Tag 24 contains exactly one embedded CBOR item. | `src/cbor/raw.rs::tag24_inner` | `mso_security::mso_requires_exactly_one_tag24_embedded_map` |
| CBOR-04 | ISO §8.1; required | Retain received ordering and authenticated bytes; sorting is not required for acceptance. | Raw envelopes in parser/models | `mso_security::original_mso_bytes_and_unsorted_map_order_are_preserved` |
| CBOR-05 | RFC 8949 §§2, 3.4.3, 5.3; required selected data model | Preserve all received tags, including Tag 2/3, in claims/status/extensions. Fields requiring native integers cannot accept tagged bignums through decoder normalization. | `raw::Item::value`; `decode_cbor`; `IssuerAuth::mso`; COSE header decoding | `tag_semantics::bignum_tags_survive_direct_arrays_maps_and_tag24_at_integer_boundaries`; `nested_unknown_tags_do_not_erase_positive_or_negative_bignums`; `unknown_status_mechanism_retains_its_entire_tagged_value_and_payload_bytes`; `status_list_index_requires_a_native_unsigned_integer`; `device_key_kty_curve_and_declared_algorithm_cannot_be_tagged_integers`; `issuer_item_retains_tagged_claim_value_and_original_tag24_bytes` |
| CBOR-06 | RFC 8949 §§3.3, 5.7; required selected simple-value profile | Accept false/true/null and IEEE floats; reject undefined and other unsupported simple values before a decoder can map them to null. | `src/cbor/raw.rs`; strict diagnostic decoder | `tag_semantics::undefined_and_unsupported_simple_values_fail_before_value_projection`; `undefined_cannot_be_accepted_as_a_detached_null_payload`; diagnostic unit test |
| CBOR-07 | RFC 8949 §§3.4.3, 4.2.1–4.2.2; issuance | Canonical encoding requires native small integers or minimally represented large bignums. Reject nonpreferred Tag 2/3 inputs instead of silently dropping tags. Pre-encoded Tag 24 bstr contents remain opaque and unchanged. | `data_item::write_canonical` | `canonical_bignum_inputs_must_already_use_preferred_representation`; `canonical_integer_boundaries_preserve_native_and_large_bignum_types`; `cbor_optimization::canonical_keys_match_wire_order_at_every_header_width`; `borrowed_canonical_writer_matches_encoded_key_reference`; `canonical_output_preserves_opaque_tag24_bytes` |
| COSE-01 | RFC 9052 §§3, 3.1 plus the selected header profile | Reject duplicate labels, unprocessed or misplaced critical semantics, cross-bucket duplicates and headers outside the selected alg/crit/kid/x5chain profile. | `src/cose/mod.rs`; `src/parser.rs` | `parser_security::empty_security_headers_cannot_disappear_during_cose_decoding`; `duplicate_header_labels_are_rejected_across_buckets_even_for_empty_kid`; `unknown_text_private_and_unsigned_header_labels_fail_closed`; unit `rejects_private_use_critical_header`, `rejects_critical_header_from_unprotected_bucket`, `rejects_critical_alg_when_alg_header_is_absent`, `serialized_empty_critical_array_is_rejected_during_cose_parse`; `verification_boundaries::parsed_issuer_and_holder_headers_enforce_critical_semantics` |
| COSE-02 | RFC 9052 §§4.2, 4.4, 9; required | Sig_structure uses original protected bytes/payload and empty external AAD; detached mode is explicit. | `src/cose/structure.rs`; `src/cose/verify.rs`; `src/device_auth.rs` | `interop_test::annex_d_original_bytes_digests_and_issuer_signature`; `response_external::external_holder_signs_sig_structure_and_finishes_a_detached_proof`; `encoder_preserves_original_protected_header_bytes`; `verifier_test::embedded_device_payload_is_rejected`; units `signed_protected_bytes_must_match_decoded_header_fields`; `inputs_match_independent_coset_encoding_at_length_boundaries`; `received_empty_protected_bytes_are_retained` |
| COSE-03 | RFC 9053 §§2, 7; required | Bind key type, curve, algorithm and operations; reject invalid points, private material and unsupported combinations. Fixed-width ECDSA R\|\|S. | `src/cose/key.rs`; `src/cose/verify.rs` | COSE-06 substitution tests; `roundtrip_test::device_key_must_be_public_complete_and_on_a_supported_curve`; `iso_boundaries::device_verification_key_requires_verification_use_and_no_base_iv`; unit `der_encoded_es256_signature_is_rejected`, `raw_rs_length_is_required`, `ec2_verification_keys_require_both_coordinates_before_signing_preparation`, `okp_verification_keys_require_x_but_reject_y` |
| COSE-04 | RFC 9052 §§6.2–6.3; optional primitive API | Mac0 requires the supported algorithm, empty AAD and caller-authorized key. Detached payload and original protected bytes are authenticated. The session-bound reader contract is READER-05 below. | `src/device_auth.rs` | Four algorithm unit tests plus `tests/cose_mac_boundaries.rs`: `python_hmac_sha256_vector_verifies_detached_mac0`, `device_mac_rejects_modified_and_wrong_length_tags`, `device_mac_requires_the_supplied_external_key`, `device_mac_authenticates_the_complete_original_payload`, `device_mac_requires_empty_external_aad`, `device_mac_rejects_embedded_payloads`, `device_mac_authenticates_original_protected_header_bytes`, `device_mac_rejects_protected_header_metadata_mismatches`, `device_mac_rejects_unsupported_or_unprotected_critical_headers`. Fixed tags use Python standard-library HMAC and manually encoded MAC_structure. |
| COSE-05 | Original protected-header evidence; required | Reject malformed/nonminimal/trailing protected CBOR and disagreement with the decoded header. Empty protected bytes may decode but do not authenticate an algorithm. | `src/cose/mod.rs`; `src/parser.rs` | `parser_security::protected_headers_reject_duplicate_nonminimal_or_trailing_cbor`; `empty_protected_bstr_is_decodable_but_does_not_claim_authentication`; `a_single_nonempty_kid_is_accepted_and_an_empty_kid_fails_closed`; `verification_boundaries::public_device_verification_still_checks_original_header_binding` |
| COSE-06 | RFC 6979 A.2.6; RFC 8032 §7.1; independent primitive vectors | Fixed P-384/SHA-384 `sample`/`test` and Ed25519 TEST 1 exercise verification without using the library signer to derive expectations. | `src/cose/verify.rs`; `src/cose/key.rs` | All nine `tests/cose_vectors.rs` tests: `rfc6979_p384_sha384_sample_and_test_verify`, `rfc6979_p384_rejects_modified_signature_and_message`, `rfc6979_p384_rejects_algorithm_substitution`, `rfc6979_p384_rejects_curve_and_key_type_substitution`, `rfc8032_ed25519_empty_message_verifies`, `rfc8032_ed25519_rejects_modified_signature_and_message`, `rfc8032_ed25519_rejects_algorithm_substitution`, `rfc8032_ed25519_rejects_curve_and_key_type_substitution`, `official_vectors_require_exact_cose_signature_lengths` |
| COSE-07 | RFC 9052 §§3, 4.2, 6.2; required native field types | Construct Sign1/Mac0 from exactly four typed wire fields, retaining original protected bytes. Decode header values through the tag-preserving path; direct primitives apply the same contract to original_data. | `parser::parse_cose`; `cose::parse_header`; `validate_headers`; `validate_parsed_headers` | `tag_semantics::cose_alg_and_critical_labels_reject_bignums_in_every_wire_role`; `direct_sign1_verification_rejects_signed_bignum_header_types`; `direct_mac0_verification_rejects_authenticated_bignum_header_types`. Direct vectors authenticate the deliberately invalid header using independent valid signatures/MACs. |
| X509-01 | ISO §9.1.2.4; required | `x5chain` uses the designated bucket; every chain member must be a nonempty byte string. The library decodes leaf DER for signature and signed-time checks. With `certificate-profile`, DS profile enforcement is automatic; the application validates the full certificate path and revocation. | `src/model/issuer_auth.rs`; `src/verifier.rs` | `x5chain_checks_every_entry_and_borrows_the_leaf`; `missing_duplicate_or_protected_x5chain_is_rejected`; `verification_boundaries::parsed_issuer_chain_must_remain_in_the_unprotected_header` |
| X509-02 | RFC 9360; boundary | Extraction returns untrusted DER for application path validation. | `src/model/issuer_auth.rs`; pending-trust API | `mso_security::x5chain_checks_every_entry_and_borrows_the_leaf`; `verifier_test::wrong_leaf_key_is_not_an_issuer_signature`; `roundtrip_test::issuer_and_holder_roundtrip_has_pending_trust_not_a_final_valid_flag` |
| X509-03 | ISO Annex B.1.1/B.1.4; required with `certificate-profile` | Strict DER, v3, positive bounded serial, signature algorithm consistency, DS key/duration, KU/EKU/SKI/AKI/IAN/CRLDP, permitted extensions and subject encodings. Automatically checked by issuance and verification. | `src/certificate.rs`; builder/verifier | `certificate_profiles::signed_annex_b_positive_and_negative_profiles`; `issuance_and_verification_enforce_profiles_without_an_application_check`; signed non-DER fixtures |
| X509-04 | ISO Annex B.1.2/B.1.3; callable profile with external evidence | IACA root and link constraints; link subject/SPKI match new root, issuer/AKI match old root, expiry bounded by old root, changed DN requires matching SAN. Root self-signatures and path remain external. | `src/certificate.rs` | 58 signed fixture matrix; `rollover_requires_corresponding_new_root_not_only_a_valid_signature`; 20-calendar-year/457-day bounds |
| X509-05 | ISO Annex B.1.1; path-dependent requirement | Compare x5chain with authenticated root evidence; reject the transmitted IACA root without confusing same-name rollover links with roots. | `certificate::check_x5chain_root_exclusion` | `root_exclusion_uses_the_authenticated_anchor_not_a_name_guess` |
| MDL-01 | ISO §7.2.1/Table 5; required for supplied fields | Validate known standard CBOR types, Latin-1 limits, date tags, whole UTC timestamps, issue_date ≤ validFrom, country/jurisdiction relation and enumerated values. With profile feature, bind supplied issuing_country/jurisdiction to DS C/ST. | `src/mdl.rs`; `cbor::date`; builder/verifier | `mdl_data` signed positive/negative cases; `country_and_optional_jurisdiction_bind_to_the_actual_document_signer` |
| MDL-02 | ISO §§7.2.4–7.2.6; required for supplied fields | DrivingPrivileges schema, full-date fields and nonempty codes; age_over_NN bool; biometric-template byte string begins 7F61. Image/biometric payload decoding remains outside supported scope. | `src/mdl.rs` | `mdl_data::mdl_data_types_are_authoritative_for_issuance_and_signed_verification` |
| MDL-03 | ISO §7.2.1; required | Table 5 elements in device retrieval must be IssuerSigned, even if a valid MSO authorizes their namespace to a device. Domestic/future fields remain separately authorized. | `src/mdl.rs`; verifier/response builder | `response_external::table_five_elements_cannot_be_device_signed_even_with_issuer_authorization` verifies both signatures independently |
| MSO-01 | ISO §§8.1, 9.1.2.4; required | Emit version 1.0; accept unknown numeric minor versions of known major 1. Mandatory members include DeviceKeyInfo. | `parse_mso_ref` in `src/model/issuer_auth.rs`; `types::supports_version` | `mandatory_mso_fields_and_version_are_enforced`; `unknown_minor_mso_versions_are_accepted_and_preserved`; `iso_boundaries::compatible_minor_versions_preserve_issuer_and_holder_authentication`; `device_key_is_required_and_information_extensions_are_preserved` |
| MSO-02 | ISO §9.1.2.4; required | Require Tag 24 and project its original payload. | `MsoRef::parse`; `IssuerAuthRef::mso`; `IssuerAuth::mso` | `mso_requires_exactly_one_tag24_embedded_map`; `parser_security::present_mso_payload_must_be_one_tag24_wrapped_map`; `mso_security::original_mso_bytes_and_unsorted_map_order_are_preserved` |
| MSO-03 | ISO §§9.1.2.4–9.1.2.5; required; the upper bound is in §9.1.2.4 prose, printed p. 51, in addition to CDDL `uint` | Digest name/length and `0 <= digestID < 2^31` checked together, including undisclosed MSO entries. Historical unrestricted-u32 issuer output can be rejected; see the migration inventory/reissuance requirement. | `parse_value_digests`; `src/builder.rs` | `digest_algorithms_and_output_lengths_are_bound`; `digest_identifiers_and_namespace_shapes_are_strict`; `digest_id_range_boundary_is_enforced`; `random_digest_ids_are_unique_and_31_bit` |
| MSO-04 | ISO §9.1.2.4; required | Tag 0, UTC `Z`, whole seconds; `signed <= validFrom < validUntil`. | `parse_datetime`; `ValidityInfo::validate` | `timestamp_tag_and_iso_utc_whole_second_profile_are_required`; `validity_order_and_required_members_are_enforced` |
| TIME-01 | RFC 3339 §§5.6–5.7; required precision boundary | A whole second labelled `60` remains distinct: ordinary `59.999999999 < 60 < next second`. Unix conversion returns `None` for leap seconds. No self-written calendar or timezone rules. | `src/time.rs::Timestamp`; `src/verifier.rs` | Unit `leap_second_has_exact_order_beyond_the_last_ordinary_nanosecond`; `utc_normalization_retains_leap_seconds_and_ordinary_fractional_precision`; `iso_boundaries::whole_leap_second_is_not_truncated_to_the_certificate_last_regular_second` |
| TIME-02 | ISO §§7.2.1/9.1.2.4; RFC 3339 §5.6; API precision bound | Accept `T`/`t` and `Z`/`z`; MSO and mDL tdate require exactly 20-byte UTC whole seconds. Formatting emits uppercase. General issuance input has at most nine fractional digits; longer input rejects before any interval comparison. Fractional leap seconds reject. | `src/time.rs`; `cbor::date`; MSO parser; builder | Unit `rfc3339_letters_are_case_insensitive_and_format_as_uppercase`; `iso_boundaries::authenticated_mso_timestamps_accept_rfc3339_letter_case`; `authenticated_mso_timestamps_still_require_whole_seconds_and_utc_designator`; `mdl_data::mdl_timestamps_accept_rfc3339_letter_case`; `roundtrip_test::normalization_cannot_hide_reversed_order_or_create_an_empty_interval` |
| TIME-03 | Range/conversion integrity; required | Four-digit UTC years, exact ordinary nanoseconds, checked offset conversion and consistent equality/order/hash. No silent projection of leap seconds into POSIX time. | `src/time.rs` | Unit `unix_conversion_preserves_negative_and_subsecond_instants`; `utc_offsets_preserve_identity_and_four_digit_year_bounds_are_checked` |
| MSO-05 | ISO §9.1.2.4; required when present | Nonempty, typed, disjoint KeyAuthorizations; no filtering malformed items. | `parse_key_authorizations` | `key_authorizations_preserve_both_disjoint_forms`; `malformed_or_overlapping_key_authorizations_are_rejected_without_filtering` |
| MSO-06 | ISO §§8.1, 9.1.2.4 and selected extension policy | Preserve MSO/DeviceKeyInfo extensions and integer keyInfo. Positive RFU keyInfo labels are ignored for admission without discarding their values; an empty keyInfo map is permitted. Proprietary negative or undesignated zero labels and unknown security extensions require profile support. | `src/model/types.rs`; MSO parser; `src/verifier.rs` | `device_key_is_required_and_information_extensions_are_preserved`; `iso_boundaries::authenticated_rfu_key_information_is_preserved_without_extra_authority`; `unknown_authenticated_device_key_information_requires_explicit_profile_support`; `verifier_test::unauthenticated_future_mso_extension_is_not_silently_dropped` (the test re-signs the modified MSO); `validity_order_and_required_members_are_enforced`; `malformed_or_overlapping_key_authorizations_are_rejected_without_filtering` |
| ITEMS-01 | ISO §9.1.2.5; required | Hash received IssuerSignedItemBytes; require random salts of at least 16 bytes without reuse and authenticated namespace/digest references. | `src/model/issuer_signed_item.rs`; parser/verifier | `interop_test::annex_d_original_bytes_digests_and_issuer_signature`; `verifier_test::tampered_attribute_original_bytes_fail_digest`; `iso_boundaries::received_short_random_is_rejected_even_with_matching_authenticated_digests`; `received_random_reuse_is_rejected_within_and_across_namespaces`; `disclosed_namespace_and_digest_id_must_exist_in_the_authenticated_mso` |
| ITEMS-02 | Selective disclosure; required | Missing undisclosed values are permitted; supplied values must match authenticated digests without identifier collisions. | `src/verifier.rs`; `src/disclosure.rs` | `parser_security::issuer_namespaces_may_be_absent_but_cannot_be_an_explicit_empty_map`; `iso_boundaries::selective_disclosure_can_omit_one_item_or_the_complete_issuer_namespaces`; `received_duplicate_digest_ids_reject_even_identical_authenticated_items`; `received_duplicate_identifiers_reject_distinct_authenticated_digest_ids` |
| ITEMS-03 | Security extension boundary; required | Unknown item/issuer/device security fields cannot disappear during parsing. | `src/parser.rs` | `iso_boundaries::unknown_authenticated_item_semantics_cannot_be_dropped`; `unknown_issuer_and_device_security_fields_fail_closed`; `response_structure::unknown_or_duplicate_response_and_document_fields_fail_closed` |
| ITEMS-04 | Public/private input boundary; required | Wire-verification paths reuse the parser's item-uniqueness checks while models remain private. Standalone disclosure checks validate caller-mutable IDs, identifiers and salts before digest comparison. The caller supplies an authenticated MSO and consistent encoded metadata. | `src/parser.rs`; `src/disclosure.rs`; `src/verifier.rs` | `disclosure_boundary::standalone_disclosure_rejects_duplicate_decoded_digest_ids`; `standalone_disclosure_rejects_duplicate_decoded_identifiers`; `standalone_disclosure_rejects_reused_decoded_salts`; `standalone_disclosure_rejects_short_decoded_salts` |
| DEVICE-01 | ISO §§9.1.3.4, 9.1.3.6; required | Tag 24 DeviceAuthenticationBytes binds docType, transcript, received namespaces. | `src/session.rs`; `src/device_auth.rs` | `session_final::device_authentication_has_outer_tag24_and_exact_independent_encoding`; `device_authentication_retains_original_transcript_and_namespace_order`; `verifier_test::incorrect_session_binding_is_rejected`; `doc_type_is_bound_to_mso_and_holder_signature` |
| DEVICE-02 | ISO §9.1.3.4; required | Authenticated MSO key and explicit device-element authorization. | `src/verifier.rs`; `src/cose/key.rs`; `src/response_builder.rs` | `response_external::preparing_rejects_unauthorized_device_namespaces`; `element_authorizations_do_not_authorize_other_elements_in_same_namespace`; wrong-holder/docType regressions |
| DEVICE-03 | ISO §§9.1.3.5, 9.1.5.1; optional core API | EMacKey salt hashes Tag 24 SessionTranscriptBytes. | `src/session.rs` | `emac_key_matches_independent_hkdf_vector_with_tag24_salt` |
| DEVICE-04 | ISO §8.3.2.1.2.2; required | DeviceNameSpaces may be empty, but each namespace that occurs must contain at least one DeviceSignedItems entry. Check received, holder-signing and public payload-construction paths. | `src/parser.rs`; `src/response_builder.rs`; `src/session.rs` | `namespace_cardinality::device_namespace_cardinality_is_checked_before_authentication`; `response_external::preparing_rejects_empty_device_items_even_for_an_authorized_namespace`; `session_test::public_authentication_payload_checks_device_namespace_cardinality` |
| RESPONSE-01 | ISO §§8.1, 8.3.2.1.2.2; required | Parser validates shape/known status/count and preserves textual version and known error status; presentation authentication requires major version 1 and status 0, accepting numeric unknown minor versions. | `src/parser.rs`; `src/verifier.rs` | `response_structure::device_response_root_must_be_a_map`; `device_response_version_is_required_text_and_supported_for_verification`; `unknown_minor_response_version_reaches_authentication`; `device_response_status_is_required_unsigned_known_and_successful_for_verification`; `device_response_documents_are_required_nonempty_arrays`; `device_response_document_count_limits_apply_before_document_decoding`; `document_required_fields_reject_missing_empty_and_wrong_types`; `missing_device_signed_cannot_be_a_verified_presentation` |
| RESPONSE-02 | HAIP §5.3.1; optional profile | `max_documents = 1`; separate credentials use separate responses. A generic larger bound still returns no partial successes if any document fails. | Caller profile; parser/verifier | `verifier_test::haip_multiple_documents_are_rejected_before_partial_verification` tests both max 1 and max 2 with a damaged second signature |
| VERIFY-01 | ISO §9.3.1; required | Match docTypes; check current MSO validity and signed-time leaf-certificate interval, with inclusive endpoints and no loss of leap-second precision. | `src/verifier.rs` | `iso_boundaries::issued_doc_type_must_match_the_authenticated_mso_without_a_holder_proof`; `current_validity_includes_both_endpoints_and_rejects_adjacent_times`; `authenticated_mso_signed_time_is_contained_by_inclusive_leaf_certificate_bounds`; `whole_leap_second_is_not_truncated_to_the_certificate_last_regular_second` |
| VERIFY-02 | Trust boundary; required | Protocol-authenticated output remains pending external trust and revocation. | `src/verifier.rs` | `roundtrip_test::issuer_and_holder_roundtrip_has_pending_trust_not_a_final_valid_flag` |
| ISSUE-01 | OID4VCI A.2.4; optional profile | External signing input; verified completion; IssuerSigned assembly without key custody. | `src/builder.rs`; `src/encoder.rs::encode_issuer_signed` | `roundtrip_test::issue_and_verify_disclosure`; `signer_with_wrong_key_cannot_complete`; `state_reference_is_covered_by_issuer_signature`; `response_external::official_annex_d_signed_items_and_payloads_survive_encoding_exactly` |
| ISSUE-02 | Profile contract; required | Validate issuance fields and status, then enforce duplicate-key and resource limits on the encoded Tag 24 MSO. | `src/builder.rs`; `parse_status_ref`; `cbor::raw::validate` | `roundtrip_test::invalid_validity_order_cannot_be_issued`; `duplicate_attributes_cannot_be_issued`; `device_key_must_be_public_complete_and_on_a_supported_curve`; `ambiguous_element_value_is_rejected_before_external_signing`; `subsecond_clock_input_is_normalized_only_after_order_validation`; `normalization_cannot_hide_reversed_order_or_create_an_empty_interval` |
| ISSUE-03 | External holder signing; optional | Prepare Sig_structure; verify returned signature; emit detached DeviceSignature without key custody. | `src/response_builder.rs` | `response_external::external_holder_signs_sig_structure_and_finishes_a_detached_proof`; `external_holder_wrong_key_altered_input_and_der_signatures_are_rejected`; `preparing_rejects_algorithm_curve_mismatch_and_unsupported_algorithms` |
| ENCODE-01 | Original signed-byte integrity; required | Encoding retains raw protected headers, disclosures and namespaces; attaching a device payload is rejected. Raw Tag 24 fields must have exact framing; embedded content and resource budgets are checked in the complete output. | `src/encoder.rs` | `response_external::encoder_preserves_original_protected_header_bytes`; `encoder_never_substitutes_decoded_attributes_for_signed_item_bytes`; `encoder_cannot_silently_attach_a_device_signature_payload`; `official_annex_d_signed_items_and_payloads_survive_encoding_exactly`; `encoder_checks_raw_tag24_framing_and_embedded_contents_after_model_mutation`; `encoder_applies_budgets_to_the_complete_envelope` |

## Device-retrieval reader

The request/error APIs are available without features. Session operations require
`reader-session`; portable extended curves additionally require `reader-crypto`.
These features select implementation cost, not the standard's mandatory scope.

| ID | ISO 2021 contract | Implementation | Regression contract |
| --- | --- | --- | --- |
| READER-01 | §8.3.2.1.2.1 and §7.2.5: immutable Tag 24 ItemsRequest, typed retention intent, nonempty requested fields, requestInfo preservation, bounded DeviceRequest encoding and cumulative age limit. | `src/reader.rs`: `ItemsRequest`, `encode_device_request`; `ReaderSession` | `reader_requests::unsigned_requests_retain_exact_items_and_unknown_request_info`; `request_schema_rejects_ambiguous_or_empty_requested_elements`; `age_attestation_limit_applies_to_the_complete_request`; `session_reader::age_limit_spans_requests_and_failed_send_does_not_consume_budget` |
| READER-02 | §9.1.4: optional reader authentication binds exact request/transcript bytes, protected algorithm and unprotected x5chain; external completion verifies the signature. | `prepare_reader_authentication`; `PreparedReaderAuthentication::finish` | `reader_requests::independently_generated_reader_authentication_vector`; `reader_signature_binds_exact_request_transcript_and_certificate`; `external_completion_rejects_wrong_key_input_der_and_algorithm` |
| READER-03 | §§8.3.2.1.2.2–3: status-only, document and element errors retain raw untrusted fields; no partial credential admission. | `ResponseEnvelope`; `session::reader::ReaderResponse` | `reader_requests::status_only_and_document_errors_are_available_without_claims`; `mixed_document_errors_never_relax_atomic_presentation_verification`; `response_errors_reject_invalid_shapes_duplicates_and_trailing_bytes`; `session_reader::status_and_mixed_error_responses_never_contain_authenticated_claims` |
| READER-04 | §§8.2.1.1, 9.1.1, 9.1.5: original engagement/handover/key bytes; separate agreement-key roles; matching curves, checked points and fixed-width nonzero ECDH results. Reader EC2 is uncompressed; device EC2 permits compressed encoding. | `ReaderSession::new`; `AgreementPublicKey`; external `ReaderKeyAgreement` | `session_reader::agreement_roles_optional_parameters_and_invalid_points_are_checked_once`; `handover_roles_and_bounded_transcript_are_enforced`; `composed_transcript_and_encrypted_request_share_outer_resource_limits`; `session_agreement_curves::supported_table22_agreement_curves_match_independent_full_session_vectors` |
| READER-05 | §§9.1.3.4–5: HMAC-256/256 uses the issuer-authenticated SDevice key and this session's reader private key; detached payload, original protected bytes and the same disclosure/authorization checks as signatures. | `verify_device_mac`; shared `verify_parsed_presentation` | `session_reader::independent_full_session_mac_signature_and_directional_keys`; `authentication_failures_close_and_release_without_partial_claims` |
| READER-06 | §9.1.1: HKDF contexts, AES-256-GCM, distinct directional counters from 1, ordered request/response transitions, replay rejection and terminal key release. | `ReaderSession`; `SessionStatus` | `session_reader::independent_full_session_mac_signature_and_directional_keys`; `replay_order_and_wrong_session_fail_closed`; `terminal_data_is_authenticated_before_external_key_destruction`; `parallel_sessions_keep_counters_and_authentication_independent`; unit `directional_counter_exhaustion_terminates_without_wrap_or_reuse` |
| READER-07 | §§9.1.2.4, 9.1.3.6, 9.1.5.2: portable Brainpool P256/P384 and Ed448 across COSE, SPKI, borrowed and owned verification; P320/P512 remain unsupported. | `src/cose/reader_crypto.rs`; existing `VerificationKey` | `reader_crypto::independent_extended_curve_presentations_follow_the_compiled_capability`; `extended_curve_presentations_reject_changed_transcripts_signatures_and_claims`; `a_failed_extended_document_rejects_the_entire_response`; COSE units `independent_wycheproof_cases_cover_owned_borrowed_and_spki_paths`, `rfc8032_ed448_blank_and_one_octet_verify_without_prehashing`, `compressed_brainpool_keys_verify_and_reject_changed_parity_and_invalid_x`, `ed448_rejects_identity_forgery_and_noncanonical_points` |

The frozen reader-authentication and session fixtures are generated independently
using Python CBOR framing, Python cryptography and standard-library HKDF/HMAC.
The [portable cryptography corpus](../tests/vectors/reader_crypto/README.md)
records selected Wycheproof cases, RFC vectors, independent full presentations,
source revisions, licenses and hashes. These fixtures support their specified
protocol/algorithm cases; they are not the ISO/IEC TS 18013-6 conformance suite.

## Borrowed API and direct encoding regressions

Borrowed and owned entry points share the protocol checks above. These tests
add ownership, mutable-model and validation-proof coverage; they do not assert
that every operation is allocation-free.

| Contract | Implementation | Regression tests |
| --- | --- | --- |
| Text, bytes, tags, status, authorizations and certificate slices refer to the original input until explicit owned conversion. | `src/model/borrowed.rs`; parser and verifier | `borrowed::parsed_fields_and_authenticated_material_borrow_the_original_input`; `status_extensions_and_authorizations_remain_borrowed_until_explicit_conversion`; `value_views_keep_nested_spans_and_explicit_tag_identity`; `borrowed_verification::authenticated_large_values_headers_digests_and_certificates_borrow_wire_storage`; `issuer_only_authentication_borrows_the_credential_and_owns_only_on_request` |
| A cached MSO proof requires the same payload address/length and initial limits no looser than defaults in all four dimensions. Custom parsing cannot relax default holder limits. | `parser::parse_issuer_signed`; `IssuerAuthRef::mso` | Unit `mso_proof_cannot_be_reused_for_a_replaced_payload`; `borrowed::relaxed_parsing_limits_do_not_raise_default_holder_mso_limits` |
| Borrowed and owned authentication reject the same invalid evidence. Segmented verification preserves algorithm binding and strict Ed25519 rejection. | `src/verifier.rs`; `src/cose/verify.rs` | `borrowed_verification::borrowed_and_owned_entry_points_reject_the_same_authenticated_failures`; `external_ed25519_holder_signing_and_borrowed_verification_keep_strict_verification`; units `multipart_owned_borrowed_and_spki_paths_agree_for_all_algorithms`, `ed25519_single_and_multipart_paths_reject_a_weak_key_forgery` |
| Encoding preserves signed bytes after filtering or editing projections; replaced raw fields still require exact framing and complete-output budgets. | `src/encoder/borrowed.rs` | `borrowed_encoding::borrowed_encoding_matches_owned_and_preserves_annex_d_signed_bytes`; `encoding_uses_current_unsigned_fields_and_keeps_protected_bytes_authoritative`; `borrowed_items_can_be_filtered_and_reordered_without_decoding_the_signed_fields`; `mutated_raw_fields_require_exact_tag24_framing_and_valid_embedded_cbor`; `borrowed_encoding_applies_limits_to_the_complete_output` |
| Issuer verification, disclosure selection, external holder signing and final wire encoding work with borrowed documents; wrong signatures and unauthorized namespaces fail. | `src/response_builder.rs`; borrowed verifier/encoder | `borrowed_verification::borrowed_credential_disclosure_holder_signing_and_wire_output_form_one_flow`; `borrowed_holder_rejects_wrong_signatures_and_unauthorized_namespaces` |
| Direct item/MSO encoding matches canonical schema bytes, and measured lengths match encoded output at header-width boundaries. | `src/builder.rs`; `data_item::encoded_len` | Units `direct_mso_encoding_matches_independent_canonical_schema`, `borrowed_item_encoding_matches_schema_bytes_and_preserves_tag24`, `measured_length_matches_canonical_output_without_unbounded_recursion` |

## Encoding and extension rules

The accepted CBOR profile uses definite lengths, shortest integer/length
encodings and unique integer, text or byte-string map keys. It accepts booleans,
null and IEEE floats; compound keys, floating-point keys, undefined and other
simple values are rejected. Input map order is retained. Issuance orders maps
deterministically while preserving opaque signed Tag 24 contents.

Tags remain visible in claims and extensions, including Tags 2 and 3. Protocol
integer fields require native integers. Small bignums must be supplied as native
integers for deterministic issuance; larger bignums use minimal byte strings.

The presentation API requires a nonempty document type, successful response
status and at least one document. Unknown MSO/DeviceKeyInfo security extensions
require profile support. Positive RFU keyInfo labels are retained and ignored;
zero and negative labels require defined semantics. Status preserves every
member for application evaluation.

COSE headers use the selected alg/crit/kid/x5chain allowlist. Original protected
bytes must agree with their decoded fields. Unsupported critical labels reject.
ISO 2021's unprotected x5chain accepts a single certificate byte string or a
nonempty certificate array, including a one-element array. Every element must be
a nonempty byte string. Applications validate DER, paths and issuer identity.

Signature-purpose COSE keys retain the existing strict `alg`/`key_ops`/`base_iv`
profile. This is narrower than ISO §9.1.5.2's recommendation to ignore optional
key parameters. EReader/EDevice parsing ignores optional parameters; MSO SDevice
keys still pass common metadata syntax/profile checks before their MAC-specific
role validation. Neither path accepts private key material in a public key.

## Time

MSO validity requires Tag 0 with a 20-byte UTC whole-second timestamp and
`signed <= validFrom < validUntil`. Verification checks the current MSO interval
and signed-time containment within the leaf certificate validity interval.
Application path validation uses the current verification time.

`Timestamp` delegates calendar and RFC 3339 parsing to `time`. It accepts
case-insensitive `T`/`Z` letters under [RFC 3339 §5.6](https://www.rfc-editor.org/rfc/rfc3339.html#section-5.6),
permits at most nine ordinary fractional digits and retains whole leap seconds
distinctly. Fractional leap seconds are rejected. Comparison orders
`59.999999999 < 60 < next second`; Unix conversion returns `None` for `60`.
Formatting emits uppercase `T`/`Z` and preserves the leap label. Signed MSO bytes
remain unchanged. ISO's whole-second and UTC-designator restrictions apply equally
to uppercase and lowercase input.

[CGPM Resolution 5 (2026)](https://www.bipm.org/en/cgpm-2026/resolution-5)
sets continuous UTC from 20 May 2027. Historical
[RFC 3339 leap-second timestamps](https://www.rfc-editor.org/rfc/rfc3339.html#section-5.7)
remain part of the accepted wire format and retain their exact ordering during
validity and certificate-boundary checks.

The core migrated from Chrono after
[RUSTSEC-2026-0543](https://github.com/rustsec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md),
an unmaintained-package advisory. Historical benchmark baselines retain their
original dependencies.

## Final SessionTranscript

| Contract | Source | Implementation and tests |
| --- | --- | --- |
| Redirect binds full Client ID, nonce, optional encryption-key thumbprint and Response URI | OpenID4VP Final B.2.6.1 | `session.rs`; `final_redirect_matches_official_vector_and_borrows_validated_bytes`, `every_redirect_context_parameter_is_bound` |
| DC API binds its distinct handover and platform origin | OpenID4VP Final B.2.6.2 | `session.rs`; `final_dc_api_matches_official_vector_and_borrows_validated_bytes`, `every_dc_api_context_parameter_and_transport_is_bound` |
| JWK thumbprints use required members and canonical JSON | [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) | `official_thumbprint_excludes_optional_jwk_members` |
| Unencrypted mode uses null | OpenID4VP Final B.2.6 | `unencrypted_modes_bind_null_instead_of_empty_or_text_thumbprint` |
| Validation binds every byte to the supplied context | OpenID4VP Final B.2.6 | `every_byte_of_the_official_transcript_is_authenticated_by_context`, `rejects_old_draft_handover_as_final`, `structural_validation_rejects_malformed_nonminimal_or_trailing_cbor` |
| Generated and borrowed paths agree across contexts | Property test | `arbitrary_context_roundtrips_bind_and_match_ciborium` |

These tests are in `tests/session_final.rs`. Applications authenticate the request
context, select the actual response-encryption key and enforce nonce freshness.
`from_cbor` checks transcript structure; the Final validators additionally check
the supplied request binding.

## MSO status

Token Status List draft-21 §6.3 extends the original ISO 2021 MSO schema.
The library preserves the complete `status` value and projects a known
`status_list` reference with its unsigned index and original URI spelling.

| Contract | Tests in `tests/mso_security.rs` or `tests/tag_semantics.rs` |
| --- | --- |
| Preserve absent, known and unknown mechanisms distinctly | `absence_is_distinct_from_unknown_or_known_status`, `unknown_status_payloads_cannot_be_silently_discarded` |
| Reject malformed references and retain all unsigned indices | `malformed_status_is_never_treated_as_absence`, `all_unsigned_status_indices_are_preserved` |
| Check URI syntax and preserve spelling | `status_uri_uses_rfc3986_without_normalizing_or_authorizing_fetch` |
| Retain tags, unknown values and original payload bytes | `unknown_status_mechanism_retains_its_entire_tagged_value_and_payload_bytes`, `status_list_index_requires_a_native_unsigned_integer` |
| Bind issued status to the issuer signature | `roundtrip_test::state_reference_is_covered_by_issuer_signature` |

Applications evaluate supported mechanisms after issuer authentication, authorize
network requests, validate the status-list signature and signer, and apply
freshness, index and state policy. Issuers allocate indices and publish lists.
Certificate revocation and credential status are separate checks.

## Application responsibilities

| Library result | Application completion |
| --- | --- |
| Authenticated document, MSO, disclosure and holder proof | Requested claims, request freshness and authorization |
| Leaf-first certificate chain and optional checked DS profile | Trust anchors, X.509 path/signature validation and revocation; actual path/root evidence for library profile helpers |
| Complete authenticated status extension | Supported mechanism, list signature, authorized signer, URI, time, index and state |
| Transcript bound to supplied context | Authentic request context, encryption-key selection and nonce consumption |
| Immutable signing input and verified completion | Signing-key authorization, issuer policy and status publication |
| ReaderSession with validated agreement peers and ordered counters | Fresh private-key generation/destruction, actual ECDH, NFC/BLE/QR acquisition, retrieval-option processing, transport errors/closure and timers |
| Reader requests and untrusted protocol errors | Retention intent, requested-claim policy, reader identity/certificate policy and error presentation; no claims from error-bearing responses |

Runtime validation records identify exact revisions, feature sets, targets,
fuzz campaigns, advisory snapshots and measurements. The independent vectors
and code/test mapping above define the covered behavior.
