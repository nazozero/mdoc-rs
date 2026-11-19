# Migration

## 0.3 to 0.4

Version 0.4 adds the feature-gated public `MdocError::CertificateProfile` variant.
`MdocError` is exhaustively matchable; feature unification can expose this variant
to a downstream exhaustive match. Update those matches when enabling the feature.
Existing verification and signing entry points remain available.

ISO mDL values supplied to the builder or disclosed to verification now undergo
Table 5 type/date validation. Standard fields cannot be supplied as DeviceSigned
even with KeyAuthorizations. Reissue incorrectly encoded credentials; do not
repair authenticated bytes in storage. Partial disclosures and partial issuance
inputs remain supported; completeness of a full licence is a separate admission
decision.

Applications previously implementing Annex B should enable `certificate-profile`
and remove their duplicate intrinsic DS checks. Both verification entry points
and `DocumentBuilder::prepare` perform these checks automatically. Borrowed
pending results expose `leaf_certificate()` for path integration; `into_parts`
still returns the original document/MSO/DER slices. Without the feature, all
certificate profile checks remain pending with the caller. Success never implies
that the issuer is trusted.

Use `check_iaca_profile` at root admission, `check_issuer_binding` with the actual
DS issuer, and `check_iaca_link_profile(link, old_root, new_root)` for rollover.
The caller authenticates link/root signatures and validates both root profiles;
the helper does not derive root validity from a cross-signed intermediate.
Use `check_x5chain_root_exclusion` once the path engine identifies the anchor.
Keep certificate path/revocation engines, tenant trust stores and HSM operations
in the application. `FullDateRef` and `validate_date_tag` replace allocating
full-date validation in JSON adapters; adapters still choose the JSON mapping.

The feature adds borrowed `x509-parser 0.18.1` public types. Strict DER still
uses the existing `x509-cert` decoder because the parsers have different input
acceptance boundaries. The empty default feature set and core crypto support
are unchanged.

## mdoc-rs 0.2.0 to nazo-mdoc 0.3

The compatibility baseline is `mdoc-rs 0.2.0` at
`9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`. Version 0.3 uses package name
`nazo-mdoc` and Rust crate name `nazo_mdoc` in the same repository.

Update the dependency to a tested full Git revision and remove any old
`[patch.crates-io].mdoc-rs` override. Enable `issue` for signing preparation and
encoding, then regenerate the consumer's lockfile.

## API changes

| Previous API or representation | Replacement |
| --- | --- |
| `MDoc` and `DeviceResponse` | Shared `DeviceResponse` model |
| `Verifier`, `VerifyOptions`, assessments and `VerifiedMDoc.is_valid` | `verify_presentation`, explicit time/document limit and `PendingTrustDocument` |
| Library certificate trust store and validation switches | Application X.509 trust and revocation policy |
| `CoseSigner`, `DocumentBuilder::sign` | `prepare(CoseAlgorithm, chain)` → external signature → `finish(signature)` |
| `DeviceResponseBuilder` with private keys | `prepare_device_authentication` → external signature → `finish` |
| `SessionTranscript::Raw` | `from_cbor` for structure, Final `validate_*` methods for context binding |
| Draft `Oid4vp` handover with `mdoc_nonce` | Final Redirect and DC API handovers |
| `IssuerSignedItem.encoded` inner map | Complete IssuerSignedItemBytes: Tag 24, byte string and map |
| `DeviceSigned.name_spaces_bytes` inner map | Complete DeviceNameSpacesBytes |
| Optional `Mso.device_key_info` | Required DeviceKeyInfo |
| Repeated MSO decoding in the consumer | Authenticated MSO available from the pending result |
| Automatic date-tag inference | Explicit CBOR types selected by the caller's schema |
| TSP, HTTP, PKCS11 and engagement dependencies | Application components |
| Chrono validity and verifier time | `Timestamp` |

Encoded fields are authoritative. Changing a decoded claim requires rebuilding
and signing the credential. `verify_issued` and `verify_presentation` accept wire
bytes and construct authenticated projections from them.

## Borrowed APIs and owned storage

Keep the input buffer alive while using these views:

| Operation | Borrowed entry point | Result |
| --- | --- | --- |
| Parse a response or issued credential | `parser::parse_borrowed`, `parser::parse_issued_borrowed` | `DeviceResponseRef`, `IssuerSignedRef`; untrusted until authenticated |
| Authenticate issuer and holder | `verify_presentation_borrowed` | `Vec<PendingTrustDocumentRef>` |
| Authenticate an issued credential | `verify_issued_borrowed` | `PendingIssuerTrustDocumentRef` |
| Encode existing borrowed fields (`issue`) | `encoder::encode_device_response_borrowed`, `encoder::encode_issuer_signed_borrowed` | Owned wire bytes, preserving original signed fields |
| Prepare an external holder signature (`issue`) | `response_builder::prepare_device_authentication_borrowed` | `PreparedDeviceAuthenticationRef`; `finish(&signature)` returns DeviceResponse bytes |

`CborValueRef` exposes typed values and their original encoding without first
building a `ciborium::Value` tree. Use its `to_owned()` for one owned value, or
the model/pending result's `into_owned()` for independent storage. Cloning a
borrowed model still borrows its input. Pending results also offer `into_parts()`
to move out the document, MSO and certificate references for selective disclosure.

`parse`, `parse_issued`, `verify_issued` and `verify_presentation` return owned
results through the same borrowed core. Custom parsing limits do not raise the
default MSO limits of holder preparation. Borrowed holder preparation retains one
contiguous `signing_input()` for the external signer and writes the completed
response directly after checking the signature.

## Cryptographic dependency types

This revision uses the versions in [Cargo.toml](../Cargo.toml) and
[Cargo.lock](../Cargo.lock). Consumers passing cryptographic types across API
boundaries must align their dependencies:

| Type family | Current versions | Consumer adjustment |
| --- | --- | --- |
| DER, OIDs and certificates | `der 0.8.3`, `const-oid 0.10.3`, `x509-cert 0.3.0`, `spki 0.8.1` | `cose_key_from_spki` accepts the SPKI type reexported by x509-cert 0.3. Certificate fields now use accessors such as `tbs_certificate().subject_public_key_info()`. Use the upstream certificate builder for construction. |
| ECDSA and signature traits | `p256`, `p384`, `p521` 0.14.0; `signature 3.0.0` | Use the matching `Signer`/`Verifier` traits and return fixed-width raw ECDSA signatures to `finish`. |
| Ed25519 | `ed25519-dalek 3.0.0` | The old `std` feature is removed. Verification retains `verify_strict`; multipart Ed25519 input is joined because the upstream multipart API does not provide the same strict checks. |
| Hashes, HMAC and HKDF | `sha2 0.11.1`, `hmac 0.13.0`, `hkdf 0.13.0` | Use the current digest types together. HMAC construction needs `hmac::KeyInit` in scope alongside `Mac`. |

Types from older DER/SPKI or signature crate majors are distinct Rust types;
unchanged DER or COSE wire formats do not make them interchangeable. COSE model
arguments remain `coset 0.4.2` types. The library's certificate-builder and P-256
PKCS#8 features are enabled only for its tests.

## Verification and trust

`PendingTrustDocument` contains verified issuer and holder signatures, disclosure
hashes, document-type binding, MSO validity, signer certificate time containment
and device-key authorizations. Complete X.509 path validation, certificate
revocation, credential status, request freshness and authorization before
admitting it as a trusted credential.

The MSO preserves unknown status mechanisms and members. Applications must
evaluate the entire authenticated extension under their supported status policy.
The `status_list` and `status_raw` builders encode the issuer's supplied value;
status-index allocation, authorization and list publication belong to the issuer
application.

## Time

MSO dates use Tag 0 and UTC whole seconds. Builders check ordering before and
after truncating subsecond input. The parser rejects epoch tags, fractional MSO
seconds and numeric UTC offsets. MSO and mDL timestamps accept `T`/`t` and `Z`/`z`
as required by RFC 3339 §5.6; authenticated input bytes are preserved.

`Timestamp::parse_rfc3339` preserves whole leap seconds, and `format_rfc3339`
renders UTC with uppercase `T`/`Z`. `unix_seconds` and `unix_nanos` return `None`
for leap seconds. Consumers using another time type must handle that case
explicitly; `truncate_to_second` retains the leap-second marker.

## Existing credentials

The baseline issuer generated digest IDs across the full `u32` range.
ISO/IEC 18013-5:2021 §9.1.2.4 requires IDs below `2^31`. Version 0.3 checks this
bound in every MSO digest map and disclosed item.

Inventory previously issued credentials before rollout. Reissue credentials with
out-of-range IDs through the authorized signing path: both the item digests and
MSO signature must be rebuilt. Omitting an affected disclosure leaves its MSO
entry in place. Test the remaining credential population against the current
encoding and verification profile.

## Presentations

The parser accepts bounded multi-document responses. Set the verification limit
to 1 for HAIP. A failed document rejects the whole response.

`verify_presentation` requires detached DeviceSignature. Applications using
DeviceMAC call the separate primitive with an established EMacKey and enforce
reader-key/session binding in their transport protocol.
