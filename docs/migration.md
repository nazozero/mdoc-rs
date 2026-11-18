# Migrating from mdoc-rs 0.2.0

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
seconds and non-`Z` offsets.

`Timestamp::parse_rfc3339` preserves whole leap seconds, and `format_rfc3339`
renders UTC. `unix_seconds` and `unix_nanos` return `None` for leap seconds.
Consumers using another time type must handle that case explicitly;
`truncate_to_second` retains the leap-second marker.

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
