# Migrating from the NazoAuth mdoc-rs production branch

## Version and source

The compatibility baseline is `mdoc-rs 0.2.0` at
`9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`, on
`nazoauth/patched-rustcrypto`. The package becomes `nazo-mdoc 0.3.0` and the Rust
crate is `nazo_mdoc`. The Git repository name remains unchanged. Existing pins
continue resolving their old package and code; no redirect or republished old
version is required. Downstream migration is a single, reviewable API update,
not a permanent compatibility wrapper.

A workspace should declare `nazo-mdoc` using a full Git `rev`, use
`default-features = false, features = ["issue"]` where issuance is needed, and
remove the old `[patch.crates-io].mdoc-rs` override. Do not point `mdoc-rs` at a
revision whose package is named `nazo-mdoc`. Regenerate Cargo.lock from the full
resolved graph. Keep independent WebAuthn revisions intact. A combined integration
branch must resolve both dependencies together rather than choose one lockfile.

## API changes

| Previous API/representation | Replacement |
| --- | --- |
| `Verifier`, `VerifyOptions`, `VerifiedMDoc.is_valid`, assessments | `verify_presentation` + explicit time/profile + `PendingTrustDocument` |
| Mutable assessment overrides to compensate for duplicate checks | One protocol authentication followed by the host's trust/status decision |
| `disable_certificate_chain_validation` | Removed; core never claims to establish certificate trust |
| `CoseSigner`, `DocumentBuilder::sign` | `prepare(CoseAlgorithm, chain)` → external signature → `finish(signature)` |
| `DeviceResponseBuilder` with private keys | `prepare_device_authentication` → external signature → `finish` |
| `SessionTranscript::Raw` unchecked bytes | `from_cbor` structural check, or a Final context-bound validator |
| Old `Oid4vp` with `mdoc_nonce` | Final Redirect/DC API contexts and official-vector-backed constructors |
| `IssuerSignedItem.encoded` inner map bytes | Complete received IssuerSignedItemBytes (Tag 24 + bstr + map) |
| `DeviceSigned.name_spaces_bytes` inner map bytes | Complete received DeviceNameSpacesBytes, copied verbatim into DeviceAuthenticationBytes |
| `Mso.device_key_info: Option<_>` | Mandatory DeviceKeyInfo |
| Repeated MSO decoding by verifier and host | Authenticate/decode once; consume the returned immutable MSO |
| Automatic schema inference from attribute names | Explicit namespace/schema mapping in the caller; core preserves typed values |
| Implicit optional TSP/HTTP/PKCS11/engagement dependencies | Removed from the protocol core |
| Chrono `DateTime<Utc>` in validity and verifier options | Core `Timestamp`; explicit, fallible Unix conversion and leap-second-preserving RFC3339 |

The raw encoded fields are authoritative. Editing a public decoded
`element_value` does not edit its signed wire bytes. To issue a different claim,
use a new builder and signature. `verify_issued` and `verify_presentation` take
wire bytes and rebuild authenticated claim projections; the digest helper alone
must not be used to certify arbitrary mutable model fields.

`ValidityInfo` is encoded as Tag 0 UTC whole seconds. Builders validate ordering
before and after conversion to whole seconds; malformed wire timestamps,
epoch tags, fractional seconds and non-Z offsets are rejected. Signed time must
fall inside the leaf certificate validity interval. Current credential validity
is checked against the explicit verification time.

The core no longer depends on the unmaintained Chrono crate
([RUSTSEC-2026-0543](https://rustsec.org/advisories/RUSTSEC-2026-0543.html)).
`Timestamp::from_unix_nanos`/`from_unix_seconds` construct ordinary instants;
`parse_rfc3339` preserves leap seconds and `format_rfc3339` renders UTC.
`unix_seconds`/`unix_nanos` return `None` for leap seconds. An application still
using another date library must preserve this distinction at its boundary; it
must not map a leap second to the preceding ordinary second for a trust decision.
`truncate_to_second` removes subsecond precision while preserving the leap marker.
This type is an mdoc UTC instant, not a general time-zone or duration library.

## Security checks transferred to the host

A successful `PendingTrustDocument` guarantees issuer/holder cryptographic
verification, signed docType binding, MSO structure/validity, leaf signing-time
interval, disclosure hashes and device key authorizations. It explicitly leaves
X.509 trust anchoring, certificate revocation, MSO status evaluation, request
freshness/replay policy, requested claims and business authorization unfinished.
There is no way to convert this into a final-valid core result by switching off
one of these responsibilities.

NazoAuth consumes this result inside its existing verifier pipeline. Its chain
validation uses the complete leaf-first chain; its status verifier rejects unknown
mechanisms, malformed references, invalid/untrusted lists, unavailable servers,
revoked/suspended/unknown values and out-of-range indices. Those checks run before
NazoAuth constructs a verified credential. An authenticated MSO with an unsupported
status remains `Some(status)` and cannot become a credential without a status.

The library's `status_list`/`status_raw` builders only encode an explicit issuer
choice. They are not allocation or publication services. NazoAuth's issuance
integration defaults to no status issuance. Enabling its published-list policy
requires an existing valid list, authorized URI/index, matching issuer trust and
an active index; no fictitious reference is synthesized without publication.

## Limits and interoperability

The generic parser permits bounded multiple-document responses, while the HAIP
profile rejects counts other than one before verifying individual documents.
Verification of a multi-document response is atomic: an error returns no partial
successful results. Batches of separate responses can be isolated by the host's
explicit presentation policy.

The server profile requires detached device signatures. Unsupported DeviceMAC
presentations fail closed. The separate MAC primitive accepts a caller-derived
EMacKey and verifies HMAC-256/256; it does not take ECDH private keys or implicitly
establish reader-key/session binding. Full proximity device engagement and reader
authentication are outside the server core.
