//! Protocol boundaries with authenticated inputs, distinct from final issuer trust.
#![cfg(feature = "issue")]

mod common;

use ciborium::Value;
use common::*;
use der::{Decode, Encode};
use nazo_mdoc::{MdocError, model::*, time::Timestamp, verifier::verify_issued};
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &value
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap()
        .1
}

fn field_mut<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    &mut value
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap()
        .1
}

fn encode(value: &Value) -> Vec<u8> {
    nazo_mdoc::cbor::data_item::encode_cbor(value).unwrap()
}

fn tagged(value: &Value) -> Vec<u8> {
    encode(&nazo_mdoc::cbor::data_item::encode_as_tag24(value).unwrap())
}

fn assert_issuer_signature(document: &IssuerSignedDocument) {
    let auth = &document.issuer_signed.issuer_auth;
    let leaf = x509_cert::Certificate::from_der(auth.certificate_der().unwrap()).unwrap();
    let key =
        nazo_mdoc::cose::key::cose_key_from_spki(leaf.tbs_certificate().subject_public_key_info())
            .unwrap();
    let sign1 = &auth.cose_sign1;
    assert!(
        nazo_mdoc::cose::verify_cose_signature(
            &sign1.tbs_data(&[]),
            &sign1.signature,
            &key,
            nazo_mdoc::cose::key::algorithms::ES256,
        )
        .unwrap(),
        "the intended rejection must not be a corrupt issuer signature"
    );
}

fn authenticate_mso(document: &mut IssuerSignedDocument, change: impl FnOnce(&mut Value)) {
    let sign1 = &mut document.issuer_signed.issuer_auth.cose_sign1;
    let inner = nazo_mdoc::cbor::raw::tag24_inner(sign1.payload.as_ref().unwrap()).unwrap();
    let mut value: Value = ciborium::from_reader(inner).unwrap();
    change(&mut value);
    sign1.payload = Some(tagged(&value));
    let signature: p256::ecdsa::Signature = issuer_key().sign(&sign1.tbs_data(&[]));
    sign1.signature = signature.to_bytes().to_vec();
    assert_issuer_signature(document);
}

fn parse_time(value: &str) -> Timestamp {
    Timestamp::parse_rfc3339(value).unwrap()
}

fn set_dates(
    document: &mut IssuerSignedDocument,
    signed: Timestamp,
    from: Timestamp,
    until: Timestamp,
) {
    authenticate_mso(document, |mso| {
        let dates = field_mut(mso, "validityInfo");
        for (name, date) in [
            ("signed", signed),
            ("validFrom", from),
            ("validUntil", until),
        ] {
            *field_mut(dates, name) =
                Value::Tag(0, Box::new(Value::Text(date.format_rfc3339().unwrap())));
        }
    });
}

fn expect_validity_rejection(document: &IssuerSignedDocument, at: Timestamp, reason: &str) {
    let result = verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, at);
    assert!(
        matches!(result, Err(MdocError::Validity(ref message)) if message.contains(reason)),
        "expected {reason}, received {result:?}"
    );
}

#[test]
fn authenticated_mso_signed_time_is_contained_by_inclusive_leaf_certificate_bounds() {
    let leaf = x509_cert::Certificate::from_der(&hex::decode(GENUINE_CERT_HEX).unwrap()).unwrap();
    let convert = |value: x509_cert::time::Time| {
        Timestamp::from_unix_seconds(value.to_unix_duration().as_secs().try_into().unwrap())
            .unwrap()
    };
    let before = convert(leaf.tbs_certificate().validity().not_before);
    let after = convert(leaf.tbs_certificate().validity().not_after);
    for (signed, accepted) in [
        (offset_seconds(before, -1), false),
        (before, true),
        (after, true),
        (offset_seconds(after, 1), false),
    ] {
        let mut document = issue(builder());
        set_dates(
            &mut document,
            signed,
            signed,
            offset_seconds(signed, 24 * 60 * 60),
        );
        let at = offset_seconds(signed, 1);
        if accepted {
            let pending =
                verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, at).unwrap();
            assert_eq!(pending.mso().validity_info.signed, signed);
        } else {
            expect_validity_rejection(&document, at, "outside signer certificate validity");
        }
    }
}

fn replace_public_fixture_certificate_dates(
    document: &mut IssuerSignedDocument,
    not_before: Timestamp,
    not_after: Timestamp,
) {
    // A fresh, genuinely self-signed public test certificate keeps certificate
    // corruption from being the explanation. It still is not a trust anchor.
    let original =
        x509_cert::Certificate::from_der(&hex::decode(GENUINE_CERT_HEX).unwrap()).unwrap();
    let to_time = |value: Timestamp| {
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(
                value.unix_seconds().unwrap().try_into().unwrap(),
            ))
            .unwrap(),
        )
    };
    use x509_cert::builder::{Builder, CertificateBuilder, profile::cabf::Root};
    let profile = Root::new(
        false,
        "CN=Public test fixture,O=nazo-mdoc tests,C=US"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let leaf = CertificateBuilder::new(
        profile,
        1u32.into(),
        x509_cert::time::Validity::new(to_time(not_before), to_time(not_after)),
        original.tbs_certificate().subject_public_key_info().clone(),
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(&issuer_key())
    .unwrap();
    let tbs = leaf.tbs_certificate().to_der().unwrap();
    let signature = p256::ecdsa::Signature::from_der(leaf.signature().as_bytes().unwrap()).unwrap();
    issuer_key()
        .verifying_key()
        .verify(&tbs, &signature)
        .unwrap();
    let headers = &mut document
        .issuer_signed
        .issuer_auth
        .cose_sign1
        .unprotected
        .rest;
    let (_, value) = headers
        .iter_mut()
        .find(|(label, _)| *label == coset::Label::Int(33))
        .unwrap();
    *value = Value::Bytes(leaf.to_der().unwrap());
}

#[test]
fn whole_leap_second_is_not_truncated_to_the_certificate_last_regular_second() {
    let regular = parse_time("2016-12-31T23:59:59Z");
    let leap = parse_time("2016-12-31T23:59:60Z");
    let next = parse_time("2017-01-01T00:00:00Z");
    assert!(leap.is_leap_second());
    assert!(leap.is_whole_second());
    assert_eq!(leap.unix_seconds(), None);
    assert_eq!(leap.unix_nanos(), None);
    assert_eq!(leap.format_rfc3339().unwrap(), "2016-12-31T23:59:60Z");
    assert!(regular < leap && leap < next);
    for (end, accepted) in [(regular, false), (next, true)] {
        let mut document = issue(builder());
        replace_public_fixture_certificate_dates(
            &mut document,
            parse_time("2016-01-01T00:00:00Z"),
            end,
        );
        set_dates(
            &mut document,
            leap,
            next,
            offset_seconds(next, 24 * 60 * 60),
        );
        assert_eq!(
            document
                .issuer_signed
                .issuer_auth
                .mso()
                .unwrap()
                .validity_info
                .signed,
            leap
        );
        if accepted {
            let pending =
                verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, next).unwrap();
            assert_eq!(pending.mso().validity_info.signed, leap);
        } else {
            expect_validity_rejection(&document, next, "outside signer certificate validity");
        }
    }
}

#[test]
fn current_validity_includes_both_endpoints_and_rejects_adjacent_times() {
    let document = issue(builder());
    let dates = validity();
    for at in [dates.valid_from, dates.valid_until] {
        let pending =
            verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, at).unwrap();
        assert_eq!(pending.mso().validity_info.valid_from, dates.valid_from);
        assert_eq!(pending.mso().validity_info.valid_until, dates.valid_until);
    }
    for at in [
        offset_seconds(dates.valid_from, -1),
        offset_seconds(dates.valid_until, 1),
    ] {
        expect_validity_rejection(&document, at, "not valid at verification time");
    }
}

#[test]
fn issued_doc_type_must_match_the_authenticated_mso_without_a_holder_proof() {
    let document = issue(builder());
    assert_issuer_signature(&document);
    let result = verify_issued(
        &document.to_issuer_signed_cbor().unwrap(),
        "org.example.anotherDocument",
        now(),
    );
    assert!(
        matches!(result, Err(MdocError::Mso(ref message)) if message.contains("docType differs"))
    );
}

#[test]
fn device_verification_key_requires_verification_use_and_no_base_iv() {
    use coset::{KeyOperation, iana::KeyOperation as Operation};
    let algorithm = nazo_mdoc::cose::key::algorithms::ES256;
    let mut key = device_key();
    nazo_mdoc::cose::validate_verification_key(&key, algorithm).unwrap();
    key.key_ops
        .insert(KeyOperation::Assigned(Operation::Verify));
    nazo_mdoc::cose::validate_verification_key(&key, algorithm).unwrap();
    key.key_ops.clear();
    key.key_ops.insert(KeyOperation::Assigned(Operation::Sign));
    assert!(nazo_mdoc::cose::validate_verification_key(&key, algorithm).is_err());
    key.key_ops.clear();
    key.base_iv = vec![0; 12];
    assert!(nazo_mdoc::cose::validate_verification_key(&key, algorithm).is_err());
}

#[test]
fn selective_disclosure_can_omit_one_item_or_the_complete_issuer_namespaces() {
    let complete = issue(builder());
    for keep in [0, 1] {
        let mut document = complete.clone();
        if keep == 0 {
            document.issuer_signed.name_spaces.clear();
        } else {
            document
                .issuer_signed
                .name_spaces
                .get_mut(NS)
                .unwrap()
                .truncate(keep);
        }
        let issued = document.to_issuer_signed_cbor().unwrap();
        let wire: Value = ciborium::from_reader(issued.as_slice()).unwrap();
        assert_eq!(
            wire.as_map()
                .unwrap()
                .iter()
                .any(|(key, _)| key.as_text() == Some("nameSpaces")),
            keep != 0,
            "all-hidden disclosure omits nameSpaces rather than emitting an empty map"
        );
        let pending = verify_issued(&issued, DOC_TYPE, now()).unwrap();
        assert_eq!(pending.mso().value_digests[NS].len(), 2);
        assert_eq!(
            pending
                .document()
                .issuer_signed
                .name_spaces
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            keep
        );
        let presented = present(document, &transcript());
        assert_eq!(
            verify(&presented.to_device_response_cbor().unwrap())
                .unwrap()
                .len(),
            1
        );
    }
}

fn edit_item(
    document: &mut IssuerSignedDocument,
    namespace: &str,
    index: usize,
    edit: impl FnOnce(&mut Value),
) {
    let item = &mut document
        .issuer_signed
        .name_spaces
        .get_mut(namespace)
        .unwrap()[index];
    let mut value: Value =
        ciborium::from_reader(nazo_mdoc::cbor::raw::tag24_inner(&item.encoded).unwrap()).unwrap();
    edit(&mut value);
    item.encoded = tagged(&value);
}

fn authenticate_received_item_digests(document: &mut IssuerSignedDocument) {
    let digests = Value::Map(
        document
            .issuer_signed
            .name_spaces
            .iter()
            .map(|(namespace, items)| {
                let values = items
                    .iter()
                    .map(|item| {
                        let value: Value = ciborium::from_reader(
                            nazo_mdoc::cbor::raw::tag24_inner(&item.encoded).unwrap(),
                        )
                        .unwrap();
                        (
                            field(&value, "digestID").clone(),
                            Value::Bytes(Sha256::digest(&item.encoded).to_vec()),
                        )
                    })
                    .collect();
                (namespace.clone().into(), Value::Map(values))
            })
            .collect(),
    );
    authenticate_mso(document, |mso| *field_mut(mso, "valueDigests") = digests);
}

fn expect_item_rejection(document: &IssuerSignedDocument, reason: &str) {
    assert_issuer_signature(document);
    let result = verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, now());
    assert!(
        matches!(result, Err(MdocError::Parse(ref message)) if message.contains(reason)),
        "expected {reason}, received {result:?}"
    );
}

#[test]
fn received_short_random_is_rejected_even_with_matching_authenticated_digests() {
    for length in [0, 1, 15] {
        let mut document = issue(builder());
        edit_item(&mut document, NS, 0, |item| {
            *field_mut(item, "random") = Value::Bytes(vec![7; length]);
        });
        authenticate_received_item_digests(&mut document);
        expect_item_rejection(&document, "random must be at least 16 bytes");
    }
}

#[test]
fn received_random_reuse_is_rejected_within_and_across_namespaces() {
    const OTHER: &str = "org.example.other";
    for (namespace, index) in [(NS, 1), (OTHER, 0)] {
        let mut document = issue(builder().add_namespace(OTHER, vec![("claim", true.into())]));
        let random = document.issuer_signed.name_spaces[NS][0].random.clone();
        edit_item(&mut document, namespace, index, |item| {
            *field_mut(item, "random") = Value::Bytes(random);
        });
        authenticate_received_item_digests(&mut document);
        expect_item_rejection(&document, "reused IssuerSignedItem random");
    }
}

#[test]
fn received_duplicate_digest_ids_reject_even_identical_authenticated_items() {
    let mut document = issue(builder());
    let items = document.issuer_signed.name_spaces.get_mut(NS).unwrap();
    items[1] = items[0].clone();
    // Both received copies are covered by the same authentic digest entry.
    expect_item_rejection(&document, "duplicate digestID or elementIdentifier");
}

#[test]
fn received_duplicate_identifiers_reject_distinct_authenticated_digest_ids() {
    let mut document = issue(builder());
    let name = document.issuer_signed.name_spaces[NS][0]
        .element_identifier
        .clone();
    assert_ne!(
        document.issuer_signed.name_spaces[NS][0].digest_id,
        document.issuer_signed.name_spaces[NS][1].digest_id
    );
    edit_item(&mut document, NS, 1, |item| {
        *field_mut(item, "elementIdentifier") = name.into();
    });
    authenticate_received_item_digests(&mut document);
    expect_item_rejection(&document, "duplicate digestID or elementIdentifier");
}

#[test]
fn disclosed_namespace_and_digest_id_must_exist_in_the_authenticated_mso() {
    const OTHER: &str = "org.example.other";
    for omit_namespace in [false, true] {
        let mut document = issue(builder().add_namespace(OTHER, vec![("claim", true.into())]));
        let digest_id = document.issuer_signed.name_spaces[NS][0].digest_id;
        authenticate_mso(&mut document, |mso| {
            let digests = field_mut(mso, "valueDigests");
            if omit_namespace {
                digests
                    .as_map_mut()
                    .unwrap()
                    .retain(|(key, _)| key.as_text() != Some(NS));
            } else {
                field_mut(digests, NS)
                    .as_map_mut()
                    .unwrap()
                    .retain(|(key, _)| {
                        key.as_integer().map(i128::from) != Some(i128::from(digest_id))
                    });
            }
        });
        document.issuer_signed.issuer_auth.mso().unwrap();
        let result = verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, now());
        let reason = if omit_namespace {
            "namespace absent from MSO"
        } else {
            "digestID absent from MSO"
        };
        assert!(
            matches!(result, Err(MdocError::Disclosure(ref message)) if message == reason),
            "expected {reason}, received {result:?}"
        );
    }
}

#[test]
fn unknown_authenticated_item_semantics_cannot_be_dropped() {
    let mut document = issue(builder());
    edit_item(&mut document, NS, 0, |item| {
        item.as_map_mut()
            .unwrap()
            .push(("future_security".into(), true.into()));
    });
    authenticate_received_item_digests(&mut document);
    expect_item_rejection(&document, "unsupported IssuerSignedItem field");
}

#[test]
fn compatible_minor_versions_preserve_issuer_and_holder_authentication() {
    let original = issue(builder());
    for version in ["1.1", "1.17", "01.002", "1.18446744073709551616"] {
        let mut document = original.clone();
        authenticate_mso(&mut document, |mso| {
            *field_mut(mso, "version") = version.into();
        });
        let pending =
            verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, now()).unwrap();
        assert_eq!(pending.mso().version, version);
        let document = present(document, &transcript());
        let mut response: Value =
            ciborium::from_reader(document.to_device_response_cbor().unwrap().as_slice()).unwrap();
        *field_mut(&mut response, "version") = version.into();
        let verified = verify(&encode(&response)).unwrap();
        assert_eq!(verified[0].mso().version, version);

        let wrong_session =
            nazo_mdoc::session::SessionTranscript::redirect(nazo_mdoc::session::RedirectHandover {
                client_id: "x509_san_dns:example.com",
                nonce: "a-different-request",
                jwk_thumbprint: None,
                response_uri: "https://example.com/response",
            })
            .unwrap();
        assert!(matches!(
            nazo_mdoc::verify_presentation(
                &encode(&response),
                &wrong_session,
                &nazo_mdoc::VerificationOptions {
                    now: now(),
                    max_documents: 1
                },
            ),
            Err(MdocError::DeviceAuth(_))
        ));
    }
}

#[test]
fn authenticated_rfu_key_information_is_preserved_without_extra_authority() {
    let original = issue(builder());
    for info in [
        Value::Map(vec![]),
        Value::Map(vec![
            (1.into(), Value::Tag(60000, Box::new("reserved".into()))),
            (u64::MAX.into(), Value::Bytes(vec![1, 2, 3])),
        ]),
    ] {
        let mut document = original.clone();
        authenticate_mso(&mut document, |mso| {
            field_mut(mso, "deviceKeyInfo")
                .as_map_mut()
                .unwrap()
                .push(("keyInfo".into(), info.clone()));
        });
        let pending =
            verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, now()).unwrap();
        assert_eq!(pending.mso().device_key_info.key_info, Some(info.clone()));
        let unauthorized = tagged(&Value::Map(vec![(
            NS.into(),
            Value::Map(vec![("device_claim".into(), true.into())]),
        )]));
        assert!(matches!(
            nazo_mdoc::response_builder::prepare_device_authentication(
                document.clone(),
                &transcript(),
                unauthorized,
                -7,
            ),
            Err(MdocError::DeviceAuth(_))
        ));
        let document = present(document, &transcript());
        let verified = verify(&document.to_device_response_cbor().unwrap()).unwrap();
        assert_eq!(verified[0].mso().device_key_info.key_info, Some(info));
    }
}

#[test]
fn unknown_authenticated_device_key_information_requires_explicit_profile_support() {
    for (name, extension) in [
        ("future_security", Value::Bool(true)),
        (
            "keyInfo",
            Value::Map(vec![((-1).into(), "proprietary".into())]),
        ),
    ] {
        let mut document = issue(builder());
        authenticate_mso(&mut document, |mso| {
            field_mut(mso, "deviceKeyInfo")
                .as_map_mut()
                .unwrap()
                .push((name.into(), extension));
        });
        let parsed = document.issuer_signed.issuer_auth.mso().unwrap();
        if name == "keyInfo" {
            assert!(parsed.device_key_info.key_info.is_some());
        } else {
            assert!(parsed.device_key_info.additional_fields.contains_key(name));
        }
        let result = verify_issued(&document.to_issuer_signed_cbor().unwrap(), DOC_TYPE, now());
        assert!(
            matches!(result, Err(MdocError::Mso(ref message)) if message.contains("unsupported MSO or DeviceKeyInfo extension"))
        );
    }
}

#[test]
fn unknown_issuer_and_device_security_fields_fail_closed() {
    let document = present(issue(builder()), &transcript());
    assert_issuer_signature(&document);
    let original: Value =
        ciborium::from_reader(document.to_device_response_cbor().unwrap().as_slice()).unwrap();
    for path in [
        &["issuerSigned"][..],
        &["deviceSigned"][..],
        &["deviceSigned", "deviceAuth"][..],
    ] {
        let mut wire = original.clone();
        let mut target = &mut field_mut(&mut wire, "documents").as_array_mut().unwrap()[0];
        for name in path {
            target = field_mut(target, name);
        }
        target
            .as_map_mut()
            .unwrap()
            .push(("future_security".into(), true.into()));
        assert!(
            matches!(verify(&encode(&wire)), Err(MdocError::Parse(_))),
            "path {path:?}"
        );
    }
}
