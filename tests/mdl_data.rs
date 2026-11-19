#![cfg(feature = "issue")]
mod common;

use ciborium::Value;
use common::*;
use nazo_mdoc::{builder::DocumentBuilder, model::CoseAlgorithm};
use signature::{Signer, Verifier};

fn tagged(tag: u64, text: &str) -> Value {
    Value::Tag(tag, Box::new(text.into()))
}
fn map(fields: &[(&str, Value)]) -> Value {
    Value::Map(
        fields
            .iter()
            .map(|(key, value)| ((*key).into(), value.clone()))
            .collect(),
    )
}
fn prepare(
    doc_type: &str,
    name: &str,
    value: Value,
) -> Result<nazo_mdoc::builder::PreparedDocument, nazo_mdoc::MdocError> {
    DocumentBuilder::new(doc_type)
        .add_namespace(NS, vec![(name, value)])
        .device_key(device_key())
        .validity(validity())
        .prepare(
            CoseAlgorithm::ES256,
            vec![hex::decode(GENUINE_CERT_HEX).unwrap()],
        )
}

// Issue a generic document, then authenticate an mDL MSO over its unchanged item
// digests. This bypasses the mDL builder validation for the negative reader case.
fn signed_mdl(name: &str, value: Value) -> Vec<u8> {
    let prepared = prepare("example.test", name, value).unwrap();
    let signature: p256::ecdsa::Signature = issuer_key().sign(prepared.signing_input());
    let mut document = prepared.finish(signature.to_bytes().to_vec()).unwrap();
    document.doc_type = DOC_TYPE.into();
    let auth = &mut document.issuer_signed.issuer_auth.cose_sign1;
    let mut mso: Value = ciborium::from_reader(
        nazo_mdoc::cbor::raw::tag24_inner(auth.payload.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    mso.as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(name, _)| name.as_text() == Some("docType"))
        .unwrap()
        .1 = DOC_TYPE.into();
    auth.payload = Some(
        nazo_mdoc::cbor::encode_cbor(&nazo_mdoc::cbor::data_item::encode_as_tag24(&mso).unwrap())
            .unwrap(),
    );
    let signature: p256::ecdsa::Signature = issuer_key().sign(&auth.tbs_data(&[]));
    issuer_key()
        .verifying_key()
        .verify(&auth.tbs_data(&[]), &signature)
        .unwrap();
    auth.signature = signature.to_bytes().to_vec();
    document.to_issuer_signed_cbor().unwrap()
}

#[test]
fn mdl_data_types_are_authoritative_for_issuance_and_signed_verification() {
    let privilege = |date| {
        Value::Array(vec![map(&[
            ("vehicle_category_code", "B".into()),
            ("issue_date", date),
        ])])
    };
    let cases = vec![
        ("family_name", "Lindqvist".into(), true),
        ("family_name", Value::Text("A".repeat(151)), false),
        ("family_name", "李".into(), false),
        ("family_name_national_character", "李".into(), true),
        ("portrait", Value::Bytes(vec![0xff, 0xd8, 0xff]), true),
        ("portrait", "base64-is-an-application-mapping".into(), false),
        ("birth_date", tagged(1004, "1990-02-28"), true),
        ("birth_date", tagged(0, "1990-02-28T00:00:00Z"), false),
        ("birth_date", tagged(1004, "1990-02-29"), false),
        ("birth_date", "1990-02-28".into(), false),
        ("issue_date", tagged(0, "2026-11-17T12:00:00Z"), true),
        ("issue_date", tagged(1004, "2026-11-17"), true),
        ("issue_date", tagged(0, "2026-11-17T12:00:01Z"), false),
        ("issue_date", tagged(1004, "2026-11-18"), false),
        ("expiry_date", tagged(0, "2027-01-01T00:00:00+00:00"), false),
        ("expiry_date", tagged(0, "2027-01-01T00:00:00.1Z"), false),
        ("expiry_date", tagged(1004, "2027-01-01"), true),
        (
            "portrait_capture_date",
            tagged(0, "2026-01-01T00:00:00Z"),
            true,
        ),
        ("portrait_capture_date", tagged(1004, "2026-01-01"), false),
        ("driving_privileges", Value::Array(vec![]), true),
        (
            "driving_privileges",
            privilege(tagged(1004, "2020-01-01")),
            true,
        ),
        (
            "driving_privileges",
            privilege(tagged(0, "2020-01-01T00:00:00Z")),
            false,
        ),
        (
            "driving_privileges",
            Value::Array(vec![map(&[("issue_date", tagged(1004, "2020-01-01"))])]),
            false,
        ),
        (
            "driving_privileges",
            Value::Array(vec![map(&[
                ("vehicle_category_code", "B".into()),
                ("codes", Value::Array(vec![])),
            ])]),
            false,
        ),
        ("age_over_21", true.into(), true),
        ("age_over_21", 1u64.into(), false),
        ("age_over_100", true.into(), false),
        ("height", (-1i64).into(), false),
        ("sex", 9u64.into(), true),
        ("sex", 3u64.into(), false),
        ("eye_colour", "green".into(), true),
        ("eye_colour", "purple".into(), false),
        ("hair_colour", "auburn".into(), true),
        ("issuing_country", "SE".into(), true),
        ("issuing_country", "se".into(), false),
        ("issuing_jurisdiction", "SE-AB".into(), true),
        ("issuing_jurisdiction", "SE-ab".into(), false),
        (
            "biometric_template_face",
            Value::Bytes(vec![0x7f, 0x61, 0]),
            true,
        ),
        (
            "biometric_template_face",
            Value::Bytes(vec![0x75, 0x7f, 0x61, 0]),
            false,
        ),
        (
            "biometric_template_",
            Value::Bytes(vec![0x7f, 0x61, 0]),
            false,
        ),
    ];
    for (name, value, accepted) in cases {
        let issued = prepare(DOC_TYPE, name, value.clone());
        assert_eq!(issued.is_ok(), accepted, "builder: {name}={value:?}");
        let encoded = signed_mdl(name, value.clone());
        let verified = nazo_mdoc::verify_issued_borrowed(&encoded, DOC_TYPE, now());
        assert_eq!(
            verified.is_ok(),
            accepted,
            "reader: {name}={value:?}: {verified:?}"
        );
    }
}

#[test]
#[cfg(feature = "certificate-profile")]
fn authenticated_country_and_jurisdiction_are_checked_before_pending_trust() {
    for (name, value) in [("issuing_country", "US"), ("issuing_jurisdiction", "US-CA")] {
        assert!(prepare(DOC_TYPE, name, value.into()).is_err());
        let encoded = signed_mdl(name, value.into());
        assert!(matches!(
            nazo_mdoc::verify_issued_borrowed(&encoded, DOC_TYPE, now()),
            Err(nazo_mdoc::MdocError::CertificateProfile(_))
        ));
    }
}

#[test]
fn same_country_jurisdiction_binding_is_enforced_without_certificate_profiles() {
    let result = DocumentBuilder::new(DOC_TYPE)
        .add_namespace(
            NS,
            vec![
                ("issuing_country", "SE".into()),
                ("issuing_jurisdiction", "CA-ON".into()),
            ],
        )
        .device_key(device_key())
        .validity(validity())
        .prepare(
            CoseAlgorithm::ES256,
            vec![hex::decode(GENUINE_CERT_HEX).unwrap()],
        );
    assert!(result.is_err());
}
