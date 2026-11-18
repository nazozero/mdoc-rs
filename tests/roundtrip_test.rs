//! Issuance/presentation interoperability using independent external signers.
#![cfg(feature = "issue")]
mod common;
use common::*;
use nazo_mdoc::{MdocError, model::*};

#[test]
fn issue_and_verify_disclosure() {
    let document = issue(builder());
    let bytes = document.to_issuer_signed_cbor().unwrap();
    let pending = nazo_mdoc::verifier::verify_issued(&bytes, DOC_TYPE, now()).unwrap();
    assert_eq!(pending.mso().doc_type, DOC_TYPE);
    assert_eq!(pending.document().issuer_signed.name_spaces[NS].len(), 2);
    assert_eq!(
        pending.certificates()[0],
        hex::decode(GENUINE_CERT_HEX).unwrap()
    );
}

#[test]
fn issuer_and_holder_roundtrip_has_pending_trust_not_a_final_valid_flag() {
    let document = present(issue(builder()), &transcript());
    let result = verify(&document.to_device_response_cbor().unwrap()).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].mso().doc_type, DOC_TYPE);
    assert!(result[0].mso().status.is_none());
}

#[test]
fn expected_update_is_signed_and_preserved() {
    let mut dates = validity();
    dates.expected_update = Some(offset_seconds(now(), 24 * 60 * 60));
    let document = issue(builder().validity(dates.clone()));
    assert_eq!(
        document
            .issuer_signed
            .issuer_auth
            .mso()
            .unwrap()
            .validity_info
            .expected_update,
        dates.expected_update
    );
}

#[test]
fn invalid_validity_order_cannot_be_issued() {
    let mut dates = validity();
    dates.valid_from = offset_seconds(dates.valid_from, -60 * 60);
    assert!(
        builder()
            .validity(dates)
            .prepare(
                CoseAlgorithm::ES256,
                vec![hex::decode(GENUINE_CERT_HEX).unwrap()]
            )
            .is_err()
    );
}

#[test]
fn signer_with_wrong_key_cannot_complete() {
    use signature::Signer;
    let prepared = builder()
        .prepare(
            CoseAlgorithm::ES256,
            vec![hex::decode(GENUINE_CERT_HEX).unwrap()],
        )
        .unwrap();
    let signature: p256::ecdsa::Signature = holder_key().sign(prepared.signing_input());
    assert!(matches!(
        prepared.finish(signature.to_bytes().to_vec()),
        Err(MdocError::Signature(_))
    ));
}

#[test]
fn duplicate_attributes_cannot_be_issued() {
    assert!(
        builder()
            .add_namespace(NS, vec![("family_name", "duplicate".into())])
            .prepare(
                CoseAlgorithm::ES256,
                vec![hex::decode(GENUINE_CERT_HEX).unwrap()]
            )
            .is_err()
    );
}

#[test]
fn state_reference_is_covered_by_issuer_signature() {
    let document = issue(builder().status_list(42, "https://issuer.example/status/1"));
    let pending = nazo_mdoc::verifier::verify_issued(
        &document.to_issuer_signed_cbor().unwrap(),
        DOC_TYPE,
        now(),
    )
    .unwrap();
    assert_eq!(
        pending
            .mso()
            .status
            .as_ref()
            .unwrap()
            .status_list
            .as_ref()
            .unwrap()
            .idx,
        42
    );
}

#[test]
fn subsecond_clock_input_is_normalized_only_after_order_validation() {
    let mut dates = validity();
    dates.signed = offset_milliseconds(dates.signed, 100);
    dates.valid_from = offset_milliseconds(dates.valid_from, 200);
    dates.valid_until = offset_milliseconds(dates.valid_until, 300);
    let result = issue(builder().validity(dates));
    let actual = result
        .issuer_signed
        .issuer_auth
        .mso()
        .unwrap()
        .validity_info;
    assert_eq!(actual.signed, validity().signed);
    assert_eq!(actual.valid_from, validity().valid_from);
    assert_eq!(actual.valid_until, validity().valid_until);
}

#[test]
fn normalization_cannot_hide_reversed_order_or_create_an_empty_interval() {
    let mut reversed = validity();
    reversed.signed = offset_milliseconds(reversed.signed, 900);
    reversed.valid_from = offset_milliseconds(reversed.valid_from, 100);
    let mut empty = validity();
    empty.valid_until = offset_milliseconds(empty.valid_from, 500);
    for dates in [reversed, empty] {
        assert!(
            builder()
                .validity(dates)
                .prepare(
                    CoseAlgorithm::ES256,
                    vec![hex::decode(GENUINE_CERT_HEX).unwrap()]
                )
                .is_err()
        );
    }
}

#[test]
fn device_key_must_be_public_complete_and_on_a_supported_curve() {
    let public = device_key();
    let mut secret = public.clone();
    secret
        .params
        .push((coset::Label::Int(-4), ciborium::Value::Bytes(vec![42; 32])));
    let mut missing = public.clone();
    missing
        .params
        .retain(|(label, _)| *label != coset::Label::Int(-3));
    let mut off_curve = public.clone();
    for (label, value) in &mut off_curve.params {
        if matches!(label, coset::Label::Int(-2 | -3)) {
            *value = ciborium::Value::Bytes(vec![0; 32]);
        }
    }
    for invalid in [secret, missing, off_curve] {
        assert!(
            builder()
                .device_key(invalid)
                .prepare(
                    CoseAlgorithm::ES256,
                    vec![hex::decode(GENUINE_CERT_HEX).unwrap()]
                )
                .is_err()
        );
    }
}

#[test]
fn generic_issuer_preserves_explicit_tags_and_does_not_infer_custom_schema() {
    let explicit = nazo_mdoc::cbor::date::FullDate::new("2000-02-29")
        .unwrap()
        .to_cbor();
    let doc = issue(builder().add_namespace(
        "org.example.custom",
        vec![
            ("birth_date", "custom-value".into()),
            ("calendar_date", explicit.clone()),
        ],
    ));
    let parsed =
        nazo_mdoc::verifier::verify_issued(&doc.to_issuer_signed_cbor().unwrap(), DOC_TYPE, now())
            .unwrap();
    let items = &parsed.document().issuer_signed.name_spaces["org.example.custom"];
    assert_eq!(
        items[0].element_value,
        ciborium::Value::Text("custom-value".into())
    );
    assert_eq!(items[1].element_value, explicit);
}

#[test]
fn ambiguous_element_value_is_rejected_before_external_signing() {
    let duplicate = ciborium::Value::Map(vec![("x".into(), 1.into()), ("x".into(), 2.into())]);
    assert!(
        builder()
            .add_namespace("org.example", vec![("ambiguous", duplicate)])
            .prepare(
                CoseAlgorithm::ES256,
                vec![hex::decode(GENUINE_CERT_HEX).unwrap()]
            )
            .is_err()
    );
}
