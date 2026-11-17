//! The signing implementations in these tests live outside the protocol core.
#![cfg(feature = "issue")]

mod common;

use ciborium::Value;
use common::*;
use coset::CborSerializable;
use nazo_mdoc::{
    model::{DeviceAuth, IssuerSignedDocument},
    response_builder::prepare_device_authentication,
};
use signature::Signer;

const EMPTY_NAMESPACES: &[u8] = &[0xd8, 0x18, 0x41, 0xa0];

fn encode(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).unwrap();
    encoded
}

fn tagged(value: &Value) -> Vec<u8> {
    encode(&Value::Tag(24, Box::new(Value::Bytes(encode(value)))))
}

fn sign_external(document: IssuerSignedDocument, namespaces: Vec<u8>) -> IssuerSignedDocument {
    let prepared = prepare_device_authentication(document, &transcript(), namespaces, -7).unwrap();
    let signature: p256::ecdsa::Signature = holder_key().sign(prepared.signing_input());
    prepared.finish(signature.to_bytes().to_vec()).unwrap()
}

fn with_authorizations(
    mut document: IssuerSignedDocument,
    authorizations: Value,
) -> IssuerSignedDocument {
    let auth = &mut document.issuer_signed.issuer_auth.cose_sign1;
    let inner = nazo_mdoc::cbor::raw::tag24_inner(auth.payload.as_deref().unwrap()).unwrap();
    let mut mso: Value = ciborium::from_reader(inner).unwrap();
    let key_info = mso
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("deviceKeyInfo"))
        .unwrap();
    key_info
        .1
        .as_map_mut()
        .unwrap()
        .push((Value::Text("keyAuthorizations".into()), authorizations));
    auth.payload = Some(tagged(&mso));
    let signature: p256::ecdsa::Signature = issuer_key().sign(&auth.tbs_data(&[]));
    auth.signature = signature.to_bytes().to_vec();
    document
}

#[test]
fn external_holder_signs_sig_structure_and_finishes_a_detached_proof() {
    let prepared = prepare_device_authentication(
        issue(builder()),
        &transcript(),
        EMPTY_NAMESPACES.to_vec(),
        -7,
    )
    .unwrap();
    assert_eq!(prepared.algorithm(), -7);
    let input: Value = ciborium::from_reader(prepared.signing_input()).unwrap();
    let input = input.as_array().unwrap();
    assert_eq!(input.len(), 4);
    assert_eq!(input[0].as_text(), Some("Signature1"));
    assert_eq!(input[1].as_bytes().unwrap(), &[0xa1, 0x01, 0x26]);
    assert!(input[2].as_bytes().unwrap().is_empty());
    let payload = input[3].as_bytes().unwrap();
    assert!(payload.starts_with(&[0xd8, 0x18]));
    let signature: p256::ecdsa::Signature = holder_key().sign(prepared.signing_input());
    let document = prepared.finish(signature.to_bytes().to_vec()).unwrap();
    let DeviceAuth::Signature(sign1) = &document.device_signed.as_ref().unwrap().device_auth else {
        panic!("expected DeviceSignature");
    };
    assert!(sign1.payload.is_none());
    let pending = verify(&document.to_device_response_cbor().unwrap()).unwrap();
    assert_eq!(pending.len(), 1);
}

#[test]
fn external_holder_wrong_key_altered_input_and_der_signatures_are_rejected() {
    let prepare = || {
        prepare_device_authentication(
            issue(builder()),
            &transcript(),
            EMPTY_NAMESPACES.to_vec(),
            -7,
        )
        .unwrap()
    };
    let prepared = prepare();
    let signature: p256::ecdsa::Signature = issuer_key().sign(prepared.signing_input());
    assert!(prepared.finish(signature.to_bytes().to_vec()).is_err());

    let prepared = prepare();
    let signature: p256::ecdsa::Signature = holder_key().sign(b"not the prepared Sig_structure");
    assert!(prepared.finish(signature.to_bytes().to_vec()).is_err());

    let prepared = prepare();
    let signature: p256::ecdsa::Signature = holder_key().sign(prepared.signing_input());
    assert!(
        prepared
            .finish(signature.to_der().as_bytes().to_vec())
            .is_err()
    );
}

#[test]
fn preparing_rejects_algorithm_curve_mismatch_and_unsupported_algorithms() {
    for algorithm in [-35, -36, -8, 5, -999] {
        assert!(
            prepare_device_authentication(
                issue(builder()),
                &transcript(),
                EMPTY_NAMESPACES.to_vec(),
                algorithm,
            )
            .is_err()
        );
    }
}

#[test]
fn preparing_rejects_unauthorized_device_namespaces() {
    let namespaces = tagged(&Value::Map(vec![(
        Value::Text("device.example".into()),
        Value::Map(vec![(Value::Text("a".into()), Value::Integer(1.into()))]),
    )]));
    assert!(
        prepare_device_authentication(issue(builder()), &transcript(), namespaces, -7).is_err()
    );
}

#[test]
fn authorized_device_namespace_is_signed_and_encoded_without_reordering_raw_map() {
    let document = with_authorizations(
        issue(builder()),
        Value::Map(vec![(
            Value::Text("nameSpaces".into()),
            Value::Array(vec![Value::Text("device.example".into())]),
        )]),
    );
    let namespaces = tagged(&Value::Map(vec![(
        Value::Text("device.example".into()),
        Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]),
    )]));
    let document = sign_external(document, namespaces.clone());
    let encoded = document.to_device_response_cbor().unwrap();
    let pending = verify(&encoded).unwrap();
    let device = pending[0].document().device_signed.as_ref().unwrap();
    assert_eq!(device.name_spaces_bytes, namespaces);
    assert_eq!(
        device.name_spaces["device.example"]["a"]
            .as_integer()
            .unwrap(),
        1.into()
    );
}

#[test]
fn element_authorizations_do_not_authorize_other_elements_in_same_namespace() {
    let document = with_authorizations(
        issue(builder()),
        Value::Map(vec![(
            Value::Text("dataElements".into()),
            Value::Map(vec![(
                Value::Text("device.example".into()),
                Value::Array(vec![Value::Text("a".into())]),
            )]),
        )]),
    );
    let namespaces = |element: &str| {
        tagged(&Value::Map(vec![(
            Value::Text("device.example".into()),
            Value::Map(vec![(
                Value::Text(element.into()),
                Value::Integer(1.into()),
            )]),
        )]))
    };
    assert!(
        prepare_device_authentication(document.clone(), &transcript(), namespaces("b"), -7)
            .is_err()
    );
    let signed = sign_external(document, namespaces("a"));
    assert!(verify(&signed.to_device_response_cbor().unwrap()).is_ok());
}

#[test]
fn encoder_preserves_original_protected_header_bytes() {
    let mut document = issue(builder());
    // Protected header {4: h'6b', 1: -7}: valid shortest framing, unsorted map.
    let original = hex::decode("a204416b0126").unwrap();
    let auth = &mut document.issuer_signed.issuer_auth.cose_sign1;
    auth.protected = coset::ProtectedHeader {
        original_data: Some(original.clone()),
        header: coset::Header::from_slice(&original).unwrap(),
    };
    let signature: p256::ecdsa::Signature = issuer_key().sign(&auth.tbs_data(&[]));
    auth.signature = signature.to_bytes().to_vec();
    let encoded = document.to_issuer_signed_cbor().unwrap();
    let pending = nazo_mdoc::verifier::verify_issued(&encoded, DOC_TYPE, now()).unwrap();
    assert_eq!(
        pending
            .document()
            .issuer_signed
            .issuer_auth
            .cose_sign1
            .protected
            .original_data
            .as_ref()
            .unwrap(),
        &original
    );
}

#[test]
fn encoder_never_substitutes_decoded_attributes_for_signed_item_bytes() {
    let mut document = issue(builder());
    let item = document
        .issuer_signed
        .name_spaces
        .get_mut(NS)
        .unwrap()
        .iter_mut()
        .find(|item| item.element_identifier == "family_name")
        .unwrap();
    let original = item.encoded.clone();
    item.element_value = Value::Text("untrusted replacement".into());
    item.random.clear();
    let encoded = document.to_issuer_signed_cbor().unwrap();
    let pending = nazo_mdoc::verifier::verify_issued(&encoded, DOC_TYPE, now()).unwrap();
    let item = pending.document().issuer_signed.name_spaces[NS]
        .iter()
        .find(|item| item.element_identifier == "family_name")
        .unwrap();
    assert_eq!(item.element_value.as_text(), Some("Lindqvist"));
    assert_eq!(item.encoded, original);
}

#[test]
fn encoder_cannot_silently_attach_a_device_signature_payload() {
    let mut document = sign_external(issue(builder()), EMPTY_NAMESPACES.to_vec());
    let DeviceAuth::Signature(sign1) = &mut document.device_signed.as_mut().unwrap().device_auth
    else {
        panic!("expected DeviceSignature");
    };
    sign1.payload = Some(vec![0]);
    assert!(document.to_device_response_cbor().is_err());
}

#[test]
fn official_annex_d_signed_items_and_payloads_survive_encoding_exactly() {
    let original =
        nazo_mdoc::parse_hex(include_str!("vectors/iso_18013_5_annex_d_mdl.hex")).unwrap();
    let encoded = original.to_cbor().unwrap();
    let parsed = nazo_mdoc::parse(&encoded).unwrap();
    for (old, new) in original.documents.iter().zip(&parsed.documents) {
        assert_eq!(
            old.issuer_signed.issuer_auth.cose_sign1.payload,
            new.issuer_signed.issuer_auth.cose_sign1.payload
        );
        assert_eq!(
            old.issuer_signed
                .issuer_auth
                .cose_sign1
                .protected
                .original_data,
            new.issuer_signed
                .issuer_auth
                .cose_sign1
                .protected
                .original_data
        );
        for (namespace, items) in &old.issuer_signed.name_spaces {
            for (old_item, new_item) in items.iter().zip(&new.issuer_signed.name_spaces[namespace])
            {
                assert_eq!(old_item.encoded, new_item.encoded);
            }
        }
    }
}
