//! Authentication retains source slices until the caller explicitly owns them.
#![cfg(feature = "issue")]

mod common;

use common::*;
use nazo_mdoc::{
    MdocError, VerificationOptions,
    model::{DeviceAuthRef, IssuerSignedDocumentRef},
    response_builder::{prepare_device_authentication, prepare_device_authentication_borrowed},
    verifier::{verify_issued_borrowed, verify_presentation_borrowed},
};
use signature::Signer;

fn options() -> VerificationOptions {
    VerificationOptions {
        now: now(),
        max_documents: 1,
    }
}

fn points_into(input: &[u8], value: &[u8]) {
    let start = input.as_ptr() as usize;
    let value_start = value.as_ptr() as usize;
    assert!(value_start >= start);
    assert!(value_start + value.len() <= start + input.len());
}

fn check_document_slices(encoded: &[u8], document: &IssuerSignedDocumentRef<'_>) {
    for (namespace, items) in &document.issuer_signed.name_spaces {
        points_into(encoded, namespace.as_bytes());
        for item in items {
            points_into(encoded, item.encoded);
            points_into(encoded, item.random);
            points_into(encoded, item.element_identifier.as_bytes());
            points_into(encoded, item.element_value.encoded());
        }
    }
    let issuer = &document.issuer_signed.issuer_auth.cose_sign1;
    points_into(encoded, issuer.protected);
    points_into(encoded, issuer.signature);
    points_into(encoded, issuer.payload.unwrap());
}

fn tag24(value: &ciborium::Value) -> Vec<u8> {
    let mut inner = Vec::new();
    ciborium::into_writer(value, &mut inner).unwrap();
    let mut encoded = Vec::new();
    ciborium::into_writer(
        &ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(inner))),
        &mut encoded,
    )
    .unwrap();
    encoded
}

fn authorize_device_namespace(
    mut document: nazo_mdoc::model::IssuerSignedDocument,
) -> nazo_mdoc::model::IssuerSignedDocument {
    use ciborium::Value;
    let auth = &mut document.issuer_signed.issuer_auth.cose_sign1;
    let inner = nazo_mdoc::cbor::raw::tag24_inner(auth.payload.as_deref().unwrap()).unwrap();
    let mut mso: Value = ciborium::from_reader(inner).unwrap();
    let (_, key_info) = mso
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("deviceKeyInfo"))
        .unwrap();
    key_info.as_map_mut().unwrap().push((
        "keyAuthorizations".into(),
        Value::Map(vec![(
            "nameSpaces".into(),
            Value::Array(vec!["device.example".into()]),
        )]),
    ));
    auth.payload = Some(tag24(&mso));
    let signature: p256::ecdsa::Signature = issuer_key().sign(&auth.tbs_data(&[]));
    auth.signature = signature.to_bytes().to_vec();
    document
}

#[test]
fn authenticated_large_values_headers_digests_and_certificates_borrow_wire_storage() {
    let document = issue(
        builder()
            .add_namespace(
                NS,
                vec![("portrait", ciborium::Value::Bytes(vec![0x5a; 65_536]))],
            )
            .status_list(17, "https://issuer.example/status"),
    );
    let encoded = present(document, &transcript())
        .to_device_response_cbor()
        .unwrap();
    let borrowed = verify_presentation_borrowed(&encoded, &transcript(), &options()).unwrap();
    let authenticated = &borrowed[0];
    let document = authenticated.document();
    points_into(&encoded, document.doc_type.as_bytes());
    check_document_slices(&encoded, document);
    let portrait = document.issuer_signed.name_spaces[NS]
        .iter()
        .find(|item| item.element_identifier == "portrait")
        .unwrap();
    let value = portrait.element_value.as_bytes().unwrap();
    assert_eq!(value.len(), 65_536);
    assert!(value.iter().all(|byte| *byte == 0x5a));
    points_into(&encoded, value);
    let device = document.device_signed.as_ref().unwrap();
    points_into(&encoded, device.name_spaces_bytes);
    let DeviceAuthRef::Signature(signature) = &device.device_auth else {
        panic!("signature")
    };
    points_into(&encoded, signature.protected);
    points_into(&encoded, signature.signature);
    for certificate in authenticated.certificates() {
        points_into(&encoded, certificate);
    }
    let mso = authenticated.mso();
    points_into(&encoded, mso.doc_type.as_bytes());
    for (namespace, digests) in &mso.value_digests {
        points_into(&encoded, namespace.as_bytes());
        for digest in digests.values() {
            points_into(&encoded, digest);
        }
    }
    let status = mso.status.as_ref().unwrap();
    points_into(&encoded, status.raw.encoded());
    points_into(
        &encoded,
        status.status_list.as_ref().unwrap().uri.as_bytes(),
    );

    let owned = nazo_mdoc::verify_presentation(&encoded, &transcript(), &options()).unwrap();
    let converted = borrowed.into_iter().next().unwrap().into_owned().unwrap();
    assert_eq!(
        converted.document().to_device_response_cbor().unwrap(),
        owned[0].document().to_device_response_cbor().unwrap()
    );
    assert_eq!(converted.certificates(), owned[0].certificates());
}

#[test]
fn issuer_only_authentication_borrows_the_credential_and_owns_only_on_request() {
    let encoded = issue(builder()).to_issuer_signed_cbor().unwrap();
    let borrowed = {
        let expected_doc_type = DOC_TYPE.to_owned();
        verify_issued_borrowed(&encoded, &expected_doc_type, now()).unwrap()
    };
    check_document_slices(&encoded, borrowed.document());
    points_into(&encoded, borrowed.document().doc_type.as_bytes());
    points_into(&encoded, borrowed.certificates()[0]);
    let owned = borrowed.into_owned().unwrap();
    drop(encoded);
    assert_eq!(owned.document().doc_type, DOC_TYPE);
    assert_eq!(
        owned.certificates()[0],
        hex::decode(GENUINE_CERT_HEX).unwrap()
    );
}

#[test]
fn borrowed_and_owned_entry_points_reject_the_same_authenticated_failures() {
    let mut altered = present(issue(builder()), &transcript());
    altered.issuer_signed.issuer_auth.cose_sign1.signature[0] ^= 1;
    let encoded = altered.to_device_response_cbor().unwrap();
    let borrowed = verify_presentation_borrowed(&encoded, &transcript(), &options()).unwrap_err();
    let owned = nazo_mdoc::verify_presentation(&encoded, &transcript(), &options()).unwrap_err();
    assert!(matches!(borrowed, MdocError::Signature(_)));
    assert_eq!(borrowed.to_string(), owned.to_string());

    let encoded = present(issue(builder()), &transcript())
        .to_device_response_cbor()
        .unwrap();
    let other =
        nazo_mdoc::session::SessionTranscript::redirect(nazo_mdoc::session::RedirectHandover {
            client_id: "x509_san_dns:example.com",
            nonce: "different-request",
            jwk_thumbprint: None,
            response_uri: "https://example.com/response",
        })
        .unwrap();
    let borrowed = verify_presentation_borrowed(&encoded, &other, &options()).unwrap_err();
    let owned = nazo_mdoc::verify_presentation(&encoded, &other, &options()).unwrap_err();
    assert!(matches!(borrowed, MdocError::DeviceAuth(_)));
    assert_eq!(borrowed.to_string(), owned.to_string());

    let issued = issue(builder()).to_issuer_signed_cbor().unwrap();
    let borrowed = verify_issued_borrowed(&issued, "wrong-document", now()).unwrap_err();
    let owned = nazo_mdoc::verifier::verify_issued(&issued, "wrong-document", now()).unwrap_err();
    assert!(matches!(borrowed, MdocError::Mso(_)));
    assert_eq!(borrowed.to_string(), owned.to_string());
}

#[test]
fn external_ed25519_holder_signing_and_borrowed_verification_keep_strict_verification() {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let key = coset::CoseKeyBuilder::new_okp_key()
        .param(-1, ciborium::Value::Integer(6.into()))
        .param(
            -2,
            ciborium::Value::Bytes(signer.verifying_key().as_bytes().to_vec()),
        )
        .build();
    let document = issue(builder().device_key(key));
    let prepared =
        prepare_device_authentication(document, &transcript(), vec![0xd8, 0x18, 0x41, 0xa0], -8)
            .unwrap();
    let signature: ed25519_dalek::Signature = signer.sign(prepared.signing_input());
    let signed = prepared.finish(signature.to_bytes().to_vec()).unwrap();
    let encoded = signed.to_device_response_cbor().unwrap();
    let borrowed = verify_presentation_borrowed(&encoded, &transcript(), &options()).unwrap();
    assert_eq!(borrowed.len(), 1);
    check_document_slices(&encoded, borrowed[0].document());
    assert_eq!(
        nazo_mdoc::verify_presentation(&encoded, &transcript(), &options())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn borrowed_credential_disclosure_holder_signing_and_wire_output_form_one_flow() {
    use ciborium::Value;
    let credential = authorize_device_namespace(issue(
        builder().add_namespace(NS, vec![("portrait", Value::Bytes(vec![0x5a; 65_536]))]),
    ))
    .to_issuer_signed_cbor()
    .unwrap();
    let authenticated = verify_issued_borrowed(&credential, DOC_TYPE, now()).unwrap();
    let (mut disclosed, _mso, certificates) = authenticated.into_parts();
    points_into(&credential, certificates[0]);
    let items = disclosed.issuer_signed.name_spaces.get_mut(NS).unwrap();
    items.retain(|item| item.element_identifier == "portrait");
    assert_eq!(items.len(), 1);
    let original_item = items[0].encoded;
    points_into(&credential, original_item);
    points_into(&credential, items[0].element_value.as_bytes().unwrap());
    let namespaces = tag24(&Value::Map(vec![(
        "device.example".into(),
        Value::Map(vec![
            ("z".into(), Value::Bytes(vec![0x6b; 16_384])),
            ("a".into(), Value::Text("original order".into())),
        ]),
    )]));
    let prepared =
        prepare_device_authentication_borrowed(disclosed, &transcript(), &namespaces, -7).unwrap();
    assert_eq!(prepared.algorithm(), -7);
    let signature: p256::ecdsa::Signature = holder_key().sign(prepared.signing_input());
    let response = prepared.finish(signature.to_bytes().as_ref()).unwrap();
    let verified = verify_presentation_borrowed(&response, &transcript(), &options()).unwrap();
    let document = verified[0].document();
    check_document_slices(&response, document);
    assert_eq!(document.issuer_signed.name_spaces[NS].len(), 1);
    assert_eq!(
        document.issuer_signed.name_spaces[NS][0].encoded,
        original_item
    );
    let device = document.device_signed.as_ref().unwrap();
    assert_eq!(device.name_spaces_bytes, namespaces);
    let value = device.name_spaces["device.example"]["z"]
        .as_bytes()
        .unwrap();
    assert_eq!(value.len(), 16_384);
    points_into(&response, value);
    points_into(&response, verified[0].certificates()[0]);
}

#[test]
fn borrowed_holder_rejects_wrong_signatures_and_unauthorized_namespaces() {
    use ciborium::Value;
    let credential = issue(builder()).to_issuer_signed_cbor().unwrap();
    let authenticated = verify_issued_borrowed(&credential, DOC_TYPE, now()).unwrap();
    let empty_namespaces = [0xd8, 0x18, 0x41, 0xa0];
    let prepared = prepare_device_authentication_borrowed(
        authenticated.document().clone(),
        &transcript(),
        &empty_namespaces,
        -7,
    )
    .unwrap();
    let wrong_signature: p256::ecdsa::Signature = issuer_key().sign(prepared.signing_input());
    assert!(matches!(
        prepared.finish(wrong_signature.to_bytes().as_ref()),
        Err(MdocError::Signature(_))
    ));

    let namespaces = tag24(&Value::Map(vec![(
        "device.example".into(),
        Value::Map(vec![("a".into(), Value::Bool(true))]),
    )]));
    assert!(matches!(
        prepare_device_authentication_borrowed(
            authenticated.document().clone(),
            &transcript(),
            &namespaces,
            -7,
        ),
        Err(MdocError::DeviceAuth(_))
    ));
}
