//! Negative regressions are enabled for the production issue configuration.
#![cfg(feature = "issue")]
mod common;
use ciborium::Value;
use common::*;
use nazo_mdoc::{
    MdocError,
    model::*,
    session::{RedirectHandover, SessionTranscript},
};

fn encoded() -> Vec<u8> {
    present(issue(builder()), &transcript())
        .to_device_response_cbor()
        .unwrap()
}
fn device_signature(document: &mut IssuerSignedDocument) -> &mut coset::CoseSign1 {
    match &mut document.device_signed.as_mut().unwrap().device_auth {
        DeviceAuth::Signature(sign1) => sign1,
        _ => unreachable!(),
    }
}
fn mutate_mso(document: &mut IssuerSignedDocument, change: impl FnOnce(&mut Value), resign: bool) {
    use signature::Signer;
    let sign1 = &mut document.issuer_signed.issuer_auth.cose_sign1;
    let inner = nazo_mdoc::cbor::raw::tag24_inner(sign1.payload.as_ref().unwrap()).unwrap();
    let mut mso: Value = ciborium::from_reader(inner).unwrap();
    change(&mut mso);
    let bytes = nazo_mdoc::cbor::data_item::encode_cbor(&mso).unwrap();
    sign1.payload = Some(
        nazo_mdoc::cbor::data_item::encode_cbor(&nazo_mdoc::cbor::data_item::wrap_tag24(&bytes))
            .unwrap(),
    );
    if resign {
        let sig: p256::ecdsa::Signature = issuer_key().sign(&sign1.tbs_data(&[]));
        sign1.signature = sig.to_bytes().to_vec();
    }
}

#[test]
fn tampered_issuer_signature_is_rejected() {
    let mut doc = present(issue(builder()), &transcript());
    doc.issuer_signed.issuer_auth.cose_sign1.signature[0] ^= 1;
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::Signature(_))
    ));
}

#[test]
fn missing_holder_signature_is_rejected() {
    assert!(matches!(
        verify(&issue(builder()).to_device_response_cbor().unwrap()),
        Err(MdocError::DeviceAuth(_))
    ));
}

#[test]
fn incorrect_session_binding_is_rejected() {
    let other = SessionTranscript::redirect(RedirectHandover {
        client_id: "x509_san_dns:example.com",
        nonce: "another-nonce",
        jwk_thumbprint: None,
        response_uri: "https://example.com/response",
    })
    .unwrap();
    let doc = present(issue(builder()), &other);
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::DeviceAuth(_))
    ));
}

#[test]
fn embedded_device_payload_is_rejected() {
    let mut value: Value = ciborium::from_reader(encoded().as_slice()).unwrap();
    fn field<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
        &mut value
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some(name))
            .unwrap()
            .1
    }
    let doc = &mut field(&mut value, "documents").as_array_mut().unwrap()[0];
    let sign1 = field(field(doc, "deviceSigned"), "deviceAuth");
    field(sign1, "deviceSignature").as_array_mut().unwrap()[2] = Value::Bytes(vec![1, 2, 3]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    assert!(matches!(verify(&bytes), Err(MdocError::DeviceAuth(_))));
}

#[test]
fn unprotected_device_algorithm_is_rejected() {
    let mut doc = present(issue(builder()), &transcript());
    device_signature(&mut doc).unprotected.alg =
        Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256));
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::Cose(_))
    ));
}

#[test]
fn tampered_attribute_original_bytes_fail_digest() {
    let mut doc = present(issue(builder()), &transcript());
    let item = &mut doc.issuer_signed.name_spaces.get_mut(NS).unwrap()[0];
    let mut value: Value =
        ciborium::from_reader(nazo_mdoc::cbor::raw::tag24_inner(&item.encoded).unwrap()).unwrap();
    for (key, value) in value.as_map_mut().unwrap() {
        if key.as_text() == Some("elementValue") {
            *value = "TAMPERED".into();
        }
    }
    item.encoded = nazo_mdoc::cbor::data_item::encode_cbor(
        &nazo_mdoc::cbor::data_item::encode_as_tag24(&value).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::Disclosure(_))
    ));
}

#[test]
fn changing_decoded_attribute_does_not_change_authenticated_wire_claim() {
    let mut doc = present(issue(builder()), &transcript());
    doc.issuer_signed.name_spaces.get_mut(NS).unwrap()[0].element_value = "UNSIGNED".into();
    let pending = verify(&doc.to_device_response_cbor().unwrap()).unwrap();
    assert_ne!(
        pending[0].document().issuer_signed.name_spaces[NS][0]
            .element_value
            .as_text(),
        Some("UNSIGNED")
    );
}

#[test]
fn doc_type_is_bound_to_mso_and_holder_signature() {
    let mut doc = present(issue(builder()), &transcript());
    doc.doc_type = "other.type".into();
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::DeviceAuth(_))
    ));
}

#[test]
fn mso_status_tampering_cannot_be_ignored() {
    let mut doc = present(
        issue(builder().status_list(42, "https://issuer.example/status")),
        &transcript(),
    );
    mutate_mso(
        &mut doc,
        |mso| {
            mso.as_map_mut()
                .unwrap()
                .retain(|(key, _)| key.as_text() != Some("status"))
        },
        false,
    );
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::Signature(_))
    ));
}

#[test]
fn unsupported_status_mechanism_is_preserved_for_host_rejection() {
    let status = Value::Map(vec![(
        "future_status".into(),
        Value::Map(vec![("uri".into(), "https://issuer.example/status".into())]),
    )]);
    let doc = present(issue(builder().status_raw(status.clone())), &transcript());
    let result = verify(&doc.to_device_response_cbor().unwrap()).unwrap();
    let parsed = result[0].mso().status.as_ref().unwrap();
    assert_eq!(parsed.raw, status);
    assert!(parsed.status_list.is_none());
}

#[test]
fn wrong_leaf_key_is_not_an_issuer_signature() {
    let mut doc = present(issue(builder()), &transcript());
    doc.issuer_signed.issuer_auth.cose_sign1.unprotected.rest[0].1 =
        Value::Bytes(hex::decode(EVIL_CERT_HEX).unwrap());
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::Signature(_))
    ));
}

#[test]
fn unauthenticated_future_mso_extension_is_not_silently_dropped() {
    let mut doc = present(issue(builder()), &transcript());
    mutate_mso(
        &mut doc,
        |mso| {
            mso.as_map_mut()
                .unwrap()
                .push(("future_validation".into(), true.into()))
        },
        true,
    );
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::Mso(_))
    ));
}

#[test]
fn haip_multiple_documents_are_rejected_before_partial_verification() {
    let doc = present(issue(builder()), &transcript());
    let mut second = doc.clone();
    second.issuer_signed.issuer_auth.cose_sign1.signature[0] ^= 1;
    let response = MDoc {
        version: "1.0".into(),
        status: MDocStatus::Ok,
        documents: vec![doc, second],
    };
    let encoded = response.to_cbor().unwrap();
    assert!(matches!(
        verify(&encoded),
        Err(MdocError::DocumentCount { actual: 2, max: 1 })
    ));
    assert!(
        nazo_mdoc::verify_presentation(
            &encoded,
            &transcript(),
            &nazo_mdoc::VerificationOptions {
                now: now(),
                max_documents: 2
            }
        )
        .is_err()
    );
}

#[test]
fn issuer_validity_is_checked_at_explicit_time() {
    let bytes = encoded();
    assert!(matches!(
        nazo_mdoc::verify_presentation(
            &bytes,
            &transcript(),
            &nazo_mdoc::VerificationOptions {
                now: now() + chrono::Duration::days(31),
                max_documents: 1
            }
        ),
        Err(MdocError::Validity(_))
    ));
}

#[test]
fn nonempty_device_data_requires_key_authorizations() {
    use signature::Signer;
    let mut doc = issue(builder());
    let namespace = Value::Map(vec![(
        "extension".into(),
        Value::Map(vec![("claim".into(), true.into())]),
    )]);
    let bytes = nazo_mdoc::cbor::data_item::encode_cbor(
        &nazo_mdoc::cbor::data_item::encode_as_tag24(&namespace).unwrap(),
    )
    .unwrap();
    let payload =
        nazo_mdoc::session::build_device_authentication(&transcript(), DOC_TYPE, &bytes).unwrap();
    let mut sign1 = coset::CoseSign1Builder::new()
        .protected(
            coset::HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES256)
                .build(),
        )
        .payload(payload)
        .create_signature(&[], |data| {
            let signature: p256::ecdsa::Signature = holder_key().sign(data);
            signature.to_bytes().to_vec()
        })
        .build();
    sign1.payload = None;
    doc.device_signed = Some(DeviceSigned {
        device_auth: DeviceAuth::Signature(sign1),
        name_spaces: Default::default(),
        name_spaces_bytes: bytes,
    });
    assert!(matches!(
        verify(&doc.to_device_response_cbor().unwrap()),
        Err(MdocError::DeviceAuth(_))
    ));
}

#[test]
fn issuer_only_verification_rejects_private_device_key_material() {
    let mut doc = issue(builder());
    mutate_mso(
        &mut doc,
        |mso| {
            let info = &mut mso
                .as_map_mut()
                .unwrap()
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some("deviceKeyInfo"))
                .unwrap()
                .1;
            let key = &mut info
                .as_map_mut()
                .unwrap()
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some("deviceKey"))
                .unwrap()
                .1;
            key.as_map_mut()
                .unwrap()
                .push(((-4).into(), Value::Bytes(vec![42; 32])));
        },
        true,
    );
    assert!(
        nazo_mdoc::verifier::verify_issued(&doc.to_issuer_signed_cbor().unwrap(), DOC_TYPE, now())
            .is_err()
    );
}
