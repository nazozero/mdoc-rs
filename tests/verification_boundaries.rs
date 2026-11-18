//! Wire-only verification reuses parser checks; mutable-model APIs check them.
#![cfg(feature = "issue")]

mod common;

use common::*;
use coset::{RegisteredLabelWithPrivate, iana};
use nazo_mdoc::{MdocError, model::DeviceAuth, model::IssuerSignedDocument};
use signature::Signer;

fn signature(document: &mut IssuerSignedDocument, holder: bool) -> &mut coset::CoseSign1 {
    if holder {
        let DeviceAuth::Signature(signature) =
            &mut document.device_signed.as_mut().unwrap().device_auth
        else {
            unreachable!()
        };
        signature
    } else {
        &mut document.issuer_signed.issuer_auth.cose_sign1
    }
}

fn resign(document: &mut IssuerSignedDocument, holder: bool) {
    let detached = holder.then(|| {
        nazo_mdoc::session::build_device_authentication(
            &transcript(),
            &document.doc_type,
            &document.device_signed.as_ref().unwrap().name_spaces_bytes,
        )
        .unwrap()
    });
    let signature = signature(document, holder);
    signature.protected.original_data = None;
    let input = if let Some(payload) = detached {
        coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            signature.protected.clone(),
            None,
            &[],
            &payload,
        )
    } else {
        signature.tbs_data(&[])
    };
    let key = if holder { holder_key() } else { issuer_key() };
    let signed: p256::ecdsa::Signature = key.sign(&input);
    signature.signature = signed.to_bytes().to_vec();
}

#[test]
fn parsed_issuer_and_holder_headers_enforce_critical_semantics() {
    for holder in [false, true] {
        for understood in [false, true] {
            let mut document = present(issue(builder()), &transcript());
            let header = &mut signature(&mut document, holder).protected.header;
            header.key_id = vec![1];
            header.crit = vec![RegisteredLabelWithPrivate::Assigned(if understood {
                iana::HeaderParameter::Alg
            } else {
                iana::HeaderParameter::Kid
            })];
            resign(&mut document, holder);
            let result = verify(&document.to_device_response_cbor().unwrap());
            if understood {
                assert!(result.is_ok());
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("unsupported critical")
                );
            }
        }
    }
}

#[test]
fn parsed_issuer_chain_must_remain_in_the_unprotected_header() {
    let mut document = present(issue(builder()), &transcript());
    let issuer = signature(&mut document, false);
    issuer.protected.header.rest = std::mem::take(&mut issuer.unprotected.rest);
    resign(&mut document, false);
    assert!(matches!(
        verify(&document.to_device_response_cbor().unwrap()),
        Err(MdocError::Certificate(reason)) if reason.contains("unprotected header")
    ));
}

#[test]
fn public_device_verification_still_checks_original_header_binding() {
    let encoded = present(issue(builder()), &transcript())
        .to_device_response_cbor()
        .unwrap();
    let mut document = nazo_mdoc::parse(&encoded).unwrap().documents.remove(0);
    let payload = nazo_mdoc::session::build_device_authentication(
        &transcript(),
        &document.doc_type,
        &document.device_signed.as_ref().unwrap().name_spaces_bytes,
    )
    .unwrap();
    signature(&mut document, true).protected.header.key_id = vec![1];
    assert!(matches!(
        nazo_mdoc::device_auth::verify_device_auth(
            &document.device_signed.as_ref().unwrap().device_auth,
            &payload,
            &device_key(),
            None,
        ),
        Err(MdocError::Cose(reason)) if reason.contains("differs from original signed bytes")
    ));
}
