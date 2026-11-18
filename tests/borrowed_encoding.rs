#![cfg(feature = "issue")]

use ciborium::Value;
use nazo_mdoc::{
    MdocError,
    cbor::raw::{Limits, tag24_inner, validate},
    encoder::{
        encode_device_response, encode_device_response_borrowed, encode_issuer_signed,
        encode_issuer_signed_borrowed,
    },
    model::{CborValueRef, CoseLabelRef, CoseSign1Ref, DeviceAuthRef, DeviceResponseStatus},
    parser::{parse, parse_borrowed, parse_issued_borrowed},
};

const NS: &str = "org.iso.18013.5.1";

fn fixture() -> Vec<u8> {
    hex::decode(
        include_str!("vectors/iso_18013_5_annex_d_mdl.hex")
            .split_whitespace()
            .collect::<String>(),
    )
    .unwrap()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).unwrap();
    encoded
}

fn tagged(value: &Value) -> Vec<u8> {
    encode(&Value::Tag(24, Box::new(Value::Bytes(encode(value)))))
}

#[test]
fn borrowed_encoding_matches_owned_and_preserves_annex_d_signed_bytes() {
    let input = fixture();
    let mut borrowed = parse_borrowed(&input).unwrap();
    let mut owned = parse(&input).unwrap();
    for with_namespaces in [true, false] {
        if !with_namespaces {
            borrowed.documents[0].issuer_signed.name_spaces.clear();
            owned.documents[0].issuer_signed.name_spaces.clear();
        }
        let encoded = encode_device_response_borrowed(&borrowed).unwrap();
        assert_eq!(encoded, encode_device_response(&owned).unwrap());
        let reparsed = parse_borrowed(&encoded).unwrap();
        for (before, after) in borrowed.documents.iter().zip(&reparsed.documents) {
            let before_auth = &before.issuer_signed.issuer_auth.cose_sign1;
            let after_auth = &after.issuer_signed.issuer_auth.cose_sign1;
            assert_eq!(before_auth.protected, after_auth.protected);
            assert_eq!(before_auth.payload, after_auth.payload);
            assert_eq!(before_auth.signature, after_auth.signature);
            assert_eq!(
                before.device_signed.as_ref().unwrap().name_spaces_bytes,
                after.device_signed.as_ref().unwrap().name_spaces_bytes
            );
            for (namespace, items) in &before.issuer_signed.name_spaces {
                for (before, after) in items
                    .iter()
                    .zip(&after.issuer_signed.name_spaces[namespace])
                {
                    assert_eq!(before.encoded, after.encoded);
                }
            }
        }
        for (borrowed, owned) in borrowed.documents.iter().zip(&owned.documents) {
            let issued = encode_issuer_signed_borrowed(&borrowed.issuer_signed).unwrap();
            assert_eq!(issued, encode_issuer_signed(&owned.issuer_signed).unwrap());
            assert_eq!(issued, borrowed.to_issuer_signed_cbor().unwrap());
            assert_eq!(
                borrowed.to_device_response_cbor().unwrap(),
                owned.to_device_response_cbor().unwrap()
            );
            assert_eq!(
                parse_issued_borrowed(&issued).unwrap().name_spaces.len(),
                borrowed.issuer_signed.name_spaces.len()
            );
        }
    }
}

#[test]
fn encoding_uses_current_unsigned_fields_and_keeps_protected_bytes_authoritative() {
    let input = fixture();
    let chain = encode(&Value::Array(vec![
        Value::Bytes(vec![1; 65_536]),
        Value::Bytes(vec![2; 256]),
    ]));
    let mut response = parse_borrowed(&input).unwrap();
    response.status = DeviceResponseStatus::GeneralError;
    response.version = "1.7";
    let document = &mut response.documents[0];
    document.doc_type = "changed.doc.type";
    let auth = &mut document.issuer_signed.issuer_auth.cose_sign1;
    let protected = auth.protected;
    auth.protected_header.key_id = b"decoded metadata is not the signed header";
    auth.unprotected.alg = Some(CoseLabelRef::Int(-7));
    auth.unprotected.crit = vec![CoseLabelRef::Int(4), CoseLabelRef::Text("private")];
    auth.unprotected.key_id = b"current kid";
    auth.unprotected.x5chain = Some(CborValueRef::parse(&chain).unwrap());
    auth.signature = b"current proof";

    let DeviceAuthRef::Mac(mac) = &document.device_signed.as_ref().unwrap().device_auth else {
        panic!("Annex D fixture uses deviceMac");
    };
    let signature = DeviceAuthRef::Signature(CoseSign1Ref {
        protected: mac.protected,
        protected_header: mac.protected_header.clone(),
        unprotected: mac.unprotected.clone(),
        payload: None,
        signature: mac.tag,
    });
    for device_auth in [DeviceAuthRef::Mac(mac.clone()), signature] {
        response.documents[0]
            .device_signed
            .as_mut()
            .unwrap()
            .device_auth = device_auth;
        let owned = response.clone().into_owned().unwrap();
        assert_eq!(
            encode_device_response_borrowed(&response).unwrap(),
            encode_device_response(&owned).unwrap()
        );
        assert_eq!(
            response.documents[0].to_device_response_cbor().unwrap(),
            owned.documents[0].to_device_response_cbor().unwrap()
        );
        assert_eq!(
            response.documents[0]
                .issuer_signed
                .issuer_auth
                .cose_sign1
                .protected,
            protected
        );

        match &mut response.documents[0]
            .device_signed
            .as_mut()
            .unwrap()
            .device_auth
        {
            DeviceAuthRef::Signature(auth) => auth.payload = Some(&[]),
            DeviceAuthRef::Mac(auth) => auth.payload = Some(&[]),
        }
        assert!(encode_device_response_borrowed(&response).is_err());
    }
}

#[test]
fn borrowed_items_can_be_filtered_and_reordered_without_decoding_the_signed_fields() {
    let input = fixture();
    let mut response = parse_borrowed(&input).unwrap();
    let issuer = &mut response.documents[0].issuer_signed;
    let original_count: usize = issuer.name_spaces.values().map(Vec::len).sum();
    let payload = issuer.issuer_auth.cose_sign1.payload;
    let signature = issuer.issuer_auth.cose_sign1.signature;
    for items in issuer.name_spaces.values_mut() {
        items.reverse();
        items.truncate(1);
        // As in the owned API, edited projections never replace signed bytes.
        items[0].element_identifier = "edited projection";
        items[0].element_value = CborValueRef::parse(&[0xf6]).unwrap();
        items[0].random = &[];
    }
    let selected: Vec<_> = issuer
        .name_spaces
        .iter()
        .map(|(namespace, items)| (*namespace, items[0].encoded))
        .collect();
    let encoded = encode_issuer_signed_borrowed(issuer).unwrap();
    let parsed = parse_issued_borrowed(&encoded).unwrap();
    assert!(parsed.name_spaces.values().map(Vec::len).sum::<usize>() < original_count);
    assert_eq!(parsed.issuer_auth.cose_sign1.payload, payload);
    assert_eq!(parsed.issuer_auth.cose_sign1.signature, signature);
    let mso = parsed.issuer_auth.mso().unwrap();
    for (namespace, original_bytes) in selected {
        let item = &parsed.name_spaces[namespace][0];
        assert_eq!(item.encoded, original_bytes);
        assert_ne!(item.element_identifier, "edited projection");
        assert!(item.verify_digest(
            mso.value_digests[namespace][&item.digest_id],
            &mso.digest_algorithm
        ));
    }
}

#[test]
fn mutated_raw_fields_require_exact_tag24_framing_and_valid_embedded_cbor() {
    let input = fixture();
    let original = parse_borrowed(&input).unwrap();
    for wire in [
        "a0",
        "41a0",
        "d81741a0",
        "d818a0",
        "d818d81841a0",
        "d81841a000",
        "d81841",
        "d81842a0",
        "d9001841a0",
        "d8185801a0",
        "d81840",
        "d81841ff",
        "d81847a2616101616102",
        "d81842a000",
    ] {
        let invalid = hex::decode(wire).unwrap();
        let mut response = original.clone();
        let document = &mut response.documents[0];
        document.issuer_signed.name_spaces.get_mut(NS).unwrap()[0].encoded = &invalid;
        assert!(document.to_issuer_signed_cbor().is_err(), "issuer: {wire}");
        assert!(
            document.to_device_response_cbor().is_err(),
            "document: {wire}"
        );
        assert!(
            encode_device_response_borrowed(&response).is_err(),
            "response: {wire}"
        );

        let mut response = original.clone();
        response.documents[0]
            .device_signed
            .as_mut()
            .unwrap()
            .name_spaces_bytes = &invalid;
        assert!(
            response.documents[0].to_device_response_cbor().is_err(),
            "device: {wire}"
        );
        assert!(
            encode_device_response_borrowed(&response).is_err(),
            "response device: {wire}"
        );
    }
}

#[test]
fn borrowed_encoding_applies_limits_to_the_complete_output() {
    let input = fixture();
    let original = parse_borrowed(&input).unwrap();
    let template = original.documents[0].issuer_signed.name_spaces[NS][0];
    let inner: Value = ciborium::from_reader(tag24_inner(template.encoded).unwrap()).unwrap();
    let limits = Limits::default();
    let mut nested = Value::Null;
    for _ in 0..limits.max_depth - 4 {
        nested = Value::Array(vec![nested]);
    }
    for (claim, expected) in [
        (
            Value::Bytes(vec![0; limits.max_bytes / 2]),
            "CBOR byte limit exceeded",
        ),
        (
            Value::Array(vec![
                Value::Array(vec![
                    Value::Null;
                    limits.max_collection_items
                ]);
                9
            ]),
            "CBOR item limit exceeded",
        ),
        (nested, "CBOR nesting limit exceeded"),
    ] {
        let mut value = inner.clone();
        value
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some("elementValue"))
            .unwrap()
            .1 = claim;
        let encoded = tagged(&value);
        validate(&encoded).expect("each individual item fits the default budgets");
        let item = nazo_mdoc::model::IssuerSignedItemRef {
            encoded: &encoded,
            ..template
        };
        let mut response = original.clone();
        let document = &mut response.documents[0];
        document.issuer_signed.name_spaces.clear();
        document.issuer_signed.name_spaces.insert(NS, vec![item; 2]);
        for result in [
            document.to_issuer_signed_cbor(),
            document.to_device_response_cbor(),
            encode_device_response_borrowed(&response),
        ] {
            assert!(
                matches!(&result, Err(MdocError::Cbor(reason)) if reason == expected),
                "expected {expected}, got {result:?}"
            );
        }
    }
}
