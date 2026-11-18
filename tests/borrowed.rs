//! Borrowed parsing retains slices into the caller's original encoded buffer.

use ciborium::Value;
use nazo_mdoc::{
    cbor::raw::Limits,
    model::{CborValueRef, CoseLabelRef, DeviceAuthRef, MsoRef},
    parser::{parse, parse_borrowed, parse_borrowed_with_limits, parse_issued_borrowed},
};

fn fixture() -> Vec<u8> {
    hex::decode(
        include_str!("vectors/iso_18013_5_annex_d_mdl.hex")
            .split_whitespace()
            .collect::<String>(),
    )
    .unwrap()
}

fn borrows(input: &[u8], value: &[u8]) {
    let start = input.as_ptr() as usize;
    let value_start = value.as_ptr() as usize;
    assert!(
        value_start >= start && value_start + value.len() <= start + input.len(),
        "slice does not refer to the original input"
    );
}

#[test]
fn parsed_fields_and_authenticated_material_borrow_the_original_input() {
    let input = fixture();
    let response = parse_borrowed(&input).unwrap();
    borrows(&input, response.version.as_bytes());
    for document in &response.documents {
        borrows(&input, document.doc_type.as_bytes());
        let auth = &document.issuer_signed.issuer_auth;
        borrows(&input, auth.cose_sign1.protected);
        borrows(&input, auth.cose_sign1.payload.unwrap());
        borrows(&input, auth.cose_sign1.signature);
        for certificate in auth.certificate_chain_der().unwrap() {
            borrows(&input, certificate);
        }
        for (namespace, items) in &document.issuer_signed.name_spaces {
            borrows(&input, namespace.as_bytes());
            for item in items {
                borrows(&input, item.random);
                borrows(&input, item.element_identifier.as_bytes());
                borrows(&input, item.encoded);
                borrows(&input, item.element_value.encoded());
                borrows(item.encoded, item.random);
                borrows(item.encoded, item.element_value.encoded());
            }
        }
        let mso = auth.mso().unwrap();
        borrows(&input, mso.version.as_bytes());
        borrows(&input, mso.doc_type.as_bytes());
        for (namespace, digests) in &mso.value_digests {
            borrows(&input, namespace.as_bytes());
            for digest in digests.values() {
                borrows(&input, digest);
            }
        }
        for (label, value) in &mso.device_key_info.device_key.params {
            borrows(&input, value.encoded());
            if matches!(label, CoseLabelRef::Int(-2 | -3)) {
                borrows(&input, value.as_bytes().unwrap());
            }
        }
        if let Some(device) = &document.device_signed {
            borrows(&input, device.name_spaces_bytes);
            match &device.device_auth {
                DeviceAuthRef::Signature(auth) => {
                    borrows(&input, auth.protected);
                    borrows(&input, auth.signature);
                }
                DeviceAuthRef::Mac(auth) => {
                    borrows(&input, auth.protected);
                    borrows(&input, auth.tag);
                }
            }
            for (namespace, elements) in &device.name_spaces {
                borrows(&input, namespace.as_bytes());
                for (identifier, value) in elements {
                    borrows(&input, identifier.as_bytes());
                    borrows(&input, value.encoded());
                }
            }
        }
    }
    let owned = response.into_owned().unwrap();
    let expected = parse(&input).unwrap();
    assert_eq!(owned.version, expected.version);
    assert_eq!(owned.documents.len(), expected.documents.len());
    for (document, expected) in owned.documents.iter().zip(&expected.documents) {
        assert_eq!(document.doc_type, expected.doc_type);
        assert_eq!(
            document.issuer_signed.issuer_auth.cose_sign1,
            expected.issuer_signed.issuer_auth.cose_sign1
        );
        for (namespace, items) in &document.issuer_signed.name_spaces {
            for (item, expected) in items
                .iter()
                .zip(&expected.issuer_signed.name_spaces[namespace])
            {
                assert_eq!(item.encoded, expected.encoded);
                assert_eq!(item.element_value, expected.element_value);
            }
        }
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn member_mut<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
    &mut value
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(name, _)| name.as_text() == Some(key))
        .unwrap()
        .1
}

#[test]
fn status_extensions_and_authorizations_remain_borrowed_until_explicit_conversion() {
    let input = fixture();
    let response = parse_borrowed(&input).unwrap();
    let payload = response.documents[0]
        .issuer_signed
        .issuer_auth
        .cose_sign1
        .payload
        .unwrap();
    let inner = nazo_mdoc::cbor::raw::tag24_inner(payload).unwrap();
    let mut mso: Value = ciborium::from_reader(inner).unwrap();
    let status = Value::Map(vec![
        (
            "status_list".into(),
            Value::Map(vec![
                ("idx".into(), 42.into()),
                ("uri".into(), "https://issuer.example/status".into()),
            ]),
        ),
        (
            "future".into(),
            Value::Tag(60000, Box::new(Value::Bytes(vec![7; 4096]))),
        ),
    ]);
    mso.as_map_mut()
        .unwrap()
        .push(("status".into(), status.clone()));
    mso.as_map_mut()
        .unwrap()
        .push(("extension".into(), Value::Bytes(vec![9; 4096])));
    let info = member_mut(&mut mso, "deviceKeyInfo");
    info.as_map_mut().unwrap().push((
        "keyAuthorizations".into(),
        Value::Map(vec![
            (
                "nameSpaces".into(),
                Value::Array(vec!["whole.namespace".into()]),
            ),
            (
                "dataElements".into(),
                Value::Map(vec![(
                    "other.namespace".into(),
                    Value::Array(vec!["element".into()]),
                )]),
            ),
        ]),
    ));
    let payload = encode(&Value::Tag(24, Box::new(Value::Bytes(encode(&mso)))));
    let parsed = MsoRef::parse(&payload).unwrap();
    let status_ref = parsed.status.as_ref().unwrap();
    borrows(&payload, status_ref.raw.encoded());
    borrows(
        &payload,
        status_ref.status_list.as_ref().unwrap().uri.as_bytes(),
    );
    borrows(
        &payload,
        parsed.additional_fields["extension"].as_bytes().unwrap(),
    );
    let authorizations = parsed.device_key_info.key_authorizations.as_ref().unwrap();
    for namespace in authorizations.name_spaces.as_ref().unwrap() {
        borrows(&payload, namespace.as_bytes());
    }
    for (namespace, elements) in authorizations.data_elements.as_ref().unwrap() {
        borrows(&payload, namespace.as_bytes());
        for element in elements {
            borrows(&payload, element.as_bytes());
        }
    }
    assert_eq!(status_ref.raw.to_owned().unwrap(), status);
    let owned = parsed.into_owned().unwrap();
    drop(payload);
    assert_eq!(owned.status.unwrap().raw, status);
    assert_eq!(
        owned.additional_fields["extension"].as_bytes().unwrap(),
        &[9; 4096]
    );
}

#[test]
fn value_views_keep_nested_spans_and_explicit_tag_identity() {
    let value = Value::Map(vec![(
        "nested".into(),
        Value::Array(vec![
            Value::Tag(2, Box::new(Value::Bytes(vec![1]))),
            Value::Integer((-(1i128 << 64)).try_into().unwrap()),
            Value::Text("borrowed".into()),
            Value::Bool(true),
            Value::Null,
            Value::Tag(24, Box::new(Value::Bytes(encode(&"embedded".into())))),
        ]),
    )]);
    let encoded = encode(&value);
    let borrowed = CborValueRef::parse(&encoded).unwrap();
    let (key, values) = borrowed.map().unwrap().next().unwrap().unwrap();
    borrows(&encoded, key.as_text().unwrap().as_bytes());
    let values: Vec<_> = values.array().unwrap().map(Result::unwrap).collect();
    for value in &values {
        borrows(&encoded, value.encoded());
    }
    assert_eq!(values[0].as_integer(), None);
    let (tag, tagged) = values[0].tagged().unwrap();
    assert_eq!(tag, 2);
    borrows(&encoded, tagged.as_bytes().unwrap());
    assert_eq!(values[1].as_integer(), Some(-(1i128 << 64)));
    borrows(&encoded, values[2].as_text().unwrap().as_bytes());
    assert_eq!(values[3].as_bool(), Some(true));
    assert!(values[4].is_null());
    let embedded = values[5].embedded().unwrap();
    assert_eq!(embedded.as_text(), Some("embedded"));
    borrows(&encoded, embedded.as_text().unwrap().as_bytes());
    assert!(values[2].tagged().is_err());
    assert!(values[0].embedded().is_err());
    assert_eq!(values[1].as_float(), None);
    assert_eq!(values[2].as_bool(), None);
    assert!(!values[2].is_null());
    assert_eq!(borrowed.to_owned().unwrap(), value);

    // Scalar access supports every IEEE 754 wire width without owning a value
    // tree, including the sign of zero and non-finite values.
    for (wire, expected) in [
        (&[0xf9, 0x80, 0x00][..], -0.0f64),
        (&[0xfa, 0x3f, 0xc0, 0x00, 0x00][..], 1.5),
        (&[0xfb, 0xc0, 0x04, 0, 0, 0, 0, 0, 0][..], -2.5),
        (&[0xf9, 0x7c, 0x00][..], f64::INFINITY),
    ] {
        let parsed = CborValueRef::parse(wire).unwrap();
        assert_eq!(parsed.as_float().unwrap().to_bits(), expected.to_bits());
        assert_eq!(parsed.as_integer(), None);
    }
    assert!(
        CborValueRef::parse(&[0xf9, 0x7e, 0x00])
            .unwrap()
            .as_float()
            .unwrap()
            .is_nan()
    );
}

#[test]
fn borrowed_entry_points_preserve_input_limits_and_reject_bad_envelopes() {
    let input = fixture();
    assert!(parse_borrowed_with_limits(&input, Limits::default(), 0).is_err());
    assert!(
        parse_borrowed_with_limits(
            &input,
            Limits {
                max_bytes: input.len() - 1,
                ..Limits::default()
            },
            16
        )
        .is_err()
    );
    for bytes in [
        &[][..],
        &[0xa0],
        &[0x00, 0x00],
        &[0xa2, 0x61, b'a', 1, 0x61, b'a', 2],
    ] {
        assert!(parse_borrowed(bytes).is_err());
        assert!(parse_issued_borrowed(bytes).is_err());
    }
}

#[test]
fn issued_borrowed_parser_uses_the_callers_envelope() {
    let input = fixture();
    let response: Value = ciborium::from_reader(input.as_slice()).unwrap();
    let document = &response
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_text() == Some("documents"))
        .unwrap()
        .1
        .as_array()
        .unwrap()[0];
    let issuer = &document
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_text() == Some("issuerSigned"))
        .unwrap()
        .1;
    let encoded = encode(issuer);
    let issuer = parse_issued_borrowed(&encoded).unwrap();
    borrows(&encoded, issuer.issuer_auth.cose_sign1.payload.unwrap());
    for items in issuer.name_spaces.values() {
        for item in items {
            borrows(&encoded, item.encoded);
        }
    }
}

#[cfg(feature = "issue")]
#[test]
fn relaxed_parsing_limits_do_not_raise_default_holder_mso_limits() {
    use nazo_mdoc::{
        MdocError,
        response_builder::{prepare_device_authentication, prepare_device_authentication_borrowed},
        session::SessionTranscript,
    };

    let original: Value = ciborium::from_reader(fixture().as_slice()).unwrap();
    let defaults = Limits::default();
    let mut nested = Value::Null;
    for _ in 0..defaults.max_depth {
        nested = Value::Array(vec![nested]);
    }
    let transcript = SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    let namespaces = &[0xd8, 0x18, 0x41, 0xa0];
    for (extension, limits, expected) in [
        (
            Value::Array(vec![Value::Null; defaults.max_collection_items + 1]),
            Limits {
                max_collection_items: defaults.max_collection_items + 1,
                ..defaults
            },
            "CBOR collection limit exceeded",
        ),
        (
            nested,
            Limits {
                max_depth: defaults.max_depth + 4,
                ..defaults
            },
            "CBOR nesting limit exceeded",
        ),
    ] {
        let mut response = original.clone();
        let document = &mut member_mut(&mut response, "documents")
            .as_array_mut()
            .unwrap()[0];
        let issuer = member_mut(document, "issuerSigned");
        let fields = member_mut(issuer, "issuerAuth").as_array_mut().unwrap();
        let payload = fields[2].as_bytes().unwrap();
        let mut mso: Value =
            ciborium::from_reader(nazo_mdoc::cbor::raw::tag24_inner(payload).unwrap()).unwrap();
        mso.as_map_mut()
            .unwrap()
            .push(("extension".into(), extension));
        fields[2] = Value::Bytes(encode(&Value::Tag(
            24,
            Box::new(Value::Bytes(encode(&mso))),
        )));
        let encoded = encode(&response);
        assert!(encoded.len() < defaults.max_bytes);
        let parsed = parse_borrowed_with_limits(&encoded, limits, 16)
            .expect("custom parsing limits permit this MSO envelope");
        let document = parsed.documents.into_iter().next().unwrap();
        assert!(matches!(
            document.issuer_signed.issuer_auth.mso(),
            Err(MdocError::Cbor(reason)) if reason == expected
        ));
        let owned = document.clone().into_owned().unwrap();
        assert!(matches!(
            prepare_device_authentication_borrowed(document, &transcript, namespaces, -7),
            Err(MdocError::Cbor(reason)) if reason == expected
        ));
        assert!(matches!(
            prepare_device_authentication(owned, &transcript, namespaces.to_vec(), -7),
            Err(MdocError::Cbor(reason)) if reason == expected
        ));
    }
}
