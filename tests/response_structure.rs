//! DeviceResponse envelope regressions, enabled without the issuance feature.
//!
//! Mutations start from the inherited ISO Annex D wire fixture. Parsing proves
//! structure only: known error statuses and unknown textual versions remain
//! visible in the model, while the presentation verifier must reject them
//! before attempting issuer or holder authentication.

use ciborium::Value;
use nazo_mdoc::{
    MdocError, VerificationOptions, cbor::raw::Limits, parser, session::SessionTranscript,
    time::Timestamp, verify_presentation,
};

fn fixture() -> Value {
    let bytes = hex::decode(
        include_str!("vectors/iso_18013_5_annex_d_mdl.hex")
            .split_whitespace()
            .collect::<String>(),
    )
    .unwrap();
    ciborium::from_reader(bytes.as_slice()).unwrap()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
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

fn replace_or_remove(value: &mut Value, name: &str, replacement: Option<Value>) {
    match replacement {
        Some(replacement) => *field_mut(value, name) = replacement,
        None => value
            .as_map_mut()
            .unwrap()
            .retain(|(key, _)| key.as_text() != Some(name)),
    }
}

fn document_mut(response: &mut Value) -> &mut Value {
    &mut field_mut(response, "documents").as_array_mut().unwrap()[0]
}

fn assert_rejected_by_presentation_envelope(bytes: &[u8]) {
    // These cases must fail at the envelope gate, before this structural-only
    // transcript or the fixture's DeviceMAC can be used as holder evidence.
    let transcript = SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    let error = verify_presentation(
        bytes,
        &transcript,
        &VerificationOptions {
            now: Timestamp::from_unix_seconds(1_609_459_200).unwrap(),
            max_documents: 16,
        },
    )
    .unwrap_err();
    assert!(
        matches!(&error, MdocError::Parse(reason)
            if reason == "unsupported version or non-success DeviceResponse status"),
        "expected envelope rejection, got {error:?}"
    );
}

#[test]
fn device_response_root_must_be_a_map() {
    assert!(parser::parse(&encode(&fixture())).is_ok());
    for root in [Value::Null, Value::Array(vec![]), true.into(), "1.0".into()] {
        assert!(parser::parse(&encode(&root)).is_err(), "root: {root:?}");
    }
}

#[test]
fn device_response_version_is_required_text_and_supported_for_verification() {
    for replacement in [
        None,
        Some(Value::Null),
        Some(1.into()),
        Some(Value::Bytes(b"1.0".to_vec())),
        Some(Value::Array(vec![])),
    ] {
        let mut response = fixture();
        replace_or_remove(&mut response, "version", replacement.clone());
        assert!(
            parser::parse(&encode(&response)).is_err(),
            "version: {replacement:?}"
        );
    }
    for version in ["", "0.9", "1.1", "2.0", "1.0\0"] {
        let mut response = fixture();
        *field_mut(&mut response, "version") = version.into();
        let bytes = encode(&response);
        assert_eq!(parser::parse(&bytes).unwrap().version, version);
        assert_rejected_by_presentation_envelope(&bytes);
    }
}

#[test]
fn device_response_status_is_required_unsigned_known_and_successful_for_verification() {
    for replacement in [
        None,
        Some(Value::Null),
        Some((-1).into()),
        Some(1.into()),
        Some(9.into()),
        Some(13.into()),
        Some(255.into()),
        Some(256.into()),
        Some(u64::MAX.into()),
        Some(Value::Float(0.0)),
        Some(false.into()),
        Some("0".into()),
        Some(Value::Bytes(vec![0])),
    ] {
        let mut response = fixture();
        replace_or_remove(&mut response, "status", replacement.clone());
        assert!(
            parser::parse(&encode(&response)).is_err(),
            "status: {replacement:?}"
        );
    }
    for status in [10u8, 11, 12] {
        let mut response = fixture();
        *field_mut(&mut response, "status") = status.into();
        let bytes = encode(&response);
        assert_eq!(parser::parse(&bytes).unwrap().status as u8, status);
        assert_rejected_by_presentation_envelope(&bytes);
    }
}

#[test]
fn device_response_documents_are_required_nonempty_arrays() {
    for replacement in [
        None,
        Some(Value::Null),
        Some(Value::Map(vec![])),
        Some(1.into()),
        Some("documents".into()),
        Some(Value::Bytes(vec![])),
    ] {
        let mut response = fixture();
        replace_or_remove(&mut response, "documents", replacement.clone());
        assert!(
            parser::parse(&encode(&response)).is_err(),
            "documents: {replacement:?}"
        );
    }
    let mut response = fixture();
    *field_mut(&mut response, "documents") = Value::Array(vec![]);
    assert!(matches!(
        parser::parse(&encode(&response)),
        Err(MdocError::DocumentCount { actual: 0, max: 16 })
    ));
}

#[test]
fn device_response_document_count_limits_apply_before_document_decoding() {
    let mut response = fixture();
    let document = document_mut(&mut response).clone();
    let one = encode(&response);
    assert!(matches!(
        parser::parse_with_limits(&one, Limits::default(), 0),
        Err(MdocError::DocumentCount { actual: 1, max: 0 })
    ));
    for maximum in [1, 2, 16] {
        *field_mut(&mut response, "documents") = Value::Array(vec![document.clone(); maximum]);
        let bytes = encode(&response);
        assert_eq!(
            parser::parse_with_limits(&bytes, Limits::default(), maximum)
                .unwrap()
                .documents
                .len(),
            maximum
        );
        // Invalid documents must not be decoded once the array length already
        // exceeds policy. Assert the count error, not a later map/type error.
        *field_mut(&mut response, "documents") = Value::Array(vec![Value::Null; maximum + 1]);
        assert!(matches!(
            parser::parse_with_limits(&encode(&response), Limits::default(), maximum),
            Err(MdocError::DocumentCount { actual, max })
                if actual == maximum + 1 && max == maximum
        ));
    }
    *field_mut(&mut response, "documents") = Value::Array(vec![Value::Null; 17]);
    assert!(matches!(
        parser::parse(&encode(&response)),
        Err(MdocError::DocumentCount {
            actual: 17,
            max: 16
        })
    ));
}

#[test]
fn document_required_fields_reject_missing_empty_and_wrong_types() {
    for name in ["docType", "issuerSigned"] {
        for replacement in [
            None,
            Some(Value::Null),
            Some(1.into()),
            Some(Value::Bytes(vec![])),
            Some(Value::Array(vec![])),
            Some(Value::Map(vec![])),
            Some("".into()),
        ] {
            let mut response = fixture();
            replace_or_remove(document_mut(&mut response), name, replacement.clone());
            assert!(
                parser::parse(&encode(&response)).is_err(),
                "{name}: {replacement:?}"
            );
        }
    }
    for replacement in [
        Value::Null,
        1.into(),
        Value::Array(vec![]),
        Value::Map(vec![]),
    ] {
        let mut response = fixture();
        *field_mut(document_mut(&mut response), "deviceSigned") = replacement.clone();
        assert!(
            parser::parse(&encode(&response)).is_err(),
            "deviceSigned: {replacement:?}"
        );
    }
}

#[test]
fn missing_device_signed_cannot_be_a_verified_presentation() {
    let mut response = fixture();
    replace_or_remove(document_mut(&mut response), "deviceSigned", None);
    let bytes = encode(&response);
    assert!(
        parser::parse(&bytes).unwrap().documents[0]
            .device_signed
            .is_none()
    );
    let transcript = SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    assert!(matches!(
        verify_presentation(
            &bytes,
            &transcript,
            &VerificationOptions {
                now: Timestamp::from_unix_seconds(1_609_459_200).unwrap(),
                max_documents: 1,
            },
        ),
        Err(MdocError::DeviceAuth(reason)) if reason == "missing holder authentication"
    ));
}

#[test]
fn unknown_or_duplicate_response_and_document_fields_fail_closed() {
    for document_level in [false, true] {
        let mut response = fixture();
        let object = if document_level {
            document_mut(&mut response)
        } else {
            &mut response
        };
        object
            .as_map_mut()
            .unwrap()
            .push(("future_security_extension".into(), true.into()));
        assert!(parser::parse(&encode(&response)).is_err());
    }
    for (document_level, fields) in [
        (false, ["version", "status", "documents"]),
        (true, ["docType", "issuerSigned", "deviceSigned"]),
    ] {
        for name in fields {
            let mut response = fixture();
            let object = if document_level {
                document_mut(&mut response)
            } else {
                &mut response
            };
            let duplicate = field_mut(object, name).clone();
            object.as_map_mut().unwrap().push((name.into(), duplicate));
            assert!(
                matches!(parser::parse(&encode(&response)), Err(MdocError::Cbor(_))),
                "duplicate {name}"
            );
        }
    }
}
