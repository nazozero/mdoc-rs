use ciborium::Value;
use nazo_mdoc::reader::{ItemsRequest, ResponseEnvelope, encode_device_request};

#[cfg(feature = "issue")]
mod common;

fn encode(value: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    bytes
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

fn request(elements: Vec<(&str, Value)>) -> Vec<u8> {
    let inner = encode(map(vec![
        (
            "requestInfo",
            map(vec![(
                "application.example",
                Value::Array(vec![1.into(), true.into()]),
            )]),
        ),
        (
            "nameSpaces",
            map(vec![("org.iso.18013.5.1", map(elements))]),
        ),
        ("docType", "org.iso.18013.5.1.mDL".into()),
    ]));
    encode(Value::Tag(24, Box::new(Value::Bytes(inner))))
}

fn response(status: u64, extra: Vec<(&str, Value)>) -> Vec<u8> {
    let mut fields = vec![("version", "1.0".into()), ("status", status.into())];
    fields.extend(extra);
    encode(map(fields))
}

#[test]
fn independently_generated_reader_authentication_vector() {
    let vector: std::collections::HashMap<_, _> =
        include_str!("vectors/reader/reader_authentication.tsv")
            .lines()
            .map(|line| {
                let (name, value) = line.split_once('\t').unwrap();
                (name, hex::decode(value).unwrap())
            })
            .collect();
    let items = ItemsRequest::from_bytes(&vector["items"]).unwrap();
    let transcript =
        nazo_mdoc::session::SessionTranscript::from_cbor(&vector["transcript"]).unwrap();
    let chain = [vector["certificate"].as_slice()];
    let prepared =
        nazo_mdoc::reader::prepare_reader_authentication(items, &transcript, &chain, -7).unwrap();
    assert_eq!(prepared.signing_input(), vector["signing_input"]);
    let document = prepared.finish(&vector["signature"]).unwrap();
    encode_device_request(&[document]).unwrap();
    let mut changed = vector["signature"].clone();
    changed[0] ^= 1;
    assert!(
        nazo_mdoc::reader::prepare_reader_authentication(items, &transcript, &chain, -7)
            .unwrap()
            .finish(&changed)
            .is_err()
    );
    let mut changed_transcript = vector["transcript"].clone();
    let point_index = changed_transcript.len() - 5;
    changed_transcript[point_index] ^= 1;
    let changed_transcript =
        nazo_mdoc::session::SessionTranscript::from_cbor(&changed_transcript).unwrap();
    assert!(
        nazo_mdoc::reader::prepare_reader_authentication(items, &changed_transcript, &chain, -7)
            .unwrap()
            .finish(&vector["signature"])
            .is_err()
    );
}

#[test]
fn unsigned_requests_retain_exact_items_and_unknown_request_info() {
    let bytes = request(vec![
        ("family_name", false.into()),
        ("age_over_18", true.into()),
    ]);
    let items = ItemsRequest::from_bytes(&bytes).unwrap();
    assert!(std::ptr::eq(items.as_bytes(), bytes.as_slice()));
    let output = encode_device_request(&[items.unsigned()]).unwrap();
    assert_eq!(output.age_requests(), 1);
    let decoded: Value = ciborium::from_reader(output.as_bytes()).unwrap();
    let documents = decoded
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_text() == Some("docRequests"))
        .unwrap()
        .1
        .as_array()
        .unwrap();
    let document = documents[0].as_map().unwrap();
    assert_eq!(document.len(), 1);
    assert_eq!(encode(document[0].1.clone()), bytes);
}

#[test]
fn request_schema_rejects_ambiguous_or_empty_requested_elements() {
    for bytes in [
        request(vec![]),
        request(vec![("family_name", 1.into())]),
        request(vec![
            ("family_name", false.into()),
            ("family_name", true.into()),
        ]),
        request(vec![("", false.into())]),
        encode(Value::Tag(
            24,
            Box::new(Value::Bytes(encode(map(vec![(
                "docType",
                "example".into(),
            )])))),
        )),
    ] {
        assert!(ItemsRequest::from_bytes(&bytes).is_err());
    }
    assert!(encode_device_request(&[]).is_err());
}

#[test]
fn age_attestation_limit_applies_to_the_complete_request() {
    let one = request(vec![("age_over_18", false.into())]);
    let two = request(vec![
        ("age_over_21", false.into()),
        ("age_over_65", false.into()),
    ]);
    let three = request(vec![
        ("age_over_18", false.into()),
        ("age_over_21", false.into()),
        ("age_over_65", false.into()),
    ]);
    assert!(ItemsRequest::from_bytes(&three).is_err());
    assert!(
        encode_device_request(&[
            ItemsRequest::from_bytes(&one).unwrap().unsigned(),
            ItemsRequest::from_bytes(&two).unwrap().unsigned()
        ])
        .is_err()
    );
    assert_eq!(
        encode_device_request(&[ItemsRequest::from_bytes(&two).unwrap().unsigned()])
            .unwrap()
            .age_requests(),
        2
    );
}

#[test]
fn status_only_and_document_errors_are_available_without_claims() {
    for status in [0, 10, 11, 12, 999] {
        let bytes = response(status, vec![]);
        let envelope = ResponseEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(envelope.status(), status);
        assert!(envelope.documents().is_none());
        assert!(nazo_mdoc::parse_borrowed(&bytes).is_err());
    }
    for code in [0, -123, 999] {
        let bytes = response(
            0,
            vec![(
                "documentErrors",
                Value::Array(vec![map(vec![("example", code.into())])]),
            )],
        );
        let envelope = ResponseEnvelope::from_bytes(&bytes).unwrap();
        let errors = envelope.document_errors().unwrap();
        let actual = errors
            .array()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .map()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .1
            .as_integer();
        assert_eq!(actual, Some(code as i128));
        assert!(nazo_mdoc::parse_borrowed(&bytes).is_err());
    }
}

#[test]
fn mixed_document_errors_never_relax_atomic_presentation_verification() {
    let document = map(vec![
        ("docType", "example".into()),
        ("issuerSigned", map(vec![])),
        ("deviceSigned", map(vec![])),
        (
            "errors",
            map(vec![("example", map(vec![("missing", 0.into())]))]),
        ),
    ]);
    let bytes = response(
        0,
        vec![
            ("documents", Value::Array(vec![document.clone()])),
            (
                "documentErrors",
                Value::Array(vec![map(vec![("another", (-42).into())])]),
            ),
        ],
    );
    let envelope = ResponseEnvelope::from_bytes(&bytes).unwrap();
    assert!(envelope.documents().is_some());
    assert!(envelope.document_errors().is_some());
    assert!(nazo_mdoc::parse_borrowed(&bytes).is_err());
    let bytes = response(10, vec![("documents", Value::Array(vec![document]))]);
    assert!(ResponseEnvelope::from_bytes(&bytes).is_err());
}

#[test]
fn response_errors_reject_invalid_shapes_duplicates_and_trailing_bytes() {
    for extra in [
        vec![("documents", Value::Array(vec![]))],
        vec![("documentErrors", Value::Array(vec![]))],
        vec![(
            "documentErrors",
            Value::Array(vec![map(vec![("example", true.into())])]),
        )],
        vec![("status", 0.into())],
        vec![(
            "documentErrors",
            Value::Array(vec![map(vec![("one", 0.into()), ("two", 0.into())])]),
        )],
    ] {
        assert!(ResponseEnvelope::from_bytes(&response(0, extra)).is_err());
    }
    let mut bytes = response(0, vec![]);
    bytes.push(0);
    assert!(ResponseEnvelope::from_bytes(&bytes).is_err());
}

#[cfg(feature = "issue")]
mod signing {
    use super::*;
    use coset::CborSerializable;
    use nazo_mdoc::reader::prepare_reader_authentication;
    use signature::{Signer, Verifier};

    #[test]
    fn reader_signature_binds_exact_request_transcript_and_certificate() {
        let bytes = request(vec![("family_name", false.into())]);
        let cert = hex::decode(common::GENUINE_CERT_HEX).unwrap();
        let chain = [cert.as_slice()];
        let transcript = common::transcript();
        let prepared = prepare_reader_authentication(
            ItemsRequest::from_bytes(&bytes).unwrap(),
            &transcript,
            &chain,
            -7,
        )
        .unwrap();
        assert_eq!(prepared.algorithm(), -7);
        let input = prepared.signing_input().to_vec();
        let sig: p256::ecdsa::Signature = common::issuer_key().sign(&input);
        let document = prepared.finish(&sig.to_bytes()).unwrap();
        let cose = coset::CoseSign1::from_slice(document.reader_authentication().unwrap()).unwrap();
        assert!(cose.payload.is_none());
        assert_eq!(
            cose.protected.original_data.as_deref(),
            Some(&[0xa1, 0x01, 0x26][..])
        );
        assert_eq!(cose.unprotected.rest[0].0, coset::Label::Int(33));
        assert_eq!(cose.unprotected.rest[0].1.as_bytes(), Some(&cert));
        let payload = encode(Value::Tag(
            24,
            Box::new(Value::Bytes(encode(Value::Array(vec![
                "ReaderAuthentication".into(),
                ciborium::from_reader(transcript.as_bytes()).unwrap(),
                ciborium::from_reader(bytes.as_slice()).unwrap(),
            ])))),
        ));
        assert_eq!(cose.tbs_detached_data(&payload, &[]), input);
        common::issuer_key()
            .verifying_key()
            .verify(&input, &sig)
            .unwrap();
        let output = encode_device_request(&[document]).unwrap();
        nazo_mdoc::cbor::raw::validate(output.as_bytes()).unwrap();
    }

    #[test]
    fn external_completion_rejects_wrong_key_input_der_and_algorithm() {
        let bytes = request(vec![("family_name", false.into())]);
        let cert = hex::decode(common::GENUINE_CERT_HEX).unwrap();
        let chain = [cert.as_slice()];
        let transcript = common::transcript();
        let prepare = || {
            prepare_reader_authentication(
                ItemsRequest::from_bytes(&bytes).unwrap(),
                &transcript,
                &chain,
                -7,
            )
            .unwrap()
        };
        let prepared = prepare();
        let sig: p256::ecdsa::Signature = common::holder_key().sign(prepared.signing_input());
        assert!(prepared.finish(&sig.to_bytes()).is_err());
        let prepared = prepare();
        let sig: p256::ecdsa::Signature = common::issuer_key().sign(b"changed request");
        assert!(prepared.finish(&sig.to_bytes()).is_err());
        let prepared = prepare();
        let sig: p256::ecdsa::Signature = common::issuer_key().sign(prepared.signing_input());
        assert!(prepared.finish(sig.to_der().as_bytes()).is_err());
        assert!(
            prepare_reader_authentication(
                ItemsRequest::from_bytes(&bytes).unwrap(),
                &transcript,
                &chain,
                -35
            )
            .is_err()
        );
        assert!(
            prepare_reader_authentication(
                ItemsRequest::from_bytes(&bytes).unwrap(),
                &transcript,
                &[],
                -7
            )
            .is_err()
        );
    }
}
