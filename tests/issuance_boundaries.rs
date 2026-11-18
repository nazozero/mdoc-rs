//! Caller-supplied status is checked before preparing an external signature.
#![cfg(feature = "issue")]

mod common;

use ciborium::Value;
use common::*;
use nazo_mdoc::model::CoseAlgorithm;

fn status_list(fields: Vec<(Value, Value)>) -> Value {
    Value::Map(vec![("status_list".into(), Value::Map(fields))])
}

#[test]
fn preparation_rejects_invalid_and_duplicate_status_fields() {
    let valid_uri = Value::Text("https://issuer.example/status".into());
    let mut too_deep = Value::Null;
    for _ in 0..33 {
        too_deep = Value::Array(vec![too_deep]);
    }
    for status in [
        Value::Null,
        Value::Map(vec![]),
        Value::Map(vec![(1.into(), Value::Null)]),
        Value::Map(vec![("status_list".into(), Value::Null)]),
        status_list(vec![("uri".into(), valid_uri.clone())]),
        status_list(vec![("idx".into(), 1.into())]),
        status_list(vec![
            ("idx".into(), (-1).into()),
            ("uri".into(), valid_uri.clone()),
        ]),
        status_list(vec![
            ("idx".into(), 1.into()),
            ("uri".into(), "relative/path".into()),
        ]),
        status_list(vec![
            ("idx".into(), 1.into()),
            ("uri".into(), valid_uri.clone()),
            ("uri".into(), valid_uri),
        ]),
        Value::Map(vec![("custom".into(), too_deep)]),
    ] {
        assert!(
            builder()
                .status_raw(status)
                .prepare(
                    CoseAlgorithm::ES256,
                    vec![hex::decode(GENUINE_CERT_HEX).unwrap()]
                )
                .is_err()
        );
    }
}

#[test]
fn preparation_preserves_custom_authenticated_status_values() {
    let status = Value::Map(vec![(
        "custom".into(),
        Value::Tag(1000, Box::new(Value::Array(vec![true.into(), 42.into()]))),
    )]);
    let document = issue(builder().status_raw(status.clone()));
    let verified = nazo_mdoc::verifier::verify_issued(
        &document.to_issuer_signed_cbor().unwrap(),
        DOC_TYPE,
        now(),
    )
    .unwrap();
    assert_eq!(verified.mso().status.as_ref().unwrap().raw, status);
}
