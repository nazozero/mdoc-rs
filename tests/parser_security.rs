//! Wire-level regressions run without the issuance feature.
use ciborium::Value;
use nazo_mdoc::{cbor::raw::Limits, parser};

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
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

fn cose(protected: Vec<u8>, unprotected: Value) -> Value {
    Value::Array(vec![
        Value::Bytes(protected),
        unprotected,
        Value::Null,
        Value::Bytes(vec![0; 64]),
    ])
}

fn issuer_signed() -> Value {
    map(vec![(
        "issuerAuth",
        cose(hex::decode("a10126").unwrap(), Value::Map(vec![])),
    )])
}

fn parses_headers(protected: Vec<u8>, unprotected: Value, mechanism: &str) -> bool {
    parses_headers_with_limits(protected, unprotected, mechanism, Limits::default())
}

fn parses_headers_with_limits(
    protected: Vec<u8>,
    unprotected: Value,
    mechanism: &str,
    limits: Limits,
) -> bool {
    let auth = cose(protected, unprotected);
    if mechanism == "issuerAuth" {
        return parser::parse_issued_with_limits(&encode(&map(vec![(mechanism, auth)])), limits)
            .is_ok();
    }
    let device_signed = map(vec![
        (
            "nameSpaces",
            Value::Tag(24, Box::new(Value::Bytes(vec![0xa0]))),
        ),
        ("deviceAuth", map(vec![(mechanism, auth)])),
    ]);
    let document = map(vec![
        ("docType", "test".into()),
        ("issuerSigned", issuer_signed()),
        ("deviceSigned", device_signed),
    ]);
    let response = map(vec![
        ("version", "1.0".into()),
        ("documents", Value::Array(vec![document])),
        ("status", 0.into()),
    ]);
    parser::parse_with_limits(&encode(&response), limits, 1).is_ok()
}

fn issuer_with_payload(payload: Vec<u8>) -> Vec<u8> {
    let mut issuer = issuer_signed();
    issuer.as_map_mut().unwrap()[0].1.as_array_mut().unwrap()[2] = Value::Bytes(payload);
    encode(&issuer)
}

#[test]
fn issuer_namespaces_may_be_absent_but_cannot_be_an_explicit_empty_map() {
    let mut issuer = issuer_signed();
    assert!(parser::parse_issued(&encode(&issuer)).is_ok());
    issuer
        .as_map_mut()
        .unwrap()
        .push(("nameSpaces".into(), Value::Map(vec![])));
    assert!(parser::parse_issued(&encode(&issuer)).is_err());
}

#[test]
fn empty_security_headers_cannot_disappear_during_cose_decoding() {
    for mechanism in ["issuerAuth", "deviceSignature", "deviceMac"] {
        for (label, value) in [
            (3, Value::Text(String::new())),
            (5, Value::Bytes(vec![])),
            (6, Value::Bytes(vec![])),
            (7, Value::Array(vec![])),
            (9, Value::Bytes(vec![])),
        ] {
            let protected = encode(&Value::Map(vec![
                (1.into(), (-7).into()),
                (label.into(), value.clone()),
            ]));
            assert!(!parses_headers(protected, Value::Map(vec![]), mechanism));
            assert!(!parses_headers(
                hex::decode("a10126").unwrap(),
                Value::Map(vec![(label.into(), value)]),
                mechanism
            ));
        }
    }
}

#[test]
fn duplicate_header_labels_are_rejected_across_buckets_even_for_empty_kid() {
    for mechanism in ["issuerAuth", "deviceSignature", "deviceMac"] {
        for protected_kid in [vec![], vec![1]] {
            for unprotected_kid in [vec![], vec![2]] {
                let protected = encode(&Value::Map(vec![
                    (1.into(), (-7).into()),
                    (4.into(), Value::Bytes(protected_kid.clone())),
                ]));
                let unprotected = Value::Map(vec![(4.into(), Value::Bytes(unprotected_kid))]);
                assert!(!parses_headers(protected, unprotected, mechanism));
            }
        }
        let protected = encode(&Value::Map(vec![
            (1.into(), (-7).into()),
            (33.into(), Value::Bytes(vec![1])),
        ]));
        assert!(!parses_headers(
            protected,
            Value::Map(vec![(33.into(), Value::Bytes(vec![1]))]),
            mechanism
        ));
    }
}

#[test]
fn a_single_nonempty_kid_is_accepted_and_an_empty_kid_fails_closed() {
    for mechanism in ["issuerAuth", "deviceSignature", "deviceMac"] {
        assert!(parses_headers(
            hex::decode("a20126044101").unwrap(),
            Value::Map(vec![]),
            mechanism
        ));
        assert!(parses_headers(
            hex::decode("a10126").unwrap(),
            Value::Map(vec![(4.into(), Value::Bytes(vec![1]))]),
            mechanism
        ));
        assert!(!parses_headers(
            hex::decode("a201260440").unwrap(),
            Value::Map(vec![]),
            mechanism
        ));
        assert!(!parses_headers(
            hex::decode("a10126").unwrap(),
            Value::Map(vec![(4.into(), Value::Bytes(vec![]))]),
            mechanism
        ));
    }
}

#[test]
fn unknown_text_private_and_unsigned_header_labels_fail_closed() {
    for label in [
        Value::Text("future".into()),
        (-65_537).into(),
        65_537.into(),
    ] {
        let protected = encode(&Value::Map(vec![
            (1.into(), (-7).into()),
            (label.clone(), true.into()),
        ]));
        assert!(!parses_headers(protected, Value::Map(vec![]), "issuerAuth"));
        assert!(!parses_headers(
            hex::decode("a10126").unwrap(),
            Value::Map(vec![(label, true.into())]),
            "issuerAuth"
        ));
    }
}

#[test]
fn protected_headers_reject_duplicate_nonminimal_or_trailing_cbor() {
    for protected in ["a3012604400440", "a1180126", "a1012600", "bf0126ff", "8101"] {
        assert!(!parses_headers(
            hex::decode(protected).unwrap(),
            Value::Map(vec![]),
            "issuerAuth"
        ));
    }
}

#[test]
fn empty_protected_bstr_is_decodable_but_does_not_claim_authentication() {
    // Parsing reports structure only. Signature verification separately requires
    // an authenticated algorithm and cannot accept this missing protected alg.
    assert!(parses_headers(vec![], Value::Map(vec![]), "issuerAuth"));
}

#[test]
fn custom_collection_limits_reach_protected_headers_in_all_cose_roles() {
    let protected = encode(&Value::Map(vec![
        (1.into(), (-7).into()),
        (2.into(), Value::Array(vec![1.into(); 9])),
    ]));
    let limits = Limits {
        max_collection_items: 8,
        ..Limits::default()
    };
    for mechanism in ["issuerAuth", "deviceSignature", "deviceMac"] {
        assert!(parses_headers(
            protected.clone(),
            Value::Map(vec![]),
            mechanism
        ));
        assert!(!parses_headers_with_limits(
            protected.clone(),
            Value::Map(vec![]),
            mechanism,
            limits
        ));
    }
}

#[test]
fn custom_depth_and_item_limits_reach_protected_headers() {
    let mut nested = Value::Null;
    for _ in 0..8 {
        nested = Value::Array(vec![nested]);
    }
    let protected = encode(&Value::Map(vec![
        (1.into(), (-7).into()),
        (33.into(), nested),
    ]));
    assert!(parses_headers(
        protected.clone(),
        Value::Map(vec![]),
        "issuerAuth"
    ));
    assert!(!parses_headers_with_limits(
        protected,
        Value::Map(vec![]),
        "issuerAuth",
        Limits {
            max_depth: 3,
            ..Limits::default()
        }
    ));

    let protected = encode(&Value::Map(vec![
        (1.into(), (-7).into()),
        (2.into(), Value::Array(vec![1.into(); 64])),
    ]));
    assert!(parses_headers(
        protected.clone(),
        Value::Map(vec![]),
        "issuerAuth"
    ));
    assert!(!parses_headers_with_limits(
        protected,
        Value::Map(vec![]),
        "issuerAuth",
        Limits {
            max_items: 64,
            ..Limits::default()
        }
    ));
}

#[test]
fn custom_limits_reach_mso_cbor_inside_the_cose_payload_byte_string() {
    let inner = map(vec![("extension", Value::Array(vec![Value::Null; 64]))]);
    let payload = encode(&Value::Tag(24, Box::new(Value::Bytes(encode(&inner)))));
    let wire = issuer_with_payload(payload);
    assert!(parser::parse_issued(&wire).is_ok());
    for limits in [
        Limits {
            max_collection_items: 8,
            ..Limits::default()
        },
        Limits {
            max_items: 64,
            ..Limits::default()
        },
    ] {
        assert!(parser::parse_issued_with_limits(&wire, limits).is_err());
    }

    let mut nested = Value::Null;
    for _ in 0..8 {
        nested = Value::Array(vec![nested]);
    }
    let inner = map(vec![("extension", nested)]);
    let payload = encode(&Value::Tag(24, Box::new(Value::Bytes(encode(&inner)))));
    let wire = issuer_with_payload(payload);
    assert!(parser::parse_issued(&wire).is_ok());
    assert!(
        parser::parse_issued_with_limits(
            &wire,
            Limits {
                max_depth: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn present_mso_payload_must_be_one_tag24_wrapped_map() {
    let valid = hex::decode("d81841a0").unwrap();
    assert!(parser::parse_issued(&issuer_with_payload(valid)).is_ok());
    for malformed in [
        "a0",
        "d8184100",
        "d81841a000",
        "d81842a000",
        "d81841bf",
        "d81841a1",
    ] {
        assert!(
            parser::parse_issued(&issuer_with_payload(hex::decode(malformed).unwrap())).is_err()
        );
    }
}
