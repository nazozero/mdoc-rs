//! Wire-equivalence checks for the borrowed encoder and validated projection.

use ciborium::Value;
use nazo_mdoc::cbor::data_item::{decode_cbor, encode_cbor, encode_cbor_canonical};
use proptest::prelude::*;
use std::collections::BTreeMap;

// Independent ordering oracle: serialize each key with ciborium and compare
// its bytes, including integer-width and string-length transitions.
fn reference_canonical(value: &Value) -> Value {
    match value {
        Value::Map(entries) => {
            let mut entries: Vec<_> = entries
                .iter()
                .map(|(key, value)| (key.clone(), reference_canonical(value)))
                .collect();
            entries.sort_by_cached_key(|(key, _)| encode_cbor(key).unwrap());
            Value::Map(entries)
        }
        Value::Array(values) => Value::Array(values.iter().map(reference_canonical).collect()),
        Value::Tag(tag, value) => Value::Tag(*tag, Box::new(reference_canonical(value))),
        scalar => scalar.clone(),
    }
}

#[test]
fn canonical_keys_match_wire_order_at_every_header_width() {
    let mut keys = Vec::new();
    for argument in [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
        u64::MAX,
    ] {
        keys.push(Value::Integer(argument.into()));
        keys.push(Value::Integer(
            (-1 - i128::from(argument)).try_into().unwrap(),
        ));
    }
    for length in [0, 1, 23, 24, 255, 256, 65_535, 65_536] {
        keys.push(Value::Bytes(vec![b'a'; length]));
        keys.push(Value::Text("a".repeat(length)));
    }
    keys.extend([
        Value::Bytes(vec![0]),
        Value::Bytes(vec![255]),
        Value::Text("z".into()),
        Value::Text("é".into()),
        Value::Text("汉".into()),
    ]);
    keys.reverse();
    let input = Value::Map(
        keys.into_iter()
            .enumerate()
            .map(|(index, key)| (key, (index as u64).into()))
            .collect(),
    );
    let expected = encode_cbor(&reference_canonical(&input)).unwrap();
    assert_eq!(encode_cbor_canonical(&input).unwrap(), expected);
}

#[test]
fn canonical_encoding_rejects_duplicate_and_unsupported_keys() {
    for key in [
        Value::Integer((-1).into()),
        Value::Bytes(vec![1, 2]),
        Value::Text("x".into()),
    ] {
        let input = Value::Map(vec![(key.clone(), 1.into()), (key, 2.into())]);
        assert!(encode_cbor_canonical(&input).is_err());
    }
    for key in [
        Value::Array(vec![1.into()]),
        Value::Map(vec![]),
        Value::Tag(0, Box::new("2026-11-18T00:00:00Z".into())),
        Value::Float(1.0),
        Value::Bool(false),
        Value::Null,
    ] {
        assert!(encode_cbor_canonical(&Value::Map(vec![(key, 0.into())])).is_err());
    }
}

#[test]
fn projection_preserves_integer_limits_and_nested_tag_types() {
    let value = Value::Array(vec![
        Value::Integer(u64::MAX.into()),
        Value::Integer((-(1i128 << 64)).try_into().unwrap()),
        Value::Tag(2, Box::new(Value::Bytes(vec![1]))),
        Value::Tag(3, Box::new(Value::Bytes(vec![1]))),
        Value::Tag(
            60000,
            Box::new(Value::Map(vec![(
                "tagged".into(),
                Value::Tag(24, Box::new(Value::Bytes(vec![0xc2, 0x41, 1]))),
            )])),
        ),
    ]);
    let encoded = encode_cbor(&value).unwrap();
    assert_eq!(decode_cbor(&encoded).unwrap(), value);
    assert_eq!(
        encode_cbor(&decode_cbor(&encoded).unwrap()).unwrap(),
        encoded
    );
}

#[test]
fn projection_preserves_float_values_and_signed_zero() {
    for (wire, expected) in [
        ("f98000", -0.0),
        ("f90400", 2f64.powi(-14)),
        ("f90001", 2f64.powi(-24)),
        ("f97c00", f64::INFINITY),
        ("f9fc00", f64::NEG_INFINITY),
        ("fa80000000", -0.0),
        ("fa00000001", 2f64.powi(-149)),
        ("fb8000000000000000", -0.0),
        ("fb0000000000000001", f64::from_bits(1)),
    ] {
        let Value::Float(decoded) = decode_cbor(&hex::decode(wire).unwrap()).unwrap() else {
            panic!("expected floating-point value");
        };
        assert_eq!(decoded.to_bits(), expected.to_bits(), "{wire}");
    }
    for wire in ["f97e00", "fa7fc00001", "fb7ff8000000000001"] {
        assert!(matches!(
            decode_cbor(&hex::decode(wire).unwrap()).unwrap(),
            Value::Float(value) if value.is_nan()
        ));
    }
}

#[test]
fn canonical_output_preserves_opaque_tag24_bytes() {
    // The inner map has valid, unsorted keys. Tag 24 carries those bytes intact.
    let inner = vec![0xa2, 0x61, b'z', 1, 0x61, b'a', 2];
    let value = Value::Tag(24, Box::new(Value::Bytes(inner.clone())));
    let encoded = encode_cbor_canonical(&value).unwrap();
    assert_eq!(decode_cbor(&encoded).unwrap(), value);
    assert_eq!(nazo_mdoc::cbor::raw::tag24_inner(&encoded).unwrap(), inner);
}

fn key_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<u64>().prop_map(|value| Value::Integer(value.into())),
        any::<u64>().prop_map(|value| Value::Integer((-1 - i128::from(value)).try_into().unwrap())),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        prop::collection::vec(any::<char>(), 0..20)
            .prop_map(|chars| Value::Text(chars.into_iter().collect())),
    ]
}

fn value_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        key_strategy(),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
        any::<i32>().prop_map(|value| Value::Float(f64::from(value) / 8.0)),
    ]
    .prop_recursive(3, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            inner
                .clone()
                .prop_map(|value| Value::Tag(60000, Box::new(value))),
            prop::collection::vec((key_strategy(), inner), 0..8).prop_map(|entries| {
                let entries: BTreeMap<_, _> = entries
                    .into_iter()
                    .map(|(key, value)| (encode_cbor(&key).unwrap(), (key, value)))
                    .collect();
                Value::Map(entries.into_values().rev().collect())
            }),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn borrowed_canonical_writer_matches_encoded_key_reference(value in value_strategy()) {
        let expected = encode_cbor(&reference_canonical(&value)).unwrap();
        prop_assert_eq!(encode_cbor_canonical(&value).unwrap(), expected);
    }

    #[test]
    fn validated_projection_preserves_generated_values(value in value_strategy()) {
        let encoded = encode_cbor(&value).unwrap();
        prop_assert_eq!(decode_cbor(&encoded).unwrap(), value);
    }
}
