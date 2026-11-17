//! Input-boundary checks independent of cryptographic fixtures.
use nazo_mdoc::cbor::raw::{Limits, validate, validate_with_limits};
use proptest::prelude::*;

#[test]
fn malformed_encodings_fail_closed() {
    for bytes in [
        &[][..],
        &[0x00, 0x00],
        &[0x18, 0x00],
        &[0x19, 0, 24],
        &[0x9f, 0xff],
        &[0xa2, 0x61, b'a', 1, 0x61, b'a', 2],
        &[0xa1, 0x81, 0, 0],
        &[0x61, 0xff],
        &[0xd8, 24, 0x42, 0, 0],
        &[0xd8, 24, 0x00],
        &[0x5b, 255, 255, 255, 255, 255, 255, 255, 255],
        &[0xa1, 0x62, b'a'],
        &[0xf8, 0],
    ] {
        assert!(validate(bytes).is_err(), "accepted {bytes:x?}");
    }
}

#[test]
fn limits_apply_inside_tag24_and_before_allocating_collections() {
    assert!(
        validate_with_limits(
            &[0x82, 0, 0],
            Limits {
                max_collection_items: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        validate_with_limits(
            &[0xd8, 24, 0x43, 0x81, 0x81, 0],
            Limits {
                max_depth: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        validate_with_limits(
            &[0x82, 0, 0],
            Limits {
                max_items: 2,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        validate_with_limits(
            &[0x43, 1, 2, 3],
            Limits {
                max_bytes: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn valid_map_order_is_not_rewritten() {
    let a = [0xa2, 0x61, b'b', 1, 0x61, b'a', 2];
    let b = [0xa2, 0x61, b'a', 2, 0x61, b'b', 1];
    validate(&a).unwrap();
    validate(&b).unwrap();
    assert_ne!(a, b);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn arbitrary_input_never_panics(bytes in prop::collection::vec(any::<u8>(),0..4096)) {
        let _=validate(&bytes);
        let _=nazo_mdoc::parse(&bytes);
        let _=nazo_mdoc::parser::parse_issued(&bytes);
        let _=nazo_mdoc::session::SessionTranscript::from_cbor(&bytes);
    }
    #[test]
    fn duplicate_text_keys_always_rejected(key in "[a-z]{1,32}", first in any::<u64>(), second in any::<u64>()) {
        let value=ciborium::Value::Map(vec![(key.clone().into(),first.into()),(key.into(),second.into())]);
        let mut bytes=Vec::new(); ciborium::into_writer(&value,&mut bytes).unwrap();
        prop_assert!(validate(&bytes).is_err());
    }
}
