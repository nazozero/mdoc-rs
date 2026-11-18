//! ISO 18013-5 §8.3.2.1.2.2 permits an empty DeviceNameSpaces map, but every
//! namespace that occurs must contain at least one DeviceSignedItems entry.

use ciborium::Value;
use nazo_mdoc::{MdocError, parser};

fn field_mut<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    &mut value
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap()
        .1
}

#[test]
fn device_namespace_cardinality_is_checked_before_authentication() {
    let original = hex::decode(
        include_str!("vectors/iso_18013_5_annex_d_mdl.hex")
            .split_whitespace()
            .collect::<String>(),
    )
    .unwrap();
    // Fixed wire values distinguish the outer map from its per-namespace maps.
    // Each mutation retains the original issuer's opaque signature and MSO;
    // this test deliberately exercises decoding, not cryptographic validity.
    for (inner, permitted) in [
        ("a0", true),                        // {}
        ("a1626e73a16161f6", true),          // {"ns": {"a": null}}
        ("a1626e73a0", false),               // {"ns": {}}
        ("a2626f6ba16161f6626e73a0", false), // {"ok": {"a": null}, "ns": {}}
    ] {
        let mut response: Value = ciborium::from_reader(original.as_slice()).unwrap();
        let document = &mut field_mut(&mut response, "documents")
            .as_array_mut()
            .unwrap()[0];
        let device = field_mut(document, "deviceSigned");
        let namespaces = Value::Tag(24, Box::new(Value::Bytes(hex::decode(inner).unwrap())));
        *field_mut(device, "nameSpaces") = namespaces.clone();
        let mut encoded = Vec::new();
        ciborium::into_writer(&response, &mut encoded).unwrap();
        let result = parser::parse(&encoded);
        if permitted {
            let parsed = result.expect("outer map may be empty; an inner map may not");
            let mut expected = Vec::new();
            ciborium::into_writer(&namespaces, &mut expected).unwrap();
            assert_eq!(
                parsed.documents[0]
                    .device_signed
                    .as_ref()
                    .unwrap()
                    .name_spaces_bytes,
                expected,
            );
        } else {
            assert!(
                matches!(result, Err(MdocError::Parse(ref reason)) if reason == "empty DeviceSignedItems map"),
                "{inner}: {result:?}"
            );
        }
    }
}
