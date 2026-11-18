use nazo_mdoc::session::{SessionBinding, SessionTranscript};

#[test]
fn raw_transcript_encoding_borrows_both_owned_and_borrowed_storage() {
    use std::borrow::Cow;
    let bytes = vec![0x83, 0xf6, 0xf6, 0xf6];
    let pointer = bytes.as_ptr();
    let transcript = SessionTranscript::from_cbor(&bytes).unwrap();
    assert_eq!(transcript.binding(), SessionBinding::StructureOnly);
    let encoded = transcript.to_cbor_bytes().unwrap();
    assert!(matches!(encoded, Cow::Borrowed(_)));
    assert_eq!(encoded.as_ptr(), pointer);
    assert_eq!(encoded.as_ref(), bytes);
    let transcript = SessionTranscript::from_owned_cbor(bytes).unwrap();
    let encoded = transcript.to_cbor_bytes().unwrap();
    assert!(matches!(encoded, Cow::Borrowed(_)));
    assert_eq!(encoded.as_ptr(), pointer);
}

#[test]
fn public_authentication_payload_checks_device_namespace_cardinality() {
    let transcript = SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    for (inner, permitted) in [
        ("a0", true),
        ("a1626e73a16161f6", true), // {"ns": {"a": null}}
        ("a1626e73a0", false),      // {"ns": {}}
        ("a160a16161f6", false),    // {"": {"a": null}}
        ("a1626e73a160f6", false),  // {"ns": {"": null}}
    ] {
        let inner = hex::decode(inner).unwrap();
        let encoded = nazo_mdoc::cbor::data_item::encode_cbor(
            &nazo_mdoc::cbor::data_item::wrap_tag24(&inner),
        )
        .unwrap();
        assert_eq!(
            nazo_mdoc::session::build_device_authentication(&transcript, "test", &encoded).is_ok(),
            permitted,
            "DeviceNameSpaces {inner:?}"
        );
    }
}
