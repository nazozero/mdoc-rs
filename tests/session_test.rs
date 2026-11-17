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
