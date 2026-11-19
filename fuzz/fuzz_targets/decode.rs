#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(text) = std::str::from_utf8(input) {
        let _ = nazo_mdoc::Timestamp::parse_rfc3339(text);
        let _ = nazo_mdoc::cbor::date::FullDate::new(text);
    }
    let _ = nazo_mdoc::cbor::raw::validate(input);
    if let Ok(value) = nazo_mdoc::CborValueRef::parse(input) {
        let valid_from = "2026-11-17T12:00:00Z".parse().unwrap();
        for name in [
            "birth_date",
            "issue_date",
            "driving_privileges",
            "biometric_template_face",
        ] {
            let _ = nazo_mdoc::mdl::validate_element(name, value, valid_from);
        }
    }
    if let Ok(value) = nazo_mdoc::cbor::decode_cbor(input) {
        let _ = nazo_mdoc::cbor::data_item::encode_cbor_canonical(&value);
    }
    let _ = nazo_mdoc::session::SessionTranscript::from_cbor(input);
    if let Ok(response) = nazo_mdoc::parse_borrowed(input) {
        for document in &response.documents {
            let auth = &document.issuer_signed.issuer_auth;
            let _ = auth.certificate_chain_der();
            let _ = auth.mso();
            if let Some(device) = &document.device_signed {
                let _ = nazo_mdoc::session::build_device_authentication_bytes(
                    &[0x83, 0xf6, 0xf6, 0xf6],
                    document.doc_type,
                    device.name_spaces_bytes,
                );
            }
        }
        let _ = response.into_owned();
    }
    // Exercise COSE and certificate parsing through bounded verification APIs
    // using a fixed transcript context.
    let transcript =
        nazo_mdoc::session::SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    let options = nazo_mdoc::VerificationOptions {
        now: "2026-11-17T12:00:00Z".parse().unwrap(),
        max_documents: 1,
    };
    if let Ok(documents) = nazo_mdoc::verify_presentation_borrowed(input, &transcript, &options) {
        for document in documents {
            let _ = document.into_owned();
        }
    }
    if let Ok(document) =
        nazo_mdoc::verify_issued_borrowed(input, "org.iso.18013.5.1.mDL", options.now)
    {
        let _ = document.into_owned();
    }
    if let Ok(issued) = nazo_mdoc::parser::parse_issued_borrowed(input) {
        let _ = issued.issuer_auth.mso();
        let _ = issued.issuer_auth.certificate_chain_der();
    }
});
