#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = nazo_mdoc::cbor::raw::validate(input);
    let _ = nazo_mdoc::session::SessionTranscript::from_cbor(input);
    if let Ok(response) = nazo_mdoc::parse(input) {
        for document in response.documents {
            let auth = &document.issuer_signed.issuer_auth;
            let _ = auth.certificate_chain_der();
            let _ = auth.mso();
            if let Some(device) = document.device_signed {
                let _ = nazo_mdoc::session::build_device_authentication_bytes(
                    &[0x83, 0xf6, 0xf6, 0xf6],
                    &document.doc_type,
                    &device.name_spaces_bytes,
                );
            }
        }
    }
    // Exercise COSE header/key/signature and certificate parsing behind the same
    // bounded, byte-oriented admission APIs. The fixed context is a fuzz input
    // parameter, not a claim that arbitrary presentations are trustworthy.
    let transcript =
        nazo_mdoc::session::SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    let options = nazo_mdoc::VerificationOptions {
        now: "2026-11-17T12:00:00Z".parse().unwrap(),
        max_documents: 1,
    };
    let _ = nazo_mdoc::verify_presentation(input, &transcript, &options);
    let _ = nazo_mdoc::verifier::verify_issued(input, "org.iso.18013.5.1.mDL", options.now);
    if let Ok(issued) = nazo_mdoc::parser::parse_issued(input) {
        let _ = issued.issuer_auth.mso();
        let _ = issued.issuer_auth.certificate_der();
    }
});
