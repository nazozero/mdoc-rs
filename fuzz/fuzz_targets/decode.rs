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
                    &[0x83,0xf6,0xf6,0xf6], &document.doc_type, &device.name_spaces_bytes,
                );
            }
        }
    }
    if let Ok(issued) = nazo_mdoc::parser::parse_issued(input) {
        let _ = issued.issuer_auth.mso();
        let _ = issued.issuer_auth.certificate_der();
    }
});
