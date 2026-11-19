#![no_main]
use libfuzzer_sys::fuzz_target;
use nazo_mdoc::certificate::{
    check_document_signer_profile, check_iaca_link_profile, check_iaca_profile,
    check_issuer_binding, check_mdl_issuer_attribute,
};

fuzz_target!(|input: &[u8]| {
    if let Ok((_, certificate)) = x509_parser::parse_x509_certificate(input) {
        let _ = check_document_signer_profile(&certificate);
        let _ = check_iaca_profile(&certificate);
        let _ = check_iaca_link_profile(&certificate, &certificate, &certificate);
        let _ = check_issuer_binding(&certificate, &certificate);
        let _ = check_mdl_issuer_attribute(&certificate, "issuing_country", "US");
        let _ = check_mdl_issuer_attribute(&certificate, "issuing_jurisdiction", "US-CA");
    }
});
