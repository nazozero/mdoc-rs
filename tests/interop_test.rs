//! The inherited ISO Annex D fixture is exercised without the removed tsp feature.
use der::Decode;
use nazo_mdoc::{cose, disclosure, parse_hex};
const ANNEX_D: &str = include_str!("vectors/iso_18013_5_annex_d_mdl.hex");

#[test]
fn annex_d_original_bytes_digests_and_issuer_signature() {
    let document = parse_hex(ANNEX_D).unwrap().documents.remove(0);
    let auth = &document.issuer_signed.issuer_auth;
    let mso = auth.mso().unwrap();
    assert_eq!(mso.doc_type, "org.iso.18013.5.1.mDL");
    assert_eq!(
        mso.validity_info.valid_until.to_rfc3339(),
        "2021-10-01T13:30:02+00:00"
    );
    assert!(
        document.issuer_signed.name_spaces["org.iso.18013.5.1"]
            .iter()
            .any(|item| item.element_identifier == "family_name"
                && item.element_value.as_text() == Some("Doe"))
    );
    disclosure::verify_disclosure(&document.issuer_signed.name_spaces, &mso).unwrap();
    let certificate = x509_cert::Certificate::from_der(auth.certificate_der().unwrap()).unwrap();
    let key = cose::key::cose_key_from_spki(&certificate.tbs_certificate.subject_public_key_info)
        .unwrap();
    assert!(
        cose::verify_cose_signature(
            &auth.cose_sign1.tbs_data(&[]),
            &auth.cose_sign1.signature,
            &key,
            -7
        )
        .unwrap()
    );
}
