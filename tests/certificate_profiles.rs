#![cfg(feature = "certificate-profile")]

use nazo_mdoc::certificate::*;
use signature::Verifier;
use x509_parser::certificate::X509Certificate;

#[cfg(feature = "issue")]
mod common;

struct Vector {
    name: &'static str,
    kind: &'static str,
    accepted: bool,
    issuer: Vec<u8>,
    der: Vec<u8>,
}
fn vectors() -> Vec<Vector> {
    include_str!("vectors/certificates/profiles.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            Vector {
                name: fields[0],
                kind: fields[1],
                accepted: fields[2] == "true",
                issuer: hex::decode(fields[3]).unwrap(),
                der: hex::decode(fields[4]).unwrap(),
            }
        })
        .collect()
}
fn parse(der: &[u8]) -> X509Certificate<'_> {
    let (rest, certificate) = x509_parser::parse_x509_certificate(der).unwrap();
    assert!(rest.is_empty());
    certificate
}
fn verify_signature(certificate: &X509Certificate<'_>, issuer: &[u8]) {
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(issuer).unwrap();
    let signature =
        p256::ecdsa::Signature::from_der(certificate.signature_value.data.as_ref()).unwrap();
    key.verify(certificate.tbs_certificate.as_ref(), &signature)
        .unwrap();
}

#[test]
fn signed_annex_b_positive_and_negative_profiles() {
    let vectors = vectors();
    let find = |name| parse(&vectors.iter().find(|v| v.name == name).unwrap().der);
    let old = find("old");
    let new = find("new");
    let same = find("new_same");
    for vector in &vectors {
        let certificate = parse(&vector.der);
        verify_signature(&certificate, &vector.issuer);
        let result = match vector.kind {
            "root" => check_iaca_profile(&certificate),
            "ds" => check_document_signer_profile(&certificate),
            "link" => check_iaca_link_profile(&certificate, &old, &new),
            "link_same" => check_iaca_link_profile(&certificate, &old, &same),
            _ => unreachable!(),
        };
        assert_eq!(
            result.is_ok(),
            vector.accepted,
            "{}: {result:?}",
            vector.name
        );
    }
}

#[test]
fn rollover_requires_corresponding_new_root_not_only_a_valid_signature() {
    let vectors = vectors();
    let find = |name| parse(&vectors.iter().find(|v| v.name == name).unwrap().der);
    let old = find("old");
    let new = find("new");
    let link = find("link_renamed");
    check_iaca_link_profile(&link, &old, &new).unwrap();
    assert!(check_iaca_link_profile(&link, &old, &old).is_err());
    assert!(check_iaca_link_profile(&link, &new, &new).is_err());
    assert!(check_iaca_link_profile(&link, &old, &link).is_err());
}

#[test]
fn country_and_optional_jurisdiction_bind_to_the_actual_document_signer() {
    let vectors = vectors();
    let certificate = parse(
        &vectors
            .iter()
            .find(|v| v.name == "ds_national")
            .unwrap()
            .der,
    );
    check_mdl_issuer_attribute(&certificate, "issuing_country", "US").unwrap();
    check_mdl_issuer_attribute(&certificate, "issuing_jurisdiction", "US-CA").unwrap();
    assert!(check_mdl_issuer_attribute(&certificate, "issuing_country", "CA").is_err());
    assert!(check_mdl_issuer_attribute(&certificate, "issuing_jurisdiction", "CA-ON").is_err());
}

#[test]
fn root_exclusion_uses_the_authenticated_anchor_not_a_name_guess() {
    let vectors = vectors();
    let der = |name| {
        vectors
            .iter()
            .find(|v| v.name == name)
            .unwrap()
            .der
            .as_slice()
    };
    check_x5chain_root_exclusion(&[der("ds"), der("link_same_name")], der("old")).unwrap();
    assert!(check_x5chain_root_exclusion(&[der("ds"), der("old")], der("old")).is_err());
}

#[test]
#[cfg(feature = "issue")]
fn issuance_and_verification_enforce_profiles_without_an_application_check() {
    use nazo_mdoc::{builder::DocumentBuilder, model::CoseAlgorithm};
    use signature::Signer;

    let vectors = vectors();
    let vector = |name| vectors.iter().find(|vector| vector.name == name).unwrap();
    let good = vector("ds");
    let bad = vector("ds_wrong_ku");
    for vector in [good, bad] {
        verify_signature(&parse(&vector.der), &vector.issuer);
    }
    let builder = || {
        DocumentBuilder::new("example.profile")
            .add_namespace("example", vec![("claim", true.into())])
            .device_key(common::device_key())
            .validity(common::validity())
    };
    assert!(matches!(
        builder().prepare(CoseAlgorithm::ES256, vec![bad.der.clone()]),
        Err(nazo_mdoc::MdocError::CertificateProfile(_))
    ));
    let key = p256::ecdsa::SigningKey::from_slice(&{
        let mut bytes = [0; 32];
        bytes[31] = 29; // Public test-only DS scalar in generate.py.
        bytes
    })
    .unwrap();
    let prepared = builder()
        .prepare(CoseAlgorithm::ES256, vec![good.der.clone()])
        .unwrap();
    let signature: p256::ecdsa::Signature = key.sign(prepared.signing_input());
    let mut document = prepared.finish(signature.to_bytes().to_vec()).unwrap();
    let bytes = document.to_issuer_signed_cbor().unwrap();
    let _ = nazo_mdoc::verify_issued_borrowed(&bytes, "example.profile", common::now()).unwrap();
    let auth = &mut document.issuer_signed.issuer_auth.cose_sign1;
    key.verifying_key()
        .verify(&auth.tbs_data(&[]), &signature)
        .unwrap();
    // x5chain is unprotected. Substitute a certificate for the same public
    // key: the MSO and X.509 signatures both remain cryptographically valid.
    auth.unprotected
        .rest
        .iter_mut()
        .find(|(label, _)| *label == coset::Label::Int(33))
        .unwrap()
        .1 = ciborium::Value::Bytes(bad.der.clone());
    let bytes = document.to_issuer_signed_cbor().unwrap();
    assert!(matches!(
        nazo_mdoc::verify_issued_borrowed(&bytes, "example.profile", common::now()),
        Err(nazo_mdoc::MdocError::CertificateProfile(_))
    ));
}
