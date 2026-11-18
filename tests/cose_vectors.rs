//! Independent known-answer tests for the signature primitive selected by COSE.
//!
//! Public keys, messages and signatures are copied from the cited RFC vectors;
//! no signing operation or private key is used to derive an expected answer.
//! These test the algorithm/key dispatch and fixed-width signature primitive.
//!
//! Sources:
//! - RFC 6979 Appendix A.2.6, NIST P-384 with SHA-384 ("sample" and "test"):
//!   <https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.6>
//! - RFC 8032 Section 7.1, Ed25519 TEST 1 (empty message):
//!   <https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1>

use coset::{Algorithm, CoseKey, CoseKeyBuilder, KeyType, Label, iana};
use nazo_mdoc::cose::{key::algorithms, validate_verification_key, verify_cose_signature};

// RFC 6979 A.2.6 public point U = (Ux, Uy). Preserve the RFC's signature
// scalars exactly, including high-S values; do not normalize expected bytes.
const P384_X: &str = concat!(
    "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64",
    "DEF8F0EA9055866064A254515480BC13",
);
const P384_Y: &str = concat!(
    "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1",
    "288B231C3AE0D4FE7344FD2533264720",
);
const P384_SAMPLE_SIGNATURE: &str = concat!(
    "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C",
    "81A648152E44ACF96E36DD1E80FABE46",
    "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F",
    "A329C145786E679E7B82C71A38628AC8",
);
const P384_TEST_SIGNATURE: &str = concat!(
    "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB",
    "0542A7F0812998DA8F1DD3CA3CF023DB",
    "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E0",
    "6A739F040649A667BF3B828246BAA5A5",
);

// RFC 8032 7.1 TEST 1: the message has exactly zero bytes.
const ED25519_PUBLIC: &str = concat!(
    "d75a980182b10ab7d54bfed3c964073a",
    "0ee172f3daa62325af021a68f707511a",
);
const ED25519_EMPTY_SIGNATURE: &str = concat!(
    "e5564300c360ac729086e2cc806e828a",
    "84877f1eb8e5d974d873e06522490155",
    "5fb8821590a33bacc61e39701cf9b46b",
    "d25bf5f0595bbe24655141438e7a100b",
);

fn p384_key() -> CoseKey {
    let mut key = CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_384,
        hex::decode(P384_X).unwrap(),
        hex::decode(P384_Y).unwrap(),
    )
    .build();
    key.alg = Some(Algorithm::Assigned(iana::Algorithm::ES384));
    key
}

fn ed25519_key() -> CoseKey {
    CoseKey {
        kty: KeyType::Assigned(iana::KeyType::OKP),
        alg: Some(Algorithm::Assigned(iana::Algorithm::EdDSA)),
        params: vec![
            (Label::Int(-1), 6.into()),
            (
                Label::Int(-2),
                ciborium::Value::Bytes(hex::decode(ED25519_PUBLIC).unwrap()),
            ),
        ],
        ..Default::default()
    }
}

fn replace_curve(key: &mut CoseKey, curve: i64) {
    key.params
        .iter_mut()
        .find(|(label, _)| *label == Label::Int(-1))
        .unwrap()
        .1 = curve.into();
}

#[test]
fn rfc6979_p384_sha384_sample_and_test_verify() {
    let key = p384_key();
    validate_verification_key(&key, algorithms::ES384).unwrap();
    for (message, signature) in [
        (b"sample".as_slice(), P384_SAMPLE_SIGNATURE),
        (b"test".as_slice(), P384_TEST_SIGNATURE),
    ] {
        let signature = hex::decode(signature).unwrap();
        assert_eq!(signature.len(), 96);
        assert!(verify_cose_signature(message, &signature, &key, algorithms::ES384).unwrap());
    }
}

#[test]
fn rfc6979_p384_rejects_modified_signature_and_message() {
    let key = p384_key();
    let signature = hex::decode(P384_SAMPLE_SIGNATURE).unwrap();
    assert!(!verify_cose_signature(b"samplf", &signature, &key, algorithms::ES384).unwrap());
    let mut altered = signature;
    // Change a low scalar bit, retaining the RFC vector's valid scalar range.
    altered[95] ^= 1;
    assert!(!verify_cose_signature(b"sample", &altered, &key, algorithms::ES384).unwrap());
}

#[test]
fn rfc6979_p384_rejects_algorithm_substitution() {
    let key = p384_key();
    let signature = hex::decode(P384_SAMPLE_SIGNATURE).unwrap();
    for algorithm in [algorithms::ES256, algorithms::ES512, algorithms::EDDSA, -37] {
        assert!(verify_cose_signature(b"sample", &signature, &key, algorithm).is_err());
    }
    let mut mismatched_declaration = key;
    mismatched_declaration.alg = Some(Algorithm::Assigned(iana::Algorithm::ES256));
    assert!(
        verify_cose_signature(
            b"sample",
            &signature,
            &mismatched_declaration,
            algorithms::ES384,
        )
        .is_err()
    );
}

#[test]
fn rfc6979_p384_rejects_curve_and_key_type_substitution() {
    let signature = hex::decode(P384_SAMPLE_SIGNATURE).unwrap();
    let mut wrong_curve = p384_key();
    replace_curve(&mut wrong_curve, 1); // P-256 instead of P-384.
    assert!(verify_cose_signature(b"sample", &signature, &wrong_curve, algorithms::ES384).is_err());
    let mut wrong_type = p384_key();
    wrong_type.kty = KeyType::Assigned(iana::KeyType::OKP);
    assert!(verify_cose_signature(b"sample", &signature, &wrong_type, algorithms::ES384).is_err());
}

#[test]
fn rfc8032_ed25519_empty_message_verifies() {
    let key = ed25519_key();
    validate_verification_key(&key, algorithms::EDDSA).unwrap();
    let signature = hex::decode(ED25519_EMPTY_SIGNATURE).unwrap();
    assert_eq!(signature.len(), 64);
    assert!(verify_cose_signature(b"", &signature, &key, algorithms::EDDSA).unwrap());
}

#[test]
fn rfc8032_ed25519_rejects_modified_signature_and_message() {
    let key = ed25519_key();
    let signature = hex::decode(ED25519_EMPTY_SIGNATURE).unwrap();
    assert!(!verify_cose_signature(b"\0", &signature, &key, algorithms::EDDSA).unwrap());
    let mut altered = signature;
    // 0x0b -> 0x0a leaves S canonical; strict verification must still fail.
    altered[63] ^= 1;
    assert!(!verify_cose_signature(b"", &altered, &key, algorithms::EDDSA).unwrap());
}

#[test]
fn rfc8032_ed25519_rejects_algorithm_substitution() {
    let key = ed25519_key();
    let signature = hex::decode(ED25519_EMPTY_SIGNATURE).unwrap();
    for algorithm in [algorithms::ES256, algorithms::ES384, algorithms::ES512, -37] {
        assert!(verify_cose_signature(b"", &signature, &key, algorithm).is_err());
    }
    let mut mismatched_declaration = key;
    mismatched_declaration.alg = Some(Algorithm::Assigned(iana::Algorithm::ES256));
    assert!(
        verify_cose_signature(b"", &signature, &mismatched_declaration, algorithms::EDDSA,)
            .is_err()
    );
}

#[test]
fn rfc8032_ed25519_rejects_curve_and_key_type_substitution() {
    let signature = hex::decode(ED25519_EMPTY_SIGNATURE).unwrap();
    let mut wrong_curve = ed25519_key();
    // X25519 has the same COSE OKP key type and 32-byte public-key width, but
    // is not an Ed25519 signing curve. Checking only byte width would be wrong.
    replace_curve(&mut wrong_curve, 4);
    assert!(verify_cose_signature(b"", &signature, &wrong_curve, algorithms::EDDSA).is_err());
    let mut wrong_type = ed25519_key();
    wrong_type.kty = KeyType::Assigned(iana::KeyType::EC2);
    assert!(verify_cose_signature(b"", &signature, &wrong_type, algorithms::EDDSA).is_err());
}

#[test]
fn official_vectors_require_exact_cose_signature_lengths() {
    for (message, signature, key, algorithm) in [
        (
            b"sample".as_slice(),
            hex::decode(P384_SAMPLE_SIGNATURE).unwrap(),
            p384_key(),
            algorithms::ES384,
        ),
        (
            b"".as_slice(),
            hex::decode(ED25519_EMPTY_SIGNATURE).unwrap(),
            ed25519_key(),
            algorithms::EDDSA,
        ),
    ] {
        assert!(
            verify_cose_signature(message, &signature[..signature.len() - 1], &key, algorithm)
                .is_err()
        );
        let mut extended = signature;
        extended.push(0);
        assert!(verify_cose_signature(message, &extended, &key, algorithm).is_err());
    }
}
