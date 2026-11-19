use super::*;
use crate::cose::key::{CoseKeyExt, cose_key_from_spki};
use coset::CborSerializable;
use der::Decode;

struct Vector {
    curve: i64,
    alg: i64,
    case: String,
    valid: bool,
    spki: x509_cert::spki::SubjectPublicKeyInfoOwned,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fn vectors() -> Vec<Vector> {
    include_str!("../../tests/vectors/reader_crypto/wycheproof.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter(|line| !matches!(line.split('\t').next(), Some("257" | "259")))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            Vector {
                curve: fields[0].parse().unwrap(),
                alg: fields[1].parse().unwrap(),
                case: format!("curve {} tcId {} {}", fields[0], fields[2], fields[7]),
                valid: fields[3] == "valid",
                spki: x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(
                    &hex::decode(fields[4]).unwrap(),
                )
                .unwrap(),
                message: hex::decode(fields[5]).unwrap(),
                signature: hex::decode(fields[6]).unwrap(),
            }
        })
        .collect()
}

#[test]
fn independent_wycheproof_cases_cover_owned_borrowed_and_spki_paths() {
    for v in vectors() {
        let key = cose_key_from_spki(&v.spki).unwrap();
        assert_eq!(key.curve().unwrap(), v.curve);
        let result = verify_cose_signature(&v.message, &v.signature, &key, v.alg);
        assert_eq!(result.unwrap_or(false), v.valid, "{} owned", v.case);
        let encoded = key.to_vec().unwrap();
        let borrowed = CoseKeyRef::parse(crate::cbor::raw::Item::parse(&encoded).unwrap()).unwrap();
        let split = v.message.len() / 2;
        let parts = [&v.message[..split], &v.message[split..]];
        let result = verify_cose_signature_borrowed(&parts, &v.signature, &borrowed, v.alg);
        assert_eq!(result.unwrap_or(false), v.valid, "{} borrowed", v.case);
        let result = VerificationKey::from_spki(&v.spki, v.alg)
            .and_then(|key| key.verify(&parts, &v.signature));
        assert_eq!(result.unwrap_or(false), v.valid, "{} spki", v.case);
    }
}

fn one_per_curve() -> Vec<Vector> {
    let mut seen = std::collections::BTreeSet::new();
    vectors()
        .into_iter()
        .filter(|v| v.valid && seen.insert(v.curve))
        .collect()
}

#[test]
fn rfc8032_ed448_blank_and_one_octet_verify_without_prehashing() {
    for row in include_str!("../../tests/vectors/reader_crypto/rfc8032.tsv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = row.split('\t').collect();
        let key = coset::CoseKeyBuilder::new_okp_key()
            .param(-1, 7.into())
            .param(-2, ciborium::Value::Bytes(hex::decode(fields[1]).unwrap()))
            .build();
        let message = hex::decode(fields[2]).unwrap();
        let signature = hex::decode(fields[3]).unwrap();
        assert!(verify_cose_signature(&message, &signature, &key, algorithms::EDDSA).unwrap());
        let parts = [&message[..0], message.as_slice()];
        assert!(verify_cose_signature_parts(&parts, &signature, &key, algorithms::EDDSA).unwrap());
    }
}

#[test]
fn curve_algorithm_usage_encoding_and_point_substitutions_fail() {
    for v in one_per_curve() {
        let key = cose_key_from_spki(&v.spki).unwrap();
        let wrong_alg = if v.alg == algorithms::ES256 {
            algorithms::ES384
        } else {
            algorithms::ES256
        };
        assert!(VerificationKey::from_spki(&v.spki, wrong_alg).is_err());
        assert!(verify_cose_signature(&v.message, &v.signature, &key, wrong_alg).is_err());
        let mut wrong_curve = key.clone();
        wrong_curve
            .params
            .iter_mut()
            .find(|(label, _)| *label == coset::Label::Int(-1))
            .unwrap()
            .1 = 1.into();
        assert!(
            !verify_cose_signature(&v.message, &v.signature, &wrong_curve, v.alg).unwrap_or(false)
        );
        let mut usage = key.clone();
        usage.key_ops.insert(coset::KeyOperation::Assigned(
            coset::iana::KeyOperation::Sign,
        ));
        assert!(verify_cose_signature(&v.message, &v.signature, &usage, v.alg).is_err());
        let mut private = key.clone();
        private
            .params
            .push((coset::Label::Int(-4), ciborium::Value::Bytes(vec![1; 32])));
        assert!(verify_cose_signature(&v.message, &v.signature, &private, v.alg).is_err());
        let mut invalid_point = key.clone();
        for (label, value) in &mut invalid_point.params {
            if matches!(label, coset::Label::Int(-2 | -3)) {
                value.as_bytes_mut().unwrap().fill(0);
            }
        }
        assert!(
            !verify_cose_signature(&v.message, &v.signature, &invalid_point, v.alg)
                .unwrap_or(false)
        );
        for len in [v.signature.len() - 1, v.signature.len() + 1] {
            assert!(verify_cose_signature(&v.message, &vec![0; len], &key, v.alg).is_err());
        }
        let mut changed = v.message.clone();
        changed.push(0);
        assert!(!verify_cose_signature(&changed, &v.signature, &key, v.alg).unwrap_or(false));
    }
}

#[test]
fn ed448_rejects_identity_forgery_and_noncanonical_points() {
    let mut identity = vec![0; 57];
    identity[0] = 1;
    let mut forged = vec![0; 114];
    forged[..57].copy_from_slice(&identity);
    let mut noncanonical = vec![0xff; 57];
    noncanonical[56] = 0x7f;
    for public in [identity, vec![0; 57], noncanonical] {
        let key = coset::CoseKeyBuilder::new_okp_key()
            .param(-1, 7.into())
            .param(-2, ciborium::Value::Bytes(public))
            .build();
        assert!(
            !verify_cose_signature(b"forged", &forged, &key, algorithms::EDDSA).unwrap_or(false)
        );
    }
}

#[test]
fn standalone_key_validation_accepts_strict_ed448_points() {
    for v in one_per_curve() {
        let key = cose_key_from_spki(&v.spki).unwrap();
        let encoded = key.to_vec().unwrap();
        let borrowed = CoseKeyRef::parse(crate::cbor::raw::Item::parse(&encoded).unwrap()).unwrap();
        let checked = crate::cose::validate_borrowed_device_public_key(&borrowed);
        assert!(checked.is_ok(), "curve {} standalone point validation", v.curve);
    }
}

#[test]
fn compressed_brainpool_keys_verify_and_reject_changed_parity_and_invalid_x() {
    for v in one_per_curve().into_iter().filter(|v| v.curve != 7) {
        let mut key = cose_key_from_spki(&v.spki).unwrap();
        let y = &mut key
            .params
            .iter_mut()
            .find(|(label, _)| *label == coset::Label::Int(-3))
            .unwrap()
            .1;
        let odd = y.as_bytes().unwrap().last().unwrap() & 1 == 1;
        *y = ciborium::Value::Bool(odd);
        assert!(verify_cose_signature(&v.message, &v.signature, &key, v.alg).unwrap());
        assert!(matches!(key.public_key_bytes().unwrap()[0], 2 | 3));
        let encoded = key.clone().to_vec().unwrap();
        let borrowed = CoseKeyRef::parse(crate::cbor::raw::Item::parse(&encoded).unwrap()).unwrap();
        assert!(
            verify_cose_signature_borrowed(&[&v.message], &v.signature, &borrowed, v.alg).unwrap()
        );
        assert!(crate::cose::validate_borrowed_device_public_key(&borrowed).is_ok());
        key.params
            .iter_mut()
            .find(|(label, _)| *label == coset::Label::Int(-3))
            .unwrap()
            .1 = ciborium::Value::Bool(!odd);
        assert!(!verify_cose_signature(&v.message, &v.signature, &key, v.alg).unwrap_or(false));
        key.params
            .iter_mut()
            .find(|(label, _)| *label == coset::Label::Int(-2))
            .unwrap()
            .1
            .as_bytes_mut()
            .unwrap()
            .fill(0xff);
        assert!(verify_cose_signature(&v.message, &v.signature, &key, v.alg).is_err());

    }
}

#[test]
fn prepared_portable_verification_is_shareable_without_mutable_session_state() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<VerificationKey>();
    for v in one_per_curve() {
        let key = VerificationKey::from_spki(&v.spki, v.alg).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let v = &v;
                let key = &key;
                scope.spawn(move || {
                    for _ in 0..16 {
                        assert!(key.verify(&[&v.message], &v.signature).unwrap());
                    }
                });
            }
        });
    }
}

#[test]
fn unreviewed_brainpool_curves_are_explicitly_unsupported() {
    for curve in [257i128, 259] {
        assert!(matches!(
            crate::cose::key::SignatureCurve::from_id(curve),
            Err(MdocError::UnsupportedAlgorithm(_))
        ));
    }
}
