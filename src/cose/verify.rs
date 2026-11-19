//! COSE signature verification using RustCrypto.

use crate::cose::key::algorithms;
use crate::error::MdocError;
use crate::model::{CoseKeyRef, CoseLabelRef};
#[cfg(any(not(feature = "certificate-profile"), test))]
use der::referenced::OwnedToRef;
use signature::MultipartVerifier;

/// Verify a COSE signature given the to-be-signed data, signature bytes, and a COSE_Key.
///
/// Supports ES256 (P-256), ES384 (P-384), ES512 (P-521), and EdDSA (Ed25519).
pub fn verify_cose_signature(
    tbs_data: &[u8],
    signature: &[u8],
    cose_key: &coset::CoseKey,
    alg_id: i64,
) -> Result<bool, MdocError> {
    verify_cose_signature_parts(&[tbs_data], signature, cose_key, alg_id)
}

pub(crate) fn verify_cose_signature_parts(
    parts: &[&[u8]],
    signature: &[u8],
    key: &coset::CoseKey,
    alg: i64,
) -> Result<bool, MdocError> {
    VerificationKey::from_cose(key, alg)?.verify(parts, signature)
}

pub(crate) fn verify_cose_signature_borrowed(
    parts: &[&[u8]],
    signature: &[u8],
    key: &CoseKeyRef<'_>,
    alg: i64,
) -> Result<bool, MdocError> {
    VerificationKey::from_borrowed(key, alg)?.verify(parts, signature)
}

/// A parsed public key retained by a prepared operation. All constructors check
/// the algorithm binding before passing key material to the official verifier.
#[derive(Debug)]
pub(crate) enum VerificationKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl VerificationKey {
    pub(crate) fn from_cose(key: &coset::CoseKey, alg: i64) -> Result<Self, MdocError> {
        Self::from_parts(owned_key_parts(key, alg)?, alg)
    }

    pub(crate) fn from_borrowed(key: &CoseKeyRef<'_>, alg: i64) -> Result<Self, MdocError> {
        Self::from_parts(borrowed_key_parts(key, alg)?, alg)
    }

    #[cfg(any(not(feature = "certificate-profile"), test))]
    pub(crate) fn from_spki(
        spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
        alg: i64,
    ) -> Result<Self, MdocError> {
        Self::from_spki_ref(spki.owned_to_ref(), alg)
    }

    pub(crate) fn from_spki_ref(
        spki: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        alg: i64,
    ) -> Result<Self, MdocError> {
        let (key_alg, bytes) = super::key::spki_key_bytes(spki)?;
        if key_alg != alg {
            return Err(MdocError::Cose("algorithm/key type/curve mismatch".into()));
        }
        Self::from_bytes(bytes, alg)
    }

    fn from_parts(parts: PublicKeyParts<'_>, alg: i64) -> Result<Self, MdocError> {
        match parts.y {
            Some(y) => {
                // Coordinate widths were checked by the metadata parser.
                let mut point = [0; 133];
                let width = parts.x.len();
                point[0] = 4;
                point[1..1 + width].copy_from_slice(parts.x);
                point[1 + width..1 + 2 * width].copy_from_slice(y);
                Self::from_bytes(&point[..1 + 2 * width], alg)
            }
            None => Self::from_bytes(parts.x, alg),
        }
    }

    fn from_bytes(bytes: &[u8], alg: i64) -> Result<Self, MdocError> {
        match alg {
            algorithms::ES256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self::P256)
                .map_err(|e| MdocError::Signature(format!("P-256 key: {e}"))),
            algorithms::ES384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self::P384)
                .map_err(|e| MdocError::Signature(format!("P-384 key: {e}"))),
            algorithms::ES512 => p521::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self::P521)
                .map_err(|e| MdocError::Signature(format!("P-521 key: {e}"))),
            algorithms::EDDSA => ed25519_dalek::VerifyingKey::from_bytes(
                bytes
                    .try_into()
                    .map_err(|_| MdocError::Signature("Ed25519 key length".into()))?,
            )
            .map(Self::Ed25519)
            .map_err(|e| MdocError::Signature(format!("Ed25519 key: {e}"))),
            _ => Err(MdocError::UnsupportedAlgorithm(format!(
                "COSE algorithm {alg}"
            ))),
        }
    }

    pub(super) fn validate_device_point(&self) -> Result<(), MdocError> {
        if matches!(self, Self::Ed25519(key) if key.is_weak()) {
            return Err(MdocError::Cose("invalid device public point".into()));
        }
        Ok(())
    }

    pub(crate) fn verify(&self, parts: &[&[u8]], signature: &[u8]) -> Result<bool, MdocError> {
        let (algorithm, signature_len) = match self {
            Self::P256(_) => ("ES256", 64),
            Self::P384(_) => ("ES384", 96),
            Self::P521(_) => ("ES512", 132),
            Self::Ed25519(_) => ("Ed25519", 64),
        };
        if signature.len() != signature_len {
            if matches!(self, Self::Ed25519(_)) {
                return Err(MdocError::Signature(
                    "Ed25519 signature must be 64 bytes".into(),
                ));
            }
            return Err(MdocError::Signature(format!(
                "{algorithm} signature must be {signature_len}-byte raw r||s, got {} bytes",
                signature.len()
            )));
        }
        match self {
            Self::P256(key) => {
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| MdocError::Signature(format!("P-256 sig: {e}")))?;
                Ok(key.multipart_verify(parts, &signature).is_ok())
            }
            Self::P384(key) => {
                let signature = p384::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| MdocError::Signature(format!("P-384 sig: {e}")))?;
                Ok(key.multipart_verify(parts, &signature).is_ok())
            }
            Self::P521(key) => {
                let signature = p521::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| MdocError::Signature(format!("P-521 sig: {e}")))?;
                Ok(key.multipart_verify(parts, &signature).is_ok())
            }
            Self::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|e| MdocError::Signature(format!("Ed25519 sig: {e}")))?;
                // Dalek's multipart and streaming APIs omit strict R-point
                // checks. Keep verify_strict; only multipart Ed25519 needs a copy.
                let message;
                let bytes = if let [part] = parts {
                    *part
                } else {
                    message = parts.concat();
                    &message
                };
                Ok(key.verify_strict(bytes, &signature).is_ok())
            }
        }
    }
}

struct PublicKeyParts<'a> {
    x: &'a [u8],
    y: Option<&'a [u8]>,
}

fn algorithm_parameters(alg: i64) -> Result<(coset::iana::KeyType, i128, usize), MdocError> {
    use coset::iana::KeyType;
    match alg {
        algorithms::ES256 => Ok((KeyType::EC2, 1, 32)),
        algorithms::ES384 => Ok((KeyType::EC2, 2, 48)),
        algorithms::ES512 => Ok((KeyType::EC2, 3, 66)),
        algorithms::EDDSA => Ok((KeyType::OKP, 6, 32)),
        _ => Err(MdocError::UnsupportedAlgorithm(format!(
            "COSE algorithm {alg}"
        ))),
    }
}

/// Enforce the COSE algorithm, key type, curve and declared key usage together.
pub fn validate_verification_key(key: &coset::CoseKey, alg: i64) -> Result<(), MdocError> {
    owned_key_parts(key, alg).map(|_| ())
}

fn owned_key_parts(key: &coset::CoseKey, alg: i64) -> Result<PublicKeyParts<'_>, MdocError> {
    use coset::{Algorithm, KeyOperation, KeyType, Label, iana};
    let (key_type, curve, coordinate_len) = algorithm_parameters(alg)?;
    if key.kty != KeyType::Assigned(key_type) {
        return Err(MdocError::Cose("algorithm/key type/curve mismatch".into()));
    }
    if let Some(declared) = &key.alg
        && !matches!(declared, Algorithm::Assigned(value) if *value as i64 == alg)
    {
        return Err(MdocError::Cose(
            "COSE_Key algorithm does not match signature".into(),
        ));
    }
    if !key.base_iv.is_empty()
        || (!key.key_ops.is_empty()
            && !key
                .key_ops
                .contains(&KeyOperation::Assigned(iana::KeyOperation::Verify)))
    {
        return Err(MdocError::Cose(
            "COSE_Key does not authorize signature verification".into(),
        ));
    }
    public_key_parts(
        key.params.iter().map(|(label, value)| {
            (
                match label {
                    Label::Int(label) => Some(*label),
                    _ => None,
                },
                value.as_integer().map(i128::from),
                value.as_bytes().map(Vec::as_slice),
            )
        }),
        curve,
        coordinate_len,
        key_type == iana::KeyType::EC2,
    )
}

fn borrowed_key_parts<'a>(key: &CoseKeyRef<'a>, alg: i64) -> Result<PublicKeyParts<'a>, MdocError> {
    let (key_type, curve, coordinate_len) = algorithm_parameters(alg)?;
    if key.kty != CoseLabelRef::Int(key_type as i64) {
        return Err(MdocError::Cose("algorithm/key type/curve mismatch".into()));
    }
    if key
        .alg
        .is_some_and(|declared| declared != CoseLabelRef::Int(alg))
    {
        return Err(MdocError::Cose(
            "COSE_Key algorithm does not match signature".into(),
        ));
    }
    if !key.base_iv.is_empty()
        || (!key.key_ops.is_empty()
            && !key
                .key_ops
                .contains(&CoseLabelRef::Int(coset::iana::KeyOperation::Verify as i64)))
    {
        return Err(MdocError::Cose(
            "COSE_Key does not authorize signature verification".into(),
        ));
    }
    public_key_parts(
        key.params.iter().map(|(label, value)| {
            (
                match label {
                    CoseLabelRef::Int(label) => Some(*label),
                    _ => None,
                },
                value.as_integer(),
                value.as_bytes(),
            )
        }),
        curve,
        coordinate_len,
        key_type == coset::iana::KeyType::EC2,
    )
}

/// Shared validation reads only the metadata and coordinate slices; neither
/// the owned nor borrowed model needs a second COSE key or a CBOR value tree.
fn public_key_parts<'a>(
    params: impl Iterator<Item = (Option<i64>, Option<i128>, Option<&'a [u8]>)>,
    curve: i128,
    coordinate_len: usize,
    ec2: bool,
) -> Result<PublicKeyParts<'a>, MdocError> {
    let mut labels = 0u8;
    let mut result = PublicKeyParts { x: &[], y: None };
    for (label, integer, bytes) in params {
        let bit = match label {
            Some(-1) => 1,
            Some(-2) => 2,
            Some(-3) if ec2 => 4,
            _ => {
                return Err(MdocError::Cose(
                    "private or unsupported COSE_Key parameter".into(),
                ));
            }
        };
        if labels & bit != 0 {
            return Err(MdocError::Cose("duplicate COSE_Key parameter".into()));
        }
        labels |= bit;
        if bit == 1 {
            if integer != Some(curve) {
                return Err(MdocError::Cose("algorithm/key type/curve mismatch".into()));
            }
        } else {
            let bytes = bytes
                .filter(|bytes| bytes.len() == coordinate_len)
                .ok_or_else(|| MdocError::Cose("invalid COSE_Key coordinate length/type".into()))?;
            if bit == 2 {
                result.x = bytes;
            } else {
                result.y = Some(bytes);
            }
        }
    }
    if labels != if ec2 { 7 } else { 3 } {
        return Err(MdocError::Cose(
            "missing required COSE_Key coordinate".into(),
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToSec1Point;

    #[test]
    fn coordinate_widths_are_checked_before_fixed_buffer_conversion() {
        for (algorithm, curve, width) in [(-7, 1, 32), (-35, 2, 48), (-36, 3, 66)] {
            for label in [-2, -3] {
                for bad_width in [0, width - 1, width + 1] {
                    let key = coset::CoseKey {
                        kty: coset::KeyType::Assigned(coset::iana::KeyType::EC2),
                        params: vec![
                            (coset::Label::Int(-1), curve.into()),
                            (
                                coset::Label::Int(-2),
                                ciborium::Value::Bytes(vec![
                                    0;
                                    if label == -2 {
                                        bad_width
                                    } else {
                                        width
                                    }
                                ]),
                            ),
                            (
                                coset::Label::Int(-3),
                                ciborium::Value::Bytes(vec![
                                    0;
                                    if label == -3 {
                                        bad_width
                                    } else {
                                        width
                                    }
                                ]),
                            ),
                        ],
                        ..Default::default()
                    };
                    let error =
                        verify_cose_signature(b"message", &[0; 132], &key, algorithm).unwrap_err();
                    assert!(error.to_string().contains("coordinate length/type"));
                }
            }
        }
    }

    #[test]
    fn duplicate_public_key_parameters_are_rejected() {
        for label in [-1, -2, -3] {
            let mut key = p256_cose_key();
            let duplicate = key
                .params
                .iter()
                .find(|(key, _)| *key == coset::Label::Int(label))
                .unwrap()
                .clone();
            key.params.push(duplicate);
            let error = validate_verification_key(&key, algorithms::ES256).unwrap_err();
            assert!(error.to_string().contains("duplicate COSE_Key parameter"));
        }
    }

    fn p256_cose_key() -> coset::CoseKey {
        let sk = p256::ecdsa::SigningKey::from_slice(&[1u8; 32]).unwrap();
        let pk = p256::PublicKey::from(sk.verifying_key());
        let point = pk.to_sec1_point(false);
        coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
        .build()
    }

    #[test]
    fn der_encoded_es256_signature_is_rejected() {
        // Only fixed-length raw r||s is accepted; a DER-length
        // signature (e.g. 70/71/72 bytes) must be rejected, not parsed.
        let key = p256_cose_key();
        for len in [70usize, 71, 72] {
            let der_like = vec![0x30u8; len];
            let res = verify_cose_signature(b"message", &der_like, &key, algorithms::ES256);
            assert!(
                res.is_err(),
                "DER-length ({len}) signature must be rejected"
            );
        }
    }

    #[test]
    fn raw_rs_length_is_required() {
        let key = p256_cose_key();
        // 63 bytes (one short of raw r||s) must be rejected.
        assert!(verify_cose_signature(b"m", &[0u8; 63], &key, algorithms::ES256).is_err());
    }

    #[test]
    fn ec2_verification_keys_require_both_coordinates_before_signing_preparation() {
        let complete = p256_cose_key();
        assert!(validate_verification_key(&complete, algorithms::ES256).is_ok());
        for missing in [-2, -3] {
            let mut key = complete.clone();
            key.params
                .retain(|(label, _)| *label != coset::Label::Int(missing));
            let error = validate_verification_key(&key, algorithms::ES256).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("missing required COSE_Key coordinate")
            );
        }
    }

    #[test]
    fn okp_verification_keys_require_x_but_reject_y() {
        let public = ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes();
        let mut key = coset::CoseKey {
            kty: coset::KeyType::Assigned(coset::iana::KeyType::OKP),
            params: vec![
                (coset::Label::Int(-1), 6.into()),
                (
                    coset::Label::Int(-2),
                    ciborium::Value::Bytes(public.to_vec()),
                ),
            ],
            ..Default::default()
        };
        assert!(validate_verification_key(&key, algorithms::EDDSA).is_ok());
        key.params
            .push((coset::Label::Int(-3), ciborium::Value::Bytes(vec![0; 32])));
        assert!(validate_verification_key(&key, algorithms::EDDSA).is_err());
        key.params.truncate(1);
        let error = validate_verification_key(&key, algorithms::EDDSA).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing required COSE_Key coordinate")
        );
    }

    // ── ES512 / P-521 known-answer vector ───────────────────────────────────
    // P-521 ECDSA signature over the message below, produced with OpenSSL
    // (`openssl dgst -sha512 -sign`) over a freshly generated secp521r1 key.
    // An independent known-answer vector exercises the verification arm.
    const P521_POINT_HEX: &str = "04004d094025302ae8650de954e88b7c9ece537f8805e1a6aa93ea81c24f2b937f2bdf111a3eb19c4cfa6e64cf57057d2ad72be45ec1c321495fa0d0287cbc96bfe6aa003c7a4aa96e1bec02d00343916609d9ab1373b82bae8dac7b1a1b9ab202784eec97fc03add136303f9abe94199f0189abef977830d4ce6f6b12e8d97f609e0b8b39";
    const P521_SIG_HEX: &str = "0012fcd041336a469dfb0a421cda7bb0e5964b1dadc586e57508adb26daa1de4bcac002a1bf4b689bf582b9a7b37570f9fb1dcc919433f4991ecdace09864cc022e901c9be99673eb84c97aff057549b655f1bd363413a0ce9a0e4f19abec89bddd746502af21a8907ec5c30d143196ba337fe2c26356a3707c741e43c975cd063413680";
    const P521_MSG: &[u8] = b"device authentication bytes";

    fn p521_cose_key() -> coset::CoseKey {
        let point = hex::decode(P521_POINT_HEX).unwrap();
        // Uncompressed SEC1 point: 0x04 || x(66) || y(66).
        let x = point[1..67].to_vec();
        let y = point[67..133].to_vec();
        coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_521, x, y).build()
    }

    #[test]
    fn es512_known_answer_verifies() {
        let key = p521_cose_key();
        let sig = hex::decode(P521_SIG_HEX).unwrap();
        assert_eq!(sig.len(), 132, "P-521 raw r||s is 132 bytes");
        assert!(
            verify_cose_signature(P521_MSG, &sig, &key, algorithms::ES512).unwrap(),
            "valid ES512 signature must verify"
        );
        // Flipping a low byte keeps r/s parseable as in-range scalars but
        // breaks the signature, so verification returns Ok(false).
        let mut bad = sig.clone();
        bad[131] ^= 0x01;
        assert!(!verify_cose_signature(P521_MSG, &bad, &key, algorithms::ES512).unwrap());
    }

    #[test]
    fn es512_rejects_wrong_length() {
        let key = p521_cose_key();
        // 131 bytes (one short of raw r||s) must be rejected, not parsed.
        assert!(verify_cose_signature(b"m", &[0u8; 131], &key, algorithms::ES512).is_err());
    }

    fn assert_multipart_paths(key: &coset::CoseKey, alg: i64, message: &[u8], signature: &[u8]) {
        use crate::cose::key::CoseKeyExt;
        use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
        use coset::CborSerializable;
        let encoded = key.clone().to_vec().unwrap();
        let borrowed = CoseKeyRef::parse(crate::cbor::raw::Item::parse(&encoded).unwrap()).unwrap();
        let parts = [&message[..3], &message[3..8], &message[8..]];
        assert!(verify_cose_signature_parts(&parts, signature, key, alg).unwrap());
        assert!(verify_cose_signature_borrowed(&parts, signature, &borrowed, alg).unwrap());
        let algorithm = if alg == algorithms::EDDSA {
            x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::ObjectIdentifier::new_unwrap("1.3.101.112"),
                parameters: None,
            }
        } else {
            let curve = match alg {
                algorithms::ES256 => SECP_256_R_1,
                algorithms::ES384 => SECP_384_R_1,
                algorithms::ES512 => SECP_521_R_1,
                _ => unreachable!(),
            };
            x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(der::asn1::Any::encode_from(&curve).unwrap()),
            }
        };
        let spki = x509_cert::spki::SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: der::asn1::BitString::from_bytes(&key.public_key_bytes().unwrap())
                .unwrap(),
        };
        assert!(
            VerificationKey::from_spki(&spki, alg)
                .unwrap()
                .verify(&parts, signature)
                .unwrap()
        );
        let mismatched = if alg == algorithms::ES256 {
            algorithms::ES384
        } else {
            algorithms::ES256
        };
        assert!(VerificationKey::from_spki(&spki, mismatched).is_err());
        let changed_parts = [&message[..3], b"changed", &message[8..]];
        assert!(
            !verify_cose_signature_borrowed(&changed_parts, signature, &borrowed, alg).unwrap()
        );
        assert!(
            !VerificationKey::from_spki(&spki, alg)
                .unwrap()
                .verify(&changed_parts, signature)
                .unwrap()
        );
    }

    #[test]
    fn multipart_owned_borrowed_and_spki_paths_agree_for_all_algorithms() {
        use signature::Signer;
        let message = b"fragmented authentication message";
        let signer = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let signature: p256::ecdsa::Signature = signer.sign(message);
        assert_multipart_paths(
            &p256_cose_key(),
            algorithms::ES256,
            message,
            &signature.to_bytes(),
        );

        let signer = p384::ecdsa::SigningKey::from_slice(&[2; 48]).unwrap();
        let point = signer.verifying_key().to_sec1_point(false);
        let key = super::super::key::cose_key_from_sec1_bytes(2, point.as_bytes()).unwrap();
        let signature: p384::ecdsa::Signature = signer.sign(message);
        assert_multipart_paths(&key, algorithms::ES384, message, &signature.to_bytes());

        assert_multipart_paths(
            &p521_cose_key(),
            algorithms::ES512,
            P521_MSG,
            &hex::decode(P521_SIG_HEX).unwrap(),
        );

        let signer = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let key = coset::CoseKeyBuilder::new_okp_key()
            .param(-1, 6.into())
            .param(
                -2,
                ciborium::Value::Bytes(signer.verifying_key().to_bytes().to_vec()),
            )
            .build();
        let signature: ed25519_dalek::Signature = signer.sign(message);
        assert!(
            verify_cose_signature(message, &signature.to_bytes(), &key, algorithms::EDDSA).unwrap()
        );
        assert_multipart_paths(&key, algorithms::EDDSA, message, &signature.to_bytes());
    }

    #[test]
    fn ed25519_single_and_multipart_paths_reject_a_weak_key_forgery() {
        use coset::CborSerializable;
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut forged = [0; 64];
        forged[0] = 1;
        let public = ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&forged);
        let parts: &[&[u8]] = &[b"forged", b" message"];
        // The upstream non-strict multipart API accepts this; our strict path must not.
        assert!(public.multipart_verify(parts, &signature).is_ok());
        let key = coset::CoseKeyBuilder::new_okp_key()
            .param(-1, 6.into())
            .param(-2, ciborium::Value::Bytes(identity.to_vec()))
            .build();
        assert!(
            !verify_cose_signature(b"forged message", &forged, &key, algorithms::EDDSA).unwrap()
        );
        assert!(!verify_cose_signature_parts(parts, &forged, &key, algorithms::EDDSA).unwrap());
        let encoded = key.to_vec().unwrap();
        let borrowed = CoseKeyRef::parse(crate::cbor::raw::Item::parse(&encoded).unwrap()).unwrap();
        assert!(
            !verify_cose_signature_borrowed(parts, &forged, &borrowed, algorithms::EDDSA).unwrap()
        );
        assert!(super::super::validate_borrowed_device_public_key(&borrowed).is_err());
    }
}
