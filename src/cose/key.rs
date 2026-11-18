//! COSE Key conversion utilities.
//!
//! Convert between `coset::CoseKey` and RustCrypto types for signature
//! verification and ECDH operations.

use crate::error::MdocError;
use coset::iana;

/// Validate a supported signature-only device public key before issuing it.
/// Private coordinates and unsupported algorithms must never enter an MSO.
/// Point validation is delegated to the same RustCrypto implementations used
/// for signature verification, not reimplemented here.
#[cfg(feature = "issue")]
pub(crate) fn validate_device_public_key(key: &coset::CoseKey) -> Result<(), MdocError> {
    let alg = match (&key.kty, key.curve()?) {
        (coset::KeyType::Assigned(iana::KeyType::EC2), 1) => -7,
        (coset::KeyType::Assigned(iana::KeyType::EC2), 2) => -35,
        (coset::KeyType::Assigned(iana::KeyType::EC2), 3) => -36,
        (coset::KeyType::Assigned(iana::KeyType::OKP), 6) => -8,
        _ => return Err(MdocError::Cose("unsupported device public key".into())),
    };
    crate::cose::verify::VerificationKey::from_cose(key, alg)?.validate_device_point()
}

/// Validate a device key directly from its original MSO parameters.
pub(crate) fn validate_borrowed_device_public_key(
    key: &crate::model::CoseKeyRef<'_>,
) -> Result<(), MdocError> {
    use crate::model::CoseLabelRef;
    let curve = key.params.iter().find_map(|(label, value)| {
        (*label == CoseLabelRef::Int(-1))
            .then(|| value.as_integer())
            .flatten()
    });
    let alg = match (key.kty, curve) {
        (CoseLabelRef::Int(2), Some(1)) => algorithms::ES256,
        (CoseLabelRef::Int(2), Some(2)) => algorithms::ES384,
        (CoseLabelRef::Int(2), Some(3)) => algorithms::ES512,
        (CoseLabelRef::Int(1), Some(6)) => algorithms::EDDSA,
        _ => return Err(MdocError::Cose("unsupported device public key".into())),
    };
    crate::cose::verify::VerificationKey::from_borrowed(key, alg)?.validate_device_point()
}

/// Extension trait for `coset::CoseKey` with mdoc-specific operations.
pub trait CoseKeyExt {
    /// Extract the raw public key bytes (uncompressed point for EC2, or raw for OKP).
    fn public_key_bytes(&self) -> Result<Vec<u8>, MdocError>;

    /// Get the COSE algorithm identifier.
    fn algorithm(&self) -> Result<i64, MdocError>;

    /// Get the curve identifier.
    fn curve(&self) -> Result<i64, MdocError>;
}

impl CoseKeyExt for coset::CoseKey {
    fn public_key_bytes(&self) -> Result<Vec<u8>, MdocError> {
        match &self.kty {
            coset::KeyType::Assigned(iana::KeyType::EC2) => {
                // EC2 key: extract x and y coordinates
                let x = get_param(&self.params, iana::Ec2KeyParameter::X as i64)?;
                let y = get_param(&self.params, iana::Ec2KeyParameter::Y as i64)?;
                // Uncompressed point: 0x04 || x || y
                let mut bytes = Vec::with_capacity(1 + x.len() + y.len());
                bytes.push(0x04);
                bytes.extend_from_slice(x);
                bytes.extend_from_slice(y);
                Ok(bytes)
            }
            coset::KeyType::Assigned(iana::KeyType::OKP) => {
                // OKP key: extract x coordinate (raw public key)
                let x = get_param(&self.params, iana::OkpKeyParameter::X as i64)?;
                Ok(x.to_vec())
            }
            _ => Err(MdocError::Cose(format!(
                "unsupported key type: {:?}",
                self.kty
            ))),
        }
    }

    fn algorithm(&self) -> Result<i64, MdocError> {
        match &self.alg {
            Some(coset::Algorithm::Assigned(a)) => Ok(*a as i64),
            Some(coset::Algorithm::PrivateUse(v)) => Ok(*v),
            _ => Err(MdocError::Cose("missing algorithm in COSE key".to_string())),
        }
    }

    fn curve(&self) -> Result<i64, MdocError> {
        match &self.kty {
            coset::KeyType::Assigned(iana::KeyType::EC2 | iana::KeyType::OKP) => {
                for (label, value) in &self.params {
                    if let coset::Label::Int(-1) = label
                        && let ciborium::Value::Integer(crv) = value
                    {
                        return i64::try_from(i128::from(*crv))
                            .map_err(|_| MdocError::Cose("curve out of range".into()));
                    }
                }
                Err(MdocError::Cose("missing curve in COSE key".to_string()))
            }
            _ => Err(MdocError::Cose(format!(
                "unsupported key type: {:?}",
                self.kty
            ))),
        }
    }
}

/// Extract a byte-string parameter from COSE key params by label.
pub(super) fn get_param(
    params: &[(coset::Label, ciborium::Value)],
    label: i64,
) -> Result<&[u8], MdocError> {
    for (l, v) in params {
        if let coset::Label::Int(n) = l
            && *n == label
            && let ciborium::Value::Bytes(b) = v
        {
            return Ok(b);
        }
    }
    Err(MdocError::Cose(format!(
        "missing COSE key parameter with label {label}"
    )))
}

/// Map COSE algorithm identifier to human-readable name.
pub fn cose_alg_to_name(alg: i64) -> &'static str {
    match alg {
        -7 => "ES256",
        -35 => "ES384",
        -36 => "ES512",
        -8 => "EdDSA",
        5 => "HMAC256",
        6 => "HMAC384",
        7 => "HMAC512",
        _ => "unknown",
    }
}

/// Build an EC2 `coset::CoseKey` from an uncompressed SEC1 public point
/// (`0x04 || x || y`).
///
/// `curve_id` is a COSE curve identifier (see [`curves`]): P-256 (1), P-384 (2),
/// or P-521 (3).
pub fn cose_key_from_sec1_bytes(curve_id: i64, point: &[u8]) -> Result<coset::CoseKey, MdocError> {
    let (curve, coord_len) = match curve_id {
        curves::P256 => (iana::EllipticCurve::P_256, 32usize),
        curves::P384 => (iana::EllipticCurve::P_384, 48),
        curves::P521 => (iana::EllipticCurve::P_521, 66),
        other => {
            return Err(MdocError::Cose(format!(
                "unsupported curve id {other} (expected P-256/384/521)"
            )));
        }
    };

    if point.len() != 1 + 2 * coord_len || point[0] != 0x04 {
        return Err(MdocError::Cose(format!(
            "expected uncompressed SEC1 point (0x04 + {} bytes), got {} bytes",
            2 * coord_len,
            point.len()
        )));
    }

    let x = point[1..1 + coord_len].to_vec();
    let y = point[1 + coord_len..].to_vec();
    Ok(coset::CoseKeyBuilder::new_ec2_pub_key(curve, x, y).build())
}

/// Convert a PEM `SubjectPublicKeyInfo` (`BEGIN PUBLIC KEY`) for P-256, P-384,
/// P-521 or Ed25519 into a COSE public key.
pub fn cose_key_from_pem(pem: &str) -> Result<coset::CoseKey, MdocError> {
    use der::DecodePem;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let spki = SubjectPublicKeyInfoOwned::from_pem(pem.as_bytes())
        .map_err(|e| MdocError::Cose(format!("parse SubjectPublicKeyInfo PEM: {e}")))?;

    cose_key_from_spki(&spki)
}

/// Convert an X.509 public key according to its algorithm and curve OIDs.
/// The application validates the certificate.
pub fn cose_key_from_spki(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Result<coset::CoseKey, MdocError> {
    let (alg, bytes) = spki_key_bytes(spki)?;
    if alg == algorithms::EDDSA {
        return Ok(coset::CoseKeyBuilder::new_okp_key()
            .param(-1, ciborium::Value::Integer(curves::ED25519.into()))
            .param(-2, ciborium::Value::Bytes(bytes.to_vec()))
            .build());
    }
    let curve = match alg {
        algorithms::ES256 => curves::P256,
        algorithms::ES384 => curves::P384,
        algorithms::ES512 => curves::P521,
        _ => unreachable!("supported SPKI algorithm"),
    };
    cose_key_from_sec1_bytes(curve, bytes)
}

/// Read the algorithm and original public point without converting through an
/// owned COSE key. This preserves the SPKI restrictions of the public adapter.
pub(super) fn spki_key_bytes(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Result<(i64, &[u8]), MdocError> {
    use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
    if spki.algorithm.oid == const_oid::ObjectIdentifier::new_unwrap("1.3.101.112") {
        if spki.algorithm.parameters.is_some() {
            return Err(MdocError::Cose(
                "Ed25519 SPKI parameters must be absent".into(),
            ));
        }
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| MdocError::Cose("unaligned SPKI".into()))?;
        if bytes.len() != 32 {
            return Err(MdocError::Cose("invalid Ed25519 SPKI length".into()));
        }
        return Ok((algorithms::EDDSA, bytes));
    }
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(MdocError::Cose(format!(
            "not an EC public key (algorithm OID {})",
            spki.algorithm.oid
        )));
    }
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| MdocError::Cose("EC public key missing curve parameters".into()))?
        .decode_as::<der::asn1::ObjectIdentifier>()
        .map_err(|e| MdocError::Cose(format!("decode EC curve OID: {e}")))?;
    let (alg, width) = match curve_oid {
        SECP_256_R_1 => (algorithms::ES256, 32),
        SECP_384_R_1 => (algorithms::ES384, 48),
        SECP_521_R_1 => (algorithms::ES512, 66),
        other => return Err(MdocError::Cose(format!("unsupported EC curve OID {other}"))),
    };
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| MdocError::Cose("EC public key is not byte-aligned".into()))?;
    if point.len() != 1 + 2 * width || point[0] != 4 {
        return Err(MdocError::Cose(format!(
            "expected uncompressed SEC1 point (0x04 + {} bytes), got {} bytes",
            2 * width,
            point.len()
        )));
    }
    Ok((alg, point))
}

/// COSE curve identifiers.
pub mod curves {
    pub const P256: i64 = 1;
    pub const P384: i64 = 2;
    pub const P521: i64 = 3;
    pub const ED25519: i64 = 6;
}

/// COSE algorithm identifiers.
pub mod algorithms {
    pub const ES256: i64 = -7;
    pub const ES384: i64 = -35;
    pub const ES512: i64 = -36;
    pub const EDDSA: i64 = -8;
    pub const HMAC256: i64 = 5;
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkkMIHcZAXvdMoVYC+SWxjqo52Vx3\ncf7F60N4hHF0YU3gPJY8I8C4Cbzfgy95fmgo8ixHpts1CeArK45q9hMsVA==\n-----END PUBLIC KEY-----\n";
    const P521_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBQF1zqB0Ee3LO98QLvzquEuZMJLQJ\n4H694x92BAEW84Cnap0V9bRe6jtbNFxStdd94m61Peyzq9IaeflZe9J+/n4Aet1R\nBDyAT7NBFVFQ5dgg6i0XMdlgh3n/fTAHkXxTmL7KcmuDXhoD3gw1bnBMnbqQmgmy\nf8FgQTm9YZArU6O1voU=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn pem_p256_maps_to_p256_curve() {
        let key = cose_key_from_pem(P256_PUB_PEM).expect("parse P-256 PEM");
        assert_eq!(key.curve().unwrap(), curves::P256);
        // public_key_bytes returns 0x04 || x(32) || y(32) = 65 bytes.
        assert_eq!(key.public_key_bytes().unwrap().len(), 65);
    }

    #[test]
    fn pem_p521_maps_to_p521_curve() {
        let key = cose_key_from_pem(P521_PUB_PEM).expect("parse P-521 PEM");
        assert_eq!(key.curve().unwrap(), curves::P521);
        // 0x04 || x(66) || y(66) = 133 bytes.
        assert_eq!(key.public_key_bytes().unwrap().len(), 133);
    }

    #[test]
    fn sec1_round_trips_through_cose_key() {
        // Build from PEM, extract SEC1, rebuild from SEC1, expect the same point.
        let from_pem = cose_key_from_pem(P256_PUB_PEM).unwrap();
        let sec1 = from_pem.public_key_bytes().unwrap();
        let from_sec1 = cose_key_from_sec1_bytes(curves::P256, &sec1).unwrap();
        assert_eq!(
            from_sec1.public_key_bytes().unwrap(),
            sec1,
            "round trip must preserve the point"
        );
    }

    #[test]
    fn sec1_rejects_wrong_length() {
        // 0x04 prefix but too short for P-256.
        assert!(cose_key_from_sec1_bytes(curves::P256, &[0x04; 40]).is_err());
    }
}
