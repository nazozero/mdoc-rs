//! COSE Key conversion utilities.
//!
//! Convert public keys and preserve their curve/algorithm binding across
//! RustCrypto and the optional native reader backend.

use crate::error::MdocError;
use coset::iana;
use der::referenced::OwnedToRef;

/// Validate a supported signature-only device public key before issuing it.
/// Private coordinates and unsupported algorithms must never enter an MSO.
/// Point validation is delegated to the selected cryptographic backend.
/// Standalone Ed448 device keys are rejected; its native point check requires
/// an actual holder signature.
#[cfg(feature = "issue")]
pub(crate) fn validate_device_public_key(key: &coset::CoseKey) -> Result<(), MdocError> {
    let alg = SignatureCurve::from_id(i128::from(key.curve()?))?.algorithm();
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
    let alg = SignatureCurve::from_id(
        curve.ok_or_else(|| MdocError::Cose("missing device public-key curve".into()))?,
    )?
    .algorithm();
    crate::cose::verify::VerificationKey::from_borrowed(key, alg)?.validate_device_point()
}

/// Extension trait for `coset::CoseKey` with mdoc-specific operations.
pub trait CoseKeyExt {
    /// Extract SEC1 bytes for EC2 (preserving y-coordinate compression), or raw OKP bytes.
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
                let y = self
                    .params
                    .iter()
                    .find(|(label, _)| *label == coset::Label::Int(-3))
                    .map(|(_, value)| value)
                    .ok_or_else(|| MdocError::Cose("missing COSE_Key y coordinate".into()))?;
                let mut bytes = Vec::with_capacity(1 + x.len() + y.as_bytes().map_or(0, Vec::len));
                if let Some(odd) = y.as_bool() {
                    bytes.push(2 | u8::from(odd));
                    bytes.extend_from_slice(x);
                } else {
                    let y = y
                        .as_bytes()
                        .ok_or_else(|| MdocError::Cose("invalid COSE_Key y coordinate".into()))?;
                    bytes.push(4);
                    bytes.extend_from_slice(x);
                    bytes.extend_from_slice(y);
                }
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
/// or P-521 (3); `reader-crypto` also enables Brainpool curves (256–259)
/// on native targets.
pub fn cose_key_from_sec1_bytes(curve_id: i64, point: &[u8]) -> Result<coset::CoseKey, MdocError> {
    let curve = SignatureCurve::from_id(i128::from(curve_id))?;
    if curve.key_type() != iana::KeyType::EC2 {
        return Err(MdocError::Cose("SEC1 requires an EC2 curve".into()));
    }
    let coord_len = curve.width();

    if point.len() != 1 + 2 * coord_len || point[0] != 0x04 {
        return Err(MdocError::Cose(format!(
            "expected uncompressed SEC1 point (0x04 + {} bytes), got {} bytes",
            2 * coord_len,
            point.len()
        )));
    }

    let x = point[1..1 + coord_len].to_vec();
    let y = point[1 + coord_len..].to_vec();
    Ok(coset::CoseKey {
        kty: coset::KeyType::Assigned(iana::KeyType::EC2),
        params: vec![
            (coset::Label::Int(-1), curve_id.into()),
            (coset::Label::Int(-2), ciborium::Value::Bytes(x)),
            (coset::Label::Int(-3), ciborium::Value::Bytes(y)),
        ],
        ..Default::default()
    })
}

/// Convert a PEM `SubjectPublicKeyInfo` (`BEGIN PUBLIC KEY`) for P-256, P-384,
/// P-521 or Ed25519 into a COSE public key. The native `reader-crypto` feature
/// additionally supports Brainpool and Ed448.
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
    let (curve, bytes) = spki_key_bytes(spki.owned_to_ref())?;
    if curve.key_type() == iana::KeyType::OKP {
        return Ok(coset::CoseKeyBuilder::new_okp_key()
            .param(-1, ciborium::Value::Integer(curve.id().into()))
            .param(-2, ciborium::Value::Bytes(bytes.to_vec()))
            .build());
    }
    cose_key_from_sec1_bytes(curve.id(), bytes)
}

/// Read the original public point and its curve without allocating a COSE key.
/// The curve remains distinct from the signature algorithm throughout dispatch.
pub(super) fn spki_key_bytes(
    spki: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
) -> Result<(SignatureCurve, &[u8]), MdocError> {
    use const_oid::{
        ObjectIdentifier as Oid,
        db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
    };
    const ED25519_OID: Oid = Oid::new_unwrap("1.3.101.112");
    const ED448_OID: Oid = Oid::new_unwrap("1.3.101.113");
    const BP256_OID: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.7");
    const BP320_OID: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.9");
    const BP384_OID: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.11");
    const BP512_OID: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.13");
    let curve = match spki.algorithm.oid {
        ED25519_OID => SignatureCurve::Ed25519,
        ED448_OID => SignatureCurve::Ed448,
        ID_EC_PUBLIC_KEY => {
            let oid = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| MdocError::Cose("EC public key missing curve parameters".into()))?
                .decode_as::<Oid>()
                .map_err(|e| MdocError::Cose(format!("decode EC curve OID: {e}")))?;
            match oid {
                SECP_256_R_1 => SignatureCurve::P256,
                SECP_384_R_1 => SignatureCurve::P384,
                SECP_521_R_1 => SignatureCurve::P521,
                BP256_OID => SignatureCurve::Brainpool256,
                BP320_OID => SignatureCurve::Brainpool320,
                BP384_OID => SignatureCurve::Brainpool384,
                BP512_OID => SignatureCurve::Brainpool512,
                other => return Err(MdocError::Cose(format!("unsupported EC curve OID {other}"))),
            }
        }
        oid => return Err(MdocError::Cose(format!("unsupported public key OID {oid}"))),
    };
    curve.require_backend()?;
    let bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| MdocError::Cose("unaligned SPKI".into()))?;
    if curve.key_type() == iana::KeyType::OKP {
        if spki.algorithm.parameters.is_some() {
            return Err(MdocError::Cose(
                "EdDSA SPKI parameters must be absent".into(),
            ));
        }
        if bytes.len() != curve.width() {
            return Err(MdocError::Cose("invalid EdDSA SPKI length".into()));
        }
    } else if bytes.len() != 1 + 2 * curve.width() || bytes[0] != 4 {
        return Err(MdocError::Cose(
            "EC SPKI requires an uncompressed SEC1 point".into(),
        ));
    }
    Ok((curve, bytes))
}

/// ISO/IEC 18013-5:2021 signature curves, keeping algorithm and curve separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignatureCurve {
    P256,
    P384,
    P521,
    Ed25519,
    Ed448,
    Brainpool256,
    Brainpool320,
    Brainpool384,
    Brainpool512,
}

impl SignatureCurve {
    pub(crate) fn from_id(id: i128) -> Result<Self, MdocError> {
        let curve = match id {
            1 => Self::P256,
            2 => Self::P384,
            3 => Self::P521,
            6 => Self::Ed25519,
            7 => Self::Ed448,
            256 => Self::Brainpool256,
            257 => Self::Brainpool320,
            258 => Self::Brainpool384,
            259 => Self::Brainpool512,
            _ => return Err(MdocError::Cose("unsupported signature curve".into())),
        };
        curve.require_backend()?;
        Ok(curve)
    }

    fn require_backend(self) -> Result<(), MdocError> {
        if matches!(
            self,
            Self::Ed448
                | Self::Brainpool256
                | Self::Brainpool320
                | Self::Brainpool384
                | Self::Brainpool512
        ) && !cfg!(all(feature = "reader-crypto", not(target_family = "wasm")))
        {
            return Err(MdocError::UnsupportedAlgorithm(
                "curve requires reader-crypto on a native target".into(),
            ));
        }
        Ok(())
    }

    pub(crate) const fn id(self) -> i64 {
        match self {
            Self::P256 => curves::P256,
            Self::P384 => curves::P384,
            Self::P521 => curves::P521,
            Self::Ed25519 => curves::ED25519,
            Self::Ed448 => curves::ED448,
            Self::Brainpool256 => curves::BP256,
            Self::Brainpool320 => curves::BP320,
            Self::Brainpool384 => curves::BP384,
            Self::Brainpool512 => curves::BP512,
        }
    }

    pub(crate) const fn algorithm(self) -> i64 {
        match self {
            Self::P256 | Self::Brainpool256 => algorithms::ES256,
            Self::P384 | Self::Brainpool320 | Self::Brainpool384 => algorithms::ES384,
            Self::P521 | Self::Brainpool512 => algorithms::ES512,
            Self::Ed25519 | Self::Ed448 => algorithms::EDDSA,
        }
    }

    pub(crate) const fn key_type(self) -> iana::KeyType {
        match self {
            Self::Ed25519 | Self::Ed448 => iana::KeyType::OKP,
            _ => iana::KeyType::EC2,
        }
    }

    pub(crate) const fn width(self) -> usize {
        match self {
            Self::P256 | Self::Brainpool256 | Self::Ed25519 => 32,
            Self::Brainpool320 => 40,
            Self::P384 | Self::Brainpool384 => 48,
            Self::P521 => 66,
            Self::Brainpool512 => 64,
            Self::Ed448 => 57,
        }
    }
}

/// COSE curve identifiers.
pub mod curves {
    pub const P256: i64 = 1;
    pub const P384: i64 = 2;
    pub const P521: i64 = 3;
    pub const ED25519: i64 = 6;
    pub const ED448: i64 = 7;
    pub const BP256: i64 = 256;
    pub const BP320: i64 = 257;
    pub const BP384: i64 = 258;
    pub const BP512: i64 = 259;
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
