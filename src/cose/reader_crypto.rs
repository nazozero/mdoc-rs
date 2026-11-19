//! Portable Brainpool and Ed448 verification for the ISO reader algorithms.
//! COSE signature and point validation use the same RustCrypto arithmetic.

use super::key::SignatureCurve;
use crate::error::MdocError;
use signature::MultipartVerifier;

#[derive(Clone, Debug)]
pub(crate) enum ExtendedVerificationKey {
    Brainpool256(ecdsa::VerifyingKey<bp256::BrainpoolP256r1>),
    Brainpool384(ecdsa::VerifyingKey<bp384::BrainpoolP384r1>),
    Ed448(ed448_goldilocks::VerifyingKey),
}

impl ExtendedVerificationKey {
    pub(crate) fn from_bytes(bytes: &[u8], curve: SignatureCurve) -> Result<Self, MdocError> {
        match curve {
            SignatureCurve::Brainpool256 => ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self::Brainpool256)
                .map_err(|_| MdocError::Signature("invalid Brainpool P256 public point".into())),
            SignatureCurve::Brainpool384 => ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self::Brainpool384)
                .map_err(|_| MdocError::Signature("invalid Brainpool P384 public point".into())),
            SignatureCurve::Ed448 => {
                if !canonical_ed448_point(bytes) {
                    return Err(MdocError::Signature("noncanonical Ed448 public point".into()));
                }
                ed448_goldilocks::VerifyingKey::from_bytes(
                    bytes.try_into().expect("canonical Ed448 points have length 57"),
                )
                .map(Self::Ed448)
                .map_err(|_| MdocError::Signature("invalid Ed448 public point".into()))
            }
            _ => Err(MdocError::UnsupportedAlgorithm(
                "unsupported extended signature curve".into(),
            )),
        }
    }

    pub(crate) fn verify(&self, parts: &[&[u8]], signature: &[u8]) -> Result<bool, MdocError> {
        match self {
            Self::Brainpool256(key) => {
                let signature =
                    bp256::r1::ecdsa::Signature::from_slice(signature).map_err(|_| {
                        MdocError::Signature("Brainpool P256 signature length or scalar".into())
                    })?;
                Ok(key.multipart_verify(parts, &signature).is_ok())
            }
            Self::Brainpool384(key) => {
                let signature =
                    bp384::r1::ecdsa::Signature::from_slice(signature).map_err(|_| {
                        MdocError::Signature("Brainpool P384 signature length or scalar".into())
                    })?;
                Ok(key.multipart_verify(parts, &signature).is_ok())
            }
            Self::Ed448(key) => {
                let parsed =
                    ed448_goldilocks::Signature::from_slice(signature).map_err(|_| {
                        MdocError::Signature("Ed448 signature must be 114 bytes".into())
                    })?;
                if !canonical_ed448_point(&signature[..57]) {
                    return Ok(false);
                }
                let message;
                let bytes = if let [part] = parts {
                    *part
                } else {
                    message = parts.concat();
                    &message
                };
                Ok(key.verify_raw(&parsed, bytes).is_ok())
            }
        }
    }
}

/// RFC 8032 §5.2.2: Ed448 has a 448-bit y coordinate and one sign bit.
/// Reject unused high bits and y >= 2^448 - 2^224 - 1 before point decoding.
/// The comparison is public-data only and does not allocate.
fn canonical_ed448_point(bytes: &[u8]) -> bool {
    if bytes.len() != 57 || bytes[56] & 0x7f != 0 {
        return false;
    }
    const MODULUS: [u8; 56] = {
        let mut p = [0xff; 56];
        p[28] = 0xfe;
        p
    };
    for i in (0..56).rev() {
        if bytes[i] != MODULUS[i] {
            return bytes[i] < MODULUS[i];
        }
    }
    false
}

#[cfg(test)]
mod encoding_tests {
    use super::canonical_ed448_point;

    #[test]
    fn ed448_y_is_strictly_below_field_modulus_and_unused_bits_are_clear() {
        let mut p = [0xff; 57];
        p[28] = 0xfe;
        p[56] = 0;
        assert!(!canonical_ed448_point(&p), "y == p");
        p[28] = 0xff;
        assert!(!canonical_ed448_point(&p), "y > p");
        p[28] = 0xfe;
        p[0] = 0xfe;
        assert!(canonical_ed448_point(&p), "y == p-1 is canonical");
        p[56] = 1;
        assert!(!canonical_ed448_point(&p), "unused top bit");
        p[56] = 0x80;
        assert!(canonical_ed448_point(&p), "sign bit is permitted");
    }
}
