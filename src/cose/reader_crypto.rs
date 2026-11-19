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
            SignatureCurve::Ed448 => ed448_goldilocks::VerifyingKey::from_bytes(
                bytes.try_into()
                    .map_err(|_| MdocError::Signature("Ed448 key length".into()))?,
            )
            .map(Self::Ed448)
            .map_err(|_| MdocError::Signature("invalid Ed448 public point".into())),
            _ => Err(MdocError::UnsupportedAlgorithm(
                "unsupported extended signature curve".into(),
            )),
        }
    }

    pub(crate) fn verify(&self, parts: &[&[u8]], signature: &[u8]) -> Result<bool, MdocError> {
        match self {
            Self::Brainpool256(key) => {
                let signature = bp256::r1::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| MdocError::Signature("Brainpool P256 signature length or scalar".into()))?;
                Ok(key.multipart_verify(parts, &signature).is_ok())
            }
            Self::Brainpool384(key) => {
                let signature = bp384::r1::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| MdocError::Signature("Brainpool P384 signature length or scalar".into()))?;
                Ok(key.multipart_verify(parts, &signature).is_ok())
            }
            Self::Ed448(key) => {
                let signature = ed448_goldilocks::Signature::from_slice(signature)
                    .map_err(|_| MdocError::Signature("Ed448 signature must be 114 bytes".into()))?;
                let message;
                let bytes = if let [part] = parts {
                    *part
                } else {
                    message = parts.concat();
                    &message
                };
                Ok(key.verify_raw(&signature, bytes).is_ok())
            }
        }
    }
}
