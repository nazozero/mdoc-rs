//! Native verification of the ISO curves absent from the default Rust backend.
//! No private-key or certificate-path operation is performed here.

use super::key::{SignatureCurve, algorithms, curves};
use crate::error::MdocError;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    nid::Nid,
    pkey::{Id, PKey, Public},
};
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Clone, Debug)]
pub(crate) enum ExtendedVerificationKey {
    Brainpool {
        key: EcKey<Public>,
        curve: SignatureCurve,
    },
    Ed448(PKey<Public>),
}

fn crypto_error(error: ErrorStack) -> MdocError {
    MdocError::Signature(format!("OpenSSL: {error}"))
}

/// Decode one named Brainpool public point at the protocol boundary.
/// SEC1 decoding checks curve membership; every selected Brainpool group has
/// cofactor one (RFC 5639), so excluding infinity also establishes subgroup
/// membership without another scalar multiplication.
pub(crate) fn ec_public_key(curve: i64, bytes: &[u8]) -> Result<EcKey<Public>, MdocError> {
    let nid = match curve {
        curves::BP256 => Nid::BRAINPOOL_P256R1,
        curves::BP320 => Nid::BRAINPOOL_P320R1,
        curves::BP384 => Nid::BRAINPOOL_P384R1,
        curves::BP512 => Nid::BRAINPOOL_P512R1,
        _ => return Err(MdocError::Cose("unsupported Brainpool curve".into())),
    };
    let group = EcGroup::from_curve_name(nid).map_err(crypto_error)?;
    let mut context = BigNumContext::new().map_err(crypto_error)?;
    let point = EcPoint::from_bytes(&group, bytes, &mut context).map_err(crypto_error)?;
    if point.is_infinity(&group) {
        return Err(MdocError::Cose("invalid public point at infinity".into()));
    }
    EcKey::from_public_key(&group, &point).map_err(crypto_error)
}

impl ExtendedVerificationKey {
    pub(crate) fn from_bytes(bytes: &[u8], curve: SignatureCurve) -> Result<Self, MdocError> {
        match curve {
            SignatureCurve::Ed448 => PKey::public_key_from_raw_bytes(bytes, Id::ED448)
                .map(Self::Ed448)
                .map_err(crypto_error),
            SignatureCurve::Brainpool256
            | SignatureCurve::Brainpool320
            | SignatureCurve::Brainpool384
            | SignatureCurve::Brainpool512 => Ok(Self::Brainpool {
                key: ec_public_key(curve.id(), bytes)?,
                curve,
            }),
            _ => Err(MdocError::Cose(
                "unsupported native verification curve".into(),
            )),
        }
    }

    pub(crate) fn validate_device_point(&self) -> Result<(), MdocError> {
        match self {
            Self::Brainpool { .. } => Ok(()),
            // The default OpenSSL provider validates Ed448 points while verifying
            // a signature, not on raw-key import/public_check. Do not represent
            // an unproven raw device key as independently validated.
            Self::Ed448(_) => Err(MdocError::UnsupportedAlgorithm(
                "standalone Ed448 device-key validation requires a point-validation backend".into(),
            )),
        }
    }

    pub(crate) fn verify(&self, parts: &[&[u8]], signature: &[u8]) -> Result<bool, MdocError> {
        match self {
            Self::Brainpool { key, curve } => {
                let width = curve.width();
                if signature.len() != 2 * width {
                    return Err(MdocError::Signature(format!(
                        "Brainpool signature must be {}-byte raw r||s",
                        2 * width,
                    )));
                }
                let signature = EcdsaSig::from_private_components(
                    BigNum::from_slice(&signature[..width]).map_err(crypto_error)?,
                    BigNum::from_slice(&signature[width..]).map_err(crypto_error)?,
                )
                .map_err(crypto_error)?;
                // Hash the borrowed authenticated fragments directly. Converting
                // raw r||s to OpenSSL BIGNUMs does not re-encode the message/DER.
                match curve.algorithm() {
                    algorithms::ES256 => signature.verify(&hash_parts::<Sha256>(parts), key),
                    algorithms::ES384 => signature.verify(&hash_parts::<Sha384>(parts), key),
                    algorithms::ES512 => signature.verify(&hash_parts::<Sha512>(parts), key),
                    _ => unreachable!("Brainpool ECDSA curve"),
                }
                .map_err(crypto_error)
            }
            Self::Ed448(key) => {
                if signature.len() != 114 {
                    return Err(MdocError::Signature(
                        "Ed448 signature must be 114 bytes".into(),
                    ));
                }
                // Pure Ed448 uses the complete message, not Ed448ph. OpenSSL
                // exposes a one-shot API, so only fragmented inputs need a copy.
                let message;
                let bytes = if let [part] = parts {
                    *part
                } else {
                    message = parts.concat();
                    &message
                };
                openssl::sign::Verifier::new_without_digest(key)
                    .map_err(crypto_error)?
                    .verify_oneshot(signature, bytes)
                    .map_err(crypto_error)
            }
        }
    }
}

fn hash_parts<D: Digest>(parts: &[&[u8]]) -> sha2::digest::Output<D> {
    let mut hash = D::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize()
}
