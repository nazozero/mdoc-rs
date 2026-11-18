//! Device authentication verification (ISO 18013-5 §9.1.3).

use crate::error::MdocError;
use crate::model::types::DeviceAuth;

/// Signature or MAC result for the supplied payload and key.
#[derive(Clone, Debug)]
pub struct DeviceAuthResult {
    /// Whether the signature or MAC matches the supplied bytes and key.
    pub is_valid: bool,
    /// Algorithm used.
    pub algorithm: String,
    /// Reasons for failure, if any.
    pub reasons: Vec<String>,
}

/// Check the cryptographic signature or MAC over the supplied detached payload.
///
/// Supply complete `DeviceAuthenticationBytes`, including Tag 24 and its byte
/// string envelope, for the authenticated request. The caller establishes the
/// payload schema and key provenance. [`crate::verify_presentation`] performs
/// these checks for a wire presentation.
///
/// For `DeviceAuth::Signature`, checks the COSE_Sign1 using the supplied device
/// public key. Authenticating that key in an issuer-signed MSO is a separate step.
///
/// For `DeviceAuth::Mac`, the caller supplies an already-derived ephemeral MAC
/// key. Private keys and ECDH operations remain outside this core.
pub fn verify_device_auth(
    device_auth: &DeviceAuth,
    device_authentication_bytes: &[u8],
    device_key: &coset::CoseKey,
    ephemeral_mac_key: Option<&[u8; 32]>,
) -> Result<DeviceAuthResult, MdocError> {
    match device_auth {
        DeviceAuth::Signature(sign1) => {
            let algorithm = crate::cose::validate_headers(&sign1.protected, &sign1.unprotected)?;
            let is_valid =
                verify_device_signature(sign1, device_authentication_bytes, device_key, algorithm)?;
            Ok(DeviceAuthResult {
                is_valid,
                algorithm: crate::cose::cose_alg_to_name(algorithm).to_owned(),
                reasons: if is_valid {
                    vec![]
                } else {
                    vec!["device signature verification failed".to_owned()]
                },
            })
        }
        DeviceAuth::Mac(mac0) => {
            let mac_key = ephemeral_mac_key.ok_or_else(|| {
                MdocError::DeviceAuth(
                    "ephemeral MAC key required for COSE_Mac0 verification".to_string(),
                )
            })?;
            verify_device_mac(mac0, device_authentication_bytes, mac_key)
        }
    }
}

/// The caller has validated the protected header and selected its algorithm.
/// Return only the signature result when no diagnostic model is needed.
pub(crate) fn verify_device_signature(
    sign1: &coset::CoseSign1,
    device_authentication_bytes: &[u8],
    device_key: &coset::CoseKey,
    algorithm: i64,
) -> Result<bool, MdocError> {
    if sign1.payload.is_some() {
        return Err(MdocError::DeviceAuth(
            "deviceSignature must use a detached payload".into(),
        ));
    }
    crate::cose::with_protected_bytes(&sign1.protected, |protected| {
        let framing = crate::cose::AuthenticationStructure::sign1(
            protected.len(),
            device_authentication_bytes.len(),
        );
        crate::cose::verify_cose_signature_parts(
            &framing.parts(protected, device_authentication_bytes),
            &sign1.signature,
            device_key,
            algorithm,
        )
    })
}

/// Check an HMAC-256/256 COSE_Mac0 using an externally derived EMacKey.
///
/// The caller establishes the ECDH peer key and SessionTranscriptBytes binding
/// when deriving the key, and authenticates the issuer and payload schema.
pub fn verify_device_mac(
    mac0: &coset::CoseMac0,
    device_authentication_bytes: &[u8],
    mac_key: &[u8; 32],
) -> Result<DeviceAuthResult, MdocError> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    if mac0.payload.is_some() {
        return Err(MdocError::DeviceAuth(
            "deviceMac must use a detached payload".into(),
        ));
    }
    match mac0.protected.header.alg.as_ref() {
        Some(coset::Algorithm::Assigned(coset::iana::Algorithm::HMAC_256_256)) => {}
        Some(algorithm) => {
            return Err(MdocError::DeviceAuth(format!(
                "unsupported COSE_Mac0 algorithm: {algorithm:?}"
            )));
        }
        None => {
            return Err(MdocError::DeviceAuth(
                "missing algorithm in device MAC".to_string(),
            ));
        }
    }

    crate::cose::validate_headers(&mac0.protected, &mac0.unprotected)?;

    let is_valid = crate::cose::with_protected_bytes(&mac0.protected, |protected| {
        let framing = crate::cose::AuthenticationStructure::mac0(
            protected.len(),
            device_authentication_bytes.len(),
        );
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key)
            .map_err(|e| MdocError::DeviceAuth(format!("HMAC init: {e}")))?;
        for part in framing.parts(protected, device_authentication_bytes) {
            hmac.update(part);
        }
        Ok(hmac.verify_slice(&mac0.tag).is_ok())
    })?;

    Ok(DeviceAuthResult {
        is_valid,
        algorithm: "HMAC256".to_string(),
        reasons: if is_valid {
            vec![]
        } else {
            vec!["MAC verification failed".to_string()]
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_mac(
        algorithm: Option<coset::Algorithm>,
        device_authentication: &[u8],
        key: &[u8; 32],
    ) -> coset::CoseMac0 {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let protected = coset::ProtectedHeader {
            original_data: None,
            header: coset::Header {
                alg: algorithm,
                ..coset::Header::default()
            },
        };
        let mac_structure = coset::mac_structure_data(
            coset::MacContext::CoseMac0,
            protected.clone(),
            &[],
            device_authentication,
        );
        let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("fixed-length HMAC key");
        hmac.update(&mac_structure);

        coset::CoseMac0 {
            protected,
            unprotected: coset::Header::default(),
            payload: None,
            tag: hmac.finalize().into_bytes().to_vec(),
        }
    }

    #[test]
    fn device_mac_accepts_valid_hmac_256_256() {
        let authentication = b"device-authentication";
        let key = [7; 32];
        let mac0 = device_mac(
            Some(coset::Algorithm::Assigned(
                coset::iana::Algorithm::HMAC_256_256,
            )),
            authentication,
            &key,
        );

        let result = verify_device_mac(&mac0, authentication, &key)
            .expect("supported HMAC algorithm and valid tag");
        assert!(result.is_valid);
        assert_eq!(result.algorithm, "HMAC256");
    }

    #[test]
    fn device_mac_rejects_missing_algorithm() {
        let authentication = b"device-authentication";
        let key = [7; 32];
        let mac0 = device_mac(None, authentication, &key);

        let error = verify_device_mac(&mac0, authentication, &key)
            .expect_err("the device MAC algorithm is mandatory");
        assert!(error.to_string().contains("missing algorithm"));
    }

    #[test]
    fn device_mac_rejects_wrong_assigned_algorithm() {
        let authentication = b"device-authentication";
        let key = [7; 32];
        let mac0 = device_mac(
            Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256)),
            authentication,
            &key,
        );

        let error = verify_device_mac(&mac0, authentication, &key)
            .expect_err("a signature algorithm cannot identify a device MAC");
        assert!(
            error
                .to_string()
                .contains("unsupported COSE_Mac0 algorithm")
        );
    }

    #[test]
    fn device_mac_rejects_private_use_algorithm() {
        let authentication = b"device-authentication";
        let key = [7; 32];
        let mac0 = device_mac(
            Some(coset::Algorithm::PrivateUse(-65_537)),
            authentication,
            &key,
        );

        let error = verify_device_mac(&mac0, authentication, &key)
            .expect_err("private-use MAC algorithms are not implemented");
        assert!(
            error
                .to_string()
                .contains("unsupported COSE_Mac0 algorithm")
        );
    }
}
