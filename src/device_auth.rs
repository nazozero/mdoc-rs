//! Device authentication verification (ISO 18013-5 §9.1.3).

use crate::error::MdocError;
use crate::model::types::DeviceAuth;

/// Result of a cryptographic comparison against caller-supplied payload bytes.
///
/// This primitive result does not authenticate an MSO or issuer, validate the
/// payload's DeviceAuthentication schema, or establish request context or trust.
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
/// The intended payload is the complete `DeviceAuthenticationBytes` (Tag 24 and
/// byte-string envelope included), constructed for the authenticated request
/// context. This low-level operation accepts those bytes as given; it does not
/// validate their schema or prove their provenance. Prefer
/// [`crate::verify_presentation`] for wire presentations and authenticated claims.
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
            verify_device_signature(sign1, device_authentication_bytes, device_key)
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

fn verify_device_signature(
    sign1: &coset::CoseSign1,
    device_authentication_bytes: &[u8],
    device_key: &coset::CoseKey,
) -> Result<DeviceAuthResult, MdocError> {
    if sign1.payload.is_some() {
        return Err(MdocError::DeviceAuth(
            "deviceSignature must use a detached payload".into(),
        ));
    }
    let alg_id = crate::cose::validate_headers(&sign1.protected, &sign1.unprotected)?;
    let alg_name = crate::cose::cose_alg_to_name(alg_id).to_string();

    // Build the Sig_structure for verification
    // Sig_structure = ["Signature1", protected, external_aad, payload]
    // For device auth, external_aad is empty and payload is DeviceAuthentication bytes
    let sig_structure = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        sign1.protected.clone(),
        None,
        &[], // external_aad
        device_authentication_bytes,
    );

    let is_valid =
        crate::cose::verify_cose_signature(&sig_structure, &sign1.signature, device_key, alg_id)?;

    Ok(DeviceAuthResult {
        is_valid,
        algorithm: alg_name,
        reasons: if is_valid {
            vec![]
        } else {
            vec!["device signature verification failed".to_string()]
        },
    })
}

/// Check an HMAC-256/256 COSE_Mac0 using an externally derived EMacKey.
///
/// As with [`verify_device_auth`], success only authenticates the supplied bytes
/// under this key. The caller must establish the ECDH peer key and the correct
/// SessionTranscriptBytes binding when deriving the key; this function does not
/// authenticate the MSO, issuer, payload schema, or request context.
pub fn verify_device_mac(
    mac0: &coset::CoseMac0,
    device_authentication_bytes: &[u8],
    mac_key: &[u8; 32],
) -> Result<DeviceAuthResult, MdocError> {
    use hmac::{Hmac, Mac};
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

    // Build Mac_structure
    let mac_structure = coset::mac_structure_data(
        coset::MacContext::CoseMac0,
        mac0.protected.clone(),
        &[], // external_aad
        device_authentication_bytes,
    );

    // Compute HMAC-SHA256
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key)
        .map_err(|e| MdocError::DeviceAuth(format!("HMAC init: {e}")))?;
    hmac.update(&mac_structure);

    // Verify against tag
    let tag = &mac0.tag;

    let is_valid = hmac.verify_slice(tag).is_ok();

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
        use hmac::{Hmac, Mac};
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
