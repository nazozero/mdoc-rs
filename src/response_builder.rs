//! Prepare device authentication for an external signer.
//!
//! Private keys, ECDH, signer selection and request authorization belong to the
//! application. This module prepares the COSE Sig_structure and verifies the
//! returned signature against the MSO device key before assembling a detached
//! `DeviceSignature`.

use std::collections::HashMap;

use coset::{CborSerializable, CoseKey, CoseSign1, Header, HeaderBuilder, ProtectedHeader};

use crate::cbor::raw;
use crate::cose::{validate_verification_key, verify_cose_signature};
use crate::error::MdocError;
use crate::model::document::{DeviceSigned, IssuerSignedDocument};
use crate::model::types::DeviceAuth;
use crate::session::{SessionTranscript, build_device_authentication_validated};

/// A device-signature operation awaiting an externally produced signature.
///
/// Retains the exact signing input and its document until completion.
#[derive(Debug)]
#[must_use = "send signing_input to the holder's signer and complete with finish"]
pub struct PreparedDeviceAuthentication {
    document: IssuerSignedDocument,
    name_spaces: HashMap<String, HashMap<String, ciborium::Value>>,
    name_spaces_bytes: Vec<u8>,
    protected: ProtectedHeader,
    signing_input: Vec<u8>,
    device_key: CoseKey,
    algorithm: i64,
}

/// Prepare a holder signature for one document and the supplied transcript.
///
/// `device_name_spaces_bytes` is the complete original
/// `DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)` value. It is
/// decoded once to check its model and the MSO's KeyAuthorizations. The original
/// bytes are retained for the proof and presentation. Empty namespaces can be
/// represented as `[0xd8, 0x18, 0x41, 0xa0]`.
///
/// The caller must authorize the request and obtain this document from a source
/// whose issuer signature, trust and status have been verified. An existing
/// device proof is replaced after the new signature passes `finish`.
pub fn prepare_device_authentication(
    document: IssuerSignedDocument,
    transcript: &SessionTranscript<'_>,
    device_name_spaces_bytes: Vec<u8>,
    algorithm: i64,
) -> Result<PreparedDeviceAuthentication, MdocError> {
    let assigned_algorithm = match algorithm {
        -7 => coset::iana::Algorithm::ES256,
        -35 => coset::iana::Algorithm::ES384,
        -36 => coset::iana::Algorithm::ES512,
        -8 => coset::iana::Algorithm::EdDSA,
        _ => {
            return Err(MdocError::UnsupportedAlgorithm(format!(
                "device signature algorithm {algorithm}"
            )));
        }
    };
    let mso = document.issuer_signed.issuer_auth.mso()?;
    if mso.doc_type != document.doc_type {
        return Err(MdocError::Mso("document docType differs from MSO".into()));
    }
    validate_verification_key(&mso.device_key_info.device_key, algorithm)?;
    let name_spaces = decode_namespaces(&device_name_spaces_bytes)?;
    crate::verifier::check_key_authorizations(&mso.device_key_info, &name_spaces)?;
    let payload = build_device_authentication_validated(
        transcript,
        &document.doc_type,
        &device_name_spaces_bytes,
    );
    let header = HeaderBuilder::new().algorithm(assigned_algorithm).build();
    let protected = ProtectedHeader {
        original_data: Some(header.clone().to_vec()?),
        header,
    };
    let signing_input = crate::cose::sign1_structure(&protected, &payload)?;
    Ok(PreparedDeviceAuthentication {
        document,
        name_spaces,
        name_spaces_bytes: device_name_spaces_bytes,
        protected,
        signing_input,
        device_key: mso.device_key_info.device_key,
        algorithm,
    })
}

impl PreparedDeviceAuthentication {
    /// Exact COSE Sig_structure bytes to send to the external signer.
    /// ECDSA signers return fixed-width raw `r || s`, not ASN.1 DER.
    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    /// Protected COSE algorithm of this signing operation.
    pub fn algorithm(&self) -> i64 {
        self.algorithm
    }

    /// Verify the external signature and attach a detached COSE_Sign1 proof.
    /// A wrong key, altered input, DER-encoded ECDSA value, or invalid signature
    /// cannot produce a successfully completed document.
    pub fn finish(mut self, signature: Vec<u8>) -> Result<IssuerSignedDocument, MdocError> {
        if !verify_cose_signature(
            &self.signing_input,
            &signature,
            &self.device_key,
            self.algorithm,
        )? {
            return Err(MdocError::Signature(
                "external holder signature does not match signing input and device key".into(),
            ));
        }
        self.document.device_signed = Some(DeviceSigned {
            device_auth: DeviceAuth::Signature(CoseSign1 {
                protected: self.protected,
                unprotected: Header::default(),
                payload: None,
                signature,
            }),
            name_spaces: self.name_spaces,
            name_spaces_bytes: self.name_spaces_bytes,
        });
        Ok(self.document)
    }
}

fn decode_namespaces(
    encoded: &[u8],
) -> Result<HashMap<String, HashMap<String, ciborium::Value>>, MdocError> {
    let namespaces = raw::Item::parse(encoded)?.embedded()?.map()?;
    let mut decoded = HashMap::new();
    for namespace in namespaces {
        let (name, elements) = namespace?;
        let name = name.text()?;
        if name.is_empty() {
            return Err(MdocError::Issuance("empty device namespace".into()));
        }
        let mut values = HashMap::new();
        for element in elements.map()? {
            let (name, value) = element?;
            let name = name.text()?;
            if name.is_empty() {
                return Err(MdocError::Issuance(
                    "empty device element identifier".into(),
                ));
            }
            values.insert(name.to_owned(), value.value()?);
        }
        if values.is_empty() {
            return Err(MdocError::Issuance("empty DeviceSignedItems map".into()));
        }
        decoded.insert(name.to_owned(), values);
    }
    Ok(decoded)
}
