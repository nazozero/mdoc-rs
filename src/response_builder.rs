//! Prepare device authentication for an external signer.
//!
//! Private keys, ECDH, signer selection and request authorization belong to the
//! application. This module prepares the COSE Sig_structure and verifies the
//! returned signature against the MSO device key before assembling a detached
//! `DeviceSignature`.

use std::collections::HashMap;

use coset::{CoseSign1, Header, HeaderBuilder, ProtectedHeader};

use crate::cbor::raw;
use crate::cose::VerificationKey;
use crate::error::MdocError;
use crate::model::document::{DeviceSigned, IssuerSignedDocument};
use crate::model::{
    CborValueRef, CoseHeaderRef, CoseLabelRef, CoseSign1Ref, DeviceAuth, DeviceAuthRef,
    DeviceSignedRef, IssuerSignedDocumentRef, MsoRef,
};
use crate::session::{DeviceAuthentication, SessionTranscript};

/// A device-signature operation awaiting an externally produced signature.
///
/// Retains the exact signing input and its document until completion.
#[derive(Debug)]
#[must_use = "send signing_input to the holder's signer and complete with finish"]
pub struct PreparedDeviceAuthentication {
    document: IssuerSignedDocument,
    name_spaces: HashMap<String, HashMap<String, ciborium::Value>>,
    name_spaces_bytes: Vec<u8>,
    signature: PreparedSignature,
}

/// Holder signing operation retaining borrowed credential and namespace fields.
///
/// `finish` writes the completed DeviceResponse directly, so these fields never
/// need to become an owned credential model.
#[derive(Debug)]
#[must_use = "send signing_input to the holder's signer and complete with finish"]
pub struct PreparedDeviceAuthenticationRef<'a> {
    document: IssuerSignedDocumentRef<'a>,
    name_spaces: DeviceNameSpacesRef<'a>,
    name_spaces_bytes: &'a [u8],
    signature: PreparedSignature,
}

type DeviceNameSpacesRef<'a> = HashMap<&'a str, HashMap<&'a str, CborValueRef<'a>>>;

#[derive(Debug)]
struct PreparedSignature {
    protected: ProtectedHeader,
    signing_input: Vec<u8>,
    device_key: VerificationKey,
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
    let mso = MsoRef::parse(
        document
            .issuer_signed
            .issuer_auth
            .cose_sign1
            .payload
            .as_deref()
            .ok_or_else(|| MdocError::Mso("missing COSE_Sign1 payload".into()))?,
    )?;
    let (signature, name_spaces) = prepare_signature(
        mso,
        &document.doc_type,
        transcript,
        &device_name_spaces_bytes,
        algorithm,
    )?;
    // The existing owned return contract requests independent decoded fields.
    let name_spaces = name_spaces
        .into_iter()
        .map(|(namespace, elements)| {
            Ok((
                namespace.to_owned(),
                elements
                    .into_iter()
                    .map(|(name, value)| Ok((name.to_owned(), value.to_owned()?)))
                    .collect::<Result<_, MdocError>>()?,
            ))
        })
        .collect::<Result<_, MdocError>>()?;
    Ok(PreparedDeviceAuthentication {
        document,
        name_spaces,
        name_spaces_bytes: device_name_spaces_bytes,
        signature,
    })
}

/// Prepare a holder signature without copying credential or namespace values.
///
/// The caller authenticates issuer trust, credential status and the request
/// before selecting disclosures and passing this borrowed document. Both input
/// buffers must remain alive through `finish`, which returns DeviceResponse
/// bytes. `signing_input` is the one continuous message required by an external
/// signer; no intermediate DeviceAuthentication buffer is constructed.
pub fn prepare_device_authentication_borrowed<'a>(
    document: IssuerSignedDocumentRef<'a>,
    transcript: &SessionTranscript<'_>,
    device_name_spaces_bytes: &'a [u8],
    algorithm: i64,
) -> Result<PreparedDeviceAuthenticationRef<'a>, MdocError> {
    let (signature, name_spaces) = prepare_signature(
        document.issuer_signed.issuer_auth.parsed_mso()?,
        document.doc_type,
        transcript,
        device_name_spaces_bytes,
        algorithm,
    )?;
    Ok(PreparedDeviceAuthenticationRef {
        document,
        name_spaces,
        name_spaces_bytes: device_name_spaces_bytes,
        signature,
    })
}

fn prepare_signature<'a>(
    mso: MsoRef<'_>,
    doc_type: &str,
    transcript: &SessionTranscript<'_>,
    device_name_spaces_bytes: &'a [u8],
    algorithm: i64,
) -> Result<(PreparedSignature, DeviceNameSpacesRef<'a>), MdocError> {
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
    if mso.doc_type != doc_type {
        return Err(MdocError::Mso("document docType differs from MSO".into()));
    }
    let device_key = VerificationKey::from_borrowed(&mso.device_key_info.device_key, algorithm)?;
    let name_spaces = crate::parser::parse_device_namespaces(
        raw::Item::parse(device_name_spaces_bytes)?.embedded()?,
    )
    .map_err(|error| match error {
        MdocError::Parse(message) => MdocError::Issuance(message),
        error => error,
    })?;
    for (namespace, elements) in &name_spaces {
        crate::verifier::check_key_authorizations(
            &mso.device_key_info,
            namespace,
            elements.keys().copied(),
        )?;
    }
    let payload = DeviceAuthentication::new(transcript, doc_type, device_name_spaces_bytes);
    let header = HeaderBuilder::new().algorithm(assigned_algorithm).build();
    let mut encoded_header = Vec::new();
    crate::cose::push_header(&mut encoded_header, &header)?;
    let protected = ProtectedHeader {
        original_data: Some(encoded_header),
        header,
    };
    let signing_input = crate::cose::with_protected_bytes(&protected, |bytes| {
        let framing = crate::cose::AuthenticationStructure::sign1(bytes.len(), payload.len());
        Ok(payload.authentication_parts(framing.prefix(bytes)).concat())
    })?;
    Ok((
        PreparedSignature {
            protected,
            signing_input,
            device_key,
            algorithm,
        },
        name_spaces,
    ))
}

impl PreparedDeviceAuthentication {
    /// Exact COSE Sig_structure bytes to send to the external signer.
    /// ECDSA signers return fixed-width raw `r || s`, not ASN.1 DER.
    pub fn signing_input(&self) -> &[u8] {
        &self.signature.signing_input
    }

    /// Protected COSE algorithm of this signing operation.
    pub fn algorithm(&self) -> i64 {
        self.signature.algorithm
    }

    /// Verify the external signature and attach a detached COSE_Sign1 proof.
    /// A wrong key, altered input, DER-encoded ECDSA value, or invalid signature
    /// cannot produce a successfully completed document.
    pub fn finish(mut self, signature: Vec<u8>) -> Result<IssuerSignedDocument, MdocError> {
        self.signature.verify(&signature)?;
        self.document.device_signed = Some(DeviceSigned {
            device_auth: DeviceAuth::Signature(CoseSign1 {
                protected: self.signature.protected,
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

impl PreparedDeviceAuthenticationRef<'_> {
    /// Exact COSE Sig_structure bytes to send to the external signer.
    /// ECDSA signers return fixed-width raw `r || s`, not ASN.1 DER.
    pub fn signing_input(&self) -> &[u8] {
        &self.signature.signing_input
    }

    pub fn algorithm(&self) -> i64 {
        self.signature.algorithm
    }

    /// Verify an external signature and write the complete DeviceResponse.
    /// Writes borrowed credential fields, device values and the signature into
    /// the output buffer, without constructing an owned credential model.
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>, MdocError> {
        self.signature.verify(signature)?;
        let document = IssuerSignedDocumentRef {
            doc_type: self.document.doc_type,
            issuer_signed: self.document.issuer_signed,
            device_signed: Some(DeviceSignedRef {
                device_auth: DeviceAuthRef::Signature(CoseSign1Ref {
                    protected: self
                        .signature
                        .protected
                        .original_data
                        .as_deref()
                        .expect("preparation retains encoded protected headers"),
                    protected_header: CoseHeaderRef {
                        alg: Some(CoseLabelRef::Int(self.signature.algorithm)),
                        labels: 1 << 1,
                        ..Default::default()
                    },
                    unprotected: CoseHeaderRef::default(),
                    payload: None,
                    signature,
                }),
                name_spaces: self.name_spaces,
                name_spaces_bytes: self.name_spaces_bytes,
            }),
        };
        document.to_device_response_cbor()
    }
}

impl PreparedSignature {
    fn verify(&self, signature: &[u8]) -> Result<(), MdocError> {
        if !self.device_key.verify(&[&self.signing_input], signature)? {
            return Err(MdocError::Signature(
                "external holder signature does not match signing input and device key".into(),
            ));
        }
        Ok(())
    }
}
