//! Protocol authentication with an explicit, unfinished application trust decision.
//!
//! A successful result authenticates the signed bytes and holder binding. It is
//! deliberately named `PendingTrustDocument`: X.509 path policy, certificate
//! revocation, credential status and request authorization remain with the host.
//! There is no `is_valid` flag or switch that can mark a skipped check as passed.

use crate::time::Timestamp;
use crate::{MdocError, cbor::raw::Limits, model::*, session::SessionTranscript};
use der::Decode;
use std::collections::HashMap;

/// Verification time and the presentation profile's document count limit.
#[derive(Clone, Debug)]
pub struct VerificationOptions {
    pub now: Timestamp,
    /// HAIP callers set this to 1. Generic bounded ISO responses can allow more.
    pub max_documents: usize,
}

/// Authenticated protocol data which MUST NOT yet be treated as a trusted credential.
#[derive(Debug)]
#[must_use = "complete issuer trust, certificate revocation, status and request policy in the host"]
pub struct PendingTrustDocument {
    document: IssuerSignedDocument,
    mso: Mso,
    certificates: Vec<Vec<u8>>,
}

impl PendingTrustDocument {
    pub fn document(&self) -> &IssuerSignedDocument {
        &self.document
    }
    /// This MSO came from the successfully verified issuerAuth payload.
    pub fn mso(&self) -> &Mso {
        &self.mso
    }
    /// Leaf first. These certificates have NOT been anchored to a trust store.
    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }
    pub fn device_key(&self) -> &coset::CoseKey {
        &self.mso.device_key_info.device_key
    }
    pub fn into_parts(self) -> (IssuerSignedDocument, Mso, Vec<Vec<u8>>) {
        (self.document, self.mso, self.certificates)
    }
}

/// Verify every document atomically. A failure returns no partial successes.
///
/// The caller must supply the transcript for its authenticated request context.
/// A structurally valid raw transcript alone cannot prove request freshness.
/// This server presentation profile requires DeviceSignature. DeviceMAC remains
/// available as an explicit primitive in `device_auth`, with external key setup.
pub fn verify_presentation(
    encoded: &[u8],
    transcript: &SessionTranscript<'_>,
    options: &VerificationOptions,
) -> Result<Vec<PendingTrustDocument>, MdocError> {
    let response =
        crate::parser::parse_with_limits(encoded, Limits::default(), options.max_documents)?;
    if response.version != "1.0" || response.status != MDocStatus::Ok {
        return Err(MdocError::Parse(
            "unsupported version or non-success DeviceResponse status".into(),
        ));
    }
    let mut verified = Vec::with_capacity(response.documents.len());
    for document in response.documents {
        let (mso, certificates, certificate_interval) = authenticate_issuer(&document)?;
        let device = document
            .device_signed
            .as_ref()
            .ok_or_else(|| MdocError::DeviceAuth("missing holder authentication".into()))?;
        if !matches!(device.device_auth, DeviceAuth::Signature(_)) {
            return Err(MdocError::DeviceAuth(
                "DeviceMAC is not enabled by the server signature profile".into(),
            ));
        }
        check_key_authorizations(&mso.device_key_info, &device.name_spaces)?;
        let payload = crate::session::build_device_authentication_validated(
            transcript,
            &document.doc_type,
            &device.name_spaces_bytes,
        );
        let result = crate::device_auth::verify_device_auth(
            &device.device_auth,
            &payload,
            &mso.device_key_info.device_key,
            None,
        )
        .map_err(|error| MdocError::DeviceAuth(error.to_string()))?;
        if !result.is_valid {
            return Err(MdocError::DeviceAuth(
                "holder signature does not match session".into(),
            ));
        }
        validate_claims(&document, &mso, options.now, certificate_interval)?;
        verified.push(PendingTrustDocument {
            document,
            mso,
            certificates,
        });
    }
    Ok(verified)
}

/// Issuer-only authentication for credentials before presentation. The distinct
/// result type cannot stand in for a holder-authenticated presentation.
#[derive(Debug)]
#[must_use = "issuer authentication does not establish holder binding or issuer trust"]
pub struct PendingIssuerTrustDocument {
    document: IssuerSignedDocument,
    mso: Mso,
    certificates: Vec<Vec<u8>>,
}

impl PendingIssuerTrustDocument {
    pub fn document(&self) -> &IssuerSignedDocument {
        &self.document
    }
    pub fn mso(&self) -> &Mso {
        &self.mso
    }
    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }
}

/// Authenticate the OpenID4VCI IssuerSigned wire object for an expected docType.
/// Parse/verify from bytes so public decoded model fields cannot be substituted.
pub fn verify_issued(
    encoded: &[u8],
    expected_doc_type: &str,
    now: Timestamp,
) -> Result<PendingIssuerTrustDocument, MdocError> {
    let document = IssuerSignedDocument {
        doc_type: expected_doc_type.to_owned(),
        issuer_signed: crate::parser::parse_issued(encoded)?,
        device_signed: None,
    };
    let (mso, certificates, certificate_interval) = authenticate_issuer(&document)?;
    crate::cose::key::validate_device_public_key(&mso.device_key_info.device_key)?;
    validate_claims(&document, &mso, now, certificate_interval)?;
    Ok(PendingIssuerTrustDocument {
        document,
        mso,
        certificates,
    })
}

type CertificateInterval = (Timestamp, Timestamp);
type IssuerEvidence = (Mso, Vec<Vec<u8>>, CertificateInterval);

pub(crate) fn certificate_interval(
    leaf: &x509_cert::Certificate,
) -> Result<CertificateInterval, MdocError> {
    let validity = &leaf.tbs_certificate.validity;
    let convert = |time: x509_cert::time::Time| {
        let seconds = i64::try_from(time.to_unix_duration().as_secs())
            .map_err(|_| MdocError::Certificate("certificate time out of range".into()))?;
        Timestamp::from_unix_seconds(seconds)
            .map_err(|_| MdocError::Certificate("certificate time out of range".into()))
    };
    Ok((convert(validity.not_before)?, convert(validity.not_after)?))
}

fn authenticate_issuer(document: &IssuerSignedDocument) -> Result<IssuerEvidence, MdocError> {
    let auth = &document.issuer_signed.issuer_auth;
    let sign1 = &auth.cose_sign1;
    let algorithm = crate::cose::validate_headers(&sign1.protected, &sign1.unprotected)?;
    if sign1.payload.is_none() {
        return Err(MdocError::Signature(
            "issuerAuth requires an embedded MSO payload".into(),
        ));
    }
    let certificates = auth.certificate_chain_der()?;
    let leaf = x509_cert::Certificate::from_der(&certificates[0])
        .map_err(|error| MdocError::Certificate(error.to_string()))?;
    let issuer_key =
        crate::cose::key::cose_key_from_spki(&leaf.tbs_certificate.subject_public_key_info)?;
    if !crate::cose::verify_cose_signature(
        &sign1.tbs_data(&[]),
        &sign1.signature,
        &issuer_key,
        algorithm,
    )? {
        return Err(MdocError::Signature("issuerAuth signature mismatch".into()));
    }
    // Decode exactly once, and only expose this MSO after signature success.
    let mso = auth.mso()?;
    let interval = certificate_interval(&leaf)?;
    Ok((mso, certificates, interval))
}

fn validate_claims(
    document: &IssuerSignedDocument,
    mso: &Mso,
    now: Timestamp,
    certificate_interval: CertificateInterval,
) -> Result<(), MdocError> {
    if mso.doc_type != document.doc_type {
        return Err(MdocError::Mso(
            "docType differs from authenticated MSO".into(),
        ));
    }
    if !mso.additional_fields.is_empty()
        || !mso.device_key_info.additional_fields.is_empty()
        || mso.device_key_info.key_info.is_some()
    {
        return Err(MdocError::Mso(
            "unsupported MSO or DeviceKeyInfo extension".into(),
        ));
    }
    let validity = &mso.validity_info;
    if now < validity.valid_from || now > validity.valid_until {
        return Err(MdocError::Validity(
            "credential is not valid at verification time".into(),
        ));
    }
    if validity.signed < certificate_interval.0 || validity.signed > certificate_interval.1 {
        return Err(MdocError::Validity(
            "MSO signed time is outside signer certificate validity".into(),
        ));
    }
    crate::disclosure::verify_disclosure(&document.issuer_signed.name_spaces, mso)?;
    Ok(())
}

pub(crate) fn check_key_authorizations(
    key_info: &DeviceKeyInfo,
    name_spaces: &HashMap<String, HashMap<String, ciborium::Value>>,
) -> Result<(), MdocError> {
    for (namespace, elements) in name_spaces {
        let permitted = key_info
            .key_authorizations
            .as_ref()
            .ok_or_else(|| MdocError::DeviceAuth("device data has no keyAuthorizations".into()))?;
        if permitted
            .name_spaces
            .as_ref()
            .is_some_and(|namespaces| namespaces.contains(namespace))
        {
            continue;
        }
        for element in elements.keys() {
            if !permitted
                .data_elements
                .as_ref()
                .and_then(|map| map.get(namespace))
                .is_some_and(|names| names.contains(element))
            {
                return Err(MdocError::DeviceAuth(
                    "device data exceeds keyAuthorizations".into(),
                ));
            }
        }
    }
    Ok(())
}
