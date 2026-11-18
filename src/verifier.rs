//! Issuer and holder authentication over the received mdoc bytes.
//!
//! Applications complete X.509 trust, certificate revocation, credential status
//! and request authorization using the returned authenticated evidence.

use crate::time::Timestamp;
use crate::{MdocError, cbor::raw::Limits, model::*, session::SessionTranscript};
use der::Decode;

/// Verification time and the presentation profile's document count limit.
#[derive(Clone, Debug)]
pub struct VerificationOptions {
    pub now: Timestamp,
    /// HAIP callers set this to 1. Generic bounded ISO responses can allow more.
    pub max_documents: usize,
}

/// Authenticated protocol data awaiting the application's trust and status checks.
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
    /// Leaf-first certificate chain for the application's trust evaluation.
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

/// Authenticated claims and certificate bytes borrowing the received presentation.
#[derive(Debug)]
#[must_use = "complete issuer trust, certificate revocation, status and request policy in the host"]
pub struct PendingTrustDocumentRef<'a> {
    document: IssuerSignedDocumentRef<'a>,
    mso: MsoRef<'a>,
    certificates: Vec<&'a [u8]>,
}

impl<'a> PendingTrustDocumentRef<'a> {
    pub fn document(&self) -> &IssuerSignedDocumentRef<'a> {
        &self.document
    }
    pub fn mso(&self) -> &MsoRef<'a> {
        &self.mso
    }
    /// Leaf-first DER slices into the original presentation.
    pub fn certificates(&self) -> &[&'a [u8]] {
        &self.certificates
    }
    pub fn device_key(&self) -> &CoseKeyRef<'a> {
        &self.mso.device_key_info.device_key
    }
    /// Move the borrowed document and evidence without cloning their indexes.
    pub fn into_parts(self) -> (IssuerSignedDocumentRef<'a>, MsoRef<'a>, Vec<&'a [u8]>) {
        (self.document, self.mso, self.certificates)
    }
    /// Materialize independent storage after authentication succeeds.
    pub fn into_owned(self) -> Result<PendingTrustDocument, MdocError> {
        Ok(PendingTrustDocument {
            document: self.document.into_owned()?,
            mso: self.mso.into_owned()?,
            certificates: self.certificates.into_iter().map(<[u8]>::to_vec).collect(),
        })
    }
}

/// Verify every document and retain owned authenticated data.
///
/// Verification uses [`verify_presentation_borrowed`]; successful results are
/// then copied into independent storage. A failure returns no partial successes.
pub fn verify_presentation(
    encoded: &[u8],
    transcript: &SessionTranscript<'_>,
    options: &VerificationOptions,
) -> Result<Vec<PendingTrustDocument>, MdocError> {
    verify_presentation_borrowed(encoded, transcript, options)?
        .into_iter()
        .map(PendingTrustDocumentRef::into_owned)
        .collect()
}

/// Authenticate every document while borrowing the original encoded values.
///
/// The caller supplies the transcript for its authenticated request context and
/// keeps `encoded` alive while using the result. This presentation API requires
/// DeviceSignature. DeviceMAC is available through the explicitly keyed primitive.
pub fn verify_presentation_borrowed<'a>(
    encoded: &'a [u8],
    transcript: &SessionTranscript<'_>,
    options: &VerificationOptions,
) -> Result<Vec<PendingTrustDocumentRef<'a>>, MdocError> {
    let response = crate::parser::parse_borrowed_with_limits(
        encoded,
        Limits::default(),
        options.max_documents,
    )?;
    if !supports_version(response.version) || response.status != DeviceResponseStatus::Ok {
        return Err(MdocError::Parse(
            "unsupported version or non-success DeviceResponse status".into(),
        ));
    }
    let mut verified = Vec::with_capacity(response.documents.len());
    for document in response.documents {
        let (mso, certificates, certificate_interval) =
            authenticate_issuer(&document.issuer_signed.issuer_auth)?;
        let device = document
            .device_signed
            .as_ref()
            .ok_or_else(|| MdocError::DeviceAuth("missing holder authentication".into()))?;
        let DeviceAuthRef::Signature(signature) = &device.device_auth else {
            return Err(MdocError::DeviceAuth(
                "presentation verification requires DeviceSignature".into(),
            ));
        };
        for (namespace, elements) in &device.name_spaces {
            check_key_authorizations(&mso.device_key_info, namespace, elements.keys().copied())?;
        }
        if signature.payload.is_some() {
            return Err(MdocError::DeviceAuth(
                "deviceSignature must use a detached payload".into(),
            ));
        }
        let payload = crate::session::DeviceAuthentication::new(
            transcript,
            document.doc_type,
            device.name_spaces_bytes,
        );
        let framing =
            crate::cose::AuthenticationStructure::sign1(signature.protected.len(), payload.len());
        let parts = payload.authentication_parts(framing.prefix(signature.protected));
        let is_valid = crate::cose::validate_borrowed_headers(
            &signature.protected_header,
            &signature.unprotected,
        )
        .and_then(|algorithm| {
            crate::cose::verify_cose_signature_borrowed(
                &parts,
                signature.signature,
                &mso.device_key_info.device_key,
                algorithm,
            )
        })
        .map_err(|error| MdocError::DeviceAuth(error.to_string()))?;
        if !is_valid {
            return Err(MdocError::DeviceAuth(
                "holder signature does not match session".into(),
            ));
        }
        validate_claims(&document, &mso, options.now, certificate_interval)?;
        verified.push(PendingTrustDocumentRef {
            document,
            mso,
            certificates,
        });
    }
    Ok(verified)
}

/// Issuer-only authentication for credentials before presentation.
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

/// Issuer-authenticated credential borrowing its original wire representation.
#[derive(Debug)]
#[must_use = "issuer authentication does not establish holder binding or issuer trust"]
pub struct PendingIssuerTrustDocumentRef<'a> {
    document: IssuerSignedDocumentRef<'a>,
    mso: MsoRef<'a>,
    certificates: Vec<&'a [u8]>,
}

impl<'a> PendingIssuerTrustDocumentRef<'a> {
    pub fn document(&self) -> &IssuerSignedDocumentRef<'a> {
        &self.document
    }
    pub fn mso(&self) -> &MsoRef<'a> {
        &self.mso
    }
    pub fn certificates(&self) -> &[&'a [u8]] {
        &self.certificates
    }
    /// Move the borrowed document and evidence without cloning their indexes.
    pub fn into_parts(self) -> (IssuerSignedDocumentRef<'a>, MsoRef<'a>, Vec<&'a [u8]>) {
        (self.document, self.mso, self.certificates)
    }
    pub fn into_owned(self) -> Result<PendingIssuerTrustDocument, MdocError> {
        Ok(PendingIssuerTrustDocument {
            document: self.document.into_owned()?,
            mso: self.mso.into_owned()?,
            certificates: self.certificates.into_iter().map(<[u8]>::to_vec).collect(),
        })
    }
}

/// Authenticate an OpenID4VCI IssuerSigned wire object and retain owned data.
pub fn verify_issued(
    encoded: &[u8],
    expected_doc_type: &str,
    now: Timestamp,
) -> Result<PendingIssuerTrustDocument, MdocError> {
    verify_issued_borrowed(encoded, expected_doc_type, now)?.into_owned()
}

/// Authenticate an OpenID4VCI IssuerSigned object while borrowing its wire bytes.
pub fn verify_issued_borrowed<'a>(
    encoded: &'a [u8],
    expected_doc_type: &str,
    now: Timestamp,
) -> Result<PendingIssuerTrustDocumentRef<'a>, MdocError> {
    let issuer_signed = crate::parser::parse_issued_borrowed(encoded)?;
    let (mso, certificates, certificate_interval) =
        authenticate_issuer(&issuer_signed.issuer_auth)?;
    if mso.doc_type != expected_doc_type {
        return Err(MdocError::Mso(
            "docType differs from authenticated MSO".into(),
        ));
    }
    let document = IssuerSignedDocumentRef {
        doc_type: mso.doc_type,
        issuer_signed,
        device_signed: None,
    };
    crate::cose::validate_borrowed_device_public_key(&mso.device_key_info.device_key)?;
    validate_claims(&document, &mso, now, certificate_interval)?;
    Ok(PendingIssuerTrustDocumentRef {
        document,
        mso,
        certificates,
    })
}

type CertificateInterval = (Timestamp, Timestamp);
type IssuerEvidence<'a> = (MsoRef<'a>, Vec<&'a [u8]>, CertificateInterval);

pub(crate) fn certificate_interval(
    leaf: &x509_cert::Certificate,
) -> Result<CertificateInterval, MdocError> {
    let validity = leaf.tbs_certificate().validity();
    let convert = |time: x509_cert::time::Time| {
        let seconds = i64::try_from(time.to_unix_duration().as_secs())
            .map_err(|_| MdocError::Certificate("certificate time out of range".into()))?;
        Timestamp::from_unix_seconds(seconds)
            .map_err(|_| MdocError::Certificate("certificate time out of range".into()))
    };
    Ok((convert(validity.not_before)?, convert(validity.not_after)?))
}

fn authenticate_issuer<'a>(auth: &IssuerAuthRef<'a>) -> Result<IssuerEvidence<'a>, MdocError> {
    let sign1 = &auth.cose_sign1;
    let algorithm =
        crate::cose::validate_borrowed_headers(&sign1.protected_header, &sign1.unprotected)?;
    let payload = sign1.payload.ok_or_else(|| {
        MdocError::Signature("issuerAuth requires an embedded MSO payload".into())
    })?;
    let certificates = auth.certificate_chain_der()?;
    let leaf = x509_cert::Certificate::from_der(certificates[0])
        .map_err(|error| MdocError::Certificate(error.to_string()))?;
    let framing = crate::cose::AuthenticationStructure::sign1(sign1.protected.len(), payload.len());
    if !crate::cose::verify_spki_signature(
        &framing.parts(sign1.protected, payload),
        sign1.signature,
        leaf.tbs_certificate().subject_public_key_info(),
        algorithm,
    )? {
        return Err(MdocError::Signature("issuerAuth signature mismatch".into()));
    }
    let mso = auth.parsed_mso()?;
    let interval = certificate_interval(&leaf)?;
    Ok((mso, certificates, interval))
}

fn validate_claims(
    document: &IssuerSignedDocumentRef<'_>,
    mso: &MsoRef<'_>,
    now: Timestamp,
    certificate_interval: CertificateInterval,
) -> Result<(), MdocError> {
    if mso.doc_type != document.doc_type {
        return Err(MdocError::Mso(
            "docType differs from authenticated MSO".into(),
        ));
    }
    // Positive RFU keyInfo labels are retained without authorization semantics.
    let mut unsupported_key_info = false;
    if let Some(info) = mso.device_key_info.key_info {
        for entry in info.map()? {
            if entry?.0.as_integer().is_none_or(|label| label <= 0) {
                unsupported_key_info = true;
            }
        }
    }
    if !mso.additional_fields.is_empty()
        || !mso.device_key_info.additional_fields.is_empty()
        || unsupported_key_info
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
    crate::disclosure::verify_borrowed_disclosure(&document.issuer_signed.name_spaces, mso)?;
    Ok(())
}

/// Check one namespace's identifiers against authenticated key authorizations.
pub(crate) fn check_key_authorizations<'a>(
    key_info: &DeviceKeyInfoRef<'_>,
    namespace: &str,
    elements: impl Iterator<Item = &'a str>,
) -> Result<(), MdocError> {
    let permitted = key_info
        .key_authorizations
        .as_ref()
        .ok_or_else(|| MdocError::DeviceAuth("device data has no keyAuthorizations".into()))?;
    if permitted
        .name_spaces
        .as_ref()
        .is_some_and(|names| names.contains(&namespace))
    {
        return Ok(());
    }
    let permitted_elements = permitted
        .data_elements
        .as_ref()
        .and_then(|map| map.get(namespace));
    for element in elements {
        if !permitted_elements.is_some_and(|names| names.contains(&element)) {
            return Err(MdocError::DeviceAuth(
                "device data exceeds keyAuthorizations".into(),
            ));
        }
    }
    Ok(())
}
