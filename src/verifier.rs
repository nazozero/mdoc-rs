//! Issuer and holder authentication over the received mdoc bytes.
//!
//! Applications complete X.509 trust, certificate revocation, credential status
//! and request authorization using the returned authenticated evidence.

use crate::time::Timestamp;
use crate::{MdocError, cbor::raw::Limits, model::*, session::SessionTranscript};
#[cfg(not(feature = "certificate-profile"))]
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
    #[cfg(feature = "certificate-profile")]
    leaf_certificate: x509_parser::certificate::X509Certificate<'a>,
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
    /// The borrowed leaf whose Document Signer profile and MSO signature passed.
    /// Certificate path, revocation and trust are still pending.
    #[cfg(feature = "certificate-profile")]
    pub fn leaf_certificate(&self) -> &x509_parser::certificate::X509Certificate<'a> {
        &self.leaf_certificate
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
    #[cfg(feature = "certificate-profile")]
    {
        verify_presentation_borrowed_inner::<false>(
            encoded,
            transcript,
            options,
            None,
            |_, _, _| unreachable!("signature-only policy"),
        )
    }
    #[cfg(not(feature = "certificate-profile"))]
    {
        verify_presentation_borrowed_inner::<false>(encoded, transcript, options, |_, _, _| {
            unreachable!("signature-only policy")
        })
    }
}

/// Reuse static DS profile/key validation only if the received leaf is byte-for-byte
/// identical to the prevalidated signer. Issuer signatures, holder proofs and
/// current certificate trust/revocation are still checked every time.
#[cfg(feature = "certificate-profile")]
pub fn verify_presentation_borrowed_with_signer<'a>(
    encoded: &'a [u8],
    transcript: &SessionTranscript<'_>,
    options: &VerificationOptions,
    signer: Option<&crate::certificate::PreparedDocumentSigner>,
) -> Result<Vec<PendingTrustDocumentRef<'a>>, MdocError> {
    verify_presentation_borrowed_inner::<false>(encoded, transcript, options, signer, |_, _, _| {
        unreachable!("signature-only policy")
    })
}

#[cfg(feature = "reader-session")]
pub(crate) fn verify_presentation_borrowed_in_session<
    'a,
    K: crate::session::reader::ReaderKeyAgreement,
>(
    response: DeviceResponseRef<'a>,
    transcript: &SessionTranscript<'_>,
    options: &VerificationOptions,
    reader_key: &mut K,
    reader_curve: i64,
    salt: &[u8; 32],
    #[cfg(feature = "certificate-profile")] signer: Option<
        &crate::certificate::PreparedDocumentSigner,
    >,
) -> Result<Vec<PendingTrustDocumentRef<'a>>, MdocError> {
    verify_parsed_presentation::<true>(
        response,
        transcript,
        options,
        #[cfg(feature = "certificate-profile")]
        signer,
        |device_key, mac, payload| {
            crate::session::reader::verify_device_mac(
                reader_key,
                reader_curve,
                device_key,
                mac,
                salt,
                payload,
            )
        },
    )
}

fn verify_presentation_borrowed_inner<'a, const ALLOW_MAC: bool>(
    encoded: &'a [u8],
    transcript: &SessionTranscript<'_>,
    options: &VerificationOptions,
    #[cfg(feature = "certificate-profile")] signer: Option<
        &crate::certificate::PreparedDocumentSigner,
    >,
    verify_mac: impl FnMut(
        &CoseKeyRef<'_>,
        &CoseMac0Ref<'_>,
        &crate::session::DeviceAuthentication<'_>,
    ) -> Result<(), MdocError>,
) -> Result<Vec<PendingTrustDocumentRef<'a>>, MdocError> {
    let response = crate::parser::parse_borrowed_with_limits(
        encoded,
        Limits::default(),
        options.max_documents,
    )?;
    verify_parsed_presentation::<ALLOW_MAC>(
        response,
        transcript,
        options,
        #[cfg(feature = "certificate-profile")]
        signer,
        verify_mac,
    )
}

fn verify_parsed_presentation<'a, const ALLOW_MAC: bool>(
    response: DeviceResponseRef<'a>,
    transcript: &SessionTranscript<'_>,
    options: &VerificationOptions,
    #[cfg(feature = "certificate-profile")] signer: Option<
        &crate::certificate::PreparedDocumentSigner,
    >,
    mut verify_mac: impl FnMut(
        &CoseKeyRef<'_>,
        &CoseMac0Ref<'_>,
        &crate::session::DeviceAuthentication<'_>,
    ) -> Result<(), MdocError>,
) -> Result<Vec<PendingTrustDocumentRef<'a>>, MdocError> {
    if !supports_version(response.version) || response.status != DeviceResponseStatus::Ok {
        return Err(MdocError::Parse(
            "unsupported version or non-success DeviceResponse status".into(),
        ));
    }
    let mut verified = Vec::with_capacity(response.documents.len());
    for document in response.documents {
        let device = document
            .device_signed
            .as_ref()
            .ok_or_else(|| MdocError::DeviceAuth("missing holder authentication".into()))?;
        if !ALLOW_MAC && matches!(device.device_auth, DeviceAuthRef::Mac(_)) {
            return Err(MdocError::DeviceAuth(
                "presentation verification requires DeviceSignature".into(),
            ));
        }
        let IssuerEvidence {
            mso,
            certificates,
            interval: certificate_interval,
            #[cfg(feature = "certificate-profile")]
            leaf_certificate,
        } = authenticate_issuer(
            &document.issuer_signed.issuer_auth,
            #[cfg(feature = "certificate-profile")]
            signer,
        )?;
        for (namespace, elements) in &device.name_spaces {
            for name in elements.keys() {
                crate::mdl::check_device_element(document.doc_type, namespace, name)?;
            }
            check_key_authorizations(&mso.device_key_info, namespace, elements.keys().copied())?;
        }
        let payload = crate::session::DeviceAuthentication::new(
            transcript,
            document.doc_type,
            device.name_spaces_bytes,
        );
        match &device.device_auth {
            DeviceAuthRef::Signature(signature) => {
                verify_holder_signature(signature, &mso.device_key_info.device_key, &payload)?
            }
            DeviceAuthRef::Mac(mac) => verify_mac(&mso.device_key_info.device_key, mac, &payload)?,
        }
        validate_claims(&document, &mso, options.now, certificate_interval)?;
        #[cfg(feature = "certificate-profile")]
        crate::certificate::check_mdl_document_attributes(&document, &leaf_certificate)?;
        verified.push(PendingTrustDocumentRef {
            document,
            mso,
            certificates,
            #[cfg(feature = "certificate-profile")]
            leaf_certificate,
        });
    }
    Ok(verified)
}

fn verify_holder_signature(
    signature: &CoseSign1Ref<'_>,
    device_key: &CoseKeyRef<'_>,
    payload: &crate::session::DeviceAuthentication<'_>,
) -> Result<(), MdocError> {
    if signature.payload.is_some() {
        return Err(MdocError::DeviceAuth(
            "deviceSignature must use a detached payload".into(),
        ));
    }
    let framing =
        crate::cose::AuthenticationStructure::sign1(signature.protected.len(), payload.len());
    let parts = payload.authentication_parts(framing.prefix(signature.protected));
    let is_valid =
        crate::cose::validate_borrowed_headers(&signature.protected_header, &signature.unprotected)
            .and_then(|algorithm| {
                crate::cose::verify_cose_signature_borrowed(
                    &parts,
                    signature.signature,
                    device_key,
                    algorithm,
                )
            })
            .map_err(|error| MdocError::DeviceAuth(error.to_string()))?;
    if !is_valid {
        return Err(MdocError::DeviceAuth(
            "holder signature does not match session".into(),
        ));
    }
    Ok(())
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
    #[cfg(feature = "certificate-profile")]
    leaf_certificate: x509_parser::certificate::X509Certificate<'a>,
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
    /// The borrowed leaf whose Document Signer profile and MSO signature passed.
    /// Certificate path, revocation and trust are still pending.
    #[cfg(feature = "certificate-profile")]
    pub fn leaf_certificate(&self) -> &x509_parser::certificate::X509Certificate<'a> {
        &self.leaf_certificate
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
    let IssuerEvidence {
        mso,
        certificates,
        interval: certificate_interval,
        #[cfg(feature = "certificate-profile")]
        leaf_certificate,
    } = authenticate_issuer(
        &issuer_signed.issuer_auth,
        #[cfg(feature = "certificate-profile")]
        None,
    )?;
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
    #[cfg(feature = "certificate-profile")]
    crate::certificate::check_mdl_document_attributes(&document, &leaf_certificate)?;
    Ok(PendingIssuerTrustDocumentRef {
        document,
        mso,
        certificates,
        #[cfg(feature = "certificate-profile")]
        leaf_certificate,
    })
}

type CertificateInterval = (Timestamp, Timestamp);
struct IssuerEvidence<'a> {
    mso: MsoRef<'a>,
    certificates: Vec<&'a [u8]>,
    interval: CertificateInterval,
    #[cfg(feature = "certificate-profile")]
    leaf_certificate: x509_parser::certificate::X509Certificate<'a>,
}

#[cfg(not(feature = "certificate-profile"))]

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

fn authenticate_issuer<'a>(
    auth: &IssuerAuthRef<'a>,
    #[cfg(feature = "certificate-profile")] signer: Option<
        &crate::certificate::PreparedDocumentSigner,
    >,
) -> Result<IssuerEvidence<'a>, MdocError> {
    let sign1 = &auth.cose_sign1;
    let algorithm =
        crate::cose::validate_borrowed_headers(&sign1.protected_header, &sign1.unprotected)?;
    let payload = sign1.payload.ok_or_else(|| {
        MdocError::Signature("issuerAuth requires an embedded MSO payload".into())
    })?;
    let certificates = auth.certificate_chain_der()?;
    #[cfg(not(feature = "certificate-profile"))]
    let leaf = x509_cert::Certificate::from_der(certificates[0])
        .map_err(|error| MdocError::Certificate(error.to_string()))?;
    #[cfg(feature = "certificate-profile")]
    let reused = signer.filter(|signer| signer.matches(certificates[0], algorithm));
    #[cfg(feature = "certificate-profile")]
    let leaf = if reused.is_some() {
        let (rest, leaf) = x509_parser::parse_x509_certificate(certificates[0])
            .map_err(|error| MdocError::Certificate(error.to_string()))?;
        if !rest.is_empty() {
            return Err(MdocError::Certificate("trailing certificate bytes".into()));
        }
        leaf
    } else {
        crate::certificate::parse_document_signer(certificates[0])?
    };
    #[cfg(not(feature = "certificate-profile"))]
    let key = crate::cose::VerificationKey::from_spki(
        leaf.tbs_certificate().subject_public_key_info(),
        algorithm,
    )?;
    #[cfg(feature = "certificate-profile")]
    let parsed_key;
    #[cfg(feature = "certificate-profile")]
    let key = if let Some(signer) = reused {
        &signer.key
    } else {
        parsed_key = crate::cose::VerificationKey::from_spki_ref(
            crate::certificate::spki(&leaf)?,
            algorithm,
        )?;
        &parsed_key
    };
    let framing = crate::cose::AuthenticationStructure::sign1(sign1.protected.len(), payload.len());
    if !key.verify(&framing.parts(sign1.protected, payload), sign1.signature)? {
        return Err(MdocError::Signature("issuerAuth signature mismatch".into()));
    }

    let mso = auth.mso()?;
    #[cfg(not(feature = "certificate-profile"))]
    let interval = certificate_interval(&leaf)?;
    #[cfg(feature = "certificate-profile")]
    let interval = crate::certificate::interval(&leaf)?;
    Ok(IssuerEvidence {
        mso,
        certificates,
        interval,
        #[cfg(feature = "certificate-profile")]
        leaf_certificate: leaf,
    })
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
    if document.doc_type == crate::mdl::DOC_TYPE
        && let Some(items) = document
            .issuer_signed
            .name_spaces
            .get(crate::mdl::NAMESPACE)
    {
        let (mut country, mut jurisdiction) = (None, None);
        for item in items {
            if item.element_identifier == "issuing_country" {
                country = item.element_value.as_text();
            }
            if item.element_identifier == "issuing_jurisdiction" {
                jurisdiction = item.element_value.as_text();
            }
            crate::mdl::validate_element(
                item.element_identifier,
                item.element_value,
                validity.valid_from,
            )?;
        }
        crate::mdl::check_jurisdiction(country, jurisdiction)?;
    }
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
