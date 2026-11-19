//! ISO/IEC 18013-5:2021 device-retrieval requests and response envelopes.
//!
//! Requests retain their original `ItemsRequestBytes`. Reader authentication
//! uses an external signer. Reader identity, certificate trust and retention
//! policy belong to the host. Response envelopes expose untrusted protocol
//! errors; credential admission continues through the presentation verifier.

use der::{Decode, referenced::OwnedToRef};

use crate::{
    MdocError,
    cbor::raw::{self, Item, Limits, push_bytes, push_head, push_text},
    cose::VerificationKey,
    model::{CborValueRef, types::supports_version},
    session::SessionTranscript,
};

fn error(message: &str) -> MdocError {
    MdocError::ReaderAuth(message.into())
}

/// Checked, immutable `#6.24(bstr .cbor ItemsRequest)` from §8.3.2.1.2.1.
/// Values and map order remain in the caller's buffer.
#[derive(Clone, Copy, Debug)]
pub struct ItemsRequest<'a> {
    encoded: &'a [u8],
    doc_type: &'a str,
    age_requests: usize,
}

impl<'a> ItemsRequest<'a> {
    pub fn from_bytes(encoded: &'a [u8]) -> Result<Self, MdocError> {
        let request = Item::parse(encoded)?.embedded()?;
        let mut doc_type = None;
        let mut namespaces = false;
        let mut age_requests = 0;
        for entry in request.map()? {
            let (key, value) = entry?;
            match key.text()? {
                "docType" => doc_type = Some(nonempty_text(value)?),
                "nameSpaces" => {
                    let map = value.map()?;
                    if map.len() == 0 {
                        return Err(error("request nameSpaces must not be empty"));
                    }
                    for entry in map {
                        let (name, elements) = entry?;
                        let namespace = nonempty_text(name)?;
                        let elements = elements.map()?;
                        if elements.len() == 0 {
                            return Err(error("requested data elements must not be empty"));
                        }
                        for entry in elements {
                            let (name, retain) = entry?;
                            let name = nonempty_text(name)?;
                            if namespace == "org.iso.18013.5.1"
                                && name.strip_prefix("age_over_").is_some_and(|age| {
                                    age.len() == 2 && age.bytes().all(|byte| byte.is_ascii_digit())
                                })
                            {
                                age_requests += 1;
                            }
                            if !matches!(retain.bytes(), [0xf4] | [0xf5]) {
                                return Err(error("intentToRetain must be a boolean"));
                            }
                        }
                    }
                    namespaces = true;
                }
                "requestInfo" => {
                    for entry in value.map()? {
                        entry?.0.text()?;
                    }
                }
                _ => return Err(error("unsupported ItemsRequest field")),
            }
        }
        if !namespaces {
            return Err(error("missing request nameSpaces"));
        }
        let doc_type = doc_type.ok_or_else(|| error("missing request docType"))?;
        if doc_type != "org.iso.18013.5.1.mDL" {
            age_requests = 0;
        }
        if age_requests > 2 {
            return Err(error("mDL retrieval permits at most two age attestations"));
        }
        Ok(Self {
            encoded,
            doc_type,
            age_requests,
        })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.encoded
    }

    pub fn doc_type(&self) -> &'a str {
        self.doc_type
    }

    /// Reader authentication is optional. Retention remains a host obligation
    /// for every requested element, including derived data and signatures.
    pub fn unsigned(self) -> DocumentRequest<'a> {
        DocumentRequest {
            items: self,
            authentication: None,
        }
    }
}

fn nonempty_text(item: Item<'_>) -> Result<&str, MdocError> {
    let text = item.text()?;
    if text.is_empty() {
        return Err(error("empty document, namespace or element identifier"));
    }
    Ok(text)
}

/// One request whose optional reader proof can only be attached by `finish`.
#[derive(Debug)]
pub struct DocumentRequest<'a> {
    items: ItemsRequest<'a>,
    authentication: Option<Vec<u8>>,
}

impl<'a> DocumentRequest<'a> {
    pub fn items(&self) -> ItemsRequest<'a> {
        self.items
    }

    /// Untagged, detached COSE_Sign1, when reader authentication was selected.
    pub fn reader_authentication(&self) -> Option<&[u8]> {
        self.authentication.as_deref()
    }
}

/// A reader proof bound to an immutable request, transcript and certificate key.
#[derive(Debug)]
#[must_use = "sign signing_input with the reader key and complete with finish"]
pub struct PreparedReaderAuthentication<'a> {
    items: ItemsRequest<'a>,
    certificates: &'a [&'a [u8]],
    key: VerificationKey,
    algorithm: i64,
    protected: Vec<u8>,
    signing_input: Vec<u8>,
}

/// Prepare §9.1.4.4 without importing a private key.
///
/// The host selects and authorizes the reader identity and certificate chain.
/// This function checks DER and the leaf's signature algorithm/key binding;
/// it does not apply the Document Signer certificate profile to reader keys.
pub fn prepare_reader_authentication<'a>(
    items: ItemsRequest<'a>,
    transcript: &SessionTranscript<'_>,
    certificates: &'a [&'a [u8]],
    algorithm: i64,
) -> Result<PreparedReaderAuthentication<'a>, MdocError> {
    let leaf = certificates
        .first()
        .ok_or_else(|| error("reader x5chain must not be empty"))?;
    let mut certificate_bytes = 0usize;
    for certificate in certificates {
        certificate_bytes = certificate_bytes
            .checked_add(certificate.len())
            .filter(|length| *length <= Limits::default().max_bytes)
            .ok_or_else(|| error("reader certificate chain exceeds byte limit"))?;
        if certificate.is_empty() {
            return Err(error("reader x5chain contains an empty certificate"));
        }
    }
    // Parse each configured certificate once at preparation, not per fragment.
    let certificate = x509_cert::Certificate::from_der(leaf)
        .map_err(|_| error("invalid reader certificate DER"))?;
    let key = VerificationKey::from_spki_ref(
        certificate
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref(),
        algorithm,
    )?;
    for certificate in &certificates[1..] {
        x509_cert::Certificate::from_der(certificate)
            .map_err(|_| error("invalid reader certificate DER"))?;
    }
    let mut protected = vec![0xa1, 0x01];
    // Key construction above rejects unsupported or mismatched algorithms.
    push_head(&mut protected, 1, (-1 - algorithm) as u64);
    const READER_AUTH: &[u8] = b"\x83\x74ReaderAuthentication";
    let inner_len = READER_AUTH.len() + transcript.as_bytes().len() + items.as_bytes().len();
    let (tagged_head, head_len) = raw::cbor_head(2, inner_len as u64);
    let payload_len = 2 + head_len + inner_len;
    let framing = crate::cose::AuthenticationStructure::sign1(protected.len(), payload_len);
    let prefix = framing.prefix(&protected);
    let mut signing_input =
        Vec::with_capacity(prefix.iter().map(|part| part.len()).sum::<usize>() + payload_len);
    for part in prefix {
        signing_input.extend_from_slice(part);
    }
    signing_input.extend_from_slice(&[0xd8, 0x18]);
    signing_input.extend_from_slice(&tagged_head[..head_len]);
    signing_input.extend_from_slice(READER_AUTH);
    signing_input.extend_from_slice(transcript.as_bytes());
    signing_input.extend_from_slice(items.as_bytes());
    Ok(PreparedReaderAuthentication {
        items,
        certificates,
        key,
        algorithm,
        protected,
        signing_input,
    })
}

impl<'a> PreparedReaderAuthentication<'a> {
    /// Complete COSE Sig_structure. ECDSA completion requires raw fixed-width r||s.
    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    pub fn algorithm(&self) -> i64 {
        self.algorithm
    }

    pub fn finish(self, signature: &[u8]) -> Result<DocumentRequest<'a>, MdocError> {
        if !self.key.verify(&[&self.signing_input], signature)? {
            return Err(error("external reader signature did not verify"));
        }
        let mut authentication = vec![0x84];
        push_bytes(&mut authentication, &self.protected);
        authentication.extend_from_slice(&[0xa1, 0x18, 0x21]);
        if self.certificates.len() == 1 {
            push_bytes(&mut authentication, self.certificates[0]);
        } else {
            push_head(&mut authentication, 4, self.certificates.len() as u64);
            for certificate in self.certificates {
                push_bytes(&mut authentication, certificate);
            }
        }
        authentication.push(0xf6);
        push_bytes(&mut authentication, signature);
        Ok(DocumentRequest {
            items: self.items,
            authentication: Some(authentication),
        })
    }
}

/// A validated version 1.0 request ready for the reader session's encryption.
#[derive(Debug)]
pub struct DeviceRequest {
    encoded: Vec<u8>,
    age_requests: usize,
}

impl DeviceRequest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.encoded
    }
    /// The session enforces the two-attestation limit across all its requests.
    pub fn age_requests(&self) -> usize {
        self.age_requests
    }
}

/// Encode a version 1.0 DeviceRequest while preserving each ItemsRequestBytes.
pub fn encode_device_request(
    documents: &[DocumentRequest<'_>],
) -> Result<DeviceRequest, MdocError> {
    let limits = Limits::default();
    if documents.is_empty() || documents.len() > limits.max_collection_items {
        return Err(error(
            "DeviceRequest requires a bounded nonempty docRequests array",
        ));
    }
    let age_requests: usize = documents
        .iter()
        .map(|document| document.items.age_requests)
        .sum();
    if age_requests > 2 {
        return Err(error("mDL retrieval permits at most two age attestations"));
    }
    let size = documents.iter().try_fold(64usize, |total, document| {
        total
            .checked_add(document.items.encoded.len())
            .and_then(|total| {
                total.checked_add(document.authentication.as_ref().map_or(0, Vec::len))
            })
            .and_then(|total| total.checked_add(32))
            .filter(|total| *total <= limits.max_bytes)
            .ok_or_else(|| error("DeviceRequest exceeds byte limit"))
    })?;
    let mut encoded = Vec::with_capacity(size);
    encoded.push(0xa2);
    push_text(&mut encoded, "version");
    push_text(&mut encoded, "1.0");
    push_text(&mut encoded, "docRequests");
    push_head(&mut encoded, 4, documents.len() as u64);
    for document in documents {
        encoded.push(if document.authentication.is_some() {
            0xa2
        } else {
            0xa1
        });
        push_text(&mut encoded, "itemsRequest");
        encoded.extend_from_slice(document.items.encoded);
        if let Some(authentication) = &document.authentication {
            push_text(&mut encoded, "readerAuth");
            encoded.extend_from_slice(authentication);
        }
    }
    // Nested requests share one envelope's item/depth budget.
    raw::validate(&encoded)?;
    Ok(DeviceRequest {
        encoded,
        age_requests,
    })
}

/// An untrusted response envelope, including status-only and mixed-error replies.
///
/// Documents and error details are raw borrowed values. No credential has been
/// authenticated by this type. Existing presentation verification remains atomic.
#[derive(Clone, Copy, Debug)]
pub struct ResponseEnvelope<'a> {
    encoded: &'a [u8],
    version: &'a str,
    status: u64,
    documents: Option<CborValueRef<'a>>,
    document_errors: Option<CborValueRef<'a>>,
    has_errors: bool,
}

impl<'a> ResponseEnvelope<'a> {
    pub fn from_bytes(encoded: &'a [u8]) -> Result<Self, MdocError> {
        Self::from_validated(Item::parse(encoded)?)
    }

    pub(crate) fn from_validated(root: Item<'a>) -> Result<Self, MdocError> {
        let encoded = root.bytes();
        let mut version = None;
        let mut status = None;
        let mut documents = None;
        let mut document_errors = None;
        let mut has_errors = false;
        for entry in root.map()? {
            let (key, value) = entry?;
            match key.text()? {
                "version" => {
                    let text = value.text()?;
                    if !supports_version(text) {
                        return Err(error("unsupported DeviceResponse version"));
                    }
                    version = Some(text);
                }
                "status" => status = Some(value.uint()?),
                "documents" => {
                    let entries = value.array()?;
                    if entries.len() == 0 {
                        return Err(error("present documents array must not be empty"));
                    }
                    for document in entries {
                        has_errors |= check_document_envelope(document?)?;
                    }
                    documents = Some(CborValueRef::from_item(value));
                }
                "documentErrors" => {
                    let entries = value.array()?;
                    if entries.len() == 0 {
                        return Err(error("present documentErrors array must not be empty"));
                    }
                    for entry in entries {
                        let entries = entry?.map()?;
                        if entries.len() != 1 {
                            return Err(error("DocumentError must contain one document type"));
                        }
                        for entry in entries {
                            check_error_item(entry?)?;
                        }
                    }
                    document_errors = Some(CborValueRef::from_item(value));
                    has_errors = true;
                }
                _ => {}
            }
        }
        let status = status.ok_or_else(|| error("missing response status"))?;
        if status != 0 && documents.is_some() {
            return Err(error("nonzero response status must not include documents"));
        }
        Ok(Self {
            encoded,
            version: version.ok_or_else(|| error("missing response version"))?,
            status,
            documents,
            document_errors,
            has_errors,
        })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.encoded
    }
    pub fn version(&self) -> &'a str {
        self.version
    }
    /// Known 2021 status codes are 0, 10, 11 and 12. Unknown codes remain visible.
    pub fn status(&self) -> u64 {
        self.status
    }
    pub fn documents(&self) -> Option<CborValueRef<'a>> {
        self.documents
    }
    pub fn document_errors(&self) -> Option<CborValueRef<'a>> {
        self.document_errors
    }
    /// Includes document-level and element-level errors, independently of status.
    pub fn has_errors(&self) -> bool {
        self.has_errors
    }
}

fn check_document_envelope(document: Item<'_>) -> Result<bool, MdocError> {
    let mut required = 0u8;
    let mut has_errors = false;
    for entry in document.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "docType" => {
                nonempty_text(value)?;
                required |= 1;
            }
            "issuerSigned" => {
                value.map()?;
                required |= 2;
            }
            "deviceSigned" => {
                value.map()?;
                required |= 4;
            }
            "errors" => {
                has_errors = true;
                let namespaces = value.map()?;
                if namespaces.len() == 0 {
                    return Err(error("empty Errors map"));
                }
                for entry in namespaces {
                    let (namespace, elements) = entry?;
                    nonempty_text(namespace)?;
                    let elements = elements.map()?;
                    if elements.len() == 0 {
                        return Err(error("empty ErrorItems map"));
                    }
                    for entry in elements {
                        check_error_item(entry?)?;
                    }
                }
            }
            _ => {}
        }
    }
    if required != 7 {
        return Err(error("incomplete response Document"));
    }
    Ok(has_errors)
}

fn check_error_item((name, code): (Item<'_>, Item<'_>)) -> Result<(), MdocError> {
    nonempty_text(name)?;
    if code.as_integer().is_none() {
        return Err(error("ErrorCode must be an integer"));
    }
    Ok(())
}
