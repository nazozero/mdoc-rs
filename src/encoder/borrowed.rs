//! Wire encoding directly from borrowed protocol models.

use crate::MdocError;
use crate::cbor::raw::{self, push_bytes, push_head, push_text};
use crate::model::{
    CoseHeaderRef, CoseLabelRef, DeviceAuthRef, DeviceResponseRef, DeviceResponseStatus,
    IssuerSignedDocumentRef, IssuerSignedRef,
};

fn push_label(out: &mut Vec<u8>, label: CoseLabelRef<'_>) {
    match label {
        CoseLabelRef::Int(value) if value >= 0 => push_head(out, 0, value as u64),
        CoseLabelRef::Int(value) => push_head(out, 1, (-1 - value) as u64),
        CoseLabelRef::Text(value) => push_text(out, value),
    }
}

fn push_header(out: &mut Vec<u8>, header: &CoseHeaderRef<'_>) {
    let entries = usize::from(header.alg.is_some())
        + usize::from(!header.crit.is_empty())
        + usize::from(!header.key_id.is_empty())
        + usize::from(header.x5chain.is_some());
    push_head(out, 5, entries as u64);
    if let Some(algorithm) = header.alg {
        out.push(0x01);
        push_label(out, algorithm);
    }
    if !header.crit.is_empty() {
        out.push(0x02);
        push_head(out, 4, header.crit.len() as u64);
        for label in &header.crit {
            push_label(out, *label);
        }
    }
    if !header.key_id.is_empty() {
        out.push(0x04);
        push_bytes(out, header.key_id);
    }
    if let Some(chain) = header.x5chain {
        push_head(out, 0, 33);
        out.extend_from_slice(chain.encoded());
    }
}

fn push_cose(
    out: &mut Vec<u8>,
    protected: &[u8],
    unprotected: &CoseHeaderRef<'_>,
    payload: Option<&[u8]>,
    signature_or_tag: &[u8],
) {
    out.push(0x84);
    push_bytes(out, protected);
    push_header(out, unprotected);
    if let Some(payload) = payload {
        push_bytes(out, payload);
    } else {
        out.push(0xf6);
    }
    push_bytes(out, signature_or_tag);
}

fn push_issuer_signed(out: &mut Vec<u8>, issuer: &IssuerSignedRef<'_>) -> Result<(), MdocError> {
    let has_namespaces = !issuer.name_spaces.is_empty();
    push_head(out, 5, if has_namespaces { 2 } else { 1 });
    push_text(out, "issuerAuth");
    let auth = &issuer.issuer_auth.cose_sign1;
    push_cose(
        out,
        auth.protected,
        &auth.unprotected,
        auth.payload,
        auth.signature,
    );
    if has_namespaces {
        push_text(out, "nameSpaces");
        push_head(out, 5, issuer.name_spaces.len() as u64);
        let mut namespaces: Vec<_> = issuer.name_spaces.iter().collect();
        namespaces.sort_unstable_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
        for (namespace, items) in namespaces {
            if namespace.is_empty() || items.is_empty() {
                return Err(MdocError::Issuance(
                    "issuer namespaces and item arrays must not be empty".into(),
                ));
            }
            push_text(out, namespace);
            push_head(out, 4, items.len() as u64);
            for item in items {
                // The raw signed field is authoritative; its public slice can
                // be replaced, so check framing before final envelope validation.
                raw::validate_tag24_framing(item.encoded)?;
                out.extend_from_slice(item.encoded);
            }
        }
    }
    Ok(())
}

fn push_document(
    out: &mut Vec<u8>,
    document: &IssuerSignedDocumentRef<'_>,
) -> Result<(), MdocError> {
    if document.doc_type.is_empty() {
        return Err(MdocError::Issuance("docType must not be empty".into()));
    }
    push_head(
        out,
        5,
        if document.device_signed.is_some() {
            3
        } else {
            2
        },
    );
    push_text(out, "docType");
    push_text(out, document.doc_type);
    if let Some(device) = &document.device_signed {
        push_text(out, "deviceSigned");
        out.push(0xa2);
        push_text(out, "deviceAuth");
        out.push(0xa1);
        match &device.device_auth {
            DeviceAuthRef::Signature(auth) => {
                if auth.payload.is_some() {
                    return Err(MdocError::Issuance(
                        "device signature payload must be detached".into(),
                    ));
                }
                push_text(out, "deviceSignature");
                push_cose(out, auth.protected, &auth.unprotected, None, auth.signature);
            }
            DeviceAuthRef::Mac(auth) => {
                if auth.payload.is_some() {
                    return Err(MdocError::Issuance(
                        "device MAC payload must be detached".into(),
                    ));
                }
                push_text(out, "deviceMac");
                push_cose(out, auth.protected, &auth.unprotected, None, auth.tag);
            }
        }
        push_text(out, "nameSpaces");
        raw::validate_tag24_framing(device.name_spaces_bytes)?;
        out.extend_from_slice(device.name_spaces_bytes);
    }
    push_text(out, "issuerSigned");
    push_issuer_signed(out, &document.issuer_signed)
}

/// Encode an IssuerSigned value directly from borrowed fields.
///
/// Signed item bytes, protected headers and the issuer payload are preserved;
/// decoded claim fields do not replace their authenticated wire representations.
/// The result is structurally checked, but encoding does not authenticate it.
pub fn encode_issuer_signed_borrowed(issuer: &IssuerSignedRef<'_>) -> Result<Vec<u8>, MdocError> {
    let mut out = Vec::new();
    push_issuer_signed(&mut out, issuer)?;
    raw::validate(&out)?;
    Ok(out)
}

/// Encode a borrowed DeviceResponse without materializing owned protocol models.
/// Signed fields retain their original bytes; the complete output is validated.
pub fn encode_device_response_borrowed(
    response: &DeviceResponseRef<'_>,
) -> Result<Vec<u8>, MdocError> {
    encode_response(response.version, &response.status, &response.documents)
}

fn encode_response(
    version: &str,
    status: &DeviceResponseStatus,
    documents: &[IssuerSignedDocumentRef<'_>],
) -> Result<Vec<u8>, MdocError> {
    let mut out = Vec::new();
    out.push(0xa3);
    push_text(&mut out, "status");
    push_head(&mut out, 0, status.clone() as u64);
    push_text(&mut out, "version");
    push_text(&mut out, version);
    push_text(&mut out, "documents");
    push_head(&mut out, 4, documents.len() as u64);
    for document in documents {
        push_document(&mut out, document)?;
    }
    raw::validate(&out)?;
    Ok(out)
}

impl IssuerSignedDocumentRef<'_> {
    /// Encode the issued IssuerSigned value without a DeviceResponse wrapper.
    pub fn to_issuer_signed_cbor(&self) -> Result<Vec<u8>, MdocError> {
        encode_issuer_signed_borrowed(&self.issuer_signed)
    }

    /// Encode one borrowed document as a successful version 1.0 DeviceResponse.
    pub fn to_device_response_cbor(&self) -> Result<Vec<u8>, MdocError> {
        encode_response("1.0", &DeviceResponseStatus::Ok, std::slice::from_ref(self))
    }
}
