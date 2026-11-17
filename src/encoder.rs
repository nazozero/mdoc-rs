//! Wire encoding for issued credentials and device responses.
//!
//! The unsigned map framing is deterministic. Signed `IssuerSignedItemBytes`,
//! `DeviceNameSpacesBytes`, protected COSE headers and COSE payloads retain their
//! original bytes. Encoding a document does not authenticate it or establish
//! issuer trust, certificate status, or credential status.

use coset::CborSerializable;

use crate::cbor::raw::{self, push_head, push_text};
use crate::error::MdocError;
use crate::model::document::{IssuerSigned, IssuerSignedDocument};
use crate::model::mdoc::{MDoc, MDocStatus};
use crate::model::types::DeviceAuth;

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

// COSE_Sign1 and COSE_Mac0 share the four-element wire structure. Serialize the
// byte-string fields by borrowing them rather than cloning an entire COSE object
// and then decoding it into a Value tree. In particular, original_data takes
// precedence over a reconstructed protected header.
fn push_cose(
    out: &mut Vec<u8>,
    protected: &coset::ProtectedHeader,
    unprotected: &coset::Header,
    payload: Option<&[u8]>,
    signature_or_tag: &[u8],
) -> Result<(), MdocError> {
    out.push(0x84);
    if let Some(original) = &protected.original_data {
        push_bytes(out, original);
    } else if protected.is_empty() {
        out.push(0x40);
    } else {
        push_bytes(out, &protected.header.clone().to_vec()?);
    }
    out.extend_from_slice(&unprotected.clone().to_vec()?);
    if let Some(payload) = payload {
        push_bytes(out, payload);
    } else {
        out.push(0xf6);
    }
    push_bytes(out, signature_or_tag);
    Ok(())
}

fn push_issuer_signed(out: &mut Vec<u8>, issuer_signed: &IssuerSigned) -> Result<(), MdocError> {
    let has_namespaces = !issuer_signed.name_spaces.is_empty();
    push_head(out, 5, if has_namespaces { 2 } else { 1 });
    push_text(out, "issuerAuth");
    let auth = &issuer_signed.issuer_auth.cose_sign1;
    push_cose(
        out,
        &auth.protected,
        &auth.unprotected,
        auth.payload.as_deref(),
        &auth.signature,
    )?;
    if has_namespaces {
        push_text(out, "nameSpaces");
        push_head(out, 5, issuer_signed.name_spaces.len() as u64);
        let mut namespaces: Vec<_> = issuer_signed.name_spaces.iter().collect();
        namespaces.sort_unstable_by(|(a, _), (b, _)| {
            a.len()
                .cmp(&b.len())
                .then_with(|| a.as_bytes().cmp(b.as_bytes()))
        });
        for (name, items) in namespaces {
            if name.is_empty() || items.is_empty() {
                return Err(MdocError::Issuance(
                    "issuer namespaces and item arrays must not be empty".into(),
                ));
            }
            push_text(out, name);
            push_head(out, 4, items.len() as u64);
            for item in items {
                // The public model can be assembled or edited by a caller.
                // Check each raw item once at this encoding boundary; never
                // replace it with a serialization of the decoded attributes.
                raw::tag24_inner(&item.encoded)?;
                out.extend_from_slice(&item.encoded);
            }
        }
    }
    Ok(())
}

fn push_document(out: &mut Vec<u8>, doc: &IssuerSignedDocument) -> Result<(), MdocError> {
    if doc.doc_type.is_empty() {
        return Err(MdocError::Issuance("docType must not be empty".into()));
    }
    push_head(out, 5, if doc.device_signed.is_some() { 3 } else { 2 });
    push_text(out, "docType");
    push_text(out, &doc.doc_type);
    if let Some(device) = &doc.device_signed {
        push_text(out, "deviceSigned");
        out.push(0xa2);
        push_text(out, "deviceAuth");
        out.push(0xa1);
        match &device.device_auth {
            DeviceAuth::Signature(auth) => {
                if auth.payload.is_some() {
                    return Err(MdocError::Issuance(
                        "device signature payload must be detached".into(),
                    ));
                }
                push_text(out, "deviceSignature");
                push_cose(
                    out,
                    &auth.protected,
                    &auth.unprotected,
                    None,
                    &auth.signature,
                )?;
            }
            DeviceAuth::Mac(auth) => {
                if auth.payload.is_some() {
                    return Err(MdocError::Issuance(
                        "device MAC payload must be detached".into(),
                    ));
                }
                push_text(out, "deviceMac");
                push_cose(out, &auth.protected, &auth.unprotected, None, &auth.tag)?;
            }
        }
        push_text(out, "nameSpaces");
        raw::tag24_inner(&device.name_spaces_bytes)?;
        out.extend_from_slice(&device.name_spaces_bytes);
    }
    push_text(out, "issuerSigned");
    push_issuer_signed(out, &doc.issuer_signed)
}

/// Encode the `IssuerSigned` CBOR value carried by OpenID4VCI 1.0 Final A.2.4.
/// The caller applies base64url encoding for the credential response.
pub fn encode_issuer_signed(issuer_signed: &IssuerSigned) -> Result<Vec<u8>, MdocError> {
    let mut out = Vec::new();
    push_issuer_signed(&mut out, issuer_signed)?;
    raw::validate(&out)?;
    Ok(out)
}

/// Encode an ISO DeviceResponse. Document-count policies, such as HAIP's
/// separate DeviceResponse for each mdoc, belong to the presentation profile.
pub fn encode_device_response(mdoc: &MDoc) -> Result<Vec<u8>, MdocError> {
    let mut out = Vec::new();
    out.push(0xa3);
    push_text(&mut out, "status");
    push_head(&mut out, 0, mdoc.status.clone() as u64);
    push_text(&mut out, "version");
    push_text(&mut out, &mdoc.version);
    push_text(&mut out, "documents");
    push_head(&mut out, 4, mdoc.documents.len() as u64);
    for doc in &mdoc.documents {
        push_document(&mut out, doc)?;
    }
    raw::validate(&out)?;
    Ok(out)
}

impl MDoc {
    /// Encode this container as a DeviceResponse.
    pub fn to_cbor(&self) -> Result<Vec<u8>, MdocError> {
        encode_device_response(self)
    }

    /// Encode this container as a DeviceResponse.
    pub fn to_device_response_cbor(&self) -> Result<Vec<u8>, MdocError> {
        self.to_cbor()
    }
}

impl IssuerSignedDocument {
    /// Encode the issued `IssuerSigned` value, without a DeviceResponse wrapper.
    pub fn to_issuer_signed_cbor(&self) -> Result<Vec<u8>, MdocError> {
        encode_issuer_signed(&self.issuer_signed)
    }

    /// Encode one document as a version 1.0, successful DeviceResponse.
    /// This does not infer that the document is authenticated or trusted.
    pub fn to_device_response_cbor(&self) -> Result<Vec<u8>, MdocError> {
        let mut out = Vec::new();
        out.push(0xa3);
        push_text(&mut out, "status");
        push_head(&mut out, 0, MDocStatus::Ok as u64);
        push_text(&mut out, "version");
        push_text(&mut out, "1.0");
        push_text(&mut out, "documents");
        out.push(0x81);
        push_document(&mut out, self)?;
        raw::validate(&out)?;
        Ok(out)
    }
}
