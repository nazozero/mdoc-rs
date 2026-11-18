//! Wire encoding for issued credentials and device responses.
//!
//! The unsigned map framing is deterministic. Signed `IssuerSignedItemBytes`,
//! `DeviceNameSpacesBytes`, protected COSE headers and COSE payloads retain their
//! original bytes. Use the verifier APIs to authenticate encoded documents.

mod borrowed;
pub use borrowed::{encode_device_response_borrowed, encode_issuer_signed_borrowed};

use crate::cbor::raw::{self, push_bytes, push_head, push_text};
use crate::cose::{push_header, push_protected_header};
use crate::error::MdocError;
use crate::model::device_response::{DeviceResponse, DeviceResponseStatus};
use crate::model::document::{IssuerSigned, IssuerSignedDocument};
use crate::model::types::DeviceAuth;

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
    push_protected_header(out, protected)?;
    push_header(out, unprotected)?;
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
                // Public models may be edited. Check the framing here and
                // validate embedded contents once in the completed envelope.
                raw::validate_tag24_framing(&item.encoded)?;
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
        raw::validate_tag24_framing(&device.name_spaces_bytes)?;
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
pub fn encode_device_response(mdoc: &DeviceResponse) -> Result<Vec<u8>, MdocError> {
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

impl DeviceResponse {
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
    /// Authentication and trust evaluation use the verifier APIs.
    pub fn to_device_response_cbor(&self) -> Result<Vec<u8>, MdocError> {
        let mut out = Vec::new();
        out.push(0xa3);
        push_text(&mut out, "status");
        push_head(&mut out, 0, DeviceResponseStatus::Ok as u64);
        push_text(&mut out, "version");
        push_text(&mut out, "1.0");
        push_text(&mut out, "documents");
        out.push(0x81);
        push_document(&mut out, self)?;
        raw::validate(&out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;
    use coset::{AsCborValue, CborSerializable};

    fn headers() -> (coset::ProtectedHeader, coset::Header) {
        (
            coset::ProtectedHeader {
                original_data: Some(hex::decode("a204430102030126").unwrap()),
                header: coset::HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::ES256)
                    .key_id(vec![1, 2, 3])
                    .build(),
            },
            coset::HeaderBuilder::new()
                .text_value(
                    "extension".into(),
                    Value::Tag(42, Box::new(Value::Bool(true))),
                )
                .value(
                    33,
                    Value::Array(vec![
                        Value::Bytes(vec![0x5a; 65_536]),
                        Value::Bytes(vec![0x6b; 256]),
                    ]),
                )
                .build(),
        )
    }

    #[test]
    fn borrowed_cose_wire_encoding_matches_independent_coset_sign1_and_mac0() {
        let (protected, unprotected) = headers();
        for original_data in [protected.original_data.clone(), None, Some(Vec::new())] {
            let protected = coset::ProtectedHeader {
                original_data,
                header: protected.header.clone(),
            };
            for payload in [None, Some(Vec::new()), Some(vec![0x7c; 65_536])] {
                let proof = vec![0x8d; 64];
                let mut actual = Vec::new();
                push_cose(
                    &mut actual,
                    &protected,
                    &unprotected,
                    payload.as_deref(),
                    &proof,
                )
                .unwrap();
                assert_eq!(
                    actual,
                    coset::CoseSign1 {
                        protected: protected.clone(),
                        unprotected: unprotected.clone(),
                        payload: payload.clone(),
                        signature: proof.clone(),
                    }
                    .to_vec()
                    .unwrap()
                );
                assert_eq!(
                    actual,
                    coset::CoseMac0 {
                        protected: protected.clone(),
                        unprotected: unprotected.clone(),
                        payload,
                        tag: proof,
                    }
                    .to_vec()
                    .unwrap()
                );
            }
        }
    }

    #[test]
    fn public_issuer_encoder_preserves_coset_extension_values_and_errors() {
        let (protected, unprotected) = headers();
        let mut issuer_signed = IssuerSigned {
            issuer_auth: crate::model::IssuerAuth::new(coset::CoseSign1 {
                protected,
                unprotected,
                payload: Some(vec![0x7c; 256]),
                signature: vec![0x8d; 64],
            }),
            name_spaces: Default::default(),
        };
        let expected = Value::Map(vec![(
            Value::Text("issuerAuth".into()),
            issuer_signed
                .issuer_auth
                .cose_sign1
                .clone()
                .to_cbor_value()
                .unwrap(),
        )]);
        let mut expected_bytes = Vec::new();
        ciborium::into_writer(&expected, &mut expected_bytes).unwrap();
        assert_eq!(
            encode_issuer_signed(&issuer_signed).unwrap(),
            expected_bytes
        );

        issuer_signed
            .issuer_auth
            .cose_sign1
            .unprotected
            .rest
            .push((coset::Label::Int(33), Value::Bytes(vec![0x99])));
        assert!(matches!(
            encode_issuer_signed(&issuer_signed),
            Err(MdocError::Cose(_))
        ));

        let unprotected = &mut issuer_signed.issuer_auth.cose_sign1.unprotected;
        unprotected.rest = vec![(coset::Label::Int(4), Value::Bytes(vec![2]))];
        unprotected.key_id = vec![1];
        assert!(matches!(
            encode_issuer_signed(&issuer_signed),
            Err(MdocError::Cbor(_))
        ));
    }
}
