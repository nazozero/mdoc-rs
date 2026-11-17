//! Strict DeviceResponse decoding. Authentication is a separate operation.
//!
//! Signed byte strings are copied once from their original wire slices; neither
//! map order nor Tag 24 envelopes are reconstructed before digest verification.

use crate::{
    MdocError,
    cbor::raw::{Item, Limits},
    model::*,
};
use std::collections::{HashMap, HashSet};

fn error(message: &str) -> MdocError {
    MdocError::Parse(message.into())
}
fn missing<T>(value: Option<T>, field: &str) -> Result<T, MdocError> {
    value.ok_or_else(|| error(&format!("missing {field}")))
}

/// Decode a bounded DeviceResponse; this does not authenticate its contents.
pub fn parse(bytes: &[u8]) -> Result<MDoc, MdocError> {
    parse_with_limits(bytes, Limits::default(), 16)
}

/// Apply caller-selected byte/collection and document limits before decoding.
///
/// The same limits apply to the protected headers and MSO payloads embedded in
/// COSE byte strings. Item/depth budgets restart at each such envelope; Tag 24
/// shares the budget of its enclosing CBOR envelope.
pub fn parse_with_limits(
    bytes: &[u8],
    limits: Limits,
    max_documents: usize,
) -> Result<MDoc, MdocError> {
    let root = Item::parse_with_limits(bytes, limits)?;
    let (mut version, mut status, mut documents) = (None, None, None);
    for entry in root.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "version" => version = Some(value.text()?.to_owned()),
            "status" => {
                status = Some(
                    u8::try_from(value.uint()?)
                        .map_err(|_| error("invalid DeviceResponse status"))?,
                )
            }
            "documents" => {
                let items = value.array()?;
                if items.len() == 0 || items.len() > max_documents {
                    return Err(MdocError::DocumentCount {
                        actual: items.len(),
                        max: max_documents,
                    });
                }
                let mut result = Vec::with_capacity(items.len());
                for document in items {
                    result.push(parse_document(document?, limits)?);
                }
                documents = Some(result);
            }
            // Error-bearing/unknown messages are not credential presentations.
            _ => return Err(error("unsupported DeviceResponse field")),
        }
    }
    let status = missing(status, "status")?;
    if !matches!(status, 0 | 10 | 11 | 12) {
        return Err(error("unknown DeviceResponse status"));
    }
    Ok(MDoc {
        version: missing(version, "version")?,
        status: MDocStatus::from_u8(status),
        documents: missing(documents, "documents")?,
    })
}

fn parse_document(value: Item<'_>, limits: Limits) -> Result<IssuerSignedDocument, MdocError> {
    let (mut doc_type, mut issuer_signed, mut device_signed) = (None, None, None);
    for entry in value.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "docType" => doc_type = Some(value.text()?.to_owned()),
            "issuerSigned" => issuer_signed = Some(parse_issuer_signed(value, limits)?),
            "deviceSigned" => device_signed = Some(parse_device_signed(value, limits)?),
            _ => return Err(error("unsupported Document field")),
        }
    }
    let doc_type = missing(doc_type, "docType")?;
    if doc_type.is_empty() {
        return Err(error("empty docType"));
    }
    Ok(IssuerSignedDocument {
        doc_type,
        issuer_signed: missing(issuer_signed, "issuerSigned")?,
        device_signed,
    })
}

/// Decode the IssuerSigned map used by OpenID4VCI A.2.4.
/// The caller must authenticate issuerAuth before using the parsed data.
pub fn parse_issued(bytes: &[u8]) -> Result<IssuerSigned, MdocError> {
    parse_issued_with_limits(bytes, Limits::default())
}

/// Decode an OpenID4VCI IssuerSigned map with caller-selected CBOR limits.
///
/// The same limits also apply to known inner COSE envelopes: the protected
/// header map and embedded MSO payload. Item/depth budgets restart at each
/// COSE byte-string envelope; Tag 24 shares its enclosing envelope's budget.
pub fn parse_issued_with_limits(bytes: &[u8], limits: Limits) -> Result<IssuerSigned, MdocError> {
    parse_issuer_signed(Item::parse_with_limits(bytes, limits)?, limits)
}

fn parse_issuer_signed(value: Item<'_>, limits: Limits) -> Result<IssuerSigned, MdocError> {
    let mut issuer_auth = None;
    let mut name_spaces = HashMap::new();
    let mut salts = HashSet::new();
    for entry in value.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "issuerAuth" => {
                let sign1 = parse_sign1(value, limits)?;
                if let Some(payload) = &sign1.payload {
                    // COSE payload is an opaque bstr to the outer CBOR scan.
                    // Check its known MSO envelope before any claim decoding.
                    Item::parse_with_limits(payload, limits)?
                        .embedded()?
                        .map()?;
                }
                issuer_auth = Some(IssuerAuth::new(sign1));
            }
            "nameSpaces" => {
                for entry in value.map()? {
                    let (namespace, values) = entry?;
                    let namespace = namespace.text()?;
                    if namespace.is_empty() {
                        return Err(error("empty issuer namespace"));
                    }
                    let values = values.array()?;
                    if values.len() == 0 {
                        return Err(error("empty issuer namespace items"));
                    }
                    let mut ids = HashSet::new();
                    let mut identifiers = HashSet::new();
                    let mut items = Vec::with_capacity(values.len());
                    for value in values {
                        let item = parse_item(value?)?;
                        if !ids.insert(item.digest_id)
                            || !identifiers.insert(item.element_identifier.clone())
                        {
                            return Err(error("duplicate digestID or elementIdentifier"));
                        }
                        if !salts.insert(item.random.clone()) {
                            return Err(error("reused IssuerSignedItem random"));
                        }
                        items.push(item);
                    }
                    name_spaces.insert(namespace.to_owned(), items);
                }
                if name_spaces.is_empty() {
                    return Err(error("empty issuer nameSpaces map"));
                }
            }
            _ => return Err(error("unsupported IssuerSigned field")),
        }
    }
    Ok(IssuerSigned {
        issuer_auth: missing(issuer_auth, "issuerAuth")?,
        name_spaces,
    })
}

fn parse_item(value: Item<'_>) -> Result<IssuerSignedItem, MdocError> {
    let encoded = value.bytes();
    let inner = value.embedded()?;
    let (mut digest_id, mut random, mut element_identifier, mut element_value) =
        (None, None, None, None);
    for entry in inner.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "digestID" => {
                let id = value.uint()?;
                if id >= 1 << 31 {
                    return Err(error("digestID must be less than 2^31"));
                }
                digest_id = Some(id as u32);
            }
            "random" => {
                let salt = value.bstr()?;
                if salt.len() < 16 {
                    return Err(error("IssuerSignedItem random must be at least 16 bytes"));
                }
                random = Some(salt.to_vec());
            }
            "elementIdentifier" => {
                let identifier = value.text()?;
                if identifier.is_empty() {
                    return Err(error("empty elementIdentifier"));
                }
                element_identifier = Some(identifier.to_owned());
            }
            "elementValue" => element_value = Some(value.value()?),
            _ => return Err(error("unsupported IssuerSignedItem field")),
        }
    }
    Ok(IssuerSignedItem {
        digest_id: missing(digest_id, "digestID")?,
        random: missing(random, "random")?,
        element_identifier: missing(element_identifier, "elementIdentifier")?,
        element_value: missing(element_value, "elementValue")?,
        encoded: encoded.to_vec(),
    })
}

fn parse_device_signed(value: Item<'_>, limits: Limits) -> Result<DeviceSigned, MdocError> {
    let (mut device_auth, mut namespace_bytes) = (None, None);
    let mut name_spaces = HashMap::new();
    for entry in value.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "deviceAuth" => device_auth = Some(parse_device_auth(value, limits)?),
            "nameSpaces" => {
                namespace_bytes = Some(value.bytes().to_vec());
                for entry in value.embedded()?.map()? {
                    let (namespace, elements) = entry?;
                    let namespace = namespace.text()?;
                    if namespace.is_empty() {
                        return Err(error("empty device namespace"));
                    }
                    let mut decoded = HashMap::new();
                    for element in elements.map()? {
                        let (identifier, value) = element?;
                        let identifier = identifier.text()?;
                        if identifier.is_empty() {
                            return Err(error("empty device elementIdentifier"));
                        }
                        decoded.insert(identifier.to_owned(), value.value()?);
                    }
                    name_spaces.insert(namespace.to_owned(), decoded);
                }
            }
            _ => return Err(error("unsupported DeviceSigned field")),
        }
    }
    Ok(DeviceSigned {
        device_auth: missing(device_auth, "deviceAuth")?,
        name_spaces,
        name_spaces_bytes: missing(namespace_bytes, "DeviceNameSpacesBytes")?,
    })
}

struct CoseFields {
    protected: coset::ProtectedHeader,
    unprotected: coset::Header,
    payload: Option<Vec<u8>>,
    authentication: Vec<u8>,
}

fn parse_cose(value: Item<'_>, limits: Limits) -> Result<CoseFields, MdocError> {
    let mut fields = value.array()?;
    if fields.len() != 4 {
        return Err(error("COSE structure must contain four fields"));
    }
    let protected = fields.next().expect("four fields")?.bstr()?;
    let (protected_labels, protected_header) = if protected.is_empty() {
        (0, coset::Header::default())
    } else {
        // Protected headers are a bstr, not Tag 24, so validate their map here.
        crate::cose::parse_header(Item::parse_with_limits(protected, limits)?)?
    };
    let (unprotected_labels, unprotected) =
        crate::cose::parse_header(fields.next().expect("four fields")?)?;
    if protected_labels & unprotected_labels != 0 {
        return Err(MdocError::Cose(
            "duplicate header across protected/unprotected buckets".into(),
        ));
    }
    let payload = fields.next().expect("four fields")?;
    let payload = if payload.bytes() == [0xf6] {
        None
    } else {
        Some(payload.bstr()?.to_vec())
    };
    Ok(CoseFields {
        protected: coset::ProtectedHeader {
            original_data: Some(protected.to_vec()),
            header: protected_header,
        },
        unprotected,
        payload,
        authentication: fields.next().expect("four fields")?.bstr()?.to_vec(),
    })
}

fn parse_sign1(value: Item<'_>, limits: Limits) -> Result<coset::CoseSign1, MdocError> {
    let fields = parse_cose(value, limits)?;
    Ok(coset::CoseSign1 {
        protected: fields.protected,
        unprotected: fields.unprotected,
        payload: fields.payload,
        signature: fields.authentication,
    })
}

fn parse_device_auth(value: Item<'_>, limits: Limits) -> Result<DeviceAuth, MdocError> {
    let mut map = value.map()?;
    let (key, value) = map.next().ok_or_else(|| error("empty deviceAuth"))??;
    if map.next().is_some() {
        return Err(error("deviceAuth must contain exactly one mechanism"));
    }
    match key.text()? {
        "deviceSignature" => Ok(DeviceAuth::Signature(parse_sign1(value, limits)?)),
        "deviceMac" => {
            let fields = parse_cose(value, limits)?;
            Ok(DeviceAuth::Mac(coset::CoseMac0 {
                protected: fields.protected,
                unprotected: fields.unprotected,
                payload: fields.payload,
                tag: fields.authentication,
            }))
        }
        _ => Err(error("unsupported device authentication mechanism")),
    }
}

/// Decode a hex fixture, ignoring ASCII whitespace.
pub fn parse_hex(text: &str) -> Result<MDoc, MdocError> {
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut high = None;
    for c in text.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let value = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return Err(error("invalid hex character")),
        };
        if let Some(h) = high.take() {
            bytes.push(h << 4 | value);
        } else {
            high = Some(value);
        }
    }
    if high.is_some() {
        return Err(error("odd hex length"));
    }
    parse(&bytes)
}
