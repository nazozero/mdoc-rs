//! Strict DeviceResponse decoding. Authentication is a separate operation.
//!
//! Signed byte strings retain their original map order and Tag 24 envelopes.

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

/// Decode a bounded DeviceResponse. Use the verifier to authenticate its contents.
pub fn parse(bytes: &[u8]) -> Result<DeviceResponse, MdocError> {
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
) -> Result<DeviceResponse, MdocError> {
    parse_borrowed_with_limits(bytes, limits, max_documents)?.into_owned()
}

/// Decode a DeviceResponse while borrowing its strings, byte strings and claims.
pub fn parse_borrowed(bytes: &[u8]) -> Result<DeviceResponseRef<'_>, MdocError> {
    parse_borrowed_with_limits(bytes, Limits::default(), 16)
}

/// Borrow a DeviceResponse under caller-selected CBOR and document limits.
pub fn parse_borrowed_with_limits(
    bytes: &[u8],
    limits: Limits,
    max_documents: usize,
) -> Result<DeviceResponseRef<'_>, MdocError> {
    let root = Item::parse_with_limits(bytes, limits)?;
    let (mut version, mut status, mut documents) = (None, None, None);
    for entry in root.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "version" => version = Some(value.text()?),
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
    Ok(DeviceResponseRef {
        version: missing(version, "version")?,
        status: DeviceResponseStatus::from_u8(status)
            .ok_or_else(|| error("unknown DeviceResponse status"))?,
        documents: missing(documents, "documents")?,
    })
}

fn parse_document(
    value: Item<'_>,
    limits: Limits,
) -> Result<IssuerSignedDocumentRef<'_>, MdocError> {
    let (mut doc_type, mut issuer_signed, mut device_signed) = (None, None, None);
    for entry in value.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "docType" => doc_type = Some(value.text()?),
            "issuerSigned" => issuer_signed = Some(parse_issuer_signed(value, limits)?),
            "deviceSigned" => device_signed = Some(parse_device_signed(value, limits)?),
            _ => return Err(error("unsupported Document field")),
        }
    }
    let doc_type = missing(doc_type, "docType")?;
    if doc_type.is_empty() {
        return Err(error("empty docType"));
    }
    Ok(IssuerSignedDocumentRef {
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
    parse_issued_borrowed_with_limits(bytes, limits)?.into_owned()
}

/// Borrow the IssuerSigned map used by OpenID4VCI A.2.4.
pub fn parse_issued_borrowed(bytes: &[u8]) -> Result<IssuerSignedRef<'_>, MdocError> {
    parse_issued_borrowed_with_limits(bytes, Limits::default())
}

pub fn parse_issued_borrowed_with_limits(
    bytes: &[u8],
    limits: Limits,
) -> Result<IssuerSignedRef<'_>, MdocError> {
    parse_issuer_signed(Item::parse_with_limits(bytes, limits)?, limits)
}

fn parse_issuer_signed(value: Item<'_>, limits: Limits) -> Result<IssuerSignedRef<'_>, MdocError> {
    let mut issuer_auth = None;
    let mut name_spaces = HashMap::new();
    let mut salts = HashSet::new();
    for entry in value.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "issuerAuth" => {
                let sign1 = parse_sign1(value, limits)?;
                let validated_mso_payload = sign1
                    .payload
                    .map(|payload| Item::parse_with_limits(payload, limits))
                    .transpose()?;
                if let Some(payload) = validated_mso_payload {
                    // COSE payload is an opaque bstr to the outer CBOR scan.
                    // Check its known MSO envelope before any claim decoding.
                    payload.embedded()?.map()?;
                }
                // Operations without a Limits parameter retain the default
                // budget. A proof from looser parsing cannot establish that.
                let defaults = Limits::default();
                let validated_mso_payload = validated_mso_payload.filter(|_| {
                    limits.max_bytes <= defaults.max_bytes
                        && limits.max_depth <= defaults.max_depth
                        && limits.max_items <= defaults.max_items
                        && limits.max_collection_items <= defaults.max_collection_items
                });
                issuer_auth = Some(IssuerAuthRef {
                    cose_sign1: sign1,
                    validated_mso_payload,
                });
            }
            "nameSpaces" => {
                let namespaces = value.map()?;
                if namespaces.len() == 0 {
                    return Err(error("empty issuer nameSpaces map"));
                }
                name_spaces.reserve(namespaces.len());
                for entry in namespaces {
                    let (namespace, values) = entry?;
                    let namespace = namespace.text()?;
                    if namespace.is_empty() {
                        return Err(error("empty issuer namespace"));
                    }
                    let values = values.array()?;
                    if values.len() == 0 {
                        return Err(error("empty issuer namespace items"));
                    }
                    let mut ids = HashSet::with_capacity(values.len());
                    let mut identifiers = HashSet::with_capacity(values.len());
                    salts.reserve(values.len());
                    let mut items = Vec::with_capacity(values.len());
                    for value in values {
                        items.push(parse_item(value?, &mut ids, &mut identifiers, &mut salts)?);
                    }
                    name_spaces.insert(namespace, items);
                }
            }
            _ => return Err(error("unsupported IssuerSigned field")),
        }
    }
    Ok(IssuerSignedRef {
        issuer_auth: missing(issuer_auth, "issuerAuth")?,
        name_spaces,
    })
}

fn parse_item<'a>(
    value: Item<'a>,
    ids: &mut HashSet<u32>,
    identifiers: &mut HashSet<&'a str>,
    salts: &mut HashSet<&'a [u8]>,
) -> Result<IssuerSignedItemRef<'a>, MdocError> {
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
                random = Some(salt);
            }
            "elementIdentifier" => {
                let identifier = value.text()?;
                if identifier.is_empty() {
                    return Err(error("empty elementIdentifier"));
                }
                element_identifier = Some(identifier);
            }
            "elementValue" => element_value = Some(CborValueRef::from_item(value)),
            _ => return Err(error("unsupported IssuerSignedItem field")),
        }
    }
    let digest_id = missing(digest_id, "digestID")?;
    let random = missing(random, "random")?;
    let element_identifier = missing(element_identifier, "elementIdentifier")?;
    let element_value = missing(element_value, "elementValue")?;
    if !ids.insert(digest_id) || !identifiers.insert(element_identifier) {
        return Err(error("duplicate digestID or elementIdentifier"));
    }
    if !salts.insert(random) {
        return Err(error("reused IssuerSignedItem random"));
    }
    Ok(IssuerSignedItemRef {
        digest_id,
        random,
        element_identifier,
        element_value,
        encoded,
    })
}

fn parse_device_signed(value: Item<'_>, limits: Limits) -> Result<DeviceSignedRef<'_>, MdocError> {
    let (mut device_auth, mut namespace_bytes) = (None, None);
    let mut name_spaces = HashMap::new();
    for entry in value.map()? {
        let (key, value) = entry?;
        match key.text()? {
            "deviceAuth" => device_auth = Some(parse_device_auth(value, limits)?),
            "nameSpaces" => {
                namespace_bytes = Some(value.bytes());
                name_spaces = parse_device_namespaces(value.embedded()?)?;
            }
            _ => return Err(error("unsupported DeviceSigned field")),
        }
    }
    Ok(DeviceSignedRef {
        device_auth: missing(device_auth, "deviceAuth")?,
        name_spaces,
        name_spaces_bytes: missing(namespace_bytes, "DeviceNameSpacesBytes")?,
    })
}

pub(crate) fn parse_device_namespaces(
    value: Item<'_>,
) -> Result<HashMap<&str, HashMap<&str, CborValueRef<'_>>>, MdocError> {
    let namespaces = value.map()?;
    let mut name_spaces = HashMap::with_capacity(namespaces.len());
    for entry in namespaces {
        let (namespace, elements) = entry?;
        let namespace = namespace.text()?;
        if namespace.is_empty() {
            return Err(error("empty device namespace"));
        }
        let elements = elements.map()?;
        let mut decoded = HashMap::with_capacity(elements.len());
        for element in elements {
            let (identifier, value) = element?;
            let identifier = identifier.text()?;
            if identifier.is_empty() {
                return Err(error("empty device elementIdentifier"));
            }
            decoded.insert(identifier, CborValueRef::from_item(value));
        }
        if decoded.is_empty() {
            return Err(error("empty DeviceSignedItems map"));
        }
        name_spaces.insert(namespace, decoded);
    }
    Ok(name_spaces)
}

struct CoseFields<'a> {
    protected: &'a [u8],
    protected_header: CoseHeaderRef<'a>,
    unprotected: CoseHeaderRef<'a>,
    payload: Option<&'a [u8]>,
    authentication: &'a [u8],
}

fn parse_cose(value: Item<'_>, limits: Limits) -> Result<CoseFields<'_>, MdocError> {
    let mut fields = value.array()?;
    if fields.len() != 4 {
        return Err(error("COSE structure must contain four fields"));
    }
    let protected = fields.next().expect("four fields")?.bstr()?;
    let protected_header = if protected.is_empty() {
        CoseHeaderRef::default()
    } else {
        // Protected headers are a bstr, not Tag 24, so validate their map here.
        CoseHeaderRef::parse(Item::parse_with_limits(protected, limits)?)?
    };
    let unprotected = CoseHeaderRef::parse(fields.next().expect("four fields")?)?;
    if protected_header.labels & unprotected.labels != 0 {
        return Err(MdocError::Cose(
            "duplicate header across protected/unprotected buckets".into(),
        ));
    }
    let payload = fields.next().expect("four fields")?;
    let payload = if payload.bytes() == [0xf6] {
        None
    } else {
        Some(payload.bstr()?)
    };
    Ok(CoseFields {
        protected,
        protected_header,
        unprotected,
        payload,
        authentication: fields.next().expect("four fields")?.bstr()?,
    })
}

fn parse_sign1(value: Item<'_>, limits: Limits) -> Result<CoseSign1Ref<'_>, MdocError> {
    let fields = parse_cose(value, limits)?;
    Ok(CoseSign1Ref {
        protected: fields.protected,
        protected_header: fields.protected_header,
        unprotected: fields.unprotected,
        payload: fields.payload,
        signature: fields.authentication,
    })
}

fn parse_device_auth(value: Item<'_>, limits: Limits) -> Result<DeviceAuthRef<'_>, MdocError> {
    let mut map = value.map()?;
    let (key, value) = map.next().ok_or_else(|| error("empty deviceAuth"))??;
    if map.next().is_some() {
        return Err(error("deviceAuth must contain exactly one mechanism"));
    }
    match key.text()? {
        "deviceSignature" => Ok(DeviceAuthRef::Signature(parse_sign1(value, limits)?)),
        "deviceMac" => {
            let fields = parse_cose(value, limits)?;
            Ok(DeviceAuthRef::Mac(CoseMac0Ref {
                protected: fields.protected,
                protected_header: fields.protected_header,
                unprotected: fields.unprotected,
                payload: fields.payload,
                tag: fields.authentication,
            }))
        }
        _ => Err(error("unsupported device authentication mechanism")),
    }
}

/// Decode a hex fixture, ignoring ASCII whitespace.
pub fn parse_hex(text: &str) -> Result<DeviceResponse, MdocError> {
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
