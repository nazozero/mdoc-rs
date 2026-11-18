//! IssuerAuth — COSE_Sign1 with strict MSO parsing and untrusted certificates.

use super::{
    CborValueRef, CoseKeyRef, DeviceKeyInfoRef, DigestAlgorithm, KeyAuthorizationsRef, Mso, MsoRef,
    MsoStatusRef, StatusListInfoRef, ValidityInfo,
};
use crate::cbor::raw::{Item, Map};
use crate::error::MdocError;
use ciborium::Value;
use coset::CoseSign1;
use std::collections::HashMap;

/// Issuer authentication (COSE_Sign1 containing the MSO).
#[derive(Clone, Debug)]
pub struct IssuerAuth {
    /// COSE object retaining the received protected-header and payload bytes.
    pub cose_sign1: CoseSign1,
}

impl IssuerAuth {
    /// Wrap an unverified COSE object.
    pub fn new(cose_sign1: CoseSign1) -> Self {
        Self { cose_sign1 }
    }

    /// Parse the MSO from its mandatory Tag 24 payload.
    ///
    /// Returns structurally checked data and preserves the original payload.
    /// Authenticate the issuer signature before using the claims.
    pub fn mso(&self) -> Result<Mso, MdocError> {
        let payload = self
            .cose_sign1
            .payload
            .as_deref()
            .ok_or_else(|| mso_error("missing COSE_Sign1 payload"))?;
        MsoRef::parse(payload)?.into_owned()
    }

    /// Borrow the leaf certificate's DER from the unprotected x5chain header.
    ///
    /// Checks every container element. The returned certificate requires
    /// application path validation against trusted issuers.
    pub fn certificate_der(&self) -> Result<&[u8], MdocError> {
        let value = self.x5chain()?;
        validate_cert_chain(value)?;
        match value {
            Value::Bytes(bytes) => Ok(bytes),
            Value::Array(chain) => chain[0]
                .as_bytes()
                .map(Vec::as_slice)
                .ok_or_else(|| certificate_error("x5chain entry is not bytes")),
            _ => Err(certificate_error("x5chain is not bytes or an array")),
        }
    }

    /// Extract certificate bytes in x5chain order after checking the container.
    /// The caller validates DER, certificate signatures and issuer trust.
    pub fn certificate_chain_der(&self) -> Result<Vec<Vec<u8>>, MdocError> {
        match self.x5chain()? {
            Value::Bytes(bytes) if !bytes.is_empty() => Ok(vec![bytes.clone()]),
            Value::Array(chain) if !chain.is_empty() => chain
                .iter()
                .map(|value| match value {
                    Value::Bytes(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
                    _ => Err(certificate_error(
                        "x5chain entries must be nonempty byte strings",
                    )),
                })
                .collect(),
            _ => Err(certificate_error(
                "x5chain must contain at least one nonempty certificate",
            )),
        }
    }

    fn x5chain(&self) -> Result<&Value, MdocError> {
        let label = coset::Label::Int(33);
        if self
            .cose_sign1
            .protected
            .header
            .rest
            .iter()
            .any(|(key, _)| *key == label)
        {
            return Err(certificate_error(
                "ISO mdoc x5chain must be in the unprotected header",
            ));
        }
        let mut found = None;
        for (key, value) in &self.cose_sign1.unprotected.rest {
            if *key == label && found.replace(value).is_some() {
                return Err(certificate_error("duplicate x5chain header"));
            }
        }
        found.ok_or_else(|| certificate_error("missing x5chain in unprotected header"))
    }
}

fn certificate_error(message: impl Into<String>) -> MdocError {
    MdocError::Certificate(message.into())
}

fn validate_cert_chain(value: &Value) -> Result<(), MdocError> {
    match value {
        Value::Bytes(bytes) if !bytes.is_empty() => Ok(()),
        Value::Array(chain) if !chain.is_empty() => {
            for certificate in chain {
                if !matches!(certificate, Value::Bytes(bytes) if !bytes.is_empty()) {
                    return Err(certificate_error(
                        "x5chain entries must be nonempty byte strings",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(certificate_error(
            "x5chain must contain at least one nonempty certificate",
        )),
    }
}

fn mso_error(message: impl Into<String>) -> MdocError {
    MdocError::Mso(message.into())
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, MdocError> {
    value.ok_or_else(|| mso_error(format!("missing {field}")))
}

fn mso_map<'a>(value: Item<'a>, field: &str) -> Result<Map<'a>, MdocError> {
    value
        .map()
        .map_err(|_| mso_error(format!("{field} is not a CBOR map")))
}

fn mso_text<'a>(value: Item<'a>, field: &str) -> Result<&'a str, MdocError> {
    value
        .as_text()
        .ok_or_else(|| mso_error(format!("{field} is not text")))
}

/// Project one validated MSO while retaining references to its wire bytes.
pub(crate) fn parse_mso_ref(value: Item<'_>) -> Result<MsoRef<'_>, MdocError> {
    let mut version = None;
    let mut digest_algorithm = None;
    let mut doc_type = None;
    let mut validity_info = None;
    let mut value_digests = None;
    let mut device_key_info = None;
    let mut status = None;
    let mut additional_fields = HashMap::new();
    for entry in mso_map(value, "MSO")? {
        let (key, value) = entry?;
        let key = mso_text(key, "MSO key")?;
        match key {
            "version" => version = Some(mso_text(value, key)?),
            "digestAlgorithm" => {
                let name = mso_text(value, key)?;
                digest_algorithm = Some(
                    DigestAlgorithm::from_str_name(name)
                        .ok_or_else(|| MdocError::UnsupportedAlgorithm(name.to_owned()))?,
                );
            }
            "docType" => doc_type = Some(mso_text(value, key)?),
            "validityInfo" => validity_info = Some(parse_validity_info(value)?),
            "valueDigests" => value_digests = Some(parse_value_digests(value)?),
            "deviceKeyInfo" => device_key_info = Some(parse_device_key_info(value)?),
            "status" => status = Some(parse_status_ref(value)?),
            _ => {
                additional_fields.insert(key, CborValueRef::from_item(value));
            }
        }
    }
    let version = required(version, "version")?;
    if !super::types::supports_version(version) {
        return Err(mso_error("unsupported MSO version"));
    }
    let digest_algorithm = required(digest_algorithm, "digestAlgorithm")?;
    let value_digests: HashMap<&str, HashMap<u32, &[u8]>> =
        required(value_digests, "valueDigests")?;
    if value_digests
        .values()
        .flat_map(HashMap::values)
        .any(|digest| digest.len() != digest_algorithm.output_size())
    {
        return Err(mso_error("digest length does not match digestAlgorithm"));
    }
    let doc_type = required(doc_type, "docType")?;
    if doc_type.is_empty() {
        return Err(mso_error("docType is empty"));
    }
    Ok(MsoRef {
        version,
        digest_algorithm,
        doc_type,
        validity_info: required(validity_info, "validityInfo")?,
        value_digests,
        device_key_info: required(device_key_info, "deviceKeyInfo")?,
        status,
        additional_fields,
    })
}

fn parse_value_digests(value: Item<'_>) -> Result<HashMap<&str, HashMap<u32, &[u8]>>, MdocError> {
    let namespaces = mso_map(value, "valueDigests")?;
    if namespaces.len() == 0 {
        return Err(mso_error("valueDigests must not be empty"));
    }
    let mut result = HashMap::with_capacity(namespaces.len());
    for entry in namespaces {
        let (namespace, values) = entry?;
        let namespace = mso_text(namespace, "valueDigests namespace")?;
        let values = mso_map(values, "namespace digests")?;
        if values.len() == 0 {
            return Err(mso_error("namespace digests must not be empty"));
        }
        let mut digests = HashMap::with_capacity(values.len());
        for entry in values {
            let (id, digest) = entry?;
            let id = id
                .as_integer()
                .and_then(|id| u32::try_from(id).ok())
                .filter(|id| *id < 1 << 31)
                .ok_or_else(|| mso_error("digestID must be an unsigned integer below 2^31"))?;
            let digest = digest
                .as_bytes()
                .ok_or_else(|| mso_error("digest value is not bytes"))?;
            digests.insert(id, digest);
        }
        result.insert(namespace, digests);
    }
    Ok(result)
}

pub(crate) fn parse_status_ref(value: Item<'_>) -> Result<MsoStatusRef<'_>, MdocError> {
    let mechanisms = mso_map(value, "status")?;
    if mechanisms.len() == 0 {
        return Err(mso_error("status must contain at least one mechanism"));
    }
    let mut status_list = None;
    for entry in mechanisms {
        let (mechanism, details) = entry?;
        if mso_text(mechanism, "status mechanism")? == "status_list" {
            let mut idx = None;
            let mut uri = None;
            for entry in mso_map(details, "status.status_list")? {
                let (key, value) = entry?;
                match mso_text(key, "status_list key")? {
                    "idx" => {
                        idx = Some(
                            value
                                .as_integer()
                                .and_then(|value| u64::try_from(value).ok())
                                .ok_or_else(|| {
                                    mso_error("status.status_list.idx must be an unsigned integer")
                                })?,
                        );
                    }
                    "uri" => {
                        let value = mso_text(value, "status.status_list.uri")?;
                        iri_string::types::UriStr::new(value).map_err(|_| {
                            mso_error("status.status_list.uri must be an RFC 3986 URI")
                        })?;
                        uri = Some(value);
                    }
                    _ => {}
                }
            }
            status_list = Some(StatusListInfoRef {
                idx: required(idx, "status.status_list.idx")?,
                uri: required(uri, "status.status_list.uri")?,
            });
        }
    }
    Ok(MsoStatusRef {
        status_list,
        raw: CborValueRef::from_item(value),
    })
}

fn parse_validity_info(value: Item<'_>) -> Result<ValidityInfo, MdocError> {
    let mut signed = None;
    let mut valid_from = None;
    let mut valid_until = None;
    let mut expected_update = None;
    for entry in mso_map(value, "validityInfo")? {
        let (key, value) = entry?;
        let slot = match mso_text(key, "validityInfo key")? {
            "signed" => &mut signed,
            "validFrom" => &mut valid_from,
            "validUntil" => &mut valid_until,
            "expectedUpdate" => &mut expected_update,
            _ => return Err(mso_error("unsupported validityInfo member")),
        };
        *slot = Some(parse_datetime(value)?);
    }
    let validity = ValidityInfo {
        signed: required(signed, "validityInfo.signed")?,
        valid_from: required(valid_from, "validityInfo.validFrom")?,
        valid_until: required(valid_until, "validityInfo.validUntil")?,
        expected_update,
    };
    validity.validate()?;
    Ok(validity)
}

fn parse_datetime(value: Item<'_>) -> Result<crate::time::Timestamp, MdocError> {
    let (tag, inner) = value
        .tagged()
        .map_err(|_| mso_error("MSO timestamps require tdate (Tag 0)"))?;
    if tag != 0 {
        return Err(mso_error("MSO timestamps require tdate (Tag 0)"));
    }
    let text = mso_text(inner, "tdate content")?;
    if text.len() != 20 || !text.ends_with('Z') || text.as_bytes()[10] != b'T' {
        return Err(mso_error(
            "MSO timestamps require whole UTC seconds with Z offset",
        ));
    }
    crate::time::Timestamp::parse_rfc3339(text).map_err(|_| mso_error("invalid MSO timestamp"))
}

fn parse_device_key_info(value: Item<'_>) -> Result<DeviceKeyInfoRef<'_>, MdocError> {
    let mut device_key = None;
    let mut key_authorizations = None;
    let mut key_info = None;
    let mut additional_fields = HashMap::new();
    for entry in mso_map(value, "deviceKeyInfo")? {
        let (key, value) = entry?;
        let key = mso_text(key, "deviceKeyInfo key")?;
        match key {
            "deviceKey" => {
                device_key = Some(
                    CoseKeyRef::parse(value)
                        .map_err(|error| mso_error(format!("invalid device COSE_Key: {error}")))?,
                )
            }
            "keyAuthorizations" => key_authorizations = Some(parse_key_authorizations(value)?),
            "keyInfo" => {
                for entry in mso_map(value, "keyInfo")? {
                    if entry?.0.as_integer().is_none() {
                        return Err(mso_error("keyInfo labels must be integers"));
                    }
                }
                key_info = Some(CborValueRef::from_item(value));
            }
            _ => {
                additional_fields.insert(key, CborValueRef::from_item(value));
            }
        }
    }
    Ok(DeviceKeyInfoRef {
        device_key: required(device_key, "deviceKeyInfo.deviceKey")?,
        key_authorizations,
        key_info,
        additional_fields,
    })
}

fn parse_key_authorizations(value: Item<'_>) -> Result<KeyAuthorizationsRef<'_>, MdocError> {
    let mut name_spaces = None;
    let mut data_elements = None;
    let fields = mso_map(value, "keyAuthorizations")?;
    if fields.len() == 0 {
        return Err(mso_error("keyAuthorizations must not be empty"));
    }
    for entry in fields {
        let (key, value) = entry?;
        match mso_text(key, "keyAuthorizations key")? {
            "nameSpaces" => name_spaces = Some(parse_authorized_names(value)?),
            "dataElements" => {
                let namespaces = mso_map(value, "authorized dataElements")?;
                if namespaces.len() == 0 {
                    return Err(mso_error("authorized dataElements must not be empty"));
                }
                let mut elements = HashMap::with_capacity(namespaces.len());
                for entry in namespaces {
                    let (namespace, names) = entry?;
                    elements.insert(
                        mso_text(namespace, "authorized namespace")?,
                        parse_authorized_names(names)?,
                    );
                }
                data_elements = Some(elements);
            }
            _ => return Err(mso_error("unsupported keyAuthorizations member")),
        }
    }
    if let (Some(namespaces), Some(elements)) = (&name_spaces, &data_elements)
        && namespaces
            .iter()
            .any(|namespace| elements.contains_key(namespace))
    {
        return Err(mso_error(
            "keyAuthorizations namespace appears in both authorization forms",
        ));
    }
    Ok(KeyAuthorizationsRef {
        name_spaces,
        data_elements,
    })
}

fn parse_authorized_names(value: Item<'_>) -> Result<Vec<&str>, MdocError> {
    let values = value
        .array()
        .map_err(|_| mso_error("authorization list must be a nonempty array"))?;
    if values.len() == 0 {
        return Err(mso_error("authorization list must be a nonempty array"));
    }
    values
        .map(|value| mso_text(value?, "authorized name"))
        .collect()
}
