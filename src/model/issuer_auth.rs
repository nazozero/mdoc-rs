//! IssuerAuth — COSE_Sign1 with strict MSO parsing and untrusted certificates.

use super::types::{
    DeviceKeyInfo, DigestAlgorithm, KeyAuthorizations, Mso, MsoStatus, StatusListInfo, ValidityInfo,
};
use crate::error::MdocError;
use ciborium::Value;
use coset::{AsCborValue, CoseKey, CoseSign1};
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
        let mso = crate::cbor::raw::Item::parse(payload)?
            .embedded()?
            .value()?;
        parse_mso_value(mso)
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

fn as_map<'a>(value: &'a Value, field: &str) -> Result<&'a [(Value, Value)], MdocError> {
    value
        .as_map()
        .map(Vec::as_slice)
        .ok_or_else(|| mso_error(format!("{field} is not a CBOR map")))
}

fn as_text<'a>(value: &'a Value, field: &str) -> Result<&'a str, MdocError> {
    value
        .as_text()
        .ok_or_else(|| mso_error(format!("{field} is not text")))
}

fn into_map(value: Value, field: &str) -> Result<Vec<(Value, Value)>, MdocError> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(mso_error(format!("{field} is not a CBOR map"))),
    }
}

fn into_text(value: Value, field: &str) -> Result<String, MdocError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(mso_error(format!("{field} is not text"))),
    }
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, MdocError> {
    value.ok_or_else(|| mso_error(format!("missing {field}")))
}

/// Project an MSO whose complete encoding has passed raw CBOR validation,
/// establishing unique map keys including extension values.
pub(crate) fn parse_mso_value(value: Value) -> Result<Mso, MdocError> {
    let mut version = None;
    let mut digest_algorithm = None;
    let mut doc_type = None;
    let mut validity_info = None;
    let mut value_digests = None;
    let mut device_key_info = None;
    let mut status = None;
    let mut additional_fields = HashMap::new();

    for (key, value) in into_map(value, "MSO")? {
        let key = into_text(key, "MSO key")?;
        match key.as_str() {
            "version" => version = Some(into_text(value, &key)?),
            "digestAlgorithm" => {
                let name = into_text(value, &key)?;
                let algorithm = DigestAlgorithm::from_str_name(&name)
                    .ok_or(MdocError::UnsupportedAlgorithm(name))?;
                digest_algorithm = Some(algorithm);
            }
            "docType" => doc_type = Some(into_text(value, &key)?),
            "validityInfo" => validity_info = Some(parse_validity_info(value)?),
            "valueDigests" => value_digests = Some(parse_value_digests(value)?),
            "deviceKeyInfo" => device_key_info = Some(parse_device_key_info(value)?),
            "status" => status = Some(parse_status(value)?),
            _ => {
                additional_fields.insert(key, value);
            }
        }
    }

    let version = required(version, "version")?;
    if !super::types::supports_version(&version) {
        return Err(mso_error("unsupported MSO version"));
    }
    let digest_algorithm = required(digest_algorithm, "digestAlgorithm")?;
    let value_digests: HashMap<String, HashMap<u32, Vec<u8>>> =
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
    Ok(Mso {
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

fn parse_value_digests(value: Value) -> Result<HashMap<String, HashMap<u32, Vec<u8>>>, MdocError> {
    let namespaces = into_map(value, "valueDigests")?;
    if namespaces.is_empty() {
        return Err(mso_error("valueDigests must not be empty"));
    }
    let mut result = HashMap::with_capacity(namespaces.len());
    for (namespace, values) in namespaces {
        let namespace = into_text(namespace, "valueDigests namespace")?;
        let values = into_map(values, "namespace digests")?;
        if values.is_empty() {
            return Err(mso_error("namespace digests must not be empty"));
        }
        let mut digests = HashMap::with_capacity(values.len());
        for (id, digest) in values {
            let id = id
                .as_integer()
                .and_then(|id| u32::try_from(id).ok())
                .filter(|id| *id < 1 << 31)
                .ok_or_else(|| mso_error("digestID must be an unsigned integer below 2^31"))?;
            let Value::Bytes(digest) = digest else {
                return Err(mso_error("digest value is not bytes"));
            };
            digests.insert(id, digest);
        }
        result.insert(namespace, digests);
    }
    Ok(result)
}

// The MSO decoder validates raw CBOR before this projection. Issuance validates
// the resulting encoding before returning a prepared operation.
pub(crate) fn parse_status(value: Value) -> Result<MsoStatus, MdocError> {
    let mechanisms = as_map(&value, "status")?;
    if mechanisms.is_empty() {
        return Err(mso_error("status must contain at least one mechanism"));
    }
    let mut status_list = None;
    for (mechanism, details) in mechanisms {
        if as_text(mechanism, "status mechanism")? == "status_list" {
            let mut idx = None;
            let mut uri = None;
            for (key, value) in as_map(details, "status.status_list")? {
                let key = as_text(key, "status_list key")?;
                match key {
                    "idx" => {
                        let index = value
                            .as_integer()
                            .and_then(|value| u64::try_from(value).ok())
                            .ok_or_else(|| {
                                mso_error("status.status_list.idx must be an unsigned integer")
                            })?;
                        idx = Some(index);
                    }
                    "uri" => {
                        let value = as_text(value, "status.status_list.uri")?;
                        iri_string::types::UriStr::new(value).map_err(|_| {
                            mso_error("status.status_list.uri must be an RFC 3986 URI")
                        })?;
                        uri = Some(value.to_owned());
                    }
                    _ => {} // Retained in `raw`; application policy decides.
                }
            }
            status_list = Some(StatusListInfo {
                idx: required(idx, "status.status_list.idx")?,
                uri: required(uri, "status.status_list.uri")?,
            });
        }
    }
    Ok(MsoStatus {
        status_list,
        raw: value,
    })
}

fn parse_validity_info(value: Value) -> Result<ValidityInfo, MdocError> {
    let mut signed = None;
    let mut valid_from = None;
    let mut valid_until = None;
    let mut expected_update = None;
    for (key, value) in into_map(value, "validityInfo")? {
        let key = into_text(key, "validityInfo key")?;
        let slot = match key.as_str() {
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

fn parse_datetime(value: Value) -> Result<crate::time::Timestamp, MdocError> {
    let Value::Tag(0, inner) = value else {
        return Err(mso_error("MSO timestamps require tdate (Tag 0)"));
    };
    let text = into_text(*inner, "tdate content")?;
    if text.len() != 20 || !text.ends_with('Z') || text.as_bytes()[10] != b'T' {
        return Err(mso_error(
            "MSO timestamps require whole UTC seconds with Z offset",
        ));
    }
    crate::time::Timestamp::parse_rfc3339(&text).map_err(|_| mso_error("invalid MSO timestamp"))
}

fn parse_device_key_info(value: Value) -> Result<DeviceKeyInfo, MdocError> {
    let mut device_key = None;
    let mut key_authorizations = None;
    let mut key_info = None;
    let mut additional_fields = HashMap::new();
    for (key, value) in into_map(value, "deviceKeyInfo")? {
        let key = into_text(key, "deviceKeyInfo key")?;
        match key.as_str() {
            "deviceKey" => {
                let key = CoseKey::from_cbor_value(value)
                    .map_err(|error| mso_error(format!("invalid device COSE_Key: {error}")))?;
                device_key = Some(key);
            }
            "keyAuthorizations" => key_authorizations = Some(parse_key_authorizations(value)?),
            "keyInfo" => {
                for (label, _) in as_map(&value, "keyInfo")? {
                    if label.as_integer().is_none() {
                        return Err(mso_error("keyInfo labels must be integers"));
                    }
                }
                key_info = Some(value);
            }
            _ => {
                additional_fields.insert(key, value);
            }
        }
    }
    Ok(DeviceKeyInfo {
        device_key: required(device_key, "deviceKeyInfo.deviceKey")?,
        key_authorizations,
        key_info,
        additional_fields,
    })
}

fn parse_key_authorizations(value: Value) -> Result<KeyAuthorizations, MdocError> {
    let mut name_spaces = None;
    let mut data_elements = None;
    let fields = into_map(value, "keyAuthorizations")?;
    if fields.is_empty() {
        return Err(mso_error("keyAuthorizations must not be empty"));
    }
    for (key, value) in fields {
        let key = into_text(key, "keyAuthorizations key")?;
        match key.as_str() {
            "nameSpaces" => name_spaces = Some(parse_authorized_names(value)?),
            "dataElements" => {
                let namespaces = into_map(value, "authorized dataElements")?;
                if namespaces.is_empty() {
                    return Err(mso_error("authorized dataElements must not be empty"));
                }
                let mut elements = HashMap::with_capacity(namespaces.len());
                for (namespace, names) in namespaces {
                    let namespace = into_text(namespace, "authorized namespace")?;
                    elements.insert(namespace, parse_authorized_names(names)?);
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
    Ok(KeyAuthorizations {
        name_spaces,
        data_elements,
    })
}

fn parse_authorized_names(value: Value) -> Result<Vec<String>, MdocError> {
    let Value::Array(values) = value else {
        return Err(mso_error("authorization list must be a nonempty array"));
    };
    if values.is_empty() {
        return Err(mso_error("authorization list must be a nonempty array"));
    }
    values
        .into_iter()
        .map(|value| into_text(value, "authorized name"))
        .collect()
}
