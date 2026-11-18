//! Protocol models borrowing text, byte strings and claims from validated CBOR.

use std::collections::{HashMap, HashSet};

use coset::{
    AsCborValue,
    iana::{self, EnumI64, WithPrivateRange},
};

use super::*;
use crate::{MdocError, cbor::raw::Item};

/// One validated CBOR value, retaining its complete original encoding.
#[derive(Clone, Copy, Debug)]
pub struct CborValueRef<'a>(Item<'a>);

impl<'a> CborValueRef<'a> {
    pub fn parse(encoded: &'a [u8]) -> Result<Self, MdocError> {
        Item::parse(encoded).map(Self)
    }

    pub fn encoded(self) -> &'a [u8] {
        self.0.bytes()
    }
    pub fn as_bytes(self) -> Option<&'a [u8]> {
        self.0.as_bytes()
    }
    pub fn as_text(self) -> Option<&'a str> {
        self.0.as_text()
    }
    pub fn as_integer(self) -> Option<i128> {
        self.0.as_integer()
    }

    pub fn as_bool(self) -> Option<bool> {
        match self.encoded() {
            [0xf4] => Some(false),
            [0xf5] => Some(true),
            _ => None,
        }
    }

    pub fn as_float(self) -> Option<f64> {
        if !matches!(self.encoded()[0], 0xf9..=0xfb) {
            return None;
        }
        Some(ciborium::from_reader(self.encoded()).expect("validated CBOR float"))
    }

    pub fn is_null(self) -> bool {
        self.encoded() == [0xf6]
    }

    pub fn tagged(self) -> Result<(u64, Self), MdocError> {
        self.0.tagged().map(|(tag, inner)| (tag, Self(inner)))
    }

    /// Borrow the already validated CBOR value inside a Tag 24 byte string.
    pub fn embedded(self) -> Result<Self, MdocError> {
        self.0.embedded().map(Self)
    }

    /// Decode an owned value only when the caller needs independent storage.
    pub fn to_owned(self) -> Result<ciborium::Value, MdocError> {
        self.0.value()
    }

    pub fn array(
        self,
    ) -> Result<impl ExactSizeIterator<Item = Result<Self, MdocError>> + 'a, MdocError> {
        Ok(self.0.array()?.map(|item| item.map(Self)))
    }

    pub fn map(
        self,
    ) -> Result<impl ExactSizeIterator<Item = Result<(Self, Self), MdocError>> + 'a, MdocError>
    {
        Ok(self
            .0
            .map()?
            .map(|entry| entry.map(|(key, value)| (Self(key), Self(value)))))
    }

    pub(crate) fn from_item(item: Item<'a>) -> Self {
        Self(item)
    }
}

/// Integer or text COSE label with borrowed text storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoseLabelRef<'a> {
    Int(i64),
    Text(&'a str),
}

impl<'a> CoseLabelRef<'a> {
    fn parse(value: Item<'a>) -> Result<Self, MdocError> {
        if let Some(integer) = value.as_integer() {
            return i64::try_from(integer)
                .map(Self::Int)
                .map_err(|_| cose_error("COSE label exceeds signed integer range"));
        }
        value
            .as_text()
            .map(Self::Text)
            .ok_or_else(|| cose_error("COSE label must be integer or text"))
    }

    fn value(self) -> ciborium::Value {
        match self {
            Self::Int(value) => value.into(),
            Self::Text(value) => value.into(),
        }
    }

    fn into_owned(self) -> coset::Label {
        match self {
            Self::Int(value) => coset::Label::Int(value),
            Self::Text(value) => coset::Label::Text(value.to_owned()),
        }
    }
}

fn cose_error(message: &str) -> MdocError {
    MdocError::Cose(message.into())
}

fn registered_label<'a>(
    value: Item<'a>,
    accepts: impl FnOnce(i64) -> bool,
) -> Result<CoseLabelRef<'a>, MdocError> {
    let label = CoseLabelRef::parse(value)?;
    if let CoseLabelRef::Int(integer) = label
        && !accepts(integer)
    {
        return Err(cose_error("unregistered COSE label"));
    }
    Ok(label)
}

fn algorithm(value: Item<'_>) -> Result<CoseLabelRef<'_>, MdocError> {
    registered_label(value, |value| {
        iana::Algorithm::from_i64(value).is_some() || iana::Algorithm::is_private(value)
    })
}

fn nonempty_bytes(value: Item<'_>) -> Result<&[u8], MdocError> {
    let bytes = value.bstr()?;
    if bytes.is_empty() {
        return Err(cose_error("COSE byte string must not be empty"));
    }
    Ok(bytes)
}

/// Supported COSE header fields backed by the original CBOR.
#[derive(Clone, Debug, Default)]
pub struct CoseHeaderRef<'a> {
    pub alg: Option<CoseLabelRef<'a>>,
    pub crit: Vec<CoseLabelRef<'a>>,
    pub key_id: &'a [u8],
    pub x5chain: Option<CborValueRef<'a>>,
    pub(crate) labels: u64,
}

impl<'a> CoseHeaderRef<'a> {
    pub(crate) fn parse(header: Item<'a>) -> Result<Self, MdocError> {
        let mut result = Self::default();
        for entry in header.map()? {
            let (label, value) = entry?;
            let label = match label.uint() {
                Ok(label @ (1 | 2 | 4 | 33)) => label,
                _ => return Err(cose_error("unsupported COSE header extension")),
            };
            result.labels |= 1 << label;
            match label {
                1 => result.alg = Some(algorithm(value)?),
                2 => {
                    let labels = value.array()?;
                    if labels.len() == 0 {
                        return Err(cose_error("critical header list must not be empty"));
                    }
                    result.crit.reserve(labels.len());
                    for label in labels {
                        result.crit.push(registered_label(label?, |value| {
                            iana::HeaderParameter::from_i64(value).is_some()
                                || iana::HeaderParameter::is_private(value)
                        })?);
                    }
                }
                4 => result.key_id = nonempty_bytes(value)?,
                33 => result.x5chain = Some(CborValueRef(value)),
                _ => unreachable!("supported header label"),
            }
        }
        Ok(result)
    }

    pub fn into_owned(self) -> Result<coset::Header, MdocError> {
        Ok(coset::Header {
            alg: self
                .alg
                .map(|value| coset::Algorithm::from_cbor_value(value.value()))
                .transpose()?,
            crit: self
                .crit
                .into_iter()
                .map(|value| {
                    coset::RegisteredLabelWithPrivate::<iana::HeaderParameter>::from_cbor_value(
                        value.value(),
                    )
                    .map_err(MdocError::from)
                })
                .collect::<Result<_, _>>()?,
            key_id: self.key_id.to_vec(),
            rest: self
                .x5chain
                .map(|value| value.to_owned().map(|value| (coset::Label::Int(33), value)))
                .transpose()?
                .into_iter()
                .collect(),
            ..Default::default()
        })
    }
}

/// A COSE_Sign1 whose authenticated byte strings borrow the input.
#[derive(Clone, Debug)]
pub struct CoseSign1Ref<'a> {
    pub protected: &'a [u8],
    pub protected_header: CoseHeaderRef<'a>,
    pub unprotected: CoseHeaderRef<'a>,
    pub payload: Option<&'a [u8]>,
    pub signature: &'a [u8],
}

impl CoseSign1Ref<'_> {
    pub fn into_owned(self) -> Result<coset::CoseSign1, MdocError> {
        Ok(coset::CoseSign1 {
            protected: coset::ProtectedHeader {
                original_data: Some(self.protected.to_vec()),
                header: self.protected_header.into_owned()?,
            },
            unprotected: self.unprotected.into_owned()?,
            payload: self.payload.map(<[u8]>::to_vec),
            signature: self.signature.to_vec(),
        })
    }
}

/// A COSE_Mac0 whose authenticated byte strings borrow the input.
#[derive(Clone, Debug)]
pub struct CoseMac0Ref<'a> {
    pub protected: &'a [u8],
    pub protected_header: CoseHeaderRef<'a>,
    pub unprotected: CoseHeaderRef<'a>,
    pub payload: Option<&'a [u8]>,
    pub tag: &'a [u8],
}

impl CoseMac0Ref<'_> {
    pub fn into_owned(self) -> Result<coset::CoseMac0, MdocError> {
        Ok(coset::CoseMac0 {
            protected: coset::ProtectedHeader {
                original_data: Some(self.protected.to_vec()),
                header: self.protected_header.into_owned()?,
            },
            unprotected: self.unprotected.into_owned()?,
            payload: self.payload.map(<[u8]>::to_vec),
            tag: self.tag.to_vec(),
        })
    }
}

/// COSE key metadata and parameters borrowing the original MSO.
#[derive(Clone, Debug)]
pub struct CoseKeyRef<'a> {
    pub kty: CoseLabelRef<'a>,
    pub key_id: &'a [u8],
    pub alg: Option<CoseLabelRef<'a>>,
    pub key_ops: Vec<CoseLabelRef<'a>>,
    pub base_iv: &'a [u8],
    pub params: Vec<(CoseLabelRef<'a>, CborValueRef<'a>)>,
}

impl<'a> CoseKeyRef<'a> {
    pub(crate) fn parse(value: Item<'a>) -> Result<Self, MdocError> {
        let mut kty = None;
        let mut key = Self {
            kty: CoseLabelRef::Int(0),
            key_id: &[],
            alg: None,
            key_ops: Vec::new(),
            base_iv: &[],
            params: Vec::new(),
        };
        for entry in value.map()? {
            let (label, value) = entry?;
            match CoseLabelRef::parse(label)? {
                CoseLabelRef::Int(1) => {
                    kty = Some(registered_label(value, |value| {
                        iana::KeyType::from_i64(value).is_some()
                    })?)
                }
                CoseLabelRef::Int(2) => key.key_id = nonempty_bytes(value)?,
                CoseLabelRef::Int(3) => key.alg = Some(algorithm(value)?),
                CoseLabelRef::Int(4) => {
                    let operations = value.array()?;
                    if operations.len() == 0 {
                        return Err(cose_error("key_ops must not be empty"));
                    }
                    let mut seen = HashSet::with_capacity(operations.len());
                    key.key_ops.reserve(operations.len());
                    for operation in operations {
                        let operation = registered_label(operation?, |value| {
                            iana::KeyOperation::from_i64(value).is_some()
                        })?;
                        if !seen.insert(operation) {
                            return Err(cose_error("duplicate key_ops entry"));
                        }
                        key.key_ops.push(operation);
                    }
                }
                CoseLabelRef::Int(5) => key.base_iv = nonempty_bytes(value)?,
                label => key.params.push((label, CborValueRef(value))),
            }
        }
        key.kty = kty
            .filter(|key| *key != CoseLabelRef::Int(0))
            .ok_or_else(|| cose_error("missing COSE key type"))?;
        Ok(key)
    }

    pub fn into_owned(self) -> Result<coset::CoseKey, MdocError> {
        let mut key_ops = std::collections::BTreeSet::new();
        for operation in self.key_ops {
            let operation = coset::KeyOperation::from_cbor_value(operation.value())?;
            if !key_ops.insert(operation) {
                return Err(cose_error("duplicate key_ops entry"));
            }
        }
        Ok(coset::CoseKey {
            kty: coset::KeyType::from_cbor_value(self.kty.value())?,
            key_id: self.key_id.to_vec(),
            alg: self
                .alg
                .map(|value| coset::Algorithm::from_cbor_value(value.value()))
                .transpose()?,
            key_ops,
            base_iv: self.base_iv.to_vec(),
            params: self
                .params
                .into_iter()
                .map(|(label, value)| Ok((label.into_owned(), value.to_owned()?)))
                .collect::<Result<_, MdocError>>()?,
        })
    }
}

#[derive(Clone, Debug)]
pub enum DeviceAuthRef<'a> {
    Signature(CoseSign1Ref<'a>),
    Mac(CoseMac0Ref<'a>),
}

impl DeviceAuthRef<'_> {
    pub fn into_owned(self) -> Result<DeviceAuth, MdocError> {
        Ok(match self {
            Self::Signature(value) => DeviceAuth::Signature(value.into_owned()?),
            Self::Mac(value) => DeviceAuth::Mac(value.into_owned()?),
        })
    }
}

#[derive(Clone, Debug)]
pub struct IssuerAuthRef<'a> {
    pub cose_sign1: CoseSign1Ref<'a>,
    // Proof for the exact immutable payload checked under default or stricter
    // limits. It is never exposed as an unchecked CBOR constructor.
    pub(crate) validated_mso_payload: Option<Item<'a>>,
}

impl<'a> IssuerAuthRef<'a> {
    pub fn mso(&self) -> Result<MsoRef<'a>, MdocError> {
        MsoRef::parse(
            self.cose_sign1
                .payload
                .ok_or_else(|| MdocError::Mso("missing COSE_Sign1 payload".into()))?,
        )
    }

    pub(crate) fn parsed_mso(&self) -> Result<MsoRef<'a>, MdocError> {
        if let Some(validated) = self.validated_mso_payload
            && self.cose_sign1.payload.is_some_and(|current| {
                // Both address and length must match: public fields can be
                // replaced, while the original borrowed bytes stay immutable.
                std::ptr::eq(current, validated.bytes())
            })
        {
            return super::issuer_auth::parse_mso_ref(validated.embedded()?);
        }
        self.mso()
    }

    pub fn certificate_chain_der(&self) -> Result<Vec<&'a [u8]>, MdocError> {
        let error = || {
            MdocError::Certificate(
                "x5chain must contain nonempty DER byte strings in the unprotected header".into(),
            )
        };
        if self.cose_sign1.protected_header.x5chain.is_some() {
            return Err(error());
        }
        let value = self.cose_sign1.unprotected.x5chain.ok_or_else(error)?;
        if let Some(bytes) = value.as_bytes() {
            if bytes.is_empty() {
                return Err(error());
            }
            return Ok(vec![bytes]);
        }
        let entries = value.array().map_err(|_| error())?;
        if entries.len() == 0 {
            return Err(error());
        }
        entries
            .map(|entry| {
                entry?
                    .as_bytes()
                    .filter(|bytes| !bytes.is_empty())
                    .ok_or_else(error)
            })
            .collect()
    }

    pub fn into_owned(self) -> Result<IssuerAuth, MdocError> {
        Ok(IssuerAuth::new(self.cose_sign1.into_owned()?))
    }
}

#[derive(Clone, Debug)]
pub struct DeviceResponseRef<'a> {
    pub version: &'a str,
    pub status: DeviceResponseStatus,
    pub documents: Vec<IssuerSignedDocumentRef<'a>>,
}

impl DeviceResponseRef<'_> {
    pub fn into_owned(self) -> Result<DeviceResponse, MdocError> {
        Ok(DeviceResponse {
            version: self.version.to_owned(),
            status: self.status,
            documents: self
                .documents
                .into_iter()
                .map(IssuerSignedDocumentRef::into_owned)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct IssuerSignedDocumentRef<'a> {
    pub doc_type: &'a str,
    pub issuer_signed: IssuerSignedRef<'a>,
    pub device_signed: Option<DeviceSignedRef<'a>>,
}

impl IssuerSignedDocumentRef<'_> {
    pub fn into_owned(self) -> Result<IssuerSignedDocument, MdocError> {
        Ok(IssuerSignedDocument {
            doc_type: self.doc_type.to_owned(),
            issuer_signed: self.issuer_signed.into_owned()?,
            device_signed: self
                .device_signed
                .map(DeviceSignedRef::into_owned)
                .transpose()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct IssuerSignedRef<'a> {
    pub issuer_auth: IssuerAuthRef<'a>,
    pub name_spaces: HashMap<&'a str, Vec<IssuerSignedItemRef<'a>>>,
}

impl IssuerSignedRef<'_> {
    pub fn into_owned(self) -> Result<IssuerSigned, MdocError> {
        Ok(IssuerSigned {
            issuer_auth: self.issuer_auth.into_owned()?,
            name_spaces: self
                .name_spaces
                .into_iter()
                .map(|(namespace, items)| {
                    Ok((
                        namespace.to_owned(),
                        items
                            .into_iter()
                            .map(IssuerSignedItemRef::into_owned)
                            .collect::<Result<_, _>>()?,
                    ))
                })
                .collect::<Result<_, MdocError>>()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IssuerSignedItemRef<'a> {
    pub digest_id: u32,
    pub random: &'a [u8],
    pub element_identifier: &'a str,
    pub element_value: CborValueRef<'a>,
    pub encoded: &'a [u8],
}

impl IssuerSignedItemRef<'_> {
    pub fn verify_digest(&self, expected: &[u8], algorithm: &DigestAlgorithm) -> bool {
        super::issuer_signed_item::digest_matches(self.encoded, expected, algorithm)
    }

    pub fn into_owned(self) -> Result<IssuerSignedItem, MdocError> {
        Ok(IssuerSignedItem {
            digest_id: self.digest_id,
            random: self.random.to_vec(),
            element_identifier: self.element_identifier.to_owned(),
            element_value: self.element_value.to_owned()?,
            encoded: self.encoded.to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct DeviceSignedRef<'a> {
    pub device_auth: DeviceAuthRef<'a>,
    pub name_spaces: HashMap<&'a str, HashMap<&'a str, CborValueRef<'a>>>,
    pub name_spaces_bytes: &'a [u8],
}

impl DeviceSignedRef<'_> {
    pub fn into_owned(self) -> Result<DeviceSigned, MdocError> {
        Ok(DeviceSigned {
            device_auth: self.device_auth.into_owned()?,
            name_spaces: self
                .name_spaces
                .into_iter()
                .map(|(namespace, elements)| {
                    Ok((
                        namespace.to_owned(),
                        elements
                            .into_iter()
                            .map(|(name, value)| Ok((name.to_owned(), value.to_owned()?)))
                            .collect::<Result<_, MdocError>>()?,
                    ))
                })
                .collect::<Result<_, MdocError>>()?,
            name_spaces_bytes: self.name_spaces_bytes.to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct MsoRef<'a> {
    pub version: &'a str,
    pub digest_algorithm: DigestAlgorithm,
    pub doc_type: &'a str,
    pub validity_info: ValidityInfo,
    pub value_digests: HashMap<&'a str, HashMap<u32, &'a [u8]>>,
    pub device_key_info: DeviceKeyInfoRef<'a>,
    pub status: Option<MsoStatusRef<'a>>,
    pub additional_fields: HashMap<&'a str, CborValueRef<'a>>,
}

impl<'a> MsoRef<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<Self, MdocError> {
        super::issuer_auth::parse_mso_ref(Item::parse(payload)?.embedded()?)
    }

    pub fn into_owned(self) -> Result<Mso, MdocError> {
        Ok(Mso {
            version: self.version.to_owned(),
            digest_algorithm: self.digest_algorithm,
            doc_type: self.doc_type.to_owned(),
            validity_info: self.validity_info,
            value_digests: self
                .value_digests
                .into_iter()
                .map(|(namespace, values)| {
                    (
                        namespace.to_owned(),
                        values
                            .into_iter()
                            .map(|(id, bytes)| (id, bytes.to_vec()))
                            .collect(),
                    )
                })
                .collect(),
            device_key_info: self.device_key_info.into_owned()?,
            status: self.status.map(MsoStatusRef::into_owned).transpose()?,
            additional_fields: own_fields(self.additional_fields)?,
        })
    }
}

fn own_fields(
    fields: HashMap<&str, CborValueRef<'_>>,
) -> Result<HashMap<String, ciborium::Value>, MdocError> {
    fields
        .into_iter()
        .map(|(key, value)| Ok((key.to_owned(), value.to_owned()?)))
        .collect()
}

#[derive(Clone, Debug)]
pub struct DeviceKeyInfoRef<'a> {
    pub device_key: CoseKeyRef<'a>,
    pub key_authorizations: Option<KeyAuthorizationsRef<'a>>,
    pub key_info: Option<CborValueRef<'a>>,
    pub additional_fields: HashMap<&'a str, CborValueRef<'a>>,
}

impl DeviceKeyInfoRef<'_> {
    pub fn into_owned(self) -> Result<DeviceKeyInfo, MdocError> {
        Ok(DeviceKeyInfo {
            device_key: self.device_key.into_owned()?,
            key_authorizations: self
                .key_authorizations
                .map(KeyAuthorizationsRef::into_owned),
            key_info: self.key_info.map(CborValueRef::to_owned).transpose()?,
            additional_fields: own_fields(self.additional_fields)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct KeyAuthorizationsRef<'a> {
    pub name_spaces: Option<Vec<&'a str>>,
    pub data_elements: Option<HashMap<&'a str, Vec<&'a str>>>,
}

impl KeyAuthorizationsRef<'_> {
    pub fn into_owned(self) -> KeyAuthorizations {
        KeyAuthorizations {
            name_spaces: self
                .name_spaces
                .map(|values| values.into_iter().map(str::to_owned).collect()),
            data_elements: self.data_elements.map(|values| {
                values
                    .into_iter()
                    .map(|(namespace, values)| {
                        (
                            namespace.to_owned(),
                            values.into_iter().map(str::to_owned).collect(),
                        )
                    })
                    .collect()
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MsoStatusRef<'a> {
    pub status_list: Option<StatusListInfoRef<'a>>,
    pub raw: CborValueRef<'a>,
}

impl MsoStatusRef<'_> {
    pub fn into_owned(self) -> Result<MsoStatus, MdocError> {
        Ok(MsoStatus {
            status_list: self.status_list.map(|value| StatusListInfo {
                idx: value.idx,
                uri: value.uri.to_owned(),
            }),
            raw: self.raw.to_owned()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StatusListInfoRef<'a> {
    pub idx: u64,
    pub uri: &'a str,
}

#[cfg(test)]
mod tests {
    #[test]
    fn parsed_mso_proof_cannot_be_reused_for_a_replaced_payload() {
        let input = hex::decode(
            include_str!("../../tests/vectors/iso_18013_5_annex_d_mdl.hex")
                .split_whitespace()
                .collect::<String>(),
        )
        .unwrap();
        let mut response = crate::parser::parse_borrowed(&input).unwrap();
        let auth = &mut response.documents[0].issuer_signed.issuer_auth;
        let original = auth.cose_sign1.payload.unwrap();
        assert!(auth.parsed_mso().is_ok());

        // A shorter slice has the same address, but is not the validated item.
        auth.cose_sign1.payload = Some(&original[..original.len() - 1]);
        assert!(auth.parsed_mso().is_err());
        auth.cose_sign1.payload = None;
        assert!(auth.parsed_mso().is_err());
        auth.cose_sign1.payload = Some(&[0xd8, 0x18, 0x41, 0xff]);
        assert!(auth.parsed_mso().is_err());

        // Equal contents in a new buffer must produce references to that buffer.
        let replacement = original.to_vec();
        auth.cose_sign1.payload = Some(&replacement);
        let mso = auth.parsed_mso().unwrap();
        let start = replacement.as_ptr() as usize;
        let doc_type = mso.doc_type.as_ptr() as usize;
        assert!(doc_type >= start && doc_type + mso.doc_type.len() <= start + replacement.len());
    }
}
