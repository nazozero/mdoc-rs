//! COSE authentication framing over borrowed message fragments.

use std::collections::BTreeSet;

use coset::iana::{EnumI64, WithPrivateRange};
use coset::{Header, Label, ProtectedHeader, RegisteredLabel, RegisteredLabelWithPrivate};

use crate::MdocError;
use crate::cbor::raw::{push_bytes, push_head, push_text};

/// Fixed CBOR framing for a four-field COSE authentication structure.
/// The protected header and payload stay in their original storage.
pub(crate) struct AuthenticationStructure {
    context: &'static [u8],
    protected_head: ([u8; 9], usize),
    payload_head: ([u8; 9], usize),
}

impl AuthenticationStructure {
    pub(crate) fn sign1(protected_len: usize, payload_len: usize) -> Self {
        Self::new(b"\x84\x6aSignature1", protected_len, payload_len)
    }

    pub(crate) fn mac0(protected_len: usize, payload_len: usize) -> Self {
        Self::new(b"\x84\x64MAC0", protected_len, payload_len)
    }

    fn new(context: &'static [u8], protected_len: usize, payload_len: usize) -> Self {
        Self {
            context,
            protected_head: crate::cbor::raw::cbor_head(2, protected_len as u64),
            payload_head: crate::cbor::raw::cbor_head(2, payload_len as u64),
        }
    }

    pub(crate) fn prefix<'a>(&'a self, protected: &'a [u8]) -> [&'a [u8]; 5] {
        [
            self.context,
            &self.protected_head.0[..self.protected_head.1],
            protected,
            &[0x40],
            &self.payload_head.0[..self.payload_head.1],
        ]
    }

    pub(crate) fn parts<'a>(&'a self, protected: &'a [u8], payload: &'a [u8]) -> [&'a [u8]; 6] {
        let [context, protected_head, protected, aad, payload_head] = self.prefix(protected);
        [
            context,
            protected_head,
            protected,
            aad,
            payload_head,
            payload,
        ]
    }
}

/// Use the original protected bytes, serializing only newly constructed headers.
pub(crate) fn with_protected_bytes<T>(
    protected: &ProtectedHeader,
    use_bytes: impl FnOnce(&[u8]) -> Result<T, MdocError>,
) -> Result<T, MdocError> {
    match &protected.original_data {
        Some(bytes) => use_bytes(bytes),
        None if protected.is_empty() => use_bytes(&[]),
        None => {
            let mut encoded = Vec::new();
            push_header(&mut encoded, &protected.header)?;
            use_bytes(&encoded)
        }
    }
}

/// Write a protected bucket, retaining received bytes before considering fields.
pub(crate) fn push_protected_header(
    out: &mut Vec<u8>,
    protected: &ProtectedHeader,
) -> Result<(), MdocError> {
    with_protected_bytes(protected, |bytes| {
        push_bytes(out, bytes);
        Ok(())
    })
}

/// Write coset's header layout directly from field references. In particular,
/// certificate chains and unknown values need no intermediate owned Value tree.
pub(crate) fn push_header(out: &mut Vec<u8>, header: &Header) -> Result<(), MdocError> {
    let entries = usize::from(header.alg.is_some())
        + usize::from(!header.crit.is_empty())
        + usize::from(header.content_type.is_some())
        + usize::from(!header.key_id.is_empty())
        + usize::from(!header.iv.is_empty())
        + usize::from(!header.partial_iv.is_empty())
        + usize::from(!header.counter_signatures.is_empty())
        + header.rest.len();
    push_head(out, 5, entries as u64);
    if let Some(algorithm) = &header.alg {
        out.push(0x01);
        push_registered_label(out, algorithm);
    }
    if !header.crit.is_empty() {
        out.push(0x02);
        push_head(out, 4, header.crit.len() as u64);
        for label in &header.crit {
            push_registered_label(out, label);
        }
    }
    if let Some(content_type) = &header.content_type {
        out.push(0x03);
        match content_type {
            RegisteredLabel::Assigned(value) => push_integer(out, value.to_i64()),
            RegisteredLabel::Text(value) => push_text(out, value),
        }
    }
    for (label, bytes) in [
        (0x04, &header.key_id),
        (0x05, &header.iv),
        (0x06, &header.partial_iv),
    ] {
        if !bytes.is_empty() {
            out.push(label);
            push_bytes(out, bytes);
        }
    }
    if !header.counter_signatures.is_empty() {
        out.push(0x07);
        if header.counter_signatures.len() > 1 {
            push_head(out, 4, header.counter_signatures.len() as u64);
        }
        for signature in &header.counter_signatures {
            out.push(0x83);
            push_protected_header(out, &signature.protected)?;
            push_header(out, &signature.unprotected)?;
            push_bytes(out, &signature.signature);
        }
    }
    let mut seen = BTreeSet::new();
    for (label, value) in &header.rest {
        // Match coset's duplicate-rest check without cloning labels. The usual
        // single x5chain entry does not need a set allocation.
        if header.rest.len() > 1 && !seen.insert(label) {
            return Err(coset::CoseError::DuplicateMapKey.into());
        }
        match label {
            Label::Int(value) => push_integer(out, *value),
            Label::Text(value) => push_text(out, value),
        }
        ciborium::into_writer(value, &mut *out)?;
    }
    Ok(())
}

fn push_integer(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        push_head(out, 0, value as u64);
    } else {
        push_head(out, 1, (-1 - value) as u64);
    }
}

fn push_registered_label<T: EnumI64 + WithPrivateRange>(
    out: &mut Vec<u8>,
    label: &RegisteredLabelWithPrivate<T>,
) {
    match label {
        RegisteredLabelWithPrivate::Assigned(value) => push_integer(out, value.to_i64()),
        RegisteredLabelWithPrivate::PrivateUse(value) => push_integer(out, *value),
        RegisteredLabelWithPrivate::Text(value) => push_text(out, value),
    }
}

/// Contiguous RFC 9052 signing input for an external signer.
#[cfg(any(feature = "issue", test))]
pub(crate) fn sign1_structure(
    protected: &ProtectedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, MdocError> {
    with_protected_bytes(protected, |bytes| {
        Ok(AuthenticationStructure::sign1(bytes.len(), payload.len())
            .parts(bytes, payload)
            .concat())
    })
}

#[cfg(test)]
fn mac0_structure(protected: &ProtectedHeader, payload: &[u8]) -> Result<Vec<u8>, MdocError> {
    with_protected_bytes(protected, |bytes| {
        Ok(AuthenticationStructure::mac0(bytes.len(), payload.len())
            .parts(bytes, payload)
            .concat())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;
    use coset::CborSerializable;

    fn assert_header_matches_coset(header: &Header) {
        let mut actual = vec![0xaa];
        push_header(&mut actual, header).unwrap();
        assert_eq!(actual[0], 0xaa);
        assert_eq!(actual[1..], header.clone().to_vec().unwrap());
    }

    #[test]
    fn borrowed_headers_match_coset_fields_extensions_and_countersignatures() {
        assert_header_matches_coset(&Header::default());
        let counter_signature = coset::CoseSignature {
            protected: ProtectedHeader {
                original_data: Some(hex::decode("a204430102030126").unwrap()),
                header: coset::HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::ES256)
                    .key_id(vec![1, 2, 3])
                    .build(),
            },
            unprotected: coset::HeaderBuilder::new().key_id(vec![0x42]).build(),
            signature: vec![0x55; 64],
        };
        let mut header = Header {
            alg: Some(coset::iana::Algorithm::ES256.into()),
            crit: vec![
                coset::iana::HeaderParameter::Alg.into(),
                RegisteredLabelWithPrivate::PrivateUse(i64::MIN),
                RegisteredLabelWithPrivate::Text("扩展".into()),
            ],
            content_type: Some(RegisteredLabel::Assigned(
                coset::iana::CoapContentFormat::Cbor,
            )),
            key_id: vec![0x11; 24],
            iv: vec![0x22; 12],
            // Serialization, like coset, leaves semantic validation to callers.
            partial_iv: vec![0x33; 5],
            rest: vec![
                (Label::Text("z".into()), Value::Integer(7.into())),
                (
                    Label::Int(33),
                    Value::Array(vec![
                        Value::Bytes(vec![0x44; 65_536]),
                        Value::Bytes(vec![0x45; 255]),
                    ]),
                ),
                (
                    Label::Text("a".into()),
                    Value::Tag(
                        42,
                        Box::new(Value::Map(vec![
                            (Value::Text("second".into()), Value::Bool(true)),
                            (Value::Text("first".into()), Value::Null),
                        ])),
                    ),
                ),
                (Label::Int(i64::MIN), Value::Integer(u64::MAX.into())),
                (Label::Int(i64::MAX), Value::Text("preserved".into())),
            ],
            ..Header::default()
        };
        for algorithm in [
            coset::iana::Algorithm::ES256.into(),
            RegisteredLabelWithPrivate::PrivateUse(i64::MIN),
            RegisteredLabelWithPrivate::PrivateUse(i64::MAX),
            RegisteredLabelWithPrivate::Text("custom-signature".into()),
        ] {
            header.alg = Some(algorithm);
            for count in 0..=2 {
                header.counter_signatures = vec![counter_signature.clone(); count];
                assert_header_matches_coset(&header);
            }
        }
        header.content_type = Some(RegisteredLabel::Text("application/example+cbor".into()));
        header.counter_signatures[0].protected.original_data = None;
        header.counter_signatures[1].protected.original_data = Some(Vec::new());
        assert_header_matches_coset(&header);
    }

    #[test]
    fn borrowed_header_duplicate_handling_matches_coset_serialization() {
        for label in [Label::Int(33), Label::Text("extension".into())] {
            let header = Header {
                rest: vec![(label.clone(), Value::Null), (label, Value::Bool(true))],
                ..Header::default()
            };
            let expected: MdocError = header.clone().to_vec().unwrap_err().into();
            let actual = push_header(&mut Vec::new(), &header).unwrap_err();
            assert_eq!(actual.to_string(), expected.to_string());
        }
        // coset checks duplicate labels within rest at serialization time;
        // the complete encoder separately validates duplicate map keys.
        assert_header_matches_coset(&Header {
            alg: Some(coset::iana::Algorithm::ES256.into()),
            rest: vec![(Label::Int(1), Value::Integer((-8).into()))],
            ..Header::default()
        });
    }

    #[test]
    fn inputs_match_independent_coset_encoding_at_length_boundaries() {
        let header = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .key_id(vec![1, 2, 3])
            .build();
        let protected = ProtectedHeader {
            header: header.clone(),
            // Deliberately use a different map order from coset's serializer.
            original_data: Some(hex::decode("a204430102030126").unwrap()),
        };
        for protected in [
            ProtectedHeader::default(),
            ProtectedHeader {
                header,
                original_data: None,
            },
            protected,
        ] {
            for size in [0, 23, 24, 255, 256, 65_535, 65_536] {
                let payload = vec![0x5a; size];
                assert_eq!(
                    sign1_structure(&protected, &payload).unwrap(),
                    coset::sig_structure_data(
                        coset::SignatureContext::CoseSign1,
                        protected.clone(),
                        None,
                        &[],
                        &payload,
                    )
                );
                assert_eq!(
                    mac0_structure(&protected, &payload).unwrap(),
                    coset::mac_structure_data(
                        coset::MacContext::CoseMac0,
                        protected.clone(),
                        &[],
                        &payload,
                    )
                );
            }
        }
    }

    #[test]
    fn received_empty_protected_bytes_are_retained() {
        let protected = ProtectedHeader {
            original_data: Some(Vec::new()),
            header: coset::HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES256)
                .build(),
        };
        assert_eq!(
            sign1_structure(&protected, &[]).unwrap(),
            hex::decode("846a5369676e617475726531404040").unwrap()
        );
    }
}
