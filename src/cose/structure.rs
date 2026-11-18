//! COSE authentication inputs with borrowed protected headers and payloads.

use std::borrow::Cow;

use coset::{CborSerializable, ProtectedHeader};

use crate::MdocError;
use crate::cbor::raw::{push_bytes, push_text};

/// RFC 9052 §4.4, COSE_Sign1 with empty external AAD.
pub(crate) fn sign1_structure(
    protected: &ProtectedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, MdocError> {
    authentication_structure("Signature1", protected, payload)
}

/// RFC 9052 §6.3, COSE_Mac0 with empty external AAD.
pub(crate) fn mac0_structure(
    protected: &ProtectedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, MdocError> {
    authentication_structure("MAC0", protected, payload)
}

fn authentication_structure(
    context: &str,
    protected: &ProtectedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, MdocError> {
    let bytes = match &protected.original_data {
        Some(bytes) => Cow::Borrowed(bytes.as_slice()),
        None if protected.is_empty() => Cow::Borrowed(&[][..]),
        None => Cow::Owned(protected.header.clone().to_vec()?),
    };
    // Four-element array, context, two bstr headers and empty external AAD.
    let mut out = Vec::with_capacity(context.len() + bytes.len() + payload.len() + 21);
    out.push(0x84);
    push_text(&mut out, context);
    push_bytes(&mut out, &bytes);
    out.push(0x40);
    push_bytes(&mut out, payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
