//! COSE key and signature utilities for mdoc.

use crate::error::MdocError;
use coset::{AsCborValue, RegisteredLabelWithPrivate, iana};

pub mod key;
mod structure;
mod verify;

pub use key::{CoseKeyExt, cose_alg_to_name};
pub(crate) use structure::{mac0_structure, sign1_structure};
pub use verify::{validate_verification_key, verify_cose_signature};

/// Check wire labels and decode without normalizing tags into field types.
/// The bitset records the labels that actually occurred on the wire.
pub(crate) fn parse_header(
    header: crate::cbor::raw::Item<'_>,
) -> Result<(u64, coset::Header), MdocError> {
    let mut labels = 0u64;
    for entry in header.map()? {
        let (label, _) = entry?;
        let label = match label.uint() {
            Ok(label @ (1 | 2 | 4 | 33)) => label,
            _ => return Err(MdocError::Cose("unsupported COSE header extension".into())),
        };
        labels |= 1 << label;
    }
    Ok((labels, coset::Header::from_cbor_value(header.value()?)?))
}

/// Validate a signature/MAC header without silently accepting security extensions.
pub(crate) fn validate_headers(
    protected: &coset::ProtectedHeader,
    unprotected: &coset::Header,
) -> Result<i64, MdocError> {
    let mut original_labels = 0;
    if let Some(original) = &protected.original_data {
        let decoded = if original.is_empty() {
            coset::Header::default()
        } else {
            let (labels, decoded) = parse_header(crate::cbor::raw::Item::parse(original)?)?;
            original_labels = labels;
            decoded
        };
        if decoded != protected.header {
            return Err(MdocError::Cose(
                "protected header differs from original signed bytes".into(),
            ));
        }
    }
    validate_critical_headers(protected, unprotected)?;
    if unprotected.alg.is_some() {
        return Err(MdocError::Cose(
            "alg must occur only in the protected bucket".into(),
        ));
    }
    let algorithm = match protected.header.alg {
        Some(coset::Algorithm::Assigned(value)) => value as i64,
        _ => {
            return Err(MdocError::Cose(
                "missing or unsupported protected algorithm".into(),
            ));
        }
    };
    let mut seen = 0u64;
    for (index, header) in [&protected.header, unprotected].into_iter().enumerate() {
        // Only alg, crit, kid and x5chain are processed by this profile.
        if header.content_type.is_some()
            || !header.iv.is_empty()
            || !header.partial_iv.is_empty()
            || !header.counter_signatures.is_empty()
        {
            return Err(MdocError::Cose("unsupported COSE security header".into()));
        }
        let has_key_id =
            !header.key_id.is_empty() || (index == 0 && original_labels & (1 << 4) != 0);
        if has_key_id {
            if seen & (1 << 4) != 0 {
                return Err(MdocError::Cose(
                    "duplicate header across protected/unprotected buckets".into(),
                ));
            }
            seen |= 1 << 4;
        }
        for (label, _) in &header.rest {
            if *label != coset::Label::Int(33) {
                return Err(MdocError::Cose("unsupported COSE header extension".into()));
            }
            if seen & (1 << 33) != 0 {
                return Err(MdocError::Cose(
                    "duplicate header across protected/unprotected buckets".into(),
                ));
            }
            seen |= 1 << 33;
        }
    }
    Ok(algorithm)
}

/// Validate the COSE critical-header contract implemented by this crate.
///
/// RFC 9052 requires every entry in `crit` to name a protected header that the
/// recipient understands and processes. This profile currently processes only the
/// protected `alg` header, so all other assigned, text, and private-use labels
/// fail closed. A `crit` parameter in the unprotected bucket is always invalid.
pub(crate) fn validate_critical_headers(
    protected: &coset::ProtectedHeader,
    unprotected: &coset::Header,
) -> Result<(), MdocError> {
    if !unprotected.crit.is_empty() {
        return Err(MdocError::Cose(
            "critical headers must be in the protected header bucket".to_string(),
        ));
    }

    for label in &protected.header.crit {
        match label {
            RegisteredLabelWithPrivate::Assigned(iana::HeaderParameter::Alg) => {
                if protected.header.alg.is_none() {
                    return Err(MdocError::Cose(
                        "critical alg header is not present in the protected bucket".to_string(),
                    ));
                }
            }
            RegisteredLabelWithPrivate::Assigned(parameter) => {
                return Err(MdocError::Cose(format!(
                    "unsupported critical COSE header parameter: {parameter:?}"
                )));
            }
            RegisteredLabelWithPrivate::PrivateUse(value) => {
                return Err(MdocError::Cose(format!(
                    "unsupported private-use critical COSE header parameter: {value}"
                )));
            }
            RegisteredLabelWithPrivate::Text(value) => {
                return Err(MdocError::Cose(format!(
                    "unsupported text critical COSE header parameter: {value}"
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CborSerializable;

    #[test]
    fn accepts_present_protected_alg_as_understood_critical_header() {
        let protected = coset::ProtectedHeader {
            original_data: None,
            header: coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .add_critical(iana::HeaderParameter::Alg)
                .build(),
        };

        assert!(validate_critical_headers(&protected, &coset::Header::default()).is_ok());
    }

    #[test]
    fn rejects_private_use_critical_header() {
        let protected = coset::ProtectedHeader {
            original_data: None,
            header: coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(-65_537))
                .build(),
        };

        let error = validate_critical_headers(&protected, &coset::Header::default())
            .expect_err("private-use critical labels are not implemented");
        assert!(error.to_string().contains("private-use critical"));
    }

    #[test]
    fn rejects_critical_header_from_unprotected_bucket() {
        let protected = coset::ProtectedHeader::default();
        let unprotected = coset::HeaderBuilder::new()
            .add_critical(iana::HeaderParameter::Alg)
            .build();

        let error = validate_critical_headers(&protected, &unprotected)
            .expect_err("crit is required to be integrity protected");
        assert!(error.to_string().contains("protected header bucket"));
    }

    #[test]
    fn rejects_critical_alg_when_alg_header_is_absent() {
        let protected = coset::ProtectedHeader {
            original_data: None,
            header: coset::HeaderBuilder::new()
                .add_critical(iana::HeaderParameter::Alg)
                .build(),
        };

        let error = validate_critical_headers(&protected, &coset::Header::default())
            .expect_err("a critical label must name a present protected header");
        assert!(error.to_string().contains("is not present"));
    }

    #[test]
    fn serialized_empty_critical_array_is_rejected_during_cose_parse() {
        // COSE_Sign1 = [h'a10280', {}, nil, h'']: protected { 2: [] }.
        let encoded = [0x84, 0x43, 0xa1, 0x02, 0x80, 0xa0, 0xf6, 0x40];

        assert!(coset::CoseSign1::from_slice(&encoded).is_err());
    }

    #[test]
    fn serialized_private_use_critical_header_is_parsed_then_rejected() {
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(-65_537))
            .build();
        let encoded = coset::CoseSign1Builder::new()
            .protected(protected)
            .signature(vec![0; 64])
            .build()
            .to_vec()
            .expect("serialize private-use critical header");
        let parsed = coset::CoseSign1::from_slice(&encoded)
            .expect("coset 0.4 represents private-use critical labels");

        let error = validate_critical_headers(&parsed.protected, &parsed.unprotected)
            .expect_err("this profile does not implement this private-use header");
        assert!(error.to_string().contains("private-use critical"));
    }

    #[test]
    fn original_protected_bytes_cannot_hide_empty_security_headers() {
        // A typed default cannot override explicit unsupported wire fields.
        for encoded in ["a201260540", "a201260640", "a201260780"] {
            let protected = coset::ProtectedHeader {
                original_data: Some(hex::decode(encoded).unwrap()),
                header: coset::HeaderBuilder::new()
                    .algorithm(iana::Algorithm::ES256)
                    .build(),
            };
            assert!(validate_headers(&protected, &coset::Header::default()).is_err());
        }
    }

    #[test]
    fn original_empty_kid_is_rejected_instead_of_treated_as_absent() {
        let protected = coset::ProtectedHeader {
            original_data: Some(hex::decode("a201260440").unwrap()),
            header: coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build(),
        };
        assert!(validate_headers(&protected, &coset::Header::default()).is_err());
        let unprotected = coset::HeaderBuilder::new().key_id(vec![1]).build();
        assert!(validate_headers(&protected, &unprotected).is_err());
    }

    #[test]
    fn signed_protected_bytes_must_match_decoded_header_fields() {
        let protected = coset::ProtectedHeader {
            original_data: Some(hex::decode("a1013822").unwrap()), // ES384, not ES256.
            header: coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build(),
        };
        assert!(validate_headers(&protected, &coset::Header::default()).is_err());
    }
}
