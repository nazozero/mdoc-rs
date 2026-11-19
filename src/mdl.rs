//! ISO/IEC 18013-5:2021 §7.2 mDL data-element encodings.
//!
//! Validation covers the values supplied for issuance or disclosed for reading.
//! A partial disclosure need not contain every mandatory licence data element.
//! Domestic namespaces retain their own schemas and JSON mappings.

use crate::{CborValueRef, MdocError, Timestamp, cbor::date};

pub const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
pub const NAMESPACE: &str = "org.iso.18013.5.1";

fn invalid() -> MdocError {
    MdocError::Cbor("invalid ISO mDL data element".into())
}

fn text(value: CborValueRef<'_>) -> Result<&str, MdocError> {
    value.as_text().ok_or_else(invalid)
}

fn latin1(value: CborValueRef<'_>) -> Result<(), MdocError> {
    let value = text(value)?;
    if value.chars().count() > 150 || value.chars().any(|c| u32::from(c) > 255) {
        return Err(invalid());
    }
    Ok(())
}

fn country(value: CborValueRef<'_>) -> Result<(), MdocError> {
    let value = text(value)?;
    if value.len() != 2 || !value.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(invalid());
    }
    Ok(())
}

fn date(value: CborValueRef<'_>, full_only: bool, time_only: bool) -> Result<(), MdocError> {
    let (tag, inner) = value.tagged()?;
    if (full_only && tag != 1004) || (time_only && tag != 0) {
        return Err(invalid());
    }
    date::validate_date_tag(tag, text(inner)?)
}

enum Element {
    Latin1,
    Text,
    Country,
    Jurisdiction,
    Bytes,
    BirthDate,
    IssueDate,
    ExpiryDate,
    PortraitDate,
    Sex,
    Unsigned,
    EyeColour,
    HairColour,
    Privileges,
    Age,
    Biometric,
}

fn element(name: &str) -> Option<Element> {
    Some(match name {
        "family_name"
        | "given_name"
        | "issuing_authority"
        | "document_number"
        | "administrative_number"
        | "birth_place"
        | "resident_address"
        | "resident_city"
        | "resident_state"
        | "resident_postal_code" => Element::Latin1,
        "family_name_national_character"
        | "given_name_national_character"
        | "un_distinguishing_sign" => Element::Text,
        "issuing_country" | "nationality" | "resident_country" => Element::Country,
        "issuing_jurisdiction" => Element::Jurisdiction,
        "portrait" | "signature_usual_mark" => Element::Bytes,
        "birth_date" => Element::BirthDate,
        "issue_date" => Element::IssueDate,
        "expiry_date" => Element::ExpiryDate,
        "portrait_capture_date" => Element::PortraitDate,
        "sex" => Element::Sex,
        "height" | "weight" | "age_in_years" | "age_birth_year" => Element::Unsigned,
        "eye_colour" => Element::EyeColour,
        "hair_colour" => Element::HairColour,
        "driving_privileges" => Element::Privileges,
        _ if name.starts_with("age_over_") => Element::Age,
        _ if name.starts_with("biometric_template_") => Element::Biometric,
        _ => return None,
    })
}

/// Whether an identifier belongs to the Table 5 mDL schema, including its
/// age-attestation and biometric-template identifier families.
pub fn is_standard_element(name: &str) -> bool {
    element(name).is_some()
}

/// Table 5 elements must be issuer-signed, even when KeyAuthorizations grant
/// the device permission to sign other data in the same namespace (§7.2.1).
pub(crate) fn check_device_element(
    doc_type: &str,
    namespace: &str,
    name: &str,
) -> Result<(), MdocError> {
    if doc_type == DOC_TYPE && namespace == NAMESPACE && is_standard_element(name) {
        return Err(MdocError::DeviceAuth(
            "ISO mDL Table 5 elements must be issuer-signed".into(),
        ));
    }
    Ok(())
}

/// Validate a supplied Table 5 element, including the MSO-bound issue date.
/// Unknown identifiers are left to their separately selected data schema.
/// This does not decode image formats or assert real-world claim accuracy.
pub fn validate_element(
    name: &str,
    value: CborValueRef<'_>,
    valid_from: Timestamp,
) -> Result<(), MdocError> {
    let Some(element) = element(name) else {
        return Ok(());
    };
    match element {
        Element::Latin1 => latin1(value),
        Element::Text => text(value).map(|_| ()),
        Element::Country => country(value),
        Element::Jurisdiction => {
            let v = text(value)?.as_bytes();
            if !(4..=6).contains(&v.len())
                || !v[..2].iter().all(u8::is_ascii_uppercase)
                || v[2] != b'-'
                || !v[3..]
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return Err(invalid());
            }
            Ok(())
        }
        Element::Bytes => value.as_bytes().map(|_| ()).ok_or_else(invalid),
        Element::BirthDate => date(value, true, false),
        Element::IssueDate => {
            date(value, false, false)?;
            let (tag, inner) = value.tagged()?;
            let text = text(inner)?;
            let after = if tag == 1004 {
                date::parse_full_date(text)? > valid_from.date()
            } else {
                date::parse_tdate(text)? > valid_from
            };
            if after { Err(invalid()) } else { Ok(()) }
        }
        Element::ExpiryDate => date(value, false, false),
        Element::PortraitDate => date(value, false, true),
        Element::Sex => match value.as_integer() {
            Some(0 | 1 | 2 | 9) => Ok(()),
            _ => Err(invalid()),
        },
        Element::Unsigned => {
            if value.as_integer().is_some_and(|v| v >= 0) {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        Element::EyeColour => {
            if [
                "black",
                "blue",
                "brown",
                "dichromatic",
                "grey",
                "green",
                "hazel",
                "maroon",
                "pink",
                "unknown",
            ]
            .contains(&text(value)?)
            {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        Element::HairColour => {
            if [
                "bald", "black", "blond", "brown", "grey", "red", "auburn", "sandy", "white",
                "unknown",
            ]
            .contains(&text(value)?)
            {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        Element::Privileges => driving_privileges(value),
        Element::Age => {
            if name.len() == 11
                && name.as_bytes()[9..].iter().all(u8::is_ascii_digit)
                && value.as_bool().is_some()
            {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        Element::Biometric => {
            let suffix = &name["biometric_template_".len()..];
            if suffix.is_empty()
                || !suffix
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                || !value
                    .as_bytes()
                    .is_some_and(|bytes| bytes.starts_with(&[0x7f, 0x61]))
            {
                return Err(invalid());
            }
            Ok(())
        }
    }
}

fn driving_privileges(value: CborValueRef<'_>) -> Result<(), MdocError> {
    for privilege in value.array()? {
        let mut category = false;
        for entry in privilege?.map()? {
            let (name, value) = entry?;
            match text(name)? {
                "vehicle_category_code" => {
                    text(value)?;
                    category = true;
                }
                "issue_date" | "expiry_date" => date(value, true, false)?,
                "codes" => {
                    let codes = value.array()?;
                    if codes.len() == 0 {
                        return Err(invalid());
                    }
                    for code in codes {
                        let mut has_code = false;
                        for entry in code?.map()? {
                            let (name, value) = entry?;
                            match text(name)? {
                                "code" => {
                                    text(value)?;
                                    has_code = true;
                                }
                                "sign" | "value" => {
                                    text(value)?;
                                }
                                _ => return Err(invalid()),
                            }
                        }
                        if !has_code {
                            return Err(invalid());
                        }
                    }
                }
                _ => return Err(invalid()),
            }
        }
        if !category {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(crate) fn check_jurisdiction(
    country: Option<&str>,
    jurisdiction: Option<&str>,
) -> Result<(), MdocError> {
    if let (Some(country), Some(jurisdiction)) = (country, jurisdiction)
        && jurisdiction.as_bytes().get(..2) != Some(country.as_bytes())
    {
        return Err(invalid());
    }
    Ok(())
}
