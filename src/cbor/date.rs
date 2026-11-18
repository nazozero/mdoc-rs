//! CBOR Tag 1004 — Full-date string (RFC 8943).
//!
//! Used in mdoc for date-only fields: `birth_date`, `issue_date`, `expiry_date`.
//! Format: `YYYY-MM-DD` (RFC 3339 full-date).

use crate::error::MdocError;
use ciborium::Value;

/// CBOR Tag number for full-date strings.
pub const TAG_FULL_DATE: u64 = 1004;

/// A full-date value (RFC 8943, CBOR Tag 1004).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullDate(String);

impl FullDate {
    /// Create a new FullDate from a string.
    pub fn new(date: &str) -> Result<Self, MdocError> {
        use ::time::format_description::{BorrowedFormatItem, Component, modifier};
        let format = [
            BorrowedFormatItem::Component(Component::CalendarYearFullStandardRange(
                modifier::CalendarYearFullStandardRange::default(),
            )),
            BorrowedFormatItem::StringLiteral("-"),
            BorrowedFormatItem::Component(Component::MonthNumerical(
                modifier::MonthNumerical::default(),
            )),
            BorrowedFormatItem::StringLiteral("-"),
            BorrowedFormatItem::Component(Component::Day(modifier::Day::default())),
        ];
        // Fixed-width components validate digits, separators and calendar values.
        // The length also excludes the parser's optional year sign.
        if date.len() != 10 || ::time::Date::parse(date, &format[..]).is_err() {
            return Err(MdocError::Cbor("invalid full-date".into()));
        }
        Ok(Self(date.to_owned()))
    }

    /// Get the date string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encode as a CBOR Tag 1004 value.
    pub fn to_cbor(&self) -> Value {
        Value::Tag(TAG_FULL_DATE, Box::new(Value::Text(self.0.clone())))
    }

    /// Decode a Tag 1004 full-date. Untagged text is not accepted.
    pub fn from_cbor(value: &Value) -> Result<Self, MdocError> {
        match value {
            Value::Tag(TAG_FULL_DATE, inner) => match inner.as_ref() {
                Value::Text(s) => Self::new(s),
                _ => Err(MdocError::Cbor(
                    "Tag 1004 inner value is not text".to_string(),
                )),
            },
            _ => Err(MdocError::Cbor(format!(
                "expected Tag 1004, got {:?}",
                value
            ))),
        }
    }
}

impl std::fmt::Display for FullDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_date_round_trip() {
        let date = FullDate::new("1990-01-15").unwrap();
        let cbor = date.to_cbor();
        let decoded = FullDate::from_cbor(&cbor).unwrap();
        assert_eq!(decoded, date);
    }

    #[test]
    fn full_date_from_plain_text() {
        let val = Value::Text("2026-03-19".to_string());
        assert!(FullDate::from_cbor(&val).is_err());
        assert!(FullDate::new("2026-02-30").is_err());
    }

    #[test]
    fn full_date_requires_exact_width_ascii_and_valid_calendar() {
        for date in ["0000-01-01", "2000-02-29", "2024-02-29", "9999-12-31"] {
            assert_eq!(FullDate::new(date).unwrap().as_str(), date);
        }
        for date in [
            "",
            "2026-1-18",
            "2026-11-1",
            "+2026-11-18",
            "-2026-11-18",
            "02026-11-18",
            "2026/11/18",
            "2026-11/18",
            "202x-11-18",
            "2026-1 -18",
            "2026-11- 1",
            "2026-11-18x",
            "2026-11-18\n",
            "2026-1é-1",
            "２０２６-11-18",
            "2026-00-18",
            "2026-13-18",
            "2026-11-00",
            "2026-11-31",
            "2026-02-29",
            "1900-02-29",
        ] {
            assert!(FullDate::new(date).is_err(), "accepted {date:?}");
        }
    }
}
