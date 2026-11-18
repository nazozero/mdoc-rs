//! UTC timestamps for protocol validation, backed by `time`.
//!
//! `time` handles calendar validation and RFC 3339 parsing/formatting. This type
//! preserves whole leap seconds and their ordering; Unix conversion returns
//! `None` for a leap second. The MSO wire profile requires whole UTC seconds.

use ::time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
use std::{cmp::Ordering, str::FromStr};

use crate::MdocError;

/// A UTC timestamp with exact ordering for ordinary instants and whole leap seconds.
///
/// Values are confined to four-digit UTC years `0000..=9999`. Ordinary values
/// retain nanoseconds, allowing callers to validate issuance intervals before
/// truncating them to the whole seconds required by the MSO wire profile.
/// Whole leap seconds are retained explicitly and sort after every nanosecond
/// of the preceding ordinary second and before the following second.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Timestamp {
    // Always UTC. A leap second stores the preceding ordinary second with
    // nanosecond zero; only this module can construct that representation.
    utc: OffsetDateTime,
    leap_second: bool,
}

impl Timestamp {
    /// Construct an ordinary instant from Unix seconds, rejecting unsupported years.
    pub fn from_unix_seconds(seconds: i64) -> Result<Self, MdocError> {
        let utc = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(|_| invalid("Unix timestamp is out of range"))?;
        Self::checked(utc, false)
    }

    /// Construct an ordinary instant from Unix nanoseconds without truncating precision.
    pub fn from_unix_nanos(nanoseconds: i128) -> Result<Self, MdocError> {
        let utc = OffsetDateTime::from_unix_timestamp_nanos(nanoseconds)
            .map_err(|_| invalid("Unix timestamp is out of range"))?;
        Self::checked(utc, false)
    }

    /// Parse a bounded RFC 3339 timestamp and normalize its offset to UTC.
    ///
    /// This protocol API requires an uppercase `T` separator and at most nine
    /// fractional digits. Extra digits reject to preserve interval precision.
    /// Ordinary fractional seconds are retained. Positive leap seconds must be
    /// whole seconds; fractional leap seconds are outside this protocol type.
    /// The `time` parser validates the calendar and possible UTC leap-second
    /// position; checking an actual occurrence requires an external schedule.
    pub fn parse_rfc3339(text: &str) -> Result<Self, MdocError> {
        let bytes = text.as_bytes();
        if !(20..=35).contains(&bytes.len()) || bytes.get(10) != Some(&b'T') {
            return Err(invalid(
                "timestamps require bounded RFC 3339 with a T separator",
            ));
        }
        if bytes.get(19) == Some(&b'.') {
            let digits = bytes[20..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if !(1..=9).contains(&digits) {
                return Err(invalid(
                    "timestamp fraction must contain one to nine digits",
                ));
            }
        }
        let parsed = OffsetDateTime::parse(text, &Rfc3339)
            .map_err(|_| invalid("invalid RFC 3339 timestamp"))?;
        // RFC 3339 has fixed-width date/hour/minute/second fields. Inspect the
        // original second before the dependency's leap-second stand-in can lose
        // that information. All syntax/calendar validation remains with `time`.
        let leap_second = bytes.get(17..19) == Some(b"60");
        if leap_second && bytes.get(19) == Some(&b'.') {
            return Err(invalid("fractional leap seconds are unsupported"));
        }
        let utc = parsed
            .checked_to_offset(UtcOffset::UTC)
            .ok_or_else(|| invalid("UTC timestamp is out of range"))?;
        let utc = if leap_second {
            // `time` maps second 60 to the preceding nanosecond. Retain an
            // explicit flag and an integral base instead of exposing the clamp.
            utc.truncate_to_second()
        } else {
            utc
        };
        Self::checked(utc, leap_second)
    }

    /// Format UTC RFC 3339, preserving a whole leap second as `:60Z`.
    pub fn format_rfc3339(self) -> Result<String, MdocError> {
        let mut text = self
            .utc
            .format(&Rfc3339)
            .map_err(|_| invalid("cannot format RFC 3339 timestamp"))?;
        if self.leap_second {
            // The private representation guarantees an integral UTC instant in
            // a four-digit year, so these are the two ASCII second digits.
            text.replace_range(17..19, "60");
        }
        Ok(text)
    }

    /// Whether this value has the whole-second precision required by MSO tdate.
    pub fn is_whole_second(self) -> bool {
        self.utc.nanosecond() == 0
    }

    /// Whether this value represents the distinct whole second labelled `60`.
    pub fn is_leap_second(self) -> bool {
        self.leap_second
    }

    /// Truncate ordinary subsecond precision, preserving a whole leap second.
    ///
    /// Issuers must compare their original interval before truncation, then
    /// reject any interval that becomes empty. `DocumentBuilder` does both.
    #[must_use]
    pub fn truncate_to_second(self) -> Self {
        Self {
            utc: self.utc.truncate_to_second(),
            leap_second: self.leap_second,
        }
    }

    /// Unix seconds for an ordinary instant, or `None` for a leap second.
    /// Returns the containing Unix second, flooring toward negative infinity
    /// for pre-epoch instants. This intentionally drops ordinary subsecond precision.
    pub fn unix_seconds(self) -> Option<i64> {
        (!self.leap_second).then(|| self.utc.unix_timestamp())
    }

    /// Exact Unix nanoseconds for an ordinary instant, or `None` for a leap second.
    pub fn unix_nanos(self) -> Option<i128> {
        (!self.leap_second).then(|| self.utc.unix_timestamp_nanos())
    }

    fn checked(utc: OffsetDateTime, leap_second: bool) -> Result<Self, MdocError> {
        if !(0..=9999).contains(&utc.year()) {
            return Err(invalid("timestamps require four-digit UTC years"));
        }
        Ok(Self { utc, leap_second })
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.utc
            .unix_timestamp()
            .cmp(&other.utc.unix_timestamp())
            .then_with(|| self.leap_second.cmp(&other.leap_second))
            .then_with(|| self.utc.nanosecond().cmp(&other.utc.nanosecond()))
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for Timestamp {
    type Err = MdocError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse_rfc3339(text)
    }
}

fn invalid(message: &str) -> MdocError {
    MdocError::Validity(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Timestamp {
        Timestamp::parse_rfc3339(text).unwrap()
    }

    #[test]
    fn leap_second_has_exact_order_beyond_the_last_ordinary_nanosecond() {
        let regular = parse("2016-12-31T23:59:59Z");
        let last_nano = parse("2016-12-31T23:59:59.999999999Z");
        let leap = parse("2016-12-31T23:59:60Z");
        let next = parse("2017-01-01T00:00:00Z");
        assert!(regular < last_nano && last_nano < leap && leap < next);
        assert_ne!(last_nano, leap);
        assert_eq!(leap.format_rfc3339().unwrap(), "2016-12-31T23:59:60Z");
        assert_eq!(leap.truncate_to_second(), leap);
        assert!(leap.is_leap_second() && leap.is_whole_second());
        assert_eq!(leap.unix_seconds(), None);
        assert_eq!(leap.unix_nanos(), None);
    }

    #[test]
    fn utc_normalization_retains_leap_seconds_and_ordinary_fractional_precision() {
        assert_eq!(
            parse("2017-01-01T00:59:60+01:00"),
            parse("2016-12-31T23:59:60Z")
        );
        let fraction = parse("2026-11-17T13:00:00.123456789+01:00");
        assert_eq!(
            fraction.format_rfc3339().unwrap(),
            "2026-11-17T12:00:00.123456789Z"
        );
        assert!(!fraction.is_whole_second());
        assert!(!fraction.is_leap_second());
        assert_eq!(
            fraction.truncate_to_second().format_rfc3339().unwrap(),
            "2026-11-17T12:00:00Z"
        );
    }

    #[test]
    fn calendar_and_unsupported_leap_inputs_fail_closed() {
        for text in [
            "2026-11-17X12:00:00Z",
            "2026-11-17\0",
            "2026-11-17t12:00:00Z",
            "2026-11-17\u{0000}12:00:00Z",
            "2026-11-17T12:00:00.0000000001Z",
            "2026-11-17T12:00:00.0000000000Z",
            "2026-11-17T12:00:00.1234567890Z",
            "2026-02-30T00:00:00Z",
            "2016-12-31T23:59:61Z",
            "2016-12-30T23:59:60Z",
            "2016-12-31T22:59:60Z",
            "2016-12-31T23:59:60.0Z",
            "2016-12-31T23:59:60.5Z",
            "2016-12-31T23:59:60Zjunk",
            "0000-01-01T00:00:00+01:00",
            "9999-12-31T23:59:59-01:00",
            "🕰",
        ] {
            assert!(Timestamp::parse_rfc3339(text).is_err(), "{text}");
        }
    }

    #[test]
    fn unix_conversion_preserves_negative_and_subsecond_instants() {
        for nanos in [-1_000_000_001, -1, 0, 1, 1_000_000_001] {
            let timestamp = Timestamp::from_unix_nanos(nanos).unwrap();
            assert_eq!(timestamp.unix_nanos(), Some(nanos));
            assert_eq!(parse(&timestamp.format_rfc3339().unwrap()), timestamp);
        }
        assert!(Timestamp::from_unix_nanos(i128::MAX).is_err());
        assert!(Timestamp::from_unix_seconds(i64::MIN).is_err());
        assert_eq!(
            parse("0000-01-01T00:00:00Z").format_rfc3339().unwrap(),
            "0000-01-01T00:00:00Z"
        );
    }

    #[test]
    fn utc_offsets_preserve_identity_and_four_digit_year_bounds_are_checked() {
        use std::hash::{Hash, Hasher};
        let utc = parse("2026-11-17T12:00:00.123456789Z");
        let offset = parse("2026-11-17T13:00:00.123456789+01:00");
        assert_eq!(utc, offset);
        assert_eq!(utc.cmp(&offset), Ordering::Equal);
        let hash = |value: Timestamp| {
            let mut state = std::collections::hash_map::DefaultHasher::new();
            value.hash(&mut state);
            state.finish()
        };
        assert_eq!(hash(utc), hash(offset));
        let minimum = parse("0000-01-01T00:00:00Z").unix_nanos().unwrap();
        let maximum = parse("9999-12-31T23:59:59.999999999Z")
            .unix_nanos()
            .unwrap();
        for bound in [minimum, maximum] {
            assert_eq!(
                Timestamp::from_unix_nanos(bound).unwrap().unix_nanos(),
                Some(bound)
            );
        }
        assert!(Timestamp::from_unix_nanos(minimum - 1).is_err());
        assert!(Timestamp::from_unix_nanos(maximum + 1).is_err());
        assert_eq!(
            Timestamp::from_unix_nanos(-1).unwrap().unix_seconds(),
            Some(-1)
        );
    }
}
