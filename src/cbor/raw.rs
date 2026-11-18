//! Bounded CBOR validation and borrowed views of the original wire bytes.
//!
//! ISO 18013-5 uses definite lengths and shortest integer/length encodings.
//! Map order is not changed. Protocol map keys are integers, text, or bytes;
//! compound and floating-point map keys are outside this implementation's
//! supported profile. Tag 24 contents share the enclosing resource budget.

use std::collections::HashSet;

use crate::MdocError;

/// Limits applied before allocating a decoded CBOR value.
///
/// Item and depth budgets apply to one CBOR envelope, including its embedded
/// Tag 24 values. The protocol parser applies these same limits separately to
/// the known CBOR envelopes inside COSE byte strings (protected headers and the
/// issuer's MSO payload). The complete input also has to fit `max_bytes`.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_items: usize,
    pub max_collection_items: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_depth: 32,
            max_items: 65_536,
            max_collection_items: 4096,
        }
    }
}

fn error(message: &str) -> MdocError {
    MdocError::Cbor(message.into())
}

/// Validate exactly one CBOR item, including embedded Tag 24 items.
pub fn validate(bytes: &[u8]) -> Result<(), MdocError> {
    validate_with_limits(bytes, Limits::default())
}

pub fn validate_with_limits(bytes: &[u8], limits: Limits) -> Result<(), MdocError> {
    if bytes.len() > limits.max_bytes {
        return Err(error("CBOR byte limit exceeded"));
    }
    let mut budget = limits.max_items;
    let consumed = scan(bytes, 0, &limits, &mut budget)?;
    if consumed != bytes.len() {
        return Err(error("trailing CBOR data"));
    }
    Ok(())
}

// Returns (major type, argument, header length). Length arithmetic always uses
// checked operations before indexing or allocation, including on wasm32.
fn header(bytes: &[u8]) -> Result<(u8, u64, usize), MdocError> {
    let first = *bytes.first().ok_or_else(|| error("truncated CBOR"))?;
    let major = first >> 5;
    let additional = first & 31;
    let width = match additional {
        0..=23 => return Ok((major, u64::from(additional), 1)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(error("indefinite or reserved CBOR encoding")),
    };
    let encoded = bytes
        .get(1..=width)
        .ok_or_else(|| error("truncated CBOR header"))?;
    let mut argument = 0u64;
    for byte in encoded {
        argument = (argument << 8) | u64::from(*byte);
    }
    if major != 7 {
        let minimum = match width {
            1 => 24,
            2 => 256,
            4 => 65_536,
            _ => 4_294_967_296,
        };
        if argument < minimum {
            return Err(error("non-shortest CBOR integer or length"));
        }
    } else if additional == 24 && argument < 32 {
        return Err(error("invalid CBOR simple value encoding"));
    }
    Ok((major, argument, width + 1))
}

fn length(argument: u64) -> Result<usize, MdocError> {
    usize::try_from(argument).map_err(|_| error("CBOR length exceeds address space"))
}

fn end_of_string(bytes: &[u8], argument: u64, start: usize) -> Result<usize, MdocError> {
    let end = start
        .checked_add(length(argument)?)
        .ok_or_else(|| error("CBOR length overflow"))?;
    if end > bytes.len() {
        return Err(error("truncated CBOR string"));
    }
    Ok(end)
}

fn scan(
    bytes: &[u8],
    depth: usize,
    limits: &Limits,
    budget: &mut usize,
) -> Result<usize, MdocError> {
    if depth > limits.max_depth {
        return Err(error("CBOR nesting limit exceeded"));
    }
    *budget = budget
        .checked_sub(1)
        .ok_or_else(|| error("CBOR item limit exceeded"))?;
    let (major, argument, head) = header(bytes)?;
    match major {
        0 | 1 => Ok(head),
        2 | 3 => {
            let end = end_of_string(bytes, argument, head)?;
            if major == 3 {
                std::str::from_utf8(&bytes[head..end])
                    .map_err(|_| error("invalid UTF-8 in CBOR text"))?;
            }
            Ok(end)
        }
        4 | 5 => {
            let count = length(argument)?;
            if count > limits.max_collection_items {
                return Err(error("CBOR collection limit exceeded"));
            }
            let mut position = head;
            let mut keys = HashSet::new();
            for _ in 0..count {
                if major == 5 {
                    let (key_major, _, _) = header(&bytes[position..])?;
                    if key_major > 3 {
                        return Err(error("unsupported compound or floating-point map key"));
                    }
                    let size = scan(&bytes[position..], depth + 1, limits, budget)?;
                    let key = &bytes[position..position + size];
                    if !keys.insert(key) {
                        return Err(error("duplicate CBOR map key"));
                    }
                    position += size;
                }
                position += scan(&bytes[position..], depth + 1, limits, budget)?;
            }
            Ok(position)
        }
        6 => {
            let child = &bytes[head..];
            let size = scan(child, depth + 1, limits, budget)?;
            if argument == 24 {
                let (child_major, child_length, child_head) = header(child)?;
                if child_major != 2 {
                    return Err(error("Tag 24 must contain a byte string"));
                }
                let end = end_of_string(child, child_length, child_head)?;
                let inner = &child[child_head..end];
                if scan(inner, depth + 1, limits, budget)? != inner.len() {
                    return Err(error("trailing data inside Tag 24"));
                }
            }
            Ok(head + size)
        }
        // `ciborium::Value` maps undefined to null. Our supported value model
        // has no undefined/simple extension variant, so reject those wire
        // values rather than silently erase the distinction during projection.
        7 if matches!(bytes[0] & 31, 20..=22 | 25..=27) => Ok(head),
        7 => Err(error("unsupported CBOR simple value")),
        _ => unreachable!("three-bit CBOR major type"),
    }
}

/// Return the borrowed contents of an exact Tag 24 byte string after validation.
pub fn tag24_inner(bytes: &[u8]) -> Result<&[u8], MdocError> {
    Item::parse(bytes)?.tag24()
}

/// An immutable slice known to contain exactly one validated item.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Item<'a> {
    bytes: &'a [u8],
}

impl<'a> Item<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, MdocError> {
        Self::parse_with_limits(bytes, Limits::default())
    }

    pub(crate) fn parse_with_limits(bytes: &'a [u8], limits: Limits) -> Result<Self, MdocError> {
        validate_with_limits(bytes, limits)?;
        Ok(Self { bytes })
    }

    pub(crate) fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    pub(crate) fn text(self) -> Result<&'a str, MdocError> {
        let (major, _, head) = header(self.bytes)?;
        if major != 3 {
            return Err(error("expected CBOR text"));
        }
        std::str::from_utf8(&self.bytes[head..]).map_err(|_| error("invalid CBOR text"))
    }

    pub(crate) fn uint(self) -> Result<u64, MdocError> {
        let (major, argument, _) = header(self.bytes)?;
        if major != 0 {
            return Err(error("expected CBOR unsigned integer"));
        }
        Ok(argument)
    }

    pub(crate) fn bstr(self) -> Result<&'a [u8], MdocError> {
        let (major, _, head) = header(self.bytes)?;
        if major != 2 {
            return Err(error("expected CBOR byte string"));
        }
        Ok(&self.bytes[head..])
    }

    pub(crate) fn tag24(self) -> Result<&'a [u8], MdocError> {
        let (major, argument, head) = header(self.bytes)?;
        if major != 6 || argument != 24 {
            return Err(error("expected Tag 24"));
        }
        Self {
            bytes: &self.bytes[head..],
        }
        .bstr()
    }

    pub(crate) fn embedded(self) -> Result<Self, MdocError> {
        Ok(Self {
            bytes: self.tag24()?,
        })
    }

    pub(crate) fn array(self) -> Result<Items<'a>, MdocError> {
        self.items(4)
    }

    pub(crate) fn map(self) -> Result<Map<'a>, MdocError> {
        Ok(Map {
            items: self.items(5)?,
        })
    }

    fn items(self, expected: u8) -> Result<Items<'a>, MdocError> {
        let (major, count, head) = header(self.bytes)?;
        if major != expected {
            return Err(error("unexpected CBOR container type"));
        }
        Ok(Items {
            remaining: &self.bytes[head..],
            count: length(count)? * if major == 5 { 2 } else { 1 },
        })
    }

    pub(crate) fn value(self) -> Result<ciborium::Value, MdocError> {
        let mut remaining = self.bytes;
        let value = project(&mut remaining)?;
        debug_assert!(remaining.is_empty());
        Ok(value)
    }
}

// Consume one item from a validated envelope. The cursor visits each encoded
// value once; tags retain their identity and Tag 24 contents remain byte strings.
fn project(remaining: &mut &[u8]) -> Result<ciborium::Value, MdocError> {
    use ciborium::Value;

    let original = *remaining;
    let (major, argument, head) = header(original)?;
    *remaining = &original[head..];
    Ok(match major {
        0 => Value::Integer(argument.into()),
        1 => Value::Integer(
            (-1 - i128::from(argument))
                .try_into()
                .expect("CBOR negative integer fits the value model"),
        ),
        2 | 3 => {
            let (bytes, tail) = remaining.split_at(length(argument)?);
            *remaining = tail;
            if major == 2 {
                Value::Bytes(bytes.to_vec())
            } else {
                Value::Text(
                    std::str::from_utf8(bytes)
                        .expect("validated CBOR text")
                        .to_owned(),
                )
            }
        }
        4 => {
            let count = length(argument)?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(project(remaining)?);
            }
            Value::Array(values)
        }
        5 => {
            let count = length(argument)?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push((project(remaining)?, project(remaining)?));
            }
            Value::Map(values)
        }
        6 => Value::Tag(argument, Box::new(project(remaining)?)),
        7 => match original[0] {
            0xf4 => Value::Bool(false),
            0xf5 => Value::Bool(true),
            0xf6 => Value::Null,
            // Keep ciborium's IEEE 754 conversion for all three wire widths.
            _ => ciborium::from_reader(&original[..head]).map_err(|e| error(&e.to_string()))?,
        },
        _ => unreachable!("validated CBOR major type"),
    })
}

// A second, allocation-free span walk. Values are immutable and were bounded
// and fully validated by Item::parse; this walk never decodes/re-encodes them.
fn span(bytes: &[u8]) -> Result<usize, MdocError> {
    let (major, argument, head) = header(bytes)?;
    match major {
        0 | 1 | 7 => Ok(head),
        2 | 3 => end_of_string(bytes, argument, head),
        6 => Ok(head + span(&bytes[head..])?),
        4 | 5 => {
            let mut position = head;
            for _ in 0..length(argument)? * if major == 5 { 2 } else { 1 } {
                position += span(&bytes[position..])?;
            }
            Ok(position)
        }
        _ => unreachable!("three-bit CBOR major type"),
    }
}

pub(crate) struct Items<'a> {
    remaining: &'a [u8],
    count: usize,
}

impl<'a> Iterator for Items<'a> {
    type Item = Result<Item<'a>, MdocError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(span(self.remaining).map(|size| {
            let (bytes, remaining) = self.remaining.split_at(size);
            self.remaining = remaining;
            Item { bytes }
        }))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }
}

impl ExactSizeIterator for Items<'_> {}

pub(crate) struct Map<'a> {
    items: Items<'a>,
}

impl<'a> Iterator for Map<'a> {
    type Item = Result<(Item<'a>, Item<'a>), MdocError>;
    fn next(&mut self) -> Option<Self::Item> {
        let key = self.items.next()?;
        let value = self
            .items
            .next()
            .expect("validated map has an even number of items");
        Some(key.and_then(|key| value.map(|value| (key, value))))
    }
}

/// Append a shortest CBOR integer/length header without constructing a Value.
pub(crate) fn push_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=255 => out.extend_from_slice(&[prefix | 24, value as u8]),
        256..=65_535 => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

pub(crate) fn push_text(out: &mut Vec<u8>, value: &str) {
    push_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

pub(crate) fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

#[cfg(feature = "issue")]
pub(crate) fn wrap_tag24_bytes(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inner.len() + 11);
    out.extend_from_slice(&[0xd8, 0x18]);
    push_head(&mut out, 2, inner.len() as u64);
    out.extend_from_slice(inner);
    out
}
