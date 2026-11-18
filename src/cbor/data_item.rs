//! CBOR Tag 24 — Encoded CBOR Data Item (RFC 8949 §3.4.5.1).
//!
//! Used in mdoc for:
//! - IssuerSignedItem encoding (each item is independently verifiable)
//! - MSO payload inside COSE_Sign1

use crate::error::MdocError;
use ciborium::Value;

/// CBOR Tag number for encoded CBOR data items.
pub const TAG_ENCODED_CBOR: u64 = 24;

/// Encode a value to CBOR bytes.
///
/// This preserves the map element order as given. For issuance output that must
/// be reproducible and interoperable with strict verifiers, use
/// [`encode_cbor_canonical`] instead.
pub fn encode_cbor(value: &Value) -> Result<Vec<u8>, MdocError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Encode a value to **deterministic (canonical) CBOR** bytes.
///
/// This crate emits RFC 8949 core deterministic encoding for issuance.
/// ISO 18013-5's shortest-form/definite-length rules do not require map sorting;
/// readers therefore preserve and authenticate the received map order.
/// `ciborium` already emits definite-length items and shortest-form integers,
/// but it does **not** sort map keys. This wrapper recursively reorders every
/// map's entries into the RFC 8949 §4.2.1 canonical order (by the bytewise
/// lexicographic order of the *encoded* keys), so the output is stable across
/// runs regardless of the source `HashMap` iteration order.
///
/// Tag 2/3 inputs must already use preferred bignum representation: a nonempty
/// byte string longer than eight bytes with no leading zero. Smaller numbers
/// must be supplied as native integers instead of silently removing a tag.
/// This operates on the explicit Value tree; pre-encoded Tag 24 contents remain
/// byte strings, and unknown tags have no inferred semantic normalization.
pub fn encode_cbor_canonical(value: &Value) -> Result<Vec<u8>, MdocError> {
    let mut bytes = Vec::new();
    write_canonical(value, &mut bytes, 0)?;
    crate::cbor::raw::validate(&bytes)?;
    Ok(bytes)
}

/// Write borrowed values in RFC 8949 core deterministic order. The caller
/// validates the complete output envelope before using or returning it.
pub(crate) fn write_canonical(
    value: &Value,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<(), MdocError> {
    use crate::cbor::raw::{push_bytes, push_head, push_text};

    if depth > crate::cbor::raw::Limits::default().max_depth {
        return Err(MdocError::Cbor("CBOR nesting limit exceeded".into()));
    }
    match value {
        Value::Map(entries) => {
            let mut keyed = entries
                .iter()
                .map(|(key, value)| Ok((key_order(key)?, key, value)))
                .collect::<Result<Vec<_>, MdocError>>()?;
            keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            push_head(out, 5, entries.len() as u64);
            for (_, key, value) in keyed {
                write_canonical(key, out, depth + 1)?;
                write_canonical(value, out, depth + 1)?;
            }
        }
        Value::Array(items) => {
            push_head(out, 4, items.len() as u64);
            for item in items {
                write_canonical(item, out, depth + 1)?;
            }
        }
        Value::Tag(tag @ (2 | 3), inner) => {
            let Value::Bytes(magnitude) = inner.as_ref() else {
                return Err(MdocError::Cbor("bignum tag must contain bytes".into()));
            };
            if magnitude.len() <= 8 || magnitude[0] == 0 {
                return Err(MdocError::Cbor(
                    "bignum must use preferred encoding; use a native integer for small values"
                        .into(),
                ));
            }
            push_head(out, 6, *tag);
            write_canonical(inner, out, depth + 1)?;
        }
        Value::Tag(tag, inner) => {
            push_head(out, 6, *tag);
            write_canonical(inner, out, depth + 1)?;
        }
        Value::Bytes(bytes) => push_bytes(out, bytes),
        Value::Text(text) => push_text(out, text),
        // Ciborium retains its preferred integer and floating-point encoding.
        scalar => ciborium::into_writer(scalar, out)?,
    }
    Ok(())
}

// For the supported scalar keys, encoded-byte order is major type, shortest
// integer/length argument, then string contents. No encoded key buffer is needed.
fn key_order(key: &Value) -> Result<(u8, u64, &[u8]), MdocError> {
    Ok(match key {
        Value::Integer(integer) => {
            let integer = i128::from(*integer);
            if integer >= 0 {
                (0, integer as u64, &[])
            } else {
                (1, (-1 - integer) as u64, &[])
            }
        }
        Value::Bytes(bytes) => (2, bytes.len() as u64, bytes),
        Value::Text(text) => (3, text.len() as u64, text.as_bytes()),
        _ => {
            return Err(MdocError::Cbor(
                "unsupported compound or floating-point map key".into(),
            ));
        }
    })
}

/// Decode bounded CBOR bytes, preserving tags rather than normalizing tagged
/// bignums into untagged integers. Unsupported simple values fail closed.
pub fn decode_cbor(bytes: &[u8]) -> Result<Value, MdocError> {
    crate::cbor::raw::Item::parse(bytes)?.value()
}

/// Wrap bytes in CBOR Tag 24 (encoded CBOR data item).
pub fn wrap_tag24(data: &[u8]) -> Value {
    Value::Tag(TAG_ENCODED_CBOR, Box::new(Value::Bytes(data.to_vec())))
}

/// Unwrap CBOR Tag 24 to get the inner bytes.
pub fn unwrap_tag24(value: &Value) -> Result<Vec<u8>, MdocError> {
    tag24_bytes(value).map(<[u8]>::to_vec)
}

fn tag24_bytes(value: &Value) -> Result<&[u8], MdocError> {
    match value {
        Value::Tag(TAG_ENCODED_CBOR, inner) => match inner.as_ref() {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(MdocError::Cbor(
                "Tag 24 inner value is not bytes".to_string(),
            )),
        },
        _ => Err(MdocError::Cbor(format!("expected Tag 24, got {:?}", value))),
    }
}

/// Encode a value and wrap it in Tag 24.
pub fn encode_as_tag24(value: &Value) -> Result<Value, MdocError> {
    Ok(Value::Tag(
        TAG_ENCODED_CBOR,
        Box::new(Value::Bytes(encode_cbor(value)?)),
    ))
}

/// Unwrap Tag 24 and decode the inner CBOR.
pub fn decode_tag24(value: &Value) -> Result<Value, MdocError> {
    decode_cbor(tag24_bytes(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag24_round_trip() {
        let original = Value::Text("hello".to_string());
        let wrapped = encode_as_tag24(&original).unwrap();
        let decoded = decode_tag24(&wrapped).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn tag24_bytes_round_trip() {
        let data = b"test data";
        let tagged = wrap_tag24(data);
        let unwrapped = unwrap_tag24(&tagged).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn unwrap_plain_bytes() {
        // Some impls omit tag 24 and just use raw bytes
        let val = Value::Bytes(b"raw bytes".to_vec());
        assert!(unwrap_tag24(&val).is_err());
    }

    #[test]
    fn canonical_sorts_map_keys_by_encoded_bytes() {
        // RFC 8949 §4.2.1: keys sort lexicographically by their encoded bytes.
        // Text-key encoding is major-type-3 + length, so shorter keys sort first.
        let map = Value::Map(vec![
            (
                Value::Text("elementValue".into()),
                Value::Text("Doe".into()),
            ),
            (Value::Text("digestID".into()), Value::Integer(0u8.into())),
            (Value::Text("random".into()), Value::Bytes(vec![1, 2, 3])),
            (
                Value::Text("elementIdentifier".into()),
                Value::Text("family_name".into()),
            ),
        ]);
        let bytes = encode_cbor_canonical(&map).unwrap();
        // Decode and confirm the key order is: random(6) < digestID(8)
        // < elementValue(12) < elementIdentifier(17).
        let decoded = decode_cbor(&bytes).unwrap();
        let keys: Vec<String> = decoded
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect();
        assert_eq!(
            keys,
            vec!["random", "digestID", "elementValue", "elementIdentifier"]
        );
    }

    #[test]
    fn canonical_is_order_independent() {
        // Two maps with the same entries in different orders must encode identically.
        let a = Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2u8.into())),
            (Value::Text("a".into()), Value::Integer(1u8.into())),
        ]);
        let b = Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1u8.into())),
            (Value::Text("b".into()), Value::Integer(2u8.into())),
        ]);
        assert_eq!(
            encode_cbor_canonical(&a).unwrap(),
            encode_cbor_canonical(&b).unwrap()
        );
    }

    #[test]
    fn canonical_recurses_into_nested_maps() {
        let nested = Value::Map(vec![(
            Value::Text("outer".into()),
            Value::Map(vec![
                (Value::Text("zz".into()), Value::Integer(1u8.into())),
                (Value::Text("a".into()), Value::Integer(2u8.into())),
            ]),
        )]);
        let bytes = encode_cbor_canonical(&nested).unwrap();
        let decoded = decode_cbor(&bytes).unwrap();
        let inner = decoded.as_map().unwrap()[0].1.as_map().unwrap();
        let keys: Vec<String> = inner
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect();
        assert_eq!(keys, vec!["a", "zz"]);
    }

    #[test]
    fn canonical_bignum_inputs_must_already_use_preferred_representation() {
        for tag in [2, 3] {
            for inner in [
                Value::Bytes(vec![]),
                Value::Bytes(vec![1]),
                Value::Bytes(vec![0xff; 8]),
                Value::Bytes(vec![0; 9]),
                Value::Bytes([vec![0], vec![0xff; 9]].concat()),
                Value::Text("18446744073709551616".into()),
            ] {
                let value = Value::Tag(tag, Box::new(inner));
                for nested in [
                    value.clone(),
                    Value::Array(vec![value.clone()]),
                    Value::Map(vec![("number".into(), value)]),
                ] {
                    assert!(encode_cbor_canonical(&nested).is_err());
                }
            }
        }
    }

    #[test]
    fn canonical_integer_boundaries_preserve_native_and_large_bignum_types() {
        for (value, expected) in [
            (Value::Integer(u64::MAX.into()), "1bffffffffffffffff"),
            (
                Value::Integer((-(1i128 << 64)).try_into().unwrap()),
                "3bffffffffffffffff",
            ),
            (
                Value::Tag(2, Box::new(Value::Bytes([vec![1], vec![0; 8]].concat()))),
                "c249010000000000000000",
            ),
            (
                Value::Tag(3, Box::new(Value::Bytes([vec![1], vec![0; 8]].concat()))),
                "c349010000000000000000",
            ),
        ] {
            let wire = encode_cbor_canonical(&value).unwrap();
            assert_eq!(wire, hex::decode(expected).unwrap());
            assert_eq!(decode_cbor(&wire).unwrap(), value);
        }
    }
}
