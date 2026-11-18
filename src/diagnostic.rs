//! CBOR diagnostic notation (RFC 8949 §8; feature: `debug`).
//!
//! Displays decoded values, map order, tags and byte strings for inspection.

use ciborium::Value;

/// Render a decoded CBOR value as a single-line diagnostic-notation string.
///
/// Examples: `{"docType": "org.iso.18013.5.1.mDL", ...}`, `1004("2019-10-20")`,
/// `24(h'a4686469...')`.
pub fn to_diagnostic(value: &Value) -> String {
    let mut out = String::new();
    render(value, &mut out);
    out
}

/// Decode CBOR bytes and render them in diagnostic notation. Returns a short
/// error marker string for bytes outside the supported bounded CBOR profile.
pub fn bytes_to_diagnostic(bytes: &[u8]) -> String {
    match crate::cbor::decode_cbor(bytes) {
        Ok(v) => to_diagnostic(&v),
        Err(e) => format!("<invalid CBOR: {e}>"),
    }
}

fn render(value: &Value, out: &mut String) {
    use std::fmt::Write;
    match value {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            let _ = write!(out, "{n}");
        }
        Value::Bytes(b) => {
            out.push_str("h'");
            for byte in b {
                let _ = write!(out, "{byte:02x}");
            }
            out.push('\'');
        }
        Value::Float(f) => {
            if f.is_finite() {
                let _ = write!(out, "{f:?}");
            } else if f.is_nan() {
                out.push_str("NaN");
            } else {
                out.push_str(if f.is_sign_negative() {
                    "-Infinity"
                } else {
                    "Infinity"
                });
            }
        }
        Value::Text(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\u{8}' => out.push_str("\\b"),
                    '\t' => out.push_str("\\t"),
                    '\n' => out.push_str("\\n"),
                    '\u{c}' => out.push_str("\\f"),
                    '\r' => out.push_str("\\r"),
                    '\u{0}'..='\u{1f}' => {
                        let _ = write!(out, "\\u{:04x}", u32::from(c));
                    }
                    _ => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
        Value::Tag(tag, inner) => {
            let _ = write!(out, "{tag}(");
            render(inner, out);
            out.push(')');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(item, out);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(k, out);
                out.push_str(": ");
                render(v, out);
            }
            out.push('}');
        }
        // ciborium::Value is non-exhaustive.
        other => {
            let _ = write!(out, "{other:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_scalars() {
        assert_eq!(to_diagnostic(&Value::Integer(42i32.into())), "42");
        assert_eq!(to_diagnostic(&Value::Bool(true)), "true");
        assert_eq!(to_diagnostic(&Value::Null), "null");
        assert_eq!(to_diagnostic(&Value::Text("hi".into())), "\"hi\"");
    }

    #[test]
    fn text_uses_json_escapes_and_preserves_printable_unicode() {
        let controls: String = (0u8..=31).map(char::from).collect();
        assert_eq!(
            to_diagnostic(&Value::Text(controls)),
            concat!(
                "\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007",
                "\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f",
                "\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017",
                "\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\"",
            )
        );
        assert_eq!(
            to_diagnostic(&Value::Text("水 / \"quoted\" \\".into())),
            r#""水 / \"quoted\" \\""#,
        );
    }

    #[test]
    fn floats_keep_their_type_sign_and_standard_nonfinite_names() {
        for (value, expected) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (-4.0, "-4.0"),
            (1.5, "1.5"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
            (f64::NAN, "NaN"),
            (-f64::NAN, "NaN"),
        ] {
            assert_eq!(to_diagnostic(&Value::Float(value)), expected);
        }
        for value in [f64::from_bits(1), f64::MIN_POSITIVE, 1e20, f64::MAX] {
            let rendered = to_diagnostic(&Value::Float(value));
            assert!(rendered.contains('.') || rendered.contains('e'));
            assert_eq!(rendered.parse::<f64>().unwrap().to_bits(), value.to_bits());
        }
    }

    #[test]
    fn renders_bytes_as_hex() {
        assert_eq!(
            to_diagnostic(&Value::Bytes(vec![0xa4, 0x00, 0xff])),
            "h'a400ff'"
        );
    }

    #[test]
    fn renders_tag_with_content() {
        // full-date Tag 1004 wrapping a text date.
        let v = Value::Tag(1004, Box::new(Value::Text("2019-10-20".into())));
        assert_eq!(to_diagnostic(&v), "1004(\"2019-10-20\")");
    }

    #[test]
    fn renders_map_and_array() {
        let v = Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1i32.into())),
            (
                Value::Text("b".into()),
                Value::Array(vec![Value::Integer(2i32.into()), Value::Bool(false)]),
            ),
        ]);
        assert_eq!(to_diagnostic(&v), "{\"a\": 1, \"b\": [2, false]}");
    }

    #[test]
    fn bytes_to_diagnostic_round_trips() {
        let v = Value::Map(vec![(
            Value::Text("k".into()),
            Value::Tag(24, Box::new(Value::Bytes(vec![0x82, 0x01, 0x02]))),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&v, &mut buf).unwrap();
        assert_eq!(bytes_to_diagnostic(&buf), "{\"k\": 24(h'820102')}");
        assert_eq!(bytes_to_diagnostic(&[0xc2, 0x41, 0x01]), "2(h'01')");
        assert!(bytes_to_diagnostic(&[0xf7]).starts_with("<invalid CBOR:"));
    }
}
