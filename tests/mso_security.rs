//! Structural MSO regressions. These deliberately do not claim authentication:
//! the protocol verifier must verify issuer and holder signatures before exposing
//! status or claims to the relying party's trust and revocation policy.

use ciborium::Value;
use coset::{CoseSign1, Label};
use nazo_mdoc::model::{IssuerAuth, Mso};
use proptest::prelude::*;

const NAMESPACE: &str = "org.iso.18013.5.1";

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn map<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("encode test value");
    bytes
}

fn tagged(bytes: Vec<u8>) -> Vec<u8> {
    encode(&Value::Tag(24, Box::new(Value::Bytes(bytes))))
}

fn auth_with_payload(payload: Vec<u8>) -> IssuerAuth {
    IssuerAuth::new(CoseSign1 {
        payload: Some(payload),
        ..Default::default()
    })
}

fn parse(value: &Value) -> Result<Mso, nazo_mdoc::MdocError> {
    auth_with_payload(tagged(encode(value))).mso()
}

fn member_mut<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
    let Value::Map(fields) = value else {
        panic!("test value must be a map")
    };
    &mut fields
        .iter_mut()
        .find(|(label, _)| label.as_text() == Some(key))
        .expect("test member exists")
        .1
}

fn set(value: &mut Value, key: &str, replacement: Value) {
    let Value::Map(fields) = value else {
        panic!("test value must be a map")
    };
    if let Some((_, current)) = fields
        .iter_mut()
        .find(|(label, _)| label.as_text() == Some(key))
    {
        *current = replacement;
    } else {
        fields.push((text(key), replacement));
    }
}

fn remove(value: &mut Value, key: &str) {
    let Value::Map(fields) = value else {
        panic!("test value must be a map")
    };
    fields.retain(|(label, _)| label.as_text() != Some(key));
}

fn tdate(value: &str) -> Value {
    Value::Tag(0, Box::new(text(value)))
}

fn valid_mso() -> Value {
    // Public generator point for NIST P-256. No private key is needed to check
    // the MSO model, and a structurally valid key does not confer issuer trust.
    let key = Value::Map(vec![
        (1.into(), 2.into()),
        ((-1).into(), 1.into()),
        (
            (-2).into(),
            Value::Bytes(
                hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                    .expect("x coordinate"),
            ),
        ),
        (
            (-3).into(),
            Value::Bytes(
                hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
                    .expect("y coordinate"),
            ),
        ),
    ]);
    map([
        ("version", text("1.0")),
        ("digestAlgorithm", text("SHA-256")),
        (
            "valueDigests",
            map([(
                NAMESPACE,
                Value::Map(vec![(0.into(), Value::Bytes(vec![0; 32]))]),
            )]),
        ),
        ("deviceKeyInfo", map([("deviceKey", key)])),
        ("docType", text("org.iso.18013.5.1.mDL")),
        (
            "validityInfo",
            map([
                ("signed", tdate("2026-01-01T00:00:00Z")),
                ("validFrom", tdate("2026-01-01T00:00:00Z")),
                ("validUntil", tdate("2027-01-01T00:00:00Z")),
            ]),
        ),
    ])
}

fn status(index: Value, uri: Value) -> Value {
    map([("status_list", map([("idx", index), ("uri", uri)]))])
}

#[test]
fn mandatory_mso_fields_and_version_are_enforced() {
    let valid = valid_mso();
    assert!(parse(&valid).is_ok());
    for key in [
        "version",
        "digestAlgorithm",
        "valueDigests",
        "deviceKeyInfo",
        "docType",
        "validityInfo",
    ] {
        let mut value = valid.clone();
        remove(&mut value, key);
        assert!(parse(&value).is_err(), "missing {key} must fail");
    }
    for version in [
        "", "0.9", "2.0", "1", "1.", ".1", "1.1.0", "1.+1", "1.-1", "+1.0", "1.０", "1.0\0", "1. 1",
    ] {
        let mut value = valid.clone();
        set(&mut value, "version", text(version));
        assert!(parse(&value).is_err(), "unsupported version {version}");
    }
    let mut value = valid;
    set(&mut value, "docType", text(""));
    assert!(
        parse(&value).is_err(),
        "this core profile rejects empty docType"
    );
}

#[test]
fn unknown_minor_mso_versions_are_accepted_and_preserved() {
    // ISO 18013-5 §8.1: a known major version must not be rejected merely
    // because its backwards-compatible minor version is unfamiliar.
    for version in [
        "1.0",
        "1.1",
        "1.12",
        "01.002",
        "1.999999999999999999999999999999999999999999999999999999",
    ] {
        let mut value = valid_mso();
        set(&mut value, "version", text(version));
        let encoded = tagged(encode(&value));
        let auth = auth_with_payload(encoded.clone());
        let parsed = auth.mso().expect("supported major version");
        assert_eq!(parsed.version, version);
        assert_eq!(auth.cose_sign1.payload.as_deref(), Some(encoded.as_slice()));
    }
}

#[test]
fn mso_requires_exactly_one_tag24_embedded_map() {
    let encoded = encode(&valid_mso());
    let accepted = tagged(encoded.clone());
    assert!(auth_with_payload(accepted.clone()).mso().is_ok());
    let mut outer_trailing = accepted;
    outer_trailing.push(0);
    let mut inner_trailing = encoded.clone();
    inner_trailing.push(0);
    for payload in [
        encoded.clone(),
        encode(&Value::Bytes(encoded.clone())),
        encode(&Value::Tag(23, Box::new(Value::Bytes(encoded)))),
        encode(&Value::Tag(24, Box::new(Value::Null))),
        tagged(encode(&Value::Null)),
        outer_trailing,
        tagged(inner_trailing),
    ] {
        assert!(auth_with_payload(payload).mso().is_err());
    }
    assert!(IssuerAuth::new(CoseSign1::default()).mso().is_err());
}

#[test]
fn original_mso_bytes_and_unsorted_map_order_are_preserved() {
    let mut value = valid_mso();
    let Value::Map(fields) = &mut value else {
        unreachable!()
    };
    fields.reverse();
    let payload = tagged(encode(&value));
    let auth = auth_with_payload(payload.clone());
    assert!(
        auth.mso().is_ok(),
        "ISO shortest encoding does not require sorted map keys"
    );
    assert_eq!(auth.cose_sign1.payload.as_deref(), Some(payload.as_slice()));
}

#[test]
fn embedded_duplicates_nonshortest_and_indefinite_lengths_are_rejected() {
    let mut value = valid_mso();
    let Value::Map(fields) = &mut value else {
        unreachable!()
    };
    fields.push((text("version"), text("1.0")));
    assert!(parse(&value).is_err());

    let encoded = encode(&valid_mso());
    assert_eq!(encoded[0], 0xa6);
    let mut nonshortest = vec![0xb8, 6];
    nonshortest.extend_from_slice(&encoded[1..]);
    assert!(auth_with_payload(tagged(nonshortest)).mso().is_err());
    let mut indefinite = vec![0xbf];
    indefinite.extend_from_slice(&encoded[1..]);
    indefinite.push(0xff);
    assert!(auth_with_payload(tagged(indefinite)).mso().is_err());

    let mut unknown = valid_mso();
    set(
        &mut unknown,
        "future",
        Value::Map(vec![(text("same"), 1.into()), (text("same"), 2.into())]),
    );
    assert!(
        parse(&unknown).is_err(),
        "unknown extensions cannot hide duplicate keys"
    );
}

#[test]
fn digest_algorithms_and_output_lengths_are_bound() {
    for (algorithm, size) in [("SHA-256", 32), ("SHA-384", 48), ("SHA-512", 64)] {
        let mut value = valid_mso();
        set(&mut value, "digestAlgorithm", text(algorithm));
        set(
            &mut value,
            "valueDigests",
            map([(
                NAMESPACE,
                Value::Map(vec![(0.into(), Value::Bytes(vec![0; size]))]),
            )]),
        );
        assert!(
            parse(&value).is_ok(),
            "{algorithm} with matching output length"
        );
        for bad_size in [0, size - 1, size + 1] {
            set(
                &mut value,
                "valueDigests",
                map([(
                    NAMESPACE,
                    Value::Map(vec![(0.into(), Value::Bytes(vec![0; bad_size]))]),
                )]),
            );
            assert!(
                parse(&value).is_err(),
                "{algorithm} cannot accept {bad_size} bytes"
            );
        }
    }
    for algorithm in ["SHA-1", "sha-256", "SHA256", "SHA3-256", ""] {
        let mut value = valid_mso();
        set(&mut value, "digestAlgorithm", text(algorithm));
        assert!(parse(&value).is_err());
    }
}

#[test]
fn digest_identifiers_and_namespace_shapes_are_strict() {
    let mut value = valid_mso();
    set(
        &mut value,
        "valueDigests",
        map([(
            NAMESPACE,
            Value::Map(vec![((i32::MAX as u64).into(), Value::Bytes(vec![0; 32]))]),
        )]),
    );
    assert!(
        parse(&value).is_ok(),
        "2^31 - 1 is the largest permitted digestID"
    );
    for id in [
        (-1).into(),
        (1u64 << 31).into(),
        u64::MAX.into(),
        text("0"),
        Value::Float(0.0),
    ] {
        set(
            &mut value,
            "valueDigests",
            map([(NAMESPACE, Value::Map(vec![(id, Value::Bytes(vec![0; 32]))]))]),
        );
        assert!(parse(&value).is_err());
    }
    for digests in [
        Value::Map(vec![]),
        map([(NAMESPACE, Value::Map(vec![]))]),
        map([(NAMESPACE, Value::Map(vec![(0.into(), text("not bytes"))]))]),
        map([(
            NAMESPACE,
            Value::Map(vec![
                (0.into(), Value::Bytes(vec![0; 32])),
                (0.into(), Value::Bytes(vec![1; 32])),
            ]),
        )]),
        map([
            (
                NAMESPACE,
                Value::Map(vec![(0.into(), Value::Bytes(vec![0; 32]))]),
            ),
            (
                NAMESPACE,
                Value::Map(vec![(1.into(), Value::Bytes(vec![0; 32]))]),
            ),
        ]),
        Value::Array(vec![]),
    ] {
        set(&mut value, "valueDigests", digests);
        assert!(parse(&value).is_err());
    }
}

#[test]
fn absence_is_distinct_from_unknown_or_known_status() {
    assert!(parse(&valid_mso()).expect("valid MSO").status.is_none());
    for raw in [
        map([("identifier_list", 7.into())]),
        status(42.into(), text("https://issuer.example/status/list")),
        map([
            (
                "status_list",
                map([
                    ("idx", 42.into()),
                    ("uri", text("https://issuer.example/status/list")),
                    ("future", Value::Bool(true)),
                ]),
            ),
            ("future_status", Value::Bytes(vec![1, 2, 3])),
        ]),
    ] {
        let mut value = valid_mso();
        set(&mut value, "status", raw.clone());
        let parsed = parse(&value)
            .expect("status structure accepted")
            .status
            .expect("present status must never disappear");
        assert_eq!(parsed.raw, raw);
        if let Some(reference) = parsed.status_list {
            assert_eq!(reference.idx, 42);
            assert_eq!(reference.uri, "https://issuer.example/status/list");
        }
    }
}

#[test]
fn malformed_status_is_never_treated_as_absence() {
    for raw in [
        Value::Null,
        Value::Map(vec![]),
        Value::Array(vec![]),
        Value::Map(vec![(1.into(), Value::Null)]),
        map([("status_list", Value::Null)]),
        map([("status_list", Value::Map(vec![]))]),
        map([("status_list", map([("idx", 0.into())]))]),
        map([(
            "status_list",
            map([("uri", text("https://issuer.example/list"))]),
        )]),
        status(text("42"), text("https://issuer.example/list")),
        status((-1).into(), text("https://issuer.example/list")),
        status(Value::Float(0.0), text("https://issuer.example/list")),
        status(
            0.into(),
            Value::Bytes(b"https://issuer.example/list".to_vec()),
        ),
        map([(
            "status_list",
            Value::Map(vec![
                (text("idx"), 0.into()),
                (text("idx"), 1.into()),
                (text("uri"), text("https://issuer.example/list")),
            ]),
        )]),
        map([("unknown", Value::Null), ("unknown", Value::Bool(true))]),
    ] {
        let mut value = valid_mso();
        set(&mut value, "status", raw);
        assert!(parse(&value).is_err(), "invalid status must reject the MSO");
    }
}

#[test]
fn status_uri_uses_rfc3986_without_normalizing_or_authorizing_fetch() {
    for uri in [
        "",
        "/relative",
        "//issuer.example/list",
        "https://issuer.example/%GG",
        "https://issuer.example/has space",
        "https://例子.example/list",
    ] {
        let mut value = valid_mso();
        set(&mut value, "status", status(0.into(), text(uri)));
        assert!(parse(&value).is_err(), "invalid URI {uri:?}");
    }
    // Scheme/host allowlists, HTTPS requirements and fragment restrictions are
    // relying-party policy. The core validates generic URI syntax only.
    for uri in [
        "https://ISSUER.example:443/a/%2f?q=%41#fragment",
        "urn:example:status",
        "http://127.0.0.1/list",
    ] {
        let mut value = valid_mso();
        set(&mut value, "status", status(u64::MAX.into(), text(uri)));
        let reference = parse(&value)
            .expect("valid generic URI")
            .status
            .expect("status present")
            .status_list
            .expect("known reference");
        assert_eq!(reference.uri, uri, "preserve reference identity exactly");
        assert_eq!(
            reference.idx,
            u64::MAX,
            "range bounds need the fetched list"
        );
    }
}

#[test]
fn timestamp_tag_and_iso_utc_whole_second_profile_are_required() {
    for field in ["signed", "validFrom", "validUntil"] {
        for bad in [
            text("2026-01-01T00:00:00Z"),
            Value::Tag(1, Box::new(1_767_225_600u64.into())),
            Value::Tag(6, Box::new(text("2026-01-01T00:00:00Z"))),
            Value::Tag(0, Box::new(0.into())),
            tdate("2026-01-01T00:00:00.000Z"),
            tdate("2026-01-01T00:00:00+00:00"),
            tdate("2026-01-01T00:00:00-01:00"),
            tdate("2026-01-01T00:00:00"),
            tdate("2026-01-01T00:00:00z"),
            tdate("2026-01-01X00:00:00Z"),
            tdate("2026-01-01\x0000:00:00Z"),
            tdate("2026-01-01t00:00:00Z"),
            tdate("2026-02-30T00:00:00Z"),
        ] {
            let mut value = valid_mso();
            set(member_mut(&mut value, "validityInfo"), field, bad);
            assert!(parse(&value).is_err(), "invalid {field} representation");
        }
    }
}

#[test]
fn validity_order_and_required_members_are_enforced() {
    for (signed, from, until) in [
        (
            "2026-01-02T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        ),
        (
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ),
        (
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ),
    ] {
        let mut value = valid_mso();
        set(
            &mut value,
            "validityInfo",
            map([
                ("signed", tdate(signed)),
                ("validFrom", tdate(from)),
                ("validUntil", tdate(until)),
            ]),
        );
        assert!(parse(&value).is_err());
    }
    for field in ["signed", "validFrom", "validUntil"] {
        let mut value = valid_mso();
        remove(member_mut(&mut value, "validityInfo"), field);
        assert!(parse(&value).is_err());
    }
    let mut value = valid_mso();
    set(
        member_mut(&mut value, "validityInfo"),
        "expectedUpdate",
        tdate("2026-06-01T00:00:00Z"),
    );
    assert!(
        parse(&value)
            .expect("valid expectedUpdate")
            .validity_info
            .expected_update
            .is_some()
    );
    set(
        member_mut(&mut value, "validityInfo"),
        "futureRule",
        Value::Null,
    );
    assert!(
        parse(&value).is_err(),
        "unknown validity semantics must fail closed"
    );
}

#[test]
fn key_authorizations_preserve_both_disjoint_forms() {
    let mut value = valid_mso();
    set(
        member_mut(&mut value, "deviceKeyInfo"),
        "keyAuthorizations",
        map([
            ("nameSpaces", Value::Array(vec![text("whole.namespace")])),
            (
                "dataElements",
                map([(
                    "other.namespace",
                    Value::Array(vec![text("selected_element")]),
                )]),
            ),
        ]),
    );
    let authorization = parse(&value)
        .expect("disjoint authorizations")
        .device_key_info
        .key_authorizations
        .expect("authorization present");
    assert_eq!(
        authorization.name_spaces.expect("namespaces"),
        ["whole.namespace"]
    );
    assert_eq!(
        authorization.data_elements.expect("elements")["other.namespace"],
        ["selected_element"]
    );
}

#[test]
fn malformed_or_overlapping_key_authorizations_are_rejected_without_filtering() {
    for authorization in [
        Value::Null,
        Value::Map(vec![]),
        map([("nameSpaces", Value::Array(vec![]))]),
        map([(
            "nameSpaces",
            Value::Array(vec![text("namespace"), 1.into()]),
        )]),
        map([("nameSpaces", text("namespace"))]),
        map([("dataElements", Value::Map(vec![]))]),
        map([("dataElements", map([("namespace", Value::Array(vec![]))]))]),
        map([(
            "dataElements",
            map([("namespace", Value::Array(vec![Value::Null]))]),
        )]),
        map([(
            "dataElements",
            Value::Map(vec![(0.into(), Value::Array(vec![text("element")]))]),
        )]),
        map([
            ("nameSpaces", Value::Array(vec![text("namespace")])),
            (
                "dataElements",
                map([("namespace", Value::Array(vec![text("element")]))]),
            ),
        ]),
        map([("futureAuthorization", Value::Bool(true))]),
    ] {
        let mut value = valid_mso();
        set(
            member_mut(&mut value, "deviceKeyInfo"),
            "keyAuthorizations",
            authorization,
        );
        assert!(parse(&value).is_err());
    }
}

#[test]
fn device_key_is_required_and_information_extensions_are_preserved() {
    let mut value = valid_mso();
    remove(member_mut(&mut value, "deviceKeyInfo"), "deviceKey");
    assert!(parse(&value).is_err());

    let mut value = valid_mso();
    let key_info = Value::Map(vec![((-1).into(), Value::Bytes(vec![7, 8, 9]))]);
    set(
        member_mut(&mut value, "deviceKeyInfo"),
        "keyInfo",
        key_info.clone(),
    );
    set(
        member_mut(&mut value, "deviceKeyInfo"),
        "futureKeyRule",
        Value::Bool(true),
    );
    set(&mut value, "futureMsoRule", Value::Bytes(vec![1, 2, 3]));
    let parsed = parse(&value).expect("preserve extensions for verifier profile");
    assert_eq!(parsed.device_key_info.key_info, Some(key_info));
    assert_eq!(
        parsed.device_key_info.additional_fields["futureKeyRule"],
        Value::Bool(true)
    );
    assert_eq!(
        parsed.additional_fields["futureMsoRule"],
        Value::Bytes(vec![1, 2, 3])
    );
    set(
        member_mut(&mut value, "deviceKeyInfo"),
        "keyInfo",
        map([("not_integer", Value::Null)]),
    );
    assert!(parse(&value).is_err());
}

fn auth_with_chain(value: Value) -> IssuerAuth {
    let mut cose = CoseSign1::default();
    cose.unprotected.rest.push((Label::Int(33), value));
    IssuerAuth::new(cose)
}

#[test]
fn x5chain_checks_every_entry_and_borrows_the_leaf() {
    for value in [
        Value::Bytes(vec![1, 2]),
        Value::Array(vec![Value::Bytes(vec![1, 2]), Value::Bytes(vec![3, 4])]),
    ] {
        let auth = auth_with_chain(value);
        assert_eq!(auth.certificate_der().expect("leaf"), [1, 2]);
        let leaf = auth.certificate_der().expect("same leaf");
        let original = match &auth.cose_sign1.unprotected.rest[0].1 {
            Value::Bytes(bytes) => bytes,
            Value::Array(chain) => chain[0].as_bytes().expect("leaf bytes"),
            _ => unreachable!(),
        };
        assert!(
            std::ptr::eq(leaf.as_ptr(), original.as_ptr()),
            "certificate leaf must be borrowed"
        );
        assert_eq!(auth.certificate_chain_der().expect("chain")[0], [1, 2]);
    }
    for value in [
        Value::Null,
        Value::Bytes(vec![]),
        Value::Array(vec![]),
        Value::Array(vec![Value::Bytes(vec![1]), Value::Null]),
        Value::Array(vec![
            Value::Bytes(vec![1]),
            text("silently dropped in the old implementation"),
        ]),
        Value::Array(vec![Value::Bytes(vec![1]), Value::Bytes(vec![])]),
    ] {
        let auth = auth_with_chain(value);
        assert!(
            auth.certificate_der().is_err(),
            "later malformed entries also reject leaf extraction"
        );
        assert!(auth.certificate_chain_der().is_err());
    }
}

#[test]
fn missing_duplicate_or_protected_x5chain_is_rejected() {
    assert!(
        IssuerAuth::new(CoseSign1::default())
            .certificate_der()
            .is_err()
    );
    let mut duplicate = auth_with_chain(Value::Bytes(vec![1]));
    duplicate
        .cose_sign1
        .unprotected
        .rest
        .push((Label::Int(33), Value::Bytes(vec![2])));
    assert!(duplicate.certificate_der().is_err());
    let mut protected = auth_with_chain(Value::Bytes(vec![1]));
    protected
        .cose_sign1
        .protected
        .header
        .rest
        .push((Label::Int(33), Value::Bytes(vec![1])));
    assert!(protected.certificate_der().is_err());
}

proptest! {
    #[test]
    fn all_unsigned_status_indices_are_preserved(index in any::<u64>()) {
        let mut value = valid_mso();
        set(&mut value, "status", status(index.into(), text("https://issuer.example/status/list")));
        let reference = parse(&value).expect("valid status").status.expect("status present").status_list.expect("known reference");
        prop_assert_eq!(reference.idx, index);
    }

    #[test]
    fn unknown_status_payloads_cannot_be_silently_discarded(payload in prop::collection::vec(any::<u8>(), 0..256)) {
        let raw = map([("future_status", Value::Bytes(payload))]);
        let mut value = valid_mso();
        set(&mut value, "status", raw.clone());
        let parsed = parse(&value).expect("retained unknown mechanism").status.expect("status must remain present");
        prop_assert_eq!(parsed.raw, raw);
        prop_assert!(parsed.status_list.is_none());
    }

    #[test]
    fn digest_id_range_boundary_is_enforced(id in any::<u32>()) {
        let mut value = valid_mso();
        set(&mut value, "valueDigests", map([(NAMESPACE, Value::Map(vec![(id.into(), Value::Bytes(vec![0; 32]))]))]));
        prop_assert_eq!(parse(&value).is_ok(), id < 1 << 31);
    }
}
