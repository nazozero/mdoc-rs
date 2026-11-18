//! Wire-level type preservation, independent of issuance and application trust.
//!
//! Small CBOR bignums are still tagged byte strings, not native protocol ints.
//! These tests use explicit wire bytes and the inherited Annex D MSO. Mutated
//! Annex D payloads are structural fixtures, not authenticated credentials.
//! The direct COSE tests use independently generated, cryptographically valid
//! signatures/tags over deliberately invalid typed headers, so a bad signature
//! cannot accidentally make their policy-rejection assertions pass.

use ciborium::Value;
use coset::{CoseMac0, CoseSign1, Header, HeaderBuilder, ProtectedHeader, iana};
use nazo_mdoc::{
    MdocError,
    cbor::{data_item, raw},
    cose::{validate_verification_key, verify_cose_signature},
    device_auth::{verify_device_auth, verify_device_mac},
    model::{DeviceAuth, IssuerAuth},
    parser,
};

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("literal wire fixture")
}

fn encode(value: &Value) -> Vec<u8> {
    let mut result = Vec::new();
    ciborium::into_writer(value, &mut result).expect("encode fixture");
    result
}

fn tagged_integer(tag: u64, magnitude: Vec<u8>) -> Value {
    Value::Tag(tag, Box::new(Value::Bytes(magnitude)))
}

fn field_mut<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    &mut value
        .as_map_mut()
        .expect("fixture map")
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .expect("fixture field")
        .1
}

fn set_field(value: &mut Value, name: &str, replacement: Value) {
    let fields = value.as_map_mut().expect("fixture map");
    if let Some((_, current)) = fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
    {
        *current = replacement;
    } else {
        fields.push((name.into(), replacement));
    }
}

fn annex_mso() -> (IssuerAuth, Value) {
    let document = parser::parse_hex(include_str!("vectors/iso_18013_5_annex_d_mdl.hex"))
        .expect("inherited independent Annex D wire")
        .documents
        .remove(0);
    let auth = document.issuer_signed.issuer_auth;
    let inner = raw::tag24_inner(auth.cose_sign1.payload.as_deref().unwrap()).unwrap();
    // The existing fixture has no bignums. Expected tagged values below are
    // constructed explicitly, never decoded through the implementation tested.
    let mso = ciborium::from_reader(inner).expect("original fixture MSO");
    (auth, mso)
}

fn replace_mso(auth: &mut IssuerAuth, mso: &Value) -> Vec<u8> {
    let payload = encode(&Value::Tag(24, Box::new(Value::Bytes(encode(mso)))));
    auth.cose_sign1.payload = Some(payload.clone());
    payload
}

#[test]
fn bignum_tags_survive_direct_arrays_maps_and_tag24_at_integer_boundaries() {
    for tag in [2u8, 3] {
        for length in [0usize, 1, 8, 16, 17] {
            let magnitude = vec![0xff; length];
            // All lengths here fit the one-byte bstr header. No decoder or
            // bignum arithmetic is used to obtain these expected wire values.
            let mut wire = vec![0xc0 + tag, 0x40 + length as u8];
            wire.extend_from_slice(&magnitude);
            let expected = tagged_integer(u64::from(tag), magnitude);
            assert!(raw::validate(&wire).is_ok());
            let decoded = data_item::decode_cbor(&wire).unwrap();
            assert_eq!(decoded, expected, "tag {tag}, magnitude length {length}");
            assert_eq!(encode(&decoded), wire, "received representation survives");

            let mut array = vec![0x81];
            array.extend_from_slice(&wire);
            assert_eq!(
                data_item::decode_cbor(&array).unwrap(),
                Value::Array(vec![expected.clone()])
            );

            let mut map = bytes("a16178"); // {"x": <tagged value>}
            map.extend_from_slice(&wire);
            assert_eq!(
                data_item::decode_cbor(&map).unwrap(),
                Value::Map(vec![("x".into(), expected.clone())])
            );

            let embedded = Value::Tag(24, Box::new(Value::Bytes(wire.clone())));
            let envelope = encode(&embedded);
            assert_eq!(data_item::decode_cbor(&envelope).unwrap(), embedded);
            assert_eq!(data_item::decode_tag24(&embedded).unwrap(), expected);
            assert_eq!(raw::tag24_inner(&envelope).unwrap(), wire);
        }
    }
}

#[test]
fn nested_unknown_tags_do_not_erase_positive_or_negative_bignums() {
    // 60000({"x": [2(h'01'), 3(h'06')]}), not {"x": [1, -7]}.
    let wire = bytes("d9ea60a1617882c24101c34106");
    let expected = Value::Tag(
        60000,
        Box::new(Value::Map(vec![(
            "x".into(),
            Value::Array(vec![tagged_integer(2, vec![1]), tagged_integer(3, vec![6])]),
        )])),
    );
    let decoded = data_item::decode_cbor(&wire).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(encode(&decoded), wire);
}

#[test]
fn unknown_status_mechanism_retains_its_entire_tagged_value_and_payload_bytes() {
    let (mut auth, mut mso) = annex_mso();
    let expected = Value::Map(vec![(
        "future".into(),
        Value::Array(vec![
            tagged_integer(2, vec![1]),
            Value::Map(vec![("x".into(), tagged_integer(3, vec![6]))]),
        ]),
    )]);
    let expected_wire = bytes("a16666757475726582c24101a16178c34106");
    assert_eq!(encode(&expected), expected_wire);
    set_field(&mut mso, "status", expected.clone());
    let received_payload = replace_mso(&mut auth, &mso);

    let status = auth.mso().unwrap().status.expect("status cannot disappear");
    assert!(
        status.status_list.is_none(),
        "unknown mechanism stays unknown"
    );
    assert_eq!(status.raw, expected);
    assert_eq!(encode(&status.raw), expected_wire);
    assert_eq!(
        auth.cose_sign1.payload.as_deref(),
        Some(received_payload.as_slice())
    );
}

#[test]
fn status_list_index_requires_a_native_unsigned_integer() {
    let (mut auth, mut mso) = annex_mso();
    let status = Value::Map(vec![(
        "status_list".into(),
        Value::Map(vec![
            ("idx".into(), 0.into()),
            ("uri".into(), "https://issuer.example/status".into()),
        ]),
    )]);
    set_field(&mut mso, "status", status);
    let _ = replace_mso(&mut auth, &mso);
    assert_eq!(
        auth.mso().unwrap().status.unwrap().status_list.unwrap().idx,
        0
    );

    // Each bignum denotes a value representable by u64. A normalizing decoder
    // used to turn these invalid field types into accepted integer indexes.
    for magnitude in [vec![], vec![0], vec![1], vec![0xff; 8]] {
        let mut modified = mso.clone();
        *field_mut(
            field_mut(field_mut(&mut modified, "status"), "status_list"),
            "idx",
        ) = tagged_integer(2, magnitude.clone());
        let received_payload = replace_mso(&mut auth, &modified);
        assert!(
            auth.mso().is_err(),
            "tagged idx {magnitude:?} cannot become uint"
        );
        assert_eq!(
            auth.cose_sign1.payload.as_deref(),
            Some(received_payload.as_slice())
        );
    }
}

#[test]
fn device_key_kty_curve_and_declared_algorithm_cannot_be_tagged_integers() {
    let (mut auth, mso) = annex_mso();
    validate_verification_key(&auth.mso().unwrap().device_key_info.device_key, -7).unwrap();
    for (label, replacement) in [
        (1i64, tagged_integer(2, vec![2])), // kty = EC2
        (-1, tagged_integer(2, vec![1])),   // crv = P-256
        (3, tagged_integer(3, vec![6])),    // alg = ES256
    ] {
        let mut modified = mso.clone();
        let fields = field_mut(field_mut(&mut modified, "deviceKeyInfo"), "deviceKey")
            .as_map_mut()
            .unwrap();
        if let Some((_, value)) = fields.iter_mut().find(|(key, _)| {
            key.as_integer().and_then(|key| i64::try_from(key).ok()) == Some(label)
        }) {
            *value = replacement;
        } else {
            fields.push((label.into(), replacement));
        }
        let _ = replace_mso(&mut auth, &modified);
        // kty/alg can fail model decoding; curve is a COSE key parameter whose
        // native integer type must also be enforced by key-use validation.
        let usable = auth
            .mso()
            .and_then(|mso| validate_verification_key(&mso.device_key_info.device_key, -7));
        assert!(
            usable.is_err(),
            "tagged COSE key parameter {label} cannot be usable"
        );
    }
}

// These helpers frame already-encoded values without decoding them. In
// particular, they must not erase the f7 or tagged types under test.
fn wire_map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    assert!(entries.len() < 24);
    let mut wire = vec![0xa0 + entries.len() as u8];
    for (key, value) in entries {
        wire.extend_from_slice(&encode(&Value::Text((*key).into())));
        wire.extend_from_slice(value);
    }
    wire
}

fn cose_wire(protected: &[u8], unprotected: &Value, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x84];
    wire.extend_from_slice(&encode(&Value::Bytes(protected.to_vec())));
    wire.extend_from_slice(&encode(unprotected));
    wire.extend_from_slice(payload);
    wire.extend_from_slice(&encode(&Value::Bytes(vec![0; 64])));
    wire
}

fn parse_role(cose: Vec<u8>, role: &str) -> Result<(), MdocError> {
    if role == "issuerAuth" {
        return parser::parse_issued(&wire_map(&[(role, cose)])).map(|_| ());
    }
    let issuer = wire_map(&[(
        "issuerAuth",
        cose_wire(&bytes("a10126"), &Value::Map(vec![]), &[0xf6]),
    )]);
    let device = wire_map(&[
        ("nameSpaces", bytes("d81841a0")),
        ("deviceAuth", wire_map(&[(role, cose)])),
    ]);
    let document = wire_map(&[
        ("docType", encode(&"test".into())),
        ("issuerSigned", issuer),
        ("deviceSigned", device),
    ]);
    let mut documents = vec![0x81];
    documents.extend_from_slice(&document);
    parser::parse(&wire_map(&[
        ("version", encode(&"1.0".into())),
        ("documents", documents),
        ("status", vec![0]),
    ]))
    .map(|_| ())
}

#[test]
fn issuer_item_retains_tagged_claim_value_and_original_tag24_bytes() {
    let expected = Value::Array(vec![tagged_integer(2, vec![1]), tagged_integer(3, vec![6])]);
    let item = Value::Map(vec![
        ("digestID".into(), 0.into()),
        ("random".into(), Value::Bytes(vec![42; 16])),
        ("elementIdentifier".into(), "tagged_value".into()),
        ("elementValue".into(), expected.clone()),
    ]);
    let tagged = Value::Tag(24, Box::new(Value::Bytes(encode(&item))));
    let received_item = encode(&tagged);
    let issuer = wire_map(&[
        (
            "issuerAuth",
            cose_wire(&bytes("a10126"), &Value::Map(vec![]), &[0xf6]),
        ),
        (
            "nameSpaces",
            encode(&Value::Map(vec![(
                "org.example".into(),
                Value::Array(vec![tagged]),
            )])),
        ),
    ]);
    let parsed = parser::parse_issued(&issuer).unwrap();
    let item = &parsed.name_spaces["org.example"][0];
    assert_eq!(item.element_value, expected);
    assert_eq!(item.encoded, received_item);
}

#[test]
fn cose_alg_and_critical_labels_reject_bignums_in_every_wire_role() {
    for role in ["issuerAuth", "deviceSignature", "deviceMac"] {
        let ordinary = if role == "deviceMac" {
            "a10105"
        } else {
            "a10126"
        };
        let tagged_alg = if role == "deviceMac" {
            "a101c24105"
        } else {
            "a101c34106"
        };
        let ordinary_critical = if role == "deviceMac" {
            "a20105028101"
        } else {
            "a20126028101"
        };
        let tagged_critical = if role == "deviceMac" {
            "a201050281c24101"
        } else {
            "a201260281c24101"
        };
        for good in [ordinary, ordinary_critical] {
            assert!(
                parse_role(cose_wire(&bytes(good), &Value::Map(vec![]), &[0xf6]), role).is_ok()
            );
        }
        for bad in [tagged_alg, tagged_critical] {
            assert!(
                parse_role(cose_wire(&bytes(bad), &Value::Map(vec![]), &[0xf6]), role).is_err(),
                "{role} must reject original protected header {bad}"
            );
        }
        let unprotected = Value::Map(vec![(
            2.into(),
            Value::Array(vec![tagged_integer(2, vec![1])]),
        )]);
        assert!(parse_role(cose_wire(&bytes(ordinary), &unprotected, &[0xf6]), role).is_err());
    }
}

#[test]
fn undefined_and_unsupported_simple_values_fail_before_value_projection() {
    for wire in ["f7", "e0", "f0", "f820", "f8ff"] {
        let scalar = bytes(wire);
        let mut array = vec![0x81];
        array.extend_from_slice(&scalar);
        let map = wire_map(&[("x", scalar.clone())]);
        let embedded = encode(&Value::Tag(24, Box::new(Value::Bytes(scalar.clone()))));
        for context in [scalar, array, map, embedded] {
            assert!(
                raw::validate(&context).is_err(),
                "unsupported simple wire {wire}"
            );
            assert!(data_item::decode_cbor(&context).is_err());
        }
    }
    for (wire, expected) in [
        ("f4", Value::Bool(false)),
        ("f5", Value::Bool(true)),
        ("f6", Value::Null),
        ("f93c00", Value::Float(1.0)),
        ("fa3f800000", Value::Float(1.0)),
        ("fb3ff0000000000000", Value::Float(1.0)),
    ] {
        assert_eq!(data_item::decode_cbor(&bytes(wire)).unwrap(), expected);
    }
}

#[test]
fn undefined_cannot_be_accepted_as_a_detached_null_payload() {
    for role in ["issuerAuth", "deviceSignature", "deviceMac"] {
        let protected = bytes(if role == "deviceMac" {
            "a10105"
        } else {
            "a10126"
        });
        assert!(parse_role(cose_wire(&protected, &Value::Map(vec![]), &[0xf6]), role).is_ok());
        assert!(
            parse_role(cose_wire(&protected, &Value::Map(vec![]), &[0xf7]), role).is_err(),
            "{role}: undefined is not COSE's detached null"
        );
    }
}

const PAYLOAD_HEX: &str = concat!(
    "d8185823847444657669636541757468656e7469636174696f6e",
    "83f6f6f66474657374d81841a0",
);

fn original_header(algorithm: iana::Algorithm, crit: bool, wire: &[u8]) -> ProtectedHeader {
    let mut builder = HeaderBuilder::new().algorithm(algorithm);
    if crit {
        builder = builder.add_critical(iana::HeaderParameter::Alg);
    }
    ProtectedHeader {
        original_data: Some(wire.to_vec()),
        header: builder.build(),
    }
}

fn structure(prefix: &str, protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut wire = bytes(prefix);
    wire.extend_from_slice(&encode(&Value::Bytes(protected.to_vec())));
    wire.push(0x40); // empty external_aad
    wire.extend_from_slice(&encode(&Value::Bytes(payload.to_vec())));
    wire
}

#[test]
fn direct_sign1_verification_rejects_signed_bignum_header_types() {
    // Synthetic independent Python cryptography/OpenSSL ECDSA signatures over
    // explicit Sig_structure bytes (RFC 9052 section 4.4), using private scalar
    // 1 on P-256. All three signatures were independently verified in Python.
    // The public point is the curve generator. These are not official vectors.
    let public = nazo_mdoc::cose::key::cose_key_from_sec1_bytes(
        1,
        &bytes(concat!(
            "04",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )),
    )
    .unwrap();
    let payload = bytes(PAYLOAD_HEX);
    for (header_hex, signature_hex, critical, accepted) in [
        (
            "a10126",
            concat!(
                "1164b58485a29cbf288e1d908a48fe3eb7dce91fc20879974d8f95b0e8f2575e4",
                "fc647c6a47ead66ca35f120792d05734b30d77344645178a9c31a575aabee38"
            ),
            false,
            true,
        ),
        (
            "a101c34106",
            concat!(
                "f8baca85984f8d635c7f490952fc29a9f333b5a164fae0be23421cbd13ae17b82",
                "f57fa1ad51053483d3a2b0a4ba3da5be25f40c8c51402b25d17a432e61b1779"
            ),
            false,
            false,
        ),
        (
            "a201260281c24101",
            concat!(
                "c5e4d691fbc8f130acde0edbd3a37ee3680f73912a84f3810ef45f41f86e8ec0",
                "735cdd7f6ceaa7002bd5d87572071e247940a2d962a61330f8f6a88d4c172a9f"
            ),
            true,
            false,
        ),
    ] {
        let header = bytes(header_hex);
        let signature = bytes(signature_hex);
        let tbs = structure("846a5369676e617475726531", &header, &payload);
        assert!(verify_cose_signature(&tbs, &signature, &public, -7).unwrap());
        let auth = DeviceAuth::Signature(CoseSign1 {
            protected: original_header(iana::Algorithm::ES256, critical, &header),
            unprotected: Header::default(),
            payload: None,
            signature,
        });
        let result = verify_device_auth(&auth, &payload, &public, None);
        if accepted {
            assert!(result.unwrap().is_valid);
        } else {
            assert!(
                result.is_err(),
                "valid signature does not authorize header {header_hex}"
            );
        }
    }
}

#[test]
fn direct_mac0_verification_rejects_authenticated_bignum_header_types() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Independent Python standard-library tags:
    // hmac.digest(bytes(range(32)), explicit_mac_structure, hashlib.sha256).
    // Typed normalized headers are intentionally supplied to reproduce direct
    // callers bypassing wire parsing; original_data must still be checked.
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let payload = bytes(PAYLOAD_HEX);
    for (header_hex, tag_hex, critical, accepted) in [
        (
            "a10105",
            "8e61aa68d003dafbd1a92e7e6393fe6a348a1568f3bfc3d26bd0571c556364da",
            false,
            true,
        ),
        (
            "a101c24105",
            "904cd073117b8df27afed5c27e1a1d9c2ddbaea55249ac53a9cbf5b5272bad85",
            false,
            false,
        ),
        (
            "a201050281c24101",
            "c091549fad27d90981f5233e234846ed5c1865906b5638f2be0a06447a0e7716",
            true,
            false,
        ),
    ] {
        let header = bytes(header_hex);
        let tag = bytes(tag_hex);
        let authenticated = structure("84644d414330", &header, &payload);
        let mut check = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        check.update(&authenticated);
        check
            .verify_slice(&tag)
            .expect("independent tag authenticates the raw header");
        let mac = CoseMac0 {
            protected: original_header(iana::Algorithm::HMAC_256_256, critical, &header),
            unprotected: Header::default(),
            payload: None,
            tag,
        };
        let result = verify_device_mac(&mac, &payload, &key);
        if accepted {
            assert!(result.unwrap().is_valid);
        } else {
            assert!(
                result.is_err(),
                "valid MAC does not authorize header {header_hex}"
            );
        }
    }
}
