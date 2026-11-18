//! OpenID4VP 1.0 Final and ISO device-authentication regression vectors.
//!
//! The handover vectors below are the non-normative examples published by the
//! OpenID Foundation in OpenID4VP 1.0 Final B.2.6.1 and B.2.6.2:
//! https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html
//! Copyright (c) 2025 OpenID Foundation. Attribution does not imply endorsement
//! or certification. Their SHA-256/RFC7638 values were also independently
//! recomputed with Python's hashlib, json, and hmac standard-library modules.

use std::borrow::Cow;

use ciborium::Value;
use nazo_mdoc::session::{
    DcApiHandover, RedirectHandover, SessionBinding, SessionTranscript,
    build_device_authentication, build_device_authentication_bytes, derive_ephemeral_mac_key,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

const NONCE: &str = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
const REDIRECT_HEX: &str = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac";
const DC_API_HEX: &str = "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a";
const EMPTY_NAMESPACES: &[u8] = &[0xd8, 0x18, 0x41, 0xa0];

fn thumbprint() -> [u8; 32] {
    hex::decode("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047")
        .unwrap()
        .try_into()
        .unwrap()
}

fn redirect_context(thumbprint: Option<&[u8; 32]>) -> RedirectHandover<'_> {
    RedirectHandover {
        client_id: "x509_san_dns:example.com",
        nonce: NONCE,
        jwk_thumbprint: thumbprint,
        response_uri: "https://example.com/response",
    }
}

fn dc_api_context(thumbprint: Option<&[u8; 32]>) -> DcApiHandover<'_> {
    DcApiHandover {
        origin: "https://example.com",
        nonce: NONCE,
        jwk_thumbprint: thumbprint,
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

#[test]
fn final_redirect_matches_official_vector_and_borrows_validated_bytes() {
    let expected = hex::decode(REDIRECT_HEX).unwrap();
    let thumbprint = thumbprint();
    let context = redirect_context(Some(&thumbprint));
    let transcript = SessionTranscript::redirect(context).unwrap();
    assert_eq!(transcript.as_bytes(), expected);
    assert_eq!(transcript.binding(), SessionBinding::OpenId4VpRedirect);
    let borrowed = SessionTranscript::validate_redirect(&expected, context).unwrap();
    assert_eq!(borrowed.as_bytes().as_ptr(), expected.as_ptr());
    assert_eq!(borrowed.binding(), SessionBinding::OpenId4VpRedirect);
}

#[test]
fn final_dc_api_matches_official_vector_and_borrows_validated_bytes() {
    let expected = hex::decode(DC_API_HEX).unwrap();
    let thumbprint = thumbprint();
    let context = dc_api_context(Some(&thumbprint));
    let transcript = SessionTranscript::dc_api(context).unwrap();
    assert_eq!(transcript.as_bytes(), expected);
    assert_eq!(transcript.binding(), SessionBinding::OpenId4VpDcApi);
    let borrowed = SessionTranscript::validate_dc_api(&expected, context).unwrap();
    assert_eq!(borrowed.as_bytes().as_ptr(), expected.as_ptr());
}

#[test]
fn official_thumbprint_excludes_optional_jwk_members() {
    // RFC7638 lexicographic ordering of only the mandatory public members.
    let canonical = r#"{"crv":"P-256","kty":"EC","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0","y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc"}"#;
    assert_eq!(&Sha256::digest(canonical.as_bytes())[..], thumbprint());
}

#[test]
fn every_redirect_context_parameter_is_bound() {
    let bytes = hex::decode(REDIRECT_HEX).unwrap();
    let thumbprint = thumbprint();
    let context = redirect_context(Some(&thumbprint));
    let mut other_key = thumbprint;
    other_key[0] ^= 1;
    for changed in [
        RedirectHandover {
            nonce: "different",
            ..context
        },
        RedirectHandover {
            client_id: "example.com",
            ..context
        },
        RedirectHandover {
            response_uri: "https://example.com/elsewhere",
            ..context
        },
        RedirectHandover {
            jwk_thumbprint: Some(&other_key),
            ..context
        },
        RedirectHandover {
            jwk_thumbprint: None,
            ..context
        },
    ] {
        assert!(SessionTranscript::validate_redirect(&bytes, changed).is_err());
    }
}

#[test]
fn every_dc_api_context_parameter_and_transport_is_bound() {
    let bytes = hex::decode(DC_API_HEX).unwrap();
    let thumbprint = thumbprint();
    let context = dc_api_context(Some(&thumbprint));
    let mut other_key = thumbprint;
    other_key[31] ^= 1;
    for changed in [
        DcApiHandover {
            nonce: "different",
            ..context
        },
        DcApiHandover {
            origin: "https://other.example",
            ..context
        },
        DcApiHandover {
            origin: "origin:https://example.com",
            ..context
        },
        DcApiHandover {
            jwk_thumbprint: Some(&other_key),
            ..context
        },
        DcApiHandover {
            jwk_thumbprint: None,
            ..context
        },
    ] {
        assert!(SessionTranscript::validate_dc_api(&bytes, changed).is_err());
    }
    assert!(
        SessionTranscript::validate_redirect(&bytes, redirect_context(Some(&thumbprint))).is_err()
    );
    assert!(
        SessionTranscript::validate_dc_api(&hex::decode(REDIRECT_HEX).unwrap(), context,).is_err()
    );
}

#[test]
fn unencrypted_modes_bind_null_instead_of_empty_or_text_thumbprint() {
    let context = redirect_context(None);
    let transcript = SessionTranscript::redirect(context).unwrap();
    let info = Value::Array(vec![
        Value::Text(context.client_id.into()),
        Value::Text(context.nonce.into()),
        Value::Null,
        Value::Text(context.response_uri.into()),
    ]);
    let expected = Sha256::digest(encode(&info));
    assert_eq!(&transcript.as_bytes()[24..], &expected[..]);
    assert!(SessionTranscript::validate_redirect(transcript.as_bytes(), context).is_ok());
    let thumbprint = thumbprint();
    assert!(
        SessionTranscript::validate_redirect(
            transcript.as_bytes(),
            redirect_context(Some(&thumbprint)),
        )
        .is_err()
    );

    let context = dc_api_context(None);
    let transcript = SessionTranscript::dc_api(context).unwrap();
    let info = Value::Array(vec![
        Value::Text(context.origin.into()),
        Value::Text(context.nonce.into()),
        Value::Null,
    ]);
    assert_eq!(
        &transcript.as_bytes()[29..],
        &Sha256::digest(encode(&info))[..]
    );
}

#[test]
fn every_byte_of_the_official_transcript_is_authenticated_by_context() {
    let original = hex::decode(REDIRECT_HEX).unwrap();
    let thumbprint = thumbprint();
    let context = redirect_context(Some(&thumbprint));
    for index in 0..original.len() {
        for bit in 0..8 {
            let mut changed = original.clone();
            changed[index] ^= 1 << bit;
            assert!(SessionTranscript::validate_redirect(&changed, context).is_err());
        }
    }
}

#[test]
fn rejects_old_draft_handover_as_final() {
    let thumbprint = thumbprint();
    let context = redirect_context(Some(&thumbprint));
    for handover in [
        Value::Array(vec![
            Value::Text("mdoc-generated-nonce".into()),
            Value::Text(context.client_id.into()),
            Value::Text(context.response_uri.into()),
            Value::Text(context.nonce.into()),
        ]),
        Value::Array(vec![
            Value::Bytes(vec![1; 32]),
            Value::Bytes(vec![2; 32]),
            Value::Text(context.nonce.into()),
        ]),
    ] {
        let bytes = encode(&Value::Array(vec![Value::Null, Value::Null, handover]));
        // Generic structural validation intentionally does not assign a profile.
        assert_eq!(
            SessionTranscript::from_cbor(&bytes).unwrap().binding(),
            SessionBinding::StructureOnly
        );
        assert!(SessionTranscript::validate_redirect(&bytes, context).is_err());
    }
}

#[test]
fn structural_validation_rejects_malformed_nonminimal_or_trailing_cbor() {
    for encoded in [
        "",
        "f6",
        "a0",
        "82f6f6",
        "84f6f6f6f6",
        "83f6f6",
        "83f6f6f600",
        "9803f6f6f6",
        "9ff6f6f6ff",
        "83a2616101616102f6f6", // duplicate map key
        "8361fff6f6",           // invalid UTF-8
    ] {
        assert!(
            SessionTranscript::from_cbor(&hex::decode(encoded).unwrap()).is_err(),
            "{encoded}"
        );
    }
    let mut extra = hex::decode(REDIRECT_HEX).unwrap();
    extra.push(0);
    let thumbprint = thumbprint();
    assert!(
        SessionTranscript::validate_redirect(&extra, redirect_context(Some(&thumbprint))).is_err()
    );
}

#[test]
fn structural_validation_preserves_borrowed_and_owned_storage() {
    let bytes = hex::decode("83f6f6f6").unwrap();
    let pointer = bytes.as_ptr();
    let borrowed = SessionTranscript::from_cbor(&bytes).unwrap();
    assert_eq!(borrowed.binding(), SessionBinding::StructureOnly);
    assert_eq!(borrowed.as_bytes().as_ptr(), pointer);
    assert!(matches!(
        borrowed.to_cbor_bytes().unwrap(),
        Cow::Borrowed(_)
    ));
    let owned = SessionTranscript::from_owned_cbor(bytes).unwrap();
    assert_eq!(owned.as_bytes().as_ptr(), pointer);
    assert!(matches!(owned.to_cbor_bytes().unwrap(), Cow::Borrowed(_)));
    let taken = owned.into_bytes();
    assert_eq!(taken.as_ptr(), pointer);
}

#[test]
fn device_authentication_has_outer_tag24_and_exact_independent_encoding() {
    let transcript = hex::decode("83f6f6f6").unwrap();
    let output = build_device_authentication_bytes(&transcript, "test", EMPTY_NAMESPACES).unwrap();
    assert_eq!(
        hex::encode(output),
        "d8185823847444657669636541757468656e7469636174696f6e83f6f6f66474657374d81841a0"
    );
}

#[test]
fn device_authentication_retains_original_transcript_and_namespace_order() {
    // ISO requires shortest definite framing, but does not require sorted maps.
    let transcript_bytes = hex::decode("83f6f6a2616202616101").unwrap();
    let namespaces = hex::decode("d8184aa1616ea2616202616101").unwrap();
    let transcript = SessionTranscript::from_cbor(&transcript_bytes).unwrap();
    let output = build_device_authentication(&transcript, "test", &namespaces).unwrap();
    let outer: Value = ciborium::from_reader(output.as_slice()).unwrap();
    let Value::Tag(24, inner) = outer else {
        panic!("outer Tag24 is mandatory")
    };
    let Value::Bytes(inner) = *inner else {
        panic!("Tag24 must contain bytes")
    };
    assert_eq!(&inner[22..22 + transcript_bytes.len()], transcript_bytes);
    assert!(inner.ends_with(&namespaces));
    assert_eq!(
        build_device_authentication_bytes(&transcript_bytes, "test", &namespaces).unwrap(),
        output
    );
}

#[test]
fn rejects_malformed_or_legacy_namespaces_before_constructing_authentication() {
    let transcript = hex::decode("83f6f6f6").unwrap();
    for invalid in [
        "a0",                   // legacy inner-map-only argument
        "41a0",                 // missing Tag24
        "d81941a0",             // wrong tag
        "d8184180",             // embedded value is not a map
        "d81841a000",           // trailing data
        "d81847a2616101616102", // embedded duplicate key
        "d81843a100a0",         // namespace name is not text
        "d81844a1616e01",       // namespace value is not a map
        "d81846a1616ea10001",   // element name is not text
    ] {
        assert!(
            build_device_authentication_bytes(&transcript, "test", &hex::decode(invalid).unwrap())
                .is_err(),
            "{invalid}"
        );
    }
    assert!(build_device_authentication_bytes(&transcript, "", EMPTY_NAMESPACES).is_err());
}

#[test]
fn emac_key_matches_independent_hkdf_vector_with_tag24_salt() {
    // Independent Python hashlib/hmac computation of RFC5869 extract/expand:
    // salt = SHA256(d8185838 || official redirect transcript)
    // IKM = bytes(range(32)); info = b"EMacKey"; L = 32.
    let transcript = hex::decode(REDIRECT_HEX).unwrap();
    let shared_secret: Vec<u8> = (0..32).collect();
    let key = derive_ephemeral_mac_key(&shared_secret, &transcript).unwrap();
    assert_eq!(
        hex::encode(key),
        "1eb3b26e32e357d30f32f5242d4535944a8fc0a4204252993abad2108225b84d"
    );
    // The old bare-transcript salt produces this distinct, incompatible key.
    assert_ne!(
        hex::encode(key),
        "1147baf3c498cda89e5e26865f48905f5639bed04bd34b59b43ad65c36d780d5"
    );
    assert!(derive_ephemeral_mac_key(&[], &transcript).is_err());
    assert!(derive_ephemeral_mac_key(&shared_secret, &[0xf6]).is_err());
}

#[test]
fn cbor_text_length_boundaries_and_utf8_match_an_independent_encoder() {
    for length in [1, 23, 24, 255, 256, 65_535, 65_536] {
        let value = if length == 1 {
            "x".to_owned()
        } else {
            format!("{}é", "x".repeat(length - 2))
        };
        let context = RedirectHandover {
            client_id: &value,
            nonce: "nonce",
            response_uri: "https://example.com/response",
            jwk_thumbprint: None,
        };
        let transcript = SessionTranscript::redirect(context).unwrap();
        let reference = encode(&Value::Array(vec![
            Value::Text(value.clone()),
            Value::Text(context.nonce.into()),
            Value::Null,
            Value::Text(context.response_uri.into()),
        ]));
        assert_eq!(&transcript.as_bytes()[24..], &Sha256::digest(reference)[..]);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_context_roundtrips_bind_and_match_ciborium(
        client_id in ".{1,128}",
        nonce in ".{1,128}",
        response_uri in ".{1,128}",
        thumbprint in any::<Option<[u8; 32]>>(),
    ) {
        let context = RedirectHandover {
            client_id: &client_id,
            nonce: &nonce,
            jwk_thumbprint: thumbprint.as_ref(),
            response_uri: &response_uri,
        };
        let transcript = SessionTranscript::redirect(context).unwrap();
        let borrowed = SessionTranscript::validate_redirect(transcript.as_bytes(), context).unwrap();
        prop_assert_eq!(borrowed.as_bytes().as_ptr(), transcript.as_bytes().as_ptr());
        let reference = encode(&Value::Array(vec![
            Value::Text(client_id.clone()),
            Value::Text(nonce.clone()),
            thumbprint.map_or(Value::Null, |value| Value::Bytes(value.to_vec())),
            Value::Text(response_uri.clone()),
        ]));
        let digest = Sha256::digest(reference);
        prop_assert_eq!(&transcript.as_bytes()[24..], &digest[..]);
        let changed_nonce = format!("{nonce}\0");
        let changed = RedirectHandover {
            nonce: &changed_nonce,
            ..context
        };
        prop_assert!(SessionTranscript::validate_redirect(transcript.as_bytes(), changed).is_err());
    }
}
