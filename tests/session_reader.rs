#![cfg(feature = "reader-session")]
//! Independent Python-cryptography session vectors; private scalars are public fixtures.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use ciborium::Value;
use nazo_mdoc::{
    MdocError, Timestamp, VerificationOptions,
    reader::{DeviceRequest, ItemsRequest, encode_device_request},
    session::{
        SessionBinding,
        reader::{
            AgreementPublicKey, Handover, ReaderKeyAgreement, ReaderResponse, ReaderSession,
            SessionStatus, SharedSecret,
        },
    },
};

fn vector(name: &str) -> Vec<u8> {
    let encoded = include_str!("vectors/session/vectors.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find_map(|(key, value)| (key == name).then_some(value))
        .expect("vector");
    hex::decode(encoded).unwrap()
}

struct SoftwareReader {
    public: Vec<u8>,
    private: p256::SecretKey,
    drops: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    override_secret: Option<Vec<u8>>,
}

impl SoftwareReader {
    fn new() -> Self {
        let mut scalar = [0; 32];
        scalar[31] = 19;
        Self {
            public: vector("reader_public"),
            private: p256::SecretKey::from_slice(&scalar).unwrap(),
            drops: Arc::default(),
            calls: Arc::default(),
            override_secret: None,
        }
    }
}

impl Drop for SoftwareReader {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

impl ReaderKeyAgreement for SoftwareReader {
    fn public_key(&self) -> &[u8] {
        &self.public
    }
    fn agree(&mut self, peer: &AgreementPublicKey) -> Result<SharedSecret, MdocError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Some(secret) = &self.override_secret {
            return Ok(SharedSecret::new(secret.clone()));
        }
        assert_eq!(peer.curve(), 1);
        let public = p256::PublicKey::from_sec1_bytes(peer.public_bytes()).unwrap();
        let shared =
            p256::ecdh::diffie_hellman(self.private.to_nonzero_scalar(), public.as_affine());
        Ok(SharedSecret::new(shared.raw_secret_bytes().to_vec()))
    }
}

fn session() -> ReaderSession<SoftwareReader> {
    ReaderSession::new(&vector("engagement"), Handover::Qr, SoftwareReader::new()).unwrap()
}

fn request() -> DeviceRequest {
    let encoded = vector("items_request");
    encode_device_request(&[ItemsRequest::from_bytes(&encoded).unwrap().unsigned()]).unwrap()
}

fn options() -> VerificationOptions {
    VerificationOptions {
        now: Timestamp::parse_rfc3339("2026-11-18T12:00:00Z").unwrap(),
        max_documents: 2,
    }
}

fn encoded(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn value(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).unwrap()
}

fn key_mutation(engagement: &mut Value, mutate: impl FnOnce(&mut Vec<(Value, Value)>)) {
    let fields = engagement.as_map_mut().unwrap();
    let security = fields
        .iter_mut()
        .find(|(key, _)| key == &Value::Integer(1.into()))
        .unwrap()
        .1
        .as_array_mut()
        .unwrap();
    let Value::Tag(24, key) = &mut security[1] else {
        panic!("key envelope")
    };
    let mut decoded = value(key.as_bytes().unwrap());
    mutate(decoded.as_map_mut().unwrap());
    **key = Value::Bytes(encoded(&decoded));
}

#[test]
fn independent_full_session_mac_signature_and_directional_keys() {
    for name in [
        "response_mac",
        "response_signature",
        "response_authorized_namespace",
    ] {
        let mut session = session();
        assert_eq!(
            session.transcript().binding(),
            SessionBinding::DeviceRetrieval
        );
        assert_eq!(session.transcript().as_bytes(), vector("transcript"));
        let request = request();
        assert_eq!(request.as_bytes(), vector("request"));
        assert_eq!(
            session.encrypt_request(&request).unwrap(),
            vector("request_1")
        );
        let mut message = vector(name);
        let start = message.as_ptr() as usize;
        let end = start + message.len();
        let ReaderResponse::Authenticated { documents, status } =
            session.receive_response(&mut message, &options()).unwrap()
        else {
            panic!("authenticated response")
        };
        assert_eq!(documents.len(), 1);
        assert_eq!(status, None);
        assert_eq!(documents[0].mso().doc_type, "example.session");
        assert_eq!(
            documents[0].document().issuer_signed.name_spaces["example"][0]
                .element_value
                .as_text(),
            Some("Ada")
        );
        let pointer = documents[0].mso().doc_type.as_ptr() as usize;
        assert!(
            (start..end).contains(&pointer),
            "claims borrow the decrypted original buffer"
        );
        drop(documents);
        assert!(!session.is_closed());
        assert_eq!(
            session.encrypt_request(&request).unwrap(),
            vector("request_2")
        );
        let mut second = vector("response_second");
        assert!(matches!(
            session.receive_response(&mut second, &options()).unwrap(),
            ReaderResponse::Authenticated { .. }
        ));
    }
}

#[test]
fn terminal_data_is_authenticated_before_external_key_destruction() {
    let key = SoftwareReader::new();
    let drops = key.drops.clone();
    let calls = key.calls.clone();
    let mut session = ReaderSession::new(&vector("engagement"), Handover::Qr, key).unwrap();
    session.encrypt_request(&request()).unwrap();
    let mut message = vector("response_termination");
    let ReaderResponse::Authenticated { documents, status } =
        session.receive_response(&mut message, &options()).unwrap()
    else {
        panic!("terminal claims")
    };
    assert_eq!(documents.len(), 1);
    assert_eq!(status, Some(SessionStatus::Termination));
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "ephemeral ECDH and issuer-authenticated static ECDH"
    );
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(session.is_closed());
    assert!(session.encrypt_request(&request()).is_err());
}

#[test]
fn authentication_failures_close_and_release_without_partial_claims() {
    for name in [
        "response_wrong_direction",
        "response_wrong_key",
        "response_bare_transcript_salt",
        "response_wrong_derivation_info",
        "response_attached_mac",
        "response_mac_missing_alg",
        "response_mac_wrong_alg",
        "response_bad_digest",
        "response_expired",
        "response_wrong_mso_doc_type",
        "response_wrong_curve",
        "response_unauthorized_namespace",
        "response_bad_mac",
        "response_short_mac",
        "response_long_mac",
        "response_unprotected_alg",
        "response_changed_protected",
        "response_bad_issuer",
    ] {
        let key = SoftwareReader::new();
        let drops = key.drops.clone();
        let calls = key.calls.clone();
        let mut session = ReaderSession::new(&vector("engagement"), Handover::Qr, key).unwrap();
        session.encrypt_request(&request()).unwrap();
        let mut message = vector(name);
        assert!(
            session.receive_response(&mut message, &options()).is_err(),
            "{name}"
        );
        assert!(session.is_closed(), "{name}");
        assert_eq!(drops.load(Ordering::Relaxed), 1, "{name}");
        if matches!(name, "response_bad_issuer" | "response_wrong_curve") {
            assert_eq!(
                calls.load(Ordering::Relaxed),
                1,
                "no unauthenticated/mismatched device-key ECDH"
            );
        }
    }
}

#[test]
fn replay_order_and_wrong_session_fail_closed() {
    let mut session = session();
    let request = request();
    assert!(
        session
            .receive_response(&mut vector("response_mac"), &options())
            .is_err()
    );
    assert!(session.is_closed());

    let mut session = self::session();
    session.encrypt_request(&request).unwrap();
    assert!(
        session.encrypt_request(&request).is_err(),
        "one outstanding request"
    );
    let mut first = vector("response_mac");
    let _ = session.receive_response(&mut first, &options()).unwrap();
    session.encrypt_request(&request).unwrap();
    assert!(
        session
            .receive_response(&mut vector("response_mac"), &options())
            .is_err(),
        "counter replay"
    );
    assert!(session.is_closed());

    let mut engagement = value(&vector("engagement"));
    engagement.as_map_mut().unwrap().reverse();
    let mut changed =
        ReaderSession::new(&encoded(&engagement), Handover::Qr, SoftwareReader::new()).unwrap();
    assert_ne!(changed.transcript().as_bytes(), vector("transcript"));
    changed.encrypt_request(&request).unwrap();
    assert!(
        changed
            .receive_response(&mut vector("response_mac"), &options())
            .is_err(),
        "original engagement encoding is bound"
    );
}

#[test]
fn status_and_mixed_error_responses_never_contain_authenticated_claims() {
    for status in [
        SessionStatus::EncryptionError,
        SessionStatus::DecodingError,
        SessionStatus::Termination,
    ] {
        let mut session = session();
        session.encrypt_request(&request()).unwrap();
        let mut message = status.encode();
        assert!(
            matches!(session.receive_response(&mut message, &options()).unwrap(), ReaderResponse::Status(received) if received == status)
        );
        assert!(session.is_closed());
    }
    for name in ["response_mixed_errors", "response_protocol_error"] {
        let mut session = session();
        session.encrypt_request(&request()).unwrap();
        let mut message = vector(name);
        let ReaderResponse::Protocol { response, status } =
            session.receive_response(&mut message, &options()).unwrap()
        else {
            panic!("untrusted protocol outcome")
        };
        assert_eq!(status, None);
        assert!(response.status() != 0 || response.has_errors());
    }
    for bad in [
        "a0",
        "a16673746174757300",
        "a2646461746140667374617475730a",
        "a2646461746140667374617475730b",
        "a2646461746140646461746140",
        "a169657265616465726b657940",
        "a1646461746140",
    ] {
        let mut session = session();
        session.encrypt_request(&request()).unwrap();
        assert!(
            session
                .receive_response(&mut hex::decode(bad).unwrap(), &options())
                .is_err(),
            "{bad}"
        );
        assert!(session.is_closed());
    }
}

#[test]
fn agreement_roles_optional_parameters_and_invalid_points_are_checked_once() {
    let mut compressed = value(&vector("engagement"));
    key_mutation(&mut compressed, |key| {
        let y = key
            .iter_mut()
            .find(|(label, _)| label == &Value::Integer((-3).into()))
            .unwrap();
        y.1 = Value::Bool(y.1.as_bytes().unwrap()[31] & 1 == 1);
    });
    assert!(ReaderSession::new(&encoded(&compressed), Handover::Qr, SoftwareReader::new()).is_ok());

    let mut key = SoftwareReader::new();
    let mut public = value(&key.public);
    let fields = public.as_map_mut().unwrap();
    let y = fields
        .iter_mut()
        .find(|(label, _)| label == &Value::Integer((-3).into()))
        .unwrap();
    y.1 = Value::Bool(y.1.as_bytes().unwrap()[31] & 1 == 1);
    key.public = encoded(&public);
    assert!(
        ReaderSession::new(&vector("engagement"), Handover::Qr, key).is_err(),
        "reader requires uncompressed EC2"
    );

    let mut key = SoftwareReader::new();
    let mut public = value(&key.public);
    public.as_map_mut().unwrap().extend([
        (3.into(), (-7).into()),
        (4.into(), Value::Array(vec![2.into()])),
        ((-99).into(), "ignored extension".into()),
    ]);
    key.public = encoded(&public);
    assert!(
        ReaderSession::new(&vector("engagement"), Handover::Qr, key).is_ok(),
        "role-specific optional fields ignored"
    );

    for private in [false, true] {
        let mut engagement = value(&vector("engagement"));
        key_mutation(&mut engagement, |key| {
            if private {
                key.push(((-4).into(), Value::Bytes(vec![1; 32])));
            } else {
                key.iter_mut()
                    .find(|(label, _)| label == &Value::Integer((-2).into()))
                    .unwrap()
                    .1 = Value::Bytes(vec![0; 32]);
            }
        });
        let key = SoftwareReader::new();
        let calls = key.calls.clone();
        assert!(ReaderSession::new(&encoded(&engagement), Handover::Qr, key).is_err());
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "invalid peer rejected before backend"
        );
    }
    for secret in [vec![], vec![1; 31], vec![0; 32], vec![1; 33]] {
        let mut key = SoftwareReader::new();
        key.override_secret = Some(secret);
        assert!(ReaderSession::new(&vector("engagement"), Handover::Qr, key).is_err());
    }
}

#[test]
fn handover_roles_and_bounded_transcript_are_enforced() {
    assert!(
        ReaderSession::new(
            &vector("engagement"),
            Handover::Nfc {
                select: b"select",
                request: None
            },
            SoftwareReader::new()
        )
        .is_err(),
        "NFC omits retrieval methods"
    );
    let mut nfc = value(&vector("engagement"));
    nfc.as_map_mut()
        .unwrap()
        .retain(|(key, _)| key != &Value::Integer(2.into()));
    let bytes = encoded(&nfc);
    assert!(ReaderSession::new(&bytes, Handover::Qr, SoftwareReader::new()).is_err());
    let first = ReaderSession::new(
        &bytes,
        Handover::Nfc {
            select: b"select",
            request: None,
        },
        SoftwareReader::new(),
    )
    .unwrap();
    let second = ReaderSession::new(
        &bytes,
        Handover::Nfc {
            select: b"select",
            request: Some(b"request"),
        },
        SoftwareReader::new(),
    )
    .unwrap();
    assert_ne!(
        first.transcript().as_bytes(),
        second.transcript().as_bytes()
    );
    assert!(
        ReaderSession::new(
            &bytes,
            Handover::Nfc {
                select: b"",
                request: None
            },
            SoftwareReader::new()
        )
        .is_err()
    );
    assert!(
        ReaderSession::new(
            &bytes,
            Handover::Nfc {
                select: &vec![1; 1024 * 1024],
                request: None
            },
            SoftwareReader::new()
        )
        .is_err()
    );
}

#[test]
fn parallel_sessions_keep_counters_and_authentication_independent() {
    // Repeated public fixtures are test material; deployed providers generate fresh keys.
    std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| {
                let mut session = session();
                assert_eq!(
                    session.encrypt_request(&request()).unwrap(),
                    vector("request_1")
                );
                let mut response = vector("response_mac");
                let ReaderResponse::Authenticated { documents, .. } =
                    session.receive_response(&mut response, &options()).unwrap()
                else {
                    panic!("claims")
                };
                assert_eq!(documents.len(), 1);
                assert_eq!(
                    session.encrypt_request(&request()).unwrap(),
                    vector("request_2")
                );
                let _ = session
                    .receive_response(&mut vector("response_second"), &options())
                    .unwrap();
            });
        }
    });
}

#[test]
fn age_limit_spans_requests_and_failed_send_does_not_consume_budget() {
    fn age_request(age: &str) -> DeviceRequest {
        let items = Value::Map(vec![
            ("docType".into(), "org.iso.18013.5.1.mDL".into()),
            (
                "nameSpaces".into(),
                Value::Map(vec![(
                    "org.iso.18013.5.1".into(),
                    Value::Map(vec![(format!("age_over_{age}").into(), Value::Bool(false))]),
                )]),
            ),
        ]);
        let bytes = encoded(&Value::Tag(24, Box::new(Value::Bytes(encoded(&items)))));
        encode_device_request(&[ItemsRequest::from_bytes(&bytes).unwrap().unsigned()]).unwrap()
    }
    let mut session = session();
    let first = age_request("18");
    let second = age_request("21");
    session.encrypt_request(&first).unwrap();
    assert!(
        session.encrypt_request(&second).is_err(),
        "outstanding request must not consume budget"
    );
    let _ = session
        .receive_response(&mut vector("response_mac"), &options())
        .unwrap();
    session.encrypt_request(&second).unwrap();
    let _ = session
        .receive_response(&mut vector("response_second"), &options())
        .unwrap();
    assert!(session.encrypt_request(&age_request("30")).is_err());
    assert!(!session.is_closed());
    session.encrypt_request(&request()).unwrap();
}

#[test]
fn composed_transcript_and_encrypted_request_share_outer_resource_limits() {
    let mut engagement = value(&vector("engagement"));
    let mut nested = Value::Bool(false);
    for _ in 0..30 {
        nested = Value::Array(vec![nested]);
    }
    engagement.as_map_mut().unwrap().push(((-8).into(), nested));
    let bytes = encoded(&engagement);
    assert!(
        nazo_mdoc::cbor::raw::validate(&bytes).is_ok(),
        "constituent fits alone"
    );
    let key = SoftwareReader::new();
    let calls = key.calls.clone();
    assert!(
        ReaderSession::new(&bytes, Handover::Qr, key).is_err(),
        "extra transcript/Tag24 levels count"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let mut items = value(&vector("items_request"));
    let Value::Tag(24, inner) = &mut items else {
        panic!("items")
    };
    let mut request_value = value(inner.as_bytes().unwrap());
    request_value.as_map_mut().unwrap().push((
        "requestInfo".into(),
        Value::Map(vec![(
            "padding".into(),
            Value::Bytes(vec![0; 1024 * 1024 - 190]),
        )]),
    ));
    **inner = Value::Bytes(encoded(&request_value));
    let bytes = encoded(&items);
    let large =
        encode_device_request(&[ItemsRequest::from_bytes(&bytes).unwrap().unsigned()]).unwrap();
    let mut session = session();
    assert!(
        session.encrypt_request(&large).is_err(),
        "ciphertext tag and establishment key also count"
    );
    assert_eq!(
        session.encrypt_request(&request()).unwrap(),
        vector("request_1"),
        "rejected size consumes no counter"
    );
}
