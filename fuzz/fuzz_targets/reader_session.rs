#![no_main]
use std::sync::LazyLock;

use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInOut};
use libfuzzer_sys::fuzz_target;
use nazo_mdoc::{
    MdocError, VerificationOptions,
    reader::{DeviceRequest, ItemsRequest, encode_device_request},
    session::reader::{
        AgreementPublicKey, Handover, ReaderKeyAgreement, ReaderSession, SharedSecret,
    },
};

fn vector(name: &str) -> Vec<u8> {
    let value = include_str!("../../tests/vectors/session/vectors.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap();
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

struct Fixture {
    engagement: Vec<u8>,
    public: Vec<u8>,
    request: DeviceRequest,
    device: Aes256Gcm,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let items = vector("items_request");
    Fixture {
        engagement: vector("engagement"),
        public: vector("reader_public"),
        request: encode_device_request(&[ItemsRequest::from_bytes(&items).unwrap().unsigned()])
            .unwrap(),
        device: Aes256Gcm::new_from_slice(&vector("sk_device")).unwrap(),
    }
});

struct Provider<'a> {
    public: &'a [u8],
    key: p256::SecretKey,
}

impl<'a> Provider<'a> {
    fn new(public: &'a [u8]) -> Self {
        let mut scalar = [0; 32];
        scalar[31] = 19;
        Self {
            public,
            key: p256::SecretKey::from_slice(&scalar).unwrap(),
        }
    }
}

impl ReaderKeyAgreement for Provider<'_> {
    fn public_key(&self) -> &[u8] {
        self.public
    }
    fn agree(&mut self, peer: &AgreementPublicKey) -> Result<SharedSecret, MdocError> {
        if peer.curve() != 1 {
            return Err(MdocError::Session("fuzz provider supports P-256".into()));
        }
        let public = p256::PublicKey::from_sec1_bytes(peer.public_bytes())
            .map_err(|_| MdocError::Session("invalid fuzz peer".into()))?;
        Ok(SharedSecret::new(
            p256::ecdh::diffie_hellman(self.key.to_nonzero_scalar(), public.as_affine())
                .raw_secret_bytes()
                .to_vec(),
        ))
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&mode, input)) = input.split_first() else {
        return;
    };
    if input.len() > 65_536 {
        return;
    }
    let fixture = &*FIXTURE;
    match mode % 4 {
        0 => {
            let _ = ReaderSession::new(input, Handover::Qr, Provider::new(&fixture.public));
        }
        3 => {
            let _ = ReaderSession::new(&fixture.engagement, Handover::Qr, Provider::new(input));
        }
        mode => {
            let mut session = ReaderSession::new(
                &fixture.engagement,
                Handover::Qr,
                Provider::new(&fixture.public),
            )
            .unwrap();
            session.encrypt_request(&fixture.request).unwrap();
            let mut message = if mode == 1 {
                input.to_vec()
            } else {
                // Authenticated transport containing arbitrary plaintext reaches
                // response/COSE/MSO parsing without GCM rejecting every mutation.
                let mut ciphertext = input.to_vec();
                let mut nonce = [0; 12];
                nonce[7] = 1;
                nonce[11] = 1;
                fixture
                    .device
                    .encrypt_in_place(&nonce.into(), &[], &mut ciphertext)
                    .unwrap();
                let mut message = b"\xa1\x64data".to_vec();
                // Shortest length framing required by the CBOR boundary.
                let len = ciphertext.len();
                if len < 24 {
                    message.push(0x40 | len as u8);
                } else if len <= 255 {
                    message.extend_from_slice(&[0x58, len as u8]);
                } else if len <= 65_535 {
                    message.push(0x59);
                    message.extend_from_slice(&(len as u16).to_be_bytes());
                } else {
                    message.push(0x5a);
                    message.extend_from_slice(&(len as u32).to_be_bytes());
                }
                message.extend_from_slice(&ciphertext);
                message
            };
            let options = VerificationOptions {
                now: "2026-11-18T12:00:00Z".parse().unwrap(),
                max_documents: 4,
            };
            let _ = session.receive_response(&mut message, &options);
        }
    }
});
