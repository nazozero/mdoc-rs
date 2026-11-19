use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn vector(name: &str) -> Vec<u8> {
    let value = include_str!("../../../tests/vectors/session/vectors.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap();
    hex::decode(value).unwrap()
}

struct FixtureKey {
    public: Vec<u8>,
    destroyed: Arc<AtomicUsize>,
}
impl Drop for FixtureKey {
    fn drop(&mut self) {
        self.destroyed.fetch_add(1, Ordering::Relaxed);
    }
}
impl ReaderKeyAgreement for FixtureKey {
    fn public_key(&self) -> &[u8] {
        &self.public
    }
    fn agree(&mut self, _: &AgreementPublicKey) -> Result<SharedSecret, MdocError> {
        // Fixed independently computed ZAB; this test isolates exhaustion.
        Ok(SharedSecret::new(vector("zab")))
    }
}

#[test]
fn directional_counter_exhaustion_terminates_without_wrap_or_reuse() {
    let encoded = vector("items_request");
    let request =
        crate::reader::encode_device_request(&[crate::reader::ItemsRequest::from_bytes(&encoded)
            .unwrap()
            .unsigned()])
        .unwrap();
    for send in [false, true] {
        let destroyed = Arc::new(AtomicUsize::new(0));
        let mut session = ReaderSession::new(
            &vector("engagement"),
            Handover::Qr,
            FixtureKey {
                public: vector("reader_public"),
                destroyed: destroyed.clone(),
            },
        )
        .unwrap();
        if send {
            session.ciphers.as_mut().unwrap().sent = u32::MAX;
            assert!(session.encrypt_request(&request).is_err());
        } else {
            session.encrypt_request(&request).unwrap();
            session.ciphers.as_mut().unwrap().received = u32::MAX;
            let options = VerificationOptions {
                now: "2026-11-18T12:00:00Z".parse().unwrap(),
                max_documents: 1,
            };
            assert!(
                session
                    .receive_response(&mut vector("response_mac"), &options)
                    .is_err()
            );
        }
        assert!(session.is_closed());
        assert!(session.ciphers.is_none());
        assert_eq!(destroyed.load(Ordering::Relaxed), 1);
        assert!(session.encrypt_request(&request).is_err());
    }
}
