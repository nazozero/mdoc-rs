#![cfg(all(
    feature = "reader-session",
    feature = "reader-crypto",
    not(target_family = "wasm")
))]
//! Every Table 22 ECDH curve against a complete independently encoded session.
use nazo_mdoc::{
    MdocError, VerificationOptions,
    reader::{ItemsRequest, encode_device_request},
    session::reader::{
        AgreementPublicKey, Handover, ReaderKeyAgreement, ReaderResponse, ReaderSession,
        SharedSecret,
    },
};
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{Id, PKey, Private},
};

struct ExternalReader {
    public: Vec<u8>,
    key: PKey<Private>,
}
impl ReaderKeyAgreement for ExternalReader {
    fn public_key(&self) -> &[u8] {
        &self.public
    }
    fn agree(&mut self, peer: &AgreementPublicKey) -> Result<SharedSecret, MdocError> {
        let error = |e: openssl::error::ErrorStack| MdocError::Session(e.to_string());
        let key = match peer.curve() {
            4 => PKey::public_key_from_raw_bytes(peer.public_bytes(), Id::X25519).map_err(error)?,
            5 => PKey::public_key_from_raw_bytes(peer.public_bytes(), Id::X448).map_err(error)?,
            curve => {
                let nid = match curve {
                    1 => Nid::X9_62_PRIME256V1,
                    2 => Nid::SECP384R1,
                    3 => Nid::SECP521R1,
                    256 => Nid::BRAINPOOL_P256R1,
                    257 => Nid::BRAINPOOL_P320R1,
                    258 => Nid::BRAINPOOL_P384R1,
                    259 => Nid::BRAINPOOL_P512R1,
                    _ => panic!("validated curve"),
                };
                let group = EcGroup::from_curve_name(nid).map_err(error)?;
                let mut context = BigNumContext::new().map_err(error)?;
                let point = EcPoint::from_bytes(&group, peer.public_bytes(), &mut context)
                    .map_err(error)?;
                PKey::from_ec_key(EcKey::from_public_key(&group, &point).map_err(error)?)
                    .map_err(error)?
            }
        };
        let mut derive = Deriver::new(&self.key).map_err(error)?;
        derive.set_peer(&key).map_err(error)?;
        Ok(SharedSecret::new(derive.derive_to_vec().map_err(error)?))
    }
}

#[test]
fn all_table22_agreement_curves_match_independent_full_session_vectors() {
    let items = include_str!("vectors/session/vectors.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find_map(|(key, value)| (key == "items_request").then_some(value))
        .unwrap();
    let items = hex::decode(items).unwrap();
    let request =
        encode_device_request(&[ItemsRequest::from_bytes(&items).unwrap().unsigned()]).unwrap();
    let options = VerificationOptions {
        now: "2026-11-18T12:00:00Z".parse().unwrap(),
        max_documents: 1,
    };
    let mut seen = Vec::new();
    for row in include_str!("vectors/session/agreement.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = row.split('\t').collect();
        let curve: i64 = fields[0].parse().unwrap();
        let reader = ExternalReader {
            public: hex::decode(fields[2]).unwrap(),
            key: PKey::private_key_from_der(&hex::decode(fields[1]).unwrap()).unwrap(),
        };
        let mut session =
            ReaderSession::new(&hex::decode(fields[3]).unwrap(), Handover::Qr, reader).unwrap();
        assert_eq!(
            session.transcript().as_bytes(),
            hex::decode(fields[4]).unwrap(),
            "curve {curve}"
        );
        assert_eq!(
            session.encrypt_request(&request).unwrap(),
            hex::decode(fields[5]).unwrap(),
            "curve {curve}"
        );
        let mut message = hex::decode(fields[6]).unwrap();
        let ReaderResponse::Authenticated { documents, .. } =
            session.receive_response(&mut message, &options).unwrap()
        else {
            panic!("curve {curve} authentication")
        };
        assert_eq!(documents.len(), 1);
        assert_eq!(documents[0].mso().doc_type, "example.session");
        seen.push(curve);
    }
    assert_eq!(seen, [1, 2, 3, 4, 5, 256, 257, 258, 259]);
}
