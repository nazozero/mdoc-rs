#![cfg(all(
    feature = "reader-session",
    feature = "reader-crypto",
    target_os = "linux"
))]
//! Independently generated Table 22 session vectors, with external OpenSSL CLI
//! only as the test oracle. No OpenSSL library is linked into nazo-mdoc.

use der::Encode;
use nazo_mdoc::{
    MdocError, VerificationOptions,
    reader::{ItemsRequest, encode_device_request},
    session::reader::{
        AgreementPublicKey, Handover, ReaderKeyAgreement, ReaderResponse, ReaderSession,
        SharedSecret,
    },
};
use std::{fs, process::Command};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

struct ExternalReader {
    public: Vec<u8>,
    private_der: Vec<u8>,
}

fn peer_spki(peer: &AgreementPublicKey) -> Vec<u8> {
    use const_oid::{
        ObjectIdentifier as Oid,
        db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
    };
    let ec = |oid: Oid| {
        (
            ID_EC_PUBLIC_KEY,
            Some(der::asn1::Any::encode_from(&oid).unwrap()),
        )
    };
    let (oid, parameters) = match peer.curve() {
        1 => ec(SECP_256_R_1),
        2 => ec(SECP_384_R_1),
        3 => ec(SECP_521_R_1),
        256 => ec(Oid::new_unwrap("1.3.36.3.3.2.8.1.1.7")),
        258 => ec(Oid::new_unwrap("1.3.36.3.3.2.8.1.1.11")),
        4 => (Oid::new_unwrap("1.3.101.110"), None),
        5 => (Oid::new_unwrap("1.3.101.111"), None),
        _ => unreachable!("core rejected unsupported agreement curve"),
    };
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned { oid, parameters },
        subject_public_key: der::asn1::BitString::from_bytes(peer.public_bytes()).unwrap(),
    }
    .to_der()
    .unwrap()
}

impl ReaderKeyAgreement for ExternalReader {
    fn public_key(&self) -> &[u8] {
        &self.public
    }

    fn agree(&mut self, peer: &AgreementPublicKey) -> Result<SharedSecret, MdocError> {
        let dir = tempfile::tempdir().map_err(|e| MdocError::Session(e.to_string()))?;
        let private = dir.path().join("private.der");
        let public = dir.path().join("peer.der");
        fs::write(&private, &self.private_der).map_err(|e| MdocError::Session(e.to_string()))?;
        fs::write(&public, peer_spki(peer)).map_err(|e| MdocError::Session(e.to_string()))?;
        let result = Command::new("openssl")
            .args(["pkeyutl", "-derive", "-keyform", "DER"])
            .arg("-inkey")
            .arg(private)
            .arg("-peerkey")
            .arg(public)
            .output()
            .map_err(|e| MdocError::Session(e.to_string()))?;
        if !result.status.success() {
            return Err(MdocError::Session(
                String::from_utf8_lossy(&result.stderr).into_owned(),
            ));
        }
        Ok(SharedSecret::new(result.stdout))
    }
}

#[test]
fn supported_table22_agreement_curves_match_independent_full_session_vectors() {
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
            private_der: hex::decode(fields[1]).unwrap(),
        };
        if matches!(curve, 257 | 259) {
            assert!(
                ReaderSession::new(&hex::decode(fields[3]).unwrap(), Handover::Qr, reader).is_err(),
                "curve {curve} must not be accepted without a reviewed backend",
            );
            continue;
        }
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
    assert_eq!(seen, [1, 2, 3, 4, 5, 256, 258]);
}
