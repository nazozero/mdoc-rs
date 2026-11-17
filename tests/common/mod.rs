#![allow(dead_code)]
use chrono::{DateTime, Duration, Utc};
use nazo_mdoc::{
    builder::DocumentBuilder,
    model::*,
    session::{RedirectHandover, SessionTranscript},
};
use signature::Signer;

pub const GENUINE_PRIV_HEX: &str =
    "77063a7b42efb2e4097dcb56de8424c492004041964398ec2d4a5370810be09a";
pub const GENUINE_CERT_HEX: &str = "3082019c30820143a003020102021420a52f4465e053acee84e850cdbc4222c8fa9829300a06082a8648ce3d04030230243115301306035504030c0c47656e75696e652049414341310b3009060355040613025345301e170d3236303533313139353535375a170d3336303532383139353535375a30243115301306035504030c0c47656e75696e652049414341310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000411d18d37c4791c5c021f8b5d0f41a91764edd5af064231e2da7333866016491acaab1cb398fb8d9a64086bb2dc0577cce716f566dcbee15ebb8c0b8bace84353a3533051301d0603551d0e041604146cff54fce3d082f2bf41e7611c183f0693b816d6301f0603551d230418301680146cff54fce3d082f2bf41e7611c183f0693b816d6300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402207c008aa58aab0acfb093e886a653dfedd3f3ce32ff8907f7d13b5bfbaa13fff702202e30e851542f33763a96f2ae0771dc8031f12e52cc8c226db6544bd7c6b82109";

pub const EVIL_PRIV_HEX: &str = "ee89b1518af54d9a2f604972d153e5af804f365d33c64908b3735d5c30ad76d4";
pub const EVIL_CERT_HEX: &str = "308201963082013da00302010202146653c832e4a02afe1b44824fceb07e9d3e683874300a06082a8648ce3d04030230213112301006035504030c094576696c20526f6f74310b3009060355040613025345301e170d3236303533313139353535375a170d3336303532383139353535375a30213112301006035504030c094576696c20526f6f74310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000408d50a026af4aff245b2f1b06602de92d7bc05f3c32ff2c1e4666c638dfc35f1ed3c5aa18625a091422d2c0fbca674d8da55fef38bbf624b4130645a5c50e24aa3533051301d0603551d0e04160414566dc531b7d322aec2a5d6763e4d54ecb956108a301f0603551d23041830168014566dc531b7d322aec2a5d6763e4d54ecb956108a300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020347003044022050eecd1cac4bdabff24b7840aa33057d9bcbd19185f9a9ade277ae648d443c2e0220265d60d5889f788d17950f985e1de6af0c7667ae4759ff3d66424f01cf74f62e";

pub const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
pub const NS: &str = "org.iso.18013.5.1";

pub fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-17T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}
pub fn validity() -> ValidityInfo {
    ValidityInfo {
        signed: now(),
        valid_from: now(),
        valid_until: now() + Duration::days(30),
        expected_update: None,
    }
}
pub fn issuer_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&hex::decode(GENUINE_PRIV_HEX).unwrap()).unwrap()
}
pub fn holder_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap()
}
pub fn device_key() -> coset::CoseKey {
    nazo_mdoc::cose::key::cose_key_from_sec1_bytes(
        1,
        &p256::PublicKey::from(holder_key().verifying_key()).to_sec1_bytes(),
    )
    .unwrap()
}
pub fn builder() -> DocumentBuilder {
    DocumentBuilder::new(DOC_TYPE)
        .add_namespace(
            NS,
            vec![
                ("family_name", "Lindqvist".into()),
                ("age_over_21", true.into()),
            ],
        )
        .device_key(device_key())
        .validity(validity())
}
pub fn issue(builder: DocumentBuilder) -> IssuerSignedDocument {
    let prepared = builder
        .prepare(
            CoseAlgorithm::ES256,
            vec![hex::decode(GENUINE_CERT_HEX).unwrap()],
        )
        .unwrap();
    let signature: p256::ecdsa::Signature = issuer_key().sign(prepared.signing_input());
    prepared.finish(signature.to_bytes().to_vec()).unwrap()
}
pub fn transcript() -> SessionTranscript<'static> {
    SessionTranscript::redirect(RedirectHandover {
        client_id: "x509_san_dns:example.com",
        nonce: "test-nonce",
        jwk_thumbprint: None,
        response_uri: "https://example.com/response",
    })
    .unwrap()
}
pub fn present(
    mut document: IssuerSignedDocument,
    transcript: &SessionTranscript<'_>,
) -> IssuerSignedDocument {
    let namespaces = vec![0xd8, 0x18, 0x41, 0xa0];
    let payload = nazo_mdoc::session::build_device_authentication(
        transcript,
        &document.doc_type,
        &namespaces,
    )
    .unwrap();
    let mut sign1 = coset::CoseSign1Builder::new()
        .protected(
            coset::HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES256)
                .build(),
        )
        .payload(payload)
        .create_signature(&[], |input| {
            let signature: p256::ecdsa::Signature = holder_key().sign(input);
            signature.to_bytes().to_vec()
        })
        .build();
    sign1.payload = None;
    document.device_signed = Some(DeviceSigned {
        device_auth: DeviceAuth::Signature(sign1),
        name_spaces: Default::default(),
        name_spaces_bytes: namespaces,
    });
    document
}
pub fn verify(bytes: &[u8]) -> Result<Vec<nazo_mdoc::PendingTrustDocument>, nazo_mdoc::MdocError> {
    nazo_mdoc::verify_presentation(
        bytes,
        &transcript(),
        &nazo_mdoc::VerificationOptions {
            now: now(),
            max_documents: 1,
        },
    )
}
