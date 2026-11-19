//! Full issuer/holder chains encoded and signed outside nazo-mdoc.

use nazo_mdoc::{
    VerificationOptions,
    session::SessionTranscript,
    time::Timestamp,
    verifier::{verify_issued_borrowed, verify_presentation_borrowed},
};

fn options() -> VerificationOptions {
    VerificationOptions {
        now: Timestamp::parse_rfc3339("2026-11-17T12:00:00Z").unwrap(),
        max_documents: 2,
    }
}

#[test]
fn independent_extended_curve_presentations_follow_the_compiled_capability() {
    let transcript = SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    for row in include_str!("vectors/reader_crypto/presentations.tsv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = row.split('\t').collect();
        let issued = hex::decode(fields[3]).unwrap();
        let response = hex::decode(fields[4]).unwrap();
        let curve: i64 = fields[1].parse().unwrap();
        let result = verify_presentation_borrowed(&response, &transcript, &options());
        if matches!(curve, 257 | 259) {
            assert!(result.is_err(), "{} unsupported curve", fields[0]);
            assert!(verify_issued_borrowed(&issued, "org.example.reader", options().now).is_err());
            continue;
        }
        if cfg!(feature = "reader-crypto") {
            let result = result.unwrap_or_else(|error| panic!("{}: {error}", fields[0]));
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].mso().doc_type, "org.example.reader");
            let owned = nazo_mdoc::verify_presentation(&response, &transcript, &options()).unwrap();
            assert_eq!(owned.len(), 1);
            let issuer_only = verify_issued_borrowed(&issued, "org.example.reader", options().now);
            assert!(issuer_only.is_ok(), "{} issuer-only", fields[0]);
        } else {
            assert!(
                result.is_err(),
                "{} requires the portable reader-crypto feature",
                fields[0]
            );
            assert!(verify_issued_borrowed(&issued, "org.example.reader", options().now).is_err());
        }
    }
}

#[cfg(feature = "reader-crypto")]
#[test]
fn extended_curve_presentations_reject_changed_transcripts_signatures_and_claims() {
    let transcript = SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    let changed = SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0x80]).unwrap();
    for row in include_str!("vectors/reader_crypto/presentations.tsv")
        .lines()
        .skip(1)
        .filter(|row| !matches!(row.split('\t').nth(1), Some("257" | "259")))
    {
        let fields: Vec<_> = row.split('\t').collect();
        let response = hex::decode(fields[4]).unwrap();
        assert!(verify_presentation_borrowed(&response, &changed, &options()).is_err());
        for marker in [
            b"reader vector".as_slice(),
            b"org.example.reader".as_slice(),
        ] {
            let mut tampered = response.clone();
            let offset = tampered
                .windows(marker.len())
                .position(|window| window == marker)
                .unwrap();
            tampered[offset] ^= 1;
            assert!(verify_presentation_borrowed(&tampered, &transcript, &options()).is_err());
        }
        let parsed = nazo_mdoc::parse_borrowed(&response).unwrap();
        let document = &parsed.documents[0];
        let nazo_mdoc::model::DeviceAuthRef::Signature(holder) =
            &document.device_signed.as_ref().unwrap().device_auth
        else {
            panic!("signature")
        };
        for signature in [
            document.issuer_signed.issuer_auth.cose_sign1.signature,
            holder.signature,
        ] {
            let mut tampered = response.clone();
            let offset = signature.as_ptr() as usize - response.as_ptr() as usize;
            tampered[offset] ^= 1;
            assert!(verify_presentation_borrowed(&tampered, &transcript, &options()).is_err());
        }
    }
}

#[cfg(feature = "reader-crypto")]
#[test]
fn a_failed_extended_document_rejects_the_entire_response() {
    use ciborium::Value;
    let rows: Vec<_> = include_str!("vectors/reader_crypto/presentations.tsv")
        .lines()
        .skip(1)
        .filter(|row| !matches!(row.split('\t').nth(1), Some("257" | "259")))
        .collect();
    let decode = |row: &str| {
        let response = hex::decode(row.split('\t').nth(4).unwrap()).unwrap();
        ciborium::from_reader::<Value, _>(response.as_slice()).unwrap()
    };
    let mut first = decode(rows[0]);
    let second = decode(
        rows.iter()
            .find(|row| row.split('\t').nth(1) == Some("7"))
            .unwrap(),
    );
    let second_document = second
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_text() == Some("documents"))
        .unwrap()
        .1
        .as_array()
        .unwrap()[0]
        .clone();
    first
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("documents"))
        .unwrap()
        .1
        .as_array_mut()
        .unwrap()
        .push(second_document);
    let mut bytes = Vec::new();
    ciborium::into_writer(&first, &mut bytes).unwrap();
    let transcript = SessionTranscript::from_cbor(&[0x83, 0xf6, 0xf6, 0xf6]).unwrap();
    assert_eq!(
        verify_presentation_borrowed(&bytes, &transcript, &options())
            .unwrap()
            .len(),
        2
    );
    let parsed = nazo_mdoc::parse_borrowed(&bytes).unwrap();
    let signature = parsed.documents[1]
        .issuer_signed
        .issuer_auth
        .cose_sign1
        .signature;
    let offset = signature.as_ptr() as usize - bytes.as_ptr() as usize;
    bytes[offset] ^= 1;
    assert!(verify_presentation_borrowed(&bytes, &transcript, &options()).is_err());
}
