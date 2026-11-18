//! The standalone disclosure API checks caller-mutable item metadata.

use nazo_mdoc::{MdocError, disclosure::verify_disclosure, model::IssuerSignedItem, parse_hex};

const ANNEX_D: &str = include_str!("vectors/iso_18013_5_annex_d_mdl.hex");
const NAMESPACE: &str = "org.iso.18013.5.1";

fn rejects_metadata_change(change: impl FnOnce(&mut [IssuerSignedItem]), expected_error: &str) {
    let mut document = parse_hex(ANNEX_D).unwrap().documents.remove(0);
    let mso = document.issuer_signed.issuer_auth.mso().unwrap();
    verify_disclosure(&document.issuer_signed.name_spaces, &mso).unwrap();

    let items = document
        .issuer_signed
        .name_spaces
        .get_mut(NAMESPACE)
        .unwrap();
    assert!(items.len() >= 2);
    let original_bytes: Vec<_> = items.iter().map(|item| item.encoded.clone()).collect();
    change(items);
    for (item, original) in items.iter().zip(original_bytes) {
        assert_eq!(item.encoded, original);
    }

    let result = verify_disclosure(&document.issuer_signed.name_spaces, &mso);
    assert!(
        matches!(&result, Err(MdocError::Disclosure(message)) if message == expected_error),
        "expected {expected_error}, received {result:?}"
    );
}

#[test]
fn standalone_disclosure_rejects_duplicate_decoded_digest_ids() {
    rejects_metadata_change(
        |items| items[1].digest_id = items[0].digest_id,
        "duplicate digestID or elementIdentifier",
    );
}

#[test]
fn standalone_disclosure_rejects_duplicate_decoded_identifiers() {
    rejects_metadata_change(
        |items| items[1].element_identifier = items[0].element_identifier.clone(),
        "duplicate digestID or elementIdentifier",
    );
}

#[test]
fn standalone_disclosure_rejects_reused_decoded_salts() {
    rejects_metadata_change(
        |items| items[1].random = items[0].random.clone(),
        "short or reused random salt",
    );
}

#[test]
fn standalone_disclosure_rejects_short_decoded_salts() {
    for length in [0, 1, 15] {
        rejects_metadata_change(
            |items| items[0].random.truncate(length),
            "short or reused random salt",
        );
    }
}
