//! Selective disclosure checks over original IssuerSignedItemBytes.

use crate::{
    MdocError,
    model::{IssuerSignedItem, Mso},
};
use std::collections::{HashMap, HashSet};

/// Check the original `encoded` bytes of each disclosed item against an MSO.
/// Undisclosed digest entries are intentionally allowed.
///
/// The caller authenticates the MSO and keeps decoded metadata consistent with
/// `encoded`. The byte-oriented `verifier` entry points establish both contracts
/// and return authenticated claims.
pub fn verify_disclosure(
    namespaces: &HashMap<String, Vec<IssuerSignedItem>>,
    mso: &Mso,
) -> Result<(), MdocError> {
    let mut randoms = HashSet::new();
    for (namespace, items) in namespaces {
        let digests = namespace_digests(namespace, mso)?;
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for item in items {
            if !ids.insert(item.digest_id) || !names.insert(item.element_identifier.as_str()) {
                return Err(MdocError::Disclosure(
                    "duplicate digestID or elementIdentifier".into(),
                ));
            }
            if item.random.len() < 16 || !randoms.insert(item.random.as_slice()) {
                return Err(MdocError::Disclosure("short or reused random salt".into()));
            }
            verify_item_digest(item, digests, mso)?;
        }
    }
    Ok(())
}

/// Used only after parsing wire bytes: parser::parse_issuer_signed checks IDs,
/// identifiers and salt uniqueness. No caller-mutable model enters this path.
pub(crate) fn verify_parsed_disclosure(
    namespaces: &HashMap<String, Vec<IssuerSignedItem>>,
    mso: &Mso,
) -> Result<(), MdocError> {
    for (namespace, items) in namespaces {
        let digests = namespace_digests(namespace, mso)?;
        for item in items {
            verify_item_digest(item, digests, mso)?;
        }
    }
    Ok(())
}

fn namespace_digests<'a>(
    namespace: &str,
    mso: &'a Mso,
) -> Result<&'a HashMap<u32, Vec<u8>>, MdocError> {
    mso.value_digests
        .get(namespace)
        .ok_or_else(|| MdocError::Disclosure("namespace absent from MSO".into()))
}

fn verify_item_digest(
    item: &IssuerSignedItem,
    digests: &HashMap<u32, Vec<u8>>,
    mso: &Mso,
) -> Result<(), MdocError> {
    let digest = digests
        .get(&item.digest_id)
        .ok_or_else(|| MdocError::Disclosure("digestID absent from MSO".into()))?;
    if !item.verify_digest(digest, &mso.digest_algorithm) {
        return Err(MdocError::Disclosure(
            "IssuerSignedItemBytes digest mismatch".into(),
        ));
    }
    Ok(())
}
