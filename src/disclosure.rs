//! Selective disclosure checks over original IssuerSignedItemBytes.

use crate::{
    MdocError,
    model::{IssuerSignedItem, Mso},
};
use std::collections::{HashMap, HashSet};

/// Check the original `encoded` bytes of each disclosed item against an MSO.
/// Undisclosed digest entries are intentionally allowed.
///
/// This low-level helper assumes the decoded metadata still corresponds to
/// `encoded`, and does not authenticate the MSO signature. Use the byte-oriented
/// `verifier` entry points for authenticated claims: a mutated public model's
/// `element_value` is not authenticated by this function.
pub fn verify_disclosure(
    namespaces: &HashMap<String, Vec<IssuerSignedItem>>,
    mso: &Mso,
) -> Result<(), MdocError> {
    let mut randoms = HashSet::new();
    for (namespace, items) in namespaces {
        let digests = mso
            .value_digests
            .get(namespace)
            .ok_or_else(|| MdocError::Disclosure("namespace absent from MSO".into()))?;
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
            let digest = digests
                .get(&item.digest_id)
                .ok_or_else(|| MdocError::Disclosure("digestID absent from MSO".into()))?;
            if !item.verify_digest(digest, &mso.digest_algorithm) {
                return Err(MdocError::Disclosure(
                    "IssuerSignedItemBytes digest mismatch".into(),
                ));
            }
        }
    }
    Ok(())
}
