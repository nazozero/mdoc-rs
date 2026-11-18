//! IssuerSignedItem — individual attribute with digest verification.

use crate::model::types::DigestAlgorithm;

/// A single issuer-signed data element (ISO 18013-5 §9.1.2.4).
///
/// Each item contains a random salt, element identifier, and value.
/// The CBOR encoding of the item is hashed and included in the MSO's `valueDigests`.
#[derive(Clone, Debug)]
pub struct IssuerSignedItem {
    /// Digest ID — maps to `valueDigests[namespace][digestID]` in the MSO.
    pub digest_id: u32,
    /// Random salt bytes.
    pub random: Vec<u8>,
    /// Attribute name (e.g., `"family_name"`, `"birth_date"`).
    pub element_identifier: String,
    /// Attribute value (CBOR).
    pub element_value: ciborium::Value,
    /// Complete original IssuerSignedItemBytes, including Tag 24 and bstr header.
    /// This wire representation is authoritative for authentication/encoding.
    pub encoded: Vec<u8>,
}

impl IssuerSignedItem {
    /// Compute the digest of this item using the given algorithm.
    ///
    /// ISO 18013-5 §9.1.2.5 hashes the complete received
    /// `IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)` in `encoded`.
    pub fn compute_digest(&self, alg: &DigestAlgorithm) -> Vec<u8> {
        use sha2::Digest;
        match alg {
            DigestAlgorithm::Sha256 => sha2::Sha256::digest(&self.encoded).to_vec(),
            DigestAlgorithm::Sha384 => sha2::Sha384::digest(&self.encoded).to_vec(),
            DigestAlgorithm::Sha512 => sha2::Sha512::digest(&self.encoded).to_vec(),
        }
    }

    /// Compare the hash of `encoded` with a supplied digest.
    ///
    /// The comparison covers `encoded`; the MSO and mutable decoded fields
    /// require separate authentication. Use [`crate::verify_presentation`] or
    /// [`crate::verifier::verify_issued`] for authenticated decoded claims.
    pub fn verify_digest(&self, expected_digest: &[u8], alg: &DigestAlgorithm) -> bool {
        digest_matches(&self.encoded, expected_digest, alg)
    }
}

pub(crate) fn digest_matches(encoded: &[u8], expected: &[u8], alg: &DigestAlgorithm) -> bool {
    use sha2::Digest;
    match alg {
        DigestAlgorithm::Sha256 => &sha2::Sha256::digest(encoded)[..] == expected,
        DigestAlgorithm::Sha384 => &sha2::Sha384::digest(encoded)[..] == expected,
        DigestAlgorithm::Sha512 => &sha2::Sha512::digest(encoded)[..] == expected,
    }
}
