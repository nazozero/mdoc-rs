//! Document builder for mdoc issuance (feature: `issue`).

use coset::{AsCborValue, iana};
use der::Decode;
use std::collections::{HashMap, HashSet};

use crate::cbor::data_item;
use crate::cbor::raw::{push_bytes, push_head, push_text};
use crate::error::MdocError;
use crate::model::document::{IssuerSigned, IssuerSignedDocument};
use crate::model::issuer_auth::IssuerAuth;
use crate::model::issuer_signed_item::IssuerSignedItem;
use crate::model::types::{CoseAlgorithm, DigestAlgorithm, ValidityInfo};

/// Builder for creating issuer-signed mdoc documents.
pub struct DocumentBuilder {
    doc_type: String,
    name_spaces: HashMap<String, Vec<(String, ciborium::Value)>>,
    device_key: Option<coset::CoseKey>,
    validity_info: Option<ValidityInfo>,
    digest_algorithm: DigestAlgorithm,
    status: Option<ciborium::Value>,
}

/// A prepared COSE signature operation. No private key enters this type.
pub struct PreparedDocument {
    document: IssuerSignedDocument,
    signing_input: Vec<u8>,
    issuer_key: coset::CoseKey,
    algorithm: i64,
}

impl PreparedDocument {
    /// Exact COSE Sig_structure bytes to sign with the selected algorithm.
    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    /// Attach the external signature after checking it against the leaf key.
    pub fn finish(mut self, signature: Vec<u8>) -> Result<IssuerSignedDocument, MdocError> {
        if !crate::cose::verify_with_validated_key(
            &self.signing_input,
            &signature,
            &self.issuer_key,
            self.algorithm,
        )? {
            return Err(MdocError::Signature(
                "external issuer signature does not match signing input/certificate".into(),
            ));
        }
        self.document.issuer_signed.issuer_auth.cose_sign1.signature = signature;
        Ok(self.document)
    }
}

impl DocumentBuilder {
    /// Create a new document builder for the given document type.
    pub fn new(doc_type: &str) -> Self {
        Self {
            doc_type: doc_type.to_string(),
            name_spaces: HashMap::new(),
            device_key: None,
            validity_info: None,
            digest_algorithm: DigestAlgorithm::Sha256,
            status: None,
        }
    }

    /// Add attributes to a namespace.
    pub fn add_namespace(
        mut self,
        namespace: &str,
        attributes: Vec<(&str, ciborium::Value)>,
    ) -> Self {
        self.name_spaces
            .entry(namespace.to_string())
            .or_default()
            .extend(
                attributes
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value)),
            );
        self
    }

    /// Set the device public key.
    pub fn device_key(mut self, key: coset::CoseKey) -> Self {
        self.device_key = Some(key);
        self
    }

    /// Set the validity information.
    pub fn validity(mut self, info: ValidityInfo) -> Self {
        self.validity_info = Some(info);
        self
    }

    /// Set the digest algorithm.
    pub fn digest_algorithm(mut self, alg: DigestAlgorithm) -> Self {
        self.digest_algorithm = alg;
        self
    }

    /// Set the MSO `status` element to an IETF Token Status List reference
    /// (`status_list: { idx, uri }`). Embedded into the signed MSO so verifiers
    /// can look up revocation state.
    pub fn status_list(mut self, idx: u64, uri: &str) -> Self {
        let status_list = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("idx".to_string()),
                ciborium::Value::Integer(ciborium::value::Integer::from(idx)),
            ),
            (
                ciborium::Value::Text("uri".to_string()),
                ciborium::Value::Text(uri.to_string()),
            ),
        ]);
        self.status = Some(ciborium::Value::Map(vec![(
            ciborium::Value::Text("status_list".to_string()),
            status_list,
        )]));
        self
    }

    /// Set the MSO `status` element to an arbitrary CBOR value (for status
    /// mechanisms other than the Token Status List).
    pub fn status_raw(mut self, status: ciborium::Value) -> Self {
        self.status = Some(status);
        self
    }

    /// Prepare an external signing operation without taking custody of a key.
    ///
    /// 1. Generate IssuerSignedItems with random salts for each attribute
    /// 2. Compute digests for each item
    /// 3. Build the MSO with valueDigests
    /// 4. Return the exact COSE Sig_structure for an external signer
    /// 5. Complete with [`PreparedDocument::finish`], which verifies the result
    ///
    /// Input clock timestamps may have subsecond precision. Ordering is checked
    /// before normalizing them to the whole UTC seconds required by ISO mdoc;
    /// an interval that becomes empty after normalization is rejected.
    pub fn prepare(
        self,
        algorithm: CoseAlgorithm,
        certificate_chain: Vec<Vec<u8>>,
    ) -> Result<PreparedDocument, MdocError> {
        let mut validity = self
            .validity_info
            .ok_or_else(|| MdocError::Issuance("missing validity info".to_string()))?;
        if validity.signed > validity.valid_from || validity.valid_from >= validity.valid_until {
            return Err(MdocError::Validity(
                "MSO validity must satisfy signed <= validFrom < validUntil before normalization"
                    .into(),
            ));
        }
        validity.signed = validity.signed.truncate_to_second();
        validity.valid_from = validity.valid_from.truncate_to_second();
        validity.valid_until = validity.valid_until.truncate_to_second();
        validity.expected_update = validity
            .expected_update
            .map(crate::time::Timestamp::truncate_to_second);
        validity.validate()?;

        let mut name_spaces = HashMap::with_capacity(self.name_spaces.len());
        let mut value_digests = HashMap::with_capacity(self.name_spaces.len());
        if self.doc_type.is_empty() || self.name_spaces.is_empty() {
            return Err(MdocError::Issuance(
                "docType and at least one namespace are required".into(),
            ));
        }
        let device_key = self
            .device_key
            .ok_or_else(|| MdocError::Issuance("device public key is required".into()))?;
        crate::cose::key::validate_device_public_key(&device_key)?;
        if certificate_chain.is_empty() || certificate_chain.iter().any(Vec::is_empty) {
            return Err(MdocError::Issuance("nonempty x5chain is required".into()));
        }
        let leaf = x509_cert::Certificate::from_der(&certificate_chain[0])
            .map_err(|e| MdocError::Certificate(e.to_string()))?;
        let issuer_key =
            crate::cose::key::cose_key_from_spki(&leaf.tbs_certificate.subject_public_key_info)?;
        crate::cose::validate_verification_key(&issuer_key, algorithm.cose_id())?;
        let interval = crate::verifier::certificate_interval(&leaf)?;
        if validity.signed < interval.0 || validity.signed > interval.1 {
            return Err(MdocError::Validity(
                "MSO signed time outside issuer certificate validity".into(),
            ));
        }
        let mut used_digest_ids = HashSet::new();
        let mut used_randoms = HashSet::new();

        for (namespace, attributes) in self.name_spaces {
            if namespace.is_empty() || attributes.is_empty() {
                return Err(MdocError::Issuance("empty namespace".into()));
            }
            let mut identifiers = HashSet::with_capacity(attributes.len());
            for (elem_id, _) in &attributes {
                if elem_id.is_empty() || !identifiers.insert(elem_id) {
                    return Err(MdocError::Issuance(
                        "empty or duplicate elementIdentifier".into(),
                    ));
                }
            }
            let mut items = Vec::with_capacity(attributes.len());
            let mut ns_digests = HashMap::with_capacity(attributes.len());
            for (elem_id, elem_value) in attributes {
                let (digest_id, random) =
                    fresh_item_randomness(&mut used_digest_ids, &mut used_randoms)?;
                let encoded = encode_item(digest_id, &random, &elem_id, &elem_value)?;
                let item = IssuerSignedItem {
                    digest_id,
                    random,
                    element_identifier: elem_id,
                    element_value: elem_value,
                    encoded,
                };

                let digest = item.compute_digest(&self.digest_algorithm);

                ns_digests.insert(digest_id, digest);
                items.push(item);
            }

            name_spaces.insert(namespace.clone(), items);
            value_digests.insert(namespace, ns_digests);
        }

        let mso_map = build_mso_cbor(
            &self.doc_type,
            &self.digest_algorithm,
            &validity,
            value_digests,
            device_key,
            self.status
                .map(crate::model::issuer_auth::parse_status)
                .transpose()?
                .map(|status| status.raw),
        )?;

        // The builder established the field semantics above. Check uniqueness
        // and limits once on the complete Tag 24 envelope after encoding.
        let mut mso_inner = Vec::new();
        data_item::write_canonical(&mso_map, &mut mso_inner, 0)?;
        let mso_bytes = crate::cbor::raw::wrap_tag24_bytes(&mso_inner);
        crate::cbor::raw::validate(&mso_bytes)?;
        let alg = match algorithm {
            CoseAlgorithm::ES256 => iana::Algorithm::ES256,
            CoseAlgorithm::ES384 => iana::Algorithm::ES384,
            CoseAlgorithm::ES512 => iana::Algorithm::ES512,
            CoseAlgorithm::EdDSA => iana::Algorithm::EdDSA,
        };
        let mut unprotected = coset::Header::default();
        let chain = if certificate_chain.len() == 1 {
            ciborium::Value::Bytes(
                certificate_chain
                    .into_iter()
                    .next()
                    .expect("nonempty chain"),
            )
        } else {
            ciborium::Value::Array(
                certificate_chain
                    .into_iter()
                    .map(ciborium::Value::Bytes)
                    .collect(),
            )
        };
        unprotected.rest.push((coset::Label::Int(33), chain));
        let cose_sign1 = coset::CoseSign1Builder::new()
            .protected(coset::HeaderBuilder::new().algorithm(alg).build())
            .unprotected(unprotected)
            .payload(mso_bytes)
            .build();
        let signing_input = crate::cose::sign1_structure(
            &cose_sign1.protected,
            cose_sign1.payload.as_deref().expect("prepared MSO payload"),
        )?;
        Ok(PreparedDocument {
            document: IssuerSignedDocument {
                doc_type: self.doc_type,
                issuer_signed: IssuerSigned {
                    issuer_auth: IssuerAuth::new(cose_sign1),
                    name_spaces,
                },
                device_signed: None,
            },
            signing_input,
            issuer_key,
            algorithm: algorithm.cose_id(),
        })
    }
}

/// Build the MSO as a CBOR Value.
fn build_mso_cbor(
    doc_type: &str,
    digest_algorithm: &DigestAlgorithm,
    validity: &ValidityInfo,
    value_digests: HashMap<String, HashMap<u32, Vec<u8>>>,
    device_key: coset::CoseKey,
    status: Option<ciborium::Value>,
) -> Result<ciborium::Value, MdocError> {
    let mut vd_entries = Vec::with_capacity(value_digests.len());
    for (ns, digests) in value_digests {
        let mut digest_entries = Vec::with_capacity(digests.len());
        for (id, digest) in digests {
            digest_entries.push((
                ciborium::Value::Integer(ciborium::value::Integer::from(id)),
                ciborium::Value::Bytes(digest),
            ));
        }
        vd_entries.push((
            ciborium::Value::Text(ns),
            ciborium::Value::Map(digest_entries),
        ));
    }

    let mut validity_entries = vec![
        (
            ciborium::Value::Text("signed".to_string()),
            tdate(&validity.signed)?,
        ),
        (
            ciborium::Value::Text("validFrom".to_string()),
            tdate(&validity.valid_from)?,
        ),
        (
            ciborium::Value::Text("validUntil".to_string()),
            tdate(&validity.valid_until)?,
        ),
    ];
    if let Some(update) = validity.expected_update {
        validity_entries.push((
            ciborium::Value::Text("expectedUpdate".into()),
            tdate(&update)?,
        ));
    }
    let validity_map = ciborium::Value::Map(validity_entries);

    let mut mso_entries = vec![
        (
            ciborium::Value::Text("version".to_string()),
            ciborium::Value::Text("1.0".to_string()),
        ),
        (
            ciborium::Value::Text("digestAlgorithm".to_string()),
            ciborium::Value::Text(digest_algorithm.name().to_string()),
        ),
        (
            ciborium::Value::Text("docType".to_string()),
            ciborium::Value::Text(doc_type.to_string()),
        ),
        (
            ciborium::Value::Text("valueDigests".to_string()),
            ciborium::Value::Map(vd_entries),
        ),
        (
            ciborium::Value::Text("validityInfo".to_string()),
            validity_map,
        ),
    ];

    mso_entries.push((
        ciborium::Value::Text("deviceKeyInfo".to_string()),
        ciborium::Value::Map(vec![(
            ciborium::Value::Text("deviceKey".to_string()),
            device_key.to_cbor_value()?,
        )]),
    ));

    if let Some(status) = status {
        mso_entries.push((ciborium::Value::Text("status".to_string()), status));
    }

    Ok(ciborium::Value::Map(mso_entries))
}

fn encode_item(
    digest_id: u32,
    random: &[u8],
    identifier: &str,
    value: &ciborium::Value,
) -> Result<Vec<u8>, MdocError> {
    let mut inner = Vec::with_capacity(random.len() + identifier.len() + 64);
    inner.push(0xa4);
    // RFC 8949 core deterministic order for the four fixed schema keys.
    push_text(&mut inner, "random");
    push_bytes(&mut inner, random);
    push_text(&mut inner, "digestID");
    push_head(&mut inner, 0, u64::from(digest_id));
    push_text(&mut inner, "elementValue");
    data_item::write_canonical(value, &mut inner, 1)?;
    push_text(&mut inner, "elementIdentifier");
    push_text(&mut inner, identifier);
    crate::cbor::raw::validate(&inner)?;
    Ok(crate::cbor::raw::wrap_tag24_bytes(&inner))
}

fn fresh_item_randomness(
    ids: &mut HashSet<u32>,
    salts: &mut HashSet<[u8; 32]>,
) -> Result<(u32, Vec<u8>), MdocError> {
    for _ in 0..32 {
        let mut entropy = [0u8; 36];
        getrandom::fill(&mut entropy)
            .map_err(|e| MdocError::Issuance(format!("OS entropy: {e}")))?;
        let id = u32::from_be_bytes(entropy[..4].try_into().expect("four bytes")) & 0x7fff_ffff;
        let salt: [u8; 32] = entropy[4..].try_into().expect("32-byte salt");
        if !ids.contains(&id) && !salts.contains(&salt) {
            ids.insert(id);
            salts.insert(salt);
            return Ok((id, salt.to_vec()));
        }
    }
    Err(MdocError::Issuance(
        "entropy collision limit exceeded".into(),
    ))
}

fn tdate(value: &crate::time::Timestamp) -> Result<ciborium::Value, MdocError> {
    Ok(ciborium::Value::Tag(
        0,
        Box::new(ciborium::Value::Text(value.format_rfc3339()?)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_item_encoding_matches_schema_bytes_and_preserves_tag24() {
        use ciborium::Value;
        let opaque = vec![0xa2, 0x61, b'z', 0x01, 0x61, b'a', 0x02];
        let value = Value::Array(vec![
            Value::Tag(24, Box::new(Value::Bytes(opaque))),
            Value::Bytes(vec![0x5a; 65_536]),
        ]);
        let random = [0x42; 32];
        let actual = encode_item(0x7fff_ffff, &random, "portrait", &value).unwrap();
        // The reference uses a separately assembled, schema-ordered Value map.
        let reference = Value::Map(vec![
            ("random".into(), Value::Bytes(random.to_vec())),
            ("digestID".into(), Value::Integer(0x7fff_ffffu32.into())),
            ("elementValue".into(), value),
            ("elementIdentifier".into(), "portrait".into()),
        ]);
        let inner = data_item::encode_cbor(&reference).unwrap();
        let expected = data_item::encode_cbor(&data_item::wrap_tag24(&inner)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn tdate_uses_second_precision_and_utc_z() {
        let value = crate::time::Timestamp::parse_rfc3339("2026-09-01T00:00:00.123+00:00")
            .unwrap()
            .truncate_to_second();
        assert_eq!(
            tdate(&value).unwrap(),
            ciborium::Value::Tag(
                0,
                Box::new(ciborium::Value::Text("2026-09-01T00:00:00Z".into()))
            )
        );
    }

    #[test]
    fn random_digest_ids_are_unique_and_31_bit() {
        let mut ids = HashSet::new();
        let mut randoms = HashSet::new();
        for _ in 0..1000 {
            let (id, salt) = fresh_item_randomness(&mut ids, &mut randoms).unwrap();
            assert!(id < 1 << 31);
            assert_eq!(salt.len(), 32);
        }
        assert_eq!(ids.len(), 1000);
        assert_eq!(randoms.len(), 1000);
    }
}
