//! Document builder for mdoc issuance (feature: `issue`).

use coset::{AsCborValue, iana};
#[cfg(not(feature = "certificate-profile"))]
use der::Decode;
use std::collections::{HashMap, HashSet};

use crate::cbor::data_item;
use crate::cbor::raw::{head_len, push_bytes, push_head, push_text};
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
    issuer_key: crate::cose::VerificationKey,
}

impl PreparedDocument {
    /// Exact COSE Sig_structure bytes to sign with the selected algorithm.
    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    /// Attach the external signature after checking it against the leaf key.
    pub fn finish(mut self, signature: Vec<u8>) -> Result<IssuerSignedDocument, MdocError> {
        if !self.issuer_key.verify(&[&self.signing_input], &signature)? {
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
        #[cfg(not(feature = "certificate-profile"))]
        let leaf = x509_cert::Certificate::from_der(&certificate_chain[0])
            .map_err(|e| MdocError::Certificate(e.to_string()))?;
        #[cfg(not(feature = "certificate-profile"))]
        let issuer_key = crate::cose::VerificationKey::from_spki(
            leaf.tbs_certificate().subject_public_key_info(),
            algorithm.cose_id(),
        )?;
        #[cfg(not(feature = "certificate-profile"))]
        let interval = crate::verifier::certificate_interval(&leaf)?;
        #[cfg(feature = "certificate-profile")]
        let leaf = crate::certificate::parse_document_signer(&certificate_chain[0])?;
        #[cfg(feature = "certificate-profile")]
        let issuer_key = crate::cose::VerificationKey::from_spki_ref(
            crate::certificate::spki(&leaf)?,
            algorithm.cose_id(),
        )?;
        #[cfg(feature = "certificate-profile")]
        let interval = crate::certificate::interval(&leaf)?;
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
            for (elem_id, elem_value) in attributes {
                let (digest_id, random) =
                    fresh_item_randomness(&mut used_digest_ids, &mut used_randoms)?;
                let mdl =
                    self.doc_type == crate::mdl::DOC_TYPE && namespace == crate::mdl::NAMESPACE;
                let encoded = encode_item(
                    digest_id,
                    &random,
                    &elem_id,
                    &elem_value,
                    mdl.then_some(validity.valid_from),
                )?;
                #[cfg(feature = "certificate-profile")]
                if mdl && matches!(elem_id.as_str(), "issuing_country" | "issuing_jurisdiction") {
                    crate::certificate::check_mdl_issuer_attribute(
                        &leaf,
                        &elem_id,
                        elem_value.as_text().expect("validated mDL text field"),
                    )?;
                }
                let item = IssuerSignedItem {
                    digest_id,
                    random,
                    element_identifier: elem_id,
                    element_value: elem_value,
                    encoded,
                };

                items.push(item);
            }

            if self.doc_type == crate::mdl::DOC_TYPE && namespace == crate::mdl::NAMESPACE {
                let value = |name| {
                    items
                        .iter()
                        .find(|item| item.element_identifier == name)
                        .and_then(|item| item.element_value.as_text())
                };
                crate::mdl::check_jurisdiction(
                    value("issuing_country"),
                    value("issuing_jurisdiction"),
                )?;
            }
            name_spaces.insert(namespace, items);
        }

        let mso_bytes = encode_mso(
            &self.doc_type,
            &self.digest_algorithm,
            &validity,
            &name_spaces,
            device_key,
            self.status,
        )?;
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
        })
    }
}

fn text_len(value: &str) -> usize {
    head_len(value.len() as u64) + value.len()
}

fn tag24_output(inner_len: usize) -> Result<Vec<u8>, MdocError> {
    let total = 2usize
        .checked_add(head_len(inner_len as u64))
        .and_then(|len| len.checked_add(inner_len))
        .filter(|len| *len <= crate::cbor::raw::Limits::default().max_bytes)
        .ok_or_else(|| MdocError::Cbor("CBOR byte limit exceeded".into()))?;
    let mut out = Vec::with_capacity(total);
    push_head(&mut out, 6, 24);
    push_head(&mut out, 2, inner_len as u64);
    Ok(out)
}

fn write_date(out: &mut Vec<u8>, formatted: &str) {
    push_head(out, 6, 0);
    push_text(out, formatted);
}

/// Encode the fixed MSO schema directly from the issued items. Only the sorted
/// indexes own metadata; namespace text, claim data and digests are not cloned.
fn encode_mso(
    doc_type: &str,
    digest_algorithm: &DigestAlgorithm,
    validity: &ValidityInfo,
    name_spaces: &HashMap<String, Vec<IssuerSignedItem>>,
    device_key: coset::CoseKey,
    status: Option<ciborium::Value>,
) -> Result<Vec<u8>, MdocError> {
    use sha2::Digest;

    let key = device_key.to_cbor_value()?;
    let key_len = data_item::encoded_len(&key)?;
    let status_len = status.as_ref().map(data_item::encoded_len).transpose()?;
    let dates = [
        validity.signed.format_rfc3339()?,
        validity.valid_from.format_rfc3339()?,
        validity.valid_until.format_rfc3339()?,
    ];
    let update = validity
        .expected_update
        .map(|time| time.format_rfc3339())
        .transpose()?;
    let digest_len = digest_algorithm.output_size();
    let digests_len = head_len(name_spaces.len() as u64)
        + name_spaces
            .iter()
            .map(|(name, items)| {
                text_len(name)
                    + head_len(items.len() as u64)
                    + items
                        .iter()
                        .map(|item| {
                            head_len(u64::from(item.digest_id))
                                + head_len(digest_len as u64)
                                + digest_len
                        })
                        .sum::<usize>()
            })
            .sum::<usize>();
    let validity_len = 1
        + ["signed", "validFrom", "validUntil"]
            .iter()
            .zip(&dates)
            .map(|(name, date)| text_len(name) + 1 + text_len(date))
            .sum::<usize>()
        + update
            .as_ref()
            .map_or(0, |date| text_len("expectedUpdate") + 1 + text_len(date));
    let inner_len = 1
        + text_len("docType")
        + text_len(doc_type)
        + text_len("version")
        + text_len("1.0")
        + text_len("valueDigests")
        + digests_len
        + text_len("validityInfo")
        + validity_len
        + text_len("deviceKeyInfo")
        + 1
        + text_len("deviceKey")
        + key_len
        + text_len("digestAlgorithm")
        + text_len(digest_algorithm.name())
        + status_len.map_or(0, |len| text_len("status") + len);
    let mut out = tag24_output(inner_len)?;
    push_head(&mut out, 5, if status.is_some() { 7 } else { 6 });
    // Fixed text keys in RFC 8949 deterministic order (encoded length, bytes).
    if let Some(status) = &status {
        push_text(&mut out, "status");
        data_item::write_canonical(status, &mut out, 1)?;
    }
    push_text(&mut out, "docType");
    push_text(&mut out, doc_type);
    push_text(&mut out, "version");
    push_text(&mut out, "1.0");
    push_text(&mut out, "validityInfo");
    push_head(&mut out, 5, if update.is_some() { 4 } else { 3 });
    for (name, date) in ["signed", "validFrom", "validUntil"].iter().zip(&dates) {
        push_text(&mut out, name);
        write_date(&mut out, date);
    }
    if let Some(date) = update {
        push_text(&mut out, "expectedUpdate");
        write_date(&mut out, &date);
    }
    push_text(&mut out, "valueDigests");
    push_head(&mut out, 5, name_spaces.len() as u64);
    let mut namespaces: Vec<_> = name_spaces.iter().collect();
    namespaces.sort_unstable_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    for (namespace, items) in namespaces {
        push_text(&mut out, namespace);
        push_head(&mut out, 5, items.len() as u64);
        let mut items: Vec<_> = items.iter().collect();
        items.sort_unstable_by_key(|item| item.digest_id);
        for item in items {
            push_head(&mut out, 0, u64::from(item.digest_id));
            match digest_algorithm {
                DigestAlgorithm::Sha256 => {
                    push_bytes(&mut out, &sha2::Sha256::digest(&item.encoded))
                }
                DigestAlgorithm::Sha384 => {
                    push_bytes(&mut out, &sha2::Sha384::digest(&item.encoded))
                }
                DigestAlgorithm::Sha512 => {
                    push_bytes(&mut out, &sha2::Sha512::digest(&item.encoded))
                }
            }
        }
    }
    push_text(&mut out, "deviceKeyInfo");
    out.push(0xa1);
    push_text(&mut out, "deviceKey");
    data_item::write_canonical(&key, &mut out, 2)?;
    push_text(&mut out, "digestAlgorithm");
    push_text(&mut out, digest_algorithm.name());
    debug_assert_eq!(out.len(), 2 + head_len(inner_len as u64) + inner_len);

    let validated = crate::cbor::raw::Item::parse(&out)?;
    if status.is_some() {
        // Status is the first field in this deterministic schema. Its borrowed
        // parser shares exactly the same rules as received credentials.
        let (_, status) = validated
            .embedded()?
            .map()?
            .next()
            .expect("MSO status field")?;
        crate::model::issuer_auth::parse_status_ref(status)?;
    }
    Ok(out)
}

fn encode_item(
    digest_id: u32,
    random: &[u8],
    identifier: &str,
    value: &ciborium::Value,
    mdl_valid_from: Option<crate::Timestamp>,
) -> Result<Vec<u8>, MdocError> {
    let value_len = data_item::encoded_len(value)?;
    let inner_len = 1
        + text_len("random")
        + head_len(random.len() as u64)
        + random.len()
        + text_len("digestID")
        + head_len(u64::from(digest_id))
        + text_len("elementValue")
        + value_len
        + text_len("elementIdentifier")
        + text_len(identifier);
    let mut out = tag24_output(inner_len)?;
    out.push(0xa4);
    push_text(&mut out, "random");
    push_bytes(&mut out, random);
    push_text(&mut out, "digestID");
    push_head(&mut out, 0, u64::from(digest_id));
    push_text(&mut out, "elementValue");
    data_item::write_canonical(value, &mut out, 1)?;
    push_text(&mut out, "elementIdentifier");
    push_text(&mut out, identifier);
    debug_assert_eq!(out.len(), 2 + head_len(inner_len as u64) + inner_len);
    let item = crate::cbor::raw::Item::parse(&out)?;
    if let Some(valid_from) = mdl_valid_from {
        for entry in item.embedded()?.map()? {
            let (name, value) = entry?;
            if name.as_text() == Some("elementValue") {
                crate::mdl::validate_element(
                    identifier,
                    crate::CborValueRef::from_item(value),
                    valid_from,
                )?;
                break;
            }
        }
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_mso_encoding_matches_independent_canonical_schema() {
        use ciborium::Value;
        let key = coset::CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_256,
            vec![1; 32],
            vec![2; 32],
        )
        .build();
        let mut namespaces = HashMap::new();
        for namespace in ["org.example.long.namespace", "a"] {
            let mut items = Vec::new();
            for id in [65_536, 23, 255] {
                let random = vec![id as u8; 32];
                let value = Value::Bytes(vec![id as u8; 256]);
                let encoded = encode_item(id, &random, "portrait", &value, None).unwrap();
                items.push(IssuerSignedItem {
                    digest_id: id,
                    random,
                    element_identifier: "portrait".into(),
                    element_value: value,
                    encoded,
                });
            }
            namespaces.insert(namespace.into(), items);
        }
        let dates = ValidityInfo {
            signed: "2026-01-01T00:00:00Z".parse().unwrap(),
            valid_from: "2026-01-02T00:00:00Z".parse().unwrap(),
            valid_until: "2027-01-01T00:00:00Z".parse().unwrap(),
            expected_update: Some("2026-06-01T00:00:00Z".parse().unwrap()),
        };
        let date =
            |time: crate::Timestamp| Value::Tag(0, Box::new(time.format_rfc3339().unwrap().into()));
        for algorithm in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            for with_optional in [false, true] {
                let mut validity = dates.clone();
                let status = with_optional
                    .then(|| Value::Map(vec![("custom".into(), Value::Bytes(vec![0x5a; 65_536]))]));
                if !with_optional {
                    validity.expected_update = None;
                }
                let actual = encode_mso(
                    "org.example.document",
                    &algorithm,
                    &validity,
                    &namespaces,
                    key.clone(),
                    status.clone(),
                )
                .unwrap();
                let digests = Value::Map(
                    namespaces
                        .iter()
                        .map(|(namespace, items)| {
                            (
                                namespace.as_str().into(),
                                Value::Map(
                                    items
                                        .iter()
                                        .map(|item| {
                                            (
                                                item.digest_id.into(),
                                                Value::Bytes(item.compute_digest(&algorithm)),
                                            )
                                        })
                                        .collect(),
                                ),
                            )
                        })
                        .collect(),
                );
                let mut interval = vec![
                    ("validUntil".into(), date(validity.valid_until)),
                    ("signed".into(), date(validity.signed)),
                    ("validFrom".into(), date(validity.valid_from)),
                ];
                if let Some(update) = validity.expected_update {
                    interval.push(("expectedUpdate".into(), date(update)));
                }
                let mut fields = vec![
                    ("version".into(), "1.0".into()),
                    ("digestAlgorithm".into(), algorithm.name().into()),
                    ("docType".into(), "org.example.document".into()),
                    ("valueDigests".into(), digests),
                    ("validityInfo".into(), Value::Map(interval)),
                    (
                        "deviceKeyInfo".into(),
                        Value::Map(vec![(
                            "deviceKey".into(),
                            key.clone().to_cbor_value().unwrap(),
                        )]),
                    ),
                ];
                if let Some(status) = status {
                    fields.push(("status".into(), status));
                }
                let inner = data_item::encode_cbor_canonical(&Value::Map(fields)).unwrap();
                let expected =
                    data_item::encode_cbor(&Value::Tag(24, Box::new(Value::Bytes(inner)))).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn borrowed_item_encoding_matches_schema_bytes_and_preserves_tag24() {
        use ciborium::Value;
        let opaque = vec![0xa2, 0x61, b'z', 0x01, 0x61, b'a', 0x02];
        let value = Value::Array(vec![
            Value::Tag(24, Box::new(Value::Bytes(opaque))),
            Value::Bytes(vec![0x5a; 65_536]),
        ]);
        let random = [0x42; 32];
        let actual = encode_item(0x7fff_ffff, &random, "portrait", &value, None).unwrap();
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
        let mut out = Vec::new();
        write_date(&mut out, &value.format_rfc3339().unwrap());
        assert_eq!(
            data_item::decode_cbor(&out).unwrap(),
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
