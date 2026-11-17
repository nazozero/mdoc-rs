//! Core types: MSO, ValidityInfo, DeviceKeyInfo, DeviceAuth, DigestAlgorithm.

use chrono::{DateTime, Datelike, Utc};
use coset::{CoseKey, CoseMac0, CoseSign1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Digest algorithm for MSO value digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    #[serde(rename = "SHA-256")]
    Sha256,
    #[serde(rename = "SHA-384")]
    Sha384,
    #[serde(rename = "SHA-512")]
    Sha512,
}

impl DigestAlgorithm {
    /// Parse from string (as used in MSO).
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "SHA-256" => Some(Self::Sha256),
            "SHA-384" => Some(Self::Sha384),
            "SHA-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Get the string name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Get the digest output size in bytes.
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Parsed Mobile Security Object (ISO 18013-5 §9.1.2).
///
/// Parsing establishes the data model, not issuer authenticity or trust. Obtain
/// authenticated claims through the protocol verifier before making decisions.
#[derive(Clone, Debug)]
pub struct Mso {
    /// MSO version (must be "1.0").
    pub version: String,
    /// Digest algorithm for value digests.
    pub digest_algorithm: DigestAlgorithm,
    /// Document type.
    pub doc_type: String,
    /// Validity information.
    pub validity_info: ValidityInfo,
    /// Value digests: namespace → (digestID → digest bytes).
    pub value_digests: HashMap<String, HashMap<u32, Vec<u8>>>,
    /// Device key information.
    pub device_key_info: DeviceKeyInfo,
    /// Status information. `None` means the signed MSO has no `status` member;
    /// an unknown mechanism is retained as `Some`, never converted to absence.
    pub status: Option<MsoStatus>,
    /// Unrecognized MSO members, retained for an explicit profile decision.
    pub additional_fields: HashMap<String, ciborium::Value>,
}

/// MSO `status` element (revocation information).
///
/// The extension uses the IETF Token Status List draft-21 status model. It is
/// not part of the original ISO/IEC 18013-5:2021 MSO schema. Every mechanism and
/// extension member is retained in [`MsoStatus::raw`] for the caller's policy.
#[derive(Clone, Debug)]
pub struct MsoStatus {
    /// IETF Token Status List reference, when present.
    pub status_list: Option<StatusListInfo>,
    /// Complete decoded `status` value, including unknown mechanisms and
    /// members. This is not a replacement for the original signed bytes, which
    /// remain in [`super::IssuerAuth::cose_sign1`].
    pub raw: ciborium::Value,
}

/// IETF Token Status List reference (`status_list` member of the MSO `status`).
#[derive(Clone, Debug)]
pub struct StatusListInfo {
    /// Index of this credential's entry within the referenced status list.
    pub idx: u64,
    /// Syntactically valid RFC 3986 URI, preserved without normalization.
    /// Fetch authorization, permitted schemes and SSRF defenses belong to the
    /// caller; a valid URI alone is not permission to contact its target.
    pub uri: String,
}

/// Validity information (ISO 18013-5 §9.1.2.4).
#[derive(Clone, Debug)]
pub struct ValidityInfo {
    /// When the MSO was signed.
    pub signed: DateTime<Utc>,
    /// When the MSO becomes valid.
    pub valid_from: DateTime<Utc>,
    /// When the MSO expires.
    pub valid_until: DateTime<Utc>,
    /// Expected next update (optional).
    pub expected_update: Option<DateTime<Utc>>,
}

impl ValidityInfo {
    /// Validate the timestamp representation and ordering required by the MSO
    /// profile. Does not decide whether the credential is valid at a given time.
    pub fn validate(&self) -> Result<(), crate::MdocError> {
        for timestamp in [
            Some(&self.signed),
            Some(&self.valid_from),
            Some(&self.valid_until),
            self.expected_update.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            // Chrono represents a whole leap second using 1_000_000_000 ns.
            if timestamp.timestamp_subsec_nanos() % 1_000_000_000 != 0
                || !(0..=9999).contains(&timestamp.year())
            {
                return Err(crate::MdocError::Validity(
                    "MSO timestamps require whole UTC seconds and four-digit years".into(),
                ));
            }
        }
        if self.signed > self.valid_from || self.valid_from >= self.valid_until {
            return Err(crate::MdocError::Validity(
                "MSO validity must satisfy signed <= validFrom < validUntil".into(),
            ));
        }
        Ok(())
    }
}

/// Device key information from MSO.
#[derive(Clone, Debug)]
pub struct DeviceKeyInfo {
    /// Device's public key (COSE_Key).
    pub device_key: CoseKey,
    /// Key authorizations (optional).
    pub key_authorizations: Option<KeyAuthorizations>,
    /// Optional integer-keyed information about the device key. Preserved for
    /// the application's profile; it conveys no extra authorization by itself.
    pub key_info: Option<ciborium::Value>,
    /// Unrecognized members, retained for an explicit profile decision.
    pub additional_fields: HashMap<String, ciborium::Value>,
}

/// Key authorizations for device key.
#[derive(Clone, Debug)]
pub struct KeyAuthorizations {
    /// Authorized namespaces.
    pub name_spaces: Option<Vec<String>>,
    /// Authorized data elements per namespace.
    pub data_elements: Option<HashMap<String, Vec<String>>>,
}

/// Device authentication (ISO 18013-5 §9.1.3).
#[derive(Clone, Debug)]
pub enum DeviceAuth {
    /// ECDSA/EdDSA signature (COSE_Sign1).
    Signature(CoseSign1),
    /// HMAC via ECDH-derived key (COSE_Mac0).
    Mac(CoseMac0),
}

/// Supported COSE signing algorithms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoseAlgorithm {
    ES256,
    ES384,
    ES512,
    EdDSA,
}

impl CoseAlgorithm {
    /// COSE algorithm identifier.
    pub fn cose_id(&self) -> i64 {
        match self {
            Self::ES256 => -7,
            Self::ES384 => -35,
            Self::ES512 => -36,
            Self::EdDSA => -8,
        }
    }

    /// Parse from COSE algorithm identifier.
    pub fn from_cose_id(id: i64) -> Option<Self> {
        match id {
            -7 => Some(Self::ES256),
            -35 => Some(Self::ES384),
            -36 => Some(Self::ES512),
            -8 => Some(Self::EdDSA),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::EdDSA => "EdDSA",
        }
    }
}
