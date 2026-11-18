//! DeviceResponse container (ISO 18013-5 §8.3.2.1.2.2).

use super::document::IssuerSignedDocument;

/// Top-level mdoc container.
#[derive(Clone, Debug)]
pub struct DeviceResponse {
    /// Received DeviceResponse version. Verification accepts known major 1
    /// with any numeric minor version; document issuance emits "1.0".
    pub version: String,
    /// Status code.
    pub status: DeviceResponseStatus,
    /// Issuer-signed documents.
    pub documents: Vec<IssuerSignedDocument>,
}

/// DeviceResponse status codes (ISO 18013-5 Table 8).
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceResponseStatus {
    /// No error.
    Ok = 0,
    /// General error.
    GeneralError = 10,
    /// CBOR decoding error.
    CborDecodingError = 11,
    /// CBOR validation error.
    CborValidationError = 12,
}

impl DeviceResponseStatus {
    /// Parse a defined status code without substituting a known value for an unknown code.
    /// The caller decides whether a known error response is useful in its API.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Ok),
            10 => Some(Self::GeneralError),
            11 => Some(Self::CborDecodingError),
            12 => Some(Self::CborValidationError),
            _ => None,
        }
    }
}
