//! Document types: IssuerSignedDocument, DeviceSignedDocument.

use std::collections::HashMap;

use super::issuer_auth::IssuerAuth;
use super::issuer_signed_item::IssuerSignedItem;
use super::types::DeviceAuth;

/// Issuer-signed document (ISO 18013-5 §8.3.2.1.2.2).
#[derive(Clone, Debug)]
pub struct IssuerSignedDocument {
    /// Document type (e.g., `"org.iso.18013.5.1.mDL"`, `"eu.europa.ec.eudiw.pid.1"`).
    pub doc_type: String,
    /// Issuer-signed data.
    pub issuer_signed: IssuerSigned,
    /// Device-signed data (present in device responses, absent in raw issued docs).
    pub device_signed: Option<DeviceSigned>,
}

/// Issuer-signed data containing the MSO and attribute namespaces.
#[derive(Clone, Debug)]
pub struct IssuerSigned {
    /// Issuer authentication (COSE_Sign1 containing the MSO).
    pub issuer_auth: IssuerAuth,
    /// Attribute namespaces: namespace → list of signed items.
    pub name_spaces: HashMap<String, Vec<IssuerSignedItem>>,
}

/// Device-signed data (ISO 18013-5 §8.3.2.1.2.2).
#[derive(Clone, Debug)]
pub struct DeviceSigned {
    /// Device authentication (COSE_Sign1 or COSE_Mac0).
    pub device_auth: DeviceAuth,
    /// Device-provided attributes: namespace → (element → value).
    pub name_spaces: HashMap<String, HashMap<String, ciborium::Value>>,
    /// The exact, complete `DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)`
    /// field, including its Tag 24 and byte-string header.
    ///
    /// DeviceAuthentication embeds these bytes verbatim when constructing
    /// the signature or MAC input (ISO 18013-5 §9.1.3.1).
    pub name_spaces_bytes: Vec<u8>,
}

/// Type alias for DeviceSignedDocument (an IssuerSignedDocument with device_signed present).
pub type DeviceSignedDocument = IssuerSignedDocument;
