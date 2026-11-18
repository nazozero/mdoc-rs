//! ISO mdoc issuance, parsing and signature verification.
//!
//! `parse` decodes untrusted wire data. `verify_presentation` authenticates
//! issuer/holder signatures and disclosed claims, returning `PendingTrustDocument`.
//! The application completes issuer X.509 trust, certificate revocation, MSO
//! status, request freshness and authorization. The `issue` feature prepares
//! immutable signing inputs and verifies externally returned signatures.
//!
//! The protocol matrix documents supported algorithms, wire formats and tests.

#[cfg(feature = "issue")]
pub mod builder;
pub mod cbor;
pub mod cose;
pub mod device_auth;
#[cfg(feature = "debug")]
pub mod diagnostic;
pub mod disclosure;
#[cfg(feature = "issue")]
pub mod encoder;
pub mod error;
pub mod model;
pub mod parser;
#[cfg(feature = "issue")]
pub mod response_builder;
pub mod session;
pub mod time;
pub mod verifier;

pub use error::MdocError;
pub use model::{DeviceResponse, DeviceResponseStatus};
pub use parser::{parse, parse_hex};
pub use time::Timestamp;
pub use verifier::{PendingTrustDocument, VerificationOptions, verify_presentation};
