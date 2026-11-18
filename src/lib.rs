//! ISO mdoc issuance, parsing and signature verification.
//!
//! `parse_borrowed` reads untrusted wire data without copying its values.
//! `verify_presentation_borrowed` authenticates issuer/holder signatures and
//! disclosed claims, returning evidence that continues to borrow the input.
//! The corresponding owned APIs materialize independent storage explicitly.
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
pub use model::{CborValueRef, DeviceResponse, DeviceResponseRef, DeviceResponseStatus};
pub use parser::{parse, parse_borrowed, parse_hex};
pub use time::Timestamp;
pub use verifier::{
    PendingIssuerTrustDocument, PendingIssuerTrustDocumentRef, PendingTrustDocument,
    PendingTrustDocumentRef, VerificationOptions, verify_issued, verify_issued_borrowed,
    verify_presentation, verify_presentation_borrowed,
};
