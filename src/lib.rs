//! A bounded mdoc protocol core with explicit application trust boundaries.
//!
//! `parse` decodes untrusted wire data. `verify_presentation` authenticates
//! issuer/holder signatures and disclosed claims, returning `PendingTrustDocument`.
//! The host must still enforce issuer X.509 trust, certificate revocation, MSO
//! status, request binding and business authorization. No final-valid shortcut
//! exists. The `issue` feature prepares signing inputs and assembles externally
//! signed credentials; private signing keys never enter the library.
//!
//! See the protocol matrix for the supported ISO/OpenID profiles and evidence
//! boundaries. This crate is not a certification claim or a complete proximity
//! mDL reader, wallet, trust store, status client or OpenID implementation.

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
pub mod verifier;

pub use error::MdocError;
pub use model::{MDoc, MDocStatus};
pub use parser::{parse, parse_hex};
pub use verifier::{PendingTrustDocument, VerificationOptions, verify_presentation};
