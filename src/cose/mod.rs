//! COSE key and signature utilities for mdoc.

pub mod key;
mod verify;

pub use key::{cose_alg_to_name, CoseKeyExt};
pub use verify::verify_cose_signature;
