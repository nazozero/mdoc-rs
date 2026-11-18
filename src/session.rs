//! Session transcripts and device authentication inputs.
//!
//! OpenID4VP constructors implement the **1.0 Final** handovers in B.2.6.
//! Generic transcripts can be checked without assigning a transport profile.
//! Structural validation is not proof that a transcript belongs to the current
//! request: callers using [`SessionTranscript::from_cbor`] must establish that
//! association themselves. The profile-specific validators check the binding to
//! the supplied request context, whose provenance remains the caller's duty.
//!
//! Received transcripts and `DeviceNameSpacesBytes` are embedded verbatim. They
//! are never decoded and re-encoded to construct a signature or MAC input.

use std::borrow::Cow;

use sha2::{Digest, Sha256};

use crate::cbor::raw;
use crate::error::MdocError;

const REDIRECT_PREFIX: &[u8] = b"\x83\xf6\xf6\x82\x71OpenID4VPHandover\x58\x20";
const DC_API_PREFIX: &[u8] = b"\x83\xf6\xf6\x82\x76OpenID4VPDCAPIHandover\x58\x20";
const DEVICE_AUTHENTICATION_PREFIX: &[u8] = b"\x84\x74DeviceAuthentication";
const TAG24: &[u8] = &[0xd8, 0x18];

/// The validation performed when constructing a [`SessionTranscript`].
///
/// None of these states establishes issuer trust, holder authentication, replay
/// protection, or the authenticity of the request context supplied by a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionBinding {
    /// Only CBOR syntax and the three-element transcript array were checked.
    StructureOnly,
    /// Bound to the supplied OpenID4VP Final redirect request context.
    OpenId4VpRedirect,
    /// Bound to the supplied OpenID4VP Final Digital Credentials API context.
    OpenId4VpDcApi,
}

/// Exact, validated CBOR bytes of a session transcript.
///
/// Private fields prevent bypassing the structural check through an unchecked
/// `Raw` variant. Borrowed construction retains the original backing storage.
#[derive(Clone, Debug)]
pub struct SessionTranscript<'a> {
    bytes: Cow<'a, [u8]>,
    binding: SessionBinding,
}

/// Request context for OpenID4VP 1.0 Final B.2.6.1.
///
/// Use the full client identifier, including its prefix. For an encrypted
/// response, provide the RFC 7638 SHA-256 thumbprint of the public key actually
/// used for response encryption, as raw digest bytes. For an unencrypted
/// response, use `None`. `response_uri` is the Authorization Request's
/// `response_uri` or `redirect_uri`, as selected by the response mode.
///
/// Values must come from the authenticated Request Object for a signed request,
/// or from the Authorization Request parameters for an unsigned request. This
/// core does not validate the Request Object or choose an encryption key.
#[derive(Clone, Copy, Debug)]
pub struct RedirectHandover<'a> {
    pub client_id: &'a str,
    pub nonce: &'a str,
    pub jwk_thumbprint: Option<&'a [u8; 32]>,
    pub response_uri: &'a str,
}

/// Request context for OpenID4VP 1.0 Final B.2.6.2.
///
/// `origin` is the platform-provided origin, without an `origin:` prefix. The
/// caller authenticates its source. `dc_api.jwt` requires the raw SHA-256 JWK
/// thumbprint of the actual response encryption key; `dc_api` requires `None`.
#[derive(Clone, Copy, Debug)]
pub struct DcApiHandover<'a> {
    pub origin: &'a str,
    pub nonce: &'a str,
    pub jwk_thumbprint: Option<&'a [u8; 32]>,
}

impl<'a> SessionTranscript<'a> {
    /// Check one complete, definite-length CBOR three-element array and borrow
    /// its original bytes. No request-context or transport binding is inferred.
    pub fn from_cbor(bytes: &'a [u8]) -> Result<Self, MdocError> {
        validate_transcript_structure(bytes)?;
        Ok(Self {
            bytes: Cow::Borrowed(bytes),
            binding: SessionBinding::StructureOnly,
        })
    }

    /// Check the Final redirect handover against trusted request parameters,
    /// then borrow the exact supplied bytes without decoding or re-encoding.
    pub fn validate_redirect(
        bytes: &'a [u8],
        context: RedirectHandover<'_>,
    ) -> Result<Self, MdocError> {
        Self::bind(
            bytes,
            REDIRECT_PREFIX,
            context.digest()?,
            SessionBinding::OpenId4VpRedirect,
        )
    }

    /// Check the Final DC API handover against trusted request parameters,
    /// then borrow the exact supplied bytes without decoding or re-encoding.
    pub fn validate_dc_api(bytes: &'a [u8], context: DcApiHandover<'_>) -> Result<Self, MdocError> {
        Self::bind(
            bytes,
            DC_API_PREFIX,
            context.digest()?,
            SessionBinding::OpenId4VpDcApi,
        )
    }

    fn bind(
        bytes: &'a [u8],
        prefix: &[u8],
        digest: [u8; 32],
        binding: SessionBinding,
    ) -> Result<Self, MdocError> {
        // Matching this complete, fixed encoding checks its shape, shortest
        // framing, absence of trailing data, mode, and context in one pass.
        // A generic CBOR parse would duplicate those checks.
        if bytes.strip_prefix(prefix) != Some(digest.as_slice()) {
            return Err(MdocError::Session(
                "transcript does not match the OpenID4VP Final request context".into(),
            ));
        }
        Ok(Self {
            bytes: Cow::Borrowed(bytes),
            binding,
        })
    }

    /// Exact CBOR bytes, with no allocation or serialization.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Describes the checks performed, independently of later authentication.
    pub fn binding(&self) -> SessionBinding {
        self.binding
    }

    /// Borrow the already encoded bytes, including for owned transcripts.
    pub fn to_cbor_bytes(&self) -> Result<Cow<'_, [u8]>, MdocError> {
        Ok(Cow::Borrowed(self.as_bytes()))
    }

    /// Take owned bytes; copies only when the transcript borrows its storage.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes.into_owned()
    }

    /// Retain this validation state while giving the transcript owned storage.
    pub fn into_owned(self) -> SessionTranscript<'static> {
        SessionTranscript {
            bytes: Cow::Owned(self.bytes.into_owned()),
            binding: self.binding,
        }
    }
}

impl SessionTranscript<'static> {
    /// Check and take ownership of generic transcript bytes without copying.
    /// As with [`Self::from_cbor`], this does not establish request binding.
    pub fn from_owned_cbor(bytes: Vec<u8>) -> Result<Self, MdocError> {
        validate_transcript_structure(&bytes)?;
        Ok(Self {
            bytes: Cow::Owned(bytes),
            binding: SessionBinding::StructureOnly,
        })
    }

    /// Construct the OpenID4VP Final redirect transcript from trusted context.
    pub fn redirect(context: RedirectHandover<'_>) -> Result<Self, MdocError> {
        Ok(Self::from_digest(
            REDIRECT_PREFIX,
            context.digest()?,
            SessionBinding::OpenId4VpRedirect,
        ))
    }

    /// Construct the OpenID4VP Final DC API transcript from trusted context.
    pub fn dc_api(context: DcApiHandover<'_>) -> Result<Self, MdocError> {
        Ok(Self::from_digest(
            DC_API_PREFIX,
            context.digest()?,
            SessionBinding::OpenId4VpDcApi,
        ))
    }

    fn from_digest(prefix: &[u8], digest: [u8; 32], binding: SessionBinding) -> Self {
        let mut bytes = Vec::with_capacity(prefix.len() + digest.len());
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&digest);
        Self {
            bytes: Cow::Owned(bytes),
            binding,
        }
    }
}

impl RedirectHandover<'_> {
    fn digest(self) -> Result<[u8; 32], MdocError> {
        if self.client_id.is_empty() || self.nonce.is_empty() || self.response_uri.is_empty() {
            return Err(MdocError::Session(
                "client_id, nonce, and response URI must not be empty".into(),
            ));
        }
        let mut digest = Sha256::new();
        digest.update([0x84]);
        hash_text(&mut digest, self.client_id);
        hash_text(&mut digest, self.nonce);
        hash_thumbprint(&mut digest, self.jwk_thumbprint);
        hash_text(&mut digest, self.response_uri);
        Ok(digest.finalize().into())
    }
}

impl DcApiHandover<'_> {
    fn digest(self) -> Result<[u8; 32], MdocError> {
        if self.origin.is_empty() || self.nonce.is_empty() || self.origin.starts_with("origin:") {
            return Err(MdocError::Session(
                "DC API requires a nonempty unprefixed origin and nonce".into(),
            ));
        }
        let mut digest = Sha256::new();
        digest.update([0x83]);
        hash_text(&mut digest, self.origin);
        hash_text(&mut digest, self.nonce);
        hash_thumbprint(&mut digest, self.jwk_thumbprint);
        Ok(digest.finalize().into())
    }
}

fn validate_transcript_structure(bytes: &[u8]) -> Result<(), MdocError> {
    raw::validate(bytes)?;
    if bytes.first() != Some(&0x83) {
        return Err(MdocError::Session(
            "SessionTranscript must be a three-element CBOR array".into(),
        ));
    }
    Ok(())
}

fn hash_text(digest: &mut Sha256, value: &str) {
    let (head, len) = cbor_head(3, value.len());
    digest.update(&head[..len]);
    digest.update(value.as_bytes());
}

fn hash_thumbprint(digest: &mut Sha256, value: Option<&[u8; 32]>) {
    if let Some(value) = value {
        digest.update([0x58, 0x20]);
        digest.update(value);
    } else {
        digest.update([0xf6]);
    }
}

/// Build the complete `DeviceAuthenticationBytes` detached COSE payload.
///
/// The resulting encoding is `#6.24(bstr .cbor DeviceAuthentication)`, where
/// `DeviceAuthentication` is the ISO/IEC 18013-5 §9.1.3.4 four-element array.
/// Both the transcript and namespaces are embedded byte-for-byte.
///
/// **Breaking change:** `device_name_spaces_bytes` must contain the complete
/// received `DeviceNameSpacesBytes` Tag24 and byte string, including the inner
/// CBOR map. Earlier versions accepted only the inner map and omitted the outer
/// Tag24 from the authentication payload. Those legacy encodings are no longer
/// produced. Call [`build_device_authentication`] with an already checked
/// transcript to avoid repeating its structural validation.
pub fn build_device_authentication_bytes(
    session_transcript_bytes: &[u8],
    doc_type: &str,
    device_name_spaces_bytes: &[u8],
) -> Result<Vec<u8>, MdocError> {
    let transcript = SessionTranscript::from_cbor(session_transcript_bytes)?;
    build_device_authentication(&transcript, doc_type, device_name_spaces_bytes)
}

/// Build a detached payload using an already validated transcript.
///
/// `device_name_spaces_bytes` is a complete Tag24-encoded `DeviceNameSpaces`
/// map, not merely the inner map. Its encoding is checked and retained exactly.
pub fn build_device_authentication(
    transcript: &SessionTranscript<'_>,
    doc_type: &str,
    device_name_spaces_bytes: &[u8],
) -> Result<Vec<u8>, MdocError> {
    if doc_type.is_empty() {
        return Err(MdocError::Session("docType must not be empty".into()));
    }
    let namespaces = raw::Item::parse(device_name_spaces_bytes)?.embedded()?;
    for namespace in namespaces.map()? {
        let (name, elements) = namespace?;
        name.text()?;
        for element in elements.map()? {
            element?.0.text()?;
        }
    }
    Ok(build_device_authentication_validated(
        transcript,
        doc_type,
        device_name_spaces_bytes,
    ))
}

/// Internal fast path for a namespace map already validated by the parser.
/// The full original Tag24 encoding must be passed through unchanged.
pub(crate) fn build_device_authentication_validated(
    transcript: &SessionTranscript<'_>,
    doc_type: &str,
    device_name_spaces_bytes: &[u8],
) -> Vec<u8> {
    let (doc_type_head, doc_type_head_len) = cbor_head(3, doc_type.len());
    let inner_len = DEVICE_AUTHENTICATION_PREFIX.len()
        + transcript.as_bytes().len()
        + doc_type_head_len
        + doc_type.len()
        + device_name_spaces_bytes.len();
    let (outer_head, outer_head_len) = cbor_head(2, inner_len);
    let capacity = inner_len + TAG24.len() + outer_head_len;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(TAG24);
    bytes.extend_from_slice(&outer_head[..outer_head_len]);
    bytes.extend_from_slice(DEVICE_AUTHENTICATION_PREFIX);
    bytes.extend_from_slice(transcript.as_bytes());
    bytes.extend_from_slice(&doc_type_head[..doc_type_head_len]);
    bytes.extend_from_slice(doc_type.as_bytes());
    bytes.extend_from_slice(device_name_spaces_bytes);
    bytes
}

/// Derive the 32-byte `EMacKey` from an ECDH shared secret.
///
/// ISO/IEC 18013-5 §9.1.3.5 specifies HKDF-SHA256 with `info = "EMacKey"` and
/// `salt = SHA-256(SessionTranscriptBytes)`. `SessionTranscriptBytes` includes
/// the Tag24 and byte-string wrapper; hashing the bare transcript is incorrect.
/// The input here is the bare transcript, which this function validates before
/// hashing it with that wrapper. ECDH key agreement remains the caller's job.
pub fn derive_ephemeral_mac_key(
    shared_secret: &[u8],
    session_transcript_bytes: &[u8],
) -> Result<[u8; 32], MdocError> {
    let transcript = SessionTranscript::from_cbor(session_transcript_bytes)?;
    derive_ephemeral_mac_key_for(shared_secret, &transcript)
}

/// Derive `EMacKey` without repeating an already validated transcript's parse.
pub fn derive_ephemeral_mac_key_for(
    shared_secret: &[u8],
    transcript: &SessionTranscript<'_>,
) -> Result<[u8; 32], MdocError> {
    if shared_secret.is_empty() {
        return Err(MdocError::Session(
            "ECDH shared secret must not be empty".into(),
        ));
    }
    let (head, len) = cbor_head(2, transcript.as_bytes().len());
    let mut salt = Sha256::new();
    salt.update(TAG24);
    salt.update(&head[..len]);
    salt.update(transcript.as_bytes());
    let salt = salt.finalize();
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = [0; 32];
    hkdf.expand(b"EMacKey", &mut key)
        .map_err(|error| MdocError::Session(format!("HKDF expand: {error}")))?;
    Ok(key)
}

// Only CBOR length framing is needed here. Cryptographic operations remain in
// RustCrypto. No value tree or temporary HandoverInfo buffer is allocated.
fn cbor_head(major: u8, value: usize) -> ([u8; 9], usize) {
    let value = value as u64;
    let mut bytes = [0; 9];
    let (additional, width) = match value {
        0..=23 => (value as u8, 0),
        24..=0xff => (24, 1),
        0x100..=0xffff => (25, 2),
        0x1_0000..=0xffff_ffff => (26, 4),
        _ => (27, 8),
    };
    bytes[0] = (major << 5) | additional;
    bytes[1..1 + width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
    (bytes, width + 1)
}
