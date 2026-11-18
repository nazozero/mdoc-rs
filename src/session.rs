//! Session transcripts and device authentication inputs.
//!
//! OpenID4VP constructors implement the 1.0 Final handovers in B.2.6.
//! Profile-specific validators bind bytes to the supplied request context.
//! [`SessionTranscript::from_cbor`] checks structure; its caller establishes
//! request binding. Applications authenticate their request context.
//!
//! Signature and MAC inputs embed received transcripts and
//! `DeviceNameSpacesBytes` verbatim.

use std::borrow::Cow;

use sha2::{Digest, Sha256};

use crate::cbor::raw::{self, cbor_head};
use crate::error::MdocError;

const REDIRECT_PREFIX: &[u8] = b"\x83\xf6\xf6\x82\x71OpenID4VPHandover\x58\x20";
const DC_API_PREFIX: &[u8] = b"\x83\xf6\xf6\x82\x76OpenID4VPDCAPIHandover\x58\x20";
const DEVICE_AUTHENTICATION_PREFIX: &[u8] = b"\x84\x74DeviceAuthentication";
const TAG24: &[u8] = &[0xd8, 0x18];

/// The validation performed when constructing a [`SessionTranscript`].
///
/// The verifier establishes holder authentication. The application establishes
/// request authenticity, freshness and issuer trust.
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
/// Constructors validate structure. Borrowed construction retains the input storage.
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
/// or from the Authorization Request parameters for an unsigned request.
/// The application validates the Request Object and selects the encryption key.
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
    /// its original bytes. The caller establishes request and transport binding.
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
    /// The caller establishes request binding, as with [`Self::from_cbor`].
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
    let (head, len) = cbor_head(3, value.len() as u64);
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
/// `device_name_spaces_bytes` must contain the complete received
/// `DeviceNameSpacesBytes` Tag 24, byte string and inner CBOR map.
/// [`build_device_authentication`] accepts an already validated transcript.
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
/// `device_name_spaces_bytes` is a complete Tag 24 envelope containing
/// `DeviceNameSpaces`. Its encoding is checked and retained exactly.
/// `DeviceNameSpaces` may be empty; every present namespace must contain at
/// least one item, and namespace names and element identifiers must be nonempty.
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
        if name.text()?.is_empty() {
            return Err(MdocError::Session("empty device namespace".into()));
        }
        let elements = elements.map()?;
        if elements.len() == 0 {
            return Err(MdocError::Session("empty DeviceSignedItems map".into()));
        }
        for element in elements {
            if element?.0.text()?.is_empty() {
                return Err(MdocError::Session("empty device element identifier".into()));
            }
        }
    }
    Ok(
        DeviceAuthentication::new(transcript, doc_type, device_name_spaces_bytes)
            .parts()
            .concat(),
    )
}

/// Framing of validated DeviceAuthenticationBytes. Payload data remains borrowed.
pub(crate) struct DeviceAuthentication<'a> {
    transcript: &'a [u8],
    doc_type: &'a str,
    namespaces: &'a [u8],
    doc_type_head: ([u8; 9], usize),
    outer_head: ([u8; 9], usize),
    encoded_len: usize,
}

impl<'a> DeviceAuthentication<'a> {
    pub(crate) fn new(
        transcript: &'a SessionTranscript<'_>,
        doc_type: &'a str,
        namespaces: &'a [u8],
    ) -> Self {
        let doc_type_head = cbor_head(3, doc_type.len() as u64);
        let inner_len = DEVICE_AUTHENTICATION_PREFIX.len()
            + transcript.as_bytes().len()
            + doc_type_head.1
            + doc_type.len()
            + namespaces.len();
        let outer_head = cbor_head(2, inner_len as u64);
        Self {
            transcript: transcript.as_bytes(),
            doc_type,
            namespaces,
            doc_type_head,
            outer_head,
            encoded_len: inner_len + TAG24.len() + outer_head.1,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.encoded_len
    }

    pub(crate) fn parts(&self) -> [&[u8]; 7] {
        [
            TAG24,
            &self.outer_head.0[..self.outer_head.1],
            DEVICE_AUTHENTICATION_PREFIX,
            self.transcript,
            &self.doc_type_head.0[..self.doc_type_head.1],
            self.doc_type.as_bytes(),
            self.namespaces,
        ]
    }

    /// Append this seven-part payload to the five COSE framing parts.
    pub(crate) fn authentication_parts<'b>(&'b self, prefix: [&'b [u8]; 5]) -> [&'b [u8]; 12] {
        let [context, protected_head, protected, aad, payload_head] = prefix;
        let [
            tag,
            inner_head,
            device,
            transcript,
            type_head,
            doc_type,
            namespaces,
        ] = self.parts();
        [
            context,
            protected_head,
            protected,
            aad,
            payload_head,
            tag,
            inner_head,
            device,
            transcript,
            type_head,
            doc_type,
            namespaces,
        ]
    }
}

/// Derive the 32-byte `EMacKey` from an ECDH shared secret.
///
/// ISO/IEC 18013-5 §9.1.3.5 specifies HKDF-SHA256 with `info = "EMacKey"` and
/// `salt = SHA-256(SessionTranscriptBytes)`. `SessionTranscriptBytes` includes
/// the Tag 24 and byte-string wrapper.
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
    let (head, len) = cbor_head(2, transcript.as_bytes().len() as u64);
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
