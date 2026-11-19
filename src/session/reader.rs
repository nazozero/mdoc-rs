//! ISO/IEC 18013-5:2021 device-retrieval reader sessions (§9.1.1 and §9.1.3).
//!
//! The reader owns one fresh ephemeral key through [`ReaderKeyAgreement`].
//! This module binds that key to the original engagement and handover, derives
//! the separate session/MAC keys, and owns directional AES-GCM counters. Private
//! key generation, hardware custody, transport selection and inactivity timers
//! belong to the adapter. Dropping the key provider must destroy its ephemeral
//! key or release a lease whose owner destroys it.

use std::{borrow::Cow, ops::Range};

#[cfg(not(all(feature = "aws-lc", not(target_family = "wasm"))))]
use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInOut};
#[cfg(all(feature = "aws-lc", not(target_family = "wasm")))]
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::{DeviceAuthentication, SessionBinding, SessionTranscript, transcript_salt};
use crate::{
    MdocError, PendingTrustDocumentRef, VerificationOptions,
    cbor::raw::{Item, Limits, cbor_head, push_bytes},
    model::{CborValueRef, CoseKeyRef, CoseLabelRef, CoseMac0Ref},
};

fn error(message: &str) -> MdocError {
    MdocError::Session(message.into())
}

/// Public key checked for a cipher-suite-1 ECDH operation.
///
/// EC2 keys use SEC1 point encoding. X25519 and X448 use RFC 7748 byte strings;
/// their low-order rejection is completed by checking the agreement result.
/// The original COSE encoding remains in the session transcript or signed MSO.
pub struct AgreementPublicKey {
    curve: i64,
    bytes: [u8; 133],
    len: usize,
    secret_len: usize,
}

impl AgreementPublicKey {
    /// COSE curve identifier; this is distinct from a signature algorithm.
    pub fn curve(&self) -> i64 {
        self.curve
    }

    /// Checked SEC1 point or RFC 7748 public bytes for the external backend.
    pub fn public_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn from_item(item: Item<'_>, reader: bool) -> Result<Self, MdocError> {
        let (mut kty, mut crv, mut x, mut y) = (None, None, None, None);
        for entry in item.map()? {
            let (label, value) = entry?;
            match label.as_integer() {
                Some(1) => kty = value.as_integer(),
                Some(-1) => crv = value.as_integer(),
                Some(-2) => x = Some(CborValueRef::from_item(value)),
                Some(-3) => y = Some(CborValueRef::from_item(value)),
                Some(-4) => return Err(error("agreement key must contain public parameters only")),
                // §9.1.5.2: other optional COSE parameters are ignored.
                _ if label.as_integer().is_some() || label.as_text().is_some() => {}
                _ => return Err(error("invalid COSE key label")),
            }
        }
        Self::from_parameters(kty, crv, x, y, reader)
    }

    fn from_device_key(key: &CoseKeyRef<'_>) -> Result<Self, MdocError> {
        let mut crv = None;
        let mut x = None;
        let mut y = None;
        for (label, value) in &key.params {
            match label {
                CoseLabelRef::Int(-1) => crv = value.as_integer(),
                CoseLabelRef::Int(-2) => x = Some(*value),
                CoseLabelRef::Int(-3) => y = Some(*value),
                CoseLabelRef::Int(-4) => {
                    return Err(error("agreement key must contain public parameters only"));
                }
                _ => {}
            }
        }
        let kty = match key.kty {
            CoseLabelRef::Int(kty) => Some(i128::from(kty)),
            _ => None,
        };
        Self::from_parameters(kty, crv, x, y, false)
    }

    fn from_parameters(
        kty: Option<i128>,
        crv: Option<i128>,
        x: Option<CborValueRef<'_>>,
        y: Option<CborValueRef<'_>>,
        reader: bool,
    ) -> Result<Self, MdocError> {
        let curve = crv
            .and_then(|curve| i64::try_from(curve).ok())
            .ok_or_else(|| error("missing agreement curve"))?;
        let width = match (kty, curve) {
            (Some(2), 1 | 256) => 32,
            (Some(2), 257) => 40,
            (Some(2), 2 | 258) => 48,
            (Some(2), 259) => 64,
            (Some(2), 3) => 66,
            (Some(1), 4) => 32,
            (Some(1), 5) => 56,
            _ => return Err(error("unsupported cipher-suite-1 agreement key")),
        };
        let x = x
            .and_then(CborValueRef::as_bytes)
            .filter(|bytes| bytes.len() == width)
            .ok_or_else(|| error("invalid agreement x coordinate"))?;
        let mut key = Self {
            curve,
            bytes: [0; 133],
            len: 0,
            secret_len: width,
        };
        if kty == Some(1) {
            if y.is_some() {
                return Err(error("OKP agreement key must not contain y"));
            }
            key.bytes[..width].copy_from_slice(x);
            key.len = width;
            return Ok(key);
        }
        let y = y.ok_or_else(|| error("missing agreement y coordinate"))?;
        key.bytes[1..1 + width].copy_from_slice(x);
        if let Some(y) = y.as_bytes().filter(|bytes| bytes.len() == width) {
            key.bytes[0] = 4;
            key.bytes[1 + width..1 + 2 * width].copy_from_slice(y);
            key.len = 1 + 2 * width;
        } else if let Some(odd) = y.as_bool().filter(|_| !reader) {
            key.bytes[0] = if odd { 3 } else { 2 };
            key.len = 1 + width;
        } else {
            return Err(error(
                "reader key must be uncompressed; invalid agreement y coordinate",
            ));
        }
        let point = key.public_bytes();
        match curve {
            1 => p256::PublicKey::from_sec1_bytes(point)
                .map(|_| ())
                .map_err(|_| error("invalid P-256 agreement point"))?,
            2 => p384::PublicKey::from_sec1_bytes(point)
                .map(|_| ())
                .map_err(|_| error("invalid P-384 agreement point"))?,
            3 => p521::PublicKey::from_sec1_bytes(point)
                .map(|_| ())
                .map_err(|_| error("invalid P-521 agreement point"))?,
            #[cfg(feature = "reader-crypto")]
            256 => {
                bp256::elliptic_curve::PublicKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(point)
                    .map(|_| ())
                    .map_err(|_| error("invalid Brainpool P256 agreement point"))?
            }
            #[cfg(feature = "reader-crypto")]
            258 => {
                bp384::elliptic_curve::PublicKey::<bp384::BrainpoolP384r1>::from_sec1_bytes(point)
                    .map(|_| ())
                    .map_err(|_| error("invalid Brainpool P384 agreement point"))?
            }
            _ => return Err(error("agreement curve is not supported by the backend")),
        }
        Ok(key)
    }
}

/// One externally computed ECDH result. Its bytes are erased on drop.
pub struct SharedSecret(Zeroizing<Vec<u8>>);

impl SharedSecret {
    /// Transfer the external backend's ZAB output without cloning it.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// External private-key operation for one newly generated reader ephemeral key.
///
/// `public_key` returns the bare COSE_Key corresponding to that private key.
/// `agree` performs ECKA-DH (RFC 7748 for X25519/X448) with exactly the supplied
/// peer. Its result is the fixed-width ZAB output, not a derived key. The core
/// selects and validates the peer; adapters must not substitute another key,
/// return a cached unrelated secret, or reuse this ephemeral key in a new session.
/// Destruction of the provider must destroy/release the private key.
pub trait ReaderKeyAgreement {
    fn public_key(&self) -> &[u8];
    fn agree(&mut self, peer: &AgreementPublicKey) -> Result<SharedSecret, MdocError>;
}

/// Original transport handover bytes used in the session transcript.
#[derive(Clone, Copy, Debug)]
pub enum Handover<'a> {
    Qr,
    Nfc {
        /// Complete NDEF Handover Select message received from the device.
        select: &'a [u8],
        /// Complete sent Handover Request; absent for static NFC handover.
        request: Option<&'a [u8]>,
    },
}

/// ISO session status. All currently defined statuses terminate the session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionStatus {
    EncryptionError = 10,
    DecodingError = 11,
    Termination = 20,
}

impl SessionStatus {
    /// Encode a status-only SessionData message after closing the local session.
    pub fn encode(self) -> [u8; 9] {
        [0xa1, 0x66, b's', b't', b'a', b't', b'u', b's', self as u8]
    }
}

/// Issuer/holder evidence from a decrypted response. Trust and status admission
/// remain with the host, exactly as for signature-only presentation verification.
#[derive(Debug)]
#[must_use = "complete issuer trust, credential status and request policy in the host"]
pub enum ReaderResponse<'a> {
    /// Every presented document passed issuer and holder authentication.
    Authenticated {
        documents: Vec<PendingTrustDocumentRef<'a>>,
        status: Option<SessionStatus>,
    },
    /// A protocol error, mixed response or response without documents. Its
    /// raw documents and error details have no credential-authentication result.
    Protocol {
        response: crate::reader::ResponseEnvelope<'a>,
        status: Option<SessionStatus>,
    },
    /// No encrypted DeviceResponse was included.
    Status(SessionStatus),
}

impl ReaderResponse<'_> {
    /// Outer session status, distinct from the encrypted DeviceResponse status.
    pub fn session_status(&self) -> Option<SessionStatus> {
        match self {
            Self::Authenticated { status, .. } | Self::Protocol { status, .. } => *status,
            Self::Status(status) => Some(*status),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Initial,
    Waiting,
    Ready,
    Closed,
}

#[cfg(all(feature = "aws-lc", not(target_family = "wasm")))]
type SessionCipher = LessSafeKey;
#[cfg(not(all(feature = "aws-lc", not(target_family = "wasm"))))]
type SessionCipher = Aes256Gcm;

#[cfg(all(feature = "aws-lc", not(target_family = "wasm")))]
fn new_cipher(key: &[u8]) -> Result<SessionCipher, MdocError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| error("invalid session key length"))
}

#[cfg(not(all(feature = "aws-lc", not(target_family = "wasm"))))]
fn new_cipher(key: &[u8]) -> Result<SessionCipher, MdocError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| error("invalid session key length"))
}

#[cfg(all(feature = "aws-lc", not(target_family = "wasm")))]
fn seal(
    cipher: &SessionCipher,
    nonce: [u8; 12],
    plaintext: &mut [u8],
) -> Result<[u8; 16], MdocError> {
    let tag = cipher
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), plaintext)
        .map_err(|_| error("session request encryption failed"))?;
    let mut bytes = [0; 16];
    bytes.copy_from_slice(tag.as_ref());
    Ok(bytes)
}

#[cfg(not(all(feature = "aws-lc", not(target_family = "wasm"))))]
fn seal(
    cipher: &SessionCipher,
    nonce: [u8; 12],
    plaintext: &mut [u8],
) -> Result<[u8; 16], MdocError> {
    let tag = cipher
        .encrypt_inout_detached(&nonce.into(), &[], plaintext.into())
        .map_err(|_| error("session request encryption failed"))?;
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&tag);
    Ok(bytes)
}

#[cfg(all(feature = "aws-lc", not(target_family = "wasm")))]
fn open(
    cipher: &SessionCipher,
    nonce: [u8; 12],
    plaintext: &mut [u8],
    tag: &[u8],
) -> Result<(), MdocError> {
    cipher
        .open_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            tag,
            plaintext,
        )
        .map(|_| ())
        .map_err(|_| error("session response authentication failed"))
}

#[cfg(not(all(feature = "aws-lc", not(target_family = "wasm"))))]
fn open(
    cipher: &SessionCipher,
    nonce: [u8; 12],
    plaintext: &mut [u8],
    tag: &[u8],
) -> Result<(), MdocError> {
    cipher
        .decrypt_inout_detached(
            &nonce.into(),
            &[],
            plaintext.into(),
            &aes_gcm::Tag::try_from(tag).expect("16-byte tag"),
        )
        .map_err(|_| error("session response authentication failed"))
}

struct Ciphers {
    reader: SessionCipher,
    device: SessionCipher,
    sent: u32,
    received: u32,
}

/// One ordered reader session; no shared counters, cloning or global state.
///
/// Mutating operations require exclusive access. Separate sessions can run
/// concurrently. Each request uses the next SKReader counter; each response
/// uses the next SKDevice counter. Invalid messages terminate and destroy the
/// session, so a replay or failed GCM tag cannot be retried under reset counters.
pub struct ReaderSession<K: ReaderKeyAgreement> {
    transcript: SessionTranscript<'static>,
    reader_key_bytes: Range<usize>,
    reader_curve: i64,
    salt: [u8; 32],
    key: Option<K>,
    ciphers: Option<Ciphers>,
    phase: Phase,
    age_requests: usize,
}

impl<K: ReaderKeyAgreement> ReaderSession<K> {
    /// Establish cipher-suite-1 state from the exact received bare
    /// `DeviceEngagement` CBOR and transport handover. NFC/BLE/QR adapters own
    /// decoding the physical interface and matching its retrieval options.
    pub fn new(
        device_engagement: &[u8],
        handover: Handover<'_>,
        mut key: K,
    ) -> Result<Self, MdocError> {
        let reader_bytes = key.public_key();
        let size = transcript_size(device_engagement, reader_bytes, handover)?;
        let mut bytes = Vec::with_capacity(size);
        bytes.push(0x83);
        append_embedded(&mut bytes, device_engagement);
        let start = bytes.len();
        append_embedded(&mut bytes, reader_bytes);
        let reader_key_bytes = start..bytes.len();
        match handover {
            Handover::Qr => bytes.push(0xf6),
            Handover::Nfc { select, request } => {
                bytes.push(0x82);
                push_bytes(&mut bytes, select);
                if let Some(request) = request {
                    push_bytes(&mut bytes, request);
                } else {
                    bytes.push(0xf6);
                }
            }
        }
        // One validation shares depth/item budgets across every Tag 24 envelope.
        let mut fields = Item::parse(&bytes)?.array()?;
        let device_key = engagement_key(
            fields
                .next()
                .expect("three transcript fields")?
                .embedded()?,
            handover,
        )?;
        let reader_key = AgreementPublicKey::from_item(
            fields
                .next()
                .expect("three transcript fields")?
                .embedded()?,
            true,
        )?;
        if reader_key.curve != device_key.curve {
            return Err(error("reader and engagement agreement curves differ"));
        }
        let transcript = SessionTranscript {
            bytes: Cow::Owned(bytes),
            binding: SessionBinding::DeviceRetrieval,
        };
        let secret = checked_agreement(&mut key, &device_key)?;
        let salt = transcript_salt(&transcript);
        let hkdf = session_hkdf(&secret.0, &salt);
        let mut derived = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"SKReader", derived.as_mut())
            .map_err(|_| error("session key derivation failed"))?;
        let reader = new_cipher(derived.as_ref())?;
        hkdf.expand(b"SKDevice", derived.as_mut())
            .map_err(|_| error("session key derivation failed"))?;
        let device = new_cipher(derived.as_ref())?;
        Ok(Self {
            transcript,
            reader_key_bytes,
            reader_curve: reader_key.curve,
            salt,
            key: Some(key),
            ciphers: Some(Ciphers {
                reader,
                device,
                sent: 0,
                received: 0,
            }),
            phase: Phase::Initial,
            age_requests: 0,
        })
    }

    /// The same immutable transcript used by session encryption and DeviceMAC.
    pub fn transcript(&self) -> &SessionTranscript<'static> {
        &self.transcript
    }

    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// Destroy the session ciphers and release the externally held ephemeral key.
    /// The adapter also closes its transport; its inactivity timer calls this method.
    pub fn close(&mut self) {
        self.ciphers = None;
        self.key = None;
        self.phase = Phase::Closed;
    }

    /// Close locally and return a status-only session-termination message.
    pub fn terminate(&mut self) -> [u8; 9] {
        self.close();
        SessionStatus::Termination.encode()
    }

    /// Encrypt an encoded DeviceRequest into SessionEstablishment or SessionData.
    ///
    /// Use the reader request encoder to establish the plaintext schema. This
    /// layer frames and encrypts it in one output allocation. After sending, wait
    /// for a response before sending the next request. A transport failure closes
    /// the session; reconstructing it with the same ephemeral key is forbidden.
    pub fn encrypt_request(
        &mut self,
        request: &crate::reader::DeviceRequest,
    ) -> Result<Vec<u8>, MdocError> {
        if !matches!(self.phase, Phase::Initial | Phase::Ready) {
            return Err(error("session is closed or awaiting a response"));
        }
        let age_requests = self.age_requests + request.age_requests();
        if age_requests > 2 {
            return Err(error(
                "at most two age attestations may be requested in one retrieval phase",
            ));
        }
        let request = request.as_bytes();
        let ciphers = self.ciphers.as_mut().expect("active session ciphers");
        let Some(counter) = ciphers.sent.checked_add(1) else {
            self.close();
            return Err(error("reader session counter exhausted"));
        };
        let establishment = self.phase == Phase::Initial;
        let reader_key = &self.transcript.as_bytes()[self.reader_key_bytes.clone()];
        let (head, head_len) = cbor_head(2, request.len() as u64 + 16);
        let size = request.len()
            + 16
            + head_len
            + 6
            + if establishment {
                11 + reader_key.len()
            } else {
                0
            };
        if size > Limits::default().max_bytes {
            return Err(error("encrypted request exceeds the session byte limit"));
        }
        let mut output = Vec::with_capacity(size);
        output.push(if establishment { 0xa2 } else { 0xa1 });
        if establishment {
            output.extend_from_slice(b"\x6aeReaderKey");
            output.extend_from_slice(reader_key);
        }
        output.extend_from_slice(b"\x64data");
        output.extend_from_slice(&head[..head_len]);
        let start = output.len();
        output.extend_from_slice(request);
        let tag = seal(&ciphers.reader, nonce(false, counter), &mut output[start..]);
        match tag {
            Ok(tag) => output.extend_from_slice(&tag),
            Err(error) => {
                self.close();
                return Err(error);
            }
        }
        ciphers.sent = counter;
        self.phase = Phase::Waiting;
        self.age_requests = age_requests;
        Ok(output)
    }

    /// Decrypt a SessionData message in place, authenticate every presented
    /// document, and borrow the resulting claims from `message`.
    ///
    /// Both DeviceSignature and DeviceMAC run the same issuer/MSO/disclosure and
    /// device-authorization checks. Failure returns no partial document list.
    /// A terminal message containing data is verified before key destruction.
    pub fn receive_response<'a>(
        &mut self,
        message: &'a mut [u8],
        options: &VerificationOptions,
    ) -> Result<ReaderResponse<'a>, MdocError> {
        self.receive_inner(
            message,
            options,
            #[cfg(feature = "certificate-profile")]
            None,
        )
    }

    /// Reuse an immutable prepared signer under the same leaf-byte equality
    /// rule as the signature-only presentation API.
    #[cfg(feature = "certificate-profile")]
    pub fn receive_response_with_signer<'a>(
        &mut self,
        message: &'a mut [u8],
        options: &VerificationOptions,
        signer: Option<&crate::certificate::PreparedDocumentSigner>,
    ) -> Result<ReaderResponse<'a>, MdocError> {
        self.receive_inner(message, options, signer)
    }

    fn receive_inner<'a>(
        &mut self,
        message: &'a mut [u8],
        options: &VerificationOptions,
        #[cfg(feature = "certificate-profile")] signer: Option<
            &crate::certificate::PreparedDocumentSigner,
        >,
    ) -> Result<ReaderResponse<'a>, MdocError> {
        if self.phase != Phase::Waiting {
            self.close();
            return Err(error("response received outside an outstanding request"));
        }
        let result = self.receive_active(
            message,
            options,
            #[cfg(feature = "certificate-profile")]
            signer,
        );
        if match &result {
            Ok(response) => response.session_status().is_some(),
            Err(_) => true,
        } {
            self.close();
        } else {
            self.phase = Phase::Ready;
        }
        result
    }

    fn receive_active<'a>(
        &mut self,
        message: &'a mut [u8],
        options: &VerificationOptions,
        #[cfg(feature = "certificate-profile")] signer: Option<
            &crate::certificate::PreparedDocumentSigner,
        >,
    ) -> Result<ReaderResponse<'a>, MdocError> {
        let (data, status) = session_data(message)?;
        let Some(range) = data else {
            return Ok(ReaderResponse::Status(
                status.expect("nonempty session message"),
            ));
        };
        let encrypted = &mut message[range];
        let plaintext_len = encrypted
            .len()
            .checked_sub(16)
            .ok_or_else(|| error("truncated session authentication tag"))?;
        let (plaintext, tag) = encrypted.split_at_mut(plaintext_len);
        let ciphers = self.ciphers.as_mut().expect("active session ciphers");
        let counter = ciphers
            .received
            .checked_add(1)
            .ok_or_else(|| error("device session counter exhausted"))?;
        open(&ciphers.device, nonce(true, counter), plaintext, tag)?;
        ciphers.received = counter;
        let root = Item::parse(plaintext)?;
        let response = crate::reader::ResponseEnvelope::from_validated(root)?;
        if response.status() != 0 || response.has_errors() || response.documents().is_none() {
            return Ok(ReaderResponse::Protocol { response, status });
        }
        let parsed = crate::parser::parse_borrowed_validated(
            root,
            Limits::default(),
            options.max_documents,
        )?;
        let documents = crate::verifier::verify_presentation_borrowed_in_session(
            parsed,
            &self.transcript,
            options,
            self.key.as_mut().expect("active reader key"),
            self.reader_curve,
            &self.salt,
            #[cfg(feature = "certificate-profile")]
            signer,
        )?;
        Ok(ReaderResponse::Authenticated { documents, status })
    }
}

pub(crate) fn verify_device_mac<K: ReaderKeyAgreement>(
    key: &mut K,
    reader_curve: i64,
    device_key: &CoseKeyRef<'_>,
    mac: &CoseMac0Ref<'_>,
    salt: &[u8; 32],
    payload: &DeviceAuthentication<'_>,
) -> Result<(), MdocError> {
    use hmac::{Hmac, KeyInit, Mac};
    if mac.payload.is_some() {
        return Err(error("deviceMac must use a detached payload"));
    }
    if crate::cose::validate_borrowed_headers(&mac.protected_header, &mac.unprotected)? != 5 {
        return Err(error("deviceMac requires protected HMAC-256/256"));
    }
    if mac.tag.len() != 32 {
        return Err(error("deviceMac requires a 32-byte tag"));
    }
    let peer = AgreementPublicKey::from_device_key(device_key)?;
    if peer.curve != reader_curve {
        return Err(error("MSO device key and reader agreement curves differ"));
    }
    let secret = checked_agreement(key, &peer)?;
    let mut derived = Zeroizing::new([0u8; 32]);
    session_hkdf(&secret.0, salt)
        .expand(b"EMacKey", derived.as_mut())
        .map_err(|_| error("device MAC key derivation failed"))?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(derived.as_ref())
        .map_err(|_| error("invalid device MAC key length"))?;
    let framing = crate::cose::AuthenticationStructure::mac0(mac.protected.len(), payload.len());
    for part in payload.authentication_parts(framing.prefix(mac.protected)) {
        hmac.update(part);
    }
    hmac.verify_slice(mac.tag)
        .map_err(|_| error("holder MAC does not match session"))
}

fn checked_agreement<K: ReaderKeyAgreement>(
    key: &mut K,
    peer: &AgreementPublicKey,
) -> Result<SharedSecret, MdocError> {
    let secret = key.agree(peer)?;
    // The OR-reduction processes every byte; RFC 7748 low-order keys produce zero.
    if secret.0.len() != peer.secret_len || secret.0.iter().fold(0u8, |acc, byte| acc | byte) == 0 {
        return Err(error(
            "invalid ECDH result length or all-zero shared secret",
        ));
    }
    Ok(secret)
}

fn session_hkdf(secret: &[u8], salt: &[u8; 32]) -> hkdf::Hkdf<Sha256> {
    let (mut prk, hkdf) = hkdf::Hkdf::<Sha256>::extract(Some(salt), secret);
    prk.zeroize();
    hkdf
}

fn engagement_key(
    engagement: Item<'_>,
    handover: Handover<'_>,
) -> Result<AgreementPublicKey, MdocError> {
    let mut version = None;
    let mut security = None;
    let mut retrieval = None;
    for entry in engagement.map()? {
        let (label, value) = entry?;
        match label
            .as_integer()
            .ok_or_else(|| error("engagement labels must be integers"))?
        {
            0 => version = Some(value.text()?),
            1 => security = Some(value),
            2 => retrieval = Some(value),
            // Other transport/server information is authenticated byte-for-byte
            // in the transcript; interpreting it is the adapter's responsibility.
            _ => {}
        }
    }
    if !version.is_some_and(crate::model::supports_version) {
        return Err(error("unsupported DeviceEngagement version"));
    }
    match (handover, retrieval) {
        (Handover::Qr, Some(methods)) => {
            let methods = methods.array()?;
            if methods.len() == 0 {
                return Err(error("QR engagement needs a retrieval method"));
            }
            for method in methods {
                let mut method = method?.array()?;
                if method.len() != 3 {
                    return Err(error("invalid retrieval method"));
                }
                let kind = method.next().expect("three items")?.uint()?;
                let version = method.next().expect("three items")?.uint()?;
                let options = method.next().expect("three items")?;
                if matches!(kind, 1..=3) && version == 1 {
                    options.map()?;
                }
                // The adapter checks the selected transport's options.
            }
        }
        (Handover::Qr, None) => return Err(error("QR engagement needs retrieval methods")),
        (Handover::Nfc { select, request }, None) => {
            if select.is_empty() || request.is_some_and(<[u8]>::is_empty) {
                return Err(error("NFC handover messages must not be empty"));
            }
        }
        (Handover::Nfc { .. }, Some(_)) => {
            return Err(error("NFC engagement must omit retrieval methods"));
        }
    }
    let mut security = security
        .ok_or_else(|| error("missing engagement security"))?
        .array()?;
    if security.len() != 2 || security.next().expect("security item")?.as_integer() != Some(1) {
        return Err(error("engagement requires cipher suite 1"));
    }
    AgreementPublicKey::from_item(
        security.next().expect("two security items")?.embedded()?,
        false,
    )
}

fn session_data(
    encoded: &[u8],
) -> Result<(Option<Range<usize>>, Option<SessionStatus>), MdocError> {
    let mut data = None;
    let mut status = None;
    for entry in Item::parse(encoded)?.map()? {
        let (label, value) = entry?;
        match label.text()? {
            "data" => {
                let bytes = value.bstr()?;
                let start = bytes.as_ptr() as usize - encoded.as_ptr() as usize;
                data = Some(start..start + bytes.len());
            }
            "status" => {
                status = Some(match value.uint()? {
                    10 => SessionStatus::EncryptionError,
                    11 => SessionStatus::DecodingError,
                    20 => SessionStatus::Termination,
                    _ => return Err(error("unsupported session status")),
                })
            }
            _ => return Err(error("unsupported SessionData field")),
        }
    }
    if data.is_none() && status.is_none() {
        return Err(error("empty SessionData message"));
    }
    if data.is_some()
        && matches!(
            status,
            Some(SessionStatus::EncryptionError | SessionStatus::DecodingError)
        )
    {
        return Err(error("session error status must not contain data"));
    }
    Ok((data, status))
}

fn nonce(device: bool, counter: u32) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[7] = u8::from(device);
    bytes[8..].copy_from_slice(&counter.to_be_bytes());
    bytes
}

fn append_embedded(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&[0xd8, 0x18]);
    push_bytes(output, value);
}

fn transcript_size(
    engagement: &[u8],
    reader: &[u8],
    handover: Handover<'_>,
) -> Result<usize, MdocError> {
    let limit = Limits::default().max_bytes;
    let mut size = 5usize; // array + the two Tag 24 tags
    let mut add_bytes = |bytes: &[u8]| -> Result<(), MdocError> {
        size = size
            .checked_add(cbor_head(2, bytes.len() as u64).1)
            .and_then(|size| size.checked_add(bytes.len()))
            .filter(|size| *size <= limit)
            .ok_or_else(|| error("session transcript exceeds the CBOR byte limit"))?;
        Ok(())
    };
    add_bytes(engagement)?;
    add_bytes(reader)?;
    match handover {
        Handover::Qr => size += 1,
        Handover::Nfc { select, request } => {
            add_bytes(select)?;
            if let Some(request) = request {
                add_bytes(request)?;
            } else {
                size += 1;
            }
            size += 1;
        }
    }
    if size > limit {
        return Err(error("session transcript exceeds the CBOR byte limit"));
    }
    Ok(size)
}

#[cfg(test)]
mod tests;
