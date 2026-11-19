# Architecture

`nazo-mdoc` is one library with borrowed protocol views and explicit owned
models for independent storage. Applications provide signing, trust policy,
credential status and transport. Reader key agreement also stays behind an
external private-key operation; the optional reader session owns protocol state
and symmetric keys.

## Verification flow

1. `cbor::raw` checks encoding, duplicate keys and resource limits, then exposes
   borrowed spans. Embedded Tag 24 shares its envelope's budget. COSE protected
   headers and MSO payloads have separate bounded CBOR envelopes.
2. `parser` checks response, document, item and device namespace structure. It
   retains complete Tag 24 envelopes and original COSE protected bytes.
3. `verifier` authenticates the issuer signature using the leaf certificate key,
   decodes the signed MSO, authenticates the holder against the supplied
   transcript, then checks disclosure digests, authorizations and validity.
   With `certificate-profile`, DS profile validation is mandatory at this
   boundary. ISO mDL supplied fields and issuer-only placement are checked in
   every feature configuration.
4. `PendingTrustDocumentRef` exposes immutable authenticated views and leaf-first
   certificate slices. The application checks issuer trust, certificate
   revocation, credential status, request freshness and authorization.

`verify_presentation_borrowed` and `verify_issued_borrowed` authenticate wire bytes and keep parsed
documents private until validation completes. Their disclosure path reuses the
parser's digest-ID, identifier and salt checks. `verify_disclosure` accepts
caller-mutable models and repeats those checks; its caller supplies an
authenticated MSO and keeps metadata consistent with the encoded item bytes.

## Signing flow

`DocumentBuilder` receives typed attributes, a device public key, validity and
an optional status reference. It validates the inputs, generates salts and
31-bit digest IDs, and prepares the MSO and COSE signing bytes. The caller signs
those bytes. `finish` verifies the signature against the leaf certificate key
before assembling the credential. Holder signing uses the same sequence.

The prepared bytes and their key context are immutable. This lets an application
use either a synchronous local signer or an asynchronous external signer without
introducing a signing service into the library.

Reader authentication uses the same contract in `reader`: an immutable borrowed
`ItemsRequest` and session transcript form `ReaderAuthenticationBytes`. The
prepared operation retains the certificate verification key and complete signing
input. `finish` verifies the external signature and writes a detached ReaderAuth;
`encode_device_request` preserves the original ItemsRequestBytes. Reader identity
and certificate policy are supplied by the host.

Attributes retain the caller's CBOR types. Namespace-specific schema mapping
belongs to the application; `mdl` validates supplied standard mDL encodings.
Issuance uses deterministic CBOR; wire encoders copy
already signed fields verbatim.

## Reader sessions

The `reader-session` feature adds `session::reader::ReaderSession`. Its
`ReaderKeyAgreement` provider owns one fresh ephemeral private key and implements
ECDH with the validated peer selected by the core. The constructor binds the
original DeviceEngagement, reader COSE key and QR/NFC handover. Encryption keys
and the holder MAC key use distinct HKDF contexts.

Each session owns separate directional AES-GCM counters and an ordered
request/response state. Mutations require `&mut self`; independent sessions have
no shared lock. A session cannot clone or restart its counters. Failure and
termination drop its ciphers and private-key provider. The provider's lifecycle
contract includes destroying or releasing the ephemeral key; its transport
adapter owns channel closure and timeout scheduling.

Requests are checked by the request encoder before encryption. Replies decrypt
in place and the resulting authenticated claims borrow that plaintext. A
validated CBOR item is reused between response-envelope inspection and credential
parsing. Error-bearing replies expose untrusted protocol data without partial
credential admission. Successful replies reuse the issuer/disclosure/authorization
verifier for either DeviceSignature or session-bound DeviceMAC.

`reader-crypto` adds native OpenSSL verification for the extra Brainpool and
Ed448 signature combinations. Curve identity is separate from COSE algorithm:
ES384, for example, also covers the 320-bit Brainpool curve. Default RustCrypto
verification remains available without native dependencies. Ed448 standalone
device-key validation remains unsupported without a signature-checked context.

## Ownership

- Parsing stores text, byte strings, signed envelopes and claim values as slices
  or `CborValueRef` into the caller's buffer. MSO parsing uses the same bounded
  views and stores references in its namespace and digest indexes.
- The parser retains a private proof for the checked MSO payload only when the
  original `max_bytes`, `max_depth`, `max_items` and `max_collection_items` are
  each no greater than `Limits::default()`. Internal authentication and borrowed
  holder preparation reuse it only while the payload has the same slice address
  and length. A looser original limit or a replaced payload takes the default
  validation path. Public `mso()` always performs that validation independently.
- Authenticated borrowed results keep their fields private and expose read-only
  access. `into_parts` moves indexes without copying their referenced data.
- `into_owned` copies into independent storage. The old owned APIs use this
  conversion after the shared borrowed path. Their certificate-chain return
  contract retains a separate owned chain alongside the owned COSE headers.
- ECDSA verification hashes message fragments through RustCrypto's multipart
  interface; the native Brainpool backend also hashes fragments directly. HMAC
  updates from the same borrowed framing. Ed25519 retains strict verification.
  Ed25519 and native pure Ed448 assemble a contiguous message when needed by
  their backend.
- The upstream X.509 decoder owns its decoded certificate fields. Issuer public
  points go directly from SPKI to the cryptographic verification key. Prepared
  signing operations retain that key rather than rebuilding a COSE key.
  The optional profile feature also retains a borrowed `x509-parser` leaf view
  for extension checks and host reuse. Strict `x509-cert` decoding remains
  necessary because the borrowed parser accepts some BER and inner trailing
  fields. This extra parse is a correctness cost, not another path engine.
- Issuance moves attributes into the result and encodes item and MSO Tag 24
  envelopes directly into their final buffers. Digests use stack outputs;
  namespace sorting retains references. Holder preparation writes one final
  signing input from its component slices.
- Borrowed encoders preserve original signed bytes. Borrowed holder preparation
  consumes a document view and returns final response bytes after signature
  confirmation, without constructing an owned credential in between.

## Time and policy

The caller supplies verification time. `Timestamp` uses `time` for calendar
parsing and formatting, with a separate leap-second marker. It orders the last
regular second, the leap second and the next minute distinctly. Unix conversion
returns `None` for leap seconds. Builders validate time ordering before and after
normalizing issuance input to UTC whole seconds.

The library checks MSO validity and containment of the signed time within the
leaf certificate interval. The application validates the X.509 path at its
verification time and evaluates certificate revocation and credential status.
URI parsing checks syntax; the application's fetch policy governs network use.

The `certificate` module owns ISO profile rules. The application owns root
selection, certificate signatures, path validity, current time and revocation.
Link-profile validation takes authenticated old-root and corresponding new-root
evidence; name equality alone is not proof that a certificate is self-signed.
No tenant, account, application-session, storage or HTTP types enter the library.

`verify_presentation` selects DeviceSignature and verifies every document
atomically. Callers set a document limit appropriate to their presentation
profile. `ReaderSession` explicitly permits signature or MAC and selects the
issuer-authenticated MAC peer. Low-level DeviceMAC/HKDF primitives remain
available with their externally established-key contract.

See the [protocol matrix](protocol-matrix.md) for requirements and regression
tests, and [migration guide](migration.md) for the 0.3 API changes.
