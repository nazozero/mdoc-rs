# Architecture

`nazo-mdoc` is one library with borrowed protocol views and explicit owned
models for independent storage. Applications provide signing, trust policy, credential status and
transport.

## Verification flow

1. `cbor::raw` checks encoding, duplicate keys and resource limits, then exposes
   borrowed spans. Embedded Tag 24 shares its envelope's budget. COSE protected
   headers and MSO payloads have separate bounded CBOR envelopes.
2. `parser` checks response, document, item and device namespace structure. It
   retains complete Tag 24 envelopes and original COSE protected bytes.
3. `verifier` authenticates the issuer signature using the leaf certificate key,
   decodes the signed MSO, authenticates the holder against the supplied
   transcript, then checks disclosure digests, authorizations and validity.
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

Attributes retain the caller's CBOR types. Namespace-specific schema mapping
belongs to the application. Issuance uses deterministic CBOR; wire encoders copy
already signed fields verbatim.

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
  interface. HMAC updates from the same borrowed framing. Ed25519 retains strict
  verification and assembles its required contiguous message.
- The upstream X.509 decoder owns its decoded certificate fields. Issuer public
  points go directly from SPKI to the cryptographic verification key. Prepared
  signing operations retain that key rather than rebuilding a COSE key.
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

`verify_presentation` selects DeviceSignature and verifies every document
atomically. Callers set a document limit appropriate to their presentation
profile. DeviceMAC/HKDF primitives accept an externally established session key.

See the [protocol matrix](protocol-matrix.md) for requirements and regression
tests, and [migration guide](migration.md) for the 0.3 API changes.
