# Architecture

`nazo-mdoc` is one library with a shared `DeviceResponse` model for parsing and
encoding. Applications provide signing, trust policy, credential status and
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
4. `PendingTrustDocument` exposes immutable authenticated data and the leaf-first
   certificate chain. The application checks issuer trust, certificate
   revocation, credential status, request freshness and authorization.

Public parsed models are editable. Authentication therefore starts from wire
bytes; standalone primitives validate their own mutable inputs. Private paths
can reuse validation while they retain exclusive control of those inputs.

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

- Validated `SessionTranscript` values borrow their input. Final validators hash
  the supplied context and compare its framing directly with received bytes.
- Credential models own the data applications retain after releasing a request
  buffer. MSO projection moves strings, digests and key parameters into the model.
- Received Tag 24 envelopes, COSE protected headers and MSO payloads remain
  available in their original byte representation.
- Uniqueness checks borrow names and salts for the duration of validation.
- Status retains the complete CBOR extension and a typed projection of a known
  reference. The application can inspect unknown members before resolving it.
- Pending results own a leaf-first certificate chain as well as the document's
  COSE object, allowing `into_parts` to transfer both representations. Leaf-only
  access borrows DER.

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
