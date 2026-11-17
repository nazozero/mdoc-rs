# Core architecture and security boundary

`nazo-mdoc` is one package with empty default features. A separate crate for each
CBOR/COSE/model layer would add release coordination without an independent
consumer boundary. The retained repository name preserves links and provenance;
the new package name makes the intentionally breaking 0.3 API explicit. There is
no permanent wrapper pretending to implement the old verifier's trust decisions.

## Data flow

1. `cbor::raw` checks the wire envelope before building decoded containers. It
   enforces deterministic-profile lengths, unique keys and resource bounds, and
   supplies borrowed spans. Embedded Tag 24 shares its containing envelope's
   budget. Opaque COSE byte strings containing CBOR are separately checked
   envelopes. Map order on input is not normalized.
2. `parser` checks DeviceResponse, IssuerSigned, item and DeviceSigned shape. It
   retains the original complete item/namespace Tag 24 and COSE protected bytes.
   Parsed models are untrusted, editable data structures; they are not evidence.
3. `verifier` takes wire bytes, verifies issuer cryptography using the leaf's
   real public-key OIDs, decodes the signed MSO, verifies the holder over the
   requested transcript, then checks authenticated claims and disclosure. No
   caller-supplied decoded claim can replace a value from authenticated bytes.
4. `PendingTrustDocument` exposes immutable authenticated projections and the
   untrusted certificate chain. Its fields are private and there is no final
   validity flag. Issuer-only verification returns a different pending type.
5. NazoAuth completes chain/anchor, certificate revocation, credential status,
   transaction freshness, request and business policy before final admission.

The signature primitives intentionally remain small public tools. A successful
primitive is not proof of payload structure, certificate trust or a final valid
credential. Their documentation makes these narrower guarantees explicit.

## Signing

The issuer builder receives attributes, a device public key, validity, and an
explicit status choice. It validates a supported *public* device point, rejects
private key parameters, generates distinct salts and digest IDs, and builds the
MSO. Subsecond clock input is ordered before and after normalization to whole UTC
seconds. Certificate signing-time comparisons retain Chrono's leap-second ordering.

`prepare` returns exact immutable signing bytes. The host uses its existing
asynchronous key lease. `finish` verifies the returned signature before attaching
it. The holder builder follows the same prepare/sign/finish design. Neither
builder owns a private key or introduces a signing-service abstraction.

Generic attributes are typed CBOR values. This library does not infer a schema
from names such as `birth_date`. NazoAuth's mDL mapping uses explicit namespace
rules; custom schemas preserve the caller's values. Deterministic issuance
encoding validates its output profile. Wire encoders retain signed raw values
and reject invalid or oversized encoded output.

## Deliberate ownership choices

- The single borrowed lifetime belongs to SessionTranscript. Most credential
  models remain owned because the host retains claims after the request buffer
  can be released. Extra lifetimes would not eliminate those required copies.
- MSO decoding occurs once after successful issuer authentication in the main
  path. The pending result shares that decoded MSO with the host. Raw signed
  payloads remain available for independent verification or audit.
- The raw scanner precedes higher-level decoding for security, so parsing is not
  claimed to be single-pass or allocation-free. Benchmark reports include its
  cost alongside savings from removed Value trees and duplicate host verification.
- X.509 DER parsing extracts a public key and signed-time interval. It does not
  create a root store or replace NazoAuth's AWS-LC-backed path policy.
- URI syntax validation is not network authorization. The core has no HTTP
  client, DNS policy, status cache or list publisher.
- The explicit verification time avoids an implicit platform clock and permits
  deterministic tests and WASM consumers. RustCrypto curve dependencies use
  `alloc` instead of `std`, avoiding an unnecessary verifier entropy dependency.

## Fail-closed profiles

The default server verifier requires DeviceSignature, rejects unknown security
extensions and returns no partial result for an invalid multi-document response.
HAIP callers allow exactly one document. Optional Mac0/HKDF primitives remain
separate; the host must establish their session key and policy. Full proximity
engagement, reader authentication, Brainpool/Ed448, status publication and ISO
hardware certification are not implemented by this core.

See `protocol-matrix.md` for normative evidence boundaries and exact owner/test
mapping, and `migration.md` for the one-time NazoAuth migration.
