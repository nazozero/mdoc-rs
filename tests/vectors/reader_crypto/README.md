# Native reader cryptography vectors

`reader-crypto` uses the maintained [rust-openssl](https://github.com/rust-openssl/rust-openssl)
0.10.82 bindings (Apache-2.0) for Brainpool P256r1/P320r1/P384r1/P512r1 and
Ed448. The tested native library is OpenSSL 3.5.7. Existing NIST/Ed25519
verification continues to use RustCrypto. The Cargo dependency is limited to
native targets; WebAssembly builds reject the additional curves.

## Independent known answers

`wycheproof.tsv` contains 122 selected cases from
[C2SP/wycheproof at 65ca494727a52944c204441c860b039e6786b99b](https://github.com/C2SP/wycheproof/tree/65ca494727a52944c204441c860b039e6786b99b/testvectors_v1).
The upstream files, case IDs, result classifications and original file hashes
are retained in the extraction script, TSV and `source-sha256.txt`.
The data is Apache-2.0 licensed; `WYCHEPROOF-LICENSE` preserves that license.
The extraction converts strictly encoded ECDSA DER integer pairs to COSE's
fixed-width `r || s`, without changing scalar values. ASN.1 encoding cases and
integers outside that width are excluded; the COSE tests separately reject
wrong signature lengths. At most two examples of each result/flag class are
included, so this is a selected corpus rather than the complete Wycheproof suite.

`rfc8032.tsv` preserves the public keys, messages and signatures from the blank
and one-octet Ed448 cases in [RFC 8032 §7.4](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.4).
No secret keys are included. Both contiguous and multipart paths verify pure
Ed448, with an empty context and no prehash.

Existing P-384/Ed25519 RFC cases remain in `tests/cose_vectors.rs`; the
independent OpenSSL P-521 answer and NIST multipart/SPKI checks remain in
`src/cose/verify.rs`. The ISO Annex D fixture supplies an independent ES256
issuer/holder presentation.

## Independently encoded presentations

`generate_presentations.py` constructs CBOR in Python and invokes OpenSSL for
issuer/holder signatures. It imports no nazo-mdoc code. `presentations.tsv`
contains nine full issuer-and-holder cases: each Brainpool curve with full and
compressed device public keys, plus Ed448. Leaf SPKI encodings include the
correct named-curve/Ed448 OIDs. Test certificates use the existing test issuer
and fixed dates; their TBS is signed with Python cryptography's P-256 signer.
Temporary device/issuer keys are discarded after generation. Regeneration
creates different keys/signatures; the committed outputs are the frozen input.
These generated fixtures use the repository's BSD-2-Clause license.

Full verification tests cover both public result forms, changed transcript,
issuer signature, holder signature, document type and disclosed value, plus
atomic rejection of a mixed two-document response. The returned results still
require application issuer trust and request policy.

## Point validation and concurrency

Brainpool SEC1 decoding delegates curve-membership checks to OpenSSL. The four
named groups have cofactor one in [RFC 5639 §§3.4–3.7](https://www.rfc-editor.org/rfc/rfc5639.html#section-3.4).
The boundary rejects infinity; repeating a subgroup multiplication adds no
validation for these prime-order groups. See OpenSSL's
[`ossl_ec_GFp_simple_oct2point`](https://github.com/openssl/openssl/blob/openssl-3.5.7/crypto/ec/ecp_oct.c)
for compressed/uncompressed coordinate checks.

OpenSSL's default provider performs Ed448 point decoding during signature
verification. Its raw-key import and public-key check alone do not establish
mathematical point validity; see
[`ecx_validate`](https://github.com/openssl/openssl/blob/openssl-3.5.7/providers/implementations/keymgmt/ecx_kmgmt.c).
The tests reject identity and small-order-key trivial-signature forgeries and
noncanonical encodings. Standalone Ed448 device-key validation remains
unsupported in `DocumentBuilder` and `verify_issued`; a valid complete holder
signature is required for the supported Ed448 presentation path.

Native verification keys are `Send + Sync`. A regression shares each of the
five new curve keys across eight threads, with sixteen verifications per
thread. Each verification owns its operation state; the key remains immutable.
This is a race/state-isolation regression, not a throughput benchmark.

## Commands and frozen corpus

```sh
cargo test --all-features --lib cose::
cargo test --all-features --test reader_crypto
cargo test --no-default-features --test reader_crypto
python tests/vectors/reader_crypto/extract_wycheproof.py /path/to/testvectors_v1
python tests/vectors/reader_crypto/generate_presentations.py
```

| File | SHA-256 |
| --- | --- |
| `wycheproof.tsv` | `b2ccbe7001b83165b7d3d83eb590c0bf588937a1b8760ff362a9a1ccd0df7c31` |
| `rfc8032.tsv` | `57de800776cd22815130b9f4472bab52be36d7902190165bc6df48dca9495464` |
| `presentations.tsv` | `f37e0c3dfbb2bc409d1ff7bf9b25e188fac1d7f127b26b72c9ce992bb2752ab5` |
