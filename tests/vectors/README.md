# Test vectors

## ISO 18013-5 Annex D

`iso_18013_5_annex_d_mdl.hex` contains the Annex D mDL DeviceResponse.
It was imported from `pyMDOC-CBOR`'s `ISSUED_MDOC` constant in
`pymdoccbor/tests/test_01_mdoc_parser.py`.

- Issuer: "utopia ds", signed by "utopia iaca". The root certificate is omitted
  from x5chain and must be supplied separately for path validation.
- Device authentication: COSE_Mac0.
- Validity: 2020-10-01 through 2021-10-01; validity tests use an explicit time.

`tests/interop_test.rs` covers parsing, digests of complete Tag 24 item envelopes,
FullDate (Tag 1004), tdate (Tag 0) and the issuer COSE_Sign1 signature.
