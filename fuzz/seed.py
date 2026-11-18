"""Seed protocol fuzzing from checked-in independent vectors (stdlib only)."""
from pathlib import Path
root = Path(__file__).resolve().parent.parent
corpus = root / "fuzz" / "corpus" / "decode"
corpus.mkdir(parents=True, exist_ok=True)
(corpus / "annex-d").write_bytes(bytes.fromhex((root / "tests/vectors/iso_18013_5_annex_d_mdl.hex").read_text()))
(corpus / "final-redirect").write_bytes(bytes.fromhex("83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"))
(corpus / "duplicate-map-key").write_bytes(bytes.fromhex("a201000100"))
# Keep tag semantics and unsupported simple values reachable independently of
# the outer DeviceResponse grammar. Tags 2/3 must never become plain integers.
(corpus / "nested-bignum-tags").write_bytes(bytes.fromhex("83c240c24101a16178c34106"))
(corpus / "undefined-is-not-null").write_bytes(bytes.fromhex("81f7"))
