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
for line in (root / "tests/vectors/reader/reader_authentication.tsv").read_text().splitlines():
    name, value = line.split("\t")
    if name in {"items", "transcript"}:
        (corpus / ("reader-" + name)).write_bytes(bytes.fromhex(value))
(corpus / "reader-protocol-error").write_bytes(bytes.fromhex("a26776657273696f6e63312e30667374617475730a"))
certificates = root / "fuzz" / "corpus" / "certificate"
certificates.mkdir(parents=True, exist_ok=True)
for line in (root / "tests/vectors/certificates/profiles.tsv").read_text().splitlines():
    if not line.startswith("#"):
        name, _, _, _, der = line.split("\t")
        (certificates / name).write_bytes(bytes.fromhex(der))
sessions = root / "fuzz" / "corpus" / "reader_session"
sessions.mkdir(parents=True, exist_ok=True)
for line in (root / "tests/vectors/session/vectors.tsv").read_text().splitlines():
    if line.startswith("#"):
        continue
    name, value = line.split("\t")
    mode = 0 if name == "engagement" else 3 if name == "reader_public" else 2 if name == "response_plaintext" else 1 if name.startswith("response_") else None
    if mode is not None:
        (sessions / name).write_bytes(bytes([mode]) + bytes.fromhex(value))
