"""Extract representative fixed-width verification cases from upstream vectors.

Input is C2SP/wycheproof testvectors_v1 at revision
65ca494727a52944c204441c860b039e6786b99b. Invoke with its local directory.
This copies at most two cases per (result, flags) class per curve, retaining
only strictly DER-encoded, nonnegative ECDSA scalars that fit COSE's width.
ASN.1 encoding cases are excluded because COSE signatures use raw r||s.
The extracted data remains Apache-2.0 licensed (see WYCHEPROOF-LICENSE).
"""
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
SOURCES = [
    (256, -7, 32, "ecdsa_brainpoolP256r1_sha256_test.json"),
    (257, -35, 40, "ecdsa_brainpoolP320r1_sha384_test.json"),
    (258, -35, 48, "ecdsa_brainpoolP384r1_sha384_test.json"),
    (259, -36, 64, "ecdsa_brainpoolP512r1_sha512_test.json"),
    (7, -8, 57, "ed448_test.json"),
]
rows = []
hashes = []
for curve, algorithm, width, name in SOURCES:
    data = (Path(sys.argv[1]) / name).read_bytes()
    hashes.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    selected = {}
    for group in json.loads(data)["testGroups"]:
        for case in group["tests"]:
            category = (case["result"], tuple(case["flags"]))
            if case["result"] not in ("valid", "invalid") or selected.get(category, 0) >= 2:
                continue
            signature = bytes.fromhex(case["sig"])
            if curve != 7:
                try:
                    r, s = decode_dss_signature(signature)
                    signature = r.to_bytes(width, "big") + s.to_bytes(width, "big")
                except (ValueError, OverflowError):
                    continue
            selected[category] = selected.get(category, 0) + 1
            rows.append([str(curve), str(algorithm), str(case["tcId"]), case["result"],
                         group["publicKeyDer"], case["msg"], signature.hex(),
                         ",".join(case["flags"])])
(HERE / "wycheproof.tsv").write_text(
    "# Apache-2.0: selected C2SP/wycheproof cases; see README.md\n"
    "# curve algorithm tcId result spki_der message raw_signature flags\n" +
    "\n".join("\t".join(row) for row in rows) + "\n")
(HERE / "source-sha256.txt").write_text("\n".join(hashes) + "\n")
print(f"Extracted {len(rows)} independent verification vectors")
