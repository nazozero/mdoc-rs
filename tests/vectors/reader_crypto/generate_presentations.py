"""Generate fixed reader presentations using Python CBOR and OpenSSL signers.

No nazo-mdoc code is imported. Private keys are temporary test-only keys and
are deleted after generation; regeneration creates new keys/signatures.
The existing common test IACA signs certificates with the same fixed validity.
Outputs are project-owned test data under the repository's BSD-2-Clause license.
"""
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
common = (HERE / "../../common/mod.rs").read_text()
certificate = bytes.fromhex(re.search(r'GENUINE_CERT_HEX: &str = "([0-9a-f]+)"', common)[1])
issuer = ec.derive_private_key(int(re.search(r'GENUINE_PRIV_HEX: &str =\s*"([0-9a-f]+)"', common)[1], 16), ec.SECP256R1())

def tlv(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else bytes([0x80 + (length.bit_length()+7)//8]) + length.to_bytes((length.bit_length()+7)//8, "big")
    return bytes([tag]) + encoded + value

def split(data):
    result = []
    while data:
        n, head = data[1], 2
        if n & 128:
            head += n & 127
            n = int.from_bytes(data[2:head], "big")
        result.append((data[0], data[head:head+n], data[:head+n]))
        data = data[head+n:]
    return result

def cbor(value):
    def head(major, n):
        if n < 24: return bytes([(major<<5) | n])
        width = next(x for x in (1, 2, 4, 8) if n < (1 << (8*x)))
        return bytes([(major<<5) | {1:24, 2:25, 4:26, 8:27}[width]]) + n.to_bytes(width, "big")
    if value is None: return b"\xf6"
    if isinstance(value, tuple): return head(6, value[0]) + cbor(value[1])
    if isinstance(value, bool): return b"\xf5" if value else b"\xf4"
    if isinstance(value, int): return head(0 if value >= 0 else 1, value if value >= 0 else -1-value)
    if isinstance(value, bytes): return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode(); return head(3, len(data)) + data
    if isinstance(value, list): return head(4, len(value)) + b"".join(map(cbor, value))
    if isinstance(value, dict): return head(5, len(value)) + b"".join(cbor(k)+cbor(v) for k,v in value.items())
    raise TypeError(type(value))

def run(*args, data=None):
    return subprocess.run(args, input=data, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

rows = []
for name, curve, alg, width, digest in [
    ("brainpoolP256r1",256,-7,32,"sha256"),
    ("brainpoolP320r1",257,-35,40,"sha384"),
    ("brainpoolP384r1",258,-35,48,"sha384"),
    ("brainpoolP512r1",259,-36,64,"sha512"),
    ("ED448",7,-8,57,None),
]:
    with tempfile.TemporaryDirectory() as temp:
        key = str(Path(temp)/"key.pem")
        if curve == 7:
            run("openssl","genpkey","-algorithm",name,"-out",key)
        else:
            run("openssl","ecparam","-name",name,"-genkey","-noout","-out",key)
        spki = run("openssl","pkey","-in",key,"-pubout","-outform","DER")
        public = split(split(spki)[0][1])[1][1][1:]
        cose_key = {1:1,-1:curve,-2:public} if curve == 7 else {1:2,-1:curve,-2:public[1:1+width],-3:public[1+width:]}
        outer = split(split(certificate)[0][1])
        tbs_fields = split(outer[0][1]); tbs_fields[6] = (0x30, b"", spki)
        tbs = tlv(0x30,b"".join(field[2] for field in tbs_fields))
        # Replace the original SKI by the SHA-1 of the new subjectPublicKey bits.
        original_fields = split(outer[0][1]); original_spki = split(original_fields[6][1])
        old_ski = hashlib.sha1(original_spki[1][1][1:]).digest()
        marker = bytes.fromhex("0603551d0e04160414") + old_ski
        assert tbs.count(marker) == 1
        tbs = tbs.replace(marker, marker[:-20] + hashlib.sha1(public).digest())
        cert_sig = issuer.sign(tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        cert = tlv(0x30,tbs+outer[1][2]+tlv(3,b"\0"+cert_sig))
        def sign(message):
            if digest:
                r,s=decode_dss_signature(run("openssl","dgst","-"+digest,"-sign",key,data=message))
                return r.to_bytes(width,"big")+s.to_bytes(width,"big")
            path=Path(temp)/"message";path.write_bytes(message)
            return run("openssl","pkeyutl","-sign","-rawin","-inkey",key,"-in",str(path))
        variants = [(name, cose_key)]
        if curve != 7:
            compressed = dict(cose_key); compressed[-3] = bool(public[-1] & 1)
            variants.append((name + "-compressed", compressed))
        for variant, device_key in variants:
            item=(24,cbor({"digestID":0,"random":bytes(range(16)),"elementIdentifier":"name","elementValue":"reader vector"}))
            mso={"version":"1.0","digestAlgorithm":"SHA-256","valueDigests":{"org.example":{0:hashlib.sha256(cbor(item)).digest()}},
                 "deviceKeyInfo":{"deviceKey":device_key},"docType":"org.example.reader",
                 "validityInfo":{"signed":(0,"2026-11-17T12:00:00Z"),"validFrom":(0,"2026-11-17T12:00:00Z"),"validUntil":(0,"2026-12-17T12:00:00Z")}}
            protected=cbor({1:alg});payload=cbor((24,cbor(mso)))
            auth=[protected,{33:cert},payload,sign(cbor(["Signature1",protected,b"",payload]))]
            issued={"nameSpaces":{"org.example":[item]},"issuerAuth":auth}
            namespaces=(24,cbor({}));transcript=[None,None,None]
            device_payload=cbor((24,cbor(["DeviceAuthentication",transcript,"org.example.reader",namespaces])))
            device_auth=[protected,{},None,sign(cbor(["Signature1",protected,b"",device_payload]))]
            response={"version":"1.0","documents":[{"docType":"org.example.reader","issuerSigned":issued,
                      "deviceSigned":{"nameSpaces":namespaces,"deviceAuth":{"deviceSignature":device_auth}}}],"status":0}
            rows.append([variant,str(curve),str(alg),cbor(issued).hex(),cbor(response).hex()])
(HERE/"presentations.tsv").write_text("# name curve algorithm issued response\n"+"\n".join("\t".join(row) for row in rows)+"\n")
print(run("openssl","version").decode().strip())
print(f"Generated {len(rows)} independently encoded issuer/holder presentations")
