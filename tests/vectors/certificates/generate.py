"""Regenerate deterministic signed Annex B profile test vectors with cryptography.

Every negative certificate has a valid ECDSA signature over its complete TBS.
Keys are public, deterministic test-only scalars. No system clock is consulted.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

HERE = Path(__file__).resolve().parent
OLD = ec.derive_private_key(17, ec.SECP256R1())
NEW = ec.derive_private_key(19, ec.SECP256R1())
OTHER = ec.derive_private_key(23, ec.SECP256R1())
DS = ec.derive_private_key(29, ec.SECP256R1())
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = datetime(2036, 1, 1, tzinfo=timezone.utc)

def dn(cn, country='US'):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country), x509.NameAttribute(NameOID.COMMON_NAME, cn)])

OLD_DN = dn('Original IACA')
NEW_DN = dn('Successor IACA')
DS_DN = dn('Document signer')


def build(kind, key, issuer_key, subject, issuer, *, before=START, after=None, skip=(), changes=None, extra=(), san=None):
    ca = kind != 'ds'
    b = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
    b = b.serial_number(0x2743019478168719234).not_valid_before(before).not_valid_after(after or (END if ca else START + timedelta(days=365)))
    extensions = {
        'ski': (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
        'ku': (x509.KeyUsage(not ca, False, False, False, False, ca, ca, None, None), True),
        'ian': (x509.IssuerAlternativeName([x509.UniformResourceIdentifier('https://issuer.example/contact')]), False),
        'crl': (x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier('https://issuer.example/crl')], None, None, None)]), False),
    }
    if ca:
        extensions['bc'] = (x509.BasicConstraints(ca=True, path_length=0), True)
    if kind != 'root':
        extensions['aki'] = (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
    if not ca:
        extensions['eku'] = (x509.ExtendedKeyUsage([ObjectIdentifier('1.0.18013.5.1.2')]), True)
    if san is not None:
        extensions['san'] = (x509.SubjectAlternativeName([x509.DirectoryName(san)]), False)
    extensions.update(changes or {})
    for name, (value, critical) in extensions.items():
        if name not in skip:
            b = b.add_extension(value, critical)
    for value, critical in extra:
        b = b.add_extension(value, critical)
    return b.sign(issuer_key, hashes.SHA256(), ecdsa_deterministic=True).public_bytes(serialization.Encoding.DER)

vectors = []
def add(name, kind, valid=True, **kwargs):
    if kind == 'root':
        key = kwargs.pop('key', OLD)
        issuer_key = key
        subject = kwargs.pop('subject', OLD_DN)
        issuer = kwargs.pop('issuer', subject)
    elif kind == 'ds':
        key, issuer_key = DS, OLD
        subject, issuer = kwargs.pop('subject', DS_DN), kwargs.pop('issuer', OLD_DN)
    else:
        key, issuer_key = kwargs.pop('key', NEW), OLD
        subject = kwargs.pop('subject', OLD_DN if kind == 'link_same' else NEW_DN)
        issuer = kwargs.pop('issuer', OLD_DN)
    raw = build('link' if kind.startswith('link') else kind, key, issuer_key, subject, issuer, **kwargs)
    point = issuer_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    vectors.append([name, kind, str(valid).lower(), point.hex(), raw.hex()])

add('old', 'root')
add('new', 'root', key=NEW, subject=NEW_DN)
add('new_same', 'root', key=NEW, subject=OLD_DN)
add('root_twenty_years', 'root', after=datetime(2046,1,1,tzinfo=timezone.utc))
add('root_over_twenty_years', 'root', False, after=datetime(2046,1,1,tzinfo=timezone.utc)+timedelta(seconds=1))
add('root_century_clamp', 'root', before=datetime(2080,2,29,tzinfo=timezone.utc), after=datetime(2100,2,28,tzinfo=timezone.utc))
add('root_century_over', 'root', False, before=datetime(2080,2,29,tzinfo=timezone.utc), after=datetime(2100,2,28,tzinfo=timezone.utc)+timedelta(seconds=1))
for role in ['root', 'ds']:
    for ext in ['ski','ku','ian','crl'] + (['bc'] if role == 'root' else ['aki','eku']):
        add(f'{role}_missing_{ext}', role, False, skip=[ext])
    add(f'{role}_wrong_ski',role,False,changes={'ski':(x509.SubjectKeyIdentifier(bytes(20)),False)})
    add(f'{role}_critical_ski',role,False,changes={'ski':(x509.SubjectKeyIdentifier.from_public_key((OLD if role=='root' else DS).public_key()),True)})
    add(f'{role}_unknown_noncritical',role,extra=[(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'), b'\x05\x00'),False)])
    add(f'{role}_unknown_critical',role,False,extra=[(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'), b'\x05\x00'),True)])
    for oid in [33,30,36,54,46]:
        add(f'{role}_forbidden_{oid}',role,False,extra=[(x509.UnrecognizedExtension(ObjectIdentifier(f'2.5.29.{oid}'), b'\x02\x01\x00' if oid==54 else b'\x30\x00'),False)])
add('root_pathlen_one','root',False,changes={'bc':(x509.BasicConstraints(True,1),True)})
add('root_pathlen_absent','root',False,changes={'bc':(x509.BasicConstraints(True,None),True)})
add('root_not_self_issued','root',False,issuer=NEW_DN)
add('ds','ds')
add('ds_457_days','ds',after=START+timedelta(days=457))
add('ds_over_457_days','ds',False,after=START+timedelta(days=457,seconds=1))
add('ds_noncritical_eku','ds',False,changes={'eku':(x509.ExtendedKeyUsage([ObjectIdentifier('1.0.18013.5.1.2')]),False)})
add('ds_wrong_eku','ds',False,changes={'eku':(x509.ExtendedKeyUsage([ObjectIdentifier('1.3.6.1.5.5.7.3.1')]),True)})
add('ds_wrong_ku','ds',False,changes={'ku':(x509.KeyUsage(True,True,False,False,False,False,False,None,None),True)})
add('ds_ca','ds',False,extra=[(x509.BasicConstraints(True,0),False)])
add('ds_national','ds',subject=dn('National DS'))
add('link_renamed','link',san=NEW_DN)
add('link_same_name','link_same')
add('link_no_san','link',False)
add('link_wrong_san','link',False,san=OLD_DN)
add('link_wrong_issuer','link',False,san=NEW_DN,issuer=dn('Different old issuer'))
add('link_wrong_subject','link',False,san=NEW_DN,subject=dn('Different new subject'))
add('link_wrong_key','link',False,san=NEW_DN,key=OTHER)
add('link_over_old_root','link',False,san=NEW_DN,after=END+timedelta(seconds=1))
add('link_wrong_aki','link',False,san=NEW_DN,changes={'aki':(x509.AuthorityKeyIdentifier(bytes(20),None,None),False)})


# Fixture-only TLV construction for signed encoding regressions.
valid = next(row for row in vectors if row[0] == 'ds_national')
original = bytes.fromhex(valid[4])

def item(data, start=0):
    """Return one encoded TLV, its body and end, for known fixture DER."""
    length = data[start + 1]
    header = start + 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[header:header+count], 'big')
        header += count
    end = header + length
    return data[start:end], data[header:end], end

def tlv(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x80 + (size.bit_length() + 7)//8]) + size.to_bytes((size.bit_length() + 7)//8, 'big')
    return bytes([tag]) + length + body

_, content, end = item(original)
assert end == len(original)
tbs, _, next_offset = item(content)
algorithm, _, next_offset = item(content, next_offset)
_, signature_bits, end = item(content, next_offset)
assert end == len(content) and signature_bits[0] == 0
old_key = OLD
old_key.public_key().verify(signature_bits[1:], tbs, ec.ECDSA(hashes.SHA256()))

# The outer certificate value is not covered by the signature. Its actual TBS
# and signature bytes remain untouched, so no re-signing is needed here.
outer_extra = tlv(0x30, content + b'\x05\x00')

# Extension criticality is a DER BOOLEAN outside the opaque extnValue bytes.
# Change true from the required FF to BER true 01 and sign the complete changed
# TBS, ensuring this tests a parser constraint rather than signature tampering.
marker = bytes.fromhex('0603551d0f0101ff')
assert tbs.count(marker) == 1
bad_tbs = tbs.replace(marker, bytes.fromhex('0603551d0f010101'))
bad_signature = old_key.sign(bad_tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
old_key.public_key().verify(bad_signature, bad_tbs, ec.ECDSA(hashes.SHA256()))
ber_true = tlv(0x30, bad_tbs + algorithm + tlv(0x03, b'\x00' + bad_signature))

vectors.extend([
    ['ds_der_outer_extra', 'ds', 'false', valid[3], outer_extra.hex()],
    ['ds_der_critical_ber_true', 'ds', 'false', valid[3], ber_true.hex()],
])

(HERE/'profiles.tsv').write_text('# name kind accepted issuer_public_point certificate_der\n'+'\n'.join('\t'.join(row) for row in vectors)+'\n')
print(f'wrote {len(vectors)} deterministically signed certificates')
