"""Regenerate synthetic vectors with pycryptodomex==3.24.2 and impacket==0.13.1."""
from pathlib import Path
import struct, uuid, hashlib, hmac, subprocess
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from impacket.dpapi import MasterKeyFile, MasterKey, DPAPI_BLOB

password = 'fixture password ☃'
sid = 'S-1-5-21-123-456-789-1001'
guid = '00112233-4455-6677-8899-aabbccddeeff'
key = bytes(range(1,65))
prekey = hmac.digest(hashlib.sha1(password.encode('utf-16le')).digest(), (sid+'\0').encode('utf-16le'), 'sha1')
salt = bytes(range(16))
mac_salt = bytes(range(16,32))
material = hmac.digest(prekey, salt+struct.pack('>I',1), 'sha512')
for _ in range(3):
    material = bytes(a^b for a,b in zip(material,hmac.digest(prekey,material,'sha512')))
stored_mac = hmac.digest(hmac.digest(prekey,mac_salt,'sha512'),key,'sha512')
ciphertext = AES.new(material[:32],AES.MODE_CBC,material[32:48]).encrypt(mac_salt+stored_mac+key)
block = struct.pack('<I',2)+salt+struct.pack('<III',4,0x800e,0x6610)+ciphertext
header = struct.pack('<III',2,0,0)+guid.encode('utf-16le')+struct.pack('<IIIQQQQ',0,0,0,len(block),0,0,0)
master_file = header+block
assert len(header)==128
assert MasterKey(block).decrypt(prekey)==key

def sized(value): return struct.pack('<I',len(value))+value
def blob(plaintext,entropy=b'',legacy=False):
    salt = bytes(range(32))
    mac_salt = bytes(range(32,64))
    hashed = hashlib.sha1(key).digest()
    session = hmac.digest(hashed,salt+entropy,'sha512')
    ciphertext = AES.new(session[:32],AES.MODE_CBC,bytes(16)).encrypt(pad(plaintext,16))
    provider = uuid.UUID('df9d8cd0-1501-11d1-8c7a-00c04fc297eb').bytes_le
    signed = struct.pack('<I',1)+uuid.UUID(guid).bytes_le+struct.pack('<I',0)+sized('Synthetic\0'.encode('utf-16le'))
    signed += struct.pack('<II',0x6610,256)+sized(salt)+sized(b'')+struct.pack('<II',0x800e,512)+sized(mac_salt)+sized(ciphertext)
    if legacy:
        padded = hashed+bytes(128-len(hashed))
        inner = hashlib.sha512(bytes(x^0x36 for x in padded)+mac_salt).digest()
        signature = hashlib.sha512(bytes(x^0x5c for x in padded)+inner+entropy+signed).digest()
    else:
        signature = hmac.digest(hashed,mac_salt+entropy+signed,'sha512')
    result=struct.pack('<I',1)+provider+signed+sized(signature)
    assert DPAPI_BLOB(result).decrypt(key,entropy=entropy)==plaintext
    return result

payload=b'synthetic authenticated payload'
values={
    'MASTER_FILE':master_file,
    'BLOB':blob(payload),
    'BLOB_ENTROPY':blob(payload,b'context'),
    'BLOB_LEGACY_SIGNATURE':blob(payload,legacy=True),
}
destination=Path(__file__).resolve().parents[1]/'src/formats/dpapi/fixtures.rs'
text='//! Synthetic, deterministic vectors generated with PyCryptodome and checked\n//! with Impacket 0.13.1. Contains no acquired user data.\n'
text+='pub(crate) const PASSWORD: &str = "fixture password ☃";\n'
text+='pub(crate) const SID: &str = "'+sid+'";\n'
text+='pub(crate) const GUID: &str = "'+guid+'";\n'
for name,value in values.items():
    text+='pub(crate) const '+name+': &str = "'+value.hex()+'";\n'
destination.write_text(text)
subprocess.run(['rustfmt', '--edition', '2024', str(destination)], check=True)
print('Generated four synthetic interoperability vectors; reference authentication passed.')
