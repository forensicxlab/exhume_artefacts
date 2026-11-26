"""Regenerate public Signal recovery inputs with pycryptodomex and Impacket.

All credentials/keys are invented. No native credential store is opened. The
native synthetic Keychain's unauthenticated selectors are relabelled for Signal;
its native encrypted item and authenticated wrapping records remain unchanged.
"""
from pathlib import Path
import base64
import hashlib
import hmac
import json
import struct
import uuid
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from impacket.dpapi import DPAPI_BLOB

root = Path(__file__).resolve().parents[2]
destination = root / "src/recovery/fixtures"
destination.mkdir(exist_ok=True)
key_text = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
guid = "00112233-4455-6677-8899-aabbccddeeff"
master = bytes(range(1, 65))

def sized(value):
    return struct.pack("<I", len(value)) + value

def dpapi(plaintext):
    salt, mac_salt = bytes(range(32)), bytes(range(32, 64))
    hashed = hashlib.sha1(master).digest()
    session = hmac.digest(hashed, salt, "sha512")
    encrypted = AES.new(session[:32], AES.MODE_CBC, bytes(16)).encrypt(pad(plaintext, 16))
    signed = struct.pack("<I", 1) + uuid.UUID(guid).bytes_le + struct.pack("<I", 0)
    signed += sized("Synthetic\0".encode("utf-16le"))
    signed += struct.pack("<II", 0x6610, 256) + sized(salt) + sized(b"")
    signed += struct.pack("<II", 0x800e, 512) + sized(mac_salt) + sized(encrypted)
    signature = hmac.digest(hashed, mac_salt + signed, "sha512")
    blob = struct.pack("<I", 1) + uuid.UUID("df9d8cd0-1501-11d1-8c7a-00c04fc297eb").bytes_le + signed + sized(signature)
    assert DPAPI_BLOB(blob).decrypt(master) == plaintext
    return blob

storage = bytes(range(32))
nonce = bytes(range(12))
gcm = AES.new(storage, AES.MODE_GCM, nonce=nonce)
cipher, tag = gcm.encrypt_and_digest(key_text)
master_file = (root / "src/formats/dpapi/fixtures/master_file.hex").read_text()
safe_storage = b"SYNTHETIC-PARTITION-SECRET"
mac_key = hashlib.pbkdf2_hmac("sha1", safe_storage, b"saltysalt", 1003, 16)
mac_envelope = b"v10" + AES.new(mac_key, AES.MODE_CBC, b" " * 16).encrypt(pad(key_text, 16))
keychain = bytearray((root / "src/formats/keychain/fixtures/synthetic-partition.keychain-db").read_bytes())
def attribute(record, size, index):
    raw = int.from_bytes(keychain[record+24+index*4:record+28+index*4], "big")
    offset = raw & ~1
    if not raw or offset < 88 or offset + 4 >= size:
        return None
    if not raw & 1:
        if int.from_bytes(keychain[record+offset:record+offset+4], "big") != 1:
            return None
        offset += 4
    length = int.from_bytes(keychain[record+offset:record+offset+4], "big")
    if offset + 4 + length > size:
        return None
    return record + offset + 4, bytes(keychain[record+offset+4:record+offset+4+length])

matches = []
for record in range(0, len(keychain)-88, 4):
    size = int.from_bytes(keychain[record:record+4], "big")
    if not 88 <= size <= len(keychain)-record:
        continue
    service, account = attribute(record, size, 14), attribute(record, size, 13)
    if service and account and service[1] == b"Exhume Partition Fixture" and account[1] == b"fixture-partition":
        matches.append((service, account))
assert len(matches) == 1, "expected one native generic-password fixture record"
for (offset, old), new in zip(matches[0], [b"Signal Safe Storage", b"Signal Key"]):
    assert len(new) <= len(old)
    keychain[offset-4:offset] = len(new).to_bytes(4, "big")
    keychain[offset:offset+len(old)] = new + bytes(len(old)-len(new))
(destination / "signal-macos.keychain-db").write_bytes(keychain)
values = {
    "database_key": key_text.decode(), "windows_password": "fixture password ☃",
    "windows_sid": "S-1-5-21-123-456-789-1001", "master_key_guid": guid,
    "master_key_file": master_file,
    "windows_config": {"encryptedKey": (b"v10" + nonce + cipher + tag).hex()},
    "windows_local_state": {"os_crypt": {"encrypted_key": base64.b64encode(b"DPAPI" + dpapi(storage)).decode()}},
    "windows_direct_config": {"encryptedKey": dpapi(key_text).hex()},
    "macos_config": {"encryptedKey": mac_envelope.hex()},
    "macos_password": "exhume synthetic fixture password",
    "macos_login_password": "SYNTHETIC-LOGIN-PASSWORD\n",
    "protected_entropy": bytes(range(32)).hex(),
    "macos_indirect_blob": (root / "src/formats/keychain/fixtures/indirect-blob.hex").read_text(),
}
(destination / "signal-keys.json").write_text(json.dumps(values, indent=2) + "\n")
print("Generated synthetic Signal envelopes and relabelled Keychain fixture.")
