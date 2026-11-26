"""Generate invented Linux recovery vectors with PyCryptodome and SQLCipher.

GNOME's untouched upstream fixture independently verifies the binary decoder.
These additional collections exercise Signal selectors and ambiguous matches.
Pass --sqlcipher-library to regenerate the two tiny database fixtures as well.
No acquired data or native credential service is used.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

root = Path(__file__).resolve().parents[2]
destination = root / "src/recovery/fixtures"
gnome = root / "src/formats/gnome_keyring/fixtures"
key = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
password = b"SYNTHETIC-GNOME-PASSWORD\n"
storage = b"SYNTHETIC+Safe/Storage==\n"


def u32(value):
    return struct.pack(">I", value)


def text(value):
    if value is None:
        return u32(0xffffffff)
    value = value.encode() if isinstance(value, str) else value
    return u32(len(value)) + value


def attributes(values, hashed=False):
    result = u32(len(values))
    for name, value in values.items():
        encoded = hashlib.md5(value.encode()).hexdigest() if hashed else value
        result += text(name) + u32(0) + text(encoded)
    return result


def collection(ambiguous=False):
    salt = bytes(range(8))
    rounds = 2000
    outer = b"GnomeKeyring\n\r\0\n" + bytes(4) + text("Synthetic Linux Keyring")
    outer += struct.pack(">QQ", 1700000001, 1700000000)
    outer += u32(0) + u32(0) + u32(rounds) + salt + bytes(16) + u32(2)
    body = b""
    for identifier in (1, 2):
        fields = {"application": "signal" if identifier == 1 or ambiguous else "different-app", "xdg:schema": "chrome_libsecret_os_crypt_password_v2"}
        outer += u32(identifier) + u32(0) + attributes(fields, hashed=True)
        body += text("Signal Safe Storage") + text(storage if identifier == 1 else b"unrelated secret")
        body += struct.pack(">QQ", 1700000000, 1700000001) + text(None) + bytes(16)
        body += attributes(fields) + u32(0)
    body += bytes((-len(body)) % 16)
    plaintext = hashlib.md5(body).digest() + body
    derived = hashlib.sha256(password + salt).digest()
    for _ in range(rounds - 1):
        derived = hashlib.sha256(derived).digest()
    encrypted = AES.new(derived[:16], AES.MODE_CBC, derived[16:]).encrypt(plaintext)
    return outer + u32(len(encrypted)) + encrypted


def envelope(prefix, secret):
    derived = hashlib.pbkdf2_hmac("sha1", secret, b"saltysalt", 1, 16)
    return prefix + AES.new(derived, AES.MODE_CBC, b" " * 16).encrypt(pad(key, 16))


values = {
    "database_key": key.decode(),
    "password": password.decode(),
    "safe_storage": storage.decode(),
    "v10_config": {"encryptedKey": envelope(b"v10", b"peanuts").hex()},
    "v11_config": {"encryptedKey": envelope(b"v11", storage).hex(), "safeStorageBackend": "gnome_libsecret"},
    "legacy_config": {"key": key.decode()},
}
(gnome / "synthetic-signal.keyring").write_bytes(collection())
(gnome / "synthetic-ambiguous.keyring").write_bytes(collection(ambiguous=True))
(destination / "signal-linux.json").write_text(json.dumps(values, indent=2) + "\n")

parser = argparse.ArgumentParser()
parser.add_argument("--sqlcipher-library", type=Path)
args = parser.parse_args()
if args.sqlcipher_library:
    library = ctypes.CDLL(str(args.sqlcipher_library))
    database = ctypes.c_void_p()
    library.sqlite3_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    library.sqlite3_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    library.sqlite3_exec.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    library.sqlite3_close.argtypes = [ctypes.c_void_p]
    schema = (root / "tests/fixtures/signal_keychain_recovery.sql").read_text()
    encrypted = destination / "signal-linux-encrypted.sqlite"
    plaintext = destination / "signal-linux-plaintext.sqlite"
    for path in (encrypted, plaintext):
        path.unlink(missing_ok=True)
    assert library.sqlite3_open(str(encrypted).encode(), ctypes.byref(database)) == 0
    try:
        raw = b"x'" + key + b"'"
        assert library.sqlite3_key(database, raw, len(raw)) == 0
        assert library.sqlite3_exec(database, ("PRAGMA cipher_compatibility=4;" + schema).encode(), None, None, None) == 0
    finally:
        assert library.sqlite3_close(database) == 0
    with sqlite3.connect(plaintext) as connection:
        connection.executescript(schema)
    assert not encrypted.read_bytes().startswith(b"SQLite format 3")
    assert plaintext.read_bytes().startswith(b"SQLite format 3")
print("Generated invented GNOME Keyrings and Linux Signal envelopes.")
