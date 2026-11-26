"""Generate invented KWallet 0.1 vectors independently with PyCryptodome.

Reuses the invented Signal password/Safe Storage values from the Linux vectors.
QDataStream lengths count bytes; QString contents are big-endian UTF-16.
Nothing is read from a native wallet or acquired evidence.
"""
import hashlib
import argparse
import json
from pathlib import Path
import struct
import subprocess

from Cryptodome.Cipher import Blowfish

root = Path(__file__).resolve().parents[2]
values = json.loads((root / "src/recovery/fixtures/signal-linux.json").read_text())
destination = root / "src/formats/kwallet/fixtures"
destination.mkdir(parents=True, exist_ok=True)
salt = bytes(range(56))
key = hashlib.pbkdf2_hmac("sha512", values["password"].encode(), salt, 50000, 56)
parser = argparse.ArgumentParser()
parser.add_argument("--native-checker", type=Path, help="Optional compiled upstream SHA1 verifier; receives payload plus checksum on stdin")
args = parser.parse_args()


def wallet_checksum(payload):
    # KDE's forced Q_BIG_ENDIAN macro retains native little-endian message
    # words and digest output on ARM64/x86. The padding bit count remains BE.
    data = payload + b"\x80"
    # Native SHA1::hash() adds an extra block for a 55-byte remainder.
    extra = 64 if len(payload) % 64 == 55 else 0
    data += bytes((56 - len(data)) % 64 + extra) + struct.pack(">Q", len(payload) * 8)
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    mask = 0xffffffff
    def rol(n, bits):
        return ((n << bits) | (n >> (32 - bits))) & mask
    for start in range(0, len(data), 64):
        words = list(struct.unpack("<16I", data[start:start + 64]))
        for i in range(16, 80):
            words.append(rol(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1))
        a, b, c, d, e = state
        for i, word in enumerate(words):
            if i < 20:
                f, k = (b & c) | ((~b) & d), 0x5a827999
            elif i < 40:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif i < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8f1bbcdc
            else:
                f, k = b ^ c ^ d, 0xca62c1d6
            a, b, c, d, e = (rol(a, 5) + f + e + k + word) & mask, a, rol(b, 30), c, d
        state = [(x + y) & mask for x, y in zip(state, (a, b, c, d, e))]
    result = struct.pack("<5I", *state)
    if args.native_checker:
        subprocess.run([str(args.native_checker)], input=payload + result, check=True)
    return result


def u32(value):
    return struct.pack(">I", value)


def data(value):
    return u32(len(value)) + value


def text(value):
    return data(value.encode("utf-16-be"))


def wallet(folders):
    outer = b"KWALLET\n\r\0\r\n" + bytes([0, 1, 3, 2]) + u32(len(folders))
    payload = b""
    for folder, entries in folders:
        outer += hashlib.md5(folder.encode()).digest() + u32(len(entries))
        payload += text(folder) + u32(len(entries))
        for name, kind, value in entries:
            outer += hashlib.md5(name.encode()).digest()
            payload += text(name) + u32(kind) + data(value)
    # Native writer always adds 1..8 random padding bytes, even when aligned.
    padding = 8 - ((len(payload) + 32) % 8)
    plaintext = bytes(range(8)) + u32(len(payload)) + payload
    plaintext += b"\xa5" * padding + wallet_checksum(payload)
    return outer + Blowfish.new(key, Blowfish.MODE_CBC, bytes(8)).encrypt(plaintext)


folders = [
    ("Chromium Keys", [
        ("Chromium Safe Storage", 1, text(values["safe_storage"])),
        ("An unrelated stream", 2, b"SYNTHETIC-STREAM-SECRET"),
    ]),
    ("Empty folder", []),
    ("Unicode \U0001f5dd\ufe0f", [("Non-ASCII \u00e9", 1, text("SYNTHETIC-UNICODE-SECRET\n"))]),
]
(destination / "synthetic-signal.kwl").write_bytes(wallet(folders))
(destination / "synthetic-empty.kwl").write_bytes(wallet([]))
(destination / "synthetic-signal.salt").write_bytes(salt)
vectors = []
for size in (0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 129, 1000):
    payload = bytes(i % 256 for i in range(size))
    vectors.append({"length": size, "checksum": wallet_checksum(payload).hex()})
(destination / "checksum-vectors.json").write_text(json.dumps(vectors, indent=2) + "\n")

