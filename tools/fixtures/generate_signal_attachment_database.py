"""Build the small CLI database fixture with Python's independent SQLite writer.

Run generate_signal_attachment_vectors.mjs first. All data and keys are synthetic.
"""
import json
import sqlite3
from pathlib import Path

root = Path(__file__).resolve().parents[2] / "tests/fixtures"
vector = json.loads((root / "signal-attachment.json").read_text())
path = root / "signal-attachments.sqlite"
path.unlink(missing_ok=True)
with sqlite3.connect(path) as db:
    db.executescript("""
        PRAGMA page_size=4096;
        CREATE TABLE items(id TEXT PRIMARY KEY,json TEXT);
        CREATE TABLE conversations(id TEXT PRIMARY KEY,json TEXT,type TEXT,serviceId TEXT);
        CREATE TABLE messages(id TEXT,type TEXT,conversationId TEXT,json TEXT,body TEXT,sent_at INTEGER);
        INSERT INTO conversations VALUES('peer','{"profileName":"Synthetic peer"}','private','bbbbbbbb-0000-4000-8000-000000000002');
        INSERT INTO messages VALUES('text','incoming','peer','{}','Synthetic retained message',1700000000000);
    """)
    db.execute("INSERT INTO messages VALUES(?,?,?,?,?,?)", (
        "image", "incoming", "peer", json.dumps({"attachments": [{
            "contentType": "image/png", "fileName": "../untrusted-name.png", "path": "ab/photo",
            "version": 2, "localKey": vector["key"], "size": vector["size"],
            "plaintextHash": vector["plaintext_sha256"],
        }]}), None, 1700000001000,
    ))
