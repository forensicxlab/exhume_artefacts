# Fixture maintenance

Rust tests consume committed synthetic or attributed upstream data and need no Python,
Node, desktop key service or lab image. Unit tests cover format invariants; integration
tests cover public contracts, command-line behavior and independently generated vectors.
The large private Signal parser tests live alongside `desktop.rs` in `desktop/tests.rs`.

One entry point checks all committed fixture hashes and optional indexer copies:

```sh
python3 tools/fixtures/fixtures.py check --indexer ../exhume_indexer
```

Replay the independent reference implementations in a temporary directory, without
changing the checkout:

```sh
python3 -m venv /tmp/exhume-fixture-tools
/tmp/exhume-fixture-tools/bin/pip install -r tools/fixtures/requirements.lock
/tmp/exhume-fixture-tools/bin/python tools/fixtures/fixtures.py verify --indexer ../exhume_indexer
```

Use Python 3.9 or newer and Node.js 22 or newer. Python's direct reference dependencies
are declared in `requirements.txt`; the complete verified environment is pinned in `requirements.lock`; Node uses only its bundled OpenSSL/zlib modules.
The manifest pins committed inputs by SHA-256. A changed compression/SQLite version can
change bytes: inspect the resulting vector and its reference checks before accepting it.
`regenerate` performs the same staged run, then updates deterministic outputs and hashes;
with `--indexer` it also synchronizes the independent indexer fixture package.

The DPAPI generator checks both master keys and blobs with Impacket, independently of
Rust. The GNOME and KWallet generators use PyCryptodome; KWallet retains its optional
compiled upstream SHA1 verifier. The attachment generator uses Node/OpenSSL, and the small
attachment database uses Python's SQLite writer. These tools are valuable reference tests,
not application runtime dependencies. No generator reads acquired user data.

Native macOS Keychain files, the public upstream GNOME fixture and encrypted SQLCipher
fixtures are preserved seed inputs, not byte-deterministic outputs. `verify` checks their
committed hashes but does not recreate them. `generate_keychain_fixture.py` is a separate,
explicit native experiment: it temporarily changes the user's Keychain search list and
restores it in `finally`. Run it only in an isolated lab account, with its explicit output
argument, never as part of CI. SQLCipher fixture regeneration is optional via
`generate_signal_linux_vectors.py --sqlcipher-library ...`; encryption uses fresh salt.
Seed provenance, invented passwords and limitations are in each fixture directory's README.
