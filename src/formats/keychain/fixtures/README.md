# Synthetic file-based macOS Keychain

`synthetic.keychain-db` was created in an isolated ARM64 macOS 26.6.2 (25G83)
UTM lab on 2026-11-18 using Apple's `/usr/bin/security`. It contains two invented
generic-password records and their generated wrapping keys, with no real Signal
or user credentials. Each value was read back with Apple's CLI and compared to
the expected value before the fixture was locked and exported.

- Password (exact bytes): `exhume synthetic fixture password`
- Service: `Exhume Keychain Fixture`
- Account `fixture-alpha`: `SYNTHETIC-ALPHA-SECRET`
- Account `fixture-beta`: `SYNTHETIC-BETA-SECRET`
- Size: 23,496 bytes
- SHA-256: `ff504cabb9b81fbe19562ea453f679bc9d5bdf81f45c2441bdc6d4ca5d5685b6`

The file version is `0x10000`; the database and key blobs use `0x100` and Apple's
historical staged HMAC, despite being created on a current macOS release.
Tests construct the standard-HMAC variants separately. Random keys, IVs, ACLs
and timestamps mean regenerated files will have different bytes and offsets.
`tools/fixtures/generate_keychain_fixture.py` reproduces the native creation/verification
procedure in a new directory without retaining changes to the Keychain search
list or default Keychain.

`synthetic-internet.keychain-db` is a second, separate native fixture with one
invented internet password (`fixture-internet`, `fixture.invalid`, protocol
`htps`, port 443, path `/exhume-fixture`, value `SYNTHETIC-INTERNET-SECRET`). It
uses the same public Keychain password and was verified/read back and exported
using the same procedure. It tests metadata compatibility, including four-byte
protocol codes and integer ports; internet-password secret recovery is outside
the current public recovery API. The generator also creates this second file.

- Size: 22,124 bytes
- SHA-256: `b9698b2e6a5cf7b06cf4419feed531c878e996c572b68840cbd852b80fd6df9c`

`synthetic-partition.keychain-db` is a third native fixture, created with the
same public password, service `Exhume Partition Fixture`, account
`fixture-partition`, and value `SYNTHETIC-PARTITION-SECRET`. Its creation path
contains `/Library/Keychains/`, which selects blob version `0x200` in Apple's
implementation. Native readback and offline recovery both verify the value.
It exercises standard blob HMACs with a native fixture rather than a converted
version field. This fixture still uses direct password protection.

- Size: 22,388 bytes
- SHA-256: `e06fb192d0a15de49724a13fc3d6aefc424ea192c1194596579da132be55dc60`

`fixtures.rs` also contains an independently generated, synthetic indirect-login
variant: Python `hashlib`/`hmac` and PyCryptodome re-encrypt only this native
fixture's 168-byte database blob using the indirect password. The public entropy
is bytes `0..31`, and the invented session password is
`SYNTHETIC-LOGIN-PASSWORD` followed by one newline. The wrapping keys and item
payload remain the native fixture's originals. A second independent AES-CBC
vector wraps a public SQLCipher test key using the recovered synthetic password.
These vectors exercise the entire library chain, wrong inputs and cancellation;
they contain no acquired user secrets. The real SystemKeys file stays outside
the repository in the private lab evidence/analysis folders.

The implementation follows these Apple Security sources, pinned to
`db15acbe6a7f257a859ad9a3bb86097bfe0679d9`:

- `OSX/libsecurity_filedb/lib/AppleDatabase.cpp`, `MetaRecord.h`, `MetaAttribute.cpp`
- `OSX/libsecurityd/lib/ssblob.h`
- `securityd/src/dbcrypto.cpp`
- `securityd/src/transition.cpp` (SystemKeys lookup and indirect-password HMAC)
- `OSX/libsecurity_apple_cspdl/lib/SSDatabase.cpp` (login-Keychain unlock route)
- `OSX/libsecurity_cryptkit/lib/HmacSha1Legacy.c`
- `OSX/libsecurity_apple_csp/lib/wrapKeyCms.cpp`
- `OSX/libsecurity_cdsa_client/lib/securestorage.cpp`

An independent Python prototype using `hashlib`/PyCryptodome also verified both
full blob MACs and recovered both expected values. Production code has no Python
or native Keychain dependency. Individual `ssgp` payloads have no MAC: tests
explicitly demonstrate IV tampering that changes plaintext while keeping valid
padding and valid database/key signatures. Application-level validation remains
necessary.
