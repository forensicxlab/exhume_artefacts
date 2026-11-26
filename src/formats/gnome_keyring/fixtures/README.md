`gnome-48-encrypted.keyring` is an untouched public GNOME Keyring test fixture,
from tag `48.0`, commit `adadbad2fdeb79a654dca37b31349e2a1d527ef0`.
Its password is `my-keyring-password`. Both secret values are `item-secret`.
GNOME's own tests verify its two items, timestamps, string attributes and integer
attribute. The original licence is retained in `COPYING.LIB`.

Sources:

- https://github.com/GNOME/gnome-keyring/blob/48.0/pkcs11/secret-store/fixtures/encrypted.keyring
- https://github.com/GNOME/gnome-keyring/blob/48.0/pkcs11/secret-store/test-secret-binary.c
- https://github.com/GNOME/gnome-keyring/blob/48.0/pkcs11/secret-store/mock-secret-module.c

`synthetic-signal.keyring` and `synthetic-ambiguous.keyring` contain invented
data. Regenerate them, and the Linux Signal vectors, using
`tools/fixtures/generate_signal_linux_vectors.py` with PyCryptodome. The ambiguous
collection deliberately contains two matching application attributes.

The Signal database fixtures in `src/recovery/fixtures/` contain only the
existing synthetic SQL test data. The generator can rebuild them with
`--sqlcipher-library /path/to/libsqlcipher`, using SQLCipher's native C API for
the encrypted copy and Python SQLite for the plaintext copy. Tests consume
committed fixtures and require neither Python nor a running Secret Service.
