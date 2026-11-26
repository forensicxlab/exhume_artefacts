These small KWallet 0.1 files contain invented data only. Generate them with
`tools/fixtures/generate_kwallet_vectors.py` using PyCryptodome. The generator independently
implements KDE's big-endian QDataStream framing, PBKDF2-SHA512, Blowfish-CBC and
KDE's little-endian SHA-1 variant. It reuses the invented password and Safe Storage value in
`src/recovery/fixtures/signal-linux.json`; no acquired credentials are included.

`synthetic-signal.kwl` includes password, stream, empty-folder and Unicode cases.
`synthetic-empty.kwl` uses the same salt and password with no folders. Both use
`synthetic-signal.salt`. These are independent synthetic vectors, not native KDE
fixtures; acquired KDE validation is documented separately without committing
private lab data.

`checksum-vectors.json` covers block/padding boundaries, including KDE's extra
padding block at a 55-byte remainder. Each checksum and both wallet payloads were
independently checked with the unmodified `SHA1` implementation compiled from
KDE/kwallet v6.13.0 on ARM64 macOS. Pass `--native-checker` to the generator with
a program that reads payload followed by its 20-byte expected checksum and exits
successfully only when KDE's implementation verifies it. No acquired bytes are
included in these vectors.

