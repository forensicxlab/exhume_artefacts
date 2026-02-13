# exhume_artefacts

Digital forensics artefacts parser library and parser registry.

## Current parsers

The parser registry currently includes:

- `windows_evtx`: Parse Windows EVTX event log files and emit one JSON object per event record.
- `windows_pe`: Extract detailed metadata from Windows PE files (hashes, headers, sections, imports, exports, resources, etc.).
- `windows_pml`: Parse Windows ProcMon `.pml` files and emit normalized event records.

You can always verify the parsers available in your build with:

```bash
cargo run -p exhume_artefacts --example parse_file -- --list-parsers
```

## Examples

Two example binaries are available:

- `parse_file`: parse a regular file path with a named parser.
- `parse_from_fs`: parse a file inside a filesystem image by record ID.

### 1) Parse a standalone file (`parse_file`)

List parsers:

```bash
cargo run -p exhume_artefacts --example parse_file -- --list-parsers
```

Parse an EVTX file:

```bash
cargo run -p exhume_artefacts --example parse_file -- \
  /path/to/Security.evtx windows_evtx
```

Parse a PE file:

```bash
cargo run -p exhume_artefacts --example parse_file -- \
  /path/to/file.exe windows_pe
```

Parse a ProcMon PML file:

```bash
cargo run -p exhume_artefacts --example parse_file -- \
  /path/to/Logfile.pml windows_pml
```

Set a log level (`error`, `warn`, `info`, `debug`, `trace`):

```bash
cargo run -p exhume_artefacts --example parse_file -- \
  --log-level debug /path/to/file windows_evtx
```

### 2) Parse from a filesystem image (`parse_from_fs`)

List parsers:

```bash
cargo run -p exhume_artefacts --example parse_from_fs -- --list-parsers
```

Parse a file by filesystem record ID:

```bash
cargo run -p exhume_artefacts --example parse_from_fs -- \
  --body /path/to/disk.img \
  --format auto \
  --offset 0x100000 \
  --size 0x100000 \
  --record 42 \
  --parser windows_evtx
```

Notes:

- `--offset` is the filesystem start in bytes.
- `--size` is the filesystem size in sectors.
- `--record` is the file record identifier in the detected filesystem.
- Output is JSONL (one JSON object per line) on stdout.
