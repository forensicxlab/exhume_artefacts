# exhume_artefacts

Digital forensics artefact parser library and CLI for Exhume.

The crate exposes a parser trait, parser registry, reusable parser input types,
and a command-line binary that runs one named parser against a standalone file
and emits JSON Lines on stdout.

## Install

```bash
cargo add exhume_artefacts
cargo install exhume_artefacts
```

From the Exhume workspace, run the binary with:

```bash
cargo run -p exhume_artefacts -- --list-parsers
```

## CLI usage

List the parsers compiled into the binary:

```bash
exhume_artefacts --list-parsers
```

Parse a standalone file:

```bash
exhume_artefacts --file /path/to/input --parser windows_evtx
```

Set a log level (`error`, `warn`, `info`, `debug`, or `trace`):

```bash
exhume_artefacts --log-level debug --file /path/to/input --parser windows_pe
```

The CLI prints each parsed object's JSON payload as one JSONL record and writes
the final object count to stderr.

## Parser registry

Use `--list-parsers` to verify the registry for the exact build. Version `0.3.0`
includes:

| Parser | Purpose |
| --- | --- |
| `mobile_ios_calendar` | Parse Apple Calendar event records, locations, timestamps, and attendees. |
| `mobile_ios_callhistory` | Parse cellular, FaceTime, and third-party CallKit call records. |
| `mobile_ios_contacts` | Parse address book contact records and multi-value phone, email, and address data. |
| `mobile_ios_datausage` | Parse per-process cellular and Wi-Fi network usage. |
| `mobile_ios_imessage` | Parse iOS `sms.db` chats, SMS/iMessage messages, and attachment references. |
| `mobile_ios_interactionc` | Parse CoreDuet communication interaction records. |
| `mobile_ios_knowledgec` | Parse CoreDuet behavioral events such as app usage, web usage, lock state, backlight, and notifications. |
| `mobile_ios_mail` | Parse Apple Mail `Envelope Index`, with optional `Protected Index` companion data. |
| `mobile_ios_notes` | Parse Apple Notes `NoteStore.sqlite` note metadata. |
| `mobile_ios_photos` | Parse Photos `ZASSET` inventory, including filenames, capture dates, GPS, and flags. |
| `mobile_ios_routined` | Parse routined significant-location cache GPS fixes. |
| `mobile_ios_safari` | Parse Safari `History.db` sites and visits. |
| `mobile_ios_tcc` | Parse TCC privacy permission decisions. |
| `mobile_ios_whatsapp` | Parse WhatsApp for iOS `ChatStorage.sqlite` chats, messages, and media references. |
| `windows_evtx` | Parse Windows EVTX records. |
| `windows_pe` | Extract Windows PE metadata for malware analysis. |
| `windows_pml` | Parse Windows ProcMon PML v9 events. |

## Library usage

```rust
use exhume_artefacts::parsers::build_registry;
use exhume_artefacts::{run_parser_by_name, ObjectParsed, ParserInput};

fn parse_file(path: &str) -> anyhow::Result<()> {
    let registry = build_registry();
    let mut sink = |obj: ObjectParsed| {
        println!("{}", obj.json);
        Ok(())
    };

    run_parser_by_name(
        &registry,
        "windows_evtx",
        ParserInput::Path(path.into()),
        &mut sink,
    )
}
```

Parsers can receive input from a path, in-memory bytes, a `Read + Seek` source,
or a compound input with companion files. Compound input is primarily used by
`exhume_indexer` when a parser declares `CompanionSpec` entries for sidecar
files such as SQLite WAL/SHM databases or sibling metadata stores.

Parsers that expose timestamps can also produce normalized `TimelineEvent`
entries for consumers that build a supertimeline.

## Examples

Two example binaries are included for development and integration testing.

Parse a regular file path with positional arguments:

```bash
cargo run -p exhume_artefacts --example parse_file -- \
  /path/to/Security.evtx windows_evtx
```

Parse a file inside a filesystem image by record ID:

```bash
cargo run -p exhume_artefacts --example parse_from_fs -- \
  --body /path/to/disk.img \
  --format auto \
  --offset 0x100000 \
  --size 0x100000 \
  --record 42 \
  --parser windows_evtx
```

Notes for `parse_from_fs`:

- `--offset` is the filesystem start in bytes.
- `--size` is the filesystem size in sectors.
- `--record` is the file record identifier in the detected filesystem.
- Output is JSONL on stdout.

## License

GPL-2.0-or-later.
