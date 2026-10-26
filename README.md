# exhume_artefacts

The `exhume_artefacts` documentation is maintained at [forensicxlab.com](https://www.forensicxlab.com/docs/exhume_artefacts/getting-started).

The `parse_from_fs` example accepts `--password-file PATH` or `--password-stdin`
for encrypted image containers supported by `exhume_body`, or prompts without
echoing in a terminal. It opens the container before locating and parsing the
selected filesystem file.

## 0.3.4

- Update `exhume_filesystem` to `0.5.6` for its bounded APFS/exFAT range readers
  and public verified-file handle API.
- Restrict the published package to source code, examples, and release metadata.
