# DynoBox

Pure Rust firmware and OTA toolkit extracted from LTBox.

## What It Does

- unpack dynamic partitions from split `super_*.img`
- apply one or more OTA packages in sequence
- re-sign AVB images with test keys
- repack dynamic partitions back into split `super_*.img`
- scan AVB metadata from one image or a whole directory
- bump boot & vendor security patch level
- modify AVB rollback_index to bypass rollback protection
- toggle any LGSI feature flag at its registration site

## Current Commands

```powershell
dynobox unpack --input <firmware_dir> [--output <dir>]
dynobox apply --input <firmware_dir> [--output <dir>] <ota1.zip> ...
dynobox resign --input <image_dir> [--output <dir>] --key <key> [--force] [--rollback <unix_ts>] [--boot-spl <YYYY-MM-DD>] [--vendor-spl <YYYY-MM-DD>] [--fuck-lgsi [<JSON_PATH>]]
dynobox repack --input <image_dir> [--output <dir>]
dynobox info --input <image_or_dir> [--format text|json] [--output <report.txt>]
dynobox verify --input <image_or_dir> [--format text|json] [--output <report.txt>]
```

Pipeline stage keywords (`unpack`, `resign`, `repack`) can be written as bare words or with `--` prefix. Both forms work.

### GUI

```powershell
dynobox-gui                  # double-click or run with no args -> opens GUI
dynobox-gui apply --input ...  resign --key testkey_rsa4096 ...  # any args -> CLI passthrough
```

`dynobox-gui` (`crates/dyno-gui`) is a **dual-mode** binary: launched
without arguments it opens a minimal egui front-end (mode dropdown,
folder/file pickers, OTA zip list, resign-options panel that
auto-greys when resign isn't selected, scrollable log pane on the
right). Launched **with** any arguments it transparently forwards to
the sibling `dynobox` CLI and exits with that process's status code,
so the same shipped binary covers both flows.

On Windows the GUI subsystem flag suppresses the console window for
double-click launches; when invoked from a terminal the CLI
passthrough first attaches to the parent console so child stdout /
stderr lands in your shell as usual.

The GUI passes `--fuck-lgsi <json>` only — interactive pause-on-Enter still requires a real terminal, so use the CLI path when you need to hand-edit `lgsi_features.json` for the first time.

### Pipeline Example

```powershell
dynobox apply `
    --input TB322_ZUXOS_1.5.10.063_Tool\image `
    063to117.zip 117to183.zip `
    resign --key testkey_rsa4096 `
    repack `
    --output TB322_ZUXOS_1.5.10.183_Resigned `
    --complete
```

### Pipeline Behavior

- Stage order is always: **unpack → apply → resign → repack**
- When the input directory has super chunks but no standalone dynamic partition files, `apply`, `resign`, and `repack` auto-unpack super before proceeding.
- After repack, standalone dynamic partition images (system.img, vendor.img, etc.) are removed from the final output since they are packed inside the new super chunks.
- `--complete` copies all remaining input files to the output so it mirrors the original firmware structure.
- Intermediate stage folders are temporary and auto-cleaned. Final output directory follows last stage unless `--output` is set.
- `apply` runs a preflight scan before patching and a postflight verification pass after output is written.
- All pipeline commands support `--progress-format text|jsonl` for machine-readable progress.
- `verify` runs same verification engine directly and exits non-zero when failures are found.

## Workspace Layout

```text
crates/
  dyno-app/      app-layer orchestration and progress events
  dyno-cli/      CLI adapter
  dyno-core/     shared core types
  dyno-super/    super parsing and repack
  dyno-payload/  OTA payload parsing and patch apply
  dyno-xml/      rawprogram XML parsing
```

## Build

```powershell
cargo fmt
cargo build -p dynobox-cli
cargo test --workspace
```

## Current Limits

- standalone `ZUCCHINI` OTA ops not implemented
- Puffin inner `ZUCCHINI` not implemented
- `LZ4DIFF_PUFFDIFF` not implemented
