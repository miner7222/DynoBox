# DynoBox

Pure Rust firmware and OTA toolkit extracted from LTBox.

## What It Does

- unpack dynamic partitions from split `super_*.img`
- apply one or more OTA packages in sequence
- re-sign AVB images with test keys
- repack dynamic partitions back into split `super_*.img`
- scan AVB metadata from one image or a whole directory
- bump boot, vendor & system security patch level
- modify AVB rollback_index to bypass rollback protection
- toggle any LGSI feature flag at its registration site

## Current Commands

```powershell
dynobox unpack --input <firmware_dir> [--output <dir>]
dynobox apply --input <firmware_dir> [--output <dir>] <ota1.zip> ...
dynobox resign --input <image_dir> [--output <dir>] --key <key> [--force] [--rollback <unix_ts>] [--boot-spl <YYYY-MM-DD>] [--vendor-spl <YYYY-MM-DD>] [--system-spl <YYYY-MM-DD>] [--fuck-lgsi [<JSON_PATH>]]
dynobox repack --input <image_dir> [--output <dir>]
dynobox info --input <image_or_dir> [--format text|json] [--output <report.txt>]
dynobox verify --input <image_or_dir> [--format text|json] [--output <report.txt>]
```

Pipeline stage keywords (`unpack`, `resign`, `repack`) can be written as bare words or with `--` prefix. Both forms work.

### GUI mode

The shipped `dynobox` binary is **dual-mode**. Run it with any
arguments and it behaves exactly like the CLI documented above. Run
it with no arguments (e.g. double-click `dynobox.exe`) and it opens a
minimal egui front-end instead — mode dropdown, folder / file
pickers, OTA-zip list with drag-and-drop reordering, resign-options
panel that auto-greys when resign isn't selected, and a "Run in
terminal" button that spawns the same binary in a fresh OS terminal
window.

The crate is `crates/dyno-gui` and builds as `dynobox-gui[.exe]`
locally; CI / release rename the artifact to `dynobox[.exe]` so a
single binary covers both flows.

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
  dyno-cli/      CLI parsing + pipeline driver (lib + thin bin wrapper)
  dyno-core/     shared core types
  dyno-gui/      egui front-end; ships as the `dynobox` release binary
  dyno-super/    super parsing and repack
  dyno-payload/  OTA payload parsing and patch apply
  dyno-xml/      rawprogram XML parsing
```

## Build

```powershell
cargo fmt
cargo build -p dynobox-gui   # dual-mode binary; release artifact gets renamed to `dynobox[.exe]`
cargo test --workspace
```

## Current Limits

- standalone `ZUCCHINI` OTA ops not implemented
- Puffin inner `ZUCCHINI` not implemented
- `LZ4DIFF_PUFFDIFF` not implemented
