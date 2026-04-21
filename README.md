# DynoBox

Pure Rust firmware and OTA toolkit extracted from LTBox.

## What It Does

- unpack dynamic partitions from split `super_*.img`
- apply one or more OTA packages in sequence
- re-sign AVB images with test keys
- repack dynamic partitions back into split `super_*.img`
- scan AVB metadata from one image or a whole directory

## Current Commands

```powershell
dynobox unpack --input <firmware_dir> [--output <dir>] [resign -k <key>] [--rollback <unix_ts>] [repack] [--complete]
dynobox apply --input <firmware_dir> [--output <dir>] <ota1.zip> ... [resign -k <key>] [--rollback <unix_ts>] [repack] [--complete]
dynobox resign --input <image_dir> [--output <dir>] --key <key> [--force] [--rollback <unix_ts>] [repack]
dynobox repack --input <image_dir> [--output <dir>]
dynobox info --input <image_or_dir> [--format text|json] [--output <report.txt>]
dynobox verify --input <image_or_dir> [--format text|json] [--output <report.txt>]
```

Pipeline stage keywords (`unpack`, `resign`, `repack`) can be written as bare words or with `--` prefix. Both forms work.

### Pipeline Example

```powershell
dynobox apply --input TB322_ZUXOS_1.5.10.063_Tool\image 063to117.zip 117to183.zip resign --key testkey_rsa4096 repack --output TB322_ZUXOS_1.5.10.183_Resigned --complete
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

### Rollback Index Reset

`--rollback <unix_ts>` restricts the resign stage to `boot.img` and `vbmeta_system.img` only, rewrites each image's AVB `rollback_index` to the supplied Unix timestamp, and re-signs with the provided key. The new value must be less than or equal to each target image's current `rollback_index`; a higher value is rejected with an error message and no changes are written. The completion message shows the timestamp in `Thu Feb 26 02:40:50 UTC 2026` form.

```powershell
dynobox resign --input <image_dir> --output <dir> --key testkey_rsa4096 --rollback 1700000000
dynobox apply --input <firmware_dir> <ota.zip> resign --key testkey_rsa4096 --rollback 1700000000 --output <dir>
```

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
