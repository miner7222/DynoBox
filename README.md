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
dynobox unpack --input <firmware_dir> [--output <dir>] [--resign -k <key>] [--repack]
dynobox apply --input <firmware_dir> [--output <dir>] [--unpack] [--resign -k <key>] [--repack] <ota1.zip> <ota2.zip> ...
dynobox resign --input <image_dir> [--output <dir>] --key <key> [--force] [--repack]
dynobox repack --input <image_dir> [--output <dir>]
dynobox info --input <image_or_dir> [--format text|json] [--output <report.txt>]
dynobox verify --input <image_or_dir> [--format text|json] [--output <report.txt>]
```

Pipeline chaining works.

- `apply --resign`
- `apply --repack`
- `apply --resign --repack`
- `apply --unpack --resign --repack`
- `unpack --resign --repack`
- `resign --repack`

Intermediate stage folders are temporary and auto-cleaned. Final output directory follows last stage unless `--output` is set.

`apply` now runs a preflight scan before patching and a postflight verification pass after final output is written.
All pipeline commands also support `--progress-format text|jsonl` for machine-readable progress.
`verify` runs same verification engine directly and exits non-zero when failures are found.

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
