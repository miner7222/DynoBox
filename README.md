# DynoBox

Pure Rust firmware and OTA toolkit extracted from LTBox.

## What It Does

- unpack dynamic partitions from split `super_*.img`
- apply one or more OTA packages in sequence
- re-sign AVB images with test keys
- repack dynamic partitions back into split `super_*.img`
- scan AVB metadata from one image or a whole directory
- seal final outputs with a deterministic per-file SHA-256 manifest
- bump boot, vendor & system security patch level
- modify AVB rollback_index to bypass rollback protection
- toggle any LGSI feature flag at its registration site

## Current Commands

```powershell
dynobox unpack --input <firmware_dir> [--output <dir>] [--integrity-key <private.pem>]
dynobox apply --input <firmware_dir> [--output <dir>] [--integrity-key <private.pem>] <ota1.zip> ...
dynobox resign --input <image_dir> [--output <dir>] --key <key> [--integrity-key <private.pem>] [--force] [--rollback <unix_ts>] [--boot-spl <YYYY-MM-DD>] [--vendor-spl <YYYY-MM-DD>] [--system-spl <YYYY-MM-DD>] [--fuck-lgsi [<JSON_PATH>]]
dynobox repack --input <image_dir> [--output <dir>] [--integrity-key <private.pem>]
dynobox info --input <image_or_dir> [--format text|json] [--output <report.txt>]
dynobox verify --input <image_or_dir> [--trusted-integrity-key <public.pem>] [--format text|json] [--output <report.txt>]
dynobox integrity-keygen --private-key <private.pem> [--public-key <public.pem>]
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
- After final AVB/XML/super verification, every successful output pipeline writes `dynobox-manifest.json` with the size and SHA-256 of every final artifact, including `report.html` when present.
- `--integrity-key` adds a detached `dynobox-manifest.sig` Ed25519 signature. Use a dedicated manifest-signing key rather than the Android AVB key; publish or pin the generated public key separately from the firmware output.
- All pipeline commands support `--progress-format text|jsonl` for machine-readable progress.
- `verify` checks the manifest automatically when present, reports modified/missing/unexpected files separately from firmware semantic checks, and distinguishes unsigned, valid-untrusted, and trusted signatures. Supplying `--trusted-integrity-key` makes an unsigned or differently signed manifest a verification failure. Older outputs without a manifest remain supported and are marked `NOT CHECKED` for artifact integrity.

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
cargo test --workspace --locked
cargo deny check             # advisory / license / source policy (deny.toml)
```

### Install from a release

GitHub Releases (tag `v*`) publish self-contained archives after fmt, clippy
(`-D warnings`), workspace tests, and `cargo deny` all pass. Each archive
includes `README.md`, `LICENSE`, and a matching `.sha256` checksum file:

| Platform | Artifact |
| --- | --- |
| Windows x86_64 / arm64 | `DynoBox-windows_<arch>-vX.Y.Z.zip` → `dynobox.exe` (+ `README.md`, `LICENSE`) |
| Linux x86_64 / arm64 | `DynoBox-linux_<arch>-vX.Y.Z.tar.gz` → `dynobox` (mode preserved; + `README.md`, `LICENSE`) |
| macOS universal | `DynoBox-macos_universal-vX.Y.Z.zip` → `DynoBox.app` (`Contents/MacOS/dynobox`; `README.md` + `LICENSE` in `Contents/Resources/`) |

On macOS, open the app once via right-click → Open (or clear quarantine with
`xattr -dr com.apple.quarantine DynoBox.app`) if Gatekeeper blocks an ad-hoc
signed download. Extract yields a single `DynoBox.app`; docs live inside the
bundle under `Contents/Resources/` so drag-to-Applications stays clean. Local
packaging helper: `misc/macos/make-app.sh`.

## Current Limits

- standalone `ZUCCHINI` OTA ops not implemented
- Puffin inner `ZUCCHINI` not implemented
- `LZ4DIFF_PUFFDIFF` not implemented
