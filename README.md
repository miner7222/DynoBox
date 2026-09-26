# DynoBox

[![License: Apache 2.0][license-shield]][license]
[![Rust][rust-shield]][rust]
[![Build][ci-shield]][ci]
[![Latest release][release-shield]][releases]
[![Downloads][downloads-shield]][releases]

DynoBox is a cross-platform toolkit for unpacking, modifying, re-signing, and
repacking Android firmware and OTA packages. It provides both a desktop GUI and
a command-line interface.

DynoBox currently supports only some models with Qualcomm chipsets.

## ⚠️ Disclaimer

**For educational and development purposes only.** Modifying firmware can brick
your device, cause data loss, weaken device security, or void your warranty. The
author assumes **no liability** for any damage or loss. You are solely
responsible for how you use this software.

**Use at your own risk.**

---

## 🚀 Quick Start

![Windows](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white) ![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black) ![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white)

Download and extract the archive for your platform from
**[GitHub Releases][releases]**.

- Run `dynobox` without arguments to open the GUI.
- Run `dynobox --help` to use the CLI.

---

## 📋 What Can It Do?

| Feature | What it does |
|---|---|
| **Firmware pipeline** | Unpack split `super` images, apply sequential OTA packages, and repack the result |
| **AVB** | Inspect, re-sign, and verify AVB images; update rollback indexes and security patch levels |
| **Firmware customization** | Toggle Lenovo LGSI flags, remove selected system files, and apply repeatable `.dbp` patches |
| **Verification** | Validate images, XML, and `super` consistency and generate SHA-256 output manifests |
| **Automation** | Provide JSONL progress output and optional Ed25519-signed manifests for scripted workflows |

DynoBox modifies supported ext4 partition images directly; mounting them is not
required.

---

## 🛠️ Usage

The GUI exposes the common pipeline options and can launch the same operation
in a terminal. For full control, use the CLI directly.

### Apply an OTA and rebuild the firmware

```powershell
.\dynobox.exe apply `
    --input .\firmware\image `
    --output .\output `
    --resign `
    --repack `
    --complete `
    --key testkey_rsa4096 `
    .\update.zip
```

Multiple OTA packages may be listed in installation order. DynoBox
automatically unpacks dynamic partitions when the input contains split
`super_*.img` files.

### Common commands

```text
dynobox unpack             Unpack dynamic partitions from super
dynobox apply              Apply one or more OTA packages
dynobox resign             Re-sign and customize firmware images
dynobox repack             Rebuild split super images
dynobox info               Show AVB metadata
dynobox verify             Verify firmware and output integrity
dynobox integrity-keygen   Generate a manifest-signing keypair
```

Use `dynobox <command> --help` for every option, including `--boot-spl`,
`--vendor-spl`, `--system-spl`, `--fuck-lgsi`, `--debloat`, and `--plus`.

### Output provenance and trusted verification

Output manifests record full-file SHA-256 digests for generated artifacts and
for the original input images, preserving the provenance of a pipeline result.
DynoBox also recognizes manifests signed by its built-in **andtabcus** release
identity; other valid signatures remain untrusted unless their public key is
supplied with `--trusted-integrity-key`.

`dynobox verify --trust-manifest-attestation` can skip the redundant local
AVB/XML/`super` semantic pass when a trusted, valid signature covers a manifest
that records successful semantic verification. This is an explicit performance
tradeoff: use it only when you intend to trust that signer. DynoBox still hashes
every current output artifact in full and never accepts the attestation if the
manifest, signature, or artifact inventory is malformed or tampered with.

### Output directory safety

DynoBox recreates the output directory on every run. It refuses to delete a
filesystem root, your home directory, the current working directory, or an
existing non-empty directory that does not look like a DynoBox output (no
top-level `.img`, rawprogram XML, `report.html`, or manifest).

### Fixture tests

Tests that need real firmware artifacts are `#[ignore]`d, so a plain
`cargo test` lists them as ignored. Export the variable named in each test's
ignore reason (for example `DYNOBOX_FIRMWARE_DIR`) and run
`cargo test -- --ignored`.

---

## 🙏 Credits

- **[limzei89](https://note.com/limzei89/n/n3959e57a5021)**

---

## 📄 License

DynoBox is licensed under the [Apache License 2.0][license].

[license]: https://www.apache.org/licenses/LICENSE-2.0
[license-shield]: https://img.shields.io/badge/License-Apache_2.0-blue.svg
[rust]: https://www.rust-lang.org
[rust-shield]: https://img.shields.io/badge/Rust-2024_edition-000000?logo=rust&logoColor=white
[ci]: https://github.com/miner7222/DynoBox/actions/workflows/ci.yml
[ci-shield]: https://img.shields.io/github/actions/workflow/status/miner7222/DynoBox/ci.yml?branch=main&label=build&logo=github
[releases]: https://github.com/miner7222/DynoBox/releases/latest
[release-shield]: https://img.shields.io/github/v/release/miner7222/DynoBox?logo=github
[downloads-shield]: https://img.shields.io/github/downloads/miner7222/DynoBox/total?logo=github
