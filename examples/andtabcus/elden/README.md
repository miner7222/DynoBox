# ZUXOS ANDTABCUS MOD for Y700 4th Gen

Lenovo Legion Y700 4th Gen was released in China only, so a global firmware
simply does not exist for it. Unlike other models, its firmware also ships with
deliberate manufacturer restrictions that make the tablet awkward to live with
anywhere outside China.

ANDTABCUS MOD is a custom firmware built on that premise: **use outside China**,
without root and without modules. It injects a set of patches that make ZUXOS
comfortable to use as-is, and folds in fixes for a few issues Lenovo has left
unaddressed.

## Features

- Based on ZUXOS 1.5
- ABL replaced and firmware re-signed with `testkey_rsa4096`
- Passes all Play Integrity checks
- Most China-only apps and services removed
- Wi-Fi 6 GHz and all channels unlocked
- Four-app split-screen mode enabled
- Prevents Package Manager from forcibly disabling Google services
- All system languages selectable from Settings
- Circle to Search and Quick Share enabled
- Less aggressive memory management

## Installation

Flash this firmware with LTBox — see the
[LTBox installation guide](https://miner7222.github.io/ltbox/en/install-same-region-firmware.html).

Installing over a build **at or below** the base build version keeps your existing
data; no wipe is needed. Returning to stock firmware *does* require a factory
reset.

## Notes

- The initial setup wizard supports only English and Chinese. Once setup is
  complete, any language can be selected in Settings.
- Lenovo App Store has been removed. Download the Google Play Store APK from
  APKMirror on a PC, then transfer and install it on the tablet.
- Circle to Search requires the Google app to be installed before it can be
  activated.
- Long-pressing the power button launches the assistant only when the Google app
  is installed and selected as the default assistant. The regular power menu can
  be restored in Settings.

## Build Inputs

The two input files used to produce this mod are included here, so the build is
reproducible:

| File | Passed to | Purpose |
| --- | --- | --- |
| [`debloat.txt`](debloat.txt) | `--debloat` | Apps and blobs removed from `system` / `product` |
| [`lgsi_features.json`](lgsi_features.json) | `--fuck-lgsi` | LGSI feature flags toggled at their registration sites |

## Transparency

The `report.html` shipped with each release records the exact DynoBox commands
used to build that firmware. Following those steps reproduces the same mod,
although the older ABL still has to be replaced manually.

Every `.dbp` patch referenced in that report is available in the
[`patches/`](https://github.com/miner7222/DynoBox/tree/main/patches) folder at the
root of this repository.
