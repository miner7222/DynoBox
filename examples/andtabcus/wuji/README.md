# ZUXOS ANDTABCUS MOD for Y700 5G

Lenovo Legion Y700 5G (Wuji) was released only in China, so no global firmware
exists for it. Its firmware also carries intentional regional restrictions
that make it awkward to use anywhere outside China.

ANDTABCUS MOD is a custom firmware for one purpose: **comfortable use outside
China**, with no root and no modules. It patches ZUXOS to work well as-is,
plus fixes for a few issues Lenovo has left unaddressed.

## Features

- Based on ZUXOS 2.0
- ABL downgraded to allow GBL loading
- Re-signed with `testkey_rsa4096` (requires the _arb EFI from gbl_root_baldur)
- Most China-only apps and services removed
- Needless telemetry and logging removed
- All system languages selectable from Settings
- Stops Package Manager from disabling Google services
- Wi-Fi 6 GHz and all channels unlocked
- Four-app split-screen enabled
- Circle to Search and Quick Share enabled
- Less aggressive memory management
- Dolby Atmos stays off in speaker mode once disabled
- Fixed LeAudio pairing failures

## Installation

Flash this firmware with LTBox — see the
[LTBox installation guide](https://miner7222.github.io/ltbox/en/install-same-region-firmware.html).

Flashing over the base build or older keeps your data — no wipe needed.
Returning to stock *does* require a factory reset.

## Notes

- The setup wizard supports only English and Chinese. After setup, any
  language can be selected in Settings.
- Lenovo App Store is gone. Sideload the [Google Play Store](https://www.apkmirror.com/apk/google-inc/google-play-store/) APK from
  APKMirror via PC.
- Circle to Search needs the [Google app](https://play.google.com/store/apps/details?id=com.google.android.googlequicksearchbox) installed first.
- Long-press power opens the assistant only if the Google app is installed
  and set as the default assistant. The standard power menu can be
  restored in Settings.

## Build Inputs

Both input files are included for reproducibility:

| File | Passed to | Purpose |
| --- | --- | --- |
| [`debloat.txt`](debloat.txt) | `--debloat` | Apps and blobs hidden (same effect as removal) |
| [`lgsi_features.json`](lgsi_features.json) | `--fuck-lgsi` | LGSI feature flags toggled at their registration sites |

## Transparency

Each release ships a `report.html` with the exact DynoBox commands used.
Those steps reproduce the mod, except the older ABL must still be swapped
in manually.

All `.dbp` patches referenced there live in [`patches/`](https://github.com/miner7222/DynoBox/tree/main/patches) at the repo root.
