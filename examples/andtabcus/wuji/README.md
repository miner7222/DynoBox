# ZUXOS ANDTABCUS MOD for Y700 5G

Lenovo Legion Y700 5G (Wuji) was released only in China, so no global firmware
exists for it. Its firmware also carries intentional regional restrictions that
make it awkward to use anywhere outside China.

ANDTABCUS MOD is a custom firmware for one purpose: **comfortable use outside
China**, with no root and no modules. It patches ZUXOS to work well as-is, plus
fixes for a few issues the vendor has left unaddressed.

Based on **ZUXOS 2.5 (Android 17)**.

## What's changed

### Unlocked

- All system languages selectable from Settings, with improved Korean translations
- Wi-Fi 6 GHz and every channel
- Circle to Search, Quick Share and Google services
- Netflix HDR
- Four-app split-screen and seamless split
- Some locked features and settings

### Removed

- China-only apps, storefronts and preinstalled partner apps
- Telemetry, logging and diagnostics scripts
- Built-in data SIM
- Theme permission restrictions, for
  [zuiFont](https://github.com/miner7222/zuiFont) support

### Fixed

- Package Manager no longer disables Google services
- Less aggressive background killing
- LE Audio pairing failures
- Dolby Atmos stays off in speaker mode once disabled
- About reports the device as Legion Tab Y700 5G instead of the PRC name

### Updates

- Signed with `testkey_rsa4096`, with an ABL already replaced to accept that key
  and allow GBL loading
- Only OTAs signed with the mod's key are accepted; stock updates are refused
- The System update never contacts the update server

## Installation

Flash this firmware with LTBox — see the
[LTBox installation guide](https://miner7222.github.io/ltbox/en/install-same-region-firmware.html).

Flashing over the base build or older keeps your data — no wipe needed.

### System update

The built-in system updater only accepts a package built for the build it is
installed from, normally the immediately preceding release. Copy the
downloaded zip to `/sdcard/ota.zip` with exactly that name, open the System
update screen, and choose **Install update package** from the top-right menu.

A system-update install also flashes the modem firmware from the base build.
That can clear a VoLTE patch applied separately on top, so reapply it if VoLTE
stops working afterwards.

## Notes

- The setup wizard supports only English and Chinese. After setup, any
  language can be selected in Settings.
- Lenovo App Store is gone. Sideload the [Google Play Store](https://www.apkmirror.com/apk/google-inc/google-play-store/) APK from
  APKMirror via PC.
- Circle to Search needs the [Google app](https://play.google.com/store/apps/details?id=com.google.android.googlequicksearchbox) installed first.
- Long-press power opens the assistant only if the Google app is installed
  and set as the default assistant. The standard power menu can be
  restored in Settings.

## Transparency

Each release ships a `report.html` with the exact DynoBox command used, the
per-file patch results, the LGSI flag table, and the hashes of every inserted
overlay and spoof payload. That report reproduces the build.
