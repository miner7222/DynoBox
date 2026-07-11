# DynoBox patches (`.dbp`)

A `.dbp` (DynoBox Patch) file is a **TOML** document describing size-preserving
edits applied to files *inside partition images* during resign.
Pass one or more with the `--plus` resign option:

```sh
dynobox resign  -i <in> -o <out> -k <key> --plus patches/clean-launcher.dbp
dynobox unpack  -i <in> --resign -k <key> --plus a.dbp --plus b.dbp
dynobox apply   -i <in> resign  -k <key> --plus patches/zuisettings-locale.dbp  ota.zip
```

Archive ops force a method, invocation result, or compiled resource value to a
constant. Text ops replace one exact byte string in a regular file with another
same-length string. Because the edits keep every target file byte length
identical, DynoBox recomputes dex header sums and/or STORED zip-entry CRCs when
needed, then writes the file back over its ext4 extents. Every partition an op
touches has its dm-verity hash tree regenerated once and the new root digest
propagated into the owning vbmeta, so the resign loop signs over the patched
bytes. Patches that match nothing (different ROM build, refactored
classes/resources/properties) are warned about and skipped — they never abort
the resign.

> APKs are patched in place; their v1/v2/v3 signatures are **not** rebuilt.
> Integrity comes from the dm-verity'd, re-signed partition, not per-APK
> signature re-verification.

## Document format

```toml
name = "clean-launcher"                 # required, short identifier
description = "…"                       # optional

[[op]]
kind = "method_const_bool"              # op kind (see below)
partition = "system"                    # image: <partition>.img
file = "system/priv-app/…/App.apk"      # path from the image root
# … kind-specific fields …
```

`partition` selects the image (`system` → `system.img`). `file` is the path
**from the image root** — on these ROMs the system image carries a leading
`system/` directory, hence `system/priv-app/…`.

## Op kinds

### `method_const_bool`

Force a `()Z` method body to always return a constant, for every caller.
Rewrites the body to `const/4 v0, #lit; return v0` (nop-padded).

| field    | required | meaning                                             |
|----------|----------|-----------------------------------------------------|
| `class`  | yes      | JVM class descriptor, e.g. `Lcom/x/Utilities;`      |
| `method` | yes      | method name, e.g. `isZuiRow`                         |
| `proto`  | no       | JVM method descriptor; defaults to `()Z`            |
| `value`  | yes      | `true` / `false`                                    |

The method is resolved by full method id (class + name + prototype), so
obfuscated / overloaded methods are matched precisely.

### `method_const_int`

Force an integer-returning method body to always return a constant. DynoBox
uses the smallest suitable Dalvik `const` encoding and pads the replaced
instructions with `nop`.

| field    | required | meaning                                        |
|----------|----------|------------------------------------------------|
| `class`  | yes      | JVM class descriptor                           |
| `method` | yes      | method name                                    |
| `proto`  | no       | JVM method descriptor; defaults to `()I`       |
| `value`  | yes      | signed 32-bit integer                          |

### `resource_bool`

Force a compiled boolean resource inside a STORED `resources.arsc` APK entry to
`true` or `false`. This is intended for small runtime resource overlays where
rebuilding the APK would be excessive.

| field      | required | meaning                                             |
|------------|----------|-----------------------------------------------------|
| `resource` | yes      | resource entry name, e.g. `config_wifi6ghzSupport` |
| `value`    | yes      | `true` / `false`                                   |

### `resource_dimen`

Force a compiled **dimension** resource inside a STORED `resources.arsc` APK
entry to an integer `dp` value. Same in-place, size-preserving `Res_value`
rewrite as `resource_bool`; the target must already be a dimension (the op is
refused on any other value type). The value is encoded as an integer-radix
`TYPE_DIMENSION` with `COMPLEX_UNIT_DIP`, i.e. `data = (dp << 8) | 1`.

| field      | required | meaning                                             |
|------------|----------|-----------------------------------------------------|
| `resource` | yes      | dimension entry name, e.g. `google_lens_button_padding` |
| `dp`       | yes      | integer dp, `0..=16777215`                          |

### `text_replace`

Replace the first exact byte-string match inside a regular file with another
byte string of identical length. This is intended for tiny property-file edits
where growing the ext4 file would be unnecessary risk.

| field  | required | meaning                                  |
|--------|----------|------------------------------------------|
| `from` | yes      | source text/bytes to find; must be non-empty |
| `to`   | yes      | replacement text/bytes; same byte length as `from` |

### `invoke_const_bool`

Force `invoke-static target_class.target_method()Z` results to a constant, but
only at the call sites inside one class (optionally one method). Rewrites each
`invoke-static` + `move-result vAA` pair to `const/16 vAA, #lit` + 2×`nop`.

| field           | required | meaning                                                  |
|-----------------|----------|----------------------------------------------------------|
| `scan_class`    | yes      | class whose methods are scanned for call sites           |
| `scan_method`   | no       | narrow the scan to one method name                       |
| `target_class`  | yes      | class of the invoked getter, e.g. `Lcom/x/LenovoUtils;`  |
| `target_method` | yes      | getter name, e.g. `isPrcVersion`                          |
| `proto`         | no       | getter descriptor; defaults to `()Z`                     |
| `value`         | yes      | `true` / `false`                                         |

## Bundled patches

* **`clean-launcher.dbp`** — force ZuiLauncher to ROW behaviour (home slide-up
  global search → ROW branch; no first-run recommended widgets/apps). Forces
  `Utilities.isZuiRow()` + `GraphicsUtils.isZuiRow()` → `true` and
  `FeatureFlags.isIsShowPrcGlobalSearch()` → `false`.
* **`zuisettings-locale.dbp`** — make the PRC ZuiSettings behave like a ROW
  build (full language picker + previously-hidden Regional preferences
  category). Forces `LenovoUtils.isPrcVersion()` → `false` /
  `isRowVersion()` → `true` at the call sites inside the affected classes.
  Formerly fired automatically when `--fuck-lgsi` flipped `ZuiAntiCrossSell`
  `true→false`; now applied on demand.
* **`power-menu.dbp`** — show Global Actions instead of Lenovo LeVoice when
  the power key is held. Forces
  `PhoneWindowManager.getResolvedLongPressOnPowerBehavior()` → `1`
  (`LONG_PRESS_POWER_GLOBAL_ACTIONS`), including when `--fuck-lgsi` disables
  the LeVoice feature and its helper is never created.
* **`wifi-unlock.dbp`** — keep TB322 PRC Wi-Fi on a US regulatory domain by
  neutralizing Lenovo's pre-property-load assignment in
  `system.img:/system/bin/init`, replacing one duplicate
  `system.img:/system/build.prop` property with
  `ro.product.countrycode=US`. This avoids patching the compressed Mainline
  Wi-Fi APEX.
* **`google-services.dbp`** — always show the ZuiSettings "Google services"
  menu. Forces
  `GoogleServicesPreferenceController.getAvailabilityStatus()` → `0`
  (`AVAILABLE`) so the entry appears regardless of the `cn.google.services`
  system feature.
* **`google-lens-button.dbp`** — show the Google Lens camera button instead
  of ZUI AI Lens on a PRC ZuiCamera. `CaptureModule`/`WideCaptureModule`
  `getUISpec()` pick the lens button by `ApiHelper.isRow()`; forcing it →
  `true` only at those call sites turns the Google Lens button
  (`ic_google_lens`) on and the `com.zui.ai.lens` OCR button off. The button
  only launches Google Lens if the Google app is installed. A `resource_dimen`
  op also bumps `google_lens_button_padding` 2.25dp → 9dp so the `fitCenter`
  icon draws at 46 − 2·9 = 28dp, matching the ZUI AI Lens icon size.
