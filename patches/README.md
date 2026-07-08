# DynoBox patches (`.dbp`)

A `.dbp` (DynoBox Patch) file is a **TOML** document describing size-preserving
Dalvik bytecode edits applied to APKs *inside partition images* during resign.
Pass one or more with the `--plus` resign option:

```sh
dynobox resign  -i <in> -o <out> -k <key> --plus patches/clean-launcher.dbp
dynobox unpack  -i <in> --resign -k <key> --plus a.dbp --plus b.dbp
dynobox apply   -i <in> resign  -k <key> --plus patches/zuisettings-locale.dbp  ota.zip
```

Each op forces a boolean predicate to a constant. Because the edits keep every
`classes*.dex` byte length identical, DynoBox recomputes the dex header sums +
the STORED zip entry CRC and writes the APK back over its ext4 extents. Every
partition an op touches has its dm-verity hash tree regenerated once and the new
root digest propagated into the owning vbmeta, so the resign loop signs over the
patched bytes. Patches that match nothing (different ROM build, refactored
classes) are warned about and skipped — they never abort the resign.

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
file = "system/priv-app/…/App.apk"      # path of the APK from the image root
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
