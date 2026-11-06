# `--add-spoof` payload

`dynobox resign --add-spoof <DIR>/spoof.json` (or `apply --resign`) installs a
**zygote-loaded library that overrides system properties for selected apps**,
plus the developer-options edition toggle hook. It does not need root, Magisk,
KernelSU, LSPosed, or a keybox.

The library used to implement a Play Integrity Fix; that path is gone. The PIF
implementation is preserved on the `backup/pif-impl` branch.

## Layout

```text
spoof/
  libspoof.so     required, ELF64 AArch64 shared object, read from the JSON's directory
  spoof.json      example per-app list
  native/         libspoof.cpp + build scripts
```

The library is not embedded in the JSON: pass the list, and `libspoof.so` is
taken from the same directory.

## What gets installed

| Source | Destination in `system.img` |
|---|---|
| `libspoof.so` | `system/lib64/libspoof.so` |
| generated from the JSON | `system/etc/spoof/spoof.prop` |
| `app_process64` edit | `libspoof.so` as the first `DT_NEEDED` entry of `system/bin/app_process64` |
| `init.zygote64.rc` cleanup | removes a legacy `LD_PRELOAD /system/lib64/libspoof.so` line from the `service zygote /system/bin/app_process64` block |

`app_process64` is executed in a secure-exec context (`AT_SECURE=1`) on user
builds, so the dynamic linker ignores `LD_PRELOAD` for the zygote service. The
payload is therefore listed in the executable's own `DT_NEEDED` array, before
`libandroid_runtime.so`, and the linker maps it regardless of `AT_SECURE`. The
patch copies the dynamic and string tables into the writable `PT_LOAD` tail and
keeps the file length unchanged, so no ext4 blocks are allocated.

The init cleanup removes the old line in place (padded with spaces) when an
image still has one. Only the 64-bit zygote service is touched; an image without
the `service zygote /system/bin/app_process64` block is rejected.

The caller regenerates the `system` partition's dm-verity and re-signs
`vbmeta_system.img`; the payload itself only mutates data.

## JSON list

`spoof.json` is an array of `{"package", "props"}` objects. Quick settings /
app processes with a `:sub` suffix match their base package.

```json
[
  {
    "package": "com.netflix.mediaclient",
    "props": {
      "ro.product.manufacturer": "OnePlus",
      "ro.product.model": "PLK110"
    }
  }
]
```

The list is validated (unique packages, prop key/value shape, size limits) and
converted to the line format the library reads:

```text
@com.netflix.mediaclient
ro.product.manufacturer=OnePlus
ro.product.model=PLK110
```

## Runtime behaviour

- The linker loads `libspoof.so` through `app_process64`'s first `DT_NEEDED`
  entry, before `libandroid_runtime.so`. The library then replaces
  `AndroidRuntime::startReg` and registers a replacement for
  `ZygoteInit.nativeZygoteInit`, which runs in every app process after fork.
- It reads `/proc/self/cmdline`, matches the entry, mirrors the matching
  `ro.*` values onto `android.os.Build` fields, and answers
  `__system_property_get` / `__system_property_read_callback` from the same map
  in that process only. Other processes are untouched.
- Reads of `ro.vendor.config.lgsi.customize.usage` answer `MINGCHAO` while
  `persist.sys.config.model_cust` is `1`; any other value returns the real
  factory token, which is what the developer-options "device compatibility
  test mode" toggle writes (`patches/unlock-wuji.dbp` surfaces the row).

## Build

```powershell
$env:ANDROID_NDK_HOME = "$env:LOCALAPPDATA\Android\Sdk\ndk\<version>"
spoof\native\build.ps1
```

`native/build.sh` is the POSIX equivalent. The output is `spoof/libspoof.so`,
which is what the JSON directory has to contain.
