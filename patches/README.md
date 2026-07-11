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

### `method_nop`

Neutralize a **void** method for every caller: rewrite its body to `return-void`
(the first instruction nop-padded, `tries_size` zeroed). Used to disable an
init/register hook at its source so all call sites become no-ops.

| field    | required | meaning                                        |
|----------|----------|------------------------------------------------|
| `class`  | yes      | JVM class descriptor                           |
| `method` | yes      | method name                                    |
| `proto`  | no       | JVM method descriptor; must return `V`; defaults to `()V` |

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

Replace an exact byte-string match inside a regular file with another byte
string of identical length — the first match by default, or every
non-overlapping match with `all = true`. This is intended for tiny
property-file edits where growing the ext4 file would be unnecessary risk.

| field  | required | meaning                                  |
|--------|----------|------------------------------------------|
| `from` | yes      | source text/bytes to find; must be non-empty |
| `to`   | yes      | replacement text/bytes; same byte length as `from` |
| `all`  | no       | replace every match instead of just the first (default `false`) |

### `invoke_const_bool`

Force `target_class.target_method()Z` results to a constant, but only at the
call sites inside one class (optionally one method). Rewrites each format-35c
invoke (`invoke-static/virtual/super/direct/interface`) + `move-result vAA` pair
to `const/16 vAA, #lit` + 2×`nop`, so both static (`isRowVersion`) and instance
(`AppHelper.isSupportCCS`) getters can be scoped.

| field           | required | meaning                                                  |
|-----------------|----------|----------------------------------------------------------|
| `scan_class`    | yes      | class whose methods are scanned for call sites           |
| `scan_method`   | no       | narrow the scan to one method name                       |
| `target_class`  | yes      | class of the invoked getter, e.g. `Lcom/x/LenovoUtils;`  |
| `target_method` | yes      | getter name, e.g. `isPrcVersion`                          |
| `proto`         | no       | getter descriptor; defaults to `()Z`                     |
| `value`         | yes      | `true` / `false`                                         |

### `invoke_const_int`

Like `invoke_const_bool`, but for an int-returning (`I`) method: forces each
format-35c invoke of `target_class.target_method(...)I` result to `value` at its
call sites inside `scan_class` (optionally `scan_method`). Handy to pin a
`Settings.*.getInt(...)` feature gate to a constant. Same-size, in place
(`const/16` for i16-range values, else `const`), nop-padded.

| field           | required | meaning                                                  |
|-----------------|----------|----------------------------------------------------------|
| `scan_class`    | yes      | class whose methods are scanned for call sites           |
| `scan_method`   | no       | narrow the scan to one method name                       |
| `target_class`  | yes      | class of the invoked method, e.g. `Landroid/provider/Settings$Global;` |
| `target_method` | yes      | method name, e.g. `getInt`                               |
| `proto`         | no       | method descriptor; defaults to `()I`                     |
| `value`         | yes      | integer to force the result to                           |

### `fragment_hide`

Collapse a `Fragment` tile that is embedded statically as a `<fragment>` in a
compiled layout (which dbp can't edit). Rewrites the fragment's `onCreateView`
to inflate `layout` and return that view with `setVisibility(GONE)`, so the
`<fragment>` still gets a non-null view (no `IllegalStateException`) but the
slot collapses and weighted siblings reflow. The emitted body only calls
`LayoutInflater.inflate` and `View.setVisibility` — method ids a real
`onCreateView` already carries — so it stays size-preserving.

| field    | required | meaning                                                       |
|----------|----------|---------------------------------------------------------------|
| `class`  | yes      | fragment class descriptor, e.g. `Lcom/x/HomeCardFragment;`    |
| `method` | no       | view-creating method; defaults to `onCreateView`              |
| `layout` | yes      | layout resource id to inflate (integer, e.g. `0x7f0c0118`)    |

> The target must be a real `onCreateView(LayoutInflater, ViewGroup, Bundle)`
> returning a `View`; obfuscated names are matched by that exact signature.

### `nop_invoke`

Nop the first `target_class.target_method(...)` invoke that follows a
constant load inside one scanned method, but only when that invoke's result
is discarded (never nopped if a `move-result*` consumes it). Useful for
dropping a single imperative call — e.g. one `List.add()` in a menu-building
constructor, or one `Map.put()` in a static initializer — that can only be
disambiguated by a nearby constant (a string or literal loaded just before
the call). Size-preserving: the invoke's instruction is overwritten with
`nop`.

| field           | required | meaning                                                       |
|-----------------|----------|----------------------------------------------------------------|
| `scan_class`    | yes      | class whose method is scanned                                  |
| `scan_method`   | yes      | exact method name, e.g. `<init>` or `<clinit>`                 |
| `target_class`  | yes      | class of the invoked method to nop                              |
| `target_method` | yes      | method name to nop                                              |
| `proto`         | yes      | full JVM descriptor of the invoked method, e.g. `(Ljava/lang/Object;)Z` |
| `anchor_string` | one of   | a `const-string` operand that arms the scan                    |
| `anchor_int`    | one of   | a `const`/`const/4`/`const/16`/`const/high16` literal that arms the scan |

Exactly one of `anchor_string` / `anchor_int` must be set. The scan walks
`scan_method`'s instructions in order; once the anchor constant is loaded it
arms, and the very next matching-target invoke is nopped (unless a following
`move-result*` consumes its result, in which case it is left untouched and
the op reports no site).

### `force_view_gone`

Force `setVisibility(GONE)` on one or more views bound by `findViewById` inside
one scanned method, hiding static layout entries that have no visibility gate
(and whose compiled, deflated layout XML can't be edited size-preservingly).
The op finds each view's `const vView, id` / `findViewById` / `move-result` /
… / `setOnClickListener` binding. One **field-backed** view among `view_ids`
(one whose `check-cast`+`iput`+`setOnClickListener` tail is wide enough) is the
*anchor*: its tail is rewritten to load `View.GONE` into `scratch_reg` and call
`setVisibility`, dropping its click/field binding. Every other listed view's
`setOnClickListener` call is then swapped in place to
`setVisibility(view, scratch_reg)`, reusing the register the anchor loaded.

| field         | required | meaning                                                           |
|---------------|----------|-------------------------------------------------------------------|
| `scan_class`  | yes      | activity class whose method is scanned                            |
| `scan_method` | yes      | exact method name, e.g. `initView`                                |
| `view_ids`    | yes      | list of view resource ids to hide (integers)                      |
| `scratch_reg` | yes      | a nibble register (0..=15) free to clobber for the `GONE` constant |

Requires `Landroid/view/View;->setVisibility(I)V` to already be referenced in
the dex, at least one field-backed anchor among `view_ids`, and that the
anchor's dropped `iput` field is not read elsewhere. Size-preserving.

### `remoteviews_hide`

Hide a `RemoteViews` child (e.g. a home-screen widget row) that a static,
compiled layout always shows and no code path gates. Inside
`scan_class.scan_method`, the op finds the `const vId, view_id` that loads the
target id, immediately followed by a 2-unit arg-load and a 3-unit `invoke-*`
(typically the item's click-intent registration), and overwrites those 10 bytes
in place with `const/16 scratch, #8` + `invoke-virtual {rv_reg, vId, scratch},
RemoteViews->setViewVisibility(I,I)V`. The row collapses and its siblings reflow.

| field         | required | meaning                                                     |
|---------------|----------|-------------------------------------------------------------|
| `scan_class`  | yes      | class whose method builds the RemoteViews                   |
| `scan_method` | yes      | exact method name, e.g. `refreshWidget`                     |
| `view_id`     | yes      | the RemoteViews target view id (integer)                    |
| `rv_reg`      | yes      | register holding the `RemoteViews` at the site (0..=15)     |
| `scratch_reg` | yes      | a free nibble register for the `GONE` constant (0..=15)     |

Requires `RemoteViews.setViewVisibility(I,I)V` already referenced in the dex, and
the exact `[const id][2-unit load][3-unit invoke]` shape at the site. The id's
register and `rv_reg`/`scratch_reg` must all be < 16. Size-preserving.

### `field_const_bool`

Force scoped reads of one exact boolean instance field to a constant. Each
matching two-unit `iget-boolean vA, vB, field@CCCC` inside `scan_class`
(optionally only `scan_method`) becomes `const/4 vA, #value` + `nop`. The field
itself is not rewritten, so other classes keep their original reads.

| field          | required | meaning                                                      |
|----------------|----------|--------------------------------------------------------------|
| `scan_class`   | yes      | class whose methods are scanned                              |
| `scan_method`  | no       | limit to one method name when set                           |
| `target_class` | yes      | JVM class that owns the field                                |
| `target_field` | yes      | field name, e.g. `isNetworkAvail`                            |
| `value`        | yes      | `true` / `false`                                             |

Size-preserving. A missing class, field, or method is a clean no-op.

### `intent_action_broadcast`

Retarget an existing Intent action string reference and replace the matching
`Context.startActivity(Intent, Bundle)` with `Context.sendBroadcast(Intent)`.
Both action strings must already exist in the dex string table — the sorted
string-data section is never edited. The scan is conservative: a source action
must feed one `Intent.setAction`, followed by exactly one three-arg
`startActivity` on that same Intent register. Ambiguous or incomplete sequences
are left byte-for-byte unchanged.

| field         | required | meaning                                                     |
|---------------|----------|-------------------------------------------------------------|
| `from_action` | yes      | existing Intent action string to retarget                   |
| `to_action`   | yes      | existing Intent action string to use instead                |

Only the three-unit `invoke-virtual` form used by LenovoID is accepted. The
rewrite keeps instruction width identical (`startActivity` and `sendBroadcast`
are both three code units here).

### `method_broadcast_finish`

Rewrite one Activity method body (currently only `(Landroid/os/Bundle;)V`, i.e.
`onCreate`) to:

1. `invoke-super` the named `super_class` method with the original arguments
2. `Activity.finish()` before the next setup Activity can be launched
3. build an `Intent` directly from an **already-present** action string
4. `Context.sendBroadcast(Intent)`
5. `return-void`

The entire remainder of the original body is `nop`-padded. Size-preserving;
refuses shared code items, methods with try/catch tables, and incompatible
register/argument layouts. Used to skip an OOBE entry Activity before it draws
while still advancing the setup wizard.

| field         | required | meaning                                                     |
|---------------|----------|-------------------------------------------------------------|
| `class`       | yes      | JVM class owning the method                                 |
| `method`      | yes      | method name, typically `onCreate`                           |
| `proto`       | no       | defaults to `(Landroid/os/Bundle;)V`                        |
| `super_class` | yes      | JVM class of the `invoke-super` target                      |
| `action`      | yes      | existing Intent action string already in the dex            |

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
* **`debloat-setupwizard.dbp`** — make the first-boot flow independent of the
  removed `XuiEasySync.apk`, skip the Lenovo ID entry screen, and keep the final
  home button usable without the Vantage widget (7 ops across the
  setup wizard, ZuiSettings, and LenovoID):
  * **Fix Wi-Fi Next / Set up later** — in
    `DeviceActivationForWifiActivity.startPrivacySettingsActivity`, force its
    `isNetworkAvail` field read → `true` (`field_const_bool`) and its scoped
    `isPrcCommercial()` result → `false`. Both connected and offline paths leave
    the Wi-Fi page by launching Lenovo ID (which the next op then skips).
  * **Skip Lenovo ID before it draws** — `method_broadcast_finish` rewrites
    `PsLoginWizardActivity.onCreate` to run its required direct-super lifecycle,
    then `finish` + broadcast existing
    `com.zui.setupwizard.action.CLOUD_SKIP` + `return-void`. Finishing before
    signaling the next page prevents LenovoID's translucent window from
    remaining visible under SetupWizard.
  * **Skip EasySync after Lenovo ID** — `intent_action_broadcast` retargets all
    nine LenovoID source-action loads (covering ten branch-local launch
    continuations) from the existing
    `GUIDE_DATA_RESTORE_FROM_PRIVACY` string index to the existing
    `com.zui.setupwizard.action.CLOUD_SKIP` index, then replaces the associated
    `startActivity(Intent, Bundle)` with `sendBroadcast(Intent)`. Belt-and-braces
    if any completion path still runs; the sorted dex string-data table is not
    edited.
  * **Protect alternate setup pages** — force
    `ZuiUtils.getCloudActivityAction(ctx, page)` onto its offline+completed
    `null` result (`ConnectivityUtil.isOnline()` → `false` and
    `SharedPreHelper.isCloudRestoreCompleted()` → `true`) so Ai/Legion/Tianjiao
    callers do not launch LeCloud either.
  * **Keep the final home button enabled** — force the scoped
    `AppHelper.isSupportCCS()` result in `CompleteLandActivity.onCreate` →
    `true`. Without a Vantage widget rectangle, the stock false branch hides
    `btn_next`, shows the loading view, and waits for a launcher transition.

  > Keep `LenovoID.apk` installed; the patch rewrites its entry `onCreate` and
  > EasySync continuations in place rather than removing the package. Do not
  > restore the old global `AppHelper.isRow()` force: `CompleteLandActivity.onCreate`
  > gates `setContentView` on `!isRow()`, so the global patch leaves `btn_next`
  > null and crashes.
* **`google-lens-button.dbp`** — show the Google Lens camera button instead
  of ZUI AI Lens on a PRC ZuiCamera. `CaptureModule`/`WideCaptureModule`
  `getUISpec()` pick the lens button by `ApiHelper.isRow()`; forcing it →
  `true` only at those call sites turns the Google Lens button
  (`ic_google_lens`) on and the `com.zui.ai.lens` OCR button off. The button
  only launches Google Lens if the Google app is installed. A `resource_dimen`
  op also bumps `google_lens_button_padding` 2.25dp → 9dp so the `fitCenter`
  icon draws at 46 − 2·9 = 28dp, matching the ZUI AI Lens icon size.
* **`debloat-settings.dbp`** — trim Lenovo-specific ZuiSettings entries. Two
  `method_const_int` ops on `getAvailabilityStatus()`: force
  `TopLevelLenovoAccountPreferenceController` → `3` (`UNSUPPORTED_ON_DEVICE`) so
  the "Accounts & cloud service" / LeCloud tile is never shown, and force
  `TopLevelAccountEntryPreferenceController` → `0` (`AVAILABLE`) so the AOSP
  "Accounts & sync" entry always shows (otherwise hidden on PRC via
  `isPrcVersion()`). Plus two `invoke_const_bool` ops that hide the "Service
  hotline" (`LenovoServicePreferenceController`, About / device info) by flipping
  its region gate to ROW: it is shown only on PRC — `updateState()`
  `setVisible(isLenovoServiceVisible())` (= `!com.lenovo.xbb installed &&
  isPrcVersion()`) and `onResume()` `setVisible(false)` when `isRowVersion()`. So
  force `LenovoUtils.isPrcVersion()` → `false` and `isRowVersion()` → `true` at
  their call sites in that controller. (Its `getAvailabilityStatus()` is a trivial
  `return 0` that R8 deduplicated with `ImmutableMap.isHashCodeFast():Z`, so it
  can't be rewritten — DynoBox refuses shared/deduped code items, see
  `dex_patch::code_off_is_shared` — but the region gate is the real switch anyway.)
* **`disable-quick-kill.dbp`** — turn off Lenovo's ZMC "quick kill" aggressive
  reclaim. `system.img:/system/etc/ZuiMemCleanerConfig.xml` is parsed by
  `/system/bin/lmkd`, which `property_set()`s each `<Prop>`, so
  `zuimemory.use_quick_kill` drives lmkd's quick-kill path (ZuiSecurity reads
  the same file but only `zuimemory.enable`). A single `all` `text_replace`
  flips every `use_quick_kill` block `true → false`, size-preserved by dropping
  the space before `/>`.
* **`debloat-security.dbp`** — one patch that hides / disables / AOSP-replaces
  the ZuiSecurity-driven "security" surfaces across ZuiSettings, ZuiSecurity and
  ZuiPackageInstaller (merges the former antivirus, autostart, permission-manager,
  url-security and app-recommendation patches). Groups:
  * **Antivirus** — three `method_nop`s on `AntiVirusInterface`
    (`initTMSApplication` / `startAutoScanBroadcastReceiver` /
    `startUpdateTMSVirusDbReceiver`) kill the Tencent TMS engine, auto-scan and
    DB updates; a `nop_invoke` drops the phone main-list item, the
    `force_view_gone` below hides the `MainNavigationActivity` "Antivirus" nav row
    (`layout_virus`), and two `method_const_int`s (→ 3) hide the ZuiSettings
    `KillVirusPreferenceController` (antivirus) and
    `AppInstallationGuardPreferenceController` ("Safe installation", which
    configures the now-disabled install-scan) entries.
  * **Install-time virus scan** — an `invoke_const_int` forces
    `PackageInstallerActivityExtra`'s `Settings.Global "pi_safeinstall_switch"`
    `getInt` → 0 (in onCreate + onResume), so `safeInstallEnable` stays false and
    ZuiPackageInstaller does a normal install without binding ZuiSecurity's
    `ScanAppService`.
  * **Autostart** — pairs with the `ZuiAutorunManager` LGSI feature being
    disabled: `SelfStartPreferenceController` → 3, `fragment_hide` of the
    SafeCenter homepage tile, two `nop_invoke`s (main-list item + the per-app
    "Autostart Apps" permission group via `RECEIVE_BOOT_COMPLETED`), and a
    `remoteviews_hide` of the home-screen widget item.
  * **Permission manager** — `invoke_const_bool` forces `isRowVersion()` → true
    in `AppPermissionPreferenceController` (routes app permissions to the AOSP
    PermissionController), and `force_view_gone` hides the static "Permission
    manager", "Antivirus" and leftover "Autostart" nav rows on
    `MainNavigationActivity` (`layout_permission` anchor + `layout_virus` +
    `layout_auto`).
  * **URL security** — a `text_replace` renames `ro.zui.software.safeurl` in
    `system/build.prop` (size-preserving), so `isSafeUrlSupported()` reads false
    and `ZuiEmergencyDashboardFragment` removes the toggle.
  * **App recommendation** — the "Apps recommendation" toggle drives
    ZuiPackageInstaller's post-install ad list. `invoke_const_bool` forces
    `isRowVersion()` → true in `ZuiEmergencyDashboardFragment.onCreate` (so it
    `removePreference("app_recommendation")`), and a `method_nop` on
    `InstallInstallingExtra.getRecommendApp()` stops the fetch regardless of the
    setting.
* **`circle-to-search.dbp`** — enable Google Circle to Search (long-press Home)
  on a PRC build by clearing its three region gates. Forces
  `XSystemUtil.isDeviceRow()` → `true` only inside SystemUI's `AssistManager`
  (so `startAssist` takes the `ContextualSearchManager` path), forces
  `LenovoUtils.isPrcVersion()` → `false` only inside `isCircleToSearchEnable()`
  (so the ZuiSettings toggle appears), and declares the
  `CONTEXTUAL_SEARCH` + `GEMINI_EXPERIENCE` Google system features in
  `product.img:/etc/sysconfig/google.xml` (size-preserving, overwriting an
  obsolete TODO comment). Still requires the Google app's
  `ContextualSearchManager` service to actually run the search.
* **`power-gesture-settings.dbp`** — show the "Press and hold power button"
  gesture setting (ZuiSettings → gestures) on PRC. `invoke_const_bool` forces
  `LenovoUtils.isRowVersion()` → `true` only inside `PowerMenuPreferenceController`
  so its `getAvailabilityStatus()` stops returning UNSUPPORTED (the other gate —
  `config_longPressOnPowerForAssistantSettingAvailable=true` and
  `config_longPressOnPowerBehavior ∈ {1,5}` — is already met). For the toggle to
  actually switch behavior, disable LeVoice with `--fuck-lgsi` so
  `PhoneWindowManager.getResolvedLongPressOnPowerBehavior()` returns the
  setting-driven value (do not force that resolver to a constant, e.g. via a
  `method_const_int` on `getResolvedLongPressOnPowerBehavior`, or long-press is
  pinned to one behavior regardless of the setting). ZuiSystemUI needs no change
  (stock AOSP global actions + assist). The boot default
  (`config_longPressOnPowerBehavior` = 5 = Assistant) is left as-is — changing it
  means editing framework-res.apk's `resources.arsc`, which DynoBox's arsc walker
  doesn't parse.
