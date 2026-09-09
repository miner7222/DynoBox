# DynoBox patches (`.dbp`)

A `.dbp` (DynoBox Patch) file is a **TOML** document describing size-preserving
edits applied to files *inside partition images* during resign.
Pass one or more with the `--plus` resign option:

```sh
dynobox resign  -i <in> -o <out> -k <key> --plus patches/debloat-launcher.dbp
dynobox unpack  -i <in> --resign -k <key> --plus a.dbp --plus b.dbp
dynobox apply   -i <in> resign  -k <key> --plus patches/unlock-locales.dbp  ota.zip
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
name = "debloat-launcher"              # required, short identifier
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

### `method_const_string`

Force a `Ljava/lang/String;`-returning method body to an existing constant
string. Rewrites the body to `const-string v0, "value"; return-object v0`
(nop-padded). The string must already be in the target dex's string pool, so
no DEX id is added and the file length never changes.

| field    | required | meaning                                                   |
|----------|----------|-----------------------------------------------------------|
| `class`  | yes      | JVM class descriptor                                      |
| `method` | yes      | method name                                               |
| `proto`  | no       | JVM method descriptor; must return `Ljava/lang/String;`; defaults to `()Ljava/lang/String;` |
| `value`  | yes      | the returned string; must already exist in the dex pool   |

Because the rewrite starts at the method entry and uses `v0`, it is
independent of how a given build allocated registers inside the original
body, unlike a byte-pinned `method_code_patch`. It is refused when the string
is absent, its index needs `const-string/jumbo`, the code item is
R8-deduplicated, or the body is too small.

### `method_nop`

Neutralize a **void** method for every caller: rewrite its body to `return-void`
(the first instruction nop-padded, `tries_size` zeroed). Used to disable an
init/register hook at its source so all call sites become no-ops.

| field    | required | meaning                                        |
|----------|----------|------------------------------------------------|
| `class`  | yes      | JVM class descriptor                           |
| `method` | yes      | method name                                    |
| `proto`  | no       | JVM method descriptor; must return `V`; defaults to `()V` |

### `method_code_patch`

Apply an ordered, atomic set of size-preserving instruction-byte replacements
inside one method selected by full class, name, and prototype. This is the
escape hatch for control-flow fixes that cannot be expressed by a constant or
nop operation without adding DEX ids or code units.

| field         | required | meaning                                              |
|---------------|----------|------------------------------------------------------|
| `class`       | yes      | JVM class descriptor                                 |
| `method`      | yes      | exact method name                                    |
| `proto`       | yes      | full JVM method descriptor                           |
| `symbol`      | no       | named existing DEX-pool references (see below)       |
| `replacement` | yes      | one or more ordered replacement tables (see below)   |

Each `[[op.replacement]]` has distinct `from` and `to` strings containing
whitespace-separated hexadecimal bytes and an optional `expected` match count
(default `1`). Both byte strings must be non-empty, code-unit aligned, contain
whole Dalvik instructions, and have identical lengths. DynoBox applies the set
to a clone first and commits only when every ordered replacement matches its
declared count. It refuses R8-shared code items and rejects a final body whose
ordinary branch targets do not land on instruction boundaries.

Pool indexes may move even when the target smali stays structurally identical.
An `[[op.symbol]]` resolves an existing string, type, field, or method by its
semantic descriptor. Use `${name:u16}` in a normal reference operand, or
`${name:u32}` for the four-byte operand of `const-string/jumbo`. DynoBox writes
the target DEX's little-endian index into both templates before exact matching.
Missing symbols, indexes too wide for their opcode, or changed instruction
shapes skip the operation without modifying the DEX.

```toml
[[op]]
kind = "method_code_patch"
partition = "system_ext"
file = "priv-app/SystemUI/SystemUI.apk"
class = "Lcom/example/Controller;"
method = "finish"
proto = "(Z)V"

[[op.symbol]]
name = "is_empty"
kind = "method"
class = "Ljava/util/ArrayList;"
method = "isEmpty"
proto = "()Z"

[[op.replacement]]
from = "6e 10 ${is_empty:u16} 00 00 0a 00"
to = "6e 10 ${is_empty:u16} 00 00 0a 01"
expected = 1
```

Symbol tables use these fields:

- `kind = "string"`: `name`, `value`
- `kind = "type"`: `name`, `descriptor`
- `kind = "field"`: `name`, `class`, `field`, `ty`
- `kind = "method"`: `name`, `class`, `method`, `proto`

Placeholders are accepted only at matching Dalvik pool-reference operands:
string loads, type instructions, field accesses, and ordinary invokes. Symbol
names must be unique and every declaration must be used.

This operation deliberately cannot grow a method, create strings/method/field
references, or repair arbitrary verifier-invalid register typing. Pin patterns
to one known instruction shape and validate the emitted DEX before flashing.

### `method_code_redirect`

Redirect one encoded method to an already-present code item without rewriting
either body. Both methods are resolved by class, name, and full prototype. This
is intended for an R8-deduplicated target whose shared body cannot safely be
changed in place.

| field          | required | meaning                                |
|----------------|----------|----------------------------------------|
| `class`        | yes      | target JVM class descriptor            |
| `method`       | yes      | exact target method name               |
| `proto`        | yes      | full target JVM method descriptor      |
| `donor_class`  | yes      | donor JVM class descriptor             |
| `donor_method` | yes      | exact donor method name                |
| `donor_proto`  | yes      | full donor JVM method descriptor       |

DynoBox changes only the target encoded method's `code_off` ULEB128. It refuses
missing or ambiguous methods, different return descriptors, any mismatch in
`registers_size`, `ins_size`, `outs_size`, `tries_size`, or `insns_size`, and
old/new offsets with different ULEB128 widths. Code-item headers, instructions,
try items, and handlers remain byte-identical, and the DEX length never changes.

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

### `layout_collapse`

Collapse layout nodes with `android:id == node_id` inside `.xml` entries of
a zip archive: `layout_height` (or `layout_weight`) goes to zero plus any
vertical margins, so the node takes no space. Nodes already gone, or whose
height is `match_parent`/`wrap_content`, are skipped. The archive length
never changes (recompressed entries absorb slack in the local extra field).
Exactly `expected` nodes must be patched or nothing is written — a mismatch
means the layout changed shape and the op skips with a warning instead of
half-hiding a screen.

| field      | required | meaning                                                     |
|------------|----------|-------------------------------------------------------------|
| `node_id`  | yes      | view id to collapse, e.g. `0x7f090404`                      |
| `expected` | no       | total nodes that must be patched; defaults to `1`           |

### `layout_background`

Swap the `android:background` reference of layout nodes with
`android:id == node_id` to `drawable`. Same size-preserving machinery as
`layout_collapse`. Intended for repairing card visuals after hiding rows
(e.g. restoring the rounded closures a hidden row used to provide).

| field      | required | meaning                                                     |
|------------|----------|-------------------------------------------------------------|
| `node_id`  | yes      | view id whose background is swapped, e.g. `0x7f0903fe`      |
| `drawable` | yes      | replacement drawable id, e.g. `0x7f0804ab`                  |
| `expected` | no       | total nodes that must be patched; defaults to `1`           |

### `zip_entry_replace`

Overwrite the data of STORED zip entries with `payload` (whitespace-separated
hex bytes), zero-padding to each entry's original data length, and fix the
CRC32 in both the local header and the central directory. The archive length
never changes. All `entries` must resolve or nothing is written
(all-or-nothing). The payload must fit inside every listed entry. Intended for
neutralizing asset frames (e.g. boot-animation PNGs) that have no code gate —
`desc.txt` can only replay whole parts, so middle frames cannot be skipped
there.

| field     | required | meaning                                                       |
|-----------|----------|---------------------------------------------------------------|
| `entries` | yes      | exact zip entry names, e.g. `part1/frame_010.png` (non-empty, no duplicates) |
| `payload` | yes      | plain hex bytes (no `${slots}`), e.g. a 1×1 transparent PNG   |

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

* **`debloat-bootanim.dbp`**
* **`debloat-launcher.dbp`**
* **`debloat-security.dbp`**
* **`debloat-settings.dbp`**
* **`debloat-setupwizard.dbp`**
* **`debloat-telephony.dbp`**
* **`debloat-theme.dbp`**
* **`disable-dolby-atmos.dbp`**
* **`disable-quick-kill.dbp`**
* **`enable-adb-debug.dbp`**
* **`enable-circle-to-search.dbp`**
* **`enable-google-services.dbp`**
* **`fix-leaudio.dbp`**
* **`fix-storage-stats-crash.dbp`**
* **`fix-third-party-recents.dbp`**
* **`show-google-lens.dbp`**
* **`show-power-gesture.dbp`**
* **`unlock-locales.dbp`**
* **`unlock-wifi.dbp`**
