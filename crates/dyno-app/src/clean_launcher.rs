//! `--clean-launcher`: in-place dex byte patches on
//! `/system/priv-app/ZuiLauncher/ZuiLauncher.apk` inside `system.img`.
//!
//! ZUI's launcher gates all of its PRC-vs-ROW behaviour on a single region
//! predicate, `Utilities.isZuiRow()` (mirrored by an identical
//! `GraphicsUtils.isZuiRow()`), plus one derived PRC flag,
//! `FeatureFlags.isIsShowPrcGlobalSearch()` (which is literally
//! `!isZuiRow()`). Rather than surgically rewrite every consumer, this
//! forces those predicate method bodies to constants so the whole launcher
//! behaves as a ROW build regardless of the device region:
//!
//! * every `isZuiRow()Z` definition → always `true`
//! * `isIsShowPrcGlobalSearch()Z` → always `false`
//!
//! The observable effects are the ones the clean-launcher feature targets:
//!
//! 1. **Home slide-up global search** takes the ROW branch
//!    (`isIsShowPrcGlobalSearch()` is `false`), so the PRC in-launcher
//!    search UI is never shown.
//! 2. **First-run recommended widgets** are skipped:
//!    `WidgetsModel.getZUIRecommendWidgets()` returns its empty ROW-path
//!    list because `isZuiRow()` is `true`.
//! 3. **First-run recommended apps** (the PRC global-search recommend page)
//!    are not surfaced, since the ROW search branch replaces the PRC page
//!    that would display them.
//!
//! Each method body is rewritten to `const/4 v0, #lit` + `return v0`, with
//! the remainder of the overwritten instructions padded with `nop`. The
//! edit keeps every `classes*.dex` byte length identical, so the dex header
//! sums + the STORED zip entry CRC are recomputed and the APK is written
//! back over its original ext4 extents. dm-verity for `system.img` is
//! regenerated once by the resign stage's deferred pass.

use std::path::Path;

use anyhow::{Result, anyhow};

use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume, write_via_extents};
use crate::fuck_lgsi::{
    ZipEntry, crc32_ieee, dex_walker, parse_zip_central_directory, read_u16_le, read_u32_le,
    recompute_dex_header_sums, write_u32_le,
};

const ZUI_LAUNCHER_APK_PATH: &[&str] = &["system", "priv-app", "ZuiLauncher", "ZuiLauncher.apk"];

/// A predicate method whose body is forced to a constant boolean.
struct BoolTarget {
    class_descriptor: &'static str,
    method_name: &'static str,
    /// Forced return value.
    value: bool,
    /// Whether this target is an `isZuiRow`-family predicate (forced
    /// `true`) or a PRC predicate (forced `false`) — used only for
    /// reporting.
    is_row: bool,
}

/// The launcher region predicates forced to constants. All are `static ()Z`.
///
/// `isZuiRow` is defined independently in two classes (`Utilities` and
/// `icons/GraphicsUtils`); both are forced so no consumer of either sees a
/// PRC result. `isIsShowPrcGlobalSearch` is `!isZuiRow()` and is forced
/// `false` directly as well, so the ROW search branch holds even for any
/// caller that reads it without re-deriving from `isZuiRow`.
const BOOL_TARGETS: &[BoolTarget] = &[
    BoolTarget {
        class_descriptor: "Lcom/android/launcher3/Utilities;",
        method_name: "isZuiRow",
        value: true,
        is_row: true,
    },
    BoolTarget {
        class_descriptor: "Lcom/android/launcher3/icons/GraphicsUtils;",
        method_name: "isZuiRow",
        value: true,
        is_row: true,
    },
    BoolTarget {
        class_descriptor: "Lcom/android/launcher3/config/FeatureFlags;",
        method_name: "isIsShowPrcGlobalSearch",
        value: false,
        is_row: false,
    },
];

/// Per-run summary of the ZuiLauncher.apk dex patches.
#[derive(Debug, Clone)]
pub struct CleanLauncherPatch {
    /// `isZuiRow()` method bodies forced to `true`.
    pub row_methods_forced: usize,
    /// PRC predicate (`isIsShowPrcGlobalSearch`) bodies forced to `false`.
    pub prc_methods_forced: usize,
    /// `classes*.dex` entry names that received at least one patch.
    pub patched_dex_entries: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum CleanLauncherOutcome {
    Patched(CleanLauncherPatch),
    NotApplicable { reason: String },
}

/// ext4-walk `system.img` to `/system/priv-app/ZuiLauncher/ZuiLauncher.apk`
/// and force the launcher region predicates to constants in place. Returns
/// `NotApplicable` when the APK is absent (different firmware) or none of
/// the target methods were found across any `classes*.dex` (refactored
/// build). Does not touch dm-verity — the resign stage marks `system`
/// dirty and regenerates its hash tree once in the deferred pass.
pub fn apply_clean_launcher(system_image: &Path) -> Result<CleanLauncherOutcome> {
    // 1. Read the APK bytes + extents from system.img.
    let mut volume = open_ext4_volume(system_image)?;
    let inode = match lookup_inode_at_path(&mut volume, ZUI_LAUNCHER_APK_PATH)? {
        Some(i) => i,
        None => {
            return Ok(CleanLauncherOutcome::NotApplicable {
                reason: "/system/priv-app/ZuiLauncher/ZuiLauncher.apk not found in system.img"
                    .to_string(),
            });
        }
    };
    if !inode.is_file() {
        return Ok(CleanLauncherOutcome::NotApplicable {
            reason: "/system/priv-app/ZuiLauncher/ZuiLauncher.apk is not a regular file"
                .to_string(),
        });
    }
    let (mut apk_bytes, apk_extents) = inode
        .open_read_with_extents(&mut volume)
        .map_err(|e| anyhow!("Failed to read ZuiLauncher.apk from system.img: {e}"))?;
    let block_size = volume.block_size;
    drop(volume);
    if apk_extents.is_empty() {
        return Ok(CleanLauncherOutcome::NotApplicable {
            reason: "ZuiLauncher.apk has no extents (inline data not supported here)".to_string(),
        });
    }

    // 2. Parse the APK zip and select the STORED `classes*.dex` entries.
    //    Modern APKs store dex uncompressed and page-aligned, so the raw
    //    dex bytes sit directly in the zip's local file data and can be
    //    patched + CRC'd in place. Skip any DEFLATE / data-descriptor /
    //    zip64 entry (an in-place same-size patch is only valid for
    //    STORED entries).
    let zip = parse_zip_central_directory(&apk_bytes)?;
    let dex_entries: Vec<ZipEntry> = zip
        .entries
        .iter()
        .filter(|e| e.name.ends_with(".dex"))
        .filter(|e| !(e.compression_method != 0 || e.uses_data_descriptor || e.is_zip64))
        .filter(|e| e.data_start + e.compressed_size <= apk_bytes.len())
        .cloned()
        .collect();

    let mut row_methods_forced = 0usize;
    let mut prc_methods_forced = 0usize;
    let mut patched_dex_entries: Vec<String> = Vec::new();

    // 3. Each target class lives in exactly one `classes*.dex`, but we
    //    don't hardcode which — run every target against every dex and let
    //    the class_def lookup decide.
    for entry in &dex_entries {
        let dex_off = entry.data_start;
        let dex_end = dex_off + entry.compressed_size;
        let counts = {
            let dex = &mut apk_bytes[dex_off..dex_end];
            if dex.len() < 0x70 {
                continue;
            }
            patch_targets_in_dex(dex)?
        };
        if counts.any() {
            row_methods_forced += counts.row_forced;
            prc_methods_forced += counts.prc_forced;
            {
                let dex = &mut apk_bytes[dex_off..dex_end];
                recompute_dex_header_sums(dex);
            }
            let new_crc = crc32_ieee(&apk_bytes[dex_off..dex_end]);
            write_u32_le(&mut apk_bytes, entry.local_header_crc_offset, new_crc);
            write_u32_le(&mut apk_bytes, entry.cd_crc_offset, new_crc);
            patched_dex_entries.push(entry.name.clone());
        }
    }

    if row_methods_forced + prc_methods_forced == 0 {
        return Ok(CleanLauncherOutcome::NotApplicable {
            reason: "no clean-launcher predicate methods found in ZuiLauncher.apk \
                     (different ROM build or refactored classes)"
                .to_string(),
        });
    }

    // 4. Write the patched APK back over its ext4 extents (byte length
    //    unchanged).
    write_via_extents(system_image, &apk_bytes, &apk_extents, block_size)?;

    Ok(CleanLauncherOutcome::Patched(CleanLauncherPatch {
        row_methods_forced,
        prc_methods_forced,
        patched_dex_entries,
    }))
}

/// Per-dex tally of the forced predicate methods.
struct DexPatchCounts {
    row_forced: usize,
    prc_forced: usize,
}

impl DexPatchCounts {
    fn any(&self) -> bool {
        self.row_forced > 0 || self.prc_forced > 0
    }
}

/// Force every [`BOOL_TARGETS`] method defined in this `classes*.dex` slice
/// to its constant. A target whose class isn't defined here is skipped, so
/// a dex that carries none returns an all-zero tally and is left untouched.
/// The slice length is preserved; the caller recomputes the dex header sums
/// + zip CRC when `any()` is true.
fn patch_targets_in_dex(dex: &mut [u8]) -> Result<DexPatchCounts> {
    let h = read_dex_header(dex);
    let mut row_forced = 0usize;
    let mut prc_forced = 0usize;
    for target in BOOL_TARGETS {
        // All targets are `static ()Z` (boolean, no parameters).
        let Some(code_off) = find_method_code_off(
            dex,
            &h,
            target.class_descriptor,
            target.method_name,
            "Z",
            &[],
        )?
        else {
            continue;
        };
        if force_method_return_bool(dex, code_off, target.value)? {
            if target.is_row {
                row_forced += 1;
            } else {
                prc_forced += 1;
            }
        }
    }
    Ok(DexPatchCounts {
        row_forced,
        prc_forced,
    })
}

// ---------------------------------------------------------------------------
// dex header + method-table helpers
// ---------------------------------------------------------------------------

struct DexHeader {
    string_ids_size: usize,
    string_ids_off: usize,
    type_ids_size: usize,
    type_ids_off: usize,
    proto_ids_size: usize,
    proto_ids_off: usize,
    method_ids_size: usize,
    method_ids_off: usize,
    class_defs_size: usize,
    class_defs_off: usize,
}

fn read_dex_header(dex: &[u8]) -> DexHeader {
    DexHeader {
        string_ids_size: read_u32_le(dex, 0x38) as usize,
        string_ids_off: read_u32_le(dex, 0x3C) as usize,
        type_ids_size: read_u32_le(dex, 0x40) as usize,
        type_ids_off: read_u32_le(dex, 0x44) as usize,
        proto_ids_size: read_u32_le(dex, 0x48) as usize,
        proto_ids_off: read_u32_le(dex, 0x4C) as usize,
        method_ids_size: read_u32_le(dex, 0x58) as usize,
        method_ids_off: read_u32_le(dex, 0x5C) as usize,
        class_defs_size: read_u32_le(dex, 0x60) as usize,
        class_defs_off: read_u32_le(dex, 0x64) as usize,
    }
}

/// Walk a class_data_item's direct + virtual method tables, returning
/// `(method_idx, code_off)` for every method with a non-zero code_off.
/// `method_idx` is reconstructed from the per-section cumulative
/// `method_idx_diff` ULEB128 (resets between the direct and virtual
/// sections per the dex spec). Mirrors the equivalent walk in
/// `fuck_lgsi::zui_settings_dex`.
fn collect_method_code_offs(dex: &[u8], class_data_off: usize) -> Result<Vec<(u32, usize)>> {
    let mut p = class_data_off;
    let static_fields_size = dex_walker::read_uleb128(dex, &mut p)?;
    let instance_fields_size = dex_walker::read_uleb128(dex, &mut p)?;
    let direct_methods_size = dex_walker::read_uleb128(dex, &mut p)?;
    let virtual_methods_size = dex_walker::read_uleb128(dex, &mut p)?;
    for _ in 0..(static_fields_size + instance_fields_size) {
        let _ = dex_walker::read_uleb128(dex, &mut p)?;
        let _ = dex_walker::read_uleb128(dex, &mut p)?;
    }
    let mut out = Vec::new();
    for size in [direct_methods_size, virtual_methods_size] {
        let mut method_idx_acc: u64 = 0;
        for _ in 0..size {
            let diff = dex_walker::read_uleb128(dex, &mut p)?;
            method_idx_acc += diff;
            let _access = dex_walker::read_uleb128(dex, &mut p)?;
            let code_off = dex_walker::read_uleb128(dex, &mut p)? as usize;
            if code_off != 0 {
                out.push((method_idx_acc as u32, code_off));
            }
        }
    }
    Ok(out)
}

/// Resolve the `code_item` offset of the method exactly identified by
/// `class_descriptor.method_name(params...)ret` — matched by the full
/// `method_ids` index (class + name + prototype), not by name alone. This
/// disambiguates obfuscated / overloaded methods: only the overload whose
/// prototype matches is rewritten. Returns `None` when the class isn't
/// defined in this dex, the prototype isn't present, or the method has no
/// code.
fn find_method_code_off(
    dex: &[u8],
    h: &DexHeader,
    class_descriptor: &str,
    method_name: &str,
    ret_descriptor: &str,
    params: &[&str],
) -> Result<Option<usize>> {
    let Some(class_type_idx) = dex_walker::find_type_idx(
        dex,
        h.string_ids_size,
        h.string_ids_off,
        h.type_ids_size,
        h.type_ids_off,
        class_descriptor,
    )?
    else {
        return Ok(None);
    };
    let Some(name_idx) =
        dex_walker::find_string_idx_strict(dex, h.string_ids_size, h.string_ids_off, method_name)?
    else {
        return Ok(None);
    };
    let Some(proto_idx) = dex_walker::find_proto_idx(
        dex,
        h.string_ids_size,
        h.string_ids_off,
        h.type_ids_size,
        h.type_ids_off,
        h.proto_ids_size,
        h.proto_ids_off,
        ret_descriptor,
        params,
    )?
    else {
        return Ok(None);
    };
    let Some(want_method_idx) = dex_walker::find_method_idx(
        dex,
        h.method_ids_size,
        h.method_ids_off,
        class_type_idx,
        name_idx,
        proto_idx,
    )?
    else {
        return Ok(None);
    };
    let Some(class_data_off) =
        dex_walker::find_class_data_off(dex, h.class_defs_size, h.class_defs_off, class_type_idx)?
    else {
        return Ok(None);
    };
    for (method_idx, code_off) in collect_method_code_offs(dex, class_data_off)? {
        if method_idx == want_method_idx {
            return Ok(Some(code_off));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// patch primitive: force a `()Z` method body to a constant
// ---------------------------------------------------------------------------

/// Rewrite the body of the method at `code_off` (a `()Z` method) to
/// `const/4 v0, #value` + `return v0`, padding the remainder of the
/// overwritten instructions with `nop`. Returns `false` (leaving the dex
/// untouched) when the method has no registers or is too short to hold the
/// 4-byte replacement.
fn force_method_return_bool(dex: &mut [u8], code_off: usize, value: bool) -> Result<bool> {
    if code_off + 16 > dex.len() {
        return Ok(false);
    }
    // registers_size @ code_off+0 (u16). `const/4 v0` needs v0 to exist.
    if read_u16_le(dex, code_off) < 1 {
        return Ok(false);
    }
    let insns_size = read_u32_le(dex, code_off + 12) as usize;
    let insns_off = code_off + 16;
    let insns_end = match insns_off.checked_add(insns_size.checked_mul(2).unwrap_or(0)) {
        Some(e) if e <= dex.len() => e,
        _ => return Ok(false),
    };

    // Replacement is 4 bytes (2 code units):
    //   12 0L    const/4 v0, #+L   (L = 1 for true, 0 for false)
    //   0F 00    return v0
    const SEQ_LEN: usize = 4;

    // Overwrite whole instructions from the method start until at least
    // SEQ_LEN bytes are covered, so no partial instruction is left behind.
    let mut cover_end = insns_off;
    while cover_end < insns_off + SEQ_LEN {
        if cover_end + 1 >= insns_end {
            return Ok(false);
        }
        let opcode = dex[cover_end];
        let width_units = dex_walker::insn_width_units(opcode);
        if width_units == 0 {
            return Ok(false);
        }
        let next = cover_end + width_units as usize * 2;
        if next > insns_end {
            return Ok(false);
        }
        cover_end = next;
    }

    let lit: u8 = if value { 1 } else { 0 };
    let b = &mut dex[insns_off..cover_end];
    b[0] = 0x12; // const/4 vA, #+B
    b[1] = lit << 4; // B = lit (high nibble), A = v0 (low nibble = 0)
    b[2] = 0x0F; // return vAA
    b[3] = 0x00; // v0
    for pad in b.iter_mut().skip(SEQ_LEN) {
        *pad = 0x00; // nop
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const4_nibble_encoding_true_and_false() {
        // const/4 v0, #1 → 12 10 ; const/4 v0, #0 → 12 00
        let lit_true: u8 = 1 << 4;
        let lit_false: u8 = 0 << 4;
        assert_eq!(lit_true, 0x10);
        assert_eq!(lit_false, 0x00);
    }

    /// End-to-end check against real ZuiLauncher dex files. Set
    /// `DYNOBOX_ZUILAUNCHER_DEX_DIR` to a directory containing the
    /// extracted `classes.dex` … `classes3.dex`; the test asserts the two
    /// `isZuiRow` bodies and the `isIsShowPrcGlobalSearch` body are all
    /// forced, and that the dex header sums recompute cleanly.
    #[test]
    fn predicates_forced_on_real_dex_when_available() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUILAUNCHER_DEX_DIR") else {
            return;
        };
        let dir = std::path::Path::new(&dir);
        let mut total_row = 0usize;
        let mut total_prc = 0usize;
        for name in ["classes.dex", "classes2.dex", "classes3.dex"] {
            let path = dir.join(name);
            let Ok(mut dex) = std::fs::read(&path) else {
                continue;
            };
            let counts = patch_targets_in_dex(&mut dex).expect("patch walk");
            if counts.any() {
                recompute_dex_header_sums(&mut dex);
            }
            total_row += counts.row_forced;
            total_prc += counts.prc_forced;
        }
        // Two isZuiRow definitions (Utilities + GraphicsUtils) and one PRC
        // predicate (isIsShowPrcGlobalSearch).
        assert_eq!(total_row, 2, "expected both isZuiRow bodies forced");
        assert_eq!(total_prc, 1, "expected isIsShowPrcGlobalSearch forced");
    }
}
