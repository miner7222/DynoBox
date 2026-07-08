//! Reusable, size-preserving Dalvik bytecode patch primitives.
//!
//! These operate on a raw `classes*.dex` slice in place (no growth), so a
//! STORED dex entry inside an APK can be patched and its header sums + zip
//! CRC recomputed without repacking. Two primitives cover the region/flag
//! rewrites DynoBox ships as external `.dbp` patches:
//!
//! * [`force_method_return_bool`] — replace a `()Z`-style method body with
//!   `const/4 v0, #lit` + `return v0` (the rest of the overwritten
//!   instructions padded with `nop`). Forces a predicate method to a
//!   constant for every caller.
//! * [`force_invoke_const_bool`] — rewrite every
//!   `invoke-static {}, target()Z` + `move-result vAA` site inside the
//!   methods of a scan class into `const/16 vAA, #lit` + 2×`nop`. Forces a
//!   specific boolean getter's result only at the call sites within one
//!   class (optionally one method), leaving unrelated callers untouched.
//!
//! Both mirror the byte-rewrite shapes proven in `fuck_lgsi`; the dex table
//! resolvers are the `pub(crate)` `fuck_lgsi::dex_walker` helpers.

use anyhow::{Result, anyhow};

use crate::fuck_lgsi::{dex_walker, read_u16_le, read_u32_le};

// ---------------------------------------------------------------------------
// JVM method descriptor parsing
// ---------------------------------------------------------------------------

/// Split a JVM method descriptor like `"(Landroid/content/Context;)Z"` into
/// its return descriptor (`"Z"`) and parameter field descriptors
/// (`["Landroid/content/Context;"]`). Returns `None` for a malformed
/// descriptor.
pub fn parse_method_descriptor(desc: &str) -> Option<(String, Vec<String>)> {
    let bytes = desc.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut i = 1usize;
    let mut params = Vec::new();
    while i < bytes.len() && bytes[i] != b')' {
        let start = i;
        // Array dimensions.
        while i < bytes.len() && bytes[i] == b'[' {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        match bytes[i] {
            b'L' => {
                // Object type: read through the terminating ';'.
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                if i >= bytes.len() {
                    return None;
                }
                i += 1; // consume ';'
            }
            b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
                i += 1;
            }
            _ => return None,
        }
        params.push(desc[start..i].to_string());
    }
    if i >= bytes.len() || bytes[i] != b')' {
        return None;
    }
    let ret = &desc[i + 1..];
    if ret.is_empty() {
        return None;
    }
    Some((ret.to_string(), params))
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
/// sections per the dex spec).
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

/// Resolve `method_idx` to its method-name string, or `None` when the idx is
/// out of bounds / unreadable.
fn method_name_of_idx(dex: &[u8], h: &DexHeader, method_idx: u32) -> Result<Option<String>> {
    if (method_idx as usize) >= h.method_ids_size {
        return Ok(None);
    }
    let method_off = h.method_ids_off + (method_idx as usize) * 8;
    if method_off + 8 > dex.len() {
        return Ok(None);
    }
    let name_idx = read_u32_le(dex, method_off + 4);
    dex_walker::read_string_at_idx(dex, h.string_ids_size, h.string_ids_off, name_idx)
}

/// Resolve the method idx for `class.method(params...)ret` referenced in this
/// dex, or `None` when any component isn't present.
fn resolve_method_idx(
    dex: &[u8],
    h: &DexHeader,
    class_descriptor: &str,
    method_name: &str,
    ret_descriptor: &str,
    params: &[&str],
) -> Result<Option<u32>> {
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
    dex_walker::find_method_idx(
        dex,
        h.method_ids_size,
        h.method_ids_off,
        class_type_idx,
        name_idx,
        proto_idx,
    )
}

/// Resolve the `code_item` offset of the method exactly identified by
/// `class.method(params...)ret` — matched by full method idx (class + name +
/// prototype), which disambiguates obfuscated / overloaded methods. Returns
/// `None` when the class isn't defined in this dex, the prototype isn't
/// present, or the method has no code.
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
    let Some(want_method_idx) = resolve_method_idx(
        dex,
        h,
        class_descriptor,
        method_name,
        ret_descriptor,
        params,
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
// primitive 1: force a `()Z` method body to a constant
// ---------------------------------------------------------------------------

/// Force the `()Z`-shaped method `class.method(params...)ret` to always
/// return `value`, by rewriting its body to `const/4 v0, #lit` +
/// `return v0` (nop-padded). `ret_descriptor` must be `"Z"` (boolean).
/// Returns `true` when the rewrite landed, `false` when the class/method
/// isn't in this dex, the return type isn't boolean, or the method has no
/// registers / is too short.
pub fn force_method_return_bool(
    dex: &mut [u8],
    class_descriptor: &str,
    method_name: &str,
    ret_descriptor: &str,
    params: &[&str],
    value: bool,
) -> Result<bool> {
    if ret_descriptor != "Z" {
        return Err(anyhow!(
            "force_method_return_bool requires a boolean (Z) return, got `{ret_descriptor}`"
        ));
    }
    let h = read_dex_header(dex);
    let Some(code_off) = find_method_code_off(
        dex,
        &h,
        class_descriptor,
        method_name,
        ret_descriptor,
        params,
    )?
    else {
        return Ok(false);
    };
    rewrite_method_body_const_bool(dex, code_off, value)
}

/// Rewrite the body of the method at `code_off` to `const/4 v0, #value` +
/// `return v0`, padding the remainder of the overwritten instructions with
/// `nop`. Returns `false` (dex untouched) when the method has no registers
/// or is too short.
fn rewrite_method_body_const_bool(dex: &mut [u8], code_off: usize, value: bool) -> Result<bool> {
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
    let Some(cover_end) = cover_whole_instructions(dex, insns_off, insns_end, SEQ_LEN) else {
        return Ok(false);
    };

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

// ---------------------------------------------------------------------------
// primitive 2: force an invoke-static bool getter's result at call sites
// ---------------------------------------------------------------------------

/// Rewrite every `invoke-static {}, target_class.target_method(params...)ret`
/// immediately followed by `move-result vAA` into `const/16 vAA, #lit` plus
/// two `nop`s, but only inside the methods of `scan_class` (optionally
/// narrowed to `scan_method`). Returns the number of sites rewritten (0 when
/// the scan class or target method isn't present in this dex).
///
/// `ret_descriptor` must be `"Z"` (boolean getter). `scan_method`, when set,
/// filters by method name only — over-matching an overload is harmless since
/// only invoke sites of the exact target method idx are rewritten.
#[allow(clippy::too_many_arguments)]
pub fn force_invoke_const_bool(
    dex: &mut [u8],
    scan_class: &str,
    scan_method: Option<&str>,
    target_class: &str,
    target_method: &str,
    ret_descriptor: &str,
    params: &[&str],
    value: bool,
) -> Result<usize> {
    if ret_descriptor != "Z" {
        return Err(anyhow!(
            "force_invoke_const_bool requires a boolean (Z) getter, got `{ret_descriptor}`"
        ));
    }
    let h = read_dex_header(dex);
    let Some(scan_type_idx) = dex_walker::find_type_idx(
        dex,
        h.string_ids_size,
        h.string_ids_off,
        h.type_ids_size,
        h.type_ids_off,
        scan_class,
    )?
    else {
        return Ok(0);
    };
    let Some(target_method_idx) =
        resolve_method_idx(dex, &h, target_class, target_method, ret_descriptor, params)?
    else {
        return Ok(0);
    };
    let Some(class_data_off) =
        dex_walker::find_class_data_off(dex, h.class_defs_size, h.class_defs_off, scan_type_idx)?
    else {
        return Ok(0);
    };

    let literal: u8 = if value { 1 } else { 0 };
    let mut sites = 0usize;
    for (method_idx, code_off) in collect_method_code_offs(dex, class_data_off)? {
        if let Some(want) = scan_method {
            if method_name_of_idx(dex, &h, method_idx)?.as_deref() != Some(want) {
                continue;
            }
        }
        sites += rewrite_invoke_sites(dex, code_off, target_method_idx, literal)?;
    }
    Ok(sites)
}

/// Walk one method's instruction stream and rewrite each
/// `invoke-static {}, method@target_method_idx` (opcode 0x71) immediately
/// followed by `move-result vAA` (opcode 0x0A) into `const/16 vAA, #literal`
/// (opcode 0x13) + 2×`nop`. Same-size, in place.
fn rewrite_invoke_sites(
    dex: &mut [u8],
    code_off: usize,
    target_method_idx: u32,
    literal: u8,
) -> Result<usize> {
    if code_off + 16 > dex.len() {
        return Ok(0);
    }
    let insns_size = read_u32_le(dex, code_off + 12) as usize;
    let insns_off = code_off + 16;
    let insns_end = match insns_off.checked_add(insns_size.checked_mul(2).unwrap_or(0)) {
        Some(e) if e <= dex.len() => e,
        _ => return Ok(0),
    };

    let mut sites = 0usize;
    let mut pc = insns_off;
    while pc + 1 < insns_end {
        let opcode = dex[pc];
        let width_units = dex_walker::insn_width_units(opcode);
        if width_units == 0 {
            // Unknown opcode: bail rather than mis-stride and corrupt the dex.
            return Ok(sites);
        }
        let width = width_units as usize * 2;
        if pc + width > insns_end {
            return Ok(sites);
        }
        if opcode == 0x71 && pc + 8 <= insns_end {
            let method_idx = u32::from(read_u16_le(dex, pc + 2));
            if method_idx == target_method_idx && dex[pc + 6] == 0x0A {
                let aa = dex[pc + 7];
                dex[pc] = 0x13; // const/16 vAA, #+lit
                dex[pc + 1] = aa;
                dex[pc + 2] = literal;
                dex[pc + 3] = 0x00;
                dex[pc + 4] = 0x00; // nop
                dex[pc + 5] = 0x00;
                dex[pc + 6] = 0x00; // nop
                dex[pc + 7] = 0x00;
                sites += 1;
                pc += 8;
                continue;
            }
        }
        pc += width;
    }
    Ok(sites)
}

/// Advance from `start` over whole instructions until at least `min_bytes`
/// are covered, so a replacement never leaves a partial instruction behind.
/// Returns the covering end offset, or `None` when the stream is too short or
/// contains an unknown opcode.
fn cover_whole_instructions(
    dex: &[u8],
    start: usize,
    insns_end: usize,
    min_bytes: usize,
) -> Option<usize> {
    let mut cover_end = start;
    while cover_end < start + min_bytes {
        if cover_end + 1 >= insns_end {
            return None;
        }
        let width_units = dex_walker::insn_width_units(dex[cover_end]);
        if width_units == 0 {
            return None;
        }
        let next = cover_end + width_units as usize * 2;
        if next > insns_end {
            return None;
        }
        cover_end = next;
    }
    Some(cover_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_descriptor_no_args_bool() {
        assert_eq!(parse_method_descriptor("()Z"), Some(("Z".into(), vec![])));
    }

    #[test]
    fn parse_descriptor_one_object_arg() {
        assert_eq!(
            parse_method_descriptor("(Landroid/content/Context;)Ljava/util/ArrayList;"),
            Some((
                "Ljava/util/ArrayList;".into(),
                vec!["Landroid/content/Context;".into()]
            ))
        );
    }

    #[test]
    fn parse_descriptor_array_and_primitive_args() {
        assert_eq!(
            parse_method_descriptor("([Ljava/lang/String;IJ)V"),
            Some((
                "V".into(),
                vec!["[Ljava/lang/String;".into(), "I".into(), "J".into()]
            ))
        );
    }

    #[test]
    fn parse_descriptor_rejects_malformed() {
        assert_eq!(parse_method_descriptor("Z"), None);
        assert_eq!(parse_method_descriptor("()"), None);
        assert_eq!(parse_method_descriptor("(L)Z"), None);
    }

    /// `force_method_return_bool` lands on the real ZuiLauncher
    /// `Utilities.isZuiRow()`. Set `DYNOBOX_ZUILAUNCHER_DEX_DIR`.
    #[test]
    fn method_const_lands_on_real_zuilauncher() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUILAUNCHER_DEX_DIR") else {
            return;
        };
        let dir = std::path::Path::new(&dir);
        let mut hits = 0;
        for name in ["classes.dex", "classes2.dex", "classes3.dex"] {
            let Ok(mut dex) = std::fs::read(dir.join(name)) else {
                continue;
            };
            if force_method_return_bool(
                &mut dex,
                "Lcom/android/launcher3/Utilities;",
                "isZuiRow",
                "Z",
                &[],
                true,
            )
            .expect("patch")
            {
                hits += 1;
            }
        }
        assert_eq!(
            hits, 1,
            "Utilities.isZuiRow should be forced in exactly one dex"
        );
    }

    /// `force_invoke_const_bool` rewrites the real ZuiSettings
    /// `LocaleListEditor` PRC gate. Set `DYNOBOX_ZUISETTINGS_DEX_DIR`.
    #[test]
    fn invoke_const_lands_on_real_zuisettings() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUISETTINGS_DEX_DIR") else {
            return;
        };
        let dir = std::path::Path::new(&dir);
        let mut sites = 0usize;
        for name in [
            "classes.dex",
            "classes2.dex",
            "classes3.dex",
            "classes4.dex",
            "classes5.dex",
            "classes6.dex",
        ] {
            let Ok(mut dex) = std::fs::read(dir.join(name)) else {
                continue;
            };
            sites += force_invoke_const_bool(
                &mut dex,
                "Lcom/android/settings/localepicker/LocaleListEditor;",
                None,
                "Lcom/lenovo/common/utils/LenovoUtils;",
                "isPrcVersion",
                "Z",
                &[],
                false,
            )
            .expect("patch");
        }
        assert!(
            sites >= 1,
            "LocaleListEditor.isPrcVersion invoke sites should be rewritten"
        );
    }
}
