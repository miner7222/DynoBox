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
//! * [`force_method_return_int`] — replace an integer-returning method body
//!   with the smallest suitable Dalvik `const` encoding + `return v0`.
//! * [`force_invoke_const_bool`] — rewrite every
//!   `invoke-static {}, target()Z` + `move-result vAA` site inside the
//!   methods of a scan class into `const/16 vAA, #lit` + 2×`nop`. Forces a
//!   specific boolean getter's result only at the call sites within one
//!   class (optionally one method), leaving unrelated callers untouched.
//! * [`force_field_const_bool`] — rewrite scoped `iget-boolean` reads of one
//!   exact field to a constant without changing the field or other callers.
//! * [`redirect_intent_action_to_broadcast`] — retarget an existing Intent
//!   action string reference and replace the matching `startActivity` with a
//!   `sendBroadcast`, without editing the sorted dex string-data table.
//! * [`force_method_broadcast_finish`] — rewrite an Activity method body to
//!   call `super`, `finish()`, broadcast an existing action string, and return.
//! * [`force_nop_anchored_invoke`] — nop the first
//!   `target_class.target_method(...)` invoke (whose result is discarded)
//!   that follows a specific constant load inside one scan method. Drops a
//!   single imperative `List.add`/`Map.put`-style call site without
//!   disturbing the surrounding method.
//!
//! Both mirror the byte-rewrite shapes proven in `fuck_lgsi`; the dex table
//! resolvers are the `pub(crate)` `fuck_lgsi::dex_walker` helpers.

use std::collections::BTreeSet;

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
    field_ids_size: usize,
    field_ids_off: usize,
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
        field_ids_size: read_u32_le(dex, 0x50) as usize,
        field_ids_off: read_u32_le(dex, 0x54) as usize,
        method_ids_size: read_u32_le(dex, 0x58) as usize,
        method_ids_off: read_u32_le(dex, 0x5C) as usize,
        class_defs_size: read_u32_le(dex, 0x60) as usize,
        class_defs_off: read_u32_le(dex, 0x64) as usize,
    }
}

/// Resolve the exact field id for `class_descriptor.field_name:type_descriptor`.
fn resolve_field_idx(
    dex: &[u8],
    h: &DexHeader,
    class_descriptor: &str,
    field_name: &str,
    type_descriptor: &str,
) -> Result<Option<u32>> {
    let Some(class_idx) = dex_walker::find_type_idx(
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
    let Some(type_idx) = dex_walker::find_type_idx(
        dex,
        h.string_ids_size,
        h.string_ids_off,
        h.type_ids_size,
        h.type_ids_off,
        type_descriptor,
    )?
    else {
        return Ok(None);
    };
    let Some(name_idx) =
        dex_walker::find_string_idx_strict(dex, h.string_ids_size, h.string_ids_off, field_name)?
    else {
        return Ok(None);
    };

    for idx in 0..h.field_ids_size {
        let off = h.field_ids_off + idx * 8;
        if off + 8 > dex.len() {
            return Ok(None);
        }
        if u32::from(read_u16_le(dex, off)) == class_idx
            && u32::from(read_u16_le(dex, off + 2)) == type_idx
            && read_u32_le(dex, off + 4) == name_idx
        {
            return Ok(Some(idx as u32));
        }
    }
    Ok(None)
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

/// Whether `code_off` is referenced by more than one method entry across the
/// whole dex. R8/redex deduplicate identical code items — every trivial
/// `return 0` / `return false` / `return-void` body can collapse onto a single
/// shared item — so rewriting such an item in place silently changes *every*
/// method that points to it. In particular, forcing a shared `()I` method to a
/// non-boolean constant (e.g. `getAvailabilityStatus` → 3) corrupts a `()Z`
/// sharer (`ImmutableMap.isHashCodeFast`) into a `VerifyError`. Body-rewriting
/// ops must refuse a shared item. Best-effort: unparseable class_data is skipped.
fn code_off_is_shared(dex: &[u8], h: &DexHeader, code_off: usize) -> Result<bool> {
    let mut seen = 0usize;
    for idx in 0..h.class_defs_size {
        let entry_off = h.class_defs_off + idx * 32;
        if entry_off + 32 > dex.len() {
            break;
        }
        // class_data_off is at class_def + 24.
        let class_data_off = read_u32_le(dex, entry_off + 24) as usize;
        if class_data_off == 0 || class_data_off >= dex.len() {
            continue;
        }
        let Ok(offs) = collect_method_code_offs(dex, class_data_off) else {
            continue;
        };
        for (_m, off) in offs {
            if off == code_off {
                seen += 1;
                if seen >= 2 {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
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
    // Refuse a deduplicated (shared) code item — rewriting it would corrupt the
    // other methods that share it.
    if code_off_is_shared(dex, &h, code_off)? {
        return Ok(false);
    }
    rewrite_method_body_const_bool(dex, code_off, value)
}

/// Rewrite the body of the method at `code_off` to `const/4 v0, #value` +
/// `return v0`, padding the remainder of the overwritten instructions with
/// `nop`. Returns `false` (dex untouched) when the method has no registers
/// or is too short.
fn rewrite_method_body_const_bool(dex: &mut [u8], code_off: usize, value: bool) -> Result<bool> {
    rewrite_method_body_const_int(dex, code_off, i32::from(value))
}

/// Force the integer-returning method `class.method(params...)ret` to always
/// return `value`. `ret_descriptor` must be `"I"`.
/// Returns `true` when the rewrite landed, `false` when the class/method
/// isn't in this dex, or its code item cannot hold the replacement.
pub fn force_method_return_int(
    dex: &mut [u8],
    class_descriptor: &str,
    method_name: &str,
    ret_descriptor: &str,
    params: &[&str],
    value: i32,
) -> Result<bool> {
    if ret_descriptor != "I" {
        return Err(anyhow!(
            "force_method_return_int requires an integer (I) return, got `{ret_descriptor}`"
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
    // Refuse a deduplicated (shared) code item (see `code_off_is_shared`).
    if code_off_is_shared(dex, &h, code_off)? {
        return Ok(false);
    }
    rewrite_method_body_const_int(dex, code_off, value)
}

/// Rewrite the body at `code_off` to the smallest constant-load instruction
/// that can represent `value`, followed by `return v0`.
fn rewrite_method_body_const_int(dex: &mut [u8], code_off: usize, value: i32) -> Result<bool> {
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

    let mut replacement = [0u8; 8];
    let replacement_len = if (-8..=7).contains(&value) {
        replacement[0] = 0x12; // const/4 vA, #+B
        replacement[1] = ((value as u8) & 0x0f) << 4; // B, v0
        replacement[2] = 0x0f; // return vAA
        4
    } else if i16::try_from(value).is_ok() {
        replacement[0] = 0x13; // const/16 vAA, #+BBBB
        replacement[2..4].copy_from_slice(&(value as i16).to_le_bytes());
        replacement[4] = 0x0f;
        6
    } else {
        replacement[0] = 0x14; // const vAA, #+BBBBBBBB
        replacement[2..6].copy_from_slice(&value.to_le_bytes());
        replacement[6] = 0x0f;
        8
    };
    let Some(cover_end) = cover_whole_instructions(dex, insns_off, insns_end, replacement_len)
    else {
        return Ok(false);
    };

    let b = &mut dex[insns_off..cover_end];
    b[..replacement_len].copy_from_slice(&replacement[..replacement_len]);
    for pad in b.iter_mut().skip(replacement_len) {
        *pad = 0x00; // nop
    }
    Ok(true)
}

/// Force the `V`-returning method `class.method(params...)V` to do nothing:
/// rewrite its body to `return-void` (the rest of the first instruction
/// nop-padded, `tries_size` zeroed). `ret_descriptor` must be `"V"` (void).
/// Returns `true` when the rewrite landed, `false` when the class/method isn't
/// in this dex or the return type isn't void.
pub fn force_method_return_void(
    dex: &mut [u8],
    class_descriptor: &str,
    method_name: &str,
    ret_descriptor: &str,
    params: &[&str],
) -> Result<bool> {
    if ret_descriptor != "V" {
        return Err(anyhow!(
            "force_method_return_void requires a void (V) return, got `{ret_descriptor}`"
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
    // Refuse a deduplicated (shared) code item (see `code_off_is_shared`).
    if code_off_is_shared(dex, &h, code_off)? {
        return Ok(false);
    }
    rewrite_method_body_return_void(dex, code_off)
}

/// Rewrite the body at `code_off` so its first instruction is `return-void`,
/// nop-padding the remainder of that covered instruction. `tries_size` and the
/// trailing try/handler bytes are left untouched on purpose: `return-void`
/// cannot throw, so with it at address 0 the whole original body — including any
/// catch handler — becomes unreachable dead code that ART never verifies, while
/// keeping the code item byte-identical in size. Zeroing `tries_size` while the
/// handler bytes remain would instead desync the dex verifier's contiguous
/// code-item walk and get the entire dex rejected. Returns `false` when the code
/// item is too short.
fn rewrite_method_body_return_void(dex: &mut [u8], code_off: usize) -> Result<bool> {
    if code_off + 16 > dex.len() {
        return Ok(false);
    }
    let insns_size = read_u32_le(dex, code_off + 12) as usize;
    let insns_off = code_off + 16;
    let insns_end = match insns_off.checked_add(insns_size.checked_mul(2).unwrap_or(0)) {
        Some(e) if e <= dex.len() => e,
        _ => return Ok(false),
    };
    let Some(cover_end) = cover_whole_instructions(dex, insns_off, insns_end, 2) else {
        return Ok(false);
    };
    dex[insns_off] = 0x0e; // return-void
    dex[insns_off + 1] = 0x00;
    for b in dex[insns_off + 2..cover_end].iter_mut() {
        *b = 0x00; // nop
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// primitive 3: rewrite a Fragment.onCreateView to render a hidden (GONE) view
// ---------------------------------------------------------------------------

/// Rewrite `class.method(LayoutInflater, ViewGroup, Bundle) : View` so it
/// inflates `layout_id` (attachToRoot = false) and returns that view after
/// `View.setVisibility(GONE)`. This collapses a statically-embedded
/// `<fragment>` tile without editing the compiled binary layout: the fragment
/// still produces a non-null view — so `<fragment>` inflation does not throw
/// `IllegalStateException` — but the view is `GONE`, so the slot collapses and
/// weighted siblings reflow.
///
/// The emitted body only references method ids a real `onCreateView` already
/// carries (`LayoutInflater.inflate`, `View.setVisibility`), so no new dex ids
/// are added and the edit stays size-preserving (replacement + `nop` padding).
/// Returns `true` when the rewrite landed, `false` when the class/method isn't
/// in this dex or its code item can't be encoded.
pub fn force_fragment_render_gone(
    dex: &mut [u8],
    class_descriptor: &str,
    method_name: &str,
    layout_id: u32,
) -> Result<bool> {
    const ONCREATEVIEW_PARAMS: [&str; 3] = [
        "Landroid/view/LayoutInflater;",
        "Landroid/view/ViewGroup;",
        "Landroid/os/Bundle;",
    ];
    let h = read_dex_header(dex);
    let Some(code_off) = find_method_code_off(
        dex,
        &h,
        class_descriptor,
        method_name,
        "Landroid/view/View;",
        &ONCREATEVIEW_PARAMS,
    )?
    else {
        return Ok(false);
    };
    // Refuse a deduplicated (shared) code item (see `code_off_is_shared`).
    if code_off_is_shared(dex, &h, code_off)? {
        return Ok(false);
    }

    // Framework method ids the emitted body invokes. A genuine `onCreateView`
    // that inflates a layout always carries both, so an absence here means a
    // malformed target rather than a build difference — surface it loudly.
    let inflate_idx = resolve_method_idx(
        dex,
        &h,
        "Landroid/view/LayoutInflater;",
        "inflate",
        "Landroid/view/View;",
        &["I", "Landroid/view/ViewGroup;", "Z"],
    )?
    .ok_or_else(|| anyhow!("dex lacks LayoutInflater.inflate(I,ViewGroup,Z) method id"))?;
    let set_visibility_idx =
        resolve_method_idx(dex, &h, "Landroid/view/View;", "setVisibility", "V", &["I"])?
            .ok_or_else(|| anyhow!("dex lacks View.setVisibility(I) method id"))?;
    if inflate_idx > 0xffff || set_visibility_idx > 0xffff {
        return Err(anyhow!(
            "method id exceeds 16-bit invoke-virtual range (inflate={inflate_idx}, setVisibility={set_visibility_idx})"
        ));
    }

    // Parameters occupy the last `ins_size` registers of `registers_size`.
    let registers_size = u32::from(read_u16_le(dex, code_off));
    let ins_size = u32::from(read_u16_le(dex, code_off + 2));
    if ins_size < 4 || registers_size < ins_size {
        return Ok(false);
    }
    let first_param = registers_size - ins_size; // p0 (this)
    let p_inflater = first_param + 1; // p1: LayoutInflater
    let p_container = first_param + 2; // p2: ViewGroup
    // v0/v1 scratch must exist below the parameters, and every register a 35c
    // invoke names must be nibble-encodable (< 16).
    if first_param < 2 || p_container > 0x0f {
        return Ok(false);
    }
    let (v_view, v_scratch): (u16, u16) = (0, 1);
    let (p1, p2) = (p_inflater as u16, p_container as u16);

    // inflate(layout_id, container, false); view.setVisibility(GONE); return view
    let units: [u16; 14] = [
        0x0014 | (v_view << 8),                             // const v0, #layout_id
        (layout_id & 0xffff) as u16,                        //   literal lo
        (layout_id >> 16) as u16,                           //   literal hi
        0x0012 | (v_scratch << 8),                          // const/4 v1, #0 (attach=false)
        0x6e | (4 << 12),                                   // invoke-virtual {p1,v0,p2,v1}, inflate
        inflate_idx as u16,                                 //   method idx
        p1 | (v_view << 4) | (p2 << 8) | (v_scratch << 12), // C,D,E,F regs
        0x000c | (v_view << 8),                             // move-result-object v0
        0x0013 | (v_scratch << 8),                          // const/16 v1, #8 (View.GONE)
        0x0008,                                             //   literal 8
        0x6e | (2 << 12),                                   // invoke-virtual {v0,v1}, setVisibility
        set_visibility_idx as u16,                          //   method idx
        v_view | (v_scratch << 4),                          //   C,D regs
        0x0011 | (v_view << 8),                             // return-object v0
    ];
    let mut replacement = [0u8; 28];
    for (i, u) in units.iter().enumerate() {
        replacement[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }

    let insns_size = read_u32_le(dex, code_off + 12) as usize;
    let insns_off = code_off + 16;
    let insns_end = match insns_off.checked_add(insns_size.checked_mul(2).unwrap_or(0)) {
        Some(e) if e <= dex.len() => e,
        _ => return Ok(false),
    };
    let Some(cover_end) = cover_whole_instructions(dex, insns_off, insns_end, replacement.len())
    else {
        return Ok(false);
    };

    // The emitted body inflates a layout, which can throw; a leftover catch
    // handler must not intercept that with a register state set up for the old
    // body. Zeroing `tries_size` to disarm it would desync the dex verifier's
    // contiguous code-item walk (see `rewrite_method_body_return_void`), so
    // instead refuse a target that carries try/catch. Real `onCreateView` inflate
    // wrappers here have none.
    if read_u16_le(dex, code_off + 6) != 0 {
        return Ok(false);
    }

    let b = &mut dex[insns_off..cover_end];
    b[..replacement.len()].copy_from_slice(&replacement);
    for pad in b.iter_mut().skip(replacement.len()) {
        *pad = 0x00; // nop
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// primitive 2: force a bool getter's result at call sites
// ---------------------------------------------------------------------------

/// Force every format-35c invoke of `target_class.target_method(params...)Z`
/// (static / virtual / super / direct / interface) immediately followed by
/// `move-result vAA` to the constant `value`, but only inside the methods of
/// `scan_class` (optionally narrowed to `scan_method`). Returns the number of
/// sites rewritten (0 when the scan class or target method isn't present here).
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
    force_invoke_const_scoped(
        dex,
        scan_class,
        scan_method,
        target_class,
        target_method,
        ret_descriptor,
        params,
        i32::from(value),
    )
}

/// Like [`force_invoke_const_bool`] but for an int-returning (`I`) method:
/// forces each `target_class.target_method(params...)I` result to `value` at
/// its call sites inside `scan_class` (optionally `scan_method`). Same-size, in
/// place. Handy to pin a `Settings.*.getInt(...)` gate to a constant.
#[allow(clippy::too_many_arguments)]
pub fn force_invoke_const_int(
    dex: &mut [u8],
    scan_class: &str,
    scan_method: Option<&str>,
    target_class: &str,
    target_method: &str,
    ret_descriptor: &str,
    params: &[&str],
    value: i32,
) -> Result<usize> {
    if ret_descriptor != "I" {
        return Err(anyhow!(
            "force_invoke_const_int requires an int (I) method, got `{ret_descriptor}`"
        ));
    }
    force_invoke_const_scoped(
        dex,
        scan_class,
        scan_method,
        target_class,
        target_method,
        ret_descriptor,
        params,
        value,
    )
}

/// Shared body for [`force_invoke_const_bool`] / [`force_invoke_const_int`]:
/// rewrite `invoke-static … / move-result vAA` → a same-size const load of
/// `value` into vAA at the matching sites within `scan_class`.
#[allow(clippy::too_many_arguments)]
fn force_invoke_const_scoped(
    dex: &mut [u8],
    scan_class: &str,
    scan_method: Option<&str>,
    target_class: &str,
    target_method: &str,
    ret_descriptor: &str,
    params: &[&str],
    value: i32,
) -> Result<usize> {
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

    let mut sites = 0usize;
    for (method_idx, code_off) in collect_method_code_offs(dex, class_data_off)? {
        if let Some(want) = scan_method {
            if method_name_of_idx(dex, &h, method_idx)?.as_deref() != Some(want) {
                continue;
            }
        }
        sites += rewrite_invoke_sites(dex, code_off, target_method_idx, value)?;
    }
    Ok(sites)
}

/// Walk one method's instruction stream and rewrite each format-35c
/// `invoke-* {}, method@target_method_idx` (opcodes 0x6e..=0x72) immediately
/// followed by `move-result vAA` (opcode 0x0A) into a const load of `value`
/// into vAA (`const/16` for i16-range values, else `const`), nop-padded to the
/// original 4 units. Same-size, in place.
fn rewrite_invoke_sites(
    dex: &mut [u8],
    code_off: usize,
    target_method_idx: u32,
    value: i32,
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
        // Any format-35c invoke (0x6e virtual / 0x6f super / 0x70 direct /
        // 0x71 static / 0x72 interface) carries the method idx at pc+2, so match
        // the whole family — a getter is reached by whichever kind its class uses.
        if (0x6e..=0x72).contains(&opcode) && pc + 8 <= insns_end {
            let method_idx = u32::from(read_u16_le(dex, pc + 2));
            if method_idx == target_method_idx && dex[pc + 6] == 0x0A {
                let aa = dex[pc + 7];
                // Overwrite the 4-unit `invoke-* … / move-result vAA` with a
                // same-size const load of `value` into vAA, nop-padded.
                if let Ok(v16) = i16::try_from(value) {
                    dex[pc] = 0x13; // const/16 vAA, #+v16
                    dex[pc + 1] = aa;
                    dex[pc + 2..pc + 4].copy_from_slice(&v16.to_le_bytes());
                    dex[pc + 4..pc + 8].fill(0x00); // 2× nop
                } else {
                    dex[pc] = 0x14; // const vAA, #+value
                    dex[pc + 1] = aa;
                    dex[pc + 2..pc + 6].copy_from_slice(&value.to_le_bytes());
                    dex[pc + 6..pc + 8].fill(0x00); // nop
                }
                sites += 1;
                pc += 8;
                continue;
            }
        }
        pc += width;
    }
    Ok(sites)
}

// ---------------------------------------------------------------------------
// primitive 4: nop a single invoke whose result is discarded, anchored by a
// preceding constant load
// ---------------------------------------------------------------------------

/// Which constant arms the scan before the target invoke is nopped.
#[derive(Debug, Clone, Copy)]
pub enum NopAnchor<'a> {
    Int(i32),
    Str(&'a str),
}

/// Resolved form of [`NopAnchor`] (a string anchor is already turned into a
/// dex string idx) used by the inner instruction walker.
#[derive(Debug, Clone, Copy)]
enum AnchorMatch {
    Int(i32),
    StringIdx(u32),
}

/// Nop the first `target_class.target_method(params...)ret` invoke that
/// follows the `anchor` constant inside `scan_class.scan_method`, but only
/// when that invoke's result is discarded (no following `move-result*`).
/// Size-preserving: the invoke's code units are overwritten with `nop`.
/// Returns the number of sites nopped (0 when the class/method/target/anchor
/// isn't present in this dex).
#[allow(clippy::too_many_arguments)]
pub fn force_nop_anchored_invoke(
    dex: &mut [u8],
    scan_class: &str,
    scan_method: &str,
    target_class: &str,
    target_method: &str,
    ret_descriptor: &str,
    params: &[&str],
    anchor: NopAnchor<'_>,
) -> Result<usize> {
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
    let anchor_match = match anchor {
        NopAnchor::Int(v) => AnchorMatch::Int(v),
        NopAnchor::Str(s) => {
            let Some(idx) =
                dex_walker::find_string_idx_strict(dex, h.string_ids_size, h.string_ids_off, s)?
            else {
                return Ok(0);
            };
            AnchorMatch::StringIdx(idx)
        }
    };
    let Some(class_data_off) =
        dex_walker::find_class_data_off(dex, h.class_defs_size, h.class_defs_off, scan_type_idx)?
    else {
        return Ok(0);
    };

    let mut sites = 0usize;
    for (method_idx, code_off) in collect_method_code_offs(dex, class_data_off)? {
        if method_name_of_idx(dex, &h, method_idx)?.as_deref() != Some(scan_method) {
            continue;
        }
        if code_off + 16 > dex.len() {
            continue;
        }
        let insns_size = read_u32_le(dex, code_off + 12) as usize;
        let insns_off = code_off + 16;
        let insns_end = match insns_off.checked_add(insns_size.checked_mul(2).unwrap_or(0)) {
            Some(e) if e <= dex.len() => e,
            _ => continue,
        };
        sites += rewrite_first_anchored_invoke(
            dex,
            insns_off,
            insns_end,
            target_method_idx,
            anchor_match,
        );
    }
    Ok(sites)
}

/// Decode the `i32` literal loaded by a `const*` instruction at `pc`
/// (`0x12` const/4, `0x13` const/16, `0x14` const, `0x15` const/high16).
/// Returns `None` for any other opcode. Callers must only invoke this once
/// the instruction's full width has been validated to lie within bounds.
fn read_const_int(dex: &[u8], opcode: u8, pc: usize) -> Option<i32> {
    match opcode {
        0x12 => {
            // const/4 vA, #+B: B is the sign-extended high nibble of dex[pc+1].
            let raw = (dex[pc + 1] >> 4) & 0x0f;
            Some(if raw & 0x08 != 0 {
                i32::from(raw) - 16
            } else {
                i32::from(raw)
            })
        }
        0x13 => Some(i32::from(read_u16_le(dex, pc + 2) as i16)),
        0x14 => Some(read_u32_le(dex, pc + 2) as i32),
        0x15 => Some((read_u16_le(dex, pc + 2) as i16 as i32) << 16),
        _ => None,
    }
}

/// Decode the string idx loaded by a `const-string*` instruction at `pc`
/// (`0x1a` const-string, `0x1b` const-string/jumbo). Returns `None` for any
/// other opcode.
fn read_const_string_idx(dex: &[u8], opcode: u8, pc: usize) -> Option<u32> {
    match opcode {
        0x1a => Some(u32::from(read_u16_le(dex, pc + 2))),
        0x1b => Some(read_u32_le(dex, pc + 2)),
        _ => None,
    }
}

/// Walk `dex[insns_off..insns_end]`; arm on the anchor const; nop the next
/// target-idx invoke (opcode `0x6e..=0x72` or `0x74..=0x78`) whose result is
/// not consumed by a following `move-result*` (`0x0a`/`0x0b`/`0x0c`). Once a
/// target invoke has been seen while armed, the scan disarms (nopped or not)
/// so only the invoke immediately following an anchor is ever considered.
/// Stops on an unknown opcode, mirroring [`rewrite_invoke_sites`]. Returns
/// the number of sites nopped.
fn rewrite_first_anchored_invoke(
    dex: &mut [u8],
    insns_off: usize,
    insns_end: usize,
    target_method_idx: u32,
    anchor: AnchorMatch,
) -> usize {
    let mut sites = 0usize;
    let mut armed = false;
    let mut pc = insns_off;
    while pc + 1 < insns_end {
        let opcode = dex[pc];
        let width_units = dex_walker::insn_width_units(opcode);
        if width_units == 0 {
            // Unknown opcode: bail rather than mis-stride and corrupt the dex.
            break;
        }
        let width = width_units as usize * 2;
        if pc + width > insns_end {
            break;
        }

        let arms = match anchor {
            AnchorMatch::Int(want) => read_const_int(dex, opcode, pc) == Some(want),
            AnchorMatch::StringIdx(want) => read_const_string_idx(dex, opcode, pc) == Some(want),
        };
        if arms {
            armed = true;
        }

        let is_target_invoke = matches!(opcode, 0x6e..=0x72 | 0x74..=0x78)
            && u32::from(read_u16_le(dex, pc + 2)) == target_method_idx;
        if armed && is_target_invoke {
            let next_pc = pc + width;
            let has_move_result = next_pc < insns_end && matches!(dex[next_pc], 0x0a..=0x0c);
            if !has_move_result {
                for b in &mut dex[pc..pc + width] {
                    *b = 0x00;
                }
                sites += 1;
            }
            armed = false;
        }

        pc += width;
    }
    sites
}

// ---------------------------------------------------------------------------
// primitive 5: force a scoped boolean field read to a constant
// ---------------------------------------------------------------------------

/// Force reads of one exact boolean instance field to `value` inside the
/// methods of `scan_class` (optionally only `scan_method`). Each matching
/// two-unit `iget-boolean vA, vB, field@CCCC` becomes `const/4 vA, #value`
/// followed by `nop`, so code size and every dex table offset stay unchanged.
///
/// Returns the number of rewritten field-read sites. A missing class, field,
/// or method is a clean no-op.
pub fn force_field_const_bool(
    dex: &mut [u8],
    scan_class: &str,
    scan_method: Option<&str>,
    target_class: &str,
    target_field: &str,
    value: bool,
) -> Result<usize> {
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
    let Some(target_field_idx) = resolve_field_idx(dex, &h, target_class, target_field, "Z")?
    else {
        return Ok(0);
    };
    if target_field_idx > u32::from(u16::MAX) {
        return Ok(0);
    }
    let Some(class_data_off) =
        dex_walker::find_class_data_off(dex, h.class_defs_size, h.class_defs_off, scan_type_idx)?
    else {
        return Ok(0);
    };

    let mut sites = 0usize;
    for (method_idx, code_off) in collect_method_code_offs(dex, class_data_off)? {
        if let Some(want) = scan_method {
            if method_name_of_idx(dex, &h, method_idx)?.as_deref() != Some(want) {
                continue;
            }
        }
        let Some((insns_off, insns_end)) = code_instruction_bounds(dex, code_off) else {
            continue;
        };
        sites +=
            rewrite_field_bool_sites(dex, insns_off, insns_end, target_field_idx as u16, value);
    }
    Ok(sites)
}

fn code_instruction_bounds(dex: &[u8], code_off: usize) -> Option<(usize, usize)> {
    if code_off + 16 > dex.len() {
        return None;
    }
    let insns_size = read_u32_le(dex, code_off + 12) as usize;
    let insns_off = code_off + 16;
    let bytes = insns_size.checked_mul(2)?;
    let insns_end = insns_off.checked_add(bytes)?;
    (insns_end <= dex.len()).then_some((insns_off, insns_end))
}

fn rewrite_field_bool_sites(
    dex: &mut [u8],
    insns_off: usize,
    insns_end: usize,
    target_field_idx: u16,
    value: bool,
) -> usize {
    let mut sites = 0usize;
    let mut pc = insns_off;
    while pc + 1 < insns_end {
        let opcode = dex[pc];
        let width_units = dex_walker::insn_width_units(opcode);
        if width_units == 0 {
            break;
        }
        let width = usize::from(width_units) * 2;
        if pc + width > insns_end {
            break;
        }
        if opcode == 0x55 && width == 4 && read_u16_le(dex, pc + 2) == target_field_idx {
            let result_reg = dex[pc + 1] & 0x0f;
            dex[pc] = 0x12; // const/4
            dex[pc + 1] = result_reg | (u8::from(value) << 4);
            dex[pc + 2] = 0x00; // nop
            dex[pc + 3] = 0x00;
            sites += 1;
        }
        pc += width;
    }
    sites
}

// ---------------------------------------------------------------------------
// primitive 6: redirect an Intent activity launch to an existing broadcast
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IntentRedirectSite {
    string_off: usize,
    string_opcode: u8,
    start_off: usize,
    context_reg: u8,
    intent_reg: u8,
}

fn decode_invoke_35c_registers(dex: &[u8], pc: usize) -> Option<Vec<u8>> {
    if pc + 6 > dex.len() {
        return None;
    }
    let count = usize::from(dex[pc + 1] >> 4);
    if count > 5 {
        return None;
    }
    let regs = [
        dex[pc + 4] & 0x0f,
        dex[pc + 4] >> 4,
        dex[pc + 5] & 0x0f,
        dex[pc + 5] >> 4,
        dex[pc + 1] & 0x0f,
    ];
    Some(regs[..count].to_vec())
}

fn collect_instruction_offsets(dex: &[u8], start: usize, end: usize) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    let mut pc = start;
    while pc + 1 < end {
        let width_units = dex_walker::insn_width_units(dex[pc]);
        if width_units == 0 {
            return None;
        }
        let width = usize::from(width_units) * 2;
        if pc + width > end {
            return None;
        }
        out.push(pc);
        pc += width;
    }
    (pc == end).then_some(out)
}

fn locate_intent_redirect_sites(
    dex: &[u8],
    insns_off: usize,
    insns_end: usize,
    from_string_idx: u32,
    set_action_idx: u16,
    start_activity_idx: u16,
) -> Vec<IntentRedirectSite> {
    let Some(insns) = collect_instruction_offsets(dex, insns_off, insns_end) else {
        return Vec::new();
    };
    let mut sites = Vec::new();

    for (pos, &string_off) in insns.iter().enumerate() {
        let string_opcode = dex[string_off];
        if read_const_string_idx(dex, string_opcode, string_off) != Some(from_string_idx) {
            continue;
        }
        let action_reg = dex[string_off + 1];
        let next_source = insns[pos + 1..]
            .iter()
            .position(|&off| read_const_string_idx(dex, dex[off], off) == Some(from_string_idx))
            .map_or(insns.len(), |rel| pos + 1 + rel);

        let mut candidates = Vec::new();
        for &set_off in &insns[pos + 1..next_source] {
            if dex[set_off] != 0x6e || read_u16_le(dex, set_off + 2) != set_action_idx {
                continue;
            }
            let Some(set_regs) = decode_invoke_35c_registers(dex, set_off) else {
                continue;
            };
            if set_regs.len() != 2 || set_regs[1] != action_reg {
                continue;
            }
            let intent_reg = set_regs[0];
            let Some(set_pos) = insns.iter().position(|&off| off == set_off) else {
                continue;
            };
            for &start_off in &insns[set_pos + 1..next_source] {
                if dex[start_off] != 0x6e || read_u16_le(dex, start_off + 2) != start_activity_idx {
                    continue;
                }
                let Some(start_regs) = decode_invoke_35c_registers(dex, start_off) else {
                    continue;
                };
                if start_regs.len() == 3 && start_regs[1] == intent_reg {
                    candidates.push(IntentRedirectSite {
                        string_off,
                        string_opcode,
                        start_off,
                        context_reg: start_regs[0],
                        intent_reg,
                    });
                }
            }
        }
        candidates.sort_by_key(|site| site.start_off);
        candidates.dedup();
        sites.extend(candidates);
    }
    sites
}

fn write_intent_redirect_site(
    dex: &mut [u8],
    site: IntentRedirectSite,
    to_string_idx: u32,
    send_broadcast_idx: u16,
) {
    match site.string_opcode {
        0x1a => {
            dex[site.string_off + 2..site.string_off + 4]
                .copy_from_slice(&(to_string_idx as u16).to_le_bytes());
        }
        0x1b => {
            dex[site.string_off + 2..site.string_off + 6]
                .copy_from_slice(&to_string_idx.to_le_bytes());
        }
        _ => unreachable!("validated const-string opcode"),
    }
    dex[site.start_off] = 0x6e; // invoke-virtual, format 35c
    dex[site.start_off + 1] = 0x20; // A=2 args, G=0
    dex[site.start_off + 2..site.start_off + 4].copy_from_slice(&send_broadcast_idx.to_le_bytes());
    dex[site.start_off + 4] = site.context_reg | (site.intent_reg << 4);
    dex[site.start_off + 5] = 0x00;
}

/// Replace an existing Intent action reference and turn its matching
/// `Context.startActivity(Intent, Bundle)` into `Context.sendBroadcast(Intent)`.
/// Both action strings must already exist in the dex; the string-data table is
/// never edited, so its required lexical ordering remains intact. Only the
/// actual three-unit `invoke-virtual` form used by LenovoID is accepted.
///
/// The scan is conservative and atomic per site: a source action must feed an
/// `Intent.setAction`, followed by startActivity using that same Intent
/// register. Incomplete sequences are unchanged; one shared action load may
/// legitimately feed multiple branch-local pairs. Returns redirected launches.
pub fn redirect_intent_action_to_broadcast(
    dex: &mut [u8],
    from_action: &str,
    to_action: &str,
) -> Result<usize> {
    let h = read_dex_header(dex);
    let Some(from_string_idx) =
        dex_walker::find_string_idx_strict(dex, h.string_ids_size, h.string_ids_off, from_action)?
    else {
        return Ok(0);
    };
    let Some(to_string_idx) =
        dex_walker::find_string_idx_strict(dex, h.string_ids_size, h.string_ids_off, to_action)?
    else {
        return Ok(0);
    };
    let Some(set_action_idx) = resolve_method_idx(
        dex,
        &h,
        "Landroid/content/Intent;",
        "setAction",
        "Landroid/content/Intent;",
        &["Ljava/lang/String;"],
    )?
    else {
        return Ok(0);
    };
    let Some(start_activity_idx) = resolve_method_idx(
        dex,
        &h,
        "Landroid/content/Context;",
        "startActivity",
        "V",
        &["Landroid/content/Intent;", "Landroid/os/Bundle;"],
    )?
    else {
        return Ok(0);
    };
    let Some(send_broadcast_idx) = resolve_method_idx(
        dex,
        &h,
        "Landroid/content/Context;",
        "sendBroadcast",
        "V",
        &["Landroid/content/Intent;"],
    )?
    else {
        return Ok(0);
    };
    if set_action_idx > u32::from(u16::MAX)
        || start_activity_idx > u32::from(u16::MAX)
        || send_broadcast_idx > u32::from(u16::MAX)
    {
        return Ok(0);
    }

    let mut code_offsets = BTreeSet::new();
    for idx in 0..h.class_defs_size {
        let class_off = h.class_defs_off + idx * 32;
        if class_off + 32 > dex.len() {
            break;
        }
        let class_data_off = read_u32_le(dex, class_off + 24) as usize;
        if class_data_off == 0 || class_data_off >= dex.len() {
            continue;
        }
        if let Ok(methods) = collect_method_code_offs(dex, class_data_off) {
            code_offsets.extend(methods.into_iter().map(|(_, code_off)| code_off));
        }
    }

    let mut sites = Vec::new();
    for code_off in code_offsets {
        let Some((insns_off, insns_end)) = code_instruction_bounds(dex, code_off) else {
            continue;
        };
        sites.extend(locate_intent_redirect_sites(
            dex,
            insns_off,
            insns_end,
            from_string_idx,
            set_action_idx as u16,
            start_activity_idx as u16,
        ));
    }

    // Validate every edit before changing any bytes. In particular, a normal
    // const-string cannot encode a target index above u16::MAX.
    if sites.iter().any(|site| {
        site.string_opcode == 0x1a && to_string_idx > u32::from(u16::MAX)
            || !matches!(site.string_opcode, 0x1a | 0x1b)
    }) {
        return Ok(0);
    }

    for &site in &sites {
        write_intent_redirect_site(dex, site, to_string_idx, send_broadcast_idx as u16);
    }
    Ok(sites.len())
}

// ---------------------------------------------------------------------------
// primitive: rewrite a method to super + finish + broadcast(action) + return
// ---------------------------------------------------------------------------

/// Rewrite `class.method(Landroid/os/Bundle;)V` so it:
/// 1. `invoke-super {this, bundle}, super_class.method(Bundle)V`
/// 2. `Activity.finish()` before the next setup Activity can be launched
/// 3. builds an `Intent` from the already-present `action` string
/// 4. `Context.sendBroadcast(Intent)`
/// 5. `return-void`
///
/// Used to skip an OOBE entry Activity (e.g. Lenovo ID's
/// `PsLoginWizardActivity.onCreate`) without drawing its UI while still
/// advancing the setup wizard through an existing broadcast action such as
/// `com.zui.setupwizard.action.CLOUD_SKIP`.
///
/// Size-preserving: the replacement is written over the original instruction
/// stream and padded with `nop`. The action string and every referenced method
/// id must already exist in the dex. Returns `true` when the rewrite lands.
pub fn force_method_broadcast_finish(
    dex: &mut [u8],
    class_descriptor: &str,
    method_name: &str,
    ret_descriptor: &str,
    params: &[&str],
    super_class: &str,
    action: &str,
) -> Result<bool> {
    if ret_descriptor != "V" {
        return Err(anyhow!(
            "force_method_broadcast_finish requires a void (V) return, got `{ret_descriptor}`"
        ));
    }
    // Only the Activity.onCreate shape (this + one Bundle) is encoded today —
    // enough for the Lenovo ID entry skip and keeps the register layout simple.
    if params != ["Landroid/os/Bundle;"] {
        return Err(anyhow!(
            "force_method_broadcast_finish currently supports only (Landroid/os/Bundle;)V, got params {params:?}"
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
    if code_off_is_shared(dex, &h, code_off)? {
        return Ok(false);
    }
    if code_off + 16 > dex.len() {
        return Ok(false);
    }

    let registers_size = u32::from(read_u16_le(dex, code_off));
    let ins_size = u32::from(read_u16_le(dex, code_off + 2));
    let outs_size = u32::from(read_u16_le(dex, code_off + 4));
    let tries_size = read_u16_le(dex, code_off + 6);
    if tries_size != 0 {
        // Emitted body can throw (Intent construction / broadcast); refuse to
        // leave a leftover catch table aimed at the old register state.
        return Ok(false);
    }
    // this + Bundle occupy the last two parameter registers.
    if ins_size != 2 || registers_size < ins_size || outs_size < 2 {
        return Ok(false);
    }
    let first_param = registers_size - ins_size;
    // Need v0 (Intent) + v1 (action string) below the parameters.
    if first_param < 2 {
        return Ok(false);
    }
    let p0 = first_param; // this
    let p1 = first_param + 1; // Bundle
    // Every 35c register must be nibble-encodable.
    if p0 > 0x0f || p1 > 0x0f {
        return Ok(false);
    }

    let Some(action_idx) =
        dex_walker::find_string_idx_strict(dex, h.string_ids_size, h.string_ids_off, action)?
    else {
        return Ok(false);
    };
    let Some(intent_type_idx) = dex_walker::find_type_idx(
        dex,
        h.string_ids_size,
        h.string_ids_off,
        h.type_ids_size,
        h.type_ids_off,
        "Landroid/content/Intent;",
    )?
    else {
        return Ok(false);
    };
    if intent_type_idx > u32::from(u16::MAX) {
        return Ok(false);
    }

    let Some(super_on_create_idx) =
        resolve_method_idx(dex, &h, super_class, method_name, ret_descriptor, params)?
    else {
        return Ok(false);
    };
    let Some(intent_init_idx) = resolve_method_idx(
        dex,
        &h,
        "Landroid/content/Intent;",
        "<init>",
        "V",
        &["Ljava/lang/String;"],
    )?
    else {
        return Ok(false);
    };
    let Some(send_broadcast_idx) = resolve_method_idx(
        dex,
        &h,
        "Landroid/content/Context;",
        "sendBroadcast",
        "V",
        &["Landroid/content/Intent;"],
    )?
    else {
        return Ok(false);
    };
    let Some(finish_idx) =
        resolve_method_idx(dex, &h, "Landroid/app/Activity;", "finish", "V", &[])?
    else {
        return Ok(false);
    };
    for idx in [
        super_on_create_idx,
        intent_init_idx,
        send_broadcast_idx,
        finish_idx,
    ] {
        if idx > u32::from(u16::MAX) {
            return Ok(false);
        }
    }

    let replacement = encode_method_broadcast_finish_body(
        super_on_create_idx as u16,
        finish_idx as u16,
        intent_type_idx as u16,
        action_idx,
        intent_init_idx as u16,
        send_broadcast_idx as u16,
        p0 as u16,
        p1 as u16,
    );

    let insns_size = read_u32_le(dex, code_off + 12) as usize;
    let insns_off = code_off + 16;
    let insns_end = match insns_off.checked_add(insns_size.checked_mul(2).unwrap_or(0)) {
        Some(e) if e <= dex.len() => e,
        _ => return Ok(false),
    };
    if replacement.len() > insns_end - insns_off {
        return Ok(false);
    }

    let body = &mut dex[insns_off..insns_end];
    body[..replacement.len()].copy_from_slice(&replacement);
    for pad in body.iter_mut().skip(replacement.len()) {
        *pad = 0x00; // nop
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn encode_method_broadcast_finish_body(
    super_on_create_idx: u16,
    finish_idx: u16,
    intent_type_idx: u16,
    action_idx: u32,
    intent_init_idx: u16,
    send_broadcast_idx: u16,
    this_reg: u16,
    bundle_reg: u16,
) -> Vec<u8> {
    let (v_intent, v_action): (u16, u16) = (0, 1);
    let mut replacement = Vec::with_capacity(36);
    let mut push_u16 = |u: u16| replacement.extend_from_slice(&u.to_le_bytes());

    // invoke-super {this, bundle}, super.onCreate
    push_u16(0x6f | (0x20 << 8));
    push_u16(super_on_create_idx);
    push_u16(this_reg | (bundle_reg << 4));
    // Finish before the broadcast receiver can launch the next Activity.
    push_u16(0x6e | (0x10 << 8));
    push_u16(finish_idx);
    push_u16(this_reg);
    // new-instance v0, Intent
    push_u16(0x22 | (v_intent << 8));
    push_u16(intent_type_idx);
    // const-string[/jumbo] v1, action
    if let Ok(short_idx) = u16::try_from(action_idx) {
        push_u16(0x1a | (v_action << 8));
        push_u16(short_idx);
    } else {
        push_u16(0x1b | (v_action << 8));
        push_u16(action_idx as u16);
        push_u16((action_idx >> 16) as u16);
    }
    // invoke-direct {v0, v1}, Intent.<init>(String)
    push_u16(0x70 | (0x20 << 8));
    push_u16(intent_init_idx);
    push_u16(v_intent | (v_action << 4));
    // invoke-virtual {this, v0}, Context.sendBroadcast(Intent)
    push_u16(0x6e | (0x20 << 8));
    push_u16(send_broadcast_idx);
    push_u16(this_reg | (v_intent << 4));
    push_u16(0x000e); // return-void

    replacement
}

// ---------------------------------------------------------------------------
// primitive 7: force findViewById-bound views to setVisibility(GONE)
// ---------------------------------------------------------------------------

/// A located `findViewById` binding inside one method's instruction stream.
struct ViewBinding {
    /// Register the view reference lives in after `move-result-object`.
    view_reg: u8,
    /// Byte offset just past `move-result-object` (view is live from here).
    tail_start: usize,
    /// Byte offset of the entry's own `setOnClickListener` invoke.
    click_off: usize,
}

/// Locate the `const vView, view_id` / `invoke-virtual {p0, vView}, findViewById`
/// / `move-result-object vView` / … / `invoke-virtual {vView, _},
/// setOnClickListener` binding for `view_id` in `dex[insns_off..insns_end)`.
/// Returns `None` when that exact shape isn't present.
fn find_view_binding(
    dex: &[u8],
    insns_off: usize,
    insns_end: usize,
    view_id: i32,
) -> Option<ViewBinding> {
    let mut pc = insns_off;
    while pc + 1 < insns_end {
        let opcode = dex[pc];
        let width_units = dex_walker::insn_width_units(opcode);
        if width_units == 0 {
            return None;
        }
        let width = width_units as usize * 2;
        if pc + width > insns_end {
            return None;
        }
        // `const vAA, #+id` (0x14, 3 units) loading the target view id,
        // immediately followed by invoke-virtual (findViewById) + move-result.
        if opcode == 0x14
            && pc + 14 <= insns_end
            && read_u32_le(dex, pc + 2) as i32 == view_id
            && dex[pc + 6] == 0x6e
            && dex[pc + 12] == 0x0c
        {
            let view_reg = dex[pc + 1];
            if dex[pc + 13] == view_reg {
                let tail_start = pc + 14;
                if let Some(click_off) = find_click_site(dex, tail_start, insns_end, view_reg) {
                    return Some(ViewBinding {
                        view_reg,
                        tail_start,
                        click_off,
                    });
                }
            }
        }
        pc += width;
    }
    None
}

/// First `invoke-virtual` (0x6e) at/after `start` whose first-argument register
/// (C nibble) equals `view_reg` — the entry's own `setOnClickListener` call.
fn find_click_site(dex: &[u8], start: usize, insns_end: usize, view_reg: u8) -> Option<usize> {
    let mut pc = start;
    while pc + 1 < insns_end {
        let opcode = dex[pc];
        let width_units = dex_walker::insn_width_units(opcode);
        if width_units == 0 {
            return None;
        }
        let width = width_units as usize * 2;
        if pc + width > insns_end {
            return None;
        }
        if opcode == 0x6e && pc + 6 <= insns_end && (dex[pc + 4] & 0x0f) == view_reg {
            return Some(pc);
        }
        pc += width;
    }
    None
}

/// Write a 3-unit `invoke-virtual {view_reg, scratch_reg}, View.setVisibility(I)V`.
fn write_setvisibility(dex: &mut [u8], off: usize, view_reg: u8, scratch_reg: u8, setvis_idx: u16) {
    dex[off] = 0x6e; // invoke-virtual
    dex[off + 1] = 0x20; // arg count 2, G=0
    dex[off + 2] = (setvis_idx & 0xff) as u8;
    dex[off + 3] = (setvis_idx >> 8) as u8;
    dex[off + 4] = view_reg | (scratch_reg << 4); // C=view, D=scratch
    dex[off + 5] = 0x00;
}

/// Force `setVisibility(GONE)` on the views in `view_ids` bound by
/// `findViewById` inside `scan_class.scan_method`. One field-backed target
/// (whose check-cast+iput+setOnClickListener tail spans >= 5 code units) is the
/// "anchor": it is rewritten to load `View.GONE` into `scratch_reg` and hide
/// itself; every other target's `setOnClickListener` call is then swapped in
/// place to `setVisibility(view, scratch_reg)`, reusing that scratch register.
/// Size-preserving. Returns the number of views hidden (0 when the class /
/// method / `View.setVisibility` / any hideable anchor isn't present).
///
/// The anchor's `iput` is dropped, so the anchor view's field must not be read
/// elsewhere. `scratch_reg` must be a register that is free to clobber for the
/// span between the anchor and the last swapped view.
pub fn force_view_gone(
    dex: &mut [u8],
    scan_class: &str,
    scan_method: &str,
    view_ids: &[i32],
    scratch_reg: u8,
) -> Result<usize> {
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
    let Some(setvis_idx) =
        resolve_method_idx(dex, &h, "Landroid/view/View;", "setVisibility", "V", &["I"])?
    else {
        return Ok(0);
    };
    if setvis_idx > 0xffff {
        return Ok(0);
    }
    let Some(class_data_off) =
        dex_walker::find_class_data_off(dex, h.class_defs_size, h.class_defs_off, scan_type_idx)?
    else {
        return Ok(0);
    };

    let mut hidden = 0usize;
    for (method_idx, code_off) in collect_method_code_offs(dex, class_data_off)? {
        if method_name_of_idx(dex, &h, method_idx)?.as_deref() != Some(scan_method) {
            continue;
        }
        if code_off + 16 > dex.len() {
            continue;
        }
        let insns_size = read_u32_le(dex, code_off + 12) as usize;
        let insns_off = code_off + 16;
        let insns_end = match insns_off.checked_add(insns_size.checked_mul(2).unwrap_or(0)) {
            Some(e) if e <= dex.len() => e,
            _ => continue,
        };
        hidden += hide_views_in_method(
            dex,
            insns_off,
            insns_end,
            view_ids,
            scratch_reg,
            setvis_idx as u16,
        );
    }
    Ok(hidden)
}

/// Hide `view_ids` inside one method's instruction region. See
/// [`force_view_gone`] for the anchor/swap mechanism. Returns views hidden.
fn hide_views_in_method(
    dex: &mut [u8],
    insns_off: usize,
    insns_end: usize,
    view_ids: &[i32],
    scratch_reg: u8,
    setvis_idx: u16,
) -> usize {
    if scratch_reg >= 16 {
        return 0;
    }
    // Locate every requested binding first (offsets stay valid because every
    // rewrite below is size-preserving).
    let mut bindings: Vec<ViewBinding> = Vec::new();
    for &view_id in view_ids {
        if let Some(b) = find_view_binding(dex, insns_off, insns_end, view_id) {
            if b.view_reg < 16 && b.view_reg != scratch_reg {
                bindings.push(b);
            }
        }
    }
    if bindings.is_empty() {
        return 0;
    }

    // Anchor = earliest field-backed binding: its post-move-result tail spans
    // >= 10 bytes (5 units), enough for `const/16 scratch,8` + setVisibility.
    let Some(anchor_pos) = bindings
        .iter()
        .enumerate()
        .filter(|(_, b)| b.click_off + 6 >= b.tail_start + 10)
        .min_by_key(|(_, b)| b.click_off)
        .map(|(i, _)| i)
    else {
        return 0;
    };
    let anchor_view = bindings[anchor_pos].view_reg;
    let anchor_tail = bindings[anchor_pos].tail_start;
    let anchor_click = bindings[anchor_pos].click_off;

    let Some(cover_end) = cover_whole_instructions(dex, anchor_tail, insns_end, 10) else {
        return 0;
    };
    // const/16 scratch_reg, #8 (View.GONE), then setVisibility(view, scratch).
    dex[anchor_tail] = 0x13;
    dex[anchor_tail + 1] = scratch_reg;
    dex[anchor_tail + 2] = 0x08;
    dex[anchor_tail + 3] = 0x00;
    write_setvisibility(dex, anchor_tail + 4, anchor_view, scratch_reg, setvis_idx);
    for b in dex[anchor_tail + 10..cover_end].iter_mut() {
        *b = 0x00; // nop-pad the rest of the covered tail
    }
    let mut hidden = 1usize;

    // Swap every other located view whose click site executes after the anchor
    // established `scratch_reg` at runtime.
    for (i, b) in bindings.iter().enumerate() {
        if i == anchor_pos {
            continue;
        }
        if b.click_off > anchor_click {
            write_setvisibility(dex, b.click_off, b.view_reg, scratch_reg, setvis_idx);
            hidden += 1;
        }
    }
    hidden
}

// ---------------------------------------------------------------------------
// primitive 6: hide a RemoteViews child via an injected setVisibility(GONE)
// ---------------------------------------------------------------------------

/// Hide a `RemoteViews` view by rewriting one of its setup call sites inside
/// `scan_class.scan_method` into `RemoteViews.setViewVisibility(id, GONE)`. The
/// site is the `const vId, view_id` that loads the target id, immediately
/// followed by a 2-unit arg-load and a 3-unit `invoke-*` (e.g. a click-intent
/// registration). Those 10 bytes are overwritten in place with `const/16
/// scratch, #8` + `invoke-virtual {rv_reg, vId, scratch},
/// RemoteViews->setViewVisibility(I,I)V`. Size-preserving. Returns 1 when the
/// site is found and rewritten, else 0 (class/method/`setViewVisibility` absent,
/// id not loaded by a `const`, or the following two instructions don't match
/// the expected `[2-unit load][3-unit invoke]` shape).
///
/// `rv_reg` is the register holding the `RemoteViews` at the site (a method
/// parameter register); `scratch_reg` is a free nibble register. Both, and the
/// id register, must be < 16.
pub fn force_remoteviews_gone(
    dex: &mut [u8],
    scan_class: &str,
    scan_method: &str,
    view_id: i32,
    rv_reg: u8,
    scratch_reg: u8,
) -> Result<usize> {
    if rv_reg >= 16 || scratch_reg >= 16 {
        return Ok(0);
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
    let Some(setvis_idx) = resolve_method_idx(
        dex,
        &h,
        "Landroid/widget/RemoteViews;",
        "setViewVisibility",
        "V",
        &["I", "I"],
    )?
    else {
        return Ok(0);
    };
    if setvis_idx > 0xffff {
        return Ok(0);
    }
    let Some(class_data_off) =
        dex_walker::find_class_data_off(dex, h.class_defs_size, h.class_defs_off, scan_type_idx)?
    else {
        return Ok(0);
    };

    for (method_idx, code_off) in collect_method_code_offs(dex, class_data_off)? {
        if method_name_of_idx(dex, &h, method_idx)?.as_deref() != Some(scan_method) {
            continue;
        }
        if code_off + 16 > dex.len() {
            continue;
        }
        let insns_size = read_u32_le(dex, code_off + 12) as usize;
        let insns_off = code_off + 16;
        let insns_end = match insns_off.checked_add(insns_size.checked_mul(2).unwrap_or(0)) {
            Some(e) if e <= dex.len() => e,
            _ => continue,
        };
        if rewrite_remoteviews_gone(
            dex,
            insns_off,
            insns_end,
            view_id,
            rv_reg,
            scratch_reg,
            setvis_idx as u16,
        ) {
            return Ok(1);
        }
    }
    Ok(0)
}

/// Find `const vId, view_id` in `dex[insns_off..insns_end)` and overwrite the
/// following `[2-unit load][3-unit invoke]` with `const/16 scratch,#8` +
/// `setViewVisibility(rv, vId, scratch)`. Returns whether it rewrote a site.
fn rewrite_remoteviews_gone(
    dex: &mut [u8],
    insns_off: usize,
    insns_end: usize,
    view_id: i32,
    rv_reg: u8,
    scratch_reg: u8,
    setvis_idx: u16,
) -> bool {
    let mut pc = insns_off;
    while pc + 1 < insns_end {
        let opcode = dex[pc];
        let width_units = dex_walker::insn_width_units(opcode);
        if width_units == 0 {
            return false;
        }
        let width = width_units as usize * 2;
        if pc + width > insns_end {
            return false;
        }
        if opcode == 0x14 && read_u32_le(dex, pc + 2) as i32 == view_id {
            let id_reg = dex[pc + 1];
            let load_off = pc + 6; // arg-load (2 units)
            let invoke_off = pc + 10; // invoke (3 units)
            let end = pc + 16;
            if id_reg < 16
                && end <= insns_end
                && dex_walker::insn_width_units(dex[load_off]) == 2
                && matches!(dex[invoke_off], 0x6e..=0x72 | 0x74..=0x78)
                && dex_walker::insn_width_units(dex[invoke_off]) == 3
            {
                // const/16 scratch_reg, #8 (View.GONE)
                dex[load_off] = 0x13;
                dex[load_off + 1] = scratch_reg;
                dex[load_off + 2] = 0x08;
                dex[load_off + 3] = 0x00;
                // invoke-virtual {rv, id, scratch}, RemoteViews.setViewVisibility(I,I)V
                dex[invoke_off] = 0x6e;
                dex[invoke_off + 1] = 0x30; // arg count 3
                dex[invoke_off + 2] = (setvis_idx & 0xff) as u8;
                dex[invoke_off + 3] = (setvis_idx >> 8) as u8;
                dex[invoke_off + 4] = rv_reg | (id_reg << 4); // C=rv, D=id
                dex[invoke_off + 5] = scratch_reg; // E=scratch, F=0
                return true;
            }
        }
        pc += width;
    }
    false
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

    #[test]
    fn field_const_bool_rewrites_only_matching_iget_boolean() {
        // iget-boolean v3,v7,field@0x1234; unrelated iget-boolean; return-void
        let mut insns = vec![0x55, 0x73, 0x34, 0x12, 0x55, 0x21, 0x78, 0x56, 0x0e, 0x00];
        let end = insns.len();
        let sites = rewrite_field_bool_sites(&mut insns, 0, end, 0x1234, true);
        assert_eq!(sites, 1);
        assert_eq!(&insns[..4], &[0x12, 0x13, 0x00, 0x00]);
        assert_eq!(&insns[4..8], &[0x55, 0x21, 0x78, 0x56]);
    }

    #[test]
    fn field_const_bool_writes_false_and_missing_field_is_noop() {
        let original = vec![0x55, 0x84, 0x34, 0x12, 0x0e, 0x00];
        let mut false_case = original.clone();
        let false_end = false_case.len();
        assert_eq!(
            rewrite_field_bool_sites(&mut false_case, 0, false_end, 0x1234, false),
            1
        );
        assert_eq!(&false_case[..4], &[0x12, 0x04, 0x00, 0x00]);

        let mut missing = original.clone();
        let missing_end = missing.len();
        assert_eq!(
            rewrite_field_bool_sites(&mut missing, 0, missing_end, 0xabcd, true),
            0
        );
        assert_eq!(missing, original);
    }

    fn invoke_35c(method_idx: u16, regs: &[u8]) -> [u8; 6] {
        assert!(regs.len() <= 5);
        let mut out = [0u8; 6];
        out[0] = 0x6e;
        out[1] = (regs.len() as u8) << 4;
        out[2..4].copy_from_slice(&method_idx.to_le_bytes());
        if let Some(&reg) = regs.first() {
            out[4] |= reg;
        }
        if let Some(&reg) = regs.get(1) {
            out[4] |= reg << 4;
        }
        if let Some(&reg) = regs.get(2) {
            out[5] |= reg;
        }
        if let Some(&reg) = regs.get(3) {
            out[5] |= reg << 4;
        }
        if let Some(&reg) = regs.get(4) {
            out[1] |= reg;
        }
        out
    }

    #[test]
    fn intent_redirect_locates_exact_action_intent_and_start() {
        const FROM: u32 = 0x1234;
        const SET_ACTION: u16 = 0x20;
        const START: u16 = 0x21;
        let mut insns = vec![0x1a, 0x02, 0x34, 0x12]; // const-string v2, FROM
        insns.extend(invoke_35c(SET_ACTION, &[5, 2])); // setAction(v5,v2)
        insns.extend([0x12, 0x01]); // harmless const/4
        insns.extend(invoke_35c(START, &[7, 5, 9])); // startActivity(v7,v5,v9)
        insns.extend([0x0e, 0x00]);
        let sites = locate_intent_redirect_sites(&insns, 0, insns.len(), FROM, SET_ACTION, START);
        assert_eq!(
            sites,
            vec![IntentRedirectSite {
                string_off: 0,
                string_opcode: 0x1a,
                start_off: 12,
                context_reg: 7,
                intent_reg: 5,
            }]
        );

        write_intent_redirect_site(&mut insns, sites[0], 0x4321, 0x6543);
        assert_eq!(&insns[..4], &[0x1a, 0x02, 0x21, 0x43]);
        assert_eq!(
            &insns[12..18],
            &[0x6e, 0x20, 0x43, 0x65, 0x57, 0x00],
            "sendBroadcast(v7,v5) keeps the three-unit invoke width"
        );
    }

    #[test]
    fn method_broadcast_finish_encodes_super_broadcast_and_finish() {
        let super_idx: u16 = 0x1111;
        let intent_type: u16 = 0x2222;
        let init_idx: u16 = 0x3333;
        let action_idx: u16 = 0x4444;
        let send_bc: u16 = 0x6666;
        let finish: u16 = 0x7777;
        let this_reg: u16 = 2;
        let bundle_reg: u16 = 3;
        let body = encode_method_broadcast_finish_body(
            super_idx,
            finish,
            intent_type,
            u32::from(action_idx),
            init_idx,
            send_bc,
            this_reg,
            bundle_reg,
        );

        assert_eq!(body.len(), 34);
        assert_eq!(&body[0..6], &[0x6f, 0x20, 0x11, 0x11, 0x32, 0x00]);
        assert_eq!(
            &body[6..12],
            &[0x6e, 0x10, 0x77, 0x77, this_reg as u8, 0x00],
            "finish must precede all broadcast work"
        );
        assert_eq!(&body[12..16], &[0x22, 0x00, 0x22, 0x22]);
        assert_eq!(&body[16..20], &[0x1a, 0x01, 0x44, 0x44]);
        assert_eq!(&body[20..26], &[0x70, 0x20, 0x33, 0x33, 0x10, 0x00]);
        assert_eq!(
            &body[26..34],
            &[0x6e, 0x20, 0x66, 0x66, this_reg as u8, 0x00, 0x0e, 0x00]
        );

        let jumbo = encode_method_broadcast_finish_body(
            super_idx,
            finish,
            intent_type,
            0x0001_4444,
            init_idx,
            send_bc,
            this_reg,
            bundle_reg,
        );
        assert_eq!(jumbo.len(), 36);
        assert_eq!(&jumbo[16..22], &[0x1b, 0x01, 0x44, 0x44, 0x01, 0x00]);
    }

    #[test]
    fn intent_redirect_skips_wrong_register_and_keeps_branch_local_starts() {
        const FROM: u32 = 0x1234;
        const SET_ACTION: u16 = 0x20;
        const START: u16 = 0x21;

        let mut wrong = vec![0x1a, 0x02, 0x34, 0x12];
        wrong.extend(invoke_35c(SET_ACTION, &[5, 3])); // action is v3, not v2
        wrong.extend(invoke_35c(START, &[7, 5, 9]));
        assert!(
            locate_intent_redirect_sites(&wrong, 0, wrong.len(), FROM, SET_ACTION, START)
                .is_empty()
        );

        let mut ambiguous = vec![0x1a, 0x02, 0x34, 0x12];
        ambiguous.extend(invoke_35c(SET_ACTION, &[5, 2]));
        ambiguous.extend(invoke_35c(START, &[7, 5, 9]));
        ambiguous.extend(invoke_35c(START, &[7, 5, 8]));
        let sites =
            locate_intent_redirect_sites(&ambiguous, 0, ambiguous.len(), FROM, SET_ACTION, START);
        assert_eq!(sites.len(), 2, "both action-derived launches are matched");
    }

    fn code_item_with_nops(insns_size: u32) -> Vec<u8> {
        let mut code = vec![0u8; 16 + insns_size as usize * 2];
        code[0..2].copy_from_slice(&1u16.to_le_bytes());
        code[12..16].copy_from_slice(&insns_size.to_le_bytes());
        code
    }

    #[test]
    fn method_const_int_uses_smallest_dalvik_const_encoding() {
        let mut small = code_item_with_nops(4);
        assert!(rewrite_method_body_const_int(&mut small, 0, 1).unwrap());
        assert_eq!(&small[16..20], &[0x12, 0x10, 0x0f, 0x00]);

        let mut medium = code_item_with_nops(4);
        assert!(rewrite_method_body_const_int(&mut medium, 0, 0x1234).unwrap());
        assert_eq!(&medium[16..22], &[0x13, 0x00, 0x34, 0x12, 0x0f, 0x00]);

        let mut full = code_item_with_nops(4);
        assert!(rewrite_method_body_const_int(&mut full, 0, 0x1234_5678).unwrap());
        assert_eq!(
            &full[16..24],
            &[0x14, 0x00, 0x78, 0x56, 0x34, 0x12, 0x0f, 0x00]
        );
    }

    #[test]
    fn method_nop_rewrites_body_to_return_void_and_preserves_tries() {
        let mut code = code_item_with_nops(4);
        // tries_size = 1, with trailing try_item + handler bytes after the insns.
        // These must be left byte-identical: zeroing tries_size while the handler
        // bytes remain would desync the dex verifier's contiguous code-item walk.
        code[6..8].copy_from_slice(&1u16.to_le_bytes());
        // First instruction: const v0, #0x1234 (0x14, 3 units = 6 bytes).
        code[16] = 0x14;
        code[17] = 0x00;
        code[18..22].copy_from_slice(&0x1234u32.to_le_bytes());
        // Trailing try/handler region (contents arbitrary; must be preserved).
        let trailer = [0xAAu8; 12];
        code.extend_from_slice(&trailer);

        assert!(rewrite_method_body_return_void(&mut code, 0).unwrap());

        assert_eq!(&code[16..18], &[0x0e, 0x00], "return-void");
        assert_eq!(&code[18..22], &[0x00; 4], "old const nop-padded");
        assert_eq!(
            u16::from_le_bytes([code[6], code[7]]),
            1,
            "tries_size preserved"
        );
        assert_eq!(&code[24..36], &trailer, "try/handler bytes preserved");
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

    /// `force_method_return_int` lands on the real services.jar
    /// `PhoneWindowManager.getResolvedLongPressOnPowerBehavior()`.
    /// Set `DYNOBOX_SERVICES_ARCHIVE`.
    #[test]
    fn method_const_int_lands_on_real_services() {
        let Ok(path) = std::env::var("DYNOBOX_SERVICES_ARCHIVE") else {
            return;
        };
        let archive = std::fs::read(path).expect("read services archive");
        let zip = crate::fuck_lgsi::parse_zip_central_directory(&archive)
            .expect("parse services archive");
        let mut hits = 0;
        for entry in zip.entries.iter().filter(|entry| {
            entry.name.ends_with(".dex")
                && entry.compression_method == 0
                && !entry.uses_data_descriptor
                && !entry.is_zip64
                && entry.data_start + entry.compressed_size <= archive.len()
        }) {
            let mut dex =
                archive[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
            if force_method_return_int(
                &mut dex,
                "Lcom/android/server/policy/PhoneWindowManager;",
                "getResolvedLongPressOnPowerBehavior",
                "I",
                &[],
                1,
            )
            .expect("patch")
            {
                hits += 1;
            }
        }
        assert_eq!(hits, 1, "power behavior resolver should be forced once");
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

    #[test]
    fn invoke_const_int_rewrites_call_site_to_const() {
        // insns: [invoke-static {}, method@9 (3u)] [move-result v5 (1u)] = 8 bytes.
        let mut code = code_item_with_nops(4);
        code[16] = 0x71; // invoke-static
        code[18] = 0x09; // method idx 9
        code[22] = 0x0A; // move-result
        code[23] = 0x05; //   v5
        let n = rewrite_invoke_sites(&mut code, 0, 9, 0).unwrap();
        assert_eq!(n, 1);
        // const/16 v5, #0 + 2 nops
        assert_eq!(
            &code[16..24],
            &[0x13, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        // A value outside i16 range uses `const` (0x14) + 1 nop.
        let mut big = code_item_with_nops(4);
        big[16] = 0x71;
        big[18] = 0x09;
        big[22] = 0x0A;
        big[23] = 0x05;
        assert_eq!(
            rewrite_invoke_sites(&mut big, 0, 9, 0x0001_0000).unwrap(),
            1
        );
        assert_eq!(big[16], 0x14, "const vAA");
        assert_eq!(big[17], 0x05);
        assert_eq!(&big[18..22], &0x0001_0000i32.to_le_bytes());
        assert_eq!(&big[22..24], &[0x00, 0x00], "nop tail");

        // invoke-virtual (0x6e) is matched too, not just invoke-static.
        let mut virt = code_item_with_nops(4);
        virt[16] = 0x6e; // invoke-virtual
        virt[18] = 0x09;
        virt[22] = 0x0A;
        virt[23] = 0x05;
        assert_eq!(rewrite_invoke_sites(&mut virt, 0, 9, 1).unwrap(), 1);
        assert_eq!(&virt[16..20], &[0x13, 0x05, 0x01, 0x00], "const/16 v5, #1");
    }

    #[test]
    fn nop_anchored_invoke_int_anchor_skips_non_target_nops_target() {
        // const vA, #0x7f12006d (6 bytes)
        let anchor = [0x14u8, 0x00, 0x6d, 0x00, 0x12, 0x7f];
        // invoke-direct {..}, method@5 (6 bytes) — not the target idx.
        let non_target = [0x70u8, 0x00, 0x05, 0x00, 0x00, 0x00];
        // invoke-interface {..}, method@7 (6 bytes) — the target idx.
        let target = [0x72u8, 0x00, 0x07, 0x00, 0x00, 0x00];
        let mut buf = Vec::new();
        buf.extend_from_slice(&anchor);
        buf.extend_from_slice(&non_target);
        buf.extend_from_slice(&target);
        let end = buf.len();

        let sites =
            rewrite_first_anchored_invoke(&mut buf, 0, end, 7, AnchorMatch::Int(0x7f12006d));

        assert_eq!(sites, 1);
        assert_eq!(&buf[0..6], &anchor, "anchor instruction untouched");
        assert_eq!(&buf[6..12], &non_target, "non-target invoke untouched");
        assert_eq!(&buf[12..18], &[0u8; 6], "target invoke nopped");
    }

    #[test]
    fn nop_anchored_invoke_string_anchor_nops_target() {
        // const-string vA, string@42 (4 bytes)
        let anchor = [0x1au8, 0x00, 0x2a, 0x00];
        // invoke-virtual {..}, method@9 (6 bytes) — the target idx.
        let target = [0x6eu8, 0x00, 0x09, 0x00, 0x00, 0x00];
        let mut buf = Vec::new();
        buf.extend_from_slice(&anchor);
        buf.extend_from_slice(&target);
        let end = buf.len();

        let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 9, AnchorMatch::StringIdx(42));

        assert_eq!(sites, 1);
        assert_eq!(&buf[0..4], &anchor, "anchor instruction untouched");
        assert_eq!(&buf[4..10], &[0u8; 6], "target invoke nopped");
    }

    #[test]
    fn nop_anchored_invoke_used_result_is_never_nopped() {
        // const/4 v0, #+5 (2 bytes)
        let anchor = [0x12u8, 0x50];
        // invoke-virtual {..}, method@3 (6 bytes) — the target idx.
        let target = [0x6eu8, 0x00, 0x03, 0x00, 0x00, 0x00];
        // move-result-object v0 (2 bytes) — consumes the invoke's result.
        let move_result = [0x0cu8, 0x00];
        let mut buf = Vec::new();
        buf.extend_from_slice(&anchor);
        buf.extend_from_slice(&target);
        buf.extend_from_slice(&move_result);
        let original = buf.clone();
        let end = buf.len();

        let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 3, AnchorMatch::Int(5));

        assert_eq!(sites, 0, "result is consumed, must not nop");
        assert_eq!(buf, original, "buffer left entirely untouched");
    }

    #[test]
    fn nop_anchored_invoke_missing_anchor_is_noop() {
        // invoke-virtual {..}, method@3 (6 bytes) — matches target idx, but no
        // anchor ever arms the scan.
        let mut buf = vec![0x6eu8, 0x00, 0x03, 0x00, 0x00, 0x00];
        let original = buf.clone();
        let end = buf.len();

        let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 3, AnchorMatch::Int(999));

        assert_eq!(sites, 0, "anchor never present");
        assert_eq!(buf, original, "buffer left entirely untouched");
    }

    #[test]
    fn nop_anchored_invoke_target_before_anchor_is_noop() {
        // invoke-virtual {..}, method@3 (6 bytes) — target idx, but appears
        // BEFORE the const/4 anchor that follows it.
        let target = [0x6eu8, 0x00, 0x03, 0x00, 0x00, 0x00];
        // const/4 v0, #+5 (2 bytes)
        let anchor = [0x12u8, 0x50];
        let mut buf = Vec::new();
        buf.extend_from_slice(&target);
        buf.extend_from_slice(&anchor);
        let original = buf.clone();
        let end = buf.len();

        let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 3, AnchorMatch::Int(5));

        assert_eq!(sites, 0, "invoke precedes the arm, must not be nopped");
        assert_eq!(buf, original, "buffer left entirely untouched");
    }

    /// `force_nop_anchored_invoke` lands on the real ZuiSecurity dexes.
    /// Set DYNOBOX_ZUISECURITY_APK to the real ZuiSecurity.apk.
    #[test]
    fn nop_invoke_lands_on_real_zuisecurity() {
        let Ok(path) = std::env::var("DYNOBOX_ZUISECURITY_APK") else {
            return;
        };
        let apk = std::fs::read(path).expect("read ZuiSecurity.apk");
        let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("parse apk");
        let (mut list_sites, mut map_sites) = (0usize, 0usize);
        for entry in zip.entries.iter().filter(|e| {
            e.name.ends_with(".dex")
                && e.compression_method == 0
                && !e.uses_data_descriptor
                && !e.is_zip64
                && e.data_start + e.compressed_size <= apk.len()
        }) {
            let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
            list_sites += force_nop_anchored_invoke(
                &mut dex,
                "Lcom/zui/safecenter/ui/PhoneMainViewModel;",
                "<init>",
                "Ljava/util/List;",
                "add",
                "Z",
                &["Ljava/lang/Object;"],
                NopAnchor::Int(0x7f12006d),
            )
            .expect("list");
            map_sites += force_nop_anchored_invoke(
                &mut dex,
                "Lcom/lenovo/xuipermissionmanager/model/BasePermissionGroup;",
                "<clinit>",
                "Landroid/util/ArrayMap;",
                "put",
                "Ljava/lang/Object;",
                &["Ljava/lang/Object;", "Ljava/lang/Object;"],
                NopAnchor::Str("android.permission.RECEIVE_BOOT_COMPLETED"),
            )
            .expect("map");
        }
        assert_eq!(list_sites, 1, "autostart list item add nopped once");
        assert_eq!(
            map_sites, 1,
            "RECEIVE_BOOT_COMPLETED->boot_start_up put nopped once"
        );
    }

    // ---- force_view_gone -------------------------------------------------

    // Instruction fragments for synthetic `findViewById` bindings:
    // `const v0,id / invoke-virtual (findViewById) / move-result v0 /
    // [check-cast / iput] / invoke-virtual {v0,p0} setOnClickListener`.
    fn const_v0(id: u32) -> Vec<u8> {
        let b = id.to_le_bytes();
        vec![0x14, 0x00, b[0], b[1], b[2], b[3]]
    }
    fn findviewbyid() -> Vec<u8> {
        vec![0x6e, 0x20, 0x00, 0x00, 0x02, 0x00] // {p0, v0}, method@0
    }
    fn move_result_v0() -> Vec<u8> {
        vec![0x0c, 0x00]
    }
    fn check_cast_v0() -> Vec<u8> {
        vec![0x1f, 0x00, 0x00, 0x00]
    }
    fn iput_v0() -> Vec<u8> {
        vec![0x5b, 0x00, 0x00, 0x00]
    }
    fn set_on_click_v0() -> Vec<u8> {
        vec![0x6e, 0x20, 0x11, 0x11, 0x20, 0x00] // {v0,p0}, method@0x1111
    }

    #[test]
    fn force_view_gone_hides_field_backed_anchor() {
        const ID_A: u32 = 0x7f0903f1;
        let mut buf = Vec::new();
        buf.extend(const_v0(ID_A));
        buf.extend(findviewbyid());
        buf.extend(move_result_v0());
        let tail = buf.len(); // 14
        buf.extend(check_cast_v0());
        buf.extend(iput_v0());
        buf.extend(set_on_click_v0());
        let end = buf.len(); // 28
        let head = buf[..tail].to_vec();

        let n = hide_views_in_method(&mut buf, 0, end, &[ID_A as i32], 1, 0x30);

        assert_eq!(n, 1);
        assert_eq!(&buf[..tail], &head[..], "view acquisition untouched");
        assert_eq!(
            &buf[tail..tail + 4],
            &[0x13, 0x01, 0x08, 0x00],
            "const/16 v1, #8 (GONE)"
        );
        assert_eq!(
            &buf[tail + 4..tail + 10],
            &[0x6e, 0x20, 0x30, 0x00, 0x10, 0x00],
            "invoke-virtual (v0,v1) setVisibility"
        );
        assert_eq!(&buf[tail + 10..end], &[0x00; 4], "nop pad");
    }

    #[test]
    fn force_view_gone_swaps_click_only_after_anchor() {
        const ID_A: u32 = 0x7f0903f1;
        const ID_B: u32 = 0x7f0903d7;
        let mut buf = Vec::new();
        buf.extend(const_v0(ID_A));
        buf.extend(findviewbyid());
        buf.extend(move_result_v0());
        buf.extend(check_cast_v0());
        buf.extend(iput_v0());
        buf.extend(set_on_click_v0());
        buf.extend(const_v0(ID_B));
        buf.extend(findviewbyid());
        buf.extend(move_result_v0());
        let b_click = buf.len();
        buf.extend(set_on_click_v0());
        let end = buf.len();
        let b_head = buf[b_click - 14..b_click].to_vec();

        let n = hide_views_in_method(&mut buf, 0, end, &[ID_A as i32, ID_B as i32], 1, 0x30);

        assert_eq!(n, 2);
        assert_eq!(
            &buf[b_click..b_click + 6],
            &[0x6e, 0x20, 0x30, 0x00, 0x10, 0x00],
            "click-only view swapped to setVisibility (v0,v1)"
        );
        assert_eq!(
            &buf[b_click - 14..b_click],
            &b_head[..],
            "click-only view acquisition untouched"
        );
    }

    #[test]
    fn force_view_gone_click_only_without_anchor_is_noop() {
        const ID_B: u32 = 0x7f0903d7;
        let mut buf = Vec::new();
        buf.extend(const_v0(ID_B));
        buf.extend(findviewbyid());
        buf.extend(move_result_v0());
        buf.extend(set_on_click_v0());
        let end = buf.len();
        let original = buf.clone();

        let n = hide_views_in_method(&mut buf, 0, end, &[ID_B as i32], 1, 0x30);

        assert_eq!(n, 0, "no field-backed anchor to establish scratch");
        assert_eq!(buf, original, "buffer untouched");
    }

    #[test]
    fn force_view_gone_leaves_click_site_before_anchor() {
        const ID_A: u32 = 0x7f0903f1; // field-backed anchor, appears second
        const ID_B: u32 = 0x7f0903d7; // click-only, appears first
        let mut buf = Vec::new();
        buf.extend(const_v0(ID_B));
        buf.extend(findviewbyid());
        buf.extend(move_result_v0());
        let b_click = buf.len();
        buf.extend(set_on_click_v0());
        let b_click_bytes = buf[b_click..b_click + 6].to_vec();
        buf.extend(const_v0(ID_A));
        buf.extend(findviewbyid());
        buf.extend(move_result_v0());
        buf.extend(check_cast_v0());
        buf.extend(iput_v0());
        buf.extend(set_on_click_v0());
        let end = buf.len();

        let n = hide_views_in_method(&mut buf, 0, end, &[ID_A as i32, ID_B as i32], 1, 0x30);

        assert_eq!(n, 1, "only the anchor is hidden");
        assert_eq!(
            &buf[b_click..b_click + 6],
            &b_click_bytes[..],
            "click site before the anchor is not swapped"
        );
    }

    /// `force_view_gone` hides the ZuiSecurity nav entries on the real dex.
    /// Set DYNOBOX_ZUISECURITY_APK to the real ZuiSecurity.apk.
    #[test]
    fn force_view_gone_lands_on_real_zuisecurity() {
        let Ok(path) = std::env::var("DYNOBOX_ZUISECURITY_APK") else {
            return;
        };
        let apk = std::fs::read(path).expect("read ZuiSecurity.apk");
        let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("parse apk");
        let mut hidden = 0usize;
        for entry in zip.entries.iter().filter(|e| {
            e.name.ends_with(".dex")
                && e.compression_method == 0
                && !e.uses_data_descriptor
                && !e.is_zip64
                && e.data_start + e.compressed_size <= apk.len()
        }) {
            let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
            hidden += force_view_gone(
                &mut dex,
                "Lcom/zui/safecenter/ui/MainNavigationActivity;",
                "initView",
                &[0x7f0903f1, 0x7f0903d7],
                1,
            )
            .expect("hide");
        }
        assert_eq!(hidden, 2, "permission + autostart nav entries hidden");
    }

    /// `invoke_const_bool` forces `isRowVersion()` at the single call site in
    /// `AppPermissionPreferenceController` on the real ZuiSettings.apk, so the
    /// app-permission screen routes to the AOSP page. Set DYNOBOX_ZUISETTINGS_APK.
    #[test]
    fn isrowversion_forced_in_permission_controller_on_real_zuisettings() {
        let Ok(path) = std::env::var("DYNOBOX_ZUISETTINGS_APK") else {
            return;
        };
        let apk = std::fs::read(path).expect("read ZuiSettings.apk");
        let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("parse apk");
        let mut sites = 0usize;
        for entry in zip.entries.iter().filter(|e| {
            e.name.ends_with(".dex")
                && e.compression_method == 0
                && !e.uses_data_descriptor
                && !e.is_zip64
                && e.data_start + e.compressed_size <= apk.len()
        }) {
            let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
            sites += force_invoke_const_bool(
                &mut dex,
                "Lcom/android/settings/applications/appinfo/AppPermissionPreferenceController;",
                None,
                "Lcom/lenovo/common/utils/LenovoUtils;",
                "isRowVersion",
                "Z",
                &[],
                true,
            )
            .expect("patch");
        }
        assert_eq!(
            sites, 1,
            "isRowVersion forced at exactly one controller site"
        );
    }

    // ---- force_remoteviews_gone ------------------------------------------

    fn const_id(id: u32) -> Vec<u8> {
        let b = id.to_le_bytes();
        vec![0x14, 0x00, b[0], b[1], b[2], b[3]] // const v0, #id
    }

    #[test]
    fn remoteviews_gone_rewrites_setup_site() {
        const ID: u32 = 0x7f09009e;
        let mut buf = const_id(ID);
        buf.extend([0x62, 0x01, 0x00, 0x00]); // sget-object v1, field@0 (2-unit arg load)
        buf.extend([0x71, 0x40, 0x11, 0x11, 0x08, 0x01]); // invoke-static {..} (3 units)
        let end = buf.len();
        let head = buf[..6].to_vec();

        let ok = rewrite_remoteviews_gone(&mut buf, 0, end, ID as i32, 8, 1, 0x30);

        assert!(ok);
        assert_eq!(&buf[..6], &head[..], "const id load untouched");
        assert_eq!(
            &buf[6..10],
            &[0x13, 0x01, 0x08, 0x00],
            "const/16 v1, #8 (GONE)"
        );
        assert_eq!(
            &buf[10..16],
            &[0x6e, 0x30, 0x30, 0x00, 0x08, 0x01],
            "invoke-virtual setViewVisibility (v8,v0,v1)"
        );
    }

    #[test]
    fn remoteviews_gone_skips_mismatched_shape() {
        const ID: u32 = 0x7f09009e;
        // const vId, ID followed directly by a 3-unit invoke (no 2-unit load).
        let mut buf = const_id(ID);
        buf.extend([0x71, 0x30, 0x11, 0x11, 0x08, 0x00]); // invoke at pc+6 (width 3, not 2)
        buf.extend([0x71, 0x30, 0x11, 0x11, 0x08, 0x00]);
        let end = buf.len();
        let original = buf.clone();

        let ok = rewrite_remoteviews_gone(&mut buf, 0, end, ID as i32, 8, 1, 0x30);

        assert!(!ok, "wrong shape must not be rewritten");
        assert_eq!(buf, original, "buffer untouched");
    }

    /// `force_remoteviews_gone` hides the "Autostart Apps" widget item on the
    /// real ZuiSecurity.apk. Set DYNOBOX_ZUISECURITY_APK.
    #[test]
    fn remoteviews_gone_lands_on_real_zuisecurity() {
        let Ok(path) = std::env::var("DYNOBOX_ZUISECURITY_APK") else {
            return;
        };
        let apk = std::fs::read(path).expect("read ZuiSecurity.apk");
        let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("parse apk");
        let mut hit = 0usize;
        for entry in zip.entries.iter().filter(|e| {
            e.name.ends_with(".dex")
                && e.compression_method == 0
                && !e.uses_data_descriptor
                && !e.is_zip64
                && e.data_start + e.compressed_size <= apk.len()
        }) {
            let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
            hit += force_remoteviews_gone(
                &mut dex,
                "Lcom/zui/safecenter/SafecenterWidget;",
                "refreshWidget",
                0x7f09009e,
                8,
                1,
            )
            .expect("hide");
        }
        assert_eq!(hit, 1, "autostart-apps widget item hidden once");
    }

    /// `force_method_return_void` neutralizes the antivirus engine init on the
    /// real ZuiSecurity.apk. Set DYNOBOX_ZUISECURITY_APK.
    #[test]
    fn method_nop_lands_on_real_zuisecurity_antivirus() {
        let Ok(path) = std::env::var("DYNOBOX_ZUISECURITY_APK") else {
            return;
        };
        let apk = std::fs::read(path).expect("read ZuiSecurity.apk");
        let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("parse apk");
        let mut hits = 0usize;
        for entry in zip.entries.iter().filter(|e| {
            e.name.ends_with(".dex")
                && e.compression_method == 0
                && !e.uses_data_descriptor
                && !e.is_zip64
                && e.data_start + e.compressed_size <= apk.len()
        }) {
            let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
            let cls = "Lcom/lenovo/safecenter/antivirus/external/AntiVirusInterface;";
            if force_method_return_void(
                &mut dex,
                cls,
                "initTMSApplication",
                "V",
                &["Landroid/content/Context;", "Z"],
            )
            .expect("nop")
            {
                hits += 1;
            }
            let mut dex_modified = false;
            for m in [
                "startAutoScanBroadcastReceiver",
                "startUpdateTMSVirusDbReceiver",
            ] {
                if force_method_return_void(&mut dex, cls, m, "V", &["Landroid/content/Context;"])
                    .expect("nop")
                {
                    hits += 1;
                    dex_modified = true;
                }
            }
            // Optionally emit the finalized dex (sums recomputed, as dbp does) so a
            // structural validator (dexdump / dex2oat) can confirm it still loads.
            if let Ok(out) = std::env::var("DYNOBOX_ZUISECURITY_DEX_OUT") {
                if dex_modified {
                    crate::fuck_lgsi::recompute_dex_header_sums(&mut dex);
                    std::fs::write(std::path::Path::new(&out).join(&entry.name), &dex)
                        .expect("write patched dex");
                }
            }
        }
        assert_eq!(
            hits, 3,
            "all 3 AntiVirusInterface hub methods neutralized once"
        );
    }
}
