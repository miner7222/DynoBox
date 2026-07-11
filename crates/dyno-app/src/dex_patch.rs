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
//! * [`force_nop_anchored_invoke`] — nop the first
//!   `target_class.target_method(...)` invoke (whose result is discarded)
//!   that follows a specific constant load inside one scan method. Drops a
//!   single imperative `List.add`/`Map.put`-style call site without
//!   disturbing the surrounding method.
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
// primitive 2: force an invoke-static bool getter's result at call sites
// ---------------------------------------------------------------------------

/// Force every `invoke-static {}, target_class.target_method(params...)Z`
/// immediately followed by `move-result vAA` to the constant `value`, but only
/// inside the methods of `scan_class` (optionally narrowed to `scan_method`).
/// Returns the number of sites rewritten (0 when the scan class or target
/// method isn't present in this dex).
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

/// Walk one method's instruction stream and rewrite each
/// `invoke-static {}, method@target_method_idx` (opcode 0x71) immediately
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
        if opcode == 0x71 && pc + 8 <= insns_end {
            let method_idx = u32::from(read_u16_le(dex, pc + 2));
            if method_idx == target_method_idx && dex[pc + 6] == 0x0A {
                let aa = dex[pc + 7];
                // Overwrite the 4-unit `invoke-static … / move-result vAA` with a
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
// primitive 5: force findViewById-bound views to setVisibility(GONE)
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
