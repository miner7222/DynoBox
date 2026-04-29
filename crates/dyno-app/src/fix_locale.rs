//! Bypass Lenovo's `ZuiAntiCrossSell` locale gate inside `system.img`.
//!
//! The Configuration.setLocales path on TB322 vendors a region check that
//! forces `zh_CN` whenever `ro.config.lgsi.region == "prc"` and the runtime
//! locale doesn't already contain `zh`. The cheapest reliable disarm is to
//! flip the very first conditional branch to `cond_2` in `setLocales` into
//! an unconditional `goto cond_2`, so the rest of the gate is skipped
//! regardless of the LGSI feature flag, region prop, or current locale.
//!
//! End-to-end:
//!   1. Walk `system.img` as ext4 to `/system/framework/framework.jar`.
//!   2. Parse the JAR's ZIP layout (entries are stored, not deflated).
//!   3. Locate the `classes*.dex` carrying the AntiCrossSell anchor — the
//!      string `ZuiAntiCrossSell` must be in the dex string table, and a
//!      bytecode anchor matching `const-string vAA, "ZuiAntiCrossSell";
//!      invoke-static; move-result; if-eqz vAA, +cond_2` must occur in the
//!      method's insns. If the anchor is absent (already patched, different
//!      build, or the class was refactored), return [`FixLocaleOutcome::NotApplicable`]
//!      and leave both images alone.
//!   4. Replace the 4-byte `if-eqz vAA, +OFF` (opcode 0x38, fmt 21t) with
//!      `goto/16 +OFF` (opcode 0x29, fmt 20t). Both instructions are 4
//!      bytes wide and store the branch offset in the same bytes, so the
//!      branch target stays valid.
//!   5. Recompute the dex header's SHA-1 signature (covers bytes 32..) and
//!      Adler-32 checksum (covers bytes 12..) so ART will load the dex.
//!   6. Update CRC32 in the JAR's local file header and central directory
//!      entry for the modified dex. JAR length is preserved.
//!   7. Write the rewritten JAR back to `system.img` through the inode's
//!      extent map (same byte loop pattern as `vendor_spl::patch_build_prop_spl_via_ext4`).
//!   8. Regenerate the dm-verity hash tree on `system.img` and overwrite
//!      the existing tree region. Patch `system.img`'s footer Hashtree
//!      descriptor's `root_digest` (NONE-algorithm vbmeta — no signature
//!      to invalidate).
//!   9. Patch `vbmeta_system.img`'s embedded Hashtree descriptor for the
//!      `system` partition to the same new digest. The signed vbmeta is
//!      left with a stale signature, which the regular resign loop
//!      refreshes after this module returns.
//!
//! FEC blocks on `system.img` are intentionally untouched — same trade-off
//! as `vendor_spl`. dm-verity validates against `root_digest`; FEC is an
//! optional recovery code and stale FEC does not break boot.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use memchr::memmem;

use crate::avb_descriptor::{
    SHA256_DIGEST_SIZE, hex_encode, patch_hashtree_root_digest, read_hashtree_params,
    regenerate_hashtree,
};
use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume, write_via_extents};

const ANTI_CROSS_SELL_STRING: &str = "ZuiAntiCrossSell";
const FRAMEWORK_JAR_PATH: &[&str] = &["system", "framework", "framework.jar"];
const SYSTEM_PARTITION_NAME: &str = "system";

/// Outcome of an attempted `--fix-locale` pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixLocaleOutcome {
    /// AntiCrossSell anchor was found and patched. `system.img` and
    /// `vbmeta_system.img` were updated. Caller must re-sign vbmeta_system
    /// (regular resign loop handles that).
    Patched {
        dex_entry: String,
        if_eqz_offset_in_jar: u64,
        old_root_digest: String,
        new_root_digest: String,
    },
    /// The patch was a no-op for one of the legitimate skip reasons:
    /// `framework.jar` is missing, or it exists but the AntiCrossSell
    /// anchor is not present (already patched, different ROM build, or
    /// refactored class). The pipeline continues without touching
    /// `system.img` or `vbmeta_system.img`. `reason` carries the
    /// human-readable explanation for the progress log.
    NotApplicable { reason: String },
}

/// Apply `--fix-locale` to a freshly unpacked `system.img` and propagate
/// the new dm-verity root digest to `vbmeta_system.img`.
pub fn apply_fix_locale(
    system_image: &Path,
    vbmeta_system_image: &Path,
) -> Result<FixLocaleOutcome> {
    // 1. Locate framework.jar and its on-disk extent layout.
    let mut volume = open_ext4_volume(system_image)?;
    let inode = match lookup_inode_at_path(&mut volume, FRAMEWORK_JAR_PATH)? {
        Some(i) => i,
        None => {
            return Ok(FixLocaleOutcome::NotApplicable {
                reason: "/system/framework/framework.jar not found in system.img".to_string(),
            });
        }
    };
    if !inode.is_file() {
        return Err(anyhow!(
            "system.img /system/framework/framework.jar is not a regular file"
        ));
    }
    let jar_extents = inode
        .extent_mapping(&mut volume)
        .map_err(|e| anyhow!("Failed to walk framework.jar extent tree: {e}"))?;
    let jar_bytes = inode
        .open_read(&mut volume)
        .map_err(|e| anyhow!("Failed to read framework.jar from system.img: {e}"))?;
    let block_size = volume.block_size;
    drop(volume);

    if jar_extents.is_empty() {
        return Err(anyhow!(
            "framework.jar has no extents (inline data not supported here)"
        ));
    }

    // 2. Parse the JAR's ZIP central directory and find which classes*.dex
    //    carries the AntiCrossSell anchor.
    let zip = parse_zip_central_directory(&jar_bytes)?;
    let Some(target) = locate_anti_cross_sell_target(&jar_bytes, &zip)? else {
        return Ok(FixLocaleOutcome::NotApplicable {
            reason: format!(
                "no `{ANTI_CROSS_SELL_STRING}` AntiCrossSell anchor found in framework.jar; \
                 likely already patched or different build"
            ),
        });
    };

    // 3. Build the patched JAR in memory: byte-flip the if-eqz, recompute
    //    dex sha1 + adler32, recompute zip CRC32.
    let mut patched_jar = jar_bytes.clone();
    let dex_data_off = target.entry.data_start;
    let dex_data_end = dex_data_off + target.entry.compressed_size;
    let dex_slice = &mut patched_jar[dex_data_off..dex_data_end];

    // Replace `38 RR LO HI` (if-eqz) with `29 00 LO HI` (goto/16).
    // The branch offset bytes (LO HI) carry over unchanged so cond_2 stays
    // reachable. AA reg drops to 00 padding because goto/16 is fmt 20t.
    let if_eqz_off_in_dex = target.if_eqz_off_in_dex;
    if dex_slice[if_eqz_off_in_dex] != 0x38 {
        return Err(anyhow!(
            "Anchor mismatch: byte at dex offset {} is {:#04x}, expected 0x38 (if-eqz)",
            if_eqz_off_in_dex,
            dex_slice[if_eqz_off_in_dex]
        ));
    }
    dex_slice[if_eqz_off_in_dex] = 0x29; // goto/16 opcode
    dex_slice[if_eqz_off_in_dex + 1] = 0x00; // 20t padding

    recompute_dex_header_sums(dex_slice)?;

    // Recompute zip CRC32 for the patched dex entry, both in the local
    // file header and the central directory entry, so the jar still
    // verifies.
    let new_crc = crc32_ieee(dex_slice);
    write_u32_le(
        &mut patched_jar,
        target.entry.local_header_crc_offset,
        new_crc,
    );
    write_u32_le(&mut patched_jar, target.entry.cd_crc_offset, new_crc);

    if patched_jar.len() != jar_bytes.len() {
        return Err(anyhow!(
            "Internal error: patched framework.jar length {} does not match original {}",
            patched_jar.len(),
            jar_bytes.len()
        ));
    }

    // 4. Stash the JAR-relative byte offset of the patched if-eqz for the
    //    progress message — useful when reproducing on a different ROM.
    let if_eqz_offset_in_jar = (dex_data_off + if_eqz_off_in_dex) as u64;

    // 5. Write the rewritten JAR back into system.img through the inode's
    //    extent mapping. The JAR is the same length as before, so each
    //    file-byte still maps to the same disk-byte and no extents need
    //    reflowing. The write is chunked per extent to keep the seek/write
    //    count manageable on a ~50 MB jar.
    write_via_extents(system_image, &patched_jar, &jar_extents, block_size)?;

    // 6. Regenerate the dm-verity hash tree on the modified system.img and
    //    capture the new root digest.
    let hashtree = read_hashtree_params(system_image, SYSTEM_PARTITION_NAME)?
        .ok_or_else(|| anyhow!("system.img has no Hashtree descriptor for `system`"))?;
    let old_root_digest = hashtree.root_digest.clone();
    let new_root_digest = regenerate_hashtree(system_image, &hashtree)?;
    if new_root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "Regenerated hash tree returned unexpected root_digest length {}",
            new_root_digest.len()
        ));
    }

    // 7. Patch system.img's footer Hashtree descriptor (NONE algorithm —
    //    no signature, descriptor body is rewritten in place).
    patch_hashtree_root_digest(system_image, SYSTEM_PARTITION_NAME, &new_root_digest)?;

    // 8. Patch vbmeta_system.img's embedded Hashtree descriptor for
    //    `system`. The image is signed; the resign loop will refresh the
    //    signature after this module returns.
    patch_hashtree_root_digest(vbmeta_system_image, SYSTEM_PARTITION_NAME, &new_root_digest)?;

    Ok(FixLocaleOutcome::Patched {
        dex_entry: target.entry.name.clone(),
        if_eqz_offset_in_jar,
        old_root_digest: hex_encode(&old_root_digest),
        new_root_digest: hex_encode(&new_root_digest),
    })
}

// ---------------------------------------------------------------------------
// ZIP local-file-header / central-directory parsing (only what we need)
// ---------------------------------------------------------------------------

const ZIP_LOCAL_FILE_HEADER_SIG: u32 = 0x04034B50;
const ZIP_CENTRAL_DIRECTORY_SIG: u32 = 0x02014B50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIG: u32 = 0x06054B50;
/// ZIP general-purpose flag bit 3: when set, CRC + sizes in the local
/// file header are zero and the real values live in a trailing data
/// descriptor. We don't parse data descriptors and would silently rewrite
/// the wrong CRC32 offset, so bail loudly when we see it set.
const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
/// ZIP64 sentinel value for compressed/uncompressed size or local header
/// offset. When present in any of those fields the real value lives in
/// a ZIP64 extra-field record, which we don't parse. framework.jar is
/// well under 4 GiB today; bail explicitly if a future build crosses the
/// line so we fail-loud instead of silently corrupting the JAR.
const ZIP64_SENTINEL_U32: u32 = 0xFFFFFFFF;

#[derive(Debug, Clone)]
struct ZipEntry {
    name: String,
    /// Byte offset of the entry's first data byte inside the JAR, after
    /// its local file header and any extra fields.
    data_start: usize,
    /// Compressed data length. For stored entries (method 0) this equals
    /// the uncompressed length, which is the layout framework.jar uses.
    compressed_size: usize,
    /// Byte offset inside the JAR of the CRC32 field in the entry's local
    /// file header.
    local_header_crc_offset: usize,
    /// Byte offset inside the JAR of the CRC32 field in the entry's
    /// central directory record.
    cd_crc_offset: usize,
    compression_method: u16,
}

#[derive(Debug, Clone)]
struct ZipLayout {
    entries: Vec<ZipEntry>,
}

fn parse_zip_central_directory(bytes: &[u8]) -> Result<ZipLayout> {
    let eocd_off = find_eocd(bytes)?;
    if bytes.len() < eocd_off + 22 {
        return Err(anyhow!("framework.jar truncated at EOCD"));
    }
    let cd_size = read_u32_le(bytes, eocd_off + 12) as usize;
    let cd_off = read_u32_le(bytes, eocd_off + 16) as usize;
    let total_records = read_u16_le(bytes, eocd_off + 10) as usize;

    let mut entries = Vec::with_capacity(total_records);
    let mut cursor = cd_off;
    let cd_end = cd_off + cd_size;
    while cursor < cd_end {
        if bytes.len() < cursor + 46 {
            return Err(anyhow!("framework.jar central directory truncated"));
        }
        let sig = read_u32_le(bytes, cursor);
        if sig != ZIP_CENTRAL_DIRECTORY_SIG {
            return Err(anyhow!(
                "framework.jar central directory: unexpected signature {sig:#010x} at offset {cursor}"
            ));
        }
        let cd_flags = read_u16_le(bytes, cursor + 8);
        let compression_method = read_u16_le(bytes, cursor + 10);
        let cd_crc_offset = cursor + 16;
        let compressed_size_raw = read_u32_le(bytes, cursor + 20);
        let uncompressed_size_raw = read_u32_le(bytes, cursor + 24);
        let name_len = read_u16_le(bytes, cursor + 28) as usize;
        let extra_len = read_u16_le(bytes, cursor + 30) as usize;
        let comment_len = read_u16_le(bytes, cursor + 32) as usize;
        let local_header_offset_raw = read_u32_le(bytes, cursor + 42);
        let name = std::str::from_utf8(&bytes[cursor + 46..cursor + 46 + name_len])
            .context("framework.jar central directory entry has non-UTF-8 name")?
            .to_string();

        if cd_flags & ZIP_FLAG_DATA_DESCRIPTOR != 0 {
            return Err(anyhow!(
                "framework.jar entry {} uses ZIP data-descriptor (flag bit 3); CRC + sizes live in a trailing record this parser does not handle",
                name
            ));
        }
        if compressed_size_raw == ZIP64_SENTINEL_U32
            || uncompressed_size_raw == ZIP64_SENTINEL_U32
            || local_header_offset_raw == ZIP64_SENTINEL_U32
        {
            return Err(anyhow!(
                "framework.jar entry {} uses ZIP64 extended fields ({:#010x} sentinel); ZIP64 is not supported here",
                name,
                ZIP64_SENTINEL_U32
            ));
        }
        let compressed_size = compressed_size_raw as usize;
        let local_header_offset = local_header_offset_raw as usize;

        // Walk the local file header to compute data_start.
        if bytes.len() < local_header_offset + 30 {
            return Err(anyhow!(
                "framework.jar local file header for {name} truncated"
            ));
        }
        let lfh_sig = read_u32_le(bytes, local_header_offset);
        if lfh_sig != ZIP_LOCAL_FILE_HEADER_SIG {
            return Err(anyhow!(
                "framework.jar local file header for {name}: unexpected signature {lfh_sig:#010x}"
            ));
        }
        let lfh_flags = read_u16_le(bytes, local_header_offset + 6);
        if lfh_flags & ZIP_FLAG_DATA_DESCRIPTOR != 0 {
            return Err(anyhow!(
                "framework.jar entry {} local file header flags ZIP data-descriptor (bit 3); not supported",
                name
            ));
        }
        let local_header_crc_offset = local_header_offset + 14;
        let local_name_len = read_u16_le(bytes, local_header_offset + 26) as usize;
        let local_extra_len = read_u16_le(bytes, local_header_offset + 28) as usize;
        let data_start = local_header_offset + 30 + local_name_len + local_extra_len;

        entries.push(ZipEntry {
            name,
            data_start,
            compressed_size,
            local_header_crc_offset,
            cd_crc_offset,
            compression_method,
        });

        cursor += 46 + name_len + extra_len + comment_len;
    }
    Ok(ZipLayout { entries })
}

fn find_eocd(bytes: &[u8]) -> Result<usize> {
    // Standard scan: the EOCD record can be up to 65 KiB from the file end
    // because of the optional comment field. framework.jar has no comment
    // so the record sits at exactly `len - 22`, but we still scan to stay
    // tolerant of future builds.
    let max_back = std::cmp::min(bytes.len(), 65_557);
    let start = bytes.len().saturating_sub(max_back);
    for off in (start..bytes.len().saturating_sub(21)).rev() {
        if read_u32_le(bytes, off) == ZIP_END_OF_CENTRAL_DIRECTORY_SIG {
            return Ok(off);
        }
    }
    Err(anyhow!(
        "framework.jar EOCD signature not found; not a valid ZIP"
    ))
}

// ---------------------------------------------------------------------------
// Anchor location inside dex bytecode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct AnchorTarget {
    entry: ZipEntry,
    /// Byte offset of the `if-eqz` opcode inside the dex (== inside the
    /// JAR-relative dex slice).
    if_eqz_off_in_dex: usize,
}

fn locate_anti_cross_sell_target(
    jar_bytes: &[u8],
    zip: &ZipLayout,
) -> Result<Option<AnchorTarget>> {
    for entry in &zip.entries {
        if !entry.name.ends_with(".dex") {
            continue;
        }
        if entry.compression_method != 0 {
            // framework.jar entries are stored. A deflated dex would
            // require us to inflate before scanning, which is out of
            // scope; warn loudly so we do not silently no-op on a
            // future build that flips compression on.
            return Err(anyhow!(
                "framework.jar dex entry {} is compressed (method {}); only stored dex entries are supported",
                entry.name,
                entry.compression_method
            ));
        }
        let dex_bytes = &jar_bytes[entry.data_start..entry.data_start + entry.compressed_size];
        let Some(if_eqz_off) = find_anti_cross_sell_anchor(dex_bytes)? else {
            continue;
        };
        return Ok(Some(AnchorTarget {
            entry: entry.clone(),
            if_eqz_off_in_dex: if_eqz_off,
        }));
    }
    Ok(None)
}

/// Search a dex for the AntiCrossSell branch anchor and return the byte
/// offset of the `if-eqz` (within the dex) if found.
fn find_anti_cross_sell_anchor(dex_bytes: &[u8]) -> Result<Option<usize>> {
    // Locate the string ID of "ZuiAntiCrossSell" in the dex string pool.
    // dex strings are stored in UTF-8 (modified MUTF-8 for non-ASCII) with
    // a ULEB128 length prefix; the anchor is plain ASCII so a direct
    // memmem hit is conclusive.
    let needle_with_prefix = build_dex_string_with_uleb_prefix(ANTI_CROSS_SELL_STRING);
    if memmem::find(dex_bytes, &needle_with_prefix).is_none() {
        return Ok(None);
    }

    let string_idx = match find_string_idx(dex_bytes, ANTI_CROSS_SELL_STRING)? {
        Some(idx) => idx,
        None => return Ok(None),
    };

    // Scan dex bytes for `1A AA II II` (const-string vAA, "ZuiAntiCrossSell")
    // followed 12 bytes later by `38 ?? LL HH` (if-eqz vBB, +OFF). The
    // intervening 12 bytes are invoke-static (6 bytes, fmt 35c) and
    // move-result (2 bytes, fmt 11x) plus the const-string itself's 4
    // bytes — but we anchor on opcode 0x1A's byte position, so the
    // distance to the if-eqz is 4 + 6 + 2 = 12 bytes.
    let idx_lo = (string_idx & 0xFF) as u8;
    let idx_hi = ((string_idx >> 8) & 0xFF) as u8;
    if string_idx > 0xFFFF {
        // Const-string with a >16-bit string idx would have to be encoded
        // as const-string/jumbo (opcode 0x1B). The probe shows 0x1A is
        // used here, so a >16-bit idx is unexpected and would invalidate
        // the anchor pattern.
        return Err(anyhow!(
            "AntiCrossSell string idx {} exceeds 16 bits; const-string/jumbo flow not handled",
            string_idx
        ));
    }

    let mut hits = Vec::new();
    let mut i = 0usize;
    // Read four bytes at i (`1A AA II II`) plus the byte at i+12
    // (expected `38`). The tightest correct upper bound is therefore
    // i + 13 ≤ dex_bytes.len(), not i + 16.
    while i + 13 <= dex_bytes.len() {
        if dex_bytes[i] == 0x1A
            && dex_bytes[i + 2] == idx_lo
            && dex_bytes[i + 3] == idx_hi
            && dex_bytes[i + 12] == 0x38
        {
            hits.push(i + 12);
        }
        i += 1;
    }

    match hits.len() {
        0 => Ok(None),
        1 => Ok(Some(hits[0])),
        _ => Err(anyhow!(
            "AntiCrossSell anchor matched in {} places; refusing to guess which one to patch",
            hits.len()
        )),
    }
}

/// Walk the dex string_ids table and return the index of the first string
/// whose decoded value equals `needle`. Returns `Ok(None)` when the string
/// isn't in the pool.
fn find_string_idx(dex_bytes: &[u8], needle: &str) -> Result<Option<u32>> {
    if dex_bytes.len() < 0x70 {
        return Err(anyhow!("dex truncated below header size"));
    }
    let string_ids_size = read_u32_le(dex_bytes, 0x38) as usize;
    let string_ids_off = read_u32_le(dex_bytes, 0x3C) as usize;
    if string_ids_off + string_ids_size * 4 > dex_bytes.len() {
        return Err(anyhow!("dex string_ids table out of bounds"));
    }
    let needle_bytes = needle.as_bytes();
    for idx in 0..string_ids_size {
        let str_data_off = read_u32_le(dex_bytes, string_ids_off + idx * 4) as usize;
        if str_data_off >= dex_bytes.len() {
            continue;
        }
        // string_data_item: ULEB128 utf16_size, then MUTF-8 bytes ending
        // with a NUL terminator.
        let mut p = str_data_off;
        // Skip the ULEB128 length prefix.
        loop {
            if p >= dex_bytes.len() {
                return Err(anyhow!("dex string_data_item truncated at offset {p}"));
            }
            let b = dex_bytes[p];
            p += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        if p + needle_bytes.len() + 1 > dex_bytes.len() {
            continue;
        }
        if &dex_bytes[p..p + needle_bytes.len()] == needle_bytes
            && dex_bytes[p + needle_bytes.len()] == 0
        {
            return Ok(Some(idx as u32));
        }
    }
    Ok(None)
}

/// Build the byte sequence we'd expect to find inline if `needle` is in
/// the dex string pool: ULEB128(utf16-size) then MUTF-8 bytes then NUL.
/// Used as a cheap up-front existence probe before we walk the string_ids
/// table.
fn build_dex_string_with_uleb_prefix(needle: &str) -> Vec<u8> {
    // For ASCII strings the utf16_size equals the byte count.
    let len = needle.len();
    let mut out = Vec::with_capacity(len + 4);
    let mut v = len as u32;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
    out.extend_from_slice(needle.as_bytes());
    out.push(0);
    out
}

// ---------------------------------------------------------------------------
// Dex header recomputation (sha1 signature + adler32 checksum)
// ---------------------------------------------------------------------------

fn recompute_dex_header_sums(dex: &mut [u8]) -> Result<()> {
    if dex.len() < 0x70 {
        return Err(anyhow!("dex too small to recompute header sums"));
    }
    // signature = sha1(bytes[32..]); written into bytes[12..32].
    let sig = sha1_digest(&dex[32..]);
    dex[12..32].copy_from_slice(&sig);
    // checksum = adler32(bytes[12..]); written into bytes[8..12].
    let cksum = adler32(&dex[12..]);
    dex[8..12].copy_from_slice(&cksum.to_le_bytes());
    Ok(())
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    use sha1_hasher::SimpleSha1;
    let mut h = SimpleSha1::new();
    h.update(data);
    h.finalize()
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    // Process in chunks small enough that (a + max_byte * chunk_len) and
    // (b + a * chunk_len) stay under 2^32 to dodge wraparound before mod.
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

// Tiny pure-rust SHA-1, kept inline so we don't pull `sha1` as a direct
// dynobox dep just for the dex header. The `avbtool-rs` workspace already
// uses sha1 transitively, but adding it to dyno-app's manifest just for
// this single hash isn't worth the extra dep audit surface — and SHA-1 is
// a small, well-bounded primitive.
mod sha1_hasher {
    pub struct SimpleSha1 {
        h: [u32; 5],
        buffer: Vec<u8>,
        total_len: u64,
    }

    impl SimpleSha1 {
        pub fn new() -> Self {
            Self {
                h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
                buffer: Vec::with_capacity(64),
                total_len: 0,
            }
        }
        pub fn update(&mut self, data: &[u8]) {
            self.total_len = self.total_len.wrapping_add(data.len() as u64);
            self.buffer.extend_from_slice(data);
            while self.buffer.len() >= 64 {
                let block: [u8; 64] = self.buffer[..64].try_into().unwrap();
                self.process_block(&block);
                self.buffer.drain(..64);
            }
        }
        pub fn finalize(mut self) -> [u8; 20] {
            let bit_len = self.total_len.wrapping_mul(8);
            self.buffer.push(0x80);
            while self.buffer.len() % 64 != 56 {
                self.buffer.push(0);
            }
            self.buffer.extend_from_slice(&bit_len.to_be_bytes());
            while self.buffer.len() >= 64 {
                let block: [u8; 64] = self.buffer[..64].try_into().unwrap();
                self.process_block(&block);
                self.buffer.drain(..64);
            }
            let mut out = [0u8; 20];
            for (i, word) in self.h.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            out
        }
        fn process_block(&mut self, block: &[u8; 64]) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let [mut a, mut b, mut c, mut d, mut e] = self.h;
            for i in 0..80 {
                let (f, k) = if i < 20 {
                    ((b & c) | ((!b) & d), 0x5A827999)
                } else if i < 40 {
                    (b ^ c ^ d, 0x6ED9EBA1)
                } else if i < 60 {
                    ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
                } else {
                    (b ^ c ^ d, 0xCA62C1D6)
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
        }
    }
}

// ---------------------------------------------------------------------------
// CRC32 (IEEE 802.3) — byte-level implementation, no extra crate.
// ---------------------------------------------------------------------------

fn crc32_ieee(data: &[u8]) -> u32 {
    // Standard IEEE 802.3 CRC32 with reflected polynomial 0xEDB88320, no
    // table caching — at ~50 MB per call (the framework.jar dex slice) the
    // table-build cost is dwarfed by the data scan. Avoiding a static
    // keeps `dyno-app` from picking up a `once_cell` / `LazyLock` dep just
    // for one polynomial table.
    let mut table = [0u32; 256];
    for n in 0..256 {
        let mut c = n as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        table[n] = c;
    }
    let mut crc = 0xFFFFFFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF
}

// ---------------------------------------------------------------------------
// Misc small helpers
// ---------------------------------------------------------------------------

fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn write_u32_le(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"abc"), 0x024D0127);
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn crc32_ieee_known_values() {
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn sha1_known_values() {
        let d = sha1_digest(b"abc");
        let expected: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(d, expected);
    }

    #[test]
    fn build_dex_string_with_uleb_prefix_round_trip() {
        let s = build_dex_string_with_uleb_prefix("zh");
        // utf16 size = 2, ULEB128 = single byte 0x02. Then "zh" + NUL.
        assert_eq!(s, vec![0x02, b'z', b'h', 0x00]);
    }
}
