//! Shared engine for the ext4-partition security-patch-level (SPL) bumps
//! behind `--vendor-spl` and `--system-spl`.
//!
//! Both flags do the exact same thing to different partitions: walk the
//! ext4 filesystem inside the image to locate `build.prop`, rewrite the
//! 10-byte `YYYY-MM-DD` SPL value in place through the inode's extent tree
//! (ext4-aware, so the edit lands on the live data block rather than a
//! stale copy of the same string in unallocated space), regenerate the
//! dm-verity hash tree, then patch the AVB Hashtree `root_digest` and the
//! matching Property descriptor in both the partition image (NONE
//! algorithm — rewritten in place, length-stable) and the signed vbmeta
//! image (whose stale signature the resign loop refreshes afterwards).
//!
//! FEC blocks are intentionally left untouched: dm-verity validates
//! against the new `root_digest` only, and FEC is a recovery code for
//! damaged blocks — a stale FEC region does not break boot.
//!
//! The per-flag differences are captured in [`SplPatchSpec`]; `vendor_spl`
//! and `system_spl` are thin wrappers that bind a spec and re-export the
//! shared [`SplOutcome`].

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::avb_descriptor::{
    PatchPropertyOutcome, SHA256_DIGEST_SIZE, VerityProgressCallback, hex_encode,
    patch_hashtree_root_digest, patch_property_value, read_hashtree_params,
    regenerate_hashtree_with_progress,
};
use crate::ext4_helpers::{lookup_inode_at_path, map_file_offset_to_disk, open_ext4_volume};
use anyhow::{Context, Result, anyhow};
use memchr::memmem;

/// Per-partition parameters that distinguish `--vendor-spl` from
/// `--system-spl`. Everything else in the patch flow is identical.
pub struct SplPatchSpec {
    /// CLI flag name, used in validation error messages (e.g. `--vendor-spl`).
    pub flag_label: &'static str,
    /// AVB partition name in the Hashtree descriptor (e.g. `vendor`).
    pub partition_name: &'static str,
    /// Human label for the partition image in messages (e.g. `vendor.img`).
    pub image_label: &'static str,
    /// AVB Property descriptor key carrying the SPL date.
    pub avb_property: &'static str,
    /// ext4 path components of build.prop (e.g. `["build.prop"]`).
    pub build_prop_path: &'static [&'static str],
    /// Display form of the build.prop path for messages (e.g. `/build.prop`).
    pub build_prop_display: &'static str,
    /// build.prop key whose value is the SPL date, including the `=`.
    pub build_prop_needle: &'static [u8],
}

/// Result of applying an SPL bump to a partition + its vbmeta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplOutcome {
    Patched {
        old: String,
        new: String,
        old_root_digest: String,
        new_root_digest: String,
    },
    SkippedNotNewer {
        old: String,
        requested: String,
    },
    NotFound,
}

/// Result of the data-only SPL mutation (build.prop byte patch + AVB Property
/// descriptor date on the partition footer and vbmeta), *before* dm-verity is
/// regenerated. The verity hash tree + Hashtree `root_digest` are handled
/// separately (deferred to a single per-partition pass by the resign stage) so
/// combining several ops on the same partition doesn't re-walk it repeatedly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplMutationOutcome {
    Patched { old: String, new: String },
    SkippedNotNewer { old: String, requested: String },
    NotFound,
}

/// Apply the SPL change to `image` + `vbmeta_image` **without** regenerating
/// dm-verity: patch the build.prop date bytes and the AVB Property descriptor
/// date (both digest-independent and length-stable). The partition's data is
/// left "dirty"; the caller must regenerate the dm-verity hash tree and
/// re-stamp the Hashtree `root_digest` afterwards.
pub fn apply_spl_mutation(
    spec: &SplPatchSpec,
    image: &Path,
    vbmeta_image: &Path,
    new_spl: &str,
) -> Result<SplMutationOutcome> {
    validate_spl_format(spec, new_spl)?;

    let current_avb = match read_avb_property(spec, image)? {
        Some(value) => value,
        None => return Ok(SplMutationOutcome::NotFound),
    };
    if new_spl <= current_avb.as_str() {
        return Ok(SplMutationOutcome::SkippedNotNewer {
            old: current_avb,
            requested: new_spl.to_string(),
        });
    }

    // Validate the Hashtree descriptor is present + well-formed up front so we
    // fail before touching bytes, matching the old all-in-one path.
    let hashtree = read_hashtree_params(image, spec.partition_name)?.ok_or_else(|| {
        anyhow!(
            "{} has no Hashtree descriptor for partition `{}`",
            spec.image_label,
            spec.partition_name
        )
    })?;
    if hashtree.root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "{} Hashtree descriptor uses an unexpected root_digest length {} (expected {})",
            spec.image_label,
            hashtree.root_digest.len(),
            SHA256_DIGEST_SIZE
        ));
    }

    patch_build_prop_spl_via_ext4(spec, image, new_spl)?;
    patch_property_or_explain(image, spec.avb_property, new_spl)?;
    patch_property_or_explain(vbmeta_image, spec.avb_property, new_spl)?;

    Ok(SplMutationOutcome::Patched {
        old: current_avb,
        new: new_spl.to_string(),
    })
}

/// Validate `spl` is a strict `YYYY-MM-DD` ASCII string. The in-place patch
/// relies on the new value matching the existing length.
pub fn validate_spl_format(spec: &SplPatchSpec, spl: &str) -> Result<()> {
    crate::spl::validate_spl_format(spec.flag_label, spl)
}

/// Read the current SPL property value from the partition image footer,
/// or `Ok(None)` if absent.
pub fn read_avb_property(spec: &SplPatchSpec, image: &Path) -> Result<Option<String>> {
    crate::avb_descriptor::read_property_value(image, spec.avb_property)
}

/// Apply an SPL bump to `image` and propagate the change to `vbmeta_image`.
/// Caller is responsible for re-signing `vbmeta_image` after this returns.
///
/// `verity_progress` receives per-leaf-block delta byte counts during the
/// dm-verity regeneration phase — the only stage long enough (a SHA-256
/// walk over a multi-GiB image) to need a progress bar; the other phases
/// are sub-second.
pub fn apply_spl_with_progress(
    spec: &SplPatchSpec,
    image: &Path,
    vbmeta_image: &Path,
    new_spl: &str,
    verity_progress: Option<VerityProgressCallback>,
) -> Result<SplOutcome> {
    validate_spl_format(spec, new_spl)?;

    // 1. Read current SPL property from the image footer.
    let current_avb = match read_avb_property(spec, image)? {
        Some(value) => value,
        None => return Ok(SplOutcome::NotFound),
    };
    if new_spl <= current_avb.as_str() {
        return Ok(SplOutcome::SkippedNotNewer {
            old: current_avb,
            requested: new_spl.to_string(),
        });
    }

    // 2. Read hashtree descriptor params (need image_size for the rebuild
    //    and the salt/algorithm for verity regeneration after).
    let hashtree = read_hashtree_params(image, spec.partition_name)?.ok_or_else(|| {
        anyhow!(
            "{} has no Hashtree descriptor for partition `{}`",
            spec.image_label,
            spec.partition_name
        )
    })?;
    let old_root_digest = hashtree.root_digest.clone();
    if hashtree.root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "{} Hashtree descriptor uses an unexpected root_digest length {} (expected {})",
            spec.image_label,
            hashtree.root_digest.len(),
            SHA256_DIGEST_SIZE
        ));
    }

    // 3. Walk the image as an ext4 filesystem, resolve build.prop's disk-byte
    //    range via the inode extent tree, and overwrite the SPL value in
    //    place. A blind partition-wide `memchr` scan would happily land on a
    //    stale copy of the same string in unallocated space and leave the
    //    live build.prop unchanged.
    patch_build_prop_spl_via_ext4(spec, image, new_spl)?;

    // 4. Regenerate dm-verity hash tree from the modified data and write it
    //    back at `tree_offset`. `regenerate_hashtree_with_progress` mirrors
    //    `avbtool_rs::footer::generate_hash_tree` byte-for-byte but exposes a
    //    per-leaf-block progress hook.
    let new_root_digest = regenerate_hashtree_with_progress(image, &hashtree, verity_progress)?;
    if new_root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "Regenerated hash tree returned unexpected root_digest length {}",
            new_root_digest.len()
        ));
    }

    // 5. Patch the partition image footer descriptors (NONE: no signature).
    patch_property_or_explain(image, spec.avb_property, new_spl)?;
    patch_hashtree_root_digest(image, spec.partition_name, &new_root_digest)?;

    // 6. Patch vbmeta descriptors. The signed blob is left with a stale
    //    signature that the resign stage will refresh.
    patch_property_or_explain(vbmeta_image, spec.avb_property, new_spl)?;
    patch_hashtree_root_digest(vbmeta_image, spec.partition_name, &new_root_digest)?;

    Ok(SplOutcome::Patched {
        old: current_avb,
        new: new_spl.to_string(),
        old_root_digest: hex_encode(&old_root_digest),
        new_root_digest: hex_encode(&new_root_digest),
    })
}

/// Wrap `avb_descriptor::patch_property_value` with SPL-flavoured error
/// messages so callers don't have to repeat the dispatch.
fn patch_property_or_explain(image_path: &Path, target_key: &str, new_value: &str) -> Result<()> {
    match patch_property_value(image_path, target_key, new_value.as_bytes())? {
        PatchPropertyOutcome::Patched { .. } => Ok(()),
        PatchPropertyOutcome::NotFound => Err(anyhow!(
            "{} is missing the {} property descriptor",
            image_path.display(),
            target_key
        )),
        PatchPropertyOutcome::LengthMismatch {
            current_value,
            current_len,
            requested_len,
        } => Err(anyhow!(
            "{} {} property is {} bytes ({:?}); cannot replace with {} bytes",
            image_path.display(),
            target_key,
            current_len,
            current_value,
            requested_len
        )),
    }
}

/// Walk the image as an ext4 filesystem, locate build.prop, and rewrite the
/// value of the spec's SPL line in place. The lookup goes through the inode
/// extent tree — ext4-aware — so the byte rewrite always lands on the file's
/// live data block(s), never on a stale copy of the same string left over in
/// an unallocated block.
fn patch_build_prop_spl_via_ext4(spec: &SplPatchSpec, image: &Path, new_spl: &str) -> Result<()> {
    let mut volume = open_ext4_volume(image)?;
    let inode = lookup_inode_at_path(&mut volume, spec.build_prop_path)?
        .ok_or_else(|| anyhow!("{} has no {}", spec.image_label, spec.build_prop_display))?;
    if !inode.is_file() {
        return Err(anyhow!(
            "{} {} is not a regular file",
            spec.image_label,
            spec.build_prop_display
        ));
    }
    // Single tree walk that returns both the file content and its extent
    // mapping; avoids walking the inode twice for the same small build.prop.
    let (content, extents) = inode.open_read_with_extents(&mut volume).map_err(|e| {
        anyhow!(
            "Failed to read {} from {}: {e}",
            spec.build_prop_display,
            spec.image_label
        )
    })?;

    let needle = spec.build_prop_needle;
    let pos = memmem::find(&content, needle).ok_or_else(|| {
        anyhow!(
            "{} {} has no {} line",
            spec.image_label,
            spec.build_prop_display,
            String::from_utf8_lossy(needle)
        )
    })?;
    let value_start = pos + needle.len();
    let mut value_end = value_start;
    while value_end < content.len() && content[value_end] != b'\n' && content[value_end] != b'\r' {
        value_end += 1;
    }
    let value_len = value_end - value_start;
    if value_len != new_spl.len() {
        return Err(anyhow!(
            "{} {} SPL value is {} bytes; cannot in-place replace with {} bytes (only same-length YYYY-MM-DD substitutions are supported)",
            spec.image_label,
            spec.build_prop_display,
            value_len,
            new_spl.len()
        ));
    }

    let block_size = volume.block_size;
    if extents.is_empty() {
        return Err(anyhow!(
            "{} {} has no extents (likely inline data not yet supported here)",
            spec.image_label,
            spec.build_prop_display
        ));
    }

    let new_bytes = new_spl.as_bytes();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image)
        .with_context(|| format!("Failed to open {} for build.prop patch", image.display()))?;

    // Walk byte-by-byte across the extents, writing each new SPL byte at its
    // mapped on-disk position. The needle is small (10 bytes) so the loop is
    // trivially cheap; doing it per-byte keeps the code correct even when the
    // value happens to straddle an extent boundary.
    for (i, byte) in new_bytes.iter().enumerate() {
        let file_offset = (value_start + i) as u64;
        let disk_offset =
            map_file_offset_to_disk(&extents, file_offset, block_size).ok_or_else(|| {
                anyhow!(
                    "Could not map {} file offset {} to a disk block (extent gap?)",
                    spec.build_prop_display,
                    file_offset
                )
            })?;
        file.seek(SeekFrom::Start(disk_offset))?;
        file.write_all(std::slice::from_ref(byte))?;
    }
    file.flush()?;
    Ok(())
}
