//! Patch vendor.img security_patch + propagate to vbmeta.img.
//!
//! Walks the ext4 filesystem inside `vendor.img` to locate `/build.prop`,
//! resolves the disk byte range that backs the
//! `ro.vendor.build.security_patch=` line through the inode's extent
//! tree, and overwrites the 10-byte date in place. Going through the
//! ext4 reader (rather than a blind `memchr` scan over the partition
//! image) is what makes the rewrite hit the live data block instead of
//! whichever stale fragment in unallocated space happens to share the
//! same string.
//!
//! After the data-area edit:
//!   1. Re-emit the dm-verity hash tree from the modified data and write
//!      it back at `tree_offset` in vendor.img.
//!   2. Patch the AVB Hashtree descriptor's `root_digest` and the AVB
//!      Property descriptor's `com.android.build.vendor.security_patch`
//!      value in vendor.img's footer. vendor.img is `algorithm = NONE`,
//!      so the descriptor body is rewritten in place and stays
//!      length-stable (32-byte digest, 10-byte date) — no signature to
//!      invalidate.
//!   3. Patch the same fields in vbmeta.img (which carries vendor's
//!      Hashtree descriptor and the matching property). vbmeta.img is
//!      signed, so the regular resign loop re-signs it after this
//!      module returns; the in-place edit pre-loads the new bytes the
//!      fresh signature then covers.
//!
//! FEC blocks are intentionally left untouched: dm-verity validates
//! against the new `root_digest` only, and FEC is consulted as a recovery
//! code for damaged blocks. A stale FEC region does not break boot.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::avb_descriptor::{
    PatchPropertyOutcome, SHA256_DIGEST_SIZE, find_property_descriptor, hex_encode,
    patch_hashtree_root_digest, patch_property_value, read_hashtree_params, read_vbmeta_blob,
    regenerate_hashtree,
};
use crate::ext4_helpers::{lookup_inode_at_path, map_file_offset_to_disk, open_ext4_volume};
use anyhow::{Context, Result, anyhow};
use avbtool_rs::parser::{AVB_VBMETA_IMAGE_HEADER_SIZE, AvbVBMetaHeader};
use memchr::memmem;

pub const VENDOR_SPL_PROPERTY: &str = "com.android.build.vendor.security_patch";
const VENDOR_PARTITION_NAME: &str = "vendor";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorSplOutcome {
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

/// Validate `spl` is a strict `YYYY-MM-DD` ASCII string. The in-place patch
/// relies on the new value matching the existing length.
pub fn validate_spl_format(spl: &str) -> Result<()> {
    let bytes = spl.as_bytes();
    let well_formed = bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit);
    if !well_formed {
        return Err(anyhow!(
            "--vendor-spl must be in YYYY-MM-DD format (got {:?})",
            spl
        ));
    }
    Ok(())
}

/// Apply --vendor-spl to vendor.img and propagate the change to vbmeta.img.
/// Caller is responsible for re-signing vbmeta.img after this returns.
pub fn apply_vendor_spl(
    vendor_image: &Path,
    vbmeta_image: &Path,
    new_spl: &str,
) -> Result<VendorSplOutcome> {
    validate_spl_format(new_spl)?;

    // 1. Read current vendor security_patch property from vendor.img footer.
    let current_avb = match read_vendor_avb_property(vendor_image)? {
        Some(value) => value,
        None => return Ok(VendorSplOutcome::NotFound),
    };
    if new_spl <= current_avb.as_str() {
        return Ok(VendorSplOutcome::SkippedNotNewer {
            old: current_avb,
            requested: new_spl.to_string(),
        });
    }

    // 2. Read hashtree descriptor params (need image_size for the rebuild
    //    and the salt/algorithm for verity regeneration after).
    let hashtree = read_hashtree_params(vendor_image, VENDOR_PARTITION_NAME)?
        .ok_or_else(|| anyhow!("vendor.img has no Hashtree descriptor for partition `vendor`"))?;
    let old_root_digest = hashtree.root_digest.clone();
    if hashtree.root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "vendor.img Hashtree descriptor uses an unexpected root_digest length {} (expected {})",
            hashtree.root_digest.len(),
            SHA256_DIGEST_SIZE
        ));
    }

    // 3. Walk vendor.img as an ext4 filesystem, resolve `/build.prop`'s
    //    disk-byte range via the inode extent tree, and overwrite the
    //    SPL value in place. A blind partition-wide `memchr` scan would
    //    happily land on a stale copy of the same string in unallocated
    //    space and leave the live build.prop unchanged.
    patch_build_prop_spl_via_ext4(vendor_image, new_spl)?;

    // 4. Regenerate dm-verity hash tree from the modified data and write it
    //    back at `tree_offset`. avbtool-rs::generate_hash_tree returns the
    //    root digest plus the full level-packed tree blob.
    let new_root_digest = regenerate_hashtree(vendor_image, &hashtree)?;
    if new_root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "Regenerated hash tree returned unexpected root_digest length {}",
            new_root_digest.len()
        ));
    }

    // 5. Patch vendor.img footer descriptors (NONE algorithm: no signature).
    patch_property_or_explain(vendor_image, VENDOR_SPL_PROPERTY, new_spl)?;
    patch_hashtree_root_digest(vendor_image, VENDOR_PARTITION_NAME, &new_root_digest)?;

    // 6. Patch vbmeta.img descriptors. The signed blob is left with a stale
    //    signature that the resign stage will refresh.
    patch_property_or_explain(vbmeta_image, VENDOR_SPL_PROPERTY, new_spl)?;
    patch_hashtree_root_digest(vbmeta_image, VENDOR_PARTITION_NAME, &new_root_digest)?;

    Ok(VendorSplOutcome::Patched {
        old: current_avb,
        new: new_spl.to_string(),
        old_root_digest: hex_encode(&old_root_digest),
        new_root_digest: hex_encode(&new_root_digest),
    })
}

/// Wrap `avb_descriptor::patch_property_value` with vendor-spl-flavoured
/// error messages so callers don't have to repeat the dispatch.
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

/// Walk vendor.img as an ext4 filesystem, locate `/build.prop`, and
/// rewrite the value of the `ro.vendor.build.security_patch` line in
/// place. The lookup goes through the inode extent tree — ext4-aware —
/// so the byte rewrite always lands on the file's live data block(s),
/// never on a stale copy of the same string left over in an
/// unallocated block.
fn patch_build_prop_spl_via_ext4(vendor_image: &Path, new_spl: &str) -> Result<()> {
    let mut volume = open_ext4_volume(vendor_image)?;
    let inode = lookup_inode_at_path(&mut volume, &["build.prop"])?
        .ok_or_else(|| anyhow!("vendor.img has no /build.prop"))?;
    if !inode.is_file() {
        return Err(anyhow!("vendor.img /build.prop is not a regular file"));
    }
    let content = inode
        .open_read(&mut volume)
        .map_err(|e| anyhow!("Failed to read /build.prop from vendor.img: {e}"))?;

    let needle = b"ro.vendor.build.security_patch=";
    let pos = memmem::find(&content, needle)
        .ok_or_else(|| anyhow!("vendor /build.prop has no ro.vendor.build.security_patch= line"))?;
    let value_start = pos + needle.len();
    let mut value_end = value_start;
    while value_end < content.len() && content[value_end] != b'\n' && content[value_end] != b'\r' {
        value_end += 1;
    }
    let value_len = value_end - value_start;
    if value_len != new_spl.len() {
        return Err(anyhow!(
            "vendor /build.prop SPL value is {} bytes; cannot in-place replace with {} bytes (only same-length YYYY-MM-DD substitutions are supported)",
            value_len,
            new_spl.len()
        ));
    }

    let block_size = volume.block_size;
    let extents = inode
        .extent_mapping(&mut volume)
        .map_err(|e| anyhow!("Failed to walk /build.prop extent tree: {e}"))?;
    if extents.is_empty() {
        return Err(anyhow!(
            "vendor /build.prop has no extents (likely inline data not yet supported here)"
        ));
    }

    let new_bytes = new_spl.as_bytes();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(vendor_image)
        .with_context(|| {
            format!(
                "Failed to open {} for build.prop patch",
                vendor_image.display()
            )
        })?;

    // Walk byte-by-byte across the extents, writing each new SPL byte at
    // its mapped on-disk position. The needle is small (10 bytes) so the
    // loop is trivially cheap; doing it per-byte keeps the code correct
    // even when the value happens to straddle an extent boundary.
    for (i, byte) in new_bytes.iter().enumerate() {
        let file_offset = (value_start + i) as u64;
        let disk_offset =
            map_file_offset_to_disk(&extents, file_offset, block_size).ok_or_else(|| {
                anyhow!(
                    "Could not map /build.prop file offset {} to a disk block (extent gap?)",
                    file_offset
                )
            })?;
        file.seek(SeekFrom::Start(disk_offset))?;
        file.write_all(std::slice::from_ref(byte))?;
    }
    file.flush()?;
    Ok(())
}

/// Read the current `com.android.build.vendor.security_patch` from
/// `vendor.img`'s footer, or `Ok(None)` if absent.
pub fn read_vendor_avb_property(vendor_image: &Path) -> Result<Option<String>> {
    let (_, vbmeta_blob) = read_vbmeta_blob(vendor_image)?;
    if vbmeta_blob.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Ok(None);
    }
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let descriptors = crate::avb_descriptor::descriptors_slice(&vbmeta_blob, &header)?;
    Ok(find_property_descriptor(descriptors, VENDOR_SPL_PROPERTY)?.map(|hit| hit.current_value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_spl_format_round_trip() {
        assert!(validate_spl_format("2026-04-05").is_ok());
        assert!(validate_spl_format("2026-4-05").is_err());
        assert!(validate_spl_format("2026/04/05").is_err());
        assert!(validate_spl_format("").is_err());
    }
}
