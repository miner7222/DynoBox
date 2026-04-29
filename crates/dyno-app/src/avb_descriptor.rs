//! Shared AVB vbmeta navigation primitives.
//!
//! `boot_spl`, `vendor_spl`, and `fix_locale` all walk a vbmeta blob in
//! the same way:
//!   * resolve the blob's disk byte range (footer-attached or standalone),
//!   * slice the descriptors region out of the blob,
//!   * iterate descriptors looking for a Property by key or a Hashtree by
//!     partition name,
//!   * for Hashtree consumers, also read the on-disk parameters needed
//!     to regenerate the dm-verity hash tree.
//!
//! Before this module each consumer carried its own copy of the same
//! ~80–120 lines, with the same constants, the same TryFromSlice dance,
//! and the same "is this byte the start of the body" arithmetic. This
//! module is the canonical home for all of it; each consumer now keeps
//! only its own domain logic (SPL date format / dex bytecode anchor /
//! ext4 walk).

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use avbtool_rs::footer::{calc_hash_level_offsets, generate_hash_tree};
use avbtool_rs::parser::{
    AVB_FOOTER_SIZE, AVB_VBMETA_IMAGE_HEADER_SIZE, AvbFooter, AvbImageType, AvbVBMetaHeader,
    detect_avb_image_type,
};

pub const DESCRIPTOR_HEADER_SIZE: usize = 16;
pub const PROPERTY_DESCRIPTOR_SIZE: usize = 32;
pub const HASHTREE_DESCRIPTOR_FIXED_SIZE: usize = 180;
pub const DESCRIPTOR_TAG_PROPERTY: u64 = 0;
pub const DESCRIPTOR_TAG_HASHTREE: u64 = 1;
pub const SHA256_DIGEST_SIZE: usize = 32;

/// A located AVB Property descriptor inside a descriptors blob.
#[derive(Debug, Clone)]
pub struct PropertyHit {
    /// Byte offset of the descriptor inside the descriptors blob (i.e.
    /// the start of its 16-byte tag/length header).
    pub descriptor_offset_in_blob: usize,
    /// Byte offset of the value bytes inside the descriptor body.
    pub value_offset_in_descriptor: usize,
    /// Length of the existing value, in bytes.
    pub value_len: usize,
    /// The existing value, decoded lossily as UTF-8.
    pub current_value: String,
}

/// A located AVB Hashtree descriptor inside a descriptors blob.
#[derive(Debug, Clone)]
pub struct HashtreeHit {
    /// Byte offset of the descriptor inside the descriptors blob.
    pub descriptor_offset_in_blob: usize,
    /// Byte offset of the root digest bytes inside the descriptor body.
    pub root_digest_offset_in_descriptor: usize,
    /// Length of the root digest, in bytes.
    pub root_digest_len: usize,
}

/// Parameters needed to regenerate a partition's dm-verity hash tree.
#[derive(Debug, Clone)]
pub struct HashtreeParams {
    pub image_size: u64,
    pub tree_offset: u64,
    pub tree_size: u64,
    pub data_block_size: u32,
    pub hash_algorithm: String,
    pub salt: Vec<u8>,
    pub root_digest: Vec<u8>,
}

/// Read the vbmeta blob from `image_path`. Returns the in-image byte
/// offset of the blob (so callers can compute absolute file offsets when
/// patching descriptor bytes) and the blob itself.
///
/// Standalone vbmeta images (`AvbImageType::Vbmeta`) return offset 0 and
/// the entire file. Footer-attached images (`AvbImageType::Footer`) read
/// the footer to learn `vbmeta_offset` and `vbmeta_size`.
pub fn read_vbmeta_blob(image_path: &Path) -> Result<(u64, Vec<u8>)> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(image_path)
        .with_context(|| format!("Failed to open {} for vbmeta read", image_path.display()))?;
    let file_size = file.metadata()?.len();
    let img_type = detect_avb_image_type(image_path)?;
    let (vbmeta_offset, vbmeta_size) = match img_type {
        AvbImageType::Vbmeta => (0u64, file_size),
        AvbImageType::Footer => {
            file.seek(SeekFrom::End(-(AVB_FOOTER_SIZE as i64)))?;
            let footer = AvbFooter::from_reader(&mut file)?;
            (footer.vbmeta_offset, footer.vbmeta_size)
        }
        AvbImageType::None => {
            return Err(anyhow!("{} is not an AVB image", image_path.display()));
        }
    };
    let mut blob = vec![0u8; vbmeta_size as usize];
    file.seek(SeekFrom::Start(vbmeta_offset))?;
    file.read_exact(&mut blob)?;
    Ok((vbmeta_offset, blob))
}

/// Slice the descriptors region out of a vbmeta blob.
pub fn descriptors_slice<'a>(vbmeta_blob: &'a [u8], header: &AvbVBMetaHeader) -> Result<&'a [u8]> {
    let aux_offset_in_blob =
        AVB_VBMETA_IMAGE_HEADER_SIZE + header.authentication_data_block_size as usize;
    let descriptors_start = aux_offset_in_blob + header.descriptors_offset as usize;
    let descriptors_end = descriptors_start + header.descriptors_size as usize;
    if descriptors_end > vbmeta_blob.len() {
        return Err(anyhow!(
            "Descriptors range {}..{} exceeds vbmeta blob length {}",
            descriptors_start,
            descriptors_end,
            vbmeta_blob.len()
        ));
    }
    Ok(&vbmeta_blob[descriptors_start..descriptors_end])
}

/// Compute the byte offset of the descriptors region inside the vbmeta
/// blob. Useful when callers need to convert a `descriptor_offset_in_blob`
/// (relative to descriptors region) into an absolute file offset.
pub fn descriptors_start_offset_in_blob(header: &AvbVBMetaHeader) -> usize {
    AVB_VBMETA_IMAGE_HEADER_SIZE
        + header.authentication_data_block_size as usize
        + header.descriptors_offset as usize
}

/// Walk the descriptors blob and return the first Property descriptor
/// matching `target_key`, or `None`.
pub fn find_property_descriptor(
    descriptors_blob: &[u8],
    target_key: &str,
) -> Result<Option<PropertyHit>> {
    let mut cursor = 0usize;
    while cursor < descriptors_blob.len() {
        let remaining = &descriptors_blob[cursor..];
        if remaining.len() < DESCRIPTOR_HEADER_SIZE {
            return Err(anyhow!(
                "Descriptor blob ends mid-header at offset {}",
                cursor
            ));
        }
        let tag = u64::from_be_bytes(remaining[0..8].try_into().unwrap());
        let num_bytes_following = u64::from_be_bytes(remaining[8..16].try_into().unwrap()) as usize;
        let total = DESCRIPTOR_HEADER_SIZE + num_bytes_following;
        if total > remaining.len() {
            return Err(anyhow!(
                "Descriptor at offset {} truncated: needs {} bytes, has {}",
                cursor,
                total,
                remaining.len()
            ));
        }
        if tag == DESCRIPTOR_TAG_PROPERTY && total >= PROPERTY_DESCRIPTOR_SIZE {
            let body = &remaining[..total];
            let key_len = u64::from_be_bytes(body[16..24].try_into().unwrap()) as usize;
            let value_len = u64::from_be_bytes(body[24..32].try_into().unwrap()) as usize;
            let key_start = PROPERTY_DESCRIPTOR_SIZE;
            let value_start = key_start + key_len + 1;
            if body.len() > value_start + value_len {
                let key_bytes = &body[key_start..key_start + key_len];
                if key_bytes == target_key.as_bytes() {
                    let current_value =
                        String::from_utf8_lossy(&body[value_start..value_start + value_len])
                            .into_owned();
                    return Ok(Some(PropertyHit {
                        descriptor_offset_in_blob: cursor,
                        value_offset_in_descriptor: value_start,
                        value_len,
                        current_value,
                    }));
                }
            }
        }
        cursor += total;
    }
    Ok(None)
}

/// Walk the descriptors blob and return the first Hashtree descriptor
/// matching `target_partition`, or `None`.
pub fn find_hashtree_descriptor(
    descriptors_blob: &[u8],
    target_partition: &str,
) -> Result<Option<HashtreeHit>> {
    let mut cursor = 0usize;
    while cursor < descriptors_blob.len() {
        let remaining = &descriptors_blob[cursor..];
        if remaining.len() < DESCRIPTOR_HEADER_SIZE {
            return Err(anyhow!(
                "Descriptor blob ends mid-header at offset {}",
                cursor
            ));
        }
        let tag = u64::from_be_bytes(remaining[0..8].try_into().unwrap());
        let num_bytes_following = u64::from_be_bytes(remaining[8..16].try_into().unwrap()) as usize;
        let total = DESCRIPTOR_HEADER_SIZE + num_bytes_following;
        if total > remaining.len() {
            return Err(anyhow!(
                "Descriptor at offset {} truncated: needs {} bytes, has {}",
                cursor,
                total,
                remaining.len()
            ));
        }
        if tag == DESCRIPTOR_TAG_HASHTREE && total >= HASHTREE_DESCRIPTOR_FIXED_SIZE {
            let body = &remaining[..total];
            let partition_name_len =
                u32::from_be_bytes(body[104..108].try_into().unwrap()) as usize;
            let salt_len = u32::from_be_bytes(body[108..112].try_into().unwrap()) as usize;
            let root_digest_len = u32::from_be_bytes(body[112..116].try_into().unwrap()) as usize;
            let payload_start = HASHTREE_DESCRIPTOR_FIXED_SIZE;
            if body.len() >= payload_start + partition_name_len + salt_len + root_digest_len {
                let partition_name = &body[payload_start..payload_start + partition_name_len];
                if partition_name == target_partition.as_bytes() {
                    let root_digest_offset_in_descriptor =
                        payload_start + partition_name_len + salt_len;
                    return Ok(Some(HashtreeHit {
                        descriptor_offset_in_blob: cursor,
                        root_digest_offset_in_descriptor,
                        root_digest_len,
                    }));
                }
            }
        }
        cursor += total;
    }
    Ok(None)
}

/// Read the Hashtree descriptor params for `target_partition` from the
/// AVB metadata of `image_path`. Returns the on-disk parameters needed
/// to regenerate the partition's dm-verity tree. `Ok(None)` when the
/// matching descriptor is absent.
pub fn read_hashtree_params(
    image_path: &Path,
    target_partition: &str,
) -> Result<Option<HashtreeParams>> {
    let (_, vbmeta_blob) = read_vbmeta_blob(image_path)?;
    if vbmeta_blob.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Ok(None);
    }
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let descriptors = descriptors_slice(&vbmeta_blob, &header)?;

    let mut cursor = 0usize;
    while cursor < descriptors.len() {
        let remaining = &descriptors[cursor..];
        if remaining.len() < DESCRIPTOR_HEADER_SIZE {
            break;
        }
        let tag = u64::from_be_bytes(remaining[0..8].try_into().unwrap());
        let num_bytes_following = u64::from_be_bytes(remaining[8..16].try_into().unwrap()) as usize;
        let total = DESCRIPTOR_HEADER_SIZE + num_bytes_following;
        if total > remaining.len() {
            break;
        }
        if tag == DESCRIPTOR_TAG_HASHTREE && total >= HASHTREE_DESCRIPTOR_FIXED_SIZE {
            let body = &remaining[..total];
            let image_size = u64::from_be_bytes(body[20..28].try_into().unwrap());
            let tree_offset = u64::from_be_bytes(body[28..36].try_into().unwrap());
            let tree_size = u64::from_be_bytes(body[36..44].try_into().unwrap());
            let data_block_size = u32::from_be_bytes(body[44..48].try_into().unwrap());
            let hash_algorithm = read_cstring(&body[72..104]);
            let partition_name_len =
                u32::from_be_bytes(body[104..108].try_into().unwrap()) as usize;
            let salt_len = u32::from_be_bytes(body[108..112].try_into().unwrap()) as usize;
            let root_digest_len = u32::from_be_bytes(body[112..116].try_into().unwrap()) as usize;
            let payload = &body[HASHTREE_DESCRIPTOR_FIXED_SIZE..];
            if payload.len() < partition_name_len + salt_len + root_digest_len {
                break;
            }
            let partition_name = std::str::from_utf8(&payload[..partition_name_len])
                .context("Hashtree partition_name is not UTF-8")?;
            if partition_name == target_partition {
                let salt = payload[partition_name_len..partition_name_len + salt_len].to_vec();
                let root_digest = payload[partition_name_len + salt_len
                    ..partition_name_len + salt_len + root_digest_len]
                    .to_vec();
                return Ok(Some(HashtreeParams {
                    image_size,
                    tree_offset,
                    tree_size,
                    data_block_size,
                    hash_algorithm,
                    salt,
                    root_digest,
                }));
            }
        }
        cursor += total;
    }
    Ok(None)
}

/// Regenerate the dm-verity hash tree on `image_path` using `params` and
/// write it back at `params.tree_offset`. Returns the new root digest.
pub fn regenerate_hashtree(image_path: &Path, params: &HashtreeParams) -> Result<Vec<u8>> {
    let block_size = params.data_block_size as u64;
    if block_size == 0 {
        return Err(anyhow!("Hashtree descriptor reports zero data_block_size"));
    }
    let digest_size = match params.hash_algorithm.as_str() {
        "sha256" => 32u64,
        other => {
            return Err(anyhow!(
                "Unsupported hash algorithm {} for verity regeneration",
                other
            ));
        }
    };
    let digest_padding = next_pow2(digest_size) - digest_size;
    let (hash_level_offsets, expected_tree_size) =
        calc_hash_level_offsets(params.image_size, block_size, digest_size + digest_padding);
    if expected_tree_size != params.tree_size {
        return Err(anyhow!(
            "Computed hash tree size {} does not match descriptor's tree_size {}",
            expected_tree_size,
            params.tree_size
        ));
    }

    let (root_digest, hash_tree_blob) = generate_hash_tree(
        image_path,
        params.image_size,
        params.data_block_size,
        &params.hash_algorithm,
        &params.salt,
        digest_padding as usize,
        &hash_level_offsets,
        params.tree_size,
    )
    .map_err(|e| {
        anyhow!(
            "generate_hash_tree failed for {}: {e}",
            image_path.display()
        )
    })?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .with_context(|| {
            format!(
                "Failed to open {} for hash tree write",
                image_path.display()
            )
        })?;
    file.seek(SeekFrom::Start(params.tree_offset))?;
    file.write_all(&hash_tree_blob)?;
    file.flush()?;
    Ok(root_digest)
}

/// Patch the value of an AVB Property descriptor in place. Same-length
/// only — the descriptor body is not resized, so the rest of the vbmeta
/// blob layout stays valid.
///
/// Returns:
///   * `Ok(PatchPropertyOutcome::Patched { old_value })` on success,
///   * `Ok(PatchPropertyOutcome::NotFound)` if the property is absent,
///   * `Ok(PatchPropertyOutcome::LengthMismatch { … })` if the existing
///     value length differs from `new_value.len()` — caller can format
///     a per-feature error message.
pub fn patch_property_value(
    image_path: &Path,
    target_key: &str,
    new_value: &[u8],
) -> Result<PatchPropertyOutcome> {
    let (vbmeta_offset, vbmeta_blob) = read_vbmeta_blob(image_path)?;
    if vbmeta_blob.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Ok(PatchPropertyOutcome::NotFound);
    }
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let descriptors_start = descriptors_start_offset_in_blob(&header);
    let descriptors = descriptors_slice(&vbmeta_blob, &header)?;
    let Some(hit) = find_property_descriptor(descriptors, target_key)? else {
        return Ok(PatchPropertyOutcome::NotFound);
    };
    if hit.value_len != new_value.len() {
        return Ok(PatchPropertyOutcome::LengthMismatch {
            current_value: hit.current_value,
            current_len: hit.value_len,
            requested_len: new_value.len(),
        });
    }
    let value_file_offset = vbmeta_offset
        + descriptors_start as u64
        + hit.descriptor_offset_in_blob as u64
        + hit.value_offset_in_descriptor as u64;
    write_at(image_path, value_file_offset, new_value)?;
    Ok(PatchPropertyOutcome::Patched {
        old_value: hit.current_value,
    })
}

#[derive(Debug, Clone)]
pub enum PatchPropertyOutcome {
    Patched {
        old_value: String,
    },
    NotFound,
    LengthMismatch {
        current_value: String,
        current_len: usize,
        requested_len: usize,
    },
}

/// Patch the `root_digest` of the Hashtree descriptor matching
/// `target_partition`. Length-stable byte overwrite. Errors when the
/// descriptor is absent or the existing digest length differs from
/// `new_digest.len()`.
pub fn patch_hashtree_root_digest(
    image_path: &Path,
    target_partition: &str,
    new_digest: &[u8],
) -> Result<()> {
    let (vbmeta_offset, vbmeta_blob) = read_vbmeta_blob(image_path)?;
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let descriptors_start = descriptors_start_offset_in_blob(&header);
    let descriptors = descriptors_slice(&vbmeta_blob, &header)?;
    let hit = find_hashtree_descriptor(descriptors, target_partition)?.ok_or_else(|| {
        anyhow!(
            "{} has no Hashtree descriptor for `{}`",
            image_path.display(),
            target_partition
        )
    })?;
    if hit.root_digest_len != new_digest.len() {
        return Err(anyhow!(
            "{} Hashtree root_digest is {} bytes; cannot replace with {} bytes",
            image_path.display(),
            hit.root_digest_len,
            new_digest.len()
        ));
    }
    let digest_file_offset = vbmeta_offset
        + descriptors_start as u64
        + hit.descriptor_offset_in_blob as u64
        + hit.root_digest_offset_in_descriptor as u64;
    write_at(image_path, digest_file_offset, new_digest)?;
    Ok(())
}

fn write_at(image_path: &Path, file_offset: u64, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .with_context(|| {
            format!(
                "Failed to open {} for descriptor byte patch",
                image_path.display()
            )
        })?;
    file.seek(SeekFrom::Start(file_offset))?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

pub(crate) fn read_cstring(slice: &[u8]) -> String {
    let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

pub(crate) fn next_pow2(value: u64) -> u64 {
    let mut p = 1u64;
    while p < value {
        p <<= 1;
    }
    p
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_property_descriptor(key: &str, value: &str) -> Vec<u8> {
        let key_bytes = key.as_bytes();
        let value_bytes = value.as_bytes();
        let body_size = PROPERTY_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE
            + key_bytes.len()
            + 1
            + value_bytes.len()
            + 1;
        let padded = body_size.div_ceil(8) * 8;
        let mut out = Vec::with_capacity(DESCRIPTOR_HEADER_SIZE + padded);
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&(padded as u64).to_be_bytes());
        out.extend_from_slice(&(key_bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(&(value_bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(key_bytes);
        out.push(0);
        out.extend_from_slice(value_bytes);
        out.push(0);
        out.resize(DESCRIPTOR_HEADER_SIZE + padded, 0);
        out
    }

    fn build_hashtree_descriptor(partition: &str, salt: &[u8], digest: &[u8]) -> Vec<u8> {
        let body_size = HASHTREE_DESCRIPTOR_FIXED_SIZE - DESCRIPTOR_HEADER_SIZE
            + partition.len()
            + salt.len()
            + digest.len();
        let padded = body_size.div_ceil(8) * 8;
        let mut out = vec![0u8; DESCRIPTOR_HEADER_SIZE + padded];
        out[0..8].copy_from_slice(&1u64.to_be_bytes());
        out[8..16].copy_from_slice(&(padded as u64).to_be_bytes());
        out[16..20].copy_from_slice(&1u32.to_be_bytes());
        let algo = b"sha256";
        out[72..72 + algo.len()].copy_from_slice(algo);
        out[104..108].copy_from_slice(&(partition.len() as u32).to_be_bytes());
        out[108..112].copy_from_slice(&(salt.len() as u32).to_be_bytes());
        out[112..116].copy_from_slice(&(digest.len() as u32).to_be_bytes());
        let mut payload_off = HASHTREE_DESCRIPTOR_FIXED_SIZE;
        out[payload_off..payload_off + partition.len()].copy_from_slice(partition.as_bytes());
        payload_off += partition.len();
        out[payload_off..payload_off + salt.len()].copy_from_slice(salt);
        payload_off += salt.len();
        out[payload_off..payload_off + digest.len()].copy_from_slice(digest);
        out
    }

    #[test]
    fn find_descriptors_in_synthetic_blob() {
        let mut blob = Vec::new();
        blob.extend(build_property_descriptor(
            "com.android.build.boot.os_version",
            "15",
        ));
        blob.extend(build_property_descriptor(
            "com.android.build.boot.security_patch",
            "2025-02-05",
        ));
        let salt = vec![0u8; 32];
        let digest = vec![0xAAu8; 32];
        blob.extend(build_hashtree_descriptor("vendor", &salt, &digest));

        let prop = find_property_descriptor(&blob, "com.android.build.boot.security_patch")
            .unwrap()
            .unwrap();
        assert_eq!(prop.current_value, "2025-02-05");
        assert_eq!(prop.value_len, 10);
        let abs_value = prop.descriptor_offset_in_blob + prop.value_offset_in_descriptor;
        assert_eq!(&blob[abs_value..abs_value + 10], b"2025-02-05");

        let hit = find_hashtree_descriptor(&blob, "vendor").unwrap().unwrap();
        let abs_digest = hit.descriptor_offset_in_blob + hit.root_digest_offset_in_descriptor;
        assert_eq!(&blob[abs_digest..abs_digest + 32], &digest[..]);
        assert_eq!(hit.root_digest_len, 32);
    }

    #[test]
    fn find_property_descriptor_returns_none_when_missing() {
        let blob = build_property_descriptor("com.android.build.boot.os_version", "15");
        assert!(
            find_property_descriptor(&blob, "com.android.build.boot.security_patch")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn next_pow2_basic() {
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(32), 32);
        assert_eq!(next_pow2(33), 64);
    }

    #[test]
    fn read_cstring_stops_at_nul() {
        assert_eq!(read_cstring(b"sha256\0\0\0"), "sha256");
        assert_eq!(read_cstring(b"abc"), "abc");
    }

    #[test]
    fn hex_encode_lowercase() {
        assert_eq!(hex_encode(&[0xDEu8, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }
}
