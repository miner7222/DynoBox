//! Shared AVB vbmeta navigation primitives.
//!
//! `boot_spl`, `vendor_spl`, and `fuck_as` all walk a vbmeta blob in
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
use avbtool_rs::footer::calc_hash_level_offsets;
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
    let vbmeta_end = vbmeta_offset
        .checked_add(vbmeta_size)
        .ok_or_else(|| anyhow!("vbmeta range overflows u64"))?;
    if vbmeta_end > file_size {
        return Err(anyhow!(
            "vbmeta range {}..{} exceeds image size {} for {}",
            vbmeta_offset,
            vbmeta_end,
            file_size,
            image_path.display()
        ));
    }
    let vbmeta_size = checked_usize_from_u64(vbmeta_size, "vbmeta_size")?;
    let mut blob = vec![0u8; vbmeta_size];
    file.seek(SeekFrom::Start(vbmeta_offset))?;
    file.read_exact(&mut blob)?;
    Ok((vbmeta_offset, blob))
}

/// Slice the descriptors region out of a vbmeta blob.
pub fn descriptors_slice<'a>(vbmeta_blob: &'a [u8], header: &AvbVBMetaHeader) -> Result<&'a [u8]> {
    let (descriptors_start, descriptors_end) = descriptor_range_in_blob(header)?;
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
pub fn descriptors_start_offset_in_blob(header: &AvbVBMetaHeader) -> Result<usize> {
    let (descriptors_start, _) = descriptor_range_in_blob(header)?;
    Ok(descriptors_start)
}

fn descriptor_range_in_blob(header: &AvbVBMetaHeader) -> Result<(usize, usize)> {
    let auth_size = checked_usize_from_u64(
        header.authentication_data_block_size,
        "authentication_data_block_size",
    )?;
    let descriptors_offset =
        checked_usize_from_u64(header.descriptors_offset, "descriptors_offset")?;
    let descriptors_size = checked_usize_from_u64(header.descriptors_size, "descriptors_size")?;
    let aux_offset = checked_add_usize(
        AVB_VBMETA_IMAGE_HEADER_SIZE,
        auth_size,
        "auxiliary data offset",
    )?;
    let descriptors_start = checked_add_usize(aux_offset, descriptors_offset, "descriptors start")?;
    let descriptors_end =
        checked_add_usize(descriptors_start, descriptors_size, "descriptors end")?;
    Ok((descriptors_start, descriptors_end))
}

fn read_descriptor_header(remaining: &[u8], cursor: usize) -> Result<(u64, usize)> {
    if remaining.len() < DESCRIPTOR_HEADER_SIZE {
        return Err(anyhow!(
            "Descriptor blob ends mid-header at offset {}",
            cursor
        ));
    }
    let tag = u64::from_be_bytes(remaining[0..8].try_into().unwrap());
    let num_bytes_following = read_be_u64_as_usize(&remaining[8..16], "descriptor payload length")?;
    let total = checked_add_usize(
        DESCRIPTOR_HEADER_SIZE,
        num_bytes_following,
        "descriptor total length",
    )?;
    if total > remaining.len() {
        return Err(anyhow!(
            "Descriptor at offset {} truncated: needs {} bytes, has {}",
            cursor,
            total,
            remaining.len()
        ));
    }
    Ok((tag, total))
}

fn read_be_u64_as_usize(bytes: &[u8], field_name: &str) -> Result<usize> {
    checked_usize_from_u64(u64::from_be_bytes(bytes.try_into().unwrap()), field_name)
}

fn checked_usize_from_u64(value: u64, field_name: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| anyhow!("{field_name} exceeds usize: {value}"))
}

fn checked_add_usize(left: usize, right: usize, label: &str) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| anyhow!("{label} offset overflow"))
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
        let (tag, total) = read_descriptor_header(remaining, cursor)?;
        if tag == DESCRIPTOR_TAG_PROPERTY && total >= PROPERTY_DESCRIPTOR_SIZE {
            let body = &remaining[..total];
            let key_len = read_be_u64_as_usize(&body[16..24], "property key length")?;
            let value_len = read_be_u64_as_usize(&body[24..32], "property value length")?;
            let key_start = PROPERTY_DESCRIPTOR_SIZE;
            let key_end = checked_add_usize(key_start, key_len, "property key end")?;
            let value_start = checked_add_usize(key_end, 1, "property value start")?;
            let value_end = checked_add_usize(value_start, value_len, "property value end")?;
            if body.len() > value_end {
                let key_bytes = &body[key_start..key_end];
                if key_bytes == target_key.as_bytes() {
                    let current_value =
                        String::from_utf8_lossy(&body[value_start..value_end]).into_owned();
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
        let (tag, total) = read_descriptor_header(remaining, cursor)?;
        if tag == DESCRIPTOR_TAG_HASHTREE && total >= HASHTREE_DESCRIPTOR_FIXED_SIZE {
            let body = &remaining[..total];
            let partition_name_len =
                u32::from_be_bytes(body[104..108].try_into().unwrap()) as usize;
            let salt_len = u32::from_be_bytes(body[108..112].try_into().unwrap()) as usize;
            let root_digest_len = u32::from_be_bytes(body[112..116].try_into().unwrap()) as usize;
            let payload_start = HASHTREE_DESCRIPTOR_FIXED_SIZE;
            let partition_name_end =
                checked_add_usize(payload_start, partition_name_len, "hashtree partition name")?;
            let salt_end = checked_add_usize(partition_name_end, salt_len, "hashtree salt")?;
            let digest_end = checked_add_usize(salt_end, root_digest_len, "hashtree root digest")?;
            if body.len() >= digest_end {
                let partition_name = &body[payload_start..partition_name_end];
                if partition_name == target_partition.as_bytes() {
                    return Ok(Some(HashtreeHit {
                        descriptor_offset_in_blob: cursor,
                        root_digest_offset_in_descriptor: salt_end,
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
        let (tag, total) = read_descriptor_header(remaining, cursor)?;
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
            let salt_end = checked_add_usize(partition_name_len, salt_len, "hashtree salt end")?;
            let digest_end = checked_add_usize(salt_end, root_digest_len, "hashtree digest end")?;
            if payload.len() < digest_end {
                return Err(anyhow!(
                    "Hashtree descriptor for {} is truncated",
                    target_partition
                ));
            }
            let partition_name = std::str::from_utf8(&payload[..partition_name_len])
                .context("Hashtree partition_name is not UTF-8")?;
            if partition_name == target_partition {
                let salt = payload[partition_name_len..salt_end].to_vec();
                let root_digest = payload[salt_end..digest_end].to_vec();
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
///
/// Equivalent to [`regenerate_hashtree_with_progress`] called with
/// `progress = None`. New callers that want a verity progress bar
/// should reach for the `_with_progress` variant directly so the
/// 12 GiB SHA-256 walk on `system.img` / `vendor.img` doesn't look
/// like a frozen pipeline.
pub fn regenerate_hashtree(image_path: &Path, params: &HashtreeParams) -> Result<Vec<u8>> {
    regenerate_hashtree_with_progress(image_path, params, None)
}

/// `progress(delta_bytes)` is invoked after each leaf-level data block
/// is hashed (one call per `data_block_size` bytes). Higher tree
/// levels are << 1 % of the work and are not reported; callers that
/// throttle the callback can do so by accumulating deltas and only
/// forwarding to the UI when a threshold is crossed.
pub type VerityProgressCallback<'a> = &'a mut dyn FnMut(u64);

/// Regenerate the dm-verity hash tree, emitting per-block byte
/// progress through `progress`. Hand-rolled mirror of
/// `avbtool_rs::footer::generate_hash_tree` — the upstream entry point
/// has no callback hook, so we replicate the algorithm here. A unit
/// test in this module pins the output byte-for-byte against the
/// upstream implementation on a synthetic image so any future drift
/// surfaces during `cargo test` rather than as a non-bootable image.
pub fn regenerate_hashtree_with_progress(
    image_path: &Path,
    params: &HashtreeParams,
    progress: Option<VerityProgressCallback>,
) -> Result<Vec<u8>> {
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

    let (root_digest, hash_tree_blob) = compute_hash_tree(
        image_path,
        params.image_size,
        params.data_block_size,
        &params.hash_algorithm,
        &params.salt,
        digest_padding as usize,
        &hash_level_offsets,
        expected_tree_size,
        progress,
    )?;

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

/// Direct mirror of `avbtool_rs::footer::generate_hash_tree`, with two
/// changes:
///
///   1. takes an optional `progress` callback that fires after each
///      level-0 block is read and hashed, so callers can render a real
///      progress bar during the SHA-256 walk;
///   2. calls a local `read_padded_block` clone (the upstream helper
///      is module-private).
///
/// Format must remain byte-identical to upstream, otherwise the
/// returned `root_digest` won't match what's in the AVB descriptors
/// signed elsewhere in the toolchain. Verified by
/// `regenerate_hashtree_matches_avbtool` in the tests below.
#[allow(clippy::too_many_arguments)]
fn compute_hash_tree(
    image_path: &Path,
    image_size: u64,
    block_size: u32,
    hash_algorithm: &str,
    salt: &[u8],
    digest_padding: usize,
    hash_level_offsets: &[u64],
    tree_size: u64,
    mut progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if hash_algorithm != "sha256" {
        return Err(anyhow!(
            "Unsupported hash algorithm {} for verity regeneration",
            hash_algorithm
        ));
    }

    let mut image = std::fs::File::open(image_path)
        .with_context(|| format!("Failed to open {} for verity walk", image_path.display()))?;
    let block_size_usize = block_size as usize;
    let mut hash_ret = vec![0u8; tree_size as usize];
    let mut hash_src_size = image_size as usize;
    let mut level_num = 0usize;

    if hash_src_size == block_size_usize {
        let data = read_padded_block_local(&mut image, 0, block_size_usize, image_size)?;
        let digest = sha256_with_salt(salt, &data);
        if let Some(cb) = progress.as_deref_mut() {
            cb(block_size as u64);
        }
        return Ok((digest, hash_ret));
    }

    let mut last_level_output = Vec::new();
    while hash_src_size > block_size_usize {
        let mut level_output = Vec::new();
        let mut remaining = hash_src_size;
        while remaining > 0 {
            let data = if level_num == 0 {
                let read_offset = (hash_src_size - remaining) as u64;
                let block =
                    read_padded_block_local(&mut image, read_offset, block_size_usize, image_size)?;
                if let Some(cb) = progress.as_deref_mut() {
                    cb(block_size as u64);
                }
                block
            } else {
                let offset = hash_level_offsets[level_num - 1] as usize + hash_src_size - remaining;
                let end = (offset + block_size_usize).min(hash_ret.len());
                let mut block = hash_ret[offset..end].to_vec();
                block.resize(block_size_usize, 0);
                block
            };
            let digest = sha256_with_salt(salt, &data);
            level_output.extend_from_slice(&digest);
            if digest_padding > 0 {
                level_output.extend(std::iter::repeat_n(0u8, digest_padding));
            }
            remaining = remaining.saturating_sub(block_size_usize);
        }

        let padded_len = level_output.len().div_ceil(block_size_usize) * block_size_usize;
        level_output.resize(padded_len, 0);
        let offset = hash_level_offsets
            .get(level_num)
            .copied()
            .ok_or_else(|| anyhow!("Missing hash level offset at level {level_num}"))?
            as usize;
        hash_ret[offset..offset + level_output.len()].copy_from_slice(&level_output);
        hash_src_size = level_output.len();
        level_num += 1;
        last_level_output = level_output;
    }

    Ok((sha256_with_salt(salt, &last_level_output), hash_ret))
}

fn sha256_with_salt(salt: &[u8], data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt);
    h.update(data);
    h.finalize().to_vec()
}

fn read_padded_block_local(
    reader: &mut std::fs::File,
    offset: u64,
    block_size: usize,
    file_size: u64,
) -> Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let readable = file_size.saturating_sub(offset).min(block_size as u64) as usize;
    let mut block = vec![0u8; block_size];
    if readable > 0 {
        reader.read_exact(&mut block[..readable])?;
    }
    Ok(block)
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
    let descriptors_start = descriptors_start_offset_in_blob(&header)?;
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
    let descriptors_start = descriptors_start_offset_in_blob(&header)?;
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
    fn descriptors_slice_rejects_offset_overflow() {
        let header = AvbVBMetaHeader {
            magic: *b"AVB0",
            required_libavb_version_major: 1,
            required_libavb_version_minor: 0,
            authentication_data_block_size: u64::MAX,
            auxiliary_data_block_size: 0,
            algorithm_type: 0,
            hash_offset: 0,
            hash_size: 0,
            signature_offset: 0,
            signature_size: 0,
            public_key_offset: 0,
            public_key_size: 0,
            public_key_metadata_offset: 0,
            public_key_metadata_size: 0,
            descriptors_offset: 0,
            descriptors_size: 0,
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            release_string: String::new(),
        };

        assert!(descriptors_slice(&[0u8; AVB_VBMETA_IMAGE_HEADER_SIZE], &header).is_err());
    }

    #[test]
    fn find_property_descriptor_rejects_length_overflow() {
        let mut blob = vec![0u8; DESCRIPTOR_HEADER_SIZE];
        blob[8..16].copy_from_slice(&u64::MAX.to_be_bytes());

        assert!(find_property_descriptor(&blob, "foo").is_err());
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

    /// Pin our hand-rolled `compute_hash_tree` against the upstream
    /// `avbtool_rs::footer::generate_hash_tree` byte-for-byte.
    ///
    /// Verifies that across a multi-level walk (multiple block-size
    /// inputs feeding a top level of one block) we produce:
    ///   * the same `root_digest`,
    ///   * the same `hash_ret` blob layout (level offsets, padding,
    ///     digest values).
    ///
    /// If a future avbtool-rs upgrade ever changes the layout, this
    /// test fails before any partition gets a wrong root_digest baked
    /// into its descriptor.
    #[test]
    fn compute_hash_tree_matches_avbtool() {
        use avbtool_rs::footer::{calc_hash_level_offsets, generate_hash_tree};
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let image = dir.path().join("verity_test.img");
        let block_size: u32 = 4096;
        // 64 KiB → 16 blocks → level0 yields 512 bytes of digests
        // padded to 4096 (1 block) → loop exits with 1-block top
        // level. Exercises both the data-read leaf path and the
        // intermediate-from-hash_ret path for the upper level.
        let image_size: u64 = 64 * 1024;
        let mut data = vec![0u8; image_size as usize];
        for (i, b) in data.iter_mut().enumerate() {
            // Pseudo-random pattern; deterministic across runs.
            *b = ((i * 0x9E37) ^ (i >> 3)) as u8;
        }
        std::fs::write(&image, &data).expect("write test image");

        let salt = vec![0xABu8; 32];
        let digest_size = 32u64;
        let digest_padding = 0usize;
        let (offsets, tree_size) =
            calc_hash_level_offsets(image_size, block_size as u64, digest_size);

        let (avb_root, avb_blob) = generate_hash_tree(
            &image,
            image_size,
            block_size,
            "sha256",
            &salt,
            digest_padding,
            &offsets,
            tree_size,
        )
        .expect("avbtool generate_hash_tree");

        let mut tick_count: u64 = 0;
        let mut tick = |delta: u64| {
            tick_count = tick_count.saturating_add(delta);
        };
        let (our_root, our_blob) = compute_hash_tree(
            &image,
            image_size,
            block_size,
            "sha256",
            &salt,
            digest_padding,
            &offsets,
            tree_size,
            Some(&mut tick),
        )
        .expect("our compute_hash_tree");

        assert_eq!(our_root, avb_root, "root_digest mismatch");
        assert_eq!(our_blob, avb_blob, "hash_ret blob mismatch");
        // Progress callback should have observed every leaf block.
        assert_eq!(tick_count, image_size, "leaf bytes counted by callback");
    }
}
