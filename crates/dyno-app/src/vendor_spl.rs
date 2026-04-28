//! Patch vendor.img security_patch + propagate to vbmeta.img.
//!
//! Locates `ro.vendor.build.security_patch=` inside vendor.img's data area
//! by streaming byte scan and overwrites the 10-byte date that follows.
//! Because vendor.img is dm-verity protected, the data-area edit is followed
//! by:
//!   1. Re-emitting the dm-verity hash tree from the modified data and
//!      writing it back at `tree_offset` in vendor.img.
//!   2. Patching the AVB Hashtree descriptor's `root_digest` and the AVB
//!      Property descriptor's `com.android.build.vendor.security_patch` value
//!      in vendor.img's footer. vendor.img is `algorithm = NONE`, so there is
//!      no signature to invalidate; the descriptor body is rewritten in
//!      place and stays length-stable (32-byte digest, 10-byte date).
//!   3. Patching the same fields in vbmeta.img (which carries vendor's
//!      Hashtree descriptor and the matching property). vbmeta.img is signed,
//!      so the regular resign loop is expected to re-sign it after this
//!      module returns; the in-place edit pre-loads the new bytes that the
//!      signature will then cover.
//!
//! FEC blocks are intentionally left untouched: dm-verity validates against
//! the new `root_digest` only, and FEC is consulted only as a recovery code
//! for damaged blocks. A stale FEC region does not break boot.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use avbtool_rs::footer::{calc_hash_level_offsets, generate_hash_tree};
use avbtool_rs::parser::{
    AVB_FOOTER_SIZE, AVB_VBMETA_IMAGE_HEADER_SIZE, AvbFooter, AvbImageType, AvbVBMetaHeader,
    detect_avb_image_type,
};
use memchr::memmem;

pub const VENDOR_SPL_PROPERTY: &str = "com.android.build.vendor.security_patch";

const BUILD_PROP_KEY: &[u8] = b"ro.vendor.build.security_patch=";

const DESCRIPTOR_HEADER_SIZE: usize = 16;
const PROPERTY_DESCRIPTOR_SIZE: usize = 32;
const HASHTREE_DESCRIPTOR_FIXED_SIZE: usize = 180;
const DESCRIPTOR_TAG_PROPERTY: u64 = 0;
const DESCRIPTOR_TAG_HASHTREE: u64 = 1;

const SHA256_DIGEST_SIZE: usize = 32;
const SCAN_CHUNK: usize = 16 * 1024 * 1024;

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

#[derive(Debug, Clone)]
struct HashtreeParams {
    image_size: u64,
    tree_offset: u64,
    tree_size: u64,
    data_block_size: u32,
    hash_algorithm: String,
    salt: Vec<u8>,
    root_digest: Vec<u8>,
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

    // 2. Locate ro.vendor.build.security_patch= inside vendor.img data area.
    let Some((build_prop_value_offset, current_build_prop)) =
        find_build_prop_security_patch(vendor_image)?
    else {
        return Err(anyhow!(
            "vendor.img has no `ro.vendor.build.security_patch=` entry in its build.prop region"
        ));
    };
    if current_build_prop.len() != new_spl.len() {
        return Err(anyhow!(
            "Cannot patch /vendor/build.prop SPL in place: existing value {:?} ({} bytes) does not match new value length ({} bytes)",
            current_build_prop,
            current_build_prop.len(),
            new_spl.len()
        ));
    }

    // 3. Read hashtree descriptor params (need them before we mutate the data).
    let hashtree = read_vendor_hashtree_params(vendor_image)?
        .ok_or_else(|| anyhow!("vendor.img has no Hashtree descriptor for partition `vendor`"))?;
    let old_root_digest = hashtree.root_digest.clone();
    if hashtree.root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "vendor.img Hashtree descriptor uses an unexpected root_digest length {} (expected {})",
            hashtree.root_digest.len(),
            SHA256_DIGEST_SIZE
        ));
    }

    // 4. Patch build.prop SPL bytes in the data area.
    write_at_offset(vendor_image, build_prop_value_offset, new_spl.as_bytes())?;

    // 5. Regenerate dm-verity hash tree from the modified data and write it
    //    back at `tree_offset`. avbtool-rs::generate_hash_tree returns the
    //    root digest plus the full level-packed tree blob.
    let new_root_digest = regenerate_hashtree(vendor_image, &hashtree)?;
    if new_root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "Regenerated hash tree returned unexpected root_digest length {}",
            new_root_digest.len()
        ));
    }

    // 6. Patch vendor.img footer descriptors (NONE algorithm: no signature).
    patch_vendor_image_descriptors(vendor_image, new_spl, &new_root_digest)?;

    // 7. Patch vbmeta.img descriptors. The signed blob is left with a stale
    //    signature that the resign stage will refresh.
    patch_vbmeta_vendor_descriptors(vbmeta_image, new_spl, &new_root_digest)?;

    Ok(VendorSplOutcome::Patched {
        old: current_avb,
        new: new_spl.to_string(),
        old_root_digest: hex_encode(&old_root_digest),
        new_root_digest: hex_encode(&new_root_digest),
    })
}

/// Read the current `com.android.build.vendor.security_patch` from
/// `vendor.img`'s footer, or `Ok(None)` if absent.
pub fn read_vendor_avb_property(vendor_image: &Path) -> Result<Option<String>> {
    let (vbmeta_offset, vbmeta_blob) = read_vbmeta_blob(vendor_image)?;
    let _ = vbmeta_offset;
    if vbmeta_blob.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Ok(None);
    }
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let descriptors_blob = descriptors_slice(&vbmeta_blob, &header)?;

    if let Some((_, _, value)) = find_property_descriptor(descriptors_blob, VENDOR_SPL_PROPERTY)? {
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

/// Stream-scan `vendor.img` for `ro.vendor.build.security_patch=YYYY-MM-DD`
/// and return `(file_offset_of_value, current_value)`.
fn find_build_prop_security_patch(vendor_image: &Path) -> Result<Option<(u64, String)>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(vendor_image)
        .with_context(|| {
            format!(
                "Failed to open {} for build.prop scan",
                vendor_image.display()
            )
        })?;
    let file_size = file.metadata()?.len();

    let needle = BUILD_PROP_KEY;
    // Need access to needle.len() + 10 bytes after a match (date), so keep
    // an overlap region between chunks of `needle.len() + 10 - 1` bytes.
    let overlap = needle.len() + 10 - 1;
    let mut buf = vec![0u8; SCAN_CHUNK + overlap];
    let mut chunk_start: u64 = 0;

    loop {
        if chunk_start >= file_size {
            return Ok(None);
        }
        let to_read =
            std::cmp::min(buf.len() as u64, file_size.saturating_sub(chunk_start)) as usize;
        file.seek(SeekFrom::Start(chunk_start))?;
        file.read_exact(&mut buf[..to_read])?;

        if let Some(pos) = memmem::find(&buf[..to_read], needle) {
            let value_start_in_chunk = pos + needle.len();
            if value_start_in_chunk + 10 > to_read {
                // Not enough bytes for the date in this chunk — slide the
                // window so the match plus its date is fully contained next
                // iteration.
                if to_read < buf.len() {
                    return Ok(None);
                }
                chunk_start += pos as u64;
                continue;
            }
            let value_bytes = &buf[value_start_in_chunk..value_start_in_chunk + 10];
            let value = std::str::from_utf8(value_bytes)
                .with_context(|| {
                    format!(
                        "Build.prop value at offset {} is not UTF-8",
                        chunk_start + value_start_in_chunk as u64
                    )
                })?
                .to_string();
            let absolute_value_offset = chunk_start + value_start_in_chunk as u64;
            return Ok(Some((absolute_value_offset, value)));
        }

        if to_read < buf.len() {
            return Ok(None);
        }
        chunk_start += (SCAN_CHUNK) as u64;
    }
}

/// Read the Hashtree descriptor parameters for partition `vendor` from
/// vendor.img's footer.
fn read_vendor_hashtree_params(vendor_image: &Path) -> Result<Option<HashtreeParams>> {
    let (_, vbmeta_blob) = read_vbmeta_blob(vendor_image)?;
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let descriptors_blob = descriptors_slice(&vbmeta_blob, &header)?;

    let mut cursor = 0usize;
    while cursor < descriptors_blob.len() {
        let remaining = &descriptors_blob[cursor..];
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
            if partition_name == "vendor" {
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

fn regenerate_hashtree(vendor_image: &Path, params: &HashtreeParams) -> Result<Vec<u8>> {
    let block_size = params.data_block_size as u64;
    if block_size == 0 {
        return Err(anyhow!("Hashtree descriptor reports zero data_block_size"));
    }
    let digest_size = match params.hash_algorithm.as_str() {
        "sha256" => 32u64,
        other => {
            return Err(anyhow!(
                "Unsupported hash algorithm {} for vendor SPL hashtree regeneration",
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
        vendor_image,
        params.image_size,
        params.data_block_size,
        &params.hash_algorithm,
        &params.salt,
        digest_padding as usize,
        &hash_level_offsets,
        params.tree_size,
    )
    .map_err(|e| anyhow!("generate_hash_tree failed: {e}"))?;

    let mut file = OpenOptions::new()
        .write(true)
        .open(vendor_image)
        .with_context(|| {
            format!(
                "Failed to open {} for hash tree write",
                vendor_image.display()
            )
        })?;
    file.seek(SeekFrom::Start(params.tree_offset))?;
    file.write_all(&hash_tree_blob)?;
    file.flush()?;
    Ok(root_digest)
}

fn patch_vendor_image_descriptors(
    vendor_image: &Path,
    new_spl: &str,
    new_root_digest: &[u8],
) -> Result<()> {
    let (vbmeta_offset, vbmeta_blob) = read_vbmeta_blob(vendor_image)?;
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let aux_offset_in_blob =
        AVB_VBMETA_IMAGE_HEADER_SIZE + header.authentication_data_block_size as usize;
    let descriptors_start = aux_offset_in_blob + header.descriptors_offset as usize;
    let descriptors_size = header.descriptors_size as usize;
    let descriptors_blob = &vbmeta_blob[descriptors_start..descriptors_start + descriptors_size];

    let prop =
        find_property_descriptor_full(descriptors_blob, VENDOR_SPL_PROPERTY)?.ok_or_else(|| {
            anyhow!(
                "vendor.img footer is missing {} property",
                VENDOR_SPL_PROPERTY
            )
        })?;
    let hashtree = find_hashtree_descriptor(descriptors_blob, "vendor")?
        .ok_or_else(|| anyhow!("vendor.img footer is missing Hashtree descriptor for `vendor`"))?;

    if prop.value_len != new_spl.len() {
        return Err(anyhow!(
            "vendor.img footer {} property is {} bytes; cannot replace with {} bytes",
            VENDOR_SPL_PROPERTY,
            prop.value_len,
            new_spl.len()
        ));
    }
    if hashtree.root_digest_len != new_root_digest.len() {
        return Err(anyhow!(
            "vendor.img footer Hashtree root_digest is {} bytes; cannot replace with {} bytes",
            hashtree.root_digest_len,
            new_root_digest.len()
        ));
    }

    let prop_file_offset = vbmeta_offset
        + descriptors_start as u64
        + prop.descriptor_offset_in_blob as u64
        + prop.value_offset_in_descriptor as u64;
    let digest_file_offset = vbmeta_offset
        + descriptors_start as u64
        + hashtree.descriptor_offset_in_blob as u64
        + hashtree.root_digest_offset_in_descriptor as u64;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(vendor_image)
        .with_context(|| format!("Failed to open {} for footer patch", vendor_image.display()))?;
    file.seek(SeekFrom::Start(prop_file_offset))?;
    file.write_all(new_spl.as_bytes())?;
    file.seek(SeekFrom::Start(digest_file_offset))?;
    file.write_all(new_root_digest)?;
    file.flush()?;
    Ok(())
}

fn patch_vbmeta_vendor_descriptors(
    vbmeta_image: &Path,
    new_spl: &str,
    new_root_digest: &[u8],
) -> Result<()> {
    let (vbmeta_offset, vbmeta_blob) = read_vbmeta_blob(vbmeta_image)?;
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let aux_offset_in_blob =
        AVB_VBMETA_IMAGE_HEADER_SIZE + header.authentication_data_block_size as usize;
    let descriptors_start = aux_offset_in_blob + header.descriptors_offset as usize;
    let descriptors_size = header.descriptors_size as usize;
    let descriptors_blob = &vbmeta_blob[descriptors_start..descriptors_start + descriptors_size];

    let prop =
        find_property_descriptor_full(descriptors_blob, VENDOR_SPL_PROPERTY)?.ok_or_else(|| {
            anyhow!(
                "vbmeta.img is missing {} property descriptor",
                VENDOR_SPL_PROPERTY
            )
        })?;
    let hashtree = find_hashtree_descriptor(descriptors_blob, "vendor")?
        .ok_or_else(|| anyhow!("vbmeta.img is missing Hashtree descriptor for `vendor`"))?;

    if prop.value_len != new_spl.len() {
        return Err(anyhow!(
            "vbmeta.img {} property is {} bytes; cannot replace with {} bytes",
            VENDOR_SPL_PROPERTY,
            prop.value_len,
            new_spl.len()
        ));
    }
    if hashtree.root_digest_len != new_root_digest.len() {
        return Err(anyhow!(
            "vbmeta.img vendor Hashtree root_digest is {} bytes; cannot replace with {} bytes",
            hashtree.root_digest_len,
            new_root_digest.len()
        ));
    }

    let prop_file_offset = vbmeta_offset
        + descriptors_start as u64
        + prop.descriptor_offset_in_blob as u64
        + prop.value_offset_in_descriptor as u64;
    let digest_file_offset = vbmeta_offset
        + descriptors_start as u64
        + hashtree.descriptor_offset_in_blob as u64
        + hashtree.root_digest_offset_in_descriptor as u64;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(vbmeta_image)
        .with_context(|| {
            format!(
                "Failed to open {} for vendor descriptor patch",
                vbmeta_image.display()
            )
        })?;
    file.seek(SeekFrom::Start(prop_file_offset))?;
    file.write_all(new_spl.as_bytes())?;
    file.seek(SeekFrom::Start(digest_file_offset))?;
    file.write_all(new_root_digest)?;
    file.flush()?;
    Ok(())
}

fn write_at_offset(image_path: &Path, offset: u64, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .with_context(|| format!("Failed to open {} for in-place write", image_path.display()))?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn read_vbmeta_blob(image_path: &Path) -> Result<(u64, Vec<u8>)> {
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

fn descriptors_slice<'a>(vbmeta_blob: &'a [u8], header: &AvbVBMetaHeader) -> Result<&'a [u8]> {
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

#[derive(Debug, Clone)]
struct PropertyHit {
    descriptor_offset_in_blob: usize,
    value_offset_in_descriptor: usize,
    value_len: usize,
}

#[derive(Debug, Clone)]
struct HashtreeHit {
    descriptor_offset_in_blob: usize,
    root_digest_offset_in_descriptor: usize,
    root_digest_len: usize,
}

fn find_property_descriptor(
    descriptors_blob: &[u8],
    target_key: &str,
) -> Result<Option<(usize, usize, String)>> {
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
            if body.len() >= value_start + value_len + 1 {
                let key_bytes = &body[key_start..key_start + key_len];
                if key_bytes == target_key.as_bytes() {
                    let current_value =
                        String::from_utf8_lossy(&body[value_start..value_start + value_len])
                            .into_owned();
                    return Ok(Some((cursor, value_start, current_value)));
                }
            }
        }
        cursor += total;
    }
    Ok(None)
}

fn find_property_descriptor_full(
    descriptors_blob: &[u8],
    target_key: &str,
) -> Result<Option<PropertyHit>> {
    let Some((descriptor_offset_in_blob, value_offset_in_descriptor, current_value)) =
        find_property_descriptor(descriptors_blob, target_key)?
    else {
        return Ok(None);
    };
    Ok(Some(PropertyHit {
        descriptor_offset_in_blob,
        value_offset_in_descriptor,
        value_len: current_value.len(),
    }))
}

fn find_hashtree_descriptor(
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

fn read_cstring(slice: &[u8]) -> String {
    let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn next_pow2(value: u64) -> u64 {
    let mut p = 1u64;
    while p < value {
        p <<= 1;
    }
    p
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
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
        out[16..20].copy_from_slice(&1u32.to_be_bytes()); // dm-verity v1
        // image_size, tree_offset, tree_size, block sizes, fec — leave zero
        // hash_algorithm
        let algo = b"sha256";
        out[72..72 + algo.len()].copy_from_slice(algo);
        // partition_name_len, salt_len, root_digest_len
        out[104..108].copy_from_slice(&(partition.len() as u32).to_be_bytes());
        out[108..112].copy_from_slice(&(salt.len() as u32).to_be_bytes());
        out[112..116].copy_from_slice(&(digest.len() as u32).to_be_bytes());
        // flags zero
        let mut payload_off = HASHTREE_DESCRIPTOR_FIXED_SIZE;
        out[payload_off..payload_off + partition.len()].copy_from_slice(partition.as_bytes());
        payload_off += partition.len();
        out[payload_off..payload_off + salt.len()].copy_from_slice(salt);
        payload_off += salt.len();
        out[payload_off..payload_off + digest.len()].copy_from_slice(digest);
        out
    }

    #[test]
    fn find_descriptors_works() {
        let mut blob = Vec::new();
        blob.extend(build_property_descriptor(
            "com.android.build.vendor.os_version",
            "15",
        ));
        blob.extend(build_property_descriptor(VENDOR_SPL_PROPERTY, "2025-02-05"));
        let salt = vec![0u8; 32];
        let digest = vec![0xAAu8; 32];
        blob.extend(build_hashtree_descriptor("vendor", &salt, &digest));

        let prop = find_property_descriptor(&blob, VENDOR_SPL_PROPERTY)
            .unwrap()
            .unwrap();
        let absolute_value = prop.0 + prop.1;
        assert_eq!(&blob[absolute_value..absolute_value + 10], b"2025-02-05");

        let hit = find_hashtree_descriptor(&blob, "vendor").unwrap().unwrap();
        let absolute_digest = hit.descriptor_offset_in_blob + hit.root_digest_offset_in_descriptor;
        assert_eq!(&blob[absolute_digest..absolute_digest + 32], &digest[..]);
    }

    #[test]
    fn next_pow2_basic() {
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(32), 32);
        assert_eq!(next_pow2(33), 64);
    }
}
