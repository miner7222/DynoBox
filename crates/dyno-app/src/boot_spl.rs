//! Patch the `com.android.build.boot.security_patch` AVB property descriptor
//! on `boot.img` so the resign stage can re-sign over the new value.
//!
//! The patch is an in-place byte rewrite on the descriptors blob: date strings
//! are always 10 bytes, so the descriptor body keeps the same padded size and
//! no header offsets need to be recomputed. Re-signing is left to
//! `avbtool-rs::resign::resign_image_with_options`, which reads the modified
//! descriptors blob from disk and rebuilds the authentication block.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use avbtool_rs::parser::{
    AVB_FOOTER_SIZE, AVB_VBMETA_IMAGE_HEADER_SIZE, AvbFooter, AvbImageType, AvbVBMetaHeader,
    detect_avb_image_type,
};

pub const BOOT_SPL_PROPERTY: &str = "com.android.build.boot.security_patch";

const DESCRIPTOR_HEADER_SIZE: usize = 16;
const PROPERTY_DESCRIPTOR_SIZE: usize = 32;
const DESCRIPTOR_TAG_PROPERTY: u64 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootSplPatchOutcome {
    Patched { old: String, new: String },
    SkippedNotNewer { old: String, requested: String },
    NotFound,
}

/// Validate that `spl` is a strict `YYYY-MM-DD` 10-byte ASCII string. The
/// in-place patch relies on the new value matching the existing length.
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
            "--boot-spl must be in YYYY-MM-DD format (got {:?})",
            spl
        ));
    }
    Ok(())
}

/// Read the current value of the boot security_patch property descriptor.
/// Returns `Ok(None)` when the image has no AVB metadata or no such property.
pub fn read_security_patch(image_path: &Path) -> Result<Option<String>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(image_path)
        .with_context(|| format!("Failed to open {} for boot SPL read", image_path.display()))?;
    let file_size = file.metadata()?.len();

    let img_type = detect_avb_image_type(image_path)?;
    let (vbmeta_offset, vbmeta_size) = match img_type {
        AvbImageType::Vbmeta => (0u64, file_size),
        AvbImageType::Footer => {
            file.seek(SeekFrom::End(-(AVB_FOOTER_SIZE as i64)))?;
            let footer = AvbFooter::from_reader(&mut file)?;
            (footer.vbmeta_offset, footer.vbmeta_size)
        }
        AvbImageType::None => return Ok(None),
    };

    let mut vbmeta_blob = vec![0u8; vbmeta_size as usize];
    file.seek(SeekFrom::Start(vbmeta_offset))?;
    file.read_exact(&mut vbmeta_blob)?;

    if vbmeta_blob.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Ok(None);
    }
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;

    let aux_offset_in_blob =
        AVB_VBMETA_IMAGE_HEADER_SIZE + header.authentication_data_block_size as usize;
    let descriptors_start = aux_offset_in_blob + header.descriptors_offset as usize;
    let descriptors_end = descriptors_start + header.descriptors_size as usize;
    if descriptors_end > vbmeta_blob.len() {
        return Err(anyhow!(
            "VBMeta descriptors range {}..{} exceeds blob length {}",
            descriptors_start,
            descriptors_end,
            vbmeta_blob.len()
        ));
    }
    let descriptors_blob = &vbmeta_blob[descriptors_start..descriptors_end];

    if let Some((_, _, current_value)) =
        find_property_descriptor(descriptors_blob, BOOT_SPL_PROPERTY)?
    {
        Ok(Some(current_value))
    } else {
        Ok(None)
    }
}

/// Patch the `com.android.build.boot.security_patch` property descriptor in
/// `image_path` to `new_spl`. The new value must be lexicographically greater
/// than the existing one (which, for `YYYY-MM-DD`, matches chronological order).
///
/// The descriptors blob layout is preserved because both the existing and the
/// new value are 10 bytes. The image is left with a stale signature; the caller
/// is expected to re-sign immediately after.
pub fn patch_security_patch(image_path: &Path, new_spl: &str) -> Result<BootSplPatchOutcome> {
    validate_spl_format(new_spl)?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .with_context(|| format!("Failed to open {} for boot SPL patch", image_path.display()))?;
    let file_size = file.metadata()?.len();

    let img_type = detect_avb_image_type(image_path)?;
    let (vbmeta_offset, vbmeta_size) = match img_type {
        AvbImageType::Vbmeta => (0u64, file_size),
        AvbImageType::Footer => {
            file.seek(SeekFrom::End(-(AVB_FOOTER_SIZE as i64)))?;
            let footer = AvbFooter::from_reader(&mut file)?;
            (footer.vbmeta_offset, footer.vbmeta_size)
        }
        AvbImageType::None => return Ok(BootSplPatchOutcome::NotFound),
    };

    let mut vbmeta_blob = vec![0u8; vbmeta_size as usize];
    file.seek(SeekFrom::Start(vbmeta_offset))?;
    file.read_exact(&mut vbmeta_blob)?;

    if vbmeta_blob.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Ok(BootSplPatchOutcome::NotFound);
    }
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;

    let aux_offset_in_blob =
        AVB_VBMETA_IMAGE_HEADER_SIZE + header.authentication_data_block_size as usize;
    let descriptors_start = aux_offset_in_blob + header.descriptors_offset as usize;
    let descriptors_end = descriptors_start + header.descriptors_size as usize;
    if descriptors_end > vbmeta_blob.len() {
        return Err(anyhow!(
            "VBMeta descriptors range {}..{} exceeds blob length {}",
            descriptors_start,
            descriptors_end,
            vbmeta_blob.len()
        ));
    }
    let descriptors_blob = &vbmeta_blob[descriptors_start..descriptors_end];

    let Some((cursor, value_offset_in_descriptor, current_value)) =
        find_property_descriptor(descriptors_blob, BOOT_SPL_PROPERTY)?
    else {
        return Ok(BootSplPatchOutcome::NotFound);
    };

    if current_value.len() != new_spl.len() {
        return Err(anyhow!(
            "Cannot patch boot SPL in place on {}: existing value {:?} ({} bytes) does not match new value length ({} bytes). Only same-length YYYY-MM-DD replacements are supported.",
            image_path.display(),
            current_value,
            current_value.len(),
            new_spl.len()
        ));
    }

    if new_spl <= current_value.as_str() {
        return Ok(BootSplPatchOutcome::SkippedNotNewer {
            old: current_value,
            requested: new_spl.to_string(),
        });
    }

    let value_offset_in_file = vbmeta_offset
        + descriptors_start as u64
        + cursor as u64
        + value_offset_in_descriptor as u64;
    file.seek(SeekFrom::Start(value_offset_in_file))?;
    file.write_all(new_spl.as_bytes())?;
    file.flush()?;

    Ok(BootSplPatchOutcome::Patched {
        old: current_value,
        new: new_spl.to_string(),
    })
}

/// Walk the descriptors blob and return `(cursor_in_blob, value_offset_in_descriptor, current_value)`
/// for the property descriptor whose key matches `target_key`, if any.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_spl_format_accepts_iso_date() {
        assert!(validate_spl_format("2026-04-05").is_ok());
        assert!(validate_spl_format("1970-01-01").is_ok());
    }

    #[test]
    fn validate_spl_format_rejects_bad_inputs() {
        assert!(validate_spl_format("2026/04/05").is_err());
        assert!(validate_spl_format("2026-4-5").is_err());
        assert!(validate_spl_format("26-04-05").is_err());
        assert!(validate_spl_format("").is_err());
        assert!(validate_spl_format("2026-04-05 ").is_err());
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

    #[test]
    fn find_property_descriptor_locates_security_patch() {
        let mut blob = Vec::new();
        blob.extend(build_property_descriptor(
            "com.android.build.boot.os_version",
            "15",
        ));
        blob.extend(build_property_descriptor(BOOT_SPL_PROPERTY, "2025-02-05"));
        blob.extend(build_property_descriptor(
            "com.android.build.boot.fingerprint",
            "abc",
        ));

        let (cursor, value_off, value) = find_property_descriptor(&blob, BOOT_SPL_PROPERTY)
            .unwrap()
            .unwrap();
        assert_eq!(value, "2025-02-05");
        let abs_value = cursor + value_off;
        assert_eq!(&blob[abs_value..abs_value + 10], b"2025-02-05");
    }

    #[test]
    fn find_property_descriptor_returns_none_when_missing() {
        let blob = build_property_descriptor("com.android.build.boot.os_version", "15");
        assert!(
            find_property_descriptor(&blob, BOOT_SPL_PROPERTY)
                .unwrap()
                .is_none()
        );
    }
}
