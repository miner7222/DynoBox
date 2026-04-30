//! Patch the `com.android.build.boot.security_patch` AVB property descriptor
//! on `boot.img` so the resign stage can re-sign over the new value.
//!
//! The patch is an in-place byte rewrite on the descriptors blob: date strings
//! are always 10 bytes, so the descriptor body keeps the same padded size and
//! no header offsets need to be recomputed. Re-signing is left to
//! `avbtool-rs::resign::resign_image_with_options`, which reads the modified
//! descriptors blob from disk and rebuilds the authentication block.

use std::path::Path;

use anyhow::{Result, anyhow};

use crate::avb_descriptor::{
    PatchPropertyOutcome, find_property_descriptor, patch_property_value, read_vbmeta_blob,
};
use avbtool_rs::parser::{AVB_VBMETA_IMAGE_HEADER_SIZE, AvbVBMetaHeader};

pub const BOOT_SPL_PROPERTY: &str = "com.android.build.boot.security_patch";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootSplPatchOutcome {
    Patched { old: String, new: String },
    SkippedNotNewer { old: String, requested: String },
    NotFound,
}

/// Validate that `spl` is a strict `YYYY-MM-DD` 10-byte ASCII string. The
/// in-place patch relies on the new value matching the existing length.
pub fn validate_spl_format(spl: &str) -> Result<()> {
    crate::spl::validate_spl_format("--boot-spl", spl)
}

/// Read the current value of the boot security_patch property descriptor.
/// Returns `Ok(None)` when the image has no AVB metadata or no such property.
pub fn read_security_patch(image_path: &Path) -> Result<Option<String>> {
    let (_, vbmeta_blob) = read_vbmeta_blob(image_path)?;
    if vbmeta_blob.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Ok(None);
    }
    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    let descriptors = crate::avb_descriptor::descriptors_slice(&vbmeta_blob, &header)?;
    Ok(find_property_descriptor(descriptors, BOOT_SPL_PROPERTY)?.map(|hit| hit.current_value))
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

    // Read the current value first so the not-newer skip and the
    // "Patched { old, new }" logging both work without rereading.
    let current_value = match read_security_patch(image_path)? {
        Some(value) => value,
        None => return Ok(BootSplPatchOutcome::NotFound),
    };

    if new_spl <= current_value.as_str() {
        return Ok(BootSplPatchOutcome::SkippedNotNewer {
            old: current_value,
            requested: new_spl.to_string(),
        });
    }

    match patch_property_value(image_path, BOOT_SPL_PROPERTY, new_spl.as_bytes())? {
        PatchPropertyOutcome::Patched { old_value } => Ok(BootSplPatchOutcome::Patched {
            old: old_value,
            new: new_spl.to_string(),
        }),
        PatchPropertyOutcome::NotFound => Ok(BootSplPatchOutcome::NotFound),
        PatchPropertyOutcome::LengthMismatch {
            current_value,
            current_len,
            requested_len,
        } => Err(anyhow!(
            "Cannot patch boot SPL in place on {}: existing value {:?} ({} bytes) does not match new value length ({} bytes). Only same-length YYYY-MM-DD replacements are supported.",
            image_path.display(),
            current_value,
            current_len,
            requested_len
        )),
    }
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
        assert!(validate_spl_format("2026-00-05").is_err());
        assert!(validate_spl_format("2026-13-05").is_err());
        assert!(validate_spl_format("2026-04-31").is_err());
        assert!(validate_spl_format("2025-02-29").is_err());
    }
}
