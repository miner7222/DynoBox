//! `--vendor-spl`: bump `vendor.img`'s security_patch and propagate it to
//! `vbmeta.img`. Thin binding over the shared [`crate::spl_patch`] engine;
//! see that module for the full patch flow. The only vendor-specific bits
//! are the build.prop key/path, the AVB property, and the partition name.

use std::path::Path;

use crate::avb_descriptor::VerityProgressCallback;
use crate::spl_patch::{self, SplOutcome, SplPatchSpec};
use anyhow::Result;

pub const VENDOR_SPL_PROPERTY: &str = "com.android.build.vendor.security_patch";

/// `vendor.img` uses a top-level `build.prop`; its SPL key is
/// `ro.vendor.build.security_patch`.
const VENDOR_SPEC: SplPatchSpec = SplPatchSpec {
    flag_label: "--vendor-spl",
    partition_name: "vendor",
    image_label: "vendor.img",
    avb_property: VENDOR_SPL_PROPERTY,
    build_prop_path: &["build.prop"],
    build_prop_display: "/build.prop",
    build_prop_needle: b"ro.vendor.build.security_patch=",
};

/// Outcome of [`apply_vendor_spl`]; alias of the shared [`SplOutcome`].
pub type VendorSplOutcome = SplOutcome;

/// Validate `spl` is a strict `YYYY-MM-DD` ASCII string.
pub fn validate_spl_format(spl: &str) -> Result<()> {
    spl_patch::validate_spl_format(&VENDOR_SPEC, spl)
}

/// Apply `--vendor-spl` to `vendor.img` and propagate to `vbmeta.img`.
/// Caller re-signs `vbmeta.img` afterwards. Equivalent to
/// [`apply_vendor_spl_with_progress`] with `verity_progress = None`.
pub fn apply_vendor_spl(
    vendor_image: &Path,
    vbmeta_image: &Path,
    new_spl: &str,
) -> Result<VendorSplOutcome> {
    apply_vendor_spl_with_progress(vendor_image, vbmeta_image, new_spl, None)
}

/// Like [`apply_vendor_spl`] but reports dm-verity regeneration progress.
pub fn apply_vendor_spl_with_progress(
    vendor_image: &Path,
    vbmeta_image: &Path,
    new_spl: &str,
    verity_progress: Option<VerityProgressCallback>,
) -> Result<VendorSplOutcome> {
    spl_patch::apply_spl_with_progress(
        &VENDOR_SPEC,
        vendor_image,
        vbmeta_image,
        new_spl,
        verity_progress,
    )
}

/// Read the current `com.android.build.vendor.security_patch` from
/// `vendor.img`'s footer, or `Ok(None)` if absent.
pub fn read_vendor_avb_property(vendor_image: &Path) -> Result<Option<String>> {
    spl_patch::read_avb_property(&VENDOR_SPEC, vendor_image)
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
        assert!(validate_spl_format("2026-00-05").is_err());
        assert!(validate_spl_format("2026-13-05").is_err());
        assert!(validate_spl_format("2026-04-31").is_err());
        assert!(validate_spl_format("2025-02-29").is_err());
    }
}
