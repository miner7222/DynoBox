//! `--system-spl`: bump `system.img`'s security_patch and propagate it to
//! `vbmeta_system.img`. Thin binding over the shared [`crate::spl_patch`]
//! engine; see that module for the full patch flow.
//!
//! `system.img` uses the system-as-root layout, so the build.prop Settings
//! reads lives at `/system/build.prop` (mirroring
//! `/system/framework/framework.jar` that `--fuck-lgsi` walks), and the SPL
//! key is `ro.build.version.security_patch` — the value Settings surfaces as
//! "Android security update".

use std::path::Path;

use crate::avb_descriptor::VerityProgressCallback;
use crate::spl_patch::{self, SplOutcome, SplPatchSpec};
use anyhow::Result;

pub const SYSTEM_SPL_PROPERTY: &str = "com.android.build.system.security_patch";

const SYSTEM_SPEC: SplPatchSpec = SplPatchSpec {
    flag_label: "--system-spl",
    partition_name: "system",
    image_label: "system.img",
    avb_property: SYSTEM_SPL_PROPERTY,
    build_prop_path: &["system", "build.prop"],
    build_prop_display: "/system/build.prop",
    build_prop_needle: b"ro.build.version.security_patch=",
};

/// Outcome of [`apply_system_spl`]; alias of the shared [`SplOutcome`].
pub type SystemSplOutcome = SplOutcome;

/// Validate `spl` is a strict `YYYY-MM-DD` ASCII string.
pub fn validate_spl_format(spl: &str) -> Result<()> {
    spl_patch::validate_spl_format(&SYSTEM_SPEC, spl)
}

/// Apply `--system-spl` to `system.img` and propagate to
/// `vbmeta_system.img`. Caller re-signs `vbmeta_system.img` afterwards.
/// Equivalent to [`apply_system_spl_with_progress`] with
/// `verity_progress = None`.
pub fn apply_system_spl(
    system_image: &Path,
    vbmeta_system_image: &Path,
    new_spl: &str,
) -> Result<SystemSplOutcome> {
    apply_system_spl_with_progress(system_image, vbmeta_system_image, new_spl, None)
}

/// Like [`apply_system_spl`] but reports dm-verity regeneration progress.
pub fn apply_system_spl_with_progress(
    system_image: &Path,
    vbmeta_system_image: &Path,
    new_spl: &str,
    verity_progress: Option<VerityProgressCallback>,
) -> Result<SystemSplOutcome> {
    spl_patch::apply_spl_with_progress(
        &SYSTEM_SPEC,
        system_image,
        vbmeta_system_image,
        new_spl,
        verity_progress,
    )
}

/// Read the current `com.android.build.system.security_patch` from
/// `system.img`'s footer, or `Ok(None)` if absent.
pub fn read_system_avb_property(system_image: &Path) -> Result<Option<String>> {
    spl_patch::read_avb_property(&SYSTEM_SPEC, system_image)
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
