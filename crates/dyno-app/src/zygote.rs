//! Zygote preload plumbing shared by `--add-spoof`.
//!
//! The per-app property library has to be loaded by the 64-bit zygote before
//! any app process forks. New images load it through the `DT_NEEDED` entry that
//! [`crate::elf_needed`] adds to `/system/bin/app_process64`; older DynoBox
//! images used an `LD_PRELOAD` line in `init.zygote64.rc`, which the linker
//! ignores when the service runs with `AT_SECURE=1`.
//!
//! This module removes that legacy line from the
//! `service zygote /system/bin/app_process64` block, if an image still has it.
//! The block boundary is matched explicitly so a multi-service rc cannot touch
//! a different process, and the replacement keeps the file length unchanged.
//!
//! The caller regenerates `system.img` dm-verity once and re-signs
//! `vbmeta_system.img`; this module only mutates data.

use std::io::{Read, Seek};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use memchr::memmem;

use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume, write_via_extents};

pub const LIB_NAME: &str = "libspoof.so";
pub const LIB_DIR: &str = "system/lib64";
pub const LIB_PATH: &str = "system/lib64/libspoof.so";

pub const ZYGOTE_RC_PATH: &str = "system/etc/init/hw/init.zygote64.rc";
const ZYGOTE64_SERVICE_PREFIX: &str = "service zygote /system/bin/app_process64";

/// Legacy service option that older images added to zygote.
///
/// init's service option is `setenv`; `environment` was not a keyword and was
/// silently ignored. Both spellings are removed because the secure-exec linker
/// ignores `LD_PRELOAD` for the zygote service.
pub const PRELOAD_LINE: &str = "setenv LD_PRELOAD /system/lib64/libspoof.so";

/// The `environment` spelling written by even older DynoBox builds.
const LEGACY_PRELOAD_LINE: &str = "environment LD_PRELOAD /system/lib64/libspoof.so";

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;

/// State of the legacy init preload line after [`patch_init_scripts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitPatchOutcome {
    PreloadRemoved,
    AlreadyClean,
}

impl InitPatchOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::PreloadRemoved => "legacy preload removed",
            Self::AlreadyClean => "no legacy preload",
        }
    }
}

/// Result of the init-script edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitPatchResult {
    pub path: String,
    pub outcome: InitPatchOutcome,
}

/// The preload payload has to be an arm64 shared object: a 32-bit or foreign
/// ELF would either fail to load or crash zygote, taking every app with it.
pub fn validate_elf64_aarch64(bytes: &[u8], path: &Path) -> Result<()> {
    if bytes.len() < 64 {
        bail!(
            "--add-spoof: `{}` is too small to be an ELF file",
            path.display()
        );
    }
    if &bytes[0..4] != ELF_MAGIC {
        bail!("--add-spoof: `{}` is not an ELF file", path.display());
    }
    if bytes[4] != ELFCLASS64 {
        bail!(
            "--add-spoof: `{}` is not a 64-bit ELF (only arm64-v8a is supported)",
            path.display()
        );
    }
    if bytes[5] != ELFDATA2LSB {
        bail!("--add-spoof: `{}` is not little-endian", path.display());
    }
    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    if e_type != ET_DYN {
        bail!(
            "--add-spoof: `{}` is not a shared object (ELF e_type {e_type}, expected {ET_DYN})",
            path.display()
        );
    }
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if e_machine != EM_AARCH64 {
        bail!(
            "--add-spoof: `{}` targets ELF machine {e_machine}, expected AArch64 ({EM_AARCH64})",
            path.display()
        );
    }
    Ok(())
}

/// Remove the legacy preload line from `system.img`'s 64-bit zygote service.
pub fn patch_init_scripts(system_image: &Path) -> Result<InitPatchResult> {
    match patch_zygote_rc(system_image)? {
        Some(result) => Ok(result),
        None => Err(anyhow!(
            "--add-spoof: {ZYGOTE_RC_PATH} has no `{ZYGOTE64_SERVICE_PREFIX}` block; \
             patch the init script manually or update DynoBox"
        )),
    }
}

/// Patch only the service zygote /system/bin/app_process64 block.
fn patch_zygote_rc(system_image: &Path) -> Result<Option<InitPatchResult>> {
    let components = ["system", "etc", "init", "hw", "init.zygote64.rc"];
    let mut volume = open_ext4_volume(system_image)?;
    let Some(inode) = lookup_inode_at_path(&mut volume, &components)? else {
        return Ok(None);
    };
    if !inode.is_file() {
        bail!("--add-spoof: {ZYGOTE_RC_PATH} is not a regular file");
    }
    let (bytes, extents) = inode
        .open_read_with_extents(&mut volume)
        .with_context(|| format!("--add-spoof: reading {ZYGOTE_RC_PATH}"))?;
    if extents.is_empty() {
        bail!("--add-spoof: {ZYGOTE_RC_PATH} has no extent mapping");
    }

    match patch_zygote_service_bytes(&bytes)? {
        ZygotePatch::Absent => Ok(None),
        ZygotePatch::AlreadyClean => Ok(Some(InitPatchResult {
            path: ZYGOTE_RC_PATH.to_string(),
            outcome: InitPatchOutcome::AlreadyClean,
        })),
        ZygotePatch::Patched(patched) => {
            write_via_extents(system_image, &patched, &extents, volume.block_size)?;
            Ok(Some(InitPatchResult {
                path: ZYGOTE_RC_PATH.to_string(),
                outcome: InitPatchOutcome::PreloadRemoved,
            }))
        }
    }
}

enum ZygotePatch {
    Absent,
    AlreadyClean,
    Patched(Vec<u8>),
}

fn patch_zygote_service_bytes(bytes: &[u8]) -> Result<ZygotePatch> {
    let Some(start) = memmem::find(bytes, ZYGOTE64_SERVICE_PREFIX.as_bytes()) else {
        return Ok(ZygotePatch::Absent);
    };
    let end = zygote_service_end(bytes, start);
    let block = &bytes[start..end];
    let Some(patched_block) = remove_preload(block) else {
        return Ok(ZygotePatch::AlreadyClean);
    };
    let mut patched = bytes.to_vec();
    patched[start..end].copy_from_slice(&patched_block);
    Ok(ZygotePatch::Patched(patched))
}

/// Replace every legacy preload line in the service block with spaces, keeping
/// the block length unchanged. Returns `None` when the block is already clean.
fn remove_preload(block: &[u8]) -> Option<Vec<u8>> {
    let mut patched = block.to_vec();
    let mut removed = false;
    for line in [PRELOAD_LINE.as_bytes(), LEGACY_PRELOAD_LINE.as_bytes()] {
        let mut search_from = 0usize;
        while let Some(relative) = memmem::find(&patched[search_from..], line) {
            let offset = search_from + relative;
            patched[offset..offset + line.len()].fill(b' ');
            removed = true;
            search_from = offset + line.len();
        }
    }
    removed.then_some(patched)
}

fn zygote_service_end(bytes: &[u8], start: usize) -> usize {
    let rest = &bytes[start..];
    let mut end = bytes.len();
    for needle in [
        b"\nservice ".as_slice(),
        b"\non ".as_slice(),
        b"\nimport ".as_slice(),
    ] {
        if let Some(pos) = memmem::find(rest, needle) {
            end = end.min(start + pos + 1);
        }
    }
    end
}

/// Read an existing file out of the image so an already-installed payload can
/// be compared instead of blindly overwriting it.
pub(crate) fn read_existing<R: Read + Seek>(
    volume: &mut crate::ext4_reader::Ext4Volume<R>,
    components: &[&str],
    context: &str,
) -> Result<Option<Vec<u8>>> {
    let Some(inode) = lookup_inode_at_path(volume, components)? else {
        return Ok(None);
    };
    let bytes = inode
        .open_read(volume)
        .with_context(|| format!("{context}: reading existing {}", components.join("/")))?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZYGOTE_SAMPLE: &str = "\
service zygote /system/bin/app_process64 -Xzygote /system/bin --zygote --start-system-server
    class main
    user root
    onrestart write /sys/power/state on
    setenv LD_PRELOAD /system/lib64/libspoof.so
    # update SystemSuspend.cpp
    task_profiles ProcessCapacityHigh MaxPerformance
";

    const CLEAN_ZYGOTE_SAMPLE: &str = "\
service zygote /system/bin/app_process64 -Xzygote /system/bin --zygote --start-system-server
    class main
    user root
    onrestart write /sys/power/state on
    # update SystemSuspend.cpp
    task_profiles ProcessCapacityHigh MaxPerformance
";

    #[test]
    fn removes_the_preload_line_and_preserves_length() {
        match patch_zygote_service_bytes(ZYGOTE_SAMPLE.as_bytes()).unwrap() {
            ZygotePatch::Patched(bytes) => {
                assert_eq!(bytes.len(), ZYGOTE_SAMPLE.len());
                let text = String::from_utf8(bytes).unwrap();
                assert!(!text.contains(PRELOAD_LINE));
                assert!(text.contains("task_profiles ProcessCapacityHigh"));
                assert!(text.contains("class main"));
            }
            _ => panic!("expected the preload line to be removed"),
        }
    }

    #[test]
    fn removes_the_legacy_preload_line() {
        let sample = ZYGOTE_SAMPLE.replace(PRELOAD_LINE, LEGACY_PRELOAD_LINE);
        match patch_zygote_service_bytes(sample.as_bytes()).unwrap() {
            ZygotePatch::Patched(bytes) => {
                assert_eq!(bytes.len(), sample.len());
                let text = String::from_utf8(bytes).unwrap();
                assert!(!text.contains(LEGACY_PRELOAD_LINE));
                assert!(!text.contains(PRELOAD_LINE));
                assert!(text.contains("task_profiles ProcessCapacityHigh"));
            }
            _ => panic!("expected the legacy preload line to be removed"),
        }
    }

    #[test]
    fn clean_service_is_already_clean() {
        assert!(matches!(
            patch_zygote_service_bytes(CLEAN_ZYGOTE_SAMPLE.as_bytes()).unwrap(),
            ZygotePatch::AlreadyClean
        ));
    }

    #[test]
    fn zygote_service_patch_only_touches_the_64_bit_block() {
        let sample =
            format!("{ZYGOTE_SAMPLE}service other /system/bin/other\n    {PRELOAD_LINE}\n");
        match patch_zygote_service_bytes(sample.as_bytes()).unwrap() {
            ZygotePatch::Patched(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                assert_eq!(text.matches(PRELOAD_LINE).count(), 1);
                assert!(text.contains("service other /system/bin/other"));
                assert!(text.contains("task_profiles ProcessCapacityHigh"));
            }
            _ => panic!("expected the 64-bit zygote service to be patched"),
        }
    }

    fn elf64_aarch64() -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        bytes
    }

    #[test]
    fn elf_validation_accepts_arm64_shared_object() {
        validate_elf64_aarch64(&elf64_aarch64(), Path::new("libspoof.so")).unwrap();
    }

    #[test]
    fn elf_validation_rejects_32_bit() {
        let mut bytes = elf64_aarch64();
        bytes[4] = 1;
        assert!(validate_elf64_aarch64(&bytes, Path::new("libspoof.so")).is_err());
    }

    #[test]
    fn elf_validation_rejects_x86_64() {
        let mut bytes = elf64_aarch64();
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert!(validate_elf64_aarch64(&bytes, Path::new("libspoof.so")).is_err());
    }
}
