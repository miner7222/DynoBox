//! `--debloat`: hide selected files/folders from unpacked super partitions
//! (ext4 `system.img` / `product.img` / `vendor.img` …) without mounting.
//!
//! Approach (validated with an external review): the target partitions are
//! mounted **read-only under dm-verity**, so the kernel never runs `e2fsck`
//! on them and trusts the verity tree. That makes the smallest possible
//! mutation — a *dirent-only hide* — both sufficient and safe: we edit only
//! the parent directory's entry so the path becomes unreachable, leaving the
//! inode, data blocks, bitmaps, and free counts untouched. Space is not
//! reclaimed; the partition image keeps its size. The caller regenerates the
//! dm-verity hash tree and re-signs AVB afterwards.
//!
//! The edit reuses the existing read/write primitives: read the parent
//! directory's data blocks ([`Inode::open_read_with_extents`]), rewrite the
//! dirent bytes in place, and write the same-length buffer back through the
//! extent map ([`crate::ext4_helpers::write_via_extents`]).
//!
//! Hard feature gate (unsupported layouts are skipped, never mutated):
//! require `EXTENTS`; reject `metadata_csum` (directory blocks carry a
//! crc32c that a dirent edit would invalidate) and `encrypt`/`casefold`
//! (names can't be byte-matched). `gdt_csum`/`uninit_bg`, `flex_bg`, `64bit`,
//! and `htree` are fine — none add a per-directory-block checksum, and we
//! never touch group descriptors, bitmaps, or free counts.

use std::path::Path;

use anyhow::{Context, Result};

use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume, write_via_extents};
use crate::ext4_reader::{Ext4Volume, Inode};

// ext4 feature bits.
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;
const INCOMPAT_CASEFOLD: u32 = 0x2_0000;
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

// ext4 directory-entry file_type for a directory.
const FT_DIR: u8 = 2;

/// How the debloat removal list is supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebloatMode {
    /// Write an empty `debloat.txt`, pause on stdin for the user to edit it,
    /// then read it back.
    Interactive,
    /// Read the removal list from a caller-provided file (no prompt). Used for
    /// automation and non-interactive pipelines.
    ListFile(std::path::PathBuf),
}

/// Outcome of attempting to hide one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HideOutcome {
    /// The dirent was found and hidden; the image was modified.
    Removed,
    /// The path (or its parent) does not exist — ignored.
    NotFound,
}

/// Reject partitions whose on-disk layout we cannot mutate safely.
fn ensure_supported<R: std::io::Read + std::io::Seek>(volume: &Ext4Volume<R>) -> Result<()> {
    let incompat = volume.incompat_features();
    let ro_compat = volume.ro_compat_features();
    if incompat & INCOMPAT_EXTENTS == 0 {
        anyhow::bail!("ext4 image is not extent-based (block-mapped); unsupported for debloat");
    }
    // `metadata_csum` adds a crc32c to every directory block; editing a dirent
    // would invalidate it and the kernel rejects the block on read. Dirent-only
    // hiding is only safe without it. (`gdt_csum`/uninit_bg is fine — it only
    // checksums group descriptors, which we never touch; likewise flex_bg /
    // 64bit / htree add no per-directory-block checksum.)
    if ro_compat & RO_COMPAT_METADATA_CSUM != 0 {
        anyhow::bail!(
            "ext4 image uses metadata_csum; debloat would need directory-block checksum recomputation (unsupported)"
        );
    }
    // Encrypted or case-folded names can't be matched by byte comparison.
    if incompat & (INCOMPAT_ENCRYPT | INCOMPAT_CASEFOLD) != 0 {
        anyhow::bail!(
            "ext4 image uses encryption/casefold (incompat 0x{:x}); unsupported for debloat",
            incompat & (INCOMPAT_ENCRYPT | INCOMPAT_CASEFOLD)
        );
    }
    Ok(())
}

/// Recursively collect every entry path under `inode` into `out`, as
/// slash-prefixed absolute paths. Directories are emitted with a trailing
/// `/`. `depth` guards against pathologically deep or cyclic trees.
fn collect_paths<R: std::io::Read + std::io::Seek>(
    volume: &mut Ext4Volume<R>,
    inode: &Inode,
    prefix: &str,
    depth: usize,
    out: &mut Vec<String>,
) -> Result<()> {
    if depth > 64 {
        return Ok(());
    }
    let entries = inode
        .open_dir(volume)
        .with_context(|| format!("reading directory {prefix}/"))?;
    for (name, child_idx, file_type) in entries {
        if name == "." || name == ".." || name.is_empty() {
            continue;
        }
        let path = format!("{prefix}/{name}");
        let child = match volume.get_inode(child_idx) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if file_type == FT_DIR && child.is_dir() {
            out.push(format!("{path}/"));
            collect_paths(volume, &child, &path, depth + 1, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// List every file and directory path inside an ext4 partition image, each as
/// a leading-slash absolute path (directories suffixed with `/`). Returns an
/// error if the image is not a supported ext4 volume.
pub fn list_partition_paths(image_path: &Path) -> Result<Vec<String>> {
    let mut volume = open_ext4_volume(image_path)?;
    ensure_supported(&volume)?;
    let root = volume
        .root()
        .map_err(|e| anyhow::anyhow!("failed to read ext4 root inode: {e}"))?;
    let mut out = Vec::new();
    collect_paths(&mut volume, &root, "", 0, &mut out)?;
    out.sort();
    Ok(out)
}

/// Split an absolute ext4 path (`/system/app/Foo`) into `(parent_components,
/// final_name)`. Returns `None` for the root or a degenerate path.
fn split_parent_and_name(path: &str) -> Option<(Vec<String>, String)> {
    let trimmed = path.trim().trim_end_matches('/');
    let cleaned = trimmed.trim_start_matches('/');
    if cleaned.is_empty() {
        return None;
    }
    let mut comps: Vec<String> = cleaned.split('/').map(|s| s.to_string()).collect();
    if comps.iter().any(|c| c.is_empty() || c == "." || c == "..") {
        return None;
    }
    let name = comps.pop()?;
    Some((comps, name))
}

/// Rewrite `dir_data` (a directory inode's concatenated data blocks) so the
/// entry named `target` is hidden. Standard ext4 dirent removal: merge the
/// entry's `rec_len` into the preceding entry in the same block, or, when it
/// is the first entry in a block, zero its `inode` field. Returns `true` if
/// an entry was hidden.
///
/// Pure function over the byte buffer so it can be unit-tested without a real
/// filesystem. `block_size` must be the ext4 block size; dirents never span a
/// block boundary.
fn hide_dirent(dir_data: &mut [u8], block_size: usize, target: &str) -> bool {
    let target_bytes = target.as_bytes();
    let mut block_start = 0usize;
    while block_start < dir_data.len() {
        let block_end = (block_start + block_size).min(dir_data.len());
        let mut offset = block_start;
        let mut prev_offset: Option<usize> = None;
        while offset + 8 <= block_end {
            let rec_len = u16::from_le_bytes([dir_data[offset + 4], dir_data[offset + 5]]) as usize;
            if rec_len < 8 || offset + rec_len > block_end {
                break;
            }
            let inode = u32::from_le_bytes([
                dir_data[offset],
                dir_data[offset + 1],
                dir_data[offset + 2],
                dir_data[offset + 3],
            ]);
            let name_len = dir_data[offset + 6] as usize;
            if inode != 0 && offset + 8 + name_len <= block_end {
                let name = &dir_data[offset + 8..offset + 8 + name_len];
                if name == target_bytes {
                    match prev_offset {
                        Some(prev) => {
                            // Swallow this entry into the previous one.
                            let prev_rec =
                                u16::from_le_bytes([dir_data[prev + 4], dir_data[prev + 5]])
                                    as usize;
                            let merged = (prev_rec + rec_len) as u16;
                            dir_data[prev + 4..prev + 6].copy_from_slice(&merged.to_le_bytes());
                        }
                        None => {
                            // First entry in the block: zero the inode so the
                            // record is skipped, leaving rec_len intact.
                            dir_data[offset..offset + 4].copy_from_slice(&[0u8; 4]);
                        }
                    }
                    return true;
                }
            }
            prev_offset = Some(offset);
            offset += rec_len;
        }
        block_start += block_size;
    }
    false
}

/// Hide one absolute path inside `image_path` (an ext4 partition image).
/// Returns [`HideOutcome::NotFound`] for a missing/invalid path (caller
/// should ignore it) and [`HideOutcome::Removed`] when the image was
/// modified. Errors only on I/O or an unsupported ext4 layout.
pub fn hide_path(image_path: &Path, ext4_path: &str) -> Result<HideOutcome> {
    let Some((parent_comps, name)) = split_parent_and_name(ext4_path) else {
        return Ok(HideOutcome::NotFound);
    };

    let mut volume = open_ext4_volume(image_path)?;
    ensure_supported(&volume)?;

    let parent_refs: Vec<&str> = parent_comps.iter().map(|s| s.as_str()).collect();
    let parent = match lookup_inode_at_path(&mut volume, &parent_refs)? {
        Some(inode) if inode.is_dir() => inode,
        _ => return Ok(HideOutcome::NotFound),
    };

    let (mut content, extents) = parent
        .open_read_with_extents(&mut volume)
        .map_err(|e| anyhow::anyhow!("failed to read parent directory of {ext4_path}: {e}"))?;
    if extents.is_empty() {
        // Not extent-backed (e.g. inline-data directory): cannot write back.
        return Ok(HideOutcome::NotFound);
    }

    let block_size = volume.block_size as usize;
    if !hide_dirent(&mut content, block_size, &name) {
        return Ok(HideOutcome::NotFound);
    }

    write_via_extents(image_path, &content, &extents, volume.block_size)?;
    Ok(HideOutcome::Removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a one-block directory buffer of `[a, b, c]` linear dirents and a
    // trailing free record filling the block, matching ext4 layout.
    fn build_dir_block(block_size: usize, names: &[(&str, u32)]) -> Vec<u8> {
        let mut buf = vec![0u8; block_size];
        let mut off = 0usize;
        for (i, (name, inode)) in names.iter().enumerate() {
            let name_bytes = name.as_bytes();
            let base = 8 + name_bytes.len();
            let rec_len = if i == names.len() - 1 {
                block_size - off
            } else {
                base.div_ceil(4) * 4
            };
            buf[off..off + 4].copy_from_slice(&inode.to_le_bytes());
            buf[off + 4..off + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
            buf[off + 6] = name_bytes.len() as u8;
            buf[off + 7] = 1; // file_type: regular file
            buf[off + 8..off + 8 + name_bytes.len()].copy_from_slice(name_bytes);
            off += rec_len;
        }
        buf
    }

    fn entry_at<'a>(buf: &'a [u8], off: usize) -> (u32, u16, &'a [u8]) {
        let inode = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let rec_len = u16::from_le_bytes([buf[off + 4], buf[off + 5]]);
        let name_len = buf[off + 6] as usize;
        (inode, rec_len, &buf[off + 8..off + 8 + name_len])
    }

    #[test]
    fn hide_middle_entry_merges_into_previous() {
        let bs = 4096;
        let mut buf = build_dir_block(bs, &[("a", 11), ("bee", 12), ("c", 13)]);
        // Offsets: a@0 (rec 12), bee@12 (rec 12), c@24 (rec bs-24).
        assert!(hide_dirent(&mut buf, bs, "bee"));
        // `a` now spans over `bee` (12 + 12 = 24).
        let (inode_a, rec_a, name_a) = entry_at(&buf, 0);
        assert_eq!(inode_a, 11);
        assert_eq!(rec_a, 24);
        assert_eq!(name_a, b"a");
        // `c` still reachable at offset 24.
        let (inode_c, _, name_c) = entry_at(&buf, 24);
        assert_eq!(inode_c, 13);
        assert_eq!(name_c, b"c");
    }

    #[test]
    fn hide_first_entry_zeroes_inode() {
        let bs = 4096;
        let mut buf = build_dir_block(bs, &[("a", 11), ("b", 12)]);
        assert!(hide_dirent(&mut buf, bs, "a"));
        let (inode_a, rec_a, _) = entry_at(&buf, 0);
        assert_eq!(inode_a, 0, "first entry inode zeroed");
        assert_eq!(rec_a, 12, "first entry rec_len preserved");
        // `b` untouched.
        let (inode_b, _, name_b) = entry_at(&buf, 12);
        assert_eq!(inode_b, 12);
        assert_eq!(name_b, b"b");
    }

    #[test]
    fn hide_missing_entry_returns_false() {
        let bs = 4096;
        let mut buf = build_dir_block(bs, &[("a", 11), ("b", 12)]);
        let before = buf.clone();
        assert!(!hide_dirent(&mut buf, bs, "zzz"));
        assert_eq!(buf, before, "buffer unchanged when target absent");
    }

    /// Real-image round-trip, gated on `DYNOBOX_TEST_EXT4` pointing at a
    /// plain ext4 partition image (no metadata_csum). Copies it, lists paths,
    /// hides the first file entry, and asserts it disappears from a re-list.
    /// Skipped when the env var is unset so CI stays hermetic.
    #[test]
    fn hide_path_removes_entry_on_real_image() {
        let Ok(src) = std::env::var("DYNOBOX_TEST_EXT4") else {
            eprintln!("DYNOBOX_TEST_EXT4 unset; skipping real-image debloat test");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("test.img");
        std::fs::copy(&src, &img).expect("copy test ext4 image");

        let before = list_partition_paths(&img).expect("list before");
        assert!(!before.is_empty(), "image should have at least one entry");
        // Pick the first entry (file or directory) and hide it by its path
        // (directories are listed with a trailing slash; strip it for hiding).
        let listed = before[0].clone();
        let target = listed.trim_end_matches('/').to_string();

        assert_eq!(
            hide_path(&img, &target).unwrap(),
            HideOutcome::Removed,
            "target {target} should be hidden"
        );

        let after = list_partition_paths(&img).expect("list after");
        assert!(
            !after.iter().any(|p| p.trim_end_matches('/') == target),
            "{target} should be gone after hide"
        );

        // Hiding a nonexistent path is a no-op.
        assert_eq!(
            hide_path(&img, "/definitely/not/here").unwrap(),
            HideOutcome::NotFound
        );
    }

    /// Read-only lister, gated on `DYNOBOX_LIST_EXT4`. Prints every path in
    /// the image so an external harness can grep it (e.g. to confirm a
    /// debloated entry is gone). Skipped when the env var is unset.
    #[test]
    fn list_real_image_when_env_set() {
        let Ok(src) = std::env::var("DYNOBOX_LIST_EXT4") else {
            return;
        };
        let paths = list_partition_paths(std::path::Path::new(&src)).expect("list image");
        for p in &paths {
            println!("LISTED {p}");
        }
        eprintln!("total {} paths in {src}", paths.len());
    }

    #[test]
    fn split_parent_and_name_rejects_degenerate() {
        assert!(split_parent_and_name("/").is_none());
        assert!(split_parent_and_name("").is_none());
        assert!(split_parent_and_name("/a/../b").is_none());
        let (parent, name) = split_parent_and_name("/system/app/Foo/").unwrap();
        assert_eq!(parent, vec!["system", "app"]);
        assert_eq!(name, "Foo");
        let (parent, name) = split_parent_and_name("/top").unwrap();
        assert!(parent.is_empty());
        assert_eq!(name, "top");
    }
}
