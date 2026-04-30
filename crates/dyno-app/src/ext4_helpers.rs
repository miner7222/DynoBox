//! Anyhow-flavoured wrappers around `ext4_reader`.
//!
//! `vendor_spl` and `fuck_as` both walk an ext4 image to a known path,
//! then either read its data or rewrite specific bytes through the
//! inode's extent map. Each previously carried its own copies of these
//! helpers; this module is the canonical home.
//!
//! The deliberate split is:
//!
//! * `ext4_reader` — minimal read-only navigator, plain `thiserror`
//!   surface, vendored from `imgkit_scuti`. Fine to call directly when a
//!   caller wants to handle `Ext4Error` precisely.
//! * `ext4_helpers` — dynobox-flavoured wrappers that lift those errors
//!   into `anyhow::Result` with image-path context, plus the surgical
//!   write-back primitives (`write_via_extents`, `map_file_offset_to_disk`)
//!   that vendor_spl and fuck_as share.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::ext4_reader::{Ext4Volume, Inode};

/// Open `image_path` as an ext4 volume backed by a buffered file reader.
pub fn open_ext4_volume(image_path: &Path) -> Result<Ext4Volume<BufReader<File>>> {
    let file = File::open(image_path).with_context(|| {
        format!(
            "Failed to open {} for ext4 navigation",
            image_path.display()
        )
    })?;
    Ext4Volume::new(BufReader::new(file)).map_err(|e| {
        anyhow!(
            "Failed to parse ext4 superblock on {}: {e}",
            image_path.display()
        )
    })
}

/// Walk an absolute path under the ext4 root and return the matching
/// inode, or `None` if any component is missing.
///
/// `components` is a series of name components (no leading slash); for
/// `/system/framework/framework.jar` pass
/// `&["system", "framework", "framework.jar"]`.
pub fn lookup_inode_at_path<R: Read + Seek>(
    volume: &mut Ext4Volume<R>,
    components: &[&str],
) -> Result<Option<Inode>> {
    let mut current = volume
        .root()
        .map_err(|e| anyhow!("Failed to read ext4 root inode: {e}"))?;
    for name in components {
        if !current.is_dir() {
            return Ok(None);
        }
        let entries = current
            .open_dir(volume)
            .map_err(|e| anyhow!("Failed to read directory while resolving {:?}: {e}", name))?;
        let next_idx = entries
            .into_iter()
            .find(|(entry_name, _, _)| entry_name == name)
            .map(|(_, idx, _)| idx);
        let Some(idx) = next_idx else {
            return Ok(None);
        };
        current = volume
            .get_inode(idx)
            .map_err(|e| anyhow!("Failed to read inode {} for {:?}: {e}", idx, name))?;
    }
    Ok(Some(current))
}

/// Map a file-relative byte offset to the absolute on-disk byte offset
/// using an `(file_block_idx, disk_block_idx, block_count, is_unwritten)`
/// extent table. Returns `None` if the offset falls into a hole or an
/// `is_unwritten` (logically-zero) extent — in either case there's no
/// concrete disk byte to patch.
pub fn map_file_offset_to_disk(
    extents: &[(u64, u64, u64, bool)],
    file_offset: u64,
    block_size: u64,
) -> Option<u64> {
    let block_index = file_offset / block_size;
    let intra_block = file_offset % block_size;
    for &(file_block, disk_block, count, is_unwritten) in extents {
        if block_index >= file_block && block_index < file_block + count {
            if is_unwritten {
                return None;
            }
            let disk_block_for_offset = disk_block + (block_index - file_block);
            return Some(disk_block_for_offset * block_size + intra_block);
        }
    }
    None
}

/// Write a fully-buffered file's worth of bytes back into the underlying
/// partition image, hitting each extent in turn. The buffer is laid out
/// in file-order (the same order `Inode::open_read` returns it), so for
/// each extent the matching slice is copied to its disk-block range.
///
/// Errors out if any extent is `is_unwritten` — writing through unwritten
/// extents would silently allocate new on-disk blocks, which we are not
/// equipped to do correctly.
pub fn write_via_extents(
    image_path: &Path,
    buffer: &[u8],
    extents: &[(u64, u64, u64, bool)],
    block_size: u64,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .with_context(|| {
            format!(
                "Failed to open {} for extent write-back",
                image_path.display()
            )
        })?;
    for &(file_block_idx, disk_block_idx, block_count, is_unwritten) in extents {
        if is_unwritten {
            return Err(anyhow!(
                "{} has an unwritten extent at file_block {}; writing through unwritten extents is unsupported",
                image_path.display(),
                file_block_idx
            ));
        }
        let extent_file_byte = file_block_idx.saturating_mul(block_size);
        let extent_byte_count = block_count.saturating_mul(block_size);
        if extent_file_byte >= buffer.len() as u64 {
            // Extent is past the buffer's tail (alignment padding); skip.
            continue;
        }
        let buf_start = extent_file_byte as usize;
        let buf_end = std::cmp::min(buf_start + extent_byte_count as usize, buffer.len());
        let disk_byte = disk_block_idx.saturating_mul(block_size);
        file.seek(SeekFrom::Start(disk_byte))?;
        file.write_all(&buffer[buf_start..buf_end])?;
    }
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_file_offset_to_disk_basic() {
        // Single extent: file blocks 0..4 → disk blocks 100..104, 4 KiB
        // per block. File offset 0 → disk byte 100*4096 = 409600. File
        // offset 5000 → disk byte 100*4096 + 5000 - 4096 wraps into
        // block 1 of disk = 101*4096 + (5000-4096) = 414704.
        let extents = vec![(0u64, 100u64, 4u64, false)];
        assert_eq!(map_file_offset_to_disk(&extents, 0, 4096), Some(409600));
        assert_eq!(
            map_file_offset_to_disk(&extents, 5000, 4096),
            Some(101 * 4096 + (5000 - 4096))
        );
    }

    #[test]
    fn map_file_offset_to_disk_returns_none_in_hole() {
        let extents = vec![(0u64, 100u64, 1u64, false), (5u64, 200u64, 1u64, false)];
        // File block 1..4 are unmapped (hole) → None.
        assert_eq!(map_file_offset_to_disk(&extents, 4096, 4096), None);
        assert_eq!(
            map_file_offset_to_disk(&extents, 5 * 4096, 4096),
            Some(200 * 4096)
        );
    }

    #[test]
    fn map_file_offset_to_disk_returns_none_for_unwritten() {
        let extents = vec![(0u64, 100u64, 4u64, true)];
        assert_eq!(map_file_offset_to_disk(&extents, 0, 4096), None);
    }
}
