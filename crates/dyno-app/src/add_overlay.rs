//! `--add-overlay`: insert static RRO APKs into an ext4 partition image
//! (default `product.img:/overlay/`) **without mounting** it.
//!
//! Android scans `/product/overlay/**` at boot — [`OverlayScanner::scanDir`]
//! recurses into subdirectories — and enables static
//! (`<overlay android:isStatic="true">`) overlays automatically. A preinstalled
//! overlay needs no signature match unless the target package declares an
//! `<overlayable>`, so inserting the APK inside the partition image is all a
//! mount-less patcher has to do.
//!
//! This module is the allocation inverse of [`crate::debloat`]'s dirent-only
//! hide, and the same safety argument applies: the partition is mounted
//! read-only under dm-verity, the kernel never runs `e2fsck` on it, and the
//! caller regenerates the dm-verity hash tree afterwards. Unlike debloat it
//! must allocate: a free inode per file, contiguous data blocks (one inline
//! extent per file) from the largest free run, an inode plus one directory
//! block when the target directory itself has to be created, and — when a
//! directory's trailing dirent spare is too small for the new names — one or
//! more directory blocks appended to that directory's extent list.
//!
//! Metadata written: inode/block bitmaps, group-descriptor free counts,
//! `used_dirs_count` and `uninit_bg` flags (plus the bitmap padding e2fsck
//! expects), directory link counts (a new subdirectory adds one to its parent),
//! the legacy `gdt_csum` group-descriptor checksum (crc16 over
//! `uuid + u32le(group) + descriptor[..0x1E]`), and the superblock free
//! counters. New inodes copy the inline-xattr block and timestamps of an
//! existing regular file in the target directory — or of the target directory
//! itself when it is freshly created — so inserted files and directories
//! inherit the SELinux label (`u:object_r:system_file:s0` for
//! `/product/overlay`).
//!
//! Hard feature gate (unsupported layouts are rejected, never mutated):
//! require `EXTENTS`; reject `metadata_csum` (inode, directory-block, bitmap
//! and superblock crc32c would have to be recomputed), `encrypt`/`casefold`,
//! indexed (htree) directories receiving entries, and directories that would
//! need more than four extents.
//!
//! [`OverlayScanner::scanDir`]: https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/com/android/internal/content/om/OverlayScanner.java

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

// ---------------------------------------------------------------------------
// on-disk constants
// ---------------------------------------------------------------------------

const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_SIZE: usize = 1024;
const EXT4_SUPERBLOCK_MAGIC: u16 = 0xEF53;

const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;
const INCOMPAT_CASEFOLD: u32 = 0x2_0000;
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

const GD_FREE_BLOCKS_LO: usize = 0x0C;
const GD_FREE_INODES_LO: usize = 0x0E;
const GD_USED_DIRS_LO: usize = 0x10;
const GD_FLAGS: usize = 0x12;
const GD_ITABLE_UNUSED_LO: usize = 0x1C;
const GD_CHECKSUM: usize = 0x1E;
const GD_INODE_UNINIT: u16 = 0x0001;
const GD_BLOCK_UNINIT: u16 = 0x0002;

const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;

const INODE_MODE: usize = 0x00;
const INODE_SIZE_LO: usize = 0x04;
const INODE_LINKS: usize = 0x1A;
const INODE_BLOCKS_LO: usize = 0x1C;
const INODE_FLAGS: usize = 0x20;
const INODE_BLOCK: usize = 0x28;
const INODE_FILE_ACL_LO: usize = 0x68;
const INODE_SIZE_HI: usize = 0x6C;
const INODE_EXTRA_ISIZE: usize = 0x80;
const INODE_GOOD_OLD_SIZE: usize = 128;

const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXT4_INDEX_FL: u32 = 0x0000_1000;

const EXTENT_MAGIC: u16 = 0xF30A;
const EXTENT_HEADER_LEN: usize = 12;
const EXTENT_ENTRY_LEN: usize = 12;
const EXTENT_INLINE_MAX: usize = 4;

const XATTR_IBODY_MAGIC: u32 = 0xEA02_0000;

const FT_REG_FILE: u8 = 1;
const FT_DIR: u8 = 2;

const DIRENT_HEADER: usize = 8;

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

/// Default directory new overlays are written to (relative to the image root).
/// Created by [`insert_files`] when missing.
pub const DEFAULT_OVERLAY_DIR: &str = "overlay";

/// One file to insert into the image.
#[derive(Debug, Clone, Copy)]
pub struct OverlayFile<'a> {
    /// File name that appears inside `dir` (must not contain `/`).
    pub name: &'a str,
    /// Raw file contents.
    pub bytes: &'a [u8],
}

/// Result of inserting one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertedFile {
    pub name: String,
    pub inode: u32,
    pub blocks: u32,
    pub size: u64,
}

/// Insert `files` into `dir` (slash-separated, relative to the image root) of
/// the ext4 partition image at `image_path`, creating the final directory
/// component when it does not exist yet. The image is modified in place.
///
/// All space, inode, directory-capacity and layout preconditions are checked
/// before the first byte is written; only I/O failures can leave a partially
/// updated image.
pub fn insert_files(
    image_path: &Path,
    dir: &str,
    files: &[OverlayFile<'_>],
) -> Result<Vec<InsertedFile>> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    for file in files {
        validate_name(file.name)?;
    }
    let mut layout = Layout::open(image_path)?;
    layout.ensure_supported()?;
    layout.plan_and_insert(dir, files)
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." || name.len() > 255 {
        bail!("invalid file name `{name}` for an inserted file");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// little-endian helpers
// ---------------------------------------------------------------------------

fn le16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn le32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn put16(bytes: &mut [u8], off: usize, value: u16) {
    bytes[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// crc16 (gdt_csum group-descriptor checksum, e2fsprogs variant)
// ---------------------------------------------------------------------------

const CRC16_TABLE: [u16; 256] = build_crc16_table();

const fn build_crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

fn crc16(mut crc: u16, bytes: &[u8]) -> u16 {
    for byte in bytes {
        crc = (crc >> 8) ^ CRC16_TABLE[((crc ^ u16::from(*byte)) & 0xFF) as usize];
    }
    crc
}

// ---------------------------------------------------------------------------
// extents / dirents
// ---------------------------------------------------------------------------

/// (logical_block, length_blocks, physical_start)
type Extent = (u32, u32, u64);

fn inode_extents(inode: &[u8]) -> Result<Vec<Extent>> {
    let magic = le16(inode, INODE_BLOCK);
    if magic != EXTENT_MAGIC {
        bail!("inode is not extent-based (magic 0x{magic:04x})");
    }
    let entries = le16(inode, INODE_BLOCK + 2) as usize;
    let depth = le16(inode, INODE_BLOCK + 6);
    if depth != 0 {
        bail!("inode uses an extent index tree (depth {depth}); unsupported");
    }
    if entries > EXTENT_INLINE_MAX {
        bail!("inode declares {entries} extents; unsupported");
    }
    let mut out = Vec::with_capacity(entries);
    for index in 0..entries {
        let off = INODE_BLOCK + EXTENT_HEADER_LEN + EXTENT_ENTRY_LEN * index;
        let logical = le32(inode, off);
        let length = le16(inode, off + 4) & 0x7FFF;
        let start = (u64::from(le16(inode, off + 6)) << 32) | u64::from(le32(inode, off + 8));
        out.push((logical, u32::from(length), start));
    }
    Ok(out)
}

fn set_inode_extents(inode: &mut [u8], extents: &[Extent]) -> Result<()> {
    if extents.len() > EXTENT_INLINE_MAX {
        bail!("cannot encode {} extents inline", extents.len());
    }
    inode[INODE_BLOCK..INODE_BLOCK + 60].fill(0);
    put16(inode, INODE_BLOCK, EXTENT_MAGIC);
    put16(inode, INODE_BLOCK + 2, extents.len() as u16);
    put16(inode, INODE_BLOCK + 4, EXTENT_INLINE_MAX as u16);
    put16(inode, INODE_BLOCK + 6, 0);
    for (index, (logical, length, start)) in extents.iter().enumerate() {
        let off = INODE_BLOCK + EXTENT_HEADER_LEN + EXTENT_ENTRY_LEN * index;
        put32(inode, off, *logical);
        put16(
            inode,
            off + 4,
            u16::try_from(*length).context("extent length overflow")?,
        );
        put16(inode, off + 6, ((*start >> 32) & 0xFFFF) as u16);
        put32(inode, off + 8, (*start & 0xFFFF_FFFF) as u32);
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Dirent {
    name: Vec<u8>,
    inode: u32,
    file_type: u8,
    offset: usize,
    rec_len: u16,
}

fn parse_dirents(data: &[u8], block_size: usize) -> Vec<Dirent> {
    let mut out = Vec::new();
    let mut block_start = 0usize;
    while block_start < data.len() {
        let block_end = (block_start + block_size).min(data.len());
        let mut off = block_start;
        while off + DIRENT_HEADER <= block_end {
            let inode = le32(data, off);
            let rec_len = le16(data, off + 4);
            let name_len = data[off + 6] as usize;
            if rec_len < DIRENT_HEADER as u16 || off + rec_len as usize > block_end {
                break;
            }
            if inode != 0 && name_len != 0 && off + DIRENT_HEADER + name_len <= block_end {
                out.push(Dirent {
                    name: data[off + DIRENT_HEADER..off + DIRENT_HEADER + name_len].to_vec(),
                    inode,
                    file_type: data[off + 7],
                    offset: off,
                    rec_len,
                });
            }
            off += rec_len as usize;
        }
        block_start += block_size;
    }
    out
}

fn dirent_nominal_len(name_len: usize) -> u16 {
    ((DIRENT_HEADER + name_len + 3) & !3) as u16
}

fn encode_dirent(name: &[u8], inode: u32, rec_len: u16, file_type: u8) -> Vec<u8> {
    let mut buf = vec![0u8; rec_len as usize];
    put32(&mut buf, 0, inode);
    put16(&mut buf, 4, rec_len);
    buf[6] = name.len() as u8;
    buf[7] = file_type;
    buf[DIRENT_HEADER..DIRENT_HEADER + name.len()].copy_from_slice(name);
    buf
}

/// Trailing free bytes of a directory's last record (where a new entry can be
/// carved in without allocating a block).
fn trailing_spare(dirents: &[Dirent]) -> usize {
    dirents
        .last()
        .map(|d| usize::from(d.rec_len) - usize::from(dirent_nominal_len(d.name.len())))
        .unwrap_or(0)
}

/// Blocks a directory needs for `need` bytes of new entries: none when the
/// trailing spare covers them, else whole appended blocks (each holds one
/// header less than a full block).
fn dir_extra_blocks(last_spare: usize, need: usize, block_size: usize) -> u64 {
    if need <= last_spare {
        0
    } else {
        need.div_ceil(block_size - DIRENT_HEADER) as u64
    }
}

/// Physical block backing `logical` within an extent map.
fn extent_physical(extents: &[Extent], logical: u64) -> Option<u64> {
    extents.iter().find_map(|(start, len, phys)| {
        let start = u64::from(*start);
        let len = u64::from(*len);
        (logical >= start && logical < start + len).then_some(phys + (logical - start))
    })
}

// ---------------------------------------------------------------------------
// allocation bookkeeping
// ---------------------------------------------------------------------------

/// Blocks, inodes and directories marked used by one insertion pass. All
/// blocks come from a single contiguous run reserved up front, so the image
/// only has to satisfy one free-extent precondition.
struct Alloc {
    /// Next unallocated block of the reserved run.
    cursor: u64,
    group_blocks: BTreeMap<u32, u64>,
    group_inodes: BTreeMap<u32, u64>,
    group_dirs: BTreeMap<u32, u64>,
}

impl Alloc {
    fn new(run_start: u64) -> Self {
        Self {
            cursor: run_start,
            group_blocks: BTreeMap::new(),
            group_inodes: BTreeMap::new(),
            group_dirs: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// image layout
// ---------------------------------------------------------------------------

struct Layout {
    file: File,
    block_size: usize,
    inode_size: usize,
    desc_size: usize,
    blocks_per_group: u32,
    inodes_per_group: u32,
    blocks_count: u64,
    inodes_count: u32,
    groups: u32,
    uuid: [u8; 16],
    incompat: u32,
    ro_compat: u32,
    first_ino: u32,
    has_64bit: bool,
    gds: Vec<u8>,
    gd_table_off: u64,
    superblock: Vec<u8>,
}

impl Layout {
    fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening partition image {}", path.display()))?;
        let mut superblock = vec![0u8; EXT4_SUPERBLOCK_SIZE];
        file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))?;
        file.read_exact(&mut superblock)?;
        if le16(&superblock, 0x38) != EXT4_SUPERBLOCK_MAGIC {
            bail!("{} is not an ext4 image", path.display());
        }
        let block_size = 1024usize
            .checked_shl(le32(&superblock, 0x18))
            .context("invalid ext4 block size")?;
        let inode_size = usize::from(le16(&superblock, 0x58)).max(INODE_GOOD_OLD_SIZE);
        let first_data_block = u64::from(le32(&superblock, 0x14));
        let blocks_per_group = le32(&superblock, 0x20);
        let inodes_per_group = le32(&superblock, 0x28);
        let blocks_count = u64::from(le32(&superblock, 0x04));
        let inodes_count = le32(&superblock, 0x00);
        let incompat = le32(&superblock, 0x60);
        let ro_compat = le32(&superblock, 0x64);
        let has_64bit = incompat & INCOMPAT_64BIT != 0;
        let desc_size = if has_64bit {
            usize::from(le16(&superblock, 0xFE)).max(64)
        } else {
            32
        };
        if blocks_per_group == 0 || inodes_per_group == 0 || block_size == 0 {
            bail!("invalid ext4 geometry in the superblock");
        }
        let groups = blocks_count
            .saturating_sub(first_data_block)
            .div_ceil(u64::from(blocks_per_group)) as u32;
        let gd_table_off = (first_data_block + 1)
            .checked_mul(block_size as u64)
            .context("group descriptor table offset overflow")?;
        let mut gds = vec![0u8; desc_size * groups as usize];
        file.seek(SeekFrom::Start(gd_table_off))?;
        file.read_exact(&mut gds)?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&superblock[0x68..0x78]);
        Ok(Self {
            file,
            block_size,
            inode_size,
            desc_size,
            blocks_per_group,
            inodes_per_group,
            blocks_count,
            inodes_count,
            groups,
            uuid,
            incompat,
            ro_compat,
            first_ino: le32(&superblock, 0x54).max(11),
            has_64bit,
            gds,
            gd_table_off,
            superblock,
        })
    }

    fn ensure_supported(&self) -> Result<()> {
        if self.incompat & INCOMPAT_EXTENTS == 0 {
            bail!("ext4 image is not extent-based (block-mapped); unsupported for --add-overlay");
        }
        // metadata_csum adds crc32c to inodes, directory blocks, bitmaps and
        // the superblock; every one of them changes here and is not recomputed.
        if self.ro_compat & RO_COMPAT_METADATA_CSUM != 0 {
            bail!(
                "ext4 image uses metadata_csum; --add-overlay would need crc32c recomputation (unsupported)"
            );
        }
        if self.incompat & (INCOMPAT_ENCRYPT | INCOMPAT_CASEFOLD) != 0 {
            bail!("ext4 image uses encryption/casefold; unsupported for --add-overlay");
        }
        Ok(())
    }

    // -- group descriptors ------------------------------------------------

    fn gd_u16(&self, group: u32, off: usize) -> u16 {
        let base = group as usize * self.desc_size + off;
        u16::from_le_bytes([self.gds[base], self.gds[base + 1]])
    }

    fn gd_u32(&self, group: u32, off: usize) -> u32 {
        le32(&self.gds, group as usize * self.desc_size + off)
    }

    fn gd_ptr(&self, group: u32, lo_off: usize, hi_off: usize) -> u64 {
        let lo = u64::from(self.gd_u32(group, lo_off));
        if self.has_64bit {
            lo | (u64::from(self.gd_u32(group, hi_off)) << 32)
        } else {
            lo
        }
    }

    fn set_gd_u16(&mut self, group: u32, off: usize, value: u16) {
        let base = group as usize * self.desc_size + off;
        self.gds[base..base + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn inode_bitmap_block(&self, group: u32) -> u64 {
        self.gd_ptr(group, 0x04, 0x24)
    }

    fn block_bitmap_block(&self, group: u32) -> u64 {
        self.gd_ptr(group, 0x00, 0x20)
    }

    fn inode_table_block(&self, group: u32) -> u64 {
        self.gd_ptr(group, 0x08, 0x28)
    }

    fn gd_checksum(&self, group: u32) -> u16 {
        // gdt_csum (e2fsprogs 1.47): crc16(~0, uuid) -> crc16(., u32le(group))
        // -> crc16(., descriptor[..0x1E]).
        let crc = crc16(0xFFFF, &self.uuid);
        let crc = crc16(crc, &group.to_le_bytes());
        let base = group as usize * self.desc_size;
        crc16(crc, &self.gds[base..base + GD_CHECKSUM])
    }

    fn write_gd_table(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(self.gd_table_off))?;
        self.file.write_all(&self.gds)?;
        Ok(())
    }

    // -- raw I/O ----------------------------------------------------------

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)?;
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)?;
        Ok(())
    }

    fn read_block(&mut self, block: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.block_size];
        self.read_at(block * self.block_size as u64, &mut buf)?;
        Ok(buf)
    }

    fn write_block(&mut self, block: u64, data: &[u8]) -> Result<()> {
        debug_assert_eq!(data.len(), self.block_size);
        self.write_at(block * self.block_size as u64, data)
    }

    // -- inodes -----------------------------------------------------------

    fn inode_offset(&self, inode: u32) -> u64 {
        let group = (inode - 1) / self.inodes_per_group;
        let index = (inode - 1) % self.inodes_per_group;
        self.inode_table_block(group) * self.block_size as u64
            + u64::from(index) * self.inode_size as u64
    }

    fn read_inode(&mut self, inode: u32) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.inode_size];
        let off = self.inode_offset(inode);
        self.read_at(off, &mut buf)?;
        Ok(buf)
    }

    fn write_inode(&mut self, inode: u32, data: &[u8]) -> Result<()> {
        let off = self.inode_offset(inode);
        self.write_at(off, data)
    }

    // -- bitmaps ----------------------------------------------------------

    fn set_bitmap_bit(&mut self, bitmap_block: u64, bit: u32) -> Result<()> {
        let byte_off = bitmap_block * self.block_size as u64 + u64::from(bit / 8);
        let mut byte = [0u8; 1];
        self.read_at(byte_off, &mut byte)?;
        byte[0] |= 1 << (bit % 8);
        self.write_at(byte_off, &byte)
    }

    // -- planning ---------------------------------------------------------

    /// Largest in-filesystem run of free blocks: (length, start).
    fn largest_free_run(&mut self) -> Result<(u64, u64)> {
        let mut best = (0u64, 0u64);
        for group in 0..self.groups {
            let bitmap = self.block_bitmap_block(group);
            let data = self.read_block(bitmap)?;
            let group_start = u64::from(group) * u64::from(self.blocks_per_group);
            let mut run = 0u64;
            let mut start = 0u64;
            for index in 0..u64::from(self.blocks_per_group) {
                let block = group_start + index;
                if block >= self.blocks_count {
                    break;
                }
                if data[(index / 8) as usize] & (1 << (index % 8)) == 0 {
                    if run == 0 {
                        start = block;
                    }
                    run += 1;
                } else {
                    if run > best.0 {
                        best = (run, start);
                    }
                    run = 0;
                }
            }
            if run > best.0 {
                best = (run, start);
            }
        }
        Ok(best)
    }

    /// First `count` free inode numbers (at or above `s_first_ino`).
    fn free_inodes(&mut self, count: usize) -> Result<Vec<u32>> {
        let mut out = Vec::with_capacity(count);
        'groups: for group in 0..self.groups {
            let bitmap = self.inode_bitmap_block(group);
            let data = self.read_block(bitmap)?;
            for index in 0..self.inodes_per_group {
                let inode = group * self.inodes_per_group + index + 1;
                if inode > self.inodes_count || inode < self.first_ino {
                    continue;
                }
                if data[(index / 8) as usize] & (1 << (index % 8)) == 0 {
                    out.push(inode);
                    if out.len() >= count {
                        break 'groups;
                    }
                }
            }
        }
        if out.len() < count {
            bail!(
                "not enough free inodes on the image ({} of {count} available)",
                out.len()
            );
        }
        Ok(out)
    }

    /// Split `dir` into its parent directory inode and its final component.
    /// The parent must already exist as a directory.
    fn split_target_dir(&mut self, dir: &str) -> Result<(u32, String)> {
        let components: Vec<&str> = dir.split('/').filter(|c| !c.is_empty()).collect();
        let (name, parents) = components
            .split_last()
            .context("the overlay directory path must not be empty")?;
        if name.is_empty() || *name == "." || *name == ".." || name.len() > 255 {
            bail!("invalid directory name `{name}` in `{dir}`");
        }
        let mut inode = 2u32; // root
        for component in parents {
            let data = self.read_inode_data(inode)?;
            let dirents = parse_dirents(&data, self.block_size);
            let hit = dirents
                .iter()
                .find(|entry| entry.name == component.as_bytes())
                .with_context(|| format!("directory `{dir}` not found in the image"))?;
            if hit.file_type != FT_DIR {
                bail!("`{component}` in `{dir}` is not a directory");
            }
            inode = hit.inode;
        }
        Ok((inode, (*name).to_string()))
    }

    /// Full contents of a depth-0 extent file/directory, truncated to i_size.
    fn read_inode_data(&mut self, inode: u32) -> Result<Vec<u8>> {
        let raw = self.read_inode(inode)?;
        let size =
            u64::from(le32(&raw, INODE_SIZE_LO)) | (u64::from(le32(&raw, INODE_SIZE_HI)) << 32);
        let mut out = Vec::new();
        for (_, length, start) in inode_extents(&raw)? {
            for block in start..start + u64::from(length) {
                out.extend_from_slice(&self.read_block(block)?);
            }
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// Check that an inode can serve as the layout template for a new inode:
    /// it must carry its xattrs inline (the SELinux label lives in the
    /// `system.data`/`security.selinux` ibody area) and none externally.
    fn validate_inode_template(&self, raw: &[u8]) -> Result<usize> {
        let extra_isize = usize::from(le16(raw, INODE_EXTRA_ISIZE));
        if extra_isize == 0 || INODE_GOOD_OLD_SIZE + extra_isize + 4 > self.inode_size {
            bail!("template inode has no inline xattr area; unsupported");
        }
        if le32(raw, INODE_GOOD_OLD_SIZE + extra_isize) != XATTR_IBODY_MAGIC {
            bail!("template inode has no inline xattr block; unsupported");
        }
        if le32(raw, INODE_FILE_ACL_LO) != 0 {
            bail!("template inode stores xattrs externally; unsupported");
        }
        Ok(extra_isize)
    }

    /// Layout source for the new inodes: the first usable regular file of the
    /// target directory, else the directory inode itself, else the same for
    /// the parent directory.
    fn inode_template(
        &mut self,
        dir_inode: Option<u32>,
        dir_dirents: &[Dirent],
        parent_inode: u32,
        parent_dirents: &[Dirent],
    ) -> Result<(Vec<u8>, usize)> {
        let first_ino = self.first_ino;
        let mut candidates: Vec<u32> = Vec::new();
        if let Some(inode) = dir_inode {
            candidates.extend(
                dir_dirents
                    .iter()
                    .filter(|d| d.file_type == FT_REG_FILE && d.inode >= first_ino)
                    .map(|d| d.inode),
            );
            candidates.push(inode);
        }
        candidates.extend(
            parent_dirents
                .iter()
                .filter(|d| d.file_type == FT_REG_FILE && d.inode >= first_ino)
                .map(|d| d.inode),
        );
        candidates.push(parent_inode);

        let mut last_error = None;
        for inode in candidates {
            let Ok(raw) = self.read_inode(inode) else {
                continue;
            };
            match self.validate_inode_template(&raw) {
                Ok(extra_isize) => return Ok((raw, extra_isize)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("no inode with an inline xattr block to copy the layout from")
        }))
    }

    // -- mutation ---------------------------------------------------------

    fn plan_and_insert(
        &mut self,
        dir: &str,
        files: &[OverlayFile<'_>],
    ) -> Result<Vec<InsertedFile>> {
        let block_size = self.block_size;

        // 1. Parent directory (must exist) and the final component.
        let (parent_inode, dir_name) = self.split_target_dir(dir)?;
        let parent_raw = self.read_inode(parent_inode)?;
        let parent_extents = inode_extents(&parent_raw)?;
        let parent_dirents = {
            let data = self.read_inode_data(parent_inode)?;
            parse_dirents(&data, block_size)
        };

        // 2. Target directory: read its shape, or plan to create it.
        let (dir_inode, dir_dirents) = match parent_dirents
            .iter()
            .find(|d| d.name == dir_name.as_bytes())
        {
            Some(hit) => {
                if hit.file_type != FT_DIR {
                    bail!("`{dir}` exists in the image but is not a directory");
                }
                let raw = self.read_inode(hit.inode)?;
                if le16(&raw, INODE_MODE) & S_IFMT != S_IFDIR {
                    bail!("`{dir}` exists in the image but is not a directory");
                }
                if le32(&raw, INODE_FLAGS) & EXT4_INDEX_FL != 0 {
                    bail!("directory `{dir}` is htree-indexed; unsupported for --add-overlay");
                }
                let data = self.read_inode_data(hit.inode)?;
                (Some(hit.inode), parse_dirents(&data, block_size))
            }
            None => {
                if le32(&parent_raw, INODE_FLAGS) & EXT4_INDEX_FL != 0 {
                    bail!(
                        "parent directory of `{dir}` is htree-indexed; unsupported for --add-overlay"
                    );
                }
                // The parent is cloned into the new directory's inode, so it
                // must carry an inline xattr block (the SELinux label).
                self.validate_inode_template(&parent_raw).with_context(|| {
                    format!(
                        "creating `{dir}` needs its parent directory to carry an inline xattr block"
                    )
                })?;
                (None, Vec::new())
            }
        };
        let creating = dir_inode.is_none();

        // 3. Reject collisions before touching anything.
        for (index, file) in files.iter().enumerate() {
            if dir_dirents.iter().any(|d| d.name == file.name.as_bytes()) {
                bail!("`{}` already exists in `{dir}`", file.name);
            }
            if files[..index].iter().any(|other| other.name == file.name) {
                bail!("duplicate file name `{}` in the insert list", file.name);
            }
        }

        // 4. Directory capacity: the target takes the file entries (a fresh
        //    directory has only `.`/`..`), the parent takes the new name.
        let files_need: usize = files
            .iter()
            .map(|f| usize::from(dirent_nominal_len(f.name.len())))
            .sum();
        let dir_spare = if creating {
            block_size
                - usize::from(dirent_nominal_len(1))  // "."
                - usize::from(dirent_nominal_len(2)) // ".."
        } else {
            trailing_spare(&dir_dirents)
        };
        let dir_extra = dir_extra_blocks(dir_spare, files_need, block_size);
        // A directory that is created here starts with exactly one block.
        let dir_extent_count = if let Some(inode) = dir_inode {
            inode_extents(&self.read_inode(inode)?)?.len()
        } else {
            1
        };
        if dir_extent_count + dir_extra as usize > EXTENT_INLINE_MAX {
            bail!(
                "directory `{dir}` would need {} extents (> {EXTENT_INLINE_MAX}); unsupported",
                dir_extent_count + dir_extra as usize
            );
        }
        let parent_extra = if creating {
            dir_extra_blocks(
                trailing_spare(&parent_dirents),
                usize::from(dirent_nominal_len(dir_name.len())),
                block_size,
            )
        } else {
            0
        };
        if creating && parent_extents.len() + parent_extra as usize > EXTENT_INLINE_MAX {
            bail!(
                "parent directory of `{dir}` would need {} extents (> {EXTENT_INLINE_MAX}); unsupported",
                parent_extents.len() + parent_extra as usize
            );
        }

        // 5. Space and inode capacity, validated before any write.
        let payload_blocks: u64 = files
            .iter()
            .map(|f| (f.bytes.len() as u64).div_ceil(block_size as u64))
            .sum();
        let wanted = payload_blocks + dir_extra + parent_extra + u64::from(creating);
        let (run_len, run_start) = self.largest_free_run()?;
        if run_len < wanted {
            bail!("not enough contiguous free space for {wanted} block(s) ({run_len} available)");
        }
        self.free_inodes(files.len() + usize::from(creating))?;

        // 6. Inode layout template (inline xattr block with the directory's
        //    SELinux label).
        let (template, extra_isize) =
            self.inode_template(dir_inode, &dir_dirents, parent_inode, &parent_dirents)?;

        // ---- preconditions checked; mutate ----
        let mut alloc = Alloc::new(run_start);
        let dir_inode = match dir_inode {
            Some(inode) => inode,
            None => self.create_dir(&mut alloc, parent_inode, &dir_name)?,
        };

        let mut inserted = Vec::with_capacity(files.len());
        for file in files {
            let inode = self.take_inode(&mut alloc)?;
            let blocks = (file.bytes.len() as u64).div_ceil(block_size as u64) as u32;
            let start = self.take_blocks(&mut alloc, u64::from(blocks))?;
            let mut data = file.bytes.to_vec();
            data.resize(blocks as usize * block_size, 0);
            self.write_at(start * block_size as u64, &data)?;

            let mut new_inode = template.clone();
            put16(&mut new_inode, INODE_MODE, S_IFREG | 0o644);
            put32(
                &mut new_inode,
                INODE_SIZE_LO,
                (file.bytes.len() & 0xFFFF_FFFF) as u32,
            );
            put32(
                &mut new_inode,
                INODE_SIZE_HI,
                (file.bytes.len() >> 32) as u32,
            );
            put32(
                &mut new_inode,
                INODE_BLOCKS_LO,
                blocks * (block_size as u32 / 512),
            );
            put32(&mut new_inode, INODE_FLAGS, EXT4_EXTENTS_FL);
            put16(&mut new_inode, INODE_LINKS, 1);
            put32(&mut new_inode, INODE_FILE_ACL_LO, 0);
            put16(&mut new_inode, INODE_EXTRA_ISIZE, extra_isize as u16);
            set_inode_extents(&mut new_inode, &[(0, blocks, start)])?;
            self.write_inode(inode, &new_inode)?;

            inserted.push(InsertedFile {
                name: file.name.to_string(),
                inode,
                blocks,
                size: file.bytes.len() as u64,
            });
        }

        // 7. Directory entries for the inserted files.
        let entries: Vec<(Vec<u8>, u32, u8)> = inserted
            .iter()
            .map(|file| (file.name.clone().into_bytes(), file.inode, FT_REG_FILE))
            .collect();
        self.add_entries(dir_inode, &entries, &mut alloc)?;

        // 8. Accounting.
        self.refresh_groups(&alloc)?;
        Ok(inserted)
    }

    /// Create `name` as an empty directory inside `parent_inode`: one data
    /// block holding `.`/`..`, an inode cloned from the parent (inline xattr
    /// block, so the SELinux label matches) and one more link on the parent.
    fn create_dir(&mut self, alloc: &mut Alloc, parent_inode: u32, name: &str) -> Result<u32> {
        let block_size = self.block_size;
        let inode = self.take_inode(alloc)?;
        let block = self.take_blocks(alloc, 1)?;

        let mut data = vec![0u8; block_size];
        data[..12].copy_from_slice(&encode_dirent(b".", inode, 12, FT_DIR));
        data[12..].copy_from_slice(&encode_dirent(
            b"..",
            parent_inode,
            (block_size - 12) as u16,
            FT_DIR,
        ));
        self.write_block(block, &data)?;

        let mut raw = self.read_inode(parent_inode)?;
        let permissions = le16(&raw, INODE_MODE) & 0o7777;
        put16(&mut raw, INODE_MODE, S_IFDIR | permissions);
        put32(&mut raw, INODE_SIZE_LO, block_size as u32);
        put32(&mut raw, INODE_SIZE_HI, 0);
        put32(&mut raw, INODE_BLOCKS_LO, (block_size / 512) as u32);
        put32(&mut raw, INODE_FLAGS, EXT4_EXTENTS_FL);
        put16(&mut raw, INODE_LINKS, 2);
        put32(&mut raw, INODE_FILE_ACL_LO, 0);
        set_inode_extents(&mut raw, &[(0, 1, block)])?;
        self.write_inode(inode, &raw)?;

        self.add_entries(
            parent_inode,
            &[(name.as_bytes().to_vec(), inode, FT_DIR)],
            alloc,
        )?;
        let mut parent_raw = self.read_inode(parent_inode)?;
        let links = le16(&parent_raw, INODE_LINKS).saturating_add(1);
        put16(&mut parent_raw, INODE_LINKS, links);
        self.write_inode(parent_inode, &parent_raw)?;

        let group = (inode - 1) / self.inodes_per_group;
        *alloc.group_dirs.entry(group).or_default() += 1;
        Ok(inode)
    }

    /// Append directory entries to `dir_inode`: carve them out of the last
    /// record's trailing spare when they fit, else append one or more whole
    /// blocks to the directory's extent list.
    fn add_entries(
        &mut self,
        dir_inode: u32,
        entries: &[(Vec<u8>, u32, u8)],
        alloc: &mut Alloc,
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let block_size = self.block_size;
        let raw = self.read_inode(dir_inode)?;
        if le32(&raw, INODE_FLAGS) & EXT4_INDEX_FL != 0 {
            bail!("directory is htree-indexed; unsupported for --add-overlay");
        }
        let extents = inode_extents(&raw)?;
        let size =
            u64::from(le32(&raw, INODE_SIZE_LO)) | (u64::from(le32(&raw, INODE_SIZE_HI)) << 32);
        let data = self.read_inode_data(dir_inode)?;
        let dirents = parse_dirents(&data, block_size);
        let need: usize = entries
            .iter()
            .map(|(name, _, _)| usize::from(dirent_nominal_len(name.len())))
            .sum();
        let spare = trailing_spare(&dirents);

        if need <= spare {
            let last = dirents.last().context("directory has no entries")?;
            let mut data = data.clone();
            put16(
                &mut data,
                last.offset + 4,
                dirent_nominal_len(last.name.len()),
            );
            let mut cursor = last.offset + usize::from(last.rec_len) - spare;
            let mut consumed = 0usize;
            for (index, (name, inode, file_type)) in entries.iter().enumerate() {
                let nominal = usize::from(dirent_nominal_len(name.len()));
                let rec_len = if index + 1 == entries.len() {
                    (spare - consumed) as u16
                } else {
                    nominal as u16
                };
                let encoded = encode_dirent(name, *inode, rec_len, *file_type);
                data[cursor..cursor + encoded.len()].copy_from_slice(&encoded);
                cursor += encoded.len();
                consumed += nominal;
            }
            let logical = (last.offset / block_size) as u64;
            let physical = extent_physical(&extents, logical)
                .context("directory extent map does not cover the entry block")?;
            self.write_block(
                physical,
                &data[last.offset - (last.offset % block_size)..][..block_size],
            )?;
            return Ok(());
        }

        let grow_blocks = need.div_ceil(block_size - DIRENT_HEADER) as u64;
        if extents.len() + grow_blocks as usize > EXTENT_INLINE_MAX {
            bail!(
                "directory would need {} extents (> {EXTENT_INLINE_MAX}); unsupported",
                extents.len() + grow_blocks as usize
            );
        }
        let mut pending: Vec<u8> = Vec::with_capacity(need);
        for (name, inode, file_type) in entries {
            pending.extend_from_slice(&encode_dirent(
                name,
                *inode,
                dirent_nominal_len(name.len()),
                *file_type,
            ));
        }
        let capacity = block_size - DIRENT_HEADER;
        let mut new_extents = extents.clone();
        let mut cursor = 0usize;
        let mut logical = size / block_size as u64;
        while cursor < pending.len() {
            let take = capacity.min(pending.len() - cursor);
            let mut block = pending[cursor..cursor + take].to_vec();
            block.resize(block_size, 0);
            // trailing free record covering the rest of the block
            put32(&mut block, take, 0);
            put16(&mut block, take + 4, (block_size - take) as u16);
            let target = self.take_blocks(alloc, 1)?;
            self.write_block(target, &block)?;
            new_extents.push((logical as u32, 1, target));
            logical += 1;
            cursor += take;
        }
        let new_size = size + grow_blocks * block_size as u64;
        let mut new_raw = raw.clone();
        put32(&mut new_raw, INODE_SIZE_LO, (new_size & 0xFFFF_FFFF) as u32);
        put32(&mut new_raw, INODE_SIZE_HI, (new_size >> 32) as u32);
        put32(
            &mut new_raw,
            INODE_BLOCKS_LO,
            le32(&raw, INODE_BLOCKS_LO) + grow_blocks as u32 * (block_size as u32 / 512),
        );
        set_inode_extents(&mut new_raw, &new_extents)?;
        self.write_inode(dir_inode, &new_raw)?;
        Ok(())
    }

    /// Mark `count` blocks used starting at the allocator cursor.
    fn take_blocks(&mut self, alloc: &mut Alloc, count: u64) -> Result<u64> {
        let start = alloc.cursor;
        for block in start..start + count {
            let group = (block / u64::from(self.blocks_per_group)) as u32;
            let bit = (block % u64::from(self.blocks_per_group)) as u32;
            let bitmap = self.block_bitmap_block(group);
            self.set_bitmap_bit(bitmap, bit)?;
            *alloc.group_blocks.entry(group).or_default() += 1;
        }
        alloc.cursor += count;
        Ok(start)
    }

    /// Mark the next free inode used.
    fn take_inode(&mut self, alloc: &mut Alloc) -> Result<u32> {
        let inode = self.free_inodes(1)?[0];
        let group = (inode - 1) / self.inodes_per_group;
        let bit = (inode - 1) % self.inodes_per_group;
        let bitmap = self.inode_bitmap_block(group);
        self.set_bitmap_bit(bitmap, bit)?;
        *alloc.group_inodes.entry(group).or_default() += 1;
        Ok(inode)
    }

    fn refresh_groups(&mut self, alloc: &Alloc) -> Result<()> {
        for (&group, &allocated) in &alloc.group_blocks {
            let old = u64::from(self.gd_u16(group, GD_FREE_BLOCKS_LO));
            self.set_gd_u16(
                group,
                GD_FREE_BLOCKS_LO,
                old.saturating_sub(allocated) as u16,
            );
            let flags = self.gd_u16(group, GD_FLAGS);
            if flags & GD_BLOCK_UNINIT != 0 {
                self.set_gd_u16(group, GD_FLAGS, flags & !GD_BLOCK_UNINIT);
                self.set_block_bitmap_padding(group)?;
            }
        }

        for (&group, &created) in &alloc.group_dirs {
            let old = u64::from(self.gd_u16(group, GD_USED_DIRS_LO));
            self.set_gd_u16(group, GD_USED_DIRS_LO, old.saturating_add(created) as u16);
        }

        for &group in alloc.group_inodes.keys() {
            let bitmap = self.inode_bitmap_block(group);
            let data = self.read_block(bitmap)?;
            let mut used = 0u64;
            let mut highest = -1i64;
            for index in 0..self.inodes_per_group {
                if data[(index / 8) as usize] & (1 << (index % 8)) != 0 {
                    used += 1;
                    highest = i64::from(index);
                }
            }
            let free = u64::from(self.inodes_per_group) - used;
            self.set_gd_u16(group, GD_FREE_INODES_LO, free as u16);
            let unused = u64::from(self.inodes_per_group) - (highest + 1) as u64;
            self.set_gd_u16(group, GD_ITABLE_UNUSED_LO, unused as u16);

            let flags = self.gd_u16(group, GD_FLAGS);
            if flags & GD_INODE_UNINIT != 0 {
                self.set_inode_bitmap_padding(group)?;
                self.set_gd_u16(group, GD_FLAGS, flags & !GD_INODE_UNINIT);
            }
        }

        for group in 0..self.groups {
            let checksum = self.gd_checksum(group);
            self.set_gd_u16(group, GD_CHECKSUM, checksum);
        }
        self.write_gd_table()?;

        // Superblock free counters (no superblock checksum without metadata_csum).
        let free_blocks = u64::from(le32(&self.superblock, 0x0C))
            | if self.has_64bit {
                u64::from(le32(&self.superblock, 0x158)) << 32
            } else {
                0
            };
        let free_inodes = u64::from(le32(&self.superblock, 0x10));
        let allocated_blocks: u64 = alloc.group_blocks.values().sum();
        let allocated_inodes: u64 = alloc.group_inodes.values().sum();
        let free_blocks = free_blocks.saturating_sub(allocated_blocks);
        let free_inodes = free_inodes.saturating_sub(allocated_inodes);
        put32(
            &mut self.superblock,
            0x0C,
            (free_blocks & 0xFFFF_FFFF) as u32,
        );
        if self.has_64bit {
            put32(&mut self.superblock, 0x158, (free_blocks >> 32) as u32);
        }
        put32(
            &mut self.superblock,
            0x10,
            (free_inodes & 0xFFFF_FFFF) as u32,
        );
        let superblock = self.superblock.clone();
        self.write_at(EXT4_SUPERBLOCK_OFFSET, &superblock)?;
        self.file.flush()?;
        Ok(())
    }

    /// Mark the bitmap bits past the real inodes/blocks of a group as used —
    /// the padding convention e2fsck expects once an uninitialized group's
    /// bitmap becomes authoritative.
    fn set_inode_bitmap_padding(&mut self, group: u32) -> Result<()> {
        let bitmap = self.inode_bitmap_block(group);
        let mut data = self.read_block(bitmap)?;
        for bit in self.inodes_per_group as usize..self.block_size * 8 {
            data[bit / 8] |= 1 << (bit % 8);
        }
        self.write_block(bitmap, &data)
    }

    fn set_block_bitmap_padding(&mut self, group: u32) -> Result<()> {
        let bitmap = self.block_bitmap_block(group);
        let mut data = self.read_block(bitmap)?;
        let group_start = u64::from(group) * u64::from(self.blocks_per_group);
        let in_group = self.blocks_count.saturating_sub(group_start);
        let start = in_group.min(u64::from(self.blocks_per_group)) as usize;
        for bit in start..self.block_size * 8 {
            data[bit / 8] |= 1 << (bit % 8);
        }
        self.write_block(bitmap, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_matches_known_check_values() {
        assert_eq!(crc16(0xFFFF, b"123456789"), 0x4B37);
        assert_eq!(crc16(0x0000, b"123456789"), 0xBB3D);
    }

    #[test]
    fn dirent_nominal_length_is_word_aligned() {
        assert_eq!(dirent_nominal_len(1), 12);
        assert_eq!(dirent_nominal_len(4), 12);
        assert_eq!(dirent_nominal_len(5), 16);
    }

    #[test]
    fn dir_extra_blocks_uses_trailing_spare() {
        assert_eq!(dir_extra_blocks(4072, 24, 4096), 0);
        assert_eq!(dir_extra_blocks(12, 24, 4096), 1);
        assert_eq!(dir_extra_blocks(12, 4088 * 2, 4096), 2);
    }

    #[test]
    fn extent_roundtrip() {
        let mut inode = vec![0u8; 256];
        let extents = vec![(0u32, 3u32, 0x1_0000_0000u64), (3, 1, 525_447)];
        set_inode_extents(&mut inode, &extents).unwrap();
        assert_eq!(inode_extents(&inode).unwrap(), extents);
    }

    #[test]
    fn extent_physical_lookup() {
        let extents = vec![(0u32, 2u32, 100u64), (2, 3, 500)];
        assert_eq!(extent_physical(&extents, 0), Some(100));
        assert_eq!(extent_physical(&extents, 1), Some(101));
        assert_eq!(extent_physical(&extents, 4), Some(502));
        assert_eq!(extent_physical(&extents, 5), None);
    }

    #[test]
    fn dirent_parse_and_encode_roundtrip() {
        let block_size = 4096;
        let mut block = vec![0u8; block_size];
        let dotdot = encode_dirent(b"..", 2, 12, FT_DIR);
        let file = encode_dirent(b"file.apk", 481, (block_size - 12) as u16, FT_REG_FILE);
        block[..12].copy_from_slice(&dotdot);
        block[12..].copy_from_slice(&file);
        let parsed = parse_dirents(&block, block_size);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].name, b"file.apk");
        assert_eq!(parsed[1].inode, 481);
        assert_eq!(parsed[1].rec_len, (block_size - 12) as u16);
    }

    #[test]
    fn insert_rejects_bad_names() {
        let dummy = Path::new("does-not-exist.img");
        assert!(
            insert_files(
                dummy,
                "overlay",
                &[OverlayFile {
                    name: "a/b",
                    bytes: b"x"
                }]
            )
            .is_err()
        );
        assert!(
            insert_files(
                dummy,
                "overlay",
                &[OverlayFile {
                    name: "..",
                    bytes: b"x"
                }]
            )
            .is_err()
        );
    }

    /// Real-image round trip: copies `DYNOBOX_TEST_ADD_OVERLAY_IMG`, inserts a
    /// payload into the existing `overlay` directory, one into a freshly
    /// created `overlay/dynobox-test` directory and one more into the now
    /// existing created directory, then reads all back through
    /// [`crate::ext4_helpers`]. Skipped when the env var is unset so CI stays
    /// hermetic.
    #[test]
    fn insert_files_on_real_image_when_env_set() {
        let Ok(src) = std::env::var("DYNOBOX_TEST_ADD_OVERLAY_IMG") else {
            eprintln!("DYNOBOX_TEST_ADD_OVERLAY_IMG unset; skipping real-image add-overlay test");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("product.img");
        std::fs::copy(&src, &img).expect("copy test ext4 image");

        let payload_a = vec![0x50u8; 9000];
        let payload_b = vec![0x51u8; 2_500_000];
        let payload_c = vec![0x52u8; 6000];

        let first = insert_files(
            &img,
            DEFAULT_OVERLAY_DIR,
            &[OverlayFile {
                name: "test-a.apk",
                bytes: &payload_a,
            }],
        )
        .expect("insert into stock overlay directory");
        assert_eq!(first.len(), 1);
        assert!(first[0].blocks >= 3);

        // Second call creates `overlay/dynobox-test`, third one reuses it.
        let second = insert_files(
            &img,
            "overlay/dynobox-test",
            &[OverlayFile {
                name: "test-b.apk",
                bytes: &payload_b,
            }],
        )
        .expect("insert into new directory");
        assert_eq!(second.len(), 1);

        let third = insert_files(
            &img,
            "overlay/dynobox-test",
            &[OverlayFile {
                name: "test-c.apk",
                bytes: &payload_c,
            }],
        )
        .expect("insert into existing directory");
        assert_eq!(third.len(), 1);

        let mut volume = crate::ext4_helpers::open_ext4_volume(&img).expect("open");
        let overlay_dir = crate::ext4_helpers::lookup_inode_at_path(&mut volume, &["overlay"])
            .expect("lookup overlay dir")
            .expect("overlay directory exists");
        assert!(overlay_dir.is_dir());
        let created_dir =
            crate::ext4_helpers::lookup_inode_at_path(&mut volume, &["overlay", "dynobox-test"])
                .expect("lookup created dir")
                .expect("created directory exists");
        assert!(created_dir.is_dir());
        let files: [(&[&str], &Vec<u8>); 3] = [
            (&["overlay", "test-a.apk"], &payload_a),
            (&["overlay", "dynobox-test", "test-b.apk"], &payload_b),
            (&["overlay", "dynobox-test", "test-c.apk"], &payload_c),
        ];
        for (path, payload) in files {
            let inode = crate::ext4_helpers::lookup_inode_at_path(&mut volume, path)
                .expect("lookup")
                .expect("file exists");
            let data = inode.open_read(&mut volume).expect("read");
            assert_eq!(data.len(), payload.len());
            assert_eq!(data, *payload);
        }
    }
}
