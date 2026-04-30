//! Minimal ext4 read-only navigator.
//!
//! Distilled subset of `imgkit_scuti::filesystem::ext4` covering only the
//! pieces dynobox needs for surgical byte patches inside an ext4 image
//! (volume open → directory walk → inode → extent mapping → block read).
//! The full upstream crate ships ext4 / erofs / f2fs / super extractors
//! and builders plus a CLI; pulling all of that in just to navigate
//! `vendor.img` to `/build.prop` is heavy. This file vendors ~900 lines
//! of upstream into one module so dynobox depends on nothing more than
//! `zerocopy` and `thiserror`.
//!
//! What the upstream copy was trimmed of:
//!   * extended attribute (`xattr`) parsing types
//!   * `VfsCapData` / `CapData` capability blob decoding
//!   * symlink helper (`is_symlink`) and unused `file_type::*` constants
//!     other than `CHECKSUM` (still consumed by directory parsing)
//!   * Chinese error messages (rewritten in English)
//!
//! Reference: <https://github.com/Kindness-Kismet/ImgKit-Scuti>
//! files `src/filesystem/ext4/{types,volume,file,directory,error}.rs`.

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use thiserror::Error;
use zerocopy::{FromZeros, Immutable, IntoBytes, KnownLayout, TryFromBytes};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum Ext4Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid magic: expected {expected:#x}, found {found:#x}")]
    Magic { expected: u16, found: u16 },
    #[error("inode not found: {0}")]
    InodeNotFound(u32),
    #[error("path not found: {0}")]
    PathNotFound(PathBuf),
    #[error("not a directory: {0}")]
    NotADirectory(PathBuf),
    #[error("invalid extent header")]
    InvalidExtentHeader,
    #[error("invalid extent")]
    InvalidExtent,
    #[error("invalid inode size: {size} exceeds maximum {max}")]
    InvalidInodeSize { size: u64, max: u64 },
    #[error("extent tree is too deep: depth {depth}")]
    ExtentTreeTooDeep { depth: u8 },
    #[error("detected extent tree cycle at block {block}")]
    ExtentCycleDetected { block: u64 },
}

pub type Result<T> = std::result::Result<T, Ext4Error>;

// ---------------------------------------------------------------------------
// On-disk structures and constants
// ---------------------------------------------------------------------------

pub const EXT4_SUPERBLOCK_MAGIC: u16 = 0xEF53;
pub const EXT4_EXTENT_HEADER_MAGIC: u16 = 0xF30A;

const EXT2_MIN_DESC_SIZE: u16 = 32;
const EXT2_MIN_DESC_SIZE_64BIT: u16 = 64;
const INCOMPAT_64BIT: u32 = 0x80;

pub mod inode_mode {
    pub const S_IFLNK: u16 = 0xA000;
    pub const S_IFREG: u16 = 0x8000;
    pub const S_IFDIR: u16 = 0x4000;
    pub const S_IFMT: u16 = 0xF000;

    pub const EXT4_EXTENTS_FL: u32 = 0x80000;
}

mod file_type {
    pub const CHECKSUM: u8 = 0xDE;
}

#[repr(C, packed)]
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Ext4Superblock {
    pub s_inodes_count: u32,
    pub s_blocks_count_lo: u32,
    pub s_r_blocks_count_lo: u32,
    pub s_free_blocks_count_lo: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_cluster_size: u32,
    pub s_blocks_per_group: u32,
    pub s_clusters_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: u32,
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
    pub s_reserved_gdt_blocks: u16,
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: u32,
    pub s_journal_dev: u32,
    pub s_last_orphan: u32,
    pub s_hash_seed: [u32; 4],
    pub s_def_hash_version: u8,
    pub s_jnl_backup_type: u8,
    pub s_desc_size: u16,
    pub s_default_mount_opts: u32,
    pub s_first_meta_bg: u32,
    pub s_mkfs_time: u32,
    pub s_jnl_blocks: [u32; 17],
    pub s_blocks_count_hi: u32,
    pub s_r_blocks_count_hi: u32,
    pub s_free_blocks_count_hi: u32,
    pub s_min_extra_isize: u16,
    pub s_want_extra_isize: u16,
    pub s_flags: u32,
    pub s_raid_stride: u16,
    pub s_mmp_interval: u16,
    pub s_mmp_block: u64,
    pub s_raid_stripe_width: u32,
    pub s_log_groups_per_flex: u8,
    pub s_checksum_type: u8,
    pub s_reserved_pad: u16,
    pub s_kbytes_written: u64,
    pub s_snapshot_inum: u32,
    pub s_snapshot_id: u32,
    pub s_snapshot_r_blocks_count: u64,
    pub s_snapshot_list: u32,
    pub s_error_count: u32,
    pub s_first_error_time: u32,
    pub s_first_error_ino: u32,
    pub s_first_error_block: u64,
    pub s_first_error_func: [u8; 32],
    pub s_first_error_line: u32,
    pub s_last_error_time: u32,
    pub s_last_error_ino: u32,
    pub s_last_error_line: u32,
    pub s_last_error_block: u64,
    pub s_last_error_func: [u8; 32],
    pub s_mount_opts: [u8; 64],
    pub s_usr_quota_inum: u32,
    pub s_grp_quota_inum: u32,
    pub s_overhead_blocks: u32,
    pub s_backup_bgs: [u32; 2],
    pub s_encrypt_algos: [u8; 4],
    pub s_encrypt_pw_salt: [u8; 16],
    pub s_lpf_ino: u32,
    pub s_prj_quota_inum: u32,
    pub s_checksum_seed: u32,
    pub s_reserved: [u32; 98],
    pub s_checksum: u32,
}

#[repr(C, packed)]
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy)]
#[allow(dead_code)]
struct Ext4GroupDescriptor32 {
    bg_block_bitmap_lo: u32,
    bg_inode_bitmap_lo: u32,
    bg_inode_table_lo: u32,
    bg_free_blocks_count_lo: u16,
    bg_free_inodes_count_lo: u16,
    bg_used_dirs_count_lo: u16,
    bg_flags: u16,
    bg_exclude_bitmap_lo: u32,
    bg_block_bitmap_csum_lo: u16,
    bg_inode_bitmap_csum_lo: u16,
    bg_itable_unused_lo: u16,
    bg_checksum: u16,
}

#[repr(C, packed)]
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Ext4GroupDescriptor {
    bg_block_bitmap_lo: u32,
    bg_inode_bitmap_lo: u32,
    bg_inode_table_lo: u32,
    bg_free_blocks_count_lo: u16,
    bg_free_inodes_count_lo: u16,
    bg_used_dirs_count_lo: u16,
    bg_flags: u16,
    bg_exclude_bitmap_lo: u32,
    bg_block_bitmap_csum_lo: u16,
    bg_inode_bitmap_csum_lo: u16,
    bg_itable_unused_lo: u16,
    bg_checksum: u16,
    bg_block_bitmap_hi: u32,
    bg_inode_bitmap_hi: u32,
    bg_inode_table_hi: u32,
    bg_free_blocks_count_hi: u16,
    bg_free_inodes_count_hi: u16,
    bg_used_dirs_count_hi: u16,
    bg_itable_unused_hi: u16,
    bg_exclude_bitmap_hi: u32,
    bg_block_bitmap_csum_hi: u16,
    bg_inode_bitmap_csum_hi: u16,
    bg_reserved: u32,
}

impl Ext4GroupDescriptor {
    fn bg_inode_table(&self) -> u64 {
        (self.bg_inode_table_hi as u64) << 32 | self.bg_inode_table_lo as u64
    }
}

impl From<Ext4GroupDescriptor32> for Ext4GroupDescriptor {
    fn from(g: Ext4GroupDescriptor32) -> Self {
        Ext4GroupDescriptor {
            bg_block_bitmap_lo: g.bg_block_bitmap_lo,
            bg_inode_bitmap_lo: g.bg_inode_bitmap_lo,
            bg_inode_table_lo: g.bg_inode_table_lo,
            bg_free_blocks_count_lo: g.bg_free_blocks_count_lo,
            bg_free_inodes_count_lo: g.bg_free_inodes_count_lo,
            bg_used_dirs_count_lo: g.bg_used_dirs_count_lo,
            bg_flags: g.bg_flags,
            bg_exclude_bitmap_lo: g.bg_exclude_bitmap_lo,
            bg_block_bitmap_csum_lo: g.bg_block_bitmap_csum_lo,
            bg_inode_bitmap_csum_lo: g.bg_inode_bitmap_csum_lo,
            bg_itable_unused_lo: g.bg_itable_unused_lo,
            bg_checksum: g.bg_checksum,
            bg_block_bitmap_hi: 0,
            bg_inode_bitmap_hi: 0,
            bg_inode_table_hi: 0,
            bg_free_blocks_count_hi: 0,
            bg_free_inodes_count_hi: 0,
            bg_used_dirs_count_hi: 0,
            bg_itable_unused_hi: 0,
            bg_exclude_bitmap_hi: 0,
            bg_block_bitmap_csum_hi: 0,
            bg_inode_bitmap_csum_hi: 0,
            bg_reserved: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Ext4Inode {
    pub i_mode: u16,
    pub i_uid_lo: u16,
    pub i_size_lo: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_gid_lo: u16,
    pub i_links_count: u16,
    pub i_blocks_lo: u32,
    pub i_flags: u32,
    pub osd1: u32,
    pub i_block: [u8; 60],
    pub i_generation: u32,
    pub i_file_acl_lo: u32,
    pub i_size_hi: u32,
    pub i_obso_faddr: u32,
    pub i_osd2_blocks_high: u16,
    pub i_file_acl_hi: u16,
    pub i_uid_hi: u16,
    pub i_gid_hi: u16,
    pub i_osd2_checksum_lo: u16,
    pub i_osd2_reserved: u16,
    pub i_extra_isize: u16,
    pub i_checksum_hi: u16,
    pub i_ctime_extra: u32,
    pub i_mtime_extra: u32,
    pub i_atime_extra: u32,
    pub i_crtime: u32,
    pub i_crtime_extra: u32,
    pub i_version_hi: u32,
    pub i_projid: u32,
    pub i_pad: [u8; 96],
}

impl Ext4Inode {
    fn i_size(&self) -> u64 {
        (self.i_size_hi as u64) << 32 | self.i_size_lo as u64
    }
}

#[repr(C, packed)]
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy)]
struct Ext4DirEntry2 {
    inode: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
}

#[repr(C, packed)]
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy)]
struct Ext4Extent {
    ee_block: u32,
    ee_len: u16,
    ee_start_hi: u16,
    ee_start_lo: u32,
}

impl Ext4Extent {
    fn ee_start(&self) -> u64 {
        (self.ee_start_hi as u64) << 32 | self.ee_start_lo as u64
    }
    fn is_unwritten(&self) -> bool {
        self.ee_len > 32768
    }
    fn get_len(&self) -> u16 {
        if self.is_unwritten() {
            self.ee_len - 32768
        } else {
            self.ee_len
        }
    }
}

#[repr(C, packed)]
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy)]
struct Ext4ExtentHeader {
    eh_magic: u16,
    eh_entries: u16,
    #[allow(dead_code)]
    eh_max: u16,
    eh_depth: u16,
    #[allow(dead_code)]
    eh_generation: u32,
}

#[repr(C, packed)]
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy)]
struct Ext4ExtentIdx {
    #[allow(dead_code)]
    ei_block: u32,
    ei_leaf_lo: u32,
    ei_leaf_hi: u16,
    #[allow(dead_code)]
    ei_unused: u16,
}

impl Ext4ExtentIdx {
    fn ei_leaf(&self) -> u64 {
        (self.ei_leaf_hi as u64) << 32 | self.ei_leaf_lo as u64
    }
}

// ---------------------------------------------------------------------------
// Volume / Inode
// ---------------------------------------------------------------------------

pub struct Ext4Volume<R: Read + Seek> {
    stream: R,
    superblock: Ext4Superblock,
    group_descriptors: Vec<Ext4GroupDescriptor>,
    pub block_size: u64,
}

#[derive(Clone)]
pub struct Inode {
    #[allow(dead_code)]
    inode_idx: u32,
    inode: Ext4Inode,
    #[allow(dead_code)]
    data: Vec<u8>,
}

impl<R: Read + Seek> Ext4Volume<R> {
    pub fn new(mut stream: R) -> Result<Self> {
        // Read superblock at offset 1024.
        stream.seek(SeekFrom::Start(1024))?;
        let mut superblock_bytes = [0u8; std::mem::size_of::<Ext4Superblock>()];
        stream.read_exact(&mut superblock_bytes)?;
        let superblock =
            Ext4Superblock::try_read_from_bytes(&superblock_bytes[..]).map_err(|_| {
                Ext4Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "failed to parse ext4 superblock",
                ))
            })?;

        if superblock.s_magic != EXT4_SUPERBLOCK_MAGIC {
            return Err(Ext4Error::Magic {
                expected: EXT4_SUPERBLOCK_MAGIC,
                found: superblock.s_magic,
            });
        }

        let shift = 10u32
            .checked_add(superblock.s_log_block_size)
            .ok_or_else(|| {
                Ext4Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid ext4 block size shift",
                ))
            })?;
        if shift >= 63 {
            return Err(Ext4Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ext4 block size shift out of range: {shift}"),
            )));
        }
        let block_size = 1u64 << shift;
        if !(1024..=65536).contains(&block_size) {
            return Err(Ext4Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ext4 block size out of supported range: {block_size}"),
            )));
        }

        let mut desc_size = superblock.s_desc_size;
        if desc_size == 0 {
            desc_size = if (superblock.s_feature_incompat & INCOMPAT_64BIT) == 0 {
                EXT2_MIN_DESC_SIZE
            } else {
                EXT2_MIN_DESC_SIZE_64BIT
            };
        }

        let group_desc_table_offset = (1024 / block_size + 1) * block_size;
        let num_groups = superblock
            .s_inodes_count
            .div_ceil(superblock.s_inodes_per_group);
        let mut group_descriptors = Vec::with_capacity(num_groups as usize);

        stream.seek(SeekFrom::Start(group_desc_table_offset))?;
        for i in 0..num_groups {
            let is_64bit = (superblock.s_feature_incompat & INCOMPAT_64BIT) != 0;
            if !is_64bit {
                let mut gd_bytes = vec![0u8; std::mem::size_of::<Ext4GroupDescriptor32>()];
                if stream.read_exact(&mut gd_bytes).is_err() {
                    break;
                }
                let gd32 =
                    Ext4GroupDescriptor32::try_read_from_bytes(&gd_bytes[..]).map_err(|_| {
                        Ext4Error::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("failed to parse 32-bit group descriptor {i}"),
                        ))
                    })?;
                group_descriptors.push(gd32.into());
            } else {
                let mut gd_bytes = vec![0u8; desc_size as usize];
                if stream.read_exact(&mut gd_bytes).is_err() {
                    break;
                }
                let gd = Ext4GroupDescriptor::try_read_from_bytes(&gd_bytes[..]).map_err(|_| {
                    Ext4Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("failed to parse 64-bit group descriptor {i}"),
                    ))
                })?;
                group_descriptors.push(gd);
            }
        }

        Ok(Self {
            stream,
            superblock,
            group_descriptors,
            block_size,
        })
    }

    fn read_block(&mut self, block_idx: u64, buf: &mut [u8]) -> Result<()> {
        self.stream
            .seek(SeekFrom::Start(block_idx * self.block_size))?;
        self.stream.read_exact(buf)?;
        Ok(())
    }

    /// Read `block_count` consecutive blocks starting at `start_block`
    /// into `buf` in a single seek + read. The caller is responsible for
    /// sizing `buf` to `block_count * block_size` bytes.
    ///
    /// Used by `Inode::open_read_with_extents` to read each extent run
    /// in one syscall instead of one read per 4 KiB block — a measurable
    /// win on large partitions where extents typically span hundreds of
    /// blocks each.
    fn read_blocks(&mut self, start_block: u64, buf: &mut [u8]) -> Result<()> {
        self.stream
            .seek(SeekFrom::Start(start_block * self.block_size))?;
        self.stream.read_exact(buf)?;
        Ok(())
    }

    pub fn get_inode(&mut self, inode_idx: u32) -> Result<Inode> {
        if inode_idx == 0 {
            return Err(Ext4Error::InodeNotFound(inode_idx));
        }

        let group_idx = (inode_idx - 1) / self.superblock.s_inodes_per_group;
        let inode_table_entry_idx = (inode_idx - 1) % self.superblock.s_inodes_per_group;

        if group_idx as usize >= self.group_descriptors.len() {
            return Err(Ext4Error::InodeNotFound(inode_idx));
        }

        let inode_table_offset =
            self.group_descriptors[group_idx as usize].bg_inode_table() * self.block_size;
        let inode_offset =
            inode_table_offset + inode_table_entry_idx as u64 * self.superblock.s_inode_size as u64;

        self.stream.seek(SeekFrom::Start(inode_offset))?;
        let mut inode_bytes = vec![0u8; self.superblock.s_inode_size as usize];
        self.stream.read_exact(&mut inode_bytes)?;
        let inode_struct = Ext4Inode::try_read_from_bytes(&inode_bytes[..]).map_err(|_| {
            Ext4Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse inode {inode_idx}"),
            ))
        })?;

        Ok(Inode {
            inode_idx,
            inode: inode_struct,
            data: inode_bytes,
        })
    }

    pub fn root(&mut self) -> Result<Inode> {
        self.get_inode(2)
    }
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        (self.inode.i_mode & inode_mode::S_IFMT) == inode_mode::S_IFDIR
    }

    pub fn is_file(&self) -> bool {
        (self.inode.i_mode & inode_mode::S_IFMT) == inode_mode::S_IFREG
    }

    /// Walk the extent tree of this inode and return one entry per extent
    /// as `(file_block_idx, disk_block_idx, block_count, is_unwritten)`.
    /// Used to map a file-relative byte offset back to the physical byte
    /// offset inside the partition image (e.g. surgical byte patches that
    /// must hit the live data block, not stale bytes elsewhere).
    pub fn extent_mapping<R: Read + Seek>(
        &self,
        volume: &mut Ext4Volume<R>,
    ) -> Result<Vec<(u64, u64, u64, bool)>> {
        if (self.inode.i_flags & inode_mode::EXT4_EXTENTS_FL) == 0 {
            return Ok(Vec::new());
        }
        let mut mapping = Vec::new();
        let mut visited_blocks = HashSet::new();
        self.parse_extents(
            volume,
            &self.inode.i_block,
            &mut mapping,
            0,
            &mut visited_blocks,
        )?;
        mapping.sort_by_key(|&(file_block_idx, _, _, _)| file_block_idx);
        Ok(mapping)
    }

    pub fn open_read<R: Read + Seek>(&self, volume: &mut Ext4Volume<R>) -> Result<Vec<u8>> {
        let (data, _) = self.open_read_with_extents(volume)?;
        Ok(data)
    }

    /// Like [`Inode::open_read`], but also returns the extent mapping
    /// produced by the same single tree walk. Callers that need both
    /// the file content and a way to write specific bytes back through
    /// the extent tree (e.g. [`crate::fuck_as`] / [`crate::vendor_spl`])
    /// can use this to avoid two redundant walks of the same inode.
    pub fn open_read_with_extents<R: Read + Seek>(
        &self,
        volume: &mut Ext4Volume<R>,
    ) -> Result<(Vec<u8>, Vec<(u64, u64, u64, bool)>)> {
        const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024;
        let file_size = self.inode.i_size();
        if file_size > MAX_FILE_SIZE {
            return Err(Ext4Error::InvalidInodeSize {
                size: file_size,
                max: MAX_FILE_SIZE,
            });
        }

        // Inline data path: small files store content directly in i_block.
        // No extent map exists, so we return an empty mapping.
        if (self.inode.i_flags & inode_mode::EXT4_EXTENTS_FL) == 0 {
            let size = usize::try_from(file_size).map_err(|_| Ext4Error::InvalidInodeSize {
                size: file_size,
                max: usize::MAX as u64,
            })?;
            let max_inline_size = self.inode.i_block.len();
            if size > max_inline_size {
                return Err(Ext4Error::InvalidInodeSize {
                    size: size as u64,
                    max: max_inline_size as u64,
                });
            }
            return Ok((self.inode.i_block[..size].to_vec(), Vec::new()));
        }

        // Extent mode: walk the tree once, then use the same mapping
        // both for the read pass and (returned) for the caller.
        let mapping = self.extent_mapping(volume)?;

        let file_size_usize =
            usize::try_from(file_size).map_err(|_| Ext4Error::InvalidInodeSize {
                size: file_size,
                max: usize::MAX as u64,
            })?;
        let mut data = Vec::with_capacity(file_size_usize);

        for &(file_block_idx, disk_block_idx, block_count, is_unwritten) in &mapping {
            let extent_start = file_block_idx.saturating_mul(volume.block_size);
            if extent_start >= file_size {
                break;
            }
            // Fill any hole between the previous extent end and this one.
            if extent_start > data.len() as u64 {
                let hole_size = (extent_start - data.len() as u64) as usize;
                data.resize(data.len() + hole_size, 0);
            }

            // Bytes still owed to the caller from the start of this
            // extent. Cap at `block_count * block_size` (the extent
            // covers no more than that on disk).
            let remaining_in_file = file_size.saturating_sub(data.len() as u64);
            let extent_byte_count = block_count.saturating_mul(volume.block_size);
            let to_read = remaining_in_file.min(extent_byte_count) as usize;
            if to_read == 0 {
                break;
            }

            if is_unwritten {
                // Unwritten extents read as zero; no disk read needed.
                data.resize(data.len() + to_read, 0);
                continue;
            }

            // Single batched read covering the whole extent run, padded
            // up to a block boundary so `read_exact` lands on a clean
            // block-aligned region. The trailing pad bytes are dropped
            // by `truncate(to_read)` below — they never appear in the
            // returned buffer.
            let aligned_read = (to_read as u64).div_ceil(volume.block_size) * volume.block_size;
            let aligned_read = aligned_read.min(extent_byte_count) as usize;
            let prev_len = data.len();
            data.resize(prev_len + aligned_read, 0);
            volume.read_blocks(disk_block_idx, &mut data[prev_len..prev_len + aligned_read])?;
            data.truncate(prev_len + to_read);
        }
        data.resize(file_size_usize, 0);
        Ok((data, mapping))
    }

    fn parse_extents<R: Read + Seek>(
        &self,
        volume: &mut Ext4Volume<R>,
        data: &[u8],
        mapping: &mut Vec<(u64, u64, u64, bool)>,
        depth: u8,
        visited_blocks: &mut HashSet<u64>,
    ) -> Result<()> {
        const MAX_EXTENT_TREE_DEPTH: u8 = 8;
        if depth > MAX_EXTENT_TREE_DEPTH {
            return Err(Ext4Error::ExtentTreeTooDeep { depth });
        }

        let (extent_header, entries_data) = Ext4ExtentHeader::try_ref_from_prefix(data)
            .map_err(|_| Ext4Error::InvalidExtentHeader)?;

        if extent_header.eh_magic != EXT4_EXTENT_HEADER_MAGIC {
            return Err(Ext4Error::Magic {
                expected: EXT4_EXTENT_HEADER_MAGIC,
                found: extent_header.eh_magic,
            });
        }

        if extent_header.eh_depth == 0 {
            let (extents, _) = <[Ext4Extent]>::try_ref_from_prefix_with_elems(
                entries_data,
                extent_header.eh_entries as usize,
            )
            .map_err(|_| Ext4Error::InvalidExtent)?;
            for extent in extents {
                mapping.push((
                    extent.ee_block as u64,
                    extent.ee_start(),
                    extent.get_len() as u64,
                    extent.is_unwritten(),
                ));
            }
        } else {
            let (indices, _) = <[Ext4ExtentIdx]>::try_ref_from_prefix_with_elems(
                entries_data,
                extent_header.eh_entries as usize,
            )
            .map_err(|_| Ext4Error::InvalidExtent)?;
            for idx in indices {
                let child_block = idx.ei_leaf();
                if !visited_blocks.insert(child_block) {
                    return Err(Ext4Error::ExtentCycleDetected { block: child_block });
                }
                let mut block_data = vec![0u8; volume.block_size as usize];
                volume.read_block(child_block, &mut block_data)?;
                self.parse_extents(volume, &block_data, mapping, depth + 1, visited_blocks)?;
            }
        }
        Ok(())
    }

    /// Read all directory entries under this inode.
    /// Returns `Vec<(filename, child_inode_idx, file_type)>`.
    pub fn open_dir<R: Read + Seek>(
        &self,
        volume: &mut Ext4Volume<R>,
    ) -> Result<Vec<(String, u32, u8)>> {
        if !self.is_dir() {
            return Err(Ext4Error::NotADirectory(PathBuf::new()));
        }

        let data = self.open_read(volume)?;
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset + std::mem::size_of::<Ext4DirEntry2>() <= data.len() {
            if let Ok((dirent, _)) = Ext4DirEntry2::try_ref_from_prefix(&data[offset..]) {
                if dirent.rec_len == 0 {
                    break;
                }
                if offset + dirent.rec_len as usize > data.len() {
                    break;
                }
                if dirent.inode != 0 && dirent.file_type != file_type::CHECKSUM {
                    if offset + 8 + dirent.name_len as usize > data.len() {
                        break;
                    }
                    let name = String::from_utf8_lossy(
                        &data[offset + 8..offset + 8 + dirent.name_len as usize],
                    )
                    .to_string();
                    entries.push((name, dirent.inode, dirent.file_type));
                }
                offset += dirent.rec_len as usize;
            } else {
                break;
            }
        }
        Ok(entries)
    }
}
