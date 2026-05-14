use std::path::PathBuf;

pub const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616C4467;
pub const LP_METADATA_HEADER_MAGIC: u32 = 0x414C5030;
pub const LP_HEADER_FLAG_VIRTUAL_AB_DEVICE: u32 = 0x1;
pub const LP_PARTITION_ATTR_READONLY: u32 = 1 << 0;
pub const LP_SECTOR_SIZE: u64 = 512;
pub const LP_TARGET_TYPE_LINEAR: u32 = 0;
pub const LP_TARGET_TYPE_ZERO: u32 = 1;

/// Bytes that the super-image header occupies before the metadata
/// slots begin. Layout per AOSP `liblp/metadata_format.h`:
///
/// ```text
///   0x0000 .. 0x1000   reserved zero prefix (`LP_PARTITION_RESERVED_BYTES`)
///   0x1000 .. 0x2000   primary geometry
///   0x2000 .. 0x3000   backup geometry
///   0x3000 ..          metadata slot table (`metadata_max_size *
///                      metadata_slot_count * 2`)
/// ```
///
/// The data region starts immediately after the slot table, so the
/// first byte of the first dynamic partition lives at
/// `LP_PARTITION_RESERVED_BYTES + 2 * LP_METADATA_GEOMETRY_SIZE +
/// metadata_max_size * metadata_slot_count * 2`.
///
/// Both the repack planner (`dyno-super/src/repack.rs`) and the
/// metadata serialiser (`dyno-super/src/builder.rs`) consume this
/// constant so they stay in sync — they previously disagreed by
/// 4 KiB (`8192` vs the actual `12288`), which only matters when
/// the metadata slot table grows past ~1 MiB but corrupts the
/// super image silently when it does.
pub const LP_PARTITION_RESERVED_BYTES: u64 = 4096;
pub const LP_METADATA_GEOMETRY_SIZE: u64 = 4096;
pub const LP_SUPER_HEADER_BYTES: u64 = LP_PARTITION_RESERVED_BYTES + 2 * LP_METADATA_GEOMETRY_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperGeometry {
    pub metadata_max_size: u32,
    pub metadata_slot_count: u32,
    pub logical_block_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperBlockDevice {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperGroup {
    pub name: String,
    pub maximum_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperExtent {
    pub num_sectors: u64,
    pub target_type: u32,
    pub target_data: u64,
    pub target_source: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperPartition {
    pub name: String,
    pub attributes: u32,
    pub group_name: String,
    pub extents: Vec<SuperExtent>,
}

impl SuperPartition {
    pub fn slot_suffix(&self) -> Option<&'static str> {
        dynobox_core::ab_slot::slot_suffix(&self.name)
    }

    pub fn base_name(&self) -> String {
        dynobox_core::ab_slot::base_name(&self.name)
    }

    pub fn logical_size(&self) -> u64 {
        self.extents
            .iter()
            .map(|e| e.num_sectors * LP_SECTOR_SIZE)
            .sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperChunk {
    pub filename: String,
    pub path: PathBuf,
    pub start_sector: u64,
    pub num_sectors: u64,
    pub sector_size_bytes: u64,
    pub start_byte: u64,
    pub size_bytes: u64,
    pub relative_start_byte: u64,
}

impl SuperChunk {
    pub fn relative_end_byte(&self) -> u64 {
        self.relative_start_byte + self.size_bytes
    }
}

#[derive(Debug, Clone)]
pub struct SuperLayout {
    pub geometry: SuperGeometry,
    pub header_flags: u32,
    pub block_devices: Vec<SuperBlockDevice>,
    pub groups: Vec<SuperGroup>,
    pub partitions: Vec<SuperPartition>,
    pub chunks: Vec<SuperChunk>,
}

impl SuperLayout {
    pub fn super_name(&self) -> String {
        if let Some(dev) = self.block_devices.first() {
            dev.name.clone()
        } else {
            "super".to_string()
        }
    }

    pub fn dynamic_partition_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for partition in &self.partitions {
            if partition.logical_size() > 0 && partition.slot_suffix() != Some("b") {
                let base = partition.base_name();
                if !names.contains(&base) {
                    names.push(base);
                }
            }
        }
        names
    }

    pub fn find_partition(&self, name: &str) -> Option<&SuperPartition> {
        let normalized = name.to_lowercase();
        self.partitions.iter().find(|p| {
            p.name.to_lowercase() == normalized
                || (p.base_name().to_lowercase() == normalized && p.slot_suffix() != Some("b"))
        })
    }
}
