use std::path::PathBuf;

pub const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616C4467;
pub const LP_METADATA_HEADER_MAGIC: u32 = 0x414C5030;
pub const LP_HEADER_FLAG_VIRTUAL_AB_DEVICE: u32 = 0x1;
pub const LP_PARTITION_ATTR_READONLY: u32 = 1 << 0;
pub const LP_SECTOR_SIZE: u64 = 512;
pub const LP_TARGET_TYPE_LINEAR: u32 = 0;
pub const LP_TARGET_TYPE_ZERO: u32 = 1;

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
        let lowered = self.name.to_lowercase();
        if lowered.ends_with("_a") {
            Some("a")
        } else if lowered.ends_with("_b") {
            Some("b")
        } else {
            None
        }
    }

    pub fn base_name(&self) -> String {
        if self.slot_suffix().is_some() {
            self.name[..self.name.len() - 2].to_string()
        } else {
            self.name.clone()
        }
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
