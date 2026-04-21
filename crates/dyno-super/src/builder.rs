use sha2::{Digest, Sha256};
use zerocopy::{Immutable, IntoBytes};

use crate::metadata::*;
use dynobox_core::error::{DynoError, Result};

// Re-defining the binary structures exactly as in C++ for zerocopy
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Debug, Clone, Copy)]
pub struct LpMetadataGeometryRaw {
    pub magic: u32,
    pub struct_size: u32,
    pub checksum: [u8; 32],
    pub metadata_max_size: u32,
    pub metadata_slot_count: u32,
    pub logical_block_size: u32,
}

#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Debug, Clone, Copy)]
pub struct LpMetadataTableDescriptorRaw {
    pub offset: u32,
    pub num_entries: u32,
    pub entry_size: u32,
}

#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Debug, Clone, Copy)]
pub struct LpMetadataHeaderRaw {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub header_size: u32,
    pub header_checksum: [u8; 32],
    pub tables_size: u32,
    pub tables_checksum: [u8; 32],
    pub partitions: LpMetadataTableDescriptorRaw,
    pub extents: LpMetadataTableDescriptorRaw,
    pub groups: LpMetadataTableDescriptorRaw,
    pub block_devices: LpMetadataTableDescriptorRaw,
    pub flags: u32,
    pub reserved: [u8; 124],
}

#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Debug, Clone, Copy)]
pub struct LpMetadataPartitionRaw {
    pub name: [u8; 36],
    pub attributes: u32,
    pub first_extent_index: u32,
    pub num_extents: u32,
    pub group_index: u32,
}

#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Debug, Clone, Copy)]
pub struct LpMetadataExtentRaw {
    pub num_sectors: u64,
    pub target_type: u32,
    pub target_data: u64,
    pub target_source: u32,
}

#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Debug, Clone, Copy)]
pub struct LpMetadataPartitionGroupRaw {
    pub name: [u8; 36],
    pub flags: u32,
    pub maximum_size: u64,
}

#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Debug, Clone, Copy)]
pub struct LpMetadataBlockDeviceRaw {
    pub first_logical_sector: u64,
    pub alignment: u32,
    pub alignment_offset: u32,
    pub size: u64,
    pub partition_name: [u8; 36],
    pub flags: u32,
}

pub fn serialize_metadata(layout: &SuperLayout) -> Result<Vec<u8>> {
    let mut partitions_raw = Vec::new();
    let mut extents_raw = Vec::new();
    let mut groups_raw = Vec::new();
    let mut block_devices_raw = Vec::new();

    // 1. Serialize Groups
    for g in &layout.groups {
        let mut name = [0u8; 36];
        let bytes = g.name.as_bytes();
        let len = std::cmp::min(bytes.len(), 35);
        name[..len].copy_from_slice(&bytes[..len]);

        groups_raw.push(LpMetadataPartitionGroupRaw {
            name,
            flags: 0, // Slot suffixed not handled here yet
            maximum_size: g.maximum_size,
        });
    }

    // 2. Serialize Partitions and Extents
    let mut extent_index = 0;
    for p in &layout.partitions {
        let mut name = [0u8; 36];
        let bytes = p.name.as_bytes();
        let len = std::cmp::min(bytes.len(), 35);
        name[..len].copy_from_slice(&bytes[..len]);

        let group_index = layout
            .groups
            .iter()
            .position(|g| g.name == p.group_name)
            .unwrap_or(0);

        partitions_raw.push(LpMetadataPartitionRaw {
            name,
            attributes: p.attributes,
            first_extent_index: extent_index,
            num_extents: p.extents.len() as u32,
            group_index: group_index as u32,
        });

        for e in &p.extents {
            extents_raw.push(LpMetadataExtentRaw {
                num_sectors: e.num_sectors,
                target_type: e.target_type,
                target_data: e.target_data,
                target_source: e.target_source,
            });
            extent_index += 1;
        }
    }

    // 3. Serialize Block Devices
    for d in &layout.block_devices {
        let mut name = [0u8; 36];
        let bytes = d.name.as_bytes();
        let len = std::cmp::min(bytes.len(), 35);
        name[..len].copy_from_slice(&bytes[..len]);

        // first_logical_sector is the first sector after metadata,
        // aligned up to `alignment` per AOSP lpmake convention.
        let alignment: u64 = 1048576;
        let metadata_end_bytes = 4096
            + 4096 * 2
            + (layout.geometry.metadata_max_size * layout.geometry.metadata_slot_count * 2) as u64;
        let aligned_bytes = (metadata_end_bytes + alignment - 1) & !(alignment - 1);
        let first_logical_sector = aligned_bytes / 512;

        block_devices_raw.push(LpMetadataBlockDeviceRaw {
            first_logical_sector,
            alignment: alignment as u32,
            alignment_offset: 0,
            size: d.size,
            partition_name: name,
            flags: 0,
        });
    }

    // Calculate table sizes
    let partitions_size = (partitions_raw.len() * 52) as u32;
    let extents_size = (extents_raw.len() * 24) as u32;
    let groups_size = (groups_raw.len() * 48) as u32;
    let block_devices_size = (block_devices_raw.len() * 64) as u32;
    let tables_size = partitions_size + extents_size + groups_size + block_devices_size;

    // Build tables blob for checksum
    let mut tables_blob = Vec::new();
    tables_blob.extend_from_slice(partitions_raw.as_slice().as_bytes());
    tables_blob.extend_from_slice(extents_raw.as_slice().as_bytes());
    tables_blob.extend_from_slice(groups_raw.as_slice().as_bytes());
    tables_blob.extend_from_slice(block_devices_raw.as_slice().as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&tables_blob);
    let tables_checksum: [u8; 32] = hasher.finalize().into();

    // 4. Build Header
    let mut header = LpMetadataHeaderRaw {
        magic: LP_METADATA_HEADER_MAGIC,
        major_version: 10,
        minor_version: 2,
        header_size: 256,
        header_checksum: [0u8; 32],
        tables_size,
        tables_checksum,
        partitions: LpMetadataTableDescriptorRaw {
            offset: 0,
            num_entries: partitions_raw.len() as u32,
            entry_size: 52,
        },
        extents: LpMetadataTableDescriptorRaw {
            offset: partitions_size,
            num_entries: extents_raw.len() as u32,
            entry_size: 24,
        },
        groups: LpMetadataTableDescriptorRaw {
            offset: partitions_size + extents_size,
            num_entries: groups_raw.len() as u32,
            entry_size: 48,
        },
        block_devices: LpMetadataTableDescriptorRaw {
            offset: partitions_size + extents_size + groups_size,
            num_entries: block_devices_raw.len() as u32,
            entry_size: 64,
        },
        flags: layout.header_flags,
        reserved: [0u8; 124],
    };

    // Header Checksum
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    header.header_checksum = hasher.finalize().into();

    // 5. Geometry
    let mut geometry = LpMetadataGeometryRaw {
        magic: LP_METADATA_GEOMETRY_MAGIC,
        struct_size: 52,
        checksum: [0u8; 32],
        metadata_max_size: layout.geometry.metadata_max_size,
        metadata_slot_count: layout.geometry.metadata_slot_count,
        logical_block_size: layout.geometry.logical_block_size,
    };

    let mut hasher = Sha256::new();
    hasher.update(geometry.as_bytes());
    geometry.checksum = hasher.finalize().into();

    // Combine into final metadata blob (one slot)
    let mut blob = Vec::new();
    blob.extend_from_slice(header.as_bytes());
    blob.extend_from_slice(&tables_blob);

    // The blob must fit in metadata_max_size
    if blob.len() > layout.geometry.metadata_max_size as usize {
        return Err(DynoError::Tool(format!(
            "Metadata size {} exceeds max size {}",
            blob.len(),
            layout.geometry.metadata_max_size
        )));
    }

    blob.resize(layout.geometry.metadata_max_size as usize, 0);

    // Build the full super-prefix (LP_PARTITION_RESERVED_BYTES + Geometry x2 + slots).
    //
    // Per AOSP `include/liblp/metadata_format.h`, a super image begins with 4096
    // zero-filled reserved bytes, then primary geometry at 4096, backup geometry
    // at 8192, then the metadata slots. Omitting the reserved prefix produces a
    // super image that's 4096 bytes short of what OEM tooling emits.
    let mut full_prefix = Vec::new();
    let geom_bytes = geometry.as_bytes();
    full_prefix.resize(4096, 0);
    full_prefix.extend_from_slice(geom_bytes);
    full_prefix.resize(8192, 0);
    full_prefix.extend_from_slice(geom_bytes);
    full_prefix.resize(12288, 0);

    // Primary and Backup slots
    for _ in 0..layout.geometry.metadata_slot_count * 2 {
        full_prefix.extend_from_slice(&blob);
    }

    Ok(full_prefix)
}
