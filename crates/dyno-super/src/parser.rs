use std::fs::File;
use std::io::Read;
use std::path::Path;

use dynobox_core::error::{DynoError, Result};
use dynobox_xml::PartitionRecord;

use crate::metadata::*;

const HEADER_SCAN_SIZE: usize = 64 * 1024;

fn read_header_region(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; HEADER_SCAN_SIZE];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn find_geometry_offset(data: &[u8]) -> Result<usize> {
    for &offset in &[0x1000, 0x2000, 0] {
        if data.len() >= offset + 52 {
            let magic = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            if magic == LP_METADATA_GEOMETRY_MAGIC {
                return Ok(offset);
            }
        }
    }

    let header_offset = find_header_offset(data)?;
    let magic_bytes = LP_METADATA_GEOMETRY_MAGIC.to_le_bytes();
    if let Some(pos) = data[..header_offset]
        .windows(4)
        .rposition(|w| w == magic_bytes)
    {
        return Ok(pos);
    }

    Err(DynoError::Tool(
        "LP metadata geometry not found in super chunk".into(),
    ))
}

fn find_header_offset(data: &[u8]) -> Result<usize> {
    let magic_bytes = LP_METADATA_HEADER_MAGIC.to_le_bytes();
    if let Some(pos) = data.windows(4).position(|w| w == magic_bytes) {
        return Ok(pos);
    }
    Err(DynoError::Tool(
        "LP metadata header not found in super chunk".into(),
    ))
}

fn parse_geometry(data: &[u8]) -> Result<SuperGeometry> {
    let offset = find_geometry_offset(data)?;
    if data.len() < offset + 52 {
        return Err(DynoError::Tool(
            "Super chunk too small to contain geometry".into(),
        ));
    }

    let magic = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    if magic != LP_METADATA_GEOMETRY_MAGIC {
        return Err(DynoError::Tool("Invalid super geometry magic".into()));
    }

    let metadata_max_size = u32::from_le_bytes(data[offset + 40..offset + 44].try_into().unwrap());
    let metadata_slot_count =
        u32::from_le_bytes(data[offset + 44..offset + 48].try_into().unwrap());
    let logical_block_size = u32::from_le_bytes(data[offset + 48..offset + 52].try_into().unwrap());

    Ok(SuperGeometry {
        metadata_max_size,
        metadata_slot_count,
        logical_block_size,
    })
}

struct TableDescriptor {
    offset: usize,
    num_entries: usize,
    entry_size: usize,
}

fn parse_table_descriptor(data: &[u8], start_offset: usize) -> TableDescriptor {
    let offset =
        u32::from_le_bytes(data[start_offset..start_offset + 4].try_into().unwrap()) as usize;
    let num_entries =
        u32::from_le_bytes(data[start_offset + 4..start_offset + 8].try_into().unwrap()) as usize;
    let entry_size = u32::from_le_bytes(
        data[start_offset + 8..start_offset + 12]
            .try_into()
            .unwrap(),
    ) as usize;

    TableDescriptor {
        offset,
        num_entries,
        entry_size,
    }
}

fn decode_c_string(raw: &[u8]) -> String {
    let null_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..null_pos]).into_owned()
}

fn read_metadata_region(path: &Path) -> Result<Vec<u8>> {
    let header_data = read_header_region(path)?;
    let header_offset = find_header_offset(&header_data).unwrap_or(0);

    let required_bytes = match parse_geometry(&header_data) {
        Ok(geom) => header_offset + (geom.metadata_max_size * geom.metadata_slot_count) as usize,
        Err(_) => 4 * 1024 * 1024,
    };

    if header_data.len() >= required_bytes {
        return Ok(header_data);
    }

    let mut file = File::open(path)?;
    let mut buf = vec![0u8; required_bytes];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn parse_metadata(
    path: &Path,
) -> Result<(
    u32,
    Vec<SuperBlockDevice>,
    Vec<SuperGroup>,
    Vec<SuperPartition>,
)> {
    let data = read_metadata_region(path)?;
    let header_offset = find_header_offset(&data)?;

    let magic = u32::from_le_bytes(data[header_offset..header_offset + 4].try_into().unwrap());
    if magic != LP_METADATA_HEADER_MAGIC {
        return Err(DynoError::Tool("Invalid LP metadata header magic".into()));
    }

    let header_size = u32::from_le_bytes(
        data[header_offset + 8..header_offset + 12]
            .try_into()
            .unwrap(),
    ) as usize;

    let partitions_desc = parse_table_descriptor(&data, header_offset + 80);
    let extents_desc = parse_table_descriptor(&data, header_offset + 92);
    let groups_desc = parse_table_descriptor(&data, header_offset + 104);
    let block_devices_desc = parse_table_descriptor(&data, header_offset + 116);

    let header_flags = if header_size >= 132 {
        u32::from_le_bytes(
            data[header_offset + 128..header_offset + 132]
                .try_into()
                .unwrap(),
        )
    } else {
        0
    };

    let table_offset = header_offset + header_size;

    let mut extents = Vec::with_capacity(extents_desc.num_entries);
    for i in 0..extents_desc.num_entries {
        let entry_offset = table_offset + extents_desc.offset + i * extents_desc.entry_size;
        let num_sectors =
            u64::from_le_bytes(data[entry_offset..entry_offset + 8].try_into().unwrap());
        let target_type = u32::from_le_bytes(
            data[entry_offset + 8..entry_offset + 12]
                .try_into()
                .unwrap(),
        );
        let target_data = u64::from_le_bytes(
            data[entry_offset + 12..entry_offset + 20]
                .try_into()
                .unwrap(),
        );
        let target_source = u32::from_le_bytes(
            data[entry_offset + 20..entry_offset + 24]
                .try_into()
                .unwrap(),
        );

        extents.push(SuperExtent {
            num_sectors,
            target_type,
            target_data,
            target_source,
        });
    }

    let mut groups = Vec::with_capacity(groups_desc.num_entries);
    for i in 0..groups_desc.num_entries {
        let entry_offset = table_offset + groups_desc.offset + i * groups_desc.entry_size;
        let name = decode_c_string(&data[entry_offset..entry_offset + 36]);
        let maximum_size = u64::from_le_bytes(
            data[entry_offset + 40..entry_offset + 48]
                .try_into()
                .unwrap(),
        );

        groups.push(SuperGroup { name, maximum_size });
    }

    let mut block_devices = Vec::with_capacity(block_devices_desc.num_entries);
    for i in 0..block_devices_desc.num_entries {
        let entry_offset =
            table_offset + block_devices_desc.offset + i * block_devices_desc.entry_size;
        let size = u64::from_le_bytes(
            data[entry_offset + 16..entry_offset + 24]
                .try_into()
                .unwrap(),
        );
        let name = decode_c_string(&data[entry_offset + 24..entry_offset + 60]);

        block_devices.push(SuperBlockDevice { name, size });
    }

    let mut partitions = Vec::with_capacity(partitions_desc.num_entries);
    for i in 0..partitions_desc.num_entries {
        let entry_offset = table_offset + partitions_desc.offset + i * partitions_desc.entry_size;
        let name = decode_c_string(&data[entry_offset..entry_offset + 36]);
        let attributes = u32::from_le_bytes(
            data[entry_offset + 36..entry_offset + 40]
                .try_into()
                .unwrap(),
        );
        let first_extent_index = u32::from_le_bytes(
            data[entry_offset + 40..entry_offset + 44]
                .try_into()
                .unwrap(),
        ) as usize;
        let num_extents = u32::from_le_bytes(
            data[entry_offset + 44..entry_offset + 48]
                .try_into()
                .unwrap(),
        ) as usize;
        let group_index = u32::from_le_bytes(
            data[entry_offset + 48..entry_offset + 52]
                .try_into()
                .unwrap(),
        ) as usize;

        let group_name = if group_index < groups.len() {
            groups[group_index].name.clone()
        } else {
            "default".to_string()
        };

        let partition_extents =
            extents[first_extent_index..first_extent_index + num_extents].to_vec();

        partitions.push(SuperPartition {
            name,
            attributes,
            group_name,
            extents: partition_extents,
        });
    }

    Ok((header_flags, block_devices, groups, partitions))
}

fn dedupe_super_records(records: &[PartitionRecord]) -> Vec<PartitionRecord> {
    let mut unique = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for record in records {
        let key = (
            record.filename.trim().to_lowercase(),
            record
                .start_sector
                .clone()
                .unwrap_or_else(|| "0".to_string())
                .parse::<u64>()
                .unwrap_or(0),
            record
                .num_sectors
                .clone()
                .unwrap_or_else(|| "0".to_string())
                .parse::<u64>()
                .unwrap_or(0),
            record
                .sector_size_bytes
                .clone()
                .unwrap_or_else(|| "512".to_string())
                .parse::<u64>()
                .unwrap_or(LP_SECTOR_SIZE),
        );
        if seen.insert(key) {
            unique.push(record.clone());
        }
    }
    unique
}

pub fn parse_full_super_image(super_path: &Path) -> Result<SuperLayout> {
    let actual_size_bytes = std::fs::metadata(super_path)?.len();

    let geometry = parse_geometry(&read_header_region(super_path)?)?;
    let (header_flags, block_devices, groups, partitions) = parse_metadata(super_path)?;

    let chunk = SuperChunk {
        filename: super_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        path: super_path.to_path_buf(),
        start_sector: 0,
        num_sectors: actual_size_bytes / LP_SECTOR_SIZE,
        sector_size_bytes: LP_SECTOR_SIZE,
        start_byte: 0,
        size_bytes: actual_size_bytes,
        relative_start_byte: 0,
    };

    Ok(SuperLayout {
        geometry,
        header_flags,
        block_devices,
        groups,
        partitions,
        chunks: vec![chunk],
    })
}

pub fn parse_super_layout(
    super_records: &[PartitionRecord],
    image_dir: &Path,
) -> Result<SuperLayout> {
    if super_records.is_empty() {
        return Err(DynoError::MissingFile(
            "super partition records not found in rawprogram XML".into(),
        ));
    }

    let mut ordered = super_records.to_vec();
    ordered.sort_by_key(|r| {
        r.start_sector
            .clone()
            .unwrap_or_else(|| "0".to_string())
            .parse::<u64>()
            .unwrap_or(0)
    });

    let usable: Vec<_> = ordered
        .into_iter()
        .filter(|r| !r.filename.is_empty())
        .collect();
    if usable.is_empty() {
        return Err(DynoError::MissingFile(
            "no usable super chunks were found".into(),
        ));
    }

    let usable = dedupe_super_records(&usable);

    // Drop records whose file is not physically present on disk. Lenovo OEM
    // images ship a sparse whole-super placeholder (e.g. `super.img`,
    // sparse="true") in rawprogram0.xml alongside the real split chunks
    // (`super_N.img`) declared in rawprogram_unsparse0.xml; only the split
    // chunks actually exist.
    let usable: Vec<_> = usable
        .into_iter()
        .filter(|r| image_dir.join(&r.filename).exists())
        .collect();
    if usable.is_empty() {
        return Err(DynoError::MissingFile(
            "no super chunk files were found on disk".into(),
        ));
    }

    let first_sector_size_bytes = usable[0]
        .sector_size_bytes
        .clone()
        .unwrap_or_else(|| "512".to_string())
        .parse::<u64>()
        .unwrap_or(LP_SECTOR_SIZE);
    let first_start_byte = usable[0]
        .start_sector
        .clone()
        .unwrap_or_else(|| "0".to_string())
        .parse::<u64>()
        .unwrap_or(0)
        * first_sector_size_bytes;

    let mut chunks = Vec::new();
    for record in usable {
        let chunk_path = image_dir.join(&record.filename);
        if !chunk_path.exists() {
            return Err(DynoError::MissingFile(format!(
                "missing super chunk: {}",
                chunk_path.display()
            )));
        }

        let start_sector = record
            .start_sector
            .clone()
            .unwrap_or_else(|| "0".to_string())
            .parse::<u64>()
            .unwrap_or(0);
        let num_sectors = record
            .num_sectors
            .clone()
            .unwrap_or_else(|| "0".to_string())
            .parse::<u64>()
            .unwrap_or(0);
        let sector_size_bytes = record
            .sector_size_bytes
            .clone()
            .unwrap_or_else(|| "512".to_string())
            .parse::<u64>()
            .unwrap_or(LP_SECTOR_SIZE);

        let start_byte = start_sector * sector_size_bytes;
        let size_bytes = num_sectors * sector_size_bytes;
        let actual_size_bytes = std::fs::metadata(&chunk_path)?.len();

        if actual_size_bytes != size_bytes {
            return Err(DynoError::Tool(format!(
                "super chunk size mismatch for {}: expected {} bytes from XML, found {}",
                chunk_path.display(),
                size_bytes,
                actual_size_bytes
            )));
        }

        chunks.push(SuperChunk {
            filename: record.filename.clone(),
            path: chunk_path,
            start_sector,
            num_sectors,
            sector_size_bytes,
            start_byte,
            size_bytes: actual_size_bytes,
            relative_start_byte: start_byte - first_start_byte,
        });
    }

    let first_chunk_path = &chunks[0].path;
    let geometry = parse_geometry(&read_header_region(first_chunk_path)?)?;
    let (header_flags, block_devices, groups, partitions) = parse_metadata(first_chunk_path)?;

    Ok(SuperLayout {
        geometry,
        header_flags,
        block_devices,
        groups,
        partitions,
        chunks,
    })
}
