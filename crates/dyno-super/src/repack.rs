use std::path::{Path, PathBuf};

use crate::builder::serialize_metadata;
use crate::metadata::{LP_TARGET_TYPE_LINEAR, SuperExtent, SuperLayout};
use dynobox_core::error::{DynoError, Result};

#[derive(Debug, Clone)]
pub struct SuperFlashChunk {
    pub filename: String,
    pub start_sector: u64,
    pub num_sectors: u64,
    pub sector_size_bytes: u64,
    pub source_offset_bytes: u64,
    pub size_bytes: u64,
}

pub fn repack_super_image(
    source_layout: &SuperLayout,
    image_dir: &Path,
    output_dir: &Path,
    xml_paths: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let mut new_layout = source_layout.clone();

    // 1. Update partition sizes and extents based on actual files
    let mut current_data_offset_sectors = (8192
        + (source_layout.geometry.metadata_max_size
            * source_layout.geometry.metadata_slot_count
            * 2) as u64)
        / 512;
    // Align to 1MiB (2048 sectors)
    current_data_offset_sectors = (current_data_offset_sectors + 2047) & !2047;

    for partition in &mut new_layout.partitions {
        if partition.slot_suffix() == Some("b") {
            partition.extents = Vec::new();
            continue;
        }

        let img_path = image_dir.join(format!("{}.img", partition.base_name()));
        if !img_path.exists() {
            return Err(DynoError::MissingFile(format!(
                "missing dynamic partition image for repack: {}",
                img_path.display()
            )));
        }

        let size_bytes = std::fs::metadata(&img_path)?.len();
        let num_sectors = (size_bytes + 511) / 512;
        // Align to block size (usually 4096)
        let aligned_sectors = (num_sectors + 7) & !7;

        partition.extents = vec![SuperExtent {
            num_sectors: aligned_sectors,
            target_type: LP_TARGET_TYPE_LINEAR,
            target_data: current_data_offset_sectors,
            target_source: 0,
        }];

        current_data_offset_sectors += aligned_sectors;
        // Align next partition to 1MiB
        current_data_offset_sectors = (current_data_offset_sectors + 2047) & !2047;
    }

    // 2. Serialize metadata
    let metadata_prefix = serialize_metadata(&new_layout)?;

    // 3. Plan Flash Chunks
    let flash_sector_size = source_layout.chunks[0].sector_size_bytes;
    let base_start_sector = source_layout.chunks[0].start_sector;

    let mut chunk_plans = vec![SuperFlashChunk {
        filename: source_layout.chunks[0].filename.clone(),
        start_sector: source_layout.chunks[0].start_sector,
        num_sectors: (metadata_prefix.len() as u64) / flash_sector_size,
        sector_size_bytes: flash_sector_size,
        source_offset_bytes: 0,
        size_bytes: metadata_prefix.len() as u64,
    }];

    // Data chunks
    let mut created_files = Vec::new();

    // Write metadata chunk
    let meta_path = output_dir.join(&chunk_plans[0].filename);
    std::fs::write(&meta_path, &metadata_prefix)?;
    created_files.push(meta_path);

    // Write data chunks
    let mut data_chunk_index = 2;
    for partition in &new_layout.partitions {
        if partition.slot_suffix() == Some("b") || partition.logical_size() == 0 {
            continue;
        }

        let img_path = image_dir.join(format!("{}.img", partition.base_name()));
        let filename = format!("super_{}.img", data_chunk_index);
        let out_path = output_dir.join(&filename);

        std::fs::copy(&img_path, &out_path)?;

        let size_bytes = std::fs::metadata(&out_path)?.len();
        let extent = &partition.extents[0];

        chunk_plans.push(SuperFlashChunk {
            filename,
            start_sector: base_start_sector + (extent.target_data * 512 / flash_sector_size),
            num_sectors: (size_bytes as u64 + flash_sector_size - 1) / flash_sector_size,
            sector_size_bytes: flash_sector_size,
            source_offset_bytes: 0,
            size_bytes: size_bytes as u64,
        });

        created_files.push(out_path);
        data_chunk_index += 1;
    }

    // 4. Rewrite XMLs
    tracing::info!("Rewriting XML entries...");
    rewrite_super_xml_entries(xml_paths, &chunk_plans)?;

    Ok(created_files)
}

fn rewrite_super_xml_entries(xml_paths: &[PathBuf], chunk_plans: &[SuperFlashChunk]) -> Result<()> {
    for xml_path in xml_paths {
        let content = std::fs::read_to_string(xml_path)?;

        let mut new_content = String::new();
        let mut in_super = false;
        let mut template = String::new();
        let mut replaced = false;

        for line in content.lines() {
            if line.contains("<program") && line.to_lowercase().contains("label=\"super\"") {
                if !in_super {
                    in_super = true;
                    template = line.to_string();
                }
                continue;
            } else if in_super {
                in_super = false;
                replaced = true;

                for chunk in chunk_plans {
                    let mut new_line = template.clone();

                    let re_filename = regex::Regex::new(r#"filename="[^"]*""#).unwrap();
                    new_line = re_filename
                        .replace(&new_line, format!("filename=\"{}\"", chunk.filename))
                        .to_string();

                    let re_start = regex::Regex::new(r#"start_sector="[^"]*""#).unwrap();
                    new_line = re_start
                        .replace(
                            &new_line,
                            format!("start_sector=\"{}\"", chunk.start_sector),
                        )
                        .to_string();

                    let re_num = regex::Regex::new(r#"num_partition_sectors="[^"]*""#).unwrap();
                    new_line = re_num
                        .replace(
                            &new_line,
                            format!("num_partition_sectors=\"{}\"", chunk.num_sectors),
                        )
                        .to_string();

                    let re_sec = regex::Regex::new(r#"SECTOR_SIZE_IN_BYTES="[^"]*""#).unwrap();
                    new_line = re_sec
                        .replace(
                            &new_line,
                            format!("SECTOR_SIZE_IN_BYTES=\"{}\"", chunk.sector_size_bytes),
                        )
                        .to_string();

                    let size_kb = chunk.size_bytes / 1024;
                    let re_kb1 = regex::Regex::new(r#"size_in_KB="[^"]*""#).unwrap();
                    new_line = re_kb1
                        .replace(&new_line, format!("size_in_KB=\"{}\"", size_kb))
                        .to_string();
                    let re_kb2 = regex::Regex::new(r#"size_in_kb="[^"]*""#).unwrap();
                    new_line = re_kb2
                        .replace(&new_line, format!("size_in_kb=\"{}\"", size_kb))
                        .to_string();

                    new_content.push_str(&new_line);
                    new_content.push('\n');
                }
                new_content.push_str(line);
                new_content.push('\n');
            } else {
                new_content.push_str(line);
                new_content.push('\n');
            }
        }

        if replaced {
            std::fs::write(xml_path, new_content)?;
        }
    }
    Ok(())
}
