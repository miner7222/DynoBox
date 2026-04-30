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
    let line_rewriter = SuperXmlLineRewriter::new();

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
                    let new_line = line_rewriter.rewrite_line(&template, chunk);

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

struct SuperXmlLineRewriter {
    filename: regex::Regex,
    start_sector: regex::Regex,
    num_partition_sectors: regex::Regex,
    sector_size_bytes: regex::Regex,
    size_kb_upper: regex::Regex,
    size_kb_lower: regex::Regex,
}

impl SuperXmlLineRewriter {
    fn new() -> Self {
        Self {
            filename: regex::Regex::new(r#"filename="[^"]*""#)
                .expect("static filename regex parses"),
            start_sector: regex::Regex::new(r#"start_sector="[^"]*""#)
                .expect("static start_sector regex parses"),
            num_partition_sectors: regex::Regex::new(r#"num_partition_sectors="[^"]*""#)
                .expect("static num_partition_sectors regex parses"),
            sector_size_bytes: regex::Regex::new(r#"SECTOR_SIZE_IN_BYTES="[^"]*""#)
                .expect("static SECTOR_SIZE_IN_BYTES regex parses"),
            size_kb_upper: regex::Regex::new(r#"size_in_KB="[^"]*""#)
                .expect("static size_in_KB regex parses"),
            size_kb_lower: regex::Regex::new(r#"size_in_kb="[^"]*""#)
                .expect("static size_in_kb regex parses"),
        }
    }

    fn rewrite_line(&self, template: &str, chunk: &SuperFlashChunk) -> String {
        let mut line = template.to_string();
        line = self
            .filename
            .replace(&line, format!("filename=\"{}\"", chunk.filename))
            .to_string();
        line = self
            .start_sector
            .replace(&line, format!("start_sector=\"{}\"", chunk.start_sector))
            .to_string();
        line = self
            .num_partition_sectors
            .replace(
                &line,
                format!("num_partition_sectors=\"{}\"", chunk.num_sectors),
            )
            .to_string();
        line = self
            .sector_size_bytes
            .replace(
                &line,
                format!("SECTOR_SIZE_IN_BYTES=\"{}\"", chunk.sector_size_bytes),
            )
            .to_string();
        let size_kb = chunk.size_bytes / 1024;
        line = self
            .size_kb_upper
            .replace(&line, format!("size_in_KB=\"{}\"", size_kb))
            .to_string();
        self.size_kb_lower
            .replace(&line, format!("size_in_kb=\"{}\"", size_kb))
            .to_string()
    }
}

#[cfg(test)]
fn rewrite_super_xml_line(template: &str, chunk: &SuperFlashChunk) -> Result<String> {
    Ok(SuperXmlLineRewriter::new().rewrite_line(template, chunk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_super_xml_line_updates_chunk_attributes() {
        let template = r#"<program label="super" filename="super_1.img" start_sector="6" num_partition_sectors="10" SECTOR_SIZE_IN_BYTES="4096" size_in_KB="40"/>"#;
        let chunk = SuperFlashChunk {
            filename: "super_2.img".to_string(),
            start_sector: 2048,
            num_sectors: 4096,
            sector_size_bytes: 512,
            source_offset_bytes: 0,
            size_bytes: 2 * 1024 * 1024,
        };

        let line = rewrite_super_xml_line(template, &chunk).unwrap();

        assert!(line.contains(r#"filename="super_2.img""#));
        assert!(line.contains(r#"start_sector="2048""#));
        assert!(line.contains(r#"num_partition_sectors="4096""#));
        assert!(line.contains(r#"SECTOR_SIZE_IN_BYTES="512""#));
        assert!(line.contains(r#"size_in_KB="2048""#));
    }
}
