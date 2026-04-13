use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::metadata::{
    LP_SECTOR_SIZE, LP_TARGET_TYPE_LINEAR, LP_TARGET_TYPE_ZERO, SuperChunk, SuperLayout,
};
use dynobox_core::error::{DynoError, Result};

fn build_chunk_index(chunks: &[SuperChunk]) -> Vec<u64> {
    chunks.iter().map(|c| c.relative_start_byte).collect()
}

fn find_chunk<'a>(
    chunks: &'a [SuperChunk],
    chunk_starts: &[u64],
    logical_byte: u64,
) -> Result<&'a SuperChunk> {
    let idx = match chunk_starts.binary_search(&logical_byte) {
        Ok(i) => i,
        Err(i) => {
            if i == 0 {
                return Err(DynoError::Tool(format!(
                    "no super chunk covers logical byte offset {}",
                    logical_byte
                )));
            }
            i - 1
        }
    };

    if idx < chunks.len() {
        let chunk = &chunks[idx];
        if logical_byte >= chunk.relative_start_byte && logical_byte < chunk.relative_end_byte() {
            return Ok(chunk);
        }
    }

    Err(DynoError::Tool(format!(
        "no super chunk covers logical byte offset {}",
        logical_byte
    )))
}

pub fn extract_partition_images(
    layout: &SuperLayout,
    output_dir: &Path,
    partition_names: Option<&[String]>,
) -> Result<HashMap<String, PathBuf>> {
    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }

    let requested =
        partition_names.map(|names| names.iter().map(|n| n.to_lowercase()).collect::<Vec<_>>());

    let chunk_starts = build_chunk_index(&layout.chunks);
    let mut chunk_files: HashMap<PathBuf, File> = HashMap::new();
    let mut extracted = HashMap::new();

    for partition in &layout.partitions {
        if partition.slot_suffix() == Some("b") || partition.logical_size() <= 0 {
            continue;
        }

        let base_name = partition.base_name();

        if let Some(req) = &requested {
            if !req.contains(&base_name.to_lowercase()) {
                continue;
            }
        }

        let output_path = output_dir.join(format!("{}.img", base_name));
        let mut target = File::create(&output_path)?;

        for extent in &partition.extents {
            let extent_size_bytes = extent.num_sectors * LP_SECTOR_SIZE;

            if extent.target_type == LP_TARGET_TYPE_ZERO {
                let mut zero_remaining = extent_size_bytes;
                let chunk_size = std::cmp::min(zero_remaining, 4 * 1024 * 1024) as usize;
                let zero_chunk = vec![0u8; chunk_size];

                while zero_remaining > 0 {
                    let write_size = std::cmp::min(zero_remaining, zero_chunk.len() as u64);
                    target.write_all(&zero_chunk[..write_size as usize])?;
                    zero_remaining -= write_size;
                }
                continue;
            }

            if extent.target_type != LP_TARGET_TYPE_LINEAR {
                return Err(DynoError::Tool(format!(
                    "unsupported super extent type {} for {}",
                    extent.target_type, partition.name
                )));
            }

            let mut remaining_bytes = extent_size_bytes;
            let mut current_byte = extent.target_data * LP_SECTOR_SIZE;

            while remaining_bytes > 0 {
                let chunk = find_chunk(&layout.chunks, &chunk_starts, current_byte)?;
                let byte_offset = current_byte - chunk.relative_start_byte;
                let readable_bytes = std::cmp::min(remaining_bytes, chunk.size_bytes - byte_offset);

                let source = chunk_files
                    .entry(chunk.path.clone())
                    .or_insert_with(|| File::open(&chunk.path).unwrap());

                source.seek(SeekFrom::Start(byte_offset))?;

                // Read in chunks to avoid allocating huge buffers
                let mut chunk_remaining = readable_bytes;
                let mut buf = vec![0u8; std::cmp::min(chunk_remaining, 4 * 1024 * 1024) as usize];

                while chunk_remaining > 0 {
                    let read_len = std::cmp::min(chunk_remaining, buf.len() as u64) as usize;
                    source.read_exact(&mut buf[..read_len]).map_err(|e| {
                        DynoError::Tool(format!(
                            "unexpected EOF while reading {} for {}: {}",
                            chunk.filename, partition.name, e
                        ))
                    })?;
                    target.write_all(&buf[..read_len])?;
                    chunk_remaining -= read_len as u64;
                }

                remaining_bytes -= readable_bytes;
                current_byte += readable_bytes;
            }
        }

        extracted.insert(base_name, output_path);
    }

    Ok(extracted)
}
