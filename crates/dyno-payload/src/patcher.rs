use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::payload::proto::{Extent, InstallOperation, install_operation::Type};
use crate::puffin::{PuffPatchKind, apply_puffpatch_bytes, inspect_puff_patch_type};
use dynobox_core::error::{DynoError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSupportInfo {
    pub operation_name: String,
    pub detail_name: String,
    pub unsupported_reason: Option<String>,
}

pub struct Patcher {
    block_size: u64,
}

impl Patcher {
    pub fn new(block_size: u32) -> Self {
        Self {
            block_size: block_size as u64,
        }
    }

    pub fn apply_operation(
        &self,
        op: &InstallOperation,
        payload_data: &[u8],
        source_file: Option<&mut File>,
        target_file: &mut File,
    ) -> Result<()> {
        let op_type = Type::try_from(op.r#type)
            .map_err(|_| DynoError::Tool(format!("Unknown operation type: {}", op.r#type)))?;

        match op_type {
            Type::Replace => {
                self.write_extents(target_file, &op.dst_extents, payload_data)?;
            }
            Type::ReplaceBz => {
                let mut decompressor = bzip2::read::BzDecoder::new(payload_data);
                let mut decompressed = Vec::new();
                decompressor.read_to_end(&mut decompressed)?;
                self.write_extents(target_file, &op.dst_extents, &decompressed)?;
            }
            Type::ReplaceXz => {
                let mut decompressor = liblzma::read::XzDecoder::new(payload_data);
                let mut decompressed = Vec::new();
                decompressor.read_to_end(&mut decompressed)?;
                self.write_extents(target_file, &op.dst_extents, &decompressed)?;
            }
            Type::Zero => {
                let total_size = self.count_extents_size(&op.dst_extents);
                let zeros = vec![0u8; std::cmp::min(total_size, 1024 * 1024) as usize];
                self.write_extents_repeated(target_file, &op.dst_extents, &zeros, total_size)?;
            }
            Type::SourceCopy => {
                let src_fd = source_file.ok_or_else(|| {
                    DynoError::Tool("Source file required for SOURCE_COPY operation".into())
                })?;
                self.copy_extents(src_fd, target_file, &op.src_extents, &op.dst_extents)?;
            }
            Type::SourceBsdiff | Type::Bsdiff | Type::BrotliBsdiff => {
                let src_fd = source_file.ok_or_else(|| {
                    DynoError::Tool("Source file required for BSDIFF operation".into())
                })?;
                self.apply_bsdiff_android(
                    src_fd,
                    target_file,
                    &op.src_extents,
                    &op.dst_extents,
                    payload_data,
                )?;
            }
            Type::Lz4diffBsdiff => {
                let src_fd = source_file.ok_or_else(|| {
                    DynoError::Tool("Source file required for LZ4DIFF_BSDIFF operation".into())
                })?;
                let decompressed_patch = match lz4_flex::decompress_size_prepended(payload_data) {
                    Ok(data) => data,
                    Err(_) => lz4_flex::block::decompress(payload_data, 512 * 1024 * 1024)
                        .map_err(|e| DynoError::Tool(format!("LZ4 decompression failed: {}", e)))?,
                };
                self.apply_bsdiff_android(
                    src_fd,
                    target_file,
                    &op.src_extents,
                    &op.dst_extents,
                    &decompressed_patch,
                )?;
            }
            Type::Puffdiff => {
                let src_fd = source_file.ok_or_else(|| {
                    DynoError::Tool("Source file required for PUFFDIFF operation".into())
                })?;
                self.apply_puffdiff(
                    src_fd,
                    target_file,
                    &op.src_extents,
                    &op.dst_extents,
                    payload_data,
                )?;
            }
            Type::Lz4diffPuffdiff => {
                return Err(DynoError::UnsupportedOperation(
                    "LZ4DIFF_PUFFDIFF is not yet implemented in pure Rust".into(),
                ));
            }
            _ => {
                return Err(DynoError::UnsupportedOperation(format!(
                    "Operation type {:?} is not supported in pure Rust",
                    op_type
                )));
            }
        }

        Ok(())
    }

    fn write_extents(&self, file: &mut File, extents: &[Extent], data: &[u8]) -> Result<()> {
        let mut data_offset = 0;
        for extent in extents {
            let offset = extent.start_block.unwrap_or(0) * self.block_size;
            let size = extent.num_blocks.unwrap_or(0) * self.block_size;

            file.seek(SeekFrom::Start(offset))?;
            let to_write = std::cmp::min(size as usize, data.len() - data_offset);
            file.write_all(&data[data_offset..data_offset + to_write])?;
            data_offset += to_write;
        }
        Ok(())
    }

    fn write_extents_repeated(
        &self,
        file: &mut File,
        extents: &[Extent],
        pattern: &[u8],
        mut total_to_write: u64,
    ) -> Result<()> {
        for extent in extents {
            let offset = extent.start_block.unwrap_or(0) * self.block_size;
            let mut extent_remaining = extent.num_blocks.unwrap_or(0) * self.block_size;

            file.seek(SeekFrom::Start(offset))?;
            while extent_remaining > 0 && total_to_write > 0 {
                let chunk = std::cmp::min(extent_remaining, pattern.len() as u64);
                let chunk = std::cmp::min(chunk, total_to_write);
                file.write_all(&pattern[..chunk as usize])?;
                extent_remaining -= chunk;
                total_to_write -= chunk;
            }
        }
        Ok(())
    }

    fn copy_extents(
        &self,
        src: &mut File,
        dst: &mut File,
        src_extents: &[Extent],
        dst_extents: &[Extent],
    ) -> Result<()> {
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut src_ext_idx = 0;
        let mut src_ext_offset = 0u64;

        for dst_ext in dst_extents {
            let mut dst_offset = dst_ext.start_block.unwrap_or(0) * self.block_size;
            let mut dst_remaining = dst_ext.num_blocks.unwrap_or(0) * self.block_size;

            while dst_remaining > 0 {
                if src_ext_idx >= src_extents.len() {
                    return Err(DynoError::Tool(
                        "Source extents exhausted during SOURCE_COPY".into(),
                    ));
                }

                let src_ext = &src_extents[src_ext_idx];
                let src_ext_size = src_ext.num_blocks.unwrap_or(0) * self.block_size;
                let src_available = src_ext_size - src_ext_offset;

                let to_copy = std::cmp::min(dst_remaining, src_available);
                let to_copy = std::cmp::min(to_copy, buffer.len() as u64);

                src.seek(SeekFrom::Start(
                    src_ext.start_block.unwrap_or(0) * self.block_size + src_ext_offset,
                ))?;
                src.read_exact(&mut buffer[..to_copy as usize])?;

                dst.seek(SeekFrom::Start(dst_offset))?;
                dst.write_all(&buffer[..to_copy as usize])?;

                dst_offset += to_copy;
                dst_remaining -= to_copy;
                src_ext_offset += to_copy;

                if src_ext_offset >= src_ext_size {
                    src_ext_idx += 1;
                    src_ext_offset = 0;
                }
            }
        }
        Ok(())
    }

    fn read_extents_to_vec(&self, file: &mut File, extents: &[Extent]) -> Result<Vec<u8>> {
        let total_size = self.count_extents_size(extents);
        let mut data = vec![0u8; total_size as usize];
        let mut offset = 0;

        for extent in extents {
            let start = extent.start_block.unwrap_or(0) * self.block_size;
            let size = extent.num_blocks.unwrap_or(0) * self.block_size;
            file.seek(SeekFrom::Start(start))?;
            file.read_exact(&mut data[offset..offset + size as usize])?;
            offset += size as usize;
        }
        Ok(data)
    }

    fn apply_bsdiff_android(
        &self,
        src: &mut File,
        dst: &mut File,
        src_extents: &[Extent],
        dst_extents: &[Extent],
        patch_data: &[u8],
    ) -> Result<()> {
        let src_data = self.read_extents_to_vec(src, src_extents)?;
        let mut patched_data = Vec::new();

        bsdiff_android::patch_bsdf2(&src_data, patch_data, &mut patched_data)
            .map_err(|e| DynoError::Tool(format!("BSDF2 patch failed: {}", e)))?;

        let expected_size = self.count_extents_size(dst_extents);
        if patched_data.len() != expected_size as usize {
            return Err(DynoError::Tool(format!(
                "Patched data size mismatch: expected {} bytes, got {} bytes",
                expected_size,
                patched_data.len()
            )));
        }

        self.write_extents(dst, dst_extents, &patched_data)?;
        Ok(())
    }

    fn apply_puffdiff(
        &self,
        src: &mut File,
        dst: &mut File,
        src_extents: &[Extent],
        dst_extents: &[Extent],
        patch_data: &[u8],
    ) -> Result<()> {
        let src_data = self.read_extents_to_vec(src, src_extents)?;
        let patched_data = apply_puffpatch_bytes(&src_data, patch_data)?;

        let expected_size = self.count_extents_size(dst_extents);
        if patched_data.len() != expected_size as usize {
            return Err(DynoError::Tool(format!(
                "PUFFDIFF patched data size mismatch: expected {} bytes, got {} bytes",
                expected_size,
                patched_data.len()
            )));
        }

        self.write_extents(dst, dst_extents, &patched_data)?;
        Ok(())
    }

    fn count_extents_size(&self, extents: &[Extent]) -> u64 {
        extents
            .iter()
            .map(|e| e.num_blocks.unwrap_or(0) * self.block_size)
            .sum()
    }
}

pub fn inspect_operation_support(
    op: &InstallOperation,
    payload_data: &[u8],
) -> Result<OperationSupportInfo> {
    let op_type = Type::try_from(op.r#type)
        .map_err(|_| DynoError::Tool(format!("Unknown operation type: {}", op.r#type)))?;

    let info = match op_type {
        Type::Replace => supported("REPLACE"),
        Type::ReplaceBz => supported("REPLACE_BZ"),
        Type::ReplaceXz => supported("REPLACE_XZ"),
        Type::Zero => supported("ZERO"),
        Type::SourceCopy => supported("SOURCE_COPY"),
        Type::SourceBsdiff => supported("SOURCE_BSDIFF"),
        Type::Bsdiff => supported("BSDIFF"),
        Type::BrotliBsdiff => supported("BROTLI_BSDIFF"),
        Type::Lz4diffBsdiff => supported("LZ4DIFF_BSDIFF"),
        Type::Puffdiff => match inspect_puff_patch_type(payload_data)? {
            PuffPatchKind::Bsdiff => supported_with_detail("PUFFDIFF", "PUFFDIFF(BSDIFF)"),
            PuffPatchKind::Zucchini => unsupported(
                "PUFFDIFF",
                "PUFFDIFF(ZUCCHINI)",
                "Puff patch type ZUCCHINI is not yet implemented in pure Rust",
            ),
        },
        Type::Lz4diffPuffdiff => unsupported(
            "LZ4DIFF_PUFFDIFF",
            "LZ4DIFF_PUFFDIFF",
            "LZ4DIFF_PUFFDIFF is not yet implemented in pure Rust",
        ),
        Type::Zucchini => unsupported(
            "ZUCCHINI",
            "ZUCCHINI",
            "ZUCCHINI is not yet implemented in pure Rust",
        ),
        _ => {
            let name = format!("{op_type:?}");
            OperationSupportInfo {
                operation_name: name.clone(),
                detail_name: name,
                unsupported_reason: Some("Operation type is not supported in pure Rust".into()),
            }
        }
    };

    Ok(info)
}

fn supported(name: &str) -> OperationSupportInfo {
    supported_with_detail(name, name)
}

fn supported_with_detail(name: &str, detail_name: &str) -> OperationSupportInfo {
    OperationSupportInfo {
        operation_name: name.to_string(),
        detail_name: detail_name.to_string(),
        unsupported_reason: None,
    }
}

fn unsupported(name: &str, detail_name: &str, reason: &str) -> OperationSupportInfo {
    OperationSupportInfo {
        operation_name: name.to_string(),
        detail_name: detail_name.to_string(),
        unsupported_reason: Some(reason.to_string()),
    }
}

/// Type-erased progress callback called incrementally during
/// [`apply_partition_payload_with_progress`]. Receives `(done, total)`
/// weighted byte counts (see [`operation_progress_weight`] for the
/// weighting scheme). Invoked once at start with `done = 0` and after
/// every applied operation. Callers that don't need progress can use
/// the legacy [`apply_partition_payload`] entry point.
pub type ApplyProgressCallback<'a> = &'a mut dyn FnMut(u64, u64);

/// Weight assigned to a single install operation for progress reporting.
/// `data_length` (compressed patch bytes) approximates CPU-bound work for
/// REPLACE / *_BSDIFF / PUFFDIFF; `dst_bytes / 32` gives a small share to
/// SOURCE_COPY / ZERO ops so the bar still advances during fast write-only
/// phases and partitions made entirely of those ops still produce a
/// non-zero total weight.
fn operation_progress_weight(op: &crate::payload::proto::InstallOperation, block_size: u32) -> u64 {
    let data_length = op.data_length.unwrap_or(0);
    let dst_blocks: u64 = op
        .dst_extents
        .iter()
        .map(|e| e.num_blocks.unwrap_or(0))
        .sum();
    let dst_bytes = dst_blocks.saturating_mul(block_size as u64);
    data_length.saturating_add(dst_bytes / 32)
}

pub fn apply_partition_payload(
    payload_path: &Path,
    partition_name: &str,
    old_image: &Path,
    new_image: &Path,
    block_size: u32,
) -> Result<()> {
    apply_partition_payload_with_progress(
        payload_path,
        partition_name,
        old_image,
        new_image,
        block_size,
        None,
    )
}

pub fn apply_partition_payload_with_progress(
    payload_path: &Path,
    partition_name: &str,
    old_image: &Path,
    new_image: &Path,
    block_size: u32,
    mut progress: Option<ApplyProgressCallback>,
) -> Result<()> {
    use crate::payload::parse_payload_metadata;
    use prost::Message;

    let metadata = parse_payload_metadata(payload_path)?;
    let mut payload_file = File::open(payload_path)?;

    let data_offset = metadata.data_offset();

    let mut manifest_buf = vec![0u8; metadata.manifest_size as usize];
    payload_file.seek(SeekFrom::Start(metadata.manifest_offset))?;
    payload_file.read_exact(&mut manifest_buf)?;

    let manifest = crate::payload::proto::DeltaArchiveManifest::decode(&manifest_buf[..])
        .map_err(|e| DynoError::Tool(format!("Failed to re-decode manifest: {}", e)))?;

    let p_manifest = manifest
        .partitions
        .iter()
        .find(|p| p.partition_name == partition_name)
        .ok_or_else(|| {
            DynoError::Tool(format!("Partition {} manifest not found", partition_name))
        })?;

    let mut src_file = if old_image.exists() {
        Some(File::open(old_image)?)
    } else {
        None
    };

    let new_size = p_manifest
        .new_partition_info
        .as_ref()
        .unwrap()
        .size
        .unwrap();

    let mut dst_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(new_image)?;

    dst_file.set_len(new_size)?;

    if let Some(src) = src_file.as_mut() {
        let src_len = src.metadata()?.len();
        let copy_len = std::cmp::min(src_len, new_size);
        if copy_len > 0 {
            src.seek(SeekFrom::Start(0))?;
            dst_file.seek(SeekFrom::Start(0))?;
            let mut buf = vec![0u8; 1024 * 1024];
            let mut remaining = copy_len;
            while remaining > 0 {
                let chunk = std::cmp::min(remaining as usize, buf.len());
                src.read_exact(&mut buf[..chunk])?;
                dst_file.write_all(&buf[..chunk])?;
                remaining -= chunk as u64;
            }
            dst_file.flush()?;
        }
    }

    let patcher = Patcher::new(block_size);

    // Counting raw operations would advance the bar in lockstep with the
    // operation count, but that ignores how lopsided OTA work actually is:
    // SOURCE_COPY / ZERO ops typically make up the vast majority of the
    // operation list while consuming almost no CPU, and BROTLI_BSDIFF /
    // PUFFDIFF ops make up the long tail of the list while consuming
    // virtually all of the runtime. The bar would race to ~80 % during
    // SOURCE_COPY and then stall for tens of seconds during the diff tail.
    //
    // Weight each op by `data_length + dst_bytes / 32`:
    //   * `data_length` is the size of the compressed patch blob the op
    //     consumes from the payload, which dominates the runtime of every
    //     diff / replace op (decompress + apply work).
    //   * `dst_bytes / 32` gives SOURCE_COPY / ZERO ops a small but
    //     non-zero share so the bar still moves while the partition is
    //     being seeded, and so partitions that contain no diff ops at all
    //     do not divide by zero.
    let total_weight: u64 = p_manifest
        .operations
        .iter()
        .map(|op| operation_progress_weight(op, block_size))
        .sum();
    let mut done_weight: u64 = 0;

    if let Some(cb) = progress.as_deref_mut() {
        cb(0, total_weight);
    }

    for op in p_manifest.operations.iter() {
        let mut blob = vec![0u8; op.data_length.unwrap_or(0) as usize];
        if !blob.is_empty() {
            payload_file.seek(SeekFrom::Start(data_offset + op.data_offset.unwrap_or(0)))?;
            payload_file.read_exact(&mut blob)?;
        }

        patcher.apply_operation(op, &blob, src_file.as_mut(), &mut dst_file)?;

        done_weight = done_weight.saturating_add(operation_progress_weight(op, block_size));
        if let Some(cb) = progress.as_deref_mut() {
            cb(done_weight, total_weight);
        }
    }

    regenerate_verity_hash_tree(p_manifest, &mut dst_file, block_size)?;

    Ok(())
}

fn regenerate_verity_hash_tree(
    p_manifest: &crate::payload::proto::PartitionUpdate,
    dst_file: &mut File,
    block_size: u32,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    let (data_ext, tree_ext) = match (
        p_manifest.hash_tree_data_extent.as_ref(),
        p_manifest.hash_tree_extent.as_ref(),
    ) {
        (Some(d), Some(t)) => (d, t),
        _ => return Ok(()),
    };
    let algo = p_manifest.hash_tree_algorithm.as_deref().unwrap_or("");
    if !algo.eq_ignore_ascii_case("sha256") {
        return Err(DynoError::UnsupportedOperation(format!(
            "Unsupported hash_tree_algorithm: {}",
            algo
        )));
    }
    let salt: &[u8] = p_manifest.hash_tree_salt.as_deref().unwrap_or(&[]);

    let bs = block_size as u64;
    let data_start = data_ext.start_block.unwrap_or(0);
    let data_num = data_ext.num_blocks.unwrap_or(0);
    let tree_start = tree_ext.start_block.unwrap_or(0);
    let tree_num = tree_ext.num_blocks.unwrap_or(0);
    if data_num == 0 || tree_num == 0 {
        return Ok(());
    }

    let hash_size: u64 = 32;
    let hashes_per_block = bs / hash_size;

    let mut levels: Vec<Vec<u8>> = Vec::new();
    let mut level0 = Vec::with_capacity((data_num * hash_size) as usize);
    let mut buf = vec![0u8; bs as usize];
    for i in 0..data_num {
        dst_file.seek(SeekFrom::Start((data_start + i) * bs))?;
        dst_file.read_exact(&mut buf)?;
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(&buf);
        level0.extend_from_slice(&hasher.finalize());
    }
    pad_to_block_multiple(&mut level0, bs as usize);
    levels.push(level0);

    loop {
        let prev = levels.last().unwrap();
        let prev_blocks = prev.len() as u64 / bs;
        if prev_blocks <= 1 {
            break;
        }
        let mut next = Vec::with_capacity(
            ((prev_blocks + hashes_per_block - 1) / hashes_per_block * bs) as usize,
        );
        for bi in 0..prev_blocks {
            let start = (bi * bs) as usize;
            let end = start + bs as usize;
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(&prev[start..end]);
            next.extend_from_slice(&hasher.finalize());
        }
        pad_to_block_multiple(&mut next, bs as usize);
        levels.push(next);
    }

    let total_tree_blocks: u64 = levels.iter().map(|l| (l.len() as u64) / bs).sum();
    if total_tree_blocks != tree_num {
        return Err(DynoError::Tool(format!(
            "Hash tree block count mismatch: computed {} vs manifest {}",
            total_tree_blocks, tree_num
        )));
    }

    dst_file.seek(SeekFrom::Start(tree_start * bs))?;
    for level in levels.iter().rev() {
        dst_file.write_all(level)?;
    }
    dst_file.flush()?;
    Ok(())
}

fn pad_to_block_multiple(buf: &mut Vec<u8>, block_size: usize) {
    let rem = buf.len() % block_size;
    if rem != 0 {
        buf.resize(buf.len() + (block_size - rem), 0);
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::inspect_operation_support;
    use crate::payload::proto::InstallOperation;
    use crate::payload::proto::install_operation::Type;
    use crate::puffin::proto::{PatchHeader, StreamInfo, patch_header::PatchType};

    #[test]
    fn reports_standalone_zucchini_as_unsupported() {
        let op = InstallOperation {
            r#type: Type::Zucchini as i32,
            ..Default::default()
        };

        let info = inspect_operation_support(&op, &[]).unwrap();
        assert_eq!(info.detail_name, "ZUCCHINI");
        assert!(info.unsupported_reason.is_some());
    }

    #[test]
    fn reports_puffdiff_zucchini_as_unsupported() {
        let op = InstallOperation {
            r#type: Type::Puffdiff as i32,
            ..Default::default()
        };

        let info =
            inspect_operation_support(&op, &minimal_puff_patch(PatchType::Zucchini)).unwrap();
        assert_eq!(info.detail_name, "PUFFDIFF(ZUCCHINI)");
        assert!(info.unsupported_reason.is_some());
    }

    #[test]
    fn reports_puffdiff_bsdiff_as_supported() {
        let op = InstallOperation {
            r#type: Type::Puffdiff as i32,
            ..Default::default()
        };

        let info = inspect_operation_support(&op, &minimal_puff_patch(PatchType::Bsdiff)).unwrap();
        assert_eq!(info.detail_name, "PUFFDIFF(BSDIFF)");
        assert!(info.unsupported_reason.is_none());
    }

    fn minimal_puff_patch(patch_type: PatchType) -> Vec<u8> {
        let header = PatchHeader {
            version: 1,
            src: Some(StreamInfo::default()),
            dst: Some(StreamInfo::default()),
            r#type: patch_type as i32,
        };
        let encoded = header.encode_to_vec();
        let mut patch = Vec::new();
        patch.extend_from_slice(b"PUF1");
        patch.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        patch.extend_from_slice(&encoded);
        patch
    }
}
