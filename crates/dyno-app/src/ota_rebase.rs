//! Incremental OTA generation by rebasing an OEM incremental payload.
//!
//! An OEM A->B payload describes how to turn stock A into stock B. DynoBox's
//! patched A' and B' differ from stock only in a few blocks (dbp edits, AVB
//! footers, vbmeta), so most OEM operations still apply. For every
//! operation this replays exactly what update_engine would do on the device:
//!
//! 1. the operation's `src_sha256_hash` must match the blocks A' holds, and
//! 2. its output must equal the blocks B' holds.
//!
//! Operations passing both are kept verbatim, compressed data included.
//! The rest are regenerated from A' and B': `SOURCE_COPY` is split per block
//! so unchanged blocks stay copies, other operations become a brotli
//! `BROTLI_BSDIFF` from the same A' source blocks or a `REPLACE_XZ`, whichever
//! is smaller. Blocks no operation writes (apart from the hash tree and FEC,
//! which the device computes) are written explicitly.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use dynobox_payload::patcher::Patcher;
use dynobox_payload::payload::proto::{
    Extent, InstallOperation, PartitionInfo, PartitionUpdate, install_operation::Type,
};
use sha2::{Digest, Sha256};

/// Largest source + target pair worth feeding to bsdiff; bigger regenerated
/// operations fall back to `REPLACE_XZ`.
const MAX_BSDIFF_BYTES: u64 = 64 << 20;
/// Bytes per regenerated `REPLACE_XZ` operation.
const REPLACE_CHUNK: u64 = 2 << 20;

/// Per-partition rebase statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RebaseStats {
    pub kept: usize,
    /// Regenerated because the source blocks differ from stock.
    pub source_changed: usize,
    /// Regenerated because the stock output differs from the target.
    pub target_changed: usize,
    /// Regenerated because DynoBox cannot replay the stock operation.
    pub unreplayable: usize,
    /// Operations added for blocks no operation covered.
    pub filled: usize,
}

impl RebaseStats {
    pub fn regenerated(&self) -> usize {
        self.source_changed + self.target_changed + self.unreplayable
    }

    pub fn add(&mut self, other: &RebaseStats) {
        self.kept += other.kept;
        self.source_changed += other.source_changed;
        self.target_changed += other.target_changed;
        self.unreplayable += other.unreplayable;
        self.filled += other.filled;
    }
}

/// A partition image read at its logical size: bytes past the end of the
/// file read as zeros.
pub(crate) struct SizedImage {
    file: File,
    file_len: u64,
    block_size: u64,
}

impl SizedImage {
    pub(crate) fn open(path: &Path, block_size: u32) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let file_len = file.metadata()?.len();
        Ok(Self {
            file,
            file_len,
            block_size: u64::from(block_size),
        })
    }

    fn read_range(&mut self, offset: u64, out: &mut [u8]) -> Result<()> {
        out.fill(0);
        if offset < self.file_len {
            let available = ((self.file_len - offset) as usize).min(out.len());
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.read_exact(&mut out[..available])?;
        }
        Ok(())
    }

    pub(crate) fn read_extents(&mut self, extents: &[Extent]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; (extents_blocks(extents) * self.block_size) as usize];
        let mut at = 0usize;
        for extent in extents {
            let len = (extent.num_blocks() * self.block_size) as usize;
            self.read_range(
                extent.start_block() * self.block_size,
                &mut out[at..at + len],
            )?;
            at += len;
        }
        Ok(out)
    }

    fn hash_extents(&mut self, extents: &[Extent]) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 4 << 20];
        for extent in extents {
            let mut offset = extent.start_block() * self.block_size;
            let mut remaining = extent.num_blocks() * self.block_size;
            while remaining > 0 {
                let chunk = remaining.min(buf.len() as u64) as usize;
                self.read_range(offset, &mut buf[..chunk])?;
                hasher.update(&buf[..chunk]);
                offset += chunk as u64;
                remaining -= chunk as u64;
            }
        }
        Ok(hasher.finalize().into())
    }

    /// SHA-256 of the first `size` bytes.
    pub(crate) fn hash_prefix(&mut self, size: u64) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 4 << 20];
        let mut offset = 0;
        while offset < size {
            let chunk = (size - offset).min(buf.len() as u64) as usize;
            self.read_range(offset, &mut buf[..chunk])?;
            hasher.update(&buf[..chunk]);
            offset += chunk as u64;
        }
        Ok(hasher.finalize().into())
    }
}

fn extents_blocks(extents: &[Extent]) -> u64 {
    extents.iter().map(|e| e.num_blocks()).sum()
}

fn expand(extents: &[Extent]) -> Vec<u64> {
    extents
        .iter()
        .flat_map(|e| e.start_block()..e.start_block() + e.num_blocks())
        .collect()
}

/// Collapse sorted-or-not block numbers into extents, preserving order.
fn to_extents(blocks: &[u64]) -> Vec<Extent> {
    let mut out: Vec<Extent> = Vec::new();
    for &block in blocks {
        match out.last_mut() {
            Some(last) if last.start_block() + last.num_blocks() == block => {
                last.num_blocks = Some(last.num_blocks() + 1);
            }
            _ => out.push(Extent {
                start_block: Some(block),
                num_blocks: Some(1),
            }),
        }
    }
    out
}

/// The OEM payload's operation data.
pub(crate) struct ReferenceBlobs {
    file: File,
    blob_start: u64,
}

impl ReferenceBlobs {
    pub(crate) fn open(path: &Path, blob_start: u64) -> Result<Self> {
        Ok(Self {
            file: File::open(path).with_context(|| format!("opening {}", path.display()))?,
            blob_start,
        })
    }

    fn read(&mut self, op: &InstallOperation) -> Result<Vec<u8>> {
        let Some(len) = op.data_length.filter(|&len| len > 0) else {
            return Ok(Vec::new());
        };
        let offset = op
            .data_offset
            .ok_or_else(|| anyhow!("reference operation has data but no offset"))?;
        let mut data = vec![0u8; len as usize];
        self.file.seek(SeekFrom::Start(self.blob_start + offset))?;
        self.file.read_exact(&mut data)?;
        Ok(data)
    }
}

/// An operation plus the blob it carries.
struct Emitted {
    op: InstallOperation,
    data: Vec<u8>,
}

fn with_data(mut op: InstallOperation, data: Vec<u8>) -> Emitted {
    if data.is_empty() {
        op.data_length = None;
        op.data_sha256_hash = None;
    } else {
        op.data_length = Some(data.len() as u64);
        op.data_sha256_hash = Some(Sha256::digest(&data).to_vec());
    }
    op.data_offset = None;
    Emitted { op, data }
}

fn xz(data: &[u8]) -> Result<Vec<u8>> {
    let stream = liblzma::stream::Stream::new_easy_encoder(6, liblzma::stream::Check::Crc32)?;
    let mut encoder = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Operations that write `data` (block-aligned) to `dst` without a source.
fn replace_ops(dst_blocks: &[u64], data: &[u8], block: u64) -> Result<Vec<Emitted>> {
    let per_op = (REPLACE_CHUNK / block) as usize;
    let mut out = Vec::new();
    for (index, blocks) in dst_blocks.chunks(per_op).enumerate() {
        let start = index * per_op * block as usize;
        let chunk = &data[start..start + blocks.len() * block as usize];
        let dst_extents = to_extents(blocks);
        if chunk.iter().all(|&b| b == 0) {
            out.push(with_data(
                InstallOperation {
                    r#type: Type::Zero as i32,
                    dst_extents,
                    ..Default::default()
                },
                Vec::new(),
            ));
            continue;
        }
        let compressed = xz(chunk)?;
        let (kind, bytes) = if compressed.len() < chunk.len() {
            (Type::ReplaceXz, compressed)
        } else {
            (Type::Replace, chunk.to_vec())
        };
        out.push(with_data(
            InstallOperation {
                r#type: kind as i32,
                dst_extents,
                ..Default::default()
            },
            bytes,
        ));
    }
    Ok(out)
}

/// Regenerate one operation so it writes B' from A'.
fn regenerate(
    op: &InstallOperation,
    source: &mut SizedImage,
    target: &mut SizedImage,
    block: u64,
) -> Result<Vec<Emitted>> {
    let dst_blocks = expand(&op.dst_extents);
    let target_data = target.read_extents(&op.dst_extents)?;

    if op.r#type() == Type::SourceCopy && extents_blocks(&op.src_extents) == dst_blocks.len() as u64
    {
        // Keep every block pair that still matches as a copy.
        let src_blocks = expand(&op.src_extents);
        let source_data = source.read_extents(&op.src_extents)?;
        let (mut copy_src, mut copy_dst, mut changed) = (Vec::new(), Vec::new(), Vec::new());
        let mut changed_data = Vec::new();
        for (i, (&src, &dst)) in src_blocks.iter().zip(&dst_blocks).enumerate() {
            let range = i * block as usize..(i + 1) * block as usize;
            if source_data[range.clone()] == target_data[range.clone()] {
                copy_src.push(src);
                copy_dst.push(dst);
            } else {
                changed.push(dst);
                changed_data.extend_from_slice(&target_data[range]);
            }
        }
        let mut out = Vec::new();
        if !copy_src.is_empty() {
            let src_extents = to_extents(&copy_src);
            let src_hash = Sha256::digest(source.read_extents(&src_extents)?).to_vec();
            out.push(with_data(
                InstallOperation {
                    r#type: Type::SourceCopy as i32,
                    src_extents,
                    dst_extents: to_extents(&copy_dst),
                    src_sha256_hash: Some(src_hash),
                    ..Default::default()
                },
                Vec::new(),
            ));
        }
        out.extend(replace_ops(&changed, &changed_data, block)?);
        return Ok(out);
    }

    let replaced = replace_ops(&dst_blocks, &target_data, block)?;
    let replaced_len: usize = replaced.iter().map(|e| e.data.len()).sum();
    let source_len = extents_blocks(&op.src_extents) * block;
    if op.src_extents.is_empty() || source_len + target_data.len() as u64 > MAX_BSDIFF_BYTES {
        return Ok(replaced);
    }
    let source_data = source.read_extents(&op.src_extents)?;
    let mut patch = Vec::new();
    bsdiff_android::diff_bsdf2_uniform(
        &source_data,
        &target_data,
        &mut patch,
        bsdiff_android::CompressionAlgorithm::Brotli,
    )
    .context("generating a brotli bsdiff patch")?;
    if patch.len() >= replaced_len {
        return Ok(replaced);
    }
    let mut check = Vec::new();
    bsdiff_android::patch_bsdf2(&source_data, &patch, &mut check)
        .context("re-applying the generated bsdiff patch")?;
    if check != target_data {
        bail!("generated bsdiff patch does not reproduce the target blocks");
    }
    Ok(vec![with_data(
        InstallOperation {
            r#type: Type::BrotliBsdiff as i32,
            src_extents: op.src_extents.clone(),
            dst_extents: op.dst_extents.clone(),
            src_length: Some(source_len),
            dst_length: Some(target_data.len() as u64),
            src_sha256_hash: Some(Sha256::digest(&source_data).to_vec()),
            ..Default::default()
        },
        patch,
    )])
}

/// Paths and sizes for one partition's rebase.
pub(crate) struct PartitionInputs<'a> {
    pub source: Option<&'a Path>,
    pub target: &'a Path,
    /// Scratch file for replaying operations; created and removed here.
    pub probe: PathBuf,
}

/// Rebase one OEM partition update onto A' -> B'. Writes the kept and new
/// operation data to `blobs` in operation order.
pub(crate) fn rebase_partition(
    reference: &PartitionUpdate,
    inputs: PartitionInputs<'_>,
    block_size: u32,
    reference_blobs: &mut ReferenceBlobs,
    blobs: &mut impl Write,
    mut progress: impl FnMut(usize, usize),
) -> Result<(PartitionUpdate, RebaseStats)> {
    let block = u64::from(block_size);
    let name = &reference.partition_name;
    let old_size = reference
        .old_partition_info
        .as_ref()
        .and_then(|i| i.size)
        .unwrap_or(0);
    let new_size = reference
        .new_partition_info
        .as_ref()
        .and_then(|i| i.size)
        .ok_or_else(|| anyhow!("reference gives no new size for `{name}`"))?;
    if new_size % block != 0 || old_size % block != 0 {
        bail!("`{name}` sizes are not block-aligned");
    }

    // The patcher needs a real source file of at least the old size.
    let source_path = inputs.source;
    let mut source_file = match source_path {
        Some(path) => Some(sized_copy_if_short(path, old_size, &inputs.probe)?),
        None => None,
    };
    let mut source = match &source_file {
        Some((path, _)) => Some(SizedImage::open(path, block_size)?),
        None => None,
    };
    let mut target = SizedImage::open(inputs.target, block_size)?;
    let mut probe = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&inputs.probe)?;
    probe.set_len(new_size)?;
    let mut probe_reader = SizedImage::open(&inputs.probe, block_size)?;
    let patcher = Patcher::new(block_size);

    let mut stats = RebaseStats::default();
    let mut emitted: Vec<Emitted> = Vec::new();
    let total = reference.operations.len();
    for (index, op) in reference.operations.iter().enumerate() {
        let source_ok = match (&op.src_extents[..], &mut source) {
            ([], _) => true,
            (_, None) => false,
            (extents, Some(source)) => op
                .src_sha256_hash
                .as_deref()
                .is_some_and(|hash| source.hash_extents(extents).is_ok_and(|h| h[..] == *hash)),
        };
        let kept = if source_ok {
            let data = reference_blobs.read(op)?;
            let source_handle = source_file.as_mut().map(|(_, file)| file);
            match patcher.apply_operation(op, &data, source_handle, &mut probe) {
                Err(_) => {
                    stats.unreplayable += 1;
                    None
                }
                Ok(())
                    if probe_reader.hash_extents(&op.dst_extents)?
                        != target.hash_extents(&op.dst_extents)? =>
                {
                    stats.target_changed += 1;
                    None
                }
                Ok(()) => Some(data),
            }
        } else {
            stats.source_changed += 1;
            None
        };
        match kept {
            Some(data) => {
                stats.kept += 1;
                let mut op = op.clone();
                op.data_offset = None;
                emitted.push(Emitted { op, data });
            }
            None => {
                let source = source.as_mut().filter(|_| !op.src_extents.is_empty());
                let ops = match source {
                    Some(source) => regenerate(op, source, &mut target, block)?,
                    None => {
                        let data = target.read_extents(&op.dst_extents)?;
                        replace_ops(&expand(&op.dst_extents), &data, block)?
                    }
                };
                emitted.extend(ops);
            }
        }
        progress(index + 1, total);
    }

    // Write any block no operation covers, except what the device computes.
    let new_blocks = new_size / block;
    let mut covered = vec![false; new_blocks as usize];
    for extent in emitted
        .iter()
        .flat_map(|e| &e.op.dst_extents)
        .chain(reference.hash_tree_extent.iter())
        .chain(reference.fec_extent.iter())
    {
        for b in extent.start_block()..(extent.start_block() + extent.num_blocks()).min(new_blocks)
        {
            covered[b as usize] = true;
        }
    }
    let uncovered: Vec<u64> = (0..new_blocks).filter(|&b| !covered[b as usize]).collect();
    if !uncovered.is_empty() {
        let extents = to_extents(&uncovered);
        let data = target.read_extents(&extents)?;
        let fill = replace_ops(&uncovered, &data, block)?;
        stats.filled += fill.len();
        emitted.extend(fill);
    }

    let old_hash = match &mut source {
        Some(source) => Some(source.hash_prefix(old_size)?.to_vec()),
        None => None,
    };
    let new_hash = target.hash_prefix(new_size)?.to_vec();
    drop(probe);
    drop(probe_reader);
    let _ = std::fs::remove_file(&inputs.probe);
    if let Some((path, _)) = &source_file {
        if Some(path.as_path()) != source_path {
            let _ = std::fs::remove_file(path);
        }
    }

    let mut update = reference.clone();
    update.merge_operations.clear();
    update.old_partition_info = old_hash.map(|hash| PartitionInfo {
        size: Some(old_size),
        hash: Some(hash),
    });
    update.new_partition_info = Some(PartitionInfo {
        size: Some(new_size),
        hash: Some(new_hash),
    });
    update.operations = Vec::with_capacity(emitted.len());
    for Emitted { op, data } in emitted {
        blobs.write_all(&data)?;
        update.operations.push(op);
    }
    Ok((update, stats))
}

/// `path` itself when it holds at least `size` bytes, otherwise a
/// zero-extended copy next to `probe`. Returns the path and an open handle.
fn sized_copy_if_short(path: &Path, size: u64, probe: &Path) -> Result<(PathBuf, File)> {
    let len = std::fs::metadata(path)?.len();
    let chosen = if len >= size {
        path.to_path_buf()
    } else {
        let copy = probe.with_extension("src.img");
        std::fs::copy(path, &copy)?;
        OpenOptions::new().write(true).open(&copy)?.set_len(size)?;
        copy
    };
    let file = File::open(&chosen)?;
    Ok((chosen, file))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: usize = 4096;

    fn pseudo_random(len: usize, mut state: u32) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    fn extent(start: u64, blocks: u64) -> Extent {
        Extent {
            start_block: Some(start),
            num_blocks: Some(blocks),
        }
    }

    /// Stock A -> B: blocks 0..4 copied, blocks 4..8 replaced. The patched
    /// builds change block 1 in both A' and B' (the same dbp edit) and block 5
    /// only in B'. The rebased operations must turn A' into B' exactly.
    #[test]
    fn rebased_operations_turn_patched_a_into_patched_b() {
        let dir = tempfile::tempdir().unwrap();
        let stock_a = pseudo_random(8 * BLOCK, 1);
        let mut stock_b = stock_a[..4 * BLOCK].to_vec();
        stock_b.extend(pseudo_random(4 * BLOCK, 2));

        let edit = pseudo_random(BLOCK, 3);
        let mut patched_a = stock_a.clone();
        patched_a[BLOCK..2 * BLOCK].copy_from_slice(&edit);
        let mut patched_b = stock_b.clone();
        patched_b[BLOCK..2 * BLOCK].copy_from_slice(&edit);
        patched_b[5 * BLOCK + 10] ^= 0xFF;

        let replace_data = stock_b[4 * BLOCK..].to_vec();
        let reference = PartitionUpdate {
            partition_name: "system".into(),
            old_partition_info: Some(PartitionInfo {
                size: Some(stock_a.len() as u64),
                hash: Some(Sha256::digest(&stock_a).to_vec()),
            }),
            new_partition_info: Some(PartitionInfo {
                size: Some(stock_b.len() as u64),
                hash: Some(Sha256::digest(&stock_b).to_vec()),
            }),
            operations: vec![
                InstallOperation {
                    r#type: Type::SourceCopy as i32,
                    src_extents: vec![extent(0, 4)],
                    dst_extents: vec![extent(0, 4)],
                    src_sha256_hash: Some(Sha256::digest(&stock_a[..4 * BLOCK]).to_vec()),
                    ..Default::default()
                },
                InstallOperation {
                    r#type: Type::Replace as i32,
                    dst_extents: vec![extent(4, 4)],
                    data_offset: Some(0),
                    data_length: Some(replace_data.len() as u64),
                    data_sha256_hash: Some(Sha256::digest(&replace_data).to_vec()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let paths = |name: &str| dir.path().join(name);
        std::fs::write(paths("a.img"), &patched_a).unwrap();
        std::fs::write(paths("b.img"), &patched_b).unwrap();
        std::fs::write(paths("ref.bin"), &replace_data).unwrap();
        let mut reference_blobs = ReferenceBlobs::open(&paths("ref.bin"), 0).unwrap();
        let mut blobs = Vec::new();
        let (update, stats) = rebase_partition(
            &reference,
            PartitionInputs {
                source: Some(&paths("a.img")),
                target: &paths("b.img"),
                probe: paths("probe.img"),
            },
            BLOCK as u32,
            &mut reference_blobs,
            &mut blobs,
            |_, _| {},
        )
        .unwrap();
        // Both stock operations are invalidated by the patches.
        // The copy reads the patched block; the replace writes a patched one.
        assert_eq!(
            (
                stats.kept,
                stats.source_changed,
                stats.target_changed,
                stats.filled
            ),
            (0, 1, 1, 0)
        );
        assert_eq!(
            update.new_partition_info.unwrap().hash.unwrap(),
            Sha256::digest(&patched_b).to_vec()
        );
        assert_eq!(
            update.old_partition_info.unwrap().hash.unwrap(),
            Sha256::digest(&patched_a).to_vec()
        );
        // The patched source block equals the patched target block, so the
        // copy survives as one SOURCE_COPY.
        assert_eq!(update.operations[0].r#type(), Type::SourceCopy);

        let mut source = File::open(paths("a.img")).unwrap();
        let mut out = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(paths("out.img"))
            .unwrap();
        out.set_len(patched_b.len() as u64).unwrap();
        let patcher = Patcher::new(BLOCK as u32);
        let mut at = 0usize;
        for op in &update.operations {
            let len = op.data_length.unwrap_or(0) as usize;
            patcher
                .apply_operation(op, &blobs[at..at + len], Some(&mut source), &mut out)
                .unwrap();
            at += len;
        }
        assert_eq!(at, blobs.len());
        drop(out);
        assert_eq!(std::fs::read(paths("out.img")).unwrap(), patched_b);
    }

    /// Operations whose source and output are untouched are reused verbatim.
    #[test]
    fn untouched_operations_are_kept_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let a = pseudo_random(4 * BLOCK, 7);
        let mut b = a.clone();
        b.extend(vec![0u8; 4 * BLOCK]);
        let mut a_full = a.clone();
        a_full.extend(vec![0u8; 4 * BLOCK]);
        let reference = PartitionUpdate {
            partition_name: "vendor".into(),
            old_partition_info: Some(PartitionInfo {
                size: Some(a_full.len() as u64),
                hash: None,
            }),
            new_partition_info: Some(PartitionInfo {
                size: Some(b.len() as u64),
                hash: None,
            }),
            operations: vec![
                InstallOperation {
                    r#type: Type::SourceCopy as i32,
                    src_extents: vec![extent(0, 4)],
                    dst_extents: vec![extent(0, 4)],
                    src_sha256_hash: Some(Sha256::digest(&a).to_vec()),
                    ..Default::default()
                },
                InstallOperation {
                    r#type: Type::Zero as i32,
                    dst_extents: vec![extent(4, 4)],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        std::fs::write(dir.path().join("a.img"), &a_full).unwrap();
        std::fs::write(dir.path().join("b.img"), &b).unwrap();
        std::fs::write(dir.path().join("ref.bin"), b"").unwrap();
        let mut reference_blobs = ReferenceBlobs::open(&dir.path().join("ref.bin"), 0).unwrap();
        let mut blobs = Vec::new();
        let (update, stats) = rebase_partition(
            &reference,
            PartitionInputs {
                source: Some(&dir.path().join("a.img")),
                target: &dir.path().join("b.img"),
                probe: dir.path().join("probe.img"),
            },
            BLOCK as u32,
            &mut reference_blobs,
            &mut blobs,
            |_, _| {},
        )
        .unwrap();
        assert_eq!((stats.kept, stats.regenerated(), stats.filled), (2, 0, 0));
        assert_eq!(update.operations, reference.operations);
        assert!(blobs.is_empty());
    }

    #[test]
    fn to_extents_merges_runs_in_order() {
        let extents = to_extents(&[3, 4, 5, 9, 1, 2]);
        let pairs: Vec<_> = extents
            .iter()
            .map(|e| (e.start_block(), e.num_blocks()))
            .collect();
        assert_eq!(pairs, [(3, 3), (9, 1), (1, 2)]);
        assert_eq!(expand(&extents), [3, 4, 5, 9, 1, 2]);
    }
}
