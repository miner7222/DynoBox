//! Incremental OTA generation without an OEM incremental: a block-level
//! delta from A' to B'.
//!
//! Each 2 MiB chunk of the target becomes at most three operations:
//!
//! * `SOURCE_COPY` for blocks A' already holds, at the same offset or moved
//!   (found through a 128-bit digest index of every A' block),
//! * `ZERO` for all-zero blocks,
//! * a brotli `BROTLI_BSDIFF` from A''s blocks at the same offsets, or
//!   `REPLACE_XZ`, for the rest, whichever is smaller.
//!
//! This is file-agnostic, so it is larger than an OEM incremental when files
//! move around, but every block the two builds share is copied on device.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use dynobox_payload::payload::proto::{InstallOperation, install_operation::Type};
use sha2::{Digest, Sha256};

use crate::ota_rebase::{Emitted, SizedImage, diff_or_replace, replace_ops, to_extents, with_data};

/// Target blocks per chunk (2 MiB at 4 KiB blocks).
const CHUNK_BLOCKS: u64 = 512;

/// How the target's blocks were produced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeltaStats {
    /// Copied from the same offset in the source.
    pub unchanged_blocks: u64,
    /// Copied from another offset in the source.
    pub moved_blocks: u64,
    pub zero_blocks: u64,
    /// Written from operation data (bsdiff or replace).
    pub written_blocks: u64,
}

impl DeltaStats {
    pub fn add(&mut self, other: &DeltaStats) {
        self.unchanged_blocks += other.unchanged_blocks;
        self.moved_blocks += other.moved_blocks;
        self.zero_blocks += other.zero_blocks;
        self.written_blocks += other.written_blocks;
    }
}

/// A partition's delta operations plus its old and new digests.
pub(crate) struct DeltaPartition {
    pub operations: Vec<InstallOperation>,
    pub old_hash: Option<[u8; 32]>,
    pub new_hash: [u8; 32],
    pub stats: DeltaStats,
}

type BlockKey = [u8; 16];

fn block_key(data: &[u8]) -> BlockKey {
    let digest = Sha256::digest(data);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

/// Build delta operations turning `source` (the first `old_size` bytes, or
/// nothing) into the first `new_size` bytes of `target`, writing their data
/// to `blobs` in operation order.
pub(crate) fn delta_partition(
    source: Option<&Path>,
    old_size: u64,
    target: &Path,
    new_size: u64,
    block_size: u32,
    blobs: &mut impl Write,
    mut progress: impl FnMut(u64, u64),
) -> Result<DeltaPartition> {
    let block = u64::from(block_size);
    let old_blocks = old_size / block;
    let new_blocks = new_size / block;

    // Index every source block by digest; the first occurrence wins.
    let mut source = match source {
        Some(path) => Some(SizedImage::open(path, block_size)?),
        None => None,
    };
    let mut index: HashMap<BlockKey, u64> = HashMap::new();
    let mut old_hash = None;
    if let Some(source) = &mut source {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; (CHUNK_BLOCKS * block) as usize];
        let mut at = 0;
        while at < old_blocks {
            let blocks = (old_blocks - at).min(CHUNK_BLOCKS);
            let chunk = &mut buf[..(blocks * block) as usize];
            source.read_range(at * block, chunk)?;
            hasher.update(&chunk[..]);
            for (i, data) in chunk.chunks(block as usize).enumerate() {
                index.entry(block_key(data)).or_insert(at + i as u64);
            }
            at += blocks;
        }
        old_hash = Some(hasher.finalize().into());
    }

    let mut target = SizedImage::open(target, block_size)?;
    let mut new_hasher = Sha256::new();
    let mut stats = DeltaStats::default();
    let mut operations = Vec::new();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());

    let mut at = 0;
    while at < new_blocks {
        // Classify a batch of chunks in order (cheap, needs file access),
        // then diff and compress the changed blocks in parallel.
        let mut plans = Vec::with_capacity(threads * 2);
        while plans.len() < threads * 2 && at < new_blocks {
            let blocks = (new_blocks - at).min(CHUNK_BLOCKS);
            plans.push(plan_chunk(
                at,
                blocks,
                block,
                old_blocks,
                &mut source,
                &mut target,
                &index,
                &mut new_hasher,
                &mut stats,
            )?);
            at += blocks;
        }
        let changed: Vec<Result<Vec<Emitted>>> = std::thread::scope(|scope| {
            let handles: Vec<_> = plans
                .iter()
                .map(|plan| scope.spawn(move || plan.encode_changed(block)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("delta worker panicked"))
                .collect()
        });
        for (plan, changed) in plans.into_iter().zip(changed) {
            for Emitted { op, data } in plan.fixed.into_iter().chain(changed?) {
                blobs.write_all(&data)?;
                operations.push(op);
            }
        }
        progress(at, new_blocks);
    }
    Ok(DeltaPartition {
        operations,
        old_hash,
        new_hash: new_hasher.finalize().into(),
        stats,
    })
}

/// One target chunk: operations needing no work, and the changed blocks
/// still to be diffed or compressed.
struct ChunkPlan {
    fixed: Vec<Emitted>,
    changed_blocks: Vec<u64>,
    changed_target: Vec<u8>,
    /// Source blocks at the same offsets, when all of them exist.
    changed_source: Option<Vec<u8>>,
}

impl ChunkPlan {
    fn encode_changed(&self, block: u64) -> Result<Vec<Emitted>> {
        if self.changed_blocks.is_empty() {
            return Ok(Vec::new());
        }
        match &self.changed_source {
            Some(source_data) => {
                let extents = to_extents(&self.changed_blocks);
                diff_or_replace(
                    &extents,
                    Some(source_data),
                    &extents,
                    &self.changed_target,
                    block,
                )
            }
            None => replace_ops(&self.changed_blocks, &self.changed_target, block),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn plan_chunk(
    at: u64,
    blocks: u64,
    block: u64,
    old_blocks: u64,
    source: &mut Option<SizedImage>,
    target: &mut SizedImage,
    index: &HashMap<BlockKey, u64>,
    new_hasher: &mut Sha256,
    stats: &mut DeltaStats,
) -> Result<ChunkPlan> {
    let len = (blocks * block) as usize;
    let mut target_chunk = vec![0u8; len];
    target.read_range(at * block, &mut target_chunk)?;
    new_hasher.update(&target_chunk);
    let mut source_chunk = vec![0u8; len];
    if let Some(source) = source.as_mut() {
        // Only blocks inside the old partition count as same-offset.
        let same = old_blocks.saturating_sub(at).min(blocks);
        source.read_range(at * block, &mut source_chunk[..(same * block) as usize])?;
    }

    let (mut copy_src, mut copy_dst, mut zeros, mut changed) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for i in 0..blocks {
        let dst = at + i;
        let range = (i * block) as usize..((i + 1) * block) as usize;
        let data = &target_chunk[range.clone()];
        if data.iter().all(|&b| b == 0) {
            zeros.push(dst);
            stats.zero_blocks += 1;
        } else if source.is_some() && dst < old_blocks && source_chunk[range] == *data {
            copy_src.push(dst);
            copy_dst.push(dst);
            stats.unchanged_blocks += 1;
        } else if let Some(&src) = index.get(&block_key(data)) {
            copy_src.push(src);
            copy_dst.push(dst);
            stats.moved_blocks += 1;
        } else {
            changed.push(i);
        }
    }

    let mut fixed = Vec::new();
    if let (false, Some(source)) = (copy_src.is_empty(), source.as_mut()) {
        let src_extents = to_extents(&copy_src);
        let src_hash = Sha256::digest(source.read_extents(&src_extents)?).to_vec();
        fixed.push(with_data(
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
    if !zeros.is_empty() {
        fixed.push(with_data(
            InstallOperation {
                r#type: Type::Zero as i32,
                dst_extents: to_extents(&zeros),
                ..Default::default()
            },
            Vec::new(),
        ));
    }
    stats.written_blocks += changed.len() as u64;
    let slice =
        |chunk: &[u8], i: u64| chunk[(i * block) as usize..((i + 1) * block) as usize].to_vec();
    let changed_target: Vec<u8> = changed
        .iter()
        .flat_map(|&i| slice(&target_chunk, i))
        .collect();
    let all_in_source = source.is_some() && changed.iter().all(|&i| at + i < old_blocks);
    let changed_source = all_in_source.then(|| {
        changed
            .iter()
            .flat_map(|&i| slice(&source_chunk, i))
            .collect()
    });
    Ok(ChunkPlan {
        fixed,
        changed_blocks: changed.iter().map(|&i| at + i).collect(),
        changed_target,
        changed_source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dynobox_payload::patcher::Patcher;
    use std::fs::{File, OpenOptions};

    const BLOCK: usize = 4096;

    fn random_blocks(count: usize, mut state: u32) -> Vec<u8> {
        (0..count * BLOCK)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    fn block_of(data: &[u8], i: usize) -> &[u8] {
        &data[i * BLOCK..(i + 1) * BLOCK]
    }

    #[test]
    fn delta_turns_source_into_target() {
        let dir = tempfile::tempdir().unwrap();
        // 1100 blocks spans three chunks.
        let source = random_blocks(1100, 11);
        let mut target = source.clone();
        // A moved block, a zeroed block, a small in-place edit, fresh data,
        // and growth past the old size.
        let moved = block_of(&source, 900).to_vec();
        target[10 * BLOCK..11 * BLOCK].copy_from_slice(&moved);
        target[20 * BLOCK..21 * BLOCK].fill(0);
        target[600 * BLOCK + 7] ^= 0x5A;
        target[700 * BLOCK..702 * BLOCK].copy_from_slice(&random_blocks(2, 99));
        target.extend(random_blocks(3, 77));

        std::fs::write(dir.path().join("a.img"), &source).unwrap();
        std::fs::write(dir.path().join("b.img"), &target).unwrap();
        let mut blobs = Vec::new();
        let delta = delta_partition(
            Some(&dir.path().join("a.img")),
            source.len() as u64,
            &dir.path().join("b.img"),
            target.len() as u64,
            BLOCK as u32,
            &mut blobs,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(delta.stats.moved_blocks, 1);
        assert_eq!(delta.stats.zero_blocks, 1);
        assert_eq!(delta.stats.written_blocks, 1 + 2 + 3);
        assert_eq!(delta.new_hash, <[u8; 32]>::from(Sha256::digest(&target)));
        assert!(
            delta
                .operations
                .iter()
                .any(|op| op.r#type() == Type::BrotliBsdiff)
        );

        let mut src = File::open(dir.path().join("a.img")).unwrap();
        let mut out = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.path().join("out.img"))
            .unwrap();
        out.set_len(target.len() as u64).unwrap();
        let patcher = Patcher::new(BLOCK as u32);
        let mut at = 0usize;
        for op in &delta.operations {
            let len = op.data_length.unwrap_or(0) as usize;
            patcher
                .apply_operation(op, &blobs[at..at + len], Some(&mut src), &mut out)
                .unwrap();
            at += len;
        }
        drop(out);
        assert_eq!(std::fs::read(dir.path().join("out.img")).unwrap(), target);
    }

    #[test]
    fn identical_partitions_need_no_data() {
        let dir = tempfile::tempdir().unwrap();
        let data = random_blocks(40, 5);
        std::fs::write(dir.path().join("a.img"), &data).unwrap();
        let mut blobs = Vec::new();
        let delta = delta_partition(
            Some(&dir.path().join("a.img")),
            data.len() as u64,
            &dir.path().join("a.img"),
            data.len() as u64,
            BLOCK as u32,
            &mut blobs,
            |_, _| {},
        )
        .unwrap();
        assert!(blobs.is_empty());
        assert_eq!(delta.stats.unchanged_blocks, 40);
        assert_eq!(delta.old_hash, Some(delta.new_hash));
    }
}
