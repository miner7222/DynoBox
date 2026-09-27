//! Full (source-independent) partition encoding for payloads with
//! `minor_version = 0`.
//!
//! Each 2 MiB chunk becomes one operation: `ZERO` when the chunk is all
//! zeros, otherwise `REPLACE_XZ`, or plain `REPLACE` when compression does not
//! help. Chunks are compressed in parallel batches and written in order.

use std::io::{Read, Write};

use anyhow::{Context, Result, bail};
use dynobox_payload::payload::proto::{Extent, InstallOperation, install_operation::Type};
use liblzma::stream::{Check, Stream};
use sha2::{Digest, Sha256};

/// Bytes per operation; a multiple of every block size in use.
pub const CHUNK_SIZE: usize = 2 << 20;
const XZ_PRESET: u32 = 6;

/// Operations and digest of one encoded partition.
#[derive(Debug, Clone)]
pub struct EncodedPartition {
    pub operations: Vec<InstallOperation>,
    /// SHA-256 of the partition bytes (`new_partition_info.hash`).
    pub hash: [u8; 32],
}

enum Encoded {
    Zero,
    Data { kind: Type, bytes: Vec<u8> },
}

fn xz(data: &[u8]) -> Result<Vec<u8>> {
    // xz-embedded in update_engine understands CRC32 checks and plain LZMA2.
    let stream =
        Stream::new_easy_encoder(XZ_PRESET, Check::Crc32).context("creating xz encoder")?;
    let mut encoder = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn encode_chunk(data: &[u8]) -> Result<Encoded> {
    if data.iter().all(|&b| b == 0) {
        return Ok(Encoded::Zero);
    }
    let compressed = xz(data)?;
    Ok(if compressed.len() < data.len() {
        Encoded::Data {
            kind: Type::ReplaceXz,
            bytes: compressed,
        }
    } else {
        Encoded::Data {
            kind: Type::Replace,
            bytes: data.to_vec(),
        }
    })
}

/// Encode exactly `size` bytes from `source` as full-payload operations,
/// appending their data to `blobs` in operation order. `data_offset` is left
/// unset for the payload writer to assign.
pub fn encode_partition(
    source: &mut impl Read,
    size: u64,
    block_size: u32,
    blobs: &mut impl Write,
    mut progress: impl FnMut(u64),
) -> Result<EncodedPartition> {
    let block = u64::from(block_size);
    if block == 0 || CHUNK_SIZE as u64 % block != 0 {
        bail!("block size {block_size} must divide the {CHUNK_SIZE}-byte chunk size");
    }
    if size % block != 0 {
        bail!("partition size {size} is not a multiple of the {block_size}-byte block size");
    }
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let batch_chunks = threads * 2;

    let mut hasher = Sha256::new();
    let mut operations = Vec::new();
    let mut offset = 0u64;
    while offset < size {
        let mut batch = Vec::with_capacity(batch_chunks);
        while batch.len() < batch_chunks && offset < size {
            let len = (size - offset).min(CHUNK_SIZE as u64) as usize;
            let mut chunk = vec![0u8; len];
            source
                .read_exact(&mut chunk)
                .context("reading partition data")?;
            hasher.update(&chunk);
            batch.push((offset, chunk));
            offset += len as u64;
        }
        let encoded: Vec<Result<Encoded>> = std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|(_, chunk)| scope.spawn(|| encode_chunk(chunk)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("chunk encoder thread panicked"))
                .collect()
        });
        for ((chunk_offset, chunk), encoded) in batch.iter().zip(encoded) {
            let dst = Extent {
                start_block: Some(chunk_offset / block),
                num_blocks: Some(chunk.len() as u64 / block),
            };
            let op = match encoded? {
                Encoded::Zero => InstallOperation {
                    r#type: Type::Zero as i32,
                    dst_extents: vec![dst],
                    ..Default::default()
                },
                Encoded::Data { kind, bytes } => {
                    blobs.write_all(&bytes)?;
                    InstallOperation {
                        r#type: kind as i32,
                        data_length: Some(bytes.len() as u64),
                        data_sha256_hash: Some(Sha256::digest(&bytes).to_vec()),
                        dst_extents: vec![dst],
                        ..Default::default()
                    }
                }
            };
            operations.push(op);
        }
        progress(offset);
    }
    Ok(EncodedPartition {
        operations,
        hash: hasher.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_zero_compressible_and_random_chunks() {
        let mut data = vec![0u8; CHUNK_SIZE];
        data.extend(std::iter::repeat_n(0xAB, CHUNK_SIZE));
        let mut state = 0x1234_5678u32;
        data.extend((0..4096).map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        }));
        let mut blobs = Vec::new();
        let encoded =
            encode_partition(&mut &data[..], data.len() as u64, 4096, &mut blobs, |_| {}).unwrap();
        let kinds: Vec<_> = encoded.operations.iter().map(|op| op.r#type()).collect();
        assert_eq!(kinds, [Type::Zero, Type::ReplaceXz, Type::Replace]);
        let total: u64 = encoded
            .operations
            .iter()
            .filter_map(|op| op.data_length)
            .sum();
        assert_eq!(total, blobs.len() as u64);
        assert_eq!(encoded.hash, <[u8; 32]>::from(Sha256::digest(&data)));
        assert_eq!(encoded.operations[2].dst_extents[0].start_block, Some(1024));
        assert_eq!(encoded.operations[2].dst_extents[0].num_blocks, Some(1));
    }

    #[test]
    fn rejects_unaligned_sizes() {
        assert!(encode_partition(&mut &[0u8; 10][..], 10, 4096, &mut Vec::new(), |_| {}).is_err());
    }
}
