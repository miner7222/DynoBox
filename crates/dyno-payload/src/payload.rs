use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use dynobox_core::error::{DynoError, Result};

use crate::patcher::inspect_operation_support;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

pub const PAYLOAD_MAGIC: &[u8; 4] = b"CrAU";

/// Defensive ceiling on the protobuf manifest buffer we will allocate.
///
/// Real Android OTA manifests are typically well under tens of MiB; 512 MiB
/// leaves headroom for unusually large multi-partition deltas while still
/// preventing a corrupted/hostile `manifest_size` field from driving an
/// unbounded allocation even when the on-disk file is huge (sparse, or a
/// truncated header followed by attacker-controlled padding).
pub const MAX_MANIFEST_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PayloadPartitionInfo {
    pub name: String,
    pub new_size: u64,
    pub new_hash: Vec<u8>,
    pub old_size: u64,
    pub old_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PayloadMetadata {
    pub version: u64,
    pub manifest_size: u64,
    pub metadata_signature_size: u32,
    pub partitions: Vec<PayloadPartitionInfo>,
    pub block_size: u32,
    pub manifest_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedOperation {
    pub partition_name: String,
    pub operation_index: usize,
    pub operation_name: String,
    pub detail_name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPreflightReport {
    pub version: u64,
    pub block_size: u32,
    pub partition_count: usize,
    pub total_operations: usize,
    pub operation_counts: BTreeMap<String, usize>,
    pub unsupported_operations: Vec<UnsupportedOperation>,
}

impl PayloadMetadata {
    pub fn metadata_size(&self) -> u64 {
        self.manifest_offset + self.manifest_size
    }

    pub fn data_offset(&self) -> u64 {
        self.metadata_size() + self.metadata_signature_size as u64
    }
}

pub fn extract_payload(ota_zip_path: &Path, output_dir: &Path) -> Result<PathBuf> {
    let file = File::open(ota_zip_path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| {
        DynoError::Tool(format!(
            "Failed to open OTA zip {}: {}",
            ota_zip_path.display(),
            e
        ))
    })?;

    let mut payload_file = archive.by_name("payload.bin").map_err(|_| {
        DynoError::MissingFile(format!(
            "payload.bin not found in OTA zip {}",
            ota_zip_path.display()
        ))
    })?;

    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }

    let output_path = output_dir.join("payload.bin");
    let mut out = File::create(&output_path)?;
    std::io::copy(&mut payload_file, &mut out)?;

    Ok(output_path)
}

pub fn parse_payload_metadata(path: &Path) -> Result<PayloadMetadata> {
    let mut file = File::open(path)?;

    // 1. Magic (4 bytes)
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != PAYLOAD_MAGIC {
        return Err(DynoError::Tool("Invalid payload magic".into()));
    }

    // 2. Version (8 bytes, Big Endian)
    let mut version_bytes = [0u8; 8];
    file.read_exact(&mut version_bytes)?;
    let version = u64::from_be_bytes(version_bytes);

    // 3. Manifest Size (8 bytes, Big Endian)
    let mut manifest_size_bytes = [0u8; 8];
    file.read_exact(&mut manifest_size_bytes)?;
    let manifest_size = u64::from_be_bytes(manifest_size_bytes);

    // ChromeOS/Android Version 2+ logic
    // 4. Metadata Signature Size (4 bytes, Big Endian)
    let mut metadata_signature_size = 0;
    let manifest_offset: u64 = if version >= 2 {
        let mut sig_size_bytes = [0u8; 4];
        file.read_exact(&mut sig_size_bytes)?;
        metadata_signature_size = u32::from_be_bytes(sig_size_bytes);
        24 // 4 + 8 + 8 + 4
    } else {
        20 // 4 + 8 + 8
    };

    // 5. Read Manifest
    // `manifest_size` is an attacker/corruption-controlled u64 from the
    // header. Validate it against an explicit allocation ceiling *and* the
    // actual file length before allocating so a malformed payload cannot
    // trigger a multi-GB allocation or truncate on a 32-bit `usize`.
    if manifest_size > MAX_MANIFEST_BYTES {
        return Err(DynoError::Tool(format!(
            "Payload manifest size {manifest_size} exceeds maximum allowed {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let file_len = file.metadata()?.len();
    let manifest_end = manifest_offset
        .checked_add(manifest_size)
        .ok_or_else(|| DynoError::Tool("Payload manifest offset/size overflow".into()))?;
    if manifest_end > file_len {
        return Err(DynoError::Tool(format!(
            "Payload manifest size {manifest_size} exceeds file length {file_len}"
        )));
    }
    let manifest_size_usize = usize::try_from(manifest_size)
        .map_err(|_| DynoError::Tool("Payload manifest size exceeds addressable memory".into()))?;
    let mut manifest_buf = vec![0u8; manifest_size_usize];
    file.read_exact(&mut manifest_buf)?;

    use prost::Message;
    let manifest = proto::DeltaArchiveManifest::decode(&manifest_buf[..])
        .map_err(|e| DynoError::Tool(format!("Failed to decode payload manifest: {}", e)))?;

    let mut partitions = Vec::new();
    for p in manifest.partitions {
        let name = p.partition_name;

        let mut new_size = 0;
        let mut new_hash = Vec::new();
        if let Some(info) = p.new_partition_info {
            new_size = info.size.unwrap_or(0);
            new_hash = info.hash.unwrap_or_default();
        }

        let mut old_size = 0;
        let mut old_hash = Vec::new();
        if let Some(info) = p.old_partition_info {
            old_size = info.size.unwrap_or(0);
            old_hash = info.hash.unwrap_or_default();
        }

        partitions.push(PayloadPartitionInfo {
            name,
            new_size,
            new_hash,
            old_size,
            old_hash,
        });
    }

    // `block_size = 0` would propagate into the patcher and feed
    // `Patcher::block_size` straight into `extent.num_blocks * 0 =
    // 0`, plus AOSP's hashtree code in `regenerate_verity_hash_tree`
    // divides by `block_size`. Reject malformed manifests up-front
    // with a clear error rather than a downstream div-by-zero panic.
    let block_size = manifest.block_size.unwrap_or(4096);
    if block_size == 0 {
        return Err(DynoError::Tool(
            "Payload manifest declares block_size = 0".into(),
        ));
    }
    Ok(PayloadMetadata {
        version,
        manifest_size,
        metadata_signature_size,
        partitions,
        block_size,
        manifest_offset,
    })
}

pub fn inspect_payload(payload_path: &Path) -> Result<PayloadPreflightReport> {
    use prost::Message;

    let metadata = parse_payload_metadata(payload_path)?;
    let mut payload_file = File::open(payload_path)?;
    // `parse_payload_metadata` already enforced the allocation ceiling and
    // file-range checks; re-check the usize conversion so the second
    // allocation path cannot silently truncate on 32-bit targets.
    let manifest_size_usize = usize::try_from(metadata.manifest_size)
        .map_err(|_| DynoError::Tool("Payload manifest size exceeds addressable memory".into()))?;
    let mut manifest_buf = vec![0u8; manifest_size_usize];
    payload_file.seek(SeekFrom::Start(metadata.manifest_offset))?;
    payload_file.read_exact(&mut manifest_buf)?;

    let manifest = proto::DeltaArchiveManifest::decode(&manifest_buf[..])
        .map_err(|e| DynoError::Tool(format!("Failed to decode payload manifest: {}", e)))?;

    let mut operation_counts = BTreeMap::new();
    let mut unsupported_operations = Vec::new();
    let data_offset = metadata.data_offset();
    let payload_len = payload_file.metadata()?.len();

    for partition in &manifest.partitions {
        for (operation_index, operation) in partition.operations.iter().enumerate() {
            // Only PUFFDIFF classification inspects the operation blob; every
            // other type is decided from `operation.r#type` alone. Skipping the
            // read for the common case avoids streaming the whole payload data
            // section during preflight and removes a manifest-controlled
            // allocation (a malformed `data_length` could otherwise OOM).
            let needs_blob = matches!(
                proto::install_operation::Type::try_from(operation.r#type),
                Ok(proto::install_operation::Type::Puffdiff)
            );
            let mut blob = Vec::new();
            if needs_blob {
                let data_length = operation.data_length.unwrap_or(0);
                let blob_start = data_offset
                    .checked_add(operation.data_offset.unwrap_or(0))
                    .ok_or_else(|| DynoError::Tool("Operation data offset overflow".into()))?;
                let blob_end = blob_start
                    .checked_add(data_length)
                    .ok_or_else(|| DynoError::Tool("Operation data range overflow".into()))?;
                if blob_end > payload_len {
                    return Err(DynoError::Tool(format!(
                        "Operation data range {blob_start}..{blob_end} exceeds payload length {payload_len}"
                    )));
                }
                let data_len = usize::try_from(data_length).map_err(|_| {
                    DynoError::Tool("Operation data length exceeds addressable memory".into())
                })?;
                blob.resize(data_len, 0);
                if !blob.is_empty() {
                    payload_file.seek(SeekFrom::Start(blob_start))?;
                    payload_file.read_exact(&mut blob)?;
                }
            }

            let support = inspect_operation_support(operation, &blob)?;
            *operation_counts
                .entry(support.detail_name.clone())
                .or_insert(0usize) += 1;

            if let Some(reason) = support.unsupported_reason {
                unsupported_operations.push(UnsupportedOperation {
                    partition_name: partition.partition_name.clone(),
                    operation_index,
                    operation_name: support.operation_name,
                    detail_name: support.detail_name,
                    reason,
                });
            }
        }
    }

    Ok(PayloadPreflightReport {
        version: metadata.version,
        block_size: metadata.block_size,
        partition_count: manifest.partitions.len(),
        total_operations: operation_counts.values().sum(),
        operation_counts,
        unsupported_operations,
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_MANIFEST_BYTES, PAYLOAD_MAGIC, parse_payload_metadata};
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_payload_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dynobox-payload-{}-{}-{}.bin",
            label,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn write_v2_header(path: &std::path::Path, manifest_size: u64, body: &[u8]) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(PAYLOAD_MAGIC).unwrap();
        file.write_all(&2u64.to_be_bytes()).unwrap(); // version
        file.write_all(&manifest_size.to_be_bytes()).unwrap();
        file.write_all(&0u32.to_be_bytes()).unwrap(); // metadata_signature_size
        file.write_all(body).unwrap();
    }

    #[test]
    fn parse_payload_metadata_survives_mutated_input() {
        use super::proto::{DeltaArchiveManifest, PartitionInfo, PartitionUpdate};
        use prost::Message;

        let manifest = DeltaArchiveManifest {
            block_size: Some(4096),
            partitions: vec![PartitionUpdate {
                partition_name: "system".to_string(),
                new_partition_info: Some(PartitionInfo {
                    size: Some(4096),
                    hash: Some(vec![0xAB; 32]),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        let mut seed = Vec::new();
        seed.extend_from_slice(PAYLOAD_MAGIC);
        seed.extend_from_slice(&2u64.to_be_bytes());
        seed.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
        seed.extend_from_slice(&0u32.to_be_bytes());
        seed.extend_from_slice(&manifest);

        let path = temp_payload_path("mutated");
        fs::write(&path, &seed).unwrap();
        assert!(parse_payload_metadata(&path).is_ok());
        dynobox_core::testutil::for_each_mutation(&seed, 0x9A71, 1500, |bytes| {
            fs::write(&path, bytes).unwrap();
            let _ = parse_payload_metadata(&path);
        });
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_manifest_size_above_allocation_cap() {
        let path = temp_payload_path("manifest-cap");
        // Claim a manifest larger than the defensive ceiling while keeping
        // the on-disk body tiny so the failure must come from the cap, not
        // the file-length check.
        let claimed = MAX_MANIFEST_BYTES + 1;
        write_v2_header(&path, claimed, b"x");

        let err = parse_payload_metadata(&path).unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum allowed"),
            "expected allocation-cap error, got: {err}"
        );
        assert!(
            err.contains(&MAX_MANIFEST_BYTES.to_string()),
            "error should mention the cap value: {err}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_manifest_size_past_file_length() {
        let path = temp_payload_path("manifest-eof");
        // Within the allocation cap but larger than the actual file body.
        write_v2_header(&path, 64, b"short");

        let err = parse_payload_metadata(&path).unwrap_err().to_string();
        assert!(
            err.contains("exceeds file length"),
            "expected file-length error, got: {err}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_manifest_offset_size_overflow() {
        let path = temp_payload_path("manifest-overflow");
        // version >= 2 uses offset 24; u64::MAX + 24 overflows checked_add.
        write_v2_header(&path, u64::MAX, &[]);

        let err = parse_payload_metadata(&path).unwrap_err().to_string();
        // Either the allocation cap (MAX is smaller) or the overflow path
        // is acceptable; with MAX_MANIFEST_BYTES << u64::MAX the cap fires
        // first and is still a clear rejection.
        assert!(
            err.contains("exceeds maximum allowed") || err.contains("overflow"),
            "expected cap/overflow error, got: {err}"
        );
        let _ = fs::remove_file(path);
    }

    /// Per-partition OTA size breakdown for a real OTA zip.
    /// `DYNOBOX_OTA_ZIP` points at the zip; payload.bin is extracted to a temp
    /// file. Prints, per partition: new/old image sizes, per-op-type counts,
    /// and payload data bytes (what actually drives the zip size).
    #[test]
    #[ignore = "fixture: set DYNOBOX_OTA_ZIP"]
    fn dump_ota_partition_breakdown() {
        use prost::Message;
        use std::collections::BTreeMap;
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let zip_path = std::env::var("DYNOBOX_OTA_ZIP").unwrap();
        let out_dir = std::env::temp_dir().join("dynobox-ota-dump");
        let payload_path =
            crate::payload::extract_payload(std::path::Path::new(&zip_path), &out_dir).unwrap();
        let metadata = parse_payload_metadata(&payload_path).unwrap();
        let mut payload_file = File::open(&payload_path).unwrap();
        payload_file
            .seek(SeekFrom::Start(metadata.manifest_offset))
            .unwrap();
        let mut manifest_buf = vec![0u8; metadata.manifest_size as usize];
        payload_file.read_exact(&mut manifest_buf).unwrap();
        let manifest = super::proto::DeltaArchiveManifest::decode(&manifest_buf[..]).unwrap();

        println!("OTA zip: {zip_path}");
        println!(
            "payload.bin {} bytes, manifest {} bytes, block_size {}",
            std::fs::metadata(&payload_path).unwrap().len(),
            metadata.manifest_size,
            metadata.block_size
        );
        let mut total_data = 0u64;
        for p in &manifest.partitions {
            let new_size = p
                .new_partition_info
                .as_ref()
                .and_then(|i| i.size)
                .unwrap_or(0);
            let old_size = p
                .old_partition_info
                .as_ref()
                .and_then(|i| i.size)
                .unwrap_or(0);
            let mut by_type: BTreeMap<String, (usize, u64)> = BTreeMap::new();
            let mut part_data = 0u64;
            for op in &p.operations {
                let t = super::proto::install_operation::Type::try_from(op.r#type)
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|_| format!("?{}", op.r#type));
                let dl = op.data_length.unwrap_or(0);
                let e = by_type.entry(t).or_default();
                e.0 += 1;
                e.1 += dl;
                part_data += dl;
            }
            total_data += part_data;
            println!(
                "{:<24} new={:>12} old={:>12} ops={:<5} data={:>12}",
                p.partition_name,
                new_size,
                old_size,
                p.operations.len(),
                part_data
            );
            for (t, (n, b)) in &by_type {
                println!("    {t:<20} x{n:<5} {b:>12} bytes");
            }
            let mut ops_sorted = p.operations.clone();
            ops_sorted.sort_by_key(|o| std::cmp::Reverse(o.data_length.unwrap_or(0)));
            for (i, op) in ops_sorted.iter().take(8).enumerate() {
                let t = super::proto::install_operation::Type::try_from(op.r#type)
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|_| format!("?{}", op.r#type));
                let dst: String = op
                    .dst_extents
                    .iter()
                    .map(|e| {
                        format!(
                            "{}+{}",
                            e.start_block.unwrap_or(0),
                            e.num_blocks.unwrap_or(0)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let src: String = op
                    .src_extents
                    .iter()
                    .map(|e| {
                        format!(
                            "{}+{}",
                            e.start_block.unwrap_or(0),
                            e.num_blocks.unwrap_or(0)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "    #{i} {t:<14} data={:>12} dst=[{dst}] src=[{src}]",
                    op.data_length.unwrap_or(0)
                );
            }
        }
        println!("TOTAL payload data bytes: {total_data}");
    }
}
