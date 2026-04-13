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
    let manifest_offset = if version >= 2 {
        let mut sig_size_bytes = [0u8; 4];
        file.read_exact(&mut sig_size_bytes)?;
        metadata_signature_size = u32::from_be_bytes(sig_size_bytes);
        24 // 4 + 8 + 8 + 4
    } else {
        20 // 4 + 8 + 8
    };

    // 5. Read Manifest
    let mut manifest_buf = vec![0u8; manifest_size as usize];
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

    Ok(PayloadMetadata {
        version,
        manifest_size,
        metadata_signature_size,
        partitions,
        block_size: manifest.block_size.unwrap_or(4096),
        manifest_offset,
    })
}

pub fn inspect_payload(payload_path: &Path) -> Result<PayloadPreflightReport> {
    use prost::Message;

    let metadata = parse_payload_metadata(payload_path)?;
    let mut payload_file = File::open(payload_path)?;
    let mut manifest_buf = vec![0u8; metadata.manifest_size as usize];
    payload_file.seek(SeekFrom::Start(metadata.manifest_offset))?;
    payload_file.read_exact(&mut manifest_buf)?;

    let manifest = proto::DeltaArchiveManifest::decode(&manifest_buf[..])
        .map_err(|e| DynoError::Tool(format!("Failed to decode payload manifest: {}", e)))?;

    let mut operation_counts = BTreeMap::new();
    let mut unsupported_operations = Vec::new();
    let data_offset = metadata.data_offset();

    for partition in &manifest.partitions {
        for (operation_index, operation) in partition.operations.iter().enumerate() {
            let mut blob = vec![0u8; operation.data_length.unwrap_or(0) as usize];
            if !blob.is_empty() {
                payload_file.seek(SeekFrom::Start(
                    data_offset + operation.data_offset.unwrap_or(0),
                ))?;
                payload_file.read_exact(&mut blob)?;
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
