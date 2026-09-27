//! Signed `payload.bin` (A/B update_engine payload, major version 2).
//!
//! Layout: `CrAU` magic, version, manifest size, metadata-signature size,
//! manifest, metadata signature, operation blobs, payload signature.
//!
//! * The metadata signature covers the header and manifest.
//! * The payload signature covers the header, manifest and blobs, but not
//!   the metadata signature.
//! * `payload_properties.txt` records the SHA-256 and size of the whole file
//!   and of the header plus manifest.

use std::io::{Read, Seek, SeekFrom, Write};

use anyhow::{Context, Result, anyhow, bail};
use dynobox_payload::payload::proto::{DeltaArchiveManifest, Signatures, signatures::Signature};
use prost::Message;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

use crate::key::{self, OtaSigningKey};
use crate::pem::base64_encode;

pub const PAYLOAD_MAGIC: &[u8; 4] = b"CrAU";
pub const PAYLOAD_VERSION: u64 = 2;
/// magic + version + manifest size + metadata-signature size.
const HEADER_LEN: u64 = 4 + 8 + 8 + 4;

/// Where the pieces of a written payload ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadSummary {
    /// `payload_properties.txt` contents.
    pub properties: String,
    /// Header + manifest length (`METADATA_SIZE`).
    pub metadata_size: u64,
    /// Header + manifest + metadata signature length: where blobs begin, and
    /// the size of the `payload_metadata.bin` property-files entry.
    pub blob_offset: u64,
    pub file_size: u64,
}

fn signatures_for(signature: Vec<u8>) -> Signatures {
    let len = signature.len() as u32;
    Signatures {
        signatures: vec![Signature {
            data: Some(signature),
            unpadded_signature_size: Some(len),
            ..Default::default()
        }],
    }
}

/// Write a signed payload. `blobs` must yield exactly the operation data of
/// `manifest`, in operation order; `data_offset`s are reassigned so the blobs
/// are contiguous.
pub fn write_signed_payload(
    out: &mut impl Write,
    mut manifest: DeltaArchiveManifest,
    blobs: &mut impl Read,
    key: &OtaSigningKey,
) -> Result<PayloadSummary> {
    let mut blob_len = 0u64;
    for partition in &mut manifest.partitions {
        for op in &mut partition.operations {
            match op.data_length {
                Some(len) if len > 0 => {
                    op.data_offset = Some(blob_len);
                    blob_len += len;
                }
                _ => {
                    op.data_offset = None;
                    op.data_length = None;
                }
            }
        }
    }
    // RSA signatures have a fixed length, so any signature's encoding sizes
    // the reserved space.
    let signature_len = signatures_for(vec![0; key.signature_len()]).encoded_len() as u64;
    manifest.signatures_offset = Some(blob_len);
    manifest.signatures_size = Some(signature_len);
    let manifest_bytes = manifest.encode_to_vec();

    let mut header = Vec::with_capacity(HEADER_LEN as usize);
    header.extend_from_slice(PAYLOAD_MAGIC);
    header.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
    header.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
    header.extend_from_slice(&(signature_len as u32).to_be_bytes());

    let mut signed = Sha256::new();
    let mut whole = Sha256::new();
    for part in [&header[..], &manifest_bytes[..]] {
        out.write_all(part)?;
        signed.update(part);
        whole.update(part);
    }
    let metadata_hash: [u8; 32] = signed.clone().finalize().into();
    let metadata_signature = signatures_for(key.sign_digest(&metadata_hash)?).encode_to_vec();
    out.write_all(&metadata_signature)?;
    whole.update(&metadata_signature);

    let mut buf = vec![0u8; 4 << 20];
    let mut copied = 0u64;
    loop {
        let n = blobs.read(&mut buf)?;
        if n == 0 {
            break;
        }
        copied += n as u64;
        if copied > blob_len {
            bail!("payload blob source is longer than the manifest's operation data");
        }
        out.write_all(&buf[..n])?;
        signed.update(&buf[..n]);
        whole.update(&buf[..n]);
    }
    if copied != blob_len {
        bail!("payload blob source has {copied} bytes, the manifest needs {blob_len}");
    }

    let payload_hash: [u8; 32] = signed.finalize().into();
    let payload_signature = signatures_for(key.sign_digest(&payload_hash)?).encode_to_vec();
    out.write_all(&payload_signature)?;
    whole.update(&payload_signature);
    out.flush()?;

    let metadata_size = HEADER_LEN + manifest_bytes.len() as u64;
    let blob_offset = metadata_size + signature_len;
    let file_size = blob_offset + blob_len + signature_len;
    let properties = format!(
        "FILE_HASH={}\nFILE_SIZE={file_size}\nMETADATA_HASH={}\nMETADATA_SIZE={metadata_size}\n",
        base64_encode(&whole.finalize()),
        base64_encode(&metadata_hash),
    );
    Ok(PayloadSummary {
        properties,
        metadata_size,
        blob_offset,
        file_size,
    })
}

/// A payload whose signatures and properties were checked.
#[derive(Debug, Clone)]
pub struct VerifiedPayload {
    pub manifest: DeltaArchiveManifest,
    pub metadata_size: u64,
    pub blob_offset: u64,
}

fn verify_signatures(bytes: &[u8], digest: &[u8; 32], public: &RsaPublicKey) -> Result<()> {
    let signatures = Signatures::decode(bytes).context("decoding payload signatures")?;
    let mut last_error = anyhow!("payload signature block holds no signature");
    for signature in &signatures.signatures {
        let Some(data) = &signature.data else {
            continue;
        };
        let len = signature
            .unpadded_signature_size
            .map_or(data.len(), |n| n as usize)
            .min(data.len());
        match key::verify_digest(public, digest, &data[..len]) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn hash_range(
    reader: &mut (impl Read + Seek),
    start: u64,
    len: u64,
    hashers: &mut [&mut Sha256],
) -> Result<()> {
    reader.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; 4 << 20];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..chunk])?;
        for hasher in hashers.iter_mut() {
            hasher.update(&buf[..chunk]);
        }
        remaining -= chunk as u64;
    }
    Ok(())
}

/// Verify a payload occupying `[start, start + len)` of `reader`: both
/// signatures against `public`, and, when given, `payload_properties.txt`.
pub fn verify_payload(
    reader: &mut (impl Read + Seek),
    start: u64,
    len: u64,
    public: &RsaPublicKey,
    properties: Option<&str>,
) -> Result<VerifiedPayload> {
    let mut header = [0u8; HEADER_LEN as usize];
    reader.seek(SeekFrom::Start(start))?;
    reader.read_exact(&mut header)?;
    if &header[..4] != PAYLOAD_MAGIC {
        bail!("payload.bin has no CrAU magic");
    }
    let version = u64::from_be_bytes(header[4..12].try_into().expect("8 bytes"));
    if version != PAYLOAD_VERSION {
        bail!("unsupported payload major version {version}");
    }
    let manifest_len = u64::from_be_bytes(header[12..20].try_into().expect("8 bytes"));
    let metadata_signature_len = u64::from(u32::from_be_bytes(
        header[20..24].try_into().expect("4 bytes"),
    ));
    let metadata_size = HEADER_LEN
        .checked_add(manifest_len)
        .filter(|&n| n <= len)
        .ok_or_else(|| anyhow!("payload manifest runs past the payload"))?;
    let blob_offset = metadata_size
        .checked_add(metadata_signature_len)
        .filter(|&n| n <= len)
        .ok_or_else(|| anyhow!("payload metadata signature runs past the payload"))?;
    if manifest_len > 64 << 20 {
        bail!("payload manifest of {manifest_len} bytes is implausibly large");
    }
    let mut manifest_bytes = vec![0u8; manifest_len as usize];
    reader.read_exact(&mut manifest_bytes)?;
    let manifest =
        DeltaArchiveManifest::decode(&manifest_bytes[..]).context("decoding payload manifest")?;

    let mut metadata_signature = vec![0u8; metadata_signature_len as usize];
    reader.read_exact(&mut metadata_signature)?;
    let metadata_hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(header);
        hasher.update(&manifest_bytes);
        hasher.finalize().into()
    };
    verify_signatures(&metadata_signature, &metadata_hash, public)
        .context("payload metadata signature does not verify")?;

    let signatures_offset = manifest
        .signatures_offset
        .ok_or_else(|| anyhow!("payload manifest has no signatures_offset"))?;
    let signatures_size = manifest
        .signatures_size
        .ok_or_else(|| anyhow!("payload manifest has no signatures_size"))?;
    let signatures_start = blob_offset
        .checked_add(signatures_offset)
        .ok_or_else(|| anyhow!("payload signatures offset overflows"))?;
    if signatures_start.checked_add(signatures_size) != Some(len) {
        bail!("payload signature block does not end the payload");
    }

    let mut signed = Sha256::new();
    signed.update(header);
    signed.update(&manifest_bytes);
    let mut whole = Sha256::new();
    hash_range(
        reader,
        start + blob_offset,
        signatures_offset,
        &mut [&mut signed],
    )?;
    let payload_hash: [u8; 32] = signed.finalize().into();
    let mut payload_signature = vec![0u8; signatures_size as usize];
    reader.read_exact(&mut payload_signature)?;
    verify_signatures(&payload_signature, &payload_hash, public)
        .context("payload signature does not verify")?;

    if let Some(properties) = properties {
        hash_range(reader, start, len, &mut [&mut whole])?;
        let expected = format!(
            "FILE_HASH={}\nFILE_SIZE={len}\nMETADATA_HASH={}\nMETADATA_SIZE={metadata_size}\n",
            base64_encode(&whole.finalize()),
            base64_encode(&metadata_hash),
        );
        if properties != expected {
            bail!("payload_properties.txt does not match payload.bin");
        }
    }
    Ok(VerifiedPayload {
        manifest,
        metadata_size,
        blob_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::test_key;
    use dynobox_payload::payload::proto::{
        Extent, InstallOperation, PartitionInfo, PartitionUpdate, install_operation::Type,
    };

    fn manifest(data_len: u64) -> DeltaArchiveManifest {
        DeltaArchiveManifest {
            block_size: Some(4096),
            minor_version: Some(0),
            partitions: vec![PartitionUpdate {
                partition_name: "vbmeta".into(),
                new_partition_info: Some(PartitionInfo {
                    size: Some(4096),
                    hash: Some(vec![0; 32]),
                }),
                operations: vec![InstallOperation {
                    r#type: Type::Replace as i32,
                    data_length: Some(data_len),
                    dst_extents: vec![Extent {
                        start_block: Some(0),
                        num_blocks: Some(1),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn writes_a_payload_that_verifies() {
        let key = test_key(2048);
        let blob = vec![0x5A; 4096];
        let mut out = Vec::new();
        let summary = write_signed_payload(&mut out, manifest(4096), &mut &blob[..], &key).unwrap();
        assert_eq!(summary.file_size, out.len() as u64);
        let verified = verify_payload(
            &mut std::io::Cursor::new(&out),
            0,
            out.len() as u64,
            &key.public_key(),
            Some(&summary.properties),
        )
        .unwrap();
        assert_eq!(verified.blob_offset, summary.blob_offset);
        assert_eq!(
            verified.manifest.partitions[0].operations[0].data_offset,
            Some(0)
        );
        // AOSP layout: a 2048-bit signature block is 267 bytes.
        assert_eq!(summary.blob_offset - summary.metadata_size, 267);

        // Wrong key, tampered blob, and a stale properties file all fail.
        let other = test_key(4096).public_key();
        assert!(
            verify_payload(
                &mut std::io::Cursor::new(&out),
                0,
                out.len() as u64,
                &other,
                None
            )
            .is_err()
        );
        let mut tampered = out.clone();
        tampered[summary.blob_offset as usize] ^= 1;
        assert!(
            verify_payload(
                &mut std::io::Cursor::new(&tampered),
                0,
                tampered.len() as u64,
                &key.public_key(),
                None
            )
            .is_err()
        );
        let stale = summary.properties.replace("FILE_SIZE=", "FILE_SIZE=1");
        assert!(
            verify_payload(
                &mut std::io::Cursor::new(&out),
                0,
                out.len() as u64,
                &key.public_key(),
                Some(&stale)
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_a_blob_source_of_the_wrong_length() {
        let key = test_key(2048);
        assert!(
            write_signed_payload(&mut Vec::new(), manifest(4096), &mut &[0u8; 10][..], &key)
                .is_err()
        );
        assert!(
            write_signed_payload(&mut Vec::new(), manifest(4), &mut &[0u8; 10][..], &key).is_err()
        );
    }

    #[test]
    fn verifier_survives_mutated_input() {
        let key = test_key(2048);
        let mut seed = Vec::new();
        write_signed_payload(&mut seed, manifest(16), &mut &[1u8; 16][..], &key).unwrap();
        let public = key.public_key();
        dynobox_core::testutil::for_each_mutation(&seed, 0x9A10, 2000, |bytes| {
            let _ = verify_payload(
                &mut std::io::Cursor::new(bytes),
                0,
                bytes.len() as u64,
                &public,
                None,
            );
        });
    }

    /// Known-good vector: the official payload verifies against the
    /// certificate the OTA ships as `META-INF/com/android/otacert`.
    #[test]
    #[ignore = "fixture: set DYNOBOX_OTA_ZIP"]
    fn verifies_an_official_payload() {
        use std::io::Read as _;
        let path = std::env::var("DYNOBOX_OTA_ZIP").expect("set DYNOBOX_OTA_ZIP");
        let mut zip = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
        let mut cert_pem = Vec::new();
        zip.by_name("META-INF/com/android/otacert")
            .unwrap()
            .read_to_end(&mut cert_pem)
            .unwrap();
        let mut properties = String::new();
        zip.by_name("payload_properties.txt")
            .unwrap()
            .read_to_string(&mut properties)
            .unwrap();
        let (start, len) = {
            let entry = zip.by_name("payload.bin").unwrap();
            (entry.data_start().unwrap(), entry.size())
        };
        let public = crate::Certificate::from_pem_or_der(&cert_pem)
            .unwrap()
            .public_key()
            .unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        verify_payload(&mut file, start, len, &public, Some(&properties)).unwrap();
    }
}
