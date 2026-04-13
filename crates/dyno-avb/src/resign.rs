use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::info;

use crate::crypto::{AvbKey, get_embedded_key};
use crate::parser::{AvbFooter, AvbImageType, AvbVBMetaHeader, detect_avb_image_type};
use dynobox_core::error::{DynoError, Result};

const AVB_DESCRIPTOR_HEADER_SIZE: usize = 16;
const AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE: usize = 92;
const AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResignOutcome {
    Resigned,
    SkippedUnsigned,
}

pub fn resign_image(
    image_path: &Path,
    key_spec: &str,
    algorithm_name: Option<&str>,
    force: bool,
) -> Result<ResignOutcome> {
    // 1. Load key to determine its properties
    let key = if let Some(pem) = get_embedded_key(key_spec) {
        AvbKey::from_pem(pem)?
    } else {
        AvbKey::load_pem(Path::new(key_spec))?
    };

    // 2. Resolve algorithm
    let resolved_algo = match algorithm_name {
        Some(name) => name.to_string(),
        None => key.algorithm()?,
    };

    if resolved_algo != "SHA256_RSA4096"
        && resolved_algo != "SHA256_RSA2048"
        && resolved_algo != "SHA256_RSA8192"
    {
        return Err(DynoError::Tool(format!(
            "Pure Rust signing currently only supports SHA256_RSA2048/4096/8192, not {}",
            resolved_algo
        )));
    }
    if resolved_algo != key.algorithm()? {
        return Err(DynoError::Tool(format!(
            "Requested algorithm {} does not match key size {}",
            resolved_algo,
            key.bits()
        )));
    }

    let mut file = OpenOptions::new().read(true).write(true).open(image_path)?;
    let file_size = file.metadata()?.len();

    let img_type = detect_avb_image_type(image_path)?;
    let footer = match img_type {
        AvbImageType::Vbmeta => None,
        AvbImageType::Footer => {
            file.seek(SeekFrom::End(-64))?;
            Some(AvbFooter::from_reader(&mut file)?)
        }
        AvbImageType::None => return Err(DynoError::Tool("Not an AVB image".into())),
    };
    let (vbmeta_offset, vbmeta_size) = match &footer {
        Some(footer) => (footer.vbmeta_offset, footer.vbmeta_size),
        None => (0, file_size),
    };

    let mut vbmeta_blob = vec![0u8; vbmeta_size as usize];
    file.seek(SeekFrom::Start(vbmeta_offset))?;
    file.read_exact(&mut vbmeta_blob)?;

    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..256])?;
    if header.algorithm_type == 0 && !force {
        info!(
            "Skipping {} because original AVB algorithm is NONE. Use --force to sign unsigned AVB images.",
            image_path.display()
        );
        return Ok(ResignOutcome::SkippedUnsigned);
    }

    let auth_offset = 256;
    let aux_offset = auth_offset + header.authentication_data_block_size as usize;
    let aux_blob = &vbmeta_blob[aux_offset..];

    let descriptors_blob = &aux_blob[header.descriptors_offset as usize
        ..header.descriptors_offset as usize + header.descriptors_size as usize];
    let pkmd_blob = &aux_blob[header.public_key_metadata_offset as usize
        ..header.public_key_metadata_offset as usize + header.public_key_metadata_size as usize];

    let encoded_key = key.encode_public_key();
    let rewritten_descriptors =
        rewrite_descriptors_with_new_chain_key(descriptors_blob, &encoded_key)?;
    let new_pk_size = encoded_key.len();

    let mut new_aux_unpadded = Vec::new();
    new_aux_unpadded.extend_from_slice(&rewritten_descriptors);
    let new_pk_offset = new_aux_unpadded.len();
    new_aux_unpadded.extend_from_slice(&encoded_key);
    let new_pkmd_offset = new_aux_unpadded.len();
    new_aux_unpadded.extend_from_slice(pkmd_blob);

    let new_aux_size = round_to_multiple(new_aux_unpadded.len() as u64, 64) as usize;
    let mut new_aux_blob = new_aux_unpadded;
    new_aux_blob.resize(new_aux_size, 0);

    let mut new_header = header.clone();
    new_header.algorithm_type = match key.bits() {
        2048 => 1,
        4096 => 2,
        8192 => 3,
        _ => 0,
    };
    new_header.public_key_offset = new_pk_offset as u64;
    new_header.public_key_size = new_pk_size as u64;
    new_header.public_key_metadata_offset = if pkmd_blob.is_empty() {
        0
    } else {
        new_pkmd_offset as u64
    };
    new_header.public_key_metadata_size = pkmd_blob.len() as u64;
    new_header.descriptors_offset = 0;
    new_header.descriptors_size = rewritten_descriptors.len() as u64;
    new_header.auxiliary_data_block_size = new_aux_size as u64;

    let sig_size = (key.bits() / 8) as u64;
    let hash_size = 32;
    let auth_block_size = round_to_multiple(hash_size + sig_size, 64);
    new_header.authentication_data_block_size = auth_block_size;
    new_header.hash_offset = 0;
    new_header.hash_size = hash_size;
    new_header.signature_offset = hash_size;
    new_header.signature_size = sig_size;

    let header_bytes = encode_header(&new_header);

    let mut data_to_sign = header_bytes.clone();
    data_to_sign.extend_from_slice(&new_aux_blob);

    let signature = key.sign_sha256(&data_to_sign)?;

    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&data_to_sign);
    let hash = hasher.finalize();

    let mut new_auth_blob = Vec::new();
    new_auth_blob.extend_from_slice(&hash);
    new_auth_blob.extend_from_slice(&signature);
    new_auth_blob.resize(auth_block_size as usize, 0);

    let mut new_vbmeta = header_bytes;
    new_vbmeta.extend_from_slice(&new_auth_blob);
    new_vbmeta.extend_from_slice(&new_aux_blob);

    if let Some(mut footer) = footer {
        let footer_start = file_size
            .checked_sub(64)
            .ok_or_else(|| DynoError::Tool("Footer image smaller than footer size".into()))?;
        let available_space = footer_start
            .checked_sub(vbmeta_offset)
            .ok_or_else(|| DynoError::Tool("Footer image has invalid vbmeta offset".into()))?;
        if new_vbmeta.len() as u64 > available_space {
            return Err(DynoError::Tool(format!(
                "New VBMeta needs {} bytes but only {} bytes available before footer.",
                new_vbmeta.len(),
                available_space
            )));
        }

        file.seek(SeekFrom::Start(vbmeta_offset))?;
        file.write_all(&new_vbmeta)?;
        zero_fill(
            &mut file,
            vbmeta_offset + new_vbmeta.len() as u64,
            available_space - new_vbmeta.len() as u64,
        )?;

        footer.vbmeta_size = new_vbmeta.len() as u64;
        let footer_bytes = encode_footer(&footer);
        file.seek(SeekFrom::Start(footer_start))?;
        file.write_all(&footer_bytes)?;
    } else {
        if new_vbmeta.len() as u64 > file_size {
            file.set_len(new_vbmeta.len() as u64)?;
        }
        file.seek(SeekFrom::Start(vbmeta_offset))?;
        file.write_all(&new_vbmeta)?;
        if (new_vbmeta.len() as u64) < file_size {
            zero_fill(
                &mut file,
                vbmeta_offset + new_vbmeta.len() as u64,
                file_size - new_vbmeta.len() as u64,
            )?;
        }
    }

    info!(
        "Successfully re-signed {} using pure Rust ({}).",
        image_path.display(),
        resolved_algo
    );
    Ok(ResignOutcome::Resigned)
}

fn round_to_multiple(number: u64, size: u64) -> u64 {
    let remainder = number % size;
    if remainder == 0 {
        number
    } else {
        number + size - remainder
    }
}

fn encode_header(h: &AvbVBMetaHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&h.magic);
    buf.write_u32::<BigEndian>(h.required_libavb_version_major)
        .unwrap();
    buf.write_u32::<BigEndian>(h.required_libavb_version_minor)
        .unwrap();
    buf.write_u64::<BigEndian>(h.authentication_data_block_size)
        .unwrap();
    buf.write_u64::<BigEndian>(h.auxiliary_data_block_size)
        .unwrap();
    buf.write_u32::<BigEndian>(h.algorithm_type).unwrap();
    buf.write_u64::<BigEndian>(h.hash_offset).unwrap();
    buf.write_u64::<BigEndian>(h.hash_size).unwrap();
    buf.write_u64::<BigEndian>(h.signature_offset).unwrap();
    buf.write_u64::<BigEndian>(h.signature_size).unwrap();
    buf.write_u64::<BigEndian>(h.public_key_offset).unwrap();
    buf.write_u64::<BigEndian>(h.public_key_size).unwrap();
    buf.write_u64::<BigEndian>(h.public_key_metadata_offset)
        .unwrap();
    buf.write_u64::<BigEndian>(h.public_key_metadata_size)
        .unwrap();
    buf.write_u64::<BigEndian>(h.descriptors_offset).unwrap();
    buf.write_u64::<BigEndian>(h.descriptors_size).unwrap();
    buf.write_u64::<BigEndian>(h.rollback_index).unwrap();
    buf.write_u32::<BigEndian>(h.flags).unwrap();
    buf.write_u32::<BigEndian>(h.rollback_index_location)
        .unwrap();

    let mut rel = [0u8; 48];
    let rel_bytes = h.release_string.as_bytes();
    let len = std::cmp::min(rel_bytes.len(), 47);
    rel[..len].copy_from_slice(&rel_bytes[..len]);
    buf.extend_from_slice(&rel);

    buf.resize(256, 0);
    buf
}

fn encode_footer(footer: &AvbFooter) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&footer.magic);
    buf.write_u32::<BigEndian>(footer.version_major).unwrap();
    buf.write_u32::<BigEndian>(footer.version_minor).unwrap();
    buf.write_u64::<BigEndian>(footer.original_image_size)
        .unwrap();
    buf.write_u64::<BigEndian>(footer.vbmeta_offset).unwrap();
    buf.write_u64::<BigEndian>(footer.vbmeta_size).unwrap();
    buf.resize(64, 0);
    buf
}

fn rewrite_descriptors_with_new_chain_key(
    descriptors_blob: &[u8],
    new_key: &[u8],
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(descriptors_blob.len());
    let mut offset = 0usize;

    while offset < descriptors_blob.len() {
        let remaining = &descriptors_blob[offset..];
        if remaining.len() < AVB_DESCRIPTOR_HEADER_SIZE {
            return Err(DynoError::Tool(
                "Descriptor blob ends mid-header while resigning.".into(),
            ));
        }

        let mut cursor = std::io::Cursor::new(&remaining[..AVB_DESCRIPTOR_HEADER_SIZE]);
        let tag = cursor.read_u64::<BigEndian>()?;
        let num_bytes_following = cursor.read_u64::<BigEndian>()?;
        let total_len = AVB_DESCRIPTOR_HEADER_SIZE
            .checked_add(num_bytes_following as usize)
            .ok_or_else(|| DynoError::Tool("Descriptor size overflow while resigning.".into()))?;
        if total_len > remaining.len() {
            return Err(DynoError::Tool(
                "Descriptor blob truncated while resigning.".into(),
            ));
        }

        let descriptor = &remaining[..total_len];
        if tag == AVB_DESCRIPTOR_TAG_CHAIN_PARTITION {
            output.extend_from_slice(&rewrite_chain_partition_descriptor(descriptor, new_key)?);
        } else {
            output.extend_from_slice(descriptor);
        }
        offset += total_len;
    }

    Ok(output)
}

fn rewrite_chain_partition_descriptor(descriptor: &[u8], new_key: &[u8]) -> Result<Vec<u8>> {
    if descriptor.len() < AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE {
        return Err(DynoError::Tool(
            "Chain partition descriptor shorter than header.".into(),
        ));
    }

    let mut cursor = std::io::Cursor::new(
        &descriptor[AVB_DESCRIPTOR_HEADER_SIZE..AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE],
    );
    let rollback_index_location = cursor.read_u32::<BigEndian>()?;
    let partition_name_len = cursor.read_u32::<BigEndian>()? as usize;
    let public_key_len = cursor.read_u32::<BigEndian>()? as usize;
    let flags = cursor.read_u32::<BigEndian>()?;

    let body = &descriptor[AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE..];
    let needed = partition_name_len
        .checked_add(public_key_len)
        .ok_or_else(|| DynoError::Tool("Chain descriptor body size overflow.".into()))?;
    if body.len() < needed {
        return Err(DynoError::Tool("Chain descriptor body truncated.".into()));
    }
    let partition_name = &body[..partition_name_len];

    let new_num_bytes_following = round_to_multiple(
        (AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE - AVB_DESCRIPTOR_HEADER_SIZE
            + partition_name_len
            + new_key.len()) as u64,
        8,
    );

    let mut out = Vec::with_capacity(AVB_DESCRIPTOR_HEADER_SIZE + new_num_bytes_following as usize);
    out.write_u64::<BigEndian>(AVB_DESCRIPTOR_TAG_CHAIN_PARTITION)?;
    out.write_u64::<BigEndian>(new_num_bytes_following)?;
    out.write_u32::<BigEndian>(rollback_index_location)?;
    out.write_u32::<BigEndian>(partition_name_len as u32)?;
    out.write_u32::<BigEndian>(new_key.len() as u32)?;
    out.write_u32::<BigEndian>(flags)?;
    out.extend_from_slice(&[0u8; 60]);
    out.extend_from_slice(partition_name);
    out.extend_from_slice(new_key);
    out.resize(
        AVB_DESCRIPTOR_HEADER_SIZE + new_num_bytes_following as usize,
        0,
    );
    Ok(out)
}

fn zero_fill(file: &mut std::fs::File, start: u64, size: u64) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(start))?;
    let zeros = [0u8; 8192];
    let mut remaining = size;
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    Ok(())
}

pub fn rebuild_vbmeta_image(
    _output_path: &Path,
    _original_vbmeta_path: &Path,
    _chained_images: &[&Path],
    _key_spec: &str,
    _algorithm_name: Option<&str>,
) -> Result<()> {
    Err(DynoError::Tool(
        "Pure Rust vbmeta rebuilding is not yet implemented.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AVB_MAGIC, AvbVBMetaHeader};
    use std::fs;
    use tempfile::tempdir;

    fn write_minimal_vbmeta(path: &Path, algorithm_type: u32) {
        let header = AvbVBMetaHeader {
            magic: *AVB_MAGIC,
            required_libavb_version_major: 1,
            required_libavb_version_minor: 0,
            authentication_data_block_size: 0,
            auxiliary_data_block_size: 0,
            algorithm_type,
            hash_offset: 0,
            hash_size: 0,
            signature_offset: 0,
            signature_size: 0,
            public_key_offset: 0,
            public_key_size: 0,
            public_key_metadata_offset: 0,
            public_key_metadata_size: 0,
            descriptors_offset: 0,
            descriptors_size: 0,
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            release_string: "avbtool 1.3.0".to_string(),
        };

        fs::write(path, encode_header(&header)).unwrap();
    }

    #[test]
    fn skip_unsigned_image_without_force() {
        let dir = tempdir().unwrap();
        let image_path = dir.path().join("unsigned.img");
        write_minimal_vbmeta(&image_path, 0);

        let before = fs::read(&image_path).unwrap();
        let outcome = resign_image(&image_path, "testkey_rsa2048", None, false).unwrap();
        let after = fs::read(&image_path).unwrap();
        let header = AvbVBMetaHeader::from_reader(&after[..256]).unwrap();

        assert_eq!(outcome, ResignOutcome::SkippedUnsigned);
        assert_eq!(before, after);
        assert_eq!(header.algorithm_type, 0);
    }

    #[test]
    fn force_sign_unsigned_image() {
        let dir = tempdir().unwrap();
        let image_path = dir.path().join("unsigned.img");
        write_minimal_vbmeta(&image_path, 0);

        let outcome = resign_image(&image_path, "testkey_rsa2048", None, true).unwrap();
        let after = fs::read(&image_path).unwrap();
        let header = AvbVBMetaHeader::from_reader(&after[..256]).unwrap();

        assert_eq!(outcome, ResignOutcome::Resigned);
        assert_eq!(header.algorithm_type, 1);
        assert!(after.len() > 256);
    }
}
