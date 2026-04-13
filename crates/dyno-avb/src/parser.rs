use byteorder::{BigEndian, ReadBytesExt};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use dynobox_core::error::{DynoError, Result};

pub const AVB_MAGIC: &[u8; 4] = b"AVB0";
pub const AVB_FOOTER_MAGIC: &[u8; 4] = b"AVBf";
pub const AVB_VBMETA_IMAGE_HEADER_SIZE: usize = 256;
pub const AVB_FOOTER_SIZE: u64 = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AvbImageType {
    Vbmeta, // Standalone vbmeta image (starts with AVB0)
    Footer, // Image with footer (ends with AVBf)
    None,   // Neither
}

#[derive(Debug, Clone, Serialize)]
pub struct AvbVBMetaHeader {
    pub magic: [u8; 4],
    pub required_libavb_version_major: u32,
    pub required_libavb_version_minor: u32,
    pub authentication_data_block_size: u64,
    pub auxiliary_data_block_size: u64,
    pub algorithm_type: u32,
    pub hash_offset: u64,
    pub hash_size: u64,
    pub signature_offset: u64,
    pub signature_size: u64,
    pub public_key_offset: u64,
    pub public_key_size: u64,
    pub public_key_metadata_offset: u64,
    pub public_key_metadata_size: u64,
    pub descriptors_offset: u64,
    pub descriptors_size: u64,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    pub release_string: String,
}

impl AvbVBMetaHeader {
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != AVB_MAGIC {
            return Err(DynoError::Tool("Invalid VBMeta magic".into()));
        }

        let required_libavb_version_major = reader.read_u32::<BigEndian>()?;
        let required_libavb_version_minor = reader.read_u32::<BigEndian>()?;
        let authentication_data_block_size = reader.read_u64::<BigEndian>()?;
        let auxiliary_data_block_size = reader.read_u64::<BigEndian>()?;
        let algorithm_type = reader.read_u32::<BigEndian>()?;
        let hash_offset = reader.read_u64::<BigEndian>()?;
        let hash_size = reader.read_u64::<BigEndian>()?;
        let signature_offset = reader.read_u64::<BigEndian>()?;
        let signature_size = reader.read_u64::<BigEndian>()?;
        let public_key_offset = reader.read_u64::<BigEndian>()?;
        let public_key_size = reader.read_u64::<BigEndian>()?;
        let public_key_metadata_offset = reader.read_u64::<BigEndian>()?;
        let public_key_metadata_size = reader.read_u64::<BigEndian>()?;
        let descriptors_offset = reader.read_u64::<BigEndian>()?;
        let descriptors_size = reader.read_u64::<BigEndian>()?;
        let rollback_index = reader.read_u64::<BigEndian>()?;
        let flags = reader.read_u32::<BigEndian>()?;
        let rollback_index_location = reader.read_u32::<BigEndian>()?;

        let mut release_bytes = [0u8; 48];
        reader.read_exact(&mut release_bytes)?;
        let release_string = String::from_utf8_lossy(&release_bytes)
            .trim_matches(char::from(0))
            .to_string();

        Ok(Self {
            magic,
            required_libavb_version_major,
            required_libavb_version_minor,
            authentication_data_block_size,
            auxiliary_data_block_size,
            algorithm_type,
            hash_offset,
            hash_size,
            signature_offset,
            signature_size,
            public_key_offset,
            public_key_size,
            public_key_metadata_offset,
            public_key_metadata_size,
            descriptors_offset,
            descriptors_size,
            rollback_index,
            flags,
            rollback_index_location,
            release_string,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AvbFooter {
    pub magic: [u8; 4],
    pub version_major: u32,
    pub version_minor: u32,
    pub original_image_size: u64,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
}

impl AvbFooter {
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != AVB_FOOTER_MAGIC {
            return Err(DynoError::Tool("Invalid AVB footer magic".into()));
        }

        let version_major = reader.read_u32::<BigEndian>()?;
        let version_minor = reader.read_u32::<BigEndian>()?;
        let original_image_size = reader.read_u64::<BigEndian>()?;
        let vbmeta_offset = reader.read_u64::<BigEndian>()?;
        let vbmeta_size = reader.read_u64::<BigEndian>()?;

        Ok(Self {
            magic,
            version_major,
            version_minor,
            original_image_size,
            vbmeta_offset,
            vbmeta_size,
        })
    }
}

pub fn detect_avb_image_type(path: &Path) -> Result<AvbImageType> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();

    // 1. Check for AVB0 at the beginning
    if file_size >= 4 {
        let mut header_magic = [0u8; 4];
        file.read_exact(&mut header_magic)?;
        if &header_magic == AVB_MAGIC {
            return Ok(AvbImageType::Vbmeta);
        }
    }

    // 2. Check for AVBf at the end
    if file_size >= AVB_FOOTER_SIZE {
        file.seek(SeekFrom::End(-(AVB_FOOTER_SIZE as i64)))?;
        let mut footer_magic = [0u8; 4];
        file.read_exact(&mut footer_magic)?;
        if &footer_magic == AVB_FOOTER_MAGIC {
            return Ok(AvbImageType::Footer);
        }
    }

    Ok(AvbImageType::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_detect_vbmeta() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        file.write_all(AVB_MAGIC)?;
        file.write_all(&[0u8; 100])?;
        file.flush()?;

        let img_type = detect_avb_image_type(file.path())?;
        assert_eq!(img_type, AvbImageType::Vbmeta);
        Ok(())
    }

    #[test]
    fn test_detect_footer() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        file.write_all(&[0u8; 100])?;

        let mut footer = vec![0u8; AVB_FOOTER_SIZE as usize];
        footer[0..4].copy_from_slice(AVB_FOOTER_MAGIC);
        file.write_all(&footer)?;
        file.flush()?;

        let img_type = detect_avb_image_type(file.path())?;
        assert_eq!(img_type, AvbImageType::Footer);
        Ok(())
    }
}
