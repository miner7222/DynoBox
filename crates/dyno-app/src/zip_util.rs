//! Minimal ZIP central-directory reader for patching STORED entries of
//! APK / JAR archives in place, plus the ZIP CRC-32.

use anyhow::{Context, Result, anyhow};

use crate::byte_io::{read_u16_le, read_u32_le};

const ZIP_LOCAL_FILE_HEADER_SIG: u32 = 0x04034B50;
const ZIP_CENTRAL_DIRECTORY_SIG: u32 = 0x02014B50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIG: u32 = 0x06054B50;
const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
pub(crate) const ZIP64_SENTINEL_U32: u32 = 0xFFFFFFFF;

#[derive(Debug, Clone)]
pub(crate) struct ZipEntry {
    pub(crate) name: String,
    pub(crate) data_start: usize,
    pub(crate) compressed_size: usize,
    pub(crate) local_header_offset: usize,
    pub(crate) local_header_crc_offset: usize,
    pub(crate) cd_crc_offset: usize,
    pub(crate) local_header_comp_size_offset: usize,
    pub(crate) cd_comp_size_offset: usize,
    pub(crate) compression_method: u16,
    pub(crate) uses_data_descriptor: bool,
    pub(crate) is_zip64: bool,
}

impl ZipEntry {
    /// A top-level `classes.dex` / `classesN.dex` entry: the dex files ART
    /// actually loads. Dex blobs elsewhere in the archive (e.g. under
    /// `assets/`) are plain data and must be left alone.
    pub(crate) fn is_classes_dex(&self) -> bool {
        self.name
            .strip_prefix("classes")
            .and_then(|rest| rest.strip_suffix(".dex"))
            .is_some_and(|index| index.bytes().all(|b| b.is_ascii_digit()))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ZipLayout {
    pub(crate) entries: Vec<ZipEntry>,
}

pub(crate) fn parse_zip_central_directory(bytes: &[u8]) -> Result<ZipLayout> {
    let eocd_off = find_eocd(bytes)?;
    if bytes.len() < eocd_off + 22 {
        return Err(anyhow!("ZIP truncated at EOCD"));
    }
    let cd_size = read_u32_le(bytes, eocd_off + 12) as usize;
    let cd_off = read_u32_le(bytes, eocd_off + 16) as usize;
    let total_records = read_u16_le(bytes, eocd_off + 10) as usize;

    let mut entries = Vec::with_capacity(total_records);
    let mut cursor = cd_off;
    let cd_end = checked_range_end(cd_off, cd_size, "ZIP central directory")?;
    if cd_end > bytes.len() {
        return Err(anyhow!(
            "ZIP central directory range {}..{} exceeds jar length {}",
            cd_off,
            cd_end,
            bytes.len()
        ));
    }
    while cursor < cd_end {
        let fixed_end = checked_range_end(cursor, 46, "ZIP central directory entry")?;
        if fixed_end > cd_end || fixed_end > bytes.len() {
            return Err(anyhow!("ZIP central directory truncated"));
        }
        let sig = read_u32_le(bytes, cursor);
        if sig != ZIP_CENTRAL_DIRECTORY_SIG {
            return Err(anyhow!(
                "ZIP central directory: unexpected signature {sig:#010x} at offset {cursor}"
            ));
        }
        let cd_flags = read_u16_le(bytes, cursor + 8);
        let compression_method = read_u16_le(bytes, cursor + 10);
        let cd_crc_offset = cursor + 16;
        let compressed_size_raw = read_u32_le(bytes, cursor + 20);
        let uncompressed_size_raw = read_u32_le(bytes, cursor + 24);
        let name_len = read_u16_le(bytes, cursor + 28) as usize;
        let extra_len = read_u16_le(bytes, cursor + 30) as usize;
        let comment_len = read_u16_le(bytes, cursor + 32) as usize;
        let local_header_offset_raw = read_u32_le(bytes, cursor + 42);
        let variable_len = name_len
            .checked_add(extra_len)
            .and_then(|len| len.checked_add(comment_len))
            .ok_or_else(|| anyhow!("ZIP central directory entry length overflow"))?;
        let entry_end = checked_range_end(fixed_end, variable_len, "ZIP central directory entry")?;
        if entry_end > cd_end || entry_end > bytes.len() {
            return Err(anyhow!(
                "ZIP central directory entry at offset {} extends past directory end",
                cursor
            ));
        }
        let name_end = checked_range_end(fixed_end, name_len, "ZIP entry name")?;
        let name = std::str::from_utf8(&bytes[fixed_end..name_end])
            .context("ZIP central directory entry has non-UTF-8 name")?
            .to_string();

        let is_zip64 = compressed_size_raw == ZIP64_SENTINEL_U32
            || uncompressed_size_raw == ZIP64_SENTINEL_U32
            || local_header_offset_raw == ZIP64_SENTINEL_U32;
        let cd_uses_data_descriptor = cd_flags & ZIP_FLAG_DATA_DESCRIPTOR != 0;
        let compressed_size = compressed_size_raw as usize;
        let local_header_offset = local_header_offset_raw as usize;

        let local_fixed_end = checked_range_end(local_header_offset, 30, "ZIP local file header")?;
        if local_fixed_end > bytes.len() {
            return Err(anyhow!("ZIP local file header for {name} truncated"));
        }
        let lfh_sig = read_u32_le(bytes, local_header_offset);
        if lfh_sig != ZIP_LOCAL_FILE_HEADER_SIG {
            return Err(anyhow!(
                "ZIP local file header for {name}: unexpected signature {lfh_sig:#010x}"
            ));
        }
        let lfh_flags = read_u16_le(bytes, local_header_offset + 6);
        let lfh_uses_data_descriptor = lfh_flags & ZIP_FLAG_DATA_DESCRIPTOR != 0;
        let local_header_crc_offset = local_header_offset + 14;
        let local_name_len = read_u16_le(bytes, local_header_offset + 26) as usize;
        let local_extra_len = read_u16_le(bytes, local_header_offset + 28) as usize;
        let local_variable_len = local_name_len
            .checked_add(local_extra_len)
            .ok_or_else(|| anyhow!("ZIP local file header length overflow for {name}"))?;
        let data_start =
            checked_range_end(local_fixed_end, local_variable_len, "ZIP local file header")?;
        let data_end = checked_range_end(data_start, compressed_size, "ZIP entry data")?;
        if data_end > bytes.len() {
            return Err(anyhow!(
                "ZIP entry {} data range {}..{} exceeds jar length {}",
                name,
                data_start,
                data_end,
                bytes.len()
            ));
        }

        entries.push(ZipEntry {
            name,
            data_start,
            compressed_size,
            local_header_offset,
            local_header_crc_offset,
            cd_crc_offset,
            local_header_comp_size_offset: local_header_offset + 18,
            cd_comp_size_offset: cursor + 20,
            compression_method,
            uses_data_descriptor: cd_uses_data_descriptor || lfh_uses_data_descriptor,
            is_zip64,
        });

        cursor = entry_end;
    }
    Ok(ZipLayout { entries })
}

fn find_eocd(bytes: &[u8]) -> Result<usize> {
    let max_back = std::cmp::min(bytes.len(), 65_557);
    let start = bytes.len().saturating_sub(max_back);
    for off in (start..bytes.len().saturating_sub(21)).rev() {
        if read_u32_le(bytes, off) == ZIP_END_OF_CENTRAL_DIRECTORY_SIG {
            return Ok(off);
        }
    }
    Err(anyhow!(
        "ZIP end-of-central-directory signature not found; not a valid ZIP"
    ))
}

pub(crate) fn checked_range_end(start: usize, len: usize, label: &str) -> Result<usize> {
    start
        .checked_add(len)
        .ok_or_else(|| anyhow!("{label} offset overflow"))
}

/// IEEE CRC-32 (the ZIP / PNG polynomial).
pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> ZipEntry {
        ZipEntry {
            name: name.to_string(),
            data_start: 0,
            compressed_size: 0,
            local_header_offset: 0,
            local_header_crc_offset: 0,
            cd_crc_offset: 0,
            local_header_comp_size_offset: 0,
            cd_comp_size_offset: 0,
            compression_method: 0,
            uses_data_descriptor: false,
            is_zip64: false,
        }
    }

    #[test]
    fn is_classes_dex_matches_only_top_level_classes_entries() {
        for name in ["classes.dex", "classes2.dex", "classes13.dex"] {
            assert!(entry(name).is_classes_dex(), "{name}");
        }
        for name in [
            "assets/payload.dex",
            "assets/classes.dex",
            "classesX.dex",
            "classes.dex.bak",
            "lib/classes2.dex",
        ] {
            assert!(!entry(name).is_classes_dex(), "{name}");
        }
    }

    #[test]
    fn crc32_ieee_known_values() {
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn parse_zip_central_directory_rejects_truncated_entry_name() {
        let mut jar = vec![0u8; 46 + 22];
        jar[0..4].copy_from_slice(&ZIP_CENTRAL_DIRECTORY_SIG.to_le_bytes());
        jar[28..30].copy_from_slice(&1000u16.to_le_bytes());
        let eocd = 46;
        jar[eocd..eocd + 4].copy_from_slice(&ZIP_END_OF_CENTRAL_DIRECTORY_SIG.to_le_bytes());
        jar[eocd + 10..eocd + 12].copy_from_slice(&1u16.to_le_bytes());
        jar[eocd + 12..eocd + 16].copy_from_slice(&46u32.to_le_bytes());
        jar[eocd + 16..eocd + 20].copy_from_slice(&0u32.to_le_bytes());

        assert!(parse_zip_central_directory(&jar).is_err());
    }
}
