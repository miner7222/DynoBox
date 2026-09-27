//! Minimal STORE-only zip writer for OTA packages.
//!
//! update_engine reads `payload.bin` straight from the package at the offsets
//! recorded in the metadata, so every entry is stored uncompressed with no
//! data descriptor, and each entry's data offset is known up front. Entries
//! and offsets past 4 GiB use zip64 records. Timestamps are fixed at the zip
//! epoch so output is reproducible.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use anyhow::{Context, Result, bail};

const LOCAL_HEADER_SIG: u32 = 0x0403_4B50;
const CENTRAL_HEADER_SIG: u32 = 0x0201_4B50;
const EOCD_SIG: u32 = 0x0605_4B50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4B50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4B50;
const ZIP64_EXTRA_ID: u16 = 0x0001;
const U32_MAX: u64 = 0xFFFF_FFFF;
const DOS_DATE: u16 = 0x0021;

struct CentralEntry {
    name: String,
    crc: u32,
    size: u64,
    header_offset: u64,
}

pub(crate) struct ZipWriter {
    file: File,
    position: u64,
    entries: Vec<CentralEntry>,
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn clamp32(v: u64) -> u32 {
    v.min(U32_MAX) as u32
}

impl ZipWriter {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file,
            position: 0,
            entries: Vec::new(),
        }
    }

    /// Offset where the next entry's local header begins.
    pub(crate) fn position(&self) -> u64 {
        self.position
    }

    /// Local header length for an entry, i.e. its data offset minus its
    /// header offset.
    pub(crate) fn local_header_len(name: &str, size: u64) -> u64 {
        30 + name.len() as u64 + if size >= U32_MAX { 20 } else { 0 }
    }

    fn local_header(name: &str, crc: u32, size: u64) -> Vec<u8> {
        let zip64 = size >= U32_MAX;
        let mut out = Vec::new();
        put32(&mut out, LOCAL_HEADER_SIG);
        put16(&mut out, if zip64 { 45 } else { 20 });
        put16(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, DOS_DATE);
        put32(&mut out, crc);
        put32(&mut out, if zip64 { u32::MAX } else { size as u32 });
        put32(&mut out, if zip64 { u32::MAX } else { size as u32 });
        put16(&mut out, name.len() as u16);
        put16(&mut out, if zip64 { 20 } else { 0 });
        out.extend_from_slice(name.as_bytes());
        if zip64 {
            put16(&mut out, ZIP64_EXTRA_ID);
            put16(&mut out, 16);
            put64(&mut out, size);
            put64(&mut out, size);
        }
        out
    }

    /// Add a stored entry of exactly `size` bytes from `reader`; returns the
    /// entry's data offset.
    pub(crate) fn add_reader(
        &mut self,
        name: &str,
        reader: &mut impl Read,
        size: u64,
    ) -> Result<u64> {
        if name.len() > usize::from(u16::MAX) || !name.is_ascii() {
            bail!("zip entry name {name:?} is not a short ASCII path");
        }
        let header_offset = self.position;
        // The CRC is not known yet; write the header, stream the data, then
        // patch the CRC fields in place.
        let placeholder = Self::local_header(name, 0, size);
        self.file.write_all(&placeholder)?;
        let mut hasher = crc32fast::Hasher::new();
        let mut buf = vec![0u8; 4 << 20];
        let mut remaining = size;
        while remaining > 0 {
            let chunk = remaining.min(buf.len() as u64) as usize;
            reader
                .read_exact(&mut buf[..chunk])
                .with_context(|| format!("reading data for zip entry {name}"))?;
            hasher.update(&buf[..chunk]);
            self.file.write_all(&buf[..chunk])?;
            remaining -= chunk as u64;
        }
        let crc = hasher.finalize();
        let data_offset = header_offset + placeholder.len() as u64;
        self.file.seek(SeekFrom::Start(header_offset + 14))?;
        self.file.write_all(&crc.to_le_bytes())?;
        self.file.seek(SeekFrom::Start(data_offset + size))?;
        self.position = data_offset + size;
        self.entries.push(CentralEntry {
            name: name.to_string(),
            crc,
            size,
            header_offset,
        });
        Ok(data_offset)
    }

    pub(crate) fn add_bytes(&mut self, name: &str, data: &[u8]) -> Result<u64> {
        self.add_reader(name, &mut &data[..], data.len() as u64)
    }

    /// Write the central directory and an EOCD with an empty comment.
    pub(crate) fn finish(mut self) -> Result<File> {
        let cd_offset = self.position;
        let mut cd = Vec::new();
        for entry in &self.entries {
            let big_size = entry.size >= U32_MAX;
            let big_offset = entry.header_offset >= U32_MAX;
            let mut extra = Vec::new();
            if big_size {
                put64(&mut extra, entry.size);
                put64(&mut extra, entry.size);
            }
            if big_offset {
                put64(&mut extra, entry.header_offset);
            }
            let zip64 = !extra.is_empty();
            put32(&mut cd, CENTRAL_HEADER_SIG);
            put16(&mut cd, if zip64 { 45 } else { 20 });
            put16(&mut cd, if zip64 { 45 } else { 20 });
            put16(&mut cd, 0);
            put16(&mut cd, 0);
            put16(&mut cd, 0);
            put16(&mut cd, DOS_DATE);
            put32(&mut cd, entry.crc);
            put32(&mut cd, clamp32(entry.size));
            put32(&mut cd, clamp32(entry.size));
            put16(&mut cd, entry.name.len() as u16);
            put16(&mut cd, if zip64 { extra.len() as u16 + 4 } else { 0 });
            put16(&mut cd, 0);
            put16(&mut cd, 0);
            put16(&mut cd, 0);
            put32(&mut cd, 0);
            put32(&mut cd, clamp32(entry.header_offset));
            cd.extend_from_slice(entry.name.as_bytes());
            if zip64 {
                put16(&mut cd, ZIP64_EXTRA_ID);
                put16(&mut cd, extra.len() as u16);
                cd.extend_from_slice(&extra);
            }
        }
        let cd_size = cd.len() as u64;
        let count = self.entries.len() as u64;
        let mut tail = cd;
        let needs_zip64 = count >= 0xFFFF || cd_size >= U32_MAX || cd_offset >= U32_MAX;
        if needs_zip64 {
            let zip64_eocd_offset = cd_offset + cd_size;
            put32(&mut tail, ZIP64_EOCD_SIG);
            put64(&mut tail, 44);
            put16(&mut tail, 45);
            put16(&mut tail, 45);
            put32(&mut tail, 0);
            put32(&mut tail, 0);
            put64(&mut tail, count);
            put64(&mut tail, count);
            put64(&mut tail, cd_size);
            put64(&mut tail, cd_offset);
            put32(&mut tail, ZIP64_LOCATOR_SIG);
            put32(&mut tail, 0);
            put64(&mut tail, zip64_eocd_offset);
            put32(&mut tail, 1);
        }
        put32(&mut tail, EOCD_SIG);
        put16(&mut tail, 0);
        put16(&mut tail, 0);
        put16(&mut tail, count.min(0xFFFF) as u16);
        put16(&mut tail, count.min(0xFFFF) as u16);
        put32(&mut tail, clamp32(cd_size));
        put32(&mut tail, clamp32(cd_offset));
        put16(&mut tail, 0);
        self.file.write_all(&tail)?;
        self.file.flush()?;
        Ok(self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_zip_other_readers_accept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.zip");
        let mut writer = ZipWriter::new(File::create(&path).unwrap());
        let a = writer.add_bytes("payload.bin", b"payload").unwrap();
        assert_eq!(a, ZipWriter::local_header_len("payload.bin", 7));
        let before_b = writer.position();
        let b = writer
            .add_bytes("META-INF/com/android/metadata", b"k=v\n")
            .unwrap();
        assert_eq!(
            b,
            before_b + ZipWriter::local_header_len("META-INF/com/android/metadata", 4)
        );
        writer.finish().unwrap();

        let mut zip = zip::ZipArchive::new(File::open(&path).unwrap()).unwrap();
        let mut entry = zip.by_name("payload.bin").unwrap();
        assert_eq!(entry.data_start(), Some(a));
        let mut text = String::new();
        entry.read_to_string(&mut text).unwrap();
        assert_eq!(text, "payload");
        drop(entry);
        let mut entry = zip.by_name("META-INF/com/android/metadata").unwrap();
        let mut text = String::new();
        entry.read_to_string(&mut text).unwrap();
        assert_eq!(text, "k=v\n");
    }
}
