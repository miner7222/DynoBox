//! In-place edits of files inside an Android boot image's ramdisk (header
//! v3/v4, e.g. `recovery.img`), keeping the image's AVB hash footer
//! consistent.
//!
//! The ramdisk (LZ4 legacy or gzip, newc cpio) is decompressed, a file's
//! bytes are rewritten at the same length, the ramdisk is recompressed, the
//! boot image is rebuilt around it, and the AVB hash descriptor's image size
//! and digest are recomputed. The vbmeta signature is left stale for the
//! resign loop to refresh.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
const PAGE: usize = 4096;
const LZ4_LEGACY_MAGIC: [u8; 4] = [0x02, 0x21, 0x4C, 0x18];
const LZ4_LEGACY_BLOCK: usize = 8 << 20;
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
const AVB_FOOTER_MAGIC: &[u8; 4] = b"AVBf";
const AVB_FOOTER_LEN: usize = 64;
const AVB_HASH_DESCRIPTOR_TAG: u64 = 2;

/// Whether `path` starts with the Android boot image magic.
pub(crate) fn is_boot_image(path: &Path) -> Result<bool> {
    let mut magic = [0u8; 8];
    let mut file = std::fs::File::open(path)?;
    Ok(file.read(&mut magic)? == 8 && &magic == BOOT_MAGIC)
}

fn align(n: usize) -> usize {
    n.div_ceil(PAGE) * PAGE
}

fn u32_le(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| anyhow!("boot image header truncated"))
}

fn u32_be(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| anyhow!("AVB data truncated at {at}"))
}

fn u64_be(data: &[u8], at: usize) -> Result<u64> {
    data.get(at..at + 8)
        .map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes")))
        .ok_or_else(|| anyhow!("AVB data truncated at {at}"))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Compression {
    Lz4Legacy,
    Gzip,
}

fn decompress(ramdisk: &[u8]) -> Result<(Compression, Vec<u8>)> {
    if ramdisk.starts_with(&LZ4_LEGACY_MAGIC) {
        let mut out = Vec::new();
        let mut at = 4;
        while at + 4 <= ramdisk.len() {
            let len = u32_le(ramdisk, at)? as usize;
            at += 4;
            if len == u32::from_le_bytes(LZ4_LEGACY_MAGIC) as usize {
                continue; // concatenated stream
            }
            if len == 0 {
                break;
            }
            let block = ramdisk
                .get(at..at + len)
                .ok_or_else(|| anyhow!("LZ4 legacy block runs past the ramdisk"))?;
            out.extend(
                lz4_flex::block::decompress(block, LZ4_LEGACY_BLOCK)
                    .map_err(|e| anyhow!("LZ4 legacy block: {e}"))?,
            );
            at += len;
        }
        Ok((Compression::Lz4Legacy, out))
    } else if ramdisk.starts_with(&GZIP_MAGIC) {
        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(ramdisk)
            .read_to_end(&mut out)
            .context("gunzipping the ramdisk")?;
        Ok((Compression::Gzip, out))
    } else {
        bail!("unsupported ramdisk compression (expected LZ4 legacy or gzip)")
    }
}

fn compress(kind: Compression, data: &[u8]) -> Result<Vec<u8>> {
    match kind {
        Compression::Lz4Legacy => {
            let mut out = LZ4_LEGACY_MAGIC.to_vec();
            for chunk in data.chunks(LZ4_LEGACY_BLOCK) {
                let block = lz4_flex::block::compress(chunk);
                out.extend_from_slice(&(block.len() as u32).to_le_bytes());
                out.extend_from_slice(&block);
            }
            Ok(out)
        }
        Compression::Gzip => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(data)?;
            Ok(encoder.finish()?)
        }
    }
}

/// Byte range of `name`'s data inside a newc cpio archive, and whether the
/// archive uses the checksummed `070702` variant.
fn cpio_find(cpio: &[u8], name: &str) -> Result<Option<(usize, usize, usize)>> {
    let field = |at: usize, index: usize| -> Result<usize> {
        let start = at + 6 + index * 8;
        let hex = cpio
            .get(start..start + 8)
            .ok_or_else(|| anyhow!("cpio header truncated"))?;
        usize::from_str_radix(std::str::from_utf8(hex)?, 16).context("cpio header field")
    };
    let mut at = 0;
    while at + 110 <= cpio.len() {
        let magic = &cpio[at..at + 6];
        if magic != b"070701" && magic != b"070702" {
            bail!("not a newc cpio archive at offset {at}");
        }
        let file_size = field(at, 6)?;
        let name_size = field(at, 11)?;
        let name_start = at + 110;
        let entry_name = cpio
            .get(name_start..name_start + name_size.saturating_sub(1))
            .ok_or_else(|| anyhow!("cpio name truncated"))?;
        let data_start = (name_start + name_size).div_ceil(4) * 4;
        if entry_name == b"TRAILER!!!" {
            return Ok(None);
        }
        if entry_name == name.as_bytes() {
            if data_start + file_size > cpio.len() {
                bail!("cpio entry {name} runs past the archive");
            }
            return Ok(Some((at, data_start, file_size)));
        }
        at = (data_start + file_size).div_ceil(4) * 4;
    }
    bail!("cpio archive has no trailer")
}

/// Rewrite `file` inside the ramdisk of the boot image at `image_path` with
/// `edit`, which must keep the length. Returns `false` when the ramdisk has
/// no such file; the image is untouched then.
pub(crate) fn edit_ramdisk_file(
    image_path: &Path,
    file: &str,
    edit: impl FnOnce(&mut Vec<u8>) -> Result<()>,
) -> Result<bool> {
    let image =
        std::fs::read(image_path).with_context(|| format!("reading {}", image_path.display()))?;
    if !image.starts_with(BOOT_MAGIC) {
        bail!("{} is not an Android boot image", image_path.display());
    }
    let version = u32_le(&image, 40)?;
    if !(3..=4).contains(&version) {
        bail!("boot image header v{version} is not supported (only v3 and v4)");
    }
    let kernel_size = u32_le(&image, 8)? as usize;
    let ramdisk_size = u32_le(&image, 12)? as usize;
    let signature_size = if version == 4 {
        u32_le(&image, 1580)? as usize
    } else {
        0
    };
    let ramdisk_start = PAGE + align(kernel_size);
    let signature_start = ramdisk_start + align(ramdisk_size);
    let content_end = signature_start + align(signature_size);
    if content_end > image.len() {
        bail!("boot image sections run past the file");
    }

    let (kind, mut cpio) = decompress(&image[ramdisk_start..ramdisk_start + ramdisk_size])?;
    let Some((header_at, data_at, len)) = cpio_find(&cpio, file)? else {
        return Ok(false);
    };
    let mut content = cpio[data_at..data_at + len].to_vec();
    edit(&mut content)?;
    if content.len() != len {
        bail!("ramdisk edit changed the length of {file}");
    }
    if content == cpio[data_at..data_at + len] {
        return Ok(true);
    }
    cpio[data_at..data_at + len].copy_from_slice(&content);
    if &cpio[header_at..header_at + 6] == b"070702" {
        let checksum = content
            .iter()
            .fold(0u32, |acc, &b| acc.wrapping_add(u32::from(b)));
        cpio[header_at + 102..header_at + 110]
            .copy_from_slice(format!("{checksum:08X}").as_bytes());
    }
    let ramdisk = compress(kind, &cpio)?;

    // Rebuild: header page, kernel, new ramdisk, boot signature.
    let mut rebuilt = image[..ramdisk_start].to_vec();
    rebuilt[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
    rebuilt.extend_from_slice(&ramdisk);
    rebuilt.resize(align(rebuilt.len()), 0);
    rebuilt.extend_from_slice(&image[signature_start..signature_start + signature_size]);
    rebuilt.resize(align(rebuilt.len()), 0);

    let out = rewrite_avb_hash_footer(&image, rebuilt, content_end)?;
    std::fs::write(image_path, out).with_context(|| format!("writing {}", image_path.display()))?;
    Ok(true)
}

/// Place `content` in front of `image`'s AVB footer, updating the hash
/// descriptor's image size and digest. Images without a footer are returned
/// as `content` padded to the original length.
fn rewrite_avb_hash_footer(
    image: &[u8],
    content: Vec<u8>,
    old_content_end: usize,
) -> Result<Vec<u8>> {
    let total = image.len();
    let footer = &image[total.saturating_sub(AVB_FOOTER_LEN)..];
    if total < AVB_FOOTER_LEN || &footer[..4] != AVB_FOOTER_MAGIC {
        if content.len() > total {
            bail!("rebuilt boot image no longer fits the original size");
        }
        let mut out = content;
        out.resize(total.max(old_content_end), 0);
        return Ok(out);
    }
    let original_size = u64_be(footer, 12)? as usize;
    let vbmeta_offset = u64_be(footer, 20)? as usize;
    let vbmeta_size = u64_be(footer, 28)? as usize;
    let mut vbmeta = image
        .get(vbmeta_offset..vbmeta_offset + vbmeta_size)
        .ok_or_else(|| anyhow!("AVB vbmeta blob runs past the image"))?
        .to_vec();
    if original_size != old_content_end {
        bail!("AVB image size {original_size} does not match the boot image layout");
    }

    // Find and update the hash descriptor.
    let auth_size = u64_be(&vbmeta, 12)? as usize;
    let descriptors_offset = u64_be(&vbmeta, 96)? as usize;
    let descriptors_size = u64_be(&vbmeta, 104)? as usize;
    let base = 256 + auth_size + descriptors_offset;
    let end = base + descriptors_size;
    if end > vbmeta.len() {
        bail!("AVB descriptors run past the vbmeta blob");
    }
    let new_size = content.len();
    let mut at = base;
    let mut updated = false;
    while at + 16 <= end {
        let tag = u64_be(&vbmeta, at)?;
        let len = u64_be(&vbmeta, at + 8)? as usize;
        let body = at + 16;
        if body + len > end {
            bail!("AVB descriptor runs past the descriptor area");
        }
        if tag == AVB_HASH_DESCRIPTOR_TAG {
            let algorithm = &vbmeta[body + 8..body + 40];
            if !algorithm.starts_with(b"sha256\0") {
                bail!("AVB hash descriptor uses an unsupported algorithm");
            }
            let name_len = u32_be(&vbmeta, body + 40)? as usize;
            let salt_len = u32_be(&vbmeta, body + 44)? as usize;
            let digest_len = u32_be(&vbmeta, body + 48)? as usize;
            let salt_at = body + 116 + name_len;
            let digest_at = salt_at + salt_len;
            if digest_len != 32 || digest_at + 32 > body + len {
                bail!("malformed AVB hash descriptor");
            }
            let mut hasher = Sha256::new();
            hasher.update(&vbmeta[salt_at..salt_at + salt_len]);
            hasher.update(&content);
            let digest = hasher.finalize();
            vbmeta[body..body + 8].copy_from_slice(&(new_size as u64).to_be_bytes());
            vbmeta[digest_at..digest_at + 32].copy_from_slice(&digest);
            updated = true;
        }
        at = body + len;
    }
    if !updated {
        bail!("boot image AVB footer has no hash descriptor");
    }

    // Content, vbmeta right after it, zero padding, footer at the very end.
    if new_size + vbmeta.len() + AVB_FOOTER_LEN > total {
        bail!("rebuilt boot image no longer fits its partition");
    }
    let mut out = content;
    out.extend_from_slice(&vbmeta);
    out.resize(total - AVB_FOOTER_LEN, 0);
    let mut new_footer = footer.to_vec();
    new_footer[12..20].copy_from_slice(&(new_size as u64).to_be_bytes());
    new_footer[20..28].copy_from_slice(&(new_size as u64).to_be_bytes());
    out.extend_from_slice(&new_footer);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn newc_entry(name: &str, data: &[u8], magic: &[u8; 6]) -> Vec<u8> {
        let mut out = magic.to_vec();
        let fields = [
            1,
            0o100644,
            0,
            0,
            1,
            0,
            data.len(),
            0,
            0,
            0,
            0,
            name.len() + 1,
            0,
        ];
        for value in fields {
            out.extend_from_slice(format!("{value:08X}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.resize(out.len().div_ceil(4) * 4, 0);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(4) * 4, 0);
        out
    }

    fn cpio(entries: &[(&str, &[u8])], magic: &[u8; 6]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            out.extend(newc_entry(name, data, magic));
        }
        out.extend(newc_entry("TRAILER!!!", b"", magic));
        out
    }

    /// A v4 boot image with an LZ4 ramdisk and a minimal AVB hash footer.
    fn boot_image(ramdisk_cpio: &[u8], partition_size: usize) -> Vec<u8> {
        let ramdisk = compress(Compression::Lz4Legacy, ramdisk_cpio).unwrap();
        let mut image = vec![0u8; PAGE];
        image[..8].copy_from_slice(BOOT_MAGIC);
        image[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        image[40..44].copy_from_slice(&4u32.to_le_bytes());
        image.extend_from_slice(&ramdisk);
        image.resize(align(image.len()), 0);
        let content_len = image.len();

        // vbmeta: 256-byte header, no auth block, one hash descriptor.
        let salt = [7u8; 32];
        let name = b"recovery";
        let mut body = Vec::new();
        body.extend_from_slice(&(content_len as u64).to_be_bytes());
        let mut algorithm = [0u8; 32];
        algorithm[..6].copy_from_slice(b"sha256");
        body.extend_from_slice(&algorithm);
        for v in [name.len() as u32, 32, 32, 0] {
            body.extend_from_slice(&v.to_be_bytes());
        }
        body.extend_from_slice(&[0u8; 60]);
        body.extend_from_slice(name);
        body.extend_from_slice(&salt);
        let mut h = Sha256::new();
        h.update(salt);
        h.update(&image);
        body.extend_from_slice(&h.finalize());
        body.resize(body.len().div_ceil(8) * 8, 0);
        let mut descriptor = AVB_HASH_DESCRIPTOR_TAG.to_be_bytes().to_vec();
        descriptor.extend_from_slice(&(body.len() as u64).to_be_bytes());
        descriptor.extend_from_slice(&body);
        let mut vbmeta = vec![0u8; 256];
        vbmeta[..4].copy_from_slice(b"AVB0");
        vbmeta[20..28].copy_from_slice(&(descriptor.len() as u64).to_be_bytes());
        vbmeta[104..112].copy_from_slice(&(descriptor.len() as u64).to_be_bytes());
        vbmeta.extend_from_slice(&descriptor);

        let vbmeta_len = vbmeta.len();
        image.extend_from_slice(&vbmeta);
        image.resize(partition_size - AVB_FOOTER_LEN, 0);
        let mut footer = AVB_FOOTER_MAGIC.to_vec();
        footer.extend_from_slice(&1u32.to_be_bytes());
        footer.extend_from_slice(&0u32.to_be_bytes());
        footer.extend_from_slice(&(content_len as u64).to_be_bytes());
        footer.extend_from_slice(&(content_len as u64).to_be_bytes());
        footer.extend_from_slice(&(vbmeta_len as u64).to_be_bytes());
        footer.resize(AVB_FOOTER_LEN, 0);
        image.extend_from_slice(&footer);
        image
    }

    fn descriptor_matches(image: &[u8]) -> bool {
        let footer = &image[image.len() - AVB_FOOTER_LEN..];
        let size = u64_be(footer, 12).unwrap() as usize;
        let at = u64_be(footer, 20).unwrap() as usize;
        let body = at + 256 + 16;
        let stored_size = u64_be(image, body).unwrap() as usize;
        let salt = &image[body + 116 + 8..body + 116 + 8 + 32];
        let digest = &image[body + 116 + 8 + 32..body + 116 + 8 + 64];
        let mut h = Sha256::new();
        h.update(salt);
        h.update(&image[..size]);
        stored_size == size && h.finalize()[..] == *digest
    }

    #[test]
    fn edits_a_ramdisk_file_and_keeps_the_hash_descriptor_valid() {
        for magic in [b"070701", b"070702"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("recovery.img");
            let original = vec![b'A'; 1160];
            let ramdisk = cpio(
                &[
                    ("init", b"#!init"),
                    ("system/etc/security/otacerts.zip", &original),
                ],
                magic,
            );
            let image = boot_image(&ramdisk, 1 << 20);
            assert!(descriptor_matches(&image));
            std::fs::write(&path, &image).unwrap();
            assert!(is_boot_image(&path).unwrap());

            let found = edit_ramdisk_file(&path, "system/etc/security/otacerts.zip", |data| {
                data.fill(b'B');
                Ok(())
            })
            .unwrap();
            assert!(found);

            let edited = std::fs::read(&path).unwrap();
            assert_eq!(edited.len(), image.len());
            assert!(descriptor_matches(&edited));
            let ramdisk_size = u32_le(&edited, 12).unwrap() as usize;
            let (_, cpio_out) = decompress(&edited[PAGE..PAGE + ramdisk_size]).unwrap();
            let (_, at, len) = cpio_find(&cpio_out, "system/etc/security/otacerts.zip")
                .unwrap()
                .unwrap();
            assert_eq!(cpio_out[at..at + len], vec![b'B'; 1160][..]);
            assert!(cpio_find(&cpio_out, "init").unwrap().is_some());

            // A missing file leaves the image alone; length changes are refused.
            assert!(!edit_ramdisk_file(&path, "missing", |_| Ok(())).unwrap());
            assert!(
                edit_ramdisk_file(&path, "init", |data| {
                    data.push(0);
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), edited);
        }
    }

    #[test]
    fn cpio_parser_survives_mutated_input() {
        let seed = cpio(&[("a", b"data"), ("dir/b", b"more")], b"070701");
        dynobox_core::testutil::for_each_mutation(&seed, 0xC910, 3000, |bytes| {
            let _ = cpio_find(bytes, "dir/b");
        });
        let lz4 = compress(Compression::Lz4Legacy, &seed).unwrap();
        dynobox_core::testutil::for_each_mutation(&lz4, 0x1A40, 3000, |bytes| {
            let _ = decompress(bytes);
        });
    }
}
