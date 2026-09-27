//! `otacerts.zip`: the certificate bundle Android's OTA verifiers trust.
//!
//! update_engine reads `/system/etc/security/otacerts.zip` to verify payload
//! signatures, and the framework's `RecoverySystem` and recovery mode use the
//! same file for whole-package signatures. Replacing it in place requires a
//! zip of exactly the original size, so the new zip is shrunk (compression,
//! then stripping certificate fields the verifiers ignore) and padded with an
//! archive comment.

use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

use crate::cert::{Certificate, Strip};

/// Entry name used for the replacement certificate.
pub const ENTRY_NAME: &str = "ota.x509.pem";

const LOCAL_HEADER_SIG: u32 = 0x0403_4B50;
const CENTRAL_HEADER_SIG: u32 = 0x0201_4B50;
const EOCD_SIG: u32 = 0x0605_4B50;
const EOCD_LEN: usize = 22;
const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
/// 1980-01-01, the zip epoch; keeps the output reproducible.
const DOS_DATE: u16 = 0x0021;
/// Upper bound for a decompressed certificate entry.
const MAX_ENTRY_SIZE: u64 = 64 * 1024;

/// Build an `otacerts.zip` holding `cert`, exactly `size` bytes long.
pub fn build_with_size(cert: &Certificate, size: usize) -> Result<Vec<u8>> {
    let ladder = [
        (false, Strip::default()),
        (true, Strip::default()),
        (
            true,
            Strip {
                signature: true,
                ..Strip::default()
            },
        ),
        (
            true,
            Strip {
                signature: true,
                extensions: true,
                ..Strip::default()
            },
        ),
        (
            true,
            Strip {
                signature: true,
                extensions: true,
                issuer: true,
                ..Strip::default()
            },
        ),
        (
            true,
            Strip {
                signature: true,
                extensions: true,
                issuer: true,
                subject: true,
            },
        ),
    ];
    let mut smallest = usize::MAX;
    for (deflate, strip) in ladder {
        let pem = cert.stripped(strip)?.to_pem();
        let natural = build(pem.as_bytes(), deflate, 0)?;
        smallest = smallest.min(natural.len());
        if natural.len() > size {
            continue;
        }
        let padding = size - natural.len();
        if padding > usize::from(u16::MAX) {
            bail!(
                "otacerts.zip slot of {size} bytes is too large to pad a {}-byte zip",
                natural.len()
            );
        }
        let zip = build(pem.as_bytes(), deflate, padding)?;
        debug_assert_eq!(zip.len(), size);
        return Ok(zip);
    }
    bail!(
        "the OTA certificate needs at least {smallest} bytes as otacerts.zip, \
         but the image only has {size}; use a 2048-bit key"
    )
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn build(pem: &[u8], deflate: bool, comment_len: usize) -> Result<Vec<u8>> {
    let (method, data) = if deflate {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(pem)?;
        (METHOD_DEFLATE, encoder.finish()?)
    } else {
        (METHOD_STORE, pem.to_vec())
    };
    let crc = crc32fast::hash(pem);
    let name = ENTRY_NAME.as_bytes();
    let as_u32 = |n: usize| u32::try_from(n).map_err(|_| anyhow!("otacerts entry too large"));

    let mut out = Vec::new();
    put_u32(&mut out, LOCAL_HEADER_SIG);
    put_u16(&mut out, 20);
    put_u16(&mut out, 0);
    put_u16(&mut out, method);
    put_u16(&mut out, 0);
    put_u16(&mut out, DOS_DATE);
    put_u32(&mut out, crc);
    put_u32(&mut out, as_u32(data.len())?);
    put_u32(&mut out, as_u32(pem.len())?);
    put_u16(&mut out, name.len() as u16);
    put_u16(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(&data);

    let cd_offset = out.len();
    put_u32(&mut out, CENTRAL_HEADER_SIG);
    put_u16(&mut out, 20);
    put_u16(&mut out, 20);
    put_u16(&mut out, 0);
    put_u16(&mut out, method);
    put_u16(&mut out, 0);
    put_u16(&mut out, DOS_DATE);
    put_u32(&mut out, crc);
    put_u32(&mut out, as_u32(data.len())?);
    put_u32(&mut out, as_u32(pem.len())?);
    put_u16(&mut out, name.len() as u16);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    out.extend_from_slice(name);
    let cd_size = out.len() - cd_offset;

    put_u32(&mut out, EOCD_SIG);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, 1);
    put_u16(&mut out, 1);
    put_u32(&mut out, as_u32(cd_size)?);
    put_u32(&mut out, as_u32(cd_offset)?);
    put_u16(
        &mut out,
        u16::try_from(comment_len).map_err(|_| anyhow!("zip comment too long"))?,
    );
    out.resize(out.len() + comment_len, 0);
    Ok(out)
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| anyhow!("otacerts.zip truncated at {offset}"))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| anyhow!("otacerts.zip truncated at {offset}"))
}

fn slice(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    offset
        .checked_add(len)
        .and_then(|end| data.get(offset..end))
        .ok_or_else(|| anyhow!("otacerts.zip range {offset}+{len} out of bounds"))
}

/// Read every `*.x509.pem` certificate from an `otacerts.zip`.
pub fn read_certificates(zip: &[u8]) -> Result<Vec<Certificate>> {
    let min_eocd = zip.len().saturating_sub(EOCD_LEN + usize::from(u16::MAX));
    let eocd = (min_eocd..=zip.len().saturating_sub(EOCD_LEN))
        .rev()
        .find(|&offset| u32_at(zip, offset).is_ok_and(|sig| sig == EOCD_SIG))
        .ok_or_else(|| anyhow!("otacerts.zip has no end-of-central-directory record"))?;
    let entries = usize::from(u16_at(zip, eocd + 10)?);
    let mut cursor = u32_at(zip, eocd + 16)? as usize;

    let mut certs = Vec::new();
    for _ in 0..entries {
        if u32_at(zip, cursor)? != CENTRAL_HEADER_SIG {
            bail!("otacerts.zip central directory is corrupt at {cursor}");
        }
        let method = u16_at(zip, cursor + 10)?;
        let crc = u32_at(zip, cursor + 16)?;
        let compressed = u32_at(zip, cursor + 20)? as usize;
        let uncompressed = u64::from(u32_at(zip, cursor + 24)?);
        let name_len = usize::from(u16_at(zip, cursor + 28)?);
        let extra_len = usize::from(u16_at(zip, cursor + 30)?);
        let comment_len = usize::from(u16_at(zip, cursor + 32)?);
        let local = u32_at(zip, cursor + 42)? as usize;
        let name = slice(zip, cursor + 46, name_len)?;
        cursor += 46 + name_len + extra_len + comment_len;

        if !name.ends_with(b".x509.pem") {
            continue;
        }
        if u32_at(zip, local)? != LOCAL_HEADER_SIG {
            bail!("otacerts.zip local header is corrupt at {local}");
        }
        let data_start = local
            + 30
            + usize::from(u16_at(zip, local + 26)?)
            + usize::from(u16_at(zip, local + 28)?);
        let data = slice(zip, data_start, compressed)?;
        if uncompressed > MAX_ENTRY_SIZE {
            bail!("otacerts.zip entry claims {uncompressed} bytes");
        }
        let pem = match method {
            METHOD_STORE => data.to_vec(),
            METHOD_DEFLATE => {
                let mut out = Vec::new();
                DeflateDecoder::new(data)
                    .take(MAX_ENTRY_SIZE)
                    .read_to_end(&mut out)
                    .context("inflating otacerts.zip entry")?;
                out
            }
            other => bail!("otacerts.zip entry uses unsupported method {other}"),
        };
        if pem.len() as u64 != uncompressed || crc32fast::hash(&pem) != crc {
            bail!("otacerts.zip entry fails its size or CRC check");
        }
        certs.push(Certificate::from_pem_or_der(&pem)?);
    }
    if certs.is_empty() {
        bail!("otacerts.zip contains no *.x509.pem certificate");
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::test_key;

    const NOW: i64 = 1_790_467_200;

    /// The stock TB323 `otacerts.zip` is 1160 bytes.
    const STOCK_SIZE: usize = 1160;

    #[test]
    fn fits_both_key_sizes_into_the_stock_slot() {
        for bits in [2048, 4096] {
            let key = test_key(bits);
            let cert = Certificate::self_signed(&key, "DynoBox OTA", NOW).unwrap();
            let zip = build_with_size(&cert, STOCK_SIZE).unwrap();
            assert_eq!(zip.len(), STOCK_SIZE);
            let certs = read_certificates(&zip).unwrap();
            assert_eq!(certs.len(), 1);
            assert!(certs[0].matches_key(&key), "{bits}-bit key round trip");
        }
    }

    #[test]
    fn keeps_the_full_certificate_when_it_fits() {
        let key = test_key(2048);
        let cert = Certificate::self_signed(&key, "DynoBox OTA", NOW).unwrap();
        let zip = build_with_size(&cert, 4096).unwrap();
        assert_eq!(read_certificates(&zip).unwrap(), vec![cert]);
    }

    #[test]
    fn rejects_a_slot_that_is_too_small() {
        let cert = Certificate::self_signed(&test_key(4096), "DynoBox OTA", NOW).unwrap();
        let err = build_with_size(&cert, 300).unwrap_err().to_string();
        assert!(err.contains("at least"), "{err}");
    }

    #[test]
    fn reads_and_replaces_the_stock_lenovo_bundle() {
        // AOSP-built: deflated, with data descriptors, no comment.
        let stock = include_bytes!("../testdata/tb323-otacerts.zip");
        assert_eq!(stock.len(), STOCK_SIZE);
        let certs = read_certificates(stock).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs[0].public_key().is_ok());

        let key = test_key(4096);
        let cert = Certificate::self_signed(&key, "DynoBox OTA", NOW).unwrap();
        let replacement = build_with_size(&cert, stock.len()).unwrap();
        assert_eq!(replacement.len(), stock.len());
        assert!(read_certificates(&replacement).unwrap()[0].matches_key(&key));
    }

    #[test]
    fn reader_survives_mutated_input() {
        let cert = Certificate::self_signed(&test_key(2048), "DynoBox OTA", NOW).unwrap();
        let zip = build_with_size(&cert, STOCK_SIZE).unwrap();
        dynobox_core::testutil::for_each_mutation(&zip, 0x07AC, 3000, |bytes| {
            let _ = read_certificates(bytes);
        });
    }
}
