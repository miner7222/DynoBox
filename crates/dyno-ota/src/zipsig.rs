//! signapk-style whole-file signatures stored in the zip archive comment.
//!
//! The signed range is the whole file except the EOCD comment-length field
//! and the comment. The comment ends with a 6-byte footer: the signature's
//! offset from the end of the comment, the `0xFFFF` magic, and the comment
//! size.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::cert::Certificate;
use crate::cms::{self, SignedDigest};
use crate::key::OtaSigningKey;

const EOCD_MAGIC: &[u8; 4] = b"PK\x05\x06";
const EOCD_LEN: u64 = 22;
const FOOTER_LEN: usize = 6;
const COMMENT_MESSAGE: &[u8] = b"signed by DynoBox\0";

/// SHA-256 of the first `len` bytes of `reader`.
fn hash_prefix(reader: &mut (impl Read + Seek), len: u64) -> Result<[u8; 32]> {
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut remaining = len;
    let mut buf = vec![0u8; 4 << 20];
    while remaining > 0 {
        let chunk = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..chunk])?;
        hasher.update(&buf[..chunk]);
        remaining -= chunk as u64;
    }
    Ok(hasher.finalize().into())
}

/// Sign a finished zip whose EOCD is the last 22 bytes with an empty
/// comment, replacing that comment with the signature.
pub fn sign_zip(file: &mut File, key: &OtaSigningKey, certificate: &Certificate) -> Result<()> {
    let len = file.seek(SeekFrom::End(0))?;
    if len < EOCD_LEN {
        bail!("zip is too small to sign");
    }
    let mut eocd = [0u8; EOCD_LEN as usize];
    file.seek(SeekFrom::Start(len - EOCD_LEN))?;
    file.read_exact(&mut eocd)?;
    if &eocd[..4] != EOCD_MAGIC || eocd[20..22] != [0, 0] {
        bail!("zip must end with an EOCD record and no archive comment");
    }

    let digest = hash_prefix(file, len - 2)?;
    let signature = cms::sign_detached(key, certificate, &digest)?;
    let comment_len = COMMENT_MESSAGE.len() + signature.len() + FOOTER_LEN;
    let comment_len_u16 = u16::try_from(comment_len).context("signature too large")?;
    let mut tail = Vec::with_capacity(2 + comment_len);
    tail.extend_from_slice(&comment_len_u16.to_le_bytes());
    tail.extend_from_slice(COMMENT_MESSAGE);
    tail.extend_from_slice(&signature);
    tail.extend_from_slice(&((signature.len() + FOOTER_LEN) as u16).to_le_bytes());
    tail.extend_from_slice(&[0xFF, 0xFF]);
    tail.extend_from_slice(&comment_len_u16.to_le_bytes());
    if tail[2..].windows(4).any(|w| w == EOCD_MAGIC) {
        bail!("signature happens to contain the EOCD magic; sign again");
    }
    file.seek(SeekFrom::Start(len - 2))?;
    file.write_all(&tail)?;
    file.flush()?;
    Ok(())
}

/// Verify a whole-file signature and return the embedded signer. This checks
/// that the signature is valid, not that its certificate is trusted.
pub fn verify_zip(reader: &mut (impl Read + Seek)) -> Result<SignedDigest> {
    let len = reader.seek(SeekFrom::End(0))?;
    if len < EOCD_LEN + FOOTER_LEN as u64 {
        bail!("file is too small to be a signed zip");
    }
    let mut footer = [0u8; FOOTER_LEN];
    reader.seek(SeekFrom::Start(len - FOOTER_LEN as u64))?;
    reader.read_exact(&mut footer)?;
    let signature_start = u64::from(u16::from_le_bytes([footer[0], footer[1]]));
    let comment_len = u64::from(u16::from_le_bytes([footer[4], footer[5]]));
    if footer[2..4] != [0xFF, 0xFF] {
        bail!("zip is not signed (no signature footer)");
    }
    let eocd_len = EOCD_LEN + comment_len;
    if eocd_len > len || signature_start > comment_len || signature_start < FOOTER_LEN as u64 {
        bail!("zip signature footer is inconsistent");
    }
    let mut eocd = vec![0u8; eocd_len as usize];
    reader.seek(SeekFrom::Start(len - eocd_len))?;
    reader.read_exact(&mut eocd)?;
    if &eocd[..4] != EOCD_MAGIC
        || u64::from(u16::from_le_bytes([eocd[20], eocd[21]])) != comment_len
    {
        bail!("zip EOCD does not match the signature footer");
    }
    if eocd[4..].windows(4).any(|w| w == EOCD_MAGIC) {
        bail!("zip comment contains a second EOCD magic");
    }
    let cms_der = &eocd[eocd.len() - signature_start as usize..eocd.len() - FOOTER_LEN];
    let signed = cms::parse_detached(cms_der).context("parsing the zip signature")?;
    let digest = hash_prefix(reader, len - 2 - comment_len)?;
    signed
        .verify(&digest)
        .context("zip signature does not verify")?;
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::test_key;

    /// A minimal empty zip: just an EOCD with no comment.
    fn empty_zip_with(prefix: &[u8]) -> Vec<u8> {
        let mut out = prefix.to_vec();
        out.extend_from_slice(EOCD_MAGIC);
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn signs_and_verifies_and_detects_tampering() {
        let key = test_key(2048);
        let cert = Certificate::self_signed(&key, "DynoBox OTA", 1_790_467_200).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.zip");
        std::fs::write(&path, empty_zip_with(b"payload bytes")).unwrap();
        let mut file = File::options().read(true).write(true).open(&path).unwrap();
        sign_zip(&mut file, &key, &cert).unwrap();
        let signed = verify_zip(&mut file).unwrap();
        assert_eq!(signed.certificate, cert);

        // Re-signing a signed zip is refused (the comment is no longer empty).
        assert!(sign_zip(&mut file, &key, &cert).is_err());

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 1;
        assert!(verify_zip(&mut std::io::Cursor::new(bytes)).is_err());
    }

    /// Known-good vector: an OEM OTA signed by AOSP signapk.
    #[test]
    #[ignore = "fixture: set DYNOBOX_OTA_ZIP"]
    fn verifies_an_official_signapk_ota() {
        let path = std::env::var("DYNOBOX_OTA_ZIP").expect("set DYNOBOX_OTA_ZIP");
        let mut file = File::open(&path).unwrap();
        let signed = verify_zip(&mut file).unwrap();
        // The embedded CMS certificate is the one shipped as META-INF otacert.
        assert!(signed.certificate.public_key().is_ok());
    }

    #[test]
    fn verifier_survives_mutated_input() {
        let key = test_key(2048);
        let cert = Certificate::self_signed(&key, "DynoBox OTA", 1_790_467_200).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.zip");
        std::fs::write(&path, empty_zip_with(b"x")).unwrap();
        let mut file = File::options().read(true).write(true).open(&path).unwrap();
        sign_zip(&mut file, &key, &cert).unwrap();
        let seed = std::fs::read(&path).unwrap();
        dynobox_core::testutil::for_each_mutation(&seed, 0x5160, 3000, |bytes| {
            let _ = verify_zip(&mut std::io::Cursor::new(bytes));
        });
    }
}
