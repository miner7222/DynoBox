//! AES-CBC decryption for `.x` firmware files (Lenovo OSD rawprogram payloads).
//!
//! Ported from LTBox `ltbox-core::crypto`. Matches the v2 Python `crypto.py` format.
//!
//! Key derivation: PBKDF1(SHA-256, "OSD", salt, 1000, 32). Cipher: AES-256-CBC.
//! File layout: `[IV:16][Salt:16][Encrypted body]`.
//! Plaintext layout: `[original_size:i64LE][signature:8][data][sha256:32]`.

use std::path::Path;

use aes::Aes256;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use sha2::{Digest, Sha256};

use dynobox_core::error::{DynoError, Result};

const PASSWORD: &[u8] = b"OSD";
const SIGNATURE: &[u8] = &[0xcf, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xfc];

type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn pbkdf1_sha256(password: &[u8], salt: &[u8], iterations: u32, len_out: usize) -> Vec<u8> {
    let mut digest = {
        let mut h = Sha256::new();
        h.update(password);
        h.update(salt);
        h.finalize().to_vec()
    };
    for _ in 1..iterations {
        let mut h = Sha256::new();
        h.update(&digest);
        digest = h.finalize().to_vec();
    }
    digest.truncate(len_out);
    digest
}

pub fn decrypt_file(input: &Path, output: &Path) -> Result<u64> {
    let data = std::fs::read(input)?;

    if data.len() < 32 {
        return Err(DynoError::Tool(format!(
            "Encrypted file too small: {}",
            input.display()
        )));
    }

    let iv = &data[..16];
    let salt = &data[16..32];
    let encrypted = &data[32..];

    let key = pbkdf1_sha256(PASSWORD, salt, 1000, 32);

    let mut buf = encrypted.to_vec();
    let decryptor = Aes256CbcDec::new_from_slices(&key, iv)
        .map_err(|e| DynoError::Tool(format!("Cipher init error: {e}")))?;
    let plain = decryptor
        .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| DynoError::Tool(format!("Decryption error ({}): {e}", input.display())))?;

    if plain.len() < 16 {
        return Err(DynoError::Tool("Decrypted data too small".into()));
    }

    let original_size_i64 = i64::from_le_bytes(plain[0..8].try_into().unwrap());
    let signature = &plain[8..16];

    if signature != SIGNATURE {
        return Err(DynoError::Tool(format!(
            "Invalid decryption signature for {}",
            input.display()
        )));
    }

    if original_size_i64 < 0 {
        return Err(DynoError::Tool(format!(
            "Invalid original_size in header: {original_size_i64}"
        )));
    }
    let original_size = original_size_i64 as u64;
    let body_end: usize = 16usize
        .checked_add(usize::try_from(original_size).map_err(|_| {
            DynoError::Tool(format!("original_size {original_size} exceeds usize"))
        })?)
        .ok_or_else(|| {
            DynoError::Tool(format!("Header arithmetic overflow (size={original_size})"))
        })?;
    let hash_end: usize = body_end
        .checked_add(32)
        .ok_or_else(|| DynoError::Tool("Trailing SHA offset overflow".into()))?;
    if hash_end > plain.len() {
        return Err(DynoError::Tool("Truncated decrypted data".into()));
    }

    let body = &plain[16..body_end];
    let expected_hash = &plain[body_end..hash_end];

    let actual_hash = Sha256::digest(body);
    if actual_hash.as_slice() != expected_hash {
        return Err(DynoError::Tool(format!(
            "SHA-256 hash mismatch for {}",
            input.display()
        )));
    }

    std::fs::write(output, body)?;
    Ok(original_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    fn build_x_with_plaintext(plain: &[u8]) -> Vec<u8> {
        let iv = [0u8; 16];
        let salt = [0u8; 16];
        let key = pbkdf1_sha256(b"OSD", &salt, 1000, 32);
        let cipher = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();

        assert!(plain.len() % 16 == 0, "test plaintext must be 16-aligned");
        let mut buf = plain.to_vec();
        let encrypted_len = buf.len();
        buf.resize(buf.len() + 16, 0);
        let ct = cipher
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf, encrypted_len)
            .unwrap();
        let ct_len = ct.len();
        buf.truncate(ct_len);

        let mut out = Vec::with_capacity(32 + buf.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&buf);
        out
    }

    #[test]
    fn roundtrip_decrypts_valid_blob() {
        let body = b"<data><program label=\"boot\" filename=\"boot.img\"/></data>\n";
        let mut plain = Vec::new();
        plain.extend_from_slice(&(body.len() as i64).to_le_bytes());
        plain.extend_from_slice(SIGNATURE);
        plain.extend_from_slice(body);
        let hash = Sha256::digest(body);
        plain.extend_from_slice(&hash);
        while plain.len() % 16 != 0 {
            plain.push(0);
        }
        let blob = build_x_with_plaintext(&plain);

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("rawprogram0.x");
        let output = dir.path().join("rawprogram0.xml");
        std::fs::write(&input, &blob).unwrap();

        let n = decrypt_file(&input, &output).unwrap();
        assert_eq!(n as usize, body.len());
        assert_eq!(std::fs::read(&output).unwrap(), body);
    }

    #[test]
    fn negative_size_rejected() {
        let mut plain = Vec::new();
        plain.extend_from_slice(&(-1i64).to_le_bytes());
        plain.extend_from_slice(SIGNATURE);
        plain.extend_from_slice(&[0u8; 16]);
        let blob = build_x_with_plaintext(&plain);

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("bad.x");
        let output = dir.path().join("bad.xml");
        std::fs::write(&input, &blob).unwrap();

        assert!(decrypt_file(&input, &output).is_err());
    }
}
