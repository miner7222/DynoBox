//! Custom OTA support: signing keys now, OTA generation to follow.

use std::fs;
use std::path::Path;

use anyhow::{Result, bail};
use dynobox_ota::{Certificate, OtaSigningKey};
use sha2::{Digest, Sha256};

use crate::integrity_signature::write_atomic_noclobber;

/// Result of [`generate_ota_keypair`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedOtaKey {
    pub bits: usize,
    /// Lowercase hex SHA-256 of the certificate DER.
    pub cert_sha256: String,
}

/// Generate an RSA OTA signing key (PKCS#8 PEM, owner-only on Unix) and a
/// self-signed certificate for it. Existing files are never overwritten.
pub fn generate_ota_keypair(
    key_path: &Path,
    cert_path: &Path,
    bits: usize,
    subject: &str,
) -> Result<GeneratedOtaKey> {
    if key_path == cert_path {
        bail!("key and certificate paths must be different");
    }
    for path in [key_path, cert_path] {
        if path.exists() {
            bail!("refusing to overwrite {}", path.display());
        }
    }
    let key = OtaSigningKey::generate(bits)?;
    let not_before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cert = Certificate::self_signed(&key, subject, not_before)?;
    write_keypair(&key, &cert, key_path, cert_path)?;
    Ok(GeneratedOtaKey {
        bits,
        cert_sha256: dynobox_core::hex::hex_encode(&Sha256::digest(cert.der())),
    })
}

fn write_keypair(
    key: &OtaSigningKey,
    cert: &Certificate,
    key_path: &Path,
    cert_path: &Path,
) -> Result<()> {
    write_atomic_noclobber(cert_path, cert.to_pem().as_bytes(), false)?;
    if let Err(error) = write_atomic_noclobber(key_path, key.to_pkcs8_pem()?.as_bytes(), true) {
        let _ = fs::remove_file(cert_path);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_matching_key_and_certificate_without_clobbering() {
        let dir = tempfile::tempdir().unwrap();
        let (key_path, cert_path) = (dir.path().join("ota.key"), dir.path().join("ota.crt"));
        let pem = avbtool_rs::crypto::get_embedded_key("testkey_rsa2048").unwrap();
        let key = OtaSigningKey::from_bytes(pem.as_bytes()).unwrap();
        let cert = Certificate::self_signed(&key, "DynoBox OTA", 1_790_467_200).unwrap();
        write_keypair(&key, &cert, &key_path, &cert_path).unwrap();

        let reloaded = OtaSigningKey::load(&key_path).unwrap();
        assert!(
            Certificate::load(&cert_path)
                .unwrap()
                .matches_key(&reloaded)
        );

        let err = generate_ota_keypair(&key_path, &dir.path().join("new.crt"), 2048, "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing to overwrite"), "{err}");
        assert!(generate_ota_keypair(&key_path, &key_path, 2048, "x").is_err());
    }
}
