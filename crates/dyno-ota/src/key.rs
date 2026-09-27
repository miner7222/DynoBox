//! RSA OTA signing keys.
//!
//! update_engine, recovery and the framework's `RecoverySystem` all verify
//! OTA packages with RSA PKCS#1 v1.5 over SHA-256, so that is the only scheme
//! implemented here.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use rand_core::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// Key sizes Android's OTA verifiers accept.
pub const SUPPORTED_KEY_BITS: [usize; 2] = [2048, 4096];

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 section 9.2, note 1).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn digest_info(digest: &[u8; 32]) -> [u8; 51] {
    let mut out = [0u8; 51];
    out[..19].copy_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    out[19..].copy_from_slice(digest);
    out
}

/// An RSA private key used to sign OTA payloads and packages.
pub struct OtaSigningKey {
    private: RsaPrivateKey,
}

impl OtaSigningKey {
    /// Generate a new key of `bits` (2048 or 4096).
    pub fn generate(bits: usize) -> Result<Self> {
        if !SUPPORTED_KEY_BITS.contains(&bits) {
            bail!("unsupported OTA key size {bits}; use 2048 or 4096");
        }
        let private =
            RsaPrivateKey::new(&mut OsRng, bits).context("generating RSA OTA signing key")?;
        Ok(Self { private })
    }

    /// Load a PKCS#8 or PKCS#1 private key, PEM or DER.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("reading OTA key {}", path.display()))?;
        Self::from_bytes(&bytes).with_context(|| format!("loading OTA key {}", path.display()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let private = match std::str::from_utf8(bytes) {
            Ok(text) if text.contains("-----BEGIN") => RsaPrivateKey::from_pkcs8_pem(text)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(text))
                .map_err(|_| anyhow!("not an unencrypted RSA private key PEM"))?,
            _ => RsaPrivateKey::from_pkcs8_der(bytes)
                .or_else(|_| RsaPrivateKey::from_pkcs1_der(bytes))
                .map_err(|_| anyhow!("not an RSA private key (PKCS#8 or PKCS#1 DER)"))?,
        };
        let bits = private.size() * 8;
        if !SUPPORTED_KEY_BITS.contains(&bits) {
            bail!("unsupported OTA key size {bits}; use 2048 or 4096");
        }
        Ok(Self { private })
    }

    /// PKCS#8 PEM encoding of the private key.
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        Ok(self
            .private
            .to_pkcs8_pem(LineEnding::LF)
            .context("encoding OTA key as PKCS#8")?
            .to_string())
    }

    pub fn bits(&self) -> usize {
        self.private.size() * 8
    }

    /// Signature length in bytes.
    pub fn signature_len(&self) -> usize {
        self.private.size()
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.private.to_public_key()
    }

    /// Sign a precomputed SHA-256 digest.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        self.private
            .sign_with_rng(
                &mut OsRng,
                Pkcs1v15Sign::new_unprefixed(),
                &digest_info(digest),
            )
            .context("RSA signing failed")
    }

    /// Hash `message` with SHA-256 and sign it.
    pub fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_digest(&Sha256::digest(message).into())
    }
}

/// Verify a PKCS#1 v1.5 SHA-256 signature over a precomputed digest.
pub fn verify_digest(public: &RsaPublicKey, digest: &[u8; 32], signature: &[u8]) -> Result<()> {
    public
        .verify(
            Pkcs1v15Sign::new_unprefixed(),
            &digest_info(digest),
            signature,
        )
        .map_err(|_| anyhow!("RSA signature does not verify"))
}

/// Big-endian modulus and public exponent of `public`.
pub(crate) fn public_parts(public: &RsaPublicKey) -> (Vec<u8>, Vec<u8>) {
    (public.n().to_bytes_be(), public.e().to_bytes_be())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Fixed RSA test keys, so tests never pay for key generation.
    pub(crate) fn test_key(bits: usize) -> OtaSigningKey {
        let name = format!("testkey_rsa{bits}");
        let pem = avbtool_rs::crypto::get_embedded_key(&name).expect("embedded AVB test key");
        OtaSigningKey::from_bytes(pem.as_bytes()).unwrap()
    }

    #[test]
    fn signs_and_verifies_sha256() {
        for bits in SUPPORTED_KEY_BITS {
            let key = test_key(bits);
            assert_eq!(key.bits(), bits);
            let signature = key.sign_sha256(b"payload").unwrap();
            assert_eq!(signature.len(), key.signature_len());
            let digest: [u8; 32] = Sha256::digest(b"payload").into();
            verify_digest(&key.public_key(), &digest, &signature).unwrap();
            let other: [u8; 32] = Sha256::digest(b"other").into();
            assert!(verify_digest(&key.public_key(), &other, &signature).is_err());
        }
    }

    #[test]
    fn pkcs8_round_trip_and_size_check() {
        let key = test_key(2048);
        let pem = key.to_pkcs8_pem().unwrap();
        let reloaded = OtaSigningKey::from_bytes(pem.as_bytes()).unwrap();
        assert_eq!(reloaded.public_key(), key.public_key());
        let pem_8192 = avbtool_rs::crypto::get_embedded_key("testkey_rsa8192").unwrap();
        assert!(OtaSigningKey::from_bytes(pem_8192.as_bytes()).is_err());
        assert!(OtaSigningKey::generate(1024).is_err());
    }
}
