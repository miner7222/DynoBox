//! Detached Ed25519 signatures for DynoBox output manifests.
//!
//! The signature envelope embeds the public key so any verifier can establish
//! that the manifest and signature are internally consistent. Authenticity is
//! a separate decision: the embedded key is trusted only when it matches a
//! caller-supplied, externally pinned Ed25519 public key.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pkcs8::LineEnding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::integrity::{MANIFEST_FILE_NAME, MANIFEST_SIGNATURE_FILE_NAME};

pub const SIGNATURE_SCHEMA: &str = "dynobox.output_manifest_signature";
pub const SIGNATURE_VERSION: u32 = 1;
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSignatureEnvelope {
    pub schema: String,
    pub version: u32,
    pub algorithm: String,
    /// SHA-256 of the raw 32-byte Ed25519 public key.
    pub key_id: String,
    /// Raw 32-byte Ed25519 public key as lowercase hex.
    pub public_key: String,
    /// Raw 64-byte Ed25519 signature as lowercase hex.
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureTrustStatus {
    Unsigned,
    ValidUntrusted,
    ValidTrusted,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestSignatureVerification {
    pub signature_path: PathBuf,
    pub status: SignatureTrustStatus,
    pub key_id: Option<String>,
    pub issue: Option<String>,
}

impl ManifestSignatureVerification {
    pub fn is_cryptographically_valid(&self) -> bool {
        matches!(
            self.status,
            SignatureTrustStatus::ValidUntrusted | SignatureTrustStatus::ValidTrusted
        )
    }

    pub fn is_trusted(&self) -> bool {
        self.status == SignatureTrustStatus::ValidTrusted
    }
}

/// Generate a new Ed25519 keypair as PKCS#8 private PEM and SPKI public PEM.
/// Existing targets are never overwritten.
pub fn generate_integrity_keypair(private_path: &Path, public_path: &Path) -> Result<String> {
    if private_path == public_path {
        bail!("private and public key paths must be different");
    }
    if private_path.exists() {
        bail!(
            "refusing to overwrite private key at {}",
            private_path.display()
        );
    }
    if public_path.exists() {
        bail!(
            "refusing to overwrite public key at {}",
            public_path.display()
        );
    }

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("failed to obtain operating-system randomness")?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let verifying_key = signing_key.verifying_key();

    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode Ed25519 private key as PKCS#8 PEM")?;
    let public_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .context("failed to encode Ed25519 public key as SPKI PEM")?;

    write_atomic_noclobber(public_path, public_pem.as_bytes(), false)?;
    if let Err(error) = write_atomic_noclobber(private_path, private_pem.as_bytes(), true) {
        let _ = fs::remove_file(public_path);
        return Err(error);
    }

    Ok(public_key_id(&verifying_key))
}

/// Sign the exact bytes of `dynobox-manifest.json` and atomically replace the
/// detached signature envelope in the same output directory.
pub fn sign_output_manifest(output_dir: &Path, private_key_path: &Path) -> Result<String> {
    let manifest_path = output_dir.join(MANIFEST_FILE_NAME);
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("failed to read manifest at {}", manifest_path.display()))?;
    let signing_key = load_signing_key(private_key_path)?;
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&manifest_bytes);
    let envelope = ManifestSignatureEnvelope {
        schema: SIGNATURE_SCHEMA.to_string(),
        version: SIGNATURE_VERSION,
        algorithm: SIGNATURE_ALGORITHM.to_string(),
        key_id: public_key_id(&verifying_key),
        public_key: hex_encode(verifying_key.as_bytes()),
        signature: hex_encode(&signature.to_bytes()),
    };
    let bytes = serialize_signature_envelope(&envelope)?;
    let signature_path = output_dir.join(MANIFEST_SIGNATURE_FILE_NAME);
    write_atomic_replace(&signature_path, &bytes)?;
    Ok(envelope.key_id)
}

/// Parse a manifest-signing private key without producing a signature and
/// return its public-key fingerprint. Pipelines use this as an early preflight.
pub fn integrity_signing_key_id(private_key_path: &Path) -> Result<String> {
    Ok(public_key_id(
        &load_signing_key(private_key_path)?.verifying_key(),
    ))
}

/// Verify the detached signature and optionally authenticate its signer against
/// one or more externally pinned SPKI PEM public keys.
pub fn verify_output_manifest_signature(
    output_dir: &Path,
    trusted_public_keys: &[PathBuf],
) -> Result<ManifestSignatureVerification> {
    let signature_path = output_dir.join(MANIFEST_SIGNATURE_FILE_NAME);
    match fs::symlink_metadata(&signature_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ManifestSignatureVerification {
                signature_path,
                status: SignatureTrustStatus::Unsigned,
                key_id: None,
                issue: None,
            });
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect manifest signature at {}",
                    signature_path.display()
                )
            });
        }
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Ok(ManifestSignatureVerification {
                signature_path: signature_path.clone(),
                status: SignatureTrustStatus::Invalid,
                key_id: None,
                issue: Some(format!(
                    "manifest signature must be a regular file: {}",
                    signature_path.display()
                )),
            });
        }
        Ok(_) => {}
    }

    let verification = match verify_signature_inner(output_dir, trusted_public_keys) {
        Ok((key_id, trusted)) => ManifestSignatureVerification {
            signature_path,
            status: if trusted {
                SignatureTrustStatus::ValidTrusted
            } else {
                SignatureTrustStatus::ValidUntrusted
            },
            key_id: Some(key_id),
            issue: None,
        },
        Err(error) => ManifestSignatureVerification {
            signature_path,
            status: SignatureTrustStatus::Invalid,
            key_id: None,
            issue: Some(error.to_string()),
        },
    };
    Ok(verification)
}

pub fn serialize_signature_envelope(envelope: &ManifestSignatureEnvelope) -> Result<Vec<u8>> {
    validate_envelope(envelope)?;
    let mut bytes = serde_json::to_vec_pretty(envelope)
        .context("failed to serialize manifest signature envelope")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn verify_signature_inner(
    output_dir: &Path,
    trusted_public_keys: &[PathBuf],
) -> Result<(String, bool)> {
    let manifest_path = output_dir.join(MANIFEST_FILE_NAME);
    let signature_path = output_dir.join(MANIFEST_SIGNATURE_FILE_NAME);
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("failed to read manifest at {}", manifest_path.display()))?;
    let envelope_bytes = fs::read(&signature_path).with_context(|| {
        format!(
            "failed to read manifest signature at {}",
            signature_path.display()
        )
    })?;
    let envelope: ManifestSignatureEnvelope =
        serde_json::from_slice(&envelope_bytes).context("malformed manifest signature JSON")?;
    validate_envelope(&envelope)?;

    let public_bytes = decode_hex_array::<32>(&envelope.public_key, "public_key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .context("manifest signature contains an invalid Ed25519 public key")?;
    let actual_key_id = public_key_id(&verifying_key);
    if actual_key_id != envelope.key_id {
        bail!(
            "signature key_id mismatch: envelope {}, computed {}",
            envelope.key_id,
            actual_key_id
        );
    }

    let signature_bytes = decode_hex_array::<64>(&envelope.signature, "signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&manifest_bytes, &signature)
        .context("Ed25519 manifest signature verification failed")?;

    let trusted = trusted_public_keys
        .iter()
        .map(|path| load_public_key(path))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .any(|trusted_key| trusted_key == &verifying_key);
    Ok((actual_key_id, trusted))
}

fn load_public_key(path: &Path) -> Result<VerifyingKey> {
    let pem = fs::read_to_string(path)
        .with_context(|| format!("failed to read trusted public key from {}", path.display()))?;
    VerifyingKey::from_public_key_pem(&pem).with_context(|| {
        format!(
            "failed to parse Ed25519 SPKI public key from {}",
            path.display()
        )
    })
}

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let private_pem = fs::read_to_string(path)
        .with_context(|| format!("failed to read Ed25519 private key from {}", path.display()))?;
    SigningKey::from_pkcs8_pem(&private_pem).with_context(|| {
        format!(
            "failed to parse Ed25519 PKCS#8 private key from {}",
            path.display()
        )
    })
}

fn validate_envelope(envelope: &ManifestSignatureEnvelope) -> Result<()> {
    if envelope.schema != SIGNATURE_SCHEMA {
        bail!("unsupported signature schema '{}'", envelope.schema);
    }
    if envelope.version != SIGNATURE_VERSION {
        bail!("unsupported signature version {}", envelope.version);
    }
    if envelope.algorithm != SIGNATURE_ALGORITHM {
        bail!("unsupported signature algorithm '{}'", envelope.algorithm);
    }
    validate_lower_hex(&envelope.key_id, 32, "key_id")?;
    validate_lower_hex(&envelope.public_key, 32, "public_key")?;
    validate_lower_hex(&envelope.signature, 64, "signature")?;
    Ok(())
}

fn public_key_id(key: &VerifyingKey) -> String {
    hex_encode(&Sha256::digest(key.as_bytes()))
}

fn validate_lower_hex(value: &str, byte_len: usize, field: &str) -> Result<()> {
    if value.len() != byte_len * 2
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("{field} must be {} bytes of lowercase hex", byte_len);
    }
    Ok(())
}

fn decode_hex_array<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    validate_lower_hex(value, N, field)?;
    let mut output = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(anyhow!("invalid lowercase hexadecimal digit")),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn write_atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = parent_dir(path)?;
    fs::create_dir_all(parent)?;
    let file_name = utf8_file_name(path)?;
    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{file_name}."))
        .suffix(".tmp")
        .tempfile_in(parent)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| anyhow!("failed to replace {}: {}", path.display(), error.error))?;
    Ok(())
}

fn write_atomic_noclobber(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let parent = parent_dir(path)?;
    fs::create_dir_all(parent)?;
    let file_name = utf8_file_name(path)?;
    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{file_name}."))
        .suffix(".tmp")
        .tempfile_in(parent)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    if private {
        set_private_permissions(temp.path())?;
    }
    temp.persist_noclobber(path)
        .map_err(|error| anyhow!("failed to create {}: {}", path.display(), error.error))?;
    Ok(())
}

fn parent_dir(path: &Path) -> Result<&Path> {
    Ok(path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new(".")))
}

fn utf8_file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("path has a non-UTF8 file name: {}", path.display()))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::write_output_manifest_for_dir;

    fn make_output() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("boot.img"), b"boot").unwrap();
        write_output_manifest_for_dir(dir.path(), "2026-07-18T00:00:00Z", true).unwrap();
        dir
    }

    fn make_keys(dir: &Path, stem: &str) -> (PathBuf, PathBuf) {
        let private = dir.join(format!("{stem}.pem"));
        let public = dir.join(format!("{stem}.pub.pem"));
        generate_integrity_keypair(&private, &public).unwrap();
        (private, public)
    }

    #[test]
    fn unsigned_output_is_reported_separately() {
        let output = make_output();
        let verification = verify_output_manifest_signature(output.path(), &[]).unwrap();
        assert_eq!(verification.status, SignatureTrustStatus::Unsigned);
        assert!(!verification.is_cryptographically_valid());
    }

    #[test]
    fn valid_signature_is_trusted_only_by_matching_external_key() {
        let output = make_output();
        let key_dir = tempfile::tempdir().unwrap();
        let (private, public) = make_keys(key_dir.path(), "trusted");
        let (_, wrong_public) = make_keys(key_dir.path(), "wrong");
        let key_id = sign_output_manifest(output.path(), &private).unwrap();

        let untrusted = verify_output_manifest_signature(output.path(), &[]).unwrap();
        assert_eq!(untrusted.status, SignatureTrustStatus::ValidUntrusted);
        assert_eq!(untrusted.key_id.as_deref(), Some(key_id.as_str()));

        let wrong = verify_output_manifest_signature(output.path(), &[wrong_public]).unwrap();
        assert_eq!(wrong.status, SignatureTrustStatus::ValidUntrusted);

        let trusted = verify_output_manifest_signature(output.path(), &[public]).unwrap();
        assert_eq!(trusted.status, SignatureTrustStatus::ValidTrusted);
        assert!(trusted.is_trusted());
    }

    #[test]
    fn manifest_tamper_invalidates_signature() {
        let output = make_output();
        let key_dir = tempfile::tempdir().unwrap();
        let (private, _) = make_keys(key_dir.path(), "key");
        sign_output_manifest(output.path(), &private).unwrap();
        fs::write(output.path().join(MANIFEST_FILE_NAME), b"{}\n").unwrap();

        let verification = verify_output_manifest_signature(output.path(), &[]).unwrap();
        assert_eq!(verification.status, SignatureTrustStatus::Invalid);
        assert!(verification.issue.is_some());
    }

    #[test]
    fn malformed_or_tampered_envelope_is_invalid() {
        let output = make_output();
        fs::write(
            output.path().join(MANIFEST_SIGNATURE_FILE_NAME),
            b"{not-json}",
        )
        .unwrap();
        let malformed = verify_output_manifest_signature(output.path(), &[]).unwrap();
        assert_eq!(malformed.status, SignatureTrustStatus::Invalid);

        let key_dir = tempfile::tempdir().unwrap();
        let (private, _) = make_keys(key_dir.path(), "key");
        sign_output_manifest(output.path(), &private).unwrap();
        let path = output.path().join(MANIFEST_SIGNATURE_FILE_NAME);
        let mut envelope: ManifestSignatureEnvelope =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope.signature.replace_range(0..2, "00");
        fs::write(&path, serialize_signature_envelope(&envelope).unwrap()).unwrap();
        let tampered = verify_output_manifest_signature(output.path(), &[]).unwrap();
        assert_eq!(tampered.status, SignatureTrustStatus::Invalid);
    }

    #[test]
    fn key_generation_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("key.pem");
        let public = dir.path().join("key.pub.pem");
        generate_integrity_keypair(&private, &public).unwrap();
        let private_before = fs::read(&private).unwrap();
        let public_before = fs::read(&public).unwrap();

        assert!(generate_integrity_keypair(&private, &public).is_err());
        assert_eq!(fs::read(&private).unwrap(), private_before);
        assert_eq!(fs::read(&public).unwrap(), public_before);
    }

    #[test]
    fn signing_key_preflight_returns_generated_key_id() {
        let dir = tempfile::tempdir().unwrap();
        let (private, public) = make_keys(dir.path(), "key");
        let expected = public_key_id(&load_public_key(&public).unwrap());

        assert_eq!(integrity_signing_key_id(&private).unwrap(), expected);
        assert!(integrity_signing_key_id(&dir.path().join("missing.pem")).is_err());
        assert_eq!(
            parent_dir(Path::new("relative.pem")).unwrap(),
            Path::new(".")
        );
    }
}
