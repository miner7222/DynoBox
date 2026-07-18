//! Deterministic SHA-256 output manifest (phase 1).
//!
//! After a pipeline finishes writing an output directory, DynoBox records every
//! regular artifact as a sorted, relative-path inventory with size and SHA-256.
//! The manifest itself is written atomically as pretty-printed JSON with a
//! trailing newline so two runs over identical bytes produce identical files.
//!
//! Phase 1 covers generation and exact-set verification only. Signature support
//! (`dynobox-manifest.sig`) is reserved by name for a later phase.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Manifest file written into the output directory root.
pub const MANIFEST_FILE_NAME: &str = "dynobox-manifest.json";
/// Reserved signature file name (phase 2+; excluded from the inventory).
pub const MANIFEST_SIGNATURE_FILE_NAME: &str = "dynobox-manifest.sig";
/// Pipeline HTML report; always included when present as a regular file.
pub const REPORT_FILE_NAME: &str = "report.html";

/// Value of the `schema` field for this format.
pub const MANIFEST_SCHEMA: &str = "dynobox.output_manifest";
/// Current schema version.
pub const MANIFEST_VERSION: u32 = 1;

/// Streaming hash buffer sized for multi-GB firmware artifacts.
const HASH_BUFFER_SIZE: usize = 1024 * 1024;

/// Root document stored in [`MANIFEST_FILE_NAME`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputManifest {
    pub schema: String,
    pub version: u32,
    /// DynoBox package version that produced the manifest.
    pub generator: String,
    /// Caller-supplied ISO-8601 generation timestamp.
    pub generated_at: String,
    /// Whether semantic (AVB/XML/super) verification succeeded for this output.
    pub semantic_verification: bool,
    /// Sorted recursive regular-file inventory.
    pub artifacts: Vec<ManifestArtifact>,
}

/// One inventoried regular file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifact {
    /// Path relative to the output root using `/` separators.
    pub path: String,
    pub size: u64,
    /// Lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
}

/// Structured mismatch reported by [`verify_output_manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManifestIssue {
    Missing {
        path: String,
    },
    Unexpected {
        path: String,
    },
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    Malformed {
        message: String,
    },
}

/// Result of comparing an on-disk tree against its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestVerificationReport {
    pub manifest_path: PathBuf,
    pub issues: Vec<ManifestIssue>,
}

impl ManifestVerificationReport {
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }
}

/// DynoBox version string used for the `generator` field.
pub fn dynobox_generator_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Scan `output_dir`, hash every included regular file, and build a manifest.
///
/// `generated_at` is supplied by the caller so generation can be deterministic
/// in tests and so pipeline timestamps stay consistent with the HTML report.
/// Callers should pass an ISO-8601 timestamp.
pub fn build_output_manifest(
    output_dir: &Path,
    generated_at: impl Into<String>,
    semantic_verification: bool,
) -> Result<OutputManifest> {
    let artifacts = collect_artifacts(output_dir)?;
    Ok(OutputManifest {
        schema: MANIFEST_SCHEMA.to_string(),
        version: MANIFEST_VERSION,
        generator: dynobox_generator_version(),
        generated_at: generated_at.into(),
        semantic_verification,
        artifacts,
    })
}

/// Serialize `manifest` to deterministic pretty JSON and atomically replace
/// `output_dir/dynobox-manifest.json`.
pub fn write_output_manifest(output_dir: &Path, manifest: &OutputManifest) -> Result<()> {
    let path = output_dir.join(MANIFEST_FILE_NAME);
    let bytes = serialize_manifest(manifest)?;
    write_atomic(&path, &bytes)
        .with_context(|| format!("Failed to write output manifest to {}", path.display()))?;
    Ok(())
}

/// Build a manifest for `output_dir` and write it atomically.
pub fn write_output_manifest_for_dir(
    output_dir: &Path,
    generated_at: impl Into<String>,
    semantic_verification: bool,
) -> Result<OutputManifest> {
    let manifest = build_output_manifest(output_dir, generated_at, semantic_verification)?;
    write_output_manifest(output_dir, &manifest)?;
    Ok(manifest)
}

/// Read and parse `output_dir/dynobox-manifest.json`.
pub fn read_output_manifest(output_dir: &Path) -> Result<OutputManifest> {
    let path = output_dir.join(MANIFEST_FILE_NAME);
    let bytes = fs::read(&path)
        .with_context(|| format!("Failed to read output manifest from {}", path.display()))?;
    parse_manifest_bytes(&bytes)
        .with_context(|| format!("Failed to parse output manifest at {}", path.display()))
}

/// Verify that the on-disk inventory matches the stored manifest exactly.
///
/// Returns structured issues for missing, unexpected, size/digest mismatches,
/// and malformed manifests. I/O failures while reading the tree still surface
/// as `Err`.
pub fn verify_output_manifest(output_dir: &Path) -> Result<ManifestVerificationReport> {
    let manifest_path = output_dir.join(MANIFEST_FILE_NAME);
    let mut issues = Vec::new();

    let manifest = match fs::read(&manifest_path) {
        Ok(bytes) => match parse_manifest_bytes(&bytes) {
            Ok(manifest) => manifest,
            Err(err) => {
                issues.push(ManifestIssue::Malformed {
                    message: err.to_string(),
                });
                return Ok(ManifestVerificationReport {
                    manifest_path,
                    issues,
                });
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            issues.push(ManifestIssue::Malformed {
                message: format!("manifest not found: {}", manifest_path.display()),
            });
            return Ok(ManifestVerificationReport {
                manifest_path,
                issues,
            });
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "Failed to read output manifest from {}",
                    manifest_path.display()
                )
            });
        }
    };

    // `parse_manifest_bytes` already rejects duplicate / unsorted / CI-colliding
    // artifact arrays, so BTreeMap keying here is safe for verification.
    let actual = collect_artifacts(output_dir)?
        .into_iter()
        .map(|artifact| (artifact.path.clone(), artifact))
        .collect::<BTreeMap<_, _>>();
    let expected = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.clone(), artifact))
        .collect::<BTreeMap<_, _>>();

    for (path, expected_artifact) in &expected {
        match actual.get(path) {
            None => issues.push(ManifestIssue::Missing { path: path.clone() }),
            Some(actual_artifact) => {
                if actual_artifact.size != expected_artifact.size {
                    issues.push(ManifestIssue::SizeMismatch {
                        path: path.clone(),
                        expected: expected_artifact.size,
                        actual: actual_artifact.size,
                    });
                } else if actual_artifact.sha256 != expected_artifact.sha256 {
                    issues.push(ManifestIssue::DigestMismatch {
                        path: path.clone(),
                        expected: expected_artifact.sha256.clone(),
                        actual: actual_artifact.sha256.clone(),
                    });
                }
            }
        }
    }

    for path in actual.keys() {
        if !expected.contains_key(path) {
            issues.push(ManifestIssue::Unexpected { path: path.clone() });
        }
    }

    Ok(ManifestVerificationReport {
        manifest_path,
        issues,
    })
}

/// Deterministic pretty-JSON bytes ending with a single trailing newline.
pub fn serialize_manifest(manifest: &OutputManifest) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .context("Failed to serialize output manifest to JSON")?;
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn parse_manifest_bytes(bytes: &[u8]) -> Result<OutputManifest> {
    let manifest: OutputManifest =
        serde_json::from_slice(bytes).map_err(|err| anyhow!("malformed manifest JSON: {err}"))?;
    if manifest.schema != MANIFEST_SCHEMA {
        bail!(
            "unsupported manifest schema '{}'; expected '{}'",
            manifest.schema,
            MANIFEST_SCHEMA
        );
    }
    if manifest.version != MANIFEST_VERSION {
        bail!(
            "unsupported manifest version {}; expected {}",
            manifest.version,
            MANIFEST_VERSION
        );
    }

    let mut previous: Option<&str> = None;
    let mut seen_ci: HashMap<String, String> = HashMap::new();
    for artifact in &manifest.artifacts {
        validate_relative_slash_path(&artifact.path)?;
        if !is_lowercase_hex_sha256(&artifact.sha256) {
            bail!(
                "artifact '{}' has invalid sha256 digest '{}'",
                artifact.path,
                artifact.sha256
            );
        }

        if let Some(prev) = previous {
            match artifact.path.as_str().cmp(prev) {
                std::cmp::Ordering::Equal => {
                    bail!("duplicate artifact path '{}'", artifact.path);
                }
                std::cmp::Ordering::Less => {
                    bail!(
                        "artifact paths are not sorted: '{}' appears after '{}'",
                        artifact.path,
                        prev
                    );
                }
                std::cmp::Ordering::Greater => {}
            }
        }
        previous = Some(artifact.path.as_str());

        let ci_key = artifact.path.to_lowercase();
        if let Some(existing) = seen_ci.get(&ci_key) {
            bail!(
                "case-insensitive artifact path collision: '{}' and '{}'",
                existing,
                artifact.path
            );
        }
        seen_ci.insert(ci_key, artifact.path.clone());
    }

    Ok(manifest)
}

fn collect_artifacts(output_dir: &Path) -> Result<Vec<ManifestArtifact>> {
    if !output_dir.is_dir() {
        bail!(
            "output directory does not exist or is not a directory: {}",
            output_dir.display()
        );
    }

    let mut artifacts = Vec::new();
    // Lowercase path -> first-seen original path, for case-insensitive collisions.
    let mut seen_ci: HashMap<String, String> = HashMap::new();
    walk_collect(output_dir, output_dir, true, &mut artifacts, &mut seen_ci)?;
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(artifacts)
}

fn walk_collect(
    root: &Path,
    dir: &Path,
    is_root: bool,
    artifacts: &mut Vec<ManifestArtifact>,
    seen_ci: &mut HashMap<String, String>,
) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to list directory {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF8 file name under {}", dir.display()))?;

        // Only the output root may omit the reserved manifest/signature names
        // and their atomic-write temp files. Nested same-name files and arbitrary
        // user `.*.tmp` artifacts remain part of the inventory.
        if is_root && is_excluded_root_entry(name) {
            continue;
        }

        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("Failed to stat {}", path.display()))?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            bail!(
                "refusing to inventory symlink in output tree: {}",
                path.display()
            );
        }
        if file_type.is_dir() {
            walk_collect(root, &path, false, artifacts, seen_ci)?;
            continue;
        }
        if !file_type.is_file() {
            bail!(
                "refusing to inventory special file in output tree: {}",
                path.display()
            );
        }

        let relative = relative_slash_path(root, &path)?;
        let ci_key = relative.to_lowercase();
        if let Some(existing) = seen_ci.get(&ci_key) {
            if existing != &relative {
                bail!(
                    "case-insensitive path collision in output tree: '{}' and '{}'",
                    existing,
                    relative
                );
            }
            bail!("duplicate path in output tree: '{relative}'");
        }
        seen_ci.insert(ci_key, relative.clone());

        let (size, sha256) = sha256_file(&path)
            .with_context(|| format!("Failed to hash artifact {}", path.display()))?;
        artifacts.push(ManifestArtifact {
            path: relative,
            size,
            sha256,
        });
    }

    Ok(())
}

/// Root-only exclusions: the live manifest/signature files and the exact atomic
/// temp prefix patterns produced by [`write_atomic`] for those names.
fn is_excluded_root_entry(name: &str) -> bool {
    name == MANIFEST_FILE_NAME
        || name == MANIFEST_SIGNATURE_FILE_NAME
        || is_atomic_temp_for(name, MANIFEST_FILE_NAME)
        || is_atomic_temp_for(name, MANIFEST_SIGNATURE_FILE_NAME)
}

/// Atomic-write temps live beside the final file as `.{final_name}.*.tmp`.
fn is_atomic_temp_for(name: &str, final_name: &str) -> bool {
    let prefix = format!(".{final_name}.");
    // Require a non-empty random middle segment: `.{name}.<id>.tmp`.
    name.starts_with(&prefix) && name.ends_with(".tmp") && name.len() > prefix.len() + ".tmp".len()
}

fn relative_slash_path(root: &Path, full: &Path) -> Result<String> {
    let rel = full.strip_prefix(root).map_err(|_| {
        anyhow!(
            "path '{}' is outside output directory '{}'",
            full.display(),
            root.display()
        )
    })?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                let text = part
                    .to_str()
                    .ok_or_else(|| anyhow!("non-UTF8 path component in {}", full.display()))?;
                validate_path_component(text)?;
                parts.push(text);
            }
            Component::CurDir | Component::ParentDir => {
                bail!("path '{}' contains '.' or '..' components", full.display());
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("absolute path is not allowed: {}", full.display());
            }
        }
    }
    if parts.is_empty() {
        bail!("empty relative path for {}", full.display());
    }
    Ok(parts.join("/"))
}

fn validate_relative_slash_path(path: &str) -> Result<()> {
    if path.is_empty() {
        bail!("artifact path must not be empty");
    }
    if path.contains('\0') {
        bail!("artifact path must not contain NUL: '{path}'");
    }
    if path.starts_with('/') || path.starts_with('\\') {
        bail!("artifact path must be relative: '{path}'");
    }
    if path.contains('\\') {
        bail!("artifact path must use '/' separators: '{path}'");
    }
    let mut first = true;
    for component in path.split('/') {
        validate_path_component(component)?;
        if first && is_windows_drive_like(component) {
            bail!("artifact path must not start with a Windows drive component: '{path}'");
        }
        first = false;
    }
    Ok(())
}

fn validate_path_component(component: &str) -> Result<()> {
    if component.is_empty() {
        bail!("artifact path contains an empty component");
    }
    if component.contains('\0') {
        bail!("artifact path component must not contain NUL");
    }
    if component == "." || component == ".." {
        bail!("artifact path must not contain '.' or '..'");
    }
    if component.contains('\\') {
        bail!("artifact path component must not contain backslash");
    }
    if is_windows_drive_like(component) {
        bail!("artifact path must not contain a Windows drive component: '{component}'");
    }
    Ok(())
}

/// `X:` / `X:rest` style components are not portable relative path segments.
fn is_windows_drive_like(component: &str) -> bool {
    let mut chars = component.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic()
    )
}

fn sha256_file(path: &Path) -> Result<(u64, String)> {
    let pre_meta = fs::metadata(path)
        .with_context(|| format!("Failed to read metadata before hashing {}", path.display()))?;
    let pre_size = pre_meta.len();

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("file size overflow while hashing {}", path.display()))?;
    }

    let post_meta = fs::metadata(path)
        .with_context(|| format!("Failed to read metadata after hashing {}", path.display()))?;
    let post_size = post_meta.len();
    if pre_size != size || post_size != size {
        bail!(
            "file size changed while hashing {}: pre={pre_size}, read={size}, post={post_size}",
            path.display()
        );
    }

    Ok((size, hex_encode(hasher.finalize().as_slice())))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn is_lowercase_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create parent directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("manifest path has a non-UTF8 file name: {}", path.display()))?;

    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{file_name}."))
        .suffix(".tmp")
        .tempfile_in(parent)
        .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;
    temp.write_all(data)
        .and_then(|()| temp.flush())
        .and_then(|()| temp.as_file().sync_all())
        .with_context(|| format!("Failed to write temp manifest beside {}", path.display()))?;
    temp.persist(path).map_err(|err| {
        anyhow!(
            "Failed to rename temp manifest onto {}: {}",
            path.display(),
            err.error
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    fn known_digest(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
    }

    fn handcrafted_manifest_json(artifacts_json: &str) -> String {
        format!(
            r#"{{
  "schema": "{schema}",
  "version": {version},
  "generator": "test",
  "generated_at": "2026-07-18T00:00:00Z",
  "semantic_verification": true,
  "artifacts": {artifacts_json}
}}
"#,
            schema = MANIFEST_SCHEMA,
            version = MANIFEST_VERSION,
        )
    }

    #[test]
    fn sha256_known_abc() {
        let digest = Sha256::digest(b"abc");
        assert_eq!(
            hex_encode(digest.as_slice()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn deterministic_ordering_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("z.bin"), b"zzz");
        write_file(&dir.path().join("a.bin"), b"aaa");
        write_file(&dir.path().join("nested").join("m.bin"), b"mmm");
        // Root signature and exact atomic temp for the root manifest are ignored.
        write_file(&dir.path().join(MANIFEST_SIGNATURE_FILE_NAME), b"sig");
        write_file(
            &dir.path().join(format!(".{MANIFEST_FILE_NAME}.abc123.tmp")),
            b"temp",
        );

        let first = build_output_manifest(dir.path(), "2026-07-18T00:00:00Z", true).unwrap();
        let second = build_output_manifest(dir.path(), "2026-07-18T00:00:00Z", true).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first
                .artifacts
                .iter()
                .map(|artifact| artifact.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a.bin", "nested/m.bin", "z.bin"]
        );

        let bytes_a = serialize_manifest(&first).unwrap();
        let bytes_b = serialize_manifest(&second).unwrap();
        assert_eq!(bytes_a, bytes_b);
        assert!(bytes_a.ends_with(b"\n"));
        assert!(!bytes_a.ends_with(b"\n\n"));
    }

    #[test]
    fn report_html_is_included() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join(REPORT_FILE_NAME), b"<html>ok</html>");
        write_file(&dir.path().join("boot.img"), b"boot");

        let manifest = build_output_manifest(dir.path(), "2026-07-18T01:00:00Z", false).unwrap();
        let paths: Vec<&str> = manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect();
        assert!(paths.contains(&REPORT_FILE_NAME));
        assert!(paths.contains(&"boot.img"));
        assert!(!paths.contains(&MANIFEST_FILE_NAME));
    }

    #[test]
    fn write_and_verify_clean_tree() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("payload.bin"), b"payload-bytes");
        write_file(&dir.path().join(REPORT_FILE_NAME), b"<html/>");

        let manifest =
            write_output_manifest_for_dir(dir.path(), "2026-07-18T02:00:00Z", true).unwrap();
        assert!(dir.path().join(MANIFEST_FILE_NAME).is_file());
        assert!(manifest.semantic_verification);
        assert_eq!(manifest.schema, MANIFEST_SCHEMA);
        assert_eq!(manifest.version, MANIFEST_VERSION);
        assert_eq!(manifest.generator, dynobox_generator_version());

        let report = verify_output_manifest(dir.path()).unwrap();
        assert!(report.is_ok(), "{:?}", report.issues);

        // No leftover same-dir temps for the root manifest write.
        for entry in fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            assert!(
                !is_atomic_temp_for(&name, MANIFEST_FILE_NAME),
                "leftover temp file: {name}"
            );
        }
    }

    #[test]
    fn verify_detects_tamper_missing_and_extra() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("keep.bin"), b"keep");
        write_file(&dir.path().join("touch.bin"), b"original");
        write_output_manifest_for_dir(dir.path(), "2026-07-18T03:00:00Z", true).unwrap();

        // Tamper digest.
        write_file(&dir.path().join("touch.bin"), b"tampered");
        let tampered = verify_output_manifest(dir.path()).unwrap();
        assert!(!tampered.is_ok());
        assert!(
            tampered.issues.iter().any(|issue| matches!(
                issue,
                ManifestIssue::DigestMismatch { path, .. } if path == "touch.bin"
            )),
            "{:?}",
            tampered.issues
        );

        // Restore and remove a file.
        write_file(&dir.path().join("touch.bin"), b"original");
        fs::remove_file(dir.path().join("keep.bin")).unwrap();
        let missing = verify_output_manifest(dir.path()).unwrap();
        assert!(
            missing.issues.iter().any(|issue| matches!(
                issue,
                ManifestIssue::Missing { path } if path == "keep.bin"
            )),
            "{:?}",
            missing.issues
        );

        // Restore keep, add an unexpected file.
        write_file(&dir.path().join("keep.bin"), b"keep");
        write_file(&dir.path().join("extra.bin"), b"extra");
        let extra = verify_output_manifest(dir.path()).unwrap();
        assert!(
            extra.issues.iter().any(|issue| matches!(
                issue,
                ManifestIssue::Unexpected { path } if path == "extra.bin"
            )),
            "{:?}",
            extra.issues
        );
    }

    #[test]
    fn verify_detects_size_mismatch_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("blob.bin"), b"1234");
        write_output_manifest_for_dir(dir.path(), "2026-07-18T04:00:00Z", false).unwrap();

        // Same digest path but force a size mismatch by editing the manifest.
        let mut manifest = read_output_manifest(dir.path()).unwrap();
        manifest.artifacts[0].size = 1;
        // Keep digest as-is so the size branch fires first.
        write_output_manifest(dir.path(), &manifest).unwrap();
        // Actual file is still 4 bytes.
        let report = verify_output_manifest(dir.path()).unwrap();
        assert!(
            report.issues.iter().any(|issue| matches!(
                issue,
                ManifestIssue::SizeMismatch {
                    path,
                    expected: 1,
                    actual: 4
                } if path == "blob.bin"
            )),
            "{:?}",
            report.issues
        );

        write_file(&dir.path().join(MANIFEST_FILE_NAME), b"{ not valid json ]");
        let malformed = verify_output_manifest(dir.path()).unwrap();
        assert!(
            malformed
                .issues
                .iter()
                .any(|issue| matches!(issue, ManifestIssue::Malformed { .. })),
            "{:?}",
            malformed.issues
        );
    }

    #[test]
    fn excludes_only_root_manifest_signature_and_atomic_temps() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("data.bin"), b"data");
        write_file(&dir.path().join(MANIFEST_FILE_NAME), b"stale");
        write_file(&dir.path().join(MANIFEST_SIGNATURE_FILE_NAME), b"sig");
        write_file(
            &dir.path().join(format!(".{MANIFEST_FILE_NAME}.write1.tmp")),
            b"m-temp",
        );
        write_file(
            &dir.path()
                .join(format!(".{MANIFEST_SIGNATURE_FILE_NAME}.write2.tmp")),
            b"s-temp",
        );
        // Nested reserved names and arbitrary user temps are inventoried.
        write_file(
            &dir.path().join("nested").join(MANIFEST_FILE_NAME),
            b"nested-manifest",
        );
        write_file(
            &dir.path().join("nested").join(MANIFEST_SIGNATURE_FILE_NAME),
            b"nested-sig",
        );
        write_file(&dir.path().join(".user-backup.tmp"), b"user-temp");
        write_file(&dir.path().join(".partial.json.tmp"), b"other-temp");

        let manifest = build_output_manifest(dir.path(), "2026-07-18T05:00:00Z", true).unwrap();
        let paths: Vec<&str> = manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                ".partial.json.tmp",
                ".user-backup.tmp",
                "data.bin",
                &format!("nested/{MANIFEST_FILE_NAME}"),
                &format!("nested/{MANIFEST_SIGNATURE_FILE_NAME}"),
            ]
        );
    }

    #[test]
    fn validate_relative_paths_reject_dot_absolute_backslash_drive_and_nul() {
        assert!(validate_relative_slash_path("a/b").is_ok());
        assert!(validate_relative_slash_path("../x").is_err());
        assert!(validate_relative_slash_path("./x").is_err());
        assert!(validate_relative_slash_path("/abs").is_err());
        assert!(validate_relative_slash_path("a\\b").is_err());
        assert!(validate_relative_slash_path("").is_err());
        assert!(validate_relative_slash_path("C:/windows").is_err());
        assert!(validate_relative_slash_path("c:").is_err());
        assert!(validate_relative_slash_path("payload/C:evil").is_err());
        assert!(validate_relative_slash_path("a/\0b").is_err());
        assert!(validate_relative_slash_path("a\0b").is_err());
    }

    #[test]
    fn parse_rejects_duplicate_unsorted_and_case_colliding_artifacts() {
        let digest_a = known_digest(b"a");
        let digest_b = known_digest(b"b");

        let duplicate = handcrafted_manifest_json(&format!(
            r#"[
    {{ "path": "a.bin", "size": 1, "sha256": "{digest_a}" }},
    {{ "path": "a.bin", "size": 1, "sha256": "{digest_a}" }}
  ]"#
        ));
        let err = parse_manifest_bytes(duplicate.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("duplicate artifact path"),
            "expected duplicate rejection, got: {err}"
        );

        let unsorted = handcrafted_manifest_json(&format!(
            r#"[
    {{ "path": "z.bin", "size": 1, "sha256": "{digest_a}" }},
    {{ "path": "a.bin", "size": 1, "sha256": "{digest_b}" }}
  ]"#
        ));
        let err = parse_manifest_bytes(unsorted.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not sorted"),
            "expected sort rejection, got: {err}"
        );

        let case_collision = handcrafted_manifest_json(&format!(
            r#"[
    {{ "path": "Artifact.BIN", "size": 1, "sha256": "{digest_a}" }},
    {{ "path": "artifact.bin", "size": 1, "sha256": "{digest_b}" }}
  ]"#
        ));
        let err = parse_manifest_bytes(case_collision.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("case-insensitive artifact path collision"),
            "expected case-collision rejection, got: {err}"
        );

        let drive_path = handcrafted_manifest_json(&format!(
            r#"[
    {{ "path": "C:/boot.img", "size": 1, "sha256": "{digest_a}" }}
  ]"#
        ));
        let err = parse_manifest_bytes(drive_path.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Windows drive"),
            "expected drive-path rejection, got: {err}"
        );

        let sorted_ok = handcrafted_manifest_json(&format!(
            r#"[
    {{ "path": "a.bin", "size": 1, "sha256": "{digest_a}" }},
    {{ "path": "z.bin", "size": 1, "sha256": "{digest_b}" }}
  ]"#
        ));
        let ok = parse_manifest_bytes(sorted_ok.as_bytes()).unwrap();
        assert_eq!(ok.artifacts.len(), 2);
    }

    #[test]
    fn verify_reports_malformed_for_handcrafted_duplicate_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("a.bin"), b"a");
        let digest = known_digest(b"a");
        let bad = handcrafted_manifest_json(&format!(
            r#"[
    {{ "path": "a.bin", "size": 1, "sha256": "{digest}" }},
    {{ "path": "a.bin", "size": 1, "sha256": "{digest}" }}
  ]"#
        ));
        write_file(
            dir.path().join(MANIFEST_FILE_NAME).as_path(),
            bad.as_bytes(),
        );

        let report = verify_output_manifest(dir.path()).unwrap();
        assert!(
            report.issues.iter().any(|issue| matches!(
                issue,
                ManifestIssue::Malformed { message } if message.contains("duplicate artifact path")
            )),
            "{:?}",
            report.issues
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_on_supported_os() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.bin");
        write_file(&target, b"target");
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = build_output_manifest(dir.path(), "2026-07-18T06:00:00Z", true).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("symlink"),
            "expected symlink rejection, got: {message}"
        );
    }

    #[test]
    fn rejects_case_insensitive_path_collision_when_fs_allows_both() {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("Artifact.BIN");
        let lower = dir.path().join("artifact.bin");
        write_file(&upper, b"one");
        // On case-insensitive filesystems the second create overwrites the first;
        // only assert collision rejection when both names coexist as distinct entries.
        if let Err(err) = File::create_new(&lower) {
            let _ = err;
            return;
        }
        write_file(&lower, b"two");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        if names.len() < 2 {
            return;
        }

        let err = build_output_manifest(dir.path(), "2026-07-18T07:00:00Z", true).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("case-insensitive path collision"),
            "expected collision error, got: {message}"
        );
    }

    #[test]
    fn atomic_temp_helper_matches_exact_prefix_only() {
        assert!(is_atomic_temp_for(
            &format!(".{MANIFEST_FILE_NAME}.xyz.tmp"),
            MANIFEST_FILE_NAME
        ));
        assert!(is_atomic_temp_for(
            &format!(".{MANIFEST_SIGNATURE_FILE_NAME}.1.tmp"),
            MANIFEST_SIGNATURE_FILE_NAME
        ));
        assert!(!is_atomic_temp_for(".partial.json.tmp", MANIFEST_FILE_NAME));
        assert!(!is_atomic_temp_for(
            &format!(".{MANIFEST_FILE_NAME}.tmp"),
            MANIFEST_FILE_NAME
        ));
        assert!(!is_atomic_temp_for(
            &format!("x.{MANIFEST_FILE_NAME}.abc.tmp"),
            MANIFEST_FILE_NAME
        ));
    }
}
