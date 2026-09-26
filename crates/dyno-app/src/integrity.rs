//! Deterministic SHA-256 output manifests.
//!
//! After a pipeline finishes writing an output directory, DynoBox records every
//! regular artifact as a sorted, relative-path inventory with size and SHA-256.
//! The manifest itself is written atomically as pretty-printed JSON with a
//! trailing newline so two runs over identical bytes produce identical files.
//!
//! Detached Ed25519 authentication lives in [`crate::integrity_signature`].

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use dynobox_core::hex::hex_encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Manifest file written into the output directory root.
pub const MANIFEST_FILE_NAME: &str = "dynobox-manifest.json";
/// Detached signature file name; excluded from the inventory it authenticates.
pub const MANIFEST_SIGNATURE_FILE_NAME: &str = "dynobox-manifest.sig";
/// Pipeline HTML report; always included when present as a regular file.
pub const REPORT_FILE_NAME: &str = "report.html";
/// Root artifact intentionally omitted when the output passed through resign.
pub const RESIGN_EXCLUDED_ROOT_ARTIFACT: &str = "abl.elf";

/// Value of the `schema` field for this format.
pub const MANIFEST_SCHEMA: &str = "dynobox.output_manifest";
/// Current schema version.
pub const MANIFEST_VERSION: u32 = 1;

/// Streaming hash buffer sized for multi-GB firmware artifacts.
const HASH_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Root document stored in [`MANIFEST_FILE_NAME`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputManifest {
    pub schema: String,
    pub version: u32,
    /// DynoBox package version and, when built from Git, exact source revision.
    pub generator: String,
    /// Caller-supplied ISO-8601 generation timestamp.
    pub generated_at: String,
    /// Whether semantic (AVB/XML/super) verification succeeded for this output.
    pub semantic_verification: bool,
    /// Whether the producing pipeline ran a resign stage. Resign outputs omit
    /// the root `abl.elf` from their artifact inventory by policy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub resign_performed: bool,
    /// Immutable inventory of `.img` files from the original request input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_artifacts: Vec<ManifestArtifact>,
    /// Sorted recursive regular-file inventory.
    pub artifacts: Vec<ManifestArtifact>,
}

#[derive(Debug)]
struct ArtifactCandidate {
    path: String,
    full_path: PathBuf,
    discovered_size: u64,
}

/// Policy captured in a generated output manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutputManifestOptions {
    /// Whether semantic AVB/XML/super verification succeeded.
    pub semantic_verification: bool,
    /// Whether resign ran, enabling the root `abl.elf` exclusion.
    pub resign_performed: bool,
}

/// One inventoried regular file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifact {
    /// Path relative to the corresponding inventory root using `/` separators.
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

/// DynoBox build identity used for the manifest `generator` field and report.
pub fn dynobox_generator_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    match option_env!("DYNOBOX_GIT_REVISION").filter(|revision| !revision.is_empty()) {
        Some(revision) => format!("{version}+git.{revision}"),
        None => version.to_string(),
    }
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
    build_output_manifest_with_options(
        output_dir,
        generated_at,
        OutputManifestOptions {
            semantic_verification,
            resign_performed: false,
        },
    )
}

/// Scan `output_dir` using explicit pipeline policy and build a manifest.
pub fn build_output_manifest_with_options(
    output_dir: &Path,
    generated_at: impl Into<String>,
    options: OutputManifestOptions,
) -> Result<OutputManifest> {
    build_output_manifest_with_input_artifacts(output_dir, generated_at, options, &[])
}

/// Scan `output_dir` and attach an immutable original-input image inventory.
pub fn build_output_manifest_with_input_artifacts(
    output_dir: &Path,
    generated_at: impl Into<String>,
    options: OutputManifestOptions,
    input_artifacts: &[ManifestArtifact],
) -> Result<OutputManifest> {
    validate_artifact_array(input_artifacts, "input artifact")?;
    let artifacts = collect_artifacts(output_dir, options.resign_performed)?;
    Ok(OutputManifest {
        schema: MANIFEST_SCHEMA.to_string(),
        version: MANIFEST_VERSION,
        generator: dynobox_generator_version(),
        generated_at: generated_at.into(),
        semantic_verification: options.semantic_verification,
        resign_performed: options.resign_performed,
        input_artifacts: input_artifacts.to_vec(),
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

/// Build and atomically write a manifest using explicit pipeline policy.
pub fn write_output_manifest_for_dir_with_options(
    output_dir: &Path,
    generated_at: impl Into<String>,
    options: OutputManifestOptions,
) -> Result<OutputManifest> {
    write_output_manifest_for_dir_with_input_artifacts(output_dir, generated_at, options, &[])
}

/// Build and write a manifest with an immutable original-input image inventory.
pub fn write_output_manifest_for_dir_with_input_artifacts(
    output_dir: &Path,
    generated_at: impl Into<String>,
    options: OutputManifestOptions,
    input_artifacts: &[ManifestArtifact],
) -> Result<OutputManifest> {
    let manifest = build_output_manifest_with_input_artifacts(
        output_dir,
        generated_at,
        options,
        input_artifacts,
    )?;
    write_output_manifest(output_dir, &manifest)?;
    Ok(manifest)
}

/// Read and parse `output_dir/dynobox-manifest.json`.
pub fn read_output_manifest(output_dir: &Path) -> Result<OutputManifest> {
    let path = output_dir.join(MANIFEST_FILE_NAME);
    let bytes = fs::read(&path)
        .with_context(|| format!("Failed to read output manifest from {}", path.display()))?;
    parse_output_manifest_bytes(&bytes)
        .with_context(|| format!("Failed to parse output manifest at {}", path.display()))
}

/// Verify that the on-disk inventory matches the stored manifest exactly.
///
/// Returns structured issues for missing, unexpected, size/digest mismatches,
/// and malformed manifests. I/O failures while reading the tree still surface
/// as `Err`.
pub fn verify_output_manifest(output_dir: &Path) -> Result<ManifestVerificationReport> {
    let manifest_path = output_dir.join(MANIFEST_FILE_NAME);

    match fs::symlink_metadata(&manifest_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            let message = format!(
                "manifest must be a regular file, not a symlink or special file: {}",
                manifest_path.display()
            );
            return Ok(ManifestVerificationReport {
                manifest_path,
                issues: vec![ManifestIssue::Malformed { message }],
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Failed to inspect output manifest at {}",
                    manifest_path.display()
                )
            });
        }
    }

    match fs::read(&manifest_path) {
        Ok(bytes) => verify_output_manifest_bytes(output_dir, &bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let message = format!("manifest not found: {}", manifest_path.display());
            Ok(ManifestVerificationReport {
                manifest_path,
                issues: vec![ManifestIssue::Malformed { message }],
            })
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "Failed to read output manifest from {}",
                manifest_path.display()
            )
        }),
    }
}

/// Verify `output_dir` against the exact already-loaded manifest bytes.
pub fn verify_output_manifest_bytes(
    output_dir: &Path,
    manifest_bytes: &[u8],
) -> Result<ManifestVerificationReport> {
    let manifest_path = output_dir.join(MANIFEST_FILE_NAME);
    let manifest = match parse_output_manifest_bytes(manifest_bytes) {
        Ok(manifest) => manifest,
        Err(err) => {
            return Ok(ManifestVerificationReport {
                manifest_path,
                issues: vec![ManifestIssue::Malformed {
                    message: err.to_string(),
                }],
            });
        }
    };
    let candidates = discover_artifact_candidates(output_dir, manifest.resign_performed)?;

    // Parsing rejects duplicate, unsorted, and case-colliding paths, so maps
    // cannot discard distinct validated entries here.
    let actual = candidates
        .into_iter()
        .map(|candidate| (candidate.path.clone(), candidate))
        .collect::<BTreeMap<_, _>>();
    let expected = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.clone(), artifact))
        .collect::<BTreeMap<_, _>>();

    let mut hash_candidates = Vec::new();
    let mut issues = Vec::new();
    for (path, expected_artifact) in expected {
        match actual.get(&path) {
            None => issues.push(ManifestIssue::Missing { path: path.clone() }),
            Some(candidate) => {
                if candidate.discovered_size != expected_artifact.size {
                    issues.push(ManifestIssue::SizeMismatch {
                        path: path.clone(),
                        expected: expected_artifact.size,
                        actual: candidate.discovered_size,
                    });
                } else {
                    hash_candidates.push((candidate, expected_artifact));
                }
            }
        }
    }

    for path in actual.keys() {
        if !manifest
            .artifacts
            .iter()
            .any(|artifact| &artifact.path == path)
        {
            issues.push(ManifestIssue::Unexpected { path: path.clone() });
        }
    }

    let candidates_to_hash = hash_candidates
        .iter()
        .map(|(candidate, _)| ArtifactCandidate {
            path: candidate.path.clone(),
            full_path: candidate.full_path.clone(),
            discovered_size: candidate.discovered_size,
        })
        .collect::<Vec<_>>();
    let hashed = hash_candidates_bounded(&candidates_to_hash)?;
    for (artifact, (_, expected_artifact)) in hashed.into_iter().zip(hash_candidates) {
        if artifact.sha256 != expected_artifact.sha256 {
            issues.push(ManifestIssue::DigestMismatch {
                path: artifact.path,
                expected: expected_artifact.sha256.clone(),
                actual: artifact.sha256,
            });
        }
    }
    sort_manifest_issues(&mut issues);

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

pub fn parse_output_manifest_bytes(bytes: &[u8]) -> Result<OutputManifest> {
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

    validate_artifact_array(&manifest.input_artifacts, "input artifact")?;
    validate_artifact_array(&manifest.artifacts, "artifact")?;
    for artifact in &manifest.artifacts {
        if manifest.resign_performed && artifact.path == RESIGN_EXCLUDED_ROOT_ARTIFACT {
            bail!(
                "resign manifest must not inventory excluded root artifact '{}'",
                RESIGN_EXCLUDED_ROOT_ARTIFACT
            );
        }
    }

    Ok(manifest)
}

fn validate_artifact_array(artifacts: &[ManifestArtifact], label: &str) -> Result<()> {
    let mut previous: Option<&str> = None;
    let mut seen_ci: HashMap<String, String> = HashMap::new();
    for artifact in artifacts {
        validate_relative_slash_path(&artifact.path)?;
        if !is_lowercase_hex_sha256(&artifact.sha256) {
            bail!(
                "{label} '{}' has invalid sha256 digest '{}'",
                artifact.path,
                artifact.sha256
            );
        }
        if let Some(prev) = previous {
            match artifact.path.as_str().cmp(prev) {
                std::cmp::Ordering::Equal => {
                    bail!("duplicate {label} path '{}'", artifact.path);
                }
                std::cmp::Ordering::Less => {
                    bail!(
                        "{label} paths are not sorted: '{}' appears after '{}'",
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
                "case-insensitive {label} path collision: '{}' and '{}'",
                existing,
                artifact.path
            );
        }
        seen_ci.insert(ci_key, artifact.path.clone());
    }
    Ok(())
}

fn collect_artifacts(output_dir: &Path, resign_performed: bool) -> Result<Vec<ManifestArtifact>> {
    let candidates = discover_artifact_candidates(output_dir, resign_performed)?;
    hash_candidates_bounded(&candidates)
}

fn discover_artifact_candidates(
    output_dir: &Path,
    resign_performed: bool,
) -> Result<Vec<ArtifactCandidate>> {
    if !output_dir.is_dir() {
        bail!(
            "output directory does not exist or is not a directory: {}",
            output_dir.display()
        );
    }

    let mut candidates = Vec::new();
    // Lowercase path -> first-seen original path, for case-insensitive collisions.
    let mut seen_ci: HashMap<String, String> = HashMap::new();
    walk_discover_output(
        output_dir,
        output_dir,
        true,
        resign_performed,
        &mut candidates,
        &mut seen_ci,
    )?;
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(candidates)
}

fn walk_discover_output(
    root: &Path,
    dir: &Path,
    is_root: bool,
    resign_performed: bool,
    candidates: &mut Vec<ArtifactCandidate>,
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
        if is_root
            && resign_performed
            && file_type.is_file()
            && name == RESIGN_EXCLUDED_ROOT_ARTIFACT
        {
            continue;
        }
        if file_type.is_dir() {
            walk_discover_output(root, &path, false, resign_performed, candidates, seen_ci)?;
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
        candidates.push(ArtifactCandidate {
            path: relative,
            full_path: path,
            discovered_size: metadata.len(),
        });
    }

    Ok(())
}

/// Recursively inventory regular `.img` files from the original request input.
///
/// Directory inputs use normalized relative paths; a regular file input uses
/// its basename. Symlinks and special files are rejected rather than followed.
pub fn collect_input_image_artifacts(input: &Path) -> Result<Vec<ManifestArtifact>> {
    let metadata = fs::symlink_metadata(input)
        .with_context(|| format!("Failed to inspect original input {}", input.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!("refusing to inventory symlink input: {}", input.display());
    }

    let mut candidates = Vec::new();
    let mut seen_ci = HashMap::new();
    if file_type.is_dir() {
        walk_discover_input_images(input, input, &mut candidates, &mut seen_ci)?;
    } else if file_type.is_file() {
        if is_img_path(input) {
            let name = input
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("non-UTF8 original input file name: {}", input.display()))?;
            validate_path_component(name)?;
            candidates.push(ArtifactCandidate {
                path: name.to_string(),
                full_path: input.to_path_buf(),
                discovered_size: metadata.len(),
            });
        }
    } else {
        bail!(
            "refusing to inventory special-file input: {}",
            input.display()
        );
    }

    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    hash_candidates_bounded(&candidates)
}

fn walk_discover_input_images(
    root: &Path,
    dir: &Path,
    candidates: &mut Vec<ArtifactCandidate>,
    seen_ci: &mut HashMap<String, String>,
) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("Failed to read original input directory {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to list original input directory {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        entry
            .file_name()
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF8 file name under {}", dir.display()))?;
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("Failed to stat original input {}", path.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            bail!(
                "refusing to inventory symlink in original input: {}",
                path.display()
            );
        }
        if file_type.is_dir() {
            walk_discover_input_images(root, &path, candidates, seen_ci)?;
            continue;
        }
        if !file_type.is_file() {
            bail!(
                "refusing to inventory special file in original input: {}",
                path.display()
            );
        }
        if !is_img_path(&path) {
            continue;
        }

        let relative = relative_slash_path(root, &path)?;
        let ci_key = relative.to_lowercase();
        if let Some(existing) = seen_ci.get(&ci_key) {
            bail!(
                "case-insensitive input image path collision: '{}' and '{}'",
                existing,
                relative
            );
        }
        seen_ci.insert(ci_key, relative.clone());
        candidates.push(ArtifactCandidate {
            path: relative,
            full_path: path,
            discovered_size: metadata.len(),
        });
    }
    Ok(())
}

fn is_img_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("img"))
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

fn is_false(value: &bool) -> bool {
    !*value
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

fn hash_candidates_bounded(candidates: &[ArtifactCandidate]) -> Result<Vec<ManifestArtifact>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let worker_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(2)
        .min(candidates.len());

    let mut indexed = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            handles.push(scope.spawn(move || {
                let mut buffer = vec![0u8; HASH_BUFFER_SIZE];
                (worker..candidates.len())
                    .step_by(worker_count)
                    .map(|index| {
                        (
                            index,
                            hash_candidate(&candidates[index], &mut buffer).with_context(|| {
                                format!(
                                    "Failed to hash artifact {}",
                                    candidates[index].full_path.display()
                                )
                            }),
                        )
                    })
                    .collect::<Vec<_>>()
            }));
        }

        let mut results = Vec::with_capacity(candidates.len());
        for handle in handles {
            results.extend(
                handle
                    .join()
                    .map_err(|_| anyhow!("artifact hashing worker panicked"))?,
            );
        }
        Ok::<_, anyhow::Error>(results)
    })?;
    indexed.sort_by_key(|(index, _)| *index);
    indexed.into_iter().map(|(_, artifact)| artifact).collect()
}

fn hash_candidate(candidate: &ArtifactCandidate, buffer: &mut [u8]) -> Result<ManifestArtifact> {
    let path = &candidate.full_path;
    let pre_meta = fs::symlink_metadata(path)
        .with_context(|| format!("Failed to read metadata before hashing {}", path.display()))?;
    if pre_meta.file_type().is_symlink() || !pre_meta.file_type().is_file() {
        bail!(
            "artifact became a symlink or special file before hashing: {}",
            path.display()
        );
    }
    let pre_size = pre_meta.len();
    if pre_size != candidate.discovered_size {
        bail!(
            "file size changed after discovery {}: discovered={}, pre={pre_size}",
            path.display(),
            candidate.discovered_size
        );
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    loop {
        let read = file.read(buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("file size overflow while hashing {}", path.display()))?;
    }

    let post_meta = fs::symlink_metadata(path)
        .with_context(|| format!("Failed to read metadata after hashing {}", path.display()))?;
    if post_meta.file_type().is_symlink() || !post_meta.file_type().is_file() {
        bail!(
            "artifact became a symlink or special file while hashing: {}",
            path.display()
        );
    }
    let post_size = post_meta.len();
    if pre_size != size || post_size != size {
        bail!(
            "file size changed while hashing {}: pre={pre_size}, read={size}, post={post_size}",
            path.display()
        );
    }

    Ok(ManifestArtifact {
        path: candidate.path.clone(),
        size,
        sha256: hex_encode(hasher.finalize().as_slice()),
    })
}

fn sort_manifest_issues(issues: &mut [ManifestIssue]) {
    issues.sort_by(|left, right| issue_sort_key(left).cmp(&issue_sort_key(right)));
}

fn issue_sort_key(issue: &ManifestIssue) -> (&str, u8) {
    match issue {
        ManifestIssue::Missing { path } => (path, 0),
        ManifestIssue::Unexpected { path } => (path, 1),
        ManifestIssue::SizeMismatch { path, .. } => (path, 2),
        ManifestIssue::DigestMismatch { path, .. } => (path, 3),
        ManifestIssue::Malformed { message } => (message, 4),
    }
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
    fn old_v1_manifest_without_input_artifacts_parses_as_empty() {
        let json = handcrafted_manifest_json("[]");
        let manifest = parse_output_manifest_bytes(json.as_bytes()).unwrap();
        assert!(manifest.input_artifacts.is_empty());
        assert_eq!(manifest.version, 1);
    }

    #[test]
    fn input_artifacts_are_serialized_deterministically_and_validated_independently() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("output.bin"), b"output");
        let inputs = vec![
            ManifestArtifact {
                path: "boot.img".to_string(),
                size: 4,
                sha256: known_digest(b"boot"),
            },
            ManifestArtifact {
                path: "nested/system.img".to_string(),
                size: 6,
                sha256: known_digest(b"system"),
            },
        ];
        let manifest = build_output_manifest_with_input_artifacts(
            dir.path(),
            "2026-07-18T00:00:00Z",
            OutputManifestOptions {
                semantic_verification: true,
                resign_performed: false,
            },
            &inputs,
        )
        .unwrap();
        assert_eq!(manifest.input_artifacts, inputs);
        assert_eq!(
            serialize_manifest(&manifest).unwrap(),
            serialize_manifest(&manifest).unwrap()
        );

        let mut invalid_inputs = inputs;
        invalid_inputs.swap(0, 1);
        let error = build_output_manifest_with_input_artifacts(
            dir.path(),
            "2026-07-18T00:00:00Z",
            OutputManifestOptions::default(),
            &invalid_inputs,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("input artifact paths are not sorted"));
    }

    #[test]
    fn collects_only_recursive_input_images_with_normalized_paths() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("boot.img"), b"boot");
        write_file(&dir.path().join("nested").join("System.IMG"), b"system");
        write_file(&dir.path().join("nested").join("vendor.bin"), b"vendor");
        write_file(&dir.path().join("notes.img.tmp"), b"ignore");

        let artifacts = collect_input_image_artifacts(dir.path()).unwrap();
        assert_eq!(
            artifacts
                .iter()
                .map(|artifact| artifact.path.as_str())
                .collect::<Vec<_>>(),
            vec!["boot.img", "nested/System.IMG"]
        );
        assert_eq!(artifacts[0].sha256, known_digest(b"boot"));
        assert_eq!(artifacts[1].sha256, known_digest(b"system"));

        let single = collect_input_image_artifacts(&dir.path().join("boot.img")).unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].path, "boot.img");
    }

    #[test]
    fn input_image_collision_is_rejected_when_filesystem_allows_both() {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("Boot.img");
        let lower = dir.path().join("boot.img");
        write_file(&upper, b"one");
        if File::create_new(&lower).is_err() {
            return;
        }
        write_file(&lower, b"two");
        if fs::read_dir(dir.path()).unwrap().count() < 2 {
            return;
        }

        let error = collect_input_image_artifacts(dir.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("case-insensitive input image path collision"));
    }

    #[cfg(unix)]
    #[test]
    fn input_image_collector_rejects_symlinks_and_special_files() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("target.img"), b"target");
        std::os::unix::fs::symlink(dir.path().join("target.img"), dir.path().join("linked.img"))
            .unwrap();
        assert!(
            collect_input_image_artifacts(dir.path())
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );

        fs::remove_file(dir.path().join("linked.img")).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(dir.path().join("socket")).unwrap();
        assert!(
            collect_input_image_artifacts(dir.path())
                .unwrap_err()
                .to_string()
                .contains("special file")
        );
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
    fn resign_policy_excludes_only_root_abl_and_remains_verifiable() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join(RESIGN_EXCLUDED_ROOT_ARTIFACT), b"root-abl");
        write_file(
            &dir.path()
                .join("nested")
                .join(RESIGN_EXCLUDED_ROOT_ARTIFACT),
            b"nested-abl",
        );
        write_file(&dir.path().join("boot.img"), b"boot");

        let ordinary = build_output_manifest(dir.path(), "2026-07-18T01:30:00Z", true).unwrap();
        assert!(!ordinary.resign_performed);
        assert!(
            ordinary
                .artifacts
                .iter()
                .any(|artifact| artifact.path == RESIGN_EXCLUDED_ROOT_ARTIFACT)
        );
        assert!(
            !String::from_utf8(serialize_manifest(&ordinary).unwrap())
                .unwrap()
                .contains("resign_performed")
        );

        let resigned = write_output_manifest_for_dir_with_options(
            dir.path(),
            "2026-07-18T01:31:00Z",
            OutputManifestOptions {
                semantic_verification: true,
                resign_performed: true,
            },
        )
        .unwrap();
        assert!(resigned.resign_performed);
        assert_eq!(
            resigned
                .artifacts
                .iter()
                .map(|artifact| artifact.path.as_str())
                .collect::<Vec<_>>(),
            vec!["boot.img", "nested/abl.elf"]
        );
        assert!(
            String::from_utf8(serialize_manifest(&resigned).unwrap())
                .unwrap()
                .contains("\"resign_performed\": true")
        );
        assert!(
            verify_output_manifest(dir.path()).unwrap().is_ok(),
            "root abl.elf must be ignored by the matching resign policy"
        );

        write_file(
            &dir.path().join(RESIGN_EXCLUDED_ROOT_ARTIFACT),
            b"changed-root-abl",
        );
        assert!(verify_output_manifest(dir.path()).unwrap().is_ok());

        write_file(
            &dir.path()
                .join("nested")
                .join(RESIGN_EXCLUDED_ROOT_ARTIFACT),
            b"NESTED-ABL",
        );
        let nested_tamper = verify_output_manifest(dir.path()).unwrap();
        assert!(nested_tamper.issues.iter().any(|issue| matches!(
            issue,
            ManifestIssue::DigestMismatch { path, .. } if path == "nested/abl.elf"
        )));
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
    fn supplied_manifest_bytes_are_verified_without_a_second_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("blob.bin"), b"blob");
        write_output_manifest_for_dir(dir.path(), "2026-07-18T04:30:00Z", true).unwrap();
        let bytes = fs::read(dir.path().join(MANIFEST_FILE_NAME)).unwrap();
        write_file(
            &dir.path().join(MANIFEST_FILE_NAME),
            b"{ replaced on disk }",
        );

        let report = verify_output_manifest_bytes(dir.path(), &bytes).unwrap();
        assert!(report.is_ok(), "{:?}", report.issues);
        assert!(!verify_output_manifest(dir.path()).unwrap().is_ok());
    }

    #[test]
    fn verification_issues_are_path_sorted_with_parallel_digest_checks() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("a-unexpected.bin"), b"unexpected");
        write_file(&dir.path().join("b-size.bin"), b"wrong-size");
        write_file(&dir.path().join("c-digest.bin"), b"bad!");

        let manifest = OutputManifest {
            schema: MANIFEST_SCHEMA.to_string(),
            version: MANIFEST_VERSION,
            generator: "test".to_string(),
            generated_at: "2026-07-18T04:45:00Z".to_string(),
            semantic_verification: true,
            resign_performed: false,
            input_artifacts: Vec::new(),
            artifacts: vec![
                ManifestArtifact {
                    path: "b-size.bin".to_string(),
                    size: 1,
                    sha256: known_digest(b"x"),
                },
                ManifestArtifact {
                    path: "c-digest.bin".to_string(),
                    size: 4,
                    sha256: known_digest(b"good"),
                },
                ManifestArtifact {
                    path: "d-missing.bin".to_string(),
                    size: 7,
                    sha256: known_digest(b"missing"),
                },
            ],
        };
        let bytes = serialize_manifest(&manifest).unwrap();

        let first = verify_output_manifest_bytes(dir.path(), &bytes).unwrap();
        let second = verify_output_manifest_bytes(dir.path(), &bytes).unwrap();
        assert_eq!(first.issues, second.issues);
        assert!(matches!(
            &first.issues[0],
            ManifestIssue::Unexpected { path } if path == "a-unexpected.bin"
        ));
        assert!(matches!(
            &first.issues[1],
            ManifestIssue::SizeMismatch { path, .. } if path == "b-size.bin"
        ));
        assert!(matches!(
            &first.issues[2],
            ManifestIssue::DigestMismatch { path, .. } if path == "c-digest.bin"
        ));
        assert!(matches!(
            &first.issues[3],
            ManifestIssue::Missing { path } if path == "d-missing.bin"
        ));
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
        let err = parse_output_manifest_bytes(duplicate.as_bytes())
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
        let err = parse_output_manifest_bytes(unsorted.as_bytes())
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
        let err = parse_output_manifest_bytes(case_collision.as_bytes())
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
        let err = parse_output_manifest_bytes(drive_path.as_bytes())
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
        let ok = parse_output_manifest_bytes(sorted_ok.as_bytes()).unwrap();
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
