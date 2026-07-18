use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::integrity::{
    MANIFEST_FILE_NAME, ManifestIssue, ManifestVerificationReport, verify_output_manifest,
};

use crate::events::{EventSink, MessageLevel, ProgressEvent, StageKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VerificationFailureKind {
    Input,
    Integrity,
    Avb,
    Xml,
    Super,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationFailure {
    pub kind: VerificationFailureKind,
    pub path: Option<PathBuf>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuperLayoutSummary {
    pub chunk_count: usize,
    pub dynamic_partition_count: usize,
    pub dynamic_partition_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationReport {
    pub input: PathBuf,
    pub artifact_integrity: Option<ManifestVerificationReport>,
    pub image_file_count: usize,
    pub avb_image_count: usize,
    pub rawprogram_xml_count: usize,
    pub super_chunk_count: usize,
    pub super_layout: Option<SuperLayoutSummary>,
    pub failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

pub fn verify_input(input: &Path) -> anyhow::Result<VerificationReport> {
    let mut report = verify_input_semantic(input)?;
    attach_output_manifest_verification(input, &mut report);
    Ok(report)
}

fn verify_input_semantic(input: &Path) -> anyhow::Result<VerificationReport> {
    let mut report = VerificationReport {
        input: input.to_path_buf(),
        artifact_integrity: None,
        image_file_count: count_image_files(input)?,
        avb_image_count: 0,
        rawprogram_xml_count: count_rawprogram_xml_files(input)?,
        super_chunk_count: count_super_chunks(input)?,
        super_layout: None,
        failures: Vec::new(),
    };

    if report.image_file_count == 0
        && report.rawprogram_xml_count == 0
        && report.super_chunk_count == 0
    {
        report.failures.push(VerificationFailure {
            kind: VerificationFailureKind::Input,
            path: Some(input.to_path_buf()),
            message: "No .img files or rawprogram XML files found.".to_string(),
        });
        return Ok(report);
    }

    // Parse XML / super layout before AVB checks so packed dynamic partitions
    // (Hash/Hashtree targets living inside super, not as sibling .img files)
    // can be recognized when full descriptor verification is impossible.
    let mut packed_dynamic_partitions: Option<HashSet<String>> = None;

    if report.super_chunk_count > 0 && report.rawprogram_xml_count == 0 {
        report.failures.push(VerificationFailure {
            kind: VerificationFailureKind::Xml,
            path: Some(input.to_path_buf()),
            message: "Found split super chunks but no rawprogram XML files.".to_string(),
        });
    }

    if report.rawprogram_xml_count > 0 {
        match dynobox_xml::XmlCatalog::from_dir(input) {
            Ok(catalog) => {
                if let Some(super_group) = catalog.group_for("super") {
                    let records: Vec<_> = super_group.records().into_iter().cloned().collect();
                    match dynobox_super::parse_super_layout(&records, input) {
                        Ok(layout) => {
                            let mut dynamic_partition_names = layout.dynamic_partition_names();
                            dynamic_partition_names.sort();
                            let packed: HashSet<String> = dynamic_partition_names
                                .iter()
                                .map(|name| name.to_ascii_lowercase())
                                .collect();
                            report.super_layout = Some(SuperLayoutSummary {
                                chunk_count: layout.chunks.len(),
                                dynamic_partition_count: dynamic_partition_names.len(),
                                dynamic_partition_names,
                            });
                            packed_dynamic_partitions = Some(packed);
                        }
                        Err(err) => report.failures.push(VerificationFailure {
                            kind: VerificationFailureKind::Super,
                            path: Some(input.to_path_buf()),
                            message: err.to_string(),
                        }),
                    }
                }
            }
            Err(err) => report.failures.push(VerificationFailure {
                kind: VerificationFailureKind::Xml,
                path: Some(input.to_path_buf()),
                message: err.to_string(),
            }),
        }
    }

    if report.image_file_count > 0 {
        let scan_entries = avbtool_rs::info::scan_input(input)?;
        let split_fragment_names = collect_split_fragment_filenames(input);
        report.avb_image_count = scan_entries
            .iter()
            .filter(|entry| matches!(entry.result, avbtool_rs::info::ScanResult::Avb(_)))
            .count();
        for entry in &scan_entries {
            let name = entry
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
                .unwrap_or_default();
            // Split super / partition fragments are not standalone AVB
            // images; skip both scan errors and verify attempts for them.
            if split_fragment_names.contains(&name) {
                continue;
            }
            match &entry.result {
                avbtool_rs::info::ScanResult::Error(message) => {
                    report.failures.push(VerificationFailure {
                        kind: VerificationFailureKind::Avb,
                        path: Some(entry.path.clone()),
                        message: message.clone(),
                    });
                }
                avbtool_rs::info::ScanResult::Avb(info) => {
                    // Cryptographic / hashtree verification.
                    //
                    // avbtool-rs rejects chain-partition descriptors unless
                    // either `expected_chain_partitions` matches them or
                    // `follow_chain_partitions` is enabled. Populate
                    // expected entries from this image's own descriptors so
                    // a lone vbmeta does not hard-fail when a chained
                    // sibling is absent (common for packed super layouts
                    // where `vendor`/`system` live inside super, not as
                    // sibling `.img` files).
                    //
                    // Always leave `follow_chain_partitions` disabled: this
                    // directory scan already visits every sibling AVB image
                    // independently, and real vbmeta graphs can recurse or
                    // cycle when follow is enabled (stack overflow on dense
                    // OEM trees). expected_chain_partitions alone satisfies
                    // the chain-descriptor check without recursion.
                    //
                    // Hash/Hashtree descriptor targets that are packed inside
                    // a successfully validated super layout cannot be opened
                    // as sibling files. In that case fall back to
                    // signature-only verification of the vbmeta blob itself
                    // (authentication digest + RSA). Arbitrary missing
                    // targets still hard-fail.
                    let missing_targets = missing_descriptor_targets(&entry.path, info);
                    if missing_targets.is_empty() {
                        let expected_chain_partitions = expected_chain_partitions_from_info(info);
                        let options = avbtool_rs::verify::VerifyImageOptions {
                            key_blob: None,
                            expected_chain_partitions,
                            follow_chain_partitions: false,
                            accept_zeroed_hashtree: false,
                        };
                        if let Err(err) = verify_image_stack_safe(&entry.path, &options) {
                            report.failures.push(VerificationFailure {
                                kind: VerificationFailureKind::Avb,
                                path: Some(entry.path.clone()),
                                message: err.to_string(),
                            });
                        }
                    } else if descriptor_targets_are_packed(
                        &missing_targets,
                        packed_dynamic_partitions.as_ref(),
                    ) {
                        if let Err(err) = verify_vbmeta_signature_only(&entry.path, info) {
                            report.failures.push(VerificationFailure {
                                kind: VerificationFailureKind::Avb,
                                path: Some(entry.path.clone()),
                                message: err.to_string(),
                            });
                        }
                    } else {
                        report.failures.push(VerificationFailure {
                            kind: VerificationFailureKind::Avb,
                            path: Some(entry.path.clone()),
                            message: format!(
                                "Missing AVB descriptor target(s) not present in validated super layout: {}",
                                missing_targets.join(", ")
                            ),
                        });
                    }
                }
                avbtool_rs::info::ScanResult::None => {
                    // Non-AVB image (raw payload, super chunk already
                    // filtered above, etc.) — keep useful non-AVB
                    // handling by leaving it alone.
                }
            }
        }
    }

    Ok(report)
}

fn attach_output_manifest_verification(input: &Path, report: &mut VerificationReport) {
    if !input.is_dir() || !input.join(MANIFEST_FILE_NAME).is_file() {
        return;
    }

    let integrity =
        verify_output_manifest(input).unwrap_or_else(|error| ManifestVerificationReport {
            manifest_path: input.join(MANIFEST_FILE_NAME),
            issues: vec![ManifestIssue::Malformed {
                message: error.to_string(),
            }],
        });

    for issue in &integrity.issues {
        let (path, message) = manifest_issue_details(input, issue);
        report.failures.push(VerificationFailure {
            kind: VerificationFailureKind::Integrity,
            path: Some(path),
            message,
        });
    }
    report.artifact_integrity = Some(integrity);
}

fn manifest_issue_details(input: &Path, issue: &ManifestIssue) -> (PathBuf, String) {
    match issue {
        ManifestIssue::Missing { path } => (
            input.join(path),
            format!("artifact listed in manifest is missing: {path}"),
        ),
        ManifestIssue::Unexpected { path } => (
            input.join(path),
            format!("unexpected artifact is not listed in manifest: {path}"),
        ),
        ManifestIssue::SizeMismatch {
            path,
            expected,
            actual,
        } => (
            input.join(path),
            format!("artifact size mismatch: expected {expected} bytes, found {actual} bytes"),
        ),
        ManifestIssue::DigestMismatch {
            path,
            expected,
            actual,
        } => (
            input.join(path),
            format!("artifact SHA-256 mismatch: expected {expected}, found {actual}"),
        ),
        ManifestIssue::Malformed { message } => (input.join(MANIFEST_FILE_NAME), message.clone()),
    }
}

pub fn render_verification_report(report: &VerificationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Verification target:    {}", report.input.display());
    let _ = writeln!(
        out,
        "Status:                 {}",
        if report.is_clean() { "OK" } else { "FAILED" }
    );
    match &report.artifact_integrity {
        Some(integrity) if integrity.is_ok() => {
            out.push_str("Artifact integrity:     OK (SHA-256 manifest)\n");
        }
        Some(integrity) => {
            let _ = writeln!(
                out,
                "Artifact integrity:     FAILED ({} issue(s))",
                integrity.issues.len()
            );
        }
        None => out.push_str("Artifact integrity:     NOT CHECKED (no manifest)\n"),
    }
    let _ = writeln!(out, "Image files scanned:    {}", report.image_file_count);
    let _ = writeln!(out, "AVB images detected:    {}", report.avb_image_count);
    let _ = writeln!(
        out,
        "rawprogram XML files:   {}",
        report.rawprogram_xml_count
    );
    let _ = writeln!(out, "Super chunk files:      {}", report.super_chunk_count);

    if let Some(summary) = &report.super_layout {
        let _ = writeln!(
            out,
            "Super layout:           {} chunk(s), {} dynamic partition(s)",
            summary.chunk_count, summary.dynamic_partition_count
        );
        if !summary.dynamic_partition_names.is_empty() {
            let _ = writeln!(
                out,
                "Dynamic partitions:     {}",
                summary.dynamic_partition_names.join(", ")
            );
        }
    } else {
        out.push_str("Super layout:           skipped\n");
    }

    if report.failures.is_empty() {
        out.push_str("Failures:               none\n");
    } else {
        let _ = writeln!(out, "Failures:               {}", report.failures.len());
        for failure in &report.failures {
            let path = failure
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string());
            let _ = writeln!(
                out,
                "- [{:?}] {} :: {}",
                failure.kind, path, failure.message
            );
        }
    }

    out
}

pub fn emit_verification_messages<S>(report: &VerificationReport, events: &mut S)
where
    S: EventSink + ?Sized,
{
    if report.image_file_count > 0
        && report
            .failures
            .iter()
            .all(|f| f.kind != VerificationFailureKind::Avb)
    {
        events.emit(ProgressEvent::Message {
            level: MessageLevel::Info,
            text: format!(
                "Verify AVB scan clean: {} image(s), {} AVB image(s).",
                report.image_file_count, report.avb_image_count
            ),
        });
    }

    if let Some(summary) = &report.super_layout {
        events.emit(ProgressEvent::Message {
            level: MessageLevel::Info,
            text: format!(
                "Verify super layout clean: {} chunk(s), {} dynamic partition(s).",
                summary.chunk_count, summary.dynamic_partition_count
            ),
        });
    }
}

pub fn ensure_verification_clean(report: &VerificationReport) -> anyhow::Result<()> {
    if report.is_clean() {
        return Ok(());
    }

    anyhow::bail!(
        "Verification failed:\n{}",
        report
            .failures
            .iter()
            .map(|failure| {
                let path = failure
                    .path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string());
                format!("[{:?}] {} :: {}", failure.kind, path, failure.message)
            })
            .collect::<Vec<_>>()
            .join("\n")
    );
}

pub fn run_verify_stage<S>(input: &Path, events: &mut S) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    events.emit(ProgressEvent::StageStarted {
        stage: StageKind::Verify,
    });

    let report = verify_input_semantic(input)?;
    emit_verification_messages(&report, events);
    ensure_verification_clean(&report)?;

    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Verify,
    });
    Ok(())
}

/// Build `expected_chain_partitions` from the image's own chain
/// descriptors. Feeding these back into `verify_image` satisfies
/// avbtool-rs's chain-descriptor check without requiring sibling files
/// or recursive follow. Values are taken verbatim from the signed
/// descriptor blob, so the match is intentional acceptance of the
/// embedded chain metadata (signature verification still covers the
/// descriptor integrity).
fn expected_chain_partitions_from_info(
    info: &avbtool_rs::info::AvbImageInfo,
) -> Vec<avbtool_rs::verify::ExpectedChainPartition> {
    info.descriptors
        .iter()
        .filter_map(|d| match d {
            avbtool_rs::info::DescriptorInfo::ChainPartition {
                rollback_index_location,
                partition_name,
                public_key,
                ..
            } => Some(avbtool_rs::verify::ExpectedChainPartition {
                partition_name: partition_name.clone(),
                rollback_index_location: *rollback_index_location,
                public_key: public_key.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// Collect Hash/Hashtree descriptor partition names whose resolved sibling
/// target file is absent. Empty `partition_name` means "this image" and is
/// never treated as missing.
fn missing_descriptor_targets(
    image_path: &Path,
    info: &avbtool_rs::info::AvbImageInfo,
) -> Vec<String> {
    let image_dir = image_path.parent().unwrap_or_else(|| Path::new("."));
    let image_ext = image_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();

    let mut missing = Vec::new();
    for descriptor in &info.descriptors {
        let partition_name = match descriptor {
            avbtool_rs::info::DescriptorInfo::Hash { partition_name, .. }
            | avbtool_rs::info::DescriptorInfo::Hashtree { partition_name, .. } => {
                partition_name.as_str()
            }
            _ => continue,
        };
        if partition_name.is_empty() {
            continue;
        }
        let target = image_dir.join(format!("{partition_name}{image_ext}"));
        if !target.is_file() {
            missing.push(partition_name.to_string());
        }
    }
    missing.sort();
    missing.dedup();
    missing
}

/// True when every missing Hash/Hashtree target is a dynamic partition from a
/// successfully validated super layout (packed inside split-super chunks).
fn descriptor_targets_are_packed(
    missing_targets: &[String],
    packed_dynamic_partitions: Option<&HashSet<String>>,
) -> bool {
    let Some(packed) = packed_dynamic_partitions else {
        return false;
    };
    if missing_targets.is_empty() {
        return true;
    }
    missing_targets.iter().all(|name| {
        let lower = name.to_ascii_lowercase();
        if packed.contains(&lower) {
            return true;
        }
        let base = dynobox_core::ab_slot::base_name(name).to_ascii_lowercase();
        packed.contains(&base)
    })
}

/// Cryptographic verification of a vbmeta authentication digest + RSA
/// signature without resolving Hash/Hashtree/chain payload targets.
///
/// Reproduces avbtool-rs's private `verify_vbmeta_signature` using only public
/// helpers. Scan alone is not trusted.
fn verify_vbmeta_signature_only(
    path: &Path,
    info: &avbtool_rs::info::AvbImageInfo,
) -> Result<(), avbtool_rs::error::AvbToolError> {
    let vbmeta_blob = avbtool_rs::image::load_vbmeta_blob(path)?;
    verify_vbmeta_signature_local(info, &vbmeta_blob)
}

fn verify_vbmeta_signature_local(
    info: &avbtool_rs::info::AvbImageInfo,
    vbmeta_blob: &[u8],
) -> Result<(), avbtool_rs::error::AvbToolError> {
    use avbtool_rs::crypto::{AvbPublicKey, compute_hash_for_algorithm, lookup_algorithm_by_type};
    use avbtool_rs::error::AvbToolError;
    use avbtool_rs::parser::AVB_VBMETA_IMAGE_HEADER_SIZE;

    let header = &info.header;
    let algorithm = lookup_algorithm_by_type(header.algorithm_type)?;

    let auth_start = AVB_VBMETA_IMAGE_HEADER_SIZE;
    let auth_block = usize::try_from(header.authentication_data_block_size).map_err(|_| {
        AvbToolError::Validation("authentication_data_block_size exceeds usize".into())
    })?;
    let aux_block = usize::try_from(header.auxiliary_data_block_size)
        .map_err(|_| AvbToolError::Validation("auxiliary_data_block_size exceeds usize".into()))?;
    let auth_end = auth_start
        .checked_add(auth_block)
        .ok_or_else(|| AvbToolError::Validation("VBMeta auth block end overflow".into()))?;
    let aux_end = auth_end
        .checked_add(aux_block)
        .ok_or_else(|| AvbToolError::Validation("VBMeta aux block end overflow".into()))?;
    if aux_end > vbmeta_blob.len() {
        return Err(AvbToolError::Validation("VBMeta blob truncated.".into()));
    }

    let auth_blob = vbmeta_blob
        .get(auth_start..auth_end)
        .ok_or_else(|| AvbToolError::Validation("VBMeta auth slice out of range".into()))?;
    let aux_blob = vbmeta_blob
        .get(auth_end..aux_end)
        .ok_or_else(|| AvbToolError::Validation("VBMeta aux slice out of range".into()))?;

    let hash_offset = usize::try_from(header.hash_offset)
        .map_err(|_| AvbToolError::Validation("hash_offset exceeds usize".into()))?;
    let hash_size = usize::try_from(header.hash_size)
        .map_err(|_| AvbToolError::Validation("hash_size exceeds usize".into()))?;
    let hash_end = hash_offset
        .checked_add(hash_size)
        .ok_or_else(|| AvbToolError::Validation("hash range overflow".into()))?;

    let signature_offset = usize::try_from(header.signature_offset)
        .map_err(|_| AvbToolError::Validation("signature_offset exceeds usize".into()))?;
    let signature_size = usize::try_from(header.signature_size)
        .map_err(|_| AvbToolError::Validation("signature_size exceeds usize".into()))?;
    let signature_end = signature_offset
        .checked_add(signature_size)
        .ok_or_else(|| AvbToolError::Validation("signature range overflow".into()))?;

    let public_key_offset = usize::try_from(header.public_key_offset)
        .map_err(|_| AvbToolError::Validation("public_key_offset exceeds usize".into()))?;
    let public_key_size = usize::try_from(header.public_key_size)
        .map_err(|_| AvbToolError::Validation("public_key_size exceeds usize".into()))?;
    let public_key_end = public_key_offset
        .checked_add(public_key_size)
        .ok_or_else(|| AvbToolError::Validation("public key range overflow".into()))?;

    if hash_end > auth_blob.len()
        || signature_end > auth_blob.len()
        || public_key_end > aux_blob.len()
    {
        return Err(AvbToolError::Validation(
            "VBMeta offsets exceed authentication or auxiliary block.".into(),
        ));
    }

    let embedded_public_key = aux_blob
        .get(public_key_offset..public_key_end)
        .ok_or_else(|| AvbToolError::Validation("VBMeta public key slice out of range".into()))?;

    if algorithm.name == "NONE" {
        return Ok(());
    }

    let header_bytes = vbmeta_blob
        .get(..AVB_VBMETA_IMAGE_HEADER_SIZE)
        .ok_or_else(|| AvbToolError::Validation("VBMeta header slice out of range".into()))?;
    let data_to_verify = [header_bytes, aux_blob].concat();
    let computed_digest = compute_hash_for_algorithm(algorithm, &data_to_verify)?;
    let expected_digest = auth_blob
        .get(hash_offset..hash_end)
        .ok_or_else(|| AvbToolError::Validation("VBMeta hash slice out of range".into()))?;
    if computed_digest.as_slice() != expected_digest {
        return Err(AvbToolError::Validation(
            "VBMeta digest does not match authentication block.".into(),
        ));
    }

    let public_key = AvbPublicKey::decode(embedded_public_key)?;
    let signature = auth_blob
        .get(signature_offset..signature_end)
        .ok_or_else(|| AvbToolError::Validation("VBMeta signature slice out of range".into()))?;
    if !public_key.verify(algorithm, signature, &data_to_verify)? {
        return Err(AvbToolError::Validation(format!(
            "Signature check failed for {}",
            algorithm.name
        )));
    }

    Ok(())
}

/// Run [`avbtool_rs::verify::verify_image`] on a dedicated thread with a
/// larger stack.
///
/// avbtool-rs currently allocates a 1 MiB buffer on the stack inside
/// `hash_reader_prefix`. Windows PE images default to a 1 MiB main-thread
/// stack reserve, so a direct call overflows immediately on real AVB
/// images (even with `follow_chain_partitions` disabled). Spawning a
/// worker thread with an explicit stack size keeps verification usable
/// without patching avbtool-rs.
fn verify_image_stack_safe(
    path: &Path,
    options: &avbtool_rs::verify::VerifyImageOptions,
) -> Result<avbtool_rs::verify::VerifyImageReport, avbtool_rs::error::AvbToolError> {
    const VERIFY_STACK_SIZE: usize = 16 * 1024 * 1024;

    let path = path.to_path_buf();
    let options = options.clone();
    let worker = std::thread::Builder::new()
        .name("avb-verify".to_string())
        .stack_size(VERIFY_STACK_SIZE)
        .spawn(move || avbtool_rs::verify::verify_image(&path, &options))
        .map_err(|err| {
            avbtool_rs::error::AvbToolError::Tool(format!(
                "Failed to spawn AVB verify worker thread: {err}"
            ))
        })?;

    match worker.join() {
        Ok(result) => result,
        Err(_) => Err(avbtool_rs::error::AvbToolError::Tool(
            "AVB verify worker thread panicked".to_string(),
        )),
    }
}

pub fn collect_split_fragment_filenames(input: &Path) -> std::collections::HashSet<String> {
    use std::collections::{HashMap, HashSet};
    let mut result = HashSet::new();
    let catalog = match dynobox_xml::XmlCatalog::from_dir(input) {
        Ok(c) => c,
        Err(_) => return result,
    };
    let mut by_label: HashMap<String, Vec<&dynobox_xml::PartitionRecord>> = HashMap::new();
    for record in catalog.records() {
        if record.filename.trim().is_empty() {
            continue;
        }
        by_label
            .entry(record.label.to_lowercase())
            .or_default()
            .push(record);
    }
    for (_label, records) in by_label {
        let mut unique_files: HashSet<String> = HashSet::new();
        for r in &records {
            unique_files.insert(r.filename.clone());
        }
        if unique_files.len() >= 2 {
            for name in unique_files {
                result.insert(name);
            }
            if let Some(first) = records.first() {
                let base = first.base_label();
                if !base.is_empty() {
                    result.insert(format!("{}.img", base));
                    result.insert(format!("{}.bin", base));
                    result.insert(format!("{}_a.img", base));
                    result.insert(format!("{}_b.img", base));
                }
            }
        }
    }
    result
}

fn count_image_files(input: &Path) -> anyhow::Result<usize> {
    if input.is_file() {
        return Ok(1);
    }
    if !input.exists() {
        anyhow::bail!("Missing input path: {}", input.display());
    }

    let mut count = 0usize;
    count_matching_files(input, &mut count, |path| {
        path.extension().and_then(|ext| ext.to_str()) == Some("img")
    })?;
    Ok(count)
}

fn count_rawprogram_xml_files(input: &Path) -> anyhow::Result<usize> {
    count_top_level_files(input, |name| {
        name.starts_with("rawprogram") && name.ends_with(".xml")
    })
}

fn count_super_chunks(input: &Path) -> anyhow::Result<usize> {
    count_top_level_files(input, |name| {
        name.starts_with("super_") && name.ends_with(".img")
    })
}

fn count_top_level_files<F>(input: &Path, predicate: F) -> anyhow::Result<usize>
where
    F: Fn(&str) -> bool,
{
    if input.is_file() {
        let name = input
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        return Ok(usize::from(predicate(name)));
    }
    if !input.exists() {
        anyhow::bail!("Missing input path: {}", input.display());
    }

    let mut count = 0usize;
    for entry in std::fs::read_dir(input)? {
        let entry = entry?;
        if !entry.path().is_file() {
            continue;
        }

        let name = entry
            .file_name()
            .to_str()
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();
        if predicate(&name) {
            count += 1;
        }
    }
    Ok(count)
}

fn count_matching_files<F>(dir: &Path, count: &mut usize, predicate: F) -> anyhow::Result<()>
where
    F: Fn(&Path) -> bool + Copy,
{
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            count_matching_files(&path, count, predicate)?;
        } else if path.is_file() && predicate(&path) {
            *count += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    use tempfile::{NamedTempFile, tempdir};

    use crate::integrity::write_output_manifest_for_dir;

    use super::{
        VerificationFailureKind, expected_chain_partitions_from_info, render_verification_report,
        verify_input,
    };

    #[test]
    fn verify_image_only_directory_is_clean() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("dummy.img"), b"not-avb").unwrap();

        let report = verify_input(temp.path()).unwrap();

        assert!(report.is_clean());
        assert_eq!(report.image_file_count, 1);
        assert_eq!(report.avb_image_count, 0);
        assert!(report.super_layout.is_none());
        assert!(report.artifact_integrity.is_none());
        assert!(render_verification_report(&report).contains("NOT CHECKED (no manifest)"));
    }

    #[test]
    fn verify_manifest_accepts_clean_output_and_detects_tampering() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("dummy.img");
        fs::write(&image, b"not-avb").unwrap();
        write_output_manifest_for_dir(temp.path(), "2026-07-18T00:00:00Z", true).unwrap();

        let clean = verify_input(temp.path()).unwrap();
        assert!(clean.is_clean(), "{:?}", clean.failures);
        assert!(
            clean
                .artifact_integrity
                .as_ref()
                .is_some_and(|integrity| integrity.is_ok())
        );
        assert!(render_verification_report(&clean).contains("Artifact integrity:     OK"));

        fs::write(&image, b"tampered").unwrap();
        let tampered = verify_input(temp.path()).unwrap();
        assert!(!tampered.is_clean());
        assert!(
            tampered
                .failures
                .iter()
                .any(|failure| failure.kind == VerificationFailureKind::Integrity)
        );
        assert!(render_verification_report(&tampered).contains("Artifact integrity:     FAILED"));
    }

    #[test]
    fn verify_empty_directory_reports_input_failure() {
        let temp = tempdir().unwrap();

        let report = verify_input(temp.path()).unwrap();

        assert!(!report.is_clean());
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].kind, VerificationFailureKind::Input);
        assert!(render_verification_report(&report).contains("FAILED"));
    }

    #[test]
    fn verify_super_chunks_without_xml_reports_failure() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("super_1.img"), b"chunk").unwrap();

        let report = verify_input(temp.path()).unwrap();

        assert!(!report.is_clean());
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.kind == VerificationFailureKind::Xml)
        );
    }

    #[test]
    fn verify_xml_with_missing_super_chunk_reports_failure() {
        let temp = tempdir().unwrap();
        let xml_path = temp.path().join("rawprogram_unsparse0.xml");
        let mut xml = NamedTempFile::new_in(temp.path()).unwrap();
        writeln!(
            xml,
            r#"<?xml version="1.0" ?><data><program label="super" filename="super_1.img" /></data>"#
        )
        .unwrap();
        fs::rename(xml.path(), &xml_path).unwrap();

        let report = verify_input(temp.path()).unwrap();

        assert!(!report.is_clean());
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.kind == VerificationFailureKind::Super)
        );
    }

    fn sample_hash_footer_args() -> avbtool_rs::footer::HashFooterArgs {
        // Use dynamic_partition_size so the fixture does not depend on a
        // fixed partition size that can fall short of
        // MAX_VBMETA_SIZE + MAX_FOOTER_SIZE overhead.
        avbtool_rs::footer::HashFooterArgs {
            partition_size: None,
            dynamic_partition_size: true,
            partition_name: "boot".to_string(),
            hash_algorithm: "sha256".to_string(),
            salt: Some(vec![0x11, 0x22]),
            chain_partitions: Vec::new(),
            algorithm_name: "SHA256_RSA2048".to_string(),
            key_spec: Some("testkey_rsa2048".to_string()),
            public_key_metadata: None,
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            properties: Vec::new(),
            kernel_cmdlines: Vec::new(),
            include_descriptors_from_images: Vec::new(),
            release_string: None,
            append_to_release_string: None,
            output_vbmeta_image: None,
            do_not_append_vbmeta_image: false,
            use_persistent_digest: false,
            do_not_use_ab: false,
        }
    }

    fn sample_vbmeta_args(
        extra_descriptors: Vec<avbtool_rs::info::DescriptorInfo>,
        chain_partitions: Vec<avbtool_rs::builder::ChainPartitionSpec>,
    ) -> avbtool_rs::builder::VbmetaImageArgs {
        avbtool_rs::builder::VbmetaImageArgs {
            algorithm_name: "SHA256_RSA2048".to_string(),
            key_spec: Some("testkey_rsa2048".to_string()),
            public_key_metadata: None,
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            properties: Vec::new(),
            kernel_cmdlines: Vec::new(),
            extra_descriptors,
            include_descriptors_from_images: Vec::new(),
            chain_partitions,
            release_string: None,
            append_to_release_string: None,
            padding_size: 0,
        }
    }

    fn dummy_hash_descriptor(partition_name: &str) -> avbtool_rs::info::DescriptorInfo {
        avbtool_rs::info::DescriptorInfo::Hash {
            image_size: 4096,
            hash_algorithm: "sha256".to_string(),
            partition_name: partition_name.to_string(),
            salt: vec![0x11, 0x22, 0x33],
            digest: vec![0x44; 32],
            flags: 0,
        }
    }

    /// Write a parseable single-chunk super image + rawprogram XML that
    /// advertises the given dynamic partition base names.
    fn write_packed_super_fixture(dir: &Path, dynamic_names: &[&str]) {
        use dynobox_super::{
            LP_TARGET_TYPE_LINEAR, SuperBlockDevice, SuperExtent, SuperGeometry, SuperGroup,
            SuperLayout, SuperPartition, serialize_metadata,
        };

        let partitions = dynamic_names
            .iter()
            .map(|name| SuperPartition {
                name: format!("{name}_a"),
                attributes: 0,
                group_name: "default".to_string(),
                extents: vec![SuperExtent {
                    num_sectors: 8,
                    target_type: LP_TARGET_TYPE_LINEAR,
                    target_data: 2048,
                    target_source: 0,
                }],
            })
            .collect();

        let layout = SuperLayout {
            geometry: SuperGeometry {
                metadata_max_size: 65_536,
                metadata_slot_count: 1,
                logical_block_size: 4096,
            },
            header_flags: 0,
            block_devices: vec![SuperBlockDevice {
                name: "super".to_string(),
                size: 1024 * 1024,
            }],
            groups: vec![SuperGroup {
                name: "default".to_string(),
                maximum_size: 0,
            }],
            partitions,
            chunks: Vec::new(),
        };

        let mut image = serialize_metadata(&layout).expect("serialize super metadata");
        let pad = (512 - (image.len() % 512)) % 512;
        image.resize(image.len() + pad, 0);
        let num_sectors = image.len() as u64 / 512;
        fs::write(dir.join("super_1.img"), &image).unwrap();

        let xml = format!(
            r#"<?xml version="1.0" ?><data><program label="super" filename="super_1.img" start_sector="0" num_partition_sectors="{num_sectors}" SECTOR_SIZE_IN_BYTES="512" /></data>"#
        );
        fs::write(dir.join("rawprogram_unsparse0.xml"), xml).unwrap();
    }

    #[test]
    fn verify_avb_image_detects_corruption() {
        use avbtool_rs::footer::add_hash_footer;

        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        fs::write(&image, vec![0x41; 4096]).unwrap();
        add_hash_footer(&image, &sample_hash_footer_args()).unwrap();

        // Intact image must verify cleanly.
        let report = verify_input(temp.path()).unwrap();
        assert!(
            report.is_clean(),
            "intact AVB image should pass: {:?}",
            report.failures
        );
        assert_eq!(report.avb_image_count, 1);

        // Corrupt the payload; cryptographic verify must fail.
        let mut bytes = fs::read(&image).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&image, &bytes).unwrap();

        let report = verify_input(temp.path()).unwrap();
        assert!(!report.is_clean());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.kind == VerificationFailureKind::Avb),
            "corrupted AVB image must produce an Avb failure: {:?}",
            report.failures
        );
    }

    #[test]
    fn expected_chain_partitions_empty_when_no_chain_descriptors() {
        // Build a real hash-footer image (no chain descriptors) and confirm
        // expected_chain_partitions stays empty for standalone images.
        use avbtool_rs::footer::add_hash_footer;
        use avbtool_rs::info::scan_input;

        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        fs::write(&image, vec![0x41; 4096]).unwrap();
        add_hash_footer(&image, &sample_hash_footer_args()).unwrap();

        let entries = scan_input(temp.path()).unwrap();
        let info = match &entries[0].result {
            avbtool_rs::info::ScanResult::Avb(info) => info,
            other => panic!("expected Avb scan result, got {other:?}"),
        };
        assert!(expected_chain_partitions_from_info(info).is_empty());
    }

    #[test]
    fn verify_chain_vbmeta_without_siblings_is_clean() {
        // Regression: a vbmeta that chains to a sibling image must not
        // hard-fail when the sibling is absent. avbtool-rs requires either
        // expected_chain_partitions or follow_chain_partitions; we accept
        // the embedded chain descriptors without recursive follow so packed
        // layouts (chain targets living inside super) still verify clean.
        // follow_chain_partitions is always false — directory scan verifies
        // siblings independently and real graphs can recurse/cycle.
        use avbtool_rs::builder::{ChainPartitionSpec, make_vbmeta_image};
        use avbtool_rs::info::scan_input;

        let temp = tempdir().unwrap();
        let vbmeta = temp.path().join("vbmeta.img");

        // Build a signed vbmeta with one chain descriptor targeting a missing
        // `boot.img`. The chain public key is opaque descriptor payload; the
        // top-level vbmeta is signed with testkey_rsa2048.
        let chain_key = vec![0xAB; 32];
        let args = sample_vbmeta_args(
            Vec::new(),
            vec![ChainPartitionSpec {
                partition_name: "boot".to_string(),
                rollback_index_location: 1,
                public_key: chain_key.clone(),
                flags: 0,
            }],
        );
        make_vbmeta_image(&vbmeta, &args).unwrap();

        let entries = scan_input(temp.path()).unwrap();
        let info = match &entries
            .iter()
            .find(|e| e.path.file_name().and_then(|n| n.to_str()) == Some("vbmeta.img"))
            .expect("vbmeta scan entry")
            .result
        {
            avbtool_rs::info::ScanResult::Avb(info) => info,
            other => panic!("expected Avb scan result, got {other:?}"),
        };
        let expected = expected_chain_partitions_from_info(info);
        assert_eq!(expected.len(), 1);
        assert_eq!(expected[0].partition_name, "boot");
        assert_eq!(expected[0].public_key, chain_key);

        // Full directory verify must be clean despite the missing sibling.
        let report = verify_input(temp.path()).unwrap();
        assert!(
            report.is_clean(),
            "chained vbmeta without siblings must verify clean: {:?}",
            report.failures
        );
    }

    #[test]
    fn verify_allows_missing_hash_targets_packed_in_super() {
        // vbmeta.img carries a Hash descriptor for `system`, but system.img is
        // not a sibling file — it lives inside the validated super layout.
        // Signature-only verification of vbmeta must be accepted.
        use avbtool_rs::builder::make_vbmeta_image;

        let temp = tempdir().unwrap();
        write_packed_super_fixture(temp.path(), &["system"]);

        let vbmeta = temp.path().join("vbmeta.img");
        let args = sample_vbmeta_args(vec![dummy_hash_descriptor("system")], Vec::new());
        make_vbmeta_image(&vbmeta, &args).unwrap();

        let report = verify_input(temp.path()).unwrap();
        assert!(
            report.is_clean(),
            "packed super Hash target must allow signature-only verify: {:?}",
            report.failures
        );
        assert!(report.super_layout.is_some());
        assert_eq!(report.avb_image_count, 1);
    }

    #[test]
    fn verify_rejects_arbitrary_missing_hash_targets() {
        // Same Hash-for-system vbmeta, but the super layout only packs
        // `vendor`. Missing `system.img` is not justified by super → fail.
        use avbtool_rs::builder::make_vbmeta_image;

        let temp = tempdir().unwrap();
        write_packed_super_fixture(temp.path(), &["vendor"]);

        let vbmeta = temp.path().join("vbmeta.img");
        let args = sample_vbmeta_args(vec![dummy_hash_descriptor("system")], Vec::new());
        make_vbmeta_image(&vbmeta, &args).unwrap();

        let report = verify_input(temp.path()).unwrap();
        assert!(!report.is_clean());
        assert!(
            report.failures.iter().any(|f| {
                f.kind == VerificationFailureKind::Avb
                    && f.message.contains("Missing AVB descriptor target")
                    && f.message.contains("system")
            }),
            "arbitrary missing Hash target must be rejected: {:?}",
            report.failures
        );
    }

    #[test]
    fn verify_detects_vbmeta_signature_corruption() {
        // Signature-only path must still cryptographically reject a tampered
        // vbmeta; scan success alone is not enough.
        use avbtool_rs::builder::make_vbmeta_image;

        let temp = tempdir().unwrap();
        write_packed_super_fixture(temp.path(), &["system"]);

        let vbmeta = temp.path().join("vbmeta.img");
        let args = sample_vbmeta_args(vec![dummy_hash_descriptor("system")], Vec::new());
        make_vbmeta_image(&vbmeta, &args).unwrap();

        // Flip a byte in the authentication/signature region (past the 256-byte
        // header) so the signed blob no longer verifies.
        let mut bytes = fs::read(&vbmeta).unwrap();
        assert!(
            bytes.len() > 300,
            "vbmeta fixture too small: {}",
            bytes.len()
        );
        let idx = bytes.len() - 16;
        bytes[idx] ^= 0xff;
        fs::write(&vbmeta, &bytes).unwrap();

        let report = verify_input(temp.path()).unwrap();
        assert!(!report.is_clean());
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.kind == VerificationFailureKind::Avb),
            "corrupted vbmeta signature must produce an Avb failure: {:?}",
            report.failures
        );
    }
}
