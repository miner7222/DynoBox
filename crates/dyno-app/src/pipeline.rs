use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use tempfile::TempDir;

use crate::boot_spl::{
    BOOT_SPL_PROPERTY, BootSplPatchOutcome, patch_security_patch, validate_spl_format,
};
use crate::events::{CommandKind, EventSink, MessageLevel, ProgressEvent, ProgressUnit, StageKind};
use crate::fix_locale::{FixLocaleOutcome, apply_fix_locale};
use crate::vendor_spl::{
    VENDOR_SPL_PROPERTY, VendorSplOutcome, apply_vendor_spl,
    validate_spl_format as validate_vendor_spl_format,
};
use crate::verify::run_verify_stage;

const PARTITION_IMAGE_EXTENSION_FALLBACK: [&str; 5] = ["img", "bin", "elf", "melf", "mbn"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResignConfig {
    pub key: String,
    pub algorithm: Option<String>,
    pub force: bool,
    /// Unix timestamp to write into rollback_index of boot.img and vbmeta_system.img.
    /// When set, only those two images are processed; others are left untouched.
    /// The new value must be less than or equal to each image's current rollback_index.
    pub rollback_index: Option<u64>,
    /// New `com.android.build.boot.security_patch` value (YYYY-MM-DD) for boot.img.
    /// The image is re-signed regardless; the property is only rewritten when
    /// the requested date is strictly newer than the existing one.
    pub boot_spl: Option<String>,
    /// New `com.android.build.vendor.security_patch` value (YYYY-MM-DD) for
    /// vendor.img. Triggers an offline byte patch on `/vendor/build.prop`,
    /// dm-verity hash tree regeneration, and a propagation pass into vbmeta.img
    /// so the resign loop signs over the new bytes. Skipped (warn-only) when
    /// the requested date is not strictly newer than the existing value.
    pub vendor_spl: Option<String>,
    /// When set, defang Lenovo's `ZuiAntiCrossSell` locale gate inside
    /// `system.img/system/framework/framework.jar` by flipping the first
    /// conditional branch in `Configuration.setLocales` into an
    /// unconditional `goto cond_2`. Triggers a dm-verity hash tree
    /// regeneration on system.img and propagates the new root digest into
    /// vbmeta_system.img so the resign loop signs over the patched bytes.
    /// No-ops when the AntiCrossSell anchor is absent (already patched or
    /// different ROM build).
    pub fix_locale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackRequest {
    pub input: PathBuf,
    pub output: PathBuf,
    pub resign: Option<ResignConfig>,
    pub repack: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyRequest {
    pub input: PathBuf,
    pub output: PathBuf,
    pub ota_zips: Vec<PathBuf>,
    pub force_unpack: bool,
    pub resign: Option<ResignConfig>,
    pub repack: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResignRequest {
    pub input: PathBuf,
    pub output: PathBuf,
    pub config: ResignConfig,
    pub repack: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepackRequest {
    pub input: PathBuf,
    pub output: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct TransferStats {
    hard_links: usize,
    copies: usize,
}

impl TransferStats {
    fn record(&mut self, method: FileMaterializationMethod) {
        match method {
            FileMaterializationMethod::HardLink => self.hard_links += 1,
            FileMaterializationMethod::Copy => self.copies += 1,
        }
    }

    fn merge(&mut self, other: TransferStats) {
        self.hard_links += other.hard_links;
        self.copies += other.copies;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct PrepareRepackStats {
    xml_count: usize,
    super_count: usize,
    image_count: usize,
    transfers: TransferStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileMaterializationMethod {
    HardLink,
    Copy,
}

pub fn default_output_name_for_unpack(resign: bool, repack: bool) -> &'static str {
    if repack {
        "output_repack"
    } else if resign {
        "output_resign"
    } else {
        "output_unpack"
    }
}

pub fn default_output_name_for_apply(resign: bool, repack: bool) -> &'static str {
    if repack {
        "output_repack"
    } else if resign {
        "output_resign"
    } else {
        "output_apply"
    }
}

pub fn default_output_name_for_resign(repack: bool) -> &'static str {
    if repack {
        "output_repack"
    } else {
        "output_resign"
    }
}

pub fn run_unpack<S>(request: &UnpackRequest, events: &mut S) -> anyhow::Result<()>
where
    S: EventSink,
{
    run_unpack_with_ops(request, events, &RealPipelineOps)
}

pub fn run_apply<S>(request: &ApplyRequest, events: &mut S) -> anyhow::Result<()>
where
    S: EventSink,
{
    run_apply_with_ops(request, events, &RealPipelineOps)
}

pub fn run_resign<S>(request: &ResignRequest, events: &mut S) -> anyhow::Result<()>
where
    S: EventSink,
{
    run_resign_with_ops(request, events, &RealPipelineOps)
}

pub fn run_repack<S>(request: &RepackRequest, events: &mut S) -> anyhow::Result<()>
where
    S: EventSink,
{
    run_repack_with_ops(request, events, &RealPipelineOps)
}

trait PipelineOps {
    fn unpack_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()>;

    fn prepare_image_workspace_from_unpack(
        &self,
        base_input_dir: &Path,
        unpacked_image_dir: &Path,
        stage_dir: &Path,
    ) -> anyhow::Result<TransferStats>;

    fn apply_preflight(
        &self,
        ota_zips: &[PathBuf],
        scratch_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()>;

    fn apply_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        ota_zips: &[PathBuf],
        force_unpack: bool,
        scratch_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()>;

    fn resign_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        config: &ResignConfig,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()>;

    fn repack_pipeline(
        &self,
        base_input_dir: &Path,
        image_dir: &Path,
        final_output_dir: &Path,
        scratch_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()>;

    fn repack_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()>;

    fn verify_stage(&self, output_dir: &Path, events: &mut dyn EventSink) -> anyhow::Result<()>;
}

struct RealPipelineOps;

impl PipelineOps for RealPipelineOps {
    fn unpack_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        run_unpack_stage(input, out_dir, events)
    }

    fn prepare_image_workspace_from_unpack(
        &self,
        base_input_dir: &Path,
        unpacked_image_dir: &Path,
        stage_dir: &Path,
    ) -> anyhow::Result<TransferStats> {
        prepare_image_workspace_from_unpack(base_input_dir, unpacked_image_dir, stage_dir)
    }

    fn apply_preflight(
        &self,
        ota_zips: &[PathBuf],
        scratch_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        run_apply_preflight(ota_zips, scratch_dir, events)
    }

    fn apply_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        ota_zips: &[PathBuf],
        force_unpack: bool,
        scratch_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        run_apply_stage(input, out_dir, ota_zips, force_unpack, scratch_dir, events)
    }

    fn resign_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        config: &ResignConfig,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        run_resign_stage(input, out_dir, config, events)
    }

    fn repack_pipeline(
        &self,
        base_input_dir: &Path,
        image_dir: &Path,
        final_output_dir: &Path,
        scratch_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        run_repack_pipeline(
            base_input_dir,
            image_dir,
            final_output_dir,
            scratch_dir,
            events,
        )
    }

    fn repack_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        run_repack_stage(input, out_dir, events)
    }

    fn verify_stage(&self, output_dir: &Path, events: &mut dyn EventSink) -> anyhow::Result<()> {
        run_verify_stage(output_dir, events)
    }
}

fn run_unpack_with_ops<S, O>(request: &UnpackRequest, events: &mut S, ops: &O) -> anyhow::Result<()>
where
    S: EventSink,
    O: PipelineOps,
{
    events.emit(ProgressEvent::CommandStarted {
        command: CommandKind::Unpack,
        input: request.input.clone(),
        output: request.output.clone(),
    });

    let temp_root = create_pipeline_temp_root(&request.output)?;
    let decrypted_input = auto_decrypt_xml_if_needed(&request.input, temp_root.path(), events)?;
    let input_dir = decrypted_input.as_deref().unwrap_or(&request.input);

    if request.resign.is_none() && !request.repack {
        ops.unpack_stage(input_dir, &request.output, events)?;
        return ops.verify_stage(&request.output, events);
    }

    let unpack_stage_dir = temp_root.path().join("unpack_stage");
    ops.unpack_stage(input_dir, &unpack_stage_dir, events)?;

    let image_stage_dir = temp_root.path().join("image_stage");
    let prep_stats =
        ops.prepare_image_workspace_from_unpack(input_dir, &unpack_stage_dir, &image_stage_dir)?;
    message(
        events,
        MessageLevel::Info,
        format!(
            "Prepared unpack workspace using {} hardlink(s) and {} copy/copies.",
            prep_stats.hard_links, prep_stats.copies
        ),
    );

    let mut current_image_dir = image_stage_dir;

    if let Some(config) = &request.resign {
        let resign_out_dir = if request.repack {
            temp_root.path().join("resign_stage")
        } else {
            request.output.clone()
        };
        ops.resign_stage(&current_image_dir, &resign_out_dir, config, events)?;
        current_image_dir = resign_out_dir;
    }

    if request.repack {
        ops.repack_pipeline(
            &request.input,
            &current_image_dir,
            &request.output,
            temp_root.path(),
            events,
        )?;
    }

    if request.complete {
        complete_output_from_input(&request.input, &request.output, events)?;
    }

    ops.verify_stage(&request.output, events)?;

    Ok(())
}

fn run_apply_with_ops<S, O>(request: &ApplyRequest, events: &mut S, ops: &O) -> anyhow::Result<()>
where
    S: EventSink,
    O: PipelineOps,
{
    events.emit(ProgressEvent::CommandStarted {
        command: CommandKind::Apply,
        input: request.input.clone(),
        output: request.output.clone(),
    });

    let temp_root = create_pipeline_temp_root(&request.output)?;
    ops.apply_preflight(&request.ota_zips, temp_root.path(), events)?;
    let decrypted_input = auto_decrypt_xml_if_needed(&request.input, temp_root.path(), events)?;
    let input_dir = decrypted_input.as_deref().unwrap_or(&request.input);
    let pipeline_mode = request.resign.is_some() || request.repack;
    let apply_out_dir = if pipeline_mode {
        temp_root.path().join("apply_stage")
    } else {
        request.output.clone()
    };

    ops.apply_stage(
        input_dir,
        &apply_out_dir,
        &request.ota_zips,
        request.force_unpack,
        temp_root.path(),
        events,
    )?;

    let mut current_image_dir = apply_out_dir;

    if let Some(config) = &request.resign {
        let resign_out_dir = if request.repack {
            temp_root.path().join("resign_stage")
        } else {
            request.output.clone()
        };
        ops.resign_stage(&current_image_dir, &resign_out_dir, config, events)?;
        current_image_dir = resign_out_dir;
    }

    if request.repack {
        ops.repack_pipeline(
            input_dir,
            &current_image_dir,
            &request.output,
            temp_root.path(),
            events,
        )?;
    }

    if request.complete {
        complete_output_from_input(input_dir, &request.output, events)?;
    }

    ops.verify_stage(&request.output, events)?;

    Ok(())
}

fn run_resign_with_ops<S, O>(request: &ResignRequest, events: &mut S, ops: &O) -> anyhow::Result<()>
where
    S: EventSink,
    O: PipelineOps,
{
    events.emit(ProgressEvent::CommandStarted {
        command: CommandKind::Resign,
        input: request.input.clone(),
        output: request.output.clone(),
    });

    let temp_root = create_pipeline_temp_root(&request.output)?;
    let decrypted_input = auto_decrypt_xml_if_needed(&request.input, temp_root.path(), events)?;
    let decrypted_dir = decrypted_input.as_deref().unwrap_or(&request.input);
    let effective_input = auto_unpack_if_needed(decrypted_dir, temp_root.path(), events, ops)?;
    let input_dir = effective_input.as_deref().unwrap_or(decrypted_dir);

    if !request.repack {
        ops.resign_stage(input_dir, &request.output, &request.config, events)?;
        return ops.verify_stage(&request.output, events);
    }

    let resign_stage_dir = temp_root.path().join("resign_stage");
    ops.resign_stage(input_dir, &resign_stage_dir, &request.config, events)?;
    ops.repack_pipeline(
        decrypted_dir,
        &resign_stage_dir,
        &request.output,
        temp_root.path(),
        events,
    )?;
    ops.verify_stage(&request.output, events)?;
    Ok(())
}

fn run_repack_with_ops<S, O>(request: &RepackRequest, events: &mut S, ops: &O) -> anyhow::Result<()>
where
    S: EventSink,
    O: PipelineOps,
{
    events.emit(ProgressEvent::CommandStarted {
        command: CommandKind::Repack,
        input: request.input.clone(),
        output: request.output.clone(),
    });

    let temp_root = create_pipeline_temp_root(&request.output)?;
    let decrypted_input = auto_decrypt_xml_if_needed(&request.input, temp_root.path(), events)?;
    let decrypted_dir = decrypted_input.as_deref().unwrap_or(&request.input);
    let effective_input = auto_unpack_if_needed(decrypted_dir, temp_root.path(), events, ops)?;
    let input_dir = effective_input.as_deref().unwrap_or(decrypted_dir);

    ops.repack_stage(input_dir, &request.output, events)?;
    ops.verify_stage(&request.output, events)
}

/// Check if the input directory has super chunks but no standalone dynamic
/// partition files. If so, auto-unpack super into a temp workspace and merge
/// with original input files. Returns Some(workspace_path) if unpack was
/// performed, None if not needed.
fn auto_unpack_if_needed<S, O>(
    input: &Path,
    scratch_dir: &Path,
    events: &mut S,
    ops: &O,
) -> anyhow::Result<Option<PathBuf>>
where
    S: EventSink,
    O: PipelineOps + ?Sized,
{
    let catalog = match dynobox_xml::XmlCatalog::from_dir(input) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let super_group = match catalog.group_by_base_label(true).remove("super") {
        Some(g) => g,
        None => return Ok(None),
    };
    let records: Vec<_> = super_group.records().into_iter().cloned().collect();
    let layout = match dynobox_super::parse_super_layout(&records, input) {
        Ok(l) => l,
        Err(_) => return Ok(None),
    };
    let dynamic_names = layout.dynamic_partition_names();
    if dynamic_names.is_empty() {
        return Ok(None);
    }

    // Check if any standalone dynamic partition file already exists.
    let has_standalone = dynamic_names.iter().any(|name| {
        let img = input.join(format!("{name}.img"));
        img.exists()
    });
    if has_standalone {
        return Ok(None);
    }

    // No standalone dynamic partition files found — auto-unpack.
    let unpack_dir = scratch_dir.join("_auto_unpack_super");
    ops.unpack_stage(input, &unpack_dir, events)?;

    // Merge: copy all non-super original files + unpacked partitions into workspace.
    let workspace_dir = scratch_dir.join("auto_unpack_workspace");
    recreate_dir(&workspace_dir)?;
    copy_all_top_level_files(input, &workspace_dir)?;
    copy_all_top_level_files(&unpack_dir, &workspace_dir)?;

    message(
        events,
        MessageLevel::Info,
        format!(
            "Auto-unpacked {} dynamic partitions from super.",
            dynamic_names.len()
        ),
    );

    Ok(Some(workspace_dir))
}

/// If the input directory has no `rawprogram*.xml` but has `*.x` encrypted
/// files, decrypt each `.x` → `.xml` into a scratch workspace (with all other
/// input files hardlinked) and return the workspace path. Returns None when
/// no decryption is needed.
fn auto_decrypt_xml_if_needed<S>(
    input: &Path,
    scratch_dir: &Path,
    events: &mut S,
) -> anyhow::Result<Option<PathBuf>>
where
    S: EventSink,
{
    let mut has_xml = false;
    let mut x_files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(input)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("rawprogram") && lower.ends_with(".xml") {
            has_xml = true;
        }
        if lower.ends_with(".x") {
            x_files.push(path);
        }
    }

    if has_xml || x_files.is_empty() {
        return Ok(None);
    }

    let workspace_dir = scratch_dir.join("_auto_decrypt_xml");
    recreate_dir(&workspace_dir)?;

    for entry in std::fs::read_dir(input)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path.file_name().unwrap();
        let lower = file_name.to_string_lossy().to_ascii_lowercase();
        if lower.ends_with(".x") {
            continue;
        }
        materialize_file_with_fallback(&path, &workspace_dir.join(file_name))?;
    }

    let mut decrypted = 0usize;
    for x_path in &x_files {
        let stem = x_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if stem.is_empty() {
            continue;
        }
        let out = workspace_dir.join(format!("{stem}.xml"));
        dynobox_xml::decrypt_file(x_path, &out)
            .with_context(|| format!("failed to decrypt {}", x_path.display()))?;
        decrypted += 1;
    }

    message(
        events,
        MessageLevel::Info,
        format!("Auto-decrypted {decrypted} .x file(s) to .xml."),
    );

    Ok(Some(workspace_dir))
}

fn run_apply_preflight<S>(
    ota_zips: &[PathBuf],
    scratch_dir: &Path,
    events: &mut S,
) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    events.emit(ProgressEvent::StageStarted {
        stage: StageKind::Preflight,
    });

    let mut aggregate_counts = BTreeMap::new();
    let mut total_partitions = 0usize;
    let mut total_operations = 0usize;
    let mut unsupported_messages = Vec::new();

    for (index, zip_path) in ota_zips.iter().enumerate() {
        events.emit(ProgressEvent::ItemStarted {
            stage: StageKind::Preflight,
            current: index + 1,
            total: ota_zips.len(),
            item: zip_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string(),
        });

        let preflight_dir = scratch_dir.join(format!("preflight_ota_{index}"));
        let payload_path = dynobox_payload::extract_payload(zip_path, &preflight_dir)?;
        let report = dynobox_payload::inspect_payload(&payload_path)?;

        total_partitions += report.partition_count;
        total_operations += report.total_operations;
        for (name, count) in report.operation_counts {
            *aggregate_counts.entry(name).or_insert(0usize) += count;
        }

        if report.unsupported_operations.is_empty() {
            message(
                events,
                MessageLevel::Info,
                format!(
                    "Preflight OK for {}: {} partitions, {} operations.",
                    zip_path.display(),
                    report.partition_count,
                    report.total_operations
                ),
            );
        } else {
            for unsupported in report.unsupported_operations {
                unsupported_messages.push(format!(
                    "{} :: {} op #{} {} :: {}",
                    zip_path.display(),
                    unsupported.partition_name,
                    unsupported.operation_index,
                    unsupported.detail_name,
                    unsupported.reason
                ));
            }
        }
    }

    let op_summary = if aggregate_counts.is_empty() {
        "none".to_string()
    } else {
        aggregate_counts
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    message(
        events,
        MessageLevel::Info,
        format!(
            "Preflight summary: {} OTA zip(s), {} partitions, {} operations [{}].",
            ota_zips.len(),
            total_partitions,
            total_operations,
            op_summary
        ),
    );

    if !unsupported_messages.is_empty() {
        for detail in unsupported_messages.iter().take(10) {
            message(events, MessageLevel::Warning, detail.clone());
        }
        if unsupported_messages.len() > 10 {
            message(
                events,
                MessageLevel::Warning,
                format!(
                    "{} more unsupported operation entries omitted.",
                    unsupported_messages.len() - 10
                ),
            );
        }
        anyhow::bail!("Apply preflight failed. Unsupported OTA operations found before patching.");
    }

    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Preflight,
    });
    Ok(())
}

fn run_unpack_stage<S>(input: &Path, out_dir: &Path, events: &mut S) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    events.emit(ProgressEvent::StageStarted {
        stage: StageKind::Unpack,
    });

    let _workspace = dynobox_core::workspace::Workspace::new(input, out_dir)?;
    recreate_dir(out_dir)?;

    let catalog = dynobox_xml::XmlCatalog::from_dir(input)?;
    let super_group = catalog
        .group_by_base_label(true)
        .remove("super")
        .ok_or_else(|| anyhow::anyhow!("Super partition group not found in XML catalog."))?;

    let records: Vec<_> = super_group.records().into_iter().cloned().collect();
    let layout = dynobox_super::parse_super_layout(&records, input)?;
    message(
        events,
        MessageLevel::Info,
        format!(
            "Found super layout with {} partitions.",
            layout.partitions.len()
        ),
    );

    let extracted = dynobox_super::extract_partition_images(&layout, out_dir, None)?;
    message(
        events,
        MessageLevel::Info,
        format!("Unpack complete. Extracted {} images.", extracted.len()),
    );

    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Unpack,
    });
    Ok(())
}

/// Run [`dynobox_payload::apply_partition_payload_with_progress`] and forward
/// its per-op progress through `events` as throttled
/// [`ProgressEvent::ItemProgress`] events. Emits when the integer percentage
/// changes (~100 events per partition) plus a final `done == total` event,
/// so the CLI bar advances smoothly without spamming tracing output.
fn apply_payload_with_event_progress<S>(
    events: &mut S,
    stage: StageKind,
    item: &str,
    payload_path: &Path,
    old_image: &Path,
    new_image: &Path,
    block_size: u32,
) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    let mut last_emitted_pct: i32 = -1;
    let mut last_emitted_done: u64 = u64::MAX;
    let mut callback = |done: u64, total: u64| {
        let pct = if total == 0 {
            100
        } else {
            ((done * 100) / total) as i32
        };
        let final_tick = total > 0 && done == total;
        if pct == last_emitted_pct && !final_tick && last_emitted_done != u64::MAX {
            return;
        }
        last_emitted_pct = pct;
        last_emitted_done = done;
        events.emit(ProgressEvent::ItemProgress {
            stage,
            item: item.to_string(),
            done,
            total,
            unit: ProgressUnit::Bytes,
        });
    };
    dynobox_payload::apply_partition_payload_with_progress(
        payload_path,
        item,
        old_image,
        new_image,
        block_size,
        Some(&mut callback),
    )?;
    Ok(())
}

fn run_apply_stage<S>(
    input: &Path,
    out_dir: &Path,
    ota_zips: &[PathBuf],
    force_unpack: bool,
    scratch_dir: &Path,
    events: &mut S,
) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    events.emit(ProgressEvent::StageStarted {
        stage: StageKind::Apply,
    });

    recreate_dir(out_dir)?;

    let catalog = dynobox_xml::XmlCatalog::from_dir(input)?;
    let super_group = catalog.group_by_base_label(true).remove("super");
    let super_layout = if let Some(group) = super_group {
        let records: Vec<_> = group.records().into_iter().cloned().collect();
        Some(dynobox_super::parse_super_layout(&records, input)?)
    } else {
        None
    };

    let auto_unpack_dir = scratch_dir.join("_auto_unpack_super");
    let mut auto_unpack_announced = false;
    let mut auto_unpack_stage_open = false;

    if let Some(layout) = &super_layout {
        if force_unpack {
            events.emit(ProgressEvent::StageStarted {
                stage: StageKind::AutoUnpack,
            });
            message(
                events,
                MessageLevel::Info,
                format!(
                    "`--unpack` requested. Pre-unpacking {} dynamic partitions from super into {}.",
                    layout.dynamic_partition_names().len(),
                    auto_unpack_dir.display()
                ),
            );
            let extracted =
                dynobox_super::extract_partition_images(layout, &auto_unpack_dir, None)?;
            message(
                events,
                MessageLevel::Info,
                format!("Pre-unpack complete. Extracted {} images.", extracted.len()),
            );
            events.emit(ProgressEvent::StageCompleted {
                stage: StageKind::AutoUnpack,
            });
            auto_unpack_announced = true;
        } else {
            let missing_dynamic_count = layout
                .dynamic_partition_names()
                .into_iter()
                .filter(|name| {
                    let candidates = resolve_partition_source_candidates(&catalog, name);
                    find_existing_filename_in_dir(input, &candidates).is_none()
                })
                .count();
            if missing_dynamic_count > 0 {
                message(
                    events,
                    MessageLevel::Info,
                    format!(
                        "Input is missing {} standalone dynamic partition images. Apply will auto-unpack required partitions from super.",
                        missing_dynamic_count
                    ),
                );
            }
        }
    } else if force_unpack {
        message(
            events,
            MessageLevel::Warning,
            "`--unpack` requested, but no super layout found. Continuing without forced unpack."
                .to_string(),
        );
    }

    for (zip_index, zip_path) in ota_zips.iter().enumerate() {
        message(
            events,
            MessageLevel::Info,
            format!(
                "Processing OTA zip {}/{}: {}",
                zip_index + 1,
                ota_zips.len(),
                zip_path.display()
            ),
        );

        let working_dir = scratch_dir.join(format!("working_ota_{}", zip_index));
        let payload_path = dynobox_payload::extract_payload(zip_path, &working_dir)?;
        let metadata = dynobox_payload::parse_payload_metadata(&payload_path)?;

        message(
            events,
            MessageLevel::Info,
            format!(
                "Payload version: {}, blocks: {}, partitions: {}",
                metadata.version,
                metadata.block_size,
                metadata.partitions.len()
            ),
        );

        for (partition_index, p_info) in metadata.partitions.iter().enumerate() {
            events.emit(ProgressEvent::ItemStarted {
                stage: StageKind::Apply,
                current: partition_index + 1,
                total: metadata.partitions.len(),
                item: p_info.name.clone(),
            });

            let split_fragments = find_split_source_fragments(&catalog, &p_info.name);
            if !split_fragments.is_empty() && p_info.old_size > 0 {
                let all_present = split_fragments.iter().all(|f| {
                    input.join(&f.filename).exists() || out_dir.join(&f.filename).exists()
                });
                if all_present {
                    message(
                        events,
                        MessageLevel::Info,
                        format!(
                            "Reconstructing split source for {} from {} fragment(s).",
                            p_info.name,
                            split_fragments.len()
                        ),
                    );
                    let src_base = if split_fragments
                        .iter()
                        .all(|f| out_dir.join(&f.filename).exists())
                    {
                        out_dir
                    } else {
                        input
                    };
                    let recon_src = working_dir.join(format!("{}_split_src.img", p_info.name));
                    reconstruct_split_source(
                        &split_fragments,
                        src_base,
                        p_info.old_size,
                        &recon_src,
                    )?;
                    let temp_new = working_dir.join(format!("{}_new.img", p_info.name));
                    apply_payload_with_event_progress(
                        events,
                        StageKind::Apply,
                        &p_info.name,
                        &payload_path,
                        &recon_src,
                        &temp_new,
                        metadata.block_size,
                    )?;
                    split_new_image_to_fragments(&temp_new, &split_fragments, out_dir)?;
                    let _ = std::fs::remove_file(&recon_src);
                    let _ = std::fs::remove_file(&temp_new);
                    continue;
                }
            }

            let candidate_filenames = resolve_partition_source_candidates(&catalog, &p_info.name);
            let mut filename = find_existing_filename_in_dir(out_dir, &candidate_filenames)
                .or_else(|| find_existing_filename_in_dir(input, &candidate_filenames))
                .unwrap_or_else(|| {
                    candidate_filenames
                        .first()
                        .cloned()
                        .unwrap_or_else(|| format!("{}.img", p_info.name))
                });
            let mut out_path = out_dir.join(&filename);
            let mut src_path = out_dir.join(&filename);
            let cached_dynamic_path = super_layout.as_ref().and_then(|layout| {
                layout
                    .find_partition(&p_info.name)
                    .map(|_| auto_unpack_dir.join(format!("{}.img", p_info.name)))
            });

            if !src_path.exists() && force_unpack {
                if let Some(cached_path) = &cached_dynamic_path {
                    if cached_path.exists() {
                        filename = format!("{}.img", p_info.name);
                        out_path = out_dir.join(&filename);
                        src_path = cached_path.clone();
                    }
                }
            }
            if !src_path.exists() {
                src_path = input.join(&filename);
            }

            if !src_path.exists() {
                if let Some(layout) = &super_layout {
                    if layout.find_partition(&p_info.name).is_some() {
                        let cached_path = cached_dynamic_path.unwrap();
                        if !auto_unpack_announced {
                            events.emit(ProgressEvent::StageStarted {
                                stage: StageKind::AutoUnpack,
                            });
                            auto_unpack_stage_open = true;
                            message(
                                events,
                                MessageLevel::Info,
                                format!(
                                    "Packed super input detected. Auto-unpacking dynamic partitions from super into {}.",
                                    auto_unpack_dir.display()
                                ),
                            );
                            auto_unpack_announced = true;
                        }
                        if !cached_path.exists() {
                            events.emit(ProgressEvent::ItemStarted {
                                stage: StageKind::AutoUnpack,
                                current: 1,
                                total: 1,
                                item: p_info.name.clone(),
                            });
                            let extracted = dynobox_super::extract_partition_images(
                                layout,
                                &auto_unpack_dir,
                                Some(std::slice::from_ref(&p_info.name)),
                            )?;
                            if let Some(path) = extracted.get(&p_info.name) {
                                filename = format!("{}.img", p_info.name);
                                out_path = out_dir.join(&filename);
                                src_path = path.clone();
                            }
                        } else {
                            filename = format!("{}.img", p_info.name);
                            out_path = out_dir.join(&filename);
                            src_path = cached_path;
                        }
                    }
                }
            }

            if !src_path.exists() && p_info.old_size > 0 {
                anyhow::bail!("Source image for {} ({}) not found.", p_info.name, filename);
            }

            let temp_new = working_dir.join(format!("{}_new.img", p_info.name));
            apply_payload_with_event_progress(
                events,
                StageKind::Apply,
                &p_info.name,
                &payload_path,
                &src_path,
                &temp_new,
                metadata.block_size,
            )?;
            move_file_across_drives(&temp_new, &out_path)?;
            trim_trailing_zero_padding(&out_path, input.join(&filename).as_path())?;
        }
    }

    if auto_unpack_stage_open {
        events.emit(ProgressEvent::StageCompleted {
            stage: StageKind::AutoUnpack,
        });
    }

    copy_rawprogram_xml_files(input, out_dir)?;

    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Apply,
    });
    Ok(())
}

fn copy_rawprogram_xml_files(src_dir: &Path, dst_dir: &Path) -> anyhow::Result<()> {
    if let Ok(entries) = std::fs::read_dir(src_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let lower = name.to_lowercase();
            if lower.starts_with("rawprogram") && lower.ends_with(".xml") {
                let dst = dst_dir.join(&name);
                if !dst.exists() {
                    std::fs::copy(&path, &dst)
                        .with_context(|| format!("copying {} to output", name))?;
                }
            }
        }
    }
    Ok(())
}

fn resolve_partition_source_candidates(
    catalog: &dynobox_xml::XmlCatalog,
    partition_name: &str,
) -> Vec<String> {
    if let Some(record) = catalog.find_partition(partition_name) {
        let filename = record.filename.trim();
        if !filename.is_empty() {
            return vec![filename.to_string()];
        }
    }

    PARTITION_IMAGE_EXTENSION_FALLBACK
        .iter()
        .map(|ext| format!("{partition_name}.{ext}"))
        .collect()
}

fn find_existing_filename_in_dir(dir: &Path, candidates: &[String]) -> Option<String> {
    candidates.iter().find_map(|name| {
        if dir.join(name).exists() {
            Some(name.clone())
        } else {
            None
        }
    })
}

#[derive(Debug, Clone)]
struct SplitFragment {
    filename: String,
    offset: u64,
    size: u64,
}

fn find_split_source_fragments(
    catalog: &dynobox_xml::XmlCatalog,
    partition_name: &str,
) -> Vec<SplitFragment> {
    let normalized = partition_name.to_lowercase();
    let matches: Vec<_> = catalog
        .records()
        .iter()
        .filter(|r| r.base_label().to_lowercase() == normalized)
        .collect();
    if matches.is_empty() {
        return Vec::new();
    }
    let slot_a: Vec<_> = matches
        .iter()
        .copied()
        .filter(|r| r.slot_suffix() == Some("a"))
        .collect();
    let slot_none: Vec<_> = matches
        .iter()
        .copied()
        .filter(|r| r.slot_suffix().is_none())
        .collect();
    let selected = if !slot_a.is_empty() {
        slot_a
    } else if !slot_none.is_empty() {
        slot_none
    } else {
        matches.to_vec()
    };
    let mut parsed: Vec<(String, u64, u64, u64)> = selected
        .into_iter()
        .filter(|r| !r.filename.trim().is_empty())
        .filter_map(|r| {
            let start = r.start_sector.as_ref()?.parse::<u64>().ok()?;
            let num = r.num_sectors.as_ref()?.parse::<u64>().ok()?;
            let sec_size = r
                .sector_size_bytes
                .as_ref()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(4096);
            Some((r.filename.clone(), start, num, sec_size))
        })
        .collect();
    parsed.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    let mut seen = std::collections::HashSet::new();
    parsed.retain(|(name, start, _, _)| seen.insert((name.clone(), *start)));
    if parsed.len() < 2 {
        return Vec::new();
    }
    let base_sector = parsed.first().map(|(_, s, _, _)| *s).unwrap_or(0);
    parsed
        .into_iter()
        .map(|(name, start, num, sec_size)| SplitFragment {
            filename: name,
            offset: (start - base_sector) * sec_size,
            size: num * sec_size,
        })
        .collect()
}

fn reconstruct_split_source(
    fragments: &[SplitFragment],
    input: &Path,
    partition_size: u64,
    dest: &Path,
) -> anyhow::Result<()> {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dest)
        .with_context(|| format!("creating reconstructed source {}", dest.display()))?;
    out.set_len(partition_size)?;

    for frag in fragments {
        let src_path = input.join(&frag.filename);
        if !src_path.exists() {
            continue;
        }
        let frag_end = frag.offset.saturating_add(frag.size);
        if frag_end > partition_size {
            anyhow::bail!(
                "Split fragment {} extends past partition size ({} > {}).",
                frag.filename,
                frag_end,
                partition_size
            );
        }
        let mut src = File::open(&src_path)
            .with_context(|| format!("opening split fragment {}", src_path.display()))?;
        let src_len = src.metadata()?.len();
        let to_copy = std::cmp::min(src_len, frag.size);
        out.seek(SeekFrom::Start(frag.offset))?;
        let mut buf = vec![0u8; 1024 * 1024];
        let mut remaining = to_copy;
        while remaining > 0 {
            let chunk = std::cmp::min(remaining as usize, buf.len());
            src.read_exact(&mut buf[..chunk])?;
            out.write_all(&buf[..chunk])?;
            remaining -= chunk as u64;
        }
    }
    out.flush()?;
    Ok(())
}

fn split_new_image_to_fragments(
    new_image: &Path,
    fragments: &[SplitFragment],
    out_dir: &Path,
) -> anyhow::Result<()> {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};

    std::fs::create_dir_all(out_dir)?;
    let mut src = File::open(new_image)
        .with_context(|| format!("opening new image {}", new_image.display()))?;
    let src_len = src.metadata()?.len();

    for frag in fragments {
        let frag_end = frag.offset.saturating_add(frag.size);
        if frag_end > src_len {
            anyhow::bail!(
                "Split fragment {} range {}..{} exceeds new image size {}.",
                frag.filename,
                frag.offset,
                frag_end,
                src_len
            );
        }
        let dst_path = out_dir.join(&frag.filename);
        let mut dst = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dst_path)
            .with_context(|| format!("creating fragment output {}", dst_path.display()))?;
        src.seek(SeekFrom::Start(frag.offset))?;
        let mut buf = vec![0u8; 1024 * 1024];
        let mut remaining = frag.size;
        while remaining > 0 {
            let chunk = std::cmp::min(remaining as usize, buf.len());
            src.read_exact(&mut buf[..chunk])?;
            dst.write_all(&buf[..chunk])?;
            remaining -= chunk as u64;
        }
        dst.flush()?;
    }
    Ok(())
}

fn trim_trailing_zero_padding(out_path: &Path, input_file: &Path) -> anyhow::Result<()> {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};

    if !input_file.exists() {
        return Ok(());
    }
    let target_len = std::fs::metadata(input_file)?.len();
    let out_meta = std::fs::metadata(out_path)?;
    if target_len >= out_meta.len() {
        return Ok(());
    }
    let mut f = File::open(out_path)?;
    f.seek(SeekFrom::Start(target_len))?;
    let mut remaining = out_meta.len() - target_len;
    let mut buf = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        let chunk = std::cmp::min(remaining as usize, buf.len());
        f.read_exact(&mut buf[..chunk])?;
        if buf[..chunk].iter().any(|b| *b != 0) {
            return Ok(());
        }
        remaining -= chunk as u64;
    }
    drop(f);
    let writer = OpenOptions::new().write(true).open(out_path)?;
    writer.set_len(target_len)?;
    Ok(())
}

const ROLLBACK_TARGETS: &[&str] = &["boot.img", "vbmeta_system.img"];

fn run_resign_stage<S>(
    input: &Path,
    out_dir: &Path,
    config: &ResignConfig,
    events: &mut S,
) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    events.emit(ProgressEvent::StageStarted {
        stage: StageKind::Resign,
    });

    if let Some(spl) = config.boot_spl.as_deref() {
        validate_spl_format(spl)?;
    }
    if let Some(spl) = config.vendor_spl.as_deref() {
        validate_vendor_spl_format(spl)?;
    }

    recreate_dir(out_dir)?;

    // Copy ALL input files to output first (preserves non-.img files like .elf, .mbn)
    copy_all_top_level_files(input, out_dir)?;

    let all_images = collect_resignable_images(input)?;

    // Resolve --rollback. The flag's purpose is to override the AVB
    // rollback_index on boot.img / vbmeta_system.img so an older firmware can
    // be installed on a device whose anti-rollback counter has already been
    // raised; either lowering or raising the value is a legitimate operation.
    // Show the old/new pair in UTC date form and ask the user to confirm
    // before any image is touched. Answering `n` (or running on a
    // non-interactive stdin, e.g. `--progress-format jsonl`) skips the
    // rollback override; the rest of the resign stage continues normally and
    // every resignable image is re-signed without rollback rewrites.
    let mut effective_rollback: Option<u64> = None;
    let mut images: Vec<PathBuf>;
    if let Some(new_ri) = config.rollback_index {
        let filtered: Vec<PathBuf> = all_images
            .iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| ROLLBACK_TARGETS.contains(&n))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if filtered.is_empty() {
            return Err(anyhow::anyhow!(
                "--rollback requested but none of {:?} were found under {}",
                ROLLBACK_TARGETS,
                input.display()
            ));
        }
        let mut current_ris: Vec<(PathBuf, u64)> = Vec::with_capacity(filtered.len());
        for path in &filtered {
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let current_ri = read_rollback_index(path)
                .with_context(|| format!("Failed to read rollback_index from {}", filename))?;
            current_ris.push((path.clone(), current_ri));
        }
        match confirm_rollback_change(&current_ris, new_ri)? {
            RollbackConfirmation::Accepted => {
                effective_rollback = Some(new_ri);
                images = filtered;
            }
            RollbackConfirmation::DeclinedByUser => {
                message(
                    events,
                    MessageLevel::Warning,
                    "rollback index reset declined by user; continuing without rollback override (all resignable images will be re-signed normally).".to_string(),
                );
                effective_rollback = None;
                images = all_images;
            }
            RollbackConfirmation::SkippedNonInteractive => {
                message(
                    events,
                    MessageLevel::Warning,
                    "rollback index reset skipped because stdin is not a terminal (cannot prompt); continuing without rollback override.".to_string(),
                );
                effective_rollback = None;
                images = all_images;
            }
        }
    } else {
        images = all_images;
    }

    let mut vendor_spl_applied: Option<(String, String, String)> = None;
    if let Some(new_spl) = config.vendor_spl.as_deref() {
        require_images_exist("--vendor-spl", out_dir, &["vendor.img", "vbmeta.img"])?;
        ensure_images_local(out_dir, &["vendor.img", "vbmeta.img"])?;
        let vendor_path = out_dir.join("vendor.img");
        let vbmeta_path = out_dir.join("vbmeta.img");
        match apply_vendor_spl(&vendor_path, &vbmeta_path, new_spl)? {
            VendorSplOutcome::Patched {
                old,
                new,
                old_root_digest,
                new_root_digest,
            } => {
                message(
                    events,
                    MessageLevel::Info,
                    format!(
                        "vendor.img {} bumped from {} to {} (build.prop + AVB property + dm-verity root digest {} -> {})",
                        VENDOR_SPL_PROPERTY,
                        old,
                        new,
                        &old_root_digest[..16.min(old_root_digest.len())],
                        &new_root_digest[..16.min(new_root_digest.len())]
                    ),
                );
                vendor_spl_applied = Some((old, new, new_root_digest));
            }
            VendorSplOutcome::SkippedNotNewer { old, requested } => {
                message(
                    events,
                    MessageLevel::Warning,
                    format!(
                        "vendor.img {} not bumped: requested {} is not newer than current {}; re-signing without SPL change",
                        VENDOR_SPL_PROPERTY, requested, old
                    ),
                );
            }
            VendorSplOutcome::NotFound => {
                return Err(anyhow::anyhow!(
                    "vendor.img has no {} property descriptor; cannot apply --vendor-spl",
                    VENDOR_SPL_PROPERTY
                ));
            }
        }
        // The vbmeta.img patch above leaves a stale signature behind; make
        // sure the resign loop will pick it up below even if a future caller
        // tries to combine --vendor-spl with another filter.
        if vendor_spl_applied.is_some() {
            ensure_image_in_resign_list(&mut images, out_dir, "vbmeta.img");
        }
    }

    let mut fix_locale_applied: Option<(String, String)> = None;
    if config.fix_locale {
        require_images_exist(
            "--fix-locale",
            out_dir,
            &["system.img", "vbmeta_system.img"],
        )?;
        ensure_images_local(out_dir, &["system.img", "vbmeta_system.img"])?;
        let system_path = out_dir.join("system.img");
        let vbmeta_system_path = out_dir.join("vbmeta_system.img");
        match apply_fix_locale(&system_path, &vbmeta_system_path)? {
            FixLocaleOutcome::Patched {
                dex_entry,
                if_eqz_offset_in_jar,
                old_root_digest,
                new_root_digest,
            } => {
                message(
                    events,
                    MessageLevel::Info,
                    format!(
                        "system.img AntiCrossSell bypass applied: framework.jar/{} if-eqz at jar offset {:#x} -> goto/16; verity root {} -> {}",
                        dex_entry,
                        if_eqz_offset_in_jar,
                        &old_root_digest[..16.min(old_root_digest.len())],
                        &new_root_digest[..16.min(new_root_digest.len())]
                    ),
                );
                fix_locale_applied = Some((old_root_digest, new_root_digest));
            }
            FixLocaleOutcome::NotApplicable { reason } => {
                message(
                    events,
                    MessageLevel::Warning,
                    format!(
                        "--fix-locale skipped: {}; system.img and vbmeta_system.img left untouched",
                        reason
                    ),
                );
            }
        }
        // The patch above invalidates vbmeta_system.img's existing
        // signature. Make sure it ends up in the resign list even when an
        // unrelated filter (e.g. --rollback) would otherwise have skipped
        // it.
        if fix_locale_applied.is_some() {
            ensure_image_in_resign_list(&mut images, out_dir, "vbmeta_system.img");
        }
    }

    let mut boot_spl_applied: Option<(String, String)> = None;
    if let Some(new_spl) = config.boot_spl.as_deref() {
        let boot_image_in_images = images.iter().any(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == "boot.img")
                .unwrap_or(false)
        });
        if !boot_image_in_images {
            return Err(anyhow::anyhow!(
                "--boot-spl requested but boot.img was not found under {}",
                input.display()
            ));
        }
        ensure_images_local(out_dir, &["boot.img"])?;
        let boot_out_path = out_dir.join("boot.img");
        match patch_security_patch(&boot_out_path, new_spl)? {
            BootSplPatchOutcome::Patched { old, new } => {
                message(
                    events,
                    MessageLevel::Info,
                    format!(
                        "boot.img {} bumped from {} to {}",
                        BOOT_SPL_PROPERTY, old, new
                    ),
                );
                boot_spl_applied = Some((old, new));
            }
            BootSplPatchOutcome::SkippedNotNewer { old, requested } => {
                message(
                    events,
                    MessageLevel::Warning,
                    format!(
                        "boot.img {} not bumped: requested {} is not newer than current {}; re-signing without SPL change",
                        BOOT_SPL_PROPERTY, requested, old
                    ),
                );
            }
            BootSplPatchOutcome::NotFound => {
                return Err(anyhow::anyhow!(
                    "boot.img has no {} property descriptor; cannot apply --boot-spl",
                    BOOT_SPL_PROPERTY
                ));
            }
        }
    }

    let mut resigned_count = 0usize;
    let mut skipped_unsigned_count = 0usize;

    for (index, path) in images.iter().enumerate() {
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();

        events.emit(ProgressEvent::ItemStarted {
            stage: StageKind::Resign,
            current: index + 1,
            total: images.len(),
            item: filename.clone(),
        });

        let out_path = out_dir.join(&filename);
        // boot.img may have already been re-inoded by the SPL patch above; that
        // is a no-op (we copy the already-fresh inode to a new one). All other
        // images go through this guard so the resign write hits a private inode.
        ensure_local_inode(&out_path)?;

        let result = match effective_rollback {
            Some(ri) => avbtool_rs::resign::resign_image_with_options(
                &out_path,
                &config.key,
                config.algorithm.as_deref(),
                config.force,
                Some(ri),
                false,
            ),
            None => avbtool_rs::resign::resign_image(
                &out_path,
                &config.key,
                config.algorithm.as_deref(),
                config.force,
            ),
        };

        match result {
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to resign {}", filename));
            }
            Ok(avbtool_rs::resign::ResignOutcome::Resigned) => {
                resigned_count += 1;
            }
            Ok(avbtool_rs::resign::ResignOutcome::SkippedUnsigned) => {
                skipped_unsigned_count += 1;
            }
        }

        if let Some(expected_ri) = effective_rollback {
            let actual_ri = read_rollback_index(&out_path)
                .with_context(|| format!("Failed to re-read rollback_index from {}", filename))?;
            if actual_ri != expected_ri {
                return Err(anyhow::anyhow!(
                    "Post-resign verification failed for {}: rollback_index is {} but expected {}",
                    filename,
                    actual_ri,
                    expected_ri
                ));
            }
        }

        if let Some((_, ref expected_spl)) = boot_spl_applied {
            if filename == "boot.img" {
                let actual = crate::boot_spl::read_security_patch(&out_path)
                    .with_context(|| format!("Failed to re-read boot SPL from {}", filename))?;
                match actual.as_deref() {
                    Some(value) if value == expected_spl => {}
                    other => {
                        return Err(anyhow::anyhow!(
                            "Post-resign verification failed for {}: {} is {:?} but expected {:?}",
                            filename,
                            BOOT_SPL_PROPERTY,
                            other,
                            expected_spl
                        ));
                    }
                }
            }
        }

        if let Some((_, ref expected_spl, _)) = vendor_spl_applied {
            if filename == "vbmeta.img" {
                let actual = crate::vendor_spl::read_vendor_avb_property(&out_path)
                    .with_context(|| format!("Failed to re-read vendor SPL from {}", filename))?;
                match actual.as_deref() {
                    Some(value) if value == expected_spl => {}
                    other => {
                        return Err(anyhow::anyhow!(
                            "Post-resign verification failed for {}: {} is {:?} but expected {:?}",
                            filename,
                            VENDOR_SPL_PROPERTY,
                            other,
                            expected_spl
                        ));
                    }
                }
            }
        }
    }

    if let Some(ri) = effective_rollback {
        message(
            events,
            MessageLevel::Info,
            format!(
                "rollback index reset to {} ({} images re-signed: {})",
                format_unix_timestamp_utc(ri),
                resigned_count,
                images
                    .iter()
                    .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    } else {
        message(
            events,
            MessageLevel::Info,
            format!(
                "Resign complete. Re-signed {} images, skipped {} unsigned AVB images.",
                resigned_count, skipped_unsigned_count
            ),
        );
    }
    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Resign,
    });
    Ok(())
}

fn read_rollback_index(path: &Path) -> anyhow::Result<u64> {
    let entries = avbtool_rs::info::scan_input(path)?;
    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No AVB scan entry for {}", path.display()))?;
    match entry.result {
        avbtool_rs::info::ScanResult::Avb(info) => Ok(info.header.rollback_index),
        avbtool_rs::info::ScanResult::None => {
            Err(anyhow::anyhow!("{} is not an AVB image", path.display()))
        }
        avbtool_rs::info::ScanResult::Error(msg) => Err(anyhow::anyhow!(
            "Failed to parse AVB metadata in {}: {}",
            path.display(),
            msg
        )),
    }
}

/// Format a Unix timestamp as e.g. `Thu Feb 26 02:40:50 UTC 2026`.
/// Uses Howard Hinnant's civil-from-days algorithm for year/month/day.
fn format_unix_timestamp_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let sod = ts % 86_400;
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;

    // 1970-01-01 was a Thursday (weekday index 4 when Sun=0).
    let wday_idx = ((days + 4).rem_euclid(7)) as usize;
    let weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][wday_idx];

    // civil_from_days: shift epoch from 1970-03-01 so March is month 0.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };

    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(m - 1) as usize];

    format!("{weekday} {month} {d:2} {hour:02}:{minute:02}:{second:02} UTC {year}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollbackConfirmation {
    Accepted,
    DeclinedByUser,
    SkippedNonInteractive,
}

/// Print the current and requested AVB `rollback_index` for each target image
/// in UTC date form and prompt the operator with `[y/N]`. Skips automatically
/// (returns `SkippedNonInteractive`) when stdin is not a terminal — typical
/// for `--progress-format jsonl` and CI invocations — so the rest of the
/// pipeline can keep running without blocking on a prompt nobody can answer.
fn confirm_rollback_change(
    current_ris: &[(PathBuf, u64)],
    new_ri: u64,
) -> anyhow::Result<RollbackConfirmation> {
    use std::io::{IsTerminal, Write};

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "About to rewrite AVB rollback_index:")?;
    for (path, current_ri) in current_ris {
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        writeln!(
            handle,
            "  {filename}: {current_ri} ({}) -> {new_ri} ({})",
            format_unix_timestamp_utc(*current_ri),
            format_unix_timestamp_utc(new_ri),
        )?;
    }
    write!(handle, "Proceed with rollback rewrite? [y/N] ")?;
    handle.flush()?;
    drop(handle);

    if !std::io::stdin().is_terminal() {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        writeln!(
            handle,
            "(stdin is not a terminal — skipping rollback rewrite)"
        )?;
        handle.flush()?;
        return Ok(RollbackConfirmation::SkippedNonInteractive);
    }

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let trimmed = answer.trim().to_ascii_lowercase();
    if trimmed == "y" || trimmed == "yes" {
        Ok(RollbackConfirmation::Accepted)
    } else {
        Ok(RollbackConfirmation::DeclinedByUser)
    }
}

fn run_repack_stage<S>(input: &Path, out_dir: &Path, events: &mut S) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    events.emit(ProgressEvent::StageStarted {
        stage: StageKind::Repack,
    });

    recreate_dir(out_dir)?;
    let catalog = dynobox_xml::XmlCatalog::from_dir(input)?;
    let super_group = catalog
        .group_by_base_label(true)
        .remove("super")
        .ok_or_else(|| anyhow::anyhow!("Super partition group not found in XML catalog."))?;

    let mut xml_paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir(input) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().unwrap().to_string_lossy();
                if name.starts_with("rawprogram") && name.ends_with(".xml") {
                    let out_xml = out_dir.join(name.as_ref());
                    std::fs::copy(&path, &out_xml)?;
                    xml_paths.push(out_xml);
                }
            }
        }
    }

    let records: Vec<_> = super_group.records().into_iter().cloned().collect();
    let source_layout = dynobox_super::parse_super_layout(&records, input)?;
    dynobox_super::repack_super_image(&source_layout, input, out_dir, &xml_paths)?;

    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Repack,
    });
    Ok(())
}

fn run_repack_pipeline<S>(
    base_input_dir: &Path,
    image_dir: &Path,
    final_output_dir: &Path,
    scratch_dir: &Path,
    events: &mut S,
) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    let repack_stage_dir = scratch_dir.join("repack_stage");
    recreate_dir(&repack_stage_dir)?;

    events.emit(ProgressEvent::StageStarted {
        stage: StageKind::PrepareRepack,
    });
    let prep_stats = prepare_repack_stage(base_input_dir, image_dir, &repack_stage_dir)?;
    message(
        events,
        MessageLevel::Info,
        format!(
            "Prepare repack staged {} rawprogram XML(s), {} super chunk(s), {} image(s) using {} hardlink(s) and {} copy/copies.",
            prep_stats.xml_count,
            prep_stats.super_count,
            prep_stats.image_count,
            prep_stats.transfers.hard_links,
            prep_stats.transfers.copies
        ),
    );
    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::PrepareRepack,
    });

    run_repack_stage(&repack_stage_dir, final_output_dir, events)?;
    let final_copy_stats = copy_all_top_level_files(image_dir, final_output_dir)?;
    message(
        events,
        MessageLevel::Info,
        format!(
            "Final output image materialization used {} hardlink(s) and {} copy/copies.",
            final_copy_stats.hard_links, final_copy_stats.copies
        ),
    );

    // Remove standalone dynamic partition images from output — they are now
    // packed inside the super_*.img chunks produced by repack.
    let catalog = dynobox_xml::XmlCatalog::from_dir(&repack_stage_dir)?;
    if let Some(super_group) = catalog.group_by_base_label(true).remove("super") {
        let records: Vec<_> = super_group.records().into_iter().cloned().collect();
        if let Ok(layout) = dynobox_super::parse_super_layout(&records, &repack_stage_dir) {
            let mut removed = 0usize;
            for name in layout.dynamic_partition_names() {
                let img_path = final_output_dir.join(format!("{name}.img"));
                if img_path.exists() {
                    std::fs::remove_file(&img_path)?;
                    removed += 1;
                }
            }
            if removed > 0 {
                message(
                    events,
                    MessageLevel::Info,
                    format!(
                        "Cleaned up {} standalone dynamic partition image(s) from output (now inside super).",
                        removed
                    ),
                );
            }
        }
    }

    Ok(())
}

fn collect_resignable_images(input: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut images = Vec::new();
    let split_fragments = collect_split_fragment_filenames(input);
    if let Ok(entries) = std::fs::read_dir(input) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("img") {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if file_name.starts_with("super_") {
                continue;
            }
            if split_fragments.contains(file_name) {
                continue;
            }

            if let Ok(img_type) = avbtool_rs::parser::detect_avb_image_type(&path) {
                if img_type != avbtool_rs::parser::AvbImageType::None
                    && image_has_parseable_descriptors(&path)
                {
                    images.push(path);
                }
            }
        }
    }
    Ok(images)
}

/// Probe `path` with the AVB info scanner. Some images carry a footer magic
/// but malformed descriptors (notably recovery.img produced by certain Lenovo
/// OTA payloads); the resign code cannot walk those and would abort the whole
/// stage. Skip them at collection time so the stage can still process the
/// rest of the image set.
fn image_has_parseable_descriptors(path: &Path) -> bool {
    match avbtool_rs::info::scan_input(path) {
        Ok(entries) => entries
            .into_iter()
            .next()
            .is_some_and(|entry| matches!(entry.result, avbtool_rs::info::ScanResult::Avb(_))),
        Err(_) => false,
    }
}

use crate::verify::collect_split_fragment_filenames;

fn prepare_repack_stage(
    base_input_dir: &Path,
    image_dir: &Path,
    stage_dir: &Path,
) -> anyhow::Result<PrepareRepackStats> {
    let mut copied_xml = 0usize;
    let mut copied_super = 0usize;
    let mut transfers = TransferStats::default();

    for entry in std::fs::read_dir(base_input_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let copy_to_stage = (name.starts_with("rawprogram") && name.ends_with(".xml"))
            || (name.starts_with("super_") && name.ends_with(".img"));

        if copy_to_stage {
            transfers.record(materialize_file_with_fallback(
                &path,
                &stage_dir.join(name),
            )?);
            if name.ends_with(".xml") {
                copied_xml += 1;
            } else {
                copied_super += 1;
            }
        }
    }

    if copied_xml == 0 {
        anyhow::bail!(
            "No rawprogram XML files found in {}.",
            base_input_dir.display()
        );
    }
    if copied_super == 0 {
        anyhow::bail!(
            "No super chunk images found in {}.",
            base_input_dir.display()
        );
    }

    let image_transfers = copy_top_level_img_files(image_dir, stage_dir)?;
    let image_count = image_transfers.hard_links + image_transfers.copies;
    transfers.merge(image_transfers);
    Ok(PrepareRepackStats {
        xml_count: copied_xml,
        super_count: copied_super,
        image_count,
        transfers,
    })
}

fn prepare_image_workspace_from_unpack(
    base_input_dir: &Path,
    unpacked_image_dir: &Path,
    stage_dir: &Path,
) -> anyhow::Result<TransferStats> {
    recreate_dir(stage_dir)?;
    let mut transfers = copy_avb_top_level_img_files(base_input_dir, stage_dir)?;
    transfers.merge(copy_top_level_img_files(unpacked_image_dir, stage_dir)?);
    Ok(transfers)
}

fn copy_top_level_img_files(src_dir: &Path, dst_dir: &Path) -> anyhow::Result<TransferStats> {
    workspace_prepare_output_dir(dst_dir)?;
    let mut transfers = TransferStats::default();
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("img") {
            let file_name = path.file_name().unwrap();
            let file_name_str = file_name.to_string_lossy();
            if !file_name_str.starts_with("super_") {
                transfers.record(materialize_file_with_fallback(
                    &path,
                    &dst_dir.join(file_name),
                )?);
            }
        }
    }
    Ok(transfers)
}

/// Copy ALL top-level files from src_dir to dst_dir, skipping super_*.img chunks
/// and encrypted .x sources (those are consumed by auto-decrypt).
fn copy_all_top_level_files(src_dir: &Path, dst_dir: &Path) -> anyhow::Result<TransferStats> {
    workspace_prepare_output_dir(dst_dir)?;
    let mut transfers = TransferStats::default();
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path.file_name().unwrap();
        let file_name_str = file_name.to_string_lossy();
        if file_name_str.starts_with("super_") && file_name_str.ends_with(".img") {
            continue;
        }
        if file_name_str.to_ascii_lowercase().ends_with(".x") {
            continue;
        }
        let dst = dst_dir.join(file_name);
        if !dst.exists() {
            transfers.record(materialize_file_with_fallback(&path, &dst)?);
        }
    }
    Ok(transfers)
}

fn copy_avb_top_level_img_files(src_dir: &Path, dst_dir: &Path) -> anyhow::Result<TransferStats> {
    workspace_prepare_output_dir(dst_dir)?;
    let mut transfers = TransferStats::default();
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("img") {
            continue;
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if file_name.starts_with("super_") {
            continue;
        }

        if let Ok(img_type) = avbtool_rs::parser::detect_avb_image_type(&path) {
            if img_type != avbtool_rs::parser::AvbImageType::None {
                transfers.record(materialize_file_with_fallback(
                    &path,
                    &dst_dir.join(file_name),
                )?);
            }
        }
    }
    Ok(transfers)
}

fn workspace_prepare_output_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Replace `path` with a freshly-allocated inode that holds the same content,
/// breaking any hard-link relationship with the source it was materialized
/// from. Required before any in-place modification (resign / boot SPL patch),
/// because [`materialize_file_with_fallback`] hard-links by default and a
/// naive write through an O_RDWR handle would corrupt the original input.
fn ensure_local_inode(path: &Path) -> anyhow::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".relink_tmp");
    let tmp_path = std::path::PathBuf::from(tmp);
    if tmp_path.exists() {
        std::fs::remove_file(&tmp_path)?;
    }
    std::fs::copy(path, &tmp_path)
        .with_context(|| format!("Failed to break hard link on {}", path.display()))?;
    std::fs::remove_file(path)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Verify each `image_name` exists under `out_dir`, otherwise error with
/// a `feature_label`-flavoured message. Used by the `--boot-spl` /
/// `--vendor-spl` / `--fix-locale` blocks of `run_resign_stage` to fail
/// fast when the patcher is asked to operate on partitions that the
/// preceding stages did not produce.
fn require_images_exist(
    feature_label: &str,
    out_dir: &Path,
    image_names: &[&str],
) -> anyhow::Result<()> {
    for name in image_names {
        let p = out_dir.join(name);
        if !p.exists() {
            return Err(anyhow::anyhow!(
                "{} requested but {} was not found under {}",
                feature_label,
                name,
                out_dir.display()
            ));
        }
    }
    Ok(())
}

/// Run [`ensure_local_inode`] on each `out_dir/image_name`. Both
/// `--vendor-spl` and `--fix-locale` need this for two images each;
/// rolling it up into a single call keeps the patch blocks concise.
fn ensure_images_local(out_dir: &Path, image_names: &[&str]) -> anyhow::Result<()> {
    for name in image_names {
        ensure_local_inode(&out_dir.join(name))?;
    }
    Ok(())
}

/// Append `out_dir/image_name` to `images` if it isn't already listed
/// by basename. The `--vendor-spl` and `--fix-locale` blocks both need
/// to make sure the resign loop refreshes a stale signature their
/// in-place AVB descriptor patch leaves behind, even when an unrelated
/// filter (e.g. `--rollback`) would otherwise drop the corresponding
/// vbmeta image from the resign list.
fn ensure_image_in_resign_list(images: &mut Vec<PathBuf>, out_dir: &Path, image_name: &str) {
    let already_listed = images.iter().any(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == image_name)
            .unwrap_or(false)
    });
    if !already_listed {
        images.push(out_dir.join(image_name));
    }
}

fn materialize_file_with_fallback(
    src: &Path,
    dst: &Path,
) -> anyhow::Result<FileMaterializationMethod> {
    if let Some(parent) = dst.parent() {
        workspace_prepare_output_dir(parent)?;
    }

    if src == dst {
        return Ok(FileMaterializationMethod::Copy);
    }

    if dst.exists() {
        std::fs::remove_file(dst)?;
    }

    match std::fs::hard_link(src, dst) {
        Ok(()) => Ok(FileMaterializationMethod::HardLink),
        Err(_) => {
            std::fs::copy(src, dst)?;
            Ok(FileMaterializationMethod::Copy)
        }
    }
}

/// Copy all files from input directory to output that are not already present,
/// so the output mirrors the original firmware structure.
fn complete_output_from_input<S>(input: &Path, output: &Path, events: &mut S) -> anyhow::Result<()>
where
    S: EventSink + ?Sized,
{
    workspace_prepare_output_dir(output)?;
    let mut copied = 0usize;
    for entry in std::fs::read_dir(input)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path.file_name().unwrap();
        if file_name
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with(".x")
        {
            continue;
        }
        let dst = output.join(file_name);
        if !dst.exists() {
            materialize_file_with_fallback(&path, &dst)?;
            copied += 1;
        }
    }
    if copied > 0 {
        message(
            events,
            MessageLevel::Info,
            format!(
                "--complete: copied {} additional file(s) from input to output.",
                copied
            ),
        );
    }
    Ok(())
}

fn move_file_across_drives(src: &Path, dst: &Path) -> anyhow::Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(17) || e.raw_os_error() == Some(0x11) => {
            // OS error 17 (EXDEV / ERROR_NOT_SAME_DEVICE): cross-drive rename.
            // Fall back to copy + delete.
            std::fs::copy(src, dst)?;
            std::fs::remove_file(src)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn recreate_dir(dir: &Path) -> anyhow::Result<PathBuf> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    std::fs::create_dir_all(dir)?;
    Ok(dir.to_path_buf())
}

fn create_pipeline_temp_root(final_output_dir: &Path) -> anyhow::Result<TempDir> {
    if let Some(parent) = final_output_dir.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            return Ok(tempfile::Builder::new()
                .prefix("dynobox-stage-")
                .tempdir_in(parent)?);
        }
    }

    Ok(tempfile::Builder::new()
        .prefix("dynobox-stage-")
        .tempdir()?)
}

fn message<S>(events: &mut S, level: MessageLevel, text: String)
where
    S: EventSink + ?Sized,
{
    events.emit(ProgressEvent::Message { level, text });
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::events::NoopEventSink;

    #[derive(Default)]
    struct TestPipelineOps {
        calls: RefCell<Vec<String>>,
    }

    impl TestPipelineOps {
        fn record(&self, call: impl Into<String>) {
            self.calls.borrow_mut().push(call.into());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl PipelineOps for TestPipelineOps {
        fn unpack_stage(
            &self,
            _input: &Path,
            out_dir: &Path,
            _events: &mut dyn EventSink,
        ) -> anyhow::Result<()> {
            self.record("unpack_stage");
            fs::create_dir_all(out_dir)?;
            Ok(())
        }

        fn prepare_image_workspace_from_unpack(
            &self,
            _base_input_dir: &Path,
            _unpacked_image_dir: &Path,
            stage_dir: &Path,
        ) -> anyhow::Result<TransferStats> {
            self.record("prepare_image_workspace_from_unpack");
            fs::create_dir_all(stage_dir)?;
            Ok(TransferStats::default())
        }

        fn apply_preflight(
            &self,
            _ota_zips: &[PathBuf],
            _scratch_dir: &Path,
            _events: &mut dyn EventSink,
        ) -> anyhow::Result<()> {
            self.record("apply_preflight");
            Ok(())
        }

        fn apply_stage(
            &self,
            _input: &Path,
            out_dir: &Path,
            _ota_zips: &[PathBuf],
            force_unpack: bool,
            _scratch_dir: &Path,
            _events: &mut dyn EventSink,
        ) -> anyhow::Result<()> {
            self.record(format!("apply_stage(force_unpack={force_unpack})"));
            fs::create_dir_all(out_dir)?;
            fs::write(out_dir.join("apply.img"), b"apply")?;
            Ok(())
        }

        fn resign_stage(
            &self,
            _input: &Path,
            out_dir: &Path,
            _config: &ResignConfig,
            _events: &mut dyn EventSink,
        ) -> anyhow::Result<()> {
            self.record("resign_stage");
            fs::create_dir_all(out_dir)?;
            fs::write(out_dir.join("resign.img"), b"resign")?;
            Ok(())
        }

        fn repack_pipeline(
            &self,
            _base_input_dir: &Path,
            _image_dir: &Path,
            final_output_dir: &Path,
            _scratch_dir: &Path,
            _events: &mut dyn EventSink,
        ) -> anyhow::Result<()> {
            self.record("repack_pipeline");
            fs::create_dir_all(final_output_dir)?;
            fs::write(final_output_dir.join("super_1.img"), b"repack")?;
            Ok(())
        }

        fn repack_stage(
            &self,
            _input: &Path,
            out_dir: &Path,
            _events: &mut dyn EventSink,
        ) -> anyhow::Result<()> {
            self.record("repack_stage");
            fs::create_dir_all(out_dir)?;
            fs::write(out_dir.join("super_1.img"), b"repack")?;
            Ok(())
        }

        fn verify_stage(
            &self,
            output_dir: &Path,
            _events: &mut dyn EventSink,
        ) -> anyhow::Result<()> {
            self.record("verify_stage");
            assert!(output_dir.exists());
            Ok(())
        }
    }

    #[test]
    fn apply_pipeline_runs_preflight_apply_and_verify() {
        let temp = tempdir().unwrap();
        let input = temp.path().join("input");
        let output = temp.path().join("output_apply");
        fs::create_dir_all(&input).unwrap();

        let request = ApplyRequest {
            input: input.clone(),
            output: output.clone(),
            ota_zips: vec![temp.path().join("ota1.zip")],
            force_unpack: false,
            resign: None,
            repack: false,
            complete: false,
        };
        let ops = TestPipelineOps::default();
        let mut sink = NoopEventSink;

        run_apply_with_ops(&request, &mut sink, &ops).unwrap();

        assert_eq!(
            ops.calls(),
            vec![
                "apply_preflight",
                "apply_stage(force_unpack=false)",
                "verify_stage",
            ]
        );
        assert!(output.exists());
        assert_no_stage_dirs(temp.path());
    }

    #[test]
    fn apply_pipeline_with_resign_runs_expected_sequence() {
        let temp = tempdir().unwrap();
        let input = temp.path().join("input");
        let output = temp.path().join("output_resign");
        fs::create_dir_all(&input).unwrap();

        let request = ApplyRequest {
            input: input.clone(),
            output: output.clone(),
            ota_zips: vec![temp.path().join("ota1.zip")],
            force_unpack: false,
            resign: Some(sample_resign_config()),
            repack: false,
            complete: false,
        };
        let ops = TestPipelineOps::default();
        let mut sink = NoopEventSink;

        run_apply_with_ops(&request, &mut sink, &ops).unwrap();

        assert_eq!(
            ops.calls(),
            vec![
                "apply_preflight",
                "apply_stage(force_unpack=false)",
                "resign_stage",
                "verify_stage",
            ]
        );
        assert!(output.exists());
        assert_no_stage_dirs(temp.path());
    }

    #[test]
    fn apply_pipeline_with_repack_runs_expected_sequence() {
        let temp = tempdir().unwrap();
        let input = temp.path().join("input");
        let output = temp.path().join("output_repack");
        fs::create_dir_all(&input).unwrap();

        let request = ApplyRequest {
            input: input.clone(),
            output: output.clone(),
            ota_zips: vec![temp.path().join("ota1.zip")],
            force_unpack: false,
            resign: None,
            repack: true,
            complete: false,
        };
        let ops = TestPipelineOps::default();
        let mut sink = NoopEventSink;

        run_apply_with_ops(&request, &mut sink, &ops).unwrap();

        assert_eq!(
            ops.calls(),
            vec![
                "apply_preflight",
                "apply_stage(force_unpack=false)",
                "repack_pipeline",
                "verify_stage",
            ]
        );
        assert!(output.exists());
        assert_no_stage_dirs(temp.path());
    }

    #[test]
    fn apply_pipeline_with_unpack_resign_repack_runs_expected_sequence() {
        let temp = tempdir().unwrap();
        let input = temp.path().join("input");
        let output = temp.path().join("output_repack");
        fs::create_dir_all(&input).unwrap();

        let request = ApplyRequest {
            input: input.clone(),
            output: output.clone(),
            ota_zips: vec![temp.path().join("ota1.zip"), temp.path().join("ota2.zip")],
            force_unpack: true,
            resign: Some(sample_resign_config()),
            repack: true,
            complete: false,
        };
        let ops = TestPipelineOps::default();
        let mut sink = NoopEventSink;

        run_apply_with_ops(&request, &mut sink, &ops).unwrap();

        assert_eq!(
            ops.calls(),
            vec![
                "apply_preflight",
                "apply_stage(force_unpack=true)",
                "resign_stage",
                "repack_pipeline",
                "verify_stage",
            ]
        );
        assert!(output.exists());
        assert_no_stage_dirs(temp.path());
    }

    #[test]
    fn resolve_partition_source_candidates_uses_extension_fallback_when_filename_is_empty() {
        let temp = tempdir().unwrap();
        let rawprogram_path = temp.path().join("rawprogram4.xml");
        fs::write(
            &rawprogram_path,
            r#"<?xml version="1.0"?>
<data>
  <program label="qweslicstore_a" filename="" />
</data>"#,
        )
        .unwrap();

        let catalog = dynobox_xml::XmlCatalog::from_dir(temp.path()).unwrap();
        let candidates = resolve_partition_source_candidates(&catalog, "qweslicstore");
        assert_eq!(
            candidates,
            vec![
                "qweslicstore.img",
                "qweslicstore.bin",
                "qweslicstore.elf",
                "qweslicstore.melf",
                "qweslicstore.mbn",
            ]
        );
    }

    #[test]
    fn find_existing_filename_in_dir_prefers_fallback_priority_order() {
        let temp = tempdir().unwrap();
        let rawprogram_path = temp.path().join("rawprogram4.xml");
        fs::write(
            &rawprogram_path,
            r#"<?xml version="1.0"?>
<data>
  <program label="qweslicstore_a" filename="" />
</data>"#,
        )
        .unwrap();
        fs::write(temp.path().join("qweslicstore.elf"), b"elf").unwrap();
        fs::write(temp.path().join("qweslicstore.bin"), b"bin").unwrap();

        let catalog = dynobox_xml::XmlCatalog::from_dir(temp.path()).unwrap();
        let candidates = resolve_partition_source_candidates(&catalog, "qweslicstore");
        assert_eq!(
            find_existing_filename_in_dir(temp.path(), &candidates),
            Some("qweslicstore.bin".to_string())
        );
    }

    #[test]
    fn resolve_partition_source_candidates_respects_xml_filename_when_present() {
        let temp = tempdir().unwrap();
        let rawprogram_path = temp.path().join("rawprogram4.xml");
        fs::write(
            &rawprogram_path,
            r#"<?xml version="1.0"?>
<data>
  <program label="qweslicstore_a" filename="qweslicstore.bin" />
</data>"#,
        )
        .unwrap();

        let catalog = dynobox_xml::XmlCatalog::from_dir(temp.path()).unwrap();
        let candidates = resolve_partition_source_candidates(&catalog, "qweslicstore");
        assert_eq!(candidates, vec!["qweslicstore.bin"]);
    }

    fn sample_resign_config() -> ResignConfig {
        ResignConfig {
            key: "testkey_rsa2048".to_string(),
            algorithm: Some("SHA256_RSA2048".to_string()),
            force: false,
            rollback_index: None,
            boot_spl: None,
            vendor_spl: None,
            fix_locale: false,
        }
    }

    #[test]
    fn format_unix_timestamp_utc_matches_ctime_example() {
        // `date -u -d @1772073650` → Thu Feb 26 02:40:50 UTC 2026
        let s = format_unix_timestamp_utc(1_772_073_650);
        assert_eq!(s, "Thu Feb 26 02:40:50 UTC 2026");
    }

    #[test]
    fn format_unix_timestamp_utc_epoch() {
        let s = format_unix_timestamp_utc(0);
        assert_eq!(s, "Thu Jan  1 00:00:00 UTC 1970");
    }

    fn assert_no_stage_dirs(parent: &Path) {
        let leftovers: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let name = path.file_name()?.to_string_lossy();
                if path.is_dir() && name.starts_with("dynobox-stage-") {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();
        assert!(leftovers.is_empty(), "leftover temp dirs: {leftovers:?}");
    }
}
