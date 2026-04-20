use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use tempfile::TempDir;

use crate::events::{CommandKind, EventSink, MessageLevel, ProgressEvent, StageKind};
use crate::verify::run_verify_stage;

const PARTITION_IMAGE_EXTENSION_FALLBACK: [&str; 5] = ["img", "bin", "elf", "melf", "mbn"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResignConfig {
    pub key: String,
    pub algorithm: Option<String>,
    pub force: bool,
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

    if request.resign.is_none() && !request.repack {
        ops.unpack_stage(&request.input, &request.output, events)?;
        return ops.verify_stage(&request.output, events);
    }

    let temp_root = create_pipeline_temp_root(&request.output)?;
    let unpack_stage_dir = temp_root.path().join("unpack_stage");
    ops.unpack_stage(&request.input, &unpack_stage_dir, events)?;

    let image_stage_dir = temp_root.path().join("image_stage");
    let prep_stats = ops.prepare_image_workspace_from_unpack(
        &request.input,
        &unpack_stage_dir,
        &image_stage_dir,
    )?;
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
    let pipeline_mode = request.resign.is_some() || request.repack;
    let apply_out_dir = if pipeline_mode {
        temp_root.path().join("apply_stage")
    } else {
        request.output.clone()
    };

    ops.apply_stage(
        &request.input,
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
    let effective_input = auto_unpack_if_needed(&request.input, temp_root.path(), events, ops)?;
    let input_dir = effective_input.as_deref().unwrap_or(&request.input);

    if !request.repack {
        ops.resign_stage(input_dir, &request.output, &request.config, events)?;
        return ops.verify_stage(&request.output, events);
    }

    let resign_stage_dir = temp_root.path().join("resign_stage");
    ops.resign_stage(input_dir, &resign_stage_dir, &request.config, events)?;
    ops.repack_pipeline(
        &request.input,
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
    let effective_input = auto_unpack_if_needed(&request.input, temp_root.path(), events, ops)?;
    let input_dir = effective_input.as_deref().unwrap_or(&request.input);

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
                                Some(&[p_info.name.clone()]),
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
            dynobox_payload::apply_partition_payload(
                &payload_path,
                &p_info.name,
                &src_path,
                &temp_new,
                metadata.block_size,
            )?;
            move_file_across_drives(&temp_new, &out_path)?;
        }
    }

    if auto_unpack_stage_open {
        events.emit(ProgressEvent::StageCompleted {
            stage: StageKind::AutoUnpack,
        });
    }
    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Apply,
    });
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

    recreate_dir(out_dir)?;

    // Copy ALL input files to output first (preserves non-.img files like .elf, .mbn)
    copy_all_top_level_files(input, out_dir)?;

    let images = collect_resignable_images(input)?;
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

        match avbtool_rs::resign::resign_image(
            &out_path,
            &config.key,
            config.algorithm.as_deref(),
            config.force,
        ) {
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
    }

    message(
        events,
        MessageLevel::Info,
        format!(
            "Resign complete. Re-signed {} images, skipped {} unsigned AVB images.",
            resigned_count, skipped_unsigned_count
        ),
    );
    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Resign,
    });
    Ok(())
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

            if let Ok(img_type) = avbtool_rs::parser::detect_avb_image_type(&path) {
                if img_type != avbtool_rs::parser::AvbImageType::None {
                    images.push(path);
                }
            }
        }
    }
    Ok(images)
}

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

/// Copy ALL top-level files from src_dir to dst_dir, skipping super_*.img chunks.
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
        }
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
