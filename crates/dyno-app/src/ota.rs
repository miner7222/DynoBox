//! Custom OTA support: signing keys and OTA generation from DynoBox image
//! directories.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use dynobox_ota::metadata::{DeviceState, OtaMetadata, OtaType};
use dynobox_ota::package::{ExtraEntry, PackageSpec};
use dynobox_ota::{Certificate, OtaSigningKey};
use dynobox_payload::payload::proto::{DeltaArchiveManifest, PartitionInfo, PartitionUpdate};
use sha2::{Digest, Sha256};

use crate::events::{CommandKind, EventSink, MessageLevel, ProgressEvent, ProgressUnit, StageKind};
use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume};
use crate::integrity_signature::write_atomic_noclobber;
use crate::pipeline;

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

/// Partition images of a DynoBox firmware or image directory, read the way
/// the device holds them: the first `size` bytes of the partition,
/// zero-extended when the file is shorter. Lookup mirrors the apply stage:
/// split fragments, then the rawprogram filename, then `<name>.img`, then a
/// dynamic partition extracted from super.
struct PartitionImages<'a> {
    dir: &'a Path,
    scratch: &'a Path,
    catalog: Option<dynobox_xml::XmlCatalog>,
    super_layout: Option<Option<dynobox_super::SuperLayout>>,
}

impl<'a> PartitionImages<'a> {
    fn new(dir: &'a Path, scratch: &'a Path) -> Result<Self> {
        if !dir.is_dir() {
            bail!("{} is not a directory", dir.display());
        }
        let has_rawprogram = fs::read_dir(dir)?.flatten().any(|e| {
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            name.starts_with("rawprogram") && name.ends_with(".xml")
        });
        let catalog = if has_rawprogram {
            Some(dynobox_xml::XmlCatalog::from_dir(dir)?)
        } else {
            None
        };
        Ok(Self {
            dir,
            scratch,
            catalog,
            super_layout: None,
        })
    }

    fn locate<S>(&mut self, name: &str, size: u64, events: &mut S) -> Result<PathBuf>
    where
        S: EventSink + ?Sized,
    {
        if let Some(catalog) = &self.catalog {
            let fragments = pipeline::find_split_source_fragments(catalog, name);
            if !fragments.is_empty()
                && fragments
                    .iter()
                    .all(|f| self.dir.join(&f.filename).exists())
            {
                let rebuilt = self.scratch.join(format!("{name}_split.img"));
                pipeline::reconstruct_split_source(&fragments, self.dir, size, &rebuilt)?;
                return Ok(rebuilt);
            }
            let candidates = pipeline::resolve_partition_source_candidates(catalog, name);
            if let Some(file) = pipeline::find_existing_filename_in_dir(self.dir, &candidates) {
                return Ok(self.dir.join(file));
            }
        }
        for ext in ["img", "bin", "elf", "melf", "mbn"] {
            let path = self.dir.join(format!("{name}.{ext}"));
            if path.is_file() {
                return Ok(path);
            }
        }
        if self.super_layout.is_none() {
            self.super_layout = Some(match &self.catalog {
                Some(catalog) => pipeline::load_super_layout(catalog, self.dir)?,
                None => None,
            });
        }
        if let Some(Some(layout)) = &self.super_layout {
            if layout.find_partition(name).is_some() {
                let extracted = pipeline::extract_partition_images_with_progress_events(
                    events,
                    StageKind::Ota,
                    layout,
                    self.scratch,
                    Some(&[name.to_string()]),
                    1,
                )?;
                if let Some(path) = extracted.get(name) {
                    return Ok(path.clone());
                }
            }
        }
        bail!(
            "partition `{name}` not found in {} (no split fragments, rawprogram file, \
             {name}.img, or super entry)",
            self.dir.display()
        )
    }

    /// A reader yielding exactly `size` bytes of partition `name`.
    fn open<S>(&mut self, name: &str, size: u64, events: &mut S) -> Result<impl Read + use<S>>
    where
        S: EventSink + ?Sized,
    {
        let path = self.locate(name, size, events)?;
        let file = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let len = file.metadata()?.len();
        Ok(file
            .take(size)
            .chain(std::io::repeat(0).take(size.saturating_sub(len))))
    }
}

/// The parts of an OEM OTA that describe the target build.
pub(crate) struct Reference {
    pub(crate) path: PathBuf,
    pub(crate) manifest: DeltaArchiveManifest,
    pub(crate) metadata: OtaMetadata,
    pub(crate) extras: Vec<ExtraEntry>,
    /// Absolute file offset of the reference payload's operation data.
    pub(crate) blob_start: u64,
}

pub(crate) fn read_reference(path: &Path) -> Result<Reference> {
    let open = || File::open(path).with_context(|| format!("opening {}", path.display()));
    let mut zip = zip::ZipArchive::new(open()?).context("reading the reference OTA zip")?;
    let mut read = |name: &str| -> Result<Option<Vec<u8>>> {
        match zip.by_name(name) {
            Ok(mut entry) => {
                let mut out = Vec::new();
                entry.read_to_end(&mut out)?;
                Ok(Some(out))
            }
            Err(zip::result::ZipError::FileNotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    };
    let metadata = OtaMetadata::decode_pb(
        &read(dynobox_ota::metadata::PATH_METADATA_PB)?
            .ok_or_else(|| anyhow!("reference OTA has no metadata.pb"))?,
    )?;
    if metadata.r#type != OtaType::Ab as i32 {
        bail!("reference OTA is not an A/B OTA");
    }
    let mut extras = Vec::new();
    for name in ["apex_info.pb", "care_map.pb"] {
        if let Some(data) = read(name)? {
            extras.push(ExtraEntry {
                name: name.to_string(),
                data,
            });
        }
    }
    let payload_start = zip
        .by_name(dynobox_ota::package::PATH_PAYLOAD)
        .context("reference OTA has no payload.bin")?
        .data_start()
        .ok_or_else(|| anyhow!("reference payload.bin offset unknown"))?;
    let payload = dynobox_ota::payload::read_manifest(&mut open()?, payload_start)?;
    Ok(Reference {
        path: path.to_path_buf(),
        manifest: payload.manifest,
        metadata,
        extras,
        blob_start: payload_start + payload.blob_offset,
    })
}

/// Inputs for [`generate_ota`].
#[derive(Debug, Clone)]
pub struct OtaRequest {
    /// Firmware or image directory holding the build currently on the
    /// device. `None` builds a full OTA that installs over any build.
    pub source: Option<PathBuf>,
    /// Firmware or image directory holding the build to install.
    pub target: PathBuf,
    /// OEM OTA whose target is the same build as `target`. It supplies
    /// partition sizes and metadata. An OEM incremental from the source's
    /// stock build also supplies operations to reuse, unless `force_delta`.
    pub reference: PathBuf,
    pub key: PathBuf,
    pub cert: PathBuf,
    pub output: PathBuf,
    /// Package partitions even when they fail AVB verification.
    pub allow_avb_mismatch: bool,
    /// Diff source and target block by block even when the reference is an
    /// OEM incremental, e.g. when both builds share the same stock base.
    pub force_delta: bool,
    /// Physical partitions left out of the OTA; the updated slot keeps
    /// whatever image it already holds for them.
    pub exclude: Vec<String>,
}

/// Summary of a generated OTA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedOta {
    pub partitions: usize,
    pub size: u64,
    /// Operation totals for an incremental OTA rebased on an OEM incremental.
    pub incremental: Option<RebaseStats>,
    /// Block totals for an incremental OTA built as a native delta.
    pub delta: Option<DeltaStats>,
}

pub use crate::ota_delta::DeltaStats;
pub use crate::ota_rebase::RebaseStats;

/// Minor version for native delta payloads: source hashes and brotli
/// bsdiff, supported by every Virtual A/B device.
const DELTA_MINOR_VERSION: u32 = 8;

/// The reference's partitions minus `exclude`. Each excluded name must be
/// one of them, and a dynamic partition cannot be excluded: its dynamic
/// partition metadata would still create it, empty, in the updated slot.
fn select_partitions<'a>(
    manifest: &'a DeltaArchiveManifest,
    exclude: &[String],
) -> Result<Vec<&'a PartitionUpdate>> {
    let dynamic: std::collections::BTreeSet<&str> = manifest
        .dynamic_partition_metadata
        .iter()
        .flat_map(|d| &d.groups)
        .flat_map(|g| &g.partition_names)
        .map(String::as_str)
        .collect();
    for name in exclude {
        if !manifest
            .partitions
            .iter()
            .any(|p| &p.partition_name == name)
        {
            bail!("cannot exclude `{name}`: the reference OTA has no such partition");
        }
        if dynamic.contains(name.as_str()) {
            bail!(
                "cannot exclude `{name}`: it is a dynamic partition, which the updated \
                 slot would get empty"
            );
        }
    }
    Ok(manifest
        .partitions
        .iter()
        .filter(|p| !exclude.contains(&p.partition_name))
        .collect())
}

/// Parse an Android `build.prop` into key/value pairs. Quoted values lose
/// their quotes; unknown/malformed lines are ignored.
fn parse_build_props(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            ))
        })
        .collect()
}

/// Build the OTA postcondition and downgrade ceiling from the target build.
///
/// An OEM reference OTA can belong to a different build (for example an older
/// incremental used only for partition sizes). Copying its `post-build` and
/// `max_timestamp` would then label the package as that older build and make
/// update_engine reject it as a downgrade, so the postcondition and the
/// downgrade ceiling must come from the target images instead.
fn read_target_device_state<S>(
    targets: &mut PartitionImages<'_>,
    included: &[&PartitionUpdate],
    events: &mut S,
    reference: &Reference,
) -> Result<DeviceState>
where
    S: EventSink + ?Sized,
{
    let size = included
        .iter()
        .find(|p| p.partition_name == "system")
        .and_then(|p| p.new_partition_info.as_ref().and_then(|info| info.size))
        .ok_or_else(|| anyhow!("reference OTA gives no new size for `system`"))?;
    let image = targets.locate("system", size, events)?;
    let mut volume = open_ext4_volume(&image)?;
    let inode = lookup_inode_at_path(&mut volume, &["system", "build.prop"])?
        .ok_or_else(|| anyhow!("target system image has no /system/build.prop"))?;
    let bytes = inode
        .open_read(&mut volume)
        .context("reading the target /system/build.prop")?;
    let text = String::from_utf8_lossy(&bytes);
    let props = parse_build_props(&text);
    let get = |key: &str| props.get(key).cloned().unwrap_or_default();

    // Lenovo rewrites the runtime fingerprint at boot (region suffix), so the
    // image only has the partition-level fingerprint. Prefer the full one when
    // present; otherwise use the system fingerprint rather than failing: the
    // package's post-build is informational for update_engine.
    let fingerprint = {
        let full = get("ro.build.fingerprint");
        if full.is_empty() {
            get("ro.system.build.fingerprint")
        } else {
            full
        }
    };
    if fingerprint.is_empty() {
        bail!("target build.prop has no build fingerprint");
    }
    let timestamp = get("ro.build.date.utc").parse::<i64>().unwrap_or(0);
    if timestamp <= 0 {
        bail!("target build.prop has no usable ro.build.date.utc");
    }
    let build_incremental = get("ro.build.version.incremental");
    // When the reference OTA was built from the same build (same incremental)
    // its post-build is the OEM's own fingerprint, which is better than the
    // partition-level one the image carries.
    let build = reference
        .metadata
        .postcondition
        .as_ref()
        .filter(|post| !post.build.is_empty() && post.build_incremental == build_incremental)
        .map(|post| post.build.clone())
        .unwrap_or_else(|| vec![fingerprint]);
    Ok(DeviceState {
        device: vec![get("ro.product.device")],
        build,
        build_incremental,
        timestamp,
        sdk_level: get("ro.build.version.sdk"),
        security_patch_level: get("ro.build.version.security_patch"),
        ..Default::default()
    })
}

/// Build a signed A/B OTA of `request.target`: incremental from
/// `request.source` when given, otherwise full.
pub fn generate_ota<S>(request: &OtaRequest, events: &mut S) -> Result<GeneratedOta>
where
    S: EventSink + ?Sized,
{
    let key = OtaSigningKey::load(&request.key)?;
    let cert = Certificate::load(&request.cert)?;
    if !cert.matches_key(&key) {
        bail!(
            "{} does not belong to {}",
            request.cert.display(),
            request.key.display()
        );
    }
    if request.output.exists() {
        bail!("refusing to overwrite {}", request.output.display());
    }
    events.emit(ProgressEvent::CommandStarted {
        command: CommandKind::Ota,
        input: request.target.clone(),
        output: request.output.clone(),
    });
    events.emit(ProgressEvent::StageStarted {
        stage: StageKind::Ota,
    });

    let reference = read_reference(&request.reference)?;
    // Virtual A/B compression is fine: the generated payload keeps the
    // reference's dynamic-partition metadata (including its VABC settings) and
    // update_engine applies the plain delta ops through snapuserd.
    // With an OEM incremental, reuse its operations; with a full reference
    // or when asked, diff A' and B' block by block.
    let incremental_reference = reference.manifest.minor_version.unwrap_or(0) > 0;
    let rebase = request.source.is_some() && incremental_reference && !request.force_delta;
    let delta = request.source.is_some() && !rebase;
    if delta {
        message(
            events,
            if incremental_reference {
                "ota: building a block-level delta; the reference's operations are not used"
            } else {
                "ota: the reference is a full OTA, so building a block-level delta"
            },
        );
    }
    let included = select_partitions(&reference.manifest, &request.exclude)?;
    if !request.exclude.is_empty() {
        message(
            events,
            &format!(
                "ota: leaving out {}; the updated slot keeps its current images",
                request.exclude.join(", ")
            ),
        );
    }
    check_target_avb(&request.target, request.allow_avb_mismatch, events)?;
    let block_size = reference.manifest.block_size.unwrap_or(4096);
    // Scratch can reach several GB; keep it beside the output rather than in
    // the system temp directory, even for a bare relative output name.
    let scratch = pipeline::create_pipeline_temp_root(&std::path::absolute(&request.output)?)?;
    let (source_scratch, target_scratch) =
        (scratch.path().join("source"), scratch.path().join("target"));
    fs::create_dir_all(&source_scratch)?;
    fs::create_dir_all(&target_scratch)?;
    let mut targets = PartitionImages::new(&request.target, &target_scratch)?;
    let mut sources = match &request.source {
        Some(dir) => Some(PartitionImages::new(dir, &source_scratch)?),
        None => None,
    };
    // The reference may describe another build; always label the package with
    // the target's own fingerprint and downgrade ceiling.
    let target_state = read_target_device_state(&mut targets, &included, events, &reference)?;
    let mut reference_blobs = match rebase {
        true => Some(crate::ota_rebase::ReferenceBlobs::open(
            &reference.path,
            reference.blob_start,
        )?),
        false => None,
    };
    let mut delta_totals = DeltaStats::default();

    let blob_path = scratch.path().join("blobs.bin");
    let mut blobs = BufWriter::new(File::create(&blob_path)?);
    let total = included.len();
    let mut partitions = Vec::with_capacity(total);
    let mut totals = RebaseStats::default();
    for (index, reference_partition) in included.into_iter().enumerate() {
        let name = &reference_partition.partition_name;
        let size = reference_partition
            .new_partition_info
            .as_ref()
            .and_then(|info| info.size)
            .ok_or_else(|| anyhow!("reference OTA gives no new size for `{name}`"))?;
        events.emit(ProgressEvent::ItemStarted {
            stage: StageKind::Ota,
            current: index + 1,
            total,
            item: name.clone(),
        });
        let partition = match (&mut sources, &mut reference_blobs) {
            (Some(sources), Some(reference_blobs)) => {
                let old_size = reference_partition
                    .old_partition_info
                    .as_ref()
                    .and_then(|info| info.size)
                    .unwrap_or(0);
                let source_path = match old_size {
                    0 => None,
                    _ => Some(sources.locate(name, old_size, events)?),
                };
                let target_path = targets.locate(name, size, events)?;
                let (update, stats) = crate::ota_rebase::rebase_partition(
                    reference_partition,
                    crate::ota_rebase::PartitionInputs {
                        source: source_path.as_deref(),
                        target: &target_path,
                        probe: scratch.path().join(format!("{name}.probe")),
                    },
                    block_size,
                    reference_blobs,
                    &mut blobs,
                    |done, ops| {
                        events.emit(ProgressEvent::ItemProgress {
                            stage: StageKind::Ota,
                            item: name.clone(),
                            done: done as u64,
                            total: ops as u64,
                            unit: ProgressUnit::Ops,
                        })
                    },
                )
                .with_context(|| format!("rebasing partition `{name}`"))?;
                if stats.regenerated() + stats.filled > 0 {
                    message(
                        events,
                        &format!(
                            "ota {name}: {} reused; regenerated {} (source changed), {} (target changed), {} (not replayable); {} added",
                            stats.kept,
                            stats.source_changed,
                            stats.target_changed,
                            stats.unreplayable,
                            stats.filled
                        ),
                    );
                }
                totals.add(&stats);
                update
            }
            (Some(sources), None) => {
                let source_path = sources.locate(name, size, events)?;
                // Only whole blocks the flashed image actually covers are
                // known on the device; past its end a physical partition
                // holds leftovers, so never read those as source.
                let old_size = fs::metadata(&source_path)?.len() / u64::from(block_size)
                    * u64::from(block_size);
                let target_path = targets.locate(name, size, events)?;
                let delta = crate::ota_delta::delta_partition(
                    Some(&source_path),
                    old_size,
                    &target_path,
                    size,
                    block_size,
                    &mut blobs,
                    |done, blocks| {
                        events.emit(ProgressEvent::ItemProgress {
                            stage: StageKind::Ota,
                            item: name.clone(),
                            done,
                            total: blocks,
                            unit: ProgressUnit::Blocks,
                        })
                    },
                )
                .with_context(|| format!("diffing partition `{name}`"))?;
                delta_totals.add(&delta.stats);
                PartitionUpdate {
                    partition_name: name.clone(),
                    run_postinstall: reference_partition.run_postinstall,
                    postinstall_path: reference_partition.postinstall_path.clone(),
                    filesystem_type: reference_partition.filesystem_type.clone(),
                    postinstall_optional: reference_partition.postinstall_optional,
                    version: reference_partition.version.clone(),
                    // VABC needs a COW size per partition; derive a bound from
                    // the ops we just generated (the reference's estimate is
                    // for its own, much larger payload).
                    estimate_cow_size: Some({
                        // VABC sizes the COW from the blocks it must write.
                        // The delta carries whole-partition source-copy ops, so
                        // dst extents cover the partition; only the carried
                        // blobs actually land in the COW. A generous multiple
                        // plus a floor keeps the total under the device's free
                        // space while covering compression expansion.
                        let data: u64 = delta
                            .operations
                            .iter()
                            .map(|op| op.data_length.unwrap_or(0))
                            .sum();
                        (data * 8 + delta.operations.len() as u64 * 256 + (32 << 20)).min(size)
                    }),
                    old_partition_info: delta.old_hash.map(|hash| PartitionInfo {
                        size: Some(old_size),
                        hash: Some(hash.to_vec()),
                    }),
                    new_partition_info: Some(PartitionInfo {
                        size: Some(size),
                        hash: Some(delta.new_hash.to_vec()),
                    }),
                    operations: delta.operations,
                    ..Default::default()
                }
            }
            _ => {
                let mut source = targets.open(name, size, events)?;
                let encoded = dynobox_ota::full::encode_partition(
                    &mut source,
                    size,
                    block_size,
                    &mut blobs,
                    |done| {
                        events.emit(ProgressEvent::ItemProgress {
                            stage: StageKind::Ota,
                            item: name.clone(),
                            done,
                            total: size,
                            unit: ProgressUnit::Bytes,
                        })
                    },
                )
                .with_context(|| format!("encoding partition `{name}`"))?;
                PartitionUpdate {
                    partition_name: name.clone(),
                    run_postinstall: reference_partition.run_postinstall,
                    postinstall_path: reference_partition.postinstall_path.clone(),
                    filesystem_type: reference_partition.filesystem_type.clone(),
                    postinstall_optional: reference_partition.postinstall_optional,
                    version: reference_partition.version.clone(),
                    // VABC snapshots need a COW size; the reference's estimate
                    // is for its own (much larger) payload, so derive a bound
                    // from the ops we just wrote.
                    estimate_cow_size: Some(
                        encoded
                            .operations
                            .iter()
                            .map(|op| op.dst_length.unwrap_or(0).max(op.data_length.unwrap_or(0)))
                            .sum::<u64>()
                            .saturating_mul(2)
                            .saturating_add(4 << 20),
                    ),
                    new_partition_info: Some(PartitionInfo {
                        size: Some(size),
                        hash: Some(encoded.hash.to_vec()),
                    }),
                    operations: encoded.operations,
                    ..Default::default()
                }
            }
        };
        partitions.push(partition);
    }
    drop(blobs);

    let (manifest, metadata) = if rebase {
        // Same payload shape as the OEM incremental, and the OEM's
        // preconditions pin the source build.
        let mut manifest = reference.manifest.clone();
        manifest.partitions = partitions;
        manifest.signatures_offset = None;
        manifest.signatures_size = None;
        manifest.max_timestamp = Some(target_state.timestamp);
        let mut metadata = reference.metadata.clone();
        metadata.postcondition = Some(target_state.clone());
        (manifest, metadata)
    } else {
        // Full and native-delta OTAs pin only the device: a delta run on the
        // wrong build fails update_engine's source hash checks before the
        // slot switch.
        let manifest = DeltaArchiveManifest {
            block_size: Some(block_size),
            minor_version: Some(if delta { DELTA_MINOR_VERSION } else { 0 }),
            partitions,
            max_timestamp: Some(target_state.timestamp),
            dynamic_partition_metadata: reference.manifest.dynamic_partition_metadata.clone(),
            partial_update: reference.manifest.partial_update,
            apex_info: reference.manifest.apex_info.clone(),
            security_patch_level: reference.manifest.security_patch_level.clone(),
            ..Default::default()
        };
        // A full OTA may be installed over any build of this device.
        let metadata = OtaMetadata {
            r#type: OtaType::Ab as i32,
            precondition: Some(DeviceState {
                device: reference
                    .metadata
                    .precondition
                    .as_ref()
                    .map(|p| p.device.clone())
                    .unwrap_or_default(),
                ..Default::default()
            }),
            postcondition: Some(target_state.clone()),
            ..Default::default()
        };
        (manifest, metadata)
    };

    let payload_path = scratch.path().join("payload.bin");
    message(events, "ota: signing payload.bin");
    let summary = {
        let mut out = BufWriter::new(File::create(&payload_path)?);
        dynobox_ota::payload::write_signed_payload(
            &mut out,
            manifest,
            &mut File::open(&blob_path)?,
            &key,
        )?
    };
    fs::remove_file(&blob_path)?;
    message(events, "ota: writing and signing the package");
    dynobox_ota::package::write_package(
        &request.output,
        PackageSpec {
            payload: &payload_path,
            payload_summary: &summary,
            extras: reference.extras,
            metadata,
        },
        &key,
        &cert,
    )?;
    drop(scratch);

    message(events, "ota: verifying the package");
    dynobox_ota::verify::verify_package(&request.output, Some(&cert))
        .context("the generated OTA failed verification")?;
    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Ota,
    });
    Ok(GeneratedOta {
        partitions: total,
        size: fs::metadata(&request.output)?.len(),
        incremental: rebase.then_some(totals),
        delta: delta.then_some(delta_totals),
    })
}

/// Refuse a target whose images fail their AVB hash or hashtree checks: the
/// device would reject them at boot or hit dm-verity errors after the
/// update. Missing super chunks are fine for an unpacked image directory.
fn check_target_avb<S>(target: &Path, allow_mismatch: bool, events: &mut S) -> Result<()>
where
    S: EventSink + ?Sized,
{
    message(events, "ota: checking the target's AVB hashes");
    let report = crate::verify::verify_input(target)?;
    let failures: Vec<String> = report
        .failures
        .iter()
        .filter(|f| f.kind == crate::verify::VerificationFailureKind::Avb)
        .map(|f| f.message.clone())
        .collect();
    if failures.is_empty() {
        return Ok(());
    }
    if allow_mismatch {
        for failure in &failures {
            events.emit(ProgressEvent::Message {
                level: MessageLevel::Warning,
                text: format!("ota: packaging despite AVB failure: {failure}"),
            });
        }
        return Ok(());
    }
    bail!(
        "the target fails AVB verification, so the device would reject it:\n  {}\n\
         (pass --allow-avb-mismatch to package it anyway)",
        failures.join("\n  ")
    )
}

fn message<S>(events: &mut S, text: &str)
where
    S: EventSink + ?Sized,
{
    events.emit(ProgressEvent::Message {
        level: MessageLevel::Info,
        text: text.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_named_physical_partitions_only() {
        use dynobox_payload::payload::proto::{DynamicPartitionGroup, DynamicPartitionMetadata};
        let partition = |name: &str| PartitionUpdate {
            partition_name: name.into(),
            ..Default::default()
        };
        let manifest = DeltaArchiveManifest {
            partitions: vec![partition("system"), partition("abl"), partition("xbl")],
            dynamic_partition_metadata: Some(DynamicPartitionMetadata {
                groups: vec![DynamicPartitionGroup {
                    name: "main".into(),
                    partition_names: vec!["system".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let names = |exclude: &[&str]| -> Result<Vec<String>> {
            let exclude: Vec<String> = exclude.iter().map(|s| s.to_string()).collect();
            Ok(select_partitions(&manifest, &exclude)?
                .into_iter()
                .map(|p| p.partition_name.clone())
                .collect())
        };

        assert_eq!(names(&[]).unwrap(), ["system", "abl", "xbl"]);
        assert_eq!(names(&["abl", "xbl"]).unwrap(), ["system"]);
        let typo = names(&["alb"]).unwrap_err().to_string();
        assert!(typo.contains("no such partition"), "{typo}");
        let dynamic = names(&["system"]).unwrap_err().to_string();
        assert!(dynamic.contains("dynamic partition"), "{dynamic}");
    }

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

    #[test]
    fn parse_build_props_reads_fingerprint_and_timestamp() {
        let props = parse_build_props(
            "# comment\n\nro.build.fingerprint=Lenovo/TB324ZC/TB324ZC:17/x/y:user/release-keys\n\
             ro.build.date.utc=1793437559\n\
             ro.build.version.sdk=\"37\"\n\
             ro.product.device=TB324ZC\n",
        );
        assert_eq!(
            props.get("ro.build.fingerprint").map(String::as_str),
            Some("Lenovo/TB324ZC/TB324ZC:17/x/y:user/release-keys")
        );
        assert_eq!(
            props.get("ro.build.date.utc").map(String::as_str),
            Some("1793437559")
        );
        assert_eq!(
            props.get("ro.build.version.sdk").map(String::as_str),
            Some("37")
        );
        assert_eq!(
            props.get("ro.product.device").map(String::as_str),
            Some("TB324ZC")
        );
        assert!(!props.contains_key("# comment"));
    }

    #[test]
    fn partition_images_zero_extend_and_truncate_to_the_partition_size() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("abl.elf"), [7u8; 10]).unwrap();
        fs::write(dir.path().join("vbmeta.img"), [9u8; 8192]).unwrap();
        let mut images = PartitionImages::new(dir.path(), scratch.path()).unwrap();
        let mut sink = crate::events::NoopEventSink;

        let mut abl = Vec::new();
        images
            .open("abl", 16, &mut sink)
            .unwrap()
            .read_to_end(&mut abl)
            .unwrap();
        assert_eq!(abl, [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0]);
        let mut vbmeta = Vec::new();
        images
            .open("vbmeta", 4096, &mut sink)
            .unwrap()
            .read_to_end(&mut vbmeta)
            .unwrap();
        assert_eq!(vbmeta, vec![9u8; 4096]);
        assert!(images.open("tz", 4096, &mut sink).is_err());
    }
}
