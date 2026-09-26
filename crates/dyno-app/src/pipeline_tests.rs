use std::cell::RefCell;
use std::fs;

use tempfile::tempdir;

use super::*;
use crate::events::NoopEventSink;

/// Event sink that answers every prompt with a fixed reply and records
/// what it was asked.
struct ScriptedPromptSink {
    reply: PromptReply,
    asked: Vec<Prompt>,
}

impl EventSink for ScriptedPromptSink {
    fn emit(&mut self, _event: ProgressEvent) {}

    fn prompt(&mut self, prompt: &Prompt) -> PromptReply {
        self.asked.push(prompt.clone());
        self.reply
    }
}

#[test]
fn rollback_confirmation_maps_prompt_replies() {
    let targets = vec![(PathBuf::from("boot.img"), 1_700_000_000u64)];
    for (reply, expected) in [
        (PromptReply::Accepted, RollbackConfirmation::Accepted),
        (PromptReply::Declined, RollbackConfirmation::DeclinedByUser),
        (
            PromptReply::Unavailable,
            RollbackConfirmation::SkippedNonInteractive,
        ),
    ] {
        let mut sink = ScriptedPromptSink {
            reply,
            asked: Vec::new(),
        };
        assert_eq!(confirm_rollback_change(&mut sink, &targets, 0), expected);
        let [Prompt::Confirm { details, .. }] = sink.asked.as_slice() else {
            panic!("expected one confirm prompt, got {:?}", sink.asked);
        };
        assert!(details.iter().any(|line| line.contains("boot.img")));
    }
    // Sinks without prompt support never block and skip the rewrite.
    assert_eq!(
        confirm_rollback_change(&mut NoopEventSink, &targets, 0),
        RollbackConfirmation::SkippedNonInteractive
    );
}

fn write_sparse_fixture(path: &std::path::Path, block: u32, ranges: &[(u64, u64)], total: u64) {
    let mut image = avbtool_rs::sparse::SparseImage::new(block).unwrap();
    let mut cursor = 0u64;
    for &(offset, size) in ranges {
        if offset > cursor {
            image.append_dont_care(offset - cursor).unwrap();
        }
        image
            .append_raw(&vec![0x11u8; size as usize], true)
            .unwrap();
        cursor = offset + size;
    }
    if cursor < total {
        image.append_dont_care(total - cursor).unwrap();
    }
    let out = std::fs::File::create(path).unwrap();
    avbtool_rs::sparse::write_sparse_image(&image, out).unwrap();
}

/// The TB324ZC `dataext` shape: a sparse whole-partition image ships next
/// to the raw fragments the flashing XML actually references. Apply must
/// rebuild it from the post-OTA image instead of letting `--complete`
/// carry the pre-OTA copy through.
#[test]
fn rebuilds_sparse_whole_partition_image_from_fragments() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let out_dir = dir.path().join("out");
    std::fs::create_dir_all(&input).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();

    let block = 4096u64;
    let total = 64 * block;
    let ranges = [
        (0u64, 2 * block),
        (10 * block, 3 * block),
        (60 * block, block),
    ];
    write_sparse_fixture(&input.join("dataext.img"), block as u32, &ranges, total);

    // Post-OTA dense image: every byte distinct from the stale fixture.
    let new_image = dir.path().join("dataext_new.img");
    let dense: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    std::fs::write(&new_image, &dense).unwrap();

    let fragments: Vec<SplitFragment> = ranges
        .iter()
        .enumerate()
        .map(|(i, &(offset, size))| SplitFragment {
            filename: format!("dataext_{}.img", i + 1),
            offset,
            size,
        })
        .collect();

    let rebuilt = regenerate_whole_partition_image(
        &new_image, &fragments, "dataext", total, &input, &out_dir,
    )
    .unwrap();
    assert_eq!(rebuilt.as_deref(), Some("dataext.img"));

    let bytes = std::fs::read(out_dir.join("dataext.img")).unwrap();
    let image = avbtool_rs::sparse::SparseImage::parse(&bytes).unwrap();
    assert_eq!(
        image.image_size(),
        total,
        "logical size must cover the partition"
    );

    // Mapped regions must be exactly the fragment layout, so the rebuilt
    // file stays as small as the vendor's rather than a dense 512 MB blob.
    let mapped: Vec<(u64, u64)> = {
        let mut cursor = 0u64;
        let mut acc = Vec::new();
        for chunk in image.chunks() {
            match chunk {
                avbtool_rs::sparse::SparseChunk::Raw { output_size, .. } => {
                    acc.push((cursor, *output_size));
                    cursor += output_size;
                }
                avbtool_rs::sparse::SparseChunk::Fill { output_size, .. }
                | avbtool_rs::sparse::SparseChunk::DontCare { output_size } => {
                    cursor += output_size;
                }
                _ => {}
            }
        }
        acc
    };
    assert_eq!(
        mapped,
        ranges.to_vec(),
        "raw chunks must match fragment layout"
    );

    // Mapped bytes must come from the post-OTA image, not the stale input.
    let restored = image.to_dense_bytes().unwrap();
    for &(offset, size) in &ranges {
        let a = offset as usize;
        let b = (offset + size) as usize;
        assert_eq!(
            &restored[a..b],
            &dense[a..b],
            "fragment {offset} must be post-OTA data"
        );
    }
}

/// A dense whole-partition sibling is rewritten verbatim, and a partition
/// that ships no combined image leaves the output untouched.
#[test]
fn rebuilds_dense_sibling_and_skips_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let out_dir = dir.path().join("out");
    std::fs::create_dir_all(&input).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();

    let block = 4096u64;
    let total = 4 * block;
    let dense: Vec<u8> = (0..total).map(|i| (i % 97) as u8).collect();
    let new_image = dir.path().join("vm-bootsys_new.img");
    std::fs::write(&new_image, &dense).unwrap();
    std::fs::write(input.join("vm-bootsys.img"), vec![0u8; total as usize]).unwrap();

    let fragments = vec![SplitFragment {
        filename: "vm-bootsys_1.img".to_string(),
        offset: 0,
        size: total,
    }];

    let rebuilt = regenerate_whole_partition_image(
        &new_image,
        &fragments,
        "vm-bootsys",
        total,
        &input,
        &out_dir,
    )
    .unwrap();
    assert_eq!(rebuilt.as_deref(), Some("vm-bootsys.img"));
    assert_eq!(
        std::fs::read(out_dir.join("vm-bootsys.img")).unwrap(),
        dense
    );

    let absent = regenerate_whole_partition_image(
        &new_image,
        &fragments,
        "nosibling",
        total,
        &input,
        &out_dir,
    )
    .unwrap();
    assert!(
        absent.is_none(),
        "no combined image means nothing to rebuild"
    );
    assert!(!out_dir.join("nosibling.img").exists());
}

#[derive(Default)]
struct TestPipelineOps {
    calls: RefCell<Vec<String>>,
    repack_base_inputs: RefCell<Vec<PathBuf>>,
    repack_base_has_rawprogram_xml: RefCell<Vec<bool>>,
    seal_resign_flags: RefCell<Vec<bool>>,
    sealed_input_artifacts: RefCell<Vec<Vec<crate::integrity::ManifestArtifact>>>,
    mutate_stage_input: bool,
}

impl TestPipelineOps {
    fn record(&self, call: impl Into<String>) {
        self.calls.borrow_mut().push(call.into());
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn repack_base_inputs(&self) -> Vec<PathBuf> {
        self.repack_base_inputs.borrow().clone()
    }

    fn repack_base_has_rawprogram_xml(&self) -> Vec<bool> {
        self.repack_base_has_rawprogram_xml.borrow().clone()
    }

    fn seal_resign_flags(&self) -> Vec<bool> {
        self.seal_resign_flags.borrow().clone()
    }

    fn sealed_input_artifacts(&self) -> Vec<Vec<crate::integrity::ManifestArtifact>> {
        self.sealed_input_artifacts.borrow().clone()
    }

    fn mutating_stage_input() -> Self {
        Self {
            mutate_stage_input: true,
            ..Self::default()
        }
    }

    fn maybe_mutate_input(&self, input: &Path) -> anyhow::Result<()> {
        if self.mutate_stage_input {
            fs::write(input.join("source.img"), b"mutated-during-stage")?;
        }
        Ok(())
    }
}

impl PipelineOps for TestPipelineOps {
    fn unpack_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        _events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        self.record("unpack_stage");
        self.maybe_mutate_input(input)?;
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
        input: &Path,
        out_dir: &Path,
        _ota_zips: &[PathBuf],
        force_unpack: bool,
        _scratch_dir: &Path,
        _events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        self.record(format!("apply_stage(force_unpack={force_unpack})"));
        self.maybe_mutate_input(input)?;
        fs::create_dir_all(out_dir)?;
        fs::write(out_dir.join("apply.img"), b"apply")?;
        Ok(())
    }

    fn resign_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        _config: &ResignConfig,
        _events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        self.record("resign_stage");
        self.maybe_mutate_input(input)?;
        fs::create_dir_all(out_dir)?;
        fs::write(out_dir.join("resign.img"), b"resign")?;
        Ok(())
    }

    fn repack_pipeline(
        &self,
        base_input_dir: &Path,
        _image_dir: &Path,
        final_output_dir: &Path,
        _scratch_dir: &Path,
        _events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        self.record("repack_pipeline");
        self.repack_base_inputs
            .borrow_mut()
            .push(base_input_dir.to_path_buf());
        self.repack_base_has_rawprogram_xml
            .borrow_mut()
            .push(base_input_dir.join("rawprogram0.xml").exists());
        fs::create_dir_all(final_output_dir)?;
        fs::write(final_output_dir.join("super_1.img"), b"repack")?;
        Ok(())
    }

    fn repack_stage(
        &self,
        input: &Path,
        out_dir: &Path,
        _events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        self.record("repack_stage");
        self.maybe_mutate_input(input)?;
        fs::create_dir_all(out_dir)?;
        fs::write(out_dir.join("super_1.img"), b"repack")?;
        Ok(())
    }

    fn verify_stage(&self, output_dir: &Path, _events: &mut dyn EventSink) -> anyhow::Result<()> {
        self.record("verify_stage");
        assert!(output_dir.exists());
        Ok(())
    }

    fn finalize_report(&self, _output_dir: &Path) -> anyhow::Result<()> {
        self.record("finalize_report");
        Ok(())
    }

    fn seal_output(
        &self,
        _output_dir: &Path,
        resign_performed: bool,
        input_artifacts: &[crate::integrity::ManifestArtifact],
        _integrity_key: Option<&Path>,
        _events: &mut dyn EventSink,
    ) -> anyhow::Result<()> {
        self.record("seal_output");
        self.seal_resign_flags.borrow_mut().push(resign_performed);
        self.sealed_input_artifacts
            .borrow_mut()
            .push(input_artifacts.to_vec());
        Ok(())
    }
}

#[test]
fn real_pipeline_seal_hashes_report_and_final_artifacts() {
    let temp = tempdir().unwrap();
    fs::write(temp.path().join("boot.img"), b"boot").unwrap();
    fs::write(temp.path().join("report.html"), b"<html>verified</html>").unwrap();
    let mut sink = NoopEventSink;

    RealPipelineOps
        .seal_output(temp.path(), false, &[], None, &mut sink)
        .unwrap();

    let manifest = crate::integrity::read_output_manifest(temp.path()).unwrap();
    assert_eq!(
        manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect::<Vec<_>>(),
        vec!["boot.img", "report.html"]
    );
    assert!(
        crate::integrity::verify_output_manifest(temp.path())
            .unwrap()
            .is_ok()
    );
}

#[test]
fn real_pipeline_resign_seal_excludes_root_abl() {
    let output = tempdir().unwrap();
    fs::write(output.path().join("boot.img"), b"boot").unwrap();
    fs::write(
        output
            .path()
            .join(crate::integrity::RESIGN_EXCLUDED_ROOT_ARTIFACT),
        b"abl",
    )
    .unwrap();
    fs::create_dir_all(output.path().join("nested")).unwrap();
    fs::write(output.path().join("nested").join("abl.elf"), b"nested").unwrap();
    let mut sink = NoopEventSink;

    RealPipelineOps
        .seal_output(output.path(), true, &[], None, &mut sink)
        .unwrap();

    let manifest = crate::integrity::read_output_manifest(output.path()).unwrap();
    assert!(manifest.resign_performed);
    assert_eq!(
        manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect::<Vec<_>>(),
        vec!["boot.img", "nested/abl.elf"]
    );
    assert!(
        crate::integrity::verify_output_manifest(output.path())
            .unwrap()
            .is_ok()
    );
}

#[test]
fn real_pipeline_seal_signs_manifest_when_key_is_configured() {
    let output = tempdir().unwrap();
    fs::write(output.path().join("boot.img"), b"boot").unwrap();
    let keys = tempdir().unwrap();
    let private_key = keys.path().join("integrity.pem");
    let public_key = keys.path().join("integrity.pub.pem");
    crate::integrity_signature::generate_integrity_keypair(&private_key, &public_key).unwrap();
    let mut sink = NoopEventSink;
    let input_artifacts = vec![crate::integrity::ManifestArtifact {
        path: "original/boot.img".to_string(),
        size: 4,
        sha256: crate::avb_descriptor::hex_encode(Sha256::digest(b"boot").as_slice()),
    }];

    RealPipelineOps
        .seal_output(
            output.path(),
            false,
            &input_artifacts,
            Some(&private_key),
            &mut sink,
        )
        .unwrap();

    let signature =
        crate::integrity_signature::verify_output_manifest_signature(output.path(), &[public_key])
            .unwrap();
    assert!(signature.is_trusted(), "{signature:?}");
    assert_eq!(
        crate::integrity::read_output_manifest(output.path())
            .unwrap()
            .input_artifacts,
        input_artifacts
    );
}

fn assert_original_input_was_sealed(input: &Path, ops: &TestPipelineOps) {
    assert_eq!(
        fs::read(input.join("source.img")).unwrap(),
        b"mutated-during-stage"
    );
    let inventories = ops.sealed_input_artifacts();
    assert_eq!(inventories.len(), 1);
    assert_eq!(inventories[0].len(), 1);
    assert_eq!(inventories[0][0].path, "source.img");
    assert_eq!(inventories[0][0].size, b"original-input".len() as u64);
    assert_eq!(
        inventories[0][0].sha256,
        crate::avb_descriptor::hex_encode(Sha256::digest(b"original-input").as_slice())
    );
}

#[test]
fn all_pipeline_flows_capture_original_input_before_stage_mutation() {
    let temp = tempdir().unwrap();

    let unpack_input = temp.path().join("unpack-input");
    fs::create_dir_all(&unpack_input).unwrap();
    fs::write(unpack_input.join("source.img"), b"original-input").unwrap();
    let unpack_ops = TestPipelineOps::mutating_stage_input();
    run_unpack_with_ops(
        &UnpackRequest {
            input: unpack_input.clone(),
            output: temp.path().join("unpack-output"),
            integrity_key: None,
            resign: None,
            repack: true,
            complete: false,
            info: false,
        },
        &mut NoopEventSink,
        &unpack_ops,
    )
    .unwrap();
    assert_original_input_was_sealed(&unpack_input, &unpack_ops);

    let apply_input = temp.path().join("apply-input");
    fs::create_dir_all(&apply_input).unwrap();
    fs::write(apply_input.join("source.img"), b"original-input").unwrap();
    let apply_ops = TestPipelineOps::mutating_stage_input();
    run_apply_with_ops(
        &ApplyRequest {
            input: apply_input.clone(),
            output: temp.path().join("apply-output"),
            integrity_key: None,
            ota_zips: vec![temp.path().join("ota.zip")],
            force_unpack: false,
            resign: None,
            repack: true,
            complete: false,
            info: false,
        },
        &mut NoopEventSink,
        &apply_ops,
    )
    .unwrap();
    assert_original_input_was_sealed(&apply_input, &apply_ops);

    let resign_input = temp.path().join("resign-input");
    fs::create_dir_all(&resign_input).unwrap();
    fs::write(resign_input.join("source.img"), b"original-input").unwrap();
    let resign_ops = TestPipelineOps::mutating_stage_input();
    run_resign_with_ops(
        &ResignRequest {
            input: resign_input.clone(),
            output: temp.path().join("resign-output"),
            integrity_key: None,
            config: sample_resign_config(),
            repack: true,
            info: false,
        },
        &mut NoopEventSink,
        &resign_ops,
    )
    .unwrap();
    assert_original_input_was_sealed(&resign_input, &resign_ops);

    let repack_input = temp.path().join("repack-input");
    fs::create_dir_all(&repack_input).unwrap();
    fs::write(repack_input.join("source.img"), b"original-input").unwrap();
    let repack_ops = TestPipelineOps::mutating_stage_input();
    run_repack_with_ops(
        &RepackRequest {
            input: repack_input.clone(),
            output: temp.path().join("repack-output"),
            integrity_key: None,
        },
        &mut NoopEventSink,
        &repack_ops,
    )
    .unwrap();
    assert_original_input_was_sealed(&repack_input, &repack_ops);
}

#[test]
fn propagated_artifacts_display_final_output_and_keep_user_inputs() {
    let temp = tempdir().unwrap();
    let staged = temp.path().join("dynobox-stage-abc").join("resign_stage");
    let final_output = temp.path().join("final-output");
    fs::create_dir_all(&staged).unwrap();
    fs::create_dir_all(&final_output).unwrap();
    fs::write(
        staged.join("lgsi_features.json"),
        b"{\"ZuiFeature\": false}\n",
    )
    .unwrap();
    fs::write(staged.join("debloat.txt"), b"system:/system/app/Bloat\n").unwrap();
    fs::write(staged.join("blobs.txt"), b"system:/system/app/Bloat\n").unwrap();

    PipelineReport {
        command_line: "dynobox resign".to_string(),
        command_kind: "resign".to_string(),
        started_at: "2026-05-02T10:00:00Z".to_string(),
        finished_at: "2026-05-02T10:01:00Z".to_string(),
        output_dir: staged.display().to_string(),
        resigned_images: vec!["boot.img".to_string()],
        ..Default::default()
    }
    .write(&staged.join("report.html"))
    .unwrap();

    let mut sink = NoopEventSink;
    propagate_resign_artifacts(&staged, &final_output, &mut sink);

    let html = fs::read_to_string(final_output.join("report.html")).unwrap();
    assert!(html.contains("final-output"));
    assert!(!html.contains("resign_stage"));
    assert!(!html.contains("dynobox-stage-abc"));
    assert_eq!(
        fs::read_to_string(final_output.join("lgsi_features.json")).unwrap(),
        "{\"ZuiFeature\": false}\n"
    );
    assert_eq!(
        fs::read_to_string(final_output.join("debloat.txt")).unwrap(),
        "system:/system/app/Bloat\n"
    );
    assert!(!final_output.join("blobs.txt").exists());
}

#[test]
fn propagated_user_inputs_do_not_require_a_report() {
    let temp = tempdir().unwrap();
    let staged = temp.path().join("resign_stage");
    let final_output = temp.path().join("final-output");
    fs::create_dir_all(&staged).unwrap();
    fs::create_dir_all(&final_output).unwrap();
    fs::write(staged.join("lgsi_features.json"), b"{}\n").unwrap();
    fs::write(staged.join("debloat.txt"), b"product:/app/Foo\n").unwrap();

    let mut sink = NoopEventSink;
    propagate_resign_artifacts(&staged, &final_output, &mut sink);

    assert_eq!(
        fs::read_to_string(final_output.join("lgsi_features.json")).unwrap(),
        "{}\n"
    );
    assert_eq!(
        fs::read_to_string(final_output.join("debloat.txt")).unwrap(),
        "product:/app/Foo\n"
    );
}

#[test]
fn debloat_list_input_is_retained_without_a_partition_scan() {
    let temp = tempdir().unwrap();
    let list = temp.path().join("custom-removals.txt");
    let output = temp.path().join("output");
    fs::write(&list, "system:/system/app/Bloat\n").unwrap();
    fs::create_dir_all(&output).unwrap();

    let mut sink = NoopEventSink;
    let mut inode_cache = LocalInodeCache::default();
    let mut dirty_partitions = BTreeMap::new();
    let mut report = PipelineReport::default();
    run_debloat(
        &output,
        &crate::debloat::DebloatMode::ListFile(list),
        &mut sink,
        &mut inode_cache,
        &mut dirty_partitions,
        &mut report,
    )
    .unwrap();

    assert_eq!(
        fs::read_to_string(output.join("debloat.txt")).unwrap(),
        "system:/system/app/Bloat\n"
    );
    assert!(!output.join("blobs.txt").exists());
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
        integrity_key: None,
        ota_zips: vec![temp.path().join("ota1.zip")],
        force_unpack: false,
        resign: None,
        repack: false,
        complete: false,
        info: false,
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
            "finalize_report",
        ]
    );
    assert!(output.exists());
    assert!(
        ops.seal_resign_flags().is_empty(),
        "no manifest is sealed without repack"
    );
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
        integrity_key: None,
        ota_zips: vec![temp.path().join("ota1.zip")],
        force_unpack: false,
        resign: Some(sample_resign_config()),
        repack: false,
        complete: false,
        info: false,
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
            "finalize_report",
        ]
    );
    assert!(output.exists());
    assert!(
        ops.seal_resign_flags().is_empty(),
        "no manifest is sealed without repack"
    );
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
        integrity_key: None,
        ota_zips: vec![temp.path().join("ota1.zip")],
        force_unpack: false,
        resign: None,
        repack: true,
        complete: false,
        info: false,
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
            "finalize_report",
            "seal_output",
        ]
    );
    assert!(output.exists());
    assert_eq!(ops.seal_resign_flags(), vec![false]);
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
        integrity_key: None,
        ota_zips: vec![temp.path().join("ota1.zip"), temp.path().join("ota2.zip")],
        force_unpack: true,
        resign: Some(sample_resign_config()),
        repack: true,
        complete: false,
        info: false,
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
            "finalize_report",
            "seal_output",
        ]
    );
    assert!(output.exists());
    assert_eq!(ops.seal_resign_flags(), vec![true]);
    assert_no_stage_dirs(temp.path());
}

#[test]
fn unpack_repack_uses_decrypted_xml_workspace_as_repack_base() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("input");
    let output = temp.path().join("output_repack");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("rawprogram0.x"), tiny_rawprogram_x()).unwrap();

    let request = UnpackRequest {
        input: input.clone(),
        output: output.clone(),
        integrity_key: None,
        resign: None,
        repack: true,
        complete: false,
        info: false,
    };
    let ops = TestPipelineOps::default();
    let mut sink = NoopEventSink;

    run_unpack_with_ops(&request, &mut sink, &ops).unwrap();

    let base_inputs = ops.repack_base_inputs();
    assert_eq!(base_inputs.len(), 1);
    assert_ne!(base_inputs[0], input);
    assert_eq!(ops.repack_base_has_rawprogram_xml(), vec![true]);
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

#[test]
fn find_split_source_fragments_prefers_unsparse_over_whole_partition_record() {
    // Reproduces the TB320FC `vm-bootsys not found` failure: the sparse
    // manifest lists a single whole-partition `vm-bootsys.img` (absent on
    // disk), while the unsparse manifest lists the real chunk files. The
    // fragment set must come from the unsparse chunks only, otherwise the
    // phantom whole-partition file breaks the caller's all-present check.
    let temp = tempdir().unwrap();
    fs::write(
            temp.path().join("rawprogram4.xml"),
            r#"<?xml version="1.0"?>
<data>
  <program label="vm-bootsys_a" filename="vm-bootsys.img" physical_partition_number="4" start_sector="140266" num_partition_sectors="67109" SECTOR_SIZE_IN_BYTES="4096" />
  <program label="vm-bootsys_b" filename="" physical_partition_number="4" start_sector="406355" num_partition_sectors="67109" SECTOR_SIZE_IN_BYTES="4096" />
</data>"#,
        )
        .unwrap();
    fs::write(
            temp.path().join("rawprogram_unsparse4.xml"),
            r#"<?xml version="1.0"?>
<data>
  <program label="vm-bootsys_a" filename="vm-bootsys_1.img" physical_partition_number="4" start_sector="140266" num_partition_sectors="29725" SECTOR_SIZE_IN_BYTES="4096" />
  <program label="vm-bootsys_a" filename="vm-bootsys_2.img" physical_partition_number="4" start_sector="173034" num_partition_sectors="2" SECTOR_SIZE_IN_BYTES="4096" />
  <program label="vm-bootsys_a" filename="vm-bootsys_3.img" physical_partition_number="4" start_sector="173059" num_partition_sectors="2" SECTOR_SIZE_IN_BYTES="4096" />
  <program label="vm-bootsys_a" filename="vm-bootsys_4.img" physical_partition_number="4" start_sector="173405" num_partition_sectors="32399" SECTOR_SIZE_IN_BYTES="4096" />
  <program label="vm-bootsys_a" filename="vm-bootsys_5.img" physical_partition_number="4" start_sector="206148" num_partition_sectors="17" SECTOR_SIZE_IN_BYTES="4096" />
</data>"#,
        )
        .unwrap();

    let catalog = dynobox_xml::XmlCatalog::from_dir(temp.path()).unwrap();
    let fragments = find_split_source_fragments(&catalog, "vm-bootsys");

    let names: Vec<_> = fragments.iter().map(|f| f.filename.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "vm-bootsys_1.img",
            "vm-bootsys_2.img",
            "vm-bootsys_3.img",
            "vm-bootsys_4.img",
            "vm-bootsys_5.img",
        ],
        "split set must be the unsparse chunks, not the whole-partition file"
    );
    // First chunk is the base; offsets are relative to its start_sector.
    assert_eq!(fragments[0].offset, 0);
    assert_eq!(fragments[0].size, 29725 * 4096);
    assert_eq!(fragments[1].offset, (173034 - 140266) * 4096);
}

#[test]
fn assert_safe_to_wipe_rejects_exact_and_nested_overlap() {
    let base = std::env::temp_dir().join("dynobox_wipe_guard");
    let input = base.join("image");
    // target == protected input
    assert!(assert_safe_to_wipe(&input, &[&input]).is_err());
    // target lives inside protected input
    assert!(assert_safe_to_wipe(&input.join("sub"), &[&input]).is_err());
    // protected input lives inside target
    assert!(assert_safe_to_wipe(&base, &[&input]).is_err());
    // disjoint sibling is allowed
    assert!(assert_safe_to_wipe(&base.join("output"), &[&input]).is_ok());
}

#[test]
fn assert_safe_to_wipe_refuses_unrelated_non_empty_dirs() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("image");
    let out = temp.path().join("out");

    // Missing and empty directories are always fine.
    assert!(assert_safe_to_wipe(&out, &[&input]).is_ok());
    fs::create_dir_all(&out).unwrap();
    assert!(assert_safe_to_wipe(&out, &[&input]).is_ok());

    // Unrelated user data is refused.
    fs::write(out.join("notes.txt"), b"keep me").unwrap();
    let err = assert_safe_to_wipe(&out, &[&input])
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not look like a DynoBox output"), "{err}");

    // A prior DynoBox output (any top-level image / report) is disposable.
    for marker in ["boot.img", "rawprogram_unsparse0.xml", "report.html"] {
        let dir = temp.path().join(format!("prior-{marker}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("notes.txt"), b"x").unwrap();
        fs::write(dir.join(marker), b"x").unwrap();
        assert!(assert_safe_to_wipe(&dir, &[&input]).is_ok(), "{marker}");
    }

    // A regular file is never treated as an output directory.
    let file = temp.path().join("file.bin");
    fs::write(&file, b"x").unwrap();
    assert!(assert_safe_to_wipe(&file, &[&input]).is_err());
}

#[test]
fn assert_safe_to_wipe_refuses_roots_home_and_cwd() {
    let input = std::env::temp_dir().join("dynobox_wipe_anchor_input");
    let cwd = std::env::current_dir().unwrap();
    let root = cwd.ancestors().last().unwrap().to_path_buf();
    assert!(assert_safe_to_wipe(&root, &[&input]).is_err());
    assert!(assert_safe_to_wipe(&cwd, &[&input]).is_err());
    assert!(assert_safe_to_wipe(Path::new("."), &[&input]).is_err());
    if let Some(home) = std::env::home_dir() {
        assert!(assert_safe_to_wipe(&home, &[&input]).is_err());
    }
}

#[test]
fn integrity_private_key_must_not_live_inside_firmware_input() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    let key = input.join("integrity.pem");

    let error = assert_integrity_key_outside_input(Some(&key), &input).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot be copied into the output")
    );
    assert_integrity_key_outside_input(Some(&temp.path().join("keys/key.pem")), &input).unwrap();
}

#[test]
fn integrity_private_key_is_parsed_before_pipeline_mutation() {
    let temp = tempdir().unwrap();
    assert!(validate_integrity_signing_key(None).is_ok());
    assert!(validate_integrity_signing_key(Some(&temp.path().join("missing.pem"))).is_err());

    let private_key = temp.path().join("integrity.pem");
    let public_key = temp.path().join("integrity.pub.pem");
    crate::integrity_signature::generate_integrity_keypair(&private_key, &public_key).unwrap();
    validate_integrity_signing_key(Some(&private_key)).unwrap();
}

#[cfg(windows)]
#[test]
fn assert_safe_to_wipe_is_case_insensitive_on_windows() {
    // `C:\...\Image` and `C:\...\image` name the same directory on
    // Windows; the guard must catch the overlap despite the case
    // difference, otherwise `remove_dir_all` could wipe the input.
    let protected = std::env::temp_dir()
        .join("dynobox_wipe_guard_case")
        .join("Image");
    let target = std::env::temp_dir()
        .join("dynobox_wipe_guard_case")
        .join("image");
    assert!(
        assert_safe_to_wipe(&target, &[&protected]).is_err(),
        "case-differing path to the same dir must be refused"
    );
}

#[test]
fn secondary_protected_paths_cover_ota_key_lgsi_debloat_and_plus() {
    let temp = tempdir().unwrap();
    let ota = temp.path().join("nested").join("ota.zip");
    let key = temp.path().join("keys").join("custom.pem");
    let lgsi = temp.path().join("cfg").join("lgsi.json");
    let debloat = temp.path().join("lists").join("debloat.txt");
    let plus = temp.path().join("patches").join("fix.dbp");
    // Nested under a proposed output — the wipe guard must refuse.
    let output = temp.path().join("nested");

    let resign = ResignConfig {
        key: key.display().to_string(),
        algorithm: None,
        force: false,
        rollback_index: None,
        boot_spl: None,
        vendor_spl: None,
        system_spl: None,
        fuck_lgsi: Some(FuckLgsiMode::Config(lgsi.clone())),
        debloat: Some(crate::debloat::DebloatMode::ListFile(debloat.clone())),
        add_overlay: Vec::new(),
        plus: vec![plus.clone()],
    };
    let secondary =
        collect_secondary_protected_paths(Some(std::slice::from_ref(&ota)), Some(&resign));
    assert!(secondary.iter().any(|p| p == &ota));
    assert!(secondary.iter().any(|p| p == &key));
    assert!(secondary.iter().any(|p| p == &lgsi));
    assert!(secondary.iter().any(|p| p == &debloat));
    assert!(secondary.iter().any(|p| p == &plus));

    let mut refs: Vec<&Path> = vec![];
    refs.extend(secondary.iter().map(PathBuf::as_path));
    // Nested OTA under output must be refused.
    let err = assert_safe_to_wipe(&output, &refs).unwrap_err().to_string();
    assert!(
        err.contains("lives inside") || err.contains("protected"),
        "expected nested OTA refusal, got: {err}"
    );
    // Nested config under output likewise.
    let nested_cfg_out = temp.path().join("cfg");
    let err = assert_safe_to_wipe(&nested_cfg_out, &refs)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("lives inside") || err.contains("protected"),
        "expected nested LGSI config refusal, got: {err}"
    );
    // Disjoint output is fine.
    assert!(assert_safe_to_wipe(&temp.path().join("out"), &refs).is_ok());
}

#[test]
fn secondary_protected_paths_ignore_embedded_testkey_names() {
    let resign = sample_resign_config();
    let secondary = collect_secondary_protected_paths(None, Some(&resign));
    assert!(
        secondary.is_empty(),
        "embedded testkey names must not be treated as filesystem paths: {secondary:?}"
    );
}

#[test]
fn ota_digest_validation_starts_distinct_progress_after_apply_reaches_total() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("system.img");
    let data = vec![0x5au8; 2 * 1024 * 1024 + 17];
    fs::write(&path, &data).unwrap();
    let digest = Sha256::digest(&data).to_vec();
    let logical_size = data.len() as u64;
    let verify_item = "system: verify OTA target digest";
    let mut events = vec![ProgressEvent::ItemProgress {
        stage: StageKind::Apply,
        item: "system".to_string(),
        done: logical_size,
        total: logical_size,
        unit: ProgressUnit::Bytes,
    }];

    {
        let mut sink = |event| events.push(event);
        validate_partition_image_digest_with_event_progress(
            &mut sink,
            OtaDigestProgress {
                current: 2,
                total: 5,
                item: verify_item,
            },
            &path,
            logical_size,
            &digest,
            "new partition `system`",
            PartitionSizePolicy::Exact,
        )
        .unwrap();
    }

    assert!(matches!(
        &events[1],
        ProgressEvent::ItemStarted {
            stage: StageKind::Apply,
            current: 2,
            total: 5,
            item,
        } if item == verify_item
    ));
    let verification_ticks = events[2..]
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::ItemProgress {
                stage: StageKind::Apply,
                item,
                done,
                total,
                unit: ProgressUnit::Bytes,
            } if item == verify_item => Some((*done, *total)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(verification_ticks.first(), Some(&(0, logical_size)));
    assert_eq!(
        verification_ticks.last(),
        Some(&(logical_size, logical_size))
    );
    assert!(
        verification_ticks
            .windows(2)
            .all(|pair| pair[0].0 <= pair[1].0)
    );
}

#[test]
fn validate_partition_image_digest_accepts_match_and_shorter_source() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("part.img");
    let data = b"hello-payload-partition";
    fs::write(&path, data).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize().to_vec();

    validate_partition_image_digest(
        &path,
        data.len() as u64,
        &digest,
        "new partition `test`",
        PartitionSizePolicy::Exact,
    )
    .unwrap();

    // Shorter on-disk image: hash logical size > file size with trailing zeros.
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(&[0u8; 8]);
    let padded = hasher.finalize().to_vec();
    validate_partition_image_digest(
        &path,
        data.len() as u64 + 8,
        &padded,
        "old partition `test`",
        PartitionSizePolicy::AllowSourceContainer,
    )
    .unwrap();
}

#[test]
fn validate_partition_image_digest_size_only_metadata() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("part.img");
    fs::write(&path, b"abc").unwrap();

    // Fully absent metadata (size 0 + empty hash) is a no-op.
    validate_partition_image_digest(
        &path,
        0,
        &[],
        "old partition `x`",
        PartitionSizePolicy::Exact,
    )
    .unwrap();

    // Size-only: empty hash but declared size must still be enforced.
    validate_partition_image_digest(
        &path,
        3,
        &[],
        "new partition `x`",
        PartitionSizePolicy::Exact,
    )
    .unwrap();
    let err = validate_partition_image_digest(
        &path,
        4,
        &[],
        "new partition `x`",
        PartitionSizePolicy::Exact,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("exact logical size"),
        "expected exact size error for size-only metadata, got: {err}"
    );

    // Size-only with AllowSourceContainer accepts shorter sources.
    validate_partition_image_digest(
        &path,
        8,
        &[],
        "old partition `x`",
        PartitionSizePolicy::AllowSourceContainer,
    )
    .unwrap();

    // Size-only longer container is accepted regardless of tail contents.
    let mut longer = b"abc".to_vec();
    longer.extend_from_slice(&[0u8; 4]);
    longer.push(0x5a);
    fs::write(&path, &longer).unwrap();
    validate_partition_image_digest(
        &path,
        3,
        &[],
        "old partition `x`",
        PartitionSizePolicy::AllowSourceContainer,
    )
    .unwrap();
}

#[test]
fn validate_partition_image_digest_longer_zero_tail_accepted() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("part.img");
    let mut bytes = b"payload-data".to_vec();
    let logical = bytes.len() as u64;
    bytes.extend_from_slice(&[0u8; 16]); // physical zero padding past logical size
    fs::write(&path, &bytes).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&bytes[..logical as usize]);
    let digest = hasher.finalize().to_vec();

    validate_partition_image_digest(
        &path,
        logical,
        &digest,
        "old partition `test`",
        PartitionSizePolicy::AllowSourceContainer,
    )
    .unwrap();

    // Size-only longer zero tail is also accepted.
    validate_partition_image_digest(
        &path,
        logical,
        &[],
        "old partition `test`",
        PartitionSizePolicy::AllowSourceContainer,
    )
    .unwrap();
}

#[test]
fn validate_partition_image_digest_longer_nonzero_tail_ignored() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("part.img");
    let mut bytes = b"payload-data".to_vec();
    let logical = bytes.len() as u64;
    bytes.extend_from_slice(&[0u8; 8]);
    bytes.push(0x5a); // non-zero container tail (e.g. Qualcomm MELF trailer)
    fs::write(&path, &bytes).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&bytes[..logical as usize]);
    let digest = hasher.finalize().to_vec();

    // Hash covers only the logical prefix; non-zero tail is ignored.
    validate_partition_image_digest(
        &path,
        logical,
        &digest,
        "old partition `test`",
        PartitionSizePolicy::AllowSourceContainer,
    )
    .unwrap();

    // Size-only longer non-zero container tail is also accepted.
    validate_partition_image_digest(
        &path,
        logical,
        &[],
        "old partition `test`",
        PartitionSizePolicy::AllowSourceContainer,
    )
    .unwrap();
}

#[test]
fn validate_partition_image_digest_target_size_mismatch() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("part.img");
    fs::write(&path, b"abcd").unwrap();

    // Exact policy rejects both shorter and longer targets.
    let err = validate_partition_image_digest(
        &path,
        8,
        &[],
        "new partition `x`",
        PartitionSizePolicy::Exact,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("exact logical size"),
        "expected shorter exact mismatch, got: {err}"
    );

    let mut bytes = b"abcd".to_vec();
    bytes.extend_from_slice(&[0u8; 4]);
    fs::write(&path, &bytes).unwrap();
    let err = validate_partition_image_digest(
        &path,
        4,
        &[],
        "new partition `x`",
        PartitionSizePolicy::Exact,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("exact logical size"),
        "expected longer exact mismatch, got: {err}"
    );
}

#[test]
fn validate_partition_image_digest_rejects_mismatch_and_malformed() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("part.img");
    fs::write(&path, b"abc").unwrap();

    // Non-empty hash with zero logical size is malformed.
    let err = validate_partition_image_digest(
        &path,
        0,
        &[0u8; 32],
        "old partition `x`",
        PartitionSizePolicy::Exact,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("malformed PartitionInfo metadata"),
        "expected hash-without-size rejection, got: {err}"
    );

    // Malformed digest length.
    let err = validate_partition_image_digest(
        &path,
        3,
        &[0u8; 16],
        "old partition `x`",
        PartitionSizePolicy::Exact,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("malformed digest length"),
        "expected malformed digest error, got: {err}"
    );

    // Mismatch.
    let err = validate_partition_image_digest(
        &path,
        3,
        &[0u8; 32],
        "new partition `x`",
        PartitionSizePolicy::Exact,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("SHA-256 mismatch"),
        "expected mismatch error, got: {err}"
    );
}

#[test]
fn ota_digest_verification_checks_source_only_after_target_failure() {
    let mut checks = Vec::new();
    verify_target_before_source(true, |kind| {
        checks.push(kind);
        Ok(())
    })
    .unwrap();
    assert_eq!(checks, vec![OtaPartitionDigest::Target]);

    let mut checks = Vec::new();
    let error = verify_target_before_source(true, |kind| {
        checks.push(kind);
        match kind {
            OtaPartitionDigest::Target => anyhow::bail!("target mismatch"),
            OtaPartitionDigest::Source => Ok(()),
        }
    })
    .unwrap_err();
    assert_eq!(
        checks,
        vec![OtaPartitionDigest::Target, OtaPartitionDigest::Source]
    );
    assert!(format!("{error:#}").contains("target mismatch"));

    let mut checks = Vec::new();
    let error = verify_target_before_source(true, |kind| {
        checks.push(kind);
        match kind {
            OtaPartitionDigest::Target => anyhow::bail!("target mismatch"),
            OtaPartitionDigest::Source => anyhow::bail!("source mismatch"),
        }
    })
    .unwrap_err();
    assert_eq!(
        checks,
        vec![OtaPartitionDigest::Target, OtaPartitionDigest::Source]
    );
    let error = format!("{error:#}");
    assert!(error.contains("source mismatch"));
    assert!(error.contains("target mismatch"));
}

#[test]
fn find_owning_vbmeta_returns_none_when_absent() {
    let temp = tempdir().unwrap();
    // Empty dir → true absence.
    let result = find_owning_vbmeta(temp.path(), "system").unwrap();
    assert!(result.is_none());

    // Non-vbmeta files only.
    fs::write(temp.path().join("system.img"), b"not-vbmeta").unwrap();
    let result = find_owning_vbmeta(temp.path(), "system").unwrap();
    assert!(result.is_none());
}

#[test]
fn find_owning_vbmeta_propagates_missing_dir_error() {
    let temp = tempdir().unwrap();
    let missing = temp.path().join("does-not-exist");
    let err = find_owning_vbmeta(&missing, "system")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("failed to enumerate") || err.contains("looking for owning vbmeta"),
        "expected read_dir error, got: {err}"
    );
}

#[test]
fn collect_resignable_images_propagates_missing_dir() {
    let temp = tempdir().unwrap();
    let missing = temp.path().join("nope");
    let err = collect_resignable_images(&missing).unwrap_err().to_string();
    assert!(
        err.contains("failed to enumerate resign input"),
        "expected enumerate error, got: {err}"
    );
}

fn sample_resign_config() -> ResignConfig {
    ResignConfig {
        key: "testkey_rsa2048".to_string(),
        algorithm: Some("SHA256_RSA2048".to_string()),
        force: false,
        rollback_index: None,
        boot_spl: None,
        vendor_spl: None,
        system_spl: None,
        fuck_lgsi: None,
        debloat: None,
        add_overlay: Vec::new(),
        plus: Vec::new(),
    }
}

fn tiny_rawprogram_x() -> &'static [u8] {
    &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x26, 0x87, 0x5e, 0x30, 0x61, 0xa3, 0x72, 0x11, 0x01, 0xba, 0xed, 0x99, 0x14,
        0x29, 0x4a, 0x4f, 0x71, 0x7d, 0xfb, 0xfe, 0xa2, 0xa3, 0x34, 0xb6, 0xfc, 0x3a, 0xa9, 0x1d,
        0xbb, 0x38, 0x03, 0x21, 0x50, 0x0c, 0x0a, 0x65, 0x53, 0x3d, 0xe5, 0x95, 0x09, 0x70, 0x48,
        0x70, 0xce, 0x44, 0x3c, 0x6b, 0x4a, 0x04, 0x70, 0x9b, 0x7b, 0xd4, 0x9d, 0xa6, 0x5a, 0xd0,
        0xe3, 0x94, 0x40, 0x32, 0x78, 0x50,
    ]
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

/// OEM rawprogram files sometimes declare the split-super chunks under the
/// logical partition names instead of `super_*.img` (e.g. ALLDOCUBE U880).
/// The repack stage must stage those declared chunks so the metadata chunk
/// survives, while the patched standalone image wins for the data ones.
#[test]
fn prepare_repack_stage_copies_declared_super_chunks_with_partition_names() {
    let temp = tempdir().unwrap();
    let base = temp.path().join("base");
    let images = temp.path().join("images");
    let stage = temp.path().join("stage");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&images).unwrap();
    fs::write(
            base.join("rawprogram_all.xml"),
            r#"<?xml version="1.0"?>
<data>
  <program label="super" filename="super_empty.img" start_sector="8712" num_partition_sectors="99" SECTOR_SIZE_IN_BYTES="4096" />
  <program label="super" filename="system.img" start_sector="8968" num_partition_sectors="100" SECTOR_SIZE_IN_BYTES="4096" />
</data>"#,
        )
        .unwrap();
    fs::write(base.join("super_empty.img"), vec![0u8; 99 * 4096]).unwrap();
    fs::write(base.join("system.img"), vec![1u8; 100 * 4096]).unwrap();
    // The apply output carries the patched standalone system image, which
    // no longer matches the chunk record's size.
    fs::write(images.join("system.img"), vec![2u8; 200 * 4096]).unwrap();

    let stats = prepare_repack_stage(&base, &images, &stage).unwrap();
    assert_eq!(stats.xml_count, 1);
    assert_eq!(stats.super_count, 2, "both declared chunks must be staged");
    assert_eq!(fs::read(stage.join("super_empty.img")).unwrap()[0], 0);
    assert_eq!(
        fs::read(stage.join("system.img")).unwrap()[0],
        2,
        "the patched standalone image must replace the stale chunk copy"
    );
}

/// `--complete --repack` must not copy the input's stale super chunks back
/// into an output whose super was just regenerated under different names.
#[test]
fn complete_output_skips_repacked_super_chunks() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("in");
    let output = temp.path().join("out");
    fs::create_dir_all(&input).unwrap();
    fs::create_dir_all(&output).unwrap();
    fs::write(
            input.join("rawprogram_all.xml"),
            r#"<?xml version="1.0"?>
<data>
  <program label="super" filename="system.img" start_sector="0" num_partition_sectors="1" SECTOR_SIZE_IN_BYTES="4096" />
</data>"#,
        )
        .unwrap();
    fs::write(input.join("system.img"), b"stale-chunk").unwrap();
    fs::write(input.join("super_1.img"), b"stale-chunk").unwrap();
    fs::write(input.join("boot.img"), b"boot").unwrap();

    let mut sink = NoopEventSink;
    complete_output_from_input(&input, &output, true, &mut sink).unwrap();
    assert!(
        !output.join("system.img").exists(),
        "declared chunk must be skipped after repack"
    );
    assert!(
        !output.join("super_1.img").exists(),
        "super_* must be skipped"
    );
    assert_eq!(fs::read(output.join("boot.img")).unwrap(), b"boot");

    // Without `--repack` the input is mirrored verbatim (minus `.x`).
    let plain = temp.path().join("out-plain");
    fs::create_dir_all(&plain).unwrap();
    complete_output_from_input(&input, &plain, false, &mut sink).unwrap();
    assert!(plain.join("system.img").exists());
    assert!(plain.join("super_1.img").exists());
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
