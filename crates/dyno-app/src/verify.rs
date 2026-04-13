use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::events::{EventSink, MessageLevel, ProgressEvent, StageKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VerificationFailureKind {
    Input,
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
    let mut report = VerificationReport {
        input: input.to_path_buf(),
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

    if report.image_file_count > 0 {
        let scan_entries = dynobox_avb::info::scan_input(input)?;
        report.avb_image_count = scan_entries
            .iter()
            .filter(|entry| matches!(entry.result, dynobox_avb::info::ScanResult::Avb(_)))
            .count();
        report
            .failures
            .extend(scan_entries.iter().filter_map(|entry| match &entry.result {
                dynobox_avb::info::ScanResult::Error(message) => Some(VerificationFailure {
                    kind: VerificationFailureKind::Avb,
                    path: Some(entry.path.clone()),
                    message: message.clone(),
                }),
                _ => None,
            }));
    }

    if report.super_chunk_count > 0 && report.rawprogram_xml_count == 0 {
        report.failures.push(VerificationFailure {
            kind: VerificationFailureKind::Xml,
            path: Some(input.to_path_buf()),
            message: "Found split super chunks but no rawprogram XML files.".to_string(),
        });
        return Ok(report);
    }

    if report.rawprogram_xml_count > 0 {
        match dynobox_xml::XmlCatalog::from_dir(input) {
            Ok(catalog) => {
                if let Some(super_group) = catalog.group_by_base_label(true).remove("super") {
                    let records: Vec<_> = super_group.records().into_iter().cloned().collect();
                    match dynobox_super::parse_super_layout(&records, input) {
                        Ok(layout) => {
                            let mut dynamic_partition_names = layout.dynamic_partition_names();
                            dynamic_partition_names.sort();
                            report.super_layout = Some(SuperLayoutSummary {
                                chunk_count: layout.chunks.len(),
                                dynamic_partition_count: dynamic_partition_names.len(),
                                dynamic_partition_names,
                            });
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

    Ok(report)
}

pub fn render_verification_report(report: &VerificationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Verification target:    {}", report.input.display());
    let _ = writeln!(
        out,
        "Status:                 {}",
        if report.is_clean() { "OK" } else { "FAILED" }
    );
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

    let report = verify_input(input)?;
    emit_verification_messages(&report, events);
    ensure_verification_clean(&report)?;

    events.emit(ProgressEvent::StageCompleted {
        stage: StageKind::Verify,
    });
    Ok(())
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

    use tempfile::{NamedTempFile, tempdir};

    use super::{VerificationFailureKind, render_verification_report, verify_input};

    #[test]
    fn verify_image_only_directory_is_clean() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("dummy.img"), b"not-avb").unwrap();

        let report = verify_input(temp.path()).unwrap();

        assert!(report.is_clean());
        assert_eq!(report.image_file_count, 1);
        assert_eq!(report.avb_image_count, 0);
        assert!(report.super_layout.is_none());
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
}
