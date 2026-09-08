//! `--info`: read-only inventory of unpacked super partitions.
//!
//! Writes two files into the pipeline output directory:
//! * `blobs.txt` — every file/directory path found in the unpacked super
//!   partition images, one per line as `partition:/absolute/path`
//!   (same `partition:/path` format `--debloat` consumes).
//! * `lgsi_features.json` — `{feature_name -> enabled}` object map parsed
//!   from the OEM `lgsi_build_info*.html` manifest inside `product.img`
//!   (`/etc/lgsi_build_info*.html`; the exact filename varies by build).
//!
//! Both steps are read-only: no ext4 mutation, no dm-verity regen, no AVB
//! re-sign. Missing inputs are warned and skipped, never fatal — a pipeline
//! with `--info` still succeeds when e.g. `product.img` is absent or carries
//! no LGSI manifest.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::events::{EventSink, MessageLevel, ProgressEvent};
use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume};

/// Catalog of every blob path, in `--debloat` list format.
pub const INFO_BLOBS_NAME: &str = "blobs.txt";
/// Per-feature Enabled map, same shape as `--fuck-lgsi` workspace JSON.
pub const INFO_FEATURES_NAME: &str = "lgsi_features.json";

/// Outcome of an `--info` dump. `None` counts mean that artifact was skipped
/// (warned) because its source was missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoOutcome {
    /// Number of ext4 partition images successfully scanned.
    pub partitions: usize,
    /// Total `partition:/path` lines written to `blobs.txt` (`None` when skipped).
    pub blob_lines: Option<usize>,
    /// Number of LGSI features written to `lgsi_features.json` (`None` when skipped).
    pub features: Option<usize>,
    /// Actual HTML filename matched inside `product.img:/etc/`.
    pub html_name: Option<String>,
}

fn message<S: EventSink + ?Sized>(events: &mut S, level: MessageLevel, text: String) {
    events.emit(ProgressEvent::Message { level, text });
}

/// Scan `source_dir` for partition images and write `blobs.txt` +
/// `lgsi_features.json` into `dest_dir` (usually the same directory, or the
/// final pipeline output when the images live in a temp stage dir).
pub fn dump_info<S>(source_dir: &Path, dest_dir: &Path, events: &mut S) -> Result<InfoOutcome>
where
    S: EventSink + ?Sized,
{
    // 1. blobs.txt — same scan as `--debloat`, but the catalog is kept.
    // Standalone partition images are the final pipeline state; super
    // container chunks coexisting with them are stale input copies (e.g.
    // carried in by `--complete`) and must not be inventoried. Only when
    // no standalone image scans (e.g. a repack-only output) do the chunks
    // themselves become the final state and get scanned as a fallback.
    let mut blob_lines: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let entries = std::fs::read_dir(source_dir)
        .with_context(|| format!("reading {} for --info scan", source_dir.display()))?;
    let mut img_paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|x| x.to_str()) == Some("img"))
        .collect();
    img_paths.sort();
    let (standalone, chunks) = split_super_chunks(&img_paths);
    scan_images(&standalone, &mut blob_lines, &mut scanned);
    if scanned == 0 && !chunks.is_empty() {
        message(
            events,
            MessageLevel::Info,
            "--info: no standalone partition images; scanning super chunks.".to_string(),
        );
        scan_images(&chunks, &mut blob_lines, &mut scanned);
    }

    let blob_count = if scanned == 0 {
        message(
            events,
            MessageLevel::Warning,
            "--info: no supported ext4 partitions; skipped blobs.txt.".to_string(),
        );
        None
    } else {
        let blobs_path = dest_dir.join(INFO_BLOBS_NAME);
        std::fs::write(&blobs_path, format!("{}\n", blob_lines.join("\n")))
            .with_context(|| format!("writing {}", blobs_path.display()))?;
        message(
            events,
            MessageLevel::Info,
            format!(
                "--info: wrote `{}` ({} path(s), {} partition(s)).",
                blobs_path.display(),
                blob_lines.len(),
                scanned
            ),
        );
        Some(blob_lines.len())
    };

    // 2. lgsi_features.json — parse product.img:/etc/lgsi_build_info*.html.
    let (features, html_name) = match dump_lgsi_features(source_dir, dest_dir, events)? {
        Some((count, name)) => (Some(count), Some(name)),
        None => (None, None),
    };

    Ok(InfoOutcome {
        partitions: scanned,
        blob_lines: blob_count,
        features,
        html_name,
    })
}

/// Scan `paths` (already sorted) for ext4 partition listings, appending
/// `stem:/absolute/path` lines to `blob_lines` and counting successes in
/// `scanned`. Unparseable files (boot/vbmeta/erofs/packed super) are skipped.
fn scan_images(paths: &[&PathBuf], blob_lines: &mut Vec<String>, scanned: &mut usize) {
    for path in paths {
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        match crate::debloat::list_partition_paths(path) {
            Ok(paths) => {
                *scanned += 1;
                for p in paths {
                    blob_lines.push(format!("{stem}:{p}"));
                }
            }
            Err(_) => continue,
        }
    }
}

/// Split image paths into standalone partition images and super container
/// chunks (`super.img`, `super_*.img`). See [`dump_info`] for why the chunks
/// are only a fallback source.
fn split_super_chunks(img_paths: &[PathBuf]) -> (Vec<&PathBuf>, Vec<&PathBuf>) {
    let mut standalone = Vec::new();
    let mut chunks = Vec::new();
    for path in img_paths {
        let is_chunk = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_super_chunk_file_name);
        if is_chunk {
            chunks.push(path);
        } else {
            standalone.push(path);
        }
    }
    (standalone, chunks)
}

fn is_super_chunk_file_name(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower == "super.img" || (lower.starts_with("super_") && lower.ends_with(".img"))
}

fn dump_lgsi_features<S>(
    source_dir: &Path,
    dest_dir: &Path,
    events: &mut S,
) -> Result<Option<(usize, String)>>
where
    S: EventSink + ?Sized,
{
    let product_path = source_dir.join("product.img");
    if !product_path.exists() {
        message(
            events,
            MessageLevel::Warning,
            "--info: product.img not found; skipped lgsi_features.json.".to_string(),
        );
        return Ok(None);
    }
    let (html_bytes, html_name) = match read_lgsi_build_info_html_flexible(&product_path)? {
        Some(found) => found,
        None => {
            message(
                events,
                MessageLevel::Warning,
                "--info: no lgsi_build_info*.html in product.img:/etc/; skipped lgsi_features.json."
                    .to_string(),
            );
            return Ok(None);
        }
    };
    let html_features = crate::fuck_lgsi::html_parser::parse_lgsi_html(&html_bytes)
        .context("failed to parse lgsi_build_info.html")?;
    let json_path = dest_dir.join(INFO_FEATURES_NAME);
    let mut map = serde_json::Map::new();
    for f in &html_features {
        map.insert(f.name.clone(), serde_json::Value::Bool(f.enabled));
    }
    let pretty = serde_json::to_string_pretty(&serde_json::Value::Object(map))
        .context("Failed to serialise lgsi_features.json")?;
    std::fs::write(&json_path, pretty)
        .with_context(|| format!("writing {}", json_path.display()))?;
    message(
        events,
        MessageLevel::Info,
        format!(
            "--info: wrote `{}` ({} feature(s) from {html_name}).",
            json_path.display(),
            html_features.len(),
        ),
    );
    Ok(Some((html_features.len(), html_name)))
}

/// Read the first `lgsi_build_info*.html` file under `product.img:/etc/`.
/// Returns the raw bytes plus the matched filename, or `None` when `/etc`
/// holds no such file. Errors only on I/O or an unreadable ext4 volume.
fn read_lgsi_build_info_html_flexible(product_image: &Path) -> Result<Option<(Vec<u8>, String)>> {
    let mut volume = open_ext4_volume(product_image)?;
    let etc_inode = match lookup_inode_at_path(&mut volume, &["etc"])? {
        Some(inode) if inode.is_dir() => inode,
        _ => return Ok(None),
    };
    let entries = etc_inode
        .open_dir(&mut volume)
        .map_err(|e| anyhow::anyhow!("failed to list /etc in product.img: {e}"))?;
    let mut candidates: Vec<String> = entries
        .into_iter()
        .map(|(name, _, _)| name)
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower.starts_with("lgsi_build_info") && lower.ends_with(".html")
        })
        .collect();
    candidates.sort();
    let Some(matched) = candidates.into_iter().next() else {
        return Ok(None);
    };
    let inode = match lookup_inode_at_path(&mut volume, &["etc", matched.as_str()])? {
        Some(inode) => inode,
        None => return Ok(None),
    };
    if !inode.is_file() {
        return Ok(None);
    }
    let (bytes, _) = inode
        .open_read_with_extents(&mut volume)
        .map_err(|e| anyhow::anyhow!("failed to read /etc/{matched} from product.img: {e}"))?;
    Ok(Some((bytes, matched)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::NoopEventSink;

    #[test]
    fn dump_info_on_empty_dir_warns_and_writes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let dest = temp.path().join("dest");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&dest).unwrap();

        let mut sink = NoopEventSink;
        let outcome = dump_info(&source, &dest, &mut sink).unwrap();
        assert_eq!(outcome.partitions, 0);
        assert_eq!(outcome.blob_lines, None);
        assert_eq!(outcome.features, None);
        assert!(!dest.join(INFO_BLOBS_NAME).exists());
        assert!(!dest.join(INFO_FEATURES_NAME).exists());
    }

    #[test]
    fn super_chunk_file_names_are_classified_case_insensitively() {
        for name in ["super.img", "super_1.img", "super_10.img", "SUPER_2.IMG"] {
            assert!(is_super_chunk_file_name(name), "{name} should be a chunk");
        }
        for name in [
            "system.img",
            "super.img.bak",
            "superior.img",
            "my_super_1.img",
            "super",
        ] {
            assert!(
                !is_super_chunk_file_name(name),
                "{name} should not be a chunk"
            );
        }
    }

    #[test]
    fn split_super_chunks_separates_standalone_images_from_chunks() {
        let paths = vec![
            PathBuf::from("system.img"),
            PathBuf::from("super_2.img"),
            PathBuf::from("super.img"),
            PathBuf::from("vendor.img"),
        ];
        let (standalone, chunks) = split_super_chunks(&paths);
        let names = |group: &[&PathBuf]| {
            group
                .iter()
                .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&standalone), vec!["system.img", "vendor.img"]);
        assert_eq!(names(&chunks), vec!["super_2.img", "super.img"]);
    }
}
