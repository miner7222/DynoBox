//! Pipeline-end HTML report.
//!
//! `run_resign_stage` collects per-mutation before/after records into a
//! [`PipelineReport`] and writes it to `<out>/report.html` after the
//! resign loop finishes. It remains marked as pending until the final
//! pipeline verification succeeds. The report is a self-contained, no-JS,
//! no-CDN HTML page summarising every state change the stage made.
//!
//! The layout is decision-first: status, action-required warnings, run
//! metrics, and a collapsed command drawer come before the audit tables.
//! Large tables use native `<details>` so the default document stays short
//! while `Ctrl+F`, print-to-PDF, and the full audit trail keep working.
//!
//! Read-only stages (`info`, `verify`, `unpack`, `repack`, plus
//! `apply` without resign) intentionally skip the report — there's
//! nothing to summarise.

use std::fmt::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

#[derive(Debug, Clone, Default)]
pub struct PipelineReport {
    pub command_line: String,
    pub command_kind: String,
    pub started_at: String,
    pub finished_at: String,
    pub started_unix: u64,
    pub finished_unix: u64,
    pub output_dir: String,
    pub resigned_images: Vec<String>,
    pub boot_spl: Option<SplRecord>,
    pub vendor_spl: Option<SplRecord>,
    pub system_spl: Option<SplRecord>,
    pub rollback: Option<RollbackRecord>,
    pub lgsi: Option<LgsiRecord>,
    pub signing_key_change: Option<SigningKeyChange>,
    pub debloat: Option<DebloatRecord>,
    pub overlay: Option<OverlayRecord>,
    pub spoof: Option<SpoofRecord>,
    pub plus: Option<PlusRecord>,
}

/// `--plus` summary: one entry per applied `.dbp` patch, plus the verity
/// root-digest change of each partition its ops touched.
#[derive(Debug, Clone)]
pub struct PlusRecord {
    pub patches: Vec<PlusPatchRecord>,
    /// `(partition, old_root_digest, new_root_digest)` for each partition
    /// whose dm-verity was regenerated. Back-filled by the deferred pass.
    pub verity: Vec<(String, String, String)>,
}

#[derive(Debug, Clone)]
pub struct PlusPatchRecord {
    /// `name` field from the `.dbp` document.
    pub name: String,
    /// Source `.dbp` file (basename).
    pub source: String,
    pub files: Vec<PlusFileRecord>,
}

#[derive(Debug, Clone)]
pub struct PlusFileRecord {
    pub partition: String,
    /// Path of the matched target inside the partition image. A record with
    /// zero applied ops means the file existed but no exact patch site landed.
    pub file: String,
    pub ops_applied: usize,
    pub ops_skipped: usize,
    pub patched_entries: Vec<String>,
}

/// `--debloat` summary: one row per partition whose ext4 tree had entries
/// hidden, plus the verity root-digest change.
#[derive(Debug, Clone)]
pub struct DebloatRecord {
    pub partitions: Vec<DebloatPartition>,
}

#[derive(Debug, Clone)]
pub struct DebloatPartition {
    pub partition: String,
    pub removed: usize,
    pub not_found: usize,
    pub old_root_digest: String,
    pub new_root_digest: String,
}

/// `--add-overlay` summary: the static RRO APKs inserted into a partition's
/// overlay directory, plus the verity root-digest change.
#[derive(Debug, Clone)]
pub struct OverlayRecord {
    pub partition: String,
    pub files: Vec<OverlayFileRecord>,
    pub old_root_digest: String,
    pub new_root_digest: String,
}

#[derive(Debug, Clone)]
pub struct OverlayFileRecord {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub inode: u32,
    pub blocks: u32,
}

/// `--add-spoof` summary: the payload inserted into system.img, the executable
/// dependencies that load it, and the legacy init cleanup.
#[derive(Debug, Clone, Default)]
pub struct SpoofRecord {
    pub partition: String,
    pub files: Vec<SpoofFileRecord>,
    pub apps: usize,
    pub props: usize,
    pub loaders: Vec<SpoofLoaderRecord>,
    pub init_path: String,
    pub init_outcome: String,
    pub old_root_digest: String,
    pub new_root_digest: String,
}

/// One executable that maps the preload through its own `DT_NEEDED` list.
#[derive(Debug, Clone)]
pub struct SpoofLoaderRecord {
    /// Path inside the partition image, e.g. `system/bin/app_process64`.
    pub path: String,
    pub outcome: String,
}

#[derive(Debug, Clone)]
pub struct SpoofFileRecord {
    /// Path inside the partition image, e.g. `system/lib64/libspoof.so`.
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub inode: u32,
    pub blocks: u32,
}

#[derive(Debug, Clone)]
pub struct SplRecord {
    /// Property key being patched (e.g.
    /// `com.android.build.boot.security_patch`).
    pub property: String,
    pub from: Option<String>,
    pub to: String,
    pub applied: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RollbackRecord {
    pub from_unix: u64,
    pub to_unix: u64,
    pub from_iso: String,
    pub to_iso: String,
    pub applied: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct LgsiRecord {
    pub applied: Vec<LgsiChange>,
    pub skipped: Vec<LgsiSkip>,
    pub old_root_digest: String,
    pub new_root_digest: String,
}

#[derive(Debug, Clone)]
pub struct LgsiChange {
    pub name: String,
    pub from: bool,
    pub to: bool,
}

#[derive(Debug, Clone)]
pub struct LgsiSkip {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct SigningKeyChange {
    pub old_pubkey_sha1: String,
    pub new_pubkey_sha1: String,
}

impl PipelineReport {
    pub fn new(command_kind: impl Into<String>, output_dir: &Path) -> Self {
        let command_line = std::env::args()
            .map(|argument| redact_command_argument(&argument))
            .collect::<Vec<_>>()
            .join(" ");
        Self {
            command_line,
            command_kind: command_kind.into(),
            started_at: now_iso8601(),
            started_unix: now_unix(),
            finished_at: String::new(),
            finished_unix: 0,
            output_dir: output_dir.display().to_string(),
            ..Default::default()
        }
    }

    pub fn finish(&mut self) {
        self.finished_at = now_iso8601();
        self.finished_unix = now_unix();
    }

    /// Whether the report contains anything worth writing to disk. Used
    /// by callers to skip the file write when no mutating stage ran.
    pub fn has_content(&self) -> bool {
        !self.resigned_images.is_empty()
            || self.boot_spl.is_some()
            || self.vendor_spl.is_some()
            || self.system_spl.is_some()
            || self.rollback.is_some()
            || self.lgsi.is_some()
            || self.signing_key_change.is_some()
            || self.debloat.is_some()
            || self.overlay.is_some()
            || self.spoof.is_some()
            || self.plus.is_some()
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let html = self.render_html();
        std::fs::write(path, html)
            .with_context(|| format!("Failed to write pipeline report to {}", path.display()))?;
        Ok(())
    }

    pub fn render_html(&self) -> String {
        let mut out = String::with_capacity(16 * 1024);
        out.push_str(HTML_HEADER);
        out.push_str("<main id='top'>\n");

        push_header(&mut out);

        if let Some(signing_key) = &self.signing_key_change {
            push_signing_key_callout(&mut out, signing_key);
        }

        push_kpi_strip(&mut out, self);
        push_command_drawer(&mut out, &self.command_line);
        push_section_nav(&mut out, self);

        let spl_records = [
            ("boot.img", self.boot_spl.as_ref()),
            ("vendor.img", self.vendor_spl.as_ref()),
            ("system.img", self.system_spl.as_ref()),
        ];
        if spl_records.iter().any(|(_, record)| record.is_some()) {
            push_spl_section(&mut out, &spl_records);
        }
        if let Some(rollback) = &self.rollback {
            push_rollback_section(&mut out, rollback);
        }
        if let Some(debloat) = &self.debloat {
            push_debloat_section(&mut out, debloat);
        }
        if let Some(spoof) = &self.spoof {
            push_spoof_section(&mut out, spoof);
        }
        if let Some(plus) = &self.plus {
            push_plus_section(&mut out, plus);
        }
        if let Some(lgsi) = &self.lgsi {
            push_lgsi_section(&mut out, lgsi);
        }
        if let Some(overlay) = &self.overlay {
            push_overlay_section(&mut out, overlay);
        }
        push_resigned_section(&mut out, &self.resigned_images);

        out.push_str("</main>\n");
        out.push_str(HTML_FOOTER);
        out
    }
}

const HTML_HEADER: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DynoBox pipeline report</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #172033;
      --ink-2: #344054;
      --muted: #5d6878;
      --faint: #98a2b3;
      --line: #d8dee8;
      --line-2: #eaecf0;
      --surface: #ffffff;
      --surface-2: #f8fafc;
      --canvas: #edf1f6;
      --accent: #165dcc;
      --accent-bg: #edf4ff;
      --accent-line: #bfd6ff;
      --ok: #116139;
      --ok-bg: #e9f7ef;
      --ok-line: #a6e0bd;
      --warn: #7a4900;
      --warn-bg: #fff6e0;
      --warn-line: #e6b84d;
      --danger: #b42318;
      --danger-bg: #fef3f2;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body { margin: 0; padding: 24px 16px; background: var(--canvas); color: var(--ink); font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width: 1080px; margin: 0 auto; padding: 32px 36px; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; }
    h1, h2, h3 { margin: 0; color: var(--ink); text-wrap: balance; }
    h1 { font-size: clamp(1.5rem, 3vw, 2rem); line-height: 1.15; letter-spacing: -0.02em; }
    h2 { font-size: 1rem; line-height: 1.3; font-weight: 700; }
    p { margin: 0; }
    a { color: var(--accent); }

    .report-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding-bottom: 20px; border-bottom: 1px solid var(--line); }
    .product { margin: 0 0 4px; color: var(--accent); font-size: 0.78rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
    .status { margin: 2px 0 0; padding: 5px 12px; color: var(--ok); background: var(--ok-bg); border: 1px solid var(--ok-line); border-radius: 999px; font-size: 0.8rem; font-weight: 700; white-space: nowrap; }
    .status::before { content: "✓ "; }
    .status.pending { color: var(--warn); background: var(--warn-bg); border-color: var(--warn-line); }
    .status.pending::before { content: "! "; }

    .callout-warning { margin-top: 16px; padding: 14px 16px; background: var(--warn-bg); border: 1px solid var(--warn-line); border-left: 4px solid #d9822b; border-radius: 8px; scroll-margin-top: 96px; }
    .callout-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .callout-head h2 { color: var(--warn); }
    .callout-body { margin-top: 6px; color: #5c3700; font-size: 0.9rem; }
    .key-diff { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; }
    .key-diff code { display: block; margin-top: 3px; font-size: 0.78rem; overflow-wrap: anywhere; }

    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 16px; }
    .kpi-card { min-width: 0; padding: 12px 14px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 8px; }
    .kpi-label { display: block; margin-bottom: 4px; color: var(--muted); font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }
    .kpi-value { display: block; font-size: 1.02rem; font-weight: 700; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
    .kpi-sub { display: block; margin-top: 3px; color: var(--muted); font-size: 0.76rem; overflow-wrap: anywhere; }
    .kpi-sub.num-warn { color: var(--warn); font-weight: 600; }

    .cmd-drawer { margin-top: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); }
    .cmd-summary { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 12px; padding: 10px 14px; cursor: pointer; list-style: none; user-select: none; }
    .cmd-summary::-webkit-details-marker { display: none; }
    .cmd-chips { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; min-width: 0; }
    .cmd-label { margin-right: 2px; color: var(--muted); font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }
    .cmd-chip { padding: 2px 7px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 4px; font-size: 0.76rem; overflow-wrap: anywhere; }
    .cmd-chip-count { background: var(--accent-bg); border-color: var(--accent-line); color: var(--accent); font-weight: 600; }
    .cmd-toggle-hint { margin-left: auto; color: var(--accent); font-size: 0.76rem; font-weight: 600; white-space: nowrap; }
    .cmd-drawer[open] .when-closed, .cmd-drawer:not([open]) .when-open { display: none; }
    .cmd-raw { margin: 0; padding: 12px 14px; border-top: 1px solid var(--line); background: #f4f6f9; max-height: 280px; overflow: auto; user-select: all; white-space: pre-wrap; word-break: break-all; font-size: 0.78rem; line-height: 1.45; }

    .sec-nav { position: sticky; top: 0; z-index: 10; display: flex; flex-wrap: wrap; gap: 6px; margin-top: 16px; padding: 10px 0; background: rgba(255, 255, 255, 0.94); backdrop-filter: blur(6px); border-bottom: 1px solid var(--line); }
    .nav-chip { display: inline-flex; align-items: center; gap: 5px; padding: 4px 10px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 999px; color: var(--ink-2); text-decoration: none; font-size: 0.76rem; font-weight: 600; }
    .nav-chip:hover, .nav-chip:focus-visible { border-color: var(--accent); color: var(--accent); }
    .nav-chip.has-warn { background: var(--warn-bg); border-color: var(--warn-line); color: var(--warn); }
    .chip-count { color: var(--muted); font-weight: 400; font-variant-numeric: tabular-nums; }
    .nav-chip.has-warn .chip-count { color: var(--warn); }

    .sec-card { margin-top: 16px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); scroll-margin-top: 96px; }
    .sec-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px; background: var(--surface-2); border-radius: 8px; cursor: pointer; list-style: none; user-select: none; }
    .sec-header::-webkit-details-marker { display: none; }
    .sec-card[open] > .sec-header { border-bottom: 1px solid var(--line); border-radius: 8px 8px 0 0; }
    .sec-title-group { display: flex; align-items: baseline; gap: 10px; min-width: 0; }
    .sec-title { font-size: 1rem; }
    .sec-sub { color: var(--muted); font-size: 0.8rem; }
    .sec-caret { width: 14px; flex: none; color: var(--muted); }
    .sec-caret::before { content: "▸"; display: inline-block; transition: transform 0.15s ease; }
    .sec-card[open] > .sec-header .sec-caret::before { transform: rotate(90deg); }
    details.sec-card:target > .sec-header .sec-caret::before { transform: rotate(90deg); }
    .sec-badges { display: flex; flex-wrap: wrap; align-items: center; justify-content: flex-end; gap: 6px; }
    .sec-body { padding: 12px 16px 16px; }

    .badge { padding: 2px 8px; border-radius: 999px; font-size: 0.72rem; font-weight: 700; font-variant-numeric: tabular-nums; white-space: nowrap; }
    .badge-neutral { background: #eef2f6; color: var(--ink-2); }
    .badge-ok { background: var(--ok-bg); color: var(--ok); }
    .badge-warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn-line); }
    .badge-info { background: var(--accent-bg); color: var(--accent); }

    .tbl-wrap { width: 100%; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
    th, td { padding: 6px 10px; border-bottom: 1px solid var(--line-2); text-align: left; vertical-align: middle; }
    th { color: var(--muted); background: var(--surface-2); border-bottom: 1px solid var(--line); font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; white-space: nowrap; }
    th:first-child, td:first-child { padding-left: 4px; }
    th:last-child, td:last-child { padding-right: 4px; }
    tbody tr:last-child td { border-bottom: 0; }
    tbody tr:hover { background: #f8fafd; }
    tr.row-warn, tr.row-warn:hover { background: #fffcf2; }
    .col-num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
    .col-hash { font-family: "Cascadia Mono", "SFMono-Regular", Consolas, monospace; font-size: 0.72rem; letter-spacing: -0.01em; white-space: nowrap; user-select: all; color: var(--ink-2); }
    .col-path { min-width: 180px; word-break: break-word; overflow-wrap: break-word; }
    .fs-meta { color: var(--muted); font-size: 0.76rem; white-space: nowrap; }
    .group-row th { padding: 10px 6px 6px; background: #f1f5f9; color: var(--ink); font-size: 0.84rem; border-top: 1px solid var(--line); text-transform: none; letter-spacing: 0; }
    .group-row:first-child th { border-top: 0; }
    .group-row th .badge { margin-left: 6px; background: var(--surface); border: 1px solid var(--line); }

    code, .mono { font-family: "Cascadia Mono", "SFMono-Regular", Consolas, monospace; font-size: 0.9em; }
    .val-before { color: var(--muted); }
    .val-after { color: var(--ink); font-weight: 600; }
    .change-pill { display: inline-block; padding: 1px 7px; border-radius: 4px; font-family: "Cascadia Mono", "SFMono-Regular", Consolas, monospace; font-size: 0.78rem; white-space: nowrap; }
    .change-pill.is-enabled { background: var(--accent-bg); color: var(--accent); border: 1px solid var(--accent-line); }
    .change-pill.is-disabled { background: #f2f4f7; color: var(--ink-2); }
    .num-applied { color: var(--ok); font-weight: 700; }
    .num-warn { color: var(--warn); font-weight: 700; }
    .num-zero, .empty { color: var(--faint); font-weight: 400; }
    .muted { color: var(--muted); }

    .meta-list { display: grid; gap: 6px; margin-bottom: 10px; }
    .meta-row { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 10px; align-items: baseline; }
    .meta-label { color: var(--muted); font-size: 0.72rem; font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase; }
    .meta-value { min-width: 0; overflow-wrap: anywhere; font-size: 0.86rem; }
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin: 10px 0; }
    .meta-grid > div { display: flex; flex-direction: column; gap: 2px; min-width: 0; }

    .file-chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .file-chip { padding: 2px 8px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 4px; font-size: 0.8rem; }
    .cli-block { margin: 10px 0 0; padding: 10px 12px; background: #f4f6f9; border: 1px solid var(--line); border-radius: 6px; font-size: 0.82rem; overflow-x: auto; }
    .section-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
    #output-integrity { margin-top: 16px; padding: 16px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); scroll-margin-top: 96px; }
    .empty-state { color: var(--muted); font-size: 0.86rem; }

    summary:focus-visible, a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
    /* No-JS anchor navigation: reveal a collapsed section when it is targeted. */
    details.sec-card:target > *:not(summary) { display: block; }
    details.sec-card:target::details-content { content-visibility: visible; }

    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      .sec-caret::before { transition: none; }
    }

    @media (max-width: 768px) {
      body { padding: 0; }
      main { border: 0; border-radius: 0; padding: 20px 16px; }
      .report-header { gap: 10px; }
      .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .kpi-card:first-child { grid-column: 1 / -1; }
      .kpi-value, .kpi-sub { white-space: normal; overflow-wrap: anywhere; }
      .sec-header { flex-wrap: wrap; }
      .sec-badges { justify-content: flex-start; }
      .sec-nav { flex-wrap: nowrap; overflow-x: auto; }
      .nav-chip { flex: none; }
      .key-diff { grid-template-columns: 1fr; }
      .meta-row { grid-template-columns: 1fr; gap: 2px; }
      .cmd-summary { align-items: flex-start; }
      .cmd-toggle-hint { margin-left: 0; }
      table { min-width: 100%; }
    }

    @media print {
      html { scroll-behavior: auto; }
      body { padding: 0; background: #fff; font-size: 11px; }
      main { max-width: 100%; border: 0; border-radius: 0; padding: 0; }
      .sec-nav, .cmd-toggle-hint { display: none !important; }
      details::details-content { content-visibility: visible !important; }
      details > *:not(summary) { display: block !important; }
      .sec-card { break-inside: auto; }
      .callout-warning, .kpi-grid, .cmd-drawer { break-inside: avoid; }
      thead { display: table-header-group; }
      tr { break-inside: avoid; }
      a { color: inherit; text-decoration: none; }
      .sec-header { cursor: default; }
      .cmd-raw { max-height: none; }
    }
  </style>
</head>
<body>
"#;

const HTML_FOOTER: &str = r#"</body>
</html>
"#;

const OUTPUT_DIR_MARKER_START: &str = "<span data-report-output>";
const OUTPUT_DIR_MARKER_END: &str = "</span>";
const VERIFICATION_STATUS_PENDING: &str =
    "<p class='status pending' data-report-verification>Pending verification</p>";
const VERIFICATION_STATUS_VERIFIED_PREFIX: &str =
    "<p class='status' data-report-verification data-verified-at='";

fn output_integrity_section() -> String {
    let generator = esc(&crate::integrity::dynobox_generator_version());
    format!(
        r#"<section id='output-integrity' data-integrity-schema='dynobox.output_manifest' data-hash-algorithm='sha-256' data-generator='{generator}'>
<div class="section-heading"><h2>Output integrity</h2><span class="badge badge-ok">SHA-256 sealed</span></div>
<div class="meta-grid">
<div><span class="meta-label">Generator</span><span class="meta-value"><code>DynoBox {generator}</code></span></div>
<div><span class="meta-label">Manifest</span><span class="meta-value"><code>dynobox-manifest.json</code></span></div>
<div><span class="meta-label">Signature</span><span class="meta-value"><code>dynobox-manifest.sig</code></span></div>
<div><span class="meta-label">Policy</span><span class="meta-value"><code>abl.elf</code> excluded when resign runs</span></div>
</div>
<p class="empty-state">A successful pipeline seals every tracked final output file, including this report, in <code>dynobox-manifest.json</code>. When a dedicated integrity key is configured, <code>dynobox-manifest.sig</code> authenticates those exact manifest bytes.</p>
<pre class="cli-block"><code>dynobox verify --input &lt;output&gt;</code></pre>
</section>
"#
    )
}

/// Mark an existing pipeline report as verified after every output mutation
/// and the final AVB/XML/super verification have completed. Missing reports
/// are expected for workflows which did not run a mutating resign stage.
pub(crate) fn finalize_verified_report(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }

    let html = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read pipeline report from {}", path.display()))?;
    if html.contains(VERIFICATION_STATUS_VERIFIED_PREFIX) {
        return Ok(true);
    }
    if !html.contains(VERIFICATION_STATUS_PENDING) {
        anyhow::bail!(
            "Pipeline report at {} has no recognized verification marker",
            path.display()
        );
    }

    let verified_at = now_iso8601();
    let verified = format!(
        "{VERIFICATION_STATUS_VERIFIED_PREFIX}{}'>Verified</p>",
        esc(&verified_at)
    );
    let finalized = html.replacen(VERIFICATION_STATUS_PENDING, &verified, 1);
    let finalized = finalized.replacen(
        "</main>",
        &format!("{}</main>", output_integrity_section()),
        1,
    );
    std::fs::write(path, finalized)
        .with_context(|| format!("Failed to finalize pipeline report at {}", path.display()))?;
    Ok(true)
}

/// Replace the staging output shown in a rendered report with the final
/// pipeline output after repack has completed.
pub(crate) fn rewrite_report_output_dir(html: &str, output_dir: &Path) -> String {
    let Some(marker_start) = html.find(OUTPUT_DIR_MARKER_START) else {
        return html.to_string();
    };
    let value_start = marker_start + OUTPUT_DIR_MARKER_START.len();
    let Some(marker_end) = html[value_start..].find(OUTPUT_DIR_MARKER_END) else {
        return html.to_string();
    };
    let value_end = value_start + marker_end;
    let output_dir = output_dir.to_string_lossy();
    let output_name = esc(display_name(&output_dir));

    let mut rewritten =
        String::with_capacity(html.len() - (value_end - value_start) + output_name.len());
    rewritten.push_str(&html[..value_start]);
    rewritten.push_str(&output_name);
    rewritten.push_str(&html[value_end..]);
    rewritten
}

fn push_header(out: &mut String) {
    out.push_str("<header class='report-header'>\n");
    out.push_str("<div><p class='product'>DynoBox</p><h1>Pipeline report</h1></div>\n");
    out.push_str(VERIFICATION_STATUS_PENDING);
    out.push_str("\n</header>\n");
}

fn push_signing_key_callout(out: &mut String, change: &SigningKeyChange) {
    out.push_str("<section class=\"callout-warning\" id=\"sec-signing-key\" aria-labelledby=\"signing-key-title\">\n");
    out.push_str("<div class=\"callout-head\"><h2 id=\"signing-key-title\">Signing key changed</h2><span class=\"badge badge-warn\">! Action required</span></div>\n");
    out.push_str(
        "<p class=\"callout-body\">Use an <code>abl.elf</code> that trusts the new key.</p>\n",
    );
    out.push_str("<div class=\"key-diff\">\n");
    out.push_str("<div><span class=\"meta-label\">OEM key</span><code class=\"val-before\">");
    out.push_str(&esc(&change.old_pubkey_sha1));
    out.push_str("</code></div>\n");
    out.push_str("<div><span class=\"meta-label\">New key</span><code class=\"val-after\">");
    out.push_str(&esc(&change.new_pubkey_sha1));
    out.push_str("</code></div>\n");
    out.push_str("</div>\n</section>\n");
}

fn push_kpi_strip(out: &mut String, report: &PipelineReport) {
    out.push_str("<section class=\"kpi-grid\" aria-label=\"Run summary\">\n");

    let stage = if report.command_kind.is_empty() {
        "resign".to_string()
    } else {
        report.command_kind.clone()
    };

    out.push_str("<div class=\"kpi-card\"><span class=\"kpi-label\">Output</span><span class=\"kpi-value mono\">");
    out.push_str(OUTPUT_DIR_MARKER_START);
    out.push_str(&esc(display_name(&report.output_dir)));
    out.push_str(OUTPUT_DIR_MARKER_END);
    out.push_str("</span><span class=\"kpi-sub\">Stage: ");
    out.push_str(&esc(&stage));
    out.push_str("</span></div>\n");

    let finished = if report.finished_at.is_empty() {
        "—".to_string()
    } else {
        report.finished_at.replace('T', " ")
    };
    let duration = if report.started_unix > 0 && report.finished_unix >= report.started_unix {
        Some(report.finished_unix - report.started_unix)
    } else {
        None
    };
    out.push_str("<div class=\"kpi-card\"><span class=\"kpi-label\">Completed</span><span class=\"kpi-value\">");
    out.push_str(&esc(&finished));
    out.push_str("</span><span class=\"kpi-sub\">");
    if let Some(seconds) = duration {
        out.push_str("Resign stage · ");
        out.push_str(&esc(&format_duration(seconds)));
    } else {
        out.push_str("Resign stage");
    }
    out.push_str("</span></div>\n");

    let lgsi_applied = report.lgsi.as_ref().map_or(0, |l| l.applied.len());
    let debloat_hidden = report
        .debloat
        .as_ref()
        .map_or(0, |d| d.partitions.iter().map(|p| p.removed).sum());
    let overlays = report.overlay.as_ref().map_or(0, |o| o.files.len());
    let spoof_files = report.spoof.as_ref().map_or(0, |s| s.files.len());
    let system_changes = lgsi_applied + debloat_hidden + overlays + spoof_files;
    out.push_str("<div class=\"kpi-card\"><span class=\"kpi-label\">System changes</span><span class=\"kpi-value\">");
    let _ = write!(out, "{system_changes} items");
    out.push_str("</span><span class=\"kpi-sub\">");
    let mut parts = Vec::new();
    if lgsi_applied > 0 {
        parts.push(format!("{lgsi_applied}\u{00A0}LGSI"));
    }
    if debloat_hidden > 0 {
        parts.push(format!("{debloat_hidden}\u{00A0}debloat"));
    }
    if overlays > 0 {
        parts.push(format!("{overlays}\u{00A0}overlays"));
    }
    if spoof_files > 0 {
        parts.push(format!("{spoof_files}\u{00A0}spoof"));
    }
    if parts.is_empty() {
        out.push_str("No system changes");
    } else {
        out.push_str(&esc(&parts.join(" · ")));
    }
    out.push_str("</span></div>\n");

    let (plus_applied, plus_skipped, plus_packages) = plus_totals(report.plus.as_ref());
    out.push_str("<div class=\"kpi-card\"><span class=\"kpi-label\">Plus patches</span><span class=\"kpi-value\">");
    if report.plus.is_some() {
        let _ = write!(out, "{plus_applied} applied");
    } else {
        out.push('—');
    }
    out.push_str("</span><span class=\"kpi-sub");
    if plus_skipped > 0 {
        out.push_str(" num-warn");
    }
    out.push_str("\">");
    if report.plus.is_some() {
        let _ = write!(out, "{plus_packages} packages · {plus_skipped} skipped");
    } else {
        out.push_str("No .dbp patches");
    }
    out.push_str("</span></div>\n");

    let key_changed = report.signing_key_change.is_some();
    out.push_str("<div class=\"kpi-card\"><span class=\"kpi-label\">Signed &amp; integrity</span><span class=\"kpi-value\">");
    if report.resigned_images.is_empty() {
        out.push('—');
    } else {
        let _ = write!(out, "{} images", report.resigned_images.len());
    }
    out.push_str("</span><span class=\"kpi-sub");
    if key_changed {
        out.push_str(" num-warn");
    }
    out.push_str("\">");
    if key_changed {
        out.push_str("! Key changed · sealed");
    } else if report.resigned_images.is_empty() {
        out.push_str("No resigned images");
    } else {
        out.push_str("Manifest sealed");
    }
    out.push_str("</span></div>\n");

    out.push_str("</section>\n");
}

fn plus_totals(plus: Option<&PlusRecord>) -> (usize, usize, usize) {
    let Some(plus) = plus else {
        return (0, 0, 0);
    };
    let applied = plus
        .patches
        .iter()
        .flat_map(|patch| &patch.files)
        .map(|file| file.ops_applied)
        .sum();
    let skipped = plus
        .patches
        .iter()
        .flat_map(|patch| &patch.files)
        .map(|file| file.ops_skipped)
        .sum();
    (applied, skipped, plus.patches.len())
}

fn push_command_drawer(out: &mut String, command_line: &str) {
    let redacted = redact_command_line(command_line);
    let summary = summarize_command(&redacted);
    out.push_str("<details class=\"cmd-drawer\">\n<summary class=\"cmd-summary\">\n<div class=\"cmd-chips\">\n");
    out.push_str("<span class=\"cmd-label\">Command</span>\n");

    let mut chips = 0usize;
    if !summary.program.is_empty() {
        out.push_str("<code class=\"cmd-chip\">");
        out.push_str(&esc(&summary.program));
        if let Some(subcommand) = &summary.subcommand {
            out.push(' ');
            out.push_str(&esc(subcommand));
        }
        out.push_str("</code>\n");
        chips += 1;
    }
    for positional in &summary.positionals {
        if chips >= COMMAND_CHIP_LIMIT {
            break;
        }
        out.push_str("<code class=\"cmd-chip\">");
        out.push_str(&esc(positional));
        out.push_str("</code>\n");
        chips += 1;
    }
    for flag in &summary.flags {
        if chips >= COMMAND_CHIP_LIMIT {
            break;
        }
        if flag.count > 1 {
            out.push_str("<span class=\"cmd-chip cmd-chip-count\">");
            out.push_str(&esc(&flag.name));
            let _ = write!(out, " ×{}", flag.count);
            out.push_str("</span>\n");
        } else {
            out.push_str("<code class=\"cmd-chip\">");
            out.push_str(&esc(&flag.name));
            if let Some(value) = &flag.value {
                out.push(' ');
                out.push_str(&esc(value));
            }
            out.push_str("</code>\n");
        }
        chips += 1;
    }
    let hidden = summary.chip_count().saturating_sub(chips);
    if hidden > 0 {
        let _ = writeln!(out, "<span class=\"cmd-chip\">+{hidden} more</span>");
    }

    out.push_str("</div>\n<span class=\"cmd-toggle-hint\"><span class=\"when-closed\">Show full command</span><span class=\"when-open\">Hide full command</span> (");
    let _ = write!(out, "{}", summary.chars);
    out.push_str(" chars)</span>\n</summary>\n<pre class=\"cmd-raw mono\"><code>");
    out.push_str(&esc(&redacted));
    out.push_str("</code></pre>\n</details>\n");
}

const COMMAND_CHIP_LIMIT: usize = 14;

struct CommandSummary {
    program: String,
    subcommand: Option<String>,
    flags: Vec<CommandFlag>,
    positionals: Vec<String>,
    chars: usize,
}

impl CommandSummary {
    fn chip_count(&self) -> usize {
        let program = usize::from(!self.program.is_empty());
        program + self.positionals.len() + self.flags.len()
    }
}

struct CommandFlag {
    name: String,
    value: Option<String>,
    count: usize,
}

fn summarize_command(command_line: &str) -> CommandSummary {
    let tokens: Vec<&str> = command_line.split_whitespace().collect();
    let mut program = String::new();
    let mut subcommand = None;
    let mut flags: Vec<CommandFlag> = Vec::new();
    let mut positionals = Vec::new();
    let mut index = 0usize;

    if let Some(first) = tokens.first() {
        program = (*first).to_string();
        index = 1;
    }
    if index < tokens.len() && !tokens[index].starts_with('-') {
        subcommand = Some(tokens[index].to_string());
        index += 1;
    }

    while index < tokens.len() {
        let token = tokens[index];
        if token.starts_with('-') {
            let (name, value) = if let Some(rest) = token.strip_prefix("--") {
                match rest.split_once('=') {
                    Some((name, value)) => (format!("--{name}"), Some(value.to_string())),
                    None => {
                        let next = tokens.get(index + 1).copied();
                        if let Some(next) = next.filter(|next| !next.starts_with('-')) {
                            index += 1;
                            (format!("--{rest}"), Some(next.to_string()))
                        } else {
                            (format!("--{rest}"), None)
                        }
                    }
                }
            } else {
                (token.to_string(), None)
            };

            if let Some(existing) = flags.iter_mut().find(|flag| flag.name == name) {
                existing.count += 1;
                if existing.value.is_none() {
                    existing.value = value;
                }
            } else {
                flags.push(CommandFlag {
                    name,
                    value,
                    count: 1,
                });
            }
        } else {
            positionals.push(token.to_string());
        }
        index += 1;
    }

    CommandSummary {
        program,
        subcommand,
        flags,
        positionals,
        chars: command_line.chars().count(),
    }
}

struct NavChip {
    id: &'static str,
    label: &'static str,
    count: Option<String>,
    warn: bool,
}

fn push_section_nav(out: &mut String, report: &PipelineReport) {
    let mut chips: Vec<NavChip> = Vec::new();

    if report.signing_key_change.is_some() {
        chips.push(NavChip {
            id: "sec-signing-key",
            label: "Signing key",
            count: Some("changed".to_string()),
            warn: true,
        });
    }

    let spl_count = [
        report.boot_spl.as_ref(),
        report.vendor_spl.as_ref(),
        report.system_spl.as_ref(),
    ]
    .iter()
    .filter(|record| record.is_some())
    .count();
    if spl_count > 0 {
        chips.push(NavChip {
            id: "sec-spl",
            label: "Security patch",
            count: Some(spl_count.to_string()),
            warn: false,
        });
    }
    if report.rollback.is_some() {
        chips.push(NavChip {
            id: "sec-rollback",
            label: "Rollback index",
            count: Some("1".to_string()),
            warn: false,
        });
    }
    if let Some(debloat) = &report.debloat {
        let hidden: usize = debloat.partitions.iter().map(|p| p.removed).sum();
        let not_found: usize = debloat.partitions.iter().map(|p| p.not_found).sum();
        chips.push(NavChip {
            id: "sec-debloat",
            label: "Debloat",
            count: Some(if not_found > 0 {
                format!("{hidden} hidden · {not_found} missing")
            } else {
                format!("{hidden} hidden")
            }),
            warn: not_found > 0,
        });
    }
    if let Some(spoof) = &report.spoof {
        chips.push(NavChip {
            id: "sec-spoof",
            label: "Per-app spoof",
            count: Some(format!("{} files", spoof.files.len())),
            warn: false,
        });
    }
    if let Some(plus) = &report.plus {
        let (_, skipped, packages) = plus_totals(Some(plus));
        chips.push(NavChip {
            id: "sec-plus",
            label: "Plus patches",
            count: Some(if skipped > 0 {
                format!("{packages} pkgs · {skipped} skipped")
            } else {
                format!("{packages} pkgs")
            }),
            warn: skipped > 0,
        });
    }
    if let Some(lgsi) = &report.lgsi {
        chips.push(NavChip {
            id: "sec-lgsi",
            label: "LGSI features",
            count: Some(if lgsi.skipped.is_empty() {
                lgsi.applied.len().to_string()
            } else {
                format!("{} · {} skipped", lgsi.applied.len(), lgsi.skipped.len())
            }),
            warn: !lgsi.skipped.is_empty(),
        });
    }
    if let Some(overlay) = &report.overlay {
        chips.push(NavChip {
            id: "sec-overlays",
            label: "Added overlays",
            count: Some(overlay.files.len().to_string()),
            warn: false,
        });
    }
    if !report.resigned_images.is_empty() {
        chips.push(NavChip {
            id: "sec-signed",
            label: "Signed images",
            count: Some(report.resigned_images.len().to_string()),
            warn: false,
        });
    }
    chips.push(NavChip {
        id: "output-integrity",
        label: "Integrity",
        count: None,
        warn: false,
    });

    out.push_str("<nav class=\"sec-nav\" aria-label=\"Report sections\">\n");
    for chip in &chips {
        out.push_str("<a class=\"nav-chip");
        if chip.warn {
            out.push_str(" has-warn");
        }
        out.push_str("\" href=\"#");
        out.push_str(chip.id);
        out.push_str("\">");
        out.push_str(&esc(chip.label));
        if let Some(count) = &chip.count {
            out.push_str(" <span class=\"chip-count\">");
            out.push_str(&esc(count));
            out.push_str("</span>");
        }
        out.push_str("</a>\n");
    }
    out.push_str("<a class=\"nav-chip\" href=\"#top\">Top</a>\n</nav>\n");
}

struct SectionShell {
    id: &'static str,
    title: &'static str,
    subtitle: Option<String>,
    badges: Vec<(String, &'static str)>,
    open: bool,
}

fn push_section_open(out: &mut String, shell: &SectionShell) {
    out.push_str("<details class=\"sec-card\" id=\"");
    out.push_str(shell.id);
    out.push('"');
    if shell.open {
        out.push_str(" open");
    }
    out.push_str(">\n<summary class=\"sec-header\">\n<div class=\"sec-title-group\">\n<span class=\"sec-caret\" aria-hidden=\"true\"></span>\n<h2 class=\"sec-title\">");
    out.push_str(&esc(shell.title));
    out.push_str("</h2>\n");
    if let Some(subtitle) = &shell.subtitle {
        out.push_str("<span class=\"sec-sub\">");
        out.push_str(&esc(subtitle));
        out.push_str("</span>\n");
    }
    out.push_str("</div>\n<div class=\"sec-badges\">\n");
    for (text, class) in &shell.badges {
        out.push_str("<span class=\"badge ");
        out.push_str(class);
        out.push_str("\">");
        out.push_str(&esc(text));
        out.push_str("</span>\n");
    }
    out.push_str("</div>\n</summary>\n<div class=\"sec-body\">\n");
}

fn push_section_close(out: &mut String) {
    out.push_str("</div>\n</details>\n");
}

fn push_spl_section(out: &mut String, records: &[(&str, Option<&SplRecord>)]) {
    let present: Vec<_> = records
        .iter()
        .filter_map(|(image, record)| record.map(|record| (*image, record)))
        .collect();
    let applied = present.iter().filter(|(_, record)| record.applied).count();
    let skipped = present.len() - applied;
    let mut badges = Vec::new();
    if applied > 0 {
        badges.push((format!("✓ {applied} applied"), "badge-ok"));
    }
    if skipped > 0 {
        badges.push((format!("! {skipped} skipped"), "badge-warn"));
    }
    push_section_open(
        out,
        &SectionShell {
            id: "sec-spl",
            title: "Security patch",
            subtitle: Some("Security patch level per image".to_string()),
            badges,
            open: true,
        },
    );
    out.push_str("<div class=\"tbl-wrap\"><table>\n<thead><tr><th scope=\"col\">Image</th><th scope=\"col\">From</th><th scope=\"col\">To</th><th scope=\"col\">Result</th></tr></thead>\n<tbody>\n");
    for (image, record) in present {
        out.push_str("<tr><td><code>");
        out.push_str(&esc(image));
        out.push_str("</code></td><td class=\"val-before\">");
        out.push_str(&esc(record.from.as_deref().unwrap_or("(unknown)")));
        out.push_str("</td><td class=\"val-after\">");
        out.push_str(&esc(&record.to));
        out.push_str("</td><td class=\"");
        out.push_str(if record.applied {
            "num-applied\">Applied"
        } else {
            "num-warn\">Skipped"
        });
        out.push_str("</td></tr>\n");
    }
    out.push_str("</tbody>\n</table></div>\n");
    push_section_close(out);
}

fn push_rollback_section(out: &mut String, rollback: &RollbackRecord) {
    let mut badges = Vec::new();
    if rollback.applied {
        badges.push(("✓ applied".to_string(), "badge-ok"));
    } else {
        badges.push(("! skipped".to_string(), "badge-warn"));
    }
    push_section_open(
        out,
        &SectionShell {
            id: "sec-rollback",
            title: "Rollback index",
            subtitle: Some("AVB rollback index change".to_string()),
            badges,
            open: true,
        },
    );
    out.push_str("<div class=\"tbl-wrap\"><table>\n<thead><tr><th scope=\"col\">From</th><th scope=\"col\">To</th><th scope=\"col\">Result</th></tr></thead>\n<tbody><tr><td>");
    out.push_str(&esc(&rollback.from_iso));
    out.push_str(" <span class=\"mono muted\">");
    let _ = write!(out, "{}", rollback.from_unix);
    out.push_str("</span></td><td>");
    out.push_str(&esc(&rollback.to_iso));
    out.push_str(" <span class=\"mono muted\">");
    let _ = write!(out, "{}", rollback.to_unix);
    out.push_str("</span></td><td class=\"");
    out.push_str(if rollback.applied {
        "num-applied\">Applied"
    } else {
        "num-warn\">Skipped"
    });
    out.push_str("</td></tr></tbody>\n</table></div>\n");
    push_section_close(out);
}

fn push_debloat_section(out: &mut String, debloat: &DebloatRecord) {
    if debloat.partitions.is_empty() {
        return;
    }
    let hidden: usize = debloat.partitions.iter().map(|p| p.removed).sum();
    let not_found: usize = debloat.partitions.iter().map(|p| p.not_found).sum();
    let mut badges = Vec::new();
    if hidden > 0 {
        badges.push((format!("✓ {hidden} hidden"), "badge-ok"));
    }
    if not_found > 0 {
        badges.push((format!("! {not_found} not found"), "badge-warn"));
    }
    push_section_open(
        out,
        &SectionShell {
            id: "sec-debloat",
            title: "Debloat",
            subtitle: Some(format!("{} partitions", debloat.partitions.len())),
            badges,
            open: true,
        },
    );
    out.push_str("<div class=\"tbl-wrap\"><table>\n<thead><tr><th scope=\"col\">Partition</th><th scope=\"col\" class=\"col-num\">Hidden</th><th scope=\"col\" class=\"col-num\">Not found</th></tr></thead>\n<tbody>\n");
    for partition in &debloat.partitions {
        out.push_str("<tr><td><code>");
        out.push_str(&esc(&partition.partition));
        out.push_str("</code></td><td class=\"col-num ");
        out.push_str(if partition.removed > 0 {
            "num-applied\">"
        } else {
            "num-zero\">—"
        });
        if partition.removed > 0 {
            let _ = write!(out, "{}", partition.removed);
        }
        out.push_str("</td><td class=\"col-num ");
        out.push_str(if partition.not_found > 0 {
            "num-warn\">"
        } else {
            "num-zero\">—"
        });
        if partition.not_found > 0 {
            let _ = write!(out, "{}", partition.not_found);
        }
        out.push_str("</td></tr>\n");
    }
    out.push_str("</tbody>\n</table></div>\n");
    push_section_close(out);
}

fn push_spoof_section(out: &mut String, spoof: &SpoofRecord) {
    let mut badges = vec![(format!("{} files", spoof.files.len()), "badge-neutral")];
    if spoof.apps > 0 || spoof.props > 0 {
        badges.push((
            format!("{} app · {} props", spoof.apps, spoof.props),
            "badge-info",
        ));
    }
    push_section_open(
        out,
        &SectionShell {
            id: "sec-spoof",
            title: "Per-app spoof",
            subtitle: Some(format!(
                "Zygote-loaded payload in {}",
                display_name(&spoof.partition)
            )),
            badges,
            open: true,
        },
    );

    out.push_str("<div class=\"meta-list\">\n");
    if spoof.apps > 0 || spoof.props > 0 {
        out.push_str("<div class=\"meta-row\"><span class=\"meta-label\">Coverage</span><span class=\"meta-value\">");
        let _ = write!(
            out,
            "{} app(s) · {} prop(s). Only the listed app processes see the override values.",
            spoof.apps, spoof.props
        );
        out.push_str("</span></div>\n");
    }
    out.push_str("<div class=\"meta-row\"><span class=\"meta-label\">Loaders</span><span class=\"meta-value\">");
    if spoof.loaders.is_empty() {
        out.push_str("(none)");
    } else {
        for (index, loader) in spoof.loaders.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            out.push_str("<code>");
            out.push_str(&esc(&loader.path));
            out.push_str("</code> (");
            out.push_str(&esc(&loader.outcome));
            out.push(')');
        }
    }
    out.push_str("</span></div>\n");
    out.push_str("<div class=\"meta-row\"><span class=\"meta-label\">Legacy init</span><span class=\"meta-value\"><code>");
    out.push_str(&esc(&spoof.init_path));
    out.push_str("</code> (");
    out.push_str(&esc(&spoof.init_outcome));
    out.push_str(")</span></div>\n");
    if !spoof.old_root_digest.is_empty() || !spoof.new_root_digest.is_empty() {
        out.push_str("<div class=\"meta-row\"><span class=\"meta-label\">dm-verity</span><span class=\"meta-value mono\">");
        out.push_str(&esc(&spoof.old_root_digest));
        out.push_str(" &rarr; ");
        out.push_str(&esc(&spoof.new_root_digest));
        out.push_str("</span></div>\n");
    }
    out.push_str("</div>\n");

    if spoof.files.is_empty() {
        out.push_str("<p class=\"empty-state\">No spoof payload files.</p>\n");
    } else {
        out.push_str("<div class=\"tbl-wrap\"><table>\n<thead><tr><th scope=\"col\">Path</th><th scope=\"col\" class=\"col-num\">Size (B)</th><th scope=\"col\">SHA-256</th><th scope=\"col\" class=\"col-num\">Fs meta</th></tr></thead>\n<tbody>\n");
        for file in &spoof.files {
            out.push_str("<tr><td class=\"col-path\"><code>");
            out.push_str(&esc(&file.path));
            out.push_str("</code></td><td class=\"col-num\">");
            out.push_str(&format_u64(file.size));
            out.push_str("</td><td class=\"col-hash\">");
            out.push_str(&esc(&file.sha256));
            out.push_str("</td><td class=\"col-num fs-meta\">");
            let _ = write!(
                out,
                "{} · {} blk",
                format_u64(u64::from(file.inode)),
                format_u64(u64::from(file.blocks))
            );
            out.push_str("</td></tr>\n");
        }
        out.push_str("</tbody>\n</table></div>\n");
    }
    push_section_close(out);
}

fn push_plus_section(out: &mut String, plus: &PlusRecord) {
    if plus.patches.is_empty() {
        return;
    }
    let (applied, skipped, packages) = plus_totals(Some(plus));
    let skipped_targets = plus
        .patches
        .iter()
        .flat_map(|patch| &patch.files)
        .filter(|file| file.ops_skipped > 0)
        .count();
    let mut badges = vec![(format!("{packages} packages"), "badge-neutral")];
    if applied > 0 {
        badges.push((format!("✓ {applied} applied"), "badge-ok"));
    }
    if skipped > 0 {
        badges.push((format!("! {skipped} skipped"), "badge-warn"));
    }
    push_section_open(
        out,
        &SectionShell {
            id: "sec-plus",
            title: "Plus patches",
            subtitle: Some(format!("{skipped_targets} targets with skips")),
            badges,
            open: false,
        },
    );
    out.push_str("<div class=\"tbl-wrap\"><table>\n<thead><tr><th scope=\"col\">Target</th><th scope=\"col\" class=\"col-num\">Applied</th><th scope=\"col\" class=\"col-num\">Skipped</th></tr></thead>\n<tbody>\n");
    for patch in &plus.patches {
        let patch_applied: usize = patch.files.iter().map(|file| file.ops_applied).sum();
        let patch_skipped: usize = patch.files.iter().map(|file| file.ops_skipped).sum();
        out.push_str("<tr class=\"group-row\"><th colspan=\"3\" scope=\"colgroup\"><code>");
        out.push_str(&esc(&patch.name));
        out.push_str("</code> <span class=\"badge badge-neutral\">");
        out.push_str(&esc(display_name(&patch.source)));
        out.push_str("</span> ");
        if patch.files.is_empty() {
            out.push_str("<span class=\"badge badge-neutral\">No matching files</span>");
        } else {
            out.push_str("<span class=\"badge badge-neutral\">");
            let _ = write!(
                out,
                "{} targets · {} applied · {} skipped",
                patch.files.len(),
                patch_applied,
                patch_skipped
            );
            out.push_str("</span>");
        }
        out.push_str("</th></tr>\n");

        for file in &patch.files {
            let warn = file.ops_skipped > 0;
            out.push_str("<tr");
            if warn {
                out.push_str(" class=\"row-warn\"");
            }
            out.push('>');
            out.push_str("<td class=\"col-path\"><code>");
            out.push_str(&esc(&file.partition));
            out.push_str(" / ");
            out.push_str(&esc(display_name(&file.file)));
            out.push_str("</code>");
            if file.ops_applied == 0 && file.ops_skipped > 0 {
                out.push_str(
                    "<br><span class=\"empty\">Target found; no operations applied</span>",
                );
            }
            out.push_str("</td><td class=\"col-num ");
            if file.ops_applied > 0 {
                out.push_str("num-applied\">");
                let _ = write!(out, "{}", file.ops_applied);
            } else if file.ops_skipped > 0 {
                out.push_str("num-warn\">");
                let _ = write!(out, "{}", file.ops_applied);
            } else {
                out.push_str("num-zero\">—");
            }
            out.push_str("</td><td class=\"col-num ");
            if file.ops_skipped > 0 {
                out.push_str("num-warn\">");
                let _ = write!(out, "{}", file.ops_skipped);
            } else {
                out.push_str("num-zero\">—");
            }
            out.push_str("</td></tr>\n");
        }
    }
    out.push_str("</tbody>\n</table></div>\n");
    push_section_close(out);
}

fn push_lgsi_section(out: &mut String, lgsi: &LgsiRecord) {
    if lgsi.applied.is_empty() && lgsi.skipped.is_empty() {
        return;
    }
    let enabled = lgsi
        .applied
        .iter()
        .filter(|change| !change.from && change.to)
        .count();
    let disabled = lgsi
        .applied
        .iter()
        .filter(|change| change.from && !change.to)
        .count();
    let skipped = lgsi.skipped.len();
    let has_reason = skipped > 0;
    let mut badges = vec![(format!("✓ {} applied", lgsi.applied.len()), "badge-ok")];
    if enabled > 0 {
        badges.push((format!("{enabled} enabled"), "badge-info"));
    }
    if skipped > 0 {
        badges.push((format!("! {skipped} skipped"), "badge-warn"));
    }
    push_section_open(
        out,
        &SectionShell {
            id: "sec-lgsi",
            title: "LGSI features",
            subtitle: Some(format!("{disabled} disabled · {enabled} enabled")),
            badges,
            open: false,
        },
    );
    out.push_str("<div class=\"tbl-wrap\"><table>\n<thead><tr><th scope=\"col\">Feature</th><th scope=\"col\">Change</th><th scope=\"col\">Result</th>");
    if has_reason {
        out.push_str("<th scope=\"col\">Reason</th>");
    }
    out.push_str("</tr></thead>\n<tbody>\n");

    for skipped in &lgsi.skipped {
        out.push_str("<tr><td><code>");
        out.push_str(&esc(&skipped.name));
        out.push_str("</code></td><td class=\"empty\">—</td><td class=\"num-warn\">Skipped</td>");
        if has_reason {
            out.push_str("<td>");
            out.push_str(&esc(&skipped.reason));
            out.push_str("</td>");
        }
        out.push_str("</tr>\n");
    }
    for change in &lgsi.applied {
        out.push_str("<tr><td><code>");
        out.push_str(&esc(&change.name));
        out.push_str("</code></td><td>");
        push_lgsi_change(out, change);
        out.push_str("</td><td class=\"num-applied\">Applied</td>");
        if has_reason {
            out.push_str("<td class=\"empty\">—</td>");
        }
        out.push_str("</tr>\n");
    }

    out.push_str("</tbody>\n</table></div>\n");
    push_section_close(out);
}

fn push_lgsi_change(out: &mut String, change: &LgsiChange) {
    let from = if change.from { "true" } else { "false" };
    let to = if change.to { "true" } else { "false" };
    out.push_str("<span class=\"change-pill");
    if !change.from && change.to {
        out.push_str(" is-enabled");
    } else if change.from && !change.to {
        out.push_str(" is-disabled");
    }
    out.push_str("\">");
    out.push_str(from);
    out.push_str(" &rarr; <strong>");
    out.push_str(to);
    out.push_str("</strong></span>");
}

fn push_overlay_section(out: &mut String, overlay: &OverlayRecord) {
    let total: u64 = overlay.files.iter().map(|file| file.size).sum();
    let mut badges = vec![(format!("{} files", overlay.files.len()), "badge-neutral")];
    if total > 0 {
        badges.push((format_bytes(total), "badge-neutral"));
    }
    push_section_open(
        out,
        &SectionShell {
            id: "sec-overlays",
            title: "Added overlays",
            subtitle: Some(format!(
                "Static RRO APKs in {}",
                display_name(&overlay.partition)
            )),
            badges,
            open: false,
        },
    );
    if overlay.files.is_empty() {
        out.push_str("<p class=\"empty-state\">No overlay files.</p>\n");
    } else {
        out.push_str("<div class=\"tbl-wrap\"><table>\n<thead><tr><th scope=\"col\">File</th><th scope=\"col\" class=\"col-num\">Size (B)</th><th scope=\"col\">SHA-256</th><th scope=\"col\" class=\"col-num\">Fs meta</th></tr></thead>\n<tbody>\n");
        for file in &overlay.files {
            out.push_str("<tr><td><code>");
            out.push_str(&esc(&file.name));
            out.push_str("</code></td><td class=\"col-num\">");
            out.push_str(&format_u64(file.size));
            out.push_str("</td><td class=\"col-hash\">");
            out.push_str(&esc(&file.sha256));
            out.push_str("</td><td class=\"col-num fs-meta\">");
            let _ = write!(
                out,
                "{} · {} blk",
                format_u64(u64::from(file.inode)),
                format_u64(u64::from(file.blocks))
            );
            out.push_str("</td></tr>\n");
        }
        out.push_str("</tbody>\n</table></div>\n");
    }
    push_section_close(out);
}

fn push_resigned_section(out: &mut String, images: &[String]) {
    if images.is_empty() {
        return;
    }
    push_section_open(
        out,
        &SectionShell {
            id: "sec-signed",
            title: "Signed images",
            subtitle: Some("Re-signed AVB images".to_string()),
            badges: vec![(format!("{} images", images.len()), "badge-neutral")],
            open: true,
        },
    );
    out.push_str("<div class=\"file-chips\">\n");
    for image in images {
        out.push_str("<code class=\"file-chip\">");
        out.push_str(&esc(display_name(image)));
        out.push_str("</code>\n");
    }
    out.push_str("</div>\n");
    push_section_close(out);
}

fn format_u64(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value >= KIB * KIB * KIB {
        format!("{:.2} GiB", value / (KIB * KIB * KIB))
    } else if value >= KIB * KIB {
        format!("{:.2} MiB", value / (KIB * KIB))
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(total_seconds: u64) -> String {
    if total_seconds < 60 {
        format!("{total_seconds}s")
    } else if total_seconds < 3600 {
        format!("{}m {:02}s", total_seconds / 60, total_seconds % 60)
    } else {
        format!(
            "{}h {:02}m",
            total_seconds / 3600,
            (total_seconds % 3600) / 60
        )
    }
}

fn display_name(value: &str) -> &str {
    let trimmed = value.trim_end_matches(['/', '\\']);
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(value)
}

fn redact_command_line(command_line: &str) -> String {
    command_line
        .split_whitespace()
        .map(redact_command_argument)
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_command_argument(argument: &str) -> String {
    if let Some((option, value)) = argument.split_once('=') {
        if contains_path_separator(value) {
            return format!("{option}={}", display_name(value));
        }
    }
    if contains_path_separator(argument) {
        return display_name(argument).to_string();
    }
    argument.to_string()
}

fn contains_path_separator(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
}

fn esc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Best-effort ISO-8601 UTC timestamp without depending on `chrono` /
/// `time`. Falls back to a Unix epoch seconds string if SystemTime
/// dips below UNIX_EPOCH (e.g. clock-skewed embedded test rigs).
pub(crate) fn now_iso8601() -> String {
    format_unix_to_iso8601_utc(now_unix())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn format_unix_to_iso8601_utc(unix_secs: u64) -> String {
    crate::time_format::format_unix_to_iso8601_utc(unix_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_escapes_html_specials() {
        assert_eq!(esc("a<b>c&d\"e'f"), "a&lt;b&gt;c&amp;d&quot;e&#39;f");
    }

    #[test]
    fn iso8601_known_values() {
        // 2026-05-02T00:00:00Z = 1777680000 unix seconds.
        assert_eq!(
            format_unix_to_iso8601_utc(1777680000),
            "2026-05-02T00:00:00Z"
        );
        // 1970-01-01 epoch.
        assert_eq!(format_unix_to_iso8601_utc(0), "1970-01-01T00:00:00Z");
        // 2000-01-01T00:00:00Z = 946684800.
        assert_eq!(
            format_unix_to_iso8601_utc(946684800),
            "2000-01-01T00:00:00Z"
        );
        // 2024-02-29T00:00:00Z = 1709164800 (leap day sanity).
        assert_eq!(
            format_unix_to_iso8601_utc(1709164800),
            "2024-02-29T00:00:00Z"
        );
        // Mid-day timestamp: 2026-05-02T15:30:45Z =
        // 1777680000 + 15*3600 + 30*60 + 45 = 1777735845.
        assert_eq!(
            format_unix_to_iso8601_utc(1777735845),
            "2026-05-02T15:30:45Z"
        );
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(60), "1m 00s");
        assert_eq!(format_duration(3599), "59m 59s");
        assert_eq!(format_duration(3661), "1h 01m");
    }

    #[test]
    fn number_formatting() {
        assert_eq!(format_u64(0), "0");
        assert_eq!(format_u64(999), "999");
        assert_eq!(format_u64(1000), "1,000");
        assert_eq!(format_u64(4_637_990), "4,637,990");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(4_637_990), "4.42 MiB");
    }

    #[test]
    fn render_html_includes_command_and_changes() {
        let mut r = PipelineReport {
            command_line: "dynobox resign --input X --key testkey_rsa4096".to_string(),
            command_kind: "resign".to_string(),
            started_at: "2026-05-02T10:00:00Z".to_string(),
            finished_at: "2026-05-02T10:01:00Z".to_string(),
            output_dir: "/tmp/out".to_string(),
            ..Default::default()
        };
        r.boot_spl = Some(SplRecord {
            property: "com.android.build.boot.security_patch".to_string(),
            from: Some("2026-04-05".to_string()),
            to: "2026-05-01".to_string(),
            applied: true,
            reason: String::new(),
        });
        r.lgsi = Some(LgsiRecord {
            applied: vec![LgsiChange {
                name: "ZuiAntiCrossSell".to_string(),
                from: true,
                to: false,
            }],
            skipped: vec![LgsiSkip {
                name: "MissingFeature".to_string(),
                reason: "JSON entry not present in dex".to_string(),
            }],
            old_root_digest: "deadbeef".to_string(),
            new_root_digest: "cafebabe".to_string(),
        });
        let html = r.render_html();
        assert!(html.contains("DynoBox pipeline report"));
        assert!(html.contains("dynobox resign --input X --key testkey_rsa4096"));
        assert!(html.contains("ZuiAntiCrossSell"));
        assert!(html.contains("MissingFeature"));
        assert!(html.contains("2026-04-05"));
        assert!(html.contains("2026-05-01"));
    }

    #[test]
    fn render_html_redacts_absolute_paths() {
        let r = PipelineReport {
            command_line: r"dynobox apply --input D:\Downloads\Tool\image --output=D:\Downloads\Tool\final --plus=C:\Git\DynoBox\patches\unlock-wifi.dbp".to_string(),
            command_kind: "apply".to_string(),
            started_at: "2026-05-02T10:00:00Z".to_string(),
            finished_at: "2026-05-02T10:01:00Z".to_string(),
            output_dir: r"D:\Downloads\Tool\dynobox-stage-abc\resign_stage".to_string(),
            resigned_images: vec!["boot.img".to_string()],
            plus: Some(PlusRecord {
                patches: vec![PlusPatchRecord {
                    name: "unlock-wifi".to_string(),
                    source: r"C:\Git\DynoBox\patches\unlock-wifi.dbp".to_string(),
                    files: vec![PlusFileRecord {
                        partition: "product".to_string(),
                        file: r"D:\staging\product\overlay\WifiOverlay.apk".to_string(),
                        ops_applied: 1,
                        ops_skipped: 0,
                        patched_entries: Vec::new(),
                    }],
                }],
                verity: Vec::new(),
            }),
            ..Default::default()
        };

        let html = r.render_html();

        assert!(html.contains("--input image"));
        assert!(html.contains("--output=final"));
        assert!(html.contains("--plus=unlock-wifi.dbp"));
        assert!(html.contains("WifiOverlay.apk"));
        assert!(html.contains("resign_stage"));
        assert!(!html.contains(r"D:\Downloads"));
        assert!(!html.contains(r"C:\Git"));
        assert!(!html.contains(r"D:\staging"));
    }

    #[test]
    fn render_html_distinguishes_missing_targets_from_unmatched_sites() {
        let r = PipelineReport {
            plus: Some(PlusRecord {
                patches: vec![
                    PlusPatchRecord {
                        name: "missing-target".to_string(),
                        source: "missing-target.dbp".to_string(),
                        files: Vec::new(),
                    },
                    PlusPatchRecord {
                        name: "unmatched-sites".to_string(),
                        source: "unmatched-sites.dbp".to_string(),
                        files: vec![PlusFileRecord {
                            partition: "system".to_string(),
                            file: "system/priv-app/ZuiLauncher/ZuiLauncher.apk".to_string(),
                            ops_applied: 0,
                            ops_skipped: 1,
                            patched_entries: Vec::new(),
                        }],
                    },
                ],
                verity: Vec::new(),
            }),
            ..Default::default()
        };

        let html = r.render_html();
        assert_eq!(html.matches("No matching files").count(), 1);
        assert!(html.contains("system / ZuiLauncher.apk"));
        assert!(html.contains("Target found; no operations applied"));
    }

    #[test]
    fn lgsi_reason_column_only_when_skips_exist() {
        let mut r = PipelineReport {
            lgsi: Some(LgsiRecord {
                applied: vec![LgsiChange {
                    name: "A".to_string(),
                    from: true,
                    to: false,
                }],
                skipped: Vec::new(),
                old_root_digest: String::new(),
                new_root_digest: String::new(),
            }),
            ..Default::default()
        };
        let html = r.render_html();
        assert!(!html.contains(">Reason</th>"));
        assert!(html.contains("change-pill is-disabled"));

        r.lgsi.as_mut().unwrap().skipped.push(LgsiSkip {
            name: "B".to_string(),
            reason: "missing".to_string(),
        });
        let html = r.render_html();
        assert!(html.contains(">Reason</th>"));
        assert!(html.contains("missing"));
    }

    #[test]
    fn plus_patch_names_are_grouped_once() {
        let r = PipelineReport {
            plus: Some(PlusRecord {
                patches: vec![PlusPatchRecord {
                    name: "unlock-common".to_string(),
                    source: "unlock-common.dbp".to_string(),
                    files: vec![
                        PlusFileRecord {
                            partition: "system".to_string(),
                            file: "a.apk".to_string(),
                            ops_applied: 3,
                            ops_skipped: 0,
                            patched_entries: Vec::new(),
                        },
                        PlusFileRecord {
                            partition: "system".to_string(),
                            file: "b.apk".to_string(),
                            ops_applied: 1,
                            ops_skipped: 2,
                            patched_entries: Vec::new(),
                        },
                    ],
                }],
                verity: Vec::new(),
            }),
            ..Default::default()
        };
        let html = r.render_html();
        assert!(!html.contains(">Patch</th>"));
        assert!(html.contains("group-row"));
        assert!(html.contains("2 targets"));
        assert_eq!(html.matches("unlock-common").count(), 2);
        assert!(html.contains("row-warn"));
        assert!(html.contains("col-num num-warn\">2"));
    }

    #[test]
    fn zero_counters_use_muted_style() {
        let r = PipelineReport {
            debloat: Some(DebloatRecord {
                partitions: vec![DebloatPartition {
                    partition: "vendor".to_string(),
                    removed: 4,
                    not_found: 0,
                    old_root_digest: String::new(),
                    new_root_digest: String::new(),
                }],
            }),
            ..Default::default()
        };
        let html = r.render_html();
        assert!(html.contains("col-num num-zero\">—"));
        assert!(!html.contains("col-num num-warn\">0"));
    }

    #[test]
    fn command_drawer_is_collapsed_and_preserves_full_command() {
        let command = "dynobox apply --input image --add-overlay=a.apk --add-overlay=b.apk";
        let r = PipelineReport {
            command_line: command.to_string(),
            ..Default::default()
        };
        let html = r.render_html();
        assert!(html.contains("<details class=\"cmd-drawer\">"));
        assert!(html.contains("--add-overlay ×2"));
        assert!(html.contains(command));
        assert!(!html.contains("<details class=\"cmd-drawer\" open>"));
    }

    #[test]
    fn large_sections_start_collapsed() {
        let r = PipelineReport {
            lgsi: Some(LgsiRecord {
                applied: vec![LgsiChange {
                    name: "A".to_string(),
                    from: true,
                    to: false,
                }],
                skipped: Vec::new(),
                old_root_digest: String::new(),
                new_root_digest: String::new(),
            }),
            overlay: Some(OverlayRecord {
                partition: "system".to_string(),
                files: vec![OverlayFileRecord {
                    name: "a.apk".to_string(),
                    size: 1,
                    sha256: "a".repeat(64),
                    inode: 1,
                    blocks: 1,
                }],
                old_root_digest: String::new(),
                new_root_digest: String::new(),
            }),
            plus: Some(PlusRecord {
                patches: vec![PlusPatchRecord {
                    name: "p".to_string(),
                    source: "p.dbp".to_string(),
                    files: vec![PlusFileRecord {
                        partition: "system".to_string(),
                        file: "a".to_string(),
                        ops_applied: 1,
                        ops_skipped: 0,
                        patched_entries: Vec::new(),
                    }],
                }],
                verity: Vec::new(),
            }),
            debloat: Some(DebloatRecord {
                partitions: vec![DebloatPartition {
                    partition: "vendor".to_string(),
                    removed: 1,
                    not_found: 0,
                    old_root_digest: String::new(),
                    new_root_digest: String::new(),
                }],
            }),
            ..Default::default()
        };
        let html = r.render_html();
        assert!(html.contains("<details class=\"sec-card\" id=\"sec-lgsi\">"));
        assert!(html.contains("<details class=\"sec-card\" id=\"sec-overlays\">"));
        assert!(html.contains("<details class=\"sec-card\" id=\"sec-plus\">"));
        assert!(html.contains("<details class=\"sec-card\" id=\"sec-debloat\" open>"));
    }

    #[test]
    fn output_marker_survives_redesign() {
        let r = PipelineReport {
            output_dir: "/tmp/out".to_string(),
            ..Default::default()
        };
        let html = r.render_html();
        assert!(html.contains("<span data-report-output>out</span>"));
    }

    #[test]
    fn has_content_returns_true_only_when_populated() {
        let r = PipelineReport::default();
        assert!(!r.has_content());
        let mut r2 = r.clone();
        r2.resigned_images.push("boot.img".to_string());
        assert!(r2.has_content());
    }

    #[test]
    fn report_stays_pending_until_final_verification() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("report.html");
        let report = PipelineReport {
            finished_at: "2026-05-02T10:01:00Z".to_string(),
            resigned_images: vec!["boot.img".to_string()],
            ..Default::default()
        };

        report.write(&path).unwrap();
        let pending = std::fs::read_to_string(&path).unwrap();
        assert!(pending.contains("Pending verification"));
        assert!(!pending.contains(">Verified</p>"));

        assert!(finalize_verified_report(&path).unwrap());
        let verified = std::fs::read_to_string(&path).unwrap();
        assert!(verified.contains(">Verified</p>"));
        assert!(verified.contains("data-verified-at='"));
        assert!(!verified.contains("Pending verification"));
        assert!(verified.contains("id='output-integrity'"));
        assert!(verified.contains("dynobox-manifest.json"));
        let generator = crate::integrity::dynobox_generator_version();
        assert!(verified.contains(&format!("data-generator='{generator}'")));
        assert!(verified.contains(&format!("DynoBox {generator}")));

        assert!(finalize_verified_report(&path).unwrap());
        assert_eq!(verified, std::fs::read_to_string(&path).unwrap());
    }
}
