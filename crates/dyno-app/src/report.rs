//! Pipeline-end HTML report.
//!
//! `run_resign_stage` collects per-mutation before/after records into a
//! [`PipelineReport`] and writes it to `<out>/report.html` after the
//! resign loop finishes. It remains marked as pending until the final
//! pipeline verification succeeds. The report is a self-contained, no-JS,
//! no-CDN
//! HTML page summarising every state change the stage made: command
//! line, timestamps, boot/vendor SPL bumps, rollback rewrites, LGSI
//! feature toggles (applied + skipped), and any signing-key swap that
//! triggered the abl.elf-rebuild warning.
//!
//! Read-only stages (`info`, `verify`, `unpack`, `repack`, plus
//! `apply` without resign) intentionally skip the report — there's
//! nothing to summarise.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

#[derive(Debug, Clone, Default)]
pub struct PipelineReport {
    pub command_line: String,
    pub command_kind: String,
    pub started_at: String,
    pub finished_at: String,
    pub output_dir: String,
    pub resigned_images: Vec<String>,
    pub boot_spl: Option<SplRecord>,
    pub vendor_spl: Option<SplRecord>,
    pub system_spl: Option<SplRecord>,
    pub rollback: Option<RollbackRecord>,
    pub lgsi: Option<LgsiRecord>,
    pub signing_key_change: Option<SigningKeyChange>,
    pub debloat: Option<DebloatRecord>,
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
    /// Path of the patched APK inside the partition image.
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
            finished_at: String::new(),
            output_dir: output_dir.display().to_string(),
            ..Default::default()
        }
    }

    pub fn finish(&mut self) {
        self.finished_at = now_iso8601();
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
            || self.plus.is_some()
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let html = self.render_html();
        std::fs::write(path, html)
            .with_context(|| format!("Failed to write pipeline report to {}", path.display()))?;
        Ok(())
    }

    pub fn render_html(&self) -> String {
        let mut out = String::with_capacity(8 * 1024);
        out.push_str(HTML_HEADER);

        out.push_str("<main>\n<header class='report-header'>\n");
        out.push_str("<div><p class='product'>DynoBox</p><h1>Pipeline report</h1></div>\n");
        out.push_str(VERIFICATION_STATUS_PENDING);
        out.push_str("\n</header>\n");
        out.push_str("<section class='run-summary' aria-label='Run summary'>\n");
        push_summary_item(
            &mut out,
            "Command",
            &redact_command_line(&self.command_line),
            true,
        );
        push_summary_item(&mut out, "Output", display_name(&self.output_dir), false);
        push_summary_item(&mut out, "Finished", &self.finished_at, false);
        out.push_str("</section>\n");

        let spl_records = [
            ("boot.img", self.boot_spl.as_ref()),
            ("vendor.img", self.vendor_spl.as_ref()),
            ("system.img", self.system_spl.as_ref()),
        ];
        if spl_records.iter().any(|(_, record)| record.is_some()) {
            push_spl_section(&mut out, &spl_records);
        }
        if let Some(rb) = &self.rollback {
            push_rollback_section(&mut out, rb);
        }
        if let Some(l) = &self.lgsi {
            push_lgsi_section(&mut out, l);
        }
        if let Some(sk) = &self.signing_key_change {
            push_signing_key_section(&mut out, sk);
        }
        if let Some(db) = &self.debloat {
            push_debloat_section(&mut out, db);
        }
        if let Some(pl) = &self.plus {
            push_plus_section(&mut out, pl);
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
    :root { color-scheme: light; --ink: #172033; --muted: #5d6878; --line: #d8dee8; --surface: #ffffff; --canvas: #edf1f6; --accent: #165dcc; --success: #167447; --warning: #995d00; --danger: #b42318; }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 32px 20px; background: var(--canvas); color: var(--ink); font: 15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width: 960px; margin: 0 auto; padding: 40px; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; }
    .report-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; padding-bottom: 28px; }
    .product { margin: 0 0 4px; color: var(--accent); font-size: 0.84rem; font-weight: 700; letter-spacing: 0.04em; }
    h1, h2 { margin: 0; color: var(--ink); text-wrap: balance; }
    h1 { font-size: clamp(1.8rem, 4vw, 2.4rem); line-height: 1.15; letter-spacing: -0.025em; }
    h2 { font-size: 1.05rem; line-height: 1.3; }
    h3 { margin: 20px 0 8px; font-size: 0.9rem; color: var(--muted); }
    .status { margin: 2px 0 0; padding: 4px 10px; color: var(--success); background: #e9f7ef; border-radius: 999px; font-size: 0.84rem; font-weight: 700; white-space: nowrap; }
    .status.pending { color: var(--warning); background: #fff8e8; }
    .run-summary { display: grid; grid-template-columns: minmax(0, 1fr) 180px 190px; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
    .summary-item { min-width: 0; padding: 14px 16px; border-left: 1px solid var(--line); }
    .summary-item:first-child { padding-left: 0; border-left: 0; }
    .summary-label { display: block; margin-bottom: 3px; color: var(--muted); font-size: 0.78rem; font-weight: 700; }
    .summary-value { overflow-wrap: anywhere; color: var(--ink); }
    section:not(.run-summary) { padding-top: 28px; }
    .section-heading { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; margin-bottom: 10px; }
    .section-note { margin: 0; color: var(--muted); font-size: 0.88rem; }
    .warning { padding: 18px; background: #fff8e8; border: 1px solid #e8ca85; border-radius: 8px; }
    .warning p { margin: 8px 0 0; color: #654600; }
    table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
    th, td { padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); background: #f7f9fc; font-size: 0.76rem; font-weight: 700; }
    td:last-child, th:last-child { padding-right: 0; }
    th:first-child, td:first-child { padding-left: 0; }
    code, .mono { font-family: "Cascadia Mono", "SFMono-Regular", Consolas, monospace; font-size: 0.9em; overflow-wrap: anywhere; }
    .from { color: var(--danger); }
    .to, .applied { color: var(--success); font-weight: 700; }
    .skipped { color: var(--warning); font-weight: 700; }
    .not-applied, .empty { color: var(--muted); }
    .signed-images { margin: 8px 0 0; color: var(--muted); }
    .signed-images code { color: var(--ink); }
    @media (max-width: 680px) { body { padding: 0; } main { border: 0; border-radius: 0; padding: 28px 20px; } .report-header { gap: 12px; } .run-summary { grid-template-columns: 1fr; } .summary-item, .summary-item:first-child { padding: 12px 0; border: 0; border-top: 1px solid var(--line); } .summary-item:first-child { border-top: 0; } .section-heading { display: block; } .section-note { margin-top: 4px; } table { display: block; overflow-x: auto; white-space: nowrap; } }
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

fn push_summary_item(out: &mut String, label: &str, value: &str, is_command: bool) {
    out.push_str("<div class='summary-item'><span class='summary-label'>");
    out.push_str(label);
    out.push_str("</span><span class='summary-value");
    if is_command {
        out.push_str(" mono");
    }
    out.push_str("'>");
    if label == "Output" {
        out.push_str(OUTPUT_DIR_MARKER_START);
    }
    out.push_str(&esc(value));
    if label == "Output" {
        out.push_str(OUTPUT_DIR_MARKER_END);
    }
    out.push_str("</span></div>\n");
}

fn push_spl_section(out: &mut String, records: &[(&str, Option<&SplRecord>)]) {
    out.push_str("<section><div class='section-heading'><h2>Security patch</h2></div>\n");
    out.push_str("<table><tr><th>Image</th><th>From</th><th>To</th><th>Result</th></tr>\n");
    for (image, record) in records {
        let Some(spl) = record else {
            continue;
        };
        out.push_str("<tr><td><code>");
        out.push_str(image);
        out.push_str("</code></td><td class='from'>");
        out.push_str(&esc(spl.from.as_deref().unwrap_or("(unknown)")));
        out.push_str("</td><td class='to'>");
        out.push_str(&esc(&spl.to));
        out.push_str("</td><td class='");
        out.push_str(if spl.applied {
            "applied'>Applied"
        } else {
            "not-applied'>Skipped"
        });
        out.push_str("</td></tr>\n");
    }
    out.push_str("</table></section>\n");
}

fn push_rollback_section(out: &mut String, rb: &RollbackRecord) {
    out.push_str("<section><div class='section-heading'><h2>Rollback index</h2></div>\n");
    out.push_str("<table><tr><th>From</th><th>To</th><th>Result</th></tr><tr>");
    out.push_str("<td class='from'>");
    out.push_str(&esc(&rb.from_iso));
    out.push_str(" <span class='mono'>");
    out.push_str(&rb.from_unix.to_string());
    out.push_str("</span></td><td class='to'>");
    out.push_str(&esc(&rb.to_iso));
    out.push_str(" <span class='mono'>");
    out.push_str(&rb.to_unix.to_string());
    out.push_str("</span></td><td class='");
    out.push_str(if rb.applied {
        "applied'>Applied"
    } else {
        "not-applied'>Skipped"
    });
    out.push_str("</td></tr></table></section>\n");
}

fn push_lgsi_section(out: &mut String, l: &LgsiRecord) {
    if l.applied.is_empty() && l.skipped.is_empty() {
        return;
    }
    out.push_str("<section><div class='section-heading'><h2>LGSI features</h2></div>\n");
    out.push_str("<table><tr><th>Feature</th><th>Change</th><th>Result</th><th>Note</th></tr>\n");
    for change in &l.applied {
        out.push_str("<tr><td><code>");
        out.push_str(&esc(&change.name));
        out.push_str("</code></td><td><span class='from'>");
        out.push_str(if change.from { "true" } else { "false" });
        out.push_str("</span> &rarr; <span class='to'>");
        out.push_str(if change.to { "true" } else { "false" });
        out.push_str("</span></td><td class='applied'>Applied</td><td></td></tr>\n");
    }
    for skipped in &l.skipped {
        out.push_str("<tr><td><code>");
        out.push_str(&esc(&skipped.name));
        out.push_str("</code></td><td>&mdash;</td><td class='skipped'>Skipped</td><td>");
        out.push_str(&esc(&skipped.reason));
        out.push_str("</td></tr>\n");
    }
    out.push_str("</table></section>\n");
}

fn push_signing_key_section(out: &mut String, sk: &SigningKeyChange) {
    out.push_str("<section class='warning'><h2>Signing key changed</h2>");
    out.push_str("<p>Use an <code>abl.elf</code> that trusts the new key.</p>");
    out.push_str("<table><tr><th>OEM key</th><th>New key</th></tr><tr><td class='from'><code>");
    out.push_str(&esc(&sk.old_pubkey_sha1));
    out.push_str("</code></td><td class='to'><code>");
    out.push_str(&esc(&sk.new_pubkey_sha1));
    out.push_str("</code></td></tr></table></section>\n");
}

fn push_debloat_section(out: &mut String, db: &DebloatRecord) {
    out.push_str("<section><div class='section-heading'><h2>Debloat</h2></div>\n");
    out.push_str("<table><tr><th>Partition</th><th>Hidden</th><th>Not found</th></tr>\n");
    for p in &db.partitions {
        out.push_str("<tr><td><code>");
        out.push_str(&esc(&p.partition));
        out.push_str("</code></td><td class='to'>");
        out.push_str(&p.removed.to_string());
        out.push_str("</td><td class='skipped'>");
        out.push_str(&p.not_found.to_string());
        out.push_str("</td></tr>\n");
    }
    out.push_str("</table></section>\n");
}

fn push_plus_section(out: &mut String, pl: &PlusRecord) {
    if pl.patches.is_empty() {
        return;
    }
    out.push_str("<section><div class='section-heading'><h2>Plus patches</h2></div>\n");
    out.push_str("<table><tr><th>Patch</th><th>Target</th><th>Applied</th><th>Skipped</th></tr>\n");
    for patch in &pl.patches {
        if patch.files.is_empty() {
            out.push_str("<tr><td><code>");
            out.push_str(&esc(&patch.name));
            out.push_str("</code> <span class='mono'>");
            out.push_str(&esc(display_name(&patch.source)));
            out.push_str(
                "</span></td><td class='empty'>No matching files</td><td>0</td><td>0</td></tr>\n",
            );
            continue;
        }
        for f in &patch.files {
            out.push_str("<tr><td><code>");
            out.push_str(&esc(&patch.name));
            out.push_str("</code> <span class='mono'>");
            out.push_str(&esc(display_name(&patch.source)));
            out.push_str("</span></td><td><code>");
            out.push_str(&esc(&f.partition));
            out.push_str(" / ");
            out.push_str(&esc(display_name(&f.file)));
            out.push_str("</code></td><td class='to'>");
            out.push_str(&f.ops_applied.to_string());
            out.push_str("</td><td class='");
            out.push_str(if f.ops_skipped > 0 { "skipped'>" } else { "'>" });
            out.push_str(&f.ops_skipped.to_string());
            out.push_str("</td></tr>\n");
        }
    }
    out.push_str("</table></section>\n");
}

fn push_resigned_section(out: &mut String, images: &[String]) {
    if images.is_empty() {
        return;
    }
    out.push_str(
        "<section><div class='section-heading'><h2>Signed images</h2><p class='section-note'>",
    );
    out.push_str(&images.len().to_string());
    out.push_str(" images</p></div><p class='signed-images'>");
    for (index, image) in images.iter().enumerate() {
        if index > 0 {
            out.push_str(" &middot; ");
        }
        out.push_str("<code>");
        out.push_str(&esc(display_name(image)));
        out.push_str("</code>");
    }
    out.push_str("</p></section>\n");
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
fn now_iso8601() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_to_iso8601_utc(now)
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

        assert!(finalize_verified_report(&path).unwrap());
        assert_eq!(verified, std::fs::read_to_string(&path).unwrap());
    }
}
