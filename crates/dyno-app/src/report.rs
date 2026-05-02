//! Pipeline-end HTML report.
//!
//! `run_resign_stage` collects per-mutation before/after records into a
//! [`PipelineReport`] and writes it to `<out>/report.html` after the
//! resign loop finishes. The report is a self-contained, no-JS, no-CDN
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
    pub rollback: Option<RollbackRecord>,
    pub lgsi: Option<LgsiRecord>,
    pub signing_key_change: Option<SigningKeyChange>,
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
        let argv: Vec<String> = std::env::args().collect();
        let command_line = argv.join(" ");
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
            || self.rollback.is_some()
            || self.lgsi.is_some()
            || self.signing_key_change.is_some()
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

        // Header section: command, kind, timestamps, output dir.
        out.push_str("<h1>DynoBox pipeline report</h1>\n");
        out.push_str("<table class='meta'>\n");
        push_meta_row(&mut out, "Command", &esc(&self.command_line));
        push_meta_row(&mut out, "Stage", &esc(&self.command_kind));
        push_meta_row(&mut out, "Started", &esc(&self.started_at));
        push_meta_row(&mut out, "Finished", &esc(&self.finished_at));
        push_meta_row(&mut out, "Output dir", &esc(&self.output_dir));
        out.push_str("</table>\n");

        if let Some(spl) = &self.boot_spl {
            push_spl_section(&mut out, "boot.img security_patch", spl);
        }
        if let Some(spl) = &self.vendor_spl {
            push_spl_section(&mut out, "vendor.img security_patch", spl);
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
        push_resigned_section(&mut out, &self.resigned_images);

        out.push_str(HTML_FOOTER);
        out
    }
}

const HTML_HEADER: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>DynoBox pipeline report</title>
  <style>
    body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; padding: 24px; color: #1f2328; max-width: 1100px; margin: 0 auto; }
    h1 { border-bottom: 1px solid #d0d7de; padding-bottom: 12px; }
    h2 { margin-top: 36px; border-bottom: 1px solid #d0d7de; padding-bottom: 6px; font-size: 1.15em; }
    table { border-collapse: collapse; margin: 8px 0 16px 0; }
    th, td { border: 1px solid #d0d7de; padding: 6px 12px; text-align: left; vertical-align: top; }
    th { background: #f6f8fa; }
    table.meta th { width: 140px; }
    code, .mono { font-family: SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.95em; }
    .from { color: #cf222e; }
    .to { color: #1a7f37; }
    .skipped { color: #9a6700; }
    .applied { color: #1a7f37; font-weight: 600; }
    .not-applied { color: #57606a; }
    ul.entries { margin: 6px 0 12px 0; padding-left: 24px; }
    .empty { color: #57606a; font-style: italic; }
  </style>
</head>
<body>
"#;

const HTML_FOOTER: &str = r#"</body>
</html>
"#;

fn push_meta_row(out: &mut String, key: &str, val: &str) {
    out.push_str("<tr><th>");
    out.push_str(key);
    out.push_str("</th><td><code>");
    out.push_str(val);
    out.push_str("</code></td></tr>\n");
}

fn push_spl_section(out: &mut String, title: &str, spl: &SplRecord) {
    out.push_str("<h2>");
    out.push_str(&esc(title));
    out.push_str("</h2>\n");
    out.push_str(
        "<table>\n<tr><th>Property</th><th>From</th><th>To</th><th>Status</th><th>Note</th></tr>\n",
    );
    out.push_str("<tr>");
    out.push_str(&format!("<td><code>{}</code></td>", esc(&spl.property)));
    out.push_str(&format!(
        "<td class='from'>{}</td>",
        esc(spl.from.as_deref().unwrap_or("(unknown)"))
    ));
    out.push_str(&format!("<td class='to'>{}</td>", esc(&spl.to)));
    out.push_str(&format!(
        "<td class='{}'>{}</td>",
        if spl.applied {
            "applied"
        } else {
            "not-applied"
        },
        if spl.applied { "applied" } else { "skipped" }
    ));
    out.push_str(&format!("<td>{}</td>", esc(&spl.reason)));
    out.push_str("</tr>\n</table>\n");
}

fn push_rollback_section(out: &mut String, rb: &RollbackRecord) {
    out.push_str("<h2>AVB rollback_index</h2>\n");
    out.push_str(
        "<table>\n<tr><th>From (UTC)</th><th>To (UTC)</th><th>Status</th><th>Note</th></tr>\n",
    );
    out.push_str("<tr>");
    out.push_str(&format!(
        "<td class='from'>{} <span class='mono'>({})</span></td>",
        esc(&rb.from_iso),
        rb.from_unix
    ));
    out.push_str(&format!(
        "<td class='to'>{} <span class='mono'>({})</span></td>",
        esc(&rb.to_iso),
        rb.to_unix
    ));
    out.push_str(&format!(
        "<td class='{}'>{}</td>",
        if rb.applied { "applied" } else { "not-applied" },
        if rb.applied { "applied" } else { "skipped" }
    ));
    out.push_str(&format!("<td>{}</td>", esc(&rb.reason)));
    out.push_str("</tr>\n</table>\n");
}

fn push_lgsi_section(out: &mut String, l: &LgsiRecord) {
    out.push_str("<h2>LGSI feature toggles</h2>\n");
    let trim = |s: &str| s.chars().take(16).collect::<String>();
    out.push_str(&format!(
        "<p class='mono'>verity root_digest: <span class='from'>{}</span> &rarr; <span class='to'>{}</span></p>\n",
        esc(&trim(&l.old_root_digest)),
        esc(&trim(&l.new_root_digest))
    ));

    out.push_str("<h3 style='margin-bottom:4px'>Applied (");
    out.push_str(&l.applied.len().to_string());
    out.push_str(")</h3>\n");
    if l.applied.is_empty() {
        out.push_str("<p class='empty'>No features flipped.</p>\n");
    } else {
        out.push_str("<table>\n<tr><th>Feature</th><th>From</th><th>To</th></tr>\n");
        for c in &l.applied {
            out.push_str("<tr>");
            out.push_str(&format!("<td><code>{}</code></td>", esc(&c.name)));
            out.push_str(&format!(
                "<td class='from'>{}</td>",
                if c.from { "true" } else { "false" }
            ));
            out.push_str(&format!(
                "<td class='to'>{}</td>",
                if c.to { "true" } else { "false" }
            ));
            out.push_str("</tr>\n");
        }
        out.push_str("</table>\n");
    }

    out.push_str("<h3 style='margin-bottom:4px'>Skipped (");
    out.push_str(&l.skipped.len().to_string());
    out.push_str(")</h3>\n");
    if l.skipped.is_empty() {
        out.push_str("<p class='empty'>None.</p>\n");
    } else {
        out.push_str("<table>\n<tr><th>Feature</th><th>Reason</th></tr>\n");
        for s in &l.skipped {
            out.push_str("<tr>");
            out.push_str(&format!("<td><code>{}</code></td>", esc(&s.name)));
            out.push_str(&format!("<td class='skipped'>{}</td>", esc(&s.reason)));
            out.push_str("</tr>\n");
        }
        out.push_str("</table>\n");
    }
}

fn push_signing_key_section(out: &mut String, sk: &SigningKeyChange) {
    out.push_str("<h2>Signing key change</h2>\n");
    out.push_str("<p>The resigned key's public-key SHA-1 differs from the OEM signing key already on the partitions. The bootloader's <code>abl.elf</code> may need to be replaced with one that trusts the new key, otherwise the device will fail AVB verification at boot.</p>\n");
    out.push_str("<table>\n<tr><th>From (OEM)</th><th>To (resigned)</th></tr>\n");
    out.push_str("<tr>");
    out.push_str(&format!(
        "<td class='from'><code>{}</code></td>",
        esc(&sk.old_pubkey_sha1)
    ));
    out.push_str(&format!(
        "<td class='to'><code>{}</code></td>",
        esc(&sk.new_pubkey_sha1)
    ));
    out.push_str("</tr>\n</table>\n");
}

fn push_resigned_section(out: &mut String, images: &[String]) {
    out.push_str("<h2>Resigned images</h2>\n");
    if images.is_empty() {
        out.push_str("<p class='empty'>No images were resigned.</p>\n");
    } else {
        out.push_str("<ul class='entries'>\n");
        for img in images {
            out.push_str(&format!("<li><code>{}</code></li>\n", esc(img)));
        }
        out.push_str("</ul>\n");
    }
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
    // Days since epoch.
    let total_secs = unix_secs;
    let secs_in_day = 86_400u64;
    let days = total_secs / secs_in_day;
    let secs_of_day = total_secs % secs_in_day;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    // Convert days since 1970-01-01 to (Y, M, D) using the algorithm
    // from https://howardhinnant.github.io/date_algorithms.html
    // (civil_from_days). Branch-free, no leap-day edge cases.
    let z = days as i64 + 719468;
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = y + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
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
    fn render_html_includes_command_and_stages() {
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
    fn has_content_returns_true_only_when_populated() {
        let r = PipelineReport::default();
        assert!(!r.has_content());
        let mut r2 = r.clone();
        r2.resigned_images.push("boot.img".to_string());
        assert!(r2.has_content());
    }
}
