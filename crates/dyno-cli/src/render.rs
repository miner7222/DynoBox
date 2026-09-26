//! Human-readable (`--progress-format text`) and JSONL rendering of
//! pipeline events, plus the terminal prompts the text front-end answers.

use std::borrow::Cow;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use dynobox_app::events::ProgressUnit;
use dynobox_app::{EventSink, MessageLevel, ProgressEvent, Prompt, PromptReply, StageKind};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use tracing::{info, warn};

pub(crate) fn stage_name(stage: StageKind) -> &'static str {
    match stage {
        StageKind::Preflight => "preflight",
        StageKind::Unpack => "unpack",
        StageKind::Apply => "apply",
        StageKind::Resign => "resign",
        StageKind::Repack => "repack",
        StageKind::PrepareRepack => "prepare_repack",
        StageKind::AutoUnpack => "auto_unpack",
        StageKind::Verify => "verify",
    }
}

/// Text-renderer-only path state. JSONL receives the original event before
/// this sink-local transformation.
#[derive(Default)]
pub(crate) struct TextPathShortener {
    roots: Vec<String>,
}

impl TextPathShortener {
    pub(crate) fn shorten_event(&mut self, event: ProgressEvent) -> ProgressEvent {
        match event {
            ProgressEvent::CommandStarted {
                command,
                input,
                output,
            } => {
                self.roots.clear();
                self.remember_root(&input);
                self.remember_root(&output);
                ProgressEvent::CommandStarted {
                    command,
                    input,
                    output,
                }
            }
            ProgressEvent::ItemStarted {
                stage,
                current,
                total,
                item,
            } => ProgressEvent::ItemStarted {
                stage,
                current,
                total,
                item: self.shorten_text(&item).into_owned(),
            },
            ProgressEvent::ItemProgress {
                stage,
                item,
                done,
                total,
                unit,
            } => ProgressEvent::ItemProgress {
                stage,
                item: self.shorten_text(&item).into_owned(),
                done,
                total,
                unit,
            },
            ProgressEvent::Message { level, text } => ProgressEvent::Message {
                level,
                text: self.shorten_text(&text).into_owned(),
            },
            other => other,
        }
    }

    fn remember_root(&mut self, path: &Path) {
        let root = path.display().to_string();
        let root = root.trim_end_matches(['/', '\\']);
        if !root.is_empty() && !self.roots.iter().any(|known| known == root) {
            self.roots.push(root.to_string());
            self.roots
                .sort_by_key(|known| std::cmp::Reverse(known.len()));
        }
    }

    pub(crate) fn shorten_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut rendered = String::with_capacity(text.len());
        let mut copied_through = 0;
        let mut scan = 0;

        while scan < text.len() {
            if let Some(span) = self.path_span_at(text, scan) {
                let path = &text[span.path_start..span.path_end];
                if let Some(name) = display_name(path)
                    && name != path
                {
                    rendered.push_str(&text[copied_through..span.path_start]);
                    rendered.push_str(name);
                    copied_through = span.path_end;
                    scan = span.scan_end;
                    continue;
                }
            }

            scan += text[scan..]
                .chars()
                .next()
                .expect("scan is within the string")
                .len_utf8();
        }

        if copied_through == 0 {
            Cow::Borrowed(text)
        } else {
            rendered.push_str(&text[copied_through..]);
            Cow::Owned(rendered)
        }
    }

    fn path_span_at(&self, text: &str, start: usize) -> Option<PathSpan> {
        if !is_path_boundary_before(text, start) {
            return None;
        }

        let first = text[start..].chars().next()?;
        if matches!(first, '"' | '\'' | '`') {
            let content_start = start + first.len_utf8();
            if let Some(relative_close) = text[content_start..].find(first) {
                let content_end = content_start + relative_close;
                let path_end = trim_path_end(text, content_start, content_end);
                let raw = &text[content_start..content_end];
                let path = &text[content_start..path_end];
                if is_path_candidate(path, raw) || self.is_root_anchored_candidate(path, raw) {
                    return Some(PathSpan {
                        path_start: content_start,
                        path_end,
                        scan_end: content_end + first.len_utf8(),
                    });
                }
            }
        }

        for root in &self.roots {
            if !text[start..].starts_with(root) {
                continue;
            }
            let root_end = start + root.len();
            let next = text[root_end..].chars().next();
            if next.is_some_and(|ch| !is_path_separator(ch) && !is_path_terminator(ch)) {
                continue;
            }

            let scan_end = if next.is_some_and(is_path_separator) {
                token_end(text, root_end)
            } else {
                root_end
            };
            let path_end = trim_path_end(text, start, scan_end);
            let raw = &text[start..scan_end];
            let path = &text[start..path_end];
            if is_excluded_path_syntax(path, raw)
                || display_name(path).is_none_or(|name| name == path)
            {
                continue;
            }
            return Some(PathSpan {
                path_start: start,
                path_end,
                scan_end,
            });
        }

        let scan_end = token_end(text, start);
        let token = &text[start..scan_end];
        let path = token.trim_start_matches(['(', '[', '{', '<']);
        let path_start = scan_end - token.len() + (token.len() - path.len());
        let path_end = trim_path_end(text, path_start, scan_end);
        let raw = token;
        let path = &text[path_start..path_end];
        is_path_candidate(path, raw).then_some(PathSpan {
            path_start,
            path_end,
            scan_end,
        })
    }

    fn is_root_anchored_candidate(&self, path: &str, raw: &str) -> bool {
        !is_excluded_path_syntax(path, raw)
            && self.roots.iter().any(|root| {
                path.strip_prefix(root)
                    .is_some_and(|suffix| suffix.chars().next().is_some_and(is_path_separator))
            })
            && display_name(path).is_some_and(|name| name != path)
    }
}

pub(crate) struct PathSpan {
    path_start: usize,
    path_end: usize,
    scan_end: usize,
}

pub(crate) fn token_end(text: &str, start: usize) -> usize {
    start
        + text[start..]
            .find(char::is_whitespace)
            .unwrap_or(text.len() - start)
}

pub(crate) fn trim_path_end(text: &str, start: usize, mut end: usize) -> usize {
    while end > start
        && text[..end]
            .chars()
            .next_back()
            .is_some_and(is_path_terminator)
    {
        end -= text[..end]
            .chars()
            .next_back()
            .expect("path end has a preceding character")
            .len_utf8();
    }
    end
}

pub(crate) fn is_path_candidate(path: &str, raw: &str) -> bool {
    if is_excluded_path_syntax(path, raw) {
        return false;
    }

    let bytes = path.as_bytes();
    let windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    let windows_unc = path.starts_with(r"\\");
    let posix_absolute = path.starts_with('/') && !path.starts_with("//");

    (windows_drive || windows_unc || posix_absolute)
        && display_name(path).is_some_and(|name| name != path)
}

pub(crate) fn is_excluded_path_syntax(path: &str, raw: &str) -> bool {
    path.is_empty()
        || path.contains("://")
        || path.starts_with("//")
        || path.contains('=')
        || is_dex_or_jvm_identifier(raw)
}

pub(crate) fn is_dex_or_jvm_identifier(raw: &str) -> bool {
    raw.char_indices().any(|(start, ch)| {
        if ch != 'L' {
            return false;
        }

        let descriptor = &raw[start + ch.len_utf8()..];
        descriptor
            .find(';')
            .is_some_and(|end| descriptor[..end].contains('/'))
    })
}

pub(crate) fn display_name(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches(['/', '\\']);
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
}

pub(crate) fn is_path_separator(ch: char) -> bool {
    matches!(ch, '/' | '\\')
}

pub(crate) fn is_path_terminator(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '.' | ',' | ';' | '!' | '?' | ')' | ']' | '}' | '>' | '"' | '\'' | '`'
        )
}

pub(crate) fn is_path_boundary_before(text: &str, index: usize) -> bool {
    index == 0
        || text[..index].chars().next_back().is_some_and(|ch| {
            ch.is_whitespace() || matches!(ch, '"' | '\'' | '`' | '(' | '[' | '{' | '<')
        })
}

pub(crate) fn log_event(event: ProgressEvent) {
    match event {
        ProgressEvent::CommandStarted { input, output, .. } => {
            info!("input: {}", input.display());
            info!("output: {}", output.display());
        }
        ProgressEvent::StageStarted { stage } => {
            info!("{}: start", stage_name(stage));
        }
        ProgressEvent::StageCompleted { stage } => {
            info!("{}: done", stage_name(stage));
        }
        ProgressEvent::ItemStarted {
            stage,
            current,
            total,
            item,
        } => {
            if total > 1 {
                info!("{} [{}/{}] {}", stage_name(stage), current, total, item);
            } else {
                info!("{}: {}", stage_name(stage), item);
            }
        }
        // ItemProgress is consumed by the indicatif renderer in
        // `build_text_sink`; in the bare `log_event` path used by tests and
        // non-interactive callers we deliberately drop it (a tracing line per
        // 1% would flood the log).
        ProgressEvent::ItemProgress { .. } => {}
        ProgressEvent::Message { level, text } => match level {
            MessageLevel::Info => info!("{text}"),
            MessageLevel::Warning => warn!("{text}"),
        },
    }
}

pub(crate) fn print_json_line<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

pub(crate) const SPINNER_TICK_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub(crate) fn unit_label(unit: ProgressUnit) -> &'static str {
    match unit {
        ProgressUnit::Bytes => "bytes",
        ProgressUnit::Ops => "ops",
        ProgressUnit::Blocks => "blocks",
    }
}

/// Build a text-mode sink that wraps `log_event` with an indicatif progress
/// surface. Slow operations during `unpack`/`apply`/`resign` (super partition
/// extraction, OTA payload apply and digest verification on multi-GB
/// partitions, dm-verity hash tree regeneration during `--vendor-spl`) can
/// otherwise leave long gaps between log lines and look frozen on the terminal.
///
/// Behavior:
///   * `StageStarted` / `ItemStarted` → finish any active bar, log the line,
///     then attach a fresh auto-ticking spinner so the user sees the work is
///     alive even before any byte-level progress arrives.
///   * `ItemProgress` → upgrade the spinner to a determinate progress bar
///     the first time progress arrives for that item, then update its
///     position. The bar template shows `[wide_bar] done/total (eta)`.
///   * Other events → finish the active bar before printing so the next
///     `tracing::info!` line lands on a clean row.
///
/// The bar/spinner is suppressed when stderr is not a terminal
/// (`--progress-format jsonl`, redirected/piped invocations, CI).
pub(crate) struct TextSink {
    interactive: bool,
    active_bar: Option<ProgressBar>,
    active_item: Option<String>,
    bar_is_determinate: bool,
    path_shortener: TextPathShortener,
}

pub(crate) fn build_text_sink() -> TextSink {
    TextSink {
        interactive: std::io::stderr().is_terminal(),
        active_bar: None,
        active_item: None,
        bar_is_determinate: false,
        path_shortener: TextPathShortener::default(),
    }
}

impl TextSink {
    fn clear_bar(&mut self) {
        if let Some(pb) = self.active_bar.take() {
            pb.finish_and_clear();
        }
        self.bar_is_determinate = false;
        self.active_item = None;
    }
}

impl EventSink for TextSink {
    fn emit(&mut self, event: ProgressEvent) {
        let event = self.path_shortener.shorten_event(event);
        match &event {
            ProgressEvent::ItemProgress {
                item,
                done,
                total,
                unit,
                ..
            } => {
                if !self.interactive {
                    return;
                }
                let total = *total;
                let done = *done;
                let unit_str = unit_label(*unit);

                let upgrade =
                    !self.bar_is_determinate || self.active_item.as_deref() != Some(item.as_str());
                if upgrade {
                    if let Some(pb) = self.active_bar.take() {
                        pb.finish_and_clear();
                    }
                    let pb = if total == 0 {
                        let pb = ProgressBar::new_spinner();
                        pb.set_style(
                            ProgressStyle::with_template("    {spinner:.cyan} {msg} ({elapsed})")
                                .expect("static spinner template parses")
                                .tick_strings(SPINNER_TICK_FRAMES),
                        );
                        pb.enable_steady_tick(Duration::from_millis(120));
                        pb
                    } else {
                        // For Bytes-flavored progress (the OTA apply weighted-bytes
                        // metric is bytes-like even though it mixes data_length
                        // with a fraction of dst_bytes), use indicatif's
                        // `{decimal_bytes}/{decimal_total_bytes}` formatter so the
                        // numbers render as `120 MB / 1.4 GB` rather than the raw
                        // 12-digit integers a `{pos}/{len}` template would print.
                        // Other units fall back to plain integer counts with the
                        // unit label appended.
                        let template = match unit {
                        ProgressUnit::Bytes => {
                            "    {spinner:.cyan} {msg} [{wide_bar:.cyan/blue}] {decimal_bytes}/{decimal_total_bytes} ({elapsed}, ETA {eta})".to_string()
                        }
                        _ => format!(
                            "    {{spinner:.cyan}} {{msg}} [{{wide_bar:.cyan/blue}}] {{pos}}/{{len}} {} ({{elapsed}}, ETA {{eta}})",
                            unit_str
                        ),
                    };
                        let pb = ProgressBar::new(total);
                        let style = ProgressStyle::with_template(&template)
                            .expect("dynamic bar template parses")
                            .tick_strings(SPINNER_TICK_FRAMES)
                            .progress_chars("##-");
                        pb.set_style(style);
                        pb.enable_steady_tick(Duration::from_millis(200));
                        pb
                    };
                    pb.set_message(item.clone());
                    self.active_bar = Some(pb);
                    self.active_item = Some(item.clone());
                    self.bar_is_determinate = total > 0;
                }
                if let Some(pb) = self.active_bar.as_ref() {
                    if total > 0 {
                        pb.set_length(total);
                        pb.set_position(done);
                    }
                }
            }
            other => {
                if let Some(pb) = self.active_bar.take() {
                    pb.finish_and_clear();
                }
                self.bar_is_determinate = false;
                self.active_item = None;
                let starts_work = matches!(
                    other,
                    ProgressEvent::ItemStarted { .. } | ProgressEvent::StageStarted { .. }
                );
                let item_label = match other {
                    ProgressEvent::ItemStarted { item, .. } => Some(item.clone()),
                    _ => None,
                };
                log_event(event);
                if self.interactive && starts_work {
                    let pb = ProgressBar::new_spinner();
                    pb.set_style(
                        ProgressStyle::with_template("    {spinner:.cyan} {msg} ({elapsed})")
                            .expect("static spinner template parses")
                            .tick_strings(SPINNER_TICK_FRAMES),
                    );
                    pb.set_message(item_label.clone().unwrap_or_else(|| "working…".into()));
                    pb.enable_steady_tick(Duration::from_millis(120));
                    self.active_bar = Some(pb);
                    self.active_item = item_label;
                }
            }
        }
    }

    /// Terminal prompt. Prompts go to stderr so they never mix with the
    /// stdout log stream, and the active spinner is cleared first so its
    /// ticking does not overwrite the question.
    fn prompt(&mut self, prompt: &Prompt) -> PromptReply {
        if !std::io::stdin().is_terminal() {
            return PromptReply::Unavailable;
        }
        self.clear_bar();
        let mut stderr = std::io::stderr().lock();
        let (details, question) = match prompt {
            Prompt::Confirm { details, question } => (details, format!("{question} [y/N] ")),
            Prompt::Continue { details, .. } => (details, String::new()),
        };
        let _ = writeln!(stderr);
        for line in details {
            let _ = writeln!(stderr, "{line}");
        }
        let _ = write!(stderr, "{question}");
        let _ = stderr.flush();
        drop(stderr);

        if let Prompt::Continue {
            reveal: Some(dir), ..
        } = prompt
        {
            reveal_in_file_manager(dir);
        }

        let mut answer = String::new();
        match std::io::stdin().read_line(&mut answer) {
            Ok(0) | Err(_) => PromptReply::Unavailable,
            Ok(_) => match prompt {
                Prompt::Confirm { .. } => {
                    let answer = answer.trim().to_ascii_lowercase();
                    if answer == "y" || answer == "yes" {
                        PromptReply::Accepted
                    } else {
                        PromptReply::Declined
                    }
                }
                Prompt::Continue { .. } => PromptReply::Accepted,
            },
        }
    }
}

/// Open `path` in the host OS file browser. Best-effort — spawn failures
/// are ignored because the prompt already printed the path. Skipped when
/// `DYNOBOX_NO_OPEN` is set so headless or scripted runs don't pop
/// file-manager windows.
pub(crate) fn reveal_in_file_manager(path: &Path) {
    if std::env::var_os("DYNOBOX_NO_OPEN").is_some() {
        return;
    }
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg(path).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(path).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(path).spawn();
}
