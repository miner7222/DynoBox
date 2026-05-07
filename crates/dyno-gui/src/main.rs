//! Dual-mode entry point for DynoBox.
//!
//! Run `dynobox-gui` with **no args** to open the egui front-end.
//! Run it with **any args** (e.g. `dynobox-gui apply --input ... resign`)
//! and it routes argv straight into [`dynobox_cli::cli_main`] in the
//! same process — no sibling `dynobox` binary required, so CI ships a
//! single self-contained executable.
//!
//! On Windows the binary stays in the default `console` subsystem so
//! a parent shell (`cmd`, `pwsh`) properly **waits** for the process
//! to exit before returning the prompt. Explorer / shortcut launches
//! get their auto-allocated console hidden via `GetConsoleProcessList`
//! + `ShowWindow(SW_HIDE)` so the GUI window opens cleanly.
//!
//! # GUI behaviour
//!
//! The front-end is a **command builder**: pickers + toggles produce
//! the same argv the CLI accepts, and the **Run** button spawns the
//! current binary (`std::env::current_exe()`) inside a *new* OS
//! terminal window. The pipeline therefore inherits a real tty —
//! ANSI colours, indicatif progress bars, and the interactive
//! `[y/N]` rollback prompt + `--fuck-lgsi` Enter pause all work the
//! same as a hand-typed CLI run. The GUI doesn't capture stdout /
//! stderr, doesn't ship Continue / Yes / No buttons, and doesn't
//! render a log pane — the terminal owns all that.

#[cfg(unix)]
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use eframe::egui;
use egui::{CentralPanel, ScrollArea};
use egui_extras::DatePickerButton;
use jiff::civil::Date;

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    #[default]
    Apply,
    Unpack,
    Resign,
    Repack,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Apply => "Apply",
            Mode::Unpack => "Unpack",
            Mode::Resign => "Resign",
            Mode::Repack => "Repack",
        }
    }
}

struct DynoGui {
    mode: Mode,

    input: Option<PathBuf>,
    output: Option<PathBuf>,
    ota_zips: Vec<PathBuf>,

    // pipeline-stage toggles (apply / unpack only)
    do_resign: bool,
    do_repack: bool,
    do_complete: bool,

    // resign options (live behind the resign-active guard)
    key: String,
    key_path: Option<PathBuf>,
    force: bool,
    rollback: String,
    boot_spl: String,
    vendor_spl: String,
    boot_spl_date: Date,
    vendor_spl_date: Date,
    fuck_lgsi: bool,
    fuck_lgsi_config: Option<PathBuf>,

    // Last spawn result, surfaced inline next to the Run button so
    // the user knows whether the terminal launched OK.
    last_status: Option<Result<String, String>>,
}

impl Default for DynoGui {
    fn default() -> Self {
        // Reasonable initial date for the SPL pickers; users can
        // either type or pick. The string is what actually feeds the
        // CLI argv.
        let today_default = Date::constant(2026, 1, 1);
        Self {
            mode: Mode::Apply,
            input: None,
            output: None,
            ota_zips: Vec::new(),
            do_resign: true,
            do_repack: true,
            do_complete: true,
            key: String::new(),
            key_path: None,
            force: false,
            rollback: String::new(),
            boot_spl: String::new(),
            vendor_spl: String::new(),
            boot_spl_date: today_default,
            vendor_spl_date: today_default,
            fuck_lgsi: false,
            fuck_lgsi_config: None,
            last_status: None,
        }
    }
}

impl DynoGui {
    /// Whether the resign-options sub-pane should be active.
    fn resign_active(&self) -> bool {
        match self.mode {
            Mode::Resign => true,
            Mode::Apply | Mode::Unpack => self.do_resign,
            Mode::Repack => false,
        }
    }

    fn build_args(&self) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();
        match self.mode {
            Mode::Apply => {
                a.push("apply".into());
                self.push_io_args(&mut a);
                if self.do_resign {
                    a.push("--resign".into());
                }
                if self.do_repack {
                    a.push("--repack".into());
                }
                if self.do_complete {
                    a.push("--complete".into());
                }
                if self.do_resign {
                    self.push_resign_args(&mut a);
                }
                for z in &self.ota_zips {
                    a.push(z.display().to_string());
                }
            }
            Mode::Unpack => {
                a.push("unpack".into());
                self.push_io_args(&mut a);
                if self.do_resign {
                    a.push("--resign".into());
                }
                if self.do_repack {
                    a.push("--repack".into());
                }
                if self.do_complete {
                    a.push("--complete".into());
                }
                if self.do_resign {
                    self.push_resign_args(&mut a);
                }
            }
            Mode::Resign => {
                a.push("resign".into());
                self.push_io_args(&mut a);
                if self.do_repack {
                    a.push("--repack".into());
                }
                self.push_resign_args(&mut a);
            }
            Mode::Repack => {
                a.push("repack".into());
                self.push_io_args(&mut a);
            }
        }
        a
    }

    fn push_io_args(&self, a: &mut Vec<String>) {
        if let Some(p) = &self.input {
            a.push("--input".into());
            a.push(p.display().to_string());
        }
        if let Some(p) = &self.output {
            a.push("--output".into());
            a.push(p.display().to_string());
        }
    }

    fn push_resign_args(&self, a: &mut Vec<String>) {
        // Custom key file picker wins over the text field; if neither
        // is set, fall back to the embedded `testkey_rsa4096`.
        a.push("--key".into());
        let key_arg = if let Some(p) = &self.key_path {
            p.display().to_string()
        } else if !self.key.trim().is_empty() {
            self.key.trim().to_string()
        } else {
            "testkey_rsa4096".to_string()
        };
        a.push(key_arg);
        if self.force {
            a.push("--force".into());
        }
        if !self.rollback.trim().is_empty() {
            a.push("--rollback".into());
            a.push(self.rollback.trim().to_string());
        }
        if !self.boot_spl.trim().is_empty() {
            a.push("--boot-spl".into());
            a.push(self.boot_spl.trim().to_string());
        }
        if !self.vendor_spl.trim().is_empty() {
            a.push("--vendor-spl".into());
            a.push(self.vendor_spl.trim().to_string());
        }
        if self.fuck_lgsi {
            // `--fuck-lgsi` is declared `num_args = 0..=1` with
            // `default_missing_value = ""`; emit the long-form-with-
            // equals so clap binds the value (or empty string)
            // explicitly to the flag instead of swallowing the next
            // positional OTA zip.
            if let Some(p) = &self.fuck_lgsi_config {
                a.push(format!("--fuck-lgsi={}", p.display()));
            } else {
                a.push("--fuck-lgsi=".into());
            }
        }
    }

    fn locate_dynobox_exe() -> PathBuf {
        std::env::current_exe().unwrap_or_else(|_| {
            PathBuf::from(format!("dynobox-gui{}", std::env::consts::EXE_SUFFIX))
        })
    }

    fn run_in_terminal(&mut self) {
        let exe = Self::locate_dynobox_exe();
        let args = self.build_args();
        self.last_status = Some(match spawn_in_terminal(&exe, &args) {
            Ok(()) => Ok(format!("Launched: {} {}", exe.display(), args.join(" "))),
            Err(e) => Err(format!("Spawn failed: {e}")),
        });
    }
}

impl eframe::App for DynoGui {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // `CentralPanel` paints the egui theme's `window_fill`
        // background and claims all remaining space. Drawing straight
        // onto the root `ui` skipped that fill, so eframe's clear
        // colour (near-black) bled through and made the text
        // unreadable.
        CentralPanel::default().show_inside(ui, |ui| {
            ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let row_h = ui.text_style_height(&egui::TextStyle::Heading);
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), row_h),
                        egui::Layout::left_to_right(egui::Align::BOTTOM),
                        |ui| {
                            ui.heading("DynoBox");
                            ui.label(
                                egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                    .weak()
                                    .size(14.0),
                            );
                        },
                    );
                    ui.separator();

                    // Mode selector
                    ui.horizontal(|ui| {
                        ui.label("Mode:");
                        egui::ComboBox::from_id_salt("mode")
                            .selected_text(self.mode.label())
                            .show_ui(ui, |ui| {
                                for m in [Mode::Apply, Mode::Unpack, Mode::Resign, Mode::Repack] {
                                    ui.selectable_value(&mut self.mode, m, m.label());
                                }
                            });
                    });

                    ui.separator();

                    self.io_picker(ui, "Input", true);
                    self.io_picker(ui, "Output", false);

                    ui.separator();

                    match self.mode {
                        Mode::Apply => self.apply_section(ui),
                        Mode::Unpack => self.unpack_section(ui),
                        Mode::Resign | Mode::Repack => {}
                    }

                    if !matches!(self.mode, Mode::Repack) {
                        self.resign_section(ui);
                    }

                    match self.mode {
                        Mode::Apply | Mode::Unpack => {
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.do_repack, "repack");
                                ui.checkbox(&mut self.do_complete, "--complete");
                            });
                        }
                        Mode::Resign => {
                            ui.separator();
                            ui.checkbox(&mut self.do_repack, "repack");
                        }
                        Mode::Repack => {}
                    }

                    ui.separator();
                    self.run_button(ui);
                });
        });
    }
}

impl DynoGui {
    fn io_picker(&mut self, ui: &mut egui::Ui, label: &str, is_input: bool) {
        ui.horizontal(|ui| {
            ui.label(format!("{label}:"));
            if ui.button("📁").clicked()
                && let Some(p) = rfd::FileDialog::new().pick_folder()
            {
                if is_input {
                    self.input = Some(p);
                } else {
                    self.output = Some(p);
                }
            }
            let current = if is_input { &self.input } else { &self.output };
            let text = current
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "—".to_string());
            drag_scroll_path(ui, &text, if is_input { "io-input" } else { "io-output" });
        });
    }

    fn apply_section(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("OTA zips").strong());
        if ui.button("+ Add zip(s)").clicked()
            && let Some(files) = rfd::FileDialog::new()
                .add_filter("ZIP", &["zip"])
                .pick_files()
        {
            self.ota_zips.extend(files);
        }
        // Drag-and-drop reorder. `☰` handle uses `Ui::dnd_drag_source`
        // (payload = original index); the whole row is a
        // `Ui::dnd_drop_zone`. The resulting index swap is applied to
        // `self.ota_zips` so `build_args` emits the new order.
        let mut to_remove: Option<usize> = None;
        let mut drag_from: Option<usize> = None;
        let mut drop_to: Option<usize> = None;
        for (i, z) in self.ota_zips.iter().enumerate() {
            let frame = egui::Frame::default().inner_margin(2.0);
            let (_, dropped) = ui.dnd_drop_zone::<usize, _>(frame, |ui| {
                ui.horizontal(|ui| {
                    if ui.small_button("✖").clicked() {
                        to_remove = Some(i);
                    }
                    ui.dnd_drag_source(egui::Id::new(("ota-zip-handle", i)), i, |ui| {
                        ui.label(egui::RichText::new("☰").monospace());
                    })
                    .response
                    .on_hover_text("Drag to reorder");
                    drag_scroll_path(ui, &z.display().to_string(), &format!("ota-zip-{i}"));
                });
            });
            if let Some(payload) = dropped {
                drag_from = Some(*payload);
                drop_to = Some(i);
            }
        }
        if let Some(i) = to_remove {
            self.ota_zips.remove(i);
        } else if let (Some(f), Some(t)) = (drag_from, drop_to)
            && f != t
            && f < self.ota_zips.len()
        {
            let item = self.ota_zips.remove(f);
            let target = if t > f { t - 1 } else { t };
            let target = target.min(self.ota_zips.len());
            self.ota_zips.insert(target, item);
        }
        ui.separator();
        // Only the resign toggle lives here — repack / --complete
        // moved below the resign-options block (rendered by the
        // top-level update fn) so the visual pipeline reads
        // top-to-bottom: inputs → resign opts → repack / complete.
        ui.checkbox(&mut self.do_resign, "resign");
    }

    fn unpack_section(&mut self, ui: &mut egui::Ui) {
        // Same layout as `apply_section` minus the OTA-zip list.
        ui.checkbox(&mut self.do_resign, "resign");
    }

    fn resign_section(&mut self, ui: &mut egui::Ui) {
        let active = self.resign_active();
        ui.add_enabled_ui(active, |ui| {
            ui.label(egui::RichText::new("Resign options").strong());

            ui.horizontal(|ui| {
                ui.label("--key:");
                ui.add(egui::TextEdit::singleline(&mut self.key).hint_text("testkey_rsa4096"));
                if ui.button("📁").clicked()
                    && let Some(p) = rfd::FileDialog::new().pick_file()
                {
                    self.key_path = Some(p);
                }
                let mut clear_key = false;
                if let Some(p) = &self.key_path {
                    if ui.small_button("✖").clicked() {
                        clear_key = true;
                    }
                    drag_scroll_path(ui, &p.display().to_string(), "key-path");
                }
                if clear_key {
                    self.key_path = None;
                }
            });

            ui.checkbox(&mut self.force, "--force");

            ui.horizontal(|ui| {
                ui.label("Rollback (Unix ts):");
                ui.text_edit_singleline(&mut self.rollback);
            });

            spl_row(
                ui,
                "Boot SPL:",
                &mut self.boot_spl,
                &mut self.boot_spl_date,
                "boot-spl-picker",
            );
            spl_row(
                ui,
                "Vendor SPL:",
                &mut self.vendor_spl,
                &mut self.vendor_spl_date,
                "vendor-spl-picker",
            );

            ui.checkbox(&mut self.fuck_lgsi, "--fuck-lgsi");
            ui.add_enabled_ui(self.fuck_lgsi, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Config JSON:");
                    if ui.button("📁").clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .add_filter("JSON", &["json"])
                            .pick_file()
                    {
                        self.fuck_lgsi_config = Some(p);
                    }
                    let text = self
                        .fuck_lgsi_config
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(interactive — Enter in terminal)".to_string());
                    drag_scroll_path(ui, &text, "fuck-lgsi-config");
                });
            });
        });
    }

    fn run_button(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("▶ Run in terminal").clicked() {
                self.run_in_terminal();
            }
        });
        if let Some(status) = &self.last_status {
            match status {
                Ok(msg) => {
                    ui.label(egui::RichText::new(msg).weak().small());
                }
                Err(msg) => {
                    ui.label(egui::RichText::new(msg).color(egui::Color32::LIGHT_RED));
                }
            }
        }
    }
}

/// Render a single-line monospace path that the user can scroll
/// horizontally by dragging when the text overflows the available
/// width. Replaces `Label::truncate()` for path display so a long
/// `D:\Git\…\input.zip` no longer hides the filename behind an
/// ellipsis. Hover surfaces the full string as a tooltip too.
fn drag_scroll_path(ui: &mut egui::Ui, text: &str, id_salt: &str) {
    let row_h = ui.text_style_height(&egui::TextStyle::Body);
    egui::ScrollArea::horizontal()
        .id_salt(id_salt)
        .max_height(row_h)
        .auto_shrink([false, true])
        .scroll_source(egui::scroll_area::ScrollSource::ALL)
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(egui::RichText::new(text).monospace())
                    .wrap_mode(egui::TextWrapMode::Extend)
                    .selectable(true),
            )
            .on_hover_text(text);
        });
}

/// Shared row layout for the boot/vendor SPL fields: text input with
/// `YYYY-MM-DD` placeholder + a calendar popup that writes the picked
/// date into the same string when changed. `show_icon(false)` drops
/// the auto-appended `📆` glyph so only our explicit `📅` icon shows.
fn spl_row(ui: &mut egui::Ui, label: &str, value: &mut String, date: &mut Date, id_salt: &str) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::TextEdit::singleline(value).hint_text("YYYY-MM-DD"));
        let prev = *date;
        ui.add(
            DatePickerButton::new(date)
                .id_salt(id_salt)
                .format("📅")
                .show_icon(false),
        );
        if *date != prev {
            *value = format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day());
        }
    });
}

/// Spawn `exe args…` inside a brand-new OS terminal window so the
/// pipeline inherits a real tty. The terminal stays open after the
/// pipeline exits so the user can scroll back through the output and
/// answer any interactive prompts (`[y/N]`, the `--fuck-lgsi` Enter
/// pause) directly via stdin.
///
/// * **Windows** — `cmd /C start "" cmd /K <cmdline>` opens a fresh
///   `cmd.exe` window. `/K` keeps the shell alive after the pipeline
///   returns.
/// * **macOS** — write a temp `.command` script and hand it to
///   `open -a Terminal`. macOS `Terminal.app` runs `.command` files
///   like double-clicked shell scripts.
/// * **Linux / *BSD** — write a temp `.sh` script then iterate over
///   the common terminal binaries (`x-terminal-emulator`,
///   `gnome-terminal`, `konsole`, `xfce4-terminal`, `alacritty`,
///   `kitty`, `xterm`) until one spawns.
fn spawn_in_terminal(exe: &Path, args: &[String]) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        // Direct `cmd /C start cmd /K "<line>"` failed because the
        // command-line round-trip through Rust's MSVC quoting +
        // cmd.exe's idiosyncratic `/K` argument parsing mangled the
        // long path arguments — the spawned terminal closed
        // instantly. Going via a temp `.bat` sidesteps both quirks:
        // we control the script's quoting ourselves, and `start`
        // hands the file to the .bat associaton (cmd.exe) which
        // opens a new console window.
        let bat = write_windows_launcher(exe, args)?;
        Command::new("cmd")
            .arg("/C")
            .arg("start")
            .arg("") // empty quoted title (start uses first quoted arg as title)
            .arg(&bat)
            .spawn()?;
        return Ok(());
    }
    #[cfg(unix)]
    {
        let script = write_unix_launcher(exe, args)?;
        #[cfg(target_os = "macos")]
        {
            Command::new("open")
                .arg("-a")
                .arg("Terminal")
                .arg(&script)
                .spawn()?;
            return Ok(());
        }
        #[cfg(not(target_os = "macos"))]
        {
            for term in [
                "x-terminal-emulator",
                "gnome-terminal",
                "konsole",
                "xfce4-terminal",
                "alacritty",
                "kitty",
                "xterm",
            ] {
                if Command::new(term).arg("-e").arg(&script).spawn().is_ok() {
                    return Ok(());
                }
            }
            return Err(std::io::Error::other(
                "no supported terminal emulator found (install xterm or set $TERMINAL)",
            ));
        }
    }
    #[allow(unreachable_code)]
    Err(std::io::Error::other("unsupported platform"))
}

#[cfg(target_os = "windows")]
fn write_windows_launcher(exe: &Path, args: &[String]) -> std::io::Result<PathBuf> {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("dynobox-gui-{pid}-{ts}.bat"));

    // CRLF line endings + UTF-8 console codepage so non-ASCII paths
    // render correctly. `pause >nul` keeps the window open after the
    // pipeline exits so the user can scroll back through output and
    // answer interactive prompts.
    let mut content = String::new();
    content.push_str("@echo off\r\n");
    content.push_str("chcp 65001 >nul\r\n");
    content.push_str("title DynoBox\r\n");
    content.push_str(&quote_bat(&exe.display().to_string()));
    for a in args {
        content.push(' ');
        content.push_str(&quote_bat(a));
    }
    content.push_str("\r\n");
    content.push_str("set DYNOBOX_EXIT=%ERRORLEVEL%\r\n");
    content.push_str("echo.\r\n");
    content.push_str("echo DynoBox finished (exit %DYNOBOX_EXIT%). Press any key to close...\r\n");
    content.push_str("pause >nul\r\n");

    std::fs::write(&path, content)?;
    Ok(path)
}

/// Quote an argument for safe inclusion in a `.bat` script. Wraps in
/// double-quotes whenever the string contains any of the cmd.exe
/// metacharacters; embedded `"` doubles to `""` (the cmd convention
/// for escaping a literal quote inside a quoted string).
#[cfg(target_os = "windows")]
fn quote_bat(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    let needs_quote = s.chars().any(|c| {
        matches!(
            c,
            ' ' | '\t' | '"' | '%' | '&' | '|' | '<' | '>' | '^' | '(' | ')'
        )
    });
    if !needs_quote {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '"' {
            out.push('"');
            out.push('"');
        } else {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

#[cfg(unix)]
fn write_unix_launcher(
    exe: &std::path::Path,
    args: &[String],
) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let suffix = if cfg!(target_os = "macos") {
        "command"
    } else {
        "sh"
    };
    path.push(format!("dynobox-gui-{pid}-{ts}.{suffix}"));

    let mut script = String::new();
    script.push_str("#!/usr/bin/env bash\n");
    script.push_str("set -u\n");
    // Quote the exe + args via single quotes; embedded single quotes
    // escape via `'\''` (POSIX standard).
    script.push_str(&shell_quote(&exe.display().to_string()));
    for a in args {
        script.push(' ');
        script.push_str(&shell_quote(a));
    }
    script.push_str("\nstatus=$?\n");
    script.push_str("echo\n");
    script.push_str(
        "read -rp \"DynoBox finished (exit $status). Press Enter to close...\" _ || true\n",
    );

    let mut f = std::fs::File::create(&path)?;
    f.write_all(script.as_bytes())?;
    f.sync_all()?;
    let mut perm = std::fs::metadata(&path)?.permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&path, perm)?;
    Ok(path)
}

#[cfg(unix)]
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn main() {
    let argv_os: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if argv_os.len() > 1 {
        // CLI mode: hand argv off to the dynobox-cli library entry
        // point in-process. Same effect as if the user ran the
        // (now-unbuilt) standalone `dynobox` binary.
        let code = match dynobox_cli::cli_main(argv_os) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("Error: {e:?}");
                1
            }
        };
        std::process::exit(code);
    }
    #[cfg(target_os = "windows")]
    hide_owned_console();
    if let Err(e) = run_gui() {
        eprintln!("dynobox-gui: {e}");
        std::process::exit(1);
    }
}

fn run_gui() -> eframe::Result {
    eframe::run_native(
        "DynoBox",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([520.0, 720.0]),
            ..Default::default()
        },
        Box::new(|_cc| Ok(Box::new(DynoGui::default()))),
    )
}

/// Hide the attached console window iff we're the only process on it
/// — i.e. Windows allocated a fresh console for our process at startup
/// (Explorer / shortcut launch). When a parent shell is sharing the
/// console (`GetConsoleProcessList` count > 1) we leave it alone so
/// `cmd`/`pwsh`-launched users still see logs and can Ctrl-C.
#[cfg(target_os = "windows")]
fn hide_owned_console() {
    #[allow(unsafe_code)]
    unsafe {
        unsafe extern "system" {
            fn GetConsoleProcessList(buf: *mut u32, count: u32) -> u32;
            fn GetConsoleWindow() -> *mut core::ffi::c_void;
            fn ShowWindow(hwnd: *mut core::ffi::c_void, n_cmd_show: i32) -> i32;
        }
        let mut buf = [0u32; 4];
        let count = GetConsoleProcessList(buf.as_mut_ptr(), buf.len() as u32);
        if count == 1 {
            let hwnd = GetConsoleWindow();
            if !hwnd.is_null() {
                const SW_HIDE: i32 = 0;
                ShowWindow(hwnd, SW_HIDE);
            }
        }
    }
}
