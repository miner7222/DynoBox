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

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use eframe::egui;
use egui::ScrollArea;
use egui_extras::DatePickerButton;
use jiff::civil::Date;
use serde::{Deserialize, Serialize};

mod launcher;
use launcher::spawn_in_terminal;

const HISTORY_STORAGE_KEY: &str = "dynobox_run_history";
const HISTORY_SCHEMA_VERSION: u32 = 1;
const HISTORY_LIMIT: usize = 50;

/// Serde default for the overlay/patch enable toggles: history entries
/// written before those toggles existed always applied their lists, so
/// they restore enabled.
fn default_true() -> bool {
    true
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum Mode {
    #[default]
    Apply,
    Unpack,
    Resign,
    Repack,
    Ota,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FormSnapshot {
    schema_version: u32,
    /// RFC 3339 timestamp of when this snapshot was saved. Older entries
    /// deserialize with an empty string.
    #[serde(default)]
    created_at: String,
    mode: Mode,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    integrity_key: Option<PathBuf>,
    ota_zips: Vec<PathBuf>,
    do_resign: bool,
    do_repack: bool,
    do_complete: bool,
    key: String,
    key_path: Option<PathBuf>,
    force: bool,
    rollback: String,
    boot_spl: String,
    vendor_spl: String,
    system_spl: String,
    fuck_lgsi: bool,
    fuck_lgsi_config: Option<PathBuf>,
    debloat: bool,
    debloat_list: Option<PathBuf>,
    #[serde(default)]
    add_overlays: Vec<PathBuf>,
    #[serde(default = "default_true")]
    add_overlays_enabled: bool,
    #[serde(default)]
    add_spoof: Option<PathBuf>,
    #[serde(default)]
    add_spoof_enabled: bool,
    #[serde(default)]
    info: bool,
    plus_patches: Vec<PathBuf>,
    #[serde(default = "default_true")]
    plus_patches_enabled: bool,
    #[serde(default)]
    ota: OtaForm,
}

/// `ota generate` inputs, kept apart from the pipeline modes' fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct OtaForm {
    /// Build now on the device; `None` makes a full OTA.
    source: Option<PathBuf>,
    target: Option<PathBuf>,
    reference: Option<PathBuf>,
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
    output: Option<PathBuf>,
    delta: bool,
    allow_avb_mismatch: bool,
    /// Partitions to leave out, comma or space separated.
    exclude: String,
}

impl FormSnapshot {
    fn capture(gui: &DynoGui) -> Self {
        Self {
            schema_version: HISTORY_SCHEMA_VERSION,
            created_at: jiff::Timestamp::now().to_string(),
            mode: gui.mode,
            input: gui.input.clone(),
            output: gui.output.clone(),
            integrity_key: gui.integrity_key.clone(),
            ota_zips: gui.ota_zips.clone(),
            do_resign: gui.do_resign,
            do_repack: gui.do_repack,
            do_complete: gui.do_complete,
            key: gui.key.clone(),
            key_path: gui.key_path.clone(),
            force: gui.force,
            rollback: gui.rollback.clone(),
            boot_spl: gui.boot_spl.clone(),
            vendor_spl: gui.vendor_spl.clone(),
            system_spl: gui.system_spl.clone(),
            fuck_lgsi: gui.fuck_lgsi,
            fuck_lgsi_config: gui.fuck_lgsi_config.clone(),
            debloat: gui.debloat,
            debloat_list: gui.debloat_list.clone(),
            add_overlays: gui.add_overlays.clone(),
            add_overlays_enabled: gui.add_overlays_enabled,
            add_spoof: gui.add_spoof.clone(),
            add_spoof_enabled: gui.add_spoof_enabled,
            info: gui.info,
            plus_patches: gui.plus_patches.clone(),
            plus_patches_enabled: gui.plus_patches_enabled,
            ota: gui.ota.clone(),
        }
    }

    fn restore_form(&self, gui: &mut DynoGui) {
        gui.mode = self.mode;
        gui.input.clone_from(&self.input);
        gui.output.clone_from(&self.output);
        gui.integrity_key.clone_from(&self.integrity_key);
        gui.ota_zips.clone_from(&self.ota_zips);
        gui.do_resign = self.do_resign;
        gui.do_repack = self.do_repack;
        gui.do_complete = self.do_complete;
        gui.key.clone_from(&self.key);
        gui.key_path.clone_from(&self.key_path);
        gui.force = self.force;
        gui.rollback.clone_from(&self.rollback);
        gui.boot_spl.clone_from(&self.boot_spl);
        gui.vendor_spl.clone_from(&self.vendor_spl);
        gui.system_spl.clone_from(&self.system_spl);
        gui.boot_spl_date = restored_spl_date(&self.boot_spl);
        gui.vendor_spl_date = restored_spl_date(&self.vendor_spl);
        gui.system_spl_date = restored_spl_date(&self.system_spl);
        gui.fuck_lgsi = self.fuck_lgsi;
        gui.fuck_lgsi_config.clone_from(&self.fuck_lgsi_config);
        gui.debloat = self.debloat;
        gui.debloat_list.clone_from(&self.debloat_list);
        gui.add_overlays.clone_from(&self.add_overlays);
        gui.add_overlays_enabled = self.add_overlays_enabled;
        gui.add_spoof.clone_from(&self.add_spoof);
        gui.add_spoof_enabled = self.add_spoof_enabled;
        gui.info = self.info;
        gui.plus_patches.clone_from(&self.plus_patches);
        gui.plus_patches_enabled = self.plus_patches_enabled;
        gui.ota.clone_from(&self.ota);
    }

    fn command_line(&self) -> String {
        let mut gui = DynoGui::default();
        self.restore_form(&mut gui);
        gui.build_args().join(" ")
    }

    /// Equality for de-duplication: the save timestamp must not make two
    /// otherwise identical forms look different.
    fn same_form(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.created_at.clear();
        b.created_at.clear();
        a == b
    }
}

#[derive(Default)]
struct RunHistory {
    entries: Vec<FormSnapshot>,
}

impl RunHistory {
    fn from_json(payload: &str) -> Self {
        let Ok(mut entries) = serde_json::from_str::<Vec<FormSnapshot>>(payload) else {
            return Self::default();
        };
        entries.retain(|entry| entry.schema_version == HISTORY_SCHEMA_VERSION);
        entries.truncate(HISTORY_LIMIT);
        Self { entries }
    }

    fn to_json(&self) -> Option<String> {
        serde_json::to_string(&self.entries).ok()
    }

    fn insert(&mut self, snapshot: FormSnapshot) {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.same_form(&snapshot))
        {
            self.entries.remove(index);
        }
        self.entries.insert(0, snapshot);
        self.entries.truncate(HISTORY_LIMIT);
    }

    /// Entries run in `mode`, newest first, with their index in `entries`.
    fn for_mode(&self, mode: Mode) -> impl Iterator<Item = (usize, &FormSnapshot)> {
        self.entries
            .iter()
            .enumerate()
            .filter(move |(_, entry)| entry.mode == mode)
    }

    fn delete(&mut self, index: usize) {
        if index < self.entries.len() {
            self.entries.remove(index);
        }
    }
}

#[derive(Default)]
struct MissingPaths {
    paths: HashSet<PathBuf>,
}

impl MissingPaths {
    fn classify(snapshot: &FormSnapshot) -> Self {
        let mut paths = HashSet::new();
        let candidates = snapshot
            .input
            .iter()
            .chain(snapshot.integrity_key.iter())
            .chain(snapshot.ota_zips.iter())
            .chain(snapshot.key_path.iter())
            .chain(snapshot.fuck_lgsi_config.iter())
            .chain(snapshot.debloat_list.iter())
            .chain(snapshot.add_overlays.iter())
            .chain(snapshot.add_spoof.iter())
            .chain(snapshot.plus_patches.iter())
            .chain(snapshot.ota.source.iter())
            .chain(snapshot.ota.target.iter())
            .chain(snapshot.ota.reference.iter())
            .chain(snapshot.ota.key.iter())
            .chain(snapshot.ota.cert.iter());
        paths.extend(candidates.filter(|path| !path.exists()).cloned());
        Self { paths }
    }

    fn contains(&self, path: &Path) -> bool {
        self.paths.contains(path)
    }
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Apply => "Apply",
            Mode::Unpack => "Unpack",
            Mode::Resign => "Resign",
            Mode::Repack => "Repack",
            Mode::Ota => "OTA",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Mode::Apply => "Unpack, apply OTA zip(s), then optionally resign and repack.",
            Mode::Unpack => "Extract payload, super, and partition images.",
            Mode::Resign => "Sign partitions with custom keys, patches, and overlays.",
            Mode::Repack => "Rebuild partition images and super/payload.",
            Mode::Ota => "Generate a full or incremental signed OTA package.",
        }
    }

    fn all() -> [Mode; 5] {
        [
            Mode::Apply,
            Mode::Unpack,
            Mode::Resign,
            Mode::Repack,
            Mode::Ota,
        ]
    }
}

struct DynoGui {
    mode: Mode,

    input: Option<PathBuf>,
    output: Option<PathBuf>,
    integrity_key: Option<PathBuf>,
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
    system_spl: String,
    boot_spl_date: Date,
    vendor_spl_date: Date,
    system_spl_date: Date,
    fuck_lgsi: bool,
    fuck_lgsi_config: Option<PathBuf>,
    debloat: bool,
    debloat_list: Option<PathBuf>,
    add_overlays: Vec<PathBuf>,
    add_overlays_enabled: bool,
    add_spoof: Option<PathBuf>,
    add_spoof_enabled: bool,
    info: bool,
    plus_patches: Vec<PathBuf>,
    plus_patches_enabled: bool,

    ota: OtaForm,

    // Last spawn result, surfaced inline next to the Run button so
    // the user knows whether the terminal launched OK.
    last_status: Option<Result<String, String>>,
    // Command line of the last successful launch. The "command" link
    // next to the Run button opens it in a popup with a copy button.
    last_command: Option<String>,
    command_open: bool,
    command_copied: bool,

    history: RunHistory,
    history_open: bool,
    history_filter: String,
    reset_confirm: bool,
    overlay_manager_open: bool,
    patch_manager_open: bool,
    missing_paths: MissingPaths,
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
            integrity_key: None,
            ota_zips: Vec::new(),
            // `resign` toggle is opt-in for Apply / Unpack / Repack;
            // Resign mode itself ignores this flag and always runs
            // the resign stage, so the default-off keeps casual
            // unpack / apply runs from inadvertently re-signing.
            do_resign: false,
            do_repack: true,
            do_complete: true,
            key: String::new(),
            key_path: None,
            force: false,
            rollback: String::new(),
            boot_spl: String::new(),
            vendor_spl: String::new(),
            system_spl: String::new(),
            boot_spl_date: today_default,
            vendor_spl_date: today_default,
            system_spl_date: today_default,
            fuck_lgsi: false,
            fuck_lgsi_config: None,
            debloat: false,
            debloat_list: None,
            add_overlays: Vec::new(),
            add_overlays_enabled: true,
            add_spoof: None,
            add_spoof_enabled: false,
            info: false,
            plus_patches: Vec::new(),
            plus_patches_enabled: true,
            ota: OtaForm::default(),
            last_status: None,
            last_command: None,
            command_open: false,
            command_copied: false,
            history: RunHistory::default(),
            history_open: false,
            history_filter: String::new(),
            reset_confirm: false,
            overlay_manager_open: false,
            patch_manager_open: false,
            missing_paths: MissingPaths::default(),
        }
    }
}

impl DynoGui {
    /// Whether the resign-options sub-pane should be active.
    fn resign_active(&self) -> bool {
        match self.mode {
            Mode::Resign => true,
            Mode::Apply | Mode::Unpack => self.do_resign,
            Mode::Repack | Mode::Ota => false,
        }
    }

    /// True when a flag will wait for input in the terminal.
    fn has_interactive_flags(&self) -> bool {
        self.resign_active()
            && ((self.fuck_lgsi && self.fuck_lgsi_config.is_none())
                || (self.debloat && self.debloat_list.is_none()))
    }

    /// The argv the current form would launch, prefixed with the CLI name.
    fn preview_command(&self) -> String {
        let mut out = String::from("dynobox");
        for arg in self.build_args() {
            out.push(' ');
            out.push_str(&arg);
        }
        out
    }

    /// Reset every form field while keeping the current mode and history.
    fn reset_form(&mut self) {
        let mode = self.mode;
        let history = std::mem::take(&mut self.history);
        let history_open = self.history_open;
        *self = Self::default();
        self.mode = mode;
        self.history = history;
        self.history_open = history_open;
        self.reset_confirm = false;
    }

    fn apply_shortcuts(&mut self, ctx: &egui::Context) {
        let (run, history, mode) = ctx.input(|i| {
            let run = i.modifiers.command && i.key_pressed(egui::Key::Enter);
            let history = i.modifiers.command && i.key_pressed(egui::Key::H);
            let mut mode = None;
            if i.modifiers.alt {
                for (index, key) in [
                    egui::Key::Num1,
                    egui::Key::Num2,
                    egui::Key::Num3,
                    egui::Key::Num4,
                    egui::Key::Num5,
                ]
                .iter()
                .enumerate()
                {
                    if i.key_pressed(*key) {
                        mode = Some(Mode::all()[index]);
                    }
                }
            }
            (run, history, mode)
        });
        if let Some(mode) = mode {
            self.mode = mode;
        }
        if history {
            self.history_open = !self.history_open;
        }
        if run && self.validate_for_run().is_ok() {
            self.run_in_terminal();
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
                if self.info {
                    a.push("--info".into());
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
                if self.info {
                    a.push("--info".into());
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
                // `--info` is an Apply/Unpack-only toggle in the GUI; do not
                // leak a stale value into a Resign command.
                self.push_resign_args(&mut a);
            }
            Mode::Repack => {
                a.push("repack".into());
                self.push_io_args(&mut a);
            }
            Mode::Ota => self.push_ota_args(&mut a),
        }
        a
    }

    fn push_ota_args(&self, a: &mut Vec<String>) {
        a.push("ota".into());
        a.push("generate".into());
        let ota = &self.ota;
        for (flag, path) in [
            ("--source", &ota.source),
            ("--target", &ota.target),
            ("--reference", &ota.reference),
            ("--key", &ota.key),
            ("--cert", &ota.cert),
            ("--output", &ota.output),
        ] {
            if let Some(path) = path {
                a.push(flag.into());
                a.push(path.display().to_string());
            }
        }
        // `--delta` needs a source build to diff against.
        if ota.delta && ota.source.is_some() {
            a.push("--delta".into());
        }
        if ota.allow_avb_mismatch {
            a.push("--allow-avb-mismatch".into());
        }
        for name in ota
            .exclude
            .split([',', ' ', '\t'])
            .filter(|n| !n.is_empty())
        {
            a.push(format!("--exclude={name}"));
        }
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
        if let Some(p) = &self.integrity_key {
            a.push("--integrity-key".into());
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
        if !self.system_spl.trim().is_empty() {
            a.push("--system-spl".into());
            a.push(self.system_spl.trim().to_string());
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
        if self.debloat {
            // Same `num_args = 0..=1` binding rule as `--fuck-lgsi`: attach
            // the optional list file with `=` so a bare toggle stays
            // interactive without swallowing the next positional argument.
            if let Some(p) = &self.debloat_list {
                a.push(format!("--debloat={}", p.display()));
            } else {
                a.push("--debloat=".into());
            }
        }
        if self.plus_patches_enabled {
            for patch in &self.plus_patches {
                a.push(format!("--plus={}", patch.display()));
            }
        }
        if self.add_overlays_enabled {
            for overlay in &self.add_overlays {
                a.push(format!("--add-overlay={}", overlay.display()));
            }
        }
        if self.add_spoof_enabled
            && let Some(spoof) = &self.add_spoof
        {
            a.push(format!("--add-spoof={}", spoof.display()));
        }
    }

    fn locate_dynobox_exe() -> PathBuf {
        std::env::current_exe().unwrap_or_else(|_| {
            PathBuf::from(format!("dynobox-gui{}", std::env::consts::EXE_SUFFIX))
        })
    }

    fn run_in_terminal(&mut self) {
        // Pre-flight the obvious empty-required-field cases before
        // we bother spawning a terminal. The CLI would catch these
        // too, but on Windows the spawned `.bat` only pauses on a
        // successful exit — a clap parse error flashes by quickly
        // and the user has no idea what they did wrong. Surfacing
        // the validation inline in the GUI is friendlier.
        if let Err(msg) = self.validate_for_run() {
            self.last_status = Some(Err(msg));
            return;
        }
        self.missing_paths = MissingPaths::classify(&FormSnapshot::capture(self));
        let exe = Self::locate_dynobox_exe();
        let args = self.build_args();
        match spawn_in_terminal(&exe, &args) {
            Ok(()) => {
                self.history.insert(FormSnapshot::capture(self));
                self.last_command = Some(format!("{} {}", exe.display(), args.join(" ")));
                self.last_status =
                    Some(Ok("Launched in terminal — check the console window.".into()));
            }
            Err(e) => self.last_status = Some(Err(format!("Spawn failed: {e}"))),
        }
    }

    /// Return `Err(msg)` when the current control state would
    /// guarantee a CLI parse / pipeline failure. `Ok(())` lets
    /// `run_in_terminal` proceed.
    fn validate_for_run(&self) -> Result<(), String> {
        if matches!(self.mode, Mode::Ota) {
            let ota = &self.ota;
            for (unset, what) in [
                (ota.target.is_none(), "target build directory"),
                (ota.reference.is_none(), "reference OTA zip"),
                (ota.key.is_none(), "OTA signing key"),
                (ota.cert.is_none(), "OTA certificate"),
                (ota.output.is_none(), "output OTA zip"),
            ] {
                if unset {
                    return Err(format!("Missing {what}"));
                }
            }
            return Ok(());
        }
        if self.input.is_none() {
            return Err("Missing --input directory".into());
        }
        if matches!(self.mode, Mode::Apply) && self.ota_zips.is_empty() {
            return Err("Apply mode needs at least one OTA zip".into());
        }
        Ok(())
    }
}

impl eframe::App for DynoGui {
    #[allow(deprecated)]
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.apply_shortcuts(ui.ctx());

        egui::CentralPanel::default().show_inside(ui, |ui| {
            // One container width for the header, action bar, and body so the
            // right edge stays aligned when the window grows.
            let content_w = (ui.available_width() - 4.0).min(760.0);
            ui.set_max_width(content_w);

            self.render_top_bar(ui);
            ui.separator();
            self.render_action_bar(ui);
            ui.separator();
            if self.history_open {
                self.render_history(ui);
            } else {
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_max_width(content_w);
                        self.render_form(ui);
                    });
            }
        });

        self.command_window(ui.ctx());
        self.overlay_manager_window(ui.ctx());
        self.patch_manager_window(ui.ctx());
        self.reset_window(ui.ctx());
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if let Some(payload) = self.history.to_json() {
            storage.set_string(HISTORY_STORAGE_KEY, payload);
        }
    }

    fn persist_egui_memory(&self) -> bool {
        false
    }
}

impl DynoGui {
    fn from_storage(storage: Option<&dyn eframe::Storage>) -> Self {
        let mut gui = Self::default();
        if let Some(payload) = storage.and_then(|storage| storage.get_string(HISTORY_STORAGE_KEY)) {
            gui.history = RunHistory::from_json(&payload);
        }
        gui
    }

    fn load_history_entry(&mut self, snapshot: &FormSnapshot) {
        self.missing_paths = MissingPaths::classify(snapshot);
        snapshot.restore_form(self);
        self.last_status = None;
        self.history_open = false;
    }

    fn render_history(&mut self, ui: &mut egui::Ui) {
        let mode = self.mode;
        let mut load = None;
        let mut delete = None;
        let mut copy = None;
        // The inline view lives inside the panel, so its own available width is
        // the trustworthy one; cap it so the column does not stretch on wide
        // windows.
        let content_w = ui.available_width().min(680.0);
        ui.set_max_width(content_w);

        ui.horizontal(|ui| {
            ui.heading("Run history");
            ui.label(egui::RichText::new(mode.label()).small().weak());
            if ui
                .small_button("Back to form")
                .on_hover_text("Close history (Ctrl+H)")
                .clicked()
            {
                self.history_open = false;
            }
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Filter:");
            let clear_w = if self.history_filter.is_empty() {
                0.0
            } else {
                56.0
            };
            let filter_w = (content_w - 64.0 - clear_w).max(120.0);
            ui.add_sized(
                [filter_w, 24.0],
                egui::TextEdit::singleline(&mut self.history_filter)
                    .hint_text("folder, key, or patch..."),
            );
            if !self.history_filter.is_empty() && ui.small_button("Clear").clicked() {
                self.history_filter.clear();
            }
        });
        ui.separator();

        let filter = self.history_filter.to_lowercase();
        let entries: Vec<(usize, FormSnapshot)> = self
            .history
            .for_mode(mode)
            .filter(|(_, entry)| {
                filter.is_empty()
                    || entry.command_line().to_lowercase().contains(&filter)
                    || history_title(entry).to_lowercase().contains(&filter)
            })
            .map(|(index, entry)| (index, entry.clone()))
            .collect();

        if entries.is_empty() {
            ui.label(egui::RichText::new("No matching runs").weak());
            return;
        }

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (index, entry) in entries {
                    egui::Frame::group(ui.style())
                        .fill(egui::Color32::from_rgb(250, 251, 253))
                        .stroke(egui::Stroke::new(
                            1.0,
                            egui::Color32::from_rgb(216, 222, 228),
                        ))
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            // `Frame` adds its own margins; using the inner
                            // available width keeps the right border on screen.
                            ui.set_width(ui.available_width());
                            let title = format!("#{}  {}", index + 1, history_title(&entry));
                            ui.add(
                                egui::Label::new(egui::RichText::new(&title).strong()).truncate(),
                            )
                            .on_hover_text(&title);
                            ui.horizontal(|ui| {
                                if ui.small_button("Load").clicked() {
                                    load = Some(entry.clone());
                                }
                                if ui.small_button("Copy").clicked() {
                                    copy = Some(entry.command_line());
                                }
                                if ui.small_button("Remove").clicked() {
                                    delete = Some(index);
                                }
                            });
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(history_badges(&entry)).small().weak(),
                                )
                                .wrap_mode(egui::TextWrapMode::Wrap),
                            );
                            egui::CollapsingHeader::new(
                                egui::RichText::new("Show full command").small(),
                            )
                            .id_salt(("history-command", index))
                            .show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(entry.command_line())
                                            .monospace()
                                            .small(),
                                    )
                                    .wrap_mode(egui::TextWrapMode::Wrap),
                                );
                            });
                        });
                    ui.add_space(4.0);
                }
            });

        if let Some(command) = copy {
            ui.ctx().copy_text(command);
        }
        if let Some(index) = delete {
            self.history.delete(index);
        } else if let Some(snapshot) = load {
            self.load_history_entry(&snapshot);
        }
    }

    fn command_window(&mut self, ctx: &egui::Context) {
        if !self.command_open {
            return;
        }
        let mut open = self.command_open;
        let args = self.build_args();
        let command = self.preview_command();
        egui::Window::new("Command preview")
            .open(&mut open)
            .default_size([620.0, 420.0])
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Copy full command").clicked() {
                        ui.ctx().copy_text(command.clone());
                        self.command_copied = true;
                    }
                    if self.command_copied {
                        ui.label(egui::RichText::new("copied to clipboard").weak().small());
                    }
                    ui.label(
                        egui::RichText::new(format!("{} args", args.len()))
                            .weak()
                            .small(),
                    );
                });
                ui.separator();
                ScrollArea::vertical().show(ui, |ui| {
                    ui.label(egui::RichText::new("dynobox").monospace().strong());
                    for arg in &args {
                        ui.label(egui::RichText::new(arg).monospace().small());
                    }
                });
            });
        self.command_open = open;
    }

    fn overlay_manager_window(&mut self, ctx: &egui::Context) {
        if !self.overlay_manager_open {
            return;
        }
        let mut open = self.overlay_manager_open;
        let mut remove = None;
        egui::Window::new("Overlay APKs (--add-overlay)")
            .open(&mut open)
            .default_size([600.0, 360.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(format!("{} APK(s)", self.add_overlays.len())).strong(),
                    );
                    if !self.add_overlays.is_empty() && ui.small_button("Clear all").clicked() {
                        self.add_overlays.clear();
                    }
                });
                ui.separator();
                if self.add_overlays.is_empty() {
                    ui.label(egui::RichText::new("No overlay APKs added").weak());
                } else {
                    ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                        for (index, path) in self.add_overlays.iter().enumerate() {
                            ui.horizontal(|ui| {
                                if ui.small_button("Remove").on_hover_text("Remove").clicked() {
                                    remove = Some(index);
                                }
                                path_display(
                                    ui,
                                    Some(path),
                                    self.missing_paths.contains(path),
                                    "",
                                    320.0,
                                );
                            });
                        }
                    });
                }
                ui.separator();
                if ui.button("Add files...").clicked()
                    && let Some(paths) = list_dialog(&self.add_overlays)
                        .add_filter("Android package", &["apk"])
                        .pick_files()
                {
                    for path in paths {
                        if !self.add_overlays.contains(&path) {
                            self.add_overlays.push(path);
                        }
                    }
                }
            });
        self.overlay_manager_open = open;
        if let Some(index) = remove {
            self.add_overlays.remove(index);
        }
    }

    fn patch_manager_window(&mut self, ctx: &egui::Context) {
        if !self.patch_manager_open {
            return;
        }
        let mut open = self.patch_manager_open;
        let mut remove = None;
        egui::Window::new("External patches (--plus)")
            .open(&mut open)
            .default_size([600.0, 360.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(format!("{} patch(es)", self.plus_patches.len()))
                            .strong(),
                    );
                    if !self.plus_patches.is_empty() && ui.small_button("Clear all").clicked() {
                        self.plus_patches.clear();
                    }
                });
                ui.separator();
                if self.plus_patches.is_empty() {
                    ui.label(egui::RichText::new("No external patches added").weak());
                } else {
                    ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                        for (index, path) in self.plus_patches.iter().enumerate() {
                            ui.horizontal(|ui| {
                                if ui.small_button("Remove").on_hover_text("Remove").clicked() {
                                    remove = Some(index);
                                }
                                path_display(
                                    ui,
                                    Some(path),
                                    self.missing_paths.contains(path),
                                    "",
                                    320.0,
                                );
                            });
                        }
                    });
                }
                ui.separator();
                if ui.button("Add .dbp files...").clicked()
                    && let Some(paths) = list_dialog(&self.plus_patches)
                        .add_filter("DynoBox patch", &["dbp"])
                        .pick_files()
                {
                    for path in paths {
                        if !self.plus_patches.contains(&path) {
                            self.plus_patches.push(path);
                        }
                    }
                }
            });
        self.patch_manager_open = open;
        if let Some(index) = remove {
            self.plus_patches.remove(index);
        }
    }

    fn reset_window(&mut self, ctx: &egui::Context) {
        if !self.reset_confirm {
            return;
        }
        egui::Window::new("Reset form?")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label("Clear every field in the current form?");
                ui.label(
                    egui::RichText::new("History entries are kept.")
                        .weak()
                        .small(),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Reset").clicked() {
                        self.reset_form();
                    }
                    if ui.button("Cancel").clicked() {
                        self.reset_confirm = false;
                    }
                });
            });
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("DynoBox");
            ui.label(
                egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .weak()
                    .small(),
            );
            ui.add_space(12.0);
            if ui
                .button(format!(
                    "History ({})",
                    self.history.for_mode(self.mode).count()
                ))
                .on_hover_text("Show saved runs for this mode (Ctrl+H)")
                .clicked()
            {
                self.history_open = true;
            }
            if ui
                .button(if self.reset_confirm {
                    "Confirm reset"
                } else {
                    "Reset"
                })
                .on_hover_text("Clear all form fields")
                .clicked()
            {
                self.reset_confirm = true;
            }
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            for mode in Mode::all() {
                let response = ui
                    .selectable_label(self.mode == mode, mode.label())
                    .on_hover_text(format!("Alt+{}", mode_number(mode)));
                if response.clicked() {
                    self.mode = mode;
                }
            }
        });
        ui.add(
            egui::Label::new(
                egui::RichText::new(self.mode.description())
                    .small()
                    .color(egui::Color32::from_rgb(89, 99, 110)),
            )
            .truncate(),
        )
        .on_hover_text(self.mode.description());
    }

    fn render_action_bar(&mut self, ui: &mut egui::Ui) {
        let validation = self.validate_for_run();
        let args = self.build_args();
        let command = self.preview_command();
        let can_run = validation.is_ok();

        let mut status = match &validation {
            Ok(()) => "Ready".to_string(),
            Err(message) => format!("! {message}"),
        };
        if validation.is_ok() && self.has_interactive_flags() {
            status.push_str(" · interactive");
        }
        if let Some(last) = &self.last_status {
            status.push_str(" · ");
            status.push_str(match last {
                Ok(message) | Err(message) => message,
            });
        }

        ui.horizontal(|ui| {
            let status_color = if validation.is_ok() {
                egui::Color32::from_rgb(26, 127, 55)
            } else {
                egui::Color32::from_rgb(207, 34, 46)
            };
            if validation.is_ok() {
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.0, status_color);
            }
            let status_display = truncate_command(&status, 28);
            ui.label(
                egui::RichText::new(&status_display)
                    .strong()
                    .small()
                    .color(status_color),
            )
            .on_hover_text(&status);

            let run = ui
                .add_enabled(
                    can_run,
                    egui::Button::new(egui::RichText::new("▶ Run").strong()),
                )
                .on_hover_text("Run in terminal (Ctrl+Enter)");
            if run.clicked() {
                self.run_in_terminal();
            }
            if ui
                .small_button(format!("Args ({})", args.len()))
                .on_hover_text("Inspect the full argv before running")
                .clicked()
            {
                self.command_open = true;
                self.command_copied = false;
            }
            if ui
                .small_button("Copy")
                .on_hover_text("Copy the full command line")
                .clicked()
            {
                ui.ctx().copy_text(command.clone());
            }
        });
        ui.add_space(2.0);
        ui.add(
            egui::Label::new(
                egui::RichText::new(truncate_command(&command, 96))
                    .monospace()
                    .small()
                    .color(egui::Color32::from_rgb(89, 99, 110)),
            )
            .truncate(),
        )
        .on_hover_text(&command);
    }

    fn render_form(&mut self, ui: &mut egui::Ui) {
        if matches!(self.mode, Mode::Ota) {
            self.render_ota_form(ui);
            return;
        }

        self.render_core_io(ui);
        if matches!(self.mode, Mode::Apply) {
            self.render_ota_zips(ui);
        }
        if matches!(self.mode, Mode::Apply | Mode::Unpack) {
            self.render_info_toggle(ui);
        }
        if matches!(self.mode, Mode::Apply | Mode::Unpack | Mode::Resign) {
            self.render_resign_group(ui);
        }
        match self.mode {
            Mode::Apply | Mode::Unpack => self.render_repack_complete(ui),
            Mode::Resign => self.render_repack_only(ui),
            Mode::Repack => self.render_repack_info(ui),
            Mode::Ota => {}
        }
    }

    fn render_core_io(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "CORE I/O");
        egui::Grid::new("core_io_grid")
            .num_columns(2)
            .min_col_width(115.0)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Input *").strong());
                path_control(
                    ui,
                    &mut self.input,
                    PathKind::Folder,
                    "io-input",
                    &self.missing_paths,
                    "Required",
                );
                ui.end_row();

                ui.label("Output");
                path_control(
                    ui,
                    &mut self.output,
                    PathKind::Folder,
                    "io-output",
                    &self.missing_paths,
                    "Optional",
                );
                ui.end_row();

                ui.label("Manifest key");
                path_control(
                    ui,
                    &mut self.integrity_key,
                    PathKind::Open("PEM private key", &["pem"]),
                    "integrity-key",
                    &self.missing_paths,
                    "Optional",
                );
                ui.end_row();
            });
    }

    fn render_ota_zips(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("OTA ZIPS *").strong().size(12.5));
            ui.add_space(8.0);
            if ui.button("+ Add zip(s)").clicked()
                && let Some(files) = list_dialog(&self.ota_zips)
                    .add_filter("ZIP", &["zip"])
                    .pick_files()
            {
                self.ota_zips.extend(files);
            }
            ui.label(
                egui::RichText::new(format!("{} file(s)", self.ota_zips.len()))
                    .small()
                    .weak(),
            );
        });
        if self.ota_zips.is_empty() {
            ui.label(
                egui::RichText::new("Required — add at least one OTA zip.")
                    .small()
                    .color(egui::Color32::from_rgb(207, 34, 46)),
            );
            return;
        }

        let mut to_remove: Option<usize> = None;
        let mut drag_from: Option<usize> = None;
        let mut drop_to: Option<usize> = None;
        for (index, zip) in self.ota_zips.iter().enumerate() {
            let frame = egui::Frame::default().inner_margin(2.0);
            let (_, dropped) = ui.dnd_drop_zone::<usize, _>(frame, |ui| {
                ui.horizontal(|ui| {
                    if ui.small_button("Remove").clicked() {
                        to_remove = Some(index);
                    }
                    ui.dnd_drag_source(egui::Id::new(("ota-zip-handle", index)), index, |ui| {
                        ui.label(egui::RichText::new("::").monospace().weak());
                    })
                    .response
                    .on_hover_text("Drag to reorder");
                    let budget = (ui.available_width() - 8.0).clamp(120.0, 360.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(budget, 24.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            path_display(
                                ui,
                                Some(zip),
                                self.missing_paths.contains(zip),
                                "",
                                320.0,
                            );
                        },
                    );
                });
            });
            if let Some(payload) = dropped {
                drag_from = Some(*payload);
                drop_to = Some(index);
            }
        }
        if let Some(index) = to_remove {
            self.ota_zips.remove(index);
        } else if let (Some(from), Some(to)) = (drag_from, drop_to)
            && from != to
            && from < self.ota_zips.len()
        {
            let item = self.ota_zips.remove(from);
            let target = if to > from { to - 1 } else { to };
            let target = target.min(self.ota_zips.len());
            self.ota_zips.insert(target, item);
        }
    }

    fn render_info_toggle(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.info, "--info");
            ui.label(
                egui::RichText::new("Write blobs.txt + lgsi_features.json to the output.")
                    .small()
                    .weak(),
            );
        });
    }

    fn render_repack_complete(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.do_repack, "Repack images");
            ui.checkbox(&mut self.do_complete, "--complete");
        });
        ui.label(
            egui::RichText::new("Rebuild partition images and the final super/payload.")
                .small()
                .weak(),
        );
    }

    fn render_repack_only(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.checkbox(&mut self.do_repack, "Repack images after resign");
    }

    fn render_repack_info(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        section_header(ui, "REPACK");
        ui.label(
            egui::RichText::new(
                "Rebuilds partition images and super/payload from the unpacked input directory.",
            )
            .small()
            .weak(),
        );
    }

    fn render_resign_group(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        let active = self.resign_active();
        let dedicated = matches!(self.mode, Mode::Resign);
        egui::Frame::group(ui.style())
            .fill(if active {
                egui::Color32::from_rgb(246, 248, 250)
            } else {
                egui::Color32::from_rgb(250, 251, 253)
            })
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(216, 222, 228),
            ))
            .inner_margin(10.0)
            .show(ui, |ui| {
                // Pin the frame content width; otherwise a wide child can push
                // the right border past the panel edge.
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    if dedicated {
                        ui.label(egui::RichText::new("RESIGN OPTIONS").strong().size(12.5));
                    } else {
                        ui.checkbox(
                            &mut self.do_resign,
                            egui::RichText::new("Resign partitions").strong().size(13.0),
                        );
                    }
                    ui.add_space(8.0);
                    let key = if let Some(path) = &self.key_path {
                        path.file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "file".to_string())
                    } else if self.key.trim().is_empty() {
                        "default".to_string()
                    } else {
                        self.key.trim().to_string()
                    };
                    let summary = if active {
                        format!(
                            "{key} · {} ovl · {} dbp",
                            self.add_overlays.len(),
                            self.plus_patches.len()
                        )
                    } else {
                        format!("off · key: {key}")
                    };
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(summary)
                                .small()
                                .color(egui::Color32::from_rgb(89, 99, 110)),
                        )
                        .truncate(),
                    );
                });

                if !active {
                    return;
                }
                ui.separator();

                ui.horizontal(|ui| {
                    label_cell(ui, egui::RichText::new("Signing key").strong());
                    if ui.button("Browse...").clicked()
                        && let Some(path) = file_dialog(self.key_path.as_deref()).pick_file()
                    {
                        self.key_path = Some(path);
                    }
                    if let Some(path) = self.key_path.clone() {
                        let is_missing = self.missing_paths.contains(&path);
                        let avail = (ui.available_width() - 30.0).clamp(80.0, 220.0);
                        path_display(ui, Some(&path), is_missing, "", avail);
                        if ui
                            .add_sized([22.0, 22.0], egui::Button::new("×"))
                            .on_hover_text("Clear key file and use the alias")
                            .clicked()
                        {
                            self.key_path = None;
                        }
                    } else {
                        ui.add_sized(
                            [170.0, 24.0],
                            egui::TextEdit::singleline(&mut self.key).hint_text("testkey_rsa4096"),
                        );
                    }
                });
                ui.label(
                    egui::RichText::new("Alias or key file; defaults to testkey_rsa4096.")
                        .small()
                        .weak(),
                );
                ui.checkbox(
                    &mut self.force,
                    "--force (re-sign already signed partitions)",
                );

                let has_overrides = !self.rollback.trim().is_empty()
                    || !self.boot_spl.trim().is_empty()
                    || !self.vendor_spl.trim().is_empty()
                    || !self.system_spl.trim().is_empty();
                let header = if has_overrides {
                    "Anti-Rollback & SPL Overrides (configured)"
                } else {
                    "Anti-Rollback & SPL Overrides (optional)"
                };
                egui::CollapsingHeader::new(egui::RichText::new(header).size(12.0))
                    .id_salt("resign-spl-overrides")
                    .default_open(has_overrides)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            label_cell(ui, "Rollback (Unix ts)");
                            ui.add_sized(
                                [130.0, 24.0],
                                egui::TextEdit::singleline(&mut self.rollback)
                                    .hint_text("Unix seconds"),
                            );
                        });
                        spl_row(
                            ui,
                            "Boot SPL",
                            &mut self.boot_spl,
                            &mut self.boot_spl_date,
                            "boot-spl-picker",
                        );
                        spl_row(
                            ui,
                            "Vendor SPL",
                            &mut self.vendor_spl,
                            &mut self.vendor_spl_date,
                            "vendor-spl-picker",
                        );
                        spl_row(
                            ui,
                            "System SPL",
                            &mut self.system_spl,
                            &mut self.system_spl_date,
                            "system-spl-picker",
                        );
                        if ui
                            .small_button("Sync Boot -> All")
                            .on_hover_text("Copy the boot SPL into vendor and system")
                            .clicked()
                        {
                            self.vendor_spl = self.boot_spl.clone();
                            self.system_spl = self.boot_spl.clone();
                        }
                    });

                ui.separator();
                ui.label(
                    egui::RichText::new("Modifications & Patches")
                        .strong()
                        .size(12.0),
                );

                ui.checkbox(&mut self.fuck_lgsi, "--fuck-lgsi");
                if self.fuck_lgsi {
                    ui.horizontal(|ui| {
                        label_cell(ui, "Config JSON");
                        if ui.button("Browse...").clicked()
                            && let Some(path) = file_dialog(self.fuck_lgsi_config.as_deref())
                                .add_filter("JSON", &["json"])
                                .pick_file()
                        {
                            self.fuck_lgsi_config = Some(path);
                        }
                        let mut clear = false;
                        if let Some(path) = &self.fuck_lgsi_config {
                            path_display(
                                ui,
                                Some(path),
                                self.missing_paths.contains(path),
                                "",
                                320.0,
                            );
                            if ui.small_button("×").on_hover_text("Clear config").clicked() {
                                clear = true;
                            }
                        } else {
                            ui.label(
                                egui::RichText::new("(interactive — Enter in the console)")
                                    .small()
                                    .weak(),
                            );
                        }
                        if clear {
                            self.fuck_lgsi_config = None;
                        }
                    });
                    if self.fuck_lgsi_config.is_none() {
                        ui.label(
                            egui::RichText::new(
                                "Interactive: waits for Enter in the console window.",
                            )
                            .small()
                            .color(egui::Color32::from_rgb(154, 103, 0)),
                        );
                    }
                }

                ui.checkbox(&mut self.debloat, "--debloat");
                if self.debloat {
                    ui.horizontal(|ui| {
                        label_cell(ui, "List file");
                        if ui.button("Browse...").clicked()
                            && let Some(path) = file_dialog(self.debloat_list.as_deref())
                                .add_filter("Text", &["txt"])
                                .pick_file()
                        {
                            self.debloat_list = Some(path);
                        }
                        let mut clear = false;
                        if let Some(path) = &self.debloat_list {
                            path_display(
                                ui,
                                Some(path),
                                self.missing_paths.contains(path),
                                "",
                                320.0,
                            );
                            if ui.small_button("×").on_hover_text("Clear list").clicked() {
                                clear = true;
                            }
                        } else {
                            ui.label(
                                egui::RichText::new("(interactive — edit debloat.txt in console)")
                                    .small()
                                    .weak(),
                            );
                        }
                        if clear {
                            self.debloat_list = None;
                        }
                    });
                    if self.debloat_list.is_none() {
                        ui.label(
                            egui::RichText::new(
                                "Interactive: edits debloat.txt in the console window.",
                            )
                            .small()
                            .color(egui::Color32::from_rgb(154, 103, 0)),
                        );
                    }
                }

                ui.checkbox(&mut self.add_spoof_enabled, "--add-spoof");
                if self.add_spoof_enabled {
                    ui.horizontal(|ui| {
                        label_cell(ui, "Spoof JSON");
                        if ui.button("Browse...").clicked()
                            && let Some(path) = file_dialog(self.add_spoof.as_deref())
                                .add_filter("JSON", &["json"])
                                .pick_file()
                        {
                            self.add_spoof = Some(path);
                        }
                        let mut clear = false;
                        if let Some(path) = &self.add_spoof {
                            path_display(
                                ui,
                                Some(path),
                                self.missing_paths.contains(path),
                                "",
                                320.0,
                            );
                            if ui
                                .small_button("×")
                                .on_hover_text("Clear spoof JSON")
                                .clicked()
                            {
                                clear = true;
                            }
                        } else {
                            ui.label(
                                egui::RichText::new("Required")
                                    .small()
                                    .color(egui::Color32::from_rgb(207, 34, 46)),
                            );
                        }
                        if clear {
                            self.add_spoof = None;
                        }
                    });
                }

                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.add_overlays_enabled, "Overlays (--add-overlay)");
                    ui.label(
                        egui::RichText::new(format!("{} APKs", self.add_overlays.len()))
                            .small()
                            .weak(),
                    );
                    if ui.small_button("Manage...").clicked() {
                        self.overlay_manager_open = true;
                    }
                });

                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.plus_patches_enabled, "Patches (--plus)");
                    ui.label(
                        egui::RichText::new(format!("{} .dbp", self.plus_patches.len()))
                            .small()
                            .weak(),
                    );
                    if ui.small_button("Manage...").clicked() {
                        self.patch_manager_open = true;
                    }
                });
            });
    }

    fn render_ota_form(&mut self, ui: &mut egui::Ui) {
        self.render_ota_io(ui);
        self.render_ota_options(ui);
    }

    fn render_ota_io(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "OTA I/O & SIGNING KEYS");
        path_row(
            ui,
            "Source build",
            &mut self.ota.source,
            PathKind::Folder,
            "ota-source",
            &self.missing_paths,
            "Optional (full OTA)",
        );
        path_row(
            ui,
            "Target build *",
            &mut self.ota.target,
            PathKind::Folder,
            "ota-target",
            &self.missing_paths,
            "Required",
        );
        path_row(
            ui,
            "Reference OTA *",
            &mut self.ota.reference,
            PathKind::Open("ZIP", &["zip"]),
            "ota-reference",
            &self.missing_paths,
            "Required",
        );
        path_row(
            ui,
            "Signing key *",
            &mut self.ota.key,
            PathKind::Open("PEM / DER key", &["key", "pem", "der", "pk8"]),
            "ota-key",
            &self.missing_paths,
            "Required",
        );
        path_row(
            ui,
            "Certificate *",
            &mut self.ota.cert,
            PathKind::Open("PEM / DER certificate", &["crt", "pem", "der", "x509"]),
            "ota-cert",
            &self.missing_paths,
            "Required",
        );
        path_row(
            ui,
            "Output zip *",
            &mut self.ota.output,
            PathKind::Save("ZIP", &["zip"]),
            "ota-output",
            &self.missing_paths,
            "Required (new file)",
        );
    }

    fn render_ota_options(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "OTA GENERATION OPTIONS");
        let has_source = self.ota.source.is_some();
        ui.add_enabled_ui(has_source, |ui| {
            ui.checkbox(&mut self.ota.delta, "--delta")
                .on_hover_text("Diff source and target block by block");
        });
        if !has_source {
            ui.label(
                egui::RichText::new("--delta requires a source build.")
                    .small()
                    .weak(),
            );
        }
        ui.checkbox(&mut self.ota.allow_avb_mismatch, "--allow-avb-mismatch")
            .on_hover_text("Package partitions even if they fail AVB checks");
        ui.horizontal(|ui| {
            ui.label("Exclude:");
            ui.add_sized(
                [220.0, 24.0],
                egui::TextEdit::singleline(&mut self.ota.exclude).hint_text("abl, xbl"),
            );
        });
        let kind = match (has_source, self.ota.delta) {
            (false, _) => "Full OTA: installs over any build of the device.",
            (true, true) => "Incremental OTA as a block-level delta.",
            (true, false) => {
                "Incremental OTA: reuses a Lenovo incremental reference, or diffs block by block."
            }
        };
        ui.label(egui::RichText::new(kind).small().weak());
    }
}

/// The nearest existing directory at or above `path`, so a picker still
/// opens close by after the path was moved or deleted.
fn existing_dir(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|dir| !dir.as_os_str().is_empty() && dir.is_dir())
        .map(Path::to_path_buf)
}

/// A dialog opening in `dir` (or its nearest existing ancestor); without
/// one the OS falls back to the last folder any picker used.
fn dialog_in(dir: Option<&Path>) -> rfd::FileDialog {
    match dir.and_then(existing_dir) {
        Some(dir) => rfd::FileDialog::new().set_directory(dir),
        None => rfd::FileDialog::new(),
    }
}

/// A folder picker opening inside the folder already picked.
fn folder_dialog(current: Option<&Path>) -> rfd::FileDialog {
    dialog_in(current)
}

/// A file picker opening beside the file already picked, with that file
/// preselected.
fn file_dialog(current: Option<&Path>) -> rfd::FileDialog {
    let dialog = dialog_in(current.and_then(Path::parent));
    match current.and_then(Path::file_name) {
        Some(name) => dialog.set_file_name(name.to_string_lossy()),
        None => dialog,
    }
}

/// A picker adding to `list`, opening beside its last entry.
fn list_dialog(list: &[PathBuf]) -> rfd::FileDialog {
    dialog_in(list.last().and_then(|p| p.parent()))
}

/// What a [`path_row`] picker selects.
enum PathKind {
    Folder,
    /// An existing file: filter name and extensions.
    Open(&'static str, &'static [&'static str]),
    /// A new file: filter name and extensions.
    Save(&'static str, &'static [&'static str]),
}

/// A labelled path field: fixed-width label + Browse + tail-first path + clear.
fn path_row(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Option<PathBuf>,
    kind: PathKind,
    id_salt: &str,
    missing: &MissingPaths,
    placeholder: &str,
) {
    ui.horizontal(|ui| {
        label_cell(ui, label);
        path_control(ui, value, kind, id_salt, missing, placeholder);
    });
}

fn path_control(
    ui: &mut egui::Ui,
    value: &mut Option<PathBuf>,
    kind: PathKind,
    _id_salt: &str,
    missing: &MissingPaths,
    placeholder: &str,
) {
    ui.horizontal(|ui| {
        if ui.button("Browse...").clicked() {
            let current = value.as_deref();
            let picked = match kind {
                PathKind::Folder => folder_dialog(current).pick_folder(),
                PathKind::Open(name, extensions) => file_dialog(current)
                    .add_filter(name, extensions)
                    .pick_file(),
                PathKind::Save(name, extensions) => file_dialog(current)
                    .add_filter(name, extensions)
                    .save_file(),
            };
            if let Some(path) = picked {
                *value = Some(path);
            }
        }

        let is_missing = value.as_deref().is_some_and(|path| missing.contains(path));
        // Hard width: a long path must never widen the row, and the clear
        // button stays at a predictable spot instead of floating to the edge.
        let budget = (ui.ctx().content_rect().width() - 320.0).clamp(120.0, 300.0);
        path_display(ui, value.as_deref(), is_missing, placeholder, budget);
        if value.is_some()
            && ui
                .add_sized([22.0, 22.0], egui::Button::new("×"))
                .on_hover_text("Clear path")
                .clicked()
        {
            *value = None;
        }
    });
}

fn path_display(
    ui: &mut egui::Ui,
    path: Option<&Path>,
    missing: bool,
    placeholder: &str,
    width: f32,
) {
    ui.allocate_ui_with_layout(
        egui::vec2(width, 24.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            path_display_inner(ui, path, missing, placeholder, width);
        },
    );
}

/// Show the last two path segments (`parent/leaf`) so two folders named
/// `out` or `target` remain distinguishable, and fall back to the leaf when
/// the pair does not fit the budget.
fn short_path_label(path: &Path, max_chars: usize) -> String {
    let full = path.display().to_string();
    let Some(leaf) = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return truncate_command(&full, max_chars);
    };
    let parent = path
        .parent()
        .and_then(|parent| parent.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty());
    let combined = match parent {
        Some(parent) => format!("{parent}{}{leaf}", std::path::MAIN_SEPARATOR),
        None => leaf.clone(),
    };
    if combined.chars().count() <= max_chars {
        combined
    } else {
        truncate_command(&leaf, max_chars)
    }
}

fn path_display_inner(
    ui: &mut egui::Ui,
    path: Option<&Path>,
    missing: bool,
    placeholder: &str,
    max_width: f32,
) {
    let Some(path) = path else {
        ui.add(
            egui::Label::new(
                egui::RichText::new(placeholder)
                    .small()
                    .color(egui::Color32::from_rgb(130, 140, 150)),
            )
            .truncate(),
        );
        return;
    };

    let full = path.display().to_string();
    let max_chars = ((max_width / 7.5) as usize).clamp(14, 56);
    let text = short_path_label(path, max_chars);
    let color = if missing {
        egui::Color32::from_rgb(207, 34, 46)
    } else {
        egui::Color32::from_rgb(31, 35, 40)
    };

    let response = ui
        .add(
            egui::Label::new(
                egui::RichText::new(text)
                    .monospace()
                    .strong()
                    .size(12.5)
                    .color(color),
            )
            .truncate(),
        )
        .on_hover_text(&full);

    response.context_menu(|ui| {
        if ui.button("Copy full path").clicked() {
            ui.ctx().copy_text(full.clone());
            ui.close();
        }
        if ui.button("Open in file manager").clicked() {
            open_in_file_manager(path);
            ui.close();
        }
    });
}

fn open_in_file_manager(path: &Path) {
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let program = "xdg-open";

    let _ = std::process::Command::new(program).arg(path).spawn();
}

fn truncate_command(command: &str, max_chars: usize) -> String {
    if command.chars().count() <= max_chars {
        command.to_string()
    } else {
        let head: String = command.chars().take(max_chars).collect();
        format!("{head}...")
    }
}

fn history_title(entry: &FormSnapshot) -> String {
    let input = entry
        .input
        .as_deref()
        .map(|path| short_path_label(path, 24))
        .unwrap_or_else(|| "—".to_string());
    let output = entry
        .output
        .as_deref()
        .map(|path| short_path_label(path, 24))
        .unwrap_or_else(|| "auto".to_string());
    format!("{input} -> {output}")
}

fn history_badges(entry: &FormSnapshot) -> String {
    let mut parts = vec![entry.mode.label().to_string()];
    if matches!(entry.mode, Mode::Apply) {
        parts.push(format!("{} OTA", entry.ota_zips.len()));
    }
    if entry.do_resign {
        let key = if entry.key.trim().is_empty() {
            "default"
        } else {
            entry.key.trim()
        };
        parts.push(format!("resign: {key}"));
    }
    if entry.add_overlays_enabled && !entry.add_overlays.is_empty() {
        parts.push(format!("{} overlays", entry.add_overlays.len()));
    }
    if entry.plus_patches_enabled && !entry.plus_patches.is_empty() {
        parts.push(format!("{} patches", entry.plus_patches.len()));
    }
    if entry.do_repack {
        parts.push("repack".to_string());
    }
    if entry.do_complete {
        parts.push("--complete".to_string());
    }
    if !entry.created_at.is_empty() {
        // RFC 3339 is long; show `YYYY-MM-DD HH:MM` so the rest of the badge
        // line stays readable.
        let short = entry
            .created_at
            .get(..16)
            .unwrap_or(&entry.created_at)
            .replace('T', " ");
        parts.push(short);
    }
    parts.join(" · ")
}

fn mode_number(mode: Mode) -> usize {
    match mode {
        Mode::Apply => 1,
        Mode::Unpack => 2,
        Mode::Resign => 3,
        Mode::Repack => 4,
        Mode::Ota => 5,
    }
}

fn label_cell(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>) {
    ui.allocate_ui_with_layout(
        egui::vec2(115.0, 24.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            // `allocate_ui_with_layout` only caps max_rect; force both bounds
            // so every row's control starts at the same x.
            ui.set_width(115.0);
            ui.add(egui::Label::new(text).truncate());
        },
    );
}

fn section_header(ui: &mut egui::Ui, text: &str) {
    ui.add_space(4.0);
    ui.label(egui::RichText::new(text).strong().size(12.5));
    ui.add_space(2.0);
}

/// Shared row layout for the boot/vendor SPL fields: fixed-width text input
/// with a `[Pick]` button that opens the date picker.
fn spl_row(ui: &mut egui::Ui, label: &str, value: &mut String, date: &mut Date, id_salt: &str) {
    ui.horizontal(|ui| {
        label_cell(ui, label);
        ui.add_sized(
            [105.0, 24.0],
            egui::TextEdit::singleline(value).hint_text("YYYY-MM-DD"),
        );
        if let Ok(parsed) = parse_spl_date(value.trim()) {
            *date = parsed;
        }
        let previous = *date;
        ui.add(
            DatePickerButton::new(date)
                .id_salt(id_salt)
                .format("Pick")
                .show_icon(false),
        );
        if *date != previous {
            *value = format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day());
        }
    });
}

/// Parse a `YYYY-MM-DD` string into a `jiff::civil::Date`. Returns
/// `Err(())` for any malformed input — the caller treats failure as
/// "leave the picker's seed unchanged".
fn parse_spl_date(s: &str) -> Result<Date, ()> {
    let mut parts = s.split('-');
    let y: i16 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let m: i8 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let d: i8 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    if parts.next().is_some() {
        return Err(());
    }
    Date::new(y, m, d).map_err(|_| ())
}

fn restored_spl_date(value: &str) -> Date {
    parse_spl_date(value.trim()).unwrap_or(Date::constant(2026, 1, 1))
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
            viewport: egui::ViewportBuilder::default().with_inner_size([520.0, 650.0]),
            persist_window: false,
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(DynoGui::from_storage(cc.storage)))),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn populated_gui(mode: Mode) -> DynoGui {
        DynoGui {
            mode,
            input: Some(PathBuf::from("input-dir")),
            output: Some(PathBuf::from("output-dir")),
            integrity_key: Some(PathBuf::from("integrity.pem")),
            ota_zips: vec![PathBuf::from("one.zip"), PathBuf::from("two.zip")],
            do_resign: true,
            do_repack: false,
            do_complete: false,
            key: "named-key".into(),
            key_path: Some(PathBuf::from("custom-key.pem")),
            force: true,
            rollback: "1720000000".into(),
            boot_spl: "2024-01-02".into(),
            vendor_spl: "2024-03-04".into(),
            system_spl: "2024-05-06".into(),
            fuck_lgsi: true,
            fuck_lgsi_config: Some(PathBuf::from("lgsi.json")),
            debloat: true,
            debloat_list: Some(PathBuf::from("debloat.txt")),
            info: true,
            plus_patches: vec![PathBuf::from("one.dbp"), PathBuf::from("two.dbp")],
            ota: OtaForm {
                source: Some(PathBuf::from("a-dir")),
                target: Some(PathBuf::from("b-dir")),
                reference: Some(PathBuf::from("ref.zip")),
                key: Some(PathBuf::from("ota.key")),
                cert: Some(PathBuf::from("ota.crt")),
                output: Some(PathBuf::from("a-to-b.zip")),
                delta: true,
                allow_avb_mismatch: true,
                exclude: " abl, xbl  tz,".into(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn ota_mode_builds_ota_generate_args() {
        let gui = populated_gui(Mode::Ota);
        assert_eq!(
            gui.build_args(),
            vec![
                "ota",
                "generate",
                "--source",
                "a-dir",
                "--target",
                "b-dir",
                "--reference",
                "ref.zip",
                "--key",
                "ota.key",
                "--cert",
                "ota.crt",
                "--output",
                "a-to-b.zip",
                "--delta",
                "--allow-avb-mismatch",
                "--exclude=abl",
                "--exclude=xbl",
                "--exclude=tz",
            ]
        );
        assert!(gui.validate_for_run().is_ok());

        // Full OTA: no source, so `--delta` is dropped even when ticked.
        let mut full = populated_gui(Mode::Ota);
        full.ota.source = None;
        full.ota.allow_avb_mismatch = false;
        let args = full.build_args();
        assert!(!args.iter().any(|a| a == "--source" || a == "--delta"));
        assert!(!args.contains(&"--allow-avb-mismatch".to_string()));

        let mut incomplete = populated_gui(Mode::Ota);
        incomplete.ota.cert = None;
        assert_eq!(
            incomplete.validate_for_run(),
            Err("Missing OTA certificate".to_string())
        );
        // OTA mode does not need the pipeline modes' --input.
        let mut no_input = populated_gui(Mode::Ota);
        no_input.input = None;
        assert!(no_input.validate_for_run().is_ok());
    }

    #[test]
    fn repack_args_include_optional_manifest_signing_key() {
        let gui = DynoGui {
            mode: Mode::Repack,
            input: Some(PathBuf::from("input")),
            output: Some(PathBuf::from("output")),
            integrity_key: Some(PathBuf::from("integrity.pem")),
            ..Default::default()
        };

        assert_eq!(
            gui.build_args(),
            vec![
                "repack",
                "--input",
                "input",
                "--output",
                "output",
                "--integrity-key",
                "integrity.pem",
            ]
        );
    }

    #[test]
    fn snapshots_restore_every_field_in_all_modes_and_rebuild_spl_dates() {
        for mode in [
            Mode::Apply,
            Mode::Unpack,
            Mode::Resign,
            Mode::Repack,
            Mode::Ota,
        ] {
            let original = populated_gui(mode);
            let snapshot = FormSnapshot::capture(&original);
            let mut restored = DynoGui::default();

            snapshot.restore_form(&mut restored);

            assert_eq!(snapshot.command_line(), original.build_args().join(" "));
            assert!(FormSnapshot::capture(&restored).same_form(&snapshot));
            assert_eq!(restored.boot_spl_date, Date::constant(2024, 1, 2));
            assert_eq!(restored.vendor_spl_date, Date::constant(2024, 3, 4));
            assert_eq!(restored.system_spl_date, Date::constant(2024, 5, 6));
        }
    }

    #[test]
    fn info_flag_is_emitted_in_apply_and_unpack_modes() {
        for mode in [Mode::Apply, Mode::Unpack] {
            let mut gui = populated_gui(mode);
            gui.info = true;
            let args = gui.build_args();
            assert!(
                args.contains(&"--info".to_string()),
                "{mode:?} should emit --info, got: {args:?}"
            );
        }
        let mut resign = populated_gui(Mode::Resign);
        resign.info = true;
        assert!(
            !resign.build_args().contains(&"--info".to_string()),
            "Resign mode must not emit the Apply/Unpack-only --info flag"
        );
        let mut off = populated_gui(Mode::Apply);
        off.info = false;
        assert!(
            !off.build_args().contains(&"--info".to_string()),
            "info off should not emit --info"
        );
    }

    #[test]
    fn overlay_and_patch_lists_are_omitted_when_disabled() {
        let mut gui = populated_gui(Mode::Resign);
        gui.add_overlays = vec![PathBuf::from("overlay.apk")];
        gui.plus_patches = vec![PathBuf::from("extra.dbp")];
        let args = gui.build_args();
        assert!(args.iter().any(|a| a.starts_with("--add-overlay=")));
        assert!(args.iter().any(|a| a.starts_with("--plus=")));

        gui.add_overlays_enabled = false;
        gui.plus_patches_enabled = false;
        let args = gui.build_args();
        assert!(
            !args.iter().any(|a| a.starts_with("--add-overlay=")),
            "disabled overlay list must not emit --add-overlay, got: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a.starts_with("--plus=")),
            "disabled patch list must not emit --plus, got: {args:?}"
        );
    }

    #[test]
    fn add_spoof_is_emitted_only_when_enabled() {
        let mut gui = populated_gui(Mode::Resign);
        gui.add_spoof = Some(PathBuf::from("spoof.json"));
        gui.add_spoof_enabled = true;
        assert!(
            gui.build_args()
                .contains(&"--add-spoof=spoof.json".to_string()),
            "enabled spoof list should emit --add-spoof, got: {:?}",
            gui.build_args()
        );

        gui.add_spoof_enabled = false;
        assert!(
            !gui.build_args()
                .iter()
                .any(|a| a.starts_with("--add-spoof=")),
            "disabled spoof list must not emit --add-spoof"
        );
    }

    #[test]
    fn snapshots_without_enable_toggles_restore_enabled() {
        let snapshot = FormSnapshot::capture(&populated_gui(Mode::Apply));
        let mut value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        let object = value.as_object_mut().expect("snapshot object");
        object.remove("add_overlays_enabled");
        object.remove("plus_patches_enabled");
        object.remove("ota");

        let legacy: FormSnapshot = serde_json::from_value(value).expect("legacy snapshot");
        assert!(legacy.add_overlays_enabled);
        assert!(legacy.plus_patches_enabled);
        assert_eq!(legacy.ota, OtaForm::default());
    }

    #[test]
    fn history_inserts_newest_deduplicates_caps_and_deletes() {
        let mut history = RunHistory::default();
        for index in 0..55 {
            let mut gui = populated_gui(Mode::Apply);
            gui.key = format!("key-{index}");
            history.insert(FormSnapshot::capture(&gui));
        }

        assert_eq!(history.entries.len(), HISTORY_LIMIT);
        assert_eq!(history.entries[0].key, "key-54");
        assert_eq!(history.entries[HISTORY_LIMIT - 1].key, "key-5");

        let duplicate = history.entries[10].clone();
        history.insert(duplicate.clone());
        assert_eq!(history.entries.len(), HISTORY_LIMIT);
        assert_eq!(history.entries[0], duplicate);

        let second = history.entries[1].clone();
        history.delete(0);
        assert_eq!(history.entries.len(), HISTORY_LIMIT - 1);
        assert_eq!(history.entries[0], second);
    }

    #[test]
    fn missing_path_classification_covers_inputs_and_excludes_output() {
        let unique = format!(
            "dynobox-gui-history-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&base).expect("create test directory");
        let existing = base.join("existing.zip");
        std::fs::write(&existing, b"zip").expect("create existing test path");

        let mut gui = populated_gui(Mode::Apply);
        gui.input = Some(base.join("missing-input"));
        gui.output = Some(base.join("missing-output"));
        gui.integrity_key = Some(base.join("missing-integrity.pem"));
        gui.ota_zips = vec![base.join("missing.zip"), existing.clone()];
        gui.key_path = Some(base.join("missing-key.pem"));
        gui.fuck_lgsi_config = Some(base.join("missing-lgsi.json"));
        gui.debloat_list = Some(base.join("missing-debloat.txt"));
        gui.plus_patches = vec![base.join("missing.dbp")];
        gui.ota.reference = Some(base.join("missing-reference.zip"));
        gui.ota.cert = Some(base.join("missing-ota.crt"));
        gui.ota.output = Some(base.join("missing-ota-output.zip"));
        let snapshot = FormSnapshot::capture(&gui);

        let missing = MissingPaths::classify(&snapshot);

        for path in [
            snapshot.input.as_deref(),
            snapshot.integrity_key.as_deref(),
            snapshot.ota_zips.first().map(PathBuf::as_path),
            snapshot.key_path.as_deref(),
            snapshot.fuck_lgsi_config.as_deref(),
            snapshot.debloat_list.as_deref(),
            snapshot.plus_patches.first().map(PathBuf::as_path),
            snapshot.ota.reference.as_deref(),
            snapshot.ota.cert.as_deref(),
        ] {
            assert!(missing.contains(path.expect("test path should be set")));
        }
        assert!(!missing.contains(&existing));
        assert!(!missing.contains(snapshot.output.as_deref().expect("output should be set")));
        // Like --output, the OTA zip to be written is expected not to exist.
        assert!(!missing.contains(snapshot.ota.output.as_deref().expect("OTA output set")));

        std::fs::remove_dir_all(base).expect("remove test directory");
    }

    #[test]
    fn history_lists_only_the_current_mode_with_global_indices() {
        let mut history = RunHistory::default();
        for mode in [Mode::Apply, Mode::Ota, Mode::Apply, Mode::Resign] {
            let mut gui = populated_gui(mode);
            gui.key = format!("{mode:?}-{}", history.entries.len());
            history.insert(FormSnapshot::capture(&gui));
        }
        // Newest first: Resign-3, Apply-2, Ota-1, Apply-0.
        let apply: Vec<(usize, String)> = history
            .for_mode(Mode::Apply)
            .map(|(index, entry)| (index, entry.key.clone()))
            .collect();
        assert_eq!(
            apply,
            [(1, "Apply-2".to_string()), (3, "Apply-0".to_string())]
        );
        assert_eq!(history.for_mode(Mode::Unpack).count(), 0);

        // Deleting through a filtered index removes that entry only.
        history.delete(apply[1].0);
        assert_eq!(history.for_mode(Mode::Apply).count(), 1);
        assert_eq!(history.for_mode(Mode::Ota).count(), 1);
    }

    #[test]
    fn pickers_start_from_the_nearest_existing_directory() {
        let base = std::env::temp_dir().join(format!("dynobox-gui-picker-{}", std::process::id()));
        std::fs::create_dir_all(base.join("kept")).expect("create test directory");

        assert_eq!(existing_dir(&base.join("kept")), Some(base.join("kept")));
        // A moved or deleted path falls back to what still exists above it.
        assert_eq!(
            existing_dir(&base.join("gone/deeper/file.zip")),
            Some(base.clone())
        );
        assert_eq!(existing_dir(Path::new("")), None);

        std::fs::remove_dir_all(base).expect("remove test directory");
    }

    #[test]
    fn malformed_or_wrong_version_history_degrades_to_empty() {
        assert!(RunHistory::from_json("not-json").entries.is_empty());

        let mut snapshot = FormSnapshot::capture(&populated_gui(Mode::Apply));
        snapshot.schema_version = HISTORY_SCHEMA_VERSION + 1;
        let payload = serde_json::to_string(&vec![snapshot]).expect("serialize test history");
        assert!(RunHistory::from_json(&payload).entries.is_empty());
    }
}
