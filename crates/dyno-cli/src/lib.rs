use clap::{Parser, Subcommand, ValueEnum};
use dynobox_app::debloat::DebloatMode;
use dynobox_app::events::ProgressUnit;
use dynobox_app::fuck_lgsi::FuckLgsiMode;
use dynobox_app::{
    ApplyRequest, CommandKind, MessageLevel, ProgressEvent, RepackRequest, ResignConfig,
    ResignRequest, StageKind, UnpackRequest, VerificationOptions, default_output_name_for_apply,
    default_output_name_for_resign, default_output_name_for_unpack, generate_integrity_keypair,
    render_verification_report, run_apply, run_repack, run_resign, run_unpack,
    verify_input_with_options,
};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::borrow::Cow;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(
    name = "dynobox",
    about = "DynoBox: Standalone Pure Rust OTA and firmware manipulation toolkit",
    version
)]
struct Cli {
    /// Progress output format for pipeline commands
    #[arg(long, global = true, value_enum, default_value_t = ProgressFormat::Text)]
    progress_format: ProgressFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ProgressFormat {
    Text,
    Jsonl,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ReportFormat {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Unpack super image and extract dynamic partitions
    Unpack {
        /// Input directory containing firmware XMLs and super chunks
        #[arg(short, long)]
        input: PathBuf,

        /// Output directory for extracted or final pipeline output
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Optional Ed25519 PKCS#8 private key used to sign the final SHA-256 manifest
        /// (the manifest is only written when repacking)
        #[arg(long, value_name = "PRIVATE_KEY_PEM")]
        integrity_key: Option<PathBuf>,

        /// Re-sign AVB images after unpack
        #[arg(long)]
        resign: bool,

        /// Repack dynamic partitions back into super after unpack
        #[arg(long)]
        repack: bool,

        /// Path to RSA key file or embedded key name used with --resign
        #[arg(short = 'k', long, requires = "resign")]
        key: Option<String>,

        /// AVB algorithm used with --resign
        #[arg(short = 'a', long, requires = "resign")]
        algorithm: Option<String>,

        /// Force signing even when original AVB algorithm is NONE; only valid with --resign
        #[arg(long, requires = "resign")]
        force: bool,

        /// Override AVB rollback_index of boot.img and vbmeta_system.img with this Unix timestamp.
        /// A confirmation prompt shows old/new dates in UTC; answering n (or non-interactive stdin) skips the rollback rewrite and the rest of the resign stage runs normally.
        #[arg(long, value_name = "UNIX_TIMESTAMP", requires = "resign")]
        rollback: Option<u64>,

        /// Bump boot.img `com.android.build.boot.security_patch` to this YYYY-MM-DD
        /// date during resign. The image is re-signed regardless; the property is
        /// only rewritten when the requested date is strictly newer than the current.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_boot_spl, requires = "resign")]
        boot_spl: Option<String>,

        /// Bump vendor.img `com.android.build.vendor.security_patch` to this
        /// YYYY-MM-DD date during resign. Patches `/vendor/build.prop`,
        /// regenerates the dm-verity hash tree, and propagates the new value
        /// and root digest into vbmeta.img so the resign loop signs over them.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_vendor_spl, requires = "resign")]
        vendor_spl: Option<String>,

        /// Bump system.img `ro.build.version.security_patch` (the Android
        /// security update Settings shows) and the matching
        /// `com.android.build.system.security_patch` AVB property to this
        /// YYYY-MM-DD date during resign. Patches `/system/build.prop`,
        /// regenerates the dm-verity hash tree, and propagates the new value
        /// and root digest into vbmeta_system.img so the resign loop signs
        /// over them.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_system_spl, requires = "resign")]
        system_spl: Option<String>,

        /// Per-feature toggle for Lenovo's LGSI feature flags inside
        /// system.img. Bare `--fuck-lgsi` runs the interactive flow; pass a
        /// JSON path to run non-interactively. Requires --resign.
        #[arg(long, value_name = "JSON_PATH", num_args = 0..=1, default_missing_value = "", requires = "resign")]
        fuck_lgsi: Option<String>,

        /// Scan unpacked super partitions and write blobs.txt, then hide the
        /// listed files/folders from the ext4 images (no mount) and re-sign.
        /// Bare `--debloat` pauses for you to edit `<out>/debloat.txt`; pass a
        /// path (`--debloat list.txt`) to run non-interactively from that file
        /// (format: partition:/path). Requires --resign. Invalid paths ignored.
        #[arg(long, value_name = "LIST_FILE", num_args = 0..=1, default_missing_value = "", requires = "resign")]
        debloat: Option<String>,

        /// Apply an external `.dbp` patch to files inside the partition images
        /// during resign. Repeat the flag to apply several patches
        /// (`--plus a.dbp --plus b.dbp`). Requires --resign.
        #[arg(long, value_name = "DBP", requires = "resign")]
        plus: Vec<PathBuf>,

        /// Scan unpacked super partitions and write `blobs.txt` (every
        /// `partition:/path`, same format `--debloat` consumes) plus
        /// `lgsi_features.json` (parsed from
        /// `product.img:/etc/lgsi_build_info*.html`) into the output.
        /// Read-only inventory; needs no --resign.
        #[arg(long)]
        info: bool,

        /// Copy all input files to output so it mirrors the original firmware structure
        #[arg(long)]
        complete: bool,
    },
    /// Apply one or more OTA zip packages
    Apply {
        /// Input directory containing base firmware images
        #[arg(short, long)]
        input: PathBuf,

        /// Output directory for patched images (defaults to output_apply)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Optional Ed25519 PKCS#8 private key used to sign the final SHA-256 manifest
        /// (the manifest is only written when repacking)
        #[arg(long, value_name = "PRIVATE_KEY_PEM")]
        integrity_key: Option<PathBuf>,

        /// Force pre-unpack of dynamic partitions from super before applying OTA
        #[arg(long)]
        unpack: bool,

        /// Re-sign AVB images after OTA apply
        #[arg(long)]
        resign: bool,

        /// Repack dynamic partitions back into super after OTA apply
        #[arg(long)]
        repack: bool,

        /// Path to RSA key file or embedded key name used with resign
        #[arg(short = 'k', long)]
        key: Option<String>,

        /// AVB algorithm used with resign
        #[arg(short = 'a', long)]
        algorithm: Option<String>,

        /// Force signing even when original AVB algorithm is NONE; only valid with resign
        #[arg(long)]
        force: bool,

        /// Override AVB rollback_index of boot.img and vbmeta_system.img with this Unix timestamp.
        /// A confirmation prompt shows old/new dates in UTC; answering n (or non-interactive stdin) skips the rollback rewrite and the rest of the resign stage runs normally.
        #[arg(long, value_name = "UNIX_TIMESTAMP")]
        rollback: Option<u64>,

        /// Bump boot.img `com.android.build.boot.security_patch` to this YYYY-MM-DD
        /// date during resign. The image is re-signed regardless; the property is
        /// only rewritten when the requested date is strictly newer than the current.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_boot_spl)]
        boot_spl: Option<String>,

        /// Bump vendor.img `com.android.build.vendor.security_patch` to this
        /// YYYY-MM-DD date during resign. Patches `/vendor/build.prop`,
        /// regenerates the dm-verity hash tree, and propagates the new value
        /// and root digest into vbmeta.img so the resign loop signs over them.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_vendor_spl)]
        vendor_spl: Option<String>,

        /// Bump system.img `ro.build.version.security_patch` (the Android
        /// security update Settings shows) and the matching
        /// `com.android.build.system.security_patch` AVB property to this
        /// YYYY-MM-DD date during resign. Patches `/system/build.prop`,
        /// regenerates the dm-verity hash tree, and propagates the new value
        /// and root digest into vbmeta_system.img so the resign loop signs
        /// over them.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_system_spl)]
        system_spl: Option<String>,

        /// Per-feature toggle for Lenovo's LGSI feature flags inside
        /// system.img. Extracts `lgsi_build_info.html` from product.img,
        /// renders the per-feature `Enabled State` table as
        /// `<output>/lgsi_features.json`, then waits on stdin Enter for
        /// you to edit the JSON before patching the matching
        /// `LgsiFeatureInfo.<init>` registration sites. Pass a path
        /// (`--fuck-lgsi <JSON_PATH>`) to run non-interactively against
        /// a pre-edited JSON instead; it is retained as
        /// `<out>/lgsi_features.json`. Interactive workspace files are
        /// removed after a successful patch — `report.html` carries the
        /// audit trail.
        #[arg(long, value_name = "JSON_PATH", num_args = 0..=1, default_missing_value = "")]
        fuck_lgsi: Option<String>,

        /// Scan unpacked super partitions and write blobs.txt, then hide the
        /// listed files/folders from the ext4 images (no mount) and re-sign.
        /// Bare `--debloat` pauses for you to edit `<out>/debloat.txt`; pass a
        /// path (`--debloat list.txt`) to run non-interactively from that file
        /// (format: partition:/path). The input is retained as
        /// `<out>/debloat.txt`; the generated blobs.txt is removed when done.
        /// Requires --resign. Invalid paths ignored.
        #[arg(long, value_name = "LIST_FILE", num_args = 0..=1, default_missing_value = "")]
        debloat: Option<String>,

        /// Apply an external `.dbp` patch to files inside the partition images
        /// during resign. Repeat the flag to apply several patches
        /// (`--plus a.dbp --plus b.dbp`). Requires `resign` or `--resign`.
        #[arg(long, value_name = "DBP")]
        plus: Vec<PathBuf>,

        /// Scan unpacked super partitions and write `blobs.txt` plus
        /// `lgsi_features.json` into the output. Read-only inventory.
        #[arg(long)]
        info: bool,

        /// Copy all input files to output so it mirrors the original firmware structure
        #[arg(long)]
        complete: bool,

        /// OTA zip files to apply sequentially.
        /// Pipeline stage keywords (unpack, resign, repack) can also appear here
        /// as bare words instead of --flags.
        #[arg(required = true)]
        ota_zips: Vec<PathBuf>,
    },
    /// Re-sign dynamic partition images and rebuild vbmeta
    Resign {
        /// Input directory containing patched images
        #[arg(short, long)]
        input: PathBuf,

        /// Output directory for signed or final pipeline output
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Optional Ed25519 PKCS#8 private key used to sign the final SHA-256 manifest
        /// (the manifest is only written when repacking)
        #[arg(long, value_name = "PRIVATE_KEY_PEM")]
        integrity_key: Option<PathBuf>,

        /// Path to the RSA key file or name of embedded key (testkey_rsa2048, testkey_rsa4096)
        #[arg(short, long)]
        key: String,

        /// AVB algorithm to use (defaults to automatic detection based on key size)
        #[arg(short, long)]
        algorithm: Option<String>,

        /// Force signing even when original AVB algorithm is NONE
        #[arg(long)]
        force: bool,

        /// Override AVB rollback_index of boot.img and vbmeta_system.img with this Unix timestamp.
        /// A confirmation prompt shows old/new dates in UTC; answering n (or non-interactive stdin) skips the rollback rewrite and the rest of the resign stage runs normally.
        #[arg(long, value_name = "UNIX_TIMESTAMP")]
        rollback: Option<u64>,

        /// Bump boot.img `com.android.build.boot.security_patch` to this YYYY-MM-DD
        /// date during resign. The image is re-signed regardless; the property is
        /// only rewritten when the requested date is strictly newer than the current.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_boot_spl)]
        boot_spl: Option<String>,

        /// Bump vendor.img `com.android.build.vendor.security_patch` to this
        /// YYYY-MM-DD date during resign. Patches `/vendor/build.prop`,
        /// regenerates the dm-verity hash tree, and propagates the new value
        /// and root digest into vbmeta.img so the resign loop signs over them.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_vendor_spl)]
        vendor_spl: Option<String>,

        /// Bump system.img `ro.build.version.security_patch` (the Android
        /// security update Settings shows) and the matching
        /// `com.android.build.system.security_patch` AVB property to this
        /// YYYY-MM-DD date during resign. Patches `/system/build.prop`,
        /// regenerates the dm-verity hash tree, and propagates the new value
        /// and root digest into vbmeta_system.img so the resign loop signs
        /// over them.
        #[arg(long, value_name = "YYYY-MM-DD", value_parser = parse_system_spl)]
        system_spl: Option<String>,

        /// Per-feature toggle for Lenovo's LGSI feature flags inside
        /// system.img. Extracts `lgsi_build_info.html` from product.img,
        /// renders the per-feature `Enabled State` table as
        /// `<output>/lgsi_features.json`, then waits on stdin Enter for
        /// you to edit the JSON before patching the matching
        /// `LgsiFeatureInfo.<init>` registration sites inside
        /// `system.img/system/framework/framework.jar`. Pass a path
        /// (`--fuck-lgsi <JSON_PATH>`) to run non-interactively against
        /// a pre-edited JSON instead; it is retained as
        /// `<out>/lgsi_features.json`. Regenerates system.img dm-verity
        /// and propagates the new root digest into vbmeta_system.img.
        /// Interactive workspace files are removed after a successful
        /// patch — `report.html` carries the audit trail. No-op when no
        /// edits are made.
        #[arg(long, value_name = "JSON_PATH", num_args = 0..=1, default_missing_value = "")]
        fuck_lgsi: Option<String>,

        /// Scan unpacked super partitions and write blobs.txt, then hide the
        /// listed files/folders from the ext4 images (no mount) and re-sign.
        /// Bare `--debloat` pauses for you to edit `<out>/debloat.txt`; pass a
        /// path (`--debloat list.txt`) to run non-interactively from that file
        /// (format: partition:/path). The input is retained as
        /// `<out>/debloat.txt`; the generated blobs.txt is removed when done.
        /// Invalid paths are ignored.
        #[arg(long, value_name = "LIST_FILE", num_args = 0..=1, default_missing_value = "")]
        debloat: Option<String>,

        /// Apply an external `.dbp` patch to files inside the partition images.
        /// Repeat the flag to apply several patches
        /// (`--plus a.dbp --plus b.dbp`).
        #[arg(long, value_name = "DBP")]
        plus: Vec<PathBuf>,

        /// Scan unpacked super partitions and write `blobs.txt` plus
        /// `lgsi_features.json` into the output. Read-only inventory.
        #[arg(long)]
        info: bool,

        /// Repack dynamic partitions back into super after resign
        #[arg(long)]
        repack: bool,
    },
    /// Repack dynamic partitions into a new super image
    Repack {
        /// Input directory containing source firmware images
        #[arg(short, long)]
        input: PathBuf,

        /// Output directory for repacked super chunks (defaults to output_repack)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Optional Ed25519 PKCS#8 private key used to sign the final SHA-256 manifest
        #[arg(long, value_name = "PRIVATE_KEY_PEM")]
        integrity_key: Option<PathBuf>,
    },
    /// Scan AVB info from one image or all images under a directory
    Info {
        /// Input image file or directory to scan recursively
        #[arg(short, long)]
        input: PathBuf,

        /// Output format
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        format: ReportFormat,

        /// Optional output text file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify image / XML / super consistency for one file or directory
    Verify {
        /// Input image file or directory to verify
        #[arg(short, long)]
        input: PathBuf,

        /// Output format
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        format: ReportFormat,

        /// Optional output report path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Externally pinned Ed25519 SPKI public key trusted for the manifest signature.
        /// Repeat to trust multiple signers.
        #[arg(long, value_name = "PUBLIC_KEY_PEM")]
        trusted_integrity_key: Vec<PathBuf>,

        /// Accept a trusted signed manifest's semantic-verification attestation.
        /// Artifact SHA-256 verification is always performed locally.
        #[arg(long)]
        trust_manifest_attestation: bool,
    },
    /// Generate a dedicated Ed25519 manifest-signing keypair
    IntegrityKeygen {
        /// Destination for the PKCS#8 private key PEM (must not already exist)
        #[arg(long, value_name = "PRIVATE_KEY_PEM")]
        private_key: PathBuf,

        /// Destination for the SPKI public key PEM (defaults beside the private key)
        #[arg(long, value_name = "PUBLIC_KEY_PEM")]
        public_key: Option<PathBuf>,
    },
}

fn setup_logging() {
    // `tracing_subscriber::FmtSubscriber` defaults to ANSI escape
    // codes regardless of stdout being a tty, which renders as
    // literal `␛[2m`/`␛[32m` garbage when the GUI captures the
    // child's stdout into its log pane. Honour the `NO_COLOR`
    // convention (https://no-color.org) plus the GUI's own
    // `DYNOBOX_GUI=1` marker so plain text comes through whenever a
    // non-tty front-end is consuming the stream.
    let plain = std::env::var_os("NO_COLOR").is_some() || std::env::var_os("DYNOBOX_GUI").is_some();
    // Concise, uniform line style for every log line: `<LEVEL> <message>`.
    // The module target (`dynobox_cli:`) and per-line timestamp are dropped —
    // they add width without value for an interactive one-shot CLI, and
    // long-running work already surfaces elapsed time via the indicatif
    // progress spinner.
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_ansi(!plain)
        .with_target(false)
        .without_time()
        .compact()
        .finish();
    // `set_global_default` returns `SetGlobalDefaultError` when the
    // subscriber is already installed. The CLI binary calls
    // `cli_main` exactly once so the first call wins — but tests
    // (and any future in-process re-entry from the GUI binary)
    // would `.expect()` panic on the second call. Drop the error
    // silently: the existing subscriber stays active.
    let _ = tracing::subscriber::set_global_default(subscriber);
}

fn resolve_output_dir(output: Option<PathBuf>, default_name: &str) -> PathBuf {
    output.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_default()
            .join(default_name)
    })
}

fn parse_apply_positional_args(
    ota_zips: &[PathBuf],
    unpack: &mut bool,
    resign: &mut bool,
    repack: &mut bool,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut real_zips = Vec::new();
    for arg in ota_zips {
        match arg.to_string_lossy().to_lowercase().as_str() {
            "resign" => *resign = true,
            "repack" => *repack = true,
            "unpack" => *unpack = true,
            "complete" => anyhow::bail!("`complete` must be passed as `--complete`."),
            _ => real_zips.push(arg.clone()),
        }
    }
    Ok(real_zips)
}

struct ApplyResignOptions<'a> {
    key: &'a Option<String>,
    algorithm: &'a Option<String>,
    force: bool,
    rollback_index: &'a Option<u64>,
    boot_spl: &'a Option<String>,
    vendor_spl: &'a Option<String>,
    system_spl: &'a Option<String>,
    fuck_lgsi: &'a Option<String>,
    debloat: bool,
    plus: &'a [PathBuf],
}

impl ApplyResignOptions<'_> {
    fn has_any(&self) -> bool {
        self.key.is_some()
            || self.algorithm.is_some()
            || self.force
            || self.rollback_index.is_some()
            || self.boot_spl.is_some()
            || self.vendor_spl.is_some()
            || self.system_spl.is_some()
            || self.fuck_lgsi.is_some()
            || self.debloat
            || !self.plus.is_empty()
    }
}

fn validate_apply_resign_options(
    resign: bool,
    options: &ApplyResignOptions<'_>,
) -> anyhow::Result<()> {
    if !resign && options.has_any() {
        anyhow::bail!("`apply` resign options require `resign` or `--resign`.");
    }
    if resign && options.key.is_none() {
        anyhow::bail!("`apply resign` requires `--key`.");
    }
    Ok(())
}

fn resolve_info_output_path(output: Option<PathBuf>, format: ReportFormat) -> Option<PathBuf> {
    resolve_report_output_path(output, format, "avb_info.txt", "avb_info.json")
}

fn resolve_verify_output_path(output: Option<PathBuf>, format: ReportFormat) -> Option<PathBuf> {
    resolve_report_output_path(output, format, "verify_report.txt", "verify_report.json")
}

fn default_public_key_path(private_key: &Path) -> PathBuf {
    private_key.with_extension("pub.pem")
}

fn resolve_report_output_path(
    output: Option<PathBuf>,
    format: ReportFormat,
    default_text_name: &str,
    default_json_name: &str,
) -> Option<PathBuf> {
    output.map(|path| {
        if path.is_dir() {
            let default_name = match format {
                ReportFormat::Text => default_text_name,
                ReportFormat::Json => default_json_name,
            };
            path.join(default_name)
        } else {
            path
        }
    })
}

/// Map clap's `Option<String>` for `--fuck-lgsi` into a [`FuckLgsiMode`]:
/// * `None` — flag absent, no LGSI patch.
/// * `Some("")` — bare `--fuck-lgsi`, interactive pause-on-Enter flow.
/// * `Some(path)` — `--fuck-lgsi <path>`, non-interactive scripted run
///   against that JSON file.
fn resolve_fuck_lgsi_mode(fuck_lgsi: Option<String>) -> Option<FuckLgsiMode> {
    match fuck_lgsi {
        None => None,
        Some(s) if s.is_empty() => Some(FuckLgsiMode::Interactive),
        Some(path) => Some(FuckLgsiMode::Config(PathBuf::from(path))),
    }
}

/// Map the `--debloat` flag to a [`DebloatMode`]:
/// * `None` — flag absent, no debloat.
/// * `Some("")` — bare `--debloat`, interactive edit-then-Enter flow.
/// * `Some(path)` — `--debloat <path>`, non-interactive from that list file.
fn resolve_debloat_mode(debloat: Option<String>) -> Option<DebloatMode> {
    match debloat {
        None => None,
        Some(s) if s.is_empty() => Some(DebloatMode::Interactive),
        Some(path) => Some(DebloatMode::ListFile(PathBuf::from(path))),
    }
}

#[allow(clippy::too_many_arguments)]
fn make_resign_config(
    key: Option<String>,
    algorithm: Option<String>,
    force: bool,
    rollback_index: Option<u64>,
    boot_spl: Option<String>,
    vendor_spl: Option<String>,
    system_spl: Option<String>,
    fuck_lgsi: Option<FuckLgsiMode>,
    debloat: Option<DebloatMode>,
    plus: Vec<PathBuf>,
) -> Option<ResignConfig> {
    key.map(|key| ResignConfig {
        key,
        algorithm,
        force,
        rollback_index,
        boot_spl,
        vendor_spl,
        system_spl,
        fuck_lgsi,
        debloat,
        plus,
    })
}

fn parse_boot_spl(value: &str) -> Result<String, String> {
    dynobox_app::boot_spl::validate_spl_format(value)
        .map(|_| value.to_string())
        .map_err(|e| e.to_string())
}

fn parse_vendor_spl(value: &str) -> Result<String, String> {
    dynobox_app::vendor_spl::validate_spl_format(value)
        .map(|_| value.to_string())
        .map_err(|e| e.to_string())
}

fn parse_system_spl(value: &str) -> Result<String, String> {
    dynobox_app::system_spl::validate_spl_format(value)
        .map(|_| value.to_string())
        .map_err(|e| e.to_string())
}

fn command_name(command: CommandKind) -> &'static str {
    match command {
        CommandKind::Unpack => "unpack",
        CommandKind::Apply => "apply",
        CommandKind::Resign => "resign",
        CommandKind::Repack => "repack",
    }
}

fn stage_name(stage: StageKind) -> &'static str {
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
struct TextPathShortener {
    roots: Vec<String>,
}

impl TextPathShortener {
    fn shorten_event(&mut self, event: ProgressEvent) -> ProgressEvent {
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

    fn shorten_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
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

struct PathSpan {
    path_start: usize,
    path_end: usize,
    scan_end: usize,
}

fn token_end(text: &str, start: usize) -> usize {
    start
        + text[start..]
            .find(char::is_whitespace)
            .unwrap_or(text.len() - start)
}

fn trim_path_end(text: &str, start: usize, mut end: usize) -> usize {
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

fn is_path_candidate(path: &str, raw: &str) -> bool {
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

fn is_excluded_path_syntax(path: &str, raw: &str) -> bool {
    path.is_empty()
        || path.contains("://")
        || path.starts_with("//")
        || path.contains('=')
        || is_dex_or_jvm_identifier(raw)
}

fn is_dex_or_jvm_identifier(raw: &str) -> bool {
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

fn display_name(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches(['/', '\\']);
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
}

fn is_path_separator(ch: char) -> bool {
    matches!(ch, '/' | '\\')
}

fn is_path_terminator(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '.' | ',' | ';' | '!' | '?' | ')' | ']' | '}' | '>' | '"' | '\'' | '`'
        )
}

fn is_path_boundary_before(text: &str, index: usize) -> bool {
    index == 0
        || text[..index].chars().next_back().is_some_and(|ch| {
            ch.is_whitespace() || matches!(ch, '"' | '\'' | '`' | '(' | '[' | '{' | '<')
        })
}

fn log_event(event: ProgressEvent) {
    match event {
        ProgressEvent::CommandStarted {
            command,
            input,
            output,
        } => {
            info!(
                "{}: {} -> {}",
                command_name(command),
                input.display(),
                output.display()
            );
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
            info!("{} [{}/{}] {}", stage_name(stage), current, total, item);
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

fn print_json_line<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

const SPINNER_TICK_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn unit_label(unit: ProgressUnit) -> &'static str {
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
fn build_text_sink() -> impl FnMut(ProgressEvent) {
    use std::io::IsTerminal;

    let interactive = std::io::stderr().is_terminal();
    let mut active_bar: Option<ProgressBar> = None;
    let mut active_item: Option<String> = None;
    let mut bar_is_determinate = false;
    let mut path_shortener = TextPathShortener::default();

    move |event: ProgressEvent| {
        let event = path_shortener.shorten_event(event);
        match &event {
            ProgressEvent::ItemProgress {
                item,
                done,
                total,
                unit,
                ..
            } => {
                if !interactive {
                    return;
                }
                let total = *total;
                let done = *done;
                let unit_str = unit_label(*unit);

                let upgrade = !bar_is_determinate || active_item.as_deref() != Some(item.as_str());
                if upgrade {
                    if let Some(pb) = active_bar.take() {
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
                    active_bar = Some(pb);
                    active_item = Some(item.clone());
                    bar_is_determinate = total > 0;
                }
                if let Some(pb) = active_bar.as_ref() {
                    if total > 0 {
                        pb.set_length(total);
                        pb.set_position(done);
                    }
                }
            }
            other => {
                if let Some(pb) = active_bar.take() {
                    pb.finish_and_clear();
                }
                bar_is_determinate = false;
                active_item = None;
                let starts_work = matches!(
                    other,
                    ProgressEvent::ItemStarted { .. } | ProgressEvent::StageStarted { .. }
                );
                let item_label = match other {
                    ProgressEvent::ItemStarted { item, .. } => Some(item.clone()),
                    _ => None,
                };
                log_event(event);
                if interactive && starts_work {
                    let pb = ProgressBar::new_spinner();
                    pb.set_style(
                        ProgressStyle::with_template("    {spinner:.cyan} {msg} ({elapsed})")
                            .expect("static spinner template parses")
                            .tick_strings(SPINNER_TICK_FRAMES),
                    );
                    pb.set_message(item_label.clone().unwrap_or_else(|| "working…".into()));
                    pb.enable_steady_tick(Duration::from_millis(120));
                    active_bar = Some(pb);
                    active_item = item_label;
                }
            }
        }
    }
}

/// Entry point for the DynoBox CLI. The `dynobox` binary is a thin
/// wrapper that calls `cli_main(std::env::args_os())`. The dual-mode
/// `dynobox-gui` binary calls into this function directly when its
/// argv contains anything beyond the program name, so a single shipped
/// executable covers both the CLI and the GUI front-end.
///
/// `args` is anything `clap::Parser::parse_from` accepts — a
/// `Vec<String>`, `std::env::args_os()`, etc.
pub fn cli_main<I, T>(args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    if cli.progress_format == ProgressFormat::Text {
        setup_logging();
    }

    let mut text_sink = build_text_sink();
    let mut jsonl_sink = |event: ProgressEvent| {
        let _ = print_json_line(&event);
    };

    match cli.command {
        Commands::Unpack {
            input,
            output,
            integrity_key,
            resign,
            repack,
            key,
            algorithm,
            force,
            rollback,
            boot_spl,
            vendor_spl,
            system_spl,
            fuck_lgsi,
            debloat,
            plus,
            info,
            complete,
        } => {
            if resign && key.is_none() {
                anyhow::bail!("`unpack --resign` requires `--key`.");
            }

            let out_dir =
                resolve_output_dir(output, default_output_name_for_unpack(resign, repack));
            let request = UnpackRequest {
                input,
                output: out_dir,
                integrity_key,
                resign: make_resign_config(
                    key,
                    algorithm,
                    force,
                    rollback,
                    boot_spl,
                    vendor_spl,
                    system_spl,
                    resolve_fuck_lgsi_mode(fuck_lgsi),
                    resolve_debloat_mode(debloat),
                    plus,
                ),
                repack,
                complete,
                info,
            };
            match cli.progress_format {
                ProgressFormat::Text => run_unpack(&request, &mut text_sink),
                ProgressFormat::Jsonl => run_unpack(&request, &mut jsonl_sink),
            }
        }
        Commands::Apply {
            input,
            output,
            integrity_key,
            mut unpack,
            mut resign,
            mut repack,
            key,
            algorithm,
            force,
            rollback,
            boot_spl,
            vendor_spl,
            system_spl,
            fuck_lgsi,
            debloat,
            plus,
            info,
            complete,
            ota_zips,
        } => {
            // Extract bare pipeline keywords from positional args.
            // Users can write `apply ota1.zip resign repack` instead of
            // `apply ota1.zip --resign --repack`.
            let real_zips =
                parse_apply_positional_args(&ota_zips, &mut unpack, &mut resign, &mut repack)?;

            if real_zips.is_empty() {
                anyhow::bail!("No OTA zip files provided.");
            }

            let resign_options = ApplyResignOptions {
                key: &key,
                algorithm: &algorithm,
                force,
                rollback_index: &rollback,
                boot_spl: &boot_spl,
                vendor_spl: &vendor_spl,
                system_spl: &system_spl,
                fuck_lgsi: &fuck_lgsi,
                debloat: debloat.is_some(),
                plus: &plus,
            };
            validate_apply_resign_options(resign, &resign_options)?;

            let lgsi_mode = resolve_fuck_lgsi_mode(fuck_lgsi);
            let debloat_mode = resolve_debloat_mode(debloat);

            let out_dir = resolve_output_dir(output, default_output_name_for_apply(resign, repack));
            let request = ApplyRequest {
                input,
                output: out_dir,
                integrity_key,
                ota_zips: real_zips,
                force_unpack: unpack,
                resign: make_resign_config(
                    key,
                    algorithm,
                    force,
                    rollback,
                    boot_spl,
                    vendor_spl,
                    system_spl,
                    lgsi_mode,
                    debloat_mode,
                    plus,
                ),
                repack,
                complete,
                info,
            };
            match cli.progress_format {
                ProgressFormat::Text => run_apply(&request, &mut text_sink),
                ProgressFormat::Jsonl => run_apply(&request, &mut jsonl_sink),
            }
        }
        Commands::Resign {
            input,
            output,
            integrity_key,
            key,
            algorithm,
            force,
            rollback,
            boot_spl,
            vendor_spl,
            system_spl,
            fuck_lgsi,
            debloat,
            plus,
            info,
            repack,
        } => {
            let out_dir = resolve_output_dir(output, default_output_name_for_resign(repack));
            let lgsi_mode = resolve_fuck_lgsi_mode(fuck_lgsi);
            let request = ResignRequest {
                input,
                output: out_dir,
                integrity_key,
                config: ResignConfig {
                    key,
                    algorithm,
                    force,
                    rollback_index: rollback,
                    boot_spl,
                    vendor_spl,
                    system_spl,
                    fuck_lgsi: lgsi_mode,
                    debloat: resolve_debloat_mode(debloat),
                    plus,
                },
                repack,
                info,
            };
            match cli.progress_format {
                ProgressFormat::Text => run_resign(&request, &mut text_sink),
                ProgressFormat::Jsonl => run_resign(&request, &mut jsonl_sink),
            }
        }
        Commands::Repack {
            input,
            output,
            integrity_key,
        } => {
            let out_dir = resolve_output_dir(output, "output_repack");
            let request = RepackRequest {
                input,
                output: out_dir,
                integrity_key,
            };
            match cli.progress_format {
                ProgressFormat::Text => run_repack(&request, &mut text_sink),
                ProgressFormat::Jsonl => run_repack(&request, &mut jsonl_sink),
            }
        }
        Commands::Info {
            input,
            format,
            output,
        } => {
            if cli.progress_format == ProgressFormat::Text {
                info!("info: {}", input.display());
            }

            let report = match format {
                ReportFormat::Text => avbtool_rs::info::generate_info_report(&input)?,
                ReportFormat::Json => {
                    let entries = avbtool_rs::info::scan_input(&input)?;
                    serde_json::to_string_pretty(&entries)?
                }
            };
            if let Some(output_path) = resolve_info_output_path(output, format) {
                if let Some(parent) = output_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                let mut file = std::fs::File::create(&output_path)?;
                file.write_all(report.as_bytes())?;
                if cli.progress_format == ProgressFormat::Text {
                    info!("saved: {}", output_path.display());
                }
            } else {
                print!("{report}");
            }
            Ok(())
        }
        Commands::Verify {
            input,
            format,
            output,
            trusted_integrity_key,
            trust_manifest_attestation,
        } => {
            if cli.progress_format == ProgressFormat::Text {
                info!("verify: {}", input.display());
            }

            let report = verify_input_with_options(
                &input,
                &VerificationOptions {
                    trusted_integrity_keys: trusted_integrity_key,
                    trust_manifest_attestation,
                },
            )?;
            let rendered = match format {
                ReportFormat::Text => render_verification_report(&report),
                ReportFormat::Json => serde_json::to_string_pretty(&report)?,
            };
            if let Some(output_path) = resolve_verify_output_path(output, format) {
                if let Some(parent) = output_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                let mut file = std::fs::File::create(&output_path)?;
                file.write_all(rendered.as_bytes())?;
                if cli.progress_format == ProgressFormat::Text {
                    info!("saved: {}", output_path.display());
                }
            } else {
                print!("{rendered}");
            }

            dynobox_app::ensure_verification_clean(&report)
        }
        Commands::IntegrityKeygen {
            private_key,
            public_key,
        } => {
            let public_key = public_key.unwrap_or_else(|| default_public_key_path(&private_key));
            let key_id = generate_integrity_keypair(&private_key, &public_key)?;
            println!("Generated Ed25519 integrity key: {key_id}");
            println!("Private key: {}", private_key.display());
            println!("Public key:  {}", public_key.display());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{
        ApplyResignOptions, Cli, Commands, TextPathShortener, default_public_key_path,
        parse_apply_positional_args, validate_apply_resign_options,
    };
    use dynobox_app::{CommandKind, MessageLevel, ProgressEvent, StageKind};
    use std::path::PathBuf;

    #[test]
    fn cli_parses_manifest_signing_and_trusted_key_options() {
        let repack = Cli::try_parse_from([
            "dynobox",
            "repack",
            "--input",
            "input",
            "--integrity-key",
            "signing.pem",
        ])
        .unwrap();
        assert!(matches!(
            repack.command,
            Commands::Repack {
                integrity_key: Some(path),
                ..
            } if path.as_path() == std::path::Path::new("signing.pem")
        ));

        let verify = Cli::try_parse_from([
            "dynobox",
            "verify",
            "--input",
            "output",
            "--trusted-integrity-key",
            "one.pub.pem",
            "--trusted-integrity-key",
            "two.pub.pem",
            "--trust-manifest-attestation",
        ])
        .unwrap();
        assert!(matches!(
            verify.command,
            Commands::Verify {
                trusted_integrity_key,
                trust_manifest_attestation: true,
                ..
            } if trusted_integrity_key.len() == 2
        ));
    }

    #[test]
    fn text_path_shortener_keeps_command_paths_and_shortens_windows_items() {
        let mut shortener = TextPathShortener::default();
        let started = ProgressEvent::CommandStarted {
            command: CommandKind::Resign,
            input: PathBuf::from(r"D:\Git\DynoBox\firmware\image"),
            output: PathBuf::from(r"D:\Git\DynoBox\output"),
        };
        assert_eq!(shortener.shorten_event(started.clone()), started);

        let item = ProgressEvent::ItemStarted {
            stage: StageKind::Resign,
            current: 1,
            total: 1,
            item: r"D:\Git\DynoBox\output\boot.img".to_string(),
        };
        assert!(matches!(
            shortener.shorten_event(item),
            ProgressEvent::ItemStarted { item, .. } if item == "boot.img"
        ));
    }

    #[test]
    fn text_path_shortener_shortens_posix_path_embedded_in_message() {
        let shortener = TextPathShortener::default();
        assert_eq!(
            shortener.shorten_text("Report written to /tmp/dynobox-stage/report.html."),
            "Report written to report.html."
        );
    }

    #[test]
    fn text_path_shortener_shortens_multiple_paths() {
        let shortener = TextPathShortener::default();
        assert_eq!(
            shortener.shorten_text(r"Copied D:\work\input\boot.img to /tmp/output/boot.img."),
            "Copied boot.img to boot.img."
        );
    }

    #[test]
    fn text_path_shortener_shortens_delimited_path_with_spaces() {
        let shortener = TextPathShortener::default();
        assert_eq!(
            shortener.shorten_text(
                r"Preflight `D:\Firmware Files\OTA Builds\update 117.zip`: 4 partitions."
            ),
            "Preflight `update 117.zip`: 4 partitions."
        );
    }

    #[test]
    fn text_path_shortener_leaves_non_path_text_unchanged() {
        let shortener = TextPathShortener::default();
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let text = format!(
            "Keep system:/system/app/Foo.apk, version 1.5.10.063, {digest}, https://example.com/a/b, ro.product.config=/system/etc/build.prop, and Lcom/lenovo/settings/privacy/UserExperienceSwitchController;."
        );
        assert_eq!(shortener.shorten_text(&text), text);
    }

    #[test]
    fn text_path_shortener_handles_anchored_root_with_spaces() {
        let mut shortener = TextPathShortener::default();
        let _ = shortener.shorten_event(ProgressEvent::CommandStarted {
            command: CommandKind::Apply,
            input: PathBuf::from(r"D:\Firmware Images\image"),
            output: PathBuf::from(r"D:\DynoBox Output\final"),
        });
        let event = ProgressEvent::Message {
            level: MessageLevel::Info,
            text: r"Staged D:\DynoBox Output\final\report.html.".to_string(),
        };
        assert!(matches!(
            shortener.shorten_event(event),
            ProgressEvent::Message { text, .. } if text == "Staged report.html."
        ));
    }

    #[test]
    fn text_path_shortener_uses_final_component_for_remembered_relative_roots() {
        let mut shortener = TextPathShortener::default();
        let _ = shortener.shorten_event(ProgressEvent::CommandStarted {
            command: CommandKind::Apply,
            input: PathBuf::from("patches"),
            output: PathBuf::from("output"),
        });

        assert_eq!(
            shortener.shorten_text("Staged output/stage/report.html."),
            "Staged report.html."
        );
        assert_eq!(
            shortener.shorten_text("Loaded patches/vendor/update.dbp."),
            "Loaded update.dbp."
        );
        assert_eq!(
            shortener.shorten_text(r#"Saved `output/stage/report final.html`."#),
            r#"Saved `report final.html`."#
        );
    }

    #[test]
    fn text_path_shortener_leaves_live_slash_separated_prose_unchanged() {
        let shortener = TextPathShortener::default();
        let verification = "Semantic verification: ACCEPTED from trusted signed manifest (local AVB/XML/super skipped)";
        let unpack = "Unpack workspace: 12 hardlink(s), 3 copy/copies.";

        assert_eq!(shortener.shorten_text(verification), verification);
        assert_eq!(shortener.shorten_text(unpack), unpack);
    }

    #[test]
    fn text_path_shortener_leaves_unanchored_relative_tokens_unchanged() {
        let shortener = TextPathShortener::default();
        let text = "Answer y/N and preserve and/or in this sentence.";
        assert_eq!(shortener.shorten_text(text), text);

        let quoted = r#"Loaded "patches/vendor/update.dbp"."#;
        assert_eq!(shortener.shorten_text(quoted), quoted);
    }

    #[test]
    fn text_path_shortener_leaves_dex_and_jvm_identifiers_unchanged() {
        let shortener = TextPathShortener::default();
        let prototype = "(Landroid/content/Context;)Z";
        let method = "Lcom/zui/setupwizard/Foo;->initView()V";

        assert_eq!(shortener.shorten_text(prototype), prototype);
        assert_eq!(shortener.shorten_text(method), method);
    }

    #[test]
    fn text_path_shortener_handles_single_and_double_quoted_paths_with_spaces() {
        let shortener = TextPathShortener::default();
        assert_eq!(
            shortener.shorten_text(
                r#"Loaded "D:\Firmware Files\update.zip" and 'D:\OTA Builds\next.zip'."#
            ),
            r#"Loaded "update.zip" and 'next.zip'."#
        );
    }

    #[test]
    fn text_path_shortener_handles_unc_and_extended_length_paths() {
        let shortener = TextPathShortener::default();
        let text = r"Copied \\server\share\firmware\boot.img to \\?\D:\DynoBox\output\boot.img.";
        assert_eq!(shortener.shorten_text(text), "Copied boot.img to boot.img.");

        let mut rooted_shortener = TextPathShortener::default();
        let _ = rooted_shortener.shorten_event(ProgressEvent::CommandStarted {
            command: CommandKind::Apply,
            input: PathBuf::from(r"\\server\share\firmware"),
            output: PathBuf::from(r"\\?\D:\DynoBox\output"),
        });
        assert_eq!(
            rooted_shortener.shorten_text(text),
            "Copied boot.img to boot.img."
        );
    }

    #[test]
    fn text_path_shortener_leaves_scheme_relative_urls_unchanged() {
        let shortener = TextPathShortener::default();
        let text = "Fetch //cdn.example.com/a/b before continuing.";
        assert_eq!(shortener.shorten_text(text), text);
    }

    #[test]
    fn cli_parses_unpack_resign_mutation_options() {
        let cli = Cli::try_parse_from([
            "dynobox",
            "unpack",
            "--input",
            "input",
            "--resign",
            "--key",
            "testkey_rsa4096",
            "--fuck-lgsi=lgsi_features.json",
            "--debloat=debloat.txt",
            "--plus=one.dbp",
            "--plus=two.dbp",
        ])
        .expect("unpack should accept resign mutation options");

        assert!(matches!(
            cli.command,
            Commands::Unpack {
                fuck_lgsi: Some(fuck_lgsi),
                debloat: Some(debloat),
                plus,
                ..
            } if fuck_lgsi == "lgsi_features.json"
                && debloat == "debloat.txt"
                && plus == [PathBuf::from("one.dbp"), PathBuf::from("two.dbp")]
        ));
    }

    #[test]
    fn default_public_key_path_uses_pub_pem_extension() {
        assert_eq!(
            default_public_key_path(PathBuf::from("keys/integrity.pem").as_path()),
            PathBuf::from("keys/integrity.pub.pem")
        );
    }

    #[test]
    fn parse_apply_positional_args_accepts_bare_pipeline_keywords() {
        let ota_zips = vec![
            PathBuf::from("update1.zip"),
            PathBuf::from("resign"),
            PathBuf::from("repack"),
            PathBuf::from("unpack"),
            PathBuf::from("update2.zip"),
        ];
        let mut unpack = false;
        let mut resign = false;
        let mut repack = false;

        let real = parse_apply_positional_args(&ota_zips, &mut unpack, &mut resign, &mut repack)
            .expect("expected positional parse to succeed");

        assert!(unpack);
        assert!(resign);
        assert!(repack);
        assert_eq!(
            real,
            vec![PathBuf::from("update1.zip"), PathBuf::from("update2.zip")]
        );
    }

    #[test]
    fn parse_apply_positional_args_rejects_bare_complete_keyword() {
        let ota_zips = vec![PathBuf::from("update1.zip"), PathBuf::from("complete")];
        let mut unpack = false;
        let mut resign = false;
        let mut repack = false;

        let err = parse_apply_positional_args(&ota_zips, &mut unpack, &mut resign, &mut repack)
            .expect_err("bare complete must be rejected");
        assert!(err.to_string().contains("`--complete`"));
    }

    #[test]
    fn validate_apply_resign_options_rejects_key_without_resign() {
        let key = Some("testkey_rsa2048".to_string());
        let options = ApplyResignOptions {
            key: &key,
            algorithm: &None,
            force: false,
            rollback_index: &None,
            boot_spl: &None,
            vendor_spl: &None,
            system_spl: &None,
            fuck_lgsi: &None,
            debloat: false,
            plus: &[],
        };
        let err = validate_apply_resign_options(false, &options)
            .expect_err("key without resign should be rejected");

        assert!(err.to_string().contains("require `resign`"));
    }

    #[test]
    fn validate_apply_resign_options_rejects_boot_spl_without_resign() {
        let boot_spl = Some("2026-04-30".to_string());
        let options = ApplyResignOptions {
            key: &None,
            algorithm: &None,
            force: false,
            rollback_index: &None,
            boot_spl: &boot_spl,
            vendor_spl: &None,
            system_spl: &None,
            fuck_lgsi: &None,
            debloat: false,
            plus: &[],
        };
        let err = validate_apply_resign_options(false, &options)
            .expect_err("boot SPL without resign should be rejected");

        assert!(err.to_string().contains("require `resign`"));
    }

    #[test]
    fn validate_apply_resign_options_rejects_resign_without_key() {
        let options = ApplyResignOptions {
            key: &None,
            algorithm: &None,
            force: false,
            rollback_index: &None,
            boot_spl: &None,
            vendor_spl: &None,
            system_spl: &None,
            fuck_lgsi: &None,
            debloat: false,
            plus: &[],
        };
        let err = validate_apply_resign_options(true, &options)
            .expect_err("resign without key should be rejected");

        assert!(err.to_string().contains("requires `--key`"));
    }

    #[test]
    fn validate_apply_resign_options_accepts_resign_with_key() {
        let key = Some("testkey_rsa2048".to_string());
        let algorithm = Some("SHA256_RSA2048".to_string());
        let rollback_index = Some(1);
        let boot_spl = Some("2026-04-30".to_string());
        let vendor_spl = Some("2026-04-30".to_string());
        let system_spl = Some("2026-04-30".to_string());
        let options = ApplyResignOptions {
            key: &key,
            algorithm: &algorithm,
            force: true,
            rollback_index: &rollback_index,
            boot_spl: &boot_spl,
            vendor_spl: &vendor_spl,
            system_spl: &system_spl,
            fuck_lgsi: &Some(String::new()),
            debloat: false,
            plus: &[],
        };
        validate_apply_resign_options(true, &options).expect("resign with key should be accepted");
    }
}
