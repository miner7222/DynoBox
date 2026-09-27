use clap::{Parser, Subcommand, ValueEnum};
use dynobox_app::debloat::DebloatMode;
use dynobox_app::fuck_lgsi::FuckLgsiMode;
use dynobox_app::{
    ApplyRequest, ProgressEvent, RepackRequest, ResignConfig, ResignRequest, UnpackRequest,
    VerificationOptions, default_output_name_for_apply, default_output_name_for_resign,
    default_output_name_for_unpack, generate_integrity_keypair, render_verification_report,
    run_apply, run_repack, run_resign, run_unpack, verify_input_with_options,
};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod render;
use render::{build_text_sink, print_json_line};

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

        /// Insert static RRO APK(s) into `product.img:/overlay/` during
        /// resign (no mount).
        /// Repeat the flag for several overlays. Requires --resign.
        #[arg(long, value_name = "APK", requires = "resign")]
        add_overlay: Vec<PathBuf>,

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

        /// Insert static RRO APK(s) into `product.img:/overlay/` during
        /// resign (no mount).
        /// Repeat the flag for several overlays. Requires `resign`
        /// or `--resign`; `report.html` records each file by name and SHA-256.
        #[arg(long, value_name = "APK")]
        add_overlay: Vec<PathBuf>,

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

        /// Insert static RRO APK(s) into `product.img:/overlay/` during
        /// resign (no mount).
        /// Repeat the flag for several overlays; `report.html`
        /// records each file by name and SHA-256.
        #[arg(long, value_name = "APK")]
        add_overlay: Vec<PathBuf>,

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
    /// Custom OTA signing and generation
    Ota {
        #[command(subcommand)]
        command: OtaCommand,
    },
}

#[derive(Subcommand, Debug)]
enum OtaCommand {
    /// Generate an RSA OTA signing key and a self-signed certificate. Put the
    /// certificate in an `ota_cert` .dbp op so the patched firmware trusts
    /// only OTAs signed with this key
    Keygen {
        /// Destination for the PKCS#8 private key PEM (must not already exist)
        #[arg(long, value_name = "KEY_PEM")]
        key: PathBuf,

        /// Destination for the X.509 certificate PEM (must not already exist)
        #[arg(long, value_name = "CERT_PEM")]
        cert: PathBuf,

        /// RSA key size. 2048 fits the stock otacerts.zip without compression,
        /// which keeps patched images byte-reproducible across releases
        #[arg(long, default_value_t = 2048, value_parser = parse_ota_key_bits)]
        bits: usize,

        /// Certificate subject common name
        #[arg(long, default_value = "DynoBox OTA")]
        subject: String,
    },
}

fn parse_ota_key_bits(value: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(bits @ (2048 | 4096)) => Ok(bits),
        _ => Err(format!(
            "`{value}` is not a supported OTA key size (2048 or 4096)"
        )),
    }
}

fn setup_logging() {
    // `tracing_subscriber::FmtSubscriber` defaults to ANSI escape
    // codes regardless of stdout being a tty, which renders as
    // literal `␛[2m`/`␛[32m` garbage when stdout is redirected to a
    // file or pipe. Honour the `NO_COLOR` convention
    // (https://no-color.org) and drop colour whenever stdout is not a
    // terminal.
    let plain = std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal();
    // Concise, uniform line style for every log line: `<LEVEL> <message>`.
    // The module target (`dynobox_cli:`) and per-line timestamp are dropped —
    // they add width without value for an interactive one-shot CLI, and
    // long-running work already surfaces elapsed time via the indicatif
    // progress spinner.
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new("info,avbtool_rs=warn"))
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
    add_overlay: &'a [PathBuf],
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
            || !self.add_overlay.is_empty()
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
    add_overlay: Vec<PathBuf>,
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
        add_overlay,
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
            add_overlay,
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
                    add_overlay,
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
            add_overlay,
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
                add_overlay: &add_overlay,
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
                    add_overlay,
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
            add_overlay,
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
                    add_overlay,
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
        Commands::Ota {
            command:
                OtaCommand::Keygen {
                    key,
                    cert,
                    bits,
                    subject,
                },
        } => {
            let generated = dynobox_app::ota::generate_ota_keypair(&key, &cert, bits, &subject)?;
            println!("Generated {}-bit OTA signing key", generated.bits);
            println!("Private key: {}", key.display());
            println!("Certificate: {}", cert.display());
            println!("Certificate SHA-256: {}", generated.cert_sha256);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::render::TextPathShortener;
    use super::{
        ApplyResignOptions, Cli, Commands, default_public_key_path, parse_apply_positional_args,
        validate_apply_resign_options,
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
            add_overlay: &[],
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
            add_overlay: &[],
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
            add_overlay: &[],
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
            add_overlay: &[],
            plus: &[],
        };
        validate_apply_resign_options(true, &options).expect("resign with key should be accepted");
    }
}
