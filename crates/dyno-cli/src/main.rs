use clap::{Parser, Subcommand, ValueEnum};
use dynobox_app::{
    ApplyRequest, CommandKind, MessageLevel, ProgressEvent, RepackRequest, ResignConfig,
    ResignRequest, StageKind, UnpackRequest, default_output_name_for_apply,
    default_output_name_for_resign, default_output_name_for_unpack, render_verification_report,
    run_apply, run_repack, run_resign, run_unpack, verify_input,
};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
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
    },
}

fn setup_logging() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set up logging subscriber");
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

fn resolve_info_output_path(output: Option<PathBuf>, format: ReportFormat) -> Option<PathBuf> {
    resolve_report_output_path(output, format, "avb_info.txt", "avb_info.json")
}

fn resolve_verify_output_path(output: Option<PathBuf>, format: ReportFormat) -> Option<PathBuf> {
    resolve_report_output_path(output, format, "verify_report.txt", "verify_report.json")
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

fn make_resign_config(
    key: Option<String>,
    algorithm: Option<String>,
    force: bool,
    rollback_index: Option<u64>,
    boot_spl: Option<String>,
    vendor_spl: Option<String>,
) -> Option<ResignConfig> {
    key.map(|key| ResignConfig {
        key,
        algorithm,
        force,
        rollback_index,
        boot_spl,
        vendor_spl,
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

fn log_event(event: ProgressEvent) {
    match event {
        ProgressEvent::CommandStarted {
            command,
            input,
            output,
        } => {
            info!("{} command initiated.", command_name(command));
            info!("Input directory: {}", input.display());
            info!("Output directory: {}", output.display());
        }
        ProgressEvent::StageStarted { stage } => {
            info!("Starting {} stage...", stage_name(stage));
        }
        ProgressEvent::StageCompleted { stage } => {
            info!("Completed {} stage.", stage_name(stage));
        }
        ProgressEvent::ItemStarted {
            stage,
            current,
            total,
            item,
        } => {
            info!("{} {}/{}: {}", stage_name(stage), current, total, item);
        }
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.progress_format == ProgressFormat::Text {
        setup_logging();
    }

    let mut text_sink = log_event;
    let mut jsonl_sink = |event: ProgressEvent| {
        let _ = print_json_line(&event);
    };

    match cli.command {
        Commands::Unpack {
            input,
            output,
            resign,
            repack,
            key,
            algorithm,
            force,
            rollback,
            boot_spl,
            vendor_spl,
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
                resign: make_resign_config(key, algorithm, force, rollback, boot_spl, vendor_spl),
                repack,
                complete,
            };
            match cli.progress_format {
                ProgressFormat::Text => run_unpack(&request, &mut text_sink),
                ProgressFormat::Jsonl => run_unpack(&request, &mut jsonl_sink),
            }
        }
        Commands::Apply {
            input,
            output,
            mut unpack,
            mut resign,
            mut repack,
            key,
            algorithm,
            force,
            rollback,
            boot_spl,
            vendor_spl,
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

            if resign && key.is_none() {
                anyhow::bail!("`apply resign` requires `--key`.");
            }

            let out_dir = resolve_output_dir(output, default_output_name_for_apply(resign, repack));
            let request = ApplyRequest {
                input,
                output: out_dir,
                ota_zips: real_zips,
                force_unpack: unpack,
                resign: make_resign_config(key, algorithm, force, rollback, boot_spl, vendor_spl),
                repack,
                complete,
            };
            match cli.progress_format {
                ProgressFormat::Text => run_apply(&request, &mut text_sink),
                ProgressFormat::Jsonl => run_apply(&request, &mut jsonl_sink),
            }
        }
        Commands::Resign {
            input,
            output,
            key,
            algorithm,
            force,
            rollback,
            boot_spl,
            vendor_spl,
            repack,
        } => {
            let out_dir = resolve_output_dir(output, default_output_name_for_resign(repack));
            let request = ResignRequest {
                input,
                output: out_dir,
                config: ResignConfig {
                    key,
                    algorithm,
                    force,
                    rollback_index: rollback,
                    boot_spl,
                    vendor_spl,
                },
                repack,
            };
            match cli.progress_format {
                ProgressFormat::Text => run_resign(&request, &mut text_sink),
                ProgressFormat::Jsonl => run_resign(&request, &mut jsonl_sink),
            }
        }
        Commands::Repack { input, output } => {
            let out_dir = resolve_output_dir(output, "output_repack");
            let request = RepackRequest {
                input,
                output: out_dir,
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
                info!("Info command initiated.");
                info!("Input path: {}", input.display());
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
                    info!("AVB info report saved to {}", output_path.display());
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
        } => {
            if cli.progress_format == ProgressFormat::Text {
                info!("Verify command initiated.");
                info!("Input path: {}", input.display());
            }

            let report = verify_input(&input)?;
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
                    info!("Verification report saved to {}", output_path.display());
                }
            } else {
                print!("{rendered}");
            }

            dynobox_app::ensure_verification_clean(&report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_apply_positional_args;
    use std::path::PathBuf;

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
}
