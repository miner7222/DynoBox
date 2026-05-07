//! Thin wrapper around [`dynobox_cli::cli_main`]. All the actual CLI
//! parsing + pipeline driving lives in `lib.rs` so the dual-mode
//! `dynobox-gui` binary can call into this crate as a library
//! dependency without spawning a subprocess.

fn main() -> anyhow::Result<()> {
    dynobox_cli::cli_main(std::env::args_os())
}
