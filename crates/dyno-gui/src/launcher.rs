//! Launch the CLI in a fresh OS terminal window so the pipeline gets a real
//! tty (colours, progress bars, interactive prompts).

#[cfg(unix)]
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

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
pub(crate) fn spawn_in_terminal(exe: &Path, args: &[String]) -> std::io::Result<()> {
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
            // Per-terminal argv differs:
            //   * `gnome-terminal` deprecated `-e` long ago and now
            //     requires `-- <argv>` to forward to the child.
            //   * `kitty` takes a bare command + args (no `-e`).
            //   * Most others still accept `-e <script>`.
            //
            // `$TERMINAL` is honoured first so an opinionated desktop
            // env can override the candidate sweep.
            let user_term = std::env::var("TERMINAL").ok();
            let candidates: Vec<&str> = user_term
                .as_deref()
                .into_iter()
                .chain(
                    [
                        "x-terminal-emulator",
                        "gnome-terminal",
                        "konsole",
                        "xfce4-terminal",
                        "alacritty",
                        "kitty",
                        "xterm",
                    ]
                    .iter()
                    .copied(),
                )
                .collect();
            for term in candidates {
                // `$TERMINAL` may be a full path (e.g.
                // `/usr/bin/gnome-terminal`); match on the basename
                // so the special-case argv dispatch still fires.
                let basename = std::path::Path::new(term)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(term);
                let mut cmd = Command::new(term);
                match basename {
                    "gnome-terminal" => {
                        cmd.arg("--").arg("bash").arg(&script);
                    }
                    "kitty" => {
                        cmd.arg("bash").arg(&script);
                    }
                    _ => {
                        cmd.arg("-e").arg(&script);
                    }
                }
                if cmd.spawn().is_ok() {
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
    // Self-delete after user presses a key. The `(goto) 2>nul & del`
    // idiom releases the script's file handle so cmd can delete the
    // file it's currently executing, sidestepping the temp-file leak
    // that would otherwise pile up under `%TEMP%` across GUI runs.
    content.push_str("(goto) 2>nul & del \"%~f0\"\r\n");

    std::fs::write(&path, content)?;
    Ok(path)
}

/// Quote an argument for safe inclusion in a `.bat` script. Wraps in
/// double-quotes whenever the string contains any of the cmd.exe
/// metacharacters; embedded `"` doubles to `""` (the cmd convention
/// for escaping a literal quote inside a quoted string).
///
/// `%` is **doubled first** even when no other quoting is needed —
/// inside a `.bat` script `%VAR%` expands regardless of whether the
/// surrounding context is double-quoted. Without the double, a
/// Windows path containing `%USERPROFILE%` or similar would silently
/// expand to the running user's profile dir instead of the literal
/// path the GUI captured.
#[cfg(target_os = "windows")]
fn quote_bat(s: &str) -> String {
    let escaped = s.replace('%', "%%");
    if escaped.is_empty() {
        return "\"\"".into();
    }
    let needs_quote = escaped.chars().any(|c| {
        matches!(
            c,
            ' ' | '\t' | '"' | '&' | '|' | '<' | '>' | '^' | '(' | ')'
        )
    });
    if !needs_quote {
        return escaped;
    }
    let mut out = String::with_capacity(escaped.len() + 2);
    out.push('"');
    for ch in escaped.chars() {
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
fn write_unix_launcher(exe: &Path, args: &[String]) -> std::io::Result<PathBuf> {
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
    // Self-delete so the GUI doesn't leak `dynobox-gui-*.sh` /
    // `.command` files under `$TMPDIR` across runs. `rm -- "$0"`
    // works even while bash is interpreting the script — the shell
    // has already read the source into memory.
    script.push_str("rm -- \"$0\" 2>/dev/null || true\n");

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
