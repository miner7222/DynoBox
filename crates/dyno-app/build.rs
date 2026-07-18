use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Any workspace source change can alter produced firmware, even when the
    // dyno-app package itself is unchanged. Keep the embedded revision's dirty
    // marker honest without watching target/, which would cause rebuild loops.
    println!("cargo:rerun-if-changed=..");
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    emit_git_revision();
}

/// Emit the exact source revision used by output manifests and reports.
///
/// The repository-root check avoids accidentally embedding the revision of a
/// parent checkout when DynoBox is built from an unpacked source archive.
fn emit_git_revision() {
    let Some((repo_root, mut revision)) = dynobox_git_revision() else {
        println!("cargo:rustc-env=DYNOBOX_GIT_REVISION=");
        return;
    };

    for spec in ["HEAD", "index", "packed-refs", "refs"] {
        if let Some(path) = run_git(&repo_root, &["rev-parse", "--git-path", spec]) {
            let path = PathBuf::from(path.trim());
            if !path.as_os_str().is_empty() {
                let path = if path.is_absolute() {
                    path
                } else {
                    repo_root.join(path)
                };
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    if run_git(
        &repo_root,
        &["status", "--porcelain", "--untracked-files=all"],
    )
    .is_some_and(|status| !status.trim().is_empty())
    {
        revision.push_str("-dirty");
    }
    println!("cargo:rustc-env=DYNOBOX_GIT_REVISION={revision}");
}

fn dynobox_git_revision() -> Option<(PathBuf, String)> {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    let expected_root = manifest_dir.parent()?.parent()?.canonicalize().ok()?;
    let actual_root = run_git(&manifest_dir, &["rev-parse", "--show-toplevel"])?;
    let actual_root = Path::new(actual_root.trim()).canonicalize().ok()?;
    if actual_root != expected_root {
        return None;
    }

    let revision = run_git(&actual_root, &["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    if revision.len() < 12 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((actual_root, revision.to_ascii_lowercase()))
}

fn run_git(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}
