use std::{env, path::PathBuf, process::Command};

/// Run a git command and return trimmed stdout
fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

/// Resolve version as tag then branch-sha then sha then unknown
fn compute_git_rev() -> String {
    if let Some(tag) = git_output(&["describe", "--tags", "--exact-match"]) {
        return tag;
    }

    let Some(sha) = git_output(&["rev-parse", "--short=12", "HEAD"]) else {
        return "unknown".to_owned();
    };

    match git_output(&["rev-parse", "--abbrev-ref", "HEAD"]) {
        Some(branch) if branch != "HEAD" => format!("{branch}@{sha}"),
        _ => sha,
    }
}

/// Emit build rerun hints for git metadata changes
fn emit_git_rerun_hints() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned()));

    for git_dir in [manifest_dir.join(".git"), manifest_dir.join("..").join(".git")] {
        if git_dir.exists() {
            println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
            println!(
                "cargo:rerun-if-changed={}",
                git_dir.join("packed-refs").display()
            );
            break;
        }
    }

    println!("cargo:rerun-if-env-changed=GIT_DIR");
}

fn main() {
    println!("cargo:rustc-env=GIT_REV={}", compute_git_rev());
    emit_git_rerun_hints();
}
