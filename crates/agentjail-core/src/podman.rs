//! Thin, read-only wrappers around the podman CLI.
//!
//! Everything here is optional in the sense that a missing podman must never
//! panic: the caller gets an error and decides. No command is ever run through a
//! shell, and nothing here mutates host state.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TIMEOUT_HINT: &str =
    "podman inspection is bounded by the caller's patience, not by a timeout";

/// A finished command, with both streams captured.
#[derive(Debug, Clone)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == 0
    }

    pub fn stdout_trimmed(&self) -> &str {
        self.stdout.trim()
    }
}

/// Find an executable on PATH without invoking a shell.
pub fn find_in_path(program: &str, path_var: Option<&OsStr>) -> Option<PathBuf> {
    let path_var = path_var?;
    for directory in std::env::split_paths(path_var) {
        let candidate = directory.join(program);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Run `program args...` with no shell, capturing output.
///
/// `env` is the process environment to use; pass `None` to inherit.
pub fn run(
    program: &Path,
    args: &[&str],
    env: Option<&std::collections::BTreeMap<String, String>>,
) -> std::io::Result<Output> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(env) = env {
        command.env_clear();
        for (key, value) in env {
            command.env(key, value);
        }
    }
    let output = command.output()?;
    Ok(Output {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// The podman executable to use.
///
/// `AGENTJAIL_PODMAN` overrides discovery. It exists so the test suite and CI
/// can supply a fixture instead of a real runtime; it never changes what the
/// launcher does with the result.
pub fn binary() -> Option<PathBuf> {
    discover(
        std::env::var("AGENTJAIL_PODMAN").ok().as_deref(),
        std::env::var_os("PATH").as_deref(),
    )
}

/// Discovery against an explicit environment, so `doctor` reports on the
/// environment it was handed rather than on the process's own.
pub fn discover(override_path: Option<&str>, path_var: Option<&OsStr>) -> Option<PathBuf> {
    if let Some(path) = override_path {
        return Some(PathBuf::from(path));
    }
    find_in_path("podman", path_var)
}

/// Run `podman args...`, inheriting the current environment.
pub fn podman(args: &[&str]) -> Result<Output, String> {
    let binary = binary().ok_or_else(|| "podman is not installed or not on PATH".to_string())?;
    run(&binary, args, None).map_err(|error| format!("cannot run {binary:?}: {error}"))
}

/// `podman <args...>` output on success, or a readable error.
pub fn podman_stdout(args: &[&str]) -> Result<String, String> {
    let output = podman(args)?;
    if !output.success() {
        let detail = if output.stderr.is_empty() {
            output.stdout.trim().to_string()
        } else {
            output.stderr.trim().to_string()
        };
        return Err(format!(
            "podman {} failed (exit {}): {detail}",
            args.join(" "),
            output.code
        ));
    }
    Ok(output.stdout_trimmed().to_string())
}

/// `podman network inspect <name>` as raw JSON.
pub fn network_inspect(name: &str) -> Result<String, String> {
    podman_stdout(&["network", "inspect", name])
}

/// The invariant check used by `run` (preflight) and `doctor --network`.
pub fn verify_network(name: &str) -> Result<crate::network::NetworkPosture, String> {
    let raw = network_inspect(name)?;
    crate::network::verify_inspect_json(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_path_var_means_not_found() {
        assert_eq!(find_in_path("podman", None), None);
    }

    #[test]
    fn non_executable_file_is_not_found() {
        let dir = std::env::temp_dir().join(format!("agentjail-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let file = dir.join("podman");
        std::fs::write(&file, b"#!/bin/sh\n").expect("write");
        let path_var = std::env::join_paths([dir.as_path()]).expect("join");
        assert_eq!(find_in_path("podman", Some(&path_var)), None);
        std::fs::remove_dir_all(&dir).ok();
    }
}
