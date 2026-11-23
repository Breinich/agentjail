//! Thin wrappers around the podman CLI.
//!
//! Everything here is optional in the sense that a missing podman must never
//! panic: the caller gets an error and decides. No command is ever run through a
//! shell. The mutating calls (network/container create and remove) exist only for
//! the per-run lifecycle in `agentjail run`, which owns what it creates and
//! removes it on every exit path.

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

/// Names of the podman networks that exist.
pub fn network_list() -> Result<Vec<String>, String> {
    let raw = podman_stdout(&["network", "ls", "--format", "{{.Name}}"])?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Create an internal network: no route out, so the only way off it is a peer
/// that has one (the class gateway).
///
/// `--disable-dns` matters twice. Podman otherwise installs its own resolver
/// (aardvark) as the network's nameserver, which shadows the gateway the jail is
/// told to use, and on an internal network that resolver has nowhere to forward
/// to. With it off, `--dns <gateway>` is the jail's only resolver.
pub fn network_create(name: &str) -> Result<(), String> {
    let output = podman(&["network", "create", "--internal", "--disable-dns", name])?;
    if output.success() {
        return Ok(());
    }
    Err(format!(
        "podman network create --internal --disable-dns {name:?} failed ({}): {}",
        output.code,
        output.stderr.trim()
    ))
}

/// Remove a network, ignoring one that is already gone.
pub fn network_remove(name: &str) -> Result<(), String> {
    let output = podman(&["network", "rm", "-f", name])?;
    if output.success()
        || output.stderr.contains("no such network")
        || output.stderr.contains("not found")
    {
        Ok(())
    } else {
        Err(format!(
            "podman network rm -f {name:?} failed ({}): {}",
            output.code,
            output.stderr.trim()
        ))
    }
}

/// Names of containers that exist, running or not.
pub fn container_list() -> Result<Vec<String>, String> {
    let raw = podman_stdout(&["ps", "-a", "--format", "{{.Names}}"])?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Start a detached container from a ready argv (see `run::gateway_args`).
pub fn container_start(args: &[String]) -> Result<(), String> {
    let output = podman(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    if output.success() {
        return Ok(());
    }
    Err(format!(
        "podman {} failed ({}): {}",
        args.join(" "),
        output.code,
        output.stderr.trim()
    ))
}

/// Remove a container, ignoring one that is already gone.
pub fn container_remove(name: &str) -> Result<(), String> {
    let output = podman(&["rm", "-f", name])?;
    if output.success()
        || output.stderr.contains("no such container")
        || output.stderr.contains("not found")
    {
        Ok(())
    } else {
        Err(format!(
            "podman rm -f {name:?} failed ({}): {}",
            output.code,
            output.stderr.trim()
        ))
    }
}

/// The address a container has on one of its networks. Empty until the container
/// is running, so the caller polls.
pub fn container_ip(container: &str, network: &str) -> Result<String, String> {
    let format = format!("{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}");
    podman_stdout(&["container", "inspect", "--format", &format, container])
}

/// Whether an image is present locally.
pub fn image_exists(image: &str) -> bool {
    podman_stdout(&["image", "exists", image]).is_ok()
}

/// Create (or replace) a podman secret from a value passed on stdin, so the
/// value never appears in an argv that `ps` could show.
pub fn secret_create(name: &str, value: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::Stdio;

    let binary = binary().ok_or_else(|| "podman is not installed or not on PATH".to_string())?;
    let mut child = Command::new(&binary)
        .args(["secret", "create", "--replace", name, "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run {binary:?}: {error}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "podman secret create has no stdin".to_string())?;
        stdin
            .write_all(value.as_bytes())
            .map_err(|error| format!("cannot write secret {name:?} to podman: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for podman secret create: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "podman secret create {name:?} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Names of the secrets currently in the podman secret store.
pub fn secret_list() -> Result<Vec<String>, String> {
    let raw = podman_stdout(&["secret", "ls", "--format", "{{.Name}}"])?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Whether a secret exists in the podman secret store.
pub fn secret_exists(name: &str) -> bool {
    podman_stdout(&["secret", "inspect", name]).is_ok()
}

/// Remove a secret from the podman secret store, ignoring "not found".
pub fn secret_remove(name: &str) -> Result<(), String> {
    let output = podman(&["secret", "rm", name])?;
    if output.success() || output.stderr.contains("no such secret") {
        Ok(())
    } else {
        Err(format!(
            "podman secret rm {name:?} failed ({}): {}",
            output.code,
            output.stderr.trim()
        ))
    }
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
