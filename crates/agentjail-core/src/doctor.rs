//! `agentjail doctor`: the host facts the launcher depends on.
//!
//! Read-only by construction: it runs `podman` inspection commands and reads a
//! handful of `/proc` and `/sys` files. It never starts a container, never
//! writes configuration, and never runs with elevated privileges.
//!
//! The network invariant check lives in [`crate::podman::verify_network`] and is
//! the same function `run` uses. Two callers, one implementation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::paths;
use crate::podman;

#[derive(Debug, Clone, Default)]
pub struct DoctorReport {
    sections: BTreeMap<String, Vec<(String, String)>>,
    warnings: Vec<String>,
    ok: bool,
}

impl DoctorReport {
    pub fn new() -> Self {
        Self {
            ok: true,
            ..Self::default()
        }
    }

    pub fn add(&mut self, section: &str, key: &str, value: impl Into<String>) {
        self.sections
            .entry(section.to_string())
            .or_default()
            .push((key.to_string(), value.into()));
    }

    pub fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    pub fn fail(&mut self) {
        self.ok = false;
    }

    pub fn ok(&self) -> bool {
        self.ok
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn sections(&self) -> &BTreeMap<String, Vec<(String, String)>> {
        &self.sections
    }

    pub fn render_human(&self) -> String {
        let mut lines = String::new();
        for (section, entries) in &self.sections {
            lines.push_str(&format!("[{section}]\n"));
            let width = entries.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
            for (key, value) in entries {
                lines.push_str(&format!("  {key:<width$}  {value}\n"));
            }
            lines.push('\n');
        }
        if !self.warnings.is_empty() {
            lines.push_str("warnings:\n");
            for warning in &self.warnings {
                lines.push_str(&format!("  ! {warning}\n"));
            }
            lines.push('\n');
        }
        lines.push_str(if self.ok {
            "result: ok\n"
        } else {
            "result: problems found\n"
        });
        lines
    }

    pub fn render_json(&self) -> String {
        let mut sections = serde_json::Map::new();
        for (section, entries) in &self.sections {
            let mut object = serde_json::Map::new();
            for (key, value) in entries {
                object.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
            sections.insert(section.clone(), serde_json::Value::Object(object));
        }
        let document = serde_json::json!({
            "ok": self.ok,
            "sections": sections,
            "warnings": self.warnings,
        });
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Gather the report. Never panics for missing tooling, and reports problems
/// instead of silently passing them.
pub fn collect(env: &BTreeMap<String, String>, network: Option<&str>) -> DoctorReport {
    let mut report = DoctorReport::new();

    report.add("agentjail", "version", env!("CARGO_PKG_VERSION"));
    report.add(
        "agentjail",
        "profile_format",
        crate::SUPPORTED_PROFILE_VERSION.to_string(),
    );
    report.add(
        "agentjail",
        "platform",
        format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
    );

    let podman_path = podman::discover(
        env.get("AGENTJAIL_PODMAN").map(String::as_str),
        env.get("PATH").map(std::ffi::OsStr::new),
    );

    match podman_path {
        None => {
            report.add("podman", "binary", "not found");
            report.warn("podman is not installed or not on PATH; nothing can be launched");
            report.fail();
        }
        Some(binary) => {
            report.add("podman", "binary", binary.display().to_string());
            match podman::run(&binary, &["--version"], None) {
                Ok(output) if output.success() => {
                    report.add("podman", "version", output.stdout_trimmed().to_string());
                }
                Ok(output) => {
                    report.add("podman", "version", format!("error (exit {})", output.code));
                    report.warn("podman does not answer --version; the jail cannot be launched");
                    report.fail();
                }
                Err(error) => {
                    report.add("podman", "version", format!("error: {error}"));
                    report.warn("podman could not be executed");
                    report.fail();
                }
            }
            for (key, expression) in [
                ("rootless", "{{.Host.Security.Rootless}}"),
                ("storage_driver", "{{.Store.GraphDriverName}}"),
                ("cgroup_manager", "{{.Host.CgroupManager}}"),
            ] {
                let value =
                    podman_format(&binary, expression).unwrap_or_else(|| "unknown".to_string());
                if key == "rootless" && value == "false" {
                    report.warn(
                        "podman reports rootful mode; agentjail expects rootless podman and refuses to launch under root",
                    );
                    report.fail();
                }
                if key == "storage_driver" && value == "vfs" {
                    report.warn(
                        "vfs storage driver wastes disk and cannot enforce per-container size limits",
                    );
                }
                report.add("podman", key, value);
            }
            report.add(
                "podman",
                "cgroup_version",
                if Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
                    "v2"
                } else {
                    "v1"
                },
            );
        }
    }

    report.add("selinux", "state", selinux_state());
    report.add(
        "process",
        "euid",
        match current_euid() {
            Some(0) => "0 (root)".to_string(),
            Some(uid) => format!("{uid} (unprivileged user)"),
            None => "unknown".to_string(),
        },
    );
    if let Some(runtime) = container_hint() {
        report.add("process", "running_inside", runtime);
    }

    for (label, directory) in [
        ("config_dir", paths::config_dir(env)),
        ("data_dir", paths::data_dir(env)),
        ("state_dir", paths::state_dir(env)),
    ] {
        report.add("paths", label, describe_path(&directory));
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let search_dirs = paths::profile_search_dirs(env, &cwd);
    report.add(
        "paths",
        "profile_search",
        search_dirs
            .iter()
            .map(|directory| directory.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    if !search_dirs.iter().any(|directory| directory.is_dir()) {
        report.warn(
            "no profile search directory exists yet; profiles/<name>.toml must exist before a profile can be found by name",
        );
    }

    if let Some(name) = network {
        match podman::verify_network(name) {
            Ok(posture) => report.add("network", "invariant", posture.describe()),
            Err(error) => {
                report.add("network", "invariant", "FAILED");
                report.warn(format!("single-route invariant: {error}"));
                report.fail();
            }
        }
    } else {
        report.add(
            "network",
            "invariant",
            "not checked (pass --network NAME to verify an existing network)",
        );
    }

    report
}

fn podman_format(binary: &Path, expression: &str) -> Option<String> {
    let output = podman::run(binary, &["info", "--format", expression], None).ok()?;
    if !output.success() || output.stdout_trimmed().is_empty() {
        return None;
    }
    Some(output.stdout_trimmed().to_string())
}

fn describe_path(path: &Path) -> String {
    format!(
        "{} ({})",
        path.display(),
        if path.is_dir() { "present" } else { "missing" }
    )
}

fn selinux_state() -> &'static str {
    match std::fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(value) if value.trim() == "1" => "enforcing",
        Ok(_) => "permissive",
        Err(_) => "absent",
    }
}

fn current_euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

fn container_hint() -> Option<&'static str> {
    if Path::new("/run/.containerenv").exists() {
        return Some("podman");
    }
    if Path::new("/.dockerenv").exists() {
        return Some("docker");
    }
    std::env::var_os("container").map(|_| "unknown runtime")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn missing_podman_is_a_failure_not_a_pass() {
        let env = env(&[("HOME", "/home/example"), ("PATH", "/nonexistent")]);
        let report = collect(&env, None);
        assert!(!report.ok());
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("podman is not installed")));
        assert_eq!(
            report.sections()["podman"]
                .iter()
                .find(|(key, _)| key == "binary")
                .map(|(_, value)| value.as_str()),
            Some("not found")
        );
    }

    #[test]
    fn human_and_json_rendering_agree_on_ok() {
        let mut report = DoctorReport::new();
        report.add("podman", "rootless", "true");
        report.warn("a warning");
        let human = report.render_human();
        assert!(human.contains("[podman]"));
        assert!(human.contains("! a warning"));
        assert!(human.trim_end().ends_with("result: ok"));

        let json: serde_json::Value = serde_json::from_str(&report.render_json()).expect("json");
        assert_eq!(json["ok"], true);
        assert_eq!(json["sections"]["podman"]["rootless"], "true");
        assert_eq!(json["warnings"][0], "a warning");
    }

    #[test]
    fn failing_report_renders_problems() {
        let mut report = DoctorReport::new();
        report.fail();
        assert!(report.render_human().trim_end().ends_with("problems found"));
    }

    #[test]
    fn paths_section_is_reported_even_when_missing() {
        let env = env(&[("HOME", "/home/example"), ("PATH", "/nonexistent")]);
        let report = collect(&env, None);
        let paths = &report.sections()["paths"];
        assert!(paths.iter().any(|(key, _)| key == "config_dir"));
        assert!(paths.iter().any(|(_, value)| value.contains("missing")));
    }

    #[test]
    fn network_invariant_is_reported_when_requested() {
        let env = env(&[("HOME", "/home/example"), ("PATH", "/nonexistent")]);
        let report = collect(&env, Some("agentjail-test"));
        assert!(report.sections()["network"]
            .iter()
            .any(|(key, value)| key == "invariant" && value == "FAILED"));
        assert!(!report.ok());
    }
}
