//! CLI integration tests: real process, real exit codes, fake podman.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MINIMAL: &str = r#"
version = 1
description = "offline jail"
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[network]
mode = "none"
dns = "none"

[agent]
command = "bash"
args = ["-l"]
"#;

const ALLOWLIST: &str = r#"
version = 1
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[network]
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "api.example.com"
port = 443

[[secrets]]
name = "forge_token"
source = "env"
ref = "EXAMPLE_FORGE_TOKEN"
target = "EXAMPLE_FORGE_TOKEN"

[agent]
command = "bash"
args = ["-lc", "true"]
"#;

/// A fake podman: honest answers for `--version`/`info`, and an internal or
/// bridged network depending on the inspected name. No container is started.
const FAKE_PODMAN: &str = r#"#!/bin/sh
case "$1" in
  --version)
    echo "podman version 9.9.9"
    ;;
  info)
    case "$3" in
      *Rootless*) echo "true" ;;
      *GraphDriverName*) echo "overlay" ;;
      *CgroupManager*) echo "systemd" ;;
      *) echo "unknown" ;;
    esac
    ;;
  network)
    case "$2" in
      inspect)
        case "$3" in
          internal-ok)
            echo '[{"name":"internal-ok","driver":"bridge","internal":true,"ipv6_enabled":false,"subnets":[{"subnet":"10.89.0.0/24","gateway":"10.89.0.1"}]}]'
            ;;
          bridged)
            echo '[{"name":"bridged","driver":"bridge","internal":false,"subnets":[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]}]'
            ;;
          *)
            echo "network $3 not found" >&2
            exit 1
            ;;
        esac
        ;;
      *) echo "unsupported" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "unexpected: $*" >&2
    exit 1
    ;;
esac
"#;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_agentjail")
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_profile(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write profile");
    path
}

fn fake_podman(dir: &Path) -> PathBuf {
    let path = dir.join("podman");
    std::fs::write(&path, FAKE_PODMAN).expect("write fake podman");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    path
}

fn run(args: &[&str], dir: &Path, podman: Option<&Path>) -> Output {
    let mut command = Command::new(binary());
    command.args(args).current_dir(dir);
    match podman {
        Some(path) => {
            command.env("AGENTJAIL_PODMAN", path);
        }
        None => {
            command.env_remove("AGENTJAIL_PODMAN");
            command.env("PATH", "/nonexistent");
        }
    }
    command.output().expect("run agentjail")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn version_is_reported() {
    let dir = tmpdir("version");
    let output = run(&["--version"], &dir, None);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("agentjail 0.1.0"));
}

#[test]
fn no_command_is_a_usage_error() {
    let dir = tmpdir("usage");
    let output = run(&[], &dir, None);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("Usage"));
}

#[test]
fn unknown_subcommand_is_a_usage_error() {
    let dir = tmpdir("unknown");
    let output = run(&["frobnicate"], &dir, None);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn valid_profile_is_accepted() {
    let dir = tmpdir("validate-ok");
    let path = write_profile(&dir, "minimal.toml", MINIMAL);
    let output = run(&["profile", "validate", path.to_str().unwrap()], &dir, None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("OK"));
    assert!(stdout(&output).contains("no egress"));
}

#[test]
fn invalid_profile_exits_one_with_every_error() {
    let dir = tmpdir("validate-bad");
    let text = format!(
        "{MINIMAL}\n[[secrets]]\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\nvalue = \"fake-not-real\"\n"
    );
    let path = write_profile(&dir, "bad.toml", &text);
    let output = run(&["profile", "validate", path.to_str().unwrap()], &dir, None);
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(
        err.contains("inline secret material is not allowed"),
        "{err}"
    );
    assert!(
        err.contains("unknown property") || err.contains("error(s)"),
        "{err}"
    );
}

#[test]
fn missing_profile_lists_search_paths() {
    let dir = tmpdir("missing");
    let output = run(&["profile", "validate", "definitely-missing"], &dir, None);
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("not found"), "{err}");
    assert!(err.contains("definitely-missing.toml"), "{err}");
}

#[test]
fn profile_dir_is_searched_before_defaults() {
    let dir = tmpdir("profile-dir");
    let profiles = dir.join("elsewhere");
    std::fs::create_dir_all(&profiles).expect("mkdir");
    write_profile(&profiles, "named.toml", MINIMAL);
    let output = run(
        &[
            "--profile-dir",
            profiles.to_str().unwrap(),
            "profile",
            "validate",
            "named",
        ],
        &dir,
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("named.toml"));
}

#[test]
fn show_resolves_defaults_and_prints_json() {
    let dir = tmpdir("show");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let output = run(&["profile", "show", path.to_str().unwrap()], &dir, None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(document["name"], "allowlist");
    assert_eq!(
        document["profile"]["network"]["egress"][0]["protocol"],
        "tls"
    );
    assert_eq!(document["profile"]["secrets"][0]["delivery"], "env");
    assert_eq!(
        document["profile"]["secrets"][0]["ref"],
        "EXAMPLE_FORGE_TOKEN"
    );
    assert_eq!(document["profile"]["resources"]["nofile"], 1024);
}

#[test]
fn run_is_stubbed_with_exit_code_3() {
    let dir = tmpdir("run-stub");
    let path = write_profile(&dir, "minimal.toml", MINIMAL);
    let podman = fake_podman(&dir);
    let output = run(
        &["run", path.to_str().unwrap(), "--", "my-agent", "--version"],
        &dir,
        Some(&podman),
    );
    assert_eq!(output.status.code(), Some(3));
    let err = stderr(&output);
    assert!(err.contains("not implemented"), "{err}");
    assert!(err.contains("would exec my-agent --version"), "{err}");
    assert!(err.contains("docs/cli.md"), "{err}");
}

#[test]
fn run_with_a_bridged_network_refuses_with_a_clear_message() {
    let dir = tmpdir("run-bridged");
    let text = MINIMAL.replace(
        "[network]\nmode = \"none\"\ndns = \"none\"",
        "[network]\nname = \"bridged\"\nmode = \"none\"\ndns = \"none\"",
    );
    let path = write_profile(&dir, "bridged.toml", &text);
    let podman = fake_podman(&dir);
    let output = run(&["run", path.to_str().unwrap()], &dir, Some(&podman));
    assert_eq!(
        output.status.code(),
        Some(1),
        "a bridged network must be refused, not started: {}",
        stderr(&output)
    );
    let err = stderr(&output);
    assert!(err.contains("refusing to launch"), "{err}");
    assert!(err.contains("not internal"), "{err}");
}

#[test]
fn run_with_an_internal_network_passes_preflight_then_stops() {
    let dir = tmpdir("run-internal");
    let text = MINIMAL.replace(
        "[network]\nmode = \"none\"\ndns = \"none\"",
        "[network]\nname = \"internal-ok\"\nmode = \"none\"\ndns = \"none\"",
    );
    let path = write_profile(&dir, "internal.toml", &text);
    let podman = fake_podman(&dir);
    let output = run(&["run", path.to_str().unwrap()], &dir, Some(&podman));
    assert_eq!(output.status.code(), Some(3));
    let err = stderr(&output);
    assert!(err.contains("single-route invariant OK"), "{err}");
    assert!(err.contains("not implemented"), "{err}");
}

#[test]
fn run_no_secrets_is_expressible_on_both_sides_of_the_profile() {
    let dir = tmpdir("run-no-secrets");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let podman = fake_podman(&dir);
    for args in [
        vec!["run", "--no-secrets", path.to_str().unwrap()],
        vec!["run", path.to_str().unwrap(), "--no-secrets"],
    ] {
        let output = run(&args, &dir, Some(&podman));
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert!(
            stderr(&output).contains("all secrets suppressed (--no-secrets)"),
            "{}",
            stderr(&output)
        );
    }
}

#[test]
fn selftest_is_stubbed_and_names_the_network_negatives() {
    let dir = tmpdir("selftest");
    let path = write_profile(&dir, "minimal.toml", MINIMAL);
    let output = run(&["selftest", path.to_str().unwrap()], &dir, None);
    assert_eq!(output.status.code(), Some(3));
    let err = stderr(&output);
    assert!(err.contains("raw IP:port"), "{err}");
    assert!(err.contains("second route"), "{err}");
    assert!(err.contains("Positive control"), "{err}");
}

#[test]
fn doctor_json_reports_podman_and_network_check() {
    let dir = tmpdir("doctor-json");
    let podman = fake_podman(&dir);
    let output = run(
        &["doctor", "--json", "--network", "internal-ok"],
        &dir,
        Some(&podman),
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(document["ok"], true);
    assert_eq!(document["sections"]["podman"]["rootless"], "true");
    assert_eq!(
        document["sections"]["podman"]["version"],
        "podman version 9.9.9"
    );
    assert!(document["sections"]["network"]["invariant"]
        .as_str()
        .unwrap()
        .contains("internal network"));
}

#[test]
fn doctor_fails_when_podman_is_missing() {
    let dir = tmpdir("doctor-missing");
    let output = run(&["doctor", "--json"], &dir, None);
    assert_eq!(output.status.code(), Some(1));
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(document["ok"], false);
    assert!(document["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning
            .as_str()
            .unwrap()
            .contains("podman is not installed")));
}

#[test]
fn doctor_network_check_fails_closed_on_a_bridged_network() {
    let dir = tmpdir("doctor-bridged");
    let podman = fake_podman(&dir);
    let output = run(
        &["doctor", "--json", "--network", "bridged"],
        &dir,
        Some(&podman),
    );
    assert_eq!(output.status.code(), Some(1));
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(document["ok"], false);
    assert!(document["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning.as_str().unwrap().contains("not internal")));
}

#[test]
fn run_help_documents_the_launcher_contract() {
    let dir = tmpdir("run-help");
    let output = run(&["run", "--help"], &dir, None);
    assert_eq!(output.status.code(), Some(0));
    let help = stdout(&output);
    assert!(help.contains("pair of pipes"), "{help}");
    assert!(help.contains("SIGINT, SIGTERM and SIGQUIT"), "{help}");
    assert!(help.contains("128 + signal number"), "{help}");
    assert!(help.contains("no jail is orphaned"), "{help}");
}

#[test]
fn selftest_help_documents_the_negative_set() {
    let dir = tmpdir("selftest-help");
    let output = run(&["selftest", "--help"], &dir, None);
    assert_eq!(output.status.code(), Some(0));
    let help = stdout(&output);
    assert!(help.contains("raw IP:port"), "{help}");
    assert!(help.contains("podman/docker socket"), "{help}");
    assert!(help.contains("two concurrent jails"), "{help}");
    assert!(help.contains("writable-layer size"), "{help}");
}
