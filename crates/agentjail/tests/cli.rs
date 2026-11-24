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
name = "internal-ok"
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
class = "model"
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "api.anthropic.com"
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
log="${AGENTJAIL_TEST_LOG:-/dev/null}"
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
      ls)
        echo "podman"
        cat "${AGENTJAIL_TEST_NETWORKS:-/dev/null}"
        ;;
      create)
        echo "network-create $5" >> "$log"
        ;;
      inspect)
        case "$3" in
          bridged)
            echo '[{"name":"bridged","driver":"bridge","internal":false,"subnets":[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]}]'
            ;;
          *)
            echo '[{"name":"'"$3"'","driver":"bridge","internal":true,"ipv6_enabled":false,"subnets":[{"subnet":"10.89.0.0/24","gateway":"10.89.0.1"}]}]'
            ;;
        esac
        ;;
      rm)
        echo "network-rm $4" >> "$log"
        ;;
      *)
        echo "unsupported network $2" >&2
        exit 1
        ;;
    esac
    ;;
  image)
    case "$2" in
      inspect)
        # `--format {{.Id}} <reference>`: the ID this reference means right now.
        if [ -n "${AGENTJAIL_TEST_IMAGE_MISSING:-}" ]; then
          echo "Error: localhost/agentjail-gateway:1: image not known" >&2
          exit 125
        fi
        echo "${AGENTJAIL_TEST_IMAGE_ID:-sha256:5f78f0dfcc526190811f735720e01b3acfa401a40eb3406801a3e5a8b25d9783}"
        ;;
      exists) exit 0 ;;
      *) exit 1 ;;
    esac
    ;;
  container)
    case "$2" in
      inspect) echo "${AGENTJAIL_TEST_GATEWAY_IP:-10.89.0.2}" ;;
      *) exit 1 ;;
    esac
    ;;
  ps)
    cat "${AGENTJAIL_TEST_CONTAINERS:-/dev/null}"
    ;;
  rm)
    echo "container-rm $3" >> "$log"
    ;;
  secret)
    case "$2" in
      ls) : ;;
      create)
        echo "secret-create $4" >> "$log"
        mkdir -p "${AGENTJAIL_TEST_SECRETS:-secrets}"
        cat > "${AGENTJAIL_TEST_SECRETS:-secrets}/$4"
        ;;
      inspect) exit 0 ;;
      rm) echo "secret-rm $3" >> "$log" ;;
      *) exit 1 ;;
    esac
    ;;
  run)
    case " $* " in
      *" --detach "*)
        printf '%s\n' "$@" > "${AGENTJAIL_TEST_GATEWAY_ARGV:-gateway-argv.txt}"
        echo "gateway-started" >> "$log"
        ;;
      *)
        printf '%s\n' "$@" > "${AGENTJAIL_TEST_ARGV:-argv.txt}"
        echo "jail-started" >> "$log"
        exit "${AGENTJAIL_TEST_EXIT:-0}"
        ;;
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
    run_with_env(args, dir, podman, &[])
}

fn run_with_env(
    args: &[&str],
    dir: &Path,
    podman: Option<&Path>,
    extra_env: &[(&str, &str)],
) -> Output {
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
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command.output().expect("run agentjail")
}

fn recorded_argv(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
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
fn run_execs_podman_and_propagates_its_exit_code() {
    let dir = tmpdir("run-exit");
    let path = write_profile(&dir, "minimal.toml", MINIMAL);
    let podman = fake_podman(&dir);
    let argv_path = dir.join("argv.txt");
    let output = run_with_env(
        &["run", path.to_str().unwrap(), "--", "my-agent", "--version"],
        &dir,
        Some(&podman),
        &[("AGENTJAIL_TEST_EXIT", "42")],
    );
    assert_eq!(output.status.code(), Some(42), "{}", stderr(&output));
    assert!(stderr(&output).contains("preflight OK"));
    let argv = recorded_argv(&argv_path);
    assert!(!argv.is_empty(), "podman run was never invoked");
    assert!(argv.iter().any(|arg| arg == "my-agent"));
    assert!(argv.iter().any(|arg| arg == "--version"));
}

#[test]
fn run_passes_every_hardening_flag_and_no_host_environment() {
    let dir = tmpdir("run-flags");
    let path = write_profile(&dir, "minimal.toml", MINIMAL);
    let podman = fake_podman(&dir);
    let argv_path = dir.join("argv.txt");
    let output = run(&["run", path.to_str().unwrap()], &dir, Some(&podman));
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let argv = recorded_argv(&argv_path);
    let joined = argv.join(" ");
    for expected in [
        "--rm",
        "--interactive",
        "--pull=never",
        "--read-only",
        "--userns=keep-id:uid=10000,gid=10000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit",
        "--memory",
        "--cpus",
        "--ulimit",
        "--network internal-ok",
        "--tmpfs /tmp:rw,noexec,nosuid,nodev",
        "--tmpfs /run:rw,noexec,nosuid,nodev",
        "--env HOME=/home/agent",
        "--workdir /work",
    ] {
        assert!(
            joined.contains(expected),
            "missing {expected:?} in {joined}"
        );
    }
    assert!(
        !joined.contains("--env-host"),
        "host env must not leak: {joined}"
    );
    assert!(!joined.contains("--privileged"));
    assert!(!argv.iter().any(|arg| arg == "-t" || arg == "--tty"));
}

#[test]
fn run_no_secrets_injects_nothing() {
    let dir = tmpdir("run-no-secrets");
    let text = format!(
        "{MINIMAL}\n[[secrets]]\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n",
        MINIMAL = MINIMAL.trim_end()
    );
    let path = write_profile(&dir, "no-secrets.toml", &text);
    let podman = fake_podman(&dir);
    let argv_path = dir.join("argv.txt");
    let output = run_with_env(
        &["run", "--no-secrets", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[("EXAMPLE_TOKEN", "fake-token-value")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let joined = recorded_argv(&argv_path).join(" ");
    assert!(!joined.contains("--secret"));
    assert!(!joined.contains("fake-token-value"));
    assert!(stderr(&output).contains("--no-secrets"));
}

#[test]
fn run_injects_a_secret_through_the_store_not_the_argv() {
    let dir = tmpdir("run-secret");
    let text = format!(
        "{MINIMAL}\n[[secrets]]\nname = \"example\"\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n",
        MINIMAL = MINIMAL.trim_end()
    );
    let path = write_profile(&dir, "with-secret.toml", &text);
    let podman = fake_podman(&dir);
    let argv_path = dir.join("argv.txt");
    let secrets_dir = dir.join("secrets");
    std::fs::create_dir_all(&secrets_dir).expect("secrets dir");
    let log_path = dir.join("calls.log");
    let output = run_with_env(
        &["run", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[
            ("EXAMPLE_TOKEN", "fake-token-value"),
            ("AGENTJAIL_TEST_ARGV", argv_path.to_str().unwrap()),
            ("AGENTJAIL_TEST_SECRETS", secrets_dir.to_str().unwrap()),
            ("AGENTJAIL_TEST_LOG", log_path.to_str().unwrap()),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let argv = recorded_argv(&argv_path);
    let joined = argv.join(" ");
    let secret_arg = argv
        .iter()
        .find(|arg| arg.starts_with("source=agentjail-with-secret-"))
        .unwrap_or_else(|| panic!("no per-run secret in {joined}"));
    assert!(
        secret_arg.ends_with(",type=env,target=EXAMPLE_TOKEN"),
        "{secret_arg}"
    );
    let run_id = secret_arg
        .strip_prefix("source=agentjail-with-secret-")
        .and_then(|rest| rest.split('-').next())
        .expect("run id in secret name");
    assert!(
        run_id.parse::<u32>().is_ok(),
        "run id {run_id:?} is not the pid"
    );
    assert!(
        !joined.contains("fake-token-value"),
        "value leaked into argv: {joined}"
    );
    let store_name = format!("agentjail-with-secret-{run_id}-EXAMPLE_TOKEN");
    let stored = std::fs::read_to_string(secrets_dir.join(&store_name))
        .expect("secret written to the store");
    assert_eq!(stored, "fake-token-value");
    // This run created the entry, so it removes it on exit.
    let calls = std::fs::read_to_string(log_path).expect("calls log");
    assert!(
        calls
            .lines()
            .any(|line| line == format!("secret-rm {store_name}")),
        "store entry was not removed on exit: {calls}"
    );
}

#[test]
fn run_fails_closed_when_a_secret_reference_is_missing() {
    let dir = tmpdir("run-missing-secret");
    let text = format!(
        "{MINIMAL}\n[[secrets]]\nsource = \"env\"\nref = \"MISSING_AGENTJAIL_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n",
        MINIMAL = MINIMAL.trim_end()
    );
    let path = write_profile(&dir, "missing.toml", &text);
    let podman = fake_podman(&dir);
    let argv_path = dir.join("argv.txt");
    let output = run(&["run", path.to_str().unwrap()], &dir, Some(&podman));
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("MISSING_AGENTJAIL_TOKEN"), "{err}");
    assert!(!err.contains("fake"), "{err}");
    assert!(
        recorded_argv(&argv_path).is_empty(),
        "podman run must not start"
    );
}

#[test]
fn profile_validate_accepts_an_allowlist_profile_and_names_its_class() {
    let dir = tmpdir("validate-allowlist");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let output = run(&["profile", "validate", path.to_str().unwrap()], &dir, None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("egress class \"model\""), "{out}");
    assert!(out.contains("deny by default"), "{out}");
}

#[test]
fn a_destination_outside_the_profile_class_is_a_validation_error() {
    let dir = tmpdir("validate-outside");
    let text = ALLOWLIST.replace("api.anthropic.com", "api.example.com");
    let path = write_profile(&dir, "outside.toml", &text);
    let output = run(&["profile", "validate", path.to_str().unwrap()], &dir, None);
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("api.example.com:443"), "{err}");
    assert!(err.contains("egress class \"model\""), "{err}");
}

#[test]
fn an_allowlist_profile_without_a_class_is_refused() {
    let dir = tmpdir("validate-no-class");
    let text = ALLOWLIST.replace("class = \"model\"\n", "");
    let path = write_profile(&dir, "no-class.toml", &text);
    let output = run(&["profile", "validate", path.to_str().unwrap()], &dir, None);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("network.class"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn selftest_baseline_proves_every_negative_holds_without_a_jail() {
    let dir = tmpdir("selftest-baseline");
    let output = run(&["selftest", "--baseline", "--json"], &dir, None);
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    let cases = document["cases"].as_array().expect("cases");
    let verdict = |name: &str| {
        cases
            .iter()
            .find(|case| case["case"] == name)
            .unwrap_or_else(|| panic!("missing case {name}"))["verdict"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    let observed = |name: &str| {
        cases
            .iter()
            .find(|case| case["case"] == name)
            .unwrap_or_else(|| panic!("missing case {name}"))["observed"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    for case in [
        "host-secret",
        "outside-allowlist",
        "raw-ip",
        "resource-limits",
    ] {
        assert_eq!(verdict(case), "EXPECTED", "{case}: {}", stdout(&output));
    }
    // The network-control baseline needs an unprivileged user+network namespace.
    // Some hosts (Ubuntu 24.04 with AppArmor) block that; the CI selftest step
    // lifts the runner restriction, but `cargo test` must not require root.
    for case in ["network-control", "net-admin"] {
        let verdict = verdict(case);
        let observed = observed(case);
        assert!(
            verdict == "EXPECTED" || (verdict == "FAIL" && observed.contains("unavailable:")),
            "{case}: {verdict} {observed}"
        );
    }
    // These cannot be meaningful without a jail and must say so, not disappear.
    assert_eq!(verdict("jail-isolation"), "SKIPPED-BASELINE");
    assert_eq!(verdict("positive-control"), "SKIPPED-BASELINE");
    // If the baseline was fully usable, the exit code must be 0. If only the
    // namespace-dependent cases were unavailable, the failure must name exactly
    // those cases, never hide behind a generic error.
    match output.status.code() {
        Some(0) => assert_eq!(document["ok"], true),
        Some(1) => {
            let err = stderr(&output);
            assert!(
                err.contains("network-control") && err.contains("net-admin"),
                "{err}"
            );
        }
        other => panic!("unexpected exit {other:?}: {}", stderr(&output)),
    }
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
    assert!(help.contains("two-jail isolation"), "{help}");
    assert!(help.contains("NET_ADMIN"), "{help}");
    assert!(help.contains("positive control"), "{help}");
    assert!(help.contains("SKIPPED-BASELINE"), "{help}");
}

/// The class side of an allowlist run, driven end to end against a fake podman:
/// what is created, what the jail is told, and what is removed on the way out.
#[test]
fn allowlist_run_creates_the_class_network_and_gateway_and_then_removes_both() {
    let dir = tmpdir("allowlist-run");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let podman = fake_podman(&dir);
    let log = dir.join("podman.log");
    let gateway_argv = dir.join("gateway-argv.txt");
    let argv_path = dir.join("argv.txt");

    let output = run_with_env(
        &["run", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[
            ("AGENTJAIL_TEST_LOG", log.to_str().unwrap()),
            (
                "AGENTJAIL_TEST_GATEWAY_ARGV",
                gateway_argv.to_str().unwrap(),
            ),
            ("AGENTJAIL_TEST_ARGV", argv_path.to_str().unwrap()),
            (
                "AGENTJAIL_GATEWAY_IMAGE",
                "localhost/agentjail-gateway:test",
            ),
            ("EXAMPLE_FORGE_TOKEN", "fake-token-value"),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let events: Vec<String> = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    let network = events
        .iter()
        .find_map(|event| event.strip_prefix("network-create "))
        .expect("a class network was created")
        .to_string();
    assert!(
        network.starts_with("agentjail-allowlist-") && network.ends_with("-model"),
        "class network is named after the profile, the pid and the class: {network}"
    );
    assert_eq!(
        events.last().map(String::as_str),
        Some(format!("network-rm {network}").as_str()),
        "the network is removed last: {events:?}"
    );
    assert!(
        events.contains(&format!(
            "container-rm {}",
            network.replace("-model", "-gateway")
        )),
        "the gateway is removed before the network: {events:?}"
    );

    // The gateway: on the class network and its own outbound leg, one capability,
    // the committed class config, and the run id as the jail id.
    let gateway = recorded_argv(&gateway_argv).join(" ");
    for expected in [
        "--detach",
        "--cap-drop=ALL",
        "--cap-add=NET_BIND_SERVICE",
        "--read-only",
        "--pull=never",
        "--config /etc/agentjail/class.toml",
        "--jail-id allowlist-",
    ] {
        assert!(
            gateway.contains(expected),
            "missing {expected:?} in {gateway}"
        );
    }
    assert!(
        gateway.contains(&format!("--network {network} --network podman")),
        "the gateway must be dual-homed: {gateway}"
    );
    assert!(
        gateway.contains("gateway/classes/model.toml"),
        "the committed class config is what is mounted: {gateway}"
    );
    // The image is the resolved ID, not the tag: a tag is a name.
    assert!(
        gateway.contains("sha256:5f78f0dfcc526190811f735720e01b3acfa401a40eb3406801a3e5a8b25d9783"),
        "the gateway must run by pinned image ID: {gateway}"
    );
    assert!(
        !gateway.contains("localhost/agentjail-gateway:test"),
        "the gateway must not be started by tag: {gateway}"
    );

    // The jail: joined to the class network, with the gateway as resolver and
    // proxy, and no host search domain.
    let jail = recorded_argv(&argv_path).join(" ");
    for expected in [
        format!("--network {network}"),
        "--dns 10.89.0.2".to_string(),
        "--dns-search .".to_string(),
        "--env HTTPS_PROXY=http://10.89.0.2:3128".to_string(),
        "--env ALL_PROXY=http://10.89.0.2:3128".to_string(),
    ] {
        assert!(jail.contains(&expected), "missing {expected:?} in {jail}");
    }
    assert!(
        !jail.contains("--network podman"),
        "the jail must not have the gateway's outbound leg: {jail}"
    );
}

#[test]
fn a_failed_run_removes_the_class_network_and_gateway_too() {
    let dir = tmpdir("allowlist-fail");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let podman = fake_podman(&dir);
    let log = dir.join("podman.log");
    let output = run_with_env(
        &["run", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[
            ("AGENTJAIL_TEST_LOG", log.to_str().unwrap()),
            ("AGENTJAIL_TEST_EXIT", "7"),
            ("EXAMPLE_FORGE_TOKEN", "fake-token-value"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(7),
        "the agent's code is passed through"
    );
    let events = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(events.contains("network-create"), "{events}");
    assert!(events.contains("container-rm"), "{events}");
    assert!(events.contains("network-rm"), "{events}");
}

#[test]
fn a_missing_gateway_image_fails_before_anything_is_created() {
    let dir = tmpdir("allowlist-no-image");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let podman = fake_podman(&dir);
    let log = dir.join("podman.log");
    let output = run_with_env(
        &["run", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[
            ("AGENTJAIL_TEST_LOG", log.to_str().unwrap()),
            ("AGENTJAIL_TEST_IMAGE_MISSING", "1"),
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("build-gateway-image.sh"),
        "{}",
        stderr(&output)
    );
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("network-create"),
        "nothing is created for a run that cannot start"
    );
}

/// A tag that resolves to something which is not an image ID is a name with no
/// thing behind it: refused before any network or container exists.
#[test]
fn a_gateway_image_that_does_not_resolve_to_an_id_is_refused() {
    for bad in [
        "localhost/agentjail-gateway:test",
        "sha256:abc",
        "00000000000000000000000000000000000000000000000000000000000000001",
    ] {
        let dir = tmpdir("allowlist-bad-image");
        let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
        let podman = fake_podman(&dir);
        let log = dir.join("podman.log");
        let output = run_with_env(
            &["run", path.to_str().unwrap()],
            &dir,
            Some(&podman),
            &[
                ("AGENTJAIL_TEST_LOG", log.to_str().unwrap()),
                ("AGENTJAIL_TEST_IMAGE_ID", bad),
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{bad}: {}", stderr(&output));
        let err = stderr(&output);
        assert!(
            err.contains("not an image ID") || err.contains("is absent"),
            "{bad}: {err}"
        );
        assert!(
            !std::fs::read_to_string(&log)
                .unwrap_or_default()
                .contains("network-create"),
            "{bad}: a refuseable run created a network"
        );
    }
}
