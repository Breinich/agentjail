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
        # The name is the last argument whatever the flag set is.
        last=""
        for arg in "$@"; do last=$arg; done
        echo "network-create $last" >> "$log"
        echo "network-create-argv $*" >> "$log"
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
      inspect)
        case "$*" in
          *State.Status*)
            # AGENTJAIL_TEST_GATEWAY_EXITED=<code> is a gateway that refused to
            # start: the state says so, and the address never appears.
            if [ -n "${AGENTJAIL_TEST_GATEWAY_EXITED:-}" ]; then
              echo "exited ${AGENTJAIL_TEST_GATEWAY_EXITED}"
            else
              echo "running 0"
            fi
            ;;
          *IPAddress*)
            if [ -n "${AGENTJAIL_TEST_GATEWAY_EXITED:-}" ] || [ -n "${AGENTJAIL_TEST_GATEWAY_NO_ADDRESS:-}" ]; then
              echo ""
            else
              echo "${AGENTJAIL_TEST_GATEWAY_IP:-10.89.0.2}"
            fi
            ;;
          *) exit 1 ;;
        esac
        ;;
      logs)
        cat "${AGENTJAIL_TEST_GATEWAY_LOGS:-/dev/null}"
        ;;
      *) exit 1 ;;
    esac
    ;;
  ps)
    cat "${AGENTJAIL_TEST_CONTAINERS:-/dev/null}"
    ;;
  logs)
    # `podman logs` puts the container's stdout on its stdout and its stderr on
    # its stderr; a gateway refusal is on stderr, which is the case that matters.
    cat "${AGENTJAIL_TEST_GATEWAY_LOGS:-/dev/null}" >&2
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
    // What the jail actually gets, not only what the file says: the intersection
    // of the class allowlist and this profile's egress list.
    assert_eq!(document["egress"]["class"], "model");
    assert_eq!(document["egress"]["grant"][0], "api.anthropic.com:443");
    assert_eq!(
        document["egress"]["grant"]
            .as_array()
            .map(|grant| grant.len()),
        Some(1)
    );
}

#[test]
fn show_prints_an_empty_grant_as_empty_not_as_absent() {
    let dir = tmpdir("show-empty-grant");
    let text = ALLOWLIST
        .replace(
            "[[network.egress]]\nhost = \"api.anthropic.com\"\nport = 443\n",
            "",
        )
        .replace(
            "[[secrets]]\nname = \"forge_token\"\nsource = \"env\"\nref = \"EXAMPLE_FORGE_TOKEN\"\ntarget = \"EXAMPLE_FORGE_TOKEN\"\n",
            "",
        );
    let path = write_profile(&dir, "nothing.toml", &text);
    let output = run(&["profile", "show", path.to_str().unwrap()], &dir, None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(document["egress"]["class"], "model");
    assert_eq!(document["egress"]["grant"], serde_json::json!([]));
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
    let created: Vec<String> = events
        .iter()
        .filter_map(|event| event.strip_prefix("network-create "))
        .map(str::to_string)
        .collect();
    let network = created
        .iter()
        .find(|name| name.ends_with("-model"))
        .expect("a class network was created")
        .to_string();
    let egress = created
        .iter()
        .find(|name| name.ends_with("-egress"))
        .expect("the gateway's egress leg is its own network")
        .to_string();
    assert!(
        network.starts_with("agentjail-allowlist-"),
        "class network is named after the profile, the pid and the class: {network}"
    );
    assert!(
        egress.starts_with("agentjail-allowlist-"),
        "the egress network belongs to this run too: {egress}"
    );
    // IPv6 is off explicitly, on both networks, rather than left to a default.
    for name in [&network, &egress] {
        let argv = events
            .iter()
            .find(|event| {
                event.starts_with("network-create-argv ") && event.contains(name.as_str())
            })
            .expect("create argv");
        assert!(argv.contains("--ipv6=false"), "{argv}");
    }
    let class_argv = events
        .iter()
        .find(|event| event.starts_with("network-create-argv ") && event.ends_with(&network))
        .expect("class create argv");
    assert!(
        class_argv.contains("--internal --disable-dns"),
        "the class network has no route out and no runtime resolver: {class_argv}"
    );

    // Removal order: the gateway first, then its egress leg, then the class
    // network it shared with the jail.
    assert_eq!(
        events.last().map(String::as_str),
        Some(format!("network-rm {network}").as_str()),
        "the class network is removed last: {events:?}"
    );
    assert!(
        events.contains(&format!("network-rm {egress}")),
        "the egress network is removed: {events:?}"
    );
    assert!(
        events.contains(&format!(
            "container-rm {}",
            network.replace("-model", "-gateway")
        )),
        "the gateway is removed before the networks: {events:?}"
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
        gateway.contains(&format!("--network {network} --network {egress}")),
        "the gateway must be dual-homed, on its own egress leg: {gateway}"
    );
    assert!(
        gateway.contains("gateway/classes/model.toml"),
        "the committed class config is what is mounted: {gateway}"
    );
    // The class config is the ceiling, not the grant: the gateway is handed the
    // intersection of it and this profile's egress list.
    assert!(
        gateway.contains("--grant api.anthropic.com:443"),
        "the gateway must be started with the profile's grant: {gateway}"
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
fn an_allowlist_profile_that_asks_for_nothing_starts_and_says_the_grant_is_empty() {
    let dir = tmpdir("allowlist-empty-grant");
    let text = ALLOWLIST.replace(
        "[[network.egress]]\nhost = \"api.anthropic.com\"\nport = 443\n",
        "",
    );
    let path = write_profile(&dir, "nothing.toml", &text);
    let podman = fake_podman(&dir);
    let gateway_argv = dir.join("gateway-argv.txt");
    let argv_path = dir.join("argv.txt");
    let output = run_with_env(
        &["run", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[
            (
                "AGENTJAIL_TEST_GATEWAY_ARGV",
                gateway_argv.to_str().unwrap(),
            ),
            ("AGENTJAIL_TEST_ARGV", argv_path.to_str().unwrap()),
            ("EXAMPLE_FORGE_TOKEN", "fake-token-value"),
        ],
    );
    // Starting is the point: a profile that asks for nothing is legitimate, and
    // refusing it would push people back to `mode = "none"` for the same
    // guarantee. It is loud, not silent.
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("egress grant is empty: this jail has no route out"),
        "{}",
        stderr(&output)
    );
    // The jail still starts and is still given the gateway as its resolver and
    // proxy, so everything else in the profile is untouched.
    let jail = recorded_argv(&argv_path).join(" ");
    assert!(jail.contains("--dns 10.89.0.2"), "{jail}");
    assert!(
        jail.contains("--env HTTPS_PROXY=http://10.89.0.2:3128"),
        "{jail}"
    );
    // And the gateway is told the grant is empty rather than left with the
    // class allowlist.
    let gateway = recorded_argv(&gateway_argv);
    let index = gateway
        .iter()
        .position(|arg| arg == "--grant")
        .expect("the gateway is always told its grant");
    assert_eq!(gateway.get(index + 1).map(String::as_str), Some(""));
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

const AUDIT_LINES: &str = "\
ts=1795477011164 class=model jail=proof-1 peer=10.89.6.2:37888 dest=api.example.com:443 decision=allow reason=- bytes=0/0 resolved=93.184.216.34 pinned=93.184.216.34
ts=1795477011167 class=model jail=proof-1 peer=10.89.6.2:37898 dest=github.com:443 decision=deny reason=not-in-class bytes=0/0
ts=1795477011170 class=model jail=proof-1 peer=10.89.6.2:37900 dest=api.example.com:443 decision=deny reason=byte-budget bytes=0/4096 budget=8192
ts=1795477011175 class=model jail=proof-2 peer=10.89.6.9:41000 dest=github.com:443 decision=allow reason=- bytes=0/0 resolved=140.82.121.4 pinned=140.82.121.4
";

const DNS_LINES: &str = "\
ts=1795477011165 class=model jail=proof-1 peer=10.89.6.2:48512 qname=api.example.com qtype=1 decision=answer reason=in-class
ts=1795477011166 class=model jail=proof-1 peer=10.89.6.2:48513 qname=github.com qtype=1 decision=nxdomain reason=not-in-class
";

/// `agentjail audit` is the incident view: both streams, in time order, with
/// the filters that make a specific jail's story readable.
#[test]
fn audit_merges_both_streams_and_filters_by_jail_and_decision() {
    let dir = tmpdir("audit-view");
    let audit = dir.join("audit.log");
    let dns = dir.join("dns.log");
    std::fs::write(&audit, AUDIT_LINES).expect("audit");
    std::fs::write(&dns, DNS_LINES).expect("dns");

    let output = run(
        &[
            "audit",
            "--audit",
            audit.to_str().unwrap(),
            "--dns",
            dns.to_str().unwrap(),
        ],
        &dir,
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 6, "{}", stdout(&output));
    // Time order across the two streams, tagged with the stream it came from.
    assert!(
        lines[0].starts_with("stream=audit ts=1795477011164 "),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with("stream=dns ts=1795477011165 "),
        "{lines:?}"
    );
    assert!(
        lines[2].starts_with("stream=dns ts=1795477011166 "),
        "{lines:?}"
    );

    let output = run(
        &[
            "audit",
            "--audit",
            audit.to_str().unwrap(),
            "--dns",
            dns.to_str().unwrap(),
            "--jail",
            "proof-1",
            "--decision",
            "deny",
        ],
        &dir,
        None,
    );
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.contains("reason=not-in-class"), "{text}");
    assert!(text.contains("reason=byte-budget"), "{text}");
    assert!(
        text.contains("budget=8192"),
        "the counter that caused it: {text}"
    );
    assert!(!text.contains("proof-2"), "{text}");

    // Tail: the last N of the merged, filtered view.
    let output = run(
        &[
            "audit",
            "--audit",
            audit.to_str().unwrap(),
            "--dns",
            dns.to_str().unwrap(),
            "--tail",
            "2",
        ],
        &dir,
        None,
    );
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.contains("proof-2"), "{text}");

    // One stream only.
    let output = run(
        &[
            "audit",
            "--audit",
            audit.to_str().unwrap(),
            "--dns",
            dns.to_str().unwrap(),
            "--stream",
            "dns",
        ],
        &dir,
        None,
    );
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(
        text.lines().all(|line| line.starts_with("stream=dns ")),
        "{text}"
    );
}

#[test]
fn audit_reads_the_streams_configured_for_a_class() {
    let dir = tmpdir("audit-class");
    let classes = dir.join("classes");
    std::fs::create_dir_all(&classes).expect("classes");
    let audit = dir.join("model-audit.log");
    let dns = dir.join("model-dns.log");
    std::fs::write(&audit, AUDIT_LINES).expect("audit");
    std::fs::write(&dns, DNS_LINES).expect("dns");
    std::fs::write(
        classes.join("model.toml"),
        format!(
            "class = \"model\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\n\
             audit_log = \"{}\"\ndns_log = \"{}\"\nmax_bytes = 8192\nmax_connections = 2\n\
             allow = [\"api.example.com:443\"]\n",
            audit.display(),
            dns.display()
        ),
    )
    .expect("class config");

    let digest = format!(
        "sha256:{}",
        agentjail_core::class::file_digest(&classes.join("model.toml"))
            .expect("digest the fixture class")
            .trim_start_matches("sha256:")
    );
    let output = run_with_env(
        &[
            "audit",
            "--class",
            "model",
            "--class-dir",
            classes.to_str().unwrap(),
            "--class-digest",
            &digest,
            "--jail",
            "proof-2",
        ],
        &dir,
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains("proof-2"), "{text}");

    // With neither a class nor a path there is nothing to read: say so rather
    // than printing an empty report that looks like "no activity".
    let output = run(&["audit"], &dir, None);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("--class"), "{}", stderr(&output));
}

#[test]
fn audit_reads_a_captured_stream_from_stdin() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = tmpdir("audit-stdin");
    let mut child = Command::new(binary())
        .args(["audit", "--audit", "-", "--decision", "deny"])
        .current_dir(&dir)
        .env_remove("AGENTJAIL_PODMAN")
        .env("PATH", "/nonexistent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(AUDIT_LINES.as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(
        text.lines().all(|line| line.starts_with("stream=audit ")),
        "{text}"
    );
}

// ------------------------------------------- operator-defined class directory

/// A class file a profile may name by directory, plus the digest that pins it.
fn operator_class(dir: &Path, name: &str) -> String {
    std::fs::create_dir_all(dir).expect("class dir");
    let path = dir.join(format!("{name}.toml"));
    std::fs::write(
        &path,
        format!(
            "class = \"{name}\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\n\
             max_bytes = 1048576\nmax_connections = 4\naddress_policy = \"lan\"\n\
             allow = [\n  \"api.anthropic.com:443\",\n]\n"
        ),
    )
    .expect("write class");
    agentjail_core::class::file_digest(&path).expect("digest")
}

fn operator_profile(operator_dir: &Path, class: &str, digest: &str) -> String {
    ALLOWLIST
        .replace("class = \"model\"", &format!("class = \"{class}\""))
        .replace(
            "mode = \"allowlist\"",
            &format!(
                "class_dir = \"{}\"\nclass_digest = \"{digest}\"\nmode = \"allowlist\"",
                operator_dir.display()
            ),
        )
}

#[test]
fn an_operator_class_is_validated_and_digest_pinned() {
    let dir = tmpdir("operator-ok");
    let classes = dir.join("classes");
    let digest = operator_class(&classes, "bot");
    let profile = dir.join("operator.toml");
    std::fs::write(&profile, operator_profile(&classes, "bot", &digest)).expect("write");

    let output = run_with_env(
        &["profile", "validate", profile.to_str().expect("path")],
        &dir,
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("bot.toml"), "the class file is named: {text}");
    assert!(
        text.contains("egress class \"bot\""),
        "the operator class is reported: {text}"
    );
}

#[test]
fn an_operator_class_whose_file_changed_under_the_digest_is_refused() {
    let dir = tmpdir("operator-drift");
    let classes = dir.join("classes");
    let digest = operator_class(&classes, "bot");
    let profile = dir.join("operator.toml");
    std::fs::write(&profile, operator_profile(&classes, "bot", &digest)).expect("write");
    // Same path, different policy: the pin is what makes that a review event.
    std::fs::write(
        classes.join("bot.toml"),
        "class = \"bot\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\n\
         max_bytes = 1048576\nmax_connections = 4\naddress_policy = \"lan\"\n\
         allow = [\n  \"api.anthropic.com:443\",\n  \"github.com:443\",\n]\n",
    )
    .expect("rewrite class");

    let output = run_with_env(
        &["profile", "validate", profile.to_str().expect("path")],
        &dir,
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("does not match the digest this profile pins"),
        "{text}"
    );
}

#[test]
fn an_operator_class_may_not_shadow_a_built_in_class() {
    let dir = tmpdir("operator-shadow");
    let classes = dir.join("classes");
    let digest = operator_class(&classes, "model");
    let profile = dir.join("shadow.toml");
    std::fs::write(&profile, operator_profile(&classes, "model", &digest)).expect("write");

    let output = run_with_env(
        &["profile", "validate", profile.to_str().expect("path")],
        &dir,
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("must not shadow a") && text.contains("built-in"),
        "{text}"
    );
}

#[test]
fn an_operator_class_needs_both_a_directory_and_a_digest() {
    let dir = tmpdir("operator-half");
    let classes = dir.join("classes");
    let digest = operator_class(&classes, "bot");
    let profile = dir.join("half.toml");
    std::fs::write(
        &profile,
        ALLOWLIST
            .replace("class = \"model\"", "class = \"bot\"")
            .replace(
                "mode = \"allowlist\"",
                &format!(
                    "class_dir = \"{}\"\nmode = \"allowlist\"",
                    classes.display()
                ),
            ),
    )
    .expect("write");

    let output = run_with_env(
        &["profile", "validate", profile.to_str().expect("path")],
        &dir,
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("give both or neither"),
        "{}",
        stderr(&output)
    );
    // …and the digest alone pins nothing either.
    std::fs::write(
        &profile,
        ALLOWLIST
            .replace("class = \"model\"", "class = \"bot\"")
            .replace(
                "mode = \"allowlist\"",
                &format!("class_digest = \"{digest}\"\nmode = \"allowlist\""),
            ),
    )
    .expect("write");
    let output = run_with_env(
        &["profile", "validate", profile.to_str().expect("path")],
        &dir,
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("give both or neither"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_operator_class_directory_must_be_absolute() {
    let dir = tmpdir("operator-relative");
    let digest = operator_class(&dir.join("classes"), "bot");
    let profile = dir.join("relative.toml");
    std::fs::write(
        &profile,
        ALLOWLIST
            .replace("class = \"model\"", "class = \"bot\"")
            .replace(
                "mode = \"allowlist\"",
                &format!(
                    "class_dir = \"classes\"\nclass_digest = \"{digest}\"\nmode = \"allowlist\""
                ),
            ),
    )
    .expect("write");

    let output = run_with_env(
        &["profile", "validate", profile.to_str().expect("path")],
        &dir,
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("is relative"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_class_name_outside_the_built_ins_needs_an_operator_directory() {
    let dir = tmpdir("operator-unknown");
    let profile = dir.join("unknown.toml");
    std::fs::write(
        &profile,
        ALLOWLIST.replace("class = \"model\"", "class = \"bot\""),
    )
    .expect("write");

    let output = run_with_env(
        &["profile", "validate", profile.to_str().expect("path")],
        &dir,
        None,
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("needs network.class_dir and network.class_digest"),
        "{text}"
    );
}

// ---------------------------------- the grant, and the image tag, end to end

/// The intersection logic must not assume the three shipped classes: an operator
/// class is loaded from a directory and pinned by digest, and the grant is then
/// the intersection of *that* class and the profile.
#[test]
fn the_grant_is_the_intersection_for_an_operator_class_too() {
    let dir = tmpdir("operator-grant");
    let classes = dir.join("classes");
    std::fs::create_dir_all(&classes).expect("class dir");
    let class_path = classes.join("bot.toml");
    std::fs::write(
        &class_path,
        "class = \"bot\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\n\
         max_bytes = 1048576\nmax_connections = 4\naddress_policy = \"lan\"\n\
         allow = [\n  \"api.anthropic.com:443\",\n  \"api.openai.com:443\",\n]\n",
    )
    .expect("write class");
    let digest = agentjail_core::class::file_digest(&class_path).expect("digest");
    // The profile lists one of the two destinations the operator class allows.
    let path = write_profile(
        &dir,
        "operator.toml",
        &operator_profile(&classes, "bot", &digest),
    );

    // `profile show` prints the grant, and it is the intersection: one of two.
    let output = run(
        &["profile", "show", path.to_str().expect("path")],
        &dir,
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(document["egress"]["class"], "bot");
    assert_eq!(
        document["egress"]["grant"],
        serde_json::json!(["api.anthropic.com:443"]),
        "the grant is the profile's list, not the operator class's"
    );

    // And `run` hands exactly that to the gateway.
    let podman = fake_podman(&dir);
    let gateway_argv = dir.join("gateway-argv.txt");
    let output = run_with_env(
        &["run", path.to_str().expect("path")],
        &dir,
        Some(&podman),
        &[
            (
                "AGENTJAIL_TEST_GATEWAY_ARGV",
                gateway_argv.to_str().expect("path"),
            ),
            ("EXAMPLE_FORGE_TOKEN", "fake-token-value"),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let gateway = recorded_argv(&gateway_argv).join(" ");
    assert!(
        gateway.contains("--grant api.anthropic.com:443"),
        "the operator class is the ceiling, the profile is the grant: {gateway}"
    );
    assert!(
        !gateway.contains("api.openai.com"),
        "a destination only the class allows must not reach the gateway: {gateway}"
    );
    assert!(
        gateway.contains(&classes.to_string_lossy().into_owned()),
        "the operator class file is what gets mounted: {gateway}"
    );
}

/// `run` derives the gateway tag in Rust and the build script derives it in
/// shell. If the two rules drift, `run` looks for an image nobody built, and the
/// failure reads as a missing image rather than a bug.
#[test]
fn run_and_the_build_script_agree_on_the_workspace_gateway_tag() {
    let dir = tmpdir("image-tag");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let podman = fake_podman(&dir);
    let output = run_with_env(
        &["run", path.to_str().expect("path")],
        &dir,
        Some(&podman),
        &[("EXAMPLE_FORGE_TOKEN", "fake-token-value")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    // `agentjail: gateway image "localhost/agentjail-gateway:ws-xxxxxxxx" is …`
    let line = stderr(&output)
        .lines()
        .find(|line| line.contains("gateway image"))
        .unwrap_or_default()
        .to_string();
    let tag = line
        .split('"')
        .nth(1)
        .unwrap_or_else(|| panic!("no quoted image tag in {line:?}"));
    assert!(
        !tag.ends_with(":1"),
        "the shared mutable tag must not be the default: {tag}"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let output = Command::new("sh")
        .arg(root.join("scripts/gateway-image-tag.sh"))
        .arg(&root)
        .output()
        .expect("run the tag script");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        tag,
        String::from_utf8_lossy(&output.stdout).trim(),
        "run and scripts/gateway-image-tag.sh disagree about this workspace's tag"
    );
}

/// A gateway that refuses to start must be reported as a refusal, not as a
/// container that is slow to get an address.
///
/// The difference decides what the next person does. "No address after 15s" reads
/// as a slow container, and the retry somebody adds is what removes the
/// guarantee; the exit code and the gateway's own last lines say what happened
/// and which flags are missing.
#[test]
fn a_gateway_that_refuses_to_start_is_reported_as_a_refusal_not_a_timeout() {
    let dir = tmpdir("gateway-refused");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let podman = fake_podman(&dir);
    let gateway_log = dir.join("gateway.log");
    std::fs::write(
        &gateway_log,
        "agentjail-gateway: error: neither --grant nor --class-only: a gateway started without \
         either would enforce the whole class allowlist\n",
    )
    .expect("write gateway log");

    let started = std::time::Instant::now();
    let output = run_with_env(
        &["run", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[
            ("AGENTJAIL_TEST_GATEWAY_EXITED", "1"),
            ("AGENTJAIL_TEST_GATEWAY_LOGS", gateway_log.to_str().unwrap()),
            ("EXAMPLE_FORGE_TOKEN", "fake-token-value"),
        ],
    );

    assert_eq!(output.status.code(), Some(1), "the jail must not start");
    let err = stderr(&output);
    assert!(
        err.contains("refused to start"),
        "the error must say the gateway refused to start: {err}"
    );
    assert!(
        err.contains("exited with code 1"),
        "the error must name the exit code: {err}"
    );
    assert!(
        err.contains("neither --grant nor --class-only"),
        "the error must carry the gateway's own reason: {err}"
    );
    assert!(
        err.contains("policy refusal"),
        "the error must say this is a decision, not a slow container: {err}"
    );
    for timeout_phrase in ["has no address", "after 15s", "is running but"] {
        assert!(
            !err.contains(timeout_phrase),
            "a refusal must not be reported as a timeout ({timeout_phrase:?}): {err}"
        );
    }
    // It reported the exit; it did not wait out the address deadline.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the exit should be noticed on the first poll, not after the deadline"
    );
}

/// The other half: a gateway that is alive but never gets an address is still a
/// timeout, and that message says the container is running.
#[test]
fn a_gateway_that_is_alive_and_addressless_is_still_a_timeout() {
    let dir = tmpdir("gateway-addressless");
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let podman = fake_podman(&dir);
    let output = run_with_env(
        &["run", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[
            // Running, but no address ever appears.
            ("AGENTJAIL_TEST_GATEWAY_NO_ADDRESS", "1"),
            ("EXAMPLE_FORGE_TOKEN", "fake-token-value"),
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(
        err.contains("is running but has no address"),
        "an alive gateway must be reported as still starting: {err}"
    );
    assert!(
        !err.contains("refused to start"),
        "a running gateway did not refuse anything: {err}"
    );
}

/// A gateway container whose run is gone must be pruned by *any* later run, not
/// only by a run of the same profile.
///
/// The gateway is no longer started with `--rm` (so a refusal can be read back),
/// which makes an orphan possible: a run that is killed leaves its gateway, and a
/// profile nobody runs again would leave it there indefinitely. The pid in the
/// name is what makes the pruning safe - a live run of any profile is untouched.
#[test]
fn an_orphaned_gateway_of_another_profile_is_pruned_by_this_run() {
    let dir = tmpdir("prune-orphan");
    // A class-side run: that is where a gateway container exists to be orphaned.
    let path = write_profile(&dir, "allowlist.toml", ALLOWLIST);
    let podman = fake_podman(&dir);
    let log = dir.join("podman.log");
    let containers = dir.join("containers.txt");

    // A pid that is certainly not running: high enough to be above anything this
    // machine has spawned, and checked rather than assumed.
    let dead = (900_000u32..)
        .find(|pid| *pid != std::process::id() && !Path::new(&format!("/proc/{pid}")).exists())
        .expect("a pid that is not running");
    let orphan = format!("agentjail-some-other-profile-{dead}-gateway");
    // A gateway of a different profile whose run is still alive: never touched.
    let live = format!("agentjail-another-profile-{}-gateway", std::process::id());
    std::fs::write(&containers, format!("{orphan}\n{live}\npodman\n")).expect("write containers");

    let output = run_with_env(
        &["run", path.to_str().unwrap()],
        &dir,
        Some(&podman),
        &[
            ("AGENTJAIL_TEST_LOG", log.to_str().unwrap()),
            ("AGENTJAIL_TEST_CONTAINERS", containers.to_str().unwrap()),
            ("EXAMPLE_FORGE_TOKEN", "fake-token-value"),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let events = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        events.contains(&format!("container-rm {orphan}")),
        "the orphan of another profile must be pruned: {events}"
    );
    assert!(
        !events.contains(&format!("container-rm {live}")),
        "a live run of another profile must not be touched: {events}"
    );
}
