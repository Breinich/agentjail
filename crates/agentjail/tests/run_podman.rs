//! Real-jail tests. Require rootless podman and the local base image, so they
//! are `#[ignore]`d and never run in the cheap PR pipeline. Run them with:
//!
//! ```sh
//! cargo test -p agentjail --test run_podman -- --ignored --test-threads=1
//! ```
//!
//! They are the evidence that the run path is real: a container is created and
//! reaped, the agent runs as uid 10000, host environment and paths are absent,
//! limits are enforced, and a secret never appears in `podman inspect`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const IMAGE: &str = "localhost/agentjail-base:1";

fn podman(args: &[&str]) -> Output {
    Command::new("podman")
        .args(args)
        .env_remove("AGENTJAIL_PODMAN")
        .output()
        .expect("run podman")
}

fn podman_ok(args: &[&str]) -> String {
    let output = podman(args);
    assert!(
        output.status.success(),
        "podman {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn agentjail(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentjail"))
        .args(args)
        .env_remove("AGENTJAIL_PODMAN")
        .envs(env.iter().copied())
        .output()
        .expect("run agentjail")
}

fn network_name(label: &str) -> String {
    format!("agentjail-test-{}-{label}", std::process::id())
}

fn create_network(name: &str, internal: bool) {
    // Let podman choose a free subnet: hard-coded ranges collide with whatever
    // else the host already uses.
    let mut args = vec!["network", "create"];
    if internal {
        args.push("--internal");
    }
    args.push(name);
    podman_ok(&args);
}

fn remove_network(name: &str) {
    let _ = podman(&["network", "rm", "-f", name]);
}

fn tmpdir(label: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("run-podman-{label}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn image_digest() -> String {
    podman_ok(&["image", "inspect", "--format", "{{.Digest}}", IMAGE])
}

fn profile(dir: &Path, label: &str, network: &str, body: &str) -> PathBuf {
    let digest = image_digest();
    let text = format!(
        r#"version = 1
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "{digest}"

[network]
name = "{network}"
mode = "none"
dns = "none"

[agent]
{body}
"#
    );
    let path = dir.join(format!("{label}.toml"));
    std::fs::write(&path, text).expect("write profile");
    path
}

fn wait_for_containers(prefix: &str, count: usize, timeout: Duration) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    loop {
        let names: Vec<String> = podman_ok(&["ps", "--format", "{{.Names}}"])
            .lines()
            .filter(|name| name.starts_with(prefix))
            .map(str::to_string)
            .collect();
        if names.len() >= count {
            return names;
        }
        if Instant::now() > deadline {
            return names;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_container(prefix: &str, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        let names = podman_ok(&["ps", "--format", "{{.Names}}"]);
        if let Some(name) = names.lines().find(|name| name.starts_with(prefix)) {
            return Some(name.to_string());
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn no_agentjail_containers(prefix: &str) -> bool {
    podman_ok(&["ps", "-a", "--format", "{{.Names}}"])
        .lines()
        .all(|name| !name.starts_with(prefix))
}

fn remove_secrets(prefix: &str) {
    if let Ok(list) = std::process::Command::new("podman")
        .args(["secret", "ls", "--format", "{{.Name}}"])
        .output()
    {
        for name in String::from_utf8_lossy(&list.stdout).lines() {
            if name.starts_with(prefix) {
                let _ = podman(&["secret", "rm", name]);
            }
        }
    }
}

#[test]
#[ignore = "requires rootless podman and the local base image"]
fn jail_runs_as_uid_10000_without_host_env_paths_or_sockets_and_with_limits() {
    let dir = tmpdir("hardening");
    let network = network_name("hardening");
    create_network(&network, true);

    let host_secret = dir.join("host-only-secret");
    std::fs::write(&host_secret, b"host-secret-value").expect("write host secret");

    let profile_path = profile(
        &dir,
        "hardening",
        &network,
        r#"command = "sh"
args = ["-lc", "echo uid=$(id -u); echo hostvar=$(printenv HOST_SECRET_VAR || echo unset); echo socket=$(ls /run/podman/podman.sock 2>&1); echo hostfile=$(cat PLACEHOLDER 2>&1); echo mem=$(cat /sys/fs/cgroup/memory.max); echo pids=$(cat /sys/fs/cgroup/pids.max); echo nofile=$(ulimit -n); echo home=$HOME; echo home-mode=$(stat -c '%a %u' $HOME); touch $HOME/probe && echo home-writable=yes; echo ok"]"#,
    );
    let text = std::fs::read_to_string(&profile_path)
        .expect("read")
        .replace("PLACEHOLDER", host_secret.to_str().expect("path"))
        .replace(
            "[agent]",
            "[resources]\nmemory = \"256m\"\npids = 128\nnofile = 2048\ncpus = 1\n\n[agent]",
        );
    std::fs::write(&profile_path, text).expect("write profile");

    let output = agentjail(
        &["run", profile_path.to_str().expect("path")],
        &[("HOST_SECRET_VAR", "fake-host-value")],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={stdout}\nstderr={stderr}"
    );
    assert!(stdout.contains("uid=10000"), "{stdout}");
    assert!(
        stdout.contains("hostvar=unset"),
        "host env leaked: {stdout}"
    );
    assert!(
        stdout.contains("No such file or directory"),
        "host path or socket visible: {stdout}"
    );
    assert!(
        stdout.contains("mem=268435456"),
        "memory limit not enforced: {stdout}"
    );
    assert!(
        stdout.contains("pids=128"),
        "pids limit not enforced: {stdout}"
    );
    assert!(
        stdout.contains("nofile=2048"),
        "nofile limit not enforced: {stdout}"
    );
    assert!(stdout.contains("home=/home/agent"), "{stdout}");
    assert!(
        stdout.contains("home-mode=700 10000"),
        "home is not 0700 owned by the jail uid: {stdout}"
    );
    assert!(stdout.contains("home-writable=yes"), "{stdout}");
    assert!(stdout.contains("ok"), "{stdout}");
    assert!(
        no_agentjail_containers("agentjail-hardening-"),
        "the jail was not reaped"
    );

    remove_network(&network);
}

#[test]
#[ignore = "requires rootless podman and the local base image"]
fn secret_is_injected_at_start_and_absent_from_podman_inspect() {
    let dir = tmpdir("secret");
    let network = network_name("secret");
    create_network(&network, true);

    let profile_path = profile(
        &dir,
        "hardening",
        &network,
        r#"command = "sh"
args = ["-lc", "printf 'started\n'; sleep 30"]"#,
    );
    let text = std::fs::read_to_string(&profile_path).expect("read").replace(
        "[agent]",
        "[[secrets]]\nname = \"example\"\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n\n[agent]",
    );
    std::fs::write(&profile_path, text).expect("write profile");

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentjail"))
        .args(["run", profile_path.to_str().expect("path")])
        .env_remove("AGENTJAIL_PODMAN")
        .env("EXAMPLE_TOKEN", "fake-token-value-for-inspect")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentjail");

    let container =
        wait_for_container("agentjail-", Duration::from_secs(15)).expect("container did not start");
    let inspect = podman_ok(&["inspect", &container]);
    assert!(
        !inspect.contains("fake-token-value-for-inspect"),
        "secret value leaked into podman inspect: {inspect}"
    );
    assert!(
        !inspect.contains("EXAMPLE_TOKEN=fake"),
        "secret value leaked into container Env: {inspect}"
    );

    let _ = podman(&["rm", "-f", &container]);
    let _ = child.wait();
    // The store entry is a reference that survives the `--rm` container; the
    // next run prunes it. Prune here so the test leaves no state behind.
    remove_secrets("agentjail-secret-");
    remove_network(&network);
}

#[test]
#[ignore = "requires rootless podman and the local base image"]
fn no_secrets_runs_with_nothing_at_all() {
    let dir = tmpdir("no-secrets");
    let network = network_name("no-secrets");
    create_network(&network, true);

    let profile_path = profile(
        &dir,
        "hardening",
        &network,
        r#"command = "sh"
args = ["-lc", "echo token=$(printenv EXAMPLE_TOKEN || echo unset); echo ok"]"#,
    );
    let text = std::fs::read_to_string(&profile_path).expect("read").replace(
        "[agent]",
        "[[secrets]]\nname = \"example\"\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n\n[agent]",
    );
    std::fs::write(&profile_path, text).expect("write profile");

    let output = agentjail(
        &["run", "--no-secrets", profile_path.to_str().expect("path")],
        &[("EXAMPLE_TOKEN", "fake-token-value")],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("token=unset"), "{stdout}");
    assert!(stdout.contains("ok"), "{stdout}");
    remove_network(&network);
}

#[test]
#[ignore = "requires rootless podman and the local base image"]
fn a_bridged_network_is_refused_before_any_container_exists() {
    let dir = tmpdir("bridged");
    let network = network_name("bridged");
    create_network(&network, false);

    let profile_path = profile(
        &dir,
        "hardening",
        &network,
        r#"command = "sh"
args = ["-lc", "echo should-not-run"]"#,
    );
    let output = agentjail(&["run", profile_path.to_str().expect("path")], &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("refusing to launch"), "{stderr}");
    assert!(stderr.contains("not internal"), "{stderr}");
    assert!(
        no_agentjail_containers("agentjail-bridged-"),
        "a refusal created a container"
    );

    remove_network(&network);
}

#[test]
#[ignore = "requires rootless podman and the local base image"]
fn the_base_image_is_required_and_pinned() {
    // `--pull=never` is in the argv: an absent image must fail instead of
    // silently pulling a tag.
    let dir = tmpdir("missing-image");
    let network = network_name("missing-image");
    create_network(&network, true);
    let profile_path = profile(
        &dir,
        "hardening",
        &network,
        r#"command = "sh"
args = ["-lc", "true"]"#,
    );
    let text = std::fs::read_to_string(&profile_path)
        .expect("read")
        .replace(IMAGE, "localhost/agentjail-base-does-not-exist:1");
    std::fs::write(&profile_path, text).expect("write profile");
    let output = agentjail(&["run", profile_path.to_str().expect("path")], &[]);
    assert_ne!(output.status.code(), Some(0));
    remove_network(&network);
}

#[test]
#[ignore = "requires rootless podman and the local base image"]
fn concurrent_runs_of_one_profile_keep_their_own_secret_entries() {
    let dir = tmpdir("concurrent");
    let network = network_name("concurrent");
    create_network(&network, true);

    let profile_path = profile(
        &dir,
        "concurrent",
        &network,
        r#"command = "sh"
args = ["-lc", "printf 'started\n'; sleep 30"]"#,
    );
    let text = std::fs::read_to_string(&profile_path).expect("read").replace(
        "[agent]",
        "[[secrets]]\nname = \"example\"\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n\n[agent]",
    );
    std::fs::write(&profile_path, text).expect("write profile");

    let spawn = |value: &'static str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_agentjail"))
            .args(["run", profile_path.to_str().expect("path")])
            .env_remove("AGENTJAIL_PODMAN")
            .env("EXAMPLE_TOKEN", value)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn agentjail")
    };
    let mut first = spawn("fake-value-a");
    let mut second = spawn("fake-value-b");

    let containers = wait_for_containers("agentjail-concurrent-", 2, Duration::from_secs(20));
    assert_eq!(
        containers.len(),
        2,
        "expected two concurrent jails: {containers:?}"
    );
    let first_name = format!("agentjail-concurrent-{}", first.id());
    let second_name = format!("agentjail-concurrent-{}", second.id());
    assert!(containers.contains(&first_name), "{containers:?}");
    assert!(containers.contains(&second_name), "{containers:?}");

    // Distinct store entries, and both still present while both runs live:
    // neither run pruned the other's entry.
    let secrets: Vec<String> = podman_ok(&["secret", "ls", "--format", "{{.Name}}"])
        .lines()
        .filter(|name| name.starts_with("agentjail-concurrent-"))
        .map(str::to_string)
        .collect();
    assert_eq!(secrets.len(), 2, "expected one entry per run: {secrets:?}");
    for (container, expected_value) in [
        (&first_name, "fake-value-a"),
        (&second_name, "fake-value-b"),
    ] {
        let run_id = container
            .strip_prefix("agentjail-concurrent-")
            .expect("container name carries the pid");
        assert!(
            secrets
                .iter()
                .any(|secret| secret == &format!("agentjail-concurrent-{run_id}-EXAMPLE_TOKEN")),
            "container {container} has no matching entry in {secrets:?}"
        );
        // Each jail sees its own value, so neither picked up the other's entry.
        let value = podman_ok(&["exec", container, "sh", "-lc", "printenv EXAMPLE_TOKEN"]);
        assert_eq!(
            value, expected_value,
            "container {container} saw the wrong value"
        );
    }

    // SIGTERM (not SIGKILL): the supervisor forwards it, waits for podman, and
    // removes the entries on the way out.
    for child in [&first, &second] {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .expect("send SIGTERM");
    }
    for child in [&mut first, &mut second] {
        let _ = child.wait();
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let leftover: Vec<String> = podman_ok(&["secret", "ls", "--format", "{{.Name}}"])
            .lines()
            .filter(|name| name.starts_with("agentjail-concurrent-"))
            .map(str::to_string)
            .collect();
        if leftover.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "secret entries survived a signal-terminated run: {leftover:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    for container in &containers {
        let _ = podman(&["rm", "-f", container]);
    }
    remove_network(&network);
}
