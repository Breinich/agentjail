//! Gateway CLI tests: allowlist parsing is real; the proxy is not implemented.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ALLOWLIST: &str = r#"
version = 1
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[network]
mode = "allowlist"
dns = "pinned"

[[network.egress]]
host = "api.example.com"
port = 443

[agent]
command = "bash"
"#;

const OFFLINE: &str = r#"
version = 1
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
"#;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_agentjail-gateway")
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("gateway-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn run(profile: &Path) -> Output {
    Command::new(binary())
        .args(["--profile", profile.to_str().unwrap()])
        .output()
        .expect("run gateway")
}

#[test]
fn check_prints_the_allowlist_and_exits_zero() {
    let dir = tmpdir("check");
    let profile = dir.join("allowlist.toml");
    std::fs::write(&profile, ALLOWLIST).expect("write");
    let output = Command::new(binary())
        .args(["--profile", profile.to_str().unwrap(), "--check"])
        .output()
        .expect("run gateway");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("api.example.com:443/tls"), "{stdout}");
    assert!(stdout.contains("dns strategy: pinned"), "{stdout}");
}

#[test]
fn proxy_is_not_implemented_and_says_so() {
    let dir = tmpdir("stub");
    let profile = dir.join("allowlist.toml");
    std::fs::write(&profile, ALLOWLIST).expect("write");
    let output = run(&profile);
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not implemented"), "{stderr}");
    assert!(stderr.contains("description of intent"), "{stderr}");
}

#[test]
fn offline_profile_is_rejected() {
    let dir = tmpdir("offline");
    let profile = dir.join("offline.toml");
    std::fs::write(&profile, OFFLINE).expect("write");
    let output = run(&profile);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("only exists for \"allowlist\""), "{stderr}");
}

#[test]
fn invalid_profile_is_rejected_with_its_errors() {
    let dir = tmpdir("invalid");
    let profile = dir.join("invalid.toml");
    std::fs::write(&profile, ALLOWLIST.replace("dns = \"pinned\"\n", "")).expect("write");
    let output = run(&profile);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid"), "{stderr}");
    assert!(stderr.contains("dns"), "{stderr}");
}
