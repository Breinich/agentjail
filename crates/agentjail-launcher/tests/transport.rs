//! Transport contract tests for the exec-in-jail shim.
//!
//! These verify the properties a host harness depends on: stdio is pipes and
//! stderr stays separate, signals are forwarded to the agent's process group,
//! and the exit code (including death-by-signal) is propagated.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_agentjail-launcher")
}

fn launcher(args: &[&str]) -> Command {
    let mut command = Command::new(binary());
    command
        .args(args)
        .env("AGENTJAIL_ALLOW_ROOT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

#[test]
fn exit_code_is_propagated() {
    let status = launcher(&["--", "sh", "-c", "exit 7"])
        .status()
        .expect("run launcher");
    assert_eq!(status.code(), Some(7));
}

#[test]
fn death_by_signal_maps_to_128_plus_signal() {
    let status = launcher(&["--", "sh", "-c", "kill -TERM $$"])
        .status()
        .expect("run launcher");
    assert_eq!(status.code(), Some(143));
}

#[test]
fn stdio_is_pipes_and_stderr_stays_separate() {
    let mut child = launcher(&[
        "--",
        "sh",
        "-c",
        "read line; printf 'out:%s\\n' \"$line\"; printf 'err:%s\\n' \"$line\" >&2",
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn launcher");

    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"hello\n")
        .expect("write stdin");

    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stdout, "out:hello\n");
    assert_eq!(stderr, "err:hello\n");
    assert!(
        !stdout.contains("err:"),
        "stdout must not carry stderr: {stdout:?}"
    );
}

#[test]
fn sigterm_is_forwarded_to_the_agent_process_group() {
    let mut child = launcher(&[
        "--",
        "sh",
        "-c",
        "trap 'exit 42' TERM; while :; do sleep 0.05; done",
    ])
    .spawn()
    .expect("spawn launcher");

    std::thread::sleep(Duration::from_millis(400));
    kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).expect("send SIGTERM");

    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(42),
        "the child's trap should have run; a killed child would report 143"
    );
}

#[test]
fn missing_command_is_a_usage_error() {
    let output = launcher(&[]).output().expect("run launcher");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage: agentjail-launcher"), "{stderr}");
}

#[test]
fn unknown_program_exits_127() {
    let status = launcher(&["--", "definitely-not-a-real-program"])
        .status()
        .expect("run launcher");
    assert_eq!(status.code(), Some(127));
}

#[test]
fn root_is_refused_unless_explicitly_allowed() {
    // Skip on non-root: the refusal is only reachable as uid 0.
    if !is_root() {
        return;
    }
    let output = Command::new(binary())
        .args(["--", "true"])
        .env_remove("AGENTJAIL_ALLOW_ROOT")
        .output()
        .expect("run launcher");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to run the agent as root"),
        "{stderr}"
    );

    let allowed = launcher(&["--", "true"]).status().expect("run launcher");
    assert_eq!(allowed.code(), Some(0));
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(2).map(str::to_string))
        })
        .map(|uid| uid == "0")
        .unwrap_or(false)
}
