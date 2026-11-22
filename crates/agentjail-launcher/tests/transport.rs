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

// ---------------------------------------------------------------------------
// Signal coverage: SIGINT, SIGQUIT, SIGWINCH
// ---------------------------------------------------------------------------

fn send(pid: u32, signal: Signal) {
    kill(Pid::from_raw(pid as i32), signal).expect("send signal");
}

fn wait_for_line(
    receiver: &std::sync::mpsc::Receiver<String>,
    timeout: Duration,
    context: &str,
) -> String {
    receiver
        .recv_timeout(timeout)
        .unwrap_or_else(|_| panic!("timed out waiting for {context}"))
}

#[test]
fn sigint_is_forwarded_to_the_agent_process_group() {
    let mut child = launcher(&[
        "--",
        "sh",
        "-c",
        "trap 'exit 40' INT; while :; do sleep 0.05; done",
    ])
    .spawn()
    .expect("spawn launcher");
    std::thread::sleep(Duration::from_millis(400));
    send(child.id(), Signal::SIGINT);
    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(40),
        "the child's SIGINT trap should have run; 130 would mean the launcher itself died"
    );
}

#[test]
fn sigquit_is_forwarded_to_the_agent_process_group() {
    let mut child = launcher(&[
        "--",
        "sh",
        "-c",
        "trap 'exit 41' QUIT; while :; do sleep 0.05; done",
    ])
    .spawn()
    .expect("spawn launcher");
    std::thread::sleep(Duration::from_millis(400));
    send(child.id(), Signal::SIGQUIT);
    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(41),
        "the child's SIGQUIT trap should have run"
    );
}

#[test]
fn sigwinch_is_forwarded_while_the_agent_keeps_running() {
    // Without a PTY the child cannot ioctl a window size, so the observable
    // evidence is the child's SIGWINCH handler running while the session stays
    // alive (a merely killed or ignored signal would produce neither).
    let mut child = launcher(&[
        "--",
        "sh",
        "-c",
        "trap 'echo winch' WINCH; while :; do sleep 0.05; done",
    ])
    .stdout(Stdio::piped())
    .spawn()
    .expect("spawn launcher");

    let mut stdout = child.stdout.take().expect("stdout");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(&mut stdout)
            .lines()
            .map_while(Result::ok)
        {
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    std::thread::sleep(Duration::from_millis(400));
    send(child.id(), Signal::SIGWINCH);
    let line = wait_for_line(
        &receiver,
        Duration::from_secs(5),
        "the SIGWINCH handler output",
    );
    assert_eq!(line, "winch");

    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the agent must still be running after a resize"
    );

    send(child.id(), Signal::SIGTERM);
    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(143),
        "SIGTERM should terminate the agent"
    );
}

// ---------------------------------------------------------------------------
// JSON-RPC over the pipes: the interface adoption depends on
// ---------------------------------------------------------------------------

/// A line-framed stdio JSON-RPC peer: answers every request with a result,
/// then emits a shutdown notification when stdin closes.
const JSONRPC_PEER: &str = r#"#!/bin/sh
while IFS= read -r line; do
  id=${line#*\"id\":}
  id=${id%%,*}
  id=${id%%\}*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
done
printf '{"jsonrpc":"2.0","method":"shutdown"}\n'
"#;

#[test]
fn jsonrpc_session_survives_three_round_trips_and_shuts_down_cleanly() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("jsonrpc-peer");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let peer = dir.join("peer.sh");
    std::fs::write(&peer, JSONRPC_PEER).expect("write peer");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&peer, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let mut child = launcher(&["--", "sh", peer.to_str().expect("path")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn launcher");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    for id in 1..=3 {
        writeln!(
            stdin,
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\",\"params\":{{}}}}"
        )
        .expect("write request");
        stdin.flush().expect("flush");
        let line = wait_for_line(&receiver, Duration::from_secs(5), "a JSON-RPC response");
        let response: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("bad JSON {line:?}: {error}"));
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], id);
        assert_eq!(response["result"]["ok"], true);
    }

    // EOF on stdin, exactly as a harness that closes the session would do.
    drop(stdin);
    let notification = wait_for_line(
        &receiver,
        Duration::from_secs(5),
        "the shutdown notification",
    );
    let notification: serde_json::Value = serde_json::from_str(&notification).expect("valid JSON");
    assert_eq!(notification["method"], "shutdown");

    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(0),
        "clean shutdown must propagate exit 0"
    );
    let stderr = {
        use std::io::Read;
        let mut buffer = String::new();
        child
            .stderr
            .take()
            .expect("stderr")
            .read_to_string(&mut buffer)
            .expect("read stderr");
        buffer
    };
    assert!(
        !stderr.contains("jsonrpc"),
        "stderr must stay free of protocol traffic: {stderr:?}"
    );
}
