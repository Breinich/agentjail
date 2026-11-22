//! `agentjail-launcher`: the exec-in-jail shim.
//!
//! It is the first process inside the jail and does exactly four things:
//!
//! 1. Refuses to run as root (the jail's `USER` is uid 10000; this is defence
//!    in depth, and `AGENTJAIL_ALLOW_ROOT=1` exists only so the test suite and
//!    image builds can exercise it as uid 0).
//! 2. Execs the agent with stdio inherited, so stdin/stdout stay a pair of pipes
//!    and stderr stays separate. There is no pseudo-terminal anywhere in the
//!    path.
//! 3. Forwards SIGINT, SIGTERM, SIGQUIT, and SIGWINCH to the agent's process
//!    group, so a terminal resize or an interrupt reaches the whole agent tree
//!    and not just its first process.
//! 4. Exits with the agent's exit code, mapping death-by-signal N to 128 + N.
//!
//! It does not implement isolation. Podman/crun does the containment; this is
//! plumbing inside it.

use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use nix::sys::signal::{kill, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::Pid;

/// Most recently received forwardable signal, 0 when none is pending.
static PENDING: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_signal(signal: i32) {
    PENDING.store(signal, Ordering::SeqCst);
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let argv = match agent_argv(std::env::args().skip(1).collect()) {
        Ok(argv) => argv,
        Err(message) => {
            eprintln!("agentjail-launcher: {message}");
            return 2;
        }
    };

    if euid() == Some(0) && std::env::var_os("AGENTJAIL_ALLOW_ROOT").is_none() {
        eprintln!(
            "agentjail-launcher: refusing to run the agent as root inside the jail; \
             the jail runs as an unprivileged uid"
        );
        return 1;
    }

    if std::env::var_os("HOME").is_none() {
        // The image sets HOME, but a jail with a custom home must not depend on it.
        std::env::set_var("HOME", "/home/agent");
    }

    if let Err(message) = install_handlers() {
        eprintln!("agentjail-launcher: {message}");
        return 1;
    }

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    // Own process group: forwarding a signal to -pid reaches the agent and
    // everything it spawned, which is what a Ctrl-C or a stop request means.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("agentjail-launcher: cannot exec {:?}: {error}", argv[0]);
            return 127;
        }
    };

    let child_id = child.id() as i32;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return exit_code(status),
            Ok(None) => {}
            Err(error) => {
                eprintln!("agentjail-launcher: cannot wait for the agent: {error}");
                return 1;
            }
        }

        let pending = PENDING.swap(0, Ordering::SeqCst);
        if pending != 0 {
            // Negative pid: the child's own process group.
            let _ = kill(
                Pid::from_raw(-child_id),
                Signal::try_from(pending).ok().unwrap_or(Signal::SIGTERM),
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn agent_argv(mut raw: Vec<String>) -> Result<Vec<String>, String> {
    while raw.first().map(String::as_str) == Some("--") {
        raw.remove(0);
    }
    if raw.is_empty() {
        return Err(
            "no agent command given; usage: agentjail-launcher [--] <program> [args...]"
                .to_string(),
        );
    }
    Ok(raw)
}

fn install_handlers() -> Result<(), String> {
    for signal in [
        Signal::SIGINT,
        Signal::SIGTERM,
        Signal::SIGQUIT,
        Signal::SIGWINCH,
    ] {
        let action = SigAction::new(
            SigHandler::Handler(record_signal),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        // SAFETY: the handler only stores into an atomic, which is
        // async-signal-safe.
        unsafe { sigaction(signal, &action) }
            .map_err(|error| format!("cannot install a handler for {signal}: {error}"))?;
    }
    Ok(())
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

fn euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_passed_through() {
        assert_eq!(
            agent_argv(vec![
                "--".into(),
                "pi".into(),
                "--mode".into(),
                "rpc".into()
            ])
            .unwrap(),
            vec!["pi", "--mode", "rpc"]
        );
    }

    #[test]
    fn empty_command_is_a_usage_error() {
        assert!(agent_argv(vec![]).is_err());
        assert!(agent_argv(vec!["--".into()]).is_err());
    }
}
