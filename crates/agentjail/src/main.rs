//! `agentjail`: the CLI.
//!
//! Increment 1 implements profile validation, profile display, host
//! diagnostics, and the outside half of the single-route invariant. `run` and
//! `selftest` validate their inputs, run the preflight checks that exist, and
//! then stop with exit code 3 (`NOT_IMPLEMENTED`) instead of pretending.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agentjail_core::paths;
use agentjail_core::podman;
use agentjail_core::profile::{self, Profile};
use clap::{ArgAction, Parser, Subcommand};

const EXIT_OK: u8 = 0;
const EXIT_FAILURE: u8 = 1;
const EXIT_NOT_IMPLEMENTED: u8 = 3;

const LAUNCHER_CONTRACT: &str = "\
Launcher contract (fixed now, implemented in a later increment):

  * stdio is pipes, not a TTY: stdin and stdout are a pair of pipes, so a
    JSON-RPC session over fd 0/1 works unchanged. stderr stays a separate
    stream and is never merged into stdout.
  * SIGINT, SIGTERM and SIGQUIT are forwarded to the agent process, terminal
    resize events are forwarded, and EOF on stdin is propagated.
  * agentjail exits with the agent's exit code; a signal-terminated agent maps
    to 128 + signal number.
  * The container is removed on every exit path, including signal and crash,
    so no jail is orphaned.

Exit codes: 0 success, 1 failure, 2 usage error, 3 not implemented yet. Once
launching is implemented, the agent's own exit code is passed through.";

const SELFTEST_CONTRACT: &str = "\
Selftest contract (fixed now, implemented in a later increment). Each check is
run twice in the same test file -- once against the pre-jail baseline and once
against the jailed build -- and must fail on the baseline while passing in the
jail:

  network (single-route invariant)
    - a raw IP:port is unreachable: DNS pinning buys nothing if the agent can
      send packets to an address
    - a second route, interface, or peer cannot be added from inside (no
      NET_ADMIN, no ability to change the jail's own network)
    - a network that is not internal is refused with a clear message, not
      warned about and not started-then-killed
    - the gateway is the only reachable peer, verified from inside the jail

  negative (must be denied)
    - no host secrets readable: a host-only credential path and a host
      environment variable are both unreachable
    - no host path writable by default
    - no unlisted destination reachable, and no DNS answer for an unlisted name
    - no podman/docker socket or host control socket reachable
    - no escape: no /proc/1/root, no host /proc mount, no CAP_SYS_ADMIN
    - two concurrent jails on distinct networks and homes cannot see each
      other's files, sockets, or credentials

  positive control
    - exactly one call to one allowlisted destination succeeds, and the
      response is well formed

  resource limits
    - cpu, memory, pids, open files, tmpfs size, and writable-layer size are
      each enforced, not merely declared";

#[derive(Parser)]
#[command(
    name = "agentjail",
    version,
    about = "Run an AI coding agent inside a rootless Podman jail with no host secrets, no host network, its own home, and an egress allowlist.",
    long_about = None,
    after_help = "Profiles are TOML files validated against schema/profile.schema.json. See docs/profiles.md for the reference."
)]
struct Cli {
    /// Extra directory to search for <name>.toml profiles; may be repeated.
    #[arg(long = "profile-dir", value_name = "DIR", global = true, action = ArgAction::Append)]
    profile_dirs: Vec<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect and validate profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Launch an agent inside the jail.
    #[command(after_long_help = LAUNCHER_CONTRACT)]
    Run(RunArgs),
    /// Prove the jail holds by trying to break out of it.
    #[command(long_about = SELFTEST_CONTRACT)]
    Selftest {
        /// Profile name or path to a .toml profile.
        profile: String,
    },
    /// Report podman version, rootless mode, SELinux state, config paths, and a network invariant check.
    Doctor {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// Verify an existing podman network against the single-route invariant.
        #[arg(long, value_name = "NAME")]
        network: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Validate a profile against the schema and semantic rules.
    Validate {
        /// Profile name or path to a .toml profile.
        profile: String,
    },
    /// Print the effective profile with defaults resolved, as JSON.
    Show {
        /// Profile name or path to a .toml profile.
        profile: String,
    },
}

#[derive(clap::Args)]
struct RunArgs {
    /// Profile name or path to a .toml profile.
    profile: String,
    /// Launch without injecting any secrets[] entries.
    #[arg(long)]
    no_secrets: bool,
    /// Agent command and arguments after '--'; overrides agent.command/agent.args.
    #[arg(last = true, value_name = "AGENT COMMAND")]
    agent_command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let env: BTreeMap<String, String> = std::env::vars().collect();
    match dispatch(cli, &env) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("agentjail: error: {message}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn dispatch(cli: Cli, env: &BTreeMap<String, String>) -> Result<u8, String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match cli.command {
        Command::Profile { action } => match action {
            ProfileAction::Validate { profile } => {
                validate_command(&profile, &cli.profile_dirs, env, &cwd)
            }
            ProfileAction::Show { profile } => show_command(&profile, &cli.profile_dirs, env, &cwd),
        },
        Command::Run(args) => run_command(args, &cli.profile_dirs, env, &cwd),
        Command::Selftest { profile } => selftest_command(&profile, &cli.profile_dirs, env, &cwd),
        Command::Doctor { json, network } => {
            let report = agentjail_core::doctor::collect(env, network.as_deref());
            print!(
                "{}",
                if json {
                    report.render_json()
                } else {
                    report.render_human()
                }
            );
            Ok(if report.ok() { EXIT_OK } else { EXIT_FAILURE })
        }
    }
}

fn validate_command(
    reference: &str,
    extra_dirs: &[PathBuf],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<u8, String> {
    let loaded = load_profile(reference, extra_dirs, env, cwd)?;
    println!("OK {}", loaded.path.display());
    println!("   image: {}", loaded.profile.image_ref());
    println!("   {}", loaded.profile.summary());
    Ok(EXIT_OK)
}

fn show_command(
    reference: &str,
    extra_dirs: &[PathBuf],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<u8, String> {
    let loaded = load_profile(reference, extra_dirs, env, cwd)?;
    let document = serde_json::json!({
        "name": loaded.profile_name(),
        "source": loaded.path.display().to_string(),
        "profile": loaded.profile.effective_json(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(EXIT_OK)
}

fn run_command(
    args: RunArgs,
    extra_dirs: &[PathBuf],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<u8, String> {
    let loaded = load_profile(&args.profile, extra_dirs, env, cwd)?;
    let profile = &loaded.profile;
    let command = if args.agent_command.is_empty() {
        profile.agent_argv()
    } else {
        args.agent_command.clone()
    };

    // Single-route invariant, outside half: verified on every start, not once
    // per profile install, because networks change under you. A refusal is an
    // error with a clear message -- never a warning, never start-then-kill.
    let network_note = preflight_network(profile)?;

    let secrets_note = if args.no_secrets {
        "all secrets suppressed (--no-secrets)".to_string()
    } else {
        format!(
            "{} secret reference(s) would be injected",
            profile.secrets.len()
        )
    };

    eprintln!("agentjail: not implemented: container launch is not implemented in this increment");
    eprintln!(
        "profile {:?} validated: {}",
        loaded.profile_name(),
        profile.summary()
    );
    eprintln!("{network_note}");
    eprintln!(
        "would exec {} inside {}",
        command.join(" "),
        profile.image_ref()
    );
    eprintln!("{secrets_note}");
    eprintln!(
        "The launcher contract (pipes not TTY, signal and resize forwarding, exit-code propagation, \
         no orphaned containers) is documented in docs/cli.md."
    );
    Ok(EXIT_NOT_IMPLEMENTED)
}

fn selftest_command(
    reference: &str,
    extra_dirs: &[PathBuf],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<u8, String> {
    let loaded = load_profile(reference, extra_dirs, env, cwd)?;
    let profile = &loaded.profile;
    let network_note = preflight_network(profile)?;

    eprintln!("agentjail: not implemented: selftest is not implemented in this increment");
    eprintln!(
        "profile {:?} validated: {}",
        loaded.profile_name(),
        profile.summary()
    );
    eprintln!("{network_note}");
    eprintln!(
        "Planned negative set: raw IP:port unreachable; no second route, interface, or peer can be \
         added from inside; a non-internal network is refused with a clear message; host secrets \
         unreadable; host paths read-only; unlisted destinations unreachable; container control \
         sockets absent; no escape; concurrent jails isolated; resource limits enforced. Positive \
         control: one allowlisted destination answers. See docs/cli.md."
    );
    Ok(EXIT_NOT_IMPLEMENTED)
}

/// The outside half of the single-route invariant, shared with `doctor`.
///
/// Returns a line describing what was verified. When the profile names no
/// network, the launcher will create a dedicated internal one and must verify
/// it the same way before starting anything -- that creation path is not
/// implemented yet, so this returns the honest state instead of a claim.
fn preflight_network(profile: &Profile) -> Result<String, String> {
    match &profile.network.name {
        Some(name) => match podman::verify_network(name) {
            Ok(posture) => Ok(format!(
                "preflight: single-route invariant OK (outside check): {}",
                posture.describe()
            )),
            Err(error) => Err(format!(
                "refusing to launch: the network named by this profile does not satisfy the \
                 single-route invariant.\n  {error}"
            )),
        },
        None => Ok(
            "preflight: no network.name set; the launcher must create a dedicated internal network \
             and verify it (outside and inside) before starting anything -- not implemented yet"
                .to_string(),
        ),
    }
}

struct LoadedProfile {
    path: PathBuf,
    profile: Profile,
}

impl LoadedProfile {
    fn profile_name(&self) -> String {
        self.path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.profile.image.name.clone())
    }
}

fn load_profile(
    reference: &str,
    extra_dirs: &[PathBuf],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<LoadedProfile, String> {
    let path = resolve_profile_path(reference, extra_dirs, env, cwd)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read profile {}: {error}", path.display()))?;
    let profile = profile::parse_and_validate(&text).map_err(|errors| {
        format!(
            "profile {} is invalid ({} error(s)):\n{}",
            path.display(),
            errors.len(),
            errors
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;
    Ok(LoadedProfile { path, profile })
}

fn resolve_profile_path(
    reference: &str,
    extra_dirs: &[PathBuf],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<PathBuf, String> {
    let looks_like_path = reference.contains('/') || reference.ends_with(".toml");
    if looks_like_path {
        let path = PathBuf::from(reference);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "profile not found: {} (no such file)",
            path.display()
        ));
    }

    let mut dirs = extra_dirs.to_vec();
    dirs.extend(paths::profile_search_dirs(env, cwd));
    for directory in &dirs {
        let candidate = directory.join(format!("{reference}.toml"));
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let searched = dirs
        .iter()
        .map(|directory| {
            format!(
                "  - {}",
                directory.join(format!("{reference}.toml")).display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Err(format!(
        "profile {reference:?} not found; searched:\n{searched}"
    ))
}
