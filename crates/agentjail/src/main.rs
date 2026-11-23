//! `agentjail`: the CLI.
//!
//! Increment 1 implements profile validation, profile display, host
//! diagnostics, and the outside half of the single-route invariant. `run` and
//! `selftest` validate their inputs, run the preflight checks that exist, and
//! then stop with exit code 3 (`NOT_IMPLEMENTED`) instead of pretending.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};

use agentjail_core::class::{self, ClassConfig, PROXY_PORT};
use agentjail_core::lifecycle;
use agentjail_core::paths;
use agentjail_core::podman;
use agentjail_core::profile::{self, NetworkMode, Profile};
use agentjail_core::run;
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
    if let Err(errors) = run::run_blockers(&loaded.profile) {
        return Err(format!(
            "profile {} is not runnable ({} error(s)):\n{}",
            loaded.path.display(),
            errors.len(),
            errors
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    println!("OK {}", loaded.path.display());
    println!("   image: {}", loaded.profile.image_ref());
    println!("   {}", loaded.profile.summary());
    if let Some((path, class)) = resolve_class(&loaded.profile, env, cwd)? {
        println!(
            "   egress class {:?} from {}: {} allowlisted destination(s), deny by default",
            class.class,
            path.display(),
            class.allow.len()
        );
    }
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
    let profile_name = loaded.profile_name();

    run::run_blockers(profile).map_err(|errors| {
        format!(
            "refusing to run profile {profile_name:?}:\n{}",
            errors
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;

    let run_id = std::process::id();
    let mut cleanup = RunCleanup::default();
    let mut context = run::RunContext {
        container_name: run::container_name(&profile_name, run_id),
        network: String::new(),
        gateway_ip: None,
        selinux: Path::new("/sys/fs/selinux/enforce").exists(),
        term: env.get("TERM").cloned(),
    };

    match profile.network.mode {
        // Single-route invariant, outside half: verified on every start, not once
        // per profile install, because networks change under you.
        NetworkMode::None => {
            let posture = preflight_network(profile)?;
            eprintln!("agentjail: preflight OK: {}", posture.describe());
            context.network = posture.name;
        }
        // The class side creates the network, so the guard owns it from the
        // moment it exists; the invariant is verified on the network it created.
        NetworkMode::Allowlist => {
            let (network, gateway_ip) =
                start_class_side(profile, &profile_name, run_id, env, cwd, &mut cleanup)?;
            context.network = network;
            context.gateway_ip = Some(gateway_ip);
        }
    }

    let command = if args.agent_command.is_empty() {
        profile.agent_argv()
    } else {
        args.agent_command.clone()
    };

    // Secrets: resolved here by reference, injected from podman's secret store
    // as environment variables. Values never enter the container argv or config.
    // Store entries are named per run (pid), so two concurrent runs of the same
    // profile can never prune or overwrite each other's entry.
    let plans = if args.no_secrets {
        eprintln!("agentjail: --no-secrets: no secret is injected");
        Vec::new()
    } else {
        run::plan_secrets(&profile_name, run_id, profile, env).map_err(|errors| {
            format!(
                "refusing to run profile {profile_name:?}: secret resolution failed:\n{}",
                errors
                    .iter()
                    .map(|error| format!("  - {error}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })?
    };

    // Backstop: prune entries whose owning run is gone. Never by profile alone.
    let secret_prefix = run::secret_prefix(&profile_name);
    if let Ok(existing) = podman::secret_list() {
        let stale = run::stale_secret_names(&existing, &secret_prefix, run_id, pid_alive);
        for name in stale {
            let _ = podman::secret_remove(&name);
        }
    }

    // Cleanup guard: removes what this run created -- secret store entries, the
    // gateway container, the class network -- on every exit path: normal,
    // non-zero, signal, and panic (unwinding Drop). The store entry of a
    // `source = "store"` secret belongs to the user and is never removed.
    for plan in &plans {
        match &plan.action {
            run::SecretAction::Create { store_name, value } => {
                podman::secret_create(store_name, value)?;
                cleanup.secrets.push(store_name.clone());
            }
            run::SecretAction::Existing { store_name } => {
                if !podman::secret_exists(store_name) {
                    return Err(format!(
                        "refusing to run profile {profile_name:?}: secret store entry \
                         {store_name:?} does not exist"
                    ));
                }
            }
        }
    }

    let argv = run::podman_args(profile, &context, &plans, &command).map_err(|errors| {
        format!(
            "refusing to run profile {profile_name:?}:\n{}",
            errors
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;

    let binary = podman::binary().ok_or_else(|| {
        "podman is not installed or not on PATH: nothing can be launched".to_string()
    })?;
    eprintln!("agentjail: exec {} {}", binary.display(), argv.join(" "));

    #[cfg(unix)]
    {
        if cleanup.is_empty() {
            use std::os::unix::process::CommandExt;
            // Nothing to clean up: exec, so stdio, signals and the agent's exit
            // code pass through untouched with no wrapper in the path.
            let error = std::process::Command::new(&binary).args(&argv).exec();
            return Err(format!("cannot exec {}: {error}", binary.display()));
        }

        // This run owns resources, so supervise instead of exec: forward signals,
        // wait for podman, then let the guard remove them.
        eprintln!(
            "agentjail: supervising podman to clean up on exit: {}",
            cleanup.describe()
        );
        supervise(&binary, &argv)
    }
    #[cfg(not(unix))]
    {
        Err("agentjail run needs a unix host".to_string())
    }
}

/// Everything this run created, removed whenever the process stops: normal
/// exit, non-zero exit, forwarded signal, or panic. Container before network,
/// because a network cannot be removed while a peer is attached to it.
#[derive(Default)]
struct RunCleanup {
    secrets: Vec<String>,
    container: Option<String>,
    network: Option<String>,
}

impl RunCleanup {
    fn is_empty(&self) -> bool {
        self.secrets.is_empty() && self.container.is_none() && self.network.is_none()
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.secrets.is_empty() {
            parts.push(format!(
                "{} secret store entr{}",
                self.secrets.len(),
                if self.secrets.len() == 1 { "y" } else { "ies" }
            ));
        }
        if let Some(container) = &self.container {
            parts.push(format!("gateway container {container:?}"));
        }
        if let Some(network) = &self.network {
            parts.push(format!("network {network:?}"));
        }
        parts.join(", ")
    }
}

impl Drop for RunCleanup {
    fn drop(&mut self) {
        for name in &self.secrets {
            if let Err(error) = podman::secret_remove(name) {
                eprintln!("agentjail: warning: could not remove secret {name:?}: {error}");
            }
        }
        if let Some(container) = &self.container {
            if let Err(error) = podman::container_remove(container) {
                eprintln!("agentjail: warning: could not remove gateway {container:?}: {error}");
            }
        }
        if let Some(network) = &self.network {
            if let Err(error) = podman::network_remove(network) {
                eprintln!("agentjail: warning: could not remove network {network:?}: {error}");
            }
        }
    }
}

static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_signal(signal: i32) {
    PENDING_SIGNAL.store(signal, Ordering::SeqCst);
}

/// Run podman as a child so the secret store can be cleaned up afterwards.
/// Signals are forwarded; the child's exit code (or 128 + signal) is returned.
fn supervise(binary: &Path, argv: &[String]) -> Result<u8, String> {
    use nix::sys::signal::{kill, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
    use nix::unistd::Pid;

    for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGQUIT] {
        let action = SigAction::new(
            SigHandler::Handler(record_signal),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        // SAFETY: the handler only stores into an atomic.
        unsafe { sigaction(signal, &action) }
            .map_err(|error| format!("cannot install a handler for {signal}: {error}"))?;
    }

    let mut child = std::process::Command::new(binary)
        .args(argv)
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", binary.display()))?;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(code) = status.code() {
                    return Ok(code as u8);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(signal) = status.signal() {
                        return Ok((128 + signal) as u8);
                    }
                }
                return Ok(1);
            }
            Ok(None) => {}
            Err(error) => return Err(format!("cannot wait for podman: {error}")),
        }
        let pending = PENDING_SIGNAL.swap(0, Ordering::SeqCst);
        if pending != 0 {
            let _ = kill(
                Pid::from_raw(child.id() as i32),
                Signal::try_from(pending).unwrap_or(Signal::SIGTERM),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

fn selftest_command(
    reference: &str,
    extra_dirs: &[PathBuf],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<u8, String> {
    let loaded = load_profile(reference, extra_dirs, env, cwd)?;
    let profile = &loaded.profile;
    let posture = preflight_network(profile)?;

    eprintln!("agentjail: not implemented: selftest is not implemented in this increment");
    eprintln!(
        "profile {:?} validated: {}",
        loaded.profile_name(),
        profile.summary()
    );
    eprintln!("preflight OK: {}", posture.describe());
    eprintln!(
        "Planned negative set: raw IP:port unreachable; no second route, interface, or peer can be \
         added from inside; a non-internal network is refused with a clear message; host secrets \
         unreadable; host paths read-only; unlisted destinations unreachable; container control \
         sockets absent; no escape; concurrent jails isolated; resource limits enforced. Positive \
         control: one allowlisted destination answers. See docs/cli.md."
    );
    Ok(EXIT_NOT_IMPLEMENTED)
}

/// The class config this profile names, if it has one, with the classes it asks
/// for checked against it. `None` for `mode = "none"`.
fn resolve_class(
    profile: &Profile,
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<Option<(PathBuf, ClassConfig)>, String> {
    if profile.network.mode != NetworkMode::Allowlist {
        return Ok(None);
    }
    let Some(class) = profile.network.class.as_deref() else {
        return Err(
            "profile names no egress class; profile validation should have refused it".to_string(),
        );
    };
    let (path, config) = class::load(class, &class::config_search_dirs(env, cwd))?;
    let outside = run::egress_outside_class(profile, &config);
    if !outside.is_empty() {
        return Err(format!(
            "refusing to run: the profile asks for destinations its egress class does not permit\n{}",
            outside
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    Ok(Some((path, config)))
}

/// Everything the class side needs before the jail exists: the class network,
/// the class gateway on it, and the gateway's address.
fn start_class_side(
    profile: &Profile,
    profile_name: &str,
    run_id: u32,
    env: &BTreeMap<String, String>,
    cwd: &Path,
    cleanup: &mut RunCleanup,
) -> Result<(String, String), String> {
    let (config_path, config) = resolve_class(profile, env, cwd)?
        .ok_or_else(|| "class side requested for a profile with no egress class".to_string())?;

    let image = env
        .get("AGENTJAIL_GATEWAY_IMAGE")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "localhost/agentjail-gateway:1".to_string());
    if !podman::image_exists(&image) {
        return Err(format!(
            "gateway image {image:?} is not present; build it with \
             scripts/build-gateway-image.sh (or set AGENTJAIL_GATEWAY_IMAGE)"
        ));
    }
    let egress_network = egress_network(env)?;

    // Backstop for SIGKILL and host crashes: remove only what is provably dead,
    // i.e. resources of this profile whose owning pid is gone.
    prune_dead_resources(profile_name, run_id);

    let network = lifecycle::network_name(profile_name, run_id, &config.class);
    podman::network_create(&network)?;
    cleanup.network = Some(network.clone());

    // The invariant, now on the network this run created rather than one it was
    // told about: internal, has a subnet, or nothing starts.
    let posture = podman::verify_network(&network)?;
    eprintln!("agentjail: preflight OK: {}", posture.describe());

    let container = lifecycle::gateway_name(profile_name, run_id);
    let argv = run::gateway_args(&run::GatewayContext {
        container_name: container.clone(),
        image,
        class_config: config_path.to_string_lossy().into_owned(),
        network: network.clone(),
        egress_network,
        jail_id: format!("{profile_name}-{run_id}"),
        selinux: Path::new("/sys/fs/selinux/enforce").exists(),
    });
    podman::container_start(&argv)?;
    cleanup.container = Some(container.clone());

    let gateway_ip = wait_for_ip(&container, &network)?;
    eprintln!(
        "agentjail: egress class {:?}: gateway {container} at {gateway_ip}:{PROXY_PORT} on {network}, \
         {} allowlisted destination(s), audit on its own stream",
        config.class,
        config.allow.len()
    );
    Ok((network, gateway_ip))
}

/// The network the gateway uses for its own outbound leg. Never the jail's.
fn egress_network(env: &BTreeMap<String, String>) -> Result<String, String> {
    if let Some(name) = env
        .get("AGENTJAIL_EGRESS_NETWORK")
        .filter(|value| !value.is_empty())
    {
        return Ok(name.clone());
    }
    let names = podman::network_list()?;
    for candidate in ["podman", "bridge"] {
        if names.iter().any(|name| name == candidate) {
            return Ok(candidate.to_string());
        }
    }
    Err(
        "no default podman network to give the gateway its outbound leg; set \
         AGENTJAIL_EGRESS_NETWORK"
            .to_string(),
    )
}

/// Remove resources of this profile whose run is gone. Never by profile alone.
fn prune_dead_resources(profile_name: &str, run_id: u32) {
    if let Ok(names) = podman::container_list() {
        for name in lifecycle::stale_names(&names, profile_name, run_id, pid_alive) {
            let _ = podman::container_remove(&name);
        }
    }
    if let Ok(names) = podman::network_list() {
        for name in lifecycle::stale_names(&names, profile_name, run_id, pid_alive) {
            let _ = podman::network_remove(&name);
        }
    }
}

/// The gateway's address is read from podman once it is running; an address
/// that never appears fails the run before the jail starts.
fn wait_for_ip(container: &str, network: &str) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match podman::container_ip(container, network) {
            Ok(address) if !address.is_empty() => return Ok(address),
            Ok(_) | Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "gateway {container:?} has no address on {network:?} after 15s; the class network \
                 is empty of peers and the run is refused"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The outside half of the single-route invariant, shared with `doctor`.
///
/// Returns a line describing what was verified. When the profile names no
/// network, the launcher will create a dedicated internal one and must verify
/// it the same way before starting anything -- that creation path is not
/// implemented yet, so this returns the honest state instead of a claim.
fn preflight_network(profile: &Profile) -> Result<agentjail_core::network::NetworkPosture, String> {
    let Some(name) = &profile.network.name else {
        return Err(
            "refusing to launch: network.name is required; agentjail attaches to an existing \
             internal network and does not create one"
                .to_string(),
        );
    };
    podman::verify_network(name).map_err(|error| {
        format!(
            "refusing to launch: the network named by this profile does not satisfy the \
             single-route invariant.\n  {error}"
        )
    })
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
