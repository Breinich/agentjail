//! `agentjail`: the CLI.
//!
//! Profile validation, display, host diagnostics, the outside half of the
//! single-route invariant, the run path, and the selftest live here. The
//! selftest runs the same probes as a plain host process (`--baseline`) and
//! inside a real jail, so the baseline proves each negative is real.

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

mod audit;
mod probe;
mod selftest;

const EXIT_OK: u8 = 0;
const EXIT_FAILURE: u8 = 1;

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

Exit codes: 0 success, 1 failure, 2 usage error; `run` passes the agent's own
exit code through.";

const SELFTEST_CONTRACT: &str = "\
Selftest contract: one harness, two executors.

  agentjail selftest            jail every case in a real jail
  agentjail selftest --baseline run the same probes as a plain host process

The assertion functions are shared. Baseline mode proves the hazard is real:
every negative MUST hold without the jail, or the assertion is weak. Jailed mode
proves the jail denies every negative and that one allowlisted destination
answers through the proxy with its audit line.

Cases: host secret file/environment; destination outside the allowlist;
raw IP:port; route/interface/peer changes; two-jail isolation; memory, pids
and nofile limits; NET_ADMIN; positive control through the proxy; and the
documented `agentjail audit --class` view after the run, when the jail and
gateway containers are gone.

Baseline exit 0 means every negative correctly held (the hazard was observed),
non-zero names a negative that was already denied without a jail. Jailed exit 0
means every negative was denied and the positive control answered, non-zero
names the case that did not. A case that cannot run in baseline mode is printed
as SKIPPED-BASELINE with the reason, never silently omitted.

The optional profile selects the image, workdir and home; the selftest generates
its own network, limits and agent command. --json prints one object per case.";

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
    Selftest(SelftestArgs),
    /// Internal probe executed by the selftest in either executor. Not public API.
    #[command(name = "__probe", hide = true)]
    Probe(Box<ProbeArgs>),
    /// Read the audit and DNS streams back: one merged, filtered view for an incident.
    #[command(after_long_help = AUDIT_CONTRACT)]
    Audit(AuditArgs),
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
struct SelftestArgs {
    /// Profile name or path to a .toml profile (selects image, workdir and home).
    profile: Option<String>,
    /// Run the probes as a plain host process: no podman, no jail.
    #[arg(long)]
    baseline: bool,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct ProbeArgs {
    #[arg(long, default_value = "main")]
    case: String,
    #[arg(long, default_value = "jailed")]
    mode: String,
    #[arg(long, default_value = "")]
    host_secret: String,
    #[arg(long, default_value = "AGENTJAIL_SELFTEST_SECRET")]
    env_secret: String,
    #[arg(long, default_value = "")]
    target_host: String,
    #[arg(long, default_value = "")]
    target_ip: String,
    #[arg(long, default_value_t = 0)]
    allowed_port: u16,
    #[arg(long, default_value_t = 0)]
    denied_port: u16,
    #[arg(long, default_value_t = 0)]
    memory_limit: u64,
    #[arg(long, default_value_t = 0)]
    nofile_limit: u64,
    #[arg(long, default_value_t = 0)]
    pids_limit: u32,
    #[arg(long, default_value = "current")]
    netns: String,
    #[arg(long, default_value = "owner")]
    role: String,
    #[arg(long, default_value = "")]
    token: String,
    #[arg(long, default_value = "")]
    peer_token: String,
    #[arg(long, default_value_t = 0)]
    hold_ms: u64,
    #[arg(long, default_value_t = 0)]
    alloc_bytes: u64,
}

const AUDIT_CONTRACT: &str = "\
The two gateway streams, read back in one view.

  stream=audit  one line per connection decision: allow, allow-close, deny
  stream=dns    one line per query: answer, nxdomain, refused, drop

Both are `key=value` lines written by the gateway. With no path given, the
per-run files of --class are read from the state directory `agentjail doctor`
reports (default ~/.local/state/agentjail): audit/<class>/<jail-id>.audit.log
and audit/<class>/<jail-id>.dns.log. They outlive the gateway container, so the
command works after a run has finished. Files are read newest run first and the
merged view is in time order; `run` keeps the newest 20 runs per class and
prunes older ones at start. If no per-run files exist, the streams configured
in the class config are read instead. `--audit -` reads stdin, which is how a
captured `podman logs` is inspected.";

#[derive(clap::Args)]
struct AuditArgs {
    /// Egress class: whose per-run files (or configured streams) to read, and
    /// the class to filter on.
    #[arg(long, value_name = "CLASS")]
    class: Option<String>,
    /// Operator class directory, with --class-digest: where <class>.toml lives.
    #[arg(long, value_name = "DIR")]
    class_dir: Option<String>,
    /// sha256:<64 hex> pin for the class file --class-dir names.
    #[arg(long, value_name = "DIGEST")]
    class_digest: Option<String>,
    /// Audit stream: a file, or `-` for stdin.
    #[arg(long, value_name = "PATH")]
    audit: Option<String>,
    /// DNS stream: a file.
    #[arg(long, value_name = "PATH")]
    dns: Option<String>,
    /// Only lines whose jail id is exactly this.
    #[arg(long, value_name = "ID")]
    jail: Option<String>,
    /// Only lines with this decision (allow, allow-close, deny, answer, nxdomain, ...).
    #[arg(long, value_name = "DECISION")]
    decision: Option<String>,
    /// Only one stream.
    #[arg(long, value_name = "audit|dns")]
    stream: Option<String>,
    /// Only the last N matching lines.
    #[arg(long, value_name = "N")]
    tail: Option<usize>,
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
        Command::Audit(args) => audit_command(args, env, &cwd),
        Command::Selftest(args) => selftest_command(args, &cli.profile_dirs, env, &cwd),
        Command::Probe(args) => {
            let _ = args.mode;
            let args = *args;
            let output = probe::run(&probe::ProbeArgs {
                case: args.case,
                host_secret: args.host_secret,
                env_secret: args.env_secret,
                target_host: args.target_host,
                target_ip: args.target_ip,
                allowed_port: args.allowed_port,
                denied_port: args.denied_port,
                memory_limit: args.memory_limit,
                nofile_limit: args.nofile_limit,
                pids_limit: args.pids_limit,
                netns: args.netns,
                role: args.role,
                token: args.token,
                peer_token: args.peer_token,
                hold_ms: args.hold_ms,
                alloc_bytes: args.alloc_bytes,
            });
            println!(
                "{}",
                serde_json::to_string(&output).unwrap_or_else(|_| "{}".to_string())
            );
            Ok(EXIT_OK)
        }
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
    if let Some((path, class)) = resolve_class(&loaded.profile, cwd)? {
        println!(
            "   egress class {:?} from {}: grant of {} destination(s) out of {} the class allows, deny by default",
            class.class,
            path.display(),
            run::effective_grant(&loaded.profile, &class).len(),
            class.class_allow.len()
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
    let mut document = serde_json::json!({
        "name": loaded.profile_name(),
        "source": loaded.path.display().to_string(),
        "profile": loaded.profile.effective_json(),
    });
    // What the jail actually gets, not what the file says: the intersection of
    // the class allowlist and this profile's `network.egress`.
    let (class, grant) = match resolve_class(&loaded.profile, cwd)? {
        Some((_, class)) => {
            let grant = run::effective_grant(&loaded.profile, &class);
            (Some(class), grant)
        }
        None => (None, Vec::new()),
    };
    document["egress"] = serde_json::json!({
        "class": class.as_ref().map(|class| class.class.clone()),
        "grant": grant
            .iter()
            .map(|entry| format!("{}:{}", entry.host, entry.port))
            .collect::<Vec<_>>(),
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

/// `agentjail audit`: read both gateway streams back.
///
/// Paths come from the flags, or from the class config of `--class`. A stream
/// configured as `-` went to podman's log rather than a file, so there is
/// nothing here to read: say so instead of printing an empty result that looks
/// like "no activity".
fn audit_command(
    args: AuditArgs,
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<u8, String> {
    let streams = match args.stream.as_deref() {
        None => audit::Streams::Both,
        Some("audit") => audit::Streams::Audit,
        Some("dns") => audit::Streams::Dns,
        Some(other) => {
            return Err(format!(
                "--stream {other:?} is not a stream; use audit, dns, or omit it"
            ))
        }
    };

    let (mut audit_path, mut dns_path) = (args.audit.clone(), args.dns.clone());
    let mut sources: Vec<(&'static str, String)> = Vec::new();

    if audit_path.is_none() && dns_path.is_none() {
        let class = args.class.as_deref().ok_or_else(|| {
            "give --class <class> to read its per-run files, or --audit/--dns <path>".to_string()
        })?;
        let loaded = match (args.class_dir.as_deref(), args.class_digest.as_deref()) {
            (Some(dir), Some(digest)) => class::load_pinned(Path::new(dir), class, digest),
            (None, None) => class::load(class, &class::config_search_dirs(cwd)),
            _ => Err(
                "--class-dir and --class-digest go together: a directory without a digest is policy that can change under the command that reads it"
                    .to_string(),
            ),
        };
        let (path, config) = loaded
            .map_err(|error| format!("cannot read the streams of class {class:?}: {error}"))?;
        let run_dir = run::audit_dir(&paths::state_dir(env), class);
        let files = audit::run_files(&run_dir);
        if files.is_empty() {
            eprintln!(
                "agentjail: no per-run files under {}; reading the streams configured in {} \
                 (audit_log={:?}, dns_log={:?})",
                run_dir.display(),
                path.display(),
                config.audit_log,
                config.dns_log
            );
            audit_path = Some(config.audit_log);
            dns_path = Some(config.dns_log);
        } else {
            eprintln!(
                "agentjail: {} file(s) from {} (newest run first; the newest {} runs per class \
                 are kept)",
                files.len(),
                run_dir.display(),
                run::AUDIT_RETAIN_RUNS
            );
            for (stream, file) in files {
                let text = std::fs::read_to_string(&file).map_err(|error| {
                    format!(
                        "cannot read the {stream} stream {}: {error}",
                        file.display()
                    )
                })?;
                sources.push((stream, text));
            }
        }
    }

    for (name, path) in [(audit::AUDIT, audit_path), (audit::DNS, dns_path)] {
        let Some(path) = path else { continue };
        if path == "-" {
            if name == audit::AUDIT {
                // `podman logs <gateway> | agentjail audit --audit -`: the
                // captured stream is stdin, and it is the audit stream.
                let mut text = String::new();
                use std::io::Read;
                std::io::stdin()
                    .read_to_string(&mut text)
                    .map_err(|error| format!("cannot read the audit stream from stdin: {error}"))?;
                sources.push((audit::AUDIT, text));
            } else {
                eprintln!(
                    "agentjail: the {name} stream is configured as \"-\" (podman's log, not a \
                     file); capture it with `podman logs <gateway>` or set a path in the class config"
                );
            }
            continue;
        }
        if path == "stderr" || path == "stdout" {
            eprintln!(
                "agentjail: the {name} stream is configured as {path:?}, which is a pipe; \
                 capture it to a file to read it back"
            );
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read the {name} stream {path:?}: {error}"))?;
        sources.push((name, text));
    }

    let filter = audit::Filter {
        jail: args.jail,
        class: args.class,
        decision: args.decision,
        streams: Some(streams),
        tail: args.tail,
    };
    let borrowed: Vec<(&'static str, &str)> = sources
        .iter()
        .map(|(stream, text)| (*stream, text.as_str()))
        .collect();
    let lines = audit::view(&borrowed, &filter);
    for line in &lines {
        println!("{}", line.render());
    }
    eprintln!("agentjail: {} line(s)", lines.len());
    Ok(EXIT_OK)
}

/// Everything this run created, removed whenever the process stops: normal
/// exit, non-zero exit, forwarded signal, or panic. Container before networks,
/// because a network cannot be removed while a peer is attached to it, and
/// networks in reverse creation order.
#[derive(Default)]
struct RunCleanup {
    secrets: Vec<String>,
    container: Option<String>,
    networks: Vec<String>,
}

impl RunCleanup {
    fn is_empty(&self) -> bool {
        self.secrets.is_empty() && self.container.is_none() && self.networks.is_empty()
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
        for network in &self.networks {
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
        for network in self.networks.iter().rev() {
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
    args: SelftestArgs,
    extra_dirs: &[PathBuf],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<u8, String> {
    // A profile is optional so the cheap baseline mode works with no fixture at
    // all. When one is given it selects the image, workdir and home; the
    // selftest generates its own network, limits and agent command so both modes
    // run the same cases.
    let loaded = match &args.profile {
        Some(reference) => {
            let loaded = load_profile(reference, extra_dirs, env, cwd)?;
            run::run_blockers(&loaded.profile).map_err(|errors| {
                format!(
                    "refusing to selftest profile {}:\n{}",
                    loaded.path.display(),
                    errors
                        .iter()
                        .map(|error| format!("  - {error}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            })?;
            Some(loaded)
        }
        None => None,
    };
    let options = selftest::Options {
        baseline: args.baseline,
        json: args.json,
    };
    selftest::run(
        loaded.as_ref().map(|loaded| &loaded.profile),
        &options,
        env,
        cwd,
    )
}

/// The class config this profile names, if it has one, with the classes it asks
/// for checked against it. `None` for `mode = "none"`.
fn resolve_class(profile: &Profile, cwd: &Path) -> Result<Option<(PathBuf, ClassConfig)>, String> {
    if profile.network.mode != NetworkMode::Allowlist {
        return Ok(None);
    }
    let Some(class) = profile.network.class.as_deref() else {
        return Err(
            "profile names no egress class; profile validation should have refused it".to_string(),
        );
    };
    let loaded = match profile.network.class_dir.as_deref() {
        // Operator class: a directory the profile names, pinned by digest.
        Some(dir) => {
            let digest = profile.network.class_digest.as_deref().ok_or_else(|| {
                "network.class_dir without network.class_digest; profile validation should have refused it"
                    .to_string()
            })?;
            class::load_operator(dir, class, digest)?
        }
        None => class::load(class, &class::config_search_dirs(cwd))?,
    };
    let (path, config) = loaded;
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
    let (config_path, config) = resolve_class(profile, cwd)?
        .ok_or_else(|| "class side requested for a profile with no egress class".to_string())?;
    let grant = run::effective_grant(profile, &config);
    if grant.is_empty() {
        // Legitimate, and loud: a profile that asks for nothing gets nothing,
        // the same posture as `mode = "none"`.
        eprintln!("agentjail: egress grant is empty: this jail has no route out");
    }

    // Resolve the tag to an image ID now, and start the container by that ID.
    // The tag is what an operator builds; the ID is what runs, so a retag between
    // here and `podman run` cannot swap the process the jail talks to. The tag
    // itself is per workspace, so a second checkout building its own gateway
    // cannot retag this one's.
    let image_ref = run::gateway_image_reference(env, cwd)?;
    let image_id = podman::image_id(&image_ref)?;
    eprintln!("agentjail: gateway image {image_ref:?} is {image_id} (pinned by ID)");

    // Backstop for SIGKILL and host crashes: remove only what is provably dead,
    // i.e. resources of this profile whose owning pid is gone.
    prune_dead_resources(profile_name, run_id);

    let network = lifecycle::network_name(profile_name, run_id, &config.class);
    podman::network_create(&network)?;
    cleanup.networks.push(network.clone());

    // The invariant, now on the network this run created rather than one it was
    // told about: internal, has a subnet, IPv4 only, or nothing starts.
    let posture = podman::verify_network(&network)?;
    eprintln!("agentjail: preflight OK: {}", posture.describe());

    // The gateway's own outbound leg: its own network, created for this run, not
    // the host's shared default bridge. The jail never joins it.
    let egress_network = match env
        .get("AGENTJAIL_EGRESS_NETWORK")
        .filter(|value| !value.is_empty())
    {
        Some(name) => name.clone(),
        None => {
            let name = lifecycle::egress_network_name(profile_name, run_id);
            podman::egress_network_create(&name)?;
            cleanup.networks.push(name.clone());
            eprintln!("agentjail: gateway egress leg on its own network {name:?}");
            name
        }
    };

    let container = lifecycle::gateway_name(profile_name, run_id);
    let jail_id = format!("{profile_name}-{run_id}");
    let audit_dir = run::audit_dir(&paths::state_dir(env), &config.class);
    std::fs::create_dir_all(&audit_dir).map_err(|error| {
        format!(
            "cannot create the audit directory {}: {error}",
            audit_dir.display()
        )
    })?;
    let argv = run::gateway_args(&run::GatewayContext {
        container_name: container.clone(),
        image_id,
        class_config: config_path.to_string_lossy().into_owned(),
        grant: grant.clone(),
        network: network.clone(),
        egress_network,
        jail_id: jail_id.clone(),
        class: config.class.clone(),
        audit_dir: Some(audit_dir.to_string_lossy().into_owned()),
        selinux: Path::new("/sys/fs/selinux/enforce").exists(),
    });
    podman::container_start(&argv)?;
    cleanup.container = Some(container.clone());

    let gateway_ip = wait_for_ip(&container, &network)?;
    let pruned = run::prune_audit_runs(&audit_dir, run::AUDIT_RETAIN_RUNS, &jail_id);
    if !pruned.is_empty() {
        eprintln!(
            "agentjail: pruned {} audit file(s) from older runs in {}",
            pruned.len(),
            audit_dir.display()
        );
    }
    eprintln!(
        "agentjail: egress class {:?}: gateway {container} at {gateway_ip}:{PROXY_PORT} on {network}, \
         grant {} of {} class allowlisted destination(s), audit on its own stream",
        config.class,
        grant.len(),
        config.class_allow.len()
    );
    Ok((network, gateway_ip))
}

/// Remove resources whose run is gone.
///
/// Containers are pruned **by pid, across profiles**: the gateway is no longer
/// started with `--rm` (so a refusal can be read back), which means a killed run
/// leaves its gateway behind, and a profile nobody runs again would leave it
/// there indefinitely. Networks stay profile-scoped: a network name is what a
/// concurrent run of the same profile shares, and `agentjail-*` is also a shape a
/// user's own network can have.
fn prune_dead_resources(profile_name: &str, run_id: u32) {
    if let Ok(names) = podman::container_list() {
        for name in names
            .iter()
            .filter(|name| lifecycle::orphaned_container(name, run_id, pid_alive))
        {
            let _ = podman::container_remove(name);
        }
    }
    if let Ok(names) = podman::network_list() {
        for name in lifecycle::stale_names(&names, profile_name, run_id, pid_alive) {
            let _ = podman::network_remove(&name);
        }
    }
}

/// The gateway's address is read from podman once it is running.
///
/// A gateway that **exited** is a decision, not a slow start: it refused to start
/// (there is no `--grant`/`--class-only`, or the grant does not match the class),
/// so it is reported as that refusal, with its exit code and its last output.
/// Reporting it as "no address after 15s" would read as a slow container, and the
/// retry somebody then adds is exactly what removes the guarantee. "Still
/// starting" is only ever said about a container that is still alive.
fn wait_for_ip(container: &str, network: &str) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let state = podman::container_state(container);
        if let podman::ContainerState::Exited { code } = state {
            return Err(gateway_refused(container, code));
        }
        if state == podman::ContainerState::Running {
            match podman::container_ip(container, network) {
                Ok(address) if !address.is_empty() => return Ok(address),
                Ok(_) | Err(_) => {}
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(match state {
                podman::ContainerState::Running => format!(
                    "gateway {container:?} is running but has no address on {network:?} after 15s; \
                     the class network is empty of peers and the run is refused"
                ),
                _ => format!(
                    "gateway {container:?} is gone: no container by that name and no address on \
                     {network:?}; it was removed or never created, and the run is refused"
                ),
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The refusal a gateway left behind: what a security path's failure must look
/// like. The exit code says it decided, and its own last lines say why (the
/// gateway names the missing flag), so nobody has to guess or retry.
fn gateway_refused(container: &str, code: i32) -> String {
    let output = gateway_output(container);
    let output = if output.is_empty() {
        "  (it printed nothing)".to_string()
    } else {
        output
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "the egress gateway {container:?} refused to start and exited with code {code}, so the \
         jail was not started. A gateway that exits is a policy refusal, not a container that is \
         slow to come up. Its last output:\n{output}"
    )
}

/// Read the gateway's last lines, waiting briefly for them to exist.
///
/// The exit is visible to `podman inspect` a moment before the container's output
/// is flushed to its log, so a single read can return nothing -- and a refusal
/// published without its reason is the failure mode this whole path exists to
/// avoid. Bounded: one second, then report whatever there is.
fn gateway_output(container: &str) -> String {
    for attempt in 0..10 {
        let output = podman::container_output(container, 10);
        if !output.is_empty() {
            return output;
        }
        if attempt < 9 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    String::new()
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
