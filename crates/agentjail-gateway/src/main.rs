//! `agentjail-gateway`: the jail's only route out, one instance per egress
//! class.
//!
//! One binary, three instances. Each instance reads one committed class config
//! ([`agentjail_core::class`]) and runs two halves that share that single
//! allowlist:
//!
//! * **DNS** (UDP): answers `A` for names the class may reach, pinned to
//!   loopback, and NXDOMAINs everything else. Every query is logged on the DNS
//!   stream. Pinning to loopback is deliberate: a jail that resolves a name and
//!   then dials it directly reaches its own loopback and fails, instead of
//!   reaching the destination and bypassing the proxy.
//! * **CONNECT**: permits only `host:port` pairs on that allowlist, resolves the
//!   name once, checks **every** answer against the class address policy, and
//!   relays the bytes to a checked address. It logs the decision when it is
//!   made: `decision=allow` as soon as the connection exists (with the resolved
//!   set and the address dialled), `decision=allow-close` with the byte counts
//!   when it ends. Denials are logged too: they are the security signal.
//! * **Limits**: each jail has a byte budget (both directions) and a concurrent
//!   connection cap from its class config. Reaching either is a refusal in the
//!   same shape as a policy denial, with the counters that caused it.
//!
//! Nothing is decided by an ACL inside a shared proxy: the class is the network
//! the jail is joined to, and the jail cannot change its own membership.

mod audit;
mod dns;
mod egress;
mod proxy;

use std::path::PathBuf;
use std::process::ExitCode;

use agentjail_core::class::{AllowEntry, ClassConfig};
use clap::Parser;

const EXIT_OK: u8 = 0;
const EXIT_FAILURE: u8 = 1;

#[derive(Parser)]
#[command(
    name = "agentjail-gateway",
    version,
    about = "Egress gateway for one agentjail class: DNS pinning and a CONNECT allowlist."
)]
struct Cli {
    /// Class config this instance enforces (gateway/classes/<class>.toml).
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// Jail id written into every audit and DNS line. `run` passes its run id.
    #[arg(long, value_name = "ID", default_value = "-")]
    jail_id: String,

    /// Effective grant for this jail: comma-separated `host:port`, the
    /// intersection of the class allowlist and the profile's `network.egress`.
    /// Required for a jail run. An empty value is a grant of nothing (a jail
    /// with no route out) and is deliberately distinct from an absent flag.
    #[arg(long, value_name = "HOST:PORT,...")]
    grant: Option<String>,

    /// Class-level gateway: the class allowlist itself is the grant. For reading
    /// a class, not for a jail; `agentjail run` never passes it.
    #[arg(long)]
    class_only: bool,

    /// Write this run's two streams to `<DIR>/<jail-id>.audit.log` and
    /// `<DIR>/<jail-id>.dns.log` instead of the class config's destinations.
    #[arg(long, value_name = "DIR")]
    audit_dir: Option<PathBuf>,

    /// Validate the class config and print it; start no listener.
    #[arg(long)]
    check: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("agentjail-gateway: error: {message}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn run(cli: &Cli) -> Result<u8, String> {
    let text = std::fs::read_to_string(&cli.config)
        .map_err(|error| format!("cannot read class config {}: {error}", cli.config.display()))?;
    let mut config = ClassConfig::parse(&text).map_err(|errors| {
        format!(
            "class config {} is invalid:\n{}",
            cli.config.display(),
            errors
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;
    let config = select_grant(config, cli.grant.as_deref(), cli.class_only, cli.check)?;

    if let Some(dir) = &cli.audit_dir {
        // Per-run files, owned by `run`: the class config's `-` destinations go
        // to the container's own log and disappear with `--rm`.
        let file = |stream: &str| {
            dir.join(agentjail_core::run::audit_file_name(&cli.jail_id, stream))
                .to_string_lossy()
                .into_owned()
        };
        config.audit_log = file("audit");
        config.dns_log = file("dns");
    }

    if cli.check {
        println!("class: {}", config.class);
        println!("connect listener: {}", config.listen);
        println!(
            "dns listener: {} (policy: {:?})",
            config.dns, config.dns_policy
        );
        println!(
            "budget: {} byte(s) per jail, both directions; cap: {} concurrent connection(s)",
            config.max_bytes, config.max_connections
        );
        println!(
            "address policy: {} (which ranges an allowlisted name may resolve to)",
            config.address_policy.as_str()
        );
        println!(
            "audit stream: {}",
            describe_stream(&config.audit_log, "stdout")
        );
        println!("dns stream: {}", describe_stream(&config.dns_log, "stderr"));
        println!("allowlist ({} destination(s)):", config.allow.len());
        for entry in &config.allow {
            println!("  {}:{}", entry.host, entry.port);
        }
        if config.allow != config.class_allow {
            println!(
                "effective grant: {} of {} class destination(s)",
                config.allow.len(),
                config.class_allow.len()
            );
        }
        return Ok(EXIT_OK);
    }

    let logs = audit::Logs::open(&config)?.with_jail(&cli.jail_id);
    eprintln!(
        "agentjail-gateway: class {} jail {}: dns on {}, connect on {}, budget {} byte(s), cap {} connection(s), address policy {}, deny by default",
        config.class,
        cli.jail_id,
        config.dns,
        config.listen,
        config.max_bytes,
        config.max_connections,
        config.address_policy.as_str()
    );
    if config.allow != config.class_allow {
        // Printed, not implied: the operator reads what this jail gets.
        eprintln!(
            "agentjail-gateway: grant is {} of {} class destination(s){}",
            config.allow.len(),
            config.class_allow.len(),
            if config.allow.is_empty() {
                ": this jail has no route out"
            } else {
                ""
            }
        );
    }

    let dns_logs = logs.clone();
    let dns_config = config.clone();
    let dns = std::thread::spawn(move || dns::serve(&dns_config, &dns_logs));

    let proxy_result = proxy::serve(&config, &logs);
    let _ = dns.join();
    proxy_result?;
    Ok(EXIT_OK)
}

fn describe_stream(path: &str, default: &str) -> String {
    if path == "-" {
        default.to_string()
    } else {
        path.to_string()
    }
}

/// Decide what this gateway enforces. Both modes are explicit and neither is a
/// default:
///
/// * `--grant host:port,...` — a jail run. The empty string is a valid grant of
///   nothing, and is deliberately distinct from an absent flag;
/// * `--class-only` — the class allowlist itself, for a class-level gateway.
///
/// Absent both is a startup error rather than "enforce the whole class": a `run`
/// regression that stopped passing `--grant` would otherwise hand the jail every
/// destination its class lists, and look completely normal while doing it.
/// `--check` starts no listener and so enforces nothing; it needs neither.
fn select_grant(
    config: ClassConfig,
    grant: Option<&str>,
    class_only: bool,
    check: bool,
) -> Result<ClassConfig, String> {
    match (grant, class_only) {
        (Some(_), true) => Err(
            "--grant and --class-only are mutually exclusive: --grant is one jail's intersection \
             with the class allowlist, --class-only is the whole class allowlist"
                .to_string(),
        ),
        (Some(grant), false) => apply_grant(config, grant),
        (None, true) => Ok(config),
        (None, false) if check => Ok(config),
        (None, false) => Err(
            "neither --grant nor --class-only: a gateway started without either would enforce \
             the whole class allowlist, so a jail whose profile listed one destination would \
             reach every destination its class lists. Pass --grant <host:port,...> (an empty \
             value is a jail with no route out), or --class-only for a class-level gateway."
                .to_string(),
        ),
    }
}

/// Narrow the class to the grant `run` handed over.
///
/// A grant entry the class does not allow is refused instead of dropped: the
/// gateway would otherwise start with a policy nobody asked for, and the
/// difference between "the profile asked for less" and "the caller and the
/// class config disagree" would be invisible.
fn apply_grant(config: ClassConfig, grant: &str) -> Result<ClassConfig, String> {
    let mut entries = Vec::new();
    for entry in grant.split(',').map(str::trim) {
        if entry.is_empty() {
            continue;
        }
        let parsed =
            AllowEntry::parse(entry).map_err(|error| format!("--grant: {entry:?} {error}"))?;
        if !config.class_allows(&parsed.host, parsed.port) {
            return Err(format!(
                "--grant: {entry:?} is not in the {:?} class allowlist; the grant is the \
                 intersection of the class and the profile, so it cannot add a destination",
                config.class
            ));
        }
        entries.push(parsed);
    }
    Ok(config.with_grant(entries))
}
