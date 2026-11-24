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
//! * **CONNECT**: permits only `host:port` pairs on that allowlist, relays the
//!   bytes, and logs the decision when it is made: `decision=allow` as soon as
//!   the connection exists, `decision=allow-close` with the byte counts when it
//!   ends. Denials are logged too: they are the security signal.
//!
//! Nothing is decided by an ACL inside a shared proxy: the class is the network
//! the jail is joined to, and the jail cannot change its own membership.

mod audit;
mod dns;
mod proxy;

use std::path::PathBuf;
use std::process::ExitCode;

use agentjail_core::class::ClassConfig;
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
    let config = ClassConfig::parse(&text).map_err(|errors| {
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

    if cli.check {
        println!("class: {}", config.class);
        println!("connect listener: {}", config.listen);
        println!(
            "dns listener: {} (policy: {:?})",
            config.dns, config.dns_policy
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
        return Ok(EXIT_OK);
    }

    let logs = audit::Logs::open(&config)?.with_jail(&cli.jail_id);
    eprintln!(
        "agentjail-gateway: class {} jail {}: dns on {}, connect on {}, deny by default",
        config.class, cli.jail_id, config.dns, config.listen
    );

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
