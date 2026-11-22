//! `agentjail-gateway`: the jail's only route out.
//!
//! Intended shape (documented in `docs/cli.md`): one process that answers DNS
//! for allowlisted names only and accepts CONNECT for allowlisted
//! `host:port` destinations, on an internal network where it is the sole
//! reachable peer.
//!
//! Status in increment 1: the allowlist is parsed, typed, and validated from a
//! profile, and `--check` prints exactly what the proxy will permit. The proxy
//! itself (listener, CONNECT handling, DNS pinning) is **not implemented**, and
//! this binary says so and exits 3. No half-finished proxy ships: a proxy that
//! holds the security property is the whole point, and an incomplete one would
//! be worse than none.

use std::path::PathBuf;
use std::process::ExitCode;

use agentjail_core::profile::{parse_and_validate, DnsStrategy, NetworkMode, Protocol};
use clap::Parser;

const EXIT_OK: u8 = 0;
const EXIT_FAILURE: u8 = 1;
const EXIT_NOT_IMPLEMENTED: u8 = 3;

#[derive(Parser)]
#[command(
    name = "agentjail-gateway",
    version,
    about = "Egress gateway for an agentjail jail: DNS pinning and CONNECT allowlist."
)]
struct Cli {
    /// Profile whose network allowlist this gateway enforces.
    #[arg(long, value_name = "PATH")]
    profile: PathBuf,

    /// Validate the allowlist and print it; start no listener.
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
    let text = std::fs::read_to_string(&cli.profile)
        .map_err(|error| format!("cannot read profile {}: {error}", cli.profile.display()))?;
    let profile = parse_and_validate(&text).map_err(|errors| {
        format!(
            "profile {} is invalid:\n{}",
            cli.profile.display(),
            errors
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;

    if profile.network.mode != NetworkMode::Allowlist {
        return Err(format!(
            "profile {:?} has network.mode = {:?}; a gateway only exists for \"allowlist\"",
            cli.profile.display(),
            profile.network.mode.as_str()
        ));
    }

    let destinations = profile
        .network
        .egress
        .iter()
        .map(|entry| {
            format!(
                "{}:{}/{}",
                entry.host,
                entry.port,
                match entry.protocol {
                    Protocol::Tls => "tls",
                    Protocol::Http => "http",
                    Protocol::Tcp => "tcp",
                }
            )
        })
        .collect::<Vec<_>>();

    println!("allowlist ({} destination(s)):", destinations.len());
    for destination in &destinations {
        println!("  {destination}");
    }
    println!(
        "dns strategy: {}",
        match profile.network.dns {
            DnsStrategy::None => "none",
            DnsStrategy::Gateway => "gateway (allowlisted names only)",
            DnsStrategy::Pinned => "pinned (static entries, no recursive resolver)",
        }
    );
    println!("everything not listed here must be refused by the gateway, and there is no other route out");

    if cli.check {
        return Ok(EXIT_OK);
    }

    eprintln!(
        "agentjail-gateway: not implemented: the DNS and CONNECT proxy is not implemented in this \
         increment. Until it is, an allowlist profile is a description of intent, not a live control."
    );
    Ok(EXIT_NOT_IMPLEMENTED)
}
