//! The egress leg: the only place in the gateway that creates an outbound
//! socket.
//!
//! Order matters and it is deliberate:
//!
//! 1. the class allowlist is re-checked here, not only in the CONNECT half, so
//!    a bug that reaches this function with some other destination still gets a
//!    refusal;
//! 2. the name is resolved **once**;
//! 3. **every** returned address is checked against the class's address policy;
//!    one blocked answer refuses the whole name, so a poisoned or rebound answer
//!    cannot be "tried until one works";
//! 4. the connection goes to a checked address, with no re-resolution and no
//!    fallback to an address that was never checked.
//!
//! Steps 2-4 are what turn "the allowlist is a name list" into "the allowlist
//! is a name, an address set, and a decision".

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use agentjail_core::address::{AddressPolicy, Range};
use agentjail_core::class::ClassConfig;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an egress attempt was refused, in the shape the audit line prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// Not on the class allowlist (the second, independent check at the leg).
    NotInClass,
    /// The name resolved to nothing usable.
    ResolveFailed,
    /// An answer fell in a blocked range; carries the address and the range.
    Blocked { address: IpAddr, range: Range },
    /// The name resolved, every answer was checked, and none would connect.
    ConnectFailed,
}

impl Denied {
    /// The `reason=` value. A blocked answer names the range.
    pub fn reason(&self) -> String {
        match self {
            // The proxy's own check refuses this first; if the leg sees it, the
            // vocabulary stays the same so the log has one reason per decision.
            Denied::NotInClass => "not-in-class".to_string(),
            Denied::ResolveFailed => "resolve-failed".to_string(),
            Denied::Blocked { range, .. } => format!("blocked-{}", range.name()),
            Denied::ConnectFailed => "connect-failed".to_string(),
        }
    }

    /// The address the refusal is about, for `address=` on the audit line.
    pub fn address(&self) -> Option<IpAddr> {
        match self {
            Denied::Blocked { address, .. } => Some(*address),
            _ => None,
        }
    }
}

/// A checked, pinned outbound connection.
#[derive(Debug)]
pub struct Dialed {
    pub stream: TcpStream,
    /// The whole answer, in resolver order, for the audit line.
    pub resolved: Vec<SocketAddr>,
    /// The address that was actually connected to.
    pub pinned: SocketAddr,
}

impl Dialed {
    /// `a,b,c` in resolver order, for `resolved=`.
    pub fn resolved_csv(&self) -> String {
        self.resolved
            .iter()
            .map(|address| address.ip().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The pure half of the decision: every address is checked, and the first
/// permitted one is what will be dialled.
///
/// Exposed so the range table can be tested without a resolver: a test cannot
/// make a system resolver answer `10.0.0.1` for a name, and the decision is the
/// part that must be right.
pub fn pin(resolved: &[SocketAddr], policy: AddressPolicy) -> Result<SocketAddr, (IpAddr, Range)> {
    let mut checked = Vec::with_capacity(resolved.len());
    for address in resolved {
        match policy.permits(address.ip()) {
            Ok(()) => checked.push(*address),
            Err(range) => return Err((address.ip(), range)),
        }
    }
    checked
        .first()
        .copied()
        .ok_or_else(|| (IpAddr::from([0, 0, 0, 0]), Range::Unspecified))
}

/// `host:port` resolved once, checked, and connected.
pub fn dial(config: &ClassConfig, host: &str, port: u16) -> Result<Dialed, Denied> {
    if !config.allows(host, port) {
        return Err(Denied::NotInClass);
    }
    let resolved = resolve(host, port).map_err(|_| Denied::ResolveFailed)?;
    if resolved.is_empty() {
        return Err(Denied::ResolveFailed);
    }
    let _pinned = pin(&resolved, config.address_policy)
        .map_err(|(address, range)| Denied::Blocked { address, range })?;

    // Every address in `resolved` was checked just above, so trying them in
    // resolver order is not a fallback to something unchecked: it is the same
    // answer set, and a dual-stack name whose v6 side has no route still works.
    for address in &resolved {
        if let Ok(stream) = TcpStream::connect_timeout(address, CONNECT_TIMEOUT) {
            return Ok(Dialed {
                stream,
                pinned: *address,
                resolved,
            });
        }
    }
    Err(Denied::ConnectFailed)
}

fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let mut addresses: Vec<SocketAddr> = Vec::new();
    for address in (host, port).to_socket_addrs()? {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn socket(text: &str) -> SocketAddr {
        SocketAddr::new(text.parse().expect("test address"), 443)
    }

    fn config(policy: &str) -> ClassConfig {
        ClassConfig::parse(&format!(
            "class = \"model\"\nlisten = \"127.0.0.1:0\"\ndns = \"127.0.0.1:0\"\n\
             max_bytes = 1024\nmax_connections = 2\naddress_policy = \"{policy}\"\n\
             allow = [\"api.example.com:443\"]\n"
        ))
        .expect("valid class config")
    }

    #[test]
    fn each_blocked_range_is_refused_with_the_range_named() {
        for (address, range) in [
            ("127.0.0.1", Range::Loopback),
            ("169.254.169.254", Range::LinkLocal),
            ("10.0.0.1", Range::Private),
            ("100.64.0.1", Range::Cgnat),
            ("::1", Range::Loopback),
            ("fd00::1", Range::Private),
            ("::ffff:127.0.0.1", Range::Ipv4Mapped),
            ("::ffff:169.254.169.254", Range::Ipv4Mapped),
        ] {
            let error = pin(&[socket(address)], AddressPolicy::Public).expect_err(address);
            assert_eq!(error.1, range, "{address}");
            let denied = Denied::Blocked {
                address: error.0,
                range: error.1,
            };
            assert!(
                denied.reason().starts_with("blocked-"),
                "{}",
                denied.reason()
            );
            assert!(denied.reason().contains(range.name()));
        }
        // The mapped spelling names the mapped range, not the v4 one it hides.
        assert_eq!(in_range("::ffff:169.254.169.254"), "blocked-ipv4-mapped");
        assert_eq!(in_range("::ffff:127.0.0.1"), "blocked-ipv4-mapped");
    }

    fn in_range(address: &str) -> String {
        let error = pin(&[socket(address)], AddressPolicy::Public).expect_err(address);
        Denied::Blocked {
            address: error.0,
            range: error.1,
        }
        .reason()
    }

    #[test]
    fn one_blocked_answer_refuses_the_whole_name() {
        // A public answer first, a blocked one second: the name is refused
        // rather than "the public one works, so try it".
        let answer = [socket("93.184.216.34"), socket("10.0.0.1")];
        assert_eq!(
            pin(&answer, AddressPolicy::Public).expect_err("mixed answer"),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), Range::Private)
        );
        // And the other order, so it is not an accident of ordering.
        let answer = [socket("10.0.0.1"), socket("93.184.216.34")];
        assert!(pin(&answer, AddressPolicy::Public).is_err());
    }

    #[test]
    fn a_public_answer_is_pinned_to_the_first_entry() {
        let answer = [socket("93.184.216.34"), socket("93.184.216.35")];
        assert_eq!(
            pin(&answer, AddressPolicy::Public).expect("public"),
            socket("93.184.216.34")
        );
        assert!(pin(&[], AddressPolicy::Public).is_err());
    }

    #[test]
    fn the_lan_policy_permits_a_private_answer_and_nothing_looser() {
        assert_eq!(
            pin(&[socket("10.0.0.5")], AddressPolicy::Lan).expect("lan"),
            socket("10.0.0.5")
        );
        assert_eq!(
            pin(&[socket("127.0.0.1")], AddressPolicy::Lan).expect_err("loopback"),
            (IpAddr::V4(Ipv4Addr::LOCALHOST), Range::Loopback)
        );
    }

    #[test]
    fn the_leg_refuses_a_destination_the_class_does_not_list() {
        // The second check at the egress leg: no resolver, no socket, a refusal.
        let config = config("public");
        assert_eq!(
            dial(&config, "evil.example.com", 443).expect_err("not listed"),
            Denied::NotInClass
        );
    }
}
