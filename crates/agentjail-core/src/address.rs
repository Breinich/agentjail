//! Which addresses an allowlisted name is allowed to resolve to.
//!
//! An allowlist of names is only as good as the answer a resolver gives for
//! them. If `api.example.com` can be rebound to `127.0.0.1`, to the metadata
//! address, or to a LAN host, then the gateway is a proxy for internal space
//! and the class allowlist says nothing about where the bytes went. So the
//! gateway checks **every** address a name resolves to before it connects to
//! any of them, and the range that blocked an answer is named in the audit
//! line.
//!
//! `AddressPolicy` is per class because the answer differs by class: `model`
//! and `external` reach the public internet and nothing else, while `internal`
//! exists to reach named LAN services and therefore has to permit RFC1918 and
//! IPv6 ULA. Nothing relaxes loopback, link-local, CGNAT, multicast,
//! unspecified, broadcast, the IPv4-mapped / NAT64 / 6to4 spellings of an IPv4
//! address, or the martian ranges: those are never a service an allowlist
//! meant to name.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The ranges an answer must not fall in, and the name each is logged by.
///
/// The name is part of the audit format (`reason=blocked-<range>`), so it is
/// stable and short rather than a prose sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    /// `127.0.0.0/8`, `::1/128`.
    Loopback,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// RFC1918 and the IPv6 equivalent, ULA `fc00::/7`.
    Private,
    /// `100.64.0.0/10` (carrier-grade NAT).
    Cgnat,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `0.0.0.0/8` and `::/128`: "this host", never a destination.
    Unspecified,
    /// `255.255.255.255/32`.
    Broadcast,
    /// `240.0.0.0/4` except broadcast.
    Reserved,
    /// `::ffff:0:0/96`. An IPv4 address wearing an IPv6 spelling; a check that
    /// only looks at native v4 ranges walks straight past it.
    Ipv4Mapped,
    /// `64:ff9b::/96` and `64:ff9b:1::/48`: NAT64, which maps back to IPv4.
    Nat64,
    /// `2002::/16`: 6to4, which embeds an IPv4 address in the prefix.
    SixToFour,
    /// `2001::/32`: Teredo, which also carries an IPv4 address.
    Teredo,
}

impl Range {
    pub fn name(self) -> &'static str {
        match self {
            Range::Loopback => "loopback",
            Range::LinkLocal => "link-local",
            Range::Private => "private",
            Range::Cgnat => "cgnat",
            Range::Multicast => "multicast",
            Range::Unspecified => "unspecified",
            Range::Broadcast => "broadcast",
            Range::Reserved => "reserved",
            Range::Ipv4Mapped => "ipv4-mapped",
            Range::Nat64 => "nat64",
            Range::SixToFour => "six-to-four",
            Range::Teredo => "teredo",
        }
    }
}

/// The range `address` falls in, or `None` for a globally routable address.
pub fn blocked_range(address: IpAddr) -> Option<Range> {
    match address {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => blocked_v6(v6),
    }
}

fn blocked_v4(address: Ipv4Addr) -> Option<Range> {
    let octets = address.octets();
    match octets {
        [0, ..] => Some(Range::Unspecified),
        [127, ..] => Some(Range::Loopback),
        [169, 254, ..] => Some(Range::LinkLocal),
        [10, ..] => Some(Range::Private),
        [172, 16..=31, ..] => Some(Range::Private),
        [192, 168, ..] => Some(Range::Private),
        [100, 64..=127, ..] => Some(Range::Cgnat),
        [224..=239, ..] => Some(Range::Multicast),
        [255, 255, 255, 255] => Some(Range::Broadcast),
        [240..=255, ..] => Some(Range::Reserved),
        _ => None,
    }
}

fn blocked_v6(address: Ipv6Addr) -> Option<Range> {
    if let Some(mapped) = address.to_ipv4_mapped() {
        // Checked before anything else: podman and getaddrinfo can hand back
        // this spelling, and the native-v4 checks below would not see it.
        let _ = mapped;
        return Some(Range::Ipv4Mapped);
    }
    let segments = address.segments();
    if address.is_unspecified() {
        return Some(Range::Unspecified);
    }
    if address.is_loopback() {
        return Some(Range::Loopback);
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Some(Range::LinkLocal);
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Some(Range::Private); // ULA, the v6 equivalent of RFC1918
    }
    if segments[0] & 0xff00 == 0xff00 {
        return Some(Range::Multicast);
    }
    if segments[0] == 0x0064 && segments[1] == 0xff9b {
        return Some(Range::Nat64); // 64:ff9b::/96 and 64:ff9b:1::/48
    }
    if segments[0] == 0x2002 {
        return Some(Range::SixToFour);
    }
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return Some(Range::Teredo);
    }
    None
}

/// What a class is allowed to reach by address.
///
/// `Public` is the default and the strictest: an answer must be globally
/// routable. `Lan` additionally permits RFC1918 and ULA, for the `internal`
/// class. `Loopback` additionally permits loopback, and exists only so the
/// end-to-end tests can own a fixture on the machine that runs them; no
/// committed class uses it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressPolicy {
    #[default]
    Public,
    Lan,
    Loopback,
}

impl AddressPolicy {
    /// `Ok` when the class may connect to `address`, else the blocking range.
    pub fn permits(self, address: IpAddr) -> Result<(), Range> {
        let Some(range) = blocked_range(address) else {
            return Ok(());
        };
        let permitted = match range {
            Range::Private => self != AddressPolicy::Public,
            Range::Loopback => self == AddressPolicy::Loopback,
            _ => false,
        };
        if permitted {
            Ok(())
        } else {
            Err(range)
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AddressPolicy::Public => "public",
            AddressPolicy::Lan => "lan",
            AddressPolicy::Loopback => "loopback",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    fn range(text: &str) -> Option<&'static str> {
        blocked_range(addr(text)).map(Range::name)
    }

    #[test]
    fn every_range_in_the_spec_is_named() {
        for (address, expected) in [
            ("127.0.0.1", "loopback"),
            ("127.255.255.254", "loopback"),
            ("169.254.169.254", "link-local"),
            ("10.0.0.1", "private"),
            ("172.16.0.1", "private"),
            ("172.31.255.255", "private"),
            ("192.168.1.1", "private"),
            ("100.64.0.1", "cgnat"),
            ("100.127.255.255", "cgnat"),
            ("224.0.0.1", "multicast"),
            ("239.255.255.255", "multicast"),
            ("0.0.0.0", "unspecified"),
            ("0.1.2.3", "unspecified"),
            ("255.255.255.255", "broadcast"),
            ("240.0.0.1", "reserved"),
            ("::1", "loopback"),
            ("fe80::1", "link-local"),
            ("fd00::1", "private"),
            ("fc00::1", "private"),
            ("ff02::1", "multicast"),
            ("::", "unspecified"),
            ("::ffff:127.0.0.1", "ipv4-mapped"),
            ("::ffff:169.254.169.254", "ipv4-mapped"),
            ("::ffff:10.0.0.1", "ipv4-mapped"),
            ("::ffff:8.8.8.8", "ipv4-mapped"),
            ("64:ff9b::7f00:1", "nat64"),
            ("2002:7f00:1::1", "six-to-four"),
            ("2001::1", "teredo"),
        ] {
            assert_eq!(range(address), Some(expected), "{address}");
        }
    }

    #[test]
    fn a_public_address_is_not_blocked() {
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "2001:db8::1"] {
            assert_eq!(range(address), None, "{address}");
        }
    }

    #[test]
    fn the_public_policy_permits_only_global_answers() {
        let policy = AddressPolicy::Public;
        assert!(policy.permits(addr("1.1.1.1")).is_ok());
        assert!(policy.permits(addr("2606:4700::1111")).is_ok());
        for (address, expected) in [
            ("127.0.0.1", Range::Loopback),
            ("10.0.0.1", Range::Private),
            ("100.64.0.1", Range::Cgnat),
            ("169.254.169.254", Range::LinkLocal),
            ("fd00::1", Range::Private),
            ("::1", Range::Loopback),
            ("::ffff:127.0.0.1", Range::Ipv4Mapped),
        ] {
            assert_eq!(policy.permits(addr(address)), Err(expected), "{address}");
        }
    }

    #[test]
    fn the_lan_policy_relaxes_only_private_space() {
        let policy = AddressPolicy::Lan;
        assert!(policy.permits(addr("10.0.0.1")).is_ok());
        assert!(policy.permits(addr("192.168.1.10")).is_ok());
        assert!(policy.permits(addr("fd00::1")).is_ok());
        assert!(policy.permits(addr("1.1.1.1")).is_ok());
        // Everything else stays blocked, including the mapped spelling of a
        // private address: the relaxation is for the address itself, not for a
        // spelling of it.
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(policy.permits(addr(address)).is_err(), "{address}");
        }
    }

    #[test]
    fn the_loopback_policy_is_the_test_fixture_relaxation_only() {
        let policy = AddressPolicy::Loopback;
        assert!(policy.permits(addr("127.0.0.1")).is_ok());
        assert!(policy.permits(addr("::1")).is_ok());
        assert!(policy.permits(addr("10.0.0.1")).is_ok());
        assert!(policy.permits(addr("1.1.1.1")).is_ok());
        assert!(policy.permits(addr("fe80::1")).is_err());
        assert!(policy.permits(addr("::ffff:127.0.0.1")).is_err());
    }
}
