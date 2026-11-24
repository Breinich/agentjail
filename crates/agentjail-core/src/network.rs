//! The single-route invariant.
//!
//! The jail's only route off its own network must be the gateway. A hostname
//! allowlist is decorative the moment any other route or peer exists: if the
//! agent can send packets to an IP address, DNS pinning buys nothing.
//!
//! `podman network inspect` is the runtime evidence. The check is fail-closed:
//! a missing `internal` flag, a missing subnet, or any parse failure means
//! "do not launch", never "assume internal".

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkInspect {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub driver: String,
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub ipv6_enabled: bool,
    #[serde(default)]
    pub subnets: Vec<Subnet>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Subnet {
    #[serde(default)]
    pub subnet: String,
    #[serde(default)]
    pub gateway: String,
}

/// What a verified network looked like, for doctor output and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPosture {
    pub name: String,
    pub driver: String,
    pub subnets: usize,
    pub ipv6_enabled: bool,
}

impl NetworkPosture {
    pub fn describe(&self) -> String {
        format!(
            "internal network {:?} (driver={}, subnets={}, ipv6={})",
            self.name,
            if self.driver.is_empty() {
                "unknown"
            } else {
                &self.driver
            },
            self.subnets,
            self.ipv6_enabled
        )
    }
}

/// Parse and verify one `podman network inspect` result.
///
/// `podman network inspect <name>` prints an array; a single object is accepted
/// too because that is what `--format` sometimes yields.
pub fn verify_inspect_json(raw: &str) -> Result<NetworkPosture, String> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|error| format!("cannot parse network inspection output: {error}"))?;

    let value = match &parsed {
        serde_json::Value::Array(items) => items.first().cloned().ok_or_else(|| {
            "network inspection returned no network; refusing to launch".to_string()
        })?,
        serde_json::Value::Object(_) => parsed.clone(),
        _ => {
            return Err(
                "network inspection returned an unexpected shape; refusing to launch".to_string(),
            )
        }
    };

    let network: NetworkInspect = serde_json::from_value(value)
        .map_err(|error| format!("cannot read network inspection output: {error}"))?;

    if !network.internal {
        return Err(format!(
            "network {:?} is not internal; the jail would have a route off its own network, \
             so an egress allowlist could be bypassed by talking to a raw IP. Refusing to launch.",
            network.name
        ));
    }
    // IPv6 is either handled or explicitly off. A class network that carries a
    // v6 prefix is a second route out that nothing in this design manages, so a
    // jail on it has a bypass that looks like nothing at all.
    if network.ipv6_enabled {
        return Err(format!(
            "network {:?} has IPv6 enabled; a class network must be IPv4-only (create it with \
             `podman network create --ipv6=false`), because an unmanaged v6 route is a bypass. \
             Refusing to launch.",
            network.name
        ));
    }
    if network.subnets.is_empty() {
        return Err(format!(
            "network {:?} has no subnet, so the jail cannot be placed on it; refusing to launch",
            network.name
        ));
    }

    Ok(NetworkPosture {
        name: network.name,
        driver: network.driver,
        subnets: network.subnets.len(),
        ipv6_enabled: network.ipv6_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_network_passes() {
        let posture = verify_inspect_json(
            r#"[{"name":"agentjail-abc","driver":"bridge","internal":true,
                 "ipv6_enabled":false,
                 "subnets":[{"subnet":"10.89.0.0/24","gateway":"10.89.0.1"}]}]"#,
        )
        .expect("internal network should pass");
        assert_eq!(posture.name, "agentjail-abc");
        assert_eq!(posture.subnets, 1);
        assert!(posture.describe().contains("internal network"));
    }

    #[test]
    fn non_internal_network_fails_closed() {
        let error = verify_inspect_json(
            r#"[{"name":"podman","driver":"bridge","internal":false,
                 "subnets":[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]}]"#,
        )
        .expect_err("bridge network must be refused");
        assert!(error.contains("not internal"), "{error}");
        assert!(error.contains("Refusing to launch"), "{error}");
    }

    #[test]
    fn missing_internal_flag_is_not_assumed_true() {
        let error = verify_inspect_json(r#"[{"name":"x","subnets":[{"subnet":"10.0.0.0/24"}]}]"#)
            .expect_err("missing internal must fail closed");
        assert!(error.contains("not internal"), "{error}");
    }

    #[test]
    fn a_network_with_ipv6_enabled_fails_closed() {
        let error = verify_inspect_json(
            r#"[{"name":"x","internal":true,"ipv6_enabled":true,
                 "subnets":[{"subnet":"10.0.0.0/24"}]}]"#,
        )
        .expect_err("ipv6 on a class network must be refused");
        assert!(error.contains("IPv6 enabled"), "{error}");
        assert!(error.contains("--ipv6=false"), "{error}");
        assert!(error.contains("Refusing to launch"), "{error}");
    }

    #[test]
    fn network_without_subnet_fails_closed() {
        let error = verify_inspect_json(r#"[{"name":"x","internal":true,"subnets":[]}]"#)
            .expect_err("empty subnet list must fail closed");
        assert!(error.contains("no subnet"), "{error}");
    }

    #[test]
    fn empty_array_fails_closed() {
        let error = verify_inspect_json("[]").expect_err("empty result must fail closed");
        assert!(error.contains("no network"), "{error}");
    }

    #[test]
    fn garbage_fails_closed() {
        let error = verify_inspect_json("not json").expect_err("garbage must fail closed");
        assert!(error.contains("cannot parse"), "{error}");
    }

    #[test]
    fn single_object_is_accepted() {
        let posture = verify_inspect_json(
            r#"{"name":"x","internal":true,"subnets":[{"subnet":"10.0.0.0/24"}]}"#,
        )
        .expect("object form should pass");
        assert_eq!(posture.name, "x");
    }
}
