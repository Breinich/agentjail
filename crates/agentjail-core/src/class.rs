//! Egress classes: one committed config file per class, read by both halves of
//! the gateway (DNS and CONNECT) and by `agentjail run` when it checks that a
//! profile asks for nothing its class does not permit.
//!
//! A class is identified by the internal podman network the jail joins. The
//! class name below is what appears in the audit log; the network name is the
//! identity the agent cannot change from inside.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The classes this build ships. `run` refuses anything else, so a profile
/// cannot invent a class whose allowlist nobody reviewed.
pub const CLASSES: [&str; 3] = ["model", "external", "internal"];

/// The gateway's CONNECT port inside its own network.
pub const PROXY_PORT: u16 = 3128;

/// One `host` or `host:port` entry, with an exact host or a `*.suffix` wildcard.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllowEntry {
    /// Lowercase. Either a bare DNS name or `*.` plus a bare DNS name.
    pub host: String,
    pub port: u16,
}

impl AllowEntry {
    /// Whether this entry covers `host`, ignoring the port.
    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        match self.host.strip_prefix("*.") {
            Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
            None => host == self.host,
        }
    }
}

/// Environment override for the directory holding `<class>.toml`.
pub const CLASS_DIR_ENV: &str = "AGENTJAIL_CLASS_DIR";

/// Where to look for class configs, in order: the override, the checked-out
/// repository, then the one next to the installed binary.
pub fn config_search_dirs(env: &BTreeMap<String, String>, cwd: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = env.get(CLASS_DIR_ENV).filter(|value| !value.is_empty()) {
        dirs.push(PathBuf::from(dir));
    }
    dirs.push(cwd.join("gateway").join("classes"));
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        while let Some(current) = dir {
            let candidate = current.join("gateway").join("classes");
            if !dirs.contains(&candidate) {
                dirs.push(candidate);
            }
            dir = current.parent().map(Path::to_path_buf);
        }
    }
    dirs
}

/// Load the committed config for one class. A missing file is an error that
/// names every directory searched: a class without its policy file is not a
/// class.
pub fn load(class: &str, dirs: &[PathBuf]) -> Result<(PathBuf, ClassConfig), String> {
    let mut searched = Vec::new();
    for dir in dirs {
        let candidate = dir.join(format!("{class}.toml"));
        searched.push(candidate.display().to_string());
        if !candidate.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&candidate).map_err(|error| {
            format!("cannot read class config {}: {error}", candidate.display())
        })?;
        let config = ClassConfig::parse(&text).map_err(|errors| {
            format!(
                "class config {} is invalid:\n{}",
                candidate.display(),
                errors
                    .iter()
                    .map(|error| format!("  - {error}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })?;
        if config.class != class {
            return Err(format!(
                "class config {} declares class {:?}, but it was loaded for class {class:?}",
                candidate.display(),
                config.class
            ));
        }
        return Ok((candidate, config));
    }
    Err(format!(
        "no class config for {class:?}; searched:\n  {}\nset {} to point at the gateway/classes directory",
        searched.join("\n  "),
        CLASS_DIR_ENV
    ))
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsPolicy {
    /// Answer allowlisted names (pinned to loopback), NXDOMAIN everything else.
    #[default]
    Allowlist,
    /// NXDOMAIN everything, logged. For a class whose names nobody should resolve.
    Off,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClass {
    class: String,
    listen: String,
    dns: String,
    #[serde(default)]
    dns_policy: DnsPolicy,
    /// `-` means stdout for the audit stream, stderr for the DNS stream.
    #[serde(default = "dash")]
    audit_log: String,
    #[serde(default = "dash")]
    dns_log: String,
    #[serde(default)]
    allow: Vec<String>,
}

fn dash() -> String {
    "-".to_string()
}

#[derive(Debug, Clone)]
pub struct ClassConfig {
    pub class: String,
    pub listen: String,
    pub dns: String,
    pub dns_policy: DnsPolicy,
    pub audit_log: String,
    pub dns_log: String,
    pub allow: Vec<AllowEntry>,
}

impl ClassConfig {
    /// Parse and validate one committed class config. All errors at once, fail
    /// closed: an unknown key, a malformed entry, or a raw IP is a config error,
    /// never something to skip.
    pub fn parse(text: &str) -> Result<ClassConfig, Vec<String>> {
        let raw: RawClass = match toml::from_str(text) {
            Ok(raw) => raw,
            Err(error) => return Err(vec![format!("cannot parse class config: {error}")]),
        };
        let mut errors = Vec::new();

        if raw.class.is_empty()
            || !raw
                .class
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            errors.push(format!(
                "class: {:?} must be lowercase alphanumerics or '-', and is what the audit log says",
                raw.class
            ));
        }
        for (key, value) in [("listen", &raw.listen), ("dns", &raw.dns)] {
            if !is_host_port(value) {
                errors.push(format!("{key}: {value:?} is not host:port"));
            }
        }

        let mut seen = BTreeSet::new();
        let mut allow = Vec::new();
        for (index, entry) in raw.allow.iter().enumerate() {
            match parse_entry(entry) {
                Ok(parsed) => {
                    if !seen.insert(parsed.clone()) {
                        errors.push(format!("allow[{index}]: duplicate destination {entry:?}"));
                    }
                    allow.push(parsed);
                }
                Err(error) => errors.push(format!("allow[{index}]: {entry:?} {error}")),
            }
        }

        if errors.is_empty() {
            Ok(ClassConfig {
                class: raw.class,
                listen: raw.listen,
                dns: raw.dns,
                dns_policy: raw.dns_policy,
                audit_log: raw.audit_log,
                dns_log: raw.dns_log,
                allow,
            })
        } else {
            Err(errors)
        }
    }

    /// The CONNECT half's decision. A raw IP is refused even if it is listed:
    /// the allowlist is names, and an address would let the agent pick a host by
    /// number instead of by name.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        if is_ip_literal(host) {
            return false;
        }
        self.allow
            .iter()
            .any(|entry| entry.port == port && entry.matches_host(host))
    }

    /// The DNS half's decision: the name is reachable by some port.
    pub fn permits_name(&self, host: &str) -> bool {
        if is_ip_literal(host) {
            return false;
        }
        self.allow.iter().any(|entry| entry.matches_host(host))
    }
}

fn parse_entry(entry: &str) -> Result<AllowEntry, String> {
    if entry.contains('/') || entry.contains('@') || entry.contains(' ') {
        return Err("must be a bare host or host:port, with no scheme or path".to_string());
    }
    let (host, port) = match entry.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) if port > 0 => (host, port),
            _ => return Err("has a port that is not 1-65535".to_string()),
        },
        None => (entry, 443),
    };
    let bare = host.strip_prefix("*.").unwrap_or(host);
    if bare.is_empty() || !is_dns_name(bare) {
        return Err("is not a valid DNS name".to_string());
    }
    if is_ip_literal(bare) {
        return Err(
            "is a raw IP: the gateway refuses raw addresses, so listing one would never work"
                .to_string(),
        );
    }
    Ok(AllowEntry {
        host: host.to_ascii_lowercase(),
        port,
    })
}

fn is_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

fn is_host_port(value: &str) -> bool {
    // Port 0 is allowed so a test can bind an ephemeral port; nothing else uses it.
    match value.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

/// `10.1.2.3` or `[::1]`, i.e. a destination chosen by address instead of name.
pub fn is_ip_literal(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODEL: &str = r#"
class = "model"
listen = "0.0.0.0:3128"
dns = "0.0.0.0:53"
allow = ["api.example.com:443", "*.mirror.example.net:443", "plain.example.org"]
"#;

    #[test]
    fn a_committed_shape_parses_and_matches() {
        let config = ClassConfig::parse(MODEL).expect("valid class config");
        assert_eq!(config.class, "model");
        assert!(config.allows("api.example.com", 443));
        assert!(config.allows("API.Example.COM", 443));
        assert!(config.allows("a.mirror.example.net", 443));
        assert!(config.allows("plain.example.org", 443), "default port 443");
        assert!(
            !config.allows("example.com", 443),
            "a wildcard must not cover its own apex"
        );
        assert!(
            !config.allows("api.example.com", 80),
            "port is part of the match"
        );
        assert!(!config.allows("evil.example.com", 443));
        assert!(config.permits_name("a.mirror.example.net"));
        assert!(!config.permits_name("evil.example.com"));
    }

    #[test]
    fn raw_ips_are_refused_even_when_listed() {
        // Cannot even be configured...
        let text = MODEL.replace("\"plain.example.org\"", "\"192.0.2.7:443\"");
        let errors =
            ClassConfig::parse(&text).expect_err("an IP in the allowlist is a config error");
        assert!(errors[0].contains("raw IP"), "{errors:#?}");

        // ...and a lookup by address never matches.
        let config = ClassConfig::parse(MODEL).expect("valid");
        assert!(!config.allows("192.0.2.7", 443));
        assert!(!config.allows("[::1]", 443));
    }

    #[test]
    fn malformed_allow_entries_fail_closed() {
        for (entry, expected) in [
            ("https://api.example.com:443", "no scheme"),
            ("api.example.com:0", "1-65535"),
            ("api.example.com:notaport", "1-65535"),
            ("*", "not a valid DNS name"),
            ("-bad.example.com", "not a valid DNS name"),
            ("api.example.com/path", "no scheme"),
        ] {
            let text = MODEL.replace("\"plain.example.org\"", &format!("\"{entry}\""));
            let errors = ClassConfig::parse(&text).expect_err(entry);
            assert!(
                errors[0].contains(expected),
                "{entry}: expected {expected:?} in {errors:#?}"
            );
        }
    }

    #[test]
    fn unknown_keys_and_bad_listeners_fail_closed() {
        let text = format!("{MODEL}\nsurprise = true\n");
        assert!(ClassConfig::parse(&text).is_err());
        let text = MODEL.replace("listen = \"0.0.0.0:3128\"", "listen = \"3128\"");
        let errors = ClassConfig::parse(&text).expect_err("listener without host:port");
        assert!(errors[0].contains("not host:port"), "{errors:#?}");
    }

    #[test]
    fn dns_policy_defaults_to_allowlist_and_can_be_switched_off() {
        let config = ClassConfig::parse(MODEL).expect("valid");
        assert_eq!(config.dns_policy, DnsPolicy::Allowlist);
        let config = ClassConfig::parse(&format!("{MODEL}dns_policy = \"off\"\n")).expect("valid");
        assert_eq!(config.dns_policy, DnsPolicy::Off);
    }
}
