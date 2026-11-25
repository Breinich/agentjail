//! Egress classes: one committed config file per class, read by both halves of
//! the gateway (DNS and CONNECT) and by `agentjail run` when it checks that a
//! profile asks for nothing its class does not permit.
//!
//! A class is identified by the internal podman network the jail joins. The
//! class name below is what appears in the audit log; the network name is the
//! identity the agent cannot change from inside.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::address::AddressPolicy;

/// The classes this build ships. A profile may name one of these, or an operator
/// class from a directory it pins by digest (`load_operator`) — never an
/// invented name with no policy file behind it.
pub const CLASSES: [&str; 3] = ["model", "external", "internal"];

/// Digest prefix for `network.class_digest`, the same shape as `image.digest`.
pub const DIGEST_PREFIX: &str = "sha256:";

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

/// Where to look for the built-in class configs, in order: the checked-out
/// repository, then the one next to the installed binary.
///
/// There is deliberately no environment override: policy a run depends on is
/// named by a profile (and pinned by digest when it is an operator class), not
/// by whatever the caller's environment happens to contain.
pub fn config_search_dirs(cwd: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
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

/// A class name an operator may use: lowercase alphanumerics or `-`, and not one
/// of the built-in names. Shadowing a built-in class by pointing a directory at
/// it would make the same name mean two policies.
pub fn is_operator_class_name(name: &str) -> bool {
    !name.is_empty()
        && !CLASSES.contains(&name)
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `sha256:<64 lowercase hex>` of the class file's bytes.
pub fn file_digest(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read class config {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{DIGEST_PREFIX}{:x}", hasher.finalize()))
}

/// Load an operator-supplied class: `<dir>/<class>.toml`, parsed with the same
/// rules as a built-in class, and pinned by the digest the profile declares.
///
/// Fail closed on every axis: the file must exist, parse, declare the class it
/// was loaded for, and hash to exactly the digest in the profile. A directory
/// that can change under a reviewed profile is not a pin.
pub fn load_operator(
    dir: &Path,
    class: &str,
    digest: &str,
) -> Result<(PathBuf, ClassConfig), String> {
    if !is_operator_class_name(class) {
        return Err(format!(
            "class {class:?} is not an operator class name: lowercase alphanumerics or '-', and not one of the built-in classes ({})",
            CLASSES.join(", ")
        ));
    }
    if !digest.starts_with(DIGEST_PREFIX) {
        return Err(format!(
            "class_digest {digest:?} must be {DIGEST_PREFIX}<64 lowercase hex characters>"
        ));
    }
    load_pinned(dir, class, digest)
}

/// Load `<dir>/<class>.toml` and require its digest to match. No name rule: this
/// is the mechanism, and `load_operator` adds the profile-side rule that an
/// operator class may not shadow a built-in one. `audit` uses it directly, to
/// read the streams of a class file it is told about explicitly.
pub fn load_pinned(
    dir: &Path,
    class: &str,
    digest: &str,
) -> Result<(PathBuf, ClassConfig), String> {
    if !digest.starts_with(DIGEST_PREFIX) {
        return Err(format!(
            "class_digest {digest:?} must be {DIGEST_PREFIX}<64 lowercase hex characters>"
        ));
    }
    let path = dir.join(format!("{class}.toml"));
    if !path.is_file() {
        return Err(format!(
            "no class config at {}; network.class_dir must contain <class>.toml",
            path.display()
        ));
    }
    let actual = file_digest(&path)?;
    if actual != digest.to_ascii_lowercase() {
        return Err(format!(
            "class config {} does not match the digest this profile pins: expected {digest}, found {actual}. \
             Re-read the file before changing the digest: the pin exists so a policy change is a review event.",
            path.display()
        ));
    }
    load_from_path(&path, class)
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
        return load_from_path(&candidate, class);
    }
    Err(format!(
        "no class config for {class:?}; searched:\n  {}\na class is either one this build ships ({}) or an operator class named by network.class_dir with a pinned network.class_digest",
        searched.join("\n  "),
        CLASSES.join(", ")
    ))
}

/// Parse one class file and check it declares the class it was loaded for.
fn load_from_path(candidate: &Path, class: &str) -> Result<(PathBuf, ClassConfig), String> {
    let text = std::fs::read_to_string(candidate)
        .map_err(|error| format!("cannot read class config {}: {error}", candidate.display()))?;
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
    Ok((candidate.to_path_buf(), config))
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
    /// Bytes this jail may move through the gateway, both directions together.
    /// Required: an allowlisted destination with no size limit is an
    /// exfiltration channel with a receipt.
    max_bytes: Option<u64>,
    /// Concurrent CONNECT tunnels this jail may hold open. Required for the
    /// same reason.
    max_connections: Option<usize>,
    /// Which address ranges an allowlisted name may resolve to.
    #[serde(default)]
    address_policy: AddressPolicy,
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
    pub max_bytes: u64,
    pub max_connections: usize,
    pub address_policy: AddressPolicy,
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

        let max_bytes = match raw.max_bytes {
            Some(bytes) if bytes > 0 => bytes,
            Some(_) => {
                errors.push(
                    "max_bytes: must be greater than 0; a class with no byte budget is an \
                     exfiltration channel"
                        .to_string(),
                );
                0
            }
            None => {
                errors.push(
                    "max_bytes: required, in bytes, both directions together per jail; a class \
                     with no byte budget is an exfiltration channel"
                        .to_string(),
                );
                0
            }
        };
        let max_connections = match raw.max_connections {
            Some(count) if count > 0 => count,
            Some(_) => {
                errors.push(
                    "max_connections: must be greater than 0; a class with no cap has no cap"
                        .to_string(),
                );
                0
            }
            None => {
                errors.push(
                    "max_connections: required, concurrent CONNECT tunnels per jail; a class with \
                     no cap has no cap"
                        .to_string(),
                );
                0
            }
        };

        if errors.is_empty() {
            Ok(ClassConfig {
                class: raw.class,
                listen: raw.listen,
                dns: raw.dns,
                dns_policy: raw.dns_policy,
                audit_log: raw.audit_log,
                dns_log: raw.dns_log,
                allow,
                max_bytes,
                max_connections,
                address_policy: raw.address_policy,
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
max_bytes = 1048576
max_connections = 4
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

    #[test]
    fn the_limits_are_required_and_positive() {
        let config = ClassConfig::parse(MODEL).expect("valid");
        assert_eq!(config.max_bytes, 1_048_576);
        assert_eq!(config.max_connections, 4);

        for (key, value, expected) in [
            ("max_bytes", "0", "greater than 0"),
            ("max_connections", "0", "greater than 0"),
        ] {
            let text = MODEL.replace(
                &format!(
                    "{key} = {}",
                    if key == "max_bytes" { "1048576" } else { "4" }
                ),
                &format!("{key} = {value}"),
            );
            let errors = ClassConfig::parse(&text).expect_err(key);
            assert!(errors[0].contains(expected), "{key}: {errors:#?}");
        }

        for key in ["max_bytes", "max_connections"] {
            let text = MODEL.replace(
                &format!(
                    "{key} = {}",
                    if key == "max_bytes" { "1048576" } else { "4" }
                ),
                "",
            );
            let errors = ClassConfig::parse(&text).expect_err(key);
            assert!(errors[0].contains("required"), "{key}: {errors:#?}");
        }
    }

    #[test]
    fn the_address_policy_defaults_to_public_and_is_explicit_per_class() {
        let config = ClassConfig::parse(MODEL).expect("valid");
        assert_eq!(config.address_policy, AddressPolicy::Public);
        let config =
            ClassConfig::parse(&format!("{MODEL}address_policy = \"lan\"\n")).expect("valid");
        assert_eq!(config.address_policy, AddressPolicy::Lan);
        let config = ClassConfig::parse(&format!("{MODEL}address_policy = \"nonsense\"\n"));
        assert!(config.is_err(), "an unknown policy is a config error");
    }
}
