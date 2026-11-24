//! Names and stale-run pruning for the resources one run owns.
//!
//! A run creates an internal podman network (the class network the jail joins)
//! and, for an allowlist profile, a gateway container on it. Both are named
//! after the profile **and the pid of the run**, exactly like the secret store
//! entries: `agentjail-<profile>-<pid>-<class>` and
//! `agentjail-<profile>-<pid>-gateway`.
//!
//! The pid is what makes pruning safe. A prune looks at names with the same
//! profile stem, parses the pid, and removes only those whose pid is gone.
//! Pruning by profile prefix alone is the bug that would let one run delete a
//! concurrent run's network; this module refuses to do it.

/// Prefix shared by everything a profile's runs create.
pub fn profile_prefix(profile_name: &str) -> String {
    let stem: String = profile_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("agentjail-{stem}-")
}

/// `agentjail-<profile>-<pid>-<class>`: the network the jail of this run joins.
pub fn network_name(profile_name: &str, pid: u32, class: &str) -> String {
    format!("{}{pid}-{class}", profile_prefix(profile_name))
}

/// `agentjail-<profile>-<pid>-gateway`: the class gateway this run talks to.
pub fn gateway_name(profile_name: &str, pid: u32) -> String {
    format!("{}{pid}-gateway", profile_prefix(profile_name))
}

/// `agentjail-<profile>-<pid>-egress`: the gateway's own outbound leg.
pub fn egress_network_name(profile_name: &str, pid: u32) -> String {
    format!("{}{pid}-egress", profile_prefix(profile_name))
}

/// What a resource name says about the run that owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunTag {
    pub pid: u32,
    /// `None` for the gateway container, `Some(class)` for a class network.
    pub class: Option<String>,
}

/// Parse a name created by this module. Anything else is `None` and is never
/// touched by a prune.
pub fn parse_run_name(name: &str, profile_name: &str) -> Option<RunTag> {
    let rest = name.strip_prefix(&profile_prefix(profile_name))?;
    let (pid_text, suffix) = rest.split_once('-')?;
    let pid = pid_text.parse::<u32>().ok()?;
    if suffix.is_empty() {
        return None;
    }
    let class = if suffix == "gateway" {
        None
    } else {
        Some(suffix.to_string())
    };
    Some(RunTag { pid, class })
}

/// Names owned by runs that no longer exist, and therefore provably dead.
///
/// `current_pid` is never pruned even if `/proc` is unreadable for it, and a
/// name that does not parse is left alone: a prune that guesses is worse than a
/// leftover network.
pub fn stale_names(
    names: &[String],
    profile_name: &str,
    current_pid: u32,
    alive: impl Fn(u32) -> bool,
) -> Vec<String> {
    names
        .iter()
        .filter(|name| match parse_run_name(name, profile_name) {
            Some(tag) => tag.pid != current_pid && !alive(tag.pid),
            None => false,
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_carry_the_profile_the_pid_and_the_class() {
        assert_eq!(
            network_name("my/profile", 42, "model"),
            "agentjail-my-profile-42-model"
        );
        assert_eq!(
            gateway_name("my/profile", 42),
            "agentjail-my-profile-42-gateway"
        );
        assert_eq!(
            egress_network_name("my/profile", 42),
            "agentjail-my-profile-42-egress"
        );
        assert_eq!(
            parse_run_name("agentjail-my-profile-42-egress", "my/profile"),
            Some(RunTag {
                pid: 42,
                class: Some("egress".to_string())
            })
        );
        assert_eq!(
            parse_run_name("agentjail-my-profile-42-model", "my/profile"),
            Some(RunTag {
                pid: 42,
                class: Some("model".to_string())
            })
        );
        assert_eq!(
            parse_run_name("agentjail-my-profile-42-gateway", "my/profile"),
            Some(RunTag {
                pid: 42,
                class: None
            })
        );
    }

    #[test]
    fn another_profiles_names_are_never_ours() {
        assert_eq!(parse_run_name("agentjail-other-42-model", "profile"), None);
        assert_eq!(
            parse_run_name("agentjail-profile-abc-model", "profile"),
            None
        );
    }

    #[test]
    fn only_dead_pids_of_the_same_profile_are_stale() {
        let names = vec![
            network_name("profile", 100, "model"),
            network_name("profile", 200, "model"),
            gateway_name("profile", 100),
            network_name("other", 300, "model"),
            "podman".to_string(),
        ];
        let stale = stale_names(&names, "profile", 200, |_| false);
        assert_eq!(
            stale,
            vec![
                network_name("profile", 100, "model"),
                gateway_name("profile", 100)
            ]
        );
        // A live concurrent run of the same profile is untouched.
        let stale = stale_names(&names, "profile", 200, |pid| pid == 100);
        assert!(stale.is_empty());
        // The current run is never stale, even if /proc says otherwise.
        let stale = stale_names(&names, "profile", 200, |_| false);
        assert!(!stale.iter().any(|name| name.contains("-200-")));
    }
}
