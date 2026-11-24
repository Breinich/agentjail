//! The run path: turn a validated profile into a `podman run` invocation.
//!
//! Everything here is a pure planner (it returns argv vectors and the secrets to
//! inject) so it can be unit-tested without a container runtime. The CLI does the
//! side effects: creating the per-run network and class gateway, injecting
//! podman secrets, and finally either `exec`ing podman (nothing to clean up) or
//! supervising it (something to clean up).
//!
//! With `network.mode = "allowlist"` the jail joins a per-run internal network
//! whose only other peer is that class's gateway, and gets `HTTPS_PROXY` /
//! `ALL_PROXY` plus `--dns <gateway>` and `--dns-search .`.
//!
//! Deliberate limit, refused rather than half-implemented:
//! `secrets[].delivery = "file"` is not offered because secrets are injected as
//! environment variables only.

use std::collections::BTreeMap;
use std::path::Path;

use crate::class::{ClassConfig, PROXY_PORT};
use crate::profile::{Agent, Mount, NetworkMode, Profile, Secret, SecretDelivery, SecretSource};

/// Name of the container for one run of one profile.
pub fn container_name(profile_name: &str, pid: u32) -> String {
    let stem: String = profile_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("agentjail-{stem}-{pid}")
}

/// Prefix for the podman secrets of one profile. Entries also carry the pid of
/// the run that created them, so two concurrent runs never collide.
pub fn secret_prefix(profile_name: &str) -> String {
    let stem: String = profile_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("agentjail-{stem}-")
}

/// Destinations a profile asks for that its egress class does not permit.
///
/// The profile's `network.egress` is a promise to the reader; the class config is
/// the control. A profile may therefore ask for less than its class allows, never
/// more, and `run` refuses the difference before creating anything.
pub fn egress_outside_class(profile: &Profile, class: &ClassConfig) -> Vec<String> {
    let mut outside = Vec::new();
    for entry in &profile.network.egress {
        if !class.allows(&entry.host, entry.port) {
            outside.push(format!(
                "network.egress: {}:{}/{} is not in egress class {:?} \
                 (gateway/classes/{}.toml)",
                entry.host,
                entry.port,
                entry.protocol.as_str(),
                class.class,
                class.class
            ));
        }
    }
    outside
}

/// Refuse profiles this build cannot honour, before anything starts.
pub fn run_blockers(profile: &Profile) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // `network.class` presence and its membership of the shipped classes are
    // checked by profile validation; mode `none` still needs a named, existing
    // internal network because it creates nothing.
    if profile.network.mode == NetworkMode::None && profile.network.name.is_none() {
        errors.push(
            "network.name: required for mode \"none\": agentjail attaches to an existing network \
             and does not create one; name an internal podman network"
                .to_string(),
        );
    }
    let home_parent = std::path::Path::new(&profile.home)
        .parent()
        .and_then(|parent| parent.to_str())
        .unwrap_or("/");
    if home_parent == "/" {
        errors.push(
            "home: must be a subdirectory such as /home/agent, so the jail can mount \
             writable scratch for it and give it mode 0700"
                .to_string(),
        );
    }
    for (index, secret) in profile.secrets.iter().enumerate() {
        if secret.delivery == SecretDelivery::File {
            errors.push(format!(
                "secrets[{index}].delivery: \"file\" is not supported; secrets are injected as \
                 environment variables only"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// A secret to inject, resolved to a podman secret-store entry.
///
/// The value is held only for the hand-off to `podman secret create`; it is
/// never put in the container argv, the image, or the container config.
#[derive(Debug)]
pub enum SecretAction {
    /// Create this entry from a value read by reference.
    Create { store_name: String, value: String },
    /// Use an entry that already exists in the podman secret store.
    Existing { store_name: String },
}

#[derive(Debug)]
pub struct SecretPlan {
    pub env_target: String,
    pub action: SecretAction,
}

impl SecretPlan {
    /// The `--secret` argument for `podman run`. The value is not part of it.
    pub fn podman_arg(&self) -> String {
        let store_name = match &self.action {
            SecretAction::Create { store_name, .. } | SecretAction::Existing { store_name } => {
                store_name
            }
        };
        format!("source={store_name},type=env,target={}", self.env_target)
    }
}

/// Resolve every secret reference to a plan. Values are read here, by
/// reference, and a missing reference fails closed naming the reference.
pub fn plan_secrets(
    profile_name: &str,
    run_id: u32,
    profile: &Profile,
    host_env: &BTreeMap<String, String>,
) -> Result<Vec<SecretPlan>, Vec<String>> {
    let prefix = format!("{}{run_id}-", secret_prefix(profile_name));
    let mut plans = Vec::new();
    let mut errors = Vec::new();

    for (index, secret) in profile.secrets.iter().enumerate() {
        if secret.delivery != SecretDelivery::Env {
            continue; // already refused by run_blockers
        }
        let store_name = format!("{prefix}{}", sanitize(&secret.target));
        match secret.source {
            SecretSource::Env => match host_env.get(&secret.reference) {
                Some(value) if !value.is_empty() => plans.push(SecretPlan {
                    env_target: secret.target.clone(),
                    action: SecretAction::Create {
                        store_name,
                        value: value.clone(),
                    },
                }),
                Some(_) => errors.push(format!(
                    "secrets[{index}] ({}): reference {:?} is empty on the host",
                    secret.name.as_deref().unwrap_or(&secret.target),
                    secret.reference
                )),
                None => errors.push(format!(
                    "secrets[{index}] ({}): reference {:?} is not set on the host",
                    secret.name.as_deref().unwrap_or(&secret.target),
                    secret.reference
                )),
            },
            SecretSource::File => {
                if !secret.reference.starts_with('/') {
                    errors.push(format!(
                        "secrets[{index}] ({}): file reference {:?} is not absolute",
                        secret.name.as_deref().unwrap_or(&secret.target),
                        secret.reference
                    ));
                    continue;
                }
                match std::fs::read_to_string(&secret.reference) {
                    Ok(value) => plans.push(SecretPlan {
                        env_target: secret.target.clone(),
                        action: SecretAction::Create {
                            store_name,
                            value: value.trim_end_matches('\n').to_string(),
                        },
                    }),
                    Err(error) => errors.push(format!(
                        "secrets[{index}] ({}): cannot read reference {:?}: {error}",
                        secret.name.as_deref().unwrap_or(&secret.target),
                        secret.reference
                    )),
                }
            }
            SecretSource::Store => plans.push(SecretPlan {
                env_target: secret.target.clone(),
                action: SecretAction::Existing {
                    store_name: secret.reference.clone(),
                },
            }),
        }
    }

    if errors.is_empty() {
        Ok(plans)
    } else {
        Err(errors)
    }
}

/// Context for building the argv.
pub struct RunContext {
    pub container_name: String,
    /// The internal network the jail joins. For `mode = "none"` it is the
    /// profile's; for `mode = "allowlist"` it is the per-run class network.
    pub network: String,
    /// The class gateway's address on that network, when the profile has egress.
    pub gateway_ip: Option<String>,
    pub selinux: bool,
    pub term: Option<String>,
}

/// Build the full `podman run ...` argument vector (without the podman program).
///
/// `agent_command` overrides the profile's `agent` when non-empty.
pub fn podman_args(
    profile: &Profile,
    context: &RunContext,
    secrets: &[SecretPlan],
    agent_command: &[String],
) -> Result<Vec<String>, Vec<String>> {
    let mut errors = Vec::new();
    let mut args: Vec<String> = Vec::new();

    args.extend(["run".into(), "--rm".into(), "--interactive".into()]);
    args.extend(["--name".into(), context.container_name.clone()]);
    args.extend(["--pull=never".into()]);
    args.extend(["--read-only".into()]);
    args.extend(["--userns=keep-id:uid=10000,gid=10000".into()]);
    args.extend(["--cap-drop=ALL".into()]);
    args.extend(["--security-opt=no-new-privileges".into()]);
    args.extend([
        "--pids-limit".into(),
        profile.resources.effective_pids().to_string(),
    ]);
    args.extend([
        "--memory".into(),
        profile.resources.effective_memory().to_string(),
    ]);
    args.extend([
        "--cpus".into(),
        profile.resources.effective_cpus().to_string(),
    ]);
    let nofile = profile.resources.effective_nofile();
    args.extend(["--ulimit".into(), format!("nofile={nofile}:{nofile}")]);
    args.extend(["--network".into(), context.network.clone()]);
    if let Some(gateway) = &context.gateway_ip {
        // The gateway is the resolver as well as the proxy, and the search
        // domain is emptied so a host search domain cannot resolve a name the
        // class does not allow.
        args.extend(["--dns".into(), gateway.clone()]);
        args.extend(["--dns-search".into(), ".".into()]);
        let proxy = format!("http://{gateway}:{PROXY_PORT}");
        for name in ["HTTPS_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"] {
            args.extend(["--env".into(), format!("{name}={proxy}")]);
        }
    }

    // Bounded writable scratch only: /tmp and /run always, with profile sizes
    // winning. The rootfs is read-only, so there is no writable layer to limit.
    let mut scratch: Vec<(String, String, String)> = Vec::new(); // (path, size, extra opts)
    let tmpfs = &profile.resources.tmpfs;
    for (path, size) in tmpfs {
        scratch.push((
            path.clone(),
            size.clone(),
            "noexec,nosuid,nodev".to_string(),
        ));
    }
    for (path, size) in [("/tmp", "64m"), ("/run", "16m")] {
        if !tmpfs.contains_key(path) {
            scratch.push((
                path.to_string(),
                size.to_string(),
                "noexec,nosuid,nodev".to_string(),
            ));
        }
    }
    // The jail's own home is a 0700 directory inside writable scratch; the
    // entrypoint creates it as the jail uid. Mounting its parent (not the home
    // itself) is what allows ownership to be the agent's.
    let home = std::path::Path::new(&profile.home);
    let home_parent = home.parent().and_then(|p| p.to_str()).unwrap_or("/");
    let home_is_mounted = profile
        .mounts
        .iter()
        .any(|mount| mount.target == profile.home);
    if !home_is_mounted && home_parent != "/" && !tmpfs.contains_key(home_parent) {
        let size = tmpfs
            .get(&profile.home)
            .cloned()
            .unwrap_or_else(|| "256m".to_string());
        scratch.push((
            home_parent.to_string(),
            size,
            "nosuid,nodev,mode=1777".to_string(),
        ));
    }
    for (path, size, opts) in scratch {
        args.extend(["--tmpfs".into(), format!("{path}:rw,{opts},size={size}")]);
    }

    // Mounts, exactly as declared. No implicit host paths.
    for (index, mount) in profile.mounts.iter().enumerate() {
        if mount.required && !Path::new(&mount.source).exists() {
            errors.push(format!(
                "mounts[{index}].source: {:?} does not exist on the host",
                mount.source
            ));
            continue;
        }
        if !Path::new(&mount.source).exists() {
            continue;
        }
        let mut option = if mount.read_only { "ro" } else { "rw" }.to_string();
        if context.selinux {
            option.push_str(",Z");
        }
        args.extend([
            "--mount".into(),
            format!(
                "type=bind,source={},destination={},{option}",
                mount.source, mount.target
            ),
        ]);
    }

    // Environment allowlist only: HOME, TERM, and profile literals.
    args.extend(["--env".into(), format!("HOME={}", profile.home)]);
    if let Some(term) = &context.term {
        args.extend(["--env".into(), format!("TERM={term}")]);
    }
    for (name, value) in &profile.env {
        args.extend(["--env".into(), format!("{name}={}", value.as_string())]);
    }

    for secret in secrets {
        args.extend(["--secret".into(), secret.podman_arg()]);
    }

    args.extend(["--workdir".into(), profile.workdir.clone()]);
    args.push(profile.image_ref());
    if agent_command.is_empty() {
        args.extend(profile.agent_argv());
    } else {
        args.extend(agent_command.iter().cloned());
    }

    if errors.is_empty() {
        Ok(args)
    } else {
        Err(errors)
    }
}

/// Where the class config lands inside the gateway container.
pub const CONTAINER_CLASS_CONFIG: &str = "/etc/agentjail/class.toml";

/// Everything one gateway container needs to be started.
pub struct GatewayContext {
    pub container_name: String,
    /// The gateway image **by ID** (`sha256:…`), never by tag: the tag is a name
    /// and this process is the jail's only route out.
    pub image_id: String,
    /// Host path of the committed class config, bind-mounted read-only.
    pub class_config: String,
    /// The per-run internal network the jail and the gateway share.
    pub network: String,
    /// The gateway's own outbound leg. The jail never gets this network.
    pub egress_network: String,
    pub jail_id: String,
    pub selinux: bool,
}

/// `podman run -d ...` for the class gateway.
///
/// The gateway is dual-homed on purpose: the internal network is where the jail
/// can reach it, and the egress network is how it reaches the destinations the
/// class allows. The jail is single-homed, so a bypass has nowhere to go.
pub fn gateway_args(context: &GatewayContext) -> Vec<String> {
    let mut args: Vec<String> = vec!["run".into(), "--detach".into(), "--rm".into()];
    args.extend(["--name".into(), context.container_name.clone()]);
    args.extend(["--pull=never".into()]);
    args.extend(["--read-only".into()]);
    // No capabilities except the one that binds :53 as a non-root uid.
    args.extend(["--cap-drop=ALL".into()]);
    args.extend(["--cap-add=NET_BIND_SERVICE".into()]);
    args.extend(["--security-opt=no-new-privileges".into()]);
    args.extend(["--network".into(), context.network.clone()]);
    args.extend(["--network".into(), context.egress_network.clone()]);
    let mut option = "ro".to_string();
    if context.selinux {
        option.push_str(",Z");
    }
    args.extend([
        "--mount".into(),
        format!(
            "type=bind,source={},destination={CONTAINER_CLASS_CONFIG},{option}",
            context.class_config
        ),
    ]);
    args.push(context.image_id.clone());
    args.extend([
        "--config".into(),
        CONTAINER_CLASS_CONFIG.to_string(),
        "--jail-id".into(),
        context.jail_id.clone(),
    ]);
    args
}

/// Expand `{workdir}` / `{home}` in agent args (the launcher does the same at
/// run time; planning does it for display and tests).
pub fn expand_agent_args(agent: &Agent, workdir: &str, home: &str) -> Vec<String> {
    let mut argv = vec![agent.command.clone()];
    for arg in &agent.args {
        argv.push(arg.replace("{workdir}", workdir).replace("{home}", home));
    }
    argv
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Describes a mount for diagnostics (never used to build the argv).
pub fn describe_mount(mount: &Mount) -> String {
    format!(
        "{}->{}{}",
        mount.source,
        mount.target,
        if mount.read_only { " (ro)" } else { " (rw)" }
    )
}

/// Store entries left behind by runs that no longer exist.
///
/// Names are `agentjail-<profile>-<pid>-<target>`; only entries whose pid is
/// neither the current process nor alive are returned, so a prune can never
/// delete the entries of a concurrent run of the same profile.
pub fn stale_secret_names(
    names: &[String],
    prefix: &str,
    current_pid: u32,
    alive: impl Fn(u32) -> bool,
) -> Vec<String> {
    let mut stale = Vec::new();
    for name in names {
        let Some(rest) = name.strip_prefix(prefix) else {
            continue;
        };
        let Some((pid_text, target)) = rest.split_once('-') else {
            continue;
        };
        if target.is_empty() {
            continue;
        }
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        if pid != current_pid && !alive(pid) {
            stale.push(name.clone());
        }
    }
    stale
}

/// Whether `secrets` came from a `Secret` with `source = store` (used in tests).
pub fn is_store_backed(secret: &Secret) -> bool {
    matches!(secret.source, SecretSource::Store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::parse_and_validate;

    const PROFILE: &str = r#"
version = 1
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[network]
name = "agentjail-test"
mode = "none"
dns = "none"

[[mounts]]
source = "/tmp"
target = "/work/tmp"
read_only = true

[env]
LANG = "C.UTF-8"
MAX_JOBS = 4

[resources]
cpus = 2
memory = "512m"
pids = 128
nofile = 2048

[resources.tmpfs]
"/tmp" = "32m"

[agent]
command = "bash"
args = ["-lc", "echo {workdir}"]
"#;

    fn profile() -> Profile {
        parse_and_validate(PROFILE).expect("valid profile")
    }

    fn context() -> RunContext {
        RunContext {
            container_name: "agentjail-test-1".to_string(),
            network: "agentjail-test".to_string(),
            gateway_ip: None,
            selinux: false,
            term: Some("xterm-256color".to_string()),
        }
    }

    #[test]
    fn argv_has_every_hardening_flag() {
        let args = podman_args(&profile(), &context(), &[], &[]).expect("argv");
        let joined = args.join(" ");
        for expected in [
            "run --rm --interactive",
            "--name agentjail-test-1",
            "--pull=never",
            "--read-only",
            "--userns=keep-id:uid=10000,gid=10000",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit 128",
            "--memory 512m",
            "--cpus 2",
            "--ulimit nofile=2048:2048",
            "--network agentjail-test",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m",
            "--tmpfs /run:rw,noexec,nosuid,nodev,size=16m",
            "--tmpfs /home:rw,nosuid,nodev,mode=1777,size=256m",
            "--env HOME=/home/agent",
            "--env TERM=xterm-256color",
            "--env LANG=C.UTF-8",
            "--env MAX_JOBS=4",
            "--workdir /work",
        ] {
            assert!(
                joined.contains(expected),
                "missing {expected:?} in {joined}"
            );
        }
        assert!(args
            .iter()
            .any(|a| a.starts_with("sha256:") || a.contains("@sha256:")));
        assert!(joined.contains("bash -lc"));
        // no TTY, no host env passthrough, no privileged flags
        assert!(!args.iter().any(|a| a == "-t" || a == "--tty"));
        assert!(!joined.contains("--env-host"));
        assert!(!joined.contains("--privileged"));
        assert!(!joined.contains("--cap-add"));
    }

    #[test]
    fn mounts_are_exactly_the_declared_ones_and_z_labelled_when_needed() {
        let args = podman_args(&profile(), &context(), &[], &[]).expect("argv");
        let mounts: Vec<&String> = args
            .iter()
            .filter(|arg| arg.starts_with("type=bind,"))
            .collect();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0], "type=bind,source=/tmp,destination=/work/tmp,ro");

        let labelled = RunContext {
            container_name: "agentjail-test-1".to_string(),
            network: "agentjail-test".to_string(),
            gateway_ip: None,
            selinux: true,
            term: None,
        };
        let args = podman_args(&profile(), &labelled, &[], &[]).expect("argv");
        assert!(args
            .iter()
            .any(|arg| arg == "type=bind,source=/tmp,destination=/work/tmp,ro,Z"));
    }

    #[test]
    fn the_argv_carries_the_normalised_tmpfs_path() {
        // Same shape as the mount destination above: the key the validator saw
        // is the key podman gets, and the default `/tmp` entry is not emitted
        // twice because the spelled-out key is the same path.
        let text = PROFILE.replace(
            "[resources.tmpfs]\n\"/tmp\"",
            "[resources.tmpfs]\n\"/tmp/.//\"",
        );
        let profile: Profile = toml::from_str(&text).expect("typed profile");
        assert_eq!(
            profile.resources.tmpfs.keys().collect::<Vec<_>>(),
            vec!["/tmp"]
        );
        let args = podman_args(&profile, &context(), &[], &[]).expect("argv");
        let tmpfs: Vec<&String> = args
            .iter()
            .filter(|arg| arg.starts_with("/tmp:") || arg.starts_with("/run:"))
            .collect();
        assert_eq!(
            tmpfs,
            vec![
                "/tmp:rw,noexec,nosuid,nodev,size=32m",
                "/run:rw,noexec,nosuid,nodev,size=16m"
            ],
            "{args:#?}"
        );
    }

    #[test]
    fn the_argv_carries_the_normalised_destination_not_the_raw_spelling() {
        // Deliberately not `parse_and_validate`: validation refuses this target,
        // and the point here is that the argv builder cannot emit the raw string
        // even for a profile that never passed through the validator. A refactor
        // that re-reads the raw spelling would pass every validator test and
        // still hand podman `/work/../proc`.
        let text = PROFILE.replace("target = \"/work/tmp\"", "target = \"/work/../proc\"");
        let profile: Profile = toml::from_str(&text).expect("typed profile");
        assert_eq!(profile.mounts[0].target, "/proc");
        let args = podman_args(&profile, &context(), &[], &[]).expect("argv");
        let mounts: Vec<&String> = args
            .iter()
            .filter(|arg| arg.starts_with("type=bind,"))
            .collect();
        assert_eq!(mounts.len(), 1, "{args:#?}");
        assert_eq!(mounts[0], "type=bind,source=/tmp,destination=/proc,ro");
        assert!(
            !mounts[0].contains(".."),
            "the raw spelling reached the argv: {mounts:?}"
        );
    }

    #[test]
    fn missing_required_mount_fails_before_start() {
        let mut profile = profile();
        profile.mounts[0].source = "/definitely/missing/agentjail".to_string();
        let errors = podman_args(&profile, &context(), &[], &[]).expect_err("must fail");
        assert!(errors[0].contains("does not exist"), "{errors:#?}");
    }

    #[test]
    fn an_allowlist_profile_needs_no_network_name_and_a_jail_with_egress_gets_the_proxy() {
        let text = PROFILE
            .replace("mode = \"none\"", "mode = \"allowlist\"")
            .replace("dns = \"none\"", "dns = \"gateway\"")
            .replace("name = \"agentjail-test\"\n", "")
            .replace("class = ", "")
            .replace(
                "[[mounts]]",
                "class = \"model\"\n\n[[network.egress]]\nhost = \"api.anthropic.com\"\nport = 443\n\n[[mounts]]",
            );
        let profile = parse_and_validate(&text).expect("schema-valid allowlist profile");
        run_blockers(&profile).expect("an allowlist profile with a class is runnable");

        let class = crate::class::ClassConfig::parse(
            "class = \"model\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\nmax_bytes = 1048576\nmax_connections = 4\nallow = [\"api.anthropic.com:443\"]\n",
        )
        .expect("class config");
        assert!(egress_outside_class(&profile, &class).is_empty());

        let egress_context = RunContext {
            container_name: "agentjail-test-1".to_string(),
            network: "agentjail-test-42-model".to_string(),
            gateway_ip: Some("10.89.0.2".to_string()),
            selinux: false,
            term: None,
        };
        let args = podman_args(&profile, &egress_context, &[], &[]).expect("argv");
        let joined = args.join(" ");
        for expected in [
            "--network agentjail-test-42-model",
            "--dns 10.89.0.2",
            "--dns-search .",
            "--env HTTPS_PROXY=http://10.89.0.2:3128",
            "--env ALL_PROXY=http://10.89.0.2:3128",
        ] {
            assert!(
                joined.contains(expected),
                "missing {expected:?} in {joined}"
            );
        }
    }

    #[test]
    fn a_destination_outside_the_class_is_refused() {
        let text = PROFILE
            .replace("mode = \"none\"", "mode = \"allowlist\"")
            .replace("dns = \"none\"", "dns = \"gateway\"")
            .replace("name = \"agentjail-test\"\n", "")
            .replace(
                "[[mounts]]",
                "class = \"model\"\n\n[[network.egress]]\nhost = \"api.anthropic.com\"\nport = 443\n\n[[mounts]]",
            );
        let profile = parse_and_validate(&text).expect("valid");
        let class = crate::class::ClassConfig::parse(
            "class = \"model\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\nmax_bytes = 1048576\nmax_connections = 4\nallow = [\"api.openai.com:443\"]\n",
        )
        .expect("class config");
        let outside = egress_outside_class(&profile, &class);
        assert_eq!(outside.len(), 1);
        assert!(outside[0].contains("api.anthropic.com:443"), "{outside:#?}");
        assert!(
            outside[0].contains("gateway/classes/model.toml"),
            "{outside:#?}"
        );
    }

    #[test]
    fn missing_network_name_is_refused() {
        let text = PROFILE.replace("name = \"agentjail-test\"\n", "");
        let profile = parse_and_validate(&text).expect("schema-valid profile");
        let errors = run_blockers(&profile).expect_err("must refuse");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("network.name: required")),
            "{errors:#?}"
        );
    }

    #[test]
    fn file_delivery_is_refused() {
        let text = format!(
            "{PROFILE}\n[[secrets]]\nsource = \"file\"\nref = \"/tmp/x\"\ndelivery = \"file\"\ntarget = \"/tmp/secret\"\n"
        );
        let profile = parse_and_validate(&text).expect("schema-valid profile");
        let errors = run_blockers(&profile).expect_err("must refuse");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("environment variables only")),
            "{errors:#?}"
        );
    }

    #[test]
    fn secret_values_are_resolved_by_reference() {
        let text = format!(
            "{PROFILE}\n[[secrets]]\nname = \"example\"\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n"
        );
        let profile = parse_and_validate(&text).expect("valid");
        let env = BTreeMap::from([("EXAMPLE_TOKEN".to_string(), "fake-value".to_string())]);
        let plans = plan_secrets("test", 42, &profile, &env).expect("plans");
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].env_target, "EXAMPLE_TOKEN");
        assert_eq!(
            plans[0].podman_arg(),
            "source=agentjail-test-42-EXAMPLE_TOKEN,type=env,target=EXAMPLE_TOKEN"
        );
        match &plans[0].action {
            SecretAction::Create { value, .. } => assert_eq!(value, "fake-value"),
            other => panic!("expected create, got {other:?}"),
        }
    }

    #[test]
    fn missing_secret_reference_names_the_reference_not_a_value() {
        let text = format!(
            "{PROFILE}\n[[secrets]]\nsource = \"env\"\nref = \"MISSING_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n"
        );
        let profile = parse_and_validate(&text).expect("valid");
        let errors = plan_secrets("test", 42, &profile, &BTreeMap::new()).expect_err("must fail");
        assert!(errors[0].contains("MISSING_TOKEN"), "{errors:#?}");
    }

    #[test]
    fn store_backed_secrets_are_not_read_locally() {
        let text = format!(
            "{PROFILE}\n[[secrets]]\nsource = \"store\"\nref = \"existing-store-entry\"\ntarget = \"EXAMPLE_TOKEN\"\n"
        );
        let profile = parse_and_validate(&text).expect("valid");
        let plans = plan_secrets("test", 42, &profile, &BTreeMap::new()).expect("plans");
        assert!(matches!(plans[0].action, SecretAction::Existing { .. }));
        assert!(plans[0]
            .podman_arg()
            .starts_with("source=existing-store-entry,type=env"));
    }

    #[test]
    fn placeholders_expand_for_display() {
        let profile = profile();
        let argv = expand_agent_args(&profile.agent, "/work", "/home/agent");
        assert_eq!(argv, vec!["bash", "-lc", "echo /work"]);
    }

    #[test]
    fn stale_secret_names_only_cover_dead_runs_of_the_same_profile() {
        let prefix = secret_prefix("profile");
        let names = vec![
            format!("{prefix}100-TOKEN"),
            format!("{prefix}200-TOKEN"),
            "other-300-TOKEN".to_string(),
            format!("{prefix}abc-TOKEN"),
        ];
        let stale = stale_secret_names(&names, &prefix, 200, |_| false);
        assert_eq!(stale, vec![format!("{prefix}100-TOKEN")]);
        assert!(stale_secret_names(&names, &prefix, 200, |_| true).is_empty());
    }

    #[test]
    fn container_and_secret_names_are_stable_and_safe() {
        assert_eq!(container_name("my/profile", 7), "agentjail-my-profile-7");
        assert!(secret_prefix("my/profile").starts_with("agentjail-my-profile-"));
    }
}
