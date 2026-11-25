//! The profile format: typed model, fail-closed parsing, and validation.
//!
//! Validation has three layers, all of which must pass:
//!
//! 1. TOML parsing (`toml`), so syntax errors are reported before anything else.
//! 2. JSON Schema validation against the embedded, canonical
//!    `schema/profile.schema.json`, so the machine-readable document and the
//!    implementation cannot drift silently.
//! 3. Typed deserialisation into the structs below (`deny_unknown_fields`) plus
//!    semantic rules JSON Schema cannot express: unique in-jail paths, secret
//!    delivery targets that must be on a declared tmpfs, FUSE-backed mount
//!    sources crun cannot bind, duplicate egress entries, placeholders.
//!
//! Fail-closed rules: `network`, `network.mode`, `network.dns`, `home`,
//! `workdir`, `image`, and `agent.command` are required with no default. The
//! only defaults are ones whose absence is strictly restrictive (empty mount,
//! env, secret, or egress lists; read-only mounts; conservative resource caps).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

/// The only profile format version this build understands.
pub const SUPPORTED_PROFILE_VERSION: u32 = 1;

/// Placeholders allowed in `agent.args`.
pub const ARG_PLACEHOLDERS: [&str; 2] = ["workdir", "home"];

pub const DEFAULT_CPUS: f64 = 1.0;
pub const DEFAULT_MEMORY: &str = "1g";
pub const DEFAULT_PIDS: u32 = 256;
pub const DEFAULT_NOFILE: u64 = 1024;

/// Keys that would smuggle an actual credential into a profile.
const INLINE_SECRET_KEYS: [&str; 8] = [
    "value",
    "values",
    "inline",
    "literal",
    "plaintext",
    "content",
    "contents",
    "data",
];

/// Path prefixes that are FUSE-backed; crun refuses to bind-mount them.
const FUSE_PATH_PREFIXES: [&str; 3] = ["/tmp/.mount_", "/run/user/", "/dev/fuse"];

/// The jail's own runtime surface. Mounting over one of these, or binding the
/// host's copy in, replaces what the jail's namespaces provide: the host's
/// processes, devices, kernel state, or the jail root itself.
const JAIL_RUNTIME_PATHS: [&str; 5] = ["/", "/proc", "/sys", "/dev", "/run"];

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub image: Image,
    /// Normalised by deserialisation (see `normalize_path`), so validation,
    /// `profile show`, and the podman argv all see this exact string.
    #[serde(deserialize_with = "normalized_path")]
    pub workdir: String,
    #[serde(deserialize_with = "normalized_path")]
    pub home: String,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub env: BTreeMap<String, EnvValue>,
    #[serde(default)]
    pub secrets: Vec<Secret>,
    pub network: Network,
    #[serde(default)]
    pub resources: Resources,
    pub agent: Agent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    /// Fully qualified reference including registry, e.g. `ghcr.io/org/img:1`.
    pub name: String,
    /// `sha256:` plus 64 lowercase hex characters.
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    #[serde(deserialize_with = "normalized_path")]
    pub source: String,
    #[serde(deserialize_with = "normalized_path")]
    pub target: String,
    /// Defaults to `true`: writable mounts must be requested explicitly.
    #[serde(default = "default_true")]
    pub read_only: bool,
    /// Defaults to `true`: a missing host path fails the launch.
    #[serde(default = "default_true")]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum EnvValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl EnvValue {
    pub fn as_string(&self) -> String {
        match self {
            EnvValue::String(value) => value.clone(),
            EnvValue::Integer(value) => value.to_string(),
            EnvValue::Boolean(value) => value.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub source: SecretSource,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub delivery: SecretDelivery,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretSource {
    Env,
    File,
    Store,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretDelivery {
    /// The secret reaches the agent process environment only.
    #[default]
    Env,
    /// The secret is staged on a tmpfs path inside the jail.
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Attach to this existing podman network instead of creating one. It is
    /// verified against the single-route invariant on every start; `run`
    /// refuses a network that is not internal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Egress class, required with `mode = "allowlist"`. It names the internal
    /// network the jail joins and therefore which committed allowlist applies;
    /// the agent cannot change it from inside.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// Directory holding an operator-defined `<class>.toml`. Policy named by a
    /// profile, pinned by `class_digest`, instead of an environment variable
    /// that could point anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_dir: Option<PathBuf>,
    /// `sha256:<64 hex>` of the class file `class_dir` names. Required whenever
    /// `class_dir` is set: a directory that can change under a reviewed profile
    /// is not a pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_digest: Option<String>,
    pub mode: NetworkMode,
    /// Required with no default: an inherited host search domain can silently
    /// resolve internal names and defeat the allowlist.
    pub dns: DnsStrategy,
    #[serde(default)]
    pub egress: Vec<Egress>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Attached to an internal network with no route out.
    None,
    /// The gateway is the only route out, and it permits only `egress`.
    Allowlist,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsStrategy {
    /// No resolver at all (required with `mode = "none"`).
    None,
    /// Every answer comes from the gateway, which only resolves allowlisted names.
    /// The only value accepted with `mode = "allowlist"`.
    Gateway,
    /// Reserved: static entries only, no recursive resolver. Parses and is
    /// refused by validation until it is implemented, because a knob that
    /// validates and does nothing is a claim without enforcement.
    Pinned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTPS CONNECT with the destination pinned by SNI.
    #[default]
    Tls,
    /// Plaintext CONNECT; the request host is checked.
    Http,
    /// Raw TCP relay, not inspected. Restricted to 443 by validation.
    Tcp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nofile: Option<u64>,
    /// Absolute in-jail path -> size, e.g. `"/tmp" = "64m"`. Keys are
    /// normalised by deserialisation like every other path, so the argv cannot
    /// carry a spelling the validator never saw.
    #[serde(default, deserialize_with = "normalized_tmpfs")]
    pub tmpfs: BTreeMap<String, String>,
}

impl Resources {
    pub fn effective_cpus(&self) -> f64 {
        self.cpus.unwrap_or(DEFAULT_CPUS)
    }

    pub fn effective_memory(&self) -> &str {
        self.memory.as_deref().unwrap_or(DEFAULT_MEMORY)
    }

    pub fn effective_pids(&self) -> u32 {
        self.pids.unwrap_or(DEFAULT_PIDS)
    }

    pub fn effective_nofile(&self) -> u64 {
        self.nofile.unwrap_or(DEFAULT_NOFILE)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    /// Executable name resolved from PATH inside the jail, or an absolute path.
    pub command: String,
    /// Default arguments. `{workdir}` and `{home}` are expanded by the launcher.
    #[serde(default)]
    pub args: Vec<String>,
}

impl Profile {
    /// `name@sha256:<digest>` — the fully pinned reference.
    pub fn image_ref(&self) -> String {
        format!("{}@{}", self.image.name, self.image.digest)
    }

    pub fn agent_argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.agent.args.len() + 1);
        argv.push(self.agent.command.clone());
        argv.extend(self.agent.args.iter().cloned());
        argv
    }

    /// One-line summary used by `profile validate`, `run`, and `selftest`.
    pub fn summary(&self) -> String {
        let egress = match self.network.mode {
            NetworkMode::None => "no egress".to_string(),
            NetworkMode::Allowlist => format!(
                "egress class {:?}, {} allowlisted destination(s), dns={}",
                self.network.class.as_deref().unwrap_or("unset"),
                self.network.egress.len(),
                self.network.dns.as_str()
            ),
        };
        format!(
            "{} mount(s), {} secret reference(s), {egress}",
            self.mounts.len(),
            self.secrets.len()
        )
    }

    /// The document `profile show` prints: every default resolved, secret
    /// references visible, secret values never present (they are not here).
    pub fn effective_json(&self) -> serde_json::Value {
        let mounts: Vec<serde_json::Value> = self
            .mounts
            .iter()
            .map(|mount| {
                serde_json::json!({
                    "source": mount.source,
                    "target": mount.target,
                    "read_only": mount.read_only,
                    "required": mount.required,
                })
            })
            .collect();

        let env: BTreeMap<String, String> = self
            .env
            .iter()
            .map(|(name, value)| (name.clone(), value.as_string()))
            .collect();

        let secrets: Vec<serde_json::Value> = self
            .secrets
            .iter()
            .map(|secret| {
                let mut value = serde_json::json!({
                    "name": secret.name.clone().unwrap_or_else(|| secret.target.clone()),
                    "source": secret.source.as_str(),
                    "ref": secret.reference,
                    "delivery": secret.delivery.as_str(),
                    "target": secret.target,
                });
                if secret.delivery == SecretDelivery::File {
                    value["mode"] = serde_json::json!(secret.mode.as_deref().unwrap_or("0400"));
                }
                value
            })
            .collect();

        let egress: Vec<serde_json::Value> = self
            .network
            .egress
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "host": entry.host,
                    "port": entry.port,
                    "protocol": entry.protocol.as_str(),
                })
            })
            .collect();

        serde_json::json!({
            "version": self.version,
            "description": self.description,
            "image": { "name": self.image.name, "digest": self.image.digest },
            "workdir": self.workdir,
            "home": self.home,
            "mounts": mounts,
            "env": env,
            "secrets": secrets,
            "network": {
                "name": self.network.name,
                "class": self.network.class,
                "class_dir": self.network.class_dir,
                "class_digest": self.network.class_digest,
                "mode": self.network.mode.as_str(),
                "dns": self.network.dns.as_str(),
                "egress": egress,
            },
            "resources": {
                "cpus": self.resources.effective_cpus(),
                "memory": self.resources.effective_memory(),
                "pids": self.resources.effective_pids(),
                "nofile": self.resources.effective_nofile(),
                "tmpfs": self.resources.tmpfs,
            },
            "agent": { "command": self.agent.command, "args": self.agent.args },
        })
    }
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::None => "none",
            NetworkMode::Allowlist => "allowlist",
        }
    }
}

impl DnsStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsStrategy::None => "none",
            DnsStrategy::Gateway => "gateway",
            DnsStrategy::Pinned => "pinned",
        }
    }
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tls => "tls",
            Protocol::Http => "http",
            Protocol::Tcp => "tcp",
        }
    }
}

impl SecretSource {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretSource::Env => "env",
            SecretSource::File => "file",
            SecretSource::Store => "store",
        }
    }
}

impl SecretDelivery {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretDelivery::Env => "env",
            SecretDelivery::File => "file",
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

/// Lexically normalise a path: collapse `.`, `..`, repeated `/`, and a trailing
/// `/`, without consulting the filesystem.
///
/// Deliberately not `std::fs::canonicalize`: a mount source may not exist on the
/// host, and neither side of a mount is resolved the way the host would resolve
/// it. `..` above the root is a no-op, so every traversal spelling of `/proc`
/// (`/proc/`, `//proc`, `/work/../proc`) collapses to the one string that
/// validation and the podman argv both see.
pub fn normalize_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if matches!(parts.last(), Some(last) if *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            Component::Normal(name) => parts.push(name.to_str().unwrap_or_default()),
            Component::Prefix(_) => {}
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// `deserialize_with` for the path fields: the normalised form is the only form
/// that exists after parsing, so no caller can hold a validated string and pass
/// the raw one to podman.
fn normalized_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    Ok(normalize_path(&raw))
}

/// The same for the tmpfs map's keys. Two spellings of one path are one entry,
/// so `/tmp` and `/tmp/` together are a profile mistake and are refused here
/// rather than silently collapsed: one of the two sizes would disappear.
fn normalized_tmpfs<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let raw = BTreeMap::<String, String>::deserialize(deserializer)?;
    let mut tmpfs = BTreeMap::new();
    for (path, size) in raw {
        let path = normalize_path(&path);
        if tmpfs.insert(path.clone(), size).is_some() {
            return Err(D::Error::custom(format!(
                "duplicate tmpfs path {path:?} after normalisation; declare it once"
            )));
        }
    }
    Ok(tmpfs)
}

/// Parse and fully validate a profile document.
///
/// On failure every problem found is returned, each prefixed with the path of
/// the offending value, so one run tells the user everything to fix.
pub fn parse_and_validate(text: &str) -> Result<Profile, Vec<String>> {
    let value: toml::Value = match toml::from_str(text) {
        Ok(value) => value,
        Err(error) => return Err(vec![format!("profile is not valid TOML: {error}")]),
    };

    let mut errors = Vec::new();
    errors.extend(reject_inline_secrets(&value));
    errors.extend(crate::schema::validate(&value));

    let typed: Option<Profile> = match toml::from_str::<Profile>(text) {
        Ok(profile) => Some(profile),
        Err(error) => {
            errors.push(format!("typed profile: {error}"));
            None
        }
    };

    match &typed {
        Some(profile) => errors.extend(profile.semantic_errors()),
        // A structural problem in one section must not hide the specific
        // semantic messages in the others.
        None => errors.extend(partial_semantic_errors(&value)),
    }

    match (typed, errors.is_empty()) {
        (Some(profile), true) => Ok(profile),
        (_, _) => Err(errors),
    }
}

/// Inline secret material is rejected before schema validation so the error
/// names the actual mistake instead of "unknown property".
fn reject_inline_secrets(value: &toml::Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(secrets) = value.get("secrets").and_then(|v| v.as_array()) else {
        return errors;
    };
    for (index, entry) in secrets.iter().enumerate() {
        let Some(table) = entry.as_table() else {
            continue;
        };
        for key in INLINE_SECRET_KEYS {
            if table.contains_key(key) {
                let label = table
                    .get("name")
                    .or_else(|| table.get("target"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed");
                errors.push(format!(
                    "secrets[{index}] ({label}): inline secret material is not allowed (found {key:?}); \
                     use source = \"env\" | \"file\" | \"store\" plus a ref that names where the secret already lives"
                ));
            }
        }
    }
    errors
}

impl Profile {
    fn semantic_errors(&self) -> Vec<String> {
        semantic_errors(
            Some(self.version),
            &self.workdir,
            &self.home,
            &self.mounts,
            &self.env,
            &self.secrets,
            &self.network,
            &self.resources,
            &self.agent,
        )
    }
}

/// Semantic validation over the sections it can see.
///
/// Running this with per-section types rather than a single `Profile` means a
/// structural error in one section (an inline secret value, say) does not
/// suppress the useful semantic errors in the others.
#[allow(clippy::too_many_arguments)]
fn semantic_errors(
    version: Option<u32>,
    workdir: &str,
    home: &str,
    mounts: &[Mount],
    env: &BTreeMap<String, EnvValue>,
    secrets: &[Secret],
    network: &Network,
    resources: &Resources,
    agent: &Agent,
) -> Vec<String> {
    let mut errors = Vec::new();
    errors.extend(path_errors(version, workdir, home));
    errors.extend(mount_errors(mounts, home));
    errors.extend(env_errors(env));
    errors.extend(secret_errors(secrets, &resources.tmpfs));
    errors.extend(network_errors(network));
    errors.extend(resource_errors(resources));
    errors.extend(agent_errors(agent));
    errors
}

/// Best-effort semantic checks for a document whose typed parse failed.
///
/// Each section is deserialised on its own; a broken section is skipped (the
/// schema and typed errors already describe it) while the rest still produce
/// their specific messages.
fn partial_semantic_errors(value: &toml::Value) -> Vec<String> {
    fn section<T: serde::de::DeserializeOwned>(value: &toml::Value, key: &str) -> Option<T> {
        T::deserialize(value.get(key)?.clone()).ok()
    }

    let version = value
        .get("version")
        .and_then(toml::Value::as_integer)
        .and_then(|version| u32::try_from(version).ok());
    let text =
        |key: &str| normalize_path(value.get(key).and_then(toml::Value::as_str).unwrap_or(""));

    semantic_errors(
        version,
        &text("workdir"),
        &text("home"),
        &section::<Vec<Mount>>(value, "mounts").unwrap_or_default(),
        &section::<BTreeMap<String, EnvValue>>(value, "env").unwrap_or_default(),
        &section::<Vec<Secret>>(value, "secrets").unwrap_or_default(),
        &section::<Network>(value, "network").unwrap_or(Network {
            name: None,
            class: None,
            class_dir: None,
            class_digest: None,
            mode: NetworkMode::None,
            dns: DnsStrategy::None,
            egress: Vec::new(),
        }),
        &section::<Resources>(value, "resources").unwrap_or_default(),
        &section::<Agent>(value, "agent").unwrap_or(Agent {
            command: String::new(),
            args: Vec::new(),
        }),
    )
}

fn path_errors(version: Option<u32>, workdir: &str, home: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(version) = version {
        if version != SUPPORTED_PROFILE_VERSION {
            errors.push(format!(
                "version: must be {SUPPORTED_PROFILE_VERSION} (this build supports only that format)"
            ));
        }
    }
    for (field, value) in [("workdir", workdir), ("home", home)] {
        if value == "/" {
            errors.push(format!(
                "{field}: must not be the jail root '/'; pick a dedicated directory"
            ));
        }
        if !value.starts_with('/') {
            errors.push(format!("{field}: must be an absolute in-jail path"));
        }
    }
    if !workdir.is_empty() && workdir == home {
        errors.push("workdir and home must differ".to_string());
    }
    errors
}

fn mount_errors(mounts: &[Mount], home: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, mount) in mounts.iter().enumerate() {
        if let Some(previous) = seen.insert(mount.target.as_str(), index) {
            errors.push(format!(
                "mounts[{index}].target: {:?} already mounted by mounts[{previous}]",
                mount.target
            ));
        }
        // Both sides reach podman's --mount option parser, where ',' and '='
        // separate options. Podman refusing a duplicate destination is an
        // accident, not a defence: the next option key may not be harmless.
        for (field, value) in [("target", &mount.target), ("source", &mount.source)] {
            if value.contains(',') || value.contains('=') {
                errors.push(format!(
                    "mounts[{index}].{field}: {value:?} contains ',' or '=', which podman reads as --mount option syntax; a path must be only a path"
                ));
            }
        }
        if JAIL_RUNTIME_PATHS.contains(&mount.target.as_str()) {
            errors.push(format!(
                "mounts[{index}].target: refusing to mount over {:?}; it is part of the jail's own runtime surface",
                mount.target
            ));
        }
        if JAIL_RUNTIME_PATHS.contains(&mount.source.as_str()) {
            errors.push(format!(
                "mounts[{index}].source: refusing to bind the host's {:?} into the jail; it is the host's own runtime surface (processes, devices, kernel state), not a data path",
                mount.source
            ));
        }
        // The root counts as a component, so "/work" is a target (2) and "/"
        // alone is not (1).
        if Path::new(&mount.target).components().count() < 2 {
            errors.push(format!(
                "mounts[{index}].target: {:?} is the jail root, which cannot be replaced by a mount; pick a directory such as \"/work/data\"",
                mount.target
            ));
        }
        if !home.is_empty() && mount.target == home {
            errors.push(format!(
                "mounts[{index}].target: {home:?} is the jail home; mount elsewhere"
            ));
        }
        if let Some(kind) = fuse_kind(&mount.source) {
            errors.push(format!(
                "mounts[{index}].source: {:?} is {kind}; FUSE-backed paths cannot be bind-mounted into the jail \
                 (crun: cannot stat self/fd/N: Permission denied). Copy the runtime into the image \
                 (images/base/Containerfile) or into a directory that is itself a normal bind mount, \
                 e.g. under {{workdir}}/.tools",
                mount.source
            ));
        }
    }
    errors
}

fn env_errors(env: &BTreeMap<String, EnvValue>) -> Vec<String> {
    let mut errors = Vec::new();
    for (name, value) in env {
        if looks_like_credential_name(name) {
            errors.push(format!(
                "env.{name}: names that look like credentials are rejected; declare it under \
                 [[secrets]] with a reference instead of a literal value"
            ));
        }
        if let EnvValue::String(text) = value {
            if looks_like_token(text) {
                errors.push(format!(
                    "env.{name}: value looks like a credential (long unbroken token); secrets must \
                     be injected by reference, not written into a profile"
                ));
            }
        }
    }
    errors
}

fn secret_errors(secrets: &[Secret], tmpfs: &BTreeMap<String, String>) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, secret) in secrets.iter().enumerate() {
        if let Some(previous) = seen.insert(secret.target.as_str(), index) {
            errors.push(format!(
                "secrets[{index}].target: {:?} already used by secrets[{previous}]",
                secret.target
            ));
        }

        match secret.source {
            SecretSource::Env => {
                if !is_env_var_name(&secret.reference) {
                    errors.push(format!(
                        "secrets[{index}].ref: {:?} is not a valid environment variable name",
                        secret.reference
                    ));
                }
            }
            SecretSource::File => {
                if !secret.reference.starts_with('/') {
                    errors.push(format!(
                        "secrets[{index}].ref: host file reference must be an absolute path"
                    ));
                }
                if let Some(kind) = fuse_kind(&secret.reference) {
                    errors.push(format!(
                        "secrets[{index}].ref: {:?} is {kind} and cannot be read reliably; stage it on a normal filesystem first",
                        secret.reference
                    ));
                }
            }
            SecretSource::Store => {
                if !is_store_reference(&secret.reference) {
                    errors.push(format!(
                        "secrets[{index}].ref: {:?} is not a valid credential-store reference",
                        secret.reference
                    ));
                }
            }
        }

        match secret.delivery {
            SecretDelivery::Env => {
                if secret.mode.is_some() {
                    errors.push(format!(
                        "secrets[{index}].mode: only valid with delivery = \"file\"; environment delivery has no file mode"
                    ));
                }
                if !is_env_var_name(&secret.target) {
                    errors.push(format!(
                        "secrets[{index}].target: {:?} is not a valid environment variable name",
                        secret.target
                    ));
                }
            }
            SecretDelivery::File => {
                if !secret.target.starts_with('/') {
                    errors.push(format!(
                        "secrets[{index}].target: file delivery needs an absolute path"
                    ));
                } else if !tmpfs
                    .keys()
                    .any(|path| is_inside(&normalize_path(&secret.target), path))
                {
                    let declared = if tmpfs.is_empty() {
                        "none".to_string()
                    } else {
                        tmpfs.keys().cloned().collect::<Vec<_>>().join(", ")
                    };
                    errors.push(format!(
                        "secrets[{index}].target: {:?} is not inside a declared tmpfs (resources.tmpfs: {declared}); \
                         secret files must never touch a bind mount or the image filesystem",
                        secret.target
                    ));
                }
                if let Some(mode) = &secret.mode {
                    if !is_file_mode(mode) {
                        errors.push(format!(
                            "secrets[{index}].mode: {mode:?} is not an octal file mode such as 0400"
                        ));
                    }
                }
            }
        }
    }
    errors
}

/// Which class a profile may name, and — for an operator class — where its file
/// comes from and what pins it. All or nothing: a class name with no policy file
/// behind it, a directory with no digest, or a digest with no directory are each
/// a launch nobody can audit.
fn class_selection_errors(network: &Network) -> Vec<String> {
    let mut errors = Vec::new();
    let class = network.class.as_deref();
    let (dir, digest) = (
        network.class_dir.as_deref(),
        network.class_digest.as_deref(),
    );

    if let (None, Some(_)) | (Some(_), None) = (dir, digest) {
        errors.push(
            "network.class_dir and network.class_digest: give both or neither. A directory without a \
             digest is policy that can change under a reviewed profile; a digest without a directory \
             pins nothing."
                .to_string(),
        );
    }

    // Built-in class: no directory, and the name has to be one this build ships.
    let Some(dir) = dir else {
        match class {
            None => errors.push(
                "network.class: required with mode \"allowlist\"; it names which egress class \
                 (and therefore which committed allowlist) the jail joins"
                    .to_string(),
            ),
            Some(class) if !crate::class::CLASSES.contains(&class) => errors.push(format!(
                "network.class: {class:?} is not an egress class this build ships ({}); an operator \
                 class needs network.class_dir and network.class_digest",
                crate::class::CLASSES.join(", ")
            )),
            Some(_) => {}
        }
        return errors;
    };

    // Operator class.
    let dir_text = dir.display().to_string();
    if !dir.is_absolute() {
        errors.push(format!(
            "network.class_dir: {dir_text:?} is relative; the class directory is a host path, give an absolute one"
        ));
    }
    if let Some(digest) = digest {
        if !is_class_digest(digest) {
            errors.push(format!(
                "network.class_digest: {digest:?} must be sha256: followed by 64 lowercase hex characters \
                 (network.class_dir/{}.toml)",
                class.unwrap_or("<class>")
            ));
        }
    }
    match class {
        None => errors.push(
            "network.class: required with network.class_dir; it names <class>.toml inside the directory"
                .to_string(),
        ),
        Some(class) if !crate::class::is_operator_class_name(class) => errors.push(format!(
            "network.class: {class:?} cannot name an operator class: it is either one of the built-in \
             classes ({}) or not lowercase alphanumerics/'-'. An operator class must not shadow a \
             built-in one, so the same name never means two policies.",
            crate::class::CLASSES.join(", ")
        )),
        Some(_) => {}
    }
    // The class file is bind-mounted into the gateway container, so its directory
    // follows the same rules as any other mount source.
    if dir_text.contains(',') || dir_text.contains('=') {
        errors.push(format!(
            "network.class_dir: {dir_text:?} contains ',' or '=', which podman reads as --mount option syntax; a path must be only a path"
        ));
    }
    if JAIL_RUNTIME_PATHS.contains(&dir_text.as_str()) {
        errors.push(format!(
            "network.class_dir: refusing {dir_text:?}; it is part of the jail's own runtime surface, not a directory of class files"
        ));
    }
    if let Some(kind) = fuse_kind(&dir_text) {
        errors.push(format!(
            "network.class_dir: {dir_text:?} is {kind}; the class file is bind-mounted into the gateway container, so it must be a normal directory"
        ));
    }
    errors
}

fn is_class_digest(value: &str) -> bool {
    value
        .strip_prefix(crate::class::DIGEST_PREFIX)
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
}

fn network_errors(network: &Network) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen: BTreeSet<(&str, u16, Protocol)> = BTreeSet::new();

    if let Some(name) = &network.name {
        if !is_network_name(name) {
            errors.push(format!(
                "network.name: {name:?} is not a valid podman network name (alphanumerics, '.', '_', '-', at most 63 characters)"
            ));
        }
    }

    match network.mode {
        NetworkMode::None => {
            if let Some(class) = &network.class {
                errors.push(format!(
                    "network.class: {class:?} needs mode = \"allowlist\"; mode \"none\" has no route out"
                ));
            }
            if network.class_dir.is_some() || network.class_digest.is_some() {
                errors.push(
                    "network.class_dir/class_digest: only with mode = \"allowlist\"; mode \"none\" has no egress class"
                        .to_string(),
                );
            }
            if !network.egress.is_empty() {
                errors.push(format!(
                    "network.egress: mode \"none\" means no egress; {} destination(s) are declared but would never be reachable",
                    network.egress.len()
                ));
            }
            if network.dns != DnsStrategy::None {
                errors.push(
                    "network.dns: mode \"none\" has no resolver; set dns = \"none\"".to_string(),
                );
            }
        }
        NetworkMode::Allowlist => {
            errors.extend(class_selection_errors(network));
            if network.name.is_some() {
                errors.push(
                    "network.name: mode \"allowlist\" does not take a network name; the per-run \
                     class network is created for you and removed when the run ends"
                        .to_string(),
                );
            }
            if network.egress.is_empty() {
                errors.push(
                    "network.egress: mode \"allowlist\" needs at least one destination".to_string(),
                );
            }
            match network.dns {
                DnsStrategy::Gateway => {}
                DnsStrategy::None => errors.push(
                    "network.dns: mode \"allowlist\" needs dns = \"gateway\"; the class gateway \
                     is the jail's resolver"
                        .to_string(),
                ),
                // Reserved in the schema, refused here: a value that validates and
                // then does nothing is worse than one that is refused (the same
                // reason `resources.disk` was removed).
                DnsStrategy::Pinned => errors.push(
                    "network.dns: \"pinned\" is not implemented yet; the launcher always starts \
                     the class gateway as the resolver, so use dns = \"gateway\""
                        .to_string(),
                ),
            }
        }
    }

    for (index, entry) in network.egress.iter().enumerate() {
        if !seen.insert((entry.host.as_str(), entry.port, entry.protocol)) {
            errors.push(format!(
                "network.egress[{index}]: duplicate destination {}:{}/{}",
                entry.host,
                entry.port,
                entry.protocol.as_str()
            ));
        }
        if entry.host.contains('*') {
            errors.push(format!(
                "network.egress[{index}].host: wildcards are not allowed; list each destination explicitly"
            ));
        }
        if entry.host.contains(':') || entry.host.contains('/') {
            errors.push(format!(
                "network.egress[{index}].host: give a bare DNS name; schemes, paths, and ports belong in other fields"
            ));
        } else if !is_dns_name(&entry.host) {
            errors.push(format!(
                "network.egress[{index}].host: {:?} is not a valid DNS name",
                entry.host
            ));
        }
        if entry.port == 0 {
            errors.push(format!("network.egress[{index}].port: must be 1-65535"));
        }
        if entry.protocol == Protocol::Tcp && entry.port != 443 {
            errors.push(format!(
                "network.egress[{index}]: raw tcp egress is not inspected by the gateway; only tls \
                 (CONNECT with SNI pinning) and http are accepted for non-443 destinations"
            ));
        }
    }
    errors
}

fn resource_errors(resources: &Resources) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(cpus) = resources.cpus {
        if !(cpus.is_finite() && cpus > 0.0) {
            errors.push("resources.cpus: must be greater than zero".to_string());
        }
    }
    if let Some(memory) = resources.memory.as_deref() {
        if !is_size(memory) {
            errors.push(format!(
                "resources.memory: {memory:?} is not a size such as 512m or 4g"
            ));
        }
    }
    if let Some(pids) = resources.pids {
        if pids == 0 {
            errors.push("resources.pids: must be at least 1".to_string());
        }
    }
    if let Some(nofile) = resources.nofile {
        if nofile < 64 {
            errors.push("resources.nofile: must be at least 64".to_string());
        }
    }
    for (path, size) in &resources.tmpfs {
        if !path.starts_with('/') {
            errors.push(format!(
                "resources.tmpfs: {path:?} is not an absolute in-jail path"
            ));
        }
        // The key becomes podman option text (`--tmpfs <path>:rw,...`), so it
        // may not carry the characters that separate options - the same rule as
        // `mounts[].source`/`target`, one field over.
        if path.contains(',') || path.contains('=') {
            errors.push(format!(
                "resources.tmpfs: {path:?} contains ',' or '=', which podman reads as --tmpfs option syntax; a path must be only a path"
            ));
        }
        if !is_size(size) {
            errors.push(format!(
                "resources.tmpfs.{path}: {size:?} is not a size such as 64m or 1g"
            ));
        }
    }
    errors
}

fn agent_errors(agent: &Agent) -> Vec<String> {
    let mut errors = Vec::new();
    if agent.command.contains('/') && !agent.command.starts_with('/') {
        errors.push(format!(
            "agent.command: {:?} is a relative path; use a bare executable name resolved from PATH inside the jail, or an absolute in-jail path",
            agent.command
        ));
    }
    for (index, arg) in agent.args.iter().enumerate() {
        let mut rest = arg.as_str();
        while let Some(start) = rest.find('{') {
            let Some(end) = rest[start..].find('}') else {
                break;
            };
            let placeholder = &rest[start + 1..start + end];
            if !ARG_PLACEHOLDERS.contains(&placeholder) {
                errors.push(format!(
                    "agent.args[{index}]: unknown placeholder {{{placeholder}}}; supported placeholders are {{home}}, {{workdir}}"
                ));
            }
            rest = &rest[start + end + 1..];
        }
    }
    errors
}

// ---------------------------------------------------------------------------
// Small predicates (no regex dependency)
// ---------------------------------------------------------------------------

pub(crate) fn is_env_var_name(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(crate) fn is_store_reference(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '@' | '-'))
}

fn is_file_mode(value: &str) -> bool {
    let digits = value.strip_prefix('0').unwrap_or(value);
    digits.len() == 3 && digits.chars().all(|c| ('0'..='7').contains(&c))
}

pub(crate) fn is_size(value: &str) -> bool {
    let (number, unit) = match value.chars().last() {
        Some(last @ ('k' | 'K' | 'm' | 'M' | 'g' | 'G')) => (&value[..value.len() - 1], Some(last)),
        _ => (value, None),
    };
    !number.is_empty()
        && number.chars().all(|c| c.is_ascii_digit())
        && (unit.is_some() || value.chars().all(|c| c.is_ascii_digit()))
}

pub(crate) fn is_network_name(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    value.len() <= 63 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub(crate) fn is_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

pub(crate) fn is_inside(path: &str, directory: &str) -> bool {
    if path == directory {
        return true;
    }
    let prefix = if directory.ends_with('/') {
        directory.to_string()
    } else {
        format!("{directory}/")
    };
    path.starts_with(&prefix)
}

/// Returns a description when the path is FUSE-backed or an AppImage mount.
pub(crate) fn fuse_kind(path: &str) -> Option<&'static str> {
    if path.ends_with(".AppImage") {
        return Some("an AppImage (a FUSE mount at run time)");
    }
    if path.starts_with("/tmp/.mount_") {
        return Some("an AppImage runtime mount");
    }
    if path.starts_with("/run/user/") && (path.contains("/gvfs") || path.contains("/doc")) {
        return Some("a FUSE-backed user mount");
    }
    if FUSE_PATH_PREFIXES.contains(&path) {
        return Some("a FUSE device path");
    }
    None
}

fn looks_like_credential_name(name: &str) -> bool {
    const TOKENS: [&str; 12] = [
        "PASS",
        "PASSWD",
        "PASSWORD",
        "SECRET",
        "SECRETS",
        "TOKEN",
        "TOKENS",
        "APIKEY",
        "CREDENTIAL",
        "CREDENTIALS",
        "AUTH",
        "BEARER",
    ];
    let upper = name.to_ascii_uppercase();
    if upper.contains("API_KEY") || upper.contains("PRIVATE_KEY") || upper.contains("ACCESS_KEY") {
        return true;
    }
    upper.split('_').any(|token| TOKENS.contains(&token))
}

fn looks_like_token(value: &str) -> bool {
    value.len() >= 32
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
version = 1
description = "offline jail"
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[network]
mode = "none"
dns = "none"

[agent]
command = "bash"
args = ["-l"]
"#;

    fn allowlist() -> String {
        r#"
version = 1
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[network]
class = "model"
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "api.anthropic.com"
port = 443

[agent]
command = "bash"
args = ["-lc", "true"]
"#
        .to_string()
    }

    fn errors(text: &str) -> Vec<String> {
        parse_and_validate(text).expect_err("expected validation errors")
    }

    fn assert_error(text: &str, needle: &str) {
        let found = errors(text);
        assert!(
            found.iter().any(|error| error.contains(needle)),
            "expected {needle:?} in {found:#?}"
        );
    }

    #[test]
    fn minimal_profile_is_valid() {
        let profile = parse_and_validate(MINIMAL).expect("valid");
        assert_eq!(profile.image_ref().split('@').count(), 2);
        assert!(profile.summary().contains("no egress"));
        assert!(profile.mounts.is_empty());
    }

    #[test]
    fn allowlist_profile_is_valid() {
        let profile = parse_and_validate(&allowlist()).expect("valid");
        assert_eq!(profile.network.egress.len(), 1);
        assert_eq!(profile.network.egress[0].protocol, Protocol::Tls);
    }

    #[test]
    fn network_is_required_not_defaulted() {
        let text = MINIMAL.replace("[network]\nmode = \"none\"\ndns = \"none\"\n", "");
        assert_error(&text, "network");
    }

    #[test]
    fn home_is_required_not_defaulted() {
        let text = MINIMAL.replace("home = \"/home/agent\"\n", "");
        assert_error(&text, "home");
    }

    #[test]
    fn dns_is_required_not_defaulted() {
        let text = MINIMAL.replace("dns = \"none\"\n", "");
        assert_error(&text, "dns");
    }

    #[test]
    fn inline_secret_is_rejected_before_anything_else() {
        let text = format!(
            "{MINIMAL}\n[[secrets]]\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\nvalue = \"fake-not-real\"\n"
        );
        assert_error(&text, "inline secret material is not allowed");
    }

    #[test]
    fn secret_by_reference_is_accepted() {
        let text = format!(
            "{MINIMAL}\n[[secrets]]\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\n"
        );
        let profile = parse_and_validate(&text).expect("valid");
        assert_eq!(profile.secrets[0].delivery, SecretDelivery::Env);
        assert_eq!(profile.secrets[0].reference, "EXAMPLE_TOKEN");
    }

    #[test]
    fn appimage_mount_is_rejected_with_remedy() {
        let text = format!(
            "{MINIMAL}\n[[mounts]]\nsource = \"/home/me/Agent-1.0.AppImage\"\ntarget = \"/work/tool\"\n"
        );
        let found = errors(&text);
        let joined = found.join("\n");
        assert!(joined.contains("AppImage"), "{joined}");
        assert!(joined.contains("images/base/Containerfile"), "{joined}");
    }

    #[test]
    fn appimage_runtime_mount_is_rejected() {
        let text = format!(
            "{MINIMAL}\n[[mounts]]\nsource = \"/tmp/.mount_1a2b3c/agent\"\ntarget = \"/work/tool\"\n"
        );
        assert_error(&text, "FUSE");
    }

    #[test]
    fn gvfs_mount_is_rejected() {
        let text = format!(
            "{MINIMAL}\n[[mounts]]\nsource = \"/run/user/1000/gvfs/smb/x\"\ntarget = \"/work/tool\"\n"
        );
        assert_error(&text, "FUSE");
    }

    #[test]
    fn normal_mount_is_accepted_and_read_only_by_default() {
        let text = format!(
            "{MINIMAL}\n[[mounts]]\nsource = \"/srv/src/project\"\ntarget = \"/work/project\"\n"
        );
        let profile = parse_and_validate(&text).expect("valid");
        assert!(profile.mounts[0].read_only);
        assert!(profile.mounts[0].required);
    }

    #[test]
    fn duplicate_mount_target_is_rejected() {
        let text = format!(
            "{MINIMAL}\n[[mounts]]\nsource = \"/srv/a\"\ntarget = \"/work/p\"\n\n[[mounts]]\nsource = \"/srv/b\"\ntarget = \"/work/p\"\n"
        );
        assert_error(&text, "already mounted by mounts[0]");
    }

    #[test]
    fn mounting_over_runtime_paths_is_rejected() {
        for target in ["/", "/proc", "/sys", "/dev", "/run"] {
            let text =
                format!("{MINIMAL}\n[[mounts]]\nsource = \"/srv/a\"\ntarget = \"{target}\"\n");
            assert_error(&text, "refusing to mount over");
        }
    }

    #[test]
    fn normalisation_is_lexical_only() {
        for (raw, expected) in [
            ("/proc/", "/proc"),
            ("//proc", "/proc"),
            ("/work/../proc", "/proc"),
            ("/work/./sub//", "/work/sub"),
            ("/home/agent/../agent", "/home/agent"),
            ("/home/agent/../..", "/"),
            ("/", "/"),
            ("", ""),
            ("rel/../x", "x"),
            ("../x", "../x"),
            (
                "/work/x,bind-propagation=shared",
                "/work/x,bind-propagation=shared",
            ),
        ] {
            assert_eq!(normalize_path(raw), expected, "{raw}");
        }
    }

    #[test]
    fn path_fields_are_normalised_once_at_parse_time() {
        let text = format!(
            "{}\n[[mounts]]\nsource = \"/srv/src/../src/project/\"\ntarget = \"/work/./sub/\"\n",
            MINIMAL
                .replace("workdir = \"/work\"", "workdir = \"/work/./..//work/\"")
                .replace("home = \"/home/agent\"", "home = \"/home/agent/\"")
        );
        let profile = parse_and_validate(&text).expect("valid");
        assert_eq!(profile.workdir, "/work");
        assert_eq!(profile.home, "/home/agent");
        assert_eq!(profile.mounts[0].source, "/srv/src/project");
        assert_eq!(profile.mounts[0].target, "/work/sub");
        // The same string, everywhere: `profile show` and the validator agree.
        let shown = profile.effective_json();
        assert_eq!(shown["workdir"], "/work");
        assert_eq!(shown["mounts"][0]["target"], "/work/sub");
    }

    #[test]
    fn every_spelling_of_a_runtime_path_target_is_refused() {
        for target in [
            "/proc/",
            "//proc",
            "/work/../proc",
            "/dev/",
            "/sys/",
            "/run/",
            "/home/agent/../..",
        ] {
            let text =
                format!("{MINIMAL}\n[[mounts]]\nsource = \"/srv/a\"\ntarget = \"{target}\"\n");
            assert_error(&text, "refusing to mount over");
        }
    }

    #[test]
    fn a_mount_target_that_normalises_onto_home_is_refused() {
        for target in ["/home/agent/", "/home/../home/agent", "/work/../home/agent"] {
            let text =
                format!("{MINIMAL}\n[[mounts]]\nsource = \"/srv/a\"\ntarget = \"{target}\"\n");
            assert_error(&text, "is the jail home");
        }
    }

    #[test]
    fn a_target_with_one_component_is_refused() {
        let text = format!("{MINIMAL}\n[[mounts]]\nsource = \"/srv/a\"\ntarget = \"/\"\n");
        let found = errors(&text);
        assert!(
            found.iter().any(|error| error.contains("is the jail root")),
            "{found:#?}"
        );
    }

    #[test]
    fn podman_option_syntax_in_a_mount_path_is_refused() {
        for (source, target) in [
            ("/srv/a", "/work/x,bind-propagation=shared"),
            ("/srv/a", "/work/x=y"),
            ("/srv/a,bind-propagation=shared", "/work/x"),
            ("/srv/a=b", "/work/x"),
        ] {
            let text =
                format!("{MINIMAL}\n[[mounts]]\nsource = \"{source}\"\ntarget = \"{target}\"\n");
            assert_error(&text, "podman reads as --mount option syntax");
        }
    }

    #[test]
    fn binding_the_hosts_runtime_surface_in_as_a_source_is_refused() {
        for source in ["/dev", "/dev/", "/proc/", "/work/../proc", "/sys", "/run/"] {
            let text =
                format!("{MINIMAL}\n[[mounts]]\nsource = \"{source}\"\ntarget = \"/work/data\"\n");
            assert_error(&text, "refusing to bind the host's");
        }
    }

    #[test]
    fn ordinary_targets_and_sources_stay_valid() {
        for (source, target) in [
            ("/srv/src/project", "/work"),
            ("/srv/src/project/", "/work/sub"),
            ("/srv/src/.tools", "/home/agent/.tools"),
            ("/srv/src/.tools", "/run/tools"),
            ("/srv/src/project", "/srv/data"),
        ] {
            let text =
                format!("{MINIMAL}\n[[mounts]]\nsource = \"{source}\"\ntarget = \"{target}\"\n");
            let profile = parse_and_validate(&text)
                .unwrap_or_else(|errors| panic!("{source} -> {target}: {errors:#?}"));
            assert_eq!(profile.mounts.len(), 1);
        }
    }

    #[test]
    fn duplicate_targets_are_caught_after_normalisation() {
        let text = format!(
            "{MINIMAL}\n[[mounts]]\nsource = \"/srv/a\"\ntarget = \"/work/p\"\n\n[[mounts]]\nsource = \"/srv/b\"\ntarget = \"/work/./p/\"\n"
        );
        assert_error(&text, "already mounted by mounts[0]");
    }

    #[test]
    fn home_and_workdir_agreement_survives_normalisation() {
        let text = MINIMAL
            .replace("workdir = \"/work\"", "workdir = \"/work/../home/agent\"")
            .replace("home = \"/home/agent\"", "home = \"/home/agent/\"");
        assert_error(&text, "workdir and home must differ");
        let text = MINIMAL.replace("workdir = \"/work\"", "workdir = \"/work/..\"");
        assert_error(&text, "must not be the jail root");
    }

    #[test]
    fn tmpfs_key_option_syntax_is_refused() {
        // The key becomes `--tmpfs <path>:rw,...` option text, so it may not
        // carry the characters that separate options.
        for path in ["/tmp,bind-propagation=shared", "/tmp/mode=1777"] {
            let text = format!("{MINIMAL}\n[resources]\ntmpfs = {{ \"{path}\" = \"64m\" }}\n");
            assert_error(&text, "podman reads as --tmpfs option syntax");
        }
    }

    #[test]
    fn tmpfs_keys_are_normalised_and_a_second_spelling_is_refused() {
        let text = format!("{MINIMAL}\n[resources]\ntmpfs = {{ \"/tmp/./scratch/\" = \"64m\" }}\n");
        let profile = parse_and_validate(&text).expect("valid");
        assert_eq!(
            profile.resources.tmpfs.keys().collect::<Vec<_>>(),
            vec!["/tmp/scratch"]
        );
        assert_eq!(
            profile.effective_json()["resources"]["tmpfs"]["/tmp/scratch"],
            "64m"
        );

        // Two spellings of one path would collapse into one entry and silently
        // lose a size, so it is refused instead.
        let text = format!(
            "{MINIMAL}\n[resources]\ntmpfs = {{ \"/tmp\" = \"64m\", \"/tmp/\" = \"128m\" }}\n"
        );
        assert_error(&text, "duplicate tmpfs path");
    }

    #[test]
    fn tmpfs_sizes_must_stay_sizes() {
        for size in ["64m,exec", "64m,size=1g", "=64m", "64m=1g"] {
            let text = format!("{MINIMAL}\n[resources]\ntmpfs = {{ \"/tmp\" = \"{size}\" }}\n");
            let found = errors(&text);
            assert!(
                found.iter().any(|error| error.contains("is not a size")),
                "{size}: {found:#?}"
            );
        }
    }

    #[test]
    fn a_secret_target_cannot_escape_its_tmpfs_by_traversal() {
        // `/tmp/../etc/shadow` starts with the declared tmpfs as text but not as
        // a path: the containment check must run on the normalised form.
        let text = format!(
            "{MINIMAL}\n[resources]\ntmpfs = {{ \"/tmp\" = \"64m\" }}\n\n[[secrets]]\nsource = \"file\"\nref = \"/srv/secret\"\ndelivery = \"file\"\ntarget = \"/tmp/../etc/shadow\"\n"
        );
        assert_error(&text, "not inside a declared tmpfs");

        // And a traversal spelling of the declared tmpfs still holds its own
        // contents, because both sides are compared normalised.
        let text = format!(
            "{MINIMAL}\n[resources]\ntmpfs = {{ \"/tmp/../tmp/\" = \"64m\" }}\n\n[[secrets]]\nsource = \"file\"\nref = \"/srv/secret\"\ndelivery = \"file\"\ntarget = \"/tmp/secrets/x\"\n"
        );
        let profile = parse_and_validate(&text).expect("valid");
        assert_eq!(profile.secrets[0].target, "/tmp/secrets/x");
    }

    #[test]
    fn credential_like_env_name_is_rejected() {
        let text = MINIMAL.replace(
            "workdir = \"/work\"",
            "workdir = \"/work\"\nenv = { GITHUB_TOKEN = \"looks-secret\" }",
        );
        assert_error(&text, "names that look like credentials are rejected");
    }

    #[test]
    fn long_tokenish_env_value_is_rejected() {
        let text = MINIMAL.replace(
            "workdir = \"/work\"",
            "workdir = \"/work\"\nenv = { SOMETHING = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\" }",
        );
        assert_error(&text, "looks like a credential");
    }

    #[test]
    fn ordinary_env_values_are_accepted() {
        let text = MINIMAL.replace(
            "workdir = \"/work\"",
            "workdir = \"/work\"\nenv = { LANG = \"C.UTF-8\", TZ = \"UTC\", MAX_JOBS = 4, COLOR = false }",
        );
        parse_and_validate(&text).expect("valid");
    }

    #[test]
    fn file_secret_needs_a_declared_tmpfs() {
        let text = format!(
            "{MINIMAL}\n[resources]\ntmpfs = {{ \"/tmp\" = \"64m\" }}\n\n[[secrets]]\nsource = \"file\"\nref = \"/srv/secret\"\ndelivery = \"file\"\ntarget = \"/work/secret\"\n"
        );
        assert_error(&text, "not inside a declared tmpfs");
    }

    #[test]
    fn file_secret_on_tmpfs_is_accepted() {
        let text = format!(
            "{MINIMAL}\n[resources]\ntmpfs = {{ \"/tmp\" = \"64m\" }}\n\n[[secrets]]\nsource = \"file\"\nref = \"/srv/secret\"\ndelivery = \"file\"\ntarget = \"/tmp/secrets/x\"\n"
        );
        let profile = parse_and_validate(&text).expect("valid");
        assert_eq!(profile.secrets[0].delivery, SecretDelivery::File);
    }

    #[test]
    fn mode_with_env_delivery_is_rejected() {
        let text = format!(
            "{MINIMAL}\n[[secrets]]\nsource = \"env\"\nref = \"EXAMPLE_TOKEN\"\ntarget = \"EXAMPLE_TOKEN\"\nmode = \"0400\"\n"
        );
        assert_error(&text, "only valid with delivery = \"file\"");
    }

    #[test]
    fn wildcard_egress_is_rejected() {
        let text = allowlist().replace("api.anthropic.com", "*.example.com");
        assert_error(&text, "wildcards are not allowed");
    }

    #[test]
    fn egress_with_scheme_is_rejected() {
        let text = allowlist().replace(
            "host = \"api.anthropic.com\"",
            "host = \"https://api.example.com\"",
        );
        assert_error(&text, "bare DNS name");
    }

    #[test]
    fn duplicate_egress_is_rejected() {
        let text = allowlist().replace(
            "[agent]",
            "[[network.egress]]\nhost = \"api.anthropic.com\"\nport = 443\n\n[agent]",
        );
        assert_error(&text, "duplicate destination");
    }

    #[test]
    fn raw_tcp_on_non_443_is_rejected() {
        let text = allowlist().replace("port = 443", "port = 22\nprotocol = \"tcp\"");
        assert_error(&text, "raw tcp egress");
    }

    #[test]
    fn egress_in_mode_none_is_rejected() {
        let text =
            format!("{MINIMAL}\n[[network.egress]]\nhost = \"api.example.com\"\nport = 443\n");
        let found = errors(&text);
        assert!(
            found
                .iter()
                .any(|error| error.contains("mode \"none\" means no egress")),
            "{found:#?}"
        );
    }

    #[test]
    fn pinned_dns_is_refused_as_not_implemented() {
        // It parses and it is in the schema, but nothing honours it, so it is
        // refused rather than silently ignored.
        let text = allowlist().replace("dns = \"gateway\"", "dns = \"pinned\"");
        assert_error(&text, "\"pinned\" is not implemented yet");
        let text = allowlist().replace("dns = \"gateway\"", "dns = \"none\"");
        assert_error(&text, "needs dns = \"gateway\"");
        // The only accepted resolver for an allowlist profile is the gateway.
        assert!(parse_and_validate(&allowlist()).is_ok());
    }

    #[test]
    fn allowlist_without_destination_is_rejected() {
        let text = allowlist().replace(
            "[[network.egress]]\nhost = \"api.anthropic.com\"\nport = 443\n",
            "",
        );
        assert_error(&text, "needs at least one destination");
    }

    #[test]
    fn unqualified_digest_is_rejected() {
        let text = MINIMAL.replace(
            "digest = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
            "digest = \"sha256:abc\"",
        );
        assert_error(&text, "digest");
    }

    #[test]
    fn trailing_tag_without_digest_is_rejected() {
        let text = MINIMAL.replace(
            "\ndigest = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
            "",
        );
        assert_error(&text, "digest");
    }

    #[test]
    fn unknown_placeholder_is_rejected() {
        let text = MINIMAL.replace("args = [\"-l\"]", "args = [\"--dir\", \"{token}\"]");
        assert_error(&text, "unknown placeholder {token}");
    }

    #[test]
    fn known_placeholders_are_accepted() {
        let text = MINIMAL.replace(
            "args = [\"-l\"]",
            "args = [\"--dir\", \"{workdir}\", \"--home\", \"{home}\"]",
        );
        parse_and_validate(&text).expect("valid");
    }

    #[test]
    fn relative_agent_command_with_slash_is_rejected() {
        let text = MINIMAL.replace("command = \"bash\"", "command = \"bin/agent\"");
        assert_error(&text, "relative path");
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let text = format!("{MINIMAL}\nbogus_session = \"abc\"\n");
        assert_error(&text, "bogus_session");
    }

    #[test]
    fn workdir_must_not_be_root() {
        let text = MINIMAL.replace("workdir = \"/work\"", "workdir = \"/\"");
        assert_error(&text, "must not be the jail root");
    }

    #[test]
    fn workdir_and_home_must_differ() {
        let text = MINIMAL.replace("home = \"/home/agent\"", "home = \"/work\"");
        assert_error(&text, "workdir and home must differ");
    }

    #[test]
    fn bad_resource_sizes_are_rejected() {
        let text = MINIMAL.replace(
            "[agent]",
            "[resources]\nmemory = \"two gigs\"\nnofile = 1\n\n[agent]",
        );
        let found = errors(&text);
        let joined = found.join("\n");
        assert!(joined.contains("resources.memory"), "{joined}");
        assert!(joined.contains("resources.nofile"), "{joined}");
    }

    #[test]
    fn effective_defaults_are_restrictive() {
        let profile = parse_and_validate(MINIMAL).expect("valid");
        assert_eq!(profile.resources.effective_cpus(), 1.0);
        assert_eq!(profile.resources.effective_memory(), "1g");
        assert_eq!(profile.resources.effective_pids(), 256);
        assert_eq!(profile.resources.effective_nofile(), 1024);
        assert!(profile.resources.tmpfs.is_empty());
    }

    #[test]
    fn effective_json_resolves_defaults_and_hides_nothing_it_should_not() {
        let profile = parse_and_validate(&allowlist()).expect("valid");
        let document = profile.effective_json();
        assert_eq!(document["network"]["egress"][0]["protocol"], "tls");
        assert_eq!(document["resources"]["nofile"], 1024);
        assert!(document["mounts"].as_array().unwrap().is_empty());
    }

    #[test]
    fn structural_error_does_not_hide_other_semantic_errors() {
        let text = format!(
            "{MINIMAL}\n[[mounts]]\nsource = \"/tmp/.mount_abc/x\"\ntarget = \"/work/t\"\n\n[[secrets]]\nsource = \"env\"\nref = \"X\"\ntarget = \"X\"\nvalue = \"nope\"\n"
        );
        let found = errors(&text);
        let joined = found.join("\n");
        assert!(
            joined.contains("inline secret material is not allowed"),
            "{joined}"
        );
        assert!(joined.contains("FUSE-backed"), "{joined}");
    }

    #[test]
    fn multiple_errors_are_collected() {
        let text = MINIMAL
            .replace("workdir = \"/work\"", "workdir = \"/\"")
            .replace(
                "workdir = \"/\"",
                "workdir = \"/\"\nenv = { API_KEY = \"x\" }",
            );
        let found = errors(&text);
        assert!(found.len() >= 2, "{found:#?}");
        assert!(found.iter().any(|error| error.contains("API_KEY")));
        assert!(found.iter().any(|error| error.contains("jail root")));
    }

    #[test]
    fn size_and_dns_helpers() {
        assert!(is_size("512m"));
        assert!(is_size("4g"));
        assert!(is_size("1024"));
        assert!(!is_size("2gi"));
        assert!(!is_size("m"));
        assert!(is_network_name("agentjail-abc.1"));
        assert!(!is_network_name("-bad"));
        assert!(!is_network_name(""));
        assert!(is_dns_name("api.example.com"));
        assert!(!is_dns_name("-bad.example.com"));
        assert!(!is_dns_name("bad..example.com"));
        assert!(is_env_var_name("EXAMPLE_TOKEN"));
        assert!(!is_env_var_name("1TOKEN"));
        assert!(is_file_mode("0400"));
        assert!(is_file_mode("400"));
        assert!(!is_file_mode("04800"));
        assert!(is_inside("/tmp/x", "/tmp"));
        assert!(!is_inside("/tmpfoo/x", "/tmp"));
    }
}
