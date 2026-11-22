//! Locations agentjail reads from or writes to.
//!
//! Everything derives from the XDG base directory specification, with explicit
//! environment overrides for tests and unusual deployments. These functions
//! never touch the filesystem, so they are cheap to call and easy to test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "agentjail";
pub const PROFILE_DIR_ENV: &str = "AGENTJAIL_PROFILE_DIR";
pub const CONFIG_DIR_ENV: &str = "AGENTJAIL_CONFIG_DIR";
pub const DATA_DIR_ENV: &str = "AGENTJAIL_DATA_DIR";
pub const STATE_DIR_ENV: &str = "AGENTJAIL_STATE_DIR";

fn lookup<'a>(env: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(String::as_str).filter(|v| !v.is_empty())
}

fn home(env: &BTreeMap<String, String>) -> PathBuf {
    if let Some(home) = lookup(env, "HOME") {
        return PathBuf::from(home);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn xdg(env: &BTreeMap<String, String>, key: &str, fallback: &str) -> PathBuf {
    match lookup(env, key) {
        Some(base) => PathBuf::from(base),
        None => home(env).join(fallback),
    }
}

/// Directory for user configuration, including profiles.
pub fn config_dir(env: &BTreeMap<String, String>) -> PathBuf {
    match lookup(env, CONFIG_DIR_ENV) {
        Some(path) => PathBuf::from(path),
        None => xdg(env, "XDG_CONFIG_HOME", ".config").join(APP_NAME),
    }
}

/// Directory for persistent data.
pub fn data_dir(env: &BTreeMap<String, String>) -> PathBuf {
    match lookup(env, DATA_DIR_ENV) {
        Some(path) => PathBuf::from(path),
        None => xdg(env, "XDG_DATA_HOME", ".local/share").join(APP_NAME),
    }
}

/// Directory for transient jail state.
pub fn state_dir(env: &BTreeMap<String, String>) -> PathBuf {
    match lookup(env, STATE_DIR_ENV) {
        Some(path) => PathBuf::from(path),
        None => xdg(env, "XDG_STATE_HOME", ".local/state").join(APP_NAME),
    }
}

/// Ordered directories searched for `<name>.toml` profiles.
///
/// `AGENTJAIL_PROFILE_DIR` wins, then `./profiles` (so a project can pin jails
/// next to its code), then the user config directory.
pub fn profile_search_dirs(env: &BTreeMap<String, String>, cwd: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(path) = lookup(env, PROFILE_DIR_ENV) {
        dirs.push(PathBuf::from(path));
    }
    dirs.push(cwd.join("profiles"));
    dirs.push(config_dir(env).join("profiles"));
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn xdg_defaults_are_used() {
        let env = env(&[("HOME", "/home/example")]);
        assert_eq!(
            config_dir(&env),
            PathBuf::from("/home/example/.config/agentjail")
        );
        assert_eq!(
            data_dir(&env),
            PathBuf::from("/home/example/.local/share/agentjail")
        );
        assert_eq!(
            state_dir(&env),
            PathBuf::from("/home/example/.local/state/agentjail")
        );
    }

    #[test]
    fn explicit_overrides_win() {
        let env = env(&[
            ("HOME", "/home/example"),
            ("XDG_CONFIG_HOME", "/xdg/config"),
            (CONFIG_DIR_ENV, "/custom/config"),
        ]);
        assert_eq!(config_dir(&env), PathBuf::from("/custom/config"));
    }

    #[test]
    fn profile_search_order_is_override_cwd_config() {
        let env = env(&[
            ("HOME", "/home/example"),
            (PROFILE_DIR_ENV, "/extra/profiles"),
        ]);
        let dirs = profile_search_dirs(&env, Path::new("/repo"));
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/extra/profiles"),
                PathBuf::from("/repo/profiles"),
                PathBuf::from("/home/example/.config/agentjail/profiles"),
            ]
        );
    }

    #[test]
    fn empty_override_is_ignored() {
        let env = env(&[("HOME", "/home/example"), (PROFILE_DIR_ENV, "")]);
        let dirs = profile_search_dirs(&env, Path::new("/repo"));
        assert_eq!(dirs.len(), 2);
    }
}
