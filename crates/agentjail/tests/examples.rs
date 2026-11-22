//! Repository invariants: example profiles, schema/model agreement, docs, and
//! the neutrality of the product.
//!
//! These tests are what keep the scaffolding honest: every example profile must
//! validate through the same path the CLI uses, the documented files must exist,
//! and no harness-, vendor-, or site-specific term may creep into the tree.

use std::path::{Path, PathBuf};

use agentjail_core::profile::{parse_and_validate, NetworkMode};
use agentjail_core::schema;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical repo root")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn example_profiles_all_validate() {
    let profiles_dir = repo_root().join("profiles");
    let mut checked = 0;
    for entry in std::fs::read_dir(&profiles_dir).expect("profiles dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let profile = parse_and_validate(&read(&path))
            .unwrap_or_else(|errors| panic!("{}: {errors:#?}", path.display()));
        assert!(
            profile.image.digest.starts_with("sha256:") && profile.image.digest.len() == 71,
            "{}: digest must be a full sha256 pin",
            path.display()
        );
        checked += 1;
    }
    assert!(checked >= 2, "expected at least two example profiles");
}

#[test]
fn example_profiles_cover_both_network_modes() {
    let mut modes = Vec::new();
    for entry in std::fs::read_dir(repo_root().join("profiles")).expect("profiles dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let text = read(&path);
        let profile = parse_and_validate(&text).expect("valid profile");
        modes.push(profile.network.mode);
    }
    assert!(modes.contains(&NetworkMode::None));
    assert!(modes.contains(&NetworkMode::Allowlist));
}

#[test]
fn example_agents_are_generic_shells() {
    for entry in std::fs::read_dir(repo_root().join("profiles")).expect("profiles dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let profile = parse_and_validate(&read(&path)).expect("valid profile");
        assert!(
            matches!(profile.agent.command.as_str(), "bash" | "sh"),
            "{}: example profiles must not require a particular agent",
            path.display()
        );
    }
}

#[test]
fn documented_paths_exist() {
    for relative in [
        "README.md",
        "LICENSE",
        "Cargo.toml",
        "rust-toolchain.toml",
        "docs/threat-model.md",
        "docs/profiles.md",
        "docs/adopting.md",
        "docs/cli.md",
        "images/README.md",
        "images/base/Containerfile",
        "images/base/entrypoint.sh",
        "schema/profile.schema.json",
        "profiles/minimal.toml",
        "profiles/allowlist.toml",
    ] {
        let path = repo_root().join(relative);
        assert!(path.is_file(), "missing documented file: {relative}");
    }
}

#[test]
fn readme_links_to_the_required_documents() {
    let readme = read(&repo_root().join("README.md"));
    for link in [
        "docs/threat-model.md",
        "docs/profiles.md",
        "docs/adopting.md",
        "docs/cli.md",
    ] {
        assert!(readme.contains(link), "README does not link {link}");
    }
}

#[test]
fn product_sources_are_harness_neutral() {
    // Built from pieces so this test file does not match its own needles.
    let forbidden = [
        ["OR", "CA_"].concat(),
        ["orca", "_session"].concat(),
        ["orca", " orchestration"].concat(),
        ["home", "lab"].concat(),
        ["bunker", "web"].concat(),
        ["broker", " token"].concat(),
    ];
    let forbidden: Vec<&str> = forbidden.iter().map(String::as_str).collect();
    let mut offenders = Vec::new();
    for directory in ["crates", "profiles", "schema"] {
        for path in walk(&repo_root().join(directory)) {
            if !matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("rs" | "toml" | "json")
            ) {
                continue;
            }
            let text = read(&path);
            for needle in &forbidden {
                if text.contains(*needle) {
                    offenders.push(format!("{}: {needle}", path.display()));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:#?}");
}

#[test]
fn no_real_credentials_are_committed() {
    // Built from pieces so this test file does not match its own needles.
    let suspicious = [
        ["gh", "p_"].concat(),
        ["github", "_pat_"].concat(),
        ["sk-", "ant-"].concat(),
        ["AK", "IA"].concat(),
        ["BEGIN ", "OPENSSH PRIVATE KEY"].concat(),
    ];
    let suspicious: Vec<&str> = suspicious.iter().map(String::as_str).collect();
    let mut offenders = Vec::new();
    for path in walk(&repo_root()) {
        let relative = path.strip_prefix(repo_root()).expect("relative");
        if relative
            .components()
            .any(|part| matches!(part.as_os_str().to_str(), Some(".git" | "target" | ".venv")))
        {
            continue;
        }
        if !matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("rs" | "md" | "toml" | "json" | "yml" | "yaml" | "sh" | "txt")
        ) && path.file_name().and_then(|name| name.to_str()) != Some("Containerfile")
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for needle in &suspicious {
            if text.contains(*needle) {
                offenders.push(format!("{}: {needle}", relative.display()));
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:#?}");
}

#[test]
fn embedded_schema_is_the_canonical_document() {
    let on_disk = read(&repo_root().join("schema/profile.schema.json"));
    assert_eq!(
        on_disk.trim(),
        schema::PROFILE_SCHEMA_JSON.trim(),
        "the embedded schema must be the canonical file"
    );
    assert!(schema::schema_document()["$defs"]["network"]["properties"]["name"].is_object());
}

#[test]
fn every_example_profile_validates_against_the_json_schema_alone() {
    for entry in std::fs::read_dir(repo_root().join("profiles")).expect("profiles dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let document: toml::Value = toml::from_str(&read(&path)).expect("valid TOML");
        let errors = schema::validate(&document);
        assert!(errors.is_empty(), "{}: {errors:#?}", path.display());
    }
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}
