//! Repository policy: every workflow action is pinned by commit SHA.
//!
//! The repository's Actions policy sets `sha_pinning_required: true`, so a
//! tag-pinned `uses:` is rejected rather than warned about. This test fails the
//! build if a workflow reintroduces `@v4`, `@stable`, or any other moving ref,
//! and requires the version to be visible in a trailing comment
//! (`uses: owner/action@<40 hex> # v4.4.0`).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical repo root")
}

fn workflows() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(repo_root().join(".github/workflows"))
        .expect("workflows dir")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("yml" | "yaml")
            )
        })
        .collect();
    files.sort();
    files
}

/// Returns a problem description when the `uses:` value is not SHA-pinned.
fn check_uses(value: &str) -> Option<String> {
    let (target, comment) = match value.split_once('#') {
        Some((target, comment)) => (target.trim(), Some(comment.trim())),
        None => (value.trim(), None),
    };
    let Some((action, reference)) = target.rsplit_once('@') else {
        return Some(format!("{target:?} has no @<sha> reference"));
    };
    if reference.len() != 40 || !reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(format!(
            "{action}@{reference} is not a full 40-character commit SHA"
        ));
    }
    match comment {
        None | Some("") => Some(format!(
            "{action}@{reference} has no trailing version comment (expected `# v4.4.0`)"
        )),
        Some(_) => None,
    }
}

#[test]
fn every_workflow_action_is_pinned_by_commit_sha() {
    let files = workflows();
    assert!(!files.is_empty(), "expected at least one workflow");
    let mut problems = Vec::new();
    let mut checked = 0;
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read workflow");
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            let Some(value) = trimmed.strip_prefix("uses:") else {
                continue;
            };
            checked += 1;
            if let Some(problem) = check_uses(value) {
                problems.push(format!("{}:{}: {problem}", file.display(), index + 1));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert!(checked >= 3, "expected to check at least three uses: lines");
}

#[test]
fn tag_pins_are_detected() {
    for bad in [
        "actions/checkout@v4",
        "dtolnay/rust-toolchain@stable",
        "actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af6772 # v4.4.0",
    ] {
        assert!(
            check_uses(bad).is_some(),
            "{bad:?} should be rejected by the pinning check"
        );
    }
}

#[test]
fn a_pinned_action_with_a_version_comment_passes() {
    assert_eq!(
        check_uses(" actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0"),
        None
    );
}

#[test]
fn triggers_stay_as_the_owner_decided() {
    // The owner decides the trigger set; this test only records the current
    // decision so a change is deliberate. It is intentionally about the keys
    // present, not about forbidding a future decision.
    let text = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect("read ci workflow");
    let triggers = text
        .lines()
        .skip_while(|line| !line.starts_with("on:"))
        .take_while(|line| !line.starts_with("permissions:"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(triggers.contains("pull_request"), "{triggers}");
    assert!(triggers.contains("workflow_dispatch"), "{triggers}");
    assert!(
        !triggers.contains("push:"),
        "no speculative push trigger: {triggers}"
    );
}
