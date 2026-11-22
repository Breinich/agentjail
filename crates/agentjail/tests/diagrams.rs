//! Diagram policy enforcement.
//!
//! Diagrams in this repository are UML-shaped Mermaid: `sequenceDiagram` for
//! interactions, `stateDiagram-v2` for lifecycle, `classDiagram`/`erDiagram`
//! for data models. Mermaid `flowchart`/`graph` is not UML and is rejected for
//! architecture and behaviour, because it accepts relationships that mean
//! nothing.
//!
//! This is a type-level lint, not a full Mermaid syntax check: it fails the
//! build when a block is empty, uses a forbidden diagram type, or contains no
//! interaction/transition at all. Full syntax validation needs
//! `@mermaid-js/mermaid-cli` and a headless Chromium; that cost is documented in
//! `docs/adopting.md` and in the PR that introduced this policy.

use std::path::{Path, PathBuf};

const ALLOWED_TYPES: [&str; 4] = [
    "sequenceDiagram",
    "stateDiagram-v2",
    "classDiagram",
    "erDiagram",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical repo root")
}

fn markdown_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = vec![root.join("README.md")];
    for entry in std::fs::read_dir(root.join("docs")).expect("docs dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
            files.push(path);
        }
    }
    files
}

/// Returns `(start line, block body)` for each ```mermaid fence.
fn mermaid_blocks(text: &str) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some((start, body)) = current.as_mut() {
            if trimmed == "```" {
                let start = *start;
                blocks.push((start, std::mem::take(body)));
                current = None;
            } else {
                body.push_str(line);
                body.push('\n');
            }
        } else if trimmed == "```mermaid" {
            current = Some((index + 1, String::new()));
        }
    }
    blocks
}

#[test]
fn every_mermaid_block_uses_a_uml_diagram_type() {
    let mut checked = 0;
    let mut problems = Vec::new();
    for file in markdown_files() {
        let text = std::fs::read_to_string(&file).expect("read markdown");
        for (line, body) in mermaid_blocks(&text) {
            let Some(first) = body.lines().map(str::trim).find(|line| !line.is_empty()) else {
                problems.push(format!("{}:{line}: empty mermaid block", file.display()));
                continue;
            };
            if first.starts_with("flowchart") || first == "graph" || first.starts_with("graph ") {
                problems.push(format!(
                    "{}:{line}: {first:?} is not UML; use sequenceDiagram, stateDiagram-v2, classDiagram, or erDiagram",
                    file.display()
                ));
                continue;
            }
            if !ALLOWED_TYPES.contains(&first) {
                problems.push(format!(
                    "{}:{line}: unknown diagram type {first:?}; allowed: {}",
                    file.display(),
                    ALLOWED_TYPES.join(", ")
                ));
                continue;
            }
            let has_interaction = body.lines().any(|line| {
                let line = line.trim();
                line.contains("->>")
                    || line.contains("-->>")
                    || line.contains("-)")
                    || line.contains("-x")
                    || line.contains("-->")
            });
            if !has_interaction {
                problems.push(format!(
                    "{}:{line}: {first} has no interaction or transition",
                    file.display()
                ));
            }
            checked += 1;
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert!(
        checked >= 3,
        "expected the README and docs to carry at least three UML diagrams, found {checked}"
    );
}

#[test]
fn forbidden_mermaid_types_are_detected() {
    let text = "# x\n\n```mermaid\nflowchart LR\n    a --> b\n```\n";
    let blocks = mermaid_blocks(text);
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].1.trim_start().starts_with("flowchart"));
}

#[test]
fn the_policy_is_documented() {
    let adopting = std::fs::read_to_string(repo_root().join("docs/adopting.md")).expect("read");
    assert!(adopting.contains("sequenceDiagram"));
    assert!(adopting.contains("stateDiagram-v2"));
    assert!(adopting.contains("mermaid-cli"));
}
