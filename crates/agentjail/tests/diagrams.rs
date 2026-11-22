//! Diagram policy enforcement.
//!
//! Diagrams are PlantUML: `.puml` source in `docs/diagrams/`, rendered `.svg`
//! committed next to it, Markdown embeds the SVG. CI renders with a
//! digest-pinned PlantUML image, `-checkonly` first (so a syntax error fails the
//! build), then `git diff --exit-code docs/diagrams` (so a stale or hand-edited
//! SVG fails too).
//!
//! These tests cover the parts that can be checked without Java: no Mermaid is
//! left behind, every source has an up-to-date-looking SVG, every Markdown
//! reference resolves, and the policy is written down.

use std::path::{Path, PathBuf};

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

fn diagram_sources() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(repo_root().join("docs/diagrams"))
        .expect("diagrams dir")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("puml"))
        .collect();
    files.sort();
    files
}

#[test]
fn no_mermaid_is_left_behind() {
    for file in markdown_files() {
        let text = std::fs::read_to_string(&file).expect("read markdown");
        assert!(
            !text.contains("```mermaid"),
            "{}: Mermaid is no longer the diagram language; use PlantUML",
            file.display()
        );
    }
}

#[test]
fn every_puml_source_has_a_rendered_svg() {
    let sources = diagram_sources();
    assert!(sources.len() >= 2, "expected at least two diagrams");
    for source in sources {
        let svg = source.with_extension("svg");
        assert!(
            svg.is_file(),
            "missing rendered SVG for {}",
            source.display()
        );
        let contents = std::fs::read_to_string(&svg).expect("read svg");
        assert!(
            contents.starts_with("<svg"),
            "{} is not an SVG",
            svg.display()
        );
        assert!(
            contents.contains("data-diagram-type"),
            "{} does not look like a PlantUML render",
            svg.display()
        );
    }
}

#[test]
fn every_svg_has_a_source() {
    for entry in std::fs::read_dir(repo_root().join("docs/diagrams")).expect("diagrams dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("svg") {
            continue;
        }
        let source = path.with_extension("puml");
        assert!(
            source.is_file(),
            "{} has no .puml source; the SVG must be generated, never hand-edited",
            path.display()
        );
    }
}

#[test]
fn puml_sources_are_well_formed_umm_fences() {
    for source in diagram_sources() {
        let text = std::fs::read_to_string(&source).expect("read puml");
        let first = text.lines().next().unwrap_or("").trim();
        let last = text.lines().last().unwrap_or("").trim();
        assert!(
            first.starts_with("@startuml"),
            "{} does not start with @startuml",
            source.display()
        );
        assert!(
            last == "@enduml" || text.contains("\n@enduml"),
            "{} has no @enduml",
            source.display()
        );
        assert!(
            text.contains("title "),
            "{} has no title line",
            source.display()
        );
    }
}

#[test]
fn markdown_embeds_the_diagrams() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("read");
    assert!(readme.contains("docs/diagrams/deployment.svg"));

    let cli = std::fs::read_to_string(repo_root().join("docs/cli.md")).expect("read");
    assert!(cli.contains("diagrams/launcher-sequence.svg"));
    assert!(cli.contains("diagrams/run-lifecycle.svg"));

    let threat = std::fs::read_to_string(repo_root().join("docs/threat-model.md")).expect("read");
    assert!(threat.contains("diagrams/deployment.svg"));
}

#[test]
fn embedded_svg_references_resolve() {
    let root = repo_root();
    for file in markdown_files() {
        let text = std::fs::read_to_string(&file).expect("read markdown");
        let base = file.parent().expect("parent");
        for (index, segment) in text.split("](").enumerate().skip(1) {
            let Some(end) = segment.find(')') else {
                continue;
            };
            let target = &segment[..end];
            if !target.ends_with(".svg") {
                continue;
            }
            assert!(
                base.join(target).is_file(),
                "{}: reference {target} does not resolve",
                file.display()
            );
            let _ = index;
        }
    }
    assert!(root.join("docs/diagrams/deployment.svg").is_file());
}

#[test]
fn the_policy_and_its_reasoning_are_documented() {
    let adopting = std::fs::read_to_string(repo_root().join("docs/adopting.md")).expect("read");
    assert!(adopting.contains("PlantUML"));
    assert!(adopting.contains("plantuml/plantuml@sha256:"));
    assert!(adopting.contains("-checkonly"));
    assert!(adopting.contains("git diff --exit-code docs/diagrams"));
    // The proxy is documented as rejected, with the reason.
    assert!(adopting.contains("plantuml.com/plantuml/proxy"));
    assert!(adopting.contains("unauthenticated"));
}
