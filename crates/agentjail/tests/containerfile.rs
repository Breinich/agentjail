//! Static Containerfile checks, in Rust so the product tree stays one language.
//!
//! These are the rules a reviewer would otherwise re-check on every change, and
//! the ones that matter for the threat model:
//!
//! * a tag is not a pin -- every `FROM` needs a digest;
//! * the final stage must not run as root;
//! * build-time `ENV` must not carry credentials;
//! * no `ADD` from a URL, and an `ENTRYPOINT`/`CMD` must exist.

use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Instruction {
    keyword: String,
    argument: String,
    line: usize,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical repo root")
}

fn parse(text: &str) -> (Vec<Instruction>, Vec<String>) {
    let mut instructions = Vec::new();
    let mut errors = Vec::new();
    let mut buffer = String::new();
    let mut buffer_line = 0;

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let trimmed = raw.trim();
        if buffer.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        if buffer.is_empty() {
            buffer_line = number;
        }
        if let Some(stripped) = trimmed.strip_suffix('\\') {
            buffer.push_str(stripped);
            buffer.push(' ');
            continue;
        }
        buffer.push_str(trimmed);
        let (keyword, argument) = buffer
            .split_once(' ')
            .map(|(keyword, argument)| (keyword.to_string(), argument.trim().to_string()))
            .unwrap_or_else(|| (buffer.clone(), String::new()));
        let keyword = keyword.to_ascii_uppercase();
        if !is_instruction(&keyword) {
            errors.push(format!(
                "line {buffer_line}: not a Dockerfile instruction: {keyword:?}"
            ));
        } else {
            instructions.push(Instruction {
                keyword,
                argument,
                line: buffer_line,
            });
        }
        buffer.clear();
    }
    if !buffer.is_empty() {
        let (keyword, argument) = buffer
            .split_once(' ')
            .map(|(keyword, argument)| (keyword.to_string(), argument.trim().to_string()))
            .unwrap_or((buffer.clone(), String::new()));
        instructions.push(Instruction {
            keyword: keyword.to_ascii_uppercase(),
            argument,
            line: buffer_line,
        });
    }
    (instructions, errors)
}

fn is_instruction(keyword: &str) -> bool {
    matches!(
        keyword,
        "ADD"
            | "ARG"
            | "CMD"
            | "COPY"
            | "ENTRYPOINT"
            | "ENV"
            | "EXPOSE"
            | "FROM"
            | "HEALTHCHECK"
            | "LABEL"
            | "MAINTAINER"
            | "ONBUILD"
            | "RUN"
            | "SHELL"
            | "STOPSIGNAL"
            | "USER"
            | "VOLUME"
            | "WORKDIR"
    )
}

fn is_digest_pinned(image: &str) -> bool {
    match image.rsplit_once("@sha256:") {
        Some((_, digest)) => digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
}

fn mentions_credential(argument: &str) -> bool {
    let upper = argument.to_ascii_uppercase();
    const NEEDLES: [&str; 8] = [
        "PASS",
        "PASSWD",
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "APIKEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
    ];
    NEEDLES.iter().any(|needle| upper.contains(needle))
}

fn check(text: &str, label: &str) -> Vec<String> {
    let (instructions, parse_errors) = parse(text);
    let mut problems: Vec<String> = parse_errors
        .into_iter()
        .map(|error| format!("{label}: {error}"))
        .collect();
    if instructions.is_empty() {
        problems.push(format!("{label}: no instructions found"));
        return problems;
    }

    let mut stages: Vec<Vec<&Instruction>> = Vec::new();
    for instruction in &instructions {
        if instruction.keyword == "FROM" {
            stages.push(vec![instruction]);
        } else if let Some(stage) = stages.last_mut() {
            stage.push(instruction);
        } else {
            problems.push(format!(
                "{label}:{}: instruction before the first FROM",
                instruction.line
            ));
        }
    }

    for (index, stage) in stages.iter().enumerate() {
        let from = stage[0];
        let image = from.argument.split_whitespace().next().unwrap_or("");
        if !is_digest_pinned(image) {
            problems.push(format!(
                "{label}:{}: base image {image:?} is not pinned by digest (expected @sha256:<64 hex>)",
                from.line
            ));
        }
        if index != stages.len() - 1 {
            continue;
        }

        match stage.iter().rev().find(|i| i.keyword == "USER") {
            None => problems.push(format!(
                "{label}: final stage never sets USER; it would run as root"
            )),
            Some(user) => {
                let name = user.argument.split(':').next().unwrap_or("").trim();
                if name == "root" || name == "0" {
                    problems.push(format!(
                        "{label}:{}: final stage runs as root ({name})",
                        user.line
                    ));
                }
            }
        }

        if !stage
            .iter()
            .any(|instruction| matches!(instruction.keyword.as_str(), "ENTRYPOINT" | "CMD"))
        {
            problems.push(format!("{label}: final stage has no ENTRYPOINT or CMD"));
        }

        for instruction in stage {
            if instruction.keyword == "ENV" && mentions_credential(&instruction.argument) {
                problems.push(format!(
                    "{label}:{}: ENV mentions a credential-like name; image builds must not carry secrets",
                    instruction.line
                ));
            }
            if instruction.keyword == "ADD"
                && (instruction.argument.starts_with("http://")
                    || instruction.argument.starts_with("https://"))
            {
                problems.push(format!(
                    "{label}:{}: ADD from a URL is not reproducible; use a digest-pinned COPY source",
                    instruction.line
                ));
            }
        }
    }
    problems
}

fn temp_containerfile(name: &str, text: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("containerfile-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("Containerfile");
    std::fs::write(&path, text).expect("write");
    path
}

const PIN: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn repository_containerfile_passes_all_checks() {
    let path = repo_root().join("images/base/Containerfile");
    let text = std::fs::read_to_string(&path).expect("read Containerfile");
    let problems = check(&text, &path.display().to_string());
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn repository_containerfile_pins_every_from_by_digest() {
    let text =
        std::fs::read_to_string(repo_root().join("images/base/Containerfile")).expect("read");
    let froms: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("FROM "))
        .collect();
    assert!(!froms.is_empty());
    for line in froms {
        let image = line.split_whitespace().nth(1).expect("image");
        assert!(is_digest_pinned(image), "{line} is not digest-pinned");
    }
}

#[test]
fn unpinned_from_is_rejected() {
    let path = temp_containerfile(
        "unpinned",
        "FROM node:24-bookworm-slim\nUSER 1000\nCMD [\"bash\"]\n",
    );
    let text = std::fs::read_to_string(&path).expect("read");
    let problems = check(&text, "unpinned");
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("not pinned by digest")),
        "{problems:#?}"
    );
}

#[test]
fn root_user_in_final_stage_is_rejected() {
    let text = format!("FROM debian@{PIN}\nUSER root\nCMD [\"bash\"]\n");
    let problems = check(&text, "root");
    assert!(problems
        .iter()
        .any(|problem| problem.contains("runs as root")));
}

#[test]
fn missing_user_is_rejected() {
    let text = format!("FROM debian@{PIN}\nCMD [\"bash\"]\n");
    let problems = check(&text, "missing-user");
    assert!(problems
        .iter()
        .any(|problem| problem.contains("never sets USER")));
}

#[test]
fn missing_entrypoint_is_rejected() {
    let text = format!("FROM debian@{PIN}\nUSER 1000\nRUN true\n");
    let problems = check(&text, "missing-entrypoint");
    assert!(problems
        .iter()
        .any(|problem| problem.contains("no ENTRYPOINT or CMD")));
}

#[test]
fn credential_like_env_is_rejected() {
    let text = format!("FROM debian@{PIN}\nENV GITHUB_TOKEN=abc\nUSER 1000\nCMD [\"bash\"]\n");
    let problems = check(&text, "env");
    assert!(problems
        .iter()
        .any(|problem| problem.contains("credential-like name")));
}

#[test]
fn add_from_url_is_rejected() {
    let text =
        format!("FROM debian@{PIN}\nADD https://example.com/x /x\nUSER 1000\nCMD [\"bash\"]\n");
    let problems = check(&text, "add");
    assert!(problems
        .iter()
        .any(|problem| problem.contains("ADD from a URL")));
}

#[test]
fn unknown_instruction_is_rejected() {
    let text = format!("FROM debian@{PIN}\nBOGUS thing\nUSER 1000\nCMD [\"bash\"]\n");
    let problems = check(&text, "unknown");
    assert!(problems
        .iter()
        .any(|problem| problem.contains("not a Dockerfile instruction")));
}

#[test]
fn only_the_final_stage_needs_user() {
    let text = format!(
        "FROM debian@{PIN} AS builder\nRUN make\nFROM debian@{PIN}\nCOPY --from=builder /out /out\nUSER 1000\nCMD [\"/out/thing\"]\n"
    );
    assert!(check(&text, "multistage").is_empty());
}

#[test]
fn continuations_are_joined() {
    let text = format!(
        "FROM debian@{PIN}\nRUN apt-get update \\\n && apt-get install -y curl \\\n && rm -rf /var/lib/apt/lists/*\nUSER 1000\nCMD [\"bash\"]\n"
    );
    assert!(check(&text, "continuation").is_empty());
}
