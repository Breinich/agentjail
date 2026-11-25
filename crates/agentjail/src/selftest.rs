//! `agentjail selftest`: one harness, two executors.
//!
//! The assertion functions below are the same in `--baseline` and jailed mode;
//! the only difference is **where the probe runs**. In baseline mode the probe
//! is a plain host process and every negative must be *observably false* (the
//! hazard happens), which proves the assertion is not vacuous. In jailed mode
//! the same probe runs inside a real jail and every negative must be denied.
//!
//! The probe is `agentjail __probe`, a hidden subcommand of this same binary.
//! Jailed mode bind-mounts a copy of the binary read-only and runs that copy
//! inside the jail, so the code path is identical, not a shell imitation. The
//! binary must be runnable in the jail image: CI uses the static musl build, and
//! a supplied profile's image must be compatible with the host binary otherwise.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentjail_core::paths;
use agentjail_core::podman;
use agentjail_core::profile::Profile;
use agentjail_core::run;
use serde_json::{json, Value};

const SELFTEST_IMAGE: &str = "docker.io/library/node";
const SELFTEST_DIGEST: &str =
    "sha256:0e2646ab57e77b7a384a0cb59b6815b182c77e1f9c3ba36bd8435bd9c4e6680e";
const TARGET_PORT_ALLOWED: u16 = 9001;
const TARGET_PORT_DENIED: u16 = 9002;
const MEMORY_LIMIT: u64 = 128 * 1024 * 1024;
const NOFILE_LIMIT: u64 = 128;
const PIDS_LIMIT: u32 = 64;
const MOUNTED_PROBE: &str = "/opt/agentjail/agentjail";

#[derive(Clone)]
struct Target {
    image_name: String,
    image_digest: String,
    workdir: String,
    home: String,
}

impl Target {
    fn default_profile() -> Self {
        Self {
            image_name: SELFTEST_IMAGE.to_string(),
            image_digest: SELFTEST_DIGEST.to_string(),
            workdir: "/tmp".to_string(),
            home: "/home/agent".to_string(),
        }
    }

    fn from_profile(profile: &Profile) -> Self {
        Self {
            image_name: profile.image.name.clone(),
            image_digest: profile.image.digest.clone(),
            workdir: profile.workdir.clone(),
            home: profile.home.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Expected,
    Pass,
    Fail,
    SkippedBaseline,
}

impl Verdict {
    fn as_str(&self) -> &'static str {
        match self {
            Verdict::Expected => "EXPECTED",
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::SkippedBaseline => "SKIPPED-BASELINE",
        }
    }
}

struct CaseResult {
    name: &'static str,
    mode: &'static str,
    expected: String,
    observed: String,
    verdict: Verdict,
}

pub struct Options {
    pub baseline: bool,
    pub json: bool,
}

pub fn run(
    profile: Option<&Profile>,
    options: &Options,
    env: &std::collections::BTreeMap<String, String>,
    cwd: &Path,
) -> Result<u8, String> {
    let target = profile
        .map(Target::from_profile)
        .unwrap_or_else(Target::default_profile);
    let results = match if options.baseline {
        run_baseline(&target)
    } else {
        run_jailed(&target, env, cwd)
    } {
        Ok(results) => results,
        Err(error) => setup_failures(
            if options.baseline {
                "baseline"
            } else {
                "jailed"
            },
            &error,
        ),
    };

    if options.json {
        let cases: Vec<Value> = results
            .iter()
            .map(|result| {
                json!({
                    "case": result.name,
                    "mode": result.mode,
                    "expected": result.expected,
                    "observed": result.observed,
                    "verdict": result.verdict.as_str(),
                })
            })
            .collect();
        let failing: Vec<&str> = results
            .iter()
            .filter(|result| result.verdict == Verdict::Fail)
            .map(|result| result.name)
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "mode": if options.baseline { "baseline" } else { "jailed" },
                "ok": failing.is_empty(),
                "cases": cases,
                "failing_cases": failing,
            }))
            .unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        for result in &results {
            println!(
                "case={} mode={} expected=\"{}\" observed=\"{}\" verdict={}",
                result.name,
                result.mode,
                result.expected,
                result.observed,
                result.verdict.as_str()
            );
        }
    }

    let failing: Vec<&str> = results
        .iter()
        .filter(|result| result.verdict == Verdict::Fail)
        .map(|result| result.name)
        .collect();
    if failing.is_empty() {
        Ok(0)
    } else {
        Err(format!(
            "selftest failed: {} (mode {})",
            failing.join(", "),
            if options.baseline {
                "baseline: a negative did not hold without the jail, so the assertion is weak"
            } else {
                "jailed: the jail did not deny a negative or the positive control failed"
            }
        ))
    }
}

// ----------------------------------------------------------------- baseline

fn run_baseline(target: &Target) -> Result<Vec<CaseResult>, String> {
    let dir = temp_dir("baseline");
    let host_secret = dir.join("host-only-secret");
    std::fs::write(&host_secret, b"selftest-host-secret-value")
        .map_err(|error| format!("cannot write host secret fixture: {error}"))?;

    // A plain host listener is the reachable destination in baseline mode: no
    // podman, no jail, no proxy. The same probe then finds it reachable, which
    // is exactly what the negative assertions must reject.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("cannot start host baseline listener: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("cannot read baseline listener address: {error}"))?
        .port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(b"hello from host baseline\n");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });

    let executable = current_exe()?;
    let args = probe_args(
        "main",
        "baseline",
        &host_secret.to_string_lossy(),
        "127.0.0.1",
        "127.0.0.1",
        port,
        port,
        "nested",
        "owner",
        "",
        "",
        1000,
        0,
    );
    let output = Command::new(&executable)
        .args(&args)
        .env("AGENTJAIL_SELFTEST_SECRET", "host-secret-value")
        .output()
        .map_err(|error| format!("cannot run the baseline probe: {error}"))?;
    stop.store(true, Ordering::SeqCst);
    let _ = server.join();

    let observation = parse_probe(&output, "baseline probe")?;
    let results = vec![
        evaluate("host-secret", "baseline", &observation, None),
        evaluate("outside-allowlist", "baseline", &observation, None),
        evaluate("raw-ip", "baseline", &observation, None),
        evaluate("network-control", "baseline", &observation, None),
        skipped(
            "jail-isolation",
            "baseline",
            "there is no jail in baseline mode, so there are not two jails to compare",
        ),
        evaluate("resource-limits", "baseline", &observation, None),
        evaluate("net-admin", "baseline", &observation, None),
        skipped(
            "positive-control",
            "baseline",
            "baseline mode has no proxy and no gateway audit stream",
        ),
    ];

    let _ = std::fs::remove_dir_all(&dir);
    let _ = target;
    Ok(results)
}

// ------------------------------------------------------------------- jailed

fn run_jailed(
    target: &Target,
    env: &std::collections::BTreeMap<String, String>,
    cwd: &Path,
) -> Result<Vec<CaseResult>, String> {
    let dir = temp_dir("jailed");
    let mut cleanup = Cleanup::new(dir.clone());

    let main_probe = stage_probe(&dir, "agentjail-probe-main")?;

    let host_secret = dir.join("host-only-secret");
    std::fs::write(&host_secret, b"selftest-host-secret-value")
        .map_err(|error| format!("cannot write host secret fixture: {error}"))?;

    // The fixture destination is its own container, on a network the gateway
    // uses as its outbound leg. It listens on one allowed and one denied port.
    let egress_network = format!("agentjail-selftest-egress-{}", std::process::id());
    cleanup.networks.push(egress_network.clone());
    podman_ok(&["network", "create", "--ipv6=false", &egress_network])?;
    let target_name = format!("agentjail-selftest-target-{}", std::process::id());
    cleanup.containers.push(target_name.clone());
    let target_image = std::env::var("AGENTJAIL_SELFTEST_TARGET_IMAGE")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{SELFTEST_IMAGE}@{SELFTEST_DIGEST}"));
    podman_ok(&["image", "exists", &target_image]).map_err(|error| {
        format!("{error}\npull the selftest target image first: podman pull {target_image}")
    })?;
    let server = format!(
        "const net=require('net');[{TARGET_PORT_ALLOWED},{TARGET_PORT_DENIED}].forEach(p=>net.createServer(s=>{{s.end('hello from '+p+'\\n')}}).listen(p,'0.0.0.0'));setInterval(()=>{{}},1<<30);"
    );
    podman_ok(&[
        "run",
        "-d",
        "--rm",
        "--name",
        &target_name,
        "--network",
        &egress_network,
        &target_image,
        "node",
        "-e",
        &server,
    ])?;
    let target_ip = wait_for_target_ip(&target_name)?;

    let classes = dir.join("classes");
    std::fs::create_dir_all(&classes)
        .map_err(|error| format!("cannot make class directory: {error}"))?;
    // The fixture is a container on the egress network, so its name resolves to
    // RFC1918 space: `address_policy = "lan"` is what lets this generated class
    // reach it. Loopback, link-local, CGNAT and the mapped spellings stay
    // refused, exactly as in a committed class.
    let class_config = format!(
        "class = \"selftest\"\nlisten = \"0.0.0.0:3128\"\ndns = \"0.0.0.0:53\"\n\
         max_bytes = 67108864\nmax_connections = 8\naddress_policy = \"lan\"\n\
         allow = [\n  \"{}:{}\",\n]\n",
        target_name, TARGET_PORT_ALLOWED
    );
    let class_path = classes.join("selftest.toml");
    std::fs::write(&class_path, class_config)
        .map_err(|error| format!("cannot write selftest class config: {error}"))?;
    let class_digest = agentjail_core::class::file_digest(&class_path)
        .map_err(|error| format!("cannot digest the selftest class config: {error}"))?;

    let main_profile = dir.join("selftest-main.toml");
    std::fs::write(
        &main_profile,
        profile_text(
            target,
            &main_probe,
            Some((&target_name, TARGET_PORT_ALLOWED)),
            None,
            None,
            Some((&classes, &class_digest)),
        ),
    )
    .map_err(|error| format!("cannot write selftest profile: {error}"))?;

    let mut child_env = env.clone();
    child_env.insert(
        "AGENTJAIL_EGRESS_NETWORK".to_string(),
        egress_network.clone(),
    );
    child_env.insert(
        "AGENTJAIL_SELFTEST_SECRET".to_string(),
        "host-secret-value".to_string(),
    );
    child_env.insert(
        "AGENTJAIL_STATE_DIR".to_string(),
        dir.join("state").to_string_lossy().into_owned(),
    );

    let probe = probe_args(
        "main",
        "jailed",
        &host_secret.to_string_lossy(),
        &target_name,
        &target_ip,
        TARGET_PORT_ALLOWED,
        TARGET_PORT_DENIED,
        "current",
        "owner",
        "",
        "",
        1000,
        0,
    );
    let (output, audit, audit_view, jail_id) = run_in_jail(
        &main_profile,
        &probe,
        &child_env,
        cwd,
        "selftest-main",
        &classes,
        &class_digest,
    )?;
    let observation = parse_probe(&output, "jailed probe")?;

    // Two concurrent jails, each with its own home and its own token. Each
    // writes a marker and a socket under the same path and then looks for the
    // other's; a shared home would make both visible.
    let peer_a = format!("agentjail-selftest-peer-a-{}", std::process::id());
    let peer_b = format!("agentjail-selftest-peer-b-{}", std::process::id());
    cleanup.networks.push(peer_a.clone());
    cleanup.networks.push(peer_b.clone());
    podman_ok(&[
        "network",
        "create",
        "--internal",
        "--disable-dns",
        "--ipv6=false",
        &peer_a,
    ])?;
    podman_ok(&[
        "network",
        "create",
        "--internal",
        "--disable-dns",
        "--ipv6=false",
        &peer_b,
    ])?;

    let token_a = random_token("owner");
    let token_b = random_token("prober");
    let probe_a = stage_probe(&dir, "agentjail-probe-a")?;
    let probe_b = stage_probe(&dir, "agentjail-probe-b")?;
    let profile_a = dir.join("selftest-peer-a.toml");
    let profile_b = dir.join("selftest-peer-b.toml");
    // Each concurrent jail gets its own copy: podman's `:Z` relabels the source
    // per container, so two live mounts of one file would fight over the label.
    std::fs::write(
        &profile_a,
        profile_text(target, &probe_a, None, Some(&peer_a), Some(&token_a), None),
    )
    .map_err(|error| format!("cannot write peer profile: {error}"))?;
    std::fs::write(
        &profile_b,
        profile_text(target, &probe_b, None, Some(&peer_b), Some(&token_b), None),
    )
    .map_err(|error| format!("cannot write peer profile: {error}"))?;

    let probe_a = probe_args(
        "isolation",
        "jailed",
        "",
        "",
        "",
        0,
        0,
        "current",
        "owner",
        &token_a,
        &token_b,
        6000,
        0,
    );
    let probe_b = probe_args(
        "isolation",
        "jailed",
        "",
        "",
        "",
        0,
        0,
        "current",
        "prober",
        &token_b,
        &token_a,
        2000,
        0,
    );
    let child_a = spawn_in_jail(&profile_a, &probe_a, &child_env, cwd)?;
    let child_b = spawn_in_jail(&profile_b, &probe_b, &child_env, cwd)?;
    let output_a = wait_child(child_a, "peer jail A")?;
    let output_b = wait_child(child_b, "peer jail B")?;
    let peer_a = parse_probe(&output_a, "peer jail A")?;
    let peer_b = parse_probe(&output_b, "peer jail B")?;

    let isolation = json!({
        "owner": peer_a,
        "prober": peer_b,
    });

    let results = vec![
        evaluate("host-secret", "jailed", &observation, None),
        evaluate("outside-allowlist", "jailed", &observation, None),
        evaluate("raw-ip", "jailed", &observation, None),
        evaluate("network-control", "jailed", &observation, None),
        evaluate_isolation(&isolation),
        evaluate("resource-limits", "jailed", &observation, None),
        evaluate("net-admin", "jailed", &observation, None),
        evaluate("positive-control", "jailed", &observation, Some(&audit)),
        evaluate_audit_after_run(&audit_view, &jail_id),
    ];

    drop(cleanup);
    Ok(results)
}

fn run_in_jail(
    profile: &Path,
    probe: &[String],
    env: &std::collections::BTreeMap<String, String>,
    cwd: &Path,
    profile_name: &str,
    class_dir: &Path,
    class_digest: &str,
) -> Result<(Output, String, String, String), String> {
    let child = spawn_in_jail(profile, probe, env, cwd)?;
    let jail_id = format!("{profile_name}-{}", child.id());
    // The selftest's allowlist class is generated per run and pinned by digest,
    // so its files are under that class name and the state directory `run` got.
    let audit_path = run::audit_dir(&paths::state_dir(env), "selftest")
        .join(run::audit_file_name(&jail_id, "audit"));
    let output = wait_child(child, "jailed probe")?;
    let audit_file = std::fs::read_to_string(&audit_path).unwrap_or_default();
    // The documented command, run after the jail and gateway are gone. This is
    // in the jailed selftest on purpose: CI already pays for the jail here, so
    // the acceptance check runs on every push instead of only when remembered.
    let audit_view = read_audit_view(env, class_dir, class_digest)?;
    Ok((output, audit_file, audit_view, jail_id))
}

fn read_audit_view(
    env: &std::collections::BTreeMap<String, String>,
    class_dir: &Path,
    class_digest: &str,
) -> Result<String, String> {
    let output = Command::new(current_exe()?)
        .args([
            "audit",
            "--class",
            "selftest",
            "--class-dir",
            &class_dir.to_string_lossy(),
            "--class-digest",
            class_digest,
        ])
        .envs(env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("cannot run agentjail audit: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "agentjail audit exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn spawn_in_jail(
    profile: &Path,
    probe: &[String],
    env: &std::collections::BTreeMap<String, String>,
    cwd: &Path,
) -> Result<Child, String> {
    let mut command = Command::new(current_exe()?);
    command
        .current_dir(cwd)
        .arg("run")
        .arg(profile)
        .arg("--")
        .arg(MOUNTED_PROBE)
        .args(probe)
        .envs(env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .spawn()
        .map_err(|error| format!("cannot start agentjail run: {error}"))
}

fn wait_child(child: Child, label: &str) -> Result<Output, String> {
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for {label}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{label} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output)
}

fn wait_for_target_ip(name: &str) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(output) = podman::podman(&[
            "container",
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ]) {
            let address = output.stdout.trim();
            if !address.is_empty() {
                return Ok(address.to_string());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "selftest target {name:?} did not get an address within 20s"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn podman_ok(args: &[&str]) -> Result<(), String> {
    let output = podman::podman(args)?;
    if output.success() {
        Ok(())
    } else {
        Err(format!(
            "podman {} failed ({}): {}",
            args.join(" "),
            output.code,
            output.stderr.trim()
        ))
    }
}

// -------------------------------------------------------------- case results

fn evaluate(
    name: &'static str,
    mode: &'static str,
    observation: &Value,
    audit: Option<&str>,
) -> CaseResult {
    let hazard = hazard(name, observation, audit);
    let (expected, observed) = match name {
        "host-secret" => (
            if mode == "baseline" {
                "host file and host environment variable are reachable"
            } else {
                "host file unreadable and host environment variable absent"
            },
            format!(
                "file={} env={}",
                observation["host_file"].as_str().unwrap_or("missing"),
                observation["host_env"].as_str().unwrap_or("missing")
            ),
        ),
        "outside-allowlist" => (
            if mode == "baseline" {
                "a destination outside the allowlist is reachable"
            } else {
                "a destination outside the allowlist is unreachable"
            },
            format!(
                "direct={} proxy={} reachable={}",
                observation["outside"]["direct"]
                    .as_str()
                    .unwrap_or("missing"),
                observation["outside"]["proxy"]
                    .as_str()
                    .unwrap_or("missing"),
                observation["outside"]["reachable"]
                    .as_bool()
                    .unwrap_or(false)
            ),
        ),
        "raw-ip" => (
            if mode == "baseline" {
                "a raw IP:port is reachable"
            } else {
                "a raw IP:port is refused"
            },
            format!(
                "direct={} proxy={} reachable={}",
                observation["raw_ip"]["direct"]
                    .as_str()
                    .unwrap_or("missing"),
                observation["raw_ip"]["proxy"].as_str().unwrap_or("missing"),
                observation["raw_ip"]["reachable"]
                    .as_bool()
                    .unwrap_or(false)
            ),
        ),
        "network-control" => (
            if mode == "baseline" {
                "a process with no jail can add a route, create an interface and attach a peer"
            } else {
                "route, interface and peer changes are refused"
            },
            format!(
                "namespace={} route={} interface={} peer={}",
                observation["network"]["namespace"]
                    .as_str()
                    .unwrap_or("missing"),
                observation["network"]["route"]
                    .as_str()
                    .unwrap_or("missing"),
                observation["network"]["interface"]
                    .as_str()
                    .unwrap_or("missing"),
                observation["network"]["peer"].as_str().unwrap_or("missing")
            ),
        ),
        "resource-limits" => (
            if mode == "baseline" {
                "the test limits are not enforced without the jail"
            } else {
                "memory, pids and nofile limits are enforced"
            },
            format!(
                "nofile_opened={}/{} pids_spawned={}/{} memory={}",
                observation["nofile"]["opened"].as_u64().unwrap_or(0),
                NOFILE_LIMIT,
                observation["pids"]["spawned"].as_u64().unwrap_or(0),
                PIDS_LIMIT,
                observation["memory"]["exit"].as_str().unwrap_or("missing")
            ),
        ),
        "net-admin" => (
            if mode == "baseline" {
                "CAP_NET_ADMIN is available without the jail"
            } else {
                "CAP_NET_ADMIN is unavailable in the jail"
            },
            format!(
                "cap_net_admin={} namespace={}",
                observation["cap_net_admin"].as_bool().unwrap_or(false),
                observation["network"]["namespace"]
                    .as_str()
                    .unwrap_or("missing")
            ),
        ),
        "positive-control" => (
            "one allowed destination answers through the proxy and its audit line appears",
            format!(
                "status={} body={} audit={}",
                observation["positive"]["status"]
                    .as_str()
                    .unwrap_or("missing"),
                observation["positive"]["body"]
                    .as_str()
                    .unwrap_or("missing"),
                if audit
                    .map(|text| text.contains("decision=allow"))
                    .unwrap_or(false)
                {
                    "allow-line-present"
                } else {
                    "missing"
                }
            ),
        ),
        _ => ("unknown case", "unknown".to_string()),
    };

    let verdict = if mode == "baseline" {
        if hazard {
            Verdict::Expected
        } else {
            Verdict::Fail
        }
    } else if hazard {
        Verdict::Fail
    } else {
        Verdict::Pass
    };
    CaseResult {
        name,
        mode,
        expected: expected.to_string(),
        observed,
        verdict,
    }
}

fn hazard(name: &str, observation: &Value, audit: Option<&str>) -> bool {
    match name {
        "host-secret" => {
            observation["host_file"].as_str() == Some("read")
                || observation["host_env"].as_str() == Some("present")
        }
        "outside-allowlist" | "raw-ip" => {
            let key = if name == "outside-allowlist" {
                "outside"
            } else {
                "raw_ip"
            };
            observation[key]["reachable"].as_bool().unwrap_or(false)
        }
        "network-control" => ["route", "interface", "peer"]
            .iter()
            .any(|key| observation["network"][key].as_str() == Some("ok")),
        "resource-limits" => {
            let nofile = observation["nofile"]["opened"].as_u64().unwrap_or(u64::MAX);
            let pids = observation["pids"]["spawned"].as_u64().unwrap_or(u64::MAX);
            let memory = observation["memory"]["exit"].as_str().unwrap_or("missing");
            nofile > NOFILE_LIMIT || pids > u64::from(PIDS_LIMIT) || memory == "exit:0"
        }
        "net-admin" => observation["cap_net_admin"].as_bool().unwrap_or(true),
        "positive-control" => {
            let status = observation["positive"]["status"].as_str().unwrap_or("");
            let body = observation["positive"]["body"].as_str().unwrap_or("");
            let audit_ok = audit
                .map(|text| text.contains("decision=allow"))
                .unwrap_or(false);
            !(status.contains(" 200 ") && body.contains("hello from") && audit_ok)
        }
        _ => true,
    }
}

fn evaluate_audit_after_run(view: &str, jail_id: &str) -> CaseResult {
    let allow = view.contains("decision=allow");
    let deny = view.contains("decision=deny");
    let jail = view.contains(&format!("jail={jail_id}"));
    CaseResult {
        name: "audit-after-run",
        mode: "jailed",
        expected:
            "the documented audit command returns the finished run's allow and deny decisions"
                .to_string(),
        observed: format!("allow={allow} deny={deny} jail={jail}"),
        verdict: if allow && deny && jail {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
    }
}

fn evaluate_isolation(observation: &Value) -> CaseResult {
    let owner = &observation["owner"];
    let prober = &observation["prober"];
    let owner_peer_file = owner["peer_file"].as_str().unwrap_or("missing");
    let prober_peer_file = prober["peer_file"].as_str().unwrap_or("missing");
    let prober_socket = prober["peer_socket"].as_str().unwrap_or("missing");
    let credentials = owner["own_env"].as_bool().unwrap_or(false)
        && prober["own_env"].as_bool().unwrap_or(false)
        && owner["peer_env_absent"].as_bool().unwrap_or(false)
        && prober["peer_env_absent"].as_bool().unwrap_or(false);
    let own_files = owner["own_file"].as_str() == Some("present")
        && prober["own_file"].as_str() == Some("present");
    let hazard = owner_peer_file != "absent"
        || prober_peer_file != "absent"
        || prober_socket != "absent"
        || !credentials
        || !own_files;
    CaseResult {
        name: "jail-isolation",
        mode: "jailed",
        expected: "two concurrent jails cannot see each other's files, sockets or credentials"
            .to_string(),
        observed: format!(
            "owner_peer_file={owner_peer_file} prober_peer_file={prober_peer_file} prober_socket={prober_socket} own_files={} credentials={credentials}",
            own_files
        ),
        verdict: if hazard { Verdict::Fail } else { Verdict::Pass },
    }
}

/// A setup failure is still a failed case, not a missing line. This keeps the
/// non-zero exit naming the cases and keeps `SKIPPED-BASELINE` honest.
fn setup_failures(mode: &'static str, error: &str) -> Vec<CaseResult> {
    let names = if mode == "baseline" {
        &[
            "host-secret",
            "outside-allowlist",
            "raw-ip",
            "network-control",
            "resource-limits",
            "net-admin",
        ][..]
    } else {
        &[
            "host-secret",
            "outside-allowlist",
            "raw-ip",
            "network-control",
            "jail-isolation",
            "resource-limits",
            "net-admin",
            "positive-control",
            "audit-after-run",
        ][..]
    };
    let mut results: Vec<CaseResult> = names
        .iter()
        .map(|name| CaseResult {
            name,
            mode,
            expected: "the case runs and reports an observation".to_string(),
            observed: format!("setup-error:{error}"),
            verdict: Verdict::Fail,
        })
        .collect();
    if mode == "baseline" {
        results.push(skipped(
            "jail-isolation",
            "baseline",
            "there is no jail in baseline mode, so there are not two jails to compare",
        ));
        results.push(skipped(
            "positive-control",
            "baseline",
            "baseline mode has no proxy and no gateway audit stream",
        ));
    }
    results
}

fn skipped(name: &'static str, mode: &'static str, reason: &str) -> CaseResult {
    CaseResult {
        name,
        mode,
        expected: "case is meaningful in both modes".to_string(),
        observed: reason.to_string(),
        verdict: Verdict::SkippedBaseline,
    }
}

// ----------------------------------------------------------------- fixtures

fn profile_text(
    target: &Target,
    probe: &Path,
    egress: Option<(&str, u16)>,
    isolated_network: Option<&str>,
    token: Option<&str>,
    operator_class: Option<(&Path, &str)>,
) -> String {
    let mut text = String::new();
    text.push_str("version = 1\n");
    text.push_str(&format!("workdir = \"{}\"\n", escape(&target.workdir)));
    text.push_str(&format!("home = \"{}\"\n\n", escape(&target.home)));
    text.push_str("[image]\n");
    text.push_str(&format!("name = \"{}\"\n", escape(&target.image_name)));
    text.push_str(&format!(
        "digest = \"{}\"\n\n",
        escape(&target.image_digest)
    ));
    text.push_str("[network]\n");
    match egress {
        Some((host, port)) => {
            text.push_str("class = \"selftest\"\n");
            // The selftest's class is generated per run, so it is an operator
            // class: named by a directory and pinned by digest, exactly as a
            // profile would have to name it.
            if let Some((dir, digest)) = operator_class {
                text.push_str(&format!(
                    "class_dir = \"{}\"\n",
                    escape(&dir.to_string_lossy())
                ));
                text.push_str(&format!("class_digest = \"{}\"\n", escape(digest)));
            }
            text.push_str("mode = \"allowlist\"\n");
            text.push_str("dns = \"gateway\"\n\n");
            text.push_str("[[network.egress]]\n");
            text.push_str(&format!("host = \"{}\"\n", escape(host)));
            text.push_str(&format!("port = {port}\n\n"));
        }
        None => {
            text.push_str(&format!(
                "name = \"{}\"\n",
                escape(isolated_network.unwrap_or("agentjail-selftest"))
            ));
            text.push_str("mode = \"none\"\n");
            text.push_str("dns = \"none\"\n\n");
        }
    }
    text.push_str(&format!(
        "[resources]\ncpus = 1\nmemory = \"128m\"\npids = {PIDS_LIMIT}\nnofile = {NOFILE_LIMIT}\n\n"
    ));
    // `run` always installs /tmp and /run; a home under either one needs the
    // same tmpfs declared here or podman sees a duplicate mount destination.
    if let Some(parent) = Path::new(&target.home).parent() {
        let parent = parent.to_string_lossy();
        if parent == "/tmp" || parent == "/run" {
            text.push_str(&format!("[resources.tmpfs]\n\"{parent}\" = \"64m\"\n\n"));
        }
    }
    text.push_str("[[mounts]]\n");
    text.push_str(&format!(
        "source = \"{}\"\n",
        escape(&probe.to_string_lossy())
    ));
    text.push_str(&format!("target = \"{MOUNTED_PROBE}\"\n"));
    text.push_str("read_only = true\n\n");
    if let Some(token) = token {
        text.push_str("[env]\n");
        text.push_str(&format!("PEER_ID = \"{}\"\n\n", escape(token)));
    }
    text.push_str("[agent]\ncommand = \"bash\"\n");
    text
}

#[allow(clippy::too_many_arguments)]
fn probe_args(
    case: &str,
    mode: &str,
    host_secret: &str,
    target_host: &str,
    target_ip: &str,
    allowed_port: u16,
    denied_port: u16,
    netns: &str,
    role: &str,
    token: &str,
    peer_token: &str,
    hold_ms: u64,
    alloc_bytes: u64,
) -> Vec<String> {
    vec![
        "__probe".to_string(),
        "--case".to_string(),
        case.to_string(),
        "--mode".to_string(),
        mode.to_string(),
        "--host-secret".to_string(),
        host_secret.to_string(),
        "--env-secret".to_string(),
        "AGENTJAIL_SELFTEST_SECRET".to_string(),
        "--target-host".to_string(),
        target_host.to_string(),
        "--target-ip".to_string(),
        target_ip.to_string(),
        "--allowed-port".to_string(),
        allowed_port.to_string(),
        "--denied-port".to_string(),
        denied_port.to_string(),
        "--memory-limit".to_string(),
        MEMORY_LIMIT.to_string(),
        "--nofile-limit".to_string(),
        NOFILE_LIMIT.to_string(),
        "--pids-limit".to_string(),
        PIDS_LIMIT.to_string(),
        "--netns".to_string(),
        netns.to_string(),
        "--role".to_string(),
        role.to_string(),
        "--token".to_string(),
        token.to_string(),
        "--peer-token".to_string(),
        peer_token.to_string(),
        "--hold-ms".to_string(),
        hold_ms.to_string(),
        "--alloc-bytes".to_string(),
        alloc_bytes.to_string(),
    ]
}

fn parse_probe(output: &Output, label: &str) -> Result<Value, String> {
    if !output.status.success() {
        return Err(format!(
            "{label} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(text.trim()).or_else(|_| {
        text.lines()
            .rev()
            .find(|line| line.trim_start().starts_with('{'))
            .ok_or_else(|| format!("{label} printed no JSON: {}", text.trim()))
            .and_then(|line| {
                serde_json::from_str(line)
                    .map_err(|error| format!("cannot parse {label} JSON: {error}"))
            })
    })
}

fn stage_probe(dir: &Path, name: &str) -> Result<PathBuf, String> {
    let path = dir.join(name);
    std::fs::copy(current_exe()?, &path)
        .map_err(|error| format!("cannot stage the probe binary: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot make the staged probe executable: {error}"))?;
    }
    Ok(path)
}

fn current_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|error| format!("cannot locate this binary: {error}"))
}

fn temp_dir(label: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("agentjail-selftest-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn random_token(role: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{role}-{nanos:x}")
}

struct Cleanup {
    dir: PathBuf,
    containers: Vec<String>,
    networks: Vec<String>,
}

impl Cleanup {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            containers: Vec::new(),
            networks: Vec::new(),
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for container in &self.containers {
            let _ = podman::container_remove(container);
        }
        for network in &self.networks {
            let _ = podman::network_remove(network);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
