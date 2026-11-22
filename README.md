# agentjail

Run an AI coding agent — any agent — inside a rootless Podman jail with no host
secrets, no host network, its own home, and an enforced egress allowlist.

```mermaid
sequenceDiagram
    autonumber
    participant H as Host harness
    participant C as agentjail CLI
    participant P as podman
    participant L as agentjail-launcher (jail PID 1)
    participant A as agent process

    H->>C: run <profile> -- <agent command>
    C->>C: validate profile (typed structs + JSON Schema)
    C->>P: inspect the target network
    P-->>C: internal flag, subnet metadata
    C->>C: verify the single-route invariant; refuse on failure
    C->>P: create the jail (not implemented yet)
    P->>L: start with stdin and stdout as pipes
    L->>A: exec the agent in its own process group
    A-->>L: exit code (or death by signal N)
    L-->>C: the same exit code, or 128 + N
    C-->>H: the same exit code; stderr kept separate
```

An agent is a process. agentjail does not know or care whether that process is
pi, Claude Code, Codex, OpenCode, or something you wrote — it takes a command
and arguments and runs them under a policy. There is no harness-, session-, or
vendor-specific code or configuration in the product.

## What it is

- A **launcher**: `agentjail run <profile> -- <agent command…>` starts the jail,
  forwards the transport described below, and exits with the agent's exit code.
- A **profile format**: TOML parsed into typed structs with fail-closed
  defaults, validated against `schema/profile.schema.json` and against semantic
  rules JSON Schema cannot express.
- A **trio of small binaries**: `agentjail` (CLI and policy), `agentjail-launcher`
  (stdio/signal/exit-code plumbing inside the jail), `agentjail-gateway` (the
  jail's only route out).
- A **proof harness**: `agentjail selftest <profile>` is meant to attack its own
  jail and report what held.

## What it is NOT

- **Not a VM.** It is a container: it shares the host kernel. A kernel or
  runtime escape is outside any guarantee this provides.
- **Not a securer of last resort.** If the host user, the host kernel, the
  model provider, or the agent's own supply chain is already compromised, this
  is not the control that saves you. See `docs/threat-model.md`.
- **Not a secret manager.** agentjail never stores, encrypts, or rotates your
  credentials. It reads them from where they already live (an environment
  variable, a file, a credential store) by reference and injects them into the
  agent process. It never writes them into the image or a bind mount.
- **Not a reimplementation of isolation.** Podman/crun does the containment;
  agentjail is policy and plumbing around it. There is no runc/youki or
  OCI-syscall work here.
- **Not a proxy you can trust from inside.** An allowlist a jailed process can
  bypass by ignoring `HTTPS_PROXY` is not enforcement. The boundary is the
  network: an internal network with no route, where the gateway is the only
  peer. Whether the gateway is implemented yet is stated in Status, honestly.

## The single-route invariant

The jail's **only** route off its own network is the gateway. A hostname
allowlist is decorative the moment any other route exists: **if the agent can
send packets to a raw IP address, DNS pinning buys nothing.**

That is a property of the network, so it is verified — never assumed:

- **Outside**: the target network's own metadata must say `internal: true`, with
  a subnet and no upstream route (`podman network inspect`). A profile naming a
  bridged network is refused with an error, not a warning and not a
  start-then-kill.
- **Inside**: from within the jail, the only reachable peer must be the
  gateway, and no other peer or route may exist.
- Both checks run on **every start**, not once per profile install, because
  networks change under you. `run` and `doctor --network` call the **same**
  verification function (`crates/agentjail-core/src/network.rs`); there is no
  second implementation to drift.

## Quickstart

```sh
# 1. Validate a profile against the schema and semantic rules (works today).
cargo run -p agentjail -- profile validate profiles/minimal.toml

# 2. See the effective profile with every default resolved (works today).
cargo run -p agentjail -- profile show profiles/allowlist.toml
```

Host diagnostics are real and read-only, including the outside half of the
single-route invariant for any existing network:

```sh
cargo run -p agentjail -- doctor
cargo run -p agentjail -- doctor --network podman        # refusal: not internal
```

Launching and self-testing are wired up but **not implemented yet** — the
commands validate their input, run the preflight that exists, and exit `3`:

```sh
cargo run -p agentjail -- run profiles/minimal.toml -- bash -l   # exit 3
cargo run -p agentjail -- selftest profiles/minimal.toml         # exit 3
```

The gateway parses and prints its allowlist but does not proxy yet:

```sh
cargo run -p agentjail-gateway -- --profile profiles/allowlist.toml --check
```

## Profiles at a glance

```toml
version = 1
workdir = "/work"
home = "/home/agent"            # required, never defaulted

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:…"             # required: tags are labels, digests are pins

[network]
mode = "allowlist"              # required; "none" is the safe posture, not a default
dns = "gateway"                 # required; no accidental inheritance
# name = "existing-internal-network"   # optional; verified on every start

[[network.egress]]
host = "api.example.com"
port = 443

[[secrets]]
source = "env"                  # or "file" or "store"; never an inline value
ref = "EXAMPLE_FORGE_TOKEN"
target = "EXAMPLE_FORGE_TOKEN"

[agent]
command = "my-agent"            # any executable; agentjail is agent-agnostic
args = ["--mode", "rpc"]
```

Two complete examples live in `profiles/minimal.toml` (no egress) and
`profiles/allowlist.toml` (one allowlisted destination). The full reference is
`docs/profiles.md`.

## Status

Increment 1 is the scaffolding PR. Spell it out plainly:

| Piece | State |
| --- | --- |
| Typed profile model, JSON Schema validation, semantic rules, specific errors | **implemented** |
| `profile validate`, `profile show` | **implemented** |
| `doctor`, including the outside network-invariant check (`--network NAME`) | **implemented** |
| CLI wiring, exit codes, help text, launcher/selftest contracts | **implemented** |
| `agentjail-launcher`: pipes, SIGINT/SIGTERM/SIGQUIT + resize forwarding, exit codes, root refusal | **implemented** and tested |
| `run` (container launch, secret injection, inside network check, cleanup) | **not implemented** (exit 3) |
| `selftest` (negative set + positive control) | **not implemented** (exit 3) |
| Gateway proxy (DNS pinning, CONNECT allowlist) | **not implemented** — allowlist parsing only (exit 3) |
| Base image (`images/base/Containerfile`) | written; not published |
| CI: fmt, clippy, tests, profile validation, Containerfile checks, musl builds | **implemented** |
| CI: real image build | non-blocking job (external apt/npm dependency) |

`run` is deliberately not half-implemented: the single-route invariant depends
on the gateway, and a proxy that does not hold the security property would be
worse than none.

## Documentation

- [`docs/threat-model.md`](docs/threat-model.md) — assets, attacker model,
  guarantees, out-of-scope, accepted residual risks. Read this before trusting
  anything else here.
- [`docs/profiles.md`](docs/profiles.md) — the profile reference, defaults
  audit, and every validation rule.
- [`docs/cli.md`](docs/cli.md) — launcher and gateway contracts, the selftest
  design, exit codes.
- [`docs/adopting.md`](docs/adopting.md) — adoption path (stub in this increment).
- [`images/README.md`](images/README.md) — building the base image and adding a
  runtime.

## Development

The toolchain is pinned in `rust-toolchain.toml` (1.100.0, with `clippy`,
`rustfmt`, and the `x86_64-unknown-linux-musl` target).

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p agentjail -- profile validate profiles/minimal.toml
cargo run -p agentjail -- profile validate profiles/allowlist.toml
cargo build --release --target x86_64-unknown-linux-musl \
  -p agentjail-launcher -p agentjail-gateway
```

Runtime dependencies: none for the launcher, and no HTTP client anywhere — the
JSON Schema validator is built without its network resolver. The launcher and
gateway are static-pie binaries (about 485 KB and 6 MB) so they can be
bind-mounted into a jail built from any base, including `scratch`.

## License

MIT. See [`LICENSE`](LICENSE).
