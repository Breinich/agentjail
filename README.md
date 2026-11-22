# agentjail

Run an AI coding agent — any agent — inside a rootless Podman jail with no host
secrets, no host network, its own home, and an enforced egress allowlist.

```text
  host                                    jail (rootless podman)
  ┌───────────────────────────┐           ┌────────────────────────────────┐
  │ agentjail run profile --… │  stdin ──▶│ agent process (uid 10000)      │
  │  ├─ profile validation    │  stdout ◀─│  own home, declared mounts     │
  │  ├─ secret resolution     │  stderr ◀─│  no host env, no host sockets  │
  │  └─ egress gateway        │──────────▶│  internal network, no route    │
  └───────────────────────────┘  allowlist└────────────────────────────────┘
```

An agent is a process. agentjail does not know or care whether that process is
pi, Claude Code, Codex, OpenCode, or something you wrote — it takes a command
and arguments and runs them under a policy. There is no harness-specific,
session-specific, or vendor-specific code or configuration in the product.

## What it is

- A **launcher**: `agentjail run <profile> -- <agent command…>` starts the
  jail, forwards the transport described below, and exits with the agent's exit
  code.
- A **profile format**: a TOML document describing image, mounts, environment,
  secret *references*, network allowlist, resource limits, and the agent command.
  Profiles are validated against `schema/profile.schema.json`.
- A **proof harness**: `agentjail selftest <profile>` is meant to attack its own
  jail and report what held. It is not implemented yet (see Status).

## What it is NOT

- **Not a VM.** It is a container: it shares the host kernel. A kernel or
  runtime escape is outside any guarantee this provides.
- **Not a securer of last resort.** If the host user, the host kernel, the
  model provider, or the agent's own supply chain is already compromised, this
  is not the control that saves you. See `docs/threat-model.md`.
- **Not a secret manager.** agentjail never stores, encrypts, or rotates your
  credentials. It reads them from where they already live (an environment
  variable, a file, a credential store) by reference and injects them into the
  agent process. It also never writes them into the image or a bind mount.
- **Not an egress firewall you can trust from inside.** An allowlist that the
  jailed process can bypass by ignoring `HTTPS_PROXY` is not enforcement. The
  design therefore puts the boundary *outside* the process: an internal
  container network with no route, plus a gateway that is the only way out.
  Whether that gateway is implemented yet is stated in Status, honestly.

## Quickstart

```sh
# 1. Validate a profile against the schema (this works today).
agentjail profile validate profiles/minimal.toml

# 2. Inspect the effective profile with every default resolved (this works too).
agentjail profile show profiles/minimal.toml
```

Launching and self-testing are wired up but **not implemented yet** — the
commands validate their input and exit with code 3:

```sh
agentjail run profiles/minimal.toml -- bash -l   # exit 3: not implemented
agentjail selftest profiles/minimal.toml         # exit 3: not implemented
```

Host diagnostics are real and read-only:

```sh
agentjail doctor          # podman version, rootless?, SELinux, config dirs
agentjail doctor --json
```

## Profiles at a glance

```toml
version = 1
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:…"          # required: tags are labels, digests are pins

[network]
mode = "allowlist"           # or "none" (default posture: no egress)
dns = "gateway"              # required, no accidental default

[[network.egress]]
host = "api.example.com"
port = 443

[[mounts]]
source = "/home/me/src/project"
target = "/work/project"
read_only = true

[[secrets]]
source = "env"               # or "file" or "store"; never an inline value
ref = "EXAMPLE_FORGE_TOKEN"
target = "EXAMPLE_FORGE_TOKEN"

[agent]
command = "my-agent"
args = ["--mode", "rpc"]
```

Two complete examples live in `profiles/minimal.toml` (no egress) and
`profiles/allowlist.toml` (one allowlisted destination). The full reference is
`docs/profiles.md`.

## Status

Increment 1 is the scaffolding PR. Spell it out plainly:

| Piece | State |
| --- | --- |
| Profile schema + validation (schema, semantic rules, specific errors) | **implemented** |
| `profile validate`, `profile show`, `doctor` | **implemented** |
| CLI wiring, exit codes, help text, launcher/selftest contracts | **implemented** |
| `run` (container launch, transport, signals, cleanup) | **not implemented** (exit 3) |
| `selftest` (negative set + positive control) | **not implemented** (exit 3) |
| Egress gateway, DNS pinning, secret injection, resource enforcement | **not implemented** |
| Base image (`images/base/Containerfile`) | written, not published |
| CI: lint, tests, profile validation, Containerfile checks | **implemented** |
| CI: real image build | non-blocking job (external apt/npm dependency) |

## Documentation

- [`docs/threat-model.md`](docs/threat-model.md) — assets, attacker model,
  guarantees, out-of-scope, accepted residual risks. Read this before trusting
  anything else here.
- [`docs/profiles.md`](docs/profiles.md) — the profile reference and every
  validation rule.
- [`docs/cli.md`](docs/cli.md) — launcher contract, selftest design, exit codes.
- [`docs/adopting.md`](docs/adopting.md) — adoption path (stub in this increment).
- [`images/README.md`](images/README.md) — building the base image and adding a
  runtime.

## Development

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && ruff format --check .
pytest
python scripts/check_containerfile.py images
python scripts/sync_schema.py --check
```

Runtime dependency count: zero. Profiles are TOML and are parsed with the
standard library's `tomllib`; see the PR body for why TOML over YAML.

## License

MIT. See [`LICENSE`](LICENSE).
