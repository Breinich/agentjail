# Adopting agentjail

The operator's front door: what to supply, one profile to copy, which class each
role gets, what adoption does not buy, and what you have to decide. The mechanism
behind each line is one link away and is not repeated here.

Adoption is one agent instance per profile, one profile per jail. The profile is
the whole grant: a field that is not in the file is not in the jail.

## What the adopting setup must supply

- [ ] **Two images.**
  - *Base image* (the jail), pinned by digest. Build it, read the digest, paste
    it into `[image].digest` of every profile:
    ```sh
    podman build -f images/base/Containerfile -t localhost/agentjail-base:1 images/base
    podman image inspect --format '{{.Digest}}' localhost/agentjail-base:1
    ```
    A tag is not a pin: `localhost/agentjail-base:1` means "whatever carries that
    name now", and it can be re-pointed between the review and the run. The pin
    lives in the profile's `[image]` table as `digest`; the reference handed to
    podman is `name@sha256:…` with `--pull=never`, so a host without that exact
    image fails the run instead of running a different one. It fixes *which*
    image runs; it does not attest who built it.
  - *Gateway image* (the jail's only route out), built locally with a
    per-workspace tag:
    ```sh
    cargo build --locked --release --target x86_64-unknown-linux-musl -p agentjail-gateway
    scripts/build-gateway-image.sh      # prints localhost/agentjail-gateway:ws-<8 hex>
    ```
    `run` derives the same tag from the workspace (`AGENTJAIL_GATEWAY_IMAGE`
    names one explicitly), resolves it to an image **ID** once, and starts the
    container by that ID, so a retag cannot substitute the binary. Nothing is
    published.
- [ ] **One profile per agent instance.** The fields, and what each one decides:

  | Field | It decides |
  | --- | --- |
  | `image` | name + digest: exactly which image runs |
  | `workdir` | where the agent starts (not `/`) |
  | `home` | fresh 0700 scratch per run (not `/`, not `workdir`) |
  | `mounts[]` | the only host paths the jail sees; `read_only` and `required` default to `true` |
  | `network.class` | the allowlist: `model`, `external`, `internal`, or an operator class (`class_dir` + `class_digest`) |
  | `network.mode` | `none` (no route out) or `allowlist` |
  | `network.dns` | `none` with `mode = "none"`; `gateway` with `allowlist` (`pinned` is refused) |
  | `network.egress[]` | destinations *this instance* is allowed: intersected with the class, and the intersection is both the grant and the jail's DNS answer set |
  | `secrets[]` | credentials by reference only (`source` = `env`, `file`, `store`), never a value |
  | `resources` | `cpus`, `memory`, `pids`, `nofile`, `tmpfs`; the rootfs is read-only, so tmpfs is the scratch budget |

  The full reference is `docs/profiles.md`.
- [ ] **The launcher contract**, because it decides whether a host tool can adopt
  this at all:
  - `agentjail run <profile> -- <command…>`. Everything after `--` is the agent's
    argv and is not parsed, so a host tool can append its own flags
    (`agentjail run p -- mytool --its-flag`); with nothing after `--`, the
    profile's `agent.command`/`args` run.
  - stdio is **pipes, not a TTY** (no `-t`): stdin and stdout are a pair of pipes,
    so a JSON-RPC session over fd 0/1 works unchanged; stderr is a separate
    stream and is never merged into stdout.
  - closing stdin propagates EOF into the jail, which is how a host session ends.
  - SIGINT, SIGTERM and SIGQUIT reach the agent through the chain that exists:
    host-side `agentjail` → the container's PID 1 (`tini` in the base image) →
    the agent process. Inside the jail `tini` is PID 1, not
    `agentjail-launcher`, so the launcher's process-group forwarding —
    implemented and tested in its own right
    (`crates/agentjail-launcher/tests/transport.rs`) — is **not reachable from
    `run`**, and processes the agent itself spawns (its grandchildren) are not
    signalled. The jail is torn down on every exit path regardless.
  - the exit code is the agent's, including `128 + N` when it dies from signal
    `N`; a refusal is `1`, a usage error `2`.

  The full contracts (launcher, gateway, selftest, exit codes) are in
  `docs/cli.md`.
- [ ] **Credentials by reference.** `source = env|file|store`, `ref` names where
  the value already lives; it is resolved before start and injected into the
  agent's **environment** only, never written into the image or the jail's
  filesystem. An unset or unreadable reference fails the launch, naming the
  reference and never a value. Give one credential per agent — the list is the
  blast radius if the agent is compromised — and make the first run of any new
  profile `agentjail run --no-secrets <profile> -- id -u`, which proves the jail
  starts with nothing.
- [ ] **Verification before trusting it.**
  - `make check` — fmt, clippy `-D warnings`, workspace tests; no podman needed.
  - `agentjail selftest --baseline` then `agentjail selftest <profile>` on the
    same host. Baseline must exit `0` because every negative **holds** without a
    jail (the hazard is real); jailed must exit `0` because every negative is
    denied and the positive control answers. A baseline that reports a negative
    already denied is a weak assertion, not a pass. The profile only supplies the
    image, `workdir` and `home`; the selftest generates its own network, limits
    and command, so it proves the jail posture, not your egress list.
  - the egress proofs: `make proofs` (rootless podman, the static binaries, the
    gateway image, and a pinned proof jail image — the script names anything
    missing) — real internal networks, real gateway containers, real audit lines.
  - `agentjail audit --class <class>` after a run reads the decisions back:
    allow, allow-close and deny lines, merged with the DNS stream, filtered by
    jail, decision or stream.

## A worked example: a read-only reviewer

```toml
version = 1
# What this jail is for, in one line; `profile show` prints it back.
description = "Review one checkout read-only; talk to the model provider and nothing else."

# Where the agent starts and where its home is. The home is created 0700 on
# writable scratch at every start, so nothing in it survives the run.
workdir = "/work/repo"
home = "/home/agent"

[image]
# The base you built, pinned by content. A host without this exact digest
# refuses the run; the tag is only a label.
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

# The one host path the jail sees. read_only defaults to true; a reviewer must
# not write, so the agent's only writable space is scratch.
[[mounts]]
source = "/home/me/src/project"
target = "/work/repo"
read_only = true

[network]
# The LLM APIs, and only them. The class is the ceiling; the list below is what
# this instance asks for, and the intersection of the two is the grant.
class = "model"
# "allowlist": the gateway is the only way out. "none" is the safe posture for a
# task that needs no network at all.
mode = "allowlist"
# The class gateway is the resolver and answers only grant names; anything else
# is NXDOMAIN, not a silent fallback to the host's resolver.
dns = "gateway"

[[network.egress]]
# A bare name and a port: no scheme, no wildcard, no path. 443/tls is the only
# protocol the gateway relays today.
host = "api.anthropic.com"
port = 443
protocol = "tls"

[[secrets]]
# A reference, never a value: read from the host environment at launch and
# injected into the agent's environment.
source = "env"
ref = "ANTHROPIC_API_KEY"
target = "ANTHROPIC_API_KEY"

[resources]
# Limits the runtime enforces, not numbers a reviewer trusts: 2 cores, 2 GiB,
# 512 tasks, 2048 open files.
cpus = 2
memory = "2g"
pids = 512
nofile = 2048

[resources.tmpfs]
# The only writable space, with a hard size. The rootfs is read-only.
"/tmp" = "128m"

[agent]
# Any executable in the image, with any arguments. Replace with your agent; the
# base image does not ship one, so add yours per images/README.md.
command = "pi"
args = ["--mode", "rpc"]
```

Two commands verify it:

```sh
agentjail profile validate profiles/reviewer.toml
agentjail run --no-secrets profiles/reviewer.toml -- id -u
```

`validate` checks the file, the class subset and prints the grant (`grant of 1
destination(s) out of 7 the class allows`); it does not check that the image
exists. `run` does: it prints the preflight, starts the class gateway, and `id -u`
answers `10000`. Until you replace the zero digest with yours, `run` refuses (the
pin working); a `mounts[].source` that does not exist refuses the launch too
(`required` defaults to `true`), so point it at your checkout.
`agentjail profile show <profile>` prints the resolved profile and the grant the
jail will actually get; drop `--no-secrets` once the credential is set, and read
the decisions back with `agentjail audit --class model`.

## Which class per role

| Class | It can reach | Roles that get it |
| --- | --- | --- |
| `model` | the model APIs on 443 (`gateway/classes/model.toml`: Anthropic, OpenAI, OpenRouter, opencode, Google) — public addresses only, 256 MiB, 8 tunnels | any agent that has to answer a prompt: the default for an interactive or review role |
| `external` | public registries and docs on 443 (GitHub, Codeberg, crates.io, npm, PyPI, Debian, docs.rs) — public only, 1 GiB, 8 tunnels | a fetch/build role; on its own it cannot talk to a model, so an agent that must do both needs an operator class or two runs |
| `internal` | three named LAN services (`git.internal`, `registry.internal`, `wiki.internal`) — `address_policy = "lan"`, 128 MiB, 4 tunnels | a homelab-ops role, deliberately the narrowest |

One profile has exactly one class. A role that needs two is an operator class
(`network.class_dir` + `network.class_digest`, reviewed and pinned) or two runs.
The mechanism, the address policy and the deny reasons are in
`docs/egress-classes.md`.

## What adoption does not buy

- **Not a VM.** The jail shares the host kernel; a kernel or runtime escape is
  outside the guarantee. See `docs/threat-model.md`.
- **A compromised gateway has the gateway's network.** It is dual-homed, and
  nothing filters packets behind it: the class allowlist is an in-process
  decision, so a gateway that is taken over reaches everything the host can route
  to on its egress leg, the LAN included. See
  `docs/threat-model.md#if-the-gateway-itself-is-compromised`.
- **IPv6 egress is off, not filtered.** Class networks are created
  `--ipv6=false` and one reporting `ipv6_enabled: true` is refused; an AAAA-only
  destination is unreachable rather than governed.
- **`delivery = "file"` secrets are unsupported.** Refused by validation, not
  silently downgraded to a file.
- **Audit is local and finite.** Two files per run under
  `<state>/audit/<class>/` (default `~/.local/state/agentjail`), newest 20 runs
  per class, pruned at the next start. A `mode = "none"` jail has no gateway and
  therefore no audit files. Copy out what you must keep.

## What the operator must decide

- **The class per role.** Start with `model` for anything that answers prompts;
  add a destination to a class only when a real task fails, and treat a class edit
  as a review event. A role that needs two classes is a new operator class or two
  runs.
- **Where credentials come from.** `env` (the value is in your shell), `file` (a
  file outside the jail), or `store` (an existing podman secret entry, never
  removed by a run) — and whether the agent gets one at all.
- **Audit retention.** `run` keeps 20 runs per class; decide whether that is your
  retention, or whether you copy the files out before the prune.
- **Whether the agent gets a writable mount at all.** `read_only = true` is the
  default; `read_only = false` is the one path where the threat model expects
  damage, so name it deliberately.

## Diagrams

PlantUML sources in `docs/diagrams/`, rendered SVGs committed beside them. CI
renders with the digest-pinned image
`docker.io/plantuml/plantuml@sha256:2cf2f097…` (`-checkonly`, then
`git diff --exit-code docs/diagrams`), so an invalid or stale SVG fails the build.
Not the public `plantuml.com/plantuml/proxy`: it fetches `raw.githubusercontent.com`
unauthenticated, so it cannot read this private repository, and it makes every
read depend on a third party. The exact re-render command is in
`.github/workflows/ci.yml` (job `diagrams`).
