# CLI and runtime contracts

Three binaries, one workspace:

| Binary | Runs where | Job |
| --- | --- | --- |
| `agentjail` | host | policy: profile validation, preflight, doctor, launch orchestration |
| `agentjail-launcher` | inside the jail, as PID 1 | stdio/signal/exit-code plumbing around the agent |
| `agentjail-gateway` | its own container, the jail's only peer | DNS pinning and CONNECT allowlist |

The launcher and gateway are built static against musl so they can be
bind-mounted into a jail built from any base, including `scratch`.

## `agentjail run <profile> -- <agent command…>`

### Transport (a requirement, not a nicety)

The agent runs with **pipes, not a TTY**:

- stdin and stdout are a pair of pipes, so a JSON-RPC session over inherited fd
  0/1 works unchanged. There is no pseudo-terminal in the path.
- stderr is a **separate** stream and is never merged into stdout, so it cannot
  corrupt a structured protocol on stdout.
- EOF on stdin is propagated into the jail (no half-open pipe that keeps the
  agent waiting).
- terminal resize events are forwarded when the caller has a terminal, and
  ignored cleanly when it does not.

This is what a host harness needs: a container turns sockets into pipes, so the
pipes/SIGTERM/exit-code/resize path decides whether adoption is possible at all.
The later acceptance test is a 3+ turn JSON-RPC session over stdio inside the
jail.

![Launcher contract: pipes, signals, exit code](diagrams/launcher-sequence.svg)

![run: validate, verify, exec, reap](diagrams/run-lifecycle.svg)

### Signals and exit codes

`SIGINT`, `SIGTERM`, and `SIGQUIT` received by `agentjail` are forwarded to the
agent's process group; `SIGWINCH` is forwarded as a resize. The container is
removed on **every** exit path — normal exit, signal, launcher crash — so no
jail, network, or tmpfs is orphaned.

| Situation | Exit code |
| --- | --- |
| Agent exits normally | the agent's exit code |
| Agent dies from signal *N* | `128 + N` |
| Profile invalid or missing | `1` |
| Single-route invariant fails | `1`, with a refusal message, before anything starts |
| Usage error | `2` |
| Not implemented yet (increment 1) | `3` |

`--no-secrets` launches without resolving any `secrets[]` entry; the jail runs
with the profile's literal environment only.

### `agentjail-launcher`

The launcher is implemented and tested (`crates/agentjail-launcher`). Inside the
jail it:

1. refuses to run the agent as root (`AGENTJAIL_ALLOW_ROOT=1` exists only for
   tests and image builds);
2. execs the agent with inherited stdio, in its own process group;
3. forwards SIGINT/SIGTERM/SIGQUIT/SIGWINCH to that group;
4. exits with the agent's exit code, mapping death-by-signal *N* to `128 + N`.

## The single-route invariant

The jail's only route off its own network is the gateway: an internal network
with no route, with the gateway as the sole attached peer. **A hostname
allowlist is decorative the moment any other route exists; if the agent can
packet-to-IP, DNS pinning buys nothing.**

Verification happens from both sides and is fail-closed:

| Side | What is checked | Where |
| --- | --- | --- |
| Outside | the network's metadata: `internal: true`, a subnet, no upstream route | implemented: `agentjail_core::network::verify_inspect_json`, used by `doctor --network` and by `run` preflight |
| Inside | the only reachable peer is the gateway; no other peer, interface, or route exists | designed and specified below; **not implemented** (needs the run path) |

Both run on **every start** — networks change under you — and both share one
implementation of the outside check. `run` refuses a network that fails, with
an error:

```text
agentjail: error: refusing to launch: the network named by this profile does not
satisfy the single-route invariant.
  network "bridged" is not internal; the jail would have a route off its own
  network, so an egress allowlist could be bypassed by talking to a raw IP.
  Refusing to launch.
```

There is no "warning and continue" mode and no start-then-kill. A profile can
name an existing network (`network.name`); if it names a bridged one, `run`
refuses. When nothing is named, the launcher must create a dedicated internal
network and verify it the same way before starting anything.

## `agentjail selftest <profile>`

The selftest is the acceptance evidence: it attacks its own jail and asserts
what held. Every check runs **twice in the same test file** — once against the
pre-jail baseline and once inside the jail — and must fail on the baseline and
pass in the jail. A check that cannot tell the two apart is a bug in the check,
not a pass.

### Negative set (must be denied)

| Check | Denial expected |
| --- | --- |
| Raw IP:port | A direct connection to an external address fails: DNS pinning buys nothing if the agent can packet-to-IP. |
| Second route/peer | Adding a route, bringing up an interface, or attaching a peer from inside fails (no `NET_ADMIN`, no ability to change the jail's own network). |
| Bridged network | `run` handed a profile naming a non-internal network refuses with a clear message. |
| Gateway-only | From inside, the only reachable peer is the gateway. |
| Host credentials | A host-only credential file is unreadable and a host environment variable is absent. |
| Host filesystem | No host path is writable by default; only declared mounts exist. |
| Unlisted destinations | No unlisted destination connects and no unlisted name resolves. A denied destination fails fast with a connection error, not a timeout. |
| Container control | No podman or Docker socket, and no host control socket, is reachable from inside. |
| Escape | No `/proc/1/root`, no host `/proc`, no `CAP_SYS_ADMIN`, no new mount inside. |
| Concurrent jails | Two jails on distinct networks and homes cannot see each other's files, sockets, or credentials. |
| Resource limits | CPU, memory, pids, open files, tmpfs size, and writable-layer size are each enforced, not merely declared. |

### Positive control (must succeed)

Exactly one call to **one allowlisted destination** succeeds and returns a
well-formed response. If the positive control fails, a negative that also failed
proves nothing.

### Timing

A `mode = "none"` jail is expected to fail at connect time with an immediate
connection error (no hang, no long timeout). Observed on the development host
while writing this increment: `curl` exits 6 with `Could not resolve host:
api.github.com` in well under a second, because an isolated network has no
resolver. The expected signature is recorded with the test so a regression that
turns a fast refusal into a slow timeout is visible.

## `agentjail-gateway`

Implemented today: load the profile through the typed model, require
`network.mode = "allowlist"`, and print the exact allowlist and DNS strategy
(`--check`, exit 0). **Not implemented:** the listener, CONNECT handling, and
DNS pinning — the binary says so and exits 3.

The intent, documented so the implementation cannot drift: one process, DNS
answers only for allowlisted names, CONNECT only for allowlisted `host:port`,
no wildcards, no suffix matching, no dynamic widening at runtime, logs record
destination and verdict but never payload.

## In this increment

`run` and `selftest` validate the profile, run the outside network preflight
when the profile names a network, print the resolved plan, and exit `3`. They
do not start containers, do not touch the host, and do not pretend to have
tested anything.
