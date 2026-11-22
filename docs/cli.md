# CLI contracts

Two commands define the product's contract with a host harness. Neither is
implemented in increment 1; both are fixed now so the implementation cannot
quietly drift, and both are reflected verbatim in `--help`.

## `agentjail run <profile> -- <agent command…>`

### Transport

The agent runs with **pipes, not a TTY**:

- stdin and stdout are a pair of pipes, so a JSON-RPC session over inherited
  fd 0/1 works unchanged. There is no pseudo-terminal in the path;
- stderr is a **separate** stream and is never merged into stdout, so it cannot
  corrupt a structured protocol on stdout;
- EOF on stdin is propagated into the jail (no half-open pipe that keeps the
  agent waiting);
- terminal resize events are forwarded when the caller has a terminal, and
  ignored cleanly when it does not.

### Signals

`SIGINT`, `SIGTERM`, and `SIGQUIT` received by `agentjail` are forwarded to the
agent process. The container is removed on **every** exit path — normal exit,
signal, launcher crash — so no jail, network, or tmpfs is orphaned.

### Exit codes

| Situation | Exit code |
| --- | --- |
| Agent exits normally | the agent's exit code |
| Agent dies from signal *N* | `128 + N` |
| Profile invalid or missing | `1` |
| Usage error | `2` |
| Not implemented yet (increment 1) | `3` |

`--no-secrets` launches without resolving any `secrets[]` entry; the jail runs
with the profile's literal environment only.

## `agentjail selftest <profile>`

The selftest is the acceptance evidence: it attacks its own jail and asserts
what held. Every check is run **twice in the same test file** — once against the
pre-jail baseline (the same command on the host, or inside a jail with the
control disabled) and once inside the jail — and must fail on the baseline and
pass in the jail. A check that cannot tell the two apart is a bug in the check,
not a pass.

### Negative set (must be denied)

| Check | Denial expected |
| --- | --- |
| Host credentials | A host-only credential file is unreadable and a host environment variable is absent. |
| Host filesystem | No host path is writable by default; only declared mounts exist. |
| Egress | No unlisted destination connects, and no unlisted name resolves. A denied destination fails fast with a connection error, not a timeout. |
| Container control | No podman or Docker socket, and no host control socket, is reachable from inside. |
| Escape | No `/proc/1/root`, no host `/proc`, no `CAP_SYS_ADMIN`, no mount of a new filesystem. |
| Concurrent jails | Two jails started with distinct networks and homes cannot see each other's files, sockets, or credentials. |
| Resource limits | CPU, memory, pids, open files, tmpfs size, and writable-layer size are each enforced, not merely declared. |

### Positive control (must succeed)

Exactly one call to **one allowlisted destination** succeeds and returns a
well-formed response. If the positive control fails, a negative that also failed
proves nothing — both may simply be broken.

### Timing

A `mode = "none"` jail is expected to fail at connect time with an immediate
connection error (no hang, no long timeout). Observed on the development host
while writing this increment: `curl` exits 6 with `Could not resolve host:
api.github.com` in well under a second, because an isolated network has no
resolver. The expected failure signature is recorded with the test so a
regression that turns a fast refusal into a slow timeout is visible.

## In this increment

`run` and `selftest` validate the profile, print the resolved plan, and exit `3`
with a message stating that launching/checks are not implemented. They do not
start containers, do not touch the host, and do not pretend to have tested
anything.
