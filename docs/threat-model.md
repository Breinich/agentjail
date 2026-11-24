# Threat model

This document is deliberately short and deliberately blunt. It exists to stop
agentjail from overclaiming, and to make the design choices that follow
reviewable against a stated attacker.

## Assets, in priority order

1. **Host credentials outside the jail**: SSH keys, cloud and registry tokens,
   browser and keychain stores, credential-store entries, host environment
   variables.
2. **Host files**: everything the jail was not explicitly given, including the
   user's other repositories, mail, and documents.
3. **Host control surfaces**: the container runtime socket, the user's D-Bus
   and systemd session, `/proc` and `/sys`, and the network namespace of the
   host.
4. **Other jails**: a second agent's workspace, credentials, and sockets.
5. **The declared workspace**: the one path the user *did* grant, writable only
   when a profile says `read_only = false`. Damage here is expected and must
   stay here.
6. **The user's egress budget and identity**: outbound calls made under the
   user's credentials, and the destinations they reach.

## Attacker model

The defender assumes the agent **inside** the jail is hostile:

- it may be compromised through a malicious dependency, a malicious repository,
  or a hostile issue/PR it reads;
- it may be prompt-injected by content it was asked to process, so its *goals*
  are untrusted even though its code is legitimate;
- it is assumed to be able to run arbitrary commands as the jailed uid 10000,
  to forge or ignore environment variables, and to try to resolve and contact
  arbitrary destinations;
- it is assumed to know the profile (profiles are not secrets).

The attacker does **not** have code execution on the host outside the jail, and
does not already control the runtime or the kernel.

## In scope: what agentjail is supposed to guarantee

For the jailed process, and assuming a correct rootless Podman installation:

1. **No ambient host credentials.** Only `secrets[]` references resolve, and
   their values are injected into the agent process environment (or a
   size-limited tmpfs file), never written into the image, a bind mount, or the
   jail filesystem. `agentjail run --no-secrets` must remain expressible and
   drops all of them.
2. **No host filesystem by default.** The jail sees the image plus the
   explicitly declared mount targets. Nothing else is bind-mounted; the
   container root filesystem is not the host root.
3. **No host control surfaces.** No container runtime socket, no host D-Bus,
   no host `/proc`, no host network namespace.
4. **One route out, and only one.** The default network model is
   `mode = "none"`: the jail sits on an internal network with no route out and
   no resolver. With `mode = "allowlist"` the only way out is the egress
   gateway, and the gateway permits only the listed `host:port` destinations.
   This is the single-route invariant, stated and enforced separately below.
5. **No inherited DNS search domains.** Whenever the jail has a resolver
   (`mode = "allowlist"`), the launcher passes `--dns-search .`, an empty search
   list, so a host search domain cannot turn a short or unqualified name into an
   internal address. With `mode = "none"` there is no resolver at all — Podman
   rejects DNS options together with an isolated network, so there is nothing to
   inherit. This is a security property, not a convenience: a resolver that
   answers `build-server` from a host search domain silently defeats the
   allowlist.
6. **Bounded resources.** CPU, memory, pids, open files, tmpfs sizes, and the
   writable layer size are declared in the profile and enforced by the runtime,
   not merely printed.
7. **Isolation between jails.** Two concurrent jails use distinct container
   names, networks, and homes, and cannot read each other's files, sockets, or
   credentials.
8. **A predictable launcher.** Stdio is pipes (not a TTY), signals and terminal
   resize are forwarded, the agent's exit code is propagated, and the container
   is removed on every exit path. A harness that speaks JSON-RPC on inherited
   fd 0/1 can run inside the jail without a wrapper.

The negative tests for 1–7, the single-route negatives, and the positive control
for 4 are the `agentjail selftest` contract in `docs/cli.md`. Until that is
implemented, these are **design guarantees, not verified ones**, with two
exceptions that do work today: the entity/format validation of a profile, and
the outside half of the single-route invariant as exercised by
`doctor --network` and by `run` preflight (see Status in the README).

## Trust boundaries

![Trust boundaries: jail, internal network, gateway, allowlisted destination](diagrams/deployment.svg)

Solid relationships are the only permitted paths; the dashed dependency is the
one the design forbids and the environment must make impossible.

## The single-route invariant

**The jail's only route off its own network is the gateway**: an internal
network with no route, and the gateway as the sole attached peer. The invariant
is the whole allowlist. A hostname allowlist is decorative the moment any other
route or peer exists, and **if the agent can packet-to-IP, DNS pinning buys
nothing**.

Because it is a property of the network and not of the agent's environment, it
is verified, never assumed, and it fails closed:

| Side | Evidence | Status |
| --- | --- | --- |
| Outside | the target network's own metadata: `internal: true`, at least one subnet, and no upstream route or gateway exposed off that network (`podman network inspect`) | **implemented** (`crates/agentjail-core/src/network.rs`) |
| Inside | from within the jail: the only reachable peer is the gateway, and no other peer, interface, or route can be added (no `NET_ADMIN`) | **asserted on every PR** by `scripts/prove-egress-classes.sh` (proofs 2 and 3, from a real jail). It is **not yet a `selftest` case**: the capability exists, what is missing is the test inside `agentjail selftest`, which is still the exit-3 stub. |

Rules that go with it:

- **Both checks run on every start**, not once per profile install. Networks
  change under you; a network verified yesterday proves nothing today.
- **`run` and `doctor` share one implementation.** Two copies drift, and the
  drifted one is the one that says the jail is fine.
- **Unverifiable means refuse.** Missing metadata, an unparseable inspection,
  or an empty subnet list is a refusal with a clear message — never "assume
  internal", never "warn and continue", never start-then-kill.
- A profile may name an existing network (`network.name`). If that network is
  not internal, `run` refuses before anything is created; the refusal is a
  selftest case, not an aspiration.

The inside half is now implemented for allowlist profiles, and asserted on every
PR: the jail is joined to a per-run internal network whose only peer is that
class's gateway, a raw `IP:port` and a direct dial both fail, and the resolver
answers loopback for allowlisted names so "resolve then dial" reaches nothing.
See `scripts/prove-egress-classes.sh` and `docs/egress-classes.md`.

## Out of scope: explicitly not guaranteed

- **Host kernel and runtime bugs.** agentjail is a container, not a VM. A
  kernel privilege escalation, a runc/crun bug, or a Podman bug defeats it.
- **A hostile host user with the same uid**, or a host user who can edit the
  profile, the image, or the agentjail binary. The profile is trusted input.
- **Side channels** (timing, cache, speculative execution, power). Not
  addressed.
- **Model or provider compromise.** Whatever the model says, and whatever the
  provider logs or does with the traffic it receives, is outside the boundary.
- **Data the agent is legitimately given.** If the workspace contains secrets,
  a prompt-injected agent can read and use them. agentjail constrains reach, not
  judgement.
- **The agent's own supply chain** installing a malicious package that talks to
  an allowlisted destination.
- **Availability attacks inside the declared limits.** The agent may burn its
  whole CPU quota, writable-scratch budget, and egress allowance.

## Residual risks we accept, and what we do about them

### The gateway, not the environment, is the boundary

An egress allowlist enforced by an environment variable is not enforcement.

If the only thing stopping an outbound request were `HTTPS_PROXY`, a hostile
agent would simply unset it and connect directly. So:

- the jail is attached to an **internal network with no route**; the gateway is
  the only reachable peer, and it is the only thing with a route out;
- `HTTPS_PROXY`/`HTTP_PROXY` are set inside the jail **only as a convenience**
  for well-behaved clients, never as the boundary;
- the gateway refuses anything not on its class allowlist, and a raw IP literal is
  refused **even if it is listed**: the allowlist is names;
- the class is decided by the network the jail is joined to, not by a rule inside
  a shared proxy, so a jail cannot reach another class's destinations even when
  its own profile text names them (the profile is checked against the class and
  the difference is refused before start);
- DNS does not bypass this either: the gateway answers only names its class may
  reach, and answers them with **loopback**, so a client that resolves and dials
  reaches itself instead of the destination;
- a process that ignores the proxy or dials a raw address **fails closed**. That
  is the control working, not a defect: there is no route to fail over to.

#### What that claim does not cover — stated here, beside it

The sentence above is "the gateway is the only control on the egress path", and
these are the limits of that control. They are not footnotes to be found later in
a PR body:

- **The gateway's own outbound leg is unrestricted by design.** It is
  dual-homed: one leg on the per-run internal network (the jail), one leg on a
  real egress network (`podman`/`bridge` or `AGENTJAIL_EGRESS_NETWORK`). The
  CONNECT allowlist is the **only** thing standing between that second leg and
  anything the host can reach — there is no egress firewall behind the proxy, no
  second check on the resolved address, and no per-destination policy beyond the
  class file. **A bug in the proxy is therefore fleet-wide egress for that
  class**: one path that fails open, and every jail of that class has the
  gateway's whole reach. That is the residual risk of this design, accepted
  because the alternative (per-destination enforcement in the kernel) is a much
  larger thing to get right.
- **`CONNECT` only.** The proxy relays a TLS tunnel to an allowlisted
  `host:port`; a plain-HTTP request gets `405` and is logged, and
  `protocol = "http"` / `"tcp"` in a profile does nothing. So "allowed" means
  "TLS through CONNECT", and nothing else is covered by this control.
- **No per-connection byte cap and no connection limit.** An allowlisted
  destination can be used to move unlimited bytes for as long as the connection
  lives (`shortcut:` in `proxy.rs`). The jail's pids and memory limits are the
  only brakers, and neither bounds bytes out.
- **The resolver is the host's.** The gateway resolves names with the host
  resolvers, so a class name that resolves to a private address is reachable.
  Keep LAN names in `internal` and never in `model`/`external`.
- **The dual-homing shape has one end-to-end test that is `#[ignore]`d.** The
  four-way concurrent case (four runs, four distinct networks, all removed) runs
  only on a host with podman, the base image and the gateway image; in normal
  `ci` the same ground is covered by the fake-podman argv tests and by the
  lifecycle cases in the proof script, not by the concurrency test itself.

### Egress classes bound the blast radius, and are the residual authority

There is no single shared gateway. Each run starts its own gateway container,
with the committed config of its class, on its own network. That removes the
fleet-wide "union of everything" weakness: a `model` jail can only ever reach what
`model.toml` lists. What remains:

- the committed class config is authority over every profile of that class, so
  editing it is a review event;
- the gateway resolves destinations with the host's resolvers, so any name on a
  class list that resolves to a private address is reachable. Keep LAN names in
  `internal` and never in `model`/`external`;
- there is no connection cap or byte budget in the gateway yet (a `shortcut:` in
  `proxy.rs`): the profile's pids and memory limits are the only brakers;
- `protocol = "http"` / `"tcp"` entries do not work: the proxy implements CONNECT
  only, and refuses a non-CONNECT request (`405`, logged).

This is accepted risk: the gateway is small, single-purpose, and the only
component whose compromise matters most.

### A genuinely small allowlist is the target, not an aspiration

Coding agents need very little: in the spike that preceded this increment, a
full agent session over `podman run -i --rm` needed **one** destination on 443.
A second, unlisted host was denied with no fatal effect on the session. Profiles
should be written to that standard: add a destination when a task actually
fails, not because an agent might want it.

### `--network=none` failures must be fast negatives, not timeouts

The planned selftest asserts "no egress by default" against a jail with no
network. That path fails quickly and cleanly at connect time rather than
hanging, so the negative is cheap and does not need a long timeout; the
expected signature (a connection error within seconds, no hang) is recorded
alongside the test. The selftest criterion is stricter than "it failed": each
negative must **fail against the pre-jail baseline and pass inside the jail, in
the same file**, so a test that cannot distinguish the two is a bug in the test.

### FUSE-backed mounts cannot be part of the boundary

AppImage and other FUSE-backed paths cannot be bind-mounted into the jail at
all: `crun` fails with `cannot stat self/fd/N: Permission denied`. Profile
validation therefore rejects FUSE-backed `mounts[].source` values
(`/tmp/.mount_*`, gvfs, `/run/user/*/doc`, `*.AppImage`) with a clear error and a
remedy: copy the runtime into the image, or into a normal directory that is
itself a bind mount. Treating such a mount as "mostly working" would be worse
than refusing it.

### Egress is implemented, and its limits are stated where they bite

`network.mode = "allowlist"` runs. The proofs in `scripts/prove-egress-classes.sh`
run in the normal `ci` job and print the line each one asserted: class membership
beats profile text in both directions, a raw `IP:port` is refused through the
proxy and by direct dial, an allowed destination answers through the proxy with
its audit line, and a denied destination is refused and logged as a denial.
`docs/egress-classes.md` ends with the list of places where the implementation is
weaker than the design; that list is the honest current posture.

### Secret-store durability

A secret this run created lives in podman's secret store between container start
and `agentjail` exit, and `agentjail` removes it on every exit it can observe
(normal, non-zero, forwarded signal, panic). A `SIGKILL` of `agentjail` or a host
crash cannot be observed: the entry then remains until the next run of the same
profile prunes dead-pid entries. Entries are per run
(`agentjail-<profile>-<pid>-<target>`) so concurrent runs of one profile never
share, overwrite, or prune each other; a `source = "store"` entry is the user's
and is never removed. The value is never written to the image, a bind mount, or
the container `Env` list.

### "Disk limit" is scratch only

There is no writable layer to limit: the rootfs is read-only and the profile has
no `disk` field. The only writable space is the tmpfs scratch (`/tmp`, `/run`,
the home parent), bounded by the sizes in `resources.tmpfs`. An agent cannot
write more than the sum of those mounts, but that sum — not a single "disk"
number — is the real budget.

### File-delivery secrets are unsupported

`secrets[].delivery = "file"` is valid schema but refused by `run`: secrets are
injected as environment variables only, never as files, so there is no file path
inside the jail that can accidentally outlive the process.

### Secrets in the process environment are visible to the agent

A secret injected as an environment variable is readable by the agent process,
by anything it spawns, and by anything that can read `/proc/<pid>/environ`
inside the jail. That is the point — the agent must be able to use the
credential — and it is also the residual risk: one credential per agent, by
reference, so a compromised agent exposes the one credential it was given and
nothing else. `--no-secrets` exists so a session that does not need a credential
runs with none.
