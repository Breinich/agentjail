# Changelog

What an operator can do in a given release, in the language of the command or
flag that does it — not a commit log. The reasoning behind each guarantee is in
[`docs/threat-model.md`](docs/threat-model.md); what an adopting setup has to
supply, and in which order, is in [`docs/adopting.md`](docs/adopting.md). The
release notes on the release page are cut from this file.

## v0.1.0

`0.1.0` because the mechanism is complete and adoption is unproven at scale. A
`1.0.0` here would be a version number that lies: what this release has is an
implemented, tested and documented boundary, not a track record of other people
running it. The tag is what carries "unproven", so the version string does not
have to.

### Rootless jail

`agentjail run <profile> -- <command…>` starts one agent in one rootless Podman
container.

- The jail's argv is fixed, not tuned: `--read-only`, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`, `--userns=keep-id:uid=10000,gid=10000`,
  `--pull=never` against the profile's digest-pinned image.
- Limits come from the profile and are passed to the runtime: `--pids-limit`,
  `--memory`, `--cpus`, `--ulimit nofile`, and one bounded `--tmpfs` per
  `resources.tmpfs` entry.
- No host environment (`--env` carries only `HOME`, `TERM`, the profile's
  literal `env` and the proxy variables), no host home, no runtime socket, and
  no mount that `mounts[]` does not name.
- The rootfs is read-only: `home` lives on a bounded `--tmpfs` mounted at its
  parent and is created `0700` by the image entrypoint, so nothing in it
  outlives the run.

### Launcher contract

`agentjail-launcher` is the stdio/signal/exit-code shim for a jail whose
entrypoint uses it (`crates/agentjail-launcher`, exercised by
`crates/agentjail-launcher/tests/transport.rs`).

- stdio is pipes, not a TTY: stdin and stdout are one pipe pair, so a JSON-RPC
  session on inherited fd 0/1 works unchanged.
- stderr stays a separate stream and is never merged into stdout.
- closing stdin shuts the agent down cleanly, without a half-open pipe.
- `SIGINT`, `SIGTERM`, `SIGQUIT` and `SIGWINCH` are forwarded; the exit code is
  the agent's, with death by signal *N* mapped to `128 + N`.
- args before the agent command are passed through untouched, so a host tool can
  append its own flags; a missing command is a usage error, not a guess.
- it refuses to run the agent as root inside the jail.

**In `run`'s path today the launcher is not the process that runs**, so see
limitation 8 below before you read the bullet list as a promise about `run`.

### Typed profiles

`agentjail profile validate <profile>` and `agentjail profile show <profile>`.

- Every field is a typed struct with no implicit default where a default would
  be a decision: `mode`, `dns`, `home` and the image digest are required.
- Validation is fail-closed and reports **every** error, each prefixed with the
  path of the offending value, instead of stopping at the first.
- Paths are normalised lexically (`.`, `..`, `//`, a trailing `/`) before any
  comparison, so a traversal spelling of `/proc` or of a declared tmpfs is the
  same string validation and the podman argv both see (`normalize_path`; the
  secret-target containment check runs on the normalised form).
- Inline secret material is refused: `secrets[]` takes `source` + `ref` only.
- `profile show` prints the resolved profile **and the grant** the jail will
  actually get, so the effective policy is readable before anything runs.

### Egress classes

`network.class` + `[[network.egress]]`, with `gateway/classes/<class>.toml`.

- Three committed classes (`model`, `external`, `internal`) and operator classes
  named by `network.class_dir` + `network.class_digest`, pinned by `sha256` and
  parsed with the same rules; an operator class may not shadow a built-in name.
- The class is chosen by **network membership**: the jail is joined to that
  class's internal network, so the agent cannot change its class from inside.
- The grant is the profile's `network.egress` intersected with the class
  allowlist; a refusal names the side that refused it (`reason=not-in-profile`
  or `reason=not-in-class`).
- An empty grant is legitimate and announced — `run` says
  `egress grant is empty: this jail has no route out` and the gateway permits
  nothing.

### The single-route invariant

Verified from both sides on **every** start, never assumed.

- Outside: the network's own metadata must say `internal: true` with a subnet and
  no upstream route; a bridged network is refused before anything is created
  (`run` preflight and `agentjail doctor --network <name>` share one
  implementation).
- Inside: from within the jail the only reachable peer is the gateway, with no
  other route and no `NET_ADMIN` to add one — asserted by the jailed selftest and
  by `scripts/prove-egress-classes.sh` on every PR.

### Enforced limits and address checking

- Per-jail byte budget (`max_bytes`, both directions) and connection cap
  (`max_connections`) from the class config; reaching either is a refusal, logged
  with the counters that caused it.
- Every allowlisted name is resolved **once**, **every** answer is checked against
  the class `address_policy`, and the tunnel goes to a checked, pinned address —
  one blocked answer refuses the whole name.
- Blocked ranges include private, loopback, link-local, CGNAT and the
  IPv4-mapped (`::ffff:0:0/96`) spellings, so an IPv6-shaped spelling of
  `127.0.0.1` is not a way around an IPv4 policy.

### Audit

- `agentjail audit --class model` reads both gateway streams back, merged in time
  order and filterable by `--jail`, `--decision`, `--stream` and `--tail`.
- Every run writes `<state>/audit/<class>/<jail-id>.audit.log` and `.dns.log`
  (default `~/.local/state/agentjail`), so the view works after the container is
  gone.
- Denials are logged like allows: `decision=deny` carries the reason, and an
  allowed connection logs `decision=allow` at establishment with the resolved set
  plus `decision=allow-close` with its byte counts.
- Retention: the newest 20 runs per class, pruned at the next start of that class
  as a run's two files together.

### Selftest

- `agentjail selftest --baseline` runs the probes as a plain host process: every
  negative must **hold**, which is what makes the jailed run evidence rather than
  a tautology.
- `agentjail selftest` runs the same probes inside a real jail: every negative is
  denied and the positive control answers through the proxy with its audit line.
- The flip is the evidence: the same probe fails without the jail and passes with
  it, and the CI job runs both halves on every PR.

### Limitations

Stated here, beside the capability they limit, in the order the release notes
repeat them. Each one is also written where the guarantee it bounds lives:
[`docs/threat-model.md`](docs/threat-model.md),
[`docs/egress-classes.md`](docs/egress-classes.md), or the profile reference.

1. **An `allowlist` profile that asks for nothing still starts a class gateway.**
   The gateway then refuses every connection, so the reach is identical to
   `mode = "none"` — the difference is that one process exists which need not.
   Planned for phase 2: skip the gateway entirely when the grant is empty.
2. **Plain HTTP and raw TCP egress are unsupported.** The proxy implements
   `CONNECT` only; `protocol = "http"` or `"tcp"` in a profile reaches the proxy
   and is answered `405`, logged as a denial with the destination named.
3. **`dns = "pinned"` is refused by validation** ("not implemented yet"): the
   launcher always starts the class gateway as the resolver, so static entries
   would be a knob with no enforcement behind it.
4. **`secrets[].delivery = "file"` is unsupported** and refused by validation, not
   silently downgraded. Secrets reach the agent through its **environment**.
5. **IPv6 egress is off, not filtered.** Class networks are created `--ipv6=false`
   and one reporting `ipv6_enabled: true` is refused; an AAAA-only destination is
   unreachable rather than governed.
6. **There is no per-connection rate limit.** The byte budget bounds the total a
   jail moves and the cap bounds how many tunnels it holds, but neither bounds
   speed: an allowed destination can still be saturated until the budget runs
   out.
7. **The gateway image is pinned by ID, not attested.** `run` resolves the tag and
   starts the container by that image ID, which fixes the process at resolution
   time; it does not prove the ID was built from this commit.
8. **Signals reach the agent only through the chain that exists: host-side
   `agentjail` → the container's PID 1 (the image's `tini`/entrypoint) → the agent
   process.** Inside the jail the launcher is not PID 1, so `agentjail-launcher`'s
   process-group forwarding — implemented and tested in its own right — is not
   reachable from `run`. Processes the agent itself spawns (its grandchildren) are
   not signalled.

Also true of this release, and covered in `docs/threat-model.md`: the jail is a
container and not a VM; `address_policy = "lan"` (the `internal` class) reaches
the LAN by design; a compromised gateway reaches whatever the host can route to
on the gateway's own leg; and secrets are visible to the agent process through
its environment.

### Not in this release

Named so the next adopter is not surprised. Most are already written beside the
guarantee they limit in [`docs/threat-model.md`](docs/threat-model.md) and
[`docs/egress-classes.md`](docs/egress-classes.md); this list points at them
rather than restating them.

- **The gateway on an empty grant** — a class gateway still starts for a grant of
  nothing. Named, not done: a **candidate simplification** for phase 2
  (limitation 1 above).
- **Plain HTTP and raw TCP egress** (limitation 2;
  `docs/egress-classes.md#residual-weaknesses-stated-plainly`).
- **`dns = "pinned"`** (limitation 3; `docs/profiles.md` network table).
- **`secrets[].delivery = "file"`** (limitation 4;
  `docs/threat-model.md#file-delivery-secrets-are-unsupported`).
- **IPv6 egress** (limitation 5; `docs/egress-classes.md#ipv6`).
- **A per-connection rate limit** (limitation 6;
  `docs/egress-classes.md#limits-a-byte-budget-and-a-connection-cap-per-jail`).
- **Gateway image provenance beyond the digest pin** (limitation 7;
  `docs/egress-classes.md#the-image-is-pinned-by-id-not-by-tag`).

### Where to read next

- [`docs/threat-model.md`](docs/threat-model.md) — assets, attacker model,
  guarantees, and the residual risks beside each one.
- [`docs/adopting.md`](docs/adopting.md) — what an adopter has to supply, one
  worked profile, which class per role, and what adoption does not buy.
