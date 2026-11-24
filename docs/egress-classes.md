# Egress classes

Three classes — **`model`**, **`external`**, **`internal`** — each with its own
allowlist, its own resolver policy, and its own audit stream. The class is
decided by **which internal podman network the jail is joined to**, not by an
ACL inside one shared proxy: the agent cannot change its network membership from
inside the jail.

Implemented as **one binary, three instances**. `agentjail-gateway` is started
once per run with the committed config of the profile's class, and that config
is the whole policy of that instance:

| File | Class | What it is for |
| --- | --- | --- |
| `gateway/classes/model.toml` | `model` | the LLM APIs an agent talks to |
| `gateway/classes/external.toml` | `external` | public registries, mirrors, documentation |
| `gateway/classes/internal.toml` | `internal` | named LAN services, deliberately few |

A profile selects one with `network.class` (see `docs/profiles.md`). A profile
may ask for **less** than its class allows; it can never ask for more. `run`
refuses the difference before it creates anything:

```text
agentjail: error: refusing to run: the profile asks for destinations its egress class does not permit
  - network.egress: github.com:443/tls is not in egress class "model" (gateway/classes/model.toml)
```

## Why not one proxy with per-host ACLs?

Because membership beats configuration. A shared proxy decides by inspecting the
connection, and everything an inspection relies on (SNI, `Host:`, the source
address) is something the jailed side supplies. Network membership is decided by
the container runtime before the agent starts, and cannot be changed from inside
the jail (no `NET_ADMIN`, no socket to the runtime). Two jails that share a proxy
also share its failure modes: one allowlist bug is every class's allowlist bug.

The cost of the chosen shape is that there is no cross-class visibility by
default: each instance logs to its own stream, so an operator collecting them
must collect three.

## Why not dnsmasq, and what is the "smallest defensible thing"?

`dnsmasq` inside a digest-pinned image would be defensible: the allowlist would
come from config we commit, and nothing would mutate at runtime. It is not the
smallest thing here, because it is a second policy engine with its own config
syntax, a second process, and a second place the allowlist can disagree with the
proxy's. The resolver in `agentjail-gateway` is about 150 lines: one question per
packet, `A` only, no recursion, no cache, no upstream, no dynamic reload. Both
halves of the gateway read the same committed file, so the resolver and the proxy
cannot drift apart. That is smaller in code, smaller in attack surface, and
strictly more auditable than a second engine with a second config.

No generic proxy (squid, envoy, nginx) is in the path: each would either need its
own ACL file that must be kept in step with ours, or would allow more than a
`CONNECT host:port` decision needs.

## Deny by default, in both halves

**DNS.** A query for a name the class may reach is answered `A 127.0.0.1`.
Everything else is NXDOMAIN. Every query is logged on the DNS stream, answered or
not, with the query name, the qtype, and the reason (`in-class`, `not-in-class`,
`policy-off`, `ip-literal`, `qtype-not-answerable`).

Loopback is the answer on purpose. If the agent resolves a name and then dials the
address it got, it dials **its own loopback**, where nothing is listening. The
connection fails closed instead of reaching the destination and bypassing the
allowlist. The proxy is the only half that resolves for real.

**CONNECT.** Only `host:port` on the class allowlist is relayed: an exact host or
a `*.suffix` wildcard (which never covers its own apex), with the port part of the
match. Everything else is refused with `403` and logged.

A **raw `IP:port` is refused even when it is listed**: the allowlist is names, and
an address would let the client choose a host by number. A config that lists an
IP address does not start — it is a config error, not a silently dead entry.

A **non-CONNECT request is refused** (`405`, logged). `HTTPS_PROXY` makes a client
`CONNECT`; a plain `http://` fetch through the proxy is not relayed, and a
`http://` destination in a profile is a validation error.

## Fail closed is the design, not a bug

A process that ignores `HTTPS_PROXY`, dials a raw IP, or resolves a name itself
and connects to it **must fail**. That is the control working:

- the jail is joined to an internal network with no route out, so a raw address
  has nowhere to go;
- the only peer on that network is the class gateway, which refuses anything
  that is not an allowlisted `CONNECT`;
- the resolver answers loopback for allowlisted names, so "resolve then dial"
  reaches nothing.

If you want an agent to reach a destination, add it to the class config and
rebuild/redeploy the gateway image — not to the agent's environment.

## Audit

Two lines per **allowed** connection, one per denial, on a stream **separate**
from the DNS log:

```text
ts=1795477011164 class=model jail=proof-target-2463051 peer=10.89.6.2:37888 \
  dest=agentjail-proof-target-1124:9001 decision=allow reason=- bytes=0/0
ts=1795477011164 class=model jail=proof-target-2463051 peer=10.89.6.2:37889 \
  dest=agentjail-proof-target-1124:9001 decision=allow-close reason=- bytes=0/16
ts=1795477011167 class=model jail=proof-target-2463051 peer=10.89.6.2:37898 \
  dest=agentjail-proof-target-1124:9002 decision=deny reason=not-in-class bytes=0/0
```

- `ts` is Unix milliseconds; `class` and `jail` identify the policy and the run
  (`<profile>-<pid>`); `peer` is the jailed side's address; `dest` is what the
  client asked for, never rewritten.
- `decision` is `allow`, `allow-close`, or `deny`; `bytes` is `up/down`, and
  `0/0` on a denial.
- **A decision is logged when it is made, not when the connection ends.**
  `decision=allow` is written the moment the outbound connection exists (its
  `bytes` is always `0/0`), so a tunnel that is established and then reset, or a
  gateway torn down mid-relay, still leaves a line — the case an incident review
  looks for. A denial is written at decision time for the same reason.
- `decision=allow-close` carries the whole-connection byte counts, and is the
  only line that can be missing: it is written when the relay ends.
- Denials are not noise. They are the signal that something in the jail is trying
  to leave by a route it was not given.

Values that come from the network are sanitised before they are written, so a
hostname cannot forge a field or a line.

DNS lines look like this, on the other stream:

```text
ts=1795476770504 class=external jail=proof-external-2461777 peer=10.89.5.2:48512 \
  qname=github.com qtype=1 decision=answer reason=in-class
```

`audit_log` and `dns_log` in the class config are `-` by default: stdout for the
audit stream, stderr for DNS. Under podman those are separate log streams
(`podman logs` keeps them apart); a file path in the config writes to a file
instead, and both are appended.

## Network lifecycle

Every network the launcher creates is `agentjail-<profile>-<pid>-<class>` and
every gateway container is `agentjail-<profile>-<pid>-gateway`, named after the
run that owns them. A `Drop` guard removes them on **every** exit path — normal,
non-zero, forwarded signal, panic — container first, because a network cannot be
removed while a peer is attached. While the run owns resources it supervises
`podman` instead of `exec`ing it, so the guard runs and signals are still
forwarded.

A `SIGKILL` of `agentjail` (or a host crash) cannot be caught. Those leftovers are
cleaned by the **next run of the same profile**, which prunes only resources whose
owning pid is gone. Pruning by profile prefix alone would let one run delete a
concurrent run's network; the prune parses the pid and refuses to guess, and the
proof script shows another profile's run leaving them alone.

Networks are created `--internal --disable-dns`. Without `--disable-dns`, podman
installs its own resolver as the network's nameserver, which shadows the gateway
the jail is told to use — and on an internal network that resolver has nowhere to
forward to.

## Building the gateway image

The image is `scratch` plus the static binary plus the committed class configs.
Nothing is compiled inside it:

```sh
cargo build --locked --release --target x86_64-unknown-linux-musl -p agentjail-gateway
scripts/build-gateway-image.sh                 # localhost/agentjail-gateway:1
```

`run` refuses to start a class side when the image is absent, and says how to
build it. The class config is bind-mounted read-only from the checkout (or from
`AGENTJAIL_CLASS_DIR`), so what runs is what is committed, not a copy baked into
an image that may be older than the file.

### The image is pinned by ID, not by tag

A tag is a name. `localhost/agentjail-gateway:1` means "whatever carries that
name right now", and that process is the jail's only route out. So `run`
resolves it once and starts the container **by image ID**:

```text
agentjail: gateway image "localhost/agentjail-gateway:1" is sha256:5f78f0df…: (pinned by ID)
```

- Resolution is `podman image inspect --format '{{.Id}}' <reference>`; the answer
  must be `sha256:` plus 64 hex characters, or the run is refused.
- The container argv carries that ID, so a retag between the check and the start
  cannot substitute a different binary.
- An absent image, an empty answer, a tag as the answer, or anything that is not
  an ID is refused **before** a network or a container exists, and the message
  says how to build the image.

What this does not do: it does not attest that the image was built from the
commit you think it was. It fixes *which* image runs once resolution happens;
provenance of the local image store is trusted input, like the profile. To check
by hand:

```sh
podman image inspect --format '{{.Id}}' localhost/agentjail-gateway:1
```

## Proving it

`scripts/prove-egress-classes.sh` runs in the normal `ci` job. It needs podman,
the static binaries, the gateway image, and one pinned slim image used as the
jail. Each proof prints the line it asserted:

1. **class membership beats ACL text** — a jail on `model` is refused a
   destination `external` allows, and the other way round, with the committed
   class configs; a profile that writes the other class's destination into its own
   egress is refused before anything is created;
2. **a raw `IP:port` is refused** — through the proxy (`403`, logged as
   `ip-literal`) and by a direct dial from inside the jail (fails; no route);
3. **an allowed destination answers through the proxy** — `200 Connection
   established`, with the audit line visible;
4. **a denied destination is refused and logged as a denial** — `403`, with
   `decision=deny reason=not-in-class` on the audit stream;
5. **lifecycle** — a normal, a failed, and a `SIGKILL`ed run, cross-profile
   pruning, and "nothing of ours is left behind".

## Residual weaknesses, stated plainly

- **The gateway resolves with the host's resolvers**, so a name in the class
  allowlist that resolves to a private address is reachable. The class list is the
  control; there is no second check on the answer. Keep LAN names in `internal`
  and never in `model`/`external`.
- **`protocol = "http"` and `"tcp"` in a profile do not do anything yet.** The
  proxy implements `CONNECT` only; a plain-HTTP destination or a raw TCP relay is
  refused at the proxy (`405`). Only TLS on an allowlisted `host:port` works today.
- **`dns = "pinned"` is refused by validation**, not silently ignored: the
  launcher always starts the class gateway as the resolver, so a profile that asks
  for static entries only is told "not implemented yet" instead of getting
  something else.
- **Rate and size:** there is no connection cap and no byte limit per jail
  (comment: `shortcut:` in `proxy.rs`). The pids and memory limits in the profile
  are the only brakers.
- **The gateway image is pinned by ID, not attested.** `run` resolves the tag and
  starts the container by that ID, so the process is fixed at resolution time; it
  does not prove the ID was built from this commit. A stale local image is still
  possible — rebuild with `scripts/build-gateway-image.sh` after pulling. The
  class config cannot be stale: it is mounted from the checkout.
- **The gateway container's outbound leg** defaults to podman's own network
  (`podman`, else `bridge`) or `AGENTJAIL_EGRESS_NETWORK`. It is the gateway, not
  the jail, that is dual-homed.
- **Port 53 needs `NET_BIND_SERVICE`**: the gateway runs as uid 65534 with
  `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`. That capability is on the gateway
  container only.
