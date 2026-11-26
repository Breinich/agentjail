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

A **non-CONNECT request is refused** with `405` and logged **in the same shape as
a policy denial**, naming the destination the client asked for. `HTTPS_PROXY`
makes a client `CONNECT`; a plain `http://` fetch through the proxy is not
relayed, and a `http://` destination in a profile is a validation error. **Plain
HTTP and raw TCP are unsupported** — not "may work if the client is polite".

## Resolve once, check every answer, then connect

A name allowlist is only worth the answer the resolver gives for it. If
`api.example.com` can be rebound, poisoned, or made to answer `127.0.0.1`,
`169.254.169.254` or a LAN address, then "the class allows `api.example.com`"
says nothing about where the bytes went. So the CONNECT half does not hand the
name to `connect(2)`:

1. the class allowlist is checked (the decision the profile was written against);
2. the name is resolved **once**;
3. **every** returned address is checked against the class address policy
   (`address_policy = "public"` by default) and **one blocked answer refuses the
   whole name** — no "tried until one works", because that is exactly how a
   poisoned answer gets a second chance;
4. the tunnel goes to a checked address, with no re-resolution per attempt and
   no fallback to anything that was not checked.

The ranges that are never a service an allowlist meant to name, and the name each
is logged by (`reason=blocked-<range>`):

| Range | Names |
| --- | --- |
| loopback | `127.0.0.0/8`, `::1/128` |
| link-local | `169.254.0.0/16` (the metadata address lives here), `fe80::/10` |
| private | RFC1918 `10/8`, `172.16/12`, `192.168/16`, and IPv6 ULA `fc00::/7` |
| cgnat | `100.64.0.0/10` |
| multicast | `224.0.0.0/4`, `ff00::/8` |
| unspecified / martian | `0.0.0.0/8`, `::/128` |
| broadcast / reserved | `255.255.255.255/32`, `240.0.0.0/4` |
| **ipv4-mapped** | `::ffff:0:0/96` — an IPv4 address wearing an IPv6 spelling; a check that only looks at native v4 and v6 ranges walks straight past it, so the whole `/96` is refused and logged as `blocked-ipv4-mapped` |
| nat64 / 6to4 / teredo | `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, `2001::/32` — IPv6 prefixes that carry an IPv4 address |

`address_policy` is per class, because the honest answer differs by class:

| Value | Permits | Used by |
| --- | --- | --- |
| `public` (default) | globally routable answers only | `model`, `external` |
| `lan` | `public` + RFC1918 + ULA | `internal`, whose whole purpose is named LAN services |
| `loopback` | `public` + loopback | **tests only**: the end-to-end tests own a fixture on the machine that runs them, and no committed class uses this |

The relaxation is only for the range named: `lan` does not permit loopback,
link-local, CGNAT, multicast, or the IPv4-mapped spelling of a private address.
`loopback` does not permit link-local or mapped addresses either.

An allowed connection's audit line carries the whole answer, because
`dest=api.example.com` alone hides the interesting half:

```text
ts=1795549099004 class=model jail=proof-1 peer=10.89.6.2:58460 \
  dest=api.example.com:443 decision=allow reason=- bytes=0/0 \
  resolved=93.184.216.34,2606:2800:220:1:248:1893:25c8:1946 pinned=93.184.216.34
```

`resolved=` is the full set the resolver returned and `pinned=` is the address the
tunnel actually used. A rebind that lands on a public address — a redirector
instead of the provider, a hijacked mirror — is visible there and nowhere else.

## Limits: a byte budget and a connection cap, per jail

An allowlisted destination with no size limit is an exfiltration channel with a
receipt. Each jail therefore has two numbers, both **required** in its class
config — a class file that omits them does not parse, so there is no such thing
as a class that accidentally has no limit:

```toml
max_bytes = 268435456        # the whole jail, both directions together
max_connections = 8         # concurrent tunnels
```

- **Byte budget.** Every byte relayed counts against the budget, upstream and
  downstream, including bytes a client sends behind its `CONNECT` head. When a
  chunk would exceed the budget the tunnel is **cut** (both directions) and the
  refusal is logged in the denial shape, on the `deny` decision, with the counter
  that caused it: `reason=byte-budget bytes=<up>/<down> budget=<max_bytes>`.
- **Connection cap.** The cap is checked **before the request head is read**, so a
  connection flood costs neither a thread nor a read. A connection over the cap
  gets `429` and `reason=connection-cap bytes=0/0 connections=<active>/<max>
  limit=<max_connections>`.
- A normal small connection is untouched: the limits are far above one agent
  session's worth of traffic (`model` 256 MiB/8, `external` 1 GiB/8, `internal`
  128 MiB/4).
- The budget is **per jail per gateway instance**. One gateway serves exactly one
  jail, so "per gateway" and "per jail" are the same number; a second jail of the
  same class gets its own gateway and its own budget.
- There is **no rate limit** — no bytes-per-second and no connections-per-second.
  The budget bounds the total, not the speed. See the residual list at the end.

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
  dest=agentjail-proof-target-1124:9001 decision=allow reason=- bytes=0/0 \
  resolved=10.89.7.4 pinned=10.89.7.4
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
- `reason` is `-` on an allow, and on a denial it is one of `not-in-class`,
  `not-in-profile`, `ip-literal`, `blocked-<range>`, `not-connect`, `malformed`,
  `bad-port`, `no-port`, `no-host`, `client-closed`, `read-timeout`,
  `head-too-large`, `resolve-failed`, `connect-failed`, `byte-budget`,
  `connection-cap`, `internal-error`. **`internal-error` is a panic in the proxy
  itself**: the denial is written even when the code errored, because a crashed
  thread with no line looks like a connection that never happened.
- Extra fields appear only when they are the reason: `resolved=`/`pinned=` on an
  allow, `address=` on a blocked answer, `budget=` on a byte-budget denial,
  `connections=`/`limit=` on a connection cap, `bytes=` restated on a cut.
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

### Destination, rotation, retention

`audit_log` and `dns_log` in the class config decide both streams. Two modes,
with different answers to "where does it go and how long does it live":

| `audit_log` / `dns_log` | Destination | Rotation and retention |
| --- | --- | --- |
| `-` (shipped default) | stdout (audit) and stderr (DNS) of the gateway container, i.e. the runtime's log | whatever the runtime does. Under podman: `podman logs` reads the container's log file under `/var/lib/containers/storage`, and **the run's `--rm` removes it with the container** — so this stream is evidence only for as long as the container lives, or for as long as somebody captures it (`podman logs <gateway> > audit.log`). With journald as the log driver the usual `SystemMaxUse`/`MaxRetentionSec` apply. The gateway itself does not rotate or retain anything in this mode. |
| a path | a file the gateway opens `O_APPEND` and creates if missing | the gateway appends and **never rotates**: rotation and retention are the operator's, e.g. logrotate with `copytruncate` (the process keeps the file open, so `create` with a rename would keep writing to the old inode). |

A file path only works if the path is writable inside the gateway container,
which mounts its rootfs read-only: mount a directory for it, or capture the
podman log. For an incident you can reconstruct afterwards, capture the streams.

`podman logs` keeps stdout and stderr apart (`podman logs` vs `podman logs
2>&1`), which is why `-` uses two different file descriptors.

### Reading both streams back: `agentjail audit`

Grepping two files by hand is how evidence gets missed. The gateway's two
streams are read back by one command, merged in time order, with the filters an
incident actually needs:

```sh
# Both streams of a class, in time order, tagged with the stream they came from.
agentjail audit --class model

# One jail only, denials only, last 50 lines.
agentjail audit --class model --jail proof-1 --decision deny --tail 50

# Streams captured elsewhere: files, or a captured podman log on stdin.
agentjail audit --audit /var/log/agentjail/model-audit.log \
                --dns /var/log/agentjail/model-dns.log
podman logs agentjail-proof-1-gateway | agentjail audit --audit -
```

Each line is printed as `stream=audit ...` or `stream=dns ...` followed by the
line the gateway wrote, unchanged. `--decision` matches the decision field, so
`deny` gives every refusal (policy, address, budget, cap, panic) and `answer`,
`nxdomain`, `refused` or `drop` give the DNS verdicts. A stream configured as `-`
is reported as "podman's log, not a file" instead of printing an empty result
that looks like no activity.

## The gateway's own outbound leg

The gateway is dual-homed: one leg on the per-run internal class network (the
jail), one leg with a route out. The second leg is **its own network for its own
run**, `agentjail-<profile>-<pid>-egress`, created by the launcher and removed
with everything else — not the host's shared `podman`/`bridge` default, and never
the jail's network. The jail is single-homed, so a bypass has nowhere to go; the
gateway is the only container on the leg it uses.

`AGENTJAIL_EGRESS_NETWORK` overrides it, which is what the proof script does: it
puts the gateway on the network its fixture target is on.

The class allowlist is applied **at that leg too**, not only in the CONNECT
parser: `agentjail-gateway`'s `egress::dial` is the only function in the process
that creates an outbound socket, and it re-checks the class allowlist itself
(`reason=not-in-class` if it ever sees something the parser let through),
resolves once, checks every answer, and only then connects. A bug that reaches the leg with a
destination the class does not list gets a refusal there instead of a tunnel.

What this does **not** do: it does not filter packets in the kernel. There is no
egress firewall behind the proxy, so a compromised gateway process can open any
socket its network leg allows. That is the residual risk of this design and it is
stated in one place, `docs/threat-model.md`.

## IPv6

IPv6 on a class network is **disabled explicitly and verified**, not left to a
runtime default:

- both networks the launcher creates are created with `--ipv6=false`;
- `run` verifies the class network before anything is launched on it and
  **refuses** a network with `ipv6_enabled: true` — a jail with an unmanaged v6
  route is a bypass that looks like nothing at all. That refusal is covered by
  `crates/agentjail-core/src/network.rs` and by `crates/agentjail/tests/cli.rs`;
- the jail therefore has no IPv6 address on its only network and no v6 route;
- the gateway has no v6 address on either leg, so no destination is reached over
  v6 at all. An AAAA-only destination is unreachable by design: "supported" means
  IPv4, and an allowlisted name that resolves only to a global v6 address fails
  with `connect-failed` rather than silently going somewhere else.

The alternative — IPv6 parity on class networks — is a larger change (a v6
prefix per run, a v6 default route decision, a v6 answer policy) and is not
pretended here.

## Network lifecycle

Every network the launcher creates is `agentjail-<profile>-<pid>-<class>` or
`agentjail-<profile>-<pid>-egress`, and every gateway container is
`agentjail-<profile>-<pid>-gateway`, named after the run that owns them. A `Drop`
guard removes them on **every** exit path — normal, non-zero, forwarded signal,
panic — container first, because a network cannot be removed while a peer is
attached, and then the networks in reverse creation order. While the run owns
resources it supervises `podman` instead of `exec`ing it, so the guard runs and
signals are still forwarded.

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
build it. The class config is bind-mounted read-only from the checkout — or from
the directory a profile names in `network.class_dir`, in which case the profile
also pins the file's digest in `network.class_digest`. Either way what runs is a
file under review, not a copy baked into an image that may be older than the file,
and not a directory that changed since the profile was reviewed.

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
   pruning, and "nothing of ours is left behind";
6. **the byte budget cuts a tunnel** — a jail whose class allows 4096 bytes
   connects to a 1 MiB flood and receives a fraction of it, with
   `decision=deny reason=byte-budget budget=4096` on the audit stream;
7. **the connection cap refuses one** — a class with `max_connections = 1` lets
   the first tunnel through and answers the second `429`, with
   `decision=deny reason=connection-cap connections=1/1` logged;
8. **an internal answer is refused with the range named** — the same name and the
   same fixture as proof 3, with `address_policy = "public"` (what `model` and
   `external` ship): `403`, with `decision=deny reason=blocked-private
   address=<the RFC1918 answer>` logged.

## Residual weaknesses, stated plainly

- **There is a budget, not a rate.** The byte budget bounds the total a jail can
  move and the cap bounds how many tunnels it holds at once, but neither bounds
  the **speed**: 8 connections × 16 KiB chunks can move 256 MiB quickly. A jail
  that is allowed to reach a destination can still saturate that destination (and
  the host's uplink) until its budget runs out.
- **The budget is cumulative, not per connection.** One jail's budget is shared
  by every tunnel it opens; a jail that spends it on one huge fetch leaves
  nothing for the next connection, and that connection is cut with
  `reason=byte-budget`. That is deliberate (a per-connection limit would multiply
  the budget by the connection count), but it means an agent can spend its own
  allowance in one go.
- **`address_policy` is a per-class knob, and `internal` relaxes it.** A class
  config that says `lan` (or `loopback`) means a rebind inside that class is not
  caught, because LAN reach *is* that class's purpose. Keep the relaxation out of
  `model`/`external`, and read a class file's `address_policy` line as a security
  decision, not a setting. A class config is authority; editing it is a review
  event.
- **The resolver is still the host's.** The gateway resolves names with the host
  resolvers and then checks the answer. That catches a poisoned or rebound answer
  at connection time; it does not authenticate DNS, so a hostile resolver can
  answer with a *public* address of its choosing, which the policy permits. What
  it cannot do is point the jail at internal space. Pinning by DNSSEC or DoH is
  not in this build.
- **IPv6 egress is off, not implemented.** See the IPv6 section: class networks
  are IPv4-only and verified that way, so an AAAA-only destination is
  unreachable.
- **`protocol = "http"` and `"tcp"` in a profile do not do anything yet.** The
  proxy implements `CONNECT` only; a plain-HTTP destination or a raw TCP relay is
  refused at the proxy (`405`, logged as a denial with the destination named).
  Only TLS on an allowlisted `host:port` works today.
- **`dns = "pinned"` is refused by validation**, not silently ignored: the
  launcher always starts the class gateway as the resolver, so a profile that asks
  for static entries only is told "not implemented yet" instead of getting
  something else.
- **`-` (the shipped default for both streams) is evidence with a lifetime.** It
  goes to the runtime's log, and `agentjail run` removes the gateway container on
  exit: nothing captures it for you, and nothing rotates or retains it. Point the
  streams at files (and rotate them yourself with `copytruncate`) if the trail has
  to outlive the run.
- **The gateway image is pinned by ID, not attested.** `run` resolves the tag and
  starts the container by that ID, so the process is fixed at resolution time; it
  does not prove the ID was built from this commit. A stale local image is still
  possible — rebuild with `scripts/build-gateway-image.sh` after pulling. The
  class config cannot be stale: it is mounted from the checkout.
- **A compromised gateway is fleet-wide egress for its class.** Nothing behind the
  proxy filters packets, so a gateway that is taken over can open any socket its
  egress leg allows. `docs/threat-model.md` states exactly what that reaches.
- **Port 53 needs `NET_BIND_SERVICE`**: the gateway runs as uid 65534 with
  `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`. That capability is on the gateway
  container only.
