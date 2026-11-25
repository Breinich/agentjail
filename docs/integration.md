# Integrating an agent

agentjail does not know what your agent is. This document is the operator's side
of that sentence: how an agent becomes a jail, in the shapes that work today,
with each limitation stated next to the feature it limits instead of in a later
paragraph.

Read [`docs/threat-model.md`](threat-model.md) first. It is the only document
that says what the jail is worth, and nothing here claims more than it does. The
profile reference is [`docs/profiles.md`](profiles.md) and egress is
[`docs/egress-classes.md`](egress-classes.md); this page is the order in which
you touch them.

Status: `run` works for `network.mode = "none"` and for
`network.mode = "allowlist"` — with the three committed classes, or with an
operator class you pin by digest. The gateway implements `CONNECT` only.
`secrets[].delivery = "file"` is refused by `run`. Those three sentences are the
whole support surface of what follows.

### Before you type a command

- **`agentjail` below means the binary you built.** Nothing publishes it or puts
  it on your `PATH` yet. From a checkout: `cargo build --release`, then
  `./target/release/agentjail …` (CI's static build is
  `target/x86_64-unknown-linux-musl/release/agentjail`). This page writes the
  command as `agentjail` everywhere; substitute the path once.
- **No image is published either.** The profiles in `profiles/` carry an all-zero
  placeholder digest. Validation passes — it is a well-formed pin — and `run`
  then fails with `image not known`, because no image in your local store has
  that digest and `--pull=never` means nothing is fetched. A real digest comes
  from `podman image inspect --format '{{.Digest}}' <image>` after you build the
  base image (or your own agent image) yourself; see
  [`images/README.md`](../images/README.md) and step 2 of the checklist.

## 1. The integration model in one page

### One command, three inputs

```sh
agentjail run <profile> -- <agent command…>
```

The command after `--` overrides the profile's `[agent]`, so one profile can
serve a jailed shell, a single agent turn, and an agent's RPC mode without being
rewritten. If no command follows `--`, `agent.command`/`agent.args` are used.

| You supply | agentjail supplies |
| --- | --- |
| **An image** that contains your agent, pinned by digest (`image.name` + `image.digest`). Nothing is published for you: build it from `images/base` (`images/README.md`). | **Containment.** Rootless Podman with a read-only rootfs, uid 10000, `--cap-drop=ALL`, `no-new-privileges`, no host home, no host environment, no runtime socket, and the CPU/memory/pids/nofile/tmpfs numbers from the profile. |
| **A profile**: one TOML file naming that image, the mount targets your agent reads, its literal environment, its secrets by reference, and one network posture. | **Transport.** Pipes, not a TTY; stdin EOF propagated; stderr kept separate from stdout; SIGINT/SIGTERM/SIGQUIT and terminal resize forwarded; the agent's exit code passed through (`docs/cli.md`). |
| **Secret references** (`source`/`ref`/`target`): where the credential already lives, and the environment variable name the agent should find it in. | **Egress policy.** With `mode = "allowlist"`, a per-run internal network whose only peer is that class's gateway, the gateway as the resolver, and `HTTPS_PROXY`/`ALL_PROXY` pointing at it. With `mode = "none"`, an empty internal network with no route out. |
| **An egress class** (`model`, `external`, `internal`, or your own via `class_dir` + `class_digest`): the ceiling. Your profile's `egress` list narrows it, and the **intersection is the grant** the gateway enforces (§3, §4). | **Audit.** One line per connection decision and one per DNS query, per run, kept under the state directory and read back with `agentjail audit --class <class>` (`docs/egress-classes.md`). |

`home` and `workdir` are yours to choose but not to populate: `workdir` is
whatever the image has there, and `home` is a fresh 0700 directory created in
writable scratch on every start. Anything baked into the image *under* `home` is
hidden by that scratch mount, and anything the agent writes there is gone when
the run ends.

### There is no harness-specific code

There is no plugin, adapter, hook, session bridge, or vendor branch anywhere in
the three binaries, and no field in the profile that names a harness. That is a
design decision with a support consequence you should read as a promise and as a
limit:

- **Any agent works if** it can read its configuration from a path you can bake
  into the image or bind-mount, it can run without a terminal, it reaches the
  network only through a proxied TLS destination (or needs no network), and it
  writes only where the jail has writable space.
- **Nothing is special-cased.** If your agent needs a fix in agentjail, the fix
  is a profile field or a product change that applies to every agent, not a
  patch for yours.
- **No support matrix exists.** The recipes in [section 5](#5-per-agent-recipes-examples-of-the-shape-not-supported-configurations)
  are examples of the shape, not tested configurations. Your agent's own docs are
  authoritative for its flags, config paths, and stdio mode.

An agent that only has a full-screen terminal UI is not integrable as-is:
`agentjail run` allocates no pseudo-terminal, because a TTY in the path corrupts
structured output. Use the agent's print, `exec`, or RPC subcommand. An agent
that expects to log in through a browser is not integrable either: there is no
browser and no loopback port back to your host.

### What "in a jail" means for the four properties

| Property | The mechanism | Where it is verified |
| --- | --- | --- |
| Config comes from a path you chose | The image and `[[mounts]]` are the only sources; there is no host home and no `--env-host`. | `agentjail run … -- env` contains no host variable: what is there is the image's own `ENV`, plus `HOME`, `TERM`, profile literals, and secrets. |
| No TTY | `--interactive` without `-t`; stdio is pipes. | `crates/agentjail-launcher/tests/transport.rs` drives three JSON-RPC round trips. |
| One route out | An internal network with the class gateway as the only peer; raw IP, direct dial, and resolve-then-dial all fail closed. | `scripts/prove-egress-classes.sh` on every PR, plus the jailed `selftest`. |
| Writes stay in scratch | Read-only rootfs; writable space is `home`'s parent, `/tmp`, `/run`, and declared tmpfs only. | `agentjail selftest` (`resource-limits`), and the profile's own numbers. |

A profiled mount is the one place where your choice *is* the boundary. Everything
in this document that looks like a warning is about that.

## 2. Custom skills

A skill is files an agent reads. agentjail's only question about them is: **where
do those files live, and who can change them between now and the run?**

Two shapes are supported, and they differ in exactly that answer.

### Shape A: baked into the image (preferred)

The skill tree is copied in at build time. The profile's digest then describes
the agent *and* its skills, the jail has no host path for them, and a review of
the image digest is a review of everything the agent can read.

```dockerfile
# images/<agent>/Containerfile — derives from the base by digest, per images/README.md
FROM localhost/agentjail-base@sha256:<digest-of-the-base-you-built>
USER root
# Skills go outside `home` and `workdir`: `home` is fresh scratch on every start,
# and a baked path under it would never be seen.
COPY skills/ /opt/agent/skills/
COPY pi-agent/ /opt/agent/pi/
RUN chown -R 10000:10000 /opt/agent
USER 10000:10000
```

```toml
[env]
# The agent's own env var, pointing at the baked directory. Verify the name and
# the writability rules against the agent version you install.
PI_CODING_AGENT_DIR = "/opt/agent/pi"
```

Two things this shape gets wrong if you are careless:

- **A baked path under `home` is invisible.** `run` mounts writable scratch at the
  parent of `home` and the image entrypoint creates `$HOME` inside it, so
  `/home/agent/.pi/…` from the image is shadowed by an empty tmpfs. Bake outside
  `home` and point the agent at the path with its own configuration.
- **A read-only agent directory is not the same as a read-only skill directory.**
  Most agents write sessions, caches, or credentials into the same directory they
  read config from. If the agent can be told to keep sessions elsewhere (pi:
  `--session-dir` / `--no-session`), bake the config and redirect the writes.
  Otherwise treat the agent directory as writable and use the mount shape below
  for the skill tree only.

### Shape B: mounted read-only from the host

The skill tree stays on the host and is bind-mounted into the jail:

```toml
[[mounts]]
source = "/srv/agent-skills"     # absolute host path; "~" is not expanded
target = "/opt/skills"           # absolute in-jail path, not `home`, not /proc…
read_only = true                 # the default; writable access must be requested
```

Point the agent's configuration at `/opt/skills` (or mount where the agent
already looks). This is the fast-iteration shape: edit a skill, run again, no
image build.

What you accept by choosing it, in the same breath:

- **The jail's behaviour now depends on a mutable host path.** The profile's
  digest no longer describes what the agent reads. A run today and a run next
  week, from the same profile and the same image, can behave differently because
  somebody edited `/srv/agent-skills` — and nothing in the audit trail will say
  so.
- **`required = true` is the default**, so a missing host directory fails the
  launch with a message naming the mount instead of silently shrinking the jail.
  Set `required = false` only when "absent" is a legitimate state.
- **`read_only = true` protects the source from the agent**, not the jail from
  the source. Writable mounts must be asked for explicitly; do that only when the
  agent genuinely has to write (a cache, an output directory), and remember that
  what it writes lands on your host.

### The FUSE case, explicitly

A skill directory that lives on an AppImage mount cannot be bind-mounted at all.
The path looks like `/tmp/.mount_XXXXXX/…`, and `crun` refuses it:

```text
crun: cannot stat self/fd/N: Permission denied
```

Profile validation therefore rejects such a `mounts[].source` before anything
starts, with a remedy in the message. The same refusal applies to an `*.AppImage`
file itself, to `/dev/fuse`, and to the gvfs and document-portal mounts under
`/run/user/*/gvfs` and `/run/user/*/doc`. It is a list of patterns, not a
filesystem check, and it does **not** cover everything under `/run/user/`: see
the socket mistake in [§4](#common-mistakes) for the path that gets past it.
There is no "mostly works" version of this: a FUSE path is not a bind-mount
source, and treating it as one would fail at container start, after the profile
looked fine.

Your two options, and the cost of each:

1. **Copy into the image.** The skill tree becomes part of the digest. This is
   shape A and it is the right answer for anything that must be reproducible.
2. **Stage it.** Copy the tree once into a normal filesystem directory and mount
   *that*. The security consequence is the whole of the rest of this paragraph:
   the copy is now an input to the jail, and the jail's behaviour is only as
   trustworthy as the copy. If the host can change the staged directory under a
   running jail, the agent is executing content nobody reviewed; if the staged
   directory is mounted writable, the agent can change its own instructions
   mid-run and keep the change for the next one. So: stage once from a pinned
   source, stage into a directory that is not shared with anything else, and
   mount it `read_only`. Treat the staging step as part of your build, not as a
   convenience wrapper around `agentjail run`.

A third case needs neither: skills that belong to the *project* and are read
from the workspace (pi: `.pi/skills/` or `.agents/skills/` under the working
directory, Claude Code: `.claude/skills/`) arrive through the workspace mount
with no extra work, because they are already part of the repository you mounted.

## 3. MCP servers

An MCP server is either a child process of your agent or an HTTP endpoint. Only
one of the three shapes below gets a remote endpoint through the single-route
invariant without weakening it, and only one of them does not work at all.

### Shape A: stdio MCP, spawned by the agent

The server is a child process inside the jail. It inherits the jail's policy:
same uid, same read-only rootfs, same network, same egress class. That is the
good news — nothing extra to reason about.

The constraint is that **the server must live in the image.** A host install
cannot be mounted in (see the FUSE case: an AppImage or a `npx` cache on the host
is not a bind-mount source, and a host install usually drags host configuration
with it).

`npx -y some-mcp-server` at run time does work, but only with an egress class
that reaches the registry (`external` lists `registry.npmjs.org`), a writable
npm cache in scratch, and a floating version. Prefer installing at build time the
way the base image does — `--ignore-scripts`, pinned version — so the server is
part of the digest and a rebuild cannot quietly change it.

The cost of the fat ones is real, and it is paid three times:

| Cost | What it looks like |
| --- | --- |
| Image size | A browser-based MCP server (Playwright, Puppeteer) adds a browser plus drivers — hundreds of megabytes, on every host that builds the image. |
| `/dev/shm` | The profile has no `/dev/shm` knob and the launcher passes no `--shm-size`, so a browser gets Podman's default of 64 MiB and many of them crash on it. This is a limitation of this build, not a tuning value you are missing. |
| Egress | Every site the browser opens is a destination. A browser tool that visits arbitrary URLs needs the class and the profile to say so, which is a different security posture from "the agent may call its model API". |

A stdio server that fetches anything over the network is subject to exactly the
same rules as the agent: if the hostname is not in the grant — the class allowlist
**and** this profile's `egress` list — DNS answers NXDOMAIN and the server fails
to start or fails on first use.

### Shape B: remote MCP over HTTPS through the class gateway (recommended)

An MCP endpoint that is a real HTTPS URL inside this jail's grant needs no hole
in the jail: the client speaks `CONNECT host:443` to the gateway, which checks the
grant, resolves once, checks every answer, and tunnels to the pin. This is the
only remote shape that keeps the single-route invariant intact.

**The grant is the intersection: your profile narrows the class.** `run` reads
the class config — `gateway/classes/<class>.toml`, or the operator class the
profile pins — and starts the gateway with `--grant`, the set of destinations
that are **both** in the class allowlist and in the profile's
`[[network.egress]]`. The gateway enforces that grant, not the class: it is the
CONNECT allowlist *and* the DNS answer set, so a name the profile did not ask for
is `NXDOMAIN` even when the class lists it. A refusal names the side that refused
it — `reason=not-in-class` (outside the ceiling) or `reason=not-in-profile` (the
class would allow it, this profile did not ask) — and `agentjail profile show`
prints the effective grant next to the class name.

To reach a new destination:

1. **The profile** — add `[[network.egress]]`. That is the grant: the run reaches
   it, and only it, if the class allows it too.
2. **The class config**, when the destination is not already inside the ceiling —
   `gateway/classes/<class>.toml`, or the operator class file. Editing a class is
   a review event because every profile of that class shares the ceiling; for an
   operator class the edit also changes the file's digest, so `run` refuses until
   the profile's `class_digest` changes in the same review (§4).

Both halves fail closed, in different places: a class entry the profile does not
name grants nothing at run time (`not-in-profile`), and a profile entry the class
does not allow is refused before anything is created. That is why the answer to
"why can't my agent reach X" is usually one missing line, and the audit stream
says which file it belongs in.

The class file is bind-mounted read-only from the checkout or from
`network.class_dir`, so the copy inside the gateway image is never what runs: a
class edit takes effect on the next run without a rebuild. The gateway image is
tagged per workspace (`localhost/agentjail-gateway:ws-…`, derived from the
workspace path) so two checkouts that build it from different code cannot retag
each other's; `AGENTJAIL_GATEWAY_IMAGE` names one explicitly, which is what an
installed layout or a published image uses.

The added lines, in the shape of a complete profile (see
[§4](#the-smallest-allowlist-profile) for the file around them):

```toml
[network]
class = "model"
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "mcp.example.com"
port = 443

[env]
# Node 24 clients (the MCP TypeScript SDK uses `fetch`) ignore the proxy
# environment unless this is set; without it the request fails closed.
NODE_USE_ENV_PROXY = "1"

[[secrets]]
source = "env"
ref = "DOCS_TOKEN"
target = "DOCS_TOKEN"
```

Client side, the shape is the client's own: an HTTP MCP entry whose URL is the
allowlisted name and whose header interpolates the injected variable. With pi
that is `pi mcp add docs --url https://mcp.example.com/mcp --bearer-token-env-var DOCS_TOKEN`,
which lands as:

```json
{
  "mcpServers": {
    "docs": {
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer ${DOCS_TOKEN}" }
    }
  }
}
```

The environment the client needs is usually none: `run` sets `HTTPS_PROXY`,
`ALL_PROXY`, and the lowercase spellings for allowlist profiles, and a client
that honours them is done. A client that does **not** honour them fails closed,
and this is the single most common "the agent started but cannot answer":

- the gateway's resolver answers `127.0.0.1` for an allowlisted name;
- the client ignores the proxy and connects to `127.0.0.1`;
- nothing is listening there, the connection is refused, and no audit line is
  written — because the gateway never saw a connection. Only the DNS stream shows
  the query.

Fixes, in order of preference: make the client use the proxy (for Node 24:
`NODE_USE_ENV_PROXY = "1"` in `[env]`, or the runtime's `--use-env-proxy` flag),
set the proxy URL in the client's own configuration if it has one, or use a
server that speaks stdio instead.

Limits of this shape, beside the feature: `CONNECT` means TLS to an allowlisted
`host:port`, nothing more. The gateway does not terminate TLS, does not inspect
the payload, and cannot tell one MCP method from another. The session is bounded
by the class's byte budget (256 MiB for `model`) and connection cap (8), and by
nothing else — there is no rate limit. See
[`docs/egress-classes.md`](egress-classes.md#residual-weaknesses-stated-plainly).

### Shape C: plain-HTTP MCP

**Not supported today, and the failure is deliberate.** The proxy implements
`CONNECT` only: a plain `http://` request gets `405`, is refused, and is logged
as a denial naming the destination it asked for. `protocol = "http"` and
`protocol = "tcp"` in a profile validate and are **inert** — they change nothing
at run time; only TLS through `CONNECT` to a destination in the grant is a
supported shape. `dns = "pinned"` is refused for the same reason a knob that
does nothing is refused.

There is no plain-HTTP gateway in this build, so "the gateway speaks plain HTTP"
is not a configuration you are missing; it is a feature the proxy does not have.
Your options:

- **Put a TLS front in front of the server** (a reverse proxy with a certificate)
  so it becomes shape B. This is the only way a remote plain-HTTP MCP endpoint
  becomes reachable.
- **Run the server inside the jail** as a stdio child (shape A), if it can run
  there. A local HTTP server that the *agent* spawns and talks to over loopback
  inside the jail needs no egress at all — but nothing in the jail can reach a
  plain-HTTP service on your LAN or the internet today.

The `internal` class does not change this: its entries are `host:443` like every
other class, so a LAN MCP endpoint on `http://…:8080` is unreachable until it has
a TLS front. Its three shipped names (`git.internal`, `registry.internal`,
`wiki.internal`) are **placeholders** — they do not exist on any network — so
edit them before you use that class for anything real, and remember that an entry
only becomes reachable when the profile asks for it too (§3 shape B).

### Trusting a self-signed front

Because the gateway does not terminate TLS, the agent validates the real
certificate chain and a self-signed front is rejected by the runtime — not by
agentjail. The fix is to put the CA where the runtime looks, and mount it rather
than baking it if it rotates:

```toml
[[mounts]]
source = "/srv/agentjail-ca"        # contains mcp-ca.pem
target = "/opt/ca"
read_only = true

[env]
NODE_EXTRA_CA_CERTS = "/opt/ca/mcp-ca.pem"
```

| Runtime | Variable |
| --- | --- |
| Node (`fetch`, `https`, undici) | `NODE_EXTRA_CA_CERTS` — additive, keeps the system store |
| Python `requests` | `REQUESTS_CA_BUNDLE`; `SSL_CERT_FILE` for `ssl`/`urllib` |
| Go, and Rust with OpenSSL | `SSL_CERT_FILE` (`SSL_CERT_DIR` for a directory) |
| curl | `CURL_CA_BUNDLE` |
| Java | `JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/opt/ca/truststore.p12 …` |

These names are honoured by **the runtime, not by agentjail**. agentjail does not
verify that anything in the jail trusts anything; a wrong path shows up as a TLS
error from your agent, after the connection was already allowed. A CA certificate
is public material, so `[env]` is the right place for the path and the file
belongs on a read-only mount; a PEM pasted into a profile is rejected as
token-shaped, which is the validator working.

## 4. Composing a profile

### Required fields, and why each one is required

The rule behind the table: **a field whose absence could silently produce a
permissive or ambiguous configuration is required, never defaulted.** "No egress"
and "the operator forgot" must not look the same in a file.

| Field | Required because |
| --- | --- |
| `version` | The format is versioned; a future format must not be read as this one. |
| `image.name` + `image.digest` | A tag is a label, a digest is a pin. There is no way to say "whatever is there now". |
| `workdir` | Where the agent starts is a decision, not an inherited accident. |
| `home` | Owned by the jail, created 0700 per run; defaulting it would hide that the agent got a home. |
| `network.mode` | `none` (no route out) versus `allowlist` is the whole posture. |
| `network.dns` | The DNS strategy has to be written down rather than inherited, because an inherited host search domain can turn an unqualified name into an internal address in `allowlist` mode. (What this field does *not* buy you in `mode = "none"`: see [`mode = "none"` still resolves names](#mode--none-still-resolves-names).) |
| `agent.command` | Something has to run; a profile that names no executable is a jail with no purpose. |
| `network.name` (only `mode = "none"`) | `run` attaches to an existing network and creates none; naming it is the check that you meant that one. |
| `network.class` (only `mode = "allowlist"`) | It names the ceiling: a built-in class, or an operator class via `class_dir` + `class_digest` (below). `egress` is optional — an empty list is a legitimate "no route out" posture, and `run` says so out loud. |

Everything else is defaulted, and every default is the restrictive one:
`mounts = []`, `env = {}`, `secrets = []`, `read_only = true`,
`required = true`, `protocol = "tls"`, `cpus = 1`, `memory = 1g`, `pids = 256`,
`nofile = 1024`. There is no field you can omit to get *more* access.

### The refusals you will hit first

`agentjail profile validate <profile>` prints every error it finds, each prefixed
with the path of the offending value, and it also runs the checks `run` would
refuse on (a named network for `mode = "none"`, a `home` directly under `/`, a
`delivery = "file"` secret) plus the class-subset check. It is the one command
that catches all of these before anything starts.

| What you wrote | What you get |
| --- | --- |
| `mode = "none"` with `[[network.egress]]` | "mode \"none\" means no egress; N destination(s) are declared but would never be reachable" |
| `mode = "none"` with `class = …` | "needs mode = \"allowlist\"; mode \"none\" has no route out" |
| `mode = "none"` with `dns = "gateway"` | "mode \"none\" has no resolver; set dns = \"none\"" |
| `mode = "allowlist"` without `class` | "required with mode \"allowlist\"…" |
| `mode = "allowlist"` with `network.name` | "does not take a network name; the per-run class network is created for you" |
| `mode = "allowlist"` with no `egress` entries | **not an error.** The run starts and prints `agentjail: egress grant is empty: this jail has no route out` — see [below](#the-smallest-allowlist-profile) |
| `class_dir` without `class_digest`, or the reverse | "give both or neither. A directory without a digest is policy that can change under a reviewed profile; a digest without a directory pins nothing." |
| `class_dir` with no `class` in the profile | "required with network.class_dir; it names <class>.toml inside the directory" |
| an operator class named like a built-in | "cannot name an operator class: it is either one of the built-in classes (model, external, internal) or not lowercase alphanumerics/'-'. An operator class must not shadow a built-in one, so the same name never means two policies." |
| a `class_digest` that does not match the file | "class config … does not match the digest this profile pins: expected …, found …. Re-read the file before changing the digest: the pin exists so a policy change is a review event." |
| a relative, FUSE-backed, `,`/`=`-bearing, or `/run`-ish `class_dir` | refused, by name; the directory is bind-mounted, so it follows the mount rules |
| `dns = "pinned"` | "not implemented yet… use dns = \"gateway\"" |
| `host = "*.example.com"` | "wildcards are not allowed; list each destination explicitly" |
| `host = "https://api.example.com"` | "give a bare DNS name; schemes, paths, and ports belong in other fields" |
| a destination its class does not list | "the profile asks for destinations its egress class does not permit", naming the entry and the class file |
| `source` on a FUSE path | "is an AppImage runtime mount; FUSE-backed paths cannot be bind-mounted…" |
| `target = "/home/agent"` (the `home`) | "is the jail home; mount elsewhere" |
| `target = "/proc"`, `"/sys"`, `"/dev"`, `"/run"` | "part of the jail's own runtime surface" |
| `target = "/"` | "is the jail root, which cannot be replaced by a mount; pick a directory such as \"/work/data\"" |
| a mount path containing `,` or `=` | "contains ',' or '=', which podman reads as --mount option syntax" |
| an unknown key anywhere | "unknown field …, expected one of …" |
| `value = "…"` in a secret | "inline secret material is not allowed … use source = "env" \| "file" \| "store"" |
| `env.SOME_TOKEN = "…"` | "names that look like credentials are rejected" |
| `env.X = "<32+ characters of mixed letters and digits>"` | "value looks like a credential" |
| `workdir == home`, or `home = "/"` | refused, by name |

Two of these are not visible failures, which is why they get their own rows in
the common-mistakes list below: a host environment variable the agent expects is
simply *absent*, and a name that is in neither the class nor the profile simply
does not resolve.

One message in that table states an intent that the runtime does not keep: in
`mode = "none"` the jail **does** get a resolver. See
[below](#mode--none-still-resolves-names).

### Operator-defined classes: `class_dir` + `class_digest`

The three built-in classes are ceilings somebody else wrote for you. A policy of
your own is a file, a directory, and a pin:

```toml
[network]
class = "bot"                                  # not a built-in name
class_dir = "/srv/agentjail/classes"           # absolute host path
class_digest = "sha256:<64 hex>"                # sha256sum /srv/agentjail/classes/bot.toml
mode = "allowlist"
dns = "gateway"
```

- **Both fields or neither.** A directory without a digest is policy that can
  change under a reviewed profile; a digest without a directory pins nothing. One
  alone is a validation error, and the file must be `<class_dir>/<class>.toml` and
  must declare that same class name.
- **Same rules as a built-in class.** The file is parsed with the identical
  semantic rules: byte budget and connection cap required, no raw addresses, no
  duplicate entries, and `address_policy` defaulting to `public` (the restrictive
  value; `lan` is a decision you have to write down). A malformed operator class
  fails the way a malformed built-in one does.
- **The digest is the review.** `run` hashes the file and refuses a mismatch, so
  an edited class cannot silently widen a posture a profile was reviewed for: the
  class file and the profile's pin change together, in the same review.
- **No shadowing, no environment override.** An operator class may not reuse
  `model`, `external`, or `internal`, so one name never means two policies, and
  nothing in the environment can point a run at a different directory. Policy a
  run depends on is named by the profile.
- **Reading it back** needs the same pair, because the audit read resolves the
  class from it: `agentjail audit --class bot --class-dir /srv/agentjail/classes
  --class-digest sha256:<64 hex>`. Per-run audit files are keyed by class *name*
  under `<state>/audit/<class>/`, so two operator classes that share a name in
  different directories share one audit directory — give each policy its own name.

The shipped `gateway/classes/internal.toml` is a working example of the format,
though its three names are placeholders you would replace.

### One minimal profile (no egress)

Start here. If the task cannot be done with this file, add one field at a time.
The canonical version is [`profiles/minimal.toml`](../profiles/minimal.toml).

```toml
version = 1
workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:<64 hex characters from podman image inspect>"

[network]
name = "agentjail-minimal"   # an existing internal network; run creates none
mode = "none"
dns = "none"

[resources.tmpfs]
"/tmp" = "64m"

[agent]
command = "bash"
args = ["-l"]
```

```sh
podman build -f images/base/Containerfile -t localhost/agentjail-base:1 images/base
podman image inspect --format '{{.Digest}}' localhost/agentjail-base:1   # paste this
podman network create --internal agentjail-minimal
agentjail profile validate profiles/minimal.toml
agentjail run profiles/minimal.toml -- id -u      # must print 10000
podman network rm agentjail-minimal                # when you are done
```

The example files in `profiles/` carry an all-zero placeholder digest. It is a
well-formed pin, so validation passes; `run` fails with `image not known`,
because no image in your local store has that digest. That is the placeholder
working as intended.

`--pull=never` is in the launcher's argv, so nothing is fetched at run time: the
image must already exist locally and the digest must match it.

### `mode = "none"` still resolves names

Do not read `dns = "none"` as "no resolver". The validator requires that value
for this mode (it refuses `dns = "gateway"` here), but inside a network created
with `podman network create --internal` — the quickstart's own command — the jail
gets netavark's resolver anyway (for example `nameserver 10.89.6.1`), because the
launcher creates only the *allowlist* networks with `--disable-dns`.

What `run` does about that: a named network with no egress gets `--dns-search .`
too, so the resolver cannot turn a short name into an internal one through a host
search domain (measured before that fix: `search dns.podman lan.internal…
bajnok.dev`). What protects the posture is neither knob: the network is empty —
no other peer — and has no route out, so a name that resolves has nowhere to
connect.

Use `mode = "none"` to make reaching anything impossible. Do not use it to make
name resolution impossible, and do not read `dns = "none"` as a DNS policy.

### The smallest allowlist profile

The canonical version is [`profiles/allowlist.toml`](../profiles/allowlist.toml);
the two parts that matter are the class (the ceiling) and the profile's list (the
grant):

```toml
[network]
class = "model"
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "api.anthropic.com"   # port 443 is the only TLS destination that works
port = 443
```

What this reaches is the **intersection**: here one host on 443, because `model`
lists it and the profile asks for it. A host `model` lists but this profile does
not ask for is `NXDOMAIN` in the jail, and a `CONNECT` to it by name is refused
`reason=not-in-profile`. `agentjail profile show` prints that intersection, so the
grant is readable before anything runs:

```sh
agentjail profile show profiles/allowlist.toml | jq .egress
# { "class": "model", "grant": [ "api.anthropic.com:443" ] }
```

The posture worth copying is the ordering: start with `mode = "none"`, add one
grant entry when a real task fails, and never add one because an agent might want
it. Adding a class entry alone grants nothing — the class is the ceiling, and the
profile's list is what has to ask.

#### A grant of nothing is a posture, not an error

`mode = "allowlist"` with `egress = []` is no longer refused. It is a deliberate
shape: the class side still starts (per-run network, gateway, per-run audit
files), the jail still gets a resolver and the proxy variables, and the gateway
permits nothing. `run` says so on stderr:

```text
agentjail: egress grant is empty: this jail has no route out
```

Use it when you want the agent's environment to look like an egress jail — proxy
variables set, a resolver, audit files written — while proving that nothing
leaves. If you want no class side at all, use `mode = "none"` with a named
internal network; if you want one destination, this shape plus one
`[[network.egress]]` entry is the smallest thing that reaches exactly that.

### Common mistakes

- **Mounting the host's home.** `source = "/home/me"` is legal, validates, and
  hands the agent your keys, mail, other repositories, and shell history. Mount
  the one project directory, read-only unless the agent must write.
- **Mounting a socket.** Validation checks paths, not file types: a bind mount
  whose source is a unix socket is accepted. `/var/run/docker.sock` passes, and so
  does the rootless `/run/user/<uid>/podman/podman.sock` — that path is not one of
  the FUSE patterns, so the FUSE refusal does not catch it either. Either one
  inside the jail is the host, handed over deliberately. There is no legitimate
  reason for a jail to have one.
- **Assuming the agent inherits your environment.** It does not. The jail's
  environment is the *image's* own `ENV` plus `HOME`, `TERM`, the profile's
  `[env]` literals, and the `[[secrets]]` targets — and every one of those is
  visible in the image's Containerfile or your profile. No host variable is
  passed, and `PATH` is the image's `PATH`, so a tool your shell finds may still
  be missing. An agent that expects `OPENAI_BASE_URL`, `HTTP_PROXY=…`, `LANG`, or
  `TZ` gets it only if the image or the profile says so.
- **Expecting a name to resolve because *one* of the two lists has it.** A
  destination needs both lines: the class is the ceiling, the profile's
  `[[network.egress]]` is the grant. In the class but not the profile: NXDOMAIN in
  the jail, `reason=not-in-profile` through the proxy. In the profile but not the
  class: refused before anything starts. A short name that resolves to something
  else is a host search domain, not this.
- **Expecting a class file to be a per-profile policy.** Every profile of a class
  shares its ceiling, so editing `gateway/classes/<class>.toml` to narrow one jail
  narrows (or widens) all of them. A policy of your own is an operator class:
  `network.class_dir` + `network.class_digest`, pinned and parsed like a built-in
  one (§4).
- **Mounting over `home`.** `target` may not equal `home`; mount a subdirectory
  or somewhere else entirely, and remember `home` itself is scratch.
- **`source = "~/skills"`.** There is no shell to expand `~`; sources are absolute
  host paths or they are errors.
- **Expecting `mode = "none"` to create a network.** It attaches to the internal
  network you named; create it first (`podman network create --internal …`).
- **Reading the digest as provenance.** The digest pins *which* local image runs;
  it does not attest that the image was built from the commit you think. Reproving
  that is your build's job.

## 5. Per-agent recipes (examples of the shape, not supported configurations)

Each recipe is four lines of shape: what goes in the image, which config path the
agent reads, the stdio invocation, and the one rule that breaks if you get it
wrong. Versions and flags move; your agent's own documentation is authoritative,
and `images/base` already carries Node 24, Python 3.11, git, and ripgrep.

| Agent | Image contents | Config the agent reads | Stdio invocation | The rule you break |
| --- | --- | --- | --- | --- |
| **pi** | `npm i -g --ignore-scripts @earendil-works/pi-coding-agent@<version>` | agent dir `~/.pi/agent` (`PI_CODING_AGENT_DIR`): `settings.json`, `skills/`, `mcp.json`; project `.pi/` | `pi --mode rpc --no-session` (JSONL on fd 0/1), or `pi -p "<prompt>"` for one turn | Its agent dir is read *and written* (sessions, auth). A baked, read-only agent dir looks like a broken agent unless sessions are redirected (`--session-dir` / `--no-session`). |
| **Claude Code** | `npm i -g --ignore-scripts @anthropic-ai/claude-code@<version>` | `~/.claude/settings.json` and the separate global `~/.claude.json` (MCP servers, project trust) | `claude -p "<prompt>"`; add `--verbose` if you ask for `--output-format stream-json` | There are **two** paths. Mounting only `~/.claude/` silently drops the MCP servers and trust settings that live in `~/.claude.json`, and a read-only `~/.claude/` breaks transcript writes under `projects/`. |
| **Codex** | `npm i -g --ignore-scripts @openai/codex@<version>` | `$CODEX_HOME` (default `~/.codex`): `config.toml`, `auth.json` | `codex exec "<prompt>"` | The interactive TUI needs a TTY; stdio here is pipes. Use `exec`, and pre-grant anything the agent would normally ask for — no approval prompt can reach you through a pipe. |
| **OpenCode** | `npm i -g --ignore-scripts opencode-ai@<version>` | `~/.config/opencode/opencode.json` (follows `XDG_CONFIG_HOME`), auth in `~/.local/share/opencode/auth.json` | `opencode run "<prompt>"` | It reads XDG paths, and the jail inherits no environment. If you relocate with `XDG_CONFIG_HOME`/`XDG_DATA_HOME`, set both in `[env]` and mount both; half a pair gives config without credentials. |

Three shared rules that are not in the table:

- **`home` is scratch.** A config directory left at its default lives in
  `/home/agent/…`, which is empty on every run. Either mount it (a subdirectory
  of `home` is fine; `home` itself is not) or bake it and point the agent's own
  env var at it.
- **The model API host must be in the class and in the profile.** `model`
  already lists `api.anthropic.com`, `api.openai.com`, `openrouter.ai`, and
  `generativelanguage.googleapis.com` on 443 — that is the ceiling, so each still
  needs a `[[network.egress]]` line to be in the grant. A self-hosted or gateway
  endpoint needs both lines as well.
- **Credentials go in `[[secrets]]`, not `[env]`.** `env.ANTHROPIC_API_KEY` is
  rejected by name, which is the validator pointing you at the right field.

## 6. Deployment checklist

In order, with what proves each step. Do not skip a verification: every step
here fails loudly, and every step after it assumes the previous one held.

| # | Step | Verify with | What success looks like |
| --- | --- | --- | --- |
| 1 | Host has a working rootless Podman | `agentjail doctor` (and one `podman run --rm … echo ok` if it is a fresh host) | `result: ok`; `podman rootless true`; storage driver and cgroup version reported; `selinux` state reported. doctor does not check subuid/subgid ranges — a fresh host that fails on id mapping needs `usermod --add-subuids/--add-subgids` and `podman system migrate`. |
| 2 | Build (or pull) the jail image and pin it | `podman image inspect --format '{{.Digest}}' localhost/agentjail-base:1`, paste into `image.digest` | A `sha256:…` you pasted, not the all-zero placeholder |
| 3 | Write the profile, minimal first | `agentjail profile validate <profile>` and `agentjail profile show <profile>` | `OK`, the image pin, and (for an allowlist profile) `egress.grant` — the intersection you will actually get |
| 4 | Prove the jail runs at all | `agentjail run <profile> -- id -u` | `10000` — not `0`, not your uid |
| 5 | Prove the jail has no host reach | `agentjail run <profile> -- sh -c 'env; ls /home'` | No host variable, no host home: what is there is the image's `ENV` plus what the profile declared. |
| 6 | Add the destinations the agent actually needs | the class file (`gateway/classes/<class>.toml`, or your operator class) is the ceiling; the profile's `[[network.egress]]` is the grant. Add both where needed | `profile validate` prints "grant of N destination(s) out of M the class allows"; `profile show` lists exactly those N. A class-only entry does not appear in the grant |
| 7 | Prove the route works and the policy bites | one real successful agent turn; a CONNECT to a host the **class** lists but this profile does not (e.g. `https://api.openai.com` against `profiles/allowlist.toml`); a CONNECT to a host outside the class (`https://example.com`); then `agentjail audit --class <class> --decision deny` | An allow line with `resolved=`/`pinned=` for the good turn; `403`/`reason=not-in-profile` for the class-but-not-profile one, `403`/`reason=not-in-class` for the outside one, both with `deny` lines in the run's audit files |
| 8 | Prove the jail itself before trusting it | `agentjail selftest --baseline`, then `agentjail selftest <profile>` | Both exit `0`; baseline proves each hazard is real, jailed proves each is denied, `positive-control` answers |
| 9 | Decide about secrets | `agentjail run <profile> --no-secrets -- env` vs the normal run | The secret's target is absent in the first, present in the second |
| 10 | Record the evidence beside the change | commit the image digest, the profile, the class-file change, and both selftest outputs | A reviewer can reproduce the posture from the commit, not from memory |

Steps 2–4 are the README quickstart; steps 8–10 are `docs/adopting.md` steps 5
and 6. Step 6 is the one people get wrong, because the class and the profile look
like two halves of one decision: they are, and the order is ceiling first, grant
second. `agentjail profile show <profile> | jq .egress` prints the result, which is
the list to check before you run anything.

### Reading the audit and DNS streams afterwards

Every run leaves two files per class, under the state directory `agentjail doctor`
already reports (`$XDG_STATE_HOME/agentjail`, default
`~/.local/state/agentjail`):

```text
<state>/audit/<class>/<jail-id>.audit.log   # one line per connection decision
<state>/audit/<class>/<jail-id>.dns.log     # one line per DNS query
```

`<jail-id>` is `<profile>-<pid>`. The gateway writes them through a writable bind
mount of that class's audit directory; the class config is untouched and the
container's own log is not the record. So a finished run **is** auditable, and you
do not have to remember to capture anything:

```sh
agentjail audit --class model                        # both streams, all retained runs
agentjail audit --class model --decision deny        # every refusal
agentjail audit --class model --jail web-4242        # one run only
agentjail audit --class bot --class-dir /srv/agentjail/classes --class-digest sha256:<64 hex>
```

Files are read newest run first and the merged view is in time order; `--tail`
applies after filtering. `run` keeps the newest 20 runs per class and prunes older
ones at its start, removing a run's two files together, so the window is "the last
20 runs of that class", not a time. Two things worth knowing in the same breath:
retention is a run count with no time guarantee (a busy night can push yesterday
out), and the gateway *container's* log still dies with `--rm`, so `podman logs`
remains the live view while a jail runs, not the archive.

Gateway containers carry `io.agentjail.class` and `io.agentjail.jail` labels, which
is how you find the live one:

```sh
podman ps --filter label=io.agentjail.jail --format '{{.Names}} {{.Labels}}'
```

If no per-run files exist yet (a class you have never run, or a state directory
someone cleaned), `audit` says so and falls back to the class config's own
`audit_log`/`dns_log` — which for the shipped classes is `-`, so it reports that
the stream is the runtime's log instead of printing an empty result that looks
like "no activity".

### When the agent starts but cannot answer

**The usual cause is a missing line for the agent's model host — in the class, in
the profile, or both.** The symptom is specific: the agent starts, loads, lists
its tools, and every model call fails. Confirm it from inside the jail before
touching anything:

```sh
# a working tunnel answers with the provider's own 4xx (no credential needed)
agentjail run <profile> -- sh -c \
  'curl -sS -o /dev/null -w "%{http_code}\n" https://api.anthropic.com'
```

| What you see | Meaning |
| --- | --- |
| A `4xx` (typically `401`/`404`) from the provider | The grant includes the model host and the tunnel worked. The model host is fine; look at credentials or the agent's own config. |
| `403` and `reason=not-in-class` in the audit stream | The class does not list it. Add it to `gateway/classes/<class>.toml` (the ceiling) and to the profile's `[[network.egress]]` (the grant), then rerun. |
| `403` and `reason=not-in-profile` | The class lists it; this profile does not ask for it. Add the profile entry — the class needs nothing. |
| `curl` fails with a connect error, and the DNS stream shows `decision=answer` for the host | The client resolved the name, was given `127.0.0.1`, and did not use the proxy. Set `NODE_USE_ENV_PROXY = "1"` for Node 24 or the client's own proxy setting. |
| The DNS stream shows `decision=nxdomain reason=not-in-profile` | In the class, not in the grant — the same fix as the `not-in-profile` row. |
| The DNS stream shows `decision=nxdomain reason=not-in-class` | No class entry at all. |

A missing line is indistinguishable from a broken agent by feel: the process is
up, the first request hangs or errors, and nothing says "policy". The rest of the
list separates the remaining causes — each row names the evidence that rules out
the row above it.

| Evidence | Diagnosis | Fix |
| --- | --- | --- |
| DNS stream shows `qname=<host> decision=nxdomain reason=not-in-class` | The class does not list the name the agent asked for. | Add it to the class **and** to the profile. |
| DNS stream shows `qname=<host> decision=nxdomain reason=not-in-profile` | The class lists it; this profile does not ask for it. | Add it to the profile only. |
| DNS stream shows `decision=answer` for the name, and the audit stream has **no** line for it | The client ignored `HTTPS_PROXY` (or its runtime needs to be told). It dialled the loopback answer and reached nothing. | Make the client use the proxy: `NODE_USE_ENV_PROXY = "1"` in `[env]` for Node 24, or the client's own proxy setting. |
| Audit stream shows `decision=deny reason=not-in-profile` | The client used the proxy; the name is inside the ceiling but not in this profile's grant. | Add the `[[network.egress]]` entry; the class needs no change. |
| Audit stream shows `decision=deny reason=not-in-class` | The client used the proxy; the name is outside the ceiling. | Add the class entry, then the profile entry. |
| Audit stream shows `decision=deny reason=not-connect` and the client got `405` | Plain HTTP through the proxy. | TLS front, or a stdio server (shape A). See §3 shape C. |
| Audit stream shows `decision=deny reason=blocked-private`/`blocked-<range>` with `address=` | The name resolves into a range the class's `address_policy` refuses — a rebind, or a LAN name in a `public` class. | Use the `internal` class if LAN reach is the intent (a review event); otherwise treat the answer as an attack. |
| Audit stream shows `decision=deny reason=byte-budget` or `connection-cap` | The agent hit the class's ceiling. | Raise `max_bytes`/`max_connections` in the class file (review event) or reduce the work. |
| The agent fails with a certificate error naming your own front | Self-signed CA not trusted in the jail. | Mount the CA and set the runtime's variable (§3). |
| The agent fails with `EACCES`/`EROFS` writing config or state | A read-only mount (or the read-only rootfs) is where it wants to write. | Mount that path `read_only = false`, or point the agent's own state directory at `home`/tmpfs. |
| The agent fails to find its own binary or a tool | Not in the image. `PATH` is the image's, and nothing from the host is visible. | Add it to the image; do not mount a host install. |
| The agent exits immediately, or refuses to run | Nothing network-related: read the exit code and stderr. `run` exits `1` before starting on a profile/preflight refusal, `2` on a usage error, and otherwise passes the agent's own code through. | Fix what the message names; `agentjail profile validate` covers most of them. |

Two commands while doing this: `agentjail audit --class <class> --decision deny
--tail 50` (the per-run files, readable after the run) and `agentjail doctor
--network <name>` (the outside half of the single-route invariant for an existing
network). Use `--jail <id>` when several runs are retained and you want one.

## 7. What agentjail does not do for you

- **It is not a secret manager.** No storage, no encryption, no rotation. It
  reads a reference and injects the value into the agent's environment, where the
  agent, anything it spawns, and anything that can read `/proc/<pid>/environ`
  inside the jail can see it. One credential per jail, by reference.
- **It does not install agents.** No image is published, nothing is bundled, and
  no version is managed. You build an image, pin its digest, and own the update.
- **It does not merge profiles.** One profile is one run: no includes, no
  inheritance, no environment overlays, and unknown keys are rejected rather than
  ignored. To vary a run, write a second profile.
- **It does not protect a hostile host.** The host user, the host kernel, the
  container runtime, the profile, the image, and the agentjail binary are all
  trusted input. A kernel or runtime escape, or a host user with your uid, is
  outside every guarantee here (`docs/threat-model.md`).
- **It does not filter packets.** The class allowlist is a decision the gateway
  makes. Nothing behind it inspects traffic, so a compromised gateway can open
  any socket its egress leg allows, and the class allowlist becomes a hint.
- **It does not rate-limit.** A byte budget and a connection cap bound totals per
  jail, not speed.
- **It does not authenticate DNS.** The gateway resolves with the host's
  resolvers, checks every answer against the class policy, and connects to a
  checked address. A hostile resolver can still answer with a public address of
  its choosing.
- **It does not proxy plain HTTP or raw TCP**, does not implement `dns = "pinned"`,
  does not route IPv6, and does not give your agent a TTY.
- **It does not make an allowlist optional.** Skipping the class entry does not
  produce a degraded mode; it produces an unreachable destination and a denial in
  the audit stream. Skipping the *profile* entry does the same, with a different
  reason (`not-in-profile`), because the grant is the intersection. Both files are
  policy; editing either is a review event, and for an operator class the digest
  makes that literal.

### Still not implemented, stated where it bites

Each of these is a limit of this build rather than a missing flag, and each is
written up beside the guarantee it limits in `docs/egress-classes.md` and
`docs/threat-model.md`:

- **Plain HTTP and raw TCP through the proxy.** `CONNECT` is the only transport;
  `protocol = "http"`/`"tcp"` are inert (§3 shape C).
- **`dns = "pinned"`** is refused by validation instead of being silently
  ignored.
- **Secret files** (`secrets[].delivery = "file"`) are refused by `run`: secrets
  are environment variables only, which the agent and anything it spawns can read.
- **IPv6 egress.** Class networks are IPv4-only and verified that way, so an
  AAAA-only destination is unreachable.
- **A rate limit.** A byte budget and a connection cap bound totals per jail, not
  speed.
- **Gateway image provenance.** The image is pinned by ID at run time, which fixes
  which image runs; it does not attest that the ID was built from this commit, so
  a stale local image is possible.
