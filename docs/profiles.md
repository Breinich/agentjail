# Profile reference

A profile is a TOML file describing one jail. It is parsed into typed structs
(`crates/agentjail-core/src/profile.rs`) and validated three ways:

1. **TOML parsing**, so syntax errors are reported first;
2. **JSON Schema** validation against `schema/profile.schema.json`, which is
   embedded in the binaries with `include_str!` — an installed `agentjail`
   cannot run against a stale or missing copy, and CI fails at build time if the
   file disappears;
3. **typed deserialisation** (`deny_unknown_fields`) plus **semantic rules**
   JSON Schema cannot express: unique in-jail paths, secret delivery targets
   that must live on a declared tmpfs, FUSE-backed mount sources crun cannot
   bind, duplicate egress entries, placeholders.

Everything is agent-agnostic. A profile names an executable and arguments; it
never names a harness, a session, a vendor, or a credential type.

## Finding a profile

`<profile>` on the command line is either:

- a path (`/path/to/profile.toml`, `./profiles/minimal.toml`), or
- a bare name (`minimal`), looked up as `<name>.toml` in, in order:
  1. each `--profile-dir DIR` given on the command line,
  2. `$AGENTJAIL_PROFILE_DIR`,
  3. `./profiles`,
  4. `$XDG_CONFIG_HOME/agentjail/profiles` (default `~/.config/agentjail/profiles`).

The error lists every path it tried.

## Example

```toml
version = 1
description = "Coding jail with one allowlisted destination."

workdir = "/work"
home = "/home/agent"

[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[network]
class = "model"
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "api.anthropic.com"
port = 443
protocol = "tls"

[[mounts]]
source = "/home/me/src/project"
target = "/work/project"
read_only = true

[[secrets]]
name = "forge_token"
source = "env"
ref = "EXAMPLE_FORGE_TOKEN"
target = "EXAMPLE_FORGE_TOKEN"

[resources]
cpus = 2
memory = "2g"
pids = 512
nofile = 2048

[resources.tmpfs]
"/tmp" = "128m"

[agent]
command = "my-agent"
args = ["--mode", "rpc", "--workdir", "{workdir}"]
```

Complete files: `profiles/minimal.toml` (no egress) and
`profiles/allowlist.toml` (one destination, one mount, one secret).

## Top-level fields

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `version` | integer | yes | — | Profile format version; must be `1`. |
| `description` | string | no | — | Human summary, 1–500 chars. |
| `image` | table | yes | — | Image reference (below). |
| `workdir` | string | yes | — | Absolute path, the jail's working directory. Not `/`. |
| `home` | string | yes | — | Absolute path, the jail's home. Not `/`, not equal to `workdir`. |
| `mounts` | array of tables | no | `[]` | Host paths exposed inside the jail. |
| `env` | table | no | `{}` | Literal, non-secret environment values. |
| `secrets` | array of tables | no | `[]` | Credentials, by reference only. |
| `network` | table | yes | — | Egress posture and the single-route invariant (below). |
| `resources` | table | no | see below | Limits. |
| `agent` | table | yes | — | The command to run. |

Unknown keys are rejected. There is no "extra" escape hatch: a field that is not
documented is not passed through.

## Defaults audit: what may be omitted, and why

A field whose absence could silently produce a permissive or ambiguous
configuration is **required**, never defaulted. "No egress" and "the operator
forgot" must not look identical in a profile.

Required with no default: `version`, `image.name`, `image.digest`, `workdir`,
`home`, `network`, `network.mode`, `network.dns`, `agent.command`.

Defaulted, each because absence is **strictly restrictive or unambiguous**:

| Field | Default | Why that is safe |
| --- | --- | --- |
| `mounts` | `[]` | No extra host access. |
| `env` | `{}` | No extra environment. |
| `secrets` | `[]` | No credentials. |
| `network.egress` | `[]` | In `mode = "none"` there is nothing to reach; in `mode = "allowlist"` an empty list is a validation error. |
| `network.name` | none | **Required by `run` in `mode = "none"`**: there agentjail attaches to an existing internal network and does not create one. Verified on every start. An allowlist profile names no network: its per-run class network is created and verified for you. |
| `mounts[].read_only` | `true` | Writable access must be requested. |
| `mounts[].required` | `true` | A missing path fails the launch instead of silently shrinking the jail. |
| `secrets[].delivery` | `"env"` | `file` is valid schema but refused by `run`: secrets are injected as environment variables only. |
| `secrets[].mode` | `0400` for file delivery only | Not accepted at all for env delivery. |
| `network.egress[].protocol` | `"tls"` | The inspected protocol; `tcp` (uninspected) must be explicit and is limited to 443. |
| `resources` | `cpus = 1`, `memory = 1g`, `pids = 256`, `nofile = 1024`, `tmpfs = {}` | Conservative caps, not permissive ones. |
| `agent.args` | `[]` | Only the command runs. |

### `[image]`

| Field | Required | Rule |
| --- | --- | --- |
| `name` | yes | Fully qualified reference with registry and optional tag, e.g. `ghcr.io/org/agentjail-base:1`. Lowercase repository, optional `:tag`. |
| `digest` | yes | `sha256:` followed by 64 lowercase hex characters. |

A tag alone is rejected. Tags move; the digest is the pin the launcher verifies
before starting the jail. Build a local image and read the digest with:

```sh
podman build -f images/base/Containerfile -t localhost/agentjail-base:1 images/base
podman image inspect --format '{{.Digest}}' localhost/agentjail-base:1
```

### `[[mounts]]`

| Field | Required | Default | Rule |
| --- | --- | --- | --- |
| `source` | yes | — | Absolute host path. |
| `target` | yes | — | Absolute in-jail path. |
| `read_only` | no | `true` | Writable mounts must be requested explicitly. |
| `required` | no | `true` | If `false`, a missing host path skips the mount instead of failing the launch. |

Semantic rules:

- `source` and `target` are **lexically normalised** when the profile is parsed:
  `.`, `..`, repeated `/`, and a trailing `/` collapse, so `/proc/`, `//proc`,
  and `/work/../proc` are one string. There is no filesystem resolution and no
  symlink following: a source may not exist yet, and neither side is read the
  way the host would read it. Validation, `profile show`, and the podman argv
  all use that one normalised string. Because it is lexical, `..` after a
  symlink is collapsed as text (`/a/link/../b` becomes `/a/b`), which is not
  what the kernel would do: write the path you mean.
- Two mounts may not share a `target` (compared after normalisation).
- `target` may not be `/`, `/proc`, `/sys`, `/dev`, or `/run` (after
  normalisation, so every traversal spelling is refused), and may not equal
  `home`.
- `source` may not be `/`, `/proc`, `/sys`, `/dev`, or `/run` either: those are
  the host's own runtime surface (host processes, devices, kernel state), not a
  data path.
- Neither `source` nor `target` may contain `,` or `=`: both reach podman's
  `--mount` option parser, where those characters separate options.
- **FUSE-backed sources are rejected**: AppImage runtime mounts (`/tmp/.mount_*`),
  AppImage files (`*.AppImage`), gvfs and document-portal mounts
  (`/run/user/*/gvfs`, `/run/user/*/doc`), and `/dev/fuse`. `crun` cannot
  bind-mount these (`cannot stat self/fd/N: Permission denied`). Copy the runtime
  into the image, or into a normal directory that is itself a bind mount.

Nothing outside the image and these targets exists inside the jail.

### `[env]`

Values must be strings, integers, or booleans; they are stringified by
`profile show` and by the launcher. This table is for **literal, non-secret**
values (`LANG`, `TZ`, `TERM`, cache paths).

Rejected with a specific error:

- names whose underscore-separated tokens look like credentials (`PASS`,
  `PASSWORD`, `SECRET`, `TOKEN`, `APIKEY`, `CREDENTIAL(S)`, `AUTH`, `BEARER`,
  and the `API_KEY`/`PRIVATE_KEY`/`ACCESS_KEY` forms);
- values that look like a long unbroken token (≥32 characters of
  `[A-Za-z0-9_-]` mixing letters and digits).

Use `[[secrets]]` for anything credential-shaped.

### `[[secrets]]`

Secrets are **references**. A profile never contains a secret value; the keys
`value`, `values`, `inline`, `literal`, `plaintext`, `content`, `contents`, and
`data` are rejected with an error that says so, before any other validation.

| Field | Required | Default | Rule |
| --- | --- | --- | --- |
| `name` | no | `target` | Label for diagnostics; never printed with a value. |
| `source` | yes | — | `env`, `file`, or `store`. |
| `ref` | yes | — | Where the secret already lives (see below). |
| `delivery` | no | `env` | `env` or `file`. |
| `target` | yes | — | In-jail destination (see below). |
| `mode` | only for `delivery = "file"` | `0400` | Octal file mode. |

`ref` by source:

| `source` | `ref` is | Example |
| --- | --- | --- |
| `env` | a host environment variable name | `EXAMPLE_FORGE_TOKEN` |
| `file` | an absolute host file path | `/run/user/1000/secrets/forge` |
| `store` | a credential-store item identifier (`[A-Za-z0-9._:/@-]`) | `default/forge-token` |

`target` by delivery:

| `delivery` | `target` is | Rules |
| --- | --- | --- |
| `env` (default) | the environment variable name the agent process sees | `[A-Za-z_][A-Za-z0-9_]*` |
| `file` | an absolute in-jail path | must be inside a directory declared in `resources.tmpfs` |

Semantics:

- `delivery = "env"` puts the value in the agent process environment only.
  Nothing is written to the image, to a bind mount, or to the jail filesystem.
- `delivery = "file"` stages the value on a **size-limited tmpfs** and refuses
  any target that is not under a declared tmpfs, so a secret can never land on a
  bind mount or the image's writable layer.
- Two secrets may not share a `target`.
- `mode` is only valid with `delivery = "file"`; it is rejected for `env`.
- `agentjail run --no-secrets` resolves none of them. A profile with secrets
  stays valid; the secrets simply never enter the jail.

One credential per agent, by reference: give a jail the one credential the task
needs.

### `[network]`

| Field | Required | Rule |
| --- | --- | --- |
| `name` | no | Attach to this existing podman network instead of creating one (`mode = "none"` only; refused with `allowlist`). Verified against the single-route invariant on **every** start; `run` refuses a network that is not internal. Pattern: `[A-Za-z0-9][A-Za-z0-9._-]{0,62}`. |
| `class` | with `allowlist` | Egress class: `model`, `external`, or `internal`. It names the internal network the jail joins, and therefore which committed allowlist (`gateway/classes/<class>.toml`) applies. The agent cannot change it from inside. Refused with `mode = "none"`. |
| `mode` | yes | `none` or `allowlist`. |
| `dns` | yes | `none`, `gateway`, or `pinned`. `pinned` parses and is **refused by validation as not implemented**; `gateway` is the only accepted resolver with `mode = "allowlist"`. |
| `egress` | no | Array of destinations; required non-empty when `mode = "allowlist"`. |

`dns` has **no default**: leaving it out is an error, not a silent choice. An
inherited host search domain can turn an unqualified name into an internal
address and quietly defeat an allowlist, so the DNS strategy is always explicit.
When the jail has a resolver (allowlist mode), the launcher additionally passes
`--dns-search .` so host search domains cannot leak in. With `dns = "none"`
there is no resolver at all, and Podman rejects DNS options together with an
isolated network.

| `mode` | `dns` | Meaning |
| --- | --- | --- |
| `none` (safe posture) | `none` | Internal network, no route out, no resolver. `egress` must be empty. |
| `allowlist` | `gateway` | Joined to the per-run class network; the class gateway is the only peer, the resolver, and the proxy. `egress` must be a subset of the class allowlist. |
| `allowlist` | `pinned` | **Refused by validation** ("not implemented yet"): the launcher always starts the class gateway as the resolver, so this value would be a knob with no enforcement behind it. |

#### `[[network.egress]]`

| Field | Required | Default | Rule |
| --- | --- | --- | --- |
| `host` | yes | — | Bare DNS name. No scheme, no path, no port, no wildcard. |
| `port` | yes | — | Integer, 1–65535. |
| `protocol` | no | `tls` | `tls` (CONNECT with SNI pinning), `http` (plaintext CONNECT), `tcp` (raw relay). |

Semantic rules:

- Duplicate `(host, port, protocol)` triples are rejected.
- A wildcard (`*.example.com`) is rejected: list each destination.
- `protocol = "tcp"` is only accepted on port 443; raw TCP is not inspected by
  the gateway, so it is not offered as a general-purpose escape.

Keep the list small. A coding agent commonly needs one destination on 443; add
entries when a task actually fails, not pre-emptively.

## `[resources]`

| Field | Type | Default | Rule |
| --- | --- | --- | --- |
| `cpus` | number | `1` | 0.1–64 cores. |
| `memory` | string | `1g` | `^[0-9]+[kKmMgG]?$`. |
| `pids` | integer | `256` | 1–4194304. |
| `nofile` | integer | `1024` | 64–1048576. |

| `tmpfs` | table | `{}` | Absolute in-jail path → size (`"/tmp" = "64m"`). |

Semantic rules: tmpfs keys must be absolute paths, and every size must match
the size pattern; `run` mounts each as a bounded tmpfs.

There is deliberately **no `disk` field**: the rootfs is mounted read-only, so
the only writable space is this scratch. "Writable scratch" is therefore the
sum of the tmpfs sizes below, and it is enforced by the mounts themselves. An
unknown `disk` key is rejected as an unknown property rather than silently
ignored.

## `[agent]`

| Field | Required | Default | Rule |
| --- | --- | --- | --- |
| `command` | yes | — | Executable name resolved from `PATH` inside the jail, or an absolute in-jail path. A relative path containing `/` is rejected. |
| `args` | no | `[]` | Default arguments. Placeholders `{workdir}` and `{home}` are expanded; any other `{...}` is rejected. |

`agentjail run <profile> -- <command…>` **overrides** both fields; the profile's
`[agent]` is only used when no command follows `--`.

## Validation

`agentjail profile validate <profile>` exits `0` and prints the resolved image
and a summary, or exits `1` and prints **every** error it found, one per line,
each prefixed with the path of the offending value. Errors are collected rather
than fail-fast, and a structural error in one section does not hide the specific
semantic errors in the others:

```text
$ agentjail profile validate /tmp/broken.toml
agentjail: error: profile /tmp/broken.toml is invalid (8 error(s)):
  - secrets[0] (EXAMPLE_TOKEN): inline secret material is not allowed (found "value"); use source = "env" | "file" | "store" plus a ref that names where the secret already lives
  - network.egress[0].host: "*.example.com" does not match "^[a-zA-Z0-9]…"
  - secrets[0]: Additional properties are not allowed ('value' was unexpected)
  - typed profile: TOML parse error at line 25, column 1
     |
  25 | value = "fake-not-real"
     | ^^^^^
   unknown field `value`, expected one of `name`, `source`, `ref`, `delivery`, `target`, `mode`
  - mounts[0].source: "/tmp/.mount_1a2b3c/agent" is an AppImage runtime mount; FUSE-backed paths cannot be bind-mounted into the jail (crun: cannot stat self/fd/N: Permission denied). Copy the runtime into the image (images/base/Containerfile) or into a directory that is itself a normal bind mount, e.g. under {workdir}/.tools
  - network.egress[0].host: wildcards are not allowed; list each destination explicitly
  - network.egress[0].host: "*.example.com" is not a valid DNS name
  - agent.args[0]: unknown placeholder {nope}; supported placeholders are {home}, {workdir}
```

The schema is standard JSON Schema 2020-12; the validator is the `jsonschema`
crate built **without its HTTP resolver**, so validating a profile cannot make a
network request. Layering is deliberate: the schema is the language-independent
contract, the typed structs are what the launcher actually consumes, and the
semantic rules cover the cross-field constraints. `schema/profile.schema.json`
is canonical and embedded at compile time, so the two cannot drift.

## `profile show`

`agentjail profile show <profile>` prints JSON:

```json
{
  "name": "allowlist",
  "source": "/repo/profiles/allowlist.toml",
  "profile": { "version": 1, "...": "defaults resolved" }
}
```

Defaults are materialised here (`read_only = true`, `protocol = "tls"`,
`secrets[].delivery = "env"`, resource defaults, …) so what a launch would use
is visible before it happens. Secret **references** are shown; values never are
— they are not in the profile.
