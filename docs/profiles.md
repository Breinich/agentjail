# Profile reference

A profile is a TOML file describing one jail. It is validated twice:

1. **structurally**, against `schema/profile.schema.json` (JSON Schema 2020-12,
   a documented subset — see [Validation](#validation)); and
2. **semantically**, against rules JSON Schema cannot express well (unique jail
   paths, secret targets that must live on tmpfs, FUSE-backed mounts, duplicate
   egress entries, placeholders).

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
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "api.example.com"
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
disk = "4g"

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
| `network` | table | yes | — | Egress posture (below). |
| `resources` | table | no | see below | Limits. |
| `agent` | table | yes | — | The command to run. |

Unknown top-level keys are rejected. There is no "extra" escape hatch: a field
that is not documented is not passed through.

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

- Two mounts may not share a `target`.
- `target` may not be `/`, `/proc`, `/sys`, `/dev`, or `/run`, and may not equal
  `home`.
- **FUSE-backed sources are rejected**: `/tmp/.mount_*` (AppImage runtime
  mounts), `/run/user/*/gvfs`, `/run/user/*/doc`, `/dev/fuse`, and any path
  ending in `.AppImage`. `crun` cannot bind-mount these (`cannot stat
  self/fd/N: Permission denied`). Copy the runtime into the image, or into a
  normal directory that is itself a bind mount.

Nothing outside the image and these targets exists inside the jail.

### `[env]`

Values must be strings, integers, or booleans; they are stringified by
`profile show` and by the launcher. This table is for **literal, non-secret**
values (`LANG`, `TZ`, `TERM`, cache paths).

Rejected with a specific error:

- names matching credential-like patterns (`*_TOKEN`, `*_SECRET`,
  `*_PASSWORD`, `*_API_KEY`, `*_PRIVATE_KEY`, `*_CREDENTIAL(S)`, `AUTH*`, …);
- values that look like a long unbroken token (≥32 characters of
  `[A-Za-z0-9_-]` mixing letters and digits).

Use `[[secrets]]` for anything credential-shaped.

### `[[secrets]]`

Secrets are **references**. A profile never contains a secret value; the keys
`value`, `values`, `inline`, `literal`, `plaintext`, `content`, `contents`, and
`data` are rejected with an error that says so.

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
- `mode` is only valid with `delivery = "file"`; it is dropped for `env`.
- `agentjail run --no-secrets` resolves none of them. A profile with secrets
  stays valid; the secrets simply never enter the jail.

One credential per agent, by reference: give a jail the one credential the task
needs.

### `[network]`

| Field | Required | Rule |
| --- | --- | --- |
| `mode` | yes | `none` or `allowlist`. |
| `dns` | yes | `none`, `gateway`, or `pinned`. |
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
| `none` (default posture) | `none` | Internal network, no route out, no resolver. `egress` must be empty or absent. |
| `allowlist` | `gateway` | The gateway answers DNS for allowlisted names only and is the only route out. |
| `allowlist` | `pinned` | No recursive resolver; static entries only. The gateway is still the only route out. |

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
| `disk` | string | — | Writable-layer size limit, e.g. `4g`. |
| `tmpfs` | table | `{}` | Absolute in-jail path → size (`"/tmp" = "64m"`). |

Semantic rules: tmpfs keys must be absolute paths, and every size (including
`tmpfs` values) must match the size pattern. `disk` is enforced through the
container storage driver's per-container size option; `agentjail doctor` reports
the storage driver because some drivers (`vfs`) cannot enforce it.

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
each prefixed with the path of the offending value:

```text
$ agentjail profile validate profiles/broken.toml
agentjail: error: profile /repo/profiles/broken.toml is invalid (3 error(s)):
  - secrets[0] (forge_token): inline secret material is not allowed (found 'value'); use source = "env" | "file" | "store" plus a ref that names where the secret already lives
  - network: missing required property 'dns'
  - mounts[0].source: '/tmp/.mount_1a2b3c/agent' is a FUSE-backed path; FUSE-backed paths cannot be bind-mounted into the jail (crun: cannot stat self/fd/N: Permission denied). copy the runtime into the image (images/base/Containerfile) or into a directory that is itself a normal bind mount, e.g. under {workdir}/.tools
```

Errors are collected rather than fail-fast on the first problem, so one run
tells you everything to fix. Schema errors are reported before semantic errors;
semantic checks are skipped when the document's shape is already wrong, to avoid
noise.

The JSON Schema subset enforced by `src/agentjail/schema.py` is:
`type`, `const`, `enum`, `properties`, `required`, `additionalProperties`,
`items`, `minItems`, `maxItems`, `uniqueItems`, `pattern`, `minLength`,
`maxLength`, `minimum`, `maximum`, `allOf`, `anyOf`, `oneOf`, `not`,
`if`/`then`/`else`, and local `$ref` into `$defs`. Any other keyword in a schema
position is a hard error at load time, so the schema can never mean more than the
validator enforces. Annotations (`title`, `description`, `default`, `$comment`,
`$id`, `$schema`, `$defs`) are ignored.

The canonical schema is `schema/profile.schema.json`. An installed wheel ships a
byte-identical copy at `src/agentjail/data/profile.schema.json`; CI runs
`python scripts/sync_schema.py --check` so the two cannot drift.

## `profile show`

`agentjail profile show <profile>` prints JSON:

```json
{
  "name": "minimal",
  "source": "/repo/profiles/minimal.toml",
  "profile": { "version": 1, "...": "defaults resolved" }
}
```

Defaults are materialised here (`read_only = true`, `protocol = "tls"`,
`secrets[].delivery = "env"`, resource defaults, …) so what a launch would use
is visible before it happens. Secret **references** are shown; values never are
— they are not in the profile.
