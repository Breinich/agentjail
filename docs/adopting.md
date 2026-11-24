# Adopting agentjail

**Status: stub.** This document describes the intended adoption path. Nothing
here is implemented in increment 1, and it is deliberately not written as if it
were.

## What adoption will look like

1. **Build or pull the base image**, pinned by digest (`images/README.md`).
2. **Write a profile** for the task: image digest, one workspace mount, no
   egress or the smallest allowlist that works, one credential by reference.
   Validate it with `agentjail profile validate`.
3. **Verify the network** before believing the profile: the jail's only route
   out must be the gateway, checked from outside (network metadata) and from
   inside (the jail sees no other peer) on every start.
4. **Run the agent**: `agentjail run <profile> -- <agent command…>`, keeping
   stdio as pipes and letting the launcher forward signals and the exit code
   (`docs/cli.md`).
5. **Prove the jail** before trusting it: run `agentjail selftest --baseline`
   and `agentjail selftest <profile>` on the same host and record both results
   alongside the change that introduced the profile. Baseline must exit `0`
   (every hazard is real); jailed must exit `0` (every hazard is denied).
6. **Adopt incrementally**: start with `mode = "none"`, add a destination only
   when a real task fails, and treat every added mount, secret, and named
   network as a review event.

## What is not ready

- `run` supports `network.mode = "none"` and `network.mode = "allowlist"` with
  one of the three committed egress classes (`docs/egress-classes.md`). The three
  proofs and the lifecycle cases run in the normal `ci` job.
- `selftest` runs in both modes in `ci`: `--baseline` with no podman, and jailed
  after the egress proofs' podman setup. The egress class proofs remain a
  separate script for class membership and lifecycle.
- The gateway implements `CONNECT` only: a plain `http://` destination is
  refused, and `protocol = "http"`/`"tcp"` egress entries do nothing yet.
- Class membership is enforced from outside the jail; the *inside* half of the
  single-route check (no second peer, interface or route) is asserted by the
  jailed `selftest` cases and by the proof script.
- Secrets are injected by reference through podman's secret store (env vars
  only); entries this run created are removed at exit, dead-pid entries by the
  next run of the same profile.
- The gateway image (`localhost/agentjail-gateway:1`) is built locally, not
  published or pinned by digest.
- The base image is not built or published by CI.
- There is no published crate; build from a checkout with the pinned toolchain
  (`cargo build --release`), or use the static musl binaries built in CI.

Do not adopt this for anything with real credentials until the gateway, the
inside network check, and both `selftest` modes exist — and pass on the host you
care about.

## Diagrams in this repository

Diagrams are **PlantUML**, because they must be real UML — a deployment view of
the jail, network, gateway, and trust boundary, plus sequence and state
diagrams for behaviour. The `.puml` sources live in `docs/diagrams/`, their
rendered `.svg` files are committed next to them, and Markdown embeds the SVG.

Why not the classic GitHub PlantUML proxy service
(`https://www.plantuml.com/plantuml/proxy?src=...`): this repository is private, and
the proxy fetches `raw.githubusercontent.com` **unauthenticated**, so it cannot
read these files at all; even when public, it makes every README view depend on
a third party and always renders the latest commit, not the one being read. A
render hop on every read is the wrong default for a repository about isolation.

CI (job `diagrams`, read-only `contents: read`) pulls the official PlantUML
image **by digest** (`docker.io/plantuml/plantuml@sha256:2cf2f097…`, version
1.2026.10), runs `-checkonly` so a syntax error fails the build, renders with
`-tsvg`, and then fails if `git diff --exit-code docs/diagrams` reports any
change — which also catches a stale or hand-edited SVG. It never commits.

Re-render locally with the same command:

```sh
podman run --rm --user 0:0 -v "$PWD/docs/diagrams":/d \
  docker.io/plantuml/plantuml@sha256:2cf2f097652701319e29b9e6a809e68d4ddb06fbeeb696705c097da8fa6d0507 \
  -tsvg /d/*.puml
```

`--user 0:0` is only needed for rootless podman, where the image's default user
cannot otherwise write into the bind mount.
