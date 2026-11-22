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
5. **Prove the jail** before trusting it: run `agentjail selftest <profile>` on
   the same host and record the result alongside the change that introduced
   the profile.
6. **Adopt incrementally**: start with `mode = "none"`, add a destination only
   when a real task fails, and treat every added mount, secret, and named
   network as a review event.

## What is not ready

- `run` and `selftest` exit with code 3 (not implemented).
- The gateway parses an allowlist but does not proxy or resolve anything yet.
- The inside half of the single-route check needs the run path.
- There is no secret injection and no resource enforcement yet.
- The base image is not built or published by CI.
- There is no published crate; build from a checkout with the pinned toolchain
  (`cargo build --release`), or use the static musl binaries built in CI.

Do not adopt this for anything with real credentials until the gateway, the
inside network check, and `selftest` exist — and pass on the host you care
about.

## Diagrams in this repository

Diagrams are **UML-shaped Mermaid**: `sequenceDiagram` for interactions,
`stateDiagram-v2` for lifecycle, `classDiagram`/`erDiagram` if a data model
appears. Mermaid `flowchart`/`graph` is not used for architecture or behaviour:
that syntax is not UML and it accepts relationships that mean nothing.

GitHub renders Mermaid natively, so it is the only diagram language a reader
sees without plugins. A deployment/component view of the jail, network, gateway,
and trust boundary is a **UML deployment diagram**, which Mermaid cannot express
faithfully; that one is deliberately not drawn yet. If it is added, it becomes
PlantUML source rendered by CI to a committed SVG with a drift check — a
decision for a later PR, not tooling to pre-build now.

Checkability: `crates/agentjail/tests/diagrams.rs` fails the build when a
Mermaid block uses a forbidden type (`flowchart`, `graph`) or an unknown diagram
type. That is a type-level lint, not a full syntax check. Full validation needs
`@mermaid-js/mermaid-cli`, which downloads Puppeteer/Chromium (hundreds of
megabytes, minutes of CI time); the trade-off is flagged in the PR that
introduced this policy rather than hidden in a job.
