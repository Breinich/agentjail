# Adopting agentjail

**Status: stub.** This document describes the intended adoption path. Nothing
here is implemented in increment 1, and it is deliberately not written as if it
were.

## What adoption will look like

1. **Build or pull the base image**, pinned by digest
   (`images/README.md`).
2. **Write a profile** for the task: image digest, one workspace mount, no
   egress or the smallest allowlist that works, one credential by reference.
   Validate it with `agentjail profile validate`.
3. **Run the agent**: `agentjail run <profile> -- <agent command…>`, keeping
   stdio as pipes and letting the launcher forward signals and the exit code
   (`docs/cli.md`).
4. **Prove the jail** before believing it: run `agentjail selftest <profile>`
   on the same host and record the result alongside the change that introduced
   the profile.
5. **Adopt incrementally**: start with `mode = "none"`, add a destination only
   when a real task fails, and treat every added mount and secret as a review
   event.

## What is not ready

- `run` and `selftest` exit with code 3 (not implemented).
- There is no egress gateway, no DNS pinning, and no secret injection yet.
- The base image is not built or published by CI.
- There is no published package; use `pip install -e .` from a checkout.

Do not adopt this for anything with real credentials until `selftest` exists and
passes on the host you care about.
