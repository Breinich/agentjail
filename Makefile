# One entry point for "green before pushing", so the rule is one command rather
# than a list that goes stale. CI runs `make check` too: a local pass and a CI
# pass are the same command.
#
# The real-podman proofs are NOT part of `check`: they need podman, the base
# image and the gateway image, which a developer machine may not have. CI runs
# them in its own job (`make proofs` after building the static binaries).

CARGO ?= cargo

.PHONY: check
check:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings
	$(CARGO) test --workspace --locked

# The proof script expects the static binaries, the base image and the gateway
# image to exist already (see the header of scripts/prove-egress-classes.sh).
.PHONY: proofs
proofs:
	scripts/prove-egress-classes.sh

.PHONY: help
help:
	@echo "make check   fmt --check, clippy -D warnings (all targets), workspace tests"
	@echo "make proofs  the real-podman egress proofs (needs podman and both images)"
