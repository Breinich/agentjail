#!/bin/sh
# The gateway image tag for one workspace: `localhost/agentjail-gateway:ws-<8 hex>`.
#
# Not one shared mutable tag: two checkouts on a machine that build a gateway from
# different code would otherwise overwrite each other, and a run -- or a proof --
# would silently execute the other workspace's binary. The tag is derived from the
# workspace root's physical path, so a build, a run and a proof in one workspace
# agree, and two workspaces never collide.
#
# This is the shell half of the rule in `agentjail_core::run::gateway_image_tag`;
# a test asserts the two produce the same tag for the same workspace.
#
#   scripts/gateway-image-tag.sh [<workspace-root>]
set -eu

root=${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
physical=$(CDPATH= cd -- "$root" && pwd -P)
printf 'localhost/agentjail-gateway:ws-%s\n' "$(printf '%s' "$physical" | sha256sum | cut -c1-8)"
