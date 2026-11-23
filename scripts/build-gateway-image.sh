#!/bin/sh
# Build the gateway image from an already-built static binary.
#
# The build context is a staging directory, not the repository: the image only
# needs the binary and the committed class configs, and a repository-wide
# context would drag `target/` into the daemon.
#
#   scripts/build-gateway-image.sh [<binary> [<tag>]]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=${1:-$root/target/x86_64-unknown-linux-musl/release/agentjail-gateway}
tag=${2:-localhost/agentjail-gateway:1}

if [ ! -x "$binary" ]; then
  echo "missing static gateway binary: $binary" >&2
  echo "build it with: cargo build --locked --release --target x86_64-unknown-linux-musl -p agentjail-gateway" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$binary" "$stage/agentjail-gateway"
cp -r "$root/gateway/classes" "$stage/classes"
(cd "$stage" && chmod 0755 agentjail-gateway)

podman build --pull=never -f "$root/images/gateway/Containerfile" -t "$tag" "$stage"
echo "built $tag from $binary"
