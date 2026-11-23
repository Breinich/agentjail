#!/bin/sh
# Egress class proofs. Real podman, real internal networks, real gateway
# containers, real audit lines.
#
#   proof 1  class membership beats ACL text: a jail on `model` cannot reach a
#            destination `external` allows, and the other way round;
#   proof 2  a raw IP:port is refused, through the proxy and dialled directly;
#   proof 3  an allowed destination answers through the proxy, and the audit
#            stream records the connection with its byte counts;
#   proof 4  a denied destination is refused and logged as a denial.
#   proof 5  lifecycle: a normal, a failed and a signal-terminated run each leave
#            no network and no gateway behind, a SIGKILLed run is cleaned up by
#            the next run of the same profile, and no other profile's resources
#            are touched.
#
# Proofs 1, 2 and 4 run against the **committed** class configs in
# gateway/classes. Proof 3 needs a destination that answers, and CI must not
# depend on an external host, so it uses a proof-only class config that adds one
# loopback target this script starts. Nothing else differs.
#
# Requires: rootless podman, the static binaries, the gateway image, the pin.
#   cargo build --locked --release --target x86_64-unknown-linux-musl -p agentjail -p agentjail-gateway
#   scripts/build-gateway-image.sh
#   podman pull "$JAIL_IMAGE"
#   scripts/prove-egress-classes.sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin=$root/target/x86_64-unknown-linux-musl/release
agentjail=$bin/agentjail

# The jail for these proofs is the image images/base is built FROM: pinned by
# digest there already, has bash (for /dev/tcp) and node (for the target server),
# and is pulled, never built in this script.
JAIL_IMAGE=${JAIL_IMAGE:-docker.io/library/node:24-bookworm-slim@sha256:0e2646ab57e77b7a384a0cb59b6815b182c77e1f9c3ba36bd8435bd9c4e6680e}

work=$(mktemp -d)
target_net="agentjail-proof-target-$$"
target_name="agentjail-proof-target-$$"
failures=0

cleanup() {
  podman rm -f "$target_name" >/dev/null 2>&1 || true
  podman network rm -f "$target_net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

say() { printf '\n=== %s\n' "$*"; }
ok() { printf 'PASS  %s\n' "$*"; }
fail() {
  printf 'FAIL  %s\n' "$*" >&2
  failures=$((failures + 1))
}
expect() { # file, needle, label
  if grep -q -- "$2" "$1"; then
    ok "$3"
    printf '      %s\n' "$(grep -m1 -- "$2" "$1")"
  else
    fail "$3: expected $2"
    sed 's/^/      /' "$1" >&2
  fi
}

[ -x "$agentjail" ] || {
  echo "missing static binary: $agentjail" >&2
  exit 1
}
podman image exists "$JAIL_IMAGE" || {
  echo "missing proof jail image $JAIL_IMAGE; run: podman pull $JAIL_IMAGE" >&2
  exit 1
}
podman image exists localhost/agentjail-gateway:1 || {
  echo "missing gateway image; run: scripts/build-gateway-image.sh" >&2
  exit 1
}
digest=$(podman image inspect --format '{{.Digest}}' "$JAIL_IMAGE")

# ------------------------------------------------------------------ fixtures

class_config() { # path class allow-entry...
  path=$1
  class=$2
  shift 2
  {
    printf 'class = "%s"\n' "$class"
    printf 'listen = "0.0.0.0:3128"\n'
    printf 'dns = "0.0.0.0:53"\n'
    printf 'allow = [\n'
    for entry in "$@"; do printf '  "%s",\n' "$entry"; done
    printf ']\n'
  } > "$path"
}

profile_for() { # path name class egress-host egress-port
  path=$1
  class=$3
  cat > "$path" <<EOF
version = 1
# The proof jail is a stock slim image: /work only exists in images/base, and
# these proofs must not pay for that image build.
workdir = "/tmp"
home = "/home/agent"

[image]
name = "${JAIL_IMAGE%@sha256:*}"
digest = "$digest"

[network]
class = "$class"
mode = "allowlist"
dns = "gateway"

[[network.egress]]
host = "$4"
port = $5

[agent]
command = "bash"
args = ["-lc"]
EOF
}

# The jail-side helper: send one CONNECT through the proxy the jail was given and
# print the status line. bash /dev/tcp is used instead of curl so the image does
# not need extra packages.
CONNECT_FN='
send() {
  proxy=${HTTPS_PROXY#http://}
  host=${proxy%%:*}
  port=${proxy##*:}
  printf "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" "$1" "$1" \
    | timeout 10 bash -c "exec 3<>/dev/tcp/$host/$port; cat >&3; head -1 <&3"
}
'

# One jail run, with the gateway's log streams captured before the guard removes
# the gateway container.
run_jail() { # label profile script wait-for-log
  label=$1
  profile=$2
  script=$3
  wait_for=${4:-}
  say "jail $label"
  # The hold gives this script time to capture the gateway's streams before the
  # run ends and the guard removes it.
  "$agentjail" run "$profile" -- bash -lc "$script; sleep 6" \
    > "$work/$label.out" 2> "$work/$label.err" &
  agentjail_pid=$!

  gateway=""
  deadline=$(( $(date +%s) + 45 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    gateway=$(podman ps --format '{{.Names}}' 2>/dev/null | grep -- '-gateway$' | head -1 || true)
    [ -n "$gateway" ] && break
    sleep 0.5
  done
  if [ -z "$gateway" ]; then
    fail "$label: no gateway container appeared"
    sed 's/^/      /' "$work/$label.err" >&2
    kill "$agentjail_pid" 2>/dev/null || true
    wait "$agentjail_pid" 2>/dev/null || true
    return
  fi

  if [ -n "$wait_for" ]; then
    deadline=$(( $(date +%s) + 30 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      if podman logs "$gateway" 2>/dev/null | grep -q -- "$wait_for"; then break; fi
      sleep 0.5
    done
  fi
  # DNS is on stderr and the audit stream on stdout: one call, two separate files.
  podman logs "$gateway" > "$work/$label.audit" 2>"$work/$label.dns" || true
  wait "$agentjail_pid" || fail "$label: agentjail exited non-zero ($(sed -n 1p "$work/$label.err"))"
  printf '      jail output: %s\n' "$(tr '\n' '|' < "$work/$label.out")"
}

# ------------------------------------------------------- proof 1: the class wins

profile_for "$work/proof-model.toml" proof-model model api.anthropic.com 443
profile_for "$work/proof-external.toml" proof-external external github.com 443

run_jail model-committed "$work/proof-model.toml" "$CONNECT_FN
echo \"github-connect=\$(send github.com:443)\"
echo \"anthropic-connect=\$(send api.anthropic.com:443)\"
echo \"github-dns=\$(getent hosts github.com || echo nxdomain)\"
echo done" "dest=github.com:443 decision=deny"

expect "$work/model-committed.out" 'github-connect=HTTP/1.1 403 Forbidden' \
  'proof 1: a jail on `model` is refused a destination `external` allows'
expect "$work/model-committed.out" 'github-dns=nxdomain' \
  'proof 1: the resolver NXDOMAINs the same name for `model`'
expect "$work/model-committed.audit" 'decision=deny reason=not-in-class' \
  'proof 1: the refusal is a logged denial (committed model class)'
expect "$work/model-committed.dns" 'qname=github.com qtype=1 decision=nxdomain' \
  'proof 1: the NXDOMAIN query is logged on the DNS stream'

run_jail external-committed "$work/proof-external.toml" "$CONNECT_FN
echo \"anthropic-connect=\$(send api.anthropic.com:443)\"
echo done" "dest=api.anthropic.com:443 decision=deny"

expect "$work/external-committed.out" 'anthropic-connect=HTTP/1.1 403 Forbidden' \
  'proof 1: a jail on `external` is refused a destination `model` allows'
expect "$work/external-committed.audit" 'decision=deny reason=not-in-class' \
  'proof 1: the refusal is a logged denial (committed external class)'

# A profile cannot widen its class: the same destination written into the profile
# text is refused before anything is created.
say "profile text cannot widen the class"
set +e
"$agentjail" run "$work/proof-model.toml" -- bash -lc 'true' >/dev/null 2>&1
model_exit=$?
set -e
ordinary_profile=$work/proof-model.toml
sed -i 's/^host = "api.anthropic.com"$/host = "github.com"/' "$ordinary_profile"
set +e
"$agentjail" run "$ordinary_profile" -- bash -lc 'true' > "$work/widen.out" 2> "$work/widen.err"
widen_exit=$?
set -e
if [ "$widen_exit" -eq 1 ] && grep -q 'is not in egress class "model"' "$work/widen.err"; then
  ok 'proof 1: a profile asking for another class destination is refused before start'
  printf '      %s\n' "$(grep -m1 'not in egress class' "$work/widen.err")"
else
  fail "proof 1: a widened profile was not refused (exit $widen_exit)"
  sed 's/^/      /' "$work/widen.err" >&2
fi
[ "$model_exit" -eq 0 ] || fail "proof 1: the unmodified model profile failed to run"

# ------------------------------------------- proofs 2, 3, 4: one reachable target

say "starting the proof target on $target_net"
podman network create "$target_net" >/dev/null
podman run -d --rm --name "$target_name" --network "$target_net" "$JAIL_IMAGE" \
  node -e 'const net=require("net");[9001,9002].forEach(p=>net.createServer(s=>{s.end("hello from "+p+"\n")}).listen(p))' \
  >/dev/null
target_ip=""
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  target_ip=$(podman container inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$target_name" 2>/dev/null || true)
  [ -n "$target_ip" ] && break
  sleep 0.5
done
[ -n "$target_ip" ] || {
  echo "the proof target never got an address" >&2
  exit 1
}
echo "target $target_name at $target_ip:9001 (model) and :9002 (external)"

mkdir -p "$work/classes"
class_config "$work/classes/model.toml" model "$target_name:9001"
class_config "$work/classes/external.toml" external "$target_name:9002"
class_config "$work/classes/internal.toml" internal "$target_name:9001"
profile_for "$work/proof-target.toml" proof-target model "$target_name" 9001

export AGENTJAIL_CLASS_DIR=$work/classes
export AGENTJAIL_EGRESS_NETWORK=$target_net

run_jail target "$work/proof-target.toml" "$CONNECT_FN
echo \"allowed=\$(send $target_name:9001)\"
echo \"denied=\$(send $target_name:9002)\"
echo \"raw-ip=\$(send $target_ip:9001)\"
set +e
timeout 5 bash -c \"exec 3<>/dev/tcp/$target_ip/9001\" 2>/dev/null
direct=\$?
set -e
echo \"direct-dial-exit=\$direct\"
echo done" "dest=$target_name:9001 decision=allow"

expect "$work/target.out" 'allowed=HTTP/1.1 200 Connection established' \
  'proof 3: an allowed destination answers through the proxy'
expect "$work/target.audit" "dest=$target_name:9001 decision=allow" \
  'proof 3: the audit stream records it with the jail id and the class'
expect "$work/target.audit" 'class=model jail=proof-target-' \
  'proof 3: the audit line carries class and jail id'

expect "$work/target.out" 'denied=HTTP/1.1 403 Forbidden' \
  'proof 4: a destination outside the class is refused'
expect "$work/target.audit" "dest=$target_name:9002 decision=deny reason=not-in-class" \
  'proof 4: the refusal is logged as a denial'

expect "$work/target.out" 'raw-ip=HTTP/1.1 403 Forbidden' \
  'proof 2: CONNECT to a raw IP:port is refused'
expect "$work/target.audit" "dest=$target_ip:9001 decision=deny reason=ip-literal" \
  'proof 2: the raw-IP refusal is logged as an ip-literal denial'
if grep -q '^direct-dial-exit=0$' "$work/target.out"; then
  fail 'proof 2: a direct dial to the target IP succeeded from inside the jail'
else
  ok "proof 2: a direct dial to $target_ip:9001 fails closed from inside the jail"
  printf '      %s\n' "$(grep '^direct-dial-exit=' "$work/target.out")"
fi

# ------------------------------------------------------------ proof 5: lifecycle

say "lifecycle: a failed run leaves nothing behind"
profile_for "$work/proof-fail.toml" proof-fail model "$target_name" 9001
set +e
"$agentjail" run "$work/proof-fail.toml" -- bash -lc 'exit 7' >/dev/null 2>&1
fail_exit=$?
set -e
[ "$fail_exit" -eq 7 ] && ok 'lifecycle: the agent exit code is passed through' \
  || fail "lifecycle: expected exit 7, got $fail_exit"
sleep 0.5
leftover=$(podman network ls --format '{{.Name}}' | grep '^agentjail-proof-fail-' || true)
[ -z "$leftover" ] && ok 'lifecycle: a failed run leaves no network' \
  || fail "lifecycle: a failed run left $leftover"

say "lifecycle: SIGKILLed run is pruned by the next run of the same profile only"
"$agentjail" run "$work/proof-fail.toml" -- bash -lc 'sleep 60' >/dev/null 2>&1 &
killed_pid=$!
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  podman network ls --format '{{.Name}}' | grep -q '^agentjail-proof-fail-' && break
  sleep 0.5
done
kill -9 "$killed_pid" 2>/dev/null || true
wait "$killed_pid" 2>/dev/null || true
sleep 0.5
stale=$(podman network ls --format '{{.Name}}' | grep '^agentjail-proof-fail-' || true)
[ -n "$stale" ] && ok "lifecycle: a SIGKILLed run leaves $stale (uncatchable, by design)" \
  || fail 'lifecycle: expected a SIGKILLed run to leave its network behind (it did not, so this proof proves nothing)'

# Another profile must not touch it.
class_config "$work/classes/internal.toml" internal "$target_name:9001"
profile_for "$work/proof-other.toml" proof-other model "$target_name" 9001
"$agentjail" run "$work/proof-other.toml" -- bash -lc 'true' >/dev/null 2>&1 || true
still_there=$(podman network ls --format '{{.Name}}' | grep '^agentjail-proof-fail-' || true)
[ "$still_there" = "$stale" ] && ok 'lifecycle: another profile does not prune it (no profile-prefix pruning)' \
  || fail "lifecycle: another profile's run touched $stale"

# Same profile again: only the dead pid is pruned.
"$agentjail" run "$work/proof-fail.toml" -- bash -lc 'true' >/dev/null 2>&1 || true
sleep 0.5
after=$(podman network ls --format '{{.Name}}' | grep '^agentjail-proof-fail-' || true)
[ -z "$after" ] && ok 'lifecycle: a later run of the same profile prunes the dead pid entry' \
  || fail "lifecycle: leftover after the prune: $after"

# The proof target is this script's own fixture, not the run path's.
podman rm -f "$target_name" >/dev/null 2>&1 || true
podman network rm -f "$target_net" >/dev/null 2>&1 || true
unset AGENTJAIL_CLASS_DIR AGENTJAIL_EGRESS_NETWORK || true

say "lifecycle: nothing of ours is left behind"
ours=$(podman network ls --format '{{.Name}}' | grep '^agentjail-proof-' || true)
[ -z "$ours" ] && ok 'no agentjail-proof-* network remains' \
  || fail "networks left behind: $ours"
ours=$(podman ps -a --format '{{.Names}}' | grep '^agentjail-proof-' || true)
[ -z "$ours" ] && ok 'no agentjail-proof-* container remains' \
  || fail "containers left behind: $ours"
stale_tests=$(podman network ls --format '{{.Name}}' | grep '^agentjail-test-' || true)
[ -z "$stale_tests" ] && ok 'no agentjail-test-* network remains' \
  || fail "stale test networks on this host: $stale_tests"

printf '\n'
if [ "$failures" -ne 0 ]; then
  echo "FAILED: $failures proof(s)" >&2
  exit 1
fi
echo "all egress class proofs passed"
