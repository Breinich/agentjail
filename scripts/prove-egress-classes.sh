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
#            are touched;
#   proof 6  the per-jail byte budget cuts a connection and logs the refusal with
#            the counter that caused it;
#   proof 7  the per-jail connection cap refuses a second tunnel and logs it.
#
# Proofs 1, 2 and 4 run against the **committed** class configs in
# gateway/classes. Proofs 3, 6 and 7 need a destination that answers, and CI must
# not depend on an external host, so they use a proof-only class config that
# names a target container this script starts on its own network. That config
# sets `address_policy = "lan"` because the target's address is RFC1918;
# `model`/`external` ship `public`, which refuses exactly that answer. Nothing
# else differs.
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

class_config() { # path class max-bytes max-connections address-policy allow-entry...
  path=$1
  class=$2
  max_bytes=$3
  max_connections=$4
  policy=$5
  shift 5
  {
    printf 'class = "%s"\n' "$class"
    printf 'listen = "0.0.0.0:3128"\n'
    printf 'dns = "0.0.0.0:53"\n'
    printf 'max_bytes = %s\n' "$max_bytes"
    printf 'max_connections = %s\n' "$max_connections"
    printf 'address_policy = "%s"\n' "$policy"
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

# The jail-side helpers: one CONNECT through the proxy the jail was given and
# print the status line. bash /dev/tcp is used instead of curl so the image does
# not need extra packages.
#
# `connect_ok` retries briefly, and the reason is stated rather than hidden: the
# fixture is addressed by podman container name, and the gateway resolves that
# name through the embedded DNS of its egress leg, which can lag a just-started
# container by a fraction of a second. A proof that needs a successful tunnel
# must measure the thing it is about (the cap, the budget) and not that race. It
# does not soften anything: a genuinely refused destination still fails on the
# last attempt, and the printed status is the one the assertion reads.
PROXY_LIB='
proxy=${HTTPS_PROXY#http://}
proxy_host=${proxy%%:*}
proxy_port=${proxy##*:}

connect() { # fd target
  eval "exec $1<>/dev/tcp/$proxy_host/$proxy_port"
  printf "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" "$2" "$2" >&"$1"
  head -1 <&"$1"
}

connect_ok() { # fd target
  attempt=0
  while : ; do
    status=$(connect "$1" "$2")
    case "$status" in *" 200 "*) break ;; esac
    attempt=$((attempt + 1))
    [ "$attempt" -ge 5 ] && break
    sleep 1
  done
  echo "$status"
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

  # Snapshot the gateway's streams on every poll, not only after the wait below:
  # a run can end - and its gateway container be removed with it - before the
  # wait finishes, and a proof cannot assert on the logs of a container that is
  # gone. A failed capture never overwrites the last good one. DNS is on stderr
  # and the audit stream on stdout, so one call keeps them in two separate files.
  snapshot() {
    if podman logs "$gateway" > "$work/$label.audit.tmp" 2> "$work/$label.dns.tmp"; then
      mv "$work/$label.audit.tmp" "$work/$label.audit"
      mv "$work/$label.dns.tmp" "$work/$label.dns"
    fi
  }
  if [ -n "$wait_for" ]; then
    deadline=$(( $(date +%s) + 30 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      snapshot
      if grep -q -- "$wait_for" "$work/$label.audit"; then break; fi
      kill -0 "$agentjail_pid" 2>/dev/null || break
      sleep 0.5
    done
  fi
  snapshot
  wait "$agentjail_pid" || fail "$label: agentjail exited non-zero ($(sed -n 1p "$work/$label.err"))"
  printf '      jail output: %s\n' "$(tr '\n' '|' < "$work/$label.out")"
}

# ------------------------------------------------------- proof 1: the class wins

profile_for "$work/proof-model.toml" proof-model model api.anthropic.com 443
profile_for "$work/proof-external.toml" proof-external external github.com 443

run_jail model-committed "$work/proof-model.toml" "$PROXY_LIB
echo \"github-connect=\$(connect 3 github.com:443)\"
echo \"anthropic-connect=\$(connect 3 api.anthropic.com:443)\"
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

run_jail external-committed "$work/proof-external.toml" "$PROXY_LIB
echo \"anthropic-connect=\$(connect 3 api.anthropic.com:443)\"
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
# 9001/9002 answer one line and close; 9003 floods 1 MiB, which is what the byte
# budget in proof 6 must cut short; 9004 answers and **stays open**, which is what
# lets proof 7 hold one tunnel while it attempts a second. Every socket gets an
# error handler: the budget proof ends with the gateway cutting the tunnel
# mid-write, and an unhandled EPIPE in the fixture would kill the target
# container and make the *next* proof fail for a reason that has nothing to do
# with what it asserts.
podman run -d --rm --name "$target_name" --network "$target_net" "$JAIL_IMAGE" \
  node -e 'const net=require("net");const serve=(p,fn)=>net.createServer(s=>{s.on("error",()=>{});fn(s)}).listen(p);serve(9001,s=>s.end("hello from 9001\n"));serve(9002,s=>s.end("hello from 9002\n"));const f=Buffer.alloc(1048576,120);serve(9003,s=>s.end(f));serve(9004,s=>s.write("held\n"))' \
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
class_config "$work/classes/model.toml" model 268435456 8 lan "$target_name:9001"
class_config "$work/classes/external.toml" external 268435456 8 lan "$target_name:9002"
class_config "$work/classes/internal.toml" internal 268435456 8 lan "$target_name:9001"
profile_for "$work/proof-target.toml" proof-target model "$target_name" 9001

export AGENTJAIL_CLASS_DIR=$work/classes
export AGENTJAIL_EGRESS_NETWORK=$target_net

run_jail target "$work/proof-target.toml" "$PROXY_LIB
echo \"allowed=\$(connect_ok 3 $target_name:9001)\"
echo \"denied=\$(connect 3 $target_name:9002)\"
echo \"raw-ip=\$(connect 3 $target_ip:9001)\"
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

# --------------------------------------- proof 6: the byte budget cuts a tunnel

# The budget helper: open one tunnel to the flood port and count what comes
# through before the gateway ends it. The target answers 1 MiB, so a tunnel that
# is not cut delivers 1 MiB and the assertion below fails.
BUDGET_FN='
read_tunnel() { # target
  # The status line goes to stderr so the count is the only thing on stdout.
  connect_ok 3 "$1" >&2
  timeout 20 cat <&3 | wc -c
}
'

say "proof 6: the byte budget cuts a connection"
class_config "$work/classes/model.toml" model 4096 8 lan "$target_name:9003"
profile_for "$work/proof-budget.toml" proof-budget model "$target_name" 9003
run_jail budget "$work/proof-budget.toml" "$PROXY_LIB$BUDGET_FN
echo \"budget-bytes=\$(read_tunnel $target_name:9003)\"
echo done" "reason=byte-budget"

budget_bytes=$(sed -n 's/^budget-bytes=//p' "$work/budget.out" | tr -d ' \r')
[ -n "$budget_bytes" ] || budget_bytes=unknown
# The head line above may take a few bytes with it, so the exact count is not the
# assertion; "far less than the 1 MiB the target sent" is.
if [ "$budget_bytes" = unknown ] || [ "$budget_bytes" -ge 262144 ]; then
  fail "proof 6: the budget did not cut the tunnel (delivered $budget_bytes of 1048576)"
else
  ok "proof 6: the tunnel was cut at the 4096-byte budget (delivered $budget_bytes of 1048576)"
  printf '      %s\n' "$(grep '^budget-bytes=' "$work/budget.out")"
fi
expect "$work/budget.audit" "dest=$target_name:9003 decision=deny reason=byte-budget" \
  'proof 6: the cut is logged as a denial with its destination'
expect "$work/budget.audit" 'budget=4096' \
  'proof 6: the denial names the counter that caused it'

# The fixture has to survive being cut off mid-write; if it did not, the next
# proof would fail with "resolve-failed" and point at the wrong thing.
if [ "$(podman container inspect --format '{{.State.Running}}' "$target_name" 2>/dev/null || echo gone)" = true ]; then
  ok 'the proof target is still running after the cut'
else
  fail 'the proof target died when the budget cut its connection'
fi

# ------------------------------------- proof 7: the connection cap refuses one

# Two tunnels at once against a class that allows one: the first is established
# and left open, then the second is attempted while it is still open.
CAP_FN='
two_tunnels() { # target
  connect_ok 3 "$1"
  connect 4 "$1"
}
'

# Port 9004 is the fixture that stays open, so the first tunnel is still holding
# its slot when the second is attempted.
say "proof 7: the connection cap refuses a second tunnel"
class_config "$work/classes/model.toml" model 268435456 1 lan "$target_name:9004"
profile_for "$work/proof-cap.toml" proof-cap model "$target_name" 9004
run_jail cap "$work/proof-cap.toml" "$PROXY_LIB$CAP_FN
two_tunnels $target_name:9004
echo done" "reason=connection-cap"

expect "$work/cap.out" 'HTTP/1.1 200 Connection established' \
  'proof 7: the first tunnel is established (the cap has one slot)'
expect "$work/cap.out" 'HTTP/1.1 429 Too Many Requests' \
  'proof 7: the second tunnel over the cap is refused'
expect "$work/cap.audit" 'decision=deny reason=connection-cap' \
  'proof 7: the cap refusal is logged as a denial'
expect "$work/cap.audit" 'connections=1/1' \
  'proof 7: the denial names the counters that caused it'

# ------------------------- proof 8: an internal answer is refused, range named

# The same name, the same tunnel, the same fixture — only the class address
# policy differs. The target is a container on an RFC1918 network, so `public`
# (what `model` and `external` ship) must refuse the answer and name the range.
say "proof 8: a name that resolves into internal space is refused"
class_config "$work/classes/model.toml" model 268435456 8 public "$target_name:9001"
profile_for "$work/proof-blocked.toml" proof-blocked model "$target_name" 9001
run_jail blocked "$work/proof-blocked.toml" "$PROXY_LIB
echo \"blocked=\$(connect 3 $target_name:9001)\"
echo done" "reason=blocked-private"

expect "$work/blocked.out" 'blocked=HTTP/1.1 403 Forbidden' \
  'proof 8: an allowlisted name that resolves to a private address is refused'
expect "$work/blocked.audit" "dest=$target_name:9001 decision=deny reason=blocked-private" \
  'proof 8: the refusal names the range the answer fell in'
expect "$work/blocked.audit" "address=$target_ip" \
  'proof 8: the refusal names the address it was about'

# Restore the class config the later proofs use.
class_config "$work/classes/model.toml" model 268435456 8 lan "$target_name:9001"

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
class_config "$work/classes/internal.toml" internal 268435456 8 lan "$target_name:9001"
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
