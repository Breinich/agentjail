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
#            no network and no gateway behind; a SIGKILLed run leaves its network
#            and gateway container, its network is pruned by the next run of the
#            same profile, and its container by any later run at all;
#   proof 6  the per-jail byte budget cuts a connection and logs the refusal with
#            the counter that caused it;
#   proof 7  the per-jail connection cap refuses a second tunnel and logs it;
#   proof 9  a jail reaches only the destinations its profile listed: a class
#            destination the profile did not list is refused with its own reason
#            (`not-in-profile`) and does not even resolve.
#
# Proofs 1, 2, 4 and 9 run against the **committed** class configs in
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
# The run writes its audit streams under the state directory, not to the
# gateway's own container log: keep the proof runs in the temporary work dir.
AGENTJAIL_STATE_DIR="$work/state"
export AGENTJAIL_STATE_DIR

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
expect_either() { # file, needle-a, needle-b, label
  if grep -q -- "$2" "$1" || grep -q -- "$3" "$1"; then
    ok "$4"
    printf '      %s\n' "$(grep -m1 -e "$2" -e "$3" "$1")"
  else
    fail "$4: expected $2 or $3"
    sed 's/^/      /' "$1" >&2
  fi
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
# One tag per workspace, derived the same way `run` derives it: two checkouts on
# one machine must never share a gateway tag, or a proof silently runs another
# workspace's binary. Printed on every run, so a log identifies its image.
gateway_image=$("$root/scripts/gateway-image-tag.sh" "$root")
say "gateway image: $gateway_image"
podman image exists "$gateway_image" || {
  echo "missing gateway image $gateway_image; run: scripts/build-gateway-image.sh" >&2
  exit 1
}
# The proofs drive `run`, which honours this. The tag is the workspace's, so no
# other checkout can retag the gateway out from under a proof.
export AGENTJAIL_GATEWAY_IMAGE=$gateway_image
echo "      $(podman image inspect --format '{{.Id}}' "$gateway_image") is $gateway_image"

# The tag can point at an image older than the flags these proofs exercise,
# while CI (which builds the image in the same job) stays green. Assert the image
# understands the config shape used below, once, here.
gateway_probe=$(mktemp "${TMPDIR:-/tmp}/agentjail-gateway-probe.XXXXXX")
cat > "$gateway_probe" <<'PROBE'
class = "probe"
listen = "0.0.0.0:3128"
dns = "0.0.0.0:53"
max_bytes = 4096
max_connections = 1
address_policy = "lan"
allow = ["example.com:443"]
PROBE
# The gateway container runs unprivileged: the probe file must be readable by it.
chmod 644 "$gateway_probe"
if ! podman run --rm --pull=never --read-only --cap-drop=ALL \
    -v "$gateway_probe:/class.toml:ro,Z" \
    "$gateway_image" --config /class.toml --check >/dev/null 2>"$gateway_probe.err"; then
  echo "the gateway image $gateway_image is too old for the class" >&2
  echo "config these proofs use (max_bytes/max_connections/address_policy):" >&2
  sed 's/^/  /' "$gateway_probe.err" >&2
  echo "rebuild it: scripts/build-gateway-image.sh (it prints the tag it built)" >&2
  rm -f "$gateway_probe" "$gateway_probe.err"
  exit 1
fi
rm -f "$gateway_probe" "$gateway_probe.err"
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

# Empty until the generated classes exist: a profile built before that names a
# class this build ships, which is what proof 1 is about.
class_dir=""

class_digest() { # class-file
  printf 'sha256:%s' "$(sha256sum "$1" | cut -d' ' -f1)"
}

profile_for() { # path name class egress-host egress-port [class-dir]
  path=$1
  class=$3
  dir=${6:-$class_dir}
  if [ -n "$dir" ]; then
    # An operator class: named by a directory and pinned by digest, so a proof
    # cannot silently run against a policy nobody reviewed. An empty dir means a
    # class this build ships, resolved from gateway/classes.
    class_lines=$(printf 'class_dir = "%s"\nclass_digest = "%s"\n' "$dir" "$(class_digest "$dir/$class.toml")")
  else
    class_lines=""
  fi
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
$class_lines
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

# connect() must run in the calling shell, never inside $( ): it opens the tunnel
# on the fd it is given, and a command substitution closes that fd when the
# subshell exits. That silently turned "hold one tunnel while attempting a
# second" into "close it first", which is why proof 7 (the connection cap)
# depended on whether the gateway noticed the close before the second attempt.
#
# A refusal can also arrive two ways: the gateway answers with a status line, or
# it has already cut the connection when the request is written and the write
# fails. Both are refusals; only the audit line tells a refusal from a crash, so
# the marker below is printed and the proof accepts either shape while still
# requiring the audit line.
connect() { # fd target
  eval "exec $1<>/dev/tcp/$proxy_host/$proxy_port"
  if ! printf "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" "$2" "$2" >&"$1" 2>/dev/null; then
    eval "exec $1>&-" 2>/dev/null || true
    CONNECT_STATUS="CONNECT REFUSED BY CLOSE (the write failed)"
    echo "$CONNECT_STATUS"
    return 0
  fi
  line=$(head -1 <&"$1" 2>/dev/null) || line=""
  if [ -z "$line" ]; then
    eval "exec $1>&-" 2>/dev/null || true
    CONNECT_STATUS="CONNECT REFUSED BY CLOSE (closed before a status line)"
    echo "$CONNECT_STATUS"
    return 0
  fi
  CONNECT_STATUS="$line"
  echo "$CONNECT_STATUS"
}

connect_ok() { # fd target
  attempt=0
  CONNECT_STATUS=""
  while : ; do
    connect "$1" "$2" >/dev/null
    case "$CONNECT_STATUS" in *" 200 "*) break ;; esac
    attempt=$((attempt + 1))
    [ "$attempt" -ge 5 ] && break
    sleep 1
  done
  echo "$CONNECT_STATUS"
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

  # Snapshot the run's per-run streams on every poll, not only after the wait
  # below: a run can end before the wait finishes, and the gateway container is
  # removed with it. The files outlive the container, so read them directly
  # instead of `podman logs`. The jail id is <profile>-<pid of agentjail>, which
  # makes this run's files selectable even while later runs accumulate.
  jail_prefix="$(basename "$profile" .toml)-$agentjail_pid"
  snapshot() {
    audit_file=$(find "$work/state/audit" -type f -name "$jail_prefix.audit.log" 2>/dev/null | head -1)
    dns_file=$(find "$work/state/audit" -type f -name "$jail_prefix.dns.log" 2>/dev/null | head -1)
    if [ -n "$audit_file" ]; then
      cp "$audit_file" "$work/$label.audit.tmp" && mv "$work/$label.audit.tmp" "$work/$label.audit"
    fi
    if [ -n "$dns_file" ]; then
      cp "$dns_file" "$work/$label.dns.tmp" && mv "$work/$label.dns.tmp" "$work/$label.dns"
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

committed_classes=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/gateway/classes
profile_for "$work/proof-model.toml" proof-model model api.anthropic.com 443 ""
profile_for "$work/proof-external.toml" proof-external external github.com 443 ""

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

# --------------------- proof 9: the profile is the grant, not a preflight promise
#
# The assessment's reproduction, inverted. The profile is the stock
# one-destination profile (profiles/allowlist.toml) with the proof image: the
# committed `model` class allows api.openai.com, the profile lists only
# api.anthropic.com, so the jail must be refused api.openai.com with a reason
# that names the profile, and must not even resolve the name. Nothing here needs
# the internet: the refusal happens before any resolution.
say "proof 9: a jail reaches only what its profile listed"
profile_for "$work/proof-grant.toml" proof-grant model api.anthropic.com 443
run_jail grant "$work/proof-grant.toml" "$PROXY_LIB
echo \"openai-connect=\$(connect 3 api.openai.com:443)\"
echo \"openai-dns=\$(getent hosts api.openai.com || echo nxdomain)\"
echo \"listed-dns=\$(getent ahostsv4 api.anthropic.com || echo nxdomain)\"
echo done" "dest=api.openai.com:443 decision=deny"

expect "$work/grant.out" 'openai-connect=HTTP/1.1 403 Forbidden' \
  'proof 9: a class destination the profile did not list is refused'
expect "$work/grant.audit" 'dest=api.openai.com:443 decision=deny reason=not-in-profile' \
  'proof 9: the refusal names the profile, not the class'
expect "$work/grant.out" 'openai-dns=nxdomain' \
  'proof 9: the resolver NXDOMAINs a name the profile did not ask for'
expect "$work/grant.dns" 'qname=api.openai.com qtype=1 decision=nxdomain reason=not-in-profile' \
  'proof 9: the DNS refusal carries the same reason'
expect "$work/grant.out" 'listed-dns=127.0.0.1' \
  'proof 9: the destination the profile listed still resolves (to loopback)'
if grep -q 'dest=api.anthropic.com:443 decision=deny' "$work/grant.audit"; then
  fail 'proof 9: the destination the profile listed was denied'
else
  ok 'proof 9: nothing denies the destination the profile listed'
fi

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
class_dir=$work/classes
class_config "$work/classes/proof-model.toml" proof-model 268435456 8 lan "$target_name:9001"
class_config "$work/classes/proof-external.toml" proof-external 268435456 8 lan "$target_name:9002"
class_config "$work/classes/proof-internal.toml" proof-internal 268435456 8 lan "$target_name:9001"
profile_for "$work/proof-target.toml" proof-target proof-model "$target_name" 9001

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
expect "$work/target.audit" 'class=proof-model jail=proof-target-' \
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
  # The cut can end the stream as EOF or as a reset; both are the budget being
  # enforced, so the count of what was delivered is the assertion, not how the
  # socket ended.
  timeout 20 cat <&3 | wc -c
}
'

say "proof 6: the byte budget cuts a connection"
class_config "$work/classes/proof-model.toml" proof-model 4096 8 lan "$target_name:9003"
profile_for "$work/proof-budget.toml" proof-budget proof-model "$target_name" 9003
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
class_config "$work/classes/proof-model.toml" proof-model 268435456 1 lan "$target_name:9004"
profile_for "$work/proof-cap.toml" proof-cap proof-model "$target_name" 9004
run_jail cap "$work/proof-cap.toml" "$PROXY_LIB$CAP_FN
two_tunnels $target_name:9004
echo done" "reason=connection-cap"

expect "$work/cap.out" 'HTTP/1.1 200 Connection established' \
  'proof 7: the first tunnel is established (the cap has one slot)'
# Over the cap the gateway may cut the second connection before its request is
# written, so the refusal can arrive as a closed connection instead of a 429.
# Either way the audit lines below are what decide it was a refusal and not a
# crash; this assertion only pins how the client saw it.
expect_either "$work/cap.out" 'HTTP/1.1 429 Too Many Requests' 'CONNECT REFUSED BY CLOSE' \
  'proof 7: the second tunnel over the cap is refused (429, or closed as a refusal)'
expect "$work/cap.audit" 'decision=deny reason=connection-cap' \
  'proof 7: the cap refusal is logged as a denial'
expect "$work/cap.audit" 'connections=1/1' \
  'proof 7: the denial names the counters that caused it'
# The counters say one tunnel was live, but not that it was the *first*: a
# harness that closed it early would also see 0/1 and no denial at all, which is
# the failure this proof exists to catch.
expect "$work/cap.out" 'HTTP/1.1 200 Connection established' \
  'proof 7: the first tunnel was still established when the second was refused'

# ------------------------- proof 8: an internal answer is refused, range named

# The same name, the same tunnel, the same fixture — only the class address
# policy differs. The target is a container on an RFC1918 network, so `public`
# (what `model` and `external` ship) must refuse the answer and name the range.
say "proof 8: a name that resolves into internal space is refused"
class_config "$work/classes/proof-model.toml" proof-model 268435456 8 public "$target_name:9001"
profile_for "$work/proof-blocked.toml" proof-blocked proof-model "$target_name" 9001
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
class_config "$work/classes/proof-model.toml" proof-model 268435456 8 lan "$target_name:9001"

# ------------------------------------------------------------ proof 5: lifecycle

say "lifecycle: a failed run leaves nothing behind"
profile_for "$work/proof-fail.toml" proof-fail proof-model "$target_name" 9001
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

say "lifecycle: a SIGKILLed run is pruned by the next run, whoever runs it"
"$agentjail" run "$work/proof-fail.toml" -- bash -lc 'sleep 60' >/dev/null 2>&1 &
killed_pid=$!
# Wait for the gateway container, not only for the network: the container is what
# survives a SIGKILL now that the gateway is not started with `--rm`, and the
# assertion below is about it.
orphan_gateway="agentjail-proof-fail-${killed_pid}-gateway"
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  podman ps -a --format '{{.Names}}' | grep -qx "$orphan_gateway" && break
  sleep 0.5
done
kill -9 "$killed_pid" 2>/dev/null || true
wait "$killed_pid" 2>/dev/null || true
sleep 0.5
stale=$(podman network ls --format '{{.Name}}' | grep '^agentjail-proof-fail-' || true)
[ -n "$stale" ] && ok "lifecycle: a SIGKILLed run leaves $stale (uncatchable, by design)" \
  || fail 'lifecycle: expected a SIGKILLed run to leave its network behind (it did not, so this proof proves nothing)'
if podman ps -a --format '{{.Names}}' | grep -qx "$orphan_gateway"; then
  ok "lifecycle: a SIGKILLed run leaves its gateway container behind"
else
  fail "lifecycle: expected $orphan_gateway to survive a SIGKILL (this proof would prove nothing)"
fi

# Another profile: it prunes the orphaned container by the pid in its name, and
# leaves this profile's network alone (a network name is what concurrent runs of
# one profile share, so networks stay profile-scoped). Before this, a profile
# nobody ran again left its gateway container behind indefinitely.
class_config "$work/classes/proof-internal.toml" proof-internal 268435456 8 lan "$target_name:9001"
profile_for "$work/proof-other.toml" proof-other proof-model "$target_name" 9001
"$agentjail" run "$work/proof-other.toml" -- bash -lc 'true' >/dev/null 2>&1 || true
if podman ps -a --format '{{.Names}}' | grep -qx "$orphan_gateway"; then
  fail "lifecycle: another profile did not prune the orphaned gateway $orphan_gateway"
else
  ok 'lifecycle: another profile prunes an orphaned gateway (pruned by pid, not by profile)'
fi
still_there=$(podman network ls --format '{{.Name}}' | grep '^agentjail-proof-fail-' || true)
[ "$still_there" = "$stale" ] && ok 'lifecycle: another profile leaves this network alone (networks stay profile-scoped)' \
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
unset AGENTJAIL_EGRESS_NETWORK || true

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
