#!/bin/sh
# agentjail base image entrypoint.
#
# Deliberately tiny: it fixes HOME, refuses to run as root, and execs whatever
# the launcher asked for so signals and exit codes pass straight through.
set -eu

if [ "$(id -u)" = "0" ]; then
    echo "agentjail: refusing to run the agent as root inside the jail" >&2
    exit 1
fi

: "${HOME:=/home/agent}"
export HOME

# The jail mounts writable scratch one level above HOME; create HOME itself as a
# 0700 directory owned by this uid. A single-uid container does not need 1777 on
# the home, and a second user in the image must not inherit a writable one.
if ! install -d -m 0700 "$HOME" 2>/dev/null; then
    echo "agentjail: warning: cannot create $HOME with mode 0700" >&2
fi

if [ "$#" -eq 0 ]; then
    set -- bash -l
fi

exec "$@"
