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

if [ "$#" -eq 0 ]; then
    set -- bash -l
fi

exec "$@"
