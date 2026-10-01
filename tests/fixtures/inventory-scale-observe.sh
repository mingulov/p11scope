#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Owned scale observation helper (inventory breadth matrix).
#
# Spawns INV_COUNT fixture drivers (each mapping every provider in
# INV_PROVIDERS), waits for every readiness marker, then EXECS
# `p11scope inventory` so the observer is the fixtures' parent (under
# ptrace_scope=1 only a descendant's memory is readable). After the exec
# the helper IS the observer; the drivers keep sleeping (reparented)
# until the test kills them by the pids in the READY files.
#
# Environment (all required):
#   INV_DRIVER     catalog-driver binary
#   INV_COUNT      drivers to spawn (each maps every provider)
#   INV_PROVIDERS  space-separated provider.so paths (no spaces in paths)
#   INV_READY      directory for READY files (created)
#   INV_OUT        observer stdout destination (the JSON/text document)
#   P11SCOPE_BIN   p11scope binary under test
# Arguments: passed verbatim to `p11scope inventory` (e.g. --system
#   --json --max-scan-pids 4096). Observer stderr (progress) inherits
#   this shell's.
set -eu

: "${INV_DRIVER:?}" "${INV_COUNT:?}" "${INV_PROVIDERS:?}"
: "${INV_READY:?}" "${INV_OUT:?}" "${P11SCOPE_BIN:?}"

mkdir -p "$INV_READY"

i=1
while [ "$i" -le "$INV_COUNT" ]; do
    name=$(printf 'S%03d' "$i")
    # Detached stdio is load-bearing: a caller that pipes this script
    # would otherwise block on the pipes until the sleepers exit.
    # shellcheck disable=SC2086
    "$INV_DRIVER" --ready "$INV_READY/$name.ready" --call --sleep 300 \
        $INV_PROVIDERS </dev/null >"$INV_READY/$name.log" 2>&1 &
    i=$((i + 1))
done

i=1
while [ "$i" -le "$INV_COUNT" ]; do
    name=$(printf 'S%03d' "$i")
    j=0
    while [ ! -f "$INV_READY/$name.ready" ]; do
        j=$((j + 1))
        if [ "$j" -gt 300 ]; then
            echo "inventory-scale-observe: $name driver never became ready" >&2
            exit 3
        fi
        sleep 0.1
    done
    i=$((i + 1))
done

exec "$P11SCOPE_BIN" inventory "$@" > "$INV_OUT"
