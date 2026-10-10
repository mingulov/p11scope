#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Owned identity observation helper (D3d sweep cells).
#
# Spawns the owned fixture processes, waits for their readiness markers,
# then EXECS `p11scope inventory` so the observer is the fixtures'
# parent: under ptrace_scope=1 only a descendant's map_files are
# readable, so sweep proof requires the observer to be an ancestor of
# every fixture it confirms. After the exec the helper IS the observer;
# the drivers keep sleeping (reparented) until the test kills them by
# the pids in the READY files.
#
# Fixture sets (INV_SET, required):
#   sweep   H1/H2/H3 map P1 (ledgered holders), C maps the byte-identical
#           copy, D maps P1 data-only. Requires INV_P1, INV_COPY.
#   trio    H1/H2/H3 map P1 (ledgered holders only). Requires INV_P1.
#
# Environment (always required):
#   INV_DRIVER    catalog-driver binary (dlopen holders)
#   INV_DATAONLY  identity-dataonly binary (data-only mapping; sweep only)
#   INV_SET       sweep | trio
#   INV_READY     directory for READY files (created)
#   INV_OUT       observer stdout destination (the JSON document)
#   P11SCOPE_BIN  p11scope binary under test
# Arguments: passed verbatim to `p11scope inventory`. Observer stderr
# (progress) inherits this shell's.
set -eu

wait_ready() {
    name="$1"
    i=0
    while [ ! -f "$INV_READY/$name.ready" ]; do
        i=$((i + 1))
        if [ "$i" -gt 300 ]; then
            echo "inventory-identity-observe: $name driver never became ready" >&2
            exit 3
        fi
        sleep 0.1
    done
}

spawn() {
    name="$1"
    shift
    "$INV_DRIVER" --ready "$INV_READY/$name.ready" "$@" </dev/null \
        >"$INV_READY/$name.log" 2>&1 &
}

spawn_data() {
    name="$1"
    shift
    "$INV_DATAONLY" --ready "$INV_READY/$name.ready" "$@" </dev/null \
        >"$INV_READY/$name.log" 2>&1 &
}

: "${INV_DRIVER:?}" "${INV_SET:?}" "${INV_READY:?}" "${INV_OUT:?}" "${P11SCOPE_BIN:?}"

mkdir -p "$INV_READY"

case "$INV_SET" in
    sweep)
        : "${INV_P1:?}" "${INV_COPY:?}" "${INV_DATAONLY:?}"
        spawn H1 --sleep 300 "$INV_P1"
        spawn H2 --sleep 300 "$INV_P1"
        spawn H3 --sleep 300 "$INV_P1"
        spawn C --sleep 300 "$INV_COPY"
        spawn_data D --sleep 300 "$INV_P1"
        wait_ready H1
        wait_ready H2
        wait_ready H3
        wait_ready C
        wait_ready D
        ;;
    trio)
        : "${INV_P1:?}"
        spawn H1 --sleep 300 "$INV_P1"
        spawn H2 --sleep 300 "$INV_P1"
        spawn H3 --sleep 300 "$INV_P1"
        wait_ready H1
        wait_ready H2
        wait_ready H3
        ;;
    *)
        echo "inventory-identity-observe: unknown INV_SET $INV_SET" >&2
        exit 2
        ;;
esac

exec "$P11SCOPE_BIN" inventory "$@" > "$INV_OUT"
