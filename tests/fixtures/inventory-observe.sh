#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Owned inventory observation helper (module/caller inventory contract).
#
# Spawns the owned fixture processes, waits for their readiness markers,
# performs the same-path file swap between the two version-matrix spawns,
# then EXECS `p11scope inventory` so the observer is the fixtures'
# parent: under ptrace_scope=1 only a descendant's memory is readable, so
# the observer must be an ancestor of every fixture it decodes tables from.
# After the exec the helper IS the observer; the drivers keep sleeping
# (reparented) until the test kills them by the pids in the READY files.
#
# Same-path note (shared with the catalog dance): after the atomic swap,
# A's mapping still names the path with V1's (dev, ino) but the kernel
# marks it deleted, so the scan records it as verified absence, never a
# module — the inventory must show B's live edge only, plus the gap.
#
# Fixture sets (INV_SET, required):
#   contract  the D3 contract set: A maps V1 bytes at $INV_PROV, B maps V2
#             after the atomic swap, N/C map the refused shapes, H1/H2 map
#             the hardlink alias pair. Requires INV_V1, INV_V2, INV_PROV,
#             INV_NSS, INV_CLOSE, INV_H1, INV_H2.
#   e1        the multi-caller/multi-module set: A and B map P1, C maps P1
#             and P2 (multi-provider, multi-user). Requires INV_P1, INV_P2.
#
# Environment (always required):
#   INV_DRIVER    catalog-driver binary (doubles as the inventory driver)
#   INV_SET       contract | e1
#   INV_READY     directory for READY files (created)
#   INV_OUT       observer stdout destination (the JSON/text document)
#   P11SCOPE_BIN  p11scope binary under test
# Arguments: passed verbatim to `p11scope inventory` (e.g. --system --json
#   --max-scan-pids 4096). Observer stderr (progress) inherits this shell's.
set -eu

wait_ready() {
    # wait_ready <name>: poll for $INV_READY/<name>.ready up to 30s.
    name="$1"
    i=0
    while [ ! -f "$INV_READY/$name.ready" ]; do
        i=$((i + 1))
        if [ "$i" -gt 300 ]; then
            echo "inventory-observe: $name driver never became ready" >&2
            exit 3
        fi
        sleep 0.1
    done
}

spawn() {
    # spawn <name> <driver args...>: start a fixture driver detached from
    # this shell's stdio (its log goes to the ready dir). Detaching is
    # load-bearing: a caller that pipes this script (e.g. wait_with_output)
    # would otherwise block on the pipes until the 300s sleepers exit.
    name="$1"
    shift
    "$INV_DRIVER" --ready "$INV_READY/$name.ready" "$@" </dev/null \
        >"$INV_READY/$name.log" 2>&1 &
}

: "${INV_DRIVER:?}" "${INV_SET:?}" "${INV_READY:?}" "${INV_OUT:?}" "${P11SCOPE_BIN:?}"

mkdir -p "$INV_READY"

case "$INV_SET" in
    contract)
        : "${INV_V1:?}" "${INV_V2:?}" "${INV_PROV:?}"
        : "${INV_NSS:?}" "${INV_CLOSE:?}" "${INV_H1:?}" "${INV_H2:?}"
        # Same-path dance, first half: A maps V1 bytes at $INV_PROV.
        cp "$INV_V1" "$INV_PROV"
        spawn A --call --sleep 300 "$INV_PROV"
        wait_ready A

        # Atomic replace: the path now resolves to V2 bytes.
        cp "$INV_V2" "$INV_PROV.staging"
        mv "$INV_PROV.staging" "$INV_PROV"

        spawn B --call --sleep 300 "$INV_PROV"
        spawn N --sleep 300 "$INV_NSS"
        spawn C --sleep 300 "$INV_CLOSE"
        spawn H1 --call --sleep 300 "$INV_H1"
        spawn H2 --call --sleep 300 "$INV_H2"
        wait_ready B
        wait_ready N
        wait_ready C
        wait_ready H1
        wait_ready H2
        ;;
    e1)
        : "${INV_P1:?}" "${INV_P2:?}"
        # Multi-caller (A, B share P1), multi-module (C maps P1+P2),
        # multi-provider (P1, P2), multi-user (A, B, C).
        spawn A --call --sleep 300 "$INV_P1"
        spawn B --call --sleep 300 "$INV_P1"
        spawn C --call --sleep 300 "$INV_P1" "$INV_P2"
        wait_ready A
        wait_ready B
        wait_ready C
        ;;
    *)
        echo "inventory-observe: unknown INV_SET $INV_SET" >&2
        exit 2
        ;;
esac

exec "$P11SCOPE_BIN" inventory "$@" > "$INV_OUT"
