#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Owned catalog observation helper (module/caller inventory Phase 1).
#
# Spawns the eight owned fixture processes, waits for their readiness
# markers, performs the same-path file swap between the two version-matrix
# spawns, then EXECS `p11scope inspect` so the observer is the fixtures'
# parent: under ptrace_scope=1 only a descendant's memory is readable, so
# the observer must be an ancestor of every fixture it decodes tables from.
# After the exec the helper IS the observer; the drivers keep sleeping
# (reparented) until the test kills them by the pids in the READY files.
# The script never modifies its inputs: the V2 bytes are staged through a
# temp copy (the rename onto $CATALOG_PROV must be atomic, but the
# $CATALOG_V2 source file itself survives for reruns).
#
# Environment (all required):
#   CATALOG_DRIVER  catalog-driver binary
#   CATALOG_V1      version_matrix.so built -DLEGACY_MINOR=40 (first mapping)
#   CATALOG_V2      version_matrix.so built -DLEGACY_MINOR=41 (replaces V1)
#   CATALOG_PROV    path both version-matrix drivers map (the same-path dance)
#   CATALOG_TLESS   version_matrix.so mapped but never called (no tables)
#   CATALOG_MW      multi-wrapper provider.so (admitted multi-table shape)
#   CATALOG_NSS     catalog-nss provider.so (softokn refused shape)
#   CATALOG_CLOSE   catalog-closure provider.so (closure-array refused shape)
#   CATALOG_H1      version_matrix.so hardlink 1 (alias pair with H2)
#   CATALOG_H2      version_matrix.so hardlink 2 (same inode as H1)
#   CATALOG_READY   directory for READY files (created)
#   CATALOG_MARKER  E3 marker file (truncated; fixture constructors append pids)
#   CATALOG_OUT     observer stdout destination (the JSON/text document)
#   P11SCOPE_BIN    p11scope binary under test
# Arguments: passed verbatim to `p11scope inspect` (e.g. --system --json
#   --max-scan-pids 4096). Observer stderr (progress) inherits this shell's.
set -eu

wait_ready() {
    # wait_ready <name>: poll for $CATALOG_READY/<name>.ready up to 30s.
    name="$1"
    i=0
    while [ ! -f "$CATALOG_READY/$name.ready" ]; do
        i=$((i + 1))
        if [ "$i" -gt 300 ]; then
            echo "catalog-observe: $name driver never became ready" >&2
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
    "$CATALOG_DRIVER" --ready "$CATALOG_READY/$name.ready" "$@" </dev/null \
        >"$CATALOG_READY/$name.log" 2>&1 &
}

: "${CATALOG_DRIVER:?}" "${CATALOG_V1:?}" "${CATALOG_V2:?}" "${CATALOG_PROV:?}"
: "${CATALOG_TLESS:?}" "${CATALOG_MW:?}" "${CATALOG_NSS:?}" "${CATALOG_CLOSE:?}"
: "${CATALOG_H1:?}" "${CATALOG_H2:?}" "${CATALOG_READY:?}"
: "${CATALOG_MARKER:?}" "${CATALOG_OUT:?}" "${P11SCOPE_BIN:?}"

mkdir -p "$CATALOG_READY"
: > "$CATALOG_MARKER"
export P11SCOPE_CATALOG_MARKER="$CATALOG_MARKER"

# Same-path dance, first half: A maps V1 bytes at $CATALOG_PROV.
cp "$CATALOG_V1" "$CATALOG_PROV"
spawn A --call --sleep 300 "$CATALOG_PROV"
wait_ready A

# Atomic replace: the path now resolves to V2 bytes. A's mapping still
# names this path with V1's (dev, ino), but the kernel marks a mapping
# whose dentry was unlinked as deleted, so the scan records A as a
# "deleted mapping" note (verified absence, not a module) while B pins V2
# — two views, one path, two file identities, distinguished, never
# conflated. A same-path pair of two PINNED objects is unconstructable in
# one mount namespace (same path string implies the same dentry implies
# the same file); the catalog's same-path grouping itself is covered by
# unit tests, and the H1/H2 hardlink pair below covers live aliasing.
cp "$CATALOG_V2" "$CATALOG_PROV.staging"
mv "$CATALOG_PROV.staging" "$CATALOG_PROV"

spawn B --call --sleep 300 "$CATALOG_PROV"
spawn T --sleep 300 "$CATALOG_TLESS"
spawn M --sleep 300 "$CATALOG_MW"
spawn N --sleep 300 "$CATALOG_NSS"
spawn C --sleep 300 "$CATALOG_CLOSE"
spawn H1 --sleep 300 "$CATALOG_H1"
spawn H2 --sleep 300 "$CATALOG_H2"
wait_ready B
wait_ready T
wait_ready M
wait_ready N
wait_ready C
wait_ready H1
wait_ready H2

exec "$P11SCOPE_BIN" inspect "$@" > "$CATALOG_OUT"
