#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# discover-btrfs-subvol.sh DISCOVER SCRATCH OUTDIR: the discover helper's
# btrfs-subvolume twin as a CI cell.
#
# The ignored cli test isolation_btrfs_subvolume_outside_the_output_is_denied
# needs scratch on btrfs, which the ordinary CI runners lack; the
# privileged-btrfs job loop-mounts btrfs for it and runs this cell instead
# of the test binary (whose baked CARGO_BIN_EXE/CARGO_MANIFEST_DIR paths do
# not survive the inputs artifact). The cell compiles the same
# isolation_probe.c fixture with gcc and runs the shipped p11scope-discover
# in both profiles: trusted must create the subvolume outside -o
# (ISOLATION_SUBVOL=allowed), isolated must fail with EACCES and create
# nothing (ISOLATION_SUBVOL=denied(errno=13)).
#
# SCRATCH must be an empty directory on btrfs owned by the caller (the job
# chowns a subdir of its loop mount to the runner user); OUTDIR receives
# results.jsonl (one row) plus trusted.log, isolated.log and build.log.
# Must run as non-root: the fence refuses root, so a root run could never
# prove the type denial.
#
# Exit 0: the twin passed. Exit 1: it failed, or a prerequisite is missing
# (gcc, btrfs scratch, the fixture sources). Exit 2: bad usage, or root.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
ROOT=$(cd "$HERE/../.." && pwd) || exit 2
FIXTURE=$ROOT/crates/discover/tests/fixture
CELL=discover-btrfs-subvol

[ $# = 3 ] || { echo "usage: discover-btrfs-subvol.sh DISCOVER SCRATCH OUTDIR" >&2; exit 2; }
DISCOVER=$1
SCRATCH=$2
OUT=$3
[ "$(id -u)" != 0 ] || { echo "$CELL: refusing to run as root (the fence refuses root)" >&2; exit 2; }
DISCOVER=$(realpath -e -- "$DISCOVER") || exit 2
[ -x "$DISCOVER" ] || { echo "$CELL: no executable discover binary: $DISCOVER" >&2; exit 1; }
[ -d "$SCRATCH" ] || { echo "$CELL: scratch is not a directory: $SCRATCH" >&2; exit 1; }
SCRATCH=$(realpath -e -- "$SCRATCH") || exit 1
mkdir -p "$OUT" || exit 1
OUT=$(realpath -e -- "$OUT") || exit 1
fstype=$(stat -f -c %T "$SCRATCH" 2>/dev/null || true)
[ "$fstype" = "btrfs" ] || { echo "$CELL: scratch is $fstype, not btrfs: $SCRATCH" >&2; exit 1; }
for owned in isolation-probe.so isolation-backend.so sv-trusted sv-isolated; do
    [ ! -e "$SCRATCH/$owned" ] || { echo "$CELL: refusing a dirty scratch: $SCRATCH/$owned exists" >&2; exit 1; }
done
command -v gcc >/dev/null 2>&1 || { echo "$CELL: gcc not found" >&2; exit 1; }
[ -f "$FIXTURE/isolation_probe.c" ] || { echo "$CELL: fixture missing: $FIXTURE/isolation_probe.c" >&2; exit 1; }
[ -f "$FIXTURE/isolation_backend.c" ] || { echo "$CELL: fixture missing: $FIXTURE/isolation_backend.c" >&2; exit 1; }

result() {
    python3 - "$1" "$2" "$3" "$4" <<'PY' | tee "$OUT/results.jsonl"
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4]}))
PY
}

fail() {
    result "$CELL" 0 "$1" failed
    echo "$CELL: FAIL: $1" >&2
    exit 1
}

bits=$(getconf LONG_BIT)
gcc -m"$bits" -shared -fPIC -o "$SCRATCH/isolation-backend.so" \
    "$FIXTURE/isolation_backend.c" >"$OUT/build.log" 2>&1 \
    || fail "cannot build the backend fixture (see build.log)"
gcc -m"$bits" -shared -fPIC -o "$SCRATCH/isolation-probe.so" \
    "$FIXTURE/isolation_probe.c" -ldl '-Wl,-rpath,$ORIGIN' >>"$OUT/build.log" 2>&1 \
    || fail "cannot build the probe fixture (see build.log)"

ISOLATION_SUBVOL_PATH=$SCRATCH/sv-trusted "$DISCOVER" --module \
    "$SCRATCH/isolation-probe.so" >"$OUT/trusted.log" 2>&1 \
    || fail "trusted run exited nonzero (see trusted.log)"
grep -q 'ISOLATION_SUBVOL=allowed' "$OUT/trusted.log" \
    || fail "trusted run did not create the subvolume (see trusted.log)"
[ -d "$SCRATCH/sv-trusted" ] || fail "trusted run left no subvolume behind"
rmdir "$SCRATCH/sv-trusted" || fail "cannot clean the trusted subvolume"
[ ! -e "$SCRATCH/sv-trusted" ] || fail "trusted cleanup left sv-trusted behind"

ISOLATION_SUBVOL_PATH=$SCRATCH/sv-isolated "$DISCOVER" --isolation isolated --module \
    "$SCRATCH/isolation-probe.so" >"$OUT/isolated.log" 2>&1 \
    || fail "isolated run exited nonzero (see isolated.log)"
grep -q 'ISOLATION_SUBVOL=denied(errno=13)' "$OUT/isolated.log" \
    || fail "subvolume creation was not fenced (see isolated.log)"
[ ! -e "$SCRATCH/sv-isolated" ] || fail "the fenced run created sv-isolated"

result "$CELL" 1 "trusted allowed + cleaned, isolated denied(errno=13) + nothing created" qualified
echo "$CELL: PASS"
