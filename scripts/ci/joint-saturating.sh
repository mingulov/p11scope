#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# One saturating joint cell (U6 loss honesty): a 100k/s joint cell
# through scripts/ci/joint-throughput.sh, then three assertions on
# the finished cell:
#   1. the cell saturated: bpftool EVIDENCE loss is nonzero;
#   2. the published loss is exact: bpftool total == events_lost, with
#      the smaller per-map sum at zero (a single ring lost; a nonzero
#      second ring fails loud for triage, never silently);
#   3. the userspace saturation gap fired: "joint events staging
#      saturated" is recorded in the report gaps.
# The oracle is expected to fail (saturation breaks Gate 1/2); its
# verdict is reported, never the cell verdict. Exit 2 when the cell
# never finished (missing evidence); exit 1 when it finished but an
# assertion failed.
#
# Usage: joint-saturating.sh P11SCOPE OUTDIR
#   P11SCOPE  observer binary (p11scope-discover must sit beside it)
#   OUTDIR    fresh results directory (passed to joint-throughput.sh)
#   joint-saturating.sh --assert-only CELLDIR re-checks a finished
#   cell directory (the joint-10k-single evidence subdirectory).
#
# Environment: RATE (default 100k), DURATION (default 6), CELLS
# (default joint-10k-single; asserts always read joint-10k-single),
# plus the joint-throughput.sh environment (SOFTHSM_LIB, JOINT_NICE,
# SETTLEMENT_LAT=1 and STAGE_TIMINGS=1 by default here). RATE times
# DURATION must stay under the generator's 700,000-call ledger
# ceiling (100k x 6s = 600,000).
set -u

assert_cell() {
    celldir=${1:?cell directory}
    python3 -I - "$celldir" <<'EOF'
import json
import sys

celldir = sys.argv[1]

def incomplete(name, exc):
    print("saturating: cell incomplete, %s: %s" % (name, exc),
          file=sys.stderr)
    sys.exit(2)

def load(name):
    try:
        with open("%s/%s" % (celldir, name), encoding="utf-8") as stream:
            return json.load(stream)
    except OSError as exc:
        incomplete("%s unreadable" % name, exc)
    except ValueError as exc:
        incomplete("%s is not JSON" % name, exc)

failures = []
evidence = load("bpftool-evidence.json")
report = load("report.json")
try:
    with open("%s/oracle.json" % celldir, encoding="utf-8") as stream:
        oracle = stream.read().strip()
except OSError:
    oracle = "(no oracle.json)"

total = evidence["total_ring_loss_sum"]
per_map = sorted(entry["ring_loss_sum"] for entry in evidence["maps"])
published = report["observation"]["semantic_capture"]["events_lost"]
gap = next((entry for entry in report["gaps"]
            if entry.get("subject") == "joint events staging saturated"),
           None)
lifecycle = report["observation"]["lifecycle"]["ring_loss"]
print("saturating: oracle=%s" % oracle)
print("saturating: bpftool total=%d per-map=%s published events_lost=%d "
      "lifecycle ring_loss=%d saturation gap=%s"
      % (total, per_map, published, lifecycle,
         ("repeats=%d" % gap["repeats"]) if gap else "ABSENT"))
if total <= 0:
    failures.append("cell did not saturate: bpftool loss is %d" % total)
if total != published:
    failures.append("bpftool total %d != published events_lost %d"
                    % (total, published))
if not per_map or per_map[0] != 0 or per_map[-1] != published:
    failures.append("per-map loss %s is not single-ring {0, %d}"
                    % (per_map, published))
if gap is None:
    failures.append("staging-saturation gap never fired")
if failures:
    for failure in failures:
        print("saturating FAIL: %s" % failure)
    sys.exit(1)
print("saturating: PASS bpftool == published == %d, gap repeats=%d"
      % (published, gap["repeats"]))
EOF
}

if [ "${1:?usage: joint-saturating.sh P11SCOPE OUTDIR}" = "--assert-only" ]; then
    assert_cell "${2:?usage: joint-saturating.sh --assert-only CELLDIR}"
    exit "$?"
fi

P11SCOPE=$1
OUTDIR=${2:?usage: joint-saturating.sh P11SCOPE OUTDIR}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RATE=${RATE:-100k} DURATION=${DURATION:-6} CELLS=${CELLS:-joint-10k-single} \
    SETTLEMENT_LAT=${SETTLEMENT_LAT:-1} STAGE_TIMINGS=${STAGE_TIMINGS:-1} \
    "$ROOT/scripts/ci/joint-throughput.sh" "$P11SCOPE" "$OUTDIR"
cell_rc=$?
echo "saturating: cell run rc=$cell_rc (oracle failure is expected)"
assert_cell "$OUTDIR/joint-10k-single"
assert_rc=$?
exit "$assert_rc"
