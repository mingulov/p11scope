#!/bin/sh
# Gate G2: p11scope degrades HONESTLY. Three captures, each broken a
# different way on purpose; each must report PARTIAL with the exact
# induced number, never silently read as COMPLETE.
#
#   1. Aliasing    — two names, one address: counts belong to the group.
#   2. In-flight    — a call entered but not returned by capture end.
#   3. Event loss   — a tiny ring buffer overflowed under a call burst,
#                      but the aggregate maps (the count authority) still
#                      show the exact right number despite the loss.
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/induced-gaps
FIX=scripts/fixtures
mkdir -p "$WORK"

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

echo "=== build (default, non-small-ring) ==="
cargo build --release --workspace
DISCOVER=./target/release/p11scope-discover
P11SCOPE=./target/release/p11scope

echo "=== build small-ring p11scope (Gap 3 only; default build untouched) ==="
# RING_BYTES override mechanism: crates/ebpf-common's `small-ring` Cargo
# feature (off by default) shrinks RING_BYTES 256KiB -> 4KiB; build.rs
# forwards it to the eBPF crate's build only when P11SCOPE_SMALL_RING is
# set. A separate --target-dir keeps this build fully out of target/release
# so scripts/verify-attach-e2e.sh's binary is never touched by this script.
P11SCOPE_SMALL_RING=1 cargo build --release --workspace --target-dir "$WORK/ring-small"
P11SCOPE_SMALLRING=./"$WORK"/ring-small/release/p11scope

echo "=== private softhsm token (gap 3) ==="
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $PWD/$WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label induced-gaps --so-pin 1234 --pin 1234 >/dev/null

CHECK_PY='
import json, sys
obs = json.load(open(sys.argv[1]))
'

##############################################################################
echo "=== gap 1/3: aliasing ==="
##############################################################################
# helper.so's SONAME (baked into provider.so's DT_NEEDED) is "helper.so",
# so the file itself must keep that exact name for the rpath lookup below
# to find it — matching crates/discover/tests/fixture_provider.rs.
mkdir -p "$WORK/g1"
gcc -shared -fPIC -Wl,-soname,helper.so -o "$WORK/g1/helper.so" \
    crates/discover/tests/fixture/helper.c
gcc -shared -fPIC -o "$WORK/g1/provider.so" \
    crates/discover/tests/fixture/provider.c "$WORK/g1/helper.so" \
    -Wl,-rpath,"$PWD/$WORK/g1"
gcc -O0 -o "$WORK/g1_workload" "$FIX/alias_workload.c"

"$DISCOVER" --module "$WORK/g1/provider.so" -o "$WORK/g1_manifest.json"

rm -f "$WORK/g1_go"
( while [ ! -f "$WORK/g1_go" ]; do sleep 0.05; done
  exec "$WORK/g1_workload" "$WORK/g1/provider.so" 25 17 ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
    --manifest "$WORK/g1_manifest.json" --pid "$WPID" \
    --mode profile --duration 8 -o "$WORK/g1_observed.json" \
    > "$WORK/g1_profile.log" 2>&1 &
SPID=$!
sleep 3
touch "$WORK/g1_go"
wait "$WPID"
wait "$SPID"
tail -n 5 "$WORK/g1_profile.log"

python3 - "$WORK/g1_observed.json" <<PY
$CHECK_PY
ev = obs["evidence"]
alias_groups = ev["aliased"]
want = sorted(["C_CancelFunction", "C_WaitForSlotEvent"])
matches = [g for g in alias_groups if sorted(g) == want]
assert matches, f"no alias group == {want} in evidence.aliased: {alias_groups}"
assert len(matches) == 1, f"expected exactly one matching alias group, got {matches}"

fn = [f for f in obs["functions"] if sorted(f["names"]) == want]
assert len(fn) == 1, f"expected exactly one function report for {want}, got {fn}"
fn = fn[0]
assert fn["aliased"] is True, "aliased slot must be flagged aliased=true"
got_calls = fn["calls"]
want_calls = 25 + 17
assert got_calls == want_calls, f"aliased group calls: want {want_calls}, got {got_calls}"

assert ev["completeness"] == "PARTIAL", f"completeness: want PARTIAL, got {ev['completeness']!r}"
print(f"gap 1 OK: alias group {want} calls={got_calls} (want {want_calls}), completeness=PARTIAL")
PY

##############################################################################
echo "=== gap 2/3: in-flight at end ==="
##############################################################################
gcc -shared -fPIC -o "$WORK/g2_provider.so" "$FIX/blocking_provider.c"
gcc -O0 -o "$WORK/g2_workload" "$FIX/blocking_workload.c" -ldl

"$DISCOVER" --module "$WORK/g2_provider.so" -o "$WORK/g2_manifest.json"

rm -f "$WORK/g2_go"
( while [ ! -f "$WORK/g2_go" ]; do sleep 0.05; done
  exec "$WORK/g2_workload" "$WORK/g2_provider.so" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
    --manifest "$WORK/g2_manifest.json" --pid "$WPID" \
    --mode profile --duration 6 -o "$WORK/g2_observed.json" \
    > "$WORK/g2_profile.log" 2>&1 &
SPID=$!
sleep 3
touch "$WORK/g2_go"
# The workload blocks for ~60s in the probed call; only the profiler exits
# on its own (--duration). Don't `wait` on the still-blocked workload.
wait "$SPID"
tail -n 5 "$WORK/g2_profile.log"
kill -9 "$WPID" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true

python3 - "$WORK/g2_observed.json" <<PY
$CHECK_PY
ev = obs["evidence"]
in_flight = ev["in_flight_at_end"]
assert in_flight >= 1, f"in_flight_at_end: want >= 1, got {in_flight}"

fn = [f for f in obs["functions"] if "C_WaitForSlotEvent" in f["names"]]
assert len(fn) == 1, f"expected exactly one function report naming C_WaitForSlotEvent, got {fn}"
fn = fn[0]
assert fn["in_flight"] >= 1, f"slot in_flight: want >= 1, got {fn['in_flight']}"
assert fn["calls"] == 0, f"stranded call must not count as completed: calls={fn['calls']}"
assert fn["latency_ns"]["p50"] is None, "stranded call must be excluded from latency percentiles"
assert fn["latency_ns"]["p95"] is None
assert fn["latency_ns"]["p99"] is None

assert ev["completeness"] == "PARTIAL", f"completeness: want PARTIAL, got {ev['completeness']!r}"
print(f"gap 2 OK: in_flight_at_end={in_flight}, stranded call excluded from percentiles, completeness=PARTIAL")
PY

##############################################################################
echo "=== gap 3/3: event loss (tiny ring buffer, high call rate) ==="
##############################################################################
gcc -O0 -o "$WORK/g3_hammer" "$FIX/hammer.c" -ldl
"$DISCOVER" --module "$MODULE" -o "$WORK/g3_manifest.json"

N_CALLS=200000
rm -f "$WORK/g3_go"
( while [ ! -f "$WORK/g3_go" ]; do sleep 0.05; done
  exec "$WORK/g3_hammer" "$MODULE" "$N_CALLS" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE_SMALLRING" profile \
    --manifest "$WORK/g3_manifest.json" --pid "$WPID" \
    --mode profile --duration 15 -o "$WORK/g3_observed.json" \
    > "$WORK/g3_profile.log" 2>&1 &
SPID=$!
sleep 3
touch "$WORK/g3_go"
wait "$WPID"
wait "$SPID"
tail -n 5 "$WORK/g3_profile.log"

python3 - "$WORK/g3_observed.json" "$N_CALLS" <<PY
$CHECK_PY
n_calls = int(sys.argv[2])
ev = obs["evidence"]
loss = ev["event_loss"]
assert loss > 0, f"event_loss: want > 0 (tiny ring under high call rate), got {loss}"

fn = [f for f in obs["functions"] if "C_GenerateRandom" in f["names"]]
assert len(fn) == 1, f"expected exactly one function report naming C_GenerateRandom, got {fn}"
fn = fn[0]
# The aggregate STATS/RV_COUNTS maps are the count authority: they are
# updated unconditionally on every entry/return, independent of whether the
# per-call event made it into the (lossy) ring buffer. This is the point of
# the gap: event_loss > 0 must NOT mean the aggregate count is wrong.
got_calls = fn["calls"]
assert got_calls == n_calls, f"aggregate map count must stay exact despite ring loss: want {n_calls}, got {got_calls}"

assert ev["completeness"] == "PARTIAL", f"completeness: want PARTIAL, got {ev['completeness']!r}"
print(f"gap 3 OK: event_loss={loss} (>0), C_GenerateRandom calls={got_calls} (== {n_calls} despite loss), completeness=PARTIAL")
PY

echo "=== induced gaps: ALL OK ==="
