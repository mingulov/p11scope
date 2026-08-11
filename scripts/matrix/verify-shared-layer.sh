#!/bin/sh
# Phase 4 Task 3: shared-image-layer capture. Two containers from the same
# image share libsofthsm2.so as one overlay2 inode; one attach must observe
# both, and a scope naming only one container must exclude the other even
# though the probe sits on an inode both use.
#
# Uses the same discover-inside-container + /proc/<pid>/root-prefix
# approach as verify-docker.sh (see that script's header for why: no
# --pid flag on p11scope-discover, so the container's mount view is
# reached by running the helper inside it).
#
# Three captures, each a fresh `p11scope profile` invocation (attach is
# not persisted across runs):
#   1. BROAD:  --cgroup <shared parent slice>, one attach, harness run in
#              BOTH containers -> proves the shared-inode claim: one
#              attach observes both (counts == 2x spike/expected.txt).
#   2. A-ONLY: --cgroup <container A's leaf>, harness run in BOTH
#              containers concurrently -> B's calls happen on the same
#              probed inode but must NOT appear (counts == 1x, not 2x).
#              This is the negative isolation proof.
#   3. B-ONLY: symmetric to 2, with A and B swapped -> together with 2
#              this is the "two scoped runs" evidence (Task 3 brief) that
#              per-container attribution is recoverable via cgroup scope,
#              standing in for a not-yet-built cgroup_id breakdown
#              (that consumer is Task 6; cgroup_id is already captured on
#              every event per the phase plan's inherited facts).
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_CONTAINER=/usr/lib/softhsm/libsofthsm2.so
PROVIDER_REAL_PATH=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
WORK=target/matrix-shared
IMAGE=p11scope-matrix
NAME_A=p11scope-matrix-shared-a
NAME_B=p11scope-matrix-shared-b

command -v docker >/dev/null || { echo "docker required"; exit 1; }

cleanup() { docker rm -f "$NAME_A" "$NAME_B" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=== build product + workload ==="
cargo build --release --workspace
mkdir -p "$WORK/shared-a" "$WORK/shared-b"
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

echo "=== build container image ==="
docker build -q -t "$IMAGE" -f scripts/matrix/Dockerfile scripts/matrix >/dev/null

echo "=== start two containers from the same image, under one dedicated cgroup parent ==="
cleanup
docker run -d --rm --name "$NAME_A" --cgroup-parent=p11scope-shared.slice \
    -v "$PWD/target/release/p11scope-discover:/usr/local/bin/p11scope-discover:ro" \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared-a:/shared" \
    "$IMAGE" >/dev/null
docker run -d --rm --name "$NAME_B" --cgroup-parent=p11scope-shared.slice \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared-b:/shared" \
    "$IMAGE" >/dev/null
PID_A=$(docker inspect -f '{{.State.Pid}}' "$NAME_A")
PID_B=$(docker inspect -f '{{.State.Pid}}' "$NAME_B")
echo "PID_A=$PID_A PID_B=$PID_B"

echo "=== verify the provider .so really is one shared overlay2 inode ==="
INODE_A=$(docker exec "$NAME_A" stat -c %i "$PROVIDER_REAL_PATH")
INODE_B=$(docker exec "$NAME_B" stat -c %i "$PROVIDER_REAL_PATH")
echo "inode in A: $INODE_A"
echo "inode in B: $INODE_B"
if [ "$INODE_A" != "$INODE_B" ]; then
    echo "BLOCKED: provider inode differs between containers ($INODE_A vs $INODE_B)."
    echo "The image layer is not shared on this storage driver; this test would prove nothing."
    docker info --format 'storage driver: {{.Driver}}'
    exit 1
fi
echo "confirmed: both containers see the same provider inode ($INODE_A) -- storage driver $(docker info --format '{{.Driver}}')"

echo "=== discover once, inside container A's mount view ==="
docker exec "$NAME_A" p11scope-discover --module "$MODULE_IN_CONTAINER" -o /shared/manifest.json
test -s "$WORK/shared-a/manifest.json" || { echo "manifest not produced"; exit 1; }

echo "=== rewrite manifest object paths with /proc/<A's pid>/root prefix ==="
python3 - "$WORK/shared-a/manifest.json" "$WORK/manifest-host.json" "/proc/$PID_A/root" <<'PY'
import json, sys
inp, outp, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
m = json.load(open(inp))
m["module_path"] = prefix + m["module_path"]
for o in m["objects"]:
    o["path"] = prefix + o["path"]
json.dump(m, open(outp, "w"))
PY

echo "=== resolve cgroup paths: the shared parent, and each container's leaf ==="
CGROUP_A_REL=$(sed 's/^0:://' "/proc/$PID_A/cgroup")
CGROUP_B_REL=$(sed 's/^0:://' "/proc/$PID_B/cgroup")
CGROUP_PARENT_REL=$(dirname "$CGROUP_A_REL")
BROAD_PATH="/sys/fs/cgroup$CGROUP_PARENT_REL"
LEAF_A_PATH="/sys/fs/cgroup$CGROUP_A_REL"
LEAF_B_PATH="/sys/fs/cgroup$CGROUP_B_REL"
for p in "$BROAD_PATH" "$LEAF_A_PATH" "$LEAF_B_PATH"; do
    test -d "$p" || { echo "cgroup path does not exist: $p"; exit 1; }
done
echo "broad (parent, covers both): $BROAD_PATH"
echo "leaf A: $LEAF_A_PATH"
echo "leaf B: $LEAF_B_PATH"

# Runs one capture; $1 = label, $2 = --cgroup target, $3 = output json.
# Always exercises BOTH containers' harnesses during the window, so a
# narrow scope's "absence" is a real exclusion of live concurrent calls,
# not just an artifact of nothing having run.
run_capture() {
    label=$1; cg=$2; out=$3
    echo "--- capture: $label (scope=$cg) ---"
    rm -f "$WORK/shared-a/go" "$WORK/shared-b/go"
    ( while [ ! -f "$WORK/shared-a/go" ]; do sleep 0.05; done
      docker exec "$NAME_A" /usr/local/bin/harness "$MODULE_IN_CONTAINER" ) &
    wa=$!
    ( while [ ! -f "$WORK/shared-b/go" ]; do sleep 0.05; done
      docker exec "$NAME_B" /usr/local/bin/harness "$MODULE_IN_CONTAINER" ) &
    wb=$!
    sudo ./target/release/p11scope profile \
        --manifest "$WORK/manifest-host.json" --cgroup "$cg" \
        --mode metrics --duration 20 -o "$out" \
        > "$WORK/$label.log" 2>&1 &
    sp=$!
    sleep 3
    touch "$WORK/shared-a/go" "$WORK/shared-b/go"
    wait "$wa"
    wait "$wb"
    wait "$sp"
    tail -n 5 "$WORK/$label.log"
}

run_capture broad "$BROAD_PATH" "$WORK/observed-broad.json"
run_capture a-only "$LEAF_A_PATH" "$WORK/observed-a-only.json"
run_capture b-only "$LEAF_B_PATH" "$WORK/observed-b-only.json"

echo "=== verify: positive (broad == 2x oracle) ==="
python3 - "$WORK/observed-broad.json" spike/expected.txt 2 <<'PY'
import json, sys
obs = json.load(open(sys.argv[1]))
mult = int(sys.argv[3])
counts = {}
for f in obs["functions"]:
    for n in f["names"]:
        counts[n] = counts.get(n, 0) + f["calls"]
fail = 0
for line in open(sys.argv[2]):
    name, want = line.split()
    want = int(want) * mult
    got = counts.get(name, 0)
    if got != want:
        print(f"MISMATCH {name}: want {want}, got {got}")
        fail = 1
    else:
        print(f"ok {name}: {got}")
ev = obs["evidence"]
print("evidence:", ev["attached_probes"], "probes,", ev["completeness"])
if ev["attached_probes"] == 0 or ev["completeness"] != "COMPLETE":
    print("evidence gap")
    fail = 1
sys.exit(fail)
PY

echo "=== verify: negative isolation (A-only == 1x, B-only == 1x, never 2x) ==="
python3 - "$WORK/observed-a-only.json" "$WORK/observed-b-only.json" spike/expected.txt <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))

def counts(obs):
    c = {}
    for f in obs["functions"]:
        for n in f["names"]:
            c[n] = c.get(n, 0) + f["calls"]
    return c

ca, cb = counts(a), counts(b)
fail = 0
for line in open(sys.argv[3]):
    name, want = line.split()
    want = int(want)
    ga, gb = ca.get(name, 0), cb.get(name, 0)
    if ga != want:
        print(f"MISMATCH a-only {name}: want {want}, got {ga}")
        fail = 1
    if gb != want:
        print(f"MISMATCH b-only {name}: want {want}, got {gb}")
        fail = 1
    if ga == want * 2 or gb == want * 2:
        print(f"OVER-CAPTURE {name}: scoped run saw both containers' calls")
        fail = 1
    if fail == 0:
        print(f"ok {name}: a-only={ga} b-only={gb} (isolated, both containers were live)")

for label, obs in (("a-only", a), ("b-only", b)):
    ev = obs["evidence"]
    print(f"{label} evidence:", ev["attached_probes"], "probes,", ev["completeness"])
    if ev["attached_probes"] == 0 or ev["completeness"] != "COMPLETE":
        print(f"{label}: evidence gap")
        fail = 1
sys.exit(fail)
PY

echo "=== shared-layer: ALL OK ==="
