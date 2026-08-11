#!/bin/sh
# Phase 4 Task 2: Docker container capture. Runs the deterministic workload
# (spike/harness.c, oracle spike/expected.txt) inside a Docker container
# and attaches from the host.
#
# Two problems this script solves explicitly:
#
# 1. The provider path inside the container is not the host path.
#    Discovery must see the container's mount view. p11scope-discover has
#    no --pid flag (checked: crates/discover/src/main.rs takes only
#    --module/-o), so this script runs the helper INSIDE the container
#    (bind-mounted in, since this host is ubuntu:24.04/glibc 2.39 -- same
#    as the image -- so the host-built dynamic binary runs unmodified) and
#    copies the resulting manifest out. The manifest's object paths are
#    then container-relative (e.g. /usr/lib/x86_64-linux-gnu/softhsm/...);
#    this script rewrites them with a /proc/<container-pid>/root/ prefix
#    before handing the manifest to `p11scope profile`, exactly matching
#    the Phase 0 spike's bpftrace path-prefix trick (see
#    docs/superpowers/plans/2026-08-10-phase0-feasibility-spike.md, Task 4)
#    -- both the uprobe attach path (attach.rs passes slot.object straight
#    through to aya) and the manifest reuse/identity check (verify.rs reads
#    Path::new(&obj.path) directly) go through that same rewritten path.
# 2. The capture is scoped to the container's cgroup (--cgroup), using
#    Task 1's new descendant-matching so it doesn't matter whether the
#    workload runs directly in the container's leaf cgroup or a nested one.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_CONTAINER=/usr/lib/softhsm/libsofthsm2.so
WORK=target/matrix-docker
IMAGE=p11scope-matrix
NAME=p11scope-matrix-docker

command -v docker >/dev/null || { echo "docker required"; exit 1; }

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=== build product + workload ==="
cargo build --release --workspace
mkdir -p "$WORK/shared"
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

echo "=== build container image ==="
docker build -q -t "$IMAGE" -f scripts/matrix/Dockerfile scripts/matrix >/dev/null

echo "=== start container, bind-mount host binaries + shared dir ==="
cleanup
docker run -d --rm --name "$NAME" \
    -v "$PWD/target/release/p11scope-discover:/usr/local/bin/p11scope-discover:ro" \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared:/shared" \
    "$IMAGE" >/dev/null
PID=$(docker inspect -f '{{.State.Pid}}' "$NAME")
test -n "$PID" && [ "$PID" -gt 0 ] || { echo "could not get container pid"; exit 1; }
echo "container pid on host: $PID"

echo "=== discover inside the container's mount view ==="
# Runs as the container's root, via the docker daemon socket -- no host
# root required for this step (measured below).
docker exec "$NAME" p11scope-discover --module "$MODULE_IN_CONTAINER" -o /shared/manifest.json
test -s "$WORK/shared/manifest.json" || { echo "manifest not produced"; exit 1; }

echo "=== rewrite manifest object paths with /proc/<pid>/root prefix ==="
python3 - "$WORK/shared/manifest.json" "$WORK/manifest-host.json" "/proc/$PID/root" <<'PY'
import json, sys
inp, outp, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
m = json.load(open(inp))
m["module_path"] = prefix + m["module_path"]
for o in m["objects"]:
    o["path"] = prefix + o["path"]
json.dump(m, open(outp, "w"))
PY

echo "=== resolve the container's cgroup path ==="
CGROUP_REL=$(sed 's/^0:://' "/proc/$PID/cgroup")
CGROUP_PATH="/sys/fs/cgroup$CGROUP_REL"
echo "cgroup: $CGROUP_PATH"
test -d "$CGROUP_PATH" || { echo "cgroup path does not exist: $CGROUP_PATH"; exit 1; }

echo "=== measure privileges: unprivileged profile attempt ==="
set +e
UNPRIV_OUT=$(./target/release/p11scope profile --manifest "$WORK/manifest-host.json" \
    --cgroup "$CGROUP_PATH" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
echo "$UNPRIV_OUT"
echo "unprivileged exit code: $UNPRIV_RC"
if [ "$UNPRIV_RC" -eq 0 ]; then
    echo "expected unprivileged profile to fail, but it exited 0"
    exit 1
fi
echo "$UNPRIV_OUT" | grep -q "Permission denied" \
    || { echo "expected 'Permission denied' in unprivileged failure text"; exit 1; }
echo "measured: unprivileged run fails identifying /proc/<pid>/root/... (EACCES) before BPF is even touched"

echo "=== observe: attach-before-run against the container ==="
rm -f "$WORK/shared/go"
( while [ ! -f "$WORK/shared/go" ]; do sleep 0.05; done
  docker exec "$NAME" /usr/local/bin/harness "$MODULE_IN_CONTAINER" ) &
WPID=$!
sudo ./target/release/p11scope profile \
    --manifest "$WORK/manifest-host.json" --cgroup "$CGROUP_PATH" \
    --mode metrics --duration 20 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
SPID=$!
sleep 3            # let attach complete
touch "$WORK/shared/go"
wait "$WPID"
wait "$SPID"
tail -n 15 "$WORK/profile.log"

echo "=== verify against spike/expected.txt ==="
python3 - "$WORK/observed.json" spike/expected.txt <<'PY'
import json, sys
obs = json.load(open(sys.argv[1]))
counts = {}
for f in obs["functions"]:
    for n in f["names"]:
        counts[n] = counts.get(n, 0) + f["calls"]
fail = 0
for line in open(sys.argv[2]):
    name, want = line.split()
    got = counts.get(name, 0)
    if got != int(want):
        print(f"MISMATCH {name}: want {want}, got {got}")
        fail = 1
    else:
        print(f"ok {name}: {got}")
ev = obs["evidence"]
print("evidence:", ev["attached_probes"], "probes,", ev["completeness"])
if ev["attached_probes"] == 0:
    print("no probes attached")
    fail = 1
if ev["completeness"] != "COMPLETE":
    print(f"completeness: want COMPLETE, got {ev['completeness']!r}")
    fail = 1
sys.exit(fail)
PY

echo "=== docker: ALL OK ==="
