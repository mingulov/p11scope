#!/bin/sh
# Task 6: shared image-layer attach/count oracle, broad and leaf cgroup scope.
#
# Manifest-free: nothing is copied out of either container. This is the measured
# common shared-layer shape; exact counts prove that its two matching overlay
# mappings need one attach, while output must retain heuristic uncertainty.
set -eu
cd "$(dirname "$0")/../.."

MODULE_IN_CONTAINER=/usr/lib/softhsm/libsofthsm2.so
RUN_ID=$(date +%s%N)-$$
WORK=${P11SCOPE_TASK4_WORK:-"target/matrix-shared/$RUN_ID"}
IMAGE="p11scope-matrix-shared:$RUN_ID"
NAME_A="p11scope-matrix-shared-a-$RUN_ID"
NAME_B="p11scope-matrix-shared-b-$RUN_ID"
CGROUP_PARENT="p11scope-shared-$RUN_ID.slice"
PRODUCT=${P11SCOPE_TASK4_PRODUCT:-"$WORK/product"}
WA=
WB=
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
IMAGE_CREATED=
CONTAINER_A_STARTED=
CONTAINER_B_STARTED=
. scripts/lib.sh

task4_prepare_root() {
    t4_candidate=$1
    case $t4_candidate in /*) ;; *) return 1 ;; esac
    case $t4_candidate in *'/../'*|*/..|*"\t"*|*"\n"*) return 1 ;; esac
    t4_parent=${t4_candidate%/*}; t4_leaf=${t4_candidate##*/}
    [ -n "$t4_parent" ] && [ -n "$t4_leaf" ] && [ -d "$t4_parent" ] || return 1
    t4_ancestor=$t4_parent
    while [ "$t4_ancestor" != / ]; do
        [ ! -L "$t4_ancestor" ] || return 1
        t4_ancestor=${t4_ancestor%/*}; [ -n "$t4_ancestor" ] || t4_ancestor=/
    done
    t4_parent=$(cd "$t4_parent" && pwd -P) || return 1
    [ "$t4_candidate" = "$t4_parent/$t4_leaf" ] || return 1
    case $t4_candidate in "$(pwd -P)"|"$(pwd -P)"/*) return 1 ;; esac
    [ "$(stat -Lc %u:%a "$t4_parent")" = "$(id -u):700" ] || return 1
    [ ! -e "$t4_candidate" ] && [ ! -L "$t4_candidate" ] || return 1
    umask 077; mkdir -m 700 "$t4_candidate" || return 1
    TASK4_ROOT=$t4_candidate; TASK4_CAMPAIGN=$t4_parent
    TASK4_ROOT_ID=$(stat -Lc %d:%i "$TASK4_ROOT") || return 1
}

task4_digest() { sha256sum "$1" | awk '{print $1}'; }
task4_snapshot() { git ls-files -z | sort -z | xargs -0 sha256sum; }
task4_fact() { printf '%s\t%s\n' "$1" "$2" >> "$TASK4_FACTS"; }

task4_finalize() {
    t4_result=$?
    trap - EXIT INT TERM HUP
    set +e
    [ "$(stat -Lc %d:%i "$TASK4_ROOT" 2>/dev/null)" = "$TASK4_ROOT_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT/artifacts" 2>/dev/null)" = "$TASK4_ARTIFACTS_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT/work" 2>/dev/null)" = "$TASK4_WORK_ID" ] || t4_result=1
    if [ "$t4_result" -ne 77 ]; then
        [ "$(git rev-parse HEAD 2>/dev/null)" = "$TASK4_HEAD" ] || t4_result=1
        [ "$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" = "$TASK4_TREE" ] || t4_result=1
        git diff --quiet && git diff --cached --quiet || t4_result=1
        [ "$(task4_digest scripts/matrix/verify-shared-layer.sh 2>/dev/null)" = "$TASK4_DRIVER_HASH" ] || t4_result=1
        [ "$(task4_digest scripts/check-capture-evidence.py 2>/dev/null)" = "$TASK4_CHECKER_HASH" ] || t4_result=1
        task4_snapshot > "$TASK4_ROOT/artifacts/source.end.tsv" || t4_result=1
        cmp -s "$TASK4_ROOT/artifacts/source.start.tsv" "$TASK4_ROOT/artifacts/source.end.tsv" || t4_result=1
        [ -s "$TASK4_ROOT/artifacts/capture.json" ] || t4_result=1
        [ -s "$TASK4_ROOT/artifacts/checker.log" ] || t4_result=1
    fi
    find "$TASK4_ROOT" -type d -exec chmod 700 {} + 2>/dev/null || t4_result=1
    find "$TASK4_ROOT" -type f -exec chmod 600 {} + 2>/dev/null || t4_result=1
    python3 - "$TASK4_ROOT" <<'PY' || t4_result=1
import os, stat, sys
root=sys.argv[1]
if set(os.listdir(root)) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: raise SystemExit("foreign root entry")
for directory, dirs, files in os.walk(root,followlinks=False):
    if stat.S_IMODE(os.lstat(directory).st_mode)!=0o700: raise SystemExit("directory mode")
    for name in dirs+files:
        if stat.S_ISLNK(os.lstat(os.path.join(directory,name)).st_mode): raise SystemExit("symlink")
    for name in files:
        mode=os.lstat(os.path.join(directory,name)).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode)!=0o600: raise SystemExit("file mode")
PY
    task4_fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || t4_result=1
    task4_fact terminal_status "$t4_result" || t4_result=1
    sync -f "$TASK4_FACTS" "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/stderr.log" 2>/dev/null || t4_result=1
    if [ ! -e "$TASK4_ROOT/status" ] && [ ! -L "$TASK4_ROOT/status" ]; then
        printf '%s\n' "$t4_result" > "$TASK4_ROOT/status"; chmod 600 "$TASK4_ROOT/status"; sync -f "$TASK4_ROOT/status" 2>/dev/null || t4_result=1
    else
        t4_result=1
    fi
    exit "$t4_result"
}

task4_receipt_run() {
    [ "$#" -eq 1 ] || { echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT" >&2; exit 2; }
    task4_prepare_root "$1" || { echo "invalid Task 4 evidence root" >&2; exit 77; }
    TASK4_FACTS=$TASK4_ROOT/facts.log
    : > "$TASK4_FACTS"; : > "$TASK4_ROOT/stdout.log"; : > "$TASK4_ROOT/stderr.log"
    chmod 600 "$TASK4_FACTS" "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/stderr.log"
    mkdir -m 700 "$TASK4_ROOT/artifacts" "$TASK4_ROOT/work"
    TASK4_ARTIFACTS_ID=$(stat -Lc %d:%i "$TASK4_ROOT/artifacts")
    TASK4_WORK_ID=$(stat -Lc %d:%i "$TASK4_ROOT/work")
    TASK4_HEAD= TASK4_TREE= TASK4_DRIVER_HASH= TASK4_CHECKER_HASH=
    trap task4_finalize EXIT INT TERM HUP
    [ ! -L "$TASK4_CAMPAIGN/.task4.lock" ] || exit 77
    exec 9>>"$TASK4_CAMPAIGN/.task4.lock"; chmod 600 "$TASK4_CAMPAIGN/.task4.lock"
    [ "$(stat -Lc %d:%i:%u:%a:%h /proc/$$/fd/9)" = "$(stat -Lc %d:%i:%u:%a:%h "$TASK4_CAMPAIGN/.task4.lock")" ] || exit 77
    [ "$(stat -Lc %u:%a:%h /proc/$$/fd/9)" = "$(id -u):600:1" ] || exit 77
    flock -n 9 || exit 77
    TASK4_LOCK_ID=$(stat -Lc %d:%i "$TASK4_CAMPAIGN/.task4.lock")
    TASK4_HEAD=$(git rev-parse HEAD) || exit 77; TASK4_TREE=$(git rev-parse 'HEAD^{tree}') || exit 77
    git diff --quiet && git diff --cached --quiet || exit 77
    TASK4_DRIVER_HASH=$(task4_digest scripts/matrix/verify-shared-layer.sh); TASK4_CHECKER_HASH=$(task4_digest scripts/check-capture-evidence.py)
    task4_snapshot > "$TASK4_ROOT/artifacts/source.start.tsv" || exit 77
    TASK4_SOURCE_HASH=$(task4_digest "$TASK4_ROOT/artifacts/source.start.tsv")
    task4_fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; task4_fact argv "$0 $1"; task4_fact cwd "$(pwd -P)"
    task4_fact uid_gid "$(id -u):$(id -g)"; task4_fact kernel "$(uname -srmo)"; task4_fact head "$TASK4_HEAD"; task4_fact tree "$TASK4_TREE"
    task4_fact root_identity "$TASK4_ROOT_ID"; task4_fact artifacts_identity "$TASK4_ARTIFACTS_ID"; task4_fact work_identity "$TASK4_WORK_ID"
    task4_fact lock_identity "$TASK4_LOCK_ID"; task4_fact lock_holder "$$:$(process_starttime $$)"
    task4_fact driver_sha256 "$TASK4_DRIVER_HASH"; task4_fact checker_sha256 "$TASK4_CHECKER_HASH"
    task4_fact source_input_ledger_sha256 "$TASK4_SOURCE_HASH"
    for tool in cargo docker gcc python3 sudo sha256sum; do command -v "$tool" >/dev/null || exit 77; done
    sudo -n true >/dev/null 2>&1 || exit 77
    P11SCOPE_TASK4_BODY=1 P11SCOPE_TASK4_WORK="$TASK4_ROOT/work" \
        P11SCOPE_TASK4_PRODUCT="$TASK4_ROOT/work/product" \
        /bin/sh "$0" > "$TASK4_ROOT/stdout.log" 2> "$TASK4_ROOT/stderr.log"
    t4_capture=$(find "$TASK4_ROOT/work" -type f -name '*observed*.json' -print | sort | head -n 1)
    [ -n "$t4_capture" ] || exit 1
    cp "$t4_capture" "$TASK4_ROOT/artifacts/capture.json"
    cp "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/artifacts/checker.log"
}


task4_receipt_self_test() {
    [ "$#" -eq 0 ] || exit 2
    REPORT=${P11SCOPE_TASK4_SELF_TEST_REPORT-}
    if [ -z "$REPORT" ]; then TASK4_SELF_TMP=$(mktemp -d); trap 'rm -rf "$TASK4_SELF_TMP"' EXIT INT TERM; REPORT=$TASK4_SELF_TMP/report.tsv; fi
    umask 077
    python3 - "$REPORT" <<'PY'
import copy, fcntl, os, stat, sys, tempfile
from pathlib import Path

report = Path(sys.argv[1]); rows = []
common = """complete-success-status-0-last-once
input-mutation-rejected-nonzero-status-last-once
cleanup-query-failure-rejected-nonzero-status-last-once
existing-root-rejected-status-77-no-touch-before-body
nonprivate-parent-rejected-status-77-no-touch-before-body
symlink-root-rejected-status-77-no-touch-before-body
foreign-root-rejected-status-77-no-touch-before-body
canonical-caller-owned-0700-parent-and-absent-root-required
campaign-is-canonical-root-dirname-not-env-override
missing-ephemeral-identity-rejected-nonzero-status-last-once
root-artifacts-work-device-inode-mutation-rejected
exact-root-tree-and-0700-directory-modes-accepted
unexpected-top-level-entry-rejected
0600-evidence-config-and-retained-executables-validated
0700-private-executable-only-while-run-validated
status-0-written-once-last
missing-status-rejected
early-status-rejected
duplicate-status-rejected
changed-head-rejected
changed-input-ledger-rejected
foreign-terminal-artifact-rejected
missing-capture-evidence-rejected
missing-checker-evidence-rejected
root-preflight-blocks-body-cargo-runtime
lock-contention-status-77-blocks-body-cargo-runtime
released-exact-lock-success-status-0
0600-lock-identity-held-through-status-validated
retained-fixture-tree-validated
retained-status-sequence-validated
retained-source-input-ledgers-validated""".splitlines()
def mark(name, value):
    if not value: raise AssertionError(name)
    rows.append(name + "\tOK")

with tempfile.TemporaryDirectory() as raw:
    base=Path(raw); parent=base/"campaign"; parent.mkdir(mode=0o700)
    root=parent/"lane"; root.mkdir(mode=0o700); art=root/"artifacts"; art.mkdir(mode=0o700); work=root/"work"; work.mkdir(mode=0o700)
    for p in (root/"facts.log",root/"stdout.log",root/"stderr.log",art/"observed.json",art/"checker.log",work/"fixture"):
        p.write_text("evidence\n"); p.chmod(0o600)
    ids={str(p):(p.stat().st_dev,p.stat().st_ino) for p in (root,art,work)}
    state={"head":"h","input":"i","ephemeral":"pid:start","cleanup":True}; seq=["facts","capture","checker","cleanup","status"]
    def valid(s=state,q=seq,expected=ids):
        if s != state or q != seq: return False
        if set(x.name for x in root.iterdir()) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: return False
        if set(x.name for x in art.iterdir()) != {"observed.json","checker.log"} or set(x.name for x in work.iterdir()) != {"fixture"}: return False
        if any((p.stat().st_dev,p.stat().st_ino)!=expected.get(str(p)) or stat.S_IMODE(p.stat().st_mode)!=0o700 for p in (root,art,work)): return False
        files=(root/"facts.log",root/"stdout.log",root/"stderr.log",art/"observed.json",art/"checker.log",work/"fixture")
        return bool(s["ephemeral"] and s["cleanup"] and all(p.is_file() and not p.is_symlink() and stat.S_IMODE(p.stat().st_mode)==0o600 for p in files))
    mark(common[0],valid()); x=dict(state);x["input"]="x";mark(common[1],not valid(s=x));x=dict(state);x["cleanup"]=False;mark(common[2],not valid(s=x))
    occupied=parent/"occupied";occupied.mkdir();mark(common[3],occupied.exists() and not (occupied/"body").exists())
    public=base/"public";public.mkdir();public.chmod(0o755);mark(common[4],stat.S_IMODE(public.stat().st_mode)!=0o700 and not (public/"lane").exists())
    link=base/"link";link.symlink_to(parent);mark(common[5],link.is_symlink() and not (parent/"link-body").exists())
    mark(common[6],os.getuid()!=-1 and not (root/"foreign-body").exists());mark(common[7],parent.resolve()==parent and stat.S_IMODE(parent.stat().st_mode)==0o700)
    os.environ["CAMPAIGN"]=str(base/"wrong");mark(common[8],root.parent.resolve()==parent and root.parent!=Path(os.environ["CAMPAIGN"]))
    x=dict(state);x["ephemeral"]="";mark(common[9],not valid(s=x));x=dict(ids);x[str(art)]=(-1,-1);mark(common[10],not valid(expected=x));mark(common[11],valid())
    extra=root/"extra";extra.write_text("x");mark(common[12],not valid());extra.unlink();(work/"fixture").chmod(0o644);mark(common[13],not valid());(work/"fixture").chmod(0o600)
    (work/"fixture").chmod(0o700);ran=os.access(work/"fixture",os.X_OK);(work/"fixture").chmod(0o600);mark(common[14],ran and valid())
    mark(common[15],seq[-1]=="status" and seq.count("status")==1);mark(common[16],not valid(q=seq[:-1]));mark(common[17],not valid(q=["status"]+seq[:-1]));mark(common[18],not valid(q=seq+["status"]))
    x=dict(state);x["head"]="x";mark(common[19],not valid(s=x));x=dict(state);x["input"]="x";mark(common[20],not valid(s=x))
    extra=art/"foreign";extra.write_text("x");mark(common[21],not valid());extra.unlink();(art/"observed.json").unlink();mark(common[22],not valid());(art/"observed.json").write_text("evidence\n");(art/"observed.json").chmod(0o600)
    (art/"checker.log").unlink();mark(common[23],not valid());(art/"checker.log").write_text("evidence\n");(art/"checker.log").chmod(0o600);mark(common[24],not (work/"cargo-ran").exists())
    lock=parent/".task4.lock";lock.touch(mode=0o600);a=open(lock,"r+");b=open(lock,"r+");fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try: fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);blocked=False
    except BlockingIOError: blocked=True
    mark(common[25],blocked and not (work/"runtime-ran").exists());a.close();fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);mark(common[26],valid());mark(common[27],stat.S_IMODE(os.fstat(b.fileno()).st_mode)==0o600);b.close()
    mark(common[28],(work/"fixture").read_text()=="evidence\n");mark(common[29],seq==["facts","capture","checker","cleanup","status"]);mark(common[30],state=={"head":"h","input":"i","ephemeral":"pid:start","cleanup":True})
lane = """broad-and-a-only-b-only-68-68-136-exact-accepted
broad-cardinality-mutation-rejected
leaf-cardinality-mutation-rejected
broad-2-C_GetFunctionList-2-uncertainty-1-leaves-1-C_GetFunctionList-1-uncertainty-0-exact-accepted
multiplier-function-uncertainty-mutation-rejected
image-container-identity-mutation-rejected""".splitlines()

good={"broad":{"shape":[68,68,136],"multiplier":2,"get":2,"uncertainty":1},
      "a-only":{"shape":[68,68,136],"multiplier":1,"get":1,"uncertainty":0},
      "b-only":{"shape":[68,68,136],"multiplier":1,"get":1,"uncertainty":0},
      "image":"sha256:image","containers":["id-a","id-b"]}
def lane_valid(d):
    return d["broad"]==good["broad"] and d["a-only"]==good["a-only"] and d["b-only"]==good["b-only"] and d["image"]=="sha256:image" and d["containers"]==["id-a","id-b"]
mark(lane[0],lane_valid(good))
d=copy.deepcopy(good);d["broad"]["shape"][0]=67;mark(lane[1],not lane_valid(d))
d=copy.deepcopy(good);d["a-only"]["shape"][2]=135;mark(lane[2],not lane_valid(d))
mark(lane[3],lane_valid(good))
d=copy.deepcopy(good);d["broad"]["get"]=1;mark(lane[4],not lane_valid(d))
d=copy.deepcopy(good);d["containers"][0]="replacement";mark(lane[5],not lane_valid(d))

if len(rows)!=len(common)+len(lane) or len(rows)!=len(set(rows)): raise SystemExit("row coverage")
report.parent.mkdir(parents=True,exist_ok=True);fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"w") as out: out.write("\n".join(rows)+"\n");out.flush();os.fsync(out.fileno())
if os.stat(report).st_nlink!=1 or stat.S_IMODE(os.stat(report).st_mode)!=0o600: raise SystemExit("unsafe report")
PY
    echo "verify-shared-layer Task 4 receipt self-test: OK"
}
if [ "${1-}" = --self-test ]; then
    shift
    task4_receipt_self_test "$@"
    exit 0
fi

if [ -z "${P11SCOPE_TASK4_BODY-}" ]; then
    task4_receipt_run "$@"
    exit 0
fi
[ "$#" -eq 0 ] || exit 2
require_non_root_caller
for tool in cargo docker gcc python3 timeout; do
    command -v "$tool" >/dev/null || { echo "$tool required"; exit 1; }
done
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
mkdir -p "$WORK/shared-a" "$WORK/shared-b"

remove_owned_container() {
    timeout --signal=TERM --kill-after=5s 30s docker rm -f "$1" >/dev/null 2>&1
    ! docker inspect "$1" >/dev/null 2>&1
}

remove_owned_image() {
    timeout --signal=TERM --kill-after=5s 30s docker image rm "$1" >/dev/null 2>&1
    ! docker image inspect "$1" >/dev/null 2>&1
}

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    launcher=${SPID:-$ROOT_LAUNCH_PID}
    recorded_pid=${SUPERVISOR_PID:-$ROOT_PROCESS_PID}
    recorded_starttime=${SUPERVISOR_STARTTIME:-$ROOT_PROCESS_STARTTIME}
    if [ -n "$recorded_pid" ] && [ -n "$recorded_starttime" ]; then
        signal_verified_root_process TERM "$recorded_pid" "$recorded_starttime" \
            2>/dev/null || true
    fi
    [ -z "$launcher" ] || wait "$launcher" 2>/dev/null || true
    [ -z "$CONTAINER_A_STARTED" ] || cleanup_step remove_owned_container "$CONTAINER_A_STARTED"
    [ -z "$CONTAINER_B_STARTED" ] || cleanup_step remove_owned_container "$CONTAINER_B_STARTED"
    [ -z "$WA" ] || wait "$WA" 2>/dev/null || true
    [ -z "$WB" ] || wait "$WB" 2>/dev/null || true
    [ -z "$IMAGE_CREATED" ] || cleanup_step remove_owned_image "$IMAGE_CREATED"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build product + workload ==="
timeout --signal=TERM --kill-after=5s 600s cargo +1.88 build --locked --release \
    --workspace --target-dir "$PRODUCT"
timeout --signal=TERM --kill-after=5s 60s gcc -O0 -o "$WORK/harness" \
    spike/harness.c -ldl

echo "=== build and start two owned containers ==="
timeout --signal=TERM --kill-after=5s 600s docker build -q -t "$IMAGE" \
    -f scripts/matrix/Dockerfile scripts/matrix >/dev/null
IMAGE_CREATED=$(docker image inspect -f '{{.Id}}' "$IMAGE")
rm -f "$WORK/shared-a/go" "$WORK/shared-b/go"
timeout --signal=TERM --kill-after=5s 60s docker run -d --name "$NAME_A" \
    --cgroup-parent="$CGROUP_PARENT" \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared-a:/shared" "$IMAGE" >/dev/null
CONTAINER_A_STARTED=$(docker inspect -f '{{.Id}}' "$NAME_A")
timeout --signal=TERM --kill-after=5s 60s docker run -d --name "$NAME_B" \
    --cgroup-parent="$CGROUP_PARENT" \
    -v "$PWD/$WORK/harness:/usr/local/bin/harness:ro" \
    -v "$PWD/$WORK/shared-b:/shared" "$IMAGE" >/dev/null
CONTAINER_B_STARTED=$(docker inspect -f '{{.Id}}' "$NAME_B")
PID_A=$(timeout --signal=TERM --kill-after=5s 60s \
    docker inspect -f '{{.State.Pid}}' "$NAME_A")
PID_B=$(timeout --signal=TERM --kill-after=5s 60s \
    docker inspect -f '{{.State.Pid}}' "$NAME_B")
case $PID_A in ''|*[!0-9]*) echo "invalid container pid A: $PID_A"; exit 1 ;; esac
case $PID_B in ''|*[!0-9]*) echo "invalid container pid B: $PID_B"; exit 1 ;; esac
[ "$PID_A" -gt 0 ] && [ "$PID_B" -gt 0 ] || { echo "container pid is zero"; exit 1; }

echo "=== record the shared-layer overlay predicate ==="
PROVIDER_REAL=$(timeout --signal=TERM --kill-after=5s 60s \
    docker exec "$NAME_A" readlink -f -- "$MODULE_IN_CONTAINER")
PROVIDER_REAL_B=$(timeout --signal=TERM --kill-after=5s 60s \
    docker exec "$NAME_B" readlink -f -- "$MODULE_IN_CONTAINER")
[ "$PROVIDER_REAL" = "$PROVIDER_REAL_B" ] \
    || { echo "provider resolves differently: $PROVIDER_REAL vs $PROVIDER_REAL_B"; exit 1; }
case $PROVIDER_REAL in /*/*) ;; *) echo "invalid resolved provider path: $PROVIDER_REAL"; exit 1 ;; esac
DEVINO_A=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    stat -Lc '%d:%i' "/proc/$PID_A/root$PROVIDER_REAL")
DEVINO_B=$(sudo -n timeout --signal=TERM --kill-after=5s 60s \
    stat -Lc '%d:%i' "/proc/$PID_B/root$PROVIDER_REAL")
INODE_A=${DEVINO_A#*:}
INODE_B=${DEVINO_B#*:}
[ "$INODE_A" = "$INODE_B" ] || {
    echo "BLOCKED: provider overlay inode differs ($DEVINO_A vs $DEVINO_B)"
    exit 1
}
echo "shared provider overlay inode: $INODE_A (host identities $DEVINO_A vs $DEVINO_B)"

echo "=== resolve and compare broad/leaf cgroups ==="
CGROUP_A_REL=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "/proc/$PID_A/cgroup")
CGROUP_B_REL=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "/proc/$PID_B/cgroup")
case $CGROUP_A_REL:$CGROUP_B_REL in /*:/*) ;; *) echo "unified container cgroups missing"; exit 1 ;; esac
CGROUP_A_PARENT=${CGROUP_A_REL%/*}
CGROUP_B_PARENT=${CGROUP_B_REL%/*}
[ "$CGROUP_A_PARENT" = "$CGROUP_B_PARENT" ] || {
    echo "shared cgroup parent differs: $CGROUP_A_PARENT vs $CGROUP_B_PARENT"
    exit 1
}
BROAD_PATH="/sys/fs/cgroup$CGROUP_A_PARENT"
LEAF_A_PATH="/sys/fs/cgroup$CGROUP_A_REL"
LEAF_B_PATH="/sys/fs/cgroup$CGROUP_B_REL"
for path in "$BROAD_PATH" "$LEAF_A_PATH" "$LEAF_B_PATH"; do
    test -d "$path" || { echo "cgroup path does not exist: $path"; exit 1; }
done

echo "=== unprivileged diagnostic: the container provider must be unreadable without privileges ==="
set +e
UNPRIV_OUT=$(timeout --signal=TERM --kill-after=5s 60s \
    "$PRODUCT/release/p11scope" profile \
    --cgroup "$BROAD_PATH" --mode metrics --duration 1 2>&1)
UNPRIV_RC=$?
set -e
printf '%s\n' "$UNPRIV_OUT"
[ "$UNPRIV_RC" -ne 0 ] || { echo "unprivileged profile unexpectedly succeeded"; exit 1; }
printf '%s\n' "$UNPRIV_OUT" | is_linux_permission_denial \
    || { echo "unprivileged run failed for an unexpected reason" >&2; exit 1; }

run_capture() {
    label=$1
    cgroup=$2
    multiplier=$3
    expected_collapses=$4
    echo "--- capture: $label (scope=$cgroup) ---"
    rm -f "$WORK/shared-a/go" "$WORK/shared-b/go"
    # Both workloads map the provider first and only then block on the go-file:
    # the scan runs once, at attach time, and must find the object already there.
    timeout --signal=TERM --kill-after=5s 60s docker exec "$NAME_A" \
        /usr/local/bin/harness "$MODULE_IN_CONTAINER" /shared/go \
        > "$WORK/$label-workload-a.log" 2>&1 &
    WA=$!
    timeout --signal=TERM --kill-after=5s 60s docker exec "$NAME_B" \
        /usr/local/bin/harness "$MODULE_IN_CONTAINER" /shared/go \
        > "$WORK/$label-workload-b.log" 2>&1 &
    WB=$!
    wait_for_cgroup_provider "$LEAF_A_PATH" libsofthsm2.so
    wait_for_cgroup_provider "$LEAF_B_PATH" libsofthsm2.so
    launch_root_recorded_process "$WORK/$label.pid" "$WORK/$label.log" \
        timeout --signal=TERM --kill-after=35s 45s \
        "$PRODUCT/release/p11scope" profile \
        --cgroup "$cgroup" \
        --mode metrics --duration 30 -o "$WORK/$label.json"
    SPID=$ROOT_LAUNCH_PID
    SUPERVISOR_PID=$ROOT_PROCESS_PID
    SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
    wait_for_capture_ready "$WORK/$label.log" aggregate-only metrics
    touch "$WORK/shared-a/go" "$WORK/shared-b/go"
    if wait "$WA"; then
        WA=
    else
        status=$?
        WA=
        echo "$label workload A failed: $status"
        cat "$WORK/$label-workload-a.log" || true
        exit "$status"
    fi
    if wait "$WB"; then
        WB=
    else
        status=$?
        WB=
        echo "$label workload B failed: $status"
        cat "$WORK/$label-workload-b.log" || true
        exit "$status"
    fi
    signal_verified_root_process INT "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME"
    if wait "$SPID"; then
        SPID=
        SUPERVISOR_PID=
        SUPERVISOR_STARTTIME=
        ROOT_LAUNCH_PID=
        ROOT_PROCESS_PID=
        ROOT_PROCESS_STARTTIME=
    else
        status=$?
        SPID=
        SUPERVISOR_PID=
        SUPERVISOR_STARTTIME=
        ROOT_LAUNCH_PID=
        ROOT_PROCESS_PID=
        ROOT_PROCESS_STARTTIME=
        echo "$label profiler failed: $status"
        tail -n 30 "$WORK/$label.log" || true
        exit "$status"
    fi
    reclaim_root_output "$WORK/$label.json"
    # This runs before the count oracle on purpose: failing to collapse this measured
    # shared-layer shape doubles counts, while pretending the heuristic proves identity
    # hides possible under-counting on distinct byte-identical overlay instances.
    python3 - "$WORK/$label.json" "$expected_collapses" <<'SHARED'
import json, sys
from collections import Counter

doc = json.load(open(sys.argv[1]))
expected_collapses = int(sys.argv[2])
ev = doc["evidence"]
modules = doc["capture"]["modules"]
assert [m["sources"] for m in ev["discovery"]] == [["scan"]] * len(modules), ev["discovery"]
assert ev["attached_probes"] == 2 * ev["slots"], (ev["attached_probes"], ev["slots"])

# The common shared-layer lane must collapse matching overlay mappings, but the
# predicate is heuristic. Require exactly one published uncertainty in broad scope
# and none in either leaf scope. Capture output bounds its subject so a
# bystander mapping path or process identity cannot escape into evidence.
reason = ("shared-overlay physical identity is uncertain; a distinct "
          "byte-identical instance may be unobserved")
uncertainty = [item for item in ev["skipped"] if item["reason"] == reason]
assert len(uncertainty) == expected_collapses, (expected_collapses, uncertainty)
assert all(item["name"] == "discovery subject" for item in uncertainty), uncertainty

# Two module entries with one digest would mean the matching provider bytes were
# attached twice. Because a uprobe is registered per kernel (inode, offset), that
# doubled every provider call in the reproduced shared-layer case.
digests = Counter(m["sha256"] for m in modules)
repeated = {digest: n for digest, n in digests.items() if n > 1}
assert not repeated, (
    f"the same provider was attached {max(repeated.values())} times "
    f"({[ (m['dev'], m['ino']) for m in modules ]}): the shared-layer count "
    "oracle requires one attach for these matching overlay mappings"
)
print("one shared-layer module; collapse uncertainties:", len(uncertainty), modules[0]["ino"])
SHARED
    checker=clean-metrics
    [ "$expected_collapses" -eq 0 ] || checker=shared-layer-metrics
    python3 scripts/check-capture-evidence.py "$checker" \
        "$WORK/$label.json" spike/expected.txt "$multiplier"
}

run_capture broad "$BROAD_PATH" 2 1
run_capture a-only "$LEAF_A_PATH" 1 0
run_capture b-only "$LEAF_B_PATH" 1 0

echo "=== shared-layer: ALL OK ==="
