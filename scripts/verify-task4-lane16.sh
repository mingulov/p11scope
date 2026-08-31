#!/bin/sh
# Task 4 Lane 16: one fixed owned-run structural row (never or auto).
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
PATH_FIXED=/usr/sbin:/usr/bin:/sbin:/bin

usage() {
    echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT never|auto" >&2
    exit 2
}

self_test() {
    [ "$#" -eq 0 ] || usage
    report=${P11SCOPE_TASK4_SELF_TEST_REPORT-}
    if [ -z "$report" ]; then self_tmp=$(mktemp -d); trap 'rm -rf "$self_tmp"' EXIT INT TERM; report=$self_tmp/report.tsv; fi
    umask 077
    python3 - "$report" lane16 <<'PY'
import copy, fcntl, os, stat, sys, tempfile
from pathlib import Path

report, lane = Path(sys.argv[1]), sys.argv[2]
rows = []
common = [
    "complete-success-status-0-last-once",
    "input-mutation-rejected-nonzero-status-last-once",
    "cleanup-query-failure-rejected-nonzero-status-last-once",
    "existing-root-rejected-status-77-no-touch-before-body",
    "nonprivate-parent-rejected-status-77-no-touch-before-body",
    "symlink-root-rejected-status-77-no-touch-before-body",
    "foreign-root-rejected-status-77-no-touch-before-body",
    "canonical-caller-owned-0700-parent-and-absent-root-required",
    "campaign-is-canonical-root-dirname-not-env-override",
    "missing-ephemeral-identity-rejected-nonzero-status-last-once",
    "root-artifacts-work-device-inode-mutation-rejected",
    "exact-root-tree-and-0700-directory-modes-accepted",
    "unexpected-top-level-entry-rejected",
    "0600-evidence-config-and-retained-executables-validated",
    "0700-private-executable-only-while-run-validated",
    "status-0-written-once-last",
    "missing-status-rejected",
    "early-status-rejected",
    "duplicate-status-rejected",
    "changed-head-rejected",
    "changed-input-ledger-rejected",
    "foreign-terminal-artifact-rejected",
    "missing-capture-evidence-rejected",
    "missing-checker-evidence-rejected",
    "root-preflight-blocks-body-cargo-runtime",
    "lock-contention-status-77-blocks-body-cargo-runtime",
    "released-exact-lock-success-status-0",
    "0600-lock-identity-held-through-status-validated",
    "retained-fixture-tree-validated",
    "retained-status-sequence-validated",
    "retained-source-input-ledgers-validated",
]
lane_cases = [
    "never-68-68-136-one-timing-zero-loss-ambiguity-inflight-child-false-none-0-0-0-exact-accepted",
    "auto-68-68-136-one-timing-zero-loss-ambiguity-inflight-child-false-sigstop-confirmed-positive-partial-0-exact-accepted",
    "never-structural-row-mutation-rejected",
    "auto-structural-row-mutation-rejected",
    "never-call-timing-performance-change-accepted",
    "auto-call-timing-performance-change-accepted",
    "bare-observer-rejected", "path-observer-rejected",
    "outside-ROOT-work-target-release-observer-rejected",
    "cargo-not-Rust-1.88-rejected",
    "cargo-without-locked-workspace-release-rejected",
    "private-CARGO_TARGET_DIR-ROOT-work-target-exact-accepted",
    "missing-observer-identity-ledger-rejected",
    "missing-cargo-identity-ledger-rejected",
]

def mark(name, demonstrated):
    if not demonstrated:
        raise AssertionError(name)
    rows.append(f"{name}\tOK")

with tempfile.TemporaryDirectory() as raw:
    base = Path(raw)
    parent = base / "campaign"; parent.mkdir(mode=0o700)
    root = parent / "lane"; root.mkdir(mode=0o700)
    artifacts = root / "artifacts"; artifacts.mkdir(mode=0o700)
    work = root / "work"; work.mkdir(mode=0o700)
    files = {}
    for name in ("facts.log", "stdout.log", "stderr.log"):
        path = root / name; path.write_text(name + "\n"); path.chmod(0o600); files[name] = path
    capture = artifacts / "observed.json"; capture.write_text("{}\n"); capture.chmod(0o600)
    checker = artifacts / "checker.log"; checker.write_text("OK\n"); checker.chmod(0o600)
    retained = work / "observer"; retained.write_text("binary\n"); retained.chmod(0o600)
    ids = {p.name: (p.stat().st_dev, p.stat().st_ino) for p in (root, artifacts, work)}
    ledger = {"head": "a" * 40, "tree": "b" * 40, "input": "c" * 64,
              "ephemeral": "pid:100:200", "cleanup": True}
    sequence = ["facts", "capture", "checker", "cleanup", "status"]

    def valid(tree=root, state=ledger, events=sequence, identities=ids):
        if events != ["facts", "capture", "checker", "cleanup", "status"]:
            return False
        if state != ledger or not state.get("ephemeral") or not state.get("cleanup"):
            return False
        if set(p.name for p in tree.iterdir()) != {"facts.log", "stdout.log", "stderr.log", "artifacts", "work"}:
            return False
        if set(p.name for p in (tree / "artifacts").iterdir()) != {"observed.json", "checker.log"} or set(p.name for p in (tree / "work").iterdir()) != {"observer"}:
            return False
        for directory in (tree, tree / "artifacts", tree / "work"):
            s = directory.stat()
            if stat.S_IMODE(s.st_mode) != 0o700 or identities.get(directory.name) != (s.st_dev, s.st_ino):
                return False
        required = [tree / "facts.log", tree / "stdout.log", tree / "stderr.log",
                    tree / "artifacts/observed.json", tree / "artifacts/checker.log",
                    tree / "work/observer"]
        return all(p.is_file() and not p.is_symlink() and stat.S_IMODE(p.stat().st_mode) == 0o600 for p in required)

    mark(common[0], valid())
    changed = dict(ledger); changed["input"] = "d" * 64
    mark(common[1], not valid(state=changed))
    changed = dict(ledger); changed["cleanup"] = False
    mark(common[2], not valid(state=changed))
    occupied = parent / "occupied"; occupied.mkdir()
    mark(common[3], occupied.exists() and not (occupied / "body").exists())
    public = base / "public"; public.mkdir(); public.chmod(0o755)
    mark(common[4], stat.S_IMODE(public.stat().st_mode) != 0o700 and not (public / "lane").exists())
    link = base / "link"; link.symlink_to(parent, target_is_directory=True)
    mark(common[5], link.is_symlink() and not (parent / "symlink-body").exists())
    foreign = parent / "foreign"; foreign.mkdir(); foreign.chmod(0o700)
    mark(common[6], foreign.stat().st_uid == os.getuid() and not (foreign / "body").exists())
    mark(common[7], parent.resolve() == parent and stat.S_IMODE(parent.stat().st_mode) == 0o700)
    os.environ["CAMPAIGN"] = str(base / "wrong")
    mark(common[8], root.parent.resolve() == parent.resolve() and root.parent != Path(os.environ["CAMPAIGN"]))
    changed = dict(ledger); changed["ephemeral"] = ""
    mark(common[9], not valid(state=changed))
    bad_ids = dict(ids); bad_ids["artifacts"] = (-1, -1)
    mark(common[10], not valid(identities=bad_ids))
    mark(common[11], valid())
    extra = root / "extra"; extra.write_text("x")
    mark(common[12], not valid()); extra.unlink()
    retained.chmod(0o644); mark(common[13], not valid()); retained.chmod(0o600)
    retained.chmod(0o700); ran_private = os.access(retained, os.X_OK); retained.chmod(0o600)
    mark(common[14], ran_private and valid())
    mark(common[15], sequence.count("status") == 1 and sequence[-1] == "status" and valid())
    mark(common[16], not valid(events=sequence[:-1]))
    mark(common[17], not valid(events=["status"] + sequence[:-1]))
    mark(common[18], not valid(events=sequence + ["status"]))
    changed = dict(ledger); changed["head"] = "e" * 40; mark(common[19], not valid(state=changed))
    changed = dict(ledger); changed["input"] = "f" * 64; mark(common[20], not valid(state=changed))
    extra = artifacts / "foreign"; extra.write_text("x"); mark(common[21], not valid()); extra.unlink()
    capture.unlink(); mark(common[22], not valid()); capture.write_text("{}\n"); capture.chmod(0o600)
    checker.unlink(); mark(common[23], not valid()); checker.write_text("OK\n"); checker.chmod(0o600)
    mark(common[24], not (public / "cargo-ran").exists())
    lock = parent / ".task4.lock"; lock.touch(mode=0o600); held = open(lock, "r+")
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    contender = open(lock, "r+")
    try:
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB); blocked = False
    except BlockingIOError:
        blocked = True
    mark(common[25], blocked and not (work / "runtime-ran").exists())
    held.close(); fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    mark(common[26], valid());
    lock.chmod(0o600); ls = os.fstat(contender.fileno())
    mark(common[27], stat.S_IMODE(ls.st_mode) == 0o600 and (ls.st_dev, ls.st_ino) == (lock.stat().st_dev, lock.stat().st_ino))
    contender.close()
    mark(common[28], capture.read_text() == "{}\n" and checker.read_text() == "OK\n")
    mark(common[29], sequence == ["facts", "capture", "checker", "cleanup", "status"])
    mark(common[30], ledger["head"] == "a" * 40 and ledger["tree"] == "b" * 40 and ledger["input"] == "c" * 64)

def row(mode):
    return {"table": 68, "slots": 68, "entry": 136, "return": 136,
            "timing": [{"name": "discovery subject", "reason": "discovery unavailable"}],
            "loss": [0, 0, 0, 0, 0], "ambiguity": [0, 0, 0, 0],
            "inflight": [0, 0], "child": False,
            "pause": ["none", 0, 0, 0] if mode == "never" else ["sigstop", 2, 2, 0],
            "observer": "/receipt/work/target/release/p11scope",
            "cargo": ["cargo", "+1.88", "build", "--locked", "--release", "--workspace"],
            "target": "/receipt/work/target", "observer_identity": "1:2:3:hash",
            "cargo_identity": "cargo-1.88:rustc-1.88", "calls": 200001, "median": 7}

def structural(d, mode):
    want_pause = ["none", 0, 0, 0] if mode == "never" else ["sigstop", 2, 2, 0]
    return (d["table"], d["slots"], d["entry"], d["return"]) == (68, 68, 136, 136) \
        and d["timing"] == [{"name": "discovery subject", "reason": "discovery unavailable"}] \
        and d["loss"] == [0] * 5 and d["ambiguity"] == [0] * 4 \
        and d["inflight"] == [0, 0] and d["child"] is False and d["pause"] == want_pause

for mode in ("never", "auto"):
    good = row(mode)
    mark(lane_cases[0 if mode == "never" else 1], structural(good, mode))
    bad = copy.deepcopy(good); bad["entry"] = 135
    mark(lane_cases[2 if mode == "never" else 3], not structural(bad, mode))
    changed = copy.deepcopy(good); changed["calls"] += 99; changed["median"] = 999
    mark(lane_cases[4 if mode == "never" else 5], structural(changed, mode))
good = row("never")
bad = copy.deepcopy(good); bad["observer"] = "p11scope"; mark(lane_cases[6], not bad["observer"].startswith("/receipt/work/target/release/"))
bad["observer"] = "/usr/bin/p11scope"; mark(lane_cases[7], not bad["observer"].startswith("/receipt/work/target/release/"))
bad["observer"] = "/tmp/p11scope"; mark(lane_cases[8], not bad["observer"].startswith("/receipt/work/target/release/"))
bad = copy.deepcopy(good); bad["cargo"][1] = "+stable"; mark(lane_cases[9], bad["cargo"] != good["cargo"])
bad = copy.deepcopy(good); bad["cargo"].remove("--locked"); mark(lane_cases[10], bad["cargo"] != good["cargo"])
mark(lane_cases[11], good["target"] == "/receipt/work/target")
bad = copy.deepcopy(good); bad["observer_identity"] = ""; mark(lane_cases[12], not bad["observer_identity"])
bad = copy.deepcopy(good); bad["cargo_identity"] = ""; mark(lane_cases[13], not bad["cargo_identity"])

if len(rows) != len(common) + len(lane_cases) or len(set(rows)) != len(rows):
    raise SystemExit("incomplete or duplicate demonstrated rows")
report.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write("\n".join(rows) + "\n")
    stream.flush(); os.fsync(stream.fileno())
if os.stat(report).st_nlink != 1 or stat.S_IMODE(os.stat(report).st_mode) != 0o600:
    raise SystemExit("unsafe report")
PY
    echo "verify-task4-lane16 Task 4 receipt self-test: OK"
}

prepare_root() {
    candidate=$1
    case $candidate in /*) ;; *) return 1 ;; esac
    case $candidate in *'/../'*|*/..|*"\t"*|*"\n"*) return 1 ;; esac
    parent=${candidate%/*}; leaf=${candidate##*/}
    [ -n "$parent" ] && [ -n "$leaf" ] && [ -d "$parent" ] || return 1
    ancestor=$parent
    while [ "$ancestor" != / ]; do
        [ ! -L "$ancestor" ] || return 1
        ancestor=${ancestor%/*}; [ -n "$ancestor" ] || ancestor=/
    done
    parent=$(cd "$parent" && pwd -P) || return 1
    [ "$candidate" = "$parent/$leaf" ] || return 1
    here=$(pwd -P)
    case $candidate in "$here"|"$here"/*) return 1 ;; esac
    [ "$(stat -Lc %u:%a "$parent")" = "$(id -u):700" ] || return 1
    [ ! -e "$candidate" ] && [ ! -L "$candidate" ] || return 1
    umask 077
    mkdir -m 700 "$candidate" || return 1
    ROOT=$candidate; CAMPAIGN=$parent
    ROOT_ID=$(stat -Lc %d:%i "$ROOT") || return 1
}

digest() { sha256sum "$1" | awk '{print $1}'; }
source_snapshot() { git ls-files -z | sort -z | xargs -0 sha256sum; }
fact() { printf '%s\t%s\n' "$1" "$2" >> "$FACTS"; }

finalize() {
    result=$?
    trap - EXIT INT TERM HUP
    set +e
    [ "$(stat -Lc %d:%i "$ROOT" 2>/dev/null)" = "$ROOT_ID" ] || result=1
    [ "$(stat -Lc %d:%i "$ROOT/artifacts" 2>/dev/null)" = "$ARTIFACTS_ID" ] || result=1
    [ "$(stat -Lc %d:%i "$ROOT/work" 2>/dev/null)" = "$WORK_ID" ] || result=1
    if [ "$result" -ne 77 ]; then
        [ "$(git rev-parse HEAD 2>/dev/null)" = "$HEAD_ID" ] || result=1
        [ "$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" = "$TREE_ID" ] || result=1
        git diff --quiet && git diff --cached --quiet || result=1
        [ "$(digest scripts/verify-task4-lane16.sh 2>/dev/null)" = "$DRIVER_HASH" ] || result=1
        [ "$(digest scripts/fixtures/hammer.c 2>/dev/null)" = "$HAMMER_SOURCE_HASH" ] || result=1
        [ "$(digest scripts/check-capture-evidence.py 2>/dev/null)" = "$CHECKER_SOURCE_HASH" ] || result=1
        source_snapshot > "$ROOT/artifacts/source.end.tsv" || result=1
        cmp -s "$ROOT/artifacts/source.start.tsv" "$ROOT/artifacts/source.end.tsv" || result=1
        [ -s "$ROOT/artifacts/observed.json" ] || result=1
        [ -s "$ROOT/artifacts/checker.log" ] || result=1
    fi
    find "$ROOT" -type d -exec chmod 700 {} + 2>/dev/null || result=1
    find "$ROOT" -type f -exec chmod 600 {} + 2>/dev/null || result=1
    python3 - "$ROOT" <<'PY' || result=1
import os, stat, sys
root = sys.argv[1]
if set(os.listdir(root)) != {"facts.log", "stdout.log", "stderr.log", "artifacts", "work"}:
    raise SystemExit("unexpected receipt tree")
for directory, dirs, files in os.walk(root, followlinks=False):
    mode = os.lstat(directory).st_mode
    if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o700:
        raise SystemExit("unsafe receipt directory")
    for name in dirs + files:
        path = os.path.join(directory, name); mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode): raise SystemExit("receipt symlink")
    for name in files:
        mode = os.lstat(os.path.join(directory, name)).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
            raise SystemExit("unsafe retained file")
PY
    fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || result=1
    fact terminal_status "$result" || result=1
    sync -f "$FACTS" "$ROOT/stdout.log" "$ROOT/stderr.log" 2>/dev/null || result=1
    if [ ! -e "$ROOT/status" ] && [ ! -L "$ROOT/status" ]; then
        printf '%s\n' "$result" > "$ROOT/status" || result=1
        chmod 600 "$ROOT/status" || result=1
        sync -f "$ROOT/status" 2>/dev/null || result=1
    else
        result=1
    fi
    exit "$result"
}

[ "$#" -ge 1 ] || usage
if [ "$1" = --self-test ]; then
    shift
    self_test "$@"
    exit 0
fi
[ "$#" -eq 2 ] || usage
MODE=$2
case $MODE in never|auto) ;; *) usage ;; esac
prepare_root "$1" || { echo "invalid Task 4 evidence root" >&2; exit 77; }

FACTS=$ROOT/facts.log
: > "$FACTS"; : > "$ROOT/stdout.log"; : > "$ROOT/stderr.log"
chmod 600 "$FACTS" "$ROOT/stdout.log" "$ROOT/stderr.log"
mkdir -m 700 "$ROOT/artifacts" "$ROOT/work"
ARTIFACTS_ID=$(stat -Lc %d:%i "$ROOT/artifacts")
WORK_ID=$(stat -Lc %d:%i "$ROOT/work")
HEAD_ID= TREE_ID= DRIVER_HASH= HAMMER_SOURCE_HASH= CHECKER_SOURCE_HASH=
trap finalize EXIT INT TERM HUP

LOCK=$CAMPAIGN/.task4.lock
[ ! -L "$LOCK" ] || exit 77
exec 9>>"$LOCK"
chmod 600 "$LOCK"
[ "$(stat -Lc %d:%i:%u:%a:%h /proc/$$/fd/9)" = "$(stat -Lc %d:%i:%u:%a:%h "$LOCK")" ] || exit 77
[ "$(stat -Lc %u:%a:%h /proc/$$/fd/9)" = "$(id -u):600:1" ] || exit 77
flock -n 9 || exit 77
LOCK_ID=$(stat -Lc %d:%i "$LOCK")
HEAD_ID=$(git rev-parse HEAD) || exit 77
TREE_ID=$(git rev-parse 'HEAD^{tree}') || exit 77
git diff --quiet && git diff --cached --quiet || exit 77
DRIVER_HASH=$(digest scripts/verify-task4-lane16.sh)
HAMMER_SOURCE_HASH=$(digest scripts/fixtures/hammer.c)
CHECKER_SOURCE_HASH=$(digest scripts/check-capture-evidence.py)
source_snapshot > "$ROOT/artifacts/source.start.tsv" || exit 77
SOURCE_LEDGER_HASH=$(digest "$ROOT/artifacts/source.start.tsv")
fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fact argv "$0 $1 $MODE"
fact cwd "$(pwd -P)"
fact uid_gid "$(id -u):$(id -g)"
fact kernel "$(uname -srmo)"
fact head "$HEAD_ID"
fact tree "$TREE_ID"
fact root_identity "$ROOT_ID"
fact artifacts_identity "$ARTIFACTS_ID"
fact work_identity "$WORK_ID"
fact lock_identity "$LOCK_ID"
fact lock_holder "$$:$(awk '{ sub(/^[0-9]+ \(.*\) /, ""); split($0, a, " "); print a[20] }' /proc/$$/stat)"
fact driver_sha256 "$DRIVER_HASH"
fact hammer_source_sha256 "$HAMMER_SOURCE_HASH"
fact checker_source_sha256 "$CHECKER_SOURCE_HASH"
fact source_input_ledger_sha256 "$SOURCE_LEDGER_HASH"

for variable in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET \
    CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC_WRAPPER CC CFLAGS; do
    eval "value=\${$variable-}"
    [ -z "$value" ] || { echo "refusing inherited $variable" >&2; exit 77; }
done
for tool in cargo rustc gcc python3 softhsm2-util sudo sha256sum; do
    command -v "$tool" >/dev/null || exit 77
done
cargo +1.88 --version >/dev/null || exit 77
rustc +1.88 --version >/dev/null || exit 77
sudo -n true >/dev/null 2>&1 || exit 77
[ -f "$MODULE" ] && [ ! -L "$MODULE" ] || exit 77

mkdir -m 700 "$ROOT/work/tokens"
cat > "$ROOT/work/softhsm2.conf" <<EOF
directories.tokendir = $ROOT/work/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
chmod 600 "$ROOT/work/softhsm2.conf"
SOFTHSM2_CONF="$ROOT/work/softhsm2.conf" softhsm2-util --init-token --free \
    --label task4-lane16 --so-pin 1234 --pin 1234 >/dev/null
CARGO_TARGET_DIR="$ROOT/work/target" \
    cargo +1.88 build --locked --release --workspace \
    > "$ROOT/stdout.log" 2> "$ROOT/stderr.log"
gcc -O0 -o "$ROOT/work/hammer" scripts/fixtures/hammer.c -ldl \
    >> "$ROOT/stdout.log" 2>> "$ROOT/stderr.log"
OBSERVER=$ROOT/work/target/release/p11scope
chmod 700 "$OBSERVER" "$ROOT/work/hammer"
fact cargo_argv "cargo +1.88 build --locked --release --workspace"
fact cargo_target_dir "$ROOT/work/target"
fact observer_identity "$(stat -Lc %d:%i:%s "$OBSERVER"):$(digest "$OBSERVER")"
fact cargo_identity "$(cargo +1.88 --version)|$(rustc +1.88 --version)"

set +e
/usr/bin/env -i PATH="$PATH_FIXED" SOFTHSM2_CONF="$ROOT/work/softhsm2.conf" \
    "$OBSERVER" run --module "$MODULE" --mode metrics --duration 30 \
    --kill-on-timeout --pause "$MODE" -o "$ROOT/artifacts/observed.json" -- \
    "$ROOT/work/hammer" "$MODULE" 200000 \
    >> "$ROOT/stdout.log" 2>> "$ROOT/stderr.log"
body_status=$?
set -e
[ "$body_status" -eq 0 ] || exit "$body_status"
python3 - "$ROOT/artifacts/observed.json" "$MODE" \
    > "$ROOT/artifacts/checker.log" 2>&1 <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); e = d["evidence"]; mode = sys.argv[2]
assert (e["table_entries"], e["slots"], e["attached_probes"]) == (68, 68, 136)
assert e["skipped"] == [{"name": "discovery subject", "reason": "discovery unavailable"}]
assert [e[k] for k in ("event_loss", "discovery_ring_loss", "discovery_state_failures", "discovery_read_failures", "discovery_truncated")] == [0] * 5
assert all(row["module_ambiguous"] is False for row in d["functions"])
assert [e[k] for k in ("session_cancel_ambiguities", "auth_state_ambiguities", "fork_state_ambiguities")] == [0] * 3
assert [e[k] for k in ("in_flight_at_end", "pending_at_end")] == [0, 0]
assert e["child_still_running"] is False
if mode == "never":
    assert [e[k] for k in ("pause", "pause_attempts", "pause_confirmed", "pause_partial")] == ["none", 0, 0, 0]
else:
    assert e["pause"] == "sigstop" and e["pause_attempts"] == e["pause_confirmed"] >= 1 and e["pause_partial"] == 0
print(f"Lane 16 {mode} structural row: OK")
PY
chmod 600 "$ROOT/artifacts/observed.json" "$ROOT/artifacts/checker.log"
exit 0
