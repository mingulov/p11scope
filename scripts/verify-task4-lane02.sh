#!/bin/sh
# Task 4 Lane 02: six owned-run SoftHSM2 load-kind/pause rows.
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
PATH_FIXED=/usr/sbin:/usr/bin:/sbin:/bin
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
SELF_TESTING=
LAUNCHING=0
. scripts/lib.sh

usage() {
    echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT" >&2
    exit 2
}

prepare_evidence_root() {
    per_input=$1
    case $per_input in /*) ;; *) return 1 ;; esac
    case $per_input in *'/../'*|*/..|*"	"*|*"
"*) return 1 ;; esac
    per_parent=${per_input%/*}
    per_leaf=${per_input##*/}
    [ -n "$per_parent" ] && [ -n "$per_leaf" ] && [ -d "$per_parent" ] || return 1
    per_ancestor=$per_parent
    while [ "$per_ancestor" != / ]; do
        [ ! -L "$per_ancestor" ] || return 1
        per_ancestor=${per_ancestor%/*}
        [ -n "$per_ancestor" ] || per_ancestor=/
    done
    per_parent=$(cd "$per_parent" && pwd -P) || return 1
    [ "$per_input" = "$per_parent/$per_leaf" ] || return 1
    per_worktree=$(pwd -P)
    case $per_input in "$per_worktree"|"$per_worktree"/*) return 1 ;; esac
    python3 - "$per_parent" <<'PY' || return 1
import os, stat, sys
s = os.stat(sys.argv[1])
if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) & 0o077:
    raise SystemExit("evidence parent must be caller-owned and private")
PY
    [ ! -e "$per_input" ] && [ ! -L "$per_input" ] || return 1
    umask 077
    mkdir -m 700 "$per_input" || return 1
    ROOT=$per_input
    ROOT_ID=$(python3 - "$ROOT" <<'PY'
import os, stat, sys
s = os.lstat(sys.argv[1])
if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
    raise SystemExit("evidence root must be a caller-owned mode-0700 directory")
print(f"{s.st_dev}:{s.st_ino}")
PY
    ) || return 1
}

validate_root() {
    python3 - "$ROOT" "$ROOT_ID" <<'PY'
import os, stat, sys
s = os.lstat(sys.argv[1])
if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid()
        or stat.S_IMODE(s.st_mode) != 0o700
        or f"{s.st_dev}:{s.st_ino}" != sys.argv[2]):
    raise SystemExit("evidence root identity changed")
PY
}

validate_terminal_tree() {
    python3 - "$ROOT" <<'PY'
import os, stat, sys
root = sys.argv[1]
rows = {
    "01-initial-set-never", "02-initial-set-auto", "03-initial-set-always",
    "04-dlopen-never", "05-dlopen-auto", "06-dlopen-always",
}
required_dirs = {"bin", "rows", "tokens"} | {f"rows/{row}" for row in rows}
required_files = {
    "facts.log", "cargo-configs.tsv", "softhsm2.conf", "bin/p11scope",
    "bin/harness", "bin/harness-initial"
}
required_files |= {f"rows/{row}/observer.log" for row in rows}
required_files |= {f"rows/{row}/checker.log" for row in rows}
seen_dirs, seen_files = set(), set()
for directory, dirs, files in os.walk(root, followlinks=False):
    relative = os.path.relpath(directory, root)
    if relative != ".":
        seen_dirs.add(relative)
        if relative not in required_dirs and not relative.startswith("tokens/"):
            raise SystemExit(f"foreign terminal directory: {relative}")
    for name in dirs + files:
        path = os.path.join(directory, name)
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode) or stat.S_IMODE(mode) & 0o077:
            raise SystemExit(f"unsafe terminal artifact: {os.path.relpath(path, root)}")
    for name in files:
        path = os.path.join(directory, name)
        relative_file = os.path.relpath(path, root)
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise SystemExit(f"non-file terminal artifact: {relative_file}")
        if (relative_file not in required_files
                and not relative_file.startswith("tokens/")
                and not any(relative_file in {
                    f"rows/{row}/observed.json",
                } for row in rows)):
            raise SystemExit(f"foreign terminal file: {relative_file}")
        seen_files.add(relative_file)
if not required_dirs.issubset(seen_dirs) or not required_files.issubset(seen_files):
    raise SystemExit("terminal evidence tree is incomplete")
PY
}

digest() {
    digest_line=$(sha256sum "$1") || return 1
    digest_hash=${digest_line%% *}
    [ "${#digest_hash}" -eq 64 ] || return 1
    case $digest_hash in *[!0-9a-f]*) return 1 ;; esac
    printf '%s\n' "$digest_hash"
}

cargo_config_line() {
    ccl_path=$1
    if [ -e "$ccl_path" ] || [ -L "$ccl_path" ]; then
        [ -f "$ccl_path" ] && [ ! -L "$ccl_path" ] || return 1
        ccl_stat=$(stat -Lc %d:%i:%s:%u:%g:%a "$ccl_path") || return 1
        ccl_hash=$(digest "$ccl_path") || return 1
        printf '%s\t%s\t%s\n' "$ccl_path" "$ccl_stat" "$ccl_hash"
    fi
}

cargo_config_snapshot() {
    ccs_dir=$(pwd -P) || return 1
    ccs_start=$ccs_dir
    while :; do
        for ccs_path in "$ccs_dir/.cargo/config" "$ccs_dir/.cargo/config.toml"; do
            cargo_config_line "$ccs_path" || return 1
        done
        [ "$ccs_dir" != / ] || break
        ccs_dir=${ccs_dir%/*}
        [ -n "$ccs_dir" ] || ccs_dir=/
    done
    [ -n "${HOME-}" ] || return 1
    case $ccs_start in "$HOME"|"$HOME"/*) return 0 ;; esac
    for ccs_path in "$HOME/.cargo/config" "$HOME/.cargo/config.toml"; do
        cargo_config_line "$ccs_path" || return 1
    done
}

lane02_rows() {
    printf '%s\n' \
        '01-initial-set-never initial-set never' \
        '02-initial-set-auto initial-set auto' \
        '03-initial-set-always initial-set always' \
        '04-dlopen-never dlopen never' \
        '05-dlopen-auto dlopen auto' \
        '06-dlopen-always dlopen always'
}

observer_alive() {
    if [ -n "$SELF_TESTING" ]; then
        kill -0 "$WAIT_PID" 2>/dev/null
    else
        root_process_matches_starttime "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME"
    fi
}

count_byte_token() {
    python3 - "$1" "$2" <<'PY'
import sys
if len(sys.argv) != 3 or not sys.argv[2]:
    raise SystemExit("count_byte_token: expected path and non-empty token")
with open(sys.argv[1], "rb") as stream:
    print(stream.read().count(sys.argv[2].encode()))
PY
}

# The child can emit the marker after iteration N drained discovery but before
# N rendered. Two subsequent frames prove iteration N+1 drained after mapping.
wait_mapped_and_drained() {
    wmd_log=$1
    wmd_load_kind=$2
    wmd_attempt=0
    wmd_limit=${WAIT_ATTEMPTS:-240}
    wmd_delay=${WAIT_DELAY:-0.05}
    if [ "$wmd_load_kind" = initial-set ]; then
        wmd_expected=HARNESS_PROVIDER_INITIAL_SET
        wmd_rejected=HARNESS_PROVIDER_LATE_LOAD
    else
        wmd_expected=HARNESS_PROVIDER_LATE_LOAD
        wmd_rejected=HARNESS_PROVIDER_INITIAL_SET
    fi
    while :; do
        wmd_state=$(python3 - "$wmd_log" "$wmd_expected" "$wmd_rejected" <<'PY'
import sys
path, expected, rejected = sys.argv[1:]
marker = b"HARNESS_PROVIDER_MAPPED"
expected = expected.encode()
rejected = rejected.encode()
with open(sys.argv[1], "rb") as stream:
    snapshot = stream.read()
marker_count = snapshot.count(marker)
expected_count = snapshot.count(expected)
rejected_count = snapshot.count(rejected)
if marker_count > 1 or expected_count > 1 or rejected_count:
    print("invalid 0")
elif marker_count == 1 and expected_count == 1:
    offset = snapshot.index(marker) + len(marker)
    lines = snapshot[offset:].splitlines(keepends=True)
    frames = sum(line.endswith(b"\n") and b"p11scope" in line
                 and b"privacy=aggregate-only" in line for line in lines)
    print(("ready" if frames >= 2 else "pending"), frames)
else:
    print("pending 0")
PY
        ) || return 1
        wmd_status=${wmd_state%% *}
        wmd_frames=${wmd_state#* }
        case "$wmd_status" in
            ready)
                [ "$wmd_frames" -ge 2 ] || return 1
                return 0
                ;;
            pending)
                [ "$wmd_frames" -ge 0 ] || return 1
                ;;
            invalid) return 1 ;;
            *) return 1 ;;
        esac
        observer_alive || return 1
        [ "$wmd_attempt" -lt "$wmd_limit" ] || return 1
        wmd_attempt=$((wmd_attempt + 1))
        sleep "$wmd_delay"
    done
}

contained_refusal() {
    cr_policy=$1
    cr_status=$2
    cr_output_present=$3
    cr_log=$4
    [ "$cr_policy" = always ] && [ "$cr_status" -ne 0 ] \
        && [ "$cr_output_present" -eq 0 ] \
        && grep -Fq 'required pause protection could not be completed' "$cr_log" \
        && ! grep -Fq 'HARNESS_PROVIDER_' "$cr_log" \
        && ! grep -Fq 'harness OK' "$cr_log"
}

self_test() {
    SELF_TESTING=1
    expected='01-initial-set-never initial-set never
02-initial-set-auto initial-set auto
03-initial-set-always initial-set always
04-dlopen-never dlopen never
05-dlopen-auto dlopen auto
06-dlopen-always dlopen always'
    [ "$(lane02_rows)" = "$expected" ]
    [ "$(lane02_rows | awk '{print $2 "/" $3}' | sort -u | wc -l)" -eq 6 ]

    self_root=$(mktemp -d)
    trap 'find "$self_root" -depth -delete' EXIT INT TERM
    cat > "$self_root/provider.c" <<'C'
#include <string.h>
typedef unsigned long U;
struct table { unsigned char version[2], pad[6]; void *fn[68]; };
static struct table table;
static U generic(void *p) { (void)p; return 0; }
static U slots(unsigned char present, U *slot, U *count) {
    (void)present; if (slot) slot[0] = 1; *count = 1; return 0;
}
static U open_session(U slot, U flags, void *app, void *notify, U *session) {
    (void)slot; (void)flags; (void)app; (void)notify; *session = 1; return 0;
}
static U digest(U session, unsigned char *in, U in_len, unsigned char *out, U *out_len) {
    (void)session; (void)in; (void)in_len; memset(out, 0, *out_len); return 0;
}
static U random_bytes(U session, unsigned char *out, U out_len) {
    (void)session; memset(out, 0, out_len); return 0;
}
U C_GetFunctionList(void **out) {
    for (int i = 0; i < 68; i++) table.fn[i] = generic;
    table.version[0] = 2; table.version[1] = 40;
    table.fn[4] = slots; table.fn[12] = open_session;
    table.fn[38] = digest; table.fn[64] = random_bytes;
    *out = &table; return 0;
}
C
    gcc -std=c11 -O2 -Wall -Wextra -fPIC -shared -Wl,-z,defs \
        -Wl,-soname,provider.so \
        -o "$self_root/provider.so" "$self_root/provider.c"
    gcc -O0 -o "$self_root/harness" spike/harness.c -ldl
    gcc -O0 -Wl,--no-as-needed -Wl,-rpath,"$self_root" \
        -o "$self_root/harness-initial" spike/harness.c "$self_root/provider.so" -ldl
    INITIAL_DYNAMIC=$(readelf -d "$self_root/harness-initial") || exit 77
    [ "$(printf '%s\n' "$INITIAL_DYNAMIC" \
        | grep -Fc 'Shared library: [provider.so]')" -eq 1 ] || exit 77
    : > "$self_root/go"
    timeout 5 "$self_root/harness" "$self_root/provider.so" "$self_root/go" \
        > "$self_root/harness.log" 2>&1
    [ "$(grep -Fxc HARNESS_PROVIDER_MAPPED "$self_root/harness.log")" -eq 1 ]
    [ "$(grep -Fxc HARNESS_PROVIDER_LATE_LOAD "$self_root/harness.log")" -eq 1 ]
    timeout 5 "$self_root/harness-initial" "$self_root/provider.so" "$self_root/go" \
        > "$self_root/initial.log" 2>&1
    [ "$(grep -Fxc HARNESS_PROVIDER_INITIAL_SET "$self_root/initial.log")" -eq 1 ]
    marker_line=$(grep -n -F HARNESS_PROVIDER_MAPPED "$self_root/harness.log" | cut -d: -f1)
    ok_line=$(grep -n -F 'harness OK' "$self_root/harness.log" | cut -d: -f1)
    [ "$marker_line" -lt "$ok_line" ]

    WAIT_ATTEMPTS=60 WAIT_DELAY=0.01
    if count_byte_token "$self_root/missing.log" HARNESS_PROVIDER_MAPPED 2>/dev/null; then
        echo "missing marker log was treated as empty" >&2
        exit 1
    fi
    if count_byte_token "$self_root/harness.log" "" 2>/dev/null; then
        echo "empty marker token was accepted" >&2
        exit 1
    fi
    printf '%s\n' HARNESS_PROVIDER_LATE_LOAD HARNESS_PROVIDER_MAPPED \
        'p11scope — privacy=aggregate-only' \
        'p11scope — privacy=aggregate-only' \
        > "$self_root/presnapshot.log"
    WAIT_PID=$$
    wait_mapped_and_drained "$self_root/presnapshot.log" dlopen
    printf '%s\n' 'p11scope — provider diagnostic HARNESS_PROVIDER_LATE_LOAD ... HARNESS_PROVIDER_MAPPED' \
        > "$self_root/interleaved.log"
    (sleep 0.25; \
        printf '%s\n' 'p11scope — privacy=aggregate-only'; sleep 0.03; \
        printf '%s\n' 'p11scope — privacy=aggregate-only'; sleep 0.5) \
        >> "$self_root/interleaved.log" &
    WAIT_PID=$!
    wait_mapped_and_drained "$self_root/interleaved.log" dlopen
    wait "$WAIT_PID"
    printf '%s\n' HARNESS_PROVIDER_LATE_LOAD HARNESS_PROVIDER_MAPPED \
        'p11scope — privacy=aggregate-only' \
        > "$self_root/topology-race.log"
    (
        sleep 0.5
        printf '%s\n' HARNESS_PROVIDER_INITIAL_SET \
            'p11scope — privacy=aggregate-only' >> "$self_root/topology-race.log"
        sleep 0.3
    ) &
    WAIT_PID=$!
    if wait_mapped_and_drained "$self_root/topology-race.log" dlopen; then
        echo "rejected topology was accepted after a second frame" >&2
        exit 1
    fi
    wait "$WAIT_PID"
    WAIT_ATTEMPTS=20 WAIT_DELAY=0.01
    : > "$self_root/one.log"
    (printf '%s\n' HARNESS_PROVIDER_LATE_LOAD HARNESS_PROVIDER_MAPPED; sleep 0.03; \
        printf '%s\n' 'p11scope — privacy=aggregate-only'; sleep 0.3) \
        >> "$self_root/one.log" &
    WAIT_PID=$!
    if wait_mapped_and_drained "$self_root/one.log" dlopen; then
        echo "one post-marker frame was accepted" >&2
        exit 1
    fi
    wait "$WAIT_PID"
    : > "$self_root/two.log"
    (printf '%s\n' HARNESS_PROVIDER_LATE_LOAD HARNESS_PROVIDER_MAPPED; sleep 0.15; \
        printf '%s\n' 'p11scope — privacy=aggregate-only'; sleep 0.03; \
        printf '%s\n' 'p11scope — privacy=aggregate-only'; sleep 0.3) \
        >> "$self_root/two.log" &
    WAIT_PID=$!
    wait_mapped_and_drained "$self_root/two.log" dlopen
    wait "$WAIT_PID"
    : > "$self_root/initial.log"
    (printf '%s\n' HARNESS_PROVIDER_INITIAL_SET HARNESS_PROVIDER_MAPPED; sleep 0.15; \
        printf '%s\n' 'p11scope — privacy=aggregate-only'; sleep 0.03; \
        printf '%s\n' 'p11scope — privacy=aggregate-only'; sleep 0.3) \
        >> "$self_root/initial.log" &
    WAIT_PID=$!
    wait_mapped_and_drained "$self_root/initial.log" initial-set
    wait "$WAIT_PID"
    WAIT_PID=$$
    if wait_mapped_and_drained "$self_root/initial.log" dlopen; then
        echo "initial-set topology was accepted as dlopen" >&2
        exit 1
    fi
    : > "$self_root/duplicate.log"
    (printf '%s\n' HARNESS_PROVIDER_LATE_LOAD HARNESS_PROVIDER_MAPPED; sleep 0.03; \
        printf '%s\n' 'p11scope — privacy=aggregate-only privacy=aggregate-only'; sleep 0.3) \
        >> "$self_root/duplicate.log" &
    WAIT_PID=$!
    if wait_mapped_and_drained "$self_root/duplicate.log" dlopen; then
        echo "one frame with a duplicate privacy token was accepted" >&2
        exit 1
    fi
    wait "$WAIT_PID"
    : > "$self_root/unterminated.log"
    (printf '%s\n' HARNESS_PROVIDER_LATE_LOAD HARNESS_PROVIDER_MAPPED; sleep 0.03; \
        printf '%s\n' 'p11scope — privacy=aggregate-only'; sleep 0.03; \
        printf '%s' 'p11scope — privacy=aggregate-only'; sleep 0.3) \
        >> "$self_root/unterminated.log" &
    WAIT_PID=$!
    if wait_mapped_and_drained "$self_root/unterminated.log" dlopen; then
        echo "unterminated second frame was accepted" >&2
        exit 1
    fi
    wait "$WAIT_PID"
    mkdir -m 700 "$self_root/private-parent"
    ln -s "$self_root/private-parent" "$self_root/symlink-parent"
    if prepare_evidence_root "$self_root/symlink-parent/evidence"; then
        echo "symlinked evidence ancestor was accepted" >&2
        exit 1
    fi
    prepare_evidence_root "$self_root/private-parent/evidence"
    install -d -m 700 "$ROOT/bin" "$ROOT/rows" "$ROOT/tokens"
    : > "$ROOT/facts.log"
    : > "$ROOT/cargo-configs.tsv"
    : > "$ROOT/softhsm2.conf"
    : > "$ROOT/bin/p11scope"
    : > "$ROOT/bin/harness"
    : > "$ROOT/bin/harness-initial"
    lane02_rows | while read -r row_id _; do
        install -d -m 700 "$ROOT/rows/$row_id"
        : > "$ROOT/rows/$row_id/observer.log"
        : > "$ROOT/rows/$row_id/checker.log"
    done
    validate_terminal_tree
    mkdir -m 700 "$ROOT/foreign"
    if validate_terminal_tree 2>/dev/null; then
        echo "foreign terminal directory was accepted" >&2
        exit 1
    fi
    rmdir "$ROOT/foreign"
    ln -s "$ROOT/facts.log" "$ROOT/foreign-link"
    if validate_terminal_tree 2>/dev/null; then
        echo "terminal symlink was accepted" >&2
        exit 1
    fi
    unlink "$ROOT/foreign-link"
    if digest "$ROOT/missing" >/dev/null 2>&1; then
        echo "missing digest input was accepted" >&2
        exit 1
    fi
    set +e
    RUSTFLAGS=-Cdebuginfo=0 "$0" "$self_root/early-receipt" >/dev/null 2>"$self_root/early.err"
    early_status=$?
    set -e
    [ "$early_status" -eq 77 ]
    # 77 alone is ambiguous: the prerequisite loop above this refusal exits 77
    # too, so on a host missing softhsm2-util (say) the oracle would pass green
    # without the refusal ever being reached. Assert the refusal itself.
    grep -Fq "refusing inherited RUSTFLAGS" "$self_root/early.err"
    grep -Fq "$(printf 'terminal_status\t77')" "$self_root/early-receipt/facts.log"
    : > "$self_root/pid-target"
    ln -s "$self_root/pid-target" "$self_root/observer.pid"
    sudo() { [ "$1" != -n ] || shift; "$@"; }
    if launch_root_recorded_process "$self_root/observer.pid" \
        "$self_root/launch.log" /usr/bin/touch "$self_root/launched" 2>/dev/null; then
        echo "existing PID receipt was overwritten" >&2
        exit 1
    fi
    [ ! -e "$self_root/launched" ]
    printf '%s\n' 'run --pause always: required pause protection could not be completed' \
        > "$self_root/refusal.log"
    contained_refusal always 1 0 "$self_root/refusal.log"
    printf '%s\n' HARNESS_PROVIDER_LATE_LOAD >> "$self_root/refusal.log"
    if contained_refusal always 1 0 "$self_root/refusal.log"; then
        echo "post-map refusal was classified as contained" >&2
        exit 1
    fi
    python3 scripts/check-capture-evidence.py --self-test >/dev/null
    echo "verify-task4-lane02 self-test: OK"
}

[ "$#" -eq 1 ] || usage
if [ "$1" = --self-test ]; then
    self_test
    exit 0
fi

require_non_root_caller
[ -z "${SOFTHSM2_CONF-}" ] || {
    echo "refusing inherited SOFTHSM2_CONF" >&2
    exit 77
}
prepare_evidence_root "$1" || {
    echo "evidence root must be absent, canonical, caller-private, and outside the worktree" >&2
    exit 77
}

FACTS=$ROOT/facts.log
CONF=$ROOT/softhsm2.conf
CARGO_CONFIG_FACTS=$ROOT/cargo-configs.tsv
P11SCOPE=$ROOT/bin/p11scope
HARNESS=$ROOT/bin/harness
HARNESS_INITIAL=$ROOT/bin/harness-initial
RUN_FAILED=0
INVOCATIONS=0
FINALIZED=0
OWNED_RUN_STARTED=0
if ! : > "$FACTS"; then
    validate_root && rmdir -- "$ROOT" 2>/dev/null || true
    exit 1
fi

fact() {
    printf '%s\t%s\n' "$1" "$2" >> "$FACTS"
}

durable() {
    sync -f "$FACTS"
}

harness_absent() {
    sudo -n python3 - "$HARNESS" "$HARNESS_INITIAL" <<'PY'
import os, sys
wanted = {os.fsencode(path) for path in sys.argv[1:]}
for name in os.listdir('/proc'):
    if not name.isdigit():
        continue
    try:
        argv = open(f'/proc/{name}/cmdline', 'rb').read().split(b'\0')
        exe = os.path.realpath(f'/proc/{name}/exe')
    except OSError:
        continue
    if argv and argv[0] in wanted and os.fsencode(exe) == argv[0]:
        raise SystemExit(f"owned harness still running as pid {name}")
PY
}

terminate_owned_harness() {
    sudo -n python3 - "$HARNESS" "$HARNESS_INITIAL" <<'PY'
import os, select, signal, sys
wanted = {os.fsencode(path) for path in sys.argv[1:]}

def owned():
    result = []
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        try:
            fd = os.pidfd_open(int(name))
            argv = open(f'/proc/{name}/cmdline', 'rb').read().split(b'\0')
            exe = os.path.realpath(f'/proc/{name}/exe')
        except OSError:
            continue
        if argv and argv[0] in wanted and os.fsencode(exe) == argv[0]:
            result.append((int(name), fd))
    return result

targets = owned()
for pid, fd in targets:
    poller = select.poll(); poller.register(fd, select.POLLIN)
    try:
        signal.pidfd_send_signal(fd, signal.SIGTERM, None, 0)
    except ProcessLookupError:
        continue
    if not poller.poll(5000):
        signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        if not poller.poll(5000):
            raise SystemExit(f"owned harness {pid} did not exit")
if owned():
    raise SystemExit("owned harness remains after termination")
print(len(targets))
PY
}

wait_root_exit() {
    sudo -n python3 - "$1" "$2" "$3" <<'PY'
import os, select, sys
pid, expected, timeout = map(int, sys.argv[1:])
try:
    fd = os.pidfd_open(pid)
    raw = open(f"/proc/{pid}/stat", "rb").read().rsplit(b") ", 1)[1].split()
except (FileNotFoundError, ProcessLookupError):
    raise SystemExit(0)
if len(raw) < 20 or int(raw[19]) != expected:
    raise SystemExit("root observer identity changed")
poller = select.poll(); poller.register(fd, select.POLLIN)
if not poller.poll(timeout * 1000):
    raise SystemExit(1)
PY
}

stop_observer() {
    [ -n "$SPID" ] || return 0
    if root_process_matches_starttime "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME"; then
        signal_verified_root_process TERM "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME" || return 1
        if ! wait_root_exit "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME" 5; then
            signal_verified_root_process KILL "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME" || return 1
            wait_root_exit "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME" 5 || return 1
        fi
    else
        terminate_recording_launcher "$SPID" || return 1
        SPID=
        return 1
    fi
    wait "$SPID" 2>/dev/null || true
    SPID=
}

row_identity() {
    python3 - "$1" <<'PY'
import os, stat, sys
s = os.lstat(sys.argv[1])
if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
    raise SystemExit("row directory is not caller-owned mode 0700")
print(f"{s.st_dev}:{s.st_ino}")
PY
}

validate_row() {
    [ "$(row_identity "$1")" = "$2" ]
}

reclaim_verified_output() {
    sudo -n python3 - "$1" "$2" "$3" "$(id -u)" "$(id -g)" <<'PY'
import os, stat, sys
directory, identity, name, uid, gid = sys.argv[1:]
fd_dir = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
s = os.fstat(fd_dir)
if f"{s.st_dev}:{s.st_ino}" != identity:
    raise SystemExit("row directory identity changed")
fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd_dir)
s = os.fstat(fd)
if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) & 0o077:
    raise SystemExit("observer output is not a private root-owned regular file")
os.fchown(fd, int(uid), int(gid))
PY
}

remove_verified_pidfile() {
    sudo -n python3 - "$1" "$2" "$3" <<'PY'
import os, sys
directory, identity, name = sys.argv[1:]
fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
s = os.fstat(fd)
if f"{s.st_dev}:{s.st_ino}" != identity:
    raise SystemExit("row directory identity changed")
try:
    os.unlink(name, dir_fd=fd)
except FileNotFoundError:
    pass
PY
}

no_atomic_temps() {
    sudo -n python3 - "$1" "$2" <<'PY'
import os, sys
directory, identity = sys.argv[1:]
fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
s = os.fstat(fd)
if f"{s.st_dev}:{s.st_ino}" != identity:
    raise SystemExit("row directory identity changed")
if any(name.startswith('.p11scope.') and name.endswith('.tmp') for name in os.listdir(fd)):
    raise SystemExit("row retained an atomic temporary file")
PY
}

cleanup() {
    cleanup_status=$?
    trap - EXIT INT TERM
    set +e
    if [ -z "$SPID" ] && [ "$LAUNCHING" -eq 1 ] \
        && [ -n "${ROOT_LAUNCH_PID-}" ]; then
        SPID=$ROOT_LAUNCH_PID
        if [ -n "${ROOT_PROCESS_PID-}" ] && [ -n "${ROOT_PROCESS_STARTTIME-}" ]; then
            SUPERVISOR_PID=$ROOT_PROCESS_PID
            SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
        else
            terminate_recording_launcher "$SPID" || cleanup_status=1
            SPID=
        fi
    fi
    if [ -n "$SPID" ]; then
        if ! stop_observer; then
            cleanup_status=1
            [ -z "$SPID" ] || stop_observer || cleanup_status=1
        fi
    fi
    if [ "$OWNED_RUN_STARTED" -eq 1 ]; then
        terminate_owned_harness >/dev/null || cleanup_status=1
    fi
    if [ "$FINALIZED" -eq 0 ] && [ -n "${FACTS-}" ] && [ -f "$FACTS" ] \
        && validate_root; then
        fact terminal_status "$cleanup_status" || cleanup_status=1
        fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || cleanup_status=1
        durable || cleanup_status=1
    fi
    exit "$cleanup_status"
}
. scripts/cleanup-traps.sh
fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Environment hygiene first: it needs no tools, and both loops exit 77, so a host
# missing a prerequisite would otherwise mask this refusal behind the same code.
for variable in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET \
    CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC_WRAPPER CC CFLAGS; do
    eval "variable_value=\${$variable-}"
    [ -z "$variable_value" ] || { echo "refusing inherited $variable" >&2; exit 77; }
done
for command in cargo rustc gcc ldd softhsm2-util sudo sha256sum readelf sync; do
    command -v "$command" >/dev/null || { echo "$command required" >&2; exit 77; }
done
cargo +1.88 --version >/dev/null || exit 77
rustc +1.88 --version >/dev/null || exit 77
gcc --version >/dev/null || exit 77
softhsm2-util --version >/dev/null || exit 77
sudo -n true || { echo "passwordless sudo required" >&2; exit 77; }
[ -f "$MODULE" ] && [ ! -L "$MODULE" ] || {
    echo "SoftHSM2 not installed at $MODULE" >&2
    exit 77
}
TRACKED_STATUS=$(git status --porcelain=v1 --untracked-files=no) || exit 77
[ -z "$TRACKED_STATUS" ] || {
    echo "tracked worktree must be clean" >&2
    exit 77
}
for source in scripts/verify-task4-lane02.sh scripts/check-capture-evidence.py \
    scripts/lib.sh scripts/cleanup-traps.sh spike/harness.c spike/expected.txt; do
    git ls-files --error-unmatch -- "$source" >/dev/null || exit 77
done
cargo_config_snapshot > "$CARGO_CONFIG_FACTS" || exit 77
CARGO_CONFIG_HASH=$(digest "$CARGO_CONFIG_FACTS")

install -d -m 700 "$ROOT/bin" "$ROOT/rows" "$ROOT/tokens"
HEAD_ID=$(git rev-parse HEAD) || exit 1
TREE_ID=$(git rev-parse 'HEAD^{tree}') || exit 1
fact head "$HEAD_ID"
fact tree "$TREE_ID"
fact cargo_configs_sha256 "$CARGO_CONFIG_HASH"
fact uid_gid "$(id -u):$(id -g)"
fact kernel "$(uname -srmo)"
MODULE_REALPATH=$(realpath -e "$MODULE")
MODULE_STAT=$(stat -Lc %d:%i:%s:%u:%g:%a "$MODULE")
fact module_realpath "$MODULE_REALPATH"
fact module_stat "$MODULE_STAT"
MODULE_HASH=$(digest "$MODULE")
MODULE_NOTES=$(readelf -n "$MODULE") || exit 77
MODULE_BUILD_ID=$(printf '%s\n' "$MODULE_NOTES" \
    | awk '/Build ID:/{print $3; exit}') || exit 77
DRIVER_HASH=$(digest scripts/verify-task4-lane02.sh)
CHECKER_HASH=$(digest scripts/check-capture-evidence.py)
LIB_HASH=$(digest scripts/lib.sh)
CLEANUP_HASH=$(digest scripts/cleanup-traps.sh)
HARNESS_SOURCE_HASH=$(digest spike/harness.c)
EXPECTED_HASH=$(digest spike/expected.txt)
fact module_sha256 "$MODULE_HASH"
fact module_build_id "${MODULE_BUILD_ID:-absent}"
fact driver_sha256 "$DRIVER_HASH"
fact checker_sha256 "$CHECKER_HASH"
fact lib_sha256 "$LIB_HASH"
fact cleanup_traps_sha256 "$CLEANUP_HASH"
fact harness_source_sha256 "$HARNESS_SOURCE_HASH"
fact expected_sha256 "$EXPECTED_HASH"
fact cargo_version "$(cargo +1.88 --version)"
fact rustc_version "$(rustc +1.88 --version)"
fact gcc_version "$(gcc -dumpfullversion -dumpversion)"
fact softhsm_version "$(softhsm2-util --version)"
durable

install -d -m 700 "$ROOT/build"
cargo +1.88 build --locked --release --workspace --target-dir "$ROOT/build" || exit 1
install -m 700 "$ROOT/build/release/p11scope" "$P11SCOPE"
gcc -O0 -o "$HARNESS" spike/harness.c -ldl || exit 1
MODULE_DIR=${MODULE%/*}
gcc -O0 -Wl,--no-as-needed -Wl,-rpath,"$MODULE_DIR" \
    -o "$HARNESS_INITIAL" spike/harness.c "$MODULE" -ldl || exit 1
INITIAL_DYNAMIC=$(readelf -d "$HARNESS_INITIAL") || exit 77
[ "$(printf '%s\n' "$INITIAL_DYNAMIC" \
    | grep -Fc 'Shared library: [libsofthsm2.so]')" -eq 1 ] || exit 77
HARNESS_INITIAL_LDD=$(ldd "$HARNESS_INITIAL") || exit 77
INITIAL_MODULE_RESOLVED=$(printf '%s\n' "$HARNESS_INITIAL_LDD" \
    | awk '$1=="libsofthsm2.so"{print $3; exit}') || exit 77
[ -n "$INITIAL_MODULE_RESOLVED" ] || exit 77
[ "$(realpath -e "$INITIAL_MODULE_RESOLVED")" = "$MODULE_REALPATH" ] || exit 77
P11SCOPE_HASH=$(digest "$P11SCOPE")
HARNESS_HASH=$(digest "$HARNESS")
HARNESS_INITIAL_HASH=$(digest "$HARNESS_INITIAL")
P11SCOPE_PROGRAM_HEADERS=$(readelf -l "$P11SCOPE") || exit 77
INTERPRETER=$(printf '%s\n' "$P11SCOPE_PROGRAM_HEADERS" \
    | awk -F': ' '/Requesting program interpreter/{gsub(/[][]/, "", $2); print $2; exit}') || exit 77
[ -n "$INTERPRETER" ] || exit 77
INTERPRETER_REALPATH=$(realpath -e "$INTERPRETER") || exit 77
INTERPRETER_HASH=$(digest "$INTERPRETER_REALPATH")
HARNESS_LDD=$(ldd "$HARNESS") || exit 77
LIBC=$(printf '%s\n' "$HARNESS_LDD" \
    | awk '$1=="libc.so.6"{print $3; exit}') || exit 77
[ -n "$LIBC" ] || exit 77
LIBC_REALPATH=$(realpath -e "$LIBC") || exit 77
LIBC_HASH=$(digest "$LIBC_REALPATH")
fact p11scope_sha256 "$P11SCOPE_HASH"
fact harness_sha256 "$HARNESS_HASH"
fact harness_initial_sha256 "$HARNESS_INITIAL_HASH"
fact interpreter_realpath "$INTERPRETER_REALPATH"
fact interpreter_sha256 "$INTERPRETER_HASH"
fact libc_realpath "$LIBC_REALPATH"
fact libc_sha256 "$LIBC_HASH"

cat > "$CONF" <<EOF
directories.tokendir = $ROOT/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
SOFTHSM2_CONF=$CONF softhsm2-util --init-token --free --label task4-lane02 \
    --so-pin 1234 --pin 1234 >/dev/null || exit 1
CONFIG_HASH=$(digest "$CONF")
fact config_sha256 "$CONFIG_HASH"
durable

run_row() {
    row_id=$1
    load_kind=$2
    policy=$3
    row=$ROOT/rows/$row_id
    output=$row/observed.json
    log=$row/observer.log
    pidfile=$row/observer.pid
    checker_log=$row/checker.log
    go=$row/go
    validate_root || return 1
    install -d -m 700 "$row"
    row_id_dev_ino=$(row_identity "$row") || return 1
    for path in "$output" "$log" "$pidfile" "$checker_log" "$go"; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
    done
    fact "$row_id.begin_utc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    fact "$row_id.load_kind" "$load_kind"
    fact "$row_id.pause" "$policy"

    set -- /usr/bin/env -i "PATH=$PATH_FIXED" "SOFTHSM2_CONF=$CONF" \
        "SUDO_UID=$(id -u)" "SUDO_GID=$(id -g)" \
        "$P11SCOPE" run --module "$MODULE" --mode metrics --duration 30 \
        --kill-on-timeout --pause "$policy" -o "$output" --
    if [ "$load_kind" = initial-set ]; then
        set -- "$@" "$HARNESS_INITIAL" "$MODULE" "$go"
    else
        set -- "$@" "$HARNESS" "$MODULE" "$go"
    fi
    argv_index=0
    for argument do
        fact "$row_id.argv.$argv_index" "$argument"
        argv_index=$((argv_index + 1))
    done
    durable

    OWNED_RUN_STARTED=1
    ROOT_LAUNCH_PID=
    ROOT_PROCESS_PID=
    ROOT_PROCESS_STARTTIME=
    LAUNCHING=1
    if ! launch_root_recorded_process "$pidfile" "$log" "$@"; then
        if [ -n "${ROOT_LAUNCH_PID-}" ]; then
            return 1
        fi
        LAUNCHING=0
        [ "$INVOCATIONS" -ne 0 ] || return 77
        return 1
    fi
    LAUNCHING=0
    SPID=$ROOT_LAUNCH_PID
    SUPERVISOR_PID=$ROOT_PROCESS_PID
    SUPERVISOR_STARTTIME=$ROOT_PROCESS_STARTTIME
    INVOCATIONS=$((INVOCATIONS + 1))
    fact "$row_id.observer" "$SUPERVISOR_PID:$SUPERVISOR_STARTTIME"
    if wait_mapped_and_drained "$log" "$load_kind"; then
        ready_status=0
        : > "$go"
    else
        ready_status=1
    fi
    if ! wait_root_exit "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME" 40; then
        fact "$row_id.observer_timeout" 1
        stop_observer || return 1
        terminate_owned_harness >/dev/null || return 1
        return 1
    fi
    if wait "$SPID"; then observer_status=0; else observer_status=$?; fi
    SPID=
    fact "$row_id.ready" "$ready_status"
    fact "$row_id.exit" "$observer_status"

    validate_root || return 1
    validate_row "$row" "$row_id_dev_ino" || return 1
    root_process_matches_starttime "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME" \
        && { echo "$row_id observer remains live" >&2; return 1; }
    killed_harnesses=$(terminate_owned_harness) || return 1
    [ "$killed_harnesses" -eq 0 ] || {
        echo "$row_id left an owned harness after observer exit" >&2
        return 1
    }
    remove_verified_pidfile "$row" "$row_id_dev_ino" observer.pid || return 1
    rm -f -- "$go"
    harness_absent || return 1
    no_atomic_temps "$row" "$row_id_dev_ino" || return 1
    output_present=0
    if sudo -n test -e "$output"; then
        reclaim_verified_output "$row" "$row_id_dev_ino" observed.json || return 1
        output_present=1
    fi

    row_result=FAIL
    : > "$checker_log"
    if [ "$ready_status" -eq 0 ] && [ "$observer_status" -eq 0 ] \
        && [ "$output_present" -eq 1 ]; then
        set +e
        python3 scripts/check-capture-evidence.py lane02-owned-run-metrics \
            "$output" spike/expected.txt "$policy" \
            > "$checker_log" 2>&1
        checker_status=$?
        set -e
        [ "$checker_status" -ne 0 ] || row_result=PASS
    elif contained_refusal "$policy" "$observer_status" "$output_present" "$log"; then
        checker_status=1
        row_result=NON-PASS_CONTAINED_REFUSAL
    else
        checker_status=1
    fi
    fact "$row_id.checker_exit" "$checker_status"
    fact "$row_id.result" "$row_result"
    fact "$row_id.end_utc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [ -e "$output" ]; then
        output_hash=$(digest "$output") || return 1
        fact "$row_id.output_sha256" "$output_hash"
    fi
    durable
    [ "$row_result" = PASS ] || RUN_FAILED=1
}

run_row 01-initial-set-never initial-set never
run_row 02-initial-set-auto initial-set auto
run_row 03-initial-set-always initial-set always
run_row 04-dlopen-never dlopen never
run_row 05-dlopen-auto dlopen auto
run_row 06-dlopen-always dlopen always

[ "$INVOCATIONS" -eq 6 ] || {
    fact invocation_count "$INVOCATIONS"
    durable
    exit 1
}
[ "$(git rev-parse HEAD)" = "$(awk -F '\t' '$1=="head"{print $2}' "$FACTS")" ] || exit 1
[ "$(git rev-parse 'HEAD^{tree}')" = "$(awk -F '\t' '$1=="tree"{print $2}' "$FACTS")" ] || exit 1
TRACKED_STATUS=$(git status --porcelain=v1 --untracked-files=no) || exit 1
[ -z "$TRACKED_STATUS" ] || exit 1
[ "$(digest scripts/verify-task4-lane02.sh)" = "$DRIVER_HASH" ] || exit 1
[ "$(digest scripts/check-capture-evidence.py)" = "$CHECKER_HASH" ] || exit 1
[ "$(digest scripts/lib.sh)" = "$LIB_HASH" ] || exit 1
[ "$(digest scripts/cleanup-traps.sh)" = "$CLEANUP_HASH" ] || exit 1
[ "$(digest spike/harness.c)" = "$HARNESS_SOURCE_HASH" ] || exit 1
[ "$(digest spike/expected.txt)" = "$EXPECTED_HASH" ] || exit 1
[ "$(realpath -e "$MODULE")" = "$MODULE_REALPATH" ] || exit 1
[ "$(stat -Lc %d:%i:%s:%u:%g:%a "$MODULE")" = "$MODULE_STAT" ] || exit 1
[ "$(digest "$MODULE")" = "$MODULE_HASH" ] || exit 1
[ "$(digest "$P11SCOPE")" = "$P11SCOPE_HASH" ] || exit 1
[ "$(digest "$HARNESS")" = "$HARNESS_HASH" ] || exit 1
[ "$(digest "$HARNESS_INITIAL")" = "$HARNESS_INITIAL_HASH" ] || exit 1
[ "$(digest "$CONF")" = "$CONFIG_HASH" ] || exit 1
CARGO_CONFIG_NOW=$(cargo_config_snapshot) || exit 1
CARGO_CONFIG_THEN=$(cat "$CARGO_CONFIG_FACTS") || exit 1
[ "$CARGO_CONFIG_NOW" = "$CARGO_CONFIG_THEN" ] || exit 1
[ "$(digest "$CARGO_CONFIG_FACTS")" = "$CARGO_CONFIG_HASH" ] || exit 1
[ "$(realpath -e "$INTERPRETER")" = "$INTERPRETER_REALPATH" ] || exit 1
[ "$(digest "$INTERPRETER_REALPATH")" = "$INTERPRETER_HASH" ] || exit 1
[ "$(realpath -e "$LIBC")" = "$LIBC_REALPATH" ] || exit 1
[ "$(digest "$LIBC_REALPATH")" = "$LIBC_HASH" ] || exit 1
find "$ROOT/build" -depth -delete
validate_root
validate_terminal_tree
fact invocation_count "$INVOCATIONS"
fact terminal_status "$RUN_FAILED"
fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
durable
FINALIZED=1
exit "$RUN_FAILED"
