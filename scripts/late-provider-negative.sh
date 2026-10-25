#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Cell N4: node-wide never-seen late provider stays UNSUPPORTED (dev host
# primary, fedora optional repeat; no kind, host observer, initial PID namespace).
#
# Owned container O runs its ledger inside one `inventory --system --duration`
# capture (healthy twin in the same JSON); at T+20s container L starts with a
# never-scanned provider file (holder `ledger-private`: a fresh 0700 copy no
# earlier capture could contain) and runs its ledger to completion inside the
# window. The oracle requires O exact and gap-free and L scanned AND reported
# (edge with a named pre-attach gap, or no edge with a named gap); silently
# zero FAILs. Passing N4 keeps the NON-PASS/UNSUPPORTED verdict (G33): the
# boundary is REPORTED, never turned positive.
#
# The CONTROLLER runs every docker/dockerd/sudo command below. Workers only run
# `sh $0 --self-test`, which is unprivileged (PATH stubs) and proves the arg
# refusals, the pins, the cleanup trap and the oracle mutations.
set -eu
cd "$(dirname "$0")/.."

ORACLE=scripts/container-cells-oracle.py
HOLDER_DOCKERFILE=deploy/Dockerfile.holder
# Pinned base reused from deploy/Dockerfile.holder (both FROM lines); the
# self-test requires the Dockerfile to carry exactly this digest twice.
HOLDER_BASE=ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e
PROVIDER_PATH=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
# Fresh provider path inside the late container (holder `ledger-private`
# copies the provider into a 0700 directory at startup).
LATE_MODULE=/tmp/private/libsofthsm2.so
ITERS_O_DEFAULT=400
ITERS_L_DEFAULT=250
DURATION_DEFAULT=60
LATE_DELAY_DEFAULT=20

usage() {
    cat >&2 <<'EOF'
usage: scripts/late-provider-negative.sh --host dev|fedora-private --observer BIN [options]
       scripts/late-provider-negative.sh --self-test | --help

  Cell N4 driver. One `inventory --system --duration` capture on the host
  while owned container O ledgers; container L (never-seen provider path)
  starts mid-capture and ledgers inside the window. Checks n4.json with
  scripts/container-cells-oracle.py late-reported.

  --host dev            use the local docker daemon (dev host)
  --host fedora-private run ON fedora as user against a task-owned private
                        dockerd (own data-root/exec-root/pidfile/socket under
                        --task-root, --bridge=none --iptables=false)
  --observer BIN        host release p11scope binary (run through sudo -n)
  --image NAME          holder image (default p11scope-ctr-shared:$TOKEN);
                        when present it is shared with the D1 build and kept
                        (noted in facts.log); when missing on dev it is built
                        from deploy/Dockerfile.holder and removed after
  --token TOKEN         run token, short [a-z0-9-] (default <time>-<pid>)
  --iters-o N           ledger iterations for O (default 400)
  --iters-l N           ledger iterations for L (default 250)
  --duration S          inventory capture seconds (default 60)
  --late-delay S        seconds after capture start to start L (default 20;
                        must be less than --duration)
  --task-root DIR       fedora-private only: existing task root directory
  --bundle-dir DIR      fedora-private only: bundle from the D1 --bundle mode
  --work DIR            evidence directory (must not exist; default fresh 0700
                        under $TMPDIR)
  --keep                keep containers (and an owned image) for debugging
                        (prints the delete commands); the private daemon
                        always stops
  --self-test           unprivileged checks (PATH stubs, no docker)
  --help                this text

Capture flags (confirmed against `inventory --help`, src/cli.rs): the capture
is `inventory --system --duration S --caller-metadata none -o n4.json`
(src/cli.rs usage lines for --system carry --duration and --identity-backend;
N4 leaves --identity-backend at its default auto).

Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 UNRUN (cell not run, see SUMMARY reason).
Every run prints a final SUMMARY line: SUMMARY cell=N4 host=... verdict=... reason="...".

CONTROLLER (run order, after R-D1):
  # N4 on the dev host (from the repo root; BIN = host release binary):
  sh scripts/late-provider-negative.sh --host dev --observer BIN --image p11scope-ctr-shared:<D1-TOKEN> --token <TOKEN>
  # N4 on fedora (optional; needs the D1 bundle plus this driver there):
  scp scripts/late-provider-negative.sh scripts/container-cells-oracle.py scripts/lib.sh scripts/cleanup-traps.sh fedora:/home/user/p11scope-ctr-<TOKEN>/scripts/
  ssh fedora sh /home/user/p11scope-ctr-<TOKEN>/scripts/late-provider-negative.sh --host fedora-private --task-root /home/user/p11scope-ctr-<TOKEN> --bundle-dir /home/user/p11scope-ctr-<TOKEN>/bundle --observer /home/user/p11scope-ctr-<TOKEN>/p11scope --token <TOKEN>
EOF
    exit 2
}

valid_token() {
    case $1 in
        ''|*[!a-z0-9-]*|-*|*-) return 1 ;;
        *) [ "${#1}" -le 40 ] ;;
    esac
}

valid_count() {
    case $1 in
        ''|*[!0-9]*|0*) return 1 ;;
        *) [ "${#1}" -le 7 ] ;;
    esac
}

self_test() {
    [ "$#" -eq 0 ] || usage
    command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
    [ "$(grep -c "FROM $HOLDER_BASE" "$HOLDER_DOCKERFILE")" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; exit 1; }
    [ "$ITERS_O_DEFAULT" -eq 400 ] && [ "$ITERS_L_DEFAULT" -eq 250 ] \
        && [ "$DURATION_DEFAULT" -eq 60 ] && [ "$LATE_DELAY_DEFAULT" -eq 20 ] \
        || { echo "N4 defaults drifted" >&2; exit 1; }
    [ "$LATE_MODULE" = "/tmp/private/libsofthsm2.so" ] \
        || { echo "late module path drifted" >&2; exit 1; }
    # Capture flags this cell runs, against the product help text.
    grep -q 'p11scope inventory --system .*\[--duration' src/cli.rs \
        || { echo "inventory --system --duration left src/cli.rs" >&2; exit 1; }
    grep -q '\[--identity-backend auto|userspace|kernel\]' src/cli.rs \
        || { echo "inventory --identity-backend left src/cli.rs" >&2; exit 1; }
    for bad in "" "--host" "--host bogus" "--host dev" \
               "--host dev --observer" "--host dev --observer /nonexistent" \
               "--host dev --observer /bin/true --token UPPER" \
               "--host dev --observer /bin/true --token -x" \
               "--host dev --observer /bin/true --iters-o 0" \
               "--host dev --observer /bin/true --iters-l 01" \
               "--host dev --observer /bin/true --duration 60 --late-delay 60" \
               "--host dev --observer /bin/true --duration 60 --late-delay 61" \
               "--host dev --observer /bin/true --late-delay x" \
               "--host fedora-private --observer /bin/true" \
               "--host fedora-private --observer /bin/true --task-root /tmp" \
               "--bogus" "--keep --bogus"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || {
            echo "n4 driver exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    n4_help_self_test
    n4_stub_self_test
    python3 -I "$ORACLE" --self-test
    echo "late-provider-negative self-test: OK"
    exit 0
}

n4_help_self_test() {
    help=$(sh "$0" --help 2>&1 || true)
    for marker in "--host dev --observer BIN" "--host fedora-private --task-root" \
                  "inventory --system --duration" "--identity-backend" \
                  "SUMMARY cell=N4" "p11scope-ctr-shared:<D1-TOKEN>"; do
        case $help in
            *"$marker"*) ;;
            *) echo "help lost its controller line: $marker" >&2; exit 1 ;;
        esac
    done
}

n4_stub_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-n4-stub-XXXXXX")
    # shellcheck disable=SC2064
    trap "rm -rf '$stub'" EXIT
    cat > "$stub/sudo" <<'EOF'
#!/bin/sh
[ "${1-}" = "-n" ] && shift
exec "$@"
EOF
    cat > "$stub/echo-sudo" <<'EOF'
#!/bin/sh
printf 'SUDO'
printf ' %s' "$@"
printf '\n'
EOF
    chmod +x "$stub/sudo" "$stub/echo-sudo"
    # The private dockerd command carries its own roots and no network.
    argv=$(TASK_ROOT=$stub/task dockerd_argv)
    for pin in "--data-root $stub/task/docker-data" \
               "--exec-root $stub/task/docker-exec" \
               "--pidfile $stub/task/dockerd.pid" \
               "unix://$stub/task/docker.sock" \
               "--bridge=none" "--iptables=false"; do
        case $argv in
            *"$pin"*) ;;
            *) echo "dockerd argv lost its pin: $pin" >&2; exit 1 ;;
        esac
    done
    # The observer always runs through `sudo -n`, args verbatim.
    mkdir -p "$stub/echobin"
    cp "$stub/echo-sudo" "$stub/echobin/sudo"
    chmod +x "$stub/echobin/sudo"
    got=$(OBSERVER=/nonexistent/p11scope PATH="$stub/echobin:$stub" obs inventory --system)
    case $got in
        "SUDO -n /nonexistent/p11scope inventory --system") ;;
        *) echo "observer command lost sudo -n: $got" >&2; exit 1 ;;
    esac
    # N4 records the storage driver without gating on it (the late-provider
    # boundary is not overlay-specific).
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
if [ "$1" = "info" ]; then printf '%s\n' "$STUB_DRIVER"; exit 0; fi
echo "unexpected docker call: $*" >&2; exit 1
EOF
    chmod +x "$stub/docker"
    : > "$stub/facts.log"
    STUB_DRIVER=btrfs PRIVATE=0 PATH="$stub:$PATH" FACTS=$stub/facts.log record_docker_facts \
        || { echo "non-overlay driver refused" >&2; exit 1; }
    grep -q "driver=btrfs" "$stub/facts.log" \
        || { echo "driver not recorded" >&2; exit 1; }
    # LEDGER lines: exactly one complete JSON ledger with 6xN successes.
    printf '%s\n' "READY pid=1" \
        'LEDGER {"schema":"p11scope/public-cli-ledger/v1","pid":1,"complete":true,"functions":[{"name":"C_GenerateRandom","attempts":250,"successful":250},{"name":"C_DigestInit","attempts":250,"successful":250},{"name":"C_Digest","attempts":250,"successful":250},{"name":"C_FindObjectsInit","attempts":250,"successful":250},{"name":"C_FindObjects","attempts":250,"successful":250},{"name":"C_FindObjectsFinal","attempts":250,"successful":250}]}' \
        > "$stub/good.log"
    PATH="$stub:$PATH" ledger_is "$stub/good.log" 250 \
        || { echo "good LEDGER refused" >&2; exit 1; }
    printf '%s\n' "READY pid=1" > "$stub/missing.log"
    if PATH="$stub:$PATH" ledger_is "$stub/missing.log" 250 >/dev/null 2>&1; then
        echo "missing LEDGER accepted" >&2
        exit 1
    fi
    # Bundle verification: the sha256 list gates the tarball.
    printf 'fake-tarball-bytes' > "$stub/image.tar"
    printf 'img:t\n' > "$stub/image-name.txt"
    (cd "$stub" && sha256sum image.tar > sha256sum.txt)
    (cd "$stub" && verify_bundle .) \
        || { echo "good bundle refused" >&2; exit 1; }
    printf 'x' >> "$stub/image.tar"
    if (cd "$stub" && verify_bundle .) >/dev/null 2>&1; then
        echo "corrupt bundle accepted" >&2
        exit 1
    fi
    # Existing names are refused before anything is created or deleted.
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
if [ "$1" = "ps" ]; then printf '%s\n' "$STUB_NAMES"; exit 0; fi
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
    [ "$STUB_IMAGE_PRESENT" = 1 ] && exit 0 || exit 1
fi
echo "unexpected docker call: $*" >&2; exit 1
EOF
    chmod +x "$stub/docker"
    if STUB_NAMES="n4-o-t" PATH="$stub:$PATH" assert_name_free n4-o-t >/dev/null 2>&1; then
        echo "existing container name accepted" >&2
        exit 1
    fi
    STUB_NAMES="" PATH="$stub:$PATH" assert_name_free n4-o-t \
        || { echo "free container name refused" >&2; exit 1; }
    STUB_IMAGE_PRESENT=1 PATH="$stub:$PATH" image_present img:t \
        || { echo "present image missed" >&2; exit 1; }
    if STUB_IMAGE_PRESENT=0 PATH="$stub:$PATH" image_present img:t >/dev/null 2>&1; then
        echo "missing image claimed present" >&2
        exit 1
    fi
    # Cleanup trap: its own containers always; a shared D1 image is kept.
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "docker $*" >> "$STUB_CALLS"
EOF
    chmod +x "$stub/docker"
    : > "$stub/calls-own.txt"
    STUB_CALLS=$stub/calls-own.txt PRIVATE=0 PATH="$stub:$PATH" \
        N4_O=n4-o-t N4_L=n4-l-t N4_IMAGE=img:t IMAGE_SHARED=0 cleanup_owned \
        || { echo "cleanup_owned failed" >&2; exit 1; }
    grep -q "docker rm -f n4-o-t n4-l-t" "$stub/calls-own.txt" \
        || { echo "cleanup lost its container removal" >&2; exit 1; }
    grep -q "docker image rm -f img:t" "$stub/calls-own.txt" \
        || { echo "cleanup lost its owned image removal" >&2; exit 1; }
    : > "$stub/calls-shared.txt"
    STUB_CALLS=$stub/calls-shared.txt PRIVATE=0 PATH="$stub:$PATH" \
        N4_O=n4-o-t N4_L=n4-l-t N4_IMAGE=img:t IMAGE_SHARED=1 cleanup_owned \
        || { echo "cleanup_owned failed" >&2; exit 1; }
    grep -q "docker rm -f n4-o-t n4-l-t" "$stub/calls-shared.txt" \
        || { echo "cleanup lost its container removal" >&2; exit 1; }
    if grep -q "docker image rm" "$stub/calls-shared.txt"; then
        echo "cleanup removed a shared image" >&2
        exit 1
    fi
    # Private-daemon stop: the daemon dies and its state is removed.
    mkdir -p "$stub/task/docker-data" "$stub/task/docker-exec"
    sleep 60 &
    sleeper=$!
    printf '%s' "$sleeper" > "$stub/task/dockerd.pid"
    : > "$stub/task/docker.sock"
    PATH="$stub:$PATH" TASK_ROOT=$stub/task stop_private_daemon \
        || { echo "stop_private_daemon failed" >&2; kill "$sleeper" 2>/dev/null || true; exit 1; }
    if kill -0 "$sleeper" 2>/dev/null; then
        echo "private daemon survived its stop" >&2
        kill "$sleeper" 2>/dev/null || true
        exit 1
    fi
    for gone in docker-data docker-exec docker.sock dockerd.pid; do
        [ ! -e "$stub/task/$gone" ] || { echo "daemon state survived: $gone" >&2; exit 1; }
    done
    # Mid-capture proof: L must start strictly after the capture did.
    start=$(date -u -d '2026-10-25T12:00:00Z' +%s)
    l_started_after "$start" "2026-10-25T12:00:20.123456789Z" \
        || { echo "mid-capture start refused" >&2; exit 1; }
    if l_started_after "$start" "2026-10-25T11:59:59Z" >/dev/null 2>&1; then
        echo "pre-capture L start accepted" >&2
        exit 1
    fi
    if l_started_after "$start" "not-a-date" >/dev/null 2>&1; then
        echo "garbage L start accepted" >&2
        exit 1
    fi
    # Inventory readiness: pass 0's summary line, never the profile-only
    # capture line or a progress line.
    WORK=$stub
    printf '%s\n' 'p11scope: sweeping 440 process maps (cap 256)...' \
        'p11scope: pass 0: 256 scanned (1 maps-matched; 0 native, 256 scan-pinned)' > "$stub/ready.err"
    wait_ready ready 999999 || { echo "pass-0 readiness missed" >&2; exit 1; }
    printf '%s\n' 'p11scope: capturing: 3 probe(s) attached; stop with Ctrl-C' \
        'p11scope: sweeping 440 process maps (cap 256)...' > "$stub/early.err"
    if wait_ready early 999999 >/dev/null 2>&1; then
        echo "inventory readiness accepted without pass 0" >&2
        exit 1
    fi
    rm -rf "$stub"
    trap - EXIT
}

# ------------------------------------------------------------------ run path

# Docker through the selected daemon: the local one on dev, the task-owned
# private socket (root-owned, hence sudo) on fedora.
dcli() {
    if [ "${PRIVATE:-0}" -eq 1 ]; then
        sudo -n docker -H "unix://$TASK_ROOT/docker.sock" "$@"
    else
        docker "$@"
    fi
}

# The host observer always runs through passwordless sudo, args verbatim.
obs() {
    sudo -n "$OBSERVER" "$@"
}

# The exact private-daemon command (single source for start, facts and test).
dockerd_argv() {
    printf '%s\n' "dockerd --data-root $TASK_ROOT/docker-data --exec-root $TASK_ROOT/docker-exec --pidfile $TASK_ROOT/dockerd.pid -H unix://$TASK_ROOT/docker.sock --bridge=none --iptables=false"
}

# N4 records the storage driver but never gates on it: the never-seen late
# provider boundary is about scan/admission timing, not overlay identity.
record_docker_facts() {
    drv=$(dcli info --format '{{.Driver}} {{.ServerVersion}}' 2>/dev/null) \
        || { echo "docker info failed" >&2; return 1; }
    fact "docker-info=$drv"
    driver_only=$(dcli info --format '{{.Driver}}' 2>/dev/null) \
        || { echo "docker info failed" >&2; return 1; }
    fact "driver=$driver_only"
    fact "cgroup-driver=$(dcli info --format '{{.CgroupDriver}}' 2>/dev/null)"
    docker_root=$(dcli info --format '{{.DockerRootDir}}' 2>/dev/null) \
        || { echo "docker info failed" >&2; return 1; }
    fact "docker-root=$docker_root backing-fs=$(stat -f -c '%T' "$docker_root" 2>/dev/null)"
}

assert_name_free() {
    names=$(dcli ps -a --format '{{.Names}}' 2>/dev/null) \
        || { echo "docker ps failed" >&2; return 1; }
    if printf '%s\n' "$names" | grep -Fxq "$1"; then
        echo "container $1 already exists; refusing to reuse or delete it" >&2
        return 1
    fi
}

image_present() {
    dcli image inspect "$1" >/dev/null 2>&1
}

# Exactly one complete gated JSON ledger with 6xN successes (gated.c prints
# `READY pid=` once and one `LEDGER {...}` line with complete/attempts/successful).
ledger_is() {
    python3 -I - "$1" "$2" <<'PY'
import json, sys
path, iters = sys.argv[1], int(sys.argv[2])
ledgers = []
ready = 0
with open(path, encoding="utf-8") as handle:
    for line in handle:
        if line.startswith("READY "):
            ready += 1
        elif line.startswith("LEDGER "):
            ledgers.append(json.loads(line[len("LEDGER "):]))
if ready < 1 or len(ledgers) != 1:
    raise SystemExit(f"want >=1 READY and 1 LEDGER, got {ready} and {len(ledgers)}")
ledger = ledgers[0]
if ledger.get("schema") != "p11scope/public-cli-ledger/v1":
    raise SystemExit("bad ledger schema")
if ledger.get("complete") is not True:
    raise SystemExit("ledger incomplete")
functions = ledger.get("functions")
if not isinstance(functions, list) or len(functions) != 6:
    raise SystemExit("want 6 ledger functions")
names = set()
for row in functions:
    if row.get("attempts") != iters or row.get("successful") != iters:
        raise SystemExit(f"ledger row is not 6x{iters}: {row}")
    names.add(row.get("name"))
if len(names) != 6:
    raise SystemExit("ledger function names are not distinct")
PY
}

# The bundle a D1 --bundle run wrote: tarball gated by its sha256 list plus name.
verify_bundle() {
    [ -f "$1/image.tar" ] && [ -f "$1/sha256sum.txt" ] && [ -f "$1/image-name.txt" ] \
        || { echo "bundle $1 is incomplete" >&2; return 1; }
    (cd "$1" && sha256sum -c sha256sum.txt) || return 1
}

# Its own containers always; the image only when this run owns it (a shared
# D1 build is kept and was noted in facts.log).
cleanup_owned() {
    dcli rm -f "$N4_O" "$N4_L" >/dev/null 2>&1 || true
    if [ "${IMAGE_SHARED:-0}" -eq 0 ]; then
        dcli image rm -f "$N4_IMAGE" >/dev/null 2>&1 || true
    fi
}

# The private daemon always stops (even with --keep: fedora leaves nothing
# running) and its state is removed.
stop_private_daemon() {
    if [ -f "$TASK_ROOT/dockerd.pid" ]; then
        pid=$(cat "$TASK_ROOT/dockerd.pid")
        case $pid in
            ''|*[!0-9]*) echo "bad dockerd pid: $pid" >&2; return 1 ;;
        esac
        sudo -n kill "$pid" 2>/dev/null || true
        i=0
        while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 30 ]; do
            sleep 1
            i=$((i + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            sudo -n kill -9 "$pid" 2>/dev/null || true
            sleep 2
        fi
        if kill -0 "$pid" 2>/dev/null; then
            echo "dockerd $pid survived SIGKILL" >&2
            return 1
        fi
    fi
    sudo -n rm -rf "$TASK_ROOT/docker-data" "$TASK_ROOT/docker-exec" \
        "$TASK_ROOT/docker.sock" "$TASK_ROOT/dockerd.pid"
}

# True when the RFC3339 container start is strictly after the capture-start
# epoch: proves L never appeared in an earlier scan of this run.
l_started_after() {
    started=$(date -u -d "$2" +%s 2>/dev/null) \
        || { echo "bad container start: $2" >&2; return 1; }
    [ "$started" -gt "$1" ] || { echo "L started at $2, not mid-capture" >&2; return 1; }
}

say() {
    printf '%s\n' "$1"
}

fact() {
    printf '%s\n' "$1" >>"$FACTS"
}

summarize() {
    line="SUMMARY cell=N4 host=${HOST-none} verdict=$1 reason=\"$2\""
    printf '%s\n' "$line"
    if [ -n "${FACTS-}" ]; then
        printf '%s\n' "$line" >>"$FACTS"
    fi
}

unrun() {
    summarize UNRUN "$1"
    exit 3
}

fail_cell() {
    summarize FAIL "$1"
    exit 1
}

pass_cell() {
    summarize PASS "$1"
    exit 0
}

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    for capture_pid in ${CAPTURE_PIDS-}; do
        kill "$capture_pid" 2>/dev/null
    done
    if [ "${KEEP:-0}" -eq 1 ] && [ "${PRIVATE:-0}" -eq 0 ]; then
        if [ "${IMAGE_SHARED:-0}" -eq 1 ]; then
            echo "kept containers ${N4_O-} ${N4_L-} (--keep); shared image ${N4_IMAGE-} was already kept: delete with: docker rm -f ${N4_O-} ${N4_L-}" >&2
        else
            echo "kept containers ${N4_O-} ${N4_L-} and image ${N4_IMAGE-} (--keep): delete with: docker rm -f ${N4_O-} ${N4_L-}; docker image rm -f ${N4_IMAGE-}" >&2
        fi
    elif [ -n "${OWNED-}" ]; then
        cleanup_owned
    fi
    if [ "${PRIVATE:-0}" -eq 1 ] && [ -n "${DAEMON_STARTED-}" ]; then
        stop_private_daemon || true
    fi
    if [ -n "${WORK-}" ]; then
        echo "evidence directory: $WORK" >&2
    fi
    exit "$CLEANUP_STATUS"
}

container_pid() {
    pid=$(dcli inspect --format '{{.State.Pid}}' "$1" 2>/dev/null) \
        || { echo "docker inspect failed for $1" >&2; return 1; }
    case $pid in
        ''|*[!0-9]*|0) echo "bad pid for $1: $pid" >&2; return 1 ;;
    esac
    printf '%s\n' "$pid"
}

prov_stat() {
    sudo -n stat -c '%d:%i %s' "/proc/$1/root$2"
}

prov_sha() {
    sudo -n sha256sum "/proc/$1/root$2" | awk '{print $1}'
}

# Create a container's gate file from the host through its own root: a
# `docker exec touch` would add short-lived processes to the captured
# cgroup, which the capture rightly counts as pid_descendant_gaps.
release_gate() {
    sudo -n touch "/proc/$1/root/tmp/gate"
}

wait_docker_log() {
    i=0
    while [ "$i" -lt "$(($3 * 2))" ]; do
        if dcli logs "$1" 2>&1 | grep -q "$2"; then
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    echo "container $1 never printed $2" >&2
    return 1
}

save_logs() {
    dcli logs "$1" >"$2" 2>&1 || return 1
}

# A timed inventory prints no capture readiness line; pass 0's summary line
# means its first full collection (and its anchors) is in place.
wait_ready() {
    i=0
    while [ "$i" -lt 360 ]; do
        if grep -q '^p11scope: pass 0: [0-9]* scanned' "$WORK/$1.err" 2>/dev/null; then
            return 0
        fi
        kill -0 "$2" 2>/dev/null || break
        sleep 0.5
        i=$((i + 1))
    done
    echo "capture $1 never became ready" >&2
    cat "$WORK/$1.err" >&2
    return 1
}

build_image() {
    [ "$(grep -c "FROM $HOLDER_BASE" "$HOLDER_DOCKERFILE")" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; return 1; }
    dcli build -q -f "$HOLDER_DOCKERFILE" -t "$N4_IMAGE" . || return 1
}

load_bundle() {
    verify_bundle "$BUNDLE_DIR" || return 1
    want=$(cat "$BUNDLE_DIR/image-name.txt")
    [ "$want" = "$N4_IMAGE" ] \
        || { echo "bundle image $want is not $N4_IMAGE" >&2; return 1; }
    dcli load -i "$BUNDLE_DIR/image.tar" || return 1
    dcli image inspect "$N4_IMAGE" >/dev/null || return 1
}

start_private_daemon() {
    [ ! -e "$TASK_ROOT/docker.sock" ] \
        || { echo "socket $TASK_ROOT/docker.sock already exists" >&2; return 1; }
    [ ! -e "$TASK_ROOT/dockerd.pid" ] \
        || { echo "pidfile $TASK_ROOT/dockerd.pid already exists" >&2; return 1; }
    mkdir -p "$TASK_ROOT/docker-data" "$TASK_ROOT/docker-exec"
    dockerd_argv | tee -a "$FACTS"
    # shellcheck disable=SC2086
    sudo -n $(dockerd_argv) >"$TASK_ROOT/dockerd.log" 2>&1 &
    DAEMON_STARTED=1
    i=0
    while [ "$i" -lt 120 ]; do
        if dcli info >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    echo "private dockerd never answered; see $TASK_ROOT/dockerd.log" >&2
    return 1
}

HOST=
OBSERVER=
IMAGE=
TOKEN=
ITERS_O=$ITERS_O_DEFAULT
ITERS_L=$ITERS_L_DEFAULT
DURATION=$DURATION_DEFAULT
LATE_DELAY=$LATE_DELAY_DEFAULT
TASK_ROOT=
BUNDLE_DIR=
WORK_OPT=
KEEP=0

while [ "$#" -gt 0 ]; do
    case $1 in
        --self-test) [ "$#" -eq 1 ] || usage; self_test ;;
        -h|--help) usage ;;
        --host) [ "$#" -ge 2 ] || usage; [ -z "$HOST" ] || usage; HOST=$2; shift 2 ;;
        --observer) [ "$#" -ge 2 ] || usage; [ -z "$OBSERVER" ] || usage; OBSERVER=$2; shift 2 ;;
        --image) [ "$#" -ge 2 ] || usage; [ -z "$IMAGE" ] || usage; IMAGE=$2; shift 2 ;;
        --token) [ "$#" -ge 2 ] || usage; [ -z "$TOKEN" ] || usage; TOKEN=$2; shift 2 ;;
        --iters-o) [ "$#" -ge 2 ] || usage; ITERS_O=$2; shift 2 ;;
        --iters-l) [ "$#" -ge 2 ] || usage; ITERS_L=$2; shift 2 ;;
        --duration) [ "$#" -ge 2 ] || usage; DURATION=$2; shift 2 ;;
        --late-delay) [ "$#" -ge 2 ] || usage; LATE_DELAY=$2; shift 2 ;;
        --task-root) [ "$#" -ge 2 ] || usage; [ -z "$TASK_ROOT" ] || usage; TASK_ROOT=$2; shift 2 ;;
        --bundle-dir) [ "$#" -ge 2 ] || usage; [ -z "$BUNDLE_DIR" ] || usage; BUNDLE_DIR=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || usage; [ -z "$WORK_OPT" ] || usage; WORK_OPT=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[ -n "$HOST" ] || usage
case $HOST in
    dev) PRIVATE=0 ;;
    fedora-private) PRIVATE=1 ;;
    *) usage ;;
esac
[ -n "$OBSERVER" ] || usage
[ -x "$OBSERVER" ] || { echo "observer $OBSERVER is not executable" >&2; exit 2; }
[ -z "$TOKEN" ] || valid_token "$TOKEN" || usage
TOKEN=${TOKEN:-$(date +%s)-$$}
valid_token "$TOKEN" || usage
valid_count "$ITERS_O" || usage
valid_count "$ITERS_L" || usage
valid_count "$DURATION" || usage
valid_count "$LATE_DELAY" || usage
[ "$LATE_DELAY" -lt "$DURATION" ] || usage
if [ "$PRIVATE" -eq 1 ]; then
    [ -n "$TASK_ROOT" ] && [ -n "$BUNDLE_DIR" ] || usage
    [ -d "$TASK_ROOT" ] || { echo "task root $TASK_ROOT is not a directory" >&2; exit 2; }
    case $TASK_ROOT in
        *' '*) echo "task root must not contain spaces" >&2; exit 2 ;;
    esac
else
    [ -z "$TASK_ROOT$BUNDLE_DIR" ] || usage
fi

. scripts/lib.sh
require_non_root_caller || unrun "run as a non-root user with passwordless sudo"
for command in docker python3 stat sha256sum awk grep date; do
    command -v "$command" >/dev/null || unrun "$command required"
done
if [ "$PRIVATE" -eq 1 ]; then
    for command in dockerd df; do
        command -v "$command" >/dev/null || unrun "$command required"
    done
fi
sudo -n true 2>/dev/null || unrun "passwordless sudo required (sudo -n true)"

if [ -n "$WORK_OPT" ]; then
    [ ! -e "$WORK_OPT" ] || { echo "work dir $WORK_OPT already exists" >&2; exit 2; }
    mkdir -m 0700 "$WORK_OPT"
    WORK=$(cd "$WORK_OPT" && pwd -P)
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-n4-XXXXXX")
    chmod 0700 "$WORK"
fi
FACTS=$WORK/facts.log
SUMMARY_JSONL=$WORK/summary.jsonl
: >"$FACTS"
: >"$SUMMARY_JSONL"
. scripts/cleanup-traps.sh

N4_O=n4-o-$TOKEN
N4_L=n4-l-$TOKEN
if [ "$PRIVATE" -eq 1 ] && [ -z "$IMAGE" ]; then
    [ -f "$BUNDLE_DIR/image-name.txt" ] || unrun "bundle $BUNDLE_DIR has no image-name.txt"
    N4_IMAGE=$(cat "$BUNDLE_DIR/image-name.txt")
else
    N4_IMAGE=${IMAGE:-p11scope-ctr-shared:$TOKEN}
fi
OWNED=1
CAPTURE_PIDS=
IMAGE_SHARED=0

fact "cell=N4 host=$HOST token=$TOKEN date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fact "observer=$OBSERVER sha256=$(sha256sum "$OBSERVER" | awk '{print $1}')"
fact "image=$N4_IMAGE containers=$N4_O,$N4_L iters=$ITERS_O,$ITERS_L duration=$DURATION late-delay=$LATE_DELAY"
fact "kernel=$(uname -sr) $(uname -m)"
fact "kind: not used (docker-only cell); kubectl: not used (docker-only cell)"

if [ "$PRIVATE" -eq 1 ]; then
    fstype=$(df -T "$TASK_ROOT" 2>/dev/null | awk 'NR==2 {print $2}')
    fact "task-root=$TASK_ROOT fstype=${fstype-unknown}"
    [ "$fstype" != "tmpfs" ] || unrun "task root $TASK_ROOT is memory-backed; use a disk filesystem"
    verify_bundle "$BUNDLE_DIR" || unrun "bundle $BUNDLE_DIR failed verification"
    fact "bundle=$BUNDLE_DIR sha256=$(awk '{print $1}' "$BUNDLE_DIR/sha256sum.txt")"
    fact "downloads: none (private daemon loads the verified bundle; no network)"
    start_private_daemon || unrun "private dockerd failed to start"
    fact "dockerd-log=$TASK_ROOT/dockerd.log"
fi

record_docker_facts || unrun "docker info failed"
assert_name_free "$N4_O" || unrun "container $N4_O already exists"
assert_name_free "$N4_L" || unrun "container $N4_L already exists"

if [ "$PRIVATE" -eq 1 ]; then
    load_bundle || unrun "bundle load failed"
    fact "downloads: none (bundle load only)"
elif image_present "$N4_IMAGE"; then
    IMAGE_SHARED=1
    fact "image-shared=yes ($N4_IMAGE reused from the D1 build; kept after)"
else
    build_image || fail_cell "image build failed"
    fact "downloads: base $HOLDER_BASE; apt archive packages per $HOLDER_DOCKERFILE (gcc, softhsm2; unpinned, repeatable not bit-reproducible)"
fi
fact "image-id=$(dcli inspect --format '{{.Id}}' "$N4_IMAGE")"

say "=== start owned container O ($ITERS_O) ==="
dcli run -d --name "$N4_O" "$N4_IMAGE" ledger "$ITERS_O" || fail_cell "container $N4_O failed to start"
wait_docker_log "$N4_O" '^READY ' 120 || fail_cell "container $N4_O never became ready"
PID_O=$(container_pid "$N4_O") || fail_cell "no pid for $N4_O"
STAT_O=$(prov_stat "$PID_O" "$PROVIDER_PATH") || fail_cell "cannot stat O provider"
SHA_O=$(prov_sha "$PID_O" "$PROVIDER_PATH") || fail_cell "cannot hash O provider"
[ -n "$SHA_O" ] || fail_cell "empty O provider hash"
fact "pid-o=$PID_O stat-o=$STAT_O sha-o=$SHA_O late-module=$LATE_MODULE"

say "=== start inventory capture ($DURATION s) ==="
obs inventory --system --duration "$DURATION" --caller-metadata none \
    -o "$WORK/n4.json" >"$WORK/n4.out" 2>"$WORK/n4.err" &
PID_CAP=$!
CAPTURE_PIDS="$PID_CAP"
wait_ready n4 "$PID_CAP" || fail_cell "inventory capture never became ready"
CAPTURE_START=$(date +%s)
fact "capture-start-epoch=$CAPTURE_START"
release_gate "$PID_O" || fail_cell "gate release failed for $N4_O"

say "=== at T+$LATE_DELAY s: start late container L ($ITERS_L) ==="
sleep "$LATE_DELAY"
dcli run -d --user 65534 --name "$N4_L" "$N4_IMAGE" ledger-private "$ITERS_L" \
    || fail_cell "container $N4_L failed to start"
wait_docker_log "$N4_L" '^READY ' 120 || fail_cell "container $N4_L never became ready"
PID_L=$(container_pid "$N4_L") || fail_cell "no pid for $N4_L"
STAT_L=$(prov_stat "$PID_L" "$LATE_MODULE") || fail_cell "cannot stat L provider"
SHA_L=$(prov_sha "$PID_L" "$LATE_MODULE") || fail_cell "cannot hash L provider"
[ -n "$SHA_L" ] || fail_cell "empty L provider hash"
STARTED_L=$(dcli inspect --format '{{.State.StartedAt}}' "$N4_L") || fail_cell "no start time for $N4_L"
fact "pid-l=$PID_L stat-l=$STAT_L sha-l=$SHA_L started-l=$STARTED_L"
[ "$STAT_L" != "$STAT_O" ] || fail_cell "L provider is not a fresh file (stat $STAT_L)"
l_started_after "$CAPTURE_START" "$STARTED_L" || fail_cell "L did not start mid-capture"
release_gate "$PID_L" || fail_cell "gate release failed for $N4_L"

say "=== wait for both ledgers and the capture ==="
wait_docker_log "$N4_O" '^LEDGER ' "$DURATION" || fail_cell "O ledger never completed"
kill -0 "$PID_CAP" 2>/dev/null || fail_cell "O ledger completed outside the capture window"
wait_docker_log "$N4_L" '^LEDGER ' "$DURATION" || fail_cell "L ledger never completed"
kill -0 "$PID_CAP" 2>/dev/null || fail_cell "L ledger completed outside the capture window"
wait "$PID_CAP" || fail_cell "inventory capture failed"
reclaim_root_output "$WORK/n4.json" || fail_cell "cannot reclaim n4.json"
python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$WORK/n4.json" \
    || fail_cell "n4.json is not valid JSON"
save_logs "$N4_O" "$WORK/logs-o.txt" || fail_cell "cannot read $N4_O logs"
save_logs "$N4_L" "$WORK/logs-l.txt" || fail_cell "cannot read $N4_L logs"
ledger_is "$WORK/logs-o.txt" "$ITERS_O" || fail_cell "O ledger is not 6x$ITERS_O"
ledger_is "$WORK/logs-l.txt" "$ITERS_L" || fail_cell "L ledger is not 6x$ITERS_L"
grep -h '^LEDGER ' "$WORK/logs-o.txt" "$WORK/logs-l.txt" >>"$FACTS"

say "=== oracle ==="
if python3 -I "$ORACLE" late-reported "$WORK/n4.json" \
        --pid-o "$PID_O" --pid-l "$PID_L" --late-module "$LATE_MODULE" \
        >"$WORK/oracle.json" 2>"$WORK/oracle.err"; then
    cat "$WORK/oracle.json" >>"$SUMMARY_JSONL"
    cat "$WORK/oracle.json" >>"$FACTS"
    pass_cell "N4 late boundary reported (NON-PASS retained)"
else
    cat "$WORK/oracle.err" >&2 || true
    cat "$WORK/oracle.err" >>"$FACTS" || true
    fail_cell "oracle refused the N4 evidence"
fi
