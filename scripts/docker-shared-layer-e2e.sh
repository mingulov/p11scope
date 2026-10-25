#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Cell D1: Docker shared layers / storage driver / copy-up (dev host AND fedora).
#
# Two containers A and B start from one holder image (deploy/Dockerfile.holder,
# reused verbatim: pinned ubuntu:26.04 base, SoftHSM2, ledgered `gated` client),
# so both map the provider through overlay lower layers. Pre-copy-up both
# identity backends must attribute both containers exactly; after a same-bytes
# copy-up in B only (OQ5), the kernel backend must refuse B's new mapping with
# a named loss while userspace still joins it (D-C7-3, disclosed). The observer
# is the host release binary run through `sudo -n` in the initial PID namespace.
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
ITERS_A_DEFAULT=400
ITERS_B_DEFAULT=250
DURATION_DEFAULT=30

usage() {
    cat >&2 <<'EOF'
usage: scripts/docker-shared-layer-e2e.sh --host dev|fedora-private --observer BIN [options]
       scripts/docker-shared-layer-e2e.sh --bundle OUTDIR [--image NAME] [--token TOKEN]
       scripts/docker-shared-layer-e2e.sh --self-test | --help

  Cell D1 driver. Run modes share one flow: build (or load) the holder image,
  start containers A and B, capture pre-copy-up evidence, copy B's provider
  upper with identical bytes, restart B, capture post evidence, and check it
  with scripts/container-cells-oracle.py copy-up.

  --host dev            use the local docker daemon (dev host)
  --host fedora-private run ON fedora as user against a task-owned private
                        dockerd (own data-root/exec-root/pidfile/socket under
                        --task-root, --bridge=none --iptables=false)
  --observer BIN        host release p11scope binary (run through sudo -n)
  --image NAME          image name (default p11scope-ctr-shared:$TOKEN)
  --token TOKEN         run token, short [a-z0-9-] (default <time>-<pid>)
  --iters-a N           ledger iterations for A (default 400)
  --iters-b N           ledger iterations for B (default 250)
  --duration S          profile capture seconds (default 30)
  --task-root DIR       fedora-private only: existing task root directory
  --bundle-dir DIR      fedora-private only: bundle from --bundle mode
  --work DIR            evidence directory (must not exist; default fresh 0700
                        under $TMPDIR)
  --keep                keep containers/image for debugging (prints the delete
                        commands); the private daemon always stops
  --bundle OUTDIR       build the image on the dev host, save it as
                        OUTDIR/image.tar, and write OUTDIR/sha256sum.txt plus
                        the image name/id (OUTDIR must not exist)
  --self-test           unprivileged checks (PATH stubs, no docker)
  --help                this text

Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 UNRUN (cell not run, see SUMMARY reason).
Every run prints a final SUMMARY line: SUMMARY cell=D1 host=... verdict=... reason="...".

CONTROLLER (run order):
  # D1 on the dev host (from the repo root; BIN = host release binary):
  sh scripts/docker-shared-layer-e2e.sh --host dev --observer BIN --token <TOKEN>
  # D1 bundle for fedora (on the dev host):
  sh scripts/docker-shared-layer-e2e.sh --bundle /tmp/ctr-bundle-<TOKEN> --image p11scope-ctr-shared:<TOKEN>
  scp -r /tmp/ctr-bundle-<TOKEN> fedora:/home/user/p11scope-ctr-<TOKEN>/bundle
  scp BIN fedora:/home/user/p11scope-ctr-<TOKEN>/p11scope
  ssh fedora mkdir -p /home/user/p11scope-ctr-<TOKEN>/scripts
  scp scripts/docker-shared-layer-e2e.sh scripts/container-cells-oracle.py scripts/lib.sh scripts/cleanup-traps.sh fedora:/home/user/p11scope-ctr-<TOKEN>/scripts/
  # D1 on fedora (as user; run `sudo -n true` first in the session):
  ssh fedora sh /home/user/p11scope-ctr-<TOKEN>/scripts/docker-shared-layer-e2e.sh --host fedora-private --task-root /home/user/p11scope-ctr-<TOKEN> --bundle-dir /home/user/p11scope-ctr-<TOKEN>/bundle --observer /home/user/p11scope-ctr-<TOKEN>/p11scope --token <TOKEN>
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

# R4 lane from the kernel release (per-lane overlay outcome table: A = 6.1/6.6
# maps keyed by backing inode, B = 6.8+/7.x keyed by overlay inode). Anything
# else is UNRUN: the table names no row for it, so no verdict is possible.
lane_for_kernel() {
    case ${1-$(uname -r)} in
        6.1.*|6.6.*) printf 'A\n' ;;
        6.8.*|6.12.*|7.*) printf 'B\n' ;;
        *) return 1 ;;
    esac
}

self_test() {
    [ "$#" -eq 0 ] || usage
    command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
    # The Dockerfile pin this cell reuses: both stages, exactly this digest.
    [ "$(grep -c "FROM $HOLDER_BASE" "$HOLDER_DOCKERFILE")" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; exit 1; }
    [ "$ITERS_A_DEFAULT" -eq 400 ] && [ "$ITERS_B_DEFAULT" -eq 250 ] \
        || { echo "ledger defaults drifted" >&2; exit 1; }
    for kernel in 6.1.188:A 6.6.157:A 6.8.0-142-generic:B 6.12.111:B \
                  7.0.0-34-generic:B 7.2.9:B; do
        release=${kernel%:*}
        want=${kernel#*:}
        got=$(lane_for_kernel "$release") \
            || { echo "lane_for_kernel refused $release" >&2; exit 1; }
        [ "$got" = "$want" ] || { echo "lane $release -> $got (want $want)" >&2; exit 1; }
    done
    for kernel in 5.15.221 6.9.1 6.7.0 "" "garbage"; do
        if lane_for_kernel "$kernel" >/dev/null 2>&1; then
            echo "lane_for_kernel accepted $kernel" >&2
            exit 1
        fi
    done
    for bad in "" "--host" "--host bogus" "--host dev" \
               "--host dev --observer" "--host dev --observer /nonexistent" \
               "--host dev --observer /bin/true --token UPPER" \
               "--host dev --observer /bin/true --token -x" \
               "--host dev --observer /bin/true --iters-a 0" \
               "--host dev --observer /bin/true --iters-b 01" \
               "--host dev --observer /bin/true --duration x" \
               "--host fedora-private --observer /bin/true" \
               "--host fedora-private --observer /bin/true --task-root /tmp" \
               "--host fedora-private --observer /bin/true --task-root /tmp --bundle-dir /tmp --bundle-dir /tmp" \
               "--bundle" "--bundle /tmp --bundle /tmp" "--bogus" "--keep --bogus"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || {
            echo "d1 driver exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    d1_help_self_test
    d1_stub_self_test
    python3 -I "$ORACLE" --self-test
    echo "docker-shared-layer-e2e self-test: OK"
    exit 0
}

d1_help_self_test() {
    help=$(sh "$0" --help 2>&1 || true)
    for marker in "--host dev --observer BIN" "--host fedora-private --task-root" \
                  "--bundle OUTDIR" "scp -r" "sudo -n true" "SUMMARY cell=D1"; do
        case $help in
            *"$marker"*) ;;
            *) echo "help lost its controller line: $marker" >&2; exit 1 ;;
        esac
    done
}

d1_stub_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-d1-stub-XXXXXX")
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
    # Storage-driver gate: overlay2 proceeds, anything else is UNRUN.
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
if [ "$1" = "info" ]; then printf '%s\n' "$STUB_DRIVER"; exit 0; fi
echo "unexpected docker call: $*" >&2; exit 1
EOF
    chmod +x "$stub/docker"
    STUB_DRIVER=overlay2 PRIVATE=0 PATH="$stub:$PATH" require_overlay2 \
        || { echo "overlay2 wrongly refused" >&2; exit 1; }
    if STUB_DRIVER=btrfs PRIVATE=0 PATH="$stub:$PATH" require_overlay2 \
            >/dev/null 2>&1; then
        echo "btrfs wrongly accepted" >&2
        exit 1
    fi
    # The observer always runs through `sudo -n`, args verbatim.
    mkdir -p "$stub/echobin"
    cp "$stub/echo-sudo" "$stub/echobin/sudo"
    chmod +x "$stub/echobin/sudo"
    got=$(OBSERVER=/nonexistent/p11scope PATH="$stub/echobin:$stub" obs inventory --system)
    case $got in
        "SUDO -n /nonexistent/p11scope inventory --system") ;;
        *) echo "observer command lost sudo -n: $got" >&2; exit 1 ;;
    esac
    # LEDGER lines: exactly one complete JSON ledger with 6xN successes.
    ledger_log() {
        printf '%s\n' "$2" > "$stub/$1.log"
    }
    ledger_log good "READY pid=1
LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":1,\"complete\":true,\"functions\":[{\"name\":\"C_GenerateRandom\",\"attempts\":400,\"successful\":400},{\"name\":\"C_DigestInit\",\"attempts\":400,\"successful\":400},{\"name\":\"C_Digest\",\"attempts\":400,\"successful\":400},{\"name\":\"C_FindObjectsInit\",\"attempts\":400,\"successful\":400},{\"name\":\"C_FindObjects\",\"attempts\":400,\"successful\":400},{\"name\":\"C_FindObjectsFinal\",\"attempts\":400,\"successful\":400}]}"
    PATH="$stub:$PATH" ledger_is "$stub/good.log" 400 \
        || { echo "good LEDGER refused" >&2; exit 1; }
    ledger_log incomplete "LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":1,\"complete\":false,\"functions\":[]}"
    ledger_log short "LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":1,\"complete\":true,\"functions\":[{\"name\":\"C_GenerateRandom\",\"attempts\":399,\"successful\":399}]}"
    ledger_log failed "LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":1,\"complete\":true,\"functions\":[{\"name\":\"C_GenerateRandom\",\"attempts\":400,\"successful\":399},{\"name\":\"C_DigestInit\",\"attempts\":400,\"successful\":400},{\"name\":\"C_Digest\",\"attempts\":400,\"successful\":400},{\"name\":\"C_FindObjectsInit\",\"attempts\":400,\"successful\":400},{\"name\":\"C_FindObjects\",\"attempts\":400,\"successful\":400},{\"name\":\"C_FindObjectsFinal\",\"attempts\":400,\"successful\":400}]}"
    ledger_log missing "READY pid=1"
    for bad in incomplete short failed missing; do
        if PATH="$stub:$PATH" ledger_is "$stub/$bad.log" 400 >/dev/null 2>&1; then
            echo "bad LEDGER accepted: $bad" >&2
            exit 1
        fi
    done
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
    if STUB_NAMES="d1-a-t" PATH="$stub:$PATH" assert_name_free d1-a-t >/dev/null 2>&1; then
        echo "existing container name accepted" >&2
        exit 1
    fi
    STUB_NAMES="" PATH="$stub:$PATH" assert_name_free d1-a-t \
        || { echo "free container name refused" >&2; exit 1; }
    # Cleanup trap: its own containers and image, nothing else.
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "docker $*" >> "$STUB_CALLS"
EOF
    chmod +x "$stub/docker"
    : > "$stub/calls.txt"
    # shellcheck disable=SC2034
    STUB_CALLS=$stub/calls.txt PRIVATE=0 PATH="$stub:$PATH" \
        D1_A=d1-a-t D1_B=d1-b-t D1_IMAGE=img:t cleanup_owned \
        || { echo "cleanup_owned failed" >&2; exit 1; }
    grep -q "docker rm -f d1-a-t d1-b-t" "$stub/calls.txt" \
        || { echo "cleanup lost its container removal" >&2; exit 1; }
    grep -q "docker image rm -f img:t" "$stub/calls.txt" \
        || { echo "cleanup lost its image removal" >&2; exit 1; }
    # Private-daemon stop: the daemon dies and its state is removed.
    mkdir -p "$stub/task/docker-data" "$stub/task/docker-exec"
    sleep 60 &
    # shellcheck disable=SC2034
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
    # Cgroup resolution: v2 path only, verified as a directory.
    mkdir -p "$stub/cg/system.slice/docker-abc.scope"
    printf '0::/system.slice/docker-abc.scope\n' > "$stub/cgroup"
    got=$(D1_CGROUP_FILE=$stub/cgroup D1_CGROUP_ROOT=$stub/cg cg_of_pid 1234) \
        || { echo "v2 cgroup refused" >&2; exit 1; }
    [ "$got" = "$stub/cg/system.slice/docker-abc.scope" ] \
        || { echo "cgroup resolved to $got" >&2; exit 1; }
    printf '1:name=systemd:/docker/abc\n' > "$stub/cgroup-v1"
    if D1_CGROUP_FILE=$stub/cgroup-v1 D1_CGROUP_ROOT=$stub/cg cg_of_pid 1234 \
            >/dev/null 2>&1; then
        echo "v1 cgroup accepted" >&2
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

# D1 rows are overlay-specific: any other storage driver is UNRUN, recorded.
require_overlay2() {
    drv=$(dcli info --format '{{.Driver}}' 2>/dev/null) \
        || { echo "docker info failed" >&2; return 1; }
    [ "$drv" = "overlay2" ] \
        || { echo "storage driver is $drv, want overlay2" >&2; return 1; }
}

assert_name_free() {
    names=$(dcli ps -a --format '{{.Names}}' 2>/dev/null) \
        || { echo "docker ps failed" >&2; return 1; }
    if printf '%s\n' "$names" | grep -Fxq "$1"; then
        echo "container $1 already exists; refusing to reuse or delete it" >&2
        return 1
    fi
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

# The bundle a --bundle run wrote: tarball gated by its sha256 list plus name.
verify_bundle() {
    [ -f "$1/image.tar" ] && [ -f "$1/sha256sum.txt" ] && [ -f "$1/image-name.txt" ] \
        || { echo "bundle $1 is incomplete" >&2; return 1; }
    (cd "$1" && sha256sum -c sha256sum.txt) || return 1
}

# Its own containers and image, nothing else (the trap calls this).
cleanup_owned() {
    dcli rm -f "$D1_A" "$D1_B" >/dev/null 2>&1 || true
    dcli image rm -f "$D1_IMAGE" >/dev/null 2>&1 || true
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

# Cgroup v2 path of a container process, verified as a directory.
# D1_CGROUP_FILE/D1_CGROUP_ROOT are self-test hooks (attach-pod.sh pattern);
# production reads the node's own hierarchy.
cg_of_pid() {
    rel=$(awk -F: '$1 == "0" && $2 == "" {print $3}' \
        "${D1_CGROUP_FILE:-/proc/$1/cgroup}" 2>/dev/null) || return 1
    [ -n "$rel" ] || { echo "no cgroup v2 path for pid $1" >&2; return 1; }
    case $rel in
        /?*) ;;
        *) echo "bad cgroup path: $rel" >&2; return 1 ;;
    esac
    full=${D1_CGROUP_ROOT:-/sys/fs/cgroup}$rel
    [ -d "$full" ] || { echo "cgroup is not a directory: $full" >&2; return 1; }
    printf '%s\n' "$full"
}

say() {
    printf '%s\n' "$1"
}

fact() {
    printf '%s\n' "$1" >>"$FACTS"
}

summarize() {
    line="SUMMARY cell=D1 host=${HOST-none} verdict=$1 reason=\"$2\""
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
        echo "kept containers ${D1_A-} ${D1_B-} and image ${D1_IMAGE-} (--keep): delete with: docker rm -f ${D1_A-} ${D1_B-}; docker image rm -f ${D1_IMAGE-}" >&2
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
    sudo -n stat -c '%d:%i %s' "/proc/$1/root$PROVIDER_PATH"
}

prov_sha() {
    sudo -n sha256sum "/proc/$1/root$PROVIDER_PATH" | awk '{print $1}'
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

run_inventory() {
    obs inventory --system --identity-backend "$1" --caller-metadata none \
        -o "$2" >"$2.out" 2>"$2.err" || { cat "$2.err" >&2; return 1; }
    reclaim_root_output "$2" || return 1
    python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$2" || return 1
}

start_profile() {
    obs profile --cgroup "$2" --duration "$3" -o "$4" >"$WORK/$1.out" 2>"$WORK/$1.err" &
    CAPTURE_PIDS="${CAPTURE_PIDS-} $!"
    STARTED_PID=$!
}

wait_ready() {
    i=0
    while [ "$i" -lt 360 ]; do
        if grep -q 'p11scope: capturing:' "$WORK/$1.err" 2>/dev/null; then
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
    dcli build -q -f "$HOLDER_DOCKERFILE" -t "$D1_IMAGE" . || return 1
}

save_bundle() {
    printf '%s\n' "$D1_IMAGE" >"$1/image-name.txt"
    dcli inspect --format '{{.Id}}' "$D1_IMAGE" >"$1/image-id.txt" || return 1
    dcli save -o "$1/image.tar" "$D1_IMAGE" || return 1
    (cd "$1" && sha256sum image.tar >sha256sum.txt) || return 1
    fact "bundle: $1 image=$D1_IMAGE id=$(cat "$1/image-id.txt") sha256=$(awk '{print $1}' "$1/sha256sum.txt")"
}

load_bundle() {
    verify_bundle "$BUNDLE_DIR" || return 1
    want=$(cat "$BUNDLE_DIR/image-name.txt")
    [ "$want" = "$D1_IMAGE" ] \
        || { echo "bundle image $want is not $D1_IMAGE" >&2; return 1; }
    dcli load -i "$BUNDLE_DIR/image.tar" || return 1
    dcli image inspect "$D1_IMAGE" >/dev/null || return 1
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
ITERS_A=$ITERS_A_DEFAULT
ITERS_B=$ITERS_B_DEFAULT
DURATION=$DURATION_DEFAULT
TASK_ROOT=
BUNDLE_DIR=
WORK_OPT=
KEEP=0
BUNDLE_OUT=

while [ "$#" -gt 0 ]; do
    case $1 in
        --self-test) [ "$#" -eq 1 ] || usage; self_test ;;
        -h|--help) usage ;;
        --host) [ "$#" -ge 2 ] || usage; [ -z "$HOST" ] || usage; HOST=$2; shift 2 ;;
        --observer) [ "$#" -ge 2 ] || usage; [ -z "$OBSERVER" ] || usage; OBSERVER=$2; shift 2 ;;
        --image) [ "$#" -ge 2 ] || usage; [ -z "$IMAGE" ] || usage; IMAGE=$2; shift 2 ;;
        --token) [ "$#" -ge 2 ] || usage; [ -z "$TOKEN" ] || usage; TOKEN=$2; shift 2 ;;
        --iters-a) [ "$#" -ge 2 ] || usage; ITERS_A=$2; shift 2 ;;
        --iters-b) [ "$#" -ge 2 ] || usage; ITERS_B=$2; shift 2 ;;
        --duration) [ "$#" -ge 2 ] || usage; DURATION=$2; shift 2 ;;
        --task-root) [ "$#" -ge 2 ] || usage; [ -z "$TASK_ROOT" ] || usage; TASK_ROOT=$2; shift 2 ;;
        --bundle-dir) [ "$#" -ge 2 ] || usage; [ -z "$BUNDLE_DIR" ] || usage; BUNDLE_DIR=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || usage; [ -z "$WORK_OPT" ] || usage; WORK_OPT=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --bundle) [ "$#" -ge 2 ] || usage; [ -z "$BUNDLE_OUT" ] || usage; BUNDLE_OUT=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[ -z "$BUNDLE_OUT" ] || {
    [ -z "$HOST$OBSERVER$TASK_ROOT$BUNDLE_DIR$WORK_OPT" ] && [ "$KEEP" -eq 0 ] || usage
    [ ! -e "$BUNDLE_OUT" ] || { echo "bundle dir $BUNDLE_OUT already exists" >&2; exit 2; }
    [ -z "$TOKEN" ] || valid_token "$TOKEN" || usage
    TOKEN=${TOKEN:-$(date +%s)-$$}
    valid_token "$TOKEN" || usage
    D1_IMAGE=${IMAGE:-p11scope-ctr-shared:$TOKEN}
    PRIVATE=0
    for command in docker python3 sha256sum; do
        command -v "$command" >/dev/null || { echo "$command required" >&2; exit 3; }
    done
    mkdir -p "$BUNDLE_OUT"
    WORK=$BUNDLE_OUT
    FACTS=$BUNDLE_OUT/bundle.log
    : >"$FACTS"
    build_image || { echo "image build failed" >&2; exit 1; }
    save_bundle "$BUNDLE_OUT" || { echo "bundle save failed" >&2; exit 1; }
    say "BUNDLE dir=$BUNDLE_OUT image=$D1_IMAGE"
    exit 0
}

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
valid_count "$ITERS_A" || usage
valid_count "$ITERS_B" || usage
valid_count "$DURATION" || usage
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
for command in docker python3 stat sha256sum awk grep; do
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
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-d1-XXXXXX")
    chmod 0700 "$WORK"
fi
FACTS=$WORK/facts.log
SUMMARY_JSONL=$WORK/summary.jsonl
: >"$FACTS"
: >"$SUMMARY_JSONL"
. scripts/cleanup-traps.sh

D1_A=d1-a-$TOKEN
D1_B=d1-b-$TOKEN
if [ "$PRIVATE" -eq 1 ] && [ -z "$IMAGE" ]; then
    [ -f "$BUNDLE_DIR/image-name.txt" ] || unrun "bundle $BUNDLE_DIR has no image-name.txt"
    D1_IMAGE=$(cat "$BUNDLE_DIR/image-name.txt")
else
    D1_IMAGE=${IMAGE:-p11scope-ctr-shared:$TOKEN}
fi
OWNED=1
CAPTURE_PIDS=

fact "cell=D1 host=$HOST token=$TOKEN date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fact "observer=$OBSERVER sha256=$(sha256sum "$OBSERVER" | awk '{print $1}')"
fact "image=$D1_IMAGE containers=$D1_A,$D1_B iters=$ITERS_A,$ITERS_B duration=$DURATION"
fact "kernel=$(uname -sr) $(uname -m)"
LANE=$(lane_for_kernel "$(uname -r)") || unrun "kernel $(uname -r) has no R4 lane row"
fact "lane=$LANE"
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

docker_info=$(dcli info --format '{{.Driver}} {{.Server.Version}}' 2>/dev/null) \
    || unrun "docker info failed"
fact "docker-info=$docker_info"
cgroup_driver=$(dcli info --format '{{.CgroupDriver}}' 2>/dev/null) \
    || unrun "docker info failed"
fact "cgroup-driver=$cgroup_driver"
docker_root=$(dcli info --format '{{.DockerRootDir}}' 2>/dev/null) \
    || unrun "docker info failed"
fact "docker-root=$docker_root backing-fs=$(stat -f -c '%T' "$docker_root" 2>/dev/null)"
require_overlay2 || unrun "storage driver is not overlay2; D1 rows are overlay-specific"
grep -E ' overlay ' /proc/mounts | head -5 >>"$FACTS" || true
assert_name_free "$D1_A" || unrun "container $D1_A already exists"
assert_name_free "$D1_B" || unrun "container $D1_B already exists"

if [ "$PRIVATE" -eq 1 ]; then
    load_bundle || unrun "bundle load failed"
    fact "downloads: none (bundle load only)"
else
    build_image || fail_cell "image build failed"
    fact "downloads: base $HOLDER_BASE; apt archive packages per $HOLDER_DOCKERFILE (gcc, softhsm2; unpinned, repeatable not bit-reproducible)"
fi
fact "image-id=$(dcli inspect --format '{{.Id}}' "$D1_IMAGE")"

say "=== start containers A ($ITERS_A) and B ($ITERS_B) ==="
dcli run -d --name "$D1_A" "$D1_IMAGE" ledger "$ITERS_A" || fail_cell "container $D1_A failed to start"
dcli run -d --name "$D1_B" "$D1_IMAGE" ledger "$ITERS_B" || fail_cell "container $D1_B failed to start"
wait_docker_log "$D1_A" '^READY ' 120 || fail_cell "container $D1_A never became ready"
wait_docker_log "$D1_B" '^READY ' 120 || fail_cell "container $D1_B never became ready"
PID_A=$(container_pid "$D1_A") || fail_cell "no pid for $D1_A"
PID_B_PRE=$(container_pid "$D1_B") || fail_cell "no pid for $D1_B"
CG_A=$(cg_of_pid "$PID_A") || fail_cell "no cgroup for $D1_A"
CG_B=$(cg_of_pid "$PID_B_PRE") || fail_cell "no cgroup for $D1_B"
fact "pid-a=$PID_A cgroup-a=$CG_A pid-b-pre=$PID_B_PRE cgroup-b=$CG_B"
fact "cid-a=$(dcli inspect --format '{{.Id}}' "$D1_A") cid-b=$(dcli inspect --format '{{.Id}}' "$D1_B")"
STAT_A_PRE=$(prov_stat "$PID_A") || fail_cell "cannot stat A provider"
STAT_B_PRE=$(prov_stat "$PID_B_PRE") || fail_cell "cannot stat B provider"
SHA_A_PRE=$(prov_sha "$PID_A") || fail_cell "cannot hash A provider"
SHA_B_PRE=$(prov_sha "$PID_B_PRE") || fail_cell "cannot hash B provider"
[ -n "$SHA_A_PRE" ] && [ -n "$SHA_B_PRE" ] || fail_cell "empty provider hash"
fact "stat-a-pre=$STAT_A_PRE sha-a-pre=$SHA_A_PRE"
fact "stat-b-pre=$STAT_B_PRE sha-b-pre=$SHA_B_PRE"
[ "$SHA_A_PRE" = "$SHA_B_PRE" ] || fail_cell "A and B provider bytes differ pre-copy-up"

say "=== pre-copy-up captures ==="
run_inventory kernel "$WORK/d1-pre-kernel.json" || fail_cell "pre kernel inventory failed"
run_inventory userspace "$WORK/d1-pre-userspace.json" || fail_cell "pre userspace inventory failed"
start_profile pre-a "$CG_A" "$DURATION" "$WORK/d1-pre-a.json"
PID_CAP_A=$STARTED_PID
start_profile pre-b "$CG_B" "$DURATION" "$WORK/d1-pre-b.json"
PID_CAP_B=$STARTED_PID
wait_ready pre-a "$PID_CAP_A" || fail_cell "pre profile A never became ready"
wait_ready pre-b "$PID_CAP_B" || fail_cell "pre profile B never became ready"
dcli exec "$D1_A" touch /tmp/gate || fail_cell "gate release failed for $D1_A"
dcli exec "$D1_B" touch /tmp/gate || fail_cell "gate release failed for $D1_B"
wait "$PID_CAP_A" || fail_cell "pre profile A failed"
wait "$PID_CAP_B" || fail_cell "pre profile B failed"
reclaim_root_output "$WORK/d1-pre-a.json" "$WORK/d1-pre-b.json" || fail_cell "cannot reclaim pre profiles"
save_logs "$D1_A" "$WORK/logs-a-pre.txt" || fail_cell "cannot read $D1_A logs"
save_logs "$D1_B" "$WORK/logs-b-pre.txt" || fail_cell "cannot read $D1_B logs"
ledger_is "$WORK/logs-a-pre.txt" "$ITERS_A" || fail_cell "A ledger is not 6x$ITERS_A"
ledger_is "$WORK/logs-b-pre.txt" "$ITERS_B" || fail_cell "B ledger is not 6x$ITERS_B"
grep -h '^LEDGER ' "$WORK/logs-a-pre.txt" "$WORK/logs-b-pre.txt" >>"$FACTS"

say "=== same-bytes copy-up in B only (OQ5) ==="
STAT_B_COPY_PRE=$(prov_stat "$PID_B_PRE") || fail_cell "cannot re-stat B provider"
dcli exec "$D1_B" sh -c 'p=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; cp "$p" /tmp/p && cat /tmp/p > "$p" && rm /tmp/p' \
    || fail_cell "copy-up exec failed in $D1_B"
STAT_B_POST=$(prov_stat "$PID_B_PRE") || fail_cell "cannot stat B provider after copy-up"
SHA_B_POST=$(prov_sha "$PID_B_PRE") || fail_cell "cannot hash B provider after copy-up"
STAT_A_CHECK=$(prov_stat "$PID_A") || fail_cell "cannot re-stat A provider"
fact "stat-b-copy-pre=$STAT_B_COPY_PRE stat-b-post=$STAT_B_POST sha-b-post=$SHA_B_POST stat-a-check=$STAT_A_CHECK"
[ "$STAT_B_COPY_PRE" != "$STAT_B_POST" ] || fail_cell "copy-up changed no inode (stat $STAT_B_POST)"
[ "$SHA_B_POST" = "$SHA_B_PRE" ] || fail_cell "copy-up changed bytes (not same-bytes)"
[ "$STAT_A_CHECK" = "$STAT_A_PRE" ] || fail_cell "A provider moved during B copy-up"

say "=== restart B so it maps the upper copy ==="
dcli restart "$D1_B" >/dev/null || fail_cell "restart failed for $D1_B"
i=0
while [ "$(save_logs "$D1_B" "$WORK/logs-b-post.txt" && grep -c '^READY ' "$WORK/logs-b-post.txt")" -lt 2 ] \
        && [ "$i" -lt 240 ]; do
    sleep 0.5
    i=$((i + 1))
done
[ "$(grep -c '^READY ' "$WORK/logs-b-post.txt")" -ge 2 ] || fail_cell "restarted $D1_B never became ready"
PID_B_POST=$(container_pid "$D1_B") || fail_cell "no pid for restarted $D1_B"
CG_B_POST=$(cg_of_pid "$PID_B_POST") || fail_cell "no cgroup for restarted $D1_B"
STAT_B_RESTART=$(prov_stat "$PID_B_POST") || fail_cell "cannot stat restarted B provider"
SHA_B_RESTART=$(prov_sha "$PID_B_POST") || fail_cell "cannot hash restarted B provider"
fact "pid-b-post=$PID_B_POST cgroup-b-post=$CG_B_POST stat-b-restart=$STAT_B_RESTART sha-b-restart=$SHA_B_RESTART"
[ "$STAT_B_RESTART" = "$STAT_B_POST" ] || fail_cell "restarted B maps $STAT_B_RESTART, want upper $STAT_B_POST"
[ "$SHA_B_RESTART" = "$SHA_B_PRE" ] || fail_cell "restarted B bytes differ"

say "=== post-copy-up captures ==="
run_inventory kernel "$WORK/d1-post-kernel.json" || fail_cell "post kernel inventory failed"
run_inventory userspace "$WORK/d1-post-userspace.json" || fail_cell "post userspace inventory failed"
start_profile post-b "$CG_B_POST" "$DURATION" "$WORK/d1-post-b.json"
PID_CAP_BP=$STARTED_PID
wait_ready post-b "$PID_CAP_BP" || fail_cell "post profile B never became ready"
dcli exec "$D1_B" touch /tmp/gate || fail_cell "gate release failed for restarted $D1_B"
wait "$PID_CAP_BP" || fail_cell "post profile B failed"
reclaim_root_output "$WORK/d1-post-b.json" || fail_cell "cannot reclaim post profile B"
save_logs "$D1_B" "$WORK/logs-b-post.txt" || fail_cell "cannot read restarted $D1_B logs"
awk '/^READY /{n++} n>=2' "$WORK/logs-b-post.txt" >"$WORK/logs-b-post-run.txt"
ledger_is "$WORK/logs-b-post-run.txt" "$ITERS_B" || fail_cell "restarted B ledger is not 6x$ITERS_B"
grep -h '^LEDGER ' "$WORK/logs-b-post.txt" >>"$FACTS"

if [ "$LANE" = "B" ]; then
    printf '%s\n' "D-C7-3 applies: post-copy-up userspace edge to the upper mapping is backend-divergent per docs/known-limitations.md; the kernel refusal with identity_mismatch is the correct leg." >"$WORK/dc73-note.txt"
else
    printf '%s\n' "D-C7-3 does not apply on lane A: neither backend joins the upper mapping (parity none, disclosed)." >"$WORK/dc73-note.txt"
fi
fact "dc73-note=$(cat "$WORK/dc73-note.txt")"

say "=== oracle ==="
if python3 -I "$ORACLE" copy-up --lane "$LANE" \
        --pre-kernel "$WORK/d1-pre-kernel.json" \
        --pre-userspace "$WORK/d1-pre-userspace.json" \
        --post-kernel "$WORK/d1-post-kernel.json" \
        --post-userspace "$WORK/d1-post-userspace.json" \
        --pre-profile-a "$WORK/d1-pre-a.json" \
        --pre-profile-b "$WORK/d1-pre-b.json" \
        --post-profile-b "$WORK/d1-post-b.json" \
        --pid-a "$PID_A" --pid-b-pre "$PID_B_PRE" --pid-b-post "$PID_B_POST" \
        --iters-a "$ITERS_A" --iters-b "$ITERS_B" \
        --dc73-note "$WORK/dc73-note.txt" \
        >"$WORK/oracle.json" 2>"$WORK/oracle.err"; then
    cat "$WORK/oracle.json" >>"$SUMMARY_JSONL"
    cat "$WORK/oracle.json" >>"$FACTS"
    pass_cell "D1 lane $LANE copy-up verdict recorded"
else
    cat "$WORK/oracle.err" >&2 || true
    cat "$WORK/oracle.err" >>"$FACTS" || true
    fail_cell "oracle refused the D1 evidence"
fi
