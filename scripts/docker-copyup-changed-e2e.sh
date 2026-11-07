#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Cell D1-changed: Docker different-bytes copy-up (dev host, lane B only).
#
# One container B starts from the holder image (deploy/Dockerfile.holder,
# reused verbatim: pinned ubuntu:26.04 base, SoftHSM2, ledgered `gated`
# client plus the patch-unmapped tool). B's first process maps the
# provider through an overlay lower layer and holds at its gate. The
# driver then flips one unmapped provider byte inside B (patch-unmapped:
# a non-SHF_ALLOC section, so no mapped page changes and the provider
# keeps working), which copies the file up with DIFFERENT bytes (a new
# upper inode, a new sha256). No byte-identical collapse can preempt the
# kernel witness after that. A second process in B maps the upper copy;
# a cgroup profile of B then counts the stale ledger S on the
# witness-proven lower row (layer pre_copy_up) and the fresh ledger F on
# the upper row, both exact, with S != F so a swapped routing fails.
# Settled single-pass inventory captures (kernel + userspace) split the
# same way: the kernel leg attributes B-pre to the lower module and B2
# to the upper module (mapped, deep_scan, gap-free, no collapse, no
# loss); the userspace leg honestly gaps both joins (no witness there).
# The observer is the host release binary run through `sudo -n` in the
# initial PID namespace.
#
# The CONTROLLER runs every docker/sudo command below. Workers only run
# `sh $0 --self-test`, which is unprivileged (PATH stubs) and proves the
# arg refusals, the pins, the cleanup trap and the oracle mutations.
set -eu
cd "$(dirname "$0")/.."

ORACLE=scripts/container-cells-oracle.py
HOLDER_DOCKERFILE=deploy/Dockerfile.holder
# Pinned base reused from deploy/Dockerfile.holder (both FROM lines); the
# self-test requires the Dockerfile to carry exactly this digest twice.
HOLDER_BASE=ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e
PROVIDER_PATH=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
ITERS_S_DEFAULT=250
ITERS_F_DEFAULT=100
DURATION_DEFAULT=30
# The second mapper in B: the ledgered client on the image's own token,
# mapped after the patch so it runs the upper copy.
GATED=/usr/local/bin/p11scope-ledger-gated
PATCHER=/usr/local/bin/p11scope-patch-unmapped
B2_GATE=/tmp/gate-b2

usage() {
    cat >&2 <<'EOF'
usage: scripts/docker-copyup-changed-e2e.sh --host dev --observer BIN [options]
       scripts/docker-copyup-changed-e2e.sh --self-test | --help

  Cell D1-changed driver (different-bytes copy-up, both mappers ledgered
  exact). Run flow: build the holder image, start container B, capture
  pre-copy-up evidence, flip one unmapped provider byte inside B (the
  different-bytes copy-up), start a second mapper on the upper copy,
  profile B's cgroup across both ledgers, capture settled kernel and
  userspace inventories, and check everything with
  scripts/container-cells-oracle.py copy-up-changed.

  --host dev            use the local docker daemon (dev host only)
  --observer BIN        host release p11scope binary (run through sudo -n)
  --image NAME          image name (default p11scope-ctr-changed:$TOKEN)
  --token TOKEN         run token, short [a-z0-9-] (default <time>-<pid>)
  --iters-s N           stale ledger iterations for B-pre (default 250)
  --iters-f N           fresh ledger iterations for B2 (default 100, != S)
  --duration S          profile capture seconds (default 30)
  --work DIR            evidence directory (must not exist; default fresh 0700
                        under $TMPDIR)
  --keep                keep container/image for debugging (prints the delete
                        commands)
  --self-test           unprivileged checks (PATH stubs, no docker)
  --help                this text

Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 UNRUN (cell not run, see SUMMARY reason).
Every run prints a final SUMMARY line: SUMMARY cell=D1-changed host=... verdict=... reason="...".

CONTROLLER (run order):
  # D1-changed on the dev host (from the repo root; BIN = host release binary).
  # Exact rerun flags: iters 250/100, duration 30.
  sh scripts/docker-copyup-changed-e2e.sh --host dev --observer BIN --token <TOKEN> --iters-s 250 --iters-f 100 --duration 30
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

# R4 lane from the kernel release (same table as D1: A = 6.1/6.6 maps
# keyed by backing inode, B = 6.8+/7.x keyed by overlay inode). D1-changed
# rows are lane-B only: the stale VMA keying on lane A is unqualified for
# this cell, so the run path refuses any other lane as UNRUN.
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
    [ "$ITERS_S_DEFAULT" -eq 250 ] && [ "$ITERS_F_DEFAULT" -eq 100 ] \
        || { echo "ledger defaults drifted" >&2; exit 1; }
    [ "$ITERS_S_DEFAULT" -ne "$ITERS_F_DEFAULT" ] \
        || { echo "equal default ledgers cannot pin the routing" >&2; exit 1; }
    for kernel in 6.1.188:A 6.6.157:A 6.8.0-142-generic:B 6.12.111:B \
                  7.0.0-34-generic:B 7.2.9:B 7.3.1:B; do
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
               "--host dev --observer /bin/true --iters-s 0" \
               "--host dev --observer /bin/true --iters-f 01" \
               "--host dev --observer /bin/true --iters-s 100 --iters-f 100" \
               "--host dev --observer /bin/true --duration x" \
               "--host fedora-private --observer /bin/true" \
               "--bogus" "--keep --bogus"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || {
            echo "d1-changed driver exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    # The run-log note discloses copy-up-stale-caller, and the oracle call
    # proves the copy-up from facts.log. The bracketed letters keep these
    # greps from matching their own lines.
    grep -q 'copy-up-stale-caller.*run-no[t]e' "$0" \
        || { echo "driver lost its copy-up-stale-caller note" >&2; exit 1; }
    grep -q -- '--facts-log "\$FACT[S]"' "$0" \
        || { echo "oracle call lost --facts-log" >&2; exit 1; }
    grep -q -- '--run-note "\$WORK/run-note.tx[t]"' "$0" \
        || { echo "oracle call lost --run-note" >&2; exit 1; }
    grep -q -- '--pid-b2 "\$PID_B[2]"' "$0" \
        || { echo "oracle call lost --pid-b2" >&2; exit 1; }
    grep -q -- '--iters-s "\$ITERS_[S]"' "$0" \
        || { echo "oracle call lost --iters-s" >&2; exit 1; }
    grep -q -- '--iters-f "\$ITERS_[F]"' "$0" \
        || { echo "oracle call lost --iters-f" >&2; exit 1; }
    grep -q -- '--profile "\$WORK/changed-profile-b.jso[n]"' "$0" \
        || { echo "oracle call lost --profile" >&2; exit 1; }
    grep -q 'release_gate "\$PID_B2" "\$B2_GAT[E]"' "$0" \
        || { echo "second mapper gate is not released from the host" >&2; exit 1; }
    grep -q 'lower-stack-b=\$LOWER_STACK_[B]' "$0" \
        || { echo "facts lost the lower-stack-b depth" >&2; exit 1; }
    grep -q 'lane B onl[y]' "$0" \
        || { echo "run path lost its lane-B-only gate" >&2; exit 1; }
    grep -q 'PATCHER.*PROVIDER_PAT[H]' "$0" \
        || { echo "run path lost the unmapped-byte patch" >&2; exit 1; }
    d1c_help_self_test
    d1c_stub_self_test
    python3 -I "$ORACLE" --self-test
    echo "docker-copyup-changed-e2e self-test: OK"
    exit 0
}

d1c_help_self_test() {
    help=$(sh "$0" --help 2>&1 || true)
    for marker in "--host dev --observer BIN" "SUMMARY cell=D1-changed" \
                  "--iters-s 250 --iters-f 100 --duration 30"; do
        case $help in
            *"$marker"*) ;;
            *) echo "help lost its controller line: $marker" >&2; exit 1 ;;
        esac
    done
}

d1c_stub_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-d1c-stub-XXXXXX")
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
    # Storage-driver gate: overlay2 (classic store) and overlayfs (the
    # containerd image store snapshotter, Docker 29 default) proceed;
    # anything else is UNRUN.
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
if [ "$1" = "info" ]; then printf '%s\n' "$STUB_DRIVER"; exit 0; fi
echo "unexpected docker call: $*" >&2; exit 1
EOF
    chmod +x "$stub/docker"
    STUB_DRIVER=overlay2 PATH="$stub:$PATH" require_overlay2 \
        || { echo "overlay2 wrongly refused" >&2; exit 1; }
    STUB_DRIVER=overlayfs PATH="$stub:$PATH" require_overlay2 \
        || { echo "overlayfs wrongly refused" >&2; exit 1; }
    if STUB_DRIVER=btrfs PATH="$stub:$PATH" require_overlay2 \
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
    # Gate releases go through the host's /proc view: the holder default and
    # the second mapper's own gate file.
    got=$(PATH="$stub/echobin:$stub" release_gate 9999)
    [ "$got" = "SUDO -n touch /proc/9999/root/tmp/gate" ] \
        || { echo "default gate release drifted: $got" >&2; exit 1; }
    got=$(PATH="$stub/echobin:$stub" release_gate 9999 /tmp/gate-b2)
    [ "$got" = "SUDO -n touch /proc/9999/root/tmp/gate-b2" ] \
        || { echo "second mapper gate release drifted: $got" >&2; exit 1; }
    # LEDGER lines: exactly one complete JSON ledger with 6xN successes.
    ledger_log() {
        printf '%s\n' "$2" > "$stub/$1.log"
    }
    ledger_log good "READY pid=1
LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":1,\"complete\":true,\"functions\":[{\"name\":\"C_GenerateRandom\",\"attempts\":100,\"successful\":100},{\"name\":\"C_DigestInit\",\"attempts\":100,\"successful\":100},{\"name\":\"C_Digest\",\"attempts\":100,\"successful\":100},{\"name\":\"C_FindObjectsInit\",\"attempts\":100,\"successful\":100},{\"name\":\"C_FindObjects\",\"attempts\":100,\"successful\":100},{\"name\":\"C_FindObjectsFinal\",\"attempts\":100,\"successful\":100}]}"
    PATH="$stub:$PATH" ledger_is "$stub/good.log" 100 \
        || { echo "good LEDGER refused" >&2; exit 1; }
    ledger_log short "LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":1,\"complete\":true,\"functions\":[{\"name\":\"C_GenerateRandom\",\"attempts\":99,\"successful\":99}]}"
    ledger_log missing "READY pid=1"
    for bad in short missing; do
        if PATH="$stub:$PATH" ledger_is "$stub/$bad.log" 100 >/dev/null 2>&1; then
            echo "bad LEDGER accepted: $bad" >&2
            exit 1
        fi
    done
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
    if STUB_NAMES="d1c-b-t" PATH="$stub:$PATH" assert_name_free d1c-b-t >/dev/null 2>&1; then
        echo "existing container name accepted" >&2
        exit 1
    fi
    STUB_NAMES="" PATH="$stub:$PATH" assert_name_free d1c-b-t \
        || { echo "free container name refused" >&2; exit 1; }
    # Cleanup trap: its own container and image, nothing else.
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "docker $*" >> "$STUB_CALLS"
EOF
    chmod +x "$stub/docker"
    : > "$stub/calls.txt"
    # shellcheck disable=SC2034
    STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" \
        D1C_B=d1c-b-t D1C_IMAGE=img:t cleanup_owned \
        || { echo "cleanup_owned failed" >&2; exit 1; }
    grep -q "docker rm -f d1c-b-t" "$stub/calls.txt" \
        || { echo "cleanup lost its container removal" >&2; exit 1; }
    grep -q "docker image rm -f img:t" "$stub/calls.txt" \
        || { echo "cleanup lost its image removal" >&2; exit 1; }
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
    # Overlay upper directory: the root mount's upperdir only.
    printf '%s\n' \
        '612 540 0:140 / / rw,relatime master:1 - overlay overlay rw,lowerdir=/s/2/fs:/s/1/fs,upperdir=/s/9/fs,workdir=/s/9/work' \
        '613 612 0:141 / /proc rw - proc proc rw' > "$stub/mi-overlay"
    got=$(D1_MOUNTINFO_FILE=$stub/mi-overlay upper_of_pid 1234) \
        || { echo "overlay upperdir refused" >&2; exit 1; }
    [ "$got" = "/s/9/fs" ] || { echo "upperdir resolved to $got" >&2; exit 1; }
    printf '%s\n' '45 1 0:35 /@ / rw,noatime shared:1 - btrfs /dev/sda3 rw,upperdir=/x' > "$stub/mi-btrfs"
    printf '%s\n' '612 540 0:140 / / rw - overlay overlay ro,lowerdir=/s/2/fs:/s/1/fs' > "$stub/mi-ro"
    for mi in mi-btrfs mi-ro; do
        if D1_MOUNTINFO_FILE=$stub/$mi upper_of_pid 1234 >/dev/null 2>&1; then
            echo "upperdir accepted from $mi" >&2
            exit 1
        fi
    done
    # Lower-layer stack depth: the root mount's lowerdir entry count.
    got=$(D1_MOUNTINFO_FILE=$stub/mi-overlay lower_stack_of_pid 1234) \
        || { echo "overlay lower stack refused" >&2; exit 1; }
    [ "$got" = "2" ] || { echo "lower stack resolved to $got" >&2; exit 1; }
    if D1_MOUNTINFO_FILE=$stub/mi-btrfs lower_stack_of_pid 1234 >/dev/null 2>&1; then
        echo "lower stack accepted from btrfs" >&2
        exit 1
    fi
    rm -rf "$stub"
    trap - EXIT
}

# ------------------------------------------------------------------ run path

# Docker through the local daemon (dev host only; this cell has no
# fedora-private mode).
dcli() {
    docker "$@"
}

# The host observer always runs through passwordless sudo, args verbatim.
obs() {
    sudo -n "$OBSERVER" "$@"
}

# D1-changed rows are overlay-specific: overlay2 (classic store) or
# overlayfs (the containerd snapshotter); any other storage driver is
# UNRUN, recorded.
require_overlay2() {
    drv=$(dcli info --format '{{.Driver}}' 2>/dev/null) \
        || { echo "docker info failed" >&2; return 1; }
    case $drv in
        overlay2|overlayfs) ;;
        *) echo "storage driver is $drv, want overlay2 or overlayfs" >&2; return 1 ;;
    esac
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

say() {
    printf '%s\n' "$1"
}

fact() {
    printf '%s\n' "$1" >>"$FACTS"
}

summarize() {
    line="SUMMARY cell=D1-changed host=${HOST-none} verdict=$1 reason=\"$2\""
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
    if [ "${KEEP:-0}" -eq 1 ]; then
        echo "kept container ${D1C_B-} and image ${D1C_IMAGE-} (--keep): delete with: docker rm -f ${D1C_B-}; docker image rm -f ${D1C_IMAGE-}" >&2
    elif [ -n "${OWNED-}" ]; then
        cleanup_owned
    fi
    if [ -n "${WORK-}" ]; then
        echo "evidence directory: $WORK" >&2
    fi
    exit "$CLEANUP_STATUS"
}

# Its own container and image, nothing else (the trap calls this).
cleanup_owned() {
    dcli rm -f "$D1C_B" >/dev/null 2>&1 || true
    dcli image rm -f "$D1C_IMAGE" >/dev/null 2>&1 || true
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

# Cgroup v2 path of a pid, verified as a directory. D1_CGROUP_FILE and
# D1_CGROUP_ROOT are self-test hooks.
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

# Overlay upper directory of a container's root mount. D1_MOUNTINFO_FILE
# is a self-test hook.
upper_of_pid() {
    if [ -n "${D1_MOUNTINFO_FILE-}" ]; then
        info=$(cat "$D1_MOUNTINFO_FILE") || return 1
    else
        info=$(sudo -n cat "/proc/$1/mountinfo") || return 1
    fi
    up=$(printf '%s\n' "$info" | awk '
        $5 == "/" {
            for (i = 7; i <= NF && $i != "-"; i++) ;
            if ($(i + 1) != "overlay") { exit }
            n = split($(i + 3), opt, ",")
            for (j = 1; j <= n; j++) {
                if (opt[j] ~ /^upperdir=\//) { print substr(opt[j], 10); exit }
            }
        }')
    [ -n "$up" ] || { echo "no overlay upperdir on the root mount of pid $1" >&2; return 1; }
    printf '%s\n' "$up"
}

lower_stack_of_pid() {
    if [ -n "${D1_MOUNTINFO_FILE-}" ]; then
        info=$(cat "$D1_MOUNTINFO_FILE") || return 1
    else
        info=$(sudo -n cat "/proc/$1/mountinfo") || return 1
    fi
    depth=$(printf '%s\n' "$info" | awk '
        $5 == "/" {
            for (i = 7; i <= NF && $i != "-"; i++) ;
            if ($(i + 1) != "overlay") { exit }
            n = split($(i + 3), opt, ",")
            for (j = 1; j <= n; j++) {
                if (opt[j] ~ /^lowerdir=\//) {
                    stack = substr(opt[j], 10)
                    print gsub(/:/, ":", stack) + 1
                    exit
                }
            }
        }')
    [ -n "$depth" ] || { echo "no overlay lowerdir on the root mount of pid $1" >&2; return 1; }
    printf '%s\n' "$depth"
}

upper_has() {
    sudo -n test -e "$1$PROVIDER_PATH"
}

upper_stat() {
    sudo -n stat -c '%d:%i %s' "$1$PROVIDER_PATH"
}

upper_sha() {
    sudo -n sha256sum "$1$PROVIDER_PATH" | awk '{print $1}'
}

# Create a container's gate file from the host through its own root: a
# `docker exec touch` would add short-lived processes to the captured
# cgroup, which the capture rightly counts as pid_descendant_gaps.
# The gate path defaults to the holder's /tmp/gate; the second mapper
# waits on its own gate file.
release_gate() {
    sudo -n touch "/proc/$1/root${2:-/tmp/gate}"
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

wait_file_line() {
    i=0
    while [ "$i" -lt "$(($3 * 2))" ]; do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.5
        i=$((i + 1))
    done
    echo "$1 never printed $2" >&2
    return 1
}

save_logs() {
    dcli logs "$1" >"$2" 2>&1 || return 1
}

# A second process in B maps the provider after the patch, so it maps
# the upper copy while B's first process keeps the lower one. The driver
# releases its gate inside the profile window, so its ledgered rounds
# count fresh calls on the upper edge.
start_second_mapper() {
    dcli exec "$D1C_B" sh -c "SOFTHSM2_CONF=/tmp/softhsm2.conf exec $GATED $PROVIDER_PATH $ITERS_F 200 $B2_GATE" \
        >"$WORK/b2.log" 2>&1 &
    CAPTURE_PIDS="${CAPTURE_PIDS-} $!"
}

# Host PID of the process in cgroup $1 whose command line contains $2.
pid_in_cgroup_with() {
    for p in $(cat "$1/cgroup.procs"); do
        if sudo -n cat "/proc/$p/cmdline" 2>/dev/null | tr '\0' ' ' | grep -Fq -- "$2"; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    echo "no process in $1 runs $2" >&2
    return 1
}

maps_provider() {
    sudo -n grep -Fq "$PROVIDER_PATH" "/proc/$1/maps"
}

build_image() {
    [ "$(grep -c "FROM $HOLDER_BASE" "$HOLDER_DOCKERFILE")" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; return 1; }
    dcli build -q -f "$HOLDER_DOCKERFILE" -t "$D1C_IMAGE" . || return 1
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

HOST=
OBSERVER=
IMAGE=
TOKEN=
ITERS_S=$ITERS_S_DEFAULT
ITERS_F=$ITERS_F_DEFAULT
DURATION=$DURATION_DEFAULT
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
        --iters-s) [ "$#" -ge 2 ] || usage; ITERS_S=$2; shift 2 ;;
        --iters-f) [ "$#" -ge 2 ] || usage; ITERS_F=$2; shift 2 ;;
        --duration) [ "$#" -ge 2 ] || usage; DURATION=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || usage; [ -z "$WORK_OPT" ] || usage; WORK_OPT=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[ -n "$HOST" ] || usage
case $HOST in
    dev) ;;
    *) usage ;;
esac
[ -n "$OBSERVER" ] || usage
[ -x "$OBSERVER" ] || { echo "observer $OBSERVER is not executable" >&2; exit 2; }
[ -z "$TOKEN" ] || valid_token "$TOKEN" || usage
TOKEN=${TOKEN:-$(date +%s)-$$}
valid_token "$TOKEN" || usage
valid_count "$ITERS_S" || usage
valid_count "$ITERS_F" || usage
[ "$ITERS_S" != "$ITERS_F" ] || usage
valid_count "$DURATION" || usage

. scripts/lib.sh
require_non_root_caller || unrun "run as a non-root user with passwordless sudo"
for command in docker python3 stat sha256sum awk grep; do
    command -v "$command" >/dev/null || unrun "$command required"
done
sudo -n true 2>/dev/null || unrun "passwordless sudo required (sudo -n true)"

if [ -n "$WORK_OPT" ]; then
    [ ! -e "$WORK_OPT" ] || { echo "work dir $WORK_OPT already exists" >&2; exit 2; }
    mkdir -m 0700 "$WORK_OPT"
    WORK=$(cd "$WORK_OPT" && pwd -P)
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-d1c-XXXXXX")
    chmod 0700 "$WORK"
fi
FACTS=$WORK/facts.log
SUMMARY_JSONL=$WORK/summary.jsonl
: >"$FACTS"
: >"$SUMMARY_JSONL"
. scripts/cleanup-traps.sh

D1C_B=d1c-b-$TOKEN
D1C_IMAGE=${IMAGE:-p11scope-ctr-changed:$TOKEN}
OWNED=1
CAPTURE_PIDS=

fact "cell=D1-changed host=$HOST token=$TOKEN date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fact "observer=$OBSERVER sha256=$(sha256sum "$OBSERVER" | awk '{print $1}')"
fact "image=$D1C_IMAGE container=$D1C_B iters-s=$ITERS_S iters-f=$ITERS_F duration=$DURATION"
fact "kernel=$(uname -sr) $(uname -m)"
LANE=$(lane_for_kernel "$(uname -r)") || unrun "kernel $(uname -r) has no R4 lane row"
fact "lane=$LANE"
case $LANE in
    B) ;;
    *) unrun "D1-changed rows are lane B only (lane $LANE unqualified)" ;;
esac
fact "kind: not used (docker-only cell); kubectl: not used (docker-only cell)"

docker_info=$(dcli info --format '{{.Driver}} {{.ServerVersion}}' 2>/dev/null) \
    || unrun "docker info failed"
fact "docker-info=$docker_info"
cgroup_driver=$(dcli info --format '{{.CgroupDriver}}' 2>/dev/null) \
    || unrun "docker info failed"
fact "cgroup-driver=$cgroup_driver"
docker_root=$(dcli info --format '{{.DockerRootDir}}' 2>/dev/null) \
    || unrun "docker info failed"
fact "docker-root=$docker_root backing-fs=$(stat -f -c '%T' "$docker_root" 2>/dev/null)"
require_overlay2 || unrun "storage driver is not overlay2/overlayfs; D1-changed rows are overlay-specific"
grep -E ' overlay ' /proc/mounts | head -5 >>"$FACTS" || true
assert_name_free "$D1C_B" || unrun "container $D1C_B already exists"

build_image || fail_cell "image build failed"
fact "downloads: base $HOLDER_BASE; apt archive packages per $HOLDER_DOCKERFILE (gcc, softhsm2; unpinned, repeatable not bit-reproducible)"
fact "image-id=$(dcli inspect --format '{{.Id}}' "$D1C_IMAGE")"

say "=== start container B ($ITERS_S stale rounds held) ==="
dcli run -d --name "$D1C_B" "$D1C_IMAGE" ledger "$ITERS_S" || fail_cell "container $D1C_B failed to start"
wait_docker_log "$D1C_B" '^READY ' 120 || fail_cell "container $D1C_B never became ready"
PID_B_PRE=$(container_pid "$D1C_B") || fail_cell "no pid for $D1C_B"
CG_B=$(cg_of_pid "$PID_B_PRE") || fail_cell "no cgroup for $D1C_B"
fact "pid-b-pre=$PID_B_PRE cgroup-b=$CG_B"
fact "cid-b=$(dcli inspect --format '{{.Id}}' "$D1C_B")"
maps_provider "$PID_B_PRE" || fail_cell "B's first process does not map the provider"
STAT_B_PRE=$(prov_stat "$PID_B_PRE") || fail_cell "cannot stat B provider"
SHA_B_PRE=$(prov_sha "$PID_B_PRE") || fail_cell "cannot hash B provider"
[ -n "$SHA_B_PRE" ] || fail_cell "empty provider hash"
LOWER_STACK_B=$(lower_stack_of_pid "$PID_B_PRE") || fail_cell "no lower stack for $D1C_B"
fact "stat-b-pre=$STAT_B_PRE sha-b-pre=$SHA_B_PRE lower-stack-b=$LOWER_STACK_B"
UPPER_B=$(upper_of_pid "$PID_B_PRE") || fail_cell "no overlay upper layer for $D1C_B"
fact "upper-b=$UPPER_B"
if upper_has "$UPPER_B"; then fail_cell "B provider is already in its upper layer"; fi
save_logs "$D1C_B" "$WORK/logs-b-pre.txt" || fail_cell "cannot read $D1C_B logs"
grep -h '^TARGET ' "$WORK/logs-b-pre.txt" >>"$FACTS" || fail_cell "B-pre printed no TARGET lines"

say "=== different-bytes copy-up in B (unmapped-byte patch) ==="
PATCH_OUT=$(dcli exec "$D1C_B" "$PATCHER" "$PROVIDER_PATH" 2>&1) \
    || fail_cell "patch exec failed in $D1C_B: $PATCH_OUT"
fact "patch=$PATCH_OUT"
maps_provider "$PID_B_PRE" || fail_cell "B's first process no longer maps the provider after the patch"
STAT_B_POST=$(prov_stat "$PID_B_PRE") || fail_cell "cannot stat B provider after the patch"
SHA_B_POST=$(prov_sha "$PID_B_PRE") || fail_cell "cannot hash B provider after the patch"
fact "stat-b-post=$STAT_B_POST sha-b-post=$SHA_B_POST"
# The overlay merge view keeps the origin inode across copy-up (same as
# D1: stat-b-post == stat-b-pre); the copy-up proof is the changed
# bytes plus the new upper file below, not a merge-inode change.
[ "$SHA_B_POST" != "$SHA_B_PRE" ] || fail_cell "patch changed no bytes (not different-bytes)"
upper_has "$UPPER_B" || fail_cell "copy-up left no provider in B's upper layer"
UPPER_STAT_B=$(upper_stat "$UPPER_B") || fail_cell "cannot stat B upper provider"
UPPER_SHA_B=$(upper_sha "$UPPER_B") || fail_cell "cannot hash B upper provider"
fact "upper-stat-b=$UPPER_STAT_B upper-sha-b=$UPPER_SHA_B"
[ "$UPPER_SHA_B" = "$SHA_B_POST" ] || fail_cell "upper bytes are not the merge bytes"
[ "$UPPER_STAT_B" != "$STAT_B_PRE" ] || fail_cell "upper inode is the pre inode"

say "=== second mapper in B maps the upper copy ==="
start_second_mapper
wait_file_line "$WORK/b2.log" '^READY ' 60 || fail_cell "second mapper in $D1C_B never became ready"
PID_B2=$(pid_in_cgroup_with "$CG_B" "$B2_GATE") || fail_cell "no host pid for the second mapper"
maps_provider "$PID_B2" || fail_cell "second mapper does not map the provider"
maps_provider "$PID_B_PRE" || fail_cell "B's first process no longer maps the provider"
STAT_B2=$(prov_stat "$PID_B2") || fail_cell "cannot stat the second mapper's provider"
fact "pid-b2=$PID_B2 stat-b2=$STAT_B2"
grep -h '^TARGET ' "$WORK/b2.log" >>"$FACTS" || fail_cell "second mapper printed no TARGET lines"

say "=== cgroup profile of B across both ledgers ==="
start_profile changed-b "$CG_B" "$DURATION" "$WORK/changed-profile-b.json"
PID_PROF=$STARTED_PID
wait_ready changed-b "$PID_PROF" || fail_cell "profile of B never became ready"
release_gate "$PID_B_PRE" || fail_cell "gate release failed for B's first process"
release_gate "$PID_B2" "$B2_GATE" || fail_cell "gate release failed for the second mapper"
wait_docker_log "$D1C_B" '^LEDGER ' 120 || fail_cell "stale ledger never completed"
wait_file_line "$WORK/b2.log" '^LEDGER ' 120 || fail_cell "fresh ledger never completed"
kill -0 "$PID_PROF" 2>/dev/null || fail_cell "a ledger completed outside the capture window"
wait "$PID_PROF" || fail_cell "profile of B failed"
reclaim_root_output "$WORK/changed-profile-b.json" || fail_cell "cannot reclaim profile of B"
save_logs "$D1C_B" "$WORK/logs-b.txt" || fail_cell "cannot read $D1C_B logs"
ledger_is "$WORK/logs-b.txt" "$ITERS_S" || fail_cell "stale ledger is not 6x$ITERS_S"
ledger_is "$WORK/b2.log" "$ITERS_F" || fail_cell "fresh ledger is not 6x$ITERS_F"
grep -h '^LEDGER ' "$WORK/logs-b.txt" >>"$FACTS"
grep -h '^LEDGER ' "$WORK/b2.log" >>"$FACTS"

say "=== settled inventories after both ledgers ==="
maps_provider "$PID_B_PRE" || fail_cell "B's first process no longer maps the provider"
maps_provider "$PID_B2" || fail_cell "second mapper no longer maps the provider"
run_inventory kernel "$WORK/changed-kernel.json" || fail_cell "kernel inventory failed"
run_inventory userspace "$WORK/changed-userspace.json" || fail_cell "userspace inventory failed"

printf '%s\n' "copy-up-stale-caller: after B's different-bytes copy-up (one unmapped provider byte patched: a new upper inode, a new sha256), B's pre-copy-up process keeps the lower file on its key module with layer pre_copy_up (kernel backend: mapped, deep_scan, gap-free, $ITERS_S stale calls counted on the lower profile row). The second mapper joins the upper file on its own module (mapped, deep_scan, gap-free, $ITERS_F fresh calls counted on the upper profile row). Every userspace leg honestly gaps both overlay joins (no kernel witness there). No named identity loss is expected on any leg." >"$WORK/run-note.txt"
fact "run-note=$(cat "$WORK/run-note.txt")"

say "=== oracle ==="
if python3 -I "$ORACLE" copy-up-changed \
        --kernel "$WORK/changed-kernel.json" \
        --userspace "$WORK/changed-userspace.json" \
        --profile "$WORK/changed-profile-b.json" \
        --pid-b-pre "$PID_B_PRE" --pid-b2 "$PID_B2" \
        --iters-s "$ITERS_S" --iters-f "$ITERS_F" \
        --run-note "$WORK/run-note.txt" \
        --facts-log "$FACTS" \
        >"$WORK/oracle.json" 2>"$WORK/oracle.err"; then
    cat "$WORK/oracle.json" >>"$SUMMARY_JSONL"
    cat "$WORK/oracle.json" >>"$FACTS"
    cat "$WORK/oracle.err" >>"$FACTS"
    pass_cell "D1-changed lane $LANE copy-up verdict recorded"
else
    cat "$WORK/oracle.err" >&2 || true
    cat "$WORK/oracle.err" >>"$FACTS" || true
    fail_cell "oracle refused the D1-changed evidence"
fi
