#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-inventory-c1b.sh — privileged cells and stage timings for C1b
# (inventory --system attributes callers past --max-scan-pids by maps identity).
#
#   qualify-inventory-c1b.sh P11SCOPE --base DIR [--cells "cap bind deleted"]
#   qualify-inventory-c1b.sh P11SCOPE --base DIR --measure TOTAL:CALLERS[:MAPPERS] [--cap N] [--duration S]
#                            [--cpus LIST]
#
# Every cell runs in its own PID and mount namespace (unshare --pid --fork
# --mount-proc --mount), so the host's own provider groups never compete with
# the fixture for the deep-scan cap and every process is reaped with the
# namespace. Workloads are tests/fixtures/public-cli/gated.c SoftHSM2 callers
# (Initialize/OpenSession/Login, then idle with the provider mapped) and idle
# `sleep` processes, all as RUNUID:RUNGID (default 1000:1000) under setpriv
# --no-new-privs with a clean environment. The observer runs as root.
#
# Cells (the judge is the python block at the end; exit 0 = every cell held):
#   cap      CALLERS=300 SoftHSM2 callers + IDLE=200 idle, --max-scan-pids 64:
#            every caller pid registers with a mapped edge to the provider;
#            no "discovery capped" loss, an "attribution complete" note.
#   bind     150 callers by the provider's path + 150 through a bind mount of
#            its directory, + 200 idle, cap 64: all 300 register, the bound
#            ones by maps identity under their bind path.
#   deleted  100 callers of a provider copy + 50 through a second hard link
#            that is then unlinked (their maps read "(deleted)"), + 200 idle,
#            cap 64: the 100 register; the 50 are never attributed and are
#            counted as deleted_mapping losses with a "maps attribution" gap.
#   collide  btrfs only: two fresh subvolumes under the workload dir, so the
#            first file of each gets the same inode number (257) and maps
#            renders both at one (device, inode). 150 callers load the
#            provider copy from one; 150 `sleep`s LD_PRELOAD an unrelated
#            .so from the other, + 200 idle, cap 64: the 150 callers
#            register, no collision mapper gets a provider edge, and the
#            unselected ones count as identity_mismatch losses.
#   overlay  300 callers load a provider copy through an overlayfs mount
#            (lower holds the file) + 200 idle, cap 64. Before kernel 6.8 the
#            VMA holds the BACKING file, so this is the shape where comparing
#            map_files with fstat would refuse every caller: all must
#            register by maps identity, with no identity loss. Run it on a
#            6.1/6.6 vng guest (scripts/qualify-inventory-c1b-vng.sh).
# --measure runs TOTAL processes (CALLERS of them SoftHSM2 callers) once with
# P11SCOPE_STAGE_TIMINGS=1 for DURATION seconds (default 30) at --cap
# (default 256) and prints per-stage p50/p95 over the passes (pass 1 apart).
# MAPPERS of the idle processes are `sleep` with LD_PRELOAD=MODULE: they map
# the provider (one more caller each) without a SoftHSM2 session, cheaply
# enough to push the caller count past the caller budget. --cpus pins the
# observer with `taskset -c LIST` (same cores for every binary compared). The
# `uptime` load is printed at the start and end of every cell and measurement;
# on a shared host compare binaries by interleaved runs, not absolute times.
#
# Shared hosts: wrap each invocation in `flock /var/tmp/p11scope-ws-tmp/privileged.lock`.
#
# BASE must be root-owned and not group/other-writable (created 0711 when
# missing). Never run under nohup. Temp I/O stays under BASE.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd) || exit 64
SELF=$REPO/scripts/$(basename "$0")
SRC=$REPO/tests/fixtures/public-cli/gated.c
MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
RUNUID=${RUNUID:-1000} RUNGID=${RUNGID:-1000}

die() { echo "qualify-inventory-c1b: $*" >&2; exit 70; }

# ---- inner: one cell inside its namespaces (pid 1 here) ----
if [ "${1:-}" = --inner ]; then
    shift
    CELL=$1 P=$2 WL=$3 OBS=$4 CALLERS=$5 IDLE=$6 CAP=$7 DURATION=$8 MAPPERS=${9:-0} CPUS=${10:-}
    mount --make-rprivate / || die "make-rprivate"
    AS=(setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups --no-new-privs
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C SOFTHSM2_CONF="$WL/token/softhsm2.conf")
    READY=$OBS/$CELL.ready
    : > "$READY"
    caller() { # PROVIDER_PATH: one idle SoftHSM2 caller; its READY line names its pid
        "${AS[@]}" "$WL/bin/gated" "$1" 0 0 "$WL/gate" >> "$READY" 2>> "$OBS/$CELL.callers.err" &
    }
    started=0
    callers_of() { # N PATH
        local i
        for ((i = 0; i < $1; i++)); do caller "$2"; sleep 0.01; done
        started=$((started + $1))
    }
    PATHS=()
    case $CELL in
        cap|measure)
            callers_of "$CALLERS" "$MODULE"; PATHS+=("$MODULE") ;;
        bind)
            install -d -m 0755 "$WL/bindmnt" || die "bind mountpoint"
            mount --bind "$(dirname "$MODULE")" "$WL/bindmnt" || die "bind mount"
            half=$((CALLERS / 2))
            callers_of "$half" "$MODULE"
            callers_of $((CALLERS - half)) "$WL/bindmnt/$(basename "$MODULE")"
            PATHS+=("$MODULE" "$WL/bindmnt/$(basename "$MODULE")") ;;
        deleted)
            doomed=$((CALLERS / 3))
            callers_of $((CALLERS - doomed)) "$WL/bin/copyD/libsofthsm2.so"
            # The kept callers start first: the group's deep-scan
            # representative (its lowest pid) maps the surviving name.
            for _ in $(seq 300); do
                [ "$(grep -c '^READY' "$READY")" -ge $((CALLERS - doomed)) ] && break
                sleep 0.1
            done
            callers_of "$doomed" "$WL/bin/copyD/doomed.so"
            PATHS+=("$WL/bin/copyD/libsofthsm2.so") ;;
        overlay)
            callers_of "$CALLERS" "$WL/ovl/merged/libsofthsm2.so"
            PATHS+=("$WL/ovl/merged/libsofthsm2.so") ;;
        collide)
            callers_of "$CALLERS" "$WL/s1/libsofthsm2.so"
            # The provider callers start first: the shared-key group's
            # deep-scan representative is a real caller.
            for _ in $(seq 600); do
                [ "$(grep -c '^READY' "$READY")" -ge "$CALLERS" ] && break
                sleep 0.1
            done
            : > "$OBS/$CELL.fake"
            for ((i = 0; i < CALLERS; i++)); do
                "${AS[@]}" LD_PRELOAD="$WL/s2/libfake.so" sleep 100000 &
                echo "$!" >> "$OBS/$CELL.fake"
            done
            PATHS+=("$WL/s1/libsofthsm2.so") ;;
        *) die "unknown cell $CELL" ;;
    esac
    for ((i = 0; i < MAPPERS; i++)); do "${AS[@]}" LD_PRELOAD="$MODULE" sleep 100000 & done
    for ((i = MAPPERS; i < IDLE; i++)); do "${AS[@]}" sleep 100000 & done
    for t in $(seq 3000); do
        [ "$(grep -c '^READY' "$READY")" -ge "$started" ] && break
        [ $((t % 100)) -eq 0 ] && echo "$CELL: $(grep -c '^READY' "$READY") of $started ready after $((t / 10)) s" >&2
        sleep 0.1
    done
    ready=$(grep -c '^READY' "$READY")
    if [ "$ready" -lt "$started" ]; then
        # SoftHSM2 setup on one shared token occasionally never finishes for
        # one caller under heavy host load. Name the stragglers (state and
        # wait channel), then tolerate at most 1%: the judge checks every
        # caller that did become ready.
        for f in /proc/[0-9]*/comm; do
            pid=${f#/proc/}; pid=${pid%/comm}
            [ "$(cat "$f" 2>/dev/null)" = gated ] || continue
            grep -q "^READY pid=$pid\$" "$READY" && continue
            echo "$CELL: straggler pid $pid state $(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) wchan $(cat "/proc/$pid/wchan" 2>/dev/null)" \
                | tee -a "$OBS/$CELL.load" >&2
        done
        [ $((ready * 100)) -ge $((started * 99)) ] \
            || die "$CELL: only $ready of $started callers became ready"
        echo "$CELL: proceeding with $ready of $started callers ready" | tee -a "$OBS/$CELL.load" >&2
    fi
    [ "$CELL" = deleted ] && { rm -f "$WL/bin/copyD/doomed.so" || die "unlink doomed"; }
    # Every launched process must have reached its final image: a `setpriv`
    # or `env` still mid-exec is a transient group whose deep scan can lose
    # its generation, leaving its objects honestly unexamined.
    for _ in $(seq 600); do
        transient=0
        for f in /proc/[0-9]*/comm; do
            case $(cat "$f" 2>/dev/null) in setpriv|env) transient=1; break ;; esac
        done
        [ "$transient" = 0 ] && break
        sleep 0.1
    done
    PIN=()
    [ -n "$CPUS" ] && PIN=(taskset -c "$CPUS")
    echo "$CELL: load at observer start: $(cat /proc/loadavg)" >> "$OBS/$CELL.load"
    pids=(/proc/[0-9]*); echo "${#pids[@]}" > "$OBS/$CELL.nprocs"
    printf '%s\n' "${PATHS[@]}" > "$OBS/$CELL.paths"
    if [ "$CELL" != measure ]; then
        "$P" inspect --system --json --max-scan-pids "$CAP" > "$OBS/$CELL.inspect.json" 2> "$OBS/$CELL.inspect.stderr"
        echo "inspect rc=$?" >> "$OBS/$CELL.rc"
    fi
    env --default-signal=INT P11SCOPE_STAGE_TIMINGS=1 "${PIN[@]}" "$P" inventory --system --max-scan-pids "$CAP" \
        --duration "$DURATION" -o "$OBS/$CELL.json" > "$OBS/$CELL.stdout" 2> "$OBS/$CELL.stderr"
    echo "inventory rc=$?" >> "$OBS/$CELL.rc"
    echo "$CELL: load at observer end: $(cat /proc/loadavg)" >> "$OBS/$CELL.load"
    exit 0  # pid 1 exits: the kernel reaps every process of the namespace
fi

# ---- outer ----
[ $# -ge 1 ] || { sed -n '3,7p' "$0" >&2; exit 64; }
P=$(realpath -e "$1") || die "binary $1"; shift
BASE=/var/tmp/p11scope-ws-tmp/c1b-root CELLS="cap bind deleted" MEASURE="" CAP="" DURATION="" CPUS=""
while [ $# -gt 0 ]; do
    case $1 in
        --base) BASE=$2; shift 2 ;;
        --cells) CELLS=$2; shift 2 ;;
        --measure) MEASURE=$2; shift 2 ;;
        --cap) CAP=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --cpus) CPUS=$2; shift 2 ;;
        *) echo "unknown argument $1" >&2; exit 64 ;;
    esac
done
[ "$(id -u)" = 0 ] || die "must run as root"
[ "$RUNUID" != 0 ] || die "RUNUID must not be root"
for tool in gcc softhsm2-util python3 setpriv unshare; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done
[ -r "$MODULE" ] || die "SoftHSM2 provider not found: $MODULE"
{ sh -c 'kill -HUP $$' >/dev/null 2>&1; } 2>/dev/null
[ $? -eq 129 ] || die "SIGHUP is ignored here (nohup?); refusing to run"
umask 077
[ -e "$BASE" ] || { mkdir -p "$(dirname "$BASE")" && mkdir -m 0711 "$BASE"; } || die "cannot create $BASE"
BASE=$(realpath -e "$BASE") || die "realpath $BASE"
read -r base_uid base_mode <<< "$(stat -c '%u %a' "$BASE")"
[ "$base_uid" = 0 ] || die "--base $BASE must be root-owned (owner uid $base_uid)"
[ $((8#$base_mode & 8#022)) -eq 0 ] || die "BASE $BASE is group/other-writable (mode $base_mode)"
OBS=$(mktemp -d "$BASE/c1b-obs.XXXXXX") || die "mktemp obs"
WL=$(mktemp -d "$BASE/c1b-wl.XXXXXX") || die "mktemp workload"
chmod 0711 "$WL" || die "chmod workload"
(
    umask 022
    install -d -m 0755 "$WL/bin" "$WL/bin/copyD" \
        && gcc -O1 -Wall -Wextra -Werror -o "$WL/bin/gated" "$SRC" -ldl \
        && cp "$MODULE" "$WL/bin/copyD/libsofthsm2.so" \
        && : > "$WL/gate"
) || die "fixture build"
install -d -o "$RUNUID" -g "$RUNGID" -m 0700 "$WL/token" || die "token dir"
{ printf 'directories.tokendir = %s/token/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WL" \
    > "$WL/token/softhsm2.conf" && chmod 0644 "$WL/token/softhsm2.conf"; } || die "token conf"
# shellcheck disable=SC2016  # $1 expands in the RUNUID shell, by design
setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups --no-new-privs \
    env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C SOFTHSM2_CONF="$WL/token/softhsm2.conf" \
    sh -c 'mkdir -m 700 "$1" && softhsm2-util --init-token --free --label c1b --so-pin 5678 --pin 1234 >/dev/null' \
    _ "$WL/token/tokens" || die "token init as $RUNUID failed (is $BASE traversable?)"
echo "observer=$OBS workload=$WL binary=$P"
SCOPE=()
# Only under a running systemd (never inside a vng guest).
[ -d /run/systemd/system ] && command -v systemd-run >/dev/null 2>&1 \
    && SCOPE=(systemd-run --scope --quiet --collect --slice=system.slice -p TasksMax=16384)

run_cell() { # CELL CALLERS IDLE CAP DURATION [MAPPERS] -> --inner argument order
    local cell=$1 callers=$2 idle=$3 cap=$4 duration=$5 mappers=${6:-0}
    echo "cell $cell: load at start: $(uptime)"
    # A transient scope outside the invoking user's slice: its TasksMax
    # (8927 on a default desktop) would refuse a 10,000-process cell.
    "${SCOPE[@]}" unshare --pid --fork --mount-proc --mount --propagation private \
        "$SELF" --inner "$cell" "$P" "$WL" "$OBS" "$callers" "$idle" "$cap" "$duration" "$mappers" "$CPUS" \
        2> "$OBS/$cell.inner.err" < /dev/null
    echo "cell $cell: namespace exited $?"
    cat "$OBS/$cell.load" 2>/dev/null
    echo "cell $cell: load at end: $(uptime)"
}

if [ -n "$MEASURE" ]; then
    IFS=: read -r total callers mappers <<< "$MEASURE"
    mappers=${mappers:-0}
    [ $((callers + mappers)) -le "$total" ] || die "--measure TOTAL:CALLERS[:MAPPERS] needs CALLERS + MAPPERS <= TOTAL"
    # The namespace holds the workload, the inner shell, and the observer.
    run_cell measure "$callers" $((total - callers - 2)) "${CAP:-256}" "${DURATION:-30}" "$mappers"
    python3 -I - "$OBS" <<'EOF'
import re, statistics, sys, pathlib
obs = pathlib.Path(sys.argv[1])
lines = (obs / "measure.stderr").read_text().splitlines()
passes = {}
for line in lines:
    m = re.match(r"p11scope: pass (\d+): stage timings: (.*)", line)
    if m:
        passes[int(m.group(1))] = {k: float(v) for k, v in re.findall(r"(\w+) ([\d.]+)ms", m.group(2))}
def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, max(0, round(q * (len(values) - 1))))]
print(f"processes={(obs / 'measure.nprocs').read_text().strip()} passes={len(passes)}")
stages = list(dict.fromkeys(k for p in passes.values() for k in p))
rest = [p for n, p in passes.items() if n > 1]
for stage in stages + ["total"]:
    get = (lambda p: sum(p.values())) if stage == "total" else (lambda p, s=stage: p.get(s, 0.0))
    first = get(passes[1]) if 1 in passes else float("nan")
    vals = [get(p) for p in rest] or [float("nan")]
    print(f"{stage:>12}: pass1 {first:9.3f} ms  p50 {pct(vals, .5):9.3f} ms  p95 {pct(vals, .95):9.3f} ms")
print("last progress:", next((l for l in reversed(lines) if " scanned (" in l), "none"))
print("admission:", next((l for l in reversed(lines) if "admissions" in l), "none"))
print("gaps:", next((l for l in reversed(lines) if re.search(r": \d+ gaps? \(", l)), "none"))
print("rc:", (obs / "measure.rc").read_text().strip())
EOF
    exit $?
fi

# collide: two fresh btrfs subvolumes whose first files share inode 257.
setup_collision() {
    [ "$(stat -f -c %T "$WL")" = btrfs ] || die "collide needs btrfs under $BASE"
    command -v btrfs >/dev/null 2>&1 || die "collide needs btrfs-progs"
    { btrfs subvolume create "$WL/s1" >/dev/null && btrfs subvolume create "$WL/s2" >/dev/null; } \
        || die "btrfs subvolume create"
    printf 'int c1b_fake(void) { return 7; }\n' > "$WL/fake.c"
    gcc -shared -fPIC -o "$WL/libfake.so" "$WL/fake.c" || die "fake library build"
    # Each subvolume's first new inode is 257: copy one file into each.
    { cp "$MODULE" "$WL/s1/libsofthsm2.so" && cp "$WL/libfake.so" "$WL/s2/libfake.so"; } \
        || die "collision copies"
    { chmod 0755 "$WL/s1" "$WL/s2" && chmod 0644 "$WL/s1/libsofthsm2.so" "$WL/s2/libfake.so"; } \
        || die "collision modes"
    local a b
    a=$(stat -c '%i' "$WL/s1/libsofthsm2.so") b=$(stat -c '%i' "$WL/s2/libfake.so")
    [ "$a" = "$b" ] || die "no inode collision (provider $a, fake $b)"
    echo "collide: provider and fake share inode $a; stat devices $(stat -c %d "$WL/s1/libsofthsm2.so")/$(stat -c %d "$WL/s2/libfake.so")"
}
cleanup_collision() {
    [ -d "$WL/s1" ] && btrfs subvolume delete "$WL/s1" "$WL/s2" >/dev/null 2>&1
    return 0
}

# overlay: a provider copy reached only through an overlayfs mount.
setup_overlay() {
    # The merged root takes the upper dir's mode: callers must traverse it.
    { install -d -m 0755 "$WL/ovl" "$WL/ovl/lower" "$WL/ovl/merged" "$WL/ovl/upper" \
        && install -d -m 0700 "$WL/ovl/work"; } || die "overlay dirs"
    { cp "$MODULE" "$WL/ovl/lower/libsofthsm2.so" && chmod 0644 "$WL/ovl/lower/libsofthsm2.so"; } || die "overlay lower"
    mount -t overlay overlay -o "lowerdir=$WL/ovl/lower,upperdir=$WL/ovl/upper,workdir=$WL/ovl/work" "$WL/ovl/merged" \
        || die "overlay mount"
    echo "overlay: kernel $(uname -r); merged $(stat -c '%d %i' "$WL/ovl/merged/libsofthsm2.so"), lower $(stat -c '%d %i' "$WL/ovl/lower/libsofthsm2.so")"
}

declare -A SHAPE=([cap]="300 200" [bind]="300 200" [deleted]="150 200" [collide]="150 200" [overlay]="300 200")
for cell in $CELLS; do
    [ -n "${SHAPE[$cell]:-}" ] || die "unknown cell $cell"
    [ "$cell" = deleted ] && { ln -f "$WL/bin/copyD/libsofthsm2.so" "$WL/bin/copyD/doomed.so" || die "hard link"; }
    [ "$cell" = collide ] && setup_collision
    [ "$cell" = overlay ] && setup_overlay
    read -r callers idle <<< "${SHAPE[$cell]}"
    run_cell "$cell" "$callers" "$idle" "${CAP:-64}" "${DURATION:-8}"
    [ "$cell" = collide ] && cleanup_collision
    [ "$cell" = overlay ] && umount "$WL/ovl/merged"
done

python3 -I - "$OBS" "$CELLS" <<'EOF'
import json, re, sys, pathlib
obs, cells = pathlib.Path(sys.argv[1]), sys.argv[2].split()
failed = False
def check(cell, ok, what):
    global failed
    failed |= not ok
    print(f"  [{'ok' if ok else 'FAIL'}] {what}")
for cell in cells:
    print(f"cell {cell}: {(obs / f'{cell}.nprocs').read_text().strip()} processes in the namespace")
    rc = (obs / f"{cell}.rc").read_text()
    check(cell, "inventory rc=0" in rc, f"exit codes: {rc.split()}")
    ready = {int(m) for m in re.findall(r"READY pid=(\d+)", (obs / f"{cell}.ready").read_text())}
    paths = (obs / f"{cell}.paths").read_text().split()
    doc = json.loads((obs / f"{cell}.json").read_text())
    inspect = json.loads((obs / f"{cell}.inspect.json").read_text())
    callers = {c["id"]: c for c in doc["callers"] if not c["retired"]}
    modules = {m["id"]: m for m in doc["modules"]}
    by_pid = {c["pid"]: cid for cid, c in callers.items()}
    edges = {}
    for e in doc["edges"]:
        if e["caller"] in callers:
            edges.setdefault(callers[e["caller"]]["pid"], []).append(e)
    def provider_edge(pid):
        return [e for e in edges.get(pid, ())
                if e["mapping"]["state"] == "mapped"
                and any(p in paths for p in modules[e["module"]]["paths"])]
    gaps = doc["gaps"]
    capped = [g for g in gaps if g["subject"] == "discovery capped"]
    scan = inspect.get("scan", {})
    print(f"  inspect scan: { {k: scan.get(k) for k in ('status', 'enumerated', 'limit', 'deep_scanned', 'maps_matched', 'unexamined', 'unexamined_objects', 'snapshots_unavailable')} }")
    print(f"  losses: {scan.get('attribution_losses')}")
    last = [l for l in (obs / f"{cell}.stderr").read_text().splitlines() if "maps-matched" in l]
    print(f"  last pass: {last[-1] if last else 'none'}")
    for g in capped:
        print(f"  gap: {g['subject']}: {g['reason'][:160]}")
    if cell in ("cap", "bind"):
        missing = sorted(pid for pid in ready if not provider_edge(pid))
        check(cell, len(ready) >= 297, f"{len(ready)} fixture callers ready (want 300; at most 1% stragglers, named in the load log)")
        check(cell, not missing, f"every fixture pid is a caller with a mapped provider edge (missing {len(missing)}: {missing[:10]})")
        check(cell, all(g["reason"].startswith("attribution complete") for g in capped) and capped,
              "discovery capped reads 'attribution complete' (no unexamined loss)")
        check(cell, scan.get("status") == "complete", f"inspect scan status complete (got {scan.get('status')})")
        check(cell, (scan.get("maps_matched") or 0) >= 290, f"inspect maps_matched >= 290 (got {scan.get('maps_matched')})")
        evidence = [e["mapping"].get("evidence") for pid in ready for e in provider_edge(pid)]
        check(cell, evidence.count("maps_match") >= 290, f"{evidence.count('maps_match')} edges by maps_match, {evidence.count('deep_scan')} by deep_scan")
        if cell == "bind":
            bound = [p for p in paths if "bindmnt" in p][0]
            via_bind = [m for m in modules.values() if bound in m["paths"]]
            check(cell, bool(via_bind) and all(paths[0] in m["paths"] for m in via_bind),
                  "the bind path and the original path name one module (one dev/ino)")
    if cell == "deleted":
        kept = 100
        have = sorted(pid for pid in ready if provider_edge(pid))
        check(cell, len(ready) >= 149, f"{len(ready)} fixture callers ready (want 150)")
        check(cell, len(have) == kept, f"{len(have)} callers registered with an edge to the surviving name (want {kept})")
        # The doomed callers started last: the highest 50 READY pids.
        doomed = sorted(ready)[kept:]
        check(cell, not [pid for pid in doomed if pid in by_pid],
              f"none of the {len(doomed)} callers mapping only the unlinked name registered")
        losses = scan.get("attribution_losses") or {}
        check(cell, losses.get("deleted_mapping") == 50, f"deleted_mapping losses {losses.get('deleted_mapping')} (want 50)")
        check(cell, scan.get("status") != "complete", "scan status is not complete")
        check(cell, any(g["subject"] == "maps attribution" and "deleted_mapping" in g["reason"] for g in gaps),
              "a 'maps attribution' gap names deleted_mapping")
    if cell == "overlay":
        missing = sorted(pid for pid in ready if not provider_edge(pid))
        check(cell, len(ready) >= 297, f"{len(ready)} fixture callers ready (want 300)")
        check(cell, not missing, f"every ready caller through the overlay has a provider edge (missing {len(missing)}: {missing[:10]})")
        losses = scan.get("attribution_losses") or {}
        check(cell, not losses.get("identity_mismatch") and not losses.get("map_files_unavailable"),
              f"no identity loss (identity_mismatch {losses.get('identity_mismatch')}, map_files_unavailable {losses.get('map_files_unavailable')})")
        check(cell, (scan.get("maps_matched") or 0) >= len(ready) - 1, f"inspect maps_matched {scan.get('maps_matched')}")
    if cell == "collide":
        fake = {int(x) for x in (obs / "collide.fake").read_text().split()}
        mapped = sorted(pid for pid in ready if provider_edge(pid))
        check(cell, len(ready) >= 149, f"{len(ready)} fixture callers ready (want 150)")
        check(cell, len(mapped) == len(ready), f"{len(mapped)} of {len(ready)} ready provider callers registered with an edge")
        false_edges = sorted(pid for pid in fake if provider_edge(pid))
        check(cell, not false_edges, f"no collision mapper has a provider edge (false: {false_edges[:10]})")
        losses = scan.get("attribution_losses") or {}
        check(cell, (losses.get("identity_mismatch") or 0) >= 149,
              f"identity_mismatch losses {losses.get('identity_mismatch')} (want >= 149)")
print("VERDICT:", "FAIL" if failed else "PASS")
sys.exit(1 if failed else 0)
EOF
