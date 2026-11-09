#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# v0.7.0 "calls happened => data present" live regression matrix.
#
# Owner rule (2026-11-09): if a program makes PKCS#11 calls, p11scope must
# produce data about them. It may name exactly what it could not determine,
# but it must never show an empty/zero view because a proof or precondition
# failed. Every cell starts a known workload (spike/harness.c, 226 session
# calls plus one C_GetFunctionList, ground truth spike/expected.txt plus
# that call) and asserts via nodata-oracle.py:
# provider present, calls > 0 (exact where the cell promises exact), caller
# present or named-unknown with reason, every missing piece a named gap.
#
# Usage:
#   scripts/matrix/nodata-matrix.sh [--list] [--cell NAME]... [--no-oracle]
#       [--keep] [--results FILE]
# P11SCOPE_BIN=/abs/p11scope reuses a prebuilt product, else the lane build
# at target/nodata-release/release/p11scope is used. Each privileged step
# runs under flock on /var/tmp/p11scope-ws-tmp/privileged.lock (per cell).
set -eu
cd "$(dirname "$0")/../.."

RUN_ID=$(date +%s%N)-$$
WORK=
RESULTS=
NO_ORACLE=
KEEP=
ONLY_CELLS=
HARNESS_BIN=
SOFTHSM_CONF=
PROVIDER_SRC=
PRIVLOCK=/var/tmp/p11scope-ws-tmp/privileged.lock
ORACLE=$(pwd -P)/scripts/matrix/nodata-oracle.py
SPIKE_EXPECTED=$(pwd -P)/spike/expected.txt
EXPECTED_EXACT=
SPID=
PRODUCT=target/nodata-release/release/p11scope
. scripts/lib.sh
. scripts/matrix/matrix-lib.sh

usage() {
    echo "usage: nodata-matrix.sh [--list] [--cell NAME]... [--no-oracle] [--keep] [--results FILE]" >&2
}

ALL_CELLS="run-hostfs run-syspath run-pkcs11-tool profile-pid-hostfs profile-system-hostfs trace-pid-hostfs inventory-pid-hostfs inventory-system-hostfs inventory-cgroup-hostfs run-overlay profile-pid-overlay inventory-cgroup-overlay inventory-pid-overlay run-tmpfs inventory-pid-tmpfs run-bind inventory-pid-bind profile-pid-deleted inventory-pid-deleted profile-pid-copyup inventory-pid-copyup"

while [ "$#" -gt 0 ]; do
    case $1 in
        --list) printf '%s\n' $ALL_CELLS; exit 0 ;;
        --cell) ONLY_CELLS="$ONLY_CELLS ${2:?--cell needs a name}"; shift 2 ;;
        --no-oracle) NO_ORACLE=1; shift ;;
        --keep) KEEP=1; shift ;;
        --results) RESULTS=${2:?--results needs a file}; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

require_non_root_caller
for tool in gcc python3 sudo flock sha256sum; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 1; }
done
matrix_select_timeout
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 1; }
if ! matrix_prebuilt_product; then
    case $PRODUCT in /*) P11SCOPE_EXE=$PRODUCT ;; *) P11SCOPE_EXE=$(pwd -P)/$PRODUCT ;; esac
    [ -f "$P11SCOPE_EXE" ] && [ -x "$P11SCOPE_EXE" ] || {
        echo "no product: set P11SCOPE_BIN or build $PRODUCT" >&2; exit 1
    }
fi
[ -f "$ORACLE" ] || { echo "oracle missing: $ORACLE" >&2; exit 1; }
if [ -z "$ONLY_CELLS" ]; then
    ONLY_CELLS=$ALL_CELLS
else
    # shellcheck disable=SC2086
    set -- $ONLY_CELLS
    ONLY_CELLS=
    for want in "$@"; do
        case " $ALL_CELLS " in *" $want "*) ONLY_CELLS="$ONLY_CELLS $want" ;; *)
            echo "unknown cell: $want (see --list)" >&2; exit 2 ;;
        esac
    done
fi

for candidate in /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so; do
    if [ -f "$candidate" ]; then PROVIDER_SRC=$candidate; break; fi
done
[ -n "$PROVIDER_SRC" ] || { echo "SoftHSM provider not found" >&2; exit 1; }

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    if [ -n "$WORK" ] && [ -d "$WORK" ]; then
        [ -f "$WORK/children" ] && while read -r cpid _; do
            [ -n "$cpid" ] && kill -TERM "$cpid" 2>/dev/null
        done < "$WORK/children"
        sleep 1
        [ -f "$WORK/children" ] && while read -r cpid _; do
            [ -n "$cpid" ] && kill -KILL "$cpid" 2>/dev/null
        done < "$WORK/children"
        if [ -f "$WORK/mounts" ]; then
            rev_mounts=$(tac "$WORK/mounts" 2>/dev/null || cat "$WORK/mounts")
            printf '%s\n' "$rev_mounts" | while read -r mnt; do
                if [ -n "$mnt" ]; then flock "$PRIVLOCK" sudo -n umount "$mnt" 2>/dev/null; fi
            done
        fi
        if [ -f "$WORK/cgroups" ]; then
            while read -r cg; do
                [ -n "$cg" ] && [ -d "$cg" ] && flock "$PRIVLOCK" sudo -n rmdir "$cg" 2>/dev/null
            done < "$WORK/cgroups"
        fi
        if [ -f "$WORK/scopes" ]; then
            while read -r unit; do
                [ -n "$unit" ] && flock "$PRIVLOCK" sudo -n systemctl stop "$unit" 2>/dev/null
            done < "$WORK/scopes"
        fi
        [ -n "$KEEP" ] || rm -rf "$WORK"
    fi
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

matrix_private_work nodata
: > "$WORK/children"
: > "$WORK/mounts"
: > "$WORK/cgroups"
: > "$WORK/scopes"
[ -n "$RESULTS" ] || RESULTS=$WORK/results.tsv
printf 'cell\tmode\tscope\tfs\tverdict\tcalls\tendpoints\tcaller\tnote\n' > "$RESULTS"
matrix_report_product
echo "provider source: $PROVIDER_SRC"
echo "results: $RESULTS"

echo "=== build workload + token ==="
"$MATRIX_TIMEOUT" --foreground --signal=TERM --kill-after=5s 60s \
    gcc -O2 -Wall -Wextra -Werror -o "$WORK/harness" spike/harness.c -ldl
HARNESS_BIN=$WORK/harness
mkdir -p "$WORK/token/tokens"
SOFTHSM_CONF=$WORK/token/softhsm2.conf
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' \
    "$WORK/token/tokens" > "$SOFTHSM_CONF"
export SOFTHSM2_CONF=$SOFTHSM_CONF
"$MATRIX_TIMEOUT" --foreground --signal=TERM --kill-after=5s 60s \
    softhsm2-util --init-token --free --label nodata --so-pin 1234 --pin 1234 >/dev/null
# The observer counts the harness's one dlsym'd C_GetFunctionList call,
# which spike/expected.txt (session-call ground truth) omits; exact cells
# compare against this 227-call file instead.
EXPECTED_EXACT=$WORK/expected-exact.txt
{ cat "$SPIKE_EXPECTED"; echo "C_GetFunctionList 1"; } > "$EXPECTED_EXACT"
export CALLER_HARNESS=harness CALLER_TOOL=pkcs11-tool

track_child() { echo "$1 $2" >> "$WORK/children"; }
track_mount() { echo "$1" >> "$WORK/mounts"; }
track_cgroup() { echo "$1" >> "$WORK/cgroups"; }

wait_file() {
    wf_file=$1 wf_limit=${2:-200}
    wf_attempt=0
    while [ "$wf_attempt" -lt "$wf_limit" ]; do
        [ -e "$wf_file" ] && return 0
        wf_attempt=$((wf_attempt + 1))
        sleep 0.05
    done
    return 1
}

wait_grep() {
    wg_pattern=$1 wg_file=$2 wg_limit=${3:-200}
    wg_attempt=0
    while [ "$wg_attempt" -lt "$wg_limit" ]; do
        grep -Fq "$wg_pattern" "$wg_file" 2>/dev/null && return 0
        wg_attempt=$((wg_attempt + 1))
        sleep 0.05
    done
    return 1
}

# Block until the privileged lock is currently free, so a background
# observer started next does not queue behind another lane for longer
# than the readiness window allows. Best effort against a fresh race;
# the loose readiness loop below covers the residue.
flock_gate() {
    flock "$PRIVLOCK" true
}

# wait_for_capture_ready with an 8 s window; loop it while the observer
# is still alive so lock queuing or slow discovery does not fake a
# not-ready verdict. $1 = log, $2 = kind (profile|trace).
wait_ready_loose() {
    wr_log=$1 wr_kind=$2
    wr_deadline=$(($(date +%s) + 2400))
    while [ "$(date +%s)" -lt "$wr_deadline" ]; do
        if wait_for_capture_ready "$wr_log" allowlisted "$wr_kind" 2>/dev/null; then
            return 0
        fi
        if [ -n "$SPID" ] && kill -0 "$SPID" 2>/dev/null; then
            continue
        fi
        echo "observer exited before capture readiness: $wr_log" >&2
        tail -30 "$wr_log" >&2 2>/dev/null || :
        return 1
    done
    echo "observer never ready within 40 min: $wr_log" >&2
    return 1
}

# Provider layouts. Prints the module path the workload must dlopen.
# $1 = cell dir, $2 = hostfs|syspath|overlay|tmpfs|bind
provide_module() {
    pm_dir=$1 pm_fs=$2
    case $pm_fs in
        syspath) printf '%s\n' "$PROVIDER_SRC" ;;
        hostfs) cp "$PROVIDER_SRC" "$pm_dir/libnodata.so"; printf '%s\n' "$pm_dir/libnodata.so" ;;
        tmpfs)
            mkdir -p "$pm_dir/mnt"
            flock "$PRIVLOCK" sudo -n mount -t tmpfs tmpfs "$pm_dir/mnt"
            track_mount "$pm_dir/mnt"
            flock "$PRIVLOCK" sudo -n sh -c "cp '$PROVIDER_SRC' '$pm_dir/mnt/libnodata.so' && chown '$(id -u):$(id -g)' '$pm_dir/mnt/libnodata.so'"
            printf '%s\n' "$pm_dir/mnt/libnodata.so"
            ;;
        bind)
            cp "$PROVIDER_SRC" "$pm_dir/libnodata-src.so"
            : > "$pm_dir/libnodata.so"
            flock "$PRIVLOCK" sudo -n mount --bind "$pm_dir/libnodata-src.so" "$pm_dir/libnodata.so"
            track_mount "$pm_dir/libnodata.so"
            printf '%s\n' "$pm_dir/libnodata.so"
            ;;
        overlay)
            mkdir -p "$pm_dir/lower" "$pm_dir/upper" "$pm_dir/ovwork" "$pm_dir/merged"
            cp "$PROVIDER_SRC" "$pm_dir/lower/libnodata.so"
            flock "$PRIVLOCK" sudo -n mount -t overlay overlay \
                -o "lowerdir=$pm_dir/lower,upperdir=$pm_dir/upper,workdir=$pm_dir/ovwork" \
                "$pm_dir/merged"
            track_mount "$pm_dir/merged"
            printf '%s\n' "$pm_dir/merged/libnodata.so"
            ;;
        *) echo "unknown fs: $pm_fs" >&2; return 1 ;;
    esac
}

run_oracle() {
    ro_cell=$1; shift
    if [ -n "$NO_ORACLE" ]; then
        echo "cell=$ro_cell verdict=SKIPPED (no-oracle)"
        printf '%s\t%s\n' "$ro_cell" "SKIPPED" >> "$WORK/verdicts.txt"
        return 0
    fi
    set +e
    "$MATRIX_TIMEOUT" --foreground --signal=TERM --kill-after=5s 60s \
        python3 -I "$ORACLE" --cell "$ro_cell" "$@" > "$WORK/cells/$ro_cell/oracle.out" 2>&1
    ro_rc=$?
    set -e
    cat "$WORK/cells/$ro_cell/oracle.out"
    return "$ro_rc"
}

record_result() {
    rr_cell=$1 rr_mode=$2 rr_scope=$3 rr_fs=$4
    rr_verdict=FAIL rr_calls=- rr_endpoints=- rr_caller=- rr_note=
    if [ -f "$WORK/cells/$rr_cell/oracle.out" ]; then
        rr_line=$(grep -E '^RESULT ' "$WORK/cells/$rr_cell/oracle.out" | tail -n 1 || true)
        for kv in $rr_line; do
            case $kv in
                RESULT) ;;
                verdict=*) rr_verdict=${kv#verdict=} ;;
                calls=*) rr_calls=${kv#calls=} ;;
                endpoints=*) rr_endpoints=${kv#endpoints=} ;;
                caller=*) rr_caller=${kv#caller=} ;;
                note=*) rr_note=${kv#note=} ;;
            esac
        done
    fi
    if [ -n "$NO_ORACLE" ]; then rr_verdict=SKIPPED; rr_note=no-oracle; fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$rr_cell" "$rr_mode" "$rr_scope" "$rr_fs" "$rr_verdict" \
        "$rr_calls" "$rr_endpoints" "$rr_caller" "$rr_note" >> "$RESULTS"
}

# run --pause auto: the observer spawns the workload itself.
# $1 = cell, $2 = fs, $3 = workload (harness|pkcs11-tool), $4 = exact (1 or empty)
cell_run() {
    rc_cell=$1 rc_fs=$2 rc_workload=$3 rc_exact=$4
    rc_dir=$WORK/cells/$rc_cell
    mkdir -p "$rc_dir"
    echo "=== cell $rc_cell ==="
    rc_mod=$(provide_module "$rc_dir" "$rc_fs")
    set +e
    if [ "$rc_workload" = pkcs11-tool ]; then
        flock "$PRIVLOCK" sudo -n --preserve-env=SOFTHSM2_CONF \
            "$MATRIX_TIMEOUT" --foreground --signal=TERM --kill-after=5s 120s \
            "$P11SCOPE_EXE" run --module "$rc_mod" -o "$rc_dir/out.json" \
            --pause auto -v -- pkcs11-tool --module "$rc_mod" -L \
            > "$rc_dir/observer.stdout" 2> "$rc_dir/observer.stderr"
        rc_caller=$CALLER_TOOL
    else
        flock "$PRIVLOCK" sudo -n --preserve-env=SOFTHSM2_CONF \
            "$MATRIX_TIMEOUT" --foreground --signal=TERM --kill-after=5s 120s \
            "$P11SCOPE_EXE" run --module "$rc_mod" -o "$rc_dir/out.json" \
            --pause auto -v -- "$HARNESS_BIN" "$rc_mod" \
            > "$rc_dir/observer.stdout" 2> "$rc_dir/observer.stderr"
        rc_caller=$CALLER_HARNESS
    fi
    echo "observer exit: $?" > "$rc_dir/observer.rc"
    set -e
    if [ -n "$rc_exact" ]; then
        run_oracle "$rc_cell" --mode run --scope child --json "$rc_dir/out.json" \
            --stdout "$rc_dir/observer.stdout" --stderr "$rc_dir/observer.stderr" \
            --provider libnodata.so --sysprovider libsofthsm2.so --min-calls 1 \
            --exact "$EXPECTED_EXACT" --caller "$rc_caller" || true
    else
        run_oracle "$rc_cell" --mode run --scope child --json "$rc_dir/out.json" \
            --stdout "$rc_dir/observer.stdout" --stderr "$rc_dir/observer.stderr" \
            --provider libnodata.so --sysprovider libsofthsm2.so --min-calls 1 \
            --caller "$rc_caller" || true
    fi
    record_result "$rc_cell" run child "$rc_fs"
}

# Start the barrier harness in the background: maps the module, waits on
# go-file, runs the 227 calls, prints "harness OK", waits on finish-file.
# $1 = cell dir, $2 = module. Sets HARNESS_PID.
start_harness() {
    sh_dir=$1 sh_mod=$2
    rm -f "$sh_dir/go" "$sh_dir/finish"
    "$HARNESS_BIN" "$sh_mod" "$sh_dir/go" "$sh_dir/finish" \
        > "$sh_dir/harness.stdout" 2> "$sh_dir/harness.stderr" &
    HARNESS_PID=$!
    track_child "$HARNESS_PID" harness
}

# profile/trace against a live barrier workload.
# $1 = cell, $2 = mode (profile|trace), $3 = scope (pid|system),
# $4 = fs, $5 = exact (1 or empty), $6 = mutation (none|deleted|copyup)
cell_live() {
    lc_cell=$1 lc_mode=$2 lc_scope=$3 lc_fs=$4 lc_exact=$5 lc_mut=$6
    lc_dir=$WORK/cells/$lc_cell
    mkdir -p "$lc_dir"
    echo "=== cell $lc_cell ==="
    case $lc_fs in
        deleted) lc_base=hostfs ;;
        copyup) lc_base=overlay ;;
        *) lc_base=$lc_fs ;;
    esac
    lc_mod=$(provide_module "$lc_dir" "$lc_base")
    start_harness "$lc_dir" "$lc_mod"
    wait_grep HARNESS_PROVIDER_MAPPED "$lc_dir/harness.stderr" 200 || {
        echo "harness never mapped the provider"
        kill -TERM "$HARNESS_PID" 2>/dev/null
        wait "$HARNESS_PID" 2>/dev/null || true
        record_result "$lc_cell" "$lc_mode" "$lc_scope" "$lc_fs"; return 0
    }
    lc_pidargs=
    if [ "$lc_scope" = pid ]; then lc_pidargs="--caller-pid $HARNESS_PID"; fi
    case $lc_mut in
        deleted) rm -f "$lc_mod" ;;
        copyup)
            # R-41 same-bytes copy-up: a metadata-only change on the
            # merged path copies lower->upper without touching bytes.
            lc_sha_before=$(sha256sum "$lc_mod")
            chmod +x "$lc_mod"
            touch "$lc_mod"
            lc_sha_after=$(sha256sum "$lc_mod")
            if [ "$lc_sha_before" != "$lc_sha_after" ]; then
                echo "copy-up changed provider bytes" >&2
                kill -TERM "$HARNESS_PID" 2>/dev/null
                wait "$HARNESS_PID" 2>/dev/null || true
                record_result "$lc_cell" "$lc_mode" "$lc_scope" "$lc_fs"; return 0
            fi
            if [ -e "$lc_dir/upper/libnodata.so" ]; then
                echo "copy-up present: upper/libnodata.so"
            else
                echo "copy-up not observed: upper/libnodata.so absent"
            fi
            ;;
    esac
    set +e
    case $lc_scope in
        pid) lc_scopeflag="--pid $HARNESS_PID" ;;
        system) lc_scopeflag="--system" ;;
    esac
    flock_gate
    case $lc_mode in
        profile)
            # shellcheck disable=SC2086
            flock "$PRIVLOCK" sudo -n "$MATRIX_TIMEOUT" --foreground \
                --signal=TERM --kill-after=5s 120s "$P11SCOPE_EXE" "$lc_mode" \
                $lc_scopeflag --duration 10s -o "$lc_dir/out.json" \
                > "$lc_dir/observer.stdout" 2> "$lc_dir/observer.stderr" &
            SPID=$!
            wait_ready_loose "$lc_dir/observer.stderr" "$lc_mode" || {
                echo "observer never ready"; wait "$SPID" 2>/dev/null
                echo "observer exit: $?" > "$lc_dir/observer.rc"
                : > "$lc_dir/go"; : > "$lc_dir/finish"
                wait "$HARNESS_PID" 2>/dev/null; SPID=
                set -e
                # shellcheck disable=SC2086
                run_oracle "$lc_cell" --mode "$lc_mode" --scope "$lc_scope" \
                    --json "$lc_dir/out.json" --stdout "$lc_dir/observer.stdout" \
                    --stderr "$lc_dir/observer.stderr" --provider libnodata.so \
                    --sysprovider libsofthsm2.so --min-calls 1 --caller "$CALLER_HARNESS" $lc_pidargs || true
                record_result "$lc_cell" "$lc_mode" "$lc_scope" "$lc_fs"
                return 0
            }
            ;;
        trace)
            # Trace readiness is the CAPTURE line, which lands on stdout
            # (and the -o file), never stderr: combine both streams so the
            # barrier below cannot miss it and release the workload late.
            # shellcheck disable=SC2086
            flock "$PRIVLOCK" sudo -n "$MATRIX_TIMEOUT" --foreground \
                --signal=TERM --kill-after=5s 120s "$P11SCOPE_EXE" "$lc_mode" \
                $lc_scopeflag --duration 10s --max-events 1000 -v -o "$lc_dir/out.txt" \
                > "$lc_dir/observer.stdout" 2>&1 &
            SPID=$!
            wait_ready_loose "$lc_dir/observer.stdout" "$lc_mode" || {
                echo "observer never ready"; wait "$SPID" 2>/dev/null
                echo "observer exit: $?" > "$lc_dir/observer.rc"
                : > "$lc_dir/go"; : > "$lc_dir/finish"
                wait "$HARNESS_PID" 2>/dev/null; SPID=
                set -e
                # shellcheck disable=SC2086
                run_oracle "$lc_cell" --mode "$lc_mode" --scope "$lc_scope" \
                    --json "$lc_dir/out.txt" --stdout "$lc_dir/observer.stdout" \
                    --stderr "$lc_dir/observer.stdout" --provider libnodata.so \
                    --sysprovider libsofthsm2.so --min-calls 1 --caller "$CALLER_HARNESS" $lc_pidargs || true
                record_result "$lc_cell" "$lc_mode" "$lc_scope" "$lc_fs"
                return 0
            }
            ;;
    esac
    : > "$lc_dir/go"
    wait "$SPID" 2>/dev/null
    echo "observer exit: $?" > "$lc_dir/observer.rc"
    SPID=
    : > "$lc_dir/finish"
    wait "$HARNESS_PID" 2>/dev/null
    echo "harness exit: $?" > "$lc_dir/harness.rc"
    set -e
    case $lc_mode in
        profile) lc_json="$lc_dir/out.json" ;;
        trace) lc_json="$lc_dir/out.txt" ;;
    esac
    case $lc_mode in
        profile) lc_err="$lc_dir/observer.stderr" ;;
        trace) lc_err="$lc_dir/observer.stdout" ;;
    esac
    # shellcheck disable=SC2086
    if [ -n "$lc_exact" ]; then
        run_oracle "$lc_cell" --mode "$lc_mode" --scope "$lc_scope" --json "$lc_json" \
            --stdout "$lc_dir/observer.stdout" --stderr "$lc_err" \
            --provider libnodata.so --sysprovider libsofthsm2.so --min-calls 1 \
            --exact "$EXPECTED_EXACT" --caller "$CALLER_HARNESS" $lc_pidargs || true
    else
        run_oracle "$lc_cell" --mode "$lc_mode" --scope "$lc_scope" --json "$lc_json" \
            --stdout "$lc_dir/observer.stdout" --stderr "$lc_err" \
            --provider libnodata.so --sysprovider libsofthsm2.so --min-calls 1 \
            --caller "$CALLER_HARNESS" $lc_pidargs || true
    fi
    record_result "$lc_cell" "$lc_mode" "$lc_scope" "$lc_fs"
}

# inventory --pid/--system/--cgroup. The workload completes its calls first
# ("harness OK") and stays alive on the finish barrier while the inventory
# runs, so calls-happened is true at scan time.
# $1 = cell, $2 = scope (pid|system|cgroup), $3 = fs, $4 = mutation
cell_inventory() {
    ic_cell=$1 ic_scope=$2 ic_fs=$3 ic_mut=$4
    ic_dir=$WORK/cells/$ic_cell
    mkdir -p "$ic_dir"
    echo "=== cell $ic_cell ==="
    case $ic_fs in
        deleted) ic_base=hostfs ;;
        copyup) ic_base=overlay ;;
        *) ic_base=$ic_fs ;;
    esac
    ic_mod=$(provide_module "$ic_dir" "$ic_base")
    start_harness "$ic_dir" "$ic_mod"
    wait_grep HARNESS_PROVIDER_MAPPED "$ic_dir/harness.stderr" 200 || {
        echo "harness never mapped the provider"
        kill -TERM "$HARNESS_PID" 2>/dev/null
        wait "$HARNESS_PID" 2>/dev/null || true
        record_result "$ic_cell" inventory "$ic_scope" "$ic_fs"; return 0
    }
    ic_pidargs=
    if [ "$ic_scope" = pid ]; then ic_pidargs="--caller-pid $HARNESS_PID"; fi
    case $ic_mut in
        deleted) rm -f "$ic_mod" ;;
        copyup)
            # R-41 same-bytes copy-up: a metadata-only change on the
            # merged path copies lower->upper without touching bytes.
            ic_sha_before=$(sha256sum "$ic_mod")
            chmod +x "$ic_mod"
            touch "$ic_mod"
            ic_sha_after=$(sha256sum "$ic_mod")
            if [ "$ic_sha_before" != "$ic_sha_after" ]; then
                echo "copy-up changed provider bytes" >&2
                kill -TERM "$HARNESS_PID" 2>/dev/null
                wait "$HARNESS_PID" 2>/dev/null || true
                record_result "$ic_cell" inventory "$ic_scope" "$ic_fs"; return 0
            fi
            if [ -e "$ic_dir/upper/libnodata.so" ]; then
                echo "copy-up present: upper/libnodata.so"
            else
                echo "copy-up not observed: upper/libnodata.so absent"
            fi
            ;;
    esac
    ic_cgdir=
    case $ic_scope in
        cgroup)
            ic_cgdir=/sys/fs/cgroup/p11scope-nodata-$RUN_ID-$ic_cell
            flock "$PRIVLOCK" sudo -n mkdir -p "$ic_cgdir"
            track_cgroup "$ic_cgdir"
            echo "$HARNESS_PID" | flock "$PRIVLOCK" sudo -n tee "$ic_cgdir/cgroup.procs" >/dev/null
            ;;
    esac
    # System scope overlaps the live calls: the observer starts first, the
    # workload is released after attach, and the calls land mid-inventory.
    # PID/cgroup scopes scan once, so the calls complete first and the
    # process stays alive on the finish barrier during the scan.
    if [ "$ic_scope" = system ]; then
        flock_gate
        set +e
        flock "$PRIVLOCK" sudo -n "$MATRIX_TIMEOUT" --foreground \
            --signal=TERM --kill-after=5s 120s "$P11SCOPE_EXE" inventory \
            --system --duration 12s --json -o "$ic_dir/out.json" \
            > "$ic_dir/observer.stdout" 2> "$ic_dir/observer.stderr" &
        SPID=$!
        set -e
        sleep 5
        : > "$ic_dir/go"
        if ! wait_grep "harness OK" "$ic_dir/harness.stdout" 400; then
            echo "harness never finished its calls"
            wait "$SPID" 2>/dev/null || true; SPID=
            : > "$ic_dir/finish"; wait "$HARNESS_PID" 2>/dev/null || true
            record_result "$ic_cell" inventory "$ic_scope" "$ic_fs"
            return 0
        fi
        set +e
        wait "$SPID" 2>/dev/null
        echo "observer exit: $?" > "$ic_dir/observer.rc"
        SPID=
        set -e
    else
        : > "$ic_dir/go"
        if ! wait_grep "harness OK" "$ic_dir/harness.stdout" 400; then
            echo "harness never finished its calls"
            : > "$ic_dir/finish"; wait "$HARNESS_PID" 2>/dev/null || true
            record_result "$ic_cell" inventory "$ic_scope" "$ic_fs"
            return 0
        fi
        set +e
        case $ic_scope in
            pid)
                flock "$PRIVLOCK" sudo -n "$MATRIX_TIMEOUT" --foreground \
                    --signal=TERM --kill-after=5s 120s "$P11SCOPE_EXE" inventory \
                    --pid "$HARNESS_PID" --json -o "$ic_dir/out.json" \
                    > "$ic_dir/observer.stdout" 2> "$ic_dir/observer.stderr"
                ;;
            cgroup)
                flock "$PRIVLOCK" sudo -n "$MATRIX_TIMEOUT" --foreground \
                    --signal=TERM --kill-after=5s 120s "$P11SCOPE_EXE" inventory \
                    --cgroup "$ic_cgdir" --json -o "$ic_dir/out.json" \
                    > "$ic_dir/observer.stdout" 2> "$ic_dir/observer.stderr"
                ;;
        esac
        echo "observer exit: $?" > "$ic_dir/observer.rc"
        set -e
    fi
    : > "$ic_dir/finish"
    set +e
    wait "$HARNESS_PID" 2>/dev/null
    echo "harness exit: $?" > "$ic_dir/harness.rc"
    set -e
    # shellcheck disable=SC2086
    run_oracle "$ic_cell" --mode inventory --scope "$ic_scope" --json "$ic_dir/out.json" \
        --stdout "$ic_dir/observer.stdout" --stderr "$ic_dir/observer.stderr" \
        --provider libnodata.so --sysprovider libsofthsm2.so --min-calls 0 \
        --caller "$CALLER_HARNESS" $ic_pidargs || true
    record_result "$ic_cell" inventory "$ic_scope" "$ic_fs"
}

run_cell() {
    case $1 in
        run-hostfs) cell_run "$1" hostfs harness 1 ;;
        run-syspath) cell_run "$1" syspath harness 1 ;;
        run-pkcs11-tool) cell_run "$1" hostfs pkcs11-tool "" ;;
        run-overlay) cell_run "$1" overlay harness 1 ;;
        run-tmpfs) cell_run "$1" tmpfs harness 1 ;;
        run-bind) cell_run "$1" bind harness 1 ;;
        profile-pid-hostfs) cell_live "$1" profile pid hostfs 1 none ;;
        profile-system-hostfs) cell_live "$1" profile system hostfs "" none ;;
        profile-pid-overlay) cell_live "$1" profile pid overlay 1 none ;;
        profile-pid-deleted) cell_live "$1" profile pid deleted "" deleted ;;
        profile-pid-copyup) cell_live "$1" profile pid copyup "" copyup ;;
        trace-pid-hostfs) cell_live "$1" trace pid hostfs 1 none ;;
        inventory-pid-hostfs) cell_inventory "$1" pid hostfs none ;;
        inventory-system-hostfs) cell_inventory "$1" system hostfs none ;;
        inventory-cgroup-hostfs) cell_inventory "$1" cgroup hostfs none ;;
        inventory-cgroup-overlay) cell_inventory "$1" cgroup overlay none ;;
        inventory-pid-overlay) cell_inventory "$1" pid overlay none ;;
        inventory-pid-tmpfs) cell_inventory "$1" pid tmpfs none ;;
        inventory-pid-bind) cell_inventory "$1" pid bind none ;;
        inventory-pid-deleted) cell_inventory "$1" pid deleted deleted ;;
        inventory-pid-copyup) cell_inventory "$1" pid copyup copyup ;;
    esac
}

# shellcheck disable=SC2086
for cell in $ONLY_CELLS; do
    run_cell "$cell"
done

echo "=== result table ==="
column -t -s "$(printf '\t')" "$RESULTS" || cat "$RESULTS"
fails=$(awk -F'\t' '$5 == "FAIL" { n++ } END { print n + 0 }' "$RESULTS")
if [ -n "$NO_ORACLE" ]; then fails=0; fi
echo "cells: $(awk -F'\t' 'NR > 1' "$RESULTS" | wc -l), FAIL: $fails"
[ "$fails" -eq 0 ]
