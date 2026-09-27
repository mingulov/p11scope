#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Reproducible runner for the privileged (ignored) p11scope lib tests.
#
# Usage:
#   scripts/run-privileged-lib-tests.sh LIB_TEST_BINARY OUTDIR [--include-long] [SELECTOR...]
#   scripts/run-privileged-lib-tests.sh --list LIB_TEST_BINARY
#
# Run mode executes each selected ignored test once, one at a time, from the
# repo root, as:
#   <binary> --exact <full-path> --ignored --test-threads=1 --nocapture
# with TMPDIR pointed at a private dir under OUTDIR, `ulimit -n 65536`, and a
# fresh per-test evidence dir plus case index. It must run as root (exit 64
# otherwise) because the campaign loads BPF. --list mode prints the curated
# lists without running anything and works unprivileged.
#
# Per-test environment (from every std::env::var/var_os read in the files
# that define ignored tests):
#   P11SCOPE_TASK4_EVIDENCE_DIR + P11SCOPE_TASK4_CASE_INDEX: required by the
#     15 Task 4 / T7 tests (Task4Evidence::new_control, task4_fixture_receipt
#     and the identity-seal receipts in attach/inventory/activation tests).
#     The script provides a fresh OUTDIR/evidence/<seq>-<name>/ dir per test
#     and the run-order index 0..N (index < 100 is enforced by the tests; the
#     gates write offsets-<index>.json into the dir themselves, so a fresh
#     dir plus any index is sufficient). Set for every test; readers other
#     than the Task 4 gates do not exist, so it is inert elsewhere.
#   P11SCOPE_TASK4_SYNTHETIC_EVIDENCE_DIR / _DETAILED_: read only by
#     non-ignored synthetic replay tests, optional with a tempdir default;
#     the runner never executes those tests and does not set these.
#   P11SCOPE_I3A_RETIREMENT_* (retirement churn test), P11SCOPE_TEST_DISCOVERY_*
#     (manifest helper; set by its own fixture), P11SCOPE_ALIAS_COLLISION_*
#     (cross-device scan test), P11SCOPE_FIRST_USE_PROBE_CONFIG (first-use
#     probe), P11SCOPE_ROOT_RUNTIME_STAGE (root fence): each belongs to a
#     test on the static SKIP list below, which the script cannot provide a
#     fixture for, so they are never set here.
#   RLIMIT_NOFILE: the Task 4 gates sample soft/hard nofile per phase, the
#     T7 boundary cell pref lights live FD occupancy against it, and
#     Session::start may raise soft to hard at attach; wide cells attach
#     thousands of links, hence `ulimit -n 65536` before the campaign.
#
# Pass criterion: a test PASSES only if its log contains
#   "test result: ok. 1 passed"
# (exactly one test ran) and the harness exited 0. An exit code alone is not
# accepted, and "0 passed" (renamed/missing test) is a FAIL.
#
# Curation (48 ignored tests in the default-feature lib binary): 39 run by
# default, 4 run only with --include-long, 5 are statically skipped with a
# reason. Both modes verify the curation against the binary's own
# `--list --ignored` output and refuse on drift, so a new ignored test can
# never be silently dropped and a renamed one can never silently pass.
set -uo pipefail

PROG=${0##*/}
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

# Default campaign: every ignored test except the long cells and the static
# skips. Order is the binary's --list order; each runs in its own process.
DEFAULT_TESTS=(
attach::inventory::activation::privileged_tests::privileged_detailed_multithread_owner_accounting_exact
attach::inventory::activation::privileged_tests::privileged_detailed_owner_poison_is_disclosed
attach::inventory::activation::privileged_tests::privileged_inventory_activation_cgroup_separates_owned_callers
attach::inventory::activation::privileged_tests::privileged_inventory_activation_failure_preserves_usage_and_releases_resources
attach::inventory::activation::privileged_tests::privileged_inventory_activation_stop_with_owned_calls_in_progress
attach::inventory::activation::privileged_tests::privileged_inventory_activation_system_ia32
attach::inventory::activation::privileged_tests::privileged_inventory_activation_system_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_caller_cgroup_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_caller_partial_activation_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_caller_system_ia32
attach::inventory::activation::privileged_tests::privileged_inventory_caller_system_lp64
attach::inventory::activation::privileged_tests::privileged_stop_gate_freezes_capture_state_after_quiescence
attach::inventory::activation::privileged_tests::privileged_stop_gate_keeps_calls_in_flight_as_residual
attach::inventory::activation::privileged_tests::privileged_t7_detailed_hot_slot_third_rv_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n1024_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n576_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_n512_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_physical_identity_controls
attach::inventory::activation::privileged_tests::privileged_task4_inventory_2112_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2049_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n511_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n512_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n513_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_physical_identity_controls
attach::inventory::privileged_tests::privileged_inventory_caller_preparation_faults_release_exact_resources
attach::inventory::privileged_tests::privileged_inventory_caller_preparation_freezes_native_maps_and_publishes_binding
attach::inventory::privileged_tests::privileged_inventory_preparation_failure_releases_owned_resources
attach::inventory::privileged_tests::privileged_inventory_preparation_freezes_all_eight_protected_maps
attach::inventory::privileged_tests::privileged_inventory_preparation_loads_multi_without_links
attach::inventory::privileged_tests::privileged_inventory_preparation_loads_runtime_capacity_and_zero_links
attach::lifecycle_tests::exec_tests::privileged_detailed_failed_nonleader_exec_preserves_start_and_image
attach::lifecycle_tests::exec_tests::privileged_detailed_nonleader_exec_cleans_old_tid_before_same_session_rebind
attach::lifecycle_tests::privileged_detailed_nonleader_exit_preserves_same_slot_sibling_start
attach::lifecycle_tests::privileged_detailed_nonleader_exit_reclaims_start_and_preserves_leader
discovery::engine::publication_tests::broad_p11kit_admission_arithmetic
events::runtime_tests::real_retained_consumer_keeps_one_cursor_across_all_drains
events::runtime_tests::real_retained_discovery_consumer_owns_one_exact_map
events::runtime_tests::real_uretprobe_hazard_self_probe_reaches_a_verdict
)

# Long campaign cells: run only with --include-long.
LONG_TESTS=(
attach::inventory::activation::privileged_tests::privileged_bench_overhead_detailed_calls
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n4097_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6530_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n8192_boundary_lp64
)

# Static skips: external fixture/driver/env the script cannot provide.
SKIP_TESTS=(
attach::inventory::activation::privileged_tests::privileged_inventory_retirement_controlled_churn
discovery::engine::tests::lifecycle_manifest_helper_entrypoint
discovery::scan::tests::privileged_cross_device_same_inode_alias_is_refused_on_scan_path
first_use_probe::native::system_capture_observer_facts
run::root_fence_runtime::actual_original_exit_delayed_first_admission_retires_pending
)
SKIP_REASONS=(
"needs an external barrier controller: P11SCOPE_I3A_RETIREMENT_MODE=worker|synchronous plus a root-owned 0700 CONTROL_DIR, a NONCE, and an external party to write the release file; no in-repo controller exists, so run once per mode by hand"
"private helper re-executed by DiscoveryLifecycleFixture with P11SCOPE_TEST_DISCOVERY_PROVIDER/MANIFEST; its own docs say it is not a separate passing test"
"needs a live root-owned target with two private cross-device mounts (same inode, distinct dev) plus P11SCOPE_ALIAS_COLLISION_PID/HINT/TARGET/HARDLINK"
"needs a frozen supervisor config via P11SCOPE_FIRST_USE_PROBE_CONFIG plus an exclusive BPF lane; its verdict requires an external owned oracle"
"needs a separately reviewed native stage via P11SCOPE_ROOT_RUNTIME_STAGE (provider.so, driver, provider.json); the test documents no runtime skip"
)

usage() {
    cat <<EOF
usage: $PROG LIB_TEST_BINARY OUTDIR [--include-long] [SELECTOR...]
       $PROG --list LIB_TEST_BINARY
       $PROG --help

Run the curated privileged (ignored) p11scope lib tests, one at a time.
SELECTORs are literal substrings matched against full test paths; a test
runs when any SELECTOR matches (no SELECTOR runs the whole campaign).
--include-long additionally runs the long campaign cells.
--list prints the curated default, long, and skipped-with-reason lists and
verifies them against the binary, without running anything.
EOF
}

# Print the binary's ignored-test full paths, sorted unique, one per line.
binary_ignored_list() {
    "$1" --list --ignored --format terse 2>/dev/null \
        | sed -e 's/:[[:space:]]*test$//' -e '/^[[:space:]]*$/d' \
        | sort -u
}

# Compare curation against the binary. Prints drift details to stderr and
# returns 1 on any mismatch, so new tests cannot be silently dropped.
check_curation() {
    local bin=$1 workdir bin_list cur_list missing_bin missing_cur
    workdir=$(mktemp -d) || { echo "$PROG: cannot create temp dir" >&2; return 1; }
    bin_list=$workdir/bin.txt
    cur_list=$workdir/cur.txt
    if ! binary_ignored_list "$bin" >"$bin_list"; then
        echo "$PROG: cannot list ignored tests in $bin" >&2
        rm -rf "$workdir"
        return 1
    fi
    {
        printf '%s\n' "${DEFAULT_TESTS[@]}"
        printf '%s\n' "${LONG_TESTS[@]}"
        printf '%s\n' "${SKIP_TESTS[@]}"
    } | sort -u >"$cur_list"
    missing_bin=$(comm -13 "$bin_list" "$cur_list" || true)
    missing_cur=$(comm -23 "$bin_list" "$cur_list" || true)
    rm -rf "$workdir"
    if [ -n "$missing_bin" ] || [ -n "$missing_cur" ]; then
        {
            echo "$PROG: curation drift against $bin"
            [ -n "$missing_bin" ] && {
                echo "curated but absent from the binary (renamed/removed?):"
                printf '  %s\n' $missing_bin
            }
            [ -n "$missing_cur" ] && {
                echo "ignored in the binary but not curated (new test?):"
                printf '  %s\n' $missing_cur
            }
        } >&2
        return 1
    fi
    return 0
}

# --list mode: curated lists plus a verification footer. Unprivileged-safe.
list_mode() {
    local bin name i
    [ $# -eq 1 ] || { usage >&2; return 2; }
    bin=$1
    [ -x "$bin" ] || { echo "$PROG: not an executable test binary: $bin" >&2; return 1; }
    echo "default (${#DEFAULT_TESTS[@]})"
    for name in "${DEFAULT_TESTS[@]}"; do
        case $name in
            *_ia32) echo "$name :: preflight: host cc must compile -m32" ;;
            *broad_p11kit_admission_arithmetic)
                echo "$name :: preflight: host python3 must load libp11-kit.so.0" ;;
            *) echo "$name" ;;
        esac
    done
    echo "long (${#LONG_TESTS[@]}, --include-long only)"
    printf '%s\n' "${LONG_TESTS[@]}"
    echo "skipped (${#SKIP_TESTS[@]})"
    for i in "${!SKIP_TESTS[@]}"; do
        echo "${SKIP_TESTS[$i]} :: ${SKIP_REASONS[$i]}"
    done
    if check_curation "$bin"; then
        echo "verify: curation matches the binary ($(( ${#DEFAULT_TESTS[@]} + ${#LONG_TESTS[@]} + ${#SKIP_TESTS[@]} )) tests)"
        return 0
    fi
    return 1
}

# SELECTORS is the global selector list. selected() returns 0 when $1
# matches any selector (literal substring), or when there are no selectors.
SELECTORS=()
selected() {
    local name=$1 sel
    if [ "${#SELECTORS[@]}" -eq 0 ]; then
        return 0
    fi
    for sel in "${SELECTORS[@]}"; do
        case $name in
            *"$sel"*) return 0 ;;
        esac
    done
    return 1
}

main() {
    local bin outdir include_long=0
    local selected_runnable=() selected_skipped=()
    local arg name i pass=0 fail=0 skipped=0 seq=0
    local tmpdir logdir eviddir results log evdir short start end seconds rc
    local result_line verdict m32_ok=0 p11kit_ok=0 need_m32=0 need_p11kit=0

    if [ $# -eq 0 ]; then
        usage >&2
        return 2
    fi
    case $1 in
        --list) shift; list_mode "$@"; return $? ;;
        -h|--help) usage; return 0 ;;
    esac
    if [ $# -lt 2 ]; then
        usage >&2
        return 2
    fi
    bin=$1
    outdir=$2
    shift 2
    for arg in "$@"; do
        case $arg in
            --include-long) include_long=1 ;;
            --*) echo "$PROG: unknown option: $arg" >&2; usage >&2; return 2 ;;
            *) SELECTORS+=("$arg") ;;
        esac
    done

    if [ "$(id -u)" -ne 0 ]; then
        echo "$PROG: must be run as root (this campaign loads BPF)" >&2
        return 64
    fi
    [ -x "$bin" ] || { echo "$PROG: not an executable test binary: $bin" >&2; return 1; }

    # Resolve before cd-ing to the repo root so relative paths keep working.
    bin=$(CDPATH= cd "$(dirname "$bin")" && pwd)/$(basename "$bin")
    mkdir -p "$outdir" || return 1
    outdir=$(CDPATH= cd "$outdir" && pwd) || return 1

    # Fail fast when the curation no longer covers the binary exactly.
    check_curation "$bin" || return 1

    # Narrow the campaign, preserving curated order and de-duplicating.
    for name in "${DEFAULT_TESTS[@]}"; do
        if selected "$name"; then
            selected_runnable+=("$name")
        fi
    done
    if [ "$include_long" -eq 1 ]; then
        for name in "${LONG_TESTS[@]}"; do
            if selected "$name"; then
                selected_runnable+=("$name")
            fi
        done
    fi
    for i in "${!SKIP_TESTS[@]}"; do
        if selected "${SKIP_TESTS[$i]}"; then
            selected_skipped+=("$i")
        fi
    done
    # Every SELECTOR must match at least one curated test.
    for arg in ${SELECTORS[@]+"${SELECTORS[@]}"}; do
        local matched=0 candidate
        for candidate in "${DEFAULT_TESTS[@]}" "${LONG_TESTS[@]}" "${SKIP_TESTS[@]}"; do
            case $candidate in *"$arg"*) matched=1; break ;; esac
        done
        if [ "$matched" -eq 0 ]; then
            echo "$PROG: selector matches no curated test: $arg" >&2
            return 1
        fi
        if [ "$include_long" -eq 0 ]; then
            for candidate in "${LONG_TESTS[@]}"; do
                case $candidate in
                    *"$arg"*)
                        echo "$PROG: note: '$arg' matches --include-long tests, skipped without the flag" >&2
                        break
                        ;;
                esac
            done
        fi
    done

    tmpdir=$outdir/tmp
    logdir=$outdir/logs
    eviddir=$outdir/evidence
    results=$outdir/results.txt
    mkdir -p "$tmpdir" "$logdir" "$eviddir" || return 1
    chmod 0700 "$tmpdir" || return 1
    export TMPDIR=$tmpdir

    if ! ulimit -n 65536 2>/dev/null; then
        echo "$PROG: cannot raise RLIMIT_NOFILE to 65536" >&2
        return 1
    fi
    local nofile
    nofile=$(ulimit -n)
    if [ "$nofile" != "unlimited" ] && [ "$nofile" -lt 65536 ]; then
        echo "$PROG: RLIMIT_NOFILE stuck at $nofile, need 65536" >&2
        return 1
    fi

    # Runtime preflights for the two external driver dependencies. A failed
    # probe records SKIP with a reason instead of a false FAIL.
    for name in ${selected_runnable[@]+"${selected_runnable[@]}"}; do
        case $name in
            *_ia32) need_m32=1 ;;
            *broad_p11kit_admission_arithmetic) need_p11kit=1 ;;
        esac
    done
    if [ "$need_m32" -eq 1 ]; then
        if printf 'int main(void){return 0;}\n' >"$tmpdir/m32-probe.c" \
            && cc -m32 "$tmpdir/m32-probe.c" -o "$tmpdir/m32-probe" 2>/dev/null; then
            m32_ok=1
        fi
    fi
    if [ "$need_p11kit" -eq 1 ]; then
        if command -v python3 >/dev/null 2>&1 \
            && python3 -c "import ctypes; ctypes.CDLL('libp11-kit.so.0')" 2>/dev/null; then
            p11kit_ok=1
        fi
    fi

    {
        echo "# $PROG run: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# binary: $bin"
        echo "# include_long: $include_long"
        echo "# selectors: ${SELECTORS[*]:-<none>}"
    } >"$results"

    cd "$REPO_ROOT" || return 1

    # Static skips among the selection are recorded, never silently dropped.
    for i in ${selected_skipped[@]+"${selected_skipped[@]}"}; do
        echo "SKIP ${SKIP_TESTS[$i]} :: ${SKIP_REASONS[$i]}" | tee -a "$results"
        skipped=$((skipped + 1))
    done

    for name in ${selected_runnable[@]+"${selected_runnable[@]}"}; do
        case $name in
            *_ia32)
                if [ "$m32_ok" -eq 0 ]; then
                    echo "SKIP $name :: host cc -m32 probe failed (ia32 multilib unavailable)" | tee -a "$results"
                    skipped=$((skipped + 1))
                    continue
                fi
                ;;
            *broad_p11kit_admission_arithmetic)
                if [ "$p11kit_ok" -eq 0 ]; then
                    echo "SKIP $name :: host python3 cannot load libp11-kit.so.0" | tee -a "$results"
                    skipped=$((skipped + 1))
                    continue
                fi
                ;;
        esac
        short=${name##*::}
        log=$logdir/$short.log
        evdir=$eviddir/$seq-$short
        mkdir -p "$evdir" || { echo "$PROG: cannot create $evdir" >&2; return 1; }
        echo "RUN $name [case_index=$seq]"
        start=$(date +%s)
        P11SCOPE_TASK4_EVIDENCE_DIR=$evdir P11SCOPE_TASK4_CASE_INDEX=$seq \
            "$bin" --exact "$name" --ignored --test-threads=1 --nocapture \
            >"$log" 2>&1
        rc=$?
        end=$(date +%s)
        seconds=$((end - start))
        seq=$((seq + 1))
        result_line=$(command grep -F 'test result:' "$log" | tail -n 1 || true)
        [ -n "$result_line" ] || result_line="(no test result line)"
        verdict=FAIL
        if [ "$rc" -eq 0 ] \
            && command grep -qF 'test result: ok. 1 passed' "$log"; then
            verdict=PASS
        fi
        if [ "$verdict" = "PASS" ]; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
        fi
        echo "$verdict $name rc=$rc seconds=$seconds :: $result_line" | tee -a "$results"
    done

    echo "SUMMARY pass=$pass fail=$fail skipped=$skipped" | tee -a "$results"
    [ "$fail" -eq 0 ]
}

main "$@"
