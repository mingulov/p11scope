#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# lib-cells-vng.sh LIBTEST OUTDIR [KERNEL...] — run the kernel-sensitive
# privileged lib-cell subset as root inside virtme-ng guests, one guest per
# kernel, and judge every cell exactly like run-privileged-lib-tests.sh
# (exit 0 plus "test result: ok. 1 passed" in the cell log).
#
# Cells (exact selectors, all curated default cells):
#   PID-scope tiers (classic auto/singles/forced-multi):
#     attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_auto_excludes_foreign_and_reused_pid_lp64
#     attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64
#     attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_singles_excludes_foreign_and_reused_pid_lp64
#   PID-filter Multi cells:
#     attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64
#     attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64
#   identity iterator:
#     attach::identity_iter::tests::anchor_maps_validate_real_handles
#     attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none
#     attach::identity_iter::tests::whole_system_run_covers_all_children
#     attach::identity_iter::tests::wronly_anchor_fds_refuse_reads_with_eperm
#   counter readers:
#     metrics::counter_reader::tests::counter_reader_native_maps_match_all_modes
#     metrics::counter_reader::tests::counter_reader_requires_exact_maps_and_health
#   uretprobe hazard probe:
#     events::runtime_tests::real_uretprobe_hazard_self_probe_reaches_a_verdict
#
# Default kernels: v6.6.157 v6.12.111.
#
# The guest shares the host rootfs read-only and hides /tmp and /var/tmp,
# so LIBTEST and OUTDIR must live under /home. Inside the guest every cell
# runs with TMPDIR on a guest-local tmpfs: the shared 9p tree slows the
# uprobe cells 12-50x. The guest also stages its kernel's /boot/config from
# the virtme-ng cache (the check-bpf-load-kernels.sh pattern), so the
# instance hooks load the way they do on ordinary hosts. Per-cell evidence
# and logs are copied back to OUTDIR/<kernel>/; OUTDIR/results.jsonl carries
# one row per cell: {"cell", "pass", "qualification", "detail"}.
#
# Exit codes: 0 every cell passed; 1 a cell failed; 2 harness error
# (bad usage, vng failure, wrong guest kernel, missing logs);
# 77 a prerequisite is missing (vng not on PATH).
#
# Apt prerequisites on a GitHub ubuntu-26.04 runner (installed by the
# calling workflow, not here): busybox-static qemu-system-x86 qemu-utils
# seabios ipxe-qemu gcc (guest cc for the owned fixtures) softhsm2
# libp11-kit-dev (the guest shares the runner rootfs, so the provider
# cells see the runner's SoftHSM install). virtme-ng comes from pipx at
# the workflow's pinned CI_VNG_VERSION.
set -u

[ $# -ge 2 ] || { echo "usage: lib-cells-vng.sh LIBTEST OUTDIR [KERNEL...]" >&2; exit 2; }
LIBTEST=$(realpath -e -- "$1") || exit 2
OUT=$2
shift 2
if [ $# -eq 0 ]; then
    set -- v6.6.157 v6.12.111
fi
command -v vng >/dev/null || { echo "lib-cells-vng.sh: vng not on PATH" >&2; exit 77; }
command -v python3 >/dev/null || { echo "lib-cells-vng.sh: python3 not on PATH" >&2; exit 77; }
[ -x "$LIBTEST" ] || { echo "lib-cells-vng.sh: libtest not executable: $LIBTEST" >&2; exit 2; }
if [ "${LIB_CELLS_VNG_TEST:-0}" != 1 ]; then
    case "$LIBTEST:$OUT" in /tmp/*|/var/tmp/*|*:/tmp/*|*:/var/tmp/*)
        echo "lib-cells-vng.sh: libtest and OUTDIR must be under /home" >&2; exit 2;;
    esac
fi
umask 022; mkdir -p "$OUT" && chmod 755 "$OUT"; OUT=$(realpath -e -- "$OUT") || exit 2

# Single-quote a path for the guest shell.
q() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

CELLS=(
attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_auto_excludes_foreign_and_reused_pid_lp64
attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64
attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_singles_excludes_foreign_and_reused_pid_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64
attach::identity_iter::tests::anchor_maps_validate_real_handles
attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none
attach::identity_iter::tests::whole_system_run_covers_all_children
attach::identity_iter::tests::wronly_anchor_fds_refuse_reads_with_eperm
metrics::counter_reader::tests::counter_reader_native_maps_match_all_modes
metrics::counter_reader::tests::counter_reader_requires_exact_maps_and_health
events::runtime_tests::real_uretprobe_hazard_self_probe_reaches_a_verdict
)

VNG_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/virtme-ng"
RESULTS="$OUT/results.jsonl"
rm -f "$RESULTS"
FAILED=0
HARNESS_FAILED=0

for KERNEL in "$@"; do
    case "$KERNEL" in v[0-9]*.[0-9]*.[0-9]*) ;; *)
        echo "lib-cells-vng.sh: use an explicit stock kernel release: $KERNEL" >&2; exit 2;;
    esac
    KOUT="$OUT/$KERNEL"
    mkdir -p "$KOUT" && chmod 755 "$KOUT" || exit 2
    rm -f "$KOUT"/cell-*.log "$KOUT"/status.txt "$KOUT"/uname.txt "$KOUT"/vng-console.log
    {
        printf '#!/bin/sh\nset -u\n'
        printf 'KOUT=%s\nLIBTEST=%s\nVNG_CACHE=%s\n' "$(q "$KOUT")" "$(q "$LIBTEST")" "$(q "$VNG_CACHE")"
        cat <<'INNER_EOF'
uname -r > "$KOUT/uname.txt"
K=$(cat "$KOUT/uname.txt")
if [ ! -r "/boot/config-$K" ]; then
    C=$(ls "$VNG_CACHE"/*/amd64/boot/config-"$K" 2>/dev/null | head -n 1)
    [ -n "$C" ] || { echo "no-kernel-config-for-$K"; exit 2; }
    mount -t tmpfs -o mode=755 guestboot /boot && cp "$C" /boot/ || { echo "stage-boot-failed-$K"; exit 2; }
    echo "staged-boot-config-$K"
else
    echo "boot-config-present-$K"
fi
[ "$(id -u)" = 0 ] || { echo "guest root required"; exit 2; }
T=/tmp/libcells-work
mkdir -p "$T" && mount -t tmpfs -o mode=700,size=2G tmpfs "$T" || exit 2
df -T "$T" | tail -n 1
ulimit -n 65536
INNER_EOF
        i=0
        for cell in "${CELLS[@]}"; do
            printf 'ev="$T/ev-%d"; mkdir -p "$ev"\nP11SCOPE_TASK4_EVIDENCE_DIR="$ev" P11SCOPE_TASK4_CASE_INDEX=%d TMPDIR="$T" "$LIBTEST" --exact %s --ignored --test-threads=1 --nocapture > "$KOUT/cell-%d.log" 2>&1\nrc=$?\necho "%d $rc %s" >> "$KOUT/status.txt"\n' \
                "$i" "$i" "$cell" "$i" "$i" "$cell"
            i=$((i + 1))
        done
        printf 'echo "cells-done count=%d"\n' "${#CELLS[@]}"
    } > "$KOUT/inner.sh"
    s=$(date +%s)
    if ! timeout -k 30 1200 vng --run "$KERNEL" --user root --cpus 4 --memory 4G \
        --rwdir "$KOUT" --exec "sh $KOUT/inner.sh" < /dev/null >"$KOUT/vng-console.log" 2>&1; then
        echo "lib-cells-vng.sh: vng run failed or timed out on $KERNEL (see $KOUT/vng-console.log)" >&2
        HARNESS_FAILED=1
        continue
    fi
    wall=$(( $(date +%s) - s ))
    if ! grep -q '^cells-done ' "$KOUT/vng-console.log"; then
        echo "lib-cells-vng.sh: guest never finished on $KERNEL (see $KOUT/vng-console.log)" >&2
        HARNESS_FAILED=1
        continue
    fi
    if ! grep -Eq '^(staged-boot-config|boot-config-present)-' "$KOUT/vng-console.log"; then
        echo "lib-cells-vng.sh: kernel config not staged on $KERNEL" >&2
        HARNESS_FAILED=1
        continue
    fi
    if [ ! -f "$KOUT/uname.txt" ]; then
        echo "lib-cells-vng.sh: no guest uname on $KERNEL" >&2
        HARNESS_FAILED=1
        continue
    fi
    release=$(cat "$KOUT/uname.txt")
    case "$release" in
        "${KERNEL#v}"|"${KERNEL#v}-"*)
            echo "# guest release $release (expected $KERNEL)"
            ;;
        *)
            echo "lib-cells-vng.sh: guest booted $release, expected $KERNEL" >&2
            HARNESS_FAILED=1
            continue
            ;;
    esac
    if [ ! -f "$KOUT/status.txt" ] || [ "$(wc -l < "$KOUT/status.txt")" -ne "${#CELLS[@]}" ]; then
        echo "lib-cells-vng.sh: status.txt incomplete on $KERNEL" >&2
        HARNESS_FAILED=1
        continue
    fi
    # Judge every cell: exit 0 plus exactly one pass, like the privileged runner.
    i=0
    for cell in "${CELLS[@]}"; do
        log="$KOUT/cell-$i.log"
        rc=$(awk -v want="$i" '$1 == want {print $2}' "$KOUT/status.txt")
        got=$(awk -v want="$i" '$1 == want {print $3}' "$KOUT/status.txt")
        pass=0
        detail="kernel=$KERNEL wall=${wall}s rc=${rc:-absent}"
        if [ "${got:-}" != "$cell" ]; then
            HARNESS_FAILED=1
            detail="$detail status names ${got:-nothing}, expected the cell"
        elif [ ! -f "$log" ]; then
            HARNESS_FAILED=1
            detail="$detail no log"
        elif [ "${rc:-1}" = 0 ] && grep -q 'test result: ok\. 1 passed' "$log"; then
            pass=1
            detail="$detail ok"
        else
            FAILED=1
            tail_line=$(tail -n 1 "$log" 2>/dev/null | head -c 200 | tr -d '\000')
            detail="$detail ${tail_line:-empty log}"
        fi
        CELLS_JSON_CELL="$cell" CELLS_JSON_PASS="$pass" CELLS_JSON_DETAIL="$detail" python3 -I -c \
            'import json,os; print(json.dumps({"cell": os.environ["CELLS_JSON_CELL"], "pass": os.environ["CELLS_JSON_PASS"] == "1", "qualification": "qualified" if os.environ["CELLS_JSON_PASS"] == "1" else "failed", "detail": os.environ["CELLS_JSON_DETAIL"]}))' >> "$RESULTS"
        i=$((i + 1))
    done
done

if [ "$HARNESS_FAILED" -ne 0 ]; then
    echo "lib-cells-vng.sh: HARNESS ERROR (see $OUT)" >&2
    exit 2
fi
if [ "$FAILED" -ne 0 ]; then
    echo "lib-cells-vng.sh: FAIL (see $RESULTS)" >&2
    exit 1
fi
echo "lib-cells-vng.sh: PASS ($OUT/results.jsonl)"
