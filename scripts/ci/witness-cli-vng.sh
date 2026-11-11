#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# witness-cli-vng.sh TESTBIN OUTDIR KERNEL — run the P2-8 witness CLI
# cells as root inside one virtme-ng guest booted on KERNEL (a mainline
# tag such as v6.6.157, or a release candidate such as v7.4-rc1) via
# scripts/ci/run-witness-cli.sh, and judge the
# rows exactly like the host leg (exit 0 plus seven qualified rows).
#
# The guest shares the host rootfs read-only and hides /tmp and /var/tmp,
# so TESTBIN and OUTDIR must live under /home. Inside the guest the cells
# run with TMPDIR on a guest-local tmpfs: the shared 9p tree slows
# capture cells and remaps ownership. OUTDIR receives cells/results.jsonl,
# cells/summary.txt, one cells/<test>.log per cell, run.log, uname.txt,
# vng-console.log and the staged kernel-config.
#
# The pre-arm witness needs the running kernel's LTO status from
# /boot/config-{release}, but the shared rootfs only carries the host's
# configs. The harness stages the booted kernel's config from the vng
# cache as OUTDIR/kernel-config and the guest installs it over a tmpfs
# /boot before the cells run; without it the witness stays unavailable
# and the exact-count cells fail. WITNESS_VNG_CACHE overrides the cache
# root for tests.
#
# Exit codes: 0 every cell passed; 1 a cell failed; 2 harness error
# (bad usage, vng failure, wrong guest kernel, missing results,
# missing kernel config);
# 77 a prerequisite is missing (vng not on PATH).
#
# Apt prerequisites on a GitHub ubuntu-26.04 runner (installed by the
# calling workflow, not here): busybox-static qemu-system-x86 qemu-utils
# seabios ipxe-qemu gcc (the cells compile their runtime workload in the
# guest) softhsm2 (the guest shares the runner rootfs, so the provider
# cells see the runner's SoftHSM install) opensc (pkcs11-tool for the
# learned-provider cell). virtme-ng comes from pipx at
# the workflow's pinned CI_VNG_VERSION.
set -u

[ $# -eq 3 ] || { echo "usage: witness-cli-vng.sh TESTBIN OUTDIR KERNEL" >&2; exit 2; }
TESTBIN=$(realpath -e -- "$1") || exit 2
OUT=$2
KERNEL=$3
case "$KERNEL" in v[0-9]*.[0-9]*.[0-9]*|v[0-9]*.[0-9]*-rc[0-9]*) ;; *)
    echo "witness-cli-vng.sh: use an explicit stock kernel release: $KERNEL" >&2; exit 2;;
esac
command -v vng >/dev/null || { echo "witness-cli-vng.sh: vng not on PATH" >&2; exit 77; }
command -v python3 >/dev/null || { echo "witness-cli-vng.sh: python3 not on PATH" >&2; exit 77; }
[ -x "$TESTBIN" ] || { echo "witness-cli-vng.sh: test binary not executable: $TESTBIN" >&2; exit 2; }
if [ "${WITNESS_CLI_VNG_TEST:-0}" != 1 ]; then
    case "$TESTBIN:$OUT" in /tmp/*|/var/tmp/*|*:/tmp/*|*:/var/tmp/*)
        echo "witness-cli-vng.sh: test binary and OUTDIR must be under /home" >&2; exit 2;;
    esac
fi
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
RUNNER="$HERE/run-witness-cli.sh"
[ -x "$RUNNER" ] || { echo "witness-cli-vng.sh: cell runner missing: $RUNNER" >&2; exit 2; }
# Guest release match, shared with the BPF load drivers.
[ -f "$HERE/../bpf-guest-release.sh" ] || { echo "release match not found: $HERE/../bpf-guest-release.sh" >&2; exit 2; }
. "$HERE/../bpf-guest-release.sh"
umask 022; mkdir -p "$OUT" && chmod 755 "$OUT"; OUT=$(realpath -e -- "$OUT") || exit 2
# Stage the booted kernel's config for the guest LTO gate: the vng cache
# holds exactly one config per kernel tag.
VNG_CACHE="${WITNESS_VNG_CACHE:-$HOME/.cache/virtme-ng}"
shopt -s nullglob
configs=("$VNG_CACHE/$KERNEL/amd64/boot"/config-*)
shopt -u nullglob
if [ "${#configs[@]}" != 1 ]; then
    echo "witness-cli-vng.sh: want exactly one kernel config for $KERNEL in $VNG_CACHE, found ${#configs[@]}" >&2
    exit 2
fi
cp -p "${configs[0]}" "$OUT/kernel-config" || exit 2
grep -q CONFIG_LTO "$OUT/kernel-config" || {
    echo "witness-cli-vng.sh: staged kernel config lacks CONFIG_LTO for $KERNEL" >&2
    exit 2
}

# Single-quote a path for the guest shell.
q() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

{
    printf '#!/bin/sh\nset -u\n'
    printf 'OUT=%s\nTESTBIN=%s\nRUNNER=%s\n' "$(q "$OUT")" "$(q "$TESTBIN")" "$(q "$RUNNER")"
    cat <<'INNER_EOF'
uname -r > "$OUT/uname.txt"
[ "$(id -u)" = 0 ] || { echo "guest root required"; exit 2; }
# The witness LTO gate reads /boot/config-{release}; the shared rootfs
# only has the host's, so install the staged booted-kernel config over a
# guest-local /boot before the cells run.
mount -t tmpfs -o mode=755 tmpfs /boot || exit 2
cp "$OUT/kernel-config" "/boot/config-$(uname -r)" || exit 2
grep -q CONFIG_LTO "/boot/config-$(uname -r)" || exit 2
T=/tmp/witness-work
mkdir -p "$T" && mount -t tmpfs -o mode=700,size=2G tmpfs "$T" || exit 2
df -T "$T" | tail -n 1
TMPDIR="$T" "$RUNNER" "$TESTBIN" "$OUT/cells" > "$OUT/run.log" 2>&1
rc=$?
echo "cells-done witness_exit=$rc"
INNER_EOF
} > "$OUT/inner.sh"

s=$(date +%s)
if ! timeout -k 30 1200 vng --run "$KERNEL" --user root --cpus 4 --memory 4G \
    --rwdir "$OUT" --exec "sh $OUT/inner.sh" < /dev/null >"$OUT/vng-console.log" 2>&1; then
    echo "witness-cli-vng.sh: vng run failed or timed out on $KERNEL (see $OUT/vng-console.log)" >&2
    exit 2
fi
wall=$(( $(date +%s) - s ))
witness_exit=$(sed -n 's/^cells-done witness_exit=//p' "$OUT/vng-console.log" | tail -n 1)
if [ -z "$witness_exit" ]; then
    echo "witness-cli-vng.sh: guest never finished on $KERNEL (see $OUT/vng-console.log)" >&2
    exit 2
fi
if [ ! -f "$OUT/uname.txt" ]; then
    echo "witness-cli-vng.sh: no guest uname on $KERNEL" >&2
    exit 2
fi
release=$(cat "$OUT/uname.txt")
if release_ok "$KERNEL" "$release"; then
    echo "# guest release $release (expected $KERNEL)"
else
    echo "witness-cli-vng.sh: guest booted $release, expected $KERNEL" >&2
    exit 2
fi
case "$witness_exit" in
    0|1) ;;
    *)
        echo "witness-cli-vng.sh: cell runner exited $witness_exit on $KERNEL (see $OUT/run.log)" >&2
        exit 2
        ;;
esac
if [ ! -s "$OUT/cells/results.jsonl" ] || [ ! -s "$OUT/cells/summary.txt" ]; then
    echo "witness-cli-vng.sh: guest produced no cell results on $KERNEL" >&2
    exit 2
fi
# The rows must be exactly the seven cells: a truncated or
# hand-edited file is a harness error, never a partial pass.
if ! python3 -I - "$OUT/cells/results.jsonl" <<'PY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
want={'privileged_profile_pid_prearm_clean_exact_counts',
      'privileged_profile_cgroup_prearm_clean_exact_counts',
      'privileged_profile_system_prearm_clean_exact_counts',
      'privileged_profile_metrics_system_prearm_clean_exact_counts',
      'privileged_profile_pid_prearm_twin_exact_window',
      'privileged_trace_system_prearm_clean_exact_counts',
      'privileged_profile_system_learned_provider_second_round_catches_oneshots'}
ids=[row['cell'] for row in rows]
if len(ids) != len(set(ids)) or set(ids) != want:
    sys.exit('row set is not exactly the seven cells')
PY
then
    echo "witness-cli-vng.sh: bad row set on $KERNEL (see $OUT/cells/results.jsonl)" >&2
    exit 2
fi
all_pass=$(python3 -I -c '
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
print("yes" if all(row["pass"] and row["qualification"] == "qualified" for row in rows) else "no")
' "$OUT/cells/results.jsonl")
if [ "$witness_exit" -eq 0 ] && [ "$all_pass" = yes ]; then
    echo "witness-cli-vng.sh: PASS on $KERNEL in ${wall}s ($OUT/cells/results.jsonl)"
    exit 0
fi
if [ "$witness_exit" -eq 1 ] && [ "$all_pass" = no ]; then
    echo "witness-cli-vng.sh: FAIL on $KERNEL in ${wall}s (see $OUT/cells/results.jsonl)" >&2
    exit 1
fi
# The runner's exit disagrees with its rows: inconsistent, not a verdict.
echo "witness-cli-vng.sh: runner exited $witness_exit with all_pass=$all_pass on $KERNEL" >&2
exit 2
