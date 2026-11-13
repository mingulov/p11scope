#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# qualify-public-cli-vng.sh KERNEL P11SCOPE OUTDIR — run scripts/qualify-public-cli.sh as root
# inside a virtme-ng guest booted on KERNEL (a mainline tag such as v6.1.188, or a vmlinuz path),
# then the least-privilege cell (scripts/ci/minimal-setcap.sh: the observer as the unprivileged
# `nobody` user with exactly the minimal setcap set, no sudo, no CAP_SYS_ADMIN).
# The guest shares the host rootfs read-only and hides /tmp and /var/tmp, so the binary and
# OUTDIR must live under /home. Take the VM lane lock around this script.
# The vng invocation runs under scripts/ci/vng-boot-watch.sh (console to
# OUTDIR/vng-console.log, diagnostics to OUTDIR/vng-boot-diag.log): host
# KVM is probed (advisory: a denied open only selects TCG) before
# the boot, and a guest that prints nothing and
# writes no uname.txt within VNG_BOOT_TIMEOUT_S (default 300) trips
# VNG_BOOT_TIMEOUT instead of hanging to the job timeout.
# MODULE, when set, is forwarded to the guest (a provider path under /home or /usr).
# Exit codes: the guest's qualify exit (0 qualifies, 1 fails, 2 is the
# documented nonqualifying smoke); 1 when vng itself fails, when the results
# are missing, or when the minimal-setcap leg fails (a minimal failure
# dominates even a nonqualifying-smoke qualify exit).
# P11SCOPE_STARTUP_BOUND_S, when set, is forwarded for the startup-to-capturing cell.
set -u
K=$1; BIN=$(realpath -e "$2"); OUT=$3
REPO=$(cd "$(dirname "$0")/.." && pwd)
WATCH="$REPO/scripts/ci/vng-boot-watch.sh"
[ -x "$WATCH" ] || { echo "qualify-public-cli-vng.sh: boot watch missing: $WATCH" >&2; exit 1; }
case "$BIN:$OUT" in /tmp/*|/var/tmp/*|*:/tmp/*|*:/var/tmp/*) echo "binary and OUTDIR must be under /home" >&2; exit 64;; esac
# p11scope refuses -o directories writable by group/other; keep the tree owner-only.
umask 022; mkdir -p "$OUT" && chmod 755 "$OUT"; OUT=$(realpath -e "$OUT")
cat > "$OUT/inner.sh" <<INNER
#!/bin/sh
uname -r > $OUT/uname.txt
# Capture into a guest-local root-owned tmpfs: the shared 9p tree is owned by the
# host user and remaps ownership, which p11scope's -o trust and private temp-file
# identity checks rightly refuse for a root observer. Evidence is copied out after.
mkdir -p /tmp/qual && chmod 755 /tmp/qual
${MODULE:+MODULE=$MODULE }${P11SCOPE_STARTUP_BOUND_S:+P11SCOPE_STARTUP_BOUND_S=$P11SCOPE_STARTUP_BOUND_S }THREADS=4 $REPO/scripts/qualify-public-cli.sh $BIN /tmp/qual/cells > $OUT/qual.log 2>&1
echo "qual_exit=\$?" >> $OUT/qual.log
cp -r /tmp/qual/cells $OUT/cells
$REPO/scripts/ci/run-cell-script.sh minimal-setcap $BIN /tmp/qual/minimal-cells > $OUT/minimal.log 2>&1
echo "minimal_exit=\$?" >> $OUT/minimal.log
cp -r /tmp/qual/minimal-cells $OUT/minimal-cells
INNER
s=$(date +%s)
"$WATCH" --marker "$OUT/uname.txt" --console "$OUT/vng-console.log" --diag "$OUT/vng-boot-diag.log" -- \
    vng --run "$K" --user root --cpus 4 --memory 4G --rwdir "$OUT" --exec "sh $OUT/inner.sh"
vng_exit=$?
echo "vng_exit=$vng_exit wall=$(( $(date +%s)-s ))s kernel=$(cat "$OUT/uname.txt" 2>/dev/null) $(cat "$OUT/cells/summary.txt" 2>/dev/null)"
[ "$vng_exit" -eq 0 ] || exit 1
[ -s "$OUT/cells/summary.txt" ] || { echo "qualify-public-cli-vng: missing cells/summary.txt" >&2; exit 1; }
[ -s "$OUT/minimal-cells/results.jsonl" ] || { echo "qualify-public-cli-vng: missing minimal-cells/results.jsonl" >&2; exit 1; }
minimal_exit=$(sed -n 's/^minimal_exit=//p' "$OUT/minimal.log" 2>/dev/null | tail -n 1)
case "$minimal_exit" in
    0) ;;
    *) echo "qualify-public-cli-vng: minimal setcap leg failed (minimal_exit=$minimal_exit)" >&2; exit 1;;
esac
qual_exit=$(sed -n 's/^qual_exit=//p' "$OUT/qual.log" 2>/dev/null | tail -n 1)
case "$qual_exit" in
    0|1|2) exit "$qual_exit";;
    *) echo "qualify-public-cli-vng: missing qual_exit in qual.log" >&2; exit 1;;
esac
