#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-public-cli-vng.sh KERNEL P11SCOPE OUTDIR — run scripts/qualify-public-cli.sh as root
# inside a virtme-ng guest booted on KERNEL (a mainline tag such as v6.1.188, or a vmlinuz path).
# The guest shares the host rootfs read-only and hides /tmp and /var/tmp, so the binary and
# OUTDIR must live under /home. Take the VM lane lock around this script.
set -u
K=$1; BIN=$(realpath -e "$2"); OUT=$3
REPO=$(cd "$(dirname "$0")/.." && pwd)
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
THREADS=4 $REPO/scripts/qualify-public-cli.sh $BIN /tmp/qual/cells > $OUT/qual.log 2>&1
echo "qual_exit=\$?" >> $OUT/qual.log
cp -r /tmp/qual/cells $OUT/cells
INNER
s=$(date +%s)
vng --run "$K" --user root --cpus 4 --memory 4G --rwdir "$OUT" --exec "sh $OUT/inner.sh" > "$OUT/vng-console.log" 2>&1
echo "vng_exit=$? wall=$(( $(date +%s)-s ))s kernel=$(cat "$OUT/uname.txt" 2>/dev/null) $(cat "$OUT/cells/summary.txt" 2>/dev/null)"
