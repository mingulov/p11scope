#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-inventory-c1b-vng.sh KERNEL P11SCOPE OUTDIR [CELLS] — run
# scripts/qualify-inventory-c1b.sh as root inside a virtme-ng guest booted on
# KERNEL (a mainline tag such as v6.1.188, or a vmlinuz path). CELLS defaults
# to "overlay cap": the pre-6.8 overlayfs shape, where a VMA holds the backing
# file. The guest shares the host rootfs read-only and hides /tmp and
# /var/tmp, so the binary and OUTDIR must live under /home; the cells run on
# a guest-local root-owned tmpfs base. Take the privileged lock around this.
set -u
K=$1; BIN=$(realpath -e "$2"); OUT=$3; CELLS=${4:-"overlay cap"}
REPO=$(cd "$(dirname "$0")/.." && pwd)
case "$BIN:$OUT" in /tmp/*|/var/tmp/*|*:/tmp/*|*:/var/tmp/*) echo "binary and OUTDIR must be under /home" >&2; exit 64;; esac
umask 022; mkdir -p "$OUT" && chmod 755 "$OUT"; OUT=$(realpath -e "$OUT")
# Mainline guest kernels build overlayfs as a module the host rootfs lacks:
# load it from virtme-ng's kernel cache when the guest cannot modprobe it.
OVL_KO=$(find "${XDG_CACHE_HOME:-$HOME/.cache}/virtme-ng/$K" -name 'overlay.ko*' 2>/dev/null | head -n 1)
cat > "$OUT/inner.sh" <<INNER
#!/bin/sh
uname -r > $OUT/uname.txt
modprobe overlay 2>/dev/null || { [ -n "$OVL_KO" ] && insmod "$OVL_KO"; }
mkdir -p /tmp/c1b && mount -t tmpfs -o mode=0711 tmpfs /tmp/c1b
$REPO/scripts/qualify-inventory-c1b.sh $BIN --base /tmp/c1b --cells "$CELLS" > $OUT/cells.log 2>&1
echo "cells_exit=\$?" >> $OUT/cells.log
INNER
s=$(date +%s)
vng --run "$K" --user root --cpus 4 --memory 6G --rwdir "$OUT" --exec "sh $OUT/inner.sh" > "$OUT/vng-console.log" 2>&1
echo "vng_exit=$? wall=$(( $(date +%s)-s ))s kernel=$(cat "$OUT/uname.txt" 2>/dev/null) $(grep -E 'VERDICT|cells_exit' "$OUT/cells.log" 2>/dev/null | tr '\n' ' ')"
