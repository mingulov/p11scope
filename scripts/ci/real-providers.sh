#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# ci/real-providers.sh P11SCOPE OUTDIR: WP-1 entry point for WP-3 cells.
#
# Wires scripts/qualify-real-providers.sh into the privileged-tests job
# template: same arguments, same OUTDIR/results.jsonl rows, same exit
# codes (0 qualified-or-pinned, 1 failed, 2 harness error, 77 skipped).
# Needs the apt prerequisites listed at the top of the qualifier plus
# root, BTF and KVM (all present on ubuntu-26.04 runners).
#
# W3-2 finding 5: on a disposable CI runner ONLY -- root (this entry is
# invoked via sudo) on a host that declares P11SCOPE_CI_DISPOSABLE=1 --
# this entry first sets up the pkcs11 group, pkcsslotd and an
# initialised soft token (slot holding libpkcs11_sw.so, label
# ci-ock-sw), so the real-opencryptoki cells can qualify there.
# opencryptoki.conf(5) offers no tokdir redirect, so the token state
# lives in the standard system paths on the runner, which is discarded
# with the job; nothing here is "owned OUTDIR state" beyond that. Any
# setup failure only warns: the qualifier's own probe then records the
# opencryptoki cells nonqualifying (77) with its reason, never a pass.
# Local and Fedora runs never set the marker and never run this setup.
# WP-1 invokes the entry as root with the marker set; the first
# qualifying CI run yields the OCK pin material (tool_version keys as
# opensc/<v>+ock/<w>; both OCK pin lists are empty until then, so the
# cells report a harness error, not a qualification, once setup works).
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
[ $# = 2 ] || { echo 'usage: ci/real-providers.sh P11SCOPE OUTDIR' >&2; exit 64; }

ock_sw_slot() {
  awk '/^[ \t]*#/ { next } /^slot [0-9]+/ { n = $2 } /stdll[ \t]*=[ \t]*libpkcs11_sw\.so/ { print n; exit }' \
    /etc/opencryptoki/opencryptoki.conf 2>/dev/null
}

ock_slot_state() {
  # Prints ready|empty|unknown for one slot's `pkcs11-tool -L` block.
  pkcs11-tool --module "$1" -L 2>/dev/null | awk -v target="$2" '
/^Slot [0-9]+ \(0x[0-9a-fA-F]+\):/ { slot = $2; sub(/:$/, "", slot); in_target = (slot == target) }
in_target && /^  \(empty\)$/ { empty = 1 }
in_target && /token label[ ]*: [ ]*[^ ]/ { label = 1 }
END { if (label) print "ready"; else if (empty) print "empty"; else print "unknown" }'
}

ock_ci_setup() {
  getent group pkcs11 >/dev/null || groupadd -r pkcs11 || {
    echo 'ci/real-providers.sh: cannot create pkcs11 group' >&2; return 1; }
  usermod -aG pkcs11 root || {
    echo 'ci/real-providers.sh: cannot add root to pkcs11' >&2; return 1; }
  command -v pkcs11-tool >/dev/null || {
    echo 'ci/real-providers.sh: pkcs11-tool missing' >&2; return 1; }
  local ock=""
  local candidate
  for candidate in /usr/lib/x86_64-linux-gnu/pkcs11/libopencryptoki.so \
      /usr/lib64/pkcs11/libopencryptoki.so; do
    if [ -f "$candidate" ]; then ock=$candidate; break; fi
  done
  [ -n "$ock" ] || {
    echo 'ci/real-providers.sh: libopencryptoki.so missing' >&2; return 1; }
  local sw_slot
  sw_slot=$(ock_sw_slot)
  case $sw_slot in ''|*[!0-9]*) echo 'ci/real-providers.sh: soft-token slot not found' >&2; return 1;; esac
  if ! pgrep -x pkcsslotd >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
      systemctl start pkcsslotd >/dev/null 2>&1 || true
    fi
    if ! pgrep -x pkcsslotd >/dev/null 2>&1; then
      [ -x /usr/sbin/pkcsslotd ] || {
        echo 'ci/real-providers.sh: pkcsslotd missing' >&2; return 1; }
      (/usr/sbin/pkcsslotd >>/var/log/p11scope-ock-slotd.log 2>&1 &)
    fi
  fi
  local i=0
  while [ "$i" -lt 30 ]; do
    pkcsconf -s >/dev/null 2>&1 && break
    i=$((i + 1)); sleep 1
  done
  pkcsconf -s >/dev/null 2>&1 || {
    echo 'ci/real-providers.sh: pkcsslotd never became ready' >&2; return 1; }
  local state
  state=$(ock_slot_state "$ock" "$sw_slot")
  if [ "$state" = ready ]; then
    echo "ci/real-providers.sh: soft token already initialised (slot $sw_slot)" >&2
    return 0
  fi
  [ "$state" = empty ] || {
    echo "ci/real-providers.sh: soft-token slot $sw_slot in unknown state" >&2; return 1; }
  # Disposable-runner test PINs only; the runner is discarded with the job.
  pkcs11-tool --module "$ock" --slot "$sw_slot" --init-token \
    --label ci-ock-sw --so-pin 87654321 >/dev/null 2>&1 || {
    echo 'ci/real-providers.sh: token initialisation failed' >&2; return 1; }
  pkcs11-tool --module "$ock" --slot "$sw_slot" --login --login-type so \
    --so-pin 87654321 --init-pin --pin 12345678 >/dev/null 2>&1 || {
    echo 'ci/real-providers.sh: user-PIN initialisation failed' >&2; return 1; }
  [ "$(ock_slot_state "$ock" "$sw_slot")" = ready ] || {
    echo 'ci/real-providers.sh: soft token not ready after init' >&2; return 1; }
  echo "ci/real-providers.sh: soft token initialised (slot $sw_slot)" >&2
  return 0
}

if [ "${P11SCOPE_CI_DISPOSABLE:-}" = 1 ] && [ "$(id -u)" = 0 ]; then
  ock_ci_setup || echo 'ci/real-providers.sh: opencryptoki CI setup incomplete; cells will report 77' >&2
fi
exec "$HERE/../qualify-real-providers.sh" "$@"
