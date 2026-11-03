#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# ci/real-providers.sh P11SCOPE OUTDIR: WP-1 entry point for WP-3 cells.
#
# Wires scripts/qualify-real-providers.sh into the privileged-tests job
# template: same arguments, same OUTDIR/results.jsonl rows, same exit
# codes (0 qualified-or-pinned, 1 failed, 2 harness error, 77 skipped).
# Needs the apt prerequisites listed at the top of the qualifier plus
# root, BTF and KVM (all present on ubuntu-26.04 runners).
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
exec "$HERE/../qualify-real-providers.sh" "$@"
