#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# One local entry point for the root gates (requires passwordless sudo, softhsm2, gcc, python3).
set -eu
cd "$(dirname "$0")/.."

# Every lane below pins its build tools by canonical path, and
# prepared-dependency-tools.sh refuses to pin a binary that does not identify as
# the tool it claims to be. On a host using a version manager, `command -v rustup`
# is a shim whose canonical path IS the multiplexer, so all five lanes that call
# `p11scope_prepared_tools_select "$(command -v python3)" "$(command -v rustup)"`
# refuse before doing any work. Put the real toolchain binary first when one is
# there. This only reorders lookup; it never substitutes a tool a lane did not
# ask for, and a host whose `rustup` is already real is unaffected.
if [ -x "$HOME/.cargo/bin/rustup" ]; then
    case $("$HOME/.cargo/bin/rustup" --version 2>/dev/null) in
        'rustup '*) PATH="$HOME/.cargo/bin:$PATH"; export PATH ;;
    esac
fi
# Every gate's own validator self-test runs first: unprivileged, seconds, and
# a failing oracle makes every privileged result below meaningless.
echo "=== gate validator self-tests ==="
for gate in scripts/verify-inspect-doctor.sh scripts/verify-attach-e2e.sh \
    scripts/verify-induced-gaps.sh scripts/verify-canaries.sh \
    scripts/verify-discover-containers.sh scripts/verify-live-discovery-preflight.sh \
    scripts/verify-provider-matrix.sh \
    scripts/verify-capability-tier.sh; do
    "$gate" --self-test
done
python3 -I scripts/check-live-discovery-evidence.py --self-test
python3 -I tests/python/test_system_scope_measure_launch.py -v
python3 -I tests/python/test_system_scope_sample.py -v
# The inspect/doctor lane is unprivileged and takes seconds, so it runs first:
# if the CLI cannot even read a target, nothing below is worth waiting for.
for gate in scripts/verify-inspect-doctor.sh scripts/verify-attach-e2e.sh \
    scripts/verify-canaries.sh; do
    echo "=== $gate ==="
    "$gate"
done
# The induced-gaps driver takes a Task 4 receipt contract argument, not a bare
# call: an absent evidence root whose parent is private (0700) to the caller.
echo "=== scripts/verify-induced-gaps.sh ==="
scripts/verify-induced-gaps.sh "$(mktemp -d "${TMPDIR:-/tmp}/p11scope-gates-XXXXXX")/induced-gaps"
echo "=== scripts/verify-capability-tier.sh ==="
scripts/verify-capability-tier.sh
echo "=== gates: ALL OK ==="
