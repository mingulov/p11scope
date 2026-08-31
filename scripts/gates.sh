#!/bin/sh
# One local entry point for the root gates (requires passwordless sudo, softhsm2, gcc, python3).
set -eu
cd "$(dirname "$0")/.."
# Every gate's own validator self-test runs first: unprivileged, seconds, and
# a failing oracle makes every privileged result below meaningless.
echo "=== gate validator self-tests ==="
for gate in scripts/verify-inspect-doctor.sh scripts/verify-attach-e2e.sh \
    scripts/verify-induced-gaps.sh scripts/verify-canaries.sh \
    scripts/verify-discover-containers.sh scripts/verify-live-discovery-preflight.sh \
    scripts/verify-capability-tier.sh; do
    "$gate" --self-test
done
python3 scripts/check-live-discovery-evidence.py --self-test
# The inspect/doctor lane is unprivileged and takes seconds, so it runs first:
# if the CLI cannot even read a target, nothing below is worth waiting for.
for gate in scripts/verify-inspect-doctor.sh scripts/verify-attach-e2e.sh \
    scripts/verify-induced-gaps.sh scripts/verify-canaries.sh; do
    echo "=== $gate ==="
    "$gate"
done
echo "=== scripts/verify-capability-tier.sh ==="
scripts/verify-capability-tier.sh
echo "=== gates: ALL OK ==="
