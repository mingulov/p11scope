#!/bin/sh
# One local entry point for the root gates (requires passwordless sudo, softhsm2, gcc, python3).
set -eu
cd "$(dirname "$0")/.."
for gate in scripts/verify-attach-e2e.sh scripts/verify-induced-gaps.sh scripts/verify-canaries.sh; do
    echo "=== $gate ==="
    "$gate"
done
echo "=== gates: ALL OK ==="
