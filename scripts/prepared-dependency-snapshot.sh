#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

p11scope_prepared_snapshot() (
    if [ "$#" -ne 3 ]; then
        echo "usage: p11scope_prepared_snapshot PYTHON_PATH ARTIFACT_STEM PREPARED_LEDGER" >&2
        return 2
    fi

    p11scope_snapshot_python=$1
    p11scope_snapshot_stem=$2
    p11scope_snapshot_prepared=$3
    p11scope_snapshot_paths=$p11scope_snapshot_stem.tracked.paths.z
    p11scope_snapshot_sorted=$p11scope_snapshot_stem.tracked.sorted.z
    p11scope_snapshot_ledger=$p11scope_snapshot_stem.tracked.ledger.sha256

    git ls-files -z >"$p11scope_snapshot_paths" || {
        echo "prepared dependency snapshot: git ls-files failed" >&2
        return 1
    }
    sort -z "$p11scope_snapshot_paths" >"$p11scope_snapshot_sorted" || {
        echo "prepared dependency snapshot: sort failed" >&2
        return 1
    }
    xargs -0 -r sha256sum -- <"$p11scope_snapshot_sorted" >"$p11scope_snapshot_ledger" || {
        echo "prepared dependency snapshot: sha256sum producer failed" >&2
        return 1
    }
    "$p11scope_snapshot_python" -I scripts/merge-checksum-ledgers.py \
        "$p11scope_snapshot_ledger" "$p11scope_snapshot_prepared"
)
