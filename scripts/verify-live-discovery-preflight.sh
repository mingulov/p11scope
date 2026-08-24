#!/bin/sh
# Task 9 production live-discovery preflight gate.
#
# This script owns environment setup and cleanup only: it creates the one
# mode-0700 private root, builds the exact product BPF object and runner into
# it, binds the exact frozen command inputs, and drives the privileged
# preflight. Every finite lifecycle, preflight PASS-list and campaign judgement
# belongs to scripts/check-live-discovery-evidence.py.
#
#   verify-live-discovery-preflight.sh --self-test
#       nonprivileged mutation self-test of this script's own validator
#   verify-live-discovery-preflight.sh --frozen-inputs PRIVATE_ROOT
#       print the exact frozen command inputs (no path is ever guessed)
#   verify-live-discovery-preflight.sh --freeze PRIVATE_ROOT [NAME=BASE_IMAGE...]
#       build the exact candidate and freeze the private root (unprivileged)
#   verify-live-discovery-preflight.sh --run PRIVATE_ROOT KERNEL
#       drive the frozen preflight on this kernel and validate its report
#       (privileged; Task 9 Steps 2-3, after the unprivileged review checkpoint)
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh

BPF_SOURCE_RELATIVE=crates/ebpf/src/main.rs

usage() {
    echo "usage: $0 --self-test | --frozen-inputs ROOT | --freeze ROOT [NAME=BASE...] | --run ROOT KERNEL" >&2
    exit 2
}

# The one place the frozen command inputs are defined. Callers eval this
# instead of searching for or guessing any path.
frozen_inputs() {
    fi_root=$1
    printf 'PRIVATE_ROOT=%s\n' "$fi_root"
    printf 'BPF_SOURCE=%s\n' "$(realpath "$BPF_SOURCE_RELATIVE")"
    printf 'BPF_OBJECT=%s/frozen/p11scope-ebpf\n' "$fi_root"
    printf 'BPF_INVENTORY=%s/frozen/bpf-inventory.json\n' "$fi_root"
    printf 'CAMPAIGN_ROOT=%s/campaign\n' "$fi_root"
    printf 'EXECUTION_MANIFEST=%s/execution-manifest.json\n' "$fi_root"
}

# This script's validator: the private root is exactly one caller-owned,
# mode-0700 directory and every frozen command input is a real file or
# directory at its exact frozen path. No symlink may stand in for one.
require_frozen_inputs() {
    rfi_root=$1
    case $rfi_root in
        /*) ;;
        *) echo "private root must be an absolute path: $rfi_root" >&2; return 1 ;;
    esac
    [ ! -L "$rfi_root" ] || { echo "private root is a symlink: $rfi_root" >&2; return 1; }
    [ -d "$rfi_root" ] || { echo "private root is not a directory: $rfi_root" >&2; return 1; }
    rfi_mode=$(stat -Lc %a "$rfi_root") || return 1
    [ "$rfi_mode" = "700" ] || {
        echo "private root mode is $rfi_mode, want 700: $rfi_root" >&2
        return 1
    }
    rfi_owner=$(stat -Lc %u "$rfi_root") || return 1
    [ "$rfi_owner" = "$(id -u)" ] || {
        echo "private root is not owned by the caller: $rfi_root" >&2
        return 1
    }
    test -f "$BPF_SOURCE_RELATIVE" || {
        echo "canonical BPF source is missing: $BPF_SOURCE_RELATIVE" >&2
        return 1
    }
    for rfi_file in frozen/p11scope-ebpf frozen/bpf-inventory.json execution-manifest.json; do
        [ ! -L "$rfi_root/$rfi_file" ] || {
            echo "frozen input is a symlink: $rfi_root/$rfi_file" >&2
            return 1
        }
        [ -f "$rfi_root/$rfi_file" ] || {
            echo "frozen input is missing: $rfi_root/$rfi_file" >&2
            return 1
        }
    done
    for rfi_dir in campaign campaign/rows campaign/preflight; do
        [ ! -L "$rfi_root/$rfi_dir" ] || {
            echo "campaign path is a symlink: $rfi_root/$rfi_dir" >&2
            return 1
        }
        [ -d "$rfi_root/$rfi_dir" ] || {
            echo "campaign path is missing: $rfi_root/$rfi_dir" >&2
            return 1
        }
    done
}

freeze() {
    fz_root=$1
    shift
    require_non_root_caller
    [ ! -e "$fz_root" ] || {
        echo "refusing to reuse an existing private root: $fz_root" >&2
        exit 1
    }
    case $fz_root in
        /*) ;;
        *) echo "private root must be an absolute path: $fz_root" >&2; exit 1 ;;
    esac
    command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
    # Collected before the object glob below reuses the positional parameters.
    fz_bases=""
    for fz_base in "$@"; do
        fz_bases="$fz_bases --kernel-base $fz_base"
    done

    echo "=== build the exact product BPF object and runner ==="
    rm -rf target/live-discovery-freeze
    cargo +1.88 build --locked --release --workspace \
        --target-dir target/live-discovery-freeze
    set -- target/live-discovery-freeze/release/build/p11scope-*/out/p11scope-ebpf
    [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "product BPF object is not unique"; exit 1; }
    FROZEN_BPF=$1

    echo "=== lay out the mode-0700 private root ==="
    umask 077
    python3 - "$fz_root" "$FROZEN_BPF" target/live-discovery-freeze/release/p11scope <<'PY'
import runpy
import sys

checker = runpy.run_path("scripts/check-live-discovery-evidence.py", run_name="preflight_freeze")
checker["prepare_private_root"](checker["repo_root"](), sys.argv[1], sys.argv[2], sys.argv[3])
PY

    echo "=== freeze the production BPF inventory ==="
    python3 scripts/check-live-discovery-object.py \
        --source "$(realpath "$BPF_SOURCE_RELATIVE")" \
        --object "$fz_root/frozen/p11scope-ebpf" \
        --manifest "$fz_root/frozen/bpf-inventory.json"

    echo "=== freeze the execution manifest ==="
    # shellcheck disable=SC2086
    python3 scripts/check-live-discovery-evidence.py --write-manifest \
        --private-root "$fz_root" $fz_bases

    python3 - "$fz_root" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest = root / "execution-manifest.json"
(root / "campaign" / "state.json").write_text(
    json.dumps(
        {
            "schema": "p11scope-live-discovery-campaign/v1",
            "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "state": "frozen",
            "row_count": 0,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
PY

    require_frozen_inputs "$fz_root"
    echo "=== frozen inputs ==="
    frozen_inputs "$fz_root"
    echo "=== freeze: OK ==="
}

run() {
    rn_root=$1
    rn_kernel=$2
    require_non_root_caller
    sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
    require_frozen_inputs "$rn_root"

    # Bind every frozen input before anything privileged runs.
    python3 scripts/check-live-discovery-object.py \
        --source "$(realpath "$BPF_SOURCE_RELATIVE")" \
        --object "$rn_root/frozen/p11scope-ebpf" \
        --manifest "$rn_root/frozen/bpf-inventory.json"
    python3 scripts/check-live-discovery-evidence.py \
        --manifest "$rn_root/execution-manifest.json"

    # The canonical PASS list covers in-kernel behaviour (every production
    # program accepted, all 256 context ids, the cookie boundaries, both
    # short-circuits, function-IP and load-bias arithmetic, r_state +24,
    # lifecycle tombstone/drain, privacy, and the five distinct outcomes), so
    # it needs the frozen preflight harness. It is a frozen input like every
    # other: absent, this lane is UNRUN and no result may be inferred.
    RN_HARNESS=$rn_root/frozen/preflight-harness
    [ -x "$RN_HARNESS" ] || {
        echo "UNRUN: no frozen preflight harness at $RN_HARNESS" >&2
        exit 1
    }
    RN_REPORT=$rn_root/campaign/preflight/$rn_kernel.json
    sudo -n "$RN_HARNESS" \
        --object "$rn_root/frozen/p11scope-ebpf" \
        --manifest "$rn_root/execution-manifest.json" \
        --kernel "$rn_kernel" \
        --output "$RN_REPORT"
    reclaim_root_output "$RN_REPORT"
    python3 scripts/check-live-discovery-evidence.py \
        --preflight "$RN_REPORT" --manifest "$rn_root/execution-manifest.json"
    echo "=== preflight ($rn_kernel): OK ==="
}

# Mutation self-test of this script's own validator. Every claimed field of the
# frozen-input contract gets a mutation that must be refused.
self_test() {
    ST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-preflight-selftest-XXXXXX")
    cleanup() {
        CLEANUP_STATUS=$?
        trap - EXIT INT TERM
        rm -rf "$ST_WORK"
        exit "$CLEANUP_STATUS"
    }
    . scripts/cleanup-traps.sh

    good_root() {
        gr_root=$1
        rm -rf "$gr_root"
        mkdir -p "$gr_root/frozen" "$gr_root/campaign/rows" "$gr_root/campaign/preflight"
        chmod 700 "$gr_root"
        : > "$gr_root/frozen/p11scope-ebpf"
        : > "$gr_root/frozen/bpf-inventory.json"
        : > "$gr_root/execution-manifest.json"
    }

    refuses() {
        rf_label=$1
        shift
        if require_frozen_inputs "$@" 2>/dev/null; then
            echo "mutation accepted: $rf_label" >&2
            exit 1
        fi
    }

    ROOT=$ST_WORK/private
    good_root "$ROOT"
    require_frozen_inputs "$ROOT" || {
        echo "the unmutated frozen private root was rejected" >&2
        exit 1
    }

    refuses "missing private root" "$ST_WORK/absent"
    refuses "relative private root" "private"

    good_root "$ROOT"
    chmod 755 "$ROOT"
    refuses "private root mode 0755" "$ROOT"

    good_root "$ROOT"
    ln -s "$ROOT" "$ST_WORK/link"
    refuses "symlinked private root" "$ST_WORK/link"
    rm -f "$ST_WORK/link"

    for missing in frozen/p11scope-ebpf frozen/bpf-inventory.json execution-manifest.json; do
        good_root "$ROOT"
        rm -f "$ROOT/$missing"
        refuses "missing frozen input $missing" "$ROOT"

        good_root "$ROOT"
        rm -f "$ROOT/$missing"
        # A regular file behind the link, so only the symlink claim can refuse it.
        : > "$ST_WORK/substitute"
        ln -s "$ST_WORK/substitute" "$ROOT/$missing"
        refuses "symlinked frozen input $missing" "$ROOT"
    done

    for missing in campaign/rows campaign/preflight campaign; do
        good_root "$ROOT"
        rm -rf "$ROOT/$missing"
        refuses "missing campaign path $missing" "$ROOT"

        good_root "$ROOT"
        rm -rf "$ROOT/$missing"
        mkdir -p "$ST_WORK/substitute-dir"
        ln -s "$ST_WORK/substitute-dir" "$ROOT/$missing"
        refuses "symlinked campaign path $missing" "$ROOT"
        rm -f "$ROOT/$missing"
    done

    good_root "$ROOT"
    rm -rf "$ROOT/campaign"
    : > "$ROOT/campaign"
    refuses "campaign root replaced by a file" "$ROOT"

    good_root "$ROOT"
    st_expected="PRIVATE_ROOT=$ROOT
BPF_SOURCE=$(realpath "$BPF_SOURCE_RELATIVE")
BPF_OBJECT=$ROOT/frozen/p11scope-ebpf
BPF_INVENTORY=$ROOT/frozen/bpf-inventory.json
CAMPAIGN_ROOT=$ROOT/campaign
EXECUTION_MANIFEST=$ROOT/execution-manifest.json"
    [ "$(frozen_inputs "$ROOT")" = "$st_expected" ] || {
        echo "frozen command inputs are not the exact plan paths:" >&2
        frozen_inputs "$ROOT" >&2
        exit 1
    }

    echo "live discovery preflight input mutations rejected: OK"
    echo "verify-live-discovery-preflight self-test: OK"
    exit 0
}

[ "$#" -ge 1 ] || usage
case $1 in
    --self-test) [ "$#" -eq 1 ] || usage; self_test ;;
    --frozen-inputs) [ "$#" -eq 2 ] || usage; require_frozen_inputs "$2"; frozen_inputs "$2" ;;
    --freeze) [ "$#" -ge 2 ] || usage; shift; freeze "$@" ;;
    --run) [ "$#" -eq 3 ] || usage; run "$2" "$3" ;;
    *) usage ;;
esac
