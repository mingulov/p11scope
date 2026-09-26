#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Helpers shared by the container/Kubernetes matrix lanes. Source after
# scripts/lib.sh, from the repository root.

# The observer publishes `-o` only into a directory whose every ancestor is
# trusted: not group/world-writable unless sticky, and owned by root, the
# effective user or the validated SUDO_UID (src/output.rs). A checkout under a
# group-writable home fails that check, so a lane work directory lives in a
# fresh private temporary directory instead. It is always absolute, because
# the lanes hand it to docker bind mounts, systemd-run scopes and SoftHSM.
#   matrix_private_work LABEL   -> sets WORK
matrix_private_work() {
    mpw_base=${P11SCOPE_MATRIX_TMPDIR:-${TMPDIR:-/tmp}}
    case $mpw_base in
        /*) ;;
        *) echo "P11SCOPE_MATRIX_TMPDIR/TMPDIR must be absolute: $mpw_base" >&2; return 2 ;;
    esac
    umask 077
    WORK=$(mktemp -d "$mpw_base/p11scope-$1-XXXXXX") || return 1
    WORK=$(cd "$WORK" && pwd -P) || return 1
    echo "work root: $WORK"
}

# Accept a work directory handed down by a receipt wrapper; it must already
# be absolute (the receipt root is), and it is made private here.
matrix_absolute_work() {
    case $WORK in
        /*) ;;
        *) echo "work directory must be absolute: $WORK" >&2; return 2 ;;
    esac
    umask 077
    mkdir -p "$WORK" || return 1
    chmod 700 "$WORK" || return 1
    echo "work root: $WORK"
}

# Either reuse a prebuilt product (P11SCOPE_BIN, optionally
# P11SCOPE_DISCOVER_BIN; both absolute) or report that the lane must build
# one. Sets P11SCOPE_EXE and P11SCOPE_DISCOVER_EXE when prebuilt; returns 1
# when nothing was given.
#   matrix_prebuilt_product
matrix_prebuilt_product() {
    [ -n "${P11SCOPE_BIN-}" ] || return 1
    for mpp_bin in "$P11SCOPE_BIN" "${P11SCOPE_DISCOVER_BIN:-${P11SCOPE_BIN%/*}/p11scope-discover}"; do
        case $mpp_bin in
            /*) ;;
            *) echo "prebuilt product path must be absolute: $mpp_bin" >&2; exit 2 ;;
        esac
        [ -f "$mpp_bin" ] && [ -x "$mpp_bin" ] || {
            echo "prebuilt product is not an executable file: $mpp_bin" >&2
            exit 2
        }
    done
    P11SCOPE_EXE=$P11SCOPE_BIN
    P11SCOPE_DISCOVER_EXE=${P11SCOPE_DISCOVER_BIN:-${P11SCOPE_BIN%/*}/p11scope-discover}
    return 0
}

# Name the exact bytes a lane ran, so a verdict can be tied to a build.
matrix_report_product() {
    echo "product p11scope: $P11SCOPE_EXE sha256=$(sha256sum "$P11SCOPE_EXE" | awk '{print $1}')"
    if [ -n "${P11SCOPE_DISCOVER_EXE-}" ] && [ -f "$P11SCOPE_DISCOVER_EXE" ]; then
        echo "product p11scope-discover: $P11SCOPE_DISCOVER_EXE sha256=$(sha256sum "$P11SCOPE_DISCOVER_EXE" | awk '{print $1}')"
    fi
    "$P11SCOPE_EXE" --version 2>&1 | head -n 1 || true
}

# The docker and shared-layer lanes stop a capture by signalling the recorded
# root process, which is the `timeout` wrapping the observer. GNU `timeout`
# forwards that SIGINT and exits with the observer's own status, keeping 124
# for a real expiry. uutils coreutils `timeout` (the default `timeout` on
# Ubuntu 25.10 and later) exits 124 whenever it forwards any signal, even
# after the observer exits 0, which turns every clean stop into a failure.
# `--preserve-status` is no substitute: the observer treats SIGTERM as a clean
# stop, so a real expiry would then report success. Require GNU semantics.
#
# Call it with --foreground. Without it GNU `timeout` forwards a received
# signal twice, to the child and then to its own process group (traced:
# kill(child, SIGINT) then kill(0, SIGINT)), and the observer counts the
# duplicate as the operator's second stop signal, which abandons cleanup
# (exit 130, "cleanup incomplete"). --foreground forwards it exactly once.
#   matrix_select_timeout   -> sets MATRIX_TIMEOUT (absolute path)
matrix_select_timeout() {
    for mst_candidate in gnutimeout timeout; do
        mst_path=$(command -v "$mst_candidate" 2>/dev/null) || continue
        case $("$mst_path" --version 2>/dev/null | head -n 1) in
            *"GNU coreutils"*)
                MATRIX_TIMEOUT=$mst_path
                return 0
                ;;
        esac
    done
    echo "GNU coreutils timeout required: uutils timeout exits 124 for a forwarded stop signal" >&2
    return 1
}

# P11SCOPE_MATRIX_BUILD_NETWORK (for example `host`) is passed to the lanes'
# `docker build --network`. Some hosts give the default bridge network no
# usable resolver (the host's resolver is a loopback stub), so apt inside the
# image build cannot resolve its archive. It affects only the image build,
# never the containers or pods under test.
