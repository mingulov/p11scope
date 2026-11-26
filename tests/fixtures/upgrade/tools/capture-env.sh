#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Shared SoftHSM provider probe for the capture scripts. Sourced, not
# executed:
#   . "$TOOLS_DIR/capture-env.sh"
#   PROV=$(probe_provider) || exit 2
# Honors an explicit $PROV override first (it must exist); otherwise
# probes the Debian/Ubuntu and Fedora provider paths in order. Prints
# the path on stdout. Fails 2 with a named prerequisite when nothing
# matches.
probe_provider() {
    if [ -n "${PROV:-}" ]; then
        if [ -f "$PROV" ]; then
            printf '%s' "$PROV"
            return 0
        fi
        echo "missing prerequisite: PROV=$PROV does not exist" >&2
        return 2
    fi
    if [ $# -eq 0 ]; then
        set -- /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
            /usr/lib64/pkcs11/libsofthsm2.so
    fi
    for cand in "$@"; do
        if [ -f "$cand" ]; then
            printf '%s' "$cand"
            return 0
        fi
    done
    echo "missing prerequisite: no SoftHSM provider ($*); set PROV=<path>" >&2
    return 2
}
