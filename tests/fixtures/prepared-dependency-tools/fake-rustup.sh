#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

# The tool pinning layer identifies its executables by behaviour (it runs
# `rustup --version` and requires a `rustup ` banner), so a stub standing in
# for rustup must answer as rustup. Answer before the call log is written:
# the probe is a capability check, not a toolchain selection.
if [ "$1" = "--version" ]; then
    printf '%s\n' "rustup 1.99.0 (p11scope test fixture)"
    exit 0
fi

printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${RUSTUP_AUTO_INSTALL-unset}" "$#" "${1-}" "${2-}" "${3-}" "${4-}" \
    >>"$P11SCOPE_FIXTURE_LOG"

if [ "$#" -ne 4 ]; then
    printf '%s\n' "unexpected fixture argument count: $#" >&2
    exit 72
fi

query=${3-}:${4-}
if [ "${P11SCOPE_FIXTURE_FAIL_QUERY-}" = "$query" ]; then
    printf '%s\n' "fixture rustup failure: $query" >&2
    exit 71
fi

case "$query" in
    1.98.1:cargo) printf '%s\n' "$P11SCOPE_FIXTURE_STABLE_CARGO" ;;
    1.98.1:rustc) printf '%s\n' "$P11SCOPE_FIXTURE_STABLE_RUSTC" ;;
    nightly-2026-05-20:cargo) printf '%s\n' "$P11SCOPE_FIXTURE_BPF_CARGO" ;;
    nightly-2026-05-20:rustc) printf '%s\n' "$P11SCOPE_FIXTURE_BPF_RUSTC" ;;
    *)
        printf '%s\n' "unexpected fixture query: $*" >&2
        exit 73
        ;;
esac
