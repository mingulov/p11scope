#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Shared vng guest-release match for the BPF load drivers.
#
# Sourced by scripts/check-bpf-load-kernels.sh,
# scripts/check-bpf-load-journal.sh, scripts/check-bpf-load-gate1.sh and
# scripts/ci/witness-cli-vng.sh; the match lives here once, never copied
# per driver.

# Guest release match: the tag without its leading v must equal uname -r
# or prefix it, except release candidates, whose tag (v7.4-rc1) boots the
# dotted triplet (7.4.0-070400rc1-generic): there the triplet prefix plus
# the same rc marker must match, never another rc number.
release_ok() {
    _release_expected=${1#v}
    _release_guest=$2
    case "$_release_guest" in
        "$_release_expected"|"$_release_expected"-*)
            return 0
            ;;
    esac
    case "$_release_expected" in
        *-rc[0-9]*)
            _release_base=${_release_expected%-rc*}
            _release_tag=${_release_expected##*-rc}
            case "$_release_guest" in
                "$_release_base.0-"*rc"$_release_tag")
                    return 0
                    ;;
                "$_release_base.0-"*rc"$_release_tag"[!0-9]*)
                    return 0
                    ;;
            esac
            ;;
    esac
    return 1
}
