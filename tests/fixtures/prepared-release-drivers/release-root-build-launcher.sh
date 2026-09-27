#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
[ "$#" -eq 6 ] || exit 2
launcher_command=$1
P11SCOPE_RELEASE_BUILD_RECORD=$2
export P11SCOPE_RELEASE_BUILD_RECORD
unset T4_TOOLCHAIN_CARGO T4_TOOLCHAIN_RUSTC t4_nightly_cargo t4_nightly_rustc \
    RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
T4_TOOLCHAIN_CARGO=$3
T4_TOOLCHAIN_RUSTC=$4
t4_nightly_cargo=$5
t4_nightly_rustc=$6
OFFICIAL_TARGET=${launcher_command%/*}/official\ target\ with\ spaces
# The driver's own values for the path-remapping flags: its checkout, the
# sealed HOME, and the 0x1f encoded-flag separator.
RELEASE_FLAG_SEPARATOR=$(printf '\037')
RELEASE_SOURCE_ROOT=${launcher_command%/*}/source\ root\ with\ spaces
HOME=${launcher_command%/*}/home\ with\ spaces
. "$launcher_command"
