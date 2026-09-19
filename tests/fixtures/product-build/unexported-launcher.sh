#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -ge 6 ] || exit 2
launcher_helper=$1
launcher_mode=$2
launcher_stable_cargo=$3
launcher_stable_rustc=$4
launcher_bpf_cargo=$5
launcher_bpf_rustc=$6
shift 6

unset P11SCOPE_PREPARED_STABLE_CARGO \
    P11SCOPE_PREPARED_STABLE_RUSTC \
    P11SCOPE_PREPARED_BPF_CARGO \
    P11SCOPE_PREPARED_BPF_RUSTC

if [ "$launcher_mode" = prepared ]; then
    P11SCOPE_PREPARED_STABLE_CARGO=$launcher_stable_cargo
    P11SCOPE_PREPARED_STABLE_RUSTC=$launcher_stable_rustc
    P11SCOPE_PREPARED_BPF_CARGO=$launcher_bpf_cargo
    P11SCOPE_PREPARED_BPF_RUSTC=$launcher_bpf_rustc
fi

. "$launcher_helper"
p11scope_product_build "$launcher_mode" "$@"
