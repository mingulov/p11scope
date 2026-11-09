#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>

p11scope_product_build() {
    [ "$1" = prepared ] || return 64
    shift
    RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
        "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --offline "$@"
}
