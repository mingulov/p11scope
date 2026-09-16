#!/bin/sh

p11scope_product_build() {
    [ "$1" = prepared ] || return 64
    shift
    RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
        "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --offline "$@"
}
