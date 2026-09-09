#!/bin/sh
set -eu
[ "$#" -eq 0 ]
{
    printf 'cargo=%s\n' "${P11SCOPE_PREPARED_STABLE_CARGO-}"
    printf 'rustc=%s\n' "${P11SCOPE_PREPARED_STABLE_RUSTC-}"
    env | sed -n 's/^\(P11SCOPE_PREPARED_[^=]*\)=.*/name=\1/p' | sort
} > "$P11SCOPE_HANDOFF_RECORD"
