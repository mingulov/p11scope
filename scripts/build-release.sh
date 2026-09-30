#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# v0.1.0 release build.
#
# Produces the two artifact shapes the design calls for:
#   - p11scope            fully static musl build (the observer never
#                          dlopens the target provider, so static is safe
#                          and gives a single dependency-free binary)
#   - p11scope-discover   dynamic glibc AND dynamic musl builds (a static
#                          helper cannot dlopen a provider .so sanely, so
#                          discover is intentionally never static)
#
# The dynamic host attach gate and container discover builds stay isolated
# from the dedicated safe-only target directory used for the official observer.
#   - scripts/verify-attach-e2e.sh        proves dynamic attach+capture
#     correctness end to end against spike/expected.txt.
#   - scripts/verify-discover-containers.sh  builds p11scope-discover for
#     glibc (rust:1-bookworm -> run in ubuntu:24.04) and dynamic musl
#     (rust:1-alpine), and smoke-runs each against SoftHSM2 inside its
#     own container.
#
# NOTE: musl static-PIE binaries report as "static-pie linked" under
# `file`, not "statically linked" -- both mean static (no dynamic
# interpreter); `ldd` printing "statically linked"/"not a dynamic
# executable" is the second, independent confirmation.
set -eu
cd "$(dirname "$0")/.."

receipt_receipt_self_test() {
    [ "$#" -eq 0 ] || exit 2
    REPORT=${P11SCOPE_RECEIPT_SELF_TEST_REPORT-}
    if [ -z "$REPORT" ]; then RECEIPT_SELF_TMP=$(mktemp -d); trap 'rm -rf "$RECEIPT_SELF_TMP"' EXIT INT TERM; REPORT=$RECEIPT_SELF_TMP/report.tsv; fi
    umask 077
    python3 -I scripts/lane-build-release-oracle-1.py "$REPORT"
    echo "build-release Task 4 receipt self-test: OK"
}
if [ "${1-}" = --self-test ]; then
    shift
    receipt_receipt_self_test "$@"
    exit 0
fi

MODULE=/usr/lib/softhsm/libsofthsm2.so
WPID=
TARGET_STARTTIME=
LPID=
SPID=
. scripts/lib.sh
receipt_prepare_root() {
    t4_candidate=$1
    case $t4_candidate in /*) ;; *) return 1 ;; esac
    t4_tab=$(printf '\t'); t4_nl=$(printf '\nx'); t4_nl=${t4_nl%x}
    case $t4_candidate in *'/../'*|*/..|*"$t4_tab"*|*"$t4_nl"*) return 1 ;; esac
    t4_parent=${t4_candidate%/*}; t4_leaf=${t4_candidate##*/}
    [ -n "$t4_parent" ] && [ -n "$t4_leaf" ] && [ -d "$t4_parent" ] || return 1
    t4_ancestor=$t4_parent
    while [ "$t4_ancestor" != / ]; do
        [ ! -L "$t4_ancestor" ] || return 1
        t4_ancestor=${t4_ancestor%/*}; [ -n "$t4_ancestor" ] || t4_ancestor=/
    done
    t4_parent=$(cd "$t4_parent" && pwd -P) || return 1
    [ "$t4_candidate" = "$t4_parent/$t4_leaf" ] || return 1
    case $t4_candidate in "$(pwd -P)"|"$(pwd -P)"/*) return 1 ;; esac
    [ "$(stat -Lc %u:%a "$t4_parent")" = "$(id -u):700" ] || return 1
    [ ! -e "$t4_candidate" ] && [ ! -L "$t4_candidate" ] || return 1
    umask 077; mkdir -m 700 "$t4_candidate" || return 1
    RECEIPT_ROOT=$t4_candidate; RECEIPT_CAMPAIGN=$t4_parent
    RECEIPT_ROOT_ID=$(stat -Lc %d:%i "$RECEIPT_ROOT") || return 1
}

receipt_digest() { "$T4_TOOL_sha256sum" "$1" | awk '{print $1}'; }
receipt_snapshot() {
    case $1 in initial|final) ;; *) return 1 ;; esac
    t4_snapshot=$RECEIPT_ROOT/artifacts/source.$1
    git ls-files -z > "$t4_snapshot.unsorted0" || return 1
    sort -z < "$t4_snapshot.unsorted0" > "$t4_snapshot.sorted0" || return 1
    xargs -0 -r "$T4_TOOL_sha256sum" < "$t4_snapshot.sorted0" > "$t4_snapshot.tracked.sha256" || return 1
    "$T4_TOOL_python3" -I scripts/merge-checksum-ledgers.py \
        "$t4_snapshot.tracked.sha256" "$RECEIPT_PREPARED_PREFIX.$1.ledger.sha256"
}
receipt_fact() { printf '%s\t%s\n' "$1" "$2" >> "$RECEIPT_FACTS"; }

receipt_verify_artifacts() {
    [ -n "${RECEIPT_ARTIFACTS_SHA256-}" ] \
        || { echo "release artifact ledger was not recorded" >&2; return 1; }
    "$T4_TOOL_python3" -I scripts/release-artifacts.py verify \
        --dist "$RECEIPT_ROOT/work/dist" \
        --ledger "$RECEIPT_ROOT/artifacts/release-artifacts.sha256" \
        --sha256 "$RECEIPT_ARTIFACTS_SHA256" >/dev/null
}

# Hash one complete tree as a typed, sorted transcript. NUL-delimited
# enumeration keeps hostile names unambiguous; names and symlink targets still
# refuse tabs/newlines before they can enter the transcript or receipt.
receipt_tree_digest() {
    t4_tree=$1
    [ -d "$t4_tree" ] && [ ! -L "$t4_tree" ] || return 1
    t4_list=$("$T4_TOOL_mktemp") || return 1
    t4_sorted=$("$T4_TOOL_mktemp") || { rm -f "$t4_list"; return 1; }
    t4_files=$("$T4_TOOL_mktemp") || {
        rm -f "$t4_list" "$t4_sorted"
        return 1
    }
    t4_sorted_files=$("$T4_TOOL_mktemp") || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files"
        return 1
    }
    t4_hashes=$("$T4_TOOL_mktemp") || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files"
        return 1
    }
    t4_transcript=$("$T4_TOOL_mktemp") || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes"
        return 1
    }
    "$T4_TOOL_find" "$t4_tree" -mindepth 1 -print0 > "$t4_list" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes" "$t4_transcript"
        return 1
    }
    LC_ALL=C "$T4_TOOL_sort" -z "$t4_list" > "$t4_sorted" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes" "$t4_transcript"
        return 1
    }
    "$T4_TOOL_find" "$t4_tree" -mindepth 1 -type f -print0 > "$t4_files" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes" "$t4_transcript"
        return 1
    }
    LC_ALL=C "$T4_TOOL_sort" -z "$t4_files" > "$t4_sorted_files" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes" "$t4_transcript"
        return 1
    }
    "$T4_TOOL_xargs" -r -0 "$T4_TOOL_sha256sum" -z < "$t4_sorted_files" > "$t4_hashes" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes" "$t4_transcript"
        return 1
    }
    "$T4_TOOL_python3" -I scripts/lane-build-release-oracle-2.py "$t4_tree" "$t4_sorted" "$t4_hashes" > "$t4_transcript" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes" "$t4_transcript"
        return 1
    }
    t4_hash=$(
        {
            printf 'tree-sha256-v1\0'
            "$T4_TOOL_cat" "$t4_transcript"
        } | "$T4_TOOL_sha256sum" | awk '{print $1}'
    ) || {
        rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes" "$t4_transcript"
        return 1
    }
    rm -f "$t4_list" "$t4_sorted" "$t4_files" "$t4_sorted_files" "$t4_hashes" "$t4_transcript" || return 1
    [ -n "$t4_hash" ] || return 1
    printf 'tree-sha256-v1:%s\n' "$t4_hash"
}

# Cargo and rustc are rustup proxies in the effective cargo-home bin. Bind the
# entire immediate directory, while rejecting an inventory-name shadow and
# requiring both proxies to resolve to the sealed rustup executable.
receipt_cargo_home_bin_ledger() {
    t4_cargo_bin=${CARGO_HOME:-$HOME/.cargo}/bin
    [ -d "$t4_cargo_bin" ] && [ ! -L "$t4_cargo_bin" ] || return 1
    t4_list=$("$T4_TOOL_mktemp") || return 1
    t4_sorted=$("$T4_TOOL_mktemp") || { rm -f "$t4_list"; return 1; }
    t4_rows=$("$T4_TOOL_mktemp") || {
        rm -f "$t4_list" "$t4_sorted"
        return 1
    }
    "$T4_TOOL_find" "$t4_cargo_bin" -mindepth 1 -maxdepth 1 -print0 > "$t4_list" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_rows"
        return 1
    }
    LC_ALL=C "$T4_TOOL_sort" -z "$t4_list" > "$t4_sorted" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_rows"
        return 1
    }
    "$T4_TOOL_xargs" -0 "$T4_TOOL_sh" -c '
        root=$1; rustup=$2; inventory=$3; shift 3
        tab=$(printf "\t"); nl=$(printf "\nx"); nl=${nl%x}
        case $rustup in *"$tab"*|*"$nl"*) exit 1 ;; esac
        for path; do
            case $path in *"$tab"*|*"$nl"*) exit 1 ;; esac
            name=${path##*/}
            [ -n "$name" ] || exit 1
            case $name in *"$tab"*|*"$nl"*) exit 1 ;; esac
            case " $inventory " in
                *"$nl$name "*|*" $name$nl"*|*"$nl$name$nl"*)
                    case $name in cargo|rustc|rustup|bpf-linker) ;;
                    *) exit 1 ;;
                    esac
                    ;;
                *" $name "*)
                    case $name in cargo|rustc|rustup|bpf-linker) ;;
                    *) exit 1 ;;
                    esac
                    ;;
            esac
            canonical=$(realpath -e "$path" && printf X) || exit 1
            case $canonical in *"$nl"X) canonical=${canonical%"$nl"X} ;; *) exit 1 ;; esac
            case $canonical in *"$tab"*|*"$nl"*) exit 1 ;; esac
            case $name in cargo|rustc|rustup)
                [ "$canonical" = "$rustup" ] || exit 1 ;;
            esac
            if [ -L "$path" ]; then
                raw=$(find "$path" -maxdepth 0 -printf "%lX") || exit 1
                case $raw in *X) ;; *) exit 1 ;; esac
                raw=${raw%X}
                case $raw in *"$tab"*|*"$nl"*) exit 1 ;; esac
                [ -f "$canonical" ] && [ ! -L "$canonical" ] || exit 1
                digest=$(sha256sum "$canonical" | awk "{print \$1}") || exit 1
                printf "cargo_home_bin_%s\t%s symlink %s %s %s\n" \
                    "$name" "$canonical" "$raw" "$canonical" "$digest" || exit 1
            elif [ -f "$path" ]; then
                digest=$(sha256sum "$path" | awk "{print \$1}") || exit 1
                printf "cargo_home_bin_%s\t%s regular %s\n" \
                    "$name" "$canonical" "$digest" || exit 1
            else
                exit 1
            fi
        done
    ' _ "$t4_cargo_bin" "$T4_TOOL_rustup" "$RECEIPT_TOOL_INVENTORY" \
        < "$t4_sorted" > "$t4_rows" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_rows"
        return 1
    }
    t4_cargo_row=$(printf 'cargo_home_bin_cargo\t')
    "$T4_TOOL_grep" -Fq "$t4_cargo_row" "$t4_rows" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_rows"
        return 1
    }
    t4_rustc_row=$(printf 'cargo_home_bin_rustc\t')
    "$T4_TOOL_grep" -Fq "$t4_rustc_row" "$t4_rows" || {
        rm -f "$t4_list" "$t4_sorted" "$t4_rows"
        return 1
    }
    "$T4_TOOL_cat" "$t4_rows"
    t4_result=$?
    rm -f "$t4_list" "$t4_sorted" "$t4_rows" || return 1
    return "$t4_result"
}

receipt_sysroot_closure() {
    t4_compiler=$1; t4_row=$2
    t4_sysroot=$("$t4_compiler" --print sysroot) || return 1
    case $t4_sysroot in /*) ;; *) return 1 ;; esac
    t4_lib=$t4_sysroot/lib
    [ -d "$t4_lib" ] && [ ! -L "$t4_lib" ] || return 1
    [ -d "$t4_lib/rustlib/x86_64-unknown-linux-musl/lib" ] \
        && [ ! -L "$t4_lib/rustlib/x86_64-unknown-linux-musl/lib" ] || return 1
    t4_driver=$("$T4_TOOL_find" "$t4_lib" -mindepth 1 -maxdepth 1 \
        -name 'librustc_driver*.so' -print -quit) || return 1
    [ -n "$t4_driver" ] || return 1
    t4_tab=$(printf '\t'); t4_nl=$(printf '\nx'); t4_nl=${t4_nl%x}
    case $t4_sysroot:$t4_driver in *"$t4_tab"*|*"$t4_nl"*) return 1 ;; esac
    t4_tree=$(receipt_tree_digest "$t4_lib") || return 1
    printf '%s\t%s %s\n' "$t4_row" "$t4_sysroot" "$t4_tree"
}

# Cargo, rustup, the C toolchain, and the product-build handoff read these
# inputs from the environment. Any non-empty inherited value can re-steer the
# official build away from the recorded source tree without leaving a trace in
# the receipt, so the driver refuses them and supplies only command-local values.
RECEIPT_BUILD_INPUTS='RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET
CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC_WRAPPER CC CFLAGS
P11SCOPE_PRODUCT_BUILD_MODE P11SCOPE_PREPARED_STABLE_CARGO P11SCOPE_PREPARED_STABLE_RUSTC
P11SCOPE_PREPARED_BPF_CARGO P11SCOPE_PREPARED_BPF_RUSTC'

# Every external command the receipt chain reaches, in LC_ALL=C order. The
# chain runs sealed: the unsealed parent resolves each name once through the
# caller's PATH, pins it to an absolute non-symlink executable, and symlinks
# it into a private 0700 directory that becomes the sealed child's entire
# PATH. Symlinks rather than copies or rewritten call sites because the rustup
# proxy dispatches on argv[0], so `cargo +nightly-2026-05-20` from build.rs
# still selects its own toolchain. Commands run under `sudo` resolve through
# sudo's root-owned secure_path and commands inside a container resolve
# through the image, so neither is under the caller's PATH authority and
# neither is a member. An incomplete inventory fails closed as "not found"
# under the seal; it never falls back to the caller's PATH.
RECEIPT_TOOL_INVENTORY='as awk bpf-linker bpftool cargo cat cc chmod clang-18 cmp cp
date dirname docker env file find flock gcc git grep head id jq ld ldd
llvm-objcopy llvm-readelf ln ls mkdir mktemp mv python3 realpath rm rustup sed
setpriv sh sha256sum sleep softhsm2-util sort stat sudo sync tail timeout touch
uname xargs'

# The exact environment the sealed child may observe. `env -i` supplies eight
# of these; dash itself adds PWD and, because line 26 `cd`s, OLDPWD. Nothing
# else survives -- the set was pinned by observation, not by assumption. The
# comparison is exact, so a P11SCOPE_RECEIPT_SEALED forged by the caller refuses
# on the variables it also inherited instead of skipping the seal.
RECEIPT_SEALED_ENVIRONMENT='HOME
LC_ALL
OLDPWD
P11SCOPE_RECEIPT_CALLER_ARGV0
P11SCOPE_RECEIPT_CALLER_PATH
P11SCOPE_RECEIPT_SEALED
P11SCOPE_RECEIPT_SEALED_BIN
PATH
PWD
TMPDIR'

# Temporary I/O must stay on the operator-selected filesystem after env -i.
# The directory is either caller-private or the conventional root-owned sticky
# temporary root. Canonical names exclude symlink ancestors, and ':' cannot
# occur because the seal's child directory becomes PATH.
receipt_validate_tmpdir() {
    t4_temp=$1
    t4_tab=$(printf '\t'); t4_nl=$(printf '\nx'); t4_nl=${t4_nl%x}
    case $t4_temp in /*) ;; *) return 1 ;; esac
    case $t4_temp in *":"*|*"$t4_tab"*|*"$t4_nl"*) return 1 ;; esac
    [ -d "$t4_temp" ] && [ ! -L "$t4_temp" ] \
        && [ -w "$t4_temp" ] && [ -x "$t4_temp" ] || return 1
    [ "$(cd "$t4_temp" && pwd -P)" = "$t4_temp" ] || return 1
    t4_temp_mode=$(stat -Lc %u:%a "$t4_temp") || return 1
    [ "$t4_temp_mode" = "$(id -u):700" ] || [ "$t4_temp_mode" = 0:1777 ]
}

# An untracked `.cargo/config.toml` is invisible to `git ls-files`, to the
# source ledger, and to the cleanliness gate, yet Cargo obeys it. Report every
# one Cargo would consult: each repository ancestor up to /, then the effective
# cargo home. The scan only reports, so both the preflight (refuse) and
# finalization (fail the receipt) can run it -- the effective cargo home stays
# writable for the whole body, and a `[build]` rustc-wrapper or target linker
# planted there mid-run is overridden by none of the command-local values.
# Without HOME the effective cargo home cannot be named, while Cargo can still
# reach one through the passwd database, so that is a refusal too.
receipt_cargo_config_scan() {
    [ -n "${HOME-}" ] || return 1
    t4_dir=$(pwd -P) || return 1
    while :; do
        for t4_cfg in "$t4_dir/.cargo/config" "$t4_dir/.cargo/config.toml"; do
            [ ! -e "$t4_cfg" ] && [ ! -L "$t4_cfg" ] || printf '%s\n' "$t4_cfg"
        done
        [ "$t4_dir" != / ] || break
        t4_dir=${t4_dir%/*}; [ -n "$t4_dir" ] || t4_dir=/
    done
    t4_dir=${CARGO_HOME:-$HOME/.cargo}
    for t4_cfg in "$t4_dir/config" "$t4_dir/config.toml"; do
        [ ! -e "$t4_cfg" ] && [ ! -L "$t4_cfg" ] || printf '%s\n' "$t4_cfg"
    done
}

# Resolve one command to a single absolute non-symlink executable and pin it to
# the named variable, so the recorded receipt and the invocation cannot diverge.
receipt_pin_tool() {
    t4_path=$(realpath -e "$1") || return 1
    case $t4_path in /*) ;; *) return 1 ;; esac
    [ -f "$t4_path" ] && [ ! -L "$t4_path" ] && [ -x "$t4_path" ] || return 1
    eval "$2=\$t4_path"
}

# Resolve one inventory name through the CALLER's PATH and print its pinned
# absolute path. Used only by the unsealed bootstrap.
receipt_seal_pin() {
    t4_found=$(command -v "$1") || return 1
    receipt_pin_tool "$t4_found" t4_seal_pinned || return 1
    printf '%s\n' "$t4_seal_pinned"
}

# The bootstrap, in the unsealed parent. Refuse the inherited build inputs as
# explicit named signals, pin the whole reached-command inventory once, and
# re-exec this same driver under `env -i` with the sealed directory as its
# entire PATH and an exact environment allowlist. Nothing after this point
# resolves a command, or reads a variable, that the caller still controls.
# A HOME, PATH, or argv[0] carrying a tab or newline cannot be recorded as one
# TSV fact row, so it is a refusal rather than a corrupted receipt.
receipt_seal_and_reexec() {
    for t4_var in $RECEIPT_BUILD_INPUTS; do
        eval "t4_value=\${$t4_var-}"
        [ -z "$t4_value" ] || { echo "refusing inherited $t4_var" >&2; exit 77; }
    done
    TMPDIR=${TMPDIR-/var/tmp}
    receipt_validate_tmpdir "$TMPDIR" \
        || { echo "refusing unsafe TMPDIR: $TMPDIR" >&2; exit 77; }
    t4_tab=$(printf '\t'); t4_nl=$(printf '\nx'); t4_nl=${t4_nl%x}
    for t4_value in "${HOME-}" "$PATH" "$0"; do
        case $t4_value in
            *"$t4_nl"*|*"$t4_tab"*)
                echo "refusing an unrecordable HOME, PATH, or argv[0]" >&2; exit 77 ;;
        esac
    done
    t4_driver=$(pwd -P)/scripts/build-release.sh
    for t4_tool in mktemp ln env sh rm; do
        t4_pinned=$(receipt_seal_pin "$t4_tool") \
            || { echo "release tool not usable: $t4_tool" >&2; exit 77; }
        eval "t4_seal_$t4_tool=\$t4_pinned"
    done
    umask 077
    t4_seal_bin=$("$t4_seal_mktemp" -d "$TMPDIR/p11scope-receipt-seal-XXXXXX") \
        || { echo "cannot create the sealed release bin directory" >&2; exit 77; }
    for t4_tool in $RECEIPT_TOOL_INVENTORY; do
        t4_pinned=$(receipt_seal_pin "$t4_tool") \
            && "$t4_seal_ln" -s "$t4_pinned" "$t4_seal_bin/$t4_tool" \
            || { "$t4_seal_rm" -rf "$t4_seal_bin" || :
                 echo "release tool not usable: $t4_tool" >&2; exit 77; }
    done
    exec "$t4_seal_env" -i \
        PATH="$t4_seal_bin" \
        HOME="${HOME-}" \
        LC_ALL=C \
        TMPDIR="$TMPDIR" \
        P11SCOPE_RECEIPT_SEALED=1 \
        P11SCOPE_RECEIPT_SEALED_BIN="$t4_seal_bin" \
        P11SCOPE_RECEIPT_CALLER_PATH="$PATH" \
        P11SCOPE_RECEIPT_CALLER_ARGV0="$0" \
        "$t4_seal_sh" "$t4_driver" "$1"
    "$t4_seal_rm" -rf "$t4_seal_bin" || :
    echo "cannot enter the sealed release environment" >&2
    exit 77
}

# The sealed child's own check, before it takes any authority: the exported
# name set, the PATH, and the sealed directory's ownership, mode and exact
# contents all have to be what the bootstrap built.
receipt_verify_seal() {
    [ "${P11SCOPE_RECEIPT_SEALED-}" = 1 ] || return 1
    t4_bin=${P11SCOPE_RECEIPT_SEALED_BIN-}
    case $t4_bin in /*) ;; *) return 1 ;; esac
    [ "$PATH" = "$t4_bin" ] || return 1
    [ "${LC_ALL-}" = C ] || return 1
    receipt_validate_tmpdir "${TMPDIR-}" || return 1
    [ ! -L "$t4_bin" ] && [ -d "$t4_bin" ] || return 1
    [ "$(env | awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/ { print $1 }' | LC_ALL=C sort)" \
        = "$RECEIPT_SEALED_ENVIRONMENT" ] || return 1
    [ "$(stat -Lc %u:%a "$t4_bin")" = "$(id -u):700" ] || return 1
    [ "$(ls -A1 "$t4_bin")" = "$(printf '%s\n' $RECEIPT_TOOL_INVENTORY)" ] || return 1
    for t4_tool in $RECEIPT_TOOL_INVENTORY; do
        [ -L "$t4_bin/$t4_tool" ] && [ -x "$t4_bin/$t4_tool" ] || return 1
    done
}

# One row per inventory member: the path the sealed directory selects, what
# the CALLER's PATH resolves that same name to now, and the pinned binary's
# digest. Re-running this at finalization catches an in-place replacement and
# a caller PATH that resolves a different binary alike -- both refuse, neither
# warns. `receipt_digest` pipes the pinned sha256sum through `awk`, itself a
# sealed inventory member, so no unrecorded executable can decide a recorded
# digest.
receipt_tool_ledger() {
    for t4_tool in $RECEIPT_TOOL_INVENTORY; do
        t4_pinned=$(realpath -e "$P11SCOPE_RECEIPT_SEALED_BIN/$t4_tool") || return 1
        t4_found=$(PATH="$P11SCOPE_RECEIPT_CALLER_PATH" command -v "$t4_tool") || return 1
        t4_now=$(realpath -e "$t4_found") || return 1
        printf 'tool_%s\t%s %s %s\n' \
            "$t4_tool" "$t4_pinned" "$t4_now" "$(receipt_digest "$t4_pinned")" || return 1
    done
    t4_found=$(RUSTUP_AUTO_INSTALL=0 "$T4_TOOL_rustup" which --toolchain "$(cat .release-rust-version)" cargo) || return 1
    t4_now=$(realpath -e "$t4_found") || return 1
    printf 'toolchain_cargo\t%s %s %s\n' \
        "$T4_TOOLCHAIN_CARGO" "$t4_now" "$(receipt_digest "$T4_TOOLCHAIN_CARGO")" || return 1
    t4_found=$(RUSTUP_AUTO_INSTALL=0 "$T4_TOOL_rustup" which --toolchain "$(cat .release-rust-version)" rustc) || return 1
    t4_now=$(realpath -e "$t4_found") || return 1
    printf 'toolchain_rustc\t%s %s %s\n' \
        "$T4_TOOLCHAIN_RUSTC" "$t4_now" "$(receipt_digest "$T4_TOOLCHAIN_RUSTC")" || return 1
    receipt_sysroot_closure "$T4_TOOLCHAIN_RUSTC" toolchain_sysroot || return 1
    receipt_nightly_closure || return 1
}

# The shipped observer embeds an eBPF object that `build.rs` builds with a
# SECOND toolchain: `cargo +nightly-2026-05-20 ... -Z build-std=core`. Its
# cargo, rustc, sysroot, the `rust-src` tree build-std compiles, and the BPF
# linker are all effective inputs of the release artifact, and none of them is
# the release pair (`.release-rust-version`) the receipt already records.
# `bpf-linker` is bound at the
# effective cargo home because Cargo prepends `$CARGO_HOME/bin` to the PATH of
# every rustc it spawns -- verified on this host by an execve trace, which
# resolved the bpfel-unknown-none link to `~/.cargo/bin/bpf-linker` and NOT to
# the bundled rust-lld (rust-lld serves the host build-script links). The
# Both sysroot trees are digested whole; internal regular-file symlinks bind
# their raw target and canonical content, while external or unsafe links refuse.
receipt_nightly_closure() {
    t4_found=$(RUSTUP_AUTO_INSTALL=0 "$T4_TOOL_rustup" which --toolchain nightly-2026-05-20 cargo) || return 1
    receipt_pin_tool "$t4_found" t4_nightly_cargo || return 1
    printf 'toolchain_nightly_cargo\t%s %s\n' \
        "$t4_nightly_cargo" "$(receipt_digest "$t4_nightly_cargo")" || return 1
    t4_found=$(RUSTUP_AUTO_INSTALL=0 "$T4_TOOL_rustup" which --toolchain nightly-2026-05-20 rustc) || return 1
    receipt_pin_tool "$t4_found" t4_nightly_rustc || return 1
    printf 'toolchain_nightly_rustc\t%s %s\n' \
        "$t4_nightly_rustc" "$(receipt_digest "$t4_nightly_rustc")" || return 1
    t4_sysroot=$("$t4_nightly_rustc" --print sysroot) || return 1
    case $t4_sysroot in /*) ;; *) return 1 ;; esac
    t4_lib=$t4_sysroot/lib
    [ -d "$t4_lib" ] && [ ! -L "$t4_lib" ] || return 1
    t4_driver=$("$T4_TOOL_find" "$t4_lib" -mindepth 1 -maxdepth 1 \
        -name 'librustc_driver*.so' -print -quit) || return 1
    [ -n "$t4_driver" ] || return 1
    t4_sysroot_tree=$(receipt_tree_digest "$t4_lib") || return 1
    printf 'toolchain_nightly_sysroot\t%s %s\n' \
        "$t4_sysroot" "$t4_sysroot_tree" || return 1
    t4_src=$t4_sysroot/lib/rustlib/src/rust
    [ -d "$t4_src" ] && [ ! -L "$t4_src" ] || return 1
    t4_src_digest=$(receipt_tree_digest "$t4_src") || return 1
    printf 'toolchain_nightly_rust_src\t%s %s\n' "$t4_src" "$t4_src_digest" || return 1
    receipt_cargo_home_bin_ledger || return 1
    receipt_pin_tool "${CARGO_HOME:-$HOME/.cargo}/bin/bpf-linker" t4_bpf_linker || return 1
    printf 'toolchain_bpf_linker\t%s %s\n' \
        "$t4_bpf_linker" "$(receipt_digest "$t4_bpf_linker")" || return 1
}

release_body_cleanup() {
    release_cleanup_status=0
    if [ -n "$WPID" ] && [ -n "$TARGET_STARTTIME" ]; then
        signal_verified_process KILL "$WPID" "$TARGET_STARTTIME" 2>/dev/null || release_cleanup_status=1
    fi
    if [ -n "$LPID" ]; then
        kill -CONT "$LPID" 2>/dev/null || release_cleanup_status=1
        kill "$LPID" 2>/dev/null || release_cleanup_status=1
    fi
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || release_cleanup_status=1
    [ -z "$LPID" ] || wait "$LPID" 2>/dev/null || :
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || :
    return "$release_cleanup_status"
}

receipt_finalize() {
    t4_result=$?
    trap - EXIT INT TERM HUP
    set +e
    release_body_cleanup || [ "$t4_result" -ne 0 ] || t4_result=1
    [ "$(stat -Lc %d:%i "$RECEIPT_ROOT" 2>/dev/null)" = "$RECEIPT_ROOT_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$RECEIPT_ROOT/artifacts" 2>/dev/null)" = "$RECEIPT_ARTIFACTS_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$RECEIPT_ROOT/work" 2>/dev/null)" = "$RECEIPT_WORK_ID" ] || t4_result=1
    if [ "$t4_result" -ne 77 ]; then
        [ "$(git rev-parse HEAD 2>/dev/null)" = "$RECEIPT_HEAD" ] || t4_result=1
        [ "$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" = "$RECEIPT_TREE" ] || t4_result=1
        t4_status=$(git status --porcelain=v1 --untracked-files=all 2>/dev/null) || t4_result=1
        [ -z "$t4_status" ] || t4_result=1
        for t4_var in $RECEIPT_BUILD_INPUTS; do
            eval "t4_value=\${$t4_var-}"
            [ -z "$t4_value" ] || t4_result=1
        done
        t4_recheck_allowed=1
        t4_configs=$(receipt_cargo_config_scan 2>/dev/null) || { t4_result=1; t4_recheck_allowed=0; }
        if [ -n "$t4_configs" ] || [ "$t4_recheck_allowed" -eq 0 ]; then
            echo "prepared dependency recheck skipped: Cargo configuration changed or unreadable" >&2
            t4_result=1; t4_recheck_allowed=0
        fi
        if (receipt_tool_ledger) > "$RECEIPT_ROOT/artifacts/tools.final.tsv"; then
            t4_final_tools=$(cat "$RECEIPT_ROOT/artifacts/tools.final.tsv") || { t4_result=1; t4_recheck_allowed=0; }
            [ "$t4_final_tools" = "$RECEIPT_TOOLS" ] || { t4_result=1; t4_recheck_allowed=0; }
        else
            t4_result=1; t4_recheck_allowed=0
        fi
        [ "$(receipt_digest scripts/build-release.sh 2>/dev/null)" = "$RECEIPT_DRIVER_HASH" ] || t4_result=1
        [ "$(receipt_digest scripts/check-capture-evidence.py 2>/dev/null)" = "$RECEIPT_CHECKER_HASH" ] || t4_result=1
        if [ "$RECEIPT_PREPARED_ADMITTED" -eq 1 ] && [ "$t4_recheck_allowed" -eq 1 ]; then
            if "$T4_TOOL_python3" -I scripts/prepared-dependency-evidence.py recheck \
                --prefix "$RECEIPT_PREPARED_PREFIX"; then
                t4_ledger_hash=$(receipt_digest "$RECEIPT_PREPARED_PREFIX.final.ledger.sha256") \
                    && receipt_fact prepared_final_ledger "release.prepared.final.ledger.sha256 $t4_ledger_hash" || t4_result=1
                receipt_snapshot final > "$RECEIPT_ROOT/artifacts/source.end.tsv" || t4_result=1
                cmp -s "$RECEIPT_ROOT/artifacts/source.start.tsv" "$RECEIPT_ROOT/artifacts/source.end.tsv" || t4_result=1
            else
                t4_result=1
            fi
        else
            t4_result=1
        fi
        [ -s "$RECEIPT_ROOT/artifacts/capture.json" ] || t4_result=1
        [ -s "$RECEIPT_ROOT/artifacts/checker.log" ] || t4_result=1
        [ -n "$RECEIPT_CHILD_FACTS_ID" ] && [ "$(stat -Lc %d:%i /proc/$$/fd/8 2>/dev/null)" = "$RECEIPT_CHILD_FACTS_ID" ] || t4_result=1
        [ -n "$RECEIPT_CHILD_FACTS_HASH" ] && [ "$(receipt_digest /proc/$$/fd/8 2>/dev/null)" = "$RECEIPT_CHILD_FACTS_HASH" ] || t4_result=1
        receipt_verify_artifacts || t4_result=1
    fi
    find "$RECEIPT_ROOT" -type d -exec chmod 700 {} + 2>/dev/null || t4_result=1
    find "$RECEIPT_ROOT" -type f -exec chmod 600 {} + 2>/dev/null || t4_result=1
    "$T4_TOOL_python3" -I scripts/lane-build-release-oracle-3.py "$RECEIPT_ROOT" || t4_result=1
    receipt_fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || t4_result=1
    receipt_fact terminal_status "$t4_result" || t4_result=1
    "$T4_TOOL_sync" -f "$RECEIPT_FACTS" "$RECEIPT_ROOT/stdout.log" "$RECEIPT_ROOT/stderr.log" || t4_result=1
    # A readable status=0 is the receipt's completion marker. Synchronize its
    # staged content and finish seal cleanup BEFORE publishing that name, so
    # a late sync/cleanup failure cannot leave a success-looking receipt.
    t4_pending=$RECEIPT_ROOT/work/status.pending
    t4_publish=0
    if [ ! -e "$RECEIPT_ROOT/status" ] && [ ! -L "$RECEIPT_ROOT/status" ] \
        && (umask 077; set -C; printf '%s\n' "$t4_result" > "$t4_pending") \
        && "$T4_TOOL_chmod" 600 "$t4_pending" \
        && "$T4_TOOL_sync" -f "$t4_pending"; then
        t4_publish=1
    else
        t4_result=1
    fi
    if ! "$T4_TOOL_rm" -rf "$P11SCOPE_RECEIPT_SEALED_BIN"; then
        t4_result=1
        t4_publish=0
    fi
    if [ "$t4_publish" -eq 1 ]; then
        # Both paths are in the receipt filesystem; rename is atomic. The
        # absolute pinned command remains usable after removing sealed PATH.
        # There are no fallible operations after successful publication.
        "$T4_TOOL_mv" -T -- "$t4_pending" "$RECEIPT_ROOT/status" || t4_result=1
    fi
    exit "$t4_result"
}

receipt_receipt_run() {
    [ "$#" -eq 1 ] || { echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT" >&2; exit 2; }
    if [ -z "${P11SCOPE_RECEIPT_SEALED-}" ]; then receipt_seal_and_reexec "$1"; fi
    receipt_verify_seal \
        || { echo "refusing an unsealed or forged release environment" >&2; exit 77; }
    receipt_prepare_root "$1" \
        || { rm -rf "$P11SCOPE_RECEIPT_SEALED_BIN" || :
             echo "invalid Task 4 evidence root" >&2; exit 77; }
    RECEIPT_FACTS=$RECEIPT_ROOT/facts.log
    : > "$RECEIPT_FACTS"; : > "$RECEIPT_ROOT/stdout.log"; : > "$RECEIPT_ROOT/stderr.log"
    chmod 600 "$RECEIPT_FACTS" "$RECEIPT_ROOT/stdout.log" "$RECEIPT_ROOT/stderr.log"
    mkdir -m 700 "$RECEIPT_ROOT/artifacts" "$RECEIPT_ROOT/work"
    RECEIPT_ARTIFACTS_ID=$(stat -Lc %d:%i "$RECEIPT_ROOT/artifacts")
    RECEIPT_WORK_ID=$(stat -Lc %d:%i "$RECEIPT_ROOT/work")
    RECEIPT_HEAD= RECEIPT_TREE= RECEIPT_DRIVER_HASH= RECEIPT_CHECKER_HASH=
    RECEIPT_CHILD_FACTS_ID= RECEIPT_CHILD_FACTS_HASH= RECEIPT_TOOLS=
    RECEIPT_PREPARED_ADMITTED=0
    RECEIPT_PREPARED_PREFIX=$RECEIPT_ROOT/artifacts/release.prepared
    T4_TOOLCHAIN_CARGO= T4_TOOLCHAIN_RUSTC=
    for t4_tool in cargo docker file jq python3 rustup setpriv sudo sha256sum mktemp find sort xargs sh cat grep; do
        eval "T4_TOOL_$t4_tool=\$t4_tool"
    done
    # Final status publication happens after sealed PATH has been removed.
    for t4_tool in chmod mv rm sync; do
        receipt_pin_tool "$P11SCOPE_RECEIPT_SEALED_BIN/$t4_tool" "T4_TOOL_$t4_tool" || exit 77
    done
    trap receipt_finalize EXIT INT TERM HUP
    [ ! -L "$RECEIPT_CAMPAIGN/.receipt.lock" ] || exit 77
    exec 9>>"$RECEIPT_CAMPAIGN/.receipt.lock"; chmod 600 "$RECEIPT_CAMPAIGN/.receipt.lock"
    [ "$(stat -Lc %d:%i:%u:%a:%h /proc/$$/fd/9)" = "$(stat -Lc %d:%i:%u:%a:%h "$RECEIPT_CAMPAIGN/.receipt.lock")" ] || exit 77
    [ "$(stat -Lc %u:%a:%h /proc/$$/fd/9)" = "$(id -u):600:1" ] || exit 77
    flock -n 9 || exit 77
    RECEIPT_LOCK_ID=$(stat -Lc %d:%i "$RECEIPT_CAMPAIGN/.receipt.lock")
    RECEIPT_HEAD=$(git rev-parse HEAD) || exit 77; RECEIPT_TREE=$(git rev-parse 'HEAD^{tree}') || exit 77
    RECEIPT_STATUS=$(git status --porcelain=v1 --untracked-files=all) || exit 77
    [ -z "$RECEIPT_STATUS" ] || { echo "worktree must be clean, untracked files included" >&2; exit 77; }
    for t4_tool in cargo docker file jq python3 rustup setpriv sudo sha256sum; do
        t4_found=$(command -v "$t4_tool") || exit 77
        receipt_pin_tool "$t4_found" "T4_TOOL_$t4_tool" || exit 77
    done
    RECEIPT_DRIVER_HASH=$(receipt_digest scripts/build-release.sh); RECEIPT_CHECKER_HASH=$(receipt_digest scripts/check-capture-evidence.py)
    receipt_fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    receipt_fact argv "$P11SCOPE_RECEIPT_CALLER_ARGV0 $1"; receipt_fact cwd "$(pwd -P)"
    receipt_fact sealed_bin "$P11SCOPE_RECEIPT_SEALED_BIN"
    receipt_fact sealed_bin_identity "$(stat -Lc %d:%i "$P11SCOPE_RECEIPT_SEALED_BIN")"
    receipt_fact sealed_environment "$(echo $RECEIPT_SEALED_ENVIRONMENT)"
    for t4_var in $RECEIPT_SEALED_ENVIRONMENT; do
        eval "t4_value=\${$t4_var-}"
        receipt_fact "sealed_env_$t4_var" "$t4_value"
    done
    receipt_fact caller_path "$P11SCOPE_RECEIPT_CALLER_PATH"
    receipt_fact uid_gid "$(id -u):$(id -g)"; receipt_fact kernel "$(uname -srmo)"; receipt_fact head "$RECEIPT_HEAD"; receipt_fact tree "$RECEIPT_TREE"
    receipt_fact root_identity "$RECEIPT_ROOT_ID"; receipt_fact artifacts_identity "$RECEIPT_ARTIFACTS_ID"; receipt_fact work_identity "$RECEIPT_WORK_ID"
    receipt_fact lock_identity "$RECEIPT_LOCK_ID"; receipt_fact lock_holder "$$:$(process_starttime $$)"
    receipt_fact driver_sha256 "$RECEIPT_DRIVER_HASH"; receipt_fact checker_sha256 "$RECEIPT_CHECKER_HASH"
    RECEIPT_CONFIGS=$(receipt_cargo_config_scan) \
        || { echo "cannot evaluate the effective cargo home" >&2; exit 77; }
    [ -z "$RECEIPT_CONFIGS" ] || { echo "untracked cargo config: $RECEIPT_CONFIGS" >&2; exit 77; }
    for t4_var in $RECEIPT_BUILD_INPUTS; do
        eval "t4_value=\${$t4_var-}"
        [ -z "$t4_value" ] || { echo "refusing inherited $t4_var" >&2; exit 77; }
        receipt_fact "inherited_$t4_var" ""
    done
    t4_found=$(RUSTUP_AUTO_INSTALL=0 "$T4_TOOL_rustup" which --toolchain "$(cat .release-rust-version)" cargo) || exit 77
    receipt_pin_tool "$t4_found" T4_TOOLCHAIN_CARGO || exit 77
    t4_found=$(RUSTUP_AUTO_INSTALL=0 "$T4_TOOL_rustup" which --toolchain "$(cat .release-rust-version)" rustc) || exit 77
    receipt_pin_tool "$t4_found" T4_TOOLCHAIN_RUSTC || exit 77
    # Keep the nightly selections made by the complete ledger in this shell.
    receipt_tool_ledger > "$RECEIPT_ROOT/artifacts/tools.initial.tsv" || exit 77
    RECEIPT_TOOLS=$(cat "$RECEIPT_ROOT/artifacts/tools.initial.tsv") || exit 77
    printf '%s\n' "$RECEIPT_TOOLS" >> "$RECEIPT_FACTS"
    "$T4_TOOL_python3" -I scripts/prepared-dependency-evidence.py capture \
        --prefix "$RECEIPT_PREPARED_PREFIX" \
        --stable-cargo "$T4_TOOLCHAIN_CARGO" --stable-rustc "$T4_TOOLCHAIN_RUSTC" \
        --bpf-cargo "$t4_nightly_cargo" --bpf-rustc "$t4_nightly_rustc" || exit 77
    RECEIPT_PREPARED_ADMITTED=1
    t4_ledger_hash=$(receipt_digest "$RECEIPT_PREPARED_PREFIX.initial.ledger.sha256") || exit 77
    receipt_fact prepared_initial_ledger "release.prepared.initial.ledger.sha256 $t4_ledger_hash"
    receipt_snapshot initial > "$RECEIPT_ROOT/artifacts/source.start.tsv" || exit 77
    RECEIPT_SOURCE_HASH=$(receipt_digest "$RECEIPT_ROOT/artifacts/source.start.tsv") || exit 77
    receipt_fact source_input_ledger_sha256 "$RECEIPT_SOURCE_HASH"
    "$T4_TOOL_sudo" -n true >/dev/null 2>&1 || exit 77
    [ -f "$MODULE" ] || exit 77
    WORK=$RECEIPT_ROOT/work
    DIST="$WORK/dist"
    OFFICIAL_TARGET="$WORK/release-official"
    CANARY_WORK="$WORK/canaries"
    ATTACH_WORK=$WORK
    DISCOVER_BASE=$WORK
    DISCOVER_WORK="$DISCOVER_BASE/discover"
    release_body > "$RECEIPT_ROOT/stdout.log" 2> "$RECEIPT_ROOT/stderr.log"
    exec 8< "$RECEIPT_ROOT/artifacts/discover.facts"
    RECEIPT_CHILD_FACTS_ID=$(stat -Lc %d:%i /proc/$$/fd/8) || exit 1
    [ "$RECEIPT_CHILD_FACTS_ID" = "$(awk -F '\t' '$1=="facts_identity"{print $2; exit}' /proc/$$/fd/8)" ] || exit 1
    [ "$(stat -Lc %u:%a:%h /proc/$$/fd/8)" = "$(id -u):600:1" ] || exit 1
    RECEIPT_CHILD_FACTS_HASH=$(receipt_digest /proc/$$/fd/8) || exit 1
    receipt_fact child_facts_identity "$RECEIPT_CHILD_FACTS_ID"
    receipt_fact child_facts_sha256 "$RECEIPT_CHILD_FACTS_HASH"
    # csf_19fb2f: the receipt capture is bound to the literal path the static
    # smoke wrote; find remains only as a guard that the observed-capture
    # population under work/ is exactly the three known files (two attach-e2e
    # lanes plus the static smoke), so a planted decoy refuses instead of
    # being silently ranked. checker.log is the framed checker record from
    # release_body, never the whole-body stdout.
    t4_observed=$(find "$RECEIPT_ROOT/work" -type f -name '*observed*.json' -print | LC_ALL=C sort)
    [ "$t4_observed" = "$(printf '%s\n' \
        "$RECEIPT_ROOT/work/observed-scan.json" \
        "$RECEIPT_ROOT/work/observed-static-smoke.json" \
        "$RECEIPT_ROOT/work/observed.json")" ] \
        || { echo "unexpected observed capture set under work: $t4_observed" >&2; exit 1; }
    cp "$WORK/observed-static-smoke.json" "$RECEIPT_ROOT/artifacts/capture.json"
    cp "$WORK/checker.log" "$RECEIPT_ROOT/artifacts/checker.log"
    receipt_fact checker_argv "$t4_checker_argv"
    receipt_fact checker_status "$t4_checker_status"
    receipt_fact checker_log_sha256 "$(receipt_digest "$RECEIPT_ROOT/artifacts/checker.log")"
}

release_body() {
require_non_root_caller
rm -rf "$DIST"
mkdir -p "$DIST"

echo "=== release privacy gate ==="
P11SCOPE_PRODUCT_BUILD_MODE=prepared \
P11SCOPE_PREPARED_STABLE_CARGO="$T4_TOOLCHAIN_CARGO" \
P11SCOPE_PREPARED_STABLE_RUSTC="$T4_TOOLCHAIN_RUSTC" \
P11SCOPE_PREPARED_BPF_CARGO="$t4_nightly_cargo" \
P11SCOPE_PREPARED_BPF_RUSTC="$t4_nightly_rustc" \
P11SCOPE_RECEIPT_WORK="$CANARY_WORK" sh scripts/verify-canaries.sh

echo "=== p11scope: dynamic-build attach correctness ==="
P11SCOPE_PRODUCT_BUILD_MODE=prepared \
P11SCOPE_PREPARED_STABLE_CARGO="$T4_TOOLCHAIN_CARGO" \
P11SCOPE_PREPARED_STABLE_RUSTC="$T4_TOOLCHAIN_RUSTC" \
P11SCOPE_PREPARED_BPF_CARGO="$t4_nightly_cargo" \
P11SCOPE_PREPARED_BPF_RUSTC="$t4_nightly_rustc" \
P11SCOPE_RECEIPT_WORK="$ATTACH_WORK" sh scripts/verify-attach-e2e.sh

echo "=== p11scope: isolated safe-only official static build ==="
rm -rf "$OFFICIAL_TARGET"
# The rustup shim dispatches on argv[0], so its resolved non-symlink path is
# not invocable as cargo and a `+toolchain` selector cannot survive path
# pinning. Run the
# recorded toolchain binaries directly instead, offline, with RUSTC supplied
# command-locally so cargo never resolves the compiler through PATH.
# The official bytes must not embed the build host's checkout, Cargo home or
# rustup home (panic locations, BTF/DWARF line info of the embedded BPF
# object), so each is remapped to a fixed prefix. The 0x1f-separated encoded
# form keeps paths with spaces intact, and build.rs forwards the same flags
# to the embedded BPF build, whose sources live under the same three roots.
# Inherited CARGO_HOME and RUSTUP_HOME are refused above, so both are the
# defaults under HOME.
RELEASE_FLAG_SEPARATOR=$(printf '\037')
RELEASE_SOURCE_ROOT=$(pwd -P)
CARGO_TARGET_DIR="$OFFICIAL_TARGET" \
CARGO_ENCODED_RUSTFLAGS="-C${RELEASE_FLAG_SEPARATOR}target-feature=+crt-static${RELEASE_FLAG_SEPARATOR}--remap-path-prefix=$RELEASE_SOURCE_ROOT=/p11scope${RELEASE_FLAG_SEPARATOR}--remap-path-prefix=$HOME/.cargo=/cargo${RELEASE_FLAG_SEPARATOR}--remap-path-prefix=$HOME/.rustup=/rustup" \
RUSTC="$T4_TOOLCHAIN_RUSTC" \
P11SCOPE_PREPARED_BPF_CARGO="$t4_nightly_cargo" \
P11SCOPE_PREPARED_BPF_RUSTC="$t4_nightly_rustc" \
    "$T4_TOOLCHAIN_CARGO" build --locked --offline --release --no-default-features \
        --target x86_64-unknown-linux-musl --bin p11scope
P11SCOPE_STATIC=$OFFICIAL_TARGET/x86_64-unknown-linux-musl/release/p11scope

set -- "$OFFICIAL_TARGET"/x86_64-unknown-linux-musl/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "official BPF object is not unique"; exit 1; }
OFFICIAL_BPF=$1
set -- "$CANARY_WORK"/feature-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "diagnostic BPF object is not unique"; exit 1; }
DIAGNOSTIC_BPF=$1
"$T4_TOOL_python3" -I scripts/check-bpf-map-defs.py --policy-inventory "$OFFICIAL_BPF" "$DIAGNOSTIC_BPF"

if "$P11SCOPE_STATIC" profile --unsafe-unvalidated-metadata \
    --manifest /nonexistent/manifest.json --pid 1 \
    > "$OFFICIAL_TARGET/unsafe-cli.log" 2>&1; then
    echo "safe-only official observer accepted --unsafe-unvalidated-metadata"
    exit 1
fi
grep -Fq -- "--unsafe-unvalidated-metadata requires a build with" \
    "$OFFICIAL_TARGET/unsafe-cli.log" || {
        echo "safe-only observer returned the wrong unsafe-feature diagnostic"
        cat "$OFFICIAL_TARGET/unsafe-cli.log"
        exit 1
    }

echo "--- file: p11scope (static musl) ---"
"$T4_TOOL_file" "$P11SCOPE_STATIC"
"$T4_TOOL_file" "$P11SCOPE_STATIC" | grep -qE "statically linked|static-pie linked" \
    || { echo "p11scope is NOT static"; exit 1; }
echo "--- ldd: p11scope (static musl) ---"
ldd "$P11SCOPE_STATIC" || true   # diagnostic only; file(1) above is the enforced static-link check
cp "$P11SCOPE_STATIC" "$DIST/p11scope"

echo "=== p11scope-discover: dynamic glibc + dynamic musl builds ==="
P11SCOPE_RECEIPT_WORK="$DISCOVER_BASE" \
    sh scripts/verify-discover-containers.sh \
    --lane14-facts "$RECEIPT_ROOT/artifacts/discover.facts"
GLIBC_DISCOVER=$DISCOVER_WORK/glibc-build/release/p11scope-discover
MUSL_DISCOVER=$DISCOVER_WORK/musl-build/release/p11scope-discover

echo "--- file: p11scope-discover (glibc) ---"
"$T4_TOOL_file" "$GLIBC_DISCOVER"
echo "--- ldd: p11scope-discover (glibc) ---"
ldd "$GLIBC_DISCOVER"
echo "--- smoke run: p11scope-discover (glibc), on host ---"
"$GLIBC_DISCOVER" --module /usr/lib/softhsm/libsofthsm2.so -o "$DIST/.smoke-manifest-glibc.json"
n=$(grep -c '"name": "C_' "$DIST/.smoke-manifest-glibc.json")
test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
echo "glibc discover host smoke run: $n/68 function records OK"
rm -f "$DIST/.smoke-manifest-glibc.json"
cp "$GLIBC_DISCOVER" "$DIST/p11scope-discover-glibc"
cp "$GLIBC_DISCOVER" "$DIST/p11scope-discover"

echo "--- file: p11scope-discover (musl) ---"
"$T4_TOOL_file" "$MUSL_DISCOVER"
echo "musl-dynamic file/ldd/smoke run already verified inside the alpine" \
     "container by verify-discover-containers.sh above -- this (glibc)" \
     "host has no musl dynamic linker to exec it directly."
cp "$MUSL_DISCOVER" "$DIST/p11scope-discover-musl"

# Bind the exact copied bytes before any packaged helper/static smoke. The
# receipt keeps this ledger private; a public packager verifies its digest and
# the four files before restoring executable modes in its own staging tree.
RECEIPT_ARTIFACTS_SHA256=$("$T4_TOOL_python3" -I scripts/release-artifacts.py record \
    --dist "$DIST" --ledger "$RECEIPT_ROOT/artifacts/release-artifacts.sha256")
receipt_fact release_artifacts_sha256 "$RECEIPT_ARTIFACTS_SHA256"

echo "=== packaged discovery helper smoke ==="
"$DIST/p11scope-discover" --module /usr/lib/softhsm/libsofthsm2.so \
    -o "$DIST/.smoke-manifest-helper.json"
n=$(grep -c '"name": "C_' "$DIST/.smoke-manifest-helper.json")
test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
rm -f "$DIST/.smoke-manifest-helper.json"

echo "=== p11scope: smoke run of the packaged STATIC artifact itself ==="
"$DIST/p11scope" --help >/dev/null
echo "--help OK"

echo "=== official static hostile-target smoke ==="
wait_for_hardened_target() {
    wht_pid=$1
    wht_starttime=$2
    wht_attempt=0
    while [ "$wht_attempt" -lt 160 ]; do
        process_matches_starttime "$wht_pid" "$wht_starttime" || {
            echo "Hardened target $wht_pid exited or changed identity" >&2
            return 1
        }
        if awk '
            $1 == "State:" { stopped_ok = ($2 == "T" || $2 == "t") }
            $1 == "Uid:" {
                uid_ok = ($2 != 0 && $3 != 0 && $4 != 0 && $5 != 0)
            }
            $1 == "CapInh:" || $1 == "CapPrm:" || $1 == "CapEff:" || $1 == "CapAmb:" {
                caps_ok += ($2 == "0000000000000000")
            }
            $1 == "NoNewPrivs:" { nnp_ok = ($2 == 1) }
            END { exit !(stopped_ok && uid_ok && caps_ok == 4 && nnp_ok) }
        ' "/proc/$wht_pid/status" 2>/dev/null; then
            return 0
        fi
        kill -0 "$wht_pid" 2>/dev/null || {
            echo "Hardened target $wht_pid exited before its status was verified" >&2
            return 1
        }
        wht_attempt=$((wht_attempt + 1))
        sleep 0.05
    done
    echo "Hardened target $wht_pid did not stop with non-root UIDs, zero active capabilities, and NoNewPrivs" >&2
    cat "/proc/$wht_pid/status" >&2 || true
    return 1
}

export SOFTHSM2_CONF="$WORK/softhsm2.conf"
"$DIST/p11scope-discover" --module "$MODULE" -o "$WORK/release-manifest.json"

TARGET_UID=$(id -u)
TARGET_GID=$(id -g)
rm -f "$WORK/observed-static-smoke.json" "$WORK/hardened-target.pid"
"$T4_TOOL_sudo" --preserve-env=SOFTHSM2_CONF sh -c 'umask 077; exec 3>"$1"; shift; exec "$@"' \
    sh "$WORK/hardened-target.pid" \
    "$T4_TOOL_setpriv" --no-new-privs --reuid "$TARGET_UID" --regid "$TARGET_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- \
    sh -c '
        starttime=$(awk '\''{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }'\'' \
            "/proc/$$/stat") || exit 1
        case $starttime in ""|*[!0-9]*) exit 1 ;; esac
        printf "%s %s\n" "$$" "$starttime" >&3
        exec 3>&-
        kill -STOP "$$"
        exec "$1" "$2"
    ' sh "$WORK/harness" "$MODULE" &
LPID=$!
target_attempt=0
while ! "$T4_TOOL_sudo" test -s "$WORK/hardened-target.pid" && [ "$target_attempt" -lt 160 ]; do
    kill -0 "$LPID" 2>/dev/null || { echo "Hardened target launcher exited before publishing its pid"; exit 1; }
    target_attempt=$((target_attempt + 1))
    sleep 0.05
done
"$T4_TOOL_sudo" test -s "$WORK/hardened-target.pid" || { echo "Hardened target pid missing"; exit 1; }
set -- $("$T4_TOOL_sudo" cat "$WORK/hardened-target.pid")
[ "$#" -eq 2 ] || { echo "invalid Hardened target identity record"; exit 1; }
WPID=$1
TARGET_STARTTIME=$2
case $WPID:$TARGET_STARTTIME in *[!0-9:]*) echo "invalid Hardened target identity"; exit 1 ;; esac
wait_for_hardened_target "$WPID" "$TARGET_STARTTIME"

"$T4_TOOL_sudo" --preserve-env=SOFTHSM2_CONF "$DIST/p11scope" profile \
    --manifest "$WORK/release-manifest.json" \
    --pid "$WPID" \
    --mode metrics --duration 20 -o "$WORK/observed-static-smoke.json" \
    > "$WORK/profile-static-smoke.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/profile-static-smoke.log" aggregate-only metrics
signal_verified_process CONT "$WPID" "$TARGET_STARTTIME"
# sudo suspends itself when its command stops; resume it too or `wait`
# below never returns (and the exited target stays a zombie under it).
kill -CONT "$LPID" 2>/dev/null || true
if wait "$LPID"; then LPID=; WPID=; TARGET_STARTTIME=; else status=$?; LPID=; WPID=; TARGET_STARTTIME=; echo "static smoke workload failed: $status"; exit "$status"; fi
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "static smoke profiler failed: $status"; cat "$WORK/profile-static-smoke.log" || true; exit "$status"; fi
# hardened-target.pid is opened by the sudo launcher above and stays
# root-owned; the receipt's terminal mode walk requires caller ownership.
reclaim_root_output "$WORK/observed-static-smoke.json" "$WORK/hardened-target.pid"

# Framed checker record (csf_19fb2f): exact argv, the checker's own captured
# stdout/stderr, and a terminal status line. The frame keeps the record
# non-empty even though the checker is silent on success, and it -- not the
# aggregate body stdout -- is what the receipt retains as checker.log.
t4_checker_argv="$T4_TOOL_python3 -I scripts/check-capture-evidence.py clean-metrics-manifest-only $WORK/observed-static-smoke.json spike/expected.txt"
t4_checker_status=0
{
    printf 'argv\t%s\n' "$t4_checker_argv"
    "$T4_TOOL_python3" -I scripts/check-capture-evidence.py clean-metrics-manifest-only \
        "$WORK/observed-static-smoke.json" spike/expected.txt 2>&1 || t4_checker_status=$?
    printf 'status\t%s\n' "$t4_checker_status"
} > "$WORK/checker.log"
[ "$t4_checker_status" -eq 0 ] \
    || { echo "capture evidence checker failed: $t4_checker_status"; exit "$t4_checker_status"; }
echo "static p11scope smoke attach OK: $("$T4_TOOL_jq" -c .evidence "$WORK/observed-static-smoke.json")"

receipt_verify_artifacts

echo "=== dist/ ==="
ls -la "$DIST"

echo "=== build-release: ALL OK ==="
}

receipt_receipt_run "$@"
