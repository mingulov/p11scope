#!/usr/bin/env bash

lane_config() {
    case "$1" in
        jammy)
            printf '%s\n' '/tmp/p11scope-slice1b2-vms/jammy/overlay.qcow2|/tmp/p11scope-slice1b2-vms/jammy/serial.log|2222|SHA256:GD2UX29+dul1JSEIm9k1XjotD9Exr1j9vrTgG92wQEY'
            ;;
        noble)
            printf '%s\n' '/tmp/p11scope-slice1b2-vms/noble/overlay.qcow2|/tmp/p11scope-slice1b2-vms/noble/serial.log|2223|SHA256:lJncGXZAZRDW+QEdhkWpCyhco+DDPxnYB8J6IEha1aQ'
            ;;
        *)
            return 64
            ;;
    esac
}

ssh_argv() {
    local known_hosts=$1 port=$2
    printf '%s\0' \
        ssh -vv \
        -i /tmp/p11scope-slice1b2-vms/id_ed25519 \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$known_hosts" \
        -o GlobalKnownHostsFile=/dev/null \
        -o HostKeyAlgorithms=ssh-ed25519 \
        -p "$port"
}

scp_argv() {
    local known_hosts=$1 port=$2
    printf '%s\0' \
        scp -vv \
        -i /tmp/p11scope-slice1b2-vms/id_ed25519 \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$known_hosts" \
        -o GlobalKnownHostsFile=/dev/null \
        -o HostKeyAlgorithms=ssh-ed25519 \
        -P "$port"
}

reject_inherited_overrides() {
    local name
    local exact=(
        RUSTUP_HOME CARGO_HOME RUSTUP_TOOLCHAIN RUSTUP_DIST_SERVER RUSTUP_UPDATE_ROOT
        CARGO_TARGET_DIR CARGO_BUILD_TARGET RUSTC RUSTDOC RUSTC_WRAPPER
        RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CC CXX HOST_CC
        TARGET_CC AR LD CFLAGS HOST_CFLAGS TARGET_CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
    )
    for name in "${exact[@]}"; do
        if [[ -v $name ]]; then
            printf 'refusing inherited tool override\n' >&2
            return 64
        fi
    done
    while IFS='=' read -r name _; do
        case "$name" in
            CARGO_SOURCE_*|CARGO_REGISTRIES_*|CARGO_HTTP_*|CARGO_NET_*|CARGO_TARGET_*|CC_*|CXX_*|AR_*|CFLAGS_*)
                printf 'refusing inherited tool override prefix\n' >&2
                return 64
                ;;
        esac
    done < <(env)
}

provision_preflight() {
    local rustup_home=$1 cargo_home=$2 tool_home
    umask 077
    reject_inherited_overrides || return
    export RUSTUP_HOME=$rustup_home
    export CARGO_HOME=$cargo_home
    [[ ! -e $RUSTUP_HOME && ! -L $RUSTUP_HOME && ! -e $CARGO_HOME && ! -L $CARGO_HOME ]] || return 64
    mkdir -m 0700 "$RUSTUP_HOME" || return
    mkdir -m 0700 "$CARGO_HOME" || return
    for tool_home in "$RUSTUP_HOME" "$CARGO_HOME"; do
        [[ $(stat -c '%u:%a' "$tool_home") == "$(id -u):700" ]] || return 64
        [[ -z $(find "$tool_home" -mindepth 1 -maxdepth 1 -print -quit) ]] || return 64
    done
}

require_free_bytes() {
    local label=$1 path=$2 available
    available=$(df --output=avail -B1 "$path" | tail -n 1)
    [[ $available =~ ^[0-9]+$ ]] || return 64
    (( available >= 2147483648 )) || return 64
    printf '%s=%s\n' "$label" "$available"
}

fixed_inventory() {
    case "$1" in
        a)
            printf '%s\n' environment.txt manifest-digests.txt verifier.log \
                verifier-results.jsonl gate-a-cases.jsonl runner-status.txt
            ;;
        b)
            printf '%s\n' environment.txt manifest-digests.txt verifier.log \
                verifier-results.jsonl signal-timing.jsonl runner-status.txt
            ;;
        *) return 64 ;;
    esac
}

remote_export_script() {
    cat <<'REMOTE_EXPORT'
set -eu
directory=$1
varying=$2
test "$(stat -c '%u:%a' -- "$directory")" = 0:700
set -- environment.txt manifest-digests.txt verifier.log verifier-results.jsonl "$varying" runner-status.txt
test "$(find "$directory" -mindepth 1 -maxdepth 1 -printf . | wc -c)" -eq 6
total=0
for name do
    path=$directory/$name
    test -f "$path" && test ! -L "$path"
    test "$(stat -c '%u:%a' -- "$path")" = 0:600
    size=$(stat -c '%s' -- "$path")
    case "$name" in
        verifier.log) test "$size" -le 8388608 ;;
        *.jsonl) test "$size" -le 4194304 ;;
        *) test "$size" -le 65536 ;;
    esac
    total=$((total + size))
done
test "$total" -le 16777216
exec tar --format=posix --no-recursion -C "$directory" -cf - "$@"
REMOTE_EXPORT
}

export_evidence() {
    local gate=$1 known_hosts=$2 port=$3 remote_dir=$4 new_host_dir=$5 varying remote_command
    local -a ssh files
    [[ $remote_dir =~ ^/var/tmp/p11scope-slice1b2/[A-Za-z0-9._/-]+$ && $remote_dir != *..* ]] || return 64
    [[ ! -e $new_host_dir && ! -L $new_host_dir ]] || return 64
    umask 077
    mkdir -m 0700 "$new_host_dir"
    mapfile -d '' -t ssh < <(ssh_argv "$known_hosts" "$port")
    mapfile -t files < <(fixed_inventory "$gate")
    varying=${files[4]}
    remote_command="sudo -n sh -s -- $remote_dir $varying"
    remote_export_script \
        | timeout 120s "${ssh[@]}" root@127.0.0.1 "$remote_command" \
        | tar --no-same-owner --no-same-permissions -C "$new_host_dir" -xf -
}

build_fixture() {
    local output=$1 here target disassembly
    umask 077
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    [[ ! -e $output && ! -L $output ]] || return 64
    gcc -std=c11 -O2 -Wall -Wextra -Werror -pthread -fno-lto -Wl,--export-dynamic \
        -o "$output" "$here/fixture.c"
    disassembly=$(objdump -dr "$output")
    for target in spike_get_function_list spike_get_interface_list spike_stop_hook spike_late_target; do
        nm -D "$output" | awk -v target="$target" '$3 == target { found=1 } END { exit !found }'
        grep -E "call(q)?[[:space:]].*<$target(@plt)?>" <<<"$disassembly" >/dev/null
    done
    "$output" --self-check
}

run_main() {
    case "${1-}" in
        build-fixture)
            [[ $# == 2 ]] || return 64
            build_fixture "$2"
            ;;
        provision-jammy)
            printf 'provision-jammy unavailable until source and tool provenance are verified\n' >&2
            return 64
            ;;
        vm-start)
            printf 'vm-start unavailable until complete lifecycle is implemented\n' >&2
            return 64
            ;;
        *)
            printf 'usage: run.sh {build-fixture OUT|provision-jammy|vm-start LANE NEW_RUN_DIR}\n' >&2
            return 64
            ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    run_main "$@"
fi
