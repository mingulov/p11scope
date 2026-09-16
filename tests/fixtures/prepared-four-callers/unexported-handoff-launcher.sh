#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: unexported-handoff-launcher.sh COMMAND RECORDER CARGO RUSTC BPF_CARGO BPF_RUSTC" >&2
    exit 2
fi

launcher_command=$1
launcher_recorder=$2
launcher_cargo=$3
launcher_rustc=$4
launcher_bpf_cargo=$5
launcher_bpf_rustc=$6

unset P11SCOPE_PREPARED_PYTHON \
    P11SCOPE_PREPARED_RUSTUP \
    P11SCOPE_PREPARED_STABLE_CARGO \
    P11SCOPE_PREPARED_STABLE_RUSTC \
    P11SCOPE_PREPARED_BPF_CARGO \
    P11SCOPE_PREPARED_BPF_RUSTC

exec /bin/sh -c '
P11SCOPE_PREPARED_STABLE_CARGO=$1
P11SCOPE_PREPARED_STABLE_RUSTC=$2
P11SCOPE_PREPARED_BPF_CARGO=$3
P11SCOPE_PREPARED_BPF_RUSTC=$4
. "$5"
' "$launcher_recorder" "$launcher_cargo" "$launcher_rustc" \
    "$launcher_bpf_cargo" "$launcher_bpf_rustc" "$launcher_command"
