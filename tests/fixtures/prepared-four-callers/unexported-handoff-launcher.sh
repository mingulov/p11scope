#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: unexported-handoff-launcher.sh COMMAND RECORDER CARGO RUSTC" >&2
    exit 2
fi

launcher_command=$1
launcher_recorder=$2
launcher_cargo=$3
launcher_rustc=$4

unset P11SCOPE_PREPARED_PYTHON \
    P11SCOPE_PREPARED_RUSTUP \
    P11SCOPE_PREPARED_STABLE_CARGO \
    P11SCOPE_PREPARED_STABLE_RUSTC \
    P11SCOPE_PREPARED_BPF_CARGO \
    P11SCOPE_PREPARED_BPF_RUSTC

exec /bin/sh -c '
P11SCOPE_PREPARED_STABLE_CARGO=$1
P11SCOPE_PREPARED_STABLE_RUSTC=$2
. "$3"
' "$launcher_recorder" "$launcher_cargo" "$launcher_rustc" "$launcher_command"
