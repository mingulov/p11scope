#!/bin/sh

library=$1
child_env=$2
shift 2

P11SCOPE_PREPARED_PYTHON=stale-python
P11SCOPE_PREPARED_RUSTUP=stale-rustup
P11SCOPE_PREPARED_STABLE_CARGO=stale-stable-cargo
P11SCOPE_PREPARED_STABLE_RUSTC=stale-stable-rustc
P11SCOPE_PREPARED_BPF_CARGO=stale-bpf-cargo
P11SCOPE_PREPARED_BPF_RUSTC=stale-bpf-rustc
export P11SCOPE_PREPARED_PYTHON P11SCOPE_PREPARED_RUSTUP
export P11SCOPE_PREPARED_STABLE_CARGO P11SCOPE_PREPARED_STABLE_RUSTC
export P11SCOPE_PREPARED_BPF_CARGO P11SCOPE_PREPARED_BPF_RUSTC

. "$library"

before_pwd=$PWD
before_umask=$(umask)
before_options=$-
before_traps=$(trap)
before_auto_install=${RUSTUP_AUTO_INSTALL-unset}
if p11scope_prepared_tools_select "$@"; then
    selection_status=0
else
    selection_status=$?
fi

after_traps=$(trap)
if [ "$before_pwd" = "$PWD" ] && \
    [ "$before_umask" = "$(umask)" ] && \
    [ "$before_options" = "$-" ] && \
    [ "$before_traps" = "$after_traps" ]; then
    printf 'state=same\n'
else
    printf 'state=changed\n'
fi
printf 'auto_install=%s\n' "${RUSTUP_AUTO_INSTALL-unset}"
printf 'before_auto_install=%s\n' "$before_auto_install"
printf 'status=%s\n' "$selection_status"
printf 'python=%s\n' "${P11SCOPE_PREPARED_PYTHON-unset}"
printf 'rustup=%s\n' "${P11SCOPE_PREPARED_RUSTUP-unset}"
printf 'stable_cargo=%s\n' "${P11SCOPE_PREPARED_STABLE_CARGO-unset}"
printf 'stable_rustc=%s\n' "${P11SCOPE_PREPARED_STABLE_RUSTC-unset}"
printf 'bpf_cargo=%s\n' "${P11SCOPE_PREPARED_BPF_CARGO-unset}"
printf 'bpf_rustc=%s\n' "${P11SCOPE_PREPARED_BPF_RUSTC-unset}"
exported=$($child_env)
printf 'exported=%s\n' "$exported"
