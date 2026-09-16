#!/bin/sh

reported=
for name in \
    P11SCOPE_PREPARED_PYTHON \
    P11SCOPE_PREPARED_RUSTUP \
    P11SCOPE_PREPARED_STABLE_CARGO \
    P11SCOPE_PREPARED_STABLE_RUSTC \
    P11SCOPE_PREPARED_BPF_CARGO \
    P11SCOPE_PREPARED_BPF_RUSTC
do
    eval "present=\${$name+x}"
    if [ "$present" = x ]; then
        reported=${reported}${reported:+,}${name}
    fi
done
printf '%s\n' "$reported"
