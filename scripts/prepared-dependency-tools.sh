#!/bin/sh

# POSIX tool selection helpers for prepared-dependency callers.

_p11scope_prepared_tools_clear_results() {
    unset P11SCOPE_PREPARED_PYTHON \
        P11SCOPE_PREPARED_RUSTUP \
        P11SCOPE_PREPARED_STABLE_CARGO \
        P11SCOPE_PREPARED_STABLE_RUSTC \
        P11SCOPE_PREPARED_BPF_CARGO \
        P11SCOPE_PREPARED_BPF_RUSTC
}

_p11scope_prepared_tools_clear_scratch() {
    unset _p11scope_prepared_tools_python \
        _p11scope_prepared_tools_rustup \
        _p11scope_prepared_tools_stable_cargo \
        _p11scope_prepared_tools_stable_rustc \
        _p11scope_prepared_tools_bpf_cargo \
        _p11scope_prepared_tools_bpf_rustc \
        _p11scope_prepared_tools_candidate
}

_p11scope_prepared_tools_canonical_executable() {
    unset _p11scope_prepared_tools_candidate
    _p11scope_prepared_tools_candidate=$(
        realpath -e -- "$1" 2>/dev/null
    ) || return 1
    if [ ! -f "$_p11scope_prepared_tools_candidate" ] || \
        [ ! -x "$_p11scope_prepared_tools_candidate" ]; then
        unset _p11scope_prepared_tools_candidate
        return 1
    fi
    printf '%s\n' "$_p11scope_prepared_tools_candidate"
    unset _p11scope_prepared_tools_candidate
}

_p11scope_prepared_tools_rustup_which() {
    RUSTUP_AUTO_INSTALL=0 "$_p11scope_prepared_tools_rustup" \
        which --toolchain "$1" "$2"
}

_p11scope_prepared_tools_refuse() {
    _p11scope_prepared_tools_clear_results
    _p11scope_prepared_tools_clear_scratch
    printf 'p11scope_prepared_tools_select: %s\n' "$1" >&2
    return "$2"
}

p11scope_prepared_tools_select() {
    _p11scope_prepared_tools_clear_results
    _p11scope_prepared_tools_clear_scratch

    case $- in
        *a*)
            _p11scope_prepared_tools_refuse \
                'allexport shell option is unsupported' 64
            return $?
            ;;
    esac

    if [ "$#" -ne 2 ]; then
        _p11scope_prepared_tools_refuse \
            'expected PYTHON_PATH RUSTUP_PATH' 64
        return $?
    fi

    _p11scope_prepared_tools_python=$(
        _p11scope_prepared_tools_canonical_executable "$1"
    ) || {
        _p11scope_prepared_tools_refuse 'invalid python executable' 65
        return $?
    }

    _p11scope_prepared_tools_rustup=$(
        _p11scope_prepared_tools_canonical_executable "$2"
    ) || {
        _p11scope_prepared_tools_refuse 'invalid rustup executable' 65
        return $?
    }

    _p11scope_prepared_tools_stable_cargo=$(
        _p11scope_prepared_tools_rustup_which 1.88 cargo
    ) || {
        _p11scope_prepared_tools_refuse \
            'rustup failed to select stable cargo' 66
        return $?
    }
    _p11scope_prepared_tools_stable_cargo=$(
        _p11scope_prepared_tools_canonical_executable \
            "$_p11scope_prepared_tools_stable_cargo"
    ) || {
        _p11scope_prepared_tools_refuse 'invalid stable cargo executable' 65
        return $?
    }
    _p11scope_prepared_tools_stable_rustc=$(
        _p11scope_prepared_tools_rustup_which 1.88 rustc
    ) || {
        _p11scope_prepared_tools_refuse \
            'rustup failed to select stable rustc' 66
        return $?
    }
    _p11scope_prepared_tools_stable_rustc=$(
        _p11scope_prepared_tools_canonical_executable \
            "$_p11scope_prepared_tools_stable_rustc"
    ) || {
        _p11scope_prepared_tools_refuse 'invalid stable rustc executable' 65
        return $?
    }
    _p11scope_prepared_tools_bpf_cargo=$(
        _p11scope_prepared_tools_rustup_which nightly-2026-05-20 cargo
    ) || {
        _p11scope_prepared_tools_refuse \
            'rustup failed to select BPF cargo' 66
        return $?
    }
    _p11scope_prepared_tools_bpf_cargo=$(
        _p11scope_prepared_tools_canonical_executable \
            "$_p11scope_prepared_tools_bpf_cargo"
    ) || {
        _p11scope_prepared_tools_refuse 'invalid BPF cargo executable' 65
        return $?
    }
    _p11scope_prepared_tools_bpf_rustc=$(
        _p11scope_prepared_tools_rustup_which nightly-2026-05-20 rustc
    ) || {
        _p11scope_prepared_tools_refuse \
            'rustup failed to select BPF rustc' 66
        return $?
    }
    _p11scope_prepared_tools_bpf_rustc=$(
        _p11scope_prepared_tools_canonical_executable \
            "$_p11scope_prepared_tools_bpf_rustc"
    ) || {
        _p11scope_prepared_tools_refuse 'invalid BPF rustc executable' 65
        return $?
    }
    P11SCOPE_PREPARED_PYTHON=$_p11scope_prepared_tools_python
    P11SCOPE_PREPARED_RUSTUP=$_p11scope_prepared_tools_rustup
    P11SCOPE_PREPARED_STABLE_CARGO=$_p11scope_prepared_tools_stable_cargo
    P11SCOPE_PREPARED_STABLE_RUSTC=$_p11scope_prepared_tools_stable_rustc
    P11SCOPE_PREPARED_BPF_CARGO=$_p11scope_prepared_tools_bpf_cargo
    P11SCOPE_PREPARED_BPF_RUSTC=$_p11scope_prepared_tools_bpf_rustc
    _p11scope_prepared_tools_clear_scratch
}
