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

# A multiplexer shim (mise, asdf) installs one binary under many names and
# dispatches on argv[0], so the shim's canonical path names the multiplexer,
# not python, and exec'ing that path directly makes it run scripts as the
# multiplexer rather than as the interpreter. This file pins exact
# executables; a binary whose behaviour depends on its invocation name is
# precisely what it must not pin. Ask the binary to identify itself -- a path
# can be named anything, so behaviour is the only trustworthy witness -- and
# refuse whatever does not answer as python before anything runs through it.
# CPython prints its --version banner to stdout on 3.4+ but printed it to
# stderr on older releases, so capture both streams for the prefix match.
_p11scope_prepared_tools_python_identifies() {
    case $(
        "$_p11scope_prepared_tools_python" --version 2>&1
    ) in
        'Python '*) return 0 ;;
        *) return 1 ;;
    esac
}

# A multiplexer shim (mise, asdf) installs one binary under many names and
# dispatches on argv[0], so the shim's canonical path names the multiplexer,
# not rustup, and exec'ing that path directly makes it answer as the
# multiplexer. This file pins exact executables; a binary whose behaviour
# depends on its invocation name is precisely what it must not pin. Ask the
# binary to identify itself -- a path can be named anything, so behaviour is
# the only trustworthy witness -- and refuse whatever does not answer as
# rustup before any tool is selected through it.
_p11scope_prepared_tools_rustup_identifies() {
    case $(
        RUSTUP_AUTO_INSTALL=0 "$_p11scope_prepared_tools_rustup" \
            --version 2>/dev/null
    ) in
        'rustup '*) return 0 ;;
        *) return 1 ;;
    esac
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

    _p11scope_prepared_tools_python_identifies || {
        _p11scope_prepared_tools_refuse "python $1 canonicalizes to
$_p11scope_prepared_tools_python, which does not identify as python (its
--version output does not begin with 'Python '). A shim that dispatches on
argv[0] cannot be pinned; pass the real python interpreter (for example
~/.local/share/mise/installs/python/3.14/bin/python3)." 68
        return $?
    }

    _p11scope_prepared_tools_rustup=$(
        _p11scope_prepared_tools_canonical_executable "$2"
    ) || {
        _p11scope_prepared_tools_refuse 'invalid rustup executable' 65
        return $?
    }

    _p11scope_prepared_tools_rustup_identifies || {
        _p11scope_prepared_tools_refuse "rustup $2 canonicalizes to
$_p11scope_prepared_tools_rustup, which does not identify as rustup (its
--version output does not begin with 'rustup '). A shim that dispatches on
argv[0] cannot be pinned; pass the real rustup (for example
~/.cargo/bin/rustup)." 67
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
