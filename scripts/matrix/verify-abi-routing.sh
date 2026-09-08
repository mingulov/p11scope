#!/bin/sh
# Native qualification gate for actual p11scope ordinary-entry ABI routing.

ABI_ROUTING_REPO=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd -P)
cd "$ABI_ROUTING_REPO"
. scripts/lib.sh

ABI_RUNTIME_LAUNCH_PID=
ABI_RUNTIME_LAUNCH_STARTTIME=
ABI_RUNTIME_PROCESS_PID=
ABI_RUNTIME_PROCESS_STARTTIME=
ABI_RUNTIME_PIDFILE=
ABI_RUNTIME_STATUS=
ABI_RUNTIME_OWNED=0
ABI_RUNTIME_LAUNCH_OWNED=0
ABI_RUNTIME_PROCESS_OWNED=0
ABI_RUNTIME_PRIVILEGE=root
ABI_RUNTIME_ACQUIRING=0
ABI_DRIVER_FINISHING=0
ABI_TERMINAL_REPORTED=0
ABI_SUCCESS_DETAIL=

abi_result() {
    printf 'RESULT=%s%s\n' "$1" "${2:+ $2}"
    ABI_TERMINAL_REPORTED=1
}

abi_prepare_evidence_root() {
    [ "$#" -eq 1 ] || return 2
    abi_candidate=$1
    case $abi_candidate in /*) ;; *) return 1 ;; esac
    [ ! -e "$abi_candidate" ] && [ ! -L "$abi_candidate" ] || return 1
    python3 -I - "$abi_candidate" <<'PY' || return 1
import grp, os, pwd, stat, sys
p = os.path.abspath(sys.argv[1])
if os.path.normpath(sys.argv[1]) != p:
    raise SystemExit(1)
parent = os.path.dirname(p)
if os.path.realpath(parent) != parent:
    raise SystemExit(1)
cur = parent
first = True
while True:
    st = os.lstat(cur)
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise SystemExit(1)
    if st.st_mode & 0o002:
        raise SystemExit(1)
    if st.st_uid not in (0, os.getuid()):
        raise SystemExit(1)
    if st.st_mode & 0o020:
        if st.st_gid != os.getgid():
            raise SystemExit(1)
        group = grp.getgrgid(st.st_gid)
        foreign_named = any(name != pwd.getpwuid(os.getuid()).pw_name for name in group.gr_mem)
        foreign_primary = any(entry.pw_uid != os.getuid() and entry.pw_gid == st.st_gid for entry in pwd.getpwall())
        if foreign_named or foreign_primary:
            raise SystemExit(1)
    if first and (st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700):
        raise SystemExit(1)
    first = False
    nxt = os.path.dirname(cur)
    if nxt == cur:
        break
    cur = nxt
PY
    mkdir -m 700 -- "$abi_candidate" || return 1
    exec 8<"$abi_candidate" || return 1
    python3 -I - <<'PY' || return 1
import os, stat
st = os.fstat(8)
if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
    raise SystemExit(1)
PY
    ABI_EVIDENCE=$abi_candidate
    ABI_EVIDENCE_PIN=/proc/$$/fd/8
    [ "$(readlink -f -- "$ABI_EVIDENCE_PIN")" = "$abi_candidate" ] || return 1
}

abi_clear_runtime() {
    ABI_RUNTIME_LAUNCH_PID= ABI_RUNTIME_LAUNCH_STARTTIME=
    ABI_RUNTIME_PROCESS_PID= ABI_RUNTIME_PROCESS_STARTTIME=
    ABI_RUNTIME_PIDFILE= ABI_RUNTIME_OWNED=0
    ABI_RUNTIME_LAUNCH_OWNED=0 ABI_RUNTIME_PROCESS_OWNED=0
}

abi_capture_root_runtime() {
    ABI_RUNTIME_LAUNCH_PID=$ROOT_LAUNCH_PID
    ABI_RUNTIME_LAUNCH_STARTTIME=$ROOT_LAUNCH_STARTTIME
    ABI_RUNTIME_PROCESS_PID=$ROOT_PROCESS_PID
    ABI_RUNTIME_PROCESS_STARTTIME=$ROOT_PROCESS_STARTTIME
    ABI_RUNTIME_LAUNCH_OWNED=1 ABI_RUNTIME_PROCESS_OWNED=1 ABI_RUNTIME_OWNED=1
    ABI_RUNTIME_PRIVILEGE=root
}

abi_capture_user_runtime() {
    ABI_RUNTIME_LAUNCH_PID=$USER_PROCESS_LAUNCH_PID
    ABI_RUNTIME_LAUNCH_STARTTIME=$USER_PROCESS_LAUNCH_STARTTIME
    ABI_RUNTIME_PROCESS_PID=$USER_PROCESS_PID
    ABI_RUNTIME_PROCESS_STARTTIME=$USER_PROCESS_STARTTIME
    ABI_RUNTIME_LAUNCH_OWNED=1 ABI_RUNTIME_PROCESS_OWNED=1 ABI_RUNTIME_OWNED=1
    ABI_RUNTIME_PRIVILEGE=user
}

abi_refresh_runtime_ownership() {
    [ "$ABI_RUNTIME_OWNED" -eq 1 ] || return 0
    abi_refresh_status=0
    if [ "$ABI_RUNTIME_PROCESS_OWNED" -eq 1 ]; then
        if recording_launcher_active "$ABI_RUNTIME_PROCESS_PID" "$ABI_RUNTIME_PROCESS_STARTTIME"; then
            abi_refresh_status=1
        else
            abi_active_status=$?
            [ "$abi_active_status" -eq 1 ] || return 2
            case $RECORDED_LAUNCHER_STATE in
                gone|zombie) ABI_RUNTIME_PROCESS_OWNED=0 ;;
                replaced|unknown) return 2 ;;
            esac
        fi
    fi
    if [ "$ABI_RUNTIME_LAUNCH_OWNED" -eq 1 ]; then
        if recording_launcher_active "$ABI_RUNTIME_LAUNCH_PID" "$ABI_RUNTIME_LAUNCH_STARTTIME"; then
            abi_refresh_status=1
        else
            abi_active_status=$?
            [ "$abi_active_status" -eq 1 ] || return 2
            case $RECORDED_LAUNCHER_STATE in
                gone|zombie) ;;
                replaced|unknown) return 2 ;;
            esac
            abi_wait_status=0
            wait "$ABI_RUNTIME_LAUNCH_PID" || abi_wait_status=$?
            ABI_RUNTIME_STATUS=$abi_wait_status
            ABI_RUNTIME_LAUNCH_OWNED=0
        fi
    fi
    if [ "$ABI_RUNTIME_LAUNCH_OWNED" -eq 0 ] && [ "$ABI_RUNTIME_PROCESS_OWNED" -eq 0 ]; then
        abi_clear_runtime
        return 0
    fi
    return "$abi_refresh_status"
}

abi_reap_launcher() { abi_refresh_runtime_ownership; }

abi_stop_runtime() {
    [ "$ABI_RUNTIME_OWNED" -eq 1 ] || return 0
    abi_stop_status=0
    if [ "$ABI_RUNTIME_PROCESS_OWNED" -eq 1 ]; then
        terminate_recording_launcher "$ABI_RUNTIME_PROCESS_PID" "$ABI_RUNTIME_PROCESS_STARTTIME" "$ABI_RUNTIME_PRIVILEGE" || abi_stop_status=1
    fi
    if [ "$ABI_RUNTIME_LAUNCH_OWNED" -eq 1 ]; then
        terminate_recording_launcher "$ABI_RUNTIME_LAUNCH_PID" "$ABI_RUNTIME_LAUNCH_STARTTIME" "$ABI_RUNTIME_PRIVILEGE" || abi_stop_status=1
    fi
    [ "$abi_stop_status" -eq 0 ] || return 1
    abi_refresh_runtime_ownership
}

abi_wait_runtime() {
    abi_attempt=0
    while [ "$abi_attempt" -lt "${ABI_RUNTIME_WAIT_ATTEMPTS:-1500}" ]; do
        if abi_refresh_runtime_ownership; then return 0; else abi_refresh_status=$?; fi
        [ "$abi_refresh_status" -ne 2 ] || return 1
        case $RECORDED_LAUNCHER_STATE in replaced|unknown) return 1 ;; esac
        abi_attempt=$((abi_attempt + 1))
        sleep 0.05
    done
    abi_stop_runtime || return 1
    return 1
}

abi_committed_transfer_hook() { :; }

abi_launch_root_runtime() {
    [ "$ABI_RUNTIME_OWNED" -eq 0 ] && [ "$ABI_RUNTIME_ACQUIRING" -eq 0 ] && \
        [ -z "${ROOT_RECORD_CONTROL:-}" ] || return 2
    ABI_RUNTIME_ACQUIRING=1
    ABI_RUNTIME_PIDFILE=$1 abi_log=$2
    shift 2
    if ! launch_root_recorded_process "$ABI_RUNTIME_PIDFILE" "$abi_log" "$@"; then
        finalize_root_recorded_process || return 1
        ABI_RUNTIME_ACQUIRING=0
        return 1
    fi
    abi_committed_transfer_hook
    abi_capture_root_runtime
    ABI_RUNTIME_ACQUIRING=0
}

abi_complete_pending_launcher_identity() {
    [ -n "${ROOT_RECORD_IDENTITY:-}" ] || return 0
    [ -n "${ROOT_LAUNCH_PID:-}" ] || return 0
    [ -z "${ROOT_LAUNCH_STARTTIME:-}" ] || return 0
    abi_pending_record=$(recorded_process_control read "$ROOT_RECORD_IDENTITY" launcher self \
        "$ROOT_LAUNCH_PID" 0) || return 1
    ROOT_LAUNCH_STARTTIME=${abi_pending_record#* }
    export ROOT_LAUNCH_STARTTIME
}

abi_driver_cleanup() {
    abi_status=$?
    [ "$ABI_DRIVER_FINISHING" -eq 0 ] || exit "$abi_status"
    ABI_DRIVER_FINISHING=1
    trap '' HUP INT TERM
    trap - EXIT
    if [ "$ABI_RUNTIME_ACQUIRING" -eq 1 ] && [ "${ROOT_RECORD_PHASE:-}" = committed ] && \
        [ -n "${ROOT_LAUNCH_PID:-}" ] && [ -n "${ROOT_LAUNCH_STARTTIME:-}" ] && \
        [ -n "${ROOT_PROCESS_PID:-}" ] && [ -n "${ROOT_PROCESS_STARTTIME:-}" ]; then
        abi_capture_root_runtime
        ABI_RUNTIME_ACQUIRING=0
    fi
    abi_complete_pending_launcher_identity || abi_status=1
    abi_finalize_status=0
    finalize_root_recorded_process || { abi_finalize_status=1; abi_status=1; }
    if [ "$abi_finalize_status" -eq 0 ] && [ -z "${ROOT_RECORD_IDENTITY:-}" ]; then
        ABI_RUNTIME_ACQUIRING=0
    fi
    if [ "$ABI_RUNTIME_ACQUIRING" -eq 1 ]; then abi_status=1; fi
    if [ "$ABI_RUNTIME_OWNED" -eq 1 ]; then abi_stop_runtime || abi_status=1; fi
    if [ -n "${ABI_EVIDENCE_PIN:-}" ]; then
        printf 'cleanup_status=%s\n' "$abi_status" >"$ABI_EVIDENCE_PIN/driver-cleanup.status" || abi_status=1
        if [ "$abi_status" -eq 0 ]; then abi_final=PASS; else abi_final=NONPASS; fi
        printf 'result=%s\nexit_status=%s\n' "$abi_final" "$abi_status" >"$ABI_EVIDENCE_PIN/driver.status" || abi_status=1
    fi
    if [ "$ABI_TERMINAL_REPORTED" -eq 0 ]; then
        if [ "$abi_status" -eq 0 ]; then
            abi_result PASS "$ABI_SUCCESS_DETAIL"
        else
            abi_result NONPASS "reason=driver_exit exit_status=$abi_status"
        fi
    fi
    exit "$abi_status"
}

ABI_EXEC_GUARD='import ctypes, os, signal, sys
parent = os.getppid()
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG)")
if os.getppid() != parent:
    raise SystemExit(125)
os.execv(sys.argv[1], sys.argv[1:])'

abi_launch_variant_runtime() {
    abi_variant=$1 abi_binary=$2 abi_run_root=$3 abi_log=$4
    shift 4
    abi_pidfile=$WORK/run-$abi_variant.pid
    abi_launch_root_runtime "$abi_pidfile" "$abi_log" timeout --kill-after=5 -- \
        "${ABI_RUNTIME_DURATION:-60}" python3 -I -c "$ABI_EXEC_GUARD" "$abi_binary" "$abi_run_root" "$@"
}

abi_main() {
    set -eu
    require_non_root_caller
    [ "$#" -eq 1 ] || { echo "usage: $0 ABSENT_PRIVATE_EVIDENCE_ROOT" >&2; exit 1; }
    for abi_tool in cargo cmp find gcc grep id python3 readelf readlink rustc sed sha256sum sudo timeout uname; do
        command -v "$abi_tool" >/dev/null || { abi_result NONPASS "reason=missing_tool tool=$abi_tool" >&2; exit 1; }
    done
    [ "$(uname -m)" = x86_64 ] || { abi_result NONPASS reason=host_not_x86_64 >&2; exit 1; }
    abi_prepare_evidence_root "$1" || { abi_result NONPASS reason=unsafe_evidence_root >&2; exit 1; }
    EVIDENCE=$ABI_EVIDENCE_PIN
    WORK=$EVIDENCE/work
    FIXTURES=$WORK/fixtures
    DEFAULT_TARGET=$WORK/target-default
    DIAGNOSTIC_TARGET=$WORK/target-diagnostic
    mkdir -m 700 "$WORK" "$FIXTURES" "$DEFAULT_TARGET" "$DIAGNOSTIC_TARGET"
    trap abi_driver_cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    sudo -n true 2>/dev/null || { abi_result NONPASS reason=authorized_root_boundary_unavailable >&2; exit 1; }
    for abi_inherited in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CC CFLAGS P11SCOPE_SMALL_RING P11SCOPE_SMALL_STATE_MAPS P11SCOPE_SMALL_DISCOVERY_RING; do
        eval "abi_value=\${$abi_inherited-}"
        [ -z "$abi_value" ] || { abi_result NONPASS "reason=inherited_build_variable variable=$abi_inherited" >&2; exit 1; }
    done
    {
        echo "kernel_release=$(uname -r)"
        echo "kernel_version=$(uname -v)"
        for abi_tool in cargo gcc readelf sha256sum sudo timeout; do
            echo "$abi_tool=$(readlink -f "$(command -v "$abi_tool")")"
        done
        echo "gcc_version=$(gcc -dumpfullversion -dumpversion)"
        echo "cargo_version=$(cargo +1.88 --version)"
        echo "rustc_version=$(rustc +1.88 --version)"
    } >"$EVIDENCE/environment.status"
    {
        printf '%s\n' Cargo.lock Cargo.toml build.rs examples/abi-routing.rs scripts/lib.sh scripts/recorded-process-exec.py tests/fixtures/abi-routing/fail-ack.py scripts/matrix/ia32-compat-harness.c tests/shell/test_abi_routing_driver.sh scripts/matrix/verify-abi-routing.sh
        find crates/ebpf/src crates/ebpf-common/src crates/manifest/src src third-party/aya -type f -print
        find crates/ebpf crates/ebpf-common crates/manifest -maxdepth 1 -type f -print
    } | LC_ALL=C sort -u >"$WORK/source-inputs.list"
    while IFS= read -r abi_input; do sha256sum "$abi_input"; done <"$WORK/source-inputs.list" >"$EVIDENCE/source-before.sha256"
    abi_src=scripts/matrix/ia32-compat-harness.c
    abi_build_fixture() {
        abi_width=$1 abi_cfi=
        [ "$abi_width" = 32 ] && abi_cfi=-fcf-protection=branch
        gcc "-m$abi_width" -O1 -g -Wall -Wextra -Werror -fno-omit-frame-pointer $abi_cfi -rdynamic -o "$FIXTURES/harness-$abi_width" "$abi_src" -ldl
        gcc "-m$abi_width" -O1 -g -Wall -Wextra -Werror -fPIC -shared -DIA32_COMPAT_DSO -o "$FIXTURES/second-$abi_width.so" "$abi_src"
    }
    abi_build_fixture 64 >"$EVIDENCE/build-fixture64.log" 2>&1 || { abi_result NONPASS reason=native64_fixture_build_failed; exit 1; }
    abi_build_fixture 32 >"$EVIDENCE/build-fixture32.log" 2>&1 || { abi_result NONPASS reason=ia32_fixture_build_failed; exit 1; }
    abi_elf_class() { readelf -h "$1" | sed -n 's/^[[:space:]]*Class:[[:space:]]*//p'; }
    [ "$(abi_elf_class "$FIXTURES/harness-64")" = ELF64 ] && [ "$(abi_elf_class "$FIXTURES/second-64.so")" = ELF64 ] || { abi_result NONPASS reason=native64_subject_class_mismatch; exit 1; }
    [ "$(abi_elf_class "$FIXTURES/harness-32")" = ELF32 ] && [ "$(abi_elf_class "$FIXTURES/second-32.so")" = ELF32 ] || { abi_result NONPASS reason=ia32_subject_class_mismatch; exit 1; }
    abi_loader=$(readelf -l "$FIXTURES/harness-32" | sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
    [ -n "$abi_loader" ] && [ -x "$abi_loader" ] || { abi_result NONPASS "reason=ia32_loader_unavailable loader=${abi_loader:-missing}"; exit 1; }
    CARGO_TARGET_DIR="$DEFAULT_TARGET" cargo +1.88 build --locked --offline --example abi-routing --no-default-features >"$EVIDENCE/build-default.log" 2>&1 || { abi_result NONPASS reason=default_example_build_failed; exit 1; }
    CARGO_TARGET_DIR="$DIAGNOSTIC_TARGET" cargo +1.88 build --locked --offline --example abi-routing --no-default-features --features unsafe-unvalidated-metadata >"$EVIDENCE/build-diagnostic.log" 2>&1 || { abi_result NONPASS reason=diagnostic_example_build_failed; exit 1; }
    DEFAULT_BIN=$DEFAULT_TARGET/debug/examples/abi-routing
    DIAGNOSTIC_BIN=$DIAGNOSTIC_TARGET/debug/examples/abi-routing
    [ -x "$DEFAULT_BIN" ] && [ -x "$DIAGNOSTIC_BIN" ] || { abi_result NONPASS reason=example_binary_missing; exit 1; }
    printf '%s\n' object_mode=default unsafe_unvalidated_metadata=0 >"$EVIDENCE/default-build.status"
    printf '%s\n' object_mode=diagnostic unsafe_unvalidated_metadata=1 >"$EVIDENCE/diagnostic-build.status"
    sha256sum "$FIXTURES/harness-64" "$FIXTURES/second-64.so" "$FIXTURES/harness-32" "$FIXTURES/second-32.so" "$DEFAULT_BIN" "$DIAGNOSTIC_BIN" >"$EVIDENCE/built-artifacts.sha256"
    abi_run_variant() {
        abi_variant=$1 abi_binary=$2
        abi_run_root=$EVIDENCE/run-$abi_variant
        abi_log=$EVIDENCE/run-$abi_variant.log
        ABI_RUNTIME_STATUS=
        abi_launch_variant_runtime "$abi_variant" "$abi_binary" "$abi_run_root" "$abi_log" \
            "$FIXTURES/harness-64" "$FIXTURES/second-64.so" "$FIXTURES/harness-32" "$FIXTURES/second-32.so" || return 1
        abi_wait_runtime || return 1
        printf 'exit_status=%s\n' "$ABI_RUNTIME_STATUS" >"$EVIDENCE/run-$abi_variant.status"
        if [ -e "$abi_run_root" ]; then sudo -n chown -R "$(id -u):$(id -g)" "$abi_run_root" || return 1; fi
        [ "$ABI_RUNTIME_STATUS" -eq 0 ] || return "$ABI_RUNTIME_STATUS"
        grep -q '^result=PASS$' "$abi_run_root/overall.status"
    }
    abi_default_status=0; abi_run_variant default "$DEFAULT_BIN" || abi_default_status=$?
    abi_diagnostic_status=0; abi_run_variant diagnostic "$DIAGNOSTIC_BIN" || abi_diagnostic_status=$?
    while IFS= read -r abi_input; do sha256sum "$abi_input"; done <"$WORK/source-inputs.list" >"$EVIDENCE/source-after.sha256"
    cmp -s "$EVIDENCE/source-before.sha256" "$EVIDENCE/source-after.sha256" || { abi_result NONPASS reason=source_inputs_changed_during_gate; exit 1; }
    for abi_artifact in "$EVIDENCE/run-default/embedded-bpf.o" "$EVIDENCE/run-diagnostic/embedded-bpf.o"; do
        [ -f "$abi_artifact" ] || { abi_result NONPASS "reason=embedded_object_evidence_missing path=$abi_artifact"; exit 1; }
    done
    sha256sum "$EVIDENCE/run-default/embedded-bpf.o" "$EVIDENCE/run-diagnostic/embedded-bpf.o" >"$EVIDENCE/embedded-objects.sha256"
    [ "$abi_default_status" -eq 0 ] && [ "$abi_diagnostic_status" -eq 0 ] || { abi_result NONPASS "default_status=$abi_default_status diagnostic_status=$abi_diagnostic_status"; exit 1; }
    ABI_SUCCESS_DETAIL='default_rows=2 diagnostic_rows=4'
}

if [ "${ABI_ROUTING_DRIVER_LIBRARY_ONLY:-0}" != 1 ]; then abi_main "$@"; fi
