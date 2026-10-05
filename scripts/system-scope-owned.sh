# SPDX-License-Identifier: GPL-3.0-or-later
# shellcheck shell=sh
# Launch-time supervisor custody for system-scope-measure.sh.

: "${P11SCOPE_RECEIPT_HELPER:=scripts/system-scope-receipt.py}"
: "${OWNED_WRAPPER_FAILED_RECEIPTS:=}"
: "${OWNED_WRAPPER_FAILED_RECEIPT_COUNT:=0}"
: "${OWNED_WRAPPER_FAILED_RECEIPT_OVERFLOW:=false}"

# Keep exact receipt-local persistence failures in the owning shell. The
# overflow state deliberately fails every later receipt closed: once exact
# attribution cannot be retained, this owner cannot qualify another launch.
owned_wrapper_failure_known() {
    if [ "$OWNED_WRAPPER_FAILED_RECEIPT_OVERFLOW" = true ]; then
        return 0
    fi
    [ -n "$OWNED_WRAPPER_FAILED_RECEIPTS" ] || return 1
    while IFS= read -r owned_failed_receipt; do
        [ "$owned_failed_receipt" = "$1" ] && return 0
    done <<EOF
$OWNED_WRAPPER_FAILED_RECEIPTS
EOF
    return 1
}

owned_wrapper_remember_failure() {
    owned_wrapper_failure_known "$1" && return 0
    case "$OWNED_WRAPPER_FAILED_RECEIPT_COUNT" in
        ''|*[!0-9]*)
            OWNED_WRAPPER_FAILED_RECEIPT_OVERFLOW=true
            return 1
            ;;
    esac
    case "$1" in
        *'
'*)
            OWNED_WRAPPER_FAILED_RECEIPT_OVERFLOW=true
            return 1
            ;;
    esac
    if [ "${#1}" -gt 4096 ] ||
       [ "$OWNED_WRAPPER_FAILED_RECEIPT_COUNT" -ge 32 ]; then
        OWNED_WRAPPER_FAILED_RECEIPT_OVERFLOW=true
        return 1
    fi
    if [ -n "$OWNED_WRAPPER_FAILED_RECEIPTS" ]; then
        OWNED_WRAPPER_FAILED_RECEIPTS="$OWNED_WRAPPER_FAILED_RECEIPTS
$1"
    else
        OWNED_WRAPPER_FAILED_RECEIPTS=$1
    fi
    OWNED_WRAPPER_FAILED_RECEIPT_COUNT=$((
        OWNED_WRAPPER_FAILED_RECEIPT_COUNT + 1))
}

owned_process_starttime() {
    python3 -I "$P11SCOPE_RECEIPT_HELPER" process --pid "$1" |
        python3 -I -c 'import json,sys; print(json.load(sys.stdin)["starttime"])'
}

# owned_launch <root|user> <stdin|-> <stdout> <stderr> -- <argv...>
# Publishes supervisor and command identities plus the supervisor receipt.
owned_run_supervisor() {
    owned_run_privilege=$1
    shift
    if [ "$owned_run_privilege" = root ]; then
        exec sudo -n --preserve-env=SOFTHSM2_CONF \
            python3 -I scripts/system-scope-supervisor.py \
            --receipt "$OWNED_RECEIPT" \
            --receipt-helper "$P11SCOPE_RECEIPT_HELPER" \
            --wrapper-identity "$OWNED_WRAPPER_IDENTITY" \
            --receipt-owner-uid "$(id -u)" --receipt-owner-gid "$(id -g)" \
            --root-group -- "$@"
    fi
    exec python3 -I scripts/system-scope-supervisor.py \
        --receipt "$OWNED_RECEIPT" \
        --receipt-helper "$P11SCOPE_RECEIPT_HELPER" \
        --wrapper-identity "$OWNED_WRAPPER_IDENTITY" -- "$@"
}

owned_launch() {
    owned_privilege=$1
    owned_stdin=$2
    owned_stdout=$3
    owned_stderr=$4
    shift 4
    [ "$1" = -- ] || { echo "owned_launch requires --" >&2; return 2; }
    shift
    OWNED_RECEIPT=$(mktemp "${TMPDIR:-/tmp}/p11scope-owned.XXXXXX")
    OWNED_WRAPPER_IDENTITY=$(mktemp "${TMPDIR:-/tmp}/p11scope-wrapper.XXXXXX")
    if [ "$owned_stdin" = - ] && [ "$owned_stderr" = = ]; then
        owned_run_supervisor "$owned_privilege" "$@" >"$owned_stdout" 2>&1 &
    elif [ "$owned_stdin" = - ]; then
        owned_run_supervisor "$owned_privilege" "$@" \
            >"$owned_stdout" 2>"$owned_stderr" &
    elif [ "$owned_stderr" = = ]; then
        owned_run_supervisor "$owned_privilege" "$@" \
            <"$owned_stdin" >"$owned_stdout" 2>&1 &
    else
        owned_run_supervisor "$owned_privilege" "$@" \
            <"$owned_stdin" >"$owned_stdout" 2>"$owned_stderr" &
    fi
    OWNED_PID=$!
    OWNED_STARTTIME=$(owned_process_starttime "$OWNED_PID")
    printf '%s %s\n' "$OWNED_PID" "$OWNED_STARTTIME" \
        > "$OWNED_WRAPPER_IDENTITY"
}

owned_verify_launch() {
    # The supervisor's receipt must appear for a live launch, and a wrapper
    # that ends first stops this wait at once (below), so the ceiling only
    # bounds a slow start. A fixed 3 s refused healthy launches under host
    # load ~20 (DR-SCOPE-RECEIPT-SESSION-FLAKE).
    owned_verify_seconds=${P11SCOPE_OWNED_VERIFY_SECONDS:-30}
    owned_deadline=$(( $(date +%s) + owned_verify_seconds ))
    while :; do
        if python3 -I - "$1" "$2" "$3" <<'PY' 2>/dev/null
import json, sys
record = json.load(open(sys.argv[3], encoding="utf-8"))
assert record["outer_wrapper_pid"] == int(sys.argv[1])
assert record["outer_wrapper_starttime"] == int(sys.argv[2])
assert record["supervisor_pid"] > 0 and record["supervisor_starttime"] > 0
assert record["command_pid"] > 0 and record["command_starttime"] > 0
PY
        then
            break
        fi
        owned_launch_state=0
        owned_wait_root_terminal "$1" "$2" 0 || owned_launch_state=$?
        case "$owned_launch_state" in
            0) return 1 ;;
            1) ;;
            *) return 1 ;;
        esac
        [ "$(date +%s)" -lt "$owned_deadline" ] || {
            echo "owned launch: supervisor receipt not published within ${owned_verify_seconds}s" >&2
            return 1
        }
        sleep 0.01
    done
    OWNED_COMMAND_PID=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["command_pid"])' "$3")
    OWNED_COMMAND_STARTTIME=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["command_starttime"])' "$3")
    OWNED_SUPERVISOR_PID=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["supervisor_pid"])' "$3")
    OWNED_SUPERVISOR_STARTTIME=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["supervisor_starttime"])' "$3")
    [ "$(owned_process_starttime "$OWNED_SUPERVISOR_PID")" = \
      "$OWNED_SUPERVISOR_STARTTIME" ] || return 1
    python3 -I "$P11SCOPE_RECEIPT_HELPER" verify-group \
        --pid "$OWNED_COMMAND_PID" --starttime "$OWNED_COMMAND_STARTTIME" \
        --timeout 2 >/dev/null
}

owned_wait_supervisor_terminal() {
    owned_supervisor_pid=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["supervisor_pid"])' "$1") || return 2
    owned_supervisor_birth=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["supervisor_starttime"])' "$1") || return 2
    owned_wait_root_terminal "$owned_supervisor_pid" "$owned_supervisor_birth" "$2"
}

owned_process_state() {
    owned_inspection=$(mktemp "${TMPDIR:-/tmp}/p11scope-inspect.XXXXXX") || return 2
    owned_inspect_status=0
    python3 -I "$P11SCOPE_RECEIPT_HELPER" inspect-process \
        --pid "$1" --starttime "$2" >"$owned_inspection" 2>/dev/null || \
        owned_inspect_status=$?
    if [ "$owned_inspect_status" -ne 0 ]; then
        rm -f "$owned_inspection"
        return 2
    fi
    owned_state=$(python3 -I - "$owned_inspection" "$1" "$2" <<'PY'
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
pid, birth = int(sys.argv[2]), int(sys.argv[3])
if not isinstance(record, dict):
    raise SystemExit(1)
if record.get("pid") != pid or record.get("starttime") != birth:
    raise SystemExit(1)
state = record.get("state")
if state not in ("live", "terminal", "unknown"):
    raise SystemExit(1)
print(state)
PY
    ) || {
        rm -f "$owned_inspection"
        return 2
    }
    rm -f "$owned_inspection"
    printf '%s\n' "$owned_state"
}

owned_wait_root_terminal() {
    owned_end=$(( $(date +%s) + $3 ))
    while :; do
        owned_state=$(owned_process_state "$1" "$2") || return 2
        case "$owned_state" in
            terminal) return 0 ;;
            live) ;;
            *) return 2 ;;
        esac
        if [ "$(date +%s)" -ge "$owned_end" ]; then
            return 1
        fi
        sleep 0.1
    done
}

# owned_finish <supervisor-pid> <starttime> <receipt> <natural-timeout>
# Signals only the retained supervisor; it settles its private command group.
owned_finish() {
    owned_supervisor_pid=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["supervisor_pid"])' "$3") || return 1
    owned_supervisor_birth=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["supervisor_starttime"])' "$3") || return 1
    owned_root_group=$(python3 -I -c \
        'import json,sys; print("true" if json.load(open(sys.argv[1]))["root_group"] else "false")' "$3") || return 1
    owned_supervisor_state=0
    owned_wait_root_terminal "$owned_supervisor_pid" "$owned_supervisor_birth" "$4" || \
        owned_supervisor_state=$?
    if [ "$owned_supervisor_state" -eq 1 ]; then
        if [ "$owned_root_group" = true ]; then
            sudo -n python3 -I "$P11SCOPE_RECEIPT_HELPER" signal-process \
                --pid "$owned_supervisor_pid" --starttime "$owned_supervisor_birth" \
                --signal TERM >/dev/null || return 1
        else
            python3 -I "$P11SCOPE_RECEIPT_HELPER" signal-process \
                --pid "$owned_supervisor_pid" --starttime "$owned_supervisor_birth" \
                --signal TERM >/dev/null || return 1
        fi
        owned_supervisor_state=0
        owned_wait_root_terminal "$owned_supervisor_pid" \
            "$owned_supervisor_birth" 15 || owned_supervisor_state=$?
        [ "$owned_supervisor_state" -eq 0 ] || return 1
    elif [ "$owned_supervisor_state" -ne 0 ]; then
        return 1
    fi
    owned_wrapper_result=$(mktemp "${TMPDIR:-/tmp}/p11scope-wrapper-result.XXXXXX") || return 1
    owned_wrapper_error=$(mktemp "${TMPDIR:-/tmp}/p11scope-wrapper-error.XXXXXX") || {
        rm -f "$owned_wrapper_result"
        return 1
    }
    owned_wrapper_helper_status=0
    python3 -I "$P11SCOPE_RECEIPT_HELPER" settle-process \
        --pid "$1" --starttime "$2" --term-timeout 1 --total-timeout 4 \
        >"$owned_wrapper_result" 2>"$owned_wrapper_error" || \
        owned_wrapper_helper_status=$?
    owned_wrapper_terminal=false
    if [ "$owned_wrapper_helper_status" -eq 0 ]; then
        owned_wrapper_decision=
        owned_wrapper_validation_status=0
        owned_wrapper_decision=$(python3 -I "$P11SCOPE_RECEIPT_HELPER" \
            validate-wrapper-result --result "$owned_wrapper_result" \
            --pid "$1" --starttime "$2" 2>>"$owned_wrapper_error") || \
            owned_wrapper_validation_status=$?
        if [ "$owned_wrapper_validation_status" -eq 0 ] && \
           [ "$owned_wrapper_decision" = terminal ]; then
            owned_wrapper_terminal=true
        fi
    fi
    OWNED_EXIT=0
    owned_wrapper_reaped=false
    if [ "$owned_wrapper_terminal" = true ]; then
        wait "$1" 2>/dev/null || OWNED_EXIT=$?
        owned_wrapper_reaped=true
    fi
    owned_wrapper_record_status=0
    owned_wrapper_owner_failed=false
    if owned_wrapper_failure_known "$3" || \
       [ -e "$3.wrapper-owner-failed" ]; then
        owned_wrapper_owner_failed=true
    fi
    python3 -I "$P11SCOPE_RECEIPT_HELPER" record-wrapper-cleanup \
        --receipt "$3" --result "$owned_wrapper_result" \
        --error "$owned_wrapper_error" \
        --helper-status "$owned_wrapper_helper_status" \
        --pid "$1" --starttime "$2" \
        --reaped "$owned_wrapper_reaped" --wrapper-exit "$OWNED_EXIT" \
        --owner-failed "$owned_wrapper_owner_failed" \
        >/dev/null || \
        owned_wrapper_record_status=$?
    if [ "$owned_wrapper_record_status" -ne 0 ]; then
        # The in-memory ledger is authoritative for this owner. A subshell
        # contains special-builtin redirection failure so dash cannot abandon
        # cleanup of other owned launches when the directory is read-only.
        owned_wrapper_remember_failure "$3" || true
        if (umask 077; : > "$3.wrapper-owner-failed") 2>/dev/null; then
            :
        else
            owned_wrapper_sidecar_status=1
        fi
    fi
    rm -f "$owned_wrapper_result" "$owned_wrapper_error"
    owned_receipt_status=0
    python3 -I - "$3" <<'PY' || owned_receipt_status=$?
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
wrapper = record.get("outer_wrapper_cleanup", {})
valid = (record.get("terminal_proof") is True
         and record.get("cleanup_ok") is True
         and record.get("settled") is True
         and wrapper.get("helper_status") == 0
         and wrapper.get("terminal") is True
         and wrapper.get("reaped") is True
         and not wrapper.get("signal_failures")
         and record.get("outer_wrapper_cleanup_failed") is False)
raise SystemExit(0 if valid else 1)
PY
    [ "$owned_wrapper_record_status" -eq 0 ] || owned_receipt_status=1
    owned_wrapper_file=$(python3 -I -c \
        'import json,sys; print(json.load(open(sys.argv[1])).get("wrapper_identity_file", ""))' "$3" 2>/dev/null || true)
    [ -z "$owned_wrapper_file" ] || rm -f "$owned_wrapper_file"
    return "$owned_receipt_status"
}

# Read the command's exact wait status from the retained supervisor receipt.
# Exports shell-compatible exit and POSIX signal name (or literal null).
owned_command_outcome() {
    owned_outcome=$(python3 -I - "$1" <<'PY'
import json, signal, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
returncode = record["command_exit"]
if not isinstance(returncode, int):
    raise SystemExit(1)
if returncode < 0:
    number = -returncode
    print(f"{128 + number} {signal.Signals(number).name}")
else:
    print(f"{returncode} null")
PY
    ) || return 1
    OWNED_COMMAND_EXIT=${owned_outcome%% *}
    OWNED_COMMAND_SIGNAL=${owned_outcome#* }
}
