#!/usr/bin/env bash
# Loader artifact harness (Task 7). The A/B artifact's run.sh is NOT modified
# (Task 5 freeze boundary): the VM lane functions here are copied from it with
# loader-specific bundle inventory, validator, and build steps.

P11SCOPE_VM_BASES=${P11SCOPE_VM_BASES:-$HOME/src/m/p11scope-ws/vm-bases}

lane_config() {
    case "$1" in
        jammy)
            printf '%s\n' "$P11SCOPE_VM_BASES/jammy/overlay.qcow2|$P11SCOPE_VM_BASES/jammy/serial.log|2222|SHA256:GD2UX29+dul1JSEIm9k1XjotD9Exr1j9vrTgG92wQEY"
            ;;
        noble)
            printf '%s\n' "$P11SCOPE_VM_BASES/noble/overlay.qcow2|$P11SCOPE_VM_BASES/noble/serial.log|2223|SHA256:lJncGXZAZRDW+QEdhkWpCyhco+DDPxnYB8J6IEha1aQ"
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
        -i "$P11SCOPE_VM_BASES/id_ed25519" \
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
        -i "$P11SCOPE_VM_BASES/id_ed25519" \
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
    printf '%s=%s\n' "$label" "$available"
    (( available >= 2147483648 )) || return 64
}

qemu_preflight() {
    local system_version image_version
    system_version=$(qemu-system-x86_64 --version | sed -n '1p')
    image_version=$(qemu-img --version | sed -n '1p')
    [[ $system_version =~ ^QEMU\ emulator\ version\ 8\.2\.2([[:space:]\(]|$) ]]
    [[ $image_version =~ ^qemu-img\ version\ 8\.2\.2([[:space:]\(]|$) ]]
}

fixed_inventory() {
    printf '%s\n' environment.txt verifier.log verifier-results.jsonl \
        loader-facts.jsonl runner-status.txt
}

loader_runtime_reasons() {
    cat <<'REASONS'
fork
loader open
loader read
loader metadata
loader ELF
loader symbol
loader delta
loader records timeout
loader executable mapping
loader mapping bias
fixture pipes
fixture ready timeout
pipe byte
child release
child wait
registry capacity
registry phase
program missing
program type
child pid is zero
program attach
program detach
counter read
ring drain
process maps
discovery record length is not 896 bytes
REASONS
}

loader_semantics_python() {
    cat <<'PY'
import json, os, sys
directory, expected_rc = sys.argv[1:]
if expected_rc not in {"0", "1"}:
    raise SystemExit(64)
runtime_reasons = set("""
PY
    loader_runtime_reasons
    cat <<'PY'
""".splitlines())
def json_lines(name):
    with open(os.path.join(directory, name), encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]
try:
    verifier = json_lines("verifier-results.jsonl")
    facts = json_lines("loader-facts.jsonl")
    with open(os.path.join(directory, "runner-status.txt"), encoding="utf-8") as stream:
        status_lines = [line.rstrip("\n") for line in stream]
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(64)
if len(verifier) != 1 or verifier[0].get("program") != "dl_debug_state":
    raise SystemExit(64)
item = verifier[0]
if (
    item.get("load_attempted") is not True
    or not isinstance(item.get("accepted"), bool)
    or item.get("pass") is not item["accepted"]
    or item.get("failure_category") != ("none" if item["accepted"] else "verifier")
    or item.get("success_log_contract") != ("accepted_line_only" if item["accepted"] else "rejection_error_chain")
):
    raise SystemExit(64)
flows = [item.get("flow") for item in facts]
if len(facts) > 2 or flows != ["loader_startup", "no_cookie_negative"][:len(flows)]:
    raise SystemExit(64)
u64 = ["hits", "invalid_records", "ring_loss", "state_failures", "loader_hits_counter", "state_read_failures", "cookie_zero_hits", "func_ip_zero_hits"]
def bools_startup():
    return ["pid_matches", "formula_holds", "derived_debug_address_ok", "start_empty", "registry_decodable_after_drain", "state_present_delta"]
def bools_negative():
    return ["exactly_one_invalid", "no_ip_operation", "no_state_operation", "no_context_id_copied"]
def well_formed(item):
    if not isinstance(item.get("pass"), bool) or item.get("failure_category") not in {"none", "oracle", "runtime"}:
        return False
    if item.get("failure_category") == "runtime":
        # A runtime row records the metadata envelope plus the reason; the
        # flow never executed, so it carries no flow facts.
        return item.get("runtime_failure_reason") in runtime_reasons and item.get("pass") is False
    for name in u64:
        value = item.get(name)
        if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 0xffffffffffffffff:
            return False
    states = item.get("r_states")
    if item.get("flow") == "loader_startup":
        if not isinstance(states, list) or len(states) > 8:
            return False
        if any(type(state) is not int or isinstance(state, bool) or not 0 <= state <= 0xffffffff for state in states):
            return False
    names = bools_startup() if item.get("flow") == "loader_startup" else bools_negative()
    if any(not isinstance(item.get(name), bool) for name in names):
        return False
    if item.get("flow") == "loader_startup" and (not isinstance(item.get("loader_sha256"), str) or len(item["loader_sha256"]) != 64):
        return False
    before = item.get("counters_before")
    after = item.get("counters_after")
    if item.get("flow") == "loader_startup":
        for counts in [before, after]:
            if not isinstance(counts, list) or len(counts) != 6 or any(type(n) is not int or isinstance(n, bool) or n < 0 for n in counts):
                return False
    return True
def oracle(item):
    if item.get("flow") == "loader_startup":
        return (
            item["hits"] == 2 and item["r_states"] == [1, 0]
            and item["pid_matches"] is True and item["formula_holds"] is True
            and item["derived_debug_address_ok"] is True
            and item["invalid_records"] == 0 and item["state_read_failures"] == 0
            and item["cookie_zero_hits"] == 0
            and item["func_ip_zero_hits"] <= item["loader_hits_counter"]
            and item["ring_loss"] == 0 and item["state_failures"] == 0
            and item["start_empty"] is True
            and item["registry_decodable_after_drain"] is True
        )
    return (
        item["hits"] == 1 and item["invalid_records"] == 1
        and item["exactly_one_invalid"] is True
        and item["no_ip_operation"] is True and item["no_state_operation"] is True
        and item["no_context_id_copied"] is True
        and item["loader_hits_counter"] == 1 and item["state_read_failures"] == 0
        and item["cookie_zero_hits"] == 1 and item["func_ip_zero_hits"] == 0
        and item["ring_loss"] == 0 and item["state_failures"] == 0
    )
if any(not well_formed(item) for item in facts):
    raise SystemExit(64)
accepted = verifier[0]["accepted"]
expected_status = "PASS" if expected_rc == "0" else "FAIL"
if len(status_lines) != 2 or status_lines[0] != f"status={expected_status}":
    raise SystemExit(64)
category = status_lines[1].removeprefix("failure_category=") if status_lines[1].startswith("failure_category=") else ""
if expected_status == "PASS":
    if category != "none" or not accepted or len(facts) != 2:
        raise SystemExit(64)
    if any(item.get("failure_category") != "none" or "runtime_failure_reason" in item or not oracle(item) for item in facts):
        raise SystemExit(64)
elif category == "verifier":
    if accepted or facts:
        raise SystemExit(64)
elif category == "runtime":
    if not accepted or not facts:
        raise SystemExit(64)
    for item in facts[:-1]:
        if "runtime_failure_reason" in item:
            raise SystemExit(64)
        if item.get("failure_category") == "none" and not oracle(item):
            raise SystemExit(64)
        if item.get("failure_category") == "oracle" and oracle(item):
            raise SystemExit(64)
        if item.get("failure_category") not in ("none", "oracle"):
            raise SystemExit(64)
    last = facts[-1]
    if last.get("failure_category") != "runtime" or last.get("runtime_failure_reason") not in runtime_reasons:
        raise SystemExit(64)
elif category == "oracle":
    if not accepted or len(facts) != 2:
        raise SystemExit(64)
    for item in facts:
        if "runtime_failure_reason" in item:
            raise SystemExit(64)
        if item.get("failure_category") == "none" and not oracle(item):
            raise SystemExit(64)
        if item.get("failure_category") == "oracle" and oracle(item):
            raise SystemExit(64)
        if item.get("failure_category") not in ("none", "oracle"):
            raise SystemExit(64)
    if not any(item.get("failure_category") == "oracle" for item in facts):
        raise SystemExit(64)
else:
    raise SystemExit(64)
for name in ["environment.txt", "verifier.log"]:
    if os.path.getsize(os.path.join(directory, name)) == 0:
        raise SystemExit(64)
PY
}

remote_export_script() {
    cat <<'REMOTE_EXPORT'
set -eu
directory=$1
expected_rc=$2
set -- environment.txt verifier.log verifier-results.jsonl loader-facts.jsonl runner-status.txt
test "$(find "$directory" -mindepth 1 -maxdepth 1 -printf . | wc -c)" -eq 5
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
python3 - "$directory" "$expected_rc" <<'PY'
REMOTE_EXPORT
    loader_semantics_python
    cat <<'REMOTE_EXPORT'
PY
exec tar --format=posix --no-recursion -C "$directory" -cf - "$@"
REMOTE_EXPORT
}

export_evidence() {
    local known_hosts=$1 port=$2 remote_dir=$3 new_host_dir=$4 expected_rc=$5 remote_command
    [[ $remote_dir =~ ^/var/tmp/p11scope-slice1b2-loader/[A-Za-z0-9._/-]+$ && $remote_dir != *..* ]] || return 64
    [[ ! -e $new_host_dir && ! -L $new_host_dir ]] || return 64
    umask 077
    mkdir -m 0700 "$new_host_dir"
    local -a ssh
    mapfile -d '' -t ssh < <(ssh_argv "$known_hosts" "$port")
    remote_command="sudo -n sh -s -- $remote_dir $expected_rc"
    # A failed export or extraction must not leave a stale directory that
    # blocks the next lane attempt from creating it fresh.
    if ! remote_export_script \
        | timeout 120s "${ssh[@]}" p11scope@127.0.0.1 "$remote_command" \
        | tar --no-same-owner --no-same-permissions -C "$new_host_dir" -xf -; then
        rm -rf "$new_host_dir"
        return 64
    fi
}

validate_local_export() {
    local directory=$1 expected_rc=$2 name size total=0
    local -a files
    [[ -d $directory && ! -L $directory && $(stat -c '%u:%a' "$directory") == "$(id -u):700" ]] || return 64
    mapfile -t files < <(fixed_inventory)
    [[ $(find "$directory" -mindepth 1 -maxdepth 1 -printf . | wc -c) == 5 ]] || return 64
    for name in "${files[@]}"; do
        [[ -f $directory/$name && ! -L $directory/$name && $(stat -c '%u:%a' "$directory/$name") == "$(id -u):600" ]] || return 64
        size=$(stat -c '%s' "$directory/$name")
        case "$name" in
            verifier.log) (( size <= 8388608 )) || return 64 ;;
            *.jsonl) (( size <= 4194304 )) || return 64 ;;
            *) (( size <= 65536 )) || return 64 ;;
        esac
        total=$(( size + total ))
    done
    (( total <= 16777216 )) || return 64
    loader_semantics_python | python3 - "$directory" "$expected_rc" || return 64
    [[ ! -e $directory.sha256 && ! -L $directory.sha256 ]] || return 64
    (cd "$directory" && sha256sum "${files[@]}") >"$directory.sha256"
    chmod 0600 "$directory.sha256"
}

validate_backing_chain_file() {
    local json=$1 runtime=$2 retained=$3 official=$4
    python3 - "$json" "$runtime" "$retained" "$official" <<'PY'
import json, os, sys
path, runtime, retained, official = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    chain = json.load(stream)
expected = [runtime, retained, official]
if len(chain) != 3 or any(not os.path.isabs(value) for value in expected):
    raise SystemExit(64)
for index, (entry, filename) in enumerate(zip(chain, expected)):
    if entry.get("filename") != filename or entry.get("format") != "qcow2":
        raise SystemExit(64)
    if index < 2:
        if entry.get("backing-filename") != expected[index + 1] or entry.get("backing-filename-format") != "qcow2":
            raise SystemExit(64)
    elif "backing-filename" in entry:
        raise SystemExit(64)
PY
}

strict_ssh() {
    local known_hosts=$1 port=$2
    shift 2
    local -a ssh
    mapfile -d '' -t ssh < <(ssh_argv "$known_hosts" "$port")
    timeout 30s "${ssh[@]}" p11scope@127.0.0.1 "$@"
}

gate_ssh() {
    local known_hosts=$1 port=$2
    shift 2
    local -a ssh
    mapfile -d '' -t ssh < <(ssh_argv "$known_hosts" "$port")
    timeout 150s "${ssh[@]}" p11scope@127.0.0.1 "$@"
}

strict_ssh_long() {
    local known_hosts=$1 port=$2
    shift 2
    local -a ssh
    mapfile -d '' -t ssh < <(ssh_argv "$known_hosts" "$port")
    timeout 3600s "${ssh[@]}" p11scope@127.0.0.1 "$@"
}

private_start_lane() {
    local lane=$1 run_dir=$2 config retained official initial_serial port fingerprint
    local accel_name boot_start boot_ok=0
    qemu_preflight || return
    config=$(lane_config "$lane") || return
    IFS='|' read -r retained initial_serial port fingerprint <<<"$config"
    case "$lane" in
        jammy) official="$P11SCOPE_VM_BASES/jammy/jammy-server-cloudimg-amd64.img" ;;
        noble) official="$P11SCOPE_VM_BASES/noble/noble-server-cloudimg-amd64.img" ;;
        *) return 64 ;;
    esac
    [[ ! -e $run_dir && ! -L $run_dir ]] || return 64
    [[ $(stat -c '%a' "$retained") == 444 && -f $official && -f $initial_serial ]] || return 64
    [[ ! -e /proc/net/tcp || -z $(ss -H -ltn "sport = :$port") ]] || return 64
    umask 077
    mkdir -m 0700 "$run_dir" || return 64
    require_free_bytes before-overlay "$run_dir" >"$run_dir/free-space.before-overlay.txt" || return 64
    sha256sum "$retained" >"$run_dir/retained.before.sha256" || return 64
    qemu-img create -f qcow2 -F qcow2 -b "$retained" "$run_dir/runtime.qcow2" \
        >"$run_dir/qemu-img-create.stdout" 2>"$run_dir/qemu-img-create.stderr" || return 64
    chmod 0600 "$run_dir/runtime.qcow2" || return 64
    qemu-img info --backing-chain --output=json "$run_dir/runtime.qcow2" \
        >"$run_dir/backing-chain.before.json" || return 64
    validate_backing_chain_file "$run_dir/backing-chain.before.json" \
        "$run_dir/runtime.qcow2" "$retained" "$official" || return 64
    require_free_bytes before-boot "$run_dir" >"$run_dir/free-space.before-boot.txt" || return 64
    accel_name=${P11SCOPE_SPIKE_ACCEL:-tcg}
    local -a accel
    case "$accel_name" in
        kvm) [[ -w /dev/kvm ]] || return 64; accel=(-accel kvm -cpu host) ;;
        tcg) accel=(-accel tcg,thread=multi -cpu max) ;;
        *) return 64 ;;
    esac
    printf 'accel=%s\n' "$accel_name" >"$run_dir/host-accel.txt" || return 64
    PRIVATE_RUN_DIR=$run_dir
    PRIVATE_RETAINED=$retained
    PRIVATE_OFFICIAL=$official
    PRIVATE_PORT=$port
    PRIVATE_FINGERPRINT=$fingerprint
    PRIVATE_KNOWN_HOSTS=$run_dir/known_hosts
    PRIVATE_LANE_OWNED=1
    boot_start=$(date +%s.%N)
    qemu-system-x86_64 "${accel[@]}" -machine q35 -m 1024 -smp 2 \
        -drive "file=$run_dir/runtime.qcow2,if=virtio,format=qcow2" \
        -netdev "user,id=n1,hostfwd=tcp:127.0.0.1:$port-:22" \
        -device virtio-net-pci,netdev=n1 -display none -serial "file:$run_dir/runtime.serial.log" \
        -no-reboot -daemonize -pidfile "$run_dir/qemu.pid" || return 64
    PRIVATE_QEMU_PID=$(cat "$run_dir/qemu.pid") || return 64
    [[ $PRIVATE_QEMU_PID =~ ^[0-9]+$ ]] || return 64
    private_recover_qemu_pid || return 64
    chmod 0600 "$run_dir/runtime.serial.log" || return 64
    ps -ww -p "$PRIVATE_QEMU_PID" -o pid=,args= >"$run_dir/qemu.argv.txt" || return 64
    local attempt
    for attempt in $(seq 1 120); do
        if ss -H -ltnp "sport = :$port" | grep -F "pid=$PRIVATE_QEMU_PID," \
            >"$run_dir/listener.txt" 2>"$run_dir/listener.stderr"; then
            break
        fi
        sleep 1
    done
    grep -F "pid=$PRIVATE_QEMU_PID," "$run_dir/listener.txt" >/dev/null || return 64
    for attempt in $(seq 1 120); do
        if ssh-keyscan -T 5 -p "$port" -t ed25519 127.0.0.1 \
            >"$PRIVATE_KNOWN_HOSTS.tmp" 2>"$run_dir/ssh-keyscan.stderr"; then
            mv "$PRIVATE_KNOWN_HOSTS.tmp" "$PRIVATE_KNOWN_HOSTS"
            chmod 0600 "$PRIVATE_KNOWN_HOSTS"
            break
        fi
        sleep 1
    done
    [[ -f $PRIVATE_KNOWN_HOSTS && $(wc -l <"$PRIVATE_KNOWN_HOSTS") == 1 ]] || return 64
    awk '$2 == "ssh-ed25519" { ok=1 } END { exit !ok }' "$PRIVATE_KNOWN_HOSTS" || return 64
    ssh-keygen -lf "$PRIVATE_KNOWN_HOSTS" -E sha256 >"$run_dir/hostkey-fingerprint.txt" || return 64
    grep -F "$fingerprint" "$run_dir/hostkey-fingerprint.txt" >/dev/null || return 64
    for attempt in $(seq 1 120); do
        if strict_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" true \
            >"$run_dir/ssh-ready.stdout" 2>"$run_dir/ssh-ready.stderr"; then
            boot_ok=1
            break
        fi
        sleep 1
    done
    if (( boot_ok )); then
        awk -v s="$boot_start" -v e="$(date +%s.%N)" \
            'BEGIN { printf "boot_to_ssh_s=%.3f\n", e - s }' \
            >"$run_dir/boot-to-ssh.txt"
        return 0
    fi
    return 64
}

private_recover_qemu_pid() {
    local candidate=${PRIVATE_QEMU_PID-} argument expected matched
    local -a command
    if [[ -z $candidate && -n ${PRIVATE_RUN_DIR-} && -r $PRIVATE_RUN_DIR/qemu.pid ]]; then
        candidate=$(<"$PRIVATE_RUN_DIR/qemu.pid") || candidate=
    fi
    PRIVATE_QEMU_PID=
    [[ $candidate =~ ^[0-9]+$ && -r /proc/$candidate/cmdline ]] || return 64
    mapfile -d '' -t command <"/proc/$candidate/cmdline" || return 64
    # A reaped-or-zombie qemu has an empty cmdline; it cannot be confirmed live.
    (( ${#command[@]} > 0 )) || return 64
    [[ ${command[0]##*/} == qemu-system-x86_64 ]] || return 64
    for expected in \
        "file=$PRIVATE_RUN_DIR/runtime.qcow2,if=virtio,format=qcow2" \
        "user,id=n1,hostfwd=tcp:127.0.0.1:$PRIVATE_PORT-:22" \
        "file:$PRIVATE_RUN_DIR/runtime.serial.log" "$PRIVATE_RUN_DIR/qemu.pid"; do
        matched=0
        for argument in "${command[@]}"; do
            [[ $argument != "$expected" ]] || matched=1
        done
        (( matched == 1 )) || return 64
    done
    PRIVATE_QEMU_PID=$candidate
}

private_qemu_exited() {
    local candidate=$1 state
    [[ ! -r /proc/$candidate/stat ]] && return 0
    state=$(awk '{print $3}' "/proc/$candidate/stat" 2>/dev/null) || {
        [[ ! -r /proc/$candidate/stat ]]
        return
    }
    [[ $state == Z ]]
}

private_cleanup_lane() {
    local rc
    [[ ${PRIVATE_LANE_OWNED-0} == 1 ]] || { [[ ${PRIVATE_LANE_INTERRUPTED-0} != 1 ]] && return 0 || return 64; }
    if [[ ${PRIVATE_LANE_CLEANUP-idle} == done ]]; then
        return "${PRIVATE_FINISH_RC-0}"
    fi
    [[ ${PRIVATE_LANE_CLEANUP-idle} == idle ]] || return 64
    PRIVATE_LANE_CLEANUP=running
    if private_finish_lane; then rc=0; else rc=$?; fi
    (( PRIVATE_LANE_INTERRUPTED != 1 )) || rc=64
    PRIVATE_FINISH_RC=$rc
    PRIVATE_LANE_CLEANUP=done
    PRIVATE_LANE_OWNED=0
    return "$rc"
}

private_lane_trap() {
    local signal=$1
    if [[ $signal != EXIT && ${PRIVATE_LANE_CLEANUP-idle} == running ]]; then
        PRIVATE_LANE_INTERRUPTED=1
        return 0
    fi
    private_cleanup_lane || true
    if [[ $signal != EXIT ]]; then
        trap - EXIT INT TERM
        exit 64
    fi
}

private_arm_lane_traps() {
    trap 'private_lane_trap EXIT' EXIT
    trap 'private_lane_trap INT' INT
    trap 'private_lane_trap TERM' TERM
}

private_disarm_lane_traps() {
    trap - EXIT INT TERM
}

private_finish_lane() {
    local shutdown_rc=0 post_rc=0 forced=0 unexpected_exit=0 attempt candidate wait_rc=0
    if [[ ${PRIVATE_LANE_OWNED-0} == 1 ]] && ! private_recover_qemu_pid; then
        post_rc=64
    fi
    if [[ -n ${PRIVATE_QEMU_PID-} && -r /proc/$PRIVATE_QEMU_PID/stat ]]; then
        strict_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" sudo -n shutdown -h now \
            >"$PRIVATE_RUN_DIR/shutdown.stdout" 2>"$PRIVATE_RUN_DIR/shutdown.stderr" || shutdown_rc=$?
        printf '%s\n' "$shutdown_rc" >"$PRIVATE_RUN_DIR/shutdown.status" || post_rc=64
        for attempt in $(seq 1 120); do
            if [[ ! -r /proc/$PRIVATE_QEMU_PID/stat ]]; then
                PRIVATE_QEMU_PID=
                break
            fi
            # An exited-but-unreaped qemu is a zombie with empty cmdline; treat it as gone
            # instead of crashing private_recover_qemu_pid on its empty argv.
            if [[ $(awk '{print $3}' /proc/$PRIVATE_QEMU_PID/stat 2>/dev/null) == Z ]]; then
                PRIVATE_QEMU_PID=
                break
            fi
            candidate=$PRIVATE_QEMU_PID
            if ! private_recover_qemu_pid; then
                private_qemu_exited "$candidate" && PRIVATE_QEMU_PID= || wait_rc=64
                break
            fi
            sleep 1
        done
        (( wait_rc == 0 )) || post_rc=64
        if [[ -n $PRIVATE_QEMU_PID && -r /proc/$PRIVATE_QEMU_PID/stat ]]; then
            if ! private_recover_qemu_pid; then
                post_rc=64
            elif ! kill "$PRIVATE_QEMU_PID"; then
                post_rc=64
            else
                forced=1
            fi
            for attempt in $(seq 1 10); do
                [[ -n $PRIVATE_QEMU_PID ]] || break
                if [[ ! -r /proc/$PRIVATE_QEMU_PID/stat ]]; then
                    PRIVATE_QEMU_PID=
                    break
                fi
                if [[ $(awk '{print $3}' /proc/$PRIVATE_QEMU_PID/stat 2>/dev/null) == Z ]]; then
                    PRIVATE_QEMU_PID=
                    break
                fi
                candidate=$PRIVATE_QEMU_PID
                if ! private_recover_qemu_pid; then
                    private_qemu_exited "$candidate" && PRIVATE_QEMU_PID= || post_rc=64
                    break
                fi
                sleep 1
            done
            [[ -z $PRIVATE_QEMU_PID || ! -r /proc/$PRIVATE_QEMU_PID/stat ]] || post_rc=64
        fi
    elif [[ -n ${PRIVATE_QEMU_PID-} ]]; then
        unexpected_exit=1
    fi
    qemu-img check "$PRIVATE_RUN_DIR/runtime.qcow2" \
        >"$PRIVATE_RUN_DIR/qemu-img-check.stdout" 2>"$PRIVATE_RUN_DIR/qemu-img-check.stderr" || post_rc=64
    qemu-img info --backing-chain --output=json "$PRIVATE_RUN_DIR/runtime.qcow2" \
        >"$PRIVATE_RUN_DIR/backing-chain.after.json" || post_rc=64
    validate_backing_chain_file "$PRIVATE_RUN_DIR/backing-chain.after.json" \
        "$PRIVATE_RUN_DIR/runtime.qcow2" "$PRIVATE_RETAINED" "$PRIVATE_OFFICIAL" || post_rc=64
    [[ $(stat -c '%a' "$PRIVATE_RETAINED") == 444 ]] || post_rc=64
    sha256sum "$PRIVATE_RETAINED" >"$PRIVATE_RUN_DIR/retained.after.sha256" || post_rc=64
    cmp "$PRIVATE_RUN_DIR/retained.before.sha256" "$PRIVATE_RUN_DIR/retained.after.sha256" || post_rc=64
    require_free_bytes after-shutdown "$PRIVATE_RUN_DIR" >"$PRIVATE_RUN_DIR/free-space.after-shutdown.txt" || post_rc=64
    ss -H -ltn "sport = :$PRIVATE_PORT" >"$PRIVATE_RUN_DIR/listener.after.txt" || post_rc=64
    [[ ! -s $PRIVATE_RUN_DIR/listener.after.txt ]] || post_rc=64
    grep -F 'reboot: Power down' "$PRIVATE_RUN_DIR/runtime.serial.log" \
        >"$PRIVATE_RUN_DIR/power-down.txt" || post_rc=64
    (( (shutdown_rc == 0 || shutdown_rc == 255) && post_rc == 0 && forced == 0 && unexpected_exit == 0 )) || return 64
}

quiesce_gate_runner() {
    local known_hosts=$1 port=$2 runner=$3
    strict_ssh "$known_hosts" "$port" \
        "sudo -n timeout --signal=TERM --kill-after=5s 15s sh -c 'for process in /proc/[0-9]*; do test \"\$(readlink \"\$process/exe\" 2>/dev/null)\" = \"\$1\" || continue; kill -TERM \"\${process##*/}\" 2>/dev/null || :; done; while :; do found=0; for process in /proc/[0-9]*; do test \"\$(readlink \"\$process/exe\" 2>/dev/null)\" = \"\$1\" || continue; found=1; done; test \"\$found\" -eq 0 && exit 0; sleep 1; done' sh $runner"
}

validate_execution_bundle() {
    local bundle=$1 name
    [[ -d $bundle && ! -L $bundle ]] || return 64
    [[ $(find "$bundle" -mindepth 1 -maxdepth 1 -printf . | wc -c) == 6 ]] || return 64
    for name in source-elf.manifest build-evidence.txt execution.manifest \
        slice1b2-loader-bpf slice1b2-fixture slice1b2-runner; do
        [[ -f $bundle/$name && ! -L $bundle/$name ]] || return 64
    done
    python3 - "$bundle" <<'PY'
import hashlib, json, os, sys
bundle = sys.argv[1]
def digest(name):
    with open(os.path.join(bundle, name), "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()
with open(os.path.join(bundle, "source-elf.manifest"), encoding="utf-8") as stream:
    source = json.load(stream)
with open(os.path.join(bundle, "execution.manifest"), encoding="utf-8") as stream:
    execution = json.load(stream)
expected = {
    "source_commit", "source_manifest_sha256", "build_evidence_sha256",
    "bpf_sha256", "runner_sha256", "fixture_sha256",
}
if set(execution) != expected or execution["source_commit"] != source["source_commit"]:
    raise SystemExit(64)
for field, name in {
    "source_manifest_sha256": "source-elf.manifest",
    "build_evidence_sha256": "build-evidence.txt",
    "bpf_sha256": "slice1b2-loader-bpf",
    "runner_sha256": "slice1b2-runner",
    "fixture_sha256": "slice1b2-fixture",
}.items():
    if execution[field] != digest(name):
        raise SystemExit(64)
if execution["bpf_sha256"] != source["bpf_sha256"]:
    raise SystemExit(64)
PY
}

validate_source_inputs() {
    local archive=$1 manifest=$2 expected_manifest_sha=$3 script=$4
    [[ $(sha256sum "$manifest" | awk '{print $1}') == "$expected_manifest_sha" ]] || return 64
    python3 - "$archive" "$manifest" "$script" <<'PY'
import hashlib, json, sys, tarfile
archive, manifest, script = sys.argv[1:]
def digest(data): return hashlib.sha256(data).hexdigest()
with open(manifest, encoding="utf-8") as stream:
    expected = json.load(stream)
with open(archive, "rb") as stream:
    if digest(stream.read()) != expected["source_archive_sha256"]:
        raise SystemExit(64)
seen = {}
with tarfile.open(archive, "r:") as bundle:
    for member in bundle:
        parts = member.name.split("/")
        if member.isdir() and member.name == "source":
            continue
        if not member.name.startswith("source/") or member.name.startswith("/") or any(part in ("", ".", "..") for part in parts[:-1]):
            raise SystemExit(64)
        if member.isdir(): continue
        if member.isreg():
            data, kind = bundle.extractfile(member).read(), "regular"
            mode = 0o100755 if member.mode & 0o111 else 0o100644
        elif member.issym():
            data, kind, mode = member.linkname.encode(), "symlink", 0o120000
        else: raise SystemExit(64)
        if member.name in seen: raise SystemExit(64)
        seen[member.name] = {"path": member.name, "git_mode": mode, "type": kind, "sha256": digest(data)}
if seen != {member["path"]: member for member in expected["members"]}:
    raise SystemExit(64)
with open(script, "rb") as stream:
    if digest(stream.read()) != seen["source/spike/slice1b2-loader-host/run.sh"]["sha256"]:
        raise SystemExit(64)
PY
}

loader_lane() {
    local lane=$1 bundle=$2 run_dir=$3 export_dir=$4
    local remote=/var/tmp/p11scope-slice1b2-loader/bundle
    local loader_out=/var/tmp/p11scope-slice1b2-loader/loader
    local lane_rc=64 finish_rc=0 rc=0 name remote_command
    [[ ! -e $run_dir && ! -L $run_dir && ! -e $export_dir && ! -L $export_dir ]] || {
        printf 'loader-lane requires new run and export directories\n' >&2
        return 64
    }
    validate_execution_bundle "$bundle" || return
    exec {lifecycle_lock}>/tmp/p11scope-slice1b2-spike-vm.lock
    flock -n "$lifecycle_lock" || return 64
    PRIVATE_QEMU_PID=
    PRIVATE_LANE_OWNED=0
    PRIVATE_LANE_CLEANUP=idle
    PRIVATE_LANE_INTERRUPTED=0
    PRIVATE_FINISH_RC=0
    private_arm_lane_traps
    private_start_lane "$lane" "$run_dir" || {
        private_cleanup_lane || true
        private_disarm_lane_traps
        return 64
    }
    strict_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" \
        "test ! -e /var/tmp/p11scope-slice1b2-loader && mkdir -m 0700 /var/tmp/p11scope-slice1b2-loader && mkdir -m 0700 $remote" \
        >"$run_dir/bundle-mkdir.stdout" 2>"$run_dir/bundle-mkdir.stderr" || rc=64
    if (( rc == 0 )); then
        local -a scp
        mapfile -d '' -t scp < <(scp_argv "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT")
        for name in source-elf.manifest build-evidence.txt execution.manifest \
            slice1b2-loader-bpf slice1b2-fixture slice1b2-runner; do
            timeout 120s "${scp[@]}" "$bundle/$name" "p11scope@127.0.0.1:$remote/$name" \
                >>"$run_dir/scp.stdout" 2>>"$run_dir/scp.stderr" || rc=64
        done
    fi
    (cd "$bundle" && sha256sum source-elf.manifest build-evidence.txt execution.manifest \
        slice1b2-loader-bpf slice1b2-fixture slice1b2-runner) >"$run_dir/bundle.host.sha256"
    if (( rc == 0 )); then
        strict_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" \
            "cd $remote && sha256sum source-elf.manifest build-evidence.txt execution.manifest slice1b2-loader-bpf slice1b2-fixture slice1b2-runner" \
            >"$run_dir/bundle.guest.sha256" 2>"$run_dir/bundle-hash.stderr" || rc=64
        cmp "$run_dir/bundle.host.sha256" "$run_dir/bundle.guest.sha256" || rc=64
    fi
    if (( rc == 0 )); then
        strict_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" 'systemd-detect-virt; uname -r' \
            >"$run_dir/virt.txt" 2>&1 || rc=64
    fi
    if (( rc == 0 )); then
        remote_command="$remote/slice1b2-runner --self-check"
        strict_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" "$remote_command" \
            >"$run_dir/self-check.stdout" 2>"$run_dir/self-check.stderr" || rc=64
    fi
    if (( rc == 0 )); then
        remote_command="sudo -n timeout --signal=TERM --kill-after=5s 600s $remote/slice1b2-runner loader-diag $remote/slice1b2-loader-bpf /var/tmp/p11scope-slice1b2-loader/diag"
        local -a ssh_diag
        mapfile -d '' -t ssh_diag < <(ssh_argv "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT")
        if timeout 660s "${ssh_diag[@]}" p11scope@127.0.0.1 "$remote_command" \
            >"$run_dir/loader-diag.stdout" 2>"$run_dir/loader-diag.stderr"; then
            printf 'PASS\n' >"$run_dir/loader-diag.outcome"
        else
            rc=$?
            printf 'FAIL(%s)\n' "$rc" >"$run_dir/loader-diag.outcome"
            (( rc == 1 )) || rc=64
        fi
    fi
    if (( rc == 0 )); then
        remote_command="sudo -n taskset -c 0 timeout --signal=TERM --kill-after=5s 300s $remote/slice1b2-runner loader-hit --source-manifest $remote/source-elf.manifest --build-evidence $remote/build-evidence.txt --execution-manifest $remote/execution.manifest --bpf $remote/slice1b2-loader-bpf --fixture $remote/slice1b2-fixture --out $loader_out"
        if gate_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" "$remote_command" \
            >"$run_dir/loader-hit.stdout" 2>"$run_dir/loader-hit.stderr"; then
            rc=0
        else
            rc=$?
        fi
        printf '%s\n' "$rc" >"$run_dir/loader-hit.status"
        case "$rc" in
            0|1)
                # Preserve the raw guest evidence before export validation can
                # fail the lane: a later export or validator failure must never
                # destroy the facts it rejected.
                local -a guest_files
                mapfile -t guest_files < <(fixed_inventory)
                gate_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" \
                    "sudo -n tar --format=posix --no-recursion -C $loader_out -cf - ${guest_files[*]}" \
                    >"$run_dir/guest-evidence.tar" 2>"$run_dir/guest-evidence.stderr" || {
                    rm -f "$run_dir/guest-evidence.tar"
                }
                lane_rc=$rc
                export_evidence "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" "$loader_out" "$export_dir" "$lane_rc" \
                    >"$run_dir/export.stdout" 2>"$run_dir/export.stderr" || rc=64
                if (( rc == 0 || rc == 1 )); then
                    validate_local_export "$export_dir" "$lane_rc" || rc=64
                fi
                if (( rc == 0 || rc == 1 )); then
                    if (( lane_rc == 0 )); then
                        printf 'PASS\n' >"$run_dir/loader.outcome"
                    else
                        printf 'FAIL\n' >"$run_dir/loader.outcome"
                    fi
                fi
                (( rc == 0 || rc == 1 )) || lane_rc=64
                ;;
            124)
                if quiesce_gate_runner "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" \
                    "$remote/slice1b2-runner" >"$run_dir/quiesce.stdout" 2>"$run_dir/quiesce.stderr"; then
                    printf 'TIMEOUT\n' >"$run_dir/loader.outcome"
                    lane_rc=2
                else
                    rc=64
                fi
                ;;
            *)
                rc=64
                ;;
        esac
    fi
    if (( rc == 0 || rc == 1 || rc == 124 )); then
        local -a scp
        mapfile -d '' -t scp < <(scp_argv "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT")
        timeout 120s "${scp[@]}" \
            "p11scope@127.0.0.1:/var/tmp/p11scope-slice1b2-loader/diag/diag.jsonl" \
            "$run_dir/diag.jsonl" >/dev/null 2>&1 || true
    fi
    private_cleanup_lane || finish_rc=$?
    private_disarm_lane_traps
    (( finish_rc == 0 )) || return 64
    (( rc == 0 || rc == 1 || rc == 124 )) || return 64
    return "$lane_rc"
}

build_bpf() {
    local output=$1 here root object rustc_verbose objdump_bin cmpxchg_count
    [[ ! -e $output && ! -L $output ]] || {
        printf 'build-bpf requires a new output directory\n' >&2
        return 64
    }
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    root=$(cd "$here/.." && pwd)
    [[ -z $(git -C "$root" status --porcelain --untracked-files=all) ]] || {
        printf 'build-bpf requires clean HEAD\n' >&2
        return 64
    }
    rustc_verbose=$(rustc +nightly --version --verbose)
    grep -Fx 'rustc 1.97.0-nightly (e50aa6fba 2026-05-19)' <<<"$rustc_verbose" >/dev/null
    grep -Fx 'commit-hash: e50aa6fba4e63ab34c72bf9acfd2c307c1155d1a' <<<"$rustc_verbose" >/dev/null
    grep -Fx 'LLVM version: 22.1.4' <<<"$rustc_verbose" >/dev/null
    rustup component list --toolchain nightly --installed | grep -Fx rust-src >/dev/null
    umask 077
    mkdir -m 0700 "$output"
    git -C "$root" archive --format=tar --prefix=source/ HEAD >"$output/source.tar"
    cargo +nightly build --manifest-path "$here/slice1b2-loader-bpf/Cargo.toml" --locked --release \
        --target bpfel-unknown-none -Z build-std=core \
        >"$output/bpf-build.stdout" 2>"$output/bpf-build.stderr"
    object=$here/slice1b2-loader-bpf/target/bpfel-unknown-none/release/slice1b2-loader-bpf
    install -m 0600 "$object" "$output/slice1b2-loader-bpf"
    objdump_bin=$(rustc +nightly --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump
    python3 "$here/slice1b2-loader-bpf/check-init-shape.py" "$output/slice1b2-loader-bpf" "$objdump_bin" || return 64
    cmpxchg_count=$("$objdump_bin" -d "$output/slice1b2-loader-bpf" | grep -c cmpxchg_64 || true)
    if [[ $cmpxchg_count != 1 ]]; then
        printf 'dl_debug_state must contain exactly one cmpxchg_64 (found %s)\n' "$cmpxchg_count" >&2
        return 64
    fi
    printf '%s\n' "$rustc_verbose" >"$output/nightly.txt"
    python3 - "$output/source.tar" "$output/slice1b2-loader-bpf" \
        "$(git -C "$root" rev-parse HEAD)" "$output/source-elf.manifest" <<'PY'
import hashlib, json, sys, tarfile
archive, bpf, commit, output = sys.argv[1:]
def digest(data): return hashlib.sha256(data).hexdigest()
with open(archive, "rb") as stream:
    archive_digest = digest(stream.read())
members = []
with tarfile.open(archive, "r:") as bundle:
    for member in bundle:
        parts = member.name.split("/")
        if member.isdir() and member.name == "source":
            continue
        if not member.name.startswith("source/") or member.name.startswith("/") or any(part in ("", ".", "..") for part in parts[:-1]):
            raise SystemExit(64)
        if member.isdir():
            continue
        if member.isreg():
            data = bundle.extractfile(member).read()
            kind = "regular"
            mode = 0o100755 if member.mode & 0o111 else 0o100644
        elif member.issym():
            data = member.linkname.encode()
            kind = "symlink"
            mode = 0o120000
        else:
            raise SystemExit(64)
        members.append({"path": member.name, "git_mode": mode, "type": kind, "sha256": digest(data)})
if not members or len({member["path"] for member in members}) != len(members):
    raise SystemExit(64)
with open(bpf, "rb") as stream:
    bpf_digest = digest(stream.read())
value = {
    "source_commit": commit,
    "source_archive_sha256": archive_digest,
    "bpf_sha256": bpf_digest,
    "members": sorted(members, key=lambda member: member["path"]),
    "nightly_commit": "e50aa6fba4e63ab34c72bf9acfd2c307c1155d1a",
    "llvm_version": "22.1.4",
}
with open(output, "x", encoding="utf-8") as stream:
    json.dump(value, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
PY
    chmod 0400 "$output/source-elf.manifest"
    chmod 0400 "$output/source.tar"
    sha256sum "$output/source.tar" "$output/source-elf.manifest" \
        "$output/slice1b2-loader-bpf" >"$output/source-bundle.sha256"
}

build_fixture() {
    local output=$1 here target disassembly
    umask 077
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    [[ ! -e $output && ! -L $output ]] || return 64
    gcc -std=c11 -O2 -Wall -Wextra -Werror -pthread -fno-lto -Wl,--export-dynamic \
        -o "$output" "$here/fixture.c"
    disassembly=$(objdump -dr "$output")
    for target in spike_loader_negative_hook; do
        nm -D "$output" | awk -v target="$target" '$3 == target { found=1 } END { exit !found }'
        grep -E "call(q)?[[:space:]].*<$target(@plt)?>" <<<"$disassembly" >/dev/null
    done
    "$output" --self-check
}

freeze_execution() {
    local source_dir=$1 build_dir=$2 bundle=$3
    [[ ! -e $bundle && ! -L $bundle ]] || {
        printf 'freeze-execution requires a new bundle directory\n' >&2
        return 64
    }
    local source_manifest=$source_dir/source-elf.manifest bpf=$source_dir/slice1b2-loader-bpf
    local evidence=$build_dir/build-evidence.txt runner=$build_dir/slice1b2-runner
    local fixture=$build_dir/slice1b2-fixture
    local name
    for name in "$source_manifest" "$bpf" "$evidence" "$runner" "$fixture"; do
        [[ -f $name && ! -L $name ]] || return 64
    done
    umask 077
    mkdir -m 0700 "$bundle"
    install -m 0400 "$source_manifest" "$bundle/source-elf.manifest"
    install -m 0400 "$evidence" "$bundle/build-evidence.txt"
    install -m 0500 "$bpf" "$bundle/slice1b2-loader-bpf"
    install -m 0500 "$runner" "$bundle/slice1b2-runner"
    install -m 0500 "$fixture" "$bundle/slice1b2-fixture"
    python3 - "$bundle" <<'PY'
import hashlib, json, os, sys
bundle = sys.argv[1]
def file_hash(name):
    with open(os.path.join(bundle, name), "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()
with open(os.path.join(bundle, "source-elf.manifest"), encoding="utf-8") as stream:
    source = json.load(stream)
value = {
    "source_commit": source["source_commit"],
    "source_manifest_sha256": file_hash("source-elf.manifest"),
    "build_evidence_sha256": file_hash("build-evidence.txt"),
    "bpf_sha256": file_hash("slice1b2-loader-bpf"),
    "runner_sha256": file_hash("slice1b2-runner"),
    "fixture_sha256": file_hash("slice1b2-fixture"),
}
if value["bpf_sha256"] != source["bpf_sha256"]:
    raise SystemExit(64)
with open(os.path.join(bundle, "execution.manifest"), "x", encoding="utf-8") as stream:
    json.dump(value, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
PY
    chmod 0400 "$bundle/execution.manifest"
    [[ $(find "$bundle" -mindepth 1 -maxdepth 1 -printf . | wc -c) == 6 ]]
}

provision_guest() {
    local archive=$1 manifest=$2 expected_manifest_sha=$3 rustup_binary=$4 output=$5
    local source_root=/var/tmp/slice1b2-source toolchain=/var/tmp/slice1b2-toolchain
    local rustup_home=/var/tmp/slice1b2-rustup-home cargo_home=/var/tmp/slice1b2-cargo-home
    local repo=$source_root/source host_manifest lock_before lock_after
    local ebpf_lock_before ebpf_lock_after extracted_inventory
    local toolchain_bin
    umask 077
    [[ $(sha256sum "$manifest" | awk '{print $1}') == "$expected_manifest_sha" ]] || return 64
    [[ $(sha256sum "$rustup_binary" | awk '{print $1}') == 4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10 ]] || return 64
    [[ ! -e $source_root && ! -L $source_root && ! -e $toolchain && ! -L $toolchain && ! -e $output && ! -L $output ]] || return 64
    mkdir -m 0700 "$source_root"
    extracted_inventory=$(python3 - "$archive" "$manifest" "$source_root" <<'PY'
import hashlib, json, os, stat, sys, tarfile
archive, manifest, destination = sys.argv[1:]
def digest(data): return hashlib.sha256(data).hexdigest()
with open(manifest, encoding="utf-8") as stream:
    expected = json.load(stream)
with open(archive, "rb") as stream:
    if digest(stream.read()) != expected["source_archive_sha256"]:
        raise SystemExit(64)
seen = {}
with tarfile.open(archive, "r:") as bundle:
    for member in bundle:
        parts = member.name.split("/")
        if member.isdir() and member.name == "source":
            continue
        if not member.name.startswith("source/") or member.name.startswith("/") or any(part in ("", ".", "..") for part in parts[:-1]):
            raise SystemExit(64)
        if member.isdir():
            continue
        if member.isreg():
            data = bundle.extractfile(member).read()
            kind = "regular"
            mode = 0o100755 if member.mode & 0o111 else 0o100644
        elif member.issym():
            target_parts = member.linkname.split("/")
            if member.linkname.startswith("/") or any(part in ("", ".", "..") for part in target_parts):
                raise SystemExit(64)
            data = member.linkname.encode()
            kind = "symlink"
            mode = 0o120000
        else:
            raise SystemExit(64)
        if member.name in seen:
            raise SystemExit(64)
        seen[member.name] = {"path": member.name, "git_mode": mode, "type": kind, "sha256": digest(data)}
    expected_members = {member["path"]: member for member in expected["members"]}
    if seen != expected_members:
        raise SystemExit(64)
    bundle.extractall(destination)
actual = {}
for root, dirs, files in os.walk(os.path.join(destination, "source"), followlinks=False):
    for name in files:
        path = os.path.join(root, name)
        relative = os.path.relpath(path, destination)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            data = os.readlink(path).encode()
            kind, mode = "symlink", 0o120000
        elif stat.S_ISREG(info.st_mode):
            with open(path, "rb") as stream: data = stream.read()
            kind = "regular"
            mode = 0o100755 if info.st_mode & 0o111 else 0o100644
        else:
            raise SystemExit(64)
        actual[relative] = {"path": relative, "git_mode": mode, "type": kind, "sha256": digest(data)}
if actual != expected_members:
    raise SystemExit(64)
canonical = json.dumps([actual[name] for name in sorted(actual)], sort_keys=True, separators=(",", ":"))
print(digest(canonical.encode()))
PY
    ) || return 64
    reject_inherited_overrides || return
    provision_preflight "$rustup_home" "$cargo_home"
    mkdir -m 0700 "$toolchain"
    install -m 0700 "$rustup_binary" "$toolchain/rustup"
    mkdir -m 0700 "$output"
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update \
        >"$output/apt-update.stdout" 2>"$output/apt-update.stderr"
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        gcc libc6-dev binutils ca-certificates \
        >"$output/apt-install.stdout" 2>"$output/apt-install.stderr"
    "$toolchain/rustup" toolchain install 1.88.0 --profile minimal --no-self-update \
        >"$output/rustup.stdout" 2>"$output/rustup.stderr"
    toolchain_bin=$RUSTUP_HOME/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin
    [[ -x $toolchain_bin/rustc && -x $toolchain_bin/cargo ]]
    export PATH=$toolchain_bin:$PATH
    "$toolchain/rustup" run 1.88.0 rustc --version --verbose >"$output/rustc.txt"
    "$toolchain/rustup" run 1.88.0 cargo --version --verbose >"$output/cargo.txt"
    grep -Fx 'rustc 1.88.0 (6b00bc388 2025-06-23)' "$output/rustc.txt" >/dev/null
    grep -Fx 'cargo 1.88.0 (873a06493 2025-05-10)' "$output/cargo.txt" >/dev/null
    grep -Fx 'host: x86_64-unknown-linux-gnu' "$output/rustc.txt" >/dev/null
    [[ $(getconf GNU_LIBC_VERSION) == 'glibc 2.35' ]]
    lock_before=$(sha256sum "$repo/spike/slice1b2-loader-host/Cargo.lock" | awk '{print $1}')
    ebpf_lock_before=$(sha256sum "$repo/spike/slice1b2-loader-bpf/Cargo.lock" | awk '{print $1}')
    "$toolchain/rustup" run 1.88.0 cargo fetch \
        --manifest-path "$repo/spike/slice1b2-loader-host/Cargo.toml" --locked -vv \
        >"$output/cargo-fetch.stdout" 2>"$output/cargo-fetch.stderr"
    export CARGO_NET_OFFLINE=true
    "$toolchain/rustup" run 1.88.0 cargo metadata \
        --manifest-path "$repo/spike/slice1b2-loader-host/Cargo.toml" --locked --format-version 1 \
        >"$output/locked-graph.json"
    "$toolchain/rustup" run 1.88.0 cargo build \
        --manifest-path "$repo/spike/slice1b2-loader-host/Cargo.toml" --locked --offline --release \
        >"$output/cargo-build.stdout" 2>"$output/cargo-build.stderr"
    "$toolchain/rustup" run 1.88.0 cargo test \
        --manifest-path "$repo/spike/slice1b2-loader-host/Cargo.toml" --locked --offline \
        >"$output/cargo-test.stdout" 2>"$output/cargo-test.stderr"
    "$repo/spike/slice1b2-loader-host/run.sh" build-fixture "$output/slice1b2-fixture" \
        >"$output/fixture.stdout" 2>"$output/fixture.stderr"
    install -m 0700 "$repo/spike/slice1b2-loader-host/target/release/slice1b2-loader-host" \
        "$output/slice1b2-runner"
    lock_after=$(sha256sum "$repo/spike/slice1b2-loader-host/Cargo.lock" | awk '{print $1}')
    ebpf_lock_after=$(sha256sum "$repo/spike/slice1b2-loader-bpf/Cargo.lock" | awk '{print $1}')
    [[ $lock_before == "$lock_after" && $ebpf_lock_before == "$ebpf_lock_after" ]]
    readelf --version-info "$output/slice1b2-runner" >"$output/runner-version-info.txt"
    readelf --version-info "$output/slice1b2-fixture" >"$output/fixture-version-info.txt"
    find "$CARGO_HOME/registry/cache" -type f -print0 2>/dev/null \
        | sort -z | xargs -0 -r sha256sum >"$output/cargo-cache.sha256"
    find "$CARGO_HOME/registry/src" -type f -print0 2>/dev/null \
        | sort -z | xargs -0 -r sha256sum >"$output/cargo-sources.sha256"
    host_manifest=$(sha256sum "$manifest" | awk '{print $1}')
    {
        printf 'source_manifest_sha256=%s\n' "$host_manifest"
        printf 'source_archive_sha256=%s\n' "$(sha256sum "$archive" | awk '{print $1}')"
        printf 'extracted_inventory_sha256=%s\n' "$extracted_inventory"
        printf 'host_lock_before_sha256=%s\n' "$lock_before"
        printf 'host_lock_after_sha256=%s\n' "$lock_after"
        printf 'ebpf_lock_before_sha256=%s\n' "$ebpf_lock_before"
        printf 'ebpf_lock_after_sha256=%s\n' "$ebpf_lock_after"
        printf 'locked_graph_sha256=%s\n' "$(sha256sum "$output/locked-graph.json" | awk '{print $1}')"
        printf 'cargo_fetch_stdout_sha256=%s\n' "$(sha256sum "$output/cargo-fetch.stdout" | awk '{print $1}')"
        printf 'cargo_fetch_stderr_sha256=%s\n' "$(sha256sum "$output/cargo-fetch.stderr" | awk '{print $1}')"
        printf 'cargo_cache_inventory_sha256=%s\n' "$(sha256sum "$output/cargo-cache.sha256" | awk '{print $1}')"
        printf 'cargo_sources_inventory_sha256=%s\n' "$(sha256sum "$output/cargo-sources.sha256" | awk '{print $1}')"
        printf 'runner_sha256=%s\n' "$(sha256sum "$output/slice1b2-runner" | awk '{print $1}')"
        printf 'fixture_sha256=%s\n' "$(sha256sum "$output/slice1b2-fixture" | awk '{print $1}')"
        printf 'apt_update_status=0\napt_install_status=0\nrustup_status=0\n'
        printf 'cargo_fetch_status=0\ncargo_metadata_status=0\ncargo_build_status=0\n'
        printf 'cargo_test_status=0\nfixture_build_and_self_check_status=0\n'
        getconf GNU_LIBC_VERSION
        cat "$output/rustc.txt" "$output/cargo.txt"
        gcc --version | head -n 1
        ld --version | head -n 1
        dpkg-query -W -f='${Package}\t${Version}\n' gcc libc6-dev binutils ca-certificates
        find /var/lib/apt/lists -maxdepth 1 -type f -readable ! -name lock -print0 \
            | sort -z | xargs -0 sha256sum
        cat "$output/cargo-cache.sha256" "$output/cargo-sources.sha256"
        cat "$output/runner-version-info.txt" "$output/fixture-version-info.txt"
    } >"$output/build-evidence.txt"
    chmod 0600 "$output/build-evidence.txt" "$output/slice1b2-runner" "$output/slice1b2-fixture"
}

provision_jammy() {
    local archive=$1 manifest=$2 expected_manifest_sha=$3 run_dir=$4 build_out=$5
    local input=/var/tmp/slice1b2-input remote_out=/var/tmp/slice1b2-build finish_rc=0 rc=0 name
    [[ ! -e $run_dir && ! -L $run_dir && ! -e $build_out && ! -L $build_out ]] || return 64
    [[ -f $archive && ! -L $archive && -f $manifest && ! -L $manifest ]] || return 64
    validate_source_inputs "$archive" "$manifest" "$expected_manifest_sha" "${BASH_SOURCE[0]}" || return 64
    [[ $(sha256sum "$(command -v rustup)" | awk '{print $1}') == 4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10 ]] || return 64
    exec {lifecycle_lock}>/tmp/p11scope-slice1b2-spike-vm.lock
    flock -n "$lifecycle_lock" || return 64
    PRIVATE_QEMU_PID=
    PRIVATE_LANE_OWNED=0
    PRIVATE_LANE_CLEANUP=idle
    PRIVATE_LANE_INTERRUPTED=0
    PRIVATE_FINISH_RC=0
    private_arm_lane_traps
    private_start_lane jammy "$run_dir" || {
        private_cleanup_lane || true
        private_disarm_lane_traps
        return 64
    }
    strict_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" \
        "test ! -e $input && mkdir -m 0700 $input" \
        >"$run_dir/input-mkdir.stdout" 2>"$run_dir/input-mkdir.stderr" || rc=64
    if (( rc == 0 )); then
        local -a scp
        mapfile -d '' -t scp < <(scp_argv "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT")
        timeout 120s "${scp[@]}" "$archive" "p11scope@127.0.0.1:$input/source.tar" \
            >"$run_dir/scp-archive.stdout" 2>"$run_dir/scp-archive.stderr" || rc=64
        timeout 120s "${scp[@]}" "$manifest" "p11scope@127.0.0.1:$input/source-elf.manifest" \
            >"$run_dir/scp-manifest.stdout" 2>"$run_dir/scp-manifest.stderr" || rc=64
        timeout 120s "${scp[@]}" "$(command -v rustup)" "p11scope@127.0.0.1:$input/rustup" \
            >"$run_dir/scp-rustup.stdout" 2>"$run_dir/scp-rustup.stderr" || rc=64
        timeout 120s "${scp[@]}" "${BASH_SOURCE[0]}" "p11scope@127.0.0.1:$input/run.sh" \
            >"$run_dir/scp-script.stdout" 2>"$run_dir/scp-script.stderr" || rc=64
    fi
    if (( rc == 0 )); then
        strict_ssh_long "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" \
            "env -i HOME=/home/p11scope USER=p11scope LOGNAME=p11scope PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash $input/run.sh _provision-guest $input/source.tar $input/source-elf.manifest $expected_manifest_sha $input/rustup $remote_out" \
            >"$run_dir/provision.stdout" 2>"$run_dir/provision.stderr" || rc=64
    fi
    if (( rc == 0 )); then
        umask 077
        mkdir -m 0700 "$build_out"
        local -a scp
        mapfile -d '' -t scp < <(scp_argv "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT")
        for name in build-evidence.txt slice1b2-runner slice1b2-fixture; do
            timeout 120s "${scp[@]}" "p11scope@127.0.0.1:$remote_out/$name" "$build_out/$name" \
                >>"$run_dir/scp-build.stdout" 2>>"$run_dir/scp-build.stderr" || rc=64
        done
        chmod 0600 "$build_out"/*
    fi
    private_cleanup_lane || finish_rc=$?
    private_disarm_lane_traps
    (( finish_rc == 0 && rc == 0 )) || return 64
}

run_main() {
    case "${1-}" in
        build-fixture)
            [[ $# == 2 ]] || return 64
            build_fixture "$2"
            ;;
        build-bpf)
            [[ $# == 2 ]] || return 64
            build_bpf "$2"
            ;;
        freeze-execution)
            [[ $# == 4 ]] || return 64
            freeze_execution "$2" "$3" "$4"
            ;;
        provision-jammy)
            [[ $# == 6 ]] || {
                printf 'provision-jammy arguments\n' >&2
                return 64
            }
            provision_jammy "$2" "$3" "$4" "$5" "$6"
            ;;
        _provision-guest)
            [[ $# == 6 ]] || return 64
            provision_guest "$2" "$3" "$4" "$5" "$6"
            ;;
        loader-lane)
            [[ $# == 5 ]] || return 64
            loader_lane "$2" "$3" "$4" "$5"
            ;;
        *)
            printf 'usage: run.sh {build-fixture OUT|build-bpf NEW_OUT|freeze-execution SOURCE BUILD NEW_BUNDLE|provision-jammy ARCHIVE MANIFEST MANIFEST_SHA NEW_RUN_DIR NEW_BUILD_OUT|loader-lane LANE BUNDLE NEW_RUN_DIR NEW_EXPORT}\n' >&2
            return 64
            ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    run_main "$@"
fi
