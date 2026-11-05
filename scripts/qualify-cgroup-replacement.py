#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fresh installed Cgroup admission after an owned original process group dies.

Run only in the owner's granted live lane. Each backend creates its own cgroup
tree and ordinary callers. This tests a different PID and a fresh observer;
numeric PID reuse and continuous cgroup membership are not asserted.
"""

import argparse
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
MAPPED = runpy.run_path(str(ROOT / "scripts/mapped-provider-pin.py"))
BACKENDS = ("singles", "multi")
FUNCTION, COUNT, RV = "C_GenerateRandom", 5, 0
INITIAL_FUNCTION = "C_GetInfo"
INITIAL_ATTEMPTS, INITIAL_TIMEOUT_NS = 20, 15_000_000_000


def mapped_provider(owner, pin):
    """Match maps to a private read-only calibration of the same held FD."""
    owner.verify()
    held = H6["provider_receipt"](pin)
    with open(f"/proc/{owner.pid}/maps", encoding="utf-8") as stream:
        text = stream.read(MAPPED["MAX_MAPS_BYTES"] + 1)
    if len(text) > MAPPED["MAX_MAPS_BYTES"]:
        raise ValueError("owned caller maps exceeds the bounded limit")
    matching = []
    for line in text.splitlines():
        row = MAPPED["MAPS_LINE"].fullmatch(line)
        if row is None:
            raise ValueError("malformed owned caller maps")
        if ([int(row[5], 16), int(row[6], 16)] == held["dev"]
                and int(row[7]) == held["ino"] and row[3].startswith("r")):
            matching.append(row)
    if not matching:
        raise ValueError("owned caller lacks the independently calibrated held provider mapping")
    pin.verify()
    owner.verify()
    return {"dev": held["dev"], "ino": held["ino"]}


def verify_owner(ctx, owner, expected):
    if (owner not in ctx.owners or not isinstance(owner, H6["OwnedProcess"])
            or owner.popen is None or owner.popen.pid != owner.pid or owner.pidfd is None
            or owner.identity != expected):
        raise ValueError("caller lacks the retained enrolled original owner/birth custody")
    owner.verify()


def capture_original(ctx, owner, image_pin, image, provider_pin):
    verify_owner(ctx, owner, owner.identity)
    image_pin.verify()
    actual = image_pin.image_receipt(image, owner)
    if any(image.get(field) != actual[field] for field in H6["IMAGE_FIELDS"]):
        raise ValueError("original caller image disagrees with held executable custody")
    if os.getpgid(owner.pid) != owner.pid or os.getsid(owner.pid) != owner.pid:
        raise ValueError("original caller is not the owned isolated process group leader")
    return {"original_identity": dict(owner.identity), "original_image": actual,
            "original_mapping": mapped_provider(owner, provider_pin), "original_group": owner.pid}


def kill_original(ctx, owner, image_pin, original):
    verify_owner(ctx, owner, original["original_identity"])
    image_pin.verify()
    actual = image_pin.image_receipt(original["original_image"], owner)
    if actual != original["original_image"] or original["original_group"] != owner.pid:
        raise ValueError("original image/group custody changed before death")
    if os.getpgid(owner.pid) != owner.pid or os.getsid(owner.pid) != owner.pid:
        raise ValueError("refusing to kill a process group outside original custody")
    H6["check_dispatch"]()
    deadline = H6["wait_deadline"](10)
    killed = H6["monotonic_ns"]()
    os.killpg(owner.pid, signal.SIGKILL)
    if not owner.wait_exit(H6["remaining_until"](deadline)):
        raise TimeoutError("original held pidfd did not prove group death")
    rc = H6["wait_process"](owner.popen, H6["remaining_until"](deadline))
    H6["wait_terminal_child"](owner)
    gone = not (Path("/proc") / str(owner.pid)).exists()
    if rc != -signal.SIGKILL or not gone:
        raise ValueError("original owned group was not killed and terminally reaped")
    return {"kill_ns": killed, "death_ns": H6["monotonic_ns"](),
            "original_reaped": True, "original_proc_gone": gone,
            "original_pidfd_exited": True, "original_rc": rc}


def check_replacement(ctx, old, original, death, new, image, image_pin):
    """Keep the dead original pidfd; independently verify only the new owner."""
    if (old not in ctx.owners or old.identity != original["original_identity"]
            or old.pidfd is None or old.popen.returncode != -signal.SIGKILL
            or not death.get("original_reaped") or not death.get("original_proc_gone")
            or not death.get("original_pidfd_exited")
            or (Path("/proc") / str(old.pid)).exists()
            or not old.wait_exit(H6["remaining_seconds"](0.1))):
        raise ValueError("replacement lacks retained original group-death/reap proof")
    if new is old or new.pid == old.pid:
        raise ValueError("fresh replacement requires an independently owned different PID")
    verify_owner(ctx, new, new.identity)
    image_pin.verify()
    actual = image_pin.image_receipt(image, new)
    if any(image.get(field) != actual[field] for field in H6["IMAGE_FIELDS"]):
        raise ValueError("replacement image disagrees with its independent new owner")


def group_receipt(ctx, group):
    if not any(getattr(wrapper, "group", None) is group for wrapper in ctx.groups):
        raise ValueError("selected cgroup descriptor was not created by this controller")
    group.verify()
    held = os.fstat(group.fd)
    return {"path": str(group.path), "dev": held.st_dev, "ino": held.st_ino}


def check_initial_ready(trace, ledger, receipt):
    """Prove an initial owned marker independently of the fixed measured calls."""
    proof = receipt["initial_ready"]
    image = receipt["replacement"]["replacement_image"]
    if type(proof["attempts"]) is not int or not 1 <= proof["attempts"] <= INITIAL_ATTEMPTS:
        raise ValueError("initial readiness attempt count exceeds its fixed bound")
    phases = [f"initial-{seq}" for seq in range(1, proof["attempts"] + 1)]
    calls = [row for row in ledger if row.get("kind") == "call" and row.get("phase", "").startswith("initial-")]
    lines = trace.splitlines()
    cursor, end = proof["output_cursor"], proof["proof_cursor"]
    match = H6["ROW"].fullmatch(lines[end - 1]) if 0 <= cursor < end <= len(lines) else None
    measured_before_proof = any(
        row and int(row["pid"]) == image["pid"] and row["fn"] == FUNCTION
        for line in lines[:end] if (row := H6["ROW"].fullmatch(line)))
    if (proof["proof_kind"] != "trace-row" or proof["image"] != image["image"]
            or proof["pid"] != image["pid"] or proof["marker_fn"] != INITIAL_FUNCTION
            or proof["max_attempts"] != INITIAL_ATTEMPTS
            or proof["phases"] != phases
            or len(calls) != proof["attempts"] or {row["phase"] for row in calls} != set(phases)
            or not receipt["observer_ready_ns"] <= proof["started_ns"] <= proof["observed_ns"]
               <= proof["deadline_ns"] <= min(proof["setup_deadline_ns"], proof["leg_deadline_ns"])
            or not 0 < proof["deadline_ns"] - proof["started_ns"] <= INITIAL_TIMEOUT_NS
            or proof["observed_ns"] > receipt["measured"]["t0"]
            or measured_before_proof
            or any(row["fn"] != INITIAL_FUNCTION or row["rv"] != RV or row["image"] != image["image"]
                   or row["pid"] != image["pid"] or row["tid"] != image["pid"] or row["scope"] != "selected"
                   or not proof["started_ns"] <= row["t0"] <= row["t1"] <= proof["observed_ns"]
                   for row in calls)
            or not set(phases).issubset(receipt["warmup"]["phases"])
            or not match or int(match["pid"]) != image["pid"] or int(match["tid"]) != image["pid"]
            or match["fn"] != INITIAL_FUNCTION or match["rv"] != "CKR_OK" or not match["path"]
            or json.loads(match["path"]) != image["path"]
            or json.loads(match["label"]) != Path(image["path"]).name):
        raise ValueError("invalid bounded initial owned public readiness proof")


def warm_replacement(ctx, io, caller, stdout, capture, group, image, image_pin, provider_mapping, phases):
    """Drive real initial markers inside setup; never renew a successor/leg budget."""
    if ctx.budget.phase != "setup":
        raise ValueError("initial replacement readiness must use the existing setup allowance")
    started = H6["monotonic_ns"]()
    deadline = min(started + INITIAL_TIMEOUT_NS, ctx.budget.phase_deadline_ns, ctx.budget.deadline_ns)
    cursor = len(capture.lines)

    def verify():
        verify_owner(ctx, caller, caller.identity)
        actual = image_pin.image_receipt(image, caller)
        if any(actual[field] != image[field] for field in H6["IMAGE_FIELDS"]):
            raise ValueError("replacement executable changed during initial readiness")
        io.membership(group, caller)
        if mapped_provider(caller, ctx.provider_pin) != provider_mapping:
            raise ValueError("replacement provider changed during initial readiness")

    def fresh_proof():
        for index in range(cursor, len(capture.lines)):
            match = H6["ROW"].fullmatch(capture.lines[index].strip())
            if (match and int(match["pid"]) == caller.pid and int(match["tid"]) == caller.pid
                    and match["fn"] == INITIAL_FUNCTION and match["rv"] == "CKR_OK" and match["path"]
                    and json.loads(match["path"]) == image["path"]
                    and json.loads(match["label"]) == Path(image["path"]).name):
                return index + 1
        return None

    attempts = []
    for seq in range(1, INITIAL_ATTEMPTS + 1):
        H6["remaining_until"](deadline)
        verify()
        phase = f"initial-{seq}"
        io.warm_command(caller, stdout, group, phase, phases, H6["remaining_until"](deadline))
        attempts.append(phase)
        H6["remaining_until"](deadline)
        interval_end = min(deadline, H6["monotonic_ns"]() + 500_000_000)
        try:
            end = H6["_output_wait"](capture, fresh_proof, interval_end)
        except TimeoutError:
            continue
        verify()
        H6["remaining_until"](deadline)
        observed = H6["monotonic_ns"]()
        if not started <= observed <= deadline:
            raise TimeoutError("initial replacement proof completed after its absolute deadline")
        return dict(image=image["image"], pid=caller.pid, proof_kind="trace-row", marker_fn=INITIAL_FUNCTION,
            started_ns=started, observed_ns=observed, deadline_ns=deadline,
            setup_deadline_ns=ctx.budget.phase_deadline_ns, leg_deadline_ns=ctx.budget.deadline_ns,
            attempts=seq, max_attempts=INITIAL_ATTEMPTS, phases=attempts,
            output_cursor=cursor, proof_cursor=end)
    raise TimeoutError("initial replacement warm-up attempt budget exhausted")


def evaluate_replacement(trace, ledger, receipt, file_trace=None):
    """Add independent death/admission checks to the existing H6 call oracle."""
    result = H6["evaluate_trace_h6"](trace, ledger, receipt, file_trace)
    if receipt.get("backend_refused"):
        return result  # Refusal remains a negative, never replacement acceptance.
    errors = result["errors"]
    try:
        proof = receipt["replacement"]
        old, new = proof["original_identity"], proof["replacement_identity"]
        old_image, new_image = proof["original_image"], proof["replacement_image"]
        pin = receipt["executable_pin"]
        if (old["pid"] == new["pid"] or old["ppid"] != new["ppid"]
                or old["uid"] != new["uid"] or proof["original_group"] != old["pid"]
                or not all(proof.get(field) is True for field in
                           ("original_reaped", "original_proc_gone", "original_pidfd_exited"))
                or proof["original_rc"] != -signal.SIGKILL
                or proof["manufactured_reuse"] is not False
                or proof["continuous_membership"] != "unknown"
                or receipt["fresh_observer"] is not True
                or not 0 < proof["kill_ns"] <= proof["death_ns"] <= proof["replacement_spawn_ns"]
                   <= receipt["observer_started_ns"]):
            errors.append("replacement lacks original owned group-death and fresh different-PID admission")
        for identity, image in ((old, old_image), (new, new_image)):
            if (any(type(identity[field]) is not int or identity[field] <= 0
                    for field in ("pid", "ppid", "start_time", "pid_namespace", "time_namespace"))
                    or any(identity[field] != image[field] for field in
                           ("pid", "start_time", "pid_namespace", "time_namespace"))
                    or any(image[field] != pin[field] for field in ("path", "dev", "ino", "mtime_ns"))):
                errors.append("original/replacement image lacks its own birth and the same held executable")
        if receipt["images"] != [new_image] or receipt["owned_pids"] != [new["pid"]]:
            errors.append("replacement capture reused the original PID/image authority")
        check_initial_ready(trace, ledger, receipt)
        provider = receipt["provider_before"]
        expected_mapping = {"dev": provider["dev"], "ino": provider["ino"]}
        if any(proof[field] != expected_mapping for field in ("original_mapping", "replacement_mapping")):
            errors.append("original/replacement mappings differ from the independently held provider")
        root, descendant = proof["root_before"], proof["descendant_before"]
        if (root != proof["root_after"] or descendant != proof["descendant_after"]
                or not Path(descendant["path"]).is_relative_to(Path(root["path"]))
                or descendant["path"] == root["path"]
                or any(type(group[field]) is not int or group[field] <= 0
                       for group in (root, descendant) for field in ("dev", "ino"))
                or proof["membership_before"] != proof["membership_after"]
                or proof["membership_after"] != "/" + str(Path(descendant["path"]).relative_to("/sys/fs/cgroup"))):
            errors.append("replacement lacks the original held cgroup root and selected descendant endpoints")
        argv = receipt["observer_argv"]
        if (len(argv) != 12 or argv[1] != "trace" or argv[2] != "--cgroup"
                or argv[3] != root["path"] or argv[4] != "--module" or argv[5] != provider["path"]
                or argv[6:8] != ["--attach-backend", receipt["requested_backend"]]
                or argv[8:10] != ["--duration", "120s"] or argv[10] != "-o"
                or receipt["scope_kind"] != "cgroup"):
            errors.append("observer did not select the held cgroup and exact requested public backend")
        calls = [row for row in ledger if row.get("kind") == "call" and row.get("phase") == "measured"]
        if len(calls) != COUNT or any(row["fn"] != FUNCTION or row["rv"] != RV
                                      or row["pid"] != new["pid"] or row["scope"] != "selected"
                                      for row in calls):
            errors.append("replacement measured phase differs from the fixed independent function/RV/population")
        # H6 already parses, ledger-matches and checks each published name.
        # This gate additionally requires names for every measured return;
        # unknown warm/early returns keep the shared H6 policy.
        measured_names = result.get("phase_populations", {}).get("measured", {})
        if measured_names.get("named", 0) != COUNT or measured_names.get("unknown", 0):
            errors.append("replacement measured returns lack the correct fresh held executable name")
        for ev in result.get("evidence", []):
            backend = ev.get("attach_backend", {})
            # Classic trace publishes a PID-link filter only for PID scope.
            # Cgroup is selected by the retained root/public argv; do not invent
            # Inventory's separate bpf-cgroup label here.
            if "scope_filter" not in backend or backend["scope_filter"] is not None:
                errors.append("terminal filter evidence differs from the public Cgroup trace contract")
    except (KeyError, TypeError, ValueError) as error:
        errors.append(f"invalid independent replacement proof: {error}")
    result["pass"] = not errors
    result["status"] = "pass" if not errors else "fail"
    return result


def stop_capture(ctx, owner, limit_seconds=H6["OBSERVER_STOP_SECONDS"]):
    verify_owner(ctx, owner, owner.identity)
    if getattr(owner, "replacement_stop_attempted", False):
        raise H6["LegCleanupError"]("replacement observer normal stop already attempted")
    owner.replacement_stop_attempted = True
    try:
        result = H6["stop_observer"](owner, limit_seconds)
        rc, _stopped, latency = result
        if rc != 0 or H6["stop_errors"](H6["stop_receipt"](owner, latency)):
            raise H6["LegCleanupError"]("replacement observer failed its one normal stop")
    except BaseException as error:
        case = getattr(ctx, "case", ctx)
        case.cleanup_failed = True
        case.cleanup_errors.append(f"replacement observer normal stop: {type(error).__name__}: {error}")
        raise
    return result


class LiveIO:
    """The live process/cgroup boundary; tests supply ordinary stand-in children."""
    def create_tree(self, ctx):
        top, _ = H6["create_tracked"](ctx, Path("/sys/fs/cgroup") / f"p11scope-h6-replacement-{uuid.uuid4().hex[:8]}")
        selected, _ = H6["create_tracked"](ctx, top.path / "selected")
        descendant, _ = H6["create_tracked"](ctx, selected.path / "sub")
        return selected, descendant

    def spawn_caller(self, ctx, directory, image_pin, env, tag):
        return H6["spawn_caller"](ctx.owners, ctx.readers, directory, image_pin,
                                 ctx.provider_pin, ctx.args.uid, ctx.args.gid, env, tag=tag)

    def move(self, group, owner):
        H6["check_dispatch"]()
        group.move(owner)
        return self.membership(group, owner)

    def membership(self, group, owner):
        owner.verify()
        group.verify()
        actual = H6["cgroup_of"](owner.pid)
        if actual != "/" + str(group.path.relative_to("/sys/fs/cgroup")):
            raise ValueError("owned caller is outside its selected descendant")
        return actual

    def spawn_observer(self, ctx, directory, argv, env):
        return H6["spawn_observer"](ctx.owners, ctx.readers, directory, argv, env)

    def command(self, caller, reader, group, phases):
        return H6["n3_command"](caller, reader, FUNCTION, COUNT, 100, "measured", "selected",
                                0, group, phases)

    def warm_command(self, caller, reader, group, phase, phases, remaining):
        return H6["n3_command"](caller, reader, INITIAL_FUNCTION, 1, 0, phase, "selected",
                                0, group, phases, acknowledgement_seconds=remaining)


@H6["owned_leg"]
def run_replacement(ctx, directory, backend, env, image_pin, io=None):
    ctx.terminal_budget = ctx.budget  # The final backstop cannot renew this leg's allowance.
    if ctx.cleanup_failed:
        raise H6["LegCleanupError"]("previous owned cleanup/normal stop failure prevents another backend")
    io = io or LiveIO()
    directory = Path(directory)
    directory.mkdir(mode=0o755, parents=True, exist_ok=False)
    if env is None:
        env = H6["init_token"](directory / "workload", ctx.args.uid, ctx.args.gid,
                              f"h6-cgroup-replacement-{backend}")
    image_pin.verify()
    ctx.binary.verify()
    selected, descendant = io.create_tree(ctx)
    root_before, descendant_before = group_receipt(ctx, selected), group_receipt(ctx, descendant)
    original, old_stdout, _ = io.spawn_caller(ctx, directory, image_pin, env, "original")
    old_stdout.record("ready", 0, seconds=H6["remaining_seconds"](10))
    old_image = image_pin.image_receipt(old_stdout.record("image", 0), original)
    io.move(descendant, original)
    proof = capture_original(ctx, original, image_pin, old_image, ctx.provider_pin)
    proof.update(kill_original(ctx, original, image_pin, proof))
    old_stdout.finish()
    spawned = H6["monotonic_ns"]()
    caller, stdout, _ = io.spawn_caller(ctx, directory, image_pin, env, "replacement")
    stdout.record("ready", 0, seconds=H6["remaining_seconds"](10))
    image = image_pin.image_receipt(stdout.record("image", 0), caller)
    check_replacement(ctx, original, proof, proof, caller, image, image_pin)
    membership_before = io.move(descendant, caller)
    replacement_mapping = mapped_provider(caller, ctx.provider_pin)
    if group_receipt(ctx, selected) != root_before:
        raise ValueError("selected original cgroup root changed before fresh admission")
    provider_before = H6["provider_receipt"](ctx.provider_pin)
    argv = [str(ctx.binary.path), "trace", "--cgroup", str(selected.path),
            "--module", str(ctx.provider_pin.path), "--attach-backend", backend,
            "--duration", "120s", "-o", str(directory / "trace.file.txt")]
    owned, capture, errors, started = io.spawn_observer(ctx, directory, argv, env)
    try:
        ready = H6["observer_ready"](owned, errors, backend, timeout=H6["remaining_seconds"](20))
    except H6["BackendRefused"] as refused:
        result = evaluate_replacement("", [], {"cell": "cgroup-process-replacement",
            "leg": f"replacement/{backend}", "backend_refused": str(refused)})
        H6["write_json"](directory / "result.json", result)
        return result
    ctx.binary.image_receipt({"image": 0}, owned)
    phases = []
    initial_ready = warm_replacement(ctx, io, caller, stdout, capture, descendant, image,
                                      image_pin, replacement_mapping, phases)
    check_replacement(ctx, original, proof, proof, caller, image, image_pin)
    io.command(caller, stdout, descendant, phases)
    membership_after = io.membership(descendant, caller)
    if mapped_provider(caller, ctx.provider_pin) != replacement_mapping:
        raise ValueError("replacement provider changed during measurement")
    root_after, descendant_after = group_receipt(ctx, selected), group_receipt(ctx, descendant)
    obs_rc, stopped, latency = stop_capture(ctx, owned)
    caller_rc = H6["stop_caller"](caller, stdout, 0)
    H6["finish_readers"](ctx.readers)
    proof.update(replacement_identity=dict(caller.identity), replacement_image=image,
                 replacement_mapping=replacement_mapping, root_before=root_before, root_after=root_after,
                 descendant_before=descendant_before, descendant_after=descendant_after,
                 membership_before=membership_before, membership_after=membership_after,
                 replacement_spawn_ns=spawned, manufactured_reuse=False, continuous_membership="unknown")
    measured = next(phase for phase in phases if phase["phase"] == "measured")
    receipt = dict(cell="cgroup-process-replacement", leg=f"replacement/{backend}", scope_kind="cgroup",
        owned_pids=[caller.pid], images=[image], replacement=proof, executable_pin=image_pin.metadata(),
        provider_before=provider_before, provider_after=H6["provider_receipt"](ctx.provider_pin),
        privacy_canaries=list(H6["CANARIES"]), observer_stderr="".join(errors.lines),
        observer_rc=obs_rc, caller_rc=caller_rc, observer_started_ns=started, observer_ready_ns=ready,
        observer_stopped_ns=stopped, scope_created_ns=ctx.scope_created_ns,
        pid_namespace=caller.identity["pid_namespace"], time_namespace=caller.identity["time_namespace"],
        scope_intervals=[dict(pid=caller.pid, membership="selected", t0=ready, t1=stopped)],
        measured=dict(label="replacement", t0=measured["t0"], t1=measured["t1"],
                      expected_calls=COUNT, phases=["measured"]),
        warmup=H6["warmup_receipt"](phases, measured["t0"]), initial_ready=initial_ready,
        phases=phases, exec_transitions=[], require_named=True, require_named_images=[0], first_unknown_images=[],
        successor_policy="no-transition", manual_rebind=False, abandoned_expected=0, abandoned_by_fn={},
        reuse_expected={}, requested_backend=backend, fresh_observer=True, observer_argv=argv,
        **H6["stop_receipt"](owned, latency))
    image_pin.verify()
    ctx.binary.verify()
    result = evaluate_replacement("".join(capture.lines), list(stdout.records), receipt,
                                  (directory / "trace.file.txt").read_text())
    H6["write_json"](directory / "receipt.json", receipt)
    H6["write_json"](directory / "result.json", result)
    return result


def validate_inputs(args):
    if len(set(args.backends)) != len(args.backends) or any(value not in BACKENDS for value in args.backends):
        raise ValueError("backends must be distinct singles and/or multi")
    if not args.backends:
        raise ValueError("select at least one explicit backend")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
        raise ValueError("supply the exact source commit under test")
    for path in (args.binary, args.provider, args.caller):
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ValueError("inputs must be absolute regular files without final symlinks")
    if any(not os.access(path, os.X_OK) for path in (args.binary, args.caller)):
        raise ValueError("observer and caller inputs must be executable")
    if (not args.out.is_absolute() or args.out.exists() or args.out.is_symlink() or not args.out.parent.is_dir()
            or args.out.parent.resolve() != args.out.parent):
        raise ValueError("output must be an absolute new-only directory below an existing direct parent")
    fd = os.open(args.out.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if H6["N3HARNESS"]["fs_magic"](fd) in (0x01021994, 0x858458f6):
            raise ValueError("output must live on disk, never tmpfs")
    finally:
        os.close(fd)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name, help_text in (("binary", "installed packaged observer"), ("provider", "SoftHSM provider"),
                            ("caller", "compiled tests/fixtures/cgroup-trace/caller.c")):
        parser.add_argument("--" + name, type=Path, required=True, help="absolute path to " + help_text)
    parser.add_argument("--source-revision", required=True, help="exact source commit under test")
    parser.add_argument("--uid", type=int, required=True, help="ordinary workload UID")
    parser.add_argument("--gid", type=int, required=True, help="ordinary workload GID")
    parser.add_argument("--backends", default="singles,multi", help="comma-separated singles,multi; no fallback")
    parser.add_argument("--out", type=Path, required=True, help="absolute new-only output directory on disk")
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        parser.error("live harness requires root observer and an ordinary workload uid/gid")
    args.backends = args.backends.split(",")
    try:
        validate_inputs(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return args


def main(argv=None):
    args = arguments(argv)
    os.umask(0o022)
    args.out.mkdir(mode=0o755)
    ctx = H6["Case"](args)
    results, metadata = [], {}
    with H6["signal_cleanup"]():
        try:
            with H6["cleanup_section"]():
                ctx.binary = H6["leg_pin"](ctx, args.binary)
                ctx.provider_pin = H6["leg_pin"](ctx, args.provider)
                image_pin = H6["leg_pin"](ctx, args.caller)
            metadata = dict(source_revision=args.source_revision,
                driver_head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=5).strip(),
                candidate=ctx.binary.metadata(), provider=ctx.provider_pin.metadata(), caller=image_pin.metadata(),
                kernel=os.uname().release, backends=args.backends)
            for backend in args.backends:
                results.append(run_replacement(ctx, args.out / backend, backend, None, image_pin))
                if ctx.cleanup_failed:
                    break
        except Exception as error:
            results.append({"pass": False, "status": "error", "errors": [f"{type(error).__name__}: {error}"]})
        finally:
            with H6["cleanup_section"]():
                for scope in reversed(ctx.scopes):
                    try:
                        H6["cleanup_leg_resources"](scope)
                    except H6["LegCleanupError"]:
                        pass
                try:
                    H6["cleanup_leg_resources"](ctx)
                except H6["LegCleanupError"]:
                    pass
    complete = (len(results) == len(args.backends) and all(result.get("pass") for result in results)
                and not ctx.cleanup_failed)
    summary = dict(metadata, legs=results, complete=complete, cleanup_errors=ctx.cleanup_errors,
                   cleanup=ctx.cleanup_totals)
    H6["write_json"](args.out / "summary.json", summary)
    print(json.dumps(dict(complete=complete, out=str(args.out), cleanup_errors=ctx.cleanup_errors)))
    return 0 if complete else 1


if __name__ == "__main__":
    sys.exit(main())
