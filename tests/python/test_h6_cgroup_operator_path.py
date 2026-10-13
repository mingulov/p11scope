# SPDX-License-Identifier: GPL-3.0-or-later
"""Host controls for H6's held cgroup operator path; never mount or capture."""

import copy
import contextlib
import errno
import io
import os
from pathlib import Path
import runpy
import tempfile
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
BASE = runpy.run_path(str(ROOT / "tests/python/test_automatic_exec_oracle.py"))
H6 = BASE["H6"]


def r1_inputs():
    ready, start = BASE["READY"], BASE["START"]
    image = BASE["image_record"]
    target = BASE["target_record"]
    call = BASE["call_record"]
    phases, ledger, rows = [], [image(0, "/w/caller-a", ready - 500_000_000)], []
    specs = [(0, "C_GenerateRandom", 5, "warm", "selected", 100),
             (0, "C_GetInfo", 3, "aside", "outside", 200),
             (1, "C_GetInfo", 3, "outside-b", "outside", 400),
             (1, "C_GetSessionInfo", 10, "measured", "selected", 600),
             (1, "C_GetSessionInfo", 3, "still", "selected", 700),
             (1, "C_GetSessionInfo", 3, "renamed", "selected", 800),
             (1, "C_GetInfo", 3, "operator-outside", "outside", 900)]
    request = {"kind": "exec", "image": 0, "pid": 1000, "tid": 1042,
               "start_time": 7777, "mode": "nonleader", "path": "/w/caller-b",
               "scope": "outside", "t": ready + 300_000_000}
    ledger.extend((request, image(1, "/w/caller-b", request["t"] + 20)))
    for generation, fn, count, label, scope, offset in specs:
        t0 = ready + offset * 1_000_000
        phases.append({"image": generation, "fn": fn, "count": count, "phase": label,
                       "scope": scope, "t0": t0 - 1, "t1": t0 + count * 20,
                       "actual_cgroup": "/owned/selected" if scope == "selected" else "/owned/outside"})
        ledger.append(target(generation, fn))
        for index in range(count):
            ledger.append(call(generation, fn, 0, label, scope, t0 + index * 20, t0 + index * 20 + 10))
            if scope == "selected":
                rows.append(BASE["named_row"](1000, 1000, f"/w/caller-{'a' if generation == 0 else 'b'}", fn))
    measured = next(phase for phase in phases if phase["phase"] == "measured")
    early = [phase for phase in phases if phase["t1"] < measured["t0"]]
    negative = next(phase for phase in phases if phase["phase"] == "operator-outside")
    receipt = BASE["base_receipt"](cell="cgroup-reentry", leg="trace/singles", scope_kind="cgroup",
        images=[row for row in ledger if row["kind"] == "image"], phases=phases,
        exec_transitions=[{"from_image": 0, "to_image": 1, "mode": "nonleader", "same_path": False,
                           "scope": "outside", "t0": request["t"] - 10, "t1": request["t"] + 30,
                           "request": request}],
        measured={"label": "post-reentry", "t0": measured["t0"], "t1": measured["t1"],
                  "expected_calls": 10, "phases": ["measured"]},
        warmup={"label": "early including outside", "t0": early[0]["t0"], "t1": early[-1]["t1"],
                "expected_calls": sum(phase["count"] for phase in early),
                "phases": [phase["phase"] for phase in early]},
        scope_intervals=[{"pid": 1000, "membership": "selected", "t0": ready,
                          "t1": ready + 150_000_000},
                         {"pid": 1000, "membership": "selected", "t0": ready + 500_000_000,
                          "t1": negative["t0"] - 1}],
        require_named=True, require_named_images=[1], first_unknown_images=[])
    marker_t = measured["t0"] - 1000
    marker = call(1, "C_GetInfo", 0, "successor-marker", "selected", marker_t, marker_t + 10)
    ledger.extend((target(1, "C_GetInfo"), marker))
    receipt["phases"].append({"image": 1, "fn": "C_GetInfo", "phase": "successor-marker",
        "scope": "selected", "count": 1, "t0": marker_t, "t1": marker_t + 10})
    receipt["warmup"]["t1"] = marker_t + 10
    receipt["warmup"]["expected_calls"] += 1
    receipt["warmup"]["phases"].append("successor-marker")
    receipt["successor_policy"] = "public-successor"
    receipt["successor_ready"] = [{"image": 1, "proof_kind": "trace-row", "started_ns": marker_t,
        "observed_ns": marker_t + 20, "deadline_ns": marker_t + 1_000_000_000,
        "attempts": 1, "max_attempts": 20, "output_cursor": 8, "proof_cursor": 9,
        "marker_fn": "C_GetInfo", "phases": ["successor-marker"]}]
    rows.insert(5, BASE["named_row"](1000, 1000, "/w/caller-b", "C_GetInfo"))
    text = BASE["trace_text"](rows, len(rows), len(rows), BASE["evidence"]())
    selected = {"path": "/sys/fs/cgroup/owned/selected", "dev": 7, "ino": 111, "magic": 0x63677270}
    outside = {"path": "/sys/fs/cgroup/owned/outside", "dev": 7, "ino": 222, "magic": 0x63677270}
    original = {"path": "/w/scope-path/current/root", "dev": 7, "ino": 111,
                "magic": 0x63677270, "mount_id": 101, "t": start - 100,
                "mount_namespace": 6, "filesystem": "cgroup2"}
    renamed = dict(original, path="/w/scope-path/retained/root", t=ready + 650_000_000)
    replacement = dict(original, ino=222, mount_id=102, t=ready + 750_000_000)
    receipt["operator_path"] = {
        "operation": "operator-path-ancestor-rename-and-alias-replacement",
        "namespace": {"before": {"mnt": 1, "pid": 1, "time": 2, "user": 4, "cgroup": 5},
                      "after": {"mnt": 6, "pid": 1, "time": 2, "user": 4, "cgroup": 5},
                      "prepared_ns": start - 300, "private": True,
                      "shared_or_slave": 0, "mountinfo_entries": 1},
        "probe_ns": start - 200, "selected": selected, "outside": outside,
        "initial": original, "renamed": renamed, "replacement": replacement,
        "held_after_replacement": dict(renamed, t=ready + 760_000_000),
        "outside_move_ns": negative["t0"] - 1,
    }
    return text, ledger, receipt


class OperatorPathOracleTests(unittest.TestCase):
    def test_complete_original_population_passes(self):
        text, ledger, receipt = r1_inputs()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["calls"], 22)

    def test_missing_operator_proof_is_not_a_positive(self):
        text, ledger, receipt = r1_inputs()
        receipt.pop("operator_path")
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"], "R1 accepted a missing held-root pathname control")

    def test_replacement_cannot_claim_the_original_held_inode(self):
        text, ledger, receipt = r1_inputs()
        broken = copy.deepcopy(receipt)
        broken["operator_path"]["held_after_replacement"]["ino"] = 222
        result = H6["evaluate_trace_h6"](text, ledger, broken)
        self.assertFalse(result["pass"], "R1 accepted replacement identity as its retained original")

    def test_namespace_mount_membership_population_and_chronology_are_mandatory(self):
        text, ledger, receipt = r1_inputs()
        mutations = {
            "original-namespace": lambda p, r: p["namespace"]["after"].update(mnt=1),
            "foreign-pid-namespace": lambda p, r: p["namespace"]["after"].update(pid=9),
            "shared-propagation": lambda p, r: p["namespace"].update(shared_or_slave=1),
            "no-private-proof": lambda p, r: p["namespace"].update(private=False),
            "no-mountinfo": lambda p, r: p["namespace"].update(mountinfo_entries=0),
            "foreign-canonical": lambda p, r: p["selected"].update(path="/foreign/selected"),
            "same-outside": lambda p, r: p["outside"].update(ino=111),
            "non-cgroup-bind": lambda p, r: p["initial"].update(magic=123),
            "changed-original-mount": lambda p, r: p["renamed"].update(mount_id=999),
            "same-replacement-mount": lambda p, r: p["replacement"].update(mount_id=101),
            "wrong-alias-namespace": lambda p, r: p["replacement"].update(mount_namespace=1),
            "wrong-alias-fs": lambda p, r: p["replacement"].update(filesystem="tmpfs"),
            "rename-mountpoint": lambda p, r: p["renamed"].update(path="/w/scope-path/current/renamed"),
            "late-preflight": lambda p, r: p.update(probe_ns=BASE["READY"]),
            "late-rename": lambda p, r: p["renamed"].update(t=BASE["READY"] + 710_000_000),
            "late-replacement": lambda p, r: p["replacement"].update(t=BASE["READY"] + 810_000_000),
            "outside-interval": lambda p, r: r["scope_intervals"][-1].update(t1=BASE["STOP"]),
            "changed-still-count": lambda p, r: next(x for x in r["phases"] if x["phase"] == "still").update(count=4),
            "changed-renamed-count": lambda p, r: next(x for x in r["phases"] if x["phase"] == "renamed").update(count=2),
            "changed-negative-count": lambda p, r: next(x for x in r["phases"] if x["phase"] == "operator-outside").update(count=2),
            "wrong-negative-membership": lambda p, r: next(x for x in r["phases"] if x["phase"] == "operator-outside").update(actual_cgroup="/owned/selected"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                broken = copy.deepcopy(receipt)
                mutate(broken["operator_path"], broken)
                result = H6["evaluate_trace_h6"](text, ledger, broken)
                self.assertFalse(result["pass"], (name, result["errors"]))
                self.assertTrue(any("operator-path" in error for error in result["errors"]), result["errors"])

    def test_three_replacement_outside_calls_cannot_enter_native_totals(self):
        text, ledger, receipt = r1_inputs()
        rows = text.splitlines()[3:-2]
        rows.extend(BASE["named_row"](1000, 1000, "/w/caller-b", "C_GetInfo") for _ in range(3))
        captured = BASE["trace_text"](rows, len(rows), len(rows), BASE["evidence"]())
        result = H6["evaluate_trace_h6"](captured, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("foreign count" in error for error in result["errors"]), result["errors"])


class OperatorNamespaceTests(unittest.TestCase):
    @contextlib.contextmanager
    def controls(self, fault=None):
        state = H6["_namespace_ids"]()
        before = dict(state)
        operations = []
        def clone():
            operations.append("clone")
            state["mnt"] += 1
            if fault == "other-namespace":
                state["user"] += 1
        def private():
            self.assertNotEqual(state["mnt"], before["mnt"], "propagation changed before clone")
            operations.append("private")
        patches = {"_namespace_ids": lambda: dict(state), "_unshare_mount_namespace": clone,
                   "_make_mounts_private": private,
                   "_read_mountinfo": lambda: [{"id": 1, "target": "/", "fs": "ext4",
                       "optional": ["master:1"] if fault == "slave" else []}]}
        with mock.patch.dict(H6["initialize_operator_namespace"].__globals__, patches):
            yield state, before, operations

    def test_mount_only_clone_is_enrolled_once_and_private_before_return(self):
        ctx = SimpleNamespace()
        with self.controls() as (state, before, operations):
            try:
                H6["initialize_operator_namespace"](ctx)
                self.assertEqual(operations, ["clone", "private"])
                self.assertEqual(ctx.operator_namespace.proof["before"], before)
                self.assertEqual(ctx.operator_namespace.proof["after"], state)
                for name in ("original_fd", "private_fd"):
                    os.fstat(getattr(ctx.operator_namespace, name))
                with self.assertRaisesRegex(H6["SetupError"], "already initialized"):
                    H6["initialize_operator_namespace"](ctx)
                self.assertEqual(operations, ["clone", "private"])
            finally:
                ctx.operator_namespace.close()

    def test_other_namespace_or_slave_propagation_is_not_ready(self):
        for fault in ("other-namespace", "slave"):
            ctx = SimpleNamespace()
            with self.subTest(fault=fault), self.controls(fault):
                try:
                    with self.assertRaises(H6["SetupError"]):
                        H6["initialize_operator_namespace"](ctx)
                    self.assertIsNone(ctx.operator_namespace.proof)
                finally:
                    ctx.operator_namespace.close()

    def test_failed_clone_keeps_its_original_owned_fd(self):
        ctx = SimpleNamespace()
        def refuse():
            self.assertIsNotNone(ctx.operator_namespace.original_fd, "clone ran before resource enrollment")
            raise PermissionError(errno.EPERM, "controlled unsupported mount namespace")
        namespace = H6["initialize_operator_namespace"].__globals__
        with mock.patch.dict(namespace, {"_unshare_mount_namespace": refuse}):
            try:
                with self.assertRaises(PermissionError):
                    H6["initialize_operator_namespace"](ctx)
                os.fstat(ctx.operator_namespace.original_fd)
            finally:
                ctx.operator_namespace.close()

    def test_existing_reader_or_child_refuses_before_clone(self):
        namespace = H6["initialize_operator_namespace"].__globals__
        clone = mock.Mock(side_effect=AssertionError("late clone executed"))
        for patch in (mock.patch.object(namespace["threading"], "active_count", return_value=2),
                      mock.patch.object(Path, "read_text", return_value="999")):
            ctx = SimpleNamespace()
            with patch, mock.patch.dict(namespace, {"_unshare_mount_namespace": clone}), \
                    self.assertRaises(H6["SetupError"]):
                H6["initialize_operator_namespace"](ctx)
            self.assertIsNone(ctx.operator_namespace.original_fd)
        clone.assert_not_called()

    def test_main_establishes_namespace_before_fixture_children(self):
        operations = []
        def setup(ctx):
            operations.append("namespace")
            ctx.operator_namespace = SimpleNamespace(close=lambda: operations.append("namespace-close"))
        def compile_fixtures(*args):
            self.assertEqual(operations, ["namespace"])
            operations.append("compile")
            return {}
        def runner(ctx, directory, backend):
            self.assertEqual(operations, ["namespace", "compile"])
            operations.append("cell")
            return [{"cell": "cgroup-reentry", "leg": f"{name}/{backend}", "pass": True, "status": "pass"}
                    for name in ("trace", "replacement", "stop-before", "stop-during", "inventory")]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "image"
            image.write_bytes(b"ordinary held input")
            argv = ["--binary", str(image), "--provider", str(image), "--discover", str(image),
                    "--source-revision", "0" * 40, "--uid", "1000", "--gid", "1000",
                    "--cells", "cgroup-reentry", "--backends", "singles", "--out", str(root / "out")]
            namespace = H6["main"].__globals__
            with mock.patch.dict(namespace, {"initialize_operator_namespace": setup,
                    "compile_case_fixtures": compile_fixtures, "symbol_file_offset": lambda *args: 0}), \
                    mock.patch.dict(H6["CELL_RUNNERS"], {"cgroup-reentry": runner}), \
                    mock.patch.object(os, "geteuid", return_value=0), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(H6["main"](argv), 0)
        self.assertEqual(operations, ["namespace", "compile", "cell", "namespace-close"])


class OperatorPathRouteTests(unittest.TestCase):
    def test_r1_uses_ordinary_ancestor_instead_of_forbidden_cgroup_rename(self):
        self.route()

    def test_unsupported_preflight_stops_before_observer(self):
        for fault in ("bind", "rename", "outside-bind"):
            with self.subTest(fault=fault):
                self.route(fault)

    def test_failed_unmount_retains_alias_and_native_groups_for_original_backstop(self):
        self.route("unmount")

    def test_expired_original_cleanup_cannot_unmount_or_renew(self):
        self.route("expired")

    def test_unproven_bind_transfer_retains_resources_before_observer(self):
        self.route("uncertain-bind")

    def test_foreign_mount_id_is_never_unmounted(self):
        self.route("foreign-mount")

    def test_unproven_child_keeps_operator_fd_and_native_groups(self):
        self.route("pending")

    def route(self, fault=None):
        # Real held directories/FDs supply identities. Only mounts, cgroup
        # membership and observer publication are injected; no native gate runs.
        namespace = H6["run_cgroup_r1"].__globals__
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native = root / "native"
            native.mkdir()
            executable = root / "caller"
            executable.write_bytes(b"ordinary copied fixture")
            provider = root / "provider"
            provider.write_bytes(b"ordinary provider fixture")
            native_groups, bindings, mount_ids, alias_owners, observed_argv = {}, {}, {}, [], []
            member = [None]
            tick = [BASE["START"]]
            def clock():
                tick[0] += 1_000_000
                return tick[0]
            def group(ctx, path):
                path = Path(path)
                actual = native / str(len(native_groups))
                actual.mkdir()
                fd = os.open(actual, os.O_RDONLY | os.O_DIRECTORY)
                info = os.fstat(fd)
                held = SimpleNamespace(path=path, fd=fd, identity=(info.st_dev, info.st_ino))
                held.verify = lambda: self.assertEqual((os.fstat(fd).st_dev, os.fstat(fd).st_ino), held.identity)
                native_groups[path] = held
                def remove():
                    self.assertEqual(bindings, {}, "native cgroup removed before operator mounts settled")
                    os.close(held.fd)
                    held.fd = None
                    actual.rmdir()
                wrapper = SimpleNamespace(path=path, group=held, remove=remove)
                ctx.groups.append(wrapper)
                return held, wrapper
            def move(held, caller, moves, note):
                held.verify()
                member[0] = "/" + str(held.path.relative_to("/sys/fs/cgroup"))
                moves.append({"t": clock(), "cgroup": member[0], "note": note})
                return member[0]
            def bind(source, target):
                if fault == "bind" or fault == "outside-bind" and Path(source).name == "outside":
                    raise PermissionError(errno.EPERM, "controlled unsupported bind")
                bindings[Path(target)] = native_groups[Path(source)]
                mount_ids[Path(target)] = 100 + len(mount_ids)
                if fault == "uncertain-bind":
                    raise OSError(errno.EIO, "controlled uncertain bind transfer")
            def unmount(target):
                if fault == "unmount" and Path(target).name == "root":
                    raise OSError(errno.EBUSY, "controlled busy owned alias")
                del bindings[Path(target)]
                del mount_ids[Path(target)]
            def opened(path):
                return os.dup(bindings[Path(path)].fd)
            real_rename = os.rename
            def rename(source, target, **options):
                if str(source).startswith("/sys/fs/cgroup"):
                    raise PermissionError(errno.EPERM, "native cgroup rename unsupported")
                if fault == "rename":
                    raise PermissionError(errno.EPERM, "controlled unsupported ancestor rename")
                real_rename(source, target, **options)
                # Reflect a real ordinary ancestor rename in the injected
                # mount table, preserving the actual held source and mount ID.
                base = Path(options.get("src_dir_fd") and root / "cgroup-reentry/singles/trace/scope-path" or ".")
                old = Path(source) if Path(source).is_absolute() else base / source
                new = Path(target) if Path(target).is_absolute() else base / target
                for path in list(bindings):
                    if path.is_relative_to(old):
                        changed = new / path.relative_to(old)
                        bindings[changed] = bindings.pop(path)
                        mount_ids[changed] = mount_ids.pop(path)
            def info():
                return [{"id": mount_ids[path], "target": str(path), "fs": "cgroup2", "optional": []}
                        for path in bindings]
            def mount_id(fd):
                held = os.fstat(fd)
                return next(mount_ids[path] for path, group in bindings.items()
                            if (os.fstat(group.fd).st_dev, os.fstat(group.fd).st_ino) == (held.st_dev, held.st_ino))
            def command(caller, stdout, fn, count, delay, phase, scope, image=0, group=None, phases=None):
                if group is not None:
                    self.assertEqual(member[0], "/" + str(group.path.relative_to("/sys/fs/cgroup")))
                begin = clock()
                phases.append({"image": image, "fn": fn, "count": count, "phase": phase, "scope": scope,
                               "t0": begin, "t1": clock(), "actual_cgroup": member[0]})
            caller = SimpleNamespace(pid=1000, identity={"pid_namespace": 2, "time_namespace": 3})
            stream = SimpleNamespace(record=lambda *args: {}, records=[])
            capture = SimpleNamespace(lines=[])
            observer = SimpleNamespace()
            pin = SimpleNamespace(path=executable)
            def local_pin(ctx, path):
                return SimpleNamespace(path=Path(path), image_receipt=lambda row, owner: {"image": 0, "path": str(path)})
            def execute(caller, stdout, images, mode, image_pin):
                images.append({"image": 1, "path": str(image_pin.path)})
                return {}, None, clock(), clock()
            def observe(owners, readers, directory, argv, env):
                observed_argv.append(argv)
                (Path(directory) / "trace.file.txt").write_text("")
                return observer, capture, capture, clock()
            ctx = SimpleNamespace(args=SimpleNamespace(uid=1000, gid=1000), pins={"caller": pin},
                provider_pin=SimpleNamespace(path=provider), binary=pin, owners=[], readers=[], groups=[],
                operator_paths=alias_owners, scope_created_ns=clock(),
                operator_namespace=SimpleNamespace(verify=lambda: None, proof={
                    "before": {"mnt": 1, "pid": 2, "time": 3, "user": 4, "cgroup": 5},
                    "after": {"mnt": 6, "pid": 2, "time": 3, "user": 4, "cgroup": 5},
                    "prepared_ns": tick[0], "private": True, "shared_or_slave": 0, "mountinfo_entries": 1}))
            ctx.traced, ctx.leg_pins, ctx.cleanup_errors = [], [], []
            ctx.cleanup_failed = False
            ctx.cleanup_totals = {"processes": 0, "readers": 0, "cgroups": 0, "pins": 0}
            ctx.budget = ctx.terminal_budget = H6["LegBudget"](clock=clock)
            patches = {"monotonic_ns": clock, "init_token": lambda *args: {}, "leg_pin": local_pin,
                "create_tracked": group, "move_and_verify": move, "cgroup_of": lambda pid: member[0],
                "spawn_caller": lambda *args: (caller, stream, stream), "spawn_observer": observe,
                "observer_ready": lambda *args: clock(), "caller_exec": execute,
                "warm_caller": lambda *args, **kwargs: {}, "n3_command": command,
                "stop_observer": lambda *args: (0, clock(), 0.1), "stop_caller": lambda *args: 0,
                "finish_readers": lambda *args: None, "provider_receipt": lambda *args: {},
                "stop_receipt": lambda *args: {}, "session_reuse_from": lambda *args: {},
                "evaluate_trace_h6": lambda trace, ledger, receipt, file_trace: receipt,
                "_bind_operator_mount": bind, "_unmount_operator_mount": unmount,
                "_open_operator_dir": opened, "_read_mountinfo": info, "_operator_mount_id": mount_id,
                "fs_magic": lambda fd: 0x63677270}
            token = H6["ACTIVE_LEG"].set(ctx.budget)
            try:
                with mock.patch.dict(namespace, patches), mock.patch.object(os, "rename", rename):
                    if fault in ("bind", "rename", "outside-bind", "uncertain-bind"):
                        with self.assertRaises(OSError):
                            H6["run_cgroup_r1"].__wrapped__(ctx, root / "cgroup-reentry", "singles")
                        self.assertEqual(observed_argv, [], "unsupported setup started an observer")
                        self.assertEqual(len(alias_owners), 1, "failed mutation lost enrolled ownership")
                        if fault == "uncertain-bind":
                            with self.assertRaises(H6["LegCleanupError"]):
                                H6["cleanup_leg_resources"](ctx)
                            self.assertEqual(len(ctx.operator_paths), 1)
                            self.assertEqual(len(ctx.groups), 4)
                            self.assertEqual(len(bindings), 1)
                            return
                        H6["cleanup_leg_resources"](ctx)
                        self.assertEqual(bindings, {})
                        return
                    result = H6["run_cgroup_r1"].__wrapped__(ctx, root / "cgroup-reentry", "singles")
                    self.assertIn("/scope-path/current/root",
                                  observed_argv[0][observed_argv[0].index("--cgroup") + 1])
                    counts = {phase["phase"]: phase["count"] for phase in result["phases"]}
                    self.assertEqual({key: counts[key] for key in
                        ("warm", "aside", "outside-b", "measured", "still", "renamed", "operator-outside")},
                        {"warm": 5, "aside": 3, "outside-b": 3, "measured": 10,
                         "still": 3, "renamed": 3, "operator-outside": 3})
                    self.assertEqual(result["scope_intervals"][-1]["t1"], result["operator_path"]["outside_move_ns"])
                    if fault == "expired":
                        ctx.budget.enter("cleanup")
                        tick[0] += 5_000_000_000
                    if fault == "foreign-mount":
                        mount_ids[ctx.operator_paths[0].path] += 900
                    pending_controls = {}
                    if fault == "pending":
                        owner = H6["spawn_owned"](ctx.owners, [sys.executable, "-I", "-c", "import sys; sys.stdin.read()"],
                            os.getuid(), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        def refused(*args):
                            raise OSError("controlled unproven child settlement")
                        pending_controls = {"terminate_owned": refused, "wait_terminal_child": refused}
                    if fault in ("expired", "unmount", "foreign-mount", "pending"):
                        before = dict(ctx.budget.deadlines)
                        with mock.patch.dict(namespace, pending_controls), self.assertRaises(H6["LegCleanupError"]):
                            H6["cleanup_leg_resources"](ctx)
                        self.assertEqual(len(ctx.operator_paths), 1)
                        self.assertEqual(len(ctx.groups), 4)
                        self.assertEqual(len(bindings), 2)
                        for held in native_groups.values():
                            os.fstat(held.fd)
                        if fault == "pending":
                            self.assertEqual(ctx.owners, [owner])
                            os.fstat(ctx.operator_paths[0].root_fd)
                        first_deadlines = dict(ctx.budget.deadlines)
                        with mock.patch.dict(namespace, pending_controls), self.assertRaises(H6["LegCleanupError"]):
                            H6["cleanup_leg_resources"](ctx)
                        self.assertEqual(ctx.budget.deadlines, first_deadlines)
                        if fault == "expired":
                            self.assertEqual(ctx.budget.deadlines, before)
                        self.assertTrue(ctx.cleanup_failed)
                        return
                    H6["cleanup_leg_resources"](ctx)
                    self.assertEqual(bindings, {})
                    self.assertEqual(ctx.operator_paths, [])
                    self.assertFalse(ctx.cleanup_failed)
            finally:
                H6["ACTIVE_LEG"].reset(token)
                fault = None  # Unit teardown of injected mounts, never a later positive.
                for owner in ctx.owners:
                    if owner.popen.poll() is None:
                        owner.popen.kill()
                    owner.popen.wait(timeout=2)
                    owner.close()
                with mock.patch.dict(namespace, patches):
                    for owned in list(alias_owners):
                        for entry in owned.mounts:
                            path = owned.base / entry["relative"]
                            if entry["snapshot"] is None:
                                bindings.pop(path, None)
                                mount_ids.pop(path, None)
                            elif path in mount_ids:
                                mount_ids[path] = entry["snapshot"]["mount_id"]
                        owned.remove()
                for held in native_groups.values():
                    if held.fd is not None:
                        os.close(held.fd)


if __name__ == "__main__":
    unittest.main()
