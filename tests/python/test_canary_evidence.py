#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native canary evidence tests; run under an independent process watchdog.

run_json defers callable handlers (including SIGALRM) while owning resources.
In-process alarm diagnostics alone cannot enforce the suite's wall-clock bound.
"""

import argparse
import copy
import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SUBJECT = ROOT / "scripts" / "check-canary-evidence.py"
DUMPER = ROOT / "scripts" / "dump-owned-bpf-maps.py"
CAPTURE_CHECKER = ROOT / "scripts" / "check-capture-evidence.py"
PROBE_ENTRY = ROOT / "tests" / "python" / "json_signal_lifetime_probe.py"

sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path


def load_subject(bits):
    module = load_path(SUBJECT, f"canary_evidence_{bits}")
    module.initialize(bits)
    return module


def load_dumper():
    return load_path(DUMPER, "owned_bpf_maps")


def refusal_cells(item, errno=524):
    """A cgroup_array surface: one kernel -ENOTSUPP per key, and no value.

    `cgroup_array_map_ops` has no `map_fd_sys_lookup_elem`, so this refusal is
    the only thing userspace can witness about the map's values.
    """
    return [{"key": [f"0x{byte:02x}" for byte
                     in index.to_bytes(item["key_size"], "little")], "errno": errno}
            for index in range(item["max_entries"])]


def load_capture_checker():
    return load_path(CAPTURE_CHECKER, "capture_evidence")


def owned_metrics_document(bits, calls=30):
    subject = load_capture_checker()
    evidence = subject.evidence_fixture(
        subject.VERSION_SURFACES_SCANNED,
        sources=("scan", "manifest"),
        discovery_skipped=0,
    )
    evidence["discovery"][0]["tables"] = [
        {"source": source, "version": list(version), "entries": entries}
        for (source, version, entries), count in subject.VERSION_TABLES_SCANNED.items()
        for _ in range(count)
    ]
    evidence.update(
        table_entries=988,
        slots=104,
        attached_probes=208,
        vendor_interfaces=1,
        interface_list="ok",
        child_still_running=False,
    )
    # The one skip an owned lane must publish. `p11scope run` attempts
    # initial-set discovery and the D3 amendment leaves the timing catalog
    # exactly empty, so the attempt is reported unproven rather than claimed.
    # (The F-14 future-minor disclosure is retired with the scanner
    # emission it mirrored: the scan walks every 2.x/3.x word it sees.)
    # Spelled out rather than taken from `discovery_skipped`, because the
    # fixture's generic skip carries the table-unavailable reason instead.
    evidence["skipped"] = [
        {"name": subject.DISCOVERY_SUBJECT, "reason": subject.DISCOVERY_UNAVAILABLE},
    ]
    if bits == 64:
        evidence["discovery_conflicts"] = 1
        evidence["discovery"][0]["corroboration"] = ["conflict"]
    else:
        evidence["surfaces"].extend([
            {"walk": "full", "functions": functions, "acquisition": "ok",
             "source": f"/opt/p11.so table {major}.{minor}"}
            for major, minor, functions in ((3, 1, 92), (3, 2, 104))
        ])
        evidence["discovery"][0]["tables"].extend([
            {"source": "scan", "version": [3, 1], "entries": 92},
            {"source": "scan", "version": [3, 2], "entries": 104},
        ])
        evidence["discovery"][0].update(corroborated=True, corroboration=["agreed"])
    document = subject.document_fixture(
        evidence,
        schema=subject.METRICS_SCHEMA,
        mode="metrics",
        privacy="aggregate-only",
    )
    document["functions"] = subject.function_items([(["C_GetInterfaceList"], calls)])
    return subject, document


# The probe body lives in tests/python/json_signal_lifetime_probe.py so probe
# children import one small module instead of this whole file; re-exported
# here for the remaining runpy-based call sites.
json_signal_lifetime_probe = load_path(
    PROBE_ENTRY, "json_signal_lifetime_probe").json_signal_lifetime_probe


def start_bytes(module, session, target=None, mechanism=None, mechanism_ptr=0,
                attr_type=0, capture=0):
    """Independent CallStart byte constructor; offsets are the test oracle."""
    raw = bytearray(288)
    struct.pack_into("<Q", raw, 8, session)
    struct.pack_into("<Q", raw, 24, (1 << 64) - 1 if mechanism is None else mechanism)
    struct.pack_into("<Q", raw, 32, mechanism_ptr)
    struct.pack_into("<I", raw, 56, (1 << 32) - 1)
    if attr_type:
        struct.pack_into("<Q", raw, 96, attr_type)
        struct.pack_into("<II", raw, 160, 1, 1)
    struct.pack_into("<I", raw, 256, capture)
    struct.pack_into("<I", raw, 260, (1 << 32) - 1 if target is None else target)
    return bytes(raw)


def event_bytes(index, mechanism=None, slot=0, shape=0, p0=0, p1=0, p2=0,
                attrs=(), attr_count=0, attr_total=0, attr_bools=0,
                attr_seen=0, capture=0, root_affiliation=0):
    """Independent Event byte constructor; it never calls production encoders."""
    raw = bytearray(328)
    struct.pack_into("<Q", raw, 16, 0x555 << 32 | index)
    session, target = (0x101, (1 << 32) - 1)
    if 22 <= index < 25:
        session, target = ((0x11D, 30), (0x11E, (1 << 32) - 1),
                           (0x11F, (1 << 32) - 1))[index - 22]
    struct.pack_into("<Q", raw, 32, session)
    if mechanism is None:
        mechanism = (0x250, 0xD, 0x1087)[index] if index < 3 else (1 << 64) - 1
    struct.pack_into("<Q", raw, 48, mechanism)
    struct.pack_into("<QQQ", raw, 72, p0, p1, p2)
    struct.pack_into("<II", raw, 104, slot, target)
    struct.pack_into("<I", raw, 116, shape)
    struct.pack_into("<8Q", raw, 120, *(tuple(attrs) + (0,) * (8 - len(attrs))))
    struct.pack_into("<IIII", raw, 184, attr_count, attr_total, attr_bools, attr_seen)
    struct.pack_into("<I", raw, 280, capture)
    struct.pack_into("<Q", raw, 320, root_affiliation)
    return bytes(raw)


class ImportSafetyTests(unittest.TestCase):
    def test_import_from_unrelated_cwd_is_inert(self):
        with tempfile.TemporaryDirectory() as directory:
            code = (
                "import importlib.util, pathlib, sys; "
                "sys.argv=['hostile','--raw-events']; "
                f"p=pathlib.Path({str(SUBJECT)!r}); "
                "s=importlib.util.spec_from_file_location('subject',p); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                "assert m.ALIASES is None and m.SAFE_MAPS is None"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-c", code], cwd=directory,
                env={"PYTHONPATH": directory}, text=True, capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cli_rejects_empty_invalid_and_incomplete_modes(self):
        for arguments in ((), ("--self-test", "31"), ("--raw-events", "64")):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [sys.executable, "-I", str(SUBJECT), *arguments],
                    text=True, capture_output=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)


class TargetWidthPathTests(unittest.TestCase):
    def test_direct_self_test_resolves_sources_outside_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-I", str(SUBJECT), "--self-test", str(TARGET_BITS)],
                cwd=directory, text=True, capture_output=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("target-width scalar oracles: OK", result.stdout)


class OwnedMapWrapperTests(unittest.TestCase):
    def test_full_matrix_wrapper_uses_explicit_work_and_rejects_missing_surface(self):
        subject = load_subject(TARGET_BITS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lane = "synthetic"
            prefix = root / lane
            manifest = []
            for map_id, (name, definition) in enumerate(
                sorted(subject.BPF_MAP_DEFS["SAFE_MAPS"].items()), start=1
            ):
                ring = definition["type"] == 27
                # Type from the checked-in definition: a cgroup_array has no
                # userspace lookup, so it is never a dump of anything.
                map_type, oracle = {
                    27: ("ringbuf", "mmap"), 29: ("task_storage", "task-storage"),
                    8: ("cgroup_array", "refused-lookup"),
                }.get(definition["type"], ("hash", "dump"))
                item = {
                    "name": name,
                    "id": map_id,
                    "max_entries": definition["max_entries"],
                    "key_size": 0 if ring else definition["key_size"],
                    "value_size": 0 if ring else definition["value_size"],
                    "type": map_type,
                    "oracle": oracle,
                }
                if ring:
                    subject.ring_raw_path(prefix, name).write_bytes(b"")
                else:
                    item["file"] = str(root / f"mapdump_{name}_{lane}.json")
                    Path(item["file"]).write_text(
                        json.dumps(refusal_cells(item)) + "\n" if map_type == "cgroup_array"
                        else "[]\n", encoding="utf-8")
                manifest.append(item)
            manifest_path = root / f"mapdump_manifest_{lane}.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            surfaces = subject.assert_exact_owned_map_inventory(
                root, lane, subject.SAFE_MAPS
            )
            self.assertEqual(len(surfaces), len(subject.SAFE_MAPS))

            missing = subject.ring_raw_path(prefix, "DISCOVERY")
            missing.unlink()
            with self.assertRaisesRegex(AssertionError, "has no scanned surface"):
                subject.assert_exact_owned_map_inventory(root, lane, subject.SAFE_MAPS)


class TaskStorageInventoryTests(unittest.TestCase):
    def test_task_storage_maps_use_task_storage_oracle_and_need_surfaces(self):
        subject = load_subject(TARGET_BITS)
        dumper = load_dumper()
        task_storage = [
            {"name": "TASK_COOKIE", "id": 101, "type": "task_storage",
             "key_size": 4, "value_size": 8, "max_entries": 0,
             "oracle": dumper.map_oracle({"name": "TASK_COOKIE", "type": "task_storage"})},
            {"name": "THREAD_OWNER", "id": 102, "type": "task_storage",
             "key_size": 4, "value_size": 544, "max_entries": 0,
             "oracle": dumper.map_oracle({"name": "THREAD_OWNER", "type": "task_storage"})},
            {"name": "ROOT_AFFILIATION", "id": 103, "type": "task_storage",
             "key_size": 4, "value_size": 8, "max_entries": 0,
             "oracle": dumper.map_oracle({"name": "ROOT_AFFILIATION", "type": "task_storage"})},
        ]
        self.assertEqual([item["oracle"] for item in task_storage],
                         ["task-storage"] * 3)
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "synthetic"
            prefix.mkdir()
            for item in task_storage:
                item["file"] = str(prefix / f"mapdump_{item['name']}.bin")
                Path(item["file"]).write_bytes(b"task-storage-records")
            surfaces = subject.owned_map_surfaces(
                "task-storage", task_storage,
                {item["name"] for item in task_storage}, str(prefix),
            )
            self.assertEqual(len(surfaces), 3)
            self.assertTrue(all(path.is_file() for path in surfaces))
            missing = list(task_storage)
            missing[1] = dict(missing[1])
            missing[1].pop("file")
            with self.assertRaisesRegex(AssertionError, "has no scanned surface"):
                subject.owned_map_surfaces(
                    "task-storage", missing,
                    {item["name"] for item in task_storage}, str(prefix),
                )


class TaskStorageReaderTests(unittest.TestCase):
    MAPS = [
        {"name": "TASK_COOKIE", "id": 101, "type": "task_storage",
         "oracle": "task-storage", "bytes_key": 4, "bytes_value": 8,
         "max_entries": 0, "map_flags": 1},
        {"name": "THREAD_OWNER", "id": 102, "type": "task_storage",
         "oracle": "task-storage", "bytes_key": 4, "bytes_value": 544,
         "max_entries": 0, "map_flags": 1},
        {"name": "ROOT_AFFILIATION", "id": 103, "type": "task_storage",
         "oracle": "task-storage", "bytes_key": 4, "bytes_value": 8,
         "max_entries": 0, "map_flags": 1},
    ]

    @staticmethod
    def frame(kind, map_id=0, pid=0, tid=0, value=b""):
        return struct.pack(
            "<8sIIIII", b"P11TSV1\0", kind, map_id, pid, tid, len(value)
        ) + value

    def complete_stream(self):
        owner = bytearray(544)
        owner[536:] = b"LATEBYTE"
        return b"".join([
            self.frame(1, 101, 7001, 7001, b"COOKIE01"),
            self.frame(1, 102, 7001, 7002, bytes(owner)),
            self.frame(1, 103, 7001, 7002, b"ROOTCELL"),
            self.frame(2),
        ])

    def test_native_reader_interruptions_reap_only_the_retained_helper(self):
        dumper = load_dumper()
        real_popen, real_open, real_kill = subprocess.Popen, os.pidfd_open, os.kill
        real_selector = dumper.selectors.DefaultSelector
        unrelated = real_popen([sys.executable, "-c", "import time; time.sleep(5)"])
        try:
            for case in ("wait", "reaped-wait", "collection"):
                with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    reader, obj = root / "reader", root / "reader.bpf.o"
                    obj.write_bytes(b"object")
                    reader.write_text(
                        f"#!{sys.executable}\nimport os,time\n"
                        f"os.write(1, {self.frame(2)!r})\n" + (
                            "os.close(1); os.close(2); time.sleep(5)\n"
                            if case != "reaped-wait" else ""), encoding="utf-8")
                    reader.chmod(0o700)
                    children, test_handles, handles, pipes, selectors, raw_signals = [], [], [], [], [], []

                    def capture_popen(*args, **kwargs):
                        process = real_popen(*args, **kwargs)
                        children.append(process)
                        test_handles.append(real_open(process.pid))
                        pipes.extend([process.stdout or kwargs["stdout"],
                                      process.stderr or kwargs["stderr"]])
                        original_wait = process.wait
                        interrupted = False

                        def interrupt_wait(*args, **kwargs):
                            nonlocal interrupted
                            if case != "collection" and not interrupted:
                                interrupted = True
                                if case == "reaped-wait":
                                    self.assertEqual(original_wait(*args, **kwargs), 0)
                                    with self.assertRaises(ChildProcessError):
                                        os.waitpid(process.pid, os.WNOHANG)
                                raise KeyboardInterrupt("injected native wait interruption")
                            return original_wait(*args, **kwargs)

                        process.wait = interrupt_wait
                        return process

                    def capture_open(pid, flags=0):
                        fd = real_open(pid, flags)
                        handles.append(fd)
                        return fd

                    def capture_selector():
                        selector = real_selector()
                        selectors.append(selector)
                        if case == "collection":
                            selector.select = mock.Mock(side_effect=KeyboardInterrupt(
                                "injected native collection interruption"))
                        return selector

                    def intercept_kill(pid, sig):
                        raw_signals.append((pid, sig))
                        self.assertEqual(pid, children[0].pid)
                        try:
                            os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        except ChildProcessError:
                            return  # Never forward a signal after actual reap.
                        real_kill(pid, sig)  # Safe RED cleanup of a still-owned child.

                    try:
                        with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                                mock.patch.object(dumper.os, "pidfd_open", side_effect=capture_open), \
                                mock.patch.object(dumper.os, "kill", side_effect=intercept_kill), \
                                mock.patch.object(dumper.selectors, "DefaultSelector", side_effect=capture_selector):
                            with self.assertRaisesRegex(KeyboardInterrupt, "native .* interruption"):
                                dumper.run_task_storage_reader(
                                    reader, obj, 55, self.MAPS, timeout_seconds=0.2,
                                    max_records=8, max_bytes=4096)
                        with self.assertRaises(ChildProcessError):
                            os.waitid(os.P_PIDFD, test_handles[0], os.WEXITED | os.WNOHANG)
                        self.assertTrue(all(pipe.closed for pipe in pipes))
                        self.assertEqual(len(handles), 1)
                        with self.assertRaises(OSError):
                            os.fstat(handles[0])
                        self.assertEqual(len(selectors), 1)
                        with self.assertRaises(ValueError):
                            type(selectors[0]).select(selectors[0], 0)
                        self.assertEqual(raw_signals, [])
                        self.assertIsNone(unrelated.poll())
                    finally:
                        for fd in test_handles:
                            try:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        for process in children:
                            type(process).wait(process, timeout=1)
                        for pipe in pipes:
                            pipe.close()
                        for selector in selectors:
                            selector.close()
                        for fd in test_handles:
                            os.close(fd)
        finally:
            unrelated.kill()
            unrelated.wait(timeout=1)

    def test_native_reader_validates_native_limits_before_spawn(self):
        dumper = load_dumper()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reader, obj = root / "reader", root / "reader.bpf.o"
            reader.write_text(f"#!{sys.executable}\n", encoding="utf-8")
            reader.chmod(0o700)
            obj.write_bytes(b"object")
            good = {"observer_pid": 55, "max_records": 8, "max_bytes": 4096, "timeout_seconds": 1}
            invalid = {
                "observer_pid": (0, -1, 1 << 32, True, 55.0, "55"),
                "max_records": (0, -1, 131073, True, 8.0, "8"),
                "max_bytes": (0, -1, 64 * 1024 * 1024 + 1, True, 8.0, "8"),
                "timeout_seconds": (0, -1, 60.001, 10 ** 1000, True, float("inf"), float("nan"), "1"),
            }
            for field, values in invalid.items():
                for value in values:
                    with self.subTest(field=field, value=value):
                        arguments = dict(good, **{field: value})
                        with mock.patch.object(dumper.subprocess, "Popen", side_effect=AssertionError(
                                "native helper spawned with invalid bounds")):
                            with self.assertRaisesRegex(RuntimeError, "task-storage reader.*invalid bounds"):
                                dumper.run_task_storage_reader(reader, obj, maps=self.MAPS, **arguments)

    def test_native_reader_preserves_framed_bytes_argv_and_independent_limits(self):
        dumper = load_dumper()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reader, obj, argvfile = root / "reader", root / "reader.bpf.o", root / "argv.json"
            obj.write_bytes(b"object")
            cases = (
                (1, 8, 9.25, self.frame(1, 101, 7001, 7001, b"COOKIE01") + self.frame(2)),
                (3, 560, 8.5, self.complete_stream()),
                (131072, 64 * 1024 * 1024, 60, self.frame(2)),
            )
            for maximum_records, maximum_bytes, timeout, stream in cases:
                with self.subTest(records=maximum_records, payload=maximum_bytes, timeout=timeout):
                    reader.write_text(
                        f"#!{sys.executable}\nimport json,pathlib,sys\n"
                        f"pathlib.Path({str(argvfile)!r}).write_text(json.dumps(sys.argv[1:]))\n"
                        f"sys.stdout.buffer.write({stream!r})\n", encoding="utf-8")
                    reader.chmod(0o700)
                    # Native framing may exceed the JSON caller's limit. This
                    # small independent limit detects accidental shared caps.
                    with mock.patch.object(dumper, "JSON_OUTPUT_MAX_BYTES", 32):
                        actual = dumper.run_task_storage_reader(
                            reader, obj, (1 << 32) - 1, list(reversed(self.MAPS)),
                            timeout_seconds=timeout, max_records=maximum_records,
                            max_bytes=maximum_bytes)
                    self.assertIs(type(actual), bytes)
                    self.assertEqual(actual, stream)
                    self.assertEqual(json.loads(argvfile.read_text()), [
                        str(obj), "4294967295", str(maximum_records), str(maximum_bytes),
                        str(int(timeout * 1000)),
                        "TASK_COOKIE:101:task_storage:4:8:0:1",
                        "THREAD_OWNER:102:task_storage:4:544:0:1",
                        "ROOT_AFFILIATION:103:task_storage:4:8:0:1",
                    ])
                    parsed = dumper.parse_task_storage_frames(
                        actual, self.MAPS, max_records=maximum_records, max_bytes=maximum_bytes)
                    self.assertEqual(len(parsed), 0 if maximum_records == 131072 else maximum_records)
                    if maximum_records == 3:
                        self.assertEqual(parsed[1]["value"][536:], b"LATEBYTE")
                    if maximum_records < 4:
                        self.assertEqual(len(actual), maximum_bytes + (maximum_records + 1) * 28)

    def test_task_storage_reader_diagnostic_retains_the_tail_where_the_error_lives(self):
        dumper = load_dumper()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reader, obj = root / "reader", root / "reader.bpf.o"
            obj.write_bytes(b"object")
            # Verbose native tools (libbpf, cargo, gcc, ld) log their chatter
            # first and state the actual failure LAST, so a head-only stderr
            # bound retains exactly the bytes nobody needs. The sentinel is
            # the verifier verdict that ends this session's real failure.
            sentinel = ("program exit: register R0 has smin=4294967295 "
                        "smax=4294967295 should have been in [0, 1]")
            reader.write_text(
                f"#!{sys.executable}\nimport os,sys\n"
                f"os.write(2, {b'libbpf: elf section chatter\\n' * 900!r})\n"
                f"os.write(2, {sentinel.encode() + b'\\n'!r})\n"
                f"sys.exit(9)\n", encoding="utf-8")
            reader.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, "failed with status 9") as raised:
                dumper.run_task_storage_reader(
                    reader, obj, 55, self.MAPS,
                    timeout_seconds=8, max_records=8, max_bytes=4096)
            message = str(raised.exception)
            self.assertIn(sentinel, message)
            self.assertIn("libbpf: elf section chatter", message)
            self.assertIn("bytes dropped]", message)
            self.assertLess(len(message), 4300)

    def test_native_main_bounds_collection_and_never_publishes_failed_frames(self):
        dumper = load_dumper()
        real_popen, real_open, real_close = subprocess.Popen, os.pidfd_open, os.close
        unrelated = real_popen([sys.executable, "-c", "import time; time.sleep(5)"])
        good = self.complete_stream()
        cases = {
            "output": ("os.write(1, b'x' * 4349); time.sleep(5)", "output bound"),
            "eof-timeout": (f"os.write(1, {self.frame(2)!r}); os.close(1); os.close(2); time.sleep(5)",
                            "timed out"),
            "diagnostic": ("os.write(2, b'e' * 50000); sys.exit(7)", "failed with status 7"),
            "magic": (f"os.write(1, {b'BADMAGIC' + good[8:]!r})", "invalid magic"),
            "truncated": (f"os.write(1, {good[:-29]!r})", "truncated"),
            "trailing": (f"os.write(1, {good + b'x'!r})", "after terminal EOF"),
            "missing-eof": (f"os.write(1, {good[:-28]!r})", "before terminal EOF"),
            "eof-metadata": (f"os.write(1, {self.frame(2, map_id=101)!r})", "nonzero metadata"),
            "pidfd-refusal": ("time.sleep(5)", "native pin refusal"),
            "pidfd-close": (f"os.write(1, {good!r})", "native pidfd close failure"),
        }
        inventory = [{"name": "START", "id": 99, "type": "hash", "bytes_key": 8,
                      "bytes_value": 288, "max_entries": 16384, "map_flags": 0}, *self.MAPS]

        def fake_json(args, **_kwargs):
            if args[2:4] == ["map", "show"]:
                return [next(dict(item) for item in inventory if item["id"] == int(args[-1]))]
            self.assertEqual(args[2:], ["map", "dump", "id", "99"])
            return []

        try:
            for case, (body, message) in cases.items():
                with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    reader, obj = root / "reader", root / "reader.bpf.o"
                    obj.write_bytes(b"object")
                    reader.write_text(f"#!{sys.executable}\nimport os,sys,time\n{body}\n", encoding="utf-8")
                    reader.chmod(0o700)
                    children, test_handles, handles, pipes = [], [], [], []

                    def capture_popen(*args, **kwargs):
                        process = real_popen(*args, **kwargs)
                        children.append(process)
                        test_handles.append(real_open(process.pid))
                        pipes.extend([process.stdout or kwargs["stdout"],
                                      process.stderr or kwargs["stderr"]])
                        return process

                    def capture_open(pid, flags=0):
                        if case == "pidfd-refusal":
                            raise OSError("injected native pin refusal")
                        fd = real_open(pid, flags)
                        handles.append(fd)
                        return fd

                    def close_then_fail(fd):
                        real_close(fd)
                        if case == "pidfd-close" and fd in handles:
                            raise OSError("injected native pidfd close failure")

                    argv = ["dump-owned-bpf-maps.py", "55", str(root), "case", "0", "16384",
                            str(reader), str(obj)]
                    try:
                        with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                                mock.patch.object(dumper.os, "pidfd_open", side_effect=capture_open), \
                                mock.patch.object(dumper.os, "close", side_effect=close_then_fail), \
                                mock.patch.object(dumper.glob, "glob", return_value=[]), \
                                mock.patch.object(dumper, "map_ids_from_fdinfo", return_value=[99, 101, 102, 103]), \
                                mock.patch.object(dumper, "run_json", side_effect=fake_json), \
                                mock.patch.object(dumper, "TASK_STORAGE_TIMEOUT_SECONDS", 0.2), \
                                mock.patch.object(dumper, "TASK_STORAGE_MAX_RECORDS", 8), \
                                mock.patch.object(dumper, "TASK_STORAGE_MAX_BYTES", 4096), \
                                mock.patch.object(sys, "argv", argv):
                            with self.assertRaisesRegex((RuntimeError, OSError), message) as raised:
                                dumper.main()
                        self.assertNotIn("LATEBYTE", str(raised.exception))
                        if case in ("output", "eof-timeout", "diagnostic"):
                            self.assertIn("task-storage reader", str(raised.exception))
                            self.assertLess(len(str(raised.exception)), 4300)
                        with self.assertRaises(ChildProcessError):
                            os.waitid(os.P_PIDFD, test_handles[0], os.WEXITED | os.WNOHANG)
                        self.assertTrue(all(pipe.closed for pipe in pipes))
                        for fd in handles:
                            with self.assertRaises(OSError):
                                os.fstat(fd)
                        self.assertEqual(list(root.glob("mapdump_*.bin")), [])
                        self.assertFalse((root / "mapdump_manifest_case.json").exists())
                        self.assertIsNone(unrelated.poll())
                    finally:
                        for fd in test_handles:
                            try:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        for process in children:
                            process.wait(timeout=1)
                        for pipe in pipes:
                            pipe.close()
                        for fd in test_handles:
                            os.close(fd)
        finally:
            unrelated.kill()
            unrelated.wait(timeout=1)

    def test_parser_preserves_full_values_and_late_sentinel(self):
        dumper = load_dumper()
        records = dumper.parse_task_storage_frames(
            self.complete_stream(), self.MAPS, max_records=8, max_bytes=4096
        )
        self.assertEqual(len(records), 3)
        self.assertEqual(len(records[1]["value"]), 544)
        self.assertEqual(records[1]["value"][536:], b"LATEBYTE")
        with tempfile.TemporaryDirectory() as directory:
            paths = dumper.publish_task_storage_surfaces(
                Path(directory), "case", self.MAPS, records
            )
            self.assertEqual(Path(paths["THREAD_OWNER"]).read_bytes()[536:], b"LATEBYTE")
            self.assertTrue(all((Path(path).stat().st_mode & 0o777) == 0o600
                                for path in paths.values()))

    def test_parser_refuses_malformed_duplicate_truncated_overflow_and_missing_eof(self):
        dumper = load_dumper()
        good = self.complete_stream()
        cases = {
            "magic": b"BADMAGIC" + good[8:],
            "duplicate": good[:-28] + good[:36] + self.frame(2),
            "truncated": good[:-29],
            "trailing": good + b"x",
            "missing eof": good[:-28],
        }
        for label, stream in cases.items():
            with self.subTest(label=label):
                with self.assertRaises((RuntimeError, ValueError)):
                    dumper.parse_task_storage_frames(
                        stream, self.MAPS, max_records=8, max_bytes=4096
                    )
        with self.assertRaisesRegex(RuntimeError, "record bound"):
            dumper.parse_task_storage_frames(good, self.MAPS, max_records=2, max_bytes=4096)
        with self.assertRaisesRegex(RuntimeError, "byte bound"):
            dumper.parse_task_storage_frames(good, self.MAPS, max_records=8, max_bytes=543)

    def test_main_uses_reader_and_never_dumps_task_storage(self):
        dumper = load_dumper()
        subject = load_subject(TARGET_BITS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reader = root / "reader"
            obj = root / "reader.bpf.o"
            reader.write_bytes(b"reader")
            reader.chmod(0o700)
            obj.write_bytes(b"object")
            commands = []
            inventory = [
                {"name": "CGROUP_FILTER", "id": 96, "type": "cgroup_array", "bytes_key": 4,
                 "bytes_value": 4, "max_entries": 1, "flags": 0},
                {"name": "OWNER_CTL", "id": 97, "type": "array", "bytes_key": 4,
                 "bytes_value": 56, "max_entries": 1, "flags": 0},
                {"name": "START", "id": 99, "type": "hash", "bytes_key": 8,
                 "bytes_value": 288, "max_entries": 16384, "flags": 0},
                {"name": "PERCPU_TEST", "id": 98, "type": "percpu_array", "bytes_key": 4,
                 "bytes_value": 296, "max_entries": 1, "flags": 0},
                *({key: value for key, value in item.items()
                   if key not in ("map_flags", "oracle")} | {"flags": item["map_flags"]}
                  for item in self.MAPS[:2]),
                {**{key: value for key, value in self.MAPS[2].items()
                    if key not in ("map_flags", "oracle")},
                 "name": "ROOT_AFFILIATIO", "flags": self.MAPS[2]["map_flags"]},
            ]

            def fake_json(args, require_list=False, map_identity=None):
                commands.append(tuple(args))
                if args[2:4] == ["map", "show"]:
                    map_id = int(args[-1])
                    return [next(dict(item) for item in inventory if item["id"] == map_id)]
                if args[2:4] == ["map", "dump"]:
                    if int(args[-1]) == 97:
                        return [{"key": ["0x00"] * 4, "value": ["0x00"] * 56,
                                 "formatted": {"key": 0, "value": {"limit": 0}}}]
                    if int(args[-1]) == 98:
                        planted = bytearray(296)
                        planted[100:100 + len(subject.SENTINELS["PIN"])] = subject.SENTINELS["PIN"]
                        return [{"key": ["0x00"] * 4,
                                 "values": [{"cpu": 0, "value": ["0x00"] * 296},
                                            {"cpu": 1, "value": [
                                                byte for byte in planted
                                            ]}],
                                 "formatted": {"key": 0, "values": [1, 2]}}]
                    return []
                raise AssertionError(f"unexpected bpftool command: {args}")

            argv = [
                "dump-owned-bpf-maps.py", "55", str(root), "case", "0", "16384",
                str(reader.resolve()), str(obj.resolve()),
            ]
            probes = []

            def fake_probe(item, *, fd=None):
                # Stand in for bpf(BPF_MAP_LOOKUP_ELEM) against the observer's
                # own map: one -ENOTSUPP per key, and no value anywhere.
                probes.append((item["id"], fd))
                return [{"key": list(index.to_bytes(item["bytes_key"], "little")),
                         "errno": dumper.ENOTSUPP}
                        for index in range(item["max_entries"])]

            with mock.patch.object(dumper, "map_ids_from_fdinfo",
                                   return_value=[96, 97, 98, 99, 101, 102, 103]), \
                    mock.patch.object(dumper.glob, "glob", return_value=[]), \
                    mock.patch.object(dumper, "run_json", side_effect=fake_json), \
                    mock.patch.object(dumper, "probe_refused_lookup", side_effect=fake_probe), \
                    mock.patch.object(dumper, "possible_cpu_ids", return_value=(0, 1)), \
                    mock.patch.object(dumper, "run_task_storage_reader",
                                      return_value=self.complete_stream()), \
                    mock.patch.object(sys, "argv", argv):
                dumper.main()
            dumped_ids = [int(command[-1]) for command in commands
                          if command[2:5] == ("map", "dump", "id")]
            self.assertEqual(dumped_ids, [97, 98, 99], commands)
            self.assertEqual(probes, [(96, None)])
            manifest = json.loads((root / "mapdump_manifest_case.json").read_text())
            refused = next(item for item in manifest if item["name"] == "CGROUP_FILTER")
            self.assertEqual(refused["oracle"], "refused-lookup")
            self.assertEqual(json.loads(Path(refused["file"]).read_text()),
                             [{"key": ["0x00"] * 4, "errno": 524}])
            self.assertTrue(all("map_flags" in item for item in manifest))
            task_items = [item for item in manifest if item["oracle"] == "task-storage"]
            self.assertEqual(len(task_items), 3)
            self.assertEqual(task_items[-1]["name"], "ROOT_AFFILIATION")
            self.assertTrue(all(Path(item["file"]).is_file() for item in task_items))
            stats = next(item for item in manifest if item["name"] == "PERCPU_TEST")
            cells = json.loads(Path(stats["file"]).read_text())
            self.assertNotIn("formatted", cells[0])
            self.assertEqual([row["cpu"] for row in cells[0]["values"]], [0, 1])
            self.assertEqual(len(cells[0]["values"][1]["value"]), 296)
            self.assertTrue(all(re.fullmatch(r"0x[0-9a-f]{2}", byte)
                                for byte in cells[0]["values"][1]["value"]))
            with self.assertRaisesRegex(AssertionError, "pointer canaries leaked"):
                subject.assert_final_artifact_privacy([Path(stats["file"])])
            owner_control = next(item for item in manifest if item["name"] == "OWNER_CTL")
            self.assertNotIn("formatted", json.loads(Path(owner_control["file"]).read_text())[0])

    def test_main_refuses_to_publish_an_invented_cgroup_array_value(self):
        """A refusal the kernel did not give is never written to disk.

        `main()` normalizes the probe's own cells, so a value beside them or a
        successful lookup fails the run instead of leaving a surface behind.
        """
        dumper = load_dumper()
        inventory = [
            {"name": "CGROUP_FILTER", "id": 96, "type": "cgroup_array", "bytes_key": 4,
             "bytes_value": 4, "max_entries": 1, "flags": 0},
            {"name": "START", "id": 99, "type": "hash", "bytes_key": 16,
             "bytes_value": 288, "max_entries": 16384, "flags": 0},
        ]

        def fake_json(args, **_kwargs):
            if args[2:4] == ["map", "show"]:
                return [next(dict(row) for row in inventory if row["id"] == int(args[-1]))]
            return []

        for case, cells in (
            ("value", [{"key": [0] * 4, "value": [0] * 4}]),
            ("readable", [{"key": [0] * 4, "errno": 0}]),
            ("empty", []),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                reader, obj = root / "reader", root / "reader.bpf.o"
                reader.write_bytes(b"reader")
                reader.chmod(0o700)
                obj.write_bytes(b"object")
                argv = ["dump-owned-bpf-maps.py", "55", str(root), "case", "0", "16384",
                        str(reader.resolve()), str(obj.resolve())]
                with mock.patch.object(dumper, "map_ids_from_fdinfo", return_value=[96, 99]), \
                        mock.patch.object(dumper.glob, "glob", return_value=[]), \
                        mock.patch.object(dumper, "run_json", side_effect=fake_json), \
                        mock.patch.object(dumper, "probe_refused_lookup", return_value=cells), \
                        mock.patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(RuntimeError, "stopped map refusal"):
                        dumper.main()
                self.assertEqual(list(root.glob("mapdump_*")), [])

    def test_main_rejects_returned_id_and_conflicting_flags(self):
        dumper = load_dumper()
        normalized_alias = {"name": "START", "id": 99, "type": "hash", "bytes_key": 8,
                            "bytes_value": 288, "max_entries": 16384, "map_flags": 0}
        self.assertEqual(dumper.normalize_map_metadata(normalized_alias, 99)["map_flags"], 0)
        self.assertEqual(dumper.normalize_map_metadata(
            {**normalized_alias, "flags": 0}, 99)["map_flags"], 0)
        for case in ("returned-id", "flags"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                reader = root / "reader"
                reader.write_bytes(b"reader")
                reader.chmod(0o700)
                obj = root / "reader.bpf.o"
                obj.write_bytes(b"object")
                item = {"name": "START", "id": 99, "type": "hash", "bytes_key": 8,
                        "bytes_value": 288, "max_entries": 16384, "flags": 0}
                if case == "returned-id":
                    item["id"] = 100
                else:
                    item["map_flags"] = 1
                argv = ["dump-owned-bpf-maps.py", "55", str(root), "case", "0", "16384",
                        str(reader.resolve()), str(obj.resolve())]
                with mock.patch.object(dumper, "map_ids_from_fdinfo", return_value=[99]), \
                        mock.patch.object(dumper.glob, "glob", return_value=[]), \
                        mock.patch.object(dumper, "run_json", return_value=[item]), \
                        mock.patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(RuntimeError, "map metadata"):
                        dumper.main()
                self.assertFalse((root / "mapdump_manifest_case.json").exists())

    def test_raw_dump_normalization_rejects_formatted_only_and_preserves_percpu(self):
        dumper = load_dumper()
        metadata = {"id": 7, "name": "COUNTERS", "type": "percpu_array",
                    "oracle": "dump", "bytes_key": 4, "bytes_value": 8,
                    "max_entries": 1, "map_flags": 0}
        cell = {"key": ["0x00"] * 4,
                "values": [{"cpu": 0, "value": ["0x01"] * 8},
                           {"cpu": 1, "value": ["0x02"] * 8}],
                "formatted": {"key": 0, "values": [1, 2]}}
        normalized = dumper.normalize_map_dump([cell], metadata, possible_cpus=(0, 1))
        self.assertEqual(normalized, [{"key": cell["key"], "values": cell["values"]}])
        reversed_cell = {**cell, "values": list(reversed(cell["values"]))}
        self.assertEqual(dumper.normalize_map_dump(
            [reversed_cell], metadata, possible_cpus=(0, 1)), normalized)
        mutations = [
            {"key": cell["key"], "formatted": {}},
            {**cell, "formatted": []},
            {**cell, "value": ["0x00"] * 8},
            {**cell, "values": [cell["values"][0], dict(cell["values"][0])]},
            {**cell, "values": [{"cpu": 0, "value": ["0x01"] * 7}]},
            {**cell, "values": [{"cpu": 0, "value": ["0x01"] * 8}]},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(RuntimeError, "raw map dump"):
                    dumper.normalize_map_dump([mutation], metadata, possible_cpus=(0, 1))
        control = {"id": 8, "name": "OWNER_CTL", "type": "array", "oracle": "dump",
                   "bytes_key": 4, "bytes_value": 56, "max_entries": 1, "map_flags": 0}
        with self.assertRaisesRegex(RuntimeError, "raw map dump"):
            dumper.normalize_map_dump([{"formatted": {"key": 0, "value": {}}}], control)
        for invalid_byte in (True, -1, 256):
            with self.subTest(invalid_byte=invalid_byte):
                with self.assertRaisesRegex(RuntimeError, "malformed byte array"):
                    dumper.normalize_map_dump(
                        [{"key": [invalid_byte] + [0] * 3, "value": [0] * 56}], control)
        incomplete_array = {**control, "max_entries": 2}
        with self.assertRaisesRegex(RuntimeError, "incomplete array keys"):
            dumper.normalize_map_dump(
                [{"key": ["0x00"] * 4, "value": ["0x00"] * 56}], incomplete_array)
        sparse = {"id": 9, "name": "SPARSE", "type": "prog_array", "oracle": "dump",
                  "bytes_key": 4, "bytes_value": 4, "max_entries": 8, "map_flags": 0}
        self.assertEqual(len(dumper.normalize_map_dump(
            [{"key": ["0x03", "0x00", "0x00", "0x00"], "value": ["0x01"] * 4}],
            sparse)), 1)
        with tempfile.TemporaryDirectory() as directory:
            possible = Path(directory) / "possible"
            possible.write_text("0-1,4\n", encoding="ascii")
            self.assertEqual(dumper.possible_cpu_ids(possible), (0, 1, 4))
            possible.write_text("0-1,1\n", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "duplicates"):
                dumper.possible_cpu_ids(possible)

    def test_bounded_json_acquisition_rejects_duplicates_timeout_and_output(self):
        dumper = load_dumper()
        real_popen = dumper.subprocess.Popen
        spawned = []

        def capture_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
        try:
            cases = (
                ("duplicate", [sys.executable, "-c", "print('{\\\"id\\\":1,\\\"id\\\":2}')"],
                 1, 1024, "duplicate"),
                ("timeout", [sys.executable, "-c", "import time; time.sleep(2)"],
                 0.2, 1024, "timed out"),
                ("output", [sys.executable, "-c", "print('x' * 100000)"],
                 1, 1024, "output bound"),
            )
            acquisition_process = None
            # The timeout child's pid is captured synchronously in the
            # parent via the Popen spy: a pidfile the 0.2 s budget could
            # kill the child before writing raised FileNotFoundError here
            # under load. The reaped/unreusable-pid assertions are verbatim.
            with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen):
                for label, command, timeout, maximum, message in cases:
                    with self.subTest(label=label):
                        with self.assertRaisesRegex(RuntimeError, message):
                            dumper.run_json(command, timeout_seconds=timeout, max_bytes=maximum)
                        if label == "timeout":
                            acquisition_process = spawned[-1]
            acquisition_pid = acquisition_process.pid
            with self.assertRaises(ProcessLookupError):
                os.kill(acquisition_pid, 0)
            with self.assertRaises(ChildProcessError):
                os.waitpid(acquisition_pid, os.WNOHANG)
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait()
        for timeout, maximum in ((0, 1024), (float("inf"), 1024), (1, 0),
                                 (1, dumper.JSON_OUTPUT_MAX_BYTES + 1)):
            with self.subTest(timeout=timeout, maximum=maximum):
                with self.assertRaisesRegex(RuntimeError, "invalid bounds"):
                    dumper.run_json([sys.executable, "-c", "print('[]')"],
                                    timeout_seconds=timeout, max_bytes=maximum)

    def test_json_acquisition_deadline_includes_exit_after_pipe_eof(self):
        dumper = load_dumper()
        real_popen = dumper.subprocess.Popen
        spawned = []

        def capture_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        # The child pid is captured synchronously in the parent via the
        # Popen spy, not via a pidfile the child must win a race to write:
        # under load the deadline expired before a slow child wrote it and
        # the post-hoc read failed with FileNotFoundError. The budgets below
        # are test conveniences, not the contract: the property under test
        # (post-EOF exit wait covered by the deadline, "timed out" raised,
        # owned child reaped with an unreusable pid) is asserted verbatim.
        command = ["/bin/sh", "-c",
                   "printf '[]'; exec 1>&- 2>&-; exec /bin/sleep 3",
                   "sh"]
        previous = signal.signal(
            signal.SIGALRM,
            lambda _signal, _frame: (_ for _ in ()).throw(
                TimeoutError("outer watchdog: run_json blocked past deadline")),
        )
        signal.setitimer(signal.ITIMER_REAL, 10)
        try:
            with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen):
                with self.assertRaisesRegex(RuntimeError, "timed out"):
                    dumper.run_json(command, timeout_seconds=2, max_bytes=1024)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        child_pid = spawned[0].pid
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child_pid, os.WNOHANG)

    def test_json_acquisition_setup_and_cleanup_failures_reap_only_owned_child(self):
        dumper = load_dumper()
        real_popen = dumper.subprocess.Popen
        real_selector = dumper.selectors.DefaultSelector

        class SelectorFailure:
            def __init__(self, fail_register=None, fail_close=False):
                self.inner = real_selector()
                self.fail_register = fail_register
                self.fail_close = fail_close
                self.register_calls = 0

            def register(self, *args):
                self.register_calls += 1
                if self.register_calls == self.fail_register:
                    raise OSError(f"injected register {self.register_calls} failure")
                return self.inner.register(*args)

            def unregister(self, *args):
                return self.inner.unregister(*args)

            def get_map(self):
                return self.inner.get_map()

            def select(self, *args):
                return self.inner.select(*args)

            def close(self):
                self.inner.close()
                if self.fail_close:
                    raise OSError("injected selector close failure")

        unrelated = real_popen([sys.executable, "-c", "import time; time.sleep(3)"])
        try:
            for case in ("constructor", "register-1", "register-2", "close"):
                with self.subTest(case=case):
                    spawned = []
                    selectors = []

                    def capture_popen(*args, **kwargs):
                        process = real_popen(*args, **kwargs)
                        spawned.append(process)
                        return process

                    def selector_factory():
                        if case == "constructor":
                            raise OSError("injected selector construction failure")
                        selector = SelectorFailure(
                            fail_register={"register-1": 1, "register-2": 2}.get(case),
                            fail_close=case == "close",
                        )
                        selectors.append(selector)
                        return selector

                    child = [sys.executable, "-c", (
                        "print('[]', flush=True)" if case == "close" else
                        "import time; print('[]', flush=True); time.sleep(2)"
                    )]
                    expected = ("construction" if case == "constructor" else
                                "register" if case.startswith("register") else "close")
                    with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                            mock.patch.object(dumper.selectors, "DefaultSelector",
                                              side_effect=selector_factory):
                        with self.assertRaisesRegex(OSError, expected):
                            dumper.run_json(child, timeout_seconds=0.2, max_bytes=1024)
                    process = spawned[0]
                    self.assertIsNotNone(process.poll())
                    self.assertTrue(process.stdout.closed)
                    self.assertTrue(process.stderr.closed)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(process.pid, 0)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(process.pid, os.WNOHANG)
                    if selectors:
                        with self.assertRaises(ValueError):
                            selectors[0].select(0)
                    self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait()

    def test_json_acquisition_combines_legacy_primary_and_cleanup_errors(self):
        dumper = load_dumper()
        real_popen = dumper.subprocess.Popen
        real_selector = dumper.selectors.DefaultSelector
        spawned = []

        class LegacyPrimary(RuntimeError):
            add_note = None

        class FailingSelector:
            def __init__(self):
                self.inner = real_selector()

            def register(self, *args):
                return self.inner.register(*args)

            def get_map(self):
                return self.inner.get_map()

            def select(self, *_args):
                raise LegacyPrimary("legacy acquisition failure")

            def close(self):
                self.inner.close()
                raise OSError("secondary selector cleanup failure")

        def capture_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        child = [sys.executable, "-c", "import time; time.sleep(2)"]
        with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                mock.patch.object(dumper.selectors, "DefaultSelector",
                                  side_effect=FailingSelector):
            with self.assertRaisesRegex(LegacyPrimary, "legacy acquisition") as raised:
                dumper.run_json(child, timeout_seconds=0.2, max_bytes=1024)
        self.assertIsInstance(raised.exception.__cause__, OSError)
        self.assertIn("secondary selector cleanup", str(raised.exception.__cause__))
        process = spawned[0]
        self.assertTrue(process.stdout.closed and process.stderr.closed)
        with self.assertRaises(ProcessLookupError):
            os.kill(process.pid, 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def test_json_acquisition_owns_child_across_initialization_and_cleanup_entry(self):
        dumper = load_dumper()
        real_popen = dumper.subprocess.Popen
        unrelated = real_popen([sys.executable, "-c", "import time; time.sleep(3)"])

        def watchdog(_signal, _frame):
            raise TimeoutError("outer watchdog: acquisition cleanup blocked")

        previous = signal.signal(signal.SIGALRM, watchdog)
        try:
            with self.subTest(case="pre-spawn-allocation"):
                spawned = []

                def capture_popen(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    spawned.append(process)
                    return process

                with mock.patch.object(dumper, "bytearray", side_effect=MemoryError(
                        "injected allocation failure"), create=True), \
                        mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen):
                    with self.assertRaisesRegex(MemoryError, "allocation"):
                        dumper.run_json(
                            [sys.executable, "-c", "import time; time.sleep(2)"],
                            timeout_seconds=0.2, max_bytes=1024)
                did_spawn = bool(spawned)
                for process in spawned:
                    os.kill(process.pid, signal.SIGKILL)
                    process.wait()
                    process.stdout.close()
                    process.stderr.close()
                self.assertFalse(did_spawn, "fallible buffer allocation must precede Popen")

            for case in ("first-protected-step", "cleanup-entry"):
                with self.subTest(case=case):
                    spawned = []

                    def prepared_popen(*args, **kwargs):
                        process = capture_popen(*args, **kwargs)
                        if case == "cleanup-entry":
                            process.poll = mock.Mock(side_effect=KeyboardInterrupt(
                                "injected cleanup-entry poll interruption"))
                        return process

                    patches = [mock.patch.object(
                        dumper.subprocess, "Popen", side_effect=prepared_popen)]
                    if case == "first-protected-step":
                        patches.append(mock.patch.object(
                            dumper.time, "monotonic", side_effect=MemoryError(
                                "injected first protected step failure")))
                    else:
                        patches.append(mock.patch.object(
                            dumper.selectors, "DefaultSelector",
                            side_effect=OSError("injected selector setup failure")))
                    signal.setitimer(signal.ITIMER_REAL, 0.7)
                    caught = None
                    try:
                        with patches[0], patches[1]:
                            try:
                                dumper.run_json(
                                    [sys.executable, "-c", "import time; time.sleep(2)"],
                                    timeout_seconds=0.2, max_bytes=1024)
                            except BaseException as error:
                                caught = error
                    finally:
                        signal.setitimer(signal.ITIMER_REAL, 0)
                    process = spawned[0]
                    real_poll = type(process).poll
                    was_reaped = real_poll(process) is not None
                    pipes_closed = process.stdout.closed and process.stderr.closed
                    if not was_reaped:
                        os.kill(process.pid, signal.SIGKILL)
                        type(process).wait(process)
                    process.stdout.close()
                    process.stderr.close()
                    expected = MemoryError if case == "first-protected-step" else OSError
                    self.assertIsInstance(caught, expected)
                    self.assertTrue(was_reaped)
                    self.assertTrue(pipes_closed)
                    self.assertIsNone(unrelated.poll())
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
            unrelated.terminate()
            unrelated.wait()

    def test_json_acquisition_retains_identity_after_wait_reaps_then_interrupts(self):
        dumper = load_dumper()
        real_popen = subprocess.Popen
        real_open = os.pidfd_open
        real_send = signal.pidfd_send_signal
        real_selector = dumper.selectors.DefaultSelector
        spawned, handles, selectors, deliveries, raw_signals = [], [], [], [], []
        unrelated = real_popen([sys.executable, "-c", "import time; time.sleep(5)"])

        def capture_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            original_wait = process.wait
            interrupted = False

            def reap_then_interrupt(*args, **kwargs):
                nonlocal interrupted
                result = original_wait(*args, **kwargs)
                if not interrupted:
                    interrupted = True
                    self.assertEqual(result, 0)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(process.pid, os.WNOHANG)
                    raise KeyboardInterrupt("injected after actual reap")
                return result

            process.wait = reap_then_interrupt
            return process

        def capture_open(pid, flags=0):
            fd = real_open(pid, flags)
            handles.append(fd)
            return fd

        def capture_send(fd, sig, *args):
            # This really signals the retained kernel handle after waitpid
            # has proved the child reaped; it must report ESRCH, not retarget.
            try:
                return real_send(fd, sig, *args)
            except ProcessLookupError:
                deliveries.append((fd, sig, "already reaped"))
                raise

        def capture_selector():
            selector = real_selector()
            selectors.append(selector)
            return selector

        previous = signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(
            TimeoutError("outer watchdog: post-reap cleanup blocked")))
        signal.setitimer(signal.ITIMER_REAL, 2)
        try:
            with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                    mock.patch.object(dumper.os, "pidfd_open", side_effect=capture_open), \
                    mock.patch.object(dumper.signal, "pidfd_send_signal", side_effect=capture_send), \
                    mock.patch.object(dumper.selectors, "DefaultSelector", side_effect=capture_selector), \
                    mock.patch.object(dumper.os, "kill", side_effect=lambda *args: raw_signals.append(args)):
                with self.assertRaisesRegex(KeyboardInterrupt, "after actual reap"):
                    dumper.run_json([sys.executable, "-c", "print('[]')"],
                                    timeout_seconds=0.5, max_bytes=1024)
            self.assertEqual(raw_signals, [], "cleanup must never signal a reaped numeric PID")
            self.assertEqual(len(handles), 1)
            self.assertEqual(deliveries, [(handles[0], signal.SIGKILL, "already reaped")])
            with self.assertRaises(OSError):
                os.fstat(handles[0])
            self.assertTrue(spawned[0].stdout.closed and spawned[0].stderr.closed)
            with self.assertRaises(ValueError):
                selectors[0].select(0)
            self.assertIsNone(unrelated.poll())
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
            for process in spawned:
                if process.poll() is None:
                    process.kill()
                type(process).wait(process, timeout=1)
                process.stdout.close()
                process.stderr.close()
            unrelated.kill()
            unrelated.wait(timeout=1)

    def test_json_acquisition_pidfd_refusal_requires_waitable_child(self):
        dumper = load_dumper()
        real_popen, real_kill = subprocess.Popen, os.kill
        unrelated = real_popen([sys.executable, "-c", "import time; time.sleep(5)"])
        previous = signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(
            TimeoutError("outer watchdog: pidfd refusal cleanup blocked")))
        try:
            for case in ("live", "zombie", "reaped", "waitability-refused"):
                with self.subTest(case=case):
                    spawned, signals = [], []

                    def capture_popen(*args, **kwargs):
                        process = real_popen(*args, **kwargs)
                        spawned.append(process)
                        return process

                    def refuse_pidfd(pid, _flags=0):
                        if case == "zombie":
                            result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
                            self.assertEqual(result.si_pid, pid)
                        elif case == "reaped":
                            spawned[0].wait(timeout=1)
                        raise OSError("injected pidfd acquisition refusal")

                    def owned_kill(pid, sig):
                        # Never forward an attempted stale/unrelated PID signal.
                        self.assertEqual(pid, spawned[0].pid)
                        if case in ("reaped", "waitability-refused"):
                            signals.append("unsafe signal")
                            return
                        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        signals.append(sig)
                        real_kill(pid, sig)

                    wait_patch = (mock.patch.object(dumper.os, "waitid", side_effect=OSError(
                        "injected waitability refusal")) if case == "waitability-refused"
                        else mock.patch.object(dumper.os, "waitid", wraps=os.waitid))
                    signal.setitimer(signal.ITIMER_REAL, 2)
                    try:
                        with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                                mock.patch.object(dumper.os, "pidfd_open", side_effect=refuse_pidfd), \
                                mock.patch.object(dumper.os, "kill", side_effect=owned_kill), \
                                mock.patch.object(dumper.selectors, "DefaultSelector", side_effect=
                                                  AssertionError("acquisition continued without pidfd")), \
                                wait_patch:
                            with self.assertRaisesRegex(OSError, "pidfd acquisition refusal") as raised:
                                dumper.run_json([sys.executable, "-c", (
                                    "print('[]')" if case in ("zombie", "reaped") else
                                    "import time; time.sleep(5)")], timeout_seconds=0.1, max_bytes=1024)
                        self.assertEqual(signals, [signal.SIGKILL] if case in ("live", "zombie") else [])
                        self.assertTrue(spawned[0].stdout.closed and spawned[0].stderr.closed)
                        if case == "waitability-refused":
                            self.assertIsNone(spawned[0].poll())
                            self.assertIsInstance(raised.exception.__cause__, subprocess.TimeoutExpired)
                            self.assertIn("waitability refusal", str(raised.exception.__cause__.__cause__))
                        else:
                            with self.assertRaises(ChildProcessError):
                                os.waitpid(spawned[0].pid, os.WNOHANG)
                        self.assertIsNone(unrelated.poll())
                    finally:
                        signal.setitimer(signal.ITIMER_REAL, 0)
                        for process in spawned:
                            if process.poll() is None:
                                process.kill()
                            process.wait(timeout=1)
                            process.stdout.close()
                            process.stderr.close()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
            unrelated.kill()
            unrelated.wait(timeout=1)

    def test_json_acquisition_pidfd_close_failure_is_nonpass_and_chained(self):
        dumper = load_dumper()
        real_popen, real_open, real_close = subprocess.Popen, os.pidfd_open, os.close
        real_selector = dumper.selectors.DefaultSelector
        for fail_acquisition in (False, True):
            with self.subTest(fail_acquisition=fail_acquisition):
                spawned, handles, selectors = [], [], []

                def capture_popen(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    spawned.append(process)
                    return process

                def capture_open(pid, flags=0):
                    fd = real_open(pid, flags)
                    handles.append(fd)
                    return fd

                def close_then_fail(fd):
                    real_close(fd)
                    if fd in handles:
                        raise OSError("injected pidfd close failure")

                def capture_selector():
                    selector = real_selector()
                    selectors.append(selector)
                    if fail_acquisition:
                        selector.select = mock.Mock(side_effect=KeyboardInterrupt(
                            "injected retained acquisition failure"))
                        original_close = selector.close

                        def close_selector():
                            original_close()
                            raise OSError("injected additional selector close failure")

                        selector.close = close_selector
                    return selector

                try:
                    with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                            mock.patch.object(dumper.os, "pidfd_open", side_effect=capture_open), \
                            mock.patch.object(dumper.os, "close", side_effect=close_then_fail), \
                            mock.patch.object(dumper.selectors, "DefaultSelector", side_effect=capture_selector):
                        expected = KeyboardInterrupt if fail_acquisition else OSError
                        with self.assertRaisesRegex(expected, "acquisition failure" if fail_acquisition
                                                    else "pidfd close failure") as raised:
                            dumper.run_json([sys.executable, "-c", "print('[]')"],
                                            timeout_seconds=0.5, max_bytes=1024)
                    errors = []
                    error = raised.exception
                    while error is not None:
                        errors.append(str(error))
                        error = error.__cause__
                    self.assertTrue(any("pidfd close failure" in error for error in errors))
                    if fail_acquisition:
                        self.assertTrue(any("selector close failure" in error for error in errors))
                    self.assertEqual(len(handles), 1)
                    with self.assertRaises(OSError):
                        os.fstat(handles[0])
                    self.assertTrue(spawned[0].stdout.closed and spawned[0].stderr.closed)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(spawned[0].pid, os.WNOHANG)
                    with self.assertRaises(ValueError):
                        type(selectors[0]).select(selectors[0], 0)
                finally:
                    for process in spawned:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=1)
                        process.stdout.close()
                        process.stderr.close()

    def test_json_acquisition_refuses_nonretaining_sigchld_before_spawn(self):
        dumper = load_dumper()
        for handler in (signal.SIG_IGN, lambda *_args: None):
            with self.subTest(handler=handler):
                previous = signal.signal(signal.SIGCHLD, handler)
                try:
                    with mock.patch.object(dumper.subprocess, "Popen", side_effect=AssertionError(
                            "spawned with unsupported child wait ownership")):
                        with self.assertRaisesRegex(RuntimeError, "SIGCHLD"):
                            dumper.run_json([sys.executable, "-c", "print('[]')"])
                finally:
                    signal.signal(signal.SIGCHLD, previous)

    def test_json_acquisition_defers_signals_until_owned_and_restores_masks(self):
        dumper = load_dumper()
        real_popen, real_open = subprocess.Popen, os.pidfd_open
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        previous = signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(
            TimeoutError("outer watchdog: deferred signal cleanup blocked")))
        try:
            for case in ("spawn", "pin", "pin-refused"):
                with self.subTest(case=case):
                    spawned, handles = [], []

                    def capture_popen(*args, **kwargs):
                        process = real_popen(*args, **kwargs)
                        spawned.append(process)
                        if case == "spawn":
                            os.kill(os.getpid(), signal.SIGINT)
                        return process

                    def capture_open(pid, flags=0):
                        if case == "pin-refused":
                            os.kill(os.getpid(), signal.SIGINT)
                            raise OSError("injected pidfd refusal with pending interrupt")
                        fd = real_open(pid, flags)
                        handles.append(fd)
                        if case == "pin":
                            os.kill(os.getpid(), signal.SIGINT)
                        return fd

                    signal.setitimer(signal.ITIMER_REAL, 2)
                    try:
                        with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                                mock.patch.object(dumper.os, "pidfd_open", side_effect=capture_open):
                            with self.assertRaises(OSError if case == "pin-refused" else
                                                   RuntimeError) as raised:
                                dumper.run_json([sys.executable, "-c", "import time; time.sleep(5)"],
                                                timeout_seconds=0.2, max_bytes=1024)
                        self.assertIn("pidfd refusal" if case == "pin-refused" else "timed out",
                                      str(raised.exception))
                        self.assertIsInstance(raised.exception.__cause__, KeyboardInterrupt)
                        self.assertTrue(spawned[0].stdout.closed and spawned[0].stderr.closed)
                        with self.assertRaises(ChildProcessError):
                            os.waitpid(spawned[0].pid, os.WNOHANG)
                        self.assertEqual(len(handles), 0 if case == "pin-refused" else 1)
                        for fd in handles:
                            with self.assertRaises(OSError):
                                os.fstat(fd)
                        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), original_mask)
                    finally:
                        signal.setitimer(signal.ITIMER_REAL, 0)
                        for process in spawned:
                            if process.poll() is None:
                                process.kill()
                            process.wait(timeout=1)
                            process.stdout.close()
                            process.stderr.close()

            # Preserve even a pre-existing caller mask in the actual exec'd
            # helper; temporary SIGINT/SIGALRM blocks must not survive exec.
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
            expected_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
            actual = dumper.run_json([sys.executable, "-c", (
                "import json,signal; "
                "print(json.dumps(sorted(signal.pthread_sigmask(signal.SIG_BLOCK, []))))")],
                timeout_seconds=0.5, max_bytes=1024)
            self.assertEqual(actual, sorted(expected_mask))
            for sig in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(child_signal=sig):
                    with self.assertRaisesRegex(RuntimeError, "failed"):
                        dumper.run_json([sys.executable, "-c", (
                            f"import os,signal; signal.signal({int(sig)}, signal.SIG_DFL); "
                            f"os.kill(os.getpid(), {int(sig)}); print('[]')")],
                            timeout_seconds=0.5, max_bytes=1024)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            signal.signal(signal.SIGALRM, previous)

    def test_json_acquisition_refuses_concurrent_threads_before_spawn(self):
        dumper = load_dumper()
        release = threading.Event()
        worker = threading.Thread(target=lambda: release.wait(2))
        worker.start()
        try:
            with mock.patch.object(dumper.subprocess, "Popen", side_effect=AssertionError(
                    "spawned with concurrent thread")):
                with self.assertRaisesRegex(RuntimeError, "one main thread"):
                    dumper.run_json([sys.executable, "-c", "print('[]')"])
        finally:
            release.set()
            worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

    def test_json_acquisition_records_mask_before_interruptible_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "interrupt-mask.c"
            library = Path(directory) / "interrupt-mask.so"
            source.write_text(
                "#include <signal.h>\n#include <pthread.h>\n"
                "int interrupt_then_block(void) {\n"
                "  sigset_t mask;\n"
                "  sigemptyset(&mask); sigaddset(&mask, SIGINT);\n"
                "  if (raise(SIGINT) != 0) return -1;\n"
                "  return pthread_sigmask(SIG_BLOCK, &mask, 0);\n}\n",
                encoding="ascii",
            )
            compiled = subprocess.run(
                ["cc", "-shared", "-fPIC", "-pthread", str(source), "-o", str(library)],
                text=True, capture_output=True, timeout=10, check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            command = (
                f"import runpy; m=runpy.run_path({str(Path(__file__).resolve())!r}); "
                f"m['json_signal_lifetime_probe']('mask-mutation', {str(library)!r})"
            )
            result = subprocess.run(
                ["timeout", "--kill-after=1s", "3s", sys.executable, "-I", "-c", command],
                text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["injected"])
            self.assertEqual(report["errors"][0]["type"], "KeyboardInterrupt")
            self.assertEqual(report["spawn_count"], 0)
            self.assertEqual(report["mask_after"], report["mask_before"])
            self.assertTrue(report["unrelated_alive"])

    def test_json_acquisition_defers_actual_signal_across_cleanup_entry_and_steps(self):
        for case in ("entry", "entry-live", "between-steps"):
            with self.subTest(case=case):
                command = (
                    f"import runpy; m=runpy.run_path({str(Path(__file__).resolve())!r}); "
                    f"m['json_signal_lifetime_probe']({case!r})"
                )
                result = subprocess.run(
                    ["timeout", "--kill-after=1s", "3s", sys.executable, "-I", "-c", command],
                    text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertTrue(report["injected"])
                self.assertTrue(any(error["type"] == "KeyboardInterrupt"
                                    for error in report["errors"]))
                if case == "entry-live":
                    self.assertEqual(report["errors"][0]["type"], "RuntimeError")
                    self.assertIn("timed out", report["errors"][0]["message"])
                self.assertEqual(report["spawn_count"], 1)
                self.assertEqual(report["reaped"], [True])
                self.assertEqual(report["pipes_closed"], [True])
                self.assertEqual(report["pidfds_closed"], [True])
                self.assertEqual(report["selectors_closed"], [True])
                self.assertEqual(report["mask_after"], report["mask_before"])
                self.assertTrue(report["unrelated_alive"])

    def test_json_acquisition_probe_watchdog_terminates_only_its_scope(self):
        # Exercise the external watchdog, including descendants whose cleanup
        # cannot run once their probe parent is terminated. A separate child
        # outside the timeout-created process group must survive. Become the
        # temporary subreaper so exit-readiness is followed by actual reaping.
        libc = ctypes.CDLL(None, use_errno=True)
        original_subreaper = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(original_subreaper), 0, 0, 0), 0)
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "scope.json"
            unrelated = None
            watchdog = None
            handles = []
            selector_module = load_dumper().selectors
            selector = selector_module.DefaultSelector()
            try:
                self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
                enabled = ctypes.c_int()
                self.assertEqual(libc.prctl(37, ctypes.byref(enabled), 0, 0, 0), 0)
                self.assertEqual(enabled.value, 1)
                # The probe child imports the small entry module instead of
                # this whole test file via runpy, and the waits below are
                # scaled so slow startup under load cannot beat them. The
                # property under test (the external watchdog kills the
                # lingering probe scope, exit 124) is asserted verbatim;
                # only startup headroom grows.
                unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
                watchdog = subprocess.Popen(
                    ["timeout", "--kill-after=0.2s", "6s", sys.executable, "-I",
                     str(PROBE_ENTRY), "watchdog-stall", str(pidfile)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                deadline = time.monotonic() + 5
                while not pidfile.exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(
                    pidfile.exists(),
                    f"probe did not publish {pidfile.name} within 5 s "
                    f"(watchdog poll={watchdog.poll()})",
                )
                pids = json.loads(pidfile.read_text())
                self.assertEqual(len(pids), 3)
                for pid in pids:
                    fd = os.pidfd_open(pid)
                    handles.append(fd)
                    selector.register(fd, selector_module.EVENT_READ)
                self.assertEqual(selector.select(0), [])
                _stdout, stderr = watchdog.communicate(timeout=25)
                self.assertEqual(watchdog.returncode, 124, stderr)
                exited = set()
                deadline = time.monotonic() + 0.5
                while len(exited) < len(handles) and time.monotonic() < deadline:
                    for key, _event in selector.select(max(0, deadline - time.monotonic())):
                        exited.add(key.fd)
                        selector.unregister(key.fd)
                self.assertEqual(exited, set(handles), "watchdog left a live owned descendant")
                # timeout reaps its immediate probe before it exits. Only
                # the probe's two children are adopted by this subreaper.
                with self.assertRaises(ChildProcessError):
                    os.waitid(os.P_PIDFD, handles[0], os.WEXITED | os.WNOHANG)
                for pid, fd in zip(pids[1:], handles[1:]):
                    status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                    self.assertIsNotNone(status, "exit-ready descendant was not waitable")
                    self.assertEqual(status.si_pid, pid)
                    self.assertEqual(status.si_code, os.CLD_KILLED)
                    self.assertEqual(status.si_status, signal.SIGTERM)
                    with self.assertRaises(ChildProcessError):
                        os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                self.assertIsNone(unrelated.poll())
            finally:
                cleanup_errors = []

                def cleanup(action):
                    try:
                        action()
                    except BaseException as error:
                        cleanup_errors.append(error)

                # Leave the independent watchdog alive to settle its scope
                # even if PID publication or an earlier assertion failed.
                if watchdog is not None:
                    cleanup(lambda: watchdog.wait(timeout=25))
                for fd in handles:
                    def settle_retained(fd=fd):
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        deadline = time.monotonic() + 1
                        while True:
                            try:
                                status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                            except ChildProcessError:
                                return  # Already reaped by the assertion above.
                            if status is not None:
                                return
                            if time.monotonic() >= deadline:
                                raise TimeoutError("watchdog descendant did not settle")
                            time.sleep(0.005)

                    cleanup(settle_retained)
                    cleanup(lambda fd=fd: os.close(fd))
                cleanup(selector.close)
                if watchdog is not None:
                    cleanup(watchdog.stdout.close)
                    cleanup(watchdog.stderr.close)
                if unrelated is not None:
                    cleanup(unrelated.kill)
                    cleanup(lambda: unrelated.wait(timeout=1))
                cleanup(lambda: self.assertEqual(libc.prctl(36, original_subreaper.value, 0, 0, 0), 0))
                self.assertEqual(cleanup_errors, [])

    def test_main_refuses_without_reader_before_manifest(self):
        dumper = load_dumper()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            argv = ["dump-owned-bpf-maps.py", "55", str(root), "case", "0", "16384"]
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaisesRegex((RuntimeError, SystemExit), "(?i)reader"):
                    dumper.main()
            self.assertFalse((root / "mapdump_manifest_case.json").exists())

    def test_timeout_and_bounded_start_diagnostics_leave_no_surface(self):
        dumper = load_dumper()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sleeper = root / "reader"
            sleeper.write_text("#!/bin/sh\nsleep 2\n", encoding="utf-8")
            sleeper.chmod(0o700)
            obj = root / "reader.bpf.o"
            obj.write_bytes(b"object")
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                dumper.run_task_storage_reader(
                    sleeper, obj, 55, self.MAPS, timeout_seconds=0.01,
                    max_records=8, max_bytes=4096,
                )
            self.assertEqual(list(root.glob("mapdump_*.bin")), [])
            real_write = dumper.write_binary_receipt
            calls = 0

            def fail_second(path, value):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected publish failure")
                real_write(path, value)

            records = dumper.parse_task_storage_frames(
                self.complete_stream(), self.MAPS, max_records=8, max_bytes=4096
            )
            with mock.patch.object(dumper, "write_binary_receipt", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "injected publish failure"):
                    dumper.publish_task_storage_surfaces(root, "partial", self.MAPS, records)
            self.assertEqual(list(root.glob("mapdump_*_partial.bin")), [])
        error = None
        try:
            dumper.checked_json(
                ["bpftool"], 1, "", "x" * 10000,
                map_identity={"id": 77, "name": "START", "type": "hash"},
            )
        except RuntimeError as caught:
            error = str(caught)
        self.assertIsNotNone(error)
        self.assertIn("id=77 name=START type=hash", error)
        self.assertLess(len(error), 5000)


class StoppedPopulationTests(unittest.TestCase):
    """Valid EOF and byte counts cannot substitute for exact stopped owners."""

    def fixture(self, root, *, owned=False, empty=False):
        tasks = [
            {"pid": 7001, "tid": tid, "generation": generation,
             "cookie": tid == 7001, "owner": tid != 7001, "root": owned}
            for tid, generation in ((7001, 900), (7002, 901), (7003, 902))
        ]
        if empty:
            for task in tasks:
                task.update(cookie=False, owner=False, root=False)
        roster = [{**{k: task[k] for k in ("pid", "tid", "generation")}, "state": "T"}
                  for task in tasks]
        receipt = {
            "contract": "p11scope/stopped-task-storage/v1",
            "acquisition_id": "a" * 32, "phase": "stopped",
            "lane": "owned-root" if owned else "external", "small_state": False,
            "expected": tasks, "before": roster, "after": copy.deepcopy(roster),
            "surfaces": [],
        }
        manifest = []
        for spec in TaskStorageReaderTests.MAPS:
            manifest.append({"id": spec["id"], "name": spec["name"],
                             "type": "task_storage", "key_size": 4,
                             "value_size": spec["bytes_value"], "max_entries": 0,
                             "map_flags": 1, "oracle": "task-storage"})
        for name, map_id, size in (("COOKIE_CTL", 104, 40), ("OWNER_CTL", 105, 56),
                                   ("ROOT_CTL", 106, 64), ("START", 107, 288)):
            manifest.append({"id": map_id, "name": name,
                             "type": "hash" if name == "START" else "array",
                             "key_size": 16 if name == "START" else 4,
                             "value_size": size, "max_entries": 16384 if name == "START" else 1,
                             "map_flags": 0, "oracle": "dump"})
        for name, map_id in (("EVENTS", 108), ("DISCOVERY", 109)):
            manifest.append({"id": map_id, "name": name, "type": "ringbuf",
                             "key_size": 0, "value_size": 0, "max_entries": 4096,
                             "map_flags": 0, "oracle": "mmap"})
        # The one owned map userspace cannot read at all: its surface is the
        # kernel's refusal, so the replay must validate it and not just hash it.
        manifest.append({"id": 110, "name": "CGROUP_FILTER", "type": "cgroup_array",
                         "key_size": 4, "value_size": 4, "max_entries": 1,
                         "map_flags": 0, "oracle": "refused-lookup"})
        records = []
        for task in tasks:
            for name, map_id, flag in (("TASK_COOKIE", 101, "cookie"),
                                       ("THREAD_OWNER", 102, "owner"),
                                       ("ROOT_AFFILIATION", 103, "root")):
                if not task[flag]:
                    continue
                value = struct.pack("<Q", 3 if flag == "cookie" else 1)
                if flag == "owner":
                    value = bytearray(544)
                    struct.pack_into("<Q", value, 0, (task["pid"] << 32) | task["tid"])
                    # Valid production discovery directory and both late fields.
                    struct.pack_into("<Q", value, 8, 47)
                    struct.pack_into("<QQII", value, 520, 1, 1, 1, 1)
                records.append({"map_id": map_id, "pid": task["pid"],
                                "tid": task["tid"], "generation": task["generation"],
                                "value": bytes(value)})
        controls = {
            "COOKIE_CTL": [16384, 7, 0, 0, 0],  # history exceeds live cells
            "OWNER_CTL": [16448, 0 if empty else 2, 0, 0, 0, 0, 0],
            "ROOT_CTL": [3 if owned else 0, 0, 0, 0, 0, 0, 0, 0],
        }
        return manifest, receipt, records, controls

    def publish_fixture(self, root, manifest, receipt, records, controls, refusals=(),
                        drained=0):
        # Exercise the real framed parser, including valid EOF on empty maps.
        stream = b"".join(TaskStorageReaderTests.frame(
            1, row["map_id"], row["pid"], row["tid"], row["value"]
        ) for row in records) + TaskStorageReaderTests.frame(2)
        parsed = load_dumper().parse_task_storage_frames(
            stream, TaskStorageReaderTests.MAPS, max_records=100, max_bytes=65536)
        refusals = dict(refusals)
        receipt["surfaces"] = []
        for item in manifest:
            name = item["name"]
            if item["type"] == "ringbuf":
                # Use the existing scanner's ring naming convention.
                path = load_subject(TARGET_BITS).ring_raw_path(str(root / "case"), name)
                content = b""
            else:
                path = root / f"mapdump_{name}.bin"
                item["file"] = str(path)
                if item["type"] == "task_storage":
                    content = b"".join(row["value"] for row in parsed if row["map_id"] == item["id"])
                elif name in controls:
                    words = controls[name]
                    raw = struct.pack("<" + "Q" * len(words), *words)
                    content = json.dumps([{"key": [0, 0, 0, 0], "value": list(raw)}]).encode()
                elif item["type"] == "cgroup_array":
                    content = json.dumps(refusals.get(name, refusal_cells(item))).encode()
                else:
                    content = b"[]"
            path.write_bytes(content)
            surface = {"id": item["id"], "phase": "stopped",
                       "acquisition_id": "a" * 32, "size": len(content),
                       "sha256": hashlib.sha256(content).hexdigest()}
            if item["type"] == "ringbuf":
                subject = load_subject(TARGET_BITS)
                records_kept = len(content) // subject.RING_RECORD_SIZES[name]
                surface["positions"] = [
                    drained, drained + subject.RING_RECORD_STRIDES[name] * records_kept]
            if item["type"] == "task_storage":
                surface["records"] = [{k: row[k] for k in ("pid", "tid", "generation")}
                                      for row in records if row["map_id"] == item["id"]]
            receipt["surfaces"].append(surface)
            item["snapshot"] = {"contract": receipt["contract"],
                                "acquisition_id": "a" * 32, "phase": "stopped",
                                "receipt": str(root / "snapshot.json")}
        (root / "snapshot.json").write_text(json.dumps(receipt))

    def check(self, root, manifest):
        return load_subject(TARGET_BITS).owned_map_surfaces(
            "population", manifest, {item["name"] for item in manifest}, str(root / "case"))

    def test_exact_external_owned_and_permitted_empty_populations(self):
        stride = load_subject(TARGET_BITS).RING_RECORD_STRIDES["DISCOVERY"]
        for owned, empty, small in ((False, False, False), (True, False, False),
                                    (False, True, False), (True, False, True)):
            with self.subTest(owned=owned, empty=empty, small=small), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = self.fixture(root, owned=owned, empty=empty)
                if small:
                    args[1]["small_state"] = True
                    args[3]["OWNER_CTL"][0] = 65
                    next(m for m in args[0] if m["name"] == "START")["max_entries"] = 1
                args[1]["after"].reverse()  # roster order is not task identity
                # An owned acquisition files a DISCOVERY ring its own observer
                # already drained: every record consumed, nothing retained.
                self.publish_fixture(root, *args, drained=5 * stride if owned else 0)
                self.assertEqual(len(self.check(root, args[0])), 10)

    def test_framed_records_bind_generations_for_future_coordinator(self):
        dumper = load_dumper()
        manifest, receipt, records, values = self.fixture(Path("/unused"))
        controls = {}
        for item in manifest:
            if item["name"] in values:
                words = values[item["name"]]
                controls[item["name"]] = {
                    "id": item["id"], "type": item["type"], "bytes_key": item["key_size"],
                    "bytes_value": item["value_size"], "max_entries": item["max_entries"],
                    "map_flags": item["map_flags"], "name": item["name"],
                    "oracle": item["oracle"],
                    "value": struct.pack("<" + "Q" * len(words), *words)}
        stream = b"".join(TaskStorageReaderTests.frame(
            1, row["map_id"], row["pid"], row["tid"], row["value"]
        ) for row in records) + TaskStorageReaderTests.frame(2)
        parsed = dumper.parse_task_storage_frames(
            stream, TaskStorageReaderTests.MAPS, max_records=100, max_bytes=65536)
        arguments = {key: receipt[key] for key in ("expected", "before", "after", "lane")}
        arguments["controls"] = controls
        self.assertEqual(dumper.reconcile_task_storage(TaskStorageReaderTests.MAPS, parsed, **arguments), {
            "TASK_COOKIE": [{"pid": 7001, "tid": 7001, "generation": 900}],
            "THREAD_OWNER": [{"pid": 7001, "tid": 7002, "generation": 901},
                             {"pid": 7001, "tid": 7003, "generation": 902}],
            "ROOT_AFFILIATION": [],
        })
        for key in ("expected", "before", "after"):
            with self.subTest(bound=key):
                oversized = {**arguments, key: [arguments[key][0]] * 131073}
                with self.assertRaisesRegex(RuntimeError, "roster.*oversized"):
                    dumper.reconcile_task_storage(TaskStorageReaderTests.MAPS, parsed, **oversized)
        with self.assertRaisesRegex(RuntimeError, "record population"):
            dumper.reconcile_task_storage(TaskStorageReaderTests.MAPS, [parsed[0]] * 131073, **arguments)

    def test_idle_owner_storage_is_leaseless_and_roster_bound(self):
        # The native owner keeps a thread's storage after its first call and
        # clears it when the lease returns: 544 zero bytes, no lease. It may
        # belong to any stopped in-process task that is not expected to hold
        # a lease, and never counts toward OWNER_CTL outstanding.
        idle = {"map_id": 102, "pid": 7001, "tid": 7001, "generation": 900,
                "value": bytes(544)}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, receipt, records, controls = self.fixture(root)
            records.append(dict(idle))
            self.publish_fixture(root, manifest, receipt, records, controls)
            self.assertEqual(len(self.check(root, manifest)), 10)
        for case in ("foreign", "expected-lease", "not-zero", "counted"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                row = dict(idle)
                if case == "foreign":
                    row["tid"] = 8888
                elif case == "expected-lease":
                    # A worker blocked mid-call must hold its lease, not idle.
                    records[:] = [r for r in records if not (r["map_id"] == 102 and r["tid"] == 7002)]
                    row.update(tid=7002, generation=901)
                elif case == "not-zero":
                    value = bytearray(544)
                    struct.pack_into("<Q", value, 0, (7001 << 32) | 7001)
                    row["value"] = bytes(value)
                else:
                    controls["OWNER_CTL"][1] = 3  # an idle owner holds no lease
                records.append(row)
                self.publish_fixture(root, manifest, receipt, records, controls)
                with self.assertRaisesRegex(AssertionError, "stopped"):
                    self.check(root, manifest)

    def test_idle_owner_first_does_not_shadow_affiliated_records(self):
        # An idle THREAD_OWNER for a task must not collide with that same
        # task's leased records in other maps: the owned leader holds no
        # owner lease at STOP (idle) but does hold its root affiliation and
        # cookie. Frame order must not matter.
        dumper = load_dumper()
        manifest, receipt, records, values = self.fixture(Path("/unused"), owned=True)
        records.insert(0, {"map_id": 102, "pid": 7001, "tid": 7001,
                           "generation": 900, "value": bytes(544)})
        controls = {}
        for item in manifest:
            if item["name"] in values:
                words = values[item["name"]]
                controls[item["name"]] = {
                    "id": item["id"], "type": item["type"], "bytes_key": item["key_size"],
                    "bytes_value": item["value_size"], "max_entries": item["max_entries"],
                    "map_flags": item["map_flags"], "name": item["name"],
                    "oracle": item["oracle"],
                    "value": struct.pack("<" + "Q" * len(words), *words)}
        stream = b"".join(TaskStorageReaderTests.frame(
            1, row["map_id"], row["pid"], row["tid"], row["value"]
        ) for row in records) + TaskStorageReaderTests.frame(2)
        parsed = dumper.parse_task_storage_frames(
            stream, TaskStorageReaderTests.MAPS, max_records=100, max_bytes=65536)
        arguments = {key: receipt[key] for key in ("expected", "before", "after", "lane")}
        arguments["controls"] = controls
        bound = dumper.reconcile_task_storage(TaskStorageReaderTests.MAPS, parsed, **arguments)
        self.assertEqual(bound["THREAD_OWNER"], [
            {"pid": 7001, "tid": 7002, "generation": 901},
            {"pid": 7001, "tid": 7003, "generation": 902}])
        self.assertEqual(bound["ROOT_AFFILIATION"], [
            {"pid": 7001, "tid": 7001, "generation": 900},
            {"pid": 7001, "tid": 7002, "generation": 901},
            {"pid": 7001, "tid": 7003, "generation": 902}])

    def test_valid_eof_with_missing_or_wrong_identity_population_is_terminal(self):
        for case in ("empty", "missing-worker", "foreign-owner", "nonleader-cookie",
                     "unexpected-root", "owned-missing-root", "owned-foreign-root"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root, owned=case.startswith("owned"))
                if case == "empty":
                    records.clear()
                elif case == "missing-worker":
                    records.pop(1)
                elif case in ("foreign-owner", "nonleader-cookie", "owned-foreign-root"):
                    row = next(r for r in records if r["map_id"] == {
                        "foreign-owner": 102, "nonleader-cookie": 101, "owned-foreign-root": 103}[case])
                    row["tid"] = 7002 if case == "nonleader-cookie" else 8888
                elif case == "owned-missing-root":
                    records[:] = [r for r in records if r["map_id"] != 103]
                else:
                    records.append({"map_id": 103, "pid": 7001, "tid": 7001,
                                    "generation": 900, "value": struct.pack("<Q", 1)})
                self.publish_fixture(root, manifest, receipt, records, controls)
                with self.assertRaisesRegex(AssertionError, "stopped.*map.*(population|identity)"):
                    self.check(root, manifest)

    def test_roster_rejects_missing_changed_reused_and_unstopped_tasks(self):
        for case in ("missing", "changed", "reused", "duplicate", "running", "no-state", "no-after"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                if case == "missing":
                    receipt["before"].pop()
                elif case == "changed":
                    receipt["after"][-1]["tid"] = 8888
                elif case == "reused":
                    receipt["after"][-1]["generation"] += 1
                elif case == "duplicate":
                    receipt["expected"].append(dict(receipt["expected"][-1]))
                elif case == "running":
                    receipt["before"][-1]["state"] = "S"
                elif case == "no-state":
                    receipt["before"][-1].pop("state")
                else:
                    receipt.pop("after")
                self.publish_fixture(root, manifest, receipt, records, controls)
                with self.assertRaisesRegex(AssertionError, "stopped.*roster"):
                    self.check(root, manifest)

    def test_control_health_and_exact_reservations(self):
        for name, offset, value in (("COOKIE_CTL", 0, 1), ("COOKIE_CTL", 1, 16385),
                                    ("COOKIE_CTL", 1, 2), ("OWNER_CTL", 0, 65),
                                    ("OWNER_CTL", 1, 1), ("ROOT_CTL", 0, 1)):
            with self.subTest(name=name, offset=offset), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                controls[name][offset] = value
                self.publish_fixture(root, manifest, receipt, records, controls)
                with self.assertRaisesRegex(AssertionError, f"stopped.*{name}"):
                    self.check(root, manifest)
        for name, first, end in (("COOKIE_CTL", 2, 5), ("OWNER_CTL", 2, 7), ("ROOT_CTL", 1, 8)):
            for offset in range(first, end):
                with self.subTest(name=name, offset=offset), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    manifest, receipt, records, controls = self.fixture(root)
                    controls[name][offset] = 1
                    self.publish_fixture(root, manifest, receipt, records, controls)
                    with self.assertRaisesRegex(AssertionError, f"stopped.*{name}"):
                        self.check(root, manifest)

    def test_empty_roster_cannot_certify_an_empty_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, receipt, records, controls = self.fixture(root, empty=True)
            for key in ("expected", "before", "after"):
                receipt[key] = []
            self.publish_fixture(root, manifest, receipt, records, controls)
            with self.assertRaisesRegex(AssertionError, "stopped.*roster"):
                self.check(root, manifest)

    def test_boolean_map_metadata_is_not_an_integer_contract(self):
        for name, key, value in (("TASK_COOKIE", "map_flags", True),
                                 ("OWNER_CTL", "max_entries", True),
                                 ("ROOT_CTL", "map_flags", False)):
            with self.subTest(name=name, key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                next(m for m in manifest if m["name"] == name)[key] = value
                self.publish_fixture(root, manifest, receipt, records, controls)
                with self.assertRaisesRegex(AssertionError, "stopped.*metadata"):
                    self.check(root, manifest)

    def test_snapshot_configuration_matches_start_and_ring_definitions(self):
        for name, key, value in (("START", "max_entries", 1), ("START", "type", "array"),
                                 ("EVENTS", "type", "hash"), ("DISCOVERY", "type", "hash")):
            with self.subTest(name=name, key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                item = next(m for m in manifest if m["name"] == name)
                item[key] = value
                if value == "hash":
                    item["oracle"] = "dump"
                self.publish_fixture(root, manifest, receipt, records, controls)
                with self.assertRaisesRegex(AssertionError, "stopped.*metadata"):
                    self.check(root, manifest)

    def test_owner_value_ownership_directory_and_production_tail(self):
        for offset, fmt, value in ((0, "Q", (7001 << 32) | 8888), (520, "Q", 0),
                                   (528, "Q", 2), (536, "I", 513), (540, "I", 0),
                                   (540, "I", 2), (16, "Q", 123)):
            with self.subTest(offset=offset, value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                row = next(r for r in records if r["map_id"] == 102)
                raw = bytearray(row["value"])
                struct.pack_into("<" + fmt, raw, offset, value)
                row["value"] = bytes(raw)
                self.publish_fixture(root, manifest, receipt, records, controls)
                with self.assertRaisesRegex(AssertionError, "stopped.*THREAD_OWNER.*(value|identity)"):
                    self.check(root, manifest)

    def test_settled_owner_rejects_empty_lease_but_accepts_real_activity(self):
        for occupied, domains, starts in ((0, 0, 1), (1, 1, 0)):
            with self.subTest(occupied=occupied, starts=starts), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                for row in (record for record in records if record["map_id"] == 102):
                    raw = bytearray(row["value"])
                    if not occupied:
                        raw[8:520] = bytes(512)
                    struct.pack_into("<QQII", raw, 520, occupied, domains, starts, 1)
                    row["value"] = bytes(raw)
                self.publish_fixture(root, manifest, receipt, records, controls)
                self.assertEqual(len(self.check(root, manifest)), 10)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, receipt, records, controls = self.fixture(root)
            row = next(record for record in records if record["map_id"] == 102)
            raw = bytearray(row["value"])
            raw[8:520] = bytes(512)
            struct.pack_into("<QQII", raw, 520, 0, 0, 0, 1)
            self.assertEqual(raw[543], 0)
            row["value"] = bytes(raw)
            self.publish_fixture(root, manifest, receipt, records, controls)
            with self.assertRaisesRegex(AssertionError, "stopped.*THREAD_OWNER.*tail"):
                self.check(root, manifest)

    def test_cgroup_array_surface_is_a_kernel_refusal_and_never_a_value(self):
        """The one map with no userspace lookup cannot be replayed as a dump.

        Its surface is `bpf(BPF_MAP_LOOKUP_ELEM)`'s own errno per key. A dump
        oracle on the row, an empty list, a value beside or instead of the
        refusal, and an errno that says the lookup succeeded or is merely
        unpopulated are each a different map than the one being claimed.
        """
        item = {"key_size": 4, "max_entries": 1}
        for case, oracle, cells in (
            ("dumped", "dump", None),
            ("empty", "refused-lookup", []),
            ("fabricated", "refused-lookup", [{"key": ["0x00"] * 4, "value": ["0x00"] * 4}]),
            ("valued", "refused-lookup",
             [{"key": ["0x00"] * 4, "errno": 524, "value": ["0x00"] * 4}]),
            ("readable", "refused-lookup", refusal_cells(item, errno=0)),
            ("unpopulated", "refused-lookup", refusal_cells(item, errno=2)),
            ("textual", "refused-lookup", [{"key": ["0x00"] * 4, "errno": "524"}]),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                row = next(m for m in manifest if m["name"] == "CGROUP_FILTER")
                row["oracle"] = oracle
                refusals = {} if cells is None else {"CGROUP_FILTER": cells}
                self.publish_fixture(root, manifest, receipt, records, controls, refusals)
                with self.assertRaisesRegex(AssertionError, "stopped map"):
                    self.check(root, manifest)

    def test_strict_metadata_diagnostics_are_bounded_and_redacted(self):
        marker = "PRIVATE_METADATA_MARKER"
        malformed_value = marker + "_" * 20_000
        dumper = load_dumper()
        for map_type, oracle in (("hash", "dump"), ("array", "dump"),
                                 ("prog_array", "dump"),
                                 ("cgroup_array", "refused-lookup"),
                                 ("percpu_hash", "dump"),
                                 ("percpu_array", "dump"), ("ringbuf", "mmap"),
                                 ("task_storage", "task-storage")):
            dumper.snapshot_map_metadata({
                "id": 1, "name": "CURRENT_MAP", "type": map_type, "oracle": oracle,
                "bytes_key": 0, "bytes_value": 0, "max_entries": 0, "map_flags": 0,
            })
        manifest, receipt, records, values = self.fixture(Path("/unused"))
        controls = {}
        for item in manifest:
            if item["name"] in values:
                words = values[item["name"]]
                controls[item["name"]] = {
                    "id": item["id"], "name": item["name"], "type": item["type"],
                    "oracle": item["oracle"], "bytes_key": item["key_size"],
                    "bytes_value": item["value_size"], "max_entries": item["max_entries"],
                    "map_flags": item["map_flags"],
                    "value": struct.pack("<" + "Q" * len(words), *words),
                }
        arguments = {key: receipt[key] for key in ("expected", "before", "after", "lane")}
        arguments["controls"] = controls
        direct_maps = [
            {"id": item["id"], "name": item["name"], "type": item["type"],
             "oracle": item["oracle"], "bytes_key": item["key_size"],
             "bytes_value": item["value_size"], "max_entries": item["max_entries"],
             "map_flags": item["map_flags"]}
            for item in manifest[:3]
        ]
        for key in ("name", "type", "oracle"):
            with self.subTest(boundary="direct", key=key):
                malformed = copy.deepcopy(direct_maps)
                malformed[0][key] = malformed_value
                with self.assertRaises(RuntimeError) as caught:
                    dumper.reconcile_task_storage(malformed, records, **arguments)
                error = str(caught.exception)
                self.assertNotIn(marker, error)
                self.assertLess(len(error), 256)

        for key in ("name", "type", "oracle"):
            with self.subTest(boundary="claimed", key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                self.publish_fixture(root, manifest, receipt, records, controls)
                manifest[0][key] = malformed_value
                with self.assertRaises(AssertionError) as caught:
                    self.check(root, manifest)
                error = str(caught.exception)
                self.assertNotIn(marker, error)
                self.assertLess(len(error), 256)

    def test_receipt_binds_every_surface_to_one_stopped_acquisition(self):
        for case in ("phase", "acquisition", "hash", "size", "missing-surface", "duplicate-surface",
                     "partial-claim", "unknown-contract", "no-receipt", "record-generation",
                     "duplicate-record", "missing-controls", "malformed-control", "oversized",
                     "boolean-control-byte", "duplicate-json-field", "missing-ring-positions",
                     "malformed-ring-positions", "ring-positions-contradict-bytes"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                self.publish_fixture(root, manifest, receipt, records, controls)
                ring = next(surface for surface, item in zip(receipt["surfaces"], manifest)
                            if item["type"] == "ringbuf")
                if case in ("phase", "acquisition", "hash", "size", "oversized"):
                    key, value = {"phase": ("phase", "resumed"),
                                  "acquisition": ("acquisition_id", "b" * 32),
                                  "hash": ("sha256", "0" * 64), "size": ("size", 99),
                                  "oversized": ("size", 64 * 1024 * 1024 + 1)}[case]
                    receipt["surfaces"][-1][key] = value
                elif case == "missing-surface":
                    receipt["surfaces"].pop()
                elif case == "duplicate-surface":
                    receipt["surfaces"].append(dict(receipt["surfaces"][-1]))
                elif case == "partial-claim":
                    manifest[-1].pop("snapshot")
                elif case == "unknown-contract":
                    manifest[0]["snapshot"]["contract"] = "future"
                elif case == "no-receipt":
                    manifest[0]["snapshot"]["receipt"] = str(root / "missing")
                elif case == "record-generation":
                    receipt["surfaces"][1]["records"][0]["generation"] += 1
                elif case == "duplicate-record":
                    receipt["surfaces"][1]["records"][1] = dict(receipt["surfaces"][1]["records"][0])
                elif case == "missing-controls":
                    manifest[:] = [m for m in manifest if m["name"] != "OWNER_CTL"]
                    receipt["surfaces"][:] = [s for s in receipt["surfaces"] if s["id"] != 105]
                elif case == "missing-ring-positions":
                    ring.pop("positions")
                elif case == "malformed-ring-positions":
                    ring["positions"] = [0, "PRIVATE_RAW_VALUE"]
                elif case == "ring-positions-contradict-bytes":
                    # Bytes and counters that cannot both be true: the surface is
                    # empty, so the tail between the counters must be empty too.
                    ring["positions"] = [0, load_subject(TARGET_BITS).RING_RECORD_STRIDES["EVENTS"]]
                elif case != "duplicate-json-field":
                    path = Path(manifest[3]["file"])
                    content = b'[{"key":[0,0,0,0],"value":"PRIVATE_RAW_VALUE"}]'
                    if case == "boolean-control-byte":
                        content = path.read_bytes().replace(b'"key": [0', b'"key": [false', 1)
                    path.write_bytes(content)
                    receipt["surfaces"][3].update(size=len(content), sha256=hashlib.sha256(content).hexdigest())
                (root / "snapshot.json").write_text(json.dumps(receipt))
                if case == "duplicate-json-field":
                    path = root / "snapshot.json"
                    path.write_text(path.read_text().replace('{"contract":', '{"phase":"resumed","contract":', 1))
                with self.assertRaises(AssertionError) as caught:
                    self.check(root, manifest)
                self.assertNotIn("PRIVATE_RAW_VALUE", str(caught.exception))


class FinalScannerSurfaceTests(unittest.TestCase):
    LANES = ("default-safe-start", "feature-safe-start", "feature-unsafe-fault")

    def surfaces(self, subject, root, payload):
        result = {}
        for index, lane in enumerate(self.LANES, start=1):
            path = root / f"mapdump_THREAD_OWNER_{lane}.bin"
            path.write_bytes(payload)
            manifest = [{
                "name": "THREAD_OWNER", "id": index, "type": "task_storage",
                "key_size": 4, "value_size": 544, "max_entries": 0,
                "oracle": "task-storage", "file": str(path),
            }]
            (root / f"mapdump_manifest_{lane}.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            result[lane] = subject.assert_exact_owned_map_inventory(
                root, lane, {"THREAD_OWNER"}
            )
        return result

    def test_final_scanner_rejects_late_task_storage_sentinel_in_every_start_lane(self):
        subject = load_subject(TARGET_BITS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for lane in self.LANES:
                with self.subTest(lane=lane):
                    surfaces = self.surfaces(
                        subject, root, bytes(520) + subject.SENTINELS["PIN"]
                    )
                    with self.assertRaisesRegex(AssertionError, "pointer canaries leaked"):
                        subject.assert_final_artifact_privacy(surfaces[lane])

    def test_final_identity_and_safe_alias_scans_include_task_storage_surfaces(self):
        subject = load_subject(TARGET_BITS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = struct.pack("<Q", subject.LOADER_PAUSE_IDENTITIES["marker"])
            surfaces = self.surfaces(subject, root, bytes(520) + identity)
            with self.assertRaisesRegex(AssertionError, "loader/pause identity"):
                subject.assert_final_artifact_privacy(surfaces["default-safe-start"])
            alias = struct.pack("<Q", subject.ALIASES["pss_hash"])
            surfaces = self.surfaces(subject, root, bytes(520) + alias)
            for lane in ("default-safe-start", "feature-safe-start"):
                with self.subTest(lane=lane):
                    with self.assertRaisesRegex(AssertionError, "scalar aliases"):
                        subject.assert_safe_lane_alias_privacy(lane, surfaces[lane])

    # The 10 inherited external lanes: every lane whose stopped receipt is not
    # one of the two owned-metrics rows. Their receipts were already replayed
    # semantically, and their lane surface sets already privacy-scanned, but
    # the receipt *byte file* itself never reached the final privacy/alias
    # scanner -- so a sentinel landing in one escaped the canary outright.
    EXTERNAL_RECEIPT_LANES = (
        "default-safe-profile", "default-safe-trace",
        "feature-safe-profile", "feature-safe-trace",
        "feature-unsafe-profile", "feature-unsafe-trace",
        "aggregate-only-metrics",
        "default-safe-start", "feature-safe-start", "feature-unsafe-fault",
    )

    def lane_final_set(self, subject, root, lane, receipt_bytes, *,
                       claim=True, combined_log=False):
        """One lane's final surface set, as the lane driver builds it.

        External lanes keep observer and workload logs apart, so `combined_log`
        defaults false. That is exactly the path that used to drop the receipt.
        """
        (root / f"{lane}.output").write_text("{}\n", encoding="utf-8")
        (root / f"{lane}.observer.log").write_bytes(b"")
        (root / f"{lane}.workload.log").write_bytes(b"")
        surface = root / f"mapdump_THREAD_OWNER_{lane}.bin"
        surface.write_bytes(bytes(544))
        receipt = root / f"mapdump_snapshot_{lane}.json"
        receipt.write_bytes(receipt_bytes)
        item = {
            "name": "THREAD_OWNER", "id": 1, "type": "task_storage",
            "key_size": 4, "value_size": 544, "max_entries": 0,
            "oracle": "task-storage", "file": str(surface),
        }
        if claim:
            item["snapshot"] = {
                "contract": "stopped-snapshot-v1", "acquisition_id": "0" * 32,
                "phase": "stopped", "receipt": str(receipt),
            }
        (root / f"mapdump_manifest_{lane}.json").write_text(
            json.dumps([item]), encoding="utf-8"
        )
        return receipt, subject.final_lane_artifacts(
            root, lane, [surface], combined_log=combined_log
        )

    def test_external_receipt_bytes_reach_the_final_privacy_scan_in_every_lane(self):
        subject = load_subject(TARGET_BITS)
        for lane in self.EXTERNAL_RECEIPT_LANES:
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as directory:
                receipt, paths = self.lane_final_set(
                    subject, Path(directory), lane, b"{}\n"
                )
                self.assertIn(receipt, [Path(path) for path in paths])
                # Positive control, per lane: the clean set passes, and the same
                # set with the sentinel planted only in the receipt must fail.
                subject.assert_final_artifact_privacy(paths)
                receipt.write_bytes(subject.positive_control_content())
                with self.assertRaisesRegex(AssertionError, "pointer canaries leaked"):
                    subject.assert_final_artifact_privacy(paths)

    def test_external_receipt_bytes_carry_identity_and_safe_alias_scans(self):
        subject = load_subject(TARGET_BITS)
        marker = struct.pack("<Q", subject.LOADER_PAUSE_IDENTITIES["marker"])
        alias = struct.pack("<Q", subject.ALIASES["pss_hash"])
        lane = "default-safe-profile"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _receipt, paths = self.lane_final_set(
                subject, root, lane, subject.positive_control_content(marker)
            )
            with self.assertRaisesRegex(AssertionError, "loader/pause identity"):
                subject.assert_final_artifact_privacy(paths)
            _receipt, paths = self.lane_final_set(
                subject, root, lane, subject.positive_control_content(alias)
            )
            with self.assertRaisesRegex(AssertionError, "scalar aliases"):
                subject.assert_safe_lane_alias_privacy(lane, paths)

    def test_claimless_manifest_is_refused_in_every_lane(self):
        """A manifest claiming no snapshot must fail its lane, never pass it.

        Losing the claim loses both the semantic replay and the receipt scan at
        once, and a lane that reports OK over bytes nobody read is the exact
        failure this gate exists to prevent. External lanes are held to the
        owned lanes' own fail-closed terms, so both are pinned here.
        """
        subject = load_subject(TARGET_BITS)
        for lane, combined_log in (("default-safe-profile", False),
                                   ("owned-default-metrics", True)):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(
                    AssertionError, "missing stopped snapshot claim"
                ):
                    self.lane_final_set(
                        subject, Path(directory), lane,
                        subject.positive_control_content(),
                        claim=False, combined_log=combined_log,
                    )

    def test_final_scan_names_its_receipt_and_ignores_an_unnamed_neighbour(self):
        """Scanned because NAMED in a manifest, not because present on disk.

        A claim-bearing lane whose directory also holds a sentinel-bearing file
        that no manifest names: the same bytes must draw opposite verdicts --
        invisible as the unnamed neighbour, caught as the named receipt. That
        isolates "named" from "present", which is what keeps this scanner
        tree-walk-free and the nested task-storage seed out-dir, a real
        subdirectory of the lane work root, outside the scan surface.
        """
        subject = load_subject(TARGET_BITS)
        lane = "default-safe-profile"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt, paths = self.lane_final_set(subject, root, lane, b"{}\n")
            neighbour = root / "task-storage-seed" / "seed-qualification.json"
            neighbour.parent.mkdir()
            neighbour.write_bytes(subject.positive_control_content())
            scanned = [Path(path) for path in paths]
            self.assertIn(receipt, scanned)
            self.assertNotIn(neighbour, scanned)
            subject.assert_final_artifact_privacy(paths)
            receipt.write_bytes(neighbour.read_bytes())
            with self.assertRaisesRegex(AssertionError, "pointer canaries leaked"):
                subject.assert_final_artifact_privacy(paths)


class StartRingSurfaceIntegrationTests(unittest.TestCase):
    LANES = {
        "default-safe-start": "SAFE_MAPS",
        "feature-safe-start": "UNSAFE_MAPS",
        "feature-unsafe-fault": "UNSAFE_MAPS",
    }

    def inventory(self, subject, root, lane, inventory_name):
        manifest = []
        for map_id, (name, definition) in enumerate(
            sorted(subject.BPF_MAP_DEFS[inventory_name].items()), start=1
        ):
            ring = definition["type"] == 27
            task_storage = definition["type"] == 29
            item = {
                "name": name,
                "id": map_id,
                "max_entries": definition["max_entries"],
                "key_size": 0 if ring else definition["key_size"],
                "value_size": 0 if ring else definition["value_size"],
                "type": "ringbuf" if ring else "task_storage" if task_storage else "hash",
                "oracle": "mmap" if ring else "task-storage" if task_storage else "dump",
            }
            if not ring:
                suffix = "bin" if task_storage else "json"
                path = root / f"mapdump_{name}_{lane}.{suffix}"
                path.write_bytes(bytes(544) if task_storage else b"[]\n")
                item["file"] = str(path)
            manifest.append(item)
        manifest_path = root / f"mapdump_manifest_{lane}.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path

    def test_complete_start_inventory_retains_real_ring_bytes_and_scans_every_surface(self):
        subject = load_subject(TARGET_BITS)
        discovery = bytes(subject.DISCOVERY_RECORD_SIZE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for lane, inventory_name in self.LANES.items():
                manifest = self.inventory(subject, root, lane, inventory_name)

                def records(_manifest, name):
                    rows = [] if name == "EVENTS" else [discovery]
                    stride = subject.RING_RECORD_STRIDES[name]
                    return rows, (0, stride * len(rows))

                with mock.patch.object(subject, "ring_records", side_effect=records):
                    subject.assert_raw_records(manifest, lane, 0x555, root / lane)
                self.assertEqual(
                    subject.ring_raw_path(root / lane, "DISCOVERY").read_bytes(),
                    discovery,
                )
                expected = set(subject.BPF_MAP_DEFS[inventory_name])
                surfaces = subject.assert_exact_owned_map_inventory(root, lane, expected)
                subject.assert_final_artifact_privacy(surfaces)
                if lane != "feature-unsafe-fault":
                    subject.assert_safe_lane_alias_privacy(lane, surfaces)

            missing = subject.ring_raw_path(root / "feature-unsafe-fault", "DISCOVERY")
            missing.unlink()
            with self.assertRaisesRegex(AssertionError, "has no scanned surface"):
                subject.assert_exact_owned_map_inventory(
                    root, "feature-unsafe-fault",
                    set(subject.BPF_MAP_DEFS["UNSAFE_MAPS"]),
                )

            owner = root / "mapdump_THREAD_OWNER_default-safe-start.bin"
            owner.write_bytes(bytes(520) + subject.SENTINELS["PIN"])
            surfaces = subject.assert_exact_owned_map_inventory(
                root, "default-safe-start", set(subject.BPF_MAP_DEFS["SAFE_MAPS"])
            )
            with self.assertRaisesRegex(AssertionError, "pointer canaries leaked"):
                subject.assert_final_artifact_privacy(surfaces)

    def test_start_snapshot_rejects_completed_event_records(self):
        subject = load_subject(TARGET_BITS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.inventory(subject, root, "default-safe-start", "SAFE_MAPS")

            def records(_manifest, name):
                rows = [event_bytes(0)] if name == "EVENTS" else []
                return rows, (0, subject.RING_RECORD_STRIDES[name] * len(rows))

            with mock.patch.object(subject, "ring_records", side_effect=records):
                with self.assertRaisesRegex(AssertionError, "blocked START snapshot"):
                    subject.assert_raw_records(
                        manifest, "default-safe-start", 0x555,
                        root / "default-safe-start",
                    )


class HostileStartTests(unittest.TestCase):
    def test_safe_start_records_and_padding_mutation(self):
        subject = load_subject(TARGET_BITS)
        pointers = {
            "unknown_mechanism": 0x123456789ABCDEF0,
            "exact_async": 0x223456789ABCDEF0,
            "legacy_name": 0x323456789ABCDEF0,
            "alias_name": 0x423456789ABCDEF0,
        }
        starts = [
            subject.decode_start(start_bytes(subject, 0x301,
                mechanism_ptr=pointers["unknown_mechanism"])),
            subject.decode_start(start_bytes(subject, 0x302, target=30)),
            subject.decode_start(start_bytes(subject, 0x303,
                capture=subject.ARG_READ_FAILURE)),
            subject.decode_start(start_bytes(subject, 0x304,
                capture=subject.ARG_READ_FAILURE)),
        ]
        subject.assert_hostile_records(starts, pointers)
        malformed = bytearray(start_bytes(subject, 0x301))
        struct.pack_into("<I", malformed, 268, 1)
        with self.assertRaises(AssertionError):
            subject.decode_start(bytes(malformed))


class FaultStartTests(unittest.TestCase):
    def test_distinct_fault_records_require_exact_total(self):
        subject = load_subject(TARGET_BITS)
        faults = [
            subject.decode_start(start_bytes(subject, 0x401, attr_type=2,
                capture=subject.ARG_READ_FAILURE)),
            subject.decode_start(start_bytes(subject, 0x402, attr_type=1,
                capture=subject.ARG_READ_FAILURE)),
        ]
        subject.assert_fault_records(faults, 2)
        with self.assertRaises(AssertionError):
            subject.assert_fault_records(faults, 1)


class RingLayoutTests(unittest.TestCase):
    class Mapping:
        def __init__(self, size, *, close_error=False):
            self.data = bytearray(size)
            self.closed = False
            self.close_error = close_error

        def __getitem__(self, key):
            return self.data[key]

        def close(self):
            self.closed = True
            if self.close_error:
                raise OSError("injected mapping close failure")

    def retained_fixture(self, subject, *, name="EVENTS", busy=False, close_error=False):
        mappings = [self.Mapping(mmap.PAGESIZE),
                    self.Mapping(mmap.PAGESIZE * 3, close_error=close_error)]
        event = bytes(subject.RING_RECORD_SIZES[name])
        record_size = (8 + len(event) + 7) & ~7
        struct.pack_into("<Q", mappings[1].data, 0, record_size)
        struct.pack_into("<I", mappings[1].data, mmap.PAGESIZE,
                         len(event) | ((1 << 31) if busy else 0))
        mappings[1].data[mmap.PAGESIZE + 8:mmap.PAGESIZE + 8 + len(event)] = event

        class Libc:
            def __init__(self):
                self.fds = []

            def syscall(self, *_args):
                fd = os.open("/dev/null", os.O_RDONLY)
                self.fds.append(fd)
                return fd

        libc = Libc()
        mapping_index = 0

        def fake_mmap(*_args, **_kwargs):
            nonlocal mapping_index
            result = mappings[mapping_index]
            mapping_index += 1
            return result

        real_u64 = subject.u64

        def fake_u64(value, offset):
            return real_u64(value.data if isinstance(value, self.Mapping) else value, offset)

        item = {"oracle": "mmap", "type": "ringbuf", "key_size": 0,
                "value_size": 0, "id": 7, "name": name,
                "max_entries": mmap.PAGESIZE, "map_flags": 0}
        return item, mappings, libc, fake_mmap, fake_u64

    def test_ring_layout_rejects_busy_and_wrap(self):
        subject = load_subject(TARGET_BITS)
        raw = bytearray(2 * mmap.PAGESIZE)
        event = bytes(328)
        struct.pack_into("<I", raw, 0, len(event))
        raw[8:8 + len(event)] = event
        self.assertEqual(subject.parse_ring_records(raw, mmap.PAGESIZE, 0, 336), [event])
        struct.pack_into("<I", raw, 0, len(event) | (1 << 31))
        with self.assertRaises(AssertionError):
            subject.parse_ring_records(raw, mmap.PAGESIZE, 0, 336)
        with self.assertRaises(AssertionError):
            subject.parse_ring_records(raw, mmap.PAGESIZE, 336, 0)

    def test_ring_adapter_closes_fd_and_partial_mapping_on_failure(self):
        subject = load_subject(TARGET_BITS)
        real_mmap = mmap.mmap

        class Libc:
            def __init__(self):
                self.fd = None

            def syscall(self, *_args):
                self.fd = os.open("/dev/null", os.O_RDONLY)
                return self.fd

        libc = Libc()
        consumer = real_mmap(-1, mmap.PAGESIZE)
        calls = 0

        def fail_second_mapping(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return consumer
            raise OSError("injected producer mapping failure")

        original_manifest_map = subject.manifest_map
        original_cdll = subject.ctypes.CDLL
        original_mmap = subject.mmap.mmap
        subject.manifest_map = lambda _manifest, _name: {
            "oracle": "mmap", "type": "ringbuf", "key_size": 0,
            "value_size": 0, "id": 7, "max_entries": mmap.PAGESIZE,
        }
        subject.ctypes.CDLL = lambda *_args, **_kwargs: libc
        subject.mmap.mmap = fail_second_mapping
        try:
            with self.assertRaisesRegex(OSError, "injected producer mapping failure"):
                subject.ring_records("unused")
            self.assertTrue(consumer.closed)
            with self.assertRaises(OSError):
                os.fstat(libc.fd)
        finally:
            subject.manifest_map = original_manifest_map
            subject.ctypes.CDLL = original_cdll
            subject.mmap.mmap = original_mmap
            if not consumer.closed:
                consumer.close()
            if libc.fd is not None:
                try:
                    os.close(libc.fd)
                except OSError:
                    pass

    def test_retained_ring_readers_keep_both_mappings_and_fds_until_close(self):
        subject = load_subject(TARGET_BITS)
        first = self.retained_fixture(subject)
        second = self.retained_fixture(subject, name="DISCOVERY")
        item, mappings, libc, _fake_mmap, fake_u64 = first
        second_item, second_mappings = second[:2]
        all_mappings = mappings + second_mappings
        mapping_iterator = iter(all_mappings)
        with mock.patch.object(subject.ctypes, "CDLL", return_value=libc), \
                mock.patch.object(subject.mmap, "mmap", side_effect=lambda *_a, **_k: next(mapping_iterator)), \
                mock.patch.object(subject, "u64", side_effect=fake_u64):
            readers = [subject.RetainedRingReader(item), subject.RetainedRingReader(second_item)]
            self.assertFalse(any(mapping.closed for mapping in all_mappings))
            discovery_position = (8 + subject.DISCOVERY_RECORD_SIZE + 7) & ~7
            self.assertEqual([reader.positions() for reader in readers],
                             [(0, 336), (0, discovery_position)])
            self.assertEqual(readers[0].read_records((0, 336)), [bytes(328)])
            self.assertEqual(readers[1].read_records((0, discovery_position)),
                             [bytes(subject.DISCOVERY_RECORD_SIZE)])
            self.assertTrue(all(os.fstat(fd) for fd in libc.fds))
            for reader in readers:
                reader.close()
        self.assertTrue(all(mapping.closed for mapping in all_mappings))
        for fd in libc.fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_retained_ring_reader_cleans_up_after_position_decode_and_close_failures(self):
        subject = load_subject(TARGET_BITS)
        for case in ("position", "decode", "close"):
            with self.subTest(case=case):
                item, mappings, libc, fake_mmap, fake_u64 = self.retained_fixture(
                    subject, busy=case == "decode", close_error=case == "close")
                with mock.patch.object(subject.ctypes, "CDLL", return_value=libc), \
                        mock.patch.object(subject.mmap, "mmap", side_effect=fake_mmap), \
                        mock.patch.object(subject, "u64", side_effect=(
                            OSError("injected position failure") if case == "position" else fake_u64)):
                    with self.assertRaises((AssertionError, OSError)):
                        with subject.RetainedRingReader(item) as reader:
                            positions = reader.positions()
                            reader.read_records(positions)
                self.assertTrue(all(mapping.closed for mapping in mappings))
                with self.assertRaises(OSError):
                    os.fstat(libc.fds[0])

    def test_retained_event_validation_never_opens_live_bpf_maps(self):
        subject = load_subject(TARGET_BITS)
        retained = {
            "EVENTS": [event_bytes(index) for index in range(28)],
            "DISCOVERY": [bytes(subject.DISCOVERY_RECORD_SIZE)],
        }
        positions = {name: (0, subject.RING_RECORD_STRIDES[name] * len(rows))
                     for name, rows in retained.items()}
        with mock.patch.object(subject.ctypes, "CDLL",
                               side_effect=AssertionError("live BPF open forbidden")):
            subject.assert_retained_ring_records(
                retained, "default-safe-profile", 0x555, positions)


class OwnedMetricsOracleTests(unittest.TestCase):
    def test_owned_metrics_require_exact_30_and_closed_run_evidence(self):
        canary = load_subject(TARGET_BITS)
        capture, owned = owned_metrics_document(TARGET_BITS)
        RETIRED_VERSION_SKIP = {
            "name": capture.DISCOVERY_SUBJECT,
            "reason": capture.UNSUPPORTED_TABLE_VERSION,
        }
        for lane in ("owned-default-metrics", "owned-feature-metrics"):
            with self.subTest(lane=lane):
                capture.validate_canary(lane, copy.deepcopy(owned), TARGET_BITS)
                canary.assert_owned_aggregate_metrics(copy.deepcopy(owned))
                for calls in (28, 29, 31):
                    bad = copy.deepcopy(owned)
                    bad["functions"][0]["calls"] = calls
                    with self.assertRaises(AssertionError):
                        capture.validate_canary(lane, bad, TARGET_BITS)
                    with self.assertRaises(AssertionError):
                        canary.assert_owned_aggregate_metrics(bad)
                # A retained scan refusal publishes byte-identical to the
                # initial-set skip, so an owned lane may carry two
                # categorical skips: the deterministic floor plus one.
                two = copy.deepcopy(owned)
                two["evidence"]["skipped"] = [
                    {"name": capture.DISCOVERY_SUBJECT,
                     "reason": capture.DISCOVERY_UNAVAILABLE}
                    for _ in range(2)]
                capture.validate_canary(lane, two, TARGET_BITS)
                for mutate in (
                    lambda d: d["evidence"].pop("child_still_running"),
                    lambda d: d["evidence"].update(child_still_running=True),
                    lambda d: d["evidence"].update(
                        pause="sigstop", pause_attempts=1, pause_confirmed=1),
                    # The owned categorical floor is exact: a lane that
                    # published no categorical skip left its initial-set
                    # attempt unreported. Above the ceiling — a third
                    # categorical skip, or any non-categorical item — still
                    # fails. The retired future-minor version skip is such
                    # an item (owner-approved 2026-09-27: the scan walks
                    # future minors as known prefixes and never emits it),
                    # alone or beside the categorical floor.
                    lambda d: d["evidence"].update(skipped=[
                        dict(RETIRED_VERSION_SKIP)]),
                    lambda d: d["evidence"].update(skipped=[
                        {"name": capture.DISCOVERY_SUBJECT,
                         "reason": capture.DISCOVERY_UNAVAILABLE},
                        dict(RETIRED_VERSION_SKIP)]),
                    lambda d: d["evidence"].update(skipped=[]),
                    lambda d: d["evidence"].update(skipped=[{
                        "name": capture.DISCOVERY_SUBJECT,
                        "reason": capture.TABLE_UNAVAILABLE}]),
                    lambda d: d["evidence"].update(skipped=[
                        {"name": capture.DISCOVERY_SUBJECT,
                         "reason": capture.DISCOVERY_UNAVAILABLE}
                        for _ in range(3)]),
                    lambda d: d["evidence"].update(skipped=[
                        {"name": capture.DISCOVERY_SUBJECT,
                         "reason": capture.DISCOVERY_UNAVAILABLE},
                        {"name": capture.DISCOVERY_SUBJECT,
                         "reason": capture.TABLE_UNAVAILABLE}]),
                ):
                    bad = copy.deepcopy(owned)
                    mutate(bad)
                    with self.assertRaises(AssertionError):
                        capture.validate_canary(lane, bad, TARGET_BITS)

        external = copy.deepcopy(owned)
        external["evidence"].pop("child_still_running")
        # The initial-set skip belongs to the owned lane alone: an external
        # `--pid` attach never attempts initial-set discovery, so it has
        # nothing to leave unproven, and the known-prefix scan publishes
        # no version skip for the matrix shape.
        external["evidence"]["skipped"] = []
        external["functions"][0]["calls"] = 28
        # Dropping the skip changes the verdict's inputs: re-derive the
        # published classes the way the producer would.
        capture.settle_fixture_verdict(external)
        capture.validate_canary("aggregate-only-metrics", external, TARGET_BITS)
        canary.assert_aggregate_metrics(external)
        external_30 = copy.deepcopy(external)
        external_30["functions"][0]["calls"] = 30
        with self.assertRaises(AssertionError):
            capture.validate_canary("aggregate-only-metrics", external_30, TARGET_BITS)
        with self.assertRaises(AssertionError):
            canary.assert_aggregate_metrics(external_30)
        external_owned_evidence = copy.deepcopy(external)
        external_owned_evidence["evidence"]["child_still_running"] = False
        with self.assertRaises(AssertionError):
            capture.validate_canary(
                "aggregate-only-metrics", external_owned_evidence, TARGET_BITS)

    def test_owned_metrics_judge_ring_positions_not_the_drained_residue(self):
        """The residue is empty on a healthy owned run, so it cannot be the oracle.

        `p11scope run` drains its own DISCOVERY ring on every capture tick,
        before the readiness frame the canary waits for, so an owned lane
        retains nothing whether or not it ever published a record. All three
        vectors below therefore retain exactly nothing, and only the producer
        positions separate the measured good run from the two bad ones.
        """
        subject = load_subject(TARGET_BITS)
        stride = subject.RING_RECORD_STRIDES["DISCOVERY"]
        drained = 5 * stride
        leaked = 28 * subject.RING_RECORD_STRIDES["EVENTS"]
        empty = {"EVENTS": [], "DISCOVERY": []}
        for lane in ("owned-default-metrics", "owned-feature-metrics"):
            with self.subTest(lane=lane):
                subject.assert_retained_ring_records(
                    empty, lane, 0x555,
                    {"EVENTS": (0, 0), "DISCOVERY": (drained, drained)})
                for label, expected, positions in (
                    ("nothing produced", "DISCOVERY produced 0 bytes",
                     {"EVENTS": (0, 0), "DISCOVERY": (0, 0)}),
                    ("leaked call events", f"EVENTS produced {leaked} bytes",
                     {"EVENTS": (leaked, leaked), "DISCOVERY": (drained, drained)}),
                ):
                    with self.subTest(vector=label):
                        with self.assertRaises(AssertionError) as caught:
                            subject.assert_retained_ring_records(
                                empty, lane, 0x555, positions)
                        self.assertIn(expected, str(caught.exception))
                        self.assertIn(lane, str(caught.exception))
                # A retained record is still welcome -- the canary can win the
                # race -- but only while the positions account for it.
                subject.assert_retained_ring_records(
                    {"EVENTS": [], "DISCOVERY": [bytes(subject.DISCOVERY_RECORD_SIZE)]},
                    lane, 0x555,
                    {"EVENTS": (0, 0), "DISCOVERY": (drained, drained + stride)})
                with self.assertRaisesRegex(AssertionError, "DISCOVERY retains 1 records"):
                    subject.assert_retained_ring_records(
                        {"EVENTS": [], "DISCOVERY": [bytes(subject.DISCOVERY_RECORD_SIZE)]},
                        lane, 0x555,
                        {"EVENTS": (0, 0), "DISCOVERY": (drained, drained)})
                # A call event the lane did retain is still an aggregate leak.
                with self.assertRaises(AssertionError):
                    subject.assert_retained_ring_records(
                        {"EVENTS": [event_bytes(0)], "DISCOVERY": []}, lane, 0x555,
                        {"EVENTS": (0, subject.RING_RECORD_STRIDES["EVENTS"]),
                         "DISCOVERY": (drained, drained)})

    def test_owned_final_surface_set_includes_combined_log_maps_manifest_and_receipt(self):
        subject = load_subject(TARGET_BITS)
        _capture, owned = owned_metrics_document(TARGET_BITS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lane = "owned-default-metrics"
            output = root / f"{lane}.output"
            observer = root / f"{lane}.observer.log"
            manifest = root / f"mapdump_manifest_{lane}.json"
            receipt = root / f"{lane}.receipt.json"
            root_surface = root / f"mapdump_ROOT_AFFILIATION_{lane}.bin"
            owner_surface = root / f"mapdump_THREAD_OWNER_{lane}.bin"
            output.write_text(json.dumps(owned), encoding="utf-8")
            observer.write_bytes(b"")
            receipt.write_text("{}", encoding="utf-8")
            root_surface.write_bytes(bytes(8))
            owner_surface.write_bytes(bytes(544))
            manifest.write_text(json.dumps([{"snapshot": {"receipt": str(receipt)}}]),
                                encoding="utf-8")
            paths = subject.final_lane_artifacts(
                root, lane, [root_surface, owner_surface], combined_log=True)
            self.assertEqual(set(paths), {
                output, observer, root_surface, owner_surface, manifest, receipt,
            })
            subject.assert_final_artifact_privacy(paths)
            owner_surface.unlink()
            with self.assertRaises(OSError):
                subject.assert_final_artifact_privacy(paths)
            owner_surface.write_bytes(bytes(520) + subject.SENTINELS["PIN"])
            with self.assertRaisesRegex(AssertionError, "pointer canaries leaked"):
                subject.assert_final_artifact_privacy(paths)
            owner_surface.write_bytes(bytes(544))
            root_surface.write_bytes(subject.SENTINELS["PIN"])
            with self.assertRaisesRegex(AssertionError, "pointer canaries leaked"):
                subject.assert_final_artifact_privacy(paths)
            root_surface.write_bytes(bytes(8))
            receipt.write_bytes(subject.positive_control_content())
            with self.assertRaisesRegex(AssertionError, "pointer canaries leaked"):
                subject.assert_final_artifact_privacy(paths)


class EventLayoutTests(unittest.TestCase):
    def test_exact_event328_decodes_unknown_and_positive_root_affiliation(self):
        subject = load_subject(TARGET_BITS)
        unknown = subject.decode_event(event_bytes(0, root_affiliation=0))
        positive = subject.decode_event(event_bytes(0, root_affiliation=1))
        self.assertEqual(unknown["root_affiliation"], 0)
        self.assertEqual(positive["root_affiliation"], 1)

    def test_event_rejects_old_size_and_invalid_root_affiliation(self):
        subject = load_subject(TARGET_BITS)
        with self.assertRaises(AssertionError):
            subject.decode_event(bytes(320))
        for root_affiliation in (2, (1 << 64) - 1):
            with self.subTest(root_affiliation=root_affiliation):
                with self.assertRaisesRegex(AssertionError, "root affiliation"):
                    subject.decode_event(event_bytes(0, root_affiliation=root_affiliation))


class RawSafeEventTests(unittest.TestCase):
    def test_safe_event_family_and_pid_mutation(self):
        subject = load_subject(TARGET_BITS)
        events = [event_bytes(index) for index in range(28)]
        subject.assert_event_records(events, "default-safe-profile", 0x555)
        bad = list(events)
        raw = bytearray(bad[0])
        struct.pack_into("<Q", raw, 16, 0x556 << 32)
        bad[0] = bytes(raw)
        with self.assertRaises(AssertionError):
            subject.assert_event_records(bad, "default-safe-profile", 0x555)


class RawDiagnosticEventTests(unittest.TestCase):
    def test_diagnostic_template_family(self):
        subject = load_subject(TARGET_BITS)
        aliases = subject.ALIASES
        events = [event_bytes(index) for index in range(28)]
        events[9] = event_bytes(9, mechanism=subject.REGISTERED)
        events[10] = event_bytes(10, mechanism=subject.UNKNOWN)
        events[11] = event_bytes(11, mechanism=subject.MAXIMUM)
        events[12] = event_bytes(12, mechanism=0xD, slot=401, shape=1,
            p0=aliases["pss_hash"], p1=aliases["pss_mgf"], p2=aliases["pss_salt"])
        events[13] = event_bytes(13, mechanism=0x1087, slot=402, shape=3,
            p0=aliases["gcm220_iv"], p1=aliases["gcm220_aad"], p2=aliases["gcm220_tag"])
        events[14] = event_bytes(14, mechanism=0x1087, slot=402, shape=4,
            p0=aliases["gcm240_iv"], p1=aliases["gcm240_aad"], p2=aliases["gcm240_tag"])
        events[15] = event_bytes(15, slot=403,
            attrs=(aliases["template_type"], *subject.POLICY_BOOLEAN_TYPES[:6]),
            attr_count=7, attr_total=7, attr_bools=0x3F, attr_seen=0x3F)
        events[16] = event_bytes(16, slot=403,
            attrs=(aliases["template_type"], *subject.POLICY_BOOLEAN_TYPES[6:]),
            attr_count=6, attr_total=6, attr_bools=0x7C0, attr_seen=0x7C0)
        events[17] = event_bytes(17, slot=404, attrs=(2,), attr_count=1,
            attr_total=1, capture=subject.ARG_READ_FAILURE)
        events[18] = event_bytes(18, slot=405, attrs=(1,), attr_count=1,
            attr_total=1, capture=subject.ARG_READ_FAILURE)
        subject.assert_event_records(events, "feature-unsafe-profile", 0x555)
        malformed = list(events)
        raw = bytearray(malformed[15])
        struct.pack_into("<Q", raw, 120, 0)
        malformed[15] = bytes(raw)
        with self.assertRaises(AssertionError):
            subject.assert_event_records(malformed, "feature-unsafe-profile", 0x555)


def parse_args(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target-bits", type=int, choices=(32, 64), default=64)
    known, remaining = parser.parse_known_args(argv)
    return known.target_bits, remaining


if __name__ == "__main__":
    TARGET_BITS, unittest_args = parse_args(sys.argv[1:])
    if not unittest_args:
        unittest_args = ["-v"]
    unittest.main(argv=[sys.argv[0], *unittest_args])
else:
    TARGET_BITS = 64
