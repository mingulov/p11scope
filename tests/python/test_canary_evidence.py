#!/usr/bin/env python3
"""Native tests for the checked-in canary evidence validator."""

import argparse
import copy
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SUBJECT = ROOT / "scripts" / "check-canary-evidence.py"
DUMPER = ROOT / "scripts" / "dump-owned-bpf-maps.py"


def load_subject(bits):
    spec = importlib.util.spec_from_file_location(f"canary_evidence_{bits}", SUBJECT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.initialize(bits)
    return module


def load_dumper():
    spec = importlib.util.spec_from_file_location("owned_bpf_maps", DUMPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
                if ring:
                    subject.ring_raw_path(prefix, name).write_bytes(b"")
                else:
                    item["file"] = str(root / f"mapdump_{name}_{lane}.json")
                    Path(item["file"]).write_text("[]\n", encoding="utf-8")
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reader = root / "reader"
            obj = root / "reader.bpf.o"
            reader.write_bytes(b"reader")
            reader.chmod(0o700)
            obj.write_bytes(b"object")
            commands = []
            inventory = [
                {"name": "START", "id": 99, "type": "hash", "bytes_key": 8,
                 "bytes_value": 288, "max_entries": 16384, "map_flags": 0},
                self.MAPS[0], self.MAPS[1],
                {**self.MAPS[2], "name": "ROOT_AFFILIATIO"},
            ]

            def fake_json(args, require_list=False, map_identity=None):
                commands.append(tuple(args))
                if args[2:4] == ["map", "show"]:
                    map_id = int(args[-1])
                    return [next(dict(item) for item in inventory if item["id"] == map_id)]
                if args[2:4] == ["map", "dump"]:
                    return []
                raise AssertionError(f"unexpected bpftool command: {args}")

            argv = [
                "dump-owned-bpf-maps.py", "55", str(root), "case", "0", "16384",
                str(reader.resolve()), str(obj.resolve()),
            ]
            with mock.patch.object(dumper, "map_ids_from_fdinfo", return_value=[99, 101, 102, 103]), \
                    mock.patch.object(dumper.glob, "glob", return_value=[]), \
                    mock.patch.object(dumper, "run_json", side_effect=fake_json), \
                    mock.patch.object(dumper, "run_task_storage_reader",
                                      return_value=self.complete_stream()), \
                    mock.patch.object(sys, "argv", argv):
                dumper.main()
            dumped_ids = [int(command[-1]) for command in commands
                          if command[2:5] == ("map", "dump", "id")]
            self.assertEqual(dumped_ids, [99], commands)
            manifest = json.loads((root / "mapdump_manifest_case.json").read_text())
            task_items = [item for item in manifest if item["oracle"] == "task-storage"]
            self.assertEqual(len(task_items), 3)
            self.assertEqual(task_items[-1]["name"], "ROOT_AFFILIATION")
            self.assertTrue(all(Path(item["file"]).is_file() for item in task_items))

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

    def publish_fixture(self, root, manifest, receipt, records, controls):
        # Exercise the real framed parser, including valid EOF on empty maps.
        stream = b"".join(TaskStorageReaderTests.frame(
            1, row["map_id"], row["pid"], row["tid"], row["value"]
        ) for row in records) + TaskStorageReaderTests.frame(2)
        parsed = load_dumper().parse_task_storage_frames(
            stream, TaskStorageReaderTests.MAPS, max_records=100, max_bytes=65536)
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
                else:
                    content = b"[]"
            path.write_bytes(content)
            surface = {"id": item["id"], "phase": "stopped",
                       "acquisition_id": "a" * 32, "size": len(content),
                       "sha256": hashlib.sha256(content).hexdigest()}
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
                self.publish_fixture(root, *args)
                self.assertEqual(len(self.check(root, args[0])), 9)

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
                self.assertEqual(len(self.check(root, manifest)), 9)

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

    def test_strict_metadata_diagnostics_are_bounded_and_redacted(self):
        marker = "PRIVATE_METADATA_MARKER"
        malformed_value = marker + "_" * 20_000
        dumper = load_dumper()
        for map_type, oracle in (("hash", "dump"), ("array", "dump"),
                                 ("prog_array", "dump"), ("cgroup_array", "dump"),
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
                     "boolean-control-byte", "duplicate-json-field"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, receipt, records, controls = self.fixture(root)
                self.publish_fixture(root, manifest, receipt, records, controls)
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
                    return [] if name == "EVENTS" else [discovery]

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
                return [event_bytes(0)] if name == "EVENTS" else []

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
