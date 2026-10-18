# SPDX-License-Identifier: GPL-3.0-or-later
"""H7 slice D object-cell oracle tests: 608-byte records, stopped offsets,
ledger replay and live-surface honesty, all hermetic."""

import json
import runpy
import struct
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
evidence = runpy.run_path(str(REPO / "scripts" / "check-canary-evidence.py"),
                          run_name="canary_object_tests")


def tok(raw):
    return [f"0x{byte:02x}" for byte in bytes(raw)]


def base_record(pid, session, event_type=0):
    raw = bytearray(368)
    struct.pack_into("<Q", raw, 16, (pid << 32) | 7)
    struct.pack_into("<Q", raw, 32, session)
    struct.pack_into("<I", raw, 284, event_type)
    return bytes(raw)


def valid_tail(index=21, action=1, layout=1, result=((1, 0xA11CE), (0, 0)),
               inputs=((0, 0), (0, 0)), requested0=None):
    tail = bytearray(240)
    struct.pack_into("<HHII", tail, 0, 1, 240, index, 0)
    tail[12], tail[13], tail[14] = layout, action, 0
    for slot, (status, word) in enumerate(inputs):
        struct.pack_into("<Q", tail, 16 + 8 * slot, word)
        tail[112 + slot] = status
    for slot, (status, word) in enumerate(result):
        struct.pack_into("<Q", tail, 32 + 8 * slot, word)
        tail[114 + slot] = status
    if requested0 is None:
        requested0 = bytes(32) + bytes([0, 0x10, 0, 0])
    tail[128:164] = requested0
    return bytes(tail)


def side_row(descriptor_index=21, action=1, layout=1, phase=2,
             inputs=(0, 0), input_statuses=(0, 0),
             result_ptrs=(0, 0), result_statuses=(0, 0),
             find_capacity=0, find_count_ptr=0):
    raw = bytearray(432)
    struct.pack_into("<QQ", raw, 0, 0xC00CE, 0xE9EC)
    struct.pack_into("<Q", raw, 16, 0xCAFE)
    struct.pack_into("<I", raw, 24, descriptor_index)
    raw[28], raw[29], raw[30], raw[31] = layout, action, 0, phase
    struct.pack_into("<2Q", raw, 32, *inputs)
    struct.pack_into("<2Q", raw, 48, *result_ptrs)
    struct.pack_into("<Q", raw, 80, find_capacity)
    struct.pack_into("<Q", raw, 88, find_count_ptr)
    raw[424:426] = bytes(input_statuses)
    raw[426:428] = bytes(result_statuses)
    return bytes(raw)


def start_row(session, marker):
    raw = bytearray(288)
    struct.pack_into("<Q", raw, 8, session)
    struct.pack_into("<Q", raw, 264, marker)
    return bytes(raw)


def ledger_text():
    lines = []
    for position, (index, name) in enumerate(evidence["OBJECT_LEDGER"]):
        lines.append("P11SCOPE_OBJECT " + json.dumps({
            "index": index, "name": name, "session": 0x601 + position,
            "rv": 0, "ready": 1,
        }))
    return "\n".join(lines) + "\n"


class ObjectTailTests(unittest.TestCase):
    def test_valid_create_tail_decodes(self):
        decoded = evidence["decode_object_tail"](valid_tail())
        self.assertEqual(
            decoded, {"index": 21, "action": 1, "layout": 1, "flags": 0})

    def test_tail_mutations_refuse(self):
        cases = []
        good = bytearray(valid_tail())
        for offset, size, value in [
            (0, 2, 2), (2, 2, 239), (4, 4, 0), (4, 4, 105), (4, 4, 21 - 1),
            (8, 4, 0x100),
        ]:
            bad = bytearray(good)
            bad[offset:offset + size] = value.to_bytes(size, "little")
            cases.append((f"header@{offset}={value}", bytes(bad)))
        for offset, value in [
            (12, 0), (12, 3), (13, 0), (13, 13), (14, 5), (15, 1),
            (126, 1), (239, 1),
        ]:
            bad = bytearray(good)
            bad[offset] = value
            cases.append((f"byte@{offset}={value}", bytes(bad)))
        # Handle words: VALUE needs nonzero, everything else needs zero.
        bad = bytearray(good)
        bad[114] = 1
        struct.pack_into("<Q", bad, 32, 0)
        cases.append(("zero VALUE word", bytes(bad)))
        bad = bytearray(good)
        bad[115] = 7
        struct.pack_into("<Q", bad, 40, 0x1234)
        cases.append(("nonzero unavailable word", bytes(bad)))
        bad = bytearray(good)
        bad[112] = 11
        cases.append(("input status 11", bytes(bad)))
        # Find section: refused keeps no length, cells, or validity.
        bad = bytearray(good)
        bad[127] = 1
        cases.append(("non-Find valid flag", bytes(bad)))
        bad = bytearray(good)
        bad[48] = 1
        cases.append(("non-Find handle", bytes(bad)))
        bad = bytearray(good)
        bad[124] = 9
        cases.append(("find_len 9", bytes(bad)))
        bad = bytearray(good)
        bad[125] = 0x40
        cases.append(("find flags high bit", bytes(bad)))
        # Request lists: padding, bits, counts, cells, marker honesty.
        for offset, value in [(128 + 34, 1), (128 + 33, 0x20)]:
            bad = bytearray(good)
            bad[offset] = value
            cases.append((f"list@{offset}={value:#x}", bytes(bad)))
        bad = bytearray(good)
        bad[128 + 33] = 0x11
        cases.append(("marker plus present bit", bytes(bad)))
        bad = bytearray(good)
        bad[128 + 32] = 1
        cases.append(("marker plus inspected count", bytes(bad)))
        bad = bytearray(good)
        bad[128] = 1
        cases.append(("marker plus nonzero cell", bytes(bad)))
        bad = bytearray(good)
        bad[128:164] = bytes(36)
        cases.append(("template unmarked all-zero first list", bytes(bad)))
        bad = bytearray(good)
        bad[128 + 33] = 0
        bad[128 + 32] = 1
        cases.append(("inspected without present bit", bytes(bad)))
        bad = bytearray(good)
        bad[128 + 33] = 2
        bad[128 + 32] = 7
        cases.append(("truncated short list", bytes(bad)))
        bad = bytearray(good)
        bad[128 + 33] = 1
        bad[128 + 32] = 1
        bad[128] = 7
        cases.append(("cell kind 7", bytes(bad)))
        bad = bytearray(good)
        bad[128 + 33] = 1
        bad[128 + 32] = 1
        bad[129] = 11
        cases.append(("cell status 11", bytes(bad)))
        bad = bytearray(good)
        bad[128 + 33] = 1
        bad[128 + 32] = 2
        bad[134] = 9
        cases.append(("value without VALUE status", bytes(bad)))
        bad = bytearray(good)
        bad[200] = 1
        cases.append(("non-Get result list", bytes(bad)))
        for name, blob in cases:
            with self.subTest(name):
                with self.assertRaises(AssertionError, msg=name):
                    evidence["decode_object_tail"](blob)

    def test_inspected_template_list_decodes(self):
        tail = bytearray(valid_tail())
        tail[128:132] = bytes([1, 1, 3, 0])
        tail[128 + 32] = 1
        tail[128 + 33] = 1
        self.assertEqual(evidence["decode_object_tail"](bytes(tail))["index"], 21)

    def test_decode_event_forms(self):
        plain = evidence["decode_event"](base_record(4242, 0x601))
        self.assertEqual(
            (plain["session"], plain["event_type"], plain["object"]),
            (0x601, 0, None))
        full = evidence["decode_event"](
            base_record(4242, 0x601) + valid_tail())
        self.assertEqual(full["object"]["index"], 21)
        with self.assertRaises(AssertionError):
            evidence["decode_event"](
                base_record(4242, 0x601, event_type=1) + valid_tail())
        for size in (367, 369, 607, 609):
            with self.subTest(size=size), self.assertRaises(AssertionError):
                evidence["decode_event"](bytes(size))


class MixedRingTests(unittest.TestCase):
    def test_mixed_framing_and_positions(self):
        records = [base_record(9, 0x601), base_record(9, 0x602) + valid_tail(),
                   base_record(9, 0x603)]
        body = b"".join(
            struct.pack("<II", len(row), 0) + row for row in records)
        capacity = 4096
        data = body + bytes(2 * capacity - len(body))
        span = sum(evidence["ring_stride"](len(row)) for row in records)
        parsed = evidence["parse_ring_records"](data, capacity, 0, span, (368, 608))
        self.assertEqual(parsed, records)
        self.assertIsNone(
            evidence["ring_position_fault"]("EVENTS", [0, span], parsed))
        self.assertIsNotNone(
            evidence["ring_position_fault"]("EVENTS", [0, span + 8], parsed))
        self.assertIsNotNone(
            evidence["ring_position_fault"]("EVENTS", [0, span], parsed + [b"x"]))

    def test_bad_sizes_refuse(self):
        for size in (367, 369, 607, 609):
            body = struct.pack("<II", size, 0) + bytes(size)
            capacity = 4096
            data = body + bytes(2 * capacity - len(body))
            with self.subTest(size=size), self.assertRaises(AssertionError):
                evidence["parse_ring_records"](
                    data, capacity, 0, evidence["ring_stride"](size), (368, 608))

    def test_count_compat_for_single_stride(self):
        self.assertIsNone(
            evidence["ring_position_fault"]("DISCOVERY", [0, 2 * 928], 2))


class ObjectLedgerTests(unittest.TestCase):
    def test_complete_ledger_replays(self):
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "workload.log"
            log.write_text(ledger_text())
            entries = evidence["object_ledger_entries"](str(log))
        self.assertEqual(len(entries), 25)

    def test_short_ledger_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "workload.log"
            log.write_text("\n".join(ledger_text().splitlines()[:24]) + "\n")
            with self.assertRaises(AssertionError):
                evidence["object_ledger_entries"](str(log))

    def test_failed_call_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "workload.log"
            lines = ledger_text().splitlines()
            entry = json.loads(lines[0].removeprefix("P11SCOPE_OBJECT "))
            entry["rv"], entry["ready"] = 7, 0
            lines[0] = "P11SCOPE_OBJECT " + json.dumps(entry)
            log.write_text("\n".join(lines) + "\n")
            with self.assertRaises(AssertionError):
                evidence["object_ledger_entries"](str(log))


class ObjectRecordsTests(unittest.TestCase):
    COMPLETED_PID = 4343

    ACTIONS = {20: 1, 21: 2, 58: 3, 59: 4, 62: 5, 61: 6, 22: 7,
               23: 8, 40: 8, 60: 8, 24: 11, 25: 12, 27: 10, 29: 9,
               33: 9, 42: 9, 46: 9, 48: 9, 52: 9, 72: 9, 77: 9,
               82: 9, 87: 9, 94: 9, 17: 9}

    def completion_records(self):
        records = []
        for position, (ordinal, _name) in enumerate(evidence["OBJECT_LEDGER"]):
            marked = ordinal + 1 in evidence["OBJECT_TEMPLATE_INDICES"]
            tail = bytearray(valid_tail(
                index=ordinal + 1, action=self.ACTIONS[ordinal],
                result=((0, 0), (0, 0)),
                requested0=(bytes(32) + bytes([0, 0x10, 0, 0])
                            if marked else bytes(36))))
            if ordinal == 24:
                tail[200 + 33] = 0x10
            if ordinal in evidence["OBJECT_RESULT_PRESETS"]:
                presets = evidence["OBJECT_RESULT_PRESETS"][ordinal]
                for slot, preset in enumerate(presets):
                    struct.pack_into("<Q", tail, 32 + 8 * slot, preset)
                    tail[114 + slot] = 1
            if ordinal == 27:
                tail[13] = evidence["OBJECT_FIND_ACTION"]
                struct.pack_into("<Q", tail, 32, 0)
                tail[114] = 7
                for slot, preset in enumerate(evidence["OBJECT_FIND_PRESETS"]):
                    struct.pack_into("<Q", tail, 48 + 8 * slot, preset)
                    tail[116 + slot] = 1
                tail[124], tail[127] = 8, 1
            for slot, preset in enumerate(
                    evidence["OBJECT_INPUT_PRESETS"][ordinal]):
                struct.pack_into("<Q", tail, 16 + 8 * slot, preset)
                tail[112 + slot] = 1
            records.append(base_record(self.COMPLETED_PID, 0x601 + position)
                           + bytes(tail))
        return records

    def test_completion_replay_matches_ledger(self):
        evidence["assert_object_completion_records"](
            self.completion_records(), "object-lp64", self.COMPLETED_PID)

    def test_completion_mutations_refuse(self):
        records = self.completion_records()
        short = records[:-1]
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                short, "object-lp64", self.COMPLETED_PID)
        wrong_word = [bytearray(row) for row in records]
        struct.pack_into("<Q", wrong_word[0], 368 + 32, 0xDEAD)
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in wrong_word], "object-lp64",
                self.COMPLETED_PID)
        wrong_tail = [bytearray(row) for row in records]
        struct.pack_into("<I", wrong_tail[3], 368 + 4, 22)
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in wrong_tail], "object-lp64",
                self.COMPLETED_PID)


class ObjectSideRowTests(unittest.TestCase):
    BLOCKED_PID = 4242
    POINTERS = {"template": 0x7001, "out_create": 0x7002, "out_pub": 0x7003,
                "out_priv": 0x7004, "found": 0x7005, "found_count": 0x7006}

    def blocked_fixture(self):
        starts, rows = {}, []
        specs = (
            (1001, 0x501, 21, 1, dict(result_ptrs=(0x7002, 0))),
            (1002, 0x502, 60, 4, dict(result_ptrs=(0x7003, 0x7004))),
            (1003, 0x503, 28, 10, dict(result_ptrs=(0x7005, 0),
                                       find_capacity=8, find_count_ptr=0x7006)),
            (1004, 0x504, 25, 11, dict(inputs=(0x224, 0),
                                       input_statuses=(1, 0))),
        )
        markers = {0x501: 22, 0x502: 61, 0x503: 29, 0x504: 26}
        for tid, session, index, action, fields in specs:
            starts[tid] = evidence["decode_start"](
                start_row(session, markers[session]))
            key = struct.pack("<QII", (self.BLOCKED_PID << 32) | tid, 3, 0)
            rows.append((key, evidence["decode_object_start"](
                side_row(descriptor_index=index, action=action, **fields))))
        return starts, rows

    def test_blocked_offsets_match(self):
        starts, rows = self.blocked_fixture()
        evidence["assert_object_side_rows"](rows, starts, self.POINTERS, 64)

    def test_neighbor_mutations_refuse(self):
        starts, rows = self.blocked_fixture()

        def mutated(worker, offset, size, value):
            grown = [(key, bytearray(row["raw"])) for key, row in rows]
            grown[worker][1][offset:offset + size] = value.to_bytes(
                size, "little")
            return [(key, evidence["decode_object_start"](bytes(blob)))
                    for key, blob in grown]

        cases = [
            ("create input1", 0, 40, 8, 0x7002),
            ("create result1 ptr", 0, 56, 8, 0x7002),
            ("create result status", 0, 426, 1, 1),
            ("create find capacity", 0, 80, 8, 8),
            ("create requested", 0, 352, 1, 1),
            ("create slot", 0, 96, 1, 1),
            ("pair input0", 1, 32, 8, 0x221),
            ("find input0", 2, 32, 8, 0x227),
            ("find status", 2, 426, 1, 1),
            ("get result0 ptr", 3, 48, 8, 0x7002),
            ("get input1", 3, 40, 8, 0x225),
            ("phase", 0, 31, 1, 3),
            ("layout", 0, 28, 1, 2),
            ("derive", 0, 30, 1, 1),
            ("flags", 0, 428, 2, 1),
            ("reserved", 0, 431, 1, 1),
        ]
        for name, worker, offset, size, value in cases:
            with self.subTest(name):
                with self.assertRaises(AssertionError, msg=name):
                    evidence["assert_object_side_rows"](
                        mutated(worker, offset, size, value), starts,
                        self.POINTERS, 64)


class ObjectStartsOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        evidence["initialize"](64)

    def write_cell(self, root, completed_records, blocked_rows, blocked_starts,
                   completed_log, blocked_log):
        root = Path(root)
        completed_manifest = root / "mapdump_manifest_object-lp64.json"
        blocked_manifest = root / "mapdump_manifest_object-lp64-blocked.json"
        completed_side = root / "mapdump_OBJECT_START_object-lp64.json"
        blocked_side = root / "mapdump_OBJECT_START_object-lp64-blocked.json"
        blocked_start = root / "mapdump_START_object-lp64-blocked.json"
        completed_side.write_text(json.dumps([]))
        blocked_side.write_text(json.dumps(
            [{"key": tok(key), "value": tok(row["raw"])}
             for key, row in blocked_rows]))
        blocked_start.write_text(json.dumps(
            [{"key": tok(key), "value": tok(row)}
             for key, row in blocked_starts]))
        completed_manifest.write_text(json.dumps([
            {"name": "OBJECT_START", "file": str(completed_side)},
            {"name": "START", "file": str(root / "empty.json")},
        ]))
        (root / "empty.json").write_text(json.dumps([]))
        blocked_manifest.write_text(json.dumps([
            {"name": "OBJECT_START", "file": str(blocked_side)},
            {"name": "START", "file": str(blocked_start)},
        ]))
        (root / "object-lp64.EVENTS.raw").write_bytes(b"".join(
            struct.pack("<II", len(row), 0) + row for row in completed_records))
        (root / "object-lp64-blocked.EVENTS.raw").write_bytes(b"")
        completed_log_path = root / "completed.workload.log"
        blocked_log_path = root / "blocked.workload.log"
        completed_log_path.write_text(completed_log)
        blocked_log_path.write_text(blocked_log)
        return (str(completed_manifest), str(blocked_manifest),
                str(completed_log_path), str(blocked_log_path))

    def test_full_oracle_passes(self):
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        side = ObjectSideRowTests("test_blocked_offsets_match")
        starts, rows = side.blocked_fixture()
        blocked_starts = [
            (struct.pack("<QII", (side.BLOCKED_PID << 32) | tid, 3, 0),
             start_row(start["session"],
                       {0x501: 22, 0x502: 61, 0x503: 29, 0x504: 26}[start["session"]]))
            for tid, start in sorted(starts.items())]
        blocked_log = ("P11SCOPE_OBJECT_POINTERS "
                       + json.dumps(side.POINTERS) + "\n")
        with tempfile.TemporaryDirectory() as root:
            args = self.write_cell(
                root, helper.completion_records(), rows, blocked_starts,
                ledger_text(), blocked_log)
            evidence["assert_object_starts"](*args, helper.COMPLETED_PID,
                                             side.BLOCKED_PID, 64)

    def test_completed_side_residue_refuses(self):
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        side = ObjectSideRowTests("test_blocked_offsets_match")
        starts, rows = side.blocked_fixture()
        blocked_starts = [
            (struct.pack("<QII", (side.BLOCKED_PID << 32) | tid, 3, 0),
             start_row(start["session"],
                       {0x501: 22, 0x502: 61, 0x503: 29, 0x504: 26}[start["session"]]))
            for tid, start in sorted(starts.items())]
        blocked_log = ("P11SCOPE_OBJECT_POINTERS "
                       + json.dumps(side.POINTERS) + "\n")
        with tempfile.TemporaryDirectory() as root:
            args = self.write_cell(
                root, helper.completion_records(), rows, blocked_starts,
                ledger_text(), blocked_log)
            residue = Path(root) / "mapdump_OBJECT_START_object-lp64.json"
            residue.write_text(json.dumps([{
                "key": tok(struct.pack("<QII", 1, 0, 0)),
                "value": tok(side_row()),
            }]))
            with self.assertRaises(AssertionError):
                evidence["assert_object_starts"](
                    *args, helper.COMPLETED_PID, side.BLOCKED_PID, 64)


class ObjectDriftGuardTests(unittest.TestCase):
    WORKLOAD = REPO / "scripts" / "fixtures" / "canary_workload.c"
    POLICY = REPO / "crates" / "ebpf-common" / "src" / "object_policy.rs"

    def test_oracle_matches_workload_calls(self):
        source = self.WORKLOAD.read_text()
        for index, name in evidence["OBJECT_LEDGER"]:
            self.assertIn(f"I_{name.removeprefix('C_')} = {index}", source,
                          name)
            self.assertIn(f'OBJECT_CALL(I_{name.removeprefix("C_")}, "{name}"',
                          source, name)
        for marker in ("0x0b1e0000", "0x0b1e1000", "0x0b1e2000",
                       "P11SCOPE_OBJECT", "P11SCOPE_OBJECT_POINTERS",
                       "CANARY_OBJECT_"):
            self.assertIn(marker, source, marker)

    def test_oracle_matches_rust_named_set(self):
        policy = self.POLICY.read_text()
        names = {name for _, name in evidence["OBJECT_LEDGER"]}
        self.assertEqual(len(names), 25)
        for name in names:
            self.assertIn(f'"{name}"', policy, name)


if __name__ == "__main__":
    unittest.main()
