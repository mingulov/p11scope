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


def six_fields(values=(4, 16, 1, 32, 2048, 1)):
    # Literal wire values, independently derived from the frozen v3 policy.
    cells = b"".join(struct.pack("<BBH", kind, 1, value)
                     for kind, value in enumerate(values, 1))
    return cells + bytes(8) + bytes([8, 1, 0, 0])


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
    for session, rv in ((0x701, 17), (0x702, 18), (0x703, 336), (0x704, 5), (0x705, 1)):
        lines.append("P11SCOPE_OBJECT " + json.dumps({
            "index": 24, "name": "C_GetAttributeValue", "session": session,
            "rv": rv, "ready": 1,
        }))
    return "\n".join(lines) + "\n"


class ObjectTailTests(unittest.TestCase):
    def test_valid_create_tail_decodes(self):
        decoded = evidence["decode_object_tail"](valid_tail())
        self.assertEqual(
            decoded, {"index": 21, "action": 1, "layout": 1, "flags": 0})

    def test_find_section_matches_wire_offsets(self):
        # ObjectCallWire (#[repr(C)], field order frozen since 6e9cc157
        # and pinned by the object_wire offset tests): find_len@124,
        # find_flags@125, find_valid@126, reserved1@127, reserved2@236..240.
        # The oracle must decode the struct's own Find bytes.
        tail = bytearray(valid_tail(index=28, action=evidence["OBJECT_FIND_ACTION"]))
        for slot, preset in enumerate(evidence["OBJECT_FIND_PRESETS"]):
            struct.pack_into("<Q", tail, 48 + 8 * slot, preset)
            tail[116 + slot] = 1
        tail[124], tail[126] = 8, 1
        self.assertEqual(
            evidence["decode_object_tail"](bytes(tail)),
            {"index": 28, "action": evidence["OBJECT_FIND_ACTION"],
             "layout": 1, "flags": 0})
        # The swapped twin (validity read from the reserved1 pad) refuses.
        swapped = bytearray(tail)
        swapped[126], swapped[127] = 0, 1
        with self.assertRaises(AssertionError):
            evidence["decode_object_tail"](bytes(swapped))
        # Every reserved byte rejects, mirroring validate_object_tail.
        for offset in (127, 236, 237, 238, 239):
            bad = bytearray(tail)
            bad[offset] = 1
            with self.subTest(offset=offset), self.assertRaises(AssertionError):
                evidence["decode_object_tail"](bytes(bad))

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
            (127, 1), (236, 1), (237, 1), (238, 1), (239, 1),
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
        bad[126] = 1
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
        self.assertEqual(len(entries), 30)

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

    def completion_records(self, target_bits=64):
        records = []
        for position, (ordinal, _name) in enumerate(evidence["OBJECT_LEDGER"]):
            marked = ordinal + 1 in evidence["OBJECT_TEMPLATE_INDICES"]
            tail = bytearray(valid_tail(
                index=ordinal + 1, action=self.ACTIONS[ordinal],
                layout=1 if target_bits == 64 else 2,
                result=((0, 0), (0, 0)),
                requested0=(bytes(32) + bytes([0, 0x10, 0, 0])
                            if marked else bytes(36))))
            if ordinal == 24:
                tail[128:164] = bytes(36)
                tail[200:236] = six_fields()
            elif ordinal + 1 in {21, 22, 59, 60, 62, 63}:
                tail[128:164] = six_fields()
            if ordinal == 59:
                tail[164:200] = six_fields((2, 3, 0, 24, 4096, 2))
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
                tail[124], tail[126] = 8, 1
            for slot, preset in enumerate(
                    evidence["OBJECT_INPUT_PRESETS"][ordinal]):
                struct.pack_into("<Q", tail, 16 + 8 * slot, preset)
                tail[112 + slot] = 1
            records.append(base_record(self.COMPLETED_PID, 0x601 + position)
                           + bytes(tail))
        for session, rv, curve in ((0x701, 17, 2), (0x702, 18, 3), (0x703, 336, 1),
                                   (0x704, 5, None), (0x705, 1, None)):
            base = bytearray(base_record(self.COMPLETED_PID, session))
            struct.pack_into("<Q", base, 64, rv)
            tail = bytearray(valid_tail(index=25, action=11, result=((0, 0), (0, 0)),
                                        layout=1 if target_bits == 64 else 2,
                                        inputs=((1, 0x224), (0, 0)), requested0=bytes(36)))
            tail[200:236] = (six_fields((4, 16, 1, 32, 2048, curve)) if curve else
                             bytes(32) + bytes([0, 16, 0, 0]))
            records.append(bytes(base) + bytes(tail))
        return records

    def test_completion_replay_matches_ledger(self):
        evidence["assert_object_completion_records"](
            self.completion_records(), "object-lp64", self.COMPLETED_PID)

    def test_completion_replay_keeps_the_selected_target_width(self):
        good = self.completion_records(32)
        evidence["assert_object_completion_records"](good, "object-ia32", self.COMPLETED_PID)
        bad = [bytearray(row) for row in good]
        bad[0][368 + 12] = 1
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in bad], "object-ia32", self.COMPLETED_PID)

    def test_canary_rejects_missing_six_field_capture_and_pair_mixup(self):
        good = self.completion_records()
        # Each mutant remains a structurally valid finite wire record.
        cases = []
        for field in range(6):
            bad = [bytearray(row) for row in good]
            bad[0][368 + 128 + 4 * field:368 + 132 + 4 * field] = bytes(4)
            cases.append((f"missing field {field}", bad))
        bad = [bytearray(row) for row in good]
        bad[0][368 + 128:368 + 164] = bytes(32) + bytes([0, 16, 0, 0])
        cases.append(("UNINSPECTED instead of capture", bad))
        bad = [bytearray(row) for row in good]
        bad[15][368 + 164:368 + 200] = six_fields()
        cases.append(("pair copied public template", bad))
        bad = [bytearray(row) for row in good]
        bad[4][368 + 200:368 + 236] = bytes(36)
        cases.append(("Get lost results", bad))
        for name, records in cases:
            with self.subTest(name=name), self.assertRaises(AssertionError):
                evidence["assert_object_completion_records"](
                    [bytes(row) for row in records], "object-lp64", self.COMPLETED_PID)

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

    def test_partial_results_and_error_cancel_remain_separate(self):
        good = self.completion_records()
        evidence["assert_object_completion_records"](good, "object-lp64", self.COMPLETED_PID)
        for position, change in ((25, "lost_partial"), (26, "wrong_curve"),
                                 (27, "wrong_rv"), (28, "error_values"),
                                 (29, "cancel_values")):
            bad = [bytearray(row) for row in good]
            if change == "lost_partial":
                bad[position][368 + 200:368 + 236] = bytes(32) + bytes([0, 16, 0, 0])
            elif change == "wrong_curve":
                bad[position][368 + 222:368 + 224] = b"\x01\x00"
            elif change == "wrong_rv":
                struct.pack_into("<Q", bad[position], 64, 0)
            else:
                bad[position][368 + 200:368 + 236] = six_fields()
            with self.subTest(change=change), self.assertRaises(AssertionError):
                evidence["assert_object_completion_records"](
                    [bytes(row) for row in bad], "object-lp64", self.COMPLETED_PID)


class ObjectSideRowTests(unittest.TestCase):
    BLOCKED_PID = 4242
    POINTERS = {"template": 0x7000, "peer_template": 0x8000,
                "out_create": 0x9000, "out_pub": 0x9008, "out_priv": 0x9010,
                "found": 0x9020, "found_count": 0x9060,
                "get_values": [0xA000 + 16 * i for i in range(6)]}

    def blocked_fixture(self, target_bits=64):
        starts, rows = {}, []
        specs = (
            (1001, 0x501, 21, 1, dict(result_ptrs=(0x9000, 0))),
            (1002, 0x502, 60, 4, dict(result_ptrs=(0x9008, 0x9010))),
            (1003, 0x503, 28, 10, dict(result_ptrs=(0x9020, 0),
                                       find_capacity=8, find_count_ptr=0x9060)),
            (1004, 0x504, 25, 11, dict(inputs=(0x224, 0),
                                       input_statuses=(1, 0))),
        )
        markers = {0x501: 22, 0x502: 61, 0x503: 29, 0x504: 26}
        for tid, session, index, action, fields in specs:
            starts[tid] = evidence["decode_start"](
                start_row(session, markers[session]))
            key = struct.pack("<QII", (self.BLOCKED_PID << 32) | tid, 3, 0)
            raw = bytearray(side_row(descriptor_index=index, action=action,
                                    layout=1 if target_bits == 64 else 2, **fields))
            if session in (0x501, 0x502):
                raw[352:388] = six_fields()
                if session == 0x502:
                    raw[388:424] = six_fields((2, 3, 0, 24, 4096, 2))
            if session == 0x504:
                width = target_bits // 8
                struct.pack_into("<QQ", raw, 64, 0x7000, 0x7000 + 24 * width)
                raw[430] = 8
                for slot, (pointer, capacity) in enumerate(zip(
                        self.POINTERS["get_values"], (width, width, 1, width, width, 10))):
                    struct.pack_into("<QQQBBB5x", raw, 96 + slot * 32,
                                     pointer, capacity, 0, slot + 1, slot, 0)
            rows.append((key, evidence["decode_object_start"](bytes(raw))))
        return starts, rows

    def test_blocked_offsets_match(self):
        for width in (32, 64):
            with self.subTest(width=width):
                starts, rows = self.blocked_fixture(width)
                evidence["assert_object_side_rows"](rows, starts, self.POINTERS, width)

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
            ("create requested", 0, 352, 1, 2),
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


UNINSPECTED = bytes(32) + bytes([0, 0x10, 0, 0])
STUB_CREATION_ORDINALS = {20, 21, 58, 59, 61, 62}


def stub_completion_records(helper):
    """The FULL completion fixture with stub attribute bytes: present
    pairs marked UNINSPECTED, absent pairs zero, scalars untouched."""
    records = [bytearray(row) for row in helper.completion_records()]
    for position, (ordinal, _name) in enumerate(evidence["OBJECT_LEDGER"]):
        if ordinal in STUB_CREATION_ORDINALS:
            assert records[position][368 + 128:368 + 164] == six_fields()
            records[position][368 + 128:368 + 164] = UNINSPECTED
        elif ordinal == 24:
            # Get's pair zero is descriptor-present (stub-marked) though
            # FULL never request-inspects it.
            assert records[position][368 + 128:368 + 164] == bytes(36)
            records[position][368 + 128:368 + 164] = UNINSPECTED
        else:
            assert records[position][368 + 128:368 + 164] == bytes(36)
        if ordinal == 59:
            records[position][368 + 164:368 + 200] = UNINSPECTED
        else:
            assert records[position][368 + 164:368 + 200] == bytes(36)
        if ordinal == 24:
            assert records[position][368 + 200:368 + 236] == six_fields()
            records[position][368 + 200:368 + 236] = UNINSPECTED
        else:
            assert records[position][368 + 200:368 + 236] == bytes(36)
    for position in range(25, 30):
        assert records[position][368 + 128:368 + 200] == bytes(72)
        records[position][368 + 128:368 + 164] = UNINSPECTED
        records[position][368 + 200:368 + 236] = UNINSPECTED
    assert [bytes(row) for row in records] != helper.completion_records()
    return [bytes(row) for row in records]


class ObjectAbsentModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        evidence["initialize"](64)

    def setUp(self):
        evidence["set_object_attributes"]("present")

    def tearDown(self):
        evidence["set_object_attributes"]("present")

    def test_unknown_mode_refuses(self):
        with self.assertRaises(ValueError):
            evidence["set_object_attributes"]("bogus")
        with self.assertRaises(ValueError):
            evidence["set_object_attributes"]("")
        self.assertFalse(evidence["object_attributes_absent"]())

    def test_cli_flag_forms(self):
        kept = evidence["extract_object_attributes"](
            ["--object-attributes=absent", "--object-starts", "x", "64"])
        self.assertEqual(kept, ["--object-starts", "x", "64"])
        self.assertTrue(evidence["object_attributes_absent"]())
        evidence["set_object_attributes"]("present")
        kept = evidence["extract_object_attributes"](
            ["--object-starts", "--object-attributes", "absent", "x", "64"])
        self.assertEqual(kept, ["--object-starts", "x", "64"])
        self.assertTrue(evidence["object_attributes_absent"]())
        evidence["set_object_attributes"]("present")
        kept = evidence["extract_object_attributes"](["--object-starts", "x", "64"])
        self.assertEqual(kept, ["--object-starts", "x", "64"])
        self.assertFalse(evidence["object_attributes_absent"]())
        with self.assertRaises(ValueError):
            evidence["extract_object_attributes"](["--object-attributes=bogus", "64"])
        with self.assertRaises(ValueError):
            evidence["extract_object_attributes"](["--object-attributes"])

    def test_duplicate_modes_validate_every_occurrence(self):
        # An earlier unknown mode must not be silently overwritten by a
        # later valid one: every occurrence is validated.
        with self.assertRaises(ValueError):
            evidence["extract_object_attributes"](
                ["--object-attributes=bogus", "--object-attributes=absent",
                 "64"])
        with self.assertRaises(ValueError):
            evidence["extract_object_attributes"](
                ["--object-attributes=", "--object-attributes=present",
                 "64"])
        with self.assertRaises(ValueError):
            evidence["extract_object_attributes"](
                ["--object-attributes", "bogus",
                 "--object-attributes=absent", "64"])
        with self.assertRaises(ValueError):
            evidence["extract_object_attributes"](
                ["--object-attributes=absent", "--object-attributes=bogus",
                 "64"])
        # Repeating a valid mode stays accepted and selects it.
        kept = evidence["extract_object_attributes"](
            ["--object-attributes=absent", "--object-attributes=absent",
             "64"])
        self.assertEqual(kept, ["64"])
        self.assertTrue(evidence["object_attributes_absent"]())

    def test_absent_completion_replay_matches_stub(self):
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        evidence["set_object_attributes"]("absent")
        evidence["assert_object_completion_records"](
            stub_completion_records(helper), "object-lp64", helper.COMPLETED_PID)

    def test_absent_completion_replay_keeps_the_selected_target_width(self):
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        records = [bytearray(row) for row in helper.completion_records(32)]
        for position, (ordinal, _name) in enumerate(evidence["OBJECT_LEDGER"]):
            if ordinal in STUB_CREATION_ORDINALS or ordinal == 24:
                records[position][368 + 128:368 + 164] = UNINSPECTED
            if ordinal == 59:
                records[position][368 + 164:368 + 200] = UNINSPECTED
            if ordinal == 24:
                records[position][368 + 200:368 + 236] = UNINSPECTED
        for position in range(25, 30):
            records[position][368 + 128:368 + 164] = UNINSPECTED
            records[position][368 + 200:368 + 236] = UNINSPECTED
        evidence["set_object_attributes"]("absent")
        evidence["assert_object_completion_records"](
            [bytes(row) for row in records], "object-ia32", helper.COMPLETED_PID)

    def test_absent_completion_refuses_full_values_and_unrun_capture(self):
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        evidence["set_object_attributes"]("absent")
        full = helper.completion_records()
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                full, "object-lp64", helper.COMPLETED_PID)
        stub = stub_completion_records(helper)
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                stub[:-1], "object-lp64", helper.COMPLETED_PID)
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [], "object-lp64", helper.COMPLETED_PID)
        # An unmarked creation list is not an honest stub outcome: emission
        # must still have run and marked the present pair.
        unmarked = [bytearray(row) for row in stub]
        unmarked[0][368 + 128:368 + 164] = bytes(36)
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in unmarked], "object-lp64",
                helper.COMPLETED_PID)
        # Kept scalar assertions still bite in absent mode.
        bad_scalar = [bytearray(row) for row in stub]
        struct.pack_into("<Q", bad_scalar[0], 368 + 32, 0xDEAD)
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in bad_scalar], "object-lp64",
                helper.COMPLETED_PID)

    def test_absent_completion_refuses_unmarked_get_requested(self):
        # Get returns keep the stub marking on pair zero with pair one
        # absent; each half of that expectation bites independently.
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        evidence["set_object_attributes"]("absent")
        stub = stub_completion_records(helper)
        get_pos = 25
        unmarked = [bytearray(row) for row in stub]
        unmarked[get_pos][368 + 128:368 + 164] = bytes(36)
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in unmarked], "object-lp64",
                helper.COMPLETED_PID)
        marked_absent = [bytearray(row) for row in stub]
        marked_absent[get_pos][368 + 164:368 + 200] = UNINSPECTED
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in marked_absent], "object-lp64",
                helper.COMPLETED_PID)
        leaked = [bytearray(row) for row in stub]
        leaked[get_pos][368 + 128:368 + 164] = six_fields()
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in leaked], "object-lp64",
                helper.COMPLETED_PID)

    def test_absent_completion_refuses_unmarked_get_results(self):
        # The stub establishes no Get results at any return value: the
        # result list keeps the UNINSPECTED marking on all five returns
        # and on the ledger Get.
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        evidence["set_object_attributes"]("absent")
        stub = stub_completion_records(helper)
        ledger = [ordinal for ordinal, _ in evidence["OBJECT_LEDGER"]]
        get_pos, ledger_get = 25, ledger.index(24)
        for position in (get_pos, ledger_get):
            with self.subTest(position=position):
                unmarked = [bytearray(row) for row in stub]
                unmarked[position][368 + 200:368 + 236] = bytes(36)
                with self.assertRaises(AssertionError):
                    evidence["assert_object_completion_records"](
                        [bytes(row) for row in unmarked], "object-lp64",
                        helper.COMPLETED_PID)
                leaked = [bytearray(row) for row in stub]
                leaked[position][368 + 200:368 + 236] = six_fields()
                with self.assertRaises(AssertionError):
                    evidence["assert_object_completion_records"](
                        [bytes(row) for row in leaked], "object-lp64",
                        helper.COMPLETED_PID)

    def test_absent_completion_refuses_pair_private_mutations(self):
        # Pair separation survives the stub: the pair's private list is
        # marked only for GenerateKeyPair and zero everywhere else.
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        evidence["set_object_attributes"]("absent")
        stub = stub_completion_records(helper)
        ledger = [ordinal for ordinal, _ in evidence["OBJECT_LEDGER"]]
        pair_pos, create_pos = ledger.index(59), ledger.index(20)
        unmarked = [bytearray(row) for row in stub]
        unmarked[pair_pos][368 + 164:368 + 200] = bytes(36)
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in unmarked], "object-lp64",
                helper.COMPLETED_PID)
        marked_absent = [bytearray(row) for row in stub]
        marked_absent[create_pos][368 + 164:368 + 200] = UNINSPECTED
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in marked_absent], "object-lp64",
                helper.COMPLETED_PID)
        leaked = [bytearray(row) for row in stub]
        leaked[create_pos][368 + 164:368 + 200] = six_fields(
            (2, 3, 0, 24, 4096, 2))
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                [bytes(row) for row in leaked], "object-lp64",
                helper.COMPLETED_PID)

    def test_present_completion_refuses_stub_bytes(self):
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        with self.assertRaises(AssertionError):
            evidence["assert_object_completion_records"](
                stub_completion_records(helper), "object-lp64",
                helper.COMPLETED_PID)

    def test_absent_side_rows_match_stub(self):
        side = ObjectSideRowTests("test_blocked_offsets_match")
        evidence["set_object_attributes"]("absent")
        for width in (32, 64):
            with self.subTest(width=width):
                starts, rows = self._stub_fixture(side, width)
                evidence["assert_object_side_rows"](rows, starts, side.POINTERS, width)

    def _stub_row(self, raw, descriptor_index):
        stub = bytearray(raw)
        stub[352:424] = bytes(72)
        if descriptor_index == 25:
            stub[64:96] = bytes(32)
            stub[96:352] = bytes(256)
            stub[430] = 0
        return bytes(stub)

    def _stub_fixture(self, side, width):
        starts, rows = side.blocked_fixture(width)
        assert rows[0][1]["raw"][352:388] == six_fields()
        assert rows[3][1]["descriptor_index"] == 25
        assert rows[3][1]["raw"][430] == 8
        return starts, [(key, evidence["decode_object_start"](
            self._stub_row(row["raw"], row["descriptor_index"]))) for key, row in rows]

    def test_absent_side_rows_refuse_full_values_and_leaks(self):
        side = ObjectSideRowTests("test_blocked_offsets_match")
        evidence["set_object_attributes"]("absent")
        starts, rows = side.blocked_fixture()
        with self.assertRaises(AssertionError):
            evidence["assert_object_side_rows"](rows, starts, side.POINTERS, 64)
        _starts, stub_rows = self._stub_fixture(side, 64)
        # A leaking stub row (inspected values where zeros belong) refuses.
        grown = [(key, bytearray(row["raw"])) for key, row in stub_rows]
        grown[0][1][352:388] = six_fields()
        with self.assertRaises(AssertionError):
            evidence["assert_object_side_rows"](
                [(key, evidence["decode_object_start"](bytes(blob)))
                 for key, blob in grown], starts, side.POINTERS, 64)
        # Kept scalar assertions still bite in absent mode.
        grown = [(key, bytearray(row["raw"])) for key, row in stub_rows]
        grown[0][1][48:56] = (0x1234).to_bytes(8, "little")
        with self.assertRaises(AssertionError):
            evidence["assert_object_side_rows"](
                [(key, evidence["decode_object_start"](bytes(blob)))
                 for key, blob in grown], starts, side.POINTERS, 64)

    def test_absent_side_rows_refuse_get_header_retention(self):
        # The stub acquires no Get attributes at entry: template base,
        # slots and inspected count stay zero on the Get side row, and
        # retained FULL bytes refuse, whole or in part.
        side = ObjectSideRowTests("test_blocked_offsets_match")
        evidence["set_object_attributes"]("absent")
        starts, full_rows = side.blocked_fixture()
        get_row = full_rows[3][1]["raw"]
        assert full_rows[3][1]["descriptor_index"] == 25
        assert get_row[64:80] != bytes(16) and get_row[430] == 8
        assert get_row[96:352] != bytes(256)
        _starts, stub_rows = self._stub_fixture(side, 64)

        def check(mutate):
            grown = [(key, bytearray(row["raw"])) for key, row in stub_rows]
            mutate(grown[3][1])
            with self.assertRaises(AssertionError):
                evidence["assert_object_side_rows"](
                    [(key, evidence["decode_object_start"](bytes(blob)))
                     for key, blob in grown], starts, side.POINTERS, 64)

        def retain_all(blob):
            blob[64:80] = get_row[64:80]
            blob[96:352] = get_row[96:352]
            blob[430] = 8

        def retain_count(blob):
            blob[430] = 8

        def retain_template(blob):
            blob[64:80] = get_row[64:80]

        check(retain_all)
        check(retain_count)
        check(retain_template)

    def test_present_side_rows_refuse_stub_bytes(self):
        side = ObjectSideRowTests("test_blocked_offsets_match")
        starts, _rows = side.blocked_fixture()
        _starts, stub_rows = self._stub_fixture(side, 64)
        with self.assertRaises(AssertionError):
            evidence["assert_object_side_rows"](
                stub_rows, starts, side.POINTERS, 64)

    def test_absent_full_oracle_passes_on_stub_cell(self):
        helper = ObjectRecordsTests("test_completion_replay_matches_ledger")
        side = ObjectSideRowTests("test_blocked_offsets_match")
        oracle = ObjectStartsOracleTests("test_full_oracle_passes")
        starts, _rows = side.blocked_fixture()
        _starts, stub_rows = self._stub_fixture(side, 64)
        blocked_starts = [
            (struct.pack("<QII", (side.BLOCKED_PID << 32) | tid, 3, 0),
             start_row(start["session"],
                       {0x501: 22, 0x502: 61, 0x503: 29, 0x504: 26}[start["session"]]))
            for tid, start in sorted(starts.items())]
        blocked_log = ("P11SCOPE_OBJECT_POINTERS "
                       + json.dumps(side.POINTERS) + "\n")
        evidence["set_object_attributes"]("absent")
        with tempfile.TemporaryDirectory() as root:
            args = oracle.write_cell(
                root, stub_completion_records(helper), stub_rows,
                blocked_starts, ledger_text(), blocked_log)
            evidence["assert_object_starts"](*args, helper.COMPLETED_PID,
                                             side.BLOCKED_PID, 64)


if __name__ == "__main__":
    unittest.main()
