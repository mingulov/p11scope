#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Counter-mode parity against real SoftHSM: comparator and twins.

The harness (scripts/counter-softhsm-parity.sh) runs one real SoftHSM
workload twice under `run --mode metrics`: once plain and once with
`--counter-mode <mode>`. This suite compares the two `-o` JSON
documents (`--compare PLAIN COUNTER --mode MODE`).

Gates (all must pass): the two documents report the same function
rows (keyed by names and target file offset) with exactly equal
`calls` and `errors` per row, and a hot row with calls > 0 exists
(an empty pair proves nothing); in `timestamps` and `latency` modes
the hot row of the counter document also carries nonzero
`latency_ns.total` and `latency_ns.max`. `counts` publishes no timing
and needs none.

Healthy and mutation twins run here with no SoftHSM install: the
live guest runs are the script's, on 6.6+ kernels where counter
programs load.
"""

import json
import sys
import unittest
from pathlib import Path

TIMING_MODES = ("timestamps", "latency")
ALL_MODES = ("counts",) + TIMING_MODES


class ParityMismatch(AssertionError):
    """One counter/plain parity gate failed."""


def _row_key(row):
    try:
        return (tuple(row["names"]), row["target"]["file_offset"])
    except (KeyError, TypeError) as error:
        raise ParityMismatch(f"function row lacks names/target.file_offset: {row!r}") from error


def _rows_by_key(doc, label):
    if not isinstance(doc, dict):
        raise ParityMismatch(f"{label} document is not an object")
    functions = doc.get("functions")
    if not isinstance(functions, list):
        raise ParityMismatch(f"{label} document has no functions array")
    rows = {}
    for row in functions:
        key = _row_key(row)
        if key in rows:
            raise ParityMismatch(f"{label} document repeats function row {key!r}")
        for field in ("calls", "errors"):
            value = row.get(field)
            if not isinstance(value, int) or value < 0:
                raise ParityMismatch(f"{label} row {key!r} has no {field} count: {row!r}")
        rows[key] = row
    return rows


def compare_counter_parity(plain_doc, counter_doc, mode):
    """Compare a plain and a counter-mode capture of one workload.

    Raises ParityMismatch naming the first failed gate; returns a
    summary dict on success.
    """
    if mode not in ALL_MODES:
        raise ParityMismatch(f"unknown counter mode {mode!r}")
    plain = _rows_by_key(plain_doc, "plain")
    counter = _rows_by_key(counter_doc, "counter")
    if set(plain) != set(counter):
        missing = sorted(set(plain) - set(counter))
        extra = sorted(set(counter) - set(plain))
        raise ParityMismatch(f"function rows differ: missing={missing!r} extra={extra!r}")
    for key in sorted(plain):
        for field in ("calls", "errors"):
            if plain[key][field] != counter[key][field]:
                raise ParityMismatch(
                    f"row {key!r}: plain {field}={plain[key][field]} != "
                    f"counter {field}={counter[key][field]}"
                )
    hot_key = max(sorted(counter), key=lambda key: counter[key]["calls"], default=None)
    if hot_key is None or counter[hot_key]["calls"] == 0:
        raise ParityMismatch("no hot function with calls > 0 in the counter document")
    hot = counter[hot_key]
    summary = {"rows": len(counter), "hot": list(hot_key[0]), "calls": hot["calls"]}
    if mode in TIMING_MODES:
        timing = hot.get("latency_ns")
        if not isinstance(timing, dict):
            raise ParityMismatch(f"hot row {hot_key!r} has no latency_ns in {mode} mode")
        for field in ("total", "max"):
            value = timing.get(field)
            if not isinstance(value, int) or value <= 0:
                raise ParityMismatch(
                    f"hot row {hot_key!r} has non-positive latency_ns.{field}={value!r}"
                )
        summary["total"] = timing["total"]
        summary["max"] = timing["max"]
    return summary


def _main_compare(argv):
    try:
        plain_path = argv[argv.index("--compare") + 1]
        counter_path = argv[argv.index("--compare") + 2]
        mode = argv[argv.index("--mode") + 1]
    except (ValueError, IndexError):
        print("usage: test_counter_softhsm_parity.py --compare PLAIN COUNTER --mode MODE",
              file=sys.stderr)
        return 2
    try:
        plain_doc = json.loads(Path(plain_path).read_text())
        counter_doc = json.loads(Path(counter_path).read_text())
    except (OSError, ValueError) as error:
        print(f"parity: cannot read inputs: {error}", file=sys.stderr)
        return 2
    try:
        summary = compare_counter_parity(plain_doc, counter_doc, mode)
    except ParityMismatch as error:
        print(f"parity FAIL ({mode}): {error}", file=sys.stderr)
        return 1
    print(f"parity OK ({mode}): rows={summary['rows']} hot={'+'.join(summary['hot'])} "
          f"calls={summary['calls']}" +
          (f" total={summary['total']} max={summary['max']}" if mode in TIMING_MODES else ""))
    return 0


def _row(names, offset, calls, errors, timing=None):
    row = {
        "names": list(names),
        "target": {"file_offset": offset},
        "calls": calls,
        "errors": errors,
    }
    if timing is not None:
        row["latency_ns"] = dict(timing)
    return row


def _doc(rows):
    return {"schema": "p11scope/observed-profile/v3-metrics", "functions": list(rows)}


_HOT = _row(["C_GetSlotList"], 0x12340, 200, 0,
            {"approximate": False, "total": 345678, "max": 91011})
_COLD = _row(["C_GetSlotInfo"], 0x23450, 12, 2,
             {"approximate": False, "total": 4567, "max": 890})


class ParityTwins(unittest.TestCase):
    def test_healthy_pair_passes_in_all_modes(self):
        plain = _doc([_HOT, _COLD])
        counter = _doc([dict(_HOT), dict(_COLD)])
        for mode in ALL_MODES:
            summary = compare_counter_parity(plain, counter, mode)
            self.assertEqual(summary["rows"], 2)
            self.assertEqual(summary["calls"], 200)

    def test_counts_needs_no_timing(self):
        plain = _doc([{"names": ["C_GetInfo"], "target": {"file_offset": 1},
                       "calls": 5, "errors": 0, "latency_ns": None}])
        summary = compare_counter_parity(plain, _doc([dict(plain["functions"][0])]), "counts")
        self.assertEqual(summary["calls"], 5)

    def test_calls_drift_fails(self):
        plain = _doc([_HOT])
        counter = _doc([_row(["C_GetSlotList"], 0x12340, 199, 0, _HOT["latency_ns"])])
        with self.assertRaises(ParityMismatch):
            compare_counter_parity(plain, counter, "counts")

    def test_errors_drift_fails(self):
        plain = _doc([_COLD])
        counter = _doc([_row(["C_GetSlotInfo"], 0x23450, 12, 3, _COLD["latency_ns"])])
        with self.assertRaises(ParityMismatch):
            compare_counter_parity(plain, counter, "counts")

    def test_missing_row_fails(self):
        with self.assertRaises(ParityMismatch):
            compare_counter_parity(_doc([_HOT, _COLD]), _doc([_HOT]), "counts")

    def test_extra_row_fails(self):
        with self.assertRaises(ParityMismatch):
            compare_counter_parity(_doc([_HOT]), _doc([_HOT, _COLD]), "counts")

    def test_empty_pair_fails_for_lack_of_hot_function(self):
        with self.assertRaises(ParityMismatch):
            compare_counter_parity(_doc([]), _doc([]), "counts")

    def test_zero_timing_fails_in_timing_modes(self):
        for timing in ({"approximate": False, "total": 0, "max": 12},
                       {"approximate": False, "total": 345678, "max": 0}):
            plain = _doc([_HOT])
            counter = _doc([_row(["C_GetSlotList"], 0x12340, 200, 0, timing)])
            for mode in TIMING_MODES:
                with self.assertRaises(ParityMismatch, msg=f"{mode} {timing}"):
                    compare_counter_parity(plain, counter, mode)

    def test_missing_timing_fails_in_timing_modes(self):
        plain = _doc([_HOT])
        counter = _doc([_row(["C_GetSlotList"], 0x12340, 200, 0)])
        for mode in TIMING_MODES:
            with self.assertRaises(ParityMismatch, msg=mode):
                compare_counter_parity(plain, counter, mode)


if __name__ == "__main__":
    if "--compare" in sys.argv:
        sys.exit(_main_compare(sys.argv))
    unittest.main()
