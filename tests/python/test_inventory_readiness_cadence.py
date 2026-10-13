#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay delayed Inventory publication through the real readiness controller.

Only the clock, fixture command and held-image queries are substituted. The
append-only JSONL cursor, pass accounting, marker freshness and readiness
predicate are production code. No provider, subprocess or native capture runs.
"""

import json
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
SECOND = 1_000_000_000


class InventoryReadinessCadenceTest(unittest.TestCase):
    def setUp(self):
        self.now = 100 * SECOND
        self.origin = self.now
        self.deadline = self.now + 90 * SECOND
        self.owner = SimpleNamespace(pid=101, identity={"start_time": 77})
        self.image = {"path": "/fixture/caller", "dev": 2049, "ino": 42, "mtime_ns": 222}
        self.provider = {"path": "/fixture/provider", "mapping": {"dev": [8, 1], "ino": 43}}
        self.executable = SimpleNamespace(verify=lambda: None, image_receipt=lambda *_: self.image)
        self.pin = object()
        self.globals = H6["wait_inventory_s1_ready"].__globals__
        patch = mock.patch.dict(self.globals, monotonic_ns=lambda: self.now,
                               pause_until=self.pause, provider_receipt=lambda _: self.provider)
        patch.start()
        self.addCleanup(patch.stop)
        temporary = tempfile.TemporaryDirectory(prefix="h6-readiness-cadence-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "inventory.jsonl"
        self.seq = 0
        self.pass_number = 0
        self.markers = []
        self.schedule = []
        self.on_attempt = lambda _number: None
        self.caller = {"id": "c0", "pid": 101, "start_time": 77, "incarnation": 0,
                       "authority": "scan_pinned", "lifecycle": "mapped", "status": "observed",
                       "executable": {"path": self.image["path"], "dev": 2049, "ino": 42,
                                      "mtime_secs": 0, "mtime_nanos": 222}}
        self.append("started", {"started_ns": self.now - 100})
        admitted = self.append("caller_event", {"event": "admitted", "caller": "c0",
            "identity_context": {"version": 1, "caller": self.caller}})
        committed = self.commit()
        self.cursor = H6["R5AdmissionCursor"](self.path, self.owner, self.executable)
        self.addCleanup(self.cursor.close)
        self.admission = {"caller": "c0", "incarnation": 0, "seq": admitted["seq"],
                          "completed_pass": H6["r5_pass_receipt"](committed)}

    def append(self, kind, event, *, partial=False):
        row = {"schema": "p11scope/inventory-events/v1", "seq": self.seq,
               "at_ns": self.now, "kind": kind, "event": event}
        self.seq += 1
        with self.path.open("a") as stream:
            stream.write(json.dumps(row) + ("" if partial else "\n"))
        return row

    def commit(self, *, edges=0, instances=0, semantics=0, partial=False, **changes):
        event = {"pass": self.pass_number, "scanned": 1, "maps_matched": 1,
                 "native_callers": 0, "scan_callers": 1, "totals": {"callers": 1, "modules": 1, "edges": 1},
                 "new_gaps": 0, "suppressed_delta": 0, "gaps_suppressed": 0,
                 "edge_events": edges, "instance_events": instances, "semantic_edge_events": semantics,
                 "edge_events_deferred": 0, "instance_events_deferred": 0,
                 "semantic_edge_events_deferred": 0, "unbound_rows": [], "unbound_rows_truncated": 0,
                 **changes}
        self.pass_number += 1
        return self.append("pass_committed", event, partial=partial)

    def warm(self, number, deadline):
        self.assertEqual(deadline, self.deadline, "readiness renewed its original deadline")
        self.on_attempt(number)
        start = self.now
        self.now += 1_000_000
        marker = {"ack": {"command": "W", "gen": 0, "attempt": number, "seq": number,
                          "pid": 101, "start": 77, "exe": self.image["path"], "t0": start,
                          "t1": self.now, "deadline": deadline, "idle": 1, "rv": 0},
                  "batches": [{"cell": "RX", "pid": 101, "start": 77, "gen": 0,
                               "exe": self.image["path"], "module": self.provider["path"],
                               "fn": fn, "mech": "0x250", "n": 5, "bad": 0,
                               "phase": f"h6-warm{number}", "t0": start + 1, "t1": self.now - 1}
                              for fn in ("C_DigestInit", "C_Digest")]}
        self.markers.append(marker)
        return marker

    def publish(self, marker, *, count=10, stale=False):
        module = {"id": "m0", "device_major": 8, "device_minor": 1, "inode": 43,
                  "path": self.provider["path"], "status": "observed"}
        self.append("edge_observed", {"caller": "c0", "module": "m0", "mapping": {"state": "mapped"},
            "entries": {"count": count, "last_seen_ns": marker["ack"]["t1"], "saturated": False,
                        "coverage": {"state": "counted", "lossy": False}},
            "identity_context": {"version": 1, "caller": self.caller, "module": module}})
        self.append("instance_observed", {"id": "i0", "caller": "c0", "module": "m0",
                                           "state": "observed", "reason": None})
        api = 2 if stale else count
        self.append("semantic_edge_observed", {"caller": "c0", "module": "m0", "instance": "i0",
            "semantics": "observed", "entries": {"unit": "api_entries", "count": None, "observation": "unavailable"},
            "api_returns": {"count": api, "saturated": False, "historical_only_returns": 0},
            "mechanisms": [{"mechanism_hex": "0x250", "calls": api, "errors": 0}],
            "operations": {"calls": api, "completed": api // 2, "failed": 0,
                           "unknown": 0, "orphans": 0, "dropped": 0,
                           "last_seen_ns": marker["ack"]["t0"] if stale else marker["ack"]["t1"] - 1},
            "coverage": {"lossy": False, "reasons": []}})
        self.commit(edges=1, instances=1, semantics=1)

    def at(self, seconds, callback):
        self.schedule.append((self.origin + int(seconds * SECOND), callback))
        self.schedule.sort(key=lambda item: item[0])

    def pause(self, deadline, interval):
        self.now = min(deadline, self.now + int(interval * SECOND))
        while self.schedule and self.schedule[0][0] <= self.now:
            _, callback = self.schedule.pop(0)
            callback()

    def gate(self, **kwargs):
        return H6["wait_inventory_s1_ready"](self.owner, self.executable, self.pin,
            self.admission, self.cursor, self.warm, self.deadline, **kwargs)

    def test_seven_second_passes_hold_latest_marker_until_stale_s1_catches_up(self):
        self.at(7, lambda: self.publish(self.markers[0], stale=True))
        self.at(14, lambda: self.publish(self.markers[0]))
        proof = self.gate()
        self.assertEqual(proof["attempts"], 1)
        self.assertEqual(len(self.markers), 1)
        self.assertEqual(proof["baseline"]["counts"]["api"], 10)
        self.assertEqual(proof["baseline"]["counts"]["completed"], 5)
        self.assertGreaterEqual(proof["observed_ns"], self.origin + 14 * SECOND)
        self.assertLess(proof["observed_ns"], self.deadline)

    def test_existing_acked_prefix_is_observed_before_another_warmup(self):
        first = self.warm(1, self.deadline)
        self.at(7, lambda: self.publish(first))
        proof = self.gate(prefix_batches=first["batches"], prefix_markers=[first])
        self.assertEqual(proof["attempts"], 1)
        self.assertEqual(len(self.markers), 1)

    def test_uncaptured_first_entry_gets_bounded_priming_after_two_publications(self):
        self.at(7, self.commit)
        def missed():
            self.append("gap_recorded", {"caller": "c0", "module": "m0", "pid": 101,
                "subject": "early coverage", "reason": "use_before_admission"})
            self.commit()
        self.at(14, missed)
        def second(number):
            if number == 2:
                self.assertGreaterEqual(self.now, self.origin + 14 * SECOND)
                self.at(21, lambda: self.publish(self.markers[-1]))
        self.on_attempt = second
        proof = self.gate()
        self.assertEqual(proof["attempts"], 2)
        self.assertEqual(proof["baseline"]["early"]["api_missed"], 10)
        self.assertEqual(proof["baseline"]["counts"]["completed"], 5)

    def test_absent_publication_expires_at_original_deadline_with_caller_idle(self):
        with self.assertRaises(TimeoutError):
            self.gate()
        self.assertEqual(self.now, self.deadline)
        self.assertEqual(len(self.markers), 1)

    def test_twentieth_unsuccessful_attempt_cannot_dispatch_a_twenty_first(self):
        def opportunity(number):
            elapsed = (self.now - self.origin) / SECOND
            self.at(elapsed + 0.1, self.commit)
            self.at(elapsed + 0.2, self.commit)
        self.on_attempt = opportunity
        with self.assertRaisesRegex(H6["SetupError"], "20 bounded real attempts"):
            self.gate()
        self.assertEqual(len(self.markers), 20)
        self.assertLess(self.now, self.origin + 6 * SECOND)

    def test_partial_pass_never_credits_another_attempt(self):
        self.at(7, self.commit)
        self.at(14, lambda: self.commit(partial=True))
        with self.assertRaises(TimeoutError):
            self.gate()
        self.assertEqual(len(self.markers), 1)

    def test_malformed_pass_refuses_without_dispatching_another_attempt(self):
        self.at(7, lambda: self.commit(semantic_edge_events_deferred=None))
        with self.assertRaisesRegex(H6["SetupError"], "accounting"):
            self.gate()
        self.assertEqual(len(self.markers), 1)

    def test_deferred_emitter_does_not_credit_a_settled_opportunity(self):
        self.at(7, lambda: self.commit(semantic_edge_events_deferred=1))
        self.at(14, self.commit)
        with self.assertRaises(TimeoutError):
            self.gate()
        self.assertEqual(len(self.markers), 1)

    def test_repeated_same_pass_is_not_two_publication_opportunities(self):
        self.at(7, lambda: self.commit(**{"pass": 1}))
        self.at(14, lambda: self.commit(**{"pass": 1}))
        with self.assertRaises(TimeoutError):
            self.gate()
        self.assertEqual(len(self.markers), 1)

    def test_pre_ack_passes_do_not_credit_a_new_marker(self):
        self.commit()
        self.commit()
        with self.assertRaises(TimeoutError):
            self.gate()
        self.assertEqual(len(self.markers), 1)

    def test_final_pass_is_not_a_live_readiness_opportunity(self):
        self.at(7, lambda: self.commit(final=True))
        with self.assertRaisesRegex(H6["SetupError"], "live completing pass"):
            self.gate()
        self.assertEqual(len(self.markers), 1)

    def test_expired_recovery_never_dispatches_a_priming_call(self):
        self.now = self.deadline
        with self.assertRaises(TimeoutError):
            self.gate()
        self.assertFalse(self.markers)


if __name__ == "__main__":
    unittest.main()
