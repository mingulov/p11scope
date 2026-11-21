#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Record grammar tables for scripts/journal-load-verdict.py.

The journal load gate's verdicts come from one typed helper with one
strict grammar per input: the guest status records, the probe stream
(the verifier report's own parser) and the observer proof lines. These
tables drive the helper's functions directly with small owned inputs:
each healthy shape must pass, and every malformed twin (truncated,
duplicated, reordered, mixed kinds, bad numbers, decode errors) must
fail closed with a named reason. tests/python/test_check_bpf_load_journal.py
drives the whole gate through fake guests.
"""

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/journal-load-verdict.py"
_SPEC = importlib.util.spec_from_file_location("journal_load_verdict", HELPER)
verdict = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verdict)
report = verdict.report
KERNEL = "v6.6.157"


def load_row(root, *, loaded=True, btf_id=61, processed=1000):
    return {"record": "load", "pid": 111, "root": root, "btf_resolved": True,
            "btf_fd": 4, "btf_id": btf_id, "returned_btf_id": btf_id,
            "root_type_id": 1, "returned_fd": 5 if loaded else -1,
            "program_id": 7 if loaded else 0, "program_type": 2,
            "returned_program_type": 2, "program_flags": 0,
            "expected_attach_type": 0, "insn_count": 100,
            "relocated_fnv1a64": "123456789abcdef0", "loaded": loaded,
            "errno": 0 if loaded else 22, "stats_present": True,
            "processed": processed, "limit": 1000000, "auxiliary": None}


def line(row):
    return (json.dumps(row) + "\n").encode()


def stream(rows, *, summary=None, extra=b""):
    body = b"".join(line(row) for row in rows)
    if summary is None:
        summary = {"record": "probe-summary", "pid": 111, "records": len(rows),
                   "write_failures": 0, "overflow": False}
    return body + extra + (line(summary) if summary is not False else b"")


PAIR_ROWS = [load_row("p11_entry_journal"), load_row("p11_return_journal"),
             load_row("p11_image_query")]
HEALTHY = stream(PAIR_ROWS)


class ProbeStreamTests(unittest.TestCase):
    """parse_probe_stream: the one grammar the report and the gate share."""

    def test_healthy_stream_is_valid(self):
        loads, problems = report.parse_probe_stream(HEALTHY)
        self.assertEqual(problems, [])
        self.assertEqual(len(loads), 3)

    def test_summary_only_stream_is_valid(self):
        loads, problems = report.parse_probe_stream(stream([]))
        self.assertEqual((loads, problems), ([], []))

    MALFORMED = {
        "empty": b"",
        "no summary": stream(PAIR_ROWS, summary=False),
        "truncated summary": HEALTHY[:-10],
        "truncated final newline": HEALTHY[:-1],
        "truncated load row": line(PAIR_ROWS[0])[:40] + b"\n" + stream(PAIR_ROWS[1:]),
        "blank record": stream(PAIR_ROWS, extra=b"\n"),
        "duplicated summary": HEALTHY + line(
            {"record": "probe-summary", "pid": 111, "records": 3,
             "write_failures": 0, "overflow": False}),
        "summary not final": HEALTHY + line(PAIR_ROWS[0]),
        "reordered summary first": line(
            {"record": "probe-summary", "pid": 111, "records": 3,
             "write_failures": 0, "overflow": False})
            + b"".join(line(row) for row in PAIR_ROWS),
        "summary undercounts": stream(PAIR_ROWS, summary={
            "record": "probe-summary", "pid": 111, "records": 2,
            "write_failures": 0, "overflow": False}),
        "summary count is a string": stream(PAIR_ROWS, summary={
            "record": "probe-summary", "pid": 111, "records": "3",
            "write_failures": 0, "overflow": False}),
        "summary count is a boolean": stream([PAIR_ROWS[0]], summary={
            "record": "probe-summary", "pid": 111, "records": True,
            "write_failures": 0, "overflow": False}),
        "summary count negative": stream([], summary={
            "record": "probe-summary", "pid": 111, "records": -1,
            "write_failures": 0, "overflow": False}),
        "summary write failure": stream(PAIR_ROWS, summary={
            "record": "probe-summary", "pid": 111, "records": 3,
            "write_failures": 1, "overflow": False}),
        "summary overflow": stream(PAIR_ROWS, summary={
            "record": "probe-summary", "pid": 111, "records": 3,
            "write_failures": 0, "overflow": True}),
        "summary lacks overflow": stream(PAIR_ROWS, summary={
            "record": "probe-summary", "pid": 111, "records": 3,
            "write_failures": 0}),
        "probe error": stream(PAIR_ROWS + [{"record": "probe-error",
                                            "reason": "record-bound"}]),
        "unknown kind": stream(PAIR_ROWS + [{"record": "other"}]),
        "mixed kinds on one line": line(PAIR_ROWS[0]).rstrip(b"\n")
            + line({"record": "probe-summary", "pid": 111, "records": 1,
                    "write_failures": 0, "overflow": False}),
        "incomplete load row": stream([{"record": "load",
                                        "root": "p11_entry_journal",
                                        "loaded": False}]),
        "load row with string processed": stream(
            [{**PAIR_ROWS[0], "processed": "1000"}]),
        "load row with numeric loaded": stream([{**PAIR_ROWS[0], "loaded": 1}]),
        "load row with empty root": stream([{**PAIR_ROWS[0], "root": ""}]),
        "duplicate key": HEALTHY.replace(b'"loaded": true',
                                         b'"loaded": false, "loaded": true', 1),
        "non-object record": stream(PAIR_ROWS, extra=b"[]\n"),
        "record kind not a string": stream(PAIR_ROWS, extra=b'{"record": 1}\n'),
        "invalid JSON": stream(PAIR_ROWS, extra=b"{not json}\n"),
        # Python 3.14's iterative scanner decodes this row (then it is
        # not a record object); older interpreters raise RecursionError.
        # test_recursion_error_is_a_row_problem pins that arm directly.
        "deeply nested non-object": stream(
            PAIR_ROWS, extra=b"[" * 100000 + b"0" + b"]" * 100000 + b"\n"),
        "non-ASCII byte": stream(PAIR_ROWS, extra=b"\xff\n"),
        "NUL inside a row": HEALTHY.replace(b'"pid"', b'\x00"pid"', 1),
        "carriage return": HEALTHY.replace(b"}\n", b"}\r\n", 1),
        "UTF-8 root": stream([{**PAIR_ROWS[0], "root": "p11_éntry"}]).replace(
            b"\\u00e9", "é".encode()),
        "bad number": HEALTHY.replace(b'"processed": 1000', b'"processed": 1e3', 1),
    }

    def test_malformed_streams_fail_closed(self):
        for name, data in self.MALFORMED.items():
            with self.subTest(name):
                _, problems = report.parse_probe_stream(data)
                self.assertTrue(problems, f"{name}: accepted {data[:120]!r}")

    def test_row_local_corruption_keeps_validated_loads(self):
        # One bad line never erases the independently valid load rows.
        for name in ("deeply nested non-object", "non-ASCII byte",
                     "invalid JSON", "non-object record", "probe error",
                     "unknown kind"):
            with self.subTest(name):
                loads, problems = report.parse_probe_stream(self.MALFORMED[name])
                self.assertTrue(problems)
                self.assertEqual({row["root"] for row in loads},
                                 {"p11_entry_journal", "p11_return_journal",
                                  "p11_image_query"})

    def test_recursion_error_is_a_row_problem(self):
        # A decoder RecursionError (older Pythons on deep nesting) is a
        # named row problem like any decode error, never an exception
        # that erases the validated loads around it.
        real = json.loads
        poison = b'{"record": "load", "poison": true}'

        def loads(text, **kwargs):
            if text == poison.decode():
                raise RecursionError("maximum recursion depth exceeded")
            return real(text, **kwargs)

        with mock.patch.object(report.json, "loads", side_effect=loads):
            loads_out, problems = report.parse_probe_stream(
                stream(PAIR_ROWS, extra=poison + b"\n"))
        self.assertEqual(len(loads_out), 3)
        self.assertTrue(any("invalid JSON" in problem and "recursion" in problem
                            for problem in problems), problems)

    def test_rejected_rows_are_never_counted_as_loads(self):
        loads, problems = report.parse_probe_stream(
            self.MALFORMED["incomplete load row"])
        self.assertEqual(loads, [])
        self.assertTrue(any("lacks" in problem for problem in problems))

    def test_report_reader_uses_the_same_grammar(self):
        # read_jsonl refuses exactly the streams the parser refuses.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe.jsonl"
            for name, data in self.MALFORMED.items():
                with self.subTest(name):
                    path.write_bytes(data)
                    with self.assertRaises(report.ReportError):
                        report.read_jsonl(path)
            path.write_bytes(HEALTHY)
            self.assertEqual(len(report.read_jsonl(path)), 3)


def guest_log(*, observer_rc="0", leg_rc="0", release="6.6.157-test",
              order=None, extra=()):
    records = {
        "work": "guest-work-ready=ext4 uid-mode=0:700 "
                "TMPDIR=/var/tmp/p11scope-bpf.AbC123",
        "token": "guest-stage=token-ok",
        "workload": "guest-stage=workload-ready",
        "observer": f"guest-stage=observer-rc={observer_rc}",
        "exit": f"journal-rc={leg_rc}",
        "release": f"guest-release={release}",
    }
    keys = order or ["work", "token", "workload", "observer", "exit", "release"]
    lines = ["[    0.1] virtme console noise", "boot-config-present-6.6.157-test"]
    lines += [records[key] for key in keys]
    lines += list(extra)
    return ("\n".join(lines) + "\n").encode()


class GuestStatusTests(unittest.TestCase):
    def test_healthy_logs_pass(self):
        for rc in ("0", "1", "124", "255"):
            with self.subTest(rc):
                self.assertEqual(
                    verdict.guest_status(guest_log(observer_rc=rc, leg_rc=rc), KERNEL),
                    ("ok", int(rc), "6.6.157-test"))

    MALFORMED = {
        "observer timeout, leg success": (
            guest_log(observer_rc="124", leg_rc="0"), "disagrees"),
        "observer success, leg refusal": (
            guest_log(observer_rc="0", leg_rc="1"), "disagrees"),
        "bare duplicate journal-rc": (
            guest_log(extra=["journal-rc"]), "guest exit"),
        "duplicate journal-rc": (
            guest_log(extra=["journal-rc=0"]), "guest exit"),
        "journal-rc missing delimiter value": (
            guest_log(leg_rc=""), "guest exit"),
        "journal-rc leading zero": (
            guest_log(observer_rc="0", leg_rc="00"), "guest exit"),
        "journal-rc out of range": (
            guest_log(observer_rc="256", leg_rc="256"), "guest exit"),
        "journal-rc sign": (guest_log(leg_rc="+0"), "guest exit"),
        "journal-rc trailing text": (guest_log(leg_rc="0 x"), "guest exit"),
        "journal-rc missing": (
            guest_log(order=["work", "token", "workload", "observer", "release"]),
            "guest exit"),
        "observer-rc missing": (
            guest_log(order=["work", "token", "workload", "exit", "release"]),
            "observer exit record missing"),
        "observer-rc bare": (
            guest_log(extra=["guest-stage=observer-rc"]), "corrupt"),
        "observer-rc leading zero": (
            guest_log(observer_rc="00"), "corrupt"),
        "observer-rc duplicate": (
            guest_log(extra=["guest-stage=observer-rc=0"]), "contradictory"),
        "token duplicate": (
            guest_log(extra=["guest-stage=token-ok"]), "contradictory"),
        "token and failure": (
            guest_log(extra=["guest-stage=token-failed"]), "contradictory"),
        "stage unknown": (
            guest_log(extra=["guest-stage=other"]), "corrupt"),
        "stage bare label": (guest_log(extra=["guest-stage"]), "corrupt"),
        "stage control byte": (
            guest_log(extra=["guest-stage=token-ok\x07"]), "corrupt"),
        "token missing": (
            guest_log(order=["work", "workload", "observer", "exit", "release"]),
            "never ran"),
        "stages reordered": (
            guest_log(order=["work", "workload", "token", "observer", "exit",
                             "release"]), "out of order"),
        "exit before observer": (
            guest_log(order=["work", "token", "workload", "exit", "observer",
                             "release"]), "out of order"),
        "release before exit": (
            guest_log(order=["work", "token", "workload", "observer", "release",
                             "exit"]), "out of order"),
        "work-ready after stages": (
            guest_log(order=["token", "work", "workload", "observer", "exit",
                             "release"]), "out of order"),
        "work-ready bare": (
            guest_log(order=["token", "workload", "observer", "exit", "release"],
                      extra=["guest-work-ready"]), "work area"),
        "work-ready duplicate": (
            guest_log(extra=["guest-work-ready=ext4 uid-mode=0:700 "
                             "TMPDIR=/var/tmp/p11scope-bpf.AbC123"]), "work area"),
        "release bare duplicate": (
            guest_log(extra=["guest-release"]), "release line"),
        "release with delimiter": (
            guest_log(release="6.6.157=x"), "release line"),
        "release NUL": (guest_log(release="6.6.157\x00x"), "release line"),
        "non-ASCII exit": (guest_log(leg_rc="0\xff"), "guest exit"),
    }

    def test_malformed_logs_refuse_as_infrastructure(self):
        for name, (data, reason) in self.MALFORMED.items():
            with self.subTest(name):
                status = verdict.guest_status(data, KERNEL)
                self.assertEqual(status[0], "infra", f"{name}: {status}")
                self.assertIn(reason, status[1])


LINKED = """p11scope: native usage lane active (Inventory capture activated)
p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: recorded)
p11scope: semantic calls: collected 233, joined 203, shed 30, lost 0, bindings 1, refused 0, hook misses 0, eras 0, instances 1
key operations: 2 keys on 1 provider; rev 12 populated; 1 session
  key row i1 object 9 sign key (rsa_2048): probably RSA (from mechanism); RSA 2048 (from signature length)
  key row i1 object 10 verify key (rsa_2048): probably RSA (from mechanism); size unknown (no length map for this mechanism)
key operations: the function table of /usr/lib/softhsm/libsofthsm2.so cannot be verified
p11scope: joint decoder: raw_malformed=0 raw_malformed_unprovable=0
"""


def text(data):
    return verdict.ObserverText(data.encode("latin-1"))


class ObserverTextTests(unittest.TestCase):
    def test_healthy_linked_text_passes(self):
        observed = text(LINKED)
        self.assertEqual(verdict.linked_reasons(observed), [])
        self.assertEqual(verdict.key_size_reasons(observed), [])

    LINKED_TWINS = {
        "seal duplicated": (LINKED.replace(
            "p11scope: semantic calls:",
            "p11scope: semantic lane ready; mechanisms and API results are "
            "recorded from now on (key operations: recorded)\n"
            "p11scope: semantic calls:", 1), "never sealed"),
        "seal truncated": (LINKED.replace(
            " (key operations: recorded)\n", "\n", 1), "never sealed"),
        "seal bare label duplicate": (LINKED + "p11scope: semantic lane ready\n",
                                      "never sealed"),
        "seal unknown state": (LINKED.replace(
            "(key operations: recorded)", "(key operations: maybe)"), "never sealed"),
        "stop duplicated": (LINKED + LINKED.splitlines()[2] + "\n", "idle"),
        "stop truncated": (LINKED.replace(", instances 1", ""), "idle"),
        "stop leading zero": (LINKED.replace("joined 203", "joined 0203"), "idle"),
        "stop negative": (LINKED.replace("lost 0", "lost -1"), "idle"),
        "stop zero joined": (LINKED.replace("joined 203", "joined 0"), "idle"),
        "stop zero bindings": (LINKED.replace("bindings 1", "bindings 0"), "idle"),
        "stop reordered fields": (LINKED.replace(
            "shed 30, lost 0", "lost 0, shed 30"), "idle"),
        "stop control byte": (LINKED.replace("eras 0", "eras\x070"), "idle"),
        "refusal diagnostic": (LINKED + "p11scope: key operations unavailable: x\n",
                               "linked lane refused"),
        "omitted-build reason": (LINKED + "journal-pair-unavailable-in-build\n",
                                 "linked lane refused"),
    }

    def test_malformed_linked_proofs_fail(self):
        for name, (data, reason) in self.LINKED_TWINS.items():
            with self.subTest(name):
                reasons = verdict.linked_reasons(text(data))
                self.assertTrue(reasons, name)
                self.assertIn(reason, "; ".join(reasons))

    KEY_SIZE_TWINS = {
        "summary missing": (LINKED.replace(
            "key operations: 2 keys on 1 provider; rev 12 populated; 1 session\n",
            ""), "never rendered"),
        "summary duplicated": (LINKED.replace(
            "key operations: 2 keys", "key operations: 2 keys on 1 provider; rev "
            "12 populated; 1 session\nkey operations: 2 keys", 1), "never rendered"),
        "summary plural mismatch": (LINKED.replace("2 keys", "1 keys"),
                                    "never rendered"),
        "summary bad status": (LINKED.replace("populated", "fine"),
                               "never rendered"),
        "summary leading zero": (LINKED.replace("rev 12", "rev 012"),
                                 "never rendered"),
        "RSA row missing": (LINKED.replace("RSA 2048 (from signature length)",
                                           "size unknown"), "RSA-2048"),
        "RSA row trailing text": (LINKED.replace(
            "RSA 2048 (from signature length)\n",
            "RSA 2048 (from signature length) extra\n"), "RSA-2048"),
        "RSA row verify role": (LINKED.replace("sign key (rsa_2048): probably",
                                               "verify key (rsa_2048): probably", 1),
                                "RSA-2048"),
        "RSA row unknown category": (LINKED.replace("sign key (rsa_2048)",
                                                    "sign key (rsa 2048)"), "RSA-2048"),
        "decoder missing": (LINKED.replace(
            "p11scope: joint decoder: raw_malformed=0 raw_malformed_unprovable=0\n",
            ""), "absent or unprovable"),
        "decoder duplicated": (LINKED + "p11scope: joint decoder: raw_malformed=0 "
                               "raw_malformed_unprovable=0\n", "absent or unprovable"),
        "decoder bare label": (LINKED + "p11scope: joint decoder:\n",
                               "absent or unprovable"),
        "decoder unknown": (LINKED.replace("raw_malformed=0 raw_malformed_unprovable=0",
                                           "raw_malformed=unknown raw_malformed_unprovable=1"),
                            "absent or unprovable"),
        "decoder unprovable": (LINKED.replace("raw_malformed_unprovable=0",
                                              "raw_malformed_unprovable=1"),
                               "absent or unprovable"),
        "decoder positive": (LINKED.replace("raw_malformed=0 ", "raw_malformed=3 "),
                             "malformed journal records"),
        "decoder leading zero": (LINKED.replace("raw_malformed=0 ", "raw_malformed=00 "),
                                 "absent or unprovable"),
        "decoder NUL tail": (LINKED.replace("raw_malformed_unprovable=0\n",
                                            "raw_malformed_unprovable=0\x00x\n"),
                             "absent or unprovable"),
    }

    def test_malformed_key_size_proofs_fail(self):
        for name, (data, reason) in self.KEY_SIZE_TWINS.items():
            with self.subTest(name):
                reasons = verdict.key_size_reasons(text(data))
                self.assertTrue(reasons, name)
                self.assertIn(reason, "; ".join(reasons))


class RefusalFormTests(unittest.TestCase):
    """The pre-Multi refusal: one exact producer form, nothing else."""

    SOURCE = (ROOT / "src/attach/multi_host.rs").read_text(encoding="utf-8")

    @classmethod
    def producer_text(cls):
        # Rust string continuations (`\` + newline + indentation) join
        # into one line, as the compiler renders them.
        return re.sub(r"\\\n\s*", "", cls.SOURCE)

    def test_fixed_text_matches_the_producer_source(self):
        source = self.producer_text()
        for fixed in (
                "is not supported on this host{reason}; run 'p11scope doctor' for "
                "host readiness, or use 'p11scope inventory --capture scan' or "
                "'p11scope inspect --pid N' for a scan without capture.",
                "live capture did not start: {doing} failed{reason}; run 'p11scope "
                "doctor' for host readiness, or use 'p11scope inventory --capture "
                "scan' or 'p11scope inspect --pid N' for a scan without capture.",
                "live capture refused: {}; or use 'p11scope inspect --pid N' for a "
                "scan without capture.",
                "with CAP_BPF and CAP_PERFMON held - a kernel lockdown, an LSM "
                "policy, or a container's seccomp profile is refusing BPF here. Run "
                "'p11scope doctor' for host readiness, or use 'p11scope inspect "
                "--pid N' for a scan without capture.",
                "with CAP_SYS_ADMIN held - a kernel lockdown, an LSM policy, or a "
                "container's seccomp profile is refusing BPF here. Run 'p11scope "
                "doctor' for host readiness, or use 'p11scope inspect --pid N' for "
                "a scan without capture.",
                "live capture {}: the kernel refused to {operation}{reason}. Grant "
                "the minimal set: {}, or use 'p11scope inspect --pid N' for a scan "
                "without capture.",
                "MultiHostStage::Anchor => \"prepare p11scope's self-probe\"",
                "MultiHostStage::ProgramLoad => \"load p11scope's BPF programs\"",
                "MultiHostStage::SelfLink => \"attach p11scope's probes\"",
                "MultiHostStage::Anchor => \"preparing p11scope's self-probe\"",
                "MultiHostStage::ProgramLoad => \"loading p11scope's BPF programs\"",
                "MultiHostStage::SelfLink => \"attaching p11scope's probes\""):
            with self.subTest(fixed[:40]):
                self.assertIn(fixed, source)
        userns = re.sub(r"\\\n\s*", "", (ROOT / "src/userns.rs").read_text())
        self.assertIn(verdict._USERNS_CAUSE, userns)
        main = (ROOT / "src/main.rs").read_text()
        self.assertIn('cli::ScopeArg::System => "inventory --system".to_string(),', main)
        self.assertIn('try_stderr_line(&format!("p11scope: {e:#}"))', main)
        caps = (ROOT / "src/caps.rs").read_text()
        self.assertIn('enables: "load BPF programs and attach probes"', caps)
        self.assertIn('enables: "load BPF programs alongside CAP_BPF"', caps)
        self.assertIn("cap_bpf,cap_checkpoint_restore,cap_dac_read_search,"
                      "cap_perfmon,cap_sys_ptrace=ep", caps)

    def test_each_producer_arm_has_a_form(self):
        self.assertEqual(set(verdict.LIVE_REFUSAL_FORMS),
                         {"unavailable", "did not start",
                          "refused (user namespace)",
                          "refused (capabilities held)", "needs"})

    def test_invented_cause_is_not_a_form(self):
        self.assertIsNone(verdict.live_refusal_form(
            "p11scope: inventory --system: live capture unavailable: "
            "unrelated diagnostic for a scan without capture."))

    def test_superstring_of_a_form_is_not_a_form(self):
        observed = ("p11scope: inventory --system: live capture did not start: "
                    "attaching p11scope's probes failed (Invalid argument); run "
                    "'p11scope doctor' for host readiness, or use 'p11scope "
                    "inventory --capture scan' or 'p11scope inspect --pid N' for "
                    "a scan without capture.")
        self.assertIsNotNone(verdict.live_refusal_form(observed))
        for twin in (observed + " extra", "x" + observed, observed + observed):
            with self.subTest(twin[:30]):
                self.assertIsNone(verdict.live_refusal_form(twin))

    def test_every_errno_name_fits_the_refusal_form(self):
        # Each Linux strerror name renders inside the producer's
        # ` (Name)` errno position (src/attach/multi_host.rs errno_name).
        for errno in range(1, 134):
            name = os.strerror(errno)
            with self.subTest(errno=errno, name=name):
                line = ("p11scope: inventory --system: live capture did not "
                        f"start: loading p11scope's BPF programs failed ({name}); "
                        "run 'p11scope doctor' for host readiness, or use "
                        "'p11scope inventory --capture scan' or 'p11scope "
                        "inspect --pid N' for a scan without capture.")
                self.assertEqual(verdict.live_refusal_form(line), "did not start")

    def test_observed_guest_refusal_is_a_form(self):
        # The exact line 6.1.188 and 5.15.221 guests printed for the
        # gate's command (real vng run of a dev-tip observer).
        observed = ("p11scope: inventory --system: live capture did not start: "
                    "attaching p11scope's probes failed (Invalid argument); run "
                    "'p11scope doctor' for host readiness, or use 'p11scope "
                    "inventory --capture scan' or 'p11scope inspect --pid N' for "
                    "a scan without capture.")
        self.assertEqual(verdict.live_refusal_form(observed), "did not start")
        self.assertIsNone(verdict.live_refusal_form(
            observed.replace("p11scope: inventory --system: ", "p11scope: ")))


if __name__ == "__main__":
    unittest.main()
