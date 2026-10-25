# SPDX-License-Identifier: GPL-3.0-or-later
"""Container-cells oracle (D1 copy-up, N4 late-reported): healthy twins pass, every check refuses its mutation."""

import copy
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "scripts/container-cells-oracle.py"
ORACLE = runpy.run_path(str(ORACLE_PATH))

NAMES = ("C_GenerateRandom", "C_DigestInit", "C_Digest",
         "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal")
PROVIDER = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
LATE_PROVIDER = "/tmp/private/libsofthsm2.so"
PID_A, PID_B_PRE, PID_B_POST, PID_B_SPAN = 101, 102, 103, 104
PID_O, PID_L = 201, 202
ITERS_A, ITERS_B = 400, 250
DC73_NOTE = "D-C7-3 applies: post-copy-up userspace edge is backend-divergent per docs/known-limitations.md"


def inventory(edges, gaps=(), observer="initial"):
    """One inventory v1 document over callers A/B-pre/B-post/B-span (D1) or O/L (N4).

    `edges` maps pid -> bool (edge to the provider present). Callers always
    carries every pid the legs need; gaps are (subject, reason, pid|None).
    """
    pids = [PID_A, PID_B_PRE, PID_B_POST, PID_B_SPAN, PID_O, PID_L]
    callers = [{"id": f"c{i}", "pid": pid} for i, pid in enumerate(pids)]
    by_pid = {pid: f"c{i}" for i, pid in enumerate(pids)}
    return {
        "schema": "p11scope/inventory/v1",
        "callers": callers,
        "modules": [{"id": "m0", "paths": [PROVIDER]}],
        "edges": [{"caller": by_pid[pid], "module": "m0"}
                  for pid, present in sorted(edges.items()) if present],
        "gaps": [{"subject": subject, "reason": reason, "caller": None,
                  "module": None, "pid": pid} for subject, reason, pid in gaps],
        "pid_namespace": {"observer": observer, "kernel_pids": "initial",
                          "proc_pids": "observer"},
    }


def profile(iters, event_loss=0, observer="initial", causes=()):
    causes = sorted(causes)
    return {
        "capture": {"scope": "cgroup", "modules": [{"path": PROVIDER}]},
        "evidence": {
            "attached_probes": 136,
            "event_loss": event_loss,
            "in_flight_at_end": 0,
            "verdict_detail": "concrete_gap" if causes else "attribution_only",
            "pid_namespace": {"observer": observer, "kernel_pids": "initial",
                              "proc_pids": "observer"},
            "gap_classes": {"observation": {"causes": causes,
                                            "status": "lossy" if causes else "exact"}},
        },
        "functions": [{"calls": iters, "errors": 0, "names": [name]} for name in NAMES]
        + [{"calls": 0, "errors": 0, "names": ["C_Login"]}],
    }


def good_copy_up_inputs(lane="B"):
    """Healthy D1 legs: pre parity, the spanning R4 lane row, fresh exactness."""
    pre_kernel = inventory({PID_A: True, PID_B_PRE: True})
    pre_userspace = inventory({PID_A: True, PID_B_PRE: True})
    gap = ("LATE", "identity_mismatch: mapping (0:42, 5) != opened (0:42, 6)", PID_B_SPAN)
    if lane == "B":
        span_kernel = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: False}, [gap])
        span_userspace = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: True})
        note = DC73_NOTE
    else:
        span_kernel = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: False}, [gap])
        span_userspace = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: False}, [gap])
        note = "D-C7-3 does not apply on lane A (parity none, disclosed)"
    return {
        "pre_kernel": pre_kernel,
        "pre_userspace": pre_userspace,
        "span_kernel": span_kernel,
        "span_userspace": span_userspace,
        "fresh_kernel": inventory({PID_A: True, PID_B_POST: True}),
        "fresh_userspace": inventory({PID_A: True, PID_B_POST: True}),
        "pre_profile_a": profile(ITERS_A),
        "pre_profile_b": profile(ITERS_B),
        "post_profile_b": profile(ITERS_B),
        "pid_a": PID_A,
        "pid_b_pre": PID_B_PRE,
        "pid_b_span": PID_B_SPAN,
        "pid_b_post": PID_B_POST,
        "iters_a": ITERS_A,
        "iters_b": ITERS_B,
        "lane": lane,
        "dc73_note": note,
    }


def check_copy_up(**overrides):
    inputs = good_copy_up_inputs(overrides.pop("lane", "B"))
    inputs.update(overrides)
    return ORACLE["copy_up"](**inputs)


def good_late_inputs(edge=True):
    gaps = [(LATE_PROVIDER, "module first observed after admission", PID_L)]
    return {
        "document": inventory({PID_O: True, PID_L: edge}, gaps),
        "pid_o": PID_O,
        "pid_l": PID_L,
        "late_module": LATE_PROVIDER,
    }


def check_late(**overrides):
    inputs = good_late_inputs()
    inputs.update(overrides)
    return ORACLE["late_reported"](**inputs)


def run_oracle(*args):
    return subprocess.run([sys.executable, "-I", str(ORACLE_PATH), *args],
                          capture_output=True, text=True)


def write_json(directory, name, document):
    path = Path(directory) / name
    path.write_text(json.dumps(document))
    return str(path)


class CopyUpTest(unittest.TestCase):
    def test_lane_b_healthy_passes(self):
        result = check_copy_up()
        self.assertTrue(result["ok"])
        self.assertEqual(result["lane"], "B")

    def test_lane_a_healthy_passes(self):
        result = check_copy_up(lane="A")
        self.assertTrue(result["ok"])
        self.assertEqual(result["lane"], "A")

    def test_pre_kernel_missing_b_edge_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=inventory({PID_A: True, PID_B_PRE: False}))

    def test_pre_userspace_missing_a_edge_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(pre_userspace=inventory({PID_A: False, PID_B_PRE: True}))

    def test_pre_kernel_with_identity_gap_fails(self):
        pre = inventory({PID_A: True, PID_B_PRE: True},
                        [("x", "identity_mismatch: stale", PID_B_PRE)])
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_profile_b_wrong_count_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(pre_profile_b=profile(ITERS_B + 1))

    def test_pre_profile_a_event_loss_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(pre_profile_a=profile(ITERS_A, event_loss=3))

    def test_pre_nested_observer_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(pre_profile_a=profile(ITERS_A, observer="nested",
                                                causes=("pid_namespace",)))

    def test_pre_inventory_pid_namespace_gap_fails(self):
        pre = inventory({PID_A: True, PID_B_PRE: True},
                        [("pid namespace", "observer is nested", None)],
                        observer="nested")
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_span_kernel_exact_across_copy_up_fails(self):
        """The control: a naive exact-oracle over the spanning data must FAIL."""
        span = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: True})
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_kernel_missing_edge_without_gap_fails(self):
        span = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: False})
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_kernel_upper_mapper_unscanned_fails(self):
        span = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: False},
                         [("x", "identity_mismatch: stale", PID_B_SPAN)])
        span["callers"] = [c for c in span["callers"] if c["pid"] != PID_B_SPAN]
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_lower_mapper_without_edge_fails(self):
        span = inventory({PID_A: True, PID_B_PRE: False, PID_B_SPAN: True})
        with self.assertRaises(AssertionError):
            check_copy_up(span_userspace=span)

    def test_span_lower_mapper_with_identity_loss_fails(self):
        span = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: True},
                         [("x", "identity_mismatch: stale", PID_B_PRE)])
        with self.assertRaises(AssertionError):
            check_copy_up(span_userspace=span)

    def test_span_userspace_lane_b_missing_upper_edge_fails(self):
        span = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: False},
                         [("x", "identity_mismatch: stale", PID_B_SPAN)])
        with self.assertRaises(AssertionError):
            check_copy_up(span_userspace=span)

    def test_span_userspace_lane_b_without_dc73_note_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(dc73_note="no disclosure recorded")

    def test_lane_a_span_userspace_with_upper_edge_fails(self):
        span = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: True})
        with self.assertRaises(AssertionError):
            check_copy_up(lane="A", span_userspace=span)

    def test_lane_a_with_dc73_note_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(lane="A", dc73_note=DC73_NOTE)

    def test_vacuous_identical_pre_span_fails(self):
        inputs = good_copy_up_inputs()
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=copy.deepcopy(inputs["pre_kernel"]))

    def test_fresh_after_restart_is_the_old_post_shape_and_passes(self):
        """The first D1 runs' post captures (fresh anchors) edge on both backends."""
        result = check_copy_up()
        self.assertIn(PID_B_POST, result["fresh"]["kernel_edges"])
        self.assertIn(PID_B_POST, result["fresh"]["userspace_edges"])

    def test_fresh_lane_b_restarted_b_without_edge_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(fresh_kernel=inventory({PID_A: True, PID_B_POST: False}))

    def test_fresh_lane_b_identity_loss_fails(self):
        fresh = inventory({PID_A: True, PID_B_POST: True},
                          [("x", "identity_mismatch: stale", PID_B_POST)])
        with self.assertRaises(AssertionError):
            check_copy_up(fresh_userspace=fresh)

    def test_fresh_restarted_b_unscanned_fails(self):
        fresh = inventory({PID_A: True})
        fresh["callers"] = [c for c in fresh["callers"] if c["pid"] != PID_B_POST]
        with self.assertRaises(AssertionError):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_lane_a_silent_restarted_b_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(lane="A", fresh_userspace=inventory({PID_A: True, PID_B_POST: False}))

    def test_fresh_lane_a_named_loss_passes(self):
        fresh = inventory({PID_A: True, PID_B_POST: False},
                          [("x", "identity_mismatch: stale", PID_B_POST)])
        self.assertTrue(check_copy_up(lane="A", fresh_userspace=fresh)["ok"])

    def test_post_profile_b_wrong_count_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(post_profile_b=profile(ITERS_B - 1))

    def test_post_profile_b_event_loss_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(post_profile_b=profile(ITERS_B, event_loss=1))

    def test_post_profile_b_descendant_gaps_fail(self):
        with self.assertRaises(AssertionError):
            check_copy_up(post_profile_b=profile(ITERS_B, causes=("pid_descendant_gaps",)))

    def test_span_kernel_missing_a_edge_fails(self):
        span = inventory({PID_A: False, PID_B_PRE: True, PID_B_SPAN: False},
                         [("x", "identity_mismatch: stale", PID_B_SPAN)])
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_unknown_lane_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(lane="C")


class LateReportedTest(unittest.TestCase):
    def test_edge_with_gap_passes(self):
        result = check_late()
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "edge-with-gap")

    def test_no_edge_with_named_gap_passes(self):
        inputs = good_late_inputs(edge=False)
        result = ORACLE["late_reported"](**inputs)
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "no-edge-with-gap")

    def test_o_missing_edge_fails(self):
        with self.assertRaises(AssertionError):
            check_late(document=inventory({PID_O: False, PID_L: True},
                                          [(LATE_PROVIDER, "r", PID_L)]))

    def test_o_with_gap_fails(self):
        gaps = [(LATE_PROVIDER, "r", PID_L), ("x", "y", PID_O)]
        with self.assertRaises(AssertionError):
            check_late(document=inventory({PID_O: True, PID_L: True}, gaps))

    def test_l_absent_without_gap_fails_silently_zero(self):
        document = inventory({PID_O: True, PID_L: False})
        document["callers"] = [c for c in document["callers"] if c["pid"] != PID_L]
        with self.assertRaises(AssertionError):
            check_late(document=document)

    def test_l_absent_with_gap_still_fails_unscanned(self):
        document = inventory({PID_O: True, PID_L: False},
                             [(LATE_PROVIDER, "r", PID_L)])
        document["callers"] = [c for c in document["callers"] if c["pid"] != PID_L]
        with self.assertRaises(AssertionError):
            check_late(document=document)

    def test_l_no_edge_no_gap_fails_silently_zero(self):
        with self.assertRaises(AssertionError):
            check_late(document=inventory({PID_O: True, PID_L: False}))

    def test_l_edge_without_gap_fails(self):
        with self.assertRaises(AssertionError):
            check_late(document=inventory({PID_O: True, PID_L: True}))

    def test_l_gap_with_unknown_subject_fails(self):
        with self.assertRaises(AssertionError):
            check_late(document=inventory(
                {PID_O: True, PID_L: False}, [("frobnicate", "r", PID_L)]))

    def test_stripped_gap_control_fails(self):
        """The control: the healthy document with L gaps stripped must FAIL."""
        document = good_late_inputs()["document"]
        document["gaps"] = [g for g in document["gaps"] if g["pid"] != PID_L]
        self.assertEqual(document["gaps"], [])
        with self.assertRaises(AssertionError):
            check_late(document=document)

    def test_nested_observer_fails(self):
        with self.assertRaises(AssertionError):
            check_late(document=inventory({PID_O: True, PID_L: True},
                                          [(LATE_PROVIDER, "r", PID_L)],
                                          observer="nested"))

    def test_pid_namespace_gap_fails(self):
        gaps = [(LATE_PROVIDER, "r", PID_L), ("pid namespace", "nested", None)]
        with self.assertRaises(AssertionError):
            check_late(document=inventory({PID_O: True, PID_L: True}, gaps))

    def test_o_unscanned_fails(self):
        document = inventory({PID_O: True, PID_L: True},
                             [(LATE_PROVIDER, "r", PID_L)])
        document["callers"] = [c for c in document["callers"] if c["pid"] != PID_O]
        with self.assertRaises(AssertionError):
            check_late(document=document)

    def test_frozen_gap_list_is_cited(self):
        allowed = ORACLE["ALLOWED_LATE_SUBJECTS"]
        self.assertGreaterEqual(len(allowed), 8)
        for subject, citation in allowed.items():
            self.assertRegex(citation, r"^src/.+:\d+",
                             f"uncited gap subject: {subject}")


class OracleCliTest(unittest.TestCase):
    def test_copy_up_cli_passes_lane_b(self):
        inputs = good_copy_up_inputs()
        with tempfile.TemporaryDirectory() as work:
            note = Path(work) / "dc73.txt"
            note.write_text(inputs.pop("dc73_note"))
            args = ["copy-up", "--lane", inputs.pop("lane"),
                    "--pid-a", str(inputs.pop("pid_a")),
                    "--pid-b-pre", str(inputs.pop("pid_b_pre")),
                    "--pid-b-span", str(inputs.pop("pid_b_span")),
                    "--pid-b-post", str(inputs.pop("pid_b_post")),
                    "--iters-a", str(inputs.pop("iters_a")),
                    "--iters-b", str(inputs.pop("iters_b")),
                    "--dc73-note", str(note)]
            for key, document in inputs.items():
                args += [f"--{key.replace('_', '-')}",
                         write_json(work, f"{key}.json", document)]
            completed = run_oracle(*args)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)["ok"])

    def test_copy_up_cli_refuses_mutation(self):
        inputs = good_copy_up_inputs()
        inputs["span_kernel"] = inventory({PID_A: True, PID_B_PRE: True, PID_B_SPAN: True})
        with tempfile.TemporaryDirectory() as work:
            note = Path(work) / "dc73.txt"
            note.write_text(inputs.pop("dc73_note"))
            args = ["copy-up", "--lane", inputs.pop("lane"),
                    "--pid-a", str(inputs.pop("pid_a")),
                    "--pid-b-pre", str(inputs.pop("pid_b_pre")),
                    "--pid-b-span", str(inputs.pop("pid_b_span")),
                    "--pid-b-post", str(inputs.pop("pid_b_post")),
                    "--iters-a", str(inputs.pop("iters_a")),
                    "--iters-b", str(inputs.pop("iters_b")),
                    "--dc73-note", str(note)]
            for key, document in inputs.items():
                args += [f"--{key.replace('_', '-')}",
                         write_json(work, f"{key}.json", document)]
            completed = run_oracle(*args)
            self.assertNotEqual(completed.returncode, 0)

    def test_late_reported_cli_passes(self):
        inputs = good_late_inputs()
        with tempfile.TemporaryDirectory() as work:
            path = write_json(work, "n4.json", inputs["document"])
            completed = run_oracle("late-reported", path,
                                   "--pid-o", str(inputs["pid_o"]),
                                   "--pid-l", str(inputs["pid_l"]),
                                   "--late-module", inputs["late_module"])
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)["ok"])

    def test_late_reported_cli_refuses_silent_zero(self):
        document = inventory({PID_O: True, PID_L: False})
        with tempfile.TemporaryDirectory() as work:
            path = write_json(work, "n4.json", document)
            completed = run_oracle("late-reported", path, "--pid-o", str(PID_O),
                                   "--pid-l", str(PID_L),
                                   "--late-module", LATE_PROVIDER)
            self.assertNotEqual(completed.returncode, 0)

    def test_self_test_passes(self):
        completed = run_oracle("--self-test")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_unknown_subcommand_fails(self):
        completed = run_oracle("frobnicate")
        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
