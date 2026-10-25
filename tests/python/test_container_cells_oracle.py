# SPDX-License-Identifier: GPL-3.0-or-later
"""Container-cells oracle (D1 copy-up, N4 late-reported): healthy twins pass, every check refuses its mutation.

D1 follows the live run-4 shape (Opus D1 identity investigation, binding):
pre-collapse onto A's module, span with B-pre m7-ended/m8-mapped plus B2->m8
on BOTH backends, fresh exactness. N4 follows the live run-1 ruling: L passes
via a named gap or a stated unwatched prefix (since_ns > first_seen_ns).
"""

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
FIXTURES = ROOT / "tests/python/fixtures/container-cells"

NAMES = ("C_GenerateRandom", "C_DigestInit", "C_Digest",
         "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal")
PROVIDER = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
LATE_PROVIDER = "/tmp/private/libsofthsm2.so"
PID_A, PID_B_PRE, PID_B_POST, PID_B_SPAN = 101, 102, 103, 104
PID_B3 = 105
PID_O, PID_L = 201, 202
ITERS_A, ITERS_B = 400, 250
ITERS_O, ITERS_L = 400, 250
# Overlay-shaped synthetic keys: same inode, different minor (like run 4).
KEY_A = (0, 138, 100)
KEY_B = (0, 140, 100)
NOTE_NEW = ("copy-up-stale-caller: after B's same-bytes copy-up, B's pre-copy-up "
            "process is attributed to the upper copy on both identity backends "
            "(known issue, disclosed).")
NOTE_OLD = ("D-C7-3 applies: post-copy-up userspace edge to the upper mapping is "
            "backend-divergent per docs/known-limitations.md; the kernel refusal "
            "with identity_mismatch is the correct leg.")


def key_of_module(module_id):
    return {"m7": KEY_A, "m8": KEY_B}.get(module_id, (0, 35, 7))


def edge(pid, module, evidence="deep_scan", state="mapped", count=0,
         cov="unknown", since=None, first_seen=1000, lossy=None,
         reason="not_attached"):
    return {"pid": pid, "module": module, "evidence": evidence, "state": state,
            "count": count, "cov": cov, "since": since,
            "first_seen": first_seen, "lossy": lossy, "reason": reason}


def collapse_gap(mapping_key=KEY_B, target_key=KEY_A, path=PROVIDER):
    (jmaj, jmnr, jino), (tmaj, tmnr, tino) = mapping_key, target_key
    subject = (f"{path} (ObjectKey {{ device: Device {{ major: {jmaj}, "
               f"minor: {jmnr} }}, inode: {jino} }})")
    reason = (f"mapping ObjectKey {{ device: Device {{ major: {jmaj}, minor: {jmnr} }}, "
              f"inode: {jino} }} was collapsed onto ObjectKey {{ device: Device {{ "
              f"major: {tmaj}, minor: {tmnr} }}, inode: {tino} }} by the overlayfs + "
              f"inode metadata + SHA-256 heuristic, which cannot prove physical "
              f"identity across overlay instances; calls through a distinct "
              f"byte-identical instance would not be probed")
    return (subject, reason, None)


def inventory(edges, gaps=(), observer="initial", backend="kernel",
              fallback="anchor_not_installed", modules=None, paths=None):
    """One inventory v1 document over callers A/B-pre/B-post/B-span (D1) or O/L (N4).

    `edges` is a list of edge(...) dicts; `modules` maps module id ->
    (major, minor, inode); `paths` maps module id -> [paths]. Callers always
    carries every pid the legs need; gaps are (subject, reason, pid|None).
    """
    pids = [PID_A, PID_B_PRE, PID_B_POST, PID_B_SPAN, PID_B3, PID_O, PID_L]
    callers = [{"id": f"c{i}", "pid": pid} for i, pid in enumerate(pids)]
    by_pid = {pid: f"c{i}" for i, pid in enumerate(pids)}
    modules = modules if modules is not None else {"m0": (0, 35, 7)}
    paths = paths if paths is not None else {mid: [PROVIDER] for mid in modules}
    return {
        "schema": "p11scope/inventory/v1",
        "observation": {"identity": {"backend": backend, "fallback": fallback}},
        "callers": callers,
        "modules": [{"id": mid,
                     "paths": paths[mid],
                     "identity": {"device": {"major": key[0], "minor": key[1]},
                                  "inode": key[2]}}
                    for mid, key in sorted(modules.items())],
        "edges": [{"caller": by_pid[item["pid"]], "module": item["module"],
                   "mapping": {"evidence": item["evidence"], "state": item["state"],
                               "first_seen_ns": item["first_seen"]},
                   "entries": {"count": item["count"],
                               "coverage": {"state": item["cov"],
                                            "since_ns": item["since"],
                                            "lossy": item["lossy"]}}}
                 for item in edges],
        "gaps": [{"subject": subject, "reason": reason, "caller": None,
                  "module": None, "pid": pid} for subject, reason, pid in gaps],
        "pid_namespace": {"observer": observer, "kernel_pids": "initial",
                          "proc_pids": "observer"},
    }


def facts_text(a_dev=138, a_ino=100, b_dev=140, b_ino=100,
               upper_dev=51, upper_ino=200,
               sha="8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d",
               upper_sha=None):
    upper_sha = sha if upper_sha is None else upper_sha
    return ("\n".join([
        f"stat-a-pre={a_dev}:{a_ino} 941088 sha-a-pre={sha}",
        f"stat-b-pre={b_dev}:{b_ino} 941088 sha-b-pre={sha}",
        f"upper-stat-b={upper_dev}:{upper_ino} 941088 upper-sha-b={upper_sha}",
    ]) + "\n")


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


D1_MODULES_PRE = {"m7": KEY_A}
D1_MODULES_SPAN = {"m7": KEY_A, "m8": KEY_B}


def pre_edges():
    return [edge(PID_A, "m7"), edge(PID_B_PRE, "m7")]


def span_edges(b_pre_m8_cov="watched_no_use", b_pre_m8_since=3000,
               b_pre_m8_count=0, b3_m8_cov="watched_no_use", b3_m8_count=0):
    return [edge(PID_A, "m7"),
            edge(PID_B_PRE, "m7", state="ended"),
            edge(PID_B_PRE, "m8", cov=b_pre_m8_cov, since=b_pre_m8_since,
                 count=b_pre_m8_count, first_seen=2000),
            edge(PID_B_SPAN, "m8", evidence="maps_match", cov="watched_no_use",
                 since=3000, first_seen=2000),
            edge(PID_B3, "m7", state="ended"),
            edge(PID_B3, "m8", cov=b3_m8_cov, since=3000,
                 count=b3_m8_count, first_seen=2000)]


def good_copy_up_inputs(lane="B"):
    """Healthy D1 legs: pre collapse, the run-4 span shape, fresh exactness."""
    gap = collapse_gap()
    pre_kernel = inventory(pre_edges(), [gap], backend="kernel",
                           fallback="anchor_not_installed",
                           modules=dict(D1_MODULES_PRE))
    pre_userspace = inventory(pre_edges(), [gap], backend="userspace",
                              fallback=None, modules=dict(D1_MODULES_PRE))
    span_kernel = inventory(span_edges(), [gap], backend="kernel",
                            fallback="anchor_not_installed",
                            modules=dict(D1_MODULES_SPAN))
    span_userspace = inventory(span_edges(), [gap], backend="userspace",
                               fallback=None, modules=dict(D1_MODULES_SPAN))
    return {
        "pre_kernel": pre_kernel,
        "pre_userspace": pre_userspace,
        "span_kernel": span_kernel,
        "span_userspace": span_userspace,
        "fresh_kernel": inventory(
            [edge(PID_A, "m7"), edge(PID_B_POST, "m8")], backend="kernel",
            fallback="anchor_not_installed", modules=dict(D1_MODULES_SPAN)),
        "fresh_userspace": inventory(
            [edge(PID_A, "m7"), edge(PID_B_POST, "m8")], backend="userspace",
            fallback=None, modules=dict(D1_MODULES_SPAN)),
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
        "dc73_note": NOTE_NEW,
        "facts_text": facts_text(),
    }


def check_copy_up(**overrides):
    inputs = good_copy_up_inputs(overrides.pop("lane", "B"))
    inputs.update(overrides)
    return ORACLE["copy_up"](**inputs)


def good_late_inputs(cov="watched_no_use", count=0, since=2000,
                     first_seen=1000, gaps=(), iters_l=ITERS_L):
    modules = {"m7": (0, 412, 900), "m8": (0, 138, 901)}
    paths = {"m7": [PROVIDER], "m8": [LATE_PROVIDER]}
    return {
        "document": inventory(
            [edge(PID_O, "m7", count=6 * ITERS_O, cov="counted",
                  since=1500, first_seen=1000, lossy=False),
             edge(PID_L, "m8", count=count, cov=cov, since=since,
                  first_seen=first_seen)],
            gaps, backend="kernel", fallback="below_threshold",
            modules=modules, paths=paths),
        "pid_o": PID_O,
        "pid_l": PID_L,
        "late_module": LATE_PROVIDER,
        "iters_l": iters_l,
    }


def check_late(**overrides):
    inputs = good_late_inputs()
    inputs.update(overrides)
    if "document" not in overrides and any(
            key in overrides for key in ("cov", "count", "since", "first_seen",
                                         "gaps", "iters_l")):
        keys = {key: overrides.pop(key) for key in
                ("cov", "count", "since", "first_seen", "gaps", "iters_l")
                if key in overrides}
        inputs = good_late_inputs(**keys)
        inputs.update(overrides)
    return ORACLE["late_reported"](**inputs)


def run_oracle(*args):
    return subprocess.run([sys.executable, "-I", str(ORACLE_PATH), *args],
                          capture_output=True, text=True)


def write_json(directory, name, document):
    path = Path(directory) / name
    path.write_text(json.dumps(document))
    return str(path)


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


class CopyUpTest(unittest.TestCase):
    def test_lane_b_healthy_passes(self):
        result = check_copy_up()
        self.assertTrue(result["ok"])
        self.assertEqual(result["lane"], "B")
        self.assertEqual(result["known_issue"],
                         {"pid": PID_B_PRE, "old_module": "m7", "new_module": "m8"})
        self.assertEqual(result["b_pre_round2"], {"measured": False})
        self.assertIn("checked no container edge",
                      result["kernel_proof"]["finding"])

    def test_lane_a_healthy_passes(self):
        result = check_copy_up(lane="A")
        self.assertTrue(result["ok"])
        self.assertEqual(result["lane"], "A")

    def test_pre_must_edge_one_shared_module(self):
        pre = inventory([edge(PID_A, "m7"), edge(PID_B_PRE, "m8")],
                        [collapse_gap()], backend="kernel",
                        modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_b_edge_must_be_deep_scan(self):
        pre = inventory([edge(PID_A, "m7"),
                         edge(PID_B_PRE, "m7", evidence="maps_match")],
                        [collapse_gap()], backend="kernel",
                        modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_ended_edge_is_not_an_edge(self):
        pre = inventory([edge(PID_A, "m7"),
                         edge(PID_B_PRE, "m7", state="ended")],
                        [collapse_gap()], backend="kernel",
                        modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_collapse_gap_missing_fails(self):
        pre = inventory(pre_edges(), backend="kernel",
                        modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_collapse_gap_duplicated_fails(self):
        pre = inventory(pre_edges(), [collapse_gap(), collapse_gap()],
                        backend="kernel", modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_collapse_gap_wrong_keys_fails(self):
        pre = inventory(pre_edges(),
                        [collapse_gap(mapping_key=(0, 141, 100))],
                        backend="kernel", modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_kernel_with_identity_gap_fails(self):
        pre = inventory(pre_edges(),
                        [collapse_gap(), ("x", "identity_mismatch: stale", PID_B_PRE)],
                        backend="kernel", modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_kernel_identity_must_report_kernel_with_fallback(self):
        pre = inventory(pre_edges(), [collapse_gap()], backend="userspace",
                        fallback=None, modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)
        pre = inventory(pre_edges(), [collapse_gap()], backend="kernel",
                        fallback=None, modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_profile_b_wrong_count_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(pre_profile_b=profile(ITERS_B + 1))

    def test_pre_profile_a_event_loss_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(pre_profile_a=profile(ITERS_A, event_loss=3))

    def test_pre_inventory_pid_namespace_gap_fails(self):
        pre = inventory(pre_edges(), [collapse_gap(), ("pid namespace", "nested", None)],
                        observer="nested", backend="kernel",
                        modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_span_without_new_module_fails(self):
        span = inventory([edge(PID_A, "m7"), edge(PID_B_PRE, "m7"),
                          edge(PID_B_SPAN, "m7", evidence="maps_match")],
                         [collapse_gap()], backend="kernel",
                         modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_new_module_key_already_in_pre_fails(self):
        pre = inventory(pre_edges(), [collapse_gap()], backend="kernel",
                        modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_span_collapse_gap_duplicated_fails(self):
        span = inventory(span_edges(), [collapse_gap(), collapse_gap()],
                         backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_collapse_gap_missing_fails(self):
        span = inventory(span_edges(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b2_without_edge_fails(self):
        span = inventory([item for item in span_edges()
                          if item["pid"] != PID_B_SPAN],
                         [collapse_gap()], backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b2_edge_ended_fails(self):
        edges = [item if item["pid"] != PID_B_SPAN
                 else edge(PID_B_SPAN, "m8", evidence="maps_match", state="ended")
                 for item in span_edges()]
        span = inventory(edges, [collapse_gap()], backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b2_with_identity_loss_fails(self):
        span = inventory(span_edges(),
                         [collapse_gap(), ("x", "identity_mismatch: stale", PID_B_SPAN)],
                         backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_backends_must_agree_on_new_module(self):
        span = inventory(span_edges(), [collapse_gap()], backend="userspace",
                         fallback=None,
                         modules={"m7": KEY_A, "m8": (0, 141, 100)})
        with self.assertRaises(AssertionError):
            check_copy_up(span_userspace=span)

    def test_span_b_pre_shape_change_fails(self):
        """m7 ended + m8 mapped is the pinned known-issue shape: any change FAILs."""
        variants = {
            "m7 still mapped": [edge(PID_A, "m7"), edge(PID_B_PRE, "m7"),
                                edge(PID_B_PRE, "m8", cov="watched_no_use",
                                     since=3000, first_seen=2000),
                                edge(PID_B_SPAN, "m8", evidence="maps_match")],
            "m8 ended": [edge(PID_A, "m7"), edge(PID_B_PRE, "m7", state="ended"),
                         edge(PID_B_PRE, "m8", state="ended"),
                         edge(PID_B_SPAN, "m8", evidence="maps_match")],
            "m8 missing": [edge(PID_A, "m7"), edge(PID_B_PRE, "m7", state="ended"),
                           edge(PID_B_SPAN, "m8", evidence="maps_match")],
            "m7 missing": [edge(PID_A, "m7"),
                           edge(PID_B_PRE, "m8", cov="watched_no_use",
                                since=3000, first_seen=2000),
                           edge(PID_B_SPAN, "m8", evidence="maps_match")],
        }
        for label, edges in variants.items():
            with self.subTest(label):
                span = inventory(edges, [collapse_gap()], backend="kernel",
                                 modules=dict(D1_MODULES_SPAN))
                with self.assertRaises(AssertionError):
                    check_copy_up(span_kernel=span)

    def test_facts_same_inode_fails(self):
        facts = facts_text(upper_dev=140, upper_ino=100)
        with self.assertRaises(AssertionError):
            check_copy_up(facts_text=facts)

    def test_facts_sha_drift_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(facts_text=facts_text(upper_sha="0" * 64))

    def test_facts_missing_key_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(facts_text="stat-a-pre=138:100 1 sha-a-pre=x\n")

    def test_old_dc73_note_fails(self):
        """The disproven kernel-refusal disclosure must FAIL."""
        with self.assertRaises(AssertionError):
            check_copy_up(dc73_note=NOTE_OLD)

    def test_empty_dc73_note_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(dc73_note="")

    def test_round2_m8_must_not_claim_b_pre_calls(self):
        result = check_copy_up(b_pre_round2_calls=1500)
        self.assertEqual(result["b_pre_round2"]["calls"], 1500)
        self.assertEqual(result["b_pre_round2"]["pid"], PID_B_PRE)
        self.assertEqual(result["b_pre_round2"]["span_kernel"]["m8_entries"], 0)
        bad = inventory(
            span_edges(b_pre_m8_cov="counted", b_pre_m8_since=3000,
                       b_pre_m8_count=9),
            [collapse_gap()], backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=bad, b_pre_round2_calls=1500)

    def test_round2_pid_defaults_to_b_pre(self):
        result = check_copy_up(b_pre_round2_calls=1500)
        self.assertEqual(result["b_pre_round2"]["pid"], PID_B_PRE)

    def test_round2_explicit_pid_passes(self):
        """The round-2 twin (a second lower-mapper) is measured by pid."""
        result = check_copy_up(b_pre_round2_calls=1500,
                               b_pre_round2_pid=PID_B3)
        self.assertTrue(result["ok"])
        record = result["b_pre_round2"]
        self.assertEqual(record["pid"], PID_B3)
        self.assertEqual(record["calls"], 1500)
        self.assertEqual(record["span_kernel"]["m8_entries"], 0)
        self.assertEqual(record["span_userspace"]["m8_entries"], 0)
        self.assertEqual(record["span_kernel"]["m8_status"], "watched_no_use")

    def test_round2_pid_claim_fails(self):
        bad = inventory(
            span_edges(b3_m8_cov="counted", b3_m8_count=9),
            [collapse_gap()], backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=bad, b_pre_round2_calls=1500,
                          b_pre_round2_pid=PID_B3)

    def test_round2_pid_without_new_edge_fails(self):
        edges = [item for item in span_edges() if item["pid"] != PID_B3]
        span = inventory(edges, [collapse_gap()], backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span, b_pre_round2_calls=1500,
                          b_pre_round2_pid=PID_B3)

    def test_round2_pid_without_calls_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(b_pre_round2_pid=PID_B3)

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
        span = inventory([item for item in span_edges() if item["pid"] != PID_A],
                         [collapse_gap()], backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_fresh_lane_b_restarted_b_without_edge_fails(self):
        fresh = inventory([edge(PID_A, "m7")], backend="kernel",
                          modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_lane_b_identity_loss_fails(self):
        fresh = inventory([edge(PID_A, "m7"), edge(PID_B_POST, "m8")],
                          [("x", "identity_mismatch: stale", PID_B_POST)],
                          backend="userspace", fallback=None,
                          modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(fresh_userspace=fresh)

    def test_fresh_restarted_b_unscanned_fails(self):
        fresh = inventory([edge(PID_A, "m7")], backend="kernel",
                          modules=dict(D1_MODULES_SPAN))
        fresh["callers"] = [c for c in fresh["callers"] if c["pid"] != PID_B_POST]
        with self.assertRaises(AssertionError):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_lane_a_silent_restarted_b_fails(self):
        fresh = inventory([edge(PID_A, "m7")], backend="userspace",
                          fallback=None, modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(lane="A", fresh_userspace=fresh)

    def test_fresh_lane_a_named_loss_passes(self):
        fresh = inventory([edge(PID_A, "m7")],
                          [("x", "identity_mismatch: stale", PID_B_POST)],
                          backend="userspace", fallback=None,
                          modules=dict(D1_MODULES_SPAN))
        self.assertTrue(check_copy_up(lane="A", fresh_userspace=fresh)["ok"])

    def test_fresh_after_restart_edges_both_backends(self):
        result = check_copy_up()
        self.assertIn(PID_B_POST, result["fresh"]["kernel_edges"])
        self.assertIn(PID_B_POST, result["fresh"]["userspace_edges"])

    def test_unknown_lane_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(lane="C")

    def test_inventory_maps_counts_live_edges_only(self):
        pid_of, edges = ORACLE["inventory_maps"](inventory(
            [edge(PID_A, "m7"), edge(PID_B_PRE, "m7", state="ended")],
            modules=dict(D1_MODULES_PRE)))
        self.assertIn(PID_A, edges)
        self.assertNotIn(PID_B_PRE, edges)
        self.assertIn(PID_B_PRE, pid_of.values())


class LateReportedTest(unittest.TestCase):
    def test_unwatched_prefix_passes(self):
        result = check_late()
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "unwatched-prefix")
        self.assertEqual(result["boundary"]["unwatched_ns"], 1000)
        self.assertEqual(result["boundary"]["entries"], 0)

    def test_counted_entries_with_prefix_pass(self):
        result = check_late(cov="counted", count=9, since=2000,
                            first_seen=1000)
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "unwatched-prefix")

    def test_edge_with_gap_passes(self):
        gaps = [(LATE_PROVIDER, "module first observed after admission", PID_L)]
        result = check_late(gaps=gaps, since=1000)
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "edge-with-gap")

    def test_no_edge_with_named_gap_passes(self):
        modules = {"m7": (0, 412, 900), "m8": (0, 138, 901)}
        paths = {"m7": [PROVIDER], "m8": [LATE_PROVIDER]}
        document = inventory(
            [edge(PID_O, "m7", count=6 * ITERS_O, cov="counted",
                  since=1500, first_seen=1000, lossy=False)],
            [(LATE_PROVIDER, "module first observed after admission", PID_L)],
            backend="kernel", fallback="below_threshold",
            modules=modules, paths=paths)
        result = ORACLE["late_reported"](
            document=document, pid_o=PID_O, pid_l=PID_L,
            late_module=LATE_PROVIDER, iters_l=ITERS_L)
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "no-edge-with-gap")

    def test_o_missing_edge_fails(self):
        modules = {"m7": (0, 412, 900), "m8": (0, 138, 901)}
        paths = {"m7": [PROVIDER], "m8": [LATE_PROVIDER]}
        document = inventory(
            [edge(PID_L, "m8", cov="watched_no_use", since=2000,
                  first_seen=1000)],
            backend="kernel", fallback="below_threshold",
            modules=modules, paths=paths)
        with self.assertRaises(AssertionError):
            check_late(document=document)

    def test_o_with_gap_fails(self):
        with self.assertRaises(AssertionError):
            check_late(gaps=[("x", "y", PID_O)])

    def test_l_absent_without_gap_fails_silently_zero(self):
        inputs = good_late_inputs()
        inputs["document"]["callers"] = [
            c for c in inputs["document"]["callers"] if c["pid"] != PID_L]
        with self.assertRaises(AssertionError):
            ORACLE["late_reported"](**inputs)

    def test_l_no_edge_no_gap_fails_silently_zero(self):
        modules = {"m7": (0, 412, 900), "m8": (0, 138, 901)}
        paths = {"m7": [PROVIDER], "m8": [LATE_PROVIDER]}
        document = inventory(
            [edge(PID_O, "m7", count=6 * ITERS_O, cov="counted",
                  since=1500, first_seen=1000, lossy=False)],
            backend="kernel", fallback="below_threshold",
            modules=modules, paths=paths)
        with self.assertRaises(AssertionError):
            check_late(document=document)

    def test_l_edge_without_gap_and_no_prefix_fails(self):
        with self.assertRaises(AssertionError):
            check_late(since=1000, first_seen=1000)

    def test_l_gap_with_unknown_subject_fails(self):
        with self.assertRaises(AssertionError):
            check_late(gaps=[("frobnicate", "r", PID_L)], since=1000)

    def test_stripped_gap_control_fails(self):
        """The control: the healthy gap-based document with L gaps stripped FAILs."""
        gaps = [(LATE_PROVIDER, "r", PID_L)]
        inputs = good_late_inputs(gaps=gaps, since=1000)
        inputs["document"]["gaps"] = []
        with self.assertRaises(AssertionError):
            ORACLE["late_reported"](**inputs)

    def test_since_rewritten_control_fails(self):
        """The plan's control: since_ns rewritten to <= first_seen_ns FAILs."""
        with self.assertRaises(AssertionError):
            check_late(since=500, first_seen=1000)

    def test_entries_above_ledger_fails(self):
        with self.assertRaises(AssertionError):
            check_late(cov="counted", count=6 * ITERS_L + 1)

    def test_counted_with_zero_entries_fails(self):
        with self.assertRaises(AssertionError):
            check_late(cov="counted", count=0)

    def test_watched_no_use_with_entries_fails(self):
        with self.assertRaises(AssertionError):
            check_late(cov="watched_no_use", count=3)

    def test_nested_observer_fails(self):
        inputs = good_late_inputs()
        inputs["document"]["pid_namespace"]["observer"] = "nested"
        with self.assertRaises(AssertionError):
            ORACLE["late_reported"](**inputs)

    def test_pid_namespace_gap_fails(self):
        with self.assertRaises(AssertionError):
            check_late(gaps=[("pid namespace", "nested", None)])

    def test_o_unscanned_fails(self):
        inputs = good_late_inputs()
        inputs["document"]["callers"] = [
            c for c in inputs["document"]["callers"] if c["pid"] != PID_O]
        with self.assertRaises(AssertionError):
            ORACLE["late_reported"](**inputs)

    def test_frozen_gap_list_is_cited(self):
        allowed = ORACLE["ALLOWED_LATE_SUBJECTS"]
        self.assertGreaterEqual(len(allowed), 8)
        for subject, citation in allowed.items():
            self.assertRegex(citation, r"^src/.+:\d+",
                             f"uncited gap subject: {subject}")


class FixtureTest(unittest.TestCase):
    """The real run-4 / run-1 JSONs, trimmed to what the oracle reads."""

    def test_d1_run4_fixtures_pass(self):
        facts = (FIXTURES / "d1-facts.txt").read_text()
        note = (FIXTURES / "d1-note.txt").read_text()
        result = ORACLE["copy_up"](
            load_fixture("d1-pre-kernel.json"),
            load_fixture("d1-pre-userspace.json"),
            load_fixture("d1-span-kernel.json"),
            load_fixture("d1-span-userspace.json"),
            load_fixture("d1-fresh-kernel.json"),
            load_fixture("d1-fresh-userspace.json"),
            load_fixture("d1-pre-a.json"),
            load_fixture("d1-pre-b.json"),
            load_fixture("d1-post-b.json"),
            1452406, 1452576, 1454781, 1456333, 400, 250, "B", note,
            facts)
        self.assertTrue(result["ok"])
        self.assertEqual(result["known_issue"]["pid"], 1452576)

    def test_d1_negative_fixtures_fail(self):
        facts = (FIXTURES / "d1-facts.txt").read_text()
        note = (FIXTURES / "d1-note.txt").read_text()
        base = dict(
            pre_kernel=load_fixture("d1-pre-kernel.json"),
            pre_userspace=load_fixture("d1-pre-userspace.json"),
            span_kernel=load_fixture("d1-span-kernel.json"),
            span_userspace=load_fixture("d1-span-userspace.json"),
            fresh_kernel=load_fixture("d1-fresh-kernel.json"),
            fresh_userspace=load_fixture("d1-fresh-userspace.json"),
            pre_profile_a=load_fixture("d1-pre-a.json"),
            pre_profile_b=load_fixture("d1-pre-b.json"),
            post_profile_b=load_fixture("d1-post-b.json"),
            pid_a=1452406, pid_b_pre=1452576, pid_b_span=1454781,
            pid_b_post=1456333, iters_a=400, iters_b=250, lane="B",
            dc73_note=note, facts_text=facts)
        negatives = {
            "duplicated collapse gap":
                {"span_kernel": load_fixture("d1-span-kernel-dup-collapse.json")},
            "B-pre shape changed":
                {"span_kernel": load_fixture("d1-span-kernel-bpre-mapped.json")},
            "collapse gap missing":
                {"pre_kernel": load_fixture("d1-pre-kernel-no-collapse.json")},
            "kernel proof missing":
                {"pre_kernel": load_fixture("d1-pre-kernel-userspace-identity.json")},
            "copy-up unproven (same inode)":
                {"facts_text": (FIXTURES / "d1-facts-same-inode.txt").read_text()},
            "copy-up bytes drifted":
                {"facts_text": (FIXTURES / "d1-facts-sha-drift.txt").read_text()},
        }
        for label, override in negatives.items():
            with self.subTest(label):
                inputs = dict(base)
                inputs.update(override)
                with self.assertRaises(AssertionError):
                    ORACLE["copy_up"](**inputs)

    def test_n4_run1_fixture_passes(self):
        result = ORACLE["late_reported"](
            document=load_fixture("n4.json"), pid_o=1463596, pid_l=1464203,
            late_module=LATE_PROVIDER, iters_l=250)
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "unwatched-prefix")
        self.assertEqual(result["boundary"]["unwatched_ns"], 3002684461)
        self.assertEqual(result["boundary"]["entries"], 0)

    def test_n4_since_rewritten_fixture_fails(self):
        with self.assertRaises(AssertionError):
            ORACLE["late_reported"](
                document=load_fixture("n4-since-rewritten.json"), pid_o=1463596,
                pid_l=1464203, late_module=LATE_PROVIDER, iters_l=250)


class OracleCliTest(unittest.TestCase):
    COPY_ARGS = ("--pre-kernel", "--pre-userspace", "--span-kernel",
                 "--span-userspace", "--fresh-kernel", "--fresh-userspace",
                 "--pre-profile-a", "--pre-profile-b", "--post-profile-b")

    def copy_up_args(self, work, inputs):
        note = Path(work) / "dc73.txt"
        note.write_text(inputs.pop("dc73_note"))
        facts = Path(work) / "facts.txt"
        facts.write_text(inputs.pop("facts_text"))
        args = ["copy-up", "--lane", inputs.pop("lane"),
                "--pid-a", str(inputs.pop("pid_a")),
                "--pid-b-pre", str(inputs.pop("pid_b_pre")),
                "--pid-b-span", str(inputs.pop("pid_b_span")),
                "--pid-b-post", str(inputs.pop("pid_b_post")),
                "--iters-a", str(inputs.pop("iters_a")),
                "--iters-b", str(inputs.pop("iters_b")),
                "--dc73-note", str(note), "--facts-log", str(facts)]
        if "b_pre_round2_calls" in inputs:
            args += ["--b-pre-round2-calls", str(inputs.pop("b_pre_round2_calls"))]
        if "b_pre_round2_pid" in inputs:
            args += ["--b-pre-round2-pid", str(inputs.pop("b_pre_round2_pid"))]
        for key, document in inputs.items():
            args += [f"--{key.replace('_', '-')}",
                     write_json(work, f"{key}.json", document)]
        return args

    def test_copy_up_cli_passes_lane_b(self):
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(*self.copy_up_args(work, good_copy_up_inputs()))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)["ok"])
            self.assertIn(
                "KNOWN_ISSUE cell=D1 copy-up-stale-caller pid=102 "
                "old_module=m7 new_module=m8",
                completed.stderr)

    def test_copy_up_cli_round2_passes(self):
        inputs = good_copy_up_inputs()
        inputs["b_pre_round2_calls"] = 1500
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(*self.copy_up_args(work, inputs))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["b_pre_round2"]["calls"], 1500)

    def test_copy_up_cli_round2_pid_passes(self):
        inputs = good_copy_up_inputs()
        inputs["b_pre_round2_calls"] = 1500
        inputs["b_pre_round2_pid"] = PID_B3
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(*self.copy_up_args(work, inputs))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["b_pre_round2"]["pid"], PID_B3)

    def test_copy_up_cli_refuses_mutation(self):
        inputs = good_copy_up_inputs()
        inputs["span_kernel"] = inventory(
            [item for item in span_edges() if item["pid"] != PID_B_SPAN],
            [collapse_gap()], backend="kernel", modules=dict(D1_MODULES_SPAN))
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(*self.copy_up_args(work, inputs))
            self.assertNotEqual(completed.returncode, 0)

    def test_copy_up_cli_requires_facts_log(self):
        with tempfile.TemporaryDirectory() as work:
            args = self.copy_up_args(work, good_copy_up_inputs())
            facts_flag = args.index("--facts-log")
            del args[facts_flag:facts_flag + 2]
            completed = run_oracle(*args)
            self.assertNotEqual(completed.returncode, 0)

    def test_late_reported_cli_passes(self):
        inputs = good_late_inputs()
        with tempfile.TemporaryDirectory() as work:
            path = write_json(work, "n4.json", inputs["document"])
            completed = run_oracle("late-reported", path,
                                   "--pid-o", str(inputs["pid_o"]),
                                   "--pid-l", str(inputs["pid_l"]),
                                   "--late-module", inputs["late_module"],
                                   "--iters-l", str(inputs["iters_l"]))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)["ok"])
            self.assertIn("BOUNDARY cell=N4 late-provider unwatched_ns=1000 entries=0",
                          completed.stderr)

    def test_late_reported_cli_refuses_silent_zero(self):
        modules = {"m7": (0, 412, 900), "m8": (0, 138, 901)}
        paths = {"m7": [PROVIDER], "m8": [LATE_PROVIDER]}
        document = inventory(
            [edge(PID_O, "m7", count=6 * ITERS_O, cov="counted",
                  since=1500, first_seen=1000, lossy=False)],
            backend="kernel", fallback="below_threshold",
            modules=modules, paths=paths)
        with tempfile.TemporaryDirectory() as work:
            path = write_json(work, "n4.json", document)
            completed = run_oracle("late-reported", path, "--pid-o", str(PID_O),
                                   "--pid-l", str(PID_L),
                                   "--late-module", LATE_PROVIDER,
                                   "--iters-l", str(ITERS_L))
            self.assertNotEqual(completed.returncode, 0)

    def test_late_reported_cli_requires_iters_l(self):
        inputs = good_late_inputs()
        with tempfile.TemporaryDirectory() as work:
            path = write_json(work, "n4.json", inputs["document"])
            completed = run_oracle("late-reported", path,
                                   "--pid-o", str(inputs["pid_o"]),
                                   "--pid-l", str(inputs["pid_l"]),
                                   "--late-module", inputs["late_module"])
            self.assertNotEqual(completed.returncode, 0)

    def test_self_test_passes(self):
        completed = run_oracle("--self-test")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_help_names_new_flags(self):
        for command, markers in (
                ("copy-up", ("--facts-log", "--b-pre-round2-calls",
                             "--b-pre-round2-pid")),
                ("late-reported", ("--iters-l",))):
            completed = run_oracle(command, "--help")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for marker in markers:
                self.assertIn(marker, completed.stdout)
        completed = run_oracle("--help")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for marker in ("--facts-log", "--iters-l"):
            self.assertIn(marker, completed.stdout)

    def test_unknown_subcommand_fails(self):
        completed = run_oracle("frobnicate")
        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
