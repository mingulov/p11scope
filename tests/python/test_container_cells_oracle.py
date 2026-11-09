# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Container-cells oracle (D1 copy-up, D1-changed, N4 late-reported): healthy twins pass, every check refuses its mutation.

D1 follows the live D1-extended shape (binding): pre collapses B-pre onto
A's module on the kernel leg while the userspace leg honestly gaps both
(no witness, no edges); the span splits honestly — A stays on its key,
B-pre's collapsed edge ends and its stale ranges rejoin the proven lower
on B's own key module (mapped, deep_scan, gap-free), B2 and the round-2
twin are admitted under the same key but unprobed (count 0, not_attached)
— and the span profile keeps one honestly lossy stale row; fresh commits
the split. The run-4 JSON fixtures still carry the old misattribution and
must now FAIL. N4 follows the live run-1 ruling: L passes via a named gap
or a stated unwatched prefix (since_ns > first_seen_ns).
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
NOTE_NEW = ("run log: copy-up-stale-caller disclosed for B-pre "
            "(proven lower on its key, upper admitted-unprobed, "
            "spanning profile honestly lossy)")
NOTE_OLD = ("D-C7-3 applies: post-copy-up userspace edge to the upper mapping is "
            "backend-divergent per docs/known-limitations.md; the kernel refusal "
            "with identity_mismatch is the correct leg.")


def key_of_module(module_id):
    return {"m7": KEY_A, "m8": KEY_B}.get(module_id, (0, 35, 7))


def edge(pid, module, evidence="deep_scan", state="mapped", count=0,
         cov="unknown", since=None, first_seen=1000, lossy=None,
         reason="not_attached", cov_reason=None):
    return {"pid": pid, "module": module, "evidence": evidence, "state": state,
            "count": count, "cov": cov, "since": since,
            "first_seen": first_seen, "lossy": lossy, "reason": reason,
            "cov_reason": cov_reason}


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


USERSPACE_GAP = ("original_file_unproven: kernel witness unavailable: "
                 "explicit userspace disables the kernel witness")


def unproven_gap(pid):
    """The honest overlay gap of a userspace leg (no witness, no edges)."""
    return (PROVIDER, USERSPACE_GAP, pid)


def span_gaps():
    """The flip records both directions; A keeps the committed survivor."""
    return [collapse_gap(),
            collapse_gap(mapping_key=KEY_A, target_key=KEY_B)]


def inventory(edges, gaps=(), observer="initial", backend="kernel",
              fallback="anchor_not_installed", modules=None, paths=None,
              shas=None):
    """One inventory v1 document over callers A/B-pre/B-post/B-span (D1) or O/L (N4).

    `edges` is a list of edge(...) dicts; `modules` maps module id ->
    (major, minor, inode); `paths` maps module id -> [paths]; `shas`
    maps module id -> sha256 (omitted identities stay sha-less, as
    before). Callers always carries every pid the legs need; gaps are
    (subject, reason, pid|None).
    """
    pids = [PID_A, PID_B_PRE, PID_B_POST, PID_B_SPAN, PID_B3, PID_O, PID_L]
    callers = [{"id": f"c{i}", "pid": pid} for i, pid in enumerate(pids)]
    by_pid = {pid: f"c{i}" for i, pid in enumerate(pids)}
    modules = modules if modules is not None else {"m0": (0, 35, 7)}
    paths = paths if paths is not None else {mid: [PROVIDER] for mid in modules}
    shas = shas if shas is not None else {}
    return {
        "schema": "p11scope/inventory/v1",
        "observation": {"identity": {"backend": backend, "fallback": fallback}},
        "callers": callers,
        "modules": [{"id": mid,
                     "paths": paths[mid],
                     "identity": {"device": {"major": key[0], "minor": key[1]},
                                  "inode": key[2],
                                  **({"sha256": shas[mid]} if mid in shas else {})}}
                    for mid, key in sorted(modules.items())],
        "edges": [{"caller": by_pid[item["pid"]], "module": item["module"],
                   "mapping": {"evidence": item["evidence"], "state": item["state"],
                               "first_seen_ns": item["first_seen"]},
                   "entries": {"count": item["count"],
                               "coverage": {"state": item["cov"],
                                            "since_ns": item["since"],
                                            "lossy": item["lossy"],
                                            "reason": item["cov_reason"]}}}
                 for item in edges],
        "gaps": [{"subject": subject, "reason": reason, "caller": None,
                  "module": None, "pid": pid} for subject, reason, pid in gaps],
        "pid_namespace": {"observer": observer, "kernel_pids": "initial",
                          "proc_pids": "observer"},
    }


def facts_text(a_dev=138, a_ino=100, b_dev=140, b_ino=100,
               upper_dev=51, upper_ino=200,
               sha="8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d",
               upper_sha=None, lower_stack=3):
    upper_sha = sha if upper_sha is None else upper_sha
    return ("\n".join([
        f"stat-a-pre={a_dev}:{a_ino} 941088 sha-a-pre={sha}",
        f"stat-b-pre={b_dev}:{b_ino} 941088 sha-b-pre={sha} lower-stack-b={lower_stack}",
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


def span_profile(b3_iters=ITERS_B):
    """The cgroup-B capture spanning the copy-up: one stale row, honestly lossy.

    No second object: the upper ranges refuse as an ambiguous all-plain
    collision (the named profile-spanning gap, disclosed in skipped), so
    B2's in-span round is uncounted but never silent.
    """
    identity = {"dev": [0, 140], "ino": 100, "sha256": "abc"}
    return {
        "capture": {"scope": "cgroup", "modules": [{"path": PROVIDER}]},
        "evidence": {
            "discovery": [{"path": PROVIDER, "dev": [0, 140], "ino": 100,
                           "sha256": "abc", "build_id": "bd"}],
            "attached_probes": 136,
            "event_loss": 0,
            "in_flight_at_end": 0,
            "verdict_detail": "concrete_gap",
            "skipped": [{"name": "discovery subject",
                         "reason": ("physical identity is ambiguous; "
                                    "the collision group was not attached")}],
            "pid_namespace": {"observer": "initial", "kernel_pids": "initial",
                              "proc_pids": "observer"},
            "gap_classes": {"observation": {"causes": ["skipped",
                                                       "pid_descendant_gaps"],
                                            "status": "lossy"}},
        },
        "functions": [{"names": [name], "calls": b3_iters, "errors": 0,
                       "module": dict(identity), "module_ambiguous": False}
                      for name in NAMES]
        + [{"calls": 0, "errors": 0, "names": ["C_Login"], "module": None}],
    }


def pre_edges():
    return [edge(PID_A, "m7"), edge(PID_B_PRE, "m7")]


def span_edges():
    # The honest split. A stays on its key's module; B-pre's collapsed
    # edge ended and its stale ranges rejoin the proven lower on B's own
    # key module (mapped, deep_scan, gap-free: the stale join); B2 and
    # the round-2 twin are admitted under the same key but unprobed
    # (uncertain, count 0, not_attached — never a gap).
    return [edge(PID_A, "m7"),
            edge(PID_B_PRE, "m7", state="ended"),
            edge(PID_B_PRE, "m8"),
            edge(PID_B_SPAN, "m8", state="uncertain",
                 cov_reason="not_attached"),
            edge(PID_B3, "m8", state="uncertain",
                 cov_reason="not_attached")]


def gap_only(*pids):
    """A userspace leg: every cell pid scanned yet un-edged, honestly gapped."""
    return inventory([], [unproven_gap(pid) for pid in pids],
                     backend="userspace", fallback=None, modules={})


def good_copy_up_inputs(lane="B"):
    """Healthy D1 legs: pre collapse, the honest span split, fresh exactness."""
    return {
        "pre_kernel": inventory(
            pre_edges(), [collapse_gap()], backend="kernel",
            fallback="anchor_not_installed", modules=dict(D1_MODULES_PRE)),
        "pre_userspace": gap_only(PID_A, PID_B_PRE),
        "span_kernel": inventory(
            span_edges(), span_gaps(), backend="kernel",
            fallback="anchor_not_installed", modules=dict(D1_MODULES_SPAN)),
        "span_userspace": gap_only(PID_A, PID_B_PRE, PID_B_SPAN, PID_B3),
        "fresh_kernel": inventory(
            [edge(PID_A, "m7"), edge(PID_B_POST, "m8")], backend="kernel",
            fallback="anchor_not_installed", modules=dict(D1_MODULES_SPAN)),
        "fresh_userspace": gap_only(PID_A, PID_B_POST),
        "pre_profile_a": profile(ITERS_A),
        "pre_profile_b": profile(ITERS_B),
        "post_profile_b": profile(ITERS_B),
        "span_profile": span_profile(),
        "pid_a": PID_A,
        "pid_b_pre": PID_B_PRE,
        "pid_b_span": PID_B_SPAN,
        "pid_b_post": PID_B_POST,
        "iters_a": ITERS_A,
        "iters_b": ITERS_B,
        "lane": lane,
        "dc73_note": NOTE_NEW,
        "facts_text": facts_text(),
        "b_pre_round2_pid": PID_B3,
    }


def check_copy_up(**overrides):
    inputs = good_copy_up_inputs(overrides.pop("lane", "B"))
    inputs.update(overrides)
    return ORACLE["copy_up"](**inputs)


ITERS_S, ITERS_F = 250, 100
SHA_LOWER = "8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d"
SHA_UPPER = "8d8a5c98d7a0b1c2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
# The witness-proven pair files two objects under one maps key: the
# same-key shape is the good case (proof routes, not the key).
CHANGED_MODULES = {"m8": KEY_B, "m9": KEY_B}
CHANGED_SHAS = {"m8": SHA_LOWER, "m9": SHA_UPPER}
NOTE_CHANGED = ("run log: copy-up-stale-caller disclosed for B-pre "
                "(witness-proven lower on its key with layer pre_copy_up, "
                "upper copy its own module, both mappers ledgered exact)")


def changed_facts(**overrides):
    """facts.log proving the different-bytes copy-up (upper bytes differ)."""
    return facts_text(upper_sha=SHA_UPPER, **overrides)


def changed_kernel_edges():
    return [edge(PID_B_PRE, "m8"), edge(PID_B_SPAN, "m9")]


def changed_profile(iters_s=ITERS_S, iters_f=ITERS_F):
    """The cgroup-B profile over the different-bytes copy-up: two exact rows.

    The lower row carries the stale ledger (S) with the pre_copy_up
    marker; the upper row carries the fresh ledger (F) with no marker.
    Both exact, zero loss.
    """
    lower = {"dev": [0, 140], "ino": 100, "sha256": SHA_LOWER}
    upper = {"dev": [0, 140], "ino": 100, "sha256": SHA_UPPER}
    functions = []
    for name in NAMES:
        functions.append({"names": [name], "calls": iters_s, "errors": 0,
                          "module": dict(lower), "module_ambiguous": False})
        functions.append({"names": [name], "calls": iters_f, "errors": 0,
                          "module": dict(upper), "module_ambiguous": False})
    functions.append({"calls": 0, "errors": 0, "names": ["C_Login"],
                      "module": None})
    return {
        "capture": {"scope": "cgroup",
                    "modules": [{"path": PROVIDER, **lower},
                                {"path": PROVIDER, **upper}]},
        "evidence": {
            "discovery": [{"path": PROVIDER, **lower, "build_id": "bd",
                           "layer": "pre_copy_up"},
                          {"path": PROVIDER, **upper, "build_id": "bd"}],
            "attached_probes": 136,
            "event_loss": 0,
            "in_flight_at_end": 0,
            "verdict_detail": "attribution_only",
            "pid_namespace": {"observer": "initial", "kernel_pids": "initial",
                              "proc_pids": "observer"},
            "gap_classes": {"observation": {"causes": [], "status": "exact"}},
        },
        "functions": functions,
    }


def good_changed_inputs():
    """Healthy D1-changed legs: dual attribution, dual exact counts."""
    return {
        "kernel": inventory(
            changed_kernel_edges(), backend="kernel",
            fallback="anchor_not_installed", modules=dict(CHANGED_MODULES),
            shas=dict(CHANGED_SHAS)),
        "userspace": gap_only(PID_B_PRE, PID_B_SPAN),
        "profile": changed_profile(),
        "pid_b_pre": PID_B_PRE,
        "pid_b2": PID_B_SPAN,
        "iters_s": ITERS_S,
        "iters_f": ITERS_F,
        "run_note": NOTE_CHANGED,
        "facts_text": changed_facts(),
    }


def check_changed(**overrides):
    inputs = good_changed_inputs()
    inputs.update(overrides)
    return ORACLE["copy_up_changed"](**inputs)


MIDCAPTURE_STAMPS = ("t-profile-ready=100 t-bpre-ledger=200 t-patch=300 "
                     "t-b2-ledger=400 t-profile-end=500\n")
NOTE_MIDCAPTURE = (NOTE_CHANGED + " (mid-capture: the profile started before "
                   "the patch, so the stale ledger is exact on the lower row "
                   "and the fresh ledger is unattributed; the profile "
                   "discloses provider_changed with a lossy observation)")


def midcapture_profile(iters_s=ITERS_S):
    """The mid-window cgroup-B profile: stale exact, fresh unattributed.

    Discovery attaches once at capture start, when only the lower file
    exists: one module, one unmarked discovery row, the stale ledger S on
    the lower functions. The upper file (and B2's fresh ledger) never
    joins the profile; the observer discloses that as provider_changed
    with a lossy observation and a concrete_gap verdict.
    """
    lower = {"dev": [0, 140], "ino": 100, "sha256": SHA_LOWER}
    functions = []
    for name in NAMES:
        functions.append({"names": [name], "calls": iters_s, "errors": 0,
                          "module": dict(lower), "module_ambiguous": False})
    functions.append({"calls": 0, "errors": 0, "names": ["C_Login"],
                      "module": None})
    return {
        "capture": {"scope": "cgroup",
                    "modules": [{"path": PROVIDER, **lower}]},
        "evidence": {
            "discovery": [{"path": PROVIDER, **lower, "build_id": "bd"}],
            "attached_probes": 136,
            "event_loss": 0,
            "in_flight_at_end": 0,
            "provider_changed": True,
            "verdict_detail": "concrete_gap",
            "pid_namespace": {"observer": "initial", "kernel_pids": "initial",
                              "proc_pids": "observer"},
            "gap_classes": {"observation": {
                "causes": ["skipped", "provider_changed",
                           "pid_descendant_gaps"],
                "status": "lossy"}},
        },
        "functions": functions,
    }


def good_midcapture_inputs():
    """Healthy D1-changed-midcapture legs: settled legs, lossy profile."""
    inputs = good_changed_inputs()
    inputs["run_note"] = NOTE_MIDCAPTURE
    inputs["facts_text"] = changed_facts() + MIDCAPTURE_STAMPS
    inputs["profile"] = midcapture_profile()
    return inputs


def check_midcapture(**overrides):
    inputs = good_midcapture_inputs()
    inputs.update(overrides)
    return ORACLE["copy_up_midcapture"](**inputs)


def with_ambient(document, pid=9999, module="m9", key=(0, 35, 356176),
                 count=0):
    """An ambient host provider edge outside the cell (agreement ignores it)."""
    document["callers"].append({"id": "camb", "pid": pid})
    document["modules"].append(
        {"id": module, "paths": [PROVIDER],
         "identity": {"device": {"major": key[0], "minor": key[1]},
                      "inode": key[2]}})
    document["edges"].append(
        {"caller": "camb", "module": module,
         "mapping": {"evidence": "deep_scan", "state": "mapped",
                     "first_seen_ns": 1000},
         "entries": {"count": count,
                     "coverage": {"state": "unknown", "since_ns": None,
                                  "lossy": None}}})
    return document


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
        self.assertNotIn("known_issue", result)
        self.assertEqual(result["b_pre_round2"]["pid"], PID_B3)
        self.assertEqual(result["b_pre_round2"]["new_module"], "m8")
        self.assertEqual(result["b_pre_round2"]["twin"], "uncertain")
        self.assertEqual(result["b_pre_round2"]["B2"], "uncertain")
        self.assertEqual(result["span_new_module"], "m8")
        self.assertEqual(result["lower_stack_b"], 3)
        self.assertIn("no proof attempted",
                      result["kernel_proof"]["finding"])
        self.assertIn("copy-up-stale-caller resolved",
                      result["stale_caller"])

    def test_lane_a_healthy_passes(self):
        result = check_copy_up(lane="A")
        self.assertTrue(result["ok"])
        self.assertEqual(result["lane"], "A")

    def test_ambient_provider_edge_ignored(self):
        """Sequential legs: an ambient host edge is outside the cell."""
        inputs = good_copy_up_inputs()
        with_ambient(inputs["span_kernel"], count=3)
        self.assertTrue(ORACLE["copy_up"](**inputs)["ok"])

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

    def test_pre_kernel_identity_none_or_known_fallback(self):
        """Forced kernel with null fallback (no proof attempted) passes."""
        inputs = good_copy_up_inputs()
        for key in ("pre_kernel", "span_kernel", "fresh_kernel"):
            inputs[key]["observation"]["identity"]["fallback"] = None
        result = ORACLE["copy_up"](**inputs)
        self.assertTrue(result["ok"])
        self.assertEqual(result["kernel_proof"]["runs"]["pre-kernel"],
                         {"backend": "kernel", "fallback": None})

    def test_pre_kernel_identity_unknown_fallback_fails(self):
        pre = inventory(pre_edges(), [collapse_gap()], backend="kernel",
                        fallback="frobnicate", modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_kernel_identity_wrong_backend_fails(self):
        pre = inventory(pre_edges(), [collapse_gap()], backend="userspace",
                        fallback=None, modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_pre_userspace_edge_fails(self):
        """Explicit userspace never edges the overlay provider: no witness."""
        userspace = inventory(pre_edges(), [unproven_gap(PID_A),
                                            unproven_gap(PID_B_PRE)],
                              backend="userspace", fallback=None,
                              modules=dict(D1_MODULES_PRE))
        with self.assertRaisesRegex(AssertionError, "edged the provider"):
            check_copy_up(pre_userspace=userspace)

    def test_pre_userspace_gap_missing_fails(self):
        """A cell pid without the honest gap is silence, not a pass."""
        userspace = inventory([], [unproven_gap(PID_A)],
                              backend="userspace", fallback=None, modules={})
        with self.assertRaisesRegex(AssertionError, "without the honest gap"):
            check_copy_up(pre_userspace=userspace)

    def test_pre_userspace_collapse_fails(self):
        """No userspace collapse names a cell key (nothing was proven)."""
        userspace = inventory([], [unproven_gap(PID_A), unproven_gap(PID_B_PRE),
                                   collapse_gap()],
                              backend="userspace", fallback=None,
                              modules=dict(D1_MODULES_PRE))
        with self.assertRaisesRegex(AssertionError, "names a cell key"):
            check_copy_up(pre_userspace=userspace)

    def test_span_userspace_edge_fails(self):
        userspace = inventory(
            [edge(PID_A, "m7"), edge(PID_B_PRE, "m8")],
            [unproven_gap(pid) for pid in
             (PID_A, PID_B_PRE, PID_B_SPAN, PID_B3)],
            backend="userspace", fallback=None,
            modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "edged the provider"):
            check_copy_up(span_userspace=userspace)

    def test_fresh_userspace_gap_missing_fails(self):
        userspace = inventory([], [unproven_gap(PID_A)],
                              backend="userspace", fallback=None, modules={})
        with self.assertRaisesRegex(AssertionError, "without the honest gap"):
            check_copy_up(fresh_userspace=userspace)

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
        span = inventory([edge(PID_A, "m7"), edge(PID_B_PRE, "m7")],
                         [collapse_gap()], backend="kernel",
                         modules=dict(D1_MODULES_PRE))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_new_module_key_already_in_pre_fails(self):
        pre = inventory(pre_edges(), [collapse_gap()], backend="kernel",
                        modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(pre_kernel=pre)

    def test_span_collapse_missing_fails(self):
        """A span with no collapse is neither observed shape."""
        span = inventory(span_edges(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "not an observed shape"):
            check_copy_up(span_kernel=span)

    def test_span_collapse_single_stable_passes(self):
        """The stable shape — exactly B's key onto A's — passes."""
        span = inventory(span_edges(), [collapse_gap()],
                         backend="kernel", modules=dict(D1_MODULES_SPAN))
        result = check_copy_up(span_kernel=span)
        self.assertTrue(result["ok"])

    def test_span_collapse_reversed_flip_fails(self):
        """RED: the flip pins its observed order; reversed refuses."""
        span = inventory(
            span_edges(),
            [collapse_gap(mapping_key=KEY_A, target_key=KEY_B),
             collapse_gap()],
            backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_collapse_single_inverted_fails(self):
        """RED: a lone inverted collapse (A's onto B's) refuses."""
        span = inventory(
            span_edges(),
            [collapse_gap(mapping_key=KEY_A, target_key=KEY_B)],
            backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b_pre_old_edge_live_fails(self):
        """The collapsed old edge ended; a live one is the old shape."""
        edges = [item if (item["pid"], item["module"]) != (PID_B_PRE, "m7")
                 else edge(PID_B_PRE, "m7")
                 for item in span_edges()]
        span = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "stale edge"):
            check_copy_up(span_kernel=span)

    def test_span_b_pre_old_edge_missing_fails(self):
        """Without the ended old edge the flip is unproven."""
        edges = [item for item in span_edges()
                 if (item["pid"], item["module"]) != (PID_B_PRE, "m7")]
        span = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "never ended"):
            check_copy_up(span_kernel=span)

    def test_span_b_pre_new_edge_missing_fails(self):
        """B-pre's stale ranges must rejoin the proven lower on the new key."""
        edges = [item for item in span_edges()
                 if (item["pid"], item["module"]) != (PID_B_PRE, "m8")]
        span = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b_pre_new_edge_uncertain_fails(self):
        """The stale join is mapped deep_scan, never merely uncertain."""
        edges = [item if (item["pid"], item["module"]) != (PID_B_PRE, "m8")
                 else edge(PID_B_PRE, "m8", state="uncertain")
                 for item in span_edges()]
        span = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b_pre_new_edge_maps_match_fails(self):
        edges = [item if (item["pid"], item["module"]) != (PID_B_PRE, "m8")
                 else edge(PID_B_PRE, "m8", evidence="maps_match")
                 for item in span_edges()]
        span = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b_pre_with_gap_fails(self):
        """Joined yet still carrying the gap is a contradiction."""
        span = inventory(span_edges(),
                         span_gaps() + [unproven_gap(PID_B_PRE)],
                         backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "still carries the gap"):
            check_copy_up(span_kernel=span)

    def test_span_b2_with_identity_loss_fails(self):
        span = inventory(span_edges(),
                         span_gaps() + [("x", "identity_mismatch: stale",
                                         PID_B_SPAN)],
                         backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_pidless_mismatch_aggregate_fails(self):
        """The span loss gate is global zero: pid-less aggregates refuse.

        The 0-vs-2 flip race is a named known flake (see
        docs/known-limitations.md); the gate stays exact and any
        identity_mismatch gap in the span — pid-less or not — fails.
        """
        span = inventory(
            span_edges(),
            span_gaps() + [(
                "maps attribution",
                "processes mapping pinned provider objects were not "
                "attributed to them: 2 identity_mismatch (per-process "
                "reasons in the process table)",
                None)],
            backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b2_counted_fails(self):
        """Admitted-unprobed means zero counted entries, never a ledger."""
        edges = [item if (item["pid"], item["module"]) != (PID_B_SPAN, "m8")
                 else edge(PID_B_SPAN, "m8", state="uncertain", count=6,
                           cov="counted", since=3000, first_seen=2000,
                           lossy=False)
                 for item in span_edges()]
        span = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b2_maps_match_fails(self):
        """The admitted edge carries deep_scan evidence, never maps_match."""
        edges = [item if (item["pid"], item["module"]) != (PID_B_SPAN, "m8")
                 else edge(PID_B_SPAN, "m8", state="uncertain",
                           evidence="maps_match")
                 for item in span_edges()]
        span = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b2_without_disclosure_fails(self):
        """Admitted without not_attached is silence about the unprobed round."""
        edges = [item if (item["pid"], item["module"]) != (PID_B_SPAN, "m8")
                 else edge(PID_B_SPAN, "m8", state="uncertain",
                           cov_reason=None)
                 for item in span_edges()]
        span = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_span_b2_mapped_on_old_module_fails(self):
        """Neither B2 nor the twin may map the old module."""
        span = inventory(span_edges() + [edge(PID_B_SPAN, "m7")],
                         span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "old module"):
            check_copy_up(span_kernel=span)

    def test_span_round2_pid_required(self):
        with self.assertRaisesRegex(AssertionError, "round-2 twin pid"):
            check_copy_up(b_pre_round2_pid=None)

    def test_facts_lower_stack_missing_fails(self):
        facts = facts_text().replace(" lower-stack-b=3", "")
        with self.assertRaises(AssertionError):
            check_copy_up(facts_text=facts)

    def test_facts_lower_stack_single_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(facts_text=facts_text(lower_stack=1))

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

    def test_dc73_note_with_disproven_sentence_fails(self):
        """The disclosure next to the disproven sentence still FAILs."""
        with self.assertRaisesRegex(AssertionError, "disproven"):
            check_copy_up(dc73_note=NOTE_NEW + " " + NOTE_OLD)

    def test_dc73_note_without_proof_facts_fails(self):
        """The disclosure alone is not the proof: lower/upper/unprobed/lossy."""
        with self.assertRaisesRegex(AssertionError, "proof facts"):
            check_copy_up(dc73_note="run log: copy-up-stale-caller disclosed")

    def test_round2_twin_admitted_uncertain_passes(self):
        """B2 and the twin: admitted under the new key, unprobed."""
        record = check_copy_up()["b_pre_round2"]
        self.assertEqual(record["pid"], PID_B3)
        self.assertEqual(record["new_module"], "m8")
        self.assertEqual(record["twin"], "uncertain")
        self.assertEqual(record["B2"], "uncertain")

    def test_round2_twin_mapped_passes(self):
        """Mapped where the last pass confirmed the member: still unprobed."""
        edges = [item if (item["pid"], item["module"]) != (PID_B3, "m8")
                 else edge(PID_B3, "m8", cov_reason="not_attached")
                 for item in span_edges()]
        kernel = inventory(edges, span_gaps(), backend="kernel",
                           modules=dict(D1_MODULES_SPAN))
        record = check_copy_up(span_kernel=kernel)["b_pre_round2"]
        self.assertEqual(record["twin"], "mapped")

    def test_round2_twin_gap_only_passes(self):
        """No edge at all is honestly uncounted — with the gap."""
        edges = [item for item in span_edges()
                 if (item["pid"], item["module"]) != (PID_B3, "m8")]
        kernel = inventory(edges, span_gaps() + [unproven_gap(PID_B3)],
                           backend="kernel", modules=dict(D1_MODULES_SPAN))
        record = check_copy_up(span_kernel=kernel)["b_pre_round2"]
        self.assertEqual(record["twin"], "gap-only")

    def test_round2_twin_without_gap_fails_named(self):
        """A stale twin without its refusal row is silence, not a pass."""
        edges = [item for item in span_edges()
                 if (item["pid"], item["module"]) != (PID_B3, "m8")]
        twin = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "no edge yet no gap"):
            check_copy_up(span_kernel=twin)

    def test_round2_twin_counted_fails_named(self):
        """The admitted twin never counts through the collapse."""
        edges = [item if (item["pid"], item["module"]) != (PID_B3, "m8")
                 else edge(PID_B3, "m8", state="uncertain", count=9)
                 for item in span_edges()]
        twin = inventory(edges, span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=twin)

    def test_round2_twin_admitted_with_gap_fails_named(self):
        """Admitted yet still carrying the gap is a contradiction."""
        twin = inventory(span_edges(), span_gaps() + [unproven_gap(PID_B3)],
                         backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError,
                                    "admitted yet still carries the gap"):
            check_copy_up(span_kernel=twin)

    def test_round2_twin_old_mapped_fails_named(self):
        """The twin never maps the old module."""
        twin = inventory(span_edges() + [edge(PID_B3, "m7")], span_gaps(),
                         backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "old module"):
            check_copy_up(span_kernel=twin)

    def test_round2_twin_unscanned_fails_named(self):
        """The twin pid must be scanned in the span."""
        twin = inventory(span_edges(), span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        twin["callers"] = [c for c in twin["callers"] if c["pid"] != PID_B3]
        twin["edges"] = [e for e in twin["edges"]
                         if twin["callers"] and e["caller"] in
                         {c["id"] for c in twin["callers"]}]
        with self.assertRaisesRegex(AssertionError, "unscanned"):
            check_copy_up(span_kernel=twin)

    def test_span_profile_missing_fails(self):
        with self.assertRaises(AssertionError):
            check_copy_up(span_profile=None)

    def test_span_profile_twin_row_fails(self):
        """No second object: a twin row is the unshipped shape."""
        document = span_profile()
        document["capture"]["modules"].append({"path": PROVIDER})
        document["evidence"]["discovery"].append(
            dict(document["evidence"]["discovery"][0]))
        with self.assertRaisesRegex(AssertionError, "one stale row"):
            check_copy_up(span_profile=document)

    def test_span_profile_marker_present_fails(self):
        """The single row carries no layer marker (nothing proved it)."""
        document = span_profile()
        document["evidence"]["discovery"][0]["layer"] = "pre_copy_up"
        with self.assertRaisesRegex(AssertionError, "no layer marker"):
            check_copy_up(span_profile=document)

    def test_span_profile_total_short_fails(self):
        document = span_profile()
        document["functions"][0]["calls"] = ITERS_B - 1
        with self.assertRaises(AssertionError):
            check_copy_up(span_profile=document)

    def test_span_profile_fresh_leak_fails(self):
        """Any fresh-side leak inflates a total and fails."""
        document = span_profile()
        document["functions"][0]["calls"] = ITERS_B + 1
        with self.assertRaises(AssertionError):
            check_copy_up(span_profile=document)

    def test_span_profile_function_row_missing_fails(self):
        document = span_profile()
        document["functions"] = [
            row for row in document["functions"]
            if row["names"] != ["C_Digest"]]
        with self.assertRaises(AssertionError):
            check_copy_up(span_profile=document)

    def test_span_profile_exact_verdict_fails(self):
        """The spanning verdict is honestly lossy, never exact."""
        document = span_profile()
        document["evidence"]["verdict_detail"] = "attribution_only"
        with self.assertRaises(AssertionError):
            check_copy_up(span_profile=document)

    def test_span_profile_undisclosed_skipped_fails(self):
        """B2's in-span round is uncounted but never silent."""
        document = span_profile()
        document["evidence"]["skipped"] = []
        with self.assertRaises(AssertionError):
            check_copy_up(span_profile=document)

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
                         span_gaps(), backend="kernel",
                         modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(span_kernel=span)

    def test_fresh_restarted_b_without_edge_fails(self):
        fresh = inventory([edge(PID_A, "m7")], backend="kernel",
                          modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "lost its edge"):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_restarted_b_unscanned_fails(self):
        fresh = inventory([edge(PID_A, "m7")], backend="kernel",
                          modules=dict(D1_MODULES_SPAN))
        fresh["callers"] = [c for c in fresh["callers"] if c["pid"] != PID_B_POST]
        with self.assertRaisesRegex(AssertionError, "unscanned"):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_restarted_b_wrong_key_fails(self):
        """B-post edges B's key module after the restart, never A's."""
        fresh = inventory([edge(PID_A, "m7"), edge(PID_B_POST, "m7")],
                          backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "B-post key"):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_collapse_survives_fails(self):
        fresh = inventory([edge(PID_A, "m7"), edge(PID_B_POST, "m8")],
                          [collapse_gap()], backend="kernel",
                          modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "survives the restart"):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_restarted_b_with_gap_fails(self):
        fresh = inventory([edge(PID_A, "m7"), edge(PID_B_POST, "m8")],
                          [unproven_gap(PID_B_POST)], backend="kernel",
                          modules=dict(D1_MODULES_SPAN))
        with self.assertRaisesRegex(AssertionError, "still carries the gap"):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_identity_loss_fails(self):
        fresh = inventory([edge(PID_A, "m7"), edge(PID_B_POST, "m8")],
                          [("x", "identity_mismatch: stale", PID_B_POST)],
                          backend="kernel", modules=dict(D1_MODULES_SPAN))
        with self.assertRaises(AssertionError):
            check_copy_up(fresh_kernel=fresh)

    def test_fresh_edges_committed_split(self):
        result = check_copy_up()
        self.assertIn(PID_A, result["fresh_kernel_edges"])
        self.assertIn(PID_B_POST, result["fresh_kernel_edges"])

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


class CopyUpChangedTest(unittest.TestCase):
    """D1-changed: different-bytes copy-up, both mappers ledgered exact.

    The kernel leg attributes B-pre to the witness-proven lower module
    and B2 to the upper module (same maps key, routed by proof); the
    userspace leg honestly gaps both; the cgroup-B profile counts the
    stale ledger S on the pre_copy_up row and the fresh ledger F on the
    upper row, both exact.
    """

    def test_changed_healthy_passes(self):
        result = check_changed()
        self.assertTrue(result["ok"])
        self.assertEqual(result["check"], "copy-up-changed")
        self.assertEqual(result["lower_module"]["sha256"], SHA_LOWER)
        self.assertEqual(result["upper_module"]["sha256"], SHA_UPPER)
        self.assertEqual(result["lower_stack_b"], 3)

    def test_changed_same_bytes_facts_fail(self):
        """Same-bytes evidence is not this cell (D1 owns that shape)."""
        with self.assertRaises(AssertionError):
            check_changed(facts_text=facts_text())

    def test_changed_same_inode_facts_fail(self):
        with self.assertRaises(AssertionError):
            check_changed(facts_text=changed_facts(upper_dev=140,
                                                   upper_ino=100))

    def test_changed_single_row_fails(self):
        """One kernel module cannot carry both mappers."""
        kernel = inventory(
            [edge(PID_B_PRE, "m8"), edge(PID_B_SPAN, "m8")],
            backend="kernel", fallback="anchor_not_installed",
            modules={"m8": KEY_B}, shas={"m8": SHA_LOWER})
        with self.assertRaises(AssertionError):
            check_changed(kernel=kernel)

    def test_changed_swapped_edges_fail(self):
        """B-pre on the upper row (or B2 on the lower) is misattribution."""
        kernel = inventory(
            [edge(PID_B_PRE, "m9"), edge(PID_B_SPAN, "m8")],
            backend="kernel", fallback="anchor_not_installed",
            modules=dict(CHANGED_MODULES), shas=dict(CHANGED_SHAS))
        with self.assertRaises(AssertionError):
            check_changed(kernel=kernel)

    def test_changed_b2_unprobed_fails(self):
        """The fresh mapper joins mapped deep_scan, never unprobed."""
        kernel = inventory(
            [edge(PID_B_PRE, "m8"),
             edge(PID_B_SPAN, "m9", state="uncertain",
                  cov_reason="not_attached")],
            backend="kernel", fallback="anchor_not_installed",
            modules=dict(CHANGED_MODULES), shas=dict(CHANGED_SHAS))
        with self.assertRaises(AssertionError):
            check_changed(kernel=kernel)

    def test_changed_collapse_fails(self):
        """No collapse may hide the lower/upper split."""
        kernel = inventory(
            changed_kernel_edges(), [collapse_gap()], backend="kernel",
            fallback="anchor_not_installed", modules=dict(CHANGED_MODULES),
            shas=dict(CHANGED_SHAS))
        with self.assertRaises(AssertionError):
            check_changed(kernel=kernel)

    def test_changed_identity_loss_fails(self):
        kernel = inventory(
            changed_kernel_edges(), [("x", "identity_mismatch", None)],
            backend="kernel", fallback="anchor_not_installed",
            modules=dict(CHANGED_MODULES), shas=dict(CHANGED_SHAS))
        with self.assertRaises(AssertionError):
            check_changed(kernel=kernel)

    def test_changed_userspace_edged_fails(self):
        """The negative leg never edges: without the witness, no join."""
        userspace = inventory(
            [edge(PID_B_PRE, "m8")], [unproven_gap(PID_B_SPAN)],
            backend="userspace", fallback=None,
            modules={"m8": KEY_B}, shas={"m8": SHA_LOWER})
        with self.assertRaises(AssertionError):
            check_changed(userspace=userspace)

    def test_changed_lower_row_unmarked_fails(self):
        """The profile's lower row carries the pre_copy_up marker."""
        profile = changed_profile()
        del profile["evidence"]["discovery"][0]["layer"]
        with self.assertRaises(AssertionError):
            check_changed(profile=profile)

    def test_changed_upper_row_marked_fails(self):
        """The marker travels only on the lower file's row."""
        profile = changed_profile()
        profile["evidence"]["discovery"][1]["layer"] = "pre_copy_up"
        with self.assertRaises(AssertionError):
            check_changed(profile=profile)

    def test_changed_swapped_counts_fail(self):
        """S counts on the lower row, F on the upper row — never swapped."""
        profile = changed_profile(iters_s=ITERS_F, iters_f=ITERS_S)
        with self.assertRaises(AssertionError):
            check_changed(profile=profile)

    def test_changed_single_profile_row_fails(self):
        profile = changed_profile()
        profile["capture"]["modules"] = profile["capture"]["modules"][:1]
        profile["evidence"]["discovery"] = profile["evidence"]["discovery"][:1]
        profile["functions"] = [row for row in profile["functions"]
                                if row.get("module", {}) is None
                                or row["module"]["sha256"] == SHA_LOWER]
        with self.assertRaises(AssertionError):
            check_changed(profile=profile)

    def test_changed_equal_ledgers_fail(self):
        """Equal S and F cannot pin the routing direction."""
        with self.assertRaises(AssertionError):
            check_changed(iters_s=ITERS_F)

    def test_changed_different_overlay_keys_also_pass(self):
        """The pair routes by proof: distinct overlay keys pass too."""
        upper_key = (0, 140, 200)
        kernel = inventory(
            changed_kernel_edges(), backend="kernel",
            fallback="anchor_not_installed",
            modules={"m8": KEY_B, "m9": upper_key},
            shas=dict(CHANGED_SHAS))
        result = check_changed(kernel=kernel)
        self.assertTrue(result["ok"])
        self.assertEqual(result["upper_module"]["ino"], 200)

    def test_changed_note_without_stale_caller_fails(self):
        with self.assertRaises(AssertionError):
            check_changed(run_note="run log: no disclosure here")


class CopyUpMidcaptureTest(unittest.TestCase):
    """D1-changed-midcapture: the patch lands during the running profile.

    The settled legs judge exactly as D1-changed; the window stamps in
    facts.log prove the patch is strictly inside the capture window.
    """

    def test_midcapture_healthy_passes(self):
        result = check_midcapture()
        self.assertTrue(result["ok"])
        self.assertEqual(result["check"], "copy-up-midcapture")
        self.assertEqual(result["window"]["t-patch"], "300")

    def test_midcapture_missing_stamp_fails(self):
        facts = changed_facts() + MIDCAPTURE_STAMPS.replace("t-patch=300 ", "")
        with self.assertRaises(AssertionError):
            check_midcapture(facts_text=facts)

    def test_midcapture_patch_before_stale_ledger_fails(self):
        """The stale ledger must complete before the patch lands."""
        facts = changed_facts() + MIDCAPTURE_STAMPS.replace(
            "t-patch=300", "t-patch=150")
        with self.assertRaises(AssertionError):
            check_midcapture(facts_text=facts)

    def test_midcapture_patch_after_window_fails(self):
        """A patch past the window end is the settled cell, not this one."""
        facts = changed_facts() + MIDCAPTURE_STAMPS.replace(
            "t-profile-end=500", "t-profile-end=250")
        with self.assertRaises(AssertionError):
            check_midcapture(facts_text=facts)

    def test_midcapture_settled_note_fails(self):
        """The settled run note does not name the mid-capture mode."""
        with self.assertRaises(AssertionError):
            check_midcapture(run_note=NOTE_CHANGED)

    def test_midcapture_swapped_edges_fail(self):
        """The settled legs judge exactly as D1-changed."""
        kernel = inventory(
            [edge(PID_B_PRE, "m9"), edge(PID_B_SPAN, "m8")],
            backend="kernel", fallback="anchor_not_installed",
            modules=dict(CHANGED_MODULES), shas=dict(CHANGED_SHAS))
        with self.assertRaises(AssertionError):
            check_midcapture(kernel=kernel)

    def test_midcapture_settled_profile_fails(self):
        """A dual exact profile is the settled shape, not a mid shape."""
        with self.assertRaises(AssertionError):
            check_midcapture(profile=changed_profile())

    def test_midcapture_undisclosed_loss_fails(self):
        """A single row without the provider_changed disclosure fails."""
        profile = midcapture_profile()
        profile["evidence"]["provider_changed"] = False
        profile["evidence"]["verdict_detail"] = "attribution_only"
        profile["evidence"]["gap_classes"]["observation"] = {
            "causes": [], "status": "exact"}
        with self.assertRaises(AssertionError):
            check_midcapture(profile=profile)

    def test_midcapture_fresh_row_fails(self):
        """The upper file never joins a mid-window profile."""
        profile = midcapture_profile()
        upper = {"dev": [0, 140], "ino": 100, "sha256": SHA_UPPER}
        profile["functions"].append(
            {"names": ["C_GenerateRandom"], "calls": ITERS_F, "errors": 0,
             "module": upper, "module_ambiguous": False})
        with self.assertRaises(AssertionError):
            check_midcapture(profile=profile)

    def test_midcapture_stale_short_fails(self):
        """The stale ledger stays exact even mid-window."""
        with self.assertRaises(AssertionError):
            check_midcapture(profile=midcapture_profile(iters_s=ITERS_S - 1))

    def test_midcapture_marked_lower_fails(self):
        """One file at attach time means no pair marker on the row."""
        profile = midcapture_profile()
        profile["evidence"]["discovery"][0]["layer"] = "pre_copy_up"
        with self.assertRaises(AssertionError):
            check_midcapture(profile=profile)


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

    def test_l_gap_about_unrelated_so_fails(self):
        """A gap about another .so never stands in for the late module."""
        with self.assertRaises(AssertionError):
            check_late(gaps=[("/usr/lib/libevil.so", "r", PID_L)])

    def test_l_gap_about_unrelated_device_fails(self):
        """A gap about another device:ino never names the late module."""
        with self.assertRaises(AssertionError):
            check_late(gaps=[("device 0:999 inode 1", "r", PID_L)])

    def test_l_gap_about_other_pid_mem_fails(self):
        with self.assertRaises(AssertionError):
            check_late(gaps=[("/proc/999/mem", "r", PID_L)])

    def test_l_gap_device_matching_late_key_passes(self):
        gaps = [("device 0:138 inode 901",
                 "module first observed after admission", PID_L)]
        result = check_late(gaps=gaps, since=1000)
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "edge-with-gap")

    def test_l_gap_proc_mem_of_l_passes(self):
        gaps = [("/proc/202/mem",
                 "module first observed after admission", PID_L)]
        result = check_late(gaps=gaps, since=1000)
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], "edge-with-gap")

    def test_l_gap_branch_edge_above_ledger_fails(self):
        """The gap branch bounds L's edge by its ledger total too."""
        gaps = [(LATE_PROVIDER, "module first observed after admission",
                 PID_L)]
        with self.assertRaises(AssertionError):
            check_late(gaps=gaps, cov="counted", count=6 * ITERS_L + 1)

    def test_l_gap_branch_edge_bad_status_fails(self):
        """The gap branch checks L's edge status too."""
        gaps = [(LATE_PROVIDER, "module first observed after admission",
                 PID_L)]
        with self.assertRaises(AssertionError):
            check_late(gaps=gaps, cov="frobnicate", count=5)

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
    """The real run-4 / run-1 JSONs, trimmed to what the oracle reads.

    Run 4 predates the witness: its span still maps the stale caller to
    the new module, so the old shape must now FAIL (the flip pin).
    """

    def test_d1_run4_old_shape_refused(self):
        facts = (FIXTURES / "d1-facts.txt").read_text() + "lower-stack-b=3\n"
        note = (FIXTURES / "d1-note.txt").read_text()
        with self.assertRaises(AssertionError):
            ORACLE["copy_up"](
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
                facts, 1454781, span_profile=span_profile())

    def test_d1_negative_fixtures_fail(self):
        facts = (FIXTURES / "d1-facts.txt").read_text() + "lower-stack-b=3\n"
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
            span_profile=span_profile(),
            pid_a=1452406, pid_b_pre=1452576, pid_b_span=1454781,
            pid_b_post=1456333, iters_a=400, iters_b=250, lane="B",
            dc73_note=note, facts_text=facts, b_pre_round2_pid=1454781)
        negatives = {
            "duplicated collapse gap":
                {"span_kernel": load_fixture("d1-span-kernel-dup-collapse.json")},
            "span B2 entries uncounted":
                {"span_kernel": load_fixture("d1-span-kernel-bpre-mapped.json")},
            "collapse gap missing":
                {"pre_kernel": load_fixture("d1-pre-kernel-no-collapse.json")},
            "kernel proof missing":
                {"pre_kernel": load_fixture("d1-pre-kernel-userspace-identity.json")},
            "copy-up unproven (same inode)":
                {"facts_text": (FIXTURES / "d1-facts-same-inode.txt").read_text()
                 + "lower-stack-b=3\n"},
            "copy-up bytes drifted":
                {"facts_text": (FIXTURES / "d1-facts-sha-drift.txt").read_text()
                 + "lower-stack-b=3\n"},
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
            result = json.loads(completed.stdout)
            self.assertTrue(result["ok"])
            self.assertEqual(result["b_pre_round2"]["pid"], PID_B3)
            self.assertEqual(result["b_pre_round2"]["twin"], "uncertain")
            self.assertIn(
                "D1 cell=D1 copy-up-stale-caller resolved: pid=102 "
                "edge=new-module mapped (stale ranges rejoined the proven lower "
                "on the cell's own key; the collapsed old edge ended; no gap)",
                completed.stderr)
            self.assertIn(
                "D1 cell=D1 copy-up-round2-caller resolved: pid=105 "
                "ledgered=1500 (admitted: uncertain new edge, "
                "uncounted: not_attached)",
                completed.stderr)

    def test_copy_up_cli_requires_round2_pid(self):
        inputs = good_copy_up_inputs()
        del inputs["b_pre_round2_pid"]
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(*self.copy_up_args(work, inputs))
            self.assertNotEqual(completed.returncode, 0)

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

    def changed_args(self, work, inputs):
        note = Path(work) / "run-note.txt"
        note.write_text(inputs.pop("run_note"))
        facts = Path(work) / "facts.txt"
        facts.write_text(inputs.pop("facts_text"))
        args = ["copy-up-changed",
                "--pid-b-pre", str(inputs.pop("pid_b_pre")),
                "--pid-b2", str(inputs.pop("pid_b2")),
                "--iters-s", str(inputs.pop("iters_s")),
                "--iters-f", str(inputs.pop("iters_f")),
                "--run-note", str(note), "--facts-log", str(facts)]
        for key, document in inputs.items():
            args += [f"--{key.replace('_', '-')}",
                     write_json(work, f"{key}.json", document)]
        return args

    def test_changed_cli_passes(self):
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(*self.changed_args(work, good_changed_inputs()))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["ok"])
            self.assertEqual(result["check"], "copy-up-changed")
            self.assertEqual(result["lower_module"]["sha256"], SHA_LOWER)
            self.assertEqual(result["upper_module"]["sha256"], SHA_UPPER)
            self.assertIn(
                "D1-changed cell=D1-changed copy-up-stale-caller resolved: "
                "pid=102 edge=lower-module mapped (stale ranges joined the "
                "witness-proven lower file; the upper copy is its own module; "
                "no gap)",
                completed.stderr)

    def test_changed_cli_refuses_mutation(self):
        inputs = good_changed_inputs()
        inputs["facts_text"] = facts_text()
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(*self.changed_args(work, inputs))
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("copy-up changed no bytes", completed.stderr)

    def midcapture_args(self, work, inputs):
        args = self.changed_args(work, inputs)
        args[0] = "copy-up-midcapture"
        return args

    def test_midcapture_cli_passes(self):
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(
                *self.midcapture_args(work, good_midcapture_inputs()))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["ok"])
            self.assertEqual(result["check"], "copy-up-midcapture")
            self.assertEqual(result["window"]["t-patch"], "300")

    def test_midcapture_cli_refuses_unstamped_window(self):
        inputs = good_midcapture_inputs()
        inputs["facts_text"] = changed_facts()
        with tempfile.TemporaryDirectory() as work:
            completed = run_oracle(*self.midcapture_args(work, inputs))
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("t-profile-ready", completed.stderr)

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
                ("copy-up", ("--facts-log", "--b-pre-round2-pid",
                             "--span-profile")),
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
