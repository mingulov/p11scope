# SPDX-License-Identifier: GPL-3.0-or-later
"""Self-test for the v0.7.0 no-data matrix oracle.

GREEN fixtures (a healthy cell per mode) must PASS; RED fixtures (empty
views, zero endpoints/calls, unnamed refusals, exact-count mismatches,
unrecognized shapes) must FAIL. The oracle never passes a shape it does
not understand. A final case locks the matrix copy-up cells to the
same-bytes scenario.
"""

import contextlib
import io
import json
import runpy
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = runpy.run_path(str(ROOT / "scripts/matrix/nodata-oracle.py"))

EXPECTED_COUNTS = {
    "C_CloseSession": 10,
    "C_Digest": 50,
    "C_DigestInit": 50,
    "C_Finalize": 1,
    "C_GenerateRandom": 100,
    "C_GetInfo": 3,
    "C_GetSlotList": 1,
    "C_Initialize": 1,
    "C_OpenSession": 10,
}
EXPECTED_TOTAL = sum(EXPECTED_COUNTS.values())
PROVIDER = "libnodata.so"
SYSPROVIDER = "libsofthsm2.so"
CALLER = "harness"


def profile_doc(functions, scope="pid", completeness="COMPLETE",
                provider_path="/work/cells/x/libnodata.so"):
    return {
        "schema": "p11scope/observed-profile/v3",
        "capture": {
            "scope": scope,
            "modules": [{
                "path": provider_path,
                "dev": [8, 1],
                "ino": 99,
                "sha256": "b" * 64,
                "build_id": None,
            }],
        },
        "evidence": {"completeness": completeness},
        "functions": functions,
    }


def function_row(name, calls, forwarding_layer=False):
    row = {"names": [name], "calls": calls,
           "module": {"dev": [8, 1], "ino": 99, "sha256": "b" * 64}}
    if forwarding_layer:
        row["forwarding_layer"] = True
    return row


def exact_functions():
    return [function_row(name, count)
            for name, count in sorted(EXPECTED_COUNTS.items())]


def trace_text(per_fn, caller='"harness"', raw_calls=None, extra="",
               attribution_causes=(), attribution_status="withheld",
               observation_causes=(), observation_status="exact"):
    lines = ["CAPTURE privacy=allowlisted", "identity: exact"]
    n = 0
    for index, (name, count) in enumerate(sorted(per_fn.items())):
        for _ in range(count):
            lines.append(
                "12:00:00.00000%d %s (PID 123, TID 123) exe=\"/work/harness\" "
                "%s \u2192 CKR_OK 1.0\u00b5s" % (index, caller, name))
            n += 1
    total = n if raw_calls is None else raw_calls
    lines.append("COUNT_EVIDENCE {\"stats_entered\":%d,"
                 "\"stats_returned\":%d,\"raw_calls\":%d}"
                 % (total, total, total))
    lines.append("EVIDENCE {\"event_loss\":0,"
                 "\"gap_classes\":{\"observation\":{\"causes\":[%s],"
                 "\"status\":%s},\"attribution\":{\"causes\":[%s],"
                 "\"status\":%s}}}"
                 % (",".join(json.dumps(cause)
                             for cause in observation_causes),
                    json.dumps(observation_status),
                    ",".join(json.dumps(cause)
                             for cause in attribution_causes),
                    json.dumps(attribution_status)))
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


def inventory_doc(modules=None, edges=None, callers=None, gaps=None,
                  scope="pid"):
    return {
        "schema": "p11scope/inventory/v1",
        "scope": scope,
        "callers": callers if callers is not None else [],
        "modules": modules if modules is not None else [],
        "edges": edges if edges is not None else [],
        "gaps": gaps if gaps is not None else [],
    }


def inventory_module(state="admitted", endpoints=226,
                     paths=("/work/cells/x/libnodata.so",), reasons=()):
    return {
        "id": "m1",
        "paths": list(paths),
        "identity": {"device": {"major": 8, "minor": 1}, "inode": 99,
                     "sha256": "b" * 64, "build_id": None,
                     "source": "scan"},
        "admission": {"state": state, "endpoints": endpoints,
                      "reasons": list(reasons)},
    }


def inventory_caller(pid=123, exe_path="/work/harness"):
    return {
        "id": "c1",
        "pid": pid,
        "image": {"exe": ({"path": exe_path, "dev": [8, 1], "ino": 7}
                           if exe_path else None)},
        "lifecycle_reason": None,
    }


def inventory_edge(count=226):
    return {
        "caller": "c1",
        "module": "m1",
        "entries": {"count": count, "observation": "observed",
                    "coverage": "exact"},
        "mapping": {"state": "mapped", "reason": "identity_proof"},
        "semantics": "observed",
    }


class OracleCase(unittest.TestCase):
    def base_args(self, mode, scope, min_calls=1, extra=()):
        args = ["--cell", "t", "--mode", mode, "--scope", scope,
                "--json", "{out}", "--stdout", "{stdout}",
                "--stderr", "{stderr}", "--provider", PROVIDER,
                "--sysprovider", SYSPROVIDER, "--min-calls", str(min_calls),
                "--caller", CALLER]
        args.extend(extra)
        return args

    def write_expected(self, tmp_path):
        body = "".join("%s %d\n" % item
                       for item in sorted(EXPECTED_COUNTS.items()))
        path = Path(tmp_path) / "expected.txt"
        path.write_text(body, encoding="utf-8")
        return str(path)

    def judge(self, mode, scope, out_body, stdout_body="", stderr_body="",
              min_calls=1, extra=(), files_extra=None):
        with tempfile.TemporaryDirectory() as tmp:
            files = {"out": out_body, "stdout": stdout_body,
                     "stderr": stderr_body}
            if files_extra:
                files.update(files_extra)
            paths = {}
            for name, body in files.items():
                path = Path(tmp) / name
                path.write_text(body, encoding="utf-8")
                paths[name] = str(path)
            exp_path = self.write_expected(tmp)
            args = self.base_args(mode, scope, min_calls,
                                  [a.format(expected=exp_path)
                                   for a in extra])
            rendered = [a.format(**paths) for a in args]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = ORACLE["main"](rendered)
            return rc, out.getvalue()

    def assert_result(self, text, verdict):
        lines = [line for line in text.splitlines()
                 if line.startswith("RESULT ")]
        self.assertEqual(len(lines), 1, text)
        self.assertIn("verdict=%s" % verdict, lines[0], text)

    # GREEN: healthy profile --pid cell, exact counts, caller pid named.
    def test_profile_pid_exact_pass(self):
        doc = profile_doc(exact_functions())
        rc, text = self.judge(
            "profile", "pid", json.dumps(doc),
            stdout_body="functions: 9 rows\n",
            stderr_body="p11scope: target pid 4242 attached\n",
            extra=("--exact", "{expected}", "--caller-pid", "4242"))
        self.assertEqual(rc, 0, text)
        self.assert_result(text, "PASS")

    # GREEN: a forwarding-layer row duplicates logical calls and must
    # be skipped when summing (profile schema v3).
    def test_profile_forwarding_layer_skipped_pass(self):
        doc = profile_doc(
            exact_functions()
            + [function_row("C_GenerateRandom", 100,
                            forwarding_layer=True)])
        rc, text = self.judge(
            "profile", "pid", json.dumps(doc),
            stdout_body="functions: 10 rows\n",
            stderr_body="p11scope: target pid 4242 attached\n",
            extra=("--exact", "{expected}", "--caller-pid", "4242"))
        self.assertEqual(rc, 0, text)
        self.assert_result(text, "PASS")

    # GREEN: healthy run cell, child named on the -v stderr line.
    def test_run_child_pass(self):
        doc = profile_doc(exact_functions(), scope="child")
        rc, text = self.judge(
            "run", "child", json.dumps(doc),
            stderr_body="running /work/harness as user (uid 1000) "
                        "(groups and home restored)\n",
            extra=("--exact", "{expected}"))
        self.assertEqual(rc, 0, text)
        self.assert_result(text, "PASS")

    # GREEN: healthy trace --pid cell, exact per-function events.
    def test_trace_pid_exact_pass(self):
        rc, text = self.judge(
            "trace", "pid", trace_text(EXPECTED_COUNTS),
            stderr_body="note: /work/cells/x/libnodata.so attached\n",
            extra=("--exact", "{expected}", "--caller-pid", "123"))
        self.assertEqual(rc, 0, text)
        self.assert_result(text, "PASS")

    # GREEN: healthy inventory --pid cell.
    def test_inventory_pid_pass(self):
        doc = inventory_doc(modules=[inventory_module()],
                            edges=[inventory_edge()],
                            callers=[inventory_caller(pid=4242)])
        rc, text = self.judge("inventory", "pid", json.dumps(doc),
                              min_calls=0, extra=("--caller-pid", "4242"))
        self.assertEqual(rc, 0, text)
        self.assert_result(text, "PASS")

    # GREEN: inventory caller unknown but named with a reason.
    def test_inventory_caller_named_unknown_pass(self):
        doc = inventory_doc(
            modules=[inventory_module()], edges=[inventory_edge()],
            callers=[inventory_caller(pid=4242, exe_path=None)],
            gaps=[{"caller": "c1", "module": None, "pid": 4242,
                   "subject": "caller identity unavailable",
                   "reason": "exe_unreadable", "budget": None,
                   "repeats": 1}])
        rc, text = self.judge("inventory", "pid", json.dumps(doc),
                              min_calls=0, extra=("--caller-pid", "4242"))
        self.assertEqual(rc, 0, text)
        self.assert_result(text, "PASS")

    # GREEN: profile --system is aggregate by design; no per-caller data.
    def test_profile_system_aggregate_pass(self):
        doc = profile_doc(exact_functions(), scope="system")
        rc, text = self.judge("profile", "system", json.dumps(doc))
        self.assertEqual(rc, 0, text)
        self.assert_result(text, "PASS")

    # RED: profile shows zero calls though the workload ran.
    def test_profile_zero_calls_fail(self):
        doc = profile_doc([])
        rc, text = self.judge("profile", "pid", json.dumps(doc),
                              stderr_body="p11scope: target pid 4242\n",
                              extra=("--caller-pid", "4242"))
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: zero calls", text)

    # RED: exact multiset mismatch (one call missing).
    def test_profile_exact_mismatch_fail(self):
        counts = dict(EXPECTED_COUNTS)
        counts["C_GenerateRandom"] -= 1
        doc = profile_doc([function_row(name, count)
                           for name, count in sorted(counts.items())])
        rc, text = self.judge(
            "profile", "pid", json.dumps(doc),
            stderr_body="p11scope: target pid 4242\n",
            extra=("--exact", "{expected}", "--caller-pid", "4242"))
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: exact multiset mismatch", text)

    # RED: provider module absent from the document.
    def test_profile_provider_absent_fail(self):
        doc = profile_doc(exact_functions(),
                          provider_path="/elsewhere/libother.so")
        rc, text = self.judge(
            "profile", "pid", json.dumps(doc),
            stderr_body="p11scope: target pid 4242\n",
            extra=("--caller-pid", "4242"))
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: provider libnodata.so absent", text)

    # RED: trace truncated below the promised exact counts.
    def test_trace_truncated_fail(self):
        counts = dict(EXPECTED_COUNTS)
        counts["C_GenerateRandom"] = 10
        body = trace_text(counts, extra="TRUNCATED at 1000 events "
                                       "(--max-events 1000)")
        rc, text = self.judge(
            "trace", "pid", body,
            stderr_body="note: /work/cells/x/libnodata.so attached\n",
            extra=("--exact", "{expected}"))
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: exact event multiset mismatch", text)
        self.assertNotIn("FAIL: provider", text)

    # RED: the trigger shape — inventory attaches zero endpoints.
    def test_inventory_zero_endpoints_fail(self):
        doc = inventory_doc(modules=[inventory_module(endpoints=0)],
                            edges=[], callers=[inventory_caller()])
        rc, text = self.judge("inventory", "cgroup", json.dumps(doc),
                              min_calls=0)
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: zero endpoints attached", text)

    # RED: refused admission without a named reason.
    def test_inventory_unnamed_refusal_fail(self):
        doc = inventory_doc(
            modules=[inventory_module(state="refused", endpoints=0,
                                      reasons=[])],
            edges=[], callers=[inventory_caller()])
        rc, text = self.judge("inventory", "pid", json.dumps(doc),
                              min_calls=0)
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: unnamed refusal", text)

    # RED: caller missing with no named gap anywhere.
    def test_inventory_caller_missing_unnamed_fail(self):
        doc = inventory_doc(modules=[inventory_module()],
                            edges=[inventory_edge()], callers=[], gaps=[])
        rc, text = self.judge("inventory", "pid", json.dumps(doc),
                              min_calls=0)
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: caller 'harness' absent", text)

    # RED: valid JSON the oracle does not understand must not pass.
    def test_unrecognized_shape_fail(self):
        rc, text = self.judge("profile", "pid", json.dumps({"hello": 1}))
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: oracle: unrecognized shape", text)

    # GREEN: trace with unknown-only exe but a named attribution cause
    # (manifest-less runs withhold exe labels as semantic_unverified_slots).
    def test_trace_caller_attribution_withheld_pass(self):
        body = trace_text(
            EXPECTED_COUNTS, caller="Unknown executable",
            attribution_causes=["semantic_unverified_slots"]).replace(
            'exe="/work/harness" ', "")
        rc, text = self.judge(
            "trace", "pid", body,
            stderr_body="note: /work/cells/x/libnodata.so attached\n")
        self.assertEqual(rc, 0, text)
        self.assert_result(text, "PASS")

    # RED: unknown-only callers with a named cause that is not a
    # withheld attribution (status attested) must not pass.
    def test_trace_caller_attribution_attested_fail(self):
        body = trace_text(
            EXPECTED_COUNTS, caller="Unknown executable",
            attribution_causes=["semantic_unverified_slots"],
            attribution_status="attested").replace(
            'exe="/work/harness" ', "")
        rc, text = self.judge(
            "trace", "pid", body,
            stderr_body="note: /work/cells/x/libnodata.so attached\n")
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: caller 'harness' unnamed on all", text)
        self.assertNotIn("FAIL: provider", text)

    # RED: an observation-lane cause alone does not name why the
    # caller is unknown.
    def test_trace_caller_observation_only_fail(self):
        body = trace_text(
            EXPECTED_COUNTS, caller="Unknown executable",
            observation_causes=["event_loss"],
            observation_status="lossy").replace(
            'exe="/work/harness" ', "")
        rc, text = self.judge(
            "trace", "pid", body,
            stderr_body="note: /work/cells/x/libnodata.so attached\n")
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: caller 'harness' unnamed on all", text)
        self.assertNotIn("FAIL: provider", text)

    # RED: trace with unknown-only callers and no named cause.
    def test_trace_caller_unknown_unnamed_fail(self):
        body = trace_text(EXPECTED_COUNTS,
                          caller="Unknown executable").replace(
            'exe="/work/harness" ', "")
        rc, text = self.judge(
            "trace", "pid", body,
            stderr_body="note: /work/cells/x/libnodata.so attached\n")
        self.assertEqual(rc, 1, text)
        self.assert_result(text, "FAIL")
        self.assertIn("FAIL: caller 'harness' unnamed on all", text)
        self.assertNotIn("FAIL: provider", text)


class MatrixScriptCase(unittest.TestCase):
    # The copy-up cells must model the R-41 same-bytes scenario: only
    # metadata changes on the merged path, with bytes proven unchanged.
    # Appending bytes would probe the file-changed path instead under
    # the copy-up label.
    def test_copyup_preserves_provider_bytes(self):
        script = (ROOT / "scripts/matrix/nodata-matrix.sh").read_text(
            encoding="utf-8")
        for var in ("lc_mod", "ic_mod"):
            self.assertNotIn('>> "$%s"' % var, script)
        for var in ("lc_sha_before", "lc_sha_after",
                    "ic_sha_before", "ic_sha_after"):
            self.assertIn(var, script)


if __name__ == "__main__":
    unittest.main()

