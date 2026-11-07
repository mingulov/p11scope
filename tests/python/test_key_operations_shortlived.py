#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Short-lived cells: full-script self-test through fakes, plus check units.

Runs scripts/ci/key-operations-shortlived.sh end to end with a
self-stopping fake observer (canned docs per KEYOPS_SL_SELFTEST_SCENARIO),
a fake signer/keygen pair, and asserts the shortlived-shaped and
shortlived-counted rows for every scenario: clean, no-miss,
unaccounted, refused-split, gap under/over counts, ambient headroom,
suppression, a corrupt doc, signer failure and observer exit. Also
unit-tests scripts/ci/key_operations_shortlived_checks.py. No
SoftHSM, no privilege, no real observer. Run as a script:

    python3 -I tests/python/test_key_operations_shortlived.py -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/key-operations-shortlived.sh"

sys.path.insert(0, str(ROOT / "scripts/ci"))
import key_operations_shortlived_checks as checks  # noqa: E402


FAKE_OBSERVER = """#!/bin/sh
# Fake observer: seal line, self-stop after FAKE_OBSERVE_S, canned doc.
# KEYOPS_SL_SELFTEST_SCENARIO: clean | no-miss | unaccounted |
# refused-split | undercount | ambient | overcount | suppressed |
# garbage-doc (each but garbage-doc writes a
# doc naming $FAKE_SIGNER as the fixture and $FAKE_PROVIDER as the
# subset provider, then exits $FAKE_OBS_EXIT).
out=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "-o" ]; then out=$arg; fi
    prev=$arg
done
echo "p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: recorded only with --key-operations)" >&2
sleep "${FAKE_OBSERVE_S:-3}"
scenario=${KEYOPS_SL_SELFTEST_SCENARIO:-clean}
fixture=${FAKE_SIGNER:?}
provider=${FAKE_PROVIDER:?}
if [ "$scenario" = garbage-doc ]; then
    echo "NOT JSON{{{" > "$out"
    exit "${FAKE_OBS_EXIT:-0}"
fi
caller() {
    printf '{"id": "%s", "retired": %s, "image": {"exe": {"path": "%s"}}}' \
        "$1" "$2" "$3"
}
mod='{"id": "m0", "paths": ["PROVIDER"]}'
case $scenario in
    clean)
        callers="$(caller c0 true "$fixture"),$(caller c1 true "$fixture")"
        edges='[{"caller": "c0", "module": "m0"}]'
        insts='[{"caller": "c1", "module": "m0"}]'
        sedges='[{"caller": "c1", "module": "m0", "api_returns": {"count": null}}]'
        gaps='[{"subject": "callers never admitted", "reason": "1 caller(s) with provider edges exited before semantic admission; their way"}, {"subject": "admitted callers with no joined calls", "reason": "1 admitted caller(s) exited with zero joined calls; none joined"}]'
        supp=0 ;;
    no-miss)
        callers="$(caller c0 true "$fixture")"
        edges='[{"caller": "c0", "module": "m0"}]'
        insts='[{"caller": "c0", "module": "m0"}]'
        sedges='[{"caller": "c0", "module": "m0", "api_returns": {"count": 4}}]'
        gaps='[]'
        supp=0 ;;
    unaccounted)
        callers="$(caller c0 true "$fixture")"
        edges='[]'
        insts='[]'
        sedges='[]'
        gaps='[]'
        supp=0 ;;
    refused-split)
        callers="$(caller c0 true "$fixture"),$(caller c1 true "$fixture")"
        edges='[{"caller": "c0", "module": "m0"}, {"caller": "c1", "module": "m0"}]'
        insts='[]'
        sedges='[]'
        gaps='[{"subject": "callers never admitted", "reason": "1 caller(s) with provider edges exited before semantic admission; their way"}, {"subject": "callers refused admission", "reason": "1 caller(s) with provider edges were refused semantic admission; their way"}]'
        supp=0 ;;
    undercount)
        callers="$(caller c0 true "$fixture"),$(caller c1 true "$fixture")"
        edges='[{"caller": "c0", "module": "m0"}, {"caller": "c1", "module": "m0"}]'
        insts='[]'
        sedges='[]'
        gaps='[{"subject": "callers never admitted", "reason": "1 caller(s) missing one"}]'
        supp=0 ;;
    ambient)
        callers="$(caller c0 true "$fixture"),$(caller c9 true "/usr/bin/other")"
        edges='[{"caller": "c0", "module": "m0"}, {"caller": "c9", "module": "m0"}]'
        insts='[]'
        sedges='[]'
        gaps='[{"subject": "callers never admitted", "reason": "2 caller(s) fixture plus ambient"}]'
        supp=0 ;;
    overcount)
        callers="$(caller c0 true "$fixture")"
        edges='[{"caller": "c0", "module": "m0"}]'
        insts='[]'
        sedges='[]'
        gaps='[{"subject": "callers never admitted", "reason": "5 caller(s) invented"}]'
        supp=0 ;;
    suppressed)
        callers="$(caller c0 true "$fixture"),$(caller c1 true "$fixture")"
        edges='[{"caller": "c0", "module": "m0"}]'
        insts='[{"caller": "c1", "module": "m0"}]'
        sedges='[{"caller": "c1", "module": "m0", "api_returns": {"count": null}}]'
        gaps='[]'
        supp=3 ;;
    *) echo "unknown scenario: $scenario" >&2; exit 2 ;;
esac
mod=$(printf '%s' "$mod" | sed "s|PROVIDER|$provider|")
cat > "$out" <<EOF
{"callers": [$callers], "edges": $edges, "instances": $insts,
 "semantic_edges": $sedges, "modules": [$mod],
 "gaps": $gaps, "gaps_suppressed": $supp}
EOF
exit "${FAKE_OBS_EXIT:-0}"
"""

FAKE_SIGNER = """#!/bin/sh
echo "lifetime_ms=13 signs=1"
exit "${FAKE_SIGN_EXIT:-0}"
"""

FAKE_KEYGEN = """#!/bin/sh
echo "keygen ok id=0102"
exit 0
"""

FAKE_GATED = """#!/bin/sh
echo READY
exec sleep 300
"""


class ShortlivedScriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="p11scope-keyops-shortlived-")
        self.directory = Path(self.temporary.name)
        self.fakes = self.directory / "fakes"
        self.fakes.mkdir()
        for name, content in (
                ("observer", FAKE_OBSERVER), ("signer", FAKE_SIGNER),
                ("keygen", FAKE_KEYGEN), ("gated", FAKE_GATED)):
            path = self.fakes / name
            path.write_text(content)
            path.chmod(0o755)
        self.provider = self.fakes / "provider.so"
        self.provider.write_bytes(b"fake provider")

    def tearDown(self):
        self.temporary.cleanup()

    def run_script(self, scenario="clean", extra_env=None):
        outdir = self.directory / "out"
        env = dict(os.environ)
        env.update({
            "KEYOPS_SL_SELFTEST_NO_PRIV": "1",
            "KEYOPS_SL_SELFTEST_SIGNER_BIN": str(self.fakes / "signer"),
            "KEYOPS_SL_SELFTEST_KEYGEN_BIN": str(self.fakes / "keygen"),
            "KEYOPS_SL_SELFTEST_GATED_BIN": str(self.fakes / "gated"),
            "KEYOPS_SL_SELFTEST_SCENARIO": scenario,
            "FAKE_SIGNER": str(self.fakes / "signer"),
            "FAKE_PROVIDER": str(self.provider),
            "FAKE_OBSERVE_S": "2",
            "MODULE": str(self.provider),
            "SETTLE_S": "0",
            "DURATION": "12",
            "N_CALLERS": "3",
            "TMPDIR": str(self.directory),
        })
        env.update(extra_env or {})
        proc = subprocess.run(
            ["sh", str(SCRIPT), str(self.fakes / "observer"), str(outdir)],
            capture_output=True, text=True, timeout=300, env=env)
        rows = []
        results = outdir / "results.jsonl"
        if results.exists():
            rows = [json.loads(line) for line in
                    results.read_text().splitlines()]
        return proc, outdir, {row["cell"]: row for row in rows}

    def test_all_pass(self):
        proc, outdir, rows = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertEqual(set(rows), {"shortlived-shaped", "shortlived-counted"})
        self.assertEqual((rows["shortlived-shaped"]["pass"],
                          rows["shortlived-shaped"]["qualification"]),
                         (True, "qualified"))
        self.assertEqual((rows["shortlived-counted"]["pass"],
                          rows["shortlived-counted"]["qualification"]),
                         (True, "qualified"))
        self.assertIn("E1=1", rows["shortlived-shaped"]["detail"])
        self.assertIn("E2=1", rows["shortlived-shaped"]["detail"])
        self.assertIn("G1=1 in [1, 1]", rows["shortlived-counted"]["detail"])
        self.assertTrue((outdir / "out.json").exists())
        self.assertTrue((outdir / "signers.log").exists())

    def test_no_miss_passes_shaped_when_all_rowed(self):
        # No miss is required: a future admission fix that rows every
        # short-lived caller passes the shaped row.
        proc, outdir, rows = self.run_script("no-miss")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertEqual((rows["shortlived-shaped"]["pass"],
                          rows["shortlived-shaped"]["qualification"]),
                         (True, "qualified"))
        self.assertEqual(rows["shortlived-counted"]["qualification"],
                         "qualified")

    def test_unaccounted_fails_shaped(self):
        proc, outdir, rows = self.run_script("unaccounted")
        self.assertEqual(proc.returncode, 1)
        row = rows["shortlived-shaped"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("neither shown nor counted", row["detail"])
        self.assertIn("c0", row["detail"])
        self.assertEqual(rows["shortlived-counted"]["qualification"],
                         "qualified")

    def test_refused_split_passes(self):
        proc, outdir, rows = self.run_script("refused-split")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertEqual((rows["shortlived-shaped"]["pass"],
                          rows["shortlived-shaped"]["qualification"]),
                         (True, "qualified"))
        self.assertEqual((rows["shortlived-counted"]["pass"],
                          rows["shortlived-counted"]["qualification"]),
                         (True, "qualified"))
        self.assertIn("G1+G3=2 in [2, 2]",
                      rows["shortlived-counted"]["detail"])

    def test_undercount_fails(self):
        proc, outdir, rows = self.run_script("undercount")
        self.assertEqual(proc.returncode, 1)
        row = rows["shortlived-counted"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("below fixture", row["detail"])

    def test_ambient_headroom_passes(self):
        proc, outdir, rows = self.run_script("ambient")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertEqual(rows["shortlived-counted"]["qualification"],
                         "qualified")
        self.assertIn("G1=2 in [1, 2]", rows["shortlived-counted"]["detail"])

    def test_overcount_fails(self):
        proc, outdir, rows = self.run_script("overcount")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("above fixture+ambient",
                      rows["shortlived-counted"]["detail"])

    def test_suppression_fails_shaped(self):
        proc, outdir, rows = self.run_script("suppressed")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("suppression active",
                      rows["shortlived-shaped"]["detail"])

    def test_corrupt_observer_doc_is_failed_rows(self):
        proc, outdir, rows = self.run_script("garbage-doc")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(set(rows), {"shortlived-shaped", "shortlived-counted"})
        self.assertIn("missing or unparsable",
                      rows["shortlived-shaped"]["detail"])
        self.assertIn("missing or unparsable",
                      rows["shortlived-counted"]["detail"])

    def test_signer_failure_fails_shaped(self):
        proc, outdir, rows = self.run_script(
            extra_env={"FAKE_SIGN_EXIT": "1"})
        self.assertEqual(proc.returncode, 1)
        self.assertIn("signer failure", rows["shortlived-shaped"]["detail"])

    def test_observer_exit_fails_shaped_only(self):
        proc, outdir, rows = self.run_script(
            extra_env={"FAKE_OBS_EXIT": "3"})
        self.assertEqual(proc.returncode, 1)
        self.assertIn("observer exit 3", rows["shortlived-shaped"]["detail"])
        self.assertEqual(rows["shortlived-counted"]["qualification"],
                         "qualified")

    def test_sudo_preserves_token_conf(self):
        text = SCRIPT.read_text()
        self.assertIn('SUDO="sudo -n --preserve-env=SOFTHSM2_CONF"', text)

    def test_missing_module_is_77(self):
        outdir = self.directory / "out77"
        env = dict(os.environ, KEYOPS_SL_SELFTEST_NO_PRIV="1",
                   MODULE="/nonexistent-provider.so",
                   TMPDIR=str(self.directory))
        proc = subprocess.run(
            ["sh", str(SCRIPT), str(self.fakes / "observer"), str(outdir)],
            capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(proc.returncode, 77)

    def test_usage_errors(self):
        proc = subprocess.run(["sh", str(SCRIPT)],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        outdir = self.directory / "outbad"
        env = dict(os.environ, KEYOPS_SL_SELFTEST_NO_PRIV="1", DURATION="0",
                   TMPDIR=str(self.directory))
        proc = subprocess.run(
            ["sh", str(SCRIPT), str(self.fakes / "observer"), str(outdir)],
            capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("positive integer", proc.stderr)

    def test_default_paths_exist(self):
        for rel in ("tests/fixtures/shortlived-sign/shortlived-sign.c",
                    "tests/fixtures/shortlived-sign/shortlived-keygen.c",
                    "tests/fixtures/public-cli/gated.c",
                    "scripts/ci/key_operations_shortlived_checks.py"):
            self.assertTrue((ROOT / rel).exists(), rel)


class CheckHelperTests(unittest.TestCase):
    def doc(self, callers=(), edges=(), instances=(), sedges=(), gaps=(),
            suppressed=0, provider="/p/provider.so"):
        return {
            "callers": list(callers), "edges": list(edges),
            "instances": list(instances), "semantic_edges": list(sedges),
            "modules": [{"id": "m0", "paths": [provider]}],
            "gaps": list(gaps), "gaps_suppressed": suppressed}

    def caller(self, cid, exe, retired=True):
        return {"id": cid, "retired": retired,
                "image": {"exe": {"path": exe}}}

    def test_gap_count(self):
        doc = self.doc(gaps=[
            {"subject": "callers never admitted",
             "reason": "12 caller(s) with edges"},
            {"subject": "admitted callers with no joined calls",
             "reason": "3 admitted caller(s) exited"}])
        self.assertEqual(checks.gap_count(doc, checks.NEVER_ADMITTED_SUBJECT),
                         12)
        self.assertEqual(checks.gap_count(doc, checks.WITHOUT_JOINS_SUBJECT),
                         3)
        self.assertIsNone(checks.gap_count(self.doc(), "nope"))
        self.assertIsNone(checks.gap_count({}, checks.NEVER_ADMITTED_SUBJECT))
        self.assertIsNone(checks.gap_count(
            self.doc(gaps=[{"subject": "callers never admitted",
                            "reason": "many callers"}]),
            checks.NEVER_ADMITTED_SUBJECT))

    def test_expectations_partition(self):
        # c0: edged, uninstanced -> E1. c1: instanced, no joins -> E2.
        # c2: instanced with joins -> contributes. c3: ambient E1
        # headroom. c4: live, excluded everywhere.
        doc = self.doc(
            callers=(self.caller("c0", "/f/signer"),
                     self.caller("c1", "/f/signer"),
                     self.caller("c2", "/f/signer"),
                     self.caller("c3", "/usr/bin/other"),
                     self.caller("c4", "/f/signer", retired=False)),
            edges=({"caller": "c0", "module": "m0"},
                   {"caller": "c1", "module": "m0"},
                   {"caller": "c2", "module": "m0"},
                   {"caller": "c3", "module": "m0"}),
            instances=({"caller": "c1", "module": "m0"},
                       {"caller": "c2", "module": "m0"}),
            sedges=({"caller": "c1", "module": "m0",
                     "api_returns": {"count": None}},
                    {"caller": "c2", "module": "m0",
                     "api_returns": {"count": 2}}),
            gaps=({"subject": "callers never admitted",
                   "reason": "1 caller(s) x"},
                  {"subject": "admitted callers with no joined calls",
                   "reason": "1 admitted caller(s) y"}))
        exp = checks.expectations(doc, "/f/signer", "/p/provider.so")
        self.assertEqual(
            (exp["D"], exp["D_retired"], exp["E1"], exp["E2"],
             exp["A1"], exp["A2"], exp["G1"], exp["G2"]),
            (4, 3, 1, 1, 1, 0, 1, 1))

    def test_expectations_rejects_bad_docs(self):
        bad_suppressed = self.doc()
        bad_suppressed["gaps_suppressed"] = "many"
        bad_callers = self.doc()
        bad_callers["callers"] = None
        for bad in (None, {}, {"callers": []},
                    bad_callers, bad_suppressed):
            with self.assertRaises(ValueError, msg=repr(bad)[:60]):
                checks.expectations(bad, "/f/signer", "/p/provider.so")

    def test_shaped(self):
        base = {"D": 2, "D_retired": 2, "E1": 1, "E2": 1,
                "A1": 0, "A2": 0, "G1": 1, "G2": 1, "suppressed": 0}
        ok, detail = checks.check_shaped(dict(base))
        self.assertTrue(ok, detail)
        ok, detail = checks.check_shaped({**base, "D": 0})
        self.assertFalse(ok)
        self.assertIn("no fixture caller records", detail)
        ok, detail = checks.check_shaped({**base, "D_retired": 1})
        self.assertFalse(ok)
        self.assertIn("1/2 retired", detail)
        # No miss is required: every caller rowed is the admission-fixed
        # shape, and it passes.
        ok, detail = checks.check_shaped({**base, "E1": 0, "E2": 0})
        self.assertTrue(ok, detail)
        ok, detail = checks.check_shaped({**base, "suppressed": 5})
        self.assertFalse(ok)
        self.assertIn("suppression active", detail)
        ok, detail = checks.check_shaped(
            {**base, "E1": 0, "E2": 0, "unaccounted": ["c7"]})
        self.assertFalse(ok)
        self.assertIn("neither shown nor counted", detail)
        self.assertIn("c7", detail)

    def test_counted_bounds(self):
        base = {"D": 2, "D_retired": 2, "E1": 1, "E2": 1,
                "A1": 1, "A2": 0, "G1": 2, "G2": 1, "suppressed": 0}
        ok, detail = checks.check_counted(dict(base))
        self.assertTrue(ok, detail)
        ok, _ = checks.check_counted({**base, "G1": 1})
        self.assertTrue(ok)
        ok, detail = checks.check_counted({**base, "G1": 0})
        self.assertFalse(ok)
        self.assertIn("below fixture", detail)
        ok, detail = checks.check_counted({**base, "G1": 3})
        self.assertFalse(ok)
        self.assertIn("above fixture+ambient", detail)
        ok, _ = checks.check_counted({**base, "G1": None, "E1": 0, "A1": 0})
        self.assertTrue(ok)

    def test_counted_refused_union(self):
        # The never-admitted and refused gaps partition the
        # edged-but-uninstanced callers, so their union conserves E1.
        base = {"D": 2, "D_retired": 2, "E1": 2, "E2": 0,
                "A1": 0, "A2": 0, "G1": 1, "G2": None, "G3": 1,
                "suppressed": 0}
        ok, detail = checks.check_counted(dict(base))
        self.assertTrue(ok, detail)
        self.assertIn("G1+G3=2 in [2, 2]", detail)
        ok, _ = checks.check_counted({**base, "G1": 0, "G3": 2})
        self.assertTrue(ok)
        ok, detail = checks.check_counted({**base, "G1": 0, "G3": 0})
        self.assertFalse(ok)
        self.assertIn("below fixture", detail)
        ok, detail = checks.check_counted({**base, "G1": 2, "G3": 1})
        self.assertFalse(ok)
        self.assertIn("above fixture+ambient", detail)

    def test_expectations_unaccounted_and_refused(self):
        # c0: edged, uninstanced -> E1. c1: retired fixture with no
        # edge and no joins -> unaccounted. The refused gap reads G3.
        doc = self.doc(
            callers=(self.caller("c0", "/f/signer"),
                     self.caller("c1", "/f/signer")),
            edges=({"caller": "c0", "module": "m0"},),
            gaps=({"subject": "callers refused admission",
                   "reason": "1 caller(s) were refused"},))
        exp = checks.expectations(doc, "/f/signer", "/p/provider.so")
        self.assertEqual(
            (exp["D"], exp["D_retired"], exp["E1"], exp["E2"],
             exp["G1"], exp["G3"], exp["unaccounted"]),
            (2, 2, 1, 0, None, 1, ["c1"]))


if __name__ == "__main__":
    unittest.main()
