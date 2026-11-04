# SPDX-License-Identifier: GPL-3.0-or-later
"""SoftHSM 2.7 table-shape seams, unprivileged.

Pins what scripts/ci/legacy32-shape.sh and the qualify-public-cli.sh cell
filter it relies on must do without privileges:

- the --shape-only gates: the positive plus one failing variant per
  reachable gate (version, slot count, shape words, export count,
  non-C_ exports), each asserting the gate it must fail at, so a deleted
  or weakened gate turns its test red;
- the P11SCOPE_PUBLIC_CLI_CELLS validation: unknown cells and control-mode
  combinations fail closed before any privileged setup;
- the LEGACY32_QUALIFY stub seam: it never bypasses the root requirement
  and --shape-only ignores it;
- the tests-only-host seams: LEGACY32_PREBUILT_SO/_PROBE skip the cc
  builds but still run every gate, and LEGACY32_STOCK_MODULE selects
  the stock control provider (default: system selection).

Two shape words (GATED6, GETTER_SLOT) have no failing variant by
construction: any violation of either also violates an earlier gate, so a
variant would fail before reaching them. The nm-level C_GetInterface
refutation is likewise redundant with the INTERFACES word (a symbol
visible to nm -D resolves via dlsym). The positive pins all three words.

Privileged behavior (subset campaigns, wrap/flip exit codes, the
stock-system control) is exercised by authorized live runs, not here,
except for the stock-module plumbing which is proven here with a fake
root (PATH-local `id`) plus the qualify stub. The qualify gated/mt
prebuilt pair (P11SCOPE_QUALIFY_GATED_BIN/_MT_BIN) fails closed here
only for the missing/singleton cases; its positive copy path is proven
by the same privileged live runs that use it.
Run: python3 -I tests/python/test_legacy32_shape.py -v
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEGACY32 = ROOT / "scripts/ci/legacy32-shape.sh"
QUALIFY = ROOT / "scripts/qualify-public-cli.sh"
TIMEOUT = 600
FOUR_KEYS = {"cell", "pass", "detail", "qualification"}


def run_shape(out, *, cflags=None, env_extra=None):
    env = dict(os.environ)
    if cflags is not None:
        env["LEGACY32_CFLAGS"] = cflags
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(LEGACY32), "--shape-only", str(out)],
        env=env, capture_output=True, text=True, cwd=ROOT, timeout=TIMEOUT,
    )


def read_rows(out):
    rows = []
    for line in (out / "results.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def run_qualify(args, *, cells=None, env_extra=None, timeout=TIMEOUT):
    env = dict(os.environ)
    if cells is not None:
        env["P11SCOPE_PUBLIC_CLI_CELLS"] = cells
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(QUALIFY), *args],
        env=env, capture_output=True, text=True, cwd=ROOT, timeout=timeout,
    )


def build_prebuilt_pair(dest, *, cflags=""):
    """Build a legacy32.so + shape-probe pair with the script's flags."""
    fixsrc = ROOT / "tests/fixtures/legacy32-provider"
    so = dest / "legacy32.so"
    probe = dest / "shape-probe"
    cc_base = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    # shellcheck-equivalent: split caller cflags on whitespace (tests only).
    extra = cflags.split() if cflags else []
    so_cmd = (["cc", "-std=c11", "-O2", "-fPIC", "-fno-ipa-icf",
               "-fno-merge-constants", "-Wall", "-Wextra", "-Werror",
               "-shared", "-Wl,-z,defs"] + extra +
              ["-o", str(so), str(fixsrc / "legacy32.c")])
    probe_cmd = cc_base + ["-o", str(probe),
                           str(fixsrc / "shape-probe.c"), "-ldl"]
    subprocess.run(so_cmd, check=True, capture_output=True, text=True,
                   cwd=ROOT, timeout=TIMEOUT)
    subprocess.run(probe_cmd, check=True, capture_output=True, text=True,
                   cwd=ROOT, timeout=TIMEOUT)
    return so, probe


def write_fake_id(bin_dir):
    """PATH-local `id` that reports uid 0; delegates everything else."""
    fake = bin_dir / "id"
    fake.write_text('#!/bin/bash\n'
                    'if [ "${1:-}" = "-u" ]; then echo 0; '
                    'else exec /usr/bin/id "$@"; fi\n',
                    encoding="utf-8")
    fake.chmod(0o755)
    return fake


def write_stock_stub(stub_path, log_path):
    """Qualify stub: logs MODULE, writes fail rows for legacy32, pass for stock."""
    stub_path.write_text(
        '#!/bin/bash\nset -u\ndest=$2\n'
        'if [ -z "${MODULE+x}" ]; then mod="UNSET"; else mod="$MODULE"; fi\n'
        f'echo "$dest $mod" >> "{log_path}"\n'
        'mkdir -p "$dest"\n'
        'if [ "${dest##*/}" = legacy32 ]; then p=0; q=failed; d="stub legacy32 fail"; '
        'else p=1; q=qualified; d="stub stock pass"; fi\n'
        'python3 - "$dest/results.jsonl" "$p" "$q" "$d" <<\'PY\'\n'
        'import json,sys\n'
        'p = sys.argv[2] == "1"\n'
        'rows = [{"cell": c, "pass": p, "detail": sys.argv[4],\n'
        '         "qualification": sys.argv[3]} for c in ("profile-pid", "system")]\n'
        'open(sys.argv[1], "w").write("\\n".join(json.dumps(r) for r in rows) + "\\n")\n'
        'PY\n',
        encoding="utf-8")
    stub_path.chmod(0o755)


class ShapeOnlyGateTests(unittest.TestCase):
    def assert_shape_fails_at(self, cflags, env_extra, gate):
        with tempfile.TemporaryDirectory(prefix="legacy32-") as tmp:
            out = Path(tmp) / "out"
            proc = run_shape(out, cflags=cflags, env_extra=env_extra)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(len(rows), 1, rows)
            row = rows[0]
            self.assertEqual(set(row), FOUR_KEYS, row)
            self.assertEqual(row["cell"], "legacy32-shape", row)
            self.assertFalse(row["pass"], row)
            self.assertEqual(row["qualification"], "failed", row)
            self.assertIn(gate, row["detail"], row)

    def test_the_documented_shape_passes(self):
        with tempfile.TemporaryDirectory(prefix="legacy32-") as tmp:
            out = Path(tmp) / "out"
            proc = run_shape(out)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(len(rows), 1, rows)
            row = rows[0]
            self.assertEqual(set(row), FOUR_KEYS, row)
            self.assertEqual(row["cell"], "legacy32-shape", row)
            self.assertTrue(row["pass"], row)
            self.assertEqual(row["qualification"], "qualified", row)
            for fact in ("VERSION 3 2", "NONNULL68 68", "DISTINCT68 1",
                         "SLOT68 0x1", "GATED6 1", "GETTER_SLOT 1",
                         "INTERFACES 0"):
                self.assertIn(fact, proc.stdout, proc.stdout)

    def test_the_minor_zero_variant_fails_at_the_version_gate(self):
        self.assert_shape_fails_at("-DLEGACY32_MINOR=0", None, "version gate: want VERSION 3 2")

    def test_a_foreign_slot_count_fails_at_the_slot_count_gate(self):
        self.assert_shape_fails_at(None, {"LEGACY32_EXPECT_SLOTS": "92"}, "slot-count gate")

    def test_a_null_slot_fails_at_the_nonnull_gate(self):
        self.assert_shape_fails_at("-DLEGACY32_NULL_SLOT66", None, "want NONNULL68 68")

    def test_an_aliased_slot_fails_at_the_distinct_gate(self):
        self.assert_shape_fails_at("-DLEGACY32_ALIAS_SLOT66", None, "want DISTINCT68 1")

    def test_a_foreign_tail_fails_at_the_slot68_word(self):
        self.assert_shape_fails_at(None, {"LEGACY32_EXPECT_TAIL": "0x2"}, "want SLOT68 0x2")

    def test_an_interface_export_fails_at_the_interfaces_word(self):
        self.assert_shape_fails_at("-DLEGACY32_EXPORT_INTERFACE", None, "want INTERFACES 0")

    def test_a_hidden_slot_fails_at_the_export_count_gate(self):
        self.assert_shape_fails_at(
            "-DLEGACY32_HIDE_SLOT67", None, "want exactly 68 defined C_ exports")

    def test_an_extra_export_fails_at_the_non_c_export_gate(self):
        self.assert_shape_fails_at(
            "-DLEGACY32_EXTRA_EXPORT", None, "non-C_ text export present")

    def test_shape_only_usage_requires_an_outdir(self):
        proc = subprocess.run(
            ["bash", str(LEGACY32), "--shape-only"],
            capture_output=True, text=True, cwd=ROOT, timeout=TIMEOUT,
        )
        self.assertEqual(proc.returncode, 64, proc.stderr)

    def test_shape_only_ignores_the_qualify_stub_seam(self):
        with tempfile.TemporaryDirectory(prefix="legacy32-") as tmp:
            out = Path(tmp) / "out"
            proc = run_shape(out, env_extra={"LEGACY32_QUALIFY": "/nonexistent-stub"})
            self.assertEqual(proc.returncode, 0, proc.stderr)


class CellFilterValidationTests(unittest.TestCase):
    def test_an_unknown_cell_fails_closed(self):
        observer = ROOT / "nonexistent-observer-for-filter-test"
        self.assertFalse(observer.exists())
        with tempfile.TemporaryDirectory(prefix="filter-") as tmp:
            for cells, offender in (("nope", "nope"),
                                    ("profile-pid nope", "nope"),
                                    ("names-pid", "names-pid"),
                                    ("system names-pid", "names-pid")):
                with self.subTest(cells=cells):
                    proc = run_qualify([str(observer), tmp], cells=cells)
                    self.assertEqual(proc.returncode, 64, proc.stderr)
                    self.assertIn("unsupported subset cell", proc.stderr)
                    self.assertIn(offender, proc.stderr)
                    self.assertIn("profile-pid", proc.stderr)

    def test_the_filter_cannot_combine_with_a_control_mode(self):
        with tempfile.TemporaryDirectory(prefix="filter-") as tmp:
            proc = run_qualify(
                ["--control-gated", str(ROOT / "no-observer"), tmp, str(ROOT / "no-fixture")],
                cells="profile-pid",
            )
            self.assertEqual(proc.returncode, 64, proc.stderr)
            self.assertIn("cannot be combined", proc.stderr)

    def test_supported_names_pass_validation(self):
        # A nonexistent observer fails after validation, so reaching its
        # error proves the names were accepted; no campaign can start.
        observer = ROOT / "nonexistent-observer-for-filter-test"
        self.assertFalse(observer.exists())
        with tempfile.TemporaryDirectory(prefix="filter-") as tmp:
            for cells in ("profile-pid system",
                          "profile-pid metrics-pid trace-pid mt-exact system"):
                with self.subTest(cells=cells):
                    proc = run_qualify([str(observer), tmp], cells=cells)
                    self.assertEqual(proc.returncode, 64, proc.stderr)
                    self.assertNotIn("unsupported subset cell", proc.stderr)
                    self.assertNotIn("cannot be combined", proc.stderr)


class StubSeamTests(unittest.TestCase):
    def test_the_stub_seam_never_bypasses_the_root_gate(self):
        self.assertNotEqual(os.geteuid(), 0, "this validation must run unprivileged")
        with tempfile.TemporaryDirectory(prefix="seam-") as tmp:
            env = dict(os.environ, LEGACY32_QUALIFY=str(ROOT / "no-such-qualify"))
            proc = subprocess.run(
                ["bash", str(LEGACY32), "/bin/true", tmp],
                env=env, capture_output=True, text=True, cwd=ROOT, timeout=TIMEOUT,
            )
            self.assertEqual(proc.returncode, 64, proc.stderr)
            self.assertIn("must run as root", proc.stderr)


class PrebuiltSeamTests(unittest.TestCase):
    def test_a_prebuilt_pair_passes_shape_only(self):
        with tempfile.TemporaryDirectory(prefix="prebuilt-") as tmp:
            tmp = Path(tmp)
            (tmp / "pb").mkdir(parents=True, exist_ok=True)
            so, probe = build_prebuilt_pair(tmp / "pb")
            out = tmp / "out"
            proc = run_shape(out, env_extra={
                "LEGACY32_PREBUILT_SO": str(so),
                "LEGACY32_PREBUILT_PROBE": str(probe),
            })
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(len(rows), 1, rows)
            self.assertTrue(rows[0]["pass"], rows)
            self.assertEqual(rows[0]["qualification"], "qualified", rows)
            for fact in ("VERSION 3 2", "NONNULL68 68", "DISTINCT68 1"):
                self.assertIn(fact, proc.stdout, proc.stdout)

    def test_the_prebuilt_so_is_used_not_rebuilt(self):
        # A {3,0} prebuilt must fail the version gate; a fresh build
        # would be {3,2} and pass, so failure proves the prebuilt was used.
        with tempfile.TemporaryDirectory(prefix="prebuilt-") as tmp:
            tmp = Path(tmp)
            (tmp / "pb").mkdir(parents=True, exist_ok=True)
            so, probe = build_prebuilt_pair(tmp / "pb", cflags="-DLEGACY32_MINOR=0")
            out = tmp / "out"
            proc = run_shape(out, env_extra={
                "LEGACY32_PREBUILT_SO": str(so),
                "LEGACY32_PREBUILT_PROBE": str(probe),
            })
            self.assertEqual(proc.returncode, 2, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(len(rows), 1, rows)
            self.assertIn("version gate", rows[0]["detail"], rows)

    def test_prebuilt_gates_still_run_on_a_bad_pair(self):
        # A NULL-slot prebuilt must fail at NONNULL, proving the oracle
        # still judges prebuilt bytes instead of trusting them.
        with tempfile.TemporaryDirectory(prefix="prebuilt-") as tmp:
            tmp = Path(tmp)
            (tmp / "pb").mkdir(parents=True, exist_ok=True)
            so, probe = build_prebuilt_pair(
                tmp / "pb", cflags="-DLEGACY32_NULL_SLOT66")
            out = tmp / "out"
            proc = run_shape(out, env_extra={
                "LEGACY32_PREBUILT_SO": str(so),
                "LEGACY32_PREBUILT_PROBE": str(probe),
            })
            self.assertEqual(proc.returncode, 2, proc.stderr)
            rows = read_rows(out)
            self.assertIn("want NONNULL68 68", rows[0]["detail"], rows)

    def test_a_singleton_prebuilt_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="prebuilt-") as tmp:
            tmp = Path(tmp)
            (tmp / "pb").mkdir(parents=True, exist_ok=True)
            so, probe = build_prebuilt_pair(tmp / "pb")
            for env_extra in ({"LEGACY32_PREBUILT_SO": str(so)},
                              {"LEGACY32_PREBUILT_PROBE": str(probe)}):
                with self.subTest(env_extra=env_extra):
                    out = tmp / ("out-%s" % len(os.listdir(tmp)))
                    proc = run_shape(out, env_extra=env_extra)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    rows = read_rows(out)
                    self.assertEqual(len(rows), 1, rows)
                    self.assertIn("both", rows[0]["detail"], rows)

    def test_missing_prebuilt_files_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="prebuilt-") as tmp:
            out = Path(tmp) / "out"
            proc = run_shape(out, env_extra={
                "LEGACY32_PREBUILT_SO": "/nonexistent-prebuilt.so",
                "LEGACY32_PREBUILT_PROBE": "/nonexistent-probe",
            })
            self.assertEqual(proc.returncode, 2, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(len(rows), 1, rows)
            self.assertIn("missing or unusable", rows[0]["detail"], rows)

    def test_prebuilt_rejects_build_flags(self):
        with tempfile.TemporaryDirectory(prefix="prebuilt-") as tmp:
            tmp = Path(tmp)
            (tmp / "pb").mkdir(parents=True, exist_ok=True)
            so, probe = build_prebuilt_pair(tmp / "pb")
            base = {"LEGACY32_PREBUILT_SO": str(so),
                    "LEGACY32_PREBUILT_PROBE": str(probe)}
            out = tmp / "out-flags"
            proc = run_shape(out, cflags="-DLEGACY32_MINOR=0",
                             env_extra=dict(base))
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("build flags", read_rows(out)[0]["detail"])
            out2 = tmp / "out-args"
            env = dict(os.environ, **base)
            proc2 = subprocess.run(
                ["bash", str(LEGACY32), "--shape-only", str(out2),
                 "-DLEGACY32_MINOR=0"],
                env=env, capture_output=True, text=True, cwd=ROOT,
                timeout=TIMEOUT)
            self.assertEqual(proc2.returncode, 2, proc2.stderr)
            self.assertIn("build flags", read_rows(out2)[0]["detail"])


class StockModuleSeamTests(unittest.TestCase):
    def run_with_stub(self, tmp, *, stock_module=None):
        tmp = Path(tmp)
        bindir = tmp / "bin"
        bindir.mkdir(parents=True, exist_ok=True)
        write_fake_id(bindir)
        (tmp / "pb").mkdir(parents=True, exist_ok=True)
        so, probe = build_prebuilt_pair(tmp / "pb")
        stub = tmp / "stub.sh"
        log = tmp / "modules.log"
        write_stock_stub(stub, log)
        out = tmp / "out"
        env = dict(os.environ)
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        env["LEGACY32_QUALIFY"] = str(stub)
        env["STUB"] = str(stub)
        env["LEGACY32_PREBUILT_SO"] = str(so)
        env["LEGACY32_PREBUILT_PROBE"] = str(probe)
        if stock_module is not None:
            env["LEGACY32_STOCK_MODULE"] = stock_module
        else:
            env.pop("LEGACY32_STOCK_MODULE", None)
            env.pop("MODULE", None)
        proc = subprocess.run(
            ["bash", str(LEGACY32), "/bin/true", str(out)],
            env=env, capture_output=True, text=True, cwd=ROOT,
            timeout=TIMEOUT)
        return proc, out, log

    def test_the_default_stock_leg_unsets_module(self):
        self.assertNotEqual(os.geteuid(), 0, "fake-root test must run unprivileged")
        with tempfile.TemporaryDirectory(prefix="stock-") as tmp:
            proc, out, log = self.run_with_stub(tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(len(rows), 4, rows)
            logged = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(logged), 2, logged)
            by_dest = {Path(line.split()[0]).name: line.split(None, 1)[1]
                       for line in logged}
            self.assertIn("legacy32", by_dest)
            self.assertTrue(by_dest["legacy32"].endswith("legacy32.so"),
                            by_dest)
            self.assertEqual(by_dest.get("stock"), "UNSET", by_dest)

    def test_a_stock_module_override_reaches_the_stock_leg_only(self):
        self.assertNotEqual(os.geteuid(), 0, "fake-root test must run unprivileged")
        with tempfile.TemporaryDirectory(prefix="stock-") as tmp:
            fake_stock = str(Path(tmp) / "fake-stock.so")
            Path(fake_stock).write_text("fake", encoding="utf-8")
            proc, out, log = self.run_with_stub(tmp, stock_module=fake_stock)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(
                sorted(r["cell"] for r in rows),
                ["legacy32-pid", "legacy32-system", "stock-pid", "stock-system"],
                rows)
            logged = log.read_text(encoding="utf-8").splitlines()
            by_dest = {Path(line.split()[0]).name: line.split(None, 1)[1]
                       for line in logged}
            self.assertTrue(by_dest["legacy32"].endswith("legacy32.so"),
                            by_dest)
            self.assertEqual(by_dest.get("stock"), fake_stock, by_dest)


class QualifyPrebuiltValidationTests(unittest.TestCase):
    def test_missing_or_singleton_prebuilt_fails_before_setup(self):
        self.assertNotEqual(os.geteuid(), 0, "fake-root test must run unprivileged")
        with tempfile.TemporaryDirectory(prefix="qpre-") as tmp:
            tmp = Path(tmp)
            bindir = tmp / "bin"
            bindir.mkdir(parents=True, exist_ok=True)
            write_fake_id(bindir)
            (tmp / "pb").mkdir(parents=True, exist_ok=True)
            so, _ = build_prebuilt_pair(tmp / "pb")
            cases = ({"P11SCOPE_QUALIFY_GATED_BIN": "/nonexistent-gated",
                      "P11SCOPE_QUALIFY_MT_BIN": "/nonexistent-mt"},
                     {"P11SCOPE_QUALIFY_GATED_BIN": str(so)},
                     {"P11SCOPE_QUALIFY_MT_BIN": str(so)})
            for i, env_extra in enumerate(cases):
                with self.subTest(env_extra=env_extra):
                    env = dict(os.environ, MODULE=str(so))
                    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
                    env.update(env_extra)
                    try:
                        proc = subprocess.run(
                            ["bash", str(QUALIFY), "/bin/true",
                             str(tmp / f"out-{i}")],
                            env=env, capture_output=True, text=True,
                            cwd=ROOT, timeout=30)
                    except subprocess.TimeoutExpired as exc:
                        self.fail(f"prebuilt validation timed out (built instead of failing fast): {exc}")
                    self.assertEqual(proc.returncode, 65, proc.stderr)


if __name__ == "__main__":
    unittest.main()
