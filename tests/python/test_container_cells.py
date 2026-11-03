#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Container cells entry point (S8): harness errors, exit mapping, disclosure.

Runs scripts/ci/container-cells.sh against stub tools and stub cell scripts
in a fake repo root: no docker, sudo, SoftHSM, BTF or privileged run needed.
Proves the entry point maps cell exits to results.jsonl rows and terminal
codes, passes P11SCOPE through, and asserts the R-41 copy-up disclosure
(KNOWN_ISSUE) rather than its absence.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "scripts/ci/container-cells.sh"

PIDNS_CELLS = ("host-pid", "foreign-proc", "foreign-proc-system", "nested-pid",
               "nested-run", "nested-inventory-pid", "nested-doctor-pid",
               "nested-cgroup", "nested-trace")


def write_executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


class ContainerCellsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope-container-cells-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        # Fake repo root with a copy of the entry point and stub cells.
        self.fake = self.base / "fake"
        (self.fake / "scripts/ci").mkdir(parents=True)
        (self.fake / "scripts/matrix").mkdir(parents=True)
        shutil.copy2(ENTRY, self.fake / "scripts/ci/container-cells.sh")
        self.entry = self.fake / "scripts/ci/container-cells.sh"
        # Stub tools.
        self.tools = self.base / "tools"
        self.tools.mkdir()
        write_executable(self.tools / "docker", "#!/bin/sh\nexit 0\n")
        write_executable(self.tools / "sudo",
                         '#!/bin/sh\n[ "${1-}" = "-n" ] && shift\nexec "$@"\n')
        for name in ("gcc", "softhsm2-util", "systemd-run", "capsh", "setpriv",
                     "unshare", "nsenter", "gnutimeout"):
            write_executable(self.tools / name, "#!/bin/sh\nexit 0\n")
        # Preflight hook files (must exist).
        self.module = self.base / "libsofthsm2.so"
        self.module.write_text("stub")
        self.btf = self.base / "vmlinux"
        self.btf.write_text("BTF")
        self.cgroup = self.base / "cgroup.controllers"
        self.cgroup.write_text("pids")
        # Fake observer and discover binaries.
        self.observer = self.base / "p11scope"
        write_executable(self.observer, "#!/bin/sh\nexit 0\n")
        self.discover = self.base / "p11scope-discover"
        write_executable(self.discover, "#!/bin/sh\nexit 0\n")
        self.outdir = self.base / "out"
        self.env = os.environ.copy()
        self.env.update({
            "PATH": f"{self.tools}:/usr/bin:/bin",
            "P11SCOPE_CONTAINER_CELLS_MODULE": str(self.module),
            "P11SCOPE_CONTAINER_CELLS_BTF": str(self.btf),
            "P11SCOPE_CONTAINER_CELLS_CGROUP": str(self.cgroup),
        })
        self.calls = self.base / "calls.jsonl"

    def stub_cells(self, docker_rc=0, shared_rc=0, pidns_rc=0, pidns_fail=(),
                   fork_rc=0, d1_rc=0, d1_disclosure=True):
        """Stub cell scripts; pidns_fail names failing subcells."""
        calls = str(self.calls)
        for name, rc in (("verify-docker.sh", docker_rc),
                         ("verify-shared-layer.sh", shared_rc),
                         ("verify-fork-scope.sh", fork_rc)):
            write_executable(
                self.fake / f"scripts/matrix/{name}",
                f'#!/bin/sh\necho "{name} P11SCOPE_BIN=$P11SCOPE_BIN" >>"{calls}"\n'
                f'exit {rc}\n')
        fail = json.dumps(sorted(pidns_fail))
        write_executable(
            self.fake / "scripts/matrix/verify-pidns.sh",
            "#!/bin/sh\n"
            f'echo "verify-pidns.sh P=$1 OUT=$2" >>"{calls}"\n'
            'mkdir -p "$2"\n'
            f'python3 - "$2/results.jsonl" \'{fail}\' <<\'PY\'\n'
            "import json, sys\n"
            "failing = set(json.loads(sys.argv[2]))\n"
            "with open(sys.argv[1], 'w') as handle:\n"
            f'    for cell in {list(PIDNS_CELLS)!r}:\n'
            '        handle.write(json.dumps({"cell": cell, "pass": cell not in failing,'
            ' "detail": {}}) + "\\n")\n'
            "PY\n"
            f"exit {pidns_rc}\n")
        disclosure = ("KNOWN_ISSUE cell=D1 copy-up-stale-caller pid=102 "
                      "old_module=m7 new_module=m8\n" if d1_disclosure else
                      "no disclosure here\n")
        write_executable(
            self.fake / "scripts/docker-shared-layer-e2e.sh",
            "#!/bin/sh\n"
            f'echo "docker-shared-layer-e2e.sh $*" >>"{calls}"\n'
            'work=""; while [ "$#" -gt 0 ]; do '
            'case $1 in --work) work=$2; shift 2;; *) shift;; esac; done\n'
            'mkdir -p "$work"\n'
            f'printf %s \'{disclosure}\' >"$work/facts.log"\n'
            'printf %s \'{"ok": true}\' >"$work/oracle.json"\n'
            f'if [ "{d1_rc}" -eq 3 ]; then '
            'echo \'SUMMARY cell=D1 host=dev verdict=UNRUN reason="stubbed"\'; fi\n'
            f"exit {d1_rc}\n")

    def run_entry(self, *args, env=None):
        return subprocess.run(
            ["sh", str(self.entry), *args], env=env or self.env,
            text=True, capture_output=True, timeout=60)

    def test_usage_errors_exit_2(self):
        for args in ([], [str(self.observer)],
                     [str(self.observer), str(self.outdir), "extra"],
                     ["relative/p11scope", str(self.outdir)],
                     ["/nonexistent-p11scope", str(self.outdir)]):
            with self.subTest(args=args):
                result = self.run_entry(*args)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_missing_discover_exits_77(self):
        self.stub_cells()
        env = dict(self.env, P11SCOPE_DISCOVER_BIN="/nonexistent-discover")
        result = self.run_entry(str(self.observer), str(self.outdir), env=env)
        self.assertEqual(result.returncode, 77, result.stderr)

    def test_missing_module_hook_exits_77(self):
        self.stub_cells()
        env = dict(self.env, P11SCOPE_CONTAINER_CELLS_MODULE="/nonexistent-module")
        result = self.run_entry(str(self.observer), str(self.outdir), env=env)
        self.assertEqual(result.returncode, 77, result.stderr)

    def test_all_pass_writes_five_qualified_rows(self):
        self.stub_cells()
        result = self.run_entry(str(self.observer), str(self.outdir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [json.loads(line) for line in
                (self.outdir / "results.jsonl").read_text().splitlines()]
        self.assertEqual([row["cell"] for row in rows],
                         ["docker", "shared-layer", "pidns", "fork-scope", "d1"])
        for row in rows:
            self.assertTrue(row["pass"], row)
            self.assertEqual(row["qualification"], "qualified", row)
            self.assertTrue(row["detail"], row)
        self.assertIn("KNOWN_ISSUE", rows[-1]["detail"])
        calls = (self.calls.read_text().splitlines() if self.calls.exists()
                 else [])
        self.assertTrue(any(f"P11SCOPE_BIN={self.observer}" in call for call in calls),
                        calls)
        self.assertTrue(any("--host dev" in call and f"--observer {self.observer}" in call
                            and "--iters-a 400" in call for call in calls), calls)

    def test_cell_failure_exits_1_with_failed_row(self):
        self.stub_cells(shared_rc=1)
        result = self.run_entry(str(self.observer), str(self.outdir))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        rows = {json.loads(line)["cell"]: json.loads(line) for line in
                (self.outdir / "results.jsonl").read_text().splitlines()}
        self.assertFalse(rows["shared-layer"]["pass"])
        self.assertEqual(rows["shared-layer"]["qualification"], "failed")
        self.assertTrue(rows["docker"]["pass"])

    def test_missing_prerequisite_exits_77_when_nothing_failed(self):
        self.stub_cells(fork_rc=77)
        result = self.run_entry(str(self.observer), str(self.outdir))
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        rows = {json.loads(line)["cell"]: json.loads(line) for line in
                (self.outdir / "results.jsonl").read_text().splitlines()}
        self.assertFalse(rows["fork-scope"]["pass"])
        self.assertEqual(rows["fork-scope"]["qualification"], "nonqualifying")

    def test_failure_takes_precedence_over_missing(self):
        self.stub_cells(docker_rc=1, fork_rc=77)
        result = self.run_entry(str(self.observer), str(self.outdir))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_d1_unrun_is_nonqualifying_not_failed(self):
        self.stub_cells(d1_rc=3)
        result = self.run_entry(str(self.observer), str(self.outdir))
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        rows = {json.loads(line)["cell"]: json.loads(line) for line in
                (self.outdir / "results.jsonl").read_text().splitlines()}
        self.assertFalse(rows["d1"]["pass"])
        self.assertEqual(rows["d1"]["qualification"], "nonqualifying")
        self.assertIn("UNRUN", rows["d1"]["detail"])

    def test_d1_without_disclosure_fails(self):
        # R-41 stays disclosed: a passing D1 run without KNOWN_ISSUE fails.
        self.stub_cells(d1_disclosure=False)
        result = self.run_entry(str(self.observer), str(self.outdir))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        rows = {json.loads(line)["cell"]: json.loads(line) for line in
                (self.outdir / "results.jsonl").read_text().splitlines()}
        self.assertFalse(rows["d1"]["pass"])
        self.assertEqual(rows["d1"]["qualification"], "failed")
        self.assertIn("disclosure", rows["d1"]["detail"])

    def test_pidns_subcell_failure_fails(self):
        self.stub_cells(pidns_rc=1, pidns_fail=("nested-pid",))
        result = self.run_entry(str(self.observer), str(self.outdir))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        rows = {json.loads(line)["cell"]: json.loads(line) for line in
                (self.outdir / "results.jsonl").read_text().splitlines()}
        self.assertFalse(rows["pidns"]["pass"])
        self.assertIn("nested-pid", rows["pidns"]["detail"])

    def test_pidns_zero_exit_with_failed_subcell_fails(self):
        # Defense in depth: the entry point re-checks pidns results.jsonl.
        self.stub_cells(pidns_rc=0, pidns_fail=("host-pid",))
        result = self.run_entry(str(self.observer), str(self.outdir))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        rows = {json.loads(line)["cell"]: json.loads(line) for line in
                (self.outdir / "results.jsonl").read_text().splitlines()}
        self.assertFalse(rows["pidns"]["pass"])

    def test_documents_non_root_wiring_requirement(self):
        # Union with WP-1: run-cell-script.sh requires root, this entry point
        # requires non-root. The header must state the wiring so the porter
        # wires it directly or adds a non-root mode to the template.
        header = ENTRY.read_text(encoding="utf-8")
        self.assertIn("run-cell-script", header)
        self.assertIn("non-root", header)
        self.assertIn("direct", header)


if __name__ == "__main__":
    unittest.main()
