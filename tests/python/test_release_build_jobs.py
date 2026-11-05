#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded release jobs through the actual sealed driver and child shells."""

import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
ReleaseSealFixture = runpy.run_path(str(ROOT / "tests/fixtures/release-seal/fixture.py"))["ReleaseSealFixture"]
DriverFixture = runpy.run_path(str(ROOT / "tests/python/test_prepared_container_driver.py"))["DriverFixture"]


class ReleaseBuildJobsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope-build-jobs-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def test_release_invalid_jobs_refuse_before_receipt_or_seal(self):
        invalid = [["--jobs", value] for value in (
            "", "0", "17", "01", "-1", "+2", "2.0", " 2", "2\n", "9" * 40,
        )]
        invalid += [["--jobs"], ["--jobs", "2", "--jobs", "3"]]
        for index, options in enumerate(invalid):
            with self.subTest(options=options):
                work = self.base / str(index)
                work.mkdir(mode=0o700)
                root = work / "receipt"
                environment = {**os.environ, "TMPDIR": str(work)}
                result = subprocess.run(["/bin/sh", str(ROOT / "scripts/build-release.sh"),
                                         *options, str(root)], env=environment,
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(list(work.iterdir()), [], result.stderr)

    def test_release_selection_survives_the_actual_seal_with_both_capture_modes(self):
        for jobs, mode in (("1", "full"), ("2", "p0"), ("16", "full")):
            with self.subTest(jobs=jobs, mode=mode):
                fixture = ReleaseSealFixture(self.base / jobs)
                run = fixture.run_to_sudo_probe(arguments=[
                    "--jobs", jobs, "--capture-mode", mode, str(fixture.root),
                ])
                self.assertEqual(run.output.returncode, 77, run.diagnostic())
                self.assertEqual(run.tripped(), "sudo\n", run.diagnostic())
                self.assertEqual(run.fact("build_jobs"), jobs, run.diagnostic())
                self.assertEqual(run.fact("capture_mode"), mode, run.diagnostic())
                self.assertNotIn("CARGO_BUILD_JOBS=", run.environment_dump.read_text())
                self.assertEqual(list(fixture.seal_parent.iterdir()), [])

    def test_release_omission_records_cargo_default_and_discards_inherited_jobs(self):
        fixture = ReleaseSealFixture(self.base / "default")
        run = fixture.run_to_sudo_probe({"CARGO_BUILD_JOBS": "11", "MAKEFLAGS": "-j11"})
        self.assertEqual(run.output.returncode, 77, run.diagnostic())
        self.assertEqual(run.fact("build_jobs"), "cargo-default", run.diagnostic())
        dumped = run.environment_dump.read_text()
        self.assertNotIn("CARGO_BUILD_JOBS=", dumped)
        self.assertNotIn("MAKEFLAGS=", dumped)

    def host_probe(self, name):
        fixture = ReleaseSealFixture(self.base / name)
        driver = fixture.repo / "scripts/build-release.sh"
        module = fixture.base / "provider.so"
        module.write_bytes(b"fixture provider placeholder\n")
        driver.write_text(driver.read_text().replace(
            "MODULE=/usr/lib/softhsm/libsofthsm2.so\n", "MODULE=" + shlex.quote(str(module)) + "\n", 1))
        # The only privileged boundary is replaced with an inert success.
        (fixture.fake_bin / "sudo").write_text("#!/bin/sh\nexit 0\n")
        shutil.copy2(ROOT / "scripts/product-build.sh", fixture.repo / "scripts/product-build.sh")
        for script in ("verify-canaries.sh", "verify-attach-e2e.sh"):
            (fixture.repo / "scripts" / script).write_text(
                "#!/bin/sh\nset -eu\n. scripts/product-build.sh\n"
                'p11scope_product_build prepared --release --target-dir "$P11SCOPE_RECEIPT_WORK/probe-target"\n')
        events = fixture.base / "build-events.jsonl"
        toolchain = fixture.base / "toolchain-binary"
        probe = ROOT / "tests/fixtures/release-build-jobs/host-cargo.py"
        probe_command = " ".join(shlex.quote(str(word)) for word in (sys.executable, "-I", probe, events))
        # Preserve the existing metadata/sysroot behavior, adding only the
        # otherwise external Cargo build boundary needed by this test.
        toolchain.write_text(toolchain.read_text().replace(
            'case "$*" in\n', 'case "$*" in\n"build "*) exec ' + probe_command + ' "$@" ;;\n', 1))
        for command in (["git", "-C", str(fixture.repo), "add", "-A"],
                        ["git", "-C", str(fixture.repo), "-c", "maintenance.auto=false", "-c", "gc.auto=0",
                         "-c", "user.email=fixture@example.invalid", "-c", "user.name=fixture",
                         "commit", "--quiet", "-m", "fixture: install harmless build children"]):
            result = fixture.command(command)
            self.assertEqual(result.returncode, 0, result.stderr)
        return fixture, events

    def test_actual_host_cargo_children_observe_selected_or_default_budget(self):
        for jobs in (None, "2", "16"):
            with self.subTest(jobs=jobs):
                fixture, events = self.host_probe(jobs or "default")
                options = [] if jobs is None else ["--jobs", jobs]
                run = fixture.run_to_sudo_probe(
                    {"CARGO_BUILD_JOBS": "11", "CARGO_MAKEFLAGS": "-j11", "MAKEFLAGS": "-j11", "NUM_JOBS": "11"},
                    arguments=[*options, str(fixture.root)])
                self.assertEqual(run.output.returncode, 77, run.diagnostic())
                self.assertTrue(events.exists(), run.diagnostic())
                children = [json.loads(row) for row in events.read_text().splitlines()]
                self.assertEqual(len(children), 3, children)
                self.assertEqual([row["build_jobs"] for row in children], [jobs] * 3)
                self.assertTrue(all(row["makeflags"] is None and row["cargo_makeflags"] is None
                                    and row["num_jobs"] is None for row in children), children)
                self.assertEqual(children[-1]["argv"][-4:],
                                 ["--target", "x86_64-unknown-linux-musl", "--bin", "p11scope"])
                self.assertEqual((run.root / "status").read_text(), "77\n")

    def container_fixture(self, name):
        base = self.base / name
        base.mkdir()
        fixture = DriverFixture(base)
        child_bin = base / "container-probes"
        child_bin.mkdir()
        (child_bin / "python3").symlink_to(sys.executable)
        probe = ROOT / "tests/fixtures/prepared-container-driver/build-budget-probe.py"
        for command in ("cargo", "mkdir", "cp", "apk", "sort", "cat", "chown", "stat"):
            shutil.copy2(probe, child_bin / command)
            (child_bin / command).chmod(0o755)
        fixture.config.update(probe_build_jobs=True, probe_bin=str(child_bin))
        return fixture

    def test_release_passes_the_selected_budget_as_helper_driver_arguments(self):
        source = (ROOT / "scripts/build-release.sh").read_text()
        # Execute the actual dispatch block with only the helper process
        # stubbed. This catches losing --jobs between the two real drivers.
        start = '\necho "=== p11scope-discover: dynamic glibc + dynamic musl builds ==="\n'
        end = "\nGLIBC_DISCOVER="
        dispatch = source.split(start, 1)[1].split(end, 1)[0]
        scripts = self.base / "scripts"
        scripts.mkdir()
        (scripts / "verify-discover-containers.sh").write_text('printf "%s\\n" "$@"\n')
        for jobs in ("cargo-default", "2", "16"):
            with self.subTest(jobs=jobs):
                result = subprocess.run(["/bin/sh", "-ec",
                                         'RELEASE_BUILD_JOBS=$1; RECEIPT_ROOT=$2; DISCOVER_BASE=$2/work\n' + dispatch,
                                         "dispatch", jobs, str(self.base)], cwd=self.base,
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                selected = [] if jobs == "cargo-default" else ["--jobs", jobs]
                self.assertEqual(result.stdout.splitlines(),
                                 [*selected, "--lane14-facts", str(self.base / "artifacts/discover.facts")])

    def test_container_invalid_jobs_refuse_before_facts_work_or_resources(self):
        invalid = [["--jobs", value] for value in ("", "0", "17", "01", "-1", "+2", "two", "9" * 40)]
        invalid += [["--jobs"], ["--jobs", "2", "--jobs", "3"]]
        for index, options in enumerate(invalid):
            with self.subTest(options=options):
                fixture = self.container_fixture(str(index))
                result = fixture.run(arguments=[*options, "--lane14-facts", str(fixture.facts_path)])
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(fixture.facts_path.exists())
                self.assertFalse((fixture.work / "discover").exists())
                self.assertEqual(fixture.events(), [])

    def test_real_container_cargo_children_observe_only_explicit_selected_budget(self):
        for jobs in (None, "1", "2", "16"):
            with self.subTest(jobs=jobs):
                fixture = self.container_fixture(jobs or "default")
                options = [] if jobs is None else ["--jobs", jobs]
                with patch.dict(os.environ, {"CARGO_BUILD_JOBS": "11"}):
                    result = fixture.run(arguments=[*options, "--lane14-facts", str(fixture.facts_path)])
                self.assertEqual(result.returncode, 0, result.stderr)
                children = [row for row in fixture.events() if row["kind"] == "container_cargo"]
                self.assertEqual(len(children), 2, fixture.events())
                self.assertEqual([row["build_jobs"] for row in children], [jobs, jobs])
                self.assertEqual([Path(row["argv"][-1]).name for row in children], ["glibc-build", "musl-build"])
                self.assertEqual(fixture.facts().get("build_jobs"), [jobs or "cargo-default"])
                self.assertEqual(fixture.facts()["child_exit"], ["0"])

    def test_container_cargo_failure_keeps_selected_budget_and_propagates_status(self):
        for target, count in (("glibc-build", 1), ("musl-build", 2)):
            with self.subTest(target=target):
                fixture = self.container_fixture(target)
                fixture.config.update(container_cargo_status=37, container_cargo_fail_target=target)
                result = fixture.run(arguments=["--jobs", "2", "--lane14-facts", str(fixture.facts_path)])
                self.assertEqual(result.returncode, 37, result.stderr)
                children = [row for row in fixture.events() if row["kind"] == "container_cargo"]
                self.assertEqual(len(children), count, fixture.events())
                self.assertEqual([row["build_jobs"] for row in children], ["2"] * count)
                self.assertEqual(fixture.facts()["child_exit"], ["37"])
                state = json.loads(fixture.state_path.read_text())
                self.assertEqual(state["ids"], {})
                self.assertEqual(state["networks"], {})


if __name__ == "__main__":
    unittest.main()
