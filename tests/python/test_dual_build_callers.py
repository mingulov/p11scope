#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native ordinary/prepared build tests for attach and canary callers."""

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RELEASE_RUST = (ROOT / ".release-rust-version").read_text(encoding="utf-8").strip()
FIXTURES = ROOT / "tests/fixtures/dual-build-callers"
CHILDREN = (ROOT / "scripts/verify-attach-e2e.sh", ROOT / "scripts/verify-canaries.sh")
PREPARED = ("P11SCOPE_PREPARED_STABLE_CARGO", "P11SCOPE_PREPARED_STABLE_RUSTC",
            "P11SCOPE_PREPARED_BPF_CARGO", "P11SCOPE_PREPARED_BPF_RUSTC")


def logical_commands(path):
    commands, pending = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        pending.append(line)
        if not line.rstrip().endswith("\\"):
            commands.append("\n".join(pending)); pending = []
    return commands


class DualBuildCallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope dual callers ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "checkout with spaces"
        (self.repo / "scripts").mkdir(parents=True)
        for source in CHILDREN:
            shutil.copy2(source, self.repo / "scripts" / source.name)
        for name in ("product-build.sh", "cargo.sh", "lib.sh", "cleanup-traps.sh"):
            shutil.copy2(ROOT / "scripts" / name, self.repo / "scripts" / name)
        shutil.copy2(FIXTURES / "record-preparer.py", self.repo / "scripts/prepare-dependencies.py")
        shutil.copy2(ROOT / ".release-rust-version", self.repo / ".release-rust-version")
        self.bin = self.base / "PATH tripwires"
        self.bin.mkdir()
        shutil.copy2(FIXTURES / "dispatch.py", self.bin / "dispatch.py")
        (self.bin / "dispatch.py").chmod(0o755)
        for name in ("cargo", "gcc", "softhsm2-util", "bpftool", "sudo", "rustup"):
            (self.bin / name).symlink_to("dispatch.py")
        self.tools = self.base / "selected tools with spaces"
        self.tools.mkdir()
        self.stable_cargo = self.tools / "stable cargo"
        shutil.copy2(FIXTURES / "dispatch.py", self.stable_cargo)
        self.stable_cargo.chmod(0o755)
        self.selected = (self.stable_cargo,
                         self.make_inert("stable rustc"), self.make_inert("bpf cargo"),
                         self.make_inert("bpf rustc"))
        self.events = self.base / "events.jsonl"
        self.config = self.base / "config.json"
        self.module = self.base / "module.so"
        self.module.write_bytes(b"fixture")
        self.work = self.base / "private work"
        self.environment = os.environ.copy()
        for name in (*PREPARED, "P11SCOPE_PRODUCT_BUILD_MODE"):
            self.environment.pop(name, None)
        self.environment.update(PATH=f"{self.bin}:/usr/bin:/bin",
                                P11SCOPE_DUAL_BUILD_CONFIG=str(self.config),
                                P11SCOPE_PKCS11_MODULE=str(self.module),
                                P11SCOPE_RECEIPT_WORK=str(self.work))

    def make_inert(self, name):
        path = self.tools / name
        shutil.copy2(FIXTURES / "unused-tool.sh", path)
        path.chmod(0o755)
        return path

    def configure(self, statuses):
        self.config.write_text(json.dumps({"events": str(self.events),
                                           "cargo_statuses": statuses}), encoding="utf-8")

    def rows(self):
        return [json.loads(row) for row in self.events.read_text().splitlines()]

    def run_child(self, child, bits=64, prepared=False, arguments=()):
        self.events.unlink(missing_ok=True)
        environment = self.environment.copy()
        environment["P11SCOPE_CANARY_TARGET_BITS"] = str(bits)
        if prepared:
            environment["P11SCOPE_PRODUCT_BUILD_MODE"] = "prepared"
            environment.update({name: str(value) for name, value in zip(PREPARED, self.selected)})
        return subprocess.run(["sh", str(self.repo / "scripts" / child.name), *arguments], cwd=self.base,
                              env=environment, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10)

    def expected(self, child, bits, prepared):
        prefix = ["build", "--locked", "--offline"] if prepared else [f"+{RELEASE_RUST}", "build", "--locked"]
        if child.name == "verify-attach-e2e.sh":
            return [prefix + ["--release", "--workspace", "--target-dir", str(self.work / "build")]]
        rows = [
            prefix + ["--release", "--workspace", "--target-dir", str(self.work / "default-build")],
            prefix + ["--release", "--workspace", "--features", "unsafe-unvalidated-metadata",
                      "--target-dir", str(self.work / "feature-build")],
        ]
        if bits == 32:
            rows.append(prefix + ["--release", "-p", "p11scope-discover", "--target",
                                   "i686-unknown-linux-gnu", "--target-dir",
                                   str(self.work / "helper-build")])
        return rows

    def assert_builds(self, child, bits, prepared, diagnose=False):
        expected = self.expected(child, bits, prepared)
        if diagnose:
            expected[0].extend(["--features", "skip-attribution"])
        self.configure([0] * (len(expected) - 1) + [83])
        result = self.run_child(child, bits, prepared,
                                ("--diagnose-skips",) if diagnose else ())
        self.assertEqual(result.returncode, 83, result.stderr)
        rows = self.rows()
        builds = [row for row in rows if row["kind"] == "cargo"]
        self.assertEqual([row["argv"] for row in builds], expected)
        resources = {"sudo", "gcc", "bpftool", "softhsm2-util", "rustup"}
        self.assertFalse(resources & {row["kind"] for row in rows})
        if prepared:
            for row in builds:
                self.assertEqual(row["executable"], str(self.stable_cargo.resolve()))
                self.assertEqual(row["rustc"], str(self.selected[1]))
                self.assertEqual(row["bpf_cargo"], str(self.selected[2]))
                self.assertEqual(row["bpf_rustc"], str(self.selected[3]))
            self.assertFalse(any(row["kind"] == "prepare" for row in rows))
        else:
            preparations = [row for row in rows if row["kind"] == "prepare"]
            self.assertEqual(len(preparations), len(builds))
            self.assertTrue(all(row["isolated"] == 1 and row["argv"] == []
                                for row in preparations))

    def test_canary_product_builds_precede_task_storage_helper(self):
        commands = [command.lstrip() for command in logical_commands(CHILDREN[1])]
        product_builds = [index for index, command in enumerate(commands)
                          if command.startswith("p11scope_product_build ")]
        helper_builds = [index for index, command in enumerate(commands)
                         if command.startswith("scripts/build-task-storage-reader.sh ")]
        self.assertEqual(len(product_builds), 3)
        self.assertEqual(len(helper_builds), 1)
        self.assertLess(max(product_builds), helper_builds[0])

    def test_standalone_defaults_to_ordinary_for_all_variants(self):
        self.assert_builds(CHILDREN[0], 64, False)
        self.assert_builds(CHILDREN[1], 64, False)
        self.assert_builds(CHILDREN[1], 32, False)

    def test_prepared_mode_uses_exact_tools_without_preparation_or_reselection(self):
        self.assert_builds(CHILDREN[0], 64, True)
        self.assert_builds(CHILDREN[1], 64, True)
        self.assert_builds(CHILDREN[1], 32, True)

    def test_attach_diagnostic_adds_only_fixed_feature_in_both_build_modes(self):
        for prepared in (False, True):
            with self.subTest(prepared=prepared):
                self.assert_builds(CHILDREN[0], 64, prepared, diagnose=True)

    def test_attach_rejects_unknown_or_combined_arguments_before_resources(self):
        self.configure([83])
        for arguments in (("unknown",), ("",), ("--diagnose-skips", "extra"),
                          ("--diagnose-skips", "--diagnose-skips"),
                          ("--self-test", "--diagnose-skips"),
                          ("--diagnose-skips", "--self-test")):
            with self.subTest(arguments=arguments):
                shutil.rmtree(self.work, ignore_errors=True)
                result = self.run_child(CHILDREN[0], arguments=arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse(self.work.exists())

    def configure_attach_observer(self, *, skipped=1, log_lines=(), checker_status=None,
                                  log_fault=None, terminal_attribution=False):
        """Keep the actual gate, waits and checker; fake only external commands."""
        for name in ("check-capture-evidence.py", "lane-attach-e2e-oracle.py"):
            shutil.copy2(ROOT / "scripts" / name, self.repo / "scripts" / name)
        (self.repo / "spike").mkdir()
        shutil.copy2(ROOT / "spike/expected.txt", self.repo / "spike/expected.txt")
        checker = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
        counts = {"C_CloseSession": 10, "C_Digest": 50, "C_DigestInit": 50,
                  "C_Finalize": 1, "C_GenerateRandom": 100, "C_GetInfo": 3,
                  "C_GetSlotList": 1, "C_Initialize": 1, "C_OpenSession": 10,
                  "C_GetFunctionList": 1}
        documents = []
        for sources in (("scan",), ("scan", "manifest")):
            surfaces = checker["LEGACY_SURFACES"].copy()
            if len(sources) == 2:
                surfaces += checker["LEGACY_SURFACES"]
            evidence = checker["evidence_fixture"](surfaces, sources, discovery_skipped=skipped)
            evidence.update(table_entries=68, slots=68, active_slots=68, attached_probes=136)
            evidence["discovery"][0]["path"] = "/opt/libsofthsm2.so"
            evidence["discovery"][0]["objects"][0]["path"] = "/opt/libsofthsm2.so"
            if len(sources) == 2:
                evidence["surfaces"][0]["source"] = (
                    f"{evidence['discovery'][0]['path']} table 2.40")
            document = checker["document_fixture"](
                evidence, schema=checker["METRICS_SCHEMA"], mode="metrics",
                privacy="aggregate-only")
            document["functions"] = checker["function_items"](
                [([name], calls) for name, calls in counts.items()])
            documents.append(document)
        self.module = self.base / "libsofthsm2.so"
        self.module.write_bytes(b"fixture mapping")
        self.environment["P11SCOPE_PKCS11_MODULE"] = str(self.module)
        self.config.write_text(json.dumps({"events": str(self.events),
                                           "documents": documents, "log_lines": log_lines,
                                           "terminal_attribution": terminal_attribution}),
                               encoding="utf-8")
        dispatcher = '''#!/usr/bin/python3
import json, mmap, os, shutil, sys, time
from pathlib import Path
config = json.loads(Path(os.environ["P11SCOPE_DUAL_BUILD_CONFIG"]).read_text())
kind = "cargo" if Path(sys.argv[0]).name in ("cargo", "stable cargo") else Path(sys.argv[0]).name
with Path(config["events"]).open("a") as stream:
    stream.write(json.dumps({"kind": kind, "argv": sys.argv[1:]}) + "\\n")
if kind == "cargo":
    release = Path(sys.argv[sys.argv.index("--target-dir") + 1]) / "release"
    release.mkdir(parents=True)
    for name in ("p11scope", "p11scope-discover"):
        shutil.copy2(Path(sys.argv[0]).resolve(), release / name)
elif kind == "gcc":
    shutil.copy2(Path(sys.argv[0]).resolve(), sys.argv[sys.argv.index("-o") + 1])
elif kind == "harness":
    with open(sys.argv[1], "rb") as provider, mmap.mmap(provider.fileno(), 0, access=mmap.ACCESS_READ):
        deadline = time.monotonic() + 8
        while not Path(sys.argv[2]).exists():
            if time.monotonic() > deadline:
                raise SystemExit(98)
            time.sleep(0.01)
elif kind == "p11scope":
    output = Path(sys.argv[sys.argv.index("-o") + 1])
    output.write_text(json.dumps(config["documents"][int("--manifest" in sys.argv)]))
    print("p11scope: capturing: 136 probe(s) attached; stop with Ctrl-C", flush=True)
    print("PRIVATE UNRELATED LOG SENTINEL")
    if not config["terminal_attribution"]:
        for line in config["log_lines"]:
            print(line)
    for index in range(3):
        print(f"ordinary terminal line {index}")
    if config["terminal_attribution"]:
        for line in config["log_lines"]:
            print(line)
elif kind == "p11scope-discover":
    Path(sys.argv[sys.argv.index("-o") + 1]).write_text("{}")
elif kind == "sudo":
    arguments = sys.argv[1:]
    while arguments and arguments[0].startswith("-"):
        arguments.pop(0)
    os.execvp(arguments[0], arguments)
elif kind != "softhsm2-util":
    raise SystemExit(97)
'''
        (self.bin / "dispatch.py").write_text(dispatcher, encoding="utf-8")
        shutil.copy2(self.bin / "dispatch.py", self.stable_cargo)
        if checker_status is not None:
            shutil.copy2(self.repo / "scripts/check-capture-evidence.py",
                         self.repo / "scripts/real-check-capture-evidence.py")
            wrapper = f'''import subprocess, sys
from pathlib import Path
subprocess.run([sys.executable, "-I", "scripts/real-check-capture-evidence.py", *sys.argv[1:]], check=False)
log = Path(sys.argv[2]).with_suffix(".log")
fault = {log_fault!r}
if fault in ("missing", "directory"):
    log.unlink()
if fault == "directory":
    log.mkdir()
raise SystemExit({checker_status})
'''
            (self.repo / "scripts/check-capture-evidence.py").write_text(wrapper, encoding="utf-8")

    def assert_first_lane_failed(self, result, status=1):
        self.assertEqual(result.returncode, status, result.stderr)
        self.assertIn("discovery skips: want 0, got", result.stderr)
        self.assertNotIn("=== discover", result.stdout)
        self.assertNotIn("manifest corroborated against the scan", result.stdout)
        self.assertNotIn("ALL OK", result.stdout)
        self.assertEqual(sum(row["kind"] == "p11scope" for row in self.rows()), 1)
        self.assertFalse(any(row["kind"] == "p11scope-discover" for row in self.rows()))

    def test_attach_real_checker_failure_exposes_only_opted_in_attribution(self):
        attribution = 'p11scope: skip-attribution: [0] site.rs:7 x2 :: subject="internal" reason="racing exit"'
        unanchored = "PRIVATE PREFIX SENTINEL p11scope: skip-attribution: unrelated"
        self.configure_attach_observer(log_lines=(unanchored, attribution))
        for diagnose in (False, True):
            with self.subTest(diagnose=diagnose):
                result = self.run_child(CHILDREN[0],
                                        arguments=("--diagnose-skips",) if diagnose else ())
                self.assert_first_lane_failed(result)
                self.assertNotIn("PRIVATE UNRELATED LOG SENTINEL", result.stdout + result.stderr)
                self.assertNotIn(unanchored, result.stdout + result.stderr)
                self.assertEqual(attribution in result.stderr, diagnose)
                self.assertNotIn(attribution, result.stdout)

    def test_attach_diagnostic_output_clips_lines_and_record_count(self):
        prefix = "p11scope: skip-attribution: "
        self.configure_attach_observer(log_lines=[prefix + "x" * 3000] +
                                       [prefix + f"record {index}" for index in range(80)],
                                       terminal_attribution=True)
        result = self.run_child(CHILDREN[0], arguments=("--diagnose-skips",))
        self.assert_first_lane_failed(result)
        lines = [line for line in result.stderr.splitlines() if line.startswith(prefix)]
        self.assertEqual(len(lines), 65)
        self.assertTrue(all(len(line) <= 2048 for line in lines))
        self.assertIn("[line clipped]", lines[0])
        self.assertIn("[additional lines clipped]", lines[-1])
        self.assertNotIn(prefix + "record 63", lines)
        self.assertNotIn(prefix, result.stdout)

    def test_attach_diagnostic_keeps_checker_status_with_unusable_log(self):
        self.configure_attach_observer(checker_status=37)
        for fault in (None, "missing", "directory"):
            with self.subTest(fault=fault):
                wrapper = self.repo / "scripts/check-capture-evidence.py"
                text = wrapper.read_text()
                start = text.index("fault = ")
                end = text.index("\n", start)
                wrapper.write_text(text[:start] + f"fault = {fault!r}" + text[end:])
                result = self.run_child(CHILDREN[0], arguments=("--diagnose-skips",))
                self.assert_first_lane_failed(result, 37)

    def test_attach_success_keeps_both_oracles_without_dumping_diagnostics(self):
        attribution = "p11scope: skip-attribution: 0 published record(s)"
        self.configure_attach_observer(skipped=0, log_lines=(attribution,),
                                       terminal_attribution=True)
        result = self.run_child(CHILDREN[0], arguments=("--diagnose-skips",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("=== e2e: ALL OK ===", result.stdout)
        self.assertNotIn(attribution, result.stdout + result.stderr)
        self.assertEqual(sum(row["kind"] == "p11scope" for row in self.rows()), 2)

    def test_attach_self_test_returns_before_build_or_resources(self):
        self.configure([83])
        result = subprocess.run(["sh", str(CHILDREN[0]), "--self-test"], cwd=ROOT,
                                env=self.environment, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.events.exists())
        self.assertFalse(self.work.exists())

    def test_every_partial_prepared_context_refuses_before_build_and_resources(self):
        self.configure([83])
        for child, arguments in ((CHILDREN[0], ()), (CHILDREN[0], ("--diagnose-skips",)),
                                 (CHILDREN[1], ())):
            for mask in range(15):
                with self.subTest(child=child.name, arguments=arguments, mask=mask):
                    self.events.unlink(missing_ok=True)
                    environment = self.environment.copy()
                    environment["P11SCOPE_PRODUCT_BUILD_MODE"] = "prepared"
                    for index, (name, value) in enumerate(zip(PREPARED, self.selected)):
                        if mask & (1 << index):
                            environment[name] = str(value)
                    result = subprocess.run(
                        ["sh", str(self.repo / "scripts" / child.name), *arguments], cwd=self.base,
                        env=environment, text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("complete prepared product-build context required", result.stderr)
                    self.assertFalse(self.events.exists())

    def test_release_handoffs_unexported_selected_context_to_actual_children(self):
        release = ROOT / "scripts/build-release.sh"
        commands = [command for command in logical_commands(release)
                    if command.startswith("P11SCOPE_PRODUCT_BUILD_MODE=prepared")]
        self.assertEqual(len(commands), 2)
        for command, child, bits in zip(commands, CHILDREN[::-1], (64, 64)):
            with self.subTest(child=child.name):
                self.events.unlink(missing_ok=True)
                expected = self.expected(child, bits, True)
                self.configure([0] * (len(expected) - 1) + [83])
                command_file = self.base / f"{child.name}.command"
                command_file.write_text(command, encoding="utf-8")
                result = subprocess.run(
                    ["sh", str(FIXTURES / "release-handoff-launcher.sh"),
                     str(command_file), *(str(value) for value in self.selected)],
                    cwd=self.repo, env=self.environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(result.returncode, 83, result.stderr)
                builds = [row for row in self.rows() if row["kind"] == "cargo"]
                self.assertEqual([row["argv"] for row in builds], expected)
                self.assertTrue(all(row["executable"] == str(self.stable_cargo.resolve())
                                    and row["rustc"] == str(self.selected[1])
                                    and row["bpf_cargo"] == str(self.selected[2])
                                    and row["bpf_rustc"] == str(self.selected[3]) for row in builds))

    def compiler_free_tripwires(self):
        """The PATH tripwires a delegated `--self-test` may never reach.

        The validator suites compile their own fixtures, so a real compiler is
        part of the self-test and `gcc` is deliberately left resolvable; cargo,
        the privilege escalator and the hardware tools are not, and
        `dispatch.py` records any attempt to run one.
        """
        directory = self.base / "PATH tripwires without a compiler"
        directory.mkdir()
        shutil.copy2(FIXTURES / "dispatch.py", directory / "dispatch.py")
        (directory / "dispatch.py").chmod(0o755)
        for name in ("cargo", "softhsm2-util", "bpftool", "sudo", "rustup"):
            (directory / name).symlink_to("dispatch.py")
        return directory

    def test_self_test_fast_paths_remain_before_build_setup(self):
        # The claim is that `--self-test` returns before `product-build.sh` runs
        # two `--release --workspace` builds. This file's own PATH tripwires are
        # the check, not a clock: a self-test that reached build setup, sudo or
        # a hardware tool leaves a recorded event behind, which is caught even
        # when the stand-in returns instantly. The delegated validator suites
        # grew with the canary matrix (60 evidence + 11 workload cases per
        # width, each compiling fixtures and spawning subprocesses), so a
        # budget under their cost on a slower supported guest had made this a
        # timing tripwire rather than a build-setup check; the timeout below is
        # only a hang guard, far above any observed self-test cost.
        self.configure([0, 0, 0])
        environment = dict(self.environment,
                           PATH=f"{self.compiler_free_tripwires()}:/usr/bin:/bin")
        for child in CHILDREN:
            with self.subTest(child=child.name):
                self.events.unlink(missing_ok=True)
                result = subprocess.run(["sh", str(child), "--self-test"], cwd=ROOT,
                                        env=environment, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        timeout=900)
                # The substantive check first: a recorded event names exactly
                # which tool a fallen-through self-test reached.
                self.assertFalse(
                    self.events.exists(),
                    f"{child.name} --self-test reached build setup or a resource tool: "
                    f"{self.rows() if self.events.exists() else ''}")
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
