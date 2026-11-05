#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native ordinary/prepared build tests for attach and canary callers."""

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
import runpy
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
RELEASE_RUST = (ROOT / ".release-rust-version").read_text(encoding="utf-8").strip()
FIXTURES = ROOT / "tests/fixtures/dual-build-callers"
CHILDREN = (ROOT / "scripts/verify-attach-e2e.sh", ROOT / "scripts/verify-canaries.sh")
PREPARED = ("P11SCOPE_PREPARED_STABLE_CARGO", "P11SCOPE_PREPARED_STABLE_RUSTC",
            "P11SCOPE_PREPARED_BPF_CARGO", "P11SCOPE_PREPARED_BPF_RUSTC")

SPIKE_RECORDER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long U;
static U record(const char *name) {
    FILE *stream = fopen(getenv("P11SCOPE_SPIKE_CALL_LEDGER"), "a");
    if (!stream) return 5;
    fprintf(stream, "%s\n", name);
    return fclose(stream) == 0 ? 0 : 5;
}
static U initialize(void *arg) { (void)arg; return record("C_Initialize"); }
static U finalize(void *arg) {
    (void)arg;
    U rv = record("C_Finalize");
    return getenv("P11SCOPE_SPIKE_FAIL_FINALIZE") ? 5 : rv;
}
static U info(void *arg) { (void)arg; return record("C_GetInfo"); }
static U slots(unsigned char present, U *out, U *count) {
    (void)present; out[0] = 7; *count = 1; return record("C_GetSlotList");
}
static U open_session(U slot, U flags, void *app, void *notify, U *out) {
    (void)slot; (void)flags; (void)app; (void)notify;
    static U next = 1; *out = next++; return record("C_OpenSession");
}
static U close_session(U session) { (void)session; return record("C_CloseSession"); }
static U digest_init(U session, void *mechanism) {
    (void)session; (void)mechanism; return record("C_DigestInit");
}
static U digest(U session, unsigned char *data, U size, unsigned char *out, U *length) {
    (void)session; (void)data; (void)size;
    memset(out, 0, 32); *length = 32; return record("C_Digest");
}
static U random_bytes(U session, unsigned char *out, U length) {
    (void)session; memset(out, 0, length); return record("C_GenerateRandom");
}
static struct { unsigned char version[2]; void *functions[68]; } table = {
    {2, 40}, {[0] = initialize, [1] = finalize, [2] = info, [4] = slots,
              [12] = open_session, [13] = close_session, [37] = digest_init,
              [38] = digest, [64] = random_bytes}
};
U C_GetFunctionList(void **out) { *out = &table; return record("C_GetFunctionList"); }
"""


class SpikeHarnessLifetimeTests(unittest.TestCase):
    """Run the actual C harness, with independent provider call receipts."""

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope spike lifetime build ")
        cls.addClassCleanup(temporary.cleanup)
        cls.build = Path(temporary.name)
        cls.harness = cls.build / "harness"
        cls.provider = cls.build / "recorder.so"
        source = cls.build / "recorder.c"
        source.write_text(SPIKE_RECORDER, encoding="utf-8")
        flags = ["gcc", "-O0", "-Wall", "-Wextra", "-Werror"]
        subprocess.run([*flags, str(ROOT / "spike/harness.c"), "-ldl", "-o",
                        str(cls.harness)], check=True)
        subprocess.run([*flags, "-shared", "-fPIC", str(source), "-o",
                        str(cls.provider)], check=True)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope spike lifetime case ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.ledger = self.work / "calls"
        self.environment = dict(os.environ, P11SCOPE_SPIKE_CALL_LEDGER=str(self.ledger))
        self.environment.pop("P11SCOPE_SPIKE_FAIL_FINALIZE", None)

    def assert_calls_complete(self):
        calls = self.ledger.read_text().splitlines()
        self.assertEqual(Counter(calls), {
            "C_GetFunctionList": 1, "C_Initialize": 1, "C_GetInfo": 3,
            "C_GetSlotList": 1, "C_OpenSession": 10, "C_DigestInit": 50,
            "C_Digest": 50, "C_GenerateRandom": 100, "C_CloseSession": 10,
            "C_Finalize": 1,
        })
        self.assertEqual(calls[-1], "C_Finalize")

    def test_optional_finish_holds_completed_calls_and_provider_mapping(self):
        go, finish = self.work / "go", self.work / "finish"
        log_path = self.work / "workload.log"
        log = log_path.open("w")
        self.addCleanup(log.close)
        child = subprocess.Popen([str(self.harness), str(self.provider), str(go), str(finish)],
                                 env=self.environment, stdout=log, stderr=log)

        def settle():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=3)
        self.addCleanup(settle)
        deadline = time.monotonic() + 3
        while "HARNESS_PROVIDER_MAPPED\n" not in log_path.read_text():
            self.assertIsNone(child.poll(), log_path.read_text())
            self.assertLess(time.monotonic(), deadline, "provider did not map before go")
            time.sleep(0.005)
        self.assertFalse(self.ledger.exists(), "the go latch must precede every fixed call")
        go.touch()
        deadline = time.monotonic() + 3
        while "harness OK\n" not in log_path.read_text():
            self.assertIsNone(child.poll(), log_path.read_text())
            self.assertLess(time.monotonic(), deadline, "completion acknowledgement was not flushed")
            time.sleep(0.005)
        self.assertIsNone(child.poll(), "completed workload must stay alive until finish")
        self.assertIn(str(self.provider), Path(f"/proc/{child.pid}/maps").read_text())
        self.assert_calls_complete()
        finish.touch()
        self.assertEqual(child.wait(timeout=3), 0, log_path.read_text())
        self.assert_calls_complete()

    def test_original_ungated_and_go_only_forms_exit_with_exact_counts(self):
        for gated in (False, True):
            with self.subTest(gated=gated):
                self.ledger.unlink(missing_ok=True)
                argv = [str(self.harness), str(self.provider)]
                if gated:
                    go = self.work / "go"
                    go.touch()
                    argv.append(str(go))
                result = subprocess.run(argv, env=self.environment, capture_output=True,
                                        text=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "harness OK\n")
                self.assert_calls_complete()

    def test_failed_finalize_exits_without_completion_or_finish(self):
        go = self.work / "go"
        go.touch()
        result = subprocess.run([str(self.harness), str(self.provider), str(go),
                                 str(self.work / "absent finish")],
                                env=dict(self.environment, P11SCOPE_SPIKE_FAIL_FINALIZE="1"),
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("harness OK", result.stdout)
        self.assertIn("C_Finalize failed", result.stderr)
        self.assert_calls_complete()


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
        for name in ("product-build.sh", "cargo.sh", "lib.sh", "cleanup-traps.sh", "release-matrix-contract.py"):
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

    def expected(self, child, bits, prepared, diagnose=False, capture_mode="full"):
        prefix = ["build", "--locked", "--offline"] if prepared else [f"+{RELEASE_RUST}", "build", "--locked"]
        if child.name == "verify-attach-e2e.sh":
            if capture_mode == "p0":
                features = "skip-attribution,stub-object-attributes" if diagnose else "stub-object-attributes"
                return [prefix + ["--release", "--workspace", "--features", features,
                                  "--target-dir", str(self.work / "build")]]
            if diagnose:
                return [prefix + ["--release", "--workspace", "--features", "skip-attribution",
                                  "--target-dir", str(self.work / "build")]]
            return [prefix + ["--release", "--workspace",
                              "--target-dir", str(self.work / "build")]]
        stub = ["--features", "stub-object-attributes"] if capture_mode == "p0" else []
        diagnostic = "unsafe-unvalidated-metadata" + (",stub-object-attributes" if stub else "")
        rows = [
            prefix + ["--release", "--workspace", *stub,
                      "--target-dir", str(self.work / "default-build")],
            prefix + ["--release", "--workspace", "--features", diagnostic,
                      "--target-dir", str(self.work / "feature-build")],
        ]
        if bits == 32:
            rows.append(prefix + ["--release", "-p", "p11scope-discover", "--target",
                                   "i686-unknown-linux-gnu", "--target-dir",
                                   str(self.work / "helper-build")])
        return rows

    def assert_builds(self, child, bits, prepared, diagnose=False, capture_mode=None):
        expected = self.expected(child, bits, prepared, diagnose, capture_mode or "full")
        self.configure([0] * (len(expected) - 1) + [83])
        arguments = ("--diagnose-skips",) if diagnose else ()
        if capture_mode is not None:
            arguments += ("--capture-mode", capture_mode)
        result = self.run_child(child, bits, prepared, arguments)
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

    def test_capture_modes_select_build_features_and_oracle_together(self):
        # Run the actual build caller and its actual oracle dispatcher. Only
        # external commands are replaced; no fixture recomputes mode selection.
        checker = self.repo / "scripts/check-canary-evidence.py"
        checker.write_text(
            'import json, os, pathlib, sys\n'
            'config = json.loads(pathlib.Path(os.environ["P11SCOPE_DUAL_BUILD_CONFIG"]).read_text())\n'
            'with open(config["events"], "a") as handle:\n'
            ' handle.write(json.dumps({"kind": "checker", "argv": sys.argv[1:]}) + "\\n")\n')
        sudo = self.bin / "sudo"
        sudo.unlink()
        sudo.write_text('#!/bin/sh\nexec "$@"\n')
        sudo.chmod(0o755)
        script = (self.repo / "scripts/verify-canaries.sh").read_text()
        prefix = script[:script.index('P11SCOPE_PRODUCT_BUILD_MODE=')]
        probe = self.repo / "scripts/oracle-probe.sh"
        probe.write_text(prefix + '\nassert_lanes --object-starts a b c d 1 2\n'
                         'assert_lanes "$WORK"\n')
        for mode, oracle in (("full", "present"), ("p0", "absent")):
            for bits in (32, 64):
                for prepared in (False, True):
                    with self.subTest(mode=mode, bits=bits, prepared=prepared):
                        self.assert_builds(CHILDREN[1], bits, prepared, capture_mode=mode)
                        result = subprocess.run(["sh", str(probe), "--capture-mode", mode],
                            env={**self.environment, "P11SCOPE_CANARY_TARGET_BITS": str(bits)},
                            capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        rows = [row for row in self.rows() if row["kind"] == "checker"]
                        self.assertEqual(len(rows), 2)
                        for row in rows:
                            self.assertEqual(row["argv"][:2], ["--object-attributes", oracle])
                            self.assertEqual(row["argv"][-1], str(bits))
        captures = [command for command in logical_commands(CHILDREN[1])
                    if 'scripts/capture-stopped-canary.py' in command]
        self.assertEqual(len(captures), 5)
        self.assertTrue(all('--object-attributes "$OBJECT_ATTRIBUTES"' in command for command in captures))

    def test_capture_mode_refuses_before_resources(self):
        self.configure([83])
        for arguments in (("--capture-mode", "bogus"), ("--capture-mode", ""),
                          ("--capture-mode",), ("--capture-mode", "full", "--capture-mode", "p0"),
                          ("--self-test", "--capture-mode", "p0"),
                          ("--capture-mode", "full", "--self-test"),
                          ("--capture-mode=full",), ("extra",)):
            with self.subTest(arguments=arguments):
                shutil.rmtree(self.work, ignore_errors=True)
                result = self.run_child(CHILDREN[1], arguments=arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse(self.work.exists())

    def test_release_canary_call_defaults_to_full_capture_with_p0_option(self):
        commands = [command for command in logical_commands(ROOT / "scripts/build-release.sh")
                    if command.startswith("P11SCOPE_PRODUCT_BUILD_MODE=prepared")
                    and "scripts/verify-canaries.sh" in command]
        self.assertEqual(len(commands), 1)
        self.assertIn('scripts/verify-canaries.sh --capture-mode "${RELEASE_CAPTURE_MODE-full}"', commands[0])
        source = (ROOT / "scripts/build-release.sh").read_text(encoding="utf-8")
        self.assertIn("RELEASE_CAPTURE_MODE=full", source)
        self.assertIn("full|p0) RELEASE_CAPTURE_MODE=$2", source)

    def prebuilt_canary_inputs(self, bits=64, full=False):
        inputs = self.base / "prebuilt inputs with spaces"
        inputs.mkdir(exist_ok=True)
        target = (1, 3) if bits == 32 else (2, 62)
        specifications = {
            "p11scope": (2, 62), "p11scope-discover": target,
            "canary_workload": target, "matrix-provider.so": target,
            "privacy-provider.so": target, "dump-task-storage": (2, 62),
            "dump-task-storage.bpf.o": (2, 247), "default-ebpf": (2, 247),
        }
        if full:
            specifications.update({"p11scope-diagnostic": (2, 62),
                                   "diagnostic-ebpf": (2, 247), "task-storage-canary": (2, 62)})
        for name, (elf_class, machine) in specifications.items():
            header = bytearray(20)
            header[:6] = b"\x7fELF" + bytes((elf_class, 1))
            struct.pack_into("<H", header, 18, machine)
            path = inputs / name
            path.write_bytes(header)
            path.chmod(0o600 if name.endswith((".so", ".bpf.o", "-ebpf")) else 0o700)
        return inputs

    def object_input_build_boundary(self):
        # Only compiler processes are replaced. The real runner builds its
        # command line, selects outputs, exports and validates the bundle.
        for name in ("scripts/build-task-storage-reader.sh", "scripts/native/dump-task-storage.c",
                     "scripts/native/dump-task-storage.bpf.c", "scripts/fixtures/canary_workload.c",
                     "crates/discover/tests/fixture/version_matrix.c", "scripts/release-matrix-contract.py",
                     "build.rs", "src/lib.rs"):
            destination = self.repo / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        dispatch = r'''#!/usr/bin/python3
import json, os, pathlib, struct, sys
config = json.loads(pathlib.Path(os.environ["P11SCOPE_DUAL_BUILD_CONFIG"]).read_text())
kind = pathlib.Path(sys.argv[0]).name
if kind == "stable cargo": kind = "cargo"
args = sys.argv[1:]
with open(config["events"], "a") as stream:
    stream.write(json.dumps({"kind": kind, "argv": args}) + "\n")
if config.get("fail_kind") == kind: raise SystemExit(83)
def elf(bits, machine, suffix=b""):
    header = bytearray(20)
    header[:6] = b"\x7fELF" + bytes((1 if bits == 32 else 2, 1))
    struct.pack_into("<H", header, 18, machine)
    return bytes(header) + suffix
def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content); path.chmod(0o755)
if kind == "cargo":
    target = pathlib.Path(args[args.index("--target-dir") + 1])
    if "--target" in args:
        assert args[args.index("--target") + 1] == "i686-unknown-linux-gnu"
        write(target / "i686-unknown-linux-gnu/release/p11scope-discover", elf(32, 3))
    else:
        mode = b"p0" if "stub-object-attributes" in args else b"full"
        bpf = elf(64, 247, b"controlled detailed BPF " + mode)
        write(target / "release/p11scope", elf(64, 62, b"observer " + bpf))
        write(target / "release/p11scope-discover", elf(64, 62))
        write(target / "release/build/p11scope-owned/out/p11scope-ebpf", bpf)
elif kind in ("gcc", "cc", "clang-18"):
    output = pathlib.Path(args[args.index("-o") + 1])
    bits = 32 if "-m32" in args else 64
    write(output, elf(bits, 247 if kind == "clang-18" else 3 if bits == 32 else 62,
                      output.name.encode()))
else:
    raise SystemExit(97)
'''
        (self.bin / "dispatch.py").write_text(dispatch)
        self.stable_cargo.write_text(dispatch)
        for name in ("cc", "clang-18"):
            (self.bin / name).symlink_to("dispatch.py")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        # No auto maintenance: git >= 2.47 runs it detached after a
        # commit, and its lock files race the temp-dir cleanup.
        subprocess.run(["git", "-c", "maintenance.auto=false", "-c", "gc.auto=0",
                        "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "owned source"], check=True)
        self.configure([])

    def test_prepare_object_inputs_stops_before_privilege_and_capture(self):
        self.object_input_build_boundary()
        payloads = {"p11scope", "p11scope-discover", "canary_workload", "matrix-provider.so",
                    "privacy-provider.so", "dump-task-storage", "dump-task-storage.bpf.o", "default-ebpf"}
        revision = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        for mode in ("full", "p0"):
            for bits in (32, 64):
                for prepared in (False, True):
                    with self.subTest(mode=mode, bits=bits, prepared=prepared):
                        output = self.base / f"export {mode} {bits} {prepared}"
                        result = self.run_child(CHILDREN[1], bits, prepared,
                            ("--capture-mode", mode, "--object-pilot", "--prepare-object-inputs", str(output)))
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual({path.name for path in output.iterdir()}, payloads | {"canary-build.json"})
                        facts = json.loads((output / "canary-build.json").read_text())
                        self.assertEqual(facts["source_revision"], revision)
                        self.assertTrue(facts["source_clean"])
                        self.assertEqual((facts["capture_mode"], facts["target_bits"]), (mode, bits))
                        self.assertEqual(facts["build_mode"], "prepared" if prepared else "ordinary")
                        self.assertEqual(set(facts["artifacts"]), payloads)
                        self.assertEqual([step["role"] for step in facts["builds"]],
                            ["observer", *(["helper"] if bits == 32 else []), "reader", "workload",
                             "matrix-provider", "privacy-provider"])
                        for name in payloads:
                            self.assertEqual(facts["artifacts"][name]["sha256"],
                                             hashlib.sha256((output / name).read_bytes()).hexdigest())
                        cargo = [row["argv"] for row in self.rows() if row["kind"] == "cargo"]
                        expected = self.expected(CHILDREN[1], bits, prepared, capture_mode=mode)
                        self.assertEqual(cargo, [expected[0], *expected[2:]])
                        self.assertEqual({row["kind"] for row in self.rows()}, {"cargo", "gcc", "cc", "clang-18", *([] if prepared else ["prepare"])})
                        shutil.rmtree(self.work)
                        check = subprocess.run(["python3", "-I", "-c",
                            "import pathlib,runpy,sys; api=runpy.run_path('scripts/release-matrix-contract.py'); "
                            "bundle=pathlib.Path(sys.argv[1]); facts=api['load_canary_facts'](bundle/'canary-build.json'); "
                            "api['validate_canary_inputs'](facts,bundle,facts)", str(output)],
                            cwd=self.repo, capture_output=True, text=True, timeout=5)
                        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_prepare_object_inputs_refuses_without_successful_build(self):
        self.object_input_build_boundary()
        output = self.base / "exported inputs"
        for arguments in (("--prepare-object-inputs", str(output)),
                          ("--object-pilot", "--prepare-object-inputs", "relative"),
                          ("--object-pilot", "--prepare-object-inputs", str(output), "--self-test"),
                          ("--object-pilot", "--prepare-object-inputs", str(output), "--prebuilt-dir", str(output)),
                          ("--object-pilot", "--prepare-object-inputs", str(self.work / "inputs"))):
            with self.subTest(arguments=arguments):
                result = self.run_child(CHILDREN[1], arguments=arguments)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse(output.exists())
        output.mkdir()
        (output / "owned").write_text("preserve")
        result = self.run_child(CHILDREN[1], arguments=("--object-pilot", "--prepare-object-inputs", str(output)))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual((output / "owned").read_text(), "preserve")
        self.assertFalse(self.events.exists())
        shutil.rmtree(output)
        source = self.repo / "scripts/fixtures/canary_workload.c"
        original = source.read_bytes()
        source.write_bytes(original + b"\n/* uncommitted input */\n")
        result = self.run_child(CHILDREN[1], arguments=("--object-pilot", "--prepare-object-inputs", str(output)))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(self.events.exists())
        self.assertFalse(output.exists())
        source.write_bytes(original)
        config = json.loads(self.config.read_text()) | {"fail_kind": "cargo"}
        self.config.write_text(json.dumps(config))
        result = self.run_child(CHILDREN[1], arguments=("--object-pilot", "--prepare-object-inputs", str(output)))
        self.assertEqual(result.returncode, 83, result.stdout + result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual([row["kind"] for row in self.rows()], ["prepare", "cargo"])

    def canary_acquisition_boundary(self, *, stop=83):
        # Fake only external acquisition/checker commands. The actual runner
        # still validates inputs, chooses paths, dispatches and owns its C child.
        self.configure([])
        config = json.loads(self.config.read_text()) | {"probe_status": stop}
        self.config.write_text(json.dumps(config))
        (self.bin / "clang-18").symlink_to("dispatch.py")
        for name in ("build-task-storage-reader.sh", "build-task-storage-canary.sh"):
            (self.repo / "scripts" / name).symlink_to(self.bin / "dispatch.py")
        sudo = self.bin / "sudo"
        sudo.unlink()
        sudo.write_text('#!/bin/sh\n[ "${1-}" != -n ] || shift\n'
                        '[ "${1-}" != chown ] || exit 0\nexec "$@"\n')
        sudo.chmod(0o755)
        boundary = '''import json, os, pathlib, sys, time
config = json.loads(pathlib.Path(os.environ["P11SCOPE_DUAL_BUILD_CONFIG"]).read_text())
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(config["events"], "a") as stream:
    stream.write(json.dumps({"kind": name, "argv": args}) + "\\n")
if "--refusal-probe" in args:
    raise SystemExit(config["probe_status"])
if name == "capture-stopped-canary.py":
    if config.get("acquisition_status"):
        raise SystemExit(config["acquisition_status"])
    def argument(key): return args[args.index(key) + 1]
    if "--workload-pid" in args:
        pathlib.Path(argument("--go")).touch()
        if argument("--workload-mode") in ("object", "matrix"):
            deadline = time.monotonic() + 4
            while not pathlib.Path(argument("--done")).exists():
                assert time.monotonic() < deadline, "owned fixture did not finish"
                time.sleep(.005)
            pathlib.Path(argument("--finish")).touch()
        pathlib.Path(argument("--out-dir"), "mapdump_START_" + argument("--lane") + ".json").write_text("[]")
if "--object-starts" in args:
    raise SystemExit(config.get("object_status", 0))
if "--object-pilot" in args:
    raise SystemExit(config.get("pilot_status", 0))
'''
        for name in ("dump-owned-bpf-maps.py", "check-bpf-map-defs.py", "capture-stopped-canary.py",
                     "check-capture-evidence.py", "check-canary-evidence.py", "qualify-task-storage-canary.py"):
            (self.repo / "scripts" / name).write_text(boundary)
        shutil.copy2(ROOT / "scripts/lane-lib-oracle-1.py", self.repo / "scripts/lane-lib-oracle-1.py")

    def test_prebuilt_canary_inputs_never_build_or_modify_sources(self):
        self.canary_acquisition_boundary()
        for full in (False, True):
            for bits in (32, 64):
                for mode in ("full", "p0"):
                    with self.subTest(full=full, bits=bits, mode=mode):
                        inputs = self.prebuilt_canary_inputs(bits, full)
                        before = {p.name: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in inputs.iterdir()}
                        arguments = ("--prebuilt-dir", str(inputs), "--capture-mode", mode)
                        if not full:
                            arguments += ("--object-pilot",)
                        self.environment["P11SCOPE_PRODUCT_BUILD_MODE"] = "prepared"
                        self.environment[PREPARED[0]] = "/not/an/executable"
                        result = self.run_child(CHILDREN[1], bits, arguments=arguments)
                        self.assertEqual(result.returncode, 83, result.stderr)
                        self.assertEqual([r["kind"] for r in self.rows()],
                                         ["dump-owned-bpf-maps.py", "dump-owned-bpf-maps.py"])
                        after = {p.name: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in inputs.iterdir()}
                        self.assertEqual(after, before)

    def test_prebuilt_canary_missing_mixed_or_overlapping_inputs_refuse(self):
        self.canary_acquisition_boundary()
        for arguments in (("--prebuilt-dir",), ("--prebuilt-dir", "relative"),
                          ("--prebuilt-dir", "/one", "--prebuilt-dir", "/two"),
                          ("--object-pilot", "--object-pilot"),
                          ("--self-test", "--object-pilot"),
                          ("--object-pilot", "--self-test"),
                          ("--prebuilt-dir=/one",)):
            with self.subTest(arguments=arguments):
                result = self.run_child(CHILDREN[1], arguments=arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse(self.work.exists())
        for bits in (32, 64):
            inputs = self.prebuilt_canary_inputs(bits, full=True)
            for name in sorted(path.name for path in inputs.iterdir()):
                for fault in ("missing", "wrong-width"):
                    with self.subTest(bits=bits, name=name, fault=fault):
                        self.prebuilt_canary_inputs(bits, full=True)
                        path = inputs / name
                        if fault == "missing":
                            path.unlink()
                        else:
                            raw = bytearray(path.read_bytes())
                            raw[4] = 3 - raw[4]
                            path.write_bytes(raw)
                        result = self.run_child(CHILDREN[1], bits,
                                                arguments=("--prebuilt-dir", str(inputs)))
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertFalse(self.events.exists())
        for case in ("missing", "short", "wrong-class", "wrong-machine", "big-endian", "not-executable",
                     "symlink", "writable", "overlap", "input-parent", "work-parent", "bad-build-mode"):
            with self.subTest(case=case):
                inputs = self.prebuilt_canary_inputs()
                self.environment.pop("P11SCOPE_PRODUCT_BUILD_MODE", None)
                self.environment["P11SCOPE_RECEIPT_WORK"] = str(self.work)
                target = inputs / "p11scope-discover"
                if case == "missing":
                    target.unlink()
                elif case == "short":
                    target.write_bytes(b"ELF")
                elif case in ("wrong-class", "wrong-machine", "big-endian"):
                    raw = bytearray(target.read_bytes())
                    raw[{"wrong-class": 4, "wrong-machine": 18, "big-endian": 5}[case]] = 2 if case == "big-endian" else 1
                    target.write_bytes(raw)
                elif case == "not-executable":
                    target.chmod(0o600)
                elif case == "symlink":
                    target.unlink()
                    target.symlink_to(inputs / "p11scope")
                elif case == "writable":
                    target.chmod(0o722)
                elif case in ("overlap", "input-parent", "work-parent"):
                    self.environment["P11SCOPE_RECEIPT_WORK"] = str({
                        "overlap": inputs, "input-parent": inputs / "output", "work-parent": self.base}[case])
                else:
                    self.environment["P11SCOPE_PRODUCT_BUILD_MODE"] = "prebuilt"
                result = self.run_child(CHILDREN[1], arguments=("--prebuilt-dir", str(inputs), "--object-pilot"))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.events.exists())
                if target.is_symlink():
                    target.unlink()

    def test_object_pilot_dispatches_only_completion_and_blocked_cells(self):
        self.canary_acquisition_boundary(stop=0)
        compiler = shutil.which("gcc")
        for bits, object_lane in ((32, "object-ia32"), (64, "object-lp64")):
            inputs = self.prebuilt_canary_inputs(bits, full=True)
            # Compile the existing workload/providers with the real host
            # compiler; the runner itself sees compiler tripwires in PATH.
            for argv in (
                [compiler, f"-m{bits}", "-O0", "-pthread", str(ROOT / "scripts/fixtures/canary_workload.c"),
                 "-ldl", "-o", str(inputs / "canary_workload")],
                *[[compiler, f"-m{bits}", "-shared", "-fPIC", "-DPRIVACY_FIXTURE=1", *flags,
                   str(ROOT / "crates/discover/tests/fixture/version_matrix.c"), "-o", str(inputs / name)]
                  for name, flags in (("matrix-provider.so", []), ("privacy-provider.so", ["-DPRIVACY_BLOCKS=1"]))],
            ):
                subprocess.run(argv, check=True, capture_output=True, timeout=20)
            subprocess.run([compiler, f"-m{bits}", "-x", "c", "-", "-o", str(inputs / "p11scope-discover")],
                           input=b"int main(void) { return 0; }\n", check=True, capture_output=True, timeout=20)
            for name in ("p11scope", "p11scope-diagnostic", "dump-task-storage", "task-storage-canary"):
                shutil.copyfile("/bin/true", inputs / name)
                (inputs / name).chmod(0o700)
            for field, status in ((None, 0), ("object_status", 42), ("pilot_status", 43), ("acquisition_status", 44)):
                with self.subTest(bits=bits, failure=field):
                    shutil.rmtree(self.work, ignore_errors=True)
                    config = json.loads(self.config.read_text())
                    for key in ("object_status", "pilot_status", "acquisition_status"):
                        config.pop(key, None)
                    if field:
                        config[field] = status
                    self.config.write_text(json.dumps(config))
                    result = self.run_child(CHILDREN[1], bits, arguments=("--prebuilt-dir", str(inputs), "--object-pilot"))
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                    captures = [row for row in self.rows() if row["kind"] == "capture-stopped-canary.py"]
                    lanes = [row["argv"][row["argv"].index("--lane") + 1] for row in captures]
                    self.assertEqual(lanes, [object_lane] if field == "acquisition_status" else
                                           [object_lane, object_lane + "-blocked"])
                    for row in captures:
                        self.assertEqual(row["argv"][row["argv"].index("--reader") + 1], str(inputs / "dump-task-storage"))
                        self.assertEqual(row["argv"][row["argv"].index("--obj") + 1], str(inputs / "dump-task-storage.bpf.o"))
                        self.assertEqual(row["argv"][row["argv"].index("--") + 1], str(inputs / "p11scope"))
                    self.assertNotIn("canary matrix: ALL OK", result.stdout)
                    self.assertFalse(any(row["kind"] in ("cargo", "gcc", "qualify-task-storage-canary.py") for row in self.rows()))
            if bits == 64:
                shutil.rmtree(self.work)
                self.config.write_text(json.dumps(config | {"acquisition_status": 0}))
                result = self.run_child(CHILDREN[1], arguments=("--prebuilt-dir", str(inputs)))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                rows = self.rows()
                captures = [row for row in rows if row["kind"] == "capture-stopped-canary.py"]
                self.assertEqual([row["argv"][row["argv"].index("--lane") + 1] for row in captures], [
                    "default-safe-profile", "default-safe-trace", "feature-safe-profile", "feature-safe-trace",
                    "feature-unsafe-profile", "feature-unsafe-trace", "aggregate-only-metrics",
                    "default-safe-start", "feature-safe-start", "feature-unsafe-fault",
                    "object-lp64", "object-lp64-blocked", "owned-default-metrics", "owned-feature-metrics"])
                self.assertEqual(sum(row["kind"] == "qualify-task-storage-canary.py" for row in rows), 1)
                self.assertIn("canary matrix: ALL OK", result.stdout)

    def test_canary_product_builds_precede_task_storage_helper(self):
        self.object_input_build_boundary()
        self.config.write_text(json.dumps(json.loads(self.config.read_text()) | {"fail_kind": "clang-18"}))
        for bits, expected_builds in ((32, 3), (64, 2)):
            for prepared in (False, True):
                with self.subTest(bits=bits, prepared=prepared):
                    result = self.run_child(CHILDREN[1], bits, prepared)
                    self.assertEqual(result.returncode, 83, result.stdout + result.stderr)
                    kinds = [row["kind"] for row in self.rows()]
                    product_builds = [index for index, kind in enumerate(kinds) if kind == "cargo"]
                    self.assertEqual(len(product_builds), expected_builds)
                    self.assertEqual(kinds.count("clang-18"), 1)
                    self.assertLess(max(product_builds), kinds.index("clang-18"))
                    self.assertNotIn("gcc", kinds)

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
                self.assert_builds(CHILDREN[0], 64, prepared, diagnose=True, capture_mode="p0")

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

    def attach_expected(self, prepared, features):
        prefix = ["build", "--locked", "--offline"] if prepared else [f"+{RELEASE_RUST}", "build", "--locked"]
        argv = prefix + ["--release", "--workspace"]
        if features is not None:
            argv += ["--features", features]
        return [argv + ["--target-dir", str(self.work / "build")]]

    def assert_attach_builds(self, prepared, features, arguments=()):
        expected = self.attach_expected(prepared, features)
        self.configure([0] * (len(expected) - 1) + [83])
        result = self.run_child(CHILDREN[0], 64, prepared, arguments)
        self.assertEqual(result.returncode, 83, result.stderr)
        builds = [row for row in self.rows() if row["kind"] == "cargo"]
        self.assertEqual([row["argv"] for row in builds], expected)
        resources = {"sudo", "gcc", "bpftool", "softhsm2-util", "rustup"}
        self.assertFalse(resources & {row["kind"] for row in self.rows()})

    def test_attach_defaults_to_full_capture_in_both_build_modes(self):
        for prepared in (False, True):
            with self.subTest(prepared=prepared):
                self.assert_attach_builds(prepared, None)

    def test_attach_capture_mode_p0_restores_stub_features(self):
        for prepared in (False, True):
            with self.subTest(prepared=prepared):
                self.assert_attach_builds(prepared, "stub-object-attributes",
                                           ("--capture-mode", "p0"))

    def test_attach_capture_mode_combines_with_diagnose_skips(self):
        for prepared in (False, True):
            with self.subTest(prepared=prepared):
                self.assert_attach_builds(prepared, "skip-attribution",
                                           ("--diagnose-skips",))
                self.assert_attach_builds(prepared, "skip-attribution,stub-object-attributes",
                                           ("--diagnose-skips", "--capture-mode", "p0"))
                self.assert_attach_builds(prepared, "skip-attribution",
                                           ("--capture-mode", "full", "--diagnose-skips"))

    def test_attach_capture_mode_refuses_invalid_and_accepts_valid(self):
        self.configure([83])
        for arguments in (("--capture-mode", "bogus"), ("--capture-mode",),
                          ("--capture-mode", "full", "--capture-mode", "p0"),
                          ("--capture-mode=full",),
                          ("--self-test", "--capture-mode", "full"),
                          ("--capture-mode", "full", "--self-test"),
                          ("--diagnose-skips", "--capture-mode", "bogus")):
            with self.subTest(arguments=arguments):
                shutil.rmtree(self.work, ignore_errors=True)
                result = self.run_child(CHILDREN[0], arguments=arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse(self.work.exists())
        for arguments in (("--capture-mode", "full"), ("--capture-mode", "p0")):
            with self.subTest(arguments=arguments):
                shutil.rmtree(self.work, ignore_errors=True)
                result = self.run_child(CHILDREN[0], arguments=arguments)
                self.assertEqual(result.returncode, 83, result.stderr)
                builds = [row for row in self.rows() if row["kind"] == "cargo"]
                self.assertEqual(len(builds), 1)

    def test_release_lane_calls_thread_selected_capture_mode(self):
        commands = [command for command in logical_commands(ROOT / "scripts/build-release.sh")
                    if command.startswith("P11SCOPE_PRODUCT_BUILD_MODE=prepared")]
        canary = [command for command in commands if "scripts/verify-canaries.sh" in command]
        attach = [command for command in commands if "scripts/verify-attach-e2e.sh" in command]
        self.assertEqual(len(canary), 1)
        self.assertEqual(len(attach), 1)
        self.assertIn('scripts/verify-canaries.sh --capture-mode "${RELEASE_CAPTURE_MODE-full}"', canary[0])
        self.assertIn('scripts/verify-attach-e2e.sh --capture-mode "${RELEASE_CAPTURE_MODE-full}"', attach[0])
        source = (ROOT / "scripts/build-release.sh").read_text()
        self.assertIn("RELEASE_CAPTURE_MODE=full", source)
        self.assertIn("receipt_fact capture_mode", source)

    def configure_attach_observer(self, *, skipped=1, log_lines=(), checker_status=None,
                                  log_fault=None, terminal_attribution=False, profiler_status=0,
                                  require_completed_live=False, workload_status=0,
                                  omit_completion=False):
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
                                           "terminal_attribution": terminal_attribution,
                                           "profiler_status": profiler_status,
                                           "require_completed_live": require_completed_live,
                                           "workload_status": workload_status,
                                           "omit_completion": omit_completion}),
                               encoding="utf-8")
        dispatcher = '''#!/usr/bin/python3
import json, mmap, os, select, shutil, sys, time
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
        if config["workload_status"] or config["omit_completion"]:
            raise SystemExit(config["workload_status"])
        print("harness OK", flush=True)
        phase = Path(sys.argv[2] + ".phase")
        # Existence is the observer's handoff; publish only a complete phase.
        pending_phase = phase.with_suffix(".pending")
        pending_phase.write_text("held" if len(sys.argv) == 4 else "exiting")
        pending_phase.replace(phase)
        if len(sys.argv) == 4:
            while not Path(sys.argv[3]).exists():
                if time.monotonic() > deadline:
                    raise SystemExit(98)
                time.sleep(0.01)
            with Path(config["events"]).open("a") as stream:
                stream.write(json.dumps({"kind": "workload-released"}) + "\\n")
elif kind == "p11scope":
    output = Path(sys.argv[sys.argv.index("-o") + 1])
    target = int(sys.argv[sys.argv.index("--pid") + 1])
    pin = os.pidfd_open(target)
    print("p11scope: capturing: 136 probe(s) attached; stop with Ctrl-C", flush=True)
    if config["require_completed_live"]:
        phase = output.with_name(output.stem + "-go.phase")
        deadline = time.monotonic() + 3
        while not phase.exists():
            if time.monotonic() > deadline:
                raise SystemExit("workload never completed")
            time.sleep(0.01)
        if phase.read_text() == "exiting":
            if not select.select([pin], [], [], 3)[0]:
                raise SystemExit("unheld workload never exited")
        if select.select([pin], [], [], 0)[0]:
            raise SystemExit("completed workload exited before observer terminal collection")
        if "libsofthsm2.so" not in Path(f"/proc/{target}/maps").read_text():
            raise SystemExit("completed workload lost its provider mapping")
        with Path(config["events"]).open("a") as stream:
            stream.write(json.dumps({"kind": "completed-live", "pid": target}) + "\\n")
    os.close(pin)
    output.write_text(json.dumps(config["documents"][int("--manifest" in sys.argv)]))
    print("PRIVATE UNRELATED LOG SENTINEL")
    if not config["terminal_attribution"]:
        for line in config["log_lines"]:
            print(line)
    for index in range(3):
        print(f"ordinary terminal line {index}")
    if config["terminal_attribution"]:
        for line in config["log_lines"]:
            print(line)
    raise SystemExit(config["profiler_status"])
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

    def test_attach_keeps_completed_workload_mapped_through_observer_terminal(self):
        self.configure_attach_observer(skipped=0, require_completed_live=True)
        result = self.run_child(CHILDREN[0], arguments=("--diagnose-skips",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("=== e2e: ALL OK ===", result.stdout)
        self.assertEqual(sum(row["kind"] == "completed-live" for row in self.rows()), 2)
        self.assertEqual(sum(row["kind"] == "workload-released" for row in self.rows()), 2)

    def test_attach_preserves_failed_workload_status_before_completion(self):
        self.configure_attach_observer(skipped=0, workload_status=43)
        result = self.run_child(CHILDREN[0])
        self.assertEqual(result.returncode, 43, result.stdout + result.stderr)
        self.assertIn("workload failed before completion: 43", result.stdout)
        self.assertNotIn("=== discover", result.stdout)

    def test_attach_refuses_successful_exit_without_completion(self):
        self.configure_attach_observer(skipped=0, omit_completion=True)
        result = self.run_child(CHILDREN[0])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("workload failed before completion: 1", result.stdout)
        self.assertNotIn("=== discover", result.stdout)

    def test_attach_failed_profiler_preserves_status_and_filters_private_attribution(self):
        attribution = "p11scope: skip-attribution: PRIVATE ATTRIBUTION " + "x" * 5000
        self.configure_attach_observer(log_lines=(attribution,), terminal_attribution=True,
                                       profiler_status=37)
        for diagnose in (False, True):
            with self.subTest(diagnose=diagnose):
                result = self.run_child(CHILDREN[0],
                                        arguments=("--diagnose-skips",) if diagnose else ())
                self.assertEqual(result.returncode, 37, result.stderr)
                self.assertIn("profiler failed: 37", result.stdout)
                self.assertIn("ordinary terminal line 2", result.stdout)
                self.assertEqual(attribution in result.stdout, not diagnose)
                self.assertNotIn("PRIVATE ATTRIBUTION", result.stderr)
                if diagnose:
                    self.assertNotIn("p11scope: skip-attribution:", result.stdout + result.stderr)
                self.assertNotIn("capture evidence rejected:", result.stderr)
                self.assertNotIn("=== discover", result.stdout)
                self.assertNotIn("manifest corroborated against the scan", result.stdout)
                self.assertNotIn("ALL OK", result.stdout)
                self.assertEqual(sum(row["kind"] == "p11scope" for row in self.rows()), 1)
                self.assertEqual(sum(row["kind"] == "workload-released" for row in self.rows()), 1)
                self.assertFalse(any(row["kind"] == "p11scope-discover" for row in self.rows()))

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
                default_environment = dict(self.environment)
                default_environment.pop("RELEASE_CAPTURE_MODE", None)
                self.events.unlink(missing_ok=True)
                expected = self.expected(child, bits, True, capture_mode="full")
                self.configure([0] * (len(expected) - 1) + [83])
                command_file = self.base / f"{child.name}.command"
                command_file.write_text(command, encoding="utf-8")
                result = subprocess.run(
                    ["sh", str(FIXTURES / "release-handoff-launcher.sh"),
                     str(command_file), *(str(value) for value in self.selected)],
                    cwd=self.repo, env=default_environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(result.returncode, 83, result.stderr)
                builds = [row for row in self.rows() if row["kind"] == "cargo"]
                self.assertEqual([row["argv"] for row in builds], expected)
                self.assertTrue(all(row["executable"] == str(self.stable_cargo.resolve())
                                    and row["rustc"] == str(self.selected[1])
                                    and row["bpf_cargo"] == str(self.selected[2])
                                    and row["bpf_rustc"] == str(self.selected[3]) for row in builds))
                self.events.unlink(missing_ok=True)
                p0_expected = self.expected(child, bits, True, capture_mode="p0")
                self.configure([0] * (len(p0_expected) - 1) + [83])
                selected = subprocess.run(
                    ["sh", str(FIXTURES / "release-handoff-launcher.sh"),
                     str(command_file), *(str(value) for value in self.selected)],
                    cwd=self.repo, env=dict(self.environment, RELEASE_CAPTURE_MODE="p0"), text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(selected.returncode, 83, selected.stderr)
                p0_builds = [row for row in self.rows() if row["kind"] == "cargo"]
                self.assertEqual([row["argv"] for row in p0_builds], p0_expected)
                self.assertTrue(all(row["executable"] == str(self.stable_cargo.resolve())
                                    and row["rustc"] == str(self.selected[1])
                                    and row["bpf_cargo"] == str(self.selected[2])
                                    and row["bpf_rustc"] == str(self.selected[3]) for row in p0_builds))

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
