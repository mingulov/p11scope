#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed whole-object comparisons and fresh-build driver controls.

The Git snapshots and filesystem operations are real. Only the expensive
external compiler/Cargo commands use tiny command fixtures.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from _loader import load_path

SCRIPT = ROOT / "scripts/check-bpf-noninterference.py"
NAMES = ("p11scope-ebpf", "p11scope-ebpf-inventory", "p11scope-ebpf-inventory-callers")


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "the noninterference driver is missing")
        self.driver = load_path(SCRIPT)
        self.temporary = tempfile.TemporaryDirectory(prefix="bpf-comparison-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.baseline = self.objects("baseline")
        self.candidate = self.objects("candidate")

    def objects(self, directory):
        parent = self.root / directory
        parent.mkdir()
        result = {}
        for index, name in enumerate(NAMES):
            result[name] = parent / name
            result[name].write_bytes(b"whole ELF including debug" + bytes([index]))
        return result

    def test_equal_whole_objects_pass(self):
        self.driver.compare_objects(self.baseline, self.candidate)

    def test_changed_byte_in_each_flavor_fails(self):
        for name in NAMES:
            with self.subTest(name=name):
                original = self.candidate[name].read_bytes()
                self.candidate[name].write_bytes(original + b"changed debug byte")
                with self.assertRaisesRegex(self.driver.CheckError, name):
                    self.driver.compare_objects(self.baseline, self.candidate)
                self.candidate[name].write_bytes(original)

    def test_missing_extra_and_zero_selected_objects_fail(self):
        for mapping in ({}, {k: v for k, v in self.candidate.items() if k != NAMES[0]},
                        {**self.candidate, "unexpected": self.candidate[NAMES[0]]}):
            with self.subTest(keys=list(mapping)):
                with self.assertRaises(self.driver.CheckError):
                    self.driver.compare_objects(self.baseline, mapping)

    def test_empty_object_fails(self):
        self.candidate[NAMES[1]].write_bytes(b"")
        with self.assertRaisesRegex(self.driver.CheckError, "empty"):
            self.driver.compare_objects(self.baseline, self.candidate)

    def test_baseline_candidate_same_path_and_hardlink_fail(self):
        self.candidate[NAMES[0]] = self.baseline[NAMES[0]]
        with self.assertRaisesRegex(self.driver.CheckError, "alias"):
            self.driver.compare_objects(self.baseline, self.candidate)
        linked = self.root / "linked"
        os.link(self.baseline[NAMES[0]], linked)
        self.candidate[NAMES[0]] = linked
        with self.assertRaisesRegex(self.driver.CheckError, "alias"):
            self.driver.compare_objects(self.baseline, self.candidate)

    def test_symlink_and_unreadable_missing_file_fail(self):
        path = self.candidate[NAMES[0]]
        path.unlink()
        path.symlink_to(self.baseline[NAMES[0]])
        with self.assertRaises(self.driver.CheckError):
            self.driver.compare_objects(self.baseline, self.candidate)
        path.unlink()
        with self.assertRaises(self.driver.CheckError):
            self.driver.compare_objects(self.baseline, self.candidate)

    def test_identical_objects_report_exact_verdicts(self):
        self.assertEqual(self.driver.compare_objects(dict(self.baseline), dict(self.candidate)),
                         {name: "exact" for name in NAMES})

    def test_helper_environment_owns_temporary_files_and_restores_ambient_state(self):
        previous = dict(os.environ)
        previous_directory = tempfile.tempdir
        private = self.root / "helper-temporary"
        private.mkdir(mode=0o700)
        with self.driver.helper_environment({"TMPDIR": str(private), "PATH": previous["PATH"]}):
            self.assertEqual(dict(os.environ), {"TMPDIR": str(private), "PATH": previous["PATH"]})
            with tempfile.TemporaryDirectory() as created:
                self.assertEqual(Path(created).parent, private)
        self.assertEqual(dict(os.environ), previous)
        self.assertEqual(tempfile.tempdir, previous_directory)


class CanonicalBtfTests(unittest.TestCase):
    """The BTF-order fallback accepts permutations and nothing else.

    The BTF emitter permutes type order between identical-input builds
    (27-byte .BTF-only diffs observed on real objects). The fallback must
    accept exactly that shape: identical sections, same .BTF size, same
    string set, same sorted C dump, same line records, and func_info
    differing only in type IDs. Synthetic minimal ELFs keep the cases
    hermetic; the bpftool leg is injected (the real dump is exercised by
    the unhappy-path and live fallen-back comparisons).
    """

    def setUp(self):
        self.driver = load_path(SCRIPT)
        self.temporary = tempfile.TemporaryDirectory(prefix="bpf-canonical-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    @staticmethod
    def elf(sections):
        import struct
        names = list(sections)
        shstrtab = b"\x00"
        offsets = {}
        for name in names + [".shstrtab"]:
            offsets[name] = len(shstrtab)
            shstrtab += name.encode("ascii") + b"\x00"
        blob = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        blob += struct.pack("<HHIQQQIHHHHHH", 1, 247, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
        assert len(blob) == 64
        bodies = {name: sections[name] for name in names}
        bodies[".shstrtab"] = shstrtab
        layout = {}
        for name, body in bodies.items():
            layout[name] = (len(blob), len(body))
            blob += body
        shoff = len(blob)
        headers = [b"\x00" * 64]
        for name in list(bodies):
            offset, size = layout[name]
            headers.append(struct.pack("<IIQQQQIIQQ", offsets[name], 1, 0, 0, offset, size,
                                       0, 0, 1, 0))
        shstrndx = len(headers) - 1
        blob += b"".join(headers)
        struct.pack_into("<Q", blob, 0x28, shoff)
        struct.pack_into("<H", blob, 0x3C, len(headers))
        struct.pack_into("<H", blob, 0x3E, shstrndx)
        return bytes(blob)

    @staticmethod
    def btf(type_bytes, strings):
        import struct
        strtab = b"\x00" + b"\x00".join(strings) + b"\x00"
        header = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(type_bytes),
                             len(type_bytes), len(strtab))
        return header + type_bytes + strtab

    @staticmethod
    def btf_ext(func_records, line_bytes=b"line-bytes"):
        import struct
        func_area = struct.pack("<II", 0, len(func_records)) + b"".join(
            struct.pack("<II", insn, type_id) for insn, type_id in func_records)
        header = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(func_area),
                             len(func_area), len(line_bytes))
        return header + func_area + line_bytes

    def pair(self, left_sections, right_sections):
        left = {name: self.root / f"baseline-{name}" for name in NAMES}
        right = {name: self.root / f"candidate-{name}" for name in NAMES}
        for name in NAMES:
            left[name].write_bytes(self.elf(left_sections))
            right[name].write_bytes(self.elf(right_sections))
        return left, right

    def test_permuted_btf_types_pass_with_btf_order_only_verdict(self):
        btf_left = self.btf(b"AAAABBBB", [b"alpha", b"beta"])
        btf_right = self.btf(b"BBBBAAAA", [b"alpha", b"beta"])
        ext = self.btf_ext([(8, 3), (16, 4)])
        sections = {".text": b"code", ".BTF": btf_left, ".BTF.ext": ext}
        flipped = {".text": b"code", ".BTF": btf_right, ".BTF.ext": ext}
        left, right = self.pair(sections, flipped)
        dump = lambda path, name: "struct alpha;\nstruct beta;\n"  # noqa: E731
        self.assertEqual(self.driver.compare_objects(left, right, dump_c=dump),
                         {name: "btf-order-only" for name in NAMES})

    def test_flipped_func_type_ids_fail_closed(self):
        # .BTF.ext compares byte-exact: a flip reaching func-referenced
        # types fails loudly instead of being silently normalized.
        ext_left = self.btf_ext([(8, 3), (16, 4)])
        ext_right = self.btf_ext([(8, 4), (16, 3)])
        sections = {".text": b"code", ".BTF": self.btf(b"TTTT", [b"a"]),
                    ".BTF.ext": ext_left}
        flipped = {".text": b"code", ".BTF": self.btf(b"TTTT", [b"a"]),
                   ".BTF.ext": ext_right}
        left, right = self.pair(sections, flipped)
        with self.assertRaisesRegex(self.driver.CheckError, NAMES[0]):
            self.driver.compare_objects(left, right, dump_c=lambda path, name: "same")

    def test_changed_section_byte_fails(self):
        good = {".text": b"code", ".BTF": self.btf(b"TTTT", [b"a"]), ".BTF.ext": self.btf_ext([])}
        bad = dict(good, **{".text": b"codf"})
        left, right = self.pair(good, bad)
        with self.assertRaisesRegex(self.driver.CheckError, NAMES[0]):
            self.driver.compare_objects(left, right, dump_c=lambda path, name: "same")

    def test_renamed_btf_string_fails(self):
        good = {".text": b"code", ".BTF": self.btf(b"TTTT", [b"alpha"]),
                ".BTF.ext": self.btf_ext([])}
        renamed = {".text": b"code", ".BTF": self.btf(b"TTTT", [b"alphb"]),
                   ".BTF.ext": self.btf_ext([])}
        left, right = self.pair(good, renamed)
        with self.assertRaisesRegex(self.driver.CheckError, NAMES[0]):
            self.driver.compare_objects(left, right, dump_c=lambda path, name: "same")

    def test_changed_c_dump_fails(self):
        # Permuted type bytes force the fallback; only the C dump disagrees.
        sections = {".text": b"code", ".BTF": self.btf(b"AAAABBBB", [b"a"]),
                    ".BTF.ext": self.btf_ext([])}
        flipped = {".text": b"code", ".BTF": self.btf(b"BBBBAAAA", [b"a"]),
                   ".BTF.ext": self.btf_ext([])}
        left, right = self.pair(sections, flipped)
        def dump(path, name):
            return "dump-a" if "baseline" in str(path) else "dump-b"
        with self.assertRaisesRegex(self.driver.CheckError, NAMES[0]):
            self.driver.compare_objects(left, right, dump_c=dump)

    def test_changed_line_records_fail(self):
        good = {".text": b"code", ".BTF": self.btf(b"TTTT", [b"a"]),
                ".BTF.ext": self.btf_ext([], line_bytes=b"line-one")}
        bad = {".text": b"code", ".BTF": self.btf(b"TTTT", [b"a"]),
               ".BTF.ext": self.btf_ext([], line_bytes=b"line-two")}
        left, right = self.pair(good, bad)
        with self.assertRaisesRegex(self.driver.CheckError, NAMES[0]):
            self.driver.compare_objects(left, right, dump_c=lambda path, name: "same")

    def test_malformed_fallback_inputs_fail_closed(self):
        good_btf = self.btf(b"TTTT", [b"a"])
        good_ext = self.btf_ext([(8, 3)])
        good = {".text": b"code", ".BTF": good_btf, ".BTF.ext": good_ext}
        bad_magic = b"\x00\x00" + good_btf[2:]
        truncated_ext = good_ext[:10]
        for label, bad in [("btf-magic", dict(good, **{".BTF": bad_magic})),
                           ("btf-size", dict(good, **{".BTF": good_btf + b"tail"})),
                           ("ext-truncated", dict(good, **{".BTF.ext": truncated_ext})),
                           ("ext-unpaired", {".text": b"code", ".BTF": good_btf})]:
            with self.subTest(label=label):
                left, right = self.pair(good, bad)
                with self.assertRaisesRegex(self.driver.CheckError, NAMES[0]):
                    self.driver.compare_objects(left, right, dump_c=lambda path, name: "same")
        garbage = self.root / "garbage"
        garbage.write_bytes(b"not an ELF object at all" + b"\x00" * 64)
        left = dict(self.pair(good, good)[0])
        right = dict(self.pair(good, good)[1])
        right[NAMES[1]] = garbage
        with self.assertRaisesRegex(self.driver.CheckError, NAMES[1]):
            self.driver.compare_objects(left, right, dump_c=lambda path, name: "same")

    def test_failing_dump_fails_closed_naming_the_object(self):
        sections = {".text": b"code", ".BTF": self.btf(b"TTTT", [b"a"]),
                    ".BTF.ext": self.btf_ext([])}
        left, right = self.pair(sections, dict(sections, **{".text": b"codX"}))
        def dump(path, name):
            raise self.driver.CheckError("bpftool is required for BTF-order adjudication")
        with self.assertRaisesRegex(self.driver.CheckError, NAMES[0]):
            self.driver.compare_objects(left, right, dump_c=dump)


class BuildDriverTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "the noninterference driver is missing")
        self.temporary = tempfile.TemporaryDirectory(prefix="bpf-driver-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.control = self.root / "control.json"
        self.sysroot = self.root / "nightly-sysroot"
        self.nightly_library = self.sysroot / "lib/rustlib/src/rust/library"
        (self.nightly_library / "sysroot").mkdir(parents=True)
        (self.nightly_library / "sysroot/Cargo.toml").write_text("nightly sysroot manifest\n")
        (self.nightly_library / "Cargo.lock").write_text("nightly sysroot lock\n")
        self.control.write_text(json.dumps({"sysroot": str(self.sysroot)}), encoding="utf-8")
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                                BPF_FIXTURE_CONTROL=str(self.control),
                                BPF_FIXTURE_LOG=str(self.root / "calls.jsonl"))
        fixture = ROOT / "tests/fixtures/bpf-noninterference/fake-tool.py"
        self.assertTrue(fixture.is_file(), "the fake command fixture is missing")
        for name in ("cargo", "rustc", "rustup", "clang-18", "bpf-linker", "bpftool", "llvm-readelf", "dpkg-query"):
            shutil.copy2(fixture, self.bin / name)
            (self.bin / name).chmod(0o755)
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/cargo.sh").write_text(
            '#!/bin/sh\nset -eu\ncd "$(dirname "$0")/.."\nexec cargo "$@"\n', encoding="utf-8")
        (self.repo / "scripts/cargo.sh").chmod(0o755)
        (self.repo / "scripts/prepare-dependencies.py").write_text(
            'import os\nfrom pathlib import Path\nPath("prepared").write_text("yes")\n', encoding="utf-8")
        (self.repo / "crates/ebpf").mkdir(parents=True)
        (self.repo / "Cargo.toml").write_text('[package]\nname="p11scope"\nversion="0.3.0"\n', encoding="utf-8")
        (self.repo / "Cargo.lock").write_text("root lock\n", encoding="utf-8")
        (self.repo / "crates/ebpf/Cargo.lock").write_text("bpf lock\n", encoding="utf-8")
        (self.repo / "crates/ebpf/Cargo.toml").write_text("bpf manifest\n", encoding="utf-8")
        (self.repo / ".release-rust-version").write_text("1.98.1\n", encoding="utf-8")
        (self.repo / "build_support").mkdir()
        self.write_compiler_guard("1.98.1", "48a229ceaefd4985c50990b14116b6d856af0985")
        (self.repo / "object-source").write_text("unchanged", encoding="utf-8")
        self.git("init", "-q")
        self.git("add", ".")
        self.baseline = self.commit("baseline")
        (self.repo / "unrelated").write_text("host change", encoding="utf-8")
        self.git("add", ".")
        self.candidate = self.commit("candidate")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, message):
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def configure(self, **values):
        values.setdefault("sysroot", str(self.sysroot))
        values.setdefault("dispatcher", str(self.bin / "cargo"))
        self.control.write_text(json.dumps(values), encoding="utf-8")

    def write_compiler_guard(self, release, commit):
        (self.repo / "build_support/semantic_rustc.rs").write_text(
            f'pub const RELEASE: &str = "{release}";\n'
            f'pub const COMMIT: &str = "{commit}";\n', encoding="utf-8")

    def transition_candidate(self):
        (self.repo / ".release-rust-version").write_text("1.99.1\n", encoding="utf-8")
        self.write_compiler_guard("1.99.1", "58cf8f9c35b355199727627d07ae34a4e2846d67")
        self.git("add", ".")
        self.candidate = self.commit("candidate host compiler transition")
        directories = {}
        for channel in ("1.98.1", "1.99.1", "nightly-2026-05-20"):
            directory = self.root / "toolchains" / channel
            directory.mkdir(parents=True)
            for tool in ("cargo", "rustc"):
                shutil.copy2(self.bin / tool, directory / tool)
            directories[channel] = str(directory)
        self.configure(toolchain_dirs=directories)

    def invoke(self, repeat=False, work=None, payloads=(), script=None,
               transition=False, fixture_baseline=False):
        self.work = work or self.root / "work"
        command = [sys.executable, "-I", str(script or SCRIPT), "--repo", str(self.repo),
                   "--baseline", self.baseline, "--candidate", self.baseline if repeat else self.candidate,
                   "--work", str(self.work)]
        if repeat:
            command.append("--repeat-baseline")
        if transition:
            command.append("--host-compiler-transition")
        for flag, payload in zip(("--baseline-offline-payload", "--candidate-offline-payload"), payloads):
            command += [flag, str(payload)]
        if fixture_baseline:
            # The tiny real Git fixture cannot have the historical product's
            # SHA. Patch only that reviewed selector, retaining the actual
            # driver's acquisition, metadata validation, builds and comparison.
            body = (f"import sys; from pathlib import Path; sys.path.insert(0, {str(ROOT / 'scripts')!r}); "
                    "from _loader import load_path; "
                    f"driver=load_path(Path({str(script or SCRIPT)!r})); "
                    f"driver.HOST_TRANSITION_BASELINE={self.baseline!r}; "
                    f"sys.argv={command[2:]!r}; raise SystemExit(driver.main())")
            command = [sys.executable, "-I", "-c", body]
        return subprocess.run(command, env=self.environment, text=True, capture_output=True, timeout=30)

    def payload_fixture(self):
        module = load_path(ROOT / "tests/python/test_offline_dependencies.py")
        fixture_root = self.root / "offline-fixture"
        fixture_root.mkdir()
        # Validate a real bundle of this tiny fixture's history. Using the
        # product HEAD makes repeated unbundle/fsck work grow with that repo.
        fixture = module.OfflineFixture(fixture_root, shared_repository=self.repo)
        fixture.testcase = self
        fixture.assemble()
        fixture.approve()
        for relative in ("scripts", "third-party", "crates"):
            shutil.copytree(fixture.root / relative, self.repo / relative, dirs_exist_ok=True)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(fixture.root / name, self.repo / name)
        shutil.rmtree(self.repo / "third-party/src")
        (self.repo / "third-party/.prepare-dependencies.lock").unlink()
        # Raw archived snapshots cannot use the public origin wrapper. The
        # coordinator's reviewed helper, rather than this snapshot file, runs.
        (self.repo / "scripts/offline-dependencies.py").write_text("raise RuntimeError('snapshot helper executed')\n")
        self.git("add", ".")
        self.baseline = self.commit("payload baseline")
        (self.repo / "unrelated").write_text("payload candidate")
        self.git("add", ".")
        self.candidate = self.commit("payload candidate")
        self.configure(sysroot=str(fixture.sysroot))
        return fixture

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_rustup_identity_probes(self):
        banner = "rustup 1.29.1 (d95a37b6a 2026-08-13)"
        for side in ("baseline", "candidate"):
            evidence = self.work / side
            commands = [json.loads(line) for line in (evidence / "commands.jsonl").read_text().splitlines()]
            for label in ("tools-before", "tools-after"):
                tools = json.loads((evidence / (label + ".json")).read_text())
                self.assertEqual(tools["rustup"]["version"], banner)
                own = next(command for command in commands
                           if command["stdout"] == str(evidence / (label + "-version-rustup.stdout")))
                self.assertEqual(own["argv"], ["rustup", "--help"])
                self.assertEqual(own["status"], 0)
                self.assertTrue(Path(own["stdout"]).read_text().startswith(banner + "\n\n"))
                self.assertIn("Usage: rustup", Path(own["stdout"]).read_text())
                self.assertEqual(Path(own["stderr"]).read_bytes(), b"")
                for channel in ("1.98.1", "nightly-2026-05-20"):
                    for tool in ("cargo", "rustc"):
                        expected = ["rustup", "which", "--toolchain", channel, tool]
                        self.assertTrue(any(command["argv"] == expected and command["status"] == 0
                                            for command in commands))
                        probe = [tools[channel + "-" + tool]["path"], "-vV" if tool == "rustc" else "--version"]
                        self.assertTrue(any(command["argv"] == probe and command["status"] == 0
                                            for command in commands))
            self.assertTrue(any(command["argv"] == [tools["nightly-2026-05-20-rustc"]["path"], "--print", "sysroot"]
                                and command["status"] == 0 for command in commands))
        rustup_calls = [call["argv"] for call in self.calls() if call["tool"] == "rustup"]
        self.assertEqual(rustup_calls.count(["--help"]), 4)
        self.assertNotIn(["--version"], rustup_calls)

    def test_fresh_snapshots_use_distinct_targets_and_keep_distinct_evidence(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_rustup_identity_probes()
        receipt = json.loads((self.work / "comparison.json").read_text())
        self.assertEqual(receipt["mode"], "integration")
        self.assertEqual(receipt["baseline"], self.baseline)
        self.assertEqual(receipt["candidate"], self.candidate)
        self.assertEqual(receipt["matched_objects"], list(NAMES))
        builds = [call for call in self.calls() if call["tool"] == "cargo" and "build" in call["argv"]]
        self.assertEqual(len(builds), 2)
        self.assertNotEqual(builds[0]["cwd"], builds[1]["cwd"])
        self.assertNotEqual(builds[0]["target"], builds[1]["target"])
        self.assertNotEqual(builds[0]["build_dir"], builds[1]["build_dir"])
        for call in builds:
            self.assertTrue(call["fresh"], "the source/build scratch was reused")
            self.assertTrue(call["home_fresh"], "the private Cargo home was reused")
            self.assertEqual(call["offline"], "true", "nested Cargo must also be offline")
            self.assertIn("--offline", call["argv"])
            self.assertIn("--no-default-features", call["argv"])
        for side in ("baseline", "candidate"):
            self.assertEqual(set(p.name for p in (self.work / side / "objects").iterdir()), set(NAMES))
            snapshot = json.loads((self.work / side / "snapshot.json").read_text())
            self.assertEqual(set(snapshot["lockfiles"]), {"Cargo.lock", "crates/ebpf/Cargo.lock"})
        self.assertEqual(self.git("status", "--porcelain"), "", "driver mutated its input repository")

    def test_repeat_baseline_is_explicit_diagnostic_evidence(self):
        result = self.invoke(repeat=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads((self.work / "comparison.json").read_text())["mode"], "repeat-baseline")

    def test_host_compiler_transition_selects_exact_tools_and_preserves_shared_universe(self):
        self.transition_candidate()
        result = self.invoke(transition=True, fixture_baseline=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads((self.work / "comparison.json").read_text())
        self.assertEqual(receipt["mode"], "host-compiler-transition")
        self.assertEqual(receipt["host_compilers"]["baseline"]["release"], "1.98.1")
        self.assertEqual(receipt["host_compilers"]["baseline"]["commit"],
                         "48a229ceaefd4985c50990b14116b6d856af0985")
        self.assertEqual(receipt["host_compilers"]["candidate"]["release"], "1.99.1")
        self.assertEqual(receipt["host_compilers"]["candidate"]["commit"],
                         "58cf8f9c35b355199727627d07ae34a4e2846d67")
        snapshots = [json.loads((self.work / side / "snapshot.json").read_text())
                     for side in ("baseline", "candidate")]
        self.assertEqual(snapshots[0]["tools"], snapshots[1]["tools"])
        self.assertEqual(snapshots[0]["nightly_source"], snapshots[1]["nightly_source"])
        for snapshot, release in zip(snapshots, ("1.98.1", "1.99.1")):
            self.assertEqual(snapshot["host_compiler"]["release"], release)
            remaps = snapshot["build_environment"]["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
            self.assertEqual([flag.rsplit("=", 1)[1] for flag in remaps],
                             ["/p11scope", "/p11scope-build", "/cargo", "/rustup"])
            for channel in ("1.98.1", "1.99.1", "nightly-2026-05-20"):
                for tool in ("cargo", "rustc"):
                    self.assertIn(channel + "-" + tool, snapshot["tools"])
        builds = [call for call in self.calls() if call["tool"] == "cargo" and "build" in call["argv"]]
        self.assertEqual(len(builds), 2)
        for build, snapshot in zip(builds, snapshots):
            host = snapshot["host_compiler"]
            self.assertEqual(build["executable"], host["cargo"]["path"])
            self.assertEqual(build["rustc"], host["rustc"]["path"])
            self.assertTrue(build["fresh"])
            self.assertTrue(build["home_fresh"])
        self.assertNotEqual(builds[0]["target"], builds[1]["target"])
        self.assertIn("host compiler transition", result.stdout)
        self.assertEqual(receipt["matched_objects"], list(NAMES))

    def test_host_compiler_transition_requires_opt_in_and_exact_real_baseline(self):
        self.transition_candidate()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release Rust compiler", result.stderr)
        result = self.invoke(transition=True, work=self.root / "wrong-baseline")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reviewed historical baseline", result.stderr)
        self.assertFalse((self.work / "comparison.json").exists())

    def test_host_compiler_transition_cannot_relabel_repeat_control(self):
        self.transition_candidate()
        result = self.invoke(repeat=True, transition=True, fixture_baseline=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repeat-baseline", result.stderr)
        self.assertFalse((self.work / "comparison.json").exists())

    def test_selected_host_compiler_commit_is_validated_before_acquisition(self):
        self.configure(host_metadata={"1.98.1":
            "rustc 1.98.1\nrelease: 1.98.1\ncommit-hash: wrong\nhost: x86_64-unknown-linux-gnu"})
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host compiler metadata", result.stderr)
        self.assertFalse(any(call["tool"] == "cargo" and ("fetch" in call["argv"] or "build" in call["argv"])
                             for call in self.calls()))

    def test_host_compiler_transition_rejects_unreviewed_pin_or_guard(self):
        self.transition_candidate()
        for index, (release, guard_release, commit) in enumerate((
                ("1.98.1", "1.98.1", "48a229ceaefd4985c50990b14116b6d856af0985"),
                ("1.100.0", "1.100.0", "58cf8f9c35b355199727627d07ae34a4e2846d67"),
                ("1.99.1", "1.98.1", "48a229ceaefd4985c50990b14116b6d856af0985"),
                ("1.99.1", "1.99.1", "wrong"))):
            with self.subTest(release=release, guard_release=guard_release, commit=commit):
                (self.repo / ".release-rust-version").write_text(release + "\n")
                self.write_compiler_guard(guard_release, commit)
                self.git("add", ".")
                self.candidate = self.commit("unreviewed compiler " + str(index))
                result = self.invoke(transition=True, fixture_baseline=True,
                                     work=self.root / ("unreviewed-" + str(index)))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("compiler", result.stderr)
                self.assertFalse((self.work / "comparison.json").exists())
        self.assertFalse(any(call["tool"] == "cargo" and ("fetch" in call["argv"] or "build" in call["argv"])
                             for call in self.calls()))

    def test_host_compiler_transition_still_rejects_shared_tool_and_object_drift(self):
        self.transition_candidate()
        (self.repo / "object-source").write_text("real fixture source change")
        self.git("add", ".")
        self.candidate = self.commit("changed object producer source")
        clang = self.bin / "clang-18"
        original = clang.read_bytes()
        for index, control in enumerate(({"change_tool": True}, {"mutate_flavor": NAMES[0]})):
            with self.subTest(control=control):
                clang.write_bytes(original)
                configuration = json.loads(self.control.read_text())
                self.configure(toolchain_dirs=configuration["toolchain_dirs"], **control)
                result = self.invoke(transition=True, fixture_baseline=True,
                                     work=self.root / ("transition-drift-" + str(index)))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("tool identity" if index == 0 else NAMES[0], result.stderr)
                self.assertFalse((self.work / "comparison.json").exists())

    def test_invalid_rustup_help_banner_fails_before_acquisition(self):
        for index, help_text in enumerate((
                "", "rustup\n", "rustc 1.29.1\n", "rustup version 1.29.1\n",
                "rustup 1.29\n", "rustup 1.29.1 prose\n", "\nrustup 1.29.1\n",
                "rustup 1.29.1 (not-a-build)\n", "rustup 1.29.1\x00\n", "rustup 1.29.1\r\n",
                "rustup 1.29.1\n\x1b[31mhelp\n", "rustup 1.29.1\x85rustup 1.29.1\n")):
            with self.subTest(help_text=help_text):
                self.configure(rustup_help=help_text)
                result = self.invoke(work=self.root / ("bad-help-" + str(index)))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid rustup version banner", result.stderr)
                self.assertEqual((self.work / "baseline/tools-before-version-rustup.stdout").read_bytes(),
                                 help_text.encode())
                self.assertFalse((self.work / "baseline/source.tar").exists())
                self.assertFalse((self.work / "comparison.json").exists())
        self.assertFalse(any(call["tool"] == "cargo" and ("fetch" in call["argv"] or "build" in call["argv"])
                             for call in self.calls()))

    def test_rustup_banner_accepts_other_numeric_releases_and_optional_build_suffix(self):
        for index, banner in enumerate(("rustup 2.30.1", "rustup 3.4.5 (012345678abcdef 2026-10-09)")):
            with self.subTest(banner=banner):
                self.configure(rustup_help=banner + "\n\nUsage: rustup [OPTIONS] [COMMAND]\n")
                result = self.invoke(work=self.root / ("valid-help-" + str(index)))
                self.assertEqual(result.returncode, 0, result.stderr)
                for side in ("baseline", "candidate"):
                    tools = json.loads((self.work / side / "tools-before.json").read_text())
                    self.assertEqual(tools["rustup"]["version"], banner)

    def test_failed_rustup_help_cannot_recover_a_valid_banner(self):
        self.configure(rustup_help_status=23)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tools-before-version-rustup failed (status=23", result.stderr)
        output = self.work / "baseline/tools-before-version-rustup.stdout"
        self.assertTrue(output.read_bytes().startswith(b"rustup 1.29.1 (d95a37b6a 2026-08-13)\n"))
        self.assertFalse((self.work / "baseline/source.tar").exists())
        self.assertFalse((self.work / "comparison.json").exists())
        self.assertFalse(any(call["tool"] == "cargo" and ("fetch" in call["argv"] or "build" in call["argv"])
                             for call in self.calls()))

    def test_rustup_content_and_accepted_version_drift_fail(self):
        manager = self.bin / "rustup"
        original = manager.read_bytes()
        for mutation in ("change_rustup_content", "change_rustup_version"):
            with self.subTest(mutation=mutation):
                manager.write_bytes(original)
                self.configure(**{mutation: True})
                result = self.invoke(work=self.root / mutation)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("tool identity changed", result.stderr)
                evidence = self.work / "baseline"
                before = json.loads((evidence / "tools-before.json").read_text())
                after = json.loads((evidence / "tools-after.json").read_text())
                self.assertNotEqual(before["rustup"], after["rustup"])
                field = "sha256" if mutation == "change_rustup_content" else "version"
                unchanged = "version" if field == "sha256" else "sha256"
                self.assertNotEqual(before["rustup"][field], after["rustup"][field])
                self.assertEqual(before["rustup"][unchanged], after["rustup"][unchanged])
                self.assertFalse((self.work / "comparison.json").exists())

    def test_normal_acquisition_fetches_selected_nightly_sysroot_before_offline_build(self):
        self.configure(require_sysroot=True)
        paths = (self.nightly_library / "sysroot/Cargo.toml", self.nightly_library / "Cargo.lock")
        original = {path: path.read_bytes() for path in paths}
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        fetches = [call for call in self.calls() if call["tool"] == "cargo" and "fetch" in call["argv"]]
        self.assertEqual(len(fetches), 6)
        for start in (0, 3):
            root, bpf, sysroot = fetches[start:start + 3]
            self.assertEqual(root["argv"][-1], "Cargo.toml")
            self.assertEqual(bpf["argv"][-1], "crates/ebpf/Cargo.toml")
            self.assertEqual(sysroot["argv"][0], "+nightly-2026-05-20")
            self.assertIn("--locked", sysroot["argv"])
            self.assertEqual(sysroot["argv"][-1], str(paths[0]))
            self.assertNotIn("--offline", sysroot["argv"])
            self.assertIsNone(sysroot["offline"])
        for side in ("baseline", "candidate"):
            receipt = json.loads((self.work / side / "snapshot.json").read_text())
            self.assertEqual(receipt["nightly_source"]["manifest"], str(paths[0]))
            self.assertEqual(receipt["nightly_source"]["lock"], str(paths[1]))
            self.assertIn("manifest_sha256", receipt["nightly_source"])
            self.assertIn("lock_sha256", receipt["nightly_source"])
        self.assertEqual({path: path.read_bytes() for path in paths}, original)

    def test_missing_sysroot_fetch_cannot_complete_an_offline_build(self):
        self.configure(require_sysroot=True, skip_sysroot_fetch=True)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("build failed", result.stderr)
        self.assertIn("sysroot fetch", (self.work / "baseline/build.stderr").read_text())
        self.assertTrue(any(call["tool"] == "cargo" and "fetch" in call["argv"]
                            and call["argv"][-1] == str(self.nightly_library / "sysroot/Cargo.toml")
                            for call in self.calls()))
        self.assertFalse((self.work / "comparison.json").exists())

    def test_selected_nightly_manifest_and_lock_changes_fail(self):
        for field in ("manifest", "lock"):
            with self.subTest(field=field):
                self.configure(change_sysroot=field)
                result = self.invoke(work=self.root / ("changed-nightly-" + field))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("nightly source", result.stderr)

    def test_selected_nightly_source_changes_between_snapshots_fail(self):
        self.configure(change_sysroot_at_query=3)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nightly source changed between", result.stderr)
        builds = [call for call in self.calls() if call["tool"] == "cargo" and "build" in call["argv"]]
        self.assertEqual(len(builds), 2)
        self.assertFalse((self.work / "comparison.json").exists())

    def test_missing_nightly_source_fails_before_dependency_fetches(self):
        (self.nightly_library / "Cargo.lock").unlink()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nightly", result.stderr)
        self.assertFalse(any(call["tool"] == "cargo" and "fetch" in call["argv"] for call in self.calls()))

    def test_payload_inputs_require_pair_before_commands(self):
        result = self.invoke(payloads=(self.root,))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("both", result.stderr)
        self.assertFalse((self.root / "calls.jsonl").exists())

    def test_payload_paths_must_be_absolute_real_and_disjoint_from_owned_work(self):
        linked = self.root / "linked-payload"
        linked.symlink_to(self.repo, target_is_directory=True)
        for payload in (Path("relative-payload"), linked, self.root):
            with self.subTest(payload=payload):
                result = self.invoke(payloads=(payload, payload))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("offline payload", result.stderr)
                self.assertFalse((self.root / "calls.jsonl").exists())

    def test_payload_mode_keeps_ambient_cargo_config_refusal(self):
        fixture = self.payload_fixture()
        config = self.root / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text('[build]\nrustflags=["--cfg", "poison"]\n')
        result = self.invoke(payloads=(fixture.output, fixture.output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cargo configuration", result.stderr)
        self.assertFalse(any(call["tool"] == "cargo" and "fetch" in call["argv"] for call in self.calls()))

    def test_payload_mode_uses_full_validator_copied_inputs_fresh_home_and_offline_fetches(self):
        shared_revision = self.candidate
        fixture = self.payload_fixture()
        self.assertEqual(fixture.shared_revision, shared_revision)
        self.configure(sysroot=str(fixture.sysroot), require_sysroot=True)
        helper = load_path(ROOT / "scripts/offline-dependencies.py")
        original = helper.payload_inventory(fixture.output)
        result = self.invoke(payloads=(fixture.output, fixture.output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_rustup_identity_probes()
        self.assertEqual(helper.payload_inventory(fixture.output), original)
        self.assertEqual(self.git("status", "--porcelain"), "")
        builds = [call for call in self.calls() if call["tool"] == "cargo" and "build" in call["argv"]]
        self.assertEqual(len(builds), 2)
        self.assertTrue(all(call["home_fresh"] for call in builds))
        self.assertEqual(
            builds[0]["config"].replace(str(self.work / "baseline-scratch"), "@OWNED_SCRATCH@"),
            builds[1]["config"].replace(str(self.work / "candidate-scratch"), "@OWNED_SCRATCH@"))
        for call, side in zip(builds, ("baseline", "candidate")):
            self.assertIn(str(self.work / (side + "-scratch/offline-payload/vendor")), call["config"])
        fetches = [call for call in self.calls() if call["tool"] == "cargo" and "fetch" in call["argv"]]
        self.assertEqual(len(fetches), 6)
        for call in self.calls():
            if call["tool"] == "cargo" and "fetch" in call["argv"]:
                self.assertIn("--offline", call["argv"])
                self.assertEqual(call["offline"], "true")
        for side in ("baseline", "candidate"):
            receipt = json.loads((self.work / side / "snapshot.json").read_text())
            self.assertEqual(receipt["acquisition_mode"], "verified-payload")
            self.assertEqual(receipt["offline_payload"]["supplied"]["payload_tree_sha256"],
                             receipt["offline_payload"]["copied"]["payload_tree_sha256"])
            self.assertEqual(set(receipt["coordinator"]),
                             {"check-bpf-noninterference.py", "offline-dependencies.py", "_loader.py"})

    def test_symlinked_checker_loads_only_the_receipted_canonical_payload_helper(self):
        fixture = self.payload_fixture()
        alias_directory = self.root / "checker-alias"
        alias_directory.mkdir()
        alias = alias_directory / "check-bpf-noninterference.py"
        alias.symlink_to(SCRIPT)
        marker = self.root / "unbound-helper-executed"
        decoy = alias_directory / "offline-dependencies.py"
        canonical = ROOT / "scripts/offline-dependencies.py"
        decoy.write_text(
            "from pathlib import Path\nfrom _loader import load_path\n"
            f"Path({str(marker)!r}).write_text('unbound helper executed')\n"
            f"helper = load_path(Path({str(canonical)!r}))\n"
            "for name in ('_verify_payload_contents', 'payload_inventory', '_copy_regular', "
            "'replacement_config', 'OfflineDependencyError'):\n"
            "    globals()[name] = getattr(helper, name)\n",
            encoding="utf-8",
        )
        result = self.invoke(script=alias, payloads=(fixture.output, fixture.output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists(), "an unreceipted adjacent helper executed")
        for side in ("baseline", "candidate"):
            receipt = json.loads((self.work / side / "snapshot.json").read_text())
            self.assertEqual(receipt["coordinator"]["offline-dependencies.py"]["path"],
                             str(canonical))

    def test_payload_copy_and_config_mutations_fail_without_touching_supplied_payload(self):
        fixture = self.payload_fixture()
        helper = load_path(ROOT / "scripts/offline-dependencies.py")
        original = helper.payload_inventory(fixture.output)
        for mutation, expected in (("change_payload", "checksum"), ("change_config", "configuration")):
            self.configure(sysroot=str(fixture.sysroot), **{mutation: True})
            result = self.invoke(work=self.root / mutation, payloads=(fixture.output, fixture.output))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
            self.assertEqual(helper.payload_inventory(fixture.output), original)

    def test_canonical_coordinator_helper_content_drift_is_refused(self):
        fixture = self.payload_fixture()
        coordinator = self.root / "owned-coordinator"
        coordinator.mkdir()
        for name in ("check-bpf-noninterference.py", "offline-dependencies.py", "_loader.py"):
            shutil.copy2(ROOT / "scripts" / name, coordinator / name)
        helper = coordinator / "offline-dependencies.py"
        self.configure(sysroot=str(fixture.sysroot), change_coordinator_helper=str(helper))
        result = self.invoke(script=coordinator / "check-bpf-noninterference.py",
                             payloads=(fixture.output, fixture.output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coordinator helper identity changed", result.stderr)
        self.assertFalse((self.work / "comparison.json").exists())

    def test_candidate_recipe_cannot_admit_baseline_payload(self):
        fixture = self.payload_fixture()
        recipe_path = self.repo / "third-party/offline-dependencies.json"
        recipe = json.loads(recipe_path.read_text())
        recipe["payload_tree_sha256"] = "0" * 64
        recipe_path.write_text(json.dumps(recipe))
        self.git("add", ".")
        self.candidate = self.commit("candidate with different payload closure")
        result = self.invoke(payloads=(fixture.output, fixture.output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("payload tree digest mismatch", result.stderr)
        builds = [call for call in self.calls() if call["tool"] == "cargo" and "build" in call["argv"]]
        self.assertEqual(len(builds), 1, "candidate refusal must precede its Cargo build")

    def test_equal_commits_without_diagnostic_flag_fail(self):
        self.candidate = self.baseline
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct", result.stderr)

    def test_existing_work_directory_is_refused(self):
        existing = self.root / "existing"
        existing.mkdir()
        keep = existing / "keep"
        keep.write_text("retain")
        self.assertNotEqual(self.invoke(work=existing).returncode, 0)
        self.assertEqual(keep.read_text(), "retain")

    def test_build_failure_and_failed_cargo_finished_message_fail(self):
        for control in ({"build_failure": True}, {"finished_failure": True}):
            with self.subTest(control=control):
                self.configure(**control)
                result = self.invoke(work=self.root / next(iter(control)))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.work / "comparison.json").exists())

    def test_missing_duplicate_foreign_outdir_and_empty_outputs_fail(self):
        for mode in ("missing", "duplicate", "foreign", "empty", "outside", "symlink"):
            with self.subTest(mode=mode):
                self.configure(output=mode)
                result = self.invoke(work=self.root / mode)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse((self.work / "comparison.json").exists())

    def test_changed_tool_after_first_build_fails(self):
        self.configure(change_tool=True)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tool", result.stderr)
        self.assertTrue((self.work / "baseline/p11scope-identity-build-info.txt").is_file(),
                        "available compiler receipt must survive a failed build qualification")

    def test_real_source_change_in_each_flavor_fails_comparison(self):
        for name in NAMES:
            with self.subTest(name=name):
                self.configure(mutate_flavor=name)
                (self.repo / "object-source").write_text("changed " + name, encoding="utf-8")
                self.git("add", ".")
                self.candidate = self.commit("mutated " + name)
                result = self.invoke(work=self.root / name)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertTrue((self.work / "candidate" / "sections.txt").is_file())

    def test_tracked_source_change_during_build_fails(self):
        self.configure(change_source=True)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked snapshot input changed", result.stderr)

    def test_cargo_json_malformed_or_no_selected_artifact_fails(self):
        for mode in ("malformed", "no-root-message", "no-finished-message"):
            with self.subTest(mode=mode):
                self.configure(output=mode)
                result = self.invoke(work=self.root / mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.work / "comparison.json").exists())

    def test_build_clears_inherited_diagnostic_and_cargo_overrides(self):
        self.environment.update({"RUSTFLAGS": "--cfg coverage", "RUSTC_WRAPPER": "missing-wrapper",
                                 "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "--cfg poison",
                                 "CARGO_PROFILE_RELEASE_DEBUG": "true", "CFLAGS": "-DPOISON",
                                 "P11SCOPE_SMALL_RING": "true", "P11SCOPE_SMALL_STATE_MAPS": "true",
                                 "P11SCOPE_SMALL_DISCOVERY_RING": "true"})
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for call in self.calls():
            if call["tool"] == "cargo" and "build" in call["argv"]:
                self.assertEqual(call["inherited_overrides"], {})

    def test_parent_cargo_configuration_is_refused(self):
        config = self.root / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text('[build]\nrustflags=["--cfg", "poison"]\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cargo configuration", result.stderr)

    def test_nested_bpf_parent_cargo_configuration_is_refused(self):
        config = self.repo / "crates/.cargo/config.toml"
        config.parent.mkdir()
        config.write_text('[build]\nrustflags=["--cfg", "poison"]\n')
        self.git("add", ".")
        self.candidate = self.commit("nested parent configuration")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cargo configuration", result.stderr)

    def test_duplicate_source_object_inodes_are_refused(self):
        self.configure(output="hardlink")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("alias", result.stderr)

    def distinct_selected_toolchain(self):
        selected = self.root / "selected-toolchain"
        selected.mkdir()
        for tool in ("cargo", "rustc"):
            shutil.copy2(self.bin / tool, selected / tool)
        return selected

    def test_actual_cargo_dispatcher_is_receipted_separately(self):
        selected = self.distinct_selected_toolchain()
        self.configure(toolchain_dir=str(selected))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        tools = json.loads((self.work / "baseline/tools-before.json").read_text())
        self.assertTrue("cargo" in tools, "actual PATH Cargo dispatcher is missing from the receipt")
        self.assertEqual(tools["cargo"]["path"], str(self.bin / "cargo"))
        self.assertEqual(tools["1.98.1-cargo"]["path"], str(selected / "cargo"))

    def test_changed_dispatcher_fails_with_unchanged_selected_toolchain(self):
        selected = self.distinct_selected_toolchain()
        self.configure(toolchain_dir=str(selected), change_dispatcher=True)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tool identity", result.stderr)

    def test_empty_or_relative_path_entries_fail_before_tools_run(self):
        original = self.environment["PATH"]
        for entry in ("", ".", "relative-tools"):
            with self.subTest(entry=entry):
                self.environment["PATH"] = entry + os.pathsep + original
                result = self.invoke(work=self.root / ("path-" + (entry or "empty")))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("PATH", result.stderr)
                self.assertFalse((self.root / "calls.jsonl").exists())

    def test_relative_path_decoy_cannot_split_receipt_and_execution(self):
        decoy = self.repo / "relative-tools/cargo"
        decoy.parent.mkdir()
        decoy.write_text('#!/bin/sh\necho "source-cwd decoy executed" >&2\nexit 61\n')
        decoy.chmod(0o755)
        self.git("add", ".")
        self.baseline = self.commit("source cwd Cargo decoy")
        (self.repo / "unrelated").write_text("distinct candidate")
        self.git("add", ".")
        self.candidate = self.commit("candidate with same decoy")
        self.environment["PATH"] = "relative-tools" + os.pathsep + self.environment["PATH"]
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PATH", result.stderr)
        self.assertFalse((self.root / "calls.jsonl").exists())


class WorkflowSequenceTests(unittest.TestCase):
    """Run the real CI comparison shell; replace only its expensive checker."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="bpf-workflow-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        repo = self.root / "repo"
        (repo / "scripts").mkdir(parents=True)
        (repo / "scripts/check-bpf-noninterference.py").write_text('''
import argparse, json, os
from pathlib import Path
p=argparse.ArgumentParser()
for key in ("repo", "baseline", "candidate", "work"):
    p.add_argument("--"+key, required=True)
p.add_argument("--repeat-baseline", action="store_true")
p.add_argument("--host-compiler-transition", action="store_true")
a=p.parse_args()
with Path(os.environ["CI_FIXTURE_LOG"]).open("a") as log:
    log.write(json.dumps(vars(a))+"\\n")
if a.repeat_baseline and os.environ.get("CI_FIXTURE_FAIL_CONTROL") == "true":
    raise SystemExit(23)
if a.host_compiler_transition == a.repeat_baseline:
    raise SystemExit("repeat needs old compiler; integration needs explicit transition")
work=Path(a.work)
work.mkdir()
if os.environ.get("CI_FIXTURE_MISSING_RECEIPT") != "true":
    (work/"comparison.json").write_text("{}\\n")
''', encoding="utf-8")
        self.env = dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_WORKSPACE=str(repo),
                        GITHUB_SHA="b" * 40, CI_FIXTURE_LOG=str(self.root / "calls.jsonl"))
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertTrue("\n  bpf-noninterference:\n" in ci, "required comparison job is absent")
        job = ci.split("\n  bpf-noninterference:\n", 1)[1].split("\n  contracts:\n", 1)[0]
        step = job.split("      - name: Compare complete default objects\n", 1)[1]
        body = step.split("        run: |\n", 1)[1].split("\n      - ", 1)[0]
        self.command = "\n".join(line[10:] for line in body.splitlines() if line.startswith("          "))

    def invoke(self, **environment):
        return subprocess.run(["bash", "-c", self.command],
                              cwd=self.env["GITHUB_WORKSPACE"],
                              env=dict(self.env, **environment), text=True, capture_output=True)

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def test_control_precedes_distinct_exact_candidate_comparison(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        control, integration = self.calls()
        baseline = "68c258cf54d736370e214172d187d7d3905a8bb5"
        self.assertEqual((control["baseline"], control["candidate"], control["repeat_baseline"]),
                         (baseline, baseline, True))
        self.assertEqual((integration["baseline"], integration["candidate"], integration["repeat_baseline"]),
                         (baseline, "b" * 40, False))
        self.assertFalse(control["host_compiler_transition"])
        self.assertTrue(integration["host_compiler_transition"])
        self.assertNotEqual(control["work"], integration["work"])

    def test_failed_control_stops_before_integration(self):
        result = self.invoke(CI_FIXTURE_FAIL_CONTROL="true")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls()), 1)

    def test_missing_comparison_receipt_cannot_pass(self):
        self.assertNotEqual(self.invoke(CI_FIXTURE_MISSING_RECEIPT="true").returncode, 0)


if __name__ == "__main__":
    unittest.main()
