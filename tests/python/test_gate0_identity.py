#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for scripts/check-gate0-identity.py (P2F-5 F3).

Drives the checker's real code on tiny owned BPF objects built with
clang-18: relocation enumeration covers both `.rel.x` and `.relx`
spellings, required relocation sections are byte-identical (pass), a
single drifted relocation byte fails naming the section, a relocation
present on one side only fails, and relocations against debug metadata
stay informational (the P2F-2 carve-out). Hermetic: temp dirs only.

Run: python3 -I tests/python/test_gate0_identity.py -v
"""

import contextlib
import io
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from _loader import load_path

CHECKER = load_path(ROOT / "scripts/check-gate0-identity.py", "gate0_identity")

FIXTURE_C = """\
extern int external_value;
int get_it(void) { return external_value; }
__attribute__((section("uprobe"), used)) int prog(void *ctx) {
    (void)ctx;
    return external_value;
}
"""


def readelf_offset(path, section):
    """File offset of one section via an independent readelf parse."""
    out = subprocess.run(
        ["readelf", "-S", "-W", str(path)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    for line in out:
        match = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)",
            line,
        )
        if match and match.group(1) == section:
            return int(match.group(2), 16)
    raise AssertionError(f"{section} missing from readelf output for {path}")


class Gate0IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="p11scope-gate0-id-")
        work = Path(cls.work.name)
        src = work / "fixture.c"
        src.write_text(FIXTURE_C)
        cls.fixture = work / "fixture.o"
        built = subprocess.run(
            [
                "clang-18",
                "-target",
                "bpf",
                "-mcpu=v3",
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
                str(src),
                "-o",
                str(cls.fixture),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert built.returncode == 0, built.stdout + built.stderr

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(
            prefix="p11scope-gate0-case-",
            dir=Path(self.work.name),
        )
        self.addCleanup(self.case.cleanup)

    def case_path(self, name):
        return Path(self.case.name) / name

    def flip_section_byte(self, path, section):
        offset = readelf_offset(path, section)
        data = bytearray(path.read_bytes())
        data[offset] ^= 0xFF
        path.write_bytes(bytes(data))

    def test_relocation_name_predicates(self):
        for name in (".rel.text", ".reluprobe", ".rel.BTF", ".rela.plt"):
            self.assertTrue(CHECKER.is_relocation_section(name), name)
        for name in (
            ".text",
            ".rodata",
            "maps",
            ".BTF",
            ".debug_info",
            "uprobe",
            "NULL",
        ):
            self.assertFalse(CHECKER.is_relocation_section(name), name)
        self.assertEqual(CHECKER.relocation_target(".rel.text"), ".text")
        self.assertEqual(CHECKER.relocation_target(".reluprobe"), "uprobe")
        self.assertEqual(CHECKER.relocation_target(".rela.plt"), ".plt")
        self.assertEqual(CHECKER.relocation_target(".rel.BTF.ext"), ".BTF.ext")
        for name in (
            ".rel.debug_info",
            ".rel.debug_line",
            ".rel.debug_str_offsets",
            ".rel.BTF.ext",
        ):
            self.assertTrue(CHECKER.is_informational_relocation(name), name)
        for name in (".rel.text", ".reluprobe", ".rel.BTF", ".rel.maps"):
            self.assertFalse(CHECKER.is_informational_relocation(name), name)

    def test_enumeration_lists_both_spellings_and_skips_debug(self):
        relocs = CHECKER.relocation_sections(self.fixture)
        self.assertIn(".rel.text", relocs)
        self.assertIn(".reluprobe", relocs)
        self.assertTrue(all(name.startswith(".rel") for name in relocs), relocs)
        self.assertFalse(
            [name for name in relocs if CHECKER.is_informational_relocation(name)],
            relocs,
        )
        # The fixture really has debug relocations to skip (clang -g).
        debug = [
            name
            for name in CHECKER.readelf_section_names(self.fixture)
            if CHECKER.is_relocation_section(name)
            and CHECKER.is_informational_relocation(name)
        ]
        self.assertIn(".rel.debug_info", debug)

    def test_identical_objects_have_no_problems(self):
        self.assertEqual(CHECKER.compare_object(self.fixture, self.fixture), [])

    def test_relocation_byte_drift_fails_naming_only_that_section(self):
        mutated = self.case_path("drift.o")
        shutil.copyfile(self.fixture, mutated)
        self.flip_section_byte(mutated, ".rel.text")
        problems = CHECKER.compare_object(self.fixture, mutated)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(".rel.text", problems[0])

    def test_relocation_present_on_one_side_only_fails(self):
        self.assertIn(".reluprobe", CHECKER.relocation_sections(self.fixture))
        stripped = self.case_path("stripped.o")
        removed = subprocess.run(
            [
                "llvm-objcopy",
                "--remove-section=.reluprobe",
                str(self.fixture),
                str(stripped),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        problems = CHECKER.compare_object(self.fixture, stripped)
        self.assertTrue(
            any(
                ".reluprobe" in problem and "one side only" in problem
                for problem in problems
            ),
            problems,
        )
        self.assertFalse(
            [problem for problem in problems if problem.startswith(".text")], problems
        )

    def test_debug_relocation_drift_stays_informational(self):
        mutated = self.case_path("debug-drift.o")
        shutil.copyfile(self.fixture, mutated)
        self.flip_section_byte(mutated, ".rel.debug_info")
        self.assertEqual(CHECKER.compare_object(self.fixture, mutated), [])

    def lay_out(self, root):
        """All seven objects as copies of the fixture (nested + flat)."""
        for name in CHECKER.OBJECTS:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.fixture, target)

    def test_main_passes_on_identical_dirs_and_fails_on_reloc_drift(self):
        base = self.case_path("base")
        cand = self.case_path("cand")
        self.lay_out(base)
        self.lay_out(cand)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 0)
        self.assertIn("OVERALL: PASS", out.getvalue())
        self.flip_section_byte(cand / "p11scope-ebpf-inventory-callers", ".rel.text")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 1)
        text = out.getvalue()
        self.assertIn("OVERALL: FAIL", text)
        self.assertIn("p11scope-ebpf-inventory-callers: FAIL", text)
        self.assertIn(".rel.text", text)


if __name__ == "__main__":
    unittest.main()
