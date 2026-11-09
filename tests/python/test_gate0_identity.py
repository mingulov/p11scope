#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Unit tests for scripts/check-gate0-identity.py (P2F-5 F3, r6 I1/I6, r7 R1).

Drives the checker's real code on tiny owned BPF objects built with
clang-18: relocation enumeration covers both `.rel.x` and `.relx`
spellings, required relocation sections are byte-identical (pass), a
single drifted relocation byte fails naming the section, a relocation
present on one side only fails, and relocations against debug metadata
stay informational (the P2F-2 carve-out). I1: program-section
enumeration from readelf flags, with a one-byte program-section drift
twin. I6: a true reordered-.BTF pair (surgical type-order swap)
normalizes to PASS with the decision printed, a renamed-type pair
still fails, and a .BTF-plus-code pair fails by bytes without
consulting bpftool. R1: map capacity/type pairs and a .bss size pair
fail (the C-dump fallback wrongly passed them). Hermetic: temp dirs
only (the BTF twins skip where bpftool is absent).

Run: python3 -I tests/python/test_gate0_identity.py -v
"""

import contextlib
import io
import re
import shutil
import struct
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


BTF_ORDER_C = """\
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name
struct Alpha { void *seq; unsigned long long session_id; unsigned long long seq_num; };
struct Beta { void *seq; unsigned long long session_id; unsigned long long seq_num; };
struct { __uint(type, 2); __type(key, int); __type(value, struct Alpha); __uint(max_entries, 1); } map_a __attribute__((section(".maps"), used));
struct { __uint(type, 2); __type(key, int); __type(value, struct Beta); __uint(max_entries, 1); } map_b __attribute__((section(".maps"), used));
__attribute__((section("uprobe"), used)) int prog(void *ctx) { (void)ctx; return 0; }
"""

MAP_SHAPE_C = """\
typedef unsigned int __u32;
typedef unsigned long long __u64;
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name
struct cell { __u64 a; __u32 b; };
struct {
    __uint(type, MAP_TYPE);
    __uint(max_entries, MAP_MAXE);
    __type(key, __u32);
    __type(value, struct cell);
} DEMO __attribute__((section(".maps"), used));
__attribute__((section("uprobe"), used)) int prog(void *ctx) { (void)ctx; return 0; }
"""

BSS_SIZE_C = """\
#define SEC(n) __attribute__((section(n), used))
int g[G_LEN];
SEC("uprobe") int prog(void *ctx) { (void)ctx; return g[0]; }
char LICENSE[] SEC("license") = "GPL";
"""


def _btf_record_size(kind, vlen):
    """One BTF type record's byte length (uapi btf.h layout)."""
    if kind == 1 or kind in (14, 17, 18):  # INT, VAR, DECL_TAG, TYPE_TAG
        return 16
    if kind == 3:  # ARRAY
        return 24
    if kind in (4, 5):  # STRUCT, UNION (12-byte members)
        return 12 + vlen * 12
    if kind == 6:  # ENUM
        return 12 + vlen * 8
    if kind == 19:  # ENUM64
        return 12 + vlen * 12
    if kind == 13:  # FUNC_PROTO
        return 12 + vlen * 8
    if kind == 15:  # DATASEC
        return 12 + vlen * 12
    return 12  # PTR FWD TYPEDEF VOLATILE CONST RESTRICT FUNC FLOAT


def _btf_ref_positions(kind, vlen, base):
    """File offsets of every type_id u32 in one BTF type record."""
    if kind in (2, 8, 9, 10, 11, 12, 14, 17, 18):
        return [base + 8]
    if kind == 13:  # FUNC_PROTO return + params
        return [base + 8] + [base + 16 + i * 8 for i in range(vlen)]
    if kind == 3:  # ARRAY element + index
        return [base + 12, base + 16]
    if kind in (4, 5):  # STRUCT/UNION members
        return [base + 12 + i * 12 + 8 for i in range(vlen)]
    if kind == 15:  # DATASEC entries
        return [base + 12 + i * 12 for i in range(vlen)]
    return []


def swap_btf_struct_order(path, first, second):
    """Copy of path's bytes with two named STRUCT type slots swapped.

    Both slots must be same-sized STRUCTs; every inbound type_id is
    remapped, so the result is semantically identical with .BTF bytes
    differing by order only (the round-4 flake shape: adjacent records
    swapped, referencing PTRs adjusted). Raises AssertionError unless
    the type walk ends exactly and both names resolve.
    """
    data = bytearray(path.read_bytes())
    off = readelf_offset(path, ".BTF")
    magic, version, _flags, hdr_len, type_off, type_len, str_off, _str_len = (
        struct.unpack_from("<HBBIIIII", data, off)
    )
    assert (magic, version) == (0xEB9F, 1)
    types = off + hdr_len + type_off
    str_start = off + hdr_len + str_off

    def name_at(name_off):
        end = data.index(b"\x00", str_start + name_off)
        return bytes(data[str_start + name_off : end]).decode("ascii")

    slots = {}
    cursor, type_id = types, 1
    while cursor < types + type_len:
        name_off, info, _size = struct.unpack_from("<III", data, cursor)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        size = _btf_record_size(kind, vlen)
        slots[type_id] = (cursor, size, kind, name_off)
        cursor += size
        type_id += 1
    assert cursor == types + type_len, "BTF type walk must end exactly"
    ids = {}
    for tid, (_off, _size, kind, name_off) in slots.items():
        if kind == 4 and name_at(name_off) in (first, second):
            ids[name_at(name_off)] = tid
    assert set(ids) == {first, second}, f"both STRUCTs must resolve: {ids}"
    (off_a, size_a, _, _), (off_b, size_b, _, _) = slots[ids[first]], slots[ids[second]]
    assert size_a == size_b, "same-sized STRUCT records required"
    data[off_a : off_a + size_a], data[off_b : off_b + size_b] = (
        bytes(data[off_b : off_b + size_b]),
        bytes(data[off_a : off_a + size_a]),
    )
    id_a, id_b = ids[first], ids[second]
    for _tid, (rec_off, _size, kind, _name) in slots.items():
        _name_off, info, _sz = struct.unpack_from("<III", data, rec_off)
        vlen = info & 0xFFFF
        for pos in _btf_ref_positions(kind, vlen, rec_off):
            (ref,) = struct.unpack_from("<I", data, pos)
            if ref == id_a:
                struct.pack_into("<I", data, pos, id_b)
            elif ref == id_b:
                struct.pack_into("<I", data, pos, id_a)
    return bytes(data)


class Gate0IdentityTests(unittest.TestCase):
    @classmethod
    def compile_c(cls, work, stem, source):
        src = work / f"{stem}.c"
        src.write_text(source)
        out = work / f"{stem}.o"
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
                str(out),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert built.returncode == 0, built.stdout + built.stderr
        return out

    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="p11scope-gate0-id-")
        work = Path(cls.work.name)
        cls.fixture = cls.compile_c(work, "fixture", FIXTURE_C)
        cls.btf_base = cls.compile_c(work, "btf-base", BTF_ORDER_C)
        # Same-length type rename under a same-length filename: the pair
        # differs in .BTF bytes only, while its normalized forms genuinely
        # differ (the mismatch control for the I6 fallback).
        cls.btf_renamed = cls.compile_c(
            work, "btf-rend", BTF_ORDER_C.replace("Beta", "BetX")
        )
        # R1 shape twins: same-length stems so each pair differs in .BTF
        # bytes only (map pairs) or .BTF plus the .bss header (size pair).
        cls.map_256 = cls.compile_c(
            work,
            "map-256a",
            MAP_SHAPE_C.replace("MAP_TYPE", "2").replace("MAP_MAXE", "256"),
        )
        cls.map_512 = cls.compile_c(
            work,
            "map-512a",
            MAP_SHAPE_C.replace("MAP_TYPE", "2").replace("MAP_MAXE", "512"),
        )
        cls.map_hash = cls.compile_c(
            work,
            "map-hsh1",
            MAP_SHAPE_C.replace("MAP_TYPE", "1").replace("MAP_MAXE", "256"),
        )
        cls.bss_4 = cls.compile_c(work, "bss-004a", BSS_SIZE_C.replace("G_LEN", "4"))
        cls.bss_64 = cls.compile_c(work, "bss-064a", BSS_SIZE_C.replace("G_LEN", "64"))

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

    def test_program_section_byte_drift_fails_naming_that_section(self):
        mutated = self.case_path("prog-drift.o")
        shutil.copyfile(self.fixture, mutated)
        self.flip_section_byte(mutated, "uprobe")
        problems = CHECKER.compare_object(self.fixture, mutated)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("uprobe", problems[0])

    def test_program_sections_lists_alloc_and_exec_only(self):
        sections = CHECKER.program_sections(self.fixture)
        self.assertIn(".text", sections)
        self.assertIn("uprobe", sections)
        for name in sections:
            self.assertFalse(name.startswith(".debug"), name)
        self.assertNotIn(".BTF.ext", sections)
        self.assertNotIn(".strtab", sections)

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

    def lay_out(self, root, source=None):
        """All eight objects as copies of one object (nested + flat)."""
        for name in CHECKER.OBJECTS:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source or self.fixture, target)

    def swapped_btf_twin(self, name):
        """The BTF base with its Alpha/Beta STRUCT slots swapped (I6).

        A true reordered-.BTF pair: .BTF bytes differ by order only, and
        bpftool still loads the result (raw JSON, the adjudication path).
        """
        twin = self.case_path(name)
        twin.write_bytes(swap_btf_struct_order(self.btf_base, "Alpha", "Beta"))
        dumped = subprocess.run(
            ["bpftool", "-j", "btf", "dump", "file", str(twin), "format", "raw"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(dumped.returncode, 0, dumped.stderr)
        self.assertTrue(dumped.stdout.strip())
        return twin

    @unittest.skipUnless(shutil.which("bpftool"), "I6 fallback needs bpftool")
    def test_btf_order_swap_is_btf_only_and_normalizes(self):
        twin = self.swapped_btf_twin("swapped.o")
        problems = CHECKER.compare_object(self.btf_base, twin)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith(".BTF differs"), problems)
        self.assertIsNone(CHECKER.adjudicate_btf_only(self.btf_base, twin))

    @unittest.skipUnless(shutil.which("bpftool"), "I6 fallback needs bpftool")
    def test_main_reports_btf_normalized_decision(self):
        base = self.case_path("base")
        cand = self.case_path("cand")
        self.lay_out(base, self.btf_base)
        self.lay_out(cand, self.btf_base)
        (cand / "p11scope-ebpf").write_bytes(
            swap_btf_struct_order(self.btf_base, "Alpha", "Beta")
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 0)
        text = out.getvalue()
        self.assertIn("OVERALL: PASS", text)
        self.assertIn("p11scope-ebpf: PASS", text)
        self.assertIn("bpftool-normalized", text)

    def test_btf_plus_code_diff_fails_by_bytes_without_bpftool(self):
        import unittest.mock as mock

        base = self.case_path("base")
        cand = self.case_path("cand")
        self.lay_out(base, self.btf_base)
        self.lay_out(cand, self.btf_base)
        target = cand / "p11scope-ebpf"
        target.write_bytes(swap_btf_struct_order(self.btf_base, "Alpha", "Beta"))
        self.flip_section_byte(target, "uprobe")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with mock.patch.object(
                CHECKER,
                "btf_canonical_multiset",
                side_effect=AssertionError("bytes path must not consult bpftool"),
            ):
                self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 1)
        text = out.getvalue()
        self.assertIn("OVERALL: FAIL", text)
        self.assertIn("uprobe", text)
        self.assertNotIn("bpftool-normalized", text)

    @unittest.skipUnless(shutil.which("bpftool"), "I6 fallback needs bpftool")
    def test_renamed_type_btf_still_fails(self):
        problems = CHECKER.compare_object(self.btf_base, self.btf_renamed)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith(".BTF differs"), problems)
        decision = CHECKER.adjudicate_btf_only(self.btf_base, self.btf_renamed)
        self.assertIsNotNone(decision)
        self.assertIn(".BTF", decision)
        base = self.case_path("base")
        cand = self.case_path("cand")
        self.lay_out(base, self.btf_base)
        self.lay_out(cand, self.btf_base)
        shutil.copyfile(self.btf_renamed, cand / "p11scope-ebpf")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 1)
        text = out.getvalue()
        self.assertIn("OVERALL: FAIL", text)
        self.assertIn("p11scope-ebpf: FAIL", text)
        self.assertIn(".BTF", text)

    @unittest.skipUnless(shutil.which("bpftool"), "R1 shape twins need bpftool")
    def test_map_max_entries_btf_still_fails(self):
        problems = CHECKER.compare_object(self.map_256, self.map_512)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith(".BTF differs"), problems)
        decision = CHECKER.adjudicate_btf_only(self.map_256, self.map_512)
        self.assertIsNotNone(decision)
        self.assertIn(".BTF", decision)

    @unittest.skipUnless(shutil.which("bpftool"), "R1 shape twins need bpftool")
    def test_map_type_btf_still_fails(self):
        problems = CHECKER.compare_object(self.map_256, self.map_hash)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith(".BTF differs"), problems)
        decision = CHECKER.adjudicate_btf_only(self.map_256, self.map_hash)
        self.assertIsNotNone(decision)
        self.assertIn(".BTF", decision)

    @unittest.skipUnless(shutil.which("bpftool"), "R1 shape twins need bpftool")
    def test_bss_size_header_diff_fails(self):
        problems = CHECKER.compare_object(self.bss_4, self.bss_64)
        self.assertTrue(
            any(".bss" in problem for problem in problems),
            f".bss size change must be named: {problems}",
        )
        base = self.case_path("base")
        cand = self.case_path("cand")
        self.lay_out(base, self.bss_4)
        self.lay_out(cand, self.bss_4)
        shutil.copyfile(self.bss_64, cand / "p11scope-ebpf")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 1)
        text = out.getvalue()
        self.assertIn("OVERALL: FAIL", text)
        self.assertIn(".bss", text)

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

    def test_main_compares_the_journal_object(self):
        base = self.case_path("base")
        cand = self.case_path("cand")
        self.lay_out(base)
        self.lay_out(cand)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 0)
        self.assertIn("p11scope-ebpf-journal-v1: PASS", out.getvalue())
        self.flip_section_byte(cand / "journal-v1" / "p11scope-ebpf-journal-v1", ".text")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 1)
        text = out.getvalue()
        self.assertIn("OVERALL: FAIL", text)
        self.assertIn("p11scope-ebpf-journal-v1: FAIL", text)
        self.assertIn(".text", text)

    def test_main_fails_when_the_journal_object_is_missing(self):
        base = self.case_path("base")
        cand = self.case_path("cand")
        self.lay_out(base)
        self.lay_out(cand)
        (cand / "journal-v1" / "p11scope-ebpf-journal-v1").unlink()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECKER.main(["check", str(base), str(cand)]), 1)
        text = out.getvalue()
        self.assertIn("OVERALL: FAIL", text)
        self.assertIn("p11scope-ebpf-journal-v1: FAIL", text)
        self.assertIn("missing in candidate", text)


if __name__ == "__main__":
    unittest.main()
