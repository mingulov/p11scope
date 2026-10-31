# SPDX-License-Identifier: GPL-3.0-or-later
"""Proof-off/proof-on ordinary-object comparison + shared artifact preflight.

Section 3(c): the ordinary Detailed object must be identical across the
proof switch: both configurations emit it, and the proof build perturbs
only its private object. This suite resolves both objects fail-closed
and compares executable/map/relocation semantics; metadata differences
are reported, never failed, and byte-equality is never the criterion.

Section 3(b) preflight: the shared artifact-aware resolver
(`--preflight-only`) resolves explicit object paths fail-closed
(existence, regular file, ELF magic, unambiguity, rebuild-marker
staleness) and prints resolved absolute paths with sha256. The (b) lane
procedure preflights before the unittest stage so a missing input
refuses instead of satisfying the default-negative assertion.

Run: python3 -I tests/python/test_bank_object_proof_off_on.py -v
Live: python3 -I tests/python/test_bank_object_proof_off_on.py \
        --proof-off-object <p11scope-ebpf> --proof-on-object <p11scope-ebpf> \
        [--rebuild-marker <marker>] -v
"""

import argparse
import contextlib
import hashlib
import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

checker = load_path(ROOT / "scripts/check-bpf-map-defs.py", "map_checker")

ELF_MAGIC = b"\x7fELF"

SHF_EXECINSTR = 0x4

PROOF_OFF_OBJECT = None
PROOF_ON_OBJECT = None
REBUILD_MARKER = None


class Refusal(Exception):
    """Fail-closed artifact refusal naming the offending input."""


def resolve_artifact(path, *, rebuild_marker=None):
    """Resolve one explicit object path to (abspath, sha256).

    Refuses missing, non-regular, non-ELF or stale (not newer than
    the rebuild marker) inputs, naming the offending input.
    """
    if not os.path.lexists(path):
        raise Refusal(f"missing input refuses: {path} does not exist")
    if not os.path.isfile(path):
        raise Refusal(f"not a regular file: {path}")
    with open(path, "rb") as handle:
        magic = handle.read(len(ELF_MAGIC))
    if magic != ELF_MAGIC:
        raise Refusal(f"not an ELF object: {path}")
    if rebuild_marker is not None:
        if not os.path.exists(rebuild_marker):
            raise Refusal(f"missing rebuild marker refuses: {rebuild_marker}")
        if os.stat(path).st_mtime_ns <= os.stat(rebuild_marker).st_mtime_ns:
            raise Refusal(f"stale input refuses: {path} predates {rebuild_marker}")
    abspath = os.path.realpath(path)
    digest = hashlib.sha256()
    with open(abspath, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return abspath, digest.hexdigest()


def resolve_distinct(paths, *, rebuild_marker=None):
    """Resolve each path; refuse when two inputs name one file."""
    resolved = [resolve_artifact(path, rebuild_marker=rebuild_marker) for path in paths]
    seen = {}
    for (abspath, _), original in zip(resolved, paths):
        stat = os.stat(abspath)
        identity = (stat.st_dev, stat.st_ino)
        if identity in seen:
            raise Refusal(
                f"identical inputs refuse: {original} names the same file as {seen[identity]}"
            )
        seen[identity] = original
    return resolved


def compare_named_sections(off_map, on_map, site):
    """Compare same-named section bodies; True when every side matches."""
    if not off_map and not on_map:
        print(f"{site} OK absent both sides")
        return True
    ok = True
    for name in sorted(set(off_map) | set(on_map)):
        if name not in off_map:
            print(f"{site} FAIL {name} only in proof-on object")
            ok = False
        elif name not in on_map:
            print(f"{site} FAIL {name} only in proof-off object")
            ok = False
        elif off_map[name] != on_map[name]:
            print(f"{site} FAIL {name} differs")
            ok = False
        else:
            print(f"{site} OK {name} matches")
    return ok


def compare_maps(off_elf, on_elf):
    """Compare decoded .maps definitions; undecodable FAILs closed."""
    off_has = ".maps" in off_elf.sections
    on_has = ".maps" in on_elf.sections
    if not off_has and not on_has:
        print("MAPS OK absent both sides")
        return True
    if off_has != on_has:
        print("MAPS FAIL .maps only in proof-on object" if on_has
              else "MAPS FAIL .maps only in proof-off object")
        return False
    try:
        off_maps = checker.decode_btf_maps(off_elf)
        on_maps = checker.decode_btf_maps(on_elf)
    except RuntimeError as error:
        print(f"MAPS FAIL undecodable .maps: {error}")
        return False
    if off_maps != on_maps:
        for name in sorted(set(off_maps) | set(on_maps)):
            if off_maps.get(name) != on_maps.get(name):
                print(f"MAPS FAIL {name} differs")
        return False
    print(f"MAPS OK {len(off_maps)} map(s) match")
    return True


def report_metadata(off_elf, on_elf, semantic):
    """Report non-semantic section differences; never fails."""
    off_meta = {name: body for name, (_, body) in off_elf.sections.items()
                if name not in semantic}
    on_meta = {name: body for name, (_, body) in on_elf.sections.items()
               if name not in semantic}
    for name in sorted(set(off_meta) | set(on_meta)):
        if name not in off_meta:
            print(f"META-DIFF {name} only in proof-on object")
        elif name not in on_meta:
            print(f"META-DIFF {name} only in proof-off object")
        elif off_meta[name] != on_meta[name]:
            print(f"META-DIFF {name} differs "
                  f"({hashlib.sha256(off_meta[name]).hexdigest()[:12]} vs "
                  f"{hashlib.sha256(on_meta[name]).hexdigest()[:12]})")


def compare_objects(off, on, *, rebuild_marker=None):
    """Compare two ordinary objects; 0 when semantics match, 1 on difference.

    Prints the metadata report and per-site verdicts. Refusals raise.
    Executable, relocation and decoded-map bytes are semantics: any
    difference FAILs. All other sections are metadata: reported, never
    failed. Byte-equality of the whole object is never the criterion.
    """
    (off_path, off_sha), (on_path, on_sha) = resolve_distinct(
        [off, on], rebuild_marker=rebuild_marker)
    print(f"OFF {off_path} {off_sha}")
    print(f"ON {on_path} {on_sha}")
    try:
        off_elf = checker.Elf(Path(off_path).read_bytes())
        on_elf = checker.Elf(Path(on_path).read_bytes())
    except RuntimeError as error:
        print(f"FAIL undecodable ELF: {error}")
        return 1
    off_exec = {name: body for name, (row, body) in off_elf.sections.items()
                if row[2] & SHF_EXECINSTR}
    on_exec = {name: body for name, (row, body) in on_elf.sections.items()
               if row[2] & SHF_EXECINSTR}
    off_reloc = {name: body for name, body in
                 ((n, b) for n, (_, b) in off_elf.sections.items())
                 if name.startswith(".rel")}
    on_reloc = {name: body for name, body in
                ((n, b) for n, (_, b) in on_elf.sections.items())
                if name.startswith(".rel")}
    ok = compare_named_sections(off_exec, on_exec, "EXEC")
    ok = compare_named_sections(off_reloc, on_reloc, "RELOC") and ok
    ok = compare_maps(off_elf, on_elf) and ok
    report_metadata(off_elf, on_elf,
                    set(off_exec) | set(on_exec) | set(off_reloc) | set(on_reloc)
                    | {".maps"})
    print("OK" if ok else "FAIL")
    return 0 if ok else 1


def preflight_main(objects, rebuild_marker):
    """Batch-resolve every object, then print resolutions. Returns 0 or 1."""
    try:
        resolved = resolve_distinct(objects, rebuild_marker=rebuild_marker)
    except Refusal as error:
        print(f"REFUSED {error}")
        return 1
    for abspath, sha256 in resolved:
        print(f"OK {abspath} {sha256}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--object", action="append", default=[])
    parser.add_argument("--proof-off-object")
    parser.add_argument("--proof-on-object")
    parser.add_argument("--rebuild-marker")
    return parser


def discover():
    global PROOF_OFF_OBJECT, PROOF_ON_OBJECT, REBUILD_MARKER
    parser = build_parser()
    args, remaining = parser.parse_known_args()
    if args.preflight_only:
        if args.proof_off_object or args.proof_on_object:
            parser.error("--preflight-only takes --object, not comparison flags")
        if not args.object:
            parser.error("--preflight-only needs at least one --object")
        sys.exit(preflight_main(args.object, args.rebuild_marker))
    if args.object:
        parser.error("--object needs --preflight-only")
    if bool(args.proof_off_object) != bool(args.proof_on_object):
        parser.error("--proof-off-object and --proof-on-object come as a pair")
    if args.proof_off_object:
        PROOF_OFF_OBJECT = args.proof_off_object
        PROOF_ON_OBJECT = args.proof_on_object
        REBUILD_MARKER = args.rebuild_marker
    elif args.rebuild_marker:
        parser.error("--rebuild-marker needs comparison objects")
    unittest.main(argv=[sys.argv[0], *remaining])


def write_file(path, data):
    Path(path).write_bytes(data)
    return str(path)


MIN_NS = 1_700_000_000_000_000_000


class ResolverTests(unittest.TestCase):
    def test_missing_refuses_naming_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "absent.o")
            with self.assertRaisesRegex(Refusal, "absent.o"):
                resolve_artifact(missing)

    def test_directory_refuses_as_non_regular(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(Refusal, "regular file"):
                resolve_artifact(tmp)

    def test_non_elf_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_file(os.path.join(tmp, "text.o"), b"not an object\n")
            with self.assertRaisesRegex(Refusal, "ELF"):
                resolve_artifact(path)

    def test_stale_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = write_file(os.path.join(tmp, "marker"), b"m")
            obj = write_file(os.path.join(tmp, "stale.o"), ELF_MAGIC + b"\0" * 60)
            os.utime(marker, ns=(MIN_NS + 10**9, MIN_NS + 10**9))
            os.utime(obj, ns=(MIN_NS, MIN_NS))
            with self.assertRaisesRegex(Refusal, "stale"):
                resolve_artifact(obj, rebuild_marker=marker)

    def test_fresh_resolves_with_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = write_file(os.path.join(tmp, "marker"), b"m")
            data = ELF_MAGIC + b"\0" * 60
            obj = write_file(os.path.join(tmp, "fresh.o"), data)
            os.utime(marker, ns=(MIN_NS, MIN_NS))
            os.utime(obj, ns=(MIN_NS + 10**9, MIN_NS + 10**9))
            abspath, sha256 = resolve_artifact(obj, rebuild_marker=marker)
            self.assertEqual(abspath, os.path.realpath(obj))
            self.assertEqual(sha256, hashlib.sha256(data).hexdigest())

    def test_missing_marker_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj = write_file(os.path.join(tmp, "fresh.o"), ELF_MAGIC + b"\0" * 60)
            with self.assertRaisesRegex(Refusal, "marker"):
                resolve_artifact(obj, rebuild_marker=os.path.join(tmp, "no-marker"))

    def test_duplicate_inputs_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj = write_file(os.path.join(tmp, "same.o"), ELF_MAGIC + b"\0" * 60)
            with self.assertRaisesRegex(Refusal, "identical"):
                resolve_distinct([obj, obj])


class PreflightCliTests(unittest.TestCase):
    def invoke(self, *arguments):
        return subprocess.run(
            [sys.executable, "-I", str(ROOT / "tests/python/test_bank_object_proof_off_on.py"),
             *arguments],
            cwd=ROOT, text=True, capture_output=True)

    def test_preflight_ok_prints_paths_and_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = write_file(os.path.join(tmp, "marker"), b"m")
            first = write_file(os.path.join(tmp, "a.o"), ELF_MAGIC + b"A" * 60)
            second = write_file(os.path.join(tmp, "b.o"), ELF_MAGIC + b"B" * 60)
            os.utime(marker, ns=(MIN_NS, MIN_NS))
            os.utime(first, ns=(MIN_NS + 10**9, MIN_NS + 10**9))
            os.utime(second, ns=(MIN_NS + 2 * 10**9, MIN_NS + 2 * 10**9))
            result = self.invoke("--preflight-only", "--object", first, "--object", second,
                                 "--rebuild-marker", marker)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"OK {os.path.realpath(first)}", result.stdout)
            self.assertIn(hashlib.sha256(ELF_MAGIC + b"A" * 60).hexdigest(), result.stdout)
            self.assertIn(f"OK {os.path.realpath(second)}", result.stdout)

    def test_missing_default_refuses_before_unittest_stage(self):
        # (b-NEG): the preflight names the missing input and exits
        # nonzero; the unittest stage never runs, so zero cases pass.
        with tempfile.TemporaryDirectory() as tmp:
            marker = write_file(os.path.join(tmp, "marker"), b"m")
            proof = write_file(os.path.join(tmp, "proof.o"), ELF_MAGIC + b"P" * 60)
            missing = os.path.join(tmp, "default.o")
            os.utime(marker, ns=(MIN_NS, MIN_NS))
            os.utime(proof, ns=(MIN_NS + 10**9, MIN_NS + 10**9))
            result = self.invoke("--preflight-only", "--object", proof, "--object", missing,
                                 "--rebuild-marker", marker)
            self.assertEqual(result.returncode, 1, result.stdout)
            lines = result.stdout.strip().splitlines()
            self.assertEqual(len(lines), 1, result.stdout)
            self.assertTrue(lines[0].startswith("REFUSED"), result.stdout)
            self.assertIn("default.o", lines[0])
            self.assertEqual(result.stderr, "")

    def test_preflight_without_object_is_usage_error(self):
        result = self.invoke("--preflight-only")
        self.assertEqual(result.returncode, 2)

    def test_preflight_and_comparison_flags_conflict(self):
        result = self.invoke("--preflight-only", "--object", "a.o",
                             "--proof-off-object", "b.o", "--proof-on-object", "c.o")
        self.assertEqual(result.returncode, 2)


def synthetic_elf(*, text, rel=b"\0" * 24, comment=b"v1", maps=False):
    """Minimal ELF64LE the Elf parser accepts: null, .text (exec),
    .rel.text, .symtab, .strtab, .comment, .shstrtab, plus an optional
    undecodable .maps (no .BTF on purpose). No toolchain needed."""
    blobs = {
        ".text": (1, 0x6, text),
        ".rel.text": (4, 0x0, rel),
        ".symtab": (2, 0x0, b"\0" * 24),
        ".strtab": (3, 0x0, b"\0"),
        ".comment": (1, 0x0, comment),
    }
    names = ["", ".text", ".rel.text", ".symtab", ".strtab", ".comment"]
    if maps:
        blobs[".maps"] = (1, 0x3, b"\0" * 8)
        names.insert(3, ".maps")
    names.append(".shstrtab")
    shstr = b"\0"
    offsets = {}
    for name in names[1:]:
        offsets[name] = len(shstr)
        shstr += name.encode() + b"\0"
    blobs[".shstrtab"] = (3, 0x0, shstr)
    order = names[1:]
    offset = 64
    layout = {}
    for name in order:
        layout[name] = offset
        offset += len(blobs[name][2])
    shoff = offset
    out = bytearray()
    out += ELF_MAGIC + b"\x02\x01\x01" + b"\0" * 9
    out += struct.pack("<HHI", 1, 247, 1)
    out += struct.pack("<Q", 0)
    out += struct.pack("<Q", 0)
    out += struct.pack("<Q", shoff)
    out += struct.pack("<I", 0)
    out += struct.pack("<6H", 64, 0, 0, 64, len(names), len(names) - 1)
    for name in order:
        out += blobs[name][2]
    assert len(out) == shoff
    out += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for name in order:
        typ, flags, body = blobs[name]
        link = names.index(".strtab") if name == ".symtab" else 0
        out += struct.pack("<IIQQQQIIQQ", offsets[name], typ, flags, 0,
                           layout[name], len(body), link, 0,
                           1 if body else 0, 24 if name == ".symtab" else 0)
    return bytes(out)


TEXT_A = b"\xb7\x01\x00\x00\x01\0\0\0"
TEXT_B = b"\xb7\x01\x00\x00\x02\0\0\0"


class ComparisonTests(unittest.TestCase):
    def run_compare(self, off_data, on_data, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            off = write_file(os.path.join(tmp, "off.o"), off_data)
            on = write_file(os.path.join(tmp, "on.o"), on_data)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = compare_objects(off, on, **kwargs)
            return rc, out.getvalue()

    def test_identical_synthetics_match_through_semantics(self):
        data = synthetic_elf(text=TEXT_A, comment=b"v1")
        rc, out = self.run_compare(data, data)
        self.assertEqual(rc, 0, out)
        for needle in ["EXEC", "MAPS", "RELOC", "OK"]:
            self.assertIn(needle, out)

    def test_metadata_only_difference_passes_with_report(self):
        off = synthetic_elf(text=TEXT_A, comment=b"v1")
        on = synthetic_elf(text=TEXT_A, comment=b"v2-longer")
        rc, out = self.run_compare(off, on)
        self.assertEqual(rc, 0, out)
        self.assertIn("META-DIFF", out)

    def test_exec_difference_fails(self):
        off = synthetic_elf(text=TEXT_A, comment=b"v1")
        on = synthetic_elf(text=TEXT_B, comment=b"v1")
        rc, out = self.run_compare(off, on)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL", out)
        self.assertIn(".text", out)

    def test_reloc_difference_fails(self):
        off = synthetic_elf(text=TEXT_A, rel=b"\0" * 24, comment=b"v1")
        on = synthetic_elf(text=TEXT_A, rel=b"\1" + b"\0" * 23, comment=b"v1")
        rc, out = self.run_compare(off, on)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL", out)
        self.assertIn(".rel.text", out)

    def test_maps_asymmetry_fails(self):
        off = synthetic_elf(text=TEXT_A, comment=b"v1")
        on = synthetic_elf(text=TEXT_A, comment=b"v1", maps=True)
        rc, out = self.run_compare(off, on)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL", out)
        self.assertIn(".maps", out)

    def test_undecodable_maps_fail(self):
        off = synthetic_elf(text=TEXT_A, comment=b"v1", maps=True)
        on = synthetic_elf(text=TEXT_A, comment=b"v1", maps=True)
        rc, out = self.run_compare(off, on)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL", out)

    def test_same_file_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj = write_file(os.path.join(tmp, "same.o"),
                             synthetic_elf(text=TEXT_A, comment=b"v1"))
            with self.assertRaisesRegex(Refusal, "identical"):
                compare_objects(obj, obj)

    def test_missing_input_refuses_naming_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj = write_file(os.path.join(tmp, "off.o"),
                             synthetic_elf(text=TEXT_A, comment=b"v1"))
            missing = os.path.join(tmp, "on.o")
            with self.assertRaisesRegex(Refusal, "on.o"):
                compare_objects(obj, missing)


class ComparisonLiveTests(unittest.TestCase):
    def test_proof_off_on_ordinary_objects_match(self):
        if PROOF_OFF_OBJECT is None or PROOF_ON_OBJECT is None:
            self.skipTest("explicit --proof-off-object/--proof-on-object required")
        self.assertEqual(
            compare_objects(PROOF_OFF_OBJECT, PROOF_ON_OBJECT,
                            rebuild_marker=REBUILD_MARKER),
            0)


if __name__ == "__main__":
    discover()
