#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostic helper linkage pins; objects must be supplied explicitly."""
import argparse
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

C = load_path(ROOT / "scripts/check-bpf-map-defs.py", "map_checker")
OBJECTS = []


class DiagnosticLinkageTests(unittest.TestCase):
    def test_helpers_are_global(self):
        for variant, path in OBJECTS:
            with self.subTest(variant=variant):
                body = path.read_bytes()
                names = {symbol[0] for symbol in C.Elf(body).symbols}
                if variant == "unsafe":
                    self.assertTrue(
                        C.DIAGNOSTIC_GLOBAL_HELPERS <= names,
                        "diagnostic object must define every helper",
                    )
                else:
                    self.assertTrue(
                        names.isdisjoint(C.DIAGNOSTIC_GLOBAL_HELPERS),
                        "default object must define no helper",
                    )
                C.validate_diagnostic_helper_linkage(C.Elf(body))

    def test_static_elf_binding_rejected(self):
        for variant, path in OBJECTS:
            body = path.read_bytes()
            elf = C.Elf(body)
            symbase = elf.sections[".symtab"][0][4]
            for name in sorted(C.DIAGNOSTIC_GLOBAL_HELPERS):
                with self.subTest(variant=variant, helper=name):
                    present = [i for i, symbol in enumerate(elf.symbols)
                               if symbol[0] == name]
                    if variant != "unsafe":
                        self.assertEqual(present, [])
                        continue
                    self.assertEqual(len(present), 1)
                    changed = bytearray(body)
                    struct.pack_into("<B", changed, symbase + 24 * present[0] + 4, 0x02)
                    with self.assertRaisesRegex(RuntimeError, "GLOBAL DEFAULT FUNC"):
                        C.validate_diagnostic_helper_linkage(C.Elf(bytes(changed)))

    def test_static_btf_linkage_rejected(self):
        for variant, path in OBJECTS:
            body = path.read_bytes()
            elf = C.Elf(body)
            if ".BTF" not in elf.sections:
                continue
            base = elf.sections[".BTF"][0][4]
            btf = C.Btf(elf.sections[".BTF"][1])
            for name in sorted(C.DIAGNOSTIC_GLOBAL_HELPERS):
                with self.subTest(variant=variant, helper=name):
                    nodes = [node for node in btf.types[1:]
                             if node[0] == 12 and node[1] == name]
                    if variant != "unsafe":
                        self.assertEqual(nodes, [])
                        continue
                    self.assertEqual(len(nodes), 1)
                    changed = bytearray(body)
                    struct.pack_into("<H", changed, base + nodes[0][6] + 4, 0)
                    with self.assertRaisesRegex(RuntimeError, "GLOBAL BTF FUNC"):
                        C.validate_diagnostic_helper_linkage(C.Elf(bytes(changed)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--object", type=Path, help="test the current Cargo build object")
    parser.add_argument("--variant", choices=("default", "unsafe"))
    parser.add_argument("--default-object", type=Path)
    parser.add_argument("--unsafe-object", type=Path)
    args, rest = parser.parse_known_args()
    usage = "use --object with --variant, or both --default-object and --unsafe-object"
    if args.object is not None or args.variant is not None:
        if (args.object is None or args.variant is None
                or args.default_object is not None or args.unsafe_object is not None):
            parser.error(usage)
        OBJECTS = [(args.variant, args.object)]
    else:
        if args.default_object is None or args.unsafe_object is None:
            parser.error(usage)
        OBJECTS = [("default", args.default_object), ("unsafe", args.unsafe_object)]
    unittest.main(argv=[sys.argv[0], *rest])
