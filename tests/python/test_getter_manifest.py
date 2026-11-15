#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""scripts/getter-manifest.py: a getter-only manifest from an ELF file's
own symbol table, checked against readelf as an independent oracle.

The fixture is tests/fixtures/manifest-getter/static_getter_app.c built
without -rdynamic, so its getters live only in .symtab (no dynamic
export), the shape the helper exists for.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "getter-manifest.py"
FIXTURE = ROOT / "tests" / "fixtures" / "manifest-getter" / "static_getter_app.c"


def run(*args):
    return subprocess.run([sys.executable, "-I", str(HELPER), *map(str, args)],
                          capture_output=True, text=True, check=False)


def readelf(*args):
    return subprocess.run(["readelf", "-W", *args], capture_output=True,
                          text=True, check=True).stdout


def oracle_offsets(binary):
    """{getter: file offset} from readelf's symbol and segment tables."""
    values = {}
    for line in readelf("-s", str(binary)).splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[3] == "FUNC" and fields[7] in (
                "C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList"):
            values.setdefault(fields[7], int(fields[1], 16))
    segments = []
    for line in readelf("-l", str(binary)).splitlines():
        fields = line.split()
        if fields and fields[0] == "LOAD" and "E" in fields[6:-1]:
            segments.append((int(fields[1], 16), int(fields[2], 16), int(fields[4], 16)))
    out = {}
    for name, value in values.items():
        for offset, vaddr, filesz in segments:
            if vaddr <= value < vaddr + filesz:
                out[name] = value - vaddr + offset
    return out


class GetterManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ("cc", "readelf", "strip"):
            if shutil.which(tool) is None:
                raise RuntimeError(f"{tool} is required for this suite")
        cls.dir = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.dir.name) / "app"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o",
                        str(cls.binary), str(FIXTURE)], check=True)
        # The shape under test: no PKCS#11 name in the dynamic symbols.
        assert "C_Get" not in readelf("--dyn-syms", str(cls.binary))

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def out(self, name):
        return Path(self.dir.name) / name

    def test_default_writes_every_defined_getter_at_the_oracle_offset(self):
        target = self.out("all.json")
        result = run(self.binary, "-o", target)
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(target.read_text())
        self.assertEqual(document["schema"], "p11scope-manifest/5")
        self.assertEqual(document["surfaces"], [])
        self.assertEqual(document["interface_list"], {"status": "absent"})
        self.assertEqual(document["selection_evidence"]["acquisition"], "export_absent")
        got = {g["name"]: g["resolution"]["file_offset"] for g in document["getters"]}
        self.assertEqual(set(got), {"C_GetFunctionList", "C_GetInterface",
                                    "C_GetInterfaceList"})
        self.assertEqual(got, oracle_offsets(self.binary))
        for getter in document["getters"]:
            self.assertEqual(getter["resolution"]["status"], "resolved")
            self.assertEqual(getter["resolution"]["object"], 0)

    def test_identity_names_the_exact_file(self):
        target = self.out("identity.json")
        self.assertEqual(run(self.binary, "-o", target).returncode, 0)
        document = json.loads(target.read_text())
        data = self.binary.read_bytes()
        identity = document["objects"][0]["identity"]
        self.assertEqual(identity["sha256"], hashlib.sha256(data).hexdigest())
        build_id = re.search(r"Build ID: ([0-9a-f]+)", readelf("-n", str(self.binary)))
        if build_id:
            self.assertEqual(identity, {"kind": "gnu_build_id", "value": build_id.group(1),
                                        "sha256": identity["sha256"], "reusable": True,
                                        "note": None})
        else:
            self.assertEqual(identity["kind"], "sha256")
        self.assertEqual(document["module_path"], str(self.binary.resolve()))
        self.assertEqual(document["objects"][0]["path"], str(self.binary.resolve()))
        provenance = document["provenance_objects"][0]
        info = os.stat(self.binary)
        self.assertEqual((provenance["device_major"], provenance["device_minor"],
                          provenance["inode"]),
                         (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino))
        self.assertEqual(provenance["identity"], identity)

    def test_named_getter_alone(self):
        target = self.out("list.json")
        result = run(self.binary, "-o", target, "--getter", "C_GetFunctionList")
        self.assertEqual(result.returncode, 0, result.stderr)
        names = [g["name"] for g in json.loads(target.read_text())["getters"]]
        self.assertEqual(names, ["C_GetFunctionList"])

    def test_missing_getter_exits_1_and_writes_nothing(self):
        # A program that defines C_GetFunctionList alone.
        source = self.out("list_only.c")
        source.write_text("__attribute__((noinline, used)) int C_GetFunctionList(void)"
                          " { return 0; }\nint main(void) { return C_GetFunctionList(); }\n")
        binary = self.out("list_only")
        subprocess.run(["cc", "-O2", "-o", str(binary), str(source)], check=True)
        target = self.out("missing.json")
        result = run(binary, "-o", target, "--getter", "C_GetInterface")
        self.assertEqual(result.returncode, 1)
        self.assertIn("C_GetInterface is not defined", result.stderr)
        self.assertFalse(target.exists())
        result = run(binary, "-o", target)
        self.assertEqual(result.returncode, 0, result.stderr)
        names = [g["name"] for g in json.loads(target.read_text())["getters"]]
        self.assertEqual(names, ["C_GetFunctionList"])

    def test_stripped_file_has_no_getter(self):
        stripped = self.out("stripped")
        subprocess.run(["strip", "--strip-all", "-o", str(stripped), str(self.binary)],
                       check=True)
        target = self.out("stripped.json")
        result = run(stripped, "-o", target)
        self.assertEqual(result.returncode, 1)
        self.assertIn("defines no standard getter", result.stderr)
        self.assertFalse(target.exists())

    def test_not_an_elf_and_duplicate_getter_exit_2(self):
        text = self.out("text")
        text.write_text("not an elf\n")
        result = run(text, "-o", self.out("text.json"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("not an ELF file", result.stderr)
        result = run(self.binary, "-o", self.out("dup.json"),
                     "--getter", "C_GetInterface", "--getter", "C_GetInterface")
        self.assertEqual(result.returncode, 2)
        self.assertIn("named twice", result.stderr)

    def test_truncated_elf_exits_2_without_a_traceback(self):
        data = self.binary.read_bytes()
        for cut in (64, len(data) // 2, len(data) - 64):
            truncated = self.out(f"truncated-{cut}")
            truncated.write_bytes(data[:cut])
            result = run(truncated, "-o", self.out(f"truncated-{cut}.json"))
            self.assertIn(result.returncode, (1, 2), result.stderr)
            self.assertNotIn("Traceback", result.stderr)
        # A section header table pointing past the file is an ELF error.
        broken = bytearray(data)
        broken[0x28:0x30] = (len(data) + 4096).to_bytes(8, "little")  # e_shoff
        target = self.out("broken")
        target.write_bytes(bytes(broken))
        result = run(target, "-o", self.out("broken.json"))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_two_getters_at_one_address_are_refused(self):
        source = self.out("alias.c")
        source.write_text(
            "__attribute__((noinline, used)) int C_GetFunctionList(void) { return 0; }\n"
            "int C_GetInterface(void) __attribute__((alias(\"C_GetFunctionList\")));\n"
            "int main(void) { return C_GetInterface(); }\n")
        binary = self.out("alias")
        subprocess.run(["cc", "-O2", "-o", str(binary), str(source)], check=True)
        target = self.out("alias.json")
        result = run(binary, "-o", target)
        self.assertEqual(result.returncode, 1)
        self.assertIn("same address", result.stderr)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
