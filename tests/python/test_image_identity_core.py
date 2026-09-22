# SPDX-License-Identifier: GPL-3.0-or-later
"""Native identity isolation and compiled ABI; never loads BPF."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
from _loader import load_path

CHECKER = load_path(ROOT / "scripts/check-bpf-map-defs.py", "identity_maps")


class IdentityCoreTests(unittest.TestCase):
    def test_core_object_has_only_identity_maps_and_owned_root(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-identity-core-") as directory:
            obj = Path(directory) / "core.o"
            built = subprocess.run(
                ["clang-18", "-target", "bpf", "-mcpu=v3", "-O2", "-g",
                 "-Wall", "-Wextra", "-Werror", "-c",
                 str(ROOT / "scripts/native/image-identity-core-canary.c"), "-o", str(obj)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            elf = CHECKER.Elf(obj.read_bytes())
            programs = {name for name, info, _, section, _, _ in elf.symbols
                        if info & 15 == 2 and section != elf.indices.get(".text")
                        and section in {elf.indices[name] for name, (header, _) in elf.sections.items()
                                        if header[2] & 4}}
            # This is an unlinked clang object: DATASEC offsets are relocatable.
            # Decode the actual VAR types and cross-check their ELF object sizes;
            # the production checker additionally validates final linked offsets.
            btf = CHECKER.Btf(elf.sections[".BTF"][1])
            symbols = {name: (offset, size) for name, info, _, section, offset, size in elf.symbols
                       if section == elf.indices[".maps"] and info & 15 == 1}
            maps = {}
            for node in btf.types[1:]:
                if node[0] == 14 and node[1] in symbols:
                    definition, size = btf.map_definition(node[2])
                    self.assertNotIn(node[1], maps)
                    self.assertEqual(size, symbols[node[1]][1])
                    maps[node[1]] = definition
            self.assertEqual(set(maps), set(symbols))
            self.assertEqual(programs, {"image_identity_core_canary"},
                             "identity core retained an unrelated program root")
            self.assertEqual(maps, {
                "TASK_COOKIE": CHECKER.map_def(29, 4, 8, 0, 1),
                "COOKIE_CTL": CHECKER.map_def(2, 4, 40, 1),
            })
            names = [row[0] for row in elf.symbols]
            for name in ["TASK_COOKIE", "COOKIE_CTL", "p11_link_current_identity"]:
                self.assertEqual(names.count(name), 1, name)
            for name in ["task_newtask", "p11_link_fork_allowed", "p11_link_emit_fork",
                         "p11_root_propagate_thread", "ROOT_AFFILIATION", "ROOT_CTL", "START"]:
                self.assertNotIn(name, names)
            self.assertIn(".BTF.ext", elf.sections)
            disassembly = subprocess.run(["llvm-objdump-18", "-dr", str(obj)],
                                         capture_output=True, text=True, check=True, timeout=10).stdout
            canary = disassembly.split("<image_identity_core_canary>:", 1)[1]
            self.assertIn("p11_link_current_identity", canary,
                          "fixture root must consume the real identity helper")

    def test_separate_native_units_inline_bridge_and_define_one_domain(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-identity-units-") as directory:
            directory = Path(directory)
            bitcodes = []
            for unit in ["image_identity", "image_identity_fork"]:
                output = directory / (unit + ".bc")
                built = subprocess.run(
                    ["clang-18", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                     "-emit-llvm", "-c", str(ROOT / "crates/ebpf/native" / (unit + ".c")),
                     "-o", str(output)], capture_output=True, text=True, timeout=20)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                bitcodes.append(str(output))
            linked, inlined, obj = [directory / name for name in ["linked.bc", "inlined.bc", "linked.o"]]
            commands = [
                ["llvm-link-18", *bitcodes, "-o", str(linked)],
                ["opt-18", "-passes=always-inline", str(linked), "-o", str(inlined)],
                ["llc-18", "-march=bpf", "-mcpu=v3", "-filetype=obj", str(inlined), "-o", str(obj)],
            ]
            for command in commands:
                ran = subprocess.run(command, capture_output=True, text=True, timeout=20)
                self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            elf = CHECKER.Elf(obj.read_bytes())
            names = [row[0] for row in elf.symbols]
            for name in ["TASK_COOKIE", "COOKIE_CTL", "task_newtask", "p11_link_current_identity"]:
                self.assertEqual(names.count(name), 1, name)
            disassembly = subprocess.run(["llvm-objdump-18", "-dr", str(obj)],
                                         capture_output=True, text=True, check=True, timeout=10).stdout
            hook = disassembly.split("Disassembly of section tp_btf/task_newtask:", 1)[1]
            self.assertNotIn("p11_link_task_identity", hook,
                             "typed-task bridge must inline into its native root")
            for name in ["p11_root_propagate_thread", "p11_link_fork_allowed", "p11_link_emit_fork"]:
                self.assertIn(name, hook)

    def test_fork_wrapper_uses_core_without_owning_maps(self):
        path = ROOT / "crates/ebpf/native/image_identity_fork.c"
        self.assertTrue(path.is_file(), "fork wrapper must have its own translation unit")
        wrapper = path.read_text()
        self.assertIn('SEC("tp_btf/task_newtask")', wrapper)
        self.assertEqual(wrapper.count("p11_link_task_identity("), 2)
        for name in ['TASK_COOKIE SEC(', 'COOKIE_CTL SEC(', 'cookie_for(', 'identity_for(']:
            self.assertNotIn(name, wrapper)
        core = (ROOT / "crates/ebpf/native/image_identity.c").read_text()
        self.assertNotIn('SEC("tp_btf/task_newtask")', core)
        self.assertNotIn('p11_link_fork_allowed', core)
        build = (ROOT / "build.rs").read_text()
        units = build.split('let native_units: &[&str] = if inventory {', 1)[1].split('};', 1)[0]
        inventory, detailed = units.split('} else {', 1)
        self.assertEqual(inventory.strip(), '&["task_owner"]')
        self.assertIn('"image_identity"', detailed)
        self.assertIn('"image_identity_fork"', detailed)
        self.assertNotIn('inventory-callers', build)


if __name__ == "__main__":
    unittest.main()
