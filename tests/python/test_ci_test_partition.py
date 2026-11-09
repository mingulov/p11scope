#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The coverage packer and its test-binary self-pin guard.

`scripts/ci-test-partition.py coverage-pack` archives a shard's
profiles and instrumented executables. It used to refuse executables
past the scanner's 256 MiB object limit; that tripwire's premise (an
over-limit instrumented binary means self-pin failures) died with the
small owned fixture, and the real coverage run shows the instrumented
lib suite fully green. In its place the packer runs a guard on the
actual risk: no test may pin `current_exe` or the test binary through
a size-gated scanner entry instead of the small owned fixture.

Run: python3 -I tests/python/test_ci_test_partition.py -v
"""

import runpy
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
PART = runpy.run_path(str(ROOT / "scripts/ci-test-partition.py"))

# The two self-pin flows the guard reports but excuses, as
# (file, test function). Each is benign by a mechanism its own test
# pins, and each must keep violating: a stale entry fails loudly.
EXPECTED_ALLOWLIST = frozenset({
    # Selects a mapped executable that is != the test binary (a small
    # loader .so), pinned by its `path != executable` filter.
    ("src/discovery/engine_tests.rs",
     "exact_loader_pin_is_view_owned_but_not_a_provider_module"),
    # The identity-mismatch skip precedes the size gate, pinned by its
    # identity_mismatch assertion: a mismatch must never be pinned.
    ("tests/manifest_pinning.rs",
     "a_retargeted_path_is_skipped_as_an_identity_mismatch"),
})

SELF = "std::env::current_exe().unwrap()"


def violation_cases():
    """(name, rust body) pairs the guard must flag, one per sink shape."""
    return [
        ("direct open_object",
         f"fn t() {{\n    let exe = {SELF};\n"
         "    let file = open_object(&exe).unwrap();\n}\n"),
        ("inline current_exe",
         f"fn t() {{\n    let file = open_object(&{SELF});\n}}\n"),
        ("open_rooted_object",
         "fn t() {\n    let p = std::path::Path::new(\"/proc/self/exe\");\n"
         "    let file = view.open_rooted_object(p).unwrap();\n}\n"),
        ("object_facts helper",
         f"fn t() {{\n    let exe = {SELF};\n"
         "    let key = object_facts(&exe).0;\n}\n"),
        ("pin_as_manifest_object helper",
         f"fn t() {{\n    let exe = {SELF};\n"
         "    let pins = pin_as_manifest_object(exe.to_str().unwrap());\n}\n"),
        ("identity_and_key helper",
         f"fn t() {{\n    let exe = {SELF};\n"
         "    let key = identity_and_key(&exe).unwrap().0;\n}\n"),
        ("validated_identity helper",
         f"fn t() {{\n    let exe = {SELF};\n"
         "    let id = validated_identity(&exe, key).unwrap();\n}\n"),
        ("identify helper",
         f"fn t() {{\n    let original = {SELF};\n"
         "    let id = identity::identify(&original);\n}\n"),
        ("stable_selection_maps helper",
         f"fn t() {{\n    let exe = {SELF};\n"
         "    let maps = stable_selection_maps_with_probe(&exe, key, &id, &probe, &mut b).unwrap();\n}\n"),
        ("test-binary copy",
         f"fn t() {{\n    let path = dir.join(\"x.so\");\n"
         f"    std::fs::copy({SELF}, &path).unwrap();\n}}\n"),
        ("mapped_object then pin_test_module",
         f"fn t() {{\n    let executable = {SELF};\n"
         "    let m = mapped_object(&view, mapping, &executable);\n"
         "    let pins = pin_test_module(&view, &m);\n}\n"),
        ("ScannedModule path then pin_scanned_objects",
         f"fn t() {{\n    let exe = {SELF};\n"
         "    let module = ScannedModule { path: exe.display().to_string(), ..rest };\n"
         "    let (pinned, skipped) = pin_scanned_objects(pid, &[module], &mut budget).unwrap();\n}\n"),
        ("equality-filter then pin",
         f"fn t() {{\n    let executable = {SELF};\n"
         "    let (mapping, path) = maps.iter().find_map(|m| match resolve(m) {\n"
         "        Resolved::File { path, .. } if path == executable => Some((m, path)),\n"
         "        _ => None,\n"
         "    }).unwrap();\n"
         "    let module = mapped_object(&view, mapping, &path);\n"
         "    let pins = pin_test_module(&view, &module);\n}\n"),
        # The guard cannot tell == from != through the closure, so an
        # inequality filter flags too and needs the allowlist entry.
        ("inequality-filter then pin",
         f"fn t() {{\n    let executable = {SELF};\n"
         "    let (mapping, path) = maps.iter().find_map(|m| match resolve(m) {\n"
         "        Resolved::File { path, .. } if path != executable => Some((m, path)),\n"
         "        _ => None,\n"
         "    }).unwrap();\n"
         "    let module = mapped_object(&view, mapping, &path);\n"
         "    let pins = pin_test_module(&view, &module);\n}\n"),
    ]


def benign_cases():
    """(name, rust body) pairs the guard must accept."""
    return [
        ("re-exec spawn",
         f"fn t() {{\n    let mut child = std::process::Command::new({SELF});\n"
         "    let out = child.output().unwrap();\n}\n"),
        ("real_scan_pin synthesizes without the gate",
         f"fn t() {{\n    let pins = test_fixture::real_scan_pin(&{SELF}, None, 1, \"held\");\n}}\n"),
        ("exe comparisons",
         f"fn t() {{\n    let self_exe = {SELF};\n"
         "    assert_ne!(std::fs::read_link(\"/proc/1/exe\").unwrap(), self_exe);\n}\n"),
        ("deps-dir sibling lookup",
         f"fn t() {{\n    let deps = {SELF};\n"
         "    let helper = deps.parent().unwrap().join(\"p11scope-discover\");\n}\n"),
        ("bounded interpreter read",
         f"fn t() {{\n    let executable = std::fs::File::open({SELF}).unwrap();\n"
         "    let (interp, _) = read_bounded_interpreter(&executable, 4096).unwrap();\n"
         "    std::fs::copy(interp.expect(\"interp\"), &loader).unwrap();\n}\n"),
        ("small owned fixture",
         "fn t() {\n"
         "    let object = crate::discovery::identity::test_fixture::small_owned_object();\n"
         "    let key = object_facts(object).0;\n}\n"),
        ("map-slot fd from self exe",
         "fn t() {\n    let fd = std::fs::File::open(\"/proc/self/exe\").unwrap();\n"
         "    let slot = read_map_slot(&fd);\n}\n"),
    ]


def write_tree(root, files):
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


class SelfPinGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Plain functions would bind as methods; keep them static.
        cls.violations = staticmethod(PART["self_pin_violations"])
        cls.scan = staticmethod(PART["scan_self_pins"])
        cls.check_allowlist = staticmethod(PART["check_self_pin_allowlist"])
        cls.allowlist = PART["SELF_PIN_ALLOWLIST"]

    def test_no_test_pins_the_test_binary(self):
        # The twin: fails naming file:line when any test pins
        # current_exe or the test binary through a size-gated entry.
        self.assertEqual(self.violations(ROOT), [])

    def test_allowlist_is_exact_and_live(self):
        self.assertEqual(self.allowlist, EXPECTED_ALLOWLIST)
        # Each entry must still violate: a fixed site gets its entry
        # removed, never left to linger.
        self.assertIsNone(self.check_allowlist(ROOT))

    def test_stale_allowlist_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, {"src/clean.rs": "fn t() {}\n"})
            with self.assertRaises(PART["PartitionError"]):
                self.check_allowlist(root)

    def test_violation_shapes_are_flagged(self):
        for name, body in violation_cases():
            with self.subTest(shape=name):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_tree(root, {"src/v.rs": body})
                    hits = self.scan(root)
                self.assertEqual(len(hits), 1, hits)
                rel, line, function, gate = hits[0]
                self.assertEqual(rel, "src/v.rs")
                self.assertEqual(function, "t")
                self.assertGreater(line, 1)

    def test_benign_shapes_pass(self):
        for name, body in benign_cases():
            with self.subTest(shape=name):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_tree(root, {"src/b.rs": body})
                    self.assertEqual(self.scan(root), [])

    def test_pack_refuses_a_self_pin_before_creating_output(self):
        # The packer reads its own checkout root, so the test mirrors
        # the script byte-identical into the fixture tree and drives
        # the mirror: the refusal names the violating file and no
        # output appears.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, {"src/v.rs": violation_cases()[0][1]})
            mirror = root / "scripts" / "ci-test-partition.py"
            mirror.parent.mkdir(parents=True)
            mirror.write_bytes((ROOT / "scripts" / "ci-test-partition.py")
                               .read_bytes())
            target = root / "target" / "llvm-cov-target"
            debug = target / "debug" / "deps"
            debug.mkdir(parents=True)
            exe = debug / "bin-rest"
            exe.write_bytes(b"\x7fELF")
            exe.chmod(0o755)
            (target / "p11scope-rest-1-abc.profraw").write_bytes(b"raw")
            out = root / "packed"
            pack = runpy.run_path(str(mirror))
            with self.assertRaises(pack["PartitionError"]) as raised:
                pack["coverage_pack"]("rest", target, out)
            self.assertIn("src/v.rs", str(raised.exception))
            self.assertFalse(out.exists(), "refuse before creating output")

    def test_pack_accepts_an_over_limit_executable(self):
        # The retired tripwire refused instrumented binaries past 256
        # MiB; the packer archives whatever cargo-llvm-cov needs now.
        with tempfile.TemporaryDirectory() as tmp:
            debug = Path(tmp) / "debug" / "deps"
            debug.mkdir(parents=True)
            fat = debug / "fat-test"
            with fat.open("wb") as output:
                output.truncate(256 * 1024 * 1024 + 1)
            fat.chmod(0o755)
            self.assertEqual(PART["coverage_objects"](Path(tmp) / "debug"),
                             [Path("deps/fat-test")])

    def test_size_tripwire_is_gone_but_the_product_limit_stays(self):
        self.assertNotIn("MAX_COVERAGE_OBJECT_BYTES", PART)
        source = (ROOT / "scripts" / "ci-test-partition.py").read_text()
        self.assertNotIn("scanner limit", source)
        manifest = (ROOT / "crates" / "manifest" / "src" / "identity.rs").read_text()
        self.assertIn("pub const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;",
                      manifest)


if __name__ == "__main__":
    unittest.main()
