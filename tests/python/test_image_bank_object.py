# SPDX-License-Identifier: GPL-3.0-or-later
"""Object-free image-bank checker controls and real-object CLI modes."""

import argparse
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-image-bank-object.py"
NATIVE = ROOT / "crates/ebpf/native/image_bank_proof.c"
BANK = runpy.run_path(str(CHECKER))

PROOF_OBJECT = None
DEFAULT_OBJECT = None

FIELDS = ("type", "key_size", "value_size", "max_entries", "flags")


def good_maps():
    return {name: dict(zip(FIELDS, shape))
            for name, shape in BANK["EXPECTED_MAP_SHAPES"].items()}


def good_protos():
    protos = {}
    for name, widths in BANK["BANK_CORES"].items():
        arguments = [(width, (width * 8,)) for width in widths]
        protos[name] = (1, (4, (32,)), arguments)
    return protos


def good_cores(text=3):
    return [(name, 0x12, 0, text, 8 * (index + 1), 8)
            for index, name in enumerate(BANK["BANK_CORES"])]


def good_census():
    bank_entry_helpers = {1, 2, 5, 14, 156, 158, 173, 174}
    return {
        "p11_bank_disp_enter": (
            {1, 12}, {"BANK_SELECT", "BANK_GATE", "BANK_PROGS_SINGLES"}),
        "p11_bank_disp_enter_multi": (
            {1, 12}, {"BANK_SELECT", "BANK_GATE", "BANK_PROGS_MULTI"}),
        "p11_bank_disp_birth": (
            {1, 12}, {"BANK_SELECT", "BANK_GATE", "BANK_PROGS_BIRTH"}),
        "p11_bank_entry_a": (
            set(bank_entry_helpers),
            {"TASK_COOKIE", "COOKIE_CTL", "IMAGE_CONTINUITY",
             "IMAGE_TGID_INDEX", "START", "BANK_SELECT", "BANK_GATE",
             "IMAGE_BANK_ACCOUNT"}),
        "p11_bank_entry_b": (
            set(bank_entry_helpers),
            {"TASK_COOKIE_B", "COOKIE_CTL_B", "IMAGE_CONTINUITY_B",
             "IMAGE_TGID_INDEX_B", "START", "BANK_SELECT", "BANK_GATE",
             "IMAGE_BANK_ACCOUNT"}),
        "p11_bank_birth_a": (
            {1, 156}, {"TASK_COOKIE", "COOKIE_CTL", "BANK_GATE"}),
        "p11_bank_birth_b": (
            {1, 156}, {"TASK_COOKIE_B", "COOKIE_CTL_B", "BANK_GATE"}),
        "p11_bank_return": (
            {1, 3, 14}, {"START", "IMAGE_BANK_ACCOUNT"}),
        "p11_bank_ref_entry": (
            {1, 173, 174}, {"IMAGE_BANK_ACCOUNT"}),
        "p11_bank_exec_cover": (
            {1, 158},
            {"IMAGE_TGID_INDEX", "IMAGE_TGID_INDEX_B", "IMAGE_CONTINUITY",
             "IMAGE_CONTINUITY_B"}),
        "p11_bank_query_cover": (
            {1, 5, 127, 156},
            {"IMAGE_QUERY_CTL", "IMAGE_QUERY_REQUESTS", "TASK_COOKIE",
             "TASK_COOKIE_B", "IMAGE_CONTINUITY", "IMAGE_CONTINUITY_B",
             "IMAGE_BANK_ACCOUNT"}),
    }


class CensusGraph:
    def __init__(self, table):
        self.table = table

    def census(self, root):
        return self.table[root]


def check_census(table):
    roots = {name: name for name in table}
    return BANK["proof_reachability"](CensusGraph(table), roots)


class ImageBankInventoryTests(unittest.TestCase):
    def test_root_inventory_pins_eleven_names(self):
        uprobe = {"p11_bank_disp_enter": "uprobe",
                  "p11_bank_disp_enter_multi": "uprobe",
                  "p11_bank_entry_a": "uprobe",
                  "p11_bank_entry_b": "uprobe",
                  "p11_bank_ref_entry": "uprobe"}
        uretprobe = {"p11_bank_return": "uretprobe"}
        native = {"p11_bank_disp_birth": "tp_btf/task_newtask",
                  "p11_bank_birth_a": "tp_btf/task_newtask",
                  "p11_bank_birth_b": "tp_btf/task_newtask",
                  "p11_bank_exec_cover": "fentry/exec_mm_release",
                  "p11_bank_query_cover": "iter/task"}
        self.assertEqual(BANK["RUST_UPROBE_ROOTS"], uprobe)
        self.assertEqual(BANK["RUST_URETPROBE_ROOTS"], uretprobe)
        self.assertEqual(BANK["NATIVE_ROOTS"], native)

    def test_helper_allowlist_pins_eleven_ids(self):
        self.assertEqual(BANK["ALLOWED_HELPERS"],
                         {1, 2, 3, 5, 12, 14, 127, 156, 158, 173, 174})

    def test_core_inventory_pins_six_signatures(self):
        self.assertEqual(BANK["BANK_CORES"], {
            "p11_bank_select": (),
            "p11_bank_gate_release": (4,),
            "p11_bank_enter_a": (8, 8, 8, 8),
            "p11_bank_enter_b": (8, 8, 8, 8),
            "p11_bank_complete": (8,),
            "p11_bank_ref": (8, 8),
        })

    def test_c_route_layout_pins_r0_offsets(self):
        text = NATIVE.read_text()
        for line in ("#define BANK_ROUTE_OFF 88",
                     "#define BANK_MARKER_OFF 264",
                     "#define BANK_COOKIE_OFF 272",
                     "#define BANK_EXEC_OFF 280",
                     "#define BANK_START_SIZE 288"):
            self.assertIn(line, text)


class ImageBankMapShapeTests(unittest.TestCase):
    def test_good_shapes_pass(self):
        BANK["check_map_shapes"](good_maps())

    def test_missing_map_fails_by_name(self):
        for name in ("TASK_COOKIE_B", "COOKIE_CTL_B", "IMAGE_CONTINUITY_B",
                     "IMAGE_TGID_INDEX_B", "BANK_SELECT", "BANK_GATE",
                     "BANK_PROGS_SINGLES", "BANK_PROGS_MULTI",
                     "BANK_PROGS_BIRTH", "IMAGE_BANK_ACCOUNT"):
            with self.subTest(map=name):
                maps = good_maps()
                del maps[name]
                with self.assertRaisesRegex(RuntimeError, f"has no {name} map"):
                    BANK["check_map_shapes"](maps)

    def test_wrong_size_fails_by_name(self):
        mutants = [
            ("START", "value_size", 296),
            ("START", "key_size", 8),
            ("IMAGE_BANK_ACCOUNT", "value_size", 72),
            ("IMAGE_BANK_ACCOUNT", "max_entries", 2),
            ("BANK_PROGS_SINGLES", "max_entries", 4),
            ("IMAGE_CONTINUITY_B", "max_entries", 8192),
            ("IMAGE_TGID_INDEX_B", "value_size", 16),
            ("BANK_SELECT", "value_size", 8),
            ("COOKIE_CTL_B", "value_size", 32),
            ("TASK_COOKIE_B", "type", 1),
        ]
        for name, field, value in mutants:
            with self.subTest(map=name, field=field):
                maps = good_maps()
                maps[name][field] = value
                with self.assertRaisesRegex(RuntimeError, f"{name} shape .* differs"):
                    BANK["check_map_shapes"](maps)


class ImageBankRaceFixTests(unittest.TestCase):
    def test_old_shapes_fail_by_name(self):
        for name, field, value in (("BANK_GATE", "max_entries", 1),
                                   ("BANK_SELECT", "value_size", 16)):
            with self.subTest(map=name, field=field, value=value):
                maps = good_maps()
                maps[name][field] = value
                with self.assertRaisesRegex(RuntimeError, f"{name} shape .* differs"):
                    BANK["check_map_shapes"](maps)

    def test_gate_shape_is_per_bank(self):
        self.assertEqual(BANK["EXPECTED_MAP_SHAPES"]["BANK_GATE"],
                         (2, 4, 8, 2, 0))

    def test_select_shape_carries_fixed_words(self):
        self.assertEqual(BANK["EXPECTED_MAP_SHAPES"]["BANK_SELECT"],
                         (2, 4, 32, 1, 0))

    def test_gate_release_takes_the_serving_slot(self):
        self.assertEqual(BANK["BANK_CORES"]["p11_bank_gate_release"], (4,))


class ImageBankCoreAbiTests(unittest.TestCase):
    def test_good_cores_pass(self):
        BANK["check_core_abi"](good_cores(), 3, good_protos())

    def test_missing_core_fails(self):
        cores = [symbol for symbol in good_cores()
                 if symbol[0] != "p11_bank_enter_b"]
        with self.assertRaisesRegex(RuntimeError, "core inventory differs"):
            BANK["check_core_abi"](cores, 3, good_protos())

    def test_core_argument_count_fails(self):
        protos = good_protos()
        kind, rest, arguments = protos["p11_bank_enter_a"]
        protos["p11_bank_enter_a"] = (kind, rest, arguments[:3])
        with self.assertRaisesRegex(RuntimeError, "argument count differs"):
            BANK["check_core_abi"](good_cores(), 3, protos)

    def test_core_return_fails(self):
        protos = good_protos()
        _, _, arguments = protos["p11_bank_complete"]
        protos["p11_bank_complete"] = (1, (8, (64,)), arguments)
        with self.assertRaisesRegex(RuntimeError, "must return u32"):
            BANK["check_core_abi"](good_cores(), 3, protos)

    def test_core_pointer_argument_fails(self):
        protos = good_protos()
        kind, rest, arguments = protos["p11_bank_enter_a"]
        protos["p11_bank_enter_a"] = (kind, rest, ["ptr", *arguments[1:]])
        with self.assertRaisesRegex(RuntimeError, "across the global-call boundary"):
            BANK["check_core_abi"](good_cores(), 3, protos)

    def test_core_linkage_fails(self):
        cores = [(name, 0x02, other, section, address, size)
                 for name, _, other, section, address, size in good_cores()]
        with self.assertRaisesRegex(RuntimeError, "GLOBAL DEFAULT"):
            BANK["check_core_abi"](cores, 3, good_protos())


class ImageBankReachabilityTests(unittest.TestCase):
    def test_good_census_passes(self):
        check_census(good_census())

    def test_dispatcher_without_gate_fails(self):
        for name in ("p11_bank_disp_enter", "p11_bank_disp_enter_multi",
                     "p11_bank_disp_birth"):
            with self.subTest(root=name):
                table = good_census()
                helpers, touched = table[name]
                table[name] = (helpers, touched - {"BANK_GATE"})
                with self.assertRaisesRegex(RuntimeError, "takes no gate ref"):
                    check_census(table)

    def test_dispatcher_counting_admissions_fails(self):
        table = good_census()
        helpers, touched = table["p11_bank_disp_enter"]
        table["p11_bank_disp_enter"] = (helpers, touched | {"IMAGE_BANK_ACCOUNT"})
        with self.assertRaisesRegex(RuntimeError, "counts admissions"):
            check_census(table)

    def test_dispatcher_without_tail_call_fails(self):
        table = good_census()
        _, touched = table["p11_bank_disp_enter_multi"]
        table["p11_bank_disp_enter_multi"] = ({1}, touched)
        with self.assertRaisesRegex(RuntimeError, "never tail-calls"):
            check_census(table)

    def test_bank_a_cross_touch_fails(self):
        table = good_census()
        helpers, touched = table["p11_bank_entry_a"]
        table["p11_bank_entry_a"] = (helpers, touched | {"IMAGE_CONTINUITY_B"})
        with self.assertRaisesRegex(RuntimeError, "touches second-bank maps"):
            check_census(table)

    def test_bank_b_cross_touch_fails(self):
        table = good_census()
        helpers, touched = table["p11_bank_birth_b"]
        table["p11_bank_birth_b"] = (helpers, touched | {"TASK_COOKIE"})
        with self.assertRaisesRegex(RuntimeError, "touches first-bank maps"):
            check_census(table)

    def test_return_minting_state_fails(self):
        table = good_census()
        helpers, touched = table["p11_bank_return"]
        table["p11_bank_return"] = (helpers | {2}, touched)
        with self.assertRaisesRegex(RuntimeError, "mints state"):
            check_census(table)

    def test_return_without_retire_fails(self):
        table = good_census()
        _, touched = table["p11_bank_return"]
        table["p11_bank_return"] = ({1, 14}, touched)
        with self.assertRaisesRegex(RuntimeError, "never retires its route"):
            check_census(table)

    def test_reference_impure_fails(self):
        table = good_census()
        helpers, _ = table["p11_bank_ref_entry"]
        table["p11_bank_ref_entry"] = (helpers, {"IMAGE_BANK_ACCOUNT", "START"})
        with self.assertRaisesRegex(RuntimeError, "not a pure account write"):
            check_census(table)

    def test_exec_cover_counting_fails(self):
        table = good_census()
        helpers, touched = table["p11_bank_exec_cover"]
        table["p11_bank_exec_cover"] = (helpers, touched | {"IMAGE_BANK_ACCOUNT"})
        with self.assertRaisesRegex(RuntimeError, "exec cover counts"):
            check_census(table)

    def test_query_cover_missing_input_fails(self):
        table = good_census()
        helpers, touched = table["p11_bank_query_cover"]
        table["p11_bank_query_cover"] = (helpers, touched - {"TASK_COOKIE_B"})
        with self.assertRaisesRegex(RuntimeError, "misses a dual-bank input"):
            check_census(table)

    def test_forbidden_helper_fails(self):
        table = good_census()
        helpers, touched = table["p11_bank_entry_a"]
        table["p11_bank_entry_a"] = (helpers | {25}, touched)
        with self.assertRaisesRegex(RuntimeError, "outside the proof allowlist"):
            check_census(table)


class ImageBankCliTests(unittest.TestCase):
    def invoke(self, *arguments):
        return subprocess.run([sys.executable, "-I", str(CHECKER), *arguments],
                              cwd=ROOT, text=True, capture_output=True)

    def test_cli_no_args_exits_2(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_cli_missing_file_fails(self):
        result = self.invoke("missing.o")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL", result.stdout)

    def test_proof_object_passes(self):
        if PROOF_OBJECT is None:
            self.skipTest("no proof object built (proof flavor off)")
        result = self.invoke(str(PROOF_OBJECT))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("OK roots=11", result.stdout)
        self.assertIn("helpers=[1, 2, 3, 5, 12, 14, 127, 156, 158, 173, 174]",
                      result.stdout)

    def test_default_object_has_no_proof(self):
        if DEFAULT_OBJECT is None:
            self.skipTest("no default object built")
        result = self.invoke(str(DEFAULT_OBJECT))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("FAIL", result.stdout)


def discover():
    global PROOF_OBJECT, DEFAULT_OBJECT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-object", type=Path)
    parser.add_argument("--default-object", type=Path)
    args, remaining = parser.parse_known_args()
    if args.proof_object is not None:
        PROOF_OBJECT = args.proof_object
    else:
        hits = sorted(ROOT.glob("target/r3-proof/debug/build/p11scope-*/out/"
                                "image-bank-proof-v1/"
                                "p11scope-ebpf-image-bank-proof-v1"))
        if hits:
            PROOF_OBJECT = hits[0]
    if args.default_object is not None:
        DEFAULT_OBJECT = args.default_object
    else:
        hits = sorted(ROOT.glob("target/r3/debug/build/p11scope-*/out/p11scope-ebpf"))
        if hits:
            DEFAULT_OBJECT = hits[0]
    unittest.main(argv=[sys.argv[0], *remaining])


if __name__ == "__main__":
    discover()
