#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Journal descriptor-source proof; supply the object via P11SCOPE_JOURNAL_DESCRIPTOR_OBJECT.

In-place downgrade (A′): the journal entry/return path narrows through
the same per-slot SLOT_COUNT_ONLY switch as Detailed. The generic
outlined `object_return` monomorphization lives only in the journal
object (the Oct 29 split removed it from default/unsafe), and its
mangled name carries a build hash, so consumers are selected by exact
C name or by exact mangled fragment — never by the loose
"object_return" suffix, which matches nothing. Since v0.8.0 keymeta
Task 2 each return consumer instantiates twice (the base 632-byte
form and the 648-byte END+length form); every instantiation is proven
individually, and completeness covers the grown proven set.
"""

import os
import re
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

CHECKER = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/check-entry-object.py"))
DISASSEMBLY = None

# Exact selectors. The v0 length-prefixed fragments ("13" + name) are
# stable across builds; the surrounding crate hashes are not pinned.
ENTRY_ROOT = "p11_entry_journal"
RETURN_ROOT = "p11_return_journal"
LENGTH_ENTRY_ROOT = "p11_entry_journal_length"
LENGTH_RETURN_ROOT = "p11_return_journal_length"
CAPTURE_ENTRY_FRAGMENT = "13capture_entry"
ORDINARY_RETURN_FRAGMENT = "15ordinary_return"
OBJECT_RETURN_FRAGMENT = "13object_return"


def select(fragment=None, exact=None):
    """Select exactly one consumer block by exact C name or mangled fragment."""
    matches = select_all(fragment=fragment, exact=exact)
    if len(matches) != 1:
        raise AssertionError((exact or fragment, len(matches)))
    return matches[0]


def select_all(fragment=None, exact=None):
    """Select every consumer block matching the exact C name or fragment."""
    split = CHECKER["sections"](DISASSEMBLY)
    matches = [(section, name, lines)
               for section in ("uprobe", "uretprobe", ".text")
               for name, lines in CHECKER["D"].function_blocks(split[section]).items()
               if (exact is not None and name == exact)
               or (fragment is not None and fragment in name)]
    if not matches:
        raise AssertionError((exact or fragment, 0))
    return matches


def consumer_case(section, name, lines):
    split = CHECKER["sections"](DISASSEMBLY)
    text = CHECKER["joined"](split, section) if section == ".text" else CHECKER["joined"](split, section, ".text")
    calls = {pc: target for caller, _, pc, target in CHECKER["D"].internal_call_targets(text) if caller == name and target is not None}
    outlined = section == ".text" and (name.endswith("ordinary_return") or OBJECT_RETURN_FRAGMENT in name)
    if OBJECT_RETURN_FRAGMENT in name:
        cls = CHECKER["_JournalReturnCaller"]
    else:
        cls = CHECKER["_ReturnCaller"] if outlined or name == RETURN_ROOT else CHECKER["_SeedCaller"]
    initial = {"r1": ("context", 0), "r2": ("external_key", ("uretprobe", RETURN_ROOT), 0),
        "r3": ("owned", 7, 0), "r4": ("scope_flags", ("uretprobe", RETURN_ROOT)),
        "r5": ("constant", 0), "r10": ("stack", 0)} if outlined else None
    return cls(section, name, lines, calls), initial, CHECKER["D"].function_blocks(split[".text"]), outlined


def descriptor_source_case(section, name, lines, disassembly=None):
    if disassembly is None:
        consumer, initial, blocks, outlined = consumer_case(section, name, lines)
        return CHECKER["descriptor_source_contract"](consumer, None, blocks, initial, outlined)
    global DISASSEMBLY
    saved, DISASSEMBLY = DISASSEMBLY, disassembly
    try:
        split = CHECKER["sections"](DISASSEMBLY)
        mutated = CHECKER["D"].function_blocks(split[section])[name]
        consumer, initial, blocks, outlined = consumer_case(section, name, mutated)
        return CHECKER["descriptor_source_contract"](consumer, None, blocks, initial, outlined)
    finally:
        DISASSEMBLY = saved


def mutate(disassembly, function, pc, old, new):
    """Change exactly one decoded instruction, retaining its actual-object origin."""
    symbols = list(re.finditer(r"(?m)^[0-9a-f]+ <([^>]+)>:$", disassembly))
    matches = [i for i, symbol in enumerate(symbols) if symbol[1] == function]
    if len(matches) != 1:
        raise AssertionError(f"ambiguous function {function}")
    index = matches[0]
    start = symbols[index].end()
    end = symbols[index + 1].start() if index + 1 < len(symbols) else len(disassembly)
    block = disassembly[start:end]
    pattern = rf"(?m)(^\s*{pc}:[^\n]*\t)({re.escape(old)})(\s*(?:<[^>]+>)?$)"
    changed, count = re.subn(pattern, lambda match: match[1] + new + match[3], block)
    if count != 1 or changed == block:
        raise AssertionError(f"mutation did not change {function}:{pc}: {old!r}")
    return disassembly[:start] + changed + disassembly[end]


class JournalDescriptorSourceTests(unittest.TestCase):
    def test_journal_entry_proves_its_descriptor_source(self):
        """The journal capture entry gates DESCRIPTORS on the unset side."""
        section, name, lines = select(fragment=CAPTURE_ENTRY_FRAGMENT)
        self.assertEqual(section, ".text")
        report = descriptor_source_case(section, name, lines)
        self.assertEqual(report["descriptor_source"], "count_only_gated")
        self.assertGreaterEqual(len(report["switch_lookups"]), 1)
        self.assertEqual(report["set_arm_argument_reads"], [])
        seen = len(report["object_marker_lookups"]) + len(report["object_marker_calls"])
        self.assertGreaterEqual(seen, 1, "the journal entry consults the object marker")

    def test_journal_returns_prove_their_descriptor_source(self):
        """Every journal return instantiation gates DESCRIPTORS on the unset side."""
        for fragment in (ORDINARY_RETURN_FRAGMENT, OBJECT_RETURN_FRAGMENT):
            matches = select_all(fragment=fragment)
            self.assertEqual(len(matches), 2, f"{fragment}: base + length instantiations")
            for section, name, lines in matches:
                with self.subTest(fragment=fragment, name=name):
                    self.assertEqual(section, ".text")
                    report = descriptor_source_case(section, name, lines)
                    self.assertEqual(report["descriptor_source"], "count_only_gated")
                    self.assertGreaterEqual(len(report["switch_lookups"]), 1)
                    self.assertEqual(report["set_arm_argument_reads"], [])

    def test_journal_roots_delegate_to_proven_consumers(self):
        """The journal roots exist and the entry root calls the proven capture."""
        entry_section, entry_name, entry_lines = select(exact=ENTRY_ROOT)
        self.assertEqual(entry_section, "uprobe")
        return_section, return_name, _ = select(exact=RETURN_ROOT)
        self.assertEqual(return_section, "uretprobe")
        length_entry_section, length_entry_name, _ = select(exact=LENGTH_ENTRY_ROOT)
        self.assertEqual(length_entry_section, "uprobe")
        length_return_section, _, _ = select(exact=LENGTH_RETURN_ROOT)
        self.assertEqual(length_return_section, "uretprobe")
        _, capture_name, _ = select(fragment=CAPTURE_ENTRY_FRAGMENT)
        split = CHECKER["sections"](DISASSEMBLY)
        text = CHECKER["joined"](split, entry_section, ".text")
        targets = [target for caller, _, _, target in CHECKER["D"].internal_call_targets(text)
                   if caller == entry_name and target is not None]
        self.assertIn(capture_name, targets,
                      "p11_entry_journal must call the proven capture entry")
        length_targets = [target for caller, _, _, target in CHECKER["D"].internal_call_targets(text)
                          if caller == length_entry_name and target is not None]
        self.assertIn(capture_name, length_targets,
                      "p11_entry_journal_length must call the proven capture entry")

    def test_journal_removal_rejects_the_descriptor_source(self):
        """Switch/flag removal and polarity flip reject the journal proof."""
        section, name, lines = select(fragment=CAPTURE_ENTRY_FRAGMENT)
        report = descriptor_source_case(section, name, lines)
        self.assertEqual(report["set_arm_argument_reads"], [])
        consumer, _, _, _ = consumer_case(section, name, lines)
        lookup = report["switch_lookups"][0]
        flag = report["flag_branches"][0]
        flag_text = consumer.text[flag]
        self.assertIn("goto", flag_text)
        flipped = flag_text.replace("==", "!=", 1) \
            if "==" in flag_text else flag_text.replace("!=", "==", 1)
        self.assertNotEqual(flipped, flag_text)
        for control, pc, old, new in [
                ("switch lookup removed", lookup, "call 0x1", "r0 = 0x0"),
                ("flag test removed", flag, flag_text, "goto +0x0"),
                ("flag polarity flipped", flag, flag_text, flipped)]:
            with self.subTest(control=control), self.assertRaisesRegex(RuntimeError, "descriptor source"):
                descriptor_source_case(section, name, lines,
                                       mutate(DISASSEMBLY, name, pc, old, new))

    def test_journal_switch_reads_live_only_in_proven_consumers(self):
        """Completeness: only the proven consumers read the switch."""
        split = CHECKER["sections"](DISASSEMBLY)
        proven = {name for fragment in (
            CAPTURE_ENTRY_FRAGMENT, ORDINARY_RETURN_FRAGMENT, OBJECT_RETURN_FRAGMENT)
            for _, name, _ in select_all(fragment=fragment)}
        # Capture plus both instantiations of each return consumer.
        self.assertEqual(len(proven), 5)
        readers = set()
        for section in ("uprobe", "uretprobe", ".text"):
            for name, lines in CHECKER["D"].function_blocks(split[section]).items():
                targets = [target for _, _, target in CHECKER["D"].relocation_targets(lines)]
                if "SLOT_COUNT_ONLY" in targets:
                    readers.add(name)
        self.assertEqual(readers, proven)


if __name__ == "__main__":
    path = os.environ.get("P11SCOPE_JOURNAL_DESCRIPTOR_OBJECT")
    if not path:
        raise SystemExit("set P11SCOPE_JOURNAL_DESCRIPTOR_OBJECT to the journal object")
    DISASSEMBLY = subprocess.run(
        ["llvm-objdump", "-dr", "--print-imm-hex", path],
        capture_output=True, text=True, check=True,
    ).stdout
    unittest.main(argv=[sys.argv[0], *sys.argv[1:]])
