# SPDX-License-Identifier: GPL-3.0-or-later
"""Real-object guard for the timing bank producer, its timestamps R4 build,
and the counts/timing route-copy pin.

The producer (`crates/ebpf/native/counter_bank_timing.c`) links only inside
a full bank object, so the guard compiles it with the exact project BPF
flags plus three minimal START stubs (map identities and owner
constructor/dead-code shapes the producer expects) and runs the checker's
own `BankFootprint` growth proof on the real emitted code. A bitcode-only
compile cannot see optimizer deletions: clang folds the latency bucket
chain and drops the clamp unless a barrier keeps it, and only the growth
proof on the real object refuses that.
"""

import difflib
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-counter-object.py"
NATIVE = ROOT / "crates/ebpf/native"
PRODUCER = NATIVE / "counter_bank_timing.c"
COUNTS = NATIVE / "counter_bank_proof.c"
HARNESS_SOURCE = ROOT / "tests/fixtures/task-owner/helper_tests.c"

# Minimal START stubs so the producer links as a BPF object: the three map
# identities the producer declares extern, plus the three owner constructors
# it calls. The stubs are never executed by the proof; they only satisfy
# the link. Compiled with the producer in one translation unit.
STUB_HARNESS = """#include "counter_bank_timing.c"
unsigned char COUNTER_HEALTH SEC(".maps");
unsigned char RV_COUNTS SEC(".maps");
unsigned char START SEC(".maps");
__attribute__((noinline)) void *p11_owner_start_get(const struct owner_start_key *key, u32 required)
{ (void)required; return owner_map_lookup(&START, key); }
__attribute__((noinline)) long p11_owner_start_remove(const struct owner_start_key *key, u32 required)
{ (void)required; return owner_map_delete(&START, key); }
__attribute__((noinline)) u32 p11_owner_start_aggregate(const struct owner_start_key *key, u64 ts)
{ (void)key; (void)ts; return 1; }
"""

# The R4 timing suites, mirrored from the LATENCY driver
# (`production_counter_bank_timing_helpers` in
# tests/task_owner_contracts.rs); the timestamps build below runs the same
# five against the timestamps producer.
R4_TIMING_SUITES = [
    "bank_timing_add_saturates",
    "bank_timing_max_exact_eight_and_contention",
    "bank_timing_ts_before_remove",
    "bank_timing_enter_writes_no_buckets",
    "bank_timing_enter_stores_clock",
]

# Map shapes for the growth proof, as the production bank objects carry
# them: outer HASH_OF_MAPS over 16 banks, 8192-slot route/commit tables,
# single-cell fault/health, full RV and START tables, and the mode-sized
# inner value the proof substitutes at the map-of-maps edge.
PROOF_MAPS = {
    "COUNTER_BANKS": (13, 4, 4, 16),
    "COUNTER_BANK_META": (1, 4, 32, 8192),
    "COUNTER_BANK_COMMIT": (1, 8, 16, 8192),
    "COUNTER_BANK_FAULT": (6, 4, 8, 1),
    "COUNTER_HEALTH": (6, 4, 8, 2),
    "RV_COUNTS": (5, 16, 8, 65536),
    "START": (1, 16, 288, 16384),
}
PROOF_MODES = (("TIMESTAMPS", "timestamps"), ("LATENCY", "latency"))
TIMESTAMPS_FIELDS = (0, 8, 16, 24, 32)


def require_clang(case):
    if shutil.which("clang-18") is None:
        raise unittest.SkipTest("clang-18 is required to compile the timing producer guard")


class TimingObjectProofTests(unittest.TestCase):
    """The real BPF object passes the growth proof in both modes."""

    @classmethod
    def setUpClass(cls):
        require_clang(cls)
        cls.temporary = tempfile.TemporaryDirectory(prefix="p11scope-timing-object-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        target = "bpfeb" if sys.byteorder == "big" else "bpfel"
        cls.objects = {}
        for mode, _ in PROOF_MODES:
            harness = directory / f"timing-stubs-{mode}.c"
            harness.write_text(STUB_HARNESS)
            obj = directory / f"timing-{mode}.o"
            # Exact project flags (build.rs native compile), minus
            # -emit-llvm: this guard needs the real BPF object, not
            # bitcode. The -I only resolves the harness include.
            compiled = subprocess.run(
                ["clang-18", "-target", target, "-O2", "-g",
                 "-gno-record-gcc-switches",
                 "-fdebug-compilation-dir=/p11scope/native",
                 "-Wall", "-Wextra", "-Werror", "-c",
                 f"-ffile-prefix-map={ROOT}=/p11scope",
                 "-DP11SCOPE_COUNTER_BANK_PROOF",
                 f"-DP11SCOPE_BANK_MODE_{mode}",
                 "-I", str(NATIVE), str(harness), "-o", obj.name],
                cwd=directory, capture_output=True, text=True, timeout=120)
            assert compiled.returncode == 0, (
                f"{mode} producer object compile: "
                + compiled.stdout + compiled.stderr)
            assert obj.is_file(), f"{mode} producer object emitted"
            cls.objects[mode] = obj
        cls.checker = runpy.run_path(str(CHECKER), run_name="timing_object_guard")

    def prove(self, mode, function, arguments):
        """Run the growth proof; fail loudly with the refusal wording."""
        checker = self.checker
        graph = checker["CallGraph"](self.objects[mode].read_bytes())
        define = checker["MAPS"].map_def
        size = checker["STATS_BYTES"][mode.lower()]
        maps = {name: define(*shape) for name, shape in PROOF_MAPS.items()}
        maps["COUNTER_BANK_VALUE"] = define(6, 4, size, 512)
        proof = checker["BankFootprint"](graph, maps, native_bound=8192,
                                         growth=True, mode=mode.lower())
        try:
            proof.run(graph.only(function), arguments)
        except RuntimeError as error:
            self.fail(f"{mode} {function} refused by the growth proof: {error}")
        return sorted({t[4] for t in proof.touches
                       if t[2] == "COUNTER_BANK_VALUE" and t[3] == "write"})

    def test_complete_is_accepted_with_bounded_inner_writes(self):
        scalar = self.checker["scalar"]
        arguments = [scalar(0, 0xffffffff), scalar(), scalar(),
                     scalar(0, 0xffffffff), scalar()]
        for mode, _ in PROOF_MODES:
            with self.subTest(mode=mode):
                spans = self.prove(mode, "p11_bank_complete_timed", list(arguments))
                self.assertTrue(spans, f"{mode} completion wrote no inner cells")
                for low, high in spans:
                    if high < 40:
                        self.assertEqual(low, high, f"{mode} span {low, high}")
                        self.assertIn(low, TIMESTAMPS_FIELDS, f"{mode} span {low, high}")
                    else:
                        self.assertEqual(mode, "LATENCY", f"bucket write in {mode}: {low, high}")
                        self.assertGreaterEqual(low, 40, f"span {low, high}")
                        self.assertLessEqual(high, 288, f"span {low, high}")
                if mode == "LATENCY":
                    self.assertTrue(any(high >= 40 for _, high in spans),
                                    f"latency completion wrote no buckets: {spans}")
                else:
                    self.assertFalse(any(high >= 40 for _, high in spans),
                                     f"timestamps completion wrote buckets: {spans}")

    def test_entry_bridge_is_accepted_writing_entered_only(self):
        scalar = self.checker["scalar"]
        arguments = [scalar(0, 0xffffffff), scalar(), scalar(), None, None]
        for mode, _ in PROOF_MODES:
            with self.subTest(mode=mode):
                spans = self.prove(mode, "p11_bank_enter_timed", list(arguments))
                self.assertEqual(spans, [(0, 0)], f"{mode} entry writes")


class TimestampsHarnessTests(unittest.TestCase):
    """The R4 timing suites also run against the timestamps producer."""

    @classmethod
    def setUpClass(cls):
        require_clang(cls)
        cls.temporary = tempfile.TemporaryDirectory(prefix="p11scope-timing-ts-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / "counter-bank-timing-ts"
        # Same host flags as the LATENCY R4 driver, timestamps mode.
        compiled = subprocess.run(
            ["clang-18", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-pthread",
             "-DP11SCOPE_COUNTER_BANK_PROOF", "-DP11SCOPE_BANK_MODE_TIMESTAMPS",
             "-I", str(NATIVE), str(HARNESS_SOURCE), "-o", str(cls.binary)],
            cwd=ROOT, capture_output=True, text=True, timeout=120)
        assert compiled.returncode == 0, (
            "timestamps harness compile: "
            + compiled.stdout + compiled.stderr)

    def test_timestamps_suites_pass(self):
        for suite in R4_TIMING_SUITES:
            with self.subTest(suite=suite):
                ran = subprocess.run([str(self.binary), suite], capture_output=True,
                                     text=True, timeout=120)
                self.assertEqual(ran.returncode, 0,
                                 f"timestamps {suite}: {ran.stderr}")


def function_body(text, name):
    """The braced body of the one `static INLINE` definition of `name`."""
    matches = list(re.finditer(r"static INLINE [^{]*?\b" + name + r"\([^;]*?\)\s*\{",
                               text, re.DOTALL))
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one definition of {name}, found {len(matches)}")
    start = matches[0].end() - 1
    depth = 0
    for end in range(start, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if not depth:
                return text[start:end + 1]
    raise AssertionError(f"unterminated body for {name}")


# The two bank producers cannot share code (the counts file is byte-pinned),
# so the timing file duplicates route/fault/completed_rv with systematic
# renames only: task_owner.h map helpers for the local ones, and the timing
# value/route/commit type names. Anything beyond these renames is drift.
COPY_RENAMES = (
    (r"\blookup\(", "owner_map_lookup("),
    (r"\bupdate\(", "owner_map_update("),
    ("struct counts_bank_route", "struct bank_route"),
    ("struct counts_bank_commit", "struct bank_commit"),
)


def normalized_counts_body(name):
    body = function_body(COUNTS.read_text(), name)
    for pattern, replacement in COPY_RENAMES:
        body = re.sub(pattern, replacement, body)
    return body


class RouteCopyPinTests(unittest.TestCase):
    """The duplicated route/fault/RV bodies match modulo known renames."""

    def test_copies_match_counts_modulo_renames(self):
        timing = PRODUCER.read_text()
        for name in ("route", "fault", "completed_rv"):
            with self.subTest(function=name):
                expected = function_body(timing, name)
                actual = normalized_counts_body(name)
                self.assertGreater(len(expected), 100, f"{name} body too short to pin")
                self.assertNotEqual(function_body(COUNTS.read_text(), name), expected,
                                    f"{name} copies are literally identical; the pin is vacuous")
                self.assertEqual(
                    actual, expected,
                    f"{name} drifted beyond the known renames:\n" + "".join(
                        difflib.unified_diff(actual.splitlines(True), expected.splitlines(True),
                                             "counts+renames", "timing")))


if __name__ == "__main__":
    unittest.main()
