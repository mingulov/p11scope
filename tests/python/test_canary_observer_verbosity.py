#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Every stopped-canary lane runs its observer with the text it parses.

The stopped canary proves the privacy tier post-exit from the observer
log: trace lanes match the unconditional `CAPTURE privacy=` line, while
profile/metrics lanes require the live frame's ` — privacy=` marker,
which the observer prints only under `-v`/`--verbose`. The harness must
therefore request verbose text on every non-trace observer launch and
leave trace launches concise (trace terminal wording is itself
verbosity-sensitive, so verbose trace output is not oracle-accepted).

This suite runs the real verify-canaries.sh end to end with stubbed
tools (stub cargo/gcc/sudo record argv and materialize fixture outputs;
no privilege, build, or capture happens) and pins the observer argv of
all fourteen lanes.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/canary-observer-verbosity"
DUAL_FIXTURES = ROOT / "tests/fixtures/dual-build-callers"

EXPECTED_LANES = {
    "default-safe-profile": "profile",
    "default-safe-trace": "trace",
    "feature-safe-profile": "profile",
    "feature-safe-trace": "trace",
    "feature-unsafe-profile": "profile",
    "feature-unsafe-trace": "trace",
    "aggregate-only-metrics": "metrics",
    "default-safe-start": "profile",
    "feature-safe-start": "profile",
    "feature-unsafe-fault": "profile",
    "object-lp64": "profile",
    "object-lp64-blocked": "profile",
    "owned-default-metrics": "metrics",
    "owned-feature-metrics": "metrics",
}

# Workload stand-in: publishes READY, then either lingers briefly and
# exits 0 (matrix/object lanes, which wait for success) or sleeps until
# SIGTERM (blocked lanes, which terminate it and expect status 143).
WORKLOAD_C = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 5) return 2;
    FILE *ready = fopen(argv[3], "w");
    if (!ready) return 3;
    fputs("ready\n", ready);
    if (fclose(ready) != 0) return 3;
    if (strcmp(argv[2], "matrix") == 0 || strcmp(argv[2], "object") == 0) {
        sleep(5);
        return 0;
    }
    for (;;) pause();
}
"""

# Discover stand-in: writes an empty manifest to the -o path. Manifest
# contents are irrelevant here (the oracles are stubbed); only the
# harness flow and the observer argv are under test.
DISCOVER_C = r"""
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *out = 0;
    for (int i = 1; i + 1 < argc; i++)
        if (strcmp(argv[i], "-o") == 0) out = argv[i + 1];
    if (!out) return 2;
    FILE *manifest = fopen(out, "w");
    if (!manifest) return 3;
    fputs("{}\n", manifest);
    return fclose(manifest) == 0 ? 0 : 3;
}
"""

ORACLE_STUB = """#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
raise SystemExit(0)
"""

READER_STUB = """#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
mkdir -p "$1" && cp "{elf}" "$1/dump-task-storage" && : > "$1/dump-task-storage.bpf.o"
"""

SEED_STUB = """#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
mkdir -p "$1" && cp "{elf}" "$1/task-storage-canary"
"""


class CanaryObserverVerbosityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope canary argv build ")
        cls.addClassCleanup(temporary.cleanup)
        build = Path(temporary.name)
        flags = ["gcc", "-O0", "-Wall", "-Wextra", "-Werror"]
        cls.workload = build / "workload-stub"
        (build / "workload-stub.c").write_text(WORKLOAD_C, encoding="utf-8")
        subprocess.run([*flags, str(build / "workload-stub.c"), "-o",
                        str(cls.workload)], check=True)
        cls.discover = build / "discover-stub"
        (build / "discover-stub.c").write_text(DISCOVER_C, encoding="utf-8")
        subprocess.run([*flags, str(build / "discover-stub.c"), "-o",
                        str(cls.discover)], check=True)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope canary argv ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "checkout with spaces"
        scripts = self.repo / "scripts"
        scripts.mkdir(parents=True)
        for name in ("verify-canaries.sh", "product-build.sh", "cargo.sh",
                     "lib.sh", "cleanup-traps.sh", "release-matrix-contract.py",
                     "lane-lib-oracle-1.py"):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        shutil.copy2(DUAL_FIXTURES / "record-preparer.py",
                     scripts / "prepare-dependencies.py")
        for name in ("check-bpf-map-defs.py", "check-capture-evidence.py",
                     "check-canary-evidence.py", "dump-owned-bpf-maps.py"):
            (scripts / name).write_text(ORACLE_STUB, encoding="utf-8")
        (scripts / "build-task-storage-reader.sh").write_text(
            READER_STUB.format(elf=self.discover), encoding="utf-8")
        (scripts / "build-task-storage-reader.sh").chmod(0o755)
        (scripts / "build-task-storage-canary.sh").write_text(
            SEED_STUB.format(elf=self.discover), encoding="utf-8")
        (scripts / "build-task-storage-canary.sh").chmod(0o755)
        shutil.copy2(ROOT / ".release-rust-version",
                     self.repo / ".release-rust-version")
        self.bin = self.base / "PATH tripwires"
        self.bin.mkdir()
        for tool, stub in (("cargo", "cargo-stub.py"), ("gcc", "gcc-stub.py"),
                           ("sudo", "sudo-stub.py")):
            target = self.bin / stub
            shutil.copy2(FIXTURES / stub, target)
            target.chmod(0o755)
            (self.bin / tool).symlink_to(stub)
        for name in ("bpftool", "clang-18", "rustup", "softhsm2-util"):
            target = self.bin / name
            shutil.copy2(DUAL_FIXTURES / "unused-tool.sh", target)
            target.chmod(0o755)
        self.work = self.base / "private work"
        self.work.mkdir()
        shutil.copy2(self.workload, self.work / "canary_workload")
        (self.work / "canary_workload").chmod(0o755)
        for provider in ("matrix-provider.so", "privacy-provider.so"):
            shutil.copy2(self.discover, self.work / provider)
        self.events = self.base / "events.jsonl"
        self.config = self.base / "config.json"
        self.config.write_text(json.dumps({
            "events": str(self.events),
            "elf": str(self.discover),
            "discover": str(self.discover),
        }), encoding="utf-8")
        self.environment = os.environ.copy()
        for name in ("P11SCOPE_PREPARED_STABLE_CARGO",
                     "P11SCOPE_PREPARED_STABLE_RUSTC",
                     "P11SCOPE_PREPARED_BPF_CARGO",
                     "P11SCOPE_PREPARED_BPF_RUSTC",
                     "P11SCOPE_PRODUCT_BUILD_MODE",
                     "P11SCOPE_CANARY_ARGV_CONFIG",
                     "P11SCOPE_DUAL_BUILD_CONFIG"):
            self.environment.pop(name, None)
        self.environment.update(
            PATH=f"{self.bin}:/usr/bin:/bin",
            P11SCOPE_CANARY_ARGV_CONFIG=str(self.config),
            P11SCOPE_DUAL_BUILD_CONFIG=str(self.config),
            P11SCOPE_CANARY_TARGET_BITS="64",
            P11SCOPE_RECEIPT_WORK=str(self.work),
        )

    def canary_launches(self):
        launches = []
        for row in self.events.read_text().splitlines():
            event = json.loads(row)
            if event["kind"] != "sudo":
                continue
            argv = event["argv"]
            if "scripts/capture-stopped-canary.py" not in argv:
                continue
            launches.append(argv)
        return launches

    @staticmethod
    def flag_value(argv, flag):
        for index, token in enumerate(argv):
            if token == flag and index + 1 < len(argv):
                return argv[index + 1]
        return None

    def test_non_trace_lanes_request_verbose_observer_text(self):
        result = subprocess.run(
            ["sh", str(self.repo / "scripts/verify-canaries.sh")],
            cwd=self.base, env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        self.assertEqual(result.returncode, 0,
                         f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        self.assertIn("=== canary matrix: ALL OK ===", result.stdout)
        launches = self.canary_launches()
        seen = {}
        for argv in launches:
            lane = self.flag_value(argv, "--lane")
            mode = self.flag_value(argv, "--mode")
            self.assertIsNotNone(lane, argv)
            self.assertIsNotNone(mode, argv)
            self.assertNotIn(lane, seen, f"duplicate canary lane: {lane}")
            self.assertIn(lane, EXPECTED_LANES, f"unexpected canary lane: {lane}")
            self.assertEqual(mode, EXPECTED_LANES[lane], f"lane {lane} changed mode")
            self.assertIn("--", argv)
            seen[lane] = argv[argv.index("--") + 1:]
        self.assertEqual(set(seen), set(EXPECTED_LANES),
                         "the probe must reach every lane")
        unverbose, verbose_trace = [], []
        for lane, observer in seen.items():
            requested = "-v" in observer or "--verbose" in observer
            if EXPECTED_LANES[lane] == "trace":
                if requested:
                    verbose_trace.append(lane)
            elif not requested:
                unverbose.append(lane)
        self.assertEqual(unverbose, [],
                         "non-trace lanes must run the observer verbose: "
                         "the stopped canary proves the tier from the "
                         "verbose-only live-frame marker")
        self.assertEqual(verbose_trace, [],
                         "trace lanes must stay concise: trace terminal "
                         "wording is verbosity-sensitive")
        for lane, observer in seen.items():
            self.assertTrue(os.path.isabs(observer[0]),
                            f"lane {lane}: observer path must be absolute")


if __name__ == "__main__":
    unittest.main()
