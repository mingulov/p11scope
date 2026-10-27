#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Contract for the bpf-kernels trial workflow.

The trial copies its toolchain setup from ci.yml's tests job, and the
hosted_pipeline_* contract tests read ci.yml only, so a toolchain bump
could leave bpf-kernels.yml behind with no test noticing. These tests
pin the two-way agreement instead of the values: whatever ci.yml pins
for bpf-linker, the nightly and release toolchains, clang and the
actions revisions, bpf-kernels.yml must carry the same. They also pin
that every matrix kernel has a checked-in vng download sums file, and
no unknown sums file escapes review. Historical 5.15 sums remain pinned.

Run: python3 -I tests/python/test_bpf_kernels_contract.py -v
"""

import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
BPF_YML = ROOT / ".github" / "workflows" / "bpf-kernels.yml"
RELEASE_RUST_VERSION = ROOT / ".release-rust-version"
SUMS_DIR = ROOT / "tests" / "fixtures" / "vng-kernel-sha256sums"

SUMS_LINE = re.compile(r"^[0-9a-f]{64}  (\S+)$")
DEB_NAME = re.compile(r"^linux-(image-unsigned|modules)-[^-]+-.*_amd64\.deb$")


def check_bpf_linker(ci_text, bpf_text):
    """CI_TOOL_BPF_LINKER is defined once in each file, with equal values."""
    problems = []
    values = {}
    for name, text in (("ci.yml", ci_text), ("bpf-kernels.yml", bpf_text)):
        found = re.findall(r"^\s*CI_TOOL_BPF_LINKER:\s*\"?([^\"\s]+)\"?",
                           text, re.M)
        if not found:
            problems.append(f"{name} defines no CI_TOOL_BPF_LINKER")
        else:
            values[name] = found[0]
            if len(set(found)) > 1:
                problems.append(f"{name} defines CI_TOOL_BPF_LINKER twice: "
                                f"{sorted(set(found))}")
    if len(values) == 2 and values["ci.yml"] != values["bpf-kernels.yml"]:
        problems.append("CI_TOOL_BPF_LINKER drifted: ci.yml "
                        f"{values['ci.yml']} vs bpf-kernels.yml "
                        f"{values['bpf-kernels.yml']}")
    return problems


def check_nightly(ci_text, bpf_text):
    """Both files name the same nightly toolchain(s), and at least one."""
    problems = []
    ci = set(re.findall(r"nightly-(\d{4}-\d{2}-\d{2})", ci_text))
    bpf = set(re.findall(r"nightly-(\d{4}-\d{2}-\d{2})", bpf_text))
    if not ci:
        problems.append("ci.yml names no nightly toolchain")
    if not bpf:
        problems.append("bpf-kernels.yml names no nightly toolchain")
    elif ci and bpf != ci:
        problems.append(f"nightly drifted: ci.yml {sorted(ci)} vs "
                        f"bpf-kernels.yml {sorted(bpf)}")
    return problems


def check_release_toolchain(bpf_text, release_version):
    """bpf-kernels.yml tracks the release compiler through the version
    file, never a hardcoded literal."""
    problems = []
    if release_version and release_version in bpf_text:
        problems.append("bpf-kernels.yml hardcodes the release toolchain "
                        f"{release_version}; use $(cat .release-rust-version)")
    if "cat .release-rust-version" not in bpf_text:
        problems.append("bpf-kernels.yml no longer reads "
                        ".release-rust-version")
    return problems


def check_clang(ci_text, bpf_text):
    """Both files name the same clang major version(s), and at least one."""
    problems = []
    ci = set(re.findall(r"clang-(\d+)", ci_text))
    bpf = set(re.findall(r"clang-(\d+)", bpf_text))
    if not ci:
        problems.append("ci.yml names no clang version")
    if not bpf:
        problems.append("bpf-kernels.yml names no clang version")
    elif ci and bpf != ci:
        problems.append(f"clang drifted: ci.yml {sorted(ci)} vs "
                        f"bpf-kernels.yml {sorted(bpf)}")
    return problems


def check_action_pins(ci_text, bpf_text):
    """Every actions pin in bpf-kernels.yml is a full 40-hex SHA already
    used in ci.yml, so no new action revision enters unreviewed."""
    problems = []
    uses = re.findall(r"^\s*(?:-\s+)?uses:\s+(\S+)", bpf_text, re.M)
    if not uses:
        return ["bpf-kernels.yml has no uses: lines"]
    for pinned in uses:
        if "@" not in pinned:
            problems.append(f"unpinned action: {pinned}")
            continue
        repo, sha = pinned.rsplit("@", 1)
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            problems.append(f"action pin is not a full SHA: {pinned}")
        elif f"{repo}@{sha}" not in ci_text:
            problems.append(f"action pin not in ci.yml: {pinned}")
    return problems


def matrix_kernels(bpf_text):
    """The bpf-load-kernels matrix values, e.g. ['v5.15.221', ...]."""
    match = re.search(r"kernel:\s*\[(.*?)\]", bpf_text)
    if not match:
        return []
    return [kernel.strip() for kernel in match.group(1).split(",")
            if kernel.strip()]


def check_kernel_sums(bpf_text, sums_dir):
    """Every matrix kernel has a well-formed sums file; no sums file
    names an unknown kernel; historical 5.15 checksums are retained."""
    problems = []
    kernels = matrix_kernels(bpf_text)
    kernels += re.findall(r"- kernel: (v[0-9.]+)\n\s+refusal_control: true", bpf_text)
    if not kernels:
        return ["bpf-kernels.yml names no matrix kernels"]
    for kernel in kernels:
        path = sums_dir / f"{kernel}.sums"
        if not path.is_file():
            problems.append(f"missing sums file: {path.name}")
            continue
        numeric = kernel[1:] if kernel.startswith("v") else kernel
        seen = set()
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            match = SUMS_LINE.match(line)
            if not match:
                problems.append(f"{path.name}:{number}: not a sha256sum "
                                "line")
                continue
            deb = match.group(1)
            if "/" in deb or deb in seen:
                problems.append(f"{path.name}:{number}: bad or repeated "
                                f"name {deb!r}")
                continue
            seen.add(deb)
            if "headers" in deb or not DEB_NAME.match(deb) \
                    or numeric not in deb:
                problems.append(f"{path.name}:{number}: not a vng deb of "
                                f"{kernel}: {deb!r}")
        if not seen:
            problems.append(f"{path.name}: no deb sums recorded")
    if sums_dir.is_dir():
        extra = sorted(path.name for path in sums_dir.glob("*.sums")
                       if path.stem not in kernels and path.stem != "v5.15.221")
        for name in extra:
            problems.append(f"sums file outside the matrix: {name}")
    return problems


class BpfKernelsContractTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CI_YML.is_file(), "ci.yml is missing")
        self.assertTrue(BPF_YML.is_file(), "bpf-kernels.yml is missing")
        self.ci = CI_YML.read_text(encoding="utf-8")
        self.bpf = BPF_YML.read_text(encoding="utf-8")

    def test_bpf_linker_matches_ci(self):
        self.assertEqual([], check_bpf_linker(self.ci, self.bpf))

    def test_nightly_matches_ci(self):
        self.assertEqual([], check_nightly(self.ci, self.bpf))

    def test_release_toolchain_comes_from_the_version_file(self):
        release = RELEASE_RUST_VERSION.read_text(
            encoding="utf-8").strip()
        self.assertTrue(release, ".release-rust-version is empty")
        self.assertEqual([], check_release_toolchain(self.bpf, release))

    def test_clang_matches_ci(self):
        self.assertEqual([], check_clang(self.ci, self.bpf))

    def test_action_pins_are_in_ci(self):
        self.assertEqual([], check_action_pins(self.ci, self.bpf))

    def test_kernel_sums_cover_the_matrix(self):
        self.assertEqual([], check_kernel_sums(self.bpf, SUMS_DIR))

    def test_active_positives_and_one_combined_stock_refusal_are_separate(self):
        self.assertEqual(matrix_kernels(self.bpf),
                         ["v6.6.157", "v6.12.111", "v6.18.58"])
        controls = re.findall(r"- kernel: (v[0-9.]+)\n\s+refusal_control: true", self.bpf)
        self.assertEqual(controls, ["v6.1.188"])
        self.assertEqual(self.bpf.count("scripts/check-multi-host-refusal.py"), 1)
        self.assertIn("if: matrix.refusal_control != true", self.bpf)
        self.assertIn("if: matrix.refusal_control == true", self.bpf)

    def test_final_kernel_campaign_is_not_cancelled_by_successor_push(self):
        self.assertIn("cancel-in-progress: false", self.bpf)

    def test_positive_load_commands_request_multi(self):
        driver = (ROOT / "scripts/check-bpf-load-kernels.sh").read_text()
        self.assertIn("inventory --system --capture native --attach-backend multi", driver)
        self.assertIn("--attach-backend multi --counter-mode $MODE", driver)
        self.assertNotIn("v5.15.*|v6.1.*)", driver)


if __name__ == "__main__":
    unittest.main()
