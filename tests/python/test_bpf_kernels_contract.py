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

import json
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


def check_kernel_sums(bpf_text, sums_dir, other_kernels=()):
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
        known = set(kernels) | set(other_kernels)
        extra = sorted(path.name for path in sums_dir.glob("*.sums")
                       if path.stem not in known and path.stem != "v5.15.221")
        for name in extra:
            problems.append(f"sums file outside the matrix: {name}")
    return problems


def check_no_tag_triggers(text):
    """Tag pushes trigger nothing; every branch push and PR still does.

    Release tags ride the same commit a branch push already ran
    (RELEASING.md pushes main and the tag together), so a tag run only
    duplicates the matrix on an identical SHA. GitHub runs nothing for
    an undefined ref type, so the push block must allow every branch
    explicitly next to tags-ignore; tags-ignore alone stops branch
    pushes too. Returns a problem list, like the other check_* helpers.
    """
    problems = []
    push = re.search(r"^  push:\n((?:    .*\n)+)", text, re.M)
    if not push:
        return ["no indented push: trigger block"]
    block = push.group(1)
    branches = re.search(r"^    branches:\n((?:      .*\n)+)", block, re.M)
    if not branches or "'**'" not in branches.group(1):
        problems.append("push: does not run every branch push")
    ignored = re.search(r"^    tags-ignore:\n((?:      .*\n)+)",
                        block, re.M)
    if not ignored or "'**'" not in ignored.group(1):
        problems.append("push: does not ignore tags")
    if re.search(r"^    tags:", block, re.M):
        problems.append("push: allows tag pushes")
    if "\n  pull_request:\n" not in text:
        problems.append("pull_request trigger missing")
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
        # privileged-tests.yml's public-cli guests share the sums directory.
        priv = (ROOT / ".github" / "workflows" / "privileged-tests.yml").read_text(encoding="utf-8")
        match = re.search(r"kernel:\s*\[host,([^\]]*)\]", priv)
        others = [k.strip() for k in match.group(1).split(",")] if match else []
        self.assertTrue(others, "privileged-tests.yml names no guest kernels")
        self.assertEqual([], check_kernel_sums(self.bpf, SUMS_DIR, others))

    def test_active_positives_and_combined_stock_refusals_are_separate(self):
        self.assertEqual(matrix_kernels(self.bpf),
                         ["v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1"])
        controls = re.findall(r"- kernel: (v[0-9.]+)\n\s+refusal_control: true", self.bpf)
        self.assertEqual(controls, ["v6.1.188", "v5.15.221"])
        self.assertEqual(self.bpf.count("scripts/check-multi-host-refusal.py"), 1)
        self.assertIn("if: matrix.refusal_control != true", self.bpf)
        self.assertIn("if: matrix.refusal_control == true", self.bpf)

    def test_tag_pushes_trigger_nothing(self):
        self.assertEqual([], check_no_tag_triggers(self.bpf))
        self.assertEqual([], check_no_tag_triggers(self.ci))

    def test_trigger_check_catches_branch_and_tag_regressions(self):
        base = ("on:\n  push:\n    branches:\n      - '**'\n"
                "    tags-ignore:\n      - '**'\n  pull_request:\n")
        self.assertEqual([], check_no_tag_triggers(base))
        dropped_branches = base.replace("    branches:\n      - '**'\n",
                                        "")
        self.assertIn("push: does not run every branch push",
                      check_no_tag_triggers(dropped_branches))
        restricted = base.replace("      - '**'\n", "      - 'main'\n", 1)
        self.assertIn("push: does not run every branch push",
                      check_no_tag_triggers(restricted))
        dropped_ignore = base.replace("    tags-ignore:\n      - '**'\n",
                                      "")
        self.assertIn("push: does not ignore tags",
                      check_no_tag_triggers(dropped_ignore))
        allowed_tags = base.replace("    tags-ignore:\n",
                                    "    tags:\n      - '**'\n"
                                    "    tags-ignore:\n")
        self.assertIn("push: allows tag pushes",
                      check_no_tag_triggers(allowed_tags))
        dropped_pr = base.replace("  pull_request:\n", "")
        self.assertIn("pull_request trigger missing",
                      check_no_tag_triggers(dropped_pr))

    def test_lib_cells_run_in_66_and_612_guests(self):
        match = re.search(r"lib-cells-kernels:.*?matrix:\n\s+kernel: \[(.*?)\]",
                          self.bpf, re.S)
        self.assertTrue(match, "lib-cells-kernels names no matrix kernels")
        kernels = [kernel.strip() for kernel in match.group(1).split(",")]
        self.assertEqual(kernels, ["v6.6.157", "v6.12.111"])
        self.assertEqual(self.bpf.count("scripts/ci/lib-cells-vng.sh"), 2)
        job = self.bpf[match.start():self.bpf.index("bpf-load-host:")]
        self.assertIn("gcc", job)

    def test_lib_cells_job_installs_the_provider_toolchain(self):
        # The guest shares the runner rootfs, so the provider cells see
        # only what this job installs: SoftHSM plus the p11-kit headers
        # the privileged test shards install.
        match = re.search(r"lib-cells-kernels:.*?matrix:\n\s+kernel: \[(.*?)\]",
                          self.bpf, re.S)
        self.assertTrue(match, "lib-cells-kernels names no matrix kernels")
        job = self.bpf[match.start():self.bpf.index("bpf-load-host:")]
        for package in ("softhsm2", "libp11-kit-dev"):
            with self.subTest(package=package):
                self.assertIn(package, job)

    def test_only_515_runs_the_denial_cell_for_its_denied_branch(self):
        branches = re.findall(r"- kernel: (v[0-9.]+)\n\s+refusal_control: true\n(?:\s+#.*\n)*\s+denial_branch: (\w+)",
                              self.bpf)
        self.assertEqual(branches, [("v5.15.221", "denied")])
        self.assertIn("--denial \"${{ matrix.denial_branch }}\"", self.bpf)

    def test_kernel_workflow_preserves_existing_concurrency_policy(self):
        self.assertIn("cancel-in-progress: true", self.bpf)

    def test_positive_load_commands_request_multi(self):
        driver = (ROOT / "scripts/check-bpf-load-kernels.sh").read_text()
        self.assertIn("inventory --system --capture native --attach-backend multi", driver)
        self.assertIn("--attach-backend multi --counter-mode $MODE", driver)
        self.assertIn("--prearm-module /bin/true --attach-backend multi", driver)
        self.assertNotIn("v5.15.*|v6.1.*)", driver)

    def test_witness_gate_legs_probe_through_cgroup_scope(self):
        # p11_pw_migrate loads only for --cgroup (spec section 4.4), so
        # both witness legs must probe through the production cgroup
        # path: a --system probe loads no migrate, which the budgeted
        # guest leg FAILs (missing root) and the budgetless host leg
        # silently never scores.
        driver = (ROOT / "scripts/check-bpf-load-kernels.sh").read_text()
        self.assertIn("--cgroup /sys/fs/cgroup --prearm-module /bin/true", driver)
        self.assertNotIn("--system --prearm-module", driver)
        self.assertIn("--cgroup /sys/fs/cgroup --prearm-module /bin/true", self.bpf)
        self.assertNotIn("--system --prearm-module", self.bpf)
        budgets = json.loads((ROOT / "tests/bpf-verifier-budgets.json").read_text(
            encoding="ascii"))
        self.assertIn("prearm-witness/p11_pw_migrate", budgets["programs"])


if __name__ == "__main__":
    unittest.main()
