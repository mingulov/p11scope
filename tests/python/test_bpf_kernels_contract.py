#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the bpf-kernels trial workflow.

The trial copies its toolchain setup from ci.yml's tests job, and the
hosted_pipeline_* contract tests read ci.yml only, so a toolchain bump
could leave bpf-kernels.yml behind with no test noticing. These tests
pin the two-way agreement instead of the values: whatever ci.yml pins
for bpf-linker, the nightly and release toolchains, clang and the
actions revisions, bpf-kernels.yml must carry the same. They also pin
that every selector-listed kernel has a well-formed vng download sums
file, and no unknown sums file escapes review. Kernel lists themselves
live in scripts/ci/select-cells.py (tier contract).

Run: python3 -I tests/python/test_bpf_kernels_contract.py -v
"""

import importlib.util
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
RC_VECTORS = ROOT / "tests" / "fixtures" / "rc-match-vectors.json"

_SPEC = importlib.util.spec_from_file_location(
    "select_cells", ROOT / "scripts" / "ci" / "select-cells.py")
SELECT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(SELECT)

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


def selected_kernels():
    """Every kernel the selector lists: BPF positives, refusal rows,
    lib cells and CLI guests. Kernel matrices render through dynamic
    matrices, so the sums contract reads the selector, not YAML."""
    kernels = list(SELECT.BPF_POSITIVE_KERNELS)
    kernels += [row["kernel"] for row in SELECT.BPF_REFUSAL_ROWS]
    kernels += list(SELECT.LIB_CELL_KERNELS)
    for guests in SELECT.CLI_FULL_KERNELS.values():
        kernels += [kernel for kernel in guests if kernel != "host"]
    return kernels


def deb_matches_kernel(deb, kernel):
    """True when a vng deb filename belongs to a matrix kernel tag.

    Stable tags match by substring (v7.3.1 ships 7.3.1 debs).
    Release candidates ship the dotted triplet instead (v7.4-rc1 ships
    7.4.0-070400rc1 debs), so the triplet prefix plus the same rc
    marker must match, never another rc number (mirrors
    scripts/bpf-guest-release.sh). Every marker occurrence is
    examined, like the shell glob: the name matches when any
    occurrence carries no digit tail. Shared vectors in
    tests/fixtures/rc-match-vectors.json pin the agreement."""
    numeric = kernel[1:] if kernel.startswith("v") else kernel
    if numeric in deb:
        return True
    base, sep, tag = numeric.partition("-rc")
    if not sep or not tag.isdigit():
        return False
    at = deb.find(f"{base}.0-")
    if at < 0:
        return False
    marker = f"rc{tag}"
    pos = deb.find(marker, at)
    while pos >= 0:
        tail = deb[pos + len(marker):pos + len(marker) + 1]
        if tail == "" or not tail.isdigit():
            return True
        pos = deb.find(marker, pos + 1)
    return False


def check_kernel_sums(kernels, sums_dir):
    """Every selector-listed kernel has a well-formed sums file; no
    sums file names an unknown kernel."""
    problems = []
    if not kernels:
        return ["the selector lists no kernels"]
    for kernel in kernels:
        path = sums_dir / f"{kernel}.sums"
        if not path.is_file():
            problems.append(f"missing sums file: {path.name}")
            continue
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
                    or not deb_matches_kernel(deb, kernel):
                problems.append(f"{path.name}:{number}: not a vng deb of "
                                f"{kernel}: {deb!r}")
        if not seen:
            problems.append(f"{path.name}: no deb sums recorded")
    if sums_dir.is_dir():
        known = set(kernels)
        extra = sorted(path.name for path in sums_dir.glob("*.sums")
                       if path.stem not in known)
        for name in extra:
            problems.append(f"sums file outside the matrix: {name}")
    return problems


def check_companion_pins(bpf_text):
    """The default build's companion selection is pinned once and every
    consumer reads the pin: both object-gate proof steps assert the
    build emitted exactly the pinned selection (counter objects and
    production journal present or exactly absent), and the counter and
    journal load legs run the matching load proof or exact-refusal
    control. A silent build-side companion change fails the build
    step instead of flipping the legs."""
    problems = []
    pins = {}
    for name in ("BPF_EXPECT_COUNTER_OBJECTS", "BPF_EXPECT_JOURNAL"):
        found = re.findall(rf"^\s*{name}:\s*\"?([01])\"?\s*$",
                           bpf_text, re.M)
        if not found:
            problems.append(f"bpf-kernels.yml defines no {name}")
        else:
            pins[name] = found[0]
            if len(found) > 1:
                problems.append(f"bpf-kernels.yml defines {name} twice: "
                                f"{found}")
    for step in ("Prove the default object carries no gate",
                 "Prove the gate-1 object carries the gate"):
        body = step_body(bpf_text, step)
        if body is None:
            problems.append(f"bpf-kernels.yml lost the {step} step")
            continue
        for name in ("BPF_EXPECT_COUNTER_OBJECTS", "BPF_EXPECT_JOURNAL"):
            if name not in body:
                problems.append(f"{step} does not read {name}")
    if '--expect-counter-objects "$BPF_EXPECT_COUNTER_OBJECTS"' not in bpf_text:
        problems.append("no counter leg passes --expect-counter-objects "
                        "from BPF_EXPECT_COUNTER_OBJECTS")
    if '--expect-journal "$BPF_EXPECT_JOURNAL"' not in bpf_text:
        problems.append("no journal leg passes --expect-journal "
                        "from BPF_EXPECT_JOURNAL")
    refusal = step_body(
        bpf_text,
        "Check each stock pre-Multi host falls back or refuses without "
        "side effects")
    if refusal is None:
        problems.append("bpf-kernels.yml lost the pre-Multi refusal step")
    elif '--expect-counter-objects "$BPF_EXPECT_COUNTER_OBJECTS"' not in refusal:
        problems.append("the pre-Multi refusal control does not pass "
                        "--expect-counter-objects from "
                        "BPF_EXPECT_COUNTER_OBJECTS")
    return problems


def step_body(bpf_text, step_name):
    """The shell body of one `- name:` step, or None when absent."""
    prefix = f"- name: {step_name}\n"
    start = bpf_text.find(prefix)
    if start < 0:
        return None
    rest = bpf_text[start:]
    match = re.search(r"\n      - ", rest[len(prefix):])
    if not match:
        return rest
    return rest[:len(prefix) + match.start()]


def check_driver_absence_flag(driver_text, flag, refusal, loads_gate,
                              name):
    """A load driver honors an explicit companion-absence expectation:
    it parses the flag, pins the exact documented refusal for the
    omitted build, and gates on zero loads in the absent arm."""
    problems = []
    if flag not in driver_text:
        problems.append(f"{name} parses no {flag} option")
    if refusal not in driver_text:
        problems.append(f"{name} never requires the exact refusal "
                        f"{refusal!r}")
    if loads_gate not in driver_text:
        problems.append(f"{name} never gates the absent arm on "
                        f"{loads_gate!r}")
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


def check_journal_key_sizes(bpf_text):
    """Every gate-1 journal leg loads the length pair.

    tests/bpf-verifier-budgets.json carries journal-gate1 length cells
    for every matrix kernel, and the report fails budgeted-but-missing
    roots, so each CI journal leg must pass --key-sizes to the driver:
    without it the length programs never load and their cells fail as
    missing from probe rows. Returns a problem list, like the other
    check_* helpers.
    """
    joined = re.sub(r"\\\n\s*", " ", bpf_text)
    calls = [match.group(0) for match in re.finditer(
        r"scripts/check-bpf-load-journal\.sh\b[^\n]*", joined)]
    if not calls:
        return ["bpf-kernels.yml never invokes check-bpf-load-journal.sh"]
    problems = []
    for call in calls:
        if "journal-gate1" not in call:
            continue
        if "--key-sizes 1" not in call and "--key-sizes=1" not in call:
            problems.append("gate-1 journal leg never passes --key-sizes "
                            "1, so the budgeted length pair never loads")
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
        self.assertEqual([], check_kernel_sums(selected_kernels(), SUMS_DIR))

    def test_deb_names_match_stable_and_rc_tags(self):
        # The same shared vectors the shell release_ok runs (multi-marker
        # inputs included): both matchers must agree on every one. Each
        # release is wrapped in a realistic vng deb filename; the version
        # half keeps the same markers, so a multi-marker release stays
        # multi-marker in the deb.
        vectors = json.loads(RC_VECTORS.read_text(encoding="ascii"))
        self.assertTrue(vectors, "rc-match-vectors.json names no vectors")
        for vector in vectors:
            with self.subTest(vector=vector):
                release = vector["release"]
                version = (release[:-len("-generic")]
                           if release.endswith("-generic") else release)
                deb = (f"linux-image-unsigned-{release}_{version}."
                       "202611012313_amd64.deb")
                self.assertEqual(deb_matches_kernel(deb, vector["tag"]),
                                 vector["expected"])

    def test_active_positives_and_combined_stock_refusals_are_separate(self):
        # Kernel lists live in the selector (tier contract pins them);
        # this pins the workflow half: the positive and refusal legs
        # split on the matrix flag, and the refusal driver runs once.
        rows = SELECT.BPF_REFUSAL_ROWS
        self.assertEqual([row["kernel"] for row in rows],
                         ["v6.1.188", "v5.15.221"])
        self.assertEqual(self.bpf.count("scripts/check-multi-host-refusal.py"), 1)
        self.assertIn("if: matrix.refusal_control != true", self.bpf)
        self.assertIn("if: matrix.refusal_control == true", self.bpf)

    def test_gate1_matrix_pins_the_newest_mainline_cell(self):
        # The gate-1 job renders the selector's gate-1 matrix, whose
        # positives end at the newest mainline cell (the tier contract
        # pins the full list and the YAML reference).
        self.assertEqual(SELECT.BPF_POSITIVE_KERNELS[-1], "v7.4-rc2")
        _, matrices = SELECT.build_selection(
            "bpf-kernels", "push", "refs/heads/dev/v0.8.0", "a" * 40,
            "full", {"known"}, "dev/v0.8.0")
        self.assertEqual(matrices["matrix_bpf_gate1"]["kernel"],
                         SELECT.BPF_POSITIVE_KERNELS)

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
        # The guest list lives in the selector (tier contract pins it);
        # this pins the workflow half: the vng driver runs twice (boot
        # check plus cells) in a job with a C toolchain.
        self.assertEqual(SELECT.LIB_CELL_KERNELS,
                         ["v6.6.157", "v6.12.111"])
        self.assertEqual(self.bpf.count("scripts/ci/lib-cells-vng.sh"), 2)
        job = self.bpf[self.bpf.index("  lib-cells-kernels:"):
                       self.bpf.index("  bpf-load-host:")]
        self.assertIn("gcc", job)

    def test_lib_cells_job_installs_the_provider_toolchain(self):
        # The guest shares the runner rootfs, so the provider cells see
        # only what this job installs: SoftHSM plus the p11-kit headers
        # the privileged test shards install.
        job = self.bpf[self.bpf.index("  lib-cells-kernels:"):
                       self.bpf.index("  bpf-load-host:")]
        for package in ("softhsm2", "libp11-kit-dev"):
            with self.subTest(package=package):
                self.assertIn(package, job)

    def test_only_515_runs_the_denial_cell_for_its_denied_branch(self):
        # The refusal rows live in the selector (tier contract pins
        # them); this pins that only 5.15 carries the denied branch and
        # the workflow passes it to the refusal driver.
        denied = [row["kernel"] for row in SELECT.BPF_REFUSAL_ROWS
                  if row.get("denial_branch") == "denied"]
        self.assertEqual(denied, ["v5.15.221"])
        self.assertIn("--denial \"${{ matrix.denial_branch }}\"", self.bpf)

    def test_concurrency_cancels_only_test_and_task_pushes(self):
        # The group carries the event, so a push can never cancel an
        # agent's dispatch; each dispatch adds its run id, so the
        # pending queue never replaces one either. Only pushes to
        # development branches cancel the run a newer push overtook.
        self.assertIn(
            "concurrency:\n"
            "  group: bpf-kernels-${{ github.event_name }}-${{ github.ref }}"
            "${{ github.event_name == 'workflow_dispatch' && "
            "format('-{0}', github.run_id) || '' }}\n"
            "  cancel-in-progress: ${{ github.event_name == 'push' && "
            "(startsWith(github.ref, 'refs/heads/test/') || "
            "startsWith(github.ref, 'refs/heads/task/')) }}",
            self.bpf)

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

    def test_companion_selection_is_pinned_once_and_read_everywhere(self):
        self.assertEqual([], check_companion_pins(self.bpf))

    def test_companion_pin_check_catches_a_dropped_leg(self):
        # Negative control: a leg that stops reading the pin must fail
        # the check while the pinned definition stays put.
        dropped = self.bpf.replace(
            '--expect-counter-objects "$BPF_EXPECT_COUNTER_OBJECTS"',
            '--expect-counter-objects 1')
        self.assertNotEqual(dropped, self.bpf)
        self.assertIn("no counter leg passes --expect-counter-objects "
                      "from BPF_EXPECT_COUNTER_OBJECTS",
                      check_companion_pins(dropped))

    def test_counter_legs_honor_an_absence_expectation(self):
        driver = (ROOT / "scripts/check-bpf-load-kernels.sh").read_text()
        self.assertEqual(
            [], check_driver_absence_flag(
                driver, "--expect-counter-objects",
                "counter-mode-unavailable-in-build: "
                "this build omits counter objects",
                "refused counter-mode-unavailable-in-build; "
                "no counter loads",
                "check-bpf-load-kernels.sh"))
        # The absent arm is a control on the same command, never a
        # hollowed leg: the positive counter command stays put.
        self.assertIn("--attach-backend multi --counter-mode $MODE",
                      driver)

    def test_counter_absence_check_catches_a_dropped_gate(self):
        driver = (ROOT / "scripts/check-bpf-load-kernels.sh").read_text()
        dropped = driver.replace(
            "refused counter-mode-unavailable-in-build; no counter loads",
            "counter leg passed")
        self.assertNotEqual(dropped, driver)
        self.assertIn("check-bpf-load-kernels.sh never gates the absent "
                      "arm on 'refused counter-mode-unavailable-in-build; "
                      "no counter loads'",
                      check_driver_absence_flag(
                          dropped, "--expect-counter-objects",
                          "counter-mode-unavailable-in-build: "
                          "this build omits counter objects",
                          "refused counter-mode-unavailable-in-build; "
                          "no counter loads",
                          "check-bpf-load-kernels.sh"))

    def test_journal_legs_honor_an_absence_expectation(self):
        driver = (ROOT / "scripts/check-bpf-load-journal.sh").read_text()
        self.assertEqual(
            [], check_driver_absence_flag(
                driver, "--expect-journal",
                "journal-pair-unavailable-in-build: this build omits "
                "the production journal object",
                "refused journal-pair-unavailable-in-build; "
                "no journal loads",
                "check-bpf-load-journal.sh"))

    def test_journal_absence_check_catches_a_dropped_gate(self):
        driver = (ROOT / "scripts/check-bpf-load-journal.sh").read_text()
        dropped = driver.replace(
            "refused journal-pair-unavailable-in-build; no journal loads",
            "journal leg passed")
        self.assertNotEqual(dropped, driver)
        self.assertIn("check-bpf-load-journal.sh never gates the absent "
                      "arm on 'refused journal-pair-unavailable-in-build; "
                      "no journal loads'",
                      check_driver_absence_flag(
                          dropped, "--expect-journal",
                          "journal-pair-unavailable-in-build: this build "
                          "omits the production journal object",
                          "refused journal-pair-unavailable-in-build; "
                          "no journal loads",
                          "check-bpf-load-journal.sh"))

    def test_premulti_control_honors_an_absence_expectation(self):
        driver = (ROOT / "scripts/check-multi-host-refusal.py").read_text()
        self.assertEqual(
            [], check_driver_absence_flag(
                driver, "--expect-counter-objects",
                "counter-mode-unavailable-in-build: "
                "this build omits counter objects",
                "missing counter-mode omission refusal",
                "check-multi-host-refusal.py"))

    def test_premulti_absence_check_catches_a_dropped_gate(self):
        driver = (ROOT / "scripts/check-multi-host-refusal.py").read_text()
        dropped = driver.replace("missing counter-mode omission refusal",
                                 "counter case passed")
        self.assertNotEqual(dropped, driver)
        self.assertIn("check-multi-host-refusal.py never gates the "
                      "absent arm on 'missing counter-mode omission "
                      "refusal'",
                      check_driver_absence_flag(
                          dropped, "--expect-counter-objects",
                          "counter-mode-unavailable-in-build: "
                          "this build omits counter objects",
                          "missing counter-mode omission refusal",
                          "check-multi-host-refusal.py"))

    def test_gate1_journal_leg_loads_the_length_pair(self):
        self.assertEqual([], check_journal_key_sizes(self.bpf))

    def test_journal_key_sizes_check_catches_a_dropped_flag(self):
        dropped = self.bpf.replace("--key-sizes 1", "--key-sizes 0")
        self.assertNotEqual(dropped, self.bpf)
        self.assertIn("gate-1 journal leg never passes --key-sizes 1, "
                      "so the budgeted length pair never loads",
                      check_journal_key_sizes(dropped))


if __name__ == "__main__":
    unittest.main()
