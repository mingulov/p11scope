#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the hosted privileged lib-test workflow.

privileged-tests.yml copies its toolchain setup from ci.yml, and the
hosted_pipeline_* contract tests read ci.yml only. These tests pin the
same two-way agreement bpf-kernels.yml has (bpf-linker, nightly, release
compiler through the version file, clang, action revisions) and the
coverage design: the curated runner, not a blanket --ignored; a shard
matrix that matches SHARDS; a summary job that proves every listed cell
ran exactly once and passed, enforces the floor file
tests/privileged-campaign.json and judges P11SCOPE_CELL_BRANCH lines; a
campaign input (default/long/all); checked doctor rows; a journal second
flavor and a journal-proof build; and the generic cell-script template.

Run: python3 -I tests/python/test_privileged_tests_workflow.py -v
"""

import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
PRIV_YML = ROOT / ".github" / "workflows" / "privileged-tests.yml"
RELEASE_RUST_VERSION = ROOT / ".release-rust-version"
CAMPAIGN = ROOT / "tests" / "privileged-campaign.json"
CHECKER = ROOT / "scripts" / "check-known-failing.py"
CELL_CHECKER = ROOT / "scripts" / "ci" / "check-cell-results.py"
PRIVILEGED_RUNNER = ROOT / "scripts" / "run-privileged-lib-tests.sh"
MINIMAL_SETCAP = ROOT / "scripts" / "ci" / "minimal-setcap.sh"


def load_checker_module():
    spec = importlib.util.spec_from_file_location("known_failing_checker_workflow_test", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shell_array(source, name):
    match = re.search(rf"(?ms)^{re.escape(name)}=\(\n(.*?)^\)", source)
    if match is None:
        raise AssertionError(f"shell array {name} not found")
    return [line.strip() for line in match.group(1).splitlines()
            if line.strip() and not line.strip().startswith("#")]


def shell_function(source, name):
    match = re.search(rf"(?ms)^{re.escape(name)}\(\) \{{\n(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"shell function {name} not found")
    return match.group(0)


def selector_validation_block(source):
    start_token = '    for arg in ${SELECTORS[@]+"${SELECTORS[@]}"}; do\n        local matched=0 candidate\n'
    start = source.index(start_token)
    end = source.index('\n\n    tmpdir=$outdir/tmp', start)
    return source[start:end]


def run_selector_validation(source, selector):
    block = selector_validation_block(source)
    harness = f"""set -u
DEFAULT_TESTS=(default-a)
ALTERNATIVE_TESTS=()
LONG_TESTS=()
BTRFS_TESTS=()
OVERLAY_TESTS=()
EXPECTED_FAILURE_TESTS=()
SKIP_TESTS=()
KNOWN_FAILING_TYPED_TESTS=(typed-known-a)
WIDE_DETAILED_2112_TESTS=()
PROG=run-privileged-lib-tests.sh
selector_matches() {{ [ "$1" = "$2" ]; }}
SELECTORS=({shlex.quote(selector)})
wide=0
include_long=0
include_btrfs=0
include_overlay=0
include_xfail=0
validate_selectors() {{
{block}
}}
validate_selectors
"""
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)


def run_record_typed_verdict(source, verdict_dir, *arguments):
    function = shell_function(source, "record_typed_verdict")
    verdicts = verdict_dir / "verdicts.tsv"
    if verdicts.exists():
        verdicts.unlink()
    command = " ".join(shlex.quote(str(argument)) for argument in arguments)
    harness = f"""set -u
PROG=run-privileged-lib-tests.sh
TYPED_VERDICTS={shlex.quote(str(verdicts))}
{function}
record_typed_verdict {command}
"""
    result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)
    return result, verdicts.read_bytes() if verdicts.exists() else b""


def static_skip_print_block(source):
    # Two loops iterate selected_skipped; the print loop is the one
    # whose body echoes SKIP lines into the results file.
    echo = '        echo "SKIP ${SKIP_TESTS[$i]} :: ${SKIP_REASONS[$i]}" | tee -a "$results"\n'
    at = source.index(echo)
    start = source.rindex('    for i in ${selected_skipped[@]+"${selected_skipped[@]}"}; do\n', 0, at)
    end = source.index('\n    done', at)
    return source[start:end + len('\n    done')]


def run_static_skip_print(source, temp, results_path):
    block = static_skip_print_block(source)
    function = shell_function(source, "record_typed_verdict")
    verdicts = temp / "verdicts.tsv"
    harness = f"""set -u
PROG=run-privileged-lib-tests.sh
TYPED_VERDICTS={shlex.quote(str(verdicts))}
SKIP_TESTS=(static-cell-a)
SKIP_REASONS=(preflight-missing)
selected_skipped=(0)
results={shlex.quote(str(results_path))}
skipped=0
{function}
print_static_skips() {{
{block}
}}
print_static_skips
"""
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)


def minimal_setcap_call_sites(source):
    """Production call lines for write_dynamic_selection, never its definition."""
    return [line for line in source.splitlines()
            if re.fullmatch(r"[ \t]*write_dynamic_selection([ \t;].*)?", line)]


def write_fake_privileged_libtest(path, runner_source):
    names = []
    for array in ("DEFAULT_TESTS", "ALTERNATIVE_TESTS", "LONG_TESTS", "BTRFS_TESTS",
                  "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS", "KNOWN_FAILING_TYPED_TESTS", "SKIP_TESTS"):
        names.extend(shell_array(runner_source, array))
    names = list(dict.fromkeys(names))
    script = f"""#!/usr/bin/env python3
import json
import os
import sys
NAMES = json.loads({json.dumps(json.dumps(names))})
if sys.argv[1:] == ["--list", "--ignored", "--format", "terse"]:
    print("\\n".join(name + ": test" for name in NAMES))
    raise SystemExit(0)
if len(sys.argv) >= 3 and sys.argv[1] == "--exact":
    if os.environ.get("FAKE_LIBTEST_MODE") == "fail-typed":
        sidecar = os.environ.get("P11SCOPE_TYPED_FAILURE_PATH")
        if not sidecar:
            raise SystemExit(65)
        with open(sidecar, "w", encoding="utf-8") as output:
            json.dump({{"cell": "X", "branch": "exact_branch"}}, output)
            output.write("\\n")
        print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s")
        raise SystemExit(101)
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 123 filtered out; finished in 0.01s")
    raise SystemExit(0)
raise SystemExit(64)
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def privileged_runner_mirror(temp, runner_source):
    root = temp / "mirror-root"
    script = root / "scripts/run-privileged-lib-tests.sh"
    script.parent.mkdir(parents=True)
    script.write_text(runner_source, encoding="utf-8")
    script.chmod(0o755)
    for relative in ("scripts/check-known-failing.py", "scripts/check-ignored-tests.py",
                     "scripts/ci/privileged-lib-results.py",
                     "tests/ignored-tests.json", "tests/known-failing.json"):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
    # The runner preflights its declared inputs before any setup; stage
    # the declaration and every input it names for the run mode.
    inputs_spec = importlib.util.spec_from_file_location(
        "runner_inputs_workflow_test", ROOT / "scripts/runner_inputs.py")
    inputs_module = importlib.util.module_from_spec(inputs_spec)
    inputs_spec.loader.exec_module(inputs_module)
    for relative in (inputs_module.SELF,) + inputs_module.required(
            "scripts/run-privileged-lib-tests.sh", "run"):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
        if inputs_module.executable(relative):
            target.chmod(0o755)
    workflow_target = root / ".github/workflows"
    workflow_target.mkdir(parents=True)
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        (workflow_target / workflow.name).write_text(workflow.read_text(encoding="utf-8"), encoding="utf-8")
    fakebin = temp / "fakebin"
    fakebin.mkdir()
    id_script = fakebin / "id"
    id_script.write_text("#!/bin/sh\nif [ \"$1\" = -u ]; then echo 0; exit 0; fi\nexec /usr/bin/id \"$@\"\n", encoding="utf-8")
    id_script.chmod(0o755)
    return root, script, fakebin


def run_privileged_runner_with_fake_binary(temp, runner_source, selector, mode):
    root, script, fakebin = privileged_runner_mirror(temp, runner_source)
    libtest = temp / "libtest-fake"
    write_fake_privileged_libtest(libtest, runner_source)
    outdir = temp / "runner-out"
    typed_output = temp / "typed-results.json"
    env = dict(os.environ)
    env.update({
        "PATH": str(fakebin) + os.pathsep + env.get("PATH", ""),
        "FAKE_LIBTEST_MODE": mode,
        "P11SCOPE_KNOWN_FAILING_RESULTS": str(typed_output),
        "P11SCOPE_KNOWN_FAILING_HOST": "github",
    })
    result = subprocess.run(
        ["bash", str(script), str(libtest), str(outdir), "--exact-selectors", selector],
        cwd=root, env=env, capture_output=True, text=True, timeout=60)
    verdicts = outdir / "known-failing-verdicts.tsv"
    selection = outdir / "known-failing-selection.txt"
    return {
        "run": result,
        "outdir": outdir,
        "typed_output": typed_output,
        "verdicts": verdicts.read_bytes() if verdicts.exists() else b"",
        "selection": selection.read_text(encoding="utf-8") if selection.exists() else "",
    }


def matrix_substitute(value, matrix):
    def replace(match):
        key = match.group(1)
        if key not in matrix:
            raise AssertionError(f"workflow matrix has no key {key}")
        return str(matrix[key])
    resolved = re.sub(r"\$\{\{\s*matrix\.([A-Za-z0-9_]+)\s*\}\}", replace, value)
    if "${{" in resolved:
        raise AssertionError(f"unresolved workflow expression in {value!r}")
    return resolved


def expanded_option_sequence(invocation, matrix, conditional_nonqualifying):
    expanded = []
    for name, value in invocation.get("option_sequence", []):
        if name == "array-expansion":
            if value != "allow_extra":
                raise AssertionError(f"unmodelled shell array expansion {value}")
            expanded.extend(("--allow-nonqualifying", cell) for cell in conditional_nonqualifying)
        else:
            expanded.append((name, matrix_substitute(value, matrix)))
    return expanded


def run_real_cell_invocation(invocation, matrix, temp, host, conditional_nonqualifying=()):
    rows_path = temp / "results.jsonl"
    typed_output = temp / "known-failing-results.json"
    options = expanded_option_sequence(invocation, matrix, conditional_nonqualifying)
    selected = []
    declarations = {}
    dynamic_file = temp / "dynamic-selection.txt"
    dynamic_cells = []
    if any(name == "--require-file" for name, _value in options):
        dynamic_cells = [] if host == "github" else [
            "doctor-minimal-p2", "profile-pid-p2",
            "missing-cap-cap_bpf-p2", "missing-cap-cap_perfmon-p2",
            "missing-cap-cap_checkpoint_restore-p2", "missing-cap-cap_dac_read_search-p2",
            "missing-cap-cap_sys_ptrace-p2"]
        dynamic_file.write_text("".join(cell + "\n" for cell in dynamic_cells), encoding="utf-8")
    for name, value in options:
        if name in ("--require", "--expected-failure", "--intermittent-failure", "--allow-nonqualifying"):
            if value not in selected:
                selected.append(value)
            if name != "--require":
                declarations[value] = name
        elif name == "--require-file":
            for cell in dynamic_cells:
                if cell not in selected:
                    selected.append(cell)
        elif name == "--known-failing-results":
            value = str(typed_output)
        elif name == "--known-failing-host":
            value = host
    rows = []
    for cell in selected:
        declaration = declarations.get(cell)
        if declaration == "--allow-nonqualifying":
            rows.append({"cell": cell, "pass": False, "qualification": "nonqualifying", "detail": "synthetic smoke"})
        elif declaration in ("--expected-failure", "--intermittent-failure"):
            qualification = "expected-failure" if declaration == "--expected-failure" else "qualified"
            rows.append({"cell": cell, "pass": declaration == "--intermittent-failure",
                         "qualification": qualification, "detail": "synthetic declared outcome"})
        else:
            rows.append({"cell": cell, "pass": True, "qualification": "qualified", "detail": "synthetic pass"})
    rows_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    args = [sys.executable, "-I", str(CELL_CHECKER), str(rows_path)]
    for name, value in options:
        if name == "--known-failing-results":
            value = str(typed_output)
        elif name == "--known-failing-host":
            value = host
        elif name == "--require-file":
            value = str(dynamic_file)
        args.extend((name, value))
    result = subprocess.run(args, capture_output=True, text=True, timeout=45)
    document = json.loads(typed_output.read_text(encoding="utf-8")) if typed_output.exists() else None
    return result, document, selected


def provider_matrix_entries(document, job):
    matrix = document["jobs"][job]["strategy"]["matrix"]
    entries = matrix.get("include")
    if not isinstance(entries, list) or not entries:
        raise AssertionError(f"{job} has no matrix include entries")
    return entries


_SPEC = importlib.util.spec_from_file_location(
    "bpf_kernels_contract", Path(__file__).with_name("test_bpf_kernels_contract.py"))
_BPF = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BPF)


def renamed(problems):
    return [p.replace("bpf-kernels.yml", "privileged-tests.yml") for p in problems]


def job_body(yml, name):
    """The YAML text of one top-level job (jobs are 2-space keys)."""
    bounds = [match.start() for match in
              re.finditer(r"^  \S[^:\n]*:", yml, re.M)]
    start = yml.index(f"  {name}:")
    following = [bound for bound in bounds if bound > start]
    end = min(following) if following else len(yml)
    return yml[start:end]


def check_floor_and_branches(want, full_lines, campaign):
    """Mirror of the summary's floor and branch step, for fake-result tests.

    want is the set of listed selectors, full_lines the PASS/FAIL/SKIP result
    lines, campaign the parsed floor file. Returns (checked, notes) or raises
    SystemExit on the same failures the workflow reports.
    """
    assert campaign.get("schema") == "p11scope/privileged-campaign/v1", "floor schema"
    floor = campaign["default_floor"]
    cells = campaign["default_cells"]
    assert floor == len(cells), "floor count must equal the listed names"
    assert len(cells) == len(set(cells)), "floor names must be unique"
    notes = [f"floor {floor}, listed {len(want)}"]
    if len(want) < floor:
        raise SystemExit(f"listed count {len(want)} dropped below the floor {floor}")
    missing = sorted(set(cells) - set(want))
    if missing:
        raise SystemExit("curated names disappeared without a reviewed floor edit: " + ", ".join(missing[:5]))
    notes.append(f"floor ok: all {len(cells)} curated names listed")
    branches = {}
    for line in full_lines:
        parts = line.split()
        if len(parts) >= 2:
            branches[parts[1]] = line
    checked = 0
    for cell, rule in sorted(campaign.get("branch_expectations", {}).items()):
        expected = rule.get("ci")
        status = rule.get("status", "expected")
        if status == "pending":
            notes.append(f"BRANCH pending {cell}")
            continue
        if cell not in branches:
            if cell not in want:
                notes.append(f"BRANCH skip {cell}: not in this campaign")
                continue
            raise SystemExit(f"missing result for branched cell {cell}")
        found = re.findall(r"branch=([A-Za-z0-9_.-]+)", branches[cell])
        notes.append(f"BRANCH {cell} expected {expected} found {found or 'none'}")
        if expected not in found:
            raise SystemExit(f"cell {cell} did not take the expected {expected} branch on CI")
        checked += 1
    notes.append(f"branch ok: {checked} expected cells judged")
    return checked, notes


def check_second_flavor_presence(cells, listed, pending):
    """Mirror of the privileged-second-flavor presence step, for fake-list tests.

    cells is the campaign's second_flavor cell list, listed the journal
    build's `--list` output, pending the tolerated-absent set. Returns the
    wanted list, or raises SystemExit on the same absent-cell failure the
    workflow reports.
    """
    wanted = []
    for cell in cells:
        present = (f"\n{cell}\n" in f"\n{listed}\n"
                   or f"\n{cell} :: " in listed)
        if present:
            wanted.append(cell)
        elif cell in pending:
            continue
        else:
            raise SystemExit(f"expected journal cell absent from the binary: {cell}")
    assert wanted, "no journal cells present"
    return wanted


def check_counter_flavor_presence(cells, listed, pending):
    """Mirror of the privileged-counter-flavor presence step, for fake-list tests.

    cells is the campaign's counter_flavor cell list, listed the FULL-512
    build's `--list` output, pending the tolerated-absent set. Returns the
    wanted list, or raises SystemExit on the same absent-cell failure the
    workflow reports.
    """
    wanted = []
    for cell in cells:
        present = (f"\n{cell}\n" in f"\n{listed}\n"
                   or f"\n{cell} :: " in listed)
        if present:
            wanted.append(cell)
        elif cell in pending:
            continue
        else:
            raise SystemExit(f"expected counter cell absent from the binary: {cell}")
    assert wanted, "no counter cells present"
    return wanted


def journal_proof_test_names(source):
    """Fully-qualified #[test] names under root_proof_tests, the source of truth.

    source is the text of src/semantics_objects/journal/root_proof_tests.rs,
    the module the workflow's proof step runs by filter.
    """
    names = re.findall(r"^#\[test\]\nfn (\w+)", source, re.M)
    return [f"semantics_objects::journal::root_proof_tests::{name}" for name in names]


class PrivilegedTestsWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.ci = CI_YML.read_text(encoding="utf-8")
        self.yml = PRIV_YML.read_text(encoding="utf-8")

    def test_public_cli_closed_sets_stay_in_step(self):
        # The campaign script's summary(), the release-matrix PUBLIC
        # map and the workflow's two closed sets (uniform checker
        # flags + inline need set) must name the same cells: a cell
        # dropped from any one of them would self-skip on some leg.
        # The host-leg and uniform checker invocations must also
        # require the same set (the exact drift that once left the
        # provider-info cell host-only).
        import ast

        script = (ROOT / "scripts" / "qualify-public-cli.sh").read_text(
            encoding="utf-8"
        )
        match = re.search(r"^summary doctor .+$", script, re.M)
        self.assertIsNotNone(match, "qualify script has no summary line")
        summary = set(match.group(0).split()[1:])
        self.assertTrue(summary, "summary names no cells")
        contract = ast.parse(
            (ROOT / "scripts" / "release-matrix-contract.py").read_text(
                encoding="utf-8"
            )
        )
        public = None
        for node in ast.walk(contract):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "PUBLIC"
            ):
                public = ast.literal_eval(node.value)
        self.assertIsInstance(public, dict, "PUBLIC map is not a literal dict")
        body = job_body(self.yml, "public-cli")
        need = set(
            re.findall(
                r"need = \{(.*?)\}", body, re.S
            )[0].replace('"', "").replace(",", " ").split()
        )
        # The inline need set is exactly the campaign summary: any
        # drift in either direction fails loudly here, not as a
        # silent self-skip on a guest leg.
        self.assertEqual(summary, need, "summary/need drift")
        count = re.search(r"full (\d+)-cell gate", body)
        self.assertIsNotNone(count, "closed-set count comment missing")
        self.assertEqual(
            int(count.group(1)),
            len(need),
            "closed-set count comment drifted: set the `full N-cell gate` comment "
            "in the public-cli job of .github/workflows/privileged-tests.yml "
            "to the need-set size",
        )
        host = re.search(
            r"run-cell-script\.sh public-cli-host .*?>(?:\"\$RUNNER_TEMP/qual\.log\")",
            body,
            re.S,
        )
        self.assertIsNotNone(host, "host leg has no checker invocation")
        host_requires = set(re.findall(r"--require (\S+)", host.group(0)))
        start = body.index('check-cell-results.py "$out/cells/results.jsonl"')
        uniform_lines = []
        for line in body[start:].splitlines()[1:]:
            uniform_lines.append(line)
            if not line.rstrip().endswith("\\"):
                break
        self.assertTrue(uniform_lines, "uniform checker invocation missing")
        uniform_requires = set(
            re.findall(r"--require (\S+)", "\n".join(uniform_lines))
        )
        self.assertTrue(uniform_requires, "uniform checker requires nothing")
        self.assertEqual(
            host_requires, uniform_requires, "host/uniform require drift"
        )
        self.assertTrue(
            uniform_requires <= need, "uniform requires outside the closed set"
        )
        self.assertIn("inventory-provider-info-pid", uniform_requires)
        self.assertIn("inventory-provider-info-pid", need)
        self.assertEqual(
            public.get("inventory-provider-info-pid"), "provider-info-exact"
        )

    def test_toolchain_and_action_pins_match_ci(self):
        release = RELEASE_RUST_VERSION.read_text(encoding="utf-8").strip()
        problems = (_BPF.check_bpf_linker(self.ci, self.yml)
                    + _BPF.check_nightly(self.ci, self.yml)
                    + _BPF.check_release_toolchain(self.yml, release)
                    + _BPF.check_clang(self.ci, self.yml)
                    + _BPF.check_action_pins(self.ci, self.yml))
        self.assertEqual([], renamed(problems))

    def test_shard_matrix_matches_the_shard_count(self):
        shards = re.findall(r"^\s*SHARDS:\s*(\d+)\s*$", self.yml, re.M)
        self.assertEqual(len(shards), 1, "SHARDS must be defined once")
        matrix = re.search(r"shard:\s*\[([0-9,\s]+)\]", self.yml)
        self.assertIsNotNone(matrix, "privileged-shard has no shard matrix")
        values = [int(v) for v in matrix.group(1).split(",") if v.strip()]
        self.assertEqual(values, list(range(int(shards[0]))))

    def test_cells_come_from_the_curated_runner(self):
        self.assertIn("scripts/run-privileged-lib-tests.sh --list", self.yml)
        self.assertIn('scripts/run-privileged-lib-tests.sh "$in/lib-tests"', self.yml)
        self.assertNotRegex(self.yml, r"lib-tests[^\n]*--ignored")
        # The default list must be nonempty and match its declared count.
        self.assertIn('test "$count" -eq "$declared"', self.yml)
        # Long cells run only through the campaign input, never by default.
        self.assertIn("--include-long", self.yml)
        self.assertIn("inputs.campaign", self.yml)

    def test_failures_and_skips_fail_the_shard(self):
        self.assertIn("grep -E '^(FAIL|SKIP) '", self.yml)
        self.assertIn('test "$rc" -eq 0', self.yml)
        self.assertIn("fail-fast: false", self.yml)

    def test_shard_runners_use_exact_selectors(self):
        # Every run-mode invocation passes curated full names as
        # selectors; with substring matching a prefix cell (the
        # fanotify live-drain pair) double-ran its longer sibling
        # and the coverage diff failed. Each invocation must carry
        # --exact-selectors so a prefix selector can never run an
        # unlisted sibling.
        runs = [line for line in self.yml.splitlines()
                if 'run-privileged-lib-tests.sh "$in/lib-tests"' in line
                and '"$out/run"' in line]
        self.assertEqual(len(runs), 5,
                         f"expected 5 runner invocations, got {len(runs)}")
        for line in runs:
            with self.subTest(line=line.strip()[:80]):
                self.assertIn("--exact-selectors", line)

    def test_summary_proves_every_cell_ran_once_and_passed(self):
        summary = self.yml.split("privileged-summary:", 1)
        self.assertEqual(len(summary), 2, "no privileged-summary job")
        body = summary[1]
        self.assertIn("needs: [privileged-build, privileged-shard]", body)
        self.assertIn("if: ${{ !cancelled() }}", body)
        self.assertIn('diff -u "$RUNNER_TEMP/want.txt" "$RUNNER_TEMP/ran.txt"', body)
        self.assertIn("MISSING results for shard", body)
        self.assertIn("awk '$1 != \"PASS\"'", body)

    def test_guest_kernels_have_pinned_sums(self):
        match = re.search(r"kernel:\s*\[host,([^\]]*)\]", self.yml)
        self.assertIsNotNone(match, "public-cli has no host + guest kernel matrix")
        guests = [k.strip() for k in match.group(1).split(",") if k.strip()]
        self.assertTrue(guests)
        sums = ROOT / "tests" / "fixtures" / "vng-kernel-sha256sums"
        for kernel in guests:
            self.assertTrue((sums / f"{kernel}.sums").is_file(), f"missing sums for {kernel}")
        self.assertIn("sha256sum --check", self.yml)

    def test_workflow_cancels_superseded_runs(self):
        self.assertIn("cancel-in-progress: true", self.yml)

    def test_filesystem_jobs_run_their_curated_groups(self):
        for job, flag, package, section in (
            ("privileged-btrfs", "--include-btrfs", "btrfs-progs", "btrfs"),
            ("privileged-overlay", "--include-overlay", "e2fsprogs",
             "overlay"),
        ):
            with self.subTest(job=job):
                body = job_body(self.yml, job)
                self.assertIn("needs: privileged-build", body)
                self.assertIn(flag, body)
                self.assertIn(package, body)
                # Selectors derive from the curated --list section with
                # a count check, never from a hand-kept copy. The
                # declared-count parse must accept the header's
                # `, …` suffix after the number.
                self.assertIn(f"/^{section} \\(/", body)
                self.assertIn(
                    "s/^" + section + r" (\([0-9][0-9]*\)[,)].*/", body)
                self.assertIn('test "$count" -eq "$declared"', body)
                # Failures, skips and leaked mounts fail the job.
                self.assertIn("grep -E '^(FAIL|SKIP) '", body)
                self.assertIn('test "$rc" -eq 0', body)
                self.assertIn("if: ${{ always() }}", body)
                self.assertIn("losetup -a", body)
        overlay = job_body(self.yml, "privileged-overlay")
        # The copy-up cell is a normal overlay-campaign pass now (it
        # rides the curated --list selectors like the K1 twins, never a
        # hand-kept name): no expected-failure gate may remain for it.
        self.assertNotIn("overlay_copy_up_userspace_edge_absent", overlay)
        self.assertNotIn("--include-expected-failures", overlay)
        self.assertNotIn("copyup-cell", overlay)
        self.assertNotIn("^XFAIL ", overlay)
        btrfs = job_body(self.yml, "privileged-btrfs")
        self.assertIn("--teardown", btrfs)

    def test_btrfs_job_runs_the_discover_subvolume_cell(self):
        # The ignored discover twin's CI cover: a second loop mount, a
        # runner-owned subdir, the cell script as the runner user (never
        # under sudo: the fence refuses root), and the shared judge
        # requiring exactly its row. The cleanup step tears down both
        # mounts, and the leak check covers the shared parent.
        btrfs = job_body(self.yml, "privileged-btrfs")
        self.assertIn("scripts/ci/discover-btrfs-subvol.sh", btrfs)
        self.assertNotIn("sudo -n scripts/ci/discover-btrfs-subvol.sh",
                         btrfs)
        self.assertIn("discover-btrfs.img", btrfs)
        self.assertIn("discover-btrfs-mnt", btrfs)
        self.assertIn('install -d -m 700 -o "$(id -u)" -g "$(id -g)"',
                      btrfs)
        self.assertIn("scripts/ci/check-cell-results.py", btrfs)
        self.assertIn("--require discover-btrfs-subvol", btrfs)
        self.assertIn("discover-cell/", btrfs)
        self.assertIn(
            '"$out/discover-btrfs.img" "$out/discover-btrfs-mnt"', btrfs)

    def test_privileged_input_downloads_match_uploads(self):
        # Every privileged-inputs download must name an artifact a
        # build job uploads; a renamed producer with a stale consumer
        # fails the job at the download step with zero cells run.
        steps = re.finditer(
            r"uses: actions/(upload|download)-artifact@\S+[^\n]*\n"
            r"(?P<indent>[ ]+)with:\n"
            r"(?P<body>(?:(?P=indent)[ ]+[^\n]*\n)+)",
            self.yml)
        uploads = set()
        downloads = []
        for step in steps:
            name = re.search(r"^\s+name: (\S.*\S|\S)\s*$",
                             step.group("body"), re.M)
            if name is None:
                continue
            if step.group(1) == "upload":
                uploads.add(name.group(1))
            else:
                downloads.append(name.group(1))
        self.assertTrue(downloads, "no named artifact downloads found")
        for name in downloads:
            if name.startswith("privileged-inputs"):
                self.assertIn(name, uploads,
                              f"download {name} has no producing upload")

    def test_ia32_job_installs_i386_token_tooling(self):
        # The ia32-only leg carries no amd64 SoftHSM, so token setup
        # needs the i386 softhsm2-util alongside the i386 library.
        ia32 = job_body(self.yml, "public-cli-ia32")
        self.assertRegex(ia32, r"(?<!lib)softhsm2:i386")

    def test_ia32_gate_uses_the_shared_cell_checker(self):
        # The two ia32 cells route through judge and pass with the
        # owned-provider-counts taxonomy, so the gate must be the
        # shared closed-set checker (as the host leg is), never a
        # hand-rolled comparison against a single value no script
        # in this pipeline emits.
        ia32 = job_body(self.yml, "public-cli-ia32")
        self.assertIn("scripts/ci/check-cell-results.py", ia32)
        self.assertIn("--require profile-pid-ia32", ia32)
        self.assertIn("--require run-ia32", ia32)
        self.assertNotIn('!= "qualified"', ia32)

    def test_shard_step_exports_the_discover_helper(self):
        # The exit-mappings cell resolves p11scope-discover through
        # P11SCOPE_DISCOVER_BIN: the staged layout keeps it under bin/,
        # not beside lib-tests.
        shard = job_body(self.yml, "privileged-shard")
        self.assertIn('P11SCOPE_DISCOVER_BIN="$in/bin/p11scope-discover"', shard)

    def test_campaign_input_selects_default_long_and_all(self):
        self.assertIn("campaign:", self.yml)
        self.assertIn("[default, long, all]", self.yml)
        self.assertIn("long|all", self.yml)
        self.assertIn("--include-long", self.yml)
        # Schedules run only on the default branch, so the weekly lib
        # campaign is a dispatch on the dev tip. The nightly schedule here
        # (owner 2026-11-14) runs only release-build plus pkcs11-check-full
        # on main; every other job skips on schedule.
        self.assertIn("schedules run only on the default branch", self.yml.lower())
        self.assertIn("schedule:", self.yml)
        self.assertIn("- cron: '17 3 * * *'", self.yml)
        self.assertIn("pkcs11_check_full:", self.yml)
        full = job_body(self.yml, "pkcs11-check-full")
        self.assertIn("github.event_name == 'schedule'", full)
        self.assertIn("inputs.pkcs11_check_full", full)
        providers_full = job_body(self.yml, "pkcs11-check-providers-full")
        self.assertIn("github.event_name == 'schedule'", providers_full)
        self.assertIn("inputs.pkcs11_check_full", providers_full)
        smoke = job_body(self.yml, "pkcs11-check-smoke")
        self.assertIn("github.event_name != 'schedule'", smoke)
        providers = job_body(self.yml, "pkcs11-check-providers")
        self.assertIn("github.event_name != 'schedule'", providers)

    def test_providers_matrix_runs_nss_next_to_the_pinned_providers(self):
        # The per-push matrix runs kryoptic + Haskoki (pinned artifacts)
        # plus NSS softokn (system libnss3, tool probe, no fetch). The
        # nightly FULL matrix keeps only the suite providers: a suite=no
        # row gains no FULL leg.
        providers = job_body(self.yml, "pkcs11-check-providers")
        for entry in ("provider: kryoptic", "provider: haskoki",
                      "provider: nss-softokn",
                      "discover_row: kryoptic-multi-table",
                      "discover_row: haskoki-discover",
                      "discover_row: nss-softokn-discover"):
            self.assertIn(entry, providers)
        self.assertIn("libnss3", providers)
        # The suite flag drives the identical-results allow-list: a
        # suite=no tool probe records that row as nonqualifying, and
        # check-cell-results rejects a nonqualifying row outside the
        # allow list.
        self.assertIn('suite: "yes"', providers)
        self.assertIn('suite: "no"', providers)
        self.assertIn('matrix.suite', providers)
        self.assertIn('--allow-nonqualifying "${{ matrix.provider }}-identical-results"',
                      providers)
        full = job_body(self.yml, "pkcs11-check-providers-full")
        self.assertIn("provider: kryoptic", full)
        self.assertIn("provider: haskoki", full)
        self.assertNotIn("nss-softokn", full)

    def test_tag_pushes_trigger_nothing(self):
        self.assertEqual([], _BPF.check_no_tag_triggers(self.yml))

    def test_floor_file_is_consistent_and_pinned_to_the_runner(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        self.assertEqual(campaign.get("schema"), "p11scope/privileged-campaign/v1")
        floor = campaign["default_floor"]
        cells = campaign["default_cells"]
        self.assertEqual(floor, len(cells))
        self.assertEqual(len(cells), len(set(cells)))
        # The floor names are the runner's DEFAULT_TESTS plus the default
        # build's alternative member, in runner order.
        runner = (ROOT / "scripts" / "run-privileged-lib-tests.sh").read_text(encoding="utf-8")
        def array(name):
            body = re.search(rf"{name}=\(\n(.*?)\n\)", runner, re.S).group(1)
            return [line.strip() for line in body.splitlines()
                    if line.strip() and not line.strip().startswith("#")]
        expected = array("DEFAULT_TESTS") + ["attach::tests::full_root_load_refusal_is_classified"]
        self.assertEqual(cells, expected,
                         "campaign floor drifted from the runner: edit "
                         "tests/privileged-campaign.json default_cells in runner order "
                         "and set default_floor to the cell count")
        self.assertIn("privileged-inputs-default/selectors.txt", self.yml)
        self.assertIn("tests/privileged-campaign.json", self.yml)
        self.assertIn("dropped below the floor", self.yml)
        self.assertIn("without a reviewed floor edit", self.yml)

    def test_summary_judges_branches_against_the_table(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        expectations = campaign.get("branch_expectations", {})
        self.assertIn("inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64",
                      expectations)
        self.assertEqual(expectations["inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64"]["ci"],
                         "lossless")
        self.assertIn("branch=", self.yml)
        self.assertIn("P11SCOPE_CELL_BRANCH", self.yml)
        self.assertIn("did not take the expected", self.yml)
        self.assertIn("pending", self.yml)

    def test_floor_count_drop_fails(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        cells = campaign["default_cells"]
        want = set(cells[:-1])
        full = [f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed" for name in want]
        with self.assertRaisesRegex(SystemExit, "dropped below the floor"):
            check_floor_and_branches(want, full, campaign)

    def test_floor_name_disappearance_fails(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        cells = campaign["default_cells"]
        swapped = "attach::tests::renamed_cell_for_test"
        want = set(cells[1:]) | {swapped}
        full = [f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed" for name in want]
        with self.assertRaisesRegex(SystemExit, "without a reviewed floor edit"):
            check_floor_and_branches(want, full, campaign)

    def test_floor_green_with_fake_results(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        want = set(campaign["default_cells"])
        full = [f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed" for name in sorted(want)]
        checked, notes = check_floor_and_branches(want, full, campaign)
        self.assertEqual(checked, 0)
        self.assertTrue(any("floor ok" in note for note in notes))

    def test_branch_pending_is_allowed_absent(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        want = set(campaign["default_cells"])
        full = [f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed" for name in sorted(want)]
        checked, notes = check_floor_and_branches(want, full, campaign)
        self.assertTrue(any("pending" in note for note in notes))

    def test_branch_expected_passes_with_fake_results(self):
        campaign = {"schema": "p11scope/privileged-campaign/v1", "default_floor": 1,
                    "default_cells": ["cell::a"],
                    "branch_expectations": {"cell::a": {"ci": "lossless", "status": "expected"}}}
        want = {"cell::a"}
        full = ["PASS cell::a rc=0 seconds=1 :: test result: ok. 1 passed branch=lossless"]
        checked, _ = check_floor_and_branches(want, full, campaign)
        self.assertEqual(checked, 1)

    def test_branch_missing_fails(self):
        campaign = {"schema": "p11scope/privileged-campaign/v1", "default_floor": 1,
                    "default_cells": ["cell::a"],
                    "branch_expectations": {"cell::a": {"ci": "lossless", "status": "expected"}}}
        with self.assertRaisesRegex(SystemExit, "did not take the expected lossless branch"):
            check_floor_and_branches({"cell::a"},
                                     ["PASS cell::a rc=0 seconds=1 :: test result: ok. 1 passed"],
                                     campaign)

    def test_branch_wrong_arm_fails(self):
        campaign = {"schema": "p11scope/privileged-campaign/v1", "default_floor": 1,
                    "default_cells": ["cell::a"],
                    "branch_expectations": {"cell::a": {"ci": "lossless", "status": "expected"}}}
        with self.assertRaisesRegex(SystemExit, "did not take the expected lossless branch"):
            check_floor_and_branches({"cell::a"},
                                     ["PASS cell::a rc=0 seconds=1 :: test result: ok. 1 passed branch=skipped"],
                                     campaign)

    def test_branch_missing_result_fails_when_listed(self):
        campaign = {"schema": "p11scope/privileged-campaign/v1", "default_floor": 1,
                    "default_cells": ["cell::a"],
                    "branch_expectations": {"cell::a": {"ci": "lossless", "status": "expected"}}}
        with self.assertRaisesRegex(SystemExit, "missing result for branched cell"):
            check_floor_and_branches({"cell::a"}, [], campaign)

    def test_doctor_rows_are_checked_in_both_jobs(self):
        for name in ("uprobe-multi attach (own libc)", "uretprobe vs seccomp"):
            self.assertIn(name, self.yml)
        self.assertNotIn('doctor >"$TMPDIR/doctor.txt" 2>&1 || true', self.yml)
        self.assertIn("doctor-status.txt", self.yml)
        self.assertIn("functional doctor row", self.yml)
        self.assertIn("cli-out/cells/doctor.out", self.yml)

    def test_default_shards_do_not_depend_on_journal_build(self):
        self.assertNotIn("flavor: [default, journal]", self.yml)
        self.assertIn("privileged-build-journal:", self.yml)
        shard_needs = re.search(r"privileged-shard:\s*\n\s*needs:\s*([^\n]+)", self.yml)
        self.assertIsNotNone(shard_needs, "privileged-shard has no needs")
        self.assertEqual(shard_needs.group(1).strip(), "privileged-build")
        second_needs = re.search(r"privileged-second-flavor:\s*\n\s*needs:\s*([^\n]+)", self.yml)
        self.assertIsNotNone(second_needs, "privileged-second-flavor has no needs")
        self.assertEqual(second_needs.group(1).strip(), "privileged-build-journal")

    def test_proof_build_is_cached(self):
        self.assertIn("target/proof/debug/.fingerprint", self.yml)

    def test_summary_downloads_only_default_and_shards(self):
        summary = self.yml.split("privileged-summary:", 1)[1]
        block = summary.split("privileged-second-flavor:", 1)[0]
        self.assertIn("pattern: privileged-shard-*", block)
        self.assertIn("name: privileged-inputs-default", block)

    def test_filesystem_campaigns_download_default_inputs(self):
        for job, follower in (("privileged-btrfs:", "privileged-overlay:"),
                              ("privileged-overlay:", "release-build:")):
            block = self.yml.split(job, 1)[1].split(follower, 1)[0]
            self.assertIn("name: privileged-inputs-default", block,
                          f"{job} must download the decoupled default inputs")
        self.assertNotIn("name: privileged-inputs\n", self.yml,
                           "stale single-flavor inputs download remains")

    def test_second_flavor_build_and_cells(self):
        self.assertIn("privileged-build-journal:", self.yml)
        self.assertIn("P11SCOPE_JOURNAL", self.yml)
        self.assertIn("privileged-second-flavor", self.yml)
        self.assertIn("privileged-inputs-journal", self.yml)
        self.assertIn("second_flavor", self.yml)
        self.assertIn("journal exact-list mismatch", self.yml)
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        second = campaign["second_flavor"]
        self.assertEqual(len(second["cells"]), 11)
        self.assertIn("inventory::manifest_e2e_tests::privileged_inventory_pid_key_operations_mt_sign_rows_exact",
                      second["cells"])
        self.assertIn("attach::tests::sealed_session_drain_linkage_is_behavioral", second["cells"])
        self.assertIn("inventory::privileged_tests::privileged_key_operations_linked_lane_pumps_live_discovery",
                      second["cells"])
        self.assertIn("inventory::privileged_tests::privileged_key_operations_linked_healthy_routes_without_coverage_failed",
                      second["cells"])
        # The WU-2a tolerance is spent: every second-flavor cell exists,
        # so an absent cell must fail the job, never print PENDING.
        self.assertEqual(second.get("pending", []), [])

    def test_second_flavor_absent_cell_fails(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        second = campaign["second_flavor"]
        cells = second["cells"]
        pending = set(second.get("pending", []))
        listed = "\n".join(cells[1:]) + "\n"
        with self.assertRaisesRegex(SystemExit, "expected journal cell absent"):
            check_second_flavor_presence(cells, listed, pending)

    def test_second_flavor_all_present_passes(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        second = campaign["second_flavor"]
        cells = second["cells"]
        pending = set(second.get("pending", []))
        listed = "\n".join(cells) + "\n"
        self.assertEqual(check_second_flavor_presence(cells, listed, pending), cells)

    def test_counter_flavor_build_and_cells(self):
        # The wide default build omits counter objects, so the 36
        # counter/select-endpoint cells refuse there; the FULL-512
        # counter campaign runs their positive arms from the journal
        # build (which is FULL capacities with counter objects) on
        # every push, like the journal flavor. When 0.7.x restores
        # wide companions, the twins flip back and this campaign stays
        # as the FULL positive.
        self.assertIn("privileged-counter-flavor:", self.yml)
        self.assertIn("privileged-inputs-journal", job_body(self.yml, "privileged-counter-flavor"),
                      "counter flavor reuses the FULL-512 journal build")
        self.assertIn("counter_flavor", self.yml)
        self.assertIn("counter exact-list mismatch", self.yml)
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        counter = campaign["counter_flavor"]
        self.assertEqual(len(counter["cells"]), 36)
        # One member per counter group, so a silently dropped group fails.
        members = (
            "attach::counter_banks::tests::counter_object_preflight_loads_all_modes",
            "attach::counter_banks::tests::counter_bank_mode_objects_load_lp64",
            "metrics::counter_reader::tests::counter_bank_session_old_return_survives_append_lp64",
            "metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_multi_lp64",
            "metrics::counter_reader::tests::counter_bank_session_useful_8192_latency_growth_multi_lp64",
            "metrics::counter_reader::tests::counter_engine_stages_first_512_counts_multi_lp64",
            "metrics::counter_reader::tests::counter_engine_growth_latency_multi_lp64",
            "metrics::counter_reader::tests::counter_start_raises_nofile_from_soft_1024_lp64",
            "metrics::counter_reader::tests::counter_collection_reads_live_and_terminal_lp64",
            "metrics::counter_reader::tests::counter_singles_stop_prints_detach_estimate_lp64",
            "metrics::counter_reader::tests::counter_cli_profile_latency_matches_workload_ledger_lp64",
            "metrics::counter_reader::tests::counter_cli_run_counts_with_owned_child_lp64",
            "metrics::counter_reader::tests::selected_detail_cli_profile_counts_resolves_live_plan_and_conserves_aggregate_lp64",
            "metrics::counter_reader::tests::selected_detail_system_scope_refuses_live_plan_lp64",
            "metrics::k0_live_cells::k0_live_detail_matches_ledger_counts_lp64",
            "metrics::k0_live_cells::k0_live_run_gateless_exit_matches_main_counts_lp64",
        )
        for cell in members:
            with self.subTest(cell=cell):
                self.assertIn(cell, counter["cells"])
        self.assertEqual(counter.get("pending", []), [])

    def test_counter_flavor_absent_cell_fails(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        counter = campaign["counter_flavor"]
        cells = counter["cells"]
        pending = set(counter.get("pending", []))
        listed = "\n".join(cells[1:]) + "\n"
        with self.assertRaisesRegex(SystemExit, "expected counter cell absent"):
            check_counter_flavor_presence(cells, listed, pending)

    def test_counter_flavor_all_present_passes(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        counter = campaign["counter_flavor"]
        cells = counter["cells"]
        pending = set(counter.get("pending", []))
        listed = "\n".join(cells) + "\n"
        self.assertEqual(check_counter_flavor_presence(cells, listed, pending), cells)

    def test_counter_flavor_cells_are_default_campaign_twins(self):
        # Every counter-flavor cell also runs in the default sharded
        # campaign, where the wide binary takes the exact-refusal twin
        # arm; the same test name proves the refusal on wide and the
        # positive on FULL.
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        default = set(campaign["default_cells"])
        for cell in campaign["counter_flavor"]["cells"]:
            with self.subTest(cell=cell):
                self.assertIn(cell, default)

    def test_counter_flavor_verifies_the_full512_curation(self):
        # Like the journal flavor, the counter run verifies the
        # FULL-512 curation explicitly, so a silent gating change
        # fails instead of flipping coverage.
        counter = job_body(self.yml, "privileged-counter-flavor")
        self.assertIn("run-privileged-lib-tests.sh \"$in/lib-tests\" "
                      "\"$out/run\" --full-512", counter,
                      "counter-flavor run must verify the FULL-512 curation")

    def test_journal_proof_build_and_tests(self):
        self.assertIn("P11SCOPE_JOURNAL_PROOF=1", self.yml)
        self.assertIn("root_proof_tests", self.yml)
        self.assertIn("test result: ok. 2 passed", self.yml)
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        self.assertEqual(len(campaign["journal_proof"]["cells"]), 2)
        # The floor names are pinned to the #[test] fns under the module the
        # workflow runs: a rename must update the floor, not rot it.
        source = (ROOT / "src" / "semantics_objects" / "journal"
                  / "root_proof_tests.rs").read_text(encoding="utf-8")
        self.assertEqual(campaign["journal_proof"]["cells"],
                         journal_proof_test_names(source))

    def test_build_jobs_refuse_flavor_environment(self):
        # Every image-building prove step refuses a leaked flavor/size
        # override; the journal job exempts only its intended =1.
        jobs = {}
        for match in re.finditer(
                r"^  (privileged-build-journal|privileged-build|release-build):\s*$",
                self.yml, re.M):
            jobs[match.group(1)] = match.start()
        self.assertEqual(set(jobs),
                         {"privileged-build", "privileged-build-journal", "release-build"})
        starts = sorted(jobs.items(), key=lambda kv: kv[1])
        bodies = {}
        for index, (name, start) in enumerate(starts):
            end = starts[index + 1][1] if index + 1 < len(starts) else len(self.yml)
            bodies[name] = self.yml[start:end]
        refused = {
            "privileged-build": {"P11SCOPE_SMALL_", "P11SCOPE_JOURNAL=",
                                 "P11SCOPE_JOURNAL_PROOF=", "P11SCOPE_BIRTH_MARKER=",
                                 "RUSTFLAGS=", "CARGO_ENCODED_RUSTFLAGS="},
            "release-build": {"P11SCOPE_SMALL_", "P11SCOPE_JOURNAL=",
                              "P11SCOPE_JOURNAL_PROOF=", "P11SCOPE_BIRTH_MARKER=",
                              "RUSTFLAGS=", "CARGO_ENCODED_RUSTFLAGS="},
            "privileged-build-journal": {"P11SCOPE_SMALL_", "P11SCOPE_JOURNAL_PROOF=",
                                         "P11SCOPE_BIRTH_MARKER=",
                                         "RUSTFLAGS=", "CARGO_ENCODED_RUSTFLAGS="},
        }
        for name, body in sorted(bodies.items()):
            prove = re.search(r"grep -E '\^\(.*?\)'", body)
            self.assertIsNotNone(prove, f"{name} has no prove-step refusal")
            for token in sorted(refused[name]):
                self.assertIn(token, prove.group(0), f"{name} refusal misses {token}")
        journal = bodies["privileged-build-journal"]
        self.assertIn('test "${P11SCOPE_JOURNAL:-}" = 1', journal)
        journal_pattern = re.search(r"grep -E '\^\(.*?\)'", journal).group(0)
        rest = journal_pattern.replace("P11SCOPE_JOURNAL_PROOF=", "")
        self.assertNotIn("P11SCOPE_JOURNAL=", rest,
                         "journal prove must exempt its intended P11SCOPE_JOURNAL=1")

    def test_cell_script_template_proof(self):
        self.assertIn("scripts/ci/run-cell-script.sh public-cli-host", self.yml)
        self.assertIn("scripts/ci/check-cell-results.py", self.yml)
        self.assertIn("--allow-nonqualifying trace-pid", self.yml)
        self.assertIn("--expected-failure profile-cgroup", self.yml)
        self.assertNotIn("--expected-failure inventory-cgroup", self.yml)
        self.assertNotIn("--allow-nonqualifying run-short", self.yml)
        self.assertIn("--require doctor", self.yml)
        self.assertIn("--require profile-pid", self.yml)
        self.assertIn("--require trace-pid", self.yml)
        self.assertIn("--require fifo-refused", self.yml)
        self.assertIn("WP-3", self.yml)
        self.assertIn("WP-7", self.yml)

    def test_public_cli_gate_qualifies_inventory_cgroup(self):
        # The decided no-witness shape qualifies on every leg, so the
        # uniform inline gate must not list inventory-cgroup in
        # expected_cells — while still requiring the cell itself.
        # The wide default build carries counter objects, so the 9
        # counter/select-endpoint cells run positive and stay out.
        job = job_body(self.yml, "public-cli")
        gate = re.search(r"expected_cells = \{(.*?)\}", job, re.S)
        self.assertIsNotNone(gate, "public-cli has no expected_cells gate")
        self.assertEqual(set(re.findall(r'"([^"]+)"', gate.group(1))),
                         {"profile-cgroup", "trace-cgroup",
                          "profile-pid-ia32", "run-ia32"})
        need = re.search(r"need = \{(.*?)\}", job, re.S)
        self.assertIsNotNone(need, "public-cli has no need set")
        self.assertIn("inventory-cgroup", need.group(1),
                      "the gate must still require the inventory-cgroup cell")

    def test_public_cli_does_not_swallow_qualify_rc(self):
        job = job_body(self.yml, "public-cli")
        run_step = job.split("- name: Run the public CLI cells", 1)[1].split("- name: ", 1)[0]
        # Host leg tracks qualify + minimal-setcap separately and fails on any
        # nonzero exit (never swallowed after chown/tail); guest legs accept
        # only 0 or documented-smoke 2 from qualify-public-cli-vng.sh, and
        # every leg runs check-cell-results.py over cells/results.jsonl.
        self.assertIn("qual_rc=0", run_step)
        self.assertIn("minimal_rc=0", run_step)
        self.assertIn('test "$rc" -eq 0', run_step)
        self.assertRegex(run_step, r'case "\$rc" in\s+0\|2\)')
        self.assertIn('check-cell-results.py "$out/cells/results.jsonl"', run_step)

    def test_minimal_setcap_leg_runs_on_host_and_guests(self):
        job = job_body(self.yml, "public-cli")
        # Host leg through the template; guests inside the vng wrapper.
        self.assertIn("run-cell-script.sh minimal-setcap", job)
        self.assertIn("qualify-public-cli-vng.sh", job)
        self.assertIn("libcap2-bin", job)
        # One uniform gate over the minimal results for both legs, with
        # every row required: a dropped row must fail, not shrink cover.
        self.assertIn("minimal-cells/results.jsonl", job)
        for cell in ("doctor-minimal-p4", "doctor-minimal-p3",
                     "profile-pid-p4", "profile-pid-p3",
                     "missing-cap-cap_bpf-p4", "missing-cap-cap_bpf-p3",
                     "missing-cap-cap_perfmon-p4",
                     "missing-cap-cap_perfmon-p3",
                     "missing-cap-cap_checkpoint_restore-p4",
                     "missing-cap-cap_checkpoint_restore-p3",
                     "missing-cap-cap_dac_read_search-p4",
                     "missing-cap-cap_dac_read_search-p3",
                     "missing-cap-cap_sys_ptrace-p4",
                     "missing-cap-cap_sys_ptrace-p3",
                     "inventory-system", "run-minimal",
                     "run-child-drops-caps", "postsetup-drops-sysadmin",
                     "postsetup-inventory-drops-sysadmin",
                     "run-sudo", "run-user-nobody",
                     "run-kill-on-timeout", "trace-sudo-out",
                     "inventory-sudo-event-log",
                     "inventory-sudo-fifo-out",
                     "profile-sudo-fifo-out",
                     "inventory-diff-sudo-fifo-out",
                     "inventory-sudo-stderr-fifo",
                     "daemonset-doctor", "daemonset-profile",
                     "daemonset-inventory"):
            with self.subTest(cell=cell):
                self.assertIn(f"--require {cell}", job)
        self.assertEqual(2, job.count('--require-file "$out/minimal-cells/dynamic-selection.txt"'),
                         "both the host wrapper and uniform guest gate must consume the dynamic inventory")
        # Artifacts carry the minimal evidence.
        self.assertIn("minimal-cells/known-failing-results.json", job)
        self.assertIn("minimal-cells/dynamic-selection.txt", job)
        self.assertIn("minimal-cells/logs/*.out", job)
        self.assertIn("minimal.log", job)

    def test_minimal_setcap_dynamic_selection_covers_the_current_paranoid_bonus_rows(self):
        source = MINIMAL_SETCAP.read_text(encoding="utf-8")
        calls = minimal_setcap_call_sites(source)
        self.assertTrue(calls, "production call site for write_dynamic_selection is missing")
        function = shell_function(source, "write_dynamic_selection")
        harness_template = """set -u
OUT=$1
SAVED_PARANOID=$2
paranoid_values() { printf "%s\n%s\n%s\n" "$SAVED_PARANOID" 3 4 | awk '!seen[$0]++'; }
@FUNCTION@
write_dynamic_selection
"""
        for paranoid, expected_count in (("2", 7), ("3", 0), ("4", 0)):
            with self.subTest(paranoid=paranoid):
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "dynamic-selection.txt"
                    script = harness_template.replace("@FUNCTION@", function)
                    run = subprocess.run(["bash", "-c", script, "harness", temporary, paranoid],
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    lines = output.read_text(encoding="utf-8").splitlines()
                    self.assertEqual(expected_count, len(lines), lines)
                    if paranoid == "2":
                        self.assertIn("doctor-minimal-p2", lines)
                        self.assertIn("profile-pid-p2", lines)
                        for cap in ("cap_bpf", "cap_perfmon", "cap_checkpoint_restore",
                                    "cap_dac_read_search", "cap_sys_ptrace"):
                            self.assertIn(f"missing-cap-{cap}-p2", lines)
    def test_witness_cli_matrix_runs_host_and_the_five_pinned_guests(self):
        job = job_body(self.yml, "witness-cli")
        match = re.search(r"kernel:\s*\[(.*?)\]", job)
        self.assertIsNotNone(match, "witness-cli has no kernel matrix")
        kernels = [kernel.strip() for kernel in match.group(1).split(",")]
        self.assertEqual(kernels,
                         ["host", "v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
                          "v7.4-rc3"])
        sums = ROOT / "tests" / "fixtures" / "vng-kernel-sha256sums"
        for kernel in kernels[1:]:
            self.assertTrue((sums / f"{kernel}.sums").is_file(),
                            f"missing sums for {kernel}")
        self.assertIn("sha256sum --check", job)
        self.assertIn("kernel deb set changed", job)

    def test_witness_cli_builds_and_runs_the_p28_cells(self):
        job = job_body(self.yml, "witness-cli")
        self.assertIn("--no-run --test prearm_witness_cli", job)
        self.assertIn("cargo", job)
        self.assertIn('sudo -n scripts/ci/run-witness-cli.sh "$WITNESS_TESTBIN" "$out/cells"',
                      job)
        # One kernel-parameterized guest call with no per-kernel cell
        # list: the twin runs everywhere including v6.6.157.
        invocations = [line for line in job.splitlines()
                       if "witness-cli-vng.sh" in line
                       and not line.strip().startswith("#")]
        self.assertEqual(
            invocations,
            ['            scripts/ci/witness-cli-vng.sh "$WITNESS_TESTBIN" "$out" "${{ matrix.kernel }}"'])
        self.assertIn("scripts/ci/check-cell-results.py", job)
        for cell in ("privileged_profile_pid_prearm_clean_exact_counts",
                     "privileged_profile_cgroup_prearm_clean_exact_counts",
                     "privileged_profile_system_prearm_clean_exact_counts",
                     "privileged_profile_metrics_system_prearm_clean_exact_counts",
                     "privileged_profile_pid_prearm_twin_exact_window",
                     "privileged_trace_system_prearm_clean_exact_counts",
                     "privileged_profile_system_learned_provider_second_round_catches_oneshots",
                     "privileged_trace_system_prearm_shared_provider_honest_accounting",
                     "privileged_profile_system_learned_provider_private_mount_is_learned_and_counted"):
            with self.subTest(cell=cell):
                self.assertIn(f"--require {cell}", job)
        self.assertNotIn("--expected-failure", job)
        self.assertNotIn("--allow-nonqualifying", job)
        self.assertIn("witness-cli-${{ matrix.kernel }}", job)

    def test_container_image_cell_builds_and_judges(self):
        job = job_body(self.yml, "container-image")
        # A self-contained FULL musl build: the image holds this commit's
        # static observer, and the build-time guards prove FULL defaults
        # (no size overrides, default features).
        self.assertIn("x86_64-unknown-linux-musl", job)
        self.assertIn("--bin p11scope", job)
        self.assertIn("musl-tools", job)
        self.assertIn("P11SCOPE_SMALL_", job)
        # The permanent cell runs the committed lane script against those
        # musl bytes and judges every row with the shared checker: exact
        # counts on the host and in the second container, then both
        # refusals. No smoke, no expected failures.
        self.assertIn("scripts/matrix/verify-container-image.sh", job)
        self.assertIn("--observer-bin", job)
        self.assertIn("scripts/ci/check-cell-results.py", job)
        # The checker is not executable (100644, like the other CI helpers);
        # the judge step must run it through the interpreter, as the other
        # lanes do, or the step dies with Permission denied on a green cell.
        self.assertIn("python3 -I scripts/ci/check-cell-results.py", job)
        for cell in ("host-exact", "container-exact",
                     "refusal-pidns", "refusal-cap"):
            with self.subTest(cell=cell):
                self.assertIn(f"--require {cell}", job)
        self.assertNotIn("--expected-failure", job)
        self.assertNotIn("--allow-nonqualifying", job)
        self.assertIn("name: container-image", job)

    def test_journal_proof_builds_at_full_capacities(self):
        # The private proof refuses SMALL/WIDE/unsafe/P0 (build.rs): its
        # pins were validated at FULL, so the proof step builds FULL
        # (--no-default-features) in its own target dir while the
        # product stays wide. The proof configuration itself never
        # changes: the same filter must select the same 2 tests.
        step = re.search(
            r"Build P11SCOPE_JOURNAL_PROOF=1 and run root_proof_tests"
            r"[\s\S]*?test result: ok\. 2 passed",
            self.yml)
        self.assertIsNotNone(step, "proof step with the 2-test gate")
        self.assertIn("--no-default-features", step.group(0),
                      "proof step must build FULL capacities, not the wide default")
        self.assertIn("--target-dir target/proof", step.group(0),
                      "proof build must keep its separate target dir")

    def test_journal_flavor_verifies_the_full512_curation(self):
        # The journal flavor builds FULL (--no-default-features), where
        # the 21 wide-only cells do not exist; its --list and the
        # second-flavor run verify the FULL-512 curation explicitly, so
        # a silent gating change fails instead of flipping coverage.
        journal = job_body(self.yml, "privileged-build-journal")
        self.assertIn("--no-default-features", journal)
        self.assertIn("--list --full-512", journal,
                      "journal --list must verify the FULL-512 curation")
        second = job_body(self.yml, "privileged-second-flavor")
        self.assertIn("run-privileged-lib-tests.sh \"$in/lib-tests\" "
                      "\"$out/run\" --full-512", second,
                      "second-flavor run must verify the FULL-512 curation")

    def test_counter_cells_are_required_positives_on_the_wide_build(self):
        # The wide default build carries counter objects, so the 9
        # counter/select-endpoint cells run positive: neither the host
        # template leg nor the shared workflow judge may declare them
        # as expected failures.
        cells = ("counter-latency-mt",
                 "counter-counts-pid", "counter-timestamps-pid",
                 "counter-latency-pid", "counter-counts-system",
                 "counter-timestamps-system", "counter-latency-system",
                 "select-endpoint-pid", "select-endpoint-system")
        job = job_body(self.yml, "public-cli")
        host_leg = job.split("qualify-public-cli-vng.sh")[0]
        for cell in cells:
            with self.subTest(cell=cell):
                self.assertNotIn(f"--expected-failure {cell}", host_leg,
                                 f"host template leg must not excuse {cell}")
        expected = re.search(r"expected_cells = \{(.*?)\}", job, re.S)
        self.assertIsNotNone(expected, "workflow judge expected_cells set")
        for cell in cells:
            with self.subTest(cell=cell):
                self.assertNotIn(f'"{cell}"', expected.group(1),
                                 f"workflow judge must not excuse {cell}")
        self.assertIn("--require counter-latency-mt", host_leg,
                      "host template leg must require the mt counter cell")

    def test_pkcs11_check_campaign_pins_match_the_cell_script(self):
        # The external suite pins live in privileged-campaign.json (not lib
        # tests) and the cell script plus both workflow jobs must match
        # them: exact version, exact smoke marker, four cells and floor.
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        check = campaign["pkcs11_check"]
        self.assertEqual(check["version"], "0.3.1")
        self.assertEqual(check["smoke_marker"], "smoke")
        self.assertEqual(check["cells"], [
            "pkcs11-check-identical-results",
            "pkcs11-check-observer-clean",
            "pkcs11-check-manifest-exact",
            "pkcs11-check-default-coverage",
        ])
        self.assertEqual(check["default_coverage_floor"], 1.0)
        self.assertNotIn("default_coverage_expected_failure", check)
        script = (ROOT / "scripts" / "ci" / "pkcs11-check-cell.sh").read_text(encoding="utf-8")
        self.assertIn("pkcs11-check==0.3.1", self.yml)
        self.assertIn("--marker smoke", script)
        # DEFAULT crash isolation: the suite invocations never pass
        # --isolation (comments and state-file names may mention it).
        invocations = [line for line in script.splitlines()
                       if 'echo "test --module' in line]
        self.assertEqual(len(invocations), 2)
        for line in invocations:
            self.assertNotIn("--isolation", line)
        self.assertIn("FLOOR=1.0", script)
        helper = (ROOT / "scripts" / "ci" / "pkcs11_check_cell_compare.py").read_text(encoding="utf-8")
        self.assertIn('PINNED_VERSION = "0.3.1"', helper)

    def test_pkcs11_check_jobs_use_the_template_with_exact_cells(self):
        for job_name, mode, timeout in (("pkcs11-check-smoke", "smoke", "30"),
                                        ("pkcs11-check-full", "full", "180")):
            with self.subTest(job=job_name):
                job = job_body(self.yml, job_name)
                self.assertIn("needs: release-build", job)
                self.assertIn("runs-on: ubuntu-26.04", job)
                self.assertIn(f"timeout-minutes: {timeout}", job)
                self.assertIn("pkcs11-check==0.3.1", job)
                self.assertIn(f"P11CHECK_MODE={mode}", job)
                self.assertIn("scripts/ci/run-cell-script.sh pkcs11-check-cell", job)
                for cell in ("pkcs11-check-identical-results",
                             "pkcs11-check-observer-clean",
                             "pkcs11-check-manifest-exact",
                             "pkcs11-check-default-coverage"):
                    self.assertIn(f"--require {cell}", job)
                self.assertNotIn("--expected-failure pkcs11-check-default-coverage", job)
                self.assertIn("P11TEST_PIN=1234", job)
                self.assertIn("rm -rf", job)
                self.assertIn("tokens", job)

    def test_pkcs11_check_install_uses_hashed_requirements(self):
        # Both jobs install through --require-hashes from the campaign-pinned
        # requirements file (never a bare version-only pip install), and every
        # requirement there is ==-pinned with sha256 hashes, including
        # pkcs11-check at the campaign version.
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        requirements = campaign["pkcs11_check"]["requirements"]
        self.assertEqual(requirements,
                         "scripts/ci/pkcs11-check-requirements.txt")
        text = (ROOT / requirements).read_text(encoding="utf-8")
        stanzas = []
        current = ""
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith("\\"):
                current += stripped[:-1] + " "
                continue
            current += stripped
            stanzas.append(current)
            current = ""
        self.assertEqual(current, "", "dangling backslash in the requirements")
        self.assertTrue(stanzas, "no requirements found")
        seen = {}
        for stanza in stanzas:
            match = re.match(r"([A-Za-z0-9_.-]+)==([^ \t]+)", stanza)
            self.assertIsNotNone(match, f"unpinned requirement: {stanza[:80]}")
            hashes = re.findall(r"--hash=sha256:[0-9a-f]{64}", stanza)
            self.assertTrue(hashes, f"unhashed requirement: {stanza[:80]}")
            seen[match.group(1).lower().replace("_", "-")] = match.group(2)
        self.assertEqual(seen.get("pkcs11-check"),
                         campaign["pkcs11_check"]["version"])
        for job_name in ("pkcs11-check-smoke", "pkcs11-check-full"):
            with self.subTest(job=job_name):
                job = job_body(self.yml, job_name)
                self.assertIn("--require-hashes", job)
                self.assertIn(f"-r {requirements}", job)
                installs = [line for line in job.splitlines()
                            if "pip" in line and "install" in line]
                self.assertTrue(installs, f"{job_name} has no pip install")
                for line in installs:
                    self.assertIn("--require-hashes", line,
                                  "bare unhashed pip install remains")

    def test_schedule_runs_only_release_build_and_full(self):
        # Every job except release-build and the two FULL jobs skips on
        # schedule, so the nightly runs only the FULL suites on main.
        names = [match.group(1) for match in
                 re.finditer(r"^  ([a-z][a-z0-9-]*):\s*$", self.yml, re.M)]
        jobs = [name for name in names
                if name not in ("push", "pull_request", "schedule", "workflow_dispatch")]
        # Top-level keys that are not jobs (permissions, env, etc.) never
        # match the job pattern above because they carry values.
        self.assertIn("release-build", jobs)
        self.assertIn("pkcs11-check-smoke", jobs)
        self.assertIn("pkcs11-check-full", jobs)
        self.assertIn("pkcs11-check-providers", jobs)
        self.assertIn("pkcs11-check-providers-full", jobs)
        for name in jobs:
            body = job_body(self.yml, name)
            with self.subTest(job=name):
                if name in ("release-build", "pkcs11-check-full",
                            "pkcs11-check-providers-full"):
                    continue
                self.assertIn("github.event_name != 'schedule'", body,
                              f"{name} must skip on schedule")
        release = job_body(self.yml, "release-build")
        self.assertNotIn("github.event_name", release,
                         "release-build must run on schedule for FULL")


class RealTypedWorkflowInvocationTests(unittest.TestCase):
    def setUp(self):
        self.document = yaml.safe_load(PRIV_YML.read_text(encoding="utf-8"))
        checker = load_checker_module()
        self.invocations, problems = checker.workflow_invocations(ROOT)
        self.assertEqual([], problems)

    def typed_invocations(self, job):
        return [invocation for invocation in self.invocations
                if invocation["job"] == job and invocation["known_results"]]

    def test_every_public_cli_typed_invocation_runs_through_the_real_checker(self):
        invocations = self.typed_invocations("public-cli")
        self.assertGreaterEqual(len(invocations), 4)
        self.assertEqual(
            {"cell:scripts/qualify-public-cli.sh", "cell:scripts/ci/minimal-setcap.sh"},
            {invocation["runner"] for invocation in invocations})
        for invocation in invocations:
            for host in ("github", "vng"):
                with self.subTest(runner=invocation["runner"], kind=invocation["kind"], host=host):
                    with tempfile.TemporaryDirectory() as temporary:
                        result, document, selected = run_real_cell_invocation(
                            invocation, {}, Path(temporary), host)
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                    self.assertIsNotNone(document)
                    self.assertTrue(document["complete"])
                    self.assertEqual(host, document["host"])
                    self.assertEqual(selected, [item["test"] for item in document["selection"]])
                    self.assertEqual(len(selected), len(document["results"]))

    def test_every_provider_matrix_typed_invocation_runs_through_the_real_checker(self):
        for job in ("pkcs11-check-providers", "pkcs11-check-providers-full"):
            invocations = self.typed_invocations(job)
            self.assertEqual(1, len(invocations), job)
            invocation = invocations[0]
            for matrix in provider_matrix_entries(self.document, job):
                conditional = []
                if job == "pkcs11-check-providers":
                    scripts = [step.get("run", "") for step in self.document["jobs"][job]["steps"]
                               if isinstance(step, dict)]
                    run_script = next(script for script in scripts if "allow_extra" in script)
                    self.assertIn('if [ "${{ matrix.suite }}" = "no" ]; then', run_script)
                    self.assertIn('allow_extra=(--allow-nonqualifying "${{ matrix.provider }}-identical-results")',
                                  run_script)
                    if matrix["suite"] == "no":
                        conditional = [matrix["provider"] + "-identical-results"]
                with self.subTest(job=job, provider=matrix["provider"]):
                    with tempfile.TemporaryDirectory() as temporary:
                        result, document, selected = run_real_cell_invocation(
                            invocation, matrix, Path(temporary), "github", conditional)
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                    self.assertIsNotNone(document)
                    self.assertTrue(document["complete"])
                    self.assertEqual(selected, [item["test"] for item in document["selection"]])
                    states = {item["test"]: item["state"] for item in document["results"]}
                    identical = matrix["provider"] + "-identical-results"
                    if conditional:
                        self.assertEqual("not_applicable", states[identical])
                    else:
                        self.assertEqual("passed", states[identical])
                    coverage = matrix["provider"] + "-default-run-coverage"
                    self.assertEqual("not_applicable", states[coverage])


class PrivilegedLibTypedRunnerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.source = PRIVILEGED_RUNNER.read_text(encoding="utf-8")
        self.yml = PRIV_YML.read_text(encoding="utf-8")

    def test_record_typed_verdict_emits_one_row_with_the_optional_sidecar_field(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            sidecar = temp / "typed-failure.json"
            result, payload = run_record_typed_verdict(
                self.source, temp, "inventory::privileged_tests::example", "FAIL", sidecar)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                ("inventory::privileged_tests::example\tFAIL\t" + str(sidecar) + "\n").encode(),
                payload)
            result, payload = run_record_typed_verdict(
                self.source, temp, "inventory::privileged_tests::example", "PASS")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(b"inventory::privileged_tests::example\tPASS\n", payload)
            for arguments in (("only-name",),
                              ("name", "FAIL", "sidecar", "fourth")):
                with self.subTest(arguments=arguments):
                    result, _payload = run_record_typed_verdict(self.source, temp, *arguments)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("at most one sidecar", result.stderr)

    def test_static_skip_print_failure_fails_loudly(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            results = temp / "results.txt"
            ok = run_static_skip_print(self.source, temp, results)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertIn("SKIP static-cell-a", results.read_text(encoding="utf-8"))
            self.assertEqual(b"static-cell-a\tSKIP\n", (temp / "verdicts.tsv").read_bytes())
            blocked = temp / "blocked"
            blocked.mkdir()
            failed = run_static_skip_print(self.source, temp, blocked)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("static skip print failed", failed.stderr)

    def test_typed_known_tests_are_curated_selector_vocabulary(self):
        accepted = run_selector_validation(self.source, "typed-known-a")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        unknown = run_selector_validation(self.source, "unknown-selector")
        self.assertNotEqual(unknown.returncode, 0)
        self.assertIn("selector matches no curated test", unknown.stderr)

    def test_real_runner_pipeline_preserves_the_sidecar_to_the_tsv_converter(self):
        selector = "attach::identity_iter::tests::anchor_maps_validate_real_handles"
        with tempfile.TemporaryDirectory() as temporary:
            outcome = run_privileged_runner_with_fake_binary(
                Path(temporary), self.source, selector, "fail-typed")
            expected_tsv = selector.encode() + b"\tFAIL\t" + str(
                outcome["outdir"] / "evidence/0-anchor_maps_validate_real_handles/typed-failure.json").encode() + b"\n"
            self.assertEqual(expected_tsv, outcome["verdicts"])
            self.assertTrue(outcome["typed_output"].is_file(),
                            outcome["run"].stdout + outcome["run"].stderr)
            document = json.loads(outcome["typed_output"].read_text(encoding="utf-8"))
            self.assertEqual(document["results"][0]["signature"], {"cell": "X", "branch": "exact_branch"})
            self.assertNotIn("selector matches no curated test", outcome["run"].stderr)
    def test_real_runner_pipeline_positive_passes_the_checker(self):
        selector = "attach::identity_iter::tests::anchor_maps_validate_real_handles"
        with tempfile.TemporaryDirectory() as temporary:
            outcome = run_privileged_runner_with_fake_binary(
                Path(temporary), self.source, selector, "pass")
            self.assertEqual(outcome["run"].returncode, 0,
                             outcome["run"].stdout + outcome["run"].stderr)
            document = json.loads(outcome["typed_output"].read_text(encoding="utf-8"))
            self.assertEqual(document["results"][0]["state"], "passed")
            self.assertIsNone(document["results"][0]["signature"])
    def test_a_typed_row_selector_reaches_execution_instead_of_selector_refusal(self):
        typed_name = "attach::inventory::activation::privileged_tests::detailed_sweep_test!"
        for array in ("DEFAULT_TESTS", "ALTERNATIVE_TESTS", "LONG_TESTS", "BTRFS_TESTS",
                      "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS", "SKIP_TESTS"):
            self.assertNotIn(typed_name, shell_array(self.source, array))
        injected = self.source.replace(
            "KNOWN_FAILING_TYPED_TESTS=(\n)",
            "KNOWN_FAILING_TYPED_TESTS=(\n" + typed_name + "\n)", 1)
        self.assertNotEqual(injected, self.source)
        with tempfile.TemporaryDirectory() as temporary:
            outcome = run_privileged_runner_with_fake_binary(
                Path(temporary), injected, typed_name, "fail-typed")
            self.assertNotIn("selector matches no curated test", outcome["run"].stderr)
            self.assertEqual(typed_name + "\n", outcome["selection"])
            rows = outcome["verdicts"].splitlines()
            self.assertEqual(1, len(rows))
            self.assertEqual(3, len(rows[0].split(b"\t")))
            self.assertEqual((typed_name + "\tXFAIL").encode(), rows[0].split(b"\t")[0] + b"\t" + rows[0].split(b"\t")[1])
    def test_typed_privileged_records_are_uploaded_for_ci_evidence(self):
        shard = job_body(self.yml, "privileged-shard")
        upload = shard.split("name: Upload the shard results and logs", 1)[1]
        for artifact in ("known-failing-results.json", "known-failing-selection.txt", "known-failing-verdicts.tsv"):
            self.assertIn(artifact, upload)


class PrivilegedShellMutationSweepTests(unittest.TestCase):
    def test_shell_boundary_mutation_sweep(self):
        source = PRIVILEGED_RUNNER.read_text(encoding="utf-8")
        failures = []
        killed = 0

        sidecar_mutant = source.replace('if [ "$#" -eq 3 ]; then', 'if false; then', 1)
        outcomes = {}
        for label, candidate in (("original", source), ("mutant", sidecar_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                result, payload = run_record_typed_verdict(
                    candidate, Path(temporary), "inventory::privileged_tests::example", "FAIL", "/sidecar.json")
            outcomes[label] = (result.returncode == 0 and payload ==
                               b"inventory::privileged_tests::example\tFAIL\t/sidecar.json\n")
        if outcomes["original"] and not outcomes["mutant"]:
            killed += 1
        else:
            failures.append(f"shell-sidecar-forwarding{outcomes}")

        selector_mutant = source.replace(
            ' "${EXPECTED_FAILURE_TESTS[@]}" "${SKIP_TESTS[@]}" "${KNOWN_FAILING_TYPED_TESTS[@]}";',
            ' "${EXPECTED_FAILURE_TESTS[@]}" "${SKIP_TESTS[@]}";', 1)
        outcomes = {}
        for label, candidate in (("original", source), ("mutant", selector_mutant)):
            if candidate == source:
                outcomes[label] = False
                continue
            accepted = run_selector_validation(candidate, "typed-known-a")
            outcomes[label] = accepted.returncode == 0
        original_accepted = run_selector_validation(source, "typed-known-a")
        outcomes["original"] = original_accepted.returncode == 0
        if outcomes["original"] and not outcomes["mutant"]:
            killed += 1
        else:
            failures.append(f"shell-typed-selector-validation{outcomes}")

        # The dynamic paranoid inventory must include every parametrized
        # row family; dropping one recreates an outside-selection failure.
        minimal_source = MINIMAL_SETCAP.read_text(encoding="utf-8")
        dynamic_mutant = minimal_source.replace(
            "missing-cap-cap_sys_ptrace-p$paranoid",
            "missing-cap-cap_sys_admin-p$paranoid", 1)
        outcomes = {}
        for label, candidate in (("original", minimal_source), ("mutant", dynamic_mutant)):
            function = shell_function(candidate, "write_dynamic_selection")
            harness = """set -u
OUT=$1
SAVED_PARANOID=2
paranoid_values() { printf "%s\n%s\n%s\n" "$SAVED_PARANOID" 3 4 | awk '!seen[$0]++'; }
@FUNCTION@
write_dynamic_selection
""".replace("@FUNCTION@", function)
            with tempfile.TemporaryDirectory() as temporary:
                run = subprocess.run(["bash", "-c", harness, "harness", temporary], capture_output=True, text=True)
                lines = []
                output = Path(temporary) / "dynamic-selection.txt"
                if output.exists():
                    lines = output.read_text(encoding="utf-8").splitlines()
                outcomes[label] = (run.returncode == 0 and len(lines) == 7 and
                                   "missing-cap-cap_sys_ptrace-p2" in lines)
        if outcomes["original"] and not outcomes["mutant"]:
            killed += 1
        else:
            failures.append(f"shell-dynamic-selection-inventory{outcomes}")

        # The static-skip print guard must see the pipeline status, not
        # the verdict call's: reverting the order silences the failure.
        order_mutant = source.replace(
            '        print_rc=("${PIPESTATUS[@]}")\n'
            '        if [ "${print_rc[0]}" -ne 0 ] || [ "${print_rc[1]}" -ne 0 ]; then\n'
            '            echo "$PROG: static skip print failed for index $i" >&2\n'
            '            return 1\n'
            '        fi\n'
            '        record_typed_verdict "${SKIP_TESTS[$i]}" SKIP',
            '        record_typed_verdict "${SKIP_TESTS[$i]}" SKIP\n'
            '        if [ "${PIPESTATUS[0]}" -ne 0 ]; then\n'
            '            echo "$PROG: static skip print failed for index $i" >&2\n'
            '            return 1\n'
            '        fi', 1)
        outcomes = {}
        for label, candidate in (("original", source), ("mutant", order_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                blocked = Path(temporary) / "blocked"
                blocked.mkdir()
                run = run_static_skip_print(candidate, Path(temporary), blocked)
                outcomes[label] = run.returncode != 0
        if outcomes["original"] and not outcomes["mutant"]:
            killed += 1
        else:
            failures.append(f"shell-skip-print-order{outcomes}")

        # The verdict arity guard rejects anything but 2-3 arguments;
        # dropping it lets a 4-argument call record a row.
        arity_mutant = source.replace('if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then', 'if false; then', 1)
        outcomes = {}
        for label, candidate in (("original", source), ("mutant", arity_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                result, _payload = run_record_typed_verdict(
                    candidate, Path(temporary), "name", "FAIL", "sidecar", "fourth")
                outcomes[label] = result.returncode != 0
        if outcomes["original"] and not outcomes["mutant"]:
            killed += 1
        else:
            failures.append(f"shell-verdict-arity{outcomes}")

        # The dynamic-selection production call site, not the function
        # definition, is the load-bearing line: removing the call while
        # keeping the definition must fail the call-site predicate.
        call_mutant = minimal_source.replace("\nwrite_dynamic_selection\n", "\n", 1)
        if (bool(minimal_setcap_call_sites(minimal_source))
                and not minimal_setcap_call_sites(call_mutant)):
            killed += 1
        else:
            failures.append("shell-dynamic-selection-call-site"
                            f"(original={bool(minimal_setcap_call_sites(minimal_source))},"
                            f"mutant={bool(minimal_setcap_call_sites(call_mutant))})")

        total = 6
        self.assertEqual([], failures, f"surviving shell mutants: {failures}; killed {killed}/{total}")
        print(f"privileged shell mutation sweep: {killed}/{total} killed")


if __name__ == "__main__":
    unittest.main()
