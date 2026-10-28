# SPDX-License-Identifier: GPL-3.0-or-later
"""CI tests the dependencies it ships (audit F-03, Package A).

The root Cargo.toml patches aya/aya-obj to recipe-selected vendored
trees (third-party/sources.json revision), but the hosted pipeline's
standalone `cargo test --manifest-path third-party/...` steps pointed
at stale `-p1` trees while the build shipped `-p2`: the shipped
ring-reader/map-relocation patches ran untested in CI. These tests pin
the three-way agreement — recipe revision, `[patch.crates-io]`, and
every standalone fetch/test manifest path in ci.yml — plus the
retained root-workspace compilation and recipe-hash verification.
The lint job's focused feature tests also prove actual, nonzero host-admission
selection in P0 and unsafe builds, with every configuration's failure retained.

Run: python3 -I tests/python/test_ci_dependency_selection.py -v
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "third-party" / "sources.json"
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"


def recipe_trees():
    """{package name: recipe-selected vendored tree dir} from sources.json."""
    recipe = json.loads(SOURCES.read_text(encoding="utf-8"))
    trees = {}
    for package in recipe["packages"]:
        trees[package["name"]] = (
            "third-party/src/%(name)s-%(version)s-p%(revision)d" % package
        )
    return trees


def patch_paths():
    """{package name: path} from the root [patch.crates-io] section."""
    text = WORKSPACE_MANIFEST.read_text(encoding="utf-8")
    section = text.split("[patch.crates-io]", 1)[1]
    section = section.split("\n[", 1)[0]
    return dict(
        re.findall(r'^(\S+) = \{ path = "([^"]+)" \}', section, re.M)
    )


def checks_job_steps(job="tests"):
    """One job's steps, each as its list of raw lines."""
    lines = CI_YML.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"  {job}:") + 1
    steps = []
    for line in lines[start:]:
        if line.strip() and not line.startswith("    ") \
                and not line.lstrip().startswith("#"):
            break
        if line.startswith("      - "):
            steps.append([line])
        elif steps:
            steps[-1].append(line)
    return steps


def ci_manifest_steps():
    """(line, tree dir) for every third-party --manifest-path CI step."""
    steps = []
    for line in CI_YML.read_text(encoding="utf-8").splitlines():
        match = re.search(r"--manifest-path (third-party/src/\S+/Cargo\.toml)",
                          line)
        if match:
            steps.append((line, match.group(1).rsplit("/", 1)[0]))
    return steps


class DependencySelectionTests(unittest.TestCase):
    def test_patch_points_at_recipe_selected_trees(self):
        trees = recipe_trees()
        patched = patch_paths()
        self.assertTrue(trees, "recipe names no vendored trees")
        for name, tree in trees.items():
            self.assertEqual(patched.get(name), tree, name)

    def test_standalone_ci_tests_use_recipe_selected_trees(self):
        trees = recipe_trees()
        steps = ci_manifest_steps()
        # Both fetch and standalone-test steps, both packages: four steps.
        self.assertEqual(len(steps), 4, steps)
        by_name = {}
        for line, path in steps:
            # Longest name first: "aya" is a string prefix of "aya-obj".
            name = next(
                candidate
                for candidate in sorted(trees, key=len, reverse=True)
                if path.startswith(f"third-party/src/{candidate}-")
            )
            self.assertEqual(path, trees[name], path)
            by_name.setdefault(name, []).append(line)
        # The aya tree's multi-backport needs fields only the sibling
        # aya-obj tree has, so its standalone steps inject that patch;
        # --locked would pin the crates.io aya-obj its own lockfile
        # names, which cannot build it. aya-obj stands alone, locked.
        injected = ('patch.crates-io.aya-obj.path="%s"'
                    % trees["aya-obj"])
        for line in by_name["aya"]:
            self.assertIn(injected, line)
            self.assertNotIn("--locked", line)
        for line in by_name["aya-obj"]:
            self.assertIn("--locked", line)
            self.assertNotIn("patch.crates-io", line)

    def test_unlocked_standalone_steps_restore_the_recipe_lock(self):
        """Hosted run 35831161630 (main, 2026-09-23) failed its dependency
        check with an aya-0.14.0-p2 tree digest mismatch: the unlocked
        standalone fetch had rewritten the tree's vendored Cargo.lock.
        Every step that resolves that tree unlocked must restore the
        recipe's lock before it ends, and the job must prove afterwards
        that the prepared trees are unchanged."""
        trees = recipe_trees()
        tree = trees["aya"]
        lock = f"{tree}/Cargo.lock"
        saved = '"$RUNNER_TEMP/aya-0.14.0-p2.Cargo.lock"'
        self.assertEqual(tree, "third-party/src/aya-0.14.0-p2")
        steps = checks_job_steps()
        unlocked_at = []
        for index, step in enumerate(steps):
            commands = [line.strip() for line in step]
            resolving = [
                at for at, line in enumerate(commands)
                if f"--manifest-path {tree}/Cargo.toml" in line
                and "--locked" not in line
            ]
            if not resolving:
                continue
            unlocked_at.append(index)
            restore = f"cp -p {saved} {lock}"
            self.assertIn(restore, commands, step)
            self.assertGreater(commands.index(restore), resolving[-1], step)
        self.assertEqual(len(unlocked_at), 2, "fetch and test resolve unlocked")
        first = unlocked_at[0]
        self.assertIn(f"cp -p {lock} {saved}",
                      [line.strip() for line in steps[first]],
                      "the first unlocked step must save the recipe lock")
        check = [
            index for index, step in enumerate(steps)
            if any(line.strip().endswith(
                "run: python3 -I scripts/prepare-dependencies.py --check")
                for line in step)
        ]
        self.assertTrue(check, "no prepared-tree check after the standalone steps")
        self.assertGreater(check[0], unlocked_at[-1])

    def test_root_workspace_compilation_and_recipe_audit_retained(self):
        ci = CI_YML.read_text(encoding="utf-8")
        self.assertIn(
            'cargo +"$(cat .release-rust-version)" test --locked --offline --workspace --all-targets',
            ci,
        )
        self.assertIn("scripts/check-prepared-dependencies.py", ci)


class FeatureRegressionExecutionTests(unittest.TestCase):
    FEATURES = (
        "stub-object-attributes",
        "unsafe-unvalidated-metadata",
        "stub-object-attributes,unsafe-unvalidated-metadata",
    )
    SELECTORS = (
        "run::tests::refused_multi_host_precedes_capture_sinks_and_empty_provider_discovery",
        "run::tests::refused_multi_host_precedes_owned_workload_and_output",
        "run::tests::counter_capture_and_run_require_host_after_build_policy_validation",
        "inventory::tests::refused_multi_host_precedes_inventory_sinks_and_auto_fallback",
        "inventory::tests::typed_multi_host_refusal_never_becomes_native_auto_scan_success",
        "attach::tests::empty_live_session_requires_host_admission_for_every_backend",
        "doctor::tests::object_capture_check_matches_build",
        "doctor::tests::object_capture_check_fails_on_flavor_mismatch",
        "doctor::tests::object_capture_check_fails_on_unsafe_flavor_mismatch",
    )

    def run_gate(self, scenario="healthy", failing_features=None):
        steps = [
            step for step in checks_job_steps("lint")
            if step[0] == "      - name: Run feature host-admission regressions"
        ]
        self.assertEqual(len(steps), 1, "the lint job must execute feature tests")
        step = steps[0]
        self.assertIn("        shell: bash", step)
        body_at = step.index("        run: |") + 1
        body = "\n".join(line[10:] for line in step[body_at:])
        with tempfile.TemporaryDirectory(prefix="ci-feature-", dir="/var/tmp") as raw:
            work = Path(raw)
            fake_bin = work / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(f"#!{sys.executable}\n" + '''\
import json
import os
import sys

args = sys.argv[1:]
features = args[args.index("--features") + 1]
with open(os.environ["FAKE_CARGO_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\\n")
selectors = json.loads(os.environ["FAKE_SELECTORS"])
scenario = os.environ["FAKE_SCENARIO"] if features == os.environ["FAKE_FEATURES"] else "healthy"
if scenario == "zero":
    selectors = []
elif scenario == "ignored":
    selectors = selectors[:-1]
elif scenario == "wrong-name":
    selectors[0] = "unrelated::test"
elif scenario == "missing-name":
    selectors = selectors[:-1]
elif scenario == "duplicate-name":
    selectors.append(selectors[0])
for selector in selectors:
    print(f"test {selector} ... ok")
if scenario == "zero":
    print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s")
elif scenario == "ignored":
    print("test result: ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s")
else:
    print("test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 6000 filtered out; finished in 0.01s")
    if scenario == "nested-zero":
        print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s")
    elif scenario == "nested-failure":
        print("test result: FAILED. 8 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s")
sys.exit(101 if scenario == "cargo-failure" else 0)
''', encoding="utf-8")
            cargo.chmod(0o700)
            log = work / "cargo.jsonl"
            env = os.environ.copy()
            env.update({
                "PATH": f"{fake_bin}:{env['PATH']}",
                "RUNNER_TEMP": str(work),
                "FAKE_CARGO_LOG": str(log),
                "FAKE_SELECTORS": json.dumps(self.SELECTORS),
                "FAKE_SCENARIO": scenario,
                "FAKE_FEATURES": failing_features or self.FEATURES[0],
            })
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", body],
                cwd=ROOT, env=env, text=True, capture_output=True, check=False,
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(len(calls), 3, result.stdout + result.stderr)
        for args, features in zip(calls, self.FEATURES, strict=True):
            self.assertEqual(args, [
                f"+{(ROOT / '.release-rust-version').read_text().strip()}",
                "test", "--locked", "--offline", "-p", "p11scope", "--lib",
                "--no-default-features", "--features", features, "--",
                "--exact", "--test-threads=1", "--color", "never", *self.SELECTORS,
            ])
        return result

    def test_all_three_feature_configurations_run_the_exact_nine_tests(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_any_cargo_failure_survives_tee_and_later_successes(self):
        for features in self.FEATURES:
            with self.subTest(features=features):
                result = self.run_gate("cargo-failure", features)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_zero_or_ignored_selection_fails_without_hiding_other_configurations(self):
        for scenario in ("zero", "ignored"):
            with self.subTest(scenario=scenario):
                result = self.run_gate(scenario)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_count_cannot_replace_the_nine_unique_named_positives(self):
        for scenario in ("wrong-name", "missing-name", "duplicate-name"):
            with self.subTest(scenario=scenario):
                result = self.run_gate(scenario)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_nested_success_cannot_hide_the_outer_zero_or_failed_summary(self):
        for scenario in ("nested-zero", "nested-failure"):
            with self.subTest(scenario=scenario):
                result = self.run_gate(scenario)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
