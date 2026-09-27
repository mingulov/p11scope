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

Run: python3 -I tests/python/test_ci_dependency_selection.py -v
"""

import json
import re
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


def checks_job_steps():
    """The checks-and-e2e job's steps, each as its list of raw lines."""
    lines = CI_YML.read_text(encoding="utf-8").splitlines()
    start = lines.index("  checks-and-e2e:") + 1
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
            "cargo +1.88 test --locked --offline --workspace --all-targets",
            ci,
        )
        self.assertIn("scripts/check-prepared-dependencies.py", ci)


if __name__ == "__main__":
    unittest.main()
