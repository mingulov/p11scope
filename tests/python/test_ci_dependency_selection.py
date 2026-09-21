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

    def test_root_workspace_compilation_and_recipe_audit_retained(self):
        ci = CI_YML.read_text(encoding="utf-8")
        self.assertIn(
            "cargo +1.88 test --locked --offline --workspace --all-targets",
            ci,
        )
        self.assertIn("scripts/check-prepared-dependencies.py", ci)


if __name__ == "__main__":
    unittest.main()
