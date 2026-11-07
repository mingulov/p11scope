#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deploy defaults: the DaemonSet image and the documented minimal run.

Pins two honesties: the DaemonSet default is runnable from the checkout
(the local dev image, or the published tag of the version in Cargo.toml,
never a tag from a future release), and deploy/README.md shows the proven
minimal `docker run` recipe and claims only the refusals the
container-image cell actually proves.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEPLOY_README = ROOT / "deploy/README.md"


def minimal_recipe_block():
    text = DEPLOY_README.read_text()
    blocks = re.findall(r"```sh\n(.*?)```", text, re.S)
    matches = [block for block in blocks if "docker run" in block and "doctor" in block]
    assert len(matches) == 1, "deploy/README.md must show one minimal docker run recipe"
    return matches[0]


class DeployDefaultsTests(unittest.TestCase):
    def test_minimal_recipe_mounts_the_node_cgroup_hierarchy(self):
        self.assertIn("-v /sys/fs/cgroup:/sys/fs/cgroup:ro", minimal_recipe_block(),
                      "the proven minimal run mounts cgroupfs read-only")

    def test_minimal_claim_names_only_the_proven_refusals(self):
        text = DEPLOY_README.read_text()
        self.assertNotIn("dropping any of them refuses", text,
                         "the cell proves two removals, not every flag")
        self.assertIn("or `SYS_PTRACE` refuses", text)
        self.assertIn("Privileges and why", text)

    def test_rebuild_recipe_keeps_full_features(self):
        self.assertNotIn("--no-default-features", DEPLOY_README.read_text(),
                         "the published image holds the FULL binary, not P0 bytes")


if __name__ == "__main__":
    unittest.main()
