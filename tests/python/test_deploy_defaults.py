#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deploy defaults: the DaemonSet image and the documented minimal run.

Pins two honesties: the DaemonSet default is runnable from the checkout
(the local dev image, or the published tag of the version in Cargo.toml,
which stays unpublished until the release step 7.4 push makes it live),
and deploy/README.md shows the proven minimal `docker run` recipe and
claims only the refusals the container-image cell actually proves.
"""

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DAEMONSET = ROOT / "deploy/k8s/20-daemonset.yaml"
DEPLOY_README = ROOT / "deploy/README.md"
DEV_IMAGE = "p11scope-observer:1"


def daemonset_image_and_policy():
    text = DAEMONSET.read_text()
    image = re.search(r"^(\s*)image: (\S+)\s*$", text, re.M)
    policy = re.search(r"^(\s*)imagePullPolicy: (\S+)\s*$", text, re.M)
    assert image is not None and policy is not None
    return image.group(2), policy.group(2)


def minimal_recipe_block():
    text = DEPLOY_README.read_text()
    blocks = re.findall(r"```sh\n(.*?)```", text, re.S)
    matches = [block for block in blocks if "docker run" in block and "doctor" in block]
    assert len(matches) == 1, "deploy/README.md must show one minimal docker run recipe"
    return matches[0]


class DeployDefaultsTests(unittest.TestCase):
    def test_daemonset_default_is_local_or_the_current_release(self):
        image, policy = daemonset_image_and_policy()
        with open(ROOT / "Cargo.toml", "rb") as handle:
            version = tomllib.load(handle)["package"]["version"]
        self.assertIn(image, {DEV_IMAGE, f"ghcr.io/mingulov/p11scope:{version}"},
                      "the default must be runnable from this checkout, "
                      "not a tag from a future release")
        self.assertEqual(policy, "Never" if image == DEV_IMAGE else "IfNotPresent")

    def test_minimal_recipe_mounts_the_node_cgroup_hierarchy(self):
        self.assertIn("-v /sys/fs/cgroup:/sys/fs/cgroup:ro", minimal_recipe_block(),
                      "the proven minimal run mounts cgroupfs read-only")

    def test_minimal_claim_names_only_the_proven_refusals(self):
        text = DEPLOY_README.read_text()
        self.assertNotIn("dropping any of them refuses", text,
                         "the cell proves two removals, not every flag")
        self.assertIn("or `SYS_PTRACE` refuses", text)
        self.assertIn("measured DaemonSet set", text,
                      "the run is the measured set, not a claimed minimum")
        self.assertIn("stands in for", text,
                      "SYS_ADMIN is the narrow-capability stand-in")
        self.assertIn("unmeasured", text,
                      "the narrow five-capability variant is named as unmeasured")
        self.assertNotIn("minimal container run", text,
                         "the old minimal wording contradicts the product term")
        self.assertNotIn("Privileges and why", text,
                         "the kind-table citation no longer applies")

    def test_rebuild_recipe_keeps_full_features(self):
        self.assertNotIn("--no-default-features", DEPLOY_README.read_text(),
                         "the published image holds the FULL binary, not P0 bytes")


if __name__ == "__main__":
    unittest.main()
