#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Deploy defaults: the DaemonSet image and the documented minimal runs.

Pins two honesties: the DaemonSet default is runnable from the checkout
(the local dev image, or the published tag of the version in Cargo.toml,
which stays unpublished until the release step 7.4 push makes it live),
and deploy/README.md shows the proven minimal `docker run` recipes (the
primary five-capability set first, then the SYS_ADMIN alternative) and
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


def minimal_recipe_blocks():
    text = DEPLOY_README.read_text()
    blocks = re.findall(r"```sh\n(.*?)```", text, re.S)
    matches = [block for block in blocks if "docker run" in block and "doctor" in block]
    assert len(matches) == 2, \
        "deploy/README.md must show the primary five-cap and alternative SYS_ADMIN recipes"
    return matches


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
        recipes = minimal_recipe_blocks()
        primary = [block for block in recipes if "--cap-drop ALL" in block]
        alternative = [block for block in recipes if "--cap-add SYS_ADMIN" in block]
        self.assertEqual(len(primary), 1, "the primary recipe drops to five caps")
        self.assertEqual(len(alternative), 1, "the alternative recipe keeps SYS_ADMIN")
        text = DEPLOY_README.read_text()
        self.assertLess(text.index(primary[0].splitlines()[0]),
                        text.index(alternative[0].splitlines()[0]),
                        "the five-cap recipe stays primary, ahead of the SYS_ADMIN alternative")
        for block in recipes:
            self.assertIn("-v /sys/fs/cgroup:/sys/fs/cgroup:ro", block,
                          "the proven minimal runs mount cgroupfs read-only")

    def test_minimal_claim_names_only_the_proven_refusals(self):
        text = DEPLOY_README.read_text()
        self.assertNotIn("dropping any of them refuses", text,
                         "the cell proves two removals, not every flag")
        self.assertIn("or `SYS_PTRACE` refuses", text)
        self.assertIn("Primary recipe (measured 2026-11-11", text,
                      "the run is the measured set, not a claimed minimum")
        self.assertIn("five-cap-exact", text,
                      "the container-image cell covering the recipe is named")
        self.assertIn("Alternative: the `SYS_ADMIN` set", text,
                      "the SYS_ADMIN run is the alternative, not the default")
        self.assertIn("close to full root", text,
                      "the alternative states the breadth of CAP_SYS_ADMIN")
        self.assertIn("file learning (fanotify)", text,
                      "the alternative names what SYS_ADMIN adds")
        self.assertIn("named gap", text,
                      "the alternative names the without-it gap")
        self.assertNotIn("minimal container run", text,
                         "the old minimal wording contradicts the product term")
        self.assertNotIn("Privileges and why", text,
                         "the kind-table citation no longer applies")

    def test_output_mount_names_the_root_owned_rule(self):
        text = DEPLOY_README.read_text()
        self.assertIn("is untrusted: owned by uid", text,
                      "the -o note quotes the user-owned-mount refusal")
        self.assertIn("planned for 0.8.0", text,
                      "the -o note names the easier-ownership plan")

    def test_rebuild_recipe_keeps_full_features(self):
        self.assertNotIn("--no-default-features", DEPLOY_README.read_text(),
                         "the published image holds the FULL binary, not P0 bytes")


if __name__ == "__main__":
    unittest.main()
