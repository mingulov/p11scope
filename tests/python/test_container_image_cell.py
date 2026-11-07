#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Permanent container-image cell: argument contract and preflight exits.

Runs scripts/matrix/verify-container-image.sh against stub tools in a fake
repo root with a hermetic PATH: no docker daemon, sudo, SoftHSM, BTF or
privileged run needed. Proves misuse exits 2 with a usage line, a missing
prerequisite exits 77, and the lane keeps its oracle and refusal markers.
The legs themselves (exact counts, attribution, refusals) are proven by
real runs of the script, not here.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "scripts/matrix/verify-container-image.sh"


def write_executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


class ContainerImageCellTests(unittest.TestCase):
    maxDiff = 4096

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope-container-image-cell-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        # Fake repo root with a copy of the lane and the helpers it sources.
        self.fake = self.base / "fake"
        (self.fake / "scripts/matrix").mkdir(parents=True)
        shutil.copy2(ENTRY, self.fake / "scripts/matrix/verify-container-image.sh")
        for helper in ("scripts/lib.sh", "scripts/matrix/matrix-lib.sh",
                       "scripts/cleanup-traps.sh"):
            shutil.copy2(ROOT / helper, self.fake / helper)
        self.entry = self.fake / "scripts/matrix/verify-container-image.sh"
        # Hermetic tools: stubs plus symlinks to the coreutils the
        # argument and preflight paths reach. Nothing else on PATH, so a
        # removed stub is genuinely missing (no /usr/bin leak-through).
        self.tools = self.base / "tools"
        self.tools.mkdir()
        self.stub_texts = {}
        self.write_stub("docker", "#!/bin/sh\nexit 0\n")
        self.write_stub("gcc", "#!/bin/sh\nexit 0\n")
        self.write_stub("python3", "#!/bin/sh\nexit 0\n")
        self.write_stub("file", "#!/bin/sh\nexit 0\n")
        self.write_stub("softhsm2-util", "#!/bin/sh\nexit 0\n")
        self.write_stub("sudo", '#!/bin/sh\n[ "${1-}" = "-n" ] && shift\nexec "$@"\n')
        self.write_stub("gnutimeout", '#!/bin/sh\necho "timeout (GNU coreutils) 9.0"\nexit 0\n')
        for name in ("dirname", "mkdir", "head", "id", "true", "rm", "cat", "date",
                     "ln", "chmod", "mktemp", "grep"):
            target = shutil.which(name)
            self.assertIsNotNone(target, f"host lacks coreutil {name}")
            (self.tools / name).symlink_to(target)
        # Preflight hook files (must exist).
        self.module = self.base / "libsofthsm2.so"
        self.module.write_text("stub")
        self.btf = self.base / "vmlinux"
        self.btf.write_text("BTF")
        self.cgroup = self.base / "cgroup.controllers"
        self.cgroup.write_text("pids")
        # A fake observer binary (executable file is enough for arg checks;
        # the static-content gate runs later, in setup).
        self.observer = self.base / "p11scope"
        write_executable(self.observer, "#!/bin/sh\nexit 0\n")
        self.outdir = self.base / "out"
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash, "host lacks bash")
        self.tmp = self.base / "tmp"
        self.tmp.mkdir()
        self.env = os.environ.copy()
        self.env.update({
            "PATH": str(self.tools),
            "TMPDIR": str(self.tmp),
            "P11SCOPE_CONTAINER_IMAGE_MODULE": str(self.module),
            "P11SCOPE_CONTAINER_IMAGE_BTF": str(self.btf),
            "P11SCOPE_CONTAINER_IMAGE_CGROUP": str(self.cgroup),
        })

    def write_stub(self, name, text):
        write_executable(self.tools / name, text)
        self.stub_texts[name] = text

    def run_cell(self, *args, remove=(), env=None):
        for name in remove:
            (self.tools / name).unlink(missing_ok=True)
        merged = dict(self.env)
        merged.update(env or {})
        try:
            return subprocess.run(
                [self.bash, str(self.entry), *args], env=merged,
                text=True, capture_output=True, timeout=60)
        finally:
            for name in remove:
                if name in self.stub_texts:
                    write_executable(self.tools / name, self.stub_texts[name])

    def test_no_args_is_a_usage_error(self):
        result = self.run_cell()
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_help_exits_zero(self):
        result = self.run_cell("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout)

    def test_both_modes_are_refused(self):
        result = self.run_cell("--observer-bin", str(self.observer),
                               "--image", "img:tag", "--out", str(self.outdir))
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_neither_mode_is_refused(self):
        result = self.run_cell("--out", str(self.outdir))
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_missing_out_is_refused(self):
        result = self.run_cell("--image", "img:tag")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_unknown_flag_is_refused(self):
        result = self.run_cell("--image", "img:tag", "--out", str(self.outdir),
                               "--vng", "v6.12.111")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_relative_observer_bin_is_refused(self):
        result = self.run_cell("--observer-bin", "relative/p11scope",
                               "--out", str(self.outdir))
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_missing_or_unusable_observer_bin_is_refused(self):
        missing = self.run_cell("--observer-bin", str(self.base / "absent"),
                                "--out", str(self.outdir))
        self.assertEqual(missing.returncode, 2)
        plain = self.base / "plain"
        plain.write_text("not executable")
        unusable = self.run_cell("--observer-bin", str(plain),
                                 "--out", str(self.outdir))
        self.assertEqual(unusable.returncode, 2)

    def test_empty_image_is_refused(self):
        result = self.run_cell("--image", "", "--out", str(self.outdir))
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_root_caller_is_refused(self):
        # Unlink first: writing through the symlink would hit /usr/bin/id.
        (self.tools / "id").unlink()
        self.write_stub("id", "#!/bin/sh\necho 0\n")
        result = self.run_cell("--image", "img:tag", "--out", str(self.outdir))
        self.assertEqual(result.returncode, 2)

    def test_missing_tool_is_a_setup_failure(self):
        for tool in ("docker", "gcc", "python3", "file", "softhsm2-util", "sudo"):
            with self.subTest(tool=tool):
                result = self.run_cell("--image", "img:tag",
                                       "--out", str(self.outdir),
                                       remove=(tool,))
                self.assertEqual(result.returncode, 77, tool)
                self.assertIn(tool, result.stderr)

    def test_sudo_without_a_password_is_a_setup_failure(self):
        self.write_stub("sudo", "#!/bin/sh\nexit 1\n")
        result = self.run_cell("--image", "img:tag", "--out", str(self.outdir))
        self.assertEqual(result.returncode, 77)

    def test_docker_daemon_down_is_a_setup_failure(self):
        self.write_stub("docker", '#!/bin/sh\n[ "$1" = info ] && exit 1\nexit 0\n')
        result = self.run_cell("--image", "img:tag", "--out", str(self.outdir))
        self.assertEqual(result.returncode, 77)

    def test_sudo_docker_fallback_reaches_setup(self):
        # Direct `docker info` fails but the sudo path succeeds (the fedora
        # layout): preflight passes and the run reaches the setup static
        # gate, which the stub `file` output cannot satisfy.
        self.write_stub("docker", '#!/bin/sh\n[ "$1" = info ] && exit 1\nexit 0\n')
        self.write_stub("sudo", '#!/bin/sh\n[ "${1-}" = "-n" ] && shift\n'
                                '[ "$2" = info ] && exit 0\nexec "$@"\n')
        result = self.run_cell("--observer-bin", str(self.observer),
                               "--out", str(self.outdir))
        self.assertEqual(result.returncode, 2)
        self.assertIn("not static-pie", result.stderr)

    def test_no_gnu_timeout_is_a_setup_failure(self):
        self.write_stub("timeout", '#!/bin/sh\necho "timeout (uutils coreutils) 0.8.0"\nexit 0\n')
        result = self.run_cell("--image", "img:tag", "--out", str(self.outdir),
                               remove=("gnutimeout",))
        self.assertEqual(result.returncode, 77)

    def test_missing_btf_or_cgroup_is_a_setup_failure(self):
        for hook in ("P11SCOPE_CONTAINER_IMAGE_BTF", "P11SCOPE_CONTAINER_IMAGE_CGROUP"):
            with self.subTest(hook=hook):
                result = self.run_cell("--image", "img:tag",
                                       "--out", str(self.outdir),
                                       env={hook: str(self.base / "absent")})
                self.assertEqual(result.returncode, 77, hook)

    def test_missing_softhsm_is_a_setup_failure(self):
        result = self.run_cell("--image", "img:tag", "--out", str(self.outdir),
                               env={"P11SCOPE_CONTAINER_IMAGE_MODULE": str(self.base / "absent")})
        self.assertEqual(result.returncode, 77)

    def test_lane_keeps_its_oracle_and_refusal_markers(self):
        text = ENTRY.read_text()
        for marker in ("--network=none", "--network none", "host-exact", "container-exact",
                       "refusal-pidns", "refusal-cap",
                       "pid-namespace-mismatch: refusing --pid",
                       "cannot identify process mount namespace: Permission denied",
                       "check-capture-evidence.py clean-metrics",
                       "check-count-multiset.py",
                       "apparmor=unconfined"):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
