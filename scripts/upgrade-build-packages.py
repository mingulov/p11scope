#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Build test DEB/RPM upgrade packages from locally built binaries.

Gate 5 needs packages built from this tree to upgrade from the official
v0.7.1 DEB/RPM. The official packager (scripts/package-release.py) needs a
trusted build-release.sh receipt; this helper reuses its DEB/RPM layout
(build_deb/build_rpm) with locally built binaries and a test RELEASE.json,
so the upgrade mechanics (install old, upgrade to new, doctor+capture,
state survival) can be exercised without the full official build.

Usage:
  python3 -I scripts/upgrade-build-packages.py \
    --observer target/.../p11scope \
    --helper target/.../p11scope-discover \
    --output-dir /tmp/out
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "package_release", ROOT / "scripts/package-release.py"
)
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


def version_from_manifest() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    package = text.split("[package]", 1)[1].split("\n[", 1)[0]
    import re

    found = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', package, re.M)
    if not found:
        raise ValueError("invalid release version in Cargo.toml")
    return found[1]


def git_head() -> str:
    env = {k: v for k, v in __import__("os").environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=__import__("os").devnull)
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        check=True,
    )
    return out.stdout.decode().strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observer", required=True, type=Path)
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--capture-mode", default="full", choices=["full", "p0"])
    args = parser.parse_args()
    observer = PACKAGE.regular(args.observer)
    helper = PACKAGE.regular(args.helper)
    version = version_from_manifest()
    head = git_head()
    try:
        epoch = PACKAGE.commit_epoch(ROOT)
    except ValueError:
        import time

        epoch = int(time.time())
    docs = {name: (PACKAGE.regular(ROOT / name), 0o644) for name in PACKAGE.LICENSES}
    test_release = {
        "schema_version": 1,
        "version": version,
        "head": head,
        "test_build": True,
        "note": "upgrade-gate5 test package; not an official release",
    }
    docs["RELEASE.json"] = (PACKAGE.encoded(test_release), 0o644)
    import tempfile

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="p11scope-upgrade-") as staging_name:
        staging = Path(staging_name)
        deb_data = PACKAGE.build_deb(
            staging, observer, helper, docs, version, args.capture_mode, epoch
        )
        rpm_data = PACKAGE.build_rpm(
            staging, observer, helper, docs, version, args.capture_mode, epoch
        )
    deb_name = f"p11scope_{version}_amd64.deb"
    rpm_name = f"p11scope-{version}-1.x86_64.rpm"
    (args.output_dir / deb_name).write_bytes(deb_data)
    (args.output_dir / rpm_name).write_bytes(rpm_data)
    sums = "".join(
        f"{PACKAGE.digest((args.output_dir / n).read_bytes())}  {n}\n"
        for n in sorted([deb_name, rpm_name])
    )
    (args.output_dir / "SHA256SUMS").write_text(sums)
    print(json.dumps({"deb": deb_name, "rpm": rpm_name, "version": version, "head": head}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
