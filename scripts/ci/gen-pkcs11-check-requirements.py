#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Regenerate scripts/ci/pkcs11-check-requirements.txt.

Reads the exact installed closure from a scratch venv (`pip freeze`),
fetches every release artifact hash from the PyPI JSON API, and writes a
pip --require-hashes requirements file covering all artifacts (wheels for
every platform plus sdists), so any runner Python resolves deterministically.

Regeneration recipe (on a pkcs11-check version bump): install the new
version into a scratch venv, smoke-test the cell against it, then run this
script with that venv's pip and review the diff before replacing the file:

    python3 -I scripts/ci/gen-pkcs11-check-requirements.py /path/to/venv/bin/pip \\
        > /tmp/pkcs11-check-requirements.txt
"""
import json
import os
import subprocess
import sys
import urllib.request

HEADER = (
    "# SPDX-License-Identifier: GPL-3.0-or-later",
    "# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>",
    "# Pinned pkcs11-check install for the CI cell (scripts/ci/pkcs11-check-cell.sh).",
    "# Installed with `pip install --require-hashes -r scripts/ci/pkcs11-check-requirements.txt` by the pkcs11-check-smoke and",
    "# pkcs11-check-full jobs in .github/workflows/privileged-tests.yml. Every requirement",
    "# carries the sha256 of each published artifact (all wheels plus the sdist),",
    "# so any runner Python resolves the same bytes. Generated 2026-11-14 from the",
    "# working 0.2.3 closure via the PyPI JSON API; to regenerate on a version bump,",
    "# install the new version into a scratch venv, smoke-test the cell, then run",
    "# scripts/ci/gen-pkcs11-check-requirements.py against that venv and review the diff.",
)


def freeze(venv_pip):
    # Plain freeze: the app closure only (pip/setuptools stay the venv's own).
    out = subprocess.run([venv_pip, "freeze"],
                         capture_output=True, text=True, check=True)
    pins = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if "==" in line and not line.startswith(("#", "-e", "--")):
            name, _, version = line.partition("==")
            pins.append((name.strip(), version.strip()))
    return pins


def hashes_for(name, version):
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=60) as response:
        meta = json.load(response)
    digests = set()
    for artifact in meta["urls"]:
        digest = artifact["digests"]["sha256"]
        digests.add(digest)
    assert digests, f"no artifacts for {name}=={version}"
    return sorted(digests)


def main(argv):
    if len(argv) != 2:
        print("usage: gen-pkcs11-check-requirements.py VENV_PIP > requirements.txt",
              file=sys.stderr)
        return 2
    venv_pip = argv[1]
    if not (os.path.isfile(venv_pip) and os.access(venv_pip, os.X_OK)):
        print(f"gen-pkcs11-check-requirements.py: not an executable pip: {venv_pip}",
              file=sys.stderr)
        return 2
    pins = freeze(venv_pip)
    print(f"{len(pins)} pinned packages", file=sys.stderr)
    lines = list(HEADER)
    for name, version in pins:
        digests = hashes_for(name, version)
        print(f"{name}=={version}: {len(digests)} hashes", file=sys.stderr)
        lines.append(f"{name}=={version} \\")
        for digest in digests[:-1]:
            lines.append(f"    --hash=sha256:{digest} \\")
        lines.append(f"    --hash=sha256:{digests[-1]}")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
