#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ordinary unprivileged operator journey with explicit observer/helper paths.

Owns a same-uid target and checks inspect identity against /proc independently.
Optional --dashboard compiles existing mapped-provider fixtures, then delegates
PTY handling to dashboard-pty-drive.py. This proves scan presentation only.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


FIXTURES = Path(__file__).resolve().parent
SOURCE = FIXTURES.parents[1]
spec = importlib.util.spec_from_file_location("offline_journey", FIXTURES / "cross-command-drive.py")
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
require, run, success = shared.require, shared.run, shared.success


def cleanup(child):
    # No competing poller/reaper. Signal only while child ownership is retained.
    if child.returncode is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    child.wait()


def identity(document, text, pid, expected, metadata):
    require(document.get("schema") == "p11scope/inspect/v1", "wrong inspect schema")
    require(document.get("application_status") == "observed", "owned application was not observed")
    application = document["application"]
    require(application["path"] == expected, "inspect executable path differs from /proc")
    require((application["dev"], application["ino"]) == (metadata.st_dev, metadata.st_ino),
            "inspect executable physical identity differs from /proc")
    require(len(application) == 7, "unexpected inspect application fields")
    require(text.startswith(f"{Path(expected).name} (PID {pid})"), "text omits owned application heading")
    require(expected in text, "inspect text differs from JSON executable path")
    require("activity was not captured by inspect" in text, "inspect invented activity coverage")
    for field in ("calls", "cmdline", "comm", "environ"):
        require(field not in document, f"inspect unexpectedly publishes {field}")
    require("\x1b" not in text, "redirected inspect text contains terminal controls")


def commands(binary, helper, root):
    for command in ([], ["inspect"], ["inventory"]):
        text = success(run([binary, *command, "--help"])).decode()
        require("usage:" in text, "help omits usage")
        require("\x1b" not in text, "redirected help contains terminal controls")
    for command in ("inspect", "inventory"):
        code, stdout, stderr = run([binary, command, "--pid", "0"])
        require(code == 2 and not stdout, "invalid PID was not a usage error")
        require(b"--pid must be greater than zero" in stderr, "invalid PID reason missing")
        require(f"Try 'p11scope {command} --help'.".encode() in stderr, "scoped next step missing")

    target = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(120)"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        pid = target.pid
        proc = Path(f"/proc/{pid}/exe")
        # Popen returns after exec; this owned process remains in the same image.
        expected, metadata = str(proc.readlink()), proc.stat()
        text = success(run([binary, "inspect", "--pid", str(pid)])).decode()
        raw = success(run([binary, "inspect", "--pid", str(pid), "--json"]))
        document = json.loads(raw)
        identity(document, text, pid, expected, metadata)
        require(document["modules"] == [] and "0 PKCS#11 modules mapped" in text,
                "owned no-provider observation was not reported honestly")
        require(target.poll() is None, "owned target exited during inspection")
        print(f"ordinary-inspect text:\n{text}", end="")
        print("ordinary-inspect JSON:\n" + raw.decode(), end="")
    finally:
        cleanup(target)

    for flag in ("--help", "-h"):
        text = success(run([helper, flag])).decode()
        for phrase in ("executes provider code in its own helper process", "host ABI",
                       "explicit observer --manifest", "does not prove application use or semantic attestation"):
            require(phrase in text, f"helper help omits {phrase!r}")
    code, stdout, stderr = run([helper, "--module"])
    require(code == 2 and not stdout and b"--module requires a value" in stderr,
            "missing module argument is not a clear usage error")
    code, stdout, stderr = run([helper, "--module", str(root / "missing-provider.so")])
    require(code == 1 and not stdout and stderr, "missing module file did not fail cleanly")
    require(b"Manifest written" not in stderr, "missing module falsely reported publication")
    return ["help-and-invalid-scope", "owned-no-provider-inspect-text-json-proc-identity",
            "helper-help-and-missing-module"]


def dashboards(binary, root):
    driver = root / "app-first-driver"
    providers = [root / "app-p1.so", root / "app-p2.so"]
    success(run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", str(driver),
                 str(FIXTURES / "catalog-driver.c"), "-ldl"], timeout=30))
    for provider in providers:
        success(run(["cc", "-shared", "-fPIC", "-DLEGACY_MINOR=40", "-o", str(provider),
                     str(SOURCE / "crates/discover/tests/fixture/version_matrix.c")], timeout=30))
    ready = root / "provider.ready"
    target = subprocess.Popen([str(driver), "--ready", str(ready), "--sleep", "120",
                               *map(str, providers)], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            require(target.poll() is None, "provider target exited before readiness")
            require(time.monotonic() < deadline, "provider readiness timed out")
            time.sleep(0.02)
        require(int(ready.read_text().split()[1]) == target.pid, "provider readiness PID mismatch")
        code, raw, stderr = run([sys.executable, "-I", str(FIXTURES / "dashboard-pty-drive.py"),
                                binary, str(target.pid), "60", "30", "app-first", "48", "12"],
                               timeout=35)
        require(code == 0, f"PTY journey exit {code}: {raw[-16000:]!r} {stderr[-4096:]!r}")
        result = raw.decode()
        require("pty-dashboard-app-first: PASS" in result, "wrong PTY mode passed")
        require("48x12" in result and "80x24" in result, "required dimensions were not exercised")
        print(result, end="")
        code, raw, stderr = run([binary, "inventory", "--pid", str(target.pid),
                                 "--capture", "scan", "--dashboard", "--json"])
        require(code == 0 and b"degraded" in stderr, "redirected dashboard did not explain degradation")
        require(b"\x1b" not in raw, "redirected dashboard polluted JSON with terminal controls")
        document = json.loads(raw)
        require(document["schema"] == "p11scope/inventory/v1", "wrong redirected inventory schema")
        require(len(document["callers"]) == 1 and document["callers"][0]["pid"] == target.pid,
                "redirected JSON lost the owned caller")
        paths = {path for module in document["modules"] for path in module["paths"]}
        require(all(str(provider) in paths for provider in providers), "redirected JSON lost mapped modules")
        require(len(document["edges"]) == 2 and all(edge["entries"]["count"] == 0
                and edge["entries"]["coverage"]["state"] == "unknown"
                for edge in document["edges"]), "scan JSON invented covered call activity")
    finally:
        cleanup(target)
    return ["owned-mapped-provider-dashboard-80x24-and-48x12", "redirected-scan-dashboard-machine-json"]


class Controls(unittest.TestCase):
    def test_wrong_executable_identity_fails(self):
        # A believable observation with another inode must not pass by name.
        document = {"schema": "p11scope/inspect/v1", "application_status": "observed",
                    "application": {"path": "/bin/owned", "dev": 1, "ino": 101}}
        class Metadata:
            st_dev, st_ino = 1, 100
        with self.assertRaisesRegex(AssertionError, "physical identity"):
            identity(document, "owned (PID 12)\n/bin/owned", 12, "/bin/owned", Metadata())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary")
    parser.add_argument("--helper")
    parser.add_argument("--dashboard", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
        return 0 if result.wasSuccessful() else 1
    if not args.binary or not args.helper:
        parser.error("explicit --binary and --helper paths are required")
    binary, helper = (str(Path(path).resolve(strict=True)) for path in (args.binary, args.helper))
    base = Path(os.environ.get("TMPDIR", "/var/tmp/p11scope-ws-tmp"))
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ordinary-journey-", dir=base) as directory:
        root = Path(directory)
        cells = commands(binary, helper, root)
        if args.dashboard:
            cells.extend(dashboards(binary, root))
        print(json.dumps({"mode": "unprivileged-owned-operator-journey; no live call qualification",
                          "binary": binary, "helper": helper, "passed": cells}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"ordinary command journey failed: {error}", file=sys.stderr)
        sys.exit(1)
