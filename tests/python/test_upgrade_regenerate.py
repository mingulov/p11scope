#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The upgrade fixtures regenerate exactly.

The README `Regenerate` manifest must list precisely the sanitizer's
input set (no missing or extra file can hide in prose), the
sanitizer's scrub rules must hold, and the full
unsanitize-then-sanitize round trip over the committed fixtures must
reproduce them byte for byte.
"""
import filecmp
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPGRADE = ROOT / "tests" / "fixtures" / "upgrade"
README = UPGRADE / "README.md"
SANITIZE = UPGRADE / "tools" / "sanitize.py"
TOOLS = UPGRADE / "tools"
_UNSET = object()


def load_sanitize():
    spec = importlib.util.spec_from_file_location("upgrade_sanitize", SANITIZE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def readme_manifest():
    """The ```manifest block under ## Regenerate: one file per line."""
    text = README.read_text(encoding="utf-8")
    match = re.search(r"```manifest\n(.*?)```", text, re.DOTALL)
    assert match is not None, "README has no ```manifest block"
    return [line.strip() for line in match.group(1).splitlines() if line.strip()]


def unsanitize(document, raw_prefix):
    """Inverse of the sanitizer's canonical maps (structure-preserving).

    Every transform is injective over the values the committed
    fixtures carry, so re-sanitizing in the same encounter order
    restores the exact canonical bytes.
    """
    if isinstance(document, dict):
        return {key: unsanitize(value, raw_prefix) for key, value in document.items()}
    if isinstance(document, list):
        return [unsanitize(value, raw_prefix) for value in document]
    if not isinstance(document, str):
        return document
    text = document.replace("/work", raw_prefix)
    # Same +9000 shift as integer pid fields: the sanitizer keys all
    # pid representations by the number in one shared map, so the
    # inverse must keep equal pids equal across representations.
    text = re.sub(r"pid:(\d+)", lambda m: f"pid:{int(m.group(1)) + 9000}", text)
    text = re.sub(r"/proc/(\d+)", lambda m: f"/proc/{int(m.group(1)) + 9000}", text)
    text = re.sub(r"\bpid (\d+)", lambda m: f"pid {int(m.group(1)) + 9000}", text)
    text = text.replace("user-1000.slice", "user-1001.slice")
    text = text.replace("session-1.scope", "session-c9.scope")
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", text):
        text = "f" + text[1:]
    return text


def unsanitize_document_integers(document):
    """Inverse integer maps applied field-wise (mirrors walk() keys).

    Unlisted integer fields pass through untouched here and in the
    sanitizer alike, so they need no inverse.
    """
    if isinstance(document, dict):
        rebuilt = {}
        for key, value in document.items():
            if key in ("mtime_secs", "mtime_nanos") and isinstance(value, int):
                rebuilt[key] = 99 if key == "mtime_secs" else 7
            elif key in ("pid", "pid_host", "handoff_child_pid",
                         "ino", "inode", "task_cookie", "exec_id") \
                    and isinstance(value, int) and not isinstance(value, bool):
                rebuilt[key] = value + 9000
            elif key == "dev" and isinstance(value, int) \
                    and not isinstance(value, bool):
                rebuilt[key] = value + 40
            elif key in ("dev", "device") and isinstance(value, dict):
                rebuilt[key] = {
                    "major": value.get("major", 0) + 40,
                    "minor": value.get("minor", 0) + 40,
                }
            elif key == "dev" and isinstance(value, list):
                rebuilt[key] = [part + 40 for part in value]
            elif key in ("device_major", "device_minor") and isinstance(value, int):
                rebuilt[key] = value + 40
            elif key == "exe" and value == "launcher":
                # Every committed "launcher" exe sits under launched_by,
                # where the sanitizer maps any value to "launcher".
                rebuilt[key] = "origlauncher"
            else:
                rebuilt[key] = unsanitize_document_integers(value)
        return rebuilt
    if isinstance(document, list):
        return [unsanitize_document_integers(value) for value in document]
    return document


class RegenerateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitize = load_sanitize()

    def test_readme_manifest_matches_sanitizer_files(self):
        """The documented capture set is exactly the sanitizer input
        set: a file missing on either side fails loudly instead of
        breaking regeneration later."""
        self.assertEqual(readme_manifest(), list(self.sanitize.FILES))
        for name in self.sanitize.FILES:
            with self.subTest(name=name):
                self.assertTrue(
                    (UPGRADE / name).is_file(), f"{name} is committed")

    def test_scrub_canonicalizes_prefix_and_cgroup(self):
        """The scrub rules rewrite the capture prefix and the cgroup
        slice/scope to canonical values."""
        prefixes = self.sanitize.build_prefixes("/custom/work")
        self.assertEqual(
            self.sanitize.scrub_string("/custom/work/f2/bin/tool", prefixes),
            "/work/f2/bin/tool")
        self.assertEqual(
            self.sanitize.scrub_string(
                "user.slice/user-4242.slice/session-z9.scope", prefixes),
            "user.slice/user-1000.slice/session-1.scope")

    def test_sanitizer_usage_errors(self):
        """Wrong argument counts fail with usage, never a traceback."""
        for argv in ([], ["a", "b", "c", "d"]):
            with self.subTest(argv=argv):
                proc = subprocess.run(
                    [sys.executable, str(SANITIZE), *argv],
                    capture_output=True, text=True, timeout=60)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("Usage", proc.stderr)

    def test_sanitizer_runs_by_direct_path(self):
        """The README documents direct execution, so the file must be
        executable, not only runnable through an interpreter."""
        self.assertTrue(os.access(SANITIZE, os.X_OK), "sanitize.py is +x")
        proc = subprocess.run(
            [str(SANITIZE)], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Usage", proc.stderr)

    def test_scrub_maps_fedora_provider_prefix(self):
        """Fedora SoftHSM paths canonicalize to the same provider
        directory as the Debian paths."""
        prefixes = self.sanitize.build_prefixes("/custom/work")
        self.assertEqual(
            self.sanitize.scrub_string(
                "/usr/lib64/pkcs11/libsofthsm2.so", prefixes),
            "/usr/lib/softhsm/libsofthsm2.so")

    def test_scrub_maps_lib64_generic(self):
        """Other Fedora library paths canonicalize under /usr/lib."""
        prefixes = self.sanitize.build_prefixes("/custom/work")
        self.assertEqual(
            self.sanitize.scrub_string(
                "/usr/lib64/libcrypto.so.3", prefixes),
            "/usr/lib/libcrypto.so.3")

    def test_readme_documents_manifest_handoff(self):
        """The manifest producer and the single raw directory are
        spelled exactly, so collection cannot drift from prose."""
        words = " ".join(README.read_text(encoding="utf-8").split())
        self.assertIn("with OUT set to one raw directory `<rawdir>`", words)
        discover = ("p11scope-discover-0.7.1 --module <provider> "
                    "-o <rawdir>/v071-manifest-softhsm.json")
        self.assertIn(discover, words)
        self.assertLess(
            words.index(discover), words.index("keyops <rawdir>"),
            "the discover producer precedes its keyops consumer")

    def write_raw_inputs(self, tmp):
        """Unsanitized copies of every committed fixture input."""
        raw = tmp / "raw"
        raw.mkdir()
        for name in self.sanitize.FILES:
            document = json.loads((UPGRADE / name).read_text(encoding="utf-8"))
            document = unsanitize(document, str(raw))
            # Integer fields invert after strings so pid-like
            # numbers inside strings are already handled above.
            document = unsanitize_document_integers(document)
            (raw / name).write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8")
        return raw

    def assert_matches_committed(self, out):
        mismatched = [
            name for name in self.sanitize.FILES
            if not filecmp.cmp(str(UPGRADE / name), str(out / name), shallow=False)
        ]
        self.assertEqual(mismatched, [])

    def test_roundtrip_reproduces_committed_fixtures(self):
        """Unsanitized copies of every committed fixture input,
        sanitized from a scratch prefix, reproduce the committed
        bytes exactly."""
        tmp = Path(tempfile.mkdtemp(prefix="upgrade-regen-"))
        try:
            raw = self.write_raw_inputs(tmp)
            out = tmp / "out"
            self.sanitize.fresh_state()
            self.sanitize.sanitize_tree(str(raw), str(out), str(raw))
            self.assert_matches_committed(out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cli_roundtrip_reproduces_committed_fixtures(self):
        """Same round trip through the real command line, so the
        rawdir/outdir/prefix argument plumbing is covered too."""
        tmp = Path(tempfile.mkdtemp(prefix="upgrade-regen-cli-"))
        try:
            raw = self.write_raw_inputs(tmp)
            out = tmp / "out"
            proc = subprocess.run(
                [sys.executable, str(SANITIZE), str(raw), str(out), str(raw)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assert_matches_committed(out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


STUB_SUDO = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -n) shift ;;
    --preserve-env=*) shift ;;
    --preserve-env) shift; shift ;;
    chown) exit 0 ;;
    rmdir) exit 0 ;;
    *) break ;;
  esac
done
exec "$@"
"""

STUB_FLOCK = """#!/bin/sh
shift
exec "$@"
"""

STUB_OBSERVER = """#!/bin/sh
o=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then o="$a"; fi
  prev="$a"
done
[ -n "$o" ] || exit 2
echo "semantic lane ready: stub" >&2
echo '{"stub": true}' > "$o"
"""

STUB_OBSERVER_SILENT = """#!/bin/sh
o=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then o="$a"; fi
  prev="$a"
done
[ -n "$o" ] || exit 2
echo '{"stub": true}' > "$o"
"""

FAKE_HELPER = """#!/bin/sh
trap 'exit 42' TERM
echo "mapped pid=$$"
sleep ${FAKE_HELPER_SLEEP:-0}
exit ${FAKE_HELPER_RC:-0}
"""

FAKE_ANCHOR = """#!/bin/sh
prev=""
for a in "$@"; do
  if [ "$prev" = "--ready" ]; then touch "$a"; fi
  prev="$a"
done
sleep 60
"""

FAKE_SIGNER = """#!/bin/sh
# Fails only arrival index $CHURN_SIGNER_FAIL_AT (unset: pass).
# Arrival order matches spawn order (2s stagger, ms runtimes);
# the mkdir lock makes the counter atomic.
state=${CHURN_SIGNER_STATE:-}
[ -n "$state" ] || exit 2
lockdir=$state.lock
while ! mkdir "$lockdir" 2>/dev/null; do sleep 0.01; done
n=0; [ -f "$state" ] && n=$(cat "$state")
echo $((n + 1)) > "$state"
rmdir "$lockdir"
[ -n "${CHURN_SIGNER_FAIL_AT:-}" ] && [ "$n" = "$CHURN_SIGNER_FAIL_AT" ] && exit 1
exit 0
"""

FAKE_CATALOG = """#!/bin/sh
prev=""
for a in "$@"; do
  if [ "$prev" = "--ready" ]; then touch "$a"; fi
  prev="$a"
done
sleep ${ANCHOR_SLEEP:-0}
exit ${ANCHOR_RC:-0}
"""


class DriverTests(unittest.TestCase):
    """Key-operations capture drivers propagate helper results."""

    def stage(self, tmp, observer=STUB_OBSERVER):
        bin = tmp / "bin"
        bin.mkdir()
        (bin / "sudo").write_text(STUB_SUDO, encoding="utf-8")
        (bin / "flock").write_text(STUB_FLOCK, encoding="utf-8")
        (bin / "observer").write_text(observer, encoding="utf-8")
        for name in ("sudo", "flock", "observer"):
            (bin / name).chmod(0o755)
        work = tmp / "work"
        helpers = work / "f2" / "bin"
        helpers.mkdir(parents=True)
        (helpers / "steady-keys").write_text(FAKE_HELPER, encoding="utf-8")
        (helpers / "steady-keys").chmod(0o755)
        out = work / "out"
        out.mkdir()
        (out / "v071-manifest-softhsm.json").write_text("{}", encoding="utf-8")
        prov = tmp / "prov.so"
        prov.write_text("stub", encoding="utf-8")
        env = dict(os.environ, TMPDIR=str(work), PROV=str(prov),
                   PATH=f"{bin}{os.pathsep}{os.environ['PATH']}")
        return work, out, env

    def run_keyops(self, script, helper_rc, observer=STUB_OBSERVER,
                     budget=None, helper_sleep=None, fake_cgroup=False):
        tmp = Path(tempfile.mkdtemp(prefix="upgrade-driver-"))
        try:
            work, out, env = self.stage(tmp, observer)
            env["FAKE_HELPER_RC"] = str(helper_rc)
            if budget is not None:
                env["READY_BUDGET"] = str(budget)
            if helper_sleep is not None:
                env["FAKE_HELPER_SLEEP"] = str(helper_sleep)
            if fake_cgroup:
                env["CG"] = str(work / "cg")
            args = ["sh", str(TOOLS / script), f"{tmp}/bin/observer",
                      "v071"]
            if script == "capture-ops.sh":
                args.append("keyops")
            args.append(str(out))
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=120, env=env)
            return proc, sorted(p.name for p in out.iterdir())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_ops_propagates_helper_failure(self):
        """A failing key workload fails the capture with its reason."""
        proc, _ = self.run_keyops("capture-ops.sh", 1)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("anchor failed rc=1", proc.stderr)

    def test_ops_success_path_writes_output(self):
        """The passing leg proves the failure leg is non-vacuous."""
        proc, files = self.run_keyops("capture-ops.sh", 0)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("v071-inventory-keyops.json", files)
        self.assertIn("v071.go", files)

    def test_ops_gate_untouched_without_readiness(self):
        """No readiness, no gate touch, exit 1 (bounded wait)."""
        proc, files = self.run_keyops(
            "capture-ops.sh", 0, observer=STUB_OBSERVER_SILENT, budget=2)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("semantic lane never ready", proc.stderr)
        self.assertNotIn("v071.go", files)

    def test_syskeyops_propagates_helper_failure(self):
        """A failing key workload fails the capture with its reason."""
        proc, _ = self.run_keyops("capture-syskeyops.sh", 1)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("anchor failed rc=1", proc.stderr)

    def test_syskeyops_waits_for_resident_anchor(self):
        """A resident anchor runs to completion: no kill lands (the
        trap would exit 42) and the capture succeeds."""
        proc, files = self.run_keyops(
            "capture-syskeyops.sh", 0, helper_sleep=3)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("v071-inventory-syskeyops.json", files)

    def test_syskeyops_success_path_writes_output(self):
        """The passing leg proves the failure leg is non-vacuous."""
        proc, files = self.run_keyops("capture-syskeyops.sh", 0)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("v071-inventory-syskeyops.json", files)
        self.assertIn("v071.sysgo", files)

    def test_syskeyops_gate_untouched_without_readiness(self):
        """No readiness, no gate touch, exit 1 (bounded wait)."""
        proc, files = self.run_keyops(
            "capture-syskeyops.sh", 0, observer=STUB_OBSERVER_SILENT,
            budget=2)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("semantic lane never ready", proc.stderr)
        self.assertNotIn("v071.sysgo", files)

    def test_cgkeyops_gate_untouched_without_readiness(self):
        """No readiness, no gate touch, exit 1 (fake cgroup fs)."""
        proc, files = self.run_keyops(
            "capture-cgkeyops.sh", 0, observer=STUB_OBSERVER_SILENT,
            budget=2, fake_cgroup=True)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("semantic lane never ready", proc.stderr)
        self.assertNotIn("v071.cggo", files)

    def test_cgkeyops_success_path_writes_output(self):
        """The passing leg proves the failure leg is non-vacuous."""
        proc, files = self.run_keyops(
            "capture-cgkeyops.sh", 0, fake_cgroup=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("v071-inventory-cgkeyops.json", files)
        self.assertIn("v071.cggo", files)


class ChurnTests(unittest.TestCase):
    """The churn workload propagates signer failures."""

    def run_workload(self, fail_at=_UNSET):
        tmp = Path(tempfile.mkdtemp(prefix="upgrade-churn-"))
        try:
            out = tmp / "out"
            out.mkdir()
            helpers = tmp / "bin"
            helpers.mkdir()
            (helpers / "catalog-driver").write_text(
                FAKE_ANCHOR, encoding="utf-8")
            (helpers / "shortlived-sign").write_text(
                FAKE_SIGNER, encoding="utf-8")
            (helpers / "catalog-driver").chmod(0o755)
            (helpers / "shortlived-sign").chmod(0o755)
            (out / "v071.go").write_text("go\n", encoding="utf-8")
            env = dict(os.environ,
                       CHURN_SIGNER_STATE=str(tmp / "signer-count"))
            if fail_at is not _UNSET:
                env["CHURN_SIGNER_FAIL_AT"] = str(fail_at)
            proc = subprocess.run(
                [str(TOOLS / "churn-workload.sh"),
                 str(out), "v071", str(helpers), "/nonexistent-prov.so"],
                capture_output=True, text=True, timeout=300, env=env)
            return proc
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_first_failing_signer_fails_workload(self):
        """A single early failure propagates (kills last-only
        aggregation)."""
        proc = self.run_workload(fail_at=0)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("signer failed", proc.stdout + proc.stderr)

    def test_middle_failing_signer_fails_workload(self):
        """A single middle failure propagates (kills truncation)."""
        proc = self.run_workload(fail_at=4)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("signer failed", proc.stdout + proc.stderr)

    def test_passing_signers_complete(self):
        """The passing leg proves the failure legs are non-vacuous."""
        proc = self.run_workload()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("workload-done", proc.stdout)

    def run_churn_driver(self, fail_at=_UNSET):
        tmp = Path(tempfile.mkdtemp(prefix="upgrade-churn-driver-"))
        try:
            work = tmp / "work"
            helpers = work / "f2" / "bin"
            helpers.mkdir(parents=True)
            bin = tmp / "bin"
            bin.mkdir()
            (bin / "sudo").write_text(STUB_SUDO, encoding="utf-8")
            (bin / "flock").write_text(STUB_FLOCK, encoding="utf-8")
            (bin / "observer").write_text(STUB_OBSERVER, encoding="utf-8")
            for name in ("sudo", "flock", "observer"):
                (bin / name).chmod(0o755)
            (helpers / "catalog-driver").write_text(
                FAKE_ANCHOR, encoding="utf-8")
            (helpers / "shortlived-sign").write_text(
                FAKE_SIGNER, encoding="utf-8")
            (helpers / "catalog-driver").chmod(0o755)
            (helpers / "shortlived-sign").chmod(0o755)
            out = work / "out"
            out.mkdir()
            prov = tmp / "prov.so"
            prov.write_text("stub", encoding="utf-8")
            env = dict(os.environ, TMPDIR=str(work), PROV=str(prov),
                       CG=str(work / "cg"),
                       CHURN_SIGNER_STATE=str(tmp / "signer-count"),
                       PATH=f"{bin}{os.pathsep}{os.environ['PATH']}")
            if fail_at is not _UNSET:
                env["CHURN_SIGNER_FAIL_AT"] = str(fail_at)
            proc = subprocess.run(
                ["sh", str(TOOLS / "capture-churn.sh"),
                 f"{tmp}/bin/observer", "v071", str(out)],
                capture_output=True, text=True, timeout=300, env=env)
            workload_log = out / "v071.workload.log"
            log = workload_log.read_text(encoding="utf-8") \
                if workload_log.is_file() else ""
            files = sorted(p.name for p in out.iterdir())
            return proc, files, log
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_propagates_signer_failure(self):
        """The driver awaits the template without discarding status."""
        proc, _, log = self.run_churn_driver(fail_at=0)
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn("signer failed", log)

    def test_driver_success_path_writes_output(self):
        """The passing leg proves the failure leg is non-vacuous."""
        proc, files, log = self.run_churn_driver()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("v071-inventory-churn.json", files)
        self.assertIn("workload-done", log)

    def test_capture_script_invokes_workload_template(self):
        """The driver runs this template, not an embedded copy."""
        text = (TOOLS / "capture-churn.sh").read_text(encoding="utf-8")
        self.assertIn("churn-workload.sh", text)
        self.assertNotIn("shortlived-sign", text)
        self.assertTrue(
            os.access(TOOLS / "churn-workload.sh", os.X_OK),
            "the template is directly executable")

class AnchorTests(unittest.TestCase):
    """Single/manprof drivers propagate abnormal anchor death."""

    def run_simple(self, script, anchor_rc, script_args, anchor_sleep=0):
        tmp = Path(tempfile.mkdtemp(prefix="upgrade-anchor-"))
        try:
            bin = tmp / "bin"
            bin.mkdir()
            (bin / "sudo").write_text(STUB_SUDO, encoding="utf-8")
            (bin / "flock").write_text(STUB_FLOCK, encoding="utf-8")
            (bin / "observer").write_text(STUB_OBSERVER, encoding="utf-8")
            for name in ("sudo", "flock", "observer"):
                (bin / name).chmod(0o755)
            work = tmp / "work"
            helpers = work / "f2" / "bin"
            helpers.mkdir(parents=True)
            (helpers / "catalog-driver").write_text(
                FAKE_CATALOG, encoding="utf-8")
            (helpers / "catalog-driver").chmod(0o755)
            out = work / "out"
            out.mkdir()
            manifest = out / "v071-manifest-softhsm.json"
            manifest.write_text("{}", encoding="utf-8")
            prov = tmp / "prov.so"
            prov.write_text("stub", encoding="utf-8")
            env = dict(os.environ, TMPDIR=str(work), PROV=str(prov),
                       ANCHOR_RC=str(anchor_rc),
                       ANCHOR_SLEEP=str(anchor_sleep),
                       PATH=f"{bin}{os.pathsep}{os.environ['PATH']}")
            proc = subprocess.run(
                ["sh", str(TOOLS / script), f"{tmp}/bin/observer",
                 *script_args, str(out)],
                capture_output=True, text=True, timeout=120, env=env)
            return proc, sorted(p.name for p in out.iterdir())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_single_propagates_anchor_failure(self):
        proc, _ = self.run_simple("capture-single.sh", 1, ("v071",))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("anchor failed rc=1", proc.stderr)

    def test_single_success_path_writes_output(self):
        proc, files = self.run_simple("capture-single.sh", 0, ("v071",))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("v071-inventory-scan.json", files)
        self.assertIn("v071-inventory-native.json", files)

    def test_single_accepts_intentional_kill(self):
        """A resident anchor killed by design (143) still passes."""
        proc, _ = self.run_simple(
            "capture-single.sh", 0, ("v071",), anchor_sleep=30)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_manprof_propagates_anchor_failure(self):
        proc, _ = self.run_simple(
            "capture-manprof.sh", 1, ("/tmp/x.json", "v071"))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("anchor failed rc=1", proc.stderr)

    def test_manprof_success_path_writes_output(self):
        proc, files = self.run_simple(
            "capture-manprof.sh", 0, ("/tmp/x.json", "v071"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("v071-manprof.json", files)

    def test_manprof_accepts_intentional_kill(self):
        """A resident anchor killed by design (143) still passes."""
        proc, _ = self.run_simple(
            "capture-manprof.sh", 0, ("/tmp/x.json", "v071"),
            anchor_sleep=30)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class ProbeTests(unittest.TestCase):
    """The shared provider probe honors overrides and fails named."""

    def probe(self, *candidates, extra_env=None):
        env = dict(os.environ)
        env.pop("PROV", None)
        env.update(extra_env or {})
        return subprocess.run(
            ["sh", "-c", '. "$1/capture-env.sh"; shift; probe_provider "$@"',
             "probe", str(TOOLS), *candidates],
            capture_output=True, text=True, timeout=60, env=env)

    def test_override_missing_file_fails_named(self):
        proc = self.probe(extra_env={"PROV": "/nonexistent-softHSM.so"})
        self.assertEqual(proc.returncode, 2)
        self.assertIn("missing prerequisite", proc.stderr)

    def test_override_existing_file_wins(self):
        with tempfile.NamedTemporaryFile() as handle:
            proc = self.probe(extra_env={"PROV": handle.name})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), handle.name)

    @unittest.skipUnless(
        os.path.isfile(
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
        or os.path.isfile("/usr/lib64/pkcs11/libsofthsm2.so"),
        "no system SoftHSM provider")
    def test_probe_finds_system_provider(self):
        proc = self.probe()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(proc.stdout.strip(), [
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib64/pkcs11/libsofthsm2.so"])

    def test_probe_empty_set_fails_named(self):
        proc = self.probe("/nonexistent-a.so", "/nonexistent-b.so")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("missing prerequisite", proc.stderr)

    def test_every_capture_script_sources_probe(self):
        """Each of the seven drivers reaches the shared probe (a
        revert to a hard-coded provider fails this test)."""
        scripts = sorted(
            p for p in TOOLS.glob("capture-*.sh")
            if p.name != "capture-env.sh")
        self.assertEqual(len(scripts), 7)
        for script in scripts:
            with self.subTest(script=script.name):
                text = script.read_text(encoding="utf-8")
                self.assertIn(". \"$TOOLS_DIR/capture-env.sh\"", text)
                self.assertIn("PROV=$(probe_provider) || exit 2", text)
                self.assertNotIn(
                    "PROV=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                    text)


if __name__ == "__main__":
    unittest.main()
