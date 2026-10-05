# SPDX-License-Identifier: GPL-3.0-or-later
"""Behavior tests for the live workload mapping receipt."""

import argparse
import hashlib
import json
import math
import os
import re
import runpy
import shlex
import signal
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RECEIPT = ROOT / "scripts" / "system-scope-receipt.py"
SUPERVISOR = ROOT / "scripts" / "system-scope-supervisor.py"
WORKLOAD_SOURCE = ROOT / "scripts" / "system-scope-workload.c"
RECEIPT_NS = runpy.run_path(str(RECEIPT))
SUPERVISOR_NS = runpy.run_path(str(SUPERVISOR))
# Wall-clock bounds in ShellOwnedLifecycleTest are of two kinds, as in
# test_lane13_evidence.py. SEMANTIC bounds are what a case asserts (a zero
# natural wait that forces the TERM path, a helper's own term/total budget)
# and stay literal. SLACK bounds only wait for an event that must happen (a
# marker, a supervisor exit, a harness cap); their expiry is a failure, so
# they scale with P11SCOPE_TEST_TIME_SCALE. A passing case never waits a SLACK
# bound out, so the default costs no time unloaded.
#
# A command whose lifetime must outlast owned_verify_launch is held on a
# release file the case touches after verification, never a fixed sleep: a
# 1-2 s sleep exited before verify-group ran under host load ~10, which
# reported "owned launch did not establish a live private session group"
# for a group that had been established (DR-SCOPE-RECEIPT-SESSION-FLAKE).
DEFAULT_TIME_SCALE = 5.0


def _time_scale():
    raw = os.environ.get("P11SCOPE_TEST_TIME_SCALE", "").strip()
    if not raw:
        return DEFAULT_TIME_SCALE
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value < 1:
        raise SystemExit("P11SCOPE_TEST_TIME_SCALE must be a finite number >= 1")
    return value


TIME_SCALE = _time_scale()


def slack(seconds):
    """Scale a wait-until bound whose expiry can only mean failure."""
    return seconds * TIME_SCALE


def slack_whole(seconds):
    """Scale a SLACK bound for shell helpers that take whole seconds."""
    return str(math.ceil(seconds * TIME_SCALE))


def slack_polls(count):
    """Scale a shell poll-loop count (one `sleep .01` per iteration)."""
    return str(math.ceil(count * TIME_SCALE))


HOLD_CODE = (
    "import pathlib,sys,time\n"
    "gate=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+float(sys.argv[2])\n"
    "while not gate.exists():\n"
    " assert time.monotonic()<deadline, 'held command was never released'\n"
    " time.sleep(.01)\n"
)


def held_command(release):
    """Shell argv for a command that lives until `release` exists."""
    return (f"python3 -c {shlex.quote(HOLD_CODE)} "
            f"{shlex.quote(str(release))} {slack(30)}")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fd_mount_id(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        prefix = "mnt_id:\t"
        for line in Path(f"/proc/self/fdinfo/{fd}").read_text(
                encoding="utf-8").splitlines():
            if line.startswith(prefix):
                return int(line.removeprefix(prefix))
    finally:
        os.close(fd)
    raise AssertionError("opened test file has no fd mount identity")


def proc_stat(pid, starttime):
    # Fields 4..21 are zero; starttime is field 22. The command deliberately
    # contains a space and ')' to exercise last-paren parsing.
    return f"{pid} (owned worker) name) S " + " ".join(["0"] * 18 + [str(starttime)]) + "\n"


class SyntheticProc:
    def __init__(self, root, mapped, *, pid=4321, starttime=777,
                 address=0x7F000123, path="/alias/provider.so", perms="r-xp",
                 mapping_dev=None, mountinfo=None):
        self.root = root
        self.pid = pid
        self.starttime = starttime
        self.address = address
        self.begin = 0x7F000000
        self.end = 0x7F001000
        process = root / str(pid)
        (process / "map_files").mkdir(parents=True)
        (process / "ns").mkdir()
        (process / "ns" / "mnt").write_text("synthetic namespace\n",
                                               encoding="utf-8")
        (process / "stat").write_text(proc_stat(pid, starttime), encoding="utf-8")
        info = mapped.stat()
        dev = mapping_dev or f"{os.major(info.st_dev):x}:{os.minor(info.st_dev):x}"
        mapping_major, mapping_minor = (int(field, 16)
                                        for field in dev.split(":", 1))
        line = (f"{self.begin:x}-{self.end:x} {perms} 00000000 {dev} "
                f"{info.st_ino} {path}\n")
        (process / "maps").write_text(line, encoding="utf-8")
        (process / "map_files" / f"{self.begin:x}-{self.end:x}").symlink_to(mapped)
        mount_id = fd_mount_id(mapped)
        if mountinfo is None:
            mountinfo = (f"{mount_id} 1 {mapping_major}:{mapping_minor} "
                         "/ /synthetic rw - "
                         "synthetic synthetic rw\n")
        (process / "mountinfo").write_text(mountinfo, encoding="utf-8")
        self.handshake = root / "mapped"
        self.handshake.write_text(
            f"pid={pid} starttime={starttime} endpoint=0x{address:x}\n",
            encoding="utf-8",
        )


class ReceiptCliTest(unittest.TestCase):
    def run_mapping(self, proc, expected, source=None, after_root=None):
        command = [
            "python3", "-I", str(RECEIPT), "mapping",
            "--proc-root", str(proc.root), "--handshake", str(proc.handshake),
            "--expected-file", str(expected),
        ]
        if source is not None:
            command += ["--source-file", str(source)]
        if after_root is not None:
            command += ["--after-proc-root", str(after_root)]
        return subprocess.run(command, cwd=ROOT, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=False)

    def test_pins_addressed_executable_mapping_and_hashes_open_object(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = base / "source.so"
            source.write_bytes(b"source-provider")
            private = base / "private.so"
            private.write_bytes(b"private-copy")
            proc = SyntheticProc(base / "proc", private)
            result = self.run_mapping(proc, private, source)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(result.stdout)
            info = private.stat()
            self.assertEqual(receipt["pid"], 4321)
            self.assertEqual(receipt["starttime"], 777)
            self.assertEqual(receipt["endpoint_address"], "0x7f000123")
            self.assertEqual(receipt["mapping"]["perms"], "r-xp")
            self.assertEqual(receipt["pinned"]["ino"], info.st_ino)
            self.assertEqual(receipt["pinned"]["sha256"], digest(private))
            self.assertEqual(receipt["expected"]["sha256"], digest(private))
            self.assertEqual(receipt["source"]["sha256"], digest(source))
            self.assertEqual(receipt["maps_before_sha256"],
                             receipt["maps_after_sha256"])

    def test_hardlink_alias_to_same_physical_copy_is_accepted(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            alias = base / "alias.so"
            os.link(private, alias)
            proc = SyntheticProc(base / "proc", private, path=str(alias))
            result = self.run_mapping(proc, alias)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["pinned"]["ino"],
                             private.stat().st_ino)

    def test_same_path_bytes_on_replacement_inode_are_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            mapped = base / "mapped.so"
            mapped.write_bytes(b"same-bytes")
            replacement = base / "expected.so"
            replacement.write_bytes(b"same-bytes")
            proc = SyntheticProc(base / "proc", mapped, path=str(replacement))
            result = self.run_mapping(proc, replacement)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected copy identity", result.stderr)

    def test_btrfs_device_domains_are_bridged_through_target_mountinfo(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            proc = SyntheticProc(base / "proc", private, mapping_dev="0:23")
            result = self.run_mapping(proc, private)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["mapping_identity"]["dev"], [0, 0x23])
            self.assertEqual(receipt["mapping_identity"]["ino"],
                             private.stat().st_ino)
            self.assertEqual(receipt["opened_file_identity"]["dev"], [
                os.major(private.stat().st_dev), os.minor(private.stat().st_dev)])
            self.assertNotEqual(receipt["mapping_identity"]["dev"],
                                receipt["opened_file_identity"]["dev"])
            self.assertEqual(receipt["opened_mapping_identity"]["dev"],
                             [0, 0x23])
            self.assertEqual(receipt["opened_mapping_identity"]["ino"],
                             private.stat().st_ino)
            self.assertEqual(receipt["mapping_bridge"]["kind"],
                             "map_files_fdinfo_target_mountinfo")
            receipt_path = base / "receipt.json"
            receipt_path.write_text(result.stdout, encoding="utf-8")
            source = base / "source.so"
            source.write_bytes(private.read_bytes())
            observer = base / "observer"
            observer.write_bytes(b"observer")
            metadata = subprocess.run([
                "python3", "-I", str(RECEIPT), "metadata",
                "--receipt", str(receipt_path), "--observer", str(observer),
                "--source-file", str(source), "--copy-file", str(private),
            ], cwd=ROOT, text=True, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, check=False)
            self.assertEqual(metadata.returncode, 0, metadata.stderr)
            joined = json.loads(metadata.stdout)["workload_module_identity"][0]
            self.assertEqual(joined["dev"], [0, 0x23])
            self.assertEqual(joined["ino"], private.stat().st_ino)
            self.assertEqual(joined["sha256"], digest(private))
            self.assertTrue(joined["report_identity_associated"])
            self.assertEqual(joined["report_identity_bridge"][
                "opened_file_identity"]["dev"], receipt[
                    "opened_file_identity"]["dev"])

    def test_same_domain_mapping_remains_associated(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            info = private.stat()
            dev = f"{os.major(info.st_dev):x}:{os.minor(info.st_dev):x}"
            proc = SyntheticProc(base / "proc", private, mapping_dev=dev)
            result = self.run_mapping(proc, private)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["mapping_identity"], {
                "dev": [os.major(info.st_dev), os.minor(info.st_dev)],
                "ino": info.st_ino,
            })
            self.assertEqual(receipt["mapping_identity"], {
                "dev": receipt["opened_mapping_identity"]["dev"],
                "ino": receipt["opened_mapping_identity"]["ino"],
            })

    def test_target_mountinfo_not_observer_mountinfo_defines_mapping_device(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            actual = private.stat()
            self.assertNotEqual([os.major(actual.st_dev), os.minor(actual.st_dev)],
                                [0, 0x23])
            proc = SyntheticProc(base / "proc", private, mapping_dev="0:23")
            result = self.run_mapping(proc, private)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)[
                "opened_mapping_identity"]["dev"], [0, 0x23])

    def test_wrong_target_mount_device_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            mount_id = fd_mount_id(private)
            proc = SyntheticProc(
                base / "proc", private, mapping_dev="0:23",
                mountinfo=f"{mount_id} 1 0:36 / /x rw - x x rw\n")
            result = self.run_mapping(proc, private)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mountinfo identity disagrees", result.stderr)

    def test_mountinfo_missing_duplicate_malformed_partial_and_overlimit_fail(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            mount_id = fd_mount_id(private)
            cases = {
                "missing": "999999 1 0:23 / /x rw - x x rw\n",
                "duplicate": (f"{mount_id} 1 0:35 / /a rw - x x rw\n"
                              f"{mount_id} 1 0:35 / /b rw - x x rw\n"),
                "malformed": f"{mount_id} 1 not-a-device / /x rw - x x rw\n",
                "short": f"{mount_id} 1 0:35\n",
                "missing separator": (
                    f"{mount_id} 1 0:35 / /x rw synthetic source rw\n"),
                "partial": f"{mount_id} 1 0:35 / /x rw - x x rw",
                "overlimit": "x" * (RECEIPT_NS["MAX_MOUNTINFO_BYTES"] + 1),
            }
            for name, table in cases.items():
                with self.subTest(name=name):
                    proc = SyntheticProc(base / name, private,
                                         mapping_dev="0:23", mountinfo=table)
                    result = self.run_mapping(proc, private)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("mountinfo", result.stderr)

    def test_missing_map_files_pin_is_unknown(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            proc = SyntheticProc(base / "proc", private)
            (proc.root / str(proc.pid) / "map_files" /
             f"{proc.begin:x}-{proc.end:x}").unlink()
            result = self.run_mapping(proc, private)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("map_files", result.stderr)

    def test_non_executable_address_mapping_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            proc = SyntheticProc(base / "proc", private, perms="r--p")
            result = self.run_mapping(proc, private)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("executable mappings", result.stderr)

    def test_pid_birth_change_between_snapshots_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            before = SyntheticProc(base / "before", private, starttime=777)
            after = SyntheticProc(base / "after", private, starttime=778)
            result = self.run_mapping(before, private, after_root=after.root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("birth identity changed", result.stderr)

    def test_mount_namespace_change_between_snapshots_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            before = SyntheticProc(base / "before", private)
            after = SyntheticProc(base / "after", private)
            result = self.run_mapping(before, private, after_root=after.root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mount namespace changed", result.stderr)

    def test_map_files_descriptor_is_retained_through_after_snapshot(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            proc = SyntheticProc(base / "proc", private)
            real_identity = RECEIPT_NS["identity_from_fd"]
            real_read_maps = RECEIPT_NS["read_maps"]
            pin = {"fd": None}
            reads = {"count": 0}

            def identity(fd, path):
                if "map_files" in str(path):
                    pin["fd"] = fd
                return real_identity(fd, path)

            def read_maps(root, pid):
                reads["count"] += 1
                if reads["count"] == 2:
                    os.fstat(pin["fd"])
                return real_read_maps(root, pid)

            args = argparse.Namespace(
                proc_root=str(proc.root), after_proc_root=None,
                handshake=str(proc.handshake), expected_file=str(private),
                source_file=None)
            with mock.patch.dict(RECEIPT_NS["mapping_receipt"].__globals__, {
                    "identity_from_fd": identity, "read_maps": read_maps}):
                RECEIPT_NS["mapping_receipt"](args)
            with self.assertRaises(OSError):
                os.fstat(pin["fd"])

    def test_final_maps_read_is_bracketed_by_birth_and_namespace(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            private = base / "private.so"
            private.write_bytes(b"provider")
            for case in ("birth", "namespace"):
                with self.subTest(case=case):
                    proc = SyntheticProc(base / case, private)
                    real_identity = RECEIPT_NS["identity_from_fd"]
                    real_read_maps = RECEIPT_NS["read_maps"]
                    pin = {"fd": None}
                    reads = {"count": 0}

                    def identity(fd, path):
                        if "map_files" in str(path):
                            pin["fd"] = fd
                        return real_identity(fd, path)

                    def raced_maps(root, pid):
                        reads["count"] += 1
                        if reads["count"] == 2:
                            if case == "birth":
                                (proc.root / str(pid) / "stat").write_text(
                                    proc_stat(pid, proc.starttime + 1),
                                    encoding="utf-8")
                            else:
                                replacement = (proc.root / str(pid) / "ns" /
                                               "replacement")
                                replacement.write_text("replacement namespace\n",
                                                       encoding="utf-8")
                                os.replace(replacement, proc.root / str(pid) /
                                           "ns" / "mnt")
                        return real_read_maps(root, pid)

                    args = argparse.Namespace(
                        proc_root=str(proc.root), after_proc_root=None,
                        handshake=str(proc.handshake),
                        expected_file=str(private), source_file=None)
                    with mock.patch.dict(
                            RECEIPT_NS["mapping_receipt"].__globals__, {
                                "identity_from_fd": identity,
                                "read_maps": raced_maps}):
                        with self.assertRaisesRegex(
                                RECEIPT_NS["ReceiptError"],
                                "birth identity changed|mount namespace changed"):
                            RECEIPT_NS["mapping_receipt"](args)
                    with self.assertRaises(OSError):
                        os.fstat(pin["fd"])

    def test_metadata_rejects_forged_mapping_bridge(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = base / "source.so"
            private = base / "private.so"
            observer = base / "observer"
            source.write_bytes(b"provider")
            private.write_bytes(b"provider")
            observer.write_bytes(b"observer")
            proc = SyntheticProc(base / "proc", private)
            mapping = self.run_mapping(proc, private, source)
            self.assertEqual(mapping.returncode, 0, mapping.stderr)
            original = json.loads(mapping.stdout)
            for name, mutate in (
                    ("opened identity", lambda value: value[
                        "opened_mapping_identity"].update(dev=[9, 9])),
                    ("exact range", lambda value: value[
                        "mapping_bridge"].update(range="1-2")),
                    ("non executable", lambda value: value[
                        "mapping"].update(perms="r--p")),
                    ("endpoint outside", lambda value: value.update(
                        endpoint_address="0x1"))):
                with self.subTest(name=name):
                    receipt = json.loads(json.dumps(original))
                    mutate(receipt)
                    receipt_path = base / "receipt.json"
                    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                    result = subprocess.run([
                        "python3", "-I", str(RECEIPT), "metadata",
                        "--receipt", str(receipt_path),
                        "--observer", str(observer),
                        "--source-file", str(source),
                        "--copy-file", str(private),
                    ], cwd=ROOT, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("mapping bridge", result.stderr)

    def test_metadata_wires_receipt_private_copy_and_observer_sha(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = base / "source.so"
            source.write_bytes(b"provider-bytes")
            private = base / "private.so"
            private.write_bytes(b"provider-bytes")
            observer_source = base / "observer-source"
            observer_source.write_bytes(b"observer")
            observer = base / "observer-copy"
            observer.write_bytes(b"observer")
            proc = SyntheticProc(base / "proc", private)
            mapping = self.run_mapping(proc, private, source)
            self.assertEqual(mapping.returncode, 0, mapping.stderr)
            receipt_path = base / "receipt.json"
            receipt_path.write_text(mapping.stdout, encoding="utf-8")
            result = subprocess.run([
                "python3", "-I", str(RECEIPT), "metadata",
                "--receipt", str(receipt_path), "--observer", str(observer),
                "--observer-source", str(observer_source),
                "--source-file", str(source), "--copy-file", str(private),
            ], cwd=ROOT, text=True, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads(result.stdout)
            identity = metadata["workload_module_identity"]
            self.assertEqual(len(identity), 1)
            self.assertEqual(identity[0]["ino"], private.stat().st_ino)
            self.assertEqual(identity[0]["sha256"], digest(private))
            self.assertTrue(identity[0]["report_identity_associated"])
            self.assertEqual(metadata["observer_binary_identity"]["sha256"],
                             digest(observer))
            self.assertEqual(metadata["observer_source_identity"]["sha256"],
                             digest(observer_source))
            self.assertNotEqual(metadata["observer_source_identity"]["ino"],
                                metadata["observer_binary_identity"]["ino"])
            self.assertEqual(metadata["provider_copy"]["source"]["sha256"],
                             digest(source))
            identity_path = base / "observer-identity.json"
            identity_path.write_text(json.dumps(
                metadata["observer_binary_identity"]), encoding="utf-8")
            observer.write_bytes(b"replacement")
            changed = subprocess.run([
                "python3", "-I", str(RECEIPT), "verify-file",
                "--identity", str(identity_path), "--path", str(observer),
            ], cwd=ROOT, text=True, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(changed.returncode, 0)
            self.assertIn("file identity changed", changed.stderr)


class OwnedChildContractTest(unittest.TestCase):
    def test_real_child_stays_gated_while_mapping_receipt_is_collected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            provider_c = base / "provider.c"
            provider_c.write_text(r'''
typedef unsigned long U;
static U ok(void *p) { (void)p; return 0; }
static U slots(unsigned char token, U *slots, U *count) {
    (void)token; if (slots && *count) slots[0] = 1; *count = 1; return 0;
}
static U open_session(U slot, U flags, void *a, void *b, U *session) {
    (void)slot; (void)flags; (void)a; (void)b; *session = 9; return 0;
}
static U close_session(U session) { (void)session; return 0; }
static U random_bytes(U session, unsigned char *out, U length) {
    (void)session; while (length--) *out++ = 7; return 0;
}
struct table_layout { unsigned char version[2]; unsigned char reserved[6]; void *functions[65]; };
static struct table_layout table;
__attribute__((constructor)) static void init(void) {
    table.version[0] = 2; table.version[1] = 40;
    table.functions[0] = ok; table.functions[1] = ok; table.functions[4] = slots;
    table.functions[12] = open_session; table.functions[13] = close_session;
    table.functions[64] = random_bytes;
}
U C_GetFunctionList(void **out) { *out = &table; return 0; }
''', encoding="utf-8")
            provider = base / "provider.so"
            workload = base / "workload"
            subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o",
                            str(provider), str(provider_c)], check=True)
            subprocess.run(["gcc", "-O0", "-Wall", "-Wextra", "-Werror",
                            "-o", str(workload), str(WORKLOAD_SOURCE), "-ldl"],
                           check=True)
            ready, mapped = base / "ready", base / "mapped"
            go, receipt_ready = base / "go", base / "receipt-ready"
            publish_gate = base / "publish-go"
            environment = dict(os.environ)
            environment["P11SCOPE_MEASURE_PUBLISH_GATE"] = str(publish_gate)
            child = subprocess.Popen([
                str(workload), str(provider), "1", "0", "1",
                str(ready), str(go), str(mapped), str(receipt_ready),
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
               env=environment)
            try:
                deadline = time.monotonic() + 5
                temporary = []
                while time.monotonic() < deadline:
                    temporary = list(base.glob("mapped.tmp.*"))
                    if temporary:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(temporary), 1)
                self.assertFalse(mapped.exists(),
                                 "destination became visible before atomic publish")
                self.assertRegex(temporary[0].read_text(encoding="utf-8"),
                                 r"^pid=\d+ starttime=\d+ endpoint=0x[0-9a-f]+\n$")
                publish_gate.touch()
                while time.monotonic() < deadline and not mapped.exists():
                    time.sleep(0.01)
                self.assertTrue(mapped.exists(), child.stderr.read() if child.poll() else "")
                result = subprocess.run([
                    "python3", "-I", str(RECEIPT), "mapping",
                    "--handshake", str(mapped), "--expected-file", str(provider),
                ], cwd=ROOT, text=True, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, check=False)
                if result.returncode != 0 and re.search(
                        r"map_files pin permission denied \(errno=(?:1|13)\)",
                        result.stderr):
                    self.skipTest("host denies unprivileged /proc/PID/map_files pin")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(child.poll(), "workload exited before receipt release")
                receipt_ready.touch()
                go.touch()
                stdout, stderr = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0, stderr)
                self.assertIn('TRUTH {"C_GenerateRandom": 1', stdout)
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()


class ProcessCustodyTest(unittest.TestCase):
    def test_receipt_owner_ids_require_canonical_numeric_values(self):
        self.assertEqual(SUPERVISOR_NS["numeric_id"]("0"), 0)
        self.assertEqual(SUPERVISOR_NS["numeric_id"]("4294967294"),
                         4294967294)
        for value in ("-1", "+1", "1.0", "root", "4294967295"):
            with self.subTest(value=value), self.assertRaises(
                    argparse.ArgumentTypeError):
                SUPERVISOR_NS["numeric_id"](value)

    def test_adopted_batch_stops_at_same_absolute_deadline(self):
        clock = [0.0]
        acquired = []

        def monotonic():
            return clock[0]

        def acquire(pid, deadline=None):
            del deadline
            acquired.append(pid)
            clock[0] += 1.0
            return {"pid": pid, "starttime": pid + 10,
                    "ppid": 1, "state": "Z", "pidfd": pid + 100}

        args = type("Args", (), {"root_group": False,
                                  "receipt_helper": str(RECEIPT)})()
        receipt = {}
        with mock.patch.dict(SUPERVISOR_NS["settle_adopted"].__globals__, {
            "direct_children": lambda pid, deadline=None: set(range(1, 13)),
            "acquire_direct_child": acquire,
        }), mock.patch.object(SUPERVISOR_NS["time"], "monotonic",
                             side_effect=monotonic), \
             mock.patch.object(SUPERVISOR_NS["select"], "select",
                               return_value=([1], [], [])), \
             mock.patch.object(SUPERVISOR_NS["os"], "waitpid",
                               return_value=(1, 0)), \
             mock.patch.object(SUPERVISOR_NS["os"], "close"):
            with self.assertRaisesRegex(TimeoutError, "deadline"):
                SUPERVISOR_NS["settle_adopted"](
                    args, signal.SIGKILL, 2.0, receipt)
        self.assertLessEqual(len(acquired), 2, acquired)
        self.assertTrue(receipt["unresolved"])

    def test_expired_real_batch_kills_every_acquired_child_without_new_census(self):
        children = []
        clock = [0.0]
        census_calls = []
        real_acquire = SUPERVISOR_NS["acquire_direct_child"]

        def acquire(pid, deadline=None):
            owned = real_acquire(pid, deadline)
            clock[0] += 1.0
            return owned

        def census(pid, deadline=None):
            census_calls.append((pid, deadline, clock[0]))
            return {child.pid for child in children}

        try:
            for _ in range(3):
                children.append(subprocess.Popen([
                    "python3", "-c",
                    "import os,signal,time; os.setsid(); "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
                ]))
            time.sleep(0.05)
            receipt = {}
            with mock.patch.dict(
                    SUPERVISOR_NS["settle_adopted"].__globals__, {
                        "direct_children": census,
                        "acquire_direct_child": acquire,
                        "time": types.SimpleNamespace(monotonic=lambda: clock[0]),
                    }):
                with self.assertRaisesRegex(TimeoutError, "deadline"):
                    SUPERVISOR_NS["settle_adopted"](
                        types.SimpleNamespace(), signal.SIGKILL, 2.0, receipt)
            for child in children[:2]:
                self.assertEqual(child.wait(timeout=2), -signal.SIGKILL)
            self.assertIsNone(children[2].poll())
            self.assertTrue(census_calls, census_calls)
            self.assertTrue(all(call[2] < 2.0 for call in census_calls),
                            census_calls)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=2)

    def test_helper_diagnostics_are_truncated_at_explicit_bound(self):
        with tempfile.TemporaryDirectory() as raw:
            helper = Path(raw) / "helper.py"
            helper.write_text(
                "import sys\nprint('x' * 70000)\nprint('y' * 70000, file=sys.stderr)\n",
                encoding="utf-8",
            )
            receipt = {"helper_attempts": [], "helper_failed": False}
            errors = []
            args = types.SimpleNamespace(receipt_helper=str(helper))
            SUPERVISOR_NS["run_group_helper"](
                args, os.getpid(), 1, "KILL", time.monotonic() + 3,
                receipt, errors)
            attempt = receipt["helper_attempts"][0]
            self.assertEqual(len(attempt["stdout"].encode()), 65536)
            self.assertEqual(len(attempt["stderr"].encode()), 65536)
            self.assertTrue(attempt["stdout_truncated"])
            self.assertTrue(attempt["stderr_truncated"])
            self.assertEqual(attempt["stdout_captured_bytes"], 65536)
            self.assertEqual(attempt["stderr_captured_bytes"], 65536)

    def test_wrapper_diagnostic_requests_only_limit_plus_one(self):
        requested = []
        class Reader:
            def __enter__(self):
                return self
            def __exit__(self, *ignored):
                pass
            def read(self, size):
                requested.append(size)
                return b"e" * size
        text, truncated, captured = RECEIPT_NS["bounded_diagnostic"](
            "ignored", opener=lambda path, mode: Reader())
        self.assertEqual(requested, [4097])
        self.assertEqual(len(text.encode()), 4096)
        self.assertTrue(truncated)
        self.assertEqual(captured, 4096)

    def test_wrapper_helper_failure_remains_failed_after_successful_retry(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            receipt = base / "receipt.json"
            result = base / "result.json"
            error = base / "error.log"
            receipt.write_text(json.dumps({"terminal_proof": True,
                                           "cleanup_ok": True,
                                           "settled": True}))
            error.write_text("first failed")
            result.write_text(json.dumps({"schema": "p11scope/wrapper-settlement/v1",
                                          "pid": 99, "starttime": 100,
                                          "terminal": False,
                                          "signals": [],
                                          "signal_failures": []}))
            args = types.SimpleNamespace(
                receipt=str(receipt), result=str(result), error=str(error),
                helper_status=42, reaped=False, wrapper_exit=0,
                pid=99, starttime=100, owner_failed=False)
            RECEIPT_NS["record_wrapper_cleanup"](args)
            error.write_text("")
            result.write_text(json.dumps({"schema": "p11scope/wrapper-settlement/v1",
                                          "pid": 99, "starttime": 100,
                                          "terminal": True,
                                          "signals": [],
                                          "signal_failures": []}))
            args.helper_status = 0
            args.reaped = True
            RECEIPT_NS["record_wrapper_cleanup"](args)
            record = json.loads(receipt.read_text())
            self.assertTrue(record["outer_wrapper_cleanup_failed"])
            self.assertEqual(len(record["outer_wrapper_cleanup_attempts"]), 2)
            self.assertTrue(record["outer_wrapper_cleanup"]["terminal"])
            self.assertTrue(record["outer_wrapper_cleanup"]["reaped"])

    def test_wrapper_signal_failure_remains_failed_after_successful_retry(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            receipt = base / "receipt.json"
            result = base / "result.json"
            error = base / "error.log"
            receipt.write_text("{}")
            error.write_text("")
            result.write_text(json.dumps({
                "schema": "p11scope/wrapper-settlement/v1",
                "pid": 99, "starttime": 100,
                "terminal": False, "signals": [],
                "signal_failures": [{"signal": "SIGKILL", "error": "EPERM"}],
            }))
            args = types.SimpleNamespace(
                receipt=str(receipt), result=str(result), error=str(error),
                helper_status=0, reaped=False, wrapper_exit=0,
                pid=99, starttime=100, owner_failed=False)
            RECEIPT_NS["record_wrapper_cleanup"](args)
            result.write_text(json.dumps({"schema": "p11scope/wrapper-settlement/v1",
                                          "pid": 99, "starttime": 100,
                                          "terminal": True,
                                          "signals": [],
                                          "signal_failures": []}))
            args.reaped = True
            RECEIPT_NS["record_wrapper_cleanup"](args)
            record = json.loads(receipt.read_text())
            self.assertTrue(record["outer_wrapper_cleanup_failed"])
            self.assertEqual(record["outer_wrapper_cleanup_attempts"][0]
                             ["signal_failures"][0]["signal"], "SIGKILL")

    def test_signal_failure_does_not_skip_other_retained_handles(self):
        handles = [
            {"pid": 11, "pidfd": 111},
            {"pid": 12, "pidfd": 112},
            {"pid": 13, "pidfd": 113},
        ]
        calls = []
        errors = []

        def send(fd, sig):
            calls.append((fd, sig))
            if fd == 112:
                raise PermissionError("injected")

        SUPERVISOR_NS["signal_retained"](
            handles, signal.SIGKILL, errors, send=send)
        self.assertEqual([fd for fd, _ in calls], [111, 112, 113])
        self.assertEqual(errors[0]["pid"], 12)

    def test_adopted_cleanup_records_failed_handle_and_reaps_others(self):
        live = {11, 12}
        closed = []

        def acquire(pid, deadline=None):
            del deadline
            return {"pid": pid, "starttime": pid + 10,
                    "ppid": 1, "state": "S", "pidfd": pid + 100}

        def signal_all(handles, sig, errors):
            del sig
            for owned in handles:
                if owned["pid"] == 11:
                    owned["signal_failed"] = True
                    errors.append({"phase": "signal", "pid": 11,
                                   "error": "injected"})

        def ready(readers, writes, errors, timeout):
            del writes, errors, timeout
            return ([fd for fd in readers if fd == 112], [], [])

        def waitpid(pid, flags):
            del flags
            live.discard(pid)
            return pid, 9

        args = type("Args", (), {})()
        receipt = {}
        with mock.patch.dict(SUPERVISOR_NS["settle_adopted"].__globals__, {
            "direct_children": lambda pid, deadline=None: set(live),
            "acquire_direct_child": acquire,
            "signal_retained": signal_all,
        }), mock.patch.object(SUPERVISOR_NS["select"], "select",
                             side_effect=ready), \
             mock.patch.object(SUPERVISOR_NS["os"], "waitpid",
                               side_effect=waitpid), \
             mock.patch.object(SUPERVISOR_NS["os"], "close",
                               side_effect=closed.append):
            SUPERVISOR_NS["settle_adopted"](
                args, signal.SIGKILL, time.monotonic() + 1, receipt)
        self.assertEqual([item["pid"] for item in receipt["reaped"]], [12])
        self.assertEqual(receipt["unresolved"][0]["pid"], 11)
        self.assertEqual(sorted(closed), [111, 112])
    def process_identity(self, pid):
        result = subprocess.run([
            "python3", "-I", str(RECEIPT), "process", "--pid", str(pid),
        ], cwd=ROOT, text=True, stdout=subprocess.PIPE,
           stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_root_exits_on_term_but_retained_child_is_killed(self):
        with tempfile.TemporaryDirectory() as raw:
            child_file = Path(raw) / "child.pid"
            child_tmp = child_file.with_suffix(".pid.tmp")
            child_code = (
                "import os,pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"tmp=pathlib.Path({str(child_tmp)!r}); "
                "tmp.write_text(str(os.getpid())); "
                f"os.replace(tmp,{str(child_file)!r}); "
                "time.sleep(60)"
            )
            parent_code = (
                "import signal,subprocess,sys,time; "
                "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
                f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                "time.sleep(60)"
            )
            process = subprocess.Popen(["python3", "-c", parent_code])
            starttime = self.process_identity(process.pid)["starttime"]
            child_identity = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not child_file.exists():
                    time.sleep(0.01)
                self.assertTrue(child_file.exists())
                child_pid = int(child_file.read_text())
                child_identity = (
                    child_pid, self.process_identity(child_pid)["starttime"])
                result = subprocess.run([
                    "python3", "-I", str(RECEIPT), "teardown",
                    "--pid", str(process.pid), "--starttime", str(starttime),
                    "--first-signal", "TERM", "--term-timeout", "0.1",
                    "--kill-timeout", "1",
                ], cwd=ROOT, text=True, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, check=False, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                proof = json.loads(result.stdout)
                self.assertIn(child_pid, proof["targets"])
                self.assertIn(child_pid, proof["escalated"])
                process.wait(timeout=2)
            finally:
                identities = [(process.pid, starttime)]
                if child_identity is not None:
                    identities.append(child_identity)
                for pid, birth in identities:
                    subprocess.run([
                        "python3", "-I", str(RECEIPT), "teardown",
                        "--pid", str(pid), "--starttime", str(birth),
                        "--first-signal", "KILL", "--kill-timeout", "1",
                    ], cwd=ROOT, text=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False, timeout=3)
                if process.poll() is None:
                    process.wait(timeout=2)

    def test_wrong_root_birth_is_refused_without_signal(self):
        process = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"])
        try:
            starttime = self.process_identity(process.pid)["starttime"]
            refused = subprocess.run([
                "python3", "-I", str(RECEIPT), "teardown", "--pid", str(process.pid),
                "--starttime", str(starttime + 1), "--first-signal", "TERM",
            ], cwd=ROOT, text=True, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIsNone(process.poll(), "wrong birth identity signalled the child")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)

    def test_descendant_birth_change_during_acquisition_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            root, child = 4100, 4101
            for pid, birth in ((root, 10), (child, 20)):
                (proc / str(pid) / "task" / str(pid)).mkdir(parents=True)
                (proc / str(pid) / "stat").write_text(proc_stat(pid, birth))
                (proc / str(pid) / "task" / str(pid) / "children").write_text(
                    f"{child}\n" if pid == root else "")
            opened = []
            def pidfd_open(pid, flags):
                del flags
                fd = os.open("/dev/null", os.O_RDONLY)
                opened.append(fd)
                if pid == child:
                    (proc / str(child) / "stat").write_text(proc_stat(child, 21))
                return fd
            with mock.patch.object(RECEIPT_NS["os"], "pidfd_open",
                                   side_effect=pidfd_open), \
                 mock.patch.dict(RECEIPT_NS["acquire_process_tree"].__globals__,
                                 {"_pidfd_terminal": lambda fd: False}):
                with self.assertRaisesRegex(RECEIPT_NS["ReceiptError"],
                                            "birth identity changed"):
                    RECEIPT_NS["acquire_process_tree"](str(proc), root, 10)
            for fd in opened:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def test_injected_signal_and_wait_failure_is_bounded(self):
        handles = [{"pid": 1, "starttime": 1, "parent": None, "pidfd": 99}]
        calls = []
        def failed_send(handle, sig):
            calls.append((handle["pid"], sig))
            raise OSError("injected signal failure")
        before = time.monotonic()
        with self.assertRaisesRegex(RECEIPT_NS["ReceiptError"],
                                    "not terminal after KILL"):
            RECEIPT_NS["teardown_custody"](
                handles, signal.SIGTERM, 0.01, 0.01,
                send=failed_send, wait=lambda owned, timeout: list(owned))
        self.assertLess(time.monotonic() - before, 0.2)
        self.assertEqual([sig for _, sig in calls],
                         [signal.SIGTERM, signal.SIGKILL])

    def test_acquisition_child_churn_obeys_total_deadline(self):
        handles = []
        next_pid = iter(range(5001, 1000000))
        snapshots = {}
        def children(proc_root, pid):
            del proc_root
            time.sleep(0.002)
            child, uses = snapshots[pid] if pid in snapshots else (next(next_pid), 0)
            snapshots[pid] = (child, uses + 1)
            if uses + 1 == 2:
                snapshots.pop(pid)
            return [child]
        def birth(proc_root, pid):
            del proc_root
            return pid + 100
        def opened(pid, flags):
            del pid, flags
            fd = os.open("/dev/null", os.O_RDONLY)
            handles.append(fd)
            return fd
        with mock.patch.object(RECEIPT_NS["os"], "pidfd_open", side_effect=opened), \
             mock.patch.dict(RECEIPT_NS["acquire_process_tree"].__globals__,
                             {"direct_children": children, "read_birth": birth,
                              "_pidfd_terminal": lambda fd: False}):
            before = time.monotonic()
            with self.assertRaisesRegex(RECEIPT_NS["ReceiptError"], "deadline"):
                RECEIPT_NS["acquire_process_tree"](
                    "/proc", 5000, 5100, deadline=before + 0.03)
            self.assertLess(time.monotonic() - before, 0.2)
        for fd in handles:
            try:
                os.close(fd)
            except OSError:
                pass

    def test_recycled_intermediate_parent_is_not_revisited(self):
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            root, parent = 6100, 6101
            for pid, birth in ((root, 10), (parent, 20)):
                (proc / str(pid) / "task" / str(pid)).mkdir(parents=True)
                (proc / str(pid) / "stat").write_text(proc_stat(pid, birth))
                (proc / str(pid) / "task" / str(pid) / "children").write_text(
                    f"{parent}\n" if pid == root else "")
            calls = {parent: 0}
            real_children = RECEIPT_NS["direct_children"]
            def children(proc_root, pid):
                result = real_children(proc_root, pid)
                if pid == parent:
                    calls[parent] += 1
                    if calls[parent] == 1:
                        (proc / str(parent) / "stat").write_text(
                            proc_stat(parent, 21))
                return result
            opened = []
            def pidfd_open(pid, flags):
                del pid, flags
                fd = os.open("/dev/null", os.O_RDONLY)
                opened.append(fd)
                return fd
            with mock.patch.object(RECEIPT_NS["os"], "pidfd_open",
                                   side_effect=pidfd_open), \
                 mock.patch.dict(RECEIPT_NS["acquire_process_tree"].__globals__,
                                 {"direct_children": children,
                                  "_pidfd_terminal": lambda fd: False}):
                with self.assertRaisesRegex(RECEIPT_NS["ReceiptError"],
                                            "retained parent.*identity"):
                    RECEIPT_NS["acquire_process_tree"](
                        str(proc), root, 10, deadline=time.monotonic() + 1)
            for fd in opened:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def test_vanished_group_census_member_does_not_abandon_live_root(self):
        process = subprocess.Popen(
            ["python3", "-c",
             "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"],
            preexec_fn=os.setsid,
        )
        birth = RECEIPT_NS["read_birth"]("/proc", process.pid)
        real_scan = RECEIPT_NS["_scan_group"]
        stale = {"pid": 99999999, "starttime": 1,
                 "pgrp": process.pid, "session": process.pid, "state": "S"}
        injected = False

        def scan(proc_root, leader, deadline):
            nonlocal injected
            records = real_scan(proc_root, leader, deadline)
            if not injected:
                injected = True
                records.append(stale)
            return records

        args = type("Args", (), {
            "proc_root": "/proc", "pid": process.pid, "starttime": birth,
            "first_signal": "KILL", "term_timeout": 0.1,
            "total_timeout": 2.0,
        })()
        try:
            with mock.patch.dict(RECEIPT_NS["settle_group"].__globals__,
                                 {"_scan_group": scan}):
                result = RECEIPT_NS["settle_group"](args)
            process.wait(timeout=1)
            self.assertIn(process.pid, result["targets"])
            self.assertEqual(process.returncode, -signal.SIGKILL)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


class VerifyGroupTest(unittest.TestCase):
    """verify-group names why a launch could not be verified."""

    PID = 4242
    BIRTH = 777

    def verify(self, proc_root, timeout=0.2):
        args = argparse.Namespace(proc_root=str(proc_root), pid=self.PID,
                                  starttime=self.BIRTH, timeout=timeout)
        return RECEIPT_NS["verify_group"](args)

    def write_stat(self, proc_root, *, state="S", pgrp=PID, session=PID):
        directory = Path(proc_root) / str(self.PID)
        directory.mkdir(exist_ok=True)
        tail = [state, "1", str(pgrp), str(session)] + ["0"] * 15
        tail += [str(self.BIRTH), "0"]
        (directory / "stat").write_text(
            f"{self.PID} (cmd) {' '.join(tail)}\n", encoding="utf-8")

    def test_live_private_session_leader_is_verified(self):
        with tempfile.TemporaryDirectory() as raw:
            self.write_stat(raw)
            self.assertEqual(self.verify(raw)["session"], self.PID)

    def test_exited_leader_fails_promptly_and_says_so(self):
        for state in (None, "Z", "X"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as raw:
                if state is not None:
                    self.write_stat(raw, state=state)
                started = time.monotonic()
                with self.assertRaisesRegex(
                    RECEIPT_NS["ReceiptError"],
                    "live private session group: leader exited before "
                    "verification",
                ):
                    self.verify(raw, timeout=30)
                self.assertLess(time.monotonic() - started, 5)

    def test_leader_outside_a_private_session_names_its_group(self):
        with tempfile.TemporaryDirectory() as raw:
            self.write_stat(raw, pgrp=1, session=1)
            with self.assertRaisesRegex(
                RECEIPT_NS["ReceiptError"],
                "live private session group: leader pgrp=1 session=1",
            ):
                self.verify(raw)

    def test_replaced_leader_birth_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            self.write_stat(raw)
            args = argparse.Namespace(proc_root=raw, pid=self.PID,
                                      starttime=self.BIRTH + 1, timeout=0.2)
            with self.assertRaisesRegex(
                RECEIPT_NS["ReceiptError"], "birth identity changed"
            ):
                RECEIPT_NS["verify_group"](args)


class ShellOwnedLifecycleTest(unittest.TestCase):
    def run_under_subreaper(self, command, timeout):
        # `timeout` is a harness cap (SLACK): it only bounds a hung case.
        timeout = slack(timeout)
        driver = r'''
import ctypes, json, os, select, signal, subprocess, sys, time
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
p = subprocess.Popen(["sh", "-c", sys.argv[2]], cwd=sys.argv[1],
                     text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
timed_out = False
try:
    out, err = p.communicate(timeout=float(sys.argv[3]))
except subprocess.TimeoutExpired as error:
    timed_out = True
    out = error.stdout or ""
    err = error.stderr or ""
    if isinstance(out, bytes): out = out.decode("utf-8", "replace")
    if isinstance(err, bytes): err = err.decode("utf-8", "replace")
    fd = os.pidfd_open(p.pid)
    signal.pidfd_send_signal(fd, signal.SIGKILL)
    os.close(fd)
    p.wait(timeout=2)
deadline = time.monotonic() + 3
reaped = []
while time.monotonic() < deadline:
    children = set()
    for path in __import__('pathlib').Path(f"/proc/{os.getpid()}/task").glob("*/children"):
        try: children.update(map(int, path.read_text().split()))
        except FileNotFoundError: pass
    if not children: break
    for pid in children:
        try:
            before = open(f"/proc/{pid}/stat").read().rsplit(") ", 1)[1].split()
            birth = int(before[19]); parent = int(before[1]); fd = os.pidfd_open(pid)
            after = open(f"/proc/{pid}/stat").read().rsplit(") ", 1)[1].split()
            if int(after[19]) != birth or int(after[1]) != os.getpid() or parent != os.getpid():
                os.close(fd); continue
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            select.select([fd], [], [], max(0, deadline-time.monotonic()))
            os.close(fd)
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited: reaped.append([pid, status])
        except (FileNotFoundError, ProcessLookupError, ChildProcessError): pass
print(json.dumps({"returncode": p.returncode, "timed_out": timed_out,
                  "stdout": out, "stderr": err, "reaped": reaped}))
'''
        result = subprocess.run(
            ["python3", "-c", driver, str(ROOT), command, str(timeout)],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=timeout + 6)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_terminal_inspection_error_is_unknown(self):
        with tempfile.TemporaryDirectory() as raw:
            helper = Path(raw) / "helper.py"
            helper.write_text(
                "import os,sys\n"
                "if sys.argv[1]=='inspect-process': raise SystemExit(42)\n"
                f"os.execv(sys.executable,[sys.executable,'-I',{str(RECEIPT)!r},*sys.argv[1:]])\n",
                encoding="utf-8")
            command = f'''
set -eu
. scripts/system-scope-owned.sh
birth=$(owned_process_starttime $$)
P11SCOPE_RECEIPT_HELPER={str(helper)!r}; export P11SCOPE_RECEIPT_HELPER
state=0; owned_wait_root_terminal $$ "$birth" 0 || state=$?
[ "$state" -eq 2 ]
'''
            result = subprocess.run(
                ["sh", "-c", command], cwd=ROOT, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=slack(3))
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)

    def test_helper_failure_still_settles_escaped_child_and_stays_sticky(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            helper = base / "receipt-helper"
            helper_child_file = base / "helper-child"
            helper.write_text(
                "import os,pathlib,subprocess,sys\n"
                "if sys.argv[1] in ('settle-group', 'teardown'):\n"
                " p=subprocess.Popen([sys.executable, '-c', "
                "'import os,signal,time; os.setsid(); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])\n"
                " pathlib.Path(os.environ['P11SCOPE_HELPER_CHILD_FILE']).write_text(str(p.pid))\n"
                " print('injected-helper-failure', file=sys.stderr); raise SystemExit(42)\n"
                f"os.execv(sys.executable, [sys.executable, '-I', {str(RECEIPT)!r}, *sys.argv[1:]])\n",
                encoding="utf-8",
            )
            child_file = base / "child"
            gate = base / "gate"
            command = f'''
set -u
cd {str(ROOT)!r}
P11SCOPE_RECEIPT_HELPER={str(helper)!r}
P11SCOPE_HELPER_CHILD_FILE={str(helper_child_file)!r}
export P11SCOPE_RECEIPT_HELPER
export P11SCOPE_HELPER_CHILD_FILE
. scripts/system-scope-owned.sh
parent_code='import os,signal,subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import os,signal,time; os.setsid(); signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"]); open(sys.argv[1],"w").write(str(p.pid));\nwhile not os.path.exists(sys.argv[2]): time.sleep(.01)'
owned_launch user - /dev/null /dev/null -- python3 -c "$parent_code" {str(child_file)!r} {str(gate)!r}
wrapper=$OWNED_PID; birth=$OWNED_STARTTIME; receipt=$OWNED_RECEIPT
owned_verify_launch "$wrapper" "$birth" "$receipt" || exit 20
for ignored in $(seq 1 {slack_polls(200)}); do [ -s {str(child_file)!r} ] && break; sleep .01; done
child=$(cat {str(child_file)!r})
touch {str(gate)!r}
finish=0; owned_finish "$wrapper" "$birth" "$receipt" {slack_whole(4)} || finish=$?
python3 -I - "$receipt" "$child" "$finish" <<'PY'
import json, pathlib, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
assert int(sys.argv[3]) != 0
assert not pathlib.Path(f"/proc/{{sys.argv[2]}}").exists()
assert record["terminal_proof"] is True
assert record["cleanup_ok"] is False
assert record["helper_failed"] is True
assert record["helper_attempts"][0]["exit"] == 42
assert record["unresolved"] == []
helper_child = pathlib.Path({str(helper_child_file)!r})
assert helper_child.exists()
assert not pathlib.Path(f"/proc/{{helper_child.read_text()}}").exists()
PY
'''
            result = subprocess.run(
                ["sh", "-c", command], cwd=ROOT, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=slack(15),
            )
            if child_file.exists():
                child = int(child_file.read_text())
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if helper_child_file.exists():
                helper_child = int(helper_child_file.read_text())
                try:
                    os.kill(helper_child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
    def run_escape_case(self, escape):
        command = f'''
set -u
cd {str(ROOT)!r}
. scripts/system-scope-owned.sh
child_file=$(mktemp)
gate=$(mktemp); rm -f "$gate"
parent_code='import os,signal,subprocess,sys,time; fn=getattr(os,sys.argv[3]); p=subprocess.Popen([sys.executable,"-c","import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"],preexec_fn=fn); open(sys.argv[1],"w").write(str(p.pid));\nwhile not os.path.exists(sys.argv[2]): time.sleep(.01)'
owned_launch user - /dev/null /dev/null -- python3 -c "$parent_code" "$child_file" "$gate" {escape!r}
root=$OWNED_PID; birth=$OWNED_STARTTIME; receipt=$OWNED_RECEIPT
owned_verify_launch "$root" "$birth" "$receipt" || exit 20
for ignored in $(seq 1 {slack_polls(200)}); do [ -s "$child_file" ] && break; sleep .01; done
child=$(cat "$child_file")
touch "$gate"
finish_rc=0; owned_finish "$root" "$birth" "$receipt" {slack_whole(4)} || finish_rc=$?
echo "child=$child finish=$finish_rc owned=$OWNED_EXIT"
rm -f "$child_file" "$gate"
'''
        result = subprocess.run(["sh", "-c", command], cwd=ROOT, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=slack(15))
        match = re.search(r"child=(\d+) finish=(\d+) owned=(\d+)", result.stdout)
        self.assertIsNotNone(match, result.stdout + result.stderr)
        child = int(match.group(1))
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(match.group(2), "0", result.stderr)
            self.assertFalse(Path(f"/proc/{child}").exists(), result.stderr)
        finally:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_finish_settles_setpgrp_descendant_after_root_exit(self):
        self.run_escape_case("setpgrp")

    def test_finish_settles_setsid_descendant_after_root_exit(self):
        self.run_escape_case("setsid")

    def test_native_sigkill_is_reported_as_shell_137(self):
        command = f'''
set -eux
cd {str(ROOT)!r}
. scripts/system-scope-owned.sh
gate=$(mktemp); rm -f "$gate"
code='import os,signal,sys,time;\nwhile not os.path.exists(sys.argv[1]): time.sleep(.01)\nos.kill(os.getpid(), signal.SIGKILL)'
owned_launch user - /dev/null /dev/null -- python3 -c "$code" "$gate"
root=$OWNED_PID; birth=$OWNED_STARTTIME; receipt=$OWNED_RECEIPT
owned_verify_launch "$root" "$birth" "$receipt"
touch "$gate"
owned_finish "$root" "$birth" "$receipt" {slack_whole(4)}
owned_command_outcome "$receipt"
python3 -I - "$receipt" "$OWNED_EXIT" "$OWNED_COMMAND_EXIT" "$OWNED_COMMAND_SIGNAL" <<'PY'
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
assert int(sys.argv[2]) == 137, sys.argv[2]
assert int(sys.argv[3]) == 137, sys.argv[3]
assert sys.argv[4] == "SIGKILL", sys.argv[4]
assert record["command_exit"] == -9, record
PY
rm -f "$gate"
'''
        result = subprocess.run(["sh", "-c", command], cwd=ROOT, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=slack(12))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_initial_receipt_failure_cleans_blocked_command(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            missing = base / "missing" / "receipt.json"
            executed = base / "executed"
            wrapper = base / "wrapper"
            command = [
                "python3", "-I", str(ROOT / "scripts/system-scope-supervisor.py"),
                "--receipt", str(missing), "--receipt-helper", str(RECEIPT),
                "--wrapper-identity", str(wrapper), "--",
                "python3", "-c",
                "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('ran'); time.sleep(60)",
                str(executed),
            ]
            process = subprocess.Popen(
                command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            birth = RECEIPT_NS["read_birth"]("/proc", process.pid)
            wrapper.write_text(f"{process.pid} {birth}\n")
            stdout, stderr = process.communicate(timeout=slack(5))
            result = subprocess.CompletedProcess(
                command, process.returncode, stdout, stderr)
            self.assertNotEqual(result.returncode, 0)
            time.sleep(0.05)
            self.assertFalse(executed.exists(), result.stderr)
            token = str(executed).encode()
            survivors = []
            for cmdline in Path("/proc").glob("[0-9]*/cmdline"):
                try:
                    if token in cmdline.read_bytes():
                        survivors.append(cmdline.parent.name)
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    pass
            self.assertEqual(survivors, [], result.stderr)

    def test_root_launch_tracks_distinct_wrapper_and_supervisor_without_sudo(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            fake_sudo = base / "sudo"
            fake_sudo.write_text(
                "#!/bin/sh\n[ \"$1\" = -n ] && shift\n"
                "case \"$1\" in --preserve-env=*) shift;; esac\n\"$@\" &\n"
                "child=$!\nwait \"$child\"\n",
                encoding="utf-8",
            )
            fake_sudo.chmod(0o755)
            command = f'''
set -eu
cd {str(ROOT)!r}
PATH={str(base)!r}:$PATH
export PATH
. scripts/system-scope-owned.sh
owned_launch root - /dev/null /dev/null -- python3 -c 'import time; time.sleep({slack_whole(10)})'
wrapper=$OWNED_PID; birth=$OWNED_STARTTIME; receipt=$OWNED_RECEIPT
owned_verify_launch "$wrapper" "$birth" "$receipt"
owned_finish "$wrapper" "$birth" "$receipt" 1
python3 -I - "$receipt" "$wrapper" <<'PY'
import json, os, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["outer_wrapper_pid"] == int(sys.argv[2])
assert record["supervisor_pid"] != record["outer_wrapper_pid"]
assert record["root_group"] is True
assert os.stat(sys.argv[1]).st_uid == os.getuid()
PY
'''
            result = subprocess.run(
                ["sh", "-c", command], cwd=ROOT, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=slack(12),
            )
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)

    def test_finish_bounds_and_kills_stalled_outer_wrapper(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            release = base / "command-release"
            fake_sudo = base / "sudo"
            fake_sudo.write_text(
                "#!/usr/bin/python3\n"
                "import os,signal,subprocess,sys,time\n"
                "args=sys.argv[1:]\n"
                "if args[:1] == ['-n']: args=args[1:]\n"
                "if args and args[0].startswith('--preserve-env='): args=args[1:]\n"
                "child=subprocess.Popen(args); child.wait()\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "while True: time.sleep(1)\n",
                encoding="utf-8",
            )
            fake_sudo.chmod(0o755)
            command = f'''
set -eu
PATH={str(base)!r}:$PATH; export PATH
. scripts/system-scope-owned.sh
owned_launch root - /dev/null /dev/null -- {held_command(release)}
wrapper=$OWNED_PID; birth=$OWNED_STARTTIME; receipt=$OWNED_RECEIPT
owned_verify_launch "$wrapper" "$birth" "$receipt"
touch {str(release)!r}
owned_finish "$wrapper" "$birth" "$receipt" {slack_whole(5)}
python3 -I - "$receipt" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r["outer_wrapper_cleanup"]["terminal"] is True
assert r["outer_wrapper_cleanup"]["escalated"] is True
assert r["outer_wrapper_cleanup"]["reaped"] is True
PY
'''
            result = self.run_under_subreaper(command, 12)
            self.assertFalse(result["timed_out"], result)
            self.assertEqual(result["returncode"], 0, result)

    def test_wrapper_identity_helper_failure_cannot_authorize_wait(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            marker = base / "wrapper-live.json"
            command_release = base / "command-release"
            fake_sudo = base / "sudo"
            fake_sudo.write_text(
                "#!/usr/bin/python3\n"
                "import json,os,pathlib,signal,subprocess,sys,time\n"
                "a=sys.argv[1:]\n"
                "if a[:1]==['-n']: a=a[1:]\n"
                "if a and a[0].startswith('--preserve-env='): a=a[1:]\n"
                "c=subprocess.Popen(a); c.wait()\n"
                f"pathlib.Path({str(marker)!r}).write_text(json.dumps({{'pid':os.getpid()}}))\n"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                "while True: time.sleep(1)\n",
                encoding="utf-8")
            fake_sudo.chmod(0o755)
            helper = base / "helper.py"
            helper.write_text(
                "import json,os,pathlib,sys\n"
                f"m=pathlib.Path({str(marker)!r})\n"
                "if sys.argv[1]=='process' and m.exists():\n"
                " r=json.loads(m.read_text())\n"
                " if int(sys.argv[sys.argv.index('--pid')+1])==r['pid']: raise SystemExit(42)\n"
                f"os.execv(sys.executable,[sys.executable,'-I',{str(RECEIPT)!r},*sys.argv[1:]])\n",
                encoding="utf-8")
            command = f'''
set -eu
PATH={str(base)!r}:$PATH; export PATH
P11SCOPE_RECEIPT_HELPER={str(helper)!r}; export P11SCOPE_RECEIPT_HELPER
. scripts/system-scope-owned.sh
owned_launch root - /dev/null /dev/null -- {held_command(command_release)}
wrapper=$OWNED_PID; birth=$OWNED_STARTTIME; receipt=$OWNED_RECEIPT
owned_verify_launch "$wrapper" "$birth" "$receipt"
touch {str(command_release)!r}
for ignored in $(seq 1 {slack_polls(300)}); do [ -s {str(marker)!r} ] && break; sleep .01; done
[ -s {str(marker)!r} ]
owned_finish "$wrapper" "$birth" "$receipt" 0
'''
            result = self.run_under_subreaper(command, 10)
            self.assertFalse(result["timed_out"], result)
            self.assertEqual(result["returncode"], 0, result)

    def run_sticky_wrapper_retry(self, failure):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            marker = base / "wrapper-live"
            release = base / "release"
            command_release = base / "command-release"
            fake_sudo = base / "sudo"
            fake_sudo.write_text(
                "#!/usr/bin/python3\n"
                "import pathlib,signal,subprocess,sys,time\n"
                "a=sys.argv[1:]\n"
                "if a[:1]==['-n']: a=a[1:]\n"
                "if a and a[0].startswith('--preserve-env='): a=a[1:]\n"
                "c=subprocess.Popen(a); c.wait()\n"
                f"pathlib.Path({str(marker)!r}).write_text('live')\n"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                f"while not pathlib.Path({str(release)!r}).exists(): time.sleep(.01)\n",
                encoding="utf-8")
            fake_sudo.chmod(0o755)
            injected = ("print('{\"terminal\":false,\"signals\":[],"
                        "\"signal_failures\":[{\"signal\":\"SIGKILL\","
                        "\"error\":\"injected\"}]}'); raise SystemExit(0)"
                        if failure == "signal" else
                        "print('injected helper failure',file=sys.stderr); raise SystemExit(42)")
            helper = base / "helper.py"
            helper.write_text(
                "import os,pathlib,sys\n"
                f"if sys.argv[1]=='settle-process' and not pathlib.Path({str(release)!r}).exists():\n"
                f" {injected}\n"
                f"os.execv(sys.executable,[sys.executable,'-I',{str(RECEIPT)!r},*sys.argv[1:]])\n",
                encoding="utf-8")
            command = f'''
set -eu
PATH={str(base)!r}:$PATH; export PATH
P11SCOPE_RECEIPT_HELPER={str(helper)!r}; export P11SCOPE_RECEIPT_HELPER
. scripts/system-scope-owned.sh
owned_launch root - /dev/null /dev/null -- {held_command(command_release)}
wrapper=$OWNED_PID; birth=$OWNED_STARTTIME; receipt=$OWNED_RECEIPT
owned_verify_launch "$wrapper" "$birth" "$receipt"
touch {str(command_release)!r}
for ignored in $(seq 1 {slack_polls(300)}); do [ -s {str(marker)!r} ] && break; sleep .01; done
first=0; owned_finish "$wrapper" "$birth" "$receipt" 0 || first=$?
touch {str(release)!r}
second=0; owned_finish "$wrapper" "$birth" "$receipt" 0 || second=$?
python3 -I - "$receipt" "$first" "$second" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert int(sys.argv[2]) != 0 and int(sys.argv[3]) != 0
assert r["outer_wrapper_cleanup_failed"] is True
assert len(r["outer_wrapper_cleanup_attempts"]) == 2
assert r["outer_wrapper_cleanup"]["terminal"] is True
assert r["outer_wrapper_cleanup"]["reaped"] is True
PY
'''
            result = self.run_under_subreaper(command, 10)
            self.assertFalse(result["timed_out"], result)
            self.assertEqual(result["returncode"], 0, result)

    def test_wrapper_helper_failure_is_sticky_across_cleanup_retry(self):
        self.run_sticky_wrapper_retry("helper")

    def test_wrapper_signal_failure_is_sticky_across_cleanup_retry(self):
        self.run_sticky_wrapper_retry("signal")

    def run_wrapper_protocol_retry(self, fault):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            marker = base / "wrapper-live"
            release = base / "release"
            command_release = base / "command-release"
            once = base / "once"
            read_log = base / "result-reads.jsonl"
            fake_sudo = base / "sudo"
            fake_sudo.write_text(
                "#!/usr/bin/python3\n"
                "import pathlib,signal,subprocess,sys,time\n"
                "a=sys.argv[1:]\n"
                "if a[:1]==['-n']: a=a[1:]\n"
                "if a and a[0].startswith('--preserve-env='): a=a[1:]\n"
                "c=subprocess.Popen(a); c.wait()\n"
                f"pathlib.Path({str(marker)!r}).write_text('live')\n"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                f"while not pathlib.Path({str(release)!r}).exists(): time.sleep(.01)\n",
                encoding="utf-8")
            fake_sudo.chmod(0o755)
            helper = base / "helper.py"
            helper.write_text(
                "import json,os,pathlib,runpy,subprocess,sys\n"
                f"real={str(RECEIPT)!r}; once=pathlib.Path({str(once)!r}); fault={fault!r}\n"
                "if sys.argv[1]=='settle-process' and not once.exists():\n"
                " once.write_text('1')\n"
                " pid=int(sys.argv[sys.argv.index('--pid')+1]); birth=int(sys.argv[sys.argv.index('--starttime')+1])\n"
                " if fault=='false-string': print(json.dumps({'schema':'p11scope/wrapper-settlement/v1','pid':pid,'starttime':birth,'terminal':'false','signals':[],'signal_failures':[]})); raise SystemExit(0)\n"
                " if fault=='nonobject': print(json.dumps(['not-an-object'])); raise SystemExit(0)\n"
                " if fault=='wrong-identity': print(json.dumps({'schema':'p11scope/wrapper-settlement/v1','pid':pid+1,'starttime':birth,'terminal':True,'signals':[],'signal_failures':[]})); raise SystemExit(0)\n"
                " if fault=='oversize':\n"
                "  p=subprocess.run([sys.executable,'-I',real,*sys.argv[1:]],stdout=subprocess.PIPE,check=True)\n"
                "  sys.stdout.buffer.write(p.stdout.rstrip()+b' '*70000+b'\\n'); raise SystemExit(0)\n"
                "runpy.run_path(real,run_name='__main__')\n",
                encoding="utf-8")
            if fault == "oversize":
                shim = base / "python3"
                shim.write_text(
                    "#!/usr/bin/python3\n"
                    "import builtins,json,os,runpy,sys\n"
                    "a=sys.argv[1:]; clean=a[1:] if a[:1]==['-I'] else a\n"
                    "if len(clean)>1 and clean[1] in ('validate-wrapper-result','record-wrapper-cleanup'):\n"
                    " original=builtins.open\n"
                    " class Seen:\n"
                    "  def __init__(self,stream,path): self.stream=stream; self.path=path\n"
                    "  def read(self,size=-1):\n"
                    "   data=self.stream.read(size)\n"
                    f"   if 'p11scope-wrapper-result.' in str(self.path): original({str(read_log)!r},'a').write(json.dumps({{'request':size,'returned':len(data)}})+'\\n')\n"
                    "   return data\n"
                    "  def __enter__(self): self.stream.__enter__(); return self\n"
                    "  def __exit__(self,*a): return self.stream.__exit__(*a)\n"
                    "  def __getattr__(self,n): return getattr(self.stream,n)\n"
                    " def opened(path,*a,**kw): return Seen(original(path,*a,**kw),path)\n"
                    " builtins.open=opened; sys.argv=clean; runpy.run_path(clean[0],run_name='__main__')\n"
                    "else: os.execv('/usr/bin/python3',['/usr/bin/python3',*sys.argv[1:]])\n",
                    encoding="utf-8")
                shim.chmod(0o755)
            command = f'''
set -eu
PATH={str(base)!r}:$PATH; export PATH
P11SCOPE_RECEIPT_HELPER={str(helper)!r}; export P11SCOPE_RECEIPT_HELPER
. scripts/system-scope-owned.sh
owned_launch root - /dev/null /dev/null -- {held_command(command_release)}
wrapper=$OWNED_PID; birth=$OWNED_STARTTIME; receipt=$OWNED_RECEIPT
owned_verify_launch "$wrapper" "$birth" "$receipt"
touch {str(command_release)!r}
for ignored in $(seq 1 {slack_polls(300)}); do [ -s {str(marker)!r} ] && break; sleep .01; done
first=0; owned_finish "$wrapper" "$birth" "$receipt" 0 || first=$?
touch {str(release)!r}
second=0; owned_finish "$wrapper" "$birth" "$receipt" 0 || second=$?
python3 -I - "$receipt" "$first" "$second" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert int(sys.argv[2]) != 0 and int(sys.argv[3]) != 0
assert r["outer_wrapper_cleanup_failed"] is True
assert len(r["outer_wrapper_cleanup_attempts"]) == 2
failed=r["outer_wrapper_cleanup_attempts"][0]
assert failed["qualification_failed"] is True
assert failed["terminal"] is False
assert 0 < len(failed["protocol_error"].encode()) < 1024
assert r["outer_wrapper_cleanup"]["terminal"] is True
assert r["outer_wrapper_cleanup"]["reaped"] is True
PY
'''
            result = self.run_under_subreaper(command, 12)
            self.assertFalse(result["timed_out"], result)
            self.assertEqual(result["returncode"], 0, result)
            if fault == "oversize":
                reads = [json.loads(line) for line in read_log.read_text().splitlines()]
                self.assertGreaterEqual(len(reads), 2, reads)
                self.assertTrue(all(item["request"] == 65537 for item in reads),
                                reads)
                self.assertTrue(all(item["returned"] <= 65537 for item in reads),
                                reads)

    def test_wrapper_false_string_protocol_failure_is_sticky(self):
        self.run_wrapper_protocol_retry("false-string")

    def test_wrapper_nonobject_protocol_failure_is_sticky(self):
        self.run_wrapper_protocol_retry("nonobject")

    def test_wrapper_oversize_protocol_failure_is_sticky(self):
        self.run_wrapper_protocol_retry("oversize")

    def test_wrapper_wrong_identity_protocol_failure_is_sticky(self):
        self.run_wrapper_protocol_retry("wrong-identity")

    def test_wrapper_receipt_write_failure_is_launch_local_and_sticky(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            once = base / "once"
            helper = base / "helper.py"
            helper.write_text(
                "import os,pathlib,sys\n"
                f"once=pathlib.Path({str(once)!r})\n"
                "if sys.argv[1]=='record-wrapper-cleanup' and not once.exists():\n"
                " once.write_text('1'); raise SystemExit(42)\n"
                f"os.execv(sys.executable,[sys.executable,'-I',{str(RECEIPT)!r},*sys.argv[1:]])\n",
                encoding="utf-8")
            command = f'''
set -eu
P11SCOPE_RECEIPT_HELPER={str(helper)!r}; export P11SCOPE_RECEIPT_HELPER
. scripts/system-scope-owned.sh
owned_launch user - /dev/null /dev/null -- {held_command(base / "release-first")}
first_wrapper=$OWNED_PID; first_birth=$OWNED_STARTTIME; first_receipt=$OWNED_RECEIPT
owned_verify_launch "$first_wrapper" "$first_birth" "$first_receipt"
touch {str(base / "release-first")!r}
first=0; owned_finish "$first_wrapper" "$first_birth" "$first_receipt" {slack_whole(3)} || first=$?
retry=0; owned_finish "$first_wrapper" "$first_birth" "$first_receipt" 0 || retry=$?
owned_launch user - /dev/null /dev/null -- {held_command(base / "release-second")}
second_wrapper=$OWNED_PID; second_birth=$OWNED_STARTTIME; second_receipt=$OWNED_RECEIPT
owned_verify_launch "$second_wrapper" "$second_birth" "$second_receipt"
touch {str(base / "release-second")!r}
other=0; owned_finish "$second_wrapper" "$second_birth" "$second_receipt" {slack_whole(3)} || other=$?
python3 -I - "$first_receipt" "$second_receipt" "$first" "$retry" "$other" <<'PY'
import json,pathlib,sys
first=json.load(open(sys.argv[1])); second=json.load(open(sys.argv[2]))
assert int(sys.argv[3]) != 0 and int(sys.argv[4]) != 0
assert int(sys.argv[5]) == 0
assert first["outer_wrapper_cleanup_failed"] is True
assert pathlib.Path(sys.argv[1]+".wrapper-owner-failed").exists()
assert second["outer_wrapper_cleanup_failed"] is False
assert not pathlib.Path(sys.argv[2]+".wrapper-owner-failed").exists()
PY
'''
            result = self.run_under_subreaper(command, 10)
            self.assertFalse(result["timed_out"], result)
            self.assertEqual(result["returncode"], 0, result)

    def test_denied_sidecars_keep_each_launch_failed_and_cleanup_continues(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            directories = {}
            releases = {}
            for name in ("a", "b", "c", "scratch"):
                directories[name] = base / name
                directories[name].mkdir(mode=0o700)
            for name in ("a", "b", "c"):
                releases[name] = base / f"release-{name}"
            command = f'''
set -eu
cd {str(ROOT)!r}
. scripts/system-scope-owned.sh
gate_code='import pathlib,sys,time; gate=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+{slack(20)}\nwhile not gate.exists():\n assert time.monotonic()<deadline\n time.sleep(.01)'

TMPDIR={str(directories["a"])!r}; export TMPDIR
owned_launch user - /dev/null /dev/null -- python3 -c "$gate_code" {str(releases["a"])!r}
a_wrapper=$OWNED_PID; a_birth=$OWNED_STARTTIME; a_receipt=$OWNED_RECEIPT
owned_verify_launch "$a_wrapper" "$a_birth" "$a_receipt"

TMPDIR={str(directories["b"])!r}; export TMPDIR
owned_launch user - /dev/null /dev/null -- python3 -c "$gate_code" {str(releases["b"])!r}
b_wrapper=$OWNED_PID; b_birth=$OWNED_STARTTIME; b_receipt=$OWNED_RECEIPT
owned_verify_launch "$b_wrapper" "$b_birth" "$b_receipt"
b_command=$OWNED_COMMAND_PID; b_command_birth=$OWNED_COMMAND_STARTTIME

TMPDIR={str(directories["scratch"])!r}; export TMPDIR
touch {str(releases["a"])!r}
owned_wait_supervisor_terminal "$a_receipt" {slack_whole(5)}
chmod 500 {str(directories["a"])!r}
a_first=0; owned_finish "$a_wrapper" "$a_birth" "$a_receipt" 0 || a_first=$?
[ "$(owned_process_starttime "$b_command")" = "$b_command_birth" ]
touch {str(base / "continued-after-a")!r}

touch {str(releases["b"])!r}
owned_wait_supervisor_terminal "$b_receipt" {slack_whole(5)}
chmod 500 {str(directories["b"])!r}
b_first=0; owned_finish "$b_wrapper" "$b_birth" "$b_receipt" 0 || b_first=$?

chmod 700 {str(directories["a"])!r}
a_retry=0; owned_finish "$a_wrapper" "$a_birth" "$a_receipt" 0 || a_retry=$?
chmod 700 {str(directories["b"])!r}
b_retry=0; owned_finish "$b_wrapper" "$b_birth" "$b_receipt" 0 || b_retry=$?

TMPDIR={str(directories["c"])!r}; export TMPDIR
owned_launch user - /dev/null /dev/null -- python3 -c "$gate_code" {str(releases["c"])!r}
c_wrapper=$OWNED_PID; c_birth=$OWNED_STARTTIME; c_receipt=$OWNED_RECEIPT
owned_verify_launch "$c_wrapper" "$c_birth" "$c_receipt"
touch {str(releases["c"])!r}
c_finish=0; owned_finish "$c_wrapper" "$c_birth" "$c_receipt" {slack_whole(5)} || c_finish=$?

python3 -I - "$a_receipt" "$b_receipt" "$c_receipt" \
    "$a_first" "$b_first" "$a_retry" "$b_retry" "$c_finish" <<'PY'
import json, pathlib, sys
a, b, c = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:4])
statuses = [int(value) for value in sys.argv[4:]]
assert all(status != 0 for status in statuses[:4]), statuses
assert statuses[4] == 0, statuses
assert a["outer_wrapper_cleanup_failed"] is True
assert b["outer_wrapper_cleanup_failed"] is True
assert c["outer_wrapper_cleanup_failed"] is False
assert a["outer_wrapper_cleanup"]["terminal"] is True
assert b["outer_wrapper_cleanup"]["terminal"] is True
assert c["outer_wrapper_cleanup"]["terminal"] is True
assert not pathlib.Path(sys.argv[1] + ".wrapper-owner-failed").exists()
assert not pathlib.Path(sys.argv[2] + ".wrapper-owner-failed").exists()
PY
[ -e {str(base / "continued-after-a")!r} ]
[ "${{OWNED_WRAPPER_FAILED_RECEIPT_COUNT:-0}}" -eq 2 ]
[ "${{OWNED_WRAPPER_FAILED_RECEIPT_OVERFLOW:-true}}" = false ]
'''
            result = self.run_under_subreaper(command, 18)
            self.assertFalse(result["timed_out"], result)
            self.assertEqual(result["returncode"], 0, result)
            self.assertEqual(result["reaped"], [], result)

    def test_launch_and_finish_settle_descendant_after_root_exit(self):
        command = f'''
set -eu
cd {str(ROOT)!r}
. scripts/system-scope-owned.sh
child_file=$(mktemp)
parent_code='import os,signal,subprocess,sys,time; signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); p=subprocess.Popen([sys.executable,"-c","import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"]); open(sys.argv[1],"w").write(str(p.pid)); time.sleep(60)'
owned_launch user - /dev/null /dev/null -- python3 -c "$parent_code" "$child_file"
root=$OWNED_PID
birth=$OWNED_STARTTIME
receipt=$OWNED_RECEIPT
owned_verify_launch "$root" "$birth" "$receipt"
command_root=$OWNED_COMMAND_PID
for ignored in $(seq 1 {slack_polls(200)}); do [ -s "$child_file" ] && break; sleep .01; done
child=$(cat "$child_file")
kill -TERM "$command_root"
owned_finish "$root" "$birth" "$receipt" {slack_whole(2)}
[ ! -e "/proc/$child/stat" ] || [ "$(sed 's/.*) //' "/proc/$child/stat" | cut -d' ' -f1)" = Z ]
rm -f "$child_file"
'''
        result = subprocess.run(["sh", "-c", command], cwd=ROOT, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=slack(12))
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
