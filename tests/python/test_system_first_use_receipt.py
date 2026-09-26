#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ordinary protocol controls; synthetic maps do not prove map_files capture."""
import array
import copy
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

m = load_path(ROOT / "scripts/system_first_use_receipt.py", "first_use_receipt")
c = load_path(ROOT / "scripts/canary_process_custody.py", "first_use_custody")


def open_fds():
    # listdir's own transient directory FD is present in its names but already
    # closed on return. Do not count that changing number as a retained handle.
    result = set()
    for name in os.listdir("/proc/self/fd"):
        try:
            os.fstat(int(name))
            result.add(name)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
    return result


class FirstUseReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope-first-use-receipt-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.provider = self.root / "provider.so"
        self.provider.write_bytes(b"synthetic ELF identity, not live evidence")
        self.file_fd = os.open(self.provider, os.O_RDONLY | os.O_CLOEXEC)
        self.ns_fd = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.file_fd)
        self.addCleanup(os.close, self.ns_fd)
        self.directory = self.root / "receipt"
        self.directory.mkdir(mode=0o700)
        self.nonce = "ab" * 32
        self.pid, self.birth = os.getpid(), m.mapping.read_birth("/proc", os.getpid())
        ns = os.fstat(self.ns_fd)
        self.packet = {
            "schema": "p11scope/first-use-fd-packet/v1", "nonce": self.nonce,
            "pid": self.pid, "birth_before": self.birth, "birth_after": self.birth,
            "endpoint_address": 0x1100, "mapping_start": 0x1000, "mapping_end": 0x2000,
            "receipt_started_ns": 70, "receipt_ready_ns": 80,
            "namespace_dev_before": [os.major(ns.st_dev), os.minor(ns.st_dev)],
            "namespace_ino_before": ns.st_ino,
            "namespace_dev_after": [os.major(ns.st_dev), os.minor(ns.st_dev)],
            "namespace_ino_after": ns.st_ino,
        }
        mountinfo = Path("/proc/self/mountinfo").read_bytes()
        mapped = m.mapping.opened_mapping_identity(self.file_fd, mountinfo)
        dev = ":".join(f"{v:02x}" for v in mapped["dev"])
        self.maps = f"1000-2000 r-xp 00000000 {dev} {mapped['ino']} /label.so\n".encode()
        for name in ("maps-before", "maps-after"):
            (self.directory / name).write_bytes(self.maps)
        (self.directory / "mountinfo").write_bytes(mountinfo)
        info = self.provider.stat()
        phases = ["object_stat", "mapped", "publication_returned", "table_verified",
                  "entry_executed", "entry_returned", "receipt_started", "receipt_sent", "unloaded"]
        self.rows = [{"phase": phase, "mono_ns": (index + 1) * 10,
                      "pid": self.pid, "birth": self.birth,
                      "module_dev": info.st_dev, "module_ino": info.st_ino,
                      "mount_ns_ino": ns.st_ino} for index, phase in enumerate(phases)]
        self.rows[3].update(entries=68, entry_address=0x1100, table_storage="file")
        self.rows[4]["body_count"] = 1
        self.rows[5]["rv"] = 0
        self.ledger = self.root / "ledger.jsonl"
        self.write_ledger()

    def write_ledger(self):
        self.ledger.write_text("".join(json.dumps(row) + "\n" for row in self.rows))

    def decode(self, raw=None):
        return m.decode_packet(raw if raw is not None else json.dumps(self.packet).encode(),
                               self.nonce, self.pid, self.birth)

    def validate(self, packet=None, file_fd=None, ns_fd=None):
        return m.validate_receipt(packet or self.decode(),
                                  self.file_fd if file_fd is None else file_fd,
                                  self.ns_fd if ns_fd is None else ns_fd,
                                  self.directory, m.mapping.file_identity(self.provider), self.ledger)

    def test_synthetic_bridge_preserves_mapping_and_file_domains(self):
        value = self.validate()
        self.assertEqual(value["acquisition"], "trusted_fixture_post_call_scm_rights")
        self.assertEqual(value["opened_file_identity"]["ino"], self.provider.stat().st_ino)
        self.assertEqual(value["endpoint_file_offset"], 0x100)
        self.assertEqual(value["mapping_bridge"]["kind"], "map_files_fdinfo_target_mountinfo")
        self.assertFalse(any(key in value for key in ("observed_entry_ns", "scan_ns", "attach_ns")))
        m.mapping.report_identity_bridge(value)

    def test_packet_rejects_malformed_duplicate_unknown_and_noncanonical_values(self):
        bad = [b"{", b"[]", json.dumps(self.packet).encode()[:-1] + b',"pid":1}',
               b" " * 4097]
        for key, value in (("nonce", "cd" * 32), ("pid", self.pid + 1),
                           ("birth_after", self.birth + 1), ("birth_before", self.birth + 1),
                           ("pid", True), ("birth_before", float(self.birth)),
                           ("mapping_start", 0x1200), ("receipt_ready_ns", 69),
                           ("namespace_dev_after", [1, 2]), ("extra", 1)):
            packet = dict(self.packet)
            packet[key] = value
            bad.append(json.dumps(packet).encode())
        for raw in bad:
            with self.subTest(raw=raw[:80]), self.assertRaises(m.ReceiptError):
                self.decode(raw)

    def test_changed_or_nonexecuting_mapping_is_rejected(self):
        for raw in (self.maps.replace(b"1000-2000", b"1000-3000"),
                    self.maps.replace(b"r-xp", b"r--p"), self.maps + self.maps):
            with self.subTest(raw=raw):
                (self.directory / "maps-after").write_bytes(raw)
                with self.assertRaises(m.ReceiptError):
                    self.validate()

    def test_missing_truncated_oversized_or_symlink_sidecar_is_rejected(self):
        path = self.directory / "maps-after"
        for content in (None, self.maps[:-1], b"x" * (2 * 1024 * 1024 + 1)):
            with self.subTest(content=None if content is None else len(content)):
                path.unlink(missing_ok=True)
                if content is not None:
                    path.write_bytes(content)
                with self.assertRaises(m.ReceiptError):
                    self.validate()
        path.unlink()
        path.symlink_to(self.directory / "maps-before")
        with self.assertRaises(m.ReceiptError):
            self.validate()

    def test_wrong_file_or_namespace_descriptor_is_rejected(self):
        other = self.root / "equal-bytes-other-inode"
        other.write_bytes(self.provider.read_bytes())
        fd = os.open(other, os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaises(m.ReceiptError):
                self.validate(file_fd=fd)
            with self.assertRaises(m.ReceiptError):
                self.validate(ns_fd=fd)
            with self.assertRaises(m.ReceiptError):
                self.validate(file_fd=self.ns_fd)
        finally:
            os.close(fd)

    def test_expected_identity_cannot_be_replaced_by_equal_bytes_or_wrong_hash(self):
        other = self.root / "expected-copy.so"
        other.write_bytes(self.provider.read_bytes())
        wrong_hash = m.mapping.file_identity(self.provider)
        wrong_hash["sha256"] = "0" * 64
        for expected in (m.mapping.file_identity(other), wrong_hash):
            with self.subTest(expected=expected), self.assertRaisesRegex(m.ReceiptError, "mapped physical file mismatch"):
                m.validate_receipt(self.decode(), self.file_fd, self.ns_fd,
                                   self.directory, expected, self.ledger)

    def test_nonmount_namespace_descriptor_is_rejected_even_with_its_own_metadata(self):
        fd = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            packet = copy.deepcopy(self.packet)
            for side in ("before", "after"):
                packet["namespace_dev_" + side] = [os.major(info.st_dev), os.minor(info.st_dev)]
                packet["namespace_ino_" + side] = info.st_ino
            with self.assertRaisesRegex(m.ReceiptError, "not a mount namespace"):
                self.validate(packet, ns_fd=fd)
        finally:
            os.close(fd)

    def test_namespace_metadata_and_mount_bridge_must_match_descriptors(self):
        packet = copy.deepcopy(self.packet)
        packet["namespace_ino_before"] += 1
        packet["namespace_ino_after"] += 1
        with self.assertRaises(m.ReceiptError):
            self.validate(packet)
        (self.directory / "mountinfo").write_bytes(b"1 1 0:1 / / rw - tmpfs tmpfs rw\n")
        with self.assertRaises(m.ReceiptError):
            self.validate()

    def test_body_generation_identity_and_time_are_independent_requirements(self):
        original = copy.deepcopy(self.rows)
        for index, key, value in ((4, "body_count", 0), (5, "rv", 1),
                                  (4, "pid", self.pid + 1), (4, "birth", self.birth + 1),
                                  (4, "module_ino", 1), (4, "mount_ns_ino", 1),
                                  (3, "entries", 67), (3, "entry_address", 0x1110),
                                  (4, "mono_ns", 65), (7, "mono_ns", 75),
                                  (6, "mono_ns", 71), (4, "body_count", True)):
            with self.subTest(index=index, key=key, value=value):
                self.rows = copy.deepcopy(original)
                self.rows[index][key] = value
                self.write_ledger()
                with self.assertRaises(m.ReceiptError):
                    self.validate()
        self.rows = original[:4] + original[5:]
        self.write_ledger()
        with self.assertRaises(m.ReceiptError):
            self.validate()

    def sockets(self):
        receive, send = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(receive.close)
        self.addCleanup(send.close)
        receive.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        return receive, send

    def send(self, sock, fds, data=b"packet"):
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
        sock.sendmsg([data], ancillary)

    def test_transport_delivers_cloexec_descriptors_and_closes_them_on_success(self):
        receive, send = self.sockets()
        self.send(send, [self.file_fd, self.ns_fd])
        before = open_fds()
        with m.received(receive, self.pid, time.monotonic() + 1) as (raw, fds):
            self.assertEqual(raw, b"packet")
            self.assertEqual(len(fds), 2)
            self.assertTrue(all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC for fd in fds))
        self.assertEqual(before, open_fds())

    def test_transport_rejects_fd_count_credentials_truncation_and_closes_every_fd(self):
        cases = [(fds, self.pid, b"packet") for fds in
                 ([], [self.file_fd], [self.file_fd, self.ns_fd, self.file_fd], [self.file_fd] * 40)]
        cases += [([self.file_fd, self.ns_fd], self.pid + 1, b"packet"),
                  ([self.file_fd, self.ns_fd], self.pid, b"x" * 4097)]
        for fds, pid, data in cases:
            with self.subTest(count=len(fds), pid=pid, size=len(data)):
                receive, send = self.sockets()
                self.send(send, fds, data)
                before = open_fds()
                with self.assertRaises(m.ReceiptError):
                    with m.received(receive, pid, time.monotonic() + 1):
                        self.fail("invalid transport accepted")
                self.assertEqual(before, open_fds())

    def test_transport_timeout_eof_and_validator_exception_close_descriptors(self):
        receive, send = self.sockets()
        with self.assertRaises(m.ReceiptError):
            with m.received(receive, self.pid, time.monotonic() + 0.02):
                self.fail("absent packet accepted")
        self.send(send, [self.file_fd, self.ns_fd])
        before = open_fds()
        with self.assertRaisesRegex(RuntimeError, "caller failed"):
            with m.received(receive, self.pid, time.monotonic() + 1):
                raise RuntimeError("caller failed")
        self.assertEqual(before, open_fds())
        send.close()
        with self.assertRaises(m.ReceiptError):
            with m.received(receive, self.pid, time.monotonic() + 1):
                self.fail("EOF accepted")

    def owned_case(self, mode):
        receive, send = self.sockets()
        self.fd_baseline = open_fds() - {str(send.fileno())}
        expected = m.mapping.file_identity(self.provider)
        template = self.root / "input.json"
        template.write_text(json.dumps({"packet": self.packet, "rows": self.rows}))
        code = """
import array,json,os,socket,sys,time
channel, template, ledger, provider, mode = sys.argv[1:]
s = socket.socket(fileno=int(channel))
value = json.load(open(template))
pid = os.getpid()
birth = int(open('/proc/self/stat').read().rsplit(') ',1)[1].split()[19])
value['packet'].update(pid=pid, birth_before=birth, birth_after=birth)
for row in value['rows']:
    row.update(pid=pid, birth=birth)
with open(ledger, 'w') as out:
    out.writelines(json.dumps(row)+'\\n' for row in value['rows'])
fds = [os.open(provider, os.O_RDONLY), os.open('/proc/self/ns/mnt', os.O_RDONLY)]
os.unlink(provider)
if mode == 'timeout':
    time.sleep(30)
packet = json.dumps(value['packet']).encode()
s.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])
if mode == 'duplicate':
    s.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])
sys.exit(7 if mode == 'nonzero' else 0)
"""
        with c.Custody() as owner:
            deadline = time.monotonic() + 3
            child = owner.launch([sys.executable, "-I", "-c", code, str(send.fileno()),
                                  str(template), str(self.ledger), str(self.provider), mode],
                                 pass_fds=(send.fileno(),), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, deadline=deadline)
            send.close()
            if mode == "timeout":
                deadline = time.monotonic() + 0.03
            # socketpair creator credentials are the parent; SCM_CREDENTIALS must be the child.
            creator = struct.unpack("3i", receive.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
            self.assertEqual(creator, os.getpid())
            try:
                result = m.collect(receive, child, self.nonce, self.directory, expected, self.ledger, deadline)
                self.assertEqual(result["pid"], child.popen.pid)
                self.assertTrue(child.settled)
                self.assertFalse(self.provider.exists())
                return result
            finally:
                self.retained_child = child

    def test_owned_sender_can_exit_and_unlink_before_receipt_validation(self):
        result = self.owned_case("positive")
        self.assertEqual(result["terminal_exit"], 0)
        self.assertTrue(self.retained_child.group.closed)
        self.assertEqual(self.fd_baseline, open_fds())

    def test_owned_duplicate_nonzero_and_timeout_are_not_success_and_settle_child(self):
        for mode, reason in (("duplicate", "duplicate or trailing receipt packet"),
                             ("nonzero", "fixture exit was 7"),
                             ("timeout", "receive deadline expired")):
            with self.subTest(mode=mode):
                self.provider.write_bytes(b"synthetic ELF identity, not live evidence")
                (self.directory / "received-packet.json").unlink(missing_ok=True)
                # Recompute the synthetic maps inode after the prior child unlinked its file.
                ino = self.provider.stat().st_ino
                parts = self.maps.decode().split()
                parts[4] = str(ino)
                self.maps = (" ".join(parts) + "\n").encode()
                for name in ("maps-before", "maps-after"):
                    (self.directory / name).write_bytes(self.maps)
                for row in self.rows:
                    row["module_ino"] = ino
                with self.assertRaisesRegex(m.ReceiptError, reason):
                    self.owned_case(mode)
                self.assertTrue(self.retained_child.settled)
                self.assertTrue(self.retained_child.group.closed)
                self.assertEqual(self.fd_baseline, open_fds())


if __name__ == "__main__":
    unittest.main()
