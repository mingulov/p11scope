# SPDX-License-Identifier: GPL-3.0-or-later
"""Private trusted-fixture post-call custody, not observer entry evidence.

Only the pinned single-thread fixture establishes that the first FD was opened
through its addressed self map_files entry after the call and before dlclose.
SCM_RIGHTS alone cannot attest how an arbitrary sender obtained a descriptor.
"""
import array
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import time

from _loader import load_path

mapping = load_path(Path(__file__).with_name("system-scope-receipt.py"), "first_use_mapping")
ReceiptError = mapping.ReceiptError
require = mapping.require
PACKET_SCHEMA = "p11scope/first-use-fd-packet/v1"
RECEIPT_SCHEMA = "p11scope/first-use-mapping-receipt/v1"
MAX_PACKET = 4096
MAX_SIDECAR = 2 * 1024 * 1024
NS_GET_NSTYPE = 0xB703  # _IO(0xb7, 3), Linux nsfs UAPI, including 5.15.
CLONE_NEWNS = 0x00020000
FIELDS = {
    "schema", "nonce", "pid", "birth_before", "birth_after", "endpoint_address",
    "mapping_start", "mapping_end", "receipt_started_ns", "receipt_ready_ns",
    "namespace_dev_before", "namespace_ino_before", "namespace_dev_after", "namespace_ino_after",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def strict_json(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ReceiptError("nonfinite JSON")))
    except (UnicodeError, ValueError) as error:
        raise ReceiptError(f"invalid JSON: {error}") from error


def integer(value, *, minimum=1):
    return type(value) is int and minimum <= value < 2**64


def decode_packet(raw, nonce, pid, birth):
    require(0 < len(raw) <= MAX_PACKET, "packet size invalid")
    value = strict_json(raw)
    require(type(value) is dict and set(value) == FIELDS, "packet fields invalid")
    require(value["schema"] == PACKET_SCHEMA, "packet schema invalid")
    require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{64}", nonce)
            and value["nonce"] == nonce, "packet nonce mismatch")
    for key in FIELDS - {"schema", "nonce", "namespace_dev_before", "namespace_dev_after"}:
        require(integer(value[key]), f"packet integer invalid: {key}")
    for key in ("namespace_dev_before", "namespace_dev_after"):
        require(type(value[key]) is list and len(value[key]) == 2
                and all(integer(v, minimum=0) for v in value[key]), "namespace device invalid")
    require(value["pid"] == pid and value["birth_before"] == birth
            and value["birth_after"] == birth, "packet owned process identity mismatch")
    require(value["namespace_dev_before"] == value["namespace_dev_after"]
            and value["namespace_ino_before"] == value["namespace_ino_after"],
            "packet namespace changed")
    require(value["mapping_start"] <= value["endpoint_address"] < value["mapping_end"],
            "packet endpoint outside range")
    require(value["receipt_started_ns"] <= value["receipt_ready_ns"], "receipt clock order invalid")
    return value


def remaining(deadline):
    require(math.isfinite(deadline), "receive deadline must be finite")
    value = deadline - time.monotonic()
    require(value > 0, "receive deadline expired")
    return value


@contextmanager
def received(sock, expected_pid, deadline, *, check_cancelled=lambda: None):
    """Close every delivered descriptor, including malformed/truncated packets."""
    require(sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET,
            "receipt requires SOCK_SEQPACKET")
    require(sock.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1,
            "receipt requires SO_PASSCRED before sender launch")
    while True:
        check_cancelled()
        if select.select([sock], [], [], min(remaining(deadline), 0.1))[0]:
            break
    ancillary_size = socket.CMSG_SPACE(8 * array.array("i").itemsize) + socket.CMSG_SPACE(12)
    raw, ancillary, flags, _ = sock.recvmsg(MAX_PACKET, ancillary_size,
                                          socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
    fds, credentials, rights = [], [], 0
    bad = False
    try:
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                rights += 1
                size = array.array("i").itemsize
                values = array.array("i")
                values.frombytes(data[:len(data) - len(data) % size])
                fds.extend(values)
                bad |= bool(len(data) % size)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
                credentials.append(struct.unpack("3i", data))
            else:
                bad = True
        require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "receipt message truncated")
        require(bool(raw), "receipt channel EOF before packet")
        require(not bad and rights == 1 and len(fds) == 2, "receipt requires exactly two descriptors")
        require(len(credentials) == 1 and credentials[0][0] == expected_pid,
                "receipt sender credentials mismatch")
        require(all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC for fd in fds),
                "received descriptor lacks CLOEXEC")
        yield raw, fds
    finally:
        for fd in fds:
            os.close(fd)


def bounded_file(path, limit=MAX_SIDECAR):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "sidecar is not a regular file")
            raw = stream.read(limit + 1)
        require(0 < len(raw) <= limit and raw.endswith(b"\n"), "sidecar truncated or exceeds bound")
        return raw
    except OSError as error:
        raise ReceiptError(f"cannot read sidecar {Path(path).name}: {error}") from error


def check_ledger(path, packet, opened):
    raw = bounded_file(path, 65536)
    rows = [strict_json(line) for line in raw.splitlines()]
    phases = ["object_stat", "mapped", "publication_returned", "table_verified",
              "entry_executed", "entry_returned", "receipt_started", "receipt_sent", "unloaded"]
    require(all(type(row) is dict for row in rows)
            and [row.get("phase") for row in rows] == phases, "workload phases missing or duplicated")
    for row in rows:
        for key in ("mono_ns", "pid", "birth", "module_ino", "mount_ns_ino"):
            require(integer(row.get(key)), f"ledger integer invalid: {key}")
        require(integer(row.get("module_dev"), minimum=0), "ledger device invalid")
        require(row["pid"] == packet["pid"] and row["birth"] == packet["birth_before"],
                "workload generation mismatch")
        require([os.major(row["module_dev"]), os.minor(row["module_dev"])] == opened["dev"]
                and row["module_ino"] == opened["ino"], "workload file identity mismatch")
        require(row["mount_ns_ino"] == packet["namespace_ino_before"], "workload namespace mismatch")
    clocks = [row["mono_ns"] for row in rows]
    require(clocks == sorted(clocks), "workload clock order invalid")
    require(type(rows[3].get("entries")) is int and rows[3]["entries"] == 68
            and type(rows[3].get("entry_address")) is int
            and rows[3]["entry_address"] == packet["endpoint_address"]
            and rows[3].get("table_storage") in {"file", "heap"}, "verified table mismatch")
    require(type(rows[4].get("body_count")) is int and rows[4]["body_count"] == 1
            and type(rows[5].get("rv")) is int and rows[5]["rv"] == 0, "ordinary body/return invalid")
    require(clocks[6] == packet["receipt_started_ns"]
            and clocks[6] <= packet["receipt_ready_ns"] <= clocks[7], "receipt/ledger clocks disagree")
    return hashlib.sha256(raw).hexdigest()


def validate_receipt(packet, file_fd, namespace_fd, directory, expected, ledger):
    """Validate retained descriptors and bounded raw evidence after child exit."""
    try:
        require(stat.S_ISREG(os.fstat(file_fd).st_mode), "mapped descriptor is not regular")
        require(fcntl.ioctl(namespace_fd, NS_GET_NSTYPE) == CLONE_NEWNS,
                "namespace descriptor is not a mount namespace")
        ns = os.fstat(namespace_fd)
        namespace = {"dev": [os.major(ns.st_dev), os.minor(ns.st_dev)], "ino": ns.st_ino}
        require(namespace == {"dev": packet["namespace_dev_before"], "ino": packet["namespace_ino_before"]},
                "namespace descriptor identity mismatch")
        before = bounded_file(Path(directory) / "maps-before")
        after = bounded_file(Path(directory) / "maps-after")
        mountinfo = bounded_file(Path(directory) / "mountinfo")
        first = mapping.addressed_mapping(mapping.parse_maps(before), packet["endpoint_address"])
        last = mapping.addressed_mapping(mapping.parse_maps(after), packet["endpoint_address"])
        require(mapping.same_mapping(first, last), "addressed mapping changed")
        require((first["start"], first["end"]) == (packet["mapping_start"], packet["mapping_end"]),
                "packet and mapping range disagree")
        require(stat.S_ISREG(os.fstat(file_fd).st_mode)
                and os.fstat(file_fd).st_size == expected["size"], "mapped file size mismatch")
        opened = mapping.identity_from_fd(file_fd, expected["path"])
        require(mapping.physical(opened) == mapping.physical(expected), "mapped physical file mismatch")
        mounted = mapping.opened_mapping_identity(file_fd, mountinfo)
        require(mounted["dev"] == first["dev"] and mounted["ino"] == first["ino"]
                and opened["ino"] == first["ino"], "mapping mount/file identity mismatch")
        ledger_hash = check_ledger(ledger, packet, opened)
    except (OSError, UnicodeError, ValueError) as error:
        raise ReceiptError(f"first-use receipt invalid: {error}") from error
    mapped = {**first, "start": hex(first["start"]), "end": hex(first["end"]), "offset": hex(first["offset"])}
    identity = {"dev": first["dev"], "ino": first["ino"]}
    bridge = {"schema": mapping.MAPPING_BRIDGE_SCHEMA, "kind": "map_files_fdinfo_target_mountinfo",
              "mapping_identity": identity, "opened_mapping_identity": mounted,
              "opened_file_identity": {key: opened[key] for key in ("dev", "ino", "sha256")}}
    receipt = {
        "schema": RECEIPT_SCHEMA, "acquisition": "trusted_fixture_post_call_scm_rights",
        "pid": packet["pid"], "starttime": packet["birth_before"], "nonce": packet["nonce"],
        "endpoint_address": hex(packet["endpoint_address"]),
        "endpoint_file_offset": first["offset"] + packet["endpoint_address"] - first["start"],
        "mapping": mapped, "mapping_identity": identity, "opened_mapping_identity": mounted,
        "opened_file_identity": opened, "expected": expected,
        "mount_namespace_identity_before": namespace, "mount_namespace_identity_after": namespace,
        "maps_before_sha256": hashlib.sha256(before).hexdigest(),
        "maps_after_sha256": hashlib.sha256(after).hexdigest(), "ledger_sha256": ledger_hash,
        "receipt_started_ns": packet["receipt_started_ns"], "receipt_ready_ns": packet["receipt_ready_ns"],
        "mapping_bridge": {
            "schema": mapping.MAPPING_BRIDGE_SCHEMA, "kind": bridge["kind"],
            "range": f"{first['start']:x}-{first['end']:x}", "mount_namespace_identity": namespace,
            "mountinfo_sha256": hashlib.sha256(mountinfo).hexdigest(), "report_identity_bridge": bridge,
        },
    }
    mapping.report_identity_bridge(receipt)
    return receipt


def terminal_eof(sock):
    """The reaped sole sender must have closed the channel after exactly one packet."""
    ancillary_size = socket.CMSG_SPACE(8 * array.array("i").itemsize) + socket.CMSG_SPACE(12)
    try:
        raw, ancillary, flags, _ = sock.recvmsg(MAX_PACKET, ancillary_size,
                                              socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
    except BlockingIOError as error:
        raise ReceiptError("receipt channel still open after child exit") from error
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            size = array.array("i").itemsize
            values = array.array("i")
            values.frombytes(data[:len(data) - len(data) % size])
            for fd in values:
                os.close(fd)
    # Linux echoes MSG_CMSG_CLOEXEC in msg_flags, including an ordinary EOF.
    require(not raw and not ancillary and not flags & ~socket.MSG_CMSG_CLOEXEC,
            "duplicate or trailing receipt packet")


def collect(sock, owned, nonce, directory, expected, ledger, deadline):
    """Caller keeps the Custody scope active and closes its sender socket copy.

    Retain the direct child before accepting a message, require successful
    ordinary wait and channel EOF, then validate the two still-open descriptors.
    The caller's Custody scope settles the exact child on every failure path.
    """
    require(owned.scope.active and not owned.scope.closed
            and owned in owned.scope.processes and not owned.settled
            and owned.group is not None and not owned.group.closed
            and owned.group.process is owned and owned.group.fd is not None,
            "receipt requires an active retained direct child")
    try:
        with received(sock, owned.popen.pid, deadline,
                      check_cancelled=owned.scope.check_cancelled) as (raw, fds):
            received_ns = time.monotonic_ns()
            with (Path(directory) / "received-packet.json").open("xb") as output:
                output.write(raw)
            packet = decode_packet(raw, nonce, owned.popen.pid, owned.group.generation)
            require(packet["receipt_ready_ns"] <= received_ns, "packet is from the future")
            status = owned.wait(deadline)
            require(status == 0, f"fixture exit was {status}")
            terminal_eof(sock)
            result = validate_receipt(packet, fds[0], fds[1], directory, expected, ledger)
            result.update(terminal_exit=status, received_ns=received_ns,
                          packet_sha256=hashlib.sha256(raw).hexdigest())
            return result
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReceiptError(f"first-use collection failed: {error}") from error
