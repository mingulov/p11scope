#!/usr/bin/env python3
"""Operate on directories retained by a live oracle receipt shell."""

import os
import stat
import sys
import time


def fail(message):
    raise RuntimeError(message)


def positive_int(raw, label):
    try:
        value = int(raw)
    except ValueError:
        fail(f"invalid {label}")
    if value <= 0:
        fail(f"invalid {label}")
    return value


def nonnegative_int(raw, label):
    try:
        value = int(raw)
    except ValueError:
        fail(f"invalid {label}")
    if value < 0:
        fail(f"invalid {label}")
    return value


def process_starttime(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as source:
            raw = source.read()
        _head, separator, tail = raw.rpartition(b") ")
        fields = tail.split()
        if not separator or len(fields) < 20:
            fail("malformed receipt process stat")
        return int(fields[19])
    except (FileNotFoundError, ProcessLookupError):
        fail("receipt process disappeared")


def receipt_is_current(receipt_pid, receipt_starttime):
    if process_starttime(receipt_pid) != receipt_starttime:
        fail("receipt process generation changed")


def reopen_receipt_directory(receipt_pid, held_fd, expected_device, expected_inode, label):
    try:
        directory_fd = os.open(
            f"/proc/{receipt_pid}/fd/{held_fd}",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
    except OSError as error:
        fail(f"could not reopen retained {label} directory: {error}")
    identity = os.fstat(directory_fd)
    if (identity.st_dev, identity.st_ino) != (expected_device, expected_inode):
        os.close(directory_fd)
        fail(f"{label} directory identity changed")
    return directory_fd


def open_control(directory_fd, name, flags):
    flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(name, flags, dir_fd=directory_fd)


def populated(directory_fd):
    try:
        fd = open_control(directory_fd, "cgroup.events", os.O_RDONLY)
    except FileNotFoundError:
        return None
    except OSError as error:
        fail(f"cgroup.events unavailable: {error}")
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 65536:
                fail("cgroup.events is too large")
    finally:
        os.close(fd)
    values = []
    for line in b"".join(chunks).splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == b"populated" and fields[1] in (b"0", b"1"):
            values.append(int(fields[1]))
    if len(values) != 1:
        fail("cgroup.events lacks one populated field")
    return values[0]


def retained_directory_retired(directory_fd):
    try:
        return os.readlink(f"/proc/self/fd/{directory_fd}").endswith(" (deleted)")
    except OSError as error:
        fail(f"could not inspect retained cgroup directory: {error}")


def probe(directory_fd):
    try:
        fd = open_control(directory_fd, "cgroup.kill", os.O_WRONLY)
    except OSError as error:
        fail(f"cgroup.kill unavailable: {error}")
    else:
        os.close(fd)
    if populated(directory_fd) is None:
        fail("cgroup.events disappeared during probe")


def kill(directory_fd, timeout_seconds):
    current = populated(directory_fd)
    if current is None:
        if retained_directory_retired(directory_fd):
            return
        fail("cgroup.events disappeared from a retained live directory")
    if current == 0:
        return
    try:
        fd = open_control(directory_fd, "cgroup.kill", os.O_WRONLY)
        try:
            if os.write(fd, b"1\n") != 2:
                fail("short cgroup.kill write")
        finally:
            os.close(fd)
    except OSError as error:
        fail(f"cgroup.kill write failed: {error}")

    deadline = time.monotonic() + timeout_seconds
    while True:
        current = populated(directory_fd)
        if current is None:
            if retained_directory_retired(directory_fd):
                return
            fail("cgroup.events disappeared from a retained live directory")
        if current == 0:
            return
        if time.monotonic() >= deadline:
            fail("cgroup remained populated after kill deadline")
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def checked_entry(parent_fd, name, expected=None):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        fail("symlink in retained artifacts")
    if stat.S_ISDIR(before.st_mode):
        flags |= os.O_DIRECTORY
    elif not stat.S_ISREG(before.st_mode):
        fail("special file in retained artifacts")
    fd = os.open(name, flags, dir_fd=parent_fd)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_mode) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
    ):
        os.close(fd)
        fail("retained artifact changed while opening")
    if expected is not None and (after.st_dev, after.st_ino) != expected:
        os.close(fd)
        fail("retained artifact identity changed")
    return fd, after


def transfer_owner(fd, metadata, caller_uid, caller_gid, *, regular):
    if metadata.st_uid == caller_uid:
        return
    if metadata.st_uid != 0:
        fail("retained artifact has foreign owner")
    if metadata.st_mode & 0o077:
        fail("root-owned retained artifact is not private")
    if regular and metadata.st_nlink != 1:
        fail("root-owned retained artifact has multiple links")
    os.fchown(fd, caller_uid, caller_gid)


def admit_directory(metadata, device, caller_uid, label, *, caller_only=False, private=True):
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} is not a directory")
    if metadata.st_dev != device:
        fail("retained artifact crossed a filesystem boundary")
    if caller_only:
        if metadata.st_uid != caller_uid:
            fail(f"{label} directory owner changed")
    elif metadata.st_uid not in (0, caller_uid):
        fail("retained artifact has foreign owner")
    if private and metadata.st_mode & 0o077:
        fail("selected directory is not private")


def checked_directory(parent_fd, name, device, caller_uid, before=None):
    if before is None:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        fail("symlink in retained artifacts")
    admit_directory(before, device, caller_uid, "selected")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=parent_fd)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
    ):
        os.close(fd)
        fail("retained artifact changed while opening")
    admit_directory(after, device, caller_uid, "selected")
    return fd, after


def reclaim_tree(directory_fd, device, caller_uid, caller_gid):
    admit_directory(os.fstat(directory_fd), device, caller_uid, "selected")
    for name in os.listdir(directory_fd):
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            fd, metadata = checked_directory(
                directory_fd, name, device, caller_uid, before=before
            )
        else:
            fd, metadata = checked_entry(
                directory_fd, name, expected=(before.st_dev, before.st_ino)
            )
        try:
            if metadata.st_dev != device:
                fail("retained artifact crossed a filesystem boundary")
            if stat.S_ISDIR(metadata.st_mode):
                reclaim_tree(fd, device, caller_uid, caller_gid)
                transfer_owner(fd, metadata, caller_uid, caller_gid, regular=False)
            elif stat.S_ISREG(metadata.st_mode):
                transfer_owner(fd, metadata, caller_uid, caller_gid, regular=True)
            else:
                fail("special file in retained artifacts")
        finally:
            os.close(fd)


def reclaim_selected_file(directory_fd, name, device, caller_uid, caller_gid):
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    fd, metadata = checked_entry(
        directory_fd, name, expected=(before.st_dev, before.st_ino)
    )
    try:
        if metadata.st_dev != device:
            fail("retained artifact crossed a filesystem boundary")
        if not stat.S_ISREG(metadata.st_mode):
            fail("selected root output is not regular")
        transfer_owner(fd, metadata, caller_uid, caller_gid, regular=True)
    finally:
        os.close(fd)


def reclaim_selected_tree(directory_fd, name, device, caller_uid, caller_gid):
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    fd, metadata = checked_directory(
        directory_fd, name, device, caller_uid, before=before
    )
    try:
        reclaim_tree(fd, device, caller_uid, caller_gid)
        transfer_owner(fd, metadata, caller_uid, caller_gid, regular=False)
    finally:
        os.close(fd)


def parse_identity(raw, label):
    if raw == "-":
        return None
    fields = raw.split(":")
    if len(fields) != 2:
        fail(f"invalid {label} identity")
    return positive_int(fields[0], f"{label} device"), positive_int(fields[1], f"{label} inode")


def reclaim_state(directory_fd, name, expected, caller_uid, caller_gid):
    if expected is None:
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        fail("unrecorded sibling state artifact appeared")
    fd, metadata = checked_entry(directory_fd, name, expected)
    try:
        if not stat.S_ISREG(metadata.st_mode):
            fail("sibling state artifact is not regular")
        transfer_owner(fd, metadata, caller_uid, caller_gid, regular=True)
    finally:
        os.close(fd)


def reclaim(argv):
    if len(argv) != 14:
        fail(
            "usage: reclaim RECEIPT_PID RECEIPT_STARTTIME WORK_FD WORK_DEVICE "
            "WORK_INODE SIBLING_FD SIBLING_DEVICE SIBLING_INODE UID GID "
            "STATE_NAME STATE_ID POLICY_NAME POLICY_ID"
        )
    receipt_pid = positive_int(argv[0], "receipt PID")
    receipt_starttime = positive_int(argv[1], "receipt starttime")
    work_fd_number = positive_int(argv[2], "work fd")
    work_device = positive_int(argv[3], "work device")
    work_inode = positive_int(argv[4], "work inode")
    sibling_fd_number = positive_int(argv[5], "sibling fd")
    sibling_device = positive_int(argv[6], "sibling device")
    sibling_inode = positive_int(argv[7], "sibling inode")
    caller_uid = positive_int(argv[8], "caller UID")
    caller_gid = nonnegative_int(argv[9], "caller GID")
    state_name, state_identity = argv[10], parse_identity(argv[11], "state")
    policy_name, policy_identity = argv[12], parse_identity(argv[13], "policy state")
    if state_name != ".pkcs11-check-isolation-state.json":
        fail("unexpected state basename")
    if policy_name != ".pkcs11-check-isolation-state-policy.json":
        fail("unexpected policy state basename")
    receipt_is_current(receipt_pid, receipt_starttime)
    work_fd = reopen_receipt_directory(receipt_pid, work_fd_number, work_device, work_inode, "work")
    sibling_fd = reopen_receipt_directory(
        receipt_pid, sibling_fd_number, sibling_device, sibling_inode, "sibling"
    )
    try:
        receipt_is_current(receipt_pid, receipt_starttime)
        admit_directory(
            os.fstat(work_fd), work_device, caller_uid, "work", caller_only=True
        )
        admit_directory(
            os.fstat(sibling_fd), sibling_device, caller_uid, "sibling", caller_only=True,
            private=False,
        )
        for name in ("observed.json", "observer.pid", "systemd-run.pid", "workload.pid"):
            reclaim_selected_file(work_fd, name, work_device, caller_uid, caller_gid)
        for name in ("reports", "tokens"):
            reclaim_selected_tree(work_fd, name, work_device, caller_uid, caller_gid)
        reclaim_state(sibling_fd, state_name, state_identity, caller_uid, caller_gid)
        reclaim_state(sibling_fd, policy_name, policy_identity, caller_uid, caller_gid)
        receipt_is_current(receipt_pid, receipt_starttime)
    finally:
        os.close(sibling_fd)
        os.close(work_fd)


def main(argv):
    if argv and argv[0] == "reclaim":
        reclaim(argv[1:])
        return 0
    if len(argv) != 7 or argv[0] not in ("probe", "kill"):
        fail("usage: OP RECEIPT_PID RECEIPT_STARTTIME FD DEVICE INODE TIMEOUT")
    operation = argv[0]
    receipt_pid = positive_int(argv[1], "receipt PID")
    receipt_starttime = positive_int(argv[2], "receipt starttime")
    held_fd = positive_int(argv[3], "held fd")
    expected_device = positive_int(argv[4], "expected device")
    expected_inode = positive_int(argv[5], "expected inode")
    try:
        timeout_seconds = float(argv[6])
    except ValueError:
        fail("invalid timeout")
    if not 0 < timeout_seconds <= 300:
        fail("invalid timeout")

    receipt_is_current(receipt_pid, receipt_starttime)
    directory_fd = reopen_receipt_directory(
        receipt_pid, held_fd, expected_device, expected_inode, "cgroup"
    )
    try:
        receipt_is_current(receipt_pid, receipt_starttime)
        if operation == "probe":
            probe(directory_fd)
        else:
            kill(directory_fd, timeout_seconds)
    finally:
        os.close(directory_fd)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"oracle cgroup helper: {error}", file=sys.stderr)
        raise SystemExit(1)
