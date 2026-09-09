#!/usr/bin/env python3
"""One-shot SELF/ACK/exec gates and bounded, identity-checked control I/O.

No child is forked here. Control descriptors are close-on-exec and command
stdin is never used by the protocol. Exit 2 means an unknown process state.
"""

import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time


OPEN = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
PHASES = ("launcher", "root", "user")
KINDS = ("self", "ack", "committed")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON record field")
        result[key] = value
    return result


def positive(value):
    if type(value) is not int or value <= 0:
        raise ValueError("expected positive integer")
    return value


def proc_state(pid, generation):
    positive(pid)
    positive(generation)
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return 1, "gone"
    tail = raw.rsplit(b") ", 1)[1].split()
    if len(tail) < 20:
        raise ValueError("short proc stat")
    if int(tail[19]) != generation:
        return 1, "replaced"
    if tail[0] in (b"Z", b"X", b"x"):
        return 1, "zombie"
    return 0, "live"


def self_identity():
    pid = os.getpid()
    raw = Path("/proc/self/stat").read_bytes()
    generation = positive(int(raw.rsplit(b") ", 1)[1].split()[19]))
    return pid, generation


def directory(path, owner, identity=None, private=False):
    fd = os.open(path, OPEN | os.O_DIRECTORY)
    info = os.fstat(fd)
    if (info.st_uid != owner or stat.S_IMODE(info.st_mode) & 0o022
            or (private and stat.S_IMODE(info.st_mode) != 0o700)
            or (identity and (info.st_dev, info.st_ino) != identity)):
        os.close(fd)
        raise ValueError("control directory custody changed")
    return fd


def prepare(pidfile, seconds):
    seconds = float(seconds)
    if not math.isfinite(seconds) or not 0 < seconds <= 8:
        raise ValueError("launch deadline must be in (0, 8] seconds")
    pidfile = os.path.abspath(pidfile)
    if "\n" in pidfile:
        raise ValueError("newline in control path")
    parent = os.path.dirname(pidfile)
    owner = os.getuid()
    parent_fd = directory(parent, owner)
    try:
        if os.path.lexists(pidfile):
            raise ValueError("process identity file already exists")
        path = tempfile.mkdtemp(prefix=".recorded-", dir=parent)
        info = os.stat(path, follow_symlinks=False)
        parent_info = os.fstat(parent_fd)
        context = dict(path=path, pidfile=pidfile, owner=owner,
                       device=info.st_dev, inode=info.st_ino,
                       parent_device=parent_info.st_dev, parent_inode=parent_info.st_ino,
                       attempt=secrets.token_hex(24),
                       deadline=time.monotonic_ns() + int(seconds * 1_000_000_000))
        with Control(context):
            pass
        print(path)
        print(json.dumps(context, separators=(",", ":")))
    finally:
        os.close(parent_fd)


class Control:
    def __init__(self, context):
        self.ctx = json.loads(context, object_pairs_hook=unique_object) if isinstance(context, str) else context
        ctx = self.ctx
        if set(ctx) != {"path", "pidfile", "owner", "device", "inode", "parent_device",
                        "parent_inode", "attempt", "deadline"}:
            raise ValueError("invalid control context")
        for key in ("inode", "parent_inode", "deadline"):
            positive(ctx[key])
        for key in ("owner", "device", "parent_device"):
            if type(ctx[key]) is not int or ctx[key] < 0:
                raise ValueError("invalid control identity")
        if not isinstance(ctx["attempt"], str) or not re.fullmatch(r"[a-f0-9]{48}", ctx["attempt"]):
            raise ValueError("invalid attempt")
        if os.path.dirname(ctx["path"]) != os.path.dirname(ctx["pidfile"]):
            raise ValueError("control parent mismatch")
        self.parent = directory(os.path.dirname(ctx["path"]), ctx["owner"],
                                (ctx["parent_device"], ctx["parent_inode"]))
        try:
            self.fd = directory(ctx["path"], ctx["owner"], (ctx["device"], ctx["inode"]), True)
        except BaseException:
            os.close(self.parent)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        os.close(self.fd)
        os.close(self.parent)

    def validate(self):
        ctx = self.ctx
        with Control(ctx):
            pass

    def before_exec(self):
        self.validate()
        if time.monotonic_ns() >= self.ctx["deadline"]:
            raise ValueError("recorded launch deadline expired")
        try:
            os.stat("cancel", dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("recorded launch canceled")
        self.coordinator()

    def coordinator_record(self, pid, generation):
        return dict(kind="coordinator", attempt=self.ctx["attempt"], owner=self.ctx["owner"],
                    pid=positive(pid), starttime=positive(generation))

    def check_coordinator_process(self, record):
        state, label = proc_state(record["pid"], record["starttime"])
        if state:
            raise ValueError(f"recorded launch coordinator is {label}")
        try:
            owner = os.stat(f"/proc/{record['pid']}", follow_symlinks=False).st_uid
        except (FileNotFoundError, ProcessLookupError):
            raise ValueError("recorded launch coordinator is gone") from None
        if owner != self.ctx["owner"]:
            raise ValueError("recorded launch coordinator owner changed")

    def coordinator(self, require_live=True):
        raw = self.read("coordinator")
        record = json.loads(raw, object_pairs_hook=unique_object)
        if record != self.coordinator_record(record["pid"], record["starttime"]):
            raise ValueError("coordinator attempt/identity mismatch")
        if require_live:
            self.check_coordinator_process(record)
        return record

    def bind_coordinator(self, pid, generation):
        record = self.coordinator_record(pid, generation)
        if os.getuid() != self.ctx["owner"]:
            raise ValueError("coordinator binder owner mismatch")
        if os.getppid() != record["pid"]:
            raise ValueError("coordinator binder is not a direct child")
        self.check_coordinator_process(record)
        self.publish("coordinator", (json.dumps(record, separators=(",", ":")) + "\n").encode(),
                     owner=self.ctx["owner"])

    def read(self, name, owner=None):
        self.validate()
        fd = os.open(name, OPEN | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != (self.ctx["owner"] if owner is None else owner)
                    or info.st_size > 1024):
                raise ValueError("invalid control record custody")
            value = os.read(fd, 1025)
            if not value.endswith(b"\n") or len(value) > 1024:
                raise ValueError("incomplete control record")
            return value
        finally:
            os.close(fd)

    def publish(self, name, value, destination=None, owner=None):
        self.validate()
        temporary = name + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(value)
                stream.flush()
                if owner is not None and os.fstat(stream.fileno()).st_uid != owner:
                    os.fchown(stream.fileno(), owner, -1)
                os.fsync(stream.fileno())
            self.validate()
            target_fd = self.fd if destination is None else self.parent
            os.link(temporary, name if destination is None else destination,
                    src_dir_fd=self.fd, dst_dir_fd=target_fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=self.fd)
        except BaseException:
            # Retain partial/colliding evidence; do not replace or adopt it.
            raise

    def record(self, phase, kind, pid, generation):
        if phase not in PHASES or kind not in KINDS:
            raise ValueError("invalid record phase/kind")
        return dict(phase=phase, kind=kind, attempt=self.ctx["attempt"],
                    pid=positive(pid), starttime=positive(generation))

    def put(self, record):
        self.publish(record["phase"] + "." + record["kind"],
                     (json.dumps(record, separators=(",", ":")) + "\n").encode(),
                     owner=self.ctx["owner"])

    def get(self, phase, kind):
        if phase not in PHASES or kind not in KINDS:
            raise ValueError("invalid phase/kind")
        raw = self.read(phase + "." + kind)
        record = json.loads(raw, object_pairs_hook=unique_object)
        if record != self.record(phase, kind, record["pid"], record["starttime"]):
            raise ValueError("record phase/attempt/identity mismatch")
        return record

    def wait(self, phase, kind, pid=0, generation=0):
        while True:
            self.before_exec()
            try:
                record = self.get(phase, kind)
            except FileNotFoundError:
                time.sleep(0.01)
                continue
            if (pid and record["pid"] != pid) or (generation and record["starttime"] != generation):
                raise ValueError("record does not match accepted identity")
            return record

    def cleanup(self):
        self.validate()
        known = {"cancel", "cancel.tmp", "coordinator", "coordinator.tmp", "durable.tmp"}
        known.update(phase + "." + kind + suffix for phase in PHASES
                     for kind in KINDS for suffix in ("", ".tmp"))
        names = os.listdir(self.fd)
        if set(names) - known:
            raise ValueError("unknown control entries; retaining custody")
        if "coordinator" in names:
            self.coordinator(require_live=False)
        for name in names:
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid not in (0, self.ctx["owner"])):
                raise ValueError("control entry custody changed")
        for name in names:
            self.validate()
            os.unlink(name, dir_fd=self.fd)
        self.validate()
        os.rmdir(os.path.basename(self.ctx["path"]), dir_fd=self.parent)


def durable_read(path):
    fd = os.open(path, OPEN | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid not in (0, os.getuid()) or info.st_size > 128):
            raise ValueError("invalid durable process identity custody")
        raw = os.read(fd, 129)
        if not re.fullmatch(rb"[1-9][0-9]* [1-9][0-9]*\n", raw):
            raise ValueError("incomplete durable process identity")
        return raw.decode().strip()
    finally:
        os.close(fd)


def main(args):
    operation, *args = args
    if operation == "prepare":
        prepare(*args)
        return 0
    if operation in ("active", "wait-gone"):
        pid, generation = map(int, args)
        deadline = time.monotonic() + (5 if operation == "wait-gone" else 0)
        while True:
            state, label = proc_state(pid, generation)
            if state or time.monotonic() >= deadline:
                print(label)
                return state
            time.sleep(0.05)
    if operation == "durable-read":
        try:
            print(durable_read(args[0]))
        except FileNotFoundError:
            return 3
        return 0
    context, *args = args
    with Control(context) as control:
        if operation == "cancel":
            try:
                control.publish("cancel", (control.ctx["attempt"] + "\n").encode(), owner=control.ctx["owner"])
            except FileExistsError:
                if control.read("cancel") != (control.ctx["attempt"] + "\n").encode():
                    raise ValueError("invalid cancellation record")
        elif operation == "bind-coordinator":
            pid, generation = map(int, args)
            control.bind_coordinator(pid, generation)
        elif operation == "cleanup":
            control.cleanup()
        elif operation == "read":
            phase, kind, pid, generation = args
            record = control.wait(phase, kind, int(pid), int(generation))
            print(record["pid"], record["starttime"])
        elif operation == "ack":
            phase, pid, generation = args
            control.before_exec()
            record = control.get(phase, "self")
            expected = control.record(phase, "self", int(pid), int(generation))
            if record != expected:
                raise ValueError("ACK does not match SELF")
            expected["kind"] = "ack"
            control.before_exec()
            control.put(expected)
        elif operation == "exec":
            phase, pidfile, *command = args
            if not command or phase not in PHASES:
                raise ValueError("missing command or invalid phase")
            control.before_exec()
            pid, generation = self_identity()
            record = control.record(phase, "self", pid, generation)
            if phase != "launcher":
                if os.path.abspath(pidfile) != control.ctx["pidfile"]:
                    raise ValueError("durable identity path mismatch")
                control.publish("durable", f"{pid} {generation}\n".encode(),
                                destination=os.path.basename(pidfile))
            control.put(record)
            control.wait(phase, "ack", pid, generation)
            control.before_exec()
            record["kind"] = "committed"
            control.put(record)
            # No control reads after commitment: the coordinator may retire it.
            if time.monotonic_ns() >= control.ctx["deadline"]:
                raise ValueError("recorded launch deadline expired before exec")
            os.execvp(command[0], command)
        else:
            raise ValueError("unknown recorded-process operation")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print(f"recorded process: {error}", file=sys.stderr)
        raise SystemExit(2)
