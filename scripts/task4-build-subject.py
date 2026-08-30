#!/usr/bin/python3
import dataclasses as _dataclasses
import errno
import fcntl
import hashlib as _hashlib
import os
import re as _re
import resource
import stat as _stat
import unicodedata as _unicodedata

class FormatError(ValueError):
    pass


class MutationError(RuntimeError):
    pass


_MAX_OFFSET = 2**63 - 1


@_dataclasses.dataclass(slots=True, eq=False)
class _OpenDescription:
    kind: str
    access: str
    offset: int | None
    identity: object


@_dataclasses.dataclass(frozen=True, slots=True)
class InputRecord:
    seq: int
    klass: str
    access: str
    result: str
    mode: int | None
    size: int | None
    sha256: str | None
    locator: str


class _SemanticTraceState:
    def __init__(self, *, root_tid, cwd, root, umask, fds):
        self._tasks = {
            root_tid: {
                "tgid": root_tid,
                "fds": dict(fds),
                "fs": {"cwd": cwd, "root": root, "umask": umask},
                "maps": {},
            }
        }
        self._pending = {}
        self._fd_table_mutators = []

    @staticmethod
    def _validate_fd_table_mutator_operation(operation):
        if type(operation) is not tuple or len(operation) != 3:
            raise FormatError("invalid pending syscall")
        name, category, arguments = operation
        if type(name) is not str or name not in {"close", "dup", "dup2"}:
            raise FormatError("invalid pending syscall")
        if type(category) is not str or category != "fd":
            raise FormatError("invalid pending syscall")
        if type(arguments) is not tuple or len(arguments) != 6:
            raise FormatError("invalid pending syscall")
        if any(type(value) is not int or not 0 <= value < 2**64 for value in arguments):
            raise FormatError("invalid pending syscall")
        endpoint_count = 2 if name == "dup2" else 1
        if any(
            type(value) is not int or not 0 <= value <= 2**31 - 1
            for value in arguments[:endpoint_count]
        ):
            raise FormatError("invalid pending syscall")
        return name, arguments

    def _validate_fd_table_mutators(self):
        owners = self._fd_table_mutators
        if type(owners) is not list or type(self._pending) is not dict:
            raise FormatError("invalid FD-table mutators")
        tables = []
        tids = set()
        for owner in owners:
            if type(owner) is not tuple or len(owner) != 3:
                raise FormatError("invalid FD-table mutator")
            table, owner_tid, pending = owner
            if type(table) is not dict or type(owner_tid) is not int or owner_tid <= 0:
                raise FormatError("invalid FD-table mutator")
            if any(table is previous for previous in tables) or owner_tid in tids:
                raise FormatError("duplicate FD-table mutator")
            task = self._task(owner_tid)
            if type(task) is not dict or task.get("fds") is not table:
                raise FormatError("stale FD-table mutator")
            self._fd_table(owner_tid)
            try:
                current_pending = self._pending[owner_tid]
            except (KeyError, TypeError) as exc:
                raise FormatError("missing pending syscall") from exc
            if current_pending is not pending:
                raise FormatError("stale pending syscall")
            self._validate_fd_table_mutator_operation(pending)
            tables.append(table)
            tids.add(owner_tid)
        return owners

    def _owner_for_fd_table_mutator(self, tid):
        fds = self._fd_table(tid)
        if type(self._pending) is not dict:
            raise FormatError("invalid pending syscall table")
        try:
            pending = self._pending[tid]
        except (KeyError, TypeError) as exc:
            raise FormatError("no pending syscall") from exc
        owners = self._validate_fd_table_mutators()
        owner_index = None
        for index, owner in enumerate(owners):
            if owner[0] is fds and owner[1] == tid and owner[2] is pending:
                if owner_index is not None:
                    raise FormatError("ambiguous FD-table mutator")
                owner_index = index
        if owner_index is None:
            raise FormatError("FD-table mutator not admitted")
        return fds, pending, owner_index

    def try_admit_fd_table_mutator(self, *, tid):
        if type(tid) is not int or tid <= 0:
            raise FormatError("invalid task")
        fds = self._fd_table(tid)
        if type(self._pending) is not dict:
            raise FormatError("invalid pending syscall table")
        try:
            pending = self._pending[tid]
        except (KeyError, TypeError) as exc:
            raise FormatError("no pending syscall") from exc
        self._validate_fd_table_mutator_operation(pending)
        owners = self._validate_fd_table_mutators()
        for owner in owners:
            if owner[0] is fds:
                return owner[1] == tid and owner[2] is pending
        owners.append((fds, tid, pending))
        return True

    def _fd_table(self, tid):
        if type(tid) is not int or tid <= 0:
            raise FormatError("invalid task")
        task = self._task(tid)
        if type(task) is not dict:
            raise FormatError("invalid task")
        try:
            fds = task["fds"]
        except (KeyError, TypeError) as exc:
            raise FormatError("invalid FD table") from exc
        if type(fds) is not dict:
            raise FormatError("invalid FD table")
        for fd, value in fds.items():
            if (
                type(fd) is not int
                or fd < 0
                or type(value) is not tuple
                or len(value) != 2
                or type(value[1]) is not bool
            ):
                raise FormatError("invalid FD table")
        return fds

    def _typed_description(self, description):
        if type(description) is not _OpenDescription:
            raise FormatError("unknown description")
        try:
            description.kind, description.access, description.offset, description.identity
        except AttributeError as exc:
            raise FormatError("invalid description") from exc
        if type(description.kind) is not str or type(description.access) is not str:
            raise FormatError("invalid description")
        if description.kind == "regular":
            if description.access not in {"read", "write", "read_write"}:
                raise FormatError("invalid description")
            if type(description.offset) is not int or not 0 <= description.offset <= _MAX_OFFSET:
                raise FormatError("invalid description")
            if description.identity is None:
                raise FormatError("invalid description")
        elif description.kind == "directory":
            if description.access != "read" or description.offset is not None or description.identity is None:
                raise FormatError("invalid description")
        elif description.kind in {"pipe", "socketpair"}:
            identity = description.identity
            if (
                description.offset is not None
                or type(identity) is not tuple
                or len(identity) != 2
                or type(identity[0]) is not object
                or type(identity[1]) is not int
                or identity[1] not in (0, 1)
            ):
                raise FormatError("invalid description")
            expected_access = "read_write" if description.kind == "socketpair" else ("read" if identity[1] == 0 else "write")
            if description.access != expected_access:
                raise FormatError("invalid description")
        else:
            raise FormatError("invalid description")
        return description

    def _validate_pair_peer(self, fds, description):
        token, endpoint = description.identity
        peer = None
        for value in fds.values():
            candidate = value[0]
            if candidate is description:
                continue
            if type(candidate) is not _OpenDescription:
                continue
            candidate = self._typed_description(candidate)
            if candidate.kind != description.kind or candidate.identity[0] is not token:
                continue
            if candidate.identity[1] == endpoint:
                raise FormatError("invalid pair peer")
            if peer is not None and peer is not candidate:
                raise FormatError("ambiguous pair peer")
            peer = candidate

    def begin_syscall(self, *, tid, operation):
        if type(tid) is not int or tid <= 0:
            raise FormatError("invalid task")
        self._task(tid)
        if type(operation) is not tuple or len(operation) != 3:
            raise FormatError("invalid operation")
        name, category, arguments = operation
        if type(name) is not str or not name:
            raise FormatError("invalid operation name")
        if type(category) is not str or category not in {
            "pure",
            "path",
            "fd",
            "mapping",
            "data",
            "lifecycle",
            "cwd_root",
            "exec",
            "mutation",
        }:
            raise FormatError("invalid operation category")
        if type(arguments) is not tuple or len(arguments) != 6:
            raise FormatError("invalid operation arguments")
        if any(type(value) is not int or not 0 <= value < 2**64 for value in arguments):
            raise FormatError("invalid operation argument")
        if tid in self._pending:
            raise FormatError("pending syscall exists")
        self._pending[tid] = operation

    def finish_syscall(self, *, tid, outcome):
        if type(tid) is not int or tid <= 0:
            raise FormatError("invalid task")
        self._task(tid)
        try:
            operation = self._pending[tid]
        except KeyError as exc:
            raise FormatError("no pending syscall") from exc
        if type(outcome) is not str or outcome not in {"success", "failure", "restart"}:
            raise FormatError("invalid syscall outcome")
        if outcome == "restart":
            return
        if operation[1] != "pure":
            raise FormatError("product syscall cannot finish")
        del self._pending[tid]

    def finish_close_syscall(self, *, tid, result, errno):
        fds, pending, owner_index = self._owner_for_fd_table_mutator(tid)
        name, arguments = self._validate_fd_table_mutator_operation(pending)
        if name != "close":
            raise FormatError("invalid pending syscall")
        fd = arguments[0]

        success = type(result) is int and result == 0 and errno is None
        failure = type(result) is int and result == -1 and type(errno) is int and errno in {
            4,
            5,
            9,
            28,
            122,
        }
        if not success and not failure:
            raise FormatError("invalid close outcome")

        present = fd in fds
        if success or (failure and errno in {4, 5, 28, 122}):
            if not present:
                raise FormatError("unknown FD")
        elif present:
            raise FormatError("present FD")

        receipt = (pending, result, errno)
        if success or (failure and errno != 9):
            self.close(tid=tid, fd=fd)
        del self._pending[tid]
        del self._fd_table_mutators[owner_index]
        return receipt

    def finish_dup2_syscall(self, *, tid, result, errno):
        fds, pending, owner_index = self._owner_for_fd_table_mutator(tid)
        name, arguments = self._validate_fd_table_mutator_operation(pending)
        if name != "dup2":
            raise FormatError("invalid pending syscall")
        oldfd, newfd = arguments[:2]

        success = type(result) is int and result == newfd and errno is None
        failure = type(result) is int and result == -1 and type(errno) is int and errno in {
            4,
            9,
            16,
            24,
        }
        if not success and not failure:
            raise FormatError("invalid dup2 outcome")
        if success:
            try:
                fds[oldfd]
            except (KeyError, TypeError) as exc:
                raise FormatError("unknown source FD") from exc

        receipt = (pending, result, errno)
        if success:
            self.dup2(tid=tid, source_fd=oldfd, target_fd=newfd)
        del self._pending[tid]
        del self._fd_table_mutators[owner_index]
        return receipt

    def finish_dup_syscall(self, *, tid, result, errno):
        fds, pending, owner_index = self._owner_for_fd_table_mutator(tid)
        name, arguments = self._validate_fd_table_mutator_operation(pending)
        if name != "dup":
            raise FormatError("invalid pending syscall")
        oldfd = arguments[0]

        success = type(result) is int and 0 <= result <= 2**31 - 1 and errno is None
        failure = type(result) is int and result == -1 and type(errno) is int and errno in {9, 24}
        if not success and not failure:
            raise FormatError("invalid dup outcome")

        source_present = oldfd in fds
        if success:
            if not source_present:
                raise FormatError("unknown source FD")
            if result in fds:
                raise FormatError("occupied result FD")
            lowest = 0
            while lowest in fds:
                lowest += 1
            if result != lowest:
                raise FormatError("non-lowest result FD")
        elif errno == 9 and source_present:
            raise FormatError("present source FD")
        elif errno == 24 and not source_present:
            raise FormatError("unknown source FD")

        receipt = (pending, result, errno)
        if success:
            self.dup2(tid=tid, source_fd=oldfd, target_fd=result)
        del self._pending[tid]
        del self._fd_table_mutators[owner_index]
        return receipt

    def _task(self, tid):
        try:
            return self._tasks[tid]
        except (KeyError, TypeError) as exc:
            raise FormatError("unknown task") from exc

    def spawn(self, *, parent_tid, child_tid, share_files, share_fs, share_vm, thread_group):
        parent = self._task(parent_tid)
        try:
            if child_tid in self._tasks:
                raise FormatError("duplicate task")
        except TypeError as exc:
            raise FormatError("invalid child task") from exc
        child = {
            "tgid": parent["tgid"] if thread_group else child_tid,
            "fds": parent["fds"] if share_files else dict(parent["fds"]),
            "fs": parent["fs"] if share_fs else dict(parent["fs"]),
            "maps": parent["maps"] if share_vm else dict(parent["maps"]),
        }
        self._tasks[child_tid] = child

    def exec_event(self, *, tid, mappings):
        if type(tid) is not int or tid <= 0:
            raise FormatError("invalid task")
        task = self._task(tid)
        if task["tgid"] != tid or any(
            other_tid != tid and other["tgid"] == tid for other_tid, other in self._tasks.items()
        ):
            raise FormatError("invalid exec task")
        fds = self._fd_table(tid)
        if type(mappings) is not dict:
            raise FormatError("invalid mapping table")
        ranges = []
        for start, value in mappings.items():
            if type(start) is not int or type(value) is not tuple or len(value) != 5:
                raise FormatError("invalid mapping")
            length, _node, offset, _prot, shared = value
            if (
                type(length) is not int
                or type(offset) is not int
                or type(shared) is not bool
                or start < 0
                or offset < 0
                or length <= 0
                or start >= 2**64
                or start + length > 2**64
            ):
                raise FormatError("invalid mapping")
            end = start + length
            if any(start < existing_end and existing_start < end for existing_start, existing_end in ranges):
                raise FormatError("overlapping mapping")
            ranges.append((start, end))
        retained_fds = {fd: value for fd, value in fds.items() if not value[1]}
        self._tasks[tid] = {
            "tgid": task["tgid"],
            "fds": retained_fds,
            "fs": task["fs"],
            "maps": dict(mappings),
        }

    def dup2(self, *, tid, source_fd, target_fd):
        fds = self._fd_table(tid)
        if (
            type(source_fd) is not int
            or source_fd < 0
            or type(target_fd) is not int
            or target_fd < 0
        ):
            raise FormatError("invalid FD")
        try:
            source = fds[source_fd]
        except (KeyError, TypeError) as exc:
            raise FormatError("unknown source FD") from exc
        if source_fd != target_fd:
            fds[target_fd] = (source[0], False)

    def close(self, *, tid, fd):
        fds = self._fd_table(tid)
        if type(fd) is not int or fd < 0:
            raise FormatError("invalid FD")
        try:
            del fds[fd]
        except (KeyError, TypeError) as exc:
            raise FormatError("unknown FD") from exc

    def install_open_fd(self, *, tid, fd, node, kind, access, cloexec):
        fds = self._fd_table(tid)
        if type(fd) is not int or fd < 0 or fd in fds:
            raise FormatError("invalid target FD")
        if type(kind) is not str or type(access) is not str or type(cloexec) is not bool:
            raise FormatError("invalid open description")
        if node is None:
            raise FormatError("invalid open node")
        if kind == "regular":
            if access not in {"read", "write", "read_write"}:
                raise FormatError("invalid open description")
            description = _OpenDescription(kind, access, 0, node)
        elif kind == "directory":
            if access != "read":
                raise FormatError("invalid open description")
            description = _OpenDescription(kind, access, None, node)
        else:
            raise FormatError("invalid open description")
        fds[fd] = (description, cloexec)

    def install_local_pair(self, *, tid, first_fd, second_fd, kind, cloexec):
        fds = self._fd_table(tid)
        if (
            type(first_fd) is not int
            or first_fd < 0
            or type(second_fd) is not int
            or second_fd < 0
            or first_fd == second_fd
            or first_fd in fds
            or second_fd in fds
        ):
            raise FormatError("invalid pair FD")
        if type(kind) is not str or kind not in {"pipe", "socketpair"} or type(cloexec) is not bool:
            raise FormatError("invalid local pair")
        token = object()
        access = "read_write" if kind == "socketpair" else None
        first_access = access or "read"
        second_access = access or "write"
        fds.update(
            {
                first_fd: (_OpenDescription(kind, first_access, None, (token, 0)), cloexec),
                second_fd: (_OpenDescription(kind, second_access, None, (token, 1)), cloexec),
            }
        )

    def apply_io_offset(self, *, tid, fd, direction, count, position):
        fds = self._fd_table(tid)
        if type(fd) is not int or fd < 0:
            raise FormatError("invalid FD")
        if type(direction) is not str or direction not in {"read", "write"}:
            raise FormatError("invalid I/O direction")
        if type(count) is not int or not 0 <= count <= _MAX_OFFSET:
            raise FormatError("invalid I/O count")
        if position is not None and (type(position) is not int or not 0 <= position <= _MAX_OFFSET):
            raise FormatError("invalid I/O position")
        try:
            description = self._typed_description(fds[fd][0])
        except KeyError as exc:
            raise FormatError("unknown FD") from exc
        if description.kind == "directory":
            raise FormatError("directory I/O unsupported")
        if description.access != "read_write" and direction != description.access:
            raise FormatError("I/O access mismatch")
        if description.kind in {"pipe", "socketpair"}:
            if position is not None:
                raise FormatError("positional pair I/O")
            self._validate_pair_peer(fds, description)
            return
        if position is None:
            if count > _MAX_OFFSET - description.offset:
                raise FormatError("I/O offset overflow")
            description.offset += count
        elif count > _MAX_OFFSET - position:
            raise FormatError("I/O position overflow")

    def set_cwd(self, *, tid, node):
        self._task(tid)["fs"]["cwd"] = node

    def set_umask(self, *, tid, value):
        task = self._task(tid)
        if type(value) is not int or not 0 <= value <= 0o777:
            raise FormatError("invalid umask")
        task["fs"]["umask"] = value

    def map_file(self, *, tid, start, length, node, offset, prot, shared):
        task = self._task(tid)
        if length <= 0 or start < 0 or offset < 0:
            raise FormatError("invalid mapping range")
        end = start + length
        for existing_start, existing in task["maps"].items():
            existing_end = existing_start + existing[0]
            if start < existing_end and existing_start < end:
                raise FormatError("overlapping mapping")
        task["maps"][start] = (length, node, offset, prot, shared)

    def snapshot(self, *, tid):
        task = self._task(tid)
        fs = task["fs"]
        return {
            "tgid": task["tgid"],
            "fds": dict(task["fds"]),
            "cwd": fs["cwd"],
            "root": fs["root"],
            "umask": fs["umask"],
            "maps": dict(task["maps"]),
        }


_REGULAR = {
    "repo",
    "vendor",
    "stable-sysroot",
    "nightly-sysroot",
    "tool",
    "dynamic",
}
_SPECIAL = {"host-config", "lane09-base", "lane09-package"}
_DIGEST = _re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = _re.compile(r"0|[1-9][0-9]*\Z")
_SEQ = _DECIMAL
_MODE = _re.compile(r"[0-7]{4}\Z")
_MAX_BYTES = 4 * 1024 * 1024


def _validate_locator(locator):
    try:
        raw = locator.encode("utf-8")
    except UnicodeError as exc:
        raise FormatError("locator is not UTF-8") from exc
    if not 1 <= len(raw) <= 4096:
        raise FormatError("invalid locator length")
    prefix = next((value for value in ("repo:/", "vendor:/", "external:/") if locator.startswith(value)), None)
    if prefix is None:
        raise FormatError("invalid locator namespace")
    tail = locator[len(prefix) :]
    if not tail:
        return prefix[:-1]
    for component in tail.split("/"):
        encoded = component.encode("utf-8")
        if not 1 <= len(encoded) <= 255 or component in (".", ".."):
            raise FormatError("invalid locator component")
        if any(_unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in component):
            raise FormatError("invalid locator code point")
    return prefix[:-1]


def _validate_records(records):
    if type(records) is not list or not 1 <= len(records) <= 4096:
        raise FormatError("records must be a bounded list")
    for record in records:
        if type(record) is not InputRecord:
            raise FormatError("non-InputRecord element")
        values = (record.klass, record.access, record.result, record.locator)
        if type(record.seq) is not int or any(type(value) is not str for value in values):
            raise FormatError("invalid scalar type")
        if record.mode is not None and type(record.mode) is not int:
            raise FormatError("invalid mode type")
        if record.size is not None and type(record.size) is not int:
            raise FormatError("invalid size type")
        if record.sha256 is not None and type(record.sha256) is not str:
            raise FormatError("invalid digest type")

    previous = None
    for index, record in enumerate(records):
        if record.seq != index or record.seq > 4095:
            raise FormatError("invalid sequence")
        namespace = _validate_locator(record.locator)
        locator_bytes = record.locator.encode("utf-8")
        if previous is not None and locator_bytes <= previous:
            raise FormatError("locators are not strictly ordered")
        previous = locator_bytes
        if record.klass == "repo" and namespace != "repo:":
            raise FormatError("repo namespace mismatch")
        if record.klass == "vendor" and namespace != "vendor:":
            raise FormatError("vendor namespace mismatch")
        if record.klass in (_REGULAR | _SPECIAL) - {"repo", "vendor"} and namespace != "external:":
            raise FormatError("external namespace mismatch")
        if record.klass in _REGULAR:
            valid = record.access in {"probe", "read", "execute", "read-execute"}
        elif record.klass in _SPECIAL:
            valid = record.access in {"probe", "read"}
        elif record.klass == "directory":
            valid = record.access in {"probe", "enumerate"}
        elif record.klass == "symlink":
            valid = record.access == "probe"
        elif record.klass == "absent":
            valid = record.access == "probe" and record.result in {"ENOENT", "ENOTDIR"}
        else:
            valid = False
        if not valid:
            raise FormatError("invalid class/access matrix")
        present = record.klass != "absent"
        if present:
            if record.result != "present":
                raise FormatError("invalid present result")
            if record.mode is None or not 0 <= record.mode <= 0o7777:
                raise FormatError("invalid mode")
            if record.size is None or not 0 <= record.size <= 4294967296:
                raise FormatError("invalid size")
            if record.klass == "symlink" and not 1 <= record.size <= 4096:
                raise FormatError("invalid symlink size")
            if record.klass == "directory" and record.size > _MAX_BYTES:
                raise FormatError("invalid directory size")
            if record.sha256 is None or _DIGEST.fullmatch(record.sha256) is None:
                raise FormatError("invalid digest")
        elif any(value is not None for value in (record.mode, record.size, record.sha256)):
            raise FormatError("absent record has values")


def parse_ledger(data: bytes) -> list[InputRecord]:
    if type(data) is not bytes or not 1 <= len(data) <= _MAX_BYTES:
        raise FormatError("invalid input-v1 container")
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data or b"\0" in data or not data.endswith(b"\n"):
        raise FormatError("invalid input-v1 framing")
    rows = data[:-1].split(b"\n")
    if not 1 <= len(rows) <= 4096 or any(not row for row in rows):
        raise FormatError("invalid input-v1 rows")
    records = []
    try:
        for row in rows:
            fields = row.decode("utf-8").split("\t")
            if len(fields) != 9 or fields[0] != "input-v1":
                raise FormatError("invalid input-v1 row")
            _, seq, klass, access, result, mode, size, digest, locator = fields
            if _SEQ.fullmatch(seq) is None:
                raise FormatError("invalid sequence spelling")
            if mode == "-":
                parsed_mode = None
            elif _MODE.fullmatch(mode) is not None:
                parsed_mode = int(mode, 8)
            else:
                raise FormatError("invalid mode spelling")
            if size == "-":
                parsed_size = None
            elif _DECIMAL.fullmatch(size) is not None:
                parsed_size = int(size)
            else:
                raise FormatError("invalid size spelling")
            parsed_digest = None if digest == "-" else digest
            records.append(InputRecord(int(seq), klass, access, result, parsed_mode, parsed_size, parsed_digest, locator))
    except (UnicodeError, ValueError) as exc:
        raise FormatError("invalid input-v1 encoding") from exc
    _validate_records(records)
    if encode_ledger(records) != data:
        raise FormatError("non-canonical input-v1")
    return records


def encode_ledger(records: list[InputRecord]) -> bytes:
    _validate_records(records)
    chunks = []
    for record in records:
        values = (
            "input-v1",
            str(record.seq),
            record.klass,
            record.access,
            record.result,
            "-" if record.mode is None else f"{record.mode:04o}",
            "-" if record.size is None else str(record.size),
            "-" if record.sha256 is None else record.sha256,
            record.locator,
        )
        chunks.append(("\t".join(values) + "\n").encode("utf-8"))
    data = b"".join(chunks)
    if len(data) > _MAX_BYTES:
        raise FormatError("input-v1 exceeds 4 MiB")
    return data


def _component(value):
    if not 1 <= len(value) <= 255 or value in (b".", b"..") or b"/" in value or b"\0" in value:
        raise FormatError("invalid path component")
    try:
        text = value.decode("utf-8")
    except UnicodeError as exc:
        raise FormatError("path is not UTF-8") from exc
    if any(_unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in text):
        raise FormatError("invalid path code point")
    return value


def _path(value, name):
    try:
        value = os.fspath(value)
    except TypeError as exc:
        raise FormatError(f"invalid {name}") from exc
    if type(value) is not str or not value.startswith("/") or value != os.path.normpath(value) or "//" in value:
        raise FormatError(f"non-canonical {name}")
    try:
        raw = value.encode("utf-8")
    except UnicodeError as exc:
        raise FormatError(f"invalid {name}") from exc
    parts = tuple(_component(part) for part in raw.split(b"/") if part)
    return parts


def _relative(value):
    if type(value) is not str or not value or value.startswith("/") or value.endswith("/") or value != os.path.normpath(value):
        raise FormatError("invalid vendor_relative")
    try:
        raw = value.encode("utf-8")
    except UnicodeError as exc:
        raise FormatError("invalid vendor_relative") from exc
    return tuple(_component(part) for part in raw.split(b"/"))


def _identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _structural(value):
    return (value.st_dev, value.st_ino, _stat.S_IFMT(value.st_mode))


def _quoted(value):
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise FormatError("invalid quoted path")
    raw = value[1:-1]
    output = bytearray()
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != "\\":
            code = ord(char)
            if code < 0x20 or code > 0x7e:
                raise FormatError("invalid quoted path byte")
            output.append(code)
            index += 1
            continue
        if raw.startswith("\\x", index) and index + 4 <= len(raw):
            try:
                output.append(int(raw[index + 2 : index + 4], 16))
            except ValueError as exc:
                raise FormatError("invalid hex escape") from exc
            index += 4
        elif index + 1 < len(raw) and raw[index + 1] in {'"', "\\"}:
            output.append(ord(raw[index + 1]))
            index += 2
        else:
            raise FormatError("invalid path escape")
    if not output or b"\0" in output:
        raise FormatError("invalid empty path")
    return bytes(output)


def _payload(value):
    raw = value[1:-1]
    index = 0
    while index < len(raw):
        code = ord(raw[index])
        if raw[index] != "\\":
            if code < 0x20 or code > 0x7e:
                raise FormatError("invalid payload byte")
            index += 1
        elif raw.startswith("\\x", index) and index + 4 <= len(raw):
            try:
                int(raw[index + 2 : index + 4], 16)
            except ValueError as exc:
                raise FormatError("invalid payload hex escape") from exc
            index += 4
        elif index + 1 < len(raw) and raw[index + 1] in {'"', "\\", "a", "b", "f", "n", "r", "t", "v"}:
            index += 2
        else:
            raise FormatError("invalid payload escape")


def _beneath(parts, root):
    return len(parts) >= len(root) and parts[: len(root)] == root


def _locator(parts, repo, vendor):
    if _beneath(parts, vendor):
        prefix, tail = "vendor:/", parts[len(vendor) :]
    elif _beneath(parts, repo):
        prefix, tail = "repo:/", parts[len(repo) :]
    else:
        prefix, tail = "external:/", parts
    text = prefix + "/".join(part.decode("utf-8") for part in tail)
    _validate_locator(text)
    return text


def discover_input_v1(
    trace: bytes,
    *,
    root_pid: int,
    initial_cwd,
    repo_root,
    vendor_relative: str,
    build_root,
    stable_sysroot_root,
    nightly_sysroot_root,
) -> bytes:
    if type(trace) is not bytes or type(root_pid) is not int or root_pid <= 0:
        raise FormatError("invalid discovery scalar")
    cwd_parts = _path(initial_cwd, "initial_cwd")
    repo_parts = _path(repo_root, "repo_root")
    build_parts = _path(build_root, "build_root")
    stable_parts = _path(stable_sysroot_root, "stable_sysroot_root")
    nightly_parts = _path(nightly_sysroot_root, "nightly_sysroot_root")
    vendor_tail = _relative(vendor_relative)
    vendor_parts = repo_parts + vendor_tail
    supplied = (repo_parts, build_parts, stable_parts, nightly_parts)
    for index, left in enumerate(supplied):
        for right in supplied[index + 1 :]:
            if _beneath(left, right) or _beneath(right, left):
                raise MutationError("anchor paths overlap")
    if not trace.endswith(b"\n") or any(byte < 0x20 and byte != 0x0A for byte in trace):
        raise FormatError("invalid trace framing")
    try:
        text = trace.decode("ascii")
    except UnicodeError as exc:
        raise FormatError("trace is not ASCII") from exc
    lines = text[:-1].split("\n")
    if not lines or any(not line for line in lines):
        raise FormatError("empty trace")

    held = []
    edges = []
    cache = {}
    observations = {}
    absent = []
    created = {}

    def close_all():
        for fd in reversed(held):
            try:
                os.close(fd)
            except OSError:
                pass

    def validate_binding(node):
        evidence = node.get("evidence")
        if node["parent"] is None:
            held_value = os.fstat(node["fd"])
            if evidence is None:
                if _structural(held_value) != node["structural"]:
                    raise MutationError("retained root changed")
            elif _identity(held_value) != evidence:
                raise MutationError("retained root changed")
            return
        try:
            edge_value = os.stat(node["name"], dir_fd=node["parent"]["fd"], follow_symlinks=False)
        except OSError as exc:
            raise MutationError("retained edge disappeared") from exc
        held_value = os.fstat(node["fd"])
        if evidence is None:
            expected = node["structural"]
            if _structural(edge_value) != expected or _structural(held_value) != expected:
                raise MutationError("retained edge changed")
        elif _identity(edge_value) != evidence or _identity(held_value) != evidence:
            raise MutationError("retained edge changed")

    def open_edge(parent, name, expected=None):
        key = (parent["fd"], name)
        if key in cache:
            node = cache[key]
            validate_binding(node)
            if expected is not None and node["kind"] != expected:
                raise MutationError("relation kind changed")
            return node
        try:
            before = os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise MutationError("claimed relation is absent") from exc
        mode = before.st_mode
        if _stat.S_ISDIR(mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            kind = "directory"
        elif _stat.S_ISREG(mode):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            kind = "regular"
        elif _stat.S_ISLNK(mode):
            flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
            kind = "symlink"
        else:
            raise FormatError("special file in relation")
        try:
            fd = os.open(name, flags, dir_fd=parent["fd"])
        except OSError as exc:
            raise MutationError("relation open failed") from exc
        held.append(fd)
        after = os.fstat(fd)
        if _structural(before) != _structural(after):
            raise MutationError("relation changed while opening")
        node = {
            "parts": parent["parts"] + (name,),
            "fd": fd,
            "stat": _identity(after),
            "pending_acquired": _identity(before),
            "structural": _structural(after),
            "kind": kind,
            "parent": parent,
            "name": name,
            "evidence": None,
        }
        cache[key] = node
        edges.append(node)
        if expected is not None and kind != expected:
            raise MutationError("relation kind mismatch")
        return node

    def anchor(parts):
        node = root_node
        for name in parts:
            node = open_edge(node, name, "directory")
            node.pop("pending_acquired", None)
        return node

    def capture_evidence(node):
        if node.get("logical"):
            return
        if node["evidence"] is not None:
            validate_binding(node)
            return
        if node["parent"] is None:
            value = _identity(os.fstat(node["fd"]))
        else:
            edge_value = _identity(os.stat(node["name"], dir_fd=node["parent"]["fd"], follow_symlinks=False))
            held_value = _identity(os.fstat(node["fd"]))
            pending = node.pop("pending_acquired", None)
            if edge_value != held_value or (pending is not None and edge_value != pending):
                raise MutationError("relation changed while evidencing")
            value = held_value
        node["evidence"] = value

    def observe(node, access, expected=None):
        if node.get("logical"):
            return
        if expected is not None and node["kind"] != expected:
            raise MutationError("trace kind differs from resolved object")
        capture_evidence(node)
        observations.setdefault(node["parts"], [node, set()])[1].add(access)

    def canonical_absence(base, floor, suffix, outcome):
        parts = list(base)
        for token in suffix:
            if not token or token == b".":
                continue
            if token == b"..":
                if len(parts) <= len(floor):
                    raise FormatError("absence suffix crosses floor")
                parts.pop()
                continue
            parts.append(_component(token))
        if outcome == "ENOTDIR" and tuple(parts) == floor:
            raise FormatError("absence ends at blocker floor")
        return tuple(parts)

    def read_symlink(node):
        if "target" in node:
            return node["target"]
        first = os.readlink(node["name"], dir_fd=node["parent"]["fd"])
        edge1 = _identity(os.stat(node["name"], dir_fd=node["parent"]["fd"], follow_symlinks=False))
        held1 = _identity(os.fstat(node["fd"]))
        if edge1 != node["evidence"] or held1 != node["evidence"]:
            raise MutationError("symlink changed after first read")
        second = os.readlink(node["name"], dir_fd=node["parent"]["fd"])
        edge2 = _identity(os.stat(node["name"], dir_fd=node["parent"]["fd"], follow_symlinks=False))
        held2 = _identity(os.fstat(node["fd"]))
        first = os.fsencode(first)
        second = os.fsencode(second)
        if edge2 != node["evidence"] or held2 != node["evidence"] or first != second:
            raise MutationError("symlink changed during observation")
        if not 1 <= len(first) <= 4096:
            raise FormatError("invalid symlink target length")
        node["target"] = first
        return first

    def resolve(start, requested, replay=None):
        if requested.startswith(b"/"):
            node = root_node
            tokens = requested.split(b"/")
        else:
            node = start
            tokens = requested.split(b"/")
        index = 0
        links = []
        follows = 0
        while index < len(tokens):
            name = tokens[index]
            index += 1
            if not name or name == b".":
                continue
            if name == b"..":
                node = node["parent"] if node["parent"] is not None else root_node
                continue
            if node["kind"] != "directory":
                if replay is not None and node is replay["boundary"]:
                    validate_binding(node)
                    return replay["errno"], node, replay["resolved"], links, replay.get("missing_name")
                suffix = (name,) + tuple(tokens[index:])
                resolved = canonical_absence(node["parts"], node["parts"], suffix, "ENOTDIR")
                capture_evidence(node)
                return "ENOTDIR", node, resolved, links, None
            key = (node["fd"], name)
            child = created.get(key)
            if child is None:
                if key in cache:
                    child = cache[key]
                    if replay is None:
                        validate_binding(child)
                elif replay is not None:
                    if replay["errno"] == "ENOENT" and node is replay["boundary"] and name == replay["missing_name"]:
                        validate_binding(node)
                        try:
                            os.stat(name, dir_fd=node["fd"], follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        except OSError as exc:
                            raise MutationError("absence relation changed") from exc
                        else:
                            raise MutationError("absence relation appeared")
                        return replay["errno"], node, replay["resolved"], links, replay.get("missing_name")
                    raise MutationError("absence replay acquired relation")
                else:
                    try:
                        os.stat(name, dir_fd=node["fd"], follow_symlinks=False)
                    except FileNotFoundError:
                        suffix = tuple(tokens[index:])
                        floor = node["parts"] + (name,)
                        resolved = canonical_absence(floor, floor, suffix, "ENOENT")
                        if not _beneath(resolved, build_parts):
                            capture_evidence(node)
                        return "ENOENT", node, resolved, links, name
                    except NotADirectoryError as exc:
                        raise MutationError("directory relation changed") from exc
                    child = open_edge(node, name)
            if child["kind"] == "symlink":
                if replay is not None and not any(child is link for link in replay["links"]):
                    raise MutationError("absence replay symlink chain changed")
                follows += 1
                if follows > 40:
                    raise FormatError("symlink depth exceeded")
                capture_evidence(child)
                target = read_symlink(child)
                links.append(child)
                tokens = tuple(target.split(b"/")) + tuple(tokens[index:])
                node = root_node if target.startswith(b"/") else child["parent"]
                index = 0
                continue
            if index < len(tokens) and child["kind"] != "directory":
                if replay is not None and child is replay["boundary"]:
                    validate_binding(child)
                    return replay["errno"], child, replay["resolved"], links, replay.get("missing_name")
                suffix = tuple(tokens[index:])
                resolved = canonical_absence(child["parts"], child["parts"], suffix, "ENOTDIR")
                capture_evidence(child)
                return "ENOTDIR", child, resolved, links, None
            if index < len(tokens):
                child.pop("pending_acquired", None)
            node = child
        if replay is not None and replay["errno"] != "present":
            raise MutationError("absence replay result changed")
        if node.get("logical"):
            return "present", node, node["parts"], links, None
        capture_evidence(node)
        return "present", node, node["parts"], links, None

    try:
        root_fd = os.open(b"/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        held.append(root_fd)
        root_stat = os.fstat(root_fd)
        root_node = {
            "parts": (),
            "fd": root_fd,
            "stat": _identity(root_stat),
            "structural": _structural(root_stat),
            "kind": "directory",
            "parent": None,
            "name": None,
            "evidence": None,
        }
        cwd_node = anchor(cwd_parts)
        repo_node = anchor(repo_parts)
        build_node = anchor(build_parts)
        stable_node = anchor(stable_parts)
        nightly_node = anchor(nightly_parts)
        vendor_node = repo_node
        for name in vendor_tail:
            vendor_node = open_edge(vendor_node, name, "directory")
            vendor_node.pop("pending_acquired", None)
        named_anchors = (("repo", repo_node), ("build", build_node), ("stable", stable_node), ("nightly", nightly_node), ("vendor", vendor_node))
        lineages = {}
        for name, node in named_anchors:
            lineage = []
            while node is not None:
                lineage.append(node["stat"][:2])
                node = node["parent"]
            lineages[name] = lineage
        for index, (left_name, left) in enumerate(named_anchors):
            for right_name, right in named_anchors[index + 1 :]:
                overlap = left["stat"][:2] in lineages[right_name] or right["stat"][:2] in lineages[left_name]
                vendor_beneath_repo = left_name == "repo" and right_name == "vendor" and left["stat"][:2] != right["stat"][:2] and left["stat"][:2] in lineages["vendor"][1:] and right["stat"][:2] not in lineages["repo"]
                if overlap and not vendor_beneath_repo:
                    raise MutationError("anchor identities or lineages overlap")
        os.lseek(build_node["fd"], 0, os.SEEK_SET)
        if os.listdir(build_node["fd"]):
            raise MutationError("build root is not empty")

        descriptions = []
        processes = {root_pid: {"cwd": cwd_node, "fds": {}, "maps": {}, "alive": True}}

        def process(pid_text):
            pid = int(pid_text)
            value = processes.get(pid)
            if value is None or not value["alive"]:
                raise FormatError("unknown trace pid")
            return pid, value

        def base_for(proc, token, raw):
            if raw.startswith(b"/"):
                return root_node
            if token == "AT_FDCWD":
                return proc["cwd"]
            fd = int(token)
            ref = proc["fds"].get(fd)
            if ref is None:
                raise FormatError("unknown dirfd")
            desc = descriptions[ref[0]]
            if desc["kind"] != "directory":
                raise FormatError("non-directory dirfd")
            return desc["node"]

        def opened(proc, token, quoted, flags_text, mode_text, result_text):
            raw = _quoted(quoted)
            base = base_for(proc, token, raw)
            flags = flags_text.split("|")
            allowed = {"O_RDONLY", "O_WRONLY", "O_RDWR", "O_CLOEXEC", "O_DIRECTORY", "O_CREAT", "O_EXCL"}
            if not flags or len(flags) != len(set(flags)) or any(flag not in allowed for flag in flags):
                raise FormatError("invalid open flags")
            access = [flag for flag in flags if flag in {"O_RDONLY", "O_WRONLY", "O_RDWR"}]
            if len(access) != 1:
                raise FormatError("invalid open access")
            fd = int(result_text)
            if fd in proc["fds"]:
                raise FormatError("live fd overwritten")
            create = "O_CREAT" in flags or "O_EXCL" in flags
            if create != ("O_CREAT" in flags and "O_EXCL" in flags):
                raise FormatError("invalid exclusive output")
            if (mode_text is not None) != create or (create and mode_text != "0600"):
                raise FormatError("open mode presence mismatch")
            outcome, node, parts, links, missing_name = resolve(base, raw)
            logical = False
            if create:
                if outcome == "present" and node.get("logical"):
                    raise FormatError("duplicate exclusive output")
                if outcome != "ENOENT" or node["kind"] != "directory" or not parts:
                    raise MutationError("exclusive output already exists")
                leaf = parts[-1]
                if tuple(parts[:-1]) != node["parts"] or not _beneath(node["parts"], build_parts):
                    raise MutationError("output parent is absent")
                key = (node["fd"], leaf)
                if key in created:
                    raise FormatError("duplicate exclusive output")
                created[key] = {
                    "parts": tuple(parts),
                    "kind": "regular",
                    "logical": True,
                    "parent": node,
                    "name": leaf,
                }
                node = created[key]
                logical = True
            elif outcome != "present":
                raise MutationError("opened path is absent")
            elif _beneath(parts, build_parts) and not node.get("logical"):
                raise FormatError("unowned build input")
            directory = "O_DIRECTORY" in flags
            if directory and node["kind"] != "directory":
                raise MutationError("invalid directory open target")
            if directory and (create or access[0] != "O_RDONLY"):
                raise FormatError("invalid directory open access")
            if not directory and node["kind"] != "regular":
                raise MutationError("opened path is not regular")
            desc = {
                "parts": parts,
                "node": node,
                "kind": node["kind"],
                "readable": access[0] in {"O_RDONLY", "O_RDWR"},
                "writable": access[0] in {"O_WRONLY", "O_RDWR"},
                "owned": logical or node.get("logical", False),
                "seen": False,
                "eof": False,
            }
            descriptions.append(desc)
            proc["fds"][fd] = (len(descriptions) - 1, "O_CLOEXEC" in flags)
            if directory:
                if not desc["owned"]:
                    observe(node, "probe", "directory")
            elif not desc["owned"]:
                observe(node, "probe", "regular")

        quote = r'"(?:[^"\\]|\\.)*"'
        for line in lines:
            match = _re.fullmatch(r"([0-9]+) openat\((AT_FDCWD|[0-9]+), (" + quote + r"), ([A-Z0-9_|]+)(?:, ([0-7]+))?\) = ([0-9]+)", line)
            if match:
                _, proc = process(match[1])
                opened(proc, match[2], match[3], match[4], match[5], match[6])
                continue
            match = _re.fullmatch(r"([0-9]+) open\((" + quote + r"), ([A-Z0-9_|]+)(?:, ([0-7]+))?\) = ([0-9]+)", line)
            if match:
                _, proc = process(match[1])
                opened(proc, "AT_FDCWD", match[2], match[3], match[4], match[5])
                continue
            match = _re.fullmatch(r"([0-9]+) openat2\((AT_FDCWD|[0-9]+), (" + quote + r"), \{ flags=([A-Z0-9_|]+)(?:, mode=([0-7]+))?, resolve=0 \}, 24\) = ([0-9]+)", line)
            if match:
                _, proc = process(match[1])
                opened(proc, match[2], match[3], match[4], match[5], match[6])
                continue
            match = _re.fullmatch(r"([0-9]+) dup\(([0-9]+)\) = ([0-9]+)", line)
            if match:
                _, proc = process(match[1]); source, target = int(match[2]), int(match[3])
                if source not in proc["fds"] or target in proc["fds"]:
                    raise FormatError("invalid dup")
                proc["fds"][target] = (proc["fds"][source][0], False)
                continue
            match = _re.fullmatch(r"([0-9]+) clone\(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL\) = ([0-9]+)", line)
            if match:
                _, proc = process(match[1]); child = int(match[2])
                if child <= 0 or child in processes:
                    raise FormatError("invalid clone child")
                processes[child] = {"cwd": proc["cwd"], "fds": dict(proc["fds"]), "maps": dict(proc["maps"]), "alive": True}
                continue
            match = _re.fullmatch(r"([0-9]+) getpid\(\) = ([0-9]+)", line)
            if match:
                pid, _ = process(match[1])
                if pid != int(match[2]):
                    raise FormatError("getpid mismatch")
                continue
            match = _re.fullmatch(r"([0-9]+) close\(([0-9]+)\) = 0", line)
            if match:
                _, proc = process(match[1]); fd = int(match[2])
                if proc["fds"].pop(fd, None) is None:
                    raise FormatError("close of unknown fd")
                continue
            match = _re.fullmatch(r"([0-9]+) (read|write)\(([0-9]+), " + quote + r", ([0-9]+)\) = ([0-9]+)", line)
            if match:
                _payload(match[0][match[0].find('"') : match[0].rfind('"') + 1])
                _, proc = process(match[1]); operation, fd, count, result = match[2], int(match[3]), int(match[4]), int(match[5])
                ref = proc["fds"].get(fd)
                if ref is None or result > count:
                    raise FormatError("invalid IO")
                desc = descriptions[ref[0]]
                if operation == "read":
                    if not desc["readable"] or desc["kind"] == "directory":
                        raise FormatError("read on unreadable fd")
                    if not desc["owned"]:
                        observe(desc["node"], "read", "regular")
                elif not desc["writable"] or not desc["owned"]:
                    raise FormatError("write on unwritable input")
                continue
            match = _re.fullmatch(r"([0-9]+) mmap\(NULL, ([0-9]+), PROT_READ, MAP_PRIVATE, ([0-9]+), 0\) = ([0-9]+)", line)
            if match:
                _, proc = process(match[1]); length, fd, address = int(match[2]), int(match[3]), int(match[4])
                ref = proc["fds"].get(fd)
                if length <= 0 or ref is None or address in proc["maps"] or not descriptions[ref[0]]["readable"] or descriptions[ref[0]]["kind"] == "directory":
                    raise FormatError("invalid mmap")
                proc["maps"][address] = (length, ref[0])
                if not descriptions[ref[0]]["owned"]:
                    observe(descriptions[ref[0]]["node"], "mapped", "regular")
                continue
            match = _re.fullmatch(r"([0-9]+) munmap\(([0-9]+), ([0-9]+)\) = 0", line)
            if match:
                _, proc = process(match[1]); address, length = int(match[2]), int(match[3])
                if proc["maps"].get(address, (None,))[0] != length:
                    raise FormatError("invalid munmap")
                del proc["maps"][address]
                continue
            match = _re.fullmatch(r"([0-9]+) getdents64\(([0-9]+), 0x[0-9a-f]+, ([0-9]+)\) = ([0-9]+)", line)
            if match:
                _, proc = process(match[1]); fd, requested, result = int(match[2]), int(match[3]), int(match[4])
                ref = proc["fds"].get(fd)
                if ref is None or descriptions[ref[0]]["kind"] != "directory" or not descriptions[ref[0]]["readable"] or result > requested:
                    raise FormatError("invalid getdents64")
                desc = descriptions[ref[0]]
                if desc["eof"] and result:
                    raise FormatError("directory advanced after EOF")
                desc["seen"] = True
                if result == 0:
                    desc["eof"] = True
                if not desc["owned"]:
                    observe(desc["node"], "enumerate", "directory")
                continue
            match = _re.fullmatch(r"([0-9]+) fchdir\(([0-9]+)\) = 0", line)
            if match:
                _, proc = process(match[1]); ref = proc["fds"].get(int(match[2]))
                if ref is None or descriptions[ref[0]]["kind"] != "directory":
                    raise FormatError("invalid fchdir")
                proc["cwd"] = descriptions[ref[0]]["node"]
                continue
            match = _re.fullmatch(r"([0-9]+) newfstatat\((AT_FDCWD|[0-9]+), (" + quote + r"), 0x[0-9a-f]+, 0\) = (0|-1 (ENOENT|ENOTDIR) \([^\n]+\))", line)
            if match:
                _, proc = process(match[1]); raw = _quoted(match[3]); base = base_for(proc, match[2], raw)
                outcome, node, parts, links, missing_name = resolve(base, raw)
                if match[4] == "0":
                    if outcome != "present":
                        raise MutationError("successful stat path is absent")
                    if _beneath(parts, build_parts):
                        if node.get("logical"):
                            continue
                        raise FormatError("unowned build probe")
                    observe(node, "probe")
                else:
                    if outcome == "present":
                        if node.get("logical"):
                            raise FormatError("absent build output after creation")
                        raise MutationError("trace errno no longer matches")
                    if outcome != match[5]:
                        raise MutationError("trace errno no longer matches")
                    if _beneath(parts, build_parts):
                        if outcome == "ENOTDIR" and node.get("logical"):
                            continue
                        if outcome == "ENOENT":
                            absent.append({
                                "provisional": True,
                                "start": base,
                                "raw": raw,
                                "errno": outcome,
                                "boundary": node,
                                "resolved": parts,
                                "links": links,
                                "missing_name": missing_name,
                            })
                            continue
                        raise FormatError("unowned build absence")
                    absent.append({
                        "provisional": False,
                        "start": base,
                        "raw": raw,
                        "errno": outcome,
                        "boundary": node,
                        "resolved": parts,
                        "links": links,
                        "missing_name": missing_name,
                    })
                continue
            match = _re.fullmatch(r"([0-9]+) execve\((" + quote + r"), \[[^\n]*\], \[[^\n]*\]\) = 0", line)
            if match:
                _, proc = process(match[1]); raw = _quoted(match[2]); outcome, node, parts, links, _ = resolve(proc["cwd"], raw)
                if outcome != "present":
                    raise MutationError("executed path is absent")
                if _beneath(parts, build_parts) and not node.get("logical"):
                    raise FormatError("unowned executed output")
                if not node.get("logical"):
                    observe(node, "execute", "regular")
                proc["maps"].clear()
                proc["fds"] = {fd: ref for fd, ref in proc["fds"].items() if not ref[1]}
                continue
            match = _re.fullmatch(r"([0-9]+) \+\+\+ exited with [0-9]+ \+\+\+", line)
            if match:
                _, proc = process(match[1]); proc["fds"].clear(); proc["maps"].clear(); proc["alive"] = False
                continue
            raise FormatError("unknown trace line")
        if any(proc["alive"] for proc in processes.values()):
            raise FormatError("trace ended with live process")

        collected = {}
        access_by_locator = {}

        def directory_record(node, access):
            def scan():
                scan_fd = os.open(b".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=node["fd"])
                try:
                    entries = []
                    with os.scandir(scan_fd) as iterator:
                        for entry in iterator:
                            if len(entries) == 4096:
                                raise FormatError("directory has more than 4096 entries")
                            name = _component(os.fsencode(entry.name))
                            value = entry.stat(follow_symlinks=False)
                            if _stat.S_ISREG(value.st_mode):
                                kind = b"F"
                            elif _stat.S_ISDIR(value.st_mode):
                                kind = b"D"
                            elif _stat.S_ISLNK(value.st_mode):
                                kind = b"L"
                            else:
                                raise FormatError("special directory entry")
                            entries.append((name, kind))
                    entries.sort()
                    data = b"".join(kind + len(name).to_bytes(2, "big") + name for name, kind in entries)
                    if len(data) > _MAX_BYTES:
                        raise FormatError("directory listing exceeds 4 MiB")
                    return data
                finally:
                    os.close(scan_fd)
            s0 = _identity(os.fstat(node["fd"])); first = scan(); s1 = _identity(os.fstat(node["fd"])); second = scan(); s2 = _identity(os.fstat(node["fd"]))
            if s0 != s1 or s1 != s2 or first != second:
                raise MutationError("directory changed during collection")
            if node["evidence"] is not None and node["evidence"] != s0:
                raise MutationError("directory evidence changed")
            node["evidence"] = s0
            return access, s0[4] & 0o7777, len(first), _hashlib.sha256(first).hexdigest()

        def regular_record(node, access):
            def digest():
                value = _hashlib.sha256()
                while True:
                    chunk = os.read(node["fd"], 1024 * 1024)
                    if not chunk:
                        return value.hexdigest()
                    value.update(chunk)
            s0 = _identity(os.fstat(node["fd"])); h0 = digest(); s1 = _identity(os.fstat(node["fd"])); os.lseek(node["fd"], 0, os.SEEK_SET); h1 = digest(); s2 = _identity(os.fstat(node["fd"]))
            if s0 != s1 or s1 != s2 or h0 != h1 or not _stat.S_ISREG(s0[4]):
                raise MutationError("regular file changed during collection")
            if node["evidence"] is not None and node["evidence"] != s0:
                raise MutationError("regular file evidence changed")
            node["evidence"] = s0
            return access, s0[4] & 0o7777, s0[6], h0

        resolved_observations = {}
        for node, accesses in observations.values():
            locator = _locator(node["parts"], repo_parts, vendor_parts)
            current = resolved_observations.get(locator)
            if current is None:
                resolved_observations[locator] = [node, set(accesses)]
            else:
                if current[0]["stat"] != node["stat"] or current[0]["parts"] != node["parts"]:
                    raise MutationError("resolved locator identity conflict")
                current[1].update(accesses)

        for locator, (node, accesses) in resolved_observations.items():
            if "enumerate" in accesses:
                access = "enumerate"
            elif "read" in accesses or "mapped" in accesses:
                access = "read-execute" if "execute" in accesses else "read"
            elif "execute" in accesses:
                access = "execute"
            else:
                access = "probe"
            access_by_locator[locator] = accesses
            if node["kind"] == "directory":
                if access not in {"probe", "enumerate"}:
                    raise FormatError("invalid directory access")
                row = ("directory",) + directory_record(node, access)
            elif node["kind"] == "regular":
                row = (None,) + regular_record(node, access)
            else:
                raise FormatError("resolved path is not consumable")
            collected[locator] = row

        absent_proofs = []
        for proof in absent:
            if proof["provisional"]:
                output = created.get((proof["boundary"]["fd"], proof["resolved"][-1])) if proof["resolved"] else None
                if output is None or output["parts"] != tuple(proof["resolved"]):
                    raise FormatError("unowned build absence")
                continue
            outcome = proof["errno"]
            node = proof["boundary"]
            resolved = proof["resolved"]
            locator = _locator(resolved, repo_parts, vendor_parts)
            proof["locator"] = locator
            proof["boundary_evidence"] = node["evidence"]
            absent_proofs.append(proof)
            if outcome == "ENOENT":
                parent_locator = _locator(node["parts"], repo_parts, vendor_parts)
                if parent_locator not in collected:
                    collected[parent_locator] = ("directory",) + directory_record(node, "probe")
            else:
                blocker = node
                blocker_locator = _locator(blocker["parts"], repo_parts, vendor_parts)
                if blocker_locator not in collected:
                    collected[blocker_locator] = (None,) + regular_record(blocker, "probe")
            collected[locator] = ("absent", "probe", None, None, None, outcome)

        for node in edges:
            if node["kind"] != "symlink" or "target" not in node:
                continue
            locator = _locator(node["parts"], repo_parts, vendor_parts)
            raw = node["target"]
            collected[locator] = ("symlink", "probe", node["evidence"][4] & 0o7777, len(raw), _hashlib.sha256(raw).hexdigest())

        if len(collected) > 4096:
            raise FormatError("discovery produced too many records")

        # Every retained parent/name relation, including each anchor edge, must
        # still name the held child before any ledger bytes are returned.
        os.lseek(build_node["fd"], 0, os.SEEK_SET)
        if os.listdir(build_node["fd"]):
            raise MutationError("build root is not empty")

        validate_binding(root_node)
        for node in edges:
            validate_binding(node)

        for proof in absent_proofs:
            outcome, node, resolved, links, _ = resolve(proof["start"], proof["raw"], replay=proof)
            if (
                outcome != proof["errno"]
                or resolved != proof["resolved"]
                or _locator(resolved, repo_parts, vendor_parts) != proof["locator"]
                or node is not proof["boundary"]
                or node["evidence"] != proof["boundary_evidence"]
                or len(links) != len(proof["links"])
                or any(left is not right for left, right in zip(links, proof["links"]))
            ):
                raise MutationError("absent relation changed")

        rows = []
        for index, locator in enumerate(sorted(collected, key=lambda value: value.encode("utf-8"))):
            row = collected[locator]
            if row[0] == "absent":
                rows.append(InputRecord(index, "absent", "probe", row[5], None, None, None, locator))
                continue
            kind, access, mode, size, digest = row
            if kind is None:
                if locator.startswith("vendor:"):
                    kind = "vendor"
                elif locator.startswith("repo:"):
                    kind = "repo"
                else:
                    resolved = tuple(_component(part) for part in locator[len("external:/") :].encode("utf-8").split(b"/") if part)
                    original_accesses = access_by_locator.get(locator, set())
                    if _beneath(resolved, stable_parts):
                        kind = "stable-sysroot"
                    elif _beneath(resolved, nightly_parts):
                        kind = "nightly-sysroot"
                    elif "execute" in original_accesses:
                        kind = "tool"
                    elif "mapped" in original_accesses:
                        kind = "dynamic"
                    else:
                        kind = "tool"
            rows.append(InputRecord(index, kind, access, "present", mode, size, digest, locator))
        return encode_ledger(rows)
    except FormatError:
        raise
    except MutationError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise MutationError("filesystem relation could not be reproduced") from exc
    finally:
        close_all()


def run_reconciled_build(
    *,
    expected_ledger_fd: int,
    repo_root,
    vendor_relative: str,
    stable_sysroot_root,
    nightly_sysroot_root,
    private_parent_fd: int,
) -> "ProductionFreeze":
    if (
        type(expected_ledger_fd) is not int
        or expected_ledger_fd < 0
        or type(private_parent_fd) is not int
        or private_parent_fd < 0
    ):
        raise FormatError("invalid borrowed descriptor")

    borrowed_fcntl = fcntl.fcntl
    borrowed_f_getfd = fcntl.F_GETFD
    borrowed_f_getfl = fcntl.F_GETFL
    borrowed_os_close = os.close
    borrowed_os_fstat = os.fstat

    repo_parts = _path(repo_root, "repo_root")
    stable_parts = _path(stable_sysroot_root, "stable_sysroot_root")
    nightly_parts = _path(nightly_sysroot_root, "nightly_sysroot_root")
    vendor_tail = _relative(vendor_relative)
    supplied = (repo_parts, stable_parts, nightly_parts)
    for index, left in enumerate(supplied):
        for right in supplied[index + 1 :]:
            if _beneath(left, right) or _beneath(right, left):
                raise MutationError("anchor paths overlap")

    try:
        ledger_flags = fcntl.fcntl(expected_ledger_fd, fcntl.F_GETFL)
        ledger_value = os.fstat(expected_ledger_fd)
    except (OSError, TypeError, ValueError) as exc:
        raise FormatError("borrowed descriptor admission failed") from exc

    opath = getattr(os, "O_PATH", 0)
    if (
        type(ledger_flags) is not int
        or opath and ledger_flags & opath
        or ledger_flags & os.O_ACCMODE not in {os.O_RDONLY, os.O_RDWR}
        or not _stat.S_ISREG(ledger_value.st_mode)
        or ledger_value.st_uid != os.geteuid()
        or ledger_value.st_mode & 0o7777 != 0o600
        or ledger_value.st_nlink != 1
        or not 1 <= ledger_value.st_size <= _MAX_BYTES
    ):
        raise FormatError("invalid expected ledger descriptor")
    ledger_identity = _identity(ledger_value)

    def read_all(fd, size, failure):
        chunks = []
        offset = 0
        while offset < size:
            try:
                chunk = os.pread(fd, min(1024 * 1024, size - offset), offset)
            except Exception as exc:
                raise failure("ledger read failed") from exc
            if type(chunk) is not bytes or not chunk or len(chunk) > size - offset:
                raise failure("ledger read was short")
            chunks.append(chunk)
            offset += len(chunk)
        return b"".join(chunks)

    first = read_all(expected_ledger_fd, ledger_value.st_size, MutationError)
    try:
        first_value = os.fstat(expected_ledger_fd)
    except Exception as exc:
        raise MutationError("expected ledger changed after admission") from exc
    try:
        first_identity = _identity(first_value)
    except Exception as exc:
        raise MutationError("expected ledger changed after admission") from exc
    if first_identity != ledger_identity:
        raise MutationError("expected ledger changed after admission")
    records = parse_ledger(first)
    has_symlink_row = any(record.klass == "symlink" for record in records)

    try:
        parent_flags = fcntl.fcntl(private_parent_fd, fcntl.F_GETFL)
        parent_fd_flags = fcntl.fcntl(private_parent_fd, fcntl.F_GETFD)
        parent_value = os.fstat(private_parent_fd)
    except (OSError, TypeError, ValueError) as exc:
        raise FormatError("borrowed descriptor admission failed") from exc
    if (
        type(parent_flags) is not int
        or type(parent_fd_flags) is not int
        or opath and parent_flags & opath
        or parent_flags & os.O_ACCMODE != os.O_RDONLY
        or not parent_fd_flags & fcntl.FD_CLOEXEC
        or not _stat.S_ISDIR(parent_value.st_mode)
        or parent_value.st_uid != os.geteuid()
        or parent_value.st_mode & 0o7777 != 0o700
    ):
        raise FormatError("invalid private parent descriptor")
    parent_identity = _identity(parent_value)

    fsync_error = None
    try:
        os.fsync(private_parent_fd)
    except Exception as exc:
        fsync_error = exc

    first_failure = None
    current_parent_flags = None
    current_parent_fd_flags = None
    current_parent_identity = None
    try:
        current_parent_flags = fcntl.fcntl(private_parent_fd, fcntl.F_GETFL)
        if type(current_parent_flags) is not int:
            raise TypeError("invalid parent F_GETFL result")
    except Exception:
        current_parent_flags = None
        first_failure = MutationError("private parent F_GETFL failed")
    try:
        current_parent_fd_flags = fcntl.fcntl(private_parent_fd, fcntl.F_GETFD)
        if type(current_parent_fd_flags) is not int:
            raise TypeError("invalid parent F_GETFD result")
    except Exception:
        current_parent_fd_flags = None
        if first_failure is None:
            first_failure = MutationError("private parent F_GETFD failed")
    try:
        current_parent_identity = _identity(os.fstat(private_parent_fd))
    except Exception:
        current_parent_identity = None
        if first_failure is None:
            first_failure = MutationError("private parent fstat failed")

    second = None
    try:
        second = read_all(expected_ledger_fd, ledger_value.st_size, MutationError)
    except Exception:
        if first_failure is None:
            first_failure = MutationError("second ledger read failed")
    second_identity = None
    try:
        second_identity = _identity(os.fstat(expected_ledger_fd))
    except Exception:
        if first_failure is None:
            first_failure = MutationError("second ledger fstat failed")
    if first_failure is not None:
        raise first_failure
    parent_changed = (
        current_parent_flags != parent_flags
        or current_parent_fd_flags != parent_fd_flags
        or current_parent_identity != parent_identity
    )
    if parent_changed or second_identity != ledger_identity or second != first:
        raise MutationError("expected ledger changed after fsync")
    if (
        fsync_error is not None
        and (
            not isinstance(fsync_error, OSError)
            or fsync_error.errno
            not in {
                errno.EINVAL,
                errno.ENOSYS,
                errno.EOPNOTSUPP,
                errno.ENOTSUP,
            }
        )
    ):
        raise MutationError("private parent fsync failed") from fsync_error

    if fsync_error is not None:
        raise SystemExit(77)

    stage2_failure = None
    stage2_capability = False
    owned_fds = []
    private_ledger_fd = None
    private_parent_owned_fd = None
    graph_nodes = []
    graph_cache = {}
    graph_body_outcome = None
    owned_os_close = borrowed_os_close
    stage3_ready = False
    duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
    capability_errors = {
        errno.EINVAL,
        errno.ENOSYS,
        errno.EOPNOTSUPP,
        errno.ENOTSUP,
    }

    try:
        if type(duplicate_command) is not int or duplicate_command < 0:
            stage2_capability = True
        else:
            try:
                candidate = fcntl.fcntl(expected_ledger_fd, duplicate_command, 0)
            except OSError as exc:
                if exc.errno in capability_errors:
                    stage2_capability = True
                else:
                    stage2_failure = MutationError("ledger duplication failed")
            except Exception as exc:
                stage2_failure = MutationError("ledger duplication failed")
            else:
                if (
                    type(candidate) is not int
                    or candidate < 0
                    or candidate in {expected_ledger_fd, private_parent_fd}
                ):
                    stage2_failure = MutationError("ledger duplication returned an invalid descriptor")
                else:
                    private_ledger_fd = candidate
                    owned_fds.append(candidate)

        if private_ledger_fd is not None:
            try:
                private_parent_candidate = os.open(
                    ".",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=private_parent_fd,
                )
            except OSError as exc:
                if exc.errno in capability_errors:
                    stage2_capability = True
                else:
                    stage2_failure = MutationError("private parent open failed")
            except Exception as exc:
                stage2_failure = MutationError("private parent open failed")
            else:
                if (
                    type(private_parent_candidate) is not int
                    or private_parent_candidate < 0
                    or private_parent_candidate in {expected_ledger_fd, private_parent_fd, private_ledger_fd}
                    or private_parent_candidate in owned_fds
                ):
                    stage2_failure = MutationError("private parent open returned an invalid descriptor")
                else:
                    private_parent_owned_fd = private_parent_candidate
                    owned_fds.append(private_parent_candidate)

        private_ledger_usable = private_ledger_fd is not None
        if private_ledger_fd is not None:
            private_ledger_flags_ok = True
            try:
                private_ledger_flags = fcntl.fcntl(private_ledger_fd, fcntl.F_GETFL)
                if (
                    type(private_ledger_flags) is not int
                    or private_ledger_flags != ledger_flags
                    or opath and private_ledger_flags & opath
                    or private_ledger_flags & os.O_ACCMODE not in {os.O_RDONLY, os.O_RDWR}
                ):
                    raise MutationError("private ledger flags changed")
            except Exception as exc:
                private_ledger_flags_ok = False
                private_ledger_usable = False
                if stage2_failure is None:
                    stage2_failure = exc if isinstance(exc, MutationError) else MutationError("private ledger F_GETFL failed")

            if private_ledger_flags_ok:
                private_ledger_fd_flags_ok = True
                try:
                    private_ledger_fd_flags = fcntl.fcntl(private_ledger_fd, fcntl.F_GETFD)
                    if type(private_ledger_fd_flags) is not int or private_ledger_fd_flags != fcntl.FD_CLOEXEC:
                        raise MutationError("private ledger descriptor flags changed")
                except Exception as exc:
                    private_ledger_fd_flags_ok = False
                    private_ledger_usable = False
                    if stage2_failure is None:
                        stage2_failure = exc if isinstance(exc, MutationError) else MutationError("private ledger F_GETFD failed")

                if private_ledger_fd_flags_ok:
                    private_ledger_pre = None
                    try:
                        private_ledger_pre = _identity(os.fstat(private_ledger_fd))
                        if private_ledger_pre != ledger_identity:
                            raise MutationError("private ledger identity changed before read")
                    except Exception as exc:
                        private_ledger_pre = None
                        private_ledger_usable = False
                        if stage2_failure is None:
                            stage2_failure = exc if isinstance(exc, MutationError) else MutationError("private ledger fstat failed")

                    if private_ledger_pre is not None:
                        try:
                            private_ledger_bytes = read_all(private_ledger_fd, ledger_value.st_size, MutationError)
                            if private_ledger_bytes != first:
                                raise MutationError("private ledger bytes changed")
                        except Exception as exc:
                            private_ledger_usable = False
                            if stage2_failure is None:
                                stage2_failure = exc if isinstance(exc, MutationError) else MutationError("private ledger read failed")

                        try:
                            private_ledger_post = _identity(os.fstat(private_ledger_fd))
                            if private_ledger_post != ledger_identity:
                                raise MutationError("private ledger identity changed after read")
                        except Exception as exc:
                            private_ledger_usable = False
                            if stage2_failure is None:
                                stage2_failure = exc if isinstance(exc, MutationError) else MutationError("private ledger fstat failed")

        if private_parent_owned_fd is not None:
            private_parent_flags = None
            try:
                private_parent_flags = fcntl.fcntl(private_parent_owned_fd, fcntl.F_GETFL)
                if (
                    type(private_parent_flags) is not int
                    or opath and private_parent_flags & opath
                    or private_parent_flags & os.O_ACCMODE != os.O_RDONLY
                ):
                    raise MutationError("private parent flags changed")
            except Exception as exc:
                if stage2_failure is None:
                    stage2_failure = exc if isinstance(exc, MutationError) else MutationError("private parent F_GETFL failed")

            private_parent_fd_flags = None
            try:
                private_parent_fd_flags = fcntl.fcntl(private_parent_owned_fd, fcntl.F_GETFD)
                if type(private_parent_fd_flags) is not int or private_parent_fd_flags != fcntl.FD_CLOEXEC:
                    raise MutationError("private parent descriptor flags changed")
            except Exception as exc:
                if stage2_failure is None:
                    stage2_failure = exc if isinstance(exc, MutationError) else MutationError("private parent F_GETFD failed")

            try:
                private_parent_value = os.fstat(private_parent_owned_fd)
                if not _stat.S_ISDIR(private_parent_value.st_mode) or _identity(private_parent_value) != parent_identity:
                    raise MutationError("private parent identity changed")
            except Exception as exc:
                if stage2_failure is None:
                    stage2_failure = exc if isinstance(exc, MutationError) else MutationError("private parent fstat failed")

        if stage2_failure is None and not stage2_capability:
            try:
                stage3_o_rdonly = os.O_RDONLY
                stage3_o_cloexec = os.O_CLOEXEC
                stage3_o_nofollow = os.O_NOFOLLOW
                stage3_o_directory = os.O_DIRECTORY
                stage3_o_accmode = os.O_ACCMODE
                stage3_fd_cloexec = fcntl.FD_CLOEXEC
                stage3_f_getfd = fcntl.F_GETFD
                stage3_f_getfl = fcntl.F_GETFL
                stage3_rlimit_nofile = resource.RLIMIT_NOFILE
                stage3_os_open = os.open
                stage3_os_stat = os.stat
                stage3_os_listdir = os.listdir
                stage3_os_fsencode = os.fsencode
                stage3_os_fstat = os.fstat
                stage3_os_pread = os.pread
                stage3_os_close = os.close
                stage3_fcntl = fcntl.fcntl
                stage3_getrlimit = resource.getrlimit
                stage3_supports_dir_fd = os.supports_dir_fd
                stage3_supports_follow_symlinks = os.supports_follow_symlinks
                stage3_supports_fd = os.supports_fd
                if has_symlink_row:
                    stage3_o_path = os.O_PATH
                    stage3_os_readlink = os.readlink
            except AttributeError:
                stage2_capability = True
            except Exception:
                stage2_failure = MutationError("stage3 capability inventory failed")
            else:
                stage3_open_flags = [
                    stage3_o_cloexec,
                    stage3_o_nofollow,
                    stage3_o_directory,
                ]
                if has_symlink_row:
                    stage3_open_flags.append(stage3_o_path)
                stage3_constants_valid = (
                    type(stage3_o_rdonly) is int
                    and stage3_o_rdonly == 0
                    and all(type(value) is int and value > 0 for value in stage3_open_flags)
                    and all(
                        left & right == 0
                        for index, left in enumerate(stage3_open_flags)
                        for right in stage3_open_flags[index + 1 :]
                    )
                    and type(stage3_o_accmode) is int
                    and stage3_o_accmode > 0
                    and all(value & stage3_o_accmode == 0 for value in stage3_open_flags)
                    and stage3_o_rdonly & stage3_o_accmode == 0
                    and type(stage3_fd_cloexec) is int
                    and stage3_fd_cloexec > 0
                    and type(stage3_f_getfd) is int
                    and stage3_f_getfd >= 0
                    and type(stage3_f_getfl) is int
                    and stage3_f_getfl >= 0
                    and stage3_f_getfd != stage3_f_getfl
                    and type(stage3_rlimit_nofile) is int
                    and stage3_rlimit_nofile >= 0
                )
                stage3_callables_valid = all(
                    callable(value)
                    for value in (
                        stage3_os_open,
                        stage3_os_stat,
                        stage3_os_listdir,
                        stage3_os_fsencode,
                        stage3_os_fstat,
                        stage3_os_pread,
                        stage3_os_close,
                        stage3_fcntl,
                        stage3_getrlimit,
                    )
                    + ((stage3_os_readlink,) if has_symlink_row else ())
                )
                try:
                    stage3_support_results = (
                        stage3_os_open in stage3_supports_dir_fd,
                        stage3_os_stat in stage3_supports_dir_fd,
                        stage3_os_stat in stage3_supports_follow_symlinks,
                        stage3_os_listdir in stage3_supports_fd,
                    )
                    if has_symlink_row:
                        stage3_support_results += (
                            stage3_os_readlink in stage3_supports_dir_fd,
                        )
                except Exception:
                    stage2_failure = MutationError("stage3 capability membership failed")
                else:
                    if not stage3_constants_valid or not stage3_callables_valid:
                        stage2_failure = MutationError("invalid stage3 capability")
                    elif not all(stage3_support_results):
                        stage2_capability = True
                    else:
                        try:
                            stage3_rlimit = stage3_getrlimit(stage3_rlimit_nofile)
                        except Exception:
                            stage2_failure = MutationError("stage3 RLIMIT_NOFILE read failed")
                        else:
                            if (
                                type(stage3_rlimit) is not tuple
                                or len(stage3_rlimit) != 2
                                or any(
                                    type(value) is not int
                                    or value < 0
                                    for value in stage3_rlimit
                                )
                                or stage3_rlimit[0] > stage3_rlimit[1]
                            ):
                                stage2_failure = MutationError("invalid RLIMIT_NOFILE result")
                            else:
                                borrowed_f_getfd = stage3_f_getfd
                                borrowed_f_getfl = stage3_f_getfl
                                owned_os_close = stage3_os_close
                                stage3_ready = True

        if stage3_ready:
            class _Stage3CapacityRefusal(Exception):
                pass

            directory_flags = (
                stage3_o_rdonly
                | stage3_o_directory
                | stage3_o_cloexec
                | stage3_o_nofollow
            )
            private_parent_structural = _structural(parent_value)

            def open_owned_directory(name, parent, before, parts):
                try:
                    if parent is None:
                        candidate = stage3_os_open(name, directory_flags)
                    else:
                        candidate = stage3_os_open(
                            name,
                            directory_flags,
                            dir_fd=parent["fd"],
                        )
                except OSError as exc:
                    if exc.errno != errno.EMFILE:
                        raise MutationError("stage3 directory open failed") from exc
                    try:
                        current_limit = stage3_getrlimit(stage3_rlimit_nofile)
                    except Exception as limit_exc:
                        raise MutationError("stage3 RLIMIT_NOFILE reread failed") from limit_exc
                    if (
                        type(current_limit) is not tuple
                        or len(current_limit) != 2
                        or any(type(value) is not int or value < 0 for value in current_limit)
                        or current_limit[0] > current_limit[1]
                        or current_limit != stage3_rlimit
                    ):
                        raise MutationError("stage3 RLIMIT_NOFILE changed")
                    raise _Stage3CapacityRefusal() from exc
                except Exception as exc:
                    raise MutationError("stage3 directory open failed") from exc

                if (
                    type(candidate) is not int
                    or candidate < 0
                    or candidate in {expected_ledger_fd, private_parent_fd}
                    or candidate in owned_fds
                ):
                    raise MutationError("stage3 directory open returned an invalid descriptor")
                owned_fds.append(candidate)
                try:
                    held_value = stage3_os_fstat(candidate)
                except Exception as exc:
                    raise MutationError("stage3 held directory fstat failed") from exc
                held = _structural(held_value)
                if not _stat.S_ISDIR(held_value.st_mode) or before is not None and held != before:
                    raise MutationError("stage3 directory relation changed")
                if held == private_parent_structural:
                    raise MutationError("stage3 directory aliases private parent")
                node = {
                    "parts": parts,
                    "fd": candidate,
                    "parent": parent,
                    "name": None if parent is None else name,
                    "structural": held,
                }
                graph_nodes.append(node)
                if parent is not None:
                    graph_cache[(parent["fd"], name)] = node
                return node

            def open_edge(parent, name):
                cached = graph_cache.get((parent["fd"], name))
                if cached is not None:
                    try:
                        held_value = stage3_os_fstat(cached["fd"])
                    except Exception as exc:
                        raise MutationError("stage3 cached directory fstat failed") from exc
                    if (
                        not _stat.S_ISDIR(held_value.st_mode)
                        or _structural(held_value) != cached["structural"]
                    ):
                        raise MutationError("stage3 cached directory changed")
                    try:
                        bound_value = stage3_os_stat(
                            name,
                            dir_fd=parent["fd"],
                            follow_symlinks=False,
                        )
                    except Exception as exc:
                        raise MutationError("stage3 cached directory binding failed") from exc
                    if (
                        not _stat.S_ISDIR(bound_value.st_mode)
                        or _structural(bound_value) != cached["structural"]
                    ):
                        raise MutationError("stage3 cached directory binding changed")
                    return cached
                try:
                    before_value = stage3_os_stat(
                        name,
                        dir_fd=parent["fd"],
                        follow_symlinks=False,
                    )
                except Exception as exc:
                    raise MutationError("stage3 directory stat failed") from exc
                if not _stat.S_ISDIR(before_value.st_mode):
                    raise MutationError("stage3 path component is not a directory")
                return open_owned_directory(
                    name,
                    parent,
                    _structural(before_value),
                    parent["parts"] + (name,),
                )

            def walk_anchor(parts, start):
                node = start
                for name in parts:
                    node = open_edge(node, name)
                return node

            def lineage(node):
                result = []
                while node is not None:
                    result.append(node)
                    node = node["parent"]
                result.reverse()
                return result

            def divergent_suffixes(left, right):
                shared = 0
                while (
                    shared < len(left)
                    and shared < len(right)
                    and left[shared] is right[shared]
                ):
                    shared += 1
                left_suffix = [node["structural"] for node in left[shared:]]
                right_suffix = [node["structural"] for node in right[shared:]]
                if (
                    len(left_suffix) != len(set(left_suffix))
                    or len(right_suffix) != len(set(right_suffix))
                    or set(left_suffix) & set(right_suffix)
                ):
                    raise MutationError("stage3 anchor lineages converge")
                return left_suffix, right_suffix

            try:
                root_node = open_owned_directory(b"/", None, None, ())
                repo_node = walk_anchor(repo_parts, root_node)
                vendor_node = walk_anchor(vendor_tail, repo_node)
                repo_lineage = lineage(repo_node)
                vendor_lineage = lineage(vendor_node)
                if (
                    len(vendor_lineage) <= len(repo_lineage)
                    or any(
                        vendor is not repo
                        for vendor, repo in zip(vendor_lineage, repo_lineage)
                    )
                ):
                    raise MutationError("stage3 vendor lineage escaped repo")
                vendor_suffix = [
                    node["structural"] for node in vendor_lineage[len(repo_lineage) :]
                ]
                repo_structural = {node["structural"] for node in repo_lineage}
                if (
                    len(vendor_suffix) != len(set(vendor_suffix))
                    or set(vendor_suffix) & repo_structural
                ):
                    raise MutationError("stage3 vendor lineage aliases another anchor")

                stable_node = walk_anchor(stable_parts, root_node)
                stable_lineage = lineage(stable_node)
                _, stable_suffix = divergent_suffixes(repo_lineage, stable_lineage)
                if set(vendor_suffix) & set(stable_suffix):
                    raise MutationError("stage3 vendor lineage aliases another anchor")

                nightly_node = walk_anchor(nightly_parts, root_node)
                nightly_lineage = lineage(nightly_node)
                _, nightly_suffix = divergent_suffixes(repo_lineage, nightly_lineage)
                divergent_suffixes(stable_lineage, nightly_lineage)
                if set(vendor_suffix) & set(nightly_suffix):
                    raise MutationError("stage3 vendor lineage aliases another anchor")
            except _Stage3CapacityRefusal:
                graph_body_outcome = "capacity"
                stage2_capability = True
            except MutationError as exc:
                graph_body_outcome = "mutation"
                if stage2_failure is None:
                    stage2_failure = exc
            else:
                graph_body_outcome = "success"

        if graph_body_outcome in {"mutation", "capacity"}:
            private_failure = None

            def record_private_failure(exc, message):
                nonlocal private_failure
                if private_failure is None:
                    private_failure = (
                        exc if isinstance(exc, MutationError) else MutationError(message)
                    )

            ledger_guard_ok = True
            try:
                value = stage3_fcntl(private_ledger_fd, stage3_f_getfl)
                if type(value) is not int or value != ledger_flags:
                    raise MutationError("private ledger flags changed")
            except BaseException as exc:
                ledger_guard_ok = False
                record_private_failure(exc, "final private ledger F_GETFL failed")
            if ledger_guard_ok:
                try:
                    value = stage3_fcntl(private_ledger_fd, stage3_f_getfd)
                    if type(value) is not int or value != stage3_fd_cloexec:
                        raise MutationError("private ledger descriptor flags changed")
                except BaseException as exc:
                    ledger_guard_ok = False
                    record_private_failure(exc, "final private ledger F_GETFD failed")
            if ledger_guard_ok:
                try:
                    value = stage3_os_fstat(private_ledger_fd)
                    if _identity(value) != ledger_identity:
                        raise MutationError("private ledger identity changed before final read")
                except BaseException as exc:
                    ledger_guard_ok = False
                    record_private_failure(exc, "final private ledger fstat failed")
            if ledger_guard_ok:
                chunks = []
                offset = 0
                while offset < ledger_value.st_size:
                    try:
                        chunk = stage3_os_pread(
                            private_ledger_fd,
                            min(1024 * 1024, ledger_value.st_size - offset),
                            offset,
                        )
                        if (
                            type(chunk) is not bytes
                            or not chunk
                            or len(chunk) > ledger_value.st_size - offset
                        ):
                            raise MutationError("final private ledger read was short")
                    except BaseException as exc:
                        record_private_failure(exc, "final private ledger read failed")
                        break
                    chunks.append(chunk)
                    offset += len(chunk)
                if offset == ledger_value.st_size and b"".join(chunks) != first:
                    record_private_failure(
                        MutationError("private ledger bytes changed"),
                        "final private ledger read failed",
                    )
                try:
                    value = stage3_os_fstat(private_ledger_fd)
                    if _identity(value) != ledger_identity:
                        raise MutationError("private ledger identity changed after final read")
                except BaseException as exc:
                    record_private_failure(exc, "final private ledger fstat failed")
            try:
                value = stage3_fcntl(private_parent_owned_fd, stage3_f_getfl)
                if (
                    type(value) is not int
                    or opath and value & opath
                    or value & stage3_o_accmode != stage3_o_rdonly
                ):
                    raise MutationError("private parent flags changed")
            except BaseException as exc:
                record_private_failure(exc, "final private parent F_GETFL failed")
            try:
                value = stage3_fcntl(private_parent_owned_fd, stage3_f_getfd)
                if type(value) is not int or value != stage3_fd_cloexec:
                    raise MutationError("private parent descriptor flags changed")
            except BaseException as exc:
                record_private_failure(exc, "final private parent F_GETFD failed")
            try:
                value = stage3_os_fstat(private_parent_owned_fd)
                if (
                    not _stat.S_ISDIR(value.st_mode)
                    or _identity(value) != parent_identity
                ):
                    raise MutationError("private parent identity changed")
            except BaseException as exc:
                record_private_failure(exc, "final private parent fstat failed")
            if stage2_failure is None and private_failure is not None:
                stage2_failure = private_failure

        if private_ledger_usable:
            borrowed_ledger_flags = None
            try:
                borrowed_ledger_flags = borrowed_fcntl(expected_ledger_fd, borrowed_f_getfl)
                if type(borrowed_ledger_flags) is not int or borrowed_ledger_flags != ledger_flags:
                    raise MutationError("borrowed ledger flags changed")
            except BaseException as exc:
                if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                    raise
                if stage2_failure is None:
                    stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed ledger F_GETFL failed")
            try:
                if _identity(borrowed_os_fstat(expected_ledger_fd)) != ledger_identity:
                    raise MutationError("borrowed ledger identity changed")
            except BaseException as exc:
                if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                    raise
                if stage2_failure is None:
                    stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed ledger fstat failed")
        else:
            borrowed_ledger_flags_ok = True
            borrowed_ledger_pre = None
            try:
                borrowed_ledger_flags = borrowed_fcntl(expected_ledger_fd, borrowed_f_getfl)
                if type(borrowed_ledger_flags) is not int or borrowed_ledger_flags != ledger_flags:
                    raise MutationError("borrowed ledger flags changed")
            except BaseException as exc:
                if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                    raise
                borrowed_ledger_flags_ok = False
                if stage2_failure is None:
                    stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed ledger F_GETFL failed")
            try:
                borrowed_ledger_pre = _identity(borrowed_os_fstat(expected_ledger_fd))
                if borrowed_ledger_pre != ledger_identity:
                    raise MutationError("borrowed ledger identity changed before read")
            except BaseException as exc:
                if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                    raise
                borrowed_ledger_pre = None
                if stage2_failure is None:
                    stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed ledger fstat failed")
            if borrowed_ledger_flags_ok and borrowed_ledger_pre is not None:
                try:
                    if read_all(expected_ledger_fd, ledger_value.st_size, MutationError) != first:
                        raise MutationError("borrowed ledger bytes changed")
                except BaseException as exc:
                    if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                        raise
                    if stage2_failure is None:
                        stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed ledger read failed")
                try:
                    if _identity(borrowed_os_fstat(expected_ledger_fd)) != ledger_identity:
                        raise MutationError("borrowed ledger identity changed after read")
                except BaseException as exc:
                    if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                        raise
                    if stage2_failure is None:
                        stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed ledger fstat failed")

        borrowed_parent_flags = None
        try:
            borrowed_parent_flags = borrowed_fcntl(private_parent_fd, borrowed_f_getfl)
            if type(borrowed_parent_flags) is not int or borrowed_parent_flags != parent_flags:
                raise MutationError("borrowed parent flags changed")
        except BaseException as exc:
            if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                raise
            if stage2_failure is None:
                stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed parent F_GETFL failed")
        try:
            borrowed_parent_fd_flags = borrowed_fcntl(private_parent_fd, borrowed_f_getfd)
            if type(borrowed_parent_fd_flags) is not int or borrowed_parent_fd_flags != parent_fd_flags:
                raise MutationError("borrowed parent descriptor flags changed")
        except BaseException as exc:
            if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                raise
            if stage2_failure is None:
                stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed parent F_GETFD failed")
        try:
            if _identity(borrowed_os_fstat(private_parent_fd)) != parent_identity:
                raise MutationError("borrowed parent identity changed")
        except BaseException as exc:
            if not isinstance(exc, Exception) and graph_body_outcome not in {"mutation", "capacity"}:
                raise
            if stage2_failure is None:
                stage2_failure = exc if isinstance(exc, MutationError) else MutationError("borrowed parent fstat failed")

        if graph_body_outcome is not None:
            for node in graph_nodes:
                try:
                    value = stage3_os_fstat(node["fd"])
                    if (
                        not _stat.S_ISDIR(value.st_mode)
                        or _structural(value) != node["structural"]
                    ):
                        raise MutationError("stage3 held directory binding changed")
                except BaseException as exc:
                    if (
                        not isinstance(exc, Exception)
                        and graph_body_outcome not in {"mutation", "capacity"}
                    ):
                        raise
                    if stage2_failure is None:
                        stage2_failure = (
                            exc
                            if isinstance(exc, MutationError)
                            else MutationError("stage3 held directory binding failed")
                        )
                if node["parent"] is not None:
                    try:
                        value = stage3_os_stat(
                            node["name"],
                            dir_fd=node["parent"]["fd"],
                            follow_symlinks=False,
                        )
                        if (
                            not _stat.S_ISDIR(value.st_mode)
                            or _structural(value) != node["structural"]
                        ):
                            raise MutationError("stage3 directory edge binding changed")
                    except BaseException as exc:
                        if (
                            not isinstance(exc, Exception)
                            and graph_body_outcome not in {"mutation", "capacity"}
                        ):
                            raise
                        if stage2_failure is None:
                            stage2_failure = (
                                exc
                                if isinstance(exc, MutationError)
                                else MutationError("stage3 directory edge binding failed")
                            )

    finally:
        close_failure = None
        for owned_fd in reversed(owned_fds):
            try:
                owned_os_close(owned_fd)
            except BaseException as exc:
                if close_failure is None:
                    close_failure = exc
        if close_failure is not None:
            raise MutationError("owned descriptor close failed") from close_failure
    if stage2_failure is not None:
        raise stage2_failure
    if stage2_capability:
        raise SystemExit(77)
    raise SystemExit(77)


if __name__ == "__main__":
    raise SystemExit(77)
