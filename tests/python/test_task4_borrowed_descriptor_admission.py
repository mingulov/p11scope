"""Native borrowed-descriptor admission contracts for ``run_reconciled_build``."""

import contextlib
import fcntl
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = Path(os.environ.get("TASK4_SUBJECT_PATH", REPO / "scripts/task4-build-subject.py"))
GOLDEN = (REPO / "tests/fixtures/task4/input-ledger-golden.tsv").read_bytes()
MAX_FIXTURE_LEDGER_BYTES = 4 * 1024 * 1024 + 1
MODULE_NAME = "task4_build_subject_borrowed_descriptor_test"
MISSING = object()

sys.path.insert(0, str(REPO / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path


class IntSubclass(int):
    pass


def load_subject(test):
    previous_module = sys.modules.get(MODULE_NAME, MISSING)
    previous_dont_write_bytecode = sys.dont_write_bytecode

    def restore():
        sys.dont_write_bytecode = previous_dont_write_bytecode
        if previous_module is MISSING:
            sys.modules.pop(MODULE_NAME, None)
        else:
            sys.modules[MODULE_NAME] = previous_module

    sys.dont_write_bytecode = True
    test.addCleanup(restore)
    try:
        module = load_path(SCRIPT_PATH, MODULE_NAME)
    except FileNotFoundError:
        test.fail("could not import task4 build-subject script")
    sys.modules[MODULE_NAME] = module
    return module


def identity(value):
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


def tree_state(root):
    entries = []

    def visit(path, relative):
        value = os.lstat(path)
        mode = value.st_mode
        if stat.S_ISREG(mode):
            content = Path(path).read_bytes()
        elif stat.S_ISLNK(mode):
            content = os.fsencode(os.readlink(path))
        else:
            content = b""
        entries.append((relative, stat.S_IFMT(mode), mode & 0o7777, identity(value), content))
        if stat.S_ISDIR(mode):
            for name in sorted(os.listdir(path), key=os.fsencode):
                child_relative = name if not relative else os.path.join(relative, name)
                visit(os.path.join(path, name), child_relative)

    visit(root, "")
    return tuple(entries)


def descriptor_state(fd, offset):
    return (
        identity(os.fstat(fd)),
        fcntl.fcntl(fd, fcntl.F_GETFL),
        fcntl.fcntl(fd, fcntl.F_GETFD),
        offset,
    )


def current_offset(fd):
    try:
        return os.lseek(fd, 0, os.SEEK_CUR)
    except OSError:
        return None


def readable_ledger_state(fd):
    if type(fd) is not int or fd < 0:
        return None
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        value = os.fstat(fd)
    except (OSError, TypeError, ValueError):
        return None
    if (
        flags & getattr(os, "O_PATH", 0)
        or flags & os.O_ACCMODE == os.O_WRONLY
        or not stat.S_ISREG(value.st_mode)
    ):
        return None
    if not 0 <= value.st_size <= MAX_FIXTURE_LEDGER_BYTES:
        raise AssertionError("readable fixture ledger has an unexpected size")
    content = os.pread(fd, value.st_size, 0)
    if len(content) != value.st_size:
        raise AssertionError("readable fixture ledger read was short")
    return identity(value), content


class BorrowedDescriptorAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.module = load_subject(self)
        self.fixture = tempfile.TemporaryDirectory(prefix="p11scope-borrowed-admission-")
        self.addCleanup(self.fixture.cleanup)
        root = Path(self.fixture.name)
        self.repo_root = root / "repo"
        self.stable_root = root / "stable"
        self.nightly_root = root / "nightly"
        self.parent_root = root / "parent"
        for path in (self.repo_root, self.stable_root, self.nightly_root):
            path.mkdir(mode=0o755)
        self.parent_root.mkdir(mode=0o700)
        self.make_file(self.parent_root / "marker", b"parent-marker")
        self.ledger_path = self.make_file(root / "ledger", GOLDEN)
        self.ledger_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        self.parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        self.ledger_fd = os.open(self.ledger_path, self.ledger_flags)
        self.parent_fd = os.open(self.parent_root, self.parent_flags)
        self.addCleanup(self.close_if_open, self.parent_fd)
        self.addCleanup(self.close_if_open, self.ledger_fd)
        self.ledger_offset = os.lseek(self.ledger_fd, 11, os.SEEK_SET)
        self.parent_offset = os.lseek(self.parent_fd, 7, os.SEEK_CUR)
        self.assertEqual(self.ledger_offset, 11)
        self.assertEqual(self.parent_offset, 7)
        self.roots = (self.repo_root, self.stable_root, self.nightly_root, self.parent_root)
        self.valid = {
            "expected_ledger_fd": self.ledger_fd,
            "repo_root": str(self.repo_root),
            "vendor_relative": "vendor",
            "stable_sysroot_root": str(self.stable_root),
            "nightly_sysroot_root": str(self.nightly_root),
            "private_parent_fd": self.parent_fd,
        }

    def make_file(self, path, content, mode=0o600):
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def close_if_open(self, fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def assert_rejected(self, label, overrides, borrowed=None):
        kwargs = dict(self.valid)
        kwargs.update(overrides)
        ledger_argument = kwargs["expected_ledger_fd"]
        borrowed = borrowed or [
            (self.ledger_fd, self.ledger_offset),
            (self.parent_fd, self.parent_offset),
        ]
        trees_before = tuple(tree_state(root) for root in self.roots)
        ledger_before = (identity(os.fstat(self.ledger_fd)), os.pread(self.ledger_fd, len(GOLDEN), 0))
        argument_ledger_before = readable_ledger_state(ledger_argument)
        descriptors_before = {
            fd: descriptor_state(fd, offset) for fd, offset in borrowed
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        caught = None
        discover_calls = 0
        real_discover = self.module.discover_input_v1

        def discover_bomb(*args, **kwargs):
            nonlocal discover_calls
            discover_calls += 1
            raise SystemExit("discover_input_v1 must not be called by run_reconciled_build")

        self.module.discover_input_v1 = discover_bomb
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    self.module.run_reconciled_build(**kwargs)
                except BaseException as exc:
                    caught = exc
        finally:
            self.module.discover_input_v1 = real_discover
        self.assertEqual(discover_calls, 0, f"{label}: discover_input_v1 was called")
        self.assertIs(
            type(caught),
            self.module.FormatError,
            f"{label}: expected exact FormatError, got {type(caught).__name__}: {caught}",
        )
        self.assertEqual(stdout.getvalue(), "", f"{label}: runner wrote stdout")
        self.assertEqual(stderr.getvalue(), "", f"{label}: runner wrote stderr")
        self.assertEqual(tuple(tree_state(root) for root in self.roots), trees_before)
        self.assertEqual(
            (identity(os.fstat(self.ledger_fd)), os.pread(self.ledger_fd, len(GOLDEN), 0)),
            ledger_before,
            f"{label}: runner changed the borrowed ledger",
        )
        if argument_ledger_before is not None:
            self.assertEqual(
                readable_ledger_state(ledger_argument),
                argument_ledger_before,
                f"{label}: runner changed the supplied readable ledger",
            )
        for fd, expected in descriptors_before.items():
            self.assertEqual(
                descriptor_state(fd, current_offset(fd)),
                expected,
                f"{label}: runner changed borrowed descriptor {fd}",
            )

    def reject_role_value(self, role, value, label):
        self.assert_rejected(f"{role}-{label}", {role: value})

    def reject_alt_fd(self, label, role, fd, offset=None):
        self.addCleanup(self.close_if_open, fd)
        borrowed = [
            (self.ledger_fd, self.ledger_offset),
            (self.parent_fd, self.parent_offset),
        ]
        index = 0 if role == "expected_ledger_fd" else 1
        borrowed[index] = (fd, current_offset(fd) if offset is None else offset)
        self.assert_rejected(label, {role: fd}, borrowed)

    def test_expected_ledger_fd_bool_true(self):
        self.reject_role_value("expected_ledger_fd", True, "bool-true")

    def test_expected_ledger_fd_bool_false(self):
        self.reject_role_value("expected_ledger_fd", False, "bool-false")

    def test_expected_ledger_fd_none(self):
        self.reject_role_value("expected_ledger_fd", None, "none")

    def test_expected_ledger_fd_string(self):
        self.reject_role_value("expected_ledger_fd", "fd", "string")

    def test_expected_ledger_fd_int_subclass(self):
        self.reject_role_value("expected_ledger_fd", IntSubclass(self.ledger_fd), "int-subclass")

    def test_expected_ledger_fd_negative(self):
        self.reject_role_value("expected_ledger_fd", -1, "negative")

    def test_expected_ledger_fd_invalid(self):
        self.reject_role_value("expected_ledger_fd", 10**6, "invalid")

    def test_expected_ledger_fd_closed(self):
        fd = os.open(self.ledger_path, self.ledger_flags)
        os.close(fd)
        self.reject_role_value("expected_ledger_fd", fd, "closed")

    def test_private_parent_fd_bool_true(self):
        self.reject_role_value("private_parent_fd", True, "bool-true")

    def test_private_parent_fd_bool_false(self):
        self.reject_role_value("private_parent_fd", False, "bool-false")

    def test_private_parent_fd_none(self):
        self.reject_role_value("private_parent_fd", None, "none")

    def test_private_parent_fd_string(self):
        self.reject_role_value("private_parent_fd", "fd", "string")

    def test_private_parent_fd_int_subclass(self):
        self.reject_role_value("private_parent_fd", IntSubclass(self.parent_fd), "int-subclass")

    def test_private_parent_fd_negative(self):
        self.reject_role_value("private_parent_fd", -1, "negative")

    def test_private_parent_fd_invalid(self):
        self.reject_role_value("private_parent_fd", 10**6, "invalid")

    def test_private_parent_fd_closed(self):
        fd = os.open(self.ledger_path, self.ledger_flags)
        os.close(fd)
        self.reject_role_value("private_parent_fd", fd, "closed")

    def test_ledger_writable(self):
        fd = os.open(self.ledger_path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.reject_alt_fd("ledger-writable", "expected_ledger_fd", fd, 0)

    def test_ledger_o_path(self):
        opath = getattr(os, "O_PATH", 0)
        self.assertNotEqual(opath, 0, "Linux O_PATH is required")
        fd = os.open(self.ledger_path, opath | os.O_CLOEXEC | os.O_NOFOLLOW)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        self.assertTrue(flags & opath)
        self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
        self.reject_alt_fd("ledger-o-path", "expected_ledger_fd", fd)

    def test_ledger_wrong_kind(self):
        self.reject_alt_fd(
            "ledger-wrong-kind", "expected_ledger_fd", os.open(self.parent_root, self.parent_flags)
        )

    def test_ledger_wrong_mode(self):
        path = self.make_file(Path(self.fixture.name) / "ledger-wrong-mode", GOLDEN, 0o644)
        self.reject_alt_fd("ledger-wrong-mode", "expected_ledger_fd", os.open(path, self.ledger_flags))

    def test_ledger_nlink(self):
        path = self.make_file(Path(self.fixture.name) / "ledger-nlink", GOLDEN)
        os.link(path, f"{path}-alias")
        fd = os.open(path, self.ledger_flags)
        self.assertEqual(os.fstat(fd).st_nlink, 2)
        self.reject_alt_fd("ledger-nlink", "expected_ledger_fd", fd)

    def test_ledger_empty(self):
        path = self.make_file(Path(self.fixture.name) / "ledger-empty", b"")
        self.reject_alt_fd("ledger-empty", "expected_ledger_fd", os.open(path, self.ledger_flags))

    def test_ledger_sparse_oversize(self):
        path = Path(self.fixture.name) / "ledger-sparse"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
        os.ftruncate(fd, 4 * 1024 * 1024 + 1)
        os.close(fd)
        fd = os.open(path, self.ledger_flags)
        self.assertEqual(os.fstat(fd).st_size, 4 * 1024 * 1024 + 1)
        self.reject_alt_fd("ledger-sparse-oversize", "expected_ledger_fd", fd)

    def test_ledger_malformed(self):
        path = self.make_file(Path(self.fixture.name) / "ledger-malformed", b"not input-v1\n")
        self.reject_alt_fd("ledger-malformed", "expected_ledger_fd", os.open(path, self.ledger_flags))

    def test_parent_o_path(self):
        opath = getattr(os, "O_PATH", 0)
        self.assertNotEqual(opath, 0, "Linux O_PATH is required")
        fd = os.open(self.parent_root, opath | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        self.assertTrue(flags & opath)
        self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
        self.reject_alt_fd("parent-o-path", "private_parent_fd", fd)

    def test_parent_wrong_kind(self):
        path = self.make_file(Path(self.fixture.name) / "parent-wrong-kind", b"not a directory")
        self.reject_alt_fd("parent-wrong-kind", "private_parent_fd", os.open(path, self.ledger_flags))

    def test_parent_wrong_mode(self):
        self.parent_root.chmod(0o755)
        self.addCleanup(self.parent_root.chmod, 0o700)
        fd = os.open(self.parent_root, self.parent_flags)
        self.reject_alt_fd("parent-wrong-mode", "private_parent_fd", fd)

    def test_parent_no_cloexec(self):
        fd = os.dup(self.parent_fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        fcntl.fcntl(fd, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
        self.assertFalse(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        self.reject_alt_fd("parent-no-cloexec", "private_parent_fd", fd)


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
