"""Semantic trace private close-outcome contracts."""

from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/task4-build-subject.py"
MODULE_NAME = "task4_build_subject_semantic_close_test"
MISSING = object()

sys.path.insert(0, str(REPO / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path


class IntSubclass(int):
    pass


class StringSubclass(str):
    pass


class TupleSubclass(tuple):
    pass


INT_MAX = 2**31 - 1
MAX_U64 = 2**64 - 1
CLOSE_TAIL = (17, 2**63, MAX_U64 - 1, MAX_U64, 1)
DUP_TAIL = (17, 2**63, MAX_U64 - 1, MAX_U64, 1)
DUP2_TAIL = (17, 2**63, MAX_U64 - 1, MAX_U64)


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


class SemanticTraceCloseTests(unittest.TestCase):
    def setUp(self):
        self.module = load_subject(self)

    @staticmethod
    def _close_operation(fd=5, tail=CLOSE_TAIL):
        return ("close", "fd", (fd, *tail))

    @staticmethod
    def _dup_operation(oldfd=5, tail=DUP_TAIL):
        return ("dup", "fd", (oldfd, *tail))

    @staticmethod
    def _dup2_operation(oldfd=5, newfd=6, tail=DUP2_TAIL):
        return ("dup2", "fd", (oldfd, newfd, *tail))

    def _seed_state(self, root_tid=100):
        state = self.module._SemanticTraceState(
            root_tid=root_tid,
            cwd=object(),
            root=object(),
            umask=0o022,
            fds={
                0: (object(), True),
                2: (object(), False),
                4: (object(), True),
            },
        )
        state.install_open_fd(
            tid=root_tid,
            fd=5,
            node=object(),
            kind="regular",
            access="read_write",
            cloexec=True,
        )
        state.install_open_fd(
            tid=root_tid,
            fd=6,
            node=object(),
            kind="regular",
            access="read_write",
            cloexec=True,
        )
        state.apply_io_offset(
            tid=root_tid, fd=5, direction="write", count=7, position=None
        )
        state.map_file(
            tid=root_tid,
            start=0x1000,
            length=0x1000,
            node=object(),
            offset=0,
            prot=object(),
            shared=False,
        )
        state.spawn(
            parent_tid=root_tid,
            child_tid=101,
            share_files=True,
            share_fs=True,
            share_vm=True,
            thread_group=False,
        )
        state.spawn(
            parent_tid=root_tid,
            child_tid=102,
            share_files=False,
            share_fs=False,
            share_vm=False,
            thread_group=False,
        )
        return state

    @staticmethod
    def _arm(state, operation, tid=100):
        state.begin_syscall(tid=tid, operation=operation)
        return operation

    def _assert_owner(self, label, state, table, tid, pending):
        owners = state._fd_table_mutators
        self.assertIs(type(owners), list, f"{label}: owner collection type")
        self.assertEqual(len(owners), 1, f"{label}: owner collection length")
        owner = owners[0]
        self.assertIs(type(owner), tuple, f"{label}: owner entry type")
        self.assertEqual(len(owner), 3, f"{label}: owner entry length")
        self.assertIs(owner[0], table, f"{label}: owner table identity")
        self.assertIs(type(owner[1]), int, f"{label}: owner TID type")
        self.assertEqual(owner[1], tid, f"{label}: owner TID")
        self.assertIs(owner[2], pending, f"{label}: owner pending identity")

    def _freeze(self, value):
        value_type = type(value)
        type_tag = (value_type.__module__, value_type.__qualname__)
        if value_type is self.module._OpenDescription:
            return (
                "open-description",
                type_tag,
                id(value),
                self._freeze(value.kind),
                self._freeze(value.access),
                self._freeze(value.offset),
                self._freeze(value.identity),
            )
        if value_type in (type(None), bool, int, float, str, bytes):
            return ("scalar", type_tag, value)
        if value_type is tuple:
            return (
                "tuple",
                type_tag,
                id(value),
                tuple(self._freeze(item) for item in value),
            )
        if value_type is list:
            return (
                "list",
                type_tag,
                id(value),
                tuple(self._freeze(item) for item in value),
            )
        if value_type is dict:
            return (
                "dict",
                type_tag,
                id(value),
                tuple(
                    (self._freeze(key), self._freeze(item))
                    for key, item in value.items()
                ),
            )
        return ("object", type_tag, id(value))

    def _snapshot(self, state):
        return (
            state._tasks,
            self._freeze(state._tasks),
            state._pending,
            self._freeze(state._pending),
            state._fd_table_mutators,
            self._freeze(state._fd_table_mutators),
        )

    def _assert_unchanged(self, label, before, after):
        for position in (0, 2, 4):
            self.assertIs(
                after[position], before[position], f"{label}: container identity"
            )
        for position in (1, 3, 5):
            self.assertEqual(
                after[position], before[position], f"{label}: values or identities"
            )

    def _expect_format(self, label, state, invoke):
        before = self._snapshot(state)
        try:
            invoke()
        except BaseException as exc:
            self.assertIs(
                type(exc),
                self.module.FormatError,
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}",
            )
        else:
            self.fail(f"{label}: malformed operation was accepted")
        self._assert_unchanged(label, before, self._snapshot(state))

    def _assert_receipt(self, label, receipt, pending, result, errno):
        self.assertIs(type(receipt), tuple, f"{label}: receipt type")
        self.assertEqual(len(receipt), 3, f"{label}: receipt length")
        self.assertIs(receipt[0], pending, f"{label}: pending identity")
        self.assertIs(type(receipt[1]), int, f"{label}: result type")
        self.assertEqual(receipt[1], result, f"{label}: result")
        self.assertIs(receipt[2], errno, f"{label}: errno identity")

    def _fd_table_snapshot(self, table):
        return (
            table,
            tuple(table),
            tuple(
                (fd, entry, entry[0], entry[1], self._freeze(entry[0]))
                for fd, entry in table.items()
            ),
        )

    def _assert_fd_delta(self, label, before, after, removed_fd=None):
        before_table, before_keys, before_rows = before
        after_table, after_keys, after_rows = after
        self.assertIs(after_table, before_table, f"{label}: FD table identity")
        expected_keys = (
            tuple(fd for fd in before_keys if fd != removed_fd)
            if removed_fd is not None
            else before_keys
        )
        self.assertEqual(after_keys, expected_keys, f"{label}: FD keys")
        expected_rows = (
            tuple(row for row in before_rows if row[0] != removed_fd)
            if removed_fd is not None
            else before_rows
        )
        self.assertEqual(len(after_rows), len(expected_rows), f"{label}: row count")
        for expected, actual in zip(expected_rows, after_rows):
            self.assertEqual(expected[0], actual[0], f"{label}: non-target FD")
            self.assertIs(expected[1], actual[1], f"{label}: entry identity")
            self.assertIs(expected[2], actual[2], f"{label}: description identity")
            self.assertIs(expected[3], actual[3], f"{label}: CLOEXEC identity")
            self.assertEqual(expected[4], actual[4], f"{label}: description value")
        if removed_fd is not None:
            self.assertIn(removed_fd, before_keys, f"{label}: missing target before")
            self.assertNotIn(removed_fd, after_keys, f"{label}: retained target")

    def _admit_close(self, operation=None, tid=100):
        state = self._seed_state()
        operation = self._close_operation() if operation is None else operation
        pending = self._arm(state, operation, tid=tid)
        table = state._task(tid)["fds"]
        self.assertIs(
            state.try_admit_fd_table_mutator(tid=tid),
            True,
            "close-terminal admission failed",
        )
        self._assert_owner("close-terminal admission", state, table, tid, pending)
        return state, pending, table

    def _finish_valid_close(
        self, label, state, pending, table, fd, result, errno, delete_fd=True
    ):
        before_fds = self._fd_table_snapshot(table)
        receipt = state.finish_close_syscall(tid=100, result=result, errno=errno)
        self._assert_receipt(label, receipt, pending, result, errno)
        self._assert_fd_delta(
            label,
            before_fds,
            self._fd_table_snapshot(table),
            fd if delete_fd else None,
        )
        self.assertNotIn(100, state._pending, f"{label}: pending cleanup")
        self.assertFalse(state._fd_table_mutators, f"{label}: owner cleanup")
        return receipt

    def _expect_invalid_close(self, label, result, errno, fd=5, present=True):
        state = self._seed_state()
        table = state._task(100)["fds"]
        if not present and fd in table:
            state.close(tid=100, fd=fd)
        pending = self._arm(state, self._close_operation(fd))
        self.assertIs(
            state.try_admit_fd_table_mutator(tid=100),
            True,
            f"{label}: setup admission",
        )
        self._expect_format(
            label,
            state,
            lambda: state.finish_close_syscall(
                tid=100, result=result, errno=errno
            ),
        )
        self.assertIs(state._pending[100], pending, f"{label}: pending identity")

    def test_admission_contracts(self):
        state = self._seed_state()
        pending = self._arm(state, ("close", "fd", (5, *CLOSE_TAIL)))
        table = state._task(100)["fds"]
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self._assert_owner("first exact close admission", state, table, 100, pending)

        for label, operation in (
            ("fd zero/raw zero", self._close_operation(0, (0, 0, 0, 0, 0))),
            (
                "fd INT_MAX/raw max",
                self._close_operation(INT_MAX, (MAX_U64,) * 5),
            ),
        ):
            with self.subTest(admitted_boundary=label):
                state = self._seed_state()
                pending = self._arm(state, operation)
                table = state._task(100)["fds"]
                self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
                self._assert_owner(label, state, table, 100, pending)

        for label, bad_pending in (
            ("outer list", ["close", "fd", (5, *CLOSE_TAIL)]),
            (
                "outer tuple subclass",
                TupleSubclass(("close", "fd", (5, *CLOSE_TAIL))),
            ),
            ("two items", ("close", "fd")),
            ("four items", ("close", "fd", (5, *CLOSE_TAIL), "extra")),
            ("wrong name fcntl", ("fcntl", "fd", (5, *CLOSE_TAIL))),
            (
                "name subclass",
                (StringSubclass("close"), "fd", (5, *CLOSE_TAIL)),
            ),
            ("wrong category", ("close", "path", (5, *CLOSE_TAIL))),
            (
                "category subclass",
                ("close", StringSubclass("fd"), (5, *CLOSE_TAIL)),
            ),
            ("arguments list", ("close", "fd", list((5, *CLOSE_TAIL)))),
            (
                "arguments tuple subclass",
                ("close", "fd", TupleSubclass((5, *CLOSE_TAIL))),
            ),
            ("five args", ("close", "fd", (5, *CLOSE_TAIL)[:5])),
            ("seven args", ("close", "fd", (5, *CLOSE_TAIL) + (7,))),
        ):
            with self.subTest(malformed_shape=label):
                state = self._seed_state()
                state._pending[100] = bad_pending
                self._expect_format(
                    label,
                    state,
                    lambda: state.try_admit_fd_table_mutator(tid=100),
                )

        for suffix, bad in (
            ("bool", True),
            ("integer subclass", IntSubclass(5)),
            ("negative", -1),
            ("overflow", INT_MAX + 1),
            ("float", 5.0),
            ("None", None),
        ):
            with self.subTest(fd=suffix):
                args = list((5, *CLOSE_TAIL))
                args[0] = bad
                state = self._seed_state()
                state._pending[100] = ("close", "fd", tuple(args))
                self._expect_format(
                    f"close fd {suffix}",
                    state,
                    lambda: state.try_admit_fd_table_mutator(tid=100),
                )

        for position in range(1, 6):
            for suffix, bad in (
                ("bool", True),
                ("integer subclass", IntSubclass(1)),
                ("negative", -1),
                ("overflow", 2**64),
                ("float", 1.0),
                ("None", None),
            ):
                with self.subTest(raw_slot=position, value=suffix):
                    args = list((5, *CLOSE_TAIL))
                    args[position] = bad
                    state = self._seed_state()
                    state._pending[100] = ("close", "fd", tuple(args))
                    self._expect_format(
                        f"close raw slot {position} {suffix}",
                        state,
                        lambda: state.try_admit_fd_table_mutator(tid=100),
                    )

        state = self._seed_state()
        root_pending = self._arm(state, self._close_operation())
        peer_pending = self._arm(state, self._close_operation(), tid=101)
        copied_table = state._task(102)["fds"]
        root_table = state._task(100)["fds"]
        self.assertIsNot(root_table, copied_table)
        self.assertEqual(root_table, copied_table)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self._assert_owner("close owner setup", state, root_table, 100, root_pending)
        owners = state._fd_table_mutators
        owner = owners[0]
        before = self._snapshot(state)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self._assert_unchanged("same close owner retry", before, self._snapshot(state))
        self.assertIs(state._fd_table_mutators, owners)
        self.assertIs(owners[0], owner)
        before = self._snapshot(state)
        self.assertIs(state.try_admit_fd_table_mutator(tid=101), False)
        self._assert_unchanged(
            "shared-table close contention", before, self._snapshot(state)
        )
        copied_pending = self._arm(state, self._close_operation(), tid=102)
        self.assertIs(state.try_admit_fd_table_mutator(tid=102), True)
        self.assertEqual(len(state._fd_table_mutators), 2)
        copied_owner = state._fd_table_mutators[1]
        self.assertIs(type(copied_owner), tuple)
        self.assertEqual(len(copied_owner), 3)
        self.assertIs(copied_owner[0], copied_table)
        self.assertEqual(copied_owner[1], 102)
        self.assertIs(copied_owner[2], copied_pending)
        self.assertIs(state._pending[101], peer_pending)

    def test_stored_malformed_close_blocks_existing_handlers(self):
        for label, bad_pending in (
            ("stored close outer list", ["close", "fd", (5, *CLOSE_TAIL)]),
            (
                "stored close outer tuple subclass",
                TupleSubclass(("close", "fd", (5, *CLOSE_TAIL))),
            ),
            ("stored close wrong name", ("fcntl", "fd", (5, *CLOSE_TAIL))),
            ("stored close wrong category", ("close", "path", (5, *CLOSE_TAIL))),
            (
                "stored close arguments list",
                ("close", "fd", list((5, *CLOSE_TAIL))),
            ),
            ("stored close short shape", ("close", "fd", (5, *CLOSE_TAIL)[:5])),
            ("stored close fd bool", ("close", "fd", (True, *CLOSE_TAIL))),
            (
                "stored close fd overflow",
                ("close", "fd", (INT_MAX + 1, *CLOSE_TAIL)),
            ),
            (
                "stored close raw bool",
                ("close", "fd", (5, True, *CLOSE_TAIL[1:])),
            ),
            (
                "stored close raw overflow",
                ("close", "fd", (5, 2**64, *CLOSE_TAIL[1:])),
            ),
        ):
            for handler_name in ("dup2", "dup"):
                with self.subTest(stored=label, handler=handler_name):
                    state = self._seed_state()
                    selected = (
                        self._dup2_operation()
                        if handler_name == "dup2"
                        else self._dup_operation()
                    )
                    selected_pending = self._arm(state, selected)
                    self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
                    bad_table = state._task(102)["fds"]
                    state._pending[102] = bad_pending
                    state._fd_table_mutators.append((bad_table, 102, bad_pending))
                    self._expect_format(
                        f"{label} {handler_name} admission",
                        state,
                        lambda: state.try_admit_fd_table_mutator(tid=100),
                    )
                    if handler_name == "dup2":
                        invoke = lambda: state.finish_dup2_syscall(
                            tid=100, result=6, errno=None
                        )
                    else:
                        invoke = lambda: state.finish_dup_syscall(
                            tid=100, result=1, errno=None
                        )
                    self._expect_format(
                        f"{label} {handler_name} terminal", state, invoke
                    )
                    self.assertIs(state._pending[100], selected_pending)

    def test_terminal_outcomes_and_invalid_pairs(self):
        state = self._seed_state()
        pending = self._arm(state, self._close_operation(5))
        table = state._task(100)["fds"]
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self._assert_owner("first close-terminal admission", state, table, 100, pending)
        before_fds = self._fd_table_snapshot(table)
        receipt = state.finish_close_syscall(tid=100, result=0, errno=None)
        self._assert_receipt("first close-terminal success", receipt, pending, 0, None)
        self._assert_fd_delta(
            "first close-terminal success",
            before_fds,
            self._fd_table_snapshot(table),
            5,
        )
        self.assertNotIn(5, table)
        self.assertNotIn(100, state._pending)
        self.assertFalse(state._fd_table_mutators)

        for errno in (None, 4, 5, 28, 122):
            with self.subTest(present_errno=errno):
                result = 0 if errno is None else -1
                state, pending, table = self._admit_close()
                self._finish_valid_close(
                    f"present close result={result} errno={errno}",
                    state,
                    pending,
                    table,
                    5,
                    result,
                    errno,
                )

        state = self._seed_state()
        table = state._task(100)["fds"]
        state.close(tid=100, fd=5)
        self.assertNotIn(5, table)
        pending = self._arm(state, self._close_operation())
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self._finish_valid_close(
            "absent close EBADF", state, pending, table, 5, -1, 9, False
        )

        inverse_cases = [
            ("present EBADF inverse", -1, 9, 5, True),
            ("absent success inverse", 0, None, 5, False),
            ("unknown FD success", 0, None, 99, False),
        ]
        inverse_cases.extend(
            (f"absent post-close errno {errno}", -1, errno, 5, False)
            for errno in (4, 5, 28, 122)
        )
        for label, result, errno, fd, present in inverse_cases:
            with self.subTest(inverse=label):
                self._expect_invalid_close(label, result, errno, fd, present)

        for label, result, errno in (
            ("result bool", True, None),
            ("result false", False, None),
            ("result int subclass", IntSubclass(0), None),
            ("result float", 0.0, None),
            ("result None", None, None),
            ("result string", "0", None),
            ("success errno bool", 0, False),
            ("success errno int", 0, 0),
            ("success errno int subclass", 0, IntSubclass(9)),
            ("success errno float", 0, 0.0),
            ("success errno string", 0, "0"),
            ("failure result zero", 0, 9),
            ("failure result int subclass", IntSubclass(-1), 4),
            ("failure result float", -1.0, 4),
            ("failure result None", None, 4),
            ("failure errno None", -1, None),
            ("failure errno bool", -1, True),
            ("failure errno int subclass", -1, IntSubclass(4)),
            ("failure errno float", -1, 4.0),
            ("failure errno string", -1, "4"),
            ("failure unknown errno", -1, 1),
            ("failure wrong errno", -1, 6),
            ("unknown positive result", 1, None),
            ("unknown negative result", -2, None),
            ("restart EINTR pair", -512, 4),
            ("restart no-errno pair", -512, None),
            ("restart alternate pair", -513, 4),
        ):
            with self.subTest(invalid_outcome=label):
                self._expect_invalid_close(label, result, errno)

        state = self._seed_state()
        pending = self._arm(state, self._close_operation())
        self._expect_format(
            "close terminal without owner",
            state,
            lambda: state.finish_close_syscall(tid=100, result=0, errno=None),
        )
        self.assertIs(state._pending[100], pending)
        self.assertFalse(state._fd_table_mutators)

    def test_close_effects_preserve_aliases_mappings_and_restart(self):
        state = self._seed_state()
        root_table = state._task(100)["fds"]
        shared_table = state._task(101)["fds"]
        copied_table = state._task(102)["fds"]
        copied_entry = copied_table[5]
        root_pending = self._arm(state, self._close_operation(), tid=100)
        shared_pending = self._arm(state, self._close_operation(), tid=101)
        copied_pending = self._arm(state, self._close_operation(), tid=102)
        self.assertIs(shared_table, root_table)
        self.assertIsNot(copied_table, root_table)
        self.assertEqual(copied_table, root_table)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self._finish_valid_close(
            "shared/copy close", state, root_pending, root_table, 5, 0, None
        )
        self.assertNotIn(5, shared_table)
        self.assertIs(copied_table.get(5), copied_entry)
        self.assertIs(state._pending.get(101), shared_pending)
        self.assertIs(state._pending.get(102), copied_pending)

        state = self._seed_state()
        table = state._task(100)["fds"]
        state.dup2(tid=100, source_fd=5, target_fd=7)
        source_description = table[5][0]
        alias_entry = table[7]
        alias_description = alias_entry[0]
        self.assertIs(alias_description, source_description)
        self.assertIs(alias_entry[1], False)
        pending = self._arm(state, self._close_operation(5))
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self._finish_valid_close(
            "close one alias", state, pending, table, 5, 0, None
        )
        self.assertIs(table.get(7), alias_entry)
        self.assertIs(table[7][0], alias_description)
        self.assertIs(table[7][1], False)

        state = self._seed_state()
        table = state._task(100)["fds"]
        description = table[5][0]
        node = description.identity
        maps = state._task(100)["maps"]
        state.map_file(
            tid=100,
            start=0x3000,
            length=0x1000,
            node=node,
            offset=0,
            prot=object(),
            shared=False,
        )
        mapping = maps[0x3000]
        copied_table = state._task(102)["fds"]
        self.assertIsNot(copied_table, table)
        self.assertIs(copied_table[5][0], description)
        state.close(tid=102, fd=5)
        self.assertNotIn(5, copied_table)
        self.assertFalse(
            any(entry[0] is description for fd, entry in table.items() if fd != 5)
        )
        pending = self._arm(state, self._close_operation(5))
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self._finish_valid_close(
            "close last mapped FD", state, pending, table, 5, 0, None
        )
        self.assertIs(maps, state._task(100)["maps"])
        self.assertIs(maps.get(0x3000), mapping)
        self.assertIs(maps[0x3000][1], node)
        seen_tables = []
        for task in state._tasks.values():
            candidate = task["fds"]
            if any(candidate is existing for existing in seen_tables):
                continue
            seen_tables.append(candidate)
            self.assertFalse(
                any(entry[0] is description for entry in candidate.values())
            )

        state = self._seed_state()
        pending = self._arm(state, self._close_operation())
        table = state._task(100)["fds"]
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        owners = state._fd_table_mutators
        owner = owners[0]
        self.assertIsNone(state.finish_syscall(tid=100, outcome="restart"))
        self.assertIs(state._pending.get(100), pending)
        self.assertIs(owners[0], owner)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self.assertIs(state._fd_table_mutators, owners)
        self.assertIs(owners[0], owner)
        self._finish_valid_close(
            "close after restart", state, pending, table, 5, 0, None
        )

    def test_unrelated_owner_validation(self):
        def malformed_owner(state):
            state._fd_table_mutators.append(("bad owner",))

        def malformed_table(state):
            state._task(102)["fds"] = []
            bad_pending = self._close_operation()
            state._pending[102] = bad_pending
            state._fd_table_mutators.append(
                (state._task(102)["fds"], 102, bad_pending)
            )

        def malformed_operation(state):
            bad_pending = ["close", "fd", (5, *CLOSE_TAIL)]
            state._pending[102] = bad_pending
            state._fd_table_mutators.append(
                (state._task(102)["fds"], 102, bad_pending)
            )

        for label, configure in (
            ("close malformed unrelated owner", malformed_owner),
            ("close malformed unrelated table", malformed_table),
            ("close malformed unrelated operation", malformed_operation),
        ):
            with self.subTest(unrelated=label):
                state = self._seed_state()
                pending = self._arm(state, self._close_operation())
                table = state._task(100)["fds"]
                self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
                configure(state)
                self._expect_format(
                    label,
                    state,
                    lambda: state.finish_close_syscall(
                        tid=100, result=0, errno=None
                    ),
                )
                self.assertIs(state._pending[100], pending)
                self.assertIn(5, table)

    def test_later_owner_index_cleanup(self):
        state = self._seed_state()
        copied_pending = self._arm(state, self._close_operation(), tid=102)
        root_pending = self._arm(state, self._close_operation(), tid=100)
        state.spawn(
            parent_tid=100,
            child_tid=103,
            share_files=False,
            share_fs=False,
            share_vm=False,
            thread_group=False,
        )
        third_pending = self._arm(state, self._close_operation(), tid=103)
        self.assertIs(state.try_admit_fd_table_mutator(tid=102), True)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self.assertIs(state.try_admit_fd_table_mutator(tid=103), True)
        owners = state._fd_table_mutators
        pending_entries = state._pending
        self.assertEqual(len(owners), 3)
        self.assertEqual(len(pending_entries), 3)
        unrelated = owners[0]
        selected_owner = owners[1]
        trailing_owner = owners[2]
        self.assertIs(selected_owner, owners[1])
        self.assertIsNot(selected_owner, owners[-1])
        root_table = state._task(100)["fds"]
        effect_entry_checked = []
        original_close = state.close

        def discriminate_close(**kwargs):
            self.assertEqual(kwargs, {"tid": 100, "fd": 5})
            selected = state._fd_table_mutators[1]
            self.assertIs(selected, selected_owner)
            self.assertIs(type(selected), tuple)
            self.assertEqual(len(selected), 3)
            self.assertIs(selected[0], root_table)
            self.assertEqual(selected[1], 100)
            self.assertIs(selected[2], root_pending)
            self.assertIs(state._pending.get(100), root_pending)
            self.assertIs(state._fd_table_mutators, owners)
            self.assertIs(state._pending, pending_entries)
            self.assertIs(state._fd_table_mutators[0], unrelated)
            self.assertIs(state._fd_table_mutators[2], trailing_owner)
            self.assertIs(state._pending.get(102), copied_pending)
            self.assertIs(state._pending.get(103), third_pending)
            effect_entry_checked.append(True)
            original_close(**kwargs)
            self.assertNotIn(5, root_table)
            state._fd_table_mutators[1] = ("post-effect malformed owner",)

        state.close = discriminate_close
        before_fds = self._fd_table_snapshot(root_table)
        receipt = state.finish_close_syscall(tid=100, result=0, errno=None)
        self._assert_receipt("later-index close", receipt, root_pending, 0, None)
        self._assert_fd_delta(
            "later-index close",
            before_fds,
            self._fd_table_snapshot(root_table),
            5,
        )
        self.assertEqual(effect_entry_checked, [True])
        self.assertNotIn(100, state._pending)
        self.assertIs(state._fd_table_mutators, owners)
        self.assertIs(state._pending, pending_entries)
        self.assertEqual(len(state._fd_table_mutators), 2)
        self.assertIs(state._fd_table_mutators[0], unrelated)
        self.assertIs(state._fd_table_mutators[1], trailing_owner)
        self.assertIs(type(state._fd_table_mutators[0]), tuple)
        self.assertEqual(len(state._fd_table_mutators[0]), 3)
        self.assertIs(state._fd_table_mutators[0][0], state._task(102)["fds"])
        self.assertEqual(state._fd_table_mutators[0][1], 102)
        self.assertIs(state._fd_table_mutators[0][2], copied_pending)
        self.assertIs(state._pending.get(102), copied_pending)
        self.assertIs(state._pending.get(103), third_pending)
        self.assertEqual(set(state._pending), {102, 103})
        self.assertNotIn(5, root_table)

    def test_private_slice_exports_no_runner(self):
        self.assertFalse(callable(getattr(self.module, "run", None)))
        self.assertFalse(callable(getattr(self.module, "produce", None)))


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
