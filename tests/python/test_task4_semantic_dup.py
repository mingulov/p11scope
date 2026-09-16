"""Semantic trace private dup-outcome contracts."""

import importlib.util
from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/task4-build-subject.py"
MODULE_NAME = "task4_build_subject_semantic_dup_test"
MISSING = object()


class IntSubclass(int):
    pass


class StringSubclass(str):
    pass


class DictSubclass(dict):
    pass


class TupleSubclass(tuple):
    pass


INT_MAX = 2**31 - 1
MAX_U64 = 2**64 - 1
TAIL = (0, 17, 2**63, MAX_U64, 1)
BASE_ARGS = (5, *TAIL)


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
    spec = importlib.util.spec_from_file_location(MODULE_NAME, SCRIPT_PATH)
    if spec is None or spec.loader is None:
        test.fail("could not import task4 build-subject script")
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


class SemanticTraceDupTests(unittest.TestCase):
    def setUp(self):
        self.module = load_subject(self)

    @staticmethod
    def _dup_operation(oldfd=5, tail=TAIL):
        return ("dup", "fd", (oldfd, *tail))

    def _seed_state(self, root_tid=100, base_fds=None):
        if base_fds is None:
            base_fds = {
                0: (object(), True),
                2: (object(), False),
                4: (object(), True),
            }
        state = self.module._SemanticTraceState(
            root_tid=root_tid,
            cwd=object(),
            root=object(),
            umask=0o022,
            fds=base_fds,
        )
        state.install_open_fd(
            tid=root_tid,
            fd=5,
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

    def _arm_pending(self, state, root_tid=100, operation=None, peer=True):
        if operation is None:
            operation = self._dup_operation()
        state.begin_syscall(tid=root_tid, operation=operation)
        refs = {root_tid: operation}
        if peer:
            peer_operation = ("C_Peer", "pure", (0, 0, 0, 0, 0, 0))
            state.begin_syscall(tid=101, operation=peer_operation)
            refs[101] = peer_operation
        return refs

    def _arm_malformed_pending(self, state, pending, root_tid=100, peer=True):
        refs = {}
        if peer:
            peer_operation = ("C_Peer", "pure", (0, 0, 0, 0, 0, 0))
            state.begin_syscall(tid=101, operation=peer_operation)
            refs[101] = peer_operation
        state._pending[root_tid] = pending
        refs[root_tid] = pending
        return refs

    def _same_value(self, left, right):
        if left is right:
            return True
        if type(left) is not type(right):
            return False
        if type(left) is tuple or type(left) is list:
            return len(left) == len(right) and all(
                self._same_value(a, b) for a, b in zip(left, right)
            )
        if type(left) is dict:
            return list(left) == list(right) and all(
                self._same_value(left[key], right[key]) for key in left
            )
        try:
            return bool(left == right)
        except BaseException:
            return False

    @staticmethod
    def _description_fields(description):
        try:
            return (
                "typed",
                description.kind,
                description.access,
                description.offset,
                description.identity,
            )
        except AttributeError:
            return ("opaque", description)

    def _observation(self, state, tids=(100, 101, 102)):
        result = {}
        for tid in tids:
            task = state._task(tid)
            fds = task["fds"]
            fd_rows = []
            if isinstance(fds, dict):
                for fd, entry in fds.items():
                    if type(entry) is tuple and len(entry) == 2:
                        fd_rows.append(
                            (
                                fd,
                                entry,
                                entry[0],
                                entry[1],
                                self._description_fields(entry[0]),
                            )
                        )
                    else:
                        fd_rows.append((fd, entry, entry, None, None))
            fs = task["fs"]
            maps = task["maps"]
            result[tid] = (
                task,
                task["tgid"],
                fds,
                tuple(fd_rows),
                fs,
                (fs.get("cwd"), fs.get("root"), fs.get("umask")),
                maps,
                tuple(maps.items()) if type(maps) is dict else maps,
            )
        return result

    def _same_observation(self, before, after):
        if set(before) != set(after):
            return False
        for tid in before:
            left, right = before[tid], after[tid]
            if left[0] is not right[0] or left[1] != right[1]:
                return False
            if left[2] is not right[2] or left[4] is not right[4] or left[6] is not right[6]:
                return False
            if not self._same_value(left[5], right[5]):
                return False
            if isinstance(left[2], dict):
                if len(left[3]) != len(right[3]):
                    return False
                for old, new in zip(left[3], right[3]):
                    if old[0] != new[0] or old[1] is not new[1]:
                        return False
                    if old[2] is not new[2] or old[3] is not new[3]:
                        return False
                    if not self._same_value(old[4], new[4]):
                        return False
            if type(left[6]) is dict:
                if len(left[7]) != len(right[7]):
                    return False
                for (old_key, old_value), (new_key, new_value) in zip(
                    left[7], right[7]
                ):
                    if old_key != new_key or old_value is not new_value:
                        return False
        return True

    @staticmethod
    def _pending_refs(state):
        return {tid: operation for tid, operation in state._pending.items()}

    @staticmethod
    def _owner_snapshot(state):
        owners = state._fd_table_mutators
        rows = []
        refs = []
        if type(owners) is list:
            for owner in owners:
                if type(owner) is tuple and len(owner) == 3:
                    table, tid, pending = owner
                    refs.append((owner, table, pending))
                    rows.append(
                        (
                            type(owner),
                            type(table),
                            type(tid),
                            tid,
                            type(pending),
                        )
                    )
                else:
                    refs.append((owner, None, None))
                    rows.append(
                        (
                            type(owner),
                            len(owner) if type(owner) in (tuple, list) else None,
                        )
                    )
        return (owners, (type(owners), tuple(rows)), tuple(refs))

    def _assert_owner_snapshot(self, label, before, after):
        before_owners, before_fingerprint, before_refs = before
        after_owners, after_fingerprint, after_refs = after
        self.assertEqual(
            before_fingerprint,
            after_fingerprint,
            f"{label}: owner list/tuple/table/pending identity changed",
        )
        self.assertIs(
            after_owners,
            before_owners,
            f"{label}: owner list/tuple/table/pending identity changed",
        )
        self.assertEqual(
            len(after_refs),
            len(before_refs),
            f"{label}: owner list/tuple/table/pending identity changed",
        )
        for before_ref, after_ref in zip(before_refs, after_refs):
            self.assertTrue(
                all(
                    before_item is after_item
                    for before_item, after_item in zip(before_ref, after_ref)
                ),
                f"{label}: owner list/tuple/table/pending identity changed",
            )

    def _assert_pending(self, label, state, refs):
        self.assertEqual(
            set(state._pending), set(refs), f"{label}: pending TID set changed"
        )
        for tid, operation in refs.items():
            self.assertIs(
                state._pending[tid],
                operation,
                f"{label}: pending tuple identity changed",
            )

    def _assert_receipt(self, label, receipt, pending, result, errno):
        self.assertIs(type(receipt), tuple, f"{label}: result type")
        self.assertEqual(len(receipt), 3, f"{label}: result length")
        self.assertIs(receipt[0], pending, f"{label}: pending identity")
        self.assertIs(type(receipt[1]), int, f"{label}: result type")
        self.assertEqual(receipt[1], result, f"{label}: result value")
        if errno is None:
            self.assertIsNone(receipt[2], f"{label}: success errno")
        else:
            self.assertIs(type(receipt[2]), int, f"{label}: errno type")
            self.assertEqual(receipt[2], errno, f"{label}: errno value")

    def _assert_fd(self, label, state, tid, fd, description, cloexec):
        entry = state._task(tid)["fds"][fd]
        self.assertIs(type(entry), tuple, f"{label}: entry type")
        self.assertEqual(len(entry), 2, f"{label}: entry length")
        self.assertIs(type(entry[1]), bool, f"{label}: CLOEXEC type")
        self.assertIs(entry[0], description, f"{label}: description identity")
        self.assertIs(entry[1], cloexec, f"{label}: CLOEXEC changed")

    def _expect_rejected(self, label, state, invoke, refs=None, root_tid=100):
        before = self._observation(state, (root_tid, 101, 102))
        before_owner = self._owner_snapshot(state)
        if refs is None:
            refs = self._pending_refs(state)
        try:
            invoke()
        except BaseException as exc:
            self.assertIs(
                type(exc),
                self.module.FormatError,
                f"{label}: expected exact FormatError, got {type(exc).__name__}: {exc}",
            )
        else:
            self.fail(f"{label}: invalid completion was accepted")
        self.assertTrue(
            self._same_observation(
                before, self._observation(state, (root_tid, 101, 102))
            ),
            f"{label}: rejection changed semantic state",
        )
        self._assert_owner_snapshot(label, before_owner, self._owner_snapshot(state))
        self._assert_pending(label, state, refs)

    def _expect_rejected_pending(self, label, pending, result=1, errno=None):
        state = self._seed_state()
        refs = self._arm_malformed_pending(state, pending)
        self._expect_rejected(
            label,
            state,
            lambda: state.finish_dup_syscall(tid=100, result=result, errno=errno),
            refs,
        )

    def _expect_rejected_valid(self, label, result=1, errno=None, operation=None):
        state = self._seed_state()
        refs = self._arm_pending(state, operation=operation)
        self.assertIs(
            state.try_admit_fd_table_mutator(tid=100),
            True,
            f"{label}: valid owner admission failed",
        )
        self._expect_rejected(
            label,
            state,
            lambda: state.finish_dup_syscall(tid=100, result=result, errno=errno),
            refs,
        )

    def _expect_rejected_tid(self, label, tid, result, errno, root_tid=100):
        state = self._seed_state(root_tid)
        refs = self._arm_pending(state, root_tid=root_tid)
        self._expect_rejected(
            label,
            state,
            lambda: state.finish_dup_syscall(tid=tid, result=result, errno=errno),
            refs,
            root_tid,
        )

    def test_success_failure_and_restart_outcomes(self):
        state = self._seed_state()
        refs = self._arm_pending(state)
        pending = refs[100]
        peer_pending = refs[101]
        source = state._task(100)["fds"][5][0]
        root_table = state._task(100)["fds"]
        copied_table = state._task(102)["fds"]
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup_syscall(tid=100, result=1, errno=None)
        self._assert_receipt("lowest-gap success", receipt, pending, 1, None)
        self.assertIs(root_table, state._task(101)["fds"])
        self.assertIsNot(root_table, copied_table)
        self._assert_fd("lowest-gap source", state, 100, 5, source, True)
        self._assert_fd("lowest-gap root", state, 100, 1, source, False)
        self._assert_fd("lowest-gap shared peer", state, 101, 1, source, False)
        self.assertNotIn(1, state._task(102)["fds"])
        self.assertEqual(source.offset, 7)
        self.assertIs(state._task(100)["fds"][0][1], True)
        self._assert_pending("lowest-gap success", state, {101: peer_pending})

        state = self._seed_state(base_fds={2: (object(), False), 4: (object(), True)})
        refs = self._arm_pending(state)
        pending = refs[100]
        source = state._task(100)["fds"][5][0]
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup_syscall(tid=100, result=0, errno=None)
        self._assert_receipt("lowest-zero success", receipt, pending, 0, None)
        self._assert_fd("lowest-zero root", state, 100, 0, source, False)
        self._assert_fd("lowest-zero shared peer", state, 101, 0, source, False)
        self.assertNotIn(0, state._task(102)["fds"])
        self._assert_pending("lowest-zero success", state, {101: refs[101]})

        for errno, oldfd in ((9, 99), (24, 5)):
            state = self._seed_state()
            refs = self._arm_pending(state, operation=self._dup_operation(oldfd))
            pending = refs[100]
            before = self._observation(state)
            self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
            receipt = state.finish_dup_syscall(tid=100, result=-1, errno=errno)
            self._assert_receipt(
                f"failure errno {errno}", receipt, pending, -1, errno
            )
            self.assertTrue(self._same_observation(before, self._observation(state)))
            self._assert_pending(
                f"failure errno {errno}", state, {101: refs[101]}
            )

        self._expect_rejected_valid(
            "EBADF with existing source",
            result=-1,
            errno=9,
            operation=self._dup_operation(5),
        )
        self._expect_rejected_valid(
            "EMFILE with absent source",
            result=-1,
            errno=24,
            operation=self._dup_operation(99),
        )

        state = self._seed_state()
        refs = self._arm_pending(state)
        pending = refs[100]
        before = self._observation(state)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        self.assertIsNone(state.finish_syscall(tid=100, outcome="restart"))
        self.assertTrue(self._same_observation(before, self._observation(state)))
        self._assert_pending("restart", state, refs)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup_syscall(tid=100, result=1, errno=None)
        self._assert_receipt("completion after restart", receipt, pending, 1, None)
        self._assert_pending("completion after restart", state, {101: refs[101]})

    def test_result_and_pending_validation(self):
        for label, result in (
            ("occupied result", 0),
            ("non-lowest vacancy", 3),
            ("result equal to source", 5),
            ("negative result", -1),
            ("result above INT_MAX", INT_MAX + 1),
            ("boolean result", True),
            ("integer-subclass result", IntSubclass(1)),
        ):
            self._expect_rejected_valid(label, result=result, errno=None)
        self._expect_rejected_valid(
            "missing success source",
            result=1,
            errno=None,
            operation=self._dup_operation(99),
        )

        for label, result, errno in (
            ("EINTR", -1, 4),
            ("EBUSY", -1, 16),
            ("unknown errno one", -1, 1),
            ("unknown errno five", -1, 5),
            ("unknown errno large", -1, 2**31),
            ("success with errno", 1, 9),
            ("failure without errno", -1, None),
            ("wrong result with errno", 0, 9),
            ("other negative result", -2, 9),
            ("raw restart -512", -512, 4),
            ("raw restart -513", -513, 4),
            ("raw restart -514", -514, 4),
            ("raw restart -516", -516, 4),
        ):
            self._expect_rejected_valid(label, result=result, errno=errno)
        for label, result, errno in (
            ("result bool failure", False, 9),
            ("result integer subclass failure", IntSubclass(-1), 9),
            ("result float", 1.0, None),
            ("result string", "1", None),
            ("errno bool", -1, True),
            ("errno integer subclass", -1, IntSubclass(9)),
            ("errno float", -1, 9.0),
            ("errno string", -1, "9"),
        ):
            self._expect_rejected_valid(label, result=result, errno=errno)

        for label, bad_pending in (
            ("wrong operation name", ("dup2", "fd", BASE_ARGS)),
            ("wrong operation category", ("dup", "path", BASE_ARGS)),
            ("operation list", ["dup", "fd", BASE_ARGS]),
            ("operation tuple subclass", TupleSubclass(("dup", "fd", BASE_ARGS))),
            ("operation two-item tuple", ("dup", "fd")),
            ("operation four-item tuple", ("dup", "fd", BASE_ARGS, "extra")),
            ("operation name subclass", (StringSubclass("dup"), "fd", BASE_ARGS)),
            (
                "operation category subclass",
                ("dup", StringSubclass("fd"), BASE_ARGS),
            ),
            ("arguments list", ("dup", "fd", list(BASE_ARGS))),
            ("arguments tuple subclass", ("dup", "fd", TupleSubclass(BASE_ARGS))),
            ("five arguments", ("dup", "fd", BASE_ARGS[:5])),
            ("seven arguments", ("dup", "fd", BASE_ARGS + (7,))),
        ):
            self._expect_rejected_pending(label, bad_pending)

    def test_argument_boundaries_and_validation(self):
        for oldfd in (0, INT_MAX):
            state = self._seed_state()
            state._task(100)["fds"][oldfd] = (object(), False)
            refs = self._arm_pending(state, operation=self._dup_operation(oldfd))
            pending = refs[100]
            before = self._observation(state)
            self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
            receipt = state.finish_dup_syscall(tid=100, result=-1, errno=24)
            self._assert_receipt("oldfd boundary", receipt, pending, -1, 24)
            self.assertTrue(self._same_observation(before, self._observation(state)))
            self._assert_pending("oldfd boundary", state, {101: refs[101]})

        for label, bad in (
            ("negative", -1),
            ("above INT_MAX", INT_MAX + 1),
            ("bool", True),
            ("integer subclass", IntSubclass(5)),
            ("float", 5.0),
            ("None", None),
        ):
            args = list(BASE_ARGS)
            args[0] = bad
            self._expect_rejected_pending(
                f"oldfd {label}", ("dup", "fd", tuple(args))
            )

        for tail in ((0, 0, 0, 0, 0), (1, 2, 3, 4, 5), (MAX_U64,) * 5):
            state = self._seed_state()
            pending = self._dup_operation(5, tail)
            refs = self._arm_pending(state, operation=pending)
            self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
            receipt = state.finish_dup_syscall(tid=100, result=1, errno=None)
            self._assert_receipt("uninterpreted raw tail", receipt, pending, 1, None)
            self._assert_pending("uninterpreted raw tail", state, {101: refs[101]})

        for position in range(1, 6):
            for label, bad in (
                ("bool", True),
                ("integer subclass", IntSubclass(1)),
                ("negative", -1),
                ("u64 overflow", 2**64),
            ):
                args = list(BASE_ARGS)
                args[position] = bad
                self._expect_rejected_pending(
                    f"raw argument slot {position} {label}",
                    ("dup", "fd", tuple(args)),
                )

    def test_malformed_tables_and_legacy_topology(self):
        malformed_tables = (
            ("table dict subclass", DictSubclass({5: (object(), False)}), 0),
            (
                "boolean unrelated key",
                {5: (object(), False), True: (object(), False)},
                0,
            ),
            (
                "integer-subclass unrelated key",
                {5: (object(), False), IntSubclass(1): (object(), False)},
                0,
            ),
            (
                "negative unrelated key",
                {5: (object(), False), -1: (object(), False)},
                0,
            ),
            ("list entry", {5: (object(), False), 8: [object(), False]}, 0),
            ("short tuple entry", {5: (object(), False), 8: (object(),)}, 0),
            (
                "long tuple entry",
                {5: (object(), False), 8: (object(), False, object())},
                0,
            ),
            (
                "boolean CLOEXEC entry",
                {5: (object(), False), 8: (object(), 1)},
                0,
            ),
            (
                "tuple-subclass entry",
                {5: (object(), False), 8: TupleSubclass((object(), False))},
                0,
            ),
            (
                "malformed unrelated entry",
                {0: (object(), False), 5: (object(), False), 8: [object(), False]},
                1,
            ),
        )
        for label, table, lowest in malformed_tables:
            state = self._seed_state()
            refs = self._arm_pending(state, operation=self._dup_operation(5))
            state._task(100)["fds"] = table
            for result, errno in ((lowest, None), (-1, 24)):
                self._expect_rejected(
                    f"{label} terminal {result}",
                    state,
                    lambda result=result, errno=errno: state.finish_dup_syscall(
                        tid=100, result=result, errno=errno
                    ),
                    refs,
                )

        state = self._seed_state()
        high_fd = INT_MAX + 1
        high_description = object()
        high_entry = (high_description, True)
        state._task(100)["fds"][high_fd] = high_entry
        refs = self._arm_pending(state)
        pending = refs[100]
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup_syscall(tid=100, result=1, errno=None)
        self._assert_receipt("legacy high key", receipt, pending, 1, None)
        self.assertIs(state._task(100)["fds"][high_fd], high_entry)
        self.assertIs(state._task(100)["fds"][high_fd][0], high_description)
        self.assertIs(state._task(100)["fds"][high_fd][1], True)
        self._assert_fd(
            "legacy high key target",
            state,
            100,
            1,
            state._task(100)["fds"][5][0],
            False,
        )
        self._assert_pending("legacy high key", state, {101: refs[101]})

        state = self._seed_state()
        legacy = state._task(100)["fds"][2][0]
        refs = self._arm_pending(state, operation=self._dup_operation(2))
        pending = refs[100]
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup_syscall(tid=100, result=1, errno=None)
        self._assert_receipt("legacy opaque source", receipt, pending, 1, None)
        self._assert_fd("legacy source", state, 100, 2, legacy, False)
        self._assert_fd("legacy target", state, 100, 1, legacy, False)
        self._assert_fd("legacy shared target", state, 101, 1, legacy, False)
        self.assertNotIn(1, state._task(102)["fds"])
        self._assert_pending("legacy opaque source", state, {101: refs[101]})

    def test_invalid_tids_and_completion_lifecycle(self):
        invalid_tids = (
            ("unknown", 999),
            ("bool true", True),
            ("bool false", False),
            ("string", "100"),
            ("string subclass", StringSubclass("100")),
            ("None", None),
            ("zero", 0),
            ("negative", -1),
            ("float", 100.0),
            ("integer subclass", IntSubclass(100)),
        )
        for label, tid in invalid_tids:
            self._expect_rejected_tid(f"invalid success TID {label}", tid, 1, None)
            self._expect_rejected_tid(f"invalid failure TID {label}", tid, -1, 24)
        self._expect_rejected_tid(
            "alias success TID", IntSubclass(1), 1, None, root_tid=1
        )
        self._expect_rejected_tid(
            "alias failure TID", IntSubclass(1), -1, 24, root_tid=1
        )

        state = self._seed_state()
        self._arm_pending(state, peer=False)
        del state._pending[100]
        self._expect_rejected(
            "orphan completion",
            state,
            lambda: state.finish_dup_syscall(tid=100, result=1, errno=None),
            {},
        )

        state = self._seed_state()
        refs = self._arm_pending(state)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        first = state.finish_dup_syscall(tid=100, result=-1, errno=24)
        self._assert_receipt("duplicate setup", first, refs[100], -1, 24)
        self._expect_rejected(
            "duplicate completion",
            state,
            lambda: state.finish_dup_syscall(tid=100, result=-1, errno=24),
            {101: refs[101]},
        )

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
