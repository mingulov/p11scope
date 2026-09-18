"""Semantic trace private dup2-outcome contracts."""

from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/receipt-build-subject.py"
MODULE_NAME = "receipt_build_subject_semantic_dup2_test"
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
TAIL = (17, 2**63, 2**64 - 2, MAX_U64)
BASE_ARGS = (5, 6, *TAIL)


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
        test.fail("could not import receipt build-subject script")
    sys.modules[MODULE_NAME] = module
    return module


class SemanticTraceDup2Tests(unittest.TestCase):
    def setUp(self):
        self.module = load_subject(self)

    @staticmethod
    def _dup_operation(oldfd=5, newfd=6, tail=TAIL):
        return ("dup2", "fd", (oldfd, newfd, *tail))

    def _seed_state(self, root_tid=100, include_target=True):
        state = self.module._SemanticTraceState(
            root_tid=root_tid,
            cwd=object(),
            root=object(),
            umask=0o022,
            fds={3: (object(), False), 4: (object(), True)},
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
        if include_target:
            state.install_open_fd(
                tid=root_tid,
                fd=6,
                node=object(),
                kind="regular",
                access="read_write",
                cloexec=True,
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

    @staticmethod
    def _arm_malformed_pending(state, pending, root_tid=100, peer=True):
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
            if type(fds) is dict:
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
            if type(left[2]) is dict:
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
        self.assertEqual(after_fingerprint, before_fingerprint, label)
        self.assertIs(after_owners, before_owners, label)
        self.assertEqual(len(after_refs), len(before_refs), label)
        for before_ref, after_ref in zip(before_refs, after_refs):
            for before_item, after_item in zip(before_ref, after_ref):
                self.assertIs(after_item, before_item, label)

    def _assert_pending(self, label, state, refs):
        self.assertEqual(set(state._pending), set(refs), f"{label}: pending TIDs")
        for tid, operation in refs.items():
            self.assertIs(state._pending[tid], operation, f"{label}: pending identity")

    def _assert_receipt(self, label, receipt, pending, result, errno):
        self.assertIs(type(receipt), tuple, f"{label}: receipt type")
        self.assertEqual(len(receipt), 3, f"{label}: receipt length")
        self.assertIs(receipt[0], pending, f"{label}: pending identity")
        self.assertIs(type(receipt[1]), int, f"{label}: result type")
        self.assertEqual(receipt[1], result, f"{label}: result")
        if errno is None:
            self.assertIsNone(receipt[2], f"{label}: success errno")
        else:
            self.assertIs(type(receipt[2]), int, f"{label}: errno type")
            self.assertEqual(receipt[2], errno, f"{label}: errno")

    def _assert_fd(self, label, state, tid, fd, description, cloexec):
        entry = state._task(tid)["fds"][fd]
        self.assertIs(type(entry), tuple, f"{label}: entry type")
        self.assertEqual(len(entry), 2, f"{label}: entry length")
        self.assertIs(type(entry[1]), bool, f"{label}: CLOEXEC type")
        self.assertIs(entry[0], description, f"{label}: description identity")
        self.assertIs(entry[1], cloexec, f"{label}: CLOEXEC identity")

    def _expect_rejected(self, label, state, invoke, refs=None, root_tid=100):
        tids = (root_tid, 101, 102)
        before = self._observation(state, tids)
        before_owner = self._owner_snapshot(state)
        if refs is None:
            refs = self._pending_refs(state)
        try:
            invoke()
        except BaseException as exc:
            self.assertIs(
                type(exc),
                self.module.FormatError,
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}",
            )
        else:
            self.fail(f"{label}: invalid completion was accepted")
        self.assertTrue(
            self._same_observation(before, self._observation(state, tids)),
            f"{label}: rejection changed semantic state",
        )
        self._assert_owner_snapshot(label, before_owner, self._owner_snapshot(state))
        self._assert_pending(label, state, refs)

    def _expect_rejected_pending(self, label, pending, result=6, errno=None):
        state = self._seed_state()
        refs = self._arm_malformed_pending(state, pending)
        self._expect_rejected(
            label,
            state,
            lambda: state.finish_dup2_syscall(
                tid=100, result=result, errno=errno
            ),
            refs,
        )

    def _expect_rejected_valid(
        self, label, result=6, errno=None, operation=None
    ):
        state = self._seed_state()
        refs = self._arm_pending(state, operation=operation)
        self.assertIs(
            state.try_admit_fd_table_mutator(tid=100),
            True,
            f"{label}: valid owner admission",
        )
        self._expect_rejected(
            label,
            state,
            lambda: state.finish_dup2_syscall(
                tid=100, result=result, errno=errno
            ),
            refs,
        )

    def _expect_rejected_tid(self, label, tid, result, errno, root_tid=100):
        state = self._seed_state(root_tid)
        refs = self._arm_pending(state, root_tid=root_tid)
        self._expect_rejected(
            label,
            state,
            lambda: state.finish_dup2_syscall(tid=tid, result=result, errno=errno),
            refs,
            root_tid,
        )

    def test_success_failure_and_restart_outcomes(self):
        state = self._seed_state()
        refs = self._arm_pending(state)
        pending = refs[100]
        peer_pending = refs[101]
        source = state._task(100)["fds"][5][0]
        old_target = state._task(100)["fds"][6][0]
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup2_syscall(tid=100, result=6, errno=None)
        self._assert_receipt("distinct-target success", receipt, pending, 6, None)
        self.assertIs(state._task(100)["fds"], state._task(101)["fds"])
        self.assertIsNot(state._task(100)["fds"], state._task(102)["fds"])
        self._assert_fd("distinct-target root", state, 100, 5, source, True)
        self._assert_fd("distinct-target root", state, 100, 6, source, False)
        self._assert_fd("distinct-target shared peer", state, 101, 6, source, False)
        self._assert_fd("distinct-target copied peer", state, 102, 6, old_target, True)
        self.assertEqual(source.offset, 7)
        self.assertEqual(old_target.offset, 0)
        self._assert_pending("distinct-target success", state, {101: peer_pending})

        state = self._seed_state(include_target=False)
        refs = self._arm_pending(state)
        pending = refs[100]
        source = state._task(100)["fds"][5][0]
        root_table = state._task(100)["fds"]
        shared_table = state._task(101)["fds"]
        copied_table = state._task(102)["fds"]
        copied_before = self._observation(state, (102,))
        self.assertIs(root_table, shared_table)
        self.assertIsNot(root_table, copied_table)
        self.assertNotIn(6, state._task(100)["fds"])
        self.assertNotIn(6, state._task(102)["fds"])
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup2_syscall(tid=100, result=6, errno=None)
        self._assert_receipt("vacant-target success", receipt, pending, 6, None)
        self.assertIs(state._task(100)["fds"], root_table)
        self.assertIs(state._task(101)["fds"], shared_table)
        self.assertIs(state._task(102)["fds"], copied_table)
        self.assertIs(state._task(100)["fds"], state._task(101)["fds"])
        self._assert_fd("vacant-target root source", state, 100, 5, source, True)
        self._assert_fd("vacant-target shared source", state, 101, 5, source, True)
        self._assert_fd("vacant-target copied source", state, 102, 5, source, True)
        self._assert_fd("vacant-target root", state, 100, 6, source, False)
        self._assert_fd("vacant-target shared peer", state, 101, 6, source, False)
        self.assertNotIn(6, state._task(102)["fds"])
        self.assertTrue(
            self._same_observation(copied_before, self._observation(state, (102,)))
        )
        self._assert_pending("vacant-target success", state, {101: refs[101]})

        state = self._seed_state()
        refs = self._arm_pending(state, operation=self._dup_operation(5, 5))
        pending = refs[100]
        source = state._task(100)["fds"][5][0]
        before = self._observation(state)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup2_syscall(tid=100, result=5, errno=None)
        self._assert_receipt("same-FD success", receipt, pending, 5, None)
        self.assertTrue(self._same_observation(before, self._observation(state)))
        self._assert_fd("same-FD root", state, 100, 5, source, True)
        self._assert_fd("same-FD shared peer", state, 101, 5, source, True)
        self._assert_fd("same-FD copied peer", state, 102, 5, source, True)
        self._assert_pending("same-FD success", state, {101: refs[101]})

        for errno in (4, 9, 16, 24):
            with self.subTest(failure_errno=errno):
                state = self._seed_state()
                oldfd = 99 if errno == 9 else 5
                refs = self._arm_pending(
                    state, operation=self._dup_operation(oldfd, 6)
                )
                pending = refs[100]
                before = self._observation(state)
                self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
                receipt = state.finish_dup2_syscall(
                    tid=100, result=-1, errno=errno
                )
                self._assert_receipt(
                    f"failure errno {errno}", receipt, pending, -1, errno
                )
                self.assertTrue(
                    self._same_observation(before, self._observation(state))
                )
                self._assert_pending(
                    f"failure errno {errno}", state, {101: refs[101]}
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
        receipt = state.finish_dup2_syscall(tid=100, result=6, errno=None)
        self._assert_receipt(
            "normalized completion after restart", receipt, pending, 6, None
        )
        self._assert_pending(
            "normalized completion after restart", state, {101: refs[101]}
        )

    def test_operation_and_argument_validation(self):
        for label, bad_pending in (
            ("wrong operation name", ("dup", "fd", BASE_ARGS)),
            ("wrong operation category", ("dup2", "path", BASE_ARGS)),
            ("operation list", ["dup2", "fd", BASE_ARGS]),
            (
                "operation tuple subclass",
                TupleSubclass(("dup2", "fd", BASE_ARGS)),
            ),
            ("operation two-item tuple", ("dup2", "fd")),
            ("operation four-item tuple", ("dup2", "fd", BASE_ARGS, "extra")),
            ("arguments list", ("dup2", "fd", list(BASE_ARGS))),
            (
                "arguments tuple subclass",
                ("dup2", "fd", TupleSubclass(BASE_ARGS)),
            ),
            ("five arguments", ("dup2", "fd", BASE_ARGS[:5])),
            ("seven arguments", ("dup2", "fd", BASE_ARGS + (7,))),
        ):
            with self.subTest(operation=label):
                self._expect_rejected_pending(label, bad_pending)

        for oldfd, newfd in ((0, INT_MAX), (INT_MAX, 0)):
            with self.subTest(oldfd=oldfd, newfd=newfd):
                state = self._seed_state()
                refs = self._arm_pending(
                    state, operation=self._dup_operation(oldfd, newfd)
                )
                pending = refs[100]
                before = self._observation(state)
                self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
                receipt = state.finish_dup2_syscall(tid=100, result=-1, errno=9)
                self._assert_receipt(
                    "admitted FD endpoint", receipt, pending, -1, 9
                )
                self.assertTrue(
                    self._same_observation(before, self._observation(state))
                )
                self._assert_pending(
                    "admitted FD endpoint", state, {101: refs[101]}
                )

        for position, name in ((0, "oldfd"), (1, "newfd")):
            for label, bad in (
                ("negative", -1),
                ("above INT_MAX", INT_MAX + 1),
                ("bool", True),
                ("integer subclass", IntSubclass(5)),
                ("float", 5.0),
                ("None", None),
            ):
                with self.subTest(endpoint=name, value=label):
                    args = list(BASE_ARGS)
                    args[position] = bad
                    self._expect_rejected_pending(
                        f"{name} {label}", ("dup2", "fd", tuple(args))
                    )

        for tail in (
            (0, 0, 0, 0),
            (1, 2, 3, 4),
            (MAX_U64, MAX_U64, MAX_U64, MAX_U64),
        ):
            with self.subTest(tail=tail):
                state = self._seed_state()
                pending = self._dup_operation(5, 6, tail)
                refs = self._arm_pending(state, operation=pending)
                self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
                receipt = state.finish_dup2_syscall(
                    tid=100, result=6, errno=None
                )
                self._assert_receipt(
                    "uninterpreted raw arguments", receipt, pending, 6, None
                )
                self._assert_pending(
                    "uninterpreted raw arguments", state, {101: refs[101]}
                )

        for position in range(2, 6):
            for label, bad in (
                ("bool", True),
                ("integer subclass", IntSubclass(1)),
                ("negative", -1),
                ("u64 overflow", 2**64),
            ):
                with self.subTest(raw_slot=position, value=label):
                    args = list(BASE_ARGS)
                    args[position] = bad
                    self._expect_rejected_pending(
                        f"raw argument slot {position} {label}",
                        ("dup2", "fd", tuple(args)),
                    )

    def test_result_errno_and_source_validation(self):
        for label, result, errno in (
            ("bool success result", True, None),
            ("bool failure result", False, 4),
            ("integer-subclass success result", IntSubclass(6), None),
            ("integer-subclass failure result", IntSubclass(-1), 4),
            ("float result", 6.0, None),
            ("string result", "6", None),
            ("bool errno", -1, True),
            ("integer-subclass errno", -1, IntSubclass(4)),
            ("float errno", -1, 4.0),
            ("string errno", -1, "4"),
            ("success result with errno", 6, 4),
            ("failure result without errno", -1, None),
            ("wrong result with errno", 5, 4),
            ("other negative result", -2, 4),
        ):
            with self.subTest(outcome=label):
                self._expect_rejected_valid(label, result, errno)

        for errno in (0, 5, 25, 2**31):
            with self.subTest(unknown_errno=errno):
                self._expect_rejected_valid(
                    f"unknown errno {errno}", result=-1, errno=errno
                )

        for raw_restart in (-512, -513, -514, -516):
            with self.subTest(raw_restart=raw_restart):
                self._expect_rejected_valid(
                    f"raw restart pseudo-result {raw_restart}",
                    result=raw_restart,
                    errno=4,
                )

        self._expect_rejected_valid(
            "unknown success source",
            result=6,
            errno=None,
            operation=self._dup_operation(99, 6),
        )

    def test_malformed_tables_and_invalid_tids(self):
        for label, table, result, errno in (
            ("malformed table success list", [], 6, None),
            ("malformed table success key", {True: (object(), False)}, 6, None),
            ("malformed table success entry", {5: [object(), False]}, 6, None),
            ("malformed table failure list", [], -1, 4),
            ("malformed table failure key", {True: (object(), False)}, -1, 4),
            ("malformed table failure entry", {5: [object(), False]}, -1, 4),
        ):
            with self.subTest(table=label):
                state = self._seed_state()
                refs = self._arm_pending(state)
                state._task(100)["fds"] = table
                self._expect_rejected(
                    label,
                    state,
                    lambda result=result, errno=errno: state.finish_dup2_syscall(
                        tid=100, result=result, errno=errno
                    ),
                    refs,
                )

        invalid_tids = (
            ("unknown", 999),
            ("bool", True),
            ("false bool", False),
            ("string", "100"),
            ("string subclass", StringSubclass("100")),
            ("None", None),
            ("zero", 0),
            ("negative", -1),
            ("float", 100.0),
            ("integer subclass", IntSubclass(100)),
        )
        for label, tid in invalid_tids:
            with self.subTest(tid=label, path="success"):
                self._expect_rejected_tid(
                    f"invalid success TID {label}", tid, 6, None
                )
            with self.subTest(tid=label, path="failure"):
                self._expect_rejected_tid(
                    f"invalid failure TID {label}", tid, -1, 4
                )
        self._expect_rejected_tid(
            "alias success TID", IntSubclass(1), 6, None, root_tid=1
        )
        self._expect_rejected_tid(
            "alias failure TID", IntSubclass(1), -1, 4, root_tid=1
        )

    def test_orphan_and_duplicate_completion(self):
        state = self._seed_state()
        refs = self._arm_pending(state, peer=False)
        refs.pop(100)
        del state._pending[100]
        self._expect_rejected(
            "orphan completion",
            state,
            lambda: state.finish_dup2_syscall(tid=100, result=6, errno=None),
            {},
        )

        state = self._seed_state()
        refs = self._arm_pending(state)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        first = state.finish_dup2_syscall(tid=100, result=-1, errno=4)
        self._assert_receipt("duplicate setup", first, refs[100], -1, 4)
        before = self._observation(state)
        self._expect_rejected(
            "duplicate completion",
            state,
            lambda: state.finish_dup2_syscall(tid=100, result=-1, errno=4),
            {101: refs[101]},
        )
        self.assertTrue(self._same_observation(before, self._observation(state)))

    def test_legacy_opaque_descriptions(self):
        state = self._seed_state()
        legacy = state._task(100)["fds"][3][0]
        target = state._task(100)["fds"][6][0]
        pending = self._dup_operation(3, 6)
        refs = self._arm_pending(state, operation=pending)
        self.assertIs(state.try_admit_fd_table_mutator(tid=100), True)
        receipt = state.finish_dup2_syscall(tid=100, result=6, errno=None)
        self._assert_receipt("legacy opaque success", receipt, pending, 6, None)
        self._assert_fd("legacy opaque root source", state, 100, 3, legacy, False)
        self._assert_fd("legacy opaque root target", state, 100, 6, legacy, False)
        self._assert_fd("legacy opaque shared target", state, 101, 6, legacy, False)
        self._assert_fd("legacy opaque copied target", state, 102, 6, target, True)
        self._assert_pending("legacy opaque success", state, {101: refs[101]})


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
