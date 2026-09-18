"""Semantic trace private syscall-lifecycle contracts."""

import copy
from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/task4-build-subject.py"
MODULE_NAME = "task4_build_subject_semantic_syscall_test"
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


PRODUCT_CATEGORIES = (
    "path",
    "fd",
    "mapping",
    "data",
    "lifecycle",
    "cwd_root",
    "exec",
    "mutation",
)
ALL_CATEGORIES = ("pure",) + PRODUCT_CATEGORIES
BASE_ARGS = (1, 2, 3, 4, 5, 6)
MAX_U64 = 2**64 - 1


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


class SemanticTraceSyscallTests(unittest.TestCase):
    def setUp(self):
        self.module = load_subject(self)

    @staticmethod
    def _operation(category, name="C_Test", args=BASE_ARGS):
        return (name, category, args)

    def _new_state(self, root_tid=100):
        state = self.module._SemanticTraceState(
            root_tid=root_tid,
            cwd="initial-cwd",
            root="initial-root",
            umask=0o022,
            fds={
                3: ("shared-description", False),
                4: ("closing-description", True),
            },
        )
        state.map_file(
            tid=root_tid,
            start=0x1000,
            length=0x1000,
            node="initial-node",
            offset=0,
            prot="r",
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
        snapshots = {
            tid: state.snapshot(tid=tid) for tid in (root_tid, 101, 102)
        }
        self.assertEqual(snapshots[root_tid]["tgid"], root_tid)
        self.assertEqual(snapshots[101]["tgid"], 101)
        self.assertEqual(snapshots[102]["tgid"], 102)
        self.assertEqual(
            snapshots[root_tid], snapshots[101] | {"tgid": root_tid}
        )
        return state

    def _begin_pair(
        self, state, root_category="pure", peer_category="pure", root_tid=100
    ):
        root_operation = self._operation(root_category, "C_Root")
        peer_operation = self._operation(peer_category, "C_Peer")
        self.assertIsNone(
            state.begin_syscall(tid=root_tid, operation=root_operation)
        )
        self.assertIsNone(state.begin_syscall(tid=101, operation=peer_operation))
        self.assertIs(state._pending[root_tid], root_operation)
        self.assertIs(state._pending[101], peer_operation)
        return root_operation, peer_operation

    @staticmethod
    def _pending_refs(state):
        return {tid: state._pending[tid] for tid in state._pending}

    def _assert_pending(self, label, state, refs):
        self.assertEqual(set(state._pending), set(refs), f"{label}: pending TID set")
        for tid, expected in refs.items():
            self.assertIs(
                state._pending[tid],
                expected,
                f"{label}: pending tuple identity for TID {tid}",
            )

    @staticmethod
    def _topology(state, root_tid=100):
        return {
            tid: copy.deepcopy(state.snapshot(tid=tid))
            for tid in (root_tid, 101, 102)
        }

    def _prove_shared_aliases(self, label, state, root_tid=100):
        copied_before = copy.deepcopy(state.snapshot(tid=102))
        state.dup2(tid=root_tid, source_fd=3, target_fd=8)
        self.assertEqual(
            state.snapshot(tid=101)["fds"].get(8),
            ("shared-description", False),
            f"{label}: FD alias was not shared after rejection",
        )
        self.assertNotIn(
            8,
            state.snapshot(tid=102)["fds"],
            f"{label}: copied FD table changed after rejection",
        )
        state.set_cwd(tid=root_tid, node=f"{label}-cwd")
        self.assertEqual(
            state.snapshot(tid=101)["cwd"],
            f"{label}-cwd",
            f"{label}: FS alias was not shared after rejection",
        )
        self.assertEqual(
            state.snapshot(tid=102)["cwd"],
            copied_before["cwd"],
            f"{label}: copied FS context changed after rejection",
        )
        state.map_file(
            tid=root_tid,
            start=0x2000,
            length=1,
            node=f"{label}-node",
            offset=0,
            prot=f"{label}-protection",
            shared=False,
        )
        self.assertIn(
            0x2000,
            state.snapshot(tid=101)["maps"],
            f"{label}: VM alias was not shared after rejection",
        )
        self.assertNotIn(
            0x2000,
            state.snapshot(tid=102)["maps"],
            f"{label}: copied VM table changed after rejection",
        )

    def _assert_rejected_state(
        self, label, state, invoke, refs=None, root_tid=100
    ):
        if refs is None:
            refs = self._pending_refs(state)
        before = self._topology(state, root_tid)
        try:
            invoke()
        except BaseException as exc:
            self.assertIs(
                type(exc),
                self.module.FormatError,
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}",
            )
        else:
            self.fail(f"{label}: accepted invalid lifecycle call")
        self.assertEqual(
            self._topology(state, root_tid),
            before,
            f"{label}: rejected lifecycle call changed topology",
        )
        self._assert_pending(label, state, refs)
        self._prove_shared_aliases(label, state, root_tid)

    def _assert_rejected(
        self,
        label,
        invoke,
        root_category="pure",
        peer_category="pure",
        root_tid=100,
    ):
        state = self._new_state(root_tid)
        self._begin_pair(state, root_category, peer_category, root_tid)
        self._assert_rejected_state(
            label, state, lambda: invoke(state), root_tid=root_tid
        )

    def _assert_rejected_begin_tid(self, label, tid, root_tid=100):
        state = self._new_state(root_tid)
        peer_operation = self._operation("pure", "C_Peer")
        self.assertIsNone(state.begin_syscall(tid=101, operation=peer_operation))
        self._assert_rejected_state(
            label,
            state,
            lambda: state.begin_syscall(
                tid=tid, operation=self._operation("pure")
            ),
            {101: peer_operation},
            root_tid,
        )

    def _assert_rejected_finish_tid(self, label, tid, root_tid=100):
        state = self._new_state(root_tid)
        root_operation, peer_operation = self._begin_pair(
            state, root_tid=root_tid
        )
        self._assert_rejected_state(
            label,
            state,
            lambda: state.finish_syscall(tid=tid, outcome="success"),
            {root_tid: root_operation, 101: peer_operation},
            root_tid,
        )

    def test_invalid_begin_tid(self):
        for label, tid in (
            ("unknown TID", 999),
            ("boolean false TID", False),
            ("string TID", "100"),
            ("StringSubclass TID", StringSubclass("100")),
            ("None TID", None),
            ("zero TID", 0),
            ("negative TID", -1),
        ):
            with self.subTest(tid=label):
                self._assert_rejected(
                    label,
                    lambda state, tid=tid: state.begin_syscall(
                        tid=tid, operation=self._operation("pure")
                    ),
                )

        for label, tid, root_tid in (
            ("boolean true TID", True, 1),
            ("float TID", 100.0, 100),
            ("IntSubclass TID", IntSubclass(100), 100),
        ):
            with self.subTest(tid=label):
                self._assert_rejected_begin_tid(label, tid, root_tid)

    def test_invalid_finish_tid(self):
        for label, tid, root_tid in (
            ("orphan unknown finish TID", 999, 100),
            ("orphan boolean false finish TID", False, 100),
            ("orphan string finish TID", "100", 100),
            (
                "orphan StringSubclass finish TID",
                StringSubclass("100"),
                100,
            ),
            ("orphan None finish TID", None, 100),
            ("orphan zero finish TID", 0, 100),
            ("orphan negative finish TID", -1, 100),
            ("orphan boolean true finish TID", True, 1),
            ("orphan float finish TID", 100.0, 100),
            ("orphan IntSubclass finish TID", IntSubclass(100), 100),
        ):
            with self.subTest(tid=label):
                self._assert_rejected_finish_tid(label, tid, root_tid)

    def test_operation_shape_name_category_and_arguments_validation(self):
        for label, bad_operation in (
            ("operation list", []),
            ("operation None", None),
            (
                "operation tuple subclass",
                TupleSubclass(self._operation("pure")),
            ),
            ("operation two-item tuple", ("C_Test", "pure")),
            (
                "operation four-item tuple",
                ("C_Test", "pure", BASE_ARGS, "extra"),
            ),
        ):
            with self.subTest(operation=label):
                self._assert_rejected(
                    label,
                    lambda state, bad_operation=bad_operation: state.begin_syscall(
                        tid=102, operation=bad_operation
                    ),
                )

        for label, bad_name in (
            ("empty name", ""),
            ("None name", None),
            ("bytes name", b"C_Test"),
            ("StringSubclass name", StringSubclass("C_Test")),
        ):
            with self.subTest(name=label):
                self._assert_rejected(
                    label,
                    lambda state, bad_name=bad_name: state.begin_syscall(
                        tid=102,
                        operation=self._operation("pure", name=bad_name),
                    ),
                )

        for label, bad_category in (
            ("unknown category", "unknown"),
            ("None category", None),
            ("bytes category", b"pure"),
            ("StringSubclass category", StringSubclass("pure")),
        ):
            with self.subTest(category=label):
                self._assert_rejected(
                    label,
                    lambda state, bad_category=bad_category: state.begin_syscall(
                        tid=102, operation=self._operation(bad_category)
                    ),
                )

        for label, bad_arguments in (
            ("arguments list", []),
            ("arguments None", None),
            ("arguments tuple subclass", TupleSubclass(BASE_ARGS)),
            ("five arguments", BASE_ARGS[:5]),
            ("seven arguments", BASE_ARGS + (7,)),
        ):
            with self.subTest(arguments=label):
                self._assert_rejected(
                    label,
                    lambda state, bad_arguments=bad_arguments: state.begin_syscall(
                        tid=102,
                        operation=self._operation("pure", args=bad_arguments),
                    ),
                )

        for label, bad_value in (
            ("boolean argument", True),
            ("float argument", 1.0),
            ("IntSubclass argument", IntSubclass(1)),
            ("string argument", "1"),
            ("None argument", None),
            ("negative argument", -1),
            ("u64 overflow argument", 2**64),
        ):
            for position in range(6):
                with self.subTest(argument=label, position=position):
                    args = list(BASE_ARGS)
                    args[position] = bad_value
                    self._assert_rejected(
                        f"{label} at position {position}",
                        lambda state, args=tuple(args): state.begin_syscall(
                            tid=102,
                            operation=self._operation("pure", args=args),
                        ),
                    )

    def test_u64_argument_boundaries(self):
        for boundary in (0, MAX_U64):
            for position in range(6):
                with self.subTest(boundary=boundary, position=position):
                    args = list(BASE_ARGS)
                    args[position] = boundary
                    state = self._new_state()
                    candidate = self._operation("pure", args=tuple(args))
                    self.assertIsNone(
                        state.begin_syscall(tid=100, operation=candidate)
                    )
                    self.assertIs(state._pending[100], candidate)
                    self.assertIsNone(
                        state.finish_syscall(tid=100, outcome="success")
                    )
                    self.assertNotIn(100, state._pending)

    def test_duplicate_begin_is_atomic(self):
        state = self._new_state()
        root_operation, peer_operation = self._begin_pair(state)
        self._assert_rejected_state(
            "duplicate begin",
            state,
            lambda: state.begin_syscall(
                tid=100,
                operation=self._operation("pure", name="C_Replacement"),
            ),
            {100: root_operation, 101: peer_operation},
        )

    def test_category_restart_preserves_pending_and_topology(self):
        for category in ALL_CATEGORIES:
            with self.subTest(category=category):
                state = self._new_state()
                root_operation, peer_operation = self._begin_pair(
                    state, category, category
                )
                before = self._topology(state)
                self.assertIsNone(
                    state.finish_syscall(tid=100, outcome="restart")
                )
                self.assertEqual(self._topology(state), before)
                refs = {100: root_operation, 101: peer_operation}
                self._assert_pending(f"{category}: restart", state, refs)
                self._prove_shared_aliases(f"{category}: restart", state)
                self._assert_pending(
                    f"{category}: restart after alias probe", state, refs
                )
                self.assertIsNone(
                    state.finish_syscall(tid=101, outcome="restart")
                )
                self._assert_pending(f"{category}: peer restart", state, refs)

    def test_pure_completion_clears_only_matching_pending(self):
        for outcome in ("success", "failure"):
            with self.subTest(outcome=outcome):
                state = self._new_state()
                _, peer_operation = self._begin_pair(state, "pure", "pure")
                before = self._topology(state)
                self.assertIsNone(
                    state.finish_syscall(tid=100, outcome=outcome)
                )
                self.assertNotIn(100, state._pending)
                self.assertIs(state._pending.get(101), peer_operation)
                self.assertEqual(self._topology(state), before)
                self._prove_shared_aliases(f"pure {outcome}", state)
                self._assert_pending(
                    f"pure {outcome}: after alias probe",
                    state,
                    {101: peer_operation},
                )
                self.assertIsNone(
                    state.finish_syscall(tid=101, outcome=outcome)
                )
                self.assertFalse(state._pending)

    def test_product_completion_is_refused(self):
        for category in PRODUCT_CATEGORIES:
            for outcome in ("success", "failure"):
                with self.subTest(category=category, outcome=outcome):
                    state = self._new_state()
                    root_operation, peer_operation = self._begin_pair(
                        state, category, category
                    )
                    self._assert_rejected_state(
                        f"{category} {outcome}",
                        state,
                        lambda outcome=outcome: state.finish_syscall(
                            tid=100, outcome=outcome
                        ),
                        {100: root_operation, 101: peer_operation},
                    )

    def test_invalid_orphan_and_duplicate_finish(self):
        for label, outcome in (
            ("unknown outcome", "unknown"),
            ("None outcome", None),
            ("StringSubclass outcome", StringSubclass("success")),
        ):
            with self.subTest(outcome=label):
                self._assert_rejected(
                    label,
                    lambda state, outcome=outcome: state.finish_syscall(
                        tid=100, outcome=outcome
                    ),
                )

        state = self._new_state()
        root_operation, peer_operation = self._begin_pair(state)
        self._assert_rejected_state(
            "orphan finish",
            state,
            lambda: state.finish_syscall(tid=102, outcome="success"),
            {100: root_operation, 101: peer_operation},
        )

        state = self._new_state()
        _, peer_operation = self._begin_pair(state)
        self.assertIsNone(state.finish_syscall(tid=100, outcome="success"))
        self._assert_rejected_state(
            "duplicate finish",
            state,
            lambda: state.finish_syscall(tid=100, outcome="success"),
            {101: peer_operation},
        )


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
