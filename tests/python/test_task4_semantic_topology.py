"""Semantic trace private-state topology contracts."""

import copy
import importlib.util
from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/task4-build-subject.py"
MODULE_NAME = "task4_build_subject_semantic_topology_test"
MISSING = object()

INITIAL_ROOT = {
    "tgid": 100,
    "fds": {
        3: ("source-description", False),
        4: ("tool-description", True),
    },
    "cwd": "repo-node",
    "root": "root-node",
    "umask": 0o022,
    "maps": {
        0x1000: (0x1000, "source-node", 0, "r", False),
    },
}
SHARED_STATE = {
    "tgid": 100,
    "fds": {
        3: ("source-description", False),
        8: ("source-description", False),
        10: ("source-description", False),
    },
    "cwd": "fs-node",
    "root": "root-node",
    "umask": 0o077,
    "maps": {
        0x1000: (0x1000, "source-node", 0, "r", False),
        0x3000: (0x1000, "thread-node", 0x1000, "rw", True),
        0x5000: (0x1000, "vm-node", 0, "r", False),
    },
}
FORK_STATE = {
    "tgid": 102,
    "fds": {
        3: ("source-description", False),
        9: ("source-description", False),
    },
    "cwd": "fork-node",
    "root": "root-node",
    "umask": 0o027,
    "maps": {
        0x1000: (0x1000, "source-node", 0, "r", False),
        0x2000: (0x1000, "adjacent-node", 0, "r", False),
        0x7000: (0x1000, "fork-node", 0, "r", False),
    },
}


class SemanticTraceTopologyTests(unittest.TestCase):
    def setUp(self):
        self._previous_module = sys.modules.get(MODULE_NAME, MISSING)
        self._previous_dont_write_bytecode = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        self.addCleanup(self._restore_import_state)

        spec = importlib.util.spec_from_file_location(MODULE_NAME, SCRIPT_PATH)
        if spec is None or spec.loader is None:
            self.fail("could not import task4 build-subject script")
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[MODULE_NAME] = self.module
        spec.loader.exec_module(self.module)

    def _restore_import_state(self):
        sys.dont_write_bytecode = self._previous_dont_write_bytecode
        if self._previous_module is MISSING:
            sys.modules.pop(MODULE_NAME, None)
        else:
            sys.modules[MODULE_NAME] = self._previous_module

    def _initial_state(self):
        state = self.module._SemanticTraceState(
            root_tid=100,
            cwd="repo-node",
            root="root-node",
            umask=0o022,
            fds={
                3: ("source-description", False),
                4: ("tool-description", True),
            },
        )
        state.map_file(
            tid=100,
            start=0x1000,
            length=0x1000,
            node="source-node",
            offset=0,
            prot="r",
            shared=False,
        )
        state.spawn(
            parent_tid=100,
            child_tid=101,
            share_files=True,
            share_fs=True,
            share_vm=True,
            thread_group=True,
        )
        state.spawn(
            parent_tid=100,
            child_tid=102,
            share_files=False,
            share_fs=False,
            share_vm=False,
            thread_group=False,
        )
        state.spawn(
            parent_tid=100,
            child_tid=103,
            share_files=True,
            share_fs=False,
            share_vm=False,
            thread_group=False,
        )
        state.spawn(
            parent_tid=100,
            child_tid=104,
            share_files=False,
            share_fs=True,
            share_vm=False,
            thread_group=False,
        )
        state.spawn(
            parent_tid=100,
            child_tid=105,
            share_files=False,
            share_fs=False,
            share_vm=True,
            thread_group=False,
        )
        return state

    @staticmethod
    def _apply_shared_mutations(state):
        state.dup2(tid=101, source_fd=3, target_fd=8)
        state.set_cwd(tid=101, node="thread-node")
        state.set_umask(tid=101, value=0o077)
        state.map_file(
            tid=101,
            start=0x3000,
            length=0x1000,
            node="thread-node",
            offset=0x1000,
            prot="rw",
            shared=True,
        )
        state.close(tid=101, fd=4)
        state.dup2(tid=103, source_fd=3, target_fd=10)
        state.set_cwd(tid=104, node="fs-node")
        state.map_file(
            tid=105,
            start=0x5000,
            length=0x1000,
            node="vm-node",
            offset=0,
            prot="r",
            shared=False,
        )

    @staticmethod
    def _apply_fork_mutations(state):
        state.dup2(tid=102, source_fd=4, target_fd=4)
        state.dup2(tid=102, source_fd=4, target_fd=11)
        state.close(tid=102, fd=11)
        state.dup2(tid=102, source_fd=3, target_fd=4)
        state.dup2(tid=102, source_fd=3, target_fd=9)
        state.close(tid=102, fd=4)
        state.set_cwd(tid=102, node="fork-node")
        state.set_umask(tid=102, value=0o027)
        state.map_file(
            tid=102,
            start=0x2000,
            length=0x1000,
            node="adjacent-node",
            offset=0,
            prot="r",
            shared=False,
        )
        state.map_file(
            tid=102,
            start=0x7000,
            length=0x1000,
            node="fork-node",
            offset=0,
            prot="r",
            shared=False,
        )

    def _assert_format(self, state, label, operation, absent_tids=()):
        before = {
            tid: copy.deepcopy(state.snapshot(tid=tid))
            for tid in (100, 101, 102, 103, 104, 105)
        }
        try:
            operation()
        except BaseException as exc:
            self.assertIs(
                type(exc),
                self.module.FormatError,
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}",
            )
        else:
            self.fail(f"{label}: accepted invalid operation")

        after = {
            tid: copy.deepcopy(state.snapshot(tid=tid))
            for tid in (100, 101, 102, 103, 104, 105)
        }
        self.assertEqual(after, before, f"{label}: rejected operation mutated semantic state")
        for tid in absent_tids:
            try:
                state.snapshot(tid=tid)
            except BaseException as exc:
                self.assertIs(
                    type(exc),
                    self.module.FormatError,
                    f"{label}: absent TID {tid} returned {type(exc).__name__}: {exc}",
                )
            else:
                self.fail(f"{label}: rejected operation created TID {tid}")

    def test_initial_copied_and_shared_state(self):
        state = self._initial_state()

        self.assertEqual(state.snapshot(tid=100), INITIAL_ROOT)
        self.assertEqual(state.snapshot(tid=101), dict(INITIAL_ROOT, tgid=100))
        self.assertEqual(state.snapshot(tid=102), dict(INITIAL_ROOT, tgid=102))

    def test_shared_mutations_follow_ownership_topology(self):
        state = self._initial_state()

        state.dup2(tid=101, source_fd=3, target_fd=8)
        state.set_cwd(tid=101, node="thread-node")
        state.set_umask(tid=101, value=0o077)
        state.map_file(
            tid=101,
            start=0x3000,
            length=0x1000,
            node="thread-node",
            offset=0x1000,
            prot="rw",
            shared=True,
        )
        state.close(tid=101, fd=4)
        state.dup2(tid=103, source_fd=3, target_fd=10)
        self.assertEqual(
            state.snapshot(tid=100)["fds"],
            {
                3: ("source-description", False),
                8: ("source-description", False),
                10: ("source-description", False),
            },
        )
        self.assertEqual(state.snapshot(tid=103)["fds"], state.snapshot(tid=100)["fds"])
        self.assertEqual(
            state.snapshot(tid=104)["fds"],
            {
                3: ("source-description", False),
                4: ("tool-description", True),
            },
        )
        self.assertEqual(state.snapshot(tid=105)["fds"], state.snapshot(tid=104)["fds"])

        state.set_cwd(tid=104, node="fs-node")
        self.assertEqual(state.snapshot(tid=100)["cwd"], "fs-node")
        self.assertEqual(state.snapshot(tid=101)["cwd"], "fs-node")
        self.assertEqual(state.snapshot(tid=104)["umask"], 0o077)
        self.assertEqual(state.snapshot(tid=103)["cwd"], "repo-node")
        self.assertEqual(state.snapshot(tid=105)["cwd"], "repo-node")
        self.assertEqual(state.snapshot(tid=103)["umask"], 0o022)
        self.assertEqual(state.snapshot(tid=105)["umask"], 0o022)

        state.map_file(
            tid=105,
            start=0x5000,
            length=0x1000,
            node="vm-node",
            offset=0,
            prot="r",
            shared=False,
        )
        self.assertIn(0x5000, state.snapshot(tid=100)["maps"])
        self.assertIn(0x5000, state.snapshot(tid=101)["maps"])
        self.assertNotIn(0x5000, state.snapshot(tid=103)["maps"])
        self.assertNotIn(0x5000, state.snapshot(tid=104)["maps"])
        self.assertEqual(state.snapshot(tid=100), SHARED_STATE)
        self.assertEqual(state.snapshot(tid=101), SHARED_STATE)

    def test_fork_and_dup2_semantics(self):
        state = self._initial_state()
        self._apply_shared_mutations(state)

        state.dup2(tid=102, source_fd=4, target_fd=4)
        self.assertEqual(state.snapshot(tid=102)["fds"][4], ("tool-description", True))
        state.dup2(tid=102, source_fd=4, target_fd=11)
        self.assertEqual(state.snapshot(tid=102)["fds"][11], ("tool-description", False))
        state.close(tid=102, fd=11)
        state.dup2(tid=102, source_fd=3, target_fd=4)
        self.assertEqual(state.snapshot(tid=102)["fds"][4], ("source-description", False))
        state.dup2(tid=102, source_fd=3, target_fd=9)
        state.close(tid=102, fd=4)
        state.set_cwd(tid=102, node="fork-node")
        state.set_umask(tid=102, value=0o027)
        state.map_file(
            tid=102,
            start=0x2000,
            length=0x1000,
            node="adjacent-node",
            offset=0,
            prot="r",
            shared=False,
        )
        state.map_file(
            tid=102,
            start=0x7000,
            length=0x1000,
            node="fork-node",
            offset=0,
            prot="r",
            shared=False,
        )
        self.assertEqual(state.snapshot(tid=102), FORK_STATE)
        self.assertEqual(state.snapshot(tid=100), SHARED_STATE)

    def test_invalid_operations_are_atomic(self):
        state = self._initial_state()
        self._apply_shared_mutations(state)
        self._apply_fork_mutations(state)

        invalid_operations = (
            (
                "unknown parent",
                lambda: state.spawn(
                    parent_tid=999,
                    child_tid=106,
                    share_files=False,
                    share_fs=False,
                    share_vm=False,
                    thread_group=False,
                ),
                (106,),
            ),
            ("unknown task", lambda: state.snapshot(tid=999), (999,)),
            (
                "duplicate child TID",
                lambda: state.spawn(
                    parent_tid=100,
                    child_tid=101,
                    share_files=False,
                    share_fs=False,
                    share_vm=False,
                    thread_group=False,
                ),
                (),
            ),
            (
                "unknown dup2 source FD",
                lambda: state.dup2(tid=102, source_fd=99, target_fd=10),
                (),
            ),
            (
                "closed dup2 source FD",
                lambda: state.dup2(tid=102, source_fd=4, target_fd=10),
                (),
            ),
            ("umask bool", lambda: state.set_umask(tid=100, value=True), ()),
            ("umask float", lambda: state.set_umask(tid=100, value=1.0), ()),
            ("umask below range", lambda: state.set_umask(tid=100, value=-1), ()),
            ("umask above range", lambda: state.set_umask(tid=100, value=0o1000), ()),
        )
        for label, operation, absent_tids in invalid_operations:
            with self.subTest(operation=label):
                self._assert_format(state, label, operation, absent_tids)

        for label, start, length, offset in (
            ("zero mapping length", 0x8000, 0, 0),
            ("negative mapping length", 0x8000, -1, 0),
            ("negative mapping start", -1, 1, 0),
            ("negative mapping offset", 0x8000, 1, -1),
            ("overlap starts inside", 0x1800, 1, 0),
            ("overlap starts before and ends inside", 0x0800, 0x1000, 0),
            ("overlap encloses", 0x0800, 0x2800, 0),
        ):
            with self.subTest(operation=label):
                self._assert_format(
                    state,
                    label,
                    lambda start=start, length=length, offset=offset: state.map_file(
                        tid=100,
                        start=start,
                        length=length,
                        node="bad-node",
                        offset=offset,
                        prot="r",
                        shared=False,
                    ),
                )


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
