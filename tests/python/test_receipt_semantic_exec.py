"""Semantic trace private exec-event contracts."""

import copy
from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/task4-build-subject.py"
MODULE_NAME = "task4_build_subject_semantic_exec_test"
MISSING = object()

sys.path.insert(0, str(REPO / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path


class DictSubclass(dict):
    pass


class TupleSubclass(tuple):
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


class SemanticTraceExecTests(unittest.TestCase):
    def setUp(self):
        self.module = load_subject(self)

    def _success_state(self):
        retained_description = object()
        closing_description = object()
        old_node = object()
        old_protection = object()
        state = self.module._SemanticTraceState(
            root_tid=100,
            cwd="exec-cwd",
            root="exec-root",
            umask=0o027,
            fds={3: (retained_description, False), 4: (closing_description, True)},
        )
        state.map_file(
            tid=100,
            start=0x1000,
            length=0x1000,
            node=old_node,
            offset=0x40,
            prot=old_protection,
            shared=False,
        )
        state.spawn(
            parent_tid=100,
            child_tid=101,
            share_files=True,
            share_fs=True,
            share_vm=True,
            thread_group=False,
        )
        state.spawn(
            parent_tid=100,
            child_tid=102,
            share_files=False,
            share_fs=False,
            share_vm=False,
            thread_group=False,
        )
        return state, {
            "retained_description": retained_description,
            "closing_description": closing_description,
            "old_node": old_node,
            "old_protection": old_protection,
        }

    def _exec_with_replacement(self):
        state, tokens = self._success_state()
        result = state.exec_event(
            tid=100,
            mappings={0x2000: (1, object(), 0, object(), False)},
        )
        return state, tokens, result

    def _exec_with_original_replacement(self):
        state, tokens = self._success_state()
        replacement = {
            0x2000: (0x1000, object(), 0x200, object(), True),
            0x3000: (0x800, object(), 0, object(), False),
        }
        expected_replacement = dict(replacement)
        self.assertIsNone(state.exec_event(tid=100, mappings=replacement))
        replacement[0x2000] = (1, object(), 0, object(), False)
        replacement[0x4000] = (1, object(), 0, object(), False)
        self.assertEqual(state.snapshot(tid=100)["maps"], expected_replacement)
        return state, tokens

    def _state_after_original_fd_and_vm_mutations(self):
        state, tokens = self._exec_with_original_replacement()
        state.dup2(tid=100, source_fd=3, target_fd=8)
        self.assertEqual(
            state.snapshot(tid=100)["fds"],
            {
                3: (tokens["retained_description"], False),
                8: (tokens["retained_description"], False),
            },
        )
        self.assertEqual(
            state.snapshot(tid=101)["fds"],
            {
                3: (tokens["retained_description"], False),
                4: (tokens["closing_description"], True),
            },
        )
        state.close(tid=101, fd=4)
        self.assertEqual(
            state.snapshot(tid=101)["fds"],
            {3: (tokens["retained_description"], False)},
        )
        self.assertEqual(
            state.snapshot(tid=100)["fds"],
            {
                3: (tokens["retained_description"], False),
                8: (tokens["retained_description"], False),
            },
        )

        state.map_file(
            tid=100,
            start=0x4000,
            length=0x1000,
            node=object(),
            offset=0,
            prot=object(),
            shared=False,
        )
        self.assertIn(0x4000, state.snapshot(tid=100)["maps"])
        self.assertNotIn(0x4000, state.snapshot(tid=101)["maps"])
        state.map_file(
            tid=101,
            start=0x5000,
            length=0x1000,
            node=object(),
            offset=0,
            prot=object(),
            shared=True,
        )
        self.assertIn(0x5000, state.snapshot(tid=101)["maps"])
        self.assertNotIn(0x5000, state.snapshot(tid=100)["maps"])
        self.assertNotIn(0x4000, state.snapshot(tid=102)["maps"])
        self.assertNotIn(0x5000, state.snapshot(tid=102)["maps"])
        return state

    def _fresh_rejection(self, root_tid=100):
        state = self.module._SemanticTraceState(
            root_tid=root_tid,
            cwd="reject-cwd",
            root="reject-root",
            umask=0o022,
            fds={3: ("retained", False), 4: ("closing", True)},
        )
        state.map_file(
            tid=root_tid,
            start=0x1000,
            length=0x1000,
            node="old-node",
            offset=0x10,
            prot="old-protection",
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
    def _literal_snapshot(tgid):
        return {
            "tgid": tgid,
            "fds": {3: ("retained", False), 4: ("closing", True)},
            "cwd": "reject-cwd",
            "root": "reject-root",
            "umask": 0o022,
            "maps": {
                0x1000: (0x1000, "old-node", 0x10, "old-protection", False)
            },
        }

    def _expected_initial(self, root_tid, tids):
        expected = {
            root_tid: self._literal_snapshot(root_tid),
            101: self._literal_snapshot(101),
            102: self._literal_snapshot(102),
        }
        if 103 in tids:
            expected[103] = self._literal_snapshot(root_tid)
        return {tid: expected[tid] for tid in tids}

    @staticmethod
    def _fd_fingerprint(table):
        if isinstance(table, dict):
            return (
                type(table),
                tuple(
                    (type(key), key, type(value), value)
                    for key, value in table.items()
                ),
            )
        return (type(table), repr(table))

    def _assert_aliases(self, label, state, root_tid, valid_fd):
        copied_before = copy.deepcopy(state.snapshot(tid=102))
        state.set_cwd(tid=root_tid, node=f"{label}-cwd")
        state.set_umask(tid=root_tid, value=0o071)
        state.map_file(
            tid=root_tid,
            start=0x2000,
            length=1,
            node=f"{label}-node",
            offset=0,
            prot=f"{label}-protection",
            shared=False,
        )
        shared_after = state.snapshot(tid=101)
        copied_after = state.snapshot(tid=102)
        self.assertEqual(shared_after["cwd"], f"{label}-cwd")
        self.assertEqual(shared_after["umask"], 0o071)
        self.assertEqual(
            shared_after["maps"].get(0x2000),
            (1, f"{label}-node", 0, f"{label}-protection", False),
        )
        self.assertEqual(copied_after["cwd"], copied_before["cwd"])
        self.assertEqual(copied_after["umask"], copied_before["umask"])
        self.assertNotIn(0x2000, copied_after["maps"])
        if valid_fd:
            state.dup2(tid=root_tid, source_fd=3, target_fd=8)
            self.assertEqual(state.snapshot(tid=101)["fds"].get(8), ("retained", False))
            self.assertNotIn(8, state.snapshot(tid=102)["fds"])

    def _assert_format(
        self,
        label,
        operation,
        *,
        root_tid=100,
        tids=(100, 101, 102),
        inject_fd=None,
        add_sibling=False,
    ):
        state = self._fresh_rejection(root_tid=root_tid)
        if add_sibling:
            state.spawn(
                parent_tid=root_tid,
                child_tid=103,
                share_files=False,
                share_fs=False,
                share_vm=False,
                thread_group=True,
            )
        before = {tid: copy.deepcopy(state.snapshot(tid=tid)) for tid in tids}
        self.assertEqual(before, self._expected_initial(root_tid, tids))
        if inject_fd is not None:
            inject_fd(state)
            corrupt_before = self._fd_fingerprint(state._task(root_tid)["fds"])
            try:
                injected_target = state.snapshot(tid=root_tid)
            except BaseException:
                injected_target_non_fd = None
            else:
                injected_target.pop("fds")
                injected_target_non_fd = copy.deepcopy(injected_target)
        try:
            operation(state)
        except BaseException as exc:
            self.assertIs(
                type(exc),
                self.module.FormatError,
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}",
            )
        else:
            self.fail(f"{label}: accepted invalid operation")
        if inject_fd is not None:
            self.assertEqual(
                self._fd_fingerprint(state._task(root_tid)["fds"]), corrupt_before
            )
            if injected_target_non_fd is not None:
                target_after = state.snapshot(tid=root_tid)
                target_after.pop("fds")
                self.assertEqual(copy.deepcopy(target_after), injected_target_non_fd)
            normal_tids = tuple(tid for tid in tids if tid != root_tid)
        else:
            normal_tids = tids
        for tid in normal_tids:
            self.assertEqual(
                copy.deepcopy(state.snapshot(tid=tid)),
                before[tid],
                f"{label}: rejected operation mutated TID {tid}",
            )
        self._assert_aliases(label, state, root_tid, inject_fd is None)

    def test_exec_replaces_private_state_and_preserves_identity(self):
        state, tokens = self._success_state()
        replacement_node = object()
        replacement_protection = object()
        replacement = {
            0x2000: (
                0x1000,
                replacement_node,
                0x200,
                replacement_protection,
                True,
            ),
            0x3000: (0x800, object(), 0, object(), False),
        }
        expected_replacement = dict(replacement)

        self.assertIsNone(state.exec_event(tid=100, mappings=replacement))
        root = state.snapshot(tid=100)
        peer = state.snapshot(tid=101)
        copied_fs_peer = state.snapshot(tid=102)
        self.assertEqual(root["tgid"], 100)
        self.assertEqual(root["fds"], {3: (tokens["retained_description"], False)})
        self.assertIs(root["fds"][3][0], tokens["retained_description"])
        self.assertEqual(
            peer["fds"],
            {
                3: (tokens["retained_description"], False),
                4: (tokens["closing_description"], True),
            },
        )
        self.assertIs(peer["fds"][3][0], tokens["retained_description"])
        self.assertIs(peer["fds"][4][0], tokens["closing_description"])
        self.assertEqual(
            peer["maps"],
            {
                0x1000: (
                    0x1000,
                    tokens["old_node"],
                    0x40,
                    tokens["old_protection"],
                    False,
                )
            },
        )
        self.assertIs(peer["maps"][0x1000][1], tokens["old_node"])
        self.assertIs(peer["maps"][0x1000][3], tokens["old_protection"])
        self.assertEqual(root["maps"], expected_replacement)
        self.assertNotIn(0x1000, root["maps"])
        self.assertIs(root["maps"][0x2000][1], replacement_node)
        self.assertIs(root["maps"][0x2000][3], replacement_protection)
        self.assertEqual(
            (root["cwd"], root["root"], root["umask"]),
            ("exec-cwd", "exec-root", 0o027),
        )
        self.assertEqual(
            (
                copied_fs_peer["cwd"],
                copied_fs_peer["root"],
                copied_fs_peer["umask"],
            ),
            ("exec-cwd", "exec-root", 0o027),
        )

        replacement[0x2000] = (1, object(), 0, object(), False)
        replacement[0x4000] = (1, object(), 0, object(), False)
        self.assertEqual(state.snapshot(tid=100)["maps"], expected_replacement)

    def test_post_exec_fd_and_vm_mutations_follow_new_ownership(self):
        self._state_after_original_fd_and_vm_mutations()

    def test_post_exec_fs_mutations_follow_existing_shared_ownership(self):
        state = self._state_after_original_fd_and_vm_mutations()
        state.set_cwd(tid=100, node="exec-cwd-after")
        state.set_umask(tid=100, value=0o077)
        self.assertEqual(
            (state.snapshot(tid=101)["cwd"], state.snapshot(tid=101)["umask"]),
            ("exec-cwd-after", 0o077),
        )
        self.assertEqual(
            (state.snapshot(tid=102)["cwd"], state.snapshot(tid=102)["umask"]),
            ("exec-cwd", 0o027),
        )
        state.set_cwd(tid=101, node="peer-cwd-after")
        state.set_umask(tid=101, value=0o037)
        self.assertEqual(
            (state.snapshot(tid=100)["cwd"], state.snapshot(tid=100)["umask"]),
            ("peer-cwd-after", 0o037),
        )
        self.assertEqual(
            (state.snapshot(tid=102)["cwd"], state.snapshot(tid=102)["umask"]),
            ("exec-cwd", 0o027),
        )
        self.assertEqual(state.snapshot(tid=100)["root"], "exec-root")
        self.assertEqual(state.snapshot(tid=101)["root"], "exec-root")

    def test_post_exec_closes_do_not_cross_fd_tables(self):
        state, tokens, result = self._exec_with_replacement()
        self.assertIsNone(result)
        state.close(tid=100, fd=3)
        self.assertEqual(state.snapshot(tid=100)["fds"], {})
        self.assertEqual(
            state.snapshot(tid=101)["fds"],
            {
                3: (tokens["retained_description"], False),
                4: (tokens["closing_description"], True),
            },
        )

        state, tokens, result = self._exec_with_replacement()
        self.assertIsNone(result)
        state.close(tid=101, fd=4)
        self.assertEqual(
            state.snapshot(tid=101)["fds"],
            {3: (tokens["retained_description"], False)},
        )
        self.assertEqual(
            state.snapshot(tid=100)["fds"],
            {3: (tokens["retained_description"], False)},
        )

    def test_mapping_boundaries_are_accepted(self):
        adjacent_node = object()
        adjacent_protection = object()
        cases = (
            ("empty map", {}),
            (
                "adjacent ranges",
                {
                    0x2000: (1, adjacent_node, 0, adjacent_protection, False),
                    0x2001: (1, object(), 0, object(), True),
                },
            ),
            (
                "u64 final byte",
                {2**64 - 4: (4, object(), 0, object(), False)},
            ),
        )
        for label, mappings in cases:
            with self.subTest(mapping=label):
                state, _ = self._success_state()
                self.assertIsNone(state.exec_event(tid=100, mappings=mappings))
                self.assertEqual(state.snapshot(tid=100)["maps"], mappings)

    def test_task_and_thread_group_rejections_are_atomic(self):
        cases = (
            ("unknown TID", lambda state: state.exec_event(tid=999, mappings={}), {}),
            ("float TID", lambda state: state.exec_event(tid=100.0, mappings={}), {}),
            (
                "boolean TID does not alias root 1",
                lambda state: state.exec_event(tid=True, mappings={}),
                {"root_tid": 1, "tids": (1, 101, 102)},
            ),
            (
                "nonleader exec",
                lambda state: state.exec_event(tid=103, mappings={}),
                {"tids": (100, 101, 102, 103), "add_sibling": True},
            ),
            (
                "leader with retained sibling",
                lambda state: state.exec_event(tid=100, mappings={}),
                {"tids": (100, 101, 102, 103), "add_sibling": True},
            ),
        )
        for label, operation, options in cases:
            with self.subTest(operation=label):
                self._assert_format(label, operation, **options)

    def test_fd_table_rejections_are_atomic(self):
        def inject_table(table):
            def inject(state):
                state._task(100)["fds"] = table

            return inject

        def inject_fd_value(key, value):
            def inject(state):
                table = dict(state._task(100)["fds"])
                table[key] = value
                state._task(100)["fds"] = table

            return inject

        cases = [
            ("FD table list", inject_table([])),
            (
                "FD table dict subclass",
                inject_table(
                    DictSubclass({3: ("retained", False), 4: ("closing", True)})
                ),
            ),
        ]
        cases.extend(
            (label, inject_fd_value(key, ("bad", False)))
            for label, key in (
                ("negative FD key", -1),
                ("boolean FD key", True),
                ("non-integer FD key", "fd"),
                ("float FD key", 5.0),
            )
        )
        cases.extend(
            (label, inject_fd_value(5, value))
            for label, value in (
                ("FD value list", ["bad", False]),
                ("FD value tuple subclass", TupleSubclass(("bad", False))),
                ("FD value one-item tuple", ("bad",)),
                ("FD value three-item tuple", ("bad", False, "extra")),
                ("FD CLOEXEC integer", ("bad", 1)),
                ("FD CLOEXEC None", ("bad", None)),
            )
        )
        for label, inject_fd in cases:
            with self.subTest(operation=label):
                self._assert_format(
                    label,
                    lambda state: state.exec_event(tid=100, mappings={}),
                    inject_fd=inject_fd,
                )

    def test_mapping_rejections_are_atomic(self):
        opaque_node = object()
        opaque_protection = object()

        def mapping(length=1, offset=0, shared=False):
            return (length, opaque_node, offset, opaque_protection, shared)

        cases = [
            (
                "mappings dict subclass",
                lambda state: state.exec_event(tid=100, mappings=DictSubclass({})),
            )
        ]
        cases.extend(
            (label, lambda state, payload=payload: state.exec_event(tid=100, mappings=payload))
            for label, payload in (
                ("mappings list", []),
                (
                    "mapping value list",
                    {0x2000: [1, opaque_node, 0, opaque_protection, False]},
                ),
                (
                    "mapping value tuple subclass",
                    {0x2000: TupleSubclass(mapping())},
                ),
                (
                    "mapping value four-item tuple",
                    {0x2000: (1, opaque_node, 0, opaque_protection)},
                ),
                (
                    "mapping value six-item tuple",
                    {0x2000: (1, opaque_node, 0, opaque_protection, False, "extra")},
                ),
            )
        )
        cases.extend(
            (
                label,
                lambda state, start=start: state.exec_event(
                    tid=100, mappings={start: mapping()}
                ),
            )
            for label, start in (
                ("boolean mapping start", True),
                ("non-integer mapping start", "start"),
                ("float mapping start", 1.0),
                ("negative mapping start", -1),
            )
        )
        cases.extend(
            (
                label,
                lambda state, length=length: state.exec_event(
                    tid=100, mappings={0x2000: mapping(length=length)}
                ),
            )
            for label, length in (
                ("boolean mapping length", True),
                ("non-integer mapping length", "length"),
                ("float mapping length", 1.0),
                ("zero mapping length", 0),
                ("negative mapping length", -1),
            )
        )
        cases.extend(
            (
                label,
                lambda state, offset=offset: state.exec_event(
                    tid=100, mappings={0x2000: mapping(offset=offset)}
                ),
            )
            for label, offset in (
                ("boolean mapping offset", True),
                ("non-integer mapping offset", "offset"),
                ("float mapping offset", 1.0),
                ("negative mapping offset", -1),
            )
        )
        cases.extend(
            (
                label,
                lambda state, shared=shared: state.exec_event(
                    tid=100, mappings={0x2000: mapping(shared=shared)}
                ),
            )
            for label, shared in (
                ("integer shared flag", 1),
                ("None shared flag", None),
            )
        )
        cases.extend(
            (
                (
                    "mapping start at u64 limit",
                    lambda state: state.exec_event(
                        tid=100, mappings={2**64: mapping()}
                    ),
                ),
                (
                    "mapping range overflows u64",
                    lambda state: state.exec_event(
                        tid=100, mappings={2**64 - 1: mapping(length=2)}
                    ),
                ),
                (
                    "overlapping mapping ranges",
                    lambda state: state.exec_event(
                        tid=100,
                        mappings={
                            0x2000: mapping(length=0x10),
                            0x200F: mapping(),
                        },
                    ),
                ),
            )
        )
        for label, operation in cases:
            with self.subTest(operation=label):
                self._assert_format(label, operation)


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
