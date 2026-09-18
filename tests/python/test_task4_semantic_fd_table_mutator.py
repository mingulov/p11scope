"""Semantic trace private FD-table-mutator admission contracts."""

from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/task4-build-subject.py"
MODULE_NAME = "task4_build_subject_semantic_fd_mutator_test"
MISSING = object()

sys.path.insert(0, str(REPO / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path
module = None
REJECTION_COUNT = 0

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
        loaded = load_path(SCRIPT_PATH, MODULE_NAME)
    except FileNotFoundError:
        test.fail("could not import task4 build-subject script")
    sys.modules[MODULE_NAME] = loaded
    return loaded


class IntSubclass(int):
    pass


class StringSubclass(str):
    pass


class DictSubclass(dict):
    pass


class ListSubclass(list):
    pass


class TupleSubclass(tuple):
    pass


INT_MAX = 2**31 - 1
MAX_U64 = 2**64 - 1
DUP_TAIL = (17, 2**63, MAX_U64 - 1, MAX_U64, 1)
DUP2_TAIL = (17, 2**63, MAX_U64 - 1, MAX_U64)


def dup2_operation(oldfd=5, newfd=6, tail=DUP2_TAIL):
    return ("dup2", "fd", (oldfd, newfd, *tail))


def dup_operation(oldfd=5, tail=DUP_TAIL):
    return ("dup", "fd", (oldfd, *tail))


def seed_state(root_tid=100, include_target=True, base_fds=None):
    if base_fds is None:
        base_fds = {
            0: (object(), True),
            2: (object(), False),
            4: (object(), True),
        }
    state = module._SemanticTraceState(
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
    if include_target:
        state.install_open_fd(
            tid=root_tid,
            fd=6,
            node=object(),
            kind="regular",
            access="read_write",
            cloexec=True,
        )
    state.apply_io_offset(tid=root_tid, fd=5, direction="write", count=7, position=None)
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


def observation(state, tids=(100, 101, 102)):
    result = {}
    for tid in tids:
        task = state._task(tid)
        fds = task["fds"]
        fd_rows = []
        if type(fds) is dict:
            for fd, entry in fds.items():
                if type(entry) is tuple and len(entry) == 2:
                    fd_rows.append((fd, entry, entry[0], entry[1]))
                else:
                    fd_rows.append((fd, entry, entry, None))
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


def same_value(left, right):
    if left is right:
        return True
    if type(left) is not type(right):
        return False
    if type(left) is tuple or type(left) is list:
        return len(left) == len(right) and all(
            same_value(a, b) for a, b in zip(left, right)
        )
    if type(left) is dict:
        return (
            list(left) == list(right)
            and all(same_value(left[key], right[key]) for key in left)
        )
    try:
        return bool(left == right)
    except BaseException:
        return False


def same_observation(before, after):
    if set(before) != set(after):
        return False
    for tid in before:
        left, right = before[tid], after[tid]
        if left[0] is not right[0] or left[1] != right[1]:
            return False
        if left[2] is not right[2] or left[4] is not right[4] or left[6] is not right[6]:
            return False
        if not same_value(left[5], right[5]):
            return False
        if type(left[2]) is dict:
            if len(left[3]) != len(right[3]):
                return False
            for old, new in zip(left[3], right[3]):
                if old[0] != new[0] or old[1] is not new[1]:
                    return False
                if old[2] is not new[2] or old[3] is not new[3]:
                    return False
        if type(left[6]) is dict:
            if len(left[7]) != len(right[7]):
                return False
            for (old_key, old_value), (new_key, new_value) in zip(left[7], right[7]):
                if old_key != new_key or old_value is not new_value:
                    return False
    return True


def freeze(value):
    value_type = type(value)
    type_tag = (value_type.__module__, value_type.__qualname__)
    if value_type in (type(None), bool, int, float, str, bytes):
        return ("scalar", type_tag, value)
    if value_type is module._OpenDescription:
        return (
            "description",
            type_tag,
            id(value),
            freeze(value.kind),
            freeze(value.access),
            freeze(value.offset),
            freeze(value.identity),
        )
    if isinstance(value, tuple):
        return (
            "tuple",
            type_tag,
            id(value),
            tuple(freeze(item) for item in tuple.__iter__(value)),
        )
    if isinstance(value, list):
        return (
            "list",
            type_tag,
            id(value),
            tuple(freeze(item) for item in list.__iter__(value)),
        )
    if isinstance(value, dict):
        return (
            "dict",
            type_tag,
            id(value),
            tuple(
                (freeze(key), freeze(item))
                for key, item in dict.items(value)
            ),
        )
    return ("object", type_tag, id(value))


def retained_refs(state):
    task_rows = []
    for tid, task in dict.items(state._tasks):
        fds = task["fds"]
        fd_rows = []
        if isinstance(fds, dict):
            for fd, entry in dict.items(fds):
                description = None
                if isinstance(entry, tuple):
                    values = tuple(tuple.__iter__(entry))
                    if values:
                        description = values[0]
                elif isinstance(entry, list):
                    values = tuple(list.__iter__(entry))
                    if values:
                        description = values[0]
                fd_rows.append((fd, entry, description))
        task_rows.append((tid, task, fds, task["fs"], task["maps"], tuple(fd_rows)))

    pending = state._pending
    pending_rows = tuple(dict.items(pending))
    owners = state._fd_table_mutators
    owner_rows = []
    if isinstance(owners, list):
        for owner in list.__iter__(owners):
            if isinstance(owner, tuple) and len(owner) == 3:
                owner_rows.append((owner, owner[0], owner[2]))
            else:
                owner_rows.append((owner, None, None))
    return (
        (state._tasks, tuple(task_rows)),
        (pending, pending_rows),
        (owners, tuple(owner_rows)),
    )


def assert_retained(label, before, after):
    if before[0][0] is not after[0][0] or before[1][0] is not after[1][0] or before[2][0] is not after[2][0]:
        raise SystemExit(f"{label}: state container identity changed")
    if len(before[0][1]) != len(after[0][1]) or len(before[1][1]) != len(after[1][1]) or len(before[2][1]) != len(after[2][1]):
        raise SystemExit(f"{label}: retained object count changed")
    for old_task, new_task in zip(before[0][1], after[0][1]):
        if old_task[0] != new_task[0] or old_task[1] is not new_task[1] or old_task[2] is not new_task[2] or old_task[3] is not new_task[3] or old_task[4] is not new_task[4]:
            raise SystemExit(f"{label}: task/fd/fs/maps identity changed")
        if len(old_task[5]) != len(new_task[5]):
            raise SystemExit(f"{label}: FD entry count changed")
        for old_fd, new_fd in zip(old_task[5], new_task[5]):
            if old_fd[0] != new_fd[0] or old_fd[1] is not new_fd[1] or old_fd[2] is not new_fd[2]:
                raise SystemExit(f"{label}: FD entry/description identity changed")
    for old_pending, new_pending in zip(before[1][1], after[1][1]):
        if old_pending[0] != new_pending[0] or old_pending[1] is not new_pending[1]:
            raise SystemExit(f"{label}: pending identity changed")
    for old_owner, new_owner in zip(before[2][1], after[2][1]):
        if old_owner[0] is not new_owner[0] or old_owner[1] is not new_owner[1] or old_owner[2] is not new_owner[2]:
            raise SystemExit(f"{label}: owner tuple/table/pending identity changed")


def snapshot(state):
    # Fingerprints are immutable; retained refs separately prove object identity.
    return (
        freeze(state._tasks),
        freeze(state._pending),
        freeze(state._fd_table_mutators),
        retained_refs(state),
    )


def assert_unchanged(label, before, after):
    if before[:3] != after[:3]:
        raise SystemExit(f"{label}: state/types/values/identities changed")
    assert_retained(label, before[3], after[3])


def expect_format(label, state, invoke):
    before = snapshot(state)
    try:
        invoke()
    except BaseException as exc:
        if type(exc) is not module.FormatError:
            raise SystemExit(
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}"
            ) from exc
    else:
        raise SystemExit(f"{label}: invalid operation was accepted")
    assert_unchanged(label, before, snapshot(state))
    global REJECTION_COUNT
    REJECTION_COUNT += 1


def assert_owner(label, state, table, tid, pending):
    owners = state._fd_table_mutators
    if type(owners) is not list or len(owners) != 1:
        raise SystemExit(f"{label}: owner collection is not one built-in entry")
    owner = owners[0]
    if type(owner) is not tuple or len(owner) != 3:
        raise SystemExit(f"{label}: owner entry is not a built-in triple")
    if owner[0] is not table or type(owner[1]) is not int or owner[1] != tid:
        raise SystemExit(f"{label}: owner table/TID identity is wrong")
    if owner[2] is not pending:
        raise SystemExit(f"{label}: owner pending identity is wrong")


def arm(state, operation, tid=100):
    state.begin_syscall(tid=tid, operation=operation)
    return operation


def assert_receipt(label, receipt, pending, result, errno):
    if type(receipt) is not tuple or len(receipt) != 3:
        raise SystemExit(f"{label}: malformed semantic receipt")
    if receipt[0] is not pending or type(receipt[1]) is not int or receipt[1] != result:
        raise SystemExit(f"{label}: receipt lost pending/result identity")
    if receipt[2] is not errno:
        raise SystemExit(f"{label}: receipt errno mismatch")


def exercise_bad_owner(label, configure):
    for handler_name in ("dup2", "dup"):
        state = seed_state()
        operation = dup2_operation() if handler_name == "dup2" else dup_operation()
        arm(state, operation)
        configure(state, operation)
        finish = (
            lambda: state.finish_dup2_syscall(tid=100, result=6, errno=None)
            if handler_name == "dup2"
            else state.finish_dup_syscall(tid=100, result=1, errno=None)
        )
        expect_format(f"{label} admission", state, lambda: state.try_admit_fd_table_mutator(tid=100))
        expect_format(f"{label} {handler_name} terminal", state, finish)


def one_owner(state, operation, table=None, tid=100, pending=None):
    if table is None:
        table = state._task(100)["fds"]
    if pending is None:
        pending = operation
    state._fd_table_mutators = [(table, tid, pending)]

def exercise_bad_unrelated_table(label, table_factory):
    for handler_name in ("dup2", "dup"):
        state = seed_state()
        malformed_table = table_factory()
        operation = dup2_operation() if handler_name == "dup2" else dup_operation()
        arm(state, operation)
        peer_operation = dup2_operation() if handler_name == "dup2" else dup_operation()
        arm(state, peer_operation, tid=102)
        one_owner(state, operation)
        state._task(102)["fds"] = malformed_table
        state._fd_table_mutators.append((malformed_table, 102, peer_operation))
        finish = (
            lambda: state.finish_dup2_syscall(tid=100, result=6, errno=None)
            if handler_name == "dup2"
            else state.finish_dup_syscall(tid=100, result=1, errno=None)
        )
        expect_format(
            f"{label} admission",
            state,
            lambda: state.try_admit_fd_table_mutator(tid=100),
        )
        expect_format(f"{label} {handler_name} terminal", state, finish)

def exercise_bad_unrelated_operation(label, pending_factory):
    for handler_name in ("dup2", "dup"):
        state = seed_state()
        bad_pending = pending_factory()
        operation = dup2_operation() if handler_name == "dup2" else dup_operation()
        arm(state, operation)
        peer_operation = dup2_operation() if handler_name == "dup2" else dup_operation()
        arm(state, peer_operation, tid=102)
        one_owner(state, operation)
        state._pending[102] = bad_pending
        state._fd_table_mutators.append((state._task(102)["fds"], 102, bad_pending))
        finish = (
            lambda: state.finish_dup2_syscall(tid=100, result=6, errno=None)
            if handler_name == "dup2"
            else state.finish_dup_syscall(tid=100, result=1, errno=None)
        )
        expect_format(
            f"{label} admission",
            state,
            lambda: state.try_admit_fd_table_mutator(tid=100),
        )
        expect_format(f"{label} {handler_name} terminal", state, finish)

def duplicate_table(state, operation):
    peer_operation = dup2_operation() if operation[0] == "dup2" else dup_operation()
    arm(state, peer_operation, tid=101)
    one_owner(state, operation, table=state._task(100)["fds"], tid=100)
    state._fd_table_mutators.append((state._task(101)["fds"], 101, peer_operation))
    state._fd_table_mutators[1] = (state._task(100)["fds"], 101, peer_operation)

def duplicate_tid(state, operation):
    one_owner(state, operation, tid=100)
    state._fd_table_mutators.append((state._task(102)["fds"], 100, operation))

def stale_pending(state, operation):
    equal_pending = tuple(list(operation))
    state._pending[100] = operation
    one_owner(state, operation, pending=equal_pending)
def missing_pending(state, operation):
    del state._pending[100]
    one_owner(state, operation)

def assert_alias_after_release(label, state, peer_pending):
    if state._fd_table_mutators:
        raise SystemExit(f"{label}: owner was not released")
    if 100 in state._pending:
        raise SystemExit(f"{label}: completed pending entry was not consumed")
    if state._pending.get(101) is not peer_pending:
        raise SystemExit(f"{label}: unrelated pending identity changed")
    if state.try_admit_fd_table_mutator(tid=101) is not True:
        raise SystemExit(f"{label}: released shared alias did not admit")
def later_index_discriminator(handler_name):
    state = seed_state()
    copied_operation = dup2_operation() if handler_name == "dup2" else dup_operation()
    root_operation = dup2_operation() if handler_name == "dup2" else dup_operation()
    copied_pending = arm(state, copied_operation, tid=102)
    root_pending = arm(state, root_operation)
    if state.try_admit_fd_table_mutator(tid=102) is not True:
        raise SystemExit(f"later-index {handler_name}: copied admission failed")
    if state.try_admit_fd_table_mutator(tid=100) is not True:
        raise SystemExit(f"later-index {handler_name}: root admission failed")
    unrelated = state._fd_table_mutators[0]
    root_table = state._task(100)["fds"]
    source = root_table[5][0]
    selected_owner = state._fd_table_mutators[1]
    original_dup2 = state.dup2
    callback_count = 0

    def discriminate(**kwargs):
        nonlocal callback_count
        callback_count += 1
        selected = state._fd_table_mutators[1]
        if (
            selected is not selected_owner
            or type(selected) is not tuple
            or len(selected) != 3
            or selected[0] is not root_table
            or selected[1] != 100
            or selected[2] is not root_pending
            or state._pending.get(100) is not root_pending
        ):
            raise SystemExit(f"later-index {handler_name}: captured owner changed before effect")
        original_dup2(**kwargs)
        target = 6 if handler_name == "dup2" else 1
        if (
            state._task(100)["fds"].get(target, (None, None))[0] is not source
            or state._task(100)["fds"][target][1] is not False
        ):
            raise SystemExit(f"later-index {handler_name}: effect was not committed")
        state._fd_table_mutators[1] = ("post-effect malformed owner",)

    state.dup2 = discriminate
    try:
        if handler_name == "dup2":
            receipt = state.finish_dup2_syscall(tid=100, result=6, errno=None)
            assert_receipt("later-index dup2", receipt, root_pending, 6, None)
        else:
            receipt = state.finish_dup_syscall(tid=100, result=1, errno=None)
            assert_receipt("later-index dup", receipt, root_pending, 1, None)
    finally:
        del state.dup2
    target = 6 if handler_name == "dup2" else 1
    if callback_count != 1:
        raise SystemExit(f"later-index {handler_name}: effect callback count was not one")
    if (
        state._task(100)["fds"].get(target, (None, None))[0] is not source
        or state._task(100)["fds"][target][1] is not False
    ):
        raise SystemExit(f"later-index {handler_name}: committed effect changed after return")
    if state.dup2.__self__ is not state or state.dup2.__func__ is not original_dup2.__func__:
        raise SystemExit(f"later-index {handler_name}: instance callback was not restored")
    if 100 in state._pending:
        raise SystemExit(f"later-index {handler_name}: TID100 pending remained")
    unrelated_owner = state._fd_table_mutators[0]
    if (
        len(state._fd_table_mutators) != 1
        or unrelated_owner is not unrelated
        or type(unrelated_owner) is not tuple
        or len(unrelated_owner) != 3
        or unrelated_owner[0] is not state._task(102)["fds"]
        or unrelated_owner[1] != 102
        or unrelated_owner[2] is not copied_pending
        or state._pending.get(102) is not copied_pending
    ):
        raise SystemExit(f"later-index {handler_name}: selected owner cleanup was not index-bound")

FAMILY_REJECTIONS = {
    "first_valid_admission": 0,
    "retry_contention_and_copied_table": 0,
    "invalid_admission_tids": 7,
    "malformed_owner_collection_and_entry": 20,
    "malformed_owner_tids": 32,
    "malformed_owner_table_types": 8,
    "malformed_unrelated_owner_tables": 32,
    "duplicate_and_stale_owner_identities": 24,
    "malformed_stored_dup_operations": 32,
    "malformed_stored_dup2_operations": 36,
    "malformed_unowned_pending_shape": 12,
    "pending_endpoint_validation": 18,
    "pending_raw_argument_validation": 36,
    "canonical_endpoint_boundaries": 0,
    "terminal_requires_owner": 2,
    "malformed_terminal_and_stale_topology": 6,
    "terminal_release_and_alias_admission": 0,
    "restart_then_terminal_release": 0,
    "distinct_owner_completion_isolation": 0,
    "later_index_dup2_cleanup": 0,
    "later_index_dup_cleanup": 0,
    "private_slice_exports_no_runner": 0,
}

class SemanticTraceFdTableMutatorTests(unittest.TestCase):
    def setUp(self):
        global module
        module = load_subject(self)
        self._rejection_start = REJECTION_COUNT

    def tearDown(self):
        family = self._testMethodName.removeprefix("test_")
        self.assertEqual(REJECTION_COUNT - self._rejection_start, FAMILY_REJECTIONS[family])

    def test_first_valid_admission(self):
        # The first valid call is intentionally earliest: current production fails only
        # because try_admit_fd_table_mutator has not been implemented yet.
        state = seed_state()
        pending = arm(state, dup2_operation())
        table = state._task(100)["fds"]
        if state.try_admit_fd_table_mutator(tid=100) is not True:
            raise SystemExit("first valid admission did not return True")
        assert_owner("first valid admission", state, table, 100, pending)
        

    def test_retry_contention_and_copied_table(self):
        # Same exact table/pending/TID is the only idempotent retry; equal copied tables
        # are independent, while a shared-table alias is denied without mutation.
        state = seed_state()
        root_pending = arm(state, dup2_operation())
        peer_pending = arm(state, dup_operation(), tid=101)
        root_table = state._task(100)["fds"]
        copied_table = state._task(102)["fds"]
        if root_table == copied_table and root_table is copied_table:
            raise SystemExit("copied FD table was not a distinct equal-content object")
        if root_table != copied_table:
            raise SystemExit("copied FD table did not preserve equal content")
        if state.try_admit_fd_table_mutator(tid=100) is not True:
            raise SystemExit("root admission failed")
        owners = state._fd_table_mutators
        root_owner = owners[0]
        before = snapshot(state)
        if state.try_admit_fd_table_mutator(tid=100) is not True:
            raise SystemExit("same-object retry was not idempotent")
        assert_unchanged("same-object idempotent retry", before, snapshot(state))
        if state._fd_table_mutators is not owners or owners[0] is not root_owner:
            raise SystemExit("idempotent retry replaced the owner identity")
        before = snapshot(state)
        if state.try_admit_fd_table_mutator(tid=101) is not False:
            raise SystemExit("same-table contender was not denied")
        assert_unchanged("same-table contention", before, snapshot(state))
        copied_pending = arm(state, dup2_operation(), tid=102)
        owner_count = len(owners)
        if state.try_admit_fd_table_mutator(tid=102) is not True:
            raise SystemExit("equal-content copied table did not admit independently")
        if state._fd_table_mutators is not owners or len(state._fd_table_mutators) != owner_count + 1:
            raise SystemExit("independent copied-table admission changed owner count")
        copied_owner = state._fd_table_mutators[-1]
        if (
            type(copied_owner) is not tuple
            or len(copied_owner) != 3
            or copied_owner[0] is not copied_table
            or type(copied_owner[1]) is not int
            or copied_owner[1] != 102
            or copied_owner[2] is not copied_pending
        ):
            raise SystemExit("copied-table admission lost exact owner identities")

    def test_invalid_admission_tids(self):
        for label, bad_tid in (
            ("admission unknown TID", 999),
            ("admission bool TID", True),
            ("admission integer-subclass TID", IntSubclass(100)),
            ("admission zero TID", 0),
            ("admission negative TID", -1),
            ("admission float TID", 100.0),
            ("admission string TID", "100"),
        ):
            state = seed_state()
            arm(state, dup2_operation())
            expect_format(
                label,
                state,
                lambda bad_tid=bad_tid: state.try_admit_fd_table_mutator(tid=bad_tid),
            )
        

    def test_malformed_owner_collection_and_entry(self):
        exercise_bad_owner("owner collection tuple", lambda state, operation: setattr(state, "_fd_table_mutators", ()))
        exercise_bad_owner("owner collection list subclass", lambda state, operation: setattr(state, "_fd_table_mutators", ListSubclass()))
        exercise_bad_owner(
            "owner entry non-tuple",
            lambda state, operation: setattr(state, "_fd_table_mutators", [None]),
        )
        exercise_bad_owner(
            "owner entry wrong length",
            lambda state, operation: setattr(state, "_fd_table_mutators", [(state._task(100)["fds"], 100)]),
        )
        exercise_bad_owner(
            "owner entry tuple subclass",
            lambda state, operation: setattr(
                state,
                "_fd_table_mutators",
                [TupleSubclass((state._task(100)["fds"], 100, operation))],
            ),
        )

    def test_malformed_owner_tids(self):
        for label, bad_tid in (
            ("owner bool TID", True),
            ("owner zero TID", 0),
            ("owner negative TID", -1),
            ("owner integer-subclass TID", IntSubclass(100)),
            ("owner float TID", 100.0),
            ("owner string TID", "100"),
            ("owner None TID", None),
            ("owner unknown TID", 999),
        ):
            exercise_bad_owner(
                label,
                lambda state, operation, bad_tid=bad_tid: one_owner(
                    state, operation, tid=bad_tid
                ),
            )

    def test_malformed_owner_table_types(self):
        exercise_bad_owner(
            "owner non-dict table",
            lambda state, operation: (
                state._task(100).__setitem__("fds", []),
                one_owner(state, operation, table=state._task(100)["fds"]),
            ),
        )
        exercise_bad_owner(
            "owner dict-subclass table",
            lambda state, operation: (
                state._task(100).__setitem__("fds", DictSubclass({5: (object(), False)})),
                one_owner(state, operation, table=state._task(100)["fds"]),
            ),
        )

    def test_malformed_unrelated_owner_tables(self):
        for label, table_factory in (
            ("owner boolean FD key", lambda: {5: (object(), False), True: (object(), False)}),
            ("owner integer-subclass FD key", lambda: {5: (object(), False), IntSubclass(1): (object(), False)}),
            ("owner negative FD key", lambda: {5: (object(), False), -1: (object(), False)}),
            ("owner list FD entry", lambda: {5: (object(), False), 8: [object(), False]}),
            ("owner short FD entry", lambda: {5: (object(), False), 8: (object(),)}),
            ("owner long FD entry", lambda: {5: (object(), False), 8: (object(), False, object())}),
            ("owner boolean CLOEXEC", lambda: {5: (object(), False), 8: (object(), 1)}),
            ("owner tuple-subclass FD entry", lambda: {5: (object(), False), 8: TupleSubclass((object(), False))}),
        ):
            exercise_bad_unrelated_table(label, table_factory)

    def test_duplicate_and_stale_owner_identities(self):
        exercise_bad_owner("duplicate owner table identity", duplicate_table)

        exercise_bad_owner("duplicate owner TID value", duplicate_tid)
        exercise_bad_owner(
            "stale current table identity",
            lambda state, operation: one_owner(
                state, operation, table=dict(state._task(100)["fds"])
            ),
        )
        exercise_bad_owner(
            "unknown owner task",
            lambda state, operation: one_owner(
                state, operation, table=state._task(100)["fds"], tid=999
            ),
        )
        
        exercise_bad_owner("stale equal pending identity", stale_pending)

        exercise_bad_owner("missing pending identity", missing_pending)


    def test_malformed_stored_dup_operations(self):
        # Stored owner operations are independently closed-grammar checked before
        # either terminal handler can inspect its result.
        for label, pending_factory in (
            ("stored operation list", lambda: ["dup", "fd", (5, *DUP_TAIL)]),
            ("stored operation two items", lambda: ("dup", "fd")),
            ("stored operation name", lambda: ("fcntl", "fd", (5, *DUP_TAIL))),
            ("stored operation category", lambda: ("dup", "path", (5, *DUP_TAIL))),
            ("stored operation arguments list", lambda: ("dup", "fd", list((5, *DUP_TAIL)))),
            ("stored operation five args", lambda: ("dup", "fd", (5, *DUP_TAIL)[:5])),
            ("stored operation raw bool", lambda: ("dup", "fd", (5, True, *DUP_TAIL[1:]))),
            ("stored operation oldfd bool", lambda: ("dup", "fd", (True, *DUP_TAIL))),
        ):
            exercise_bad_unrelated_operation(label, pending_factory)
        

    def test_malformed_stored_dup2_operations(self):
        for label, pending_factory in (
            ("stored dup2 operation list", lambda: ["dup2", "fd", (5, 6, *DUP2_TAIL)]),
            ("stored dup2 operation two items", lambda: ("dup2", "fd")),
            ("stored dup2 operation name", lambda: ("fcntl", "fd", (5, 6, *DUP2_TAIL))),
            ("stored dup2 operation category", lambda: ("dup2", "path", (5, 6, *DUP2_TAIL))),
            ("stored dup2 operation arguments list", lambda: ("dup2", "fd", list((5, 6, *DUP2_TAIL)))),
            ("stored dup2 operation five args", lambda: ("dup2", "fd", (5, 6, *DUP2_TAIL)[:5])),
            ("stored dup2 operation raw bool", lambda: ("dup2", "fd", (5, 6, True, *DUP2_TAIL[1:]))),
            ("stored dup2 operation oldfd bool", lambda: ("dup2", "fd", (True, 6, *DUP2_TAIL))),
            ("stored dup2 operation newfd bool", lambda: ("dup2", "fd", (5, True, *DUP2_TAIL))),
        ):
            exercise_bad_unrelated_operation(label, pending_factory)
        

    def test_malformed_unowned_pending_shape(self):
        # Admission checks the pending object itself, even with no owners yet.  Only
        # exact dup/dup2, fd, six-u64 tuples with canonical endpoint FDs are accepted.
        for label, bad_pending in (
            ("pending outer list", ["dup", "fd", (5, *DUP_TAIL)]),
            ("pending outer tuple subclass", TupleSubclass(("dup", "fd", (5, *DUP_TAIL)))),
            ("pending two items", ("dup", "fd")),
            ("pending four items", ("dup", "fd", (5, *DUP_TAIL), "extra")),
            ("pending wrong name", ("fcntl", "fd", (5, *DUP_TAIL))),
            ("pending name subclass", (StringSubclass("dup"), "fd", (5, *DUP_TAIL))),
            ("pending wrong category", ("dup", "path", (5, *DUP_TAIL))),
            ("pending category subclass", ("dup", StringSubclass("fd"), (5, *DUP_TAIL))),
            ("pending arguments list", ("dup", "fd", list((5, *DUP_TAIL)))),
            ("pending arguments tuple subclass", ("dup", "fd", TupleSubclass((5, *DUP_TAIL)))),
            ("pending five args", ("dup", "fd", (5, *DUP_TAIL)[:5])),
            ("pending seven args", ("dup", "fd", (5, *DUP_TAIL) + (7,))),
        ):
            state = seed_state()
            state._pending[100] = bad_pending
            expect_format(label, state, lambda: state.try_admit_fd_table_mutator(tid=100))

    def test_pending_endpoint_validation(self):
        for position, label in ((0, "dup oldfd"), (1, "dup2 newfd")):
            for suffix, bad in (
                ("bool", True),
                ("integer subclass", IntSubclass(5)),
                ("negative", -1),
                ("overflow", INT_MAX + 1),
                ("float", 5.0),
                ("None", None),
            ):
                args = list((5, 6, *DUP2_TAIL)) if position == 1 else list((5, *DUP_TAIL))
                args[position] = bad
                pending = ("dup2", "fd", tuple(args)) if position == 1 else ("dup", "fd", tuple(args))
                state = seed_state()
                state._pending[100] = pending
                expect_format(f"{label} {suffix}", state, lambda: state.try_admit_fd_table_mutator(tid=100))
        
        for suffix, bad in (
            ("bool", True),
            ("integer subclass", IntSubclass(5)),
            ("negative", -1),
            ("overflow", INT_MAX + 1),
            ("float", 5.0),
            ("None", None),
        ):
            args = list((5, 6, *DUP2_TAIL))
            args[0] = bad
            pending = ("dup2", "fd", tuple(args))
            state = seed_state()
            state._pending[100] = pending
            expect_format(f"dup2 oldfd {suffix}", state, lambda: state.try_admit_fd_table_mutator(tid=100))

    def test_pending_raw_argument_validation(self):
        for position in range(2, 6):
            for suffix, bad in (
                ("bool", True),
                ("integer subclass", IntSubclass(1)),
                ("negative", -1),
                ("overflow", 2**64),
            ):
                args = list((5, 6, *DUP2_TAIL))
                args[position] = bad
                pending = ("dup2", "fd", tuple(args))
                state = seed_state()
                state._pending[100] = pending
                expect_format(f"dup2 raw slot {position} {suffix}", state, lambda: state.try_admit_fd_table_mutator(tid=100))
        
        for position in range(1, 6):
            for suffix, bad in (
                ("bool", True),
                ("integer subclass", IntSubclass(1)),
                ("negative", -1),
                ("overflow", 2**64),
            ):
                args = list((5, *DUP_TAIL))
                args[position] = bad
                pending = ("dup", "fd", tuple(args))
                state = seed_state()
                state._pending[100] = pending
                expect_format(f"dup raw slot {position} {suffix}", state, lambda: state.try_admit_fd_table_mutator(tid=100))

    def test_canonical_endpoint_boundaries(self):
        for label, pending in (
            ("dup oldfd zero", dup_operation(0)),
            ("dup oldfd INT_MAX", dup_operation(INT_MAX)),
            ("dup2 oldfd zero", dup2_operation(0, INT_MAX)),
            ("dup2 newfd zero", dup2_operation(INT_MAX, 0)),
        ):
            state = seed_state()
            arm(state, pending)
            if state.try_admit_fd_table_mutator(tid=100) is not True:
                raise SystemExit(f"{label}: canonical endpoint admission failed")
        

    def test_terminal_requires_owner(self):
        # Terminal handlers require the matching owner; these are intentional no-owner
        # rows and stay separate from malformed-owner coverage above.
        for handler_name in ("dup2", "dup"):
            state = seed_state()
            operation = dup2_operation() if handler_name == "dup2" else dup_operation()
            pending = arm(state, operation)
            before = snapshot(state)
            if handler_name == "dup2":
                invoke = lambda: state.finish_dup2_syscall(tid=100, result=6, errno=None)
            else:
                invoke = lambda: state.finish_dup_syscall(tid=100, result=1, errno=None)
            expect_format(f"no-owner {handler_name}", state, invoke)
            assert_unchanged(f"no-owner {handler_name}", before, snapshot(state))
        

    def test_malformed_terminal_and_stale_topology(self):
        # Malformed terminal pairs and stale topology retain the full owner snapshot.
        for handler_name in ("dup2", "dup"):
            state = seed_state()
            operation = dup2_operation() if handler_name == "dup2" else dup_operation()
            pending = arm(state, operation)
            table = state._task(100)["fds"]
            one_owner(state, operation, table=table, pending=pending)
            if state.try_admit_fd_table_mutator(tid=100) is not True:
                raise SystemExit(f"{handler_name}: setup admission failed")
            bad_call = (
                lambda: state.finish_dup2_syscall(tid=100, result=5, errno=4)
                if handler_name == "dup2"
                else state.finish_dup_syscall(tid=100, result=0, errno=None)
            )
            expect_format(f"malformed terminal {handler_name}", state, bad_call)
            malformed_outcome = (
                lambda: state.finish_dup2_syscall(tid=100, result=6, errno=4)
                if handler_name == "dup2"
                else state.finish_dup_syscall(tid=100, result=-512, errno=4)
            )
            expect_format(
                f"malformed normalized outcome {handler_name}",
                state,
                malformed_outcome,
            )
            state._task(100)["fds"] = dict(table)
            expect_format(
                f"stale topology {handler_name}",
                state,
                lambda: state.finish_dup2_syscall(tid=100, result=6, errno=None)
                if handler_name == "dup2"
                else state.finish_dup_syscall(tid=100, result=1, errno=None),
            )

    def test_terminal_release_and_alias_admission(self):
        # Accepted success and every admitted terminal failure consume pending and one
        # owner only; a shared alias can then acquire the same table.
        def assert_alias_after_release(label, state, peer_pending):
            if state._fd_table_mutators:
                raise SystemExit(f"{label}: owner was not released")
            if 100 in state._pending:
                raise SystemExit(f"{label}: completed pending entry was not consumed")
            if state._pending.get(101) is not peer_pending:
                raise SystemExit(f"{label}: unrelated pending identity changed")
            if state.try_admit_fd_table_mutator(tid=101) is not True:
                raise SystemExit(f"{label}: released shared alias did not admit")
        
        
        state = seed_state()
        pending = arm(state, dup2_operation())
        peer_pending = arm(state, dup2_operation(), tid=101)
        if state.try_admit_fd_table_mutator(tid=100) is not True:
            raise SystemExit("dup2 success admission failed")
        receipt = state.finish_dup2_syscall(tid=100, result=6, errno=None)
        assert_receipt("dup2 success release", receipt, pending, 6, None)
        assert_alias_after_release("dup2 success release", state, peer_pending)
        
        for errno in (4, 9, 16, 24):
            state = seed_state()
            pending = arm(state, dup2_operation())
            peer_pending = arm(state, dup2_operation(), tid=101)
            if state.try_admit_fd_table_mutator(tid=100) is not True:
                raise SystemExit(f"dup2 failure {errno} admission failed")
            receipt = state.finish_dup2_syscall(tid=100, result=-1, errno=errno)
            assert_receipt(f"dup2 failure {errno} release", receipt, pending, -1, errno)
            assert_alias_after_release(f"dup2 failure {errno} release", state, peer_pending)
        
        for errno, oldfd in ((9, 99), (24, 5)):
            state = seed_state()
            pending = arm(state, dup_operation(oldfd))
            peer_pending = arm(state, dup_operation(), tid=101)
            if state.try_admit_fd_table_mutator(tid=100) is not True:
                raise SystemExit(f"dup failure {errno} admission failed")
            receipt = state.finish_dup_syscall(tid=100, result=-1, errno=errno)
            assert_receipt(f"dup failure {errno} release", receipt, pending, -1, errno)
            assert_alias_after_release(f"dup failure {errno} release", state, peer_pending)

    def test_restart_then_terminal_release(self):
        # Restart retains the owner/pending pair and same-object re-admission is
        # idempotent before the later terminal release.
        state = seed_state()
        pending = arm(state, dup2_operation())
        if state.try_admit_fd_table_mutator(tid=100) is not True:
            raise SystemExit("restart setup admission failed")
        if state.finish_syscall(tid=100, outcome="restart") is not None:
            raise SystemExit("restart returned a non-None result")
        if state._pending[100] is not pending:
            raise SystemExit("restart replaced pending identity")
        if state.try_admit_fd_table_mutator(tid=100) is not True:
            raise SystemExit("restart same-object admission was not idempotent")
        receipt = state.finish_dup2_syscall(tid=100, result=6, errno=None)
        assert_receipt("restart terminal release", receipt, pending, 6, None)
        if state._fd_table_mutators or state._pending:
            raise SystemExit("restart terminal did not release owner and pending")

    def test_distinct_owner_completion_isolation(self):
        # Distinct-table owners are isolated; completing the shared-table owner leaves
        # the copied-table owner tuple and topology untouched.
        state = seed_state()
        root_pending = arm(state, dup2_operation())
        copied_pending = arm(state, dup_operation(), tid=102)
        copied_before = observation(state, (102,))
        if state.try_admit_fd_table_mutator(tid=100) is not True:
            raise SystemExit("isolation root admission failed")
        if state.try_admit_fd_table_mutator(tid=102) is not True:
            raise SystemExit("isolation copied admission failed")
        copied_owner = state._fd_table_mutators[1]
        receipt = state.finish_dup2_syscall(tid=100, result=6, errno=None)
        assert_receipt("isolation root completion", receipt, root_pending, 6, None)
        if len(state._fd_table_mutators) != 1 or state._fd_table_mutators[0] is not copied_owner:
            raise SystemExit("isolation completion released the unrelated owner")
        if state._pending[102] is not copied_pending:
            raise SystemExit("isolation completion changed copied pending")
        if not same_observation(copied_before, observation(state, (102,))):
            raise SystemExit("isolation completion changed copied table")

    def test_later_index_dup2_cleanup(self):
        later_index_discriminator("dup2")

    def test_later_index_dup_cleanup(self):
        later_index_discriminator("dup")

    def test_private_slice_exports_no_runner(self):
        # No runner or production BS2b callable is introduced by this private slice.
        if callable(getattr(module, "run", None)) or callable(getattr(module, "produce", None)):
            raise SystemExit("production BS2b callable became reachable")

if __name__ == "__main__":
    allowed = {f"SemanticTraceFdTableMutatorTests.test_{family}": count for family, count in FAMILY_REJECTIONS.items()}
    requested = sys.argv[1:]
    if not requested:
        raise SystemExit("no FD-table-mutator test selectors supplied")
    unknown = [selector for selector in requested if selector not in allowed]
    if unknown:
        raise SystemExit(f"unknown FD-table-mutator test selector: {unknown[0]}")
    if len(set(requested)) != len(requested):
        raise SystemExit("duplicate FD-table-mutator test selector")
    suite = unittest.defaultTestLoader.loadTestsFromNames(requested, module=sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    expected = sum(allowed[selector] for selector in requested)
    if result.testsRun != len(requested) or result.testsRun == 0 or not result.wasSuccessful() or bool(result.skipped) or REJECTION_COUNT != expected:
        raise SystemExit(1)
    print(f"fd-mutator-families={result.testsRun} rejections={REJECTION_COUNT}")
