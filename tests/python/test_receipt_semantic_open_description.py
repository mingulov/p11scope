"""Semantic trace private open-description contracts."""

from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/receipt-build-subject.py"
MODULE_NAME = "receipt_build_subject_semantic_open_description_test"
MISSING = object()

sys.path.insert(0, str(REPO / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path
module = None
_ACTIVE_TEST = None
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
        test.fail("could not import receipt build-subject script")
    sys.modules[MODULE_NAME] = loaded
    return loaded


class IntSubclass(int):
    pass


class StringSubclass(str):
    pass


class DictSubclass(dict):
    pass


class TupleSubclass(tuple):
    pass


MAX_OFFSET = 2**63 - 1
BASE_ARGS = (0, 0, 0, 0, 0, 0)

def bare_state():
    global module
    module = load_subject(_ACTIVE_TEST)
    legacy = object()
    closing = object()
    return module._SemanticTraceState(
        root_tid=100,
        cwd=object(),
        root=object(),
        umask=0o022,
        fds={3: (legacy, False), 4: (closing, True)},
    )


def seed_state():
    state = bare_state()
    state.map_file(
        tid=100,
        start=0x1000,
        length=0x1000,
        node=object(),
        offset=0,
        prot=object(),
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
    return state


def install_regular(state, fd=5, access="read_write", cloexec=False, node=None):
    if node is None:
        node = object()
    state.install_open_fd(
        tid=100,
        fd=fd,
        node=node,
        kind="regular",
        access=access,
        cloexec=cloexec,
    )


def arm_pending(state, peer=True):
    root_operation = ("C_Root", "pure", BASE_ARGS)
    peer_operation = ("C_Peer", "pure", BASE_ARGS)
    state.begin_syscall(tid=100, operation=root_operation)
    refs = {100: root_operation}
    if peer:
        state.begin_syscall(tid=101, operation=peer_operation)
        refs[101] = peer_operation
    return refs


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


def description_fields(description):
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


def observation(state, tids=(100, 101, 102)):
    result = {}
    for tid in tids:
        fds = state._task(tid)["fds"]
        snapshot = state.snapshot(tid=tid)
        fd_rows = []
        if type(fds) is dict:
            for fd, value in fds.items():
                if type(value) is tuple and len(value) == 2:
                    fd_rows.append((fd, value[0], value[1], description_fields(value[0])))
                else:
                    fd_rows.append((fd, value, None, None))
        result[tid] = (
            snapshot["tgid"],
            fds,
            fd_rows,
            snapshot["cwd"],
            snapshot["root"],
            snapshot["umask"],
            snapshot["maps"],
        )
    return result


def same_observation(before, after):
    if set(before) != set(after):
        return False
    for tid in before:
        left, right = before[tid], after[tid]
        if left[0] != right[0] or left[1] is not right[1] or not same_value(left[3:], right[3:]):
            return False
        if len(left[2]) != len(right[2]):
            return False
        for before_fd, after_fd in zip(left[2], right[2]):
            if not same_value(before_fd[0], after_fd[0]) or not same_value(before_fd[2], after_fd[2]):
                return False
            if before_fd[1] is not after_fd[1]:
                return False
            if not same_value(before_fd[3], after_fd[3]):
                return False
    return True


def expect_rejected(label, state, invoke, refs=None):
    before = observation(state)
    if refs is None:
        refs = dict(state._pending)
    try:
        invoke()
    except BaseException as exc:
        if type(exc) is not module.FormatError:
            raise SystemExit(
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}"
            ) from exc
    else:
        raise SystemExit(f"{label}: accepted invalid operation")
    after = observation(state)
    if not same_observation(before, after):
        raise SystemExit(f"{label}: rejected operation mutated semantic state")
    if set(state._pending) != set(refs) or any(
        state._pending[tid] is not operation for tid, operation in refs.items()
    ):
        raise SystemExit(f"{label}: rejected operation changed pending tuple identity")
    global REJECTION_COUNT
    REJECTION_COUNT += 1


def expect_rejected_with_bad_table(label, method, table):
    state = seed_state()
    refs = arm_pending(state)
    task = state._task(100)
    task["fds"] = table
    before_table = table
    before = observation(state)
    try:
        method(state)
    except BaseException as exc:
        if type(exc) is not module.FormatError:
            raise SystemExit(
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}"
            ) from exc
    else:
        raise SystemExit(f"{label}: accepted malformed FD table")
    if task["fds"] is not before_table or not same_observation(before, observation(state)):
        raise SystemExit(f"{label}: malformed FD table rejection mutated state")
    if set(state._pending) != set(refs) or any(
        state._pending[tid] is not operation for tid, operation in refs.items()
    ):
        raise SystemExit(f"{label}: malformed FD table changed pending identity")
    global REJECTION_COUNT
    REJECTION_COUNT += 1


def assert_pending(label, state, refs):
    if set(state._pending) != set(refs) or any(
        state._pending[tid] is not operation for tid, operation in refs.items()
    ):
        raise SystemExit(f"{label}: successful operation changed pending tuple identity")


def assert_description(description, kind, access, offset, identity):
    if type(description.kind) is not str or type(description.access) is not str:
        raise SystemExit("description kind/access types were not exact str")
    if description.kind != kind or description.access != access:
        raise SystemExit(f"description fields were not {kind}/{access}")
    if kind == "regular":
        if type(description.offset) is not int or not 0 <= description.offset <= MAX_OFFSET:
            raise SystemExit("regular description offset was not an exact bounded int")
        if description.identity is None:
            raise SystemExit("regular description identity was None")
    elif description.offset is not None:
        raise SystemExit("non-regular description offset was not None")
    if kind == "directory" and description.identity is None:
        raise SystemExit("directory description identity was None")
    if kind in ("pipe", "socketpair"):
        pair_identity = description.identity
        if type(pair_identity) is not tuple or len(pair_identity) != 2:
            raise SystemExit("local-pair identity was not an exact two-item tuple")
        if type(pair_identity[0]) is not object or type(pair_identity[1]) is not int:
            raise SystemExit("local-pair identity fields had non-exact types")
        if pair_identity[1] not in (0, 1):
            raise SystemExit("local-pair endpoint index was out of range")
    if description.offset != offset or description.identity is not identity:
        raise SystemExit("description did not retain its exact fields")


def assert_fd_entry(fds, fd, description, cloexec):
    value = fds[fd]
    if type(value) is not tuple or len(value) != 2 or type(value[1]) is not bool:
        raise SystemExit("FD entry was not an exact (description, bool) tuple")
    if value[0] is not description or value[1] is not cloexec:
        raise SystemExit("FD entry did not retain exact description/CLOEXEC")


def expect_selected_with_unrelated_fd(label, setup, invoke):
    state = seed_state()
    setup(state)
    refs = arm_pending(state)
    expect_rejected(label, state, lambda: invoke(state), refs)



def expect_malformed_pair_description(
    label, pair_kind, fd, expected_access, expected_index, direction, mutate
):
    state = seed_state()
    state.install_local_pair(
        tid=100, first_fd=10, second_fd=11, kind=pair_kind, cloexec=False
    )
    description = state.snapshot(tid=100)["fds"][fd][0]
    assert_description(description, pair_kind, expected_access, None, description.identity)
    if description.identity[1] != expected_index:
        raise SystemExit(f"{label}: selected endpoint index was wrong")
    mutate(description)
    refs = arm_pending(state)
    expect_rejected(
        label,
        state,
        lambda: state.apply_io_offset(
            tid=100, fd=fd, direction=direction, count=0, position=None
        ),
        refs,
    )


FAMILY_REJECTIONS = {
    "open_alias_exec_close_identity": 0,
    "local_pair_topology_and_io": 4,
    "malformed_pair_descriptions": 80,
    "pair_io_malformed_table": 2,
    "offset_boundaries": 2,
    "directory_io_rejection": 8,
    "open_argument_validation": 18,
    "pair_argument_validation": 19,
    "malformed_tables_and_unrelated_entries": 15,
    "io_tid_fd_validation": 10,
    "io_direction_validation": 3,
    "io_count_validation": 5,
    "io_position_validation": 6,
    "malformed_regular_description": 8,
    "regular_access_mismatch": 2,
    "legacy_opaque_io_rejection": 1,
    "dup2_same_fd_and_close": 0,
    "dup2_fd_validation": 9,
    "dup2_tid_validation": 5,
    "close_tid_fd_validation": 10,
    "legacy_opaque_topology": 0,
}


class SemanticTraceOpenDescriptionTests(unittest.TestCase):
    def setUp(self):
        global _ACTIVE_TEST
        _ACTIVE_TEST = self
        self._rejection_start = REJECTION_COUNT

    def tearDown(self):
        family = self._testMethodName.removeprefix("test_")
        self.assertEqual(
            REJECTION_COUNT - self._rejection_start,
            FAMILY_REJECTIONS[family],
            f"{family}: rejection-vector count",
        )

    def test_open_alias_exec_close_identity(self):
        # The first wished-for S4 operation is a valid install_open_fd call.  The
        # current candidate stops here with the intended missing-method AttributeError.
        state = bare_state()
        first_node = object()
        state.install_open_fd(
            tid=100,
            fd=5,
            node=first_node,
            kind="regular",
            access="read_write",
            cloexec=False,
        )
        open_refs = arm_pending(state, peer=False)
        state.install_open_fd(
            tid=100,
            fd=6,
            node=first_node,
            kind="regular",
            access="read_write",
            cloexec=False,
        )
        assert_pending("successful representative open", state, open_refs)
        directory_node = object()
        state.install_open_fd(
            tid=100,
            fd=7,
            node=directory_node,
            kind="directory",
            access="read",
            cloexec=True,
        )
        assert_pending("successful representative open", state, open_refs)
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
        peer_operation = ("C_Peer", "pure", BASE_ARGS)
        state.begin_syscall(tid=101, operation=peer_operation)
        open_refs[101] = peer_operation
        assert_pending("successful open after peer spawn", state, open_refs)
        first = state.snapshot(tid=100)["fds"]
        first_description = first[5][0]
        second_description = first[6][0]
        directory_description = first[7][0]
        if first_description is second_description:
            raise SystemExit("two opens of one node shared a description")
        assert_fd_entry(first, 5, first_description, False)
        assert_fd_entry(first, 6, second_description, False)
        assert_fd_entry(first, 7, directory_description, True)
        assert_description(first_description, "regular", "read_write", 0, first_node)
        assert_description(second_description, "regular", "read_write", 0, first_node)
        assert_description(directory_description, "directory", "read", None, directory_node)
        
        state.dup2(tid=100, source_fd=5, target_fd=8)
        assert_pending("successful representative dup2", state, open_refs)
        for tid in (100, 101, 102):
            if state.snapshot(tid=tid)["fds"][5][0] is not first_description:
                raise SystemExit("open description identity was not retained by fork/copy")
        if state.snapshot(tid=100)["fds"][8][0] is not first_description:
            raise SystemExit("dup2 did not retain the exact description object")
        if 8 in state.snapshot(tid=102)["fds"]:
            raise SystemExit("dup2 leaked into a copied FD table")
        state.apply_io_offset(tid=100, fd=8, direction="read", count=4, position=None)
        assert_pending("successful representative regular I/O", state, open_refs)
        for tid in (100, 101, 102):
            if state.snapshot(tid=tid)["fds"][5][0].offset != 4:
                raise SystemExit("non-positional I/O did not share the open offset")
        if state.snapshot(tid=100)["fds"][6][0].offset != 0:
            raise SystemExit("independent open changed its offset")
        state.apply_io_offset(tid=100, fd=5, direction="write", count=0, position=None)
        if first_description.offset != 4:
            raise SystemExit("zero-count I/O changed the shared offset")
        state.exec_event(
            tid=100,
            mappings={0x2000: (1, object(), 0, object(), False)},
        )
        root_fds = state.snapshot(tid=100)["fds"]
        peer_fds = state.snapshot(tid=101)["fds"]
        if set(root_fds) != {3, 5, 6, 8}:
            raise SystemExit("exec retained the wrong typed FD set")
        if root_fds[5][0] is not first_description or root_fds[8][0] is not first_description:
            raise SystemExit("exec did not retain description identity and offset")
        if root_fds[5][0].offset != 4:
            raise SystemExit("exec did not retain the shared regular offset")
        if 6 not in peer_fds or peer_fds[6][1] is not False:
            raise SystemExit("shared peer lost its old FD table")
        if peer_fds[6][0] is not second_description:
            raise SystemExit("shared peer changed the independent description")
        if 7 not in peer_fds or peer_fds[7][1] is not True:
            raise SystemExit("shared peer did not retain the CLOEXEC entry")
        if state.snapshot(tid=102)["fds"][6][0] is not second_description:
            raise SystemExit("copied peer changed the independent description")
        state.close(tid=100, fd=8)
        assert_pending("successful representative close", state, open_refs)
        if 8 in state.snapshot(tid=100)["fds"] or state.snapshot(tid=100)["fds"][5][0] is not first_description:
            raise SystemExit("close removed the retained alias")
        if state.snapshot(tid=101)["fds"][5][0] is not first_description:
            raise SystemExit("close changed the shared peer alias")

    def test_local_pair_topology_and_io(self):
        # Local pairs have two distinct descriptions but a common opaque pair token.
        pair_state = seed_state()
        pair_refs = arm_pending(pair_state)
        pair_state.install_local_pair(
            tid=100, first_fd=10, second_fd=11, kind="pipe", cloexec=True
        )
        assert_pending("successful representative local pair", pair_state, pair_refs)
        pipe_fds = pair_state.snapshot(tid=100)["fds"]
        pipe_read, pipe_write = pipe_fds[10][0], pipe_fds[11][0]
        assert_fd_entry(pipe_fds, 10, pipe_read, True)
        assert_fd_entry(pipe_fds, 11, pipe_write, True)
        if pipe_read is pipe_write or pipe_read.offset is not None or pipe_write.offset is not None:
            raise SystemExit("pipe endpoint descriptions or offsets are wrong")
        if pipe_read.access != "read" or pipe_write.access != "write":
            raise SystemExit("pipe endpoint access is wrong")
        if pipe_read.kind != "pipe" or pipe_write.kind != "pipe":
            raise SystemExit("pipe endpoint kind is wrong")
        if type(pipe_read.identity) is not tuple or len(pipe_read.identity) != 2:
            raise SystemExit("pipe identity is not a two-item tuple")
        if pipe_read.identity[0] is not pipe_write.identity[0] or type(pipe_read.identity[0]) is not object:
            raise SystemExit("pipe endpoints do not share one exact opaque pair token")
        if pipe_read.identity[1] != 0 or pipe_write.identity[1] != 1:
            raise SystemExit("pipe endpoint indices are wrong")
        assert_description(pipe_read, "pipe", "read", None, pipe_read.identity)
        assert_description(pipe_write, "pipe", "write", None, pipe_write.identity)
        pair_state.install_local_pair(
            tid=100, first_fd=12, second_fd=13, kind="socketpair", cloexec=False
        )
        socket_fds = pair_state.snapshot(tid=100)["fds"]
        socket_left, socket_right = socket_fds[12][0], socket_fds[13][0]
        assert_fd_entry(socket_fds, 12, socket_left, False)
        assert_fd_entry(socket_fds, 13, socket_right, False)
        if socket_left is socket_right or socket_left.access != "read_write" or socket_right.access != "read_write":
            raise SystemExit("socketpair endpoint topology is wrong")
        if socket_left.kind != "socketpair" or socket_right.kind != "socketpair":
            raise SystemExit("socketpair endpoint kind is wrong")
        if socket_left.identity[0] is not socket_right.identity[0] or socket_left.identity[1] != 0 or socket_right.identity[1] != 1:
            raise SystemExit("socketpair endpoint identity is wrong")
        assert_description(socket_left, "socketpair", "read_write", None, socket_left.identity)
        assert_description(socket_right, "socketpair", "read_write", None, socket_right.identity)
        pair_state.apply_io_offset(tid=100, fd=10, direction="read", count=4, position=None)
        pair_state.apply_io_offset(tid=100, fd=11, direction="write", count=4, position=None)
        pair_state.apply_io_offset(tid=100, fd=12, direction="read", count=4, position=None)
        assert_pending("successful representative local-pair I/O", pair_state, pair_refs)
        for endpoint in (pipe_read, pipe_write, socket_left, socket_right):
            if endpoint.offset is not None:
                raise SystemExit("local-pair I/O changed an endpoint offset")
        
        single_endpoint = seed_state()
        single_refs = arm_pending(single_endpoint)
        single_endpoint.install_local_pair(
            tid=100, first_fd=10, second_fd=11, kind="pipe", cloexec=False
        )
        remaining = single_endpoint.snapshot(tid=100)["fds"][10][0]
        single_endpoint.close(tid=100, fd=11)
        single_endpoint.apply_io_offset(
            tid=100, fd=10, direction="read", count=1, position=None
        )
        assert_pending("successful single local-pair endpoint I/O", single_endpoint, single_refs)
        if remaining.offset is not None:
            raise SystemExit("single local-pair endpoint I/O changed its offset")
        for label, fd, direction in (
            ("pipe read direction", 11, "read"),
            ("pipe write direction", 10, "write"),
            ("socket bad direction", 12, "bad"),
        ):
            invalid_pair = seed_state()
            invalid_pair.install_local_pair(
                tid=100, first_fd=10, second_fd=11, kind="pipe", cloexec=True
            )
            invalid_pair.install_local_pair(
                tid=100,
                first_fd=12,
                second_fd=13,
                kind="socketpair",
                cloexec=False,
            )
            invalid_refs = arm_pending(invalid_pair)
            expect_rejected(
                label,
                invalid_pair,
                lambda fd=fd, direction=direction: invalid_pair.apply_io_offset(
                    tid=100, fd=fd, direction=direction, count=1, position=None
                ),
                refs=invalid_refs,
            )
        invalid_pair = seed_state()
        invalid_pair.install_local_pair(
            tid=100, first_fd=10, second_fd=11, kind="pipe", cloexec=True
        )
        invalid_pair.install_local_pair(
            tid=100,
            first_fd=12,
            second_fd=13,
            kind="socketpair",
            cloexec=False,
        )
        invalid_refs = arm_pending(invalid_pair)
        expect_rejected(
            "positional pipe I/O",
            invalid_pair,
            lambda: invalid_pair.apply_io_offset(
                tid=100, fd=10, direction="read", count=0, position=0
            ),
            refs=invalid_refs,
        )

    def test_malformed_pair_descriptions(self):
        for pair_kind, endpoints in (
            (
                "pipe",
                ((10, "read", 0, "read"), (11, "write", 1, "write")),
            ),
            (
                "socketpair",
                ((10, "read_write", 0, "read"), (11, "read_write", 1, "read")),
            ),
        ):
            for fd, expected_access, expected_index, direction in endpoints:
                malformed = (
                    ("kind", lambda description: setattr(description, "kind", "unknown-pair-kind"), direction),
                    ("kind subclass", lambda description: setattr(description, "kind", StringSubclass(pair_kind)), direction),
                    (
                        "access",
                        lambda description: setattr(
                            description,
                            "access",
                            "write" if expected_access == "read" else "read",
                        ),
                        "write" if expected_access == "read" else "read",
                    ),
                    (
                        "access subclass",
                        lambda description: setattr(description, "access", StringSubclass(expected_access)),
                        direction,
                    ),
                    ("offset integer", lambda description: setattr(description, "offset", 0), direction),
                    ("offset bool", lambda description: setattr(description, "offset", True), direction),
                    ("offset subclass", lambda description: setattr(description, "offset", IntSubclass(0)), direction),
                    ("offset negative", lambda description: setattr(description, "offset", -1), direction),
                    ("offset overflow", lambda description: setattr(description, "offset", MAX_OFFSET + 1), direction),
                    ("identity non-tuple", lambda description: setattr(description, "identity", object()), direction),
                    ("identity string token", lambda description: setattr(description, "identity", ("token", expected_index)), direction),
                    ("identity integer token", lambda description: setattr(description, "identity", (1, expected_index)), direction),
                    ("identity tuple subclass", lambda description: setattr(description, "identity", TupleSubclass((object(), expected_index))), direction),
                    ("identity one item", lambda description: setattr(description, "identity", (object(),)), direction),
                    ("identity three items", lambda description: setattr(description, "identity", (object(), expected_index, 1)), direction),
                    ("identity bool index", lambda description: setattr(description, "identity", (object(), True)), direction),
                    ("identity subclass index", lambda description: setattr(description, "identity", (object(), IntSubclass(expected_index))), direction),
                    ("identity negative index", lambda description: setattr(description, "identity", (object(), -1)), direction),
                    ("identity out-of-range index", lambda description: setattr(description, "identity", (object(), 2)), direction),
                    (
                        "identity swapped valid index",
                        lambda description: setattr(
                            description,
                            "identity",
                            (description.identity[0], 1 - expected_index),
                        ),
                        direction,
                    ),
                )
                for suffix, mutate, invoke_direction in malformed:
                    expect_malformed_pair_description(
                        f"{pair_kind} endpoint {expected_index} malformed {suffix}",
                        pair_kind,
                        fd,
                        expected_access,
                        expected_index,
                        invoke_direction,
                        mutate,
                    )

    def test_pair_io_malformed_table(self):
        state = seed_state()
        state.install_local_pair(
            tid=100, first_fd=10, second_fd=11, kind="socketpair", cloexec=False
        )
        state._task(100)["fds"][True] = (object(), False)
        refs = arm_pending(state)
        expect_rejected(
            "valid pair with malformed FD key",
            state,
            lambda: state.apply_io_offset(
                tid=100, fd=10, direction="read", count=0, position=None
            ),
            refs,
        )
        state = seed_state()
        state.install_local_pair(
            tid=100, first_fd=10, second_fd=11, kind="socketpair", cloexec=False
        )
        state._task(100)["fds"][20] = [object(), False]
        refs = arm_pending(state)
        expect_rejected(
            "valid pair with malformed FD entry",
            state,
            lambda: state.apply_io_offset(
                tid=100, fd=10, direction="read", count=0, position=None
            ),
            refs,
        )

    def test_offset_boundaries(self):
        # Regular offsets use checked MAX_OFFSET arithmetic, and positional I/O does
        # not move the shared description offset.
        boundary = seed_state()
        install_regular(boundary)
        boundary.apply_io_offset(
            tid=100, fd=5, direction="read", count=1, position=MAX_OFFSET - 1
        )
        if boundary.snapshot(tid=100)["fds"][5][0].offset != 0:
            raise SystemExit("positional I/O moved the shared offset")
        boundary.apply_io_offset(
            tid=100, fd=5, direction="write", count=0, position=MAX_OFFSET
        )
        positional_overflow = seed_state()
        install_regular(positional_overflow)
        expect_rejected(
            "positional MAX_OFFSET overflow",
            positional_overflow,
            lambda: positional_overflow.apply_io_offset(
                tid=100, fd=5, direction="read", count=1, position=MAX_OFFSET
            ),
            refs={},
        )
        boundary.apply_io_offset(tid=100, fd=5, direction="read", count=MAX_OFFSET - 1, position=None)
        boundary.apply_io_offset(tid=100, fd=5, direction="read", count=1, position=None)
        if boundary.snapshot(tid=100)["fds"][5][0].offset != MAX_OFFSET:
            raise SystemExit("non-positional boundary did not reach MAX_OFFSET")
        boundary.apply_io_offset(tid=100, fd=5, direction="read", count=0, position=None)
        nonpositional_overflow = seed_state()
        install_regular(nonpositional_overflow)
        nonpositional_overflow.apply_io_offset(
            tid=100, fd=5, direction="read", count=MAX_OFFSET, position=None
        )
        expect_rejected(
            "non-positional MAX_OFFSET overflow",
            nonpositional_overflow,
            lambda: nonpositional_overflow.apply_io_offset(
                tid=100, fd=5, direction="read", count=1, position=None
            ),
            refs={},
        )

    def test_directory_io_rejection(self):
        # Directory descriptions accept only read installation and reject every S4
        # offset operation without changing the pending state or topology.
        for direction in ("read", "write"):
            for count, position in ((0, None), (1, None), (0, 0), (1, 0)):
                directory = seed_state()
                directory.install_open_fd(
                    tid=100,
                    fd=6,
                    node=object(),
                    kind="directory",
                    access="read",
                    cloexec=False,
                )
                directory_description = directory.snapshot(tid=100)["fds"][6][0]
                if (
                    directory_description.offset is not None
                    or directory_description.access != "read"
                ):
                    raise SystemExit("directory description fields are wrong")
                refs = arm_pending(directory)
                expect_rejected(
                    f"directory {direction} count={count} position={position}",
                    directory,
                    lambda direction=direction, count=count, position=position: directory.apply_io_offset(
                        tid=100,
                        fd=6,
                        direction=direction,
                        count=count,
                        position=position,
                    ),
                    refs,
                )

    def test_open_argument_validation(self):
        # Installation, I/O arguments, and malformed table/description forms reject
        # before mutation.  Each case has real pending root/peer tuples.
        for label, kwargs in (
            ("occupied open FD", dict(fd=3, node=object(), kind="regular", access="read", cloexec=False)),
            ("negative open FD", dict(fd=-1, node=object(), kind="regular", access="read", cloexec=False)),
            ("boolean open FD", dict(fd=True, node=object(), kind="regular", access="read", cloexec=False)),
            ("float open FD", dict(fd=5.0, node=object(), kind="regular", access="read", cloexec=False)),
            ("IntSubclass open FD", dict(fd=IntSubclass(5), node=object(), kind="regular", access="read", cloexec=False)),
            ("unknown open TID", dict(fd=5, node=object(), kind="regular", access="read", cloexec=False, tid=999)),
            ("boolean open TID", dict(fd=5, node=object(), kind="regular", access="read", cloexec=False, tid=True)),
            ("negative open TID", dict(fd=5, node=object(), kind="regular", access="read", cloexec=False, tid=-1)),
            ("string open TID", dict(fd=5, node=object(), kind="regular", access="read", cloexec=False, tid="100")),
            ("IntSubclass open TID", dict(fd=5, node=object(), kind="regular", access="read", cloexec=False, tid=IntSubclass(100))),
            ("open kind", dict(fd=5, node=object(), kind="pipe", access="read", cloexec=False)),
            ("open access", dict(fd=5, node=object(), kind="regular", access="bad", cloexec=False)),
            ("open None node", dict(fd=5, node=None, kind="regular", access="read", cloexec=False)),
            ("open CLOEXEC integer", dict(fd=5, node=object(), kind="regular", access="read", cloexec=1)),
            ("directory write access", dict(fd=5, node=object(), kind="directory", access="write", cloexec=False)),
            ("directory read_write access", dict(fd=5, node=object(), kind="directory", access="read_write", cloexec=False)),
            ("open StringSubclass kind", dict(fd=5, node=object(), kind=StringSubclass("regular"), access="read", cloexec=False)),
            ("open StringSubclass access", dict(fd=5, node=object(), kind="regular", access=StringSubclass("read"), cloexec=False)),
        ):
            state = seed_state()
            refs = arm_pending(state)
            tid = kwargs.pop("tid", 100)
            expect_rejected(
                label,
                state,
                lambda kwargs=kwargs, tid=tid: state.install_open_fd(tid=tid, **kwargs),
                refs,
            )

    def test_pair_argument_validation(self):
        for label, kwargs in (
            ("pair equal FDs", dict(first_fd=10, second_fd=10, kind="pipe", cloexec=False)),
            ("pair occupied first FD", dict(first_fd=3, second_fd=10, kind="pipe", cloexec=False)),
            ("pair occupied second FD", dict(first_fd=10, second_fd=3, kind="pipe", cloexec=False)),
            ("pair negative first FD", dict(first_fd=-1, second_fd=10, kind="pipe", cloexec=False)),
            ("pair negative second FD", dict(first_fd=10, second_fd=-1, kind="pipe", cloexec=False)),
            ("pair boolean first FD", dict(first_fd=True, second_fd=10, kind="pipe", cloexec=False)),
            ("pair boolean second FD", dict(first_fd=10, second_fd=False, kind="pipe", cloexec=False)),
            ("pair float first FD", dict(first_fd=10.0, second_fd=11, kind="pipe", cloexec=False)),
            ("pair float second FD", dict(first_fd=10, second_fd=11.0, kind="pipe", cloexec=False)),
            ("pair IntSubclass first FD", dict(first_fd=IntSubclass(10), second_fd=11, kind="pipe", cloexec=False)),
            ("pair IntSubclass second FD", dict(first_fd=10, second_fd=IntSubclass(11), kind="pipe", cloexec=False)),
            ("pair unknown TID", dict(first_fd=10, second_fd=11, kind="pipe", cloexec=False, tid=999)),
            ("pair boolean TID", dict(first_fd=10, second_fd=11, kind="pipe", cloexec=False, tid=True)),
            ("pair negative TID", dict(first_fd=10, second_fd=11, kind="pipe", cloexec=False, tid=-1)),
            ("pair string TID", dict(first_fd=10, second_fd=11, kind="pipe", cloexec=False, tid="100")),
            ("pair IntSubclass TID", dict(first_fd=10, second_fd=11, kind="pipe", cloexec=False, tid=IntSubclass(100))),
            ("pair kind", dict(first_fd=10, second_fd=11, kind="regular", cloexec=False)),
            ("pair StringSubclass kind", dict(first_fd=10, second_fd=11, kind=StringSubclass("pipe"), cloexec=False)),
            ("pair CLOEXEC integer", dict(first_fd=10, second_fd=11, kind="pipe", cloexec=1)),
        ):
            state = seed_state()
            refs = arm_pending(state)
            tid = kwargs.pop("tid", 100)
            expect_rejected(
                label,
                state,
                lambda kwargs=kwargs, tid=tid: state.install_local_pair(tid=tid, **kwargs),
                refs,
            )

    def test_malformed_tables_and_unrelated_entries(self):
        expect_rejected_with_bad_table(
            "open list FD table",
            lambda state: state.install_open_fd(
                tid=100, fd=5, node=object(), kind="regular", access="read", cloexec=False
            ),
            [],
        )
        
        for label, setup, invoke in (
            (
                "open valid target with malformed unrelated key",
                lambda state: state._task(100)["fds"].update({True: (object(), False)}),
                lambda state: state.install_open_fd(
                    tid=100, fd=5, node=object(), kind="regular", access="read", cloexec=False
                ),
            ),
            (
                "open valid target with malformed unrelated entry",
                lambda state: state._task(100)["fds"].update({20: [object(), False]}),
                lambda state: state.install_open_fd(
                    tid=100, fd=5, node=object(), kind="regular", access="read", cloexec=False
                ),
            ),
            (
                "pair valid targets with malformed unrelated key",
                lambda state: state._task(100)["fds"].update({True: (object(), False)}),
                lambda state: state.install_local_pair(
                    tid=100, first_fd=10, second_fd=11, kind="pipe", cloexec=False
                ),
            ),
            (
                "pair valid targets with malformed unrelated entry",
                lambda state: state._task(100)["fds"].update({20: [object(), False]}),
                lambda state: state.install_local_pair(
                    tid=100, first_fd=10, second_fd=11, kind="pipe", cloexec=False
                ),
            ),
            (
                "I/O valid description with malformed unrelated key",
                lambda state: (install_regular(state), state._task(100)["fds"].update({True: (object(), False)})),
                lambda state: state.apply_io_offset(
                    tid=100, fd=5, direction="read", count=0, position=None
                ),
            ),
            (
                "I/O valid description with malformed unrelated entry",
                lambda state: (install_regular(state), state._task(100)["fds"].update({20: [object(), False]})),
                lambda state: state.apply_io_offset(
                    tid=100, fd=5, direction="read", count=0, position=None
                ),
            ),
            (
                "dup2 valid source with malformed unrelated key",
                lambda state: state._task(100)["fds"].update({True: (object(), False)}),
                lambda state: state.dup2(tid=100, source_fd=3, target_fd=5),
            ),
            (
                "dup2 valid source with malformed unrelated entry",
                lambda state: state._task(100)["fds"].update({20: [object(), False]}),
                lambda state: state.dup2(tid=100, source_fd=3, target_fd=5),
            ),
            (
                "close valid FD with malformed unrelated key",
                lambda state: state._task(100)["fds"].update({True: (object(), False)}),
                lambda state: state.close(tid=100, fd=3),
            ),
            (
                "close valid FD with malformed unrelated entry",
                lambda state: state._task(100)["fds"].update({20: [object(), False]}),
                lambda state: state.close(tid=100, fd=3),
            ),
        ):
            expect_selected_with_unrelated_fd(label, setup, invoke)
        expect_rejected_with_bad_table(
            "pair dict subclass FD table",
            lambda state: state.install_local_pair(
                tid=100, first_fd=10, second_fd=11, kind="pipe", cloexec=False
            ),
            DictSubclass({3: (object(), False)}),
        )
        expect_rejected_with_bad_table(
            "I/O malformed FD entry",
            lambda state: state.apply_io_offset(
                tid=100, fd=3, direction="read", count=0, position=None
            ),
            {3: [object(), False]},
        )
        expect_rejected_with_bad_table(
            "dup2 malformed FD entry",
            lambda state: state.dup2(tid=100, source_fd=3, target_fd=5),
            {3: [object(), False]},
        )
        expect_rejected_with_bad_table(
            "close list FD table",
            lambda state: state.close(tid=100, fd=3),
            [],
        )

    def test_io_tid_fd_validation(self):
        for label, kwargs in (
            ("I/O unknown TID", dict(tid=999, fd=3)),
            ("I/O boolean TID", dict(tid=True, fd=3)),
            ("I/O negative TID", dict(tid=-1, fd=3)),
            ("I/O string TID", dict(tid="100", fd=3)),
            ("I/O IntSubclass TID", dict(tid=IntSubclass(100), fd=3)),
            ("I/O unknown FD", dict(tid=100, fd=99)),
            ("I/O boolean FD", dict(tid=100, fd=True)),
            ("I/O negative FD", dict(tid=100, fd=-1)),
            ("I/O float FD", dict(tid=100, fd=3.0)),
            ("I/O IntSubclass FD", dict(tid=100, fd=IntSubclass(3))),
        ):
            state = seed_state()
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda kwargs=kwargs: state.apply_io_offset(
                    direction="read", count=0, position=None, **kwargs
                ),
                refs,
            )

    def test_io_direction_validation(self):
        for label, direction in (
            ("I/O None direction", None),
            ("I/O bytes direction", b"read"),
            ("I/O StringSubclass direction", StringSubclass("read")),
        ):
            state = seed_state()
            install_regular(state)
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda direction=direction: state.apply_io_offset(
                    tid=100, fd=5, direction=direction, count=0, position=None
                ),
                refs,
            )

    def test_io_count_validation(self):
        for label, count in (
            ("I/O boolean count", True),
            ("I/O negative count", -1),
            ("I/O float count", 0.0),
            ("I/O IntSubclass count", IntSubclass(0)),
            ("I/O overflow count", MAX_OFFSET + 1),
        ):
            state = seed_state()
            install_regular(state)
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda count=count: state.apply_io_offset(
                    tid=100, fd=5, direction="read", count=count, position=None
                ),
                refs,
            )

    def test_io_position_validation(self):
        for label, position in (
            ("I/O boolean position", True),
            ("I/O negative position", -1),
            ("I/O float position", 0.0),
            ("I/O IntSubclass position", IntSubclass(0)),
            ("I/O overflow position", MAX_OFFSET + 1),
            ("I/O string position", "0"),
        ):
            state = seed_state()
            install_regular(state)
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda position=position: state.apply_io_offset(
                    tid=100, fd=5, direction="read", count=0, position=position
                ),
                refs,
            )

    def test_malformed_regular_description(self):
        for label, mutate in (
            ("malformed kind", lambda description: setattr(description, "kind", "pipe")),
            ("malformed access", lambda description: setattr(description, "access", "bad")),
            ("malformed offset bool", lambda description: setattr(description, "offset", True)),
            ("malformed offset negative", lambda description: setattr(description, "offset", -1)),
            ("malformed offset overflow", lambda description: setattr(description, "offset", MAX_OFFSET + 1)),
            ("malformed identity None", lambda description: setattr(description, "identity", None)),
            ("malformed kind subclass", lambda description: setattr(description, "kind", StringSubclass("regular"))),
            ("malformed access subclass", lambda description: setattr(description, "access", StringSubclass("read"))),
        ):
            state = seed_state()
            install_regular(state)
            mutate(state.snapshot(tid=100)["fds"][5][0])
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda: state.apply_io_offset(
                    tid=100, fd=5, direction="read", count=0, position=None
                ),
                refs,
            )

    def test_regular_access_mismatch(self):
        for label, direction, fd in (
            ("read-only write mismatch", "write", 5),
            ("write-only read mismatch", "read", 5),
        ):
            state = seed_state()
            install_regular(state, access="read" if direction == "write" else "write")
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda direction=direction, fd=fd: state.apply_io_offset(
                    tid=100, fd=fd, direction=direction, count=1, position=None
                ),
                refs,
            )

    def test_legacy_opaque_io_rejection(self):
        state = seed_state()
        refs = arm_pending(state)
        expect_rejected(
            "legacy opaque description",
            state,
            lambda: state.apply_io_offset(tid=100, fd=3, direction="read", count=0, position=None),
            refs,
        )

    def test_dup2_same_fd_and_close(self):
        # dup2/close preserve same-FD CLOEXEC and clear it only on a replacement;
        # malformed task/FD forms reject without changing pending tuples.
        state = seed_state()
        install_regular(state, fd=5, access="read", cloexec=True)
        description = state.snapshot(tid=100)["fds"][5][0]
        state.dup2(tid=100, source_fd=5, target_fd=5)
        assert_fd_entry(state.snapshot(tid=100)["fds"], 5, description, True)
        state.dup2(tid=100, source_fd=5, target_fd=6)
        assert_fd_entry(state.snapshot(tid=100)["fds"], 6, description, False)
        state.close(tid=100, fd=6)
        assert_fd_entry(state.snapshot(tid=100)["fds"], 5, description, True)

    def test_dup2_fd_validation(self):
        for label, source_fd, target_fd in (
            ("dup2 unknown source", 99, 6),
            ("dup2 negative source", -1, 6),
            ("dup2 boolean source", True, 6),
            ("dup2 float source", 3.0, 6),
            ("dup2 IntSubclass source", IntSubclass(3), 6),
            ("dup2 negative target", 3, -1),
            ("dup2 boolean target", 3, False),
            ("dup2 float target", 3, 6.0),
            ("dup2 IntSubclass target", 3, IntSubclass(6)),
        ):
            state = seed_state()
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda source_fd=source_fd, target_fd=target_fd: state.dup2(
                    tid=100, source_fd=source_fd, target_fd=target_fd
                ),
                refs,
            )

    def test_dup2_tid_validation(self):
        for label, tid, fd in (
            ("dup2 unknown TID", 999, 3),
            ("dup2 boolean TID", True, 3),
            ("dup2 negative TID", -1, 3),
            ("dup2 string TID", "100", 3),
            ("dup2 IntSubclass TID", IntSubclass(100), 3),
        ):
            state = seed_state()
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda tid=tid, fd=fd: state.dup2(tid=tid, source_fd=fd, target_fd=6),
                refs,
            )

    def test_close_tid_fd_validation(self):
        for label, tid, fd in (
            ("close unknown TID", 999, 3),
            ("close boolean TID", True, 3),
            ("close negative TID", -1, 3),
            ("close string TID", "100", 3),
            ("close IntSubclass TID", IntSubclass(100), 3),
            ("close unknown FD", 100, 99),
            ("close negative FD", 100, -1),
            ("close boolean FD", 100, False),
            ("close float FD", 100, 3.0),
            ("close IntSubclass FD", 100, IntSubclass(3)),
        ):
            state = seed_state()
            refs = arm_pending(state)
            expect_rejected(
                label,
                state,
                lambda tid=tid, fd=fd: state.close(tid=tid, fd=fd),
                refs,
            )

    def test_legacy_opaque_topology(self):
        # Legacy opaque descriptions stay valid for the existing topology methods,
        # while S4 I/O rejects them.
        legacy_state = seed_state()
        legacy = legacy_state.snapshot(tid=100)["fds"][3][0]
        legacy_state.spawn(
            parent_tid=100,
            child_tid=103,
            share_files=False,
            share_fs=False,
            share_vm=False,
            thread_group=False,
        )
        legacy_state.dup2(tid=100, source_fd=3, target_fd=8)
        if legacy_state.snapshot(tid=100)["fds"][8][0] is not legacy:
            raise SystemExit("legacy dup2 did not retain description identity")
        legacy_state.close(tid=100, fd=8)
        if 8 in legacy_state.snapshot(tid=100)["fds"] or legacy_state.snapshot(tid=103)["fds"][3][0] is not legacy:
            raise SystemExit("legacy close/copy topology changed unexpectedly")
        legacy_state.exec_event(
            tid=100,
            mappings={0x3000: (1, object(), 0, object(), False)},
        )
        if legacy_state.snapshot(tid=100)["fds"][3][0] is not legacy:
            raise SystemExit("exec did not retain legacy description identity")


if __name__ == "__main__":
    allowed = {
        f"SemanticTraceOpenDescriptionTests.test_{family}": count
        for family, count in FAMILY_REJECTIONS.items()
    }
    requested = sys.argv[1:]
    if not requested:
        raise SystemExit("no open-description test selectors supplied")
    unknown = [selector for selector in requested if selector not in allowed]
    if unknown:
        raise SystemExit(f"unknown open-description test selector: {unknown[0]}")
    if len(set(requested)) != len(requested):
        raise SystemExit("duplicate open-description test selector")
    suite = unittest.defaultTestLoader.loadTestsFromNames(
        requested, module=sys.modules[__name__]
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    expected_rejections = sum(allowed[selector] for selector in requested)
    if (
        result.testsRun != len(requested)
        or result.testsRun == 0
        or not result.wasSuccessful()
        or bool(result.skipped)
        or REJECTION_COUNT != expected_rejections
    ):
        raise SystemExit(1)
    print(
        f"open-description-families={result.testsRun} "
        f"rejections={REJECTION_COUNT}"
    )
