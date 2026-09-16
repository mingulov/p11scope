"""Complete coupled input-v1 discovery contract, preserved in execution order.

This first extraction intentionally retains the shared state and deferred A2
replay. It is one selectable contract, not independently isolated scenarios.
"""
import contextlib
import errno
import fcntl
import hashlib
import importlib.util
import io
import os
import resource
import stat
import tempfile
import sys

from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/task4-build-subject.py"
GOLDEN_PATH = REPO / "tests/fixtures/task4/input-ledger-golden.tsv"
_MODULE_NAME = "task4_build_subject"
_ABSENT = object()


def run_input_v1_contract(subject_path, golden):
    """Run the ordered original contract with a fresh subject and golden bytes.

    Restore caller module registration, bytecode mode and environment on every
    exit, including a subject import error or a failed contract observation.
    """
    previous_module = sys.modules.get(_MODULE_NAME, _ABSENT)
    previous_bytecode = sys.dont_write_bytecode
    previous_environment = dict(os.environ)
    try:
        sys.dont_write_bytecode = True
        os.environ["TASK4_GOLDEN"] = golden.decode("ascii")
        spec = importlib.util.spec_from_file_location("task4_build_subject", subject_path)
        if spec is None or spec.loader is None:
            raise SystemExit("could not import task4 build-subject script")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        runner = getattr(module, "run_reconciled_build", None)

        class IntSubclass(int):
            pass


        class StrSubclass(str):
            pass


        class BytesSubclass(bytes):
            pass


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
                    with open(path, "rb") as stream:
                        content = stream.read()
                elif stat.S_ISLNK(mode):
                    content = os.readlink(path).encode("utf-8", "surrogateescape")
                else:
                    content = b""
                entries.append((relative, stat.S_IFMT(mode), mode & 0o7777, identity(value), content))
                if stat.S_ISDIR(mode):
                    names = sorted(os.listdir(path), key=os.fsencode)
                    for name in names:
                        child = os.path.join(path, name)
                        child_relative = name if not relative else os.path.join(relative, name)
                        visit(child, child_relative)

            visit(root, "")
            return tuple(entries)


        def ledger_state(fd):
            value = os.fstat(fd)
            content = os.pread(fd, value.st_size, 0)
            if len(content) != value.st_size:
                raise SystemExit("fixture ledger read was short")
            return identity(value), content


        def readable_ledger_state(fd):
            if type(fd) is not int or fd < 0:
                return None
            try:
                flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            except (OSError, TypeError, ValueError):
                return None
            if flags & getattr(os, "O_PATH", 0) or flags & os.O_ACCMODE == os.O_WRONLY:
                return None
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return None
            except OSError:
                return None
            return ledger_state(fd)


        class StatProxy:
            def __init__(self, original, **changes):
                self._original = original
                self._changes = changes

            def __getattr__(self, name):
                if name in self._changes:
                    return self._changes[name]
                return getattr(self._original, name)


        def make_file(root, name, content, mode=0o600):
            path = os.path.join(root, name)
            with open(path, "wb") as stream:
                stream.write(content)
            os.chmod(path, mode)
            return path


        with tempfile.TemporaryDirectory(prefix="p11scope-stage1-") as fixture:
            repo_root = os.path.join(fixture, "repo")
            stable_root = os.path.join(fixture, "stable")
            nightly_root = os.path.join(fixture, "nightly")
            parent_root = os.path.join(fixture, "parent")
            for path in (repo_root, stable_root, nightly_root):
                os.mkdir(path, 0o755)
            os.mkdir(parent_root, 0o700)
            make_file(parent_root, "marker", b"parent-marker", 0o600)
            ledger_path = make_file(fixture, "ledger", os.environ["TASK4_GOLDEN"].encode("ascii"))
            ledger_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            ledger_fd = os.open(ledger_path, ledger_flags)
            parent_fd = os.open(parent_root, parent_flags)
            ledger_offset = os.lseek(ledger_fd, 11, os.SEEK_SET)
            parent_offset = os.lseek(parent_fd, 7, os.SEEK_CUR)
            if ledger_offset == 0 or parent_offset == 0 or ledger_offset == parent_offset:
                raise SystemExit("positive fixture offsets are not distinct nonzero values")
            if fcntl.fcntl(ledger_fd, fcntl.F_GETFL) & getattr(os, "O_PATH", 0):
                raise SystemExit("readable ledger fixture unexpectedly has O_PATH")
            if fcntl.fcntl(ledger_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                raise SystemExit("readable ledger fixture is not read-only")
            if fcntl.fcntl(parent_fd, fcntl.F_GETFL) & getattr(os, "O_PATH", 0):
                raise SystemExit("readable parent fixture unexpectedly has O_PATH")
            if fcntl.fcntl(parent_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                raise SystemExit("readable parent fixture is not read-only")
            if not fcntl.fcntl(parent_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
                raise SystemExit("readable parent fixture is not CLOEXEC")

            valid = dict(
                expected_ledger_fd=ledger_fd,
                repo_root=repo_root,
                vendor_relative="vendor",
                stable_sysroot_root=stable_root,
                nightly_sysroot_root=nightly_root,
                private_parent_fd=parent_fd,
            )
            roots = (repo_root, stable_root, nightly_root, parent_root)
            discover_calls = {"count": 0}
            real_discover = module.discover_input_v1

            def discover_bomb(*arguments, **arguments_by_name):
                discover_calls["count"] += 1
                raise SystemExit("discover_input_v1 must not be called by run_reconciled_build")

            def borrowed_offset(fd):
                try:
                    return os.lseek(fd, 0, os.SEEK_CUR)
                except OSError:
                    return None

            MISSING = object()

            deferred_full_a2 = []
            stage3_ready = False
            stage3_c0_state = None
            stage3_constants = frozenset(
                {
                    ("os", "O_RDONLY"),
                    ("os", "O_CLOEXEC"),
                    ("os", "O_NOFOLLOW"),
                    ("os", "O_DIRECTORY"),
                    ("os", "O_PATH"),
                    ("os", "O_ACCMODE"),
                    ("fcntl", "FD_CLOEXEC"),
                    ("fcntl", "F_GETFD"),
                    ("fcntl", "F_GETFL"),
                    ("resource", "RLIMIT_NOFILE"),
                }
            )
            stage3_callables = frozenset(
                {
                    ("os", "open"),
                    ("os", "stat"),
                    ("os", "listdir"),
                    ("os", "fstat"),
                    ("os", "pread"),
                    ("os", "close"),
                    ("os", "fsencode"),
                    ("os", "readlink"),
                    ("fcntl", "fcntl"),
                    ("resource", "getrlimit"),
                }
            )
            stage3_supports = frozenset(
                {
                    ("supports_dir_fd", "open"),
                    ("supports_dir_fd", "stat"),
                    ("supports_follow_symlinks", "stat"),
                    ("supports_fd", "listdir"),
                    ("supports_dir_fd", "readlink"),
                }
            )
            stage3_support_wrapper_targets = []

            def stage3_native_target(target):
                for wrapper, native in stage3_support_wrapper_targets:
                    if target is wrapper:
                        return native
                return target

            def stage3_maybe_inventory():
                state = stage3_c0_state
                required_constants = stage3_constants if state is None else state["required_constants"]
                required_callables = stage3_callables if state is None else state["required_callables"]
                required_supports = stage3_supports if state is None else state["required_supports"]
                values = {} if state is None else state["constant_values"]
                open_flag_names = ["O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY"]
                if ("os", "O_PATH") in required_constants:
                    open_flag_names.append("O_PATH")
                open_flags = [
                    values.get(("os", name))
                    for name in open_flag_names
                ]
                constants_valid = (
                    state is not None
                    and not state["inventory_closed"]
                    and all(type(value) is int for value in values.values())
                    and values.get(("os", "O_RDONLY")) == 0
                    and type(values.get(("os", "O_ACCMODE"))) is int
                    and values.get(("os", "O_ACCMODE"), 0) > 0
                    and all(type(value) is int and value > 0 for value in open_flags)
                    and all(
                        left & right == 0
                        for index, left in enumerate(open_flags)
                        for right in open_flags[index + 1 :]
                    )
                    and all(value & values[("os", "O_ACCMODE")] == 0 for value in open_flags)
                    and type(values.get(("fcntl", "FD_CLOEXEC"))) is int
                    and values.get(("fcntl", "FD_CLOEXEC"), 0) > 0
                    and type(values.get(("fcntl", "F_GETFD"))) is int
                    and values.get(("fcntl", "F_GETFD"), -1) >= 0
                    and type(values.get(("fcntl", "F_GETFL"))) is int
                    and values.get(("fcntl", "F_GETFL"), -1) >= 0
                    and values.get(("fcntl", "F_GETFD")) != values.get(("fcntl", "F_GETFL"))
                    and type(values.get(("resource", "RLIMIT_NOFILE"))) is int
                    and values.get(("resource", "RLIMIT_NOFILE"), -1) >= 0
                )
                if (
                    state is not None
                    and state["events"] == ["a2-complete"]
                    and set(state["constants"]) == required_constants
                    and set(state["callables"]) == required_callables
                    and set(state["supports"]) == required_supports
                    and all(count == 1 for count in state["constants"].values())
                    and all(count == 1 for count in state["callables"].values())
                    and all(count == 1 for count in state["supports"].values())
                    and state["inventory_valid"]
                    and constants_valid
                ):
                    state["events"].append("capability-inventory")

            def stage3_record(domain, item, value):
                state = stage3_c0_state
                if state is None or state["events"] != ["a2-complete"]:
                    return
                counts = state[domain]
                counts[item] = counts.get(item, 0) + 1
                if domain == "constants":
                    state["constant_values"][item] = value
                    state["inventory_valid"] &= type(value) is int
                elif domain == "callables":
                    state["inventory_valid"] &= callable(value)
                else:
                    state["inventory_valid"] &= value is True
                stage3_maybe_inventory()

            def stage3_case_is_continuation(case):
                return case is not None and (
                    case[0] == "missing-O_PATH-no-symlink-continue"
                    or case[0].startswith("continue-")
                )

            def stage3_case_is_a1(case):
                return case is not None and case[0].startswith("stage3a1-")

            def stage3_case_is_a2(case):
                return case is not None and case[0].startswith("stage3a2-")

            def stage3_case_is_a3(case):
                return case is not None and case[0].startswith("stage3a3-")

            def stage3_case_is_c0(case):
                return (
                    case is not None
                    and not stage3_case_is_a1(case)
                    and not stage3_case_is_a2(case)
                    and not stage3_case_is_a3(case)
                )

            def stage3_case_reaches_a2(case):
                return (
                    stage3_case_is_a2(case)
                    or stage3_case_is_a3(case)
                    or stage3_case_is_continuation(case)
                    or case is not None and case[0] == "stage3a1-gb-mutation"
                )

            def stage3_case_reaches_g1(case):
                return (
                    stage3_case_is_a1(case)
                    or stage3_case_is_a2(case)
                    or stage3_case_is_a3(case)
                    or stage3_case_is_continuation(case)
                )

            def stage3_a1_failure(case):
                return case is not None and case[0] == "stage3a1-failure"

            def stage3_a1_options(case):
                return case[-1] if case and isinstance(case[-1], dict) else {}

            def stage3_case_has_symlink(case):
                if case is None:
                    return True
                if stage3_case_is_a1(case) or stage3_case_is_a2(case) or stage3_case_is_a3(case):
                    return not stage3_a1_options(case).get("no_symlink", False)
                return case[5]

            def stage3_a1_failure_matches(case, edge_index, role, variant):
                if not stage3_a1_failure(case) or len(case) < 3:
                    return False
                site = case[1]
                return (site == role or site == f"edge-{edge_index}") and case[2] == variant

            def stage3_a1_injection(case, family, index):
                if (
                    family == "gb"
                    and index < len(stage3_a1_expected_bindings)
                    and stage3_a1_options(case).get("ki_token")
                    == stage3_a1_expected_bindings[index]
                ):
                    return "KeyboardInterrupt"
                if family == "gb" and stage3_a1_options(case).get("safe_failure") in {"GB", "GB-KI"} and index == 0:
                    return "error"
                if case is not None and case[0] == f"stage3a1-{family}-mutation" and case[1] == index:
                    return case[2]
                if (
                    family == "g1"
                    and case is not None
                    and case[0] == "stage3a1-g1-mutation"
                    and case[2] == "private-alias"
                    and len(case) > 4
                    and case[4] == index
                ):
                    return "private-alias-pre"
                if case is not None and case[0] == "stage3a1-lineage-mutation" and index in case[1:3]:
                    return ("lineage", case[3])
                return None

            def stage3_a1_fp_fault(case, token):
                options = stage3_a1_options(case)
                if options.get("fp_error") == token:
                    return "error"
                if options.get("fp_mismatch") == token:
                    return "mismatch"
                return None

            def stage3_a1_expected_fp_events(state):
                options = stage3_a1_options(state["stage3_case"])
                stop = (
                    options.get("fp_error")
                    or options.get("fp_mismatch")
                    or options.get("ki_token")
                )
                parent = stage3_a1_final_private[-3:]
                if stop in stage3_a1_final_private[:3]:
                    index = stage3_a1_final_private.index(stop)
                    return stage3_a1_final_private[: index + 1] + parent
                if stop in {"private-L-pread", "private-L-pread-attempt"}:
                    return (
                        *stage3_a1_final_private[:3],
                        "private-L-pread-attempt",
                        stage3_a1_final_private[4],
                        *parent,
                    )
                return stage3_a1_final_private

            def stage3_a1_maybe_interrupt(state, token):
                if stage3_a1_options(state["stage3_case"]).get("ki_token") != token:
                    return
                if state["a1_ki_attempted"] is not None:
                    raise SystemExit("stage3a1 KeyboardInterrupt injection retried")
                state["a1_ki_attempted"] = token
                raise KeyboardInterrupt()

            def stage3_a1_proxy_identity(value, structural):
                return StatProxy(
                    value,
                    **dict(
                        zip(
                            (
                                "st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                                "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
                            ),
                            structural,
                        )
                    ),
                )

            def stage3_a1_expected_token(state):
                if state["a1_phase"] != "g1":
                    return None
                events = state["expected_graph_events"]
                index = len(state["graph_events"])
                return events[index] if index < len(events) else None

            def stage3_a1_finish_body(state, outcome):
                if state["a1_phase"] != "g1":
                    return
                state["a1_body_outcome"] = outcome
                state["a1_phase"] = "cleanup" if outcome == "arbitrary" else "fp"

            def stage3_a1_c0_complete(state):
                return (
                    state["events"]
                    == ["a2-complete", "capability-inventory", "rlimit-baseline"]
                    and set(state["constants"]) == state["required_constants"]
                    and set(state["callables"]) == state["required_callables"]
                    and set(state["supports"]) == state["required_supports"]
                    and all(count == 1 for count in state["constants"].values())
                    and all(count == 1 for count in state["callables"].values())
                    and all(count == 1 for count in state["supports"].values())
                    and len(state["getrlimit"]) == 1
                )

            def stage3_a1_edge_for_prefix(state, prefix):
                for edge in state["graph_edges"]:
                    if edge[4] == prefix:
                        return edge
                return None

            def stage3_a1_fd_for_prefix(state, prefix):
                return state["graph_fds"].get(prefix)

            def stage3_a1_expected_binding_token(state):
                if state["a1_phase"] != "gb":
                    return None
                expected = [
                    token
                    for token in state["expected_graph_bindings"]
                    if token.split(":", 1)[1].encode("ascii") in state["graph_fds"]
                ]
                state["active_graph_bindings"] = expected
                index = len(state["graph_binding_events"])
                return expected[index] if index < len(expected) else None

            stage3_a1_final_private = (
                "private-L-getfl",
                "private-L-getfd",
                "private-L-fstat-pre",
                "private-L-pread-complete",
                "private-L-fstat-post",
                "private-P-getfl",
                "private-P-getfd",
                "private-P-fstat",
            )
            stage3_a1_final_borrowed = (
                "borrowed-L-getfl",
                "borrowed-L-fstat",
                "borrowed-P-getfl",
                "borrowed-P-getfd",
                "borrowed-P-fstat",
            )

            def record_final_borrowed_attempt(state, token):
                index = len(state["a1_final_borrowed_events"])
                expected = (
                    stage3_a1_final_borrowed[index]
                    if index < len(stage3_a1_final_borrowed)
                    else None
                )
                if token != expected:
                    raise SystemExit("stage3a1 final borrowed custody order drifted")
                state["a1_final_borrowed_events"].append(token)
                state["events"].append(token)
                try:
                    if token == "borrowed-P-fstat":
                        state["a1_suffix"].append("final-borrowed")
                        state["a1_phase"] = "gb"
                        safe_failure = stage3_a1_options(state["stage3_case"]).get("safe_failure")
                        if safe_failure in {"FB", "FB-KI"}:
                            state["a1_safe_failure_attempted"] = safe_failure
                            if safe_failure == "FB-KI":
                                raise KeyboardInterrupt()
                            raise OSError(errno.EIO, "stage3a1 final borrowed custody failed")
                        if stage3_a1_expected_binding_token(state) is None:
                            state["a1_suffix"].append("final-graph-bindings")
                            stage3_a3_after_gb(state)
                    stage3_a1_maybe_interrupt(state, token)
                except Exception:
                    raise
                except BaseException:
                    if state["a1_body_outcome"] != "governed":
                        state["a1_phase"] = "cleanup"
                    raise

            def stage3_a2_options(case):
                return case[-1] if case and isinstance(case[-1], dict) else {}

            def stage3_a2_fault(case):
                if case is None or case[0] != "stage3a2-fault":
                    return None, None
                return case[1], case[2]

            def stage3_a2_expectation(case):
                if (
                    case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "held-root-canonical-absence"
                ):
                    return stage3_a2_held_root_expected_operations, "success"
                return stage3_a2_case_expectations.get(
                    None if case is None or case[0] != "stage3a2-fault" else case[:3],
                    (stage3_a2_expected_operations, "success"),
                )

            def stage3_a2_expected_descriptor(state):
                if state["a1_phase"] != "a2":
                    return None
                index = len(state["a2_operations"])
                expected = state["a2_expected_operations"]
                return expected[index] if index < len(expected) else None

            def stage3_a2_regular_size(state, label):
                return stage3_a2_options(state["stage3_case"]).get(
                    "regular_size", stage3_a2_row_by_label[label][6]
                )

            def stage3_a2_role(state, value):
                if isinstance(value, tuple) and value[0] == "@held":
                    return state["graph_fds"][value[1]]
                if isinstance(value, tuple) and value[0] == "@evidence":
                    return state["a2_fds"][value[1]]
                return {
                    "@current": state["a2_current_fd"],
                    "@scan": state["a2_active_scan"],
                }.get(value, value)

            def stage3_a2_call_token(namespace, name, arguments, arguments_by_name):
                state = stage3_c0_state
                if state is None or not stage3_case_reaches_a2(state["stage3_case"]):
                    return None
                descriptor = stage3_a2_expected_descriptor(state)
                if descriptor is None:
                    return None
                token, expected_namespace, expected_name, positional, keywords = descriptor
                if namespace != expected_namespace or name != expected_name:
                    return None
                if token.startswith("regular-pread:"):
                    label = token.split(":", 1)[1]
                    expected_size = stage3_a2_regular_size(state, label)
                    remaining = expected_size - state["a2_regular_cursor"]
                    if (
                        len(arguments) != 3
                        or arguments[0] != state["a2_current_fd"]
                        or type(arguments[1]) is not int
                        or not 0 < arguments[1] <= min(1024 * 1024, remaining)
                        or arguments[2] != state["a2_regular_cursor"]
                        or arguments_by_name
                    ):
                        return None
                    return token
                expected_arguments = tuple(stage3_a2_role(state, value) for value in positional)
                expected_keywords = {
                    key: stage3_a2_role(state, value) for key, value in keywords
                }
                return token if arguments == expected_arguments and arguments_by_name == expected_keywords else None

            def stage3_a2_complete_operation(state):
                if len(state["a2_operations"]) != len(state["a2_expected_operations"]):
                    return
                outcome = state["a2_expected_outcome"]
                state["a1_body_outcome"] = outcome
                state["a1_phase"] = (
                    "fp"
                    if outcome == "success"
                    and stage3_case_composes_a3(state["stage3_case"])
                    and not state["a3_body_operations"]
                    else {"success": "fb", "governed": "fp", "arbitrary": "cleanup"}[outcome]
                )

            def stage3_a2_promote_binding(state, label):
                result = state["a2_current_fd"]
                if label == "external-root":
                    if result != state["graph_fds"].get(b"/"):
                        raise SystemExit("stage3a3 held root evidence reused the wrong descriptor")
                    state["a2_fds"][label] = result
                    state["a2_row_lineage"][label] = stage3_a2_held_root_rows[0][8]
                    return
                state["a2_fds"][label] = result
                if label != "external-parent":
                    state["a2_row_lineage"][label] = stage3_a2_row_by_label[label][8]
                key = b"@a2:" + label.encode("ascii")
                if label == "external-parent":
                    name = b"external"
                    parent_key = stage3_root_bytes
                else:
                    row = stage3_a2_row_by_label[label]
                    name = row[9]
                    parent_role = row[8]
                    parent_key = (
                        b"@a2:" + parent_role[1].encode("ascii")
                        if parent_role[0] == "@evidence"
                        else parent_role[1]
                    )
                state["graph_fds"][key] = result
                state["graph_edges"].append(("edge", "a2", name, parent_key, key, ""))
                state["expected_graph_bindings"].extend(
                    (
                        f"bind-held-fstat:{key.decode('ascii')}",
                        f"bind-parent-name-stat:{key.decode('ascii')}",
                    )
                )

            def stage3_a2_execute(callable_value, token, arguments, arguments_by_name):
                state = stage3_c0_state
                case = state["stage3_case"]
                fault_token, variant = stage3_a2_fault(case)
                operation = token.split(":", 1)[0]
                if operation != "regular-pread":
                    state["a2_operations"].append(token)
                injected = fault_token == token
                if operation.endswith("open"):
                    state["a2_open_snapshots"].append((token, tuple(state["graph_owned"])))
                if injected and operation.endswith("open"):
                    if variant == "return-True":
                        state["a2_rejected_returns"].append((True, False))
                        stage3_a2_complete_operation(state)
                        return True
                    if variant == "return-IntSubclass":
                        value = IntSubclass(0)
                        state["a2_rejected_returns"].append((value, False))
                        stage3_a2_complete_operation(state)
                        return value
                    if variant == "return-negative":
                        state["a2_rejected_returns"].append((-1, False))
                        stage3_a2_complete_operation(state)
                        return -1
                    collisions = {
                        "collision-borrowed-L": state["borrowed_ledger_fd"],
                        "collision-borrowed-P": state["borrowed_parent_fd"],
                        "collision-private-L": state["private_ledger_fd"],
                        "collision-private-P": state["private_parent_fd"],
                    }
                    if variant in collisions:
                        state["a2_rejected_returns"].append(
                            (collisions[variant], variant.startswith("collision-private-"))
                        )
                        stage3_a2_complete_operation(state)
                        return collisions[variant]
                    if variant.startswith("collision-owned-G"):
                        snapshot = state["a2_open_snapshots"][-1][1]
                        value = snapshot[int(variant.removeprefix("collision-owned-G"))]
                        state["a2_rejected_returns"].append((value, True))
                        stage3_a2_complete_operation(state)
                        return value
                    if variant == "reuse-closed-scan1":
                        closed = state["a2_scan_history"][0]
                        if closed in state["graph_owned"] or state["a2_active_scan"] is not None:
                            raise SystemExit("stage3a2 closed scan descriptor remained active")
                        value = callable_value(*arguments, **arguments_by_name)
                        if type(value) is not int or value != closed:
                            if type(value) is int and value >= 0:
                                real_close(value)
                            raise SystemExit("stage3a2 scan2 did not reuse the closed scan1 number")
                        result = value
                        injected = False
                    if variant.startswith("EIO"):
                        stage3_a2_complete_operation(state)
                        raise OSError(errno.EIO, "stage3a2 post-baseline open failed")
                    if variant == "ENFILE":
                        stage3_a2_complete_operation(state)
                        raise OSError(errno.ENFILE, "stage3a2 system file table exhausted")
                    if variant.startswith("EMFILE"):
                        state["a1_emfile"] = True
                        state["a1_emfile_pending"] = True
                        stage3_a2_complete_operation(state)
                        raise OSError(errno.EMFILE, "stage3a2 process file table exhausted")
                if injected and (variant == "error" or variant.startswith("KeyboardInterrupt")):
                    if operation == "regular-pread":
                        state["a2_operations"].append(token)
                    if variant.startswith("KeyboardInterrupt"):
                        state["a2_original_interrupt"] = token
                    stage3_a2_complete_operation(state)
                    if variant.startswith("KeyboardInterrupt"):
                        raise KeyboardInterrupt()
                    raise OSError(errno.EIO, "stage3a2 injected operation failure")
                if operation in {"scan1-close", "scan2-close"}:
                    fd = arguments[0]
                    entries = state["a2_entry_types"][state["a2_scan_start"] :]
                    encoded = b"".join(
                        {stat.S_IFREG: b"F", stat.S_IFDIR: b"D", stat.S_IFLNK: b"L"}.get(file_type, b"?")
                        + len(raw_name).to_bytes(2, "big")
                        + raw_name
                        for raw_name, file_type in sorted(entries)
                    )
                    state["a2_preimages"].append((token.split(":", 1)[1], encoded))
                    if fd in state["graph_owned"]:
                        state["graph_owned"].remove(fd)
                    state["a2_active_scan"] = None
                    result = callable_value(*arguments, **arguments_by_name)
                    state["a2_scan_closes"].append(token)
                    close_override = stage3_a2_options(case).get("scan_close_failure") == token
                    if injected and variant in {
                        "real-close-then-raise",
                        "real-close-then-KeyboardInterrupt",
                        "real-close-then-KeyboardInterrupt-outer-close",
                    } or close_override:
                        state["a2_close_uncertain"] = True
                        if state["a2_first_close_failure"] is None:
                            state["a2_first_close_failure"] = token
                        stage3_a2_complete_operation(state)
                        if "KeyboardInterrupt" in variant:
                            raise state["a2_scan_close_sentinel"]
                        raise OSError(errno.EIO, "stage3a2 scan close uncertainty")
                    try:
                        real_fstat(fd)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise SystemExit("stage3a2 scan close did not report EBADF") from exc
                    else:
                        raise SystemExit("stage3a2 scan descriptor leaked")
                    stage3_a2_complete_operation(state)
                    return result
                if not (variant == "reuse-closed-scan1" and fault_token == token):
                    result = callable_value(*arguments, **arguments_by_name)
                if injected and operation in {"parent-stat", "parent-fstat"}:
                    if variant == "wrong-kind":
                        result = StatProxy(result, st_mode=stat.S_IFREG | 0o600)
                    elif variant.startswith("identity-drift"):
                        result = StatProxy(result, st_ino=result.st_ino + 1)
                    elif variant == "private-alias":
                        result = stage3_a1_proxy_identity(result, state["private_parent_structural"])
                elif injected and operation.startswith(("regular-fstat", "directory-fstat")):
                    if variant == "wrong-kind":
                        result = StatProxy(result, st_mode=stat.S_IFIFO | 0o600)
                    elif variant.startswith("identity-drift"):
                        result = StatProxy(result, st_ino=result.st_ino + 1)
                        if variant == "identity-drift-GB":
                            state["a2_first_body_failure"] = token
                    elif variant == "mode-mismatch":
                        result = StatProxy(result, st_mode=(result.st_mode & ~0o777) | 0o644)
                    elif variant == "size-mismatch":
                        result = StatProxy(result, st_size=result.st_size + 1)
                    elif variant == "nlink-zero":
                        result = StatProxy(result, st_nlink=0)
                    elif variant == "oversize-before-read":
                        result = StatProxy(result, st_size=4_294_967_297)
                elif injected and operation.startswith("entry-stat") and variant == "special-type":
                    result = StatProxy(result, st_mode=stat.S_IFIFO | 0o600)
                elif injected and operation == "regular-pread":
                    if variant == "nonbytes":
                        result = "not-bytes"
                    elif variant == "empty":
                        result = b""
                    elif variant == "oversized-chunk":
                        result += b"x"
                    elif variant == "chunk-over-request-under-remaining":
                        result = b"x" * (arguments[1] + 1)
                    elif variant == "premature-eof":
                        attempts = state["a2_pread_attempts"].get(token, 0)
                        state["a2_pread_attempts"][token] = attempts + 1
                        result = result[:-1] if attempts == 0 else b""
                    elif variant == "bytes-mismatch":
                        result = bytes([result[0] ^ 1]) + result[1:] if result else b"x"
                elif injected and operation.startswith("list"):
                    if variant == "non-list":
                        result = None
                    elif variant == "raw-empty":
                        result = [""]
                    elif variant == "raw-dot":
                        result = ["."]
                    elif variant == "raw-dotdot":
                        result = [".."]
                    elif variant == "raw-nul":
                        result = ["nul\x00name"]
                    elif variant == "raw-slash":
                        result = ["a/b"]
                    elif variant == "raw-256":
                        result = ["x" * 256]
                    elif variant == "duplicate":
                        result = ["a", "a"]
                    elif variant == "entry-4097":
                        result = [f"e{index}" for index in range(4097)]
                    elif variant == "bytes-entry":
                        result = [b"blocker"]
                        state["a2_invalid_list_result"] = result
                    elif variant == "str-subclass-entry":
                        result = [StrSubclass("blocker")]
                        state["a2_invalid_list_result"] = result
                    elif variant == "cross-scan-drift":
                        state["a2_cross_scan"] = True
                elif operation.startswith("list"):
                    label = token.split(":", 1)[1]
                    expected_names = [entry[0] for entry in directory_entries[label]]
                    if sorted(result, key=os.fsencode) != sorted(expected_names, key=os.fsencode):
                        raise SystemExit("stage3a2 real directory fixture entries drifted")
                    if label == "repo-enum":
                        result = (
                            ["z", "raw-\udcff-name", "a"]
                            if operation == "list1"
                            else ["raw-\udcff-name", "a", "z"]
                        )
                    elif label == "external-root":
                        result = [entry[0] for entry in directory_entries[label]]
                    state["a2_list_results"].append((token, tuple(result)))
                if injected and operation.startswith("list") and variant == "cross-scan-drift":
                    label = token.split(":", 1)[1]
                    expected_names = [entry[0] for entry in directory_entries[label]]
                    if sorted(result, key=os.fsencode) != sorted(expected_names, key=os.fsencode):
                        raise SystemExit("stage3a2 cross-scan fixture entries drifted")
                    result = ["raw-\udcff-name", "a", "z"]
                    state["a2_list_results"].append((token, tuple(result)))
                if operation.endswith("open"):
                    forbidden = {
                        state["borrowed_ledger_fd"],
                        state["borrowed_parent_fd"],
                        state["private_ledger_fd"],
                        state["private_parent_fd"],
                        *state["a2_open_snapshots"][-1][1],
                    }
                    if type(result) is not int or result < 0 or (
                        variant != "reuse-closed-scan1" and result in forbidden
                    ):
                        raise SystemExit("stage3a2 native open returned an invalid or active descriptor")
                if operation.endswith("open"):
                    label = token.split(":", 1)[1]
                    if operation.startswith("scan"):
                        state["a2_active_scan"] = result
                        state["a2_scan_history"].append(result)
                        state["a2_scan_start"] = len(state["a2_entry_types"])
                    else:
                        state["a2_current_fd"] = result
                        if operation == "regular-open":
                            state["a2_regular_cursor"] = 0
                            state["a2_regular_chunks"] = []
                    if result not in state["graph_owned"]:
                        state["graph_owned"].append(result)
                if operation == "regular-pread":
                    if type(result) is bytes:
                        state["a2_regular_chunks"].append((arguments[2], arguments[1], result))
                        state["a2_regular_cursor"] += len(result)
                    expected_size = stage3_a2_regular_size(state, token.split(":", 1)[1])
                    invalid = (
                        type(result) is not bytes
                        or not result
                        or len(result) > arguments[1]
                        or state["a2_regular_cursor"] > expected_size
                    )
                    if invalid or state["a2_regular_cursor"] == expected_size:
                        state["a2_operations"].append(token)
                        if not invalid and state["a2_regular_cursor"] == expected_size:
                            state["a2_chunks_by_label"][token.split(":", 1)[1]] = tuple(
                                state["a2_regular_chunks"]
                            )
                            state["a2_regular_bytes"][token.split(":", 1)[1]] = b"".join(
                                chunk for _offset, _request, chunk in state["a2_regular_chunks"]
                            )
                if operation.startswith("fsencode"):
                    state["a2_fsencode_calls"].append((arguments[0], result))
                    state["a2_scan_raw"].append(result)
                if operation.startswith("entry-stat"):
                    raw_name = arguments[0]
                    file_type = stat.S_IFMT(result.st_mode)
                    if state["a2_cross_scan"] and operation == "entry-stat2" and raw_name == b"a":
                        file_type = stat.S_IFDIR
                        result = StatProxy(result, st_mode=stat.S_IFDIR | 0o700)
                    state["a2_entry_types"].append((raw_name, file_type))
                regular_size = stage3_a2_options(case).get("regular_size")
                if regular_size is not None and operation in {
                    "regular-fstat-pre",
                    "regular-fstat-post",
                }:
                    result = StatProxy(result, st_size=regular_size)
                    if operation == "regular-fstat-pre":
                        state["a2_row_stats"][token.split(":", 1)[1]] = result
                if token == "directory-fstat0:external-root":
                    state["a2_current_fd"] = state["graph_fds"].get(b"/")
                if stage3_a2_options(case).get("post_fstat_failure") == token:
                    if state["a2_first_body_failure"] is None:
                        state["a2_first_body_failure"] = token
                    stage3_a2_complete_operation(state)
                    if stage3_a2_options(case).get("post_fstat_interrupt"):
                        raise state["a2_post_fstat_sentinel"]
                    raise OSError(errno.EIO, "stage3a2 mandatory post-fstat sentinel")
                if operation in {"parent-fstat", "regular-fstat-pre", "directory-fstat0"} and not injected:
                    stage3_a2_promote_binding(state, token.split(":", 1)[1])
                if operation in {"regular-fstat-pre", "directory-fstat0"}:
                    state["a2_row_stats"][token.split(":", 1)[1]] = result
                stage3_a2_complete_operation(state)
                return result

            def stage3_a3_fault(case):
                if case is None or case[0] != "stage3a3-mutation":
                    return None, None
                return case[1], case[2]

            def stage3_a3_composition(case):
                if stage3_case_is_a3(case):
                    return stage3_a2_options(case)["spec"]
                if stage3_case_is_continuation(case):
                    return "no-symlink-ledger" if not stage3_case_has_symlink(case) else "relative-primary"
                if case is not None and (
                    case[0] == "stage3a1-gb-mutation"
                    or case[0] == "stage3a2-positive"
                    or case[:3] == ("stage3a2-fault", "scan2-open:repo-abs", "reuse-closed-scan1")
                ):
                    return "relative-primary"
                return None

            def stage3_case_composes_a3(case):
                return stage3_a3_composition(case) is not None

            def stage3_case_must_compose_a3(case):
                return case is not None and (
                    stage3_case_is_continuation(case)
                    or case[0] in {"stage3a1-gb-mutation", "stage3a2-positive"}
                    or case[:3]
                    == ("stage3a2-fault", "scan2-open:repo-abs", "reuse-closed-scan1")
                )

            def stage3_a3_spec(case):
                composition = stage3_a3_composition(case)
                if composition is None:
                    return (), ()
                return stage3_a3_specs[composition]

            def stage3_a3_role(state, value):
                if isinstance(value, tuple) and value[0] == "@a3":
                    return state["a3_fds"][value[1]]
                if value == "@read1":
                    return state["a3_readlinks"][-1][1]
                if value == "@read2":
                    return state["a3_readlinks"][-1][1]
                return stage3_a2_role(state, value)

            def stage3_a3_expected_descriptor(state):
                expected = (
                    state["a3_body_operations"]
                    if state["a1_phase"] in {"fb", "a3"}
                    else state["a3_absence_operations"]
                    if state["a1_phase"] == "absence"
                    else ()
                )
                index = (
                    len(state["a3_body_events"])
                    if state["a1_phase"] == "a3"
                    else len(state["a3_absence_events"])
                )
                return expected[index] if index < len(expected) else None

            def stage3_a3_call_token(namespace, name, arguments, arguments_by_name):
                state = stage3_c0_state
                if (
                    state is None
                    or not stage3_case_composes_a3(state["stage3_case"])
                    or len(state["a2_operations"]) != len(state["a2_expected_operations"])
                ):
                    return None
                descriptor = stage3_a3_expected_descriptor(state)
                if descriptor is None:
                    return None
                token, expected_namespace, expected_name, positional, keywords = descriptor
                if namespace != expected_namespace or name != expected_name:
                    return None
                expected_arguments = tuple(stage3_a3_role(state, value) for value in positional)
                expected_keywords = {key: stage3_a3_role(state, value) for key, value in keywords}
                return token if arguments == expected_arguments and arguments_by_name == expected_keywords else None

            def stage3_a3_governed(state, token):
                if state["a3_first_body_failure"] is None:
                    state["a3_first_body_failure"] = token
                state["a1_body_outcome"] = "governed"
                state["a1_phase"] = "fp"

            def stage3_a3_after_gb(state):
                if (
                    stage3_case_composes_a3(state["stage3_case"])
                    and (state["a3_started"] or not state["a3_body_operations"])
                    and not state["gb_failed"]
                    and state["a1_body_outcome"] != "governed"
                ):
                    if state["a3_absence_operations"]:
                        state["a1_phase"] = "post-gb"
                    else:
                        state["a3_markers"].append("canonical-absence-empty")
                        state["a3_forbid_later_filesystem"] = True
                        state["a1_phase"] = "cleanup"
                else:
                    state["a1_phase"] = "cleanup"

            def disjoint_root_missing_probe_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                next_descriptor = stage3_a3_expected_descriptor(state)
                return (
                    state["a1_phase"] == "a3"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "disjoint-symlink-roots"
                    and tuple(state["a3_body_events"]) == state["disjoint_first_root_tokens"]
                    and next_descriptor is not None
                    and next_descriptor[0] == "symlink-open:repo:/link-b:2"
                    and state["a1_body_outcome"] == "success"
                    and state["a3_first_body_failure"] is None
                    and not state["a1_emfile"]
                    and not state["gb_failed"]
                    and not state["disjoint_root_missing"]
                    and namespace == "fcntl"
                    and name == "fcntl"
                    and arguments
                    == (
                        state["private_ledger_fd"],
                        state["constant_values"][("fcntl", "F_GETFL")],
                    )
                    and not arguments_by_name
                )

            def reviewed_target_absence_fp_probe_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                return (
                    state["a1_phase"] == "post-gb"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "reviewed-symlink-target-absence"
                    and tuple(state["a3_body_events"]) == reviewed_target_absence_tokens
                    and tuple(state["a3_target_absence_errnos"])
                    == ((reviewed_target_absence_tokens[-1], errno.ENOENT),)
                    and not state["a3_absence_events"]
                    and state["a3_first_body_failure"] is None
                    and state["a1_body_outcome"] == "success"
                    and not state["a1_emfile"]
                    and not state["a1_emfile_pending"]
                    and not state["gb_failed"]
                    and state["a3_original_interrupt"] is None
                    and not state["reviewed_target_absence_fp_bridge"]
                    and namespace == "fcntl"
                    and name == "fcntl"
                    and arguments
                    == (
                        state["private_ledger_fd"],
                        state["constant_values"][("fcntl", "F_GETFL")],
                    )
                    and not arguments_by_name
                )

            def multi_component_absence_fp_probe_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                return (
                    state["a1_phase"] == "post-gb"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "multi-component-canonical-absence"
                    and tuple(state["a3_body_events"]) == multi_component_absence_tokens
                    and tuple(state["a3_target_absence_errnos"])
                    == ((multi_component_absence_tokens[-1], errno.ENOENT),)
                    and not state["a3_absence_events"]
                    and not state["a3_absence_errnos"]
                    and state["a3_first_body_failure"] is None
                    and state["a1_body_outcome"] == "success"
                    and not state["a1_emfile"]
                    and not state["a1_emfile_pending"]
                    and not state["gb_failed"]
                    and state["a3_original_interrupt"] is None
                    and state["a1_safe_failure_attempted"] is None
                    and state["a1_close_failure_attempted"] is None
                    and state["a3_close_failure"] is None
                    and not state["graph_close_calls"]
                    and not state["multi_component_absence_fp_bridge"]
                    and namespace == "fcntl"
                    and name == "fcntl"
                    and arguments
                    == (
                        state["private_ledger_fd"],
                        state["constant_values"][("fcntl", "F_GETFL")],
                    )
                    and not arguments_by_name
                )

            def multi_component_enotdir_fp_probe_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                return (
                    state["a1_phase"] == "post-gb"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "multi-component-canonical-enotdir"
                    and tuple(state["a3_body_events"]) == multi_component_enotdir_tokens
                    and tuple(state["a3_target_absence_errnos"])
                    == ((multi_component_enotdir_tokens[-1], errno.ENOTDIR),)
                    and not state["a3_absence_events"]
                    and not state["a3_absence_errnos"]
                    and state["a3_first_body_failure"] is None
                    and state["a1_body_outcome"] == "success"
                    and not state["a1_emfile"]
                    and not state["a1_emfile_pending"]
                    and not state["gb_failed"]
                    and state["a3_original_interrupt"] is None
                    and state["a1_safe_failure_attempted"] is None
                    and state["a1_close_failure_attempted"] is None
                    and state["a3_close_failure"] is None
                    and not state["graph_close_calls"]
                    and not state["multi_component_enotdir_fp_bridge"]
                    and namespace == "fcntl"
                    and name == "fcntl"
                    and arguments
                    == (
                        state["private_ledger_fd"],
                        state["constant_values"][("fcntl", "F_GETFL")],
                    )
                    and not arguments_by_name
                )

            def held_root_missing_probe_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                return (
                    state["a1_phase"] == "a3"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "held-root-canonical-absence"
                    and tuple(state["a3_body_events"]) == held_root_body_prefix_tokens
                    and not state["a3_target_absence_errnos"]
                    and not state["a3_absence_events"]
                    and not state["a3_absence_errnos"]
                    and state["a3_first_body_failure"] is None
                    and state["a1_body_outcome"] is None
                    and not state["a1_emfile"]
                    and not state["a1_emfile_pending"]
                    and not state["gb_failed"]
                    and state["a3_original_interrupt"] is None
                    and not state["held_root_missing"]
                    and not state["held_root_first_fp_bridge"]
                    and namespace == "os"
                    and name == "stat"
                    and arguments == (b"root-missing",)
                    and arguments_by_name
                    == {
                        "dir_fd": state["graph_fds"][b"/"],
                        "follow_symlinks": False,
                    }
                )

            def held_root_first_fp_bridge_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                return (
                    state["a1_phase"] == "a2"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "held-root-canonical-absence"
                    and state["graph_events"] == state["expected_graph_events"]
                    and state["held_root_open_redirects"] == ["open-root"]
                    and not state["a2_operations"]
                    and not state["a3_body_events"]
                    and not state["a3_absence_events"]
                    and not state["a3_target_absence_errnos"]
                    and not state["a3_absence_errnos"]
                    and not state["a1_final_private_events"]
                    and not state["a1_final_borrowed_events"]
                    and not state["graph_binding_events"]
                    and not state["graph_close_calls"]
                    and state["a1_body_outcome"] is None
                    and state["a2_first_body_failure"] is None
                    and state["a3_first_body_failure"] is None
                    and state["a1_safe_failure_attempted"] is None
                    and state["a1_close_failure_attempted"] is None
                    and state["a3_close_failure"] is None
                    and not state["a1_suffix"]
                    and not state["a1_emfile"]
                    and not state["a1_emfile_pending"]
                    and not state["gb_failed"]
                    and state["a3_original_interrupt"] is None
                    and not state["held_root_missing"]
                    and not state["held_root_first_fp_bridge"]
                    and namespace == "fcntl"
                    and name == "fcntl"
                    and arguments
                    == (
                        state["private_ledger_fd"],
                        state["constant_values"][("fcntl", "F_GETFL")],
                    )
                    and not arguments_by_name
                )

            def reviewed_target_absence_cleanup_probe_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                expected_bindings = tuple(
                    token
                    for token in state["expected_graph_bindings"]
                    if token.split(":", 1)[1].encode("ascii") in state["graph_fds"]
                )
                expected_closes = list(reversed(state["graph_owned"])) + [
                    state["private_parent_fd"], state["private_ledger_fd"]
                ]
                return (
                    state["a1_phase"] == "post-gb"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "reviewed-symlink-target-absence"
                    and tuple(state["a3_body_events"]) == reviewed_target_absence_tokens
                    and tuple(state["a3_target_absence_errnos"])
                    == ((reviewed_target_absence_tokens[-1], errno.ENOENT),)
                    and not state["a3_absence_events"]
                    and tuple(state["a1_final_private_events"]) == stage3_a1_final_private
                    and tuple(state["a1_final_borrowed_events"]) == stage3_a1_final_borrowed
                    and tuple(state["graph_binding_events"]) == expected_bindings
                    and not state["gb_failed"]
                    and state["a1_body_outcome"] == "success"
                    and not state["target_absence_missing"]
                    and not state["graph_close_calls"]
                    and expected_closes
                    and namespace == "os"
                    and name == "close"
                    and arguments == (expected_closes[0],)
                    and not arguments_by_name
                )

            def multi_component_absence_cleanup_probe_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                expected_bindings = tuple(
                    token
                    for token in state["expected_graph_bindings"]
                    if token.split(":", 1)[1].encode("ascii") in state["graph_fds"]
                )
                expected_closes = list(reversed(state["graph_owned"])) + [
                    state["private_parent_fd"], state["private_ledger_fd"]
                ]
                return (
                    state["a1_phase"] == "post-gb"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "multi-component-canonical-absence"
                    and tuple(state["a3_body_events"]) == multi_component_absence_tokens[:-1]
                    and not state["a3_target_absence_errnos"]
                    and not state["a3_absence_events"]
                    and not state["a3_absence_errnos"]
                    and tuple(state["a1_final_private_events"]) == stage3_a1_final_private
                    and tuple(state["a1_final_borrowed_events"]) == stage3_a1_final_borrowed
                    and tuple(state["graph_binding_events"]) == expected_bindings
                    and state["a3_first_body_failure"] is None
                    and state["a1_body_outcome"] == "success"
                    and not state["a1_emfile"]
                    and not state["a1_emfile_pending"]
                    and not state["gb_failed"]
                    and state["a3_original_interrupt"] is None
                    and state["a1_safe_failure_attempted"] is None
                    and state["a1_close_failure_attempted"] is None
                    and state["a3_close_failure"] is None
                    and not state["multi_component_absence_missing"]
                    and not state["multi_component_absence_fp_bridge"]
                    and not state["graph_close_calls"]
                    and expected_closes
                    and namespace == "os"
                    and name == "close"
                    and arguments == (expected_closes[0],)
                    and not arguments_by_name
                )

            def multi_component_enotdir_missing_probe_allowed(
                state, namespace, name, arguments, arguments_by_name
            ):
                case = state["stage3_case"]
                return (
                    state["a1_phase"] == "a3"
                    and case is not None
                    and case[0] == "stage3a3-case"
                    and case[1] == "multi-component-canonical-enotdir"
                    and tuple(state["a3_body_events"]) == multi_component_enotdir_tokens[:-1]
                    and not state["a3_target_absence_errnos"]
                    and not state["a3_absence_events"]
                    and not state["a3_absence_errnos"]
                    and state["a3_first_body_failure"] is None
                    and state["a1_body_outcome"] == "success"
                    and not state["a1_emfile"]
                    and not state["a1_emfile_pending"]
                    and not state["gb_failed"]
                    and state["a3_original_interrupt"] is None
                    and state["a1_safe_failure_attempted"] is None
                    and state["a1_close_failure_attempted"] is None
                    and state["a3_close_failure"] is None
                    and not state["multi_component_enotdir_missing"]
                    and not state["multi_component_enotdir_fp_bridge"]
                    and not state["a1_final_private_events"]
                    and not state["a1_final_borrowed_events"]
                    and not state["graph_binding_events"]
                    and not state["a1_suffix"]
                    and not state["graph_close_calls"]
                    and namespace == "fcntl"
                    and name == "fcntl"
                    and arguments
                    == (
                        state["private_ledger_fd"],
                        state["constant_values"][("fcntl", "F_GETFL")],
                    )
                    and not arguments_by_name
                )

            def check_reviewed_target_absence_probe_controls():
                terminal = reviewed_target_absence_tokens[-1]
                accepted = {
                    "a1_phase": "post-gb",
                    "stage3_case": (
                        "stage3a3-case", "reviewed-symlink-target-absence", {}
                    ),
                    "a3_body_events": list(reviewed_target_absence_tokens),
                    "a3_target_absence_errnos": [(terminal, errno.ENOENT)],
                    "a3_absence_events": [],
                    "a3_first_body_failure": None,
                    "a1_body_outcome": "success",
                    "a1_emfile": False,
                    "a1_emfile_pending": False,
                    "gb_failed": False,
                    "a3_original_interrupt": None,
                    "reviewed_target_absence_fp_bridge": False,
                    "private_ledger_fd": 42,
                    "constant_values": {("fcntl", "F_GETFL"): fcntl.F_GETFL},
                }
                accepted_call = ("fcntl", "fcntl", (42, fcntl.F_GETFL), {})
                if not reviewed_target_absence_fp_probe_allowed(accepted, *accepted_call):
                    raise SystemExit("stage3a3 reviewed absence positive probe was rejected")
                controls = [
                    ("partial body", {"a3_body_events": list(reviewed_target_absence_tokens[:-1])}),
                    ("changed body", {"a3_body_events": ["changed", *reviewed_target_absence_tokens[1:]]}),
                    ("extra body", {"a3_body_events": [*reviewed_target_absence_tokens, "extra"]}),
                    ("reordered body", {"a3_body_events": [reviewed_target_absence_tokens[1], reviewed_target_absence_tokens[0], *reviewed_target_absence_tokens[2:]]}),
                    ("wrong case", {"stage3_case": ("stage3a3-case", "relative-primary", {})}),
                    ("wrong phase", {"a1_phase": "fp"}),
                    ("absent errno observation", {"a3_target_absence_errnos": []}),
                    ("wrong errno observation", {"a3_target_absence_errnos": [(terminal, errno.ENOTDIR)]}),
                    ("duplicate errno observation", {"a3_target_absence_errnos": [(terminal, errno.ENOENT), (terminal, errno.ENOENT)]}),
                    ("successful errno observation", {"a3_target_absence_errnos": [(terminal, None)]}),
                    ("body failure", {"a3_first_body_failure": "body-failure"}),
                    ("capacity outcome", {"a1_body_outcome": "capacity", "a1_emfile": True}),
                    ("arbitrary outcome", {"a1_body_outcome": "arbitrary"}),
                    ("EMFILE", {"a1_emfile": True}),
                    ("GB failure", {"gb_failed": True}),
                    ("used bridge", {"reviewed_target_absence_fp_bridge": True}),
                    ("wrong namespace", {"namespace": "os"}),
                    ("wrong name", {"name": "open"}),
                    ("wrong fd", {"arguments": (43, fcntl.F_GETFL)}),
                    ("later FP token", {"arguments": (42, fcntl.F_GETFD)}),
                    ("wrong arity", {"arguments": (42, fcntl.F_GETFL, 0)}),
                    ("keywords", {"arguments_by_name": {"dir_fd": 42}}),
                    ("close", {"namespace": "os", "name": "close", "arguments": (42,)}),
                    ("graph stat", {"namespace": "os", "name": "stat", "arguments": (b"tmp",), "arguments_by_name": {"dir_fd": 42, "follow_symlinks": False}}),
                ]
                for label, overrides in controls:
                    trial = dict(accepted)
                    namespace, name, arguments, arguments_by_name = accepted_call
                    namespace = overrides.get("namespace", namespace)
                    name = overrides.get("name", name)
                    arguments = overrides.get("arguments", arguments)
                    arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                    trial.update(
                        {
                            key: value
                            for key, value in overrides.items()
                            if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                        }
                    )
                    if reviewed_target_absence_fp_probe_allowed(
                        trial, namespace, name, arguments, arguments_by_name
                    ):
                        raise SystemExit(
                            f"stage3a3 reviewed absence negative control accepted: {label}"
                        )

                cleanup_accepted = {
                    **accepted,
                    "a1_final_private_events": list(stage3_a1_final_private),
                    "a1_final_borrowed_events": list(stage3_a1_final_borrowed),
                    "graph_binding_events": [],
                    "expected_graph_bindings": [],
                    "graph_fds": {},
                    "graph_owned": [43],
                    "private_parent_fd": 41,
                    "graph_close_calls": [],
                    "target_absence_missing": False,
                }
                cleanup_call = ("os", "close", (43,), {})
                if not reviewed_target_absence_cleanup_probe_allowed(
                    cleanup_accepted, *cleanup_call
                ):
                    raise SystemExit("stage3a3 reviewed absence cleanup positive probe was rejected")
                cleanup_controls = [
                    ("incomplete FP", {"a1_final_private_events": []}),
                    ("incomplete FB", {"a1_final_borrowed_events": []}),
                    ("incomplete GB", {"graph_binding_events": ["unexpected"]}),
                    ("final absence", {"a3_absence_events": ["absent-terminal"]}),
                    ("wrong phase", {"a1_phase": "cleanup"}),
                    ("used flag", {"target_absence_missing": True}),
                    ("wrong first reverse-close FD", {"graph_owned": [44]}),
                    ("body failure", {"a1_body_outcome": "governed"}),
                    ("capacity outcome", {"a1_body_outcome": "capacity", "a1_emfile": True}),
                    ("GB failure", {"gb_failed": True}),
                    ("wrong namespace", {"namespace": "fcntl"}),
                    ("wrong name", {"name": "fstat"}),
                    ("wrong arity", {"arguments": (43, 0)}),
                    ("keywords", {"arguments_by_name": {"dir_fd": 43}}),
                ]
                for label, overrides in cleanup_controls:
                    trial = dict(cleanup_accepted)
                    namespace, name, arguments, arguments_by_name = cleanup_call
                    namespace = overrides.get("namespace", namespace)
                    name = overrides.get("name", name)
                    arguments = overrides.get("arguments", arguments)
                    arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                    trial.update(
                        {
                            key: value
                            for key, value in overrides.items()
                            if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                        }
                    )
                    if reviewed_target_absence_cleanup_probe_allowed(
                        trial, namespace, name, arguments, arguments_by_name
                    ):
                        raise SystemExit(
                            f"stage3a3 reviewed absence cleanup negative control accepted: {label}"
                        )

            def stage3_a3_execute(callable_value, token, arguments, arguments_by_name):
                state = stage3_c0_state
                case = state["stage3_case"]
                options = stage3_a2_options(case)
                if state["a1_phase"] == "fb":
                    state["a1_phase"] = "a3"
                fault_token, variant = stage3_a3_fault(case)
                injected = token == fault_token
                events = (
                    state["a3_body_events"]
                    if state["a1_phase"] == "a3"
                    else state["a3_absence_events"]
                )
                events.append(token)
                state["a3_started"] = True
                if token.startswith("absent-") and state["a3_absence_suffix_snapshot"] is None:
                    state["a3_absence_suffix_snapshot"] = (
                        tuple(state["a1_final_private_events"]),
                        tuple(state["a1_final_borrowed_events"]),
                        tuple(state["graph_binding_events"]),
                    )

                if token.startswith("readlink"):
                    state["a3_readlink_attempts"].append(token)
                    if token.startswith("readlink1:"):
                        occurrence = int(token.rsplit(":", 1)[1])
                        key = f"@a3:link:{occurrence}".encode("ascii")
                        parent_fd = arguments_by_name.get("dir_fd")
                        parent_keys = [
                            candidate
                            for candidate, fd in state["graph_fds"].items()
                            if fd == parent_fd
                        ]
                        if len(parent_keys) != 1 or key in state["graph_fds"]:
                            raise SystemExit("stage3a3 duplicate or unknown parent promotion")
                        state["graph_fds"][key] = state["a3_fds"][occurrence]
                        state["graph_edges"].append(
                            ("edge", "a3", os.fsencode(arguments[0]), parent_keys[0], key, "")
                        )
                        state["expected_graph_bindings"].extend(
                            (
                                f"bind-held-fstat:{key.decode('ascii')}",
                                f"bind-parent-name-stat:{key.decode('ascii')}",
                            )
                        )
                if token.startswith("target-fsencode"):
                    state["a3_fsencode_attempts"].append(token)

                if token.startswith("symlink-open:"):
                    occurrence = int(token.rsplit(":", 1)[1])
                    active = {
                        state["borrowed_ledger_fd"],
                        state["borrowed_parent_fd"],
                        state["private_ledger_fd"],
                        state["private_parent_fd"],
                        *state["graph_owned"],
                    }
                    state["a3_open_active"].append((token, tuple(sorted(active))))
                    if injected:
                        collisions = {
                            "collision-borrowed-L": state["borrowed_ledger_fd"],
                            "collision-borrowed-P": state["borrowed_parent_fd"],
                            "collision-private-L": state["private_ledger_fd"],
                            "collision-private-P": state["private_parent_fd"],
                            "collision-graph": state["graph_owned"][0],
                        }
                        if occurrence > 1:
                            collisions["collision-earlier-A3"] = state["a3_fds"][occurrence - 1]
                        if variant == "return-True":
                            stage3_a3_governed(state, token)
                            return True
                        if variant == "return-IntSubclass":
                            stage3_a3_governed(state, token)
                            return IntSubclass(0)
                        if variant == "return-negative":
                            stage3_a3_governed(state, token)
                            return -1
                        if variant in collisions:
                            stage3_a3_governed(state, token)
                            return collisions[variant]
                        if variant in {"EIO", "ENFILE", "EMFILE-rlimit-same", "EMFILE-rlimit-drift"}:
                            if variant.startswith("EMFILE"):
                                state["a1_emfile"] = True
                                state["a1_emfile_pending"] = True
                            stage3_a3_governed(state, token)
                            raise OSError(
                                errno.EMFILE if variant.startswith("EMFILE") else errno.ENFILE if variant == "ENFILE" else errno.EIO,
                                "stage3a3 injected symlink open failure",
                            )
                    result = callable_value(*arguments, **arguments_by_name)
                    if type(result) is not int or result < 0 or result in active:
                        stage3_a3_governed(state, token)
                        return result
                    state["a3_fds"][occurrence] = result
                    state["graph_owned"].append(result)
                    state["a3_owned_occurrences"].append(occurrence)
                    return result

                if injected and variant in {"error", "KeyboardInterrupt"}:
                    if state["a1_phase"] == "absence":
                        state["a1_phase"] = "cleanup"
                        state["a3_forbid_later_filesystem"] = True
                        if variant == "KeyboardInterrupt":
                            state["a3_original_interrupt"] = token
                            raise KeyboardInterrupt()
                        raise OSError(errno.EIO, "stage3a3 injected absence boundary failure")
                    state["a1_phase"] = "cleanup" if variant == "KeyboardInterrupt" else "fp"
                    if variant == "error":
                        stage3_a3_governed(state, token)
                        raise OSError(errno.EIO, "stage3a3 injected operation failure")
                    state["a3_original_interrupt"] = token
                    raise KeyboardInterrupt()

                if token.startswith("readlink"):
                    occurrence = int(token.rsplit(":", 1)[1])
                    native = options.get("raw_targets", {}).get(
                        occurrence, options.get("raw_target", b"./enum/../target")
                    )
                    state["a3_native_readlinks"].append((token, native))
                    result = native
                    if injected:
                        if variant == "bytes-subclass":
                            result = BytesSubclass(native)
                        elif variant == "str-subclass":
                            result = StrSubclass(native)
                        else:
                            result = {
                                "other-type": 1,
                                "empty": b"",
                                "4097-bytes": b"x" * 4097,
                                "mismatch": b"different",
                            }.get(variant, native)
                        if variant in {
                            "bytes-subclass", "str-subclass", "other-type", "empty",
                            "4097-bytes", "mismatch",
                        } and not (
                            token.startswith("readlink2:")
                            and variant in {"empty", "4097-bytes", "mismatch"}
                        ):
                            stage3_a3_governed(state, token)
                    state["a3_readlinks"].append((token, result))
                    return result

                if token.startswith("target-fsencode"):
                    if injected and variant == "error":
                        stage3_a3_governed(state, token)
                        raise OSError(errno.EIO, "stage3a3 fsencode failure")
                    result = callable_value(*arguments, **arguments_by_name)
                    if injected and variant == "nonbytes":
                        result = "not-bytes"
                        stage3_a3_governed(state, token)
                    state["a3_fsencode_calls"].append((arguments[0], result))
                    return result

                if token.startswith("target-absence-terminal:"):
                    try:
                        result = callable_value(*arguments, **arguments_by_name)
                    except OSError as exc:
                        state["a3_target_absence_errnos"].append((token, exc.errno))
                        if exc.errno == errno.ENOENT or (
                            case[0] == "stage3a3-case"
                            and case[1] == "multi-component-canonical-enotdir"
                            and exc.errno == errno.ENOTDIR
                        ):
                            state["a1_phase"] = (
                                "a3-complete"
                                if case[:2]
                                == ("stage3a3-case", "held-root-canonical-absence")
                                and exc.errno == errno.ENOENT
                                else "post-gb"
                            )
                        raise
                    return result

                if token.startswith("absent-terminal:"):
                    if injected and variant == "success":
                        state["a1_phase"] = "cleanup"
                        state["a3_forbid_later_filesystem"] = True
                        return os.stat_result((stat.S_IFREG | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                    if injected and variant == "KeyboardInterrupt":
                        state["a1_phase"] = "cleanup"
                        state["a3_forbid_later_filesystem"] = True
                        state["a3_original_interrupt"] = token
                        raise KeyboardInterrupt()
                    try:
                        callable_value(*arguments, **arguments_by_name)
                    except OSError as exc:
                        observed = errno.EIO if injected and variant == "wrong-errno" else exc.errno
                        state["a3_absence_errnos"].append((token, observed))
                        if injected and variant == "wrong-errno":
                            state["a1_phase"] = "cleanup"
                            state["a3_forbid_later_filesystem"] = True
                            raise OSError(errno.EIO, "stage3a3 wrong absence errno")
                        if len(events) == len(state["a3_absence_operations"]):
                            state["a3_absence_complete"] = True
                            state["a3_forbid_later_filesystem"] = True
                            state["a1_phase"] = "cleanup"
                        raise
                    raise SystemExit("stage3a3 canonical absence unexpectedly existed")

                result = callable_value(*arguments, **arguments_by_name)
                if injected and variant == "mismatch":
                    original = identity(result)
                    operations = (
                        state["a3_body_operations"]
                        if state["a1_phase"] == "a3"
                        else state["a3_absence_operations"]
                    )
                    next_token = operations[len(events)][0] if len(events) < len(operations) else None
                    defer_target_parent = (
                        token.startswith("target-parent-stat:")
                        and next_token == token.replace("parent-stat", "held-fstat")
                    )
                    defer_absence_parent = (
                        token.startswith("absent-boundary-parent:")
                        and next_token == token.replace("boundary-parent", "boundary-held")
                    )
                    if (
                        state["a1_phase"] == "a3"
                        and not token.startswith("symlink-held-fstat")
                        and not defer_target_parent
                    ):
                        stage3_a3_governed(state, token)
                    elif state["a1_phase"] == "absence" and not defer_absence_parent:
                        state["a1_phase"] = "cleanup"
                        state["a3_forbid_later_filesystem"] = True
                    result = StatProxy(result, st_ino=result.st_ino + 1)
                    state["a3_injections"].append((token, original, identity(result)))
                if token.startswith(("symlink-held-fstat", "symlink-parent-stat")):
                    state["a3_symlink_identities"].append((token, identity(result)))
                if (
                    variant == "mismatch"
                    and fault_token is not None
                    and fault_token.startswith("symlink-held-fstat")
                    and token == fault_token.replace("held-fstat", "parent-stat")
                ):
                    stage3_a3_governed(state, fault_token)
                if (
                    variant in {"empty", "4097-bytes", "mismatch"}
                    and fault_token is not None
                    and fault_token.startswith("readlink2:")
                    and token == f"symlink-parent-stat2:{fault_token.rsplit(':', 1)[1]}"
                ):
                    stage3_a3_governed(state, fault_token)
                if token.startswith(("target-held-fstat", "target-parent-stat")):
                    state["a3_target_identities"].append((token, identity(result)))
                if (
                    variant == "mismatch"
                    and fault_token is not None
                    and fault_token.startswith("target-parent-stat:")
                    and token == fault_token.replace("parent-stat", "held-fstat")
                ):
                    stage3_a3_governed(state, fault_token)
                if token.startswith("absent-") and not token.startswith("absent-terminal:"):
                    state["a3_boundary_identities"].append((token, identity(result)))
                if (
                    variant == "mismatch"
                    and fault_token is not None
                    and fault_token.startswith("absent-boundary-parent:")
                    and token == fault_token.replace("boundary-parent", "boundary-held")
                ):
                    state["a1_phase"] = "cleanup"
                    state["a3_forbid_later_filesystem"] = True
                if token.startswith("symlink-parent-stat0:"):
                    occurrence = int(token.rsplit(":", 1)[1])
                    if not injected and options.get("expected_route") == "follow41" and occurrence == 41:
                        state["a3_first_body_failure"] = token
                        state["a3_forbid_later_filesystem"] = True
                        state["a1_body_outcome"] = "governed"
                        state["a1_phase"] = "cleanup"
                if state["a1_phase"] == "a3" and len(events) == len(state["a3_body_operations"]):
                    state["a1_phase"] = "a3-complete"
                return result

            def stage3_a1_private_call_matches(namespace, name, arguments, arguments_by_name):
                state = stage3_c0_state
                if state is None or state["a1_phase"] != "fp":
                    return False
                index = len(state["a1_final_private_events"])
                expected = stage3_a1_expected_fp_events(state)
                if index >= len(expected):
                    return False
                token = expected[index]
                if token.startswith("private-L-"):
                    fd = state["private_ledger_fd"]
                else:
                    fd = state["private_parent_fd"]
                if not arguments or arguments[0] != fd:
                    return False
                if token.endswith("getfl") or token.endswith("getfd"):
                    command = stage3_custody_commands(state)[0 if token.endswith("getfl") else 1]
                    return namespace == "fcntl" and name == "fcntl" and arguments[1:] == (command,) and not arguments_by_name
                if "fstat" in token:
                    return namespace == "os" and name == "fstat" and len(arguments) == 1 and not arguments_by_name
                return token in {"private-L-pread-complete", "private-L-pread-attempt"} and (
                    namespace == "os"
                    and name == "pread"
                    and len(arguments) == 3
                    and type(arguments[1]) is int
                    and arguments[1] > 0
                    and arguments[2] == state["a1_private_pread_cursor"]
                    and state["a1_private_pread_cursor"] < len(state["a1_private_expected_bytes"])
                    and not arguments_by_name
                )

            def stage3_a1_graph_call_matches(namespace, name, arguments, arguments_by_name):
                state = stage3_c0_state
                case = None if state is None else state["stage3_case"]
                if (
                    state is None
                    or state["a2_complete"] != 1
                    or not stage3_case_reaches_g1(case)
                ):
                    return False
                if (
                    state["a1_phase"] == "cleanup"
                    and namespace == "os"
                    and name == "close"
                    and len(arguments) == 1
                    and not arguments_by_name
                ):
                    close_index = len(state["graph_close_calls"])
                    expected = list(reversed(state["graph_owned"]))
                    expected += [state["private_parent_fd"], state["private_ledger_fd"]]
                    return close_index < len(expected) and arguments[0] == expected[close_index]
                token = stage3_a1_expected_token(state)
                if token is None:
                    token = stage3_a1_expected_binding_token(state)
                    if token is None or state["a1_body_outcome"] == "arbitrary":
                        return False
                    operation, raw_prefix = token.split(":", 1)
                    prefix = raw_prefix.encode("ascii")
                    edge = stage3_a1_edge_for_prefix(state, prefix)
                    if edge is None:
                        return False
                    if operation == "bind-held-fstat":
                        return (
                            namespace == "os"
                            and name == "fstat"
                            and arguments == (stage3_a1_fd_for_prefix(state, prefix),)
                            and not arguments_by_name
                        )
                    return (
                        operation == "bind-parent-name-stat"
                        and namespace == "os"
                        and name == "stat"
                        and arguments == (edge[2],)
                        and arguments_by_name
                        == {
                            "dir_fd": stage3_a1_fd_for_prefix(state, edge[3]),
                            "follow_symlinks": False,
                        }
                    )
                if token == "anchor-lineages-exact":
                    return False
                if token == "open-root" or token.startswith("open-prefix:"):
                    if namespace != "os" or name != "open" or len(arguments) != 2:
                        return False
                    edge = (
                        state["graph_edges"][0]
                        if token == "open-root"
                        else stage3_a1_edge_for_prefix(
                            state, token.split(":", 1)[1].encode("ascii")
                        )
                    )
                    if edge is None or edge[0] == "cache":
                        return False
                    expected_parent = (
                        None if edge[3] is None else state["graph_fds"].get(edge[3])
                    )
                    expected_flags = (
                        state["constant_values"][("os", "O_RDONLY")]
                        | state["constant_values"][("os", "O_DIRECTORY")]
                        | state["constant_values"][("os", "O_CLOEXEC")]
                        | state["constant_values"][("os", "O_NOFOLLOW")]
                    )
                    return (
                        type(arguments[0]) is bytes
                        and arguments[0] == edge[2]
                        and arguments[1] == expected_flags
                        and arguments_by_name
                        == ({} if expected_parent is None else {"dir_fd": expected_parent})
                    )
                if token.startswith("edge-pre-stat:") or token.startswith("cache-binding-stat:"):
                    if namespace != "os" or name != "stat" or len(arguments) != 1:
                        return False
                    prefix = token.split(":", 1)[1].encode("ascii")
                    edge = stage3_a1_edge_for_prefix(state, prefix)
                    if edge is None:
                        return False
                    return (
                        arguments[0] == edge[2]
                        and arguments_by_name.get("dir_fd") == state["graph_fds"].get(edge[3])
                        and arguments_by_name.get("follow_symlinks") is False
                        and set(arguments_by_name) == {"dir_fd", "follow_symlinks"}
                    )
                if token.startswith("held-fstat:") or token.startswith("cache-held-fstat:"):
                    if namespace != "os" or name != "fstat" or len(arguments) != 1 or arguments_by_name:
                        return False
                    prefix = token.split(":", 1)[1].encode("ascii")
                    expected_fd = state.get("graph_pending_fd")
                    if expected_fd is not None:
                        expected_fd = expected_fd[1]
                    else:
                        expected_fd = stage3_a1_fd_for_prefix(state, prefix)
                    return arguments[0] == expected_fd
                return False

            def stage3_custody_commands(state):
                if "rlimit-baseline" not in state["events"]:
                    return fcntl.F_GETFL, fcntl.F_GETFD
                return (
                    state["constant_values"][("fcntl", "F_GETFL")],
                    state["constant_values"][("fcntl", "F_GETFD")],
                )

            def stage3_authorized_call(namespace, name, arguments, arguments_by_name):
                state = stage3_c0_state
                if state is None or state["a2_complete"] == 0:
                    return None
                if namespace == "resource" and name == "getrlimit":
                    if state["events"] == ["a2-complete", "capability-inventory"]:
                        return "resource-getrlimit"
                    if (
                        stage3_case_reaches_g1(state["stage3_case"])
                        and state["a1_emfile"]
                        and len(state["getrlimit"]) == 1
                        and arguments
                        == (state["constant_values"][("resource", "RLIMIT_NOFILE")],)
                        and not arguments_by_name
                    ):
                        return "resource-getrlimit-reread"
                    return None
                if (
                    stage3_case_reaches_a2(state["stage3_case"])
                    and state["a1_phase"] == "a2"
                    and namespace == "os"
                    and name == "fsencode"
                    and len(arguments) == 1
                    and not arguments_by_name
                ):
                    return "stage3a2-fsencode"
                if stage3_case_reaches_g1(state["stage3_case"]):
                    if state["a1_phase"] == "fb":
                        index = len(state["a1_final_borrowed_events"])
                        token = (
                            stage3_a1_final_borrowed[index]
                            if index < len(stage3_a1_final_borrowed)
                            else None
                        )
                        getfl, getfd = stage3_custody_commands(state)
                        expected = {
                            "borrowed-L-getfl": ("fcntl", "fcntl", state["borrowed_ledger_fd"], getfl),
                            "borrowed-L-fstat": ("os", "fstat", state["borrowed_ledger_fd"], None),
                            "borrowed-P-getfl": ("fcntl", "fcntl", state["borrowed_parent_fd"], getfl),
                            "borrowed-P-getfd": ("fcntl", "fcntl", state["borrowed_parent_fd"], getfd),
                            "borrowed-P-fstat": ("os", "fstat", state["borrowed_parent_fd"], None),
                        }.get(token)
                        if expected is not None:
                            expected_namespace, expected_name, expected_fd, expected_command = expected
                            if (
                                namespace == expected_namespace
                                and name == expected_name
                                and arguments[0] == expected_fd
                                and not arguments_by_name
                                and (
                                    expected_command is None
                                    and len(arguments) == 1
                                    or expected_command is not None
                                    and arguments[1:] == (expected_command,)
                                )
                            ):
                                return token
                    if state["a1_phase"] == "cleanup" and namespace == "os" and name == "close":
                        if arguments == (state["private_parent_fd"],) and not arguments_by_name:
                            return "close-P"
                        if arguments == (state["private_ledger_fd"],) and not arguments_by_name:
                            return "close-L"
                    return None
                if namespace == "fcntl" and name == "fcntl" and len(arguments) >= 2:
                    fd, command = arguments[:2]
                    getfl, getfd = stage3_custody_commands(state)
                    if fd == state["borrowed_ledger_fd"] and command == getfl and state["final_custody"] == 0:
                        return "borrowed-L-getfl"
                    if fd == state["borrowed_parent_fd"] and state["final_custody"] == 1:
                        if command == getfl:
                            return "borrowed-P-getfl"
                        if command == getfd:
                            return "borrowed-P-getfd"
                    return None
                if namespace == "os" and name == "fstat" and len(arguments) == 1 and not arguments_by_name:
                    if state["final_custody"] == 1:
                        if arguments[0] == state["borrowed_ledger_fd"]:
                            return "borrowed-L-fstat"
                        if arguments[0] == state["borrowed_parent_fd"]:
                            return "borrowed-P-fstat"
                    return None
                if namespace == "os" and name == "close" and len(arguments) == 1 and not arguments_by_name:
                    if state["final_custody"] == 1:
                        if arguments[0] == state["private_parent_fd"]:
                            return "close-P"
                        if arguments[0] == state["private_ledger_fd"]:
                            return "close-L"
                return None

            def check_multi_component_absence_fp_probe_controls():
                terminal = multi_component_absence_tokens[-1]
                accepted = {
                    "a1_phase": "post-gb",
                    "stage3_case": (
                        "stage3a3-case", "multi-component-canonical-absence", {}
                    ),
                    "a3_body_events": list(multi_component_absence_tokens),
                    "a3_target_absence_errnos": [(terminal, errno.ENOENT)],
                    "a3_absence_events": [],
                    "a3_absence_errnos": [],
                    "a3_first_body_failure": None,
                    "a1_body_outcome": "success",
                    "a1_emfile": False,
                    "a1_emfile_pending": False,
                    "gb_failed": False,
                    "a3_original_interrupt": None,
                    "a1_safe_failure_attempted": None,
                    "a1_close_failure_attempted": None,
                    "a3_close_failure": None,
                    "graph_close_calls": [],
                    "multi_component_absence_fp_bridge": False,
                    "private_ledger_fd": 42,
                    "constant_values": {("fcntl", "F_GETFL"): fcntl.F_GETFL},
                }
                accepted_call = ("fcntl", "fcntl", (42, fcntl.F_GETFL), {})
                if not multi_component_absence_fp_probe_allowed(accepted, *accepted_call):
                    raise SystemExit("stage3a3 multi-component absence FP positive probe was rejected")
                controls = [
                    ("wrong case", {"stage3_case": ("stage3a3-case", "relative-primary", {})}),
                    ("wrong phase", {"a1_phase": "fp"}),
                    ("partial body", {"a3_body_events": list(multi_component_absence_tokens[:-1])}),
                    ("changed body", {"a3_body_events": ["changed", *multi_component_absence_tokens[1:]]}),
                    ("reordered body", {"a3_body_events": [multi_component_absence_tokens[1], multi_component_absence_tokens[0], *multi_component_absence_tokens[2:]]}),
                    ("extra body", {"a3_body_events": [*multi_component_absence_tokens, "extra"]}),
                    ("missing immediate errno", {"a3_target_absence_errnos": []}),
                    ("wrong immediate errno", {"a3_target_absence_errnos": [(terminal, errno.ENOTDIR)]}),
                    ("duplicate immediate errno", {"a3_target_absence_errnos": [(terminal, errno.ENOENT), (terminal, errno.ENOENT)]}),
                    ("successful immediate errno", {"a3_target_absence_errnos": [(terminal, None)]}),
                    ("final absence event", {"a3_absence_events": ["absent-terminal"]}),
                    ("final absence errno", {"a3_absence_errnos": [("absent-terminal", errno.ENOENT)]}),
                    ("body failure", {"a3_first_body_failure": "body-failure"}),
                    ("governed outcome", {"a1_body_outcome": "governed"}),
                    ("capacity outcome", {"a1_body_outcome": "capacity", "a1_emfile": True}),
                    ("arbitrary outcome", {"a1_body_outcome": "arbitrary"}),
                    ("EMFILE", {"a1_emfile": True}),
                    ("EMFILE pending", {"a1_emfile_pending": True}),
                    ("GB failure", {"gb_failed": True}),
                    ("interrupt", {"a3_original_interrupt": "interrupt"}),
                    ("safe failure", {"a1_safe_failure_attempted": "FP"}),
                    ("A1 close failure", {"a1_close_failure_attempted": "close"}),
                    ("A3 close failure", {"a3_close_failure": "close"}),
                    ("used marker", {"multi_component_absence_fp_bridge": True}),
                    ("graph close", {"graph_close_calls": [43]}),
                    ("wrong namespace", {"namespace": "os"}),
                    ("wrong name", {"name": "fstat"}),
                    ("wrong fd", {"arguments": (43, fcntl.F_GETFL)}),
                    ("wrong command", {"arguments": (42, fcntl.F_GETFD)}),
                    ("wrong arity", {"arguments": (42, fcntl.F_GETFL, 0)}),
                    ("keywords", {"arguments_by_name": {"dir_fd": 42}}),
                    ("close", {"namespace": "os", "name": "close", "arguments": (42,)}),
                    ("graph stat", {"namespace": "os", "name": "stat", "arguments": (b"tmp",), "arguments_by_name": {"dir_fd": 42, "follow_symlinks": False}}),
                ]
                for label, overrides in controls:
                    trial = dict(accepted)
                    namespace, name, arguments, arguments_by_name = accepted_call
                    namespace = overrides.get("namespace", namespace)
                    name = overrides.get("name", name)
                    arguments = overrides.get("arguments", arguments)
                    arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                    trial.update(
                        {
                            key: value
                            for key, value in overrides.items()
                            if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                        }
                    )
                    if multi_component_absence_fp_probe_allowed(
                        trial, namespace, name, arguments, arguments_by_name
                    ):
                        raise SystemExit(
                            f"stage3a3 multi-component absence FP negative control accepted: {label}"
                        )

            def check_multi_component_absence_cleanup_probe_controls():
                accepted = {
                    "a1_phase": "post-gb",
                    "stage3_case": (
                        "stage3a3-case", "multi-component-canonical-absence", {}
                    ),
                    "a3_body_events": list(multi_component_absence_tokens[:-1]),
                    "a3_target_absence_errnos": [],
                    "a3_absence_events": [],
                    "a3_absence_errnos": [],
                    "a1_final_private_events": list(stage3_a1_final_private),
                    "a1_final_borrowed_events": list(stage3_a1_final_borrowed),
                    "graph_binding_events": [],
                    "expected_graph_bindings": [],
                    "graph_fds": {},
                    "graph_owned": [43],
                    "private_parent_fd": 41,
                    "private_ledger_fd": 42,
                    "a3_first_body_failure": None,
                    "a1_body_outcome": "success",
                    "a1_emfile": False,
                    "a1_emfile_pending": False,
                    "gb_failed": False,
                    "a3_original_interrupt": None,
                    "a1_safe_failure_attempted": None,
                    "a1_close_failure_attempted": None,
                    "a3_close_failure": None,
                    "multi_component_absence_missing": False,
                    "multi_component_absence_fp_bridge": False,
                    "graph_close_calls": [],
                }
                cleanup_call = ("os", "close", (43,), {})
                if not multi_component_absence_cleanup_probe_allowed(accepted, *cleanup_call):
                    raise SystemExit("stage3a3 multi-component absence cleanup positive probe was rejected")
                controls = [
                    ("wrong case", {"stage3_case": ("stage3a3-case", "relative-primary", {})}),
                    ("wrong phase", {"a1_phase": "fp"}),
                    ("partial body", {"a3_body_events": list(multi_component_absence_tokens[:-2])}),
                    ("changed body", {"a3_body_events": ["changed", *multi_component_absence_tokens[1:]]}),
                    ("reordered body", {"a3_body_events": [multi_component_absence_tokens[1], multi_component_absence_tokens[0], *multi_component_absence_tokens[2:]]}),
                    ("extra body", {"a3_body_events": [*multi_component_absence_tokens, "extra"]}),
                    ("fabricated full-suffix event", {"a3_body_events": list(multi_component_absence_tokens)}),
                    ("immediate errno", {"a3_target_absence_errnos": [(multi_component_absence_tokens[-1], errno.ENOENT)]}),
                    ("incomplete FP", {"a1_final_private_events": []}),
                    ("incomplete FB", {"a1_final_borrowed_events": []}),
                    ("incomplete GB", {"graph_binding_events": ["unexpected"]}),
                    ("absence event", {"a3_absence_events": ["absent-terminal"]}),
                    ("absence errno", {"a3_absence_errnos": [("absent-terminal", errno.ENOENT)]}),
                    ("body failure", {"a3_first_body_failure": "body-failure"}),
                    ("governed outcome", {"a1_body_outcome": "governed"}),
                    ("capacity outcome", {"a1_body_outcome": "capacity", "a1_emfile": True}),
                    ("arbitrary outcome", {"a1_body_outcome": "arbitrary"}),
                    ("EMFILE", {"a1_emfile": True}),
                    ("EMFILE pending", {"a1_emfile_pending": True}),
                    ("GB failure", {"gb_failed": True}),
                    ("interrupt", {"a3_original_interrupt": "interrupt"}),
                    ("safe failure", {"a1_safe_failure_attempted": "FP"}),
                    ("A1 close failure", {"a1_close_failure_attempted": "close"}),
                    ("A3 close failure", {"a3_close_failure": "close"}),
                    ("used FP bridge", {"multi_component_absence_fp_bridge": True}),
                    ("marker already set", {"multi_component_absence_missing": True}),
                    ("existing close", {"graph_close_calls": [43]}),
                    ("wrong fd", {"arguments": (44,)}),
                    ("wrong namespace", {"namespace": "fcntl"}),
                    ("wrong name", {"name": "fstat"}),
                    ("wrong arity", {"arguments": (43, 0)}),
                    ("keywords", {"arguments_by_name": {"dir_fd": 43}}),
                ]
                for label, overrides in controls:
                    trial = dict(accepted)
                    namespace, name, arguments, arguments_by_name = cleanup_call
                    namespace = overrides.get("namespace", namespace)
                    name = overrides.get("name", name)
                    arguments = overrides.get("arguments", arguments)
                    arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                    trial.update(
                        {
                            key: value
                            for key, value in overrides.items()
                            if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                        }
                    )
                    if multi_component_absence_cleanup_probe_allowed(
                        trial, namespace, name, arguments, arguments_by_name
                    ):
                        raise SystemExit(
                            f"stage3a3 multi-component absence cleanup negative control accepted: {label}"
                        )

                fallback_accepted = {
                    "label": "stage3a3-multi-component-canonical-absence",
                    "full_a2": True,
                    "state": {"multi_component_absence_missing": True},
                    "caught": module.MutationError("original"),
                }
                fallback_controls = [
                    ("wrong label", {"label": "stage3a3-reviewed-symlink-target-absence"}),
                    ("incomplete A2", {"full_a2": False}),
                    ("missing state", {"state": None}),
                    ("false marker", {"state": {"multi_component_absence_missing": False}}),
                    ("no exception", {"caught": None}),
                    ("SystemExit", {"caught": SystemExit(77)}),
                    ("another exception", {"caught": OSError(errno.EIO)}),
                ]
                class MutationErrorSubclass(module.MutationError):
                    pass
                fallback_controls.append(("MutationError subclass", {"caught": MutationErrorSubclass("subclass")}))
                fallback_trials = [("positive", {})] + fallback_controls
                for label, overrides in fallback_trials:
                    trial = dict(fallback_accepted)
                    trial.update(overrides)
                    state = trial["state"]
                    multi_component_absence_fallback = (
                        trial["label"] == "stage3a3-multi-component-canonical-absence"
                        and trial["full_a2"]
                        and state is not None
                        and state["multi_component_absence_missing"]
                        and type(trial["caught"]) is module.MutationError
                    )
                    if (label == "positive") != multi_component_absence_fallback:
                        raise SystemExit(
                            f"stage3a3 multi-component absence fallback control drifted: {label}"
                        )

            def check_multi_component_enotdir_probe_controls():
                terminal = multi_component_enotdir_tokens[-1]
                accepted = {
                    "a1_phase": "post-gb",
                    "stage3_case": (
                        "stage3a3-case", "multi-component-canonical-enotdir", {}
                    ),
                    "a3_body_events": list(multi_component_enotdir_tokens),
                    "a3_target_absence_errnos": [(terminal, errno.ENOTDIR)],
                    "a3_absence_events": [],
                    "a3_absence_errnos": [],
                    "a3_first_body_failure": None,
                    "a1_body_outcome": "success",
                    "a1_emfile": False,
                    "a1_emfile_pending": False,
                    "gb_failed": False,
                    "a3_original_interrupt": None,
                    "a1_safe_failure_attempted": None,
                    "a1_close_failure_attempted": None,
                    "a3_close_failure": None,
                    "graph_close_calls": [],
                    "multi_component_enotdir_fp_bridge": False,
                    "private_ledger_fd": 42,
                    "constant_values": {("fcntl", "F_GETFL"): fcntl.F_GETFL},
                }
                accepted_call = ("fcntl", "fcntl", (42, fcntl.F_GETFL), {})
                if not multi_component_enotdir_fp_probe_allowed(accepted, *accepted_call):
                    raise SystemExit("stage3a3 multi-component ENOTDIR FP positive probe was rejected")
                controls = [
                    ("wrong case", {"stage3_case": ("stage3a3-case", "relative-primary", {})}),
                    ("wrong phase", {"a1_phase": "fp"}),
                    ("partial body", {"a3_body_events": list(multi_component_enotdir_tokens[:-1])}),
                    ("changed body", {"a3_body_events": ["changed", *multi_component_enotdir_tokens[1:]]}),
                    ("reordered body", {"a3_body_events": [multi_component_enotdir_tokens[1], multi_component_enotdir_tokens[0], *multi_component_enotdir_tokens[2:]]}),
                    ("extra body", {"a3_body_events": [*multi_component_enotdir_tokens, "extra"]}),
                    ("missing immediate errno", {"a3_target_absence_errnos": []}),
                    ("wrong immediate errno", {"a3_target_absence_errnos": [(terminal, errno.ENOENT)]}),
                    ("duplicate immediate errno", {"a3_target_absence_errnos": [(terminal, errno.ENOTDIR), (terminal, errno.ENOTDIR)]}),
                    ("successful immediate errno", {"a3_target_absence_errnos": [(terminal, None)]}),
                    ("final absence event", {"a3_absence_events": ["absent-terminal"]}),
                    ("final absence errno", {"a3_absence_errnos": [("absent-terminal", errno.ENOTDIR)]}),
                    ("body failure", {"a3_first_body_failure": "body-failure"}),
                    ("governed outcome", {"a1_body_outcome": "governed"}),
                    ("capacity outcome", {"a1_body_outcome": "capacity", "a1_emfile": True}),
                    ("arbitrary outcome", {"a1_body_outcome": "arbitrary"}),
                    ("EMFILE", {"a1_emfile": True}),
                    ("EMFILE pending", {"a1_emfile_pending": True}),
                    ("GB failure", {"gb_failed": True}),
                    ("interrupt", {"a3_original_interrupt": "interrupt"}),
                    ("safe failure", {"a1_safe_failure_attempted": "FP"}),
                    ("A1 close failure", {"a1_close_failure_attempted": "close"}),
                    ("A3 close failure", {"a3_close_failure": "close"}),
                    ("used marker", {"multi_component_enotdir_fp_bridge": True}),
                    ("graph close", {"graph_close_calls": [43]}),
                    ("wrong namespace", {"namespace": "os"}),
                    ("wrong name", {"name": "fstat"}),
                    ("wrong fd", {"arguments": (43, fcntl.F_GETFL)}),
                    ("wrong command", {"arguments": (42, fcntl.F_GETFD)}),
                    ("wrong arity", {"arguments": (42, fcntl.F_GETFL, 0)}),
                    ("keywords", {"arguments_by_name": {"dir_fd": 42}}),
                    ("close", {"namespace": "os", "name": "close", "arguments": (42,)}),
                    ("graph stat", {"namespace": "os", "name": "stat", "arguments": (b"tmp",), "arguments_by_name": {"dir_fd": 42, "follow_symlinks": False}}),
                ]
                for label, overrides in controls:
                    trial = dict(accepted)
                    namespace, name, arguments, arguments_by_name = accepted_call
                    namespace = overrides.get("namespace", namespace)
                    name = overrides.get("name", name)
                    arguments = overrides.get("arguments", arguments)
                    arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                    trial.update(
                        {
                            key: value
                            for key, value in overrides.items()
                            if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                        }
                    )
                    if multi_component_enotdir_fp_probe_allowed(
                        trial, namespace, name, arguments, arguments_by_name
                    ):
                        raise SystemExit(
                            f"stage3a3 multi-component ENOTDIR FP negative control accepted: {label}"
                        )

            def check_multi_component_enotdir_missing_probe_controls():
                accepted = {
                    "a1_phase": "a3",
                    "stage3_case": (
                        "stage3a3-case", "multi-component-canonical-enotdir", {}
                    ),
                    "a3_body_events": list(multi_component_enotdir_tokens[:-1]),
                    "a3_target_absence_errnos": [],
                    "a3_absence_events": [],
                    "a3_absence_errnos": [],
                    "a1_final_private_events": [],
                    "a1_final_borrowed_events": [],
                    "graph_binding_events": [],
                    "expected_graph_bindings": [],
                    "graph_fds": {},
                    "graph_owned": [43],
                    "private_parent_fd": 41,
                    "private_ledger_fd": 42,
                    "constant_values": {("fcntl", "F_GETFL"): fcntl.F_GETFL},
                    "a3_first_body_failure": None,
                    "a1_body_outcome": "success",
                    "a1_emfile": False,
                    "a1_emfile_pending": False,
                    "gb_failed": False,
                    "a3_original_interrupt": None,
                    "a1_safe_failure_attempted": None,
                    "a1_close_failure_attempted": None,
                    "a3_close_failure": None,
                    "multi_component_enotdir_missing": False,
                    "multi_component_enotdir_fp_bridge": False,
                    "a1_suffix": [],
                    "graph_close_calls": [],
                }
                first_fp_call = ("fcntl", "fcntl", (42, fcntl.F_GETFL), {})
                if not multi_component_enotdir_missing_probe_allowed(accepted, *first_fp_call):
                    raise SystemExit("stage3a3 multi-component ENOTDIR first-FP positive probe was rejected")
                controls = [
                    ("wrong case", {"stage3_case": ("stage3a3-case", "relative-primary", {})}),
                    ("wrong phase", {"a1_phase": "fp"}),
                    ("partial body", {"a3_body_events": list(multi_component_enotdir_tokens[:-2])}),
                    ("changed body", {"a3_body_events": ["changed", *multi_component_enotdir_tokens[1:-1]]}),
                    ("reordered body", {"a3_body_events": [multi_component_enotdir_tokens[1], multi_component_enotdir_tokens[0], *multi_component_enotdir_tokens[2:-1]]}),
                    ("extra body", {"a3_body_events": [*multi_component_enotdir_tokens, "extra"]}),
                    ("fabricated full-suffix event", {"a3_body_events": list(multi_component_enotdir_tokens)}),
                    ("immediate errno", {"a3_target_absence_errnos": [(multi_component_enotdir_tokens[-1], errno.ENOTDIR)]}),
                    ("pre-existing FP", {"a1_final_private_events": list(stage3_a1_final_private)}),
                    ("pre-existing FB", {"a1_final_borrowed_events": list(stage3_a1_final_borrowed)}),
                    ("incomplete GB", {"graph_binding_events": ["unexpected"]}),
                    ("absence event", {"a3_absence_events": ["absent-terminal"]}),
                    ("absence errno", {"a3_absence_errnos": [("absent-terminal", errno.ENOTDIR)]}),
                    ("body failure", {"a3_first_body_failure": "body-failure"}),
                    ("governed outcome", {"a1_body_outcome": "governed"}),
                    ("capacity outcome", {"a1_body_outcome": "capacity", "a1_emfile": True}),
                    ("arbitrary outcome", {"a1_body_outcome": "arbitrary"}),
                    ("EMFILE", {"a1_emfile": True}),
                    ("EMFILE pending", {"a1_emfile_pending": True}),
                    ("GB failure", {"gb_failed": True}),
                    ("interrupt", {"a3_original_interrupt": "interrupt"}),
                    ("safe failure", {"a1_safe_failure_attempted": "FP"}),
                    ("A1 close failure", {"a1_close_failure_attempted": "close"}),
                    ("A3 close failure", {"a3_close_failure": "close"}),
                    ("used FP bridge", {"multi_component_enotdir_fp_bridge": True}),
                    ("marker already set", {"multi_component_enotdir_missing": True}),
                    ("existing close", {"graph_close_calls": [43]}),
                    ("existing suffix", {"a1_suffix": ["final-private"]}),
                    ("wrong fd", {"arguments": (44, fcntl.F_GETFL)}),
                    ("wrong namespace", {"namespace": "os"}),
                    ("wrong name", {"name": "fstat"}),
                    ("wrong arity", {"arguments": (42, fcntl.F_GETFL, 0)}),
                    ("keywords", {"arguments_by_name": {"dir_fd": 42}}),
                    ("close", {"namespace": "os", "name": "close", "arguments": (43,)}),
                ]
                for label, overrides in controls:
                    trial = dict(accepted)
                    namespace, name, arguments, arguments_by_name = first_fp_call
                    namespace = overrides.get("namespace", namespace)
                    name = overrides.get("name", name)
                    arguments = overrides.get("arguments", arguments)
                    arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                    trial.update(
                        {
                            key: value
                            for key, value in overrides.items()
                            if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                        }
                    )
                    if multi_component_enotdir_missing_probe_allowed(
                        trial, namespace, name, arguments, arguments_by_name
                    ):
                        raise SystemExit(
                            f"stage3a3 multi-component ENOTDIR first-FP negative control accepted: {label}"
                        )

                fallback_accepted = {
                    "label": "stage3a3-multi-component-canonical-enotdir",
                    "full_a2": True,
                    "state": {"multi_component_enotdir_missing": True},
                    "caught": module.MutationError("original"),
                }
                fallback_controls = [
                    ("wrong label", {"label": "stage3a3-multi-component-canonical-absence"}),
                    ("incomplete A2", {"full_a2": False}),
                    ("missing state", {"state": None}),
                    ("false marker", {"state": {"multi_component_enotdir_missing": False}}),
                    ("no exception", {"caught": None}),
                    ("SystemExit", {"caught": SystemExit(77)}),
                    ("another exception", {"caught": OSError(errno.EIO)}),
                ]
                class MutationErrorSubclass(module.MutationError):
                    pass
                fallback_controls.append(("MutationError subclass", {"caught": MutationErrorSubclass("subclass")}))
                fallback_trials = [("positive", {})] + fallback_controls
                for label, overrides in fallback_trials:
                    trial = dict(fallback_accepted)
                    trial.update(overrides)
                    state = trial["state"]
                    fallback = (
                        trial["label"] == "stage3a3-multi-component-canonical-enotdir"
                        and trial["full_a2"]
                        and state is not None
                        and state["multi_component_enotdir_missing"]
                        and type(trial["caught"]) is module.MutationError
                    )
                    if (label == "positive") != fallback:
                        raise SystemExit(
                            f"stage3a3 multi-component ENOTDIR fallback control drifted: {label}"
                        )

            def check_held_root_missing_probe_controls():
                accepted = {
                    "a1_phase": "a3",
                    "stage3_case": (
                        "stage3a3-case", "held-root-canonical-absence", {}
                    ),
                    "a3_body_events": list(held_root_body_prefix_tokens),
                    "a3_target_absence_errnos": [],
                    "a3_absence_events": [],
                    "a3_absence_errnos": [],
                    "a3_first_body_failure": None,
                    "a1_body_outcome": None,
                    "a1_emfile": False,
                    "a1_emfile_pending": False,
                    "gb_failed": False,
                    "a3_original_interrupt": None,
                    "held_root_missing": False,
                    "held_root_first_fp_bridge": False,
                    "graph_fds": {b"/": 42},
                }
                accepted_call = (
                    "os", "stat", (b"root-missing",),
                    {"dir_fd": 42, "follow_symlinks": False},
                )
                if not held_root_missing_probe_allowed(accepted, *accepted_call):
                    raise SystemExit("stage3a3 held root missing positive probe was rejected")
                controls = [
                    ("wrong case", {"stage3_case": ("stage3a3-case", "relative-primary", {})}),
                    ("wrong phase", {"a1_phase": "fp"}),
                    ("partial body", {"a3_body_events": list(held_root_body_prefix_tokens[:-1])}),
                    ("changed body", {"a3_body_events": ["changed", *held_root_body_prefix_tokens[1:]]}),
                    ("extra body", {"a3_body_events": [*held_root_body_prefix_tokens, "extra"]}),
                    ("immediate errno", {"a3_target_absence_errnos": [("immediate", errno.ENOENT)]}),
                    ("final absence", {"a3_absence_events": ["absent-terminal"]}),
                    ("body failure", {"a3_first_body_failure": "body-failure"}),
                    ("clean outcome", {"a1_body_outcome": "success"}),
                    ("EMFILE", {"a1_emfile": True}),
                    ("EMFILE pending", {"a1_emfile_pending": True}),
                    ("GB failure", {"gb_failed": True}),
                    ("interrupt", {"a3_original_interrupt": "interrupt"}),
                    ("used marker", {"held_root_missing": True}),
                    ("used bridge", {"held_root_first_fp_bridge": True}),
                    ("wrong root fd", {"graph_fds": {b"/": 43}}),
                    ("wrong namespace", {"namespace": "fcntl"}),
                    ("wrong name", {"name": "open"}),
                    ("wrong path", {"arguments": (b"root-missing/leaf",)}),
                    ("wrong follow", {"arguments_by_name": {"dir_fd": 42, "follow_symlinks": True}}),
                    ("wrong arity", {"arguments": (b"root-missing", 0)}),
                    ("keywords", {"arguments_by_name": {"dir_fd": 42}}),
                ]
                for label, overrides in controls:
                    trial = dict(accepted)
                    namespace, name, arguments, arguments_by_name = accepted_call
                    namespace = overrides.get("namespace", namespace)
                    name = overrides.get("name", name)
                    arguments = overrides.get("arguments", arguments)
                    arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                    trial.update(
                        {
                            key: value
                            for key, value in overrides.items()
                            if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                        }
                    )
                    if held_root_missing_probe_allowed(
                        trial, namespace, name, arguments, arguments_by_name
                    ):
                        raise SystemExit(
                            f"stage3a3 held root missing negative control accepted: {label}"
                        )

            def check_held_root_first_fp_bridge_controls():
                accepted = {
                    "a1_phase": "a2",
                    "stage3_case": (
                        "stage3a3-case", "held-root-canonical-absence", {}
                    ),
                    "graph_events": list(held_root_expected_g1),
                    "expected_graph_events": list(held_root_expected_g1),
                    "held_root_open_redirects": ["open-root"],
                    "a2_operations": [],
                    "a3_body_events": [],
                    "a3_absence_events": [],
                    "a3_target_absence_errnos": [],
                    "a3_absence_errnos": [],
                    "a1_final_private_events": [],
                    "a1_final_borrowed_events": [],
                    "graph_binding_events": [],
                    "graph_close_calls": [],
                    "a1_body_outcome": None,
                    "a2_first_body_failure": None,
                    "a3_first_body_failure": None,
                    "a1_safe_failure_attempted": None,
                    "a1_close_failure_attempted": None,
                    "a3_close_failure": None,
                    "a1_suffix": [],
                    "a1_emfile": False,
                    "a1_emfile_pending": False,
                    "gb_failed": False,
                    "a3_original_interrupt": None,
                    "held_root_missing": False,
                    "held_root_first_fp_bridge": False,
                    "private_ledger_fd": 42,
                    "constant_values": {("fcntl", "F_GETFL"): fcntl.F_GETFL},
                }
                accepted_call = ("fcntl", "fcntl", (42, fcntl.F_GETFL), {})
                if not held_root_first_fp_bridge_allowed(accepted, *accepted_call):
                    raise SystemExit("stage3a3 held root first-FP positive bridge was rejected")
                controls = [
                    ("wrong case", {"stage3_case": ("stage3a3-case", "relative-primary", {})}),
                    ("wrong phase", {"a1_phase": "fp"}),
                    ("incomplete G1", {"graph_events": list(held_root_expected_g1[:-1])}),
                    ("missing sentinel", {"held_root_open_redirects": []}),
                    ("duplicate sentinel", {"held_root_open_redirects": ["open-root", "open-root"]}),
                    ("A2 event", {"a2_operations": ["unexpected"]}),
                    ("A3 event", {"a3_body_events": ["unexpected"]}),
                    ("final absence", {"a3_absence_events": ["unexpected"]}),
                    ("FP event", {"a1_final_private_events": ["unexpected"]}),
                    ("FB event", {"a1_final_borrowed_events": ["unexpected"]}),
                    ("GB event", {"graph_binding_events": ["unexpected"]}),
                    ("close event", {"graph_close_calls": [43]}),
                    ("body failure", {"a1_body_outcome": "governed"}),
                    ("A2 failure", {"a2_first_body_failure": "failure"}),
                    ("A3 failure", {"a3_first_body_failure": "failure"}),
                    ("safe failure", {"a1_safe_failure_attempted": "FP"}),
                    ("A1 close failure", {"a1_close_failure_attempted": "close"}),
                    ("A3 close failure", {"a3_close_failure": "close"}),
                    ("existing suffix", {"a1_suffix": ["final-private"]}),
                    ("EMFILE", {"a1_emfile": True}),
                    ("EMFILE pending", {"a1_emfile_pending": True}),
                    ("GB failure", {"gb_failed": True}),
                    ("interrupt", {"a3_original_interrupt": "interrupt"}),
                    ("used marker", {"held_root_first_fp_bridge": True}),
                    ("missing probe", {"held_root_missing": True}),
                    ("wrong fd", {"private_ledger_fd": 43}),
                    ("wrong namespace", {"namespace": "os"}),
                    ("wrong name", {"name": "fstat"}),
                    ("wrong command", {"arguments": (42, fcntl.F_GETFD)}),
                    ("wrong arity", {"arguments": (42, fcntl.F_GETFL, 0)}),
                    ("keywords", {"arguments_by_name": {"dir_fd": 42}}),
                ]
                for label, overrides in controls:
                    trial = dict(accepted)
                    namespace, name, arguments, arguments_by_name = accepted_call
                    namespace = overrides.get("namespace", namespace)
                    name = overrides.get("name", name)
                    arguments = overrides.get("arguments", arguments)
                    arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                    trial.update(
                        {
                            key: value
                            for key, value in overrides.items()
                            if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                        }
                    )
                    if held_root_first_fp_bridge_allowed(
                        trial, namespace, name, arguments, arguments_by_name
                    ):
                        raise SystemExit(
                            f"stage3a3 held root first-FP negative control accepted: {label}"
                        )

            class Stage3Callable:
                def __init__(self, namespace, name, target):
                    self.namespace = namespace
                    self.name = name
                    self.target = target

                def __call__(self, *arguments, **arguments_by_name):
                    state = stage3_c0_state
                    if state is not None and state.get("a1_emfile_pending") and not (
                        self.namespace == "resource"
                        and self.name == "getrlimit"
                        and arguments
                        == (state["constant_values"][("resource", "RLIMIT_NOFILE")],)
                        and not arguments_by_name
                    ):
                        raise SystemExit("stage3a1 EMFILE RLIMIT reread was not immediate")
                    if (
                        state is not None
                        and state.get("a3_forbid_later_filesystem")
                        and self.namespace == "os"
                        and self.name != "close"
                    ):
                        raise SystemExit("stage3a3 filesystem call followed terminal absence failure")
                    if (
                        state is not None
                        and state["a2_complete"] == 1
                        and stage3_case_reaches_g1(state["stage3_case"])
                        and state["a1_phase"] == "c0"
                        and self.namespace == "os"
                        and self.name == "open"
                        and not stage3_a1_c0_complete(state)
                    ):
                        raise SystemExit("stage3a1 C0 inventory drifted")
                    if (
                        state is not None
                        and state["a2_complete"] == 1
                        and stage3_case_reaches_g1(state["stage3_case"])
                        and state["a1_phase"] == "c0"
                        and self.namespace == "os"
                        and self.name == "open"
                        and stage3_a1_c0_complete(state)
                    ):
                        state["events"].append("capacity-policy-selected")
                        state["a1_phase"] = "g1"
                    if state is not None and disjoint_root_missing_probe_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["disjoint_root_missing"] = True
                        state["a1_phase"] = "a3-complete"
                    if state is not None and reviewed_target_absence_fp_probe_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["reviewed_target_absence_fp_bridge"] = True
                        state["a1_phase"] = "fp"
                    if state is not None and reviewed_target_absence_cleanup_probe_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["target_absence_missing"] = True
                        state["a1_phase"] = "cleanup"
                    if state is not None and multi_component_absence_cleanup_probe_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["multi_component_absence_missing"] = True
                        state["a1_phase"] = "cleanup"
                    if state is not None and multi_component_enotdir_missing_probe_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["multi_component_enotdir_missing"] = True
                        state["a1_phase"] = "fp"
                    if state is not None and multi_component_absence_fp_probe_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["multi_component_absence_fp_bridge"] = True
                        state["a1_phase"] = "fp"
                    if state is not None and multi_component_enotdir_fp_probe_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["multi_component_enotdir_fp_bridge"] = True
                        state["a1_phase"] = "fp"
                    if state is not None and held_root_missing_probe_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["held_root_missing"] = True
                        try:
                            return self.target(*arguments, **arguments_by_name)
                        finally:
                            state["a1_phase"] = "a2"
                    if state is not None and held_root_first_fp_bridge_allowed(
                        state, self.namespace, self.name, arguments, arguments_by_name
                    ):
                        state["held_root_missing"] = True
                        state["held_root_first_fp_bridge"] = True
                        state["a1_phase"] = "fp"
                    if state is not None and state.get("a1_phase") == "a3-complete":
                        state["a1_phase"] = "fp"
                        if not stage3_a1_private_call_matches(
                            self.namespace, self.name, arguments, arguments_by_name
                        ):
                            state["a1_phase"] = "a3-complete"
                            if self.namespace == "os" and self.name == "close":
                                state["a1_phase"] = "cleanup"
                    if state is not None and state.get("a1_phase") == "post-gb":
                        state["a1_phase"] = "absence"
                        if stage3_a3_call_token(
                            self.namespace, self.name, arguments, arguments_by_name
                        ) is None:
                            state["a1_phase"] = "post-gb"
                            if self.namespace == "os" and self.name == "close":
                                state["a1_phase"] = "cleanup"
                    if (
                        state is not None
                        and state["stage3_case"] is not None
                        and state["stage3_case"][0] == "stage3a3-case"
                        and state["stage3_case"][1] == "multi-component-canonical-absence"
                        and state["a1_phase"] == "a3"
                        and tuple(state["a3_body_events"]) == multi_component_absence_tokens[:-1]
                        and self.namespace == "os"
                        and self.name == "stat"
                        and arguments == (b"a-missing",)
                        and arguments_by_name
                        == {
                            "dir_fd": state["a2_fds"]["repo-abs"],
                            "follow_symlinks": False,
                        }
                    ):
                        try:
                            return self.target(*arguments, **arguments_by_name)
                        finally:
                            state["a1_phase"] = "fp"
                    a1_graph_call = stage3_a1_graph_call_matches(
                        self.namespace, self.name, arguments, arguments_by_name
                    )
                    a1_private_call = stage3_a1_private_call_matches(
                        self.namespace, self.name, arguments, arguments_by_name
                    )
                    a2_call_token = stage3_a2_call_token(
                        self.namespace, self.name, arguments, arguments_by_name
                    )
                    a3_call_token = stage3_a3_call_token(
                        self.namespace, self.name, arguments, arguments_by_name
                    )
                    call_label = a3_call_token or a2_call_token or stage3_authorized_call(
                        self.namespace, self.name, arguments, arguments_by_name
                    )
                    if state is not None and state["a2_complete"] == 1:
                        if call_label is None and not a1_graph_call and not a1_private_call:
                            state["unauthorized_calls"].append((self.namespace, self.name))
                        elif call_label is not None and a3_call_token is None:
                            state["post_a2_calls"].append(call_label)
                    if call_label == "stage3a2-fsencode":
                        result = self.target(*arguments, **arguments_by_name)
                        state["a2_fsencode_calls"].append((arguments[0], result))
                        return result
                    if a2_call_token is not None:
                        return stage3_a2_execute(
                            stage3_native_target(self.target),
                            a2_call_token,
                            arguments,
                            arguments_by_name,
                        )
                    if a3_call_token is not None:
                        return stage3_a3_execute(
                            stage3_native_target(self.target),
                            a3_call_token,
                            arguments,
                            arguments_by_name,
                        )
                    if (
                        state is not None
                        and stage3_case_reaches_g1(state["stage3_case"])
                        and call_label in stage3_a1_final_borrowed
                    ):
                        record_final_borrowed_attempt(state, call_label)
                    if (
                        state is not None
                        and state["events"]
                        == ["a2-complete", "capability-inventory", "rlimit-baseline"]
                        and not a1_graph_call
                        and not a1_private_call
                        and not (
                            self.namespace == "fcntl"
                            and self.name == "fcntl"
                            and len(arguments) >= 2
                            and arguments[0] == state["borrowed_ledger_fd"]
                            and arguments[1] == stage3_custody_commands(state)[0]
                        )
                    ):
                        state["intervening"] += 1
                    if self.namespace == "os" and self.name == "open" and state is not None:
                        if state["a2_complete"] == 1:
                            state["graph_opens"] += 1
                        if state["a2_complete"] == 1 and stage3_case_reaches_g1(state["stage3_case"]):
                            token = stage3_a1_expected_token(state)
                            if token == "open-root":
                                edge = state["graph_edges"][0]
                            elif token is not None and token.startswith("open-prefix:"):
                                expected_prefix = token.split(":", 1)[1].encode("ascii")
                                edge = stage3_a1_edge_for_prefix(state, expected_prefix)
                            else:
                                raise SystemExit("stage3a1 graph acquisition order drifted")
                            if edge is None or edge[0] != "edge" and edge[0] != "root":
                                raise SystemExit("stage3a1 graph acquisition order drifted")
                            edge_index = state["graph_edges"].index(edge)
                            _kind, role, expected_path, expected_parent, expected_prefix, _event = edge
                            actual_path = arguments[0] if arguments else None
                            actual_flags = arguments[1] if len(arguments) > 1 else None
                            actual_parent = arguments_by_name.get("dir_fd")
                            expected_flags = (
                                state["constant_values"][("os", "O_RDONLY")]
                                | state["constant_values"][("os", "O_DIRECTORY")]
                                | state["constant_values"][("os", "O_CLOEXEC")]
                                | state["constant_values"][("os", "O_NOFOLLOW")]
                            )
                            expected_parent_fd = (
                                None if expected_parent is None else state["graph_fds"].get(expected_parent)
                            )
                            if (
                                type(actual_path) is not bytes
                                or actual_path != expected_path
                                or actual_flags != expected_flags
                                or actual_parent != expected_parent_fd
                            ):
                                raise SystemExit("stage3a1 graph acquisition order drifted")
                            attempt_index = len(state["graph_events"])
                            if attempt_index in state["g1_attempt_indices"]:
                                raise SystemExit("stage3a1 graph acquisition retried")
                            state["g1_attempt_indices"].append(attempt_index)
                            state["graph_events"].append(token)
                            case = state["stage3_case"]
                            for variant in (
                                "return-True",
                                "return-IntSubclass",
                                "return-negative",
                                "collision-borrowed-L",
                                "collision-borrowed-P",
                                "collision-private-L",
                                "collision-private-P",
                                "ENFILE",
                                "EMFILE-rlimit-same",
                                "EMFILE-rlimit-drift",
                                "KeyboardInterrupt",
                            ):
                                if stage3_a1_failure_matches(case, edge_index, role, variant):
                                    break
                            else:
                                variant = None
                            if (
                                variant is None
                                and stage3_a1_failure(case)
                                and len(case) >= 3
                                and (case[1] == role or case[1] == f"edge-{edge_index}")
                                and case[2].startswith("collision-owned-G")
                            ):
                                variant = case[2]
                            if variant is not None:
                                stage3_a1_finish_body(state, (
                                    "arbitrary" if variant == "KeyboardInterrupt" else "governed"
                                ))
                                if variant == "return-True":
                                    state["a1_rejected_returns"].append((True, False))
                                    return True
                                if variant == "return-IntSubclass":
                                    candidate = IntSubclass(0)
                                    state["a1_rejected_returns"].append((candidate, False))
                                    return candidate
                                if variant == "return-negative":
                                    state["a1_rejected_returns"].append((-1, False))
                                    return -1
                                if variant == "collision-borrowed-L":
                                    candidate = state["borrowed_ledger_fd"]
                                    state["a1_rejected_returns"].append((candidate, False))
                                    return candidate
                                if variant == "collision-borrowed-P":
                                    candidate = state["borrowed_parent_fd"]
                                    state["a1_rejected_returns"].append((candidate, False))
                                    return candidate
                                if variant == "collision-private-L":
                                    candidate = state["private_ledger_fd"]
                                    state["a1_rejected_returns"].append((candidate, True))
                                    return candidate
                                if variant == "collision-private-P":
                                    candidate = state["private_parent_fd"]
                                    state["a1_rejected_returns"].append((candidate, True))
                                    return candidate
                                if variant.startswith("collision-owned-G"):
                                    try:
                                        graph_index = int(variant.removeprefix("collision-owned-G"))
                                        candidate = state["graph_owned"][graph_index]
                                    except (ValueError, IndexError):
                                        raise SystemExit("stage3a1 graph collision index drifted")
                                    state["a1_rejected_returns"].append((candidate, True))
                                    return candidate
                                if variant == "KeyboardInterrupt":
                                    raise KeyboardInterrupt()
                                if variant == "ENFILE":
                                    raise OSError(errno.ENFILE, "fixture system file table exhausted")
                                if variant.startswith("EMFILE"):
                                    state["a1_emfile"] = True
                                    state["a1_emfile_pending"] = True
                                    raise OSError(errno.EMFILE, "fixture process file table exhausted")
                        target = stage3_native_target(self.target) if a1_graph_call else self.target
                        if (
                            a1_graph_call
                            and state is not None
                            and state["stage3_case"] is not None
                            and state["stage3_case"][0] == "stage3a3-case"
                            and state["stage3_case"][1] == "held-root-canonical-absence"
                            and state["a1_phase"] == "g1"
                            and token == "open-root"
                            and arguments == (b"/", arguments[1])
                            and not arguments_by_name
                        ):
                            state["held_root_open_redirects"].append("open-root")
                            result = target(stage3_root_bytes, arguments[1])
                        else:
                            result = target(*arguments, **arguments_by_name)
                        if state["a2_complete"] == 1 and stage3_case_reaches_g1(state["stage3_case"]):
                            if type(result) is not int or result < 0:
                                raise SystemExit("stage3a1 graph acquisition order drifted")
                            if result in {
                                state["borrowed_ledger_fd"],
                                state["borrowed_parent_fd"],
                                state["private_ledger_fd"],
                                state["private_parent_fd"],
                            } or result in state["graph_owned"]:
                                raise SystemExit("stage3a1 graph acquisition order drifted")
                            state["graph_owned"].append(result)
                            state["graph_pending_fd"] = (expected_prefix, result)
                        if state["a2_complete"] == 0 and state["private_parent_fd"] is None:
                            state["private_parent_fd"] = result
                        return result
                    if self.namespace == "os" and self.name == "stat" and state is not None:
                        if (
                            state["a2_complete"] == 1
                            and stage3_case_reaches_g1(state["stage3_case"])
                            and (state["a1_phase"] != "a2" or a1_graph_call)
                        ):
                            token = stage3_a1_expected_token(state)
                            binding_token = stage3_a1_expected_binding_token(state)
                            if token is None and binding_token is not None and a1_graph_call:
                                attempt_index = len(state["graph_binding_events"])
                                if attempt_index in state["gb_attempt_indices"]:
                                    raise SystemExit("stage3a1 graph binding retried")
                                state["gb_attempt_indices"].append(attempt_index)
                                state["graph_binding_events"].append(binding_token)
                                injection = stage3_a1_injection(
                                    state["stage3_case"], "gb", attempt_index
                                )
                                if injection in {"error", "KeyboardInterrupt"}:
                                    state["a1_body_outcome"] = "governed"
                                    state["gb_failed"] = True
                                    if stage3_case_is_a3(state["stage3_case"]):
                                        state["a3_later_gb_failure"] = binding_token
                                    safe_failure = stage3_a1_options(state["stage3_case"]).get("safe_failure")
                                    if safe_failure in {"GB", "GB-KI"}:
                                        state["a1_safe_failure_attempted"] = safe_failure
                                    if state["graph_binding_events"] == state["active_graph_bindings"]:
                                        stage3_a3_after_gb(state)
                                    if injection == "KeyboardInterrupt" or safe_failure == "GB-KI":
                                        stage3_a1_maybe_interrupt(state, binding_token)
                                        raise KeyboardInterrupt()
                                    raise OSError(errno.EIO, "stage3a1 graph binding stat failed")
                                result = self.target(*arguments, **arguments_by_name)
                                if injection == "mismatch":
                                    state["a1_body_outcome"] = "governed"
                                    state["gb_failed"] = True
                                    if stage3_case_is_a3(state["stage3_case"]):
                                        state["a3_later_gb_failure"] = binding_token
                                    result = StatProxy(result, st_ino=result.st_ino + 1)
                                elif (
                                    stage3_a1_options(state["stage3_case"]).get("full_binding")
                                    == binding_token
                                ):
                                    state["a1_body_outcome"] = "governed"
                                    state["gb_failed"] = True
                                    result = StatProxy(result, st_mtime_ns=result.st_mtime_ns + 1)
                                else:
                                    state["graph_binding_successes"].append(binding_token)
                                if state["graph_binding_events"] == state["active_graph_bindings"]:
                                    if not state["gb_failed"]:
                                        state["a1_suffix"].append("final-graph-bindings")
                                    stage3_a3_after_gb(state)
                                return result
                            if token is None or not (
                                token.startswith("edge-pre-stat:")
                                or token.startswith("cache-binding-stat:")
                            ):
                                raise SystemExit("stage3a1 graph acquisition order drifted")
                            attempt_index = len(state["graph_events"])
                            if attempt_index in state["g1_attempt_indices"]:
                                raise SystemExit("stage3a1 graph acquisition retried")
                            state["g1_attempt_indices"].append(attempt_index)
                            state["graph_events"].append(token)
                            prefix = token.split(":", 1)[1].encode("ascii")
                            edge = stage3_a1_edge_for_prefix(state, prefix)
                            if edge is None:
                                raise SystemExit("stage3a1 graph acquisition order drifted")
                            case = state["stage3_case"]
                            injection = stage3_a1_injection(case, "g1", attempt_index)
                            if injection == "error":
                                stage3_a1_finish_body(state, "governed")
                                raise OSError(errno.EIO, "stage3a1 graph stat failed")
                            result = self.target(*arguments, **arguments_by_name)
                            if injection == "mismatch":
                                if token.startswith("cache-binding-stat:"):
                                    stage3_a1_finish_body(state, "governed")
                                else:
                                    state["a1_body_outcome"] = "governed"
                                result = StatProxy(result, st_ino=result.st_ino + 1)
                            elif isinstance(injection, tuple) and injection[0] == "lineage":
                                result = stage3_a1_proxy_identity(
                                    result, state["graph_initial_structural"][injection[1]]
                                )
                            elif injection == "private-alias-pre":
                                result = stage3_a1_proxy_identity(
                                    result, state["private_parent_structural"]
                                )
                            if token.startswith("cache-binding-stat:") and (
                                len(state["graph_events"]) == len(state["expected_graph_events"]) - 1
                            ):
                                state["graph_events"].append("anchor-lineages-exact")
                            return result
                        return self.target(*arguments, **arguments_by_name)
                    if self.namespace == "fcntl" and self.name == "fcntl" and state is not None:
                        fd = arguments[0] if len(arguments) >= 1 else None
                        command = arguments[1] if len(arguments) >= 2 else None
                        observed_getfl, observed_getfd = stage3_custody_commands(state)
                        if a1_private_call:
                            private_token = stage3_a1_expected_fp_events(state)[len(state["a1_final_private_events"])]
                            state["a1_final_private_events"].append(private_token)
                            if tuple(state["a1_final_private_events"]) == stage3_a1_expected_fp_events(state):
                                state["a1_suffix"].append("final-private")
                                state["a1_phase"] = "fb"
                            if (
                                stage3_a1_options(state["stage3_case"]).get("safe_failure") in {"FP", "FP-KI"}
                                and private_token == "private-P-fstat"
                            ):
                                safe_failure = stage3_a1_options(state["stage3_case"]).get("safe_failure")
                                state["a1_safe_failure_attempted"] = safe_failure
                                if safe_failure == "FP-KI":
                                    raise KeyboardInterrupt()
                                raise OSError(errno.EIO, "stage3a1 final private custody failed")
                            stage3_a1_maybe_interrupt(state, private_token)
                        if (
                            not stage3_case_reaches_g1(state["stage3_case"])
                            and
                            state["a2_complete"] == 1
                            and fd == state["borrowed_ledger_fd"]
                            and command == observed_getfl
                            and state["final_custody"] == 0
                        ):
                            if state["events"] == [
                                "a2-complete",
                                "capability-inventory",
                                "rlimit-baseline",
                            ]:
                                state["events"].append("capacity-policy-selected")
                            state["events"].append("borrowed-L-getfl")
                            state["final_custody"] = 1
                        elif state["final_custody"] == 1 and fd == state["borrowed_parent_fd"]:
                            if command == observed_getfl and "borrowed-P-getfl" not in state["events"]:
                                state["events"].append("borrowed-P-getfl")
                            elif command == observed_getfd and "borrowed-P-getfd" not in state["events"]:
                                state["events"].append("borrowed-P-getfd")
                        forwarded = list(arguments)
                        if state["a2_complete"] == 1 and len(forwarded) >= 2:
                            if command == observed_getfl:
                                forwarded[1] = fcntl.F_GETFL
                            elif command == observed_getfd:
                                forwarded[1] = fcntl.F_GETFD
                        if a1_private_call:
                            fault = stage3_a1_fp_fault(state["stage3_case"], private_token)
                            if fault == "error":
                                raise OSError(errno.EIO, "stage3a1 final private custody failed")
                        target = stage3_native_target(self.target) if a1_private_call else self.target
                        result = target(*forwarded, **arguments_by_name)
                        if a1_private_call:
                            if fault == "mismatch":
                                result = result + 1 if type(result) is int else True
                            if private_token == "private-P-getfl":
                                semantic = stage3_a1_options(state["stage3_case"]).get("private_p_getfl")
                                if semantic == "benign-bit":
                                    extra = 1
                                    forbidden = result | os.O_ACCMODE | getattr(os, "O_PATH", 0)
                                    while forbidden & extra:
                                        extra <<= 1
                                    result |= extra
                                elif semantic == "True":
                                    result = True
                                elif semantic == "IntSubclass":
                                    result = IntSubclass(os.O_RDONLY)
                                elif semantic == "non-readonly":
                                    result = (result & ~os.O_ACCMODE) | os.O_WRONLY
                                elif semantic == "opath":
                                    result |= getattr(os, "O_PATH", 0)
                        duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
                        if (
                            state["a2_complete"] == 0
                            and fd == state["borrowed_ledger_fd"]
                            and command == duplicate_command
                            and type(result) is int
                            and result >= 0
                        ):
                            state["private_ledger_fd"] = result
                        return result
                    if self.namespace == "os" and self.name == "fstat" and state is not None:
                        fd = arguments[0] if len(arguments) == 1 and not arguments_by_name else None
                        if a1_private_call:
                            private_token = stage3_a1_expected_fp_events(state)[len(state["a1_final_private_events"])]
                            state["a1_final_private_events"].append(private_token)
                            if tuple(state["a1_final_private_events"]) == stage3_a1_expected_fp_events(state):
                                state["a1_suffix"].append("final-private")
                                state["a1_phase"] = "fb"
                            if (
                                stage3_a1_options(state["stage3_case"]).get("safe_failure") in {"FP", "FP-KI"}
                                and private_token == "private-P-fstat"
                            ):
                                safe_failure = stage3_a1_options(state["stage3_case"]).get("safe_failure")
                                state["a1_safe_failure_attempted"] = safe_failure
                                if safe_failure == "FP-KI":
                                    raise KeyboardInterrupt()
                                raise OSError(errno.EIO, "stage3a1 final private custody failed")
                            stage3_a1_maybe_interrupt(state, private_token)
                        if state["a2_complete"] == 1 and stage3_case_reaches_g1(state["stage3_case"]):
                            token = stage3_a1_expected_token(state)
                            binding_token = stage3_a1_expected_binding_token(state)
                            if token is None and binding_token is not None and a1_graph_call:
                                attempt_index = len(state["graph_binding_events"])
                                if attempt_index in state["gb_attempt_indices"]:
                                    raise SystemExit("stage3a1 graph binding retried")
                                state["gb_attempt_indices"].append(attempt_index)
                                state["graph_binding_events"].append(binding_token)
                                injection = stage3_a1_injection(
                                    state["stage3_case"], "gb", attempt_index
                                )
                                if injection in {"error", "KeyboardInterrupt"}:
                                    state["a1_body_outcome"] = "governed"
                                    state["gb_failed"] = True
                                    if stage3_case_is_a3(state["stage3_case"]):
                                        state["a3_later_gb_failure"] = binding_token
                                    safe_failure = stage3_a1_options(state["stage3_case"]).get("safe_failure")
                                    if safe_failure in {"GB", "GB-KI"}:
                                        state["a1_safe_failure_attempted"] = safe_failure
                                    if state["graph_binding_events"] == state["active_graph_bindings"]:
                                        stage3_a3_after_gb(state)
                                    if injection == "KeyboardInterrupt" or safe_failure == "GB-KI":
                                        stage3_a1_maybe_interrupt(state, binding_token)
                                        raise KeyboardInterrupt()
                                    raise OSError(errno.EIO, "stage3a1 graph binding fstat failed")
                                result = self.target(*arguments, **arguments_by_name)
                                if injection == "mismatch":
                                    state["a1_body_outcome"] = "governed"
                                    state["gb_failed"] = True
                                    if stage3_case_is_a3(state["stage3_case"]):
                                        state["a3_later_gb_failure"] = binding_token
                                    result = StatProxy(result, st_ino=result.st_ino + 1)
                                elif (
                                    stage3_a1_options(state["stage3_case"]).get("full_binding")
                                    == binding_token
                                ):
                                    state["a1_body_outcome"] = "governed"
                                    state["gb_failed"] = True
                                    result = StatProxy(
                                        result,
                                        st_mode=result.st_mode ^ 1,
                                        st_size=result.st_size + 1,
                                        st_mtime_ns=result.st_mtime_ns + 1,
                                    )
                                else:
                                    state["graph_binding_successes"].append(binding_token)
                                if state["graph_binding_events"] == state["active_graph_bindings"]:
                                    if not state["gb_failed"]:
                                        state["a1_suffix"].append("final-graph-bindings")
                                    stage3_a3_after_gb(state)
                                return result
                            if token is not None and (
                                token.startswith("held-fstat:")
                                or token.startswith("cache-held-fstat:")
                            ):
                                attempt_index = len(state["graph_events"])
                                if attempt_index in state["g1_attempt_indices"]:
                                    raise SystemExit("stage3a1 graph acquisition retried")
                                state["g1_attempt_indices"].append(attempt_index)
                                state["graph_events"].append(token)
                                prefix = token.split(":", 1)[1].encode("ascii")
                                expected_fd = (
                                    state["graph_pending_fd"][1]
                                    if token.startswith("held-fstat:")
                                    else stage3_a1_fd_for_prefix(state, prefix)
                                )
                                if fd != expected_fd:
                                    raise SystemExit("stage3a1 graph acquisition order drifted")
                                case = state["stage3_case"]
                                injection = stage3_a1_injection(case, "g1", attempt_index)
                                if injection == "error":
                                    stage3_a1_finish_body(state, "governed")
                                    raise OSError(errno.EIO, "stage3a1 held fstat failed")
                                result = self.target(*arguments, **arguments_by_name)
                                if injection == "mismatch":
                                    stage3_a1_finish_body(state, "governed")
                                    result = StatProxy(result, st_ino=result.st_ino + 1)
                                elif injection == "root-mismatch":
                                    stage3_a1_finish_body(state, "governed")
                                    result = StatProxy(result, st_mode=stat.S_IFREG | 0o600)
                                elif injection == "private-alias":
                                    stage3_a1_finish_body(state, "governed")
                                    result = stage3_a1_proxy_identity(
                                        result, state["private_parent_structural"]
                                    )
                                elif isinstance(injection, tuple) and injection[0] == "lineage":
                                    result = stage3_a1_proxy_identity(
                                        result, state["graph_initial_structural"][injection[1]]
                                    )
                                if token.startswith("held-fstat:"):
                                    rejects_here = injection in {"mismatch", "root-mismatch", "private-alias"}
                                    if (
                                        case is not None
                                        and case[0] == "stage3a1-g1-mutation"
                                        and len(case) > 3
                                        and case[3] == attempt_index
                                    ):
                                        rejects_here = True
                                        stage3_a1_finish_body(state, "governed")
                                    if not rejects_here:
                                        state["graph_fds"][prefix] = fd
                                        state["graph_initial_structural"][prefix] = identity(result)
                                        state["graph_pending_fd"] = None
                                        state["graph_events"].append(
                                            f"private-parent-disjoint:{prefix.decode('ascii')}"
                                        )
                                        if isinstance(injection, tuple):
                                            stage3_a1_finish_body(state, "governed")
                                        elif len(state["graph_events"]) == len(state["expected_graph_events"]) - 1:
                                            state["graph_events"].append("anchor-lineages-exact")
                                            state["a1_phase"] = (
                                                "a2"
                                                if stage3_case_reaches_a2(state["stage3_case"])
                                                else "fb"
                                            )
                                return result
                            if token is not None and token == "anchor-lineages-exact":
                                raise SystemExit("stage3a1 graph acquisition order drifted")
                        if not stage3_case_reaches_g1(state["stage3_case"]) and state["final_custody"] == 1:
                            if fd == state["borrowed_ledger_fd"] and "borrowed-L-fstat" not in state["events"]:
                                state["events"].append("borrowed-L-fstat")
                            elif fd == state["borrowed_parent_fd"] and "borrowed-P-fstat" not in state["events"]:
                                state["events"].append("borrowed-P-fstat")
                        if a1_private_call:
                            fault = stage3_a1_fp_fault(state["stage3_case"], private_token)
                            if fault == "error":
                                raise OSError(errno.EIO, "stage3a1 final private custody failed")
                        target = stage3_native_target(self.target) if a1_private_call else self.target
                        result = target(*arguments, **arguments_by_name)
                        if a1_private_call and fault == "mismatch":
                            result = StatProxy(result, st_ino=result.st_ino + 1)
                        if (
                            state["a2_complete"] == 0
                            and fd == state["private_parent_fd"]
                            and state["private_parent_fd"] is not None
                        ):
                            state["private_parent_structural"] = identity(result)
                            stage3_a2_complete()
                        return result
                    if self.namespace == "os" and self.name == "pread" and state is not None:
                        if a1_private_call:
                            private_token = stage3_a1_expected_fp_events(state)[len(state["a1_final_private_events"])]
                            fault = stage3_a1_fp_fault(state["stage3_case"], "private-L-pread")
                            if fault is not None:
                                state["a1_final_private_events"].append(private_token)
                                state["a1_fp_pread_attempted"] = True
                                raise OSError(errno.EIO, "stage3a1 final private ledger pread failed")
                            if private_token == "private-L-pread-attempt":
                                state["a1_final_private_events"].append(private_token)
                                state["a1_fp_pread_attempted"] = True
                                stage3_a1_maybe_interrupt(state, "private-L-pread")
                        target = stage3_native_target(self.target) if a1_private_call else self.target
                        result = target(*arguments, **arguments_by_name)
                        if a1_private_call:
                            cursor = state["a1_private_pread_cursor"]
                            expected = state["a1_private_expected_bytes"]
                            if (
                                type(result) is not bytes
                                or not result
                                or cursor + len(result) > len(expected)
                                or result != expected[cursor : cursor + len(result)]
                            ):
                                raise SystemExit("stage3a1 final private pread was not exact")
                            state["a1_private_pread_chunks"].append((cursor, result))
                            state["a1_private_pread_cursor"] += len(result)
                            if state["a1_private_pread_cursor"] == len(expected):
                                state["a1_final_private_events"].append(
                                    stage3_a1_final_private[len(state["a1_final_private_events"])]
                                )
                        return result
                    if self.namespace == "os" and self.name == "close" and state is not None:
                        fd = arguments[0] if len(arguments) == 1 and not arguments_by_name else None
                        if stage3_case_reaches_g1(state["stage3_case"]):
                            close_index = len(state["graph_close_calls"])
                            expected = list(reversed(state["graph_owned"]))
                            expected += [state["private_parent_fd"], state["private_ledger_fd"]]
                            if close_index >= len(expected) or fd != expected[close_index]:
                                raise SystemExit("stage3a1 reverse close order drifted")
                            if fd in state["graph_owned"]:
                                graph_index = state["graph_owned"].index(fd)
                                state["a1_custody_events"].append(f"close-G{graph_index}")
                            elif fd == state["private_parent_fd"]:
                                state["a1_custody_events"].append("close-P")
                            elif fd == state["private_ledger_fd"]:
                                state["a1_custody_events"].append("close-L")
                            state["graph_close_calls"].append(fd)
                            if close_index == len(expected) - 1:
                                state["a1_suffix"].append("reverse-close-graph-P-L")
                        if stage3_case_reaches_g1(state["stage3_case"]):
                            if fd == state["private_parent_fd"]:
                                state["events"].append("close-P")
                            elif fd == state["private_ledger_fd"]:
                                state["events"].append("close-L")
                        elif state["final_custody"] == 1:
                            if fd == state["private_parent_fd"]:
                                state["events"].append("close-P")
                            elif fd == state["private_ledger_fd"]:
                                state["events"].append("close-L")
                        target = (
                            stage3_native_target(self.target)
                            if fd in state.get("graph_owned", ())
                            else self.target
                        )
                        result = target(*arguments, **arguments_by_name)
                        if (
                            stage3_case_is_a3(state["stage3_case"])
                            and stage3_a2_options(state["stage3_case"]).get("a3_close_failure")
                            and fd in state["a3_fds"].values()
                            and state["a3_close_failure"] is None
                        ):
                            state["a3_close_failure"] = fd
                            raise state["a3_close_sentinel"]
                        if (
                            stage3_a1_options(state["stage3_case"]).get("close_failure") == "parent"
                            and fd == state["private_parent_fd"]
                        ):
                            state["a1_close_failure_attempted"] = "parent"
                            if stage3_a2_options(state["stage3_case"]).get(
                                "parent_close_sentinel"
                            ):
                                state["a2_parent_close_raised"] = state[
                                    "a2_parent_close_sentinel"
                                ]
                                raise state["a2_parent_close_sentinel"]
                            raise OSError(errno.EIO, "stage3a1 parent real-close-then-raise")
                        return result
                    if self.namespace == "resource" and self.name == "getrlimit" and state is not None:
                        limit = arguments[0] if len(arguments) == 1 and not arguments_by_name else None
                        case = state["stage3_case"]
                        if stage3_case_is_c0(case) and case[1] == "rlimit-result":
                            state["case_attempts"] += 1
                        result = (
                            case[3]
                            if stage3_case_is_c0(case) and case[1] == "rlimit-result"
                            else (1024, 1048576)
                        )
                        if (
                            state is not None
                            and stage3_case_reaches_g1(case)
                            and state["a1_emfile"]
                            and len(case) >= 3
                            and case[2] == "EMFILE-rlimit-drift"
                        ):
                            result = (1023, 1048576)
                        state["getrlimit"].append((limit, result))
                        if state.get("a1_emfile_pending"):
                            state["a1_emfile_pending"] = False
                        if (
                            state["events"] == ["a2-complete", "capability-inventory"]
                            and limit
                            == state["constant_values"].get(
                                ("resource", "RLIMIT_NOFILE"), resource.RLIMIT_NOFILE
                            )
                            and type(result) is tuple
                            and len(result) == 2
                            and all(type(item) is int and item >= 0 for item in result)
                            and result[0] <= result[1]
                        ):
                            state["events"].append("rlimit-baseline")
                            state["rlimit_baseline"] = result
                        return result
                    return self.target(*arguments, **arguments_by_name)

            class Stage3SupportProxy:
                def __init__(self, name, target):
                    self.name = name
                    self.target = target

                def __contains__(self, candidate):
                    target = candidate.target if isinstance(candidate, Stage3Callable) else candidate
                    for wrapper, native in stage3_support_wrapper_targets:
                        if target is wrapper:
                            target = native
                            break
                    result = target in self.target
                    function_name = candidate.name if isinstance(candidate, Stage3Callable) else getattr(candidate, "__name__", None)
                    item = (self.name, function_name)
                    state = stage3_c0_state
                    case = None if state is None or state["a2_complete"] == 0 else state["stage3_case"]
                    if state is not None and state["a2_complete"] == 1:
                        state["observed_items"][item] = state["observed_items"].get(item, 0) + 1
                    if (
                        case is not None
                        and stage3_case_is_c0(case)
                        and case[1] == "missing-support"
                        and case[2] == item
                        and state["case_attempts"] == 0
                    ):
                        state["case_attempts"] += 1
                        state["inventory_closed"] = not stage3_case_is_continuation(case)
                        return False
                    if result and item in stage3_supports:
                        stage3_record("supports", item, result)
                    return result

            class Stage3NativeProxy:
                def __init__(self, namespace, target):
                    self.namespace = namespace
                    self.target = target

                def __getattr__(self, name):
                    item = (self.namespace, name)
                    state = stage3_c0_state
                    case = None if state is None or state["a2_complete"] == 0 else state["stage3_case"]
                    if state is not None and state["a2_complete"] == 1:
                        state["observed_items"][item] = state["observed_items"].get(item, 0) + 1
                        allowed_items = (
                            state["required_constants"]
                            | state["required_callables"]
                            | {
                                ("os", "supports_dir_fd"),
                                ("os", "supports_follow_symlinks"),
                                ("os", "supports_fd"),
                            }
                        )
                        if item not in allowed_items:
                            state["unauthorized_attributes"].append(item)
                            raise SystemExit(
                                f"stage3 unauthorized native attribute: {self.namespace}.{name}"
                            )
                    if (
                        case is not None
                        and stage3_case_is_c0(case)
                        and case[1] == "missing"
                        and case[2] == item
                        and state["case_attempts"] == 0
                    ):
                        state["case_attempts"] += 1
                        state["inventory_closed"] = not stage3_case_is_continuation(case)
                        raise AttributeError(name)
                    value = getattr(self.target, name)
                    if (
                        case is not None
                        and stage3_case_is_c0(case)
                        and case[1] == "replace"
                        and case[2] == item
                        and state["case_attempts"] == 0
                    ):
                        state["case_attempts"] += 1
                        state["inventory_closed"] = not stage3_case_is_continuation(case)
                        value = case[3]
                    if item in stage3_constants:
                        stage3_record("constants", item, value)
                    if item in stage3_callables:
                        stage3_record("callables", item, value)
                    if callable(value) and (self.namespace == "os" and name in {
                        "open",
                        "stat",
                        "listdir",
                        "fsencode",
                        "fstat",
                        "pread",
                        "close",
                        "readlink",
                    } or self.namespace == "fcntl" and name == "fcntl" or self.namespace == "resource" and name == "getrlimit"):
                        return Stage3Callable(self.namespace, name, value)
                    if self.namespace == "os" and name in {
                        "supports_dir_fd",
                        "supports_follow_symlinks",
                        "supports_fd",
                    }:
                        return Stage3SupportProxy(name, value)
                    return value

            def stage3_a2_complete():
                state = stage3_c0_state
                if state is not None:
                    state["a2_complete"] += 1
                    state["events"].append("a2-complete")
                    state["a1_phase"] = "c0"

            def check_stage3_c0(expected_terminal):
                state = stage3_c0_state
                b_events = [
                    "borrowed-L-getfl",
                    "borrowed-L-fstat",
                    "borrowed-P-getfl",
                    "borrowed-P-getfd",
                    "borrowed-P-fstat",
                    "close-P",
                    "close-L",
                ]
                b_calls = [
                    "borrowed-L-getfl",
                    "borrowed-L-fstat",
                    "borrowed-P-getfl",
                    "borrowed-P-getfd",
                    "borrowed-P-fstat",
                    "close-P",
                    "close-L",
                ]
                if (
                    state is None
                    or state["a2_complete"] != 1
                    or set(state["constants"]) != state["required_constants"]
                    or set(state["callables"]) != state["required_callables"]
                    or set(state["supports"]) != state["required_supports"]
                    or any(count != 1 for count in state["constants"].values())
                    or any(count != 1 for count in state["callables"].values())
                    or any(count != 1 for count in state["supports"].values())
                    or not state["inventory_valid"]
                    or len(state["getrlimit"]) != 1
                    or state["events"]
                    != [
                        "a2-complete",
                        "capability-inventory",
                        "rlimit-baseline",
                        "capacity-policy-selected",
                    ]
                    + b_events
                    + [expected_terminal]
                    or state["post_a2_calls"] != ["resource-getrlimit"] + b_calls
                    or state["unauthorized_calls"]
                    or state["final_custody"] != 1
                    or state["graph_opens"] != 0
                    or state["intervening"] != 0
                ):
                    raise SystemExit("stage3a0 fd capacity policy was not evaluated exactly once")

            def check_stage3_c0_case(case, expected_terminal):
                continuation = stage3_case_is_continuation(case)
                if continuation:
                    state = stage3_c0_state
                    if case[0] == "missing-O_PATH-no-symlink-continue":
                        if (
                            state["case_attempts"] != 0
                            or state["observed_items"].get(("os", "O_PATH"), 0) != 0
                            or state["observed_items"].get(("os", "readlink"), 0) != 0
                            or state["observed_items"].get(("supports_dir_fd", "readlink"), 0) != 0
                        ):
                            raise SystemExit("stage3a0 no-symlink capability continuation drifted")
                    elif (
                        state["case_attempts"] != 1
                        or state["observed_items"].get(case[2], 0) != 1
                    ):
                        raise SystemExit(f"stage3a0 continuation shim count drifted: {case[0]}")
                    return
                state = stage3_c0_state
                b_events = [
                    "borrowed-L-getfl",
                    "borrowed-L-fstat",
                    "borrowed-P-getfl",
                    "borrowed-P-getfd",
                    "borrowed-P-fstat",
                    "close-P",
                    "close-L",
                ]
                expected_prefix = (
                    ["a2-complete", "capability-inventory"]
                    if case[1] == "rlimit-result"
                    else ["a2-complete"]
                )
                expected_calls = (
                    ["resource-getrlimit"] if case[1] == "rlimit-result" else []
                ) + b_events
                if (
                    state is None
                    or state["a2_complete"] != 1
                    or state["events"] != expected_prefix + b_events + [expected_terminal]
                    or state["post_a2_calls"] != expected_calls
                    or state["unauthorized_calls"]
                    or len(state["getrlimit"]) != (1 if case[1] == "rlimit-result" else 0)
                    or state["case_attempts"] != 1
                    or (
                        case[1] in {"missing", "missing-support", "replace"}
                        and state["observed_items"].get(case[2], 0) != 1
                    )
                    or state["final_custody"] != 1
                    or state["graph_opens"] != 0
                    or "capacity-policy-selected" in state["events"]
                ):
                    raise SystemExit(f"stage3a0 mutation vector drifted: {case[0]}")

            def check_stage3_a1(expected_terminal):
                state = stage3_c0_state
                case = None if state is None else state["stage3_case"]
                if state is None:
                    raise SystemExit("stage3a1 filesystem root anchor was not acquired exactly once")
                if (
                    set(state["constants"]) != state["required_constants"]
                    or set(state["callables"]) != state["required_callables"]
                    or set(state["supports"]) != state["required_supports"]
                    or any(count != 1 for count in state["constants"].values())
                    or any(count != 1 for count in state["callables"].values())
                    or any(count != 1 for count in state["supports"].values())
                    or not state["inventory_valid"]
                ):
                    raise SystemExit("stage3a1 C0 inventory drifted")
                expected_events = state["expected_graph_events"]
                if stage3_a1_failure(case):
                    site = case[1]
                    edge = next(edge for edge in state["graph_edges"] if edge[1] == site)
                    failed_token = edge[5]
                    expected_events = expected_events[: expected_events.index(failed_token) + 1]
                elif case[0] == "stage3a1-g1-mutation":
                    expected_events = expected_events[: case[3] + 1]
                elif case[0] == "stage3a1-lineage-mutation":
                    expected_events = expected_events[: case[4] + 1]
                elif state["graph_events"][:1] != ["open-root"]:
                    raise SystemExit("stage3a1 filesystem root anchor was not acquired exactly once")
                if state["graph_events"] != expected_events:
                    raise SystemExit("stage3a1 graph acquisition order drifted")
                expected_observed_items = (
                    state["required_constants"]
                    | state["required_callables"]
                    | state["required_supports"]
                    | {
                        ("os", "supports_dir_fd"),
                        ("os", "supports_follow_symlinks"),
                        ("os", "supports_fd"),
                    }
                )
                if (
                    set(state["observed_items"]) != expected_observed_items
                    or any(count != 1 for count in state["observed_items"].values())
                ):
                    raise SystemExit("stage3a1 native attribute observation drifted")
                if state["unauthorized_calls"] or state["unauthorized_attributes"]:
                    raise SystemExit("stage3a1 unauthorized native call")
                expected_closes = list(reversed(state["graph_owned"])) + [
                    state["private_parent_fd"],
                    state["private_ledger_fd"],
                ]
                if (
                    state["graph_close_calls"] != expected_closes
                    or any(
                        not preowned and candidate in state["graph_close_calls"]
                        for candidate, preowned in state["a1_rejected_returns"]
                    )
                ):
                    raise SystemExit("stage3a1 reverse close order drifted")
                expected_custody_events = [
                    f"close-G{index}" for index in reversed(range(len(state["graph_owned"])))
                ] + ["close-P", "close-L"]
                if state["a1_custody_events"] != expected_custody_events:
                    raise SystemExit("stage3a1 close custody ledger drifted")
                for fd in expected_closes:
                    try:
                        real_fstat(fd)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise SystemExit("stage3a1 closed owner did not report EBADF") from exc
                    else:
                        raise SystemExit("stage3a1 owned descriptor leaked")
                if state["a1_close_failure_attempted"] != stage3_a1_options(case).get("close_failure"):
                    raise SystemExit("stage3a1 close override injection drifted")
                emfile = stage3_a1_failure(case) and case[2].startswith("EMFILE")
                if (
                    len(state["getrlimit"]) != (2 if emfile else 1)
                    or state["a1_emfile_pending"]
                    or state["getrlimit"][0]
                    != (
                        state["constant_values"][("resource", "RLIMIT_NOFILE")],
                        state["rlimit_baseline"],
                    )
                ):
                    raise SystemExit("stage3a1 RLIMIT reread drifted")
                if emfile:
                    baseline = state["getrlimit"][0][1]
                    reread = state["getrlimit"][1][1]
                    if (case[2].endswith("same") and reread != baseline) or (
                        case[2].endswith("drift") and reread == baseline
                    ):
                        raise SystemExit("stage3a1 RLIMIT reread drifted")
                graph_arbitrary = (
                    stage3_a1_failure(case) and case[2] == "KeyboardInterrupt"
                )
                expects_fp = (
                    stage3_a1_failure(case) and not graph_arbitrary
                    or case[0] in {"stage3a1-g1-mutation", "stage3a1-lineage-mutation"}
                )
                expected_private = stage3_a1_expected_fp_events(state) if expects_fp else ()
                if tuple(state["a1_final_private_events"]) != expected_private:
                    raise SystemExit("stage3a1 final private custody drifted")
                if "private-L-pread-attempt" in expected_private:
                    if (
                        not state["a1_fp_pread_attempted"]
                        or state["a1_private_pread_cursor"] != 0
                        or state["a1_private_pread_chunks"]
                        or "private-L-fstat-post" not in expected_private
                    ):
                        raise SystemExit("stage3a1 final private pread fault bracket drifted")
                elif "private-L-pread-complete" in expected_private:
                    if (
                        state["a1_fp_pread_attempted"]
                        or state["a1_private_pread_cursor"] != len(state["a1_private_expected_bytes"])
                        or b"".join(chunk for _offset, chunk in state["a1_private_pread_chunks"])
                        != state["a1_private_expected_bytes"]
                    ):
                        raise SystemExit("stage3a1 final private pread coverage drifted")
                elif (
                    state["a1_fp_pread_attempted"]
                    or state["a1_private_pread_cursor"] != 0
                    or state["a1_private_pread_chunks"]
                ):
                    raise SystemExit("stage3a1 skipped private pread was attempted")
                expected_safe_failure = stage3_a1_options(case).get("safe_failure")
                if state["a1_safe_failure_attempted"] != expected_safe_failure:
                    raise SystemExit("stage3a1 safe-successor failure injection drifted")
                if state["a1_ki_attempted"] != stage3_a1_options(case).get("ki_token"):
                    raise SystemExit("stage3a1 KeyboardInterrupt injection drifted")
                expected_binding_events = state.get("active_graph_bindings", [])
                if not graph_arbitrary and state["graph_binding_events"] != expected_binding_events:
                    raise SystemExit("stage3a1 final graph binding drifted")
                expected_borrowed = () if graph_arbitrary else stage3_a1_final_borrowed
                if tuple(state["a1_final_borrowed_events"]) != expected_borrowed:
                    raise SystemExit("stage3a1 final borrowed custody drifted")
                expected_post_calls = ["resource-getrlimit"]
                if emfile:
                    expected_post_calls.append("resource-getrlimit-reread")
                expected_post_calls.extend(expected_borrowed)
                expected_post_calls.extend(("close-P", "close-L"))
                expected_post_events = [
                    "a2-complete",
                    "capability-inventory",
                    "rlimit-baseline",
                    "capacity-policy-selected",
                    *expected_borrowed,
                    "close-P",
                    "close-L",
                    expected_terminal,
                ]
                if state["post_a2_calls"] != expected_post_calls or state["events"] != expected_post_events:
                    raise SystemExit("stage3a1 post-A2 call order drifted")
                expected_binding_successes = len(expected_binding_events) - (1 if state["gb_failed"] else 0)
                if len(state["graph_binding_successes"]) != expected_binding_successes:
                    raise SystemExit("stage3a1 successful graph binding ledger drifted")
                expected_suffix = []
                if expects_fp:
                    expected_suffix.append("final-private")
                if not graph_arbitrary:
                    expected_suffix.append("final-borrowed")
                    if not state["gb_failed"]:
                        expected_suffix.append("final-graph-bindings")
                expected_suffix.append("reverse-close-graph-P-L")
                if tuple(state["a1_suffix"]) != tuple(expected_suffix):
                    raise SystemExit("stage3a1 custody suffix drifted")
                if state["a1_phase"] != "cleanup":
                    raise SystemExit("stage3a1 lifecycle phase did not reach cleanup")

            def check_stage3_a2_positive_body():
                state = stage3_c0_state
                if state is None or state["a2_expected_outcome"] != "success":
                    raise SystemExit("stage3a2 positive body was used for a non-success route")
                case = state["stage3_case"]
                fault_token, variant = stage3_a2_fault(case)
                expected_fsencode = [
                    (descriptor[3][0], os.fsencode(descriptor[3][0]))
                    for descriptor in state["a2_expected_operations"]
                    if descriptor[0].startswith("fsencode")
                    and not (descriptor[0] == fault_token and variant == "error")
                ]
                if state["a2_fsencode_calls"] != expected_fsencode:
                    raise SystemExit("stage3a2 positive fsencode invocation drifted")
                if len(state["a2_scan_closes"]) != len(set(state["a2_scan_closes"])):
                    raise SystemExit("stage3a2 positive scan descriptor was closed more than once")
                for value, preowned in state["a2_rejected_returns"]:
                    close_count = sum(
                        type(closed) is type(value) and closed == value
                        for closed in state["graph_close_calls"]
                    )
                    if close_count != (1 if preowned else 0):
                        raise SystemExit("stage3a2 positive rejected descriptor lifetime drifted")
                expected_closes = list(reversed(state["graph_owned"])) + [
                    state["private_parent_fd"],
                    state["private_ledger_fd"],
                ]
                if state["graph_close_calls"] != expected_closes:
                    raise SystemExit("stage3a2 positive reverse owner cleanup drifted")
                for fd in expected_closes:
                    try:
                        real_fstat(fd)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise SystemExit("stage3a2 positive owner did not report EBADF") from exc
                    else:
                        raise SystemExit("stage3a2 positive owner leaked")
                expected_post_calls = ["resource-getrlimit"]
                for descriptor in state["a2_expected_operations"]:
                    token = descriptor[0]
                    repeats = 1
                    if token.startswith("regular-pread:"):
                        label = token.split(":", 1)[1]
                        chunks = state["a2_chunks_by_label"].get(label)
                        if chunks is None and token == fault_token:
                            chunks = state["a2_regular_chunks"]
                        repeats = max(1, len(chunks or ()))
                    expected_post_calls.extend(token for _ in range(repeats))
                    if token == fault_token and variant is not None and variant.startswith("EMFILE"):
                        expected_post_calls.append("resource-getrlimit-reread")
                expected_a2_prefix = tuple(expected_post_calls)
                expected_post_calls.extend(stage3_a1_final_borrowed)
                expected_post_calls.extend(("close-P", "close-L"))
                if stage3_case_composes_a3(state["stage3_case"]):
                    if tuple(state["post_a2_calls"][: len(expected_a2_prefix)]) != expected_a2_prefix:
                        raise SystemExit("stage3a2 positive post-A2 call sequence drifted")
                elif state["post_a2_calls"] != expected_post_calls:
                    raise SystemExit("stage3a2 positive post-A2 call sequence drifted")
                expected_rows = stage3_a2_expected_rows
                if (
                    state["stage3_case"] is not None
                    and state["stage3_case"][0] == "stage3a3-case"
                    and state["stage3_case"][1] == "held-root-canonical-absence"
                ):
                    expected_rows = stage3_a2_held_root_rows
                for row in expected_rows:
                    label, locator, klass, access, result, mode, size, digest = row[:8]
                    observed_row = state["a2_supplied_rows"].get(locator)
                    observed_lineage = state["a2_row_lineage"].get(label)
                    if observed_row is None or observed_row + (observed_lineage,) != (
                        locator,
                        klass,
                        access,
                        result,
                        mode,
                        size,
                        digest,
                        row[8],
                    ):
                        raise SystemExit("stage3a2 positive literal ledger lineage drifted")
                    value = state["a2_row_stats"].get(label)
                    if value is None or stat.S_IMODE(value.st_mode) != mode:
                        raise SystemExit("stage3a2 positive literal row mode drifted")
                    if row[-1] == "regular":
                        content = state["a2_regular_bytes"].get(label)
                        chunks = state["a2_chunks_by_label"].get(label, ())
                        cursor = 0
                        for offset, request, chunk in chunks:
                            if (
                                offset != cursor
                                or request <= 0
                                or request > min(1024 * 1024, size - offset)
                                or not chunk
                                or cursor + len(chunk) > size
                            ):
                                raise SystemExit("stage3a2 positive pread cursor/request drifted")
                            cursor += len(chunk)
                        if (
                            content is None
                            or cursor != size
                            or len(content) != size
                            or hashlib.sha256(content).hexdigest() != digest
                        ):
                            raise SystemExit("stage3a2 positive regular row values drifted")
                    else:
                        preimages = [
                            data
                            for observed_label, data in state["a2_preimages"]
                            if observed_label == label
                        ]
                        if (
                            len(preimages) != 2
                            or preimages[0] != preimages[1]
                            or len(preimages[0]) != size
                            or hashlib.sha256(preimages[0]).hexdigest() != digest
                        ):
                            raise SystemExit("stage3a2 positive directory preimages drifted")

            def check_stage3_a2(expected_terminal):
                state = stage3_c0_state
                if (
                    state is None
                    or state["graph_events"] != state["expected_graph_events"]
                    or tuple(state["a2_operations"])
                    != tuple(descriptor[0] for descriptor in state["a2_expected_operations"])
                ):
                    raise SystemExit(
                        "stage3a2 regular and directory evidence rows were not reproduced in exact order"
                    )
                case = state["stage3_case"]
                fault_token, variant = stage3_a2_fault(case)
                expected_fsencode = [
                    (descriptor[3][0], os.fsencode(descriptor[3][0]))
                    for descriptor in state["a2_expected_operations"]
                    if descriptor[0].startswith("fsencode")
                    and not (descriptor[0] == fault_token and variant == "error")
                ]
                if state["a2_fsencode_calls"] != expected_fsencode:
                    raise SystemExit("stage3a2 fsencode invocation count drifted")
                if state["unauthorized_calls"] or state["unauthorized_attributes"]:
                    raise SystemExit("stage3a2 unauthorized native operation was reachable")
                expected_rlimit = 2 if variant is not None and variant.startswith("EMFILE") else 1
                if len(state["getrlimit"]) != expected_rlimit or state["a1_emfile_pending"]:
                    raise SystemExit("stage3a2 RLIMIT safe-suffix drifted")
                if variant == "EMFILE-rlimit-same" and state["getrlimit"][1][1] != state["rlimit_baseline"]:
                    raise SystemExit("stage3a2 unchanged RLIMIT refusal drifted")
                if variant == "EMFILE-rlimit-drift" and state["getrlimit"][1][1] == state["rlimit_baseline"]:
                    raise SystemExit("stage3a2 changed RLIMIT mutation drifted")
                if len(state["a2_scan_closes"]) != len(set(state["a2_scan_closes"])):
                    raise SystemExit("stage3a2 scan descriptor was closed more than once")
                if variant == "special-type" and not any(
                    file_type == stat.S_IFIFO for _raw_name, file_type in state["a2_entry_types"]
                ):
                    raise SystemExit("stage3a2 unsupported directory entry type was not recorded")
                for value, preowned in state["a2_rejected_returns"]:
                    close_count = sum(
                        type(closed) is type(value) and closed == value
                        for closed in state["graph_close_calls"]
                    )
                    if close_count != (1 if preowned else 0):
                        raise SystemExit("stage3a2 rejected descriptor cleanup lifetime drifted")
                expected_outcome = state["a2_expected_outcome"]
                expected_private = stage3_a1_final_private if expected_outcome == "governed" else ()
                expected_borrowed = () if expected_outcome == "arbitrary" else stage3_a1_final_borrowed
                if (
                    tuple(state["a1_final_private_events"]) != expected_private
                    or tuple(state["a1_final_borrowed_events"]) != expected_borrowed
                ):
                    raise SystemExit("stage3a2 FP/FB safe suffix drifted")
                expected_safe_failure = stage3_a1_options(case).get("safe_failure")
                if state["a1_safe_failure_attempted"] != expected_safe_failure:
                    raise SystemExit("stage3a2 safe-successor failure injection drifted")
                expected_close_failure = stage3_a2_options(case).get("close_failure")
                if state["a1_close_failure_attempted"] != expected_close_failure:
                    raise SystemExit("stage3a2 outer close failure injection drifted")
                if variant in {
                    "real-close-then-raise",
                    "real-close-then-KeyboardInterrupt",
                    "real-close-then-KeyboardInterrupt-outer-close",
                } and state["a2_first_close_failure"] != fault_token:
                    raise SystemExit("stage3a2 first scan close failure identity drifted")
                if variant == "KeyboardInterrupt-post-fstat-error" and (
                    state["a2_original_interrupt"] != fault_token
                    or state["a2_first_body_failure"]
                    != stage3_a2_options(case).get("post_fstat_failure")
                    or expected_outcome != "arbitrary"
                    or expected_terminal != "KeyboardInterrupt"
                ):
                    raise SystemExit("stage3a2 original body interrupt precedence drifted")
                if variant == "wrong-digest-post-fstat-sentinel" and (
                    state["a2_first_body_failure"] != fault_token
                    or state["caught_exception"] is not state["a2_post_fstat_sentinel"]
                    or expected_terminal != "KeyboardInterrupt"
                ):
                    raise SystemExit("stage3a2 post-fstat sentinel was not first")
                if variant == "chunk-over-request-under-remaining":
                    chunks = state["a2_regular_chunks"]
                    expected_size = stage3_a2_options(case).get("regular_size")
                    if (
                        len(chunks) != 1
                        or len(chunks[0][2]) != chunks[0][1] + 1
                        or len(chunks[0][2]) > expected_size
                    ):
                        raise SystemExit("stage3a2 per-chunk cap mutation drifted")
                if variant in {"bytes-entry", "str-subclass-entry"}:
                    entries = state["a2_invalid_list_result"]
                    expected_type = bytes if variant == "bytes-entry" else StrSubclass
                    if len(entries) != 1 or type(entries[0]) is not expected_type:
                        raise SystemExit("stage3a2 exact list entry type mutation drifted")
                if expected_safe_failure in {"GB", "GB-KI"} and not state["gb_failed"]:
                    raise SystemExit("stage3a2 GB safe-successor failure was not observed")
                if variant == "identity-drift-GB" and (
                    state["a2_first_body_failure"] != fault_token
                    or state["a1_body_outcome"] != "governed"
                    or not state["gb_failed"]
                ):
                    raise SystemExit("stage3a2 first evidence failure was lost before GB")
                if expected_outcome != "arbitrary" and not state["graph_binding_events"]:
                    raise SystemExit("stage3a2 graph/evidence binding suffix was skipped")
                expected_bindings = [
                    token
                    for token in state["expected_graph_bindings"]
                    if token.split(":", 1)[1].encode("ascii") in state["graph_fds"]
                ]
                if (
                    expected_outcome != "arbitrary"
                    and (
                        state["graph_binding_events"] != expected_bindings
                        or len(state["graph_binding_successes"])
                        != len(expected_bindings) - (1 if state["gb_failed"] else 0)
                        or any(token not in expected_bindings for token in state["graph_binding_successes"])
                    )
                ):
                    raise SystemExit("stage3a2 complete dynamic binding sequence drifted")
                expected_closes = list(reversed(state["graph_owned"])) + [
                    state["private_parent_fd"],
                    state["private_ledger_fd"],
                ]
                if state["graph_close_calls"] != expected_closes:
                    raise SystemExit("stage3a2 reverse owner cleanup drifted")
                for fd in expected_closes:
                    try:
                        real_fstat(fd)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise SystemExit("stage3a2 retained owner did not report EBADF") from exc
                    else:
                        raise SystemExit("stage3a2 retained owner leaked")
                if variant in {
                    "real-close-then-KeyboardInterrupt",
                    "real-close-then-KeyboardInterrupt-outer-close",
                } and state["caught_exception"].__cause__ is not state["a2_scan_close_sentinel"]:
                    raise SystemExit("stage3a2 scan close cause identity drifted")
                if variant == "real-close-then-KeyboardInterrupt-outer-close" and (
                    state["a2_parent_close_raised"] is not state["a2_parent_close_sentinel"]
                ):
                    raise SystemExit("stage3a2 parent close sentinel identity drifted")
                expected_suffix = []
                if expected_outcome == "governed":
                    expected_suffix.append("final-private")
                if expected_outcome != "arbitrary":
                    expected_suffix.append("final-borrowed")
                    if not state["gb_failed"]:
                        expected_suffix.append("final-graph-bindings")
                expected_suffix.append("reverse-close-graph-P-L")
                if state["a1_suffix"] != expected_suffix or state["a1_phase"] != "cleanup":
                    raise SystemExit("stage3a2 lifecycle suffix or phase drifted")
                expected_post_calls = ["resource-getrlimit"]
                for descriptor in state["a2_expected_operations"]:
                    token = descriptor[0]
                    repeats = 1
                    if token.startswith("regular-pread:"):
                        label = token.split(":", 1)[1]
                        chunks = state["a2_chunks_by_label"].get(label)
                        if chunks is None and token == fault_token:
                            chunks = state["a2_regular_chunks"]
                        repeats = max(1, len(chunks or ()))
                    expected_post_calls.extend(token for _ in range(repeats))
                    if token == fault_token and expected_rlimit == 2:
                        expected_post_calls.append("resource-getrlimit-reread")
                expected_post_calls.extend(expected_borrowed)
                expected_post_calls.extend(("close-P", "close-L"))
                if state["post_a2_calls"] != expected_post_calls:
                    raise SystemExit("stage3a2 post-A2 call sequence drifted")
                if expected_outcome == "success":
                    check_stage3_a2_positive_body()
                if state["a2_close_uncertain"] and expected_terminal != "MutationError":
                    raise SystemExit("stage3a2 scan close uncertainty lost precedence")

            def check_stage3_a2_prefix():
                state = stage3_c0_state
                if (
                    state["stage3_case"] is not None
                    and state["stage3_case"][0] == "stage3a3-case"
                    and state["stage3_case"][1] == "held-root-canonical-absence"
                    and state["held_root_missing"]
                ):
                    if (
                        state["graph_events"] != state["expected_graph_events"]
                        or state["a2_operations"]
                        or not state["held_root_first_fp_bridge"]
                    ):
                        raise SystemExit("stage3a3 held root RED prefix drifted")
                    return
                if (
                    state["graph_events"] != state["expected_graph_events"]
                    or tuple(state["a2_operations"])
                    != tuple(descriptor[0] for descriptor in state["a2_expected_operations"])
                    or state["a2_expected_outcome"] != "success"
                ):
                    raise SystemExit("stage3a3 A2 prefix drifted")
                expected_fsencode = [
                    (descriptor[3][0], os.fsencode(descriptor[3][0]))
                    for descriptor in state["a2_expected_operations"]
                    if descriptor[0].startswith("fsencode")
                ]
                if state["a2_fsencode_calls"] != expected_fsencode:
                    raise SystemExit("stage3a3 A2 fsencode prefix drifted")
                check_stage3_a2_positive_body()

            def check_stage3_a3(expected_terminal):
                state = stage3_c0_state
                case = state["stage3_case"]
                options = stage3_a2_options(case)
                body_tokens = tuple(descriptor[0] for descriptor in state["a3_body_operations"])
                absence_tokens = tuple(descriptor[0] for descriptor in state["a3_absence_operations"])
                fault_token, fault_variant = stage3_a3_fault(case)
                held_root_case = (
                    case[0] == "stage3a3-case"
                    and case[1] == "held-root-canonical-absence"
                )
                held_root_fallback = (
                    held_root_case
                    and state["held_root_missing"]
                    and state["held_root_first_fp_bridge"]
                    and expected_terminal == "MutationError"
                )
                held_root_early_fallback = held_root_fallback and not state["a3_started"]
                observed_body_tokens = tuple(state["a3_body_events"])
                if not state["a3_started"]:
                    if held_root_early_fallback:
                        expected_body = ()
                    elif (
                        case[0] == "stage3a3-case"
                        and case[1] == "relative-primary"
                        and tuple(state["a1_final_private_events"]) == ()
                        and tuple(state["a1_final_borrowed_events"]) == stage3_a1_final_borrowed
                        and state["a1_phase"] == "cleanup"
                    ):
                        raise SystemExit(
                            "stage3a3 canonical absence was not the final filesystem observation"
                        )
                    else:
                        raise SystemExit("stage3a3 executable case performed no A3 operation")
                else:
                    expected_body = body_tokens
                if fault_token in body_tokens:
                    end = body_tokens.index(fault_token) + 1
                    if fault_variant == "mismatch" and fault_token.startswith("symlink-held-fstat"):
                        end += 1
                    elif (
                        fault_variant in {"empty", "4097-bytes", "mismatch"}
                        and fault_token.startswith("readlink2:")
                    ):
                        end += 2
                    elif (
                        fault_variant == "mismatch"
                        and fault_token.startswith("target-parent-stat:")
                        and end < len(body_tokens)
                        and body_tokens[end] == fault_token.replace("parent-stat", "held-fstat")
                    ):
                        end += 1
                    expected_body = body_tokens[:end]
                if options.get("expected_route", "success") == "follow41":
                    refused = next(
                        token
                        for token in body_tokens
                        if token == "symlink-parent-stat0:41"
                    )
                    expected_body = body_tokens[: body_tokens.index(refused) + 1]
                disjoint_first_root_only = False
                if case[0] == "stage3a3-case" and case[1] == "disjoint-symlink-roots":
                    if observed_body_tokens not in (state["disjoint_first_root_tokens"], body_tokens):
                        raise SystemExit("stage3a3 disjoint symlink body operation order drifted")
                    disjoint_first_root_only = observed_body_tokens == state["disjoint_first_root_tokens"]
                    expected_body = observed_body_tokens
                if (
                    case[0] == "stage3a3-case"
                    and case[1] == "multi-component-canonical-absence"
                    and expected_terminal == "MutationError"
                    and tuple(state["a3_body_events"]) == multi_component_absence_tokens[:-1]
                    and not state["a3_target_absence_errnos"]
                ):
                    expected_body = multi_component_absence_tokens[:-1]
                if (
                    case[0] == "stage3a3-case"
                    and case[1] == "multi-component-canonical-enotdir"
                    and expected_terminal == "MutationError"
                    and tuple(state["a3_body_events"]) == multi_component_enotdir_tokens[:-1]
                    and not state["a3_target_absence_errnos"]
                ):
                    expected_body = multi_component_enotdir_tokens[:-1]
                if held_root_fallback and not held_root_early_fallback:
                    expected_body = held_root_body_prefix_tokens
                if tuple(state["a3_body_events"]) != expected_body:
                    raise SystemExit("stage3a3 body operation order drifted")
                route = options.get("expected_route", "success")
                if route == "success" and stage3_case_composes_a3(case) and (
                    state["a1_body_outcome"] == "governed"
                    or expected_terminal == "MutationError"
                    and not state["a3_absence_events"]
                    and not state["a3_markers"]
                ):
                    route = "governed"
                expected_absence = (
                    absence_tokens
                    if route in {"success", "absence-failure", "absence-arbitrary"}
                    else ()
                )
                if fault_token in absence_tokens:
                    end = absence_tokens.index(fault_token) + 1
                    if (
                        fault_variant == "mismatch"
                        and fault_token.startswith("absent-boundary-parent:")
                        and end < len(absence_tokens)
                        and absence_tokens[end]
                        == fault_token.replace("boundary-parent", "boundary-held")
                    ):
                        end += 1
                    expected_absence = absence_tokens[:end]
                if route == "success" and tuple(state["a3_absence_events"]) != expected_absence:
                    raise SystemExit("stage3a3 canonical absence was not the final filesystem observation")
                if route.startswith("absence-") and tuple(state["a3_absence_events"]) != expected_absence:
                    raise SystemExit("stage3a3 terminal absence mutation order drifted")
                if route not in {"success", "absence-failure", "absence-arbitrary"} and state["a3_absence_events"]:
                    raise SystemExit("stage3a3 rejected body reached canonical absence")
                if absence_tokens and not held_root_case:
                    if any(
                        not (
                            absence_tokens[index].startswith("absent-boundary-parent:")
                            and absence_tokens[index + 1].startswith("absent-boundary-held:")
                            and absence_tokens[index + 2].startswith("absent-terminal:")
                        )
                        for index in range(0, len(absence_tokens), 3)
                    ):
                        raise SystemExit("stage3a3 canonical absence order drifted")
                    if route == "success" and (
                        not state["a3_absence_complete"]
                        or not state["a3_absence_events"][-1].startswith("absent-terminal:")
                        or tuple(value for _token, value in state["a3_absence_errnos"])
                        != (errno.ENOENT, errno.ENOTDIR, errno.ENOENT)
                    ):
                        raise SystemExit("stage3a3 canonical absence was not the final filesystem observation")
                elif held_root_case and route == "success" and (
                    not state["a3_absence_complete"]
                    or tuple(state["a3_absence_events"]) != held_root_absence_tokens
                    or tuple(value for _token, value in state["a3_absence_errnos"])
                    != (errno.ENOENT,)
                ):
                    raise SystemExit("stage3a3 held root canonical absence was not replayed")
                elif (
                    route == "success"
                    and not held_root_case
                    and state["a3_markers"] != ["canonical-absence-empty"]
                ):
                    raise SystemExit("stage3a3 empty canonical-absence ledger was not explicit")
                expected_boundary_tokens = tuple(
                    token
                    for token in expected_absence
                    if token.startswith(("absent-boundary-parent:", "absent-boundary-held:"))
                    and not (token == fault_token and fault_variant in {"error", "KeyboardInterrupt"})
                )
                expected_boundary_values = []
                injection_after = {
                    token: after for token, _before, after in state["a3_injections"]
                }
                for token in expected_boundary_tokens:
                    if held_root_case:
                        value = identity(state["a2_row_stats"]["external-root"])
                        expected_boundary_values.append(injection_after.get(token, value))
                        continue
                    row_label = "repo-abs-blocker" if "/blocker/child" in token else "repo-abs"
                    value = identity(state["a2_row_stats"][row_label])
                    expected_boundary_values.append(injection_after.get(token, value))
                if (
                    tuple(token for token, _value in state["a3_boundary_identities"])
                    != expected_boundary_tokens
                    or tuple(value for _token, value in state["a3_boundary_identities"])
                    != tuple(expected_boundary_values)
                ):
                    raise SystemExit("stage3a3 canonical absence boundary identities drifted")
                expected_absence_errnos = []
                for token in expected_absence:
                    if not token.startswith("absent-terminal:"):
                        continue
                    if token == fault_token and fault_variant in {"success", "KeyboardInterrupt"}:
                        continue
                    expected_absence_errnos.append(
                        errno.EIO
                        if token == fault_token and fault_variant == "wrong-errno"
                        else errno.ENOTDIR
                        if token.endswith(":ENOTDIR")
                        else errno.ENOENT
                    )
                if tuple(state["a3_absence_errnos"]) != tuple(
                    (token, value)
                    for token, value in zip(
                        (token for token in expected_absence if token.startswith("absent-terminal:")),
                        expected_absence_errnos,
                    )
                ):
                    raise SystemExit("stage3a3 canonical absence errno identity drifted")
                if state["unauthorized_calls"] or state["unauthorized_attributes"]:
                    raise SystemExit("stage3a3 performed an unauthorized later observation")
                if (
                    route in {"success", "follow41", "absence-failure", "absence-arbitrary"}
                    and not state["a3_forbid_later_filesystem"]
                ):
                    raise SystemExit("stage3a3 terminal filesystem sentinel was not armed")

                open_tokens = [token for token in expected_body if token.startswith("symlink-open:")]
                if fault_token in open_tokens:
                    open_tokens = open_tokens[: open_tokens.index(fault_token)]
                admitted = [int(token.rsplit(":", 1)[1]) for token in open_tokens]
                if (
                    state["a3_owned_occurrences"] != admitted
                    or len(state["a3_fds"]) != len(admitted)
                    or len(set(state["a3_fds"].values())) != len(admitted)
                    or any(state["a3_fds"][occurrence] not in state["graph_owned"] for occurrence in admitted)
                ):
                    raise SystemExit("stage3a3 occurrence ownership drifted")
                for token, active in state["a3_open_active"]:
                    occurrence = int(token.rsplit(":", 1)[1])
                    if occurrence in state["a3_fds"] and state["a3_fds"][occurrence] in active:
                        raise SystemExit("stage3a3 open did not validate the complete active owner set")
                    earlier = {
                        fd
                        for prior, fd in state["a3_fds"].items()
                        if prior < occurrence
                    }
                    fixed = {
                        state["borrowed_ledger_fd"],
                        state["borrowed_parent_fd"],
                        state["private_ledger_fd"],
                        state["private_parent_fd"],
                        *(set(state["graph_owned"]) - set(state["a3_fds"].values())),
                    }
                    if set(active) != fixed | earlier:
                        raise SystemExit("stage3a3 active owner collision set was incomplete")
                if (
                    fault_token is not None
                    and fault_token.startswith("symlink-parent-stat0:")
                    and fault_variant in {"error", "mismatch"}
                ):
                    occurrence = int(fault_token.rsplit(":", 1)[1])
                    key = f"@a3:link:{occurrence}".encode("ascii")
                    if occurrence not in state["a3_owned_occurrences"] or key in state["graph_fds"]:
                        raise SystemExit("stage3a3 failed parent bracket promoted an occurrence")

                read_attempts = tuple(
                    token for token in expected_body if token.startswith("readlink")
                )
                nonreturning = fault_variant in {"error", "KeyboardInterrupt"}
                returned_reads = tuple(
                    token for token in read_attempts if not (nonreturning and token == fault_token)
                )
                if (
                    tuple(state["a3_readlink_attempts"]) != read_attempts
                    or tuple(token for token, _value in state["a3_native_readlinks"])
                    != returned_reads
                    or tuple(token for token, _value in state["a3_readlinks"])
                    != returned_reads
                ):
                    raise SystemExit("stage3a3 readlink attempt/return prefix drifted")
                native_by_token = dict(state["a3_native_readlinks"])
                returned_by_token = dict(state["a3_readlinks"])
                for token in returned_reads:
                    occurrence = int(token.rsplit(":", 1)[1])
                    expected_raw = options.get("raw_targets", {}).get(
                        occurrence, options.get("raw_target", b"./enum/../target")
                    )
                    native = native_by_token[token]
                    if type(native) is not type(expected_raw) or native != expected_raw:
                        raise SystemExit("stage3a3 native readlink result drifted")
                    if token != fault_token and returned_by_token[token] != native:
                        raise SystemExit("stage3a3 positive readlink result was transformed")
                fsencode_attempts = tuple(
                    token for token in expected_body if token.startswith("target-fsencode")
                )
                returned_fsencodes = tuple(
                    token
                    for token in fsencode_attempts
                    if not (fault_variant == "error" and token == fault_token)
                )
                if (
                    tuple(state["a3_fsencode_attempts"]) != fsencode_attempts
                    or len(state["a3_fsencode_calls"]) != len(returned_fsencodes)
                ):
                    raise SystemExit("stage3a3 fsencode attempt/return prefix drifted")
                if any(type(value) is bytes for value in returned_by_token.values()) and fsencode_attempts:
                    raise SystemExit("stage3a3 bytes target reached fsencode")
                if len(fsencode_attempts) != sum(
                    type(value) is str for value in returned_by_token.values()
                ):
                    raise SystemExit("stage3a3 str target fsencode was not immediate and singular")
                raw_values = tuple(value for _token, value in state["a3_readlinks"])
                for occurrence in admitted[:40]:
                    reads = [
                        (token, value)
                        for token, value in state["a3_readlinks"]
                        if token.endswith(f":{occurrence}")
                    ]
                    if not reads:
                        continue
                    if fault_token is not None and any(token == fault_token for token, _value in reads):
                        observed = reads[-1][1]
                        valid_fault = (
                            fault_variant == "bytes-subclass" and type(observed) is BytesSubclass
                            or fault_variant == "str-subclass" and type(observed) is StrSubclass
                            or fault_variant == "other-type" and type(observed) is int
                            or fault_variant == "empty" and observed == b""
                            or fault_variant == "4097-bytes" and type(observed) is bytes and len(observed) == 4097
                            or fault_variant == "mismatch" and observed == b"different"
                        )
                        if not valid_fault:
                            raise SystemExit("stage3a3 readlink mutation was not operational")
                        if fault_variant in {"empty", "4097-bytes", "mismatch"} and (
                            not fault_token.startswith("readlink2:")
                            or len(reads) != 2
                            or len([token for token in returned_reads if token.endswith(f":{occurrence}")]) != 2
                        ):
                            raise SystemExit("stage3a3 second-read mutation lacked two observations")
                        continue
                    expected_raw = options.get("raw_targets", {}).get(
                        occurrence, options.get("raw_target", b"./enum/../target")
                    )
                    locator = reads[0][0].split(":", 1)[1].rsplit(":", 1)[0].encode("ascii")
                    row = state["a2_supplied_rows"].get(locator)
                    encoded = os.fsencode(expected_raw)
                    expected_read_count = sum(
                        token.endswith(f":{occurrence}") for token in returned_reads
                    )
                    expected_row_size = options.get("symlink_row_size", len(encoded))
                    expected_row_digest = options.get(
                        "symlink_row_digest", hashlib.sha256(encoded).hexdigest()
                    )
                    if (
                        len(reads) != expected_read_count
                        or any(
                            type(value) is not type(expected_raw) or value != expected_raw
                            for _token, value in reads
                        )
                        or row is None
                        or row[1:4] != ("symlink", "probe", "present")
                        or row[4] != 0o777
                        or row[5] != expected_row_size
                        or row[6] != expected_row_digest
                    ):
                        raise SystemExit("stage3a3 exact raw target S3/T3 evidence drifted")
                identity_by_occurrence = {}
                for token, value in state["a3_symlink_identities"]:
                    identity_by_occurrence.setdefault(int(token.rsplit(":", 1)[1]), []).append(value)
                expected_identity_tokens = [
                    token
                    for token in expected_body
                    if token.startswith(("symlink-held-fstat", "symlink-parent-stat"))
                    and not (token == fault_token and fault_variant in {"error", "KeyboardInterrupt"})
                ]
                if tuple(token for token, _value in state["a3_symlink_identities"]) != tuple(expected_identity_tokens):
                    raise SystemExit("stage3a3 symlink identity observation order drifted")
                for occurrence in admitted:
                    values = identity_by_occurrence.get(occurrence, ())
                    expected_count = sum(token.endswith(f":{occurrence}") for token in expected_identity_tokens)
                    mismatch_here = (
                        fault_token is not None
                        and fault_token.startswith(("symlink-held-fstat", "symlink-parent-stat"))
                        and fault_token.endswith(f":{occurrence}")
                        and fault_variant == "mismatch"
                    )
                    held_stat0_failed = (
                        fault_token == f"symlink-held-fstat0:{occurrence}"
                        and fault_variant in {"error", "KeyboardInterrupt"}
                    )
                    mode_invalid = bool(values) and not stat.S_ISLNK(values[0][4])
                    if (
                        len(values) != expected_count
                        or not values and not held_stat0_failed
                        or mode_invalid
                        or not held_stat0_failed
                        and not mismatch_here
                        and len(set(values)) != 1
                    ):
                        raise SystemExit("stage3a3 symlink identity bracket drifted")
                    if held_stat0_failed and f"@a3:link:{occurrence}".encode("ascii") in state["graph_fds"]:
                        raise SystemExit("stage3a3 failed held stat0 promoted an occurrence")
                for token, value in state["a3_symlink_identities"]:
                    occurrence = int(token.rsplit(":", 1)[1])
                    locator = next(
                        open_token.split(":", 1)[1].rsplit(":", 1)[0].encode("ascii")
                        for open_token in body_tokens
                        if open_token.startswith("symlink-open:")
                        and open_token.endswith(f":{occurrence}")
                    )
                    row = state["a2_supplied_rows"].get(locator)
                    if (
                        not stat.S_ISLNK(value[4])
                        or row is None
                        or row[4] != 0o777
                        or stat.S_IMODE(value[4]) != row[4]
                    ):
                        raise SystemExit("stage3a3 symlink mode evidence drifted")
                if fault_variant == "mismatch" and fault_token.startswith(("symlink-", "target-", "absent-")) and not any(
                    token == fault_token and before != after
                    for token, before, after in state["a3_injections"]
                ):
                    raise SystemExit("stage3a3 identity mutation was not operational")
                if 41 in admitted and any(token.endswith(":41") for token in read_attempts):
                    raise SystemExit("stage3a3 refused occurrence 41 reached readlink")

                target_tokens = [
                    token
                    for token in expected_body
                    if token.startswith(("target-parent-stat", "target-held-fstat"))
                    and not (token == fault_token and fault_variant in {"error", "KeyboardInterrupt"})
                ]
                if case[0] == "stage3a3-case":
                    expected_target_counts = {
                        "relative-primary": 4,
                        "absolute-external-str": 2 * (len(external_literal_relations) + 1),
                        "repeated-slash-vendor": 4,
                        "root-clamped-dotdot": 2 * (len(root_literal_relations) + 1),
                        "trailing-directory": 2,
                        "trailing-nondirectory": 2,
                        "chain40": 41,
                        "chain41-refused": 40,
                        "nested-trailing-slash-regular": 3,
                        "no-symlink-ledger": 0,
                        "canonical-absence-empty": 4,
                        "a3-close-real-then-raise": 4,
                        "disjoint-symlink-roots": 4,
                        "reviewed-symlink-target-absence": 2,
                        "multi-component-canonical-absence": 2,
                        "multi-component-canonical-enotdir": 4,
                        "held-root-canonical-absence": 1,
                        "symlink-size-mismatch": 0,
                        "symlink-digest-mismatch": 0,
                        "missing-reviewed-final-row": 1,
                        "final-locator-mismatch": 1,
                        "final-namespace-mismatch": 1,
                        "intermediate-unreviewed-symlink": 1,
                        "unreviewed-held-final-directory": 2,
                    }
                    target_descriptors = (
                        expected_body
                        if held_root_fallback
                        or case[1] == "disjoint-symlink-roots" and disjoint_first_root_only
                        else body_tokens
                    )
                    described_targets = sum(
                        token.startswith(("target-parent-stat", "target-held-fstat"))
                        for token in target_descriptors
                    )
                    expected_target_count = expected_target_counts[case[1]]
                    if held_root_fallback:
                        expected_target_count = 0
                    if case[1] == "disjoint-symlink-roots" and disjoint_first_root_only:
                        expected_target_count = 2
                    if described_targets != expected_target_count:
                        raise SystemExit("stage3a3 successful target components were incomplete")
                target_values = [value for _token, value in state["a3_target_identities"]]
                if tuple(token for token, _value in state["a3_target_identities"]) != tuple(target_tokens):
                    raise SystemExit("stage3a3 target edge/held identity drifted")
                paired_target_values = target_values
                if held_root_case and not held_root_fallback:
                    if (
                        target_tokens
                        != ["target-held-fstat:1:external:/root-missing/leaf"]
                        or target_values
                        != [identity(state["a2_row_stats"]["external-root"])]
                    ):
                        raise SystemExit("stage3a3 held root target identity drifted")
                    paired_target_values = []
                if (
                    fault_token
                    and fault_token.startswith("symlink-open:")
                    and target_tokens
                    and target_tokens[-1].startswith("target-parent-stat:")
                ):
                    paired_target_values = paired_target_values[:-1]
                if case[0] == "stage3a3-case" and case[1] in {"chain40", "chain41-refused"}:
                    final_pair = 2 if case[1] == "chain40" else 0
                    intermediate = target_values[:-final_pair] if final_pair else target_values
                    intermediate_tokens = target_tokens[:-final_pair] if final_pair else target_tokens
                    if any(not stat.S_ISLNK(value[4]) for value in intermediate):
                        raise SystemExit("stage3a3 chain target relation was not a symlink")
                    for token, value in zip(intermediate_tokens, intermediate):
                        occurrence = int(token.split(":", 2)[1])
                        next_identities = identity_by_occurrence.get(occurrence + 1, ())
                        if not next_identities or value != next_identities[0]:
                            raise SystemExit("stage3a3 chain target did not bind the next held stat0")
                    paired_target_values = target_values[-final_pair:] if final_pair else []
                if case[0] == "stage3a3-case" and case[1] == "nested-trailing-slash-regular":
                    intermediate = target_values[:-2]
                    intermediate_tokens = target_tokens[:-2]
                    held_stat0 = identity_by_occurrence.get(2, ())
                    if (
                        len(intermediate) != 1
                        or len(intermediate_tokens) != 1
                        or not stat.S_ISLNK(intermediate[0][4])
                        or not held_stat0
                        or intermediate[0] != held_stat0[0]
                    ):
                        raise SystemExit("stage3a3 nested intermediate relation did not bind occurrence 2 held stat0")
                    paired_target_values = target_values[-2:]
                if len(paired_target_values) % 2 and target_tokens[-1].startswith("target-parent-stat:"):
                    paired_target_values = paired_target_values[:-1]
                target_pair_drift = len(paired_target_values) % 2 != 0
                target_injection = next(
                    (
                        (before, after)
                        for token, before, after in state["a3_injections"]
                        if token == fault_token
                    ),
                    None,
                )
                for index in range(0, len(paired_target_values) - 1, 2):
                    pair_tokens = target_tokens[index : index + 2]
                    pair_values = paired_target_values[index : index + 2]
                    if fault_variant == "mismatch" and fault_token in pair_tokens:
                        fault_index = pair_tokens.index(fault_token)
                        if (
                            target_injection is None
                            or pair_values[fault_index] != target_injection[1]
                            or pair_values[1 - fault_index] != target_injection[0]
                        ):
                            target_pair_drift = True
                    elif pair_values[0] != pair_values[1]:
                        target_pair_drift = True
                if target_pair_drift:
                    raise SystemExit("stage3a3 target edge/held identity drifted")
                target_row = options.get(
                    "target_row",
                    (
                        b"repo:/target", "repo", "read", "present", 0o600, 2,
                        "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5",
                    ),
                )
                if target_values and target_row is not None:
                    locator, klass, access, result, mode, size, digest = target_row
                    locator = options.get("target_locator", locator)
                    klass = options.get("target_namespace", klass)
                    size = options.get("target_row_size", size)
                    digest = options.get("target_row_digest", digest)
                    if (
                        state["a2_supplied_rows"].get(locator)
                        != (locator, klass, access, result, mode, size, digest)
                        or stat.S_IMODE(target_values[-1][4]) != mode
                        or klass != "directory" and target_values[-1][6] != size
                    ):
                        raise SystemExit("stage3a3 literal reviewed target row drifted")
                if case[0] == "stage3a3-case" and case[1] == "reviewed-symlink-target-absence":
                    target_absence_token = reviewed_target_absence_tokens[-1]
                    if (
                        tuple(state["a3_target_absence_errnos"])
                        != ((target_absence_token, errno.ENOENT),)
                        or state["a2_supplied_rows"].get(b"repo:/abs")
                        != (
                            b"repo:/abs", "directory", "probe", "present", 0o700, 10,
                            "dff711efda3385276e20031e3c33c758adb07840d3181fb20b23d4d00af6543f",
                        )
                        or state["a3_supplied_absence_rows"].get(b"repo:/abs/a-missing")
                        != (b"repo:/abs/a-missing", "absent", "probe", "ENOENT")
                        or not state["reviewed_target_absence_fp_bridge"]
                    ):
                        raise SystemExit("stage3a3 reviewed target absence evidence drifted")
                    if expected_terminal == "SystemExit(77)" and state["target_absence_missing"]:
                        raise SystemExit("stage3a3 corrected target absence took RED fallback")
                    if expected_terminal == "MutationError" and not state["target_absence_missing"]:
                        raise SystemExit("stage3a3 target absence RED fallback was not observed")
                if case[0] == "stage3a3-case" and case[1] == "multi-component-canonical-absence":
                    immediate_token = multi_component_absence_tokens[-1]
                    if (
                        state["a2_supplied_rows"].get(b"repo:/abs")
                        != (
                            b"repo:/abs", "directory", "probe", "present", 0o700, 10,
                            "dff711efda3385276e20031e3c33c758adb07840d3181fb20b23d4d00af6543f",
                        )
                        or state["a3_supplied_absence_rows"].get(b"repo:/abs/a-missing/leaf")
                        != (b"repo:/abs/a-missing/leaf", "absent", "probe", "ENOENT")
                    ):
                        raise SystemExit("stage3a3 multi-component absence evidence drifted")
                    if expected_terminal == "SystemExit(77)":
                        if tuple(state["a3_target_absence_errnos"]) != ((immediate_token, errno.ENOENT),):
                            raise SystemExit("stage3a3 multi-component immediate absence evidence drifted")
                        if state["multi_component_absence_missing"]:
                            raise SystemExit("stage3a3 corrected multi-component absence took RED fallback")
                        if not state["multi_component_absence_fp_bridge"]:
                            raise SystemExit("stage3a3 multi-component immediate absence FP bridge was not observed")
                    if expected_terminal == "MutationError":
                        if (
                            tuple(state["a3_body_events"]) != multi_component_absence_tokens[:-1]
                            or state["a3_target_absence_errnos"]
                            or state["a3_absence_events"]
                            or state["a3_absence_errnos"]
                            or state["multi_component_absence_fp_bridge"]
                        ):
                            raise SystemExit("stage3a3 multi-component immediate absence RED accounting drifted")
                        if not state["multi_component_absence_missing"]:
                            raise SystemExit("stage3a3 multi-component absence RED fallback was not observed")
                if case[0] == "stage3a3-case" and case[1] == "multi-component-canonical-enotdir":
                    immediate_token = multi_component_enotdir_tokens[-1]
                    if (
                        state["a2_supplied_rows"].get(b"repo:/abs/blocker")
                        != (
                            b"repo:/abs/blocker", "repo", "probe", "present", 0o600, 1,
                            "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c",
                        )
                        or state["a3_supplied_absence_rows"].get(
                            b"repo:/abs/blocker/child/leaf"
                        )
                        != (b"repo:/abs/blocker/child/leaf", "absent", "probe", "ENOTDIR")
                    ):
                        raise SystemExit("stage3a3 multi-component ENOTDIR evidence drifted")
                    if expected_terminal == "SystemExit(77)":
                        if tuple(state["a3_target_absence_errnos"]) != (
                            (immediate_token, errno.ENOTDIR),
                        ):
                            raise SystemExit("stage3a3 multi-component ENOTDIR immediate evidence drifted")
                        if state["multi_component_enotdir_missing"]:
                            raise SystemExit("stage3a3 corrected multi-component ENOTDIR took RED fallback")
                        if not state["multi_component_enotdir_fp_bridge"]:
                            raise SystemExit("stage3a3 multi-component ENOTDIR FP bridge was not observed")
                    if expected_terminal == "MutationError":
                        if (
                            tuple(state["a3_body_events"]) != multi_component_enotdir_tokens[:-1]
                            or state["a3_target_absence_errnos"]
                            or state["a3_absence_events"]
                            or state["a3_absence_errnos"]
                            or state["multi_component_enotdir_fp_bridge"]
                        ):
                            raise SystemExit("stage3a3 multi-component ENOTDIR RED accounting drifted")
                        if not state["multi_component_enotdir_missing"]:
                            raise SystemExit("stage3a3 multi-component ENOTDIR RED fallback was not observed")
                if (
                    case[0] == "stage3a3-case"
                    and case[1] in {"chain40", "chain41-refused"}
                ):
                    if b"repo:/link" in state["a2_supplied_rows"]:
                        raise SystemExit("stage3a3 chain improperly retained the base link row")
                    chain_count = 40 if case[1] == "chain40" else 41
                    expected_locators = {
                        f"repo:/chain{index:02d}".encode("ascii")
                        for index in range(chain_count)
                    }
                    observed_locators = {
                        token.split(":", 1)[1].rsplit(":", 1)[0].encode("ascii")
                        for token in read_attempts
                        if token.startswith("readlink1:")
                    }
                    if observed_locators != expected_locators - ({b"repo:/chain40"} if chain_count == 41 else set()):
                        raise SystemExit("stage3a3 chain entry/intermediate locators drifted")

                expected_bindings = tuple(
                    token
                    for token in state["expected_graph_bindings"]
                    if token.split(":", 1)[1].encode("ascii") in state["graph_fds"]
                )
                promoted_occurrences = tuple(
                    int(token.rsplit(":", 1)[1])
                    for token in state["a3_readlink_attempts"]
                    if token.startswith("readlink1:")
                )
                for occurrence in admitted:
                    key = f"@a3:link:{occurrence}".encode("ascii")
                    if (key in state["graph_fds"]) != (occurrence in promoted_occurrences):
                        raise SystemExit("stage3a3 promotion preceded or followed readlink1")
                actual_a3_bindings = tuple(
                    token
                    for token in expected_bindings
                    if token.startswith(("bind-held-fstat:@a3:link:", "bind-parent-name-stat:@a3:link:"))
                )
                expected_a3_bindings = tuple(
                    token
                    for occurrence in promoted_occurrences
                    for token in (
                        f"bind-held-fstat:@a3:link:{occurrence}",
                        f"bind-parent-name-stat:@a3:link:{occurrence}",
                    )
                )
                if actual_a3_bindings != expected_a3_bindings:
                    raise SystemExit("stage3a3 dynamic binding inventory drifted")
                if case[0] == "stage3a3-case" and case[1] in {"chain40", "chain41-refused"}:
                    if promoted_occurrences != tuple(range(1, 41)):
                        raise SystemExit("stage3a3 chain promotion inventory drifted")
                    if case[1] == "chain40" and len(actual_a3_bindings) != 80:
                        raise SystemExit("stage3a3 chain40 GB binding count drifted")
                    if case[1] == "chain41-refused" and state["graph_binding_events"]:
                        raise SystemExit("stage3a3 follow41 entered graph binding")
                if case[0] == "stage3a1-gb-mutation":
                    selected = expected_bindings[case[1]]
                    expected_successes = tuple(
                        token for token in expected_bindings if token != selected
                    )
                    if (
                        not state["gb_failed"]
                        or selected in state["graph_binding_successes"]
                        or tuple(state["graph_binding_successes"]) != expected_successes
                    ):
                        raise SystemExit("stage3a1 selected GB mutation complement drifted")
                if case[0] == "stage3a2-positive":
                    if options.get("close_failure") == "parent" and (
                        state["a1_close_failure_attempted"] != "parent"
                    ):
                        raise SystemExit("stage3a2 parent close failure identity drifted")
                    selected = options.get("full_binding")
                    if selected is not None:
                        expected_successes = tuple(
                            token for token in expected_bindings if token != selected
                        )
                        if (
                            not state["gb_failed"]
                            or selected in state["graph_binding_successes"]
                            or tuple(state["graph_binding_successes"]) != expected_successes
                        ):
                            raise SystemExit("stage3a2 full-binding success complement drifted")
                if route not in {"arbitrary", "absence-arbitrary", "follow41"} and (
                    tuple(state["a1_final_private_events"]) != stage3_a1_final_private
                    or tuple(state["a1_final_borrowed_events"]) != stage3_a1_final_borrowed
                    or tuple(state["graph_binding_events"]) != expected_bindings
                ):
                    raise SystemExit("stage3a3 FP/FB/GB suffix drifted")
                if route in {"arbitrary", "follow41"} and (
                    state["a1_final_private_events"]
                    or state["a1_final_borrowed_events"]
                    or state["graph_binding_events"]
                ):
                    raise SystemExit("stage3a3 cleanup-only route entered the safe suffix")
                if state["a3_absence_events"] and state["a3_absence_suffix_snapshot"] != (
                    stage3_a1_final_private,
                    stage3_a1_final_borrowed,
                    expected_bindings,
                ):
                    raise SystemExit("stage3a3 absence preceded FP/FB/GB")
                expected_closes = list(reversed(state["graph_owned"])) + [
                    state["private_parent_fd"], state["private_ledger_fd"]
                ]
                if state["graph_close_calls"] != expected_closes:
                    raise SystemExit("stage3a3 reverse occurrence cleanup drifted")
                if options.get("a3_close_failure") and state["a3_close_failure"] is None:
                    raise SystemExit("stage3a3 retained FD close uncertainty was not injected")
                if options.get("a3_close_failure") and state["caught_exception"].__cause__ is not state["a3_close_sentinel"]:
                    raise SystemExit("stage3a3 retained FD close sentinel cause drifted")
                if route == "follow41" and (
                    state["a3_first_body_failure"] != "symlink-parent-stat0:41"
                    or b"@a3:link:41" in state["graph_fds"]
                    or not state["a3_forbid_later_filesystem"]
                ):
                    raise SystemExit("stage3a3 occurrence 41 refusal identity drifted")
                if route in {"governed", "capacity"} and fault_token is not None and state["a3_first_body_failure"] != fault_token:
                    raise SystemExit("stage3a3 first governed failure identity drifted")
                expected_rlimit_count = 2 if fault_variant is not None and fault_variant.startswith("EMFILE") else 1
                if (
                    len(state["getrlimit"]) != expected_rlimit_count
                    or state["getrlimit"][0][1] != state["rlimit_baseline"]
                    or state["a1_emfile_pending"]
                ):
                    raise SystemExit("stage3a3 EMFILE RLIMIT receipt drifted")
                if fault_variant == "EMFILE-rlimit-same" and state["getrlimit"][1][1] != state["rlimit_baseline"]:
                    raise SystemExit("stage3a3 unchanged RLIMIT reread drifted")
                if fault_variant == "EMFILE-rlimit-drift" and state["getrlimit"][1][1] == state["rlimit_baseline"]:
                    raise SystemExit("stage3a3 drifted RLIMIT reread drifted")
                if route in {"arbitrary", "absence-arbitrary"} and state["a3_original_interrupt"] != fault_token:
                    raise SystemExit("stage3a3 original interrupt identity drifted")
                expected_safe_failure = options.get("safe_failure")
                if expected_safe_failure is not None and state["a1_safe_failure_attempted"] != expected_safe_failure:
                    raise SystemExit("stage3a3 safe suffix failure identity drifted")
                if expected_safe_failure == "GB" and state["a3_later_gb_failure"] != expected_bindings[0]:
                    raise SystemExit("stage3a3 later GB failure identity drifted")
                expected_route_terminal = (
                    "SystemExit(77)" if route in {"success", "capacity"} and not options.get("a3_close_failure") else
                    "KeyboardInterrupt" if route in {"arbitrary", "absence-arbitrary"} and not options.get("a3_close_failure") else
                    "MutationError"
                )
                terminal_after_successful_absence = (
                    stage3_case_composes_a3(case)
                    and route == "success"
                    and expected_terminal == "MutationError"
                    and (
                        state["a3_absence_complete"]
                        or state["a3_markers"] == ["canonical-absence-empty"]
                    )
                )
                if expected_terminal != expected_route_terminal and not terminal_after_successful_absence:
                    raise SystemExit("stage3a3 terminal route drifted")
                if state["a1_phase"] != "cleanup":
                    raise SystemExit("stage3a3 lifecycle did not reach cleanup")
                if case[0] == "stage3a3-case" and case[1] == "disjoint-symlink-roots":
                    if state["disjoint_root_missing"] != disjoint_first_root_only:
                        raise SystemExit("stage3a3 disjoint root transition flag drifted")
                    if disjoint_first_root_only:
                        raise SystemExit("stage3a3 disjoint symlink root was not replayed")

            def run_case(
                label,
                expected,
                overrides=None,
                patches=(),
                borrowed=(),
                postcheck=None,
                custody=None,
                full_a2=False,
                stage3_case=None,
            ):
                nonlocal stage3_c0_state
                if full_a2 and not stage3_ready:
                    deferred_full_a2.append(
                        (
                            label,
                            expected,
                            overrides,
                            patches,
                            borrowed,
                            borrowed == base_borrowed,
                            postcheck,
                            custody,
                            stage3_case,
                        )
                    )
                    return
                call_kwargs = dict(valid)
                if overrides:
                    call_kwargs.update(overrides)
                ledger_argument = call_kwargs["expected_ledger_fd"]
                before_ledger = readable_ledger_state(ledger_argument)
                before_roots = tuple(tree_state(root) for root in roots)
                before_fds = []
                for fd, offset in borrowed:
                    try:
                        value = os.fstat(fd)
                        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                    except OSError as exc:
                        raise SystemExit(f"{label}: fixture borrowed fd is not open") from exc
                    before_fds.append((fd, offset, identity(value), flags, descriptor_flags))
                originals = []
                module_originals = []
                caught = None
                stdout = io.StringIO()
                stderr = io.StringIO()
                calls_before = discover_calls["count"]
                try:
                    for owner, name, replacement in patches:
                        existed = hasattr(owner, name)
                        original = getattr(owner, name) if existed else MISSING
                        originals.append((owner, name, existed, original))
                        if replacement is MISSING:
                            if existed:
                                delattr(owner, name)
                        else:
                            setattr(owner, name, replacement)
                    if full_a2:
                        held_root_case = (
                            stage3_case is not None
                            and stage3_case[0] == "stage3a3-case"
                            and stage3_case[1] == "held-root-canonical-absence"
                        )
                        stage3_c0_state = {
                            "constants": {},
                            "constant_values": {},
                            "callables": {},
                            "supports": {},
                            "inventory_valid": True,
                            "inventory_closed": False,
                            "getrlimit": [],
                            "events": [],
                            "graph_opens": 0,
                            "intervening": 0,
                            "post_a2_calls": [],
                            "unauthorized_calls": [],
                            "unauthorized_attributes": [],
                            "observed_items": {},
                            "case_attempts": 0,
                            "borrowed_ledger_fd": call_kwargs["expected_ledger_fd"],
                            "borrowed_parent_fd": call_kwargs["private_parent_fd"],
                            "private_ledger_fd": None,
                            "private_parent_fd": None,
                            "final_custody": 0,
                            "a2_complete": 0,
                            "stage3_case": stage3_case,
                            "graph_events": [],
                            "g1_attempt_indices": [],
                            "expected_graph_events": (
                                held_root_expected_g1 if held_root_case else stage3_a1_expected_g1
                            ),
                            "graph_edges": list(
                                held_root_expected_edges
                                if held_root_case
                                else stage3_a1_expected_edges
                            ),
                            "graph_fds": {},
                            "graph_owned": [],
                            "graph_pending_fd": None,
                            "graph_initial_structural": {},
                            "graph_binding_events": [],
                            "gb_attempt_indices": [],
                            "expected_graph_bindings": list(
                                held_root_expected_bindings
                                if held_root_case
                                else stage3_a1_expected_bindings
                            ),
                            "graph_close_calls": [],
                            "a1_custody_events": [],
                            "a1_suffix": [],
                            "a1_phase": "pre-a2",
                            "a1_body_outcome": None,
                            "a1_final_private_events": [],
                            "a1_final_borrowed_events": [],
                            "a1_safe_failure_attempted": None,
                            "a1_private_expected_bytes": os.environ["TASK4_GOLDEN"].encode("ascii"),
                            "a1_private_pread_cursor": 0,
                            "a1_private_pread_chunks": [],
                            "a1_fp_pread_attempted": False,
                            "a1_ki_attempted": None,
                            "a1_rejected_returns": [],
                            "a1_close_failure_attempted": None,
                            "a2_operations": [],
                            "a2_expected_operations": stage3_a2_expectation(stage3_case)[0],
                            "a2_expected_outcome": stage3_a2_expectation(stage3_case)[1],
                            "a2_fsencode_calls": [],
                            "a2_current_fd": None,
                            "a2_fds": {},
                            "a2_active_scan": None,
                            "a2_scan_history": [],
                            "a2_scan_closes": [],
                            "a2_rejected_returns": [],
                            "a2_close_uncertain": False,
                            "a2_first_close_failure": None,
                            "a2_scan_close_sentinel": KeyboardInterrupt(),
                            "a2_parent_close_sentinel": OSError(errno.EIO),
                            "a2_parent_close_raised": None,
                            "a2_post_fstat_sentinel": KeyboardInterrupt(),
                            "caught_exception": None,
                            "held_root_open_redirects": [],
                            "held_root_missing": False,
                            "held_root_first_fp_bridge": False,
                            "a2_open_snapshots": [],
                            "a2_regular_cursor": 0,
                            "a2_regular_chunks": [],
                            "a2_regular_bytes": {},
                            "a2_chunks_by_label": {},
                            "a2_pread_attempts": {},
                            "a2_list_results": [],
                            "a2_invalid_list_result": [],
                            "a2_scan_raw": [],
                            "a2_entry_types": [],
                            "a2_scan_start": 0,
                            "a2_preimages": [],
                            "a2_row_stats": {},
                            "a2_row_lineage": {},
                            "a2_supplied_rows": stage3_a2_supplied_rows(os.environ["TASK4_GOLDEN"]),
                            "a3_supplied_absence_rows": stage3_a3_supplied_absence_rows(os.environ["TASK4_GOLDEN"]),
                            "a2_cross_scan": False,
                            "a2_first_body_failure": None,
                            "a2_original_interrupt": None,
                            "a3_body_operations": stage3_a3_spec(stage3_case)[0],
                            "a3_absence_operations": stage3_a3_spec(stage3_case)[1],
                            "a3_body_events": [],
                            "a3_absence_events": [],
                            "a3_started": False,
                            "a3_fds": {},
                            "a3_owned_occurrences": [],
                            "a3_open_active": [],
                            "a3_readlinks": [],
                            "a3_native_readlinks": [],
                            "a3_readlink_attempts": [],
                            "a3_fsencode_calls": [],
                            "a3_fsencode_attempts": [],
                            "a3_target_absence_errnos": [],
                            "a3_absence_errnos": [],
                            "a3_absence_complete": False,
                            "a3_absence_suffix_snapshot": None,
                            "a3_symlink_identities": [],
                            "a3_target_identities": [],
                            "a3_boundary_identities": [],
                            "a3_markers": [],
                            "a3_first_body_failure": None,
                            "a3_original_interrupt": None,
                            "a3_close_failure": None,
                            "a3_close_sentinel": OSError(errno.EIO, "stage3a3 retained FD real-close-then-raise"),
                            "a3_forbid_later_filesystem": False,
                            "a3_injections": [],
                            "a3_later_gb_failure": None,
                            "disjoint_root_missing": False,
                            "disjoint_first_root_tokens": disjoint_first_root_tokens,
                            "reviewed_target_absence_fp_bridge": False,
                            "target_absence_missing": False,
                            "multi_component_absence_missing": False,
                            "multi_component_absence_fp_bridge": False,
                            "multi_component_enotdir_missing": False,
                            "multi_component_enotdir_fp_bridge": False,
                            "a1_emfile": False,
                            "a1_emfile_pending": False,
                            "private_parent_structural": None,
                            "graph_binding_successes": [],
                            "gb_failed": False,
                            "rlimit_baseline": None,
                            "required_constants": (
                                stage3_constants
                                if stage3_case_has_symlink(stage3_case)
                                else stage3_constants - {("os", "O_PATH")}
                            ),
                            "required_callables": (
                                stage3_callables
                                if stage3_case_has_symlink(stage3_case)
                                else stage3_callables - {("os", "readlink")}
                            ),
                            "required_supports": (
                                stage3_supports
                                if stage3_case_has_symlink(stage3_case)
                                else stage3_supports - {("supports_dir_fd", "readlink")}
                            ),
                        }
                        for name, replacement in (
                            ("os", Stage3NativeProxy("os", module.os)),
                            ("fcntl", Stage3NativeProxy("fcntl", module.fcntl)),
                            ("resource", Stage3NativeProxy("resource", resource)),
                        ):
                            existed = hasattr(module, name)
                            module_originals.append((name, existed, getattr(module, name, None)))
                            setattr(module, name, replacement)
                    module.discover_input_v1 = discover_bomb
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        try:
                            runner(**call_kwargs)
                        except BaseException as exc:
                            caught = exc
                finally:
                    module.discover_input_v1 = real_discover
                    for name, existed, original in reversed(module_originals):
                        if existed:
                            setattr(module, name, original)
                        else:
                            delattr(module, name)
                    for owner, name, existed, original in reversed(originals):
                        if existed:
                            setattr(owner, name, original)
                        elif hasattr(owner, name):
                            delattr(owner, name)
                if discover_calls["count"] != calls_before:
                    raise SystemExit(f"{label}: discover_input_v1 was called")
                if stdout.getvalue() or stderr.getvalue():
                    raise SystemExit(f"{label}: runner wrote output")
                target_absence_fallback = (
                    label == "stage3a3-reviewed-symlink-target-absence"
                    and full_a2
                    and stage3_c0_state is not None
                    and stage3_c0_state["target_absence_missing"]
                    and type(caught) is module.MutationError
                )
                multi_component_absence_fallback = (
                    label == "stage3a3-multi-component-canonical-absence"
                    and full_a2
                    and stage3_c0_state is not None
                    and stage3_c0_state["multi_component_absence_missing"]
                    and type(caught) is module.MutationError
                )
                multi_component_enotdir_fallback = (
                    label == "stage3a3-multi-component-canonical-enotdir"
                    and full_a2
                    and stage3_c0_state is not None
                    and stage3_c0_state["multi_component_enotdir_missing"]
                    and type(caught) is module.MutationError
                )
                held_root_fallback = (
                    label == "stage3a3-held-root-canonical-absence"
                    and full_a2
                    and stage3_c0_state is not None
                    and stage3_c0_state["held_root_missing"]
                    and stage3_c0_state["held_root_first_fp_bridge"]
                    and type(caught) is module.MutationError
                    and str(caught) == "stage3 evidence locator is empty"
                )
                effective_expected = (
                    module.MutationError
                    if target_absence_fallback
                    or multi_component_absence_fallback
                    or multi_component_enotdir_fallback
                    or held_root_fallback
                    else expected
                )
                if effective_expected is SystemExit:
                    if type(caught) is not SystemExit or caught.code != 77:
                        raise SystemExit(f"{label}: expected silent SystemExit(77), got {caught!r}")
                elif type(caught) is not effective_expected:
                    name = type(caught).__name__ if caught is not None else "return"
                    raise SystemExit(f"{label}: expected {effective_expected.__name__}, got {name}")
                if full_a2:
                    stage3_c0_state["caught_exception"] = caught
                    stage3_c0_state["events"].append(
                        "SystemExit(77)" if effective_expected is SystemExit else effective_expected.__name__
                    )
                if custody is not None:
                    custody()
                if full_a2:
                    expected_terminal = "SystemExit(77)" if effective_expected is SystemExit else effective_expected.__name__
                    if stage3_case_must_compose_a3(stage3_case) and not stage3_case_composes_a3(stage3_case):
                        raise SystemExit("stage3a3 required A2-to-A3 composition was deleted")
                    if stage3_case_composes_a3(stage3_case):
                        check_stage3_a2_prefix()
                        check_stage3_a3(expected_terminal)
                        if stage3_case_is_continuation(stage3_case):
                            check_stage3_c0_case(stage3_case, expected_terminal)
                    elif stage3_case_reaches_a2(stage3_case):
                        check_stage3_a2(expected_terminal)
                    elif stage3_case_is_a1(stage3_case):
                        check_stage3_a1(expected_terminal)
                    elif stage3_case is None:
                        check_stage3_c0(expected_terminal)
                    else:
                        check_stage3_c0_case(stage3_case, expected_terminal)
                if postcheck is not None:
                    postcheck()
                if tuple(tree_state(root) for root in roots) != before_roots:
                    raise SystemExit(f"{label}: runner changed a fixture tree")
                if before_ledger is not None and readable_ledger_state(ledger_argument) != before_ledger:
                    raise SystemExit(f"{label}: runner changed the borrowed ledger")
                for fd, offset, expected_identity, expected_flags, expected_descriptor_flags in before_fds:
                    try:
                        value = os.fstat(fd)
                        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                    except OSError as exc:
                        raise SystemExit(f"{label}: runner closed borrowed fd {fd}") from exc
                    if (
                        identity(value) != expected_identity
                        or flags != expected_flags
                        or descriptor_flags != expected_descriptor_flags
                    ):
                        raise SystemExit(f"{label}: runner changed borrowed fd {fd} metadata")
                    if offset is not None and borrowed_offset(fd) != offset:
                        raise SystemExit(f"{label}: runner changed borrowed fd {fd} offset")
                if target_absence_fallback:
                    raise SystemExit("stage3a3 reviewed symlink target absence was not accepted")
                if multi_component_absence_fallback:
                    raise SystemExit("stage3a3 multi-component target absence was not proven immediately")
                if multi_component_enotdir_fallback:
                    raise SystemExit("stage3a3 multi-component target ENOTDIR was not proven immediately")
                if held_root_fallback:
                    raise SystemExit("stage3a3 held root full evidence was not collected")
                stage3_c0_state = None

            base_borrowed = [(ledger_fd, ledger_offset), (parent_fd, parent_offset)]
            synthetic_context = (
                ledger_fd,
                ledger_path,
                ledger_offset,
                parent_fd,
                parent_offset,
                repo_root,
                stable_root,
                nightly_root,
                parent_root,
                valid,
                roots,
                base_borrowed,
                os.environ["TASK4_GOLDEN"],
            )

            stage2_positive = {
                "started": False,
                "dup_calls": 0,
                "open_calls": 0,
                "private_ledger": None,
                "private_parent": None,
                "private_cookie": None,
                "owned": [],
                "pread_calls": [],
                "pread_bytes": [],
                "pread_cursor": 0,
                "events": [],
                "fstat_counts": {},
                "private_fstat_values": [],
                "observed_flags": {},
                "private_parent_fstat": None,
                "close_calls": [],
                "fcntl_counts": {},
            }
            real_fcntl = fcntl.fcntl
            real_open = os.open
            real_pread = os.pread
            real_read = os.read
            real_lseek = os.lseek
            real_fstat = os.fstat
            real_close = os.close
            duplicate_commands = {
                value
                for name in dir(fcntl)
                if name.startswith("F_DUPFD")
                for value in [getattr(fcntl, name)]
                if type(value) is int
            }
            duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
            expected_open_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW

            def stage2_positive_fcntl(fd, command, *arguments):
                if type(command) is not int:
                    raise SystemExit("stage2 used a non-exact fcntl command")
                if command in duplicate_commands and command != duplicate_command:
                    raise SystemExit("stage2 used an unfixed descriptor duplication command")
                if command not in {fcntl.F_GETFL, fcntl.F_GETFD, duplicate_command}:
                    raise SystemExit("stage2 used an unapproved fcntl command")
                if command == duplicate_command:
                    stage2_positive["dup_calls"] += 1
                    if (
                        stage2_positive["dup_calls"] != 1
                        or fd != ledger_fd
                        or arguments != (0,)
                    ):
                        raise SystemExit("stage2 ledger duplication arguments drifted")
                    value = real_fcntl(fd, command, *arguments)
                    if type(value) is not int or value < 0:
                        raise SystemExit("stage2 ledger duplicate returned an unusable fd")
                    stage2_positive["private_ledger"] = value
                    stage2_positive["owned"].append(value)
                    stage2_positive["started"] = True
                    stage2_positive["events"].append("dup-L")
                    return value
                if stage2_positive["started"]:
                    tracked_fds = {ledger_fd, parent_fd, stage2_positive["private_ledger"]}
                    if stage2_positive["private_parent"] is not None:
                        tracked_fds.add(stage2_positive["private_parent"])
                    if fd not in tracked_fds:
                        raise SystemExit("stage2 observed an untracked descriptor")
                    if command not in {fcntl.F_GETFL, fcntl.F_GETFD}:
                        raise SystemExit("stage2 used an unapproved fcntl command")
                value = real_fcntl(fd, command, *arguments)
                if stage2_positive["started"]:
                    if command not in {fcntl.F_GETFL, fcntl.F_GETFD}:
                        raise SystemExit("stage2 used an unapproved fcntl command")
                    key = (fd, command)
                    if key in stage2_positive["fcntl_counts"]:
                        raise SystemExit("stage2 repeated a tracked fcntl observation")
                    stage2_positive["fcntl_counts"][key] = 1
                    if fd == stage2_positive["private_ledger"]:
                        if command not in {fcntl.F_GETFL, fcntl.F_GETFD}:
                            raise SystemExit("stage2 used an untracked private-ledger observation")
                    elif fd == stage2_positive["private_parent"]:
                        if command not in {fcntl.F_GETFL, fcntl.F_GETFD}:
                            raise SystemExit("stage2 used an untracked private-parent observation")
                    elif fd == ledger_fd:
                        if command != fcntl.F_GETFL:
                            raise SystemExit("stage2 used an untracked borrowed-ledger observation")
                    elif fd == parent_fd:
                        if command not in {fcntl.F_GETFL, fcntl.F_GETFD}:
                            raise SystemExit("stage2 used an untracked borrowed-parent observation")
                    else:
                        raise SystemExit("stage2 observed an untracked descriptor")
                    if fd in {stage2_positive["private_ledger"], stage2_positive["private_parent"]} and command in {fcntl.F_GETFL, fcntl.F_GETFD}:
                        stage2_positive["observed_flags"][(fd, command)] = value
                    if fd == stage2_positive["private_ledger"]:
                        if command == fcntl.F_GETFL:
                            stage2_positive["events"].append("L-getfl")
                        elif command == fcntl.F_GETFD:
                            stage2_positive["events"].append("L-getfd")
                    elif fd == stage2_positive["private_parent"]:
                        if command == fcntl.F_GETFL:
                            stage2_positive["events"].append("P-getfl")
                        elif command == fcntl.F_GETFD:
                            stage2_positive["events"].append("P-getfd")
                    elif fd == ledger_fd:
                        if command == fcntl.F_GETFL:
                            stage2_positive["events"].append("borrowed-L-getfl")
                    elif fd == parent_fd:
                        if command == fcntl.F_GETFL:
                            stage2_positive["events"].append("borrowed-P-getfl")
                        elif command == fcntl.F_GETFD:
                            stage2_positive["events"].append("borrowed-P-getfd")
                return value

            stage3_support_wrapper_targets.append((stage2_positive_fcntl, real_fcntl))

            def stage2_positive_open(path, flags, mode=0o777, *, dir_fd=None):
                stage2_positive["open_calls"] += 1
                if (
                    stage2_positive["open_calls"] != 1
                    or path != "."
                    or flags != expected_open_flags
                    or dir_fd != parent_fd
                ):
                    raise SystemExit("stage2 parent open arguments drifted")
                value = real_open(path, flags, mode, dir_fd=dir_fd)
                if type(value) is not int or value < 0:
                    raise SystemExit("stage2 parent open returned an unusable fd")
                stage2_positive["private_parent"] = value
                stage2_positive["owned"].append(value)
                stage2_positive["private_cookie"] = real_lseek(value, parent_offset + 1, os.SEEK_SET)
                stage2_positive["events"].append("open-P")
                return value

            stage3_support_wrapper_targets.append((stage2_positive_open, real_open))

            def stage2_positive_pread(fd, size, offset):
                owned = set(stage2_positive["owned"])
                if stage2_positive["started"] and (
                    fd in {ledger_fd, parent_fd} or fd in owned and fd != stage2_positive["private_ledger"]
                ):
                    raise SystemExit("stage2 used pread on a borrowed or non-ledger descriptor")
                if not stage2_positive["started"] or fd != stage2_positive["private_ledger"]:
                    return real_pread(fd, size, offset)
                if size > 3:
                    size = 3
                if offset != stage2_positive["pread_cursor"]:
                    raise SystemExit("stage2 private ledger pread was not contiguous")
                if stage2_positive["pread_cursor"] >= len(os.environ["TASK4_GOLDEN"].encode("ascii")):
                    raise SystemExit("stage2 extended a terminal private-ledger pread")
                stage2_positive["events"].append("L-pread")
                value = real_pread(fd, size, offset)
                if type(value) is not bytes or not value:
                    raise SystemExit("stage2 private ledger pread returned an invalid chunk")
                stage2_positive["pread_calls"].append((offset, len(value)))
                stage2_positive["pread_bytes"].append(value)
                stage2_positive["pread_cursor"] += len(value)
                return value

            stage3_support_wrapper_targets.append((stage2_positive_pread, real_pread))

            def stage2_positive_read(fd, size):
                if fd in set(stage2_positive["owned"]) | {ledger_fd, parent_fd}:
                    raise SystemExit("stage2 used read on a guarded descriptor")
                return real_read(fd, size)

            def stage2_positive_lseek(fd, offset, whence):
                if fd in set(stage2_positive["owned"]) | {ledger_fd, parent_fd}:
                    raise SystemExit("stage2 used lseek on a guarded descriptor")
                return real_lseek(fd, offset, whence)

            def stage2_positive_fstat(fd):
                value = real_fstat(fd)
                if stage2_positive["started"]:
                    count = stage2_positive["fstat_counts"].get(fd, 0) + 1
                    stage2_positive["fstat_counts"][fd] = count
                    if fd == stage2_positive["private_ledger"]:
                        stage2_positive["private_fstat_values"].append(value)
                        stage2_positive["events"].append("L-fstat-pre" if count == 1 else "L-fstat-post")
                    elif fd == stage2_positive["private_parent"]:
                        stage2_positive["private_parent_fstat"] = value
                        stage2_positive["events"].append("P-fstat")
                    elif fd == ledger_fd:
                        stage2_positive["events"].append("borrowed-L-fstat")
                    elif fd == parent_fd:
                        stage2_positive["events"].append("borrowed-P-fstat")
                return value

            stage3_support_wrapper_targets.append((stage2_positive_fstat, real_fstat))

            def stage2_positive_close(fd):
                if fd not in set(stage2_positive["owned"]):
                    raise SystemExit("stage2 closed a borrowed or invalid descriptor")
                expected = list(reversed(stage2_positive["owned"]))
                close_index = len(stage2_positive["close_calls"])
                if close_index >= len(expected) or fd != expected[close_index]:
                    raise SystemExit("stage2 closed owned descriptors out of order or twice")
                stage2_positive["close_calls"].append(fd)
                if fd == stage2_positive["private_parent"]:
                    stage2_positive["events"].append("close-P")
                elif fd == stage2_positive["private_ledger"]:
                    stage2_positive["events"].append("close-L")
                return real_close(fd)

            stage3_support_wrapper_targets.append((stage2_positive_close, real_close))

            def check_stage2_positive():
                if stage2_positive["dup_calls"] != 1:
                    raise SystemExit("stage2 ledger duplicate was not acquired exactly once")
                if stage2_positive["open_calls"] != 1:
                    raise SystemExit("stage2 parent was not opened exactly once")
                if stage2_positive["private_cookie"] in {None, 0, parent_offset}:
                    raise SystemExit("stage2 private parent cookie was not independent")
                expected_events = [
                    "dup-L", "open-P", "L-getfl", "L-getfd", "L-fstat-pre",
                    "L-pread-complete", "L-fstat-post", "P-getfl", "P-getfd", "P-fstat",
                    "borrowed-L-getfl", "borrowed-L-fstat", "borrowed-P-getfl",
                    "borrowed-P-getfd", "borrowed-P-fstat", "close-P", "close-L",
                    "SystemExit(77)",
                ]
                normalized_events = []
                index = 0
                while index < len(stage2_positive["events"]):
                    event = stage2_positive["events"][index]
                    if event == "L-pread":
                        while index < len(stage2_positive["events"]) and stage2_positive["events"][index] == "L-pread":
                            index += 1
                        normalized_events.append("L-pread-complete")
                    else:
                        normalized_events.append(event)
                        index += 1
                if normalized_events + ["SystemExit(77)"] != expected_events:
                    raise SystemExit(
                        f"stage2 positive trace drifted: {stage2_positive['events']!r}"
                    )
                ledger_size = len(os.environ["TASK4_GOLDEN"].encode("ascii"))
                if stage2_positive["pread_cursor"] != ledger_size or len(stage2_positive["pread_calls"]) < 2:
                    raise SystemExit("stage2 private ledger pread was not one multi-chunk complete pass")
                if len(stage2_positive["private_fstat_values"]) != 2:
                    raise SystemExit("stage2 private ledger identity bracket was not complete")
                private_ledger = stage2_positive["private_ledger"]
                private_parent = stage2_positive["private_parent"]
                if (
                    type(stage2_positive["observed_flags"].get((private_ledger, fcntl.F_GETFL))) is not int
                    or stage2_positive["observed_flags"].get((private_ledger, fcntl.F_GETFL)) != fcntl.fcntl(ledger_fd, fcntl.F_GETFL)
                    or stage2_positive["observed_flags"].get((private_ledger, fcntl.F_GETFD)) != fcntl.FD_CLOEXEC
                    or type(stage2_positive["observed_flags"].get((private_ledger, fcntl.F_GETFD))) is not int
                    or type(stage2_positive["observed_flags"].get((private_parent, fcntl.F_GETFL))) is not int
                    or stage2_positive["observed_flags"].get((private_parent, fcntl.F_GETFL)) & getattr(os, "O_PATH", 0)
                    or stage2_positive["observed_flags"].get((private_parent, fcntl.F_GETFL)) & os.O_ACCMODE != os.O_RDONLY
                    or stage2_positive["observed_flags"].get((private_parent, fcntl.F_GETFD)) != fcntl.FD_CLOEXEC
                    or type(stage2_positive["observed_flags"].get((private_parent, fcntl.F_GETFD))) is not int
                    or stage2_positive["private_parent_fstat"] is None
                    or not stat.S_ISDIR(stage2_positive["private_parent_fstat"].st_mode)
                    or identity(stage2_positive["private_parent_fstat"]) != identity(os.fstat(parent_fd))
                ):
                    raise SystemExit("stage2 private descriptor metadata was not exact")
                if (
                    identity(stage2_positive["private_fstat_values"][0]) != identity(stage2_positive["private_fstat_values"][1])
                    or b"".join(stage2_positive["pread_bytes"]) != os.environ["TASK4_GOLDEN"].encode("ascii")
                ):
                    raise SystemExit("stage2 private ledger identity or bytes drifted")
                cursor = 0
                for offset, length in stage2_positive["pread_calls"]:
                    if offset != cursor or length <= 0:
                        raise SystemExit("stage2 private ledger pread offsets were not contiguous")
                    cursor += length
                if cursor != ledger_size:
                    raise SystemExit("stage2 private ledger pread did not cover the ledger")
                if stage2_positive["close_calls"] != [
                    stage2_positive["private_parent"], stage2_positive["private_ledger"]
                ]:
                    raise SystemExit("stage2 owned descriptors were not closed in reverse order")
                for fd in stage2_positive["owned"]:
                    try:
                        real_fstat(fd)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise SystemExit("stage2 closed descriptor did not report EBADF") from exc
                    else:
                        raise SystemExit("stage2 owned descriptor leaked")

            run_case(
                "stage2-positive-private-custody",
                SystemExit,
                patches=(
                    (fcntl, "fcntl", stage2_positive_fcntl),
                    (module.os, "open", stage2_positive_open),
                    (module.os, "pread", stage2_positive_pread),
                    (module.os, "read", stage2_positive_read),
                    (module.os, "lseek", stage2_positive_lseek),
                    (module.os, "fstat", stage2_positive_fstat),
                    (module.os, "close", stage2_positive_close),
                    (module.os, "dup", lambda *args: (_ for _ in ()).throw(SystemExit("stage2 called os.dup"))),
                    (module.os, "dup2", lambda *args: (_ for _ in ()).throw(SystemExit("stage2 called os.dup2"))),
                ),
                borrowed=base_borrowed,
                postcheck=check_stage2_positive,
                full_a2=True,
            )

            def stage2_expected(position=None, variant=None, ledger_event="dup-L", parent_event="open-P", terminal="MutationError"):
                token = f"{position}-{variant}" if position is not None else None
                private_ledger = ledger_event == "dup-L"
                private_parent = parent_event == "open-P"
                result = [ledger_event]
                if parent_event is not None:
                    result.append(parent_event)
                if position in {"L-getfl", "L-getfd", "L-fstat-pre", "L-pread", "L-fstat-post"}:
                    prefixes = {
                        "L-getfl": [],
                        "L-getfd": ["L-getfl"],
                        "L-fstat-pre": ["L-getfl", "L-getfd"],
                        "L-pread": ["L-getfl", "L-getfd", "L-fstat-pre"],
                        "L-fstat-post": ["L-getfl", "L-getfd", "L-fstat-pre", "L-pread-complete"],
                    }
                    result.extend(prefixes[position])
                    result.append(token)
                    if position == "L-pread":
                        result.append("L-fstat-post")
                    elif position != "L-fstat-post":
                        result.extend([])
                    if private_parent:
                        result.extend(["P-getfl", "P-getfd", "P-fstat"])
                    result.extend(["borrowed-L-getfl", "borrowed-L-fstat-pre", "borrowed-L-pread-complete", "borrowed-L-fstat-post"])
                    result.extend(["borrowed-P-getfl", "borrowed-P-getfd", "borrowed-P-fstat"])
                    result.extend(["close-P", "close-L"] if private_parent else ["close-L"])
                    result.append(terminal)
                    return result
                if position in {"P-getfl", "P-getfd", "P-fstat"}:
                    result.extend(["L-getfl", "L-getfd", "L-fstat-pre", "L-pread-complete", "L-fstat-post"])
                    for operation in ("P-getfl", "P-getfd", "P-fstat"):
                        result.append(token if operation == position else operation)
                    result.extend(["borrowed-L-getfl", "borrowed-L-fstat"])
                    result.extend(["borrowed-P-getfl", "borrowed-P-getfd", "borrowed-P-fstat"])
                    result.extend(["close-P", "close-L"] if private_parent else ["close-L"])
                    result.append(terminal)
                    return result
                if position in {"borrowed-L-getfl", "borrowed-L-fstat-pre", "borrowed-L-pread", "borrowed-L-fstat-post"}:
                    result = [ledger_event]
                    if position == "borrowed-L-getfl":
                        result.extend([token, "borrowed-L-fstat-pre"])
                    elif position == "borrowed-L-fstat-pre":
                        result.extend(["borrowed-L-getfl", token])
                    elif position == "borrowed-L-pread":
                        result.extend(["borrowed-L-getfl", "borrowed-L-fstat-pre", token, "borrowed-L-fstat-post"])
                    else:
                        result.extend(["borrowed-L-getfl", "borrowed-L-fstat-pre", "borrowed-L-pread-complete", token])
                    result.extend(["borrowed-P-getfl", "borrowed-P-getfd", "borrowed-P-fstat", terminal])
                    return result
                if position in {"borrowed-P-getfl", "borrowed-P-getfd", "borrowed-P-fstat"}:
                    result.extend(
                        ["L-getfl", "L-getfd", "L-fstat-pre", "L-pread-complete", "L-fstat-post"]
                        if private_ledger
                        else ["borrowed-L-getfl", "borrowed-L-fstat-pre", "borrowed-L-pread-complete", "borrowed-L-fstat-post"]
                    )
                    if private_ledger:
                        if private_parent:
                            result.extend(["P-getfl", "P-getfd", "P-fstat"])
                        result.append("borrowed-L-getfl")
                        result.append("borrowed-L-fstat")
                    for operation in ("borrowed-P-getfl", "borrowed-P-getfd", "borrowed-P-fstat"):
                        result.append(token if operation == position else operation)
                    result.extend(["close-P", "close-L"] if private_parent else (["close-L"] if private_ledger else []))
                    result.append(terminal)
                    return result
                if private_ledger:
                    result.extend(["L-getfl", "L-getfd", "L-fstat-pre", "L-pread-complete", "L-fstat-post"])
                    if private_parent:
                        result.extend(["P-getfl", "P-getfd", "P-fstat"])
                    result.extend(["borrowed-L-getfl", "borrowed-L-fstat"])
                elif parent_event is not None and parent_event != "open-P":
                    result.extend([])
                if not private_ledger:
                    result.extend(["borrowed-L-getfl", "borrowed-L-fstat-pre", "borrowed-L-pread-complete", "borrowed-L-fstat-post"])
                result.extend(["borrowed-P-getfl", "borrowed-P-getfd", "borrowed-P-fstat"])
                if private_parent:
                    result.extend(["close-P", "close-L"])
                elif private_ledger:
                    result.append("close-L")
                result.append(terminal)
                return result

            def run_stage2_case(
                label,
                expected,
                *,
                ledger_mode="real",
                parent_mode="real",
                command_mode=None,
                failure=None,
                close_error=None,
                ledger_errno=errno.EINVAL,
                parent_errno=errno.EINVAL,
            ):
                state = {
                    "ledger_calls": 0,
                    "open_calls": 0,
                    "private_ledger": None,
                    "private_parent": None,
                    "owned": [],
                    "close_calls": [],
                    "events": [],
                    "fcntl_counts": {},
                    "fstat_counts": {},
                    "pread_counts": {},
                    "pread_cursors": {},
                    "pread_states": {},
                    "borrowed_l_fallback_phase": False,
                    "borrowed_l_getfl_exact": False,
                    "borrowed_l_fstat_pre_exact": False,
                    "stub_returns": [],
                }
                if command_mode is not None:
                    state["events"].append("command-absent" if command_mode == "absent" else "command-invalid")
                if isinstance(failure, dict):
                    failure_position, failure_variant = None, None
                else:
                    failure_position, failure_variant = failure or (None, None)

                def mode_parts(mode, default_errno):
                    if isinstance(mode, tuple):
                        return mode[0], mode[1]
                    return mode, default_errno

                ledger_kind, ledger_error = mode_parts(ledger_mode, ledger_errno)
                parent_kind, parent_error = mode_parts(parent_mode, parent_errno)
                private_duplicate_command = duplicate_command

                def unowned_stub(fd):
                    for _, value in state["stub_returns"]:
                        if fd == value and value not in {ledger_fd, parent_fd} and value not in state["owned"]:
                            return True
                    return False

                def failure_variant_for(operation):
                    if isinstance(failure, dict):
                        return failure.get(operation)
                    return failure_variant if failure_position == operation else None

                def private_ledger_usable():
                    if state["private_ledger"] is None:
                        return False
                    if failure_position is not None and failure_position.startswith("L-"):
                        return False
                    return not any(operation.startswith("L-") for operation in failure or {}) if isinstance(failure, dict) else True

                def acquisition_error(kind, error_number, prefix):
                    if kind == "allowed":
                        state["events"].append(f"{prefix}-allowed-error")
                        raise OSError(error_number, "stage2 capability refusal")
                    if kind == "eio":
                        state["events"].append(f"{prefix}-EIO-error")
                        raise OSError(errno.EIO, "stage2 mutation failure")
                    if kind == "runtime":
                        state["events"].append(f"{prefix}-RuntimeError")
                        raise RuntimeError("stage2 mutation failure")

                def wrapped_fcntl(fd, command, *arguments):
                    if type(command) is not int:
                        raise SystemExit("stage2 used a non-exact fcntl command")
                    if command in duplicate_commands and command != private_duplicate_command:
                        raise SystemExit("stage2 used an unfixed descriptor duplication command")
                    if command not in {fcntl.F_GETFL, fcntl.F_GETFD, private_duplicate_command}:
                        raise SystemExit("stage2 used an unapproved fcntl command")
                    if unowned_stub(fd):
                        raise SystemExit("stage2 used an invalid stub descriptor")
                    if command == private_duplicate_command:
                        state["ledger_calls"] += 1
                        if state["ledger_calls"] != 1 or fd != ledger_fd or arguments != (0,):
                            raise SystemExit("stage2 ledger duplication arguments drifted")
                        acquisition_error(ledger_kind, ledger_error, "dup-L")
                        if ledger_kind == "true":
                            value = True
                        elif ledger_kind == "subclass":
                            value = IntSubclass(10**6)
                        elif ledger_kind == "negative":
                            value = -1
                        elif ledger_kind == "collision-L":
                            value = ledger_fd
                        elif ledger_kind == "collision-P":
                            value = parent_fd
                        else:
                            value = real_fcntl(fd, command, *arguments)
                            state["private_ledger"] = value
                            state["owned"].append(value)
                        if ledger_kind in {"true", "subclass", "negative", "collision-L", "collision-P"}:
                            state["stub_returns"].append(("ledger", value))
                            state["events"].append(
                                {
                                    "true": "dup-L-return-True",
                                    "subclass": "dup-L-return-IntSubclass",
                                    "negative": "dup-L-return-negative",
                                    "collision-L": "dup-L-return-collision-borrowed-L",
                                    "collision-P": "dup-L-return-collision-borrowed-P",
                                }[ledger_kind]
                            )
                        else:
                            state["events"].append("dup-L")
                        return value
                    tracked_fds = {ledger_fd, parent_fd}
                    if state["private_ledger"] is not None:
                        tracked_fds.add(state["private_ledger"])
                    if state["private_parent"] is not None:
                        tracked_fds.add(state["private_parent"])
                    if fd not in tracked_fds:
                        raise SystemExit("stage2 observed an untracked descriptor")
                    key = (fd, command)
                    next_count = state["fcntl_counts"].get(key, 0) + 1
                    if fd in {state["private_ledger"], state["private_parent"]} and next_count != 1:
                        raise SystemExit("stage2 repeated a private-descriptor fcntl observation")
                    if fd == ledger_fd and (command != fcntl.F_GETFL or next_count > 2):
                        raise SystemExit("stage2 used an untracked borrowed-ledger fcntl observation")
                    if fd == parent_fd and next_count > 3:
                        raise SystemExit("stage2 used an untracked borrowed-parent fcntl observation")
                    value = real_fcntl(fd, command, *arguments)
                    state["fcntl_counts"][key] = state["fcntl_counts"].get(key, 0) + 1
                    count = state["fcntl_counts"][key]
                    operation = None
                    if fd == state["private_ledger"]:
                        if count != 1:
                            raise SystemExit("stage2 repeated a private-ledger fcntl observation")
                        operation = {fcntl.F_GETFL: "L-getfl", fcntl.F_GETFD: "L-getfd"}.get(command)
                    elif fd == state["private_parent"]:
                        if count != 1:
                            raise SystemExit("stage2 repeated a private-parent fcntl observation")
                        operation = {fcntl.F_GETFL: "P-getfl", fcntl.F_GETFD: "P-getfd"}.get(command)
                    elif fd == ledger_fd:
                        if command == fcntl.F_GETFL and count == 2:
                            operation = "borrowed-L-getfl"
                        elif count > 1 or command != fcntl.F_GETFL:
                            raise SystemExit("stage2 used an untracked borrowed-ledger fcntl observation")
                    elif fd == parent_fd:
                        if command == fcntl.F_GETFL and count == 3:
                            operation = "borrowed-P-getfl"
                        elif command == fcntl.F_GETFD and count == 3:
                            operation = "borrowed-P-getfd"
                        elif count > 2 or command not in {fcntl.F_GETFL, fcntl.F_GETFD}:
                            raise SystemExit("stage2 used an untracked borrowed-parent fcntl observation")
                    if operation is None:
                        return value
                    operation_variant = failure_variant_for(operation)
                    if operation_variant is not None:
                        if operation_variant == "exception":
                            state["events"].append(f"{operation}-exception")
                            raise OSError(errno.EIO, "stage2 injected fcntl failure")
                        if operation_variant == "KeyboardInterrupt":
                            state["events"].append(f"{operation}-KeyboardInterrupt")
                            raise KeyboardInterrupt()
                        if operation_variant == "status-mismatch":
                            state["events"].append(f"{operation}-status-mismatch")
                            return (value & ~os.O_ACCMODE) | os.O_WRONLY if operation.startswith("P-") or operation.startswith("borrowed-P-") else value | os.O_NONBLOCK
                        if operation_variant == "bool-FD_CLOEXEC":
                            state["events"].append(f"{operation}-bool-FD_CLOEXEC")
                            return True
                        if operation_variant == "IntSubclass-FD_CLOEXEC":
                            state["events"].append(f"{operation}-IntSubclass-FD_CLOEXEC")
                            return IntSubclass(fcntl.FD_CLOEXEC)
                        if operation_variant == "fd-flags-mismatch":
                            state["events"].append(f"{operation}-fd-flags-mismatch")
                            return 0
                        if operation_variant == "bool-FL_RDONLY":
                            state["events"].append(f"{operation}-bool-FL_RDONLY")
                            return False
                        if operation_variant == "IntSubclass-FL_RDONLY":
                            state["events"].append(f"{operation}-IntSubclass-FL_RDONLY")
                            return IntSubclass(value)
                        if operation_variant == "O_PATH":
                            state["events"].append(f"{operation}-O_PATH")
                            return getattr(os, "O_PATH", 0) | os.O_RDONLY
                    if operation == "borrowed-L-getfl":
                        state["borrowed_l_getfl_exact"] = operation_variant is None
                    state["events"].append(operation)
                    return value

                stage3_support_wrapper_targets.append((wrapped_fcntl, real_fcntl))

                def wrapped_open(path, flags, mode=0o777, *, dir_fd=None):
                    state["open_calls"] += 1
                    if state["open_calls"] != 1 or path != "." or flags != expected_open_flags or dir_fd != parent_fd:
                        raise SystemExit("stage2 parent open arguments drifted")
                    acquisition_error(parent_kind, parent_error, "open-P")
                    if parent_kind == "true":
                        value = True
                    elif parent_kind == "subclass":
                        value = IntSubclass(10**6 + 1)
                    elif parent_kind == "negative":
                        value = -1
                    elif parent_kind == "collision-L":
                        value = state["private_ledger"]
                    elif parent_kind == "collision-borrowed-L":
                        value = ledger_fd
                    elif parent_kind == "collision-borrowed-P":
                        value = parent_fd
                    else:
                        value = real_open(path, flags, mode, dir_fd=dir_fd)
                        state["private_parent"] = value
                        state["owned"].append(value)
                        real_lseek(value, parent_offset + 1, os.SEEK_SET)
                    if parent_kind != "real":
                        state["stub_returns"].append(("parent", value))
                        state["events"].append(
                            {
                                "true": "open-P-return-True",
                                "subclass": "open-P-return-IntSubclass",
                                "negative": "open-P-return-negative",
                                "collision-L": "open-P-return-collision-owned-L",
                                "collision-borrowed-L": "open-P-return-collision-borrowed-L",
                                "collision-borrowed-P": "open-P-return-collision-borrowed-P",
                            }.get(parent_kind, f"open-P-{parent_kind}-error")
                        )
                    else:
                        state["events"].append("open-P")
                    return value

                stage3_support_wrapper_targets.append((wrapped_open, real_open))

                def wrapped_fstat(fd):
                    if unowned_stub(fd):
                        raise SystemExit("stage2 used an invalid stub descriptor")
                    count = state["fstat_counts"].get(fd, 0) + 1
                    state["fstat_counts"][fd] = count
                    operation = None
                    if fd == state["private_ledger"]:
                        operation = "L-fstat-pre" if count == 1 else "L-fstat-post"
                    elif fd == state["private_parent"]:
                        operation = "P-fstat"
                    elif fd == ledger_fd and count >= 4:
                        if private_ledger_usable() and count == 4:
                            operation = "borrowed-L-fstat"
                        elif not private_ledger_usable() and count == 4:
                            operation = "borrowed-L-fstat-pre"
                        elif not private_ledger_usable() and count == 5:
                            operation = "borrowed-L-fstat-post"
                        else:
                            raise SystemExit("stage2 used an untracked borrowed-ledger fstat observation")
                    elif fd == parent_fd and count >= 3:
                        operation = "borrowed-P-fstat"
                    value = real_fstat(fd)
                    if operation is None:
                        return value
                    if operation == "borrowed-L-fstat-post":
                        state["borrowed_l_fallback_phase"] = False
                    operation_variant = failure_variant_for(operation)
                    if operation_variant is not None:
                        if operation_variant == "exception":
                            state["events"].append(f"{operation}-exception")
                            raise OSError(errno.EIO, "stage2 injected fstat failure")
                        if operation_variant == "kind-mismatch":
                            state["events"].append(f"{operation}-kind-mismatch")
                            return StatProxy(value, st_mode=stat.S_IFREG | 0o600)
                        if operation_variant == "identity-proxy-mismatch":
                            state["events"].append(f"{operation}-identity-proxy-mismatch")
                            return StatProxy(value, st_ino=value.st_ino + 1)
                    if operation == "borrowed-L-fstat-pre":
                        state["borrowed_l_fstat_pre_exact"] = (
                            state["borrowed_l_getfl_exact"] and operation_variant is None
                        )
                        state["borrowed_l_fallback_phase"] = state["borrowed_l_fstat_pre_exact"]
                    state["events"].append(operation)
                    return value

                stage3_support_wrapper_targets.append((wrapped_fstat, real_fstat))

                def wrapped_pread(fd, size, offset):
                    if fd == state["private_ledger"]:
                        operation = "L-pread"
                    elif fd == ledger_fd and not private_ledger_usable() and state["borrowed_l_fallback_phase"]:
                        operation = "borrowed-L-pread"
                    elif fd == ledger_fd and state["fstat_counts"].get(fd, 0) < 3:
                        return real_pread(fd, size, offset)
                    elif fd == ledger_fd:
                        raise SystemExit("stage2 used an unauthorized borrowed-ledger pread")
                    else:
                        if unowned_stub(fd) or fd in {parent_fd, state["private_parent"]} or fd in set(state["owned"]):
                            raise SystemExit("stage2 used pread on a guarded descriptor")
                        return real_pread(fd, size, offset)
                    state["pread_counts"][fd] = state["pread_counts"].get(fd, 0) + 1
                    size = min(size, 3)
                    cursor = state["pread_cursors"].get(fd, 0)
                    if state["pread_states"].get(fd) in {"failed", "complete"}:
                        raise SystemExit("stage2 retried or extended a terminal ledger pread")
                    if offset != cursor or cursor >= len(os.environ["TASK4_GOLDEN"].encode("ascii")):
                        raise SystemExit("stage2 used an extra or non-contiguous ledger pread")
                    state["events"].append(operation)
                    operation_variant = failure_variant_for(operation)
                    if operation_variant is not None:
                        if operation_variant == "exception":
                            state["pread_states"][fd] = "failed"
                            raise OSError(errno.EIO, "stage2 injected pread failure")
                        if operation_variant == "zero-first":
                            state["pread_states"][fd] = "failed"
                            return b""
                        if operation_variant == "invalid-chunk":
                            state["pread_states"][fd] = "failed"
                            return bytearray(b"invalid")
                        if operation_variant == "short-after-positive" and state["pread_counts"][fd] > 1:
                            state["pread_states"][fd] = "failed"
                            return b""
                    value = real_pread(fd, size, offset)
                    if type(value) is bytes and value:
                        state["pread_cursors"][fd] = cursor + len(value)
                        if state["pread_cursors"][fd] == len(os.environ["TASK4_GOLDEN"].encode("ascii")):
                            state["pread_states"][fd] = "complete"
                    if operation_variant == "complete-bytes-mismatch":
                        if value:
                            value = bytes([value[0] ^ 1]) + value[1:]
                    return value

                stage3_support_wrapper_targets.append((wrapped_pread, real_pread))

                def wrapped_read(fd, size):
                    if unowned_stub(fd) or fd in {ledger_fd, parent_fd} or fd in set(state["owned"]):
                        raise SystemExit("stage2 used read on a guarded descriptor")
                    return real_read(fd, size)

                def wrapped_lseek(fd, offset, whence):
                    if unowned_stub(fd) or fd in {ledger_fd, parent_fd} or fd in set(state["owned"]):
                        raise SystemExit("stage2 used lseek on a guarded descriptor")
                    return real_lseek(fd, offset, whence)

                def wrapped_close(fd):
                    if unowned_stub(fd) or fd in {ledger_fd, parent_fd}:
                        raise SystemExit("stage2 closed a borrowed or invalid descriptor")
                    if fd not in state["owned"]:
                        raise SystemExit("stage2 closed an unowned descriptor")
                    expected = list(reversed(state["owned"]))
                    close_index = len(state["close_calls"])
                    if close_index >= len(expected) or fd != expected[close_index] or fd in state["close_calls"]:
                        raise SystemExit("stage2 closed owned descriptors out of order or twice")
                    state["close_calls"].append(fd)
                    state["events"].append("close-P" if fd == state["private_parent"] else "close-L")
                    value = real_close(fd)
                    if close_error == "parent-keyboardinterrupt" and fd == state["private_parent"]:
                        raise KeyboardInterrupt()
                    if close_error == ("parent" if fd == state["private_parent"] else "ledger"):
                        raise OSError(errno.EIO, "stage2 injected close failure")
                    return value

                stage3_support_wrapper_targets.append((wrapped_close, real_close))

                def observed_trace():
                    events = list(state["events"])
                    index = 0
                    normalized = []
                    while index < len(events):
                        event = events[index]
                        if event in {"L-pread", "borrowed-L-pread"}:
                            index += 1
                            while index < len(events) and events[index] == event:
                                index += 1
                            operation_variant = failure_variant_for(event)
                            if operation_variant is not None:
                                normalized.append(f"{event}-{operation_variant}")
                            else:
                                normalized.append(f"{event}-complete")
                        else:
                            normalized.append(event)
                            index += 1
                    normalized.append(expected[-1])
                    return normalized

                def check_trace():
                    if observed_trace() != expected:
                        raise SystemExit(f"{label}: exact Stage2 event vector drifted: {observed_trace()!r}")

                def check_custody():
                    if len(state["owned"]) != len(set(state["owned"])):
                        raise SystemExit(f"{label}: duplicate owned fd")
                    expected_close = list(reversed(state["owned"]))
                    if state["close_calls"] != expected_close:
                        raise SystemExit(f"{label}: close order drifted")
                    if state["ledger_calls"] > 1 or state["open_calls"] > 1:
                        raise SystemExit(f"{label}: acquisition was retried")
                    for _, value in state["stub_returns"]:
                        if value not in state["owned"] and value in state["close_calls"]:
                            raise SystemExit(f"{label}: invalid stub descriptor was closed")
                    for role, value in state["stub_returns"]:
                        if role == "ledger" and state["private_ledger"] is not None:
                            raise SystemExit(f"{label}: ledger stub return was acquired")
                        if role == "parent" and value != state["private_ledger"] and value in state["owned"]:
                            raise SystemExit(f"{label}: parent stub return was acquired")
                    for fd in state["owned"]:
                        try:
                            real_fstat(fd)
                        except OSError as exc:
                            if exc.errno != errno.EBADF:
                                raise SystemExit(f"{label}: owned fd did not close to EBADF") from exc
                        else:
                            raise SystemExit(f"{label}: owned fd leaked")

                patches = [
                    (fcntl, "fcntl", wrapped_fcntl),
                    (module.os, "open", wrapped_open),
                    (module.os, "fstat", wrapped_fstat),
                    (module.os, "pread", wrapped_pread),
                    (module.os, "read", wrapped_read),
                    (module.os, "lseek", wrapped_lseek),
                    (module.os, "close", wrapped_close),
                    (module.os, "dup", lambda *args: (_ for _ in ()).throw(SystemExit("stage2 called os.dup"))),
                    (module.os, "dup2", lambda *args: (_ for _ in ()).throw(SystemExit("stage2 called os.dup2"))),
                ]
                if command_mode is not None:
                    patches.append(
                        (
                            fcntl,
                            "F_DUPFD_CLOEXEC",
                            MISSING if command_mode == "absent" else True if command_mode == "true" else IntSubclass(duplicate_command) if command_mode == "subclass" else -1,
                        )
                    )
                continues_to_a2 = (
                    label.startswith("stage2-usable-private-borrowed-L-getfl-")
                    or label.startswith("stage2-attempt-all-borrowed-P-")
                    or label
                    in {
                        "stage2-close-parent-real-close-then-raise",
                        "stage2-close-ledger-real-close-then-raise",
                        "stage2-close-parent-keyboardinterrupt",
                    }
                )
                run_case(
                    label,
                    KeyboardInterrupt
                    if expected[-1] == "KeyboardInterrupt"
                    else SystemExit
                    if expected[-1] == "SystemExit(77)"
                    else module.MutationError,
                    patches=tuple(patches),
                    borrowed=base_borrowed,
                    postcheck=check_trace,
                    custody=check_custody,
                    full_a2=continues_to_a2,
                    stage3_case=("stage3a2-positive",) if continues_to_a2 else None,
                )

            for variant in ("exception", "status-mismatch"):
                run_stage2_case(
                    f"stage2-usable-private-borrowed-L-getfl-{variant}",
                    [
                        "dup-L",
                        "open-P",
                        "L-getfl",
                        "L-getfd",
                        "L-fstat-pre",
                        "L-pread-complete",
                        "L-fstat-post",
                        "P-getfl",
                        "P-getfd",
                        "P-fstat",
                        f"borrowed-L-getfl-{variant}",
                        "borrowed-L-fstat",
                        "borrowed-P-getfl",
                        "borrowed-P-getfd",
                        "borrowed-P-fstat",
                        "close-P",
                        "close-L",
                        "MutationError",
                    ],
                    failure=("borrowed-L-getfl", variant),
                )

            run_stage2_case(
                "stage2-private-ledger-getfl-keyboardinterrupt",
                [
                    "dup-L",
                    "open-P",
                    "L-getfl-KeyboardInterrupt",
                    "close-P",
                    "close-L",
                    "KeyboardInterrupt",
                ],
                failure=("L-getfl", "KeyboardInterrupt"),
            )

            validation_variants = (
                ("L-getfl", ("exception", "status-mismatch")),
                ("L-getfd", ("exception", "bool-FD_CLOEXEC", "IntSubclass-FD_CLOEXEC", "fd-flags-mismatch")),
                ("L-fstat-pre", ("exception", "identity-proxy-mismatch")),
                ("L-pread", ("exception", "zero-first", "invalid-chunk", "short-after-positive", "complete-bytes-mismatch")),
                ("L-fstat-post", ("exception", "identity-proxy-mismatch")),
                ("P-getfl", ("exception", "status-mismatch", "bool-FL_RDONLY", "IntSubclass-FL_RDONLY", "O_PATH")),
                ("P-getfd", ("exception", "bool-FD_CLOEXEC", "IntSubclass-FD_CLOEXEC", "fd-flags-mismatch")),
                ("P-fstat", ("exception", "kind-mismatch", "identity-proxy-mismatch")),
                ("borrowed-L-getfl", ("exception", "status-mismatch")),
                ("borrowed-L-fstat-pre", ("exception", "identity-proxy-mismatch")),
                ("borrowed-L-pread", ("exception", "zero-first", "invalid-chunk", "short-after-positive", "complete-bytes-mismatch")),
                ("borrowed-L-fstat-post", ("exception", "identity-proxy-mismatch")),
                ("borrowed-P-getfl", ("exception", "status-mismatch")),
                ("borrowed-P-getfd", ("exception", "bool-FD_CLOEXEC", "IntSubclass-FD_CLOEXEC", "fd-flags-mismatch")),
                ("borrowed-P-fstat", ("exception", "kind-mismatch", "identity-proxy-mismatch")),
            )
            for position, variants in validation_variants:
                for variant in variants:
                    if position.startswith("borrowed-L-"):
                        ledger_event = "dup-L-allowed-error"
                        parent_event = None
                    else:
                        ledger_event = "dup-L"
                        parent_event = "open-P"
                    expected = stage2_expected(
                        position,
                        variant,
                        ledger_event=ledger_event,
                        parent_event=parent_event,
                    )
                    run_stage2_case(
                        f"stage2-attempt-all-{position}-{variant}",
                        expected,
                        ledger_mode=("allowed", errno.EINVAL) if position.startswith("borrowed-L-") else "real",
                        failure=(position, variant),
                    )

            for command_mode, first in (("absent", "command-absent"), ("true", "command-invalid"), ("subclass", "command-invalid"), ("negative", "command-invalid")):
                expected = stage2_expected(ledger_event=first, parent_event=None, terminal="SystemExit(77)")
                run_stage2_case(f"stage2-{first}-{command_mode}", expected, command_mode=command_mode)
                for position, variant in (("borrowed-L-pread", "complete-bytes-mismatch"), ("borrowed-L-fstat-pre", "identity-proxy-mismatch")):
                    mutation_expected = stage2_expected(
                        position,
                        variant,
                        ledger_event=first,
                        parent_event=None,
                    )
                    run_stage2_case(
                        f"stage2-{first}-fallback-{variant}",
                        mutation_expected,
                        command_mode=command_mode,
                        failure=(position, variant),
                    )

            for index, error_number in enumerate(dict.fromkeys((errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP))):
                expected = stage2_expected(ledger_event="dup-L-allowed-error", parent_event=None, terminal="SystemExit(77)")
                run_stage2_case(
                    f"stage2-ledger-capability-refusal-{index}",
                    expected,
                    ledger_mode=("allowed", error_number),
                )
            for kind in ("eio", "runtime"):
                expected = stage2_expected(ledger_event=f"dup-L-{kind.upper()}-error" if kind == "eio" else "dup-L-RuntimeError", parent_event=None)
                run_stage2_case(f"stage2-ledger-{kind}-error", expected, ledger_mode=kind)

            for mode, event in (
                ("true", "dup-L-return-True"),
                ("subclass", "dup-L-return-IntSubclass"),
                ("negative", "dup-L-return-negative"),
                ("collision-L", "dup-L-return-collision-borrowed-L"),
                ("collision-P", "dup-L-return-collision-borrowed-P"),
            ):
                expected = stage2_expected(ledger_event=event, parent_event=None)
                run_stage2_case(f"stage2-ledger-{mode}", expected, ledger_mode=mode)

            parent_modes = tuple(
                [
                    (("allowed", error_number), "open-P-allowed-error", "SystemExit(77)")
                    for error_number in dict.fromkeys((errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP))
                ]
                + [
                ("eio", "open-P-EIO-error", "MutationError"),
                ("runtime", "open-P-RuntimeError", "MutationError"),
                ("true", "open-P-return-True", "MutationError"),
                ("subclass", "open-P-return-IntSubclass", "MutationError"),
                ("negative", "open-P-return-negative", "MutationError"),
                ("collision-L", "open-P-return-collision-owned-L", "MutationError"),
                ("collision-borrowed-L", "open-P-return-collision-borrowed-L", "MutationError"),
                ("collision-borrowed-P", "open-P-return-collision-borrowed-P", "MutationError"),
                ]
            )
            for mode, event, terminal in parent_modes:
                expected = stage2_expected(ledger_event="dup-L", parent_event=event, terminal=terminal)
                run_stage2_case(f"stage2-parent-{event}", expected, parent_mode=mode)

            parent_refusal_failure = stage2_expected(
                "L-pread",
                "exception",
                ledger_event="dup-L",
                parent_event="open-P-allowed-error",
            )
            run_stage2_case(
                "stage2-parent-refusal-private-ledger-fallback",
                parent_refusal_failure,
                parent_mode=("allowed", errno.EINVAL),
                failure=("L-pread", "exception"),
            )
            parent_refusal_mutation = stage2_expected(
                "borrowed-P-getfl",
                "exception",
                ledger_event="dup-L",
                parent_event="open-P-allowed-error",
            )
            run_stage2_case(
                "stage2-parent-refusal-mutation-partner",
                parent_refusal_mutation,
                parent_mode=("allowed", errno.EINVAL),
                failure=("borrowed-P-getfl", "exception"),
            )
            parent_refusal_close = stage2_expected(
                ledger_event="dup-L",
                parent_event="open-P-allowed-error",
            )
            run_stage2_case(
                "stage2-parent-refusal-ledger-close-error",
                parent_refusal_close,
                parent_mode=("allowed", errno.EINVAL),
                close_error="ledger",
            )
            combined_attempt_all = [
                "dup-L", "open-P", "L-getfl", "L-getfd", "L-fstat-pre",
                "L-pread-complete", "L-fstat-post", "P-getfl-exception", "P-getfd", "P-fstat",
                "borrowed-L-getfl", "borrowed-L-fstat", "borrowed-P-getfl-exception",
                "borrowed-P-getfd", "borrowed-P-fstat", "close-P", "close-L", "MutationError",
            ]
            run_stage2_case(
                "stage2-combined-private-and-borrowed-parent-getfl-failures",
                combined_attempt_all,
                failure={"P-getfl": "exception", "borrowed-P-getfl": "exception"},
            )
            for position, variant in (("borrowed-L-pread", "complete-bytes-mismatch"), ("borrowed-L-fstat-pre", "identity-proxy-mismatch")):
                expected = stage2_expected(position, variant, ledger_event="dup-L-allowed-error", parent_event=None)
                run_stage2_case(
                    f"stage2-capability-mutation-{position}",
                    expected,
                    ledger_mode=("allowed", errno.EINVAL),
                    failure=(position, variant),
                )

            for close_target in ("parent", "ledger"):
                expected = stage2_expected(ledger_event="dup-L", parent_event="open-P")
                run_stage2_case(
                    f"stage2-close-{close_target}-real-close-then-raise",
                    expected,
                    close_error=close_target,
                )
            run_stage2_case(
                "stage2-close-parent-keyboardinterrupt",
                stage2_expected(ledger_event="dup-L", parent_event="open-P"),
                close_error="parent-keyboardinterrupt",
            )
            run_stage2_case(
                "stage2-combined-private-keyboardinterrupt-parent-close-error",
                [
                    "dup-L",
                    "open-P",
                    "L-getfl-KeyboardInterrupt",
                    "close-P",
                    "close-L",
                    "MutationError",
                ],
                failure=("L-getfl", "KeyboardInterrupt"),
                close_error="parent",
            )

            read_write_ledger = os.open(
                ledger_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            read_write_offset = os.lseek(read_write_ledger, 23, os.SEEK_SET)
            if read_write_offset == 0 or read_write_offset in {ledger_offset, parent_offset}:
                raise SystemExit("read-write ledger fixture offset is not distinct and nonzero")
            read_write_flags = fcntl.fcntl(read_write_ledger, fcntl.F_GETFL)
            read_write_value = os.fstat(read_write_ledger)
            if (
                read_write_flags & getattr(os, "O_PATH", 0)
                or read_write_flags & os.O_ACCMODE != os.O_RDWR
                or fcntl.fcntl(read_write_ledger, fcntl.F_GETFD) & fcntl.FD_CLOEXEC == 0
                or read_write_value.st_mode & 0o7777 != 0o600
                or read_write_value.st_nlink != 1
            ):
                raise SystemExit("read-write ledger fixture was not a valid 0600 regular FD")
            run_case(
                "ledger-read-write",
                SystemExit,
                {"expected_ledger_fd": read_write_ledger},
                borrowed=[(read_write_ledger, read_write_offset), (parent_fd, parent_offset)],
                full_a2=True,
            )
            os.close(read_write_ledger)

            first_pass_eof_state = {"events": [], "getfl_calls": 0, "pread_calls": 0}
            original_fcntl = fcntl.fcntl
            original_pread = os.pread
            original_fstat = os.fstat

            def first_pass_eof_fcntl(fd, command, *arguments):
                value = original_fcntl(fd, command, *arguments)
                if fd == ledger_fd and command == fcntl.F_GETFL:
                    first_pass_eof_state["events"].append("ledger-getfl")
                    first_pass_eof_state["getfl_calls"] += 1
                return value

            def first_pass_eof_pread(fd, size, offset):
                if fd == ledger_fd:
                    first_pass_eof_state["events"].append("ledger-pread-first")
                    first_pass_eof_state["pread_calls"] += 1
                    return b""
                return original_pread(fd, size, offset)

            def first_pass_eof_fstat(fd):
                value = original_fstat(fd)
                if fd == ledger_fd:
                    first_pass_eof_state["events"].append("ledger-fstat")
                return value

            def check_first_pass_eof():
                if first_pass_eof_state["getfl_calls"] != 1:
                    raise SystemExit("first-pass ledger F_GETFL shim was not reached exactly once")
                if first_pass_eof_state["pread_calls"] != 1:
                    raise SystemExit("first-pass premature EOF shim was not reached exactly once")
                if first_pass_eof_state["events"] != ["ledger-getfl", "ledger-fstat", "ledger-pread-first"]:
                    raise SystemExit("premature EOF was not injected during the first ledger pass")

            run_case(
                "first-pass-premature-eof",
                module.MutationError,
                patches=(
                    (fcntl, "fcntl", first_pass_eof_fcntl),
                    (module.os, "fstat", first_pass_eof_fstat),
                    (module.os, "pread", first_pass_eof_pread),
                ),
                borrowed=base_borrowed,
                postcheck=check_first_pass_eof,
            )

            partial_state = {
                "calls": 0,
                "events": [],
                "offsets": [],
                "lengths": [],
                "passes": [],
                "pass": 0,
                "pass1_fstat": 0,
                "pass2_fstat": 0,
                "custody_fstat": 0,
            }
            original_pread = os.pread
            original_fstat = os.fstat

            def partial_pread(fd, size, offset):
                if fd != ledger_fd:
                    return original_pread(fd, size, offset)
                partial_state["calls"] += 1
                if offset == 0 and partial_state["pass"] == 0:
                    partial_state["pass"] = 1
                elif (
                    offset == 0
                    and partial_state["pass"] == 1
                    and partial_state["pass1_fstat"] == 1
                ):
                    partial_state["pass"] = 2
                if partial_state["pass"] not in {1, 2}:
                    partial_state["passes"].append(0)
                    partial_state["events"].append("ledger-pread-invalid-pass")
                else:
                    partial_state["passes"].append(partial_state["pass"])
                    partial_state["events"].append(f"ledger-pread-pass{partial_state['pass']}")
                partial_state["offsets"].append(offset)
                chunk = original_pread(fd, min(size, 3), offset)
                partial_state["lengths"].append(len(chunk))
                return chunk

            def partial_fstat(fd):
                value = original_fstat(fd)
                if fd == ledger_fd:
                    if partial_state["pass"] == 0:
                        partial_state["events"].append("ledger-fstat-initial")
                    elif partial_state["pass"] == 1 and partial_state["pass1_fstat"] == 0:
                        partial_state["pass1_fstat"] = 1
                        partial_state["events"].append("ledger-fstat-pass1")
                    elif partial_state["pass"] == 2 and partial_state["pass2_fstat"] == 0:
                        partial_state["pass2_fstat"] = 1
                        partial_state["events"].append("ledger-fstat-pass2")
                    elif partial_state["pass"] == 2 and partial_state["custody_fstat"] == 0:
                        partial_state["custody_fstat"] = 1
                        partial_state["events"].append("ledger-fstat-custody")
                    else:
                        partial_state["events"].append("ledger-fstat-extra")
                return value

            def check_partial_pread():
                offsets = partial_state["offsets"]
                lengths = partial_state["lengths"]
                passes = partial_state["passes"]
                ledger_size = len(os.environ["TASK4_GOLDEN"].encode("ascii"))
                if partial_state["calls"] < 4 or not lengths or any(length <= 0 for length in lengths):
                    raise SystemExit("positive partial pread did not cover both complete passes")
                if len(offsets) != len(lengths) or len(offsets) != len(passes):
                    raise SystemExit("positive partial pread accounting drifted")
                if passes.count(1) < 2 or passes.count(2) < 2 or passes.count(0):
                    raise SystemExit("positive partial pread did not produce two multi-chunk passes")
                expected_events = ["ledger-fstat-initial"]
                expected_events.extend("ledger-pread-pass1" for _ in range(passes.count(1)))
                expected_events.append("ledger-fstat-pass1")
                expected_events.extend("ledger-pread-pass2" for _ in range(passes.count(2)))
                expected_events.append("ledger-fstat-pass2")
                expected_events.append("ledger-fstat-custody")
                if partial_state["events"] != expected_events:
                    raise SystemExit("positive partial pread/fstat event order drifted")
                if (
                    partial_state["pass1_fstat"] != 1
                    or partial_state["pass2_fstat"] != 1
                    or partial_state["custody_fstat"] != 1
                ):
                    raise SystemExit("positive partial pread terminal fstats were not unique")
                for pass_number in (1, 2):
                    pass_offsets = [offset for offset, pass_value in zip(offsets, passes) if pass_value == pass_number]
                    pass_lengths = [length for length, pass_value in zip(lengths, passes) if pass_value == pass_number]
                    if not pass_offsets or pass_offsets[0] != 0:
                        raise SystemExit("positive partial pread pass did not start at zero")
                    cursor = 0
                    for offset, length in zip(pass_offsets, pass_lengths):
                        if offset != cursor or length <= 0:
                            raise SystemExit("positive partial pread offsets were not contiguous")
                        cursor += length
                    if cursor != ledger_size:
                        raise SystemExit("positive partial pread pass was incomplete")

            run_case(
                "positive-partial-pread-both-passes",
                SystemExit,
                patches=((module.os, "pread", partial_pread), (module.os, "fstat", partial_fstat)),
                borrowed=base_borrowed,
                postcheck=check_partial_pread,
                full_a2=True,
            )


            for name, value in (
                ("repo_root", repo_root + "/"),
                ("stable_sysroot_root", stable_root + "/."),
                ("nightly_sysroot_root", nightly_root + "//child/.."),
                ("vendor_relative", "/vendor"),
            ):
                for role in ("expected_ledger_fd", "private_parent_fd"):
                    run_case(f"noncanonical-{name}-{role}", module.FormatError, {name: value}, borrowed=base_borrowed)

            run_case(
                "root-overlap",
                module.MutationError,
                {"stable_sysroot_root": repo_root},
                borrowed=base_borrowed,
            )

            foreign_ledger_state = {"calls": 0}
            original_fstat = os.fstat

            def foreign_ledger_fstat(fd):
                value = original_fstat(fd)
                if fd == ledger_fd:
                    foreign_ledger_state["calls"] += 1
                    return StatProxy(value, st_uid=value.st_uid + 1)
                return value

            run_case(
                "ledger-foreign-uid",
                module.FormatError,
                patches=((module.os, "fstat", foreign_ledger_fstat),),
                borrowed=base_borrowed,
                postcheck=lambda: foreign_ledger_state["calls"] >= 1
                or (_ for _ in ()).throw(SystemExit("ledger foreign uid shim was not reached")),
            )

            foreign_parent_state = {"calls": 0}
            original_fstat = os.fstat

            def foreign_parent_fstat(fd):
                value = original_fstat(fd)
                if fd == parent_fd:
                    foreign_parent_state["calls"] += 1
                    return StatProxy(value, st_uid=value.st_uid + 1)
                return value

            run_case(
                "parent-foreign-uid",
                module.FormatError,
                patches=((module.os, "fstat", foreign_parent_fstat),),
                borrowed=base_borrowed,
                postcheck=lambda: foreign_parent_state["calls"] >= 1
                or (_ for _ in ()).throw(SystemExit("parent foreign uid shim was not reached")),
            )

            writable_parent_state = {"calls": 0}
            original_fcntl = fcntl.fcntl

            def writable_parent_fcntl(fd, command, *arguments):
                value = original_fcntl(fd, command, *arguments)
                if fd == parent_fd and command == fcntl.F_GETFL:
                    writable_parent_state["calls"] += 1
                    return (value & ~os.O_ACCMODE) | os.O_RDWR
                return value

            run_case(
                "parent-writable-status",
                module.FormatError,
                patches=((fcntl, "fcntl", writable_parent_fcntl),),
                borrowed=base_borrowed,
                postcheck=lambda: writable_parent_state["calls"] >= 1
                or (_ for _ in ()).throw(SystemExit("parent writable-status shim was not reached")),
            )

            short_state = {"calls": 0, "zero_seen": False, "injected": False}
            original_pread = os.pread

            def short_pread(fd, size, offset):
                short_state["calls"] += 1
                if fd == ledger_fd and offset == 0:
                    if short_state["zero_seen"]:
                        short_state["injected"] = True
                        return b""
                    short_state["zero_seen"] = True
                return original_pread(fd, size, offset)

            run_case(
                "post-baseline-short-pread",
                module.MutationError,
                patches=((module.os, "pread", short_pread),),
                borrowed=base_borrowed,
                postcheck=lambda: (
                    short_state["calls"] >= 2 and short_state["injected"]
                ) or (_ for _ in ()).throw(SystemExit("short pread shim was not reached")),
            )

            mutated_bytes = os.environ["TASK4_GOLDEN"].encode("ascii").replace(b"libstd-abc.so", b"libstd-abX.so", 1)
            byte_state = {"fsync": 0, "injected": False}
            original_fsync = os.fsync
            original_pread = os.pread

            def byte_fsync(fd):
                if fd == parent_fd:
                    byte_state["fsync"] += 1
                return original_fsync(fd)

            def byte_pread(fd, size, offset):
                if fd == ledger_fd and byte_state["fsync"]:
                    byte_state["injected"] = True
                    return mutated_bytes[offset : offset + size]
                return original_pread(fd, size, offset)

            run_case(
                "ledger-byte-mutation-during-fsync",
                module.MutationError,
                patches=((module.os, "fsync", byte_fsync), (module.os, "pread", byte_pread)),
                borrowed=base_borrowed,
                postcheck=lambda: (
                    byte_state["fsync"] == 1 and byte_state["injected"]
                ) or (_ for _ in ()).throw(SystemExit("ledger byte mutation shim was not reached")),
            )

            identity_state = {"fsync": 0, "injected": False}
            original_fsync = os.fsync
            original_fstat = os.fstat

            def identity_fsync(fd):
                if fd == parent_fd:
                    identity_state["fsync"] += 1
                return original_fsync(fd)

            def ledger_identity_fstat(fd):
                value = original_fstat(fd)
                if fd == ledger_fd and identity_state["fsync"]:
                    identity_state["injected"] = True
                    return StatProxy(value, st_ino=value.st_ino + 1)
                return value

            run_case(
                "ledger-identity-mutation-during-fsync",
                module.MutationError,
                patches=((module.os, "fsync", identity_fsync), (module.os, "fstat", ledger_identity_fstat)),
                borrowed=base_borrowed,
                postcheck=lambda: (
                    identity_state["fsync"] == 1 and identity_state["injected"]
                ) or (_ for _ in ()).throw(SystemExit("ledger identity mutation shim was not reached")),
            )

            parent_identity_state = {"fsync": 0, "injected": False}
            original_fsync = os.fsync
            original_fstat = os.fstat

            def parent_identity_fsync(fd):
                if fd == parent_fd:
                    parent_identity_state["fsync"] += 1
                return original_fsync(fd)

            def parent_identity_fstat(fd):
                value = original_fstat(fd)
                if fd == parent_fd and parent_identity_state["fsync"]:
                    parent_identity_state["injected"] = True
                    return StatProxy(value, st_ino=value.st_ino + 1)
                return value

            run_case(
                "parent-identity-mutation-during-fsync",
                module.MutationError,
                patches=((module.os, "fsync", parent_identity_fsync), (module.os, "fstat", parent_identity_fstat)),
                borrowed=base_borrowed,
                postcheck=lambda: (
                    parent_identity_state["fsync"] == 1 and parent_identity_state["injected"]
                ) or (_ for _ in ()).throw(SystemExit("parent identity mutation shim was not reached")),
            )

            flag_state = {"fsync": 0, "getfl": 0, "injected_fl": False}
            original_fsync = os.fsync
            original_fcntl = fcntl.fcntl

            def flag_fsync(fd):
                if fd == parent_fd:
                    flag_state["fsync"] += 1
                return original_fsync(fd)

            def parent_getfl_mutation(fd, command, *arguments):
                value = original_fcntl(fd, command, *arguments)
                if fd == parent_fd and command == fcntl.F_GETFL:
                    flag_state["getfl"] += 1
                    if flag_state["fsync"]:
                        flag_state["injected_fl"] = True
                        return value | os.O_NONBLOCK
                return value

            run_case(
                "parent-getfl-mutation-during-fsync",
                module.MutationError,
                patches=((module.os, "fsync", flag_fsync), (fcntl, "fcntl", parent_getfl_mutation)),
                borrowed=base_borrowed,
                postcheck=lambda: (
                    flag_state["fsync"] == 1 and flag_state["getfl"] >= 2 and flag_state["injected_fl"]
                ) or (_ for _ in ()).throw(SystemExit("parent F_GETFL mutation shim was not reached")),
            )

            fd_state = {"fsync": 0, "getfd": 0, "injected": False}
            original_fsync = os.fsync
            original_fcntl = fcntl.fcntl

            def fd_fsync(fd):
                if fd == parent_fd:
                    fd_state["fsync"] += 1
                return original_fsync(fd)

            def parent_getfd_mutation(fd, command, *arguments):
                value = original_fcntl(fd, command, *arguments)
                if fd == parent_fd and command == fcntl.F_GETFD:
                    fd_state["getfd"] += 1
                    if fd_state["fsync"]:
                        fd_state["injected"] = True
                        return value & ~fcntl.FD_CLOEXEC
                return value

            run_case(
                "parent-getfd-mutation-during-fsync",
                module.MutationError,
                patches=((module.os, "fsync", fd_fsync), (fcntl, "fcntl", parent_getfd_mutation)),
                borrowed=base_borrowed,
                postcheck=lambda: (
                    fd_state["fsync"] == 1 and fd_state["getfd"] >= 2 and fd_state["injected"]
                ) or (_ for _ in ()).throw(SystemExit("parent F_GETFD mutation shim was not reached")),
            )

            ledger_bytes = os.environ["TASK4_GOLDEN"].encode("ascii")
            mutated_ledger_bytes = ledger_bytes.replace(b"libstd-abc.so", b"libstd-abX.so", 1)

            def fsync_error_case(label, error_number, expected, mutation=None, partial=False):
                state = {"failed": False, "fsync": 0, "events": [], "ledger_reads": []}
                original_fsync = os.fsync
                original_fstat = os.fstat
                original_pread = os.pread
                original_fcntl = fcntl.fcntl

                def wrapped_fsync(fd):
                    if fd == parent_fd:
                        state["fsync"] += 1
                        state["failed"] = True
                        raise OSError(error_number, "fixture fsync failure")
                    return original_fsync(fd)

                def wrapped_fstat(fd):
                    value = original_fstat(fd)
                    if state["failed"] and fd == parent_fd:
                        state["events"].append("parent-fstat")
                        if mutation == "parent-identity":
                            state["parent-identity"] = True
                            return StatProxy(value, st_ino=value.st_ino + 1)
                    elif state["failed"] and fd == ledger_fd:
                        state["events"].append("ledger-fstat")
                        if mutation == "ledger-identity":
                            state["ledger-identity"] = True
                            return StatProxy(value, st_ino=value.st_ino + 1)
                    return value

                def wrapped_pread(fd, size, offset):
                    read_size = min(size, 3) if partial else size
                    value = original_pread(fd, read_size, offset)
                    if state["failed"] and fd == ledger_fd:
                        state["events"].append("ledger-pread")
                        if mutation == "ledger-bytes":
                            value = mutated_ledger_bytes[offset : offset + read_size]
                            state["ledger-bytes"] = True
                        state["ledger_reads"].append((offset, len(value)))
                    return value

                def wrapped_fcntl(fd, command, *arguments):
                    value = original_fcntl(fd, command, *arguments)
                    if state["failed"] and fd == parent_fd and command == fcntl.F_GETFL:
                        state["events"].append("parent-getfl")
                        if mutation == "parent-getfl":
                            state["parent-getfl"] = True
                            return value | os.O_NONBLOCK
                    if state["failed"] and fd == parent_fd and command == fcntl.F_GETFD:
                        state["events"].append("parent-getfd")
                        if mutation == "parent-getfd":
                            state["parent-getfd"] = True
                            return value & ~fcntl.FD_CLOEXEC
                    return value

                def check_rechecks():
                    if state["fsync"] != 1:
                        raise SystemExit(f"{label}: fsync shim was not reached exactly once")
                    events = state["events"]
                    required_parent = ["parent-getfl", "parent-getfd", "parent-fstat"]
                    first_ledger_read = events.index("ledger-pread") if "ledger-pread" in events else -1
                    if first_ledger_read < 0:
                        raise SystemExit(f"{label}: second ledger pread was not reached")
                    if events[:3] != required_parent:
                        raise SystemExit(f"{label}: mandatory parent rechecks were not exact and ordered")
                    reads = state["ledger_reads"]
                    if partial and len(reads) < 2:
                        raise SystemExit(f"{label}: partial capability reread was not multi-chunk")
                    cursor = 0
                    for offset, length in reads:
                        if offset != cursor or length <= 0:
                            raise SystemExit(f"{label}: second ledger pread was not contiguous")
                        cursor += length
                    if cursor != len(ledger_bytes):
                        raise SystemExit(f"{label}: second ledger pread was incomplete")
                    expected_events = required_parent + ["ledger-pread"] * len(reads) + ["ledger-fstat"]
                    if events != expected_events:
                        raise SystemExit(f"{label}: mandatory recheck event sequence drifted")
                    if mutation is not None and not state.get(mutation):
                        raise SystemExit(f"{label}: requested mutation shim was not reached")

                patches = (
                    (module.os, "fsync", wrapped_fsync),
                    (module.os, "fstat", wrapped_fstat),
                    (module.os, "pread", wrapped_pread),
                    (fcntl, "fcntl", wrapped_fcntl),
                )
                run_case(
                    label,
                    expected,
                    patches=patches,
                    borrowed=base_borrowed,
                    postcheck=check_rechecks,
                )

            capability_names = tuple(dict.fromkeys(("EINVAL", "ENOSYS", "EOPNOTSUPP", "ENOTSUP")))
            for capability_index, capability_name in enumerate(capability_names):
                fsync_error_case(
                    f"stable-fsync-capability-refusal-{capability_name}",
                    getattr(errno, capability_name),
                    SystemExit,
                    partial=capability_index == 0,
                )
            fsync_error_case("stable-fsync-non-capability-refusal", errno.EIO, module.MutationError)
            for mutation in (
                "parent-getfl",
                "parent-getfd",
                "parent-identity",
                "ledger-bytes",
                "ledger-identity",
            ):
                fsync_error_case(
                    f"mutation-{mutation}-wins-over-capability-refusal",
                    errno.EINVAL,
                    module.MutationError,
                    mutation,
                )

            recovery_state = {
                "failed": False,
                "fsync_calls": 0,
                "fsync_targets": [],
                "getfl_failed": False,
                "events": [],
                "ledger_reads": [],
            }
            original_fstat = os.fstat
            original_pread = os.pread
            original_fcntl = fcntl.fcntl

            def recovery_fsync(fd):
                recovery_state["fsync_targets"].append(fd)
                recovery_state["fsync_calls"] += 1
                if fd == parent_fd:
                    recovery_state["failed"] = True
                    raise OSError(errno.EINVAL, "fixture capability refusal")
                raise OSError(errno.EIO, "unexpected fsync target")

            def recovery_fcntl(fd, command, *arguments):
                value = original_fcntl(fd, command, *arguments)
                if recovery_state["failed"] and fd == parent_fd and command == fcntl.F_GETFL:
                    recovery_state["events"].append("parent-getfl")
                    if not recovery_state["getfl_failed"]:
                        recovery_state["getfl_failed"] = True
                        raise OSError(errno.EIO, "fixture earliest recheck failure")
                elif recovery_state["failed"] and fd == parent_fd and command == fcntl.F_GETFD:
                    recovery_state["events"].append("parent-getfd")
                return value

            def recovery_fstat(fd):
                value = original_fstat(fd)
                if recovery_state["failed"] and fd == parent_fd:
                    recovery_state["events"].append("parent-fstat")
                elif recovery_state["failed"] and fd == ledger_fd:
                    recovery_state["events"].append("ledger-fstat")
                return value

            def recovery_pread(fd, size, offset):
                value = original_pread(fd, size, offset)
                if recovery_state["failed"] and fd == ledger_fd:
                    recovery_state["events"].append("ledger-pread")
                    recovery_state["ledger_reads"].append((offset, len(value)))
                return value

            def check_recovery_after_earliest_failure():
                if recovery_state["fsync_targets"] != [parent_fd]:
                    raise SystemExit("recovery fsync targeted an unexpected descriptor")
                if recovery_state["fsync_calls"] != 1:
                    raise SystemExit("recovery fsync shim was not reached exactly once")
                if not recovery_state["getfl_failed"]:
                    raise SystemExit("earliest parent F_GETFL failure shim was not reached")
                reads = recovery_state["ledger_reads"]
                expected_events = ["parent-getfl", "parent-getfd", "parent-fstat"]
                expected_events.extend("ledger-pread" for _ in reads)
                expected_events.append("ledger-fstat")
                if recovery_state["events"] != expected_events:
                    raise SystemExit("remaining rechecks were not attempted in fixed order")
                cursor = 0
                for offset, length in reads:
                    if offset != cursor or length <= 0:
                        raise SystemExit("recovery ledger reread was not contiguous")
                    cursor += length
                if cursor != len(ledger_bytes):
                    raise SystemExit("recovery ledger reread was incomplete")

            run_case(
                "capability-fsync-earliest-parent-recheck-failure",
                module.MutationError,
                patches=(
                    (module.os, "fsync", recovery_fsync),
                    (module.os, "fstat", recovery_fstat),
                    (module.os, "pread", recovery_pread),
                    (fcntl, "fcntl", recovery_fcntl),
                ),
                borrowed=base_borrowed,
                postcheck=check_recovery_after_earliest_failure,
            )

            run_case(
                "valid-refusal-only-runner",
                SystemExit,
                borrowed=base_borrowed,
                full_a2=True,
            )

            # Stage3A0 RED owns one independent literal fixture for every full-A2 route.

            def stage3_ledger(fixture_bytes, include_link):
                if not fixture_bytes.startswith(b"/") or any(byte >= 0x80 for byte in fixture_bytes):
                    raise SystemExit("stage3 fixture path is not absolute ASCII")
                fixture_abs = fixture_bytes[1:]
                rows = [
                    (
                        "tool",
                        "execute",
                        "present",
                        "0700",
                        "13",
                        "022036a28655c76d3ac5e1584872c898d161687b7578de171ac3447b7447bf68",
                        b"external:/" + fixture_abs + b"/external/tool",
                    ),
                    (
                        "nightly-sysroot",
                        "read",
                        "present",
                        "0600",
                        "2",
                        "28312e346b76a3f91e8283519baab5f103d79547dedff5fb7ccc0dc3c5119bbe",
                        b"external:/" + fixture_abs + b"/nightly/n.bin",
                    ),
                    (
                        "stable-sysroot",
                        "read",
                        "present",
                        "0600",
                        "2",
                        "7aa397df66304bab4fe275afe0507a01844e7fda848b4e194a9402d010721839",
                        b"external:/" + fixture_abs + b"/stable/s.bin",
                    ),
                    (
                        "directory",
                        "probe",
                        "present",
                        "0700",
                        "10",
                        "dff711efda3385276e20031e3c33c758adb07840d3181fb20b23d4d00af6543f",
                        b"repo:/abs",
                    ),
                    ("absent", "probe", "ENOENT", "-", "-", "-", b"repo:/abs/a-missing"),
                    (
                        "repo",
                        "probe",
                        "present",
                        "0600",
                        "1",
                        "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c",
                        b"repo:/abs/blocker",
                    ),
                    ("absent", "probe", "ENOTDIR", "-", "-", "-", b"repo:/abs/blocker/child"),
                    ("absent", "probe", "ENOENT", "-", "-", "-", b"repo:/abs/c-missing"),
                    (
                        "directory",
                        "enumerate",
                        "present",
                        "0700",
                        "21",
                        "2c337acb2a4a9f0836a1b0401109e0464648087c760683e6956dfa0949153305",
                        b"repo:/enum",
                    ),
                    (
                        "symlink",
                        "probe",
                        "present",
                        "0777",
                        "16",
                        "35f44f63e1bc62f86de434856c9acf9de517304b0af8b3fc978cd5d6ae0cf2cc",
                        b"repo:/link",
                    ),
                    (
                        "repo",
                        "read",
                        "present",
                        "0600",
                        "2",
                        "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5",
                        b"repo:/target",
                    ),
                    (
                        "vendor",
                        "read",
                        "present",
                        "0600",
                        "2",
                        "ade9afa39b059ce9954a97780d15c35c204ed2a8ee75199512731550556e6f5f",
                        b"vendor:/v.bin",
                    ),
                ]
                if not include_link:
                    rows = [row for row in rows if row[-1] != b"repo:/link"]
                rows.sort(key=lambda row: row[-1])
                return b"".join(
                    b"\t".join(
                        (
                            b"input-v1",
                            str(index).encode("ascii"),
                            klass.encode("ascii"),
                            access.encode("ascii"),
                            result.encode("ascii"),
                            mode.encode("ascii"),
                            size.encode("ascii"),
                            digest.encode("ascii"),
                            locator,
                        )
                    )
                    + b"\n"
                    for index, (klass, access, result, mode, size, digest, locator) in enumerate(rows)
                )

            def stage3_mkdir(path, mode):
                os.mkdir(path)
                os.chmod(path, mode)

            def stage3_file(path, content, mode):
                with open(path, "wb") as stream:
                    stream.write(content)
                os.chmod(path, mode)

            def stage3_kind(file_type):
                return {
                    stat.S_IFDIR: "directory",
                    stat.S_IFREG: "regular",
                    stat.S_IFLNK: "symlink",
                }.get(file_type, "other")

            def stage3_raw_prefixes(raw_path):
                if type(raw_path) is not bytes or not raw_path.startswith(b"/"):
                    raise SystemExit("stage3 raw anchor is not absolute bytes")
                components = [component for component in raw_path.split(b"/") if component]
                return [
                    b"/" + b"/".join(components[:index])
                    for index in range(1, len(components) + 1)
                ]

            def stage3_a1_graph_events(root_raw, repo_raw, vendor_raw, stable_raw, nightly_raw):
                return [
                    event
                    for edge in stage3_a1_graph_edges(
                        root_raw, repo_raw, vendor_raw, stable_raw, nightly_raw
                    )
                    for event in (
                        ["open-root", "held-fstat:/", "private-parent-disjoint:/"]
                        if edge[0] == "root"
                        else [
                            f"edge-pre-stat:{edge[4].decode('ascii')}",
                            f"open-prefix:{edge[4].decode('ascii')}",
                            f"held-fstat:{edge[4].decode('ascii')}",
                            f"private-parent-disjoint:{edge[4].decode('ascii')}",
                        ]
                        if edge[0] == "edge"
                        else [
                            f"cache-held-fstat:{edge[4].decode('ascii')}",
                            *([] if edge[4] == b"/" else [f"cache-binding-stat:{edge[4].decode('ascii')}"]),
                        ]
                    )
                ] + ["anchor-lineages-exact"]

            def stage3_a1_graph_edges(root_raw, repo_raw, vendor_raw, stable_raw, nightly_raw):
                held = {b"/"}
                edges = [("root", "root", b"/", None, b"/", "open-root")]
                for raw_path, anchor in ((repo_raw, "repo"),):
                    previous = b"/"
                    for prefix in stage3_raw_prefixes(raw_path):
                        if prefix not in held:
                            edge_role = (
                                "ordinary-F"
                                if prefix == root_raw
                                else anchor
                                if prefix == raw_path
                                else None
                            )
                            edges.append(("edge", edge_role, prefix.rsplit(b"/", 1)[-1], previous, prefix, f"open-prefix:{prefix.decode('ascii')}"))
                            held.add(prefix)
                        previous = prefix
                if vendor_raw in held or not vendor_raw.startswith(repo_raw + b"/"):
                    raise SystemExit("stage3 vendor lineage is not a strict repo suffix")
                edges.append(("edge", "vendor", b"vendor", repo_raw, vendor_raw, f"open-prefix:{vendor_raw.decode('ascii')}"))
                held.add(vendor_raw)
                for raw_path, anchor in ((stable_raw, "stable"), (nightly_raw, "nightly")):
                    previous = b"/"
                    for prefix in stage3_raw_prefixes(raw_path):
                        if prefix not in held:
                            edge_role = anchor if prefix == raw_path else None
                            edges.append(("edge", edge_role, prefix.rsplit(b"/", 1)[-1], previous, prefix, f"open-prefix:{prefix.decode('ascii')}"))
                            held.add(prefix)
                        elif prefix != b"/":
                            cache_role = "cache-F" if prefix == root_raw else "cache-shared"
                            edges.append(("cache", cache_role, prefix.rsplit(b"/", 1)[-1], previous, prefix, ""))
                        previous = prefix
                return edges

            stage3_a1_expected_g1 = None
            stage3_a1_expected_edges = None
            stage3_a1_expected_bindings = None
            stage3_a2_expected_operations = None
            stage3_a2_case_expectations = {}
            stage3_a2_row_by_label = {}
            stage3_a1_failure_sites = ("root", "ordinary-F", "repo", "vendor", "stable", "nightly")
            stage3_a1_base_failure_variants = (
                "return-True",
                "return-IntSubclass",
                "return-negative",
                "collision-borrowed-L",
                "collision-borrowed-P",
                "collision-private-L",
                "collision-private-P",
                "ENFILE",
                "EMFILE-rlimit-same",
                "EMFILE-rlimit-drift",
                "KeyboardInterrupt",
            )
            stage3_c0_cases = []
            for item in sorted(stage3_constants | stage3_callables):
                stage3_c0_cases.append(
                    (f"missing-{item[0]}-{item[1]}", "missing", item, None, SystemExit, True)
                )
            for item in sorted(stage3_supports):
                stage3_c0_cases.append(
                    (f"missing-{item[0]}-{item[1]}", "missing-support", item, None, SystemExit, True)
                )
            stage3_c0_cases.append(
                (
                    "missing-O_PATH-no-symlink-continue",
                    "missing",
                    ("os", "O_PATH"),
                    None,
                    SystemExit,
                    False,
                )
            )
            for item in sorted(stage3_callables):
                stage3_c0_cases.append(
                    (f"noncallable-{item[0]}-{item[1]}", "replace", item, 1, module.MutationError, True)
                )
            native_constants = {
                ("os", name): getattr(os, name)
                for name in ("O_RDONLY", "O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY", "O_PATH", "O_ACCMODE")
            }
            native_constants.update(
                {
                    ("fcntl", name): getattr(fcntl, name)
                    for name in ("FD_CLOEXEC", "F_GETFD", "F_GETFL")
                }
            )
            native_constants[("resource", "RLIMIT_NOFILE")] = resource.RLIMIT_NOFILE

            def stage3_invalid_constants(item, variants):
                for label, value in variants:
                    stage3_c0_cases.append(
                        (f"invalid-{item[0]}-{item[1]}-{label}", "replace", item, value, module.MutationError, True)
                    )

            stage3_invalid_constants(
                ("os", "O_RDONLY"),
                (("nonzero", 1), ("bool", True), ("subclass", IntSubclass(0)), ("negative", -1)),
            )
            for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY", "O_PATH"):
                item = ("os", name)
                stage3_invalid_constants(
                    item,
                    (
                        ("zero", 0),
                        ("bool", True),
                        ("subclass", IntSubclass(native_constants[item])),
                        ("negative", -1),
                    ),
                )
            for item in (("os", "O_ACCMODE"), ("fcntl", "FD_CLOEXEC")):
                stage3_invalid_constants(
                    item,
                    (
                        ("zero", 0),
                        ("bool", True),
                        ("subclass", IntSubclass(native_constants[item])),
                        ("negative", -1),
                    ),
                )
            for item in (("fcntl", "F_GETFD"), ("fcntl", "F_GETFL")):
                stage3_invalid_constants(
                    item,
                    (
                        ("bool", True),
                        ("subclass", IntSubclass(native_constants[item])),
                        ("negative", -1),
                    ),
                )
            for name in ("F_GETFD", "F_GETFL"):
                stage3_c0_cases.append(
                    (
                        f"continue-fcntl-{name}-zero",
                        "replace",
                        ("fcntl", name),
                        0,
                        SystemExit,
                        True,
                    )
                )
            stage3_c0_cases.append(
                (
                    "invalid-fcntl-F_GETFL-equals-F_GETFD",
                    "replace",
                    ("fcntl", "F_GETFL"),
                    native_constants[("fcntl", "F_GETFD")],
                    module.MutationError,
                    True,
                )
            )
            security_items = [("os", name) for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY", "O_PATH")]
            for index, left in enumerate(security_items):
                for right in security_items[index + 1 :]:
                    stage3_c0_cases.append(
                        (
                            f"collision-{left[1]}-{right[1]}",
                            "replace",
                            right,
                            native_constants[left],
                            module.MutationError,
                            True,
                        )
                    )
            for item in security_items:
                stage3_c0_cases.append(
                    (
                        f"collision-O_ACCMODE-{item[1]}",
                        "replace",
                        ("os", "O_ACCMODE"),
                        native_constants[("os", "O_ACCMODE")] | native_constants[item],
                        module.MutationError,
                        True,
                    )
                )
            rlimit_item = ("resource", "RLIMIT_NOFILE")
            stage3_invalid_constants(
                rlimit_item,
                (
                    ("bool", True),
                    ("subclass", IntSubclass(resource.RLIMIT_NOFILE)),
                    ("negative", -1),
                ),
            )
            stage3_c0_cases.append(
                (
                    "continue-resource-RLIMIT_NOFILE-zero",
                    "replace",
                    rlimit_item,
                    0,
                    SystemExit,
                    True,
                )
            )
            for label, result in (
                ("wrong-type", None),
                ("wrong-length", (1024,)),
                ("soft-bool", (True, 1048576)),
                ("hard-bool", (1024, True)),
                ("soft-subclass", (IntSubclass(1024), 1048576)),
                ("hard-subclass", (1024, IntSubclass(1048576))),
                ("soft-negative", (-1, 1048576)),
                ("hard-negative", (1024, -1)),
                ("soft-infinite", (resource.RLIM_INFINITY, 1048576)),
                ("hard-infinite", (1024, resource.RLIM_INFINITY)),
                ("reversed", (1048576, 1024)),
            ):
                stage3_c0_cases.append(
                    (f"invalid-rlimit-result-{label}", "rlimit-result", None, result, module.MutationError, True)
                )
            if len(stage3_c0_cases) != 98:
                raise SystemExit(f"stage3a0 capability table cardinality drifted: {len(stage3_c0_cases)}")

            with tempfile.TemporaryDirectory(prefix="p11scope-stage3-") as stage3_root:
                os.chmod(stage3_root, 0o700)
                repo3 = os.path.join(stage3_root, "repo")
                stable3 = os.path.join(stage3_root, "stable")
                nightly3 = os.path.join(stage3_root, "nightly")
                external3 = os.path.join(stage3_root, "external")
                parent3 = os.path.join(stage3_root, "parent")
                stage3_mkdir(repo3, 0o755)
                stage3_mkdir(stable3, 0o755)
                stage3_mkdir(nightly3, 0o755)
                stage3_mkdir(external3, 0o755)
                stage3_mkdir(parent3, 0o700)

                vendor3 = os.path.join(repo3, "vendor")
                abs3 = os.path.join(repo3, "abs")
                enum3 = os.path.join(repo3, "enum")
                stage3_mkdir(vendor3, 0o755)
                stage3_mkdir(abs3, 0o700)
                stage3_mkdir(enum3, 0o700)
                stage3_file(os.path.join(vendor3, "v.bin"), b"V\n", 0o600)
                stage3_file(os.path.join(abs3, "blocker"), b"B", 0o600)
                stage3_file(os.path.join(enum3, "a"), b"A", 0o600)
                stage3_mkdir(os.path.join(enum3, "z"), 0o700)
                raw_enum_name = os.fsencode(enum3) + b"/raw-\xff-name"
                os.symlink(b"unused", raw_enum_name)
                stage3_file(os.path.join(repo3, "target"), b"T\n", 0o600)
                os.symlink(b"./enum/../target", os.path.join(repo3, "link"))
                stage3_file(os.path.join(stable3, "s.bin"), b"S\n", 0o600)
                stage3_file(os.path.join(nightly3, "n.bin"), b"N\n", 0o600)
                stage3_file(os.path.join(external3, "tool"), b"#!/bin/false\n", 0o700)

                expected_objects = {
                    (b"", "directory", 0o700),
                    (b"repo", "directory", 0o755),
                    (b"repo/vendor", "directory", 0o755),
                    (b"repo/vendor/v.bin", "regular", 0o600),
                    (b"repo/abs", "directory", 0o700),
                    (b"repo/abs/blocker", "regular", 0o600),
                    (b"repo/enum", "directory", 0o700),
                    (b"repo/enum/a", "regular", 0o600),
                    (b"repo/enum/raw-\xff-name", "symlink", 0o777),
                    (b"repo/enum/z", "directory", 0o700),
                    (b"repo/link", "symlink", 0o777),
                    (b"repo/target", "regular", 0o600),
                    (b"stable", "directory", 0o755),
                    (b"stable/s.bin", "regular", 0o600),
                    (b"nightly", "directory", 0o755),
                    (b"nightly/n.bin", "regular", 0o600),
                    (b"external", "directory", 0o755),
                    (b"external/tool", "regular", 0o700),
                    (b"parent", "directory", 0o700),
                }
                observed_objects = {
                    (os.fsencode(relative), stage3_kind(file_type), mode)
                    for relative, file_type, mode, _identity_value, _content in tree_state(stage3_root)
                }
                if len(observed_objects) != 19 or observed_objects != expected_objects:
                    raise SystemExit("stage3 literal fixture does not contain exactly 19 objects")

                stage3_payloads = {
                    b"repo/vendor/v.bin": (b"V\n", "ade9afa39b059ce9954a97780d15c35c204ed2a8ee75199512731550556e6f5f"),
                    b"repo/abs/blocker": (b"B", "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c"),
                    b"repo/enum/a": (b"A", "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd"),
                    b"repo/target": (b"T\n", "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5"),
                    b"stable/s.bin": (b"S\n", "7aa397df66304bab4fe275afe0507a01844e7fda848b4e194a9402d010721839"),
                    b"nightly/n.bin": (b"N\n", "28312e346b76a3f91e8283519baab5f103d79547dedff5fb7ccc0dc3c5119bbe"),
                    b"external/tool": (b"#!/bin/false\n", "022036a28655c76d3ac5e1584872c898d161687b7578de171ac3447b7447bf68"),
                }
                for relative, (content, digest) in stage3_payloads.items():
                    path = os.fsencode(stage3_root) + b"/" + relative
                    with open(path, "rb") as stream:
                        observed_content = stream.read()
                    if observed_content != content or hashlib.sha256(content).hexdigest() != digest:
                        raise SystemExit(f"stage3 literal payload mismatch: {relative!r}")
                for relative, target, digest in (
                    (
                        b"repo/link",
                        b"./enum/../target",
                        "35f44f63e1bc62f86de434856c9acf9de517304b0af8b3fc978cd5d6ae0cf2cc",
                    ),
                    (
                        b"repo/enum/raw-\xff-name",
                        b"unused",
                        "febe1d741b49e5a9c31526728d8c5134a803adfc4c04c4f052673722ed85597e",
                    ),
                ):
                    path = os.fsencode(stage3_root) + b"/" + relative
                    if os.readlink(path) != target or hashlib.sha256(target).hexdigest() != digest:
                        raise SystemExit(f"stage3 literal symlink mismatch: {relative!r}")
                enum_preimage = b"F\x00\x01aL\x00\nraw-\xff-nameD\x00\x01z"
                if (
                    len(enum_preimage) != 21
                    or hashlib.sha256(enum_preimage).hexdigest()
                    != "2c337acb2a4a9f0836a1b0401109e0464648087c760683e6956dfa0949153305"
                ):
                    raise SystemExit("stage3 literal enum preimage mismatch")
                abs_preimage = b"F\x00\x07blocker"
                if (
                    len(abs_preimage) != 10
                    or hashlib.sha256(abs_preimage).hexdigest()
                    != "dff711efda3385276e20031e3c33c758adb07840d3181fb20b23d4d00af6543f"
                ):
                    raise SystemExit("stage3 literal abs preimage mismatch")

                stage3_root_bytes = os.fsencode(stage3_root)
                stage3_a1_expected_g1 = stage3_a1_graph_events(
                    stage3_root_bytes,
                    os.fsencode(repo3),
                    os.fsencode(vendor3),
                    os.fsencode(stable3),
                    os.fsencode(nightly3),
                )
                stage3_a1_expected_edges = stage3_a1_graph_edges(
                    stage3_root_bytes,
                    os.fsencode(repo3),
                    os.fsencode(vendor3),
                    os.fsencode(stable3),
                    os.fsencode(nightly3),
                )
                stage3_a1_expected_bindings = [
                    token
                    for edge in stage3_a1_expected_edges
                    if edge[0] != "cache"
                    for token in (
                        [f"bind-held-fstat:{edge[4].decode('ascii')}"]
                        if edge[0] == "root"
                        else [
                            f"bind-held-fstat:{edge[4].decode('ascii')}",
                            f"bind-parent-name-stat:{edge[4].decode('ascii')}",
                        ]
                    )
                ]
                held_root_expected_g1 = stage3_a1_graph_events(
                    b"/", b"/repo", b"/repo/vendor", b"/stable", b"/nightly"
                )
                held_root_expected_edges = stage3_a1_graph_edges(
                    b"/", b"/repo", b"/repo/vendor", b"/stable", b"/nightly"
                )
                held_root_expected_bindings = [
                    token
                    for edge in held_root_expected_edges
                    if edge[0] != "cache"
                    for token in (
                        [f"bind-held-fstat:{edge[4].decode('ascii')}"]
                        if edge[0] == "root"
                        else [
                            f"bind-held-fstat:{edge[4].decode('ascii')}",
                            f"bind-parent-name-stat:{edge[4].decode('ascii')}",
                        ]
                    )
                ]
                stage3_a2_expected_rows = (
                    ("external-tool", b"external:/" + stage3_root_bytes[1:] + b"/external/tool", "tool", "execute", "present", 0o700, 13, "022036a28655c76d3ac5e1584872c898d161687b7578de171ac3447b7447bf68", ("@evidence", "external-parent"), b"tool", "regular"),
                    ("nightly", b"external:/" + stage3_root_bytes[1:] + b"/nightly/n.bin", "nightly-sysroot", "read", "present", 0o600, 2, "28312e346b76a3f91e8283519baab5f103d79547dedff5fb7ccc0dc3c5119bbe", ("@held", os.fsencode(nightly3)), b"n.bin", "regular"),
                    ("stable", b"external:/" + stage3_root_bytes[1:] + b"/stable/s.bin", "stable-sysroot", "read", "present", 0o600, 2, "7aa397df66304bab4fe275afe0507a01844e7fda848b4e194a9402d010721839", ("@held", os.fsencode(stable3)), b"s.bin", "regular"),
                    ("repo-abs", b"repo:/abs", "directory", "probe", "present", 0o700, 10, "dff711efda3385276e20031e3c33c758adb07840d3181fb20b23d4d00af6543f", ("@held", os.fsencode(repo3)), b"abs", "directory"),
                    ("repo-abs-blocker", b"repo:/abs/blocker", "repo", "probe", "present", 0o600, 1, "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c", ("@evidence", "repo-abs"), b"blocker", "regular"),
                    ("repo-enum", b"repo:/enum", "directory", "enumerate", "present", 0o700, 21, "2c337acb2a4a9f0836a1b0401109e0464648087c760683e6956dfa0949153305", ("@held", os.fsencode(repo3)), b"enum", "directory"),
                    ("repo-target", b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5", ("@held", os.fsencode(repo3)), b"target", "regular"),
                    ("vendor", b"vendor:/v.bin", "vendor", "read", "present", 0o600, 2, "ade9afa39b059ce9954a97780d15c35c204ed2a8ee75199512731550556e6f5f", ("@held", os.fsencode(vendor3)), b"v.bin", "regular"),
                )

                def stage3_a2_supplied_rows(ledger_text):
                    supplied = {}
                    for line in ledger_text.encode("ascii").splitlines():
                        fields = line.split(b"\t")
                        if len(fields) != 9 or fields[0] != b"input-v1" or fields[4] != b"present":
                            continue
                        supplied[fields[8]] = (
                            fields[8],
                            fields[2].decode("ascii"),
                            fields[3].decode("ascii"),
                            fields[4].decode("ascii"),
                            int(fields[5], 8),
                            int(fields[6]),
                            fields[7].decode("ascii"),
                        )
                    return supplied

                def stage3_a3_supplied_absence_rows(ledger_text):
                    supplied = {}
                    for line in ledger_text.encode("ascii").splitlines():
                        fields = line.split(b"\t")
                        if len(fields) != 9 or fields[0] != b"input-v1" or fields[2] != b"absent":
                            continue
                        supplied[fields[8]] = (
                            fields[8],
                            fields[2].decode("ascii"),
                            fields[3].decode("ascii"),
                            fields[4].decode("ascii"),
                        )
                    return supplied

                stage3_a2_row_by_label = {row[0]: row for row in stage3_a2_expected_rows}
                regular_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                directory_flags = regular_flags | os.O_DIRECTORY
                stage3_a2_expected_operations = [
                    ("parent-stat:external-parent", "os", "stat", (b"external",), (("dir_fd", ("@held", stage3_root_bytes)), ("follow_symlinks", False))),
                    ("parent-open:external-parent", "os", "open", (b"external", directory_flags), (("dir_fd", ("@held", stage3_root_bytes)),)),
                    ("parent-fstat:external-parent", "os", "fstat", ("@current",), ()),
                ]

                def stage3_a2_regular_descriptors(row):
                    label, _locator, _klass, _access, _result, _mode, _size, _digest, parent_role, name, _kind = row
                    return [
                        (f"regular-open:{label}", "os", "open", (name, regular_flags), (("dir_fd", parent_role),)),
                        (f"regular-fstat-pre:{label}", "os", "fstat", ("@current",), ()),
                        (f"regular-pread:{label}", "os", "pread", ("@current", "@request", "@cursor"), ()),
                        (f"regular-fstat-post:{label}", "os", "fstat", ("@current",), ()),
                    ]

                directory_entries = {
                    "external-root": (
                        ("external", b"external", stat.S_IFDIR),
                        ("nightly", b"nightly", stat.S_IFDIR),
                        ("parent", b"parent", stat.S_IFDIR),
                        ("repo", b"repo", stat.S_IFDIR),
                        ("stable", b"stable", stat.S_IFDIR),
                    ),
                    "repo-abs": (("blocker", b"blocker", stat.S_IFREG),),
                    "repo-enum": (
                        ("a", b"a", stat.S_IFREG),
                        ("z", b"z", stat.S_IFDIR),
                        ("raw-\udcff-name", b"raw-\xff-name", stat.S_IFLNK),
                    ),
                }

                def stage3_a2_directory_descriptors(row):
                    label, _locator, _klass, _access, _result, _mode, _size, _digest, parent_role, name, _kind = row
                    result = [
                        (f"directory-open:{label}", "os", "open", (name, directory_flags), (("dir_fd", parent_role),)),
                        (f"directory-fstat0:{label}", "os", "fstat", ("@current",), ()),
                    ]
                    for scan in (1, 2):
                        result.extend(
                            (
                                (f"scan{scan}-open:{label}", "os", "open", (b".", directory_flags), (("dir_fd", ("@evidence", label)),)),
                                (f"list{scan}:{label}", "os", "listdir", ("@scan",), ()),
                            )
                        )
                        entries = directory_entries[label]
                        if label == "repo-enum":
                            entries = (
                                (entries[1], entries[2], entries[0])
                                if scan == 1
                                else (entries[2], entries[0], entries[1])
                            )
                        for text_name, raw_name, _file_type in entries:
                            suffix = raw_name.hex()
                            result.extend(
                                (
                                    (f"fsencode{scan}:{label}:{suffix}", "os", "fsencode", (text_name,), ()),
                                    (f"entry-stat{scan}:{label}:{suffix}", "os", "stat", (raw_name,), (("dir_fd", "@scan"), ("follow_symlinks", False))),
                                )
                            )
                        result.extend(
                            (
                                (f"scan{scan}-close:{label}", "os", "close", ("@scan",), ()),
                                (f"directory-fstat{scan}:{label}", "os", "fstat", (("@evidence", label),), ()),
                            )
                        )
                    return result

                stage3_a2_held_root_rows = (
                    (
                        "external-root", b"external:/", "directory", "probe", "present",
                        0o700, 46,
                        "fdebc2828ff8f3c44dd0abe878bed6766de457d1fc601f1b6a5975420b8968f2",
                        ("@held", b"/"), b"", "directory",
                    ),
                )
                stage3_a2_held_root_expected_operations = (
                    (
                        "directory-fstat0:external-root", "os", "fstat",
                        (("@held", b"/"),), (),
                    ),
                ) + tuple(
                    stage3_a2_directory_descriptors(stage3_a2_held_root_rows[0])[2:]
                )

                for row in stage3_a2_expected_rows:
                    stage3_a2_expected_operations.extend(
                        stage3_a2_regular_descriptors(row)
                        if row[-1] == "regular"
                        else stage3_a2_directory_descriptors(row)
                    )
                stage3_a2_expected_operations = tuple(stage3_a2_expected_operations)
                if (
                    tuple(row[0] for row in stage3_a2_expected_rows)
                    != (
                        "external-tool",
                        "nightly",
                        "stable",
                        "repo-abs",
                        "repo-abs-blocker",
                        "repo-enum",
                        "repo-target",
                        "vendor",
                    )
                    or len(stage3_a2_expected_rows) != 8
                    or not stage3_a2_expected_operations
                ):
                    raise SystemExit("stage3a2 literal positive oracle drifted")
                symlink_flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
                repo_raw = os.fsencode(repo3)
                link_parent = ("@held", repo_raw)

                def stage3_a3_occurrence(occurrence, name, locator, *, text_target=False):
                    read_name = name
                    result = [
                        (f"symlink-open:{locator}:{occurrence}", "os", "open", (name, symlink_flags), (("dir_fd", link_parent),)),
                        (f"symlink-held-fstat0:{occurrence}", "os", "fstat", (("@a3", occurrence),), ()),
                        (f"symlink-parent-stat0:{occurrence}", "os", "stat", (name,), (("dir_fd", link_parent), ("follow_symlinks", False))),
                        (f"readlink1:{locator}:{occurrence}", "os", "readlink", (read_name,), (("dir_fd", link_parent),)),
                    ]
                    if text_target:
                        result.append((f"target-fsencode1:{occurrence}", "os", "fsencode", ("@read1",), ()))
                    result.extend(
                        (
                            (f"symlink-held-fstat1:{occurrence}", "os", "fstat", (("@a3", occurrence),), ()),
                            (f"symlink-parent-stat1:{occurrence}", "os", "stat", (name,), (("dir_fd", link_parent), ("follow_symlinks", False))),
                            (f"readlink2:{locator}:{occurrence}", "os", "readlink", (read_name,), (("dir_fd", link_parent),)),
                        )
                    )
                    if text_target:
                        result.append((f"target-fsencode2:{occurrence}", "os", "fsencode", ("@read2",), ()))
                    result.extend(
                        (
                            (f"symlink-held-fstat2:{occurrence}", "os", "fstat", (("@a3", occurrence),), ()),
                            (f"symlink-parent-stat2:{occurrence}", "os", "stat", (name,), (("dir_fd", link_parent), ("follow_symlinks", False))),
                        )
                    )
                    return tuple(result)

                def stage3_a3_target_relation(index, label, parent_role, name, held_role):
                    return (
                        (f"target-parent-stat:{index}:{label}", "os", "stat", (name,), (("dir_fd", parent_role), ("follow_symlinks", False))),
                        (f"target-held-fstat:{index}:{label}", "os", "fstat", (held_role,), ()),
                    )

                def stage3_a3_target_components(relations):
                    return tuple(
                        descriptor
                        for index, (label, parent_role, name, held_role) in enumerate(relations)
                        for descriptor in stage3_a3_target_relation(
                            index, label, parent_role, name, held_role
                        )
                    )

                stage3_a3_absence_operations = (
                    ("absent-boundary-parent:repo:/abs/a-missing", "os", "stat", (b"abs",), (("dir_fd", ("@held", repo_raw)), ("follow_symlinks", False))),
                    ("absent-boundary-held:repo:/abs/a-missing", "os", "fstat", (("@evidence", "repo-abs"),), ()),
                    ("absent-terminal:repo:/abs/a-missing:ENOENT", "os", "stat", (b"a-missing",), (("dir_fd", ("@evidence", "repo-abs")), ("follow_symlinks", False))),
                    ("absent-boundary-parent:repo:/abs/blocker/child", "os", "stat", (b"blocker",), (("dir_fd", ("@evidence", "repo-abs")), ("follow_symlinks", False))),
                    ("absent-boundary-held:repo:/abs/blocker/child", "os", "fstat", (("@evidence", "repo-abs-blocker"),), ()),
                    ("absent-terminal:repo:/abs/blocker/child:ENOTDIR", "os", "stat", (b"child",), (("dir_fd", ("@evidence", "repo-abs-blocker")), ("follow_symlinks", False))),
                    ("absent-boundary-parent:repo:/abs/c-missing", "os", "stat", (b"abs",), (("dir_fd", ("@held", repo_raw)), ("follow_symlinks", False))),
                    ("absent-boundary-held:repo:/abs/c-missing", "os", "fstat", (("@evidence", "repo-abs"),), ()),
                    ("absent-terminal:repo:/abs/c-missing:ENOENT", "os", "stat", (b"c-missing",), (("dir_fd", ("@evidence", "repo-abs")), ("follow_symlinks", False))),
                )
                multi_component_absence_operations = (
                    ("absent-boundary-parent:repo:/abs/a-missing/leaf", "os", "stat", (b"abs",), (("dir_fd", ("@held", repo_raw)), ("follow_symlinks", False))),
                    ("absent-boundary-held:repo:/abs/a-missing/leaf", "os", "fstat", (("@evidence", "repo-abs"),), ()),
                    ("absent-terminal:repo:/abs/a-missing/leaf:ENOENT", "os", "stat", (b"a-missing/leaf",), (("dir_fd", ("@evidence", "repo-abs")), ("follow_symlinks", False))),
                ) + stage3_a3_absence_operations[3:]
                multi_component_enotdir_absence_operations = (
                    stage3_a3_absence_operations[:3]
                    + (
                        ("absent-boundary-parent:repo:/abs/blocker/child/leaf", "os", "stat", (b"blocker",), (("dir_fd", ("@evidence", "repo-abs")), ("follow_symlinks", False))),
                        ("absent-boundary-held:repo:/abs/blocker/child/leaf", "os", "fstat", (("@evidence", "repo-abs-blocker"),), ()),
                        ("absent-terminal:repo:/abs/blocker/child/leaf:ENOTDIR", "os", "stat", (b"child/leaf",), (("dir_fd", ("@evidence", "repo-abs-blocker")), ("follow_symlinks", False))),
                    )
                    + stage3_a3_absence_operations[6:]
                )

                repo_target = stage3_a3_target_components(
                    (("repo-target", ("@held", repo_raw), b"target", ("@evidence", "repo-target")),)
                )
                relative_target = stage3_a3_target_components(
                    (
                        ("repo-enum", ("@held", repo_raw), b"enum", ("@evidence", "repo-enum")),
                        ("repo-target", ("@held", repo_raw), b"target", ("@evidence", "repo-target")),
                    )
                )
                repo_enum = stage3_a3_target_components(
                    (("repo-enum", ("@held", repo_raw), b"enum", ("@evidence", "repo-enum")),)
                )
                vendor_target = stage3_a3_target_components(
                    (
                        ("vendor-dir", ("@held", repo_raw), b"vendor", ("@held", os.fsencode(vendor3))),
                        ("vendor", ("@held", os.fsencode(vendor3)), b"v.bin", ("@evidence", "vendor")),
                    )
                )
                stage3_root_literal_names = tuple(
                    name for name in stage3_root_bytes.split(b"/") if name
                )
                stage3_root_literal_prefixes = tuple(
                    b"/" + b"/".join(stage3_root_literal_names[:index])
                    for index in range(1, len(stage3_root_literal_names) + 1)
                )
                external_literal_names = stage3_root_literal_names + (b"external",)
                external_literal_prefixes = stage3_root_literal_prefixes + (os.fsencode(external3),)
                external_literal_relations = tuple(
                    (
                        "external-parent" if index == len(external_literal_names) - 1 else f"absolute-prefix-{index}",
                        ("@held", b"/") if index == 0 else (
                            ("@held", stage3_root_literal_prefixes[index - 1])
                            if index <= len(stage3_root_literal_prefixes)
                            else ("@evidence", "external-parent")
                        ),
                        name,
                        ("@evidence", "external-parent")
                        if index == len(external_literal_names) - 1
                        else ("@held", external_literal_prefixes[index]),
                    )
                    for index, name in enumerate(external_literal_names)
                )
                repo_literal_names = tuple(name for name in repo_raw.split(b"/") if name)
                repo_literal_prefixes = tuple(stage3_raw_prefixes(repo_raw))
                root_literal_relations = tuple(
                    (
                        "repo-dir" if index == len(repo_literal_names) - 1 else f"root-prefix-{index}",
                        ("@held", b"/") if index == 0 else ("@held", repo_literal_prefixes[index - 1]),
                        name,
                        ("@held", repo_raw)
                        if index == len(repo_literal_names) - 1
                        else ("@held", repo_literal_prefixes[index]),
                    )
                    for index, name in enumerate(repo_literal_names)
                )
                external_target = stage3_a3_target_components(external_literal_relations) + stage3_a3_target_components(
                    (("external-tool", ("@evidence", "external-parent"), b"tool", ("@evidence", "external-tool")),)
                )
                root_clamped_target = stage3_a3_target_components(root_literal_relations) + repo_target
                primary = stage3_a3_occurrence(1, b"link", "repo:/link")
                primary_text = stage3_a3_occurrence(1, b"link", "repo:/link", text_target=True)
                nested_trailing = (
                    primary
                    + (
                        stage3_a3_target_relation(
                            1, "repo-unreviewed-link", link_parent, b"unreviewed-link", None
                        )[0],
                    )
                    + stage3_a3_occurrence(2, b"unreviewed-link", "repo:/unreviewed-link")
                    + repo_target
                )
                disjoint_first_root = primary + repo_target
                disjoint_first_root_tokens = tuple(
                    descriptor[0] for descriptor in disjoint_first_root
                )
                disjoint_symlink_roots = (
                    disjoint_first_root
                    + stage3_a3_occurrence(2, b"link-b", "repo:/link-b")
                    + repo_target
                )
                reviewed_target_absence = (
                    primary
                    + stage3_a3_target_relation(
                        1, "repo-abs", link_parent, b"abs", ("@evidence", "repo-abs")
                    )
                    + (
                        (
                            "target-absence-terminal:1:repo:/abs/a-missing:ENOENT",
                            "os",
                            "stat",
                            (b"a-missing",),
                            (
                                ("dir_fd", ("@evidence", "repo-abs")),
                                ("follow_symlinks", False),
                            ),
                        ),
                    )
                )
                reviewed_target_absence_tokens = tuple(
                    descriptor[0] for descriptor in reviewed_target_absence
                )
                multi_component_absence = (
                    primary
                    + stage3_a3_target_relation(
                        1, "repo-abs", link_parent, b"abs", ("@evidence", "repo-abs")
                    )
                    + (
                        (
                            "target-absence-terminal:1:repo:/abs/a-missing/leaf:ENOENT",
                            "os",
                            "stat",
                            (b"a-missing/leaf",),
                            (
                                ("dir_fd", ("@evidence", "repo-abs")),
                                ("follow_symlinks", False),
                            ),
                        ),
                    )
                )
                multi_component_absence_tokens = tuple(
                    descriptor[0] for descriptor in multi_component_absence
                )
                multi_component_enotdir = (
                    primary
                    + stage3_a3_target_relation(
                        1, "repo-abs", link_parent, b"abs", ("@evidence", "repo-abs")
                    )
                    + stage3_a3_target_relation(
                        2, "repo-abs-blocker", ("@evidence", "repo-abs"), b"blocker", ("@evidence", "repo-abs-blocker")
                    )
                    + (
                        (
                            "target-absence-terminal:2:repo:/abs/blocker/child/leaf:ENOTDIR",
                            "os",
                            "stat",
                            (b"child/leaf",),
                            (
                                ("dir_fd", ("@evidence", "repo-abs-blocker")),
                                ("follow_symlinks", False),
                            ),
                        ),
                    )
                )
                multi_component_enotdir_tokens = tuple(
                    descriptor[0] for descriptor in multi_component_enotdir
                )
                held_root_primary = (
                    ("symlink-open:repo:/link:1", "os", "open", (b"link", symlink_flags), (("dir_fd", ("@held", b"/repo")),)),
                    ("symlink-held-fstat0:1", "os", "fstat", (("@a3", 1),), ()),
                    ("symlink-parent-stat0:1", "os", "stat", (b"link",), (("dir_fd", ("@held", b"/repo")), ("follow_symlinks", False))),
                    ("readlink1:repo:/link:1", "os", "readlink", (b"link",), (("dir_fd", ("@held", b"/repo")),)),
                    ("symlink-held-fstat1:1", "os", "fstat", (("@a3", 1),), ()),
                    ("symlink-parent-stat1:1", "os", "stat", (b"link",), (("dir_fd", ("@held", b"/repo")), ("follow_symlinks", False))),
                    ("readlink2:repo:/link:1", "os", "readlink", (b"link",), (("dir_fd", ("@held", b"/repo")),)),
                    ("symlink-held-fstat2:1", "os", "fstat", (("@a3", 1),), ()),
                    ("symlink-parent-stat2:1", "os", "stat", (b"link",), (("dir_fd", ("@held", b"/repo")), ("follow_symlinks", False))),
                )
                held_root_body_prefix_tokens = tuple(
                    descriptor[0] for descriptor in held_root_primary
                )
                held_root_target_absence = held_root_primary + (
                    (
                        "target-held-fstat:1:external:/root-missing/leaf", "os", "fstat",
                        (("@held", b"/"),), (),
                    ),
                    (
                        "target-absence-terminal:1:external:/root-missing/leaf:ENOENT", "os", "stat",
                        (b"root-missing/leaf",),
                        (("dir_fd", ("@held", b"/")), ("follow_symlinks", False)),
                    ),
                )
                held_root_absence = (
                    (
                        "absent-boundary-held:external:/root-missing/leaf", "os", "fstat",
                        (("@held", b"/"),), (),
                    ),
                    (
                        "absent-terminal:external:/root-missing/leaf:ENOENT", "os", "stat",
                        (b"root-missing/leaf",),
                        (("dir_fd", ("@held", b"/")), ("follow_symlinks", False)),
                    ),
                )
                held_root_absence_tokens = tuple(
                    descriptor[0] for descriptor in held_root_absence
                )
                stage3_a3_live_cases = [
                    ("relative-primary", primary + relative_target, stage3_a3_absence_operations, SystemExit, {"raw_target": b"./enum/../target", "target_row": (b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5")}, "base"),
                    ("absolute-external-str", primary_text + external_target, stage3_a3_absence_operations, SystemExit, {"raw_target": os.fsdecode(os.fsencode(external3) + b"/tool"), "target_row": (b"external:/" + stage3_root_bytes[1:] + b"/external/tool", "tool", "execute", "present", 0o700, 13, "022036a28655c76d3ac5e1584872c898d161687b7578de171ac3447b7447bf68")}, "external-str"),
                    ("repeated-slash-vendor", primary + vendor_target, stage3_a3_absence_operations, SystemExit, {"raw_target": b".//vendor///v.bin", "target_row": (b"vendor:/v.bin", "vendor", "read", "present", 0o600, 2, "ade9afa39b059ce9954a97780d15c35c204ed2a8ee75199512731550556e6f5f")}, "repeated"),
                    ("root-clamped-dotdot", primary + root_clamped_target, stage3_a3_absence_operations, SystemExit, {"raw_target": b"../" * 64 + repo_raw.lstrip(b"/") + b"/target", "target_row": (b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5")}, "root-clamped"),
                    ("trailing-directory", primary + repo_enum, stage3_a3_absence_operations, SystemExit, {"raw_target": b"./enum/", "target_row": (b"repo:/enum", "directory", "enumerate", "present", 0o700, 21, "2c337acb2a4a9f0836a1b0401109e0464648087c760683e6956dfa0949153305")}, "trailing-directory"),
                    ("trailing-nondirectory", primary + repo_target, (), module.MutationError, {"raw_target": b"./target/", "expected_route": "governed", "target_row": (b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5")}, "trailing-nondirectory"),
                ]

                chain40_parts = []
                chain41_parts = []
                for occurrence in range(1, 41):
                    current_name = f"chain{occurrence - 1:02d}".encode("ascii")
                    common = stage3_a3_occurrence(
                        occurrence, current_name, f"repo:/chain{occurrence - 1:02d}"
                    )
                    chain40_parts.extend(common)
                    chain41_parts.extend(common)
                    if occurrence == 40:
                        chain40_parts.extend(repo_target)
                        chain41_parts.append(
                            stage3_a3_target_relation(
                                occurrence, "repo-chain40", link_parent, b"chain40", None
                            )[0]
                        )
                    else:
                        next_name = f"chain{occurrence:02d}".encode("ascii")
                        relation = stage3_a3_target_relation(
                            occurrence, f"repo-chain{occurrence:02d}", link_parent, next_name, None
                        )[0]
                        chain40_parts.append(relation)
                        chain41_parts.append(relation)
                chain40 = tuple(chain40_parts)
                chain41 = tuple(chain41_parts) + stage3_a3_occurrence(41, b"chain40", "repo:/chain40")[:3]
                stage3_a3_live_cases.extend(
                    (
                        ("chain40", chain40, stage3_a3_absence_operations, SystemExit, {"raw_target": b"chain01", "target_row": (b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5")}, "chain40"),
                    ("chain41-refused", chain41, (), module.MutationError, {"raw_target": b"chain01", "expected_route": "follow41", "target_row": None}, "chain41"),
                    ("nested-trailing-slash-regular", nested_trailing, (), module.MutationError, {"raw_target": b"unreviewed-link/", "expected_route": "governed", "target_row": (b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5")}, "nested-trailing-slash-regular"),
                    ("disjoint-symlink-roots", disjoint_symlink_roots, stage3_a3_absence_operations, SystemExit, {"raw_target": b"target", "target_row": (b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5")}, "disjoint-symlink-roots"),
                    ("reviewed-symlink-target-absence", reviewed_target_absence, stage3_a3_absence_operations, SystemExit, {"raw_target": b"abs/a-missing", "target_row": (b"repo:/abs", "directory", "probe", "present", 0o700, 10, "dff711efda3385276e20031e3c33c758adb07840d3181fb20b23d4d00af6543f")}, "base"),
                    ("multi-component-canonical-absence", multi_component_absence, multi_component_absence_operations, SystemExit, {"raw_target": b"abs/a-missing/leaf", "target_row": (b"repo:/abs", "directory", "probe", "present", 0o700, 10, "dff711efda3385276e20031e3c33c758adb07840d3181fb20b23d4d00af6543f")}, "multi-component-canonical-absence"),
                    ("multi-component-canonical-enotdir", multi_component_enotdir, multi_component_enotdir_absence_operations, SystemExit, {"raw_target": b"abs/blocker/child/leaf", "target_row": (b"repo:/abs/blocker", "repo", "probe", "present", 0o600, 1, "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c")}, "multi-component-canonical-enotdir"),
                    ("held-root-canonical-absence", held_root_target_absence, held_root_absence, SystemExit, {"raw_target": b"/root-missing/leaf", "target_row": None}, "held-root-canonical-absence"),
                    ("no-symlink-ledger", (), stage3_a3_absence_operations, SystemExit, {"no_symlink": True, "target_row": None}, "no-symlink"),
                        ("canonical-absence-empty", primary + relative_target, (), SystemExit, {"raw_target": b"./enum/../target", "target_row": (b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5")}, "no-absence"),
                        ("a3-close-real-then-raise", primary + relative_target, stage3_a3_absence_operations, module.MutationError, {"raw_target": b"./enum/../target", "a3_close_failure": True, "target_row": (b"repo:/target", "repo", "read", "present", 0o600, 2, "678f81a714fbc72030f82f9980054d5cf90e6f041a367f7da2f35b0f7dafb0e5")}, "base"),
                    )
                )

                missing_target = stage3_a3_target_relation(
                    0, "repo-unreviewed-target", link_parent, b"unreviewed-target", None
                )[0:1]
                locator_mismatch_target = stage3_a3_target_relation(
                    0, "repo-locator-alias", link_parent, b"locator-alias", None
                )[0:1]
                namespace_mismatch_target = stage3_a3_target_relation(
                    0, "repo-namespace-alias", link_parent, b"namespace-alias", None
                )[0:1]
                unreviewed_target = (
                    ("target-parent-stat:0:repo-unreviewed-link", "os", "stat", (b"unreviewed-link",), (("dir_fd", link_parent), ("follow_symlinks", False))),
                )
                unreviewed_held_final_target = stage3_a3_target_relation(
                    0, "vendor-dir", link_parent, b"vendor", ("@held", os.fsencode(vendor3))
                )
                stage3_a3_live_cases.extend(
                    (
                        ("symlink-size-mismatch", primary, (), module.MutationError, {"raw_target": b"./enum/../target", "expected_route": "governed", "symlink_row_size": len(b"./enum/../target") + 1, "target_row": None}, "symlink-size-mismatch"),
                        ("symlink-digest-mismatch", primary, (), module.MutationError, {"raw_target": b"./enum/../target", "expected_route": "governed", "symlink_row_digest": "0" * 64, "target_row": None}, "symlink-digest-mismatch"),
                        ("missing-reviewed-final-row", primary + missing_target, (), module.MutationError, {"raw_target": b"./unreviewed-target", "expected_route": "governed", "target_row": None}, "base"),
                        ("final-locator-mismatch", primary + locator_mismatch_target, (), module.MutationError, {"raw_target": b"./locator-alias", "expected_route": "governed", "target_row": None}, "base"),
                        ("final-namespace-mismatch", primary + namespace_mismatch_target, (), module.MutationError, {"raw_target": b"./namespace-alias", "expected_route": "governed", "target_row": None}, "base"),
                        ("intermediate-unreviewed-symlink", primary + unreviewed_target, (), module.MutationError, {"raw_target": b"./unreviewed-link", "expected_route": "governed", "target_row": None}, "base"),
                        ("unreviewed-held-final-directory", primary + unreviewed_held_final_target, stage3_a3_absence_operations, module.MutationError, {"raw_target": b"vendor", "target_row": None}, "base"),
                    )
                )
                if len(stage3_a3_live_cases) != 24 or len({case[0] for case in stage3_a3_live_cases}) != 24:
                    raise SystemExit("stage3a3 executable live case table drifted")
                stage3_a3_specs = {
                    label: (body, absence)
                    for label, body, absence, _expected, _options, _ledger in stage3_a3_live_cases
                }

                def check_disjoint_root_missing_probe_controls():
                    accepted = {
                        "stage3_case": ("stage3a3-case", "disjoint-symlink-roots", {}),
                        "a1_phase": "a3",
                        "a3_body_operations": disjoint_symlink_roots,
                        "a3_body_events": list(disjoint_first_root_tokens),
                        "disjoint_first_root_tokens": disjoint_first_root_tokens,
                        "a3_absence_operations": (),
                        "a3_absence_events": [],
                        "a1_body_outcome": "success",
                        "a3_first_body_failure": None,
                        "a1_emfile": False,
                        "gb_failed": False,
                        "disjoint_root_missing": False,
                        "private_ledger_fd": 42,
                        "constant_values": {("fcntl", "F_GETFL"): fcntl.F_GETFL},
                    }
                    accepted_call = ("fcntl", "fcntl", (42, fcntl.F_GETFL), {})
                    if not disjoint_root_missing_probe_allowed(accepted, *accepted_call):
                        raise SystemExit("stage3a3 disjoint root positive probe was rejected")
                    controls = [
                        ("partial body", {"a3_body_events": list(disjoint_first_root_tokens[:-1])}),
                        ("changed body", {"a3_body_events": ["changed", *disjoint_first_root_tokens[1:]]}),
                        ("extra body", {"a3_body_events": [*disjoint_first_root_tokens, "extra"]}),
                        ("full body", {"a3_body_events": [descriptor[0] for descriptor in disjoint_symlink_roots]}),
                        ("wrong case", {"stage3_case": ("stage3a3-case", "relative-primary", {})}),
                        ("wrong phase", {"a1_phase": "fp"}),
                        ("governed outcome", {"a1_body_outcome": "governed"}),
                        ("capacity outcome", {"a1_body_outcome": "capacity", "a1_emfile": True}),
                        ("arbitrary outcome", {"a1_body_outcome": "arbitrary"}),
                        ("body failure", {"a3_first_body_failure": "body-failure"}),
                        ("used flag", {"disjoint_root_missing": True}),
                        ("wrong namespace", {"namespace": "os"}),
                        ("wrong name", {"name": "open"}),
                        ("wrong fd", {"arguments": (43, fcntl.F_GETFL)}),
                        ("later FP token", {"arguments": (42, fcntl.F_GETFD)}),
                        ("wrong arguments", {"arguments": (42, fcntl.F_GETFL, 0)}),
                        ("keywords", {"arguments_by_name": {"dir_fd": 42}}),
                        ("close", {"namespace": "os", "name": "close", "arguments": (42,)}),
                        (
                            "graph stat",
                            {
                                "namespace": "os",
                                "name": "stat",
                                "arguments": (b"tmp",),
                                "arguments_by_name": {"dir_fd": 42, "follow_symlinks": False},
                            },
                        ),
                        (
                            "future link-b open",
                            {
                                "namespace": "os",
                                "name": "open",
                                "arguments": (b"link-b", symlink_flags),
                                "arguments_by_name": {"dir_fd": 42},
                            },
                        ),
                    ]
                    for label, overrides in controls:
                        trial = dict(accepted)
                        namespace, name, arguments, arguments_by_name = accepted_call
                        namespace = overrides.get("namespace", namespace)
                        name = overrides.get("name", name)
                        arguments = overrides.get("arguments", arguments)
                        arguments_by_name = overrides.get("arguments_by_name", arguments_by_name)
                        trial.update(
                            {
                                key: value
                                for key, value in overrides.items()
                                if key not in {"namespace", "name", "arguments", "arguments_by_name"}
                            }
                        )
                        if disjoint_root_missing_probe_allowed(
                            trial, namespace, name, arguments, arguments_by_name
                        ):
                            raise SystemExit(
                                f"stage3a3 disjoint root negative control accepted: {label}"
                            )

                check_disjoint_root_missing_probe_controls()

                check_reviewed_target_absence_probe_controls()
                check_multi_component_absence_fp_probe_controls()
                check_multi_component_absence_cleanup_probe_controls()
                check_multi_component_enotdir_probe_controls()
                check_multi_component_enotdir_missing_probe_controls()
                check_held_root_missing_probe_controls()
                check_held_root_first_fp_bridge_controls()

                stage3_a3_mutations = []

                def stage3_a3_mutation(label, token, variant, *, options=None, expected=module.MutationError, route="governed", spec="relative-primary", ledger="base"):
                    values = dict(options or ())
                    values.update({"spec": spec, "expected_route": route})
                    stage3_a3_mutations.append((label, token, variant, values, expected, route, ledger))

                first_open = primary[0][0]
                for variant in (
                    "return-True", "return-IntSubclass", "return-negative",
                    "collision-borrowed-L", "collision-borrowed-P",
                    "collision-private-L", "collision-private-P", "collision-graph",
                    "EIO", "ENFILE", "EMFILE-rlimit-same", "EMFILE-rlimit-drift",
                ):
                    stage3_a3_mutation(
                        f"open-{variant}", first_open, variant,
                        expected=SystemExit if variant == "EMFILE-rlimit-same" else module.MutationError,
                        options={"raw_target": b"./enum/../target"},
                        route="capacity" if variant == "EMFILE-rlimit-same" else "governed",
                    )
                repeated_link_relation = stage3_a3_target_relation(
                    1, "repo-link-again", link_parent, b"link", None
                )[0:1]
                two_links = primary + repeated_link_relation + stage3_a3_occurrence(
                    2, b"link", "repo:/link"
                )
                stage3_a3_specs["two-link-collision"] = (two_links, ())
                stage3_a3_mutation(
                    "open-collision-earlier-A3", next(
                        descriptor[0]
                        for descriptor in two_links
                        if descriptor[0].startswith("symlink-open:")
                        and descriptor[0].endswith(":2")
                    ), "collision-earlier-A3",
                    options={"raw_target": b"link", "target_row": None}, spec="two-link-collision",
                )
                for bracket in range(3):
                    for role in ("held", "parent"):
                        token = f"symlink-{role}-{'fstat' if role == 'held' else 'stat'}{bracket}:1"
                        for variant in ("mismatch", "error"):
                            stage3_a3_mutation(
                                f"identity-{role}-{bracket}-{variant}", token, variant,
                                options={"raw_target": b"./enum/../target"},
                            )
                for role, token in (
                    ("held", "symlink-held-fstat1:1"),
                    ("parent", "symlink-parent-stat1:1"),
                ):
                    stage3_a3_mutation(
                        f"identity-{role}-KeyboardInterrupt", token, "KeyboardInterrupt",
                        options={"raw_target": b"./enum/../target"}, expected=KeyboardInterrupt, route="arbitrary",
                    )
                for ordinal in (1, 2):
                    token = next(descriptor[0] for descriptor in primary if descriptor[0].startswith(f"readlink{ordinal}:"))
                    for variant in ("error", "KeyboardInterrupt"):
                        stage3_a3_mutation(
                            f"read{ordinal}-{variant}", token, variant,
                            options={"raw_target": b"./enum/../target"},
                            expected=KeyboardInterrupt if variant == "KeyboardInterrupt" else module.MutationError,
                            route="arbitrary" if variant == "KeyboardInterrupt" else "governed",
                        )
                    for variant in (
                        ("bytes-subclass", "str-subclass", "other-type")
                        if ordinal == 1
                        else ("bytes-subclass", "str-subclass", "other-type", "mismatch")
                    ):
                        spec = "relative-primary"
                        raw_target = b"./enum/../target"
                        if variant == "str-subclass":
                            spec = f"read{ordinal}-str-subclass"
                            raw_target = os.fsdecode(os.fsencode(external3) + b"/tool")
                            stage3_a3_specs[spec] = (primary_text + external_target, ())
                        stage3_a3_mutation(
                            f"read{ordinal}-{variant}", token, variant,
                            options={"raw_target": raw_target}, spec=spec,
                        )
                for variant in ("empty", "4097-bytes"):
                    stage3_a3_mutation(
                        f"read2-{variant}", next(descriptor[0] for descriptor in primary if descriptor[0].startswith("readlink2:")), variant,
                        options={"raw_target": b"./enum/../target"},
                    )
                for ordinal in (1, 2):
                    token = next(descriptor[0] for descriptor in primary_text if descriptor[0].startswith(f"target-fsencode{ordinal}:"))
                    for variant in ("error", "nonbytes"):
                        stage3_a3_specs[f"text-{ordinal}-{variant}"] = (primary_text + external_target, ())
                        stage3_a3_mutation(
                            f"fsencode{ordinal}-{variant}", token, variant,
                            options={"raw_target": os.fsdecode(os.fsencode(external3) + b"/tool")},
                            spec=f"text-{ordinal}-{variant}",
                        )
                for label, token in (
                    ("target-edge-drift", "target-parent-stat:1:repo-target"),
                    ("target-held-drift", "target-held-fstat:1:repo-target"),
                ):
                    stage3_a3_mutation(label, token, "mismatch", options={"raw_target": b"./enum/../target"})
                absence_targets = (
                    ("enoent", stage3_a3_absence_operations[0][0], stage3_a3_absence_operations[1][0], stage3_a3_absence_operations[2][0]),
                    ("enotdir", stage3_a3_absence_operations[3][0], stage3_a3_absence_operations[4][0], stage3_a3_absence_operations[5][0]),
                )
                for label, parent_token, held_token, terminal_token in absence_targets:
                    for role, token in (("parent", parent_token), ("held", held_token)):
                        stage3_a3_mutation(f"absence-{label}-{role}-mismatch", token, "mismatch", options={"raw_target": b"./enum/../target"}, route="absence-failure")
                    for variant in ("wrong-errno", "success"):
                        stage3_a3_mutation(f"absence-{label}-{variant}", terminal_token, variant, options={"raw_target": b"./enum/../target"}, route="absence-failure")
                stage3_a3_mutation(
                    "absence-first-row-stops-later", stage3_a3_absence_operations[0][0], "error",
                    options={"raw_target": b"./enum/../target", "forbid_later_filesystem": True},
                    route="absence-failure",
                )
                stage3_a3_mutation(
                    "absence-terminal-KeyboardInterrupt", stage3_a3_absence_operations[2][0], "KeyboardInterrupt",
                    options={"raw_target": b"./enum/../target"}, expected=KeyboardInterrupt, route="absence-arbitrary",
                )
                for label, options, expected, route in (
                    ("governed-runs-suffix", {"safe_failure": "FP"}, module.MutationError, "governed"),
                    ("arbitrary-direct-cleanup", {}, KeyboardInterrupt, "arbitrary"),
                    ("later-GB-does-not-replace", {"safe_failure": "GB"}, module.MutationError, "governed"),
                    ("close-overrides-governed", {"a3_close_failure": True}, module.MutationError, "governed"),
                    ("close-overrides-KeyboardInterrupt", {"a3_close_failure": True}, module.MutationError, "arbitrary"),
                ):
                    token = next(descriptor[0] for descriptor in primary if descriptor[0].startswith("readlink1:"))
                    variant = (
                        "KeyboardInterrupt"
                        if "KeyboardInterrupt" in label or label == "arbitrary-direct-cleanup"
                        else "error"
                    )
                    stage3_a3_mutation(label, token, variant, options={"raw_target": b"./enum/../target", **options}, expected=expected, route=route)
                if len(stage3_a3_mutations) != len({row[0] for row in stage3_a3_mutations}):
                    raise SystemExit("stage3a3 executable finite mutation table drifted")
                stage3_a2_cases = []

                def stage3_a2_case(token, variant, expected=module.MutationError, options=None):
                    case = ("stage3a2-fault", token, variant)
                    if options is not None:
                        case += (options,)
                    stage3_a2_cases.append((f"{token}-{variant}", expected, case))

                descriptor_by_token = {
                    descriptor[0]: descriptor for descriptor in stage3_a2_expected_operations
                }
                active_graph_count = sum(edge[0] != "cache" for edge in stage3_a1_expected_edges)
                base_open_variants = (
                    "return-True",
                    "return-IntSubclass",
                    "return-negative",
                    "collision-borrowed-L",
                    "collision-borrowed-P",
                    "collision-private-L",
                    "collision-private-P",
                    "EIO",
                    "ENFILE",
                    "EMFILE-rlimit-same",
                    "EMFILE-rlimit-drift",
                )
                active_count = active_graph_count
                open_site_counts = {}
                for descriptor in stage3_a2_expected_operations:
                    token = descriptor[0]
                    operation = token.split(":", 1)[0]
                    if operation.endswith("open"):
                        open_site_counts[token] = active_count
                        active_count += 1
                    elif operation.endswith("close"):
                        active_count -= 1
                for token, owner_count in open_site_counts.items():
                    for variant in base_open_variants:
                        stage3_a2_case(
                            token,
                            variant,
                            SystemExit if variant == "EMFILE-rlimit-same" else module.MutationError,
                        )
                    for index in range(owner_count):
                        stage3_a2_case(token, f"collision-owned-G{index}")
                stage3_a2_case("scan2-open:repo-abs", "reuse-closed-scan1", SystemExit)
                for suffix in ("FP", "FB"):
                    stage3_a2_case(
                        "regular-open:external-tool",
                        f"EIO-{suffix}",
                        module.MutationError,
                        {"safe_failure": suffix},
                    )
                stage3_a2_case(
                    "regular-fstat-post:external-tool",
                    "identity-drift-GB",
                    module.MutationError,
                    {"safe_failure": "GB"},
                )
                for token, variants in (
                    ("parent-stat:external-parent", ("error", "wrong-kind")),
                    (
                        "parent-fstat:external-parent",
                        ("error", "wrong-kind", "identity-drift", "private-alias"),
                    ),
                ):
                    for variant in variants:
                        stage3_a2_case(token, variant)
                for token, variants in (
                    (
                        "regular-fstat-pre:external-tool",
                        (
                            "error",
                            "wrong-kind",
                            "mode-mismatch",
                            "size-mismatch",
                            "nlink-zero",
                            "oversize-before-read",
                        ),
                    ),
                    (
                        "regular-pread:external-tool",
                        (
                            "error",
                            "nonbytes",
                            "empty",
                            "oversized-chunk",
                            "bytes-mismatch",
                            "premature-eof",
                        ),
                    ),
                    (
                        "regular-fstat-post:external-tool",
                        ("error", "identity-drift", "mode-mismatch", "size-mismatch"),
                    ),
                    (
                        "directory-fstat0:repo-abs",
                        ("error", "wrong-kind", "mode-mismatch"),
                    ),
                    (
                        "directory-fstat1:repo-abs",
                        ("error", "identity-drift", "mode-mismatch", "size-mismatch"),
                    ),
                    (
                        "directory-fstat2:repo-abs",
                        ("error", "identity-drift", "mode-mismatch", "size-mismatch"),
                    ),
                ):
                    for variant in variants:
                        stage3_a2_case(token, variant)
                for token in ("list1:repo-abs", "list2:repo-abs"):
                    for variant in (
                        "error",
                        "non-list",
                        "raw-empty",
                        "raw-dot",
                        "raw-dotdot",
                        "raw-nul",
                        "raw-slash",
                        "raw-256",
                        "entry-4097",
                    ):
                        stage3_a2_case(token, variant)
                for variant in ("bytes-entry", "str-subclass-entry"):
                    stage3_a2_case("list1:repo-abs", variant)
                for scan in (1, 2):
                    stage3_a2_case(f"list{scan}:repo-enum", "duplicate")
                stage3_a2_case("list2:repo-enum", "cross-scan-drift")
                stage3_a2_case("list1:repo-abs", "KeyboardInterrupt", KeyboardInterrupt)
                stage3_a2_case(
                    "list1:repo-abs",
                    "KeyboardInterrupt-outer-close",
                    module.MutationError,
                    {"close_failure": "parent"},
                )
                stage3_a2_case("fsencode1:repo-abs:626c6f636b6572", "error")
                stage3_a2_case("entry-stat1:repo-abs:626c6f636b6572", "error")
                stage3_a2_case("entry-stat1:repo-abs:626c6f636b6572", "special-type")
                for token in ("scan1-close:repo-abs", "scan2-close:repo-abs"):
                    stage3_a2_case(token, "real-close-then-raise")
                stage3_a2_case(
                    "scan1-close:repo-abs",
                    "real-close-then-KeyboardInterrupt",
                )
                stage3_a2_case(
                    "scan1-close:repo-abs",
                    "real-close-then-KeyboardInterrupt-outer-close",
                    module.MutationError,
                    {"close_failure": "parent", "parent_close_sentinel": True},
                )
                stage3_a2_case(
                    "regular-pread:external-tool",
                    "KeyboardInterrupt-post-fstat-error",
                    KeyboardInterrupt,
                    {"post_fstat_failure": "regular-fstat-post:external-tool"},
                )
                stage3_a2_case(
                    "regular-pread:external-tool",
                    "chunk-over-request-under-remaining",
                    module.MutationError,
                    {"regular_size": 1_048_577},
                )
                stage3_a2_case(
                    "regular-fstat-post:external-tool",
                    "wrong-digest-post-fstat-sentinel",
                    KeyboardInterrupt,
                    {
                        "post_fstat_failure": "regular-fstat-post:external-tool",
                        "post_fstat_interrupt": True,
                    },
                )
                stage3_a2_case(
                    "list1:repo-abs",
                    "KeyboardInterrupt-close-override",
                    module.MutationError,
                    {"scan_close_failure": "scan1-close:repo-abs"},
                )
                for _label, _expected, case in stage3_a2_cases:
                    token, variant = case[1:3]
                    target_index = next(
                        index
                        for index, descriptor in enumerate(stage3_a2_expected_operations)
                        if descriptor[0] == token
                    )
                    expected = list(stage3_a2_expected_operations[: target_index + 1])
                    outcome = "arbitrary" if variant.startswith("KeyboardInterrupt") else "governed"
                    if token.startswith("regular-pread:"):
                        expected.append(stage3_a2_expected_operations[target_index + 1])
                    elif token.startswith(("list", "fsencode", "entry-stat")):
                        scan = 1 if "1:" in token.split(":", 1)[0] else 2
                        label = token.split(":", 2)[1]
                        expected.extend(
                            (
                                descriptor_by_token[f"scan{scan}-close:{label}"],
                                descriptor_by_token[f"directory-fstat{scan}:{label}"],
                            )
                        )
                    elif token.startswith(("scan1-close:", "scan2-close:")):
                        scan = 1 if token.startswith("scan1") else 2
                        label = token.split(":", 1)[1]
                        expected.append(descriptor_by_token[f"directory-fstat{scan}:{label}"])
                    stage3_a2_case_expectations[case[:3]] = (tuple(expected), outcome)
                stage3_a2_case_expectations[
                    ("stage3a2-fault", "scan2-open:repo-abs", "reuse-closed-scan1")
                ] = (stage3_a2_expected_operations, "success")
                override_key = (
                    "stage3a2-fault",
                    "list1:repo-abs",
                    "KeyboardInterrupt-close-override",
                )
                override_close = descriptor_by_token["scan1-close:repo-abs"]
                override_index = next(
                    index
                    for index, descriptor in enumerate(stage3_a2_expected_operations)
                    if descriptor[0] == "list1:repo-abs"
                )
                stage3_a2_case_expectations[override_key] = (
                    stage3_a2_expected_operations[: override_index + 1] + (override_close,),
                    "governed",
                )
                for variant in ("KeyboardInterrupt", "KeyboardInterrupt-outer-close"):
                    stage3_a2_case_expectations[
                        ("stage3a2-fault", "list1:repo-abs", variant)
                    ] = (
                        stage3_a2_expected_operations[: override_index + 1]
                        + (override_close,),
                        "arbitrary",
                    )
                for mapping_token, variants in (
                    ("regular-fstat-post:nightly", ("ledger-nightly-class",)),
                    ("regular-fstat-post:stable", ("ledger-stable-class",)),
                    (
                        "directory-fstat2:repo-enum",
                        (
                            "ledger-directory-size",
                            "ledger-directory-digest",
                        ),
                    ),
                ):
                    mapping_index = next(
                        index
                        for index, descriptor in enumerate(stage3_a2_expected_operations)
                        if descriptor[0] == mapping_token
                    )
                    for variant in variants:
                        stage3_a2_case_expectations[
                            ("stage3a2-fault", mapping_token, variant)
                        ] = (stage3_a2_expected_operations[: mapping_index + 1], "governed")
                post_fstat_index = next(
                    index
                    for index, descriptor in enumerate(stage3_a2_expected_operations)
                    if descriptor[0] == "regular-fstat-post:external-tool"
                )
                stage3_a2_case_expectations[
                    (
                        "stage3a2-fault",
                        "regular-fstat-post:external-tool",
                        "wrong-digest-post-fstat-sentinel",
                    )
                ] = (stage3_a2_expected_operations[: post_fstat_index + 1], "arbitrary")
                directory_open_index = next(
                    index
                    for index, descriptor in enumerate(stage3_a2_expected_operations)
                    if descriptor[0] == "directory-open:repo-enum"
                )
                stage3_a2_case_expectations[
                    ("stage3a2-fault", "regular-fstat-pre:repo-enum", "ledger-directory-class")
                ] = (
                    stage3_a2_expected_operations[:directory_open_index]
                    + (
                        (
                            "regular-open:repo-enum",
                            "os",
                            "open",
                            (b"enum", regular_flags),
                            (("dir_fd", ("@held", os.fsencode(repo3))),),
                        ),
                        ("regular-fstat-pre:repo-enum", "os", "fstat", ("@current",), ()),
                    ),
                    "governed",
                )
                malformed_names = {
                    "raw-empty": "",
                    "raw-dot": ".",
                    "raw-dotdot": "..",
                    "raw-nul": "nul\x00name",
                    "raw-slash": "a/b",
                    "raw-256": "x" * 256,
                }
                for scan in (1, 2):
                    list_token = f"list{scan}:repo-abs"
                    list_index = next(
                        index
                        for index, descriptor in enumerate(stage3_a2_expected_operations)
                        if descriptor[0] == list_token
                    )
                    close = descriptor_by_token[f"scan{scan}-close:repo-abs"]
                    next_fstat = descriptor_by_token[f"directory-fstat{scan}:repo-abs"]
                    for variant, text_name in malformed_names.items():
                        conversion = (
                            f"fsencode{scan}:repo-abs:malformed-{variant}",
                            "os",
                            "fsencode",
                            (text_name,),
                            (),
                        )
                        stage3_a2_case_expectations[
                            ("stage3a2-fault", list_token, variant)
                        ] = (
                            stage3_a2_expected_operations[: list_index + 1]
                            + (conversion, close, next_fstat),
                            "governed",
                        )
                cross_key = ("stage3a2-fault", "list2:repo-enum", "cross-scan-drift")
                cross_end = next(
                    index
                    for index, descriptor in enumerate(stage3_a2_expected_operations)
                    if descriptor[0] == "directory-fstat2:repo-enum"
                )
                stage3_a2_case_expectations[cross_key] = (
                    stage3_a2_expected_operations[: cross_end + 1],
                    "governed",
                )
                for scan in (1, 2):
                    list_token = f"list{scan}:repo-enum"
                    list_index = next(
                        index
                        for index, descriptor in enumerate(stage3_a2_expected_operations)
                        if descriptor[0] == list_token
                    )
                    fsencode_a = next(
                        descriptor
                        for descriptor in stage3_a2_expected_operations
                        if descriptor[0].startswith(f"fsencode{scan}:repo-enum:61")
                    )
                    stat_a = next(
                        descriptor
                        for descriptor in stage3_a2_expected_operations
                        if descriptor[0].startswith(f"entry-stat{scan}:repo-enum:61")
                    )
                    stage3_a2_case_expectations[
                        ("stage3a2-fault", list_token, "duplicate")
                    ] = (
                        stage3_a2_expected_operations[: list_index + 1]
                        + (
                            fsencode_a,
                            stat_a,
                            fsencode_a,
                            descriptor_by_token[f"scan{scan}-close:repo-enum"],
                            descriptor_by_token[f"directory-fstat{scan}:repo-enum"],
                        ),
                        "governed",
                    )
                if (
                    len(stage3_a2_cases) != 367
                    or len(stage3_a2_cases)
                    != len({label for label, _expected, _case in stage3_a2_cases})
                    or not all(case[1] in descriptor_by_token for _label, _expected, case in stage3_a2_cases)
                    or not any(
                        case[1] == "regular-fstat-pre:external-tool"
                        and case[2] == "oversize-before-read"
                        for _label, _expected, case in stage3_a2_cases
                    )
                    or any("4MiB" in label for label, _expected, _case in stage3_a2_cases)
                    or sum(token.startswith("fsencode") for token in descriptor_by_token) != 8
                    or any("symlink" in label or "absence" in label for label, _expected, _case in stage3_a2_cases)
                ):
                    raise SystemExit("stage3a2 finite failure catalog drifted")
                stage3_a1_site_edges = {
                    edge[1]: sum(
                        earlier[0] != "cache"
                        for earlier in stage3_a1_expected_edges[:index]
                    )
                    for index, edge in enumerate(stage3_a1_expected_edges)
                    if edge[1] in stage3_a1_failure_sites
                }
                if tuple(stage3_a1_site_edges) != stage3_a1_failure_sites:
                    raise SystemExit("stage3a1 acquisition sites drifted")
                stage3_a1_failure_matrix = tuple(
                    (site, variant)
                    for site in stage3_a1_failure_sites
                    for variant in stage3_a1_base_failure_variants
                    + tuple(
                        f"collision-owned-G{index}"
                        for index in range(stage3_a1_site_edges[site])
                    )
                )
                if len(stage3_a1_failure_matrix) != len(set(stage3_a1_failure_matrix)):
                    raise SystemExit("stage3a1 acquisition failure matrix drifted")
                stage3_a1_cache_f_edges = [
                    edge
                    for edge in stage3_a1_expected_edges
                    if edge[0] == "cache" and edge[1] == "cache-F"
                ]
                if len(stage3_a1_cache_f_edges) != 2:
                    raise SystemExit("stage3a1 fixture root cache reuse drifted")
                held_prefixes = set(stage3_raw_prefixes(os.fsencode(repo3)))
                held_prefixes.add(b"/")
                held_prefixes.add(os.fsencode(vendor3))
                expected_cache_prefixes = []
                for anchor_path in (os.fsencode(stable3), os.fsencode(nightly3)):
                    for prefix in stage3_raw_prefixes(anchor_path):
                        if prefix in held_prefixes:
                            expected_cache_prefixes.append(prefix)
                        else:
                            held_prefixes.add(prefix)
                actual_cache_prefixes = [
                    edge[4] for edge in stage3_a1_expected_edges if edge[0] == "cache"
                ]
                if actual_cache_prefixes != expected_cache_prefixes:
                    raise SystemExit("stage3a1 shared-prefix cache order drifted")
                stage3_a1_g1_mutations = []
                for event_index, token in enumerate(stage3_a1_expected_g1[:-1]):
                    if token.startswith("edge-pre-stat:"):
                        prefix = token.split(":", 1)[1]
                        held_index = stage3_a1_expected_g1.index(f"held-fstat:{prefix}")
                        stage3_a1_g1_mutations.extend(
                            ((event_index, "error", event_index, None), (event_index, "mismatch", held_index, None))
                        )
                    elif token.startswith("held-fstat:"):
                        stage3_a1_g1_mutations.append((event_index, "error", event_index, None))
                        stage3_a1_g1_mutations.append(
                            (
                                event_index,
                                "root-mismatch" if token == "held-fstat:/" else "mismatch",
                                event_index,
                                None,
                            )
                        )
                        raw_prefix = token.split(":", 1)[1]
                        pre_index = (
                            None
                            if raw_prefix == "/"
                            else stage3_a1_expected_g1.index(f"edge-pre-stat:{raw_prefix}")
                        )
                        stage3_a1_g1_mutations.append(
                            (event_index, "private-alias", event_index, pre_index)
                        )
                    elif token.startswith("cache-held-fstat:") or token.startswith("cache-binding-stat:"):
                        stage3_a1_g1_mutations.extend(
                            ((event_index, "error", event_index, None), (event_index, "mismatch", event_index, None))
                        )
                stage3_a1_lineage_mutations = []
                for site, source in (
                    ("vendor", os.fsencode(repo3)),
                    ("stable", os.fsencode(vendor3)),
                    ("nightly", os.fsencode(stable3)),
                ):
                    edge = next(edge for edge in stage3_a1_expected_edges if edge[1] == site)
                    raw_prefix = edge[4].decode("ascii")
                    pre_index = stage3_a1_expected_g1.index(f"edge-pre-stat:{raw_prefix}")
                    held_index = stage3_a1_expected_g1.index(f"held-fstat:{raw_prefix}")
                    stage3_a1_lineage_mutations.append(
                        (pre_index, held_index, source, held_index + 1)
                    )
                stage3_a1_gb_mutations = tuple(
                    (index, variant)
                    for index in range(len(stage3_a1_expected_bindings))
                    for variant in ("error", "mismatch")
                )
                stage3_link_path = os.path.join(repo3, "link")
                stage3_link_b_path = os.path.join(repo3, "link-b")
                stage3_target_path = os.path.join(repo3, "target")
                os.unlink(stage3_link_path)
                no_symlink_objects = expected_objects - {(b"repo/link", "symlink", 0o777)}
                observed_no_symlink_objects = {
                    (os.fsencode(relative), stage3_kind(file_type), mode)
                    for relative, file_type, mode, _identity_value, _content in tree_state(stage3_root)
                }
                if len(observed_no_symlink_objects) != 18 or observed_no_symlink_objects != no_symlink_objects:
                    raise SystemExit("stage3 no-symlink fixture does not remove exactly repo/link")
                stage3_no_symlink_ledger = stage3_ledger(stage3_root_bytes, False)
                os.symlink(b"./enum/../target", stage3_link_path)
                stage3_ledger_bytes = stage3_ledger(stage3_root_bytes, True)
                if stage3_ledger_bytes.count(b"\n") != 12 or stage3_no_symlink_ledger.count(b"\n") != 11:
                    raise SystemExit("stage3 literal ledger row cardinality drifted")
                for index in range(41):
                    target = b"target" if index == 40 else f"chain{index + 1:02d}".encode("ascii")
                    os.symlink(target, os.path.join(repo3, f"chain{index:02d}"))
                os.symlink(b"target", os.path.join(repo3, "unreviewed-link"))
                os.link(os.path.join(repo3, "target"), os.path.join(repo3, "unreviewed-target"))
                os.link(os.path.join(repo3, "target"), os.path.join(repo3, "locator-alias"))
                os.link(os.path.join(vendor3, "v.bin"), os.path.join(repo3, "namespace-alias"))
                unreviewed_link_path = os.path.join(repo3, "unreviewed-link")

                def stage3_a3_ledger(raw_target, *, include_link=True, include_absence=True, chain_count=0, mutation=None):
                    if mutation == "held-root-canonical-absence":
                        if raw_target != b"/root-missing/leaf" or not include_link or not include_absence:
                            raise SystemExit("stage3a3 held root ledger options drifted")
                        rows = [
                            [
                                b"directory", b"probe", b"present", b"0700", b"46",
                                b"fdebc2828ff8f3c44dd0abe878bed6766de457d1fc601f1b6a5975420b8968f2",
                                b"external:/",
                            ],
                            [b"absent", b"probe", b"ENOENT", b"-", b"-", b"-", b"external:/root-missing/leaf"],
                            [
                                b"symlink", b"probe", b"present", b"0777", b"18",
                                b"7c3c2ce2b11615baf3bef6954dcb3e2644b91e9fee4c7339dcf6c6983c9a7d69",
                                b"repo:/link",
                            ],
                        ]
                        return b"".join(
                            b"\t".join((b"input-v1", str(index).encode("ascii"), *row)) + b"\n"
                            for index, row in enumerate(rows)
                        )
                    rows = [line.split(b"\t")[2:] for line in stage3_ledger_bytes.splitlines()]
                    rows = [row for row in rows if include_link or row[-1] != b"repo:/link"]
                    rows = [row for row in rows if include_absence or row[0] != b"absent"]
                    if include_link:
                        encoded = os.fsencode(raw_target)
                        for row in rows:
                            if row[-1] == b"repo:/link":
                                row[4] = str(len(encoded)).encode("ascii")
                                row[5] = hashlib.sha256(encoded).hexdigest().encode("ascii")
                                break
                    if mutation == "multi-component-canonical-absence":
                        for row in rows:
                            if row[-1] == b"repo:/abs/a-missing":
                                row[-1] = b"repo:/abs/a-missing/leaf"
                                break
                    if mutation == "multi-component-canonical-enotdir":
                        for row in rows:
                            if row[-1] == b"repo:/abs/blocker/child":
                                row[-1] = b"repo:/abs/blocker/child/leaf"
                                break
                    for index in range(chain_count):
                        target = (
                            b"target"
                            if index == chain_count - 1
                            else f"chain{index + 1:02d}".encode("ascii")
                        )
                        rows.append(
                            [
                                b"symlink", b"probe", b"present", b"0777",
                                str(len(target)).encode("ascii"),
                                hashlib.sha256(target).hexdigest().encode("ascii"),
                                f"repo:/chain{index:02d}".encode("ascii"),
                            ]
                        )
                    if mutation == "nested-trailing-slash-regular":
                        target = b"target"
                        rows.append(
                            [
                                b"symlink", b"probe", b"present", b"0777",
                                str(len(target)).encode("ascii"),
                                hashlib.sha256(target).hexdigest().encode("ascii"),
                                b"repo:/unreviewed-link",
                            ]
                        )
                    if mutation == "disjoint-symlink-roots":
                        target = b"target"
                        rows.append(
                            [
                                b"symlink", b"probe", b"present", b"0777",
                                str(len(target)).encode("ascii"),
                                hashlib.sha256(target).hexdigest().encode("ascii"),
                                b"repo:/link-b",
                            ]
                        )
                    if mutation == "symlink-size-mismatch":
                        next(row for row in rows if row[-1] == b"repo:/link")[4] = str(
                            len(os.fsencode(raw_target)) + 1
                        ).encode("ascii")
                    elif mutation == "symlink-digest-mismatch":
                        next(row for row in rows if row[-1] == b"repo:/link")[5] = b"0" * 64
                    rows.sort(key=lambda row: row[-1])
                    if mutation == "nested-trailing-slash-regular":
                        symlink_locators = [
                            row[-1] for row in rows if row[0] == b"symlink"
                        ]
                        if symlink_locators != [b"repo:/link", b"repo:/unreviewed-link"]:
                            raise SystemExit("stage3a3 nested symlink ledger order drifted")
                    if mutation == "disjoint-symlink-roots":
                        symlink_locators = [
                            row[-1] for row in rows if row[0] == b"symlink"
                        ]
                        if symlink_locators != [b"repo:/link", b"repo:/link-b"]:
                            raise SystemExit("stage3a3 disjoint symlink ledger order drifted")
                    return b"".join(
                        b"\t".join((b"input-v1", str(index).encode("ascii"), *row)) + b"\n"
                        for index, row in enumerate(rows)
                    )
                stage3_ledger_path = os.path.join(fixture, "stage3-ledger")
                stage3_file(stage3_ledger_path, stage3_ledger_bytes, 0o600)
                stage3_no_symlink_path = os.path.join(fixture, "stage3-ledger-no-symlink")
                stage3_file(stage3_no_symlink_path, stage3_no_symlink_ledger, 0o600)
                stage3_ledger_fd = os.open(
                    stage3_ledger_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                )
                stage3_parent_fd = os.open(
                    parent3, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
                )
                try:
                    stage3_ledger_offset = os.lseek(stage3_ledger_fd, 11, os.SEEK_SET)
                    stage3_parent_offset = os.lseek(stage3_parent_fd, 7, os.SEEK_CUR)
                    (
                        ledger_fd,
                        ledger_path,
                        ledger_offset,
                        parent_fd,
                        parent_offset,
                        repo_root,
                        stable_root,
                        nightly_root,
                        parent_root,
                        valid,
                        roots,
                        base_borrowed,
                        _synthetic_golden,
                    ) = (
                        stage3_ledger_fd,
                        stage3_ledger_path,
                        stage3_ledger_offset,
                        stage3_parent_fd,
                        stage3_parent_offset,
                        repo3,
                        stable3,
                        nightly3,
                        parent3,
                        {
                            "expected_ledger_fd": stage3_ledger_fd,
                            "repo_root": repo3,
                            "vendor_relative": "vendor",
                            "stable_sysroot_root": stable3,
                            "nightly_sysroot_root": nightly3,
                            "private_parent_fd": stage3_parent_fd,
                        },
                        (stage3_root,),
                        [
                            (stage3_ledger_fd, stage3_ledger_offset),
                            (stage3_parent_fd, stage3_parent_offset),
                        ],
                        synthetic_context[-1],
                    )
                    os.environ["TASK4_GOLDEN"] = stage3_ledger_bytes.decode("ascii")
                    stage3_ready = True

                    def run_stage3_a3(label, expected, options, ledger_kind, stage3_case):
                        raw_target = options.get("raw_target", b"./enum/../target")
                        include_link = ledger_kind not in {"no-symlink", "chain40", "chain41"}
                        include_absence = ledger_kind != "no-absence"
                        chain_count = 40 if ledger_kind == "chain40" else 41 if ledger_kind == "chain41" else 0
                        if chain_count:
                            options["raw_targets"] = {
                                occurrence: (
                                    b"target"
                                    if occurrence == chain_count
                                    else f"chain{occurrence:02d}".encode("ascii")
                                )
                                for occurrence in range(1, chain_count + 1)
                            }
                        if ledger_kind == "nested-trailing-slash-regular":
                            options["raw_targets"] = {1: raw_target, 2: b"target"}
                        disjoint_link_before = None
                        disjoint_target_before = None
                        if os.path.lexists(stage3_link_path):
                            os.unlink(stage3_link_path)
                        if include_link:
                            os.symlink(
                                b"target" if ledger_kind == "disjoint-symlink-roots" else raw_target,
                                stage3_link_path,
                            )
                        if ledger_kind == "disjoint-symlink-roots":
                            if os.path.lexists(stage3_link_b_path):
                                raise SystemExit("stage3a3 disjoint temporary link already exists")
                            os.symlink(b"target", stage3_link_b_path)
                            disjoint_link_before = (
                                identity(os.lstat(stage3_link_path)),
                                os.readlink(stage3_link_path),
                            )
                            with open(stage3_target_path, "rb") as stream:
                                target_bytes = stream.read()
                            disjoint_target_before = (
                                identity(os.stat(stage3_target_path)),
                                target_bytes,
                            )
                        chain39 = os.path.join(repo3, "chain39")
                        if ledger_kind != "nested-trailing-slash-regular":
                            os.unlink(chain39)
                            os.symlink(b"target" if chain_count == 40 else b"chain40", chain39)
                        ledger = stage3_a3_ledger(
                            raw_target,
                            include_link=include_link,
                            include_absence=include_absence,
                            chain_count=chain_count,
                            mutation=ledger_kind if ledger_kind in {
                                "symlink-size-mismatch", "symlink-digest-mismatch",
                                "nested-trailing-slash-regular", "disjoint-symlink-roots",
                                "multi-component-canonical-absence", "multi-component-canonical-enotdir",
                                "held-root-canonical-absence",
                            } else None,
                        )
                        case_path = os.path.join(fixture, f"stage3a3-ledger-{label}")
                        stage3_file(case_path, ledger, 0o600)
                        case_fd = os.open(case_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                        case_offset = os.lseek(case_fd, 11, os.SEEK_SET)
                        original_golden = os.environ["TASK4_GOLDEN"]
                        os.environ["TASK4_GOLDEN"] = ledger.decode("ascii")
                        unreviewed_link_before = (
                            identity(os.lstat(unreviewed_link_path)),
                            os.readlink(unreviewed_link_path),
                        )
                        try:
                            case_overrides = {"expected_ledger_fd": case_fd}
                            if ledger_kind == "held-root-canonical-absence":
                                case_overrides.update(
                                    {
                                        "repo_root": "/repo",
                                        "stable_sysroot_root": "/stable",
                                        "nightly_sysroot_root": "/nightly",
                                    }
                                )
                            run_case(
                                f"stage3a3-{label}",
                                expected,
                                overrides=case_overrides,
                                borrowed=[(case_fd, case_offset), (parent_fd, parent_offset)],
                                full_a2=True,
                                stage3_case=stage3_case,
                            )
                        finally:
                            os.environ["TASK4_GOLDEN"] = original_golden
                            os.close(case_fd)
                            if ledger_kind == "disjoint-symlink-roots":
                                if not os.path.lexists(stage3_link_b_path):
                                    raise SystemExit("stage3a3 disjoint temporary link was changed")
                                os.unlink(stage3_link_b_path)
                                with open(stage3_target_path, "rb") as stream:
                                    target_after = stream.read()
                                if (
                                    (
                                        identity(os.lstat(stage3_link_path)),
                                        os.readlink(stage3_link_path),
                                    )
                                    != disjoint_link_before
                                    or (
                                        identity(os.stat(stage3_target_path)),
                                        target_after,
                                    )
                                    != disjoint_target_before
                                ):
                                    raise SystemExit(
                                        "stage3a3 disjoint root cleanup changed original link or target"
                                    )
                            else:
                                if os.path.lexists(stage3_link_path):
                                    os.unlink(stage3_link_path)
                                os.symlink(b"./enum/../target", stage3_link_path)
                            if ledger_kind != "nested-trailing-slash-regular":
                                os.unlink(chain39)
                                os.symlink(b"chain40", chain39)
                            if ledger_kind == "nested-trailing-slash-regular" and (
                                identity(os.lstat(unreviewed_link_path)),
                                os.readlink(unreviewed_link_path),
                            ) != unreviewed_link_before:
                                raise SystemExit("stage3a3 nested reused symlink changed")

                    try:
                        first_label, _body, _absence, first_expected, first_case_options, first_ledger = stage3_a3_live_cases[0]
                        first_options = dict(first_case_options)
                        first_options["spec"] = first_label
                        run_stage3_a3(
                            first_label,
                            first_expected,
                            first_options,
                            first_ledger,
                            ("stage3a3-case", first_label, first_options),
                        )
                        for (
                            label,
                            expected,
                            overrides,
                            patches,
                            stored_borrowed,
                            standard_borrowed,
                            postcheck,
                            custody,
                            stage3_case,
                        ) in deferred_full_a2:
                            close_after = None
                            if label == "ledger-read-write":
                                close_after = os.open(
                                    stage3_ledger_path,
                                    os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                                )
                                read_write_offset = os.lseek(close_after, 23, os.SEEK_SET)
                                overrides = {"expected_ledger_fd": close_after}
                                case_borrowed = [
                                    (close_after, read_write_offset),
                                    (parent_fd, parent_offset),
                                ]
                            else:
                                case_borrowed = base_borrowed if standard_borrowed else stored_borrowed
                            try:
                                if stage3_case is None and expected is SystemExit:
                                    stage3_case = ("stage3a2-positive",)
                                run_case(
                                    label,
                                    expected,
                                    overrides,
                                    patches,
                                    case_borrowed,
                                    postcheck,
                                    custody,
                                    full_a2=True,
                                    stage3_case=stage3_case,
                                )
                            finally:
                                if close_after is not None:
                                    os.close(close_after)
                        for case in stage3_c0_cases:
                            case_ledger_fd = None
                            case_overrides = None
                            case_borrowed = base_borrowed
                            case_golden = None
                            if not case[5]:
                                case_ledger_fd = os.open(
                                    stage3_no_symlink_path,
                                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                )
                                case_offset = os.lseek(case_ledger_fd, 11, os.SEEK_SET)
                                case_overrides = {"expected_ledger_fd": case_ledger_fd}
                                case_borrowed = [
                                    (case_ledger_fd, case_offset),
                                    (parent_fd, parent_offset),
                                ]
                                case_golden = os.environ["TASK4_GOLDEN"]
                                os.environ["TASK4_GOLDEN"] = stage3_no_symlink_ledger.decode("ascii")
                            try:
                                run_case(
                                    f"stage3a0-{case[0]}",
                                    case[4],
                                    case_overrides,
                                    borrowed=case_borrowed,
                                    full_a2=True,
                                    stage3_case=case,
                                )
                            finally:
                                if case_golden is not None:
                                    os.environ["TASK4_GOLDEN"] = case_golden
                                if case_ledger_fd is not None:
                                    os.close(case_ledger_fd)
                        for site, variant in stage3_a1_failure_matrix:
                            expected = (
                                SystemExit
                                if variant == "EMFILE-rlimit-same"
                                else KeyboardInterrupt
                                if variant == "KeyboardInterrupt"
                                else module.MutationError
                            )
                            run_case(
                                f"stage3a1-{site}-{variant}",
                                expected,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=("stage3a1-failure", site, variant),
                            )
                        for event_index, variant, stop_index, companion_index in stage3_a1_g1_mutations:
                            run_case(
                                f"stage3a1-g1-{event_index}-{variant}",
                                module.MutationError,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=(
                                    "stage3a1-g1-mutation",
                                    event_index,
                                    variant,
                                    stop_index,
                                    companion_index,
                                ),
                            )
                        for pre_index, held_index, source, stop_index in stage3_a1_lineage_mutations:
                            run_case(
                                f"stage3a1-lineage-{pre_index}-{held_index}",
                                module.MutationError,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=(
                                    "stage3a1-lineage-mutation",
                                    pre_index,
                                    held_index,
                                    source,
                                    stop_index,
                                ),
                            )
                        for binding_index, variant in stage3_a1_gb_mutations:
                            run_case(
                                f"stage3a1-gb-{binding_index}-{variant}",
                                module.MutationError,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=("stage3a1-gb-mutation", binding_index, variant),
                            )
                        for label, site, variant, options, expected in (
                            ("emfile-fp-failure", "vendor", "EMFILE-rlimit-same", {"safe_failure": "FP"}, module.MutationError),
                            ("emfile-fb-failure", "vendor", "EMFILE-rlimit-same", {"safe_failure": "FB"}, module.MutationError),
                            ("emfile-gb-failure", "vendor", "EMFILE-rlimit-same", {"safe_failure": "GB"}, module.MutationError),
                            ("keyboardinterrupt-close-failure", "vendor", "KeyboardInterrupt", {"close_failure": "parent"}, module.MutationError),
                            ("mutation-close-failure", "vendor", "ENFILE", {"close_failure": "parent"}, module.MutationError),
                            ("refusal-close-failure", "vendor", "EMFILE-rlimit-same", {"close_failure": "parent"}, module.MutationError),
                        ):
                            run_case(
                                f"stage3a1-{label}",
                                expected,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=("stage3a1-failure", site, variant, options),
                            )
                        for label, option in (
                            ("fp-early-L-getfl-error", {"fp_error": "private-L-getfl"}),
                            ("fp-early-L-getfl-mismatch", {"fp_mismatch": "private-L-getfl"}),
                            ("fp-early-L-getfd-error", {"fp_error": "private-L-getfd"}),
                            ("fp-early-L-getfd-mismatch", {"fp_mismatch": "private-L-getfd"}),
                            ("fp-early-L-fstat-error", {"fp_error": "private-L-fstat-pre"}),
                            ("fp-early-L-fstat-mismatch", {"fp_mismatch": "private-L-fstat-pre"}),
                            ("fp-pread-error", {"fp_error": "private-L-pread"}),
                        ):
                            run_case(
                                f"stage3a1-{label}",
                                module.MutationError,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=(
                                    "stage3a1-failure",
                                    "vendor",
                                    "ENFILE",
                                    option,
                                ),
                            )
                        for label, semantic, expected in (
                            ("private-P-getfl-benign-bit", "benign-bit", SystemExit),
                            ("private-P-getfl-True", "True", module.MutationError),
                            ("private-P-getfl-IntSubclass", "IntSubclass", module.MutationError),
                            ("private-P-getfl-opath", "opath", module.MutationError),
                            ("private-P-getfl-non-readonly", "non-readonly", module.MutationError),
                        ):
                            run_case(
                                f"stage3a1-{label}",
                                expected,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=(
                                    "stage3a1-failure",
                                    "vendor",
                                    "EMFILE-rlimit-same",
                                    {"private_p_getfl": semantic},
                                ),
                            )
                        no_symlink_fd = os.open(
                            stage3_no_symlink_path,
                            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        )
                        no_symlink_offset = os.lseek(no_symlink_fd, 11, os.SEEK_SET)
                        symlink_golden = os.environ["TASK4_GOLDEN"]
                        os.environ["TASK4_GOLDEN"] = stage3_no_symlink_ledger.decode("ascii")
                        try:
                            run_case(
                                "stage3a1-private-P-getfl-opath-no-symlink",
                                module.MutationError,
                                overrides={"expected_ledger_fd": no_symlink_fd},
                                borrowed=[
                                    (no_symlink_fd, no_symlink_offset),
                                    (parent_fd, parent_offset),
                                ],
                                full_a2=True,
                                stage3_case=(
                                    "stage3a1-failure",
                                    "vendor",
                                    "EMFILE-rlimit-same",
                                    {"private_p_getfl": "opath", "no_symlink": True},
                                ),
                            )
                        finally:
                            os.environ["TASK4_GOLDEN"] = symlink_golden
                            os.close(no_symlink_fd)
                        for family, tokens in (
                            (
                                "fp",
                                (
                                    "private-L-getfl",
                                    "private-L-getfd",
                                    "private-L-fstat-pre",
                                    "private-L-pread",
                                    "private-L-fstat-post",
                                    "private-P-getfl",
                                    "private-P-getfd",
                                    "private-P-fstat",
                                ),
                            ),
                            ("fb", stage3_a1_final_borrowed),
                            (
                                "gb",
                                (
                                    stage3_a1_expected_bindings[0],
                                    next(
                                        token
                                        for token in stage3_a1_expected_bindings
                                        if token.startswith("bind-parent-name-stat:")
                                    ),
                                ),
                            ),
                        ):
                            for token in tokens:
                                run_case(
                                    f"stage3a1-{family}-ki-{token}",
                                    module.MutationError,
                                    borrowed=base_borrowed,
                                    full_a2=True,
                                    stage3_case=(
                                        "stage3a1-failure",
                                        "vendor",
                                        "EMFILE-rlimit-same"
                                        if family == "gb" and token == stage3_a1_expected_bindings[0]
                                        else "ENFILE",
                                        {"ki_token": token},
                                    ),
                                )
                        run_case(
                            "stage3a2-success-close-failure",
                            module.MutationError,
                            borrowed=base_borrowed,
                            full_a2=True,
                            stage3_case=("stage3a2-positive", {"close_failure": "parent"}),
                        )
                        run_case(
                            "stage3a2-positive",
                            SystemExit,
                            borrowed=base_borrowed,
                            full_a2=True,
                            stage3_case=("stage3a2-positive",),
                        )
                        for label, binding_token in (
                            ("held", "bind-held-fstat:@a2:vendor"),
                            ("parent-name", "bind-parent-name-stat:@a2:vendor"),
                        ):
                            run_case(
                                f"stage3a2-full-binding-vendor-{label}",
                                module.MutationError,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=(
                                    "stage3a2-positive",
                                    {"full_binding": binding_token},
                                ),
                            )
                        stage3_a2_ledger_mutations = (
                            (
                                "nightly-class-mapping",
                                b"\tnightly-sysroot\tread\tpresent\t",
                                b"\tstable-sysroot\tread\tpresent\t",
                                "regular-fstat-post:nightly",
                                "ledger-nightly-class",
                            ),
                            (
                                "stable-class-mapping",
                                b"\tstable-sysroot\tread\tpresent\t",
                                b"\tnightly-sysroot\tread\tpresent\t",
                                "regular-fstat-post:stable",
                                "ledger-stable-class",
                            ),
                            (
                                "directory-class-mapping",
                                b"\tdirectory\tenumerate\tpresent\t0700\t21\t",
                                b"\trepo\tprobe\tpresent\t0700\t21\t",
                                "regular-fstat-pre:repo-enum",
                                "ledger-directory-class",
                            ),
                            (
                                "directory-size",
                                b"\tdirectory\tenumerate\tpresent\t0700\t21\t2c337acb2a4a9f0836a1b0401109e0464648087c760683e6956dfa0949153305\t",
                                b"\tdirectory\tenumerate\tpresent\t0700\t20\t2c337acb2a4a9f0836a1b0401109e0464648087c760683e6956dfa0949153305\t",
                                "directory-fstat2:repo-enum",
                                "ledger-directory-size",
                            ),
                            (
                                "directory-digest",
                                b"\tdirectory\tenumerate\tpresent\t0700\t21\t2c337acb2a4a9f0836a1b0401109e0464648087c760683e6956dfa0949153305\t",
                                b"\tdirectory\tenumerate\tpresent\t0700\t21\t3c337acb2a4a9f0836a1b0401109e0464648087c760683e6956dfa0949153305\t",
                                "directory-fstat2:repo-enum",
                                "ledger-directory-digest",
                            ),
                            (
                                "fifo-preimage",
                                b"\tdirectory\tprobe\tpresent\t0700\t10\tdff711efda3385276e20031e3c33c758adb07840d3181fb20b23d4d00af6543f\t",
                                b"\tdirectory\tprobe\tpresent\t0700\t10\t5a8ad9210b466a4b08234e4483e307cbc1590bdb7ad5452b1042d1b7003f0aba\t",
                                "entry-stat1:repo-abs:626c6f636b6572",
                                "special-type",
                            ),
                            (
                                "per-chunk-cap",
                                b"\ttool\texecute\tpresent\t0700\t13\t022036a28655c76d3ac5e1584872c898d161687b7578de171ac3447b7447bf68\t",
                                b"\ttool\texecute\tpresent\t0700\t1048577\t154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a\t",
                                "regular-pread:external-tool",
                                "chunk-over-request-under-remaining",
                                {"regular_size": 1_048_577},
                            ),
                            (
                                "wrong-digest-post-fstat",
                                b"\ttool\texecute\tpresent\t0700\t13\t022036a28655c76d3ac5e1584872c898d161687b7578de171ac3447b7447bf68\t",
                                b"\ttool\texecute\tpresent\t0700\t13\t122036a28655c76d3ac5e1584872c898d161687b7578de171ac3447b7447bf68\t",
                                "regular-fstat-post:external-tool",
                                "wrong-digest-post-fstat-sentinel",
                                {
                                    "post_fstat_failure": "regular-fstat-post:external-tool",
                                    "post_fstat_interrupt": True,
                                },
                            ),
                        )
                        if len(stage3_a2_ledger_mutations) != 8:
                            raise SystemExit("stage3a2 operational ledger mutation count drifted")
                        for mutation in stage3_a2_ledger_mutations:
                            label, old, new, token, variant, *case_options = mutation
                            if stage3_ledger_bytes.count(old) != 1:
                                raise SystemExit("stage3a2 ledger mutation anchor drifted")
                            mutated = stage3_ledger_bytes.replace(old, new, 1)
                            mutation_path = os.path.join(fixture, f"stage3-ledger-{label}")
                            stage3_file(mutation_path, mutated, 0o600)
                            mutation_fd = os.open(
                                mutation_path,
                                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            )
                            mutation_offset = os.lseek(mutation_fd, 11, os.SEEK_SET)
                            original_golden = os.environ["TASK4_GOLDEN"]
                            os.environ["TASK4_GOLDEN"] = mutated.decode("ascii")
                            try:
                                stage3_case = ("stage3a2-fault", token, variant)
                                if case_options:
                                    stage3_case += (case_options[0],)
                                run_case(
                                    f"stage3a2-ledger-{label}",
                                    KeyboardInterrupt
                                    if variant == "wrong-digest-post-fstat-sentinel"
                                    else module.MutationError,
                                    overrides={"expected_ledger_fd": mutation_fd},
                                    borrowed=[
                                        (mutation_fd, mutation_offset),
                                        (parent_fd, parent_offset),
                                    ],
                                    full_a2=True,
                                    stage3_case=stage3_case,
                                )
                            finally:
                                os.environ["TASK4_GOLDEN"] = original_golden
                                os.close(mutation_fd)
                        for label, expected, case in stage3_a2_cases:
                            if case[2] in {
                                "special-type",
                                "chunk-over-request-under-remaining",
                                "wrong-digest-post-fstat-sentinel",
                            }:
                                continue
                            run_case(
                                f"stage3a2-{label}",
                                expected,
                                borrowed=base_borrowed,
                                full_a2=True,
                                stage3_case=case,
                            )
                        for label, _body, _absence, expected, case_options, ledger_kind in stage3_a3_live_cases[1:]:
                            options = dict(case_options)
                            options["spec"] = label
                            run_stage3_a3(
                                label,
                                expected,
                                options,
                                ledger_kind,
                                ("stage3a3-case", label, options),
                            )
                        for label, token, variant, options, expected, _route, ledger_kind in stage3_a3_mutations:
                            run_stage3_a3(
                                label,
                                expected,
                                options,
                                ledger_kind,
                                ("stage3a3-mutation", token, variant, options),
                            )
                    finally:
                        stage3_ready = False
                        (
                            ledger_fd,
                            ledger_path,
                            ledger_offset,
                            parent_fd,
                            parent_offset,
                            repo_root,
                            stable_root,
                            nightly_root,
                            parent_root,
                            valid,
                            roots,
                            base_borrowed,
                            synthetic_golden,
                        ) = synthetic_context
                        os.environ["TASK4_GOLDEN"] = synthetic_golden
                finally:
                    os.close(stage3_parent_fd)
                    os.close(stage3_ledger_fd)
            os.close(ledger_fd)
            os.close(parent_fd)

        print("input-v1-api-ok")
    finally:
        os.environ.clear()
        os.environ.update(previous_environment)
        sys.dont_write_bytecode = previous_bytecode
        if previous_module is _ABSENT:
            sys.modules.pop(_MODULE_NAME, None)
        else:
            sys.modules[_MODULE_NAME] = previous_module


class InputV1ContractTests(unittest.TestCase):
    def test_complete_candidate_only_contract(self):
        supplied_golden = os.environ.get("TASK4_GOLDEN")
        golden = (
            GOLDEN_PATH.read_bytes()
            if supplied_golden is None
            else supplied_golden.encode("ascii")
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            run_input_v1_contract(SCRIPT_PATH, golden)
        self.assertEqual(stdout.getvalue(), "input-v1-api-ok\n")
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
