#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Execute one tests/python suite under unittest with typed terminal records.

This is an execution wrapper, not a log scraper. It monkey-patches the
stdlib unittest runner before running the suite as ``__main__``. The outer
runner's suite object is the executable selection proof; terminal outcomes
are recorded by unittest's own result callbacks. Nested unittest runners
(commonly used by mutation-test assertions inside a test) are deliberately
not part of the outer selection.

Usage:
  typed-python-suite.py SUITE FRAGMENT.json [suite-arg ...]
  typed-python-suite.py --list SUITE [suite-arg ...]

The fragment schema is p11scope/python-suite-fragment/v1. ``--list`` prints
the exact unittest ids the outer runner would select, without executing
them; check-known-failing.py uses that executable discovery path rather
than parsing Python source.
"""

import json
import runpy
import sys
import traceback
import unittest
from pathlib import Path

FRAGMENT_SCHEMA = "p11scope/python-suite-fragment/v1"
FAILURE_STATES = {"failed", "error", "unexpected_success", "skipped", "not_run"}


def raw_test_id(test):
    try:
        ident = test.id()
    except Exception:
        ident = test.__class__.__name__
    return ident if isinstance(ident, str) and ident else test.__class__.__name__


def test_identity(test):
    method = getattr(test, "_testMethodName", None)
    if isinstance(method, str) and method:
        return f"{test.__class__.__name__}.{method}"
    parts = raw_test_id(test).split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return parts[0]


def suite_event_name(test):
    return raw_test_id(test).split(".")[-1].split(" ", 1)[0]


def json_copy_typed_signature(value):
    if not isinstance(value, dict) or not value:
        return None
    try:
        copied = json.loads(json.dumps(value))
    except (TypeError, ValueError):
        return None
    return copied if isinstance(copied, dict) and copied else None


def outcome_signature(state, err):
    exception_value = err[1] if err and len(err) > 1 else None
    custom = json_copy_typed_signature(getattr(exception_value, "p11scope_signature", None))
    if custom is not None:
        return custom
    signature = {"branch": state, "oracle": "unittest"}
    if err and err[0]:
        signature["exception"] = err[0].__name__
    return signature


def flatten_suite(test):
    if isinstance(test, unittest.TestSuite):
        for child in test:
            yield from flatten_suite(child)
    else:
        yield test


class Recorder:
    def __init__(self):
        self.selection = []
        self.events = []
        self.suite_events = []
        self.depth = 0
        self.discover_only = False

    def note_selection(self, suite):
        if self.depth != 0:
            return
        for test in flatten_suite(suite):
            self.selection.append(test_identity(test))

    def note(self, test, state, err=None):
        if self.depth != 1:
            return
        signature = None if state == "passed" else outcome_signature(state, err)
        if not isinstance(test, unittest.TestCase):
            self.suite_events.append({"event": suite_event_name(test), "state": state, "signature": signature})
            return
        self.events.append({"test": test_identity(test), "state": state, "signature": signature})

    def outcomes(self):
        priority = {
            "passed": 0,
            "skipped": 1,
            "unexpected_success": 2,
            "failed": 3,
            "error": 4,
        }
        result = {}
        for event in self.events:
            old = result.get(event["test"])
            if old is None or priority[event["state"]] >= priority[old["state"]]:
                result[event["test"]] = event
        return result


RECORDER = Recorder()
ORIGINAL_RESULT = unittest.TextTestResult
ORIGINAL_RUNNER = unittest.TextTestRunner
ORIGINAL_TEST_PROGRAM = unittest.TestProgram


class RecordingTextTestResult(ORIGINAL_RESULT):
    def addSuccess(self, test):
        RECORDER.note(test, "passed")
        super().addSuccess(test)

    def addFailure(self, test, err):
        RECORDER.note(test, "failed", err)
        super().addFailure(test, err)

    def addError(self, test, err):
        RECORDER.note(test, "error", err)
        super().addError(test, err)

    def addSkip(self, test, reason):
        RECORDER.note(test, "skipped")
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        # unittest's expected-failure mechanism is the test's own contract;
        # externally it is a passing terminal outcome and needs no ledger row.
        RECORDER.note(test, "passed")
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        RECORDER.note(test, "unexpected_success")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            RECORDER.note(test, "failed", err)
        super().addSubTest(test, subtest, err)


class RecordingTestProgram(ORIGINAL_TEST_PROGRAM):
    def __init__(self, *args, **kwargs):
        if kwargs.get("testRunner") is None:
            kwargs["testRunner"] = RecordingTextTestRunner
        super().__init__(*args, **kwargs)


class RecordingTextTestRunner(ORIGINAL_RUNNER):
    def __init__(self, *args, **kwargs):
        kwargs["resultclass"] = RecordingTextTestResult
        super().__init__(*args, **kwargs)

    def run(self, test):
        outer = RECORDER.depth == 0
        if outer:
            RECORDER.note_selection(test)
        RECORDER.depth += 1
        try:
            if RECORDER.discover_only:
                result = self._makeResult()
                result.testsRun = 0
                return result
            return super().run(test)
        finally:
            RECORDER.depth -= 1


def install_recorder(discover_only):
    RECORDER.discover_only = discover_only
    unittest.TextTestResult = RecordingTextTestResult
    unittest.TextTestRunner = RecordingTextTestRunner
    # unittest.main is the TestProgram class; a None testRunner argument
    # would otherwise select the unpatched text runner.
    unittest.TestProgram = RecordingTestProgram
    unittest.main = RecordingTestProgram


def execute_suite(suite, arguments, discover_only):
    install_recorder(discover_only)
    suite = suite.resolve()
    old_argv = sys.argv[:]
    old_path = sys.path[:]
    sys.argv = [str(suite), *arguments]
    # python3 -I tests/python/x.py puts the suite directory first. Preserve
    # that execution shape instead of leaking this wrapper's scripts/ path.
    sys.path = [str(suite.parent), *[entry for entry in sys.path if entry != str(Path(__file__).parent)]]
    code = 0
    error = None
    try:
        runpy.run_path(str(suite), run_name="__main__")
    except SystemExit as exc:
        if exc.code is None:
            code = 0
        elif isinstance(exc.code, int):
            code = exc.code
        else:
            print(exc.code, file=sys.stderr)
            code = 1
    except BaseException as exc:  # the suite itself would print this traceback
        code = 1
        error = exc
        traceback.print_exception(type(exc), exc, exc.__traceback__)
    finally:
        sys.argv = old_argv
        sys.path = old_path
    return code, error


def fragment(path, invocation, process_exit):
    outcomes = RECORDER.outcomes()
    rows = []
    complete = True
    for test in RECORDER.selection:
        event = outcomes.get(test)
        if event is None:
            complete = False
            event = {
                "test": test,
                "state": "not_run",
                "signature": {"branch": "not_run", "oracle": "unittest"},
            }
        rows.append(event)
    if not RECORDER.selection:
        complete = False
    return {
        "schema": FRAGMENT_SCHEMA,
        "path": path,
        "invocation": invocation,
        "process_exit": process_exit,
        "complete": complete,
        "selection": [{"test": test} for test in RECORDER.selection],
        "results": rows,
        "suite_events": RECORDER.suite_events,
    }


def write_fragment(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv):
    if len(argv) >= 2 and argv[0] == "--list":
        suite = Path(argv[1])
        arguments = argv[2:]
        code, _error = execute_suite(suite, arguments, discover_only=True)
        payload = {
            "path": str(suite),
            "invocation": arguments,
            "tests": RECORDER.selection,
            "process_exit": code,
        }
        print(json.dumps(payload, sort_keys=True))
        # unittest 3.13+ uses exit 5 for "no tests run" in the dummy
        # discovery result; the outer selection itself is the discovery proof.
        return 0 if RECORDER.selection else 1
    if len(argv) < 2:
        print("usage: typed-python-suite.py SUITE FRAGMENT.json [suite-arg ...]", file=sys.stderr)
        return 2
    suite = Path(argv[0])
    output = Path(argv[1])
    arguments = argv[2:]
    code, _error = execute_suite(suite, arguments, discover_only=False)
    recorded_arguments = arguments[:-1] if arguments and arguments[-1] == "-v" else arguments
    write_fragment(output, fragment(str(suite), recorded_arguments, code))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
