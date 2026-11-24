#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Run a runner's self-test suite strictly.

    strict-selftest.py ROOT RUNNER MODE SUITE [TEST_NAME...]

Passes only when every selected test ran and passed: a skip, an expected
failure, an unexpected success or an empty selection fails. While the suite
runs, an audit hook records every repository file this process opens or
launches; a file the runner mode does not declare in runner_inputs.py fails
the self-test too, so its preflight cannot omit an input the suite reads.
The selection is fixed by the runner (argv), never by the environment.
Exit: 0 pass; 1 fail; 2 usage. Stdlib only.
"""
import importlib.util
import os
import runpy
import sys
import unittest

RECEIPT = "strict self-test passed"


def repo_reads(root):
    """Start recording repository files opened (read) or launched in-process."""
    root = os.path.realpath(root)
    seen = set()

    def note(path):
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if not isinstance(path, str) or not path:
            return
        real = os.path.realpath(path)
        # Bytecode caches are the interpreter's own output, never an input.
        if real.startswith(root + os.sep) and os.path.isfile(real) and "__pycache__" not in real.split(os.sep):
            seen.add(os.path.relpath(real, root))

    def hook(event, args):
        if event == "open":
            path, mode, flags = args
            writing = (mode and any(c in mode for c in "wax+")) or (flags or 0) & (os.O_WRONLY | os.O_RDWR)
            if not writing:
                note(path)
        elif event in ("subprocess.Popen", "os.exec", "os.posix_spawn"):
            argv = args[1] if len(args) > 1 else ()
            for word in [args[0]] + list(argv or ()):
                note(word)

    sys.addaudithook(hook)
    return seen


def main(argv):
    if len(argv) < 4:
        print("usage: strict-selftest.py ROOT RUNNER MODE SUITE [TEST_NAME...]", file=sys.stderr)
        return 2
    root, runner, mode, suite, names = argv[0], argv[1], argv[2], argv[3], argv[4:]
    declared = runpy.run_path(os.path.join(root, "scripts/runner_inputs.py"))
    allowed = set(declared["required"](runner, mode)) | {declared["SELF"], runner}
    seen = repo_reads(root)
    spec = importlib.util.spec_from_file_location("strict_selftest_suite", suite)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    loader = unittest.TestLoader()
    tests = (loader.loadTestsFromNames(names, module) if names else loader.loadTestsFromModule(module))
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stderr).run(tests)
    problems = []
    if result.testsRun == 0:
        problems.append("no test ran")
    if not result.wasSuccessful():
        problems.append("%d failed, %d errors" % (len(result.failures), len(result.errors)))
    for what, rows in (("skipped", result.skipped), ("expected failures", result.expectedFailures),
                       ("unexpected successes", result.unexpectedSuccesses)):
        if rows:
            problems.append("%d %s (a skip is never a pass)" % (len(rows), what))
    undeclared = sorted(seen - allowed)
    if undeclared:
        problems.append("read undeclared input(s) of %s %s: %s" % (runner, mode, ", ".join(undeclared)))
    if problems:
        print("strict self-test failed: " + "; ".join(problems), file=sys.stderr)
        return 1
    print("%s: %d tests, 0 skipped, %d repository inputs read, all declared" % (RECEIPT, result.testsRun, len(seen)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
