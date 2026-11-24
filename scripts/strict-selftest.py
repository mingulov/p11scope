#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Run a runner's self-test suite strictly, in a copy of its declared inputs.

    strict-selftest.py ROOT RUNNER MODE SUITE [TEST_NAME...]

The suite never runs in the checkout. Every input runner_inputs.py declares
for RUNNER MODE (with the declaration and the runner) is copied, modes kept,
into a fresh directory, committed there as a one-commit git checkout, and
the suite runs from there with that directory as its working directory. A file the declaration omits is simply absent, so
any read of it fails, whether this process makes it or a child does; by
`open`, an import (no bytecode cache is copied), a read-write mode, a
`dir_fd`, a shell string or an environment-passed path. The declaration is
complete exactly when the suite passes in the copy.

The copy must not be bypassed through the checkout's own path. Checkout
directories leave sys.path, the variables naming the checkout leave the
environment, and an audit hook fails the run on any event (open, listdir,
exec, spawn, chdir and so on) whose arguments name the checkout. A child
that rebuilds that path by itself is outside what the hook can see. Nothing
the suite runs knows the path except through those routes.

The result is strict: a skip, an expected failure, an unexpected success,
an empty selection, a failure or an error fails. The selection is fixed by
argv, never by the environment. Exit: 0 pass; 1 fail; 2 usage. Stdlib only.

Strict runners: qualify-release-matrix.sh --self-test (the contract suite)
and qualify-inventory-native.sh --self-test (its fixture classes). Other
self-tests stay exit-code based.
"""
import importlib.util
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest

RECEIPT = "strict self-test passed"


def names_checkout(value, checkout):
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    if isinstance(value, str):
        return value == checkout or (checkout + os.sep) in value or value.startswith(checkout + os.sep)
    if isinstance(value, os.PathLike):
        return names_checkout(os.fspath(value), checkout)
    if isinstance(value, dict):
        return any(names_checkout(k, checkout) or names_checkout(v, checkout) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(names_checkout(item, checkout) for item in value)
    return False


def guard(checkout):
    """Fail the run on any audited event that names the checkout."""
    hits = []

    def hook(event, args):
        if names_checkout(args, checkout):
            hits.append(event)

    sys.addaudithook(hook)
    return hits


def main(argv):
    if len(argv) < 4:
        print("usage: strict-selftest.py ROOT RUNNER MODE SUITE [TEST_NAME...]", file=sys.stderr)
        return 2
    root, runner, mode, suite, names = argv[0], argv[1], argv[2], argv[3], argv[4:]
    checkout = os.path.realpath(root)
    declared = runpy.run_path(os.path.join(checkout, "scripts/runner_inputs.py"))
    inputs = sorted(set(declared["required"](runner, mode)) | {declared["SELF"], runner})
    suite_name = os.path.relpath(os.path.realpath(suite), checkout)
    if suite_name not in inputs:
        print("strict self-test failed: the suite %s is not a declared input of %s %s"
              % (suite_name, runner, mode), file=sys.stderr)
        return 1
    base = os.path.realpath(tempfile.mkdtemp(prefix="strict-selftest-"))
    try:
        if names_checkout(base, checkout):
            print("strict self-test failed: the copy %s lies inside the checkout" % base, file=sys.stderr)
            return 1
        copy = os.path.join(base, "source")
        for name in inputs:
            source, target = os.path.join(checkout, name), os.path.join(copy, name)
            if not os.path.isfile(source):
                print("strict self-test failed: declared input missing: %s" % source, file=sys.stderr)
                return 1
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(source, target)
        refused = commit_copy(copy)
        if refused:
            print("strict self-test failed: " + refused, file=sys.stderr)
            return 1
        return run_in_copy(checkout, copy, suite_name, names, len(inputs))
    finally:
        shutil.rmtree(base, ignore_errors=True)


def commit_copy(copy):
    """Make the copy a one-commit checkout of exactly the declared inputs
    (the suite drives --rev and the clean-tree build checks)."""
    git = shutil.which("git")
    if git is None:
        return "git is required: the suite drives the runner's --rev checks"
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_NAME="strict-selftest", GIT_AUTHOR_EMAIL="strict-selftest@invalid",
               GIT_COMMITTER_NAME="strict-selftest", GIT_COMMITTER_EMAIL="strict-selftest@invalid")
    for argv in (["init", "-q"], ["add", "-A"], ["commit", "-q", "--no-gpg-sign", "-m", "declared inputs"]):
        result = subprocess.run([git, "-C", copy] + argv, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            return "git %s failed in the copy: %s" % (argv[0], result.stderr.strip())
    return None


def run_in_copy(checkout, copy, suite_name, names, copied):
    os.chdir(copy)
    os.environ["PWD"] = copy
    scrubbed = sorted(key for key, value in os.environ.items() if names_checkout(value, checkout))
    for key in scrubbed:
        del os.environ[key]
    sys.path[:] = [p for p in sys.path if not names_checkout(os.path.realpath(p or "."), checkout)]
    sys.path.insert(0, os.path.dirname(os.path.join(copy, suite_name)))  # as when run as a script
    sys.dont_write_bytecode = True
    hits = guard(checkout)
    spec = importlib.util.spec_from_file_location("strict_selftest_suite", os.path.join(copy, suite_name))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader = unittest.TestLoader()
    try:
        spec.loader.exec_module(module)
        tests = loader.loadTestsFromNames(names, module) if names else loader.loadTestsFromModule(module)
    except Exception as error:  # an import of an undeclared input fails here
        print("strict self-test failed: the suite did not load: %r" % (error,), file=sys.stderr)
        return 1
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
    if hits:
        problems.append("the suite reached the checkout outside its declared copy (%s)"
                        % ", ".join(sorted(set(hits))))
    if problems:
        print("strict self-test failed: " + "; ".join(problems), file=sys.stderr)
        return 1
    print("%s: %d tests, 0 skipped, run in a copy of its %d declared inputs%s" % (
        RECEIPT, result.testsRun, copied, "; checkout variables removed: " + ", ".join(scrubbed) if scrubbed else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
