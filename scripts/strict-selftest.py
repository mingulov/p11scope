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

The copy must not be bypassed.
- The runner runs as `python3 -I -S` (it re-executes itself so if started
  otherwise): no site startup, no .pth file, no sitecustomize, nothing
  preloaded. sys.path is then the suite's directory in the copy followed by
  the interpreter's standard library entries, nothing else.
- Before anything runs, every inherited GIT_* and PYTHON* variable and
  every variable whose value resolves into the checkout leaves the
  environment. A value resolves into it when the whole value, any
  os.pathsep or shell word of it, or the part after `=` of such a word,
  resolves (symlinks, `..`, `~`; a relative one, to an existing path, from
  the invocation directory or the copy) to the checkout or below it. Spaces and colons in a name are
  kept whole, so they never split an alias.
- git runs with a built environment, explicit repository and work tree, an
  empty template and no hooks, and the copy must then be one clean commit
  of exactly the declared inputs.
- An audit hook fails the run on any event (open, listdir, exec, spawn,
  chdir and so on) whose arguments resolve into the checkout by the same
  rule, relative to the current directory.
Limits: string scanning cannot be complete. A path can be spelled in
ways no scanner of environment values and audit arguments foresees (shell
expansion, a program's own syntax, a child that builds it), so the scrub
and the hook close the known spellings only. The complete fix is to run the
suite in a mount namespace where the checkout path does not exist; that is
on the v0.8.1 infrastructure list. Also, the hook sees this process
only: a child that rebuilds the checkout path with nothing naming it, or a
child interpreter's own site packages (children get no PYTHON* variable),
is outside it; nothing the two strict suites run does either.

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
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

RECEIPT = "strict self-test passed"
SOURCE_EVENTS = {"compile", "exec", "code.__new__", "marshal.loads", "marshal.load", "marshal.dumps"}


SHELL_OPERATORS = ";&|()<>`'\"{}!"


def shell_words(text):
    """Shell words of a value: shlex with the operator characters split off
    (quoted names keep them; no comment handling), each word also with
    operator characters stripped from both ends (for unbalanced or odd
    spellings). Both readings are candidates, so a quoted name and its
    stripped twin are both checked: if either resolves into the checkout,
    the value is refused (fail closed)."""
    words = []
    if len(text) <= 65536:
        try:
            lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = ""  # `#` inside a word is part of a name
            words = list(lexer)
        except ValueError:
            words = []
    if not words:
        words = text.split()
    return words + [word.strip(SHELL_OPERATORS) for word in words]


def candidates(text):
    """Every reading of a value as a path: the whole value, its os.pathsep
    parts, its shell words (quotes kept, operators split off) and their
    `--opt=` values."""
    out = {text}
    out.update(text.split(os.pathsep))
    words = shell_words(text)
    out.update(words)
    out.update(word.split("=", 1)[1] for word in words if "=" in word)
    return {c for c in out if c and "\0" not in c}


def resolves_into(text, checkout, bases):
    for candidate in candidates(text):
        if candidate.startswith("~"):
            candidate = os.path.expanduser(candidate)
        if candidate.startswith(os.sep):
            paths, relative = [candidate], False
        elif os.sep in candidate or candidate in (os.curdir, os.pardir):
            # Relative: as each context would resolve it. Only a path that
            # exists there counts, or every relative word would be an alias
            # when a context lies in the checkout.
            paths, relative = [os.path.join(base, candidate) for base in bases], True
        else:
            continue
        for path in paths:
            try:
                real = os.path.realpath(path)
                if (real == checkout or real.startswith(checkout + os.sep)) and (
                        not relative or os.path.lexists(real)):
                    return True
            except (OSError, ValueError):
                continue
    return False


def names_checkout(value, checkout, bases=None):
    """Whether a value names the checkout, literally or through any alias
    that resolves into it."""
    if bases is None:
        bases = (os.getcwd(),)
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    if isinstance(value, str):
        return (value == checkout or (checkout + os.sep) in value
                or resolves_into(value, checkout, bases))
    if isinstance(value, os.PathLike):
        return names_checkout(os.fspath(value), checkout, bases)
    if isinstance(value, dict):
        return any(names_checkout(k, checkout, bases) or names_checkout(v, checkout, bases)
                   for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(names_checkout(item, checkout, bases) for item in value)
    return False


def guard(checkout):
    """Fail the run on any audited event that names the checkout."""
    hits = []

    def hook(event, args):
        # Source text being compiled or executed is code, not a path it uses.
        if event not in SOURCE_EVENTS and names_checkout(args, checkout):
            hits.append(event)

    sys.addaudithook(hook)
    return hits


def main(argv):
    if len(argv) < 4:
        print("usage: strict-selftest.py ROOT RUNNER MODE SUITE [TEST_NAME...]", file=sys.stderr)
        return 2
    root, runner, mode, suite, names = argv[0], argv[1], argv[2], argv[3], argv[4:]
    checkout = os.path.realpath(root)
    invoked_in = os.getcwd()
    base = os.path.realpath(tempfile.mkdtemp(prefix="strict-selftest-"))
    try:
        return prepare_and_run(checkout, invoked_in, base, runner, mode, suite, names)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def prepare_and_run(checkout, invoked_in, base, runner, mode, suite, names):
    copy = os.path.join(base, "source")
    # Before anything runs (git included): no inherited git or Python
    # routing, and no variable resolving into the checkout from the
    # invocation directory or the copy, reaches the copy.
    removed = sorted(key for key, value in os.environ.items()
                     if key.startswith(("GIT_", "PYTHON")) or names_checkout(value, checkout, (invoked_in, copy)))
    for key in removed:
        del os.environ[key]
    declared = runpy.run_path(os.path.join(checkout, "scripts/runner_inputs.py"))
    inputs = sorted(set(declared["required"](runner, mode)) | {declared["SELF"], runner})
    suite_name = os.path.relpath(os.path.realpath(suite), checkout)
    if suite_name not in inputs:
        print("strict self-test failed: the suite %s is not a declared input of %s %s"
              % (suite_name, runner, mode), file=sys.stderr)
        return 1
    if base == checkout or base.startswith(checkout + os.sep):
        print("strict self-test failed: the copy %s lies inside the checkout" % base, file=sys.stderr)
        return 1
    for name in inputs:
        source, target = os.path.join(checkout, name), os.path.join(copy, name)
        if not os.path.isfile(source):
            print("strict self-test failed: declared input missing: %s" % source, file=sys.stderr)
            return 1
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(source, target)
    refused = commit_copy(copy, inputs)
    if refused:
        print("strict self-test failed: " + refused, file=sys.stderr)
        return 1
    return run_in_copy(checkout, copy, suite_name, names, len(inputs), removed)


def commit_copy(copy, inputs):
    """Make the copy a one-commit checkout of exactly the declared inputs
    (the suite drives --rev and the clean-tree build checks). Git gets a
    built environment and explicit repository, work tree, empty template and
    no hooks, so nothing inherited can route it elsewhere."""
    git = shutil.which("git")
    if git is None:
        return "git is required: the suite drives the runner's --rev checks"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": copy, "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_AUTHOR_NAME": "strict-selftest", "GIT_AUTHOR_EMAIL": "strict-selftest@invalid",
           "GIT_COMMITTER_NAME": "strict-selftest", "GIT_COMMITTER_EMAIL": "strict-selftest@invalid"}
    bound = [git, "--git-dir=" + os.path.join(copy, ".git"), "--work-tree=" + copy, "-c", "core.hooksPath=/dev/null"]
    steps = ([git, "init", "-q", "--template=", copy], bound + ["add", "-A"],
             bound + ["commit", "-q", "--no-gpg-sign", "--no-verify", "-m", "declared inputs"],
             bound + ["rev-list", "--count", "HEAD"], bound + ["status", "--porcelain"], bound + ["ls-files"])
    out = []
    for argv in steps:
        result = subprocess.run(argv, env=env, capture_output=True, text=True, cwd=copy)
        if result.returncode != 0:
            return "git %s failed in the copy: %s" % (argv[1] if argv[1] == "init" else argv[5], result.stderr.strip())
        out.append(result.stdout)
    if out[3].strip() != "1":
        return "the copy is not one commit (rev-list says %r)" % out[3].strip()
    if out[4] != "":
        return "the copy is not clean after its commit: %r" % out[4].strip()
    if sorted(out[5].split("\n")[:-1] if out[5] else []) != sorted(inputs):
        return "the copy's commit is not exactly its declared inputs"
    return None


def run_in_copy(checkout, copy, suite_name, names, copied, scrubbed):
    os.chdir(copy)
    os.environ["PWD"] = copy
    # Imports resolve in the copy or the standard library only: under -I -S
    # sys.path is the standard library alone (-I adds no script directory,
    # -S no site directory), and the suite's directory goes first.
    sys.path.insert(0, os.path.dirname(os.path.join(copy, suite_name)))
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
        RECEIPT, result.testsRun, copied, "; inherited variables removed: " + ", ".join(scrubbed) if scrubbed else ""))
    return 0


if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.no_site):
        # Always -I -S: no site startup may add paths or preload modules.
        os.execv(sys.executable, [sys.executable, "-I", "-S", os.path.abspath(__file__)] + sys.argv[1:])
    sys.exit(main(sys.argv[1:]))
