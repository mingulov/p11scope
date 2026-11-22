# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Joint linked-stop cell log builders with real libtest framing.

Shared by test_joint_stop_verdict.py (the table), test_ci_stop_races.py
(S3) and test_ignored_tests.py (LONG). The framing is the pinned
1.99.1 libtest pretty `--nocapture` output, in both the threaded form
(S3's default) and the `--test-threads=1` form (LONG), where the first
output line is glued to the `test NAME ... ` prefix and the verdict
stands on its own line. The record lines are the ones the Rust cell
prints (src/inventory/joint_stop_races_privileged_tests.rs).
"""

CELL = ("inventory::joint_stop_races_privileged_tests::"
        "privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64")
OFFSETS_MS = (0, 1, 5, 20)
OK_SUMMARY = ("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
              "12231 filtered out; finished in 148.83s")
FAILED_SUMMARY = ("test result: FAILED. 0 passed; 1 failed; 0 ignored; "
                  "0 measured; 12231 filtered out; finished in 11.68s")
S1_ERROR = ("Error: wp7-stop{k}: no joint feeds with S1 seal "
            "(producers unlinked, zero installs); not attempted")
UNATTRIBUTED_ERROR = ("Error: wp7-stop{k}: no joint feeds without S1 seal "
                      "(producers linked, zero installs unexplained); "
                      "not attempted")
BACKTRACE = [
    "",
    "Stack backtrace:",
    "   0: <anyhow::Error>::msg::<alloc::string::String>",
    "   1: p11scope::inventory::joint_stop_races_privileged_tests::run_stop_offset",
    "             at ./nptl/pthread_create.c:454:8",
]
PREAMBLE = [
    "JOINT_R16 r16-lane step=started live=1 gated=0 finished=0 ticks=0",
    "JOINT_R16 r16-map round=0 mapped=2/2",
]


def offset_of(k):
    return OFFSETS_MS[k % 4]


def case_head(k):
    """Pre-stop lines of case k up to its linked tag."""
    return ["JOINT_STOP wp7-stop%d: prep=Services(1) done; stopping in %d ms"
            % (k, offset_of(k)),
            "P11SCOPE_CELL_BRANCH=wp7-stop%d:linked" % k]


def case_outcome(k, finish="published", latch="latched", offset=None):
    """Outcome print plus the offset branch diagnostic of case k."""
    ms = offset_of(k) if offset is None else offset
    return ["JOINT_STOP outcome: offset=%d begin=polling finish=%s (3 polls) "
            "first_error=None latched=true" % (ms, finish),
            "P11SCOPE_CELL_BRANCH=offset%d:%s:%s" % (ms, latch, finish)]


def case_lines(k, finish="published"):
    """One completed case: linked, offset diagnostic, checks, marker."""
    return (case_head(k) + case_outcome(k, finish)
            + ["JOINT_STOP offset=%d: at-Q published (api_a == a_semantic)"
               % offset_of(k),
               "P11SCOPE_STOP_COMPLETE=wp7-stop%d" % k])


def matrix_body(cases=range(12)):
    body = list(PREAMBLE)
    for k in cases:
        body += case_lines(k)
    return body


def s1_body(k=0, error=None):
    return (matrix_body(range(k)) + ["P11SCOPE_CELL_BRANCH=wp7-stop%d:s1-precluded" % k]
            + [S1_ERROR.format(k=k) if error is None else error])


def unattributed_body(k=0):
    return (matrix_body(range(k))
            + ["P11SCOPE_CELL_BRANCH=wp7-stop%d:no-feeds-unattributed" % k,
               UNATTRIBUTED_ERROR.format(k=k)])


def wedge_error(ms, finish="unpublished", own=None):
    return ("Error: offset %d: the finish must reach Published then "
            "WoundDown: offset=%d begin=polling finish=%s (1000 polls) "
            "first_error=None latched=false" % (ms, ms if own is None else own,
                                               finish))


def wedge_body(k=5, finish="unpublished"):
    return (matrix_body(range(k)) + case_head(k)
            + case_outcome(k, finish, latch="no-latch")
            + [wedge_error(offset_of(k), finish)])


def frame(body, ok, threaded=True, summary=None, cell=CELL, trailer=None,
          tail=()):
    """Wrap body lines in the pinned libtest framing."""
    word = "ok" if ok else "FAILED"
    if summary is None:
        summary = OK_SUMMARY if ok else FAILED_SUMMARY
    if trailer is None:
        trailer = ([""] if ok else
                   ["", "failures:", "", "failures:", "    " + cell, ""])
    lines = ["", "running 1 test"]
    if threaded:
        lines += list(body) + ["test %s ... %s" % (cell, word)]
    else:
        body = list(body)
        if body:
            lines += ["test %s ... %s" % (cell, body[0])] + body[1:] + [word]
        else:
            lines += ["test %s ... %s" % (cell, word)]
    lines += trailer + [summary, ""] + list(tail)
    return "\n".join(lines) + "\n"


def passing(**kwargs):
    return frame(matrix_body(), True, **kwargs)


def precluded(**kwargs):
    return frame(s1_body(), False, **kwargs)
