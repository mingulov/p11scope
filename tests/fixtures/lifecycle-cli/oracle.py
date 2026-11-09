#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Lifecycle CLI oracle (WP-10, S9/S10): judge one cell from its report, ledger(s) and receipt.

Usage: oracle.py --cell NAME --report REPORT --ledger LEDGER --receipt RECEIPT [--stderr STDERR]
Writes one results.jsonl row to stdout; exit 0 when the cell passes, 1 when it
fails, 2 on harness error. Expected-failure cells exit 0 with
qualification "expected-failure" when the known gap reproduces, and 1 with
"failed" when it unexpectedly passes or fails differently (so a silent fix
gets noticed).

Ledger formats:
- public-cli-ledger/v1 (single JSON LEDGER line): reload, reuse target,
  late-dlopen, short-lived callers.
- inventory-ledger EXEC-chain lines (IDENT/MAPPED/LEDGER/EXEC/DONE per gen):
  run-exec-chain.
"""

import argparse
import json
import re
import sys

EXPECTED_FAILURES = {
    # WU-13 lane: --prearm-module reporting is incomplete at f939a5873.
    # With the flag the first calls after a late dlopen are counted
    # exactly, but observation stays lossy (skipped, loader windows)
    # because no R2-D1-6 exactness producer ships yet
    # (docs/known-limitations.md: pre-arm exactness producers are packet
    # 6.13 follow-ups). Revisit when WU-13 lands.
    "prearm-late-dlopen": "WU-13: prearm counts exact but observation lossy; reporting incomplete",
}


def fail(cell, detail, qualification="failed"):
    print(json.dumps({"cell": cell, "pass": False,
                      "qualification": qualification, "detail": detail}))
    return 1


def passed(cell, detail, qualification="qualified"):
    print(json.dumps({"cell": cell, "pass": True,
                      "qualification": qualification, "detail": detail}))
    return 0


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise HarnessError(f"{what} {path} unreadable: {exc}") from exc


class HarnessError(Exception):
    pass


class CellFailure(Exception):
    pass


def require(ok, detail):
    if not ok:
        raise CellFailure(detail)


def parse_cli_ledger(text, cell):
    """Parse p11scope/public-cli-ledger/v1 LEDGER lines; return {name: attempts}."""
    expected = {}
    complete = True
    for line in text.splitlines():
        if not line.startswith("LEDGER "):
            continue
        ledger = json.loads(line[len("LEDGER "):])
        if ledger.get("schema") != "p11scope/public-cli-ledger/v1":
            raise CellFailure(f"{cell}: unexpected ledger schema")
        if ledger.get("complete") is not True:
            complete = False
        for row in ledger.get("functions", []):
            name = row.get("name")
            attempts, successful = row.get("attempts"), row.get("successful")
            if not (isinstance(attempts, int) and isinstance(successful, int)):
                raise CellFailure(f"{cell}: invalid ledger row {row!r}")
            if attempts != successful:
                raise CellFailure(f"{cell}: workload had failed calls: {name}")
            expected[name] = expected.get(name, 0) + attempts
    require(expected, f"{cell}: no LEDGER lines")
    require(complete, f"{cell}: workload ledger incomplete")
    return expected


def check_common(receipt, cell, scope):
    require(receipt.get("cell") == cell, "receipt cell mismatch")
    require(receipt.get("scope") == scope, "receipt scope mismatch")
    for key in ("workload_ready", "capture_ready", "ledger_complete"):
        require(receipt.get(key) is True, f"missing {key}")
    for key in ("observer_exit", "workload_exit"):
        require(receipt.get(key) == 0, f"nonzero {key}")


def check_report_counts(report, expected, cell, provider):
    rows = report.get("functions")
    require(isinstance(rows, list), "missing functions")
    want_dev = tuple(provider.get("dev") or [])
    want_ino = provider.get("ino")
    matched = {}
    for row in rows:
        names = row.get("names") or []
        calls = row.get("calls")
        if not isinstance(calls, int):
            raise CellFailure(f"{cell}: invalid count row")
        obj = (row.get("target") or {}).get("object")
        if obj is None:
            continue
        got_dev = tuple(obj.get("dev") or [])
        if got_dev == want_dev and obj.get("ino") == want_ino and names:
            matched[names[0]] = matched.get(names[0], 0) + calls
    for name, want in expected.items():
        got = matched.get(name, 0)
        require(got == want,
                f"{cell}: {name} observed {got} != ledger {want}")
    extras = {name: got for name, got in matched.items()
              if name not in expected and got}
    require(not extras, f"{cell}: phantom owned calls {extras}")
    return matched


def judge_reload(report, ledger_text, receipt):
    cell = "profile-pid-reload"
    check_common(receipt, cell, "pid")
    expected = parse_cli_ledger(ledger_text, cell)
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "wrong schema")
    require(report.get("capture", {}).get("scope") == "pid", "wrong scope")
    evidence = report.get("evidence", {})
    for key in ("event_loss", "semantic_capture_failures"):
        require(evidence.get(key) == 0, f"loss {key}")
    observation = evidence.get("gap_classes", {}).get("observation", {})
    # Reload discloses loader windows; the calls themselves stay exact.
    # Pin the documented causes: no other loss may hide behind reload.
    # Ubuntu reports loader_discovery windows. Fedora's SoftHSM 2.7 shape
    # (68-slot table labelled {3,2}, walked as known_prefix) additionally
    # reports surfaces; that cause is allowed only for that known shape
    # and is labelled, so any other surfaces failure still fails.
    causes = set(observation.get("causes") or [])
    allowed = {"unprotected_live_windows", "loader_discovery"}
    known_shape = False
    if "surfaces" in causes:
        surfaces = evidence.get("surfaces") or []
        ok = (
            isinstance(surfaces, list)
            and bool(surfaces)
            and any(isinstance(entry, dict)
                    and entry.get("walk") == "known_prefix"
                    for entry in surfaces)
            and all(isinstance(entry, dict)
                    and entry.get("walk") in ("full", "known_prefix")
                    and entry.get("acquisition") == "ok"
                    for entry in surfaces)
        )
        require(ok,
                f"surfaces cause without the known SoftHSM 2.7 "
                f"known_prefix shape: {surfaces!r}")
        allowed = allowed | {"surfaces"}
        known_shape = True
    require(causes <= allowed,
            f"unexpected observation causes {causes}")
    if observation.get("status") == "exact":
        require(not causes, "exact with causes")
    else:
        require(observation.get("status") in ("lossy", "partial"),
                f"bad observation status {observation}")
    provider = receipt["provider_before"]
    matched = check_report_counts(report, expected, cell, provider)
    shown = {name: matched.get(name, 0) for name in sorted(expected)}
    detail = (f"reload totals exact across dlclose/dlopen: {shown} "
              f"causes={sorted(causes)}")
    if known_shape:
        detail += " [SoftHSM 2.7 table shape; exec-scan-legacy32]"
    return passed(cell, detail)


def judge_reuse(report, ledger_text, receipt, stderr_text):
    cell = "profile-pid-reuse"
    # The reuser's exit is not part of this receipt; only the target and
    # the observer must be clean.
    require(receipt.get("cell") == cell, "receipt cell mismatch")
    require(receipt.get("scope") == "pid", "receipt scope mismatch")
    require(receipt.get("workload_ready") is True, "target never ready")
    require(receipt.get("capture_ready") is True, "capture never ready")
    require(receipt.get("ledger_complete") is True, "target ledger incomplete")
    require(receipt.get("observer_exit") == 0, "observer nonzero")
    require(receipt.get("workload_exit") == 0, "target nonzero")
    expected = parse_cli_ledger(ledger_text, cell)
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "wrong schema")
    provider = receipt["provider_before"]
    matched = check_report_counts(report, expected, cell, provider)
    # Nothing from the reuser: observed equals the target ledger exactly,
    # and the reuser ledger (recorded in the receipt) is nonzero, so the
    # equality is non-vacuous.
    reuser_calls = receipt.get("reuser_calls", 0)
    require(isinstance(reuser_calls, int) and reuser_calls > 0,
            "reuser made no calls; cell is vacuous")
    reason = ((report.get("evidence", {}).get("scheduling", {})
               .get("phase_mono_ns", {}).get("loop_end_reason")))
    require(reason == "target_exit",
            f"loop_end_reason {reason!r} != target_exit")
    require("target exited" in stderr_text, "stderr lacks target-exited marker")
    shown = {name: matched.get(name, 0) for name in sorted(expected)}
    return passed(cell, f"target {shown} exact; reuser {reuser_calls} excluded; {reason}")


def parse_exec_ledger(text, cell):
    """Sum inventory-ledger LEDGER n per (fn, phase); require DONE ok."""
    totals = {}
    setup = {}
    dones = 0
    images = set()
    for line in text.splitlines():
        if line.startswith("LEDGER "):
            fields = dict(token.split("=", 1) for token in line.split()[1:])
            fn = fields.get("fn")
            n, bad, phase = fields.get("n"), fields.get("bad"), fields.get("phase")
            gen = fields.get("gen")
            require(fn and n is not None and bad is not None,
                    f"{cell}: malformed LEDGER line")
            require(int(bad) == 0, f"{cell}: workload had failed calls: {fn}")
            totals[fn] = totals.get(fn, 0) + int(n)
            if phase == "setup":
                setup[fn] = setup.get(fn, 0) + int(n)
            if gen is not None:
                images.add(gen)
        elif line.startswith("DONE "):
            require("status=ok" in line, f"{cell}: image did not finish ok")
            dones += 1
    require(totals, f"{cell}: no LEDGER lines")
    require(dones >= 2, f"{cell}: need at least 2 DONE ok images, got {dones}")
    return totals, setup, dones, len(images)


def judge_exec_chain(report, ledger_text, receipt):
    cell = "run-exec-chain"
    require(receipt.get("observer_exit") == 0, "observer nonzero")
    require(receipt.get("dones", 0) >= 2, "fewer than 2 DONE ok images")
    expected, setup, dones, images = parse_exec_ledger(ledger_text, cell)
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "wrong schema")
    rows = report.get("functions") or []
    observed = {}
    for row in rows:
        for name in row.get("names") or []:
            observed[name] = observed.get(name, 0) + int(row.get("calls", 0))
    evidence = report.get("evidence", {})
    observation = evidence.get("gap_classes", {}).get("observation", {})
    causes = set(observation.get("causes") or [])
    # Main and teardown phases must match exactly per function; setup may
    # fall short under --pause auto across exec, but then each setup
    # shortfall needs the named pause/exec gap causes.
    mismatched = []
    setup_short = []
    for name, want in expected.items():
        got = observed.get(name, 0)
        if got != want:
            if name in setup:
                setup_short.append(f"{name} {got}!={want}")
            else:
                mismatched.append(f"{name} {got}!={want}")
    require(not mismatched,
            f"{cell}: main/teardown mismatch: {mismatched}")
    if setup_short:
        require({"pause_partial", "loader_discovery"} <= causes,
                f"{cell}: setup short {setup_short} without named pause/exec gap {causes}")
    shown = {name: observed.get(name, 0) for name in sorted(expected)}
    return passed(cell, f"{dones} images ({images} gens) main/teardown exact; "
                        f"setup gaps {setup_short or 'none'} causes={sorted(causes)} "
                        f"totals={shown}")


def judge_churn(report, ledger_text, receipt):
    cell = "profile-system-exec-churn"
    check_common(receipt, cell, "system")
    expected = parse_cli_ledger(ledger_text, cell)
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "wrong schema")
    require(report.get("capture", {}).get("scope") == "system", "wrong scope")
    evidence = report.get("evidence", {})
    for key in ("event_loss", "semantic_capture_failures"):
        require(evidence.get(key) == 0, f"loss {key}")
    provider = receipt["provider_before"]
    matched = check_report_counts(report, expected, cell, provider)
    shown = {name: matched.get(name, 0) for name in sorted(expected)}
    return passed(cell, f"owned exact beside churn: {shown}")


def judge_prearm(report, ledger_text, receipt, with_flag):
    cell = "prearm-late-dlopen" if with_flag else "prearm-late-dlopen-noflag"
    check_common(receipt, cell, "pid")
    expected = parse_cli_ledger(ledger_text, cell)
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "wrong schema")
    provider = receipt["provider_before"]
    want_dev = tuple(provider.get("dev") or [])
    want_ino = provider.get("ino")
    rows = report.get("functions") or []
    matched = {}
    for row in rows:
        obj = (row.get("target") or {}).get("object")
        if obj is None:
            continue
        if (tuple(obj.get("dev") or []) == want_dev and
                obj.get("ino") == want_ino):
            for name in row.get("names") or []:
                matched[name] = matched.get(name, 0) + int(row.get("calls", 0))
    evidence = report.get("evidence", {})
    observation = evidence.get("gap_classes", {}).get("observation", {})
    if with_flag:
        for name, want in expected.items():
            got = matched.get(name, 0)
            require(got == want,
                    f"{cell}: {name} observed {got} != ledger {want}")
        require(observation.get("status") == "exact",
                f"lossy observation with prearm: {observation}")
        return passed(cell, f"prearmed first calls exact: {matched}")
    # Twin without the flag: the documented late-load gap must appear.
    # Either counts fall short with a named cause, or the window is disclosed.
    short = any(matched.get(name, 0) != want
                for name, want in expected.items())
    lossy = observation.get("status") != "exact"
    watches = [row for row in evidence.get("discovery", [])
               if isinstance(row, dict) and row.get("watch") is not None]
    unobserved = [row for row in evidence.get("discovery", [])
                  if isinstance(row, dict) and row.get("unobserved_windows")]
    require(short or lossy or watches or unobserved,
            f"{cell}: no late-load gap disclosed")
    shown = {name: matched.get(name, 0) for name in sorted(expected)}
    return passed(cell, f"late-load gap disclosed: short={short} lossy={lossy} "
                        f"matched={shown} causes={observation.get('causes')}")


def judge_short_cgroup(report, ledger_text, receipt):
    cell = "track-short-lived-cgroup"
    require(receipt.get("cell") == cell, "receipt cell mismatch")
    require(receipt.get("scope") == "cgroup", "receipt scope mismatch")
    require(receipt.get("capture_ready") is True, "capture never ready")
    require(receipt.get("ledger_complete") is True, "need 20 LEDGER lines")
    require(receipt.get("observer_exit") == 0, "observer nonzero")
    expected = parse_cli_ledger(ledger_text, cell)
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "wrong schema")
    evidence = report.get("evidence", {})
    hints = evidence.get("gap_exe_hints")
    require(isinstance(hints, dict), "gap_exe_hints missing")
    total = sum(int(hints.get(key, 0)) for key in
                ("links_provider", "links_pkcs11_loader",
                 "no_static_link_within_scope", "unknown"))
    require(total == 20, f"hint total {total} != 20 callers: {hints}")
    return passed(cell, f"hints match 20 callers: {hints}")


def judge_short_pid(report, ledger_text, receipt):
    cell = "track-short-lived-pid"
    check_common(receipt, cell, "pid")
    expected = parse_cli_ledger(ledger_text, cell)
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "wrong schema")
    evidence = report.get("evidence", {})
    require(evidence.get("gap_exe_hints") is None,
            "flag recorded exe hints under --pid")
    require(evidence.get("gap_exit_mappings") is None,
            "flag recorded exit mappings under --pid")
    # 7.10b: the widened --pid cell arms the PID consumer. The gated
    # workload performs no mid-capture exec, so the split is present
    # with a zero total.
    target = evidence.get("target_exec_hints")
    require(isinstance(target, dict), "target_exec_hints missing")
    require(target.get("label") == "STATIC HINT",
            f"target_exec_hints label wrong: {target!r}")
    counts = [target.get(key) for key in
              ("links_provider", "links_pkcs11_loader",
               "no_static_link_within_scope", "unknown")]
    require(all(type(count) is int and count >= 0 for count in counts),
            f"target_exec_hints counts wrong: {target!r}")
    require(sum(counts) == 0,
            f"target_exec_hints total {sum(counts)} != 0: {target!r}")
    provider = receipt["provider_before"]
    matched = check_report_counts(report, expected, cell, provider)
    shown = {name: matched.get(name, 0) for name in sorted(expected)}
    return passed(cell, f"pid exact, target split zero: {shown}")


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--cell", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--stderr", default=None)
    args = parser.parse_args(argv)
    try:
        report = load_json(args.report, "report")
        with open(args.ledger, encoding="utf-8") as handle:
            ledger_text = handle.read()
        receipt = load_json(args.receipt, "receipt")
        stderr_text = ""
        if args.stderr:
            with open(args.stderr, encoding="utf-8", errors="replace") as handle:
                stderr_text = handle.read()
        if args.cell == "profile-pid-reload":
            return judge_reload(report, ledger_text, receipt)
        if args.cell == "profile-pid-reuse":
            return judge_reuse(report, ledger_text, receipt, stderr_text)
        if args.cell == "run-exec-chain":
            return judge_exec_chain(report, ledger_text, receipt)
        if args.cell == "profile-system-exec-churn":
            return judge_churn(report, ledger_text, receipt)
        if args.cell == "prearm-late-dlopen":
            return judge_prearm(report, ledger_text, receipt, True)
        if args.cell == "prearm-late-dlopen-noflag":
            return judge_prearm(report, ledger_text, receipt, False)
        if args.cell == "track-short-lived-cgroup":
            return judge_short_cgroup(report, ledger_text, receipt)
        if args.cell == "track-short-lived-pid":
            return judge_short_pid(report, ledger_text, receipt)
        return fail(args.cell, f"oracle for {args.cell} not implemented yet")
    except HarnessError as exc:
        print(json.dumps({"cell": args.cell, "pass": False,
                          "qualification": "failed",
                          "detail": f"harness: {exc}"}))
        return 2
    except CellFailure as exc:
        if args.cell in EXPECTED_FAILURES:
            print(json.dumps({"cell": args.cell, "pass": False,
                              "qualification": "expected-failure",
                              "detail": f"{exc} [{EXPECTED_FAILURES[args.cell]}]"}))
            return 0
        return fail(args.cell, str(exc))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
