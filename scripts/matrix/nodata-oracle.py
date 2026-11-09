#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""v0.7.0 no-data matrix oracle: judge one live cell.

Owner rule: if a program makes PKCS#11 calls, p11scope must produce data
about them. For each cell the oracle asserts:

- the provider module appears in the observer output;
- calls > 0 (and the exact spike/expected.txt multiset when --exact);
- the caller appears, or a NAMED caller-unknown with a reason;
- every other missing piece is a named gap.

FAIL on an empty view, zero endpoints, zero calls, an unnamed refusal,
or a shape this oracle does not understand (never a silent pass).

Exit 0 on PASS, 1 on FAIL. The last line is always machine-readable::

    RESULT verdict=PASS|FAIL calls=N|unknown endpoints=N|unknown
        caller=named|unknown-named|missing|aggregate note=<word>
"""

import argparse
import json
import re
import sys

EVENT_FN_RE = re.compile(r" (C_[A-Za-z0-9]+) \u2192 ")
TRUNCATED_RE = re.compile(r"^TRUNCATED at \d+ events")


def build_parser():
    parser = argparse.ArgumentParser(description="judge one no-data matrix cell")
    parser.add_argument("--cell", required=True)
    parser.add_argument("--mode", required=True,
                        choices=["run", "profile", "trace", "inventory"])
    parser.add_argument("--scope", required=True,
                        choices=["pid", "cgroup", "system", "child"])
    parser.add_argument("--json", required=True)
    parser.add_argument("--stdout", required=True)
    parser.add_argument("--stderr", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--sysprovider", required=True)
    parser.add_argument("--min-calls", required=True, type=int)
    parser.add_argument("--exact", default=None)
    parser.add_argument("--caller", default=None)
    parser.add_argument("--caller-pid", default=None, type=int)
    return parser


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def load_expected(path):
    expected = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) == 2:
                expected[parts[0]] = int(parts[1])
    return expected


class Verdict:
    def __init__(self, cell, mode, scope):
        self.cell = cell
        self.mode = mode
        self.scope = scope
        self.findings = []
        self.failed = False
        self.calls = "unknown"
        self.endpoints = "unknown"
        self.caller = "missing"
        self.note = "ok"

    def bad(self, message):
        self.findings.append("FAIL: %s" % message)
        self.failed = True

    def info(self, message):
        self.findings.append("note: %s" % message)

    def report(self):
        print("cell=%s mode=%s scope=%s: %s"
              % (self.cell, self.mode, self.scope,
                 "FAIL" if self.failed else "PASS"))
        for finding in self.findings:
            print("  %s" % finding)
        if self.failed and self.note == "ok":
            for finding in self.findings:
                if finding.startswith("FAIL: "):
                    words = re.sub(r"[^A-Za-z0-9]+", "_",
                                   finding[len("FAIL: "):]).strip("_")
                    self.note = words[:60] or "fail"
                    break
        print("RESULT verdict=%s calls=%s endpoints=%s caller=%s note=%s"
              % ("FAIL" if self.failed else "PASS", self.calls,
                 self.endpoints, self.caller, self.note))
        return 1 if self.failed else 0


def provider_present(haystacks, provider, sysprovider):
    return any(provider in hay or sysprovider in hay for hay in haystacks)


def check_profile(verdict, doc, text_blobs, args):
    capture = doc.get("capture")
    functions = doc.get("functions")
    if not isinstance(capture, dict) or not isinstance(functions, list):
        verdict.bad("oracle: unrecognized profile shape "
                    "(need capture{} and functions[])")
        return
    modules = capture.get("modules")
    if not isinstance(modules, list):
        verdict.bad("oracle: unrecognized profile shape "
                    "(need capture.modules[])")
        return
    if not any(isinstance(row, dict)
               and (str(row.get("path", "")).endswith(args.provider)
                    or str(row.get("path", "")).endswith(args.sysprovider))
               for row in modules):
        verdict.bad("provider %s absent from capture.modules[] "
                    "(%d modules)" % (args.provider, len(modules)))
    else:
        verdict.info("provider present in capture.modules[]")
    counts = {}
    total = 0
    for row in functions:
        if not isinstance(row, dict):
            continue
        # Forwarding-layer rows duplicate the logical calls of the
        # provider row they contain (profile schema v3): consumers
        # summing calls must skip them to count each call once.
        if row.get("forwarding_layer"):
            continue
        names = row.get("names") or []
        calls = row.get("calls", 0) or 0
        total += calls
        if names:
            counts[names[0]] = counts.get(names[0], 0) + calls
    verdict.calls = str(total)
    verdict.endpoints = str(len(functions))
    if total < args.min_calls:
        verdict.bad("zero calls: total %d below min %d" % (total, args.min_calls))
    if args.exact:
        expected = load_expected(args.exact)
        missing = {name: count for name, count in expected.items()
                   if counts.get(name, 0) != count}
        extra = {name: count for name, count in counts.items()
                 if count > 0 and name not in expected}
        if missing or extra:
            verdict.bad("exact multiset mismatch: missing=%s extra=%s"
                        % (sorted(missing), sorted(extra)))
        else:
            verdict.info("exact multiset matches (%d calls)" % total)
    if args.scope == "system":
        # Profile counts are aggregate, not per application (cli help);
        # system scope cannot name one caller by design.
        verdict.caller = "aggregate"
        verdict.info("caller=aggregate: profile counts are aggregate, "
                     "not per-application")
        return
    if args.scope == "child":
        if args.caller and any(args.caller in blob for blob in text_blobs):
            verdict.caller = "named"
            verdict.info("child caller named on observer output")
        else:
            verdict.bad("run child caller '%s' not named on observer "
                        "output" % args.caller)
        return
    # pid scope: the target pid (or exe) must be named somewhere; a
    # bare aggregate with no target reference leaves the caller unnamed.
    pid = args.caller_pid
    blob = "\n".join(text_blobs) + json.dumps(doc)
    if pid is not None and re.search(r"\b%d\b" % pid, blob):
        verdict.caller = "named"
        verdict.info("caller pid %d named" % pid)
    elif args.caller and args.caller in blob:
        verdict.caller = "named"
        verdict.info("caller '%s' named" % args.caller)
    else:
        verdict.bad("caller unnamed: pid %s and exe '%s' absent from "
                    "profile output" % (pid, args.caller))


def parse_trace_evidence(body):
    count_evidence = None
    evidence = None
    truncated = False
    events = []
    for line in body.splitlines():
        if line.startswith("COUNT_EVIDENCE "):
            try:
                count_evidence = json.loads(line[len("COUNT_EVIDENCE "):])
            except ValueError:
                count_evidence = {}
        elif line.startswith("EVIDENCE "):
            try:
                evidence = json.loads(line[len("EVIDENCE "):])
            except ValueError:
                evidence = {}
        elif TRUNCATED_RE.match(line):
            truncated = True
        else:
            match = EVENT_FN_RE.search(line)
            if match:
                events.append((match.group(1), line))
    return events, count_evidence, evidence, truncated


def check_trace(verdict, body, text_blobs, args):
    events, count_evidence, evidence, truncated = parse_trace_evidence(body)
    if count_evidence is None or evidence is None:
        verdict.bad("oracle: unrecognized trace shape "
                    "(need COUNT_EVIDENCE and EVIDENCE lines)")
        return
    if not provider_present([body] + text_blobs, args.provider,
                            args.sysprovider):
        # Trace event lines name functions, not modules; the module must
        # still be named somewhere (the -v stderr notes name discovery).
        verdict.bad("provider %s named nowhere in trace output, "
                    "stdout or stderr" % args.provider)
    else:
        verdict.info("provider named in trace artifacts")
    counts = {}
    for name, _ in events:
        counts[name] = counts.get(name, 0) + 1
    total = len(events)
    verdict.calls = str(total)
    verdict.endpoints = str(total)
    stats_returned = count_evidence.get("stats_returned")
    if total < args.min_calls:
        verdict.bad("zero calls: %d events below min %d"
                    % (total, args.min_calls))
    if args.exact:
        expected = load_expected(args.exact)
        if stats_returned != sum(expected.values()):
            verdict.bad("trace stats_returned %s != expected %d"
                        % (stats_returned, sum(expected.values())))
        missing = {name: count for name, count in expected.items()
                   if counts.get(name, 0) != count}
        extra = {name: count for name, count in counts.items()
                 if count > 0 and name not in expected}
        if missing or extra:
            verdict.bad("exact event multiset mismatch: missing=%s "
                        "extra=%s" % (sorted(missing), sorted(extra)))
        else:
            verdict.info("exact event multiset matches (%d events)" % total)
    if truncated:
        verdict.info("trace truncated marker present")
    named = [line for _, line in events
             if args.caller and ('"%s"' % args.caller in line
                                 or "exe=" in line and args.caller in line)]
    if named:
        verdict.caller = "named"
        verdict.info("caller '%s' named on %d/%d events"
                     % (args.caller, len(named), total))
        return
    gap_classes = evidence.get("gap_classes", {})
    if not isinstance(gap_classes, dict):
        gap_classes = {}
    attribution = gap_classes.get("attribution", {})
    if not isinstance(attribution, dict):
        attribution = {}
    # Caller identity is an attribution question (a withheld name), never
    # an observation one: only a withheld attribution with a named cause
    # excuses unknown-only callers. No caller-specific cause exists in
    # current EVIDENCE (per-event identity reasons never leave the trace
    # renderer), so any withheld-attribution cause is a deliberate
    # approximation.
    causes = attribution.get("causes", []) or []
    if attribution.get("status") == "withheld" and causes:
        verdict.caller = "unknown-named"
        verdict.info("caller unknown with named attribution causes: %s"
                     % (causes,))
    else:
        verdict.bad("caller '%s' unnamed on all %d events and no "
                    "withheld attribution cause names why"
                    % (args.caller, total))


def check_inventory(verdict, doc, args):
    modules = doc.get("modules")
    edges = doc.get("edges")
    callers = doc.get("callers")
    gaps = doc.get("gaps")
    if not isinstance(modules, list) or not isinstance(edges, list) \
            or not isinstance(callers, list) or not isinstance(gaps, list):
        verdict.bad("oracle: unrecognized inventory shape "
                    "(need modules/edges/callers/gaps arrays)")
        return
    paths = [path for row in modules if isinstance(row, dict)
             for path in (row.get("paths") or [])]
    if not any(str(path).endswith(args.provider)
               or str(path).endswith(args.sysprovider) for path in paths):
        verdict.bad("provider %s absent from modules[].paths (%d "
                    "modules)" % (args.provider, len(modules)))
    else:
        verdict.info("provider present in modules[].paths")
    endpoints = 0
    for row in modules:
        admission = (row.get("admission") or {}) if isinstance(row, dict) \
            else {}
        try:
            endpoints += int(admission.get("endpoints") or 0)
        except (TypeError, ValueError):
            pass
        state = admission.get("state")
        reasons = admission.get("reasons") or []
        if state == "refused" and not reasons:
            verdict.bad("unnamed refusal: module %s refused with empty "
                        "reasons" % ((row.get("paths") or ["?"])[0],))
    verdict.endpoints = str(endpoints)
    if endpoints <= 0:
        verdict.bad("zero endpoints attached (%d modules, %d edges)"
                    % (len(modules), len(edges)))
    else:
        verdict.info("%d endpoints attached across %d edges"
                     % (endpoints, len(edges)))
    if not edges and not gaps:
        verdict.bad("empty view: no edges and no named gaps")
    entry_total = 0
    entry_known = False
    for edge in edges:
        count = ((edge.get("entries") or {}).get("count")
                 if isinstance(edge, dict) else None)
        if isinstance(count, int):
            entry_known = True
            entry_total += count
    verdict.calls = str(entry_total) if entry_known else "unknown"
    if entry_known and entry_total < args.min_calls:
        verdict.bad("entry counts %d below min %d"
                    % (entry_total, args.min_calls))
    for gap in gaps:
        if not isinstance(gap, dict):
            continue
        if not gap.get("subject") and not gap.get("reason"):
            verdict.bad("unnamed gap entry: empty subject and reason")
    # Caller: the expected pid (when given) must appear with its exe, or
    # a gap must name why the caller identity is unknown.
    pid = args.caller_pid
    target = None
    if pid is not None:
        for caller in callers:
            if isinstance(caller, dict) and caller.get("pid") == pid:
                target = caller
                break
        if target is None:
            verdict.bad("caller pid %d absent from callers[] (%d "
                        "callers)" % (pid, len(callers)))
            return
    else:
        for caller in callers:
            if not isinstance(caller, dict):
                continue
            exe = (caller.get("image") or {}).get("exe") or {}
            if args.caller and args.caller in str(exe.get("path", "")):
                target = caller
                break
    if target is not None:
        exe = (target.get("image") or {}).get("exe") or {}
        if args.caller and args.caller in str(exe.get("path", "")):
            verdict.caller = "named"
            verdict.info("caller '%s' named (pid %s)"
                         % (args.caller, target.get("pid")))
            return
        if exe.get("path") is None:
            named = [gap for gap in gaps if isinstance(gap, dict)
                     and ("caller" in str(gap.get("subject", "")).lower()
                          or "caller" in str(gap.get("reason", "")).lower()
                          or "unknown" in str(gap.get("subject", "")).lower()
                          or "unknown" in str(gap.get("reason", "")).lower())]
            if named:
                verdict.caller = "unknown-named"
                verdict.info("caller unknown with named gap: %s"
                             % (named[0].get("subject"),))
            else:
                verdict.bad("caller exe unknown with no caller gap naming "
                            "why")
            return
        verdict.bad("caller exe '%s' does not name '%s'"
                    % (exe.get("path"), args.caller))
        return
    named = [gap for gap in gaps if isinstance(gap, dict)
             and ("caller" in str(gap.get("subject", "")).lower()
                  or "caller" in str(gap.get("reason", "")).lower()
                  or "unknown" in str(gap.get("subject", "")).lower()
                  or "unknown" in str(gap.get("reason", "")).lower())]
    if named:
        verdict.caller = "unknown-named"
        verdict.info("caller unknown with named gap: %s"
                     % (named[0].get("subject"),))
    elif not callers and not gaps:
        verdict.bad("caller '%s' absent: no callers and no named gaps"
                    % (args.caller,))
    else:
        verdict.bad("caller '%s' unnamed in %d callers and no caller gap "
                    "names why" % (args.caller, len(callers)))


def main(argv):
    args = build_parser().parse_args(argv)
    verdict = Verdict(args.cell, args.mode, args.scope)
    try:
        raw = read_text(args.json)
    except OSError as exc:
        verdict.bad("cannot read %s: %s" % (args.json, exc))
        return verdict.report()
    try:
        stdout_text = read_text(args.stdout)
    except OSError:
        stdout_text = ""
    try:
        stderr_text = read_text(args.stderr)
    except OSError:
        stderr_text = ""
    if args.mode == "trace":
        check_trace(verdict, raw, [stdout_text, stderr_text], args)
        return verdict.report()
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        verdict.bad("output is not JSON: %s" % (exc,))
        return verdict.report()
    if not isinstance(doc, dict) or "schema" not in doc:
        verdict.bad("oracle: unrecognized shape (no schema key)")
        return verdict.report()
    if args.mode == "inventory":
        check_inventory(verdict, doc, args)
    else:
        check_profile(verdict, doc, [stdout_text, stderr_text], args)
    return verdict.report()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
