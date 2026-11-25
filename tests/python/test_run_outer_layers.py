# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Strict outer-layer cells for `p11scope run` under default flags.

B1/B2 shapes: pkcs11-tool pointed at OpenSC pkcs11-spy, with the spy
forwarding into p11-kit-proxy (host default config) or into OpenSC.
Ground truth always comes from the SAME run (owner one-run rule): the
spy log (one entry per forwarded call, every entry closed by a
`Returned:` line) plus the tool's own effect (exit code, listed
objects). The report's typed records (`functions[]`, `evidence.*`)
are judged against that ledger; log text never scores.

- RPO-PROXY (`test_rpo_proxy_outer`): exact-or-prefix-gap. The spy
  layer (the tool's own calls) is either counted 1:1 or missed exactly
  on a ledger-ordered prefix of at most the first two calls
  (`C_Initialize`, then `C_GetSlotList`): the spy's table is
  heap-published at the tool's `C_GetInterface` return and attaches
  ~150-250 ms later, while `C_Initialize` fires microseconds after the
  return, so the first call is physically uncatchable without a
  synchronous hold. The gap branch is exact, never tolerant: the
  missed set must equal the ledger prefix exactly, books must balance
  per function, and it still forbids surplus, missing windows, and
  exact claims (one twin per prong); phantoms are a named known issue
  instead (see below). The backend legs and the proxy closure skip
  stay strict-exact as below.
- RPO-OPENSC (`test_rpo_opensc_outer`): exact-or-prefix-gap with the
  same ledger-prefix rule (at most the first two calls). The backend
  legs are exact in both branches, including the adjudicated double
  `C_Finalize`.

Both cells count phantoms under KI-v072-proxy-phantom-inflight
instead of forbidding them: without the in-flight gate (cut from
v0.7.2), v0.7.1's phantom in-flight returns, while the spy log still
proves every call returned. Interface-acquisition (D2) follows the
established precedent:
C_GetFunctionList obeys the ledger-plus-binding rule, while the
C_GetInterface meta-export is evidenced (tuples present, never
silently dropped) rather than count-compared.
"""

import functools
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from collections import Counter
from pathlib import Path


#: Installed mode: set P11SCOPE_OUTER_STRICT=1 on a qualified host to
#: turn prerequisite skips into failures, requiring the live cells to
#: execute. Unset keeps the self-skipping default (CI-safe).
STRICT = os.environ.get("P11SCOPE_OUTER_STRICT") == "1"

SPY_BANNER = "OpenSC PKCS#11 spy"
SPY_ENTRY = re.compile(r"^([0-9]+): (C_[A-Za-z0-9]+)\s*$")
SPY_LOADED = re.compile(r"^Loaded: \"(.*)\"\s*$")
SPY_RETURNED = re.compile(r"^Returned:\s+(-?[0-9a-zA-Z]+)\s+([A-Za-z0-9_]+)\s*$")

#: CKR_CRYPTOKI_NOT_INITIALIZED, the adjudicated real extra Finalize
#: error on the OpenSC backend (trace-ordered before C_Initialize,
#: reproduced bare): pinned exactly, never folded into a generic count.
CKR_NOT_INITIALIZED = 0x190

SPY_CANDIDATES = (
    "/usr/lib64/pkcs11-spy.so",
    "/usr/lib64/pkcs11/pkcs11-spy.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11-spy.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/pkcs11-spy.so",
)
PROXY_CANDIDATES = (
    "/usr/lib64/p11-kit-proxy.so",
    "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",
)
SOFTHSM_CANDIDATES = (
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
)
OPENSC_CANDIDATES = (
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
)


class OuterError(Exception):
    """The cell failed (live) or the input is malformed (twins)."""


class SpyLedger:
    """One parsed spy log: exact per-function counts, error counts, and
    the call sequence in ledger order (for the prefix rule)."""

    def __init__(self, loaded, counts, errors, total, order):
        self.loaded = loaded
        self.counts = counts
        self.errors = errors
        self.total = total
        self.order = order


def parse_spy_log(text):
    """Parse an OpenSC pkcs11-spy log strictly.

    The banner and one `Loaded:` line are required; entries restart at
    0 and rise by exactly 1; every entry closes with a `Returned:`
    line before the next entry starts; nothing but blank lines may
    follow the last return. Any deviation raises OuterError: a
    truncated or malformed log is a harness failure, never a partial
    ledger.
    """
    if not any(SPY_BANNER in line for line in text.splitlines()[0:4]):
        raise OuterError("spy log lacks the OpenSC banner in its first lines")
    loaded = None
    counts, errors = Counter(), Counter()
    order = []
    pending = None
    expect = 0
    total = 0
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        loaded_match = SPY_LOADED.match(line)
        if loaded_match:
            if loaded is not None:
                raise OuterError("spy log carries two Loaded lines (shared log?)")
            loaded = loaded_match.group(1)
            continue
        entry = SPY_ENTRY.match(line)
        if entry:
            if pending is not None:
                raise OuterError(f"spy entry {pending} lacks its Returned line")
            seq = int(entry.group(1))
            if seq != expect:
                raise OuterError(f"spy sequence {seq}, want {expect}")
            pending = entry.group(2)
            counts[pending] += 1
            order.append(pending)
            total += 1
            expect += 1
            continue
        returned = SPY_RETURNED.match(line)
        if returned:
            if pending is None:
                raise OuterError("spy Returned line without an open entry")
            try:
                rv = int(returned.group(1), 0)
            except ValueError:
                raise OuterError(f"spy return value is not an integer: {line!r}")
            if rv != 0:
                errors[pending] += 1
            pending = None
            continue
    if loaded is None:
        raise OuterError("spy log lacks its Loaded line")
    if pending is not None:
        raise OuterError(f"spy log ends with entry {pending} unclosed")
    if total == 0:
        raise OuterError("spy log holds no calls")
    return SpyLedger(loaded, counts, errors, total, order)


def parse_report(text):
    """Parse an observed-profile report strictly (duplicate keys refuse)."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise OuterError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        report = json.loads(text, object_pairs_hook=unique)
    except ValueError as error:
        raise OuterError(f"report is not valid JSON: {error}")
    schema = report.get("schema") or ""
    if not schema.startswith("p11scope/observed-profile/v3"):
        raise OuterError(f"report schema is not observed-profile v3: {schema!r}")
    return report


class LayerView:
    """One module identity's counted rows, keyed by single function name."""

    def __init__(self):
        self.calls = Counter()
        self.errors = Counter()
        self.in_flight = Counter()
        self.rvs = {}


def split_layers(report, backend_sub, spy_sub="pkcs11-spy"):
    """Split counted `functions[]` rows by module identity.

    Returns (backend sha set, spy sha set, backend view, spy view,
    unattributed rows, unknown-name rows). A row counts only when
    `calls` is nonzero; multi-name (aliased) counted rows refuse, since
    an aliased row cannot prove per-function equality.
    """
    modules = report.get("capture", {}).get("modules", [])
    back = {m["sha256"] for m in modules
            if backend_sub in (m.get("path") or "") and m.get("sha256")}
    spy = {m["sha256"] for m in modules
           if spy_sub in (m.get("path") or "") and m.get("sha256")}
    if not back:
        raise OuterError(f"report names no backend matching {backend_sub!r}")
    if not spy:
        raise OuterError("report names no pkcs11-spy module")
    backend, spyview = LayerView(), LayerView()
    unattributed, unknown = [], []
    for row in report.get("functions", []):
        if row.get("calls", 0) <= 0:
            continue
        mod = row.get("module") or {}
        names = row.get("names") or ["unknown"]
        if not mod.get("sha256"):
            unattributed.append((names, row.get("calls")))
            continue
        if names == ["unknown"]:
            unknown.append((mod.get("sha256"), row.get("calls")))
            continue
        if len(names) > 1 or row.get("aliased"):
            raise OuterError(f"aliased counted row cannot prove equality: {names}")
        view = None
        if mod["sha256"] in back:
            view = backend
        elif mod["sha256"] in spy:
            view = spyview
        else:
            continue
        name = names[0]
        view.calls[name] += row.get("calls", 0)
        view.errors[name] += row.get("errors", 0)
        view.in_flight[name] += row.get("in_flight", 0)
        for key, count in (row.get("rv_counts") or {}).items():
            view.rvs.setdefault(name, Counter())[key] += count
    return back, spy, backend, spyview, unattributed, unknown


def gi_acquisition_proven(report, backend_indexes):
    """Whether an interface-selection tuple proves GI acquisition."""
    tuples = ((report.get("evidence", {}).get("interface_selection") or {})
              .get("tuples")) or []
    return any(t.get("module") in backend_indexes and t.get("table_match")
               for t in tuples)


def interface_selection_count(report):
    tuples = ((report.get("evidence", {}).get("interface_selection") or {})
              .get("tuples")) or []
    return sum(t.get("count", 0) for t in tuples)


def discovery_record(report, sub):
    for record in report.get("evidence", {}).get("discovery", []):
        if sub in (record.get("path") or ""):
            return record
    return None


def late_window(record):
    """The record's late_discovery window, or None (bounds must order)."""
    for window in record.get("unobserved_windows") or []:
        if window.get("reason") == "late_discovery":
            if window.get("start_ns", 1) >= window.get("end_ns", 0):
                raise OuterError(f"late_discovery window bounds do not order: {window!r}")
            return window
    return None


def row_in_flight(report):
    """Every (names, module-sha, in_flight) row with nonzero in-flight."""
    found = []
    for row in report.get("functions", []):
        if row.get("in_flight", 0) > 0:
            mod = row.get("module") or {}
            found.append((row.get("names"), mod.get("sha256"), row.get("in_flight")))
    return found


class Verdict:
    def __init__(self, ok, branch, detail):
        self.ok = ok
        self.branch = branch
        self.detail = detail

    def __bool__(self):
        return self.ok


def check_hygiene(report, unattributed, unknown, failures, notes):
    """Loss/attribution/phantom prongs shared by both cells."""
    evidence = report.get("evidence", {})
    if evidence.get("event_loss", 0) != 0:
        failures.append(f"event_loss={evidence.get('event_loss')}, want 0")
    if unattributed:
        failures.append(f"unattributed counted rows: {unattributed!r}")
    if unknown:
        failures.append(f"unknown-name counted rows: {len(unknown)}")
    stuck = row_in_flight(report)
    in_flight_end = evidence.get("in_flight_at_end", 0)
    if in_flight_end != 0 or stuck:
        # KI-v072-proxy-phantom-inflight: without the in-flight gate
        # (cut from v0.7.2), v0.7.1's phantom in-flight returns — the
        # spy log still proves every call returned. Named and counted
        # here, never failed: keyops-truth owns the docs entry.
        notes.append(
            f"phantoms (KI-v072-proxy-phantom-inflight): evidence={in_flight_end} rows={stuck!r}")
    else:
        notes.append("phantoms=0")
    # The live-table-merge class folds to this exact generic row in
    # evidence.skipped[] (the subject never reaches the document; the
    # fold is pinned by
    # live_table_merge_gap_folds_to_the_generic_discovery_row). A
    # tightly-scoped outer run must never file one: any live overflow
    # is a bug signal, and any other discovery gap here is equally
    # unexpected. The message cannot name the subject — the fold hides
    # it — so it names the fold instead.
    folded = [row for row in (evidence.get("skipped") or [])
              if row.get("name") == "discovery subject"
              and row.get("reason") == "discovery unavailable"]
    if folded:
        failures.append(f"folded discovery gap rows (live-overflow class folds here): {folded!r}")
    else:
        notes.append("folded-gaps=0")


def check_gfl_gi(report, ledger, backend, spyview, backend_indexes, failures, notes):
    """Interface-acquisition pair (D2): GFL binding rule plus the
    evidenced-not-counted meta-export rule for C_GetInterface."""
    gfl_back = backend.calls.get("C_GetFunctionList", 0)
    gfl_spy = ledger.counts.get("C_GetFunctionList", 0)
    gfl_obs_spy = spyview.calls.get("C_GetFunctionList", 0)
    acquired = gi_acquisition_proven(report, backend_indexes)
    if not ((gfl_back == 1 or (gfl_back == 0 and acquired))
            and gfl_spy in (0, 1) and gfl_obs_spy == gfl_spy):
        failures.append(
            f"C_GetFunctionList: backend={gfl_back} spy-ledger={gfl_spy} "
            f"spy-observed={gfl_obs_spy} gi-acquisition={acquired}")
    else:
        notes.append(f"gfl: backend={gfl_back} spy={gfl_spy} acquired={acquired}")
    gi_spy = ledger.counts.get("C_GetInterface", 0)
    gi_back = backend.calls.get("C_GetInterface", 0)
    gi_obs_spy = spyview.calls.get("C_GetInterface", 0)
    isel = interface_selection_count(report)
    if not (gi_back in (0, min(1, gi_spy)) and gi_obs_spy == 0
            and (isel > 0 if gi_spy > 0 else isel == 0)):
        failures.append(
            f"C_GetInterface: backend={gi_back} spy-observed={gi_obs_spy} "
            f"spy-ledger={gi_spy} selection-tuples={isel}")
    else:
        notes.append(f"gi: backend={gi_back} spy-ledger={gi_spy} tuples={isel}")


#: Table calls the gap may miss, in ledger order. The spy's table is
#: heap-published at the tool's interface return and attaches after it,
#: so only a leading prefix can precede attach; anything past the first
#: two calls is mid-burst and fails like any other miss.
PREFIX_ALLOW = ("C_Initialize", "C_GetSlotList")


def table_order(ledger):
    return [fn for fn in ledger.order
            if fn not in ("C_GetFunctionList", "C_GetInterface")]


def check_spy_prefix_gap(report, ledger, spyview, failures, notes):
    """Exact-or-prefix-gap verdict core for one spy layer.

    Returns "exact" or "prefix-gap". Exact needs every table function
    1:1 with exact errors. Otherwise the miss must be exactly the
    ledger's leading prefix (at most `C_Initialize` then
    `C_GetSlotList`), books must balance per function, and the full
    honest disclosure must hold (window, PARTIAL, zero in-flight, zero
    loss, no surplus, no unattributed rows). Anything else fails.
    """
    order = table_order(ledger)
    mark = len(failures)
    if order[:2] != list(PREFIX_ALLOW):
        failures.append(f"ledger shape drifted: table order starts {order[:2]!r}")
        return "exact"
    notes.append(f"ledger: total={ledger.total} prefix-ok")
    exact, missed = True, []
    for fn in sorted(set(ledger.counts) | set(spyview.calls)):
        if fn in ("C_GetFunctionList", "C_GetInterface"):
            continue
        want, got = ledger.counts.get(fn, 0), spyview.calls.get(fn, 0)
        wanterr, goterr = ledger.errors.get(fn, 0), spyview.errors.get(fn, 0)
        if want != got or wanterr != goterr:
            exact = False
            if got < want and goterr == wanterr:
                missed.append(fn)
            else:
                failures.append(
                    f"spy {fn}: obs calls={got} errs={goterr}, "
                    f"spy calls={want} errs={wanterr}")
    if exact:
        notes.append("spy: exact")
        return "exact"
    allowed = {frozenset(PREFIX_ALLOW[:1]), frozenset(PREFIX_ALLOW[:2])}
    if frozenset(missed) not in allowed:
        failures.append(f"spy miss is not the ledger prefix: {sorted(missed)!r}")
        return "exact"
    surplus = [fn for fn in sorted(set(ledger.counts) | set(spyview.calls))
               if fn not in ("C_GetFunctionList", "C_GetInterface")
               and spyview.calls.get(fn, 0) > ledger.counts.get(fn, 0)]
    if surplus:
        failures.append(f"gap branch with phantom surplus: {surplus!r}")
    record = discovery_record(report, "pkcs11-spy")
    window = late_window(record) if record is not None else None
    if window is None:
        failures.append("gap branch without a late_discovery window naming the spy")
    else:
        notes.append(f"gap window: [{window['start_ns']},{window['end_ns']}]")
    if report.get("evidence", {}).get("completeness") != "PARTIAL":
        failures.append("gap branch while the report claims completeness="
                        f"{report.get('evidence', {}).get('completeness')!r}")
    if len(failures) == mark:
        return "prefix-gap"
    return "exact"


def proxy_layer_counts(report):
    """Counted proxy-layer calls, keyed by single function name.

    The MUST-FIX signal lives here: `split_layers` drops proxy rows
    (neither backend nor spy), so the outer judges cannot see the
    proxy leg without this count.
    """
    modules = report.get("capture", {}).get("modules", [])
    sha = {m["sha256"] for m in modules
           if "libp11-kit" in (m.get("path") or "") and m.get("sha256")}
    calls = Counter()
    for row in report.get("functions", []):
        if row.get("calls", 0) <= 0:
            continue
        mod = row.get("module") or {}
        names = row.get("names") or ["unknown"]
        if mod.get("sha256") in sha and names != ["unknown"] and len(names) == 1:
            calls[names[0]] += row.get("calls", 0)
    return calls


def check_proxy_live_table(report, failures, notes):
    """MUST-FIX signal leg: a counting proxy run must carry its live table.

    The proxy's function-list return is observed live (linkage
    "live_return" on its discovery record); the merge-cap regression
    dropped exactly that table. With zero counted proxy calls no live
    table can exist (the pre-existing P1 arrival race is the known
    zero-count cause), so the signal is unobservable and the leg only
    names that in notes: failing here would conflate the MUST-FIX
    signal with the arrival race. Judging a zero-count proxy leg stays
    future work (SR-F5); this leg only asserts on counting runs.
    """
    proxy = proxy_layer_counts(report)
    if sum(proxy.values()) == 0:
        notes.append("proxy: 0 counted calls (P1 arrival shape; live signal unobservable)")
        return
    records = [rec for rec in (report.get("evidence", {}).get("discovery") or [])
               if "libp11-kit" in (rec.get("path") or "")]
    tables = [t for rec in records for t in (rec.get("tables") or [])]
    live = [t for t in tables if t.get("linkage") == "live_return"]
    if not live:
        failures.append(
            f"proxy: {sum(proxy.values())} counted calls but no live_return discovery table "
            f"({len(tables)} tables; MUST-FIX signal absent)")
    else:
        notes.append(f"proxy: {len(tables)} tables incl {len(live)} live")


def judge_proxy_common_legs(report, ledger, tool_rc, priv_objects, pub_objects):
    """Tool, backend, and interface legs shared by both proxy judges.

    Returns (failures, notes, backend, spyview, backend_indexes,
    unattributed, unknown). The spy layer itself is judged separately
    (strict-exact vs prefix-gap); everything else is identical.
    """
    failures, notes = [], []
    if tool_rc != 0 or priv_objects != 2 or pub_objects != 2:
        failures.append(
            f"tool effect: rc={tool_rc} priv={priv_objects} pub={pub_objects}, want rc=0 priv=2 pub=2")
    else:
        notes.append("tool: rc=0 objects=2+2")
    notes.append(f"ledger: total={ledger.total}")
    check_proxy_live_table(report, failures, notes)
    _, _, backend, spyview, unattributed, unknown = split_layers(report, "libsofthsm2.so")
    modules = report.get("capture", {}).get("modules", [])
    backend_indexes = {i for i, m in enumerate(modules) if "libsofthsm2.so" in (m.get("path") or "")}
    for fn in sorted(set(ledger.counts) | set(backend.calls)):
        if fn in ("C_GetFunctionList", "C_GetInterface"):
            continue
        want, got = ledger.counts.get(fn, 0), backend.calls.get(fn, 0)
        wanterr, goterr = ledger.errors.get(fn, 0), backend.errors.get(fn, 0)
        if fn == "C_GetSlotList":
            # The proxy enumerates slots for itself on top of the
            # forwarded calls (measured +4 on both hosts): a surplus
            # here is proxy-internal traffic, recorded never pinned,
            # while a deficit or an error mismatch still fails.
            if got < want or goterr != wanterr:
                failures.append(f"backend {fn}: obs={got}/{goterr} spy={want}/{wanterr}")
            else:
                notes.append(f"backend {fn}: obs={got} spy={want} (surplus={got - want})")
        elif want != got or wanterr != goterr:
            failures.append(
                f"backend {fn}: obs calls={got} errs={goterr}, spy calls={want} errs={wanterr}")
    check_gfl_gi(report, ledger, backend, spyview, backend_indexes, failures, notes)
    return failures, notes, backend, spyview, backend_indexes, unattributed, unknown


def judge_proxy_tail(report, failures, notes):
    """Proxy closure skip (shared tail leg). Returns nothing."""
    skips = report.get("evidence", {}).get("modules_skipped") or []
    if not any("libp11-kit" in (s.get("name") or "") and "not counted" in (s.get("reason") or "")
               for s in skips):
        failures.append(f"proxy closure skip missing: {[(s.get('name'), (s.get('reason') or '')[:60]) for s in skips]!r}")
    else:
        notes.append("proxy: closure skip named")


def judge_proxy_outer(report, ledger, tool_rc, priv_objects, pub_objects):
    """Strict-exact verdict for RPO-PROXY (no miss-tolerant branch)."""
    failures, notes, _, spyview, _, unattributed, unknown = judge_proxy_common_legs(
        report, ledger, tool_rc, priv_objects, pub_objects)
    for fn in sorted(set(ledger.counts) | set(spyview.calls)):
        if fn in ("C_GetFunctionList", "C_GetInterface"):
            continue
        want, got = ledger.counts.get(fn, 0), spyview.calls.get(fn, 0)
        wanterr, goterr = ledger.errors.get(fn, 0), spyview.errors.get(fn, 0)
        # The spy forwards 1:1: any miss fails, and any surplus is a
        # phantom count, never proxy traffic (the proxy sits behind it).
        if want != got or wanterr != goterr:
            failures.append(
                f"spy {fn}: obs calls={got} errs={goterr}, spy calls={want} errs={wanterr}")
    if not failures:
        notes.append(f"spy: exact {sum(spyview.calls.values())}/{ledger.total - ledger.counts.get('C_GetInterface', 0) - ledger.counts.get('C_GetFunctionList', 0)}")
    judge_proxy_tail(report, failures, notes)
    check_hygiene(report, unattributed, unknown, failures, notes)
    detail = "; ".join(notes + (["FAIL: " + " | ".join(failures)] if failures else []))
    return Verdict(not failures, "exact", detail)


def judge_proxy_outer_prefix_gap(report, ledger, tool_rc, priv_objects, pub_objects):
    """Exact-or-prefix-gap verdict for RPO-PROXY.

    Same legs as the strict judge, except the spy layer uses the
    prefix-gap core: exact when every forwarded call is counted,
    otherwise green only for exactly the ledger's leading prefix with
    its full typed disclosure (books balanced, window, PARTIAL, zero
    in-flight, zero loss, no surplus).
    """
    failures, notes, _, spyview, _, unattributed, unknown = judge_proxy_common_legs(
        report, ledger, tool_rc, priv_objects, pub_objects)
    branch = check_spy_prefix_gap(report, ledger, spyview, failures, notes)
    judge_proxy_tail(report, failures, notes)
    check_hygiene(report, unattributed, unknown, failures, notes)
    detail = "; ".join(notes + (["FAIL: " + " | ".join(failures)] if failures else []))
    if failures:
        branch = "exact"
    elif branch == "prefix-gap":
        missed = sorted(fn for fn in ledger.counts
                        if fn not in ("C_GetFunctionList", "C_GetInterface")
                        and spyview.calls.get(fn, 0) < ledger.counts.get(fn, 0))
        detail += f"; missed-before-attach (ledger-exact): {missed!r}"
    return Verdict(not failures, branch, detail)


OPENSC_LEDGER_SET = {"C_GetInterface": 1, "C_Initialize": 1, "C_GetSlotList": 1, "C_Finalize": 1}


def judge_opensc_outer(report, ledger, tool_rc, tool_out):
    """Exact-or-prefix-gap verdict for RPO-OPENSC.

    The backend legs are exact in both branches. The spy layer passes
    exact when every forwarded call is counted, else passes as a
    prefix gap only for exactly the ledger's leading prefix with its
    full typed disclosure (books balanced, window, PARTIAL, zero
    in-flight, zero loss, no surplus). Anything else fails.
    """
    failures, notes = [], []
    if tool_rc != 1 or "Available slots:" not in tool_out:
        failures.append(f"tool effect: rc={tool_rc}, want rc=1 with an empty slot list")
    else:
        notes.append("tool: rc=1 empty slots")
    if dict(ledger.counts) != OPENSC_LEDGER_SET or any(ledger.errors.values()):
        failures.append(
            f"ledger shape: {dict(ledger.counts)} errs={dict(ledger.errors)}, want {OPENSC_LEDGER_SET} clean")
        return Verdict(False, "exact", "FAIL: " + " | ".join(failures))
    notes.append("ledger: 4 clean calls")
    _, _, backend, spyview, unattributed, unknown = split_layers(report, "opensc-pkcs11.so")
    modules = report.get("capture", {}).get("modules", [])
    backend_indexes = {i for i, m in enumerate(modules) if "opensc-pkcs11.so" in (m.get("path") or "")}
    # Backend: exact, both branches. The double Finalize (one OK, one
    # CKR_CRYPTOKI_NOT_INITIALIZED ordered before Initialize) is real
    # tool/provider behavior reproduced bare, pinned exactly.
    if backend.calls.get("C_Initialize", 0) != 1 or backend.errors.get("C_Initialize", 0) != 0:
        failures.append(f"backend Initialize: {backend.calls.get('C_Initialize', 0)}/"
                        f"{backend.errors.get('C_Initialize', 0)}, want 1/0")
    if backend.calls.get("C_GetSlotList", 0) != 1 or backend.errors.get("C_GetSlotList", 0) != 0:
        failures.append("backend SlotList is not 1/0")
    fin_calls, fin_errs = backend.calls.get("C_Finalize", 0), backend.errors.get("C_Finalize", 0)
    fin_rvs = (backend.rvs.get("C_Finalize") or Counter())
    if fin_calls != 2 or fin_errs != 1 or fin_rvs.get(f"0x{CKR_NOT_INITIALIZED:016x}", 0) != 1:
        failures.append(
            f"backend Finalize: calls={fin_calls} errs={fin_errs} rvs={dict(fin_rvs)}, want 2/1/not-initialized")
    else:
        notes.append("backend: Init/SlotList exact, adjudicated double Finalize")
    check_gfl_gi(report, ledger, backend, spyview, backend_indexes, failures, notes)
    branch = check_spy_prefix_gap(report, ledger, spyview, failures, notes)
    check_hygiene(report, unattributed, unknown, failures, notes)
    detail = "; ".join(notes + (["FAIL: " + " | ".join(failures)] if failures else []))
    if failures:
        branch = "exact"
    elif branch == "prefix-gap":
        missed = sorted(fn for fn in ledger.counts
                        if fn not in ("C_GetFunctionList", "C_GetInterface")
                        and spyview.calls.get(fn, 0) < ledger.counts.get(fn, 0))
        detail += f"; missed-before-attach (ledger-exact): {missed!r}"
    return Verdict(not failures, branch, detail)


def probe_first(candidates):
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


class Prereqs:
    def __init__(self):
        self.binary = os.environ.get("P11SCOPE_BIN")
        if not self.binary or not os.access(self.binary, os.X_OK):
            raise OuterError("P11SCOPE_BIN is not set to an executable observer binary")
        try:
            subprocess.run(["sudo", "-n", "true"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, OSError):
            raise OuterError("passwordless sudo is required")
        for tool in ("pkcs11-tool", "softhsm2-util", "openssl"):
            if shutil.which(tool) is None:
                raise OuterError(f"tool missing: {tool}")
        self.spy = probe_first(SPY_CANDIDATES)
        self.proxy = probe_first(PROXY_CANDIDATES)
        self.softhsm = probe_first(SOFTHSM_CANDIDATES)
        self.opensc = probe_first(OPENSC_CANDIDATES)
        if self.spy is None:
            raise OuterError("pkcs11-spy.so not found")
        if self.proxy is None:
            raise OuterError("p11-kit-proxy.so not found")
        if self.softhsm is None:
            raise OuterError("libsofthsm2.so not found")
        if self.opensc is None:
            raise OuterError("opensc-pkcs11.so not found")
        # Default (system) p11-kit config must register SoftHSM: a live
        # `p11-kit list-modules` cannot prove it, since SoftHSM shows no
        # tokens without our per-test SOFTHSM2_CONF. A system .module file
        # naming the probed SoftHSM file is the registration proof.
        registered = False
        for path in (glob.glob("/usr/share/p11-kit/modules/*.module")
                     + glob.glob("/etc/pkcs11/modules/*.module")):
            try:
                text = Path(path).read_text()
            except OSError:
                continue
            if self.softhsm in text and "enabled: no" not in text:
                registered = True
        if not registered:
            raise OuterError("default p11-kit config does not route SoftHSM")


def gate(test):
    """Skip unless every live prerequisite holds (strict mode fails)."""

    @functools.wraps(test)
    def wrapper(self):
        try:
            prereqs = Prereqs()
        except OuterError as exc:
            if STRICT:
                raise AssertionError(f"strict mode requires this cell: {exc}") from exc
            self.skipTest(f"outer-layer gate prerequisite missing: {exc}")
        return test(self, prereqs)

    return wrapper


def make_soft_token(workdir, pin="1234", label="rpo-outer"):
    """A private SoftHSM token with one RSA + one EC key (2+2 objects)."""
    tokendir = Path(workdir) / "soft-rpo"
    if tokendir.exists():
        shutil.rmtree(tokendir)
    (tokendir := tokendir / "tokens").mkdir(parents=True)
    conf = tokendir.parent / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tokendir}\nobjectstore.backend = file\n")
    env = dict(os.environ, SOFTHSM2_CONF=str(conf))
    subprocess.run(["softhsm2-util", "--init-token", "--slot", "0", "--label", label,
                    "--pin", pin, "--so-pin", pin],
                   check=True, capture_output=True, env=env)
    rsa, ec = tokendir.parent / "rsa.pem", tokendir.parent / "ec.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                    "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(rsa)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC",
                    "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(ec)],
                   check=True, capture_output=True)
    subprocess.run(["softhsm2-util", "--import", str(rsa), "--token", label,
                    "--label", "sig-rsa", "--id", "0001", "--pin", pin],
                   check=True, capture_output=True, env=env)
    subprocess.run(["softhsm2-util", "--import", str(ec), "--token", label,
                    "--label", "sig-ec", "--id", "0002", "--pin", pin],
                   check=True, capture_output=True, env=env)
    return conf, label


def run_observer(prereqs, workdir, env_extra, tool_argv):
    """One `p11scope run` (default flags) under sudo; returns artifacts."""
    rundir = Path(workdir)
    report, spylog, toolout = rundir / "report.json", rundir / "spy.log", rundir / "tool.out"
    for path in (report, spylog):
        if path.exists():
            path.unlink()
    env = [f"SOFTHSM2_CONF={env_extra['SOFTHSM2_CONF']}"] if "SOFTHSM2_CONF" in env_extra else []
    env += [f"PKCS11SPY={env_extra['PKCS11SPY']}", f"PKCS11SPY_OUTPUT={spylog}"]
    cmd = ["sudo", "-n", *env, prereqs.binary, "run", "-o", str(report), "--", *tool_argv]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
    toolout.write_text(proc.stdout)
    (rundir / "tool.err").write_text(proc.stderr)
    return proc.returncode, proc.stdout, parse_report(report.read_text()), \
        parse_spy_log(spylog.read_text())


class LiveOuterCells(unittest.TestCase):
    """The two live cells (self-skipping without the gate prerequisites)."""

    @gate
    def test_rpo_proxy_outer(self, prereqs):
        workdir = tempfile.mkdtemp(prefix="rpo-proxy-")
        conf, label = make_soft_token(workdir)
        print(f"\nRPO-PROXY artifacts: {workdir}")
        rc, out, report, ledger = run_observer(
            prereqs, workdir,
            {"SOFTHSM2_CONF": str(conf), "PKCS11SPY": prereqs.proxy},
            ["pkcs11-tool", "--module", prereqs.spy, "--list-objects",
             "--token-label", label, "--login", "--pin", "1234"])
        priv = out.count("Private Key Object")
        pub = out.count("Public Key Object")
        verdict = judge_proxy_outer_prefix_gap(report, ledger, rc, priv, pub)
        print(f"RPO-PROXY branch={verdict.branch}: {verdict.detail}")
        self.assertTrue(verdict, f"{verdict.detail}\nartifacts: {workdir}")

    @gate
    def test_rpo_opensc_outer(self, prereqs):
        workdir = tempfile.mkdtemp(prefix="rpo-opensc-")
        print(f"\nRPO-OPENSC artifacts: {workdir}")
        rc, out, report, ledger = run_observer(
            prereqs, workdir, {"PKCS11SPY": prereqs.opensc},
            ["pkcs11-tool", "--module", prereqs.spy, "-L", "--list-objects"])
        verdict = judge_opensc_outer(report, ledger, rc, out)
        print(f"RPO-OPENSC branch={verdict.branch}: {verdict.detail}")
        self.assertTrue(verdict, f"{verdict.detail}\nartifacts: {workdir}")


def spy_text(entries, loaded="/real/provider.so"):
    """Render a minimal strict spy log for `entries` = [(name, rv)]."""
    lines = ["", "", "", "*************** OpenSC PKCS#11 spy *****************",
             f'Loaded: "{loaded}"', ""]
    for seq, (name, rv) in enumerate(entries):
        lines += [f"{seq}: {name}",
                  f"P:1234; T:0xabc 2026-11-24 15:00:{seq:02d}.000",
                  f"Returned:  {rv} {'CKR_OK' if rv == 0 else 'CKR_ERR'}", ""]
    return "\n".join(lines)


BACKEND_SHA = "b" * 64
SPY_SHA = "s" * 64
PROXY_SHA = "p" * 64


def function_row(name, sha, calls, errors=0, in_flight=0, rvs=None, offset=4096):
    return {"names": [name], "calls": calls, "errors": errors, "in_flight": in_flight,
            "pending_returns": 0, "aliased": False,
            "module": {"dev": [0, 35], "ino": 7, "sha256": sha},
            "module_ambiguous": False, "module_unresolved": False,
            "target": {"object": {"dev": [0, 35], "ino": 7, "sha256": sha},
                       "file_offset": offset},
            "rv_counts": rvs or {}}


def twin_report(backend_rows, spy_rows, discovery, skips=(), completeness="PARTIAL",
                in_flight=0, loss=0, tuples=(), backend_path="/m/libsofthsm2.so"):
    modules = [{"path": backend_path, "sha256": BACKEND_SHA},
               {"path": "/m/pkcs11-spy.so", "sha256": SPY_SHA}]
    return {"schema": "p11scope/observed-profile/v3",
            "capture": {"modules": modules},
            "functions": backend_rows + spy_rows,
            "evidence": {"completeness": completeness, "event_loss": loss,
                         "in_flight_at_end": in_flight, "discovery": discovery,
                         "modules_skipped": list(skips),
                         "interface_selection": {"tuples": list(tuples)}}}


def twin_discovery(path, tables=1, window=True):
    record = {"path": path, "tables": [{}] * tables}
    if window:
        record["unobserved_windows"] = [{"reason": "late_discovery",
                                         "start_ns": 100, "end_ns": 500}]
    return record


def proxy_fixture(mutate=None):
    """A passing RPO-PROXY (ledger, report): `mutate` breaks one prong."""
    ledger = parse_spy_log(spy_text([("C_GetInterface", 0), ("C_Initialize", 0),
                                     ("C_GetSlotList", 0), ("C_Login", 0),
                                     ("C_GetAttributeValue", 0), ("C_GetAttributeValue", 6)]))
    backend_rows = [function_row("C_Initialize", BACKEND_SHA, 1),
                    function_row("C_GetSlotList", BACKEND_SHA, 5),
                    function_row("C_Login", BACKEND_SHA, 1),
                    function_row("C_GetAttributeValue", BACKEND_SHA, 2, errors=1),
                    function_row("C_GetFunctionList", BACKEND_SHA, 1)]
    spy_rows = [function_row("C_Initialize", SPY_SHA, 1),
                function_row("C_GetSlotList", SPY_SHA, 1),
                function_row("C_Login", SPY_SHA, 1),
                function_row("C_GetAttributeValue", SPY_SHA, 2, errors=1)]
    discovery = [twin_discovery("/m/libsofthsm2.so"), twin_discovery("/m/pkcs11-spy.so")]
    skips = [{"name": "/usr/lib64/libp11-kit.so.0", "reason":
              "a proxy closure array in a detailed capture attaches only its published tables, "
              "and none of its 64 lookalike function tables is published yet, so calls "
              "through it are not counted (a proxy closure array is admitted whole)"}]
    report = twin_report(backend_rows, spy_rows, discovery, skips=skips,
                         tuples=[{"module": 0, "count": 1, "table_match": False}])
    if mutate:
        mutate(report, ledger)
    return ledger, report


def opensc_fixture(mutate=None):
    """A passing exact RPO-OPENSC (ledger, report)."""
    ledger = parse_spy_log(spy_text([("C_GetInterface", 0), ("C_Initialize", 0),
                                     ("C_GetSlotList", 0), ("C_Finalize", 0)]))
    backend_rows = [function_row("C_Initialize", BACKEND_SHA, 1),
                    function_row("C_GetSlotList", BACKEND_SHA, 1),
                    function_row("C_Finalize", BACKEND_SHA, 2, errors=1,
                                 rvs={f"0x{CKR_NOT_INITIALIZED:016x}": 1,
                                      "0x0000000000000000": 1}),
                    function_row("C_GetInterface", BACKEND_SHA, 1)]
    spy_rows = [function_row("C_Initialize", SPY_SHA, 1),
                function_row("C_GetSlotList", SPY_SHA, 1),
                function_row("C_Finalize", SPY_SHA, 1)]
    discovery = [twin_discovery("/m/opensc-pkcs11.so"), twin_discovery("/m/pkcs11-spy.so")]
    report = twin_report(backend_rows, spy_rows, discovery,
                         tuples=[{"module": 0, "count": 1, "table_match": True}],
                         backend_path="/m/opensc-pkcs11.so")
    if mutate:
        mutate(report, ledger)
    return ledger, report


class SpyParserTwins(unittest.TestCase):
    def test_clean_log_parses_exactly(self):
        ledger = parse_spy_log(spy_text([("C_Initialize", 0), ("C_Login", 431)]))
        self.assertEqual(dict(ledger.counts), {"C_Initialize": 1, "C_Login": 1})
        self.assertEqual(dict(ledger.errors), {"C_Login": 1})
        self.assertEqual(ledger.total, 2)

    def test_truncated_entry_refuses(self):
        with self.assertRaises(OuterError):
            parse_spy_log(spy_text([("C_Initialize", 0)]) + "\n1: C_Login\n")

    def test_unclosed_entry_before_next_refuses(self):
        # The Login entry never closes: the next entry must refuse even
        # though a later return would close the log cleanly (isolates the
        # entry check from the end-of-log backstop).
        text = spy_text([("C_Initialize", 0)])
        text += "\n1: C_Login\n2: C_Initialize\nReturned:  0 CKR_OK\n"
        with self.assertRaises(OuterError):
            parse_spy_log(text)

    def test_skipped_sequence_refuses(self):
        text = spy_text([("C_Initialize", 0), ("C_Login", 0)]).replace("\n1: C_Login", "\n2: C_Login")
        with self.assertRaises(OuterError):
            parse_spy_log(text)

    def test_missing_banner_refuses(self):
        with self.assertRaises(OuterError):
            parse_spy_log('Loaded: "/x.so"\n0: C_Initialize\nReturned:  0 CKR_OK\n')

    def test_missing_loaded_refuses(self):
        text = "\n".join(line for line in spy_text([("C_Initialize", 0)]).splitlines()
                        if not line.startswith("Loaded:"))
        with self.assertRaises(OuterError):
            parse_spy_log(text)

    def test_empty_log_refuses(self):
        with self.assertRaises(OuterError):
            parse_spy_log("*************** OpenSC PKCS#11 spy *****************\n")

    def test_loaded_without_calls_refuses(self):
        with self.assertRaises(OuterError):
            parse_spy_log("*************** OpenSC PKCS#11 spy *****************\n"
                          'Loaded: "/x.so"\n')


class ProxyJudgeTwins(unittest.TestCase):
    def verdict(self, mutate=None):
        ledger, report = proxy_fixture(mutate)
        return judge_proxy_outer(report, ledger, 0, 2, 2)

    def test_exact_shape_passes(self):
        verdict = self.verdict()
        self.assertTrue(verdict, verdict.detail)
        self.assertEqual(verdict.branch, "exact")

    def test_spy_deficit_fails(self):
        def drop(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Login"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("spy C_Login", verdict.detail)

    def test_spy_surplus_fails(self):
        def bump(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_Login"] and (row["module"] or {}).get("sha256") == SPY_SHA:
                    row["calls"] += 1
        verdict = self.verdict(bump)
        self.assertFalse(verdict, verdict.detail)

    def test_spy_error_mismatch_fails(self):
        def bump(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_Login"] and (row["module"] or {}).get("sha256") == SPY_SHA:
                    row["errors"] += 1
        verdict = self.verdict(bump)
        self.assertFalse(verdict, verdict.detail)

    def test_backend_deficit_fails(self):
        def drop(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_Login"] and (row["module"] or {}).get("sha256") == BACKEND_SHA:
                    row["calls"] -= 1
        verdict = self.verdict(drop)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("backend C_Login", verdict.detail)

    def test_backend_slotlist_surplus_passes_but_deficit_fails(self):
        self.assertTrue(self.verdict(), self.verdict().detail)

        def drop(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_GetSlotList"] and (row["module"] or {}).get("sha256") == BACKEND_SHA:
                    row["calls"] = 0
        verdict = self.verdict(drop)
        self.assertFalse(verdict, verdict.detail)

    def test_backend_other_surplus_fails(self):
        def bump(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_Login"] and (row["module"] or {}).get("sha256") == BACKEND_SHA:
                    row["calls"] += 1
        verdict = self.verdict(bump)
        self.assertFalse(verdict, verdict.detail)

    def test_missing_proxy_skip_fails(self):
        verdict = self.verdict(lambda report, _ledger: report["evidence"].__setitem__("modules_skipped", []))
        self.assertFalse(verdict, verdict.detail)

    def test_phantom_in_flight_is_a_named_known_issue(self):
        def stuck(report, _ledger):
            # A completed call that is also in flight (entered twice,
            # returned once: the double-seen shape): counts stay exact so
            # only the phantom prong can observe this.
            report["evidence"]["in_flight_at_end"] = 1
            for row in report["functions"]:
                if row["names"] == ["C_Login"] and (row["module"] or {}).get("sha256") == SPY_SHA:
                    row["in_flight"] = 1
        verdict = self.verdict(stuck)
        self.assertTrue(verdict, verdict.detail)
        self.assertIn("KI-v072-proxy-phantom-inflight", verdict.detail)
        self.assertIn("evidence=1", verdict.detail)
        self.assertIn("C_Login", verdict.detail)

    def test_event_loss_fails(self):
        verdict = self.verdict(lambda report, _ledger: report["evidence"].__setitem__("event_loss", 1))
        self.assertFalse(verdict, verdict.detail)

    def test_unattributed_counted_fails(self):
        def orphan(report, _ledger):
            report["functions"].append(function_row("C_Login", BACKEND_SHA, 1))
            report["functions"][-1]["module"] = None
        verdict = self.verdict(orphan)
        self.assertFalse(verdict, verdict.detail)

    def test_unknown_counted_fails(self):
        def anon(report, _ledger):
            row = function_row("C_Login", BACKEND_SHA, 1)
            row["names"] = ["unknown"]
            report["functions"].append(row)
        verdict = self.verdict(anon)
        self.assertFalse(verdict, verdict.detail)

    def test_aliased_counted_refuses(self):
        def alias(report, _ledger):
            row = function_row("C_Login", BACKEND_SHA, 1)
            row["names"] = ["C_Login", "C_Login"]
            row["aliased"] = True
            report["functions"].append(row)
        ledger, report = proxy_fixture(alias)
        with self.assertRaises(OuterError):
            judge_proxy_outer(report, ledger, 0, 2, 2)

    def test_missing_backend_module_refuses(self):
        ledger, report = proxy_fixture()
        report["capture"]["modules"] = [m for m in report["capture"]["modules"]
                                        if "libsofthsm2" not in m["path"]]
        with self.assertRaises(OuterError):
            judge_proxy_outer(report, ledger, 0, 2, 2)

    def test_missing_spy_module_refuses(self):
        ledger, report = proxy_fixture()
        report["capture"]["modules"] = [m for m in report["capture"]["modules"]
                                        if "pkcs11-spy" not in m["path"]]
        with self.assertRaises(OuterError):
            judge_proxy_outer(report, ledger, 0, 2, 2)

    def test_tool_effect_mismatch_fails(self):
        ledger, report = proxy_fixture()
        verdict = judge_proxy_outer(report, ledger, 0, 2, 1)
        self.assertFalse(verdict, verdict.detail)

    def test_selection_tuples_required_with_gi(self):
        verdict = self.verdict(lambda report, _ledger: report["evidence"].__setitem__(
            "interface_selection", {"tuples": []}))
        self.assertFalse(verdict, verdict.detail)

    def test_gfl_backend_zero_without_acquisition_fails(self):
        def zero(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_GetFunctionList"]:
                    row["calls"] = 0
        verdict = self.verdict(zero)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("C_GetFunctionList", verdict.detail)

    def test_gfl_backend_zero_with_acquisition_passes(self):
        def zero_and_prove(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_GetFunctionList"]:
                    row["calls"] = 0
            report["evidence"]["interface_selection"]["tuples"][0]["table_match"] = True
        verdict = self.verdict(zero_and_prove)
        self.assertTrue(verdict, verdict.detail)

    def test_gfl_spy_mismatch_fails(self):
        def add_spy_gfl(report, _ledger):
            report["functions"].append(function_row("C_GetFunctionList", SPY_SHA, 1))
        verdict = self.verdict(add_spy_gfl)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("C_GetFunctionList", verdict.detail)

    def test_gi_backend_two_fails(self):
        def add_backend_gi(report, _ledger):
            report["functions"].append(function_row("C_GetInterface", BACKEND_SHA, 2))
        verdict = self.verdict(add_backend_gi)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("C_GetInterface", verdict.detail)

    def test_gi_spy_observed_fails(self):
        def add_spy_gi(report, _ledger):
            report["functions"].append(function_row("C_GetInterface", SPY_SHA, 1))
        verdict = self.verdict(add_spy_gi)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("C_GetInterface", verdict.detail)

    def test_gi_tuples_forbidden_without_ledger(self):
        ledger = parse_spy_log(spy_text([("C_Initialize", 0)]))
        _, report = proxy_fixture()
        verdict = judge_proxy_outer(report, ledger, 0, 2, 2)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("C_GetInterface", verdict.detail)

    def test_gfl_ledger_two_fails(self):
        # The fixture ledger plus two GFLs, both observed on the spy
        # layer: every other leg stays exact, so only the 0/1 range
        # clause can fail this.
        ledger = parse_spy_log(spy_text([("C_GetInterface", 0), ("C_Initialize", 0),
                                         ("C_GetSlotList", 0), ("C_Login", 0),
                                         ("C_GetAttributeValue", 0), ("C_GetAttributeValue", 6),
                                         ("C_GetFunctionList", 0), ("C_GetFunctionList", 0)]))
        _, report = proxy_fixture()
        report["functions"].append(function_row("C_GetFunctionList", SPY_SHA, 2))
        verdict = judge_proxy_outer(report, ledger, 0, 2, 2)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("C_GetFunctionList", verdict.detail)

    def test_report_schema_must_be_v3(self):
        with self.assertRaises(OuterError):
            parse_report('{"schema": "p11scope/observed-profile/v1"}')

    def test_report_duplicate_key_refuses(self):
        # Duplicate non-schema key: only the duplicate check can refuse
        # this (the schema itself stays valid).
        with self.assertRaises(OuterError):
            parse_report('{"schema": "p11scope/observed-profile/v3", "a": 1, "a": 2}')


def proxy_live_fixture(live=True, counted=True):
    """proxy_fixture plus a proxy module, proxy rows, and a proxy record.

    `live` controls whether the proxy discovery record carries a
    live_return table; `counted` controls whether any proxy row counts.
    """
    ledger, report = proxy_fixture()
    report["capture"]["modules"].append({"path": "/m/libp11-kit.so.0", "sha256": PROXY_SHA})
    if counted:
        report["functions"].extend([
            function_row("C_Initialize", PROXY_SHA, 1),
            function_row("C_GetSlotList", PROXY_SHA, 1),
        ])
    tables = [{"linkage": "heuristic", "version": "3.1"}]
    if live:
        tables.append({"linkage": "live_return", "version": "3.1"})
    report["evidence"]["discovery"].append({"path": "/m/libp11-kit.so.0", "tables": tables})
    return ledger, report


class ProxyLiveSignalTwins(unittest.TestCase):
    def test_counting_proxy_with_live_table_passes_with_signal_note(self):
        ledger, report = proxy_live_fixture(live=True, counted=True)
        verdict = judge_proxy_outer(report, ledger, 0, 2, 2)
        self.assertTrue(verdict, verdict.detail)
        self.assertIn("tables incl 1 live", verdict.detail)

    def test_counting_proxy_without_live_table_fails_must_fix(self):
        ledger, report = proxy_live_fixture(live=False, counted=True)
        verdict = judge_proxy_outer(report, ledger, 0, 2, 2)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("MUST-FIX signal absent", verdict.detail)

    def test_zero_proxy_p1_shape_names_unobservable_signal(self):
        ledger, report = proxy_live_fixture(live=False, counted=False)
        verdict = judge_proxy_outer(report, ledger, 0, 2, 2)
        self.assertTrue(verdict, verdict.detail)
        self.assertIn("P1 arrival shape", verdict.detail)
        self.assertNotIn("MUST-FIX signal absent", verdict.detail)

    def test_prefix_gap_judge_sees_the_live_signal_too(self):
        ledger, report = proxy_live_fixture(live=True, counted=True)
        verdict = judge_proxy_outer_prefix_gap(report, ledger, 0, 2, 2)
        self.assertTrue(verdict, verdict.detail)
        self.assertIn("tables incl 1 live", verdict.detail)


FOLDED_GAP_ROW = {"name": "discovery subject", "reason": "discovery unavailable"}


class FoldedGapTwins(unittest.TestCase):
    def test_folded_discovery_gap_fails(self):
        def gap(report, _ledger):
            report["evidence"]["skipped"] = [dict(FOLDED_GAP_ROW)]
        ledger, report = proxy_fixture(gap)
        verdict = judge_proxy_outer(report, ledger, 0, 2, 2)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("folded discovery gap", verdict.detail)

    def test_zero_proxy_with_folded_gap_fails(self):
        # The 0/109 MF-1 signature with its gap: the live leg notes
        # P1, the gap leg fails.
        ledger, report = proxy_live_fixture(live=False, counted=False)
        report["evidence"]["skipped"] = [dict(FOLDED_GAP_ROW)]
        verdict = judge_proxy_outer(report, ledger, 0, 2, 2)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("folded discovery gap", verdict.detail)

    def test_folded_discovery_gap_fails_opensc(self):
        ledger, report = opensc_fixture()
        report["evidence"]["skipped"] = [dict(FOLDED_GAP_ROW)]
        verdict = judge_opensc_outer(report, ledger, 1, "Available slots:\n")
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("folded discovery gap", verdict.detail)

    def test_unrelated_skip_rows_still_pass(self):
        # Null-pointer function rows (present in every real run) are
        # not folded discovery gaps.
        def gap(report, _ledger):
            report["evidence"]["skipped"] = [
                {"name": "C_AsyncComplete", "reason": "null pointer"}]
        ledger, report = proxy_fixture(gap)
        verdict = judge_proxy_outer(report, ledger, 0, 2, 2)
        self.assertTrue(verdict, verdict.detail)
        self.assertIn("folded-gaps=0", verdict.detail)


class ProxyPrefixGapTwins(unittest.TestCase):
    def verdict(self, mutate=None):
        ledger, report = proxy_fixture(mutate)
        return judge_proxy_outer_prefix_gap(report, ledger, 0, 2, 2)

    def test_exact_shape_passes_exact(self):
        verdict = self.verdict()
        self.assertTrue(verdict, verdict.detail)
        self.assertEqual(verdict.branch, "exact")

    def test_init_only_miss_passes_prefix_gap(self):
        def drop_init(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_init)
        self.assertTrue(verdict, verdict.detail)
        self.assertEqual(verdict.branch, "prefix-gap")
        self.assertIn("C_Initialize", verdict.detail)

    def test_init_slotlist_miss_passes_prefix_gap(self):
        def drop_prefix(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] in (["C_Initialize"], ["C_GetSlotList"])
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_prefix)
        self.assertTrue(verdict, verdict.detail)
        self.assertEqual(verdict.branch, "prefix-gap")

    def test_prefix_allow_pins_the_two_call_prefix(self):
        # The gap's upper edge lives in PREFIX_ALLOW and the judge
        # derives its accepted sets from it: widening the constant
        # must fail here, not silently widen the gap.
        self.assertEqual(PREFIX_ALLOW, ("C_Initialize", "C_GetSlotList"))

    def test_three_deep_leading_miss_rejected(self):
        # K<=2 is the whole gap: a 3-deep leading miss (Init,
        # SlotList, Login) is mid-burst, not a prefix gap.
        def drop_three(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] in (["C_Initialize"], ["C_GetSlotList"],
                                                          ["C_Login"])
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_three)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("prefix", verdict.detail)

    def test_mid_miss_rejected(self):
        def drop_login(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Login"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_login)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("prefix", verdict.detail)

    def test_slotlist_only_miss_rejected(self):
        def drop_slotlist(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_GetSlotList"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_slotlist)
        self.assertFalse(verdict, verdict.detail)

    def test_prefix_gap_tolerates_phantom_as_known_issue(self):
        def drop_and_stick(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
            report["evidence"]["in_flight_at_end"] = 1
        verdict = self.verdict(drop_and_stick)
        self.assertTrue(verdict, verdict.detail)
        self.assertEqual(verdict.branch, "prefix-gap")
        self.assertIn("KI-v072-proxy-phantom-inflight", verdict.detail)
        self.assertIn("evidence=1", verdict.detail)

    def test_prefix_gap_rejects_total_miss(self):
        def drop_all_spy(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if (r["module"] or {}).get("sha256") != SPY_SHA]
        verdict = self.verdict(drop_all_spy)
        self.assertFalse(verdict, verdict.detail)


class OpenscJudgeTwins(unittest.TestCase):
    def verdict(self, mutate=None, rc=1, out="Available slots:\n"):
        ledger, report = opensc_fixture(mutate)
        return judge_opensc_outer(report, ledger, rc, out)

    def test_exact_shape_passes(self):
        verdict = self.verdict()
        self.assertTrue(verdict, verdict.detail)
        self.assertEqual(verdict.branch, "exact")

    def test_honest_gap_passes_with_its_note(self):
        def drop_init(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_init)
        self.assertTrue(verdict, verdict.detail)
        self.assertEqual(verdict.branch, "prefix-gap")
        self.assertIn("C_Initialize", verdict.detail)

    def test_gap_allows_init_slotlist_prefix(self):
        def drop_prefix(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] in (["C_Initialize"], ["C_GetSlotList"])
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_prefix)
        self.assertTrue(verdict, verdict.detail)
        self.assertEqual(verdict.branch, "prefix-gap")

    def test_three_deep_leading_miss_rejected(self):
        # The opensc ledger holds 3 table calls (Init, SlotList,
        # Finalize): missing all three is a total miss, never a
        # 2-deep prefix gap.
        def drop_three(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] in (["C_Initialize"], ["C_GetSlotList"],
                                                          ["C_Finalize"])
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_three)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("prefix", verdict.detail)

    def test_gap_rejects_non_init_miss(self):
        def drop_slotlist(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_GetSlotList"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
        verdict = self.verdict(drop_slotlist)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("prefix", verdict.detail)

    def test_gap_rejects_order_drift(self):
        # Ledger puts SlotList before Initialize (tool drift): the
        # prefix rule keys on ledger order, so drift fails loudly
        # instead of silently redefining the prefix.
        ledger = parse_spy_log(spy_text([("C_GetInterface", 0), ("C_GetSlotList", 0),
                                         ("C_Initialize", 0), ("C_Finalize", 0)]))
        _, report = opensc_fixture()
        verdict = judge_opensc_outer(report, ledger, 1, "Available slots:\n")
        self.assertFalse(verdict, verdict.detail)

    def test_gap_without_window_fails(self):
        def drop_both(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
            for record in report["evidence"]["discovery"]:
                record.pop("unobserved_windows", None)
        verdict = self.verdict(drop_both)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("window", verdict.detail)

    def test_gap_with_surplus_fails(self):
        def drop_and_bump(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
            for row in report["functions"]:
                if row["names"] == ["C_Finalize"] and (row["module"] or {}).get("sha256") == SPY_SHA:
                    row["calls"] += 1
        verdict = self.verdict(drop_and_bump)
        self.assertFalse(verdict, verdict.detail)
        self.assertIn("surplus", verdict.detail)

    def test_gap_with_phantom_is_a_named_known_issue(self):
        def drop_and_stick(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
            report["evidence"]["in_flight_at_end"] = 1
        verdict = self.verdict(drop_and_stick)
        self.assertTrue(verdict, verdict.detail)
        self.assertIn("KI-v072-proxy-phantom-inflight", verdict.detail)
        self.assertIn("evidence=1", verdict.detail)

    def test_gap_with_complete_claim_fails(self):
        def drop_and_claim(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
            report["evidence"]["completeness"] = "COMPLETE"
        verdict = self.verdict(drop_and_claim)
        self.assertFalse(verdict, verdict.detail)

    def test_backend_must_stay_exact_in_gap(self):
        def drop_both(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] in (["C_Initialize"],)
                                           and (r["module"] or {}).get("sha256") in (SPY_SHA, BACKEND_SHA))]
        verdict = self.verdict(drop_both)
        self.assertFalse(verdict, verdict.detail)

    def test_gap_rejects_spy_exact_with_backend_failure(self):
        def drop_backend_init(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == BACKEND_SHA)]
        verdict = self.verdict(drop_backend_init)
        self.assertFalse(verdict, verdict.detail)

    def test_gap_rejects_spy_error_mismatch(self):
        # Spy counts exact but an error mismatches: the gap branch sees
        # no deficit, so only the deficit-required clause can fail this.
        def err_spy_init(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_Initialize"] and (row["module"] or {}).get("sha256") == SPY_SHA:
                    row["errors"] += 1
        verdict = self.verdict(err_spy_init)
        self.assertFalse(verdict, verdict.detail)

    def test_window_bounds_must_order(self):
        def drop_init_and_scramble(report, _ledger):
            report["functions"] = [r for r in report["functions"]
                                   if not (r["names"] == ["C_Initialize"]
                                           and (r["module"] or {}).get("sha256") == SPY_SHA)]
            for record in report["evidence"]["discovery"]:
                for window in record.get("unobserved_windows") or []:
                    window["start_ns"], window["end_ns"] = window["end_ns"], window["start_ns"]
        ledger, report = opensc_fixture(drop_init_and_scramble)
        with self.assertRaises(OuterError):
            judge_opensc_outer(report, ledger, 1, "Available slots:\n")

    def test_wrong_finalize_shape_fails(self):
        def single(report, _ledger):
            for row in report["functions"]:
                if row["names"] == ["C_Finalize"] and (row["module"] or {}).get("sha256") == BACKEND_SHA:
                    row["calls"] = 1
                    row["errors"] = 0
                    row["rv_counts"] = {"0x0000000000000000": 1}
        verdict = self.verdict(single)
        self.assertFalse(verdict, verdict.detail)

    def test_ledger_drift_fails(self):
        # A late second Initialize: counts drift while the leading
        # order stays intact, so only the ledger-shape pin can fail
        # this (isolates it from the order pin and the prefix rule).
        ledger = parse_spy_log(spy_text([("C_GetInterface", 0), ("C_Initialize", 0),
                                         ("C_GetSlotList", 0), ("C_Finalize", 0),
                                         ("C_Initialize", 0)]))
        _, report = opensc_fixture()
        verdict = judge_opensc_outer(report, ledger, 1, "Available slots:\n")
        self.assertFalse(verdict, verdict.detail)

    def test_tool_effect_mismatch_fails(self):
        verdict = self.verdict(rc=0)
        self.assertFalse(verdict, verdict.detail)


if __name__ == "__main__":
    unittest.main()
