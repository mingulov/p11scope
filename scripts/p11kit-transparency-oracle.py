#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Judge p11-kit transparency: no layer's calls are silently hidden.

Ground truth (independent of p11scope):

- the workload's LEDGER: calls it made into the proxy or client module;
- the OpenSC pkcs11-spy log: every call that reached the spied provider;
- mapped-provider pins: the physical identity of each watched module.

Transparency: for every watched layer, the report either counts that
layer's ledger exactly at the layer's module identity, or the report is
not exact (observation ``lossy``) and names the layer, or a covering
cause, as a gap or skip. A report that says ``exact`` while any layer's
counts differ is a failure, as is a layer with calls that the report
omits without a named gap.

Comparison scope: every ``C_*`` function the ledgers name, except the
selection meta-exports ``C_GetInterface``/``C_GetInterfaceList``. Those
are parsed and reported (never silently dropped), but p11scope's counted
surface is the function-list catalog plus the provisional
``C_GetFunctionList`` export (``src/plan.rs``,
``add_provisional_get_function_list``); ``C_GetInterface`` results are
evidenced as ``interface_selection`` tuples, not counted slots. The
detail always records their spy counts. ``C_GetFunctionList`` itself is
compared: the workload calls it once, and the provider's provisional
slot is expected at zero when p11-kit used ``C_GetInterface`` instead.

Observed rows with zero calls assert nothing and are ignored unless the
ledger expects calls there. Every nonzero observed standard-name row at
a watched identity must equal the ledger: ``==``, never ``>=``.

``--exact-only ROLE:NAMES`` splits a layer: the named functions (the
post-settle loop and teardown, which cannot race) must equal the ledger,
while the rest (setup calls, which race loader attach by construction)
is exact-or-covered. Cover excuses MISSES only: observed above the
ledger is a phantom count and always fails. ``--forbid-unknown`` forbids
unknown/ambiguous/unresolved rows without requiring exact observation;
``--strict`` requires whole-layer equality plus exact observation.

``--spy-binding ROLE`` marks the layer behind the spy: its
``C_GetFunctionList`` row is the spy's one-time binding call, below the
spy's logging layer and timing-dependent, so it is recorded and bounded
at 1, never compared. ``--require-pause`` asserts run-cell pause
evidence (sigstop, confirmed >= 1, nothing partial).
"""

import argparse
import json
import re
import stat
import sys
from pathlib import Path

LEDGER_SCHEMA = "p11scope/p11kit-ledger/v1"
RECEIPT_SCHEMA = "p11scope/p11kit-receipt/v1"
PROFILE_SCHEMA = "p11scope/observed-profile/v3"
METRICS_SCHEMA = "p11scope/observed-profile/v3-metrics"

# Selection meta-exports: parsed and reported, excluded from count
# equality for the reason in the module docstring.
META_EXPORTS = frozenset({"C_GetInterface", "C_GetInterfaceList"})

SPY_HEADER = re.compile(r"^(\d+): (C_[A-Za-z0-9]+)\s*$")
SPY_PID = re.compile(r"^P:(\d+);")
SPY_LOADED = re.compile(r"^Loaded: \"(.*)\"\s*$")


class EvidenceError(Exception):
    """The cell failed: the property is violated or the lifecycle did not
    produce coherent evidence (exit 1)."""


class HarnessError(Exception):
    """The invocation is wrong: malformed script-generated JSON, bad specs,
    or a fixture/ledger contract break (exit 2)."""


def require(condition, detail, harness=False):
    if not condition:
        raise HarnessError(detail) if harness else EvidenceError(detail)


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def unique_object(pairs, harness=True):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key, harness=harness)
        result[key] = value
    return result


def parse(text, harness=True):
    try:
        return json.loads(text, object_pairs_hook=lambda pairs: unique_object(pairs, harness))
    except ValueError as error:
        if harness:
            raise HarnessError("invalid JSON: " + str(error))
        raise EvidenceError("invalid JSON: " + str(error))


def read(path):
    require(stat.S_ISREG(path.stat().st_mode),
            "evidence must be a regular file: " + str(path), harness=True)
    require(path.stat().st_size <= 64 * 1024 * 1024,
            "evidence exceeds size limit: " + str(path), harness=True)
    return path.read_text(encoding="utf-8")


def identity(value, what="identity", harness=True):
    require(isinstance(value, dict), "missing " + what, harness=harness)
    dev = value.get("dev")
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev),
            "invalid device " + what, harness=harness)
    require(integer(value.get("ino")) and value["ino"] > 0,
            "invalid inode " + what, harness=harness)
    require(isinstance(value.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", value["sha256"]),
            "missing hash " + what, harness=harness)
    return (dev[0], dev[1], value["ino"], value["sha256"])


def pin_identity(pin, what="pin"):
    # A mapped-provider pin carries the module identity plus the private
    # FD identity and mapping anchor; only the module triple is compared.
    return identity(pin, what)


def parse_spy_log(text):
    """Parse an OpenSC pkcs11-spy log into completed per-function counts.

    Only block headers (``N: C_Name``), the ``P:pid`` line, the ``Loaded:``
    line, and the presence of a ``Returned:`` line are read; payload lines
    (arguments, PINs, key material) are never inspected. Returns
    ``(counts, meta, loaded, pids, incomplete)``: completed counts for
    compared functions, completed counts for the meta-exports, the loaded
    module path (or None), the sorted PID set, and ``[(seq, name)]``
    blocks without a return.
    """
    counts, meta, pids, incomplete = {}, {}, set(), []
    loaded, seq, name, returned, seqs = None, None, None, False, []
    require("OpenSC PKCS#11 spy" in text[:4096],
            "not an OpenSC pkcs11-spy log")

    def close():
        if name is None:
            return
        if returned:
            bucket = meta if name in META_EXPORTS else counts
            bucket[name] = bucket.get(name, 0) + 1
        else:
            incomplete.append((seq, name))

    for line in text.splitlines():
        header = SPY_HEADER.match(line)
        if header:
            close()
            seq, name, returned = int(header[1]), header[2], False
            seqs.append(seq)
            continue
        if name is None:
            loaded_match = SPY_LOADED.match(line)
            if loaded_match:
                loaded = loaded_match[1]
            continue
        if line.startswith("Returned:"):
            returned = True
        else:
            pid_match = SPY_PID.match(line)
            if pid_match:
                pids.add(int(pid_match[1]))
    close()
    require(seqs, "spy log holds no call blocks")
    require(all(b > a for a, b in zip(seqs, seqs[1:])),
            "spy log sequence numbers are not strictly increasing")
    return counts, meta, loaded, sorted(pids), incomplete


def parse_workload(text):
    """Parse workload stdout into (ledger, targets, ready_pid).

    TARGET lines may come before or after READY (gated.c prints them
    before; through-proxy.c prints READY first, before its first call).
    Exactly one READY and one complete LEDGER are required.
    """
    targets, ledgers, ready = [], [], []
    for line in text.splitlines():
        if line.startswith("TARGET "):
            targets.append(parse(line[7:]))
        elif line.startswith("LEDGER "):
            ledgers.append(parse(line[7:]))
        elif line.startswith("READY "):
            match = re.fullmatch(r"READY pid=([0-9]+)", line)
            require(match is not None, "invalid workload READY")
            ready.append(int(match[1]))
    require(len(ready) == 1, "missing or duplicate workload READY")
    require(len(ledgers) == 1, "missing or duplicate LEDGER")
    ledger = ledgers[0]
    require(ledger.get("schema") == LEDGER_SCHEMA and
            ledger.get("pid") == ready[0] and ledger.get("complete") is True,
            "invalid or incomplete fixture ledger")
    functions = ledger.get("functions")
    require(isinstance(functions, list) and functions,
            "missing ledger functions")
    expected = {}
    for row in functions:
        name = row.get("name")
        require(isinstance(name, str) and name.startswith("C_") and name not in expected,
                "duplicate or invalid ledger function")
        attempts, successes = row.get("attempts"), row.get("successful")
        require(integer(attempts) and integer(successes) and
                attempts > 0 and attempts == successes,
                "workload had failed calls or no successful calls: " + name)
        expected[name] = attempts
    seen = set()
    for row in targets:
        name = row.get("name")
        require(isinstance(name, str) and name in expected and name not in seen,
                "duplicate or unexpected fixture target")
        require(integer(row.get("file_offset")), "invalid fixture target")
        seen.add(name)
    return expected, targets, ready[0]


def row_owner(row):
    """Validate the v3 exclusive ownership relation of one function row."""
    require({"module", "module_ambiguous", "module_unresolved"} <= set(row),
            "missing required row ownership evidence")
    ambiguous, unresolved = row["module_ambiguous"], row["module_unresolved"]
    require(type(ambiguous) is bool and type(unresolved) is bool,
            "invalid row ownership flag")
    module = row["module"]
    if module is None:
        require(ambiguous != unresolved,
                "null module requires exactly one ownership reason")
        return None
    require(not ambiguous and not unresolved,
            "nonnull module contradicts ownership reason")
    require(isinstance(module, dict) and {"dev", "ino", "sha256"} <= set(module),
            "missing module ownership identity")
    return identity(module, "module ownership", harness=False)


def collect_layers(report):
    """Group nonzero observed calls by owning module identity.

    Returns ``(by_module, zero, unknown, ambiguous, unresolved, aliased)``:
    per-identity ``{name: calls}`` for single standard names, zero-call
    rows, ``["unknown"]`` rows, null-module rows by reason, and rows whose
    several names touch compared functions (unattributable).
    """
    rows = report.get("functions")
    require(isinstance(rows, list), "missing functions")
    by_module, zero, unknown = {}, [], []
    ambiguous, unresolved, aliased = [], [], []
    for row in rows:
        owner = row_owner(row)
        require(integer(row.get("calls")), "invalid function count")
        names = row.get("names")
        require(isinstance(names, list) and names and
                all(isinstance(name, str) for name in names),
                "invalid function names")
        calls = row["calls"]
        if owner is None:
            (ambiguous if row["module_ambiguous"] else unresolved).append(row)
            continue
        if names == ["unknown"]:
            unknown.append(row)
            continue
        if len(names) != 1 or not names[0].startswith("C_"):
            if calls:
                aliased.append(row)
            else:
                zero.append(row)
            continue
        if not calls:
            zero.append(row)
            continue
        if names[0] in META_EXPORTS:
            zero.append(row)
            continue
        bucket = by_module.setdefault(owner, {})
        require(names[0] not in bucket,
                "duplicate observed row for one module and name: " + names[0])
        bucket[names[0]] = calls
    return by_module, zero, unknown, ambiguous, unresolved, aliased


def offset_observed(rows, ident, targets):
    """Match rows to TARGET lines by physical target for one identity.

    The proxy's live entry points stay ``["unknown"]`` (heuristic tables
    are never ordinal-named), so the proxy layer is attributed by
    ``(module, file_offset)``, never by name. Returns ``(matched,
    internal, consumed)``: ``{name: calls}`` at TARGET offsets (summed
    when several rows share one offset, e.g. retire/reattach),
    ``[(offset, calls, ordinals)]`` nonzero rows at other offsets
    (genuine non-workload calls, e.g. p11-kit-internal), and every row
    index this identity's offset layer looked at.
    """
    by_offset = {}
    for row in targets:
        if row.get("dev") == [ident[0], ident[1]] and row.get("ino") == ident[2]:
            offset = row["file_offset"]
            require(offset not in by_offset,
                    "two TARGET lines share one offset: %r" % (offset,), harness=True)
            by_offset[offset] = row["name"]
    matched, internal, consumed = {}, [], set()
    for index, row in enumerate(rows):
        if row_owner(row) != ident:
            continue
        target = row.get("target")
        require(isinstance(target, dict) and integer(target.get("file_offset")),
                "invalid physical target")
        obj = target.get("object")
        if obj is not None and (obj.get("dev") != [ident[0], ident[1]] or
                                obj.get("ino") != ident[2]):
            # A forwarded entry names the dependency, not this module.
            if row["calls"]:
                internal.append((target["file_offset"], row["calls"], row.get("ordinals")))
            consumed.add(index)
            continue
        consumed.add(index)
        name = by_offset.get(target["file_offset"])
        if name is None:
            if row["calls"]:
                internal.append((target["file_offset"], row["calls"], row.get("ordinals")))
            continue
        matched[name] = matched.get(name, 0) + row["calls"]
    return matched, internal, consumed


def gap_inventory(evidence):
    """Every short, human-readable record of what the report gave up on."""
    texts = []
    for entry in evidence.get("modules_skipped", []):
        require(isinstance(entry, dict), "invalid modules_skipped entry")
        texts.append("modules_skipped: %s: %s" % (entry.get("name"), entry.get("reason")))
    for entry in evidence.get("skipped", []):
        require(isinstance(entry, dict), "invalid skipped entry")
        texts.append("skipped: %s: %s" % (entry.get("name"), entry.get("reason")))
    for module in evidence.get("discovery", []):
        if not isinstance(module, dict):
            continue
        for entry in module.get("skipped", []):
            texts.append("discovery[%s] skipped: %s: %s"
                         % (module.get("path"), entry.get("name"), entry.get("reason")))
    gaps = evidence.get("gap_classes", {})
    for group in ("observation", "attribution", "semantics"):
        status = gaps.get(group, {})
        texts.append("gap %s: %s causes=%s"
                     % (group, status.get("status"), status.get("causes")))
    return texts


def transparency_note(evidence, exact):
    """One-line disclosure summary appended to layer-mismatch errors, so an
    expected-failure detail still proves the gap was named, not silent."""
    skipped = [entry.get("name") for entry in evidence.get("modules_skipped", [])
               if isinstance(entry, dict)]
    return " [transparency: lossy=%s skipped-modules=%s]" % (not exact, skipped)


def discovery_identities(evidence):
    found = set()
    for module in evidence.get("discovery", []):
        if isinstance(module, dict) and module.get("sha256") is not None:
            try:
                found.add(identity(module, "discovery"))
            except (EvidenceError, HarnessError):
                continue
    return found


def check_receipt(receipt, cell, scope, mode, workload_pid, minimal=False):
    require(receipt.get("schema") == RECEIPT_SCHEMA and receipt.get("cell") == cell,
            "receipt schema or cell mismatch", harness=True)
    require(receipt.get("scope") == scope, "receipt scope mismatch", harness=True)
    require(receipt.get("mode") == mode, "receipt mode mismatch", harness=True)
    for key in ("observer_exit", "workload_exit"):
        require(type(receipt.get(key)) is int and receipt[key] == 0,
                "nonzero or missing " + key)
    if minimal:
        # Tool cells (a real tool, not the ledgered fixture) carry no PID
        # custody, gate, or LEDGER: the exits plus the fresh spy log are the
        # evidence. The caller must guarantee the spy file is per-cell fresh.
        return
    for key in ("workload_ready", "capture_ready", "ledger_complete"):
        require(receipt.get(key) is True, "missing " + key)
    if scope != "run":
        require(receipt.get("gate_released") is True, "gate was not safely released")
    launched = receipt.get("launched_pid")
    require(integer(launched) and launched == workload_pid and
            receipt.get("ready_pid") == workload_pid,
            "workload READY does not match launched PID")


def fmt_counts(counts):
    return "{" + ", ".join("%s=%d" % item for item in sorted(counts.items())) + "}"


def judge(report_text, ledger_text, spy_text, receipt, args):
    if args.no_workload:
        require(ledger_text is None, "tool cell takes no workload ledger", harness=True)
        check_receipt(receipt, args.cell, args.scope, args.mode, None, minimal=True)
        expected, targets = {}, []
    else:
        require(ledger_text is not None, "missing workload ledger", harness=True)
        check_receipt(receipt, args.cell, args.scope, args.mode, parse_workload(ledger_text)[2])
        expected, targets, _ = parse_workload(ledger_text)
    spy_counts, spy_meta, spy_loaded, spy_pids = {}, {}, None, []
    if spy_text is not None:
        spy_counts, spy_meta, spy_loaded, spy_pids, spy_incomplete = parse_spy_log(spy_text)
        require(not spy_incomplete,
                "spy log holds calls without a return: %r" % (spy_incomplete,))
        require(spy_counts, "spy log holds no compared calls")
        if receipt.get("spy_loaded") is not None:
            require(spy_loaded == receipt["spy_loaded"],
                    "spy logged a different module than the owned copy: %r" % (spy_loaded,))
        if receipt.get("spy_pid") is not None:
            require(spy_pids == [receipt["spy_pid"]],
                    "spy log PIDs differ from the recorded caller: %r" % (spy_pids,))
    report = parse(report_text, harness=False)
    want_schema = METRICS_SCHEMA if args.mode == "metrics" else PROFILE_SCHEMA
    require(report.get("schema") == want_schema, "unsupported or wrong cell profile schema")
    require(report.get("lane") == args.mode and
            report.get("capture", {}).get("mode") == args.mode,
            "report lane or capture mode differs from declared cell")
    if args.scope != "run":
        require(report.get("capture", {}).get("scope") == args.scope,
                "report capture scope differs from declared cell")
    evidence = report.get("evidence")
    require(isinstance(evidence, dict), "missing capture evidence")
    observation = evidence.get("gap_classes", {}).get("observation", {})
    exact = observation.get("status") == "exact"
    by_module, zero, unknown, ambiguous, unresolved, aliased = collect_layers(report)
    require(not aliased, "aliased row touches compared functions: %r"
            % ([row.get("names") for row in aliased],))

    layers = []
    for spec in args.layer:
        fields = spec.split(":")
        require(len(fields) in (3, 4), "bad --layer spec: " + spec, harness=True)
        role, pin_path, kind = fields[0], fields[1], fields[2]
        mode = fields[3] if len(fields) == 4 else "name"
        require(kind in ("workload", "spy"), "layer kind must be workload or spy: " + spec,
                harness=True)
        require(mode in ("name", "offset"), "layer mode must be name or offset: " + spec,
                harness=True)
        require(kind != "spy" or spy_text is not None,
                "spy layer without a spy log: " + spec, harness=True)
        require(kind != "workload" or not args.no_workload,
                "workload layer without a workload ledger: " + spec, harness=True)
        pin = parse(read(Path(pin_path)))
        ident = pin_identity(pin, role + " pin")
        ledger = expected if kind == "workload" else spy_counts
        layers.append((role, ident, ledger, mode))
    require(layers, "no watched layer declared", harness=True)
    forbid = set()
    for pin_path in args.forbid:
        forbid.add(pin_identity(parse(read(Path(pin_path))), "forbidden pin"))
    if args.target_identity:
        require(not args.no_workload, "tool cell takes no target identity", harness=True)
        want = pin_identity(parse(read(Path(args.target_identity))), "target pin")
        require(targets, "workload printed no TARGET lines")
        for row in targets:
            require(row.get("dev") == [want[0], want[1]] and row.get("ino") == want[2],
                    "workload called a different object than the watched proxy: "
                    + row.get("name", "?"))

    notes = ["observation=%s causes=%r" % (observation.get("status"),
                                           observation.get("causes"))]
    if spy_meta:
        notes.append("selection-meta spy counts (not counted slots): "
                     + fmt_counts(spy_meta))
    if zero:
        notes.append("%d zero-call rows ignored" % len(zero))
    # A forbidden identity must leave no trace: no rows, no discovery entry.
    for ident in forbid:
        require(ident not in by_module, "forbidden identity has counted rows")
        require(ident not in discovery_identities(evidence),
                "forbidden identity is a discovery entry")

    strict = args.strict
    gaps = gap_inventory(evidence)
    # Pinned gap text is verified before any layer verdict: a missing pin
    # fails even when the layers also fail, so the pin is never vacuous.
    for basename, substring in args.expect_skip:
        require(any(basename in text and substring in text for text in gaps),
                "pinned skip text absent: %s / %s" % (basename, substring))
    if args.expect_skip_any:
        require(any(basename in text and substring in text
                    for text in gaps
                    for basename, substring in args.expect_skip_any),
                "pinned skip text absent (any of): %s"
                % ("; ".join("%s / %s" % pair for pair in args.expect_skip_any),))
    exact_only = {}
    for role, names in args.exact_only:
        exact_only.setdefault(role, set()).update(names.split(","))
    rows = report["functions"]
    consumed, totals = set(), {}
    for role, ident, ledger, mode in layers:
        internal = []
        if role in args.spy_binding:
            # The spy resolves the real C_GetFunctionList once per process to
            # build its forward table. That binding call into the provider is
            # below the spy's logging layer (the log records calls the spy
            # RECEIVES), timing-dependent (0 when the provisional slot
            # attaches late, 1 when pre-mapped or paused), and never a
            # forwarded workload call: p11-kit reaches the provider only
            # through the spy handle. It is recorded, never compared, and
            # bounded: a second binding would be a new behavior, not this one.
            if role in exact_only and "C_GetFunctionList" in exact_only[role]:
                raise HarnessError("--spy-binding and --exact-only overlap on %s" % role)
            bound = dict(by_module.get(ident, {})) if mode == "name" else None
            if mode == "offset":
                raise HarnessError("--spy-binding needs a name-compared layer: " + role)
            binding = bound.pop("C_GetFunctionList", 0)
            require(binding <= 1,
                    "%s: provider C_GetFunctionList binding calls %d > 1" % (role, binding))
            if binding:
                notes.append("%s: C_GetFunctionList binding below the spy log: %d"
                             % (role, binding))
            observed = bound
        elif mode == "offset":
            have = {row["name"] for row in targets
                    if row.get("dev") == [ident[0], ident[1]] and row.get("ino") == ident[2]}
            missing = set(ledger) - have
            require(not missing,
                    "ledger names without a TARGET at the %s identity: %s"
                    % (role, sorted(missing)), harness=True)
            observed, internal, used = offset_observed(rows, ident, targets)
            consumed |= used
        else:
            observed = by_module.get(ident, {})
        if strict:
            # Strict mode requires whole-layer equality; subsets refine
            # transparency mode only.
            subset, rest = set(ledger) | set(observed), set()
        elif role in exact_only:
            subset = exact_only[role]
            unknown_subset = subset - set(ledger)
            require(not unknown_subset,
                    "exact-only names absent from the %s ledger: %s"
                    % (role, sorted(unknown_subset)), harness=True)
            rest = (set(ledger) | set(observed)) - subset
        else:
            subset, rest = set(), set(ledger) | set(observed)
        exact_delta = {name: (ledger.get(name, 0), observed.get(name, 0))
                       for name in sorted(subset)
                       if ledger.get(name, 0) != observed.get(name, 0)}
        if exact_delta:
            raise EvidenceError(
                "%s: observed %s differs from ledger %s (exact-subset delta %r)%s"
                % (role, fmt_counts(observed), fmt_counts(ledger), exact_delta,
                   transparency_note(evidence, exact)))
        rest_delta = {name: (ledger.get(name, 0), observed.get(name, 0))
                      for name in sorted(rest)
                      if ledger.get(name, 0) != observed.get(name, 0)}
        totals[role] = sum(observed.values())
        if internal:
            notes.append("%s: %d internal calls at %d unmatched offsets: %r"
                         % (role, sum(calls for _, calls, _ in internal),
                            len(internal), sorted(internal)))
        if not rest_delta:
            notes.append("%s: exact %s" % (role, fmt_counts(observed)))
            continue
        detail = "%s: observed %s differs from ledger %s (delta %r)" % (
            role, fmt_counts(observed), fmt_counts(ledger), rest_delta)
        if role in args.require_exact or strict:
            raise EvidenceError(detail + transparency_note(evidence, exact))
        # Transparency fallback: the report must be inexact and must name
        # the layer or a covering cause. Cover excuses MISSES (observed
        # below the ledger) only: a surplus is a phantom count and always
        # fails, covered or not.
        surplus = {name: pair for name, pair in rest_delta.items() if pair[1] > pair[0]}
        require(not surplus, detail + "; phantom counts above the ledger: %r" % (surplus,))
        require(not exact,
                detail + "; report still claims exact observation")
        cause_cover = [text for text in gaps if "causes=" in text and "[]" not in text]
        named = [text for text in gaps
                 if args.module_name.get(role, "\0") in text or ident[3] in text]
        require(cause_cover or named,
                detail + "; no named gap or covering cause")
        notes.append(detail + " [covered: %s]" % "; ".join((named + cause_cover)[:3]))
    if args.forbid_unknown or strict:
        bad = [row for index, row in enumerate(rows)
               if index not in consumed and row["calls"] and
               (row["names"] == ["unknown"] or row["module"] is None)]
        unk = sum(1 for row in bad if row["names"] == ["unknown"] and row["module"] is not None)
        amb = sum(1 for row in bad if row["module_ambiguous"])
        unr = sum(1 for row in bad if row["module_unresolved"])
        require(not bad, "unattributed calls where none are allowed: unknown=%d "
                         "ambiguous=%d unresolved=%d" % (unk, amb, unr))
    if args.require_pause:
        require(evidence.get("pause") == "sigstop" and
                integer(evidence.get("pause_confirmed")) and evidence["pause_confirmed"] >= 1 and
                evidence.get("pause_partial") == 0,
                "pause not confirmed: pause=%r confirmed=%r partial=%r" % (
                    evidence.get("pause"), evidence.get("pause_confirmed"),
                    evidence.get("pause_partial")))
        notes.append("pause confirmed: %s attempts=%r confirmed=%r" % (
            evidence.get("pause"), evidence.get("pause_attempts"),
            evidence.get("pause_confirmed")))
    if strict:
        require(exact and observation.get("causes") == [],
                "lossy or unknown observation gap class")

    notes.append("layer totals %r; unknown=%d ambiguous=%d unresolved=%d" % (
        totals, len(unknown), len(ambiguous), len(unresolved)))
    return "p11kit-transparent", "; ".join(notes)


INV_SCHEMA = "p11scope/inventory/v1"


def inventory_identity(entry):
    found = entry.get("identity", {})
    device = found.get("device", {})
    return (device.get("major"), device.get("minor"), found.get("inode"), found.get("sha256"))


def judge_inventory(inv_text, args):
    """Judge an inventory document: named backends admitted whole (exact
    endpoint counts, never >=) and named refusals carrying pinned text."""
    inv = parse(inv_text, harness=False)
    require(inv.get("schema") == INV_SCHEMA, "not an inventory v1 document")
    modules = inv.get("modules")
    require(isinstance(modules, list), "missing inventory modules")
    by_identity = {}
    for entry in modules:
        require(isinstance(entry, dict), "invalid inventory module")
        by_identity.setdefault(inventory_identity(entry), []).append(entry)
    notes = []
    for spec in args.expect_admitted:
        pin_path, want = spec.rsplit(":", 1)
        require(want.isdigit(), "bad --expect-admitted count: " + spec, harness=True)
        pin = parse(read(Path(pin_path)))
        ident = (pin["dev"][0], pin["dev"][1], pin["ino"], pin["sha256"])
        found = by_identity.get(ident, [])
        require(len(found) == 1, "backend identity absent or ambiguous: %s" % spec)
        admission = found[0].get("admission", {})
        require(admission.get("state") == "admitted",
                "backend not admitted whole: %s state=%r reasons=%r"
                % (spec, admission.get("state"), admission.get("reasons")))
        require(admission.get("endpoints") == int(want),
                "backend endpoint count %r differs from pinned %s" % (
                    admission.get("endpoints"), want))
        notes.append("%s: admitted whole (%s endpoints)" % (Path(pin_path).name, want))
    for pin_path, substring in args.expect_refused:
        pin = parse(read(Path(pin_path)))
        ident = (pin["dev"][0], pin["dev"][1], pin["ino"], pin["sha256"])
        found = by_identity.get(ident, [])
        require(len(found) == 1, "refused identity absent or ambiguous: " + pin_path)
        admission = found[0].get("admission", {})
        reasons = " ".join(reason for reason in admission.get("reasons", [])
                           if isinstance(reason, str))
        require(admission.get("state") == "refused",
                "expected a named refusal for %s, state=%r" % (pin_path, admission.get("state")))
        require(substring in reasons,
                "pinned refusal text absent for %s: %s" % (pin_path, substring))
        notes.append("%s: refused as named (%s)" % (Path(pin_path).name, substring))
    return "inventory-admission", "; ".join(notes)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default=None)
    parser.add_argument("--inventory", default=None,
                        help="inventory v1 document (inventory mode; takes "
                             "--expect-admitted/--expect-refused instead of "
                             "report layers)")
    parser.add_argument("--expect-admitted", action="append", default=[],
                        help="PINFILE:ENDPOINTS admitted whole (inventory mode)")
    parser.add_argument("--expect-refused", action="append", default=[], nargs=2,
                        metavar=("PINFILE", "SUBSTRING"),
                        help="PINFILE refused with pinned reason text (inventory mode)")
    parser.add_argument("--ledger", default=None,
                        help="workload stdout with READY/TARGET/LEDGER "
                             "(omit with --no-workload)")
    parser.add_argument("--spy", default=None,
                        help="OpenSC pkcs11-spy log (omit when no spied module "
                             "is in scope; then no spy layer may be declared)")
    parser.add_argument("--no-workload", action="store_true",
                        help="tool cell: no fixture ledger (a real tool ran); "
                             "only spy layers, exits, and the fresh spy log "
                             "are checked")
    parser.add_argument("--receipt", default=None)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--scope", default=None, choices=("pid", "system", "run"))
    parser.add_argument("--mode", default=None, choices=("profile", "metrics"))
    parser.add_argument("--layer", action="append", default=[],
                        help="ROLE:PINFILE:workload|spy[:name|offset] (repeatable); "
                             "offset attributes by TARGET file offset")
    parser.add_argument("--require-exact", action="append", default=[],
                        help="layer role whose whole ledger must equal (no cover; "
                             "dominates --exact-only for the same role)")
    parser.add_argument("--forbid", action="append", default=[],
                        help="pin file whose identity must not appear (repeatable)")
    parser.add_argument("--target-identity",
                        help="pin file the workload TARGET lines must point at")
    parser.add_argument("--expect-skip", action="append", default=[], nargs=2,
                        metavar=("BASENAME", "SUBSTRING"),
                        help="pinned gap text that must appear (repeatable; every "
                             "pair is required)")
    parser.add_argument("--expect-skip-any", action="append", default=[], nargs=2,
                        metavar=("BASENAME", "SUBSTRING"),
                        help="pinned gap text of which at least one pair must "
                             "appear (repeatable; for pre/post-fix disjunctions)")
    parser.add_argument("--module-name", action="append", default=[], nargs=2,
                        metavar=("ROLE", "NAME"),
                        help="gap-text name for a layer role (repeatable)")
    parser.add_argument("--strict", action="store_true",
                        help="require exact observation and no unknown rows")
    parser.add_argument("--forbid-unknown", action="store_true",
                        help="forbid unknown/ambiguous/unresolved rows without requiring exactness")
    parser.add_argument("--exact-only", action="append", default=[], nargs=2,
                        metavar=("ROLE", "NAMES"),
                        help="comma-separated function subset that must be exact; "
                             "the rest is exact-or-covered (repeatable)")
    parser.add_argument("--spy-binding", action="append", default=[],
                        help="layer role behind the spy: its C_GetFunctionList row "
                             "is the spy's one-time binding (recorded, bounded "
                             "at 1, never compared)")
    parser.add_argument("--require-pause", action="store_true",
                        help="require pause evidence sigstop with confirmed>=1 "
                             "and no partial (run cells)")
    args = parser.parse_args(argv)
    args.expect_skip = [tuple(pair) for pair in args.expect_skip]
    args.expect_skip_any = [tuple(pair) for pair in args.expect_skip_any]
    args.module_name = dict(args.module_name)
    args.expect_refused = [tuple(pair) for pair in args.expect_refused]
    result = {"cell": args.cell, "pass": False, "detail": "", "qualification": "failed"}
    try:
        if args.inventory:
            require(not args.report and not args.receipt and not args.layer,
                    "inventory mode takes no report layers", harness=True)
            require(args.expect_admitted or args.expect_refused,
                    "inventory mode needs an expectation", harness=True)
            qualification, detail = judge_inventory(read(Path(args.inventory)), args)
        else:
            require(args.report and args.receipt, "missing report or receipt", harness=True)
            require(args.scope and args.mode, "missing scope or mode", harness=True)
            for spec in args.layer:
                require(spec.count(":") >= 2, "bad --layer spec: " + spec, harness=True)
            spy_text = read(Path(args.spy)) if args.spy else None
            ledger_text = read(Path(args.ledger)) if args.ledger else None
            qualification, detail = judge(read(Path(args.report)), ledger_text,
                                          spy_text, parse(read(Path(args.receipt))),
                                          args)
        result.update({"pass": True, "qualification": qualification, "detail": detail})
        code = 0
    except HarnessError as error:
        result.update(qualification="failed", detail="harness: " + str(error))
        code = 2
    except (EvidenceError, OSError, ValueError, TypeError, KeyError,
            AttributeError, AssertionError) as error:
        result["detail"] = str(error)
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
