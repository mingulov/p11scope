# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge real-provider `run` evidence against an independent pkcs11-spy ledger.

Each WP-3 cell runs a real distro tool under `p11scope run --pause auto`
with the tool's PKCS#11 calls routed through OpenSC `pkcs11-spy.so`, which
appends one entry per forwarded call to a spy log. This oracle checks:

- the tool exited 0 and a v3 report was published for the cell's mode;
- per function, the observed count at the spied module's identity equals
  the spy log count (exact, both directions; unknown or aliased rows
  cannot qualify), with two exact spy-boundary rules: the spy calls the
  real C_GetFunctionList once per client process without logging it, so
  the observed count there is the ledger count plus the logged process
  count; and C_GetInterface/C_GetInterfaceList are forwarded only when
  the spied module exports them (recorded in the receipt from its
  dynamic symbols), otherwise the observed count must be zero;
- the pause outcome equals the pinned expectation (cells pinning partial
  today record the known OpenSC-partial-pause failure owned by the
  exec-real-providers lane);
- the set of observation causes equals the pinned per-cell list, where
  every pin carries a reason and an owner (the ratchet: a fixed cause or
  a new cause both fail until the pin is updated); single-sample entries
  carry `"provisional": true`, which never changes a verdict;
- where the pin declares a p11-kit skip, the p11-kit-subject skip text
  names the pinned endpoint count for the installed p11-kit version
  (other subjects, such as the runtime-built spy table, are covered by
  the cause pin and listed in the detail);
- a metrics twin skipped nothing except, where the pin declares a p11-kit
  skip, exactly that pinned p11-kit closure skip (W3-2 finding 1: the
  closure skip is the same named product behaviour in metrics as in
  profile; any other skip still fails).

Counts, tool exit, report schema, the p11-kit skip text and the
metrics skip rule are strict: any violation fails the cell. Only the
pause outcome and the observation-cause set are pinnable, and then only
to exactly the pinned values. A pin may list `alternates`: further
accepted (cause set, pause) shapes for cells whose outcome flaps with
identical exact counts; the actual shape must equal the primary or one
alternate jointly, and any third shape fails.
"""

import argparse
import json
from pathlib import Path
import re
import stat
import sys

RECEIPT_SCHEMA = "p11scope/real-provider-receipt/v1"
EXPECTS_SCHEMA = "p11scope/real-provider-expected-causes/v1"

SPY_HEADER = "OpenSC PKCS#11 spy"
SPY_ENTRY = re.compile(r"^([0-9]+): (C_[A-Za-z0-9]+)$")
SPY_LOADED = re.compile(r"^Loaded: \"(.*)\"$")
SPY_RETURNED = re.compile(r"^Returned:\s+(-?[0-9]+)\s+([A-Za-z0-9_]+)\s*$")

# Mirrors src/plan.rs: growth_omitted_count ("admitted module needs N more;")
# and whole_refusal_needed_count ("module needs N more;").
GROWTH_PREFIX = "admitted module needs "
WHOLE_PREFIX = "module needs "


class EvidenceError(Exception):
    pass


class HarnessError(Exception):
    pass


def require(condition, detail):
    if not condition:
        raise EvidenceError(detail)


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=unique_object)


def read(path):
    require(stat.S_ISREG(path.stat().st_mode), "evidence must be a regular file")
    require(path.stat().st_size <= 64 * 1024 * 1024, "evidence exceeds size limit")
    return path.read_text(encoding="utf-8")


def identity(value):
    require(isinstance(value, dict), "missing physical identity")
    dev = value.get("dev")
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev),
            "invalid device identity")
    require(integer(value.get("ino")) and value["ino"] > 0, "invalid inode identity")
    require(isinstance(value.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", value["sha256"]), "missing provider hash")
    return (*dev, value["ino"], value["sha256"])


def provider_pin(value):
    physical = identity(value)
    anchor = value.get("mapping")
    require(isinstance(anchor, dict) and isinstance(anchor.get("dev"), list) and
            all(integer(x) for x in anchor["dev"]) and anchor["dev"] == list(physical[:2]) and
            type(anchor.get("ino")) is int and anchor["ino"] == physical[2] and
            type(anchor.get("file_offset")) is int and anchor["file_offset"] == 0 and
            integer(anchor.get("length")) and anchor["length"] > 0 and
            anchor.get("permissions") == "r--p", "missing or invalid independent mapping anchor")
    file = value.get("file_identity")
    require(isinstance(file, dict), "missing private FD identity")
    dev = file.get("dev")
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev) and
            type(file.get("ino")) is int and file["ino"] == physical[2] and
            integer(file.get("size")) and file["size"] >= anchor["length"] and
            all(type(file.get(key)) is int for key in ("mtime_ns", "ctime_ns")),
            "invalid private FD identity")
    return physical, (*dev, file["ino"], file["size"], file["mtime_ns"], file["ctime_ns"])


def ownership(row):
    """Validate the v3 exclusive ownership relation; absence has no authority."""
    require({"module", "module_ambiguous", "module_unresolved"} <= set(row),
            "missing required row ownership evidence")
    ambiguous, unresolved = row["module_ambiguous"], row["module_unresolved"]
    require(type(ambiguous) is bool and type(unresolved) is bool, "invalid row ownership flag")
    module = row["module"]
    if module is None:
        require(ambiguous != unresolved, "null module requires exactly one ownership reason")
        return None
    require(not ambiguous and not unresolved, "nonnull module contradicts ownership reason")
    require(isinstance(module, dict) and {"dev", "ino", "sha256"} <= set(module),
            "missing module ownership identity")
    dev = module["dev"]
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev) and
            integer(module["ino"]) and module["ino"] > 0, "invalid module ownership identity")
    if module["sha256"] is None:
        return None
    return identity(module)


def parse_spy_log(text):
    """Parse an OpenSC pkcs11-spy log into (loaded path, counts, processes).

    Format established on OpenSC 0.27.0~rc1: a header naming the loaded
    module, then one `<seq>: <C_Function>` entry per forwarded call, each
    closed by a `Returned:` line. Every entry must close: a trailing
    entry without `Returned:` is a truncated log, never a partial count.
    Sequences may restart at 0 when several processes share one log file,
    so only per-entry completeness is required, never global sequence
    order. Each client process prints one header, so the header count is
    the process count behind the C_GetFunctionList boundary rule.
    """
    if "Error: no module specified" in text:
        raise HarnessError("spy log has no module: PKCS11SPY was unset")
    require(SPY_HEADER in text, "spy log lacks the OpenSC spy header")
    loaded = None
    processes = 0
    for line in text.splitlines():
        match = SPY_LOADED.match(line.strip())
        if match:
            processes += 1
            if loaded is None:
                loaded = match.group(1)
            else:
                require(loaded == match.group(1),
                        "spy log names two spied modules: %s and %s" % (loaded, match.group(1)))
    if loaded is None:
        raise HarnessError("spy log names no loaded module")
    counts = {}
    current = None
    for line in text.splitlines():
        entry = SPY_ENTRY.match(line)
        if entry:
            require(current is None, "spy log entry never returned: %s" % current)
            current = entry.group(2)
            continue
        if SPY_RETURNED.match(line):
            require(current is not None, "spy log return without an entry")
            counts[current] = counts.get(current, 0) + 1
            current = None
    require(current is None, "spy log is truncated at entry: " + str(current))
    require(counts, "spy log holds no completed calls")
    return loaded, counts, processes


def skip_needed_count(reason):
    """The stated count of a capacity skip reason, or None (see plan.rs)."""
    for prefix in (GROWTH_PREFIX, WHOLE_PREFIX):
        if reason.startswith(prefix):
            tail = reason[len(prefix):]
            number, separator, _ = tail.partition(" more;")
            if separator and number.isdigit():
                return int(number)
    return None


def skipped_counts(evidence):
    """Parsed (subject, count) pairs from every modules_skipped reason."""
    skipped = evidence.get("modules_skipped")
    require(isinstance(skipped, list), "missing evidence modules_skipped")
    pairs = []
    for row in skipped:
        require(isinstance(row, dict), "invalid modules_skipped row")
        reason = row.get("reason")
        require(isinstance(reason, str), "modules_skipped row lacks a reason")
        parsed = skip_needed_count(reason)
        if parsed is not None:
            pairs.append((row.get("name"), parsed))
    return pairs


def select_pin(expects, cell, os_id, tool_version):
    if expects.get("schema") != EXPECTS_SCHEMA:
        raise HarnessError("expected-causes schema mismatch")
    cells = expects.get("cells")
    if not isinstance(cells, dict) or cell not in cells:
        raise HarnessError("no expected-causes entry for cell: " + cell)
    entries = cells[cell]
    if not isinstance(entries, list):
        raise HarnessError("expected-causes entry is not a list for cell: " + cell)
    for entry in entries:
        if not isinstance(entry, dict):
            raise HarnessError("invalid expected-causes entry for cell: " + cell)
        if not isinstance(entry.get("os"), str) or not entry.get("os").strip() or \
                not isinstance(entry.get("tool_version"), str) or \
                not entry.get("tool_version").strip():
            raise HarnessError("expected-causes entry lacks its os/tool key for cell: " + cell)
        if entry.get("os") == os_id and entry.get("tool_version") == tool_version:
            return entry
    raise HarnessError("no expected-causes pin for cell %s on os %s tool %s"
                       % (cell, os_id, tool_version))


def check_causes_shape(rows, cell):
    if not isinstance(rows, list):
        raise HarnessError("pin lacks an observation list for cell: " + cell)
    for row in rows:
        if not isinstance(row, dict):
            raise HarnessError("invalid pinned cause for cell: " + cell)
        for key in ("cause", "reason", "owner"):
            value = row.get(key)
            if not isinstance(value, str) or not value.strip():
                raise HarnessError("pinned cause lacks %s for cell: %s" % (key, cell))
    names = [row["cause"] for row in rows]
    if len(set(names)) != len(names):
        raise HarnessError("pinned cause duplicated for cell: " + cell)
    return set(names)


def check_pause_shape(pause, cell):
    if not isinstance(pause, dict):
        raise HarnessError("pin lacks a pause expectation for cell: " + cell)
    if pause.get("status") not in ("sigstop", "partial"):
        raise HarnessError("pin names an unknown pause status for cell: " + cell)
    for key in ("reason", "owner"):
        value = pause.get(key)
        if not isinstance(value, str) or not value.strip():
            raise HarnessError("pinned pause lacks %s for cell: %s" % (key, cell))
    return pause


def check_pin_shape(pin, cell):
    causes = check_causes_shape(pin.get("observation"), cell)
    pause = check_pause_shape(pin.get("pause"), cell)
    if "provisional" in pin and type(pin["provisional"]) is not bool:
        raise HarnessError("pin carries a non-boolean provisional marker for cell: " + cell)
    skip = pin.get("p11kit_skip")
    if not (skip is None or (integer(skip) and skip > 0)):
        raise HarnessError("pin names an invalid p11kit_skip for cell: " + cell)
    version = pin.get("p11kit_version")
    if skip is None:
        if version is not None:
            raise HarnessError("pin carries a p11-kit version without a skip for cell: " + cell)
    elif not isinstance(version, str) or not version.strip():
        raise HarnessError("pin names a p11-kit skip without its version for cell: " + cell)
    alternates = []
    if "alternates" in pin:
        raw = pin["alternates"]
        if not isinstance(raw, list):
            raise HarnessError("pin carries a non-list alternates for cell: " + cell)
        for alt in raw:
            if not isinstance(alt, dict):
                raise HarnessError("invalid alternate shape for cell: " + cell)
            alternates.append((check_causes_shape(alt.get("observation"), cell),
                               check_pause_shape(alt.get("pause"), cell)["status"]))
    shapes = [(causes, pause["status"])] + alternates
    if len({(frozenset(names), status) for names, status in shapes}) != len(shapes):
        raise HarnessError("pin carries a duplicated shape for cell: " + cell)
    return causes, pause, skip, version, alternates


def judge(report_text, spy_text, receipt, expects, cell):
    require(receipt.get("schema") == RECEIPT_SCHEMA, "receipt schema mismatch")
    require(receipt.get("cell") == cell, "receipt cell mismatch")
    mode = receipt.get("mode")
    require(mode in ("profile", "metrics"), "receipt names an unknown mode")
    os_id = receipt.get("os_id")
    require(isinstance(os_id, str) and os_id.strip(), "receipt lacks os_id")
    tool_version = receipt.get("tool_version")
    require(isinstance(tool_version, str) and tool_version.strip(), "receipt lacks tool_version")
    spied_path = receipt.get("spied_module")
    require(isinstance(spied_path, str) and spied_path, "receipt lacks spied_module")
    require(type(receipt.get("run_exit")) is int, "receipt lacks run_exit")
    require(receipt.get("run_exit") == 0,
            "tool exited %s; run propagates the child status" % receipt.get("run_exit"))
    require(provider_pin(receipt.get("provider_before")) ==
            provider_pin(receipt.get("provider_after")),
            "spied module physical identity or hash changed")
    provider = identity(receipt["provider_before"])

    pin = select_pin(expects, cell, os_id, tool_version)
    pinned_causes, pinned_pause, pinned_skip, pinned_p11kit, alternates = \
        check_pin_shape(pin, cell)

    loaded, spy_counts, processes = parse_spy_log(spy_text)
    require(loaded == spied_path,
            "spy ledger is for %s, not the spied module %s" % (loaded, spied_path))
    exports = receipt.get("spied_exports")
    require(isinstance(exports, dict) and
            all(type(exports.get(name)) is bool
                for name in ("C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList")),
            "receipt lacks spied_exports booleans")
    require(exports["C_GetFunctionList"], "spied module exports no C_GetFunctionList")

    report = parse(report_text)
    schema = "p11scope/observed-profile/v3-metrics" if mode == "metrics" else "p11scope/observed-profile/v3"
    require(report.get("schema") == schema, "unsupported or wrong cell profile schema")
    require(report.get("lane") == mode and report.get("capture", {}).get("mode") == mode,
            "report lane or capture mode differs from declared cell/schema")
    evidence = report.get("evidence")
    require(isinstance(evidence, dict), "missing capture evidence")

    admitted = evidence.get("discovery")
    require(isinstance(admitted, list) and any(
        isinstance(row, dict) and row.get("sha256") is not None and identity(row) == provider
        for row in admitted), "spied module not admitted")

    rows = report.get("functions")
    require(isinstance(rows, list), "missing functions")
    observed = {}
    for row in rows:
        owner = ownership(row)
        require(integer(row.get("calls")), "invalid function count")
        require(isinstance(row.get("names"), list) and
                all(isinstance(name, str) for name in row["names"]), "invalid function names")
        target = row.get("target")
        require(isinstance(target, dict), "invalid physical target")
        obj = target.get("object")
        if obj is None:
            continue
        if identity(obj) != provider:
            continue
        calls = row["calls"]
        if calls == 0:
            continue
        require(owner == provider,
                "spied target row has a different publishing module: %s" % row["names"])
        names = row["names"]
        require(len(names) == 1 and names[0].startswith("C_") and names[0] != "C_",
                "spied row is not one attributable function: %s" % names)
        name = names[0]
        require("unknown" not in name,
                "spied row carries no attributable name: %s" % names)
        observed[name] = observed.get(name, 0) + calls

    for name in sorted(set(spy_counts) | set(observed) | {"C_GetFunctionList"}):
        ledger = spy_counts.get(name, 0)
        seen = observed.get(name, 0)
        if name == "C_GetFunctionList":
            require(seen == ledger + processes,
                    "spied C_GetFunctionList count %d differs from ledger %d plus %d processes"
                    % (seen, ledger, processes))
        elif name in ("C_GetInterface", "C_GetInterfaceList") and not exports[name]:
            require(seen == 0,
                    "spied %s count %d with no such export to forward to" % (name, seen))
        else:
            require(seen == ledger,
                    "spied %s count %d differs from spy ledger %d" % (name, seen, ledger))

    gaps = evidence.get("gap_classes", {})
    observation = gaps.get("observation", {})
    require(observation.get("status") in ("exact", "lossy"), "missing observation gap class")
    actual_causes = observation.get("causes")
    require(isinstance(actual_causes, list) and all(isinstance(c, str) for c in actual_causes),
            "invalid observation causes")
    fixed = sorted(pinned_causes - set(actual_causes))
    new = sorted(set(actual_causes) - pinned_causes)

    pause = evidence.get("pause")
    require(pause in ("none", "sigstop", "partial"), "missing pause outcome")
    # The actual (cause set, pause) shape must equal the primary or one
    # alternate jointly; a mix of two shapes, or any third shape, fails
    # with the primary-relative diagnostic below.
    if (set(actual_causes), pause) not in [(pinned_causes, pinned_pause["status"])] + alternates:
        require(not fixed and not new,
                "observation causes differ from pin (fixed: %s; new: %s)"
                % (",".join(fixed) or "none", ",".join(new) or "none"))
        require(pause == pinned_pause["status"],
                "pause is %s, pinned %s" % (pause, pinned_pause["status"]))

    pairs = skipped_counts(evidence)
    p11kit = sorted(count for name, count in pairs
                    if isinstance(name, str) and "p11-kit" in name)
    if pinned_skip is None:
        require(not p11kit, "unpinned p11-kit capacity skip names: %s" % p11kit)
    else:
        require(p11kit == [pinned_skip],
                "p11-kit skip names %s, pinned %d" % (p11kit, pinned_skip))
        installed = receipt.get("p11kit_version")
        require(installed == pinned_p11kit,
                "installed p11-kit %s differs from pinned %s" % (installed, pinned_p11kit))

    if mode == "metrics":
        skipped = evidence.get("modules_skipped")
        if pinned_skip is None:
            require(skipped == [], "metrics twin skipped modules: %s" % skipped)
        else:
            # The p11-kit check above already requires exactly one p11-kit
            # capacity row naming the pinned count; here every remaining
            # row must be that same exempted closure row, nothing else.
            rest = [row for row in skipped
                    if not (isinstance(row.get("name"), str) and "p11-kit" in row["name"]
                            and skip_needed_count(row["reason"]) == pinned_skip)]
            require(rest == [], "metrics twin skipped modules: %s" % skipped)

    deviations = []
    if actual_causes:
        deviations.append("observation causes pinned: %s" % ",".join(sorted(actual_causes)))
    if pause != "sigstop":
        deviations.append("pause pinned %s (%s; %s)"
                          % (pause, pinned_pause["reason"], pinned_pause["owner"]))
    if pinned_skip is not None:
        deviations.append("p11-kit skip pinned at %d endpoints" % pinned_skip)
    others = sorted("%s=%d" % (name.rsplit("/", 1)[-1] if isinstance(name, str) else "?",
                                       count)
                    for name, count in pairs
                    if not (isinstance(name, str) and "p11-kit" in name))
    if others:
        deviations.append("other capacity skips: %s" % ",".join(others))
    if deviations:
        return "expected-failure", "; ".join(deviations)
    return "qualified", ("spied counts match the independent ledger; "
                         "pause confirmed; no observation gaps")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("report", "spy", "receipt", "expect", "cell"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args(argv)
    result = {"cell": args.cell, "pass": False, "detail": "", "qualification": "failed"}
    try:
        qualification, detail = judge(read(Path(args.report)), read(Path(args.spy)),
                                      parse(read(Path(args.receipt))),
                                      parse(read(Path(args.expect))), args.cell)
        result.update({"pass": True, "qualification": qualification, "detail": detail})
        code = 0 if qualification == "qualified" else 3
    except HarnessError as error:
        result["detail"] = "harness: " + str(error)
        code = 2
    except (EvidenceError, OSError, ValueError, TypeError, KeyError,
            AttributeError, AssertionError) as error:
        result["detail"] = str(error)
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
