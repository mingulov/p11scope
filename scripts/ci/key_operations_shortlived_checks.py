#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Conservation checks for the short-lived key-operations cell.

scripts/ci/key-operations-shortlived.sh runs N short-lived SoftHSM
signers under `inventory --system --key-operations` and judges two
rows from the observer JSON:

* shortlived-shaped: fixture callers discovered, all retired, and
  every one either rowed or counted in a named gap (conservation;
  no miss is required, so a future admission fix passes this row).
* shortlived-counted: the terminal gaps conserve the recomputed
  miss counts within ambient headroom, with the never-admitted and
  refused gaps conserved as one union.

The oracle recomputes the expected counts from the published
callers/edges/instances/semantic_edges records, independently of the
observer implementation: a fixture record the observer missed must
appear in exactly one of the terminal gaps, and ambient
(non-fixture) subset records bound how far the published counts may
legitimately exceed the fixture recomputation. The oracle cannot
split the never-admitted and refused gaps per caller (the refusal
mark is internal), so the counted row conserves their union. No
privilege, no SoftHSM, no observer: pure functions over a parsed
doc. Suite: tests/python/test_key_operations_shortlived.py.
"""
import json
import re

NEVER_ADMITTED_SUBJECT = "callers never admitted"
WITHOUT_JOINS_SUBJECT = "admitted callers with no joined calls"
REFUSED_SUBJECT = "callers refused admission"

_COUNT_PREFIX = re.compile(r"\s*(\d+)\b")


def gap_count(doc, subject):
    """Published count for a terminal gap subject, or None if absent.

    The terminal gaps stage at most once per run; the first matching
    row wins. A row whose reason carries no leading integer reads as
    None (unparsable, never zero).
    """
    if not isinstance(doc, dict):
        return None
    gaps = doc.get("gaps")
    if not isinstance(gaps, list):
        return None
    for gap in gaps:
        if not isinstance(gap, dict):
            continue
        if gap.get("subject") != subject:
            continue
        reason = gap.get("reason")
        if not isinstance(reason, str):
            return None
        match = _COUNT_PREFIX.match(reason)
        return int(match.group(1)) if match else None
    return None


def _caller_exe(caller):
    image = caller.get("image") or {}
    exe = image.get("exe") or {}
    return exe.get("path")


def expectations(doc, fixture_path, provider_path):
    """Recompute the miss counts from the published records.

    Returns a dict with D (fixture records discovered), D_retired,
    E1/E2 (fixture never-admitted/without-joins expectations), A1/A2
    (ambient headroom for each gap), G1/G2/G3 (published gap counts,
    None when the gap row is absent) and unaccounted (retired fixture
    caller ids neither rowed nor in E1/E2 shape, in doc order).
    Raises ValueError when the doc is missing or unparsable.
    """
    if not isinstance(doc, dict):
        raise ValueError("missing or unparsable observer doc")
    for key in ("callers", "edges", "instances", "semantic_edges", "modules"):
        if not isinstance(doc.get(key), list):
            raise ValueError(f"missing or unparsable observer doc: {key!r}")
    subset = {
        module.get("id")
        for module in doc["modules"]
        if isinstance(module, dict)
        and isinstance(module.get("paths"), list)
        and provider_path in module["paths"]
    }
    callers = {}
    for caller in doc["callers"]:
        if not isinstance(caller, dict) or "id" not in caller:
            continue
        callers[caller["id"]] = {
            "retired": bool(caller.get("retired")),
            "fixture": _caller_exe(caller) == fixture_path,
        }
    edged = {}
    for edge in doc["edges"]:
        if not isinstance(edge, dict):
            continue
        if edge.get("module") in subset:
            edged.setdefault(edge.get("caller"), set()).add(edge["module"])
    instanced = {}
    for instance in doc["instances"]:
        if not isinstance(instance, dict):
            continue
        if instance.get("module") in subset:
            instanced.setdefault(instance.get("caller"), set()).add(
                instance["module"])
    joined = set()
    for row in doc["semantic_edges"]:
        if not isinstance(row, dict):
            continue
        returns = row.get("api_returns") or {}
        count = returns.get("count")
        if isinstance(count, int) and count > 0:
            joined.add(row.get("caller"))
    suppressed = doc.get("gaps_suppressed", 0)
    if not isinstance(suppressed, int):
        raise ValueError("missing or unparsable observer doc: gaps_suppressed")
    exp = {"D": 0, "D_retired": 0, "E1": 0, "E2": 0, "A1": 0, "A2": 0,
           "G1": gap_count(doc, NEVER_ADMITTED_SUBJECT),
           "G2": gap_count(doc, WITHOUT_JOINS_SUBJECT),
           "G3": gap_count(doc, REFUSED_SUBJECT),
           "unaccounted": [],
           "suppressed": suppressed}
    for cid, record in callers.items():
        if record["fixture"]:
            exp["D"] += 1
        if not record["retired"]:
            continue
        if record["fixture"]:
            exp["D_retired"] += 1
        e1 = cid in edged and cid not in instanced
        e2 = cid in instanced and cid not in joined
        if record["fixture"]:
            exp["E1"] += e1
            exp["E2"] += e2
            if not e1 and not e2 and cid not in joined:
                exp["unaccounted"].append(cid)
        else:
            exp["A1"] += e1
            exp["A2"] += e2
    return exp


def check_shaped(exp):
    """Shape and conservation: discovered, all retired, every fixture
    caller either rowed or counted in a named gap. No miss is
    required: a future admission fix that rows every caller passes.
    """
    if exp["suppressed"] > 0:
        return False, (
            f"gap suppression active ({exp['suppressed']} dropped): "
            "terminal gaps may be missing")
    if exp["D"] < 1:
        return False, f"no fixture caller records discovered (D={exp['D']})"
    if exp["D_retired"] != exp["D"]:
        return False, (
            f"fixture shape incomplete: {exp['D_retired']}/{exp['D']} retired")
    unaccounted = exp.get("unaccounted") or []
    if unaccounted:
        names = ", ".join(str(cid) for cid in unaccounted)
        return False, (
            f"conservation violated: {len(unaccounted)} fixture caller(s) "
            f"neither shown nor counted in a named gap: {names}")
    return True, (
        f"D={exp['D']} retired, E1={exp['E1']} never-admitted, "
        f"E2={exp['E2']} without-joins")


def check_counted(exp):
    """Gap conservation within ambient headroom (absent reads as 0).

    The never-admitted and refused gaps partition the retired
    edged-but-uninstanced callers, which the oracle cannot split per
    caller, so their union conserves E1 within ambient headroom.
    """
    problems = []
    g1 = exp["G1"] if exp["G1"] is not None else 0
    g3 = exp.get("G3") if exp.get("G3") is not None else 0
    union, low, high = g1 + g3, exp["E1"], exp["E1"] + exp["A1"]
    if union < low:
        problems.append(
            f"never-admitted+refused: published {union} below fixture {low}")
    elif union > high:
        problems.append(
            f"never-admitted+refused: published {union} "
            f"above fixture+ambient {high}")
    g2 = exp["G2"] if exp["G2"] is not None else 0
    low2, high2 = exp["E2"], exp["E2"] + exp["A2"]
    if g2 < low2:
        problems.append(
            f"without-joins: published {g2} below fixture {low2}")
    elif g2 > high2:
        problems.append(
            f"without-joins: published {g2} above fixture+ambient {high2}")
    if problems:
        return False, "; ".join(problems)
    if g3:
        return True, (
            f"G1+G3={union} in [{exp['E1']}, {exp['E1'] + exp['A1']}] "
            f"(G1={g1} never-admitted, G3={g3} refused), "
            f"G2={g2} in [{exp['E2']}, {exp['E2'] + exp['A2']}]")
    return True, (
        f"G1={g1} in [{exp['E1']}, {exp['E1'] + exp['A1']}], "
        f"G2={g2} in [{exp['E2']}, {exp['E2'] + exp['A2']}]")


def _one_line(text):
    return " ".join(str(text).split())


def main(argv):
    # --judge OUT_JSON SIGNER PROVIDER SPAWNED SIGN_FAIL OBS_EXIT:
    # print shaped_pass, shaped_detail, counted_pass, counted_detail.
    if len(argv) != 7 or argv[0] != "--judge":
        raise SystemExit("usage: key_operations_shortlived_checks.py "
                         "--judge OUT_JSON SIGNER PROVIDER SPAWNED "
                         "SIGN_FAIL OBS_EXIT")
    _, out_path, signer, provider, spawned, sign_fail, obs_exit = argv
    try:
        with open(out_path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        doc = None
    if int(sign_fail) > 0:
        shaped = (False, f"{sign_fail} signer failure(s)")
    elif int(obs_exit) != 0:
        shaped = (False, f"observer exit {obs_exit}")
    elif doc is None:
        shaped = (False, "missing or unparsable observer doc")
    else:
        try:
            shaped = check_shaped(expectations(doc, signer, provider))
        except ValueError as exc:
            shaped = (False, str(exc))
    if doc is None:
        counted = (False, "missing or unparsable observer doc")
    else:
        try:
            counted = check_counted(expectations(doc, signer, provider))
        except ValueError as exc:
            counted = (False, str(exc))
    print(1 if shaped[0] else 0)
    print(_one_line(f"spawned={spawned} {shaped[1]}"))
    print(1 if counted[0] else 0)
    print(_one_line(counted[1]))


if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
