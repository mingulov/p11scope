#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Conservation checks for the short-lived key-operations cell.

scripts/ci/key-operations-shortlived.sh runs N short-lived SoftHSM
signers under `inventory --system --key-operations` and judges two
rows from the observer JSON:

* shortlived-shaped: the cell exercised the miss path (fixture
  callers discovered, all retired, at least one missed its rows).
* shortlived-counted: the two terminal gaps conserve the recomputed
  miss counts within ambient headroom.

The oracle recomputes the expected counts from the published
callers/edges/instances/semantic_edges records, independently of the
observer implementation: a fixture record the observer missed must
appear in exactly one of the two terminal gaps, and ambient
(non-fixture) subset records bound how far the published counts may
legitimately exceed the fixture recomputation. No privilege, no
SoftHSM, no observer: pure functions over a parsed doc. Suite:
tests/python/test_key_operations_shortlived.py.
"""
import json
import re

NEVER_ADMITTED_SUBJECT = "callers never admitted"
WITHOUT_JOINS_SUBJECT = "admitted callers with no joined calls"

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
    (ambient headroom for each gap) and G1/G2 (published gap counts,
    None when the gap row is absent). Raises ValueError when the doc
    is missing or unparsable.
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
        else:
            exp["A1"] += e1
            exp["A2"] += e2
    return exp


def check_shaped(exp, floor=1):
    """Vacuity and shape: discovered, all retired, miss path hit."""
    if exp["suppressed"] > 0:
        return False, (
            f"gap suppression active ({exp['suppressed']} dropped): "
            "terminal gaps may be missing")
    if exp["D"] < 1:
        return False, f"no fixture caller records discovered (D={exp['D']})"
    if exp["D_retired"] != exp["D"]:
        return False, (
            f"fixture shape incomplete: {exp['D_retired']}/{exp['D']} retired")
    missed = exp["E1"] + exp["E2"]
    if missed < floor:
        return False, (
            f"miss path not exercised: {missed} missed fixture caller(s), "
            f"floor {floor} (every short-lived caller rowed)")
    return True, (
        f"D={exp['D']} retired, E1={exp['E1']} never-admitted, "
        f"E2={exp['E2']} without-joins")


def check_counted(exp):
    """Gap conservation within ambient headroom (absent reads as 0)."""
    problems = []
    for name, gkey, ekey, akey in (
            ("never-admitted", "G1", "E1", "A1"),
            ("without-joins", "G2", "E2", "A2")):
        published = exp[gkey] if exp[gkey] is not None else 0
        low, high = exp[ekey], exp[ekey] + exp[akey]
        if published < low:
            problems.append(
                f"{name}: published {published} below fixture {low}")
        elif published > high:
            problems.append(
                f"{name}: published {published} above fixture+ambient {high}")
    if problems:
        return False, "; ".join(problems)
    g1 = exp["G1"] if exp["G1"] is not None else 0
    g2 = exp["G2"] if exp["G2"] is not None else 0
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
