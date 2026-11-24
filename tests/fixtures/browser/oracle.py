# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Oracles for the G33 browser cells.

Each ``check_*`` takes a ``cells.CellResult``, the parsed report, the
server ground truth, and the expected module identity, and returns a list
of failure strings (empty means the cell passed). Expectations are
minimums over exact observed counts, never exact equalities: browsers are
allowed to call more (version drift), never less than the calibrated
floor, and silent cells (zero calls where traffic is mandatory) always
fail. Verdicts are asserted structurally (schema, module identity, zero
event loss, probes attached) rather than by ``COMPLETE``: scan-path
captures without operator manifests report ``PARTIAL`` with
``attribution_only`` (counts exact, names withheld) or ``concrete_gap``
(window caveats), and the oracle pins which one each cell earned.
Observation gaps are allowlisted per cell (only causes that provably do
not affect the asserted property), kernel capture failures fail every
cell, and absence checks count entered-but-unreturned calls and refuse
unattributed rows.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "p11scope/observed-profile/v3"


class OracleError(RuntimeError):
    """The report itself is unreadable (not a cell failure)."""


def load_report(path: Path) -> dict[str, Any]:
    """Parse an observed-profile report and pin its schema."""
    try:
        report = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise OracleError(f"cannot parse {path}: {exc}") from exc
    if report.get("schema") != SCHEMA:
        raise OracleError(f"{path}: schema {report.get('schema')!r} != {SCHEMA!r}")
    return report


def sha256_of(path: Path) -> str:
    """Content hash of the provider file (module identity anchor)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def module_counts(report: dict[str, Any], module_sha: str) -> dict[str, int]:
    """Sum completed ``calls`` per function name for rows into ``module_sha``.

    Rows are matched by the pinned object identity
    (``target.object.sha256``), never by name alone; a retired-and-reattached
    target contributes one row per cell, so counts sum across rows. Rows no
    authorized source named (``["unknown"]``, empty, or missing names) are
    bucketed under ``"unknown"`` so unattributed activity can never hide
    behind a missing label.
    """
    counts: dict[str, int] = {}
    for row in report.get("functions", []):
        target = row.get("target") or {}
        obj = target.get("object") or {}
        if obj.get("sha256") != module_sha:
            continue
        calls = row.get("calls") or 0
        for name in row.get("names") or ["unknown"]:
            counts[name] = counts.get(name, 0) + calls
    return counts


def module_open_entries(report: dict[str, Any], module_sha: str) -> dict[str, int]:
    """Sum ``in_flight`` (entries minus returns) per name for ``module_sha``.

    Same row matching and ``"unknown"`` bucketing as module_counts.
    Absence checks read this beside the return counts: an entered call
    happened even when its return never arrived.
    """
    opened: dict[str, int] = {}
    for row in report.get("functions", []):
        target = row.get("target") or {}
        obj = target.get("object") or {}
        if obj.get("sha256") != module_sha:
            continue
        entries = row.get("in_flight") or 0
        for name in row.get("names") or ["unknown"]:
            opened[name] = opened.get(name, 0) + entries
    return opened


def evidence(report: dict[str, Any]) -> dict[str, Any]:
    """The report's evidence block (gap classes, verdict, loss counters)."""
    return report.get("evidence", {})


def check_no_event_loss(report: dict[str, Any]) -> list[str]:
    """The capture recorded no event loss (counts are not lower bounds)."""
    failures = []
    loss = evidence(report).get("event_loss", 0) or 0
    if loss != 0:
        failures.append(f"event_loss={loss}, want 0")
    return failures


def check_attached(report: dict[str, Any]) -> list[str]:
    """At least one probe attached (the module was seen and hooked)."""
    failures = []
    attached = evidence(report).get("attached_probes", 0) or 0
    if attached < 1:
        failures.append(f"attached_probes={attached}, want >= 1")
    return failures


def check_min_counts(counts: dict[str, int], floors: dict[str, int]) -> list[str]:
    """Every floored function was observed at least its minimum."""
    failures = []
    for name, floor in floors.items():
        observed = counts.get(name, 0)
        if observed < floor:
            failures.append(f"{name}: observed {observed}, want >= {floor}")
    return failures


def check_zero_counts(counts: dict[str, int],
                      open_entries: dict[str, int] | None = None) -> list[str]:
    """No calls or open entries were observed for the module (absence twin)."""
    failures = []
    returned = sum(counts.values())
    opened = sum((open_entries or {}).values())
    total = returned + opened
    if total != 0:
        failures.append(
            f"observed {total} calls/entries, want 0 "
            f"(returned={returned} open={opened} counts={counts})")
    return failures


def check_absent(counts: dict[str, int], names: tuple[str, ...],
                 open_entries: dict[str, int] | None = None) -> list[str]:
    """Named functions were never called (boundary pins amid noisy traffic).

    ``open_entries`` (from module_open_entries) counts entered-but-unreturned
    calls per name; an in-flight forbidden call crossed the boundary even
    though it never returned. Rows no authorized source named (the
    ``"unknown"`` bucket, returned or open) fail every absence: a forbidden
    call could be hiding in unattributed activity.
    """
    failures = []
    opened = open_entries or {}
    for name in names:
        observed = counts.get(name, 0)
        if observed != 0:
            failures.append(f"{name}: observed {observed}, want 0 (boundary crossed?)")
        entered = opened.get(name, 0)
        if entered != 0:
            failures.append(
                f"{name}: {entered} entered but unreturned "
                f"(in-flight at end) (boundary crossed?)")
    unattributed = counts.get("unknown", 0) + opened.get("unknown", 0)
    if unattributed != 0:
        failures.append(
            f"unknown: {unattributed} unattributed calls/entries hide "
            f"{list(names)} (absence unprovable)")
    return failures


def check_function_rows_typed(report: dict[str, Any]) -> list[str]:
    """Every functions[] row carries typed counts and name lists.

    The counters read ``calls``/``in_flight`` with ``or 0``: a JSON
    boolean or float would silently count (``True`` is ``1``), and a
    string ``names`` would bucket per character. Each row must be an
    object whose ``calls``/``in_flight`` are missing, null, or u64
    (booleans are not counters), whose ``names`` is missing, null, or
    a list of strings (missing or empty still buckets under
    ``"unknown"``), and whose ``target``/``object`` navigation is
    missing, null, or an object. A malformed row fails: floors over
    untyped rows could pass on a boolean.
    """
    failures = []
    functions = report.get("functions")
    if functions is None:
        return []
    if not isinstance(functions, list):
        return ["functions section is not a list"]
    for index, row in enumerate(functions):
        if not isinstance(row, dict):
            failures.append(f"functions[{index}] is not an object")
            continue
        target = row.get("target")
        if target is not None and not isinstance(target, dict):
            failures.append(f"functions[{index}].target is not an object")
            continue
        obj = (target or {}).get("object")
        if obj is not None and not isinstance(obj, dict):
            failures.append(f"functions[{index}].target.object is not an object")
            continue
        for key in ("calls", "in_flight"):
            value = row.get(key)
            if value is not None and not _u64(value):
                failures.append(
                    f"functions[{index}].{key}={value!r}: want a u64 counter")
        names = row.get("names")
        if names is not None and (
                not isinstance(names, list)
                or not all(isinstance(name, str) for name in names)):
            failures.append(
                f"functions[{index}].names={names!r}: want a list of strings")
    return failures


def check_exact_counts(counts: dict[str, int],
                       expected: dict[str, int]) -> list[str]:
    """Named functions were observed exactly their expected counts.

    Floors allow silent overcounts (duplicate records); exactness ties
    each completed count to independent ground truth (one sign pair per
    TLS handshake). Missing names read as zero.
    """
    failures = []
    for name, want in expected.items():
        observed = counts.get(name, 0)
        if observed != want:
            failures.append(f"{name}: observed {observed}, want exactly {want}")
    return failures


def check_zero_open_entries(opened: dict[str, int],
                            names: tuple[str, ...]) -> list[str]:
    """Named functions have no entered-but-unreturned calls at end.

    Completed counts alone cannot see a surplus call still in flight;
    the pair (completed exact, in-flight zero) closes it.
    """
    failures = []
    for name in names:
        entered = opened.get(name, 0)
        if entered != 0:
            failures.append(
                f"{name}: {entered} entered but unreturned "
                f"(in-flight at end)")
    return failures


def check_no_cross_function_alias(report: dict[str, Any], module_shas,
                                  pairs: tuple[tuple[str, str], ...]) -> list[str]:
    """No single row claims both names of an asserted pair.

    The counters add a row's calls to every name it lists, so one
    aliased row could satisfy two floors with a single call. Distinct
    PKCS#11 functions never share a slot address in a real report, so
    a row naming both halves of a pair is malformed: the pair must
    come from distinct rows. Only rows attributed to ``module_shas``
    are judged.
    """
    failures = []
    shas = set(module_shas)
    for row in report.get("functions") or []:
        if not isinstance(row, dict):
            continue
        target = row.get("target") or {}
        obj = target.get("object") or {} if isinstance(target, dict) else {}
        if not isinstance(obj, dict) or obj.get("sha256") not in shas:
            continue
        names = row.get("names") or []
        if not isinstance(names, list):
            continue
        for first, second in pairs:
            if first in names and second in names:
                failures.append(
                    f"row names both {first} and {second}: one aliased row "
                    f"cannot prove two functions")
    return failures


def check_observation_gaps(report: dict[str, Any], allowed) -> list[str]:
    """Every observation gap cause is explicitly allowed for this cell.

    ``allowed`` names the causes that provably do not affect the cell's
    asserted property (per-cell table in the suite); any other cause fails.
    A missing ``gap_classes.observation`` block fails closed: coverage that
    cannot be verified is not coverage.
    """
    failures = []
    classes = evidence(report).get("gap_classes")
    if not isinstance(classes, dict) or "observation" not in classes:
        return ["gap_classes.observation missing: cannot verify observation coverage"]
    observation = classes["observation"] or {}
    causes = observation.get("causes") or []
    allowed_set = set(allowed)
    for cause in causes:
        if cause not in allowed_set:
            failures.append(
                f"observation gap cause {cause!r} not allowed for this cell "
                f"(allowed: {sorted(allowed_set)})")
    return failures


#: The one gap cause the never-mapped-run cell (FF-NOMOD) qualifies
#: through the gate below (controller ruling 2026-11-09): task-level
#: exit tracking for run-tree members lives in the shared link registry
#: beside zero module probes, so a mid-flow teardown race can count a
#: link loss while the asserted property (no module ever mapped — zero
#: rows, zero probes) still holds.
NOMOD_QUALIFIED_LINK_LOSS = "task_uprobe_link_losses"


def check_observation_gaps_nomod_qualified(report: dict[str, Any], allowed) -> list[str]:
    """FF-NOMOD gap check: the named link loss is qualified, all else fails.

    Behaves exactly like check_observation_gaps except that a sole
    ``task_uprobe_link_losses`` cause beyond ``allowed`` passes when the
    asserted never-mapped property is intact: zero attached probes AND
    zero function rows. Any other gap cause, any attached probe, or any
    row falls back to the fail-closed verdict, as does a missing
    ``gap_classes.observation`` block. Only the FF-NOMOD cell takes this
    path; every other cell keeps calling check_observation_gaps.
    """
    failures = []
    classes = evidence(report).get("gap_classes")
    if not isinstance(classes, dict) or "observation" not in classes:
        return ["gap_classes.observation missing: cannot verify observation coverage"]
    observation = classes["observation"] or {}
    causes = observation.get("causes") or []
    allowed_set = set(allowed)
    extra = [cause for cause in causes if cause not in allowed_set]
    if (len(extra) == 1 and extra[0] == NOMOD_QUALIFIED_LINK_LOSS
            and (evidence(report).get("attached_probes", 0) or 0) == 0
            and len(report.get("functions") or []) == 0):
        return []
    for cause in causes:
        if cause not in allowed_set:
            failures.append(
                f"observation gap cause {cause!r} not allowed for this cell "
                f"(allowed: {sorted(allowed_set)})")
    return failures


def check_capture_intact(report: dict[str, Any]) -> list[str]:
    """No kernel capture failure truncated or refused the observation.

    A halted capture (owner poison), refused owner admissions, unavailable
    identities, or root affiliation failures mean calls after some moment
    were never counted; the cell's window is void for floors and absences
    alike. Healthy runs keep every counter at zero. A missing
    ``kernel_control`` block fails closed (v3 always carries it).
    """
    failures = []
    control = evidence(report).get("kernel_control")
    if not isinstance(control, dict):
        return ["kernel_control missing: cannot verify capture integrity"]
    if control.get("capture_halted"):
        failures.append(
            f"capture_halted with owner_poison={control.get('owner_poison')}: "
            f"calls after the halt were never counted")
    for key in ("owner_admission_failures", "identity_unavailable"):
        value = control.get(key) or 0
        if value != 0:
            failures.append(
                f"kernel_control.{key}={value}, want 0 (refused/lost call accounting)")
    refused = control.get("root_affiliation_failures") or []
    if refused:
        failures.append(
            f"kernel_control.root_affiliation_failures={refused}: "
            f"discovery attribution incomplete")
    return failures


#: Skipped-record reasons that carry no coverage gap: NULL table entries
#: (never callable) and discovery subjects skipped because the module was
#: never mapped (the structural never-mapped shape).
STRUCTURAL_SKIPPED_REASONS = frozenset({"null pointer", "discovery unavailable"})


def check_skipped_structural(report: dict[str, Any]) -> list[str]:
    """Every skipped record is structural, never a detach-coverage gap.

    Static detach history retains observation loss through the ``skipped``
    cause even after exact pairs reattach: calls during the gap may be
    missing. Never-mapped cells allow the ``skipped`` cause only when every
    record is structural (checked here, beside the cause allowance).
    """
    failures = []
    for record in evidence(report).get("skipped") or []:
        reason = (record or {}).get("reason")
        if reason not in STRUCTURAL_SKIPPED_REASONS:
            failures.append(
                f"skipped record {(record or {}).get('name')!r} reason {reason!r}: "
                f"possible coverage gap, want structural only")
    return failures


#: The one learned-file reason a run-floor cell tolerates: the
#: provider was first used before the pre-attach scan learned it
#: (src/render.rs LEARNED_FIRST_RUN_REASON, verbatim). Every other
#: learned-file reason (overflow, caps, unbound tables, unavailable
#: learning, replaced files) stays refused: each hides unbounded loss.
LEARNED_FIRST_USE_REASON = (
    "a provider file was learned after its first use; "
    "its earlier calls were not observed")

#: Short-lived run-tree children that exited while discovery still
#: walked them (src/render.rs MID_FLIGHT_REASON, verbatim).
MID_FLIGHT_REASON = "process exited mid-flight"


def check_skipped_run_floor(report: dict[str, Any]) -> list[str]:
    """Skipped records a run-mode floor cell provably survives.

    Beside the structural reasons (shared with the base check), two
    run-tree timing classes pass: subjects that exited mid-flight
    (owned short-lived descendants retiring between admission passes)
    and the single learned-first-use record (the pre-attach window the
    run-sign cells close with a spawn delay and CR-RUN-NODELAY holds
    with the first-map stop; window loss can only undercount, never
    invent a sign). Any other record — a retire window, a detach gap,
    another learned-file reason — fails: it could hide the asserted
    signs.
    """
    failures = []
    for record in evidence(report).get("skipped") or []:
        record = record or {}
        name = record.get("name")
        reason = record.get("reason")
        if reason in STRUCTURAL_SKIPPED_REASONS:
            continue
        if name == "discovery subject" and reason == MID_FLIGHT_REASON:
            continue
        if (name == "learned provider file"
                and reason == LEARNED_FIRST_USE_REASON):
            continue
        failures.append(
            f"skipped record {name!r} reason {reason!r}: "
            f"possible coverage gap, want run-floor timing only")
    return failures


def check_verdict(report: dict[str, Any], allowed: tuple[str, ...]) -> list[str]:
    """The verdict detail is one the cell earned during calibration."""
    failures = []
    detail = evidence(report).get("verdict_detail")
    if detail not in allowed:
        failures.append(f"verdict_detail={detail!r}, want one of {list(allowed)}")
    return failures


# Floor tables, calibrated on the dev host (Playwright Firefox 157 /
# Chromium 156, SoftHSM 2.6.1) with background network activity stabilized
# out during calibration (stabilized-vs-unstabilized comparison plus
# trace-timestamp correlation for FF-STARTUP). Per-run floors reproduce
# the calibrated flow-caused shape and sit far below typical counts
# (FF-STARTUP sees C_FindObjects x26), so version drift adds calls
# without breaking the cell; only silence fails.
FF_STARTUP_FLOORS = {
    "C_FindObjectsInit": 1,
    "C_FindObjects": 1,
    "C_FindObjectsFinal": 1,
    "C_GetSessionInfo": 1,
}
# Chromium enumerates the registered provider stably (x5/x5/x5 on every
# run, both flows): the token is demonstrably reachable while private
# operations stay absent.
CR_ENUMERATION_FLOORS = {
    "C_FindObjectsInit": 1,
    "C_FindObjects": 1,
    "C_FindObjectsFinal": 1,
}
# There are deliberately no FF-PINBOUND floors: Firefox stalls at the
# interactive-PIN boundary with racy selection enumeration (x0 or x16
# across runs), so only the login/signing absences are pinned.

#: Top-level report keys that would publish object facts. Profile never
#: publishes them (key-operation browser populations are 0.6.0); their
#: presence fails the S1 proof below.
JOINT_CONTENT_KEYS = ("object_observations", "key_operations",
                      "unknown_key_operations")

#: S1 session counters rendered by the profile lane (render.rs
#: SessionsOut); balance is opened+inherited-closed with saturation.
SESSION_COUNTERS = ("opened", "inherited", "closed", "async_opened",
                    "peak_concurrent", "balance")

MAX_U64 = (1 << 64) - 1


def _u64(value: Any) -> bool:
    """A JSON u64 counter (booleans are not counters)."""
    return type(value) is int and 0 <= value <= MAX_U64


def check_no_joint_content(report: dict[str, Any]) -> list[str]:
    """The report publishes no object facts (the S1-active negative half).

    Key-operation browser populations arrive in 0.6.0; a v0.5.0
    profile report carrying a Joint section fails instead of passing
    with the S1 checks blind to it.
    """
    failures = []
    for key in JOINT_CONTENT_KEYS:
        if key in report:
            failures.append(
                f"report carries top-level {key!r}: profile never publishes "
                f"object facts")
    return failures


def check_s1_mechanisms_absent(report: dict[str, Any]) -> list[str]:
    """No mechanism-attributed calls happened in the enumeration flow.

    Enumeration (slot/token/object discovery) never initializes an
    operation, so the S1 mechanisms section must be present and empty;
    a missing section fails closed (use is then unverifiable).
    """
    if "mechanisms" not in report:
        return ["mechanisms section missing: cannot verify S1 mechanism use"]
    mechanisms = report["mechanisms"]
    if not isinstance(mechanisms, list):
        return ["mechanisms section is not a list"]
    failures = []
    for entry in mechanisms:
        if isinstance(entry, dict) and _u64(entry.get("mechanism")):
            detail = ""
            if _u64(entry.get("calls")) and _u64(entry.get("errors")):
                detail = (f" (calls={entry['calls']}"
                          f" errors={entry['errors']})")
            failures.append(
                f"mechanism 0x{entry['mechanism']:x} used by an enumeration "
                f"flow, want none{detail}")
        else:
            failures.append("mechanisms section carries a malformed entry")
    return failures


#: Operation categories the product attributes to a mechanism row
#: (src/semantics.rs OPERATIONS): the family-sign leg requires "sign".
SIGN_OPS = frozenset({"sign"})


def check_s1_sign_mechanisms(report: dict[str, Any], module_shas,
                             family_ids, min_calls: int,
                             exact_calls: int | None = None) -> list[str]:
    """Family sign mechanisms attributed to the module reach the floor.

    ``module_shas`` is the discovery-resolved identity set of the signing
    provider (one sha, or several for a copy-up pair); ``family_ids``
    the closed numeric family (the product's own keymeta table mirror);
    ``min_calls`` the attributed-call floor. Only ``by_module`` calls
    whose module sha is in the set count: row totals without attribution
    are unprovable and fail closed, as do a missing section, a non-list
    section, and any malformed entry (the v3 schema always renders
    ``mechanism``/``calls``/``errors`` u64s plus a ``by_module`` list).
    A family entry that contributes attributed calls must also show
    signing use in its row-wide ``ops`` (a list containing ``"sign"``):
    ``ops`` is row-wide while ``by_module`` partitions counts, so this
    leg is sound only on the narrowed single-provider scan, where the
    row's operations are the module's. A contributing entry with
    missing, non-list, or sign-free ``ops`` (an encrypt-only RSA row)
    fails: the family id alone never proves a sign happened.
    ``exact_calls`` (None for a floor-only leg) pins the attributed
    total exactly: duplicate mechanism records then fail instead of
    passing a floor.
    """
    if "mechanisms" not in report:
        return ["mechanisms section missing: cannot verify sign mechanisms"]
    mechanisms = report["mechanisms"]
    if not isinstance(mechanisms, list):
        return ["mechanisms section is not a list"]
    shas = set(module_shas)
    ids = set(family_ids)
    total = 0
    for entry in mechanisms:
        if not isinstance(entry, dict):
            return ["mechanisms section carries a malformed entry"]
        if not _u64(entry.get("mechanism")):
            return ["mechanisms section carries a malformed entry"]
        by_module = entry.get("by_module")
        if not isinstance(by_module, list):
            return ["mechanisms section carries a malformed entry"]
        if entry["mechanism"] not in ids:
            continue
        attributed = 0
        for part in by_module:
            if not isinstance(part, dict):
                return ["mechanisms section carries a malformed entry"]
            module = part.get("module")
            if not isinstance(module, dict):
                return ["mechanisms section carries a malformed entry"]
            if not _u64(part.get("calls")) or not _u64(part.get("errors")):
                return ["mechanisms section carries a malformed entry"]
            if module.get("sha256") in shas:
                attributed += part["calls"]
        if attributed > 0:
            ops = entry.get("ops")
            if (not isinstance(ops, list)
                    or not all(isinstance(op, str) for op in ops)
                    or SIGN_OPS.isdisjoint(ops)):
                return [f"mechanism 0x{entry['mechanism']:x} attributes "
                        f"{attributed} family calls without signing use "
                        f"(ops={ops!r}): cannot verify a sign happened"]
        total += attributed
    if exact_calls is not None:
        if total != exact_calls:
            return [f"family sign mechanisms attributed to the module: "
                    f"observed {total}, want exactly {exact_calls}"]
        return []
    if total < min_calls:
        return [f"family sign mechanisms attributed to the module: "
                f"observed {total}, want >= {min_calls}"]
    return []


def discovery_module_shas(report: dict[str, Any],
                          basename: str) -> tuple[set[str], list[str]]:
    """Sha256 set of discovery[] rows whose path basename is ``basename``.

    The run-sign cells resolve the signing provider's identity from the
    report's own discovery list (exact basename equality, never a
    substring), so no host path is hard-coded. Returns (shas, failures):
    a missing or non-list discovery list fails closed, as does a
    matching row with no usable digest (absent, non-string, or not
    64 lowercase hex) — loud, never a silent empty set the cell would
    misread as unmapped. Non-dict entries and non-matching rows carry
    no evidence either way and are skipped.
    """
    discovery = evidence(report).get("discovery")
    if not isinstance(discovery, list):
        return set(), ["evidence.discovery missing: cannot resolve "
                       f"the {basename} module identity"]
    shas: set[str] = set()
    for row in discovery:
        if not isinstance(row, dict):
            continue
        path = row.get("path")
        if not isinstance(path, str) or path.rsplit("/", 1)[-1] != basename:
            continue
        digest = row.get("sha256")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            return set(), [f"discovery row for {path} carries no usable "
                           f"sha256: cannot attribute its calls"]
        shas.add(digest)
    return shas, []


def check_discovery_shas_anchored(shas, known_shas, required_sha,
                                  basename: str) -> list[str]:
    """Discovery-resolved shas are files the cell hashed independently.

    ``shas`` is the report's discovery resolution for ``basename``
    (``discovery_module_shas``); ``known_shas`` the content hashes of
    the provider files the cell itself located on disk, and
    ``required_sha`` the observed module's hash among them. A coherent
    substitution — another digest under a same-basename path, with
    functions and S1 rows rewritten to match — would otherwise
    attribute counts to a file the run never mapped. Any resolved sha
    outside the known set fails, as does a missing observed module;
    a known file the run never mapped is fine (subset, not equality).
    """
    failures = []
    resolved, known = set(shas), set(known_shas)
    unknown = resolved - known
    if unknown:
        failures.append(
            f"discovery resolved {basename} shas the cell never hashed "
            f"on disk: {sorted(unknown)}")
    if required_sha not in resolved:
        failures.append(
            f"observed {basename} module (sha256 {required_sha}) never "
            f"discovered: cannot attribute its calls")
    return failures


def check_s1_logins_absent(report: dict[str, Any]) -> list[str]:
    """No login happened (the S1 login accounting is empty).

    A missing section fails closed, like the mechanisms section.
    """
    if "logins" not in report:
        return ["logins section missing: cannot verify S1 logins"]
    logins = report["logins"]
    if not isinstance(logins, dict):
        return ["logins section is not an object"]
    if logins:
        return [f"logins observed {logins}, want none (boundary crossed?)"]
    return []


def check_s1_sessions(report: dict[str, Any], opened_min: int = 0,
                      zero: bool = False) -> list[str]:
    """S1 session accounting balances, with a per-cell opened floor.

    The six counters must be present u64 values with
    balance == opened+inherited-closed (saturating, as rendered);
    ``opened_min`` floors sessions opened inside the capture window,
    and ``zero`` requires all counters at zero for never-mapped cells.
    A floored call needs a session, not an in-window open: attach-mode
    cells observe enumeration on sessions the browser opened at
    startup, strictly before capture, so they must leave ``opened_min``
    at zero.
    """
    if "sessions" not in report:
        return ["sessions section missing: cannot verify S1 sessions"]
    sessions = report["sessions"]
    if not isinstance(sessions, dict):
        return ["sessions section is not an object"]
    failures = []
    for name in SESSION_COUNTERS:
        if not _u64(sessions.get(name)):
            failures.append(f"sessions.{name} is not a u64 counter")
    if failures:
        return failures
    total = min(sessions["opened"] + sessions["inherited"], MAX_U64)
    balance = total - min(sessions["closed"], total)
    if sessions["balance"] != balance:
        failures.append(
            f"sessions balance {sessions['balance']} != opened "
            f"{sessions['opened']}+inherited {sessions['inherited']}-closed "
            f"{sessions['closed']}")
    if zero:
        for name in SESSION_COUNTERS:
            if sessions[name] != 0:
                failures.append(
                    f"sessions.{name}={sessions[name]}, want 0 "
                    f"(module never mapped)")
    elif sessions["opened"] < opened_min:
        failures.append(
            f"sessions.opened={sessions['opened']}, want >= {opened_min}")
    return failures
