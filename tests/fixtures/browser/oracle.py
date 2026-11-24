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


def check_skipped_run_exact(report: dict[str, Any], allowed) -> list[str]:
    """Every skipped record is an allowed (name, reason) pair, nothing else.

    Run-default cells honestly disclose spawn-window timing skips
    (short-lived discovery subjects that exit mid-flight); the pairs
    are a closed world calibrated per cell, so a new skip reason fails
    loud instead of widening the allowance silently.
    """
    failures = []
    allowed_set = set(allowed)
    for record in evidence(report).get("skipped") or []:
        pair = ((record or {}).get("name"), (record or {}).get("reason"))
        if pair not in allowed_set:
            failures.append(
                f"skipped record {pair[0]!r} reason {pair[1]!r}: outside "
                f"the calibrated run set")
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


#: RSA-PSS with SHA-256 (the TLS 1.3 CertificateVerify mechanism NSS
#: uses for a 2048-bit RSA client credential).
CKM_SHA256_RSA_PKCS_PSS = 0x43
#: HMAC with SHA-256 (the in-tree NSS seeding operation's mechanism).
CKM_SHA256_HMAC = 0x251


def check_mechanisms_present(report: dict[str, Any]) -> list[str]:
    """A mechanism-attributed call happened (the sign-cell S1 positive half).

    Sign cells assert mechanism presence with function linkage (see
    check_linkage_exact), so the mechanisms section must exist and be a
    non-empty list; a missing section fails closed, like the absent leg.
    """
    if "mechanisms" not in report:
        return ["mechanisms section missing: cannot verify S1 mechanism use"]
    mechanisms = report["mechanisms"]
    if not isinstance(mechanisms, list):
        return ["mechanisms section is not a list"]
    if not mechanisms:
        return ["mechanisms section empty: no mechanism-attributed call observed"]
    return []


def _linkage_cells(holder: dict[str, Any], label: str, mechanism: int,
                   scope: str) -> tuple[dict[str, dict[str, int]], list[str]]:
    """Strict typed read of one ``by_function`` linkage breakdown.

    Returns (cells, failures): ``cells`` maps function name to its
    ``{"calls", "errors"}`` counts. The holder (a mechanism row or
    one provider's ``by_module`` cell) must carry ``by_function`` (a
    missing field is the no-linkage failure, never a skip), a list
    of ``{"function", "calls", "errors"}`` objects with unique string
    names and u64 counters. Malformed input fails closed.
    """
    failures: list[str] = []
    cells: dict[str, dict[str, int]] = {}
    linkage = holder.get("by_function")
    if linkage is None:
        return cells, [f"{label}: no function x mechanism linkage "
                       f"(by_function missing on the 0x{mechanism:x} {scope})"]
    if not isinstance(linkage, list):
        return cells, [f"{label}: by_function is not a list"]
    for entry in linkage:
        if not isinstance(entry, dict):
            failures.append(f"{label}: by_function carries a malformed entry")
            continue
        name = entry.get("function")
        calls = entry.get("calls")
        errors = entry.get("errors")
        if not isinstance(name, str) or not name:
            failures.append(f"{label}: by_function entry without a function name")
            continue
        if name in cells:
            failures.append(f"{label}: by_function names {name!r} twice")
            continue
        if not _u64(calls) or not _u64(errors):
            failures.append(f"{label}: by_function[{name}] counters are not u64")
            continue
        cells[name] = {"calls": calls, "errors": errors}
    return cells, failures


def _check_linkage_tables(cells: dict[str, dict[str, int]],
                          totals: dict[str, Any], mechanism: int,
                          exact: dict[str, int], floors: dict[str, int],
                          label: str, unlisted: str, scope: str) -> list[str]:
    """Compare one linkage breakdown against its expected tables.

    Shared core behind the row and module checks: ``exact`` functions
    compare exactly, ``floors`` need only reach their minimum,
    unlisted cells follow ``unlisted`` (``"forbid"`` fails all,
    ``"allow_verify"`` permits ``C_Verify*``), errors pin at zero,
    and the cells must sum to the holder's own ``calls``/``errors``
    totals. ``scope`` nouns the holder in messages (``"row"`` or
    ``"module cell"``).
    """
    failures = []
    for name, want in exact.items():
        observed = cells.get(name, {}).get("calls", 0)
        if observed != want:
            failures.append(f"{label}: ({name} x 0x{mechanism:x}): observed "
                            f"{observed}, want exactly {want}")
    for name, floor in floors.items():
        observed = cells.get(name, {}).get("calls", 0)
        if observed < floor:
            failures.append(f"{label}: ({name} x 0x{mechanism:x}): observed "
                            f"{observed}, want >= {floor}")
    for name in cells:
        if name in exact or name in floors:
            continue
        if unlisted == "allow_verify" and name.startswith(_VERIFY_FAMILY_PREFIX):
            continue
        failures.append(f"{label}: ({name} x 0x{mechanism:x}): observed "
                        f"{cells[name]['calls']}, want exactly 0 "
                        f"(linkage outside the expected table)")
    if not _u64(totals.get("calls")) or not _u64(totals.get("errors")):
        failures.append(f"{label}: {scope} totals are not u64 counters")
        return failures
    if sum(cell["calls"] for cell in cells.values()) != totals["calls"]:
        failures.append(f"{label}: linkage cells sum to "
                        f"{sum(cell['calls'] for cell in cells.values())}, "
                        f"{scope} calls={totals['calls']} "
                        f"(linkage accounting drift?)")
    if sum(cell["errors"] for cell in cells.values()) != totals["errors"]:
        failures.append(f"{label}: linkage errors sum to "
                        f"{sum(cell['errors'] for cell in cells.values())}, "
                        f"{scope} errors={totals['errors']}")
    for name in list(exact) + list(floors):
        if name in cells and cells[name]["errors"] != 0:
            failures.append(f"{label}: ({name} x 0x{mechanism:x}): errors "
                            f"{cells[name]['errors']}, want 0")
    return failures


def _mechanism_row(report: dict[str, Any], mechanism: int) -> dict[str, Any] | None:
    """The mechanisms[] row for ``mechanism``, or None when missing."""
    for entry in report.get("mechanisms", []) or []:
        if isinstance(entry, dict) and entry.get("mechanism") == mechanism:
            return entry
    return None


def check_linkage_exact(report: dict[str, Any], mechanism: int,
                        exact: dict[str, int], label: str) -> list[str]:
    """The mechanism's function linkage equals ``exact`` (strict typed read).

    Every ``exact`` function must show exactly its count (returned
    calls; errors pinned at zero beside them), no other function may
    appear (an ``"unknown"`` cell hides linkage and fails), and the
    cells must sum to the row's own ``calls``/``errors`` totals (exact
    by construction: every attributed call carries exactly one cell).
    Missing row, missing linkage, malformed entries, and count
    mismatches all fail.
    """
    row = _mechanism_row(report, mechanism)
    if row is None:
        return [f"{label}: no mechanism row for 0x{mechanism:x}"]
    cells, failures = _linkage_cells(row, label, mechanism, "row")
    if failures:
        return failures
    return _check_linkage_tables(cells, row, mechanism, exact, {}, label,
                                 "forbid", "row")


#: Function-name prefix allowed past the expected table under the
#: ``allow_verify`` unlisted policy: server-driven verification legs
#: share the row with the asserted sign legs, and no sign-family call
#: can hide behind a ``C_Verify*`` name.
_VERIFY_FAMILY_PREFIX = "C_Verify"


def check_linkage_floored(report: dict[str, Any], mechanism: int,
                          exact: dict[str, int], floors: dict[str, int],
                          label: str, unlisted: str = "forbid") -> list[str]:
    """Like check_linkage_exact with racy-chunked legs floored, not pinned.

    ``exact`` functions compare exactly and every other named function
    must be absent, as above; ``floors`` functions need only reach
    their minimum (multipart update legs, whose per-run count follows
    transcript chunking). ``unlisted`` selects the rule for cells
    outside both tables: ``"forbid"`` fails them all (a single-family
    row), ``"allow_verify"`` additionally permits ``C_Verify*`` cells
    (server-driven verification sharing the row with the asserted
    sign legs — the sign family stays fully pinned, and ``"unknown"``
    still fails since it could hide sign legs). Anything else raises.
    The cell-sum and error-shape rules still apply: the cells sum
    exactly to the row totals, floors included.
    """
    if unlisted not in ("forbid", "allow_verify"):
        raise ValueError(f"{label}: unlisted={unlisted!r}, want forbid|allow_verify")
    row = _mechanism_row(report, mechanism)
    if row is None:
        return [f"{label}: no mechanism row for 0x{mechanism:x}"]
    cells, failures = _linkage_cells(row, label, mechanism, "row")
    if failures:
        return failures
    return _check_linkage_tables(cells, row, mechanism, exact, floors,
                                 label, unlisted, "row")


def check_module_linkage(report: dict[str, Any], mechanism: int,
                         module_sha: str, exact: dict[str, int],
                         floors: dict[str, int], label: str,
                         unlisted: str = "forbid") -> list[str]:
    """One provider's legs on a shared mechanism row equal the tables.

    Rows are shared (one mechanism id serves several providers), so
    row-level linkage cannot isolate one provider's legs; this check
    scopes to the ``by_module`` cell for ``module_sha`` and compares
    its inner ``by_function`` breakdown with the exact/floors/unlisted
    rules above. The inner cells must sum to the cell's own totals
    (exact by construction). A missing row, a missing module cell, a
    missing inner breakdown, and count mismatches all fail.
    """
    if unlisted not in ("forbid", "allow_verify"):
        raise ValueError(f"{label}: unlisted={unlisted!r}, want forbid|allow_verify")
    row = _mechanism_row(report, mechanism)
    if row is None:
        return [f"{label}: no mechanism row for 0x{mechanism:x}"]
    cell = None
    for candidate in row.get("by_module", []) or []:
        if not isinstance(candidate, dict):
            return [f"{label}: by_module carries a malformed entry"]
        module = candidate.get("module") or {}
        if module.get("sha256") == module_sha:
            cell = candidate
            break
    if cell is None:
        return [f"{label}: no by_module cell for the expected module "
                f"on the 0x{mechanism:x} row"]
    cells, failures = _linkage_cells(cell, label, mechanism, "module cell")
    if failures:
        return failures
    return _check_linkage_tables(cells, cell, mechanism, exact, floors,
                                 label, unlisted, "module cell")


def check_module_covers_row(report: dict[str, Any], mechanism: int,
                            module_sha: str, label: str) -> list[str]:
    """The row's every call is attributed to ``module_sha`` (sole user).

    The row must carry a ``by_module`` cell for the module whose calls
    equal the row totals: with a single in-tree user of the mechanism,
    any unattributed or foreign-module share fails. A missing row or
    a missing cell fails closed.
    """
    for entry in report.get("mechanisms", []) or []:
        if isinstance(entry, dict) and entry.get("mechanism") == mechanism:
            row = entry
            break
    else:
        return [f"{label}: no mechanism row for 0x{mechanism:x}"]
    cells = {}
    for cell in row.get("by_module", []) or []:
        if not isinstance(cell, dict):
            return [f"{label}: by_module carries a malformed entry"]
        module = cell.get("module") or {}
        if module.get("sha256") == module_sha:
            cells = cell
            break
    else:
        return [f"{label}: no by_module cell for the expected module "
                f"on the 0x{mechanism:x} row"]
    if not _u64(cells.get("calls")) or not _u64(row.get("calls")):
        return [f"{label}: module/row call counters are not u64"]
    if cells["calls"] != row["calls"]:
        return [f"{label}: module cell calls={cells['calls']} != row "
                f"calls={row['calls']} (another user shares 0x{mechanism:x}?)"]
    return []


def system_softokn_sha(report: dict[str, Any], bundled_path: str) -> str:
    """The system softokn module's sha, anchored to the real file.

    The report's capture modules must name exactly one ``libsoftokn3.so``
    besides the bundled one; its bytes on disk must hash to the
    reported sha (an unanchored report value is not an identity).
    Raises :class:`OracleError` when the capture names zero or two,
    the file is unreadable, or the hash disagrees.
    """
    candidates = [module for module in
                  (report.get("capture") or {}).get("modules", []) or []
                  if isinstance(module, dict)
                  and (module.get("path") or "").endswith("/libsoftokn3.so")
                  and module.get("path") != bundled_path]
    if len(candidates) != 1:
        raise OracleError(f"want exactly one system libsoftokn3.so besides "
                          f"{bundled_path}, capture names {len(candidates)}")
    module = candidates[0]
    try:
        actual = sha256_of(Path(module["path"]))
    except (OSError, KeyError) as exc:
        raise OracleError(f"cannot hash system softokn "
                          f"{module.get('path')!r}: {exc}") from exc
    if actual != module.get("sha256"):
        raise OracleError(f"system softokn hash {actual[:16]}... != report "
                          f"{str(module.get('sha256'))[:16]}...")
    return actual


def check_no_state_drops(report: dict[str, Any]) -> list[str]:
    """No semantic state admission drop pressured this capture.

    The linkage sums are exact by construction, but a pressured run
    sheds rows, bindings, and module cells elsewhere: a missed Init
    leg under pressure is lost attribution, not a background change.
    Healthy captures keep both counters at zero; a nonzero drop fails
    the strict table instead of letting pressure pass as a shape.
    """
    failures = []
    for key in ("semantic_state_drops", "semantic_history_drops"):
        value = evidence(report).get(key, 0) or 0
        if value != 0:
            failures.append(f"{key}={value}, want 0 (strict sums unverifiable)")
    return failures


def check_cc_ground_truth(server: dict[str, Any], flow: dict[str, Any],
                          label: str) -> list[str]:
    """Exactly one full client-cert handshake + served request happened.

    The observer-independent ground truth: the TLS server saw one
    completed handshake presenting one client certificate and served
    one request, with no empty certs, stalls, refusals, abandonments,
    failures, or error text; the browser flow loaded the page with
    HTTP 200. Strict equality on every counter; mistyped facts fail.
    """
    failures = []

    def want(key, expected):
        value = server.get(key)
        if type(value) is not int or value != expected:
            failures.append(f"{label}: server {key}={value!r}, want {expected}")

    for key in ("handshakes_ok", "client_certs_presented", "requests_served"):
        want(key, 1)
    for key in ("empty_certs", "selection_stalls", "cert_refusals",
                "abandoned", "handshake_failures"):
        want(key, 0)
    errors = server.get("handshake_errors")
    if errors != []:
        failures.append(f"{label}: handshake_errors={errors!r}, want []")
    if flow.get("loaded") is not True:
        failures.append(f"{label}: flow loaded={flow.get('loaded')!r}, want True "
                        f"(error: {flow.get('error')!r})")
    if flow.get("http_status") != 200:
        failures.append(f"{label}: http_status={flow.get('http_status')!r}, want 200")
    return failures


def check_plain_ground_truth(server: dict[str, Any], flow: dict[str, Any],
                             label: str) -> list[str]:
    """Exactly one full handshake with no client cert + served request.

    The no-sign control twin: same strict shape as the cc ground
    truth except no certificate is presented (the server never asks),
    so no CertificateVerify sign may exist anywhere in the capture.
    """
    failures = []

    def want(key, expected):
        value = server.get(key)
        if type(value) is not int or value != expected:
            failures.append(f"{label}: server {key}={value!r}, want {expected}")

    want("handshakes_ok", 1)
    want("client_certs_presented", 0)
    want("requests_served", 1)
    for key in ("empty_certs", "selection_stalls", "cert_refusals",
                "abandoned", "handshake_failures"):
        want(key, 0)
    errors = server.get("handshake_errors")
    if errors != []:
        failures.append(f"{label}: handshake_errors={errors!r}, want []")
    if flow.get("loaded") is not True:
        failures.append(f"{label}: flow loaded={flow.get('loaded')!r}, want True "
                        f"(error: {flow.get('error')!r})")
    if flow.get("http_status") != 200:
        failures.append(f"{label}: http_status={flow.get('http_status')!r}, want 200")
    return failures


def check_bundled_coverage_or_named_gap(report: dict[str, Any], module_sha: str,
                                        module_path: str, gap_cause: str,
                                        label: str) -> list[str]:
    """The bundled provider is covered, or its miss is a named gap.

    Passes when the discovery entry for ``module_path`` shows an
    attached scan (tables observed) and the module's function rows
    counted calls. Otherwise the miss must be disclosed, not silent:
    a ``gap_cause`` observation cause must name the window, the
    discovery entry must carry its observed-load count, and the entry
    must carry the ``gap_cause`` unobserved window itself (a valid
    ``[start_ns, end_ns)`` interval). A prearmed but never attached
    file with no window and no cause fails.
    """
    failures = []
    entry = None
    for candidate in evidence(report).get("discovery", []) or []:
        if isinstance(candidate, dict) and candidate.get("path") == module_path:
            entry = candidate
            break
    calls = 0
    for row in report.get("functions", []) or []:
        target = (row.get("target") or {}).get("object") or {}
        if target.get("sha256") == module_sha:
            calls += row.get("calls") or 0
    tables = len((entry or {}).get("tables", []) or [])
    attached = (entry or {}).get("attached_at_ns") is not None
    if entry is not None and attached and tables > 0 and calls > 0:
        return []
    causes = ((evidence(report).get("gap_classes") or {}).get("observation") or {})
    if gap_cause not in (causes.get("causes") or []):
        failures.append(f"{label}: {module_path} has tables={tables} calls={calls} "
                        f"attached={attached} with no {gap_cause!r} gap cause "
                        f"(silent provider miss)")
        return failures
    loads = ((entry or {}).get("first_loaded_by") or {}).get("pre_attach_loads")
    if type(loads) is not int or loads < 1:
        failures.append(f"{label}: {gap_cause!r} names the miss but the discovery "
                        f"entry carries pre_attach_loads={loads!r} (gap has no counts)")
    windows = (entry or {}).get("unobserved_windows") or []
    shaped = [window for window in windows
              if isinstance(window, dict)
              and window.get("reason") == gap_cause
              and type(window.get("start_ns")) is int
              and type(window.get("end_ns")) is int
              and window["start_ns"] < window["end_ns"]]
    if not shaped:
        failures.append(f"{label}: {gap_cause!r} names the miss but the discovery "
                        f"entry carries no {gap_cause!r} window "
                        f"(unobserved_windows={windows!r})")
    return failures


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
