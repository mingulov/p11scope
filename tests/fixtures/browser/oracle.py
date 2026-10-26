# SPDX-License-Identifier: GPL-3.0-or-later
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
#: publishes them (key-operation browser populations are 0.5.1); their
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

    Key-operation browser populations arrive in 0.5.1; a v0.5.0
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


def check_s1_sessions(report: dict[str, Any], opened_min: int = 0,
                      zero: bool = False) -> list[str]:
    """S1 session accounting balances, with a per-cell opened floor.

    The six counters must be present u64 values with
    balance == opened+inherited-closed (saturating, as rendered);
    ``opened_min`` floors opened sessions for cells whose floored
    calls need one (FindObjects cannot run without a session), and
    ``zero`` requires all counters at zero for never-mapped cells.
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
