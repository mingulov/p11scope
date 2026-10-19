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
    """Sum ``calls`` per function name for rows attached into ``module_sha``.

    Rows are matched by the pinned object identity
    (``target.object.sha256``), never by name alone; a retired-and-reattached
    target contributes one row per cell, so counts sum across rows.
    """
    counts: dict[str, int] = {}
    for row in report.get("functions", []):
        target = row.get("target") or {}
        obj = target.get("object") or {}
        if obj.get("sha256") != module_sha:
            continue
        calls = row.get("calls") or 0
        for name in row.get("names", []):
            counts[name] = counts.get(name, 0) + calls
    return counts


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


def check_zero_counts(counts: dict[str, int]) -> list[str]:
    """No calls were observed for the module (absence twin)."""
    failures = []
    total = sum(counts.values())
    if total != 0:
        failures.append(f"observed {total} calls for an unregistered module: {counts}")
    return failures


def check_absent(counts: dict[str, int], names: tuple[str, ...]) -> list[str]:
    """Named functions were never called (boundary pins amid noisy traffic)."""
    failures = []
    for name in names:
        observed = counts.get(name, 0)
        if observed != 0:
            failures.append(f"{name}: observed {observed}, want 0 (boundary crossed?)")
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
# out, so every floored call is flow-caused. Floors sit far below typical
# counts (FF-STARTUP sees C_FindObjects x26) so version drift adds calls
# without breaking the cell; only silence fails.
FF_STARTUP_FLOORS = {
    "C_FindObjectsInit": 1,
    "C_FindObjects": 1,
    "C_FindObjectsFinal": 1,
    "C_GetSessionInfo": 1,
}
# There are deliberately no PINBOUND floors: both browsers stall at the
# interactive-PIN boundary before any token use (FF-PINBOUND pins the
# mapped-and-armed zero; CR-PINBOUND the never-mapped zero).
