# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Drive the real Rust skip projection from Python qualification twins.

The permission/deferral/unreadable (and now unverified/terminal)
qualification twins must judge the bytes the producer emits, never
source text: a re-pointed, removed, or unreachable `capture_skipped_out`
arm keeps every source-text guard green while the public row goes
wrong. This helper builds (when stale) and runs the
`skip_projection_probe` example via the cargo wrapper, feeding it
internal pairs on stdin and parsing the public rows from stdout.

Shared by `test_public_cli_oracle.py` and `test_public_cli_breadth.py`
(they are mirrors; both judge the same producer). Not a suite itself:
it defines no tests, so the suite registry ignores it.
"""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CARGO_WRAPPER = ROOT / "scripts/cargo.sh"
RELEASE_RUST = (ROOT / ".release-rust-version").read_text(encoding="utf-8").strip()

# Per-process cache: {(subject, reason): (name, reason)}. The cargo build
# itself is cached in target/ across suites, so the first suite warms the
# second.
_CACHE = {}


def _run_probe(pairs):
    """Run the probe binary on [(subject, reason)], return [(name, reason)]."""
    stdin = json.dumps([{"subject": s, "reason": r} for s, r in pairs])
    try:
        completed = subprocess.run(
            [str(CARGO_WRAPPER), "+" + RELEASE_RUST, "run", "--locked", "--quiet",
             "--example", "skip_projection_probe"],
            input=stdin, capture_output=True, text=True, cwd=ROOT,
            timeout=1500,
        )
    except FileNotFoundError as error:
        raise AssertionError(
            "skip projection fixture needs the cargo wrapper and a Rust "
            f"toolchain ({CARGO_WRAPPER} +{RELEASE_RUST}): {error}") from error
    except subprocess.TimeoutExpired as error:
        raise AssertionError(
            "skip projection fixture timed out building/running the probe "
            "(cold Rust builds take minutes; a warm target/ is seconds)") from error
    assert completed.returncode == 0, (
        "skip projection probe failed "
        f"(exit {completed.returncode}): {completed.stderr.strip()[-2000:]}")
    try:
        rows = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            "skip projection probe printed non-JSON: "
            f"{completed.stdout.strip()[-500:]!r}") from error
    assert isinstance(rows, list) and len(rows) == len(pairs), (
        f"probe returned {len(rows) if isinstance(rows, list) else '?'} rows "
        f"for {len(pairs)} pairs")
    out = []
    for row in rows:
        assert isinstance(row, dict), f"probe row is not an object: {row!r}"
        out.append((row["name"], row["reason"]))
    return out


def project_rows(pairs):
    """Project [(subject, reason)] through the real `capture_skipped_out`.

    Returns [(name, reason)] in order. Fails loudly when the toolchain,
    the build, or the probe output is unusable — never skips, never
    falls back to source text.
    """
    missing = [pair for pair in pairs if pair not in _CACHE]
    if missing:
        # Deduplicate the subprocess call; cache fills per pair.
        ordered = list(dict.fromkeys(missing))
        for pair, row in zip(ordered, _run_probe(ordered)):
            _CACHE[pair] = row
    return [_CACHE[pair] for pair in pairs]


def check_row(projected, expected_name, expected_reason, *, context):
    """Raise unless `projected` is exactly the expected public row.

    `projected` is a (name, reason) tuple, usually from `project_rows`.
    Exact match: a routed-to-generic, mislabelled, or unreachable arm
    fails here. Pure logic over its arguments so the negative controls
    can feed it broken rows without a Rust build.
    """
    assert isinstance(projected, tuple) and len(projected) == 2, (
        f"{context}: projected row is not a pair: {projected!r}")
    assert projected == (expected_name, expected_reason), (
        f"{context}: producer projects to {projected[0]!r}/{projected[1]!r}, "
        f"expected {expected_name!r}/{expected_reason!r}")


def assert_binary_row(subject, reason, expected_name, expected_reason, *, context):
    """Project one internal pair via the binary and exact-match the row.

    Returns the projected row as {"name": ..., "reason": ...} for the
    oracle rejection twins. Fails when the binary is unusable or its
    bytes differ from the expected row.
    """
    [(name, projected_reason)] = project_rows([(subject, reason)])
    check_row((name, projected_reason), expected_name, expected_reason,
              context=context)
    return {"name": name, "reason": projected_reason}
