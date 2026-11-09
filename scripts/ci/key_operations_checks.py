#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Shared document checks for the key-operations CI cells.

Both scripts/ci/key-operations-linked-control.sh and
scripts/ci/key-operations-system.sh call this helper; the Python suites
import it and feed it fake or mutated documents for the non-vacuity
pairs. It never runs an observer and needs no privilege.

Checks (each prints one human-readable detail line):
  ring-loss DOC     observation.lifecycle.ring_loss == 0 (exit 0/1)
  no-loss-gap DOC   no gap whose subject/reason names kernel-side loss
  oo DOC            object_observations status + reason (always exit 0)
  stop EXIT STDERR DOC
                    a complete stop: exit 0, the document parses, and no
                    "cleanup incomplete" marker in the observer stderr
Exit 2 on usage errors.
"""
import json
import re
import sys

# Kernel-side loss vocabulary. Each token names dropped kernel data (a
# ring that overwrote unread records, events that never arrived, a
# truncated collection), never a userspace disclosure: first-burst shed
# rows, custody notes and "unknown" coverage are honest non-loss and
# must not match. "custody lost" is deliberately absent: a dead PID
# target loses no kernel data, and neither is "native owner lost" (a
# userspace scan error, not dropped kernel data).
#
# Subject tokens below are the product's real gap subjects
# (src/discovery/caller_registry.rs, inventory_coordinator/leader_exit.rs
# and semantics.rs); reason tokens are the real lifecycle/EVENTS
# phrasings (src/attach/inventory/capture.rs, caller_registry.rs).
LOSS_RE = re.compile(
    r"ring[ _]loss|event[ _]loss|events[ _]lost|events[ _]loss[ _]unknown"
    r"|lost[ _]+[0-9]+[ _]+(events|records?)"
    r"|discovery[ _]loss|truncat|overflow|dropped[ _]+events?"
    r"|semantic[ _]capture[ _]loss|semantic[ _]calls[ _]lost"
    r"|native[ _]count[ _]refresh[ _]loss|lifecycle[ _]evidence[ _]lost"
    r"|leader[ _]task[ _]link[ _]loss|batch[ _]+dropped"
    r"|ring[ _]+lost|record[ _]+was[ _]+lost",
    re.IGNORECASE,
)


def load_document(path):
    """Parse an observer JSON document; raise ValueError with context."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as error:
        raise ValueError(f"cannot parse {path}: {error}")


def check_ring_loss(document):
    """observation.lifecycle.ring_loss must read exactly 0."""
    try:
        value = document["observation"]["lifecycle"]["ring_loss"]
    except (KeyError, TypeError):
        return False, "observation.lifecycle.ring_loss missing"
    if value != 0:
        return False, f"observation.lifecycle.ring_loss == {value!r}, want 0"
    return True, "observation.lifecycle.ring_loss == 0"


def iter_loss_gaps(document):
    """Yield (subject, reason) for gaps that name kernel-side loss."""
    gaps = document.get("gaps", [])
    if not isinstance(gaps, list):
        return
    for gap in gaps:
        if not isinstance(gap, dict):
            continue
        subject = gap.get("subject", "")
        reason = gap.get("reason", "")
        text = f"{subject} {reason}"
        if LOSS_RE.search(text):
            yield subject, reason


def check_no_loss_gap(document):
    """No gap may name kernel-side loss."""
    hits = list(iter_loss_gaps(document))
    if hits:
        subject, reason = hits[0]
        return False, f"loss gap: [{subject}] {reason}"[:300]
    return True, "no known-loss gap"


def object_observations(document):
    """Return (status, reason) of the object_observations section."""
    section = document.get("object_observations", {})
    if not isinstance(section, dict):
        return "missing", "not a section"
    return section.get("status", "missing"), section.get("reason", "")


def check_stop(exit_code, stderr_text, document):
    """A complete stop: exit 0, a parseable document, no incomplete cleanup."""
    if exit_code != 0:
        return False, f"observer exit {exit_code}, want 0"
    if not isinstance(document, dict):
        return False, "observer report missing or unparseable"
    if "cleanup incomplete" in stderr_text:
        return False, "observer stderr reports cleanup incomplete"
    return True, "complete stop: exit 0, report parses, cleanup finished"


def main(argv):
    if len(argv) < 3:
        print(__doc__.splitlines()[-1], file=sys.stderr)
        return 2
    command = argv[1]
    try:
        if command == "oo":
            _, reason = (None, None)
            document = load_document(argv[2])
            status, reason = object_observations(document)
            print(f"status={status} reason={reason}")
            return 0
        if command == "ring-loss":
            ok, detail = check_ring_loss(load_document(argv[2]))
        elif command == "no-loss-gap":
            ok, detail = check_no_loss_gap(load_document(argv[2]))
        elif command == "stop":
            if len(argv) != 5:
                print("usage: key_operations_checks.py stop EXIT STDERR DOC",
                      file=sys.stderr)
                return 2
            with open(argv[3], encoding="utf-8") as handle:
                stderr_text = handle.read()
            try:
                document = load_document(argv[4])
            except ValueError:
                document = None
            ok, detail = check_stop(int(argv[2]), stderr_text, document)
        else:
            print(f"unknown check {command}", file=sys.stderr)
            return 2
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    print(detail)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
