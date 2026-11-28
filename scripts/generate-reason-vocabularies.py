#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Derive B1 reason vocabularies mechanically from producer sources.

Each reason-map vocabulary comes from its authoritative definition site:
an enum plus its exhaustive code()/label() match (asserted 1:1), or string
consts. v072 reads the working tree; v071 reads v0.7.1 tag bytes via
``git show`` (same anchors; a missing anchor is a loud error, never a
silent skip). Output is the committed scripts/upgrade-reason-vocabularies.json.
Any product-side refactor that moves these sites breaks generation loudly,
which is the point: vocabularies must be re-pinned deliberately.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "scripts" / "upgrade-reason-vocabularies.json"

# map-prefix -> derivation recipe. Keys are flattened B1 paths ([0]-normalized).
ENUM_SOURCES = [
    # (map prefix, file, enum name, fn name)
    ("modules[0].unbound_use.reasons", "src/discovery/native_binding.rs",
     "UnboundReason", "code"),
    ("modules[0].departed_use.entries.coverage.unknown",
     "src/discovery/caller_registry.rs", "UnknownReason", "code"),
    ("modules[0].departed_use.entries.observation",
     "src/discovery/caller_registry.rs", "EntryObservation", "label"),
    ("modules[0].departed_use.instances.reasons",
     "src/discovery/caller_registry/instance_input.rs", "InstanceReason", "label"),
    ("modules[0].departed_use.instances.loss_reasons",
     "src/discovery/caller_registry/instance_input.rs", "InstanceReason", "label"),
    ("observation.native_witnesses.unbound_reasons",
     "src/discovery/native_binding.rs", "UnboundReason", "code"),
]
CONST_SOURCES = [
    # (map prefix, file, const names)
    ("modules[0].unbound_use.reasons",
     "src/discovery/caller_registry.rs", ["NO_MAPPING_EDGE"]),
    ("modules[0].departed_use.semantics.labels",
     "src/semantics_edge.rs",
     ["SEMANTIC_OBSERVED", "SEMANTIC_UNKNOWN_UNAUTHORIZED",
      "SEMANTIC_UNKNOWN_AMBIGUOUS", "SEMANTIC_UNKNOWN_COUNT_ONLY",
      "SEMANTIC_UNKNOWN_NO_EVIDENCE", "SEMANTIC_UNKNOWN_DOUBLE_LOAD"]),
    ("modules[0].departed_use.semantics.labels",
     "src/discovery/caller_registry.rs", ["SEMANTIC_UNKNOWN"]),
    ("modules[0].departed_use.semantics.labels",
     "src/inventory/present.rs", ["SEMANTIC_WITHHELD_WITH_CLAIMED_CHILDREN"]),
]


def read_source(rev, relpath):
    if rev == "tree":
        return (ROOT / relpath).read_text()
    completed = subprocess.run(
        ["git", "show", f"{rev}:{relpath}"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"cannot read {rev}:{relpath}: "
                           f"{completed.stderr.decode()[:200]}")
    return completed.stdout.decode()


def parse_enum_labels(text, enum_name, fn_name, where):
    decl = re.search(rf"pub(?:\(crate\))?\s+enum\s+{enum_name}\b", text)
    if not decl:
        raise RuntimeError(f"{where}: enum {enum_name} not found")
    # Variants: consecutive `Variant` / `Variant(...)` / `Variant{{...}}` lines
    # inside the enum body (comments and attributes skipped).
    variants = set()
    depth = 0
    started = False
    for line in text[decl.end():].splitlines():
        depth += line.count("{") - line.count("}")
        if not started:
            if depth > 0:
                started = True
            continue
        if depth <= 0:
            break
        stripped = line.split("//")[0].strip().rstrip(",").strip()
        if not stripped or stripped.startswith("#"):
            continue
        ident = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", stripped)
        if ident:
            variants.add(ident.group(1))
    if not variants:
        raise RuntimeError(f"{where}: no variants parsed for {enum_name}")
    # The label fn: the `fn {fn_name}(` whose nearest preceding `impl`
    # names this enum; exactly one must match.
    impls = [match for match in re.finditer(r"(?m)^(\s*)impl\s+([A-Za-z_][A-Za-z0-9_:<> ]*?)\s*(?:\{|where\b)", text)]
    fns = [match for match in re.finditer(rf"(?m)^\s*(?:pub(?:\(crate\))?\s+)?(?:const\s+)?fn\s+{fn_name}\s*\(", text)]
    anchored = []
    for fn in fns:
        owner = None
        for impl in impls:
            if impl.start() < fn.start():
                owner = impl.group(2)
            else:
                break
        if owner is not None and re.search(rf"\b{enum_name}\b", owner):
            anchored.append(fn)
    if len(anchored) != 1:
        raise RuntimeError(f"{where}: found {len(anchored)} {enum_name}::{fn_name} fns")
    arms = {}
    for line in text[anchored[0].end():].splitlines():
        arm = re.match(r"\s*Self::([A-Za-z_][A-Za-z0-9_]*)\b[^{]*=>\s*\"((?:[^\"\\]|\\.)*)\"\s*,?\s*$", line)
        if arm:
            variant, literal = arm.group(1), arm.group(2)
            if variant in arms:
                raise RuntimeError(f"{where}: duplicate arm {variant}")
            arms[variant] = literal
        if re.match(r"\s*\}\s*$", line) and arms:
            break
    if set(arms) != variants:
        raise RuntimeError(
            f"{where}: {enum_name}::{fn_name} arms {sorted(arms)} != "
            f"variants {sorted(variants)}")
    return sorted(arms.values())


def parse_consts(text, names, where):
    found = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        match = re.match(r"\s*(?:pub(?:\(crate\))?\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&\s*str\s*=\s*(.*)$", lines[index])
        if match and match.group(1) in names:
            rest = match.group(2).strip()
            while not rest.rstrip().endswith(";"):
                index += 1
                if index >= len(lines):
                    raise RuntimeError(f"{where}: unterminated const {match.group(1)}")
                continuation = lines[index].strip()
                if rest.endswith("\\"):
                    rest = rest[:-1] + continuation
                else:
                    rest = rest + " " + continuation
            literal = re.fullmatch(r"\"((?:[^\"\\]|\\.)*)\"\s*;", rest.strip())
            if not literal:
                raise RuntimeError(f"{where}: const {match.group(1)} is not a plain literal: {rest[:80]}")
            found[match.group(1)] = literal.group(1)
        index += 1
    missing = set(names) - set(found)
    if missing:
        raise RuntimeError(f"{where}: consts not found: {sorted(missing)}")
    return [found[name] for name in names]


def derive_revision(rev):
    vocab = {}
    bad = []

    def add(prefix, labels):
        vocab.setdefault(prefix, []).extend(labels)

    for prefix, relpath, enum_name, fn_name in ENUM_SOURCES:
        try:
            text = read_source(rev, relpath)
            add(prefix, parse_enum_labels(text, enum_name, fn_name, f"{rev}:{relpath}"))
        except RuntimeError as exc:
            bad.append(str(exc))
    for prefix, relpath, names in CONST_SOURCES:
        try:
            text = read_source(rev, relpath)
            add(prefix, parse_consts(text, names, f"{rev}:{relpath}"))
        except RuntimeError as exc:
            bad.append(str(exc))
    if bad:
        raise RuntimeError("vocabulary derivation failed:\n" + "\n".join(bad))
    return {prefix: sorted(set(labels)) for prefix, labels in vocab.items()}


def derive_reason_vocabularies():
    return {"v071": derive_revision("v0.7.1"), "v072": derive_revision("tree")}


def main():
    try:
        vocabularies = derive_reason_vocabularies()
    except RuntimeError as exc:
        print(f"generate-reason-vocabularies: {exc}", file=sys.stderr)
        return 1
    for era in ("v071", "v072"):
        for prefix in sorted(vocabularies[era]):
            print(f"{era} {prefix}: {len(vocabularies[era][prefix])} labels")
    for prefix in sorted(set(vocabularies["v071"]) | set(vocabularies["v072"])):
        old = set(vocabularies["v071"].get(prefix, []))
        new = set(vocabularies["v072"].get(prefix, []))
        if old - new:
            print(f"REMOVED {prefix}: {sorted(old - new)}")
        if new - old:
            print(f"ADDED {prefix}: {sorted(new - old)}")
    OUT.write_text(json.dumps(vocabularies, indent=2) + "\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
