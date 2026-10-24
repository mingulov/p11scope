#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Every ignored Rust test is a tracked obligation (v0.5 closure).

Scans the workspace Rust sources under src/, tests/ and crates/ for real
`#[ignore]` attributes (comment and string mentions do not count) and
compares them both ways against tests/ignored-tests.json:

- an ignore site with no inventory entry fails;
- an inventory entry with no matching site fails;
- a `feature` entry without a non-empty `owner` fails: the owner names
  the lane that runs the test (a runner list or a dedicated build).
  The owner must be one of ALLOWED_OWNERS; a new lane extends that
  tuple (and gains its own curation rule when it runs tests);
- a `privileged` entry whose test is not curated in
  scripts/run-privileged-lib-tests.sh fails. Macro-defined sites
  (path ending in `!`) expand to their `name!(test, ...)` invocations in
  the same file; every default-build expansion must be curated in the
  default lists, while expansions gated on a cargo feature exist in no
  default binary, so they must be curated in WIDE_DETAILED_2112_TESTS
  instead (the runner's own drift check cannot see them);
- a `feature` entry owned by the wide-detailed-2112 runner, and every
  member of WIDE_DETAILED_2112_TESTS, must resolve both ways: an owned
  entry missing from the list fails, and a list member that is neither
  a wide-owned entry nor a feature-gated expansion fails;
- a `live-kernel` or `privileged` entry under tests/ (an ignored
  integration test) must be curated as `file:path` in the runner's
  INTEGRATION_TESTS list, and every list member must resolve back to
  such an entry.

Usage:
  python3 -I scripts/check-ignored-tests.py [--root DIR]
      [--inventory PATH] [--runner PATH]
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = "tests/ignored-tests.json"
DEFAULT_RUNNER = "scripts/run-privileged-lib-tests.sh"
SCAN_DIRS = ("src", "tests", "crates")
EXCLUDED_SEGMENTS = ("third-party", "target")
RUNNER_LISTS = (
    "DEFAULT_TESTS",
    "ALTERNATIVE_TESTS",
    "LONG_TESTS",
    "SKIP_TESTS",
)
WIDE_LIST = "WIDE_DETAILED_2112_TESTS"
WIDE_OWNER = "wide-detailed-2112 runner"
ALLOWED_OWNERS = (
    WIDE_OWNER,
    "counter-bank-proof build",
    "counter-artifacts build",
)
INTEGRATION_LIST = "INTEGRATION_TESTS"
INTEGRATION_CELLS = ("live-kernel", "privileged")

MOD_RE = re.compile(
    r"((?:#\s*\[[^\]]*\]\s*)*)"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*(;|\{)"
)
IGNORE_RE = re.compile(r"#\s*\[\s*ignore\b")
FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*|\$name)\b")
MACRO_DEF_RE = re.compile(r"macro_rules!\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{")
PATH_ATTR_RE = re.compile(r'path\s*=\s*"([^"]+)"')


def strip_code(text):
    """Blank comments and string/char literals, keeping offsets and newlines."""
    out = list(text)
    n = len(text)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    i = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            blank(i, n if j < 0 else j)
            i = n if j < 0 else j
        elif c == "/" and nxt == "*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1
                    j += 2
                elif text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and nxt in "#\"":
            m = re.match(r'r#*"', text[i:])
            if m:
                close = '"' + "#" * (len(m.group(0)) - 2)
                j = text.find(close, i + len(m.group(0)))
                j = n if j < 0 else j + len(close)
                blank(i, j)
                i = j
            else:
                i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
        elif c == "'":
            m = re.match(r"'(?:\\.|[^'\\])'", text[i:])
            if m:
                blank(i, i + len(m.group(0)))
                i += len(m.group(0))
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def decode_rust_str(raw):
    """Decode the escapes of a plain (non-raw) Rust string body."""
    out = []
    i = 0
    while i < len(raw):
        if raw[i] == "\\" and i + 1 < len(raw):
            esc = raw[i + 1]
            simple = {"n": "\n", "t": "\t", "r": "\r",
                      "\\": "\\", '"': '"', "0": "\0"}
            if esc in simple:
                out.append(simple[esc])
                i += 2
            elif esc == "x":
                out.append(chr(int(raw[i + 2:i + 4], 16)))
                i += 4
            elif esc == "u":
                end = raw.find("}", i + 3)
                out.append(chr(int(raw[i + 3:end], 16)))
                i = end + 1
            else:
                out.append(esc)
                i += 2
        else:
            out.append(raw[i])
            i += 1
    return "".join(out)


def crate_roots(root):
    """Crate-root files: workspace lib/bin, every tests/ file, every crates/ member."""
    roots = []
    for cand in (root / "src" / "lib.rs", root / "src" / "main.rs"):
        if cand.is_file():
            roots.append(cand)
    tests = root / "tests"
    if tests.is_dir():
        roots.extend(sorted(p for p in tests.glob("*.rs") if p.is_file()))
    crates = root / "crates"
    if crates.is_dir():
        for cargo in sorted(crates.rglob("Cargo.toml")):
            if any(seg in EXCLUDED_SEGMENTS for seg in cargo.parts):
                continue
            member = cargo.parent
            for cand in (member / "src" / "lib.rs", member / "src" / "main.rs"):
                if cand.is_file():
                    roots.append(cand)
            for sub in ("tests", "benches", "examples"):
                subdir = member / sub
                if subdir.is_dir():
                    roots.extend(sorted(p for p in subdir.glob("*.rs")
                                        if p.is_file()))
    return roots


def child_candidates(path, name):
    """Where `mod name;` inside `path` may live (Rust file lookup rules)."""
    if path.stem in ("mod", "lib", "main"):
        base = path.parent
    else:
        base = path.parent / path.stem
    return [base / f"{name}.rs", base / name / "mod.rs"]


def build_filemap(root):
    """Map every reachable .rs file to its module path segments."""
    filemap = {}

    def visit(path, prefix):
        if path in filemap:
            return
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        filemap[path] = prefix
        stripped = strip_code(text)
        for match in MOD_RE.finditer(stripped):
            # #[path] strings are blanked above; read them from the original.
            original_attrs = text[match.start(1):match.end(1)]
            path_match = PATH_ATTR_RE.search(original_attrs)
            name, term = match.group(2), match.group(3)
            if term != ";":
                continue
            if path_match:
                visit(path.parent / path_match.group(1), prefix + [name])
            else:
                found = [c for c in child_candidates(path, name) if c.is_file()]
                if found:
                    visit(found[0], prefix + [name])

    for entry in crate_roots(root):
        visit(entry, [])
    return filemap


def rust_files(root):
    """Every scanned .rs file, sorted, minus excluded segments."""
    found = []
    for dirname in SCAN_DIRS:
        top = root / dirname
        if not top.is_dir():
            continue
        for path in sorted(top.rglob("*.rs")):
            if any(seg in EXCLUDED_SEGMENTS for seg in path.parts):
                continue
            found.append(path)
    return found


def macro_spans(stripped):
    """(name, start, end) brace spans of every macro_rules! definition."""
    spans = []
    for match in MACRO_DEF_RE.finditer(stripped):
        depth = 1
        i = match.end()
        while i < len(stripped) and depth:
            if stripped[i] == "{":
                depth += 1
            elif stripped[i] == "}":
                depth -= 1
            i += 1
        spans.append((match.group(1), match.start(), i))
    return spans


def inline_mods_at(stripped, upto):
    """Inline `mod name {` segments enclosing the offset."""
    mods = []
    depth = 0
    pattern = re.compile(
        r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{|\{|\}"
    )
    for match in pattern.finditer(stripped[:upto]):
        token = match.group(0)
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            while mods and mods[-1][1] >= depth:
                mods.pop()
        else:
            mods.append((match.group(1), depth))
            depth += 1
    return [name for name, _ in mods]


def attribute_end(stripped, start):
    """Offset just past the `#[...]` attribute starting at `start`."""
    depth = 0
    for idx in range(start, len(stripped)):
        char = stripped[idx]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return idx + 1
    raise ValueError("unterminated attribute")


def parse_reason(text, start, end):
    """The ignore reason: `= "..."` (possibly multiline) or "" when bare."""
    body = text[start:end]
    eq = body.find("=")
    if eq < 0:
        return ""
    quote = body.find('"', eq)
    if quote < 0:
        raise ValueError("ignore reason is not a string")
    i = start + quote + 1
    while True:
        if i >= len(text):
            raise ValueError("unterminated ignore reason")
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return decode_rust_str(text[start + quote + 1:i])
        i += 1


def scan_file(path, filemap):
    """All ignore sites in one file.

    Returns (sites, errors). A site is (line, module_segments, item, macro,
    reason) where item is the following fn name ($name in macros) and macro
    is the enclosing macro_rules! name or None.
    """
    text = path.read_text(encoding="utf-8")
    stripped = strip_code(text)
    spans = macro_spans(stripped)
    base = filemap.get(path, [])
    sites, errors = [], []
    for match in IGNORE_RE.finditer(stripped):
        line = text.count("\n", 0, match.start()) + 1
        try:
            end = attribute_end(stripped, match.start())
            reason = parse_reason(text, match.start(), end)
        except ValueError as exc:
            errors.append(f"{path}:{line}: {exc}")
            continue
        fn_match = FN_RE.search(stripped, end, min(len(stripped), end + 2000))
        if fn_match is None:
            errors.append(f"{path}:{line}: #[ignore] with no following fn")
            continue
        gap = stripped[end:fn_match.start()]
        if re.search(r"[{;}()=]", gap):
            errors.append(f"{path}:{line}: #[ignore] is not on a fn item")
            continue
        enclosing = [name for name, lo, hi in spans if lo <= match.start() < hi]
        macro = enclosing[-1] if enclosing else None
        mods = inline_mods_at(stripped, match.start())
        sites.append((line, base + mods, fn_match.group(1), macro, reason))
    return sites, errors


def scan_sources(root):
    """{file: [(line, path, macro, reason)]} plus parse errors."""
    root = Path(root)
    filemap = build_filemap(root)
    found, errors = {}, []
    for path in rust_files(root):
        sites, file_errors = scan_file(path, filemap)
        for message in file_errors:
            errors.append(f"{path.relative_to(root)}: {message}")
        if sites:
            rel = path.relative_to(root).as_posix()
            found[rel] = []
            for line, segments, item, macro, reason in sites:
                if macro is not None:
                    full = "::".join([*segments, macro]) + "!"
                else:
                    full = "::".join([*segments, item])
                found[rel].append((line, full, macro, reason))
    return found, errors


def runner_lists(runner_path):
    """{list name: set of curated items} for every runner curation list."""
    text = Path(runner_path).read_text(encoding="utf-8")
    lists = {}
    for name in (*RUNNER_LISTS, WIDE_LIST, INTEGRATION_LIST):
        match = re.search(rf"^{name}=\(\n(.*?)\n\)", text, re.M | re.S)
        if match is None:
            raise ValueError(f"{runner_path} has no {name} list")
        items = set()
        for line in match.group(1).splitlines():
            entry = line.split("#")[0].strip()
            if entry:
                items.add(entry.split()[0])
        lists[name] = items
    return lists


def runner_registered(runner_path):
    """Test paths curated by the privileged runner's four default lists."""
    lists = runner_lists(runner_path)
    registered = set()
    for name in RUNNER_LISTS:
        registered |= lists[name]
    return registered


def cfg_blocked_above(stripped, original, offset):
    """Attributes directly above `offset`, from the original text."""
    i = offset
    chunks = []
    while True:
        j = i - 1
        while j >= 0 and stripped[j] in " \t\n":
            j -= 1
        if j < 0 or stripped[j] != "]":
            break
        depth = 0
        k = j
        while k >= 0:
            if stripped[k] == "]":
                depth += 1
            elif stripped[k] == "[":
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if k < 1 or stripped[k - 1] != "#":
            break
        chunks.append(original[k - 1:j + 1])
        i = k - 1
    return "\n".join(reversed(chunks))


def default_absent(cfg_attrs):
    """True when the cfg gates need a cargo feature (absent by default).

    `not(...)` spans are removed first, so `cfg(not(feature = "x"))`
    counts as present while `cfg(feature = "x")` counts as absent.
    """
    remaining = re.sub(r"not\s*\([^()]*\)", "", cfg_attrs)
    return "feature" in remaining


def macro_expansions(path, macro):
    """(name, default_absent) for each `macro!(name, ...)` invocation."""
    text = Path(path).read_text(encoding="utf-8")
    stripped = strip_code(text)
    def_spans = [(lo, hi) for _, lo, hi in macro_spans(stripped)
                 if _ == macro]
    found = []
    pattern = re.compile(rf"(?<![A-Za-z0-9_:]){re.escape(macro)}\s*!"
                         r"\s*([(\[{])")
    for match in pattern.finditer(stripped):
        if any(lo <= match.start() < hi for lo, hi in def_spans):
            continue
        arg = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)",
                       stripped[match.end():])
        if arg is None:
            found.append((None, False))
            continue
        attrs = cfg_blocked_above(stripped, text, match.start())
        found.append((arg.group(1), default_absent(attrs)))
    return found


def load_inventory(inventory_path):
    """(schema_cells, entries, errors). Entries are raw dicts in file order."""
    raw = Path(inventory_path).read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return set(), [], [f"{inventory_path}: invalid JSON: {exc}"]
    if not isinstance(data, dict) or not isinstance(data.get("sites"), list):
        return set(), [], [f"{inventory_path}: expected an object with a "
                           '"sites" list']
    cells = data.get("cells", {})
    if not isinstance(cells, dict) or not cells:
        return set(), [], [f"{inventory_path}: expected a nonempty "
                           '"cells" legend']
    return set(cells), data["sites"], []


def check(root=ROOT, inventory=None, runner=None):
    """The full inventory check. Returns a list of failure lines (empty OK)."""
    root = Path(root)
    inventory = Path(inventory) if inventory else root / DEFAULT_INVENTORY
    runner = Path(runner) if runner else root / DEFAULT_RUNNER
    failures = []

    cells, entries, load_errors = load_inventory(inventory)
    failures.extend(f"FAIL inventory: {e}" for e in load_errors)
    try:
        lists = runner_lists(runner)
    except (FileNotFoundError, ValueError) as exc:
        failures.append(f"FAIL runner: {exc}")
        lists = {}
    registered = set()
    for name in RUNNER_LISTS:
        registered |= lists.get(name, set())
    wide = lists.get(WIDE_LIST, set())
    integration = lists.get(INTEGRATION_LIST, set())

    sites, scan_errors = scan_sources(root)
    failures.extend(f"FAIL scan: {e}" for e in scan_errors)

    indexed = {}
    for rel, items in sites.items():
        for line, full, macro, _reason in items:
            indexed.setdefault((rel, full), []).append((line, macro))

    seen = set()
    for pos, entry in enumerate(entries):
        where = f"{inventory} entry {pos}"
        if not isinstance(entry, dict):
            failures.append(f"FAIL {where}: not an object")
            continue
        keys = set(entry)
        is_feature = (isinstance(entry.get("cell"), str)
                      and entry["cell"] == "feature")
        want = ("file/path/reason/cell/owner" if is_feature
                else "file/path/reason/cell")
        if keys != set(want.split("/")):
            failures.append(f"FAIL {where}: keys must be exactly {want}")
            continue
        key = (entry["file"], entry["path"])
        if key in seen:
            failures.append(f"FAIL {where}: duplicate of {key[0]} {key[1]}")
            continue
        seen.add(key)
        if not isinstance(entry["cell"], str) or entry["cell"] not in cells:
            failures.append(f"FAIL {where}: cell {entry['cell']!r} is not in "
                            f"the closed set {sorted(cells)}")
        matches = indexed.get(key, [])
        if not matches:
            failures.append(f"FAIL {where}: no matching #[ignore] site for "
                            f"{key[0]} {key[1]}")
            continue
        if entry["cell"] == "feature":
            owner = entry["owner"]
            if not isinstance(owner, str) or not owner.strip():
                failures.append(
                    f"FAIL {where}: feature {entry['path']} must name "
                    "a non-empty owner")
                continue
            if owner not in ALLOWED_OWNERS:
                failures.append(
                    f"FAIL {where}: feature {entry['path']} has unknown "
                    f"owner {owner!r} (expected one of "
                    f"{', '.join(ALLOWED_OWNERS)})")
                continue
            if owner == WIDE_OWNER and entry["path"] not in wide:
                failures.append(
                    f"FAIL {where}: feature {entry['path']} is owned by "
                    f"{WIDE_OWNER} but not curated in {WIDE_LIST}")
            continue
        if (isinstance(entry.get("file"), str)
                and entry["file"].startswith("tests/")):
            if entry["cell"] in INTEGRATION_CELLS:
                curated = f"{entry['file']}:{entry['path']}"
                if curated not in integration:
                    failures.append(
                        f"FAIL {where}: {entry['cell']} integration "
                        f"{entry['path']} is not curated in "
                        f"{INTEGRATION_LIST}")
            continue
        if entry["cell"] != "privileged":
            continue
        _line, macro = matches[0]
        if macro is None:
            if entry["path"] not in registered:
                failures.append(
                    f"FAIL {where}: privileged {entry['path']} is not "
                    f"curated in {runner.relative_to(root)
                                     if runner.is_relative_to(root)
                                     else runner}")
        else:
            stem = entry["path"][:-1]
            module = stem.rsplit("::", 1)[0] if "::" in stem else ""
            expansions = macro_expansions(root / entry["file"], macro)
            if not expansions:
                failures.append(f"FAIL {where}: macro {macro} has no "
                                "invocations to verify")
            for name, absent in expansions:
                expanded = f"{module}::{name}" if module else name
                if name is None:
                    failures.append(f"FAIL {where}: cannot parse a "
                                    f"{macro}! invocation")
                elif not absent and expanded not in registered:
                    failures.append(
                        f"FAIL {where}: privileged macro {macro}! expands "
                        f"to {expanded}, not curated in "
                        f"{runner.relative_to(root)
                            if runner.is_relative_to(root) else runner}")
                elif absent and expanded not in wide:
                    failures.append(
                        f"FAIL {where}: privileged macro {macro}! expands "
                        f"to feature-gated {expanded}, not curated in "
                        f"{WIDE_LIST}")

    for (rel, full), matches in sorted(indexed.items()):
        if (rel, full) not in seen:
            lines = ",".join(str(line) for line, _ in matches)
            failures.append(f"FAIL {rel}:{lines}: #[ignore] site {full} "
                            "has no inventory entry")

    wide_sites = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("cell") == "feature" and entry.get("owner") == WIDE_OWNER:
            wide_sites.add(entry.get("path"))
        path = entry.get("path")
        if (isinstance(path, str) and path.endswith("!")
                and (entry.get("file"), path) in indexed):
            stem = path[:-1]
            macro = stem.rsplit("::", 1)[-1]
            module = stem.rsplit("::", 1)[0] if "::" in stem else ""
            for name, absent in macro_expansions(root / entry["file"],
                                                 macro):
                if name is not None and absent:
                    wide_sites.add(f"{module}::{name}" if module else name)
    for member in sorted(wide):
        if member not in wide_sites:
            failures.append(f"FAIL runner: {WIDE_LIST} member {member} is "
                            "not a wide-owned inventory site or a "
                            "feature-gated expansion")

    curated_sites = set()
    for entry in entries:
        if (isinstance(entry, dict) and isinstance(entry.get("file"), str)
                and entry["file"].startswith("tests/")
                and entry.get("cell") in INTEGRATION_CELLS):
            curated_sites.add(f"{entry['file']}:{entry.get('path')}")
    for member in sorted(integration):
        if member not in curated_sites:
            failures.append(f"FAIL runner: {INTEGRATION_LIST} member "
                            f"{member} is not a live-kernel/privileged "
                            "integration inventory entry")
    return failures


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--inventory", default=None)
    parser.add_argument("--runner", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root)
    failures = check(root=root, inventory=args.inventory, runner=args.runner)
    inv = Path(args.inventory) if args.inventory else root / DEFAULT_INVENTORY
    try:
        entries = load_inventory(inv)[1]
        count = len(entries)
    except (FileNotFoundError, OSError):
        count = 0
    for failure in failures:
        print(failure)
    if failures:
        print(f"ignored-tests: {len(failures)} problem(s), "
              f"{count} inventoried site(s)")
        return 1
    print(f"ignored-tests: all {count} inventoried site(s) match the sources; "
          "privileged, wide-feature and integration curation verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
