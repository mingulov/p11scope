#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Section-level gate-0 identity check (ruling P2F-2, hardened by P2F-5 F3,
I1 program sections and the P2F-9 structural .BTF fallback).

Compares the seven default BPF objects between two build output directories
(a base OUT_DIR and a candidate OUT_DIR). For each object the following must
be byte-identical:

- .text (executable code)
- every other allocated or executable non-debug section, enumerated from
  readelf flags (the BPF program sections: uprobe, fentry/*, ...), so a
  same-length code change inside a program section fails naming it
- .rodata (read-only data; both missing counts as identical)
- .maps and maps (map definitions, C and Rust sides)
- every allocated section's ELF type and size from the readelf header, so
  NOBITS sections such as .bss (no bytes to dump) still fail on growth
- symbol table (llvm-nm output)
- .BTF raw bytes (type/func records; line info lives in .BTF.ext, not .BTF),
  with the structural fallback below
- every relocation section (.rel*) present in either object, except
  relocations against debug metadata (see below); absent on both counts
  as identical, as for .rodata. Both spellings (.rel.text and .reluprobe)
  are covered, so a change that only re-targets references (e.g. map-index
  churn with identical code bytes) fails.

When .BTF is the only differing section, the comparison falls back to an
ID-free structural check (bpftool JSON raw dump with each type reference
replaced by the canonical form of the type it points to, cycles broken by
kind+name, compared as a sorted multiset: a pure type-ID permutation
leaves it identical while any added, removed or reshaped type changes it)
and the report says which path decided. Any other differing section fails
by bytes without consulting bpftool. The C dump is not used here: it omits
anonymous map structs, VAR/DATASEC records and array sizes, so real
map-capacity, map-type and .bss-size changes normalize equal under it.
The noninterference fallback pairs its C dump with the .BTF size, the
string set, exact .BTF.ext bytes and exact bytes for every other section,
which this debug-allowing checker does not.

Debug metadata (.debug_*, .BTF.ext line info) may differ: clang -g embeds the
source MD5, so any edit to a shared C file changes those bytes. They are
reported as informational only and never fail the check. Relocations against
them (.rel.debug_*, .rel.BTF.ext) drift with the debug bytes themselves and
are skipped for the same reason.

Usage:
  python3 -I scripts/check-gate0-identity.py BASE_OUT CANDIDATE_OUT

Each OUT_DIR holds p11scope-ebpf{,-inventory,-inventory-callers,-identity}
at its top level and the three counter-bank objects under
counter-bank-growth-v2/ (a flat directory holding all seven by basename is
also accepted, for archived evidence). Exits 0 only when every required
section matches for all seven objects.
"""

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

OBJECTS = (
    "p11scope-ebpf",
    "p11scope-ebpf-inventory",
    "p11scope-ebpf-inventory-callers",
    "p11scope-ebpf-identity",
    "counter-bank-growth-v2/p11scope-ebpf-counts-bank-growth-v2",
    "counter-bank-growth-v2/p11scope-ebpf-latency-bank-growth-v2",
    "counter-bank-growth-v2/p11scope-ebpf-timestamps-bank-growth-v2",
)

REQUIRED_SECTIONS = (".text", ".rodata", ".maps", "maps", ".BTF")
INFORMATIONAL_SECTIONS = (".BTF.ext", ".debug_info", ".debug_line")


def section_bytes(path: Path, section: str) -> bytes | None:
    """Raw bytes of one ELF section, or None when the section is absent."""
    objcopy = shutil.which("llvm-objcopy")
    if objcopy is None:
        raise RuntimeError("llvm-objcopy not on PATH")
    # --dump-section writes the file even for non-alloc sections (unlike
    # -O binary --only-section, which silently yields empty bytes there).
    tmp = path.parent / f".gate0-{path.name}-{section.replace('/', '_')}.tmp"
    try:
        result = subprocess.run(
            [objcopy, f"--dump-section={section}={tmp}", str(path), "/dev/null"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or not tmp.is_file():
            return None
        return tmp.read_bytes()
    finally:
        tmp.unlink(missing_ok=True)


def symbol_text(path: Path) -> str:
    """Deterministic symbol listing (llvm-nm sorts by name)."""
    nm = shutil.which("llvm-nm")
    if nm is None:
        raise RuntimeError("llvm-nm not on PATH")
    result = subprocess.run(
        [nm, str(path)], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"llvm-nm failed on {path}: {result.stderr.strip()}")
    return result.stdout


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_relocation_section(name: str) -> bool:
    """True for ELF relocation section names (.rel*)."""
    return name.startswith(".rel")


def relocation_target(name: str) -> str:
    """The section a relocation section applies to (.relS -> S)."""
    if name.startswith(".rela"):
        return name[len(".rela") :]
    return name[len(".rel") :]


def is_informational_relocation(name: str) -> bool:
    """True when a relocation section targets debug metadata.

    Relocations against .debug_* and .BTF.ext drift with the debug bytes
    themselves, which ruling P2F-2 allows to differ (clang -g embeds the
    source MD5); they are skipped, never compared. Relocations against
    required sections (.rel.BTF included) are compared like code.
    """
    target = relocation_target(name)
    return target == ".BTF.ext" or target.startswith(".debug")


def readelf_sections(path: Path) -> list[tuple[str, str]]:
    """Every ELF section's (name, flags) via readelf -S -W (wide: never truncated).

    Flags are the single-letter section flags (WAXMSILOGT...); flag-less
    rows report "". The first token after the fixed columns is flags
    exactly when it is all letters: link/info/align are numeric, so a
    missing flags field cannot be mistaken for the link number.
    """
    readelf = shutil.which("readelf")
    if readelf is None:
        raise RuntimeError("readelf not on PATH")
    result = subprocess.run(
        [readelf, "-S", "-W", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"readelf failed on {path}: {result.stderr.strip()}")
    sections = []
    for line in result.stdout.splitlines():
        match = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+"
            r"\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s*(.*)$",
            line,
        )
        if match:
            rest = match.group(2).split()
            flags = (
                rest[0]
                if rest and re.fullmatch(r"[A-Za-z]+", rest[0])
                else ""
            )
            sections.append((match.group(1), flags))
    return sections


def readelf_section_names(path: Path) -> list[str]:
    """All ELF section names via readelf -S -W (wide: never truncated)."""
    return [name for name, _ in readelf_sections(path)]


def readelf_section_headers(path: Path) -> dict[str, tuple[str, str, int]]:
    """Every ELF section's (type, flags, size) via readelf -S -W.

    Keys are section names; values are the ELF type (PROGBITS, NOBITS,
    ...), the single-letter flags as in readelf_sections, and the header
    size in bytes. Raises RuntimeError when readelf is missing or fails.
    """
    readelf = shutil.which("readelf")
    if readelf is None:
        raise RuntimeError("readelf not on PATH")
    result = subprocess.run(
        [readelf, "-S", "-W", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"readelf failed on {path}: {result.stderr.strip()}")
    headers: dict[str, tuple[str, str, int]] = {}
    for line in result.stdout.splitlines():
        match = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+"
            r"\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s*(.*)$",
            line,
        )
        if match:
            rest = match.group(4).split()
            flags = (
                rest[0]
                if rest and re.fullmatch(r"[A-Za-z]+", rest[0])
                else ""
            )
            headers[match.group(1)] = (
                match.group(2),
                flags,
                int(match.group(3), 16),
            )
    return headers


def is_program_section(name: str, flags: str) -> bool:
    """True for allocated or executable non-debug sections (I1).

    These hold code and live data: .text plus every BPF program section
    (uprobe, uretprobe, fentry/*, ...). Debug metadata never carries A/X
    but is excluded by name anyway, as is .BTF.ext line info.
    """
    if name.startswith(".debug") or name == ".BTF.ext":
        return False
    return "A" in flags or "X" in flags


def program_sections(path: Path) -> list[str]:
    """Allocated/executable non-debug sections of one object, sorted."""
    return sorted(
        name for name, flags in readelf_sections(path) if is_program_section(name, flags)
    )


def relocation_sections(path: Path) -> list[str]:
    """Required relocation sections of one object, sorted.

    Every .rel* section present, except relocations against informational
    debug metadata (see is_informational_relocation).
    """
    return sorted(
        name
        for name in readelf_section_names(path)
        if is_relocation_section(name) and not is_informational_relocation(name)
    )


def compare_object(base_obj: Path, cand_obj: Path) -> list[str]:
    """Problems comparing one object pair; [] means identical.

    Every required section, every allocated/executable non-debug section
    present in either object, and every relocation section present in
    either object must be byte-identical (absent on both counts as
    identical); every allocated non-debug section's ELF type and size must
    match too, so NOBITS sections such as .bss (no bytes to dump) are not
    skipped; and the symbol listings must match. Raises RuntimeError when
    a required tool is missing or fails.
    """
    problems: list[str] = []
    relocs = sorted(
        set(relocation_sections(base_obj)) | set(relocation_sections(cand_obj))
    )
    programs = sorted(
        set(program_sections(base_obj)) | set(program_sections(cand_obj))
    )
    sections: list[str] = []
    for section in list(REQUIRED_SECTIONS) + programs + relocs:
        if section not in sections:
            sections.append(section)
    for section in sections:
        base_bytes = section_bytes(base_obj, section)
        cand_bytes = section_bytes(cand_obj, section)
        if base_bytes is None and cand_bytes is None:
            continue
        if base_bytes is None or cand_bytes is None:
            problems.append(f"{section} present on one side only")
        elif digest(base_bytes) != digest(cand_bytes):
            problems.append(
                f"{section} differs "
                f"({digest(base_bytes)[:12]} vs {digest(cand_bytes)[:12]})"
            )
    base_headers = readelf_section_headers(base_obj)
    cand_headers = readelf_section_headers(cand_obj)
    allocated: set[str] = set()
    for name, (_, flags, _) in list(base_headers.items()) + list(cand_headers.items()):
        if "A" in flags and not name.startswith(".debug") and name != ".BTF.ext":
            allocated.add(name)
    for name in sorted(allocated):
        base_header = base_headers.get(name)
        cand_header = cand_headers.get(name)
        if base_header is None or cand_header is None:
            if not any(problem.startswith(name) for problem in problems):
                problems.append(f"{name} present on one side only (ELF header)")
        else:
            base_type, _, base_size = base_header
            cand_type, _, cand_size = cand_header
            if base_type != cand_type or base_size != cand_size:
                problems.append(
                    f"{name} header differs "
                    f"(type {base_type} vs {cand_type}, "
                    f"size {base_size} vs {cand_size})"
                )
    base_syms = symbol_text(base_obj)
    cand_syms = symbol_text(cand_obj)
    if base_syms != cand_syms:
        problems.append("symbols (llvm-nm) differ")
    return problems


BTF_REF_KEYS = ("type_id", "ret_type_id", "index_type_id")


def btf_canonical_multiset(path: Path) -> list[str]:
    """The ID-free structural BTF type multiset, sorted.

    Takes `bpftool -j btf dump file X format raw`, drops every `id`, and
    replaces each type reference (`type_id`, `ret_type_id`,
    `index_type_id`) with the canonical form of the type it points to,
    breaking reference cycles by kind+name. A pure type-ID permutation
    (the round-4 flake) sorts to an identical multiset, while any added,
    removed or reshaped type -- including anonymous map structs, VAR,
    DATASEC, FUNC and array sizes, which the C dump omits -- changes it.
    Both sides always use this run's bpftool, so no cross-version skew
    can pass or fail the comparison. Raises RuntimeError when bpftool is
    missing, fails, or emits an unparseable or dangling type table.
    """
    bpftool = shutil.which("bpftool")
    if bpftool is None:
        raise RuntimeError("bpftool not on PATH")
    result = subprocess.run(
        [bpftool, "-j", "btf", "dump", "file", str(path), "format", "raw"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(
            f"bpftool BTF dump failed on {path}: {result.stderr.strip()[:200]}"
        )
    try:
        raw_types = json.loads(result.stdout)["types"]
        by_id = {entry["id"]: entry for entry in raw_types}
    except (ValueError, KeyError, TypeError) as error:
        raise RuntimeError(
            f"bpftool BTF dump unparseable on {path}: {error}"
        ) from error
    memo: dict[int, str] = {}

    def canonical(type_id: int, stack: frozenset[int]) -> str:
        if type_id == 0:
            return "void"
        try:
            entry = by_id[type_id]
        except KeyError:
            raise RuntimeError(
                f"bpftool BTF dump on {path} references unknown type {type_id}"
            ) from None
        if type_id in stack:
            return f"{entry.get('kind')}:{entry.get('name')}"
        if type_id in memo:
            return memo[type_id]
        grown = stack | {type_id}

        def substitute(value):  # type: ignore[no-untyped-def]
            if isinstance(value, dict):
                return {
                    key: (
                        canonical(item, grown)
                        if key in BTF_REF_KEYS and isinstance(item, int)
                        else substitute(item)
                    )
                    for key, item in sorted(value.items())
                    if key != "id"
                }
            if isinstance(value, list):
                return [substitute(item) for item in value]
            return value

        form = json.dumps(substitute(entry), sort_keys=True)
        memo[type_id] = form
        return form

    return sorted(canonical(type_id, frozenset()) for type_id in by_id)


def is_btf_only_problems(problems: list[str]) -> bool:
    """True when .BTF bytes are the only difference (the fallback trigger).

    Only a byte mismatch (".BTF differs") qualifies: a .BTF section
    present on one side only is a structural difference, never an order
    flake, and fails by bytes.
    """
    return len(problems) == 1 and problems[0].startswith(".BTF differs")


def adjudicate_btf_only(base_obj: Path, cand_obj: Path) -> str | None:
    """None when the .BTF-only pair normalizes equal, else its problem.

    A normalized match means the byte difference is a semantically null
    type-ID permutation (the round-4 flake); a mismatch, or an
    unavailable bpftool, fails closed naming .BTF.
    """
    try:
        match = btf_canonical_multiset(base_obj) == btf_canonical_multiset(cand_obj)
    except RuntimeError as error:
        return f".BTF differs (bpftool unavailable for normalized comparison: {error})"
    if match:
        return None
    return ".BTF differs (bpftool-normalized forms differ)"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: check-gate0-identity.py BASE_OUT CANDIDATE_OUT",
            file=sys.stderr,
        )
        return 2
    base = Path(argv[1])
    candidate = Path(argv[2])

    def locate(root: Path, name: str) -> Path:
        nested = root / name
        if nested.is_file():
            return nested
        flat = root / Path(name).name
        if flat.is_file():
            return flat
        return nested

    failed = False
    for name in OBJECTS:
        base_obj = locate(base, name)
        cand_obj = locate(candidate, name)
        short = Path(name).name
        if not base_obj.is_file():
            print(f"{short}: FAIL (missing in base: {base_obj})")
            failed = True
            continue
        if not cand_obj.is_file():
            print(f"{short}: FAIL (missing in candidate: {cand_obj})")
            failed = True
            continue
        try:
            problems = compare_object(base_obj, cand_obj)
        except RuntimeError as error:
            print(f"{short}: FAIL ({error})")
            failed = True
            continue
        btf_note = ""
        if is_btf_only_problems(problems):
            decision = adjudicate_btf_only(base_obj, cand_obj)
            if decision is None:
                problems = []
                btf_note = ".BTF decided by bpftool-normalized comparison"
            else:
                problems = [decision]
        if problems:
            print(f"{short}: FAIL ({'; '.join(problems)})")
            failed = True
        else:
            notes: list[str] = [btf_note] if btf_note else []
            for section in INFORMATIONAL_SECTIONS:
                base_bytes = section_bytes(base_obj, section)
                cand_bytes = section_bytes(cand_obj, section)
                if base_bytes is None and cand_bytes is None:
                    continue
                if base_bytes is None or cand_bytes is None:
                    notes.append(f"{section} present on one side only")
                elif digest(base_bytes) != digest(cand_bytes):
                    notes.append(f"{section} differs (allowed)")
            suffix = f" [{'; '.join(notes)}]" if notes else " [debug identical]"
            print(f"{short}: PASS{suffix}")
    if failed:
        print("OVERALL: FAIL")
        return 1
    print("OVERALL: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
