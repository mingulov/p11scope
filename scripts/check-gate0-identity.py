#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Section-level gate-0 identity check (ruling P2F-2).

Compares the seven default BPF objects between two build output directories
(a base OUT_DIR and a candidate OUT_DIR). For each object the following must
be byte-identical:

- .text (executable code)
- .rodata (read-only data; both missing counts as identical)
- .maps and maps (map definitions, C and Rust sides)
- symbol table (llvm-nm output)
- .BTF raw bytes (type/func records; line info lives in .BTF.ext, not .BTF)

Debug metadata (.debug_*, .BTF.ext line info) may differ: clang -g embeds the
source MD5, so any edit to a shared C file changes those bytes. They are
reported as informational only and never fail the check.

Usage:
  python3 -I scripts/check-gate0-identity.py BASE_OUT CANDIDATE_OUT

Each OUT_DIR holds p11scope-ebpf{,-inventory,-inventory-callers,-identity}
at its top level and the three counter-bank objects under
counter-bank-growth-v2/ (a flat directory holding all seven by basename is
also accepted, for archived evidence). Exits 0 only when every required
section matches for all seven objects.
"""

import hashlib
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
        problems: list[str] = []
        for section in REQUIRED_SECTIONS:
            try:
                base_bytes = section_bytes(base_obj, section)
                cand_bytes = section_bytes(cand_obj, section)
            except RuntimeError as error:
                print(f"{short}: FAIL ({error})")
                failed = True
                break
            if base_bytes is None and cand_bytes is None:
                continue
            if base_bytes is None or cand_bytes is None:
                problems.append(f"{section} present on one side only")
            elif digest(base_bytes) != digest(cand_bytes):
                problems.append(
                    f"{section} differs "
                    f"({digest(base_bytes)[:12]} vs {digest(cand_bytes)[:12]})"
                )
        else:
            try:
                base_syms = symbol_text(base_obj)
                cand_syms = symbol_text(cand_obj)
            except RuntimeError as error:
                print(f"{short}: FAIL ({error})")
                failed = True
                continue
            if base_syms != cand_syms:
                problems.append("symbols (llvm-nm) differ")
        if problems:
            print(f"{short}: FAIL ({'; '.join(problems)})")
            failed = True
        else:
            notes: list[str] = []
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
