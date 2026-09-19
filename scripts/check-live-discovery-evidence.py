#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Frozen execution manifest, preflight, and campaign validator for the
Slice 1b-2 production live-discovery gates.

This file owns the finite lifecycle and campaign semantics; the shell gate
(`scripts/verify-live-discovery-preflight.sh`) owns environment setup and
cleanup only. Everything it claims is either recomputed from the exact
candidate sources in this worktree or recomputed from the frozen bytes under
the private root - nothing is trusted because the manifest said so.

Modes:
  --write-manifest --private-root ROOT [--fixture-bits 32|64]
                                         publish v2 from built fixtures and
                                         completed prepared dependency receipts
  --preflight FILE --manifest FILE       validate one preflight report
  --campaign ROOT --manifest FILE        validate the campaign under ROOT
  --self-test                            nonprivileged mutation self-test
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile

MANIFEST_SCHEMA = "p11scope-live-discovery-execution/v2"
HISTORICAL_MANIFEST_SCHEMA = "p11scope-live-discovery-execution/v1"
PREFLIGHT_SCHEMA = "p11scope-live-discovery-preflight/v1"
CAMPAIGN_SCHEMA = "p11scope-live-discovery-campaign/v1"
ROW_SCHEMA = "p11scope-live-discovery-row/v1"
OBJECT_SCHEMA = "p11scope-live-discovery-object/v1"

# Verbatim frozen fixture build flags (plan Task 9 Step 1).
CFLAGS = "-std=c11 -O2 -Wall -Wextra -Werror -fPIC"
SHARED_LDFLAGS = "-shared -Wl,-z,defs"
DRIVER_LDFLAGS = "-ldl -pthread"

FIXTURE_SOURCES = (
    "tests/fixtures/live-discovery-provider.c",
    "tests/fixtures/live-discovery-driver.c",
)
HISTORICAL_VALIDATORS = (
    "scripts/check-live-discovery-evidence.py",
    "scripts/check-live-discovery-object.py",
    "scripts/verify-live-discovery-preflight.sh",
)
VALIDATORS = HISTORICAL_VALIDATORS + (
    "scripts/prepared-dependency-tools.sh",
    "scripts/prepared-dependency-snapshot.sh",
    "scripts/product-build.sh",
    "scripts/merge-checksum-ledgers.py",
    "scripts/prepared-dependency-evidence.py",
    "scripts/check-prepared-dependencies.py",
    "scripts/prepare-dependencies.py",
)
PROVIDERS = {"exported": "provider-exported.so", "hidden": "provider-hidden.so"}
DRIVERS = {
    "initial_set": {
        "exported": "driver-needed-exported",
        "hidden": "driver-needed-hidden",
    },
    "dlopen": {"exported": "driver-dlopen", "hidden": "driver-dlopen"},
}
FIXTURE_OUTPUTS = tuple(PROVIDERS.values()) + (
    "driver-needed-exported",
    "driver-needed-hidden",
    "driver-dlopen",
)

# The three standard return ABIs and the exact production programs that attach
# to each. Per-surface target sets stay disjoint so a row cannot borrow another
# surface's evidence.
SURFACE_TARGETS = {
    "C_GetFunctionList": ["function_list_entry", "function_list_return"],
    "C_GetInterfaceList": ["interface_list_entry", "interface_list_return"],
    "C_GetInterface": ["interface_entry", "interface_return"],
}
MARKER_PREFIX = "P11SCOPE_FIXTURE"

# The deterministic fixture lanes, each frozen as an exact invocation of a
# frozen driver over frozen provider bytes. `{exported}`/`{hidden}` are the
# frozen provider paths; `{exported_copy}` is a byte-identical copy of the
# exported provider at a second path, so a lane can separate a raw content key
# from a full (device/inode/path) identity. `markers` says which per-surface
# markers that lane must produce: both phases, the application phase only, or
# none at all.
PROVIDER_REFERENCES = ("{exported}", "{hidden}", "{exported_copy}")
FIXTURE_ENV_KNOBS = (
    "P11SCOPE_FIXTURE_GATE",
    "P11SCOPE_FIXTURE_QUIET",
    "P11SCOPE_FIXTURE_INTERFACES",
    "P11SCOPE_FIXTURE_REPEAT",
    "P11SCOPE_FIXTURE_TRUNCATE",
)
MARKER_EXPECTATIONS = ("constructor+application", "application", "none")
LANES = {
    "initial-set-provider": {
        "driver": "driver-needed-exported",
        "argv": ["needed"],
        "env": {},
        "markers": "constructor+application",
    },
    "late-dlopen-provider": {
        "driver": "driver-dlopen",
        "argv": ["dlopen", "{exported}"],
        "env": {"P11SCOPE_FIXTURE_GATE": "1"},
        "markers": "constructor+application",
    },
    "exported-tables": {
        "driver": "driver-needed-exported",
        "argv": ["needed"],
        "env": {},
        "markers": "constructor+application",
    },
    "hidden-tables": {
        "driver": "driver-needed-hidden",
        "argv": ["needed"],
        "env": {},
        "markers": "constructor+application",
    },
    "two-providers": {
        "driver": "driver-dlopen",
        "argv": ["dlopen", "{exported}", "{hidden}"],
        "env": {},
        "markers": "constructor+application",
    },
    "shared-exact-target": {
        "driver": "driver-dlopen",
        "argv": ["dlopen", "{exported}", "{exported}"],
        "env": {},
        "markers": "constructor+application",
    },
    "identity-collision": {
        "driver": "driver-dlopen",
        "argv": ["dlopen", "{exported}", "{exported_copy}"],
        "env": {},
        "markers": "constructor+application",
    },
    "child-exec-failure": {
        "driver": "driver-dlopen",
        "argv": ["exec-fail"],
        "env": {},
        "markers": "none",
    },
    "loss-ring-state-read-truncation": {
        "driver": "driver-dlopen",
        "argv": ["dlopen", "{exported}"],
        "env": {
            "P11SCOPE_FIXTURE_QUIET": "1",
            "P11SCOPE_FIXTURE_REPEAT": "200000",
            "P11SCOPE_FIXTURE_TRUNCATE": "1",
        },
        "markers": "none",
    },
    "pause-partial": {
        "driver": "driver-dlopen",
        "argv": ["pause-partial", "{exported}", "{hidden}"],
        "env": {"P11SCOPE_FIXTURE_GATE": "1"},
        "markers": "constructor+application",
    },
    "zero-modules": {
        "driver": "driver-dlopen",
        "argv": ["zero-modules"],
        "env": {},
        "markers": "none",
    },
}

LOAD_KINDS = ("initial_set", "dlopen")
TABLE_KINDS = ("exported", "hidden")
PAUSE_POLICIES = ("never", "auto", "always")
CHILDREN_PER_ROW = 20
FALLBACK_PER_KERNEL = 20
FALLBACK_REASONS = ("hook_absent", "hook_unresolved", "hook_unsafe")
NON_PASS_OUTCOMES = (
    "mixed",
    "missing",
    "timed_out",
    "replaced",
    "lifecycle_failed",
    "privacy_failed",
    "unclassified",
)
# The isolated A/B spike proved its lifecycle over exactly these four maps. The
# production oracle is the complete product inventory; a row that reports the
# A/B set is reporting the wrong campaign's evidence.
AB_FOUR_MAP_ORACLE = ("COUNTERS", "DISCOVERY", "DISCOVERY_STATE", "PAUSE_PIDS")
PREFLIGHT_OUTCOMES = ("capacity", "stale", "generation", "identity", "state_read")
# glibc 2.41 is the first release carrying the rtld-audit fix for bug 31986.
GLIBC_31986_FIXED_FROM = (2, 41)
# The forced dlopen_return fallback attaches at the return of the pinned
# companion libc's dlopen; its reviewed offset is that symbol's file offset.
FALLBACK_SYMBOL = "dlopen"
# The every-hit loader hook the product attaches in the pinned interpreter.
DEBUG_STATE_SYMBOL = "_dl_debug_state"

# Frozen campaign parameters. These are declared once here, before the first
# privileged run, so no lane can invent its own budget or kernel later.
FROZEN_KERNELS = (
    ("jammy", "5.15.", "retained Ubuntu cloud image overlay base"),
    ("noble", "6.8.", "retained Ubuntu cloud image overlay base"),
    ("fedora", "6.19.", "retained Fedora cloud image overlay base"),
)
FROZEN_CAPS = ("CAP_BPF", "CAP_PERFMON", "CAP_SYS_PTRACE", "CAP_SYS_RESOURCE")
FROZEN_DEADLINES = {"attempt_seconds": 120, "campaign_seconds": 64800, "pause_poll_ms": 1}
FROZEN_TOPOLOGY = {"cold_boot": True, "containers": ["docker", "kind"]}


def fail(message):
    raise RuntimeError(message)


def check(claims):
    for okay, message in claims:
        if not okay:
            fail(message)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(Path(path).read_bytes())


def repo_root():
    return Path(__file__).resolve().parents[1]


def get(document, *path, default=None):
    for key in path:
        if not isinstance(document, dict) or key not in document:
            return default
        document = document[key]
    return document


# --------------------------------------------------------------------------
# Source-bound constants. The preflight oracle below is only meaningful if its
# boundaries are the product's own, so they are parsed out of the exact
# candidate sources rather than restated as literals.
# --------------------------------------------------------------------------


def rust_const(text, name, path):
    match = re.search(
        rf"(?:pub(?:\(crate\))?\s+)?const\s+{name}\s*:\s*[A-Za-z0-9_]+\s*=\s*([^;]+);",
        text,
    )
    if not match:
        fail(f"{path}: constant {name} is missing")
    expression = re.sub(r"(?<=[0-9])_?(?:u|i)(?:8|16|32|64|size)\b", "", match.group(1))
    expression = expression.replace("_", "").strip()
    if not re.fullmatch(r"[0-9a-fx()<>+\-* ]+", expression):
        fail(f"{path}: constant {name} is not a plain integer expression")
    # The product spells these as shifted expressions (`1 << 8`, `(1 << 55) - 1`),
    # which ast.literal_eval cannot evaluate. The input is one constant from a
    # source file in this worktree, already restricted above to digits and
    # arithmetic, and eval runs with no builtins and no names in scope.
    return int(eval(expression, {"__builtins__": {}}, {}))  # noqa: S307


def loader_state_offsets(source, path):
    marker = "fn loader_state_address("
    start = source.find(marker)
    if start == -1:
        fail(f"{path}: loader_state_address is missing")
    opening = source.find("{", start + len(marker))
    if opening == -1:
        fail(f"{path}: loader_state_address body is malformed")
    depth = 0
    end = None
    for cursor in range(opening, len(source)):
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
            if depth == 0:
                end = cursor
                break
    if end is None:
        fail(f"{path}: loader_state_address body is malformed")
    body = source[opening + 1 : end]
    offsets = {}
    for variant, abi in [("Lp64", "linux-lp64"), ("Ilp32", "linux-ilp32")]:
        matches = re.findall(rf"ElfAbi::{variant}\s*=>\s*([0-9_]+)", body)
        if len(matches) != 1:
            fail(f"{path}: loader_state_address needs one {variant} offset arm")
        offsets[abi] = int(matches[0].replace("_", ""))
    return offsets


def source_constants(root, engine_source=None):
    common_path = root / "crates/ebpf-common/src/lib.rs"
    loader_path = root / "src/discovery/loader.rs"
    ebpf_path = root / "crates/ebpf/src/main.rs"
    engine_path = root / "src/discovery/engine.rs"
    common = common_path.read_text()
    loader = loader_path.read_text()
    ebpf = ebpf_path.read_text()
    engine = engine_path.read_text() if engine_source is None else engine_source
    payload_mask = rust_const(common, "LOADER_STATE_PAYLOAD_MASK", common_path)
    r_state_offsets = loader_state_offsets(engine, engine_path)
    facts = {
        "context_ids": rust_const(common, "LOADER_CONTEXT_ID_MASK", common_path) + 1,
        "present_bit": rust_const(common, "LOADER_STATE_PRESENT", common_path),
        "shift": rust_const(common, "LOADER_STATE_SHIFT", common_path),
        "absent_sentinel": rust_const(common, "LOADER_STATE_ABSENT_SENTINEL", common_path),
        "payload_bits": payload_mask.bit_length(),
        "delta_min": rust_const(loader, "MIN_STATE_DELTA", loader_path),
        "delta_max": rust_const(loader, "MAX_STATE_DELTA", loader_path),
        "max_contexts": rust_const(loader, "MAX_LOADER_CONTEXTS", loader_path),
        "r_state_offsets": r_state_offsets,
        "function_ip_helper": "bpf_get_func_ip",
        "function_ip_fallback": "pt_regs.rip",
    }
    check(
        [
            (
                facts["context_ids"] == facts["max_contexts"],
                "loader context id mask and MAX_LOADER_CONTEXTS disagree",
            ),
            (
                facts["delta_max"] == (1 << (facts["payload_bits"] - 1)) - 1
                and facts["delta_min"] == -(1 << (facts["payload_bits"] - 1)),
                "signed state-delta bounds do not match the payload mask",
            ),
            (
                "helpers::bpf_get_func_ip" in ebpf,
                "the product no longer resolves the function IP through bpf_get_func_ip",
            ),
            (
                "(*ctx.regs).rip" in ebpf,
                "the product no longer carries the x86-64 pt_regs.rip fallback",
            ),
            (
                r_state_offsets["linux-lp64"] == ELF_ABIS[(2, 62)][1],
                "the product LP64 r_state offset differs from the ELF ABI oracle",
            ),
            (
                r_state_offsets["linux-ilp32"] == ELF_ABIS[(1, 3)][1],
                "the product ILP32 r_state offset differs from the ELF ABI oracle",
            ),
        ]
    )
    return facts


def production_inventory(root):
    """Exact production map/program inventory, from the one checked-in list."""
    checker = runpy.run_path(
        str(root / "scripts/check-bpf-map-defs.py"), run_name="live_discovery_evidence"
    )
    return {
        "maps": sorted(checker["SAFE_MAPS"]),
        "programs": sorted(checker["SAFE_PROGRAMS"]),
    }


# --------------------------------------------------------------------------
# Minimal ELF reader: PT_INTERP, PT_LOAD list, and a named dynamic symbol's
# pinned file offset. Enough to bind interpreter/loader/hook identities without
# adding a dependency or trusting an external tool's formatting.
# --------------------------------------------------------------------------

ELF_ABIS = {
    # (EI_CLASS, e_machine): (name, r_debug.r_state offset)
    (1, 3): ("linux-ilp32", 12),  # ELF32, EM_386
    (2, 62): ("linux-lp64", 24),  # ELF64, EM_X86_64
}


def _elf_unpack(fmt, blob, offset, path, label):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(blob):
        fail(f"{path}: truncated {label}")
    return struct.unpack_from(fmt, blob, offset)


def elf_facts(path, symbols=()):
    blob = Path(path).read_bytes()
    if len(blob) < 16 or blob[:4] != b"\x7fELF" or blob[5] != 1:
        fail(f"{path}: not a little-endian ELF object")
    elf_class = blob[4]
    if elf_class == 2:
        header_fmt = "<HHIQQQIHHHHHH"
        program_fmt = "<IIQQQQQQ"
        section_fmt = "<IIQQQQIIQQ"
        symbol_fmt = "<IBBHQQ"
    elif elf_class == 1:
        header_fmt = "<HHIIIIIHHHHHH"
        program_fmt = "<IIIIIIII"
        section_fmt = "<IIIIIIIIII"
        symbol_fmt = "<IIIBBH"
    else:
        fail(f"{path}: unsupported ELF class {elf_class}")
    (elf_type, machine, _, _, phoff, shoff, _, ehsize, phentsize, phnum, shentsize, shnum, _) = (
        _elf_unpack(header_fmt, blob, 16, path, "ELF header")
    )
    abi = ELF_ABIS.get((elf_class, machine))
    if abi is None:
        fail(f"{path}: unsupported ELF class/machine pair {elf_class}/{machine}")
    if elf_type not in (2, 3):
        fail(f"{path}: unsupported ELF type {elf_type}")
    expected_header = 52 if elf_class == 1 else 64
    if ehsize != expected_header:
        fail(f"{path}: malformed ELF header size {ehsize}")
    if phnum and phentsize < struct.calcsize(program_fmt):
        fail(f"{path}: malformed program-header entry size {phentsize}")
    if shnum and shentsize < struct.calcsize(section_fmt):
        fail(f"{path}: malformed section-header entry size {shentsize}")
    loads = []
    interpreter = None
    for index in range(phnum):
        program = _elf_unpack(
            program_fmt, blob, phoff + index * phentsize, path, f"program header {index}"
        )
        if elf_class == 2:
            kind, _, offset, vaddr, _, filesz, memsz, _ = program
        else:
            kind, offset, vaddr, _, filesz, memsz, _, _ = program
        if kind == 1:
            if filesz > memsz:
                fail(f"{path}: PT_LOAD file size exceeds memory size")
            if offset + filesz > len(blob):
                fail(f"{path}: PT_LOAD file range is out of bounds")
            loads.append({"offset": offset, "vaddr": vaddr, "filesz": filesz, "memsz": memsz})
        elif kind == 3:
            end = offset + filesz
            if filesz < 2 or end > len(blob):
                fail(f"{path}: truncated PT_INTERP")
            raw_interpreter = blob[offset:end]
            if not raw_interpreter.endswith(b"\0") or b"\0" in raw_interpreter[:-1]:
                fail(f"{path}: PT_INTERP is not terminated by one trailing NUL")
            interpreter = raw_interpreter[:-1].decode()
            if not interpreter.startswith("/"):
                fail(f"{path}: PT_INTERP is not one nonempty absolute path")
    sections = [
        _elf_unpack(
            section_fmt, blob, shoff + index * shentsize, path, f"section header {index}"
        )
        for index in range(shnum)
    ]
    version_tables = {}
    for version in sections:
        if version[1] != 0x6FFFFFFF:  # SHT_GNU_versym
            continue
        linked = version[6]
        if linked >= len(sections) or sections[linked][1] != 11:
            fail(f"{path}: symbol versions have invalid dynamic-symbol association")
        if linked in version_tables:
            fail(f"{path}: duplicate symbol-version table")
        dynamic = sections[linked]
        if dynamic[9] < struct.calcsize(symbol_fmt) or dynamic[5] % dynamic[9]:
            fail(f"{path}: malformed versioned dynamic-symbol table")
        if dynamic[4] + dynamic[5] > len(blob):
            fail(f"{path}: versioned dynamic-symbol table is out of bounds")
        if (
            version[9] != 2
            or version[5] % 2
            or version[5] < 2 * (dynamic[5] // dynamic[9])
            or version[4] + version[5] > len(blob)
        ):
            fail(f"{path}: malformed or truncated symbol-version table")
        version_tables[linked] = version
    resolved = {}
    for symbol in symbols:
        found = []
        for section_index, section in enumerate(sections):
            if section[1] not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
                continue
            if section[6] >= len(sections):
                fail(f"{path}: symbol table has invalid string-table index")
            strings = sections[section[6]]
            strtab = blob[strings[4] : strings[4] + strings[5]]
            if section[9] < struct.calcsize(symbol_fmt):
                fail(f"{path}: malformed symbol-table entry size {section[9]}")
            versions = version_tables.get(section_index)
            for cursor in range(section[4], section[4] + section[5], section[9]):
                ordinal = (cursor - section[4]) // section[9]
                if versions is not None:
                    version = _elf_unpack(
                        "<H", blob, versions[4] + ordinal * 2, path, "symbol version"
                    )[0]
                    if version & 0x8000:
                        continue
                symbol_entry = _elf_unpack(symbol_fmt, blob, cursor, path, "symbol table entry")
                if elf_class == 2:
                    name_offset, _, _, _, value, size = symbol_entry
                else:
                    name_offset, value, size, _, _, _ = symbol_entry
                if name_offset >= len(strtab):
                    fail(f"{path}: symbol name is outside its string table")
                end = strtab.find(b"\0", name_offset)
                if end == -1:
                    fail(f"{path}: unterminated symbol name")
                if strtab[name_offset:end].decode("utf-8", "replace") == symbol:
                    found.append((value, size))
        unique = sorted(set(found))
        if len(unique) != 1 or unique[0][0] == 0:
            fail(f"{path}: expected exactly one defined {symbol!r}, found {len(unique)}")
        value, size = unique[0]
        segment = next(
            (load for load in loads if load["vaddr"] <= value < load["vaddr"] + load["filesz"]),
            None,
        )
        if segment is None:
            fail(f"{path}: {symbol!r} is outside every PT_LOAD segment")
        resolved[symbol] = {
            "vaddr": value,
            "size": size,
            "file_offset": value - segment["vaddr"] + segment["offset"],
        }
    return {
        "path": str(path),
        "sha256": sha256_bytes(blob),
        "elf_class": elf_class,
        "machine": machine,
        "abi": abi[0],
        "r_state_offset": abi[1],
        "interpreter": interpreter,
        "loads": loads,
        "symbols": resolved,
    }


def glibc_release(version):
    match = re.fullmatch(r"(\d+)\.(\d+)", str(version))
    if not match:
        fail(f"unsupported libc version {version!r}; expected MAJOR.MINOR")
    return (int(match.group(1)), int(match.group(2)))


# --------------------------------------------------------------------------
# Freeze
# --------------------------------------------------------------------------


def frozen_paths(private_root):
    private_root = Path(private_root)
    frozen = private_root / "frozen"
    return {
        "private_root": private_root,
        "frozen": frozen,
        "bpf_object": frozen / "p11scope-ebpf",
        "bpf_inventory": frozen / "bpf-inventory.json",
        "runner": frozen / "p11scope",
        "fixtures": frozen / "fixtures",
        "campaign": private_root / "campaign",
        "manifest": private_root / "execution-manifest.json",
        "dependencies": private_root / "dependencies",
    }


def prepared_binding(private_root, root):
    """Bind retained shared evidence without querying Cargo or selecting tools.

    The private shared helper calls below deliberately remain a narrow adapter:
    it owns metadata projection, prepared input admission and receipt identities.
    This checker owns only their exact frozen layout and manifest binding.
    """
    directory = frozen_paths(private_root)["dependencies"]
    check([(directory.is_dir() and not directory.is_symlink(),
            "prepared dependency directory is missing or symlinked")])
    evidence = runpy.run_path(str(root / "scripts/prepared-dependency-evidence.py"))
    load = evidence["_load_module"]
    checker = load(root / "scripts/check-prepared-dependencies.py", "live_prepared_checker")
    preparer = load(root / "scripts/prepare-dependencies.py", "live_preparer")
    ledger = runpy.run_path(str(root / "scripts/merge-checksum-ledgers.py"))
    try:
        return _bind_prepared_receipts(directory, root, evidence, checker, preparer, ledger)
    except (evidence["EvidenceError"], checker.MetadataError,
            preparer.PreparationError, ledger["LedgerError"]) as error:
        fail(f"prepared dependencies: {error}")


def _bind_prepared_receipts(directory, root, evidence, checker, preparer, ledger):
    prefix = directory / "prepared"
    initial = evidence["_read_initial"](prefix, root, checker, preparer)
    final = evidence["_read_json_artifact"](Path(str(prefix) + ".final.receipt.json"), "final receipt")
    check([(isinstance(final, dict) and set(final) == set(initial),
            "prepared final receipt fields differ")])
    check([(final.get("phase") == "final", "prepared final receipt phase differs")])
    for field in set(initial) - {"phase", "artifacts"}:
        check([(final.get(field) == initial[field], f"prepared final {field} differs")])
    check([(final["artifacts"] == evidence["_artifact_identities"](prefix, "final"),
            "prepared final retained artifact identities differ")])
    # Reuse the metadata verifier and projection; never implement a resolver here.
    metadata = [
        f"{workspace}={prefix}.final.{context}.stdout.json"
        for context, workspace, _ in evidence["WORKSPACES"]
    ]
    projection = evidence["_projection"](
        checker.verify_details(root, root / "third-party/sources.json", metadata)
    )
    for field, value in projection.items():
        check([(final[field] == value, f"prepared final {field} projection differs")])
    for context, _, _ in evidence["WORKSPACES"]:
        for suffix in ("command.json", "context.json", "status"):
            check([(Path(f"{prefix}.initial.{context}.{suffix}").read_bytes()
                    == Path(f"{prefix}.final.{context}.{suffix}").read_bytes(),
                    f"prepared final {context} {suffix} differs")])
    artifacts = {
        f"{phase}.{suffix}": evidence["_identity"](
            Path(f"{prefix}.{phase}.{suffix}"), f"prepared {phase} {suffix}"
        )
        for phase in ("initial", "final")
        for suffix in evidence["_phase_suffixes"](phase)
    }
    snapshots = {
        phase: evidence["_identity"](directory / f"source.{phase}.sha256", f"{phase} snapshot")
        for phase in ("initial", "final")
    }
    check([(snapshots["initial"]["sha256"] == snapshots["final"]["sha256"],
            "prepared source snapshots differ")])
    rows = ledger["merge_ledgers"]([directory / "source.final.sha256"])
    check([(bool(rows), "prepared source snapshot is empty")])
    for relative, digest in rows:
        check([(sha256_file(root / relative) == digest, f"prepared source changed: {relative}")])
    return {"artifacts": artifacts, "snapshots": snapshots,
            "selected_tools": initial["tools"], "selected_inputs": initial["inputs"]}


def tool_line(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True).stdout.splitlines()[0]


def host_glibc_version():
    line = tool_line(["ldd", "--version"])
    match = re.search(r"(\d+\.\d+)\s*$", line)
    if not match:
        fail(f"cannot read a glibc version from {line!r}")
    return match.group(1)


def companion_libc_path(driver):
    """The exact libc the frozen dlopen driver resolves, from its own ldd."""
    for line in subprocess.run(
        ["ldd", str(driver)], capture_output=True, text=True, check=True
    ).stdout.splitlines():
        match = re.search(r"\blibc\.so\.6\s*=>\s*(\S+)", line)
        if match:
            return Path(match.group(1)).resolve(strict=True)
    fail(f"{driver}: no libc.so.6 in its resolved dependencies")


def _manifest_content(private_root, root, kernel_bases, fixture_bits=None, *, historical_fixture=False):
    """Build the frozen fixtures, then freeze one execution manifest.

    Every digest, ELF identity, toolchain identity and source-bound boundary
    below is computed here and recomputed by bind_manifest; nothing is trusted
    because a caller passed it in.
    """
    paths = frozen_paths(private_root)
    dependencies = None if historical_fixture else prepared_binding(private_root, root)
    constants = source_constants(root)
    inventory = production_inventory(root)
    fixtures = paths["fixtures"]
    commands = build_fixtures(root, fixtures, fixture_bits, execute=historical_fixture)
    toolchain = {
        "cc": "gcc",
        "cc_version": tool_line(["gcc", "--version"]),
        "ld_version": tool_line(["ld", "--version"]),
        "cflags": CFLAGS,
        "shared_ldflags": SHARED_LDFLAGS,
        "driver_ldflags": DRIVER_LDFLAGS,
    }

    fixture_elfs = {
        name: elf_facts(
            fixtures / name,
            symbols=("C_GetFunctionList",) if name == "provider-exported.so" else (),
        )
        for name in FIXTURE_OUTPUTS
    }
    driver = fixture_elfs["driver-needed-exported"]
    provider = fixture_elfs["provider-exported.so"]
    interpreter_path = Path(driver["interpreter"])
    interpreter = elf_facts(interpreter_path, symbols=(DEBUG_STATE_SYMBOL,))
    companion_path = companion_libc_path(fixtures / "driver-dlopen")
    companion = elf_facts(companion_path, symbols=(FALLBACK_SYMBOL,))
    check(
        [
            (
                len(
                    {facts["abi"] for facts in fixture_elfs.values()}
                    | {interpreter["abi"], companion["abi"]}
                )
                == 1,
                "the frozen fixtures, interpreter, and companion libc ABIs differ",
            ),
            (
                constants["r_state_offsets"].get(interpreter["abi"])
                == interpreter["r_state_offset"],
                "the interpreter r_state layout is not source-bound",
            ),
        ]
    )
    libc_version = host_glibc_version()
    inputs = {
        "caps": list(FROZEN_CAPS),
        "deadlines": dict(FROZEN_DEADLINES),
        "topology": dict(FROZEN_TOPOLOGY),
        "kernels": [
            {
                "name": name,
                "release_prefix": prefix,
                "base": {
                    "source": base_source,
                    "path": str(kernel_bases[name]) if kernel_bases.get(name) else None,
                    # Absent a retained base at freeze time the identity is
                    # pinned by the campaign's own first row and must then stay
                    # byte-identical for every later row of that kernel.
                    "sha256": sha256_file(kernel_bases[name]) if kernel_bases.get(name) else None,
                },
            }
            for name, prefix, base_source in FROZEN_KERNELS
        ],
        "commands": commands,
        "interpreter": {"path": str(interpreter_path), "libc_version": libc_version},
        "companion_libc": {"path": str(companion_path), "libc_version": libc_version},
        "provenance": {
            "elf": "scripts/check-live-discovery-evidence.py ELF reader (PT_INTERP, PT_LOAD, dynsym)",
            "libc_version": "ldd --version",
            "companion_libc": f"ldd {fixtures / 'driver-dlopen'}",
            "toolchain": "gcc --version; ld --version",
        },
    }

    manifest = {
        "schema": HISTORICAL_MANIFEST_SCHEMA if historical_fixture else MANIFEST_SCHEMA,
        "private_root": str(paths["private_root"]),
        "bpf_source": {
            "canonical_path": str((root / "crates/ebpf/src/main.rs").resolve(strict=True)),
            "sha256": sha256_file(root / "crates/ebpf/src/main.rs"),
        },
        "bpf_object": {"path": str(paths["bpf_object"]), "sha256": sha256_file(paths["bpf_object"])},
        "bpf_inventory": {
            "path": str(paths["bpf_inventory"]),
            "sha256": sha256_file(paths["bpf_inventory"]),
        },
        "runner": {"path": str(paths["runner"]), "sha256": sha256_file(paths["runner"])},
        "validators": {
            name: sha256_file(root / name)
            for name in (HISTORICAL_VALIDATORS if historical_fixture else VALIDATORS)
        },
        "inventory": inventory,
        "cookie": {
            "context_ids": constants["context_ids"],
            "absent_sentinel": constants["absent_sentinel"],
            "present_bit": constants["present_bit"],
            "shift": constants["shift"],
            "delta_min": constants["delta_min"],
            "delta_max": constants["delta_max"],
        },
        "function_ip": {
            "helper": constants["function_ip_helper"],
            "fallback": constants["function_ip_fallback"],
        },
        "r_state_offset": interpreter["r_state_offset"],
        "ab_four_map_oracle": list(AB_FOUR_MAP_ORACLE),
        "privacy": {
            "allowlist": "docs/privacy/allowlist-v1.md",
            "allowlist_sha256": sha256_file(root / "docs/privacy/allowlist-v1.md"),
        },
        "caps": inputs["caps"],
        "deadlines": inputs["deadlines"],
        "topology": inputs["topology"],
        "kernels": inputs["kernels"],
        "campaign": {
            "root": str(paths["campaign"]),
            "load_kinds": list(LOAD_KINDS),
            "table_kinds": list(TABLE_KINDS),
            "pause_policies": list(PAUSE_POLICIES),
            "children_per_row": CHILDREN_PER_ROW,
            "fallback_per_kernel": FALLBACK_PER_KERNEL,
            "primary_attempts": len(LOAD_KINDS)
            * len(TABLE_KINDS)
            * len(PAUSE_POLICIES)
            * CHILDREN_PER_ROW
            * len(inputs["kernels"]),
            "fallback_attempts": FALLBACK_PER_KERNEL * len(inputs["kernels"]),
        },
        "fixtures": {
            "sources": {name: sha256_file(root / name) for name in FIXTURE_SOURCES},
            "toolchain": toolchain,
            "commands": inputs["commands"],
            "outputs": {
                name: {
                    "path": str(fixtures / name),
                    "sha256": sha256_file(fixtures / name),
                }
                for name in FIXTURE_OUTPUTS
            },
            "providers": PROVIDERS,
            "drivers": DRIVERS,
        },
        "loader": {
            "interpreter": {
                "path": str(interpreter_path),
                "sha256": interpreter["sha256"],
                "elf_class": interpreter["elf_class"],
                "machine": interpreter["machine"],
                "abi": interpreter["abi"],
                "dt_needed_driver_interp": driver["interpreter"],
                "libc_version": inputs["interpreter"]["libc_version"],
                "rtld_audit_31986_fixed": glibc_release(inputs["interpreter"]["libc_version"])
                >= GLIBC_31986_FIXED_FROM,
            },
            "companion_libc": {
                "path": str(companion["path"]),
                "sha256": companion["sha256"],
                "libc_version": inputs["companion_libc"]["libc_version"],
                "fallback_symbol": FALLBACK_SYMBOL,
                "fallback_offset": companion["symbols"][FALLBACK_SYMBOL]["file_offset"],
                "rtld_audit_31986_fixed": glibc_release(
                    inputs["companion_libc"]["libc_version"]
                )
                >= GLIBC_31986_FIXED_FROM,
            },
            "provenance": inputs["provenance"],
        },
        "hooks": {
            "debug_state": {
                "file": str(interpreter_path),
                "symbol": DEBUG_STATE_SYMBOL,
                "file_offset": interpreter["symbols"][DEBUG_STATE_SYMBOL]["file_offset"],
                "vaddr": interpreter["symbols"][DEBUG_STATE_SYMBOL]["vaddr"],
            },
            "export": {
                "file": str(fixtures / "provider-exported.so"),
                "symbol": "C_GetFunctionList",
                "file_offset": provider["symbols"]["C_GetFunctionList"]["file_offset"],
                "vaddr": provider["symbols"]["C_GetFunctionList"]["vaddr"],
            },
        },
        "surfaces": {
            surface: {
                "constructor_marker": f"{MARKER_PREFIX} ctor {surface}",
                "application_marker": f"{MARKER_PREFIX} app {surface}",
                "targets": list(targets),
            }
            for surface, targets in SURFACE_TARGETS.items()
        },
        "lanes": copy.deepcopy(LANES),
    }
    if dependencies is not None:
        manifest["prepared_dependencies"] = dependencies
    return manifest


def build_manifest(private_root, root, kernel_bases, fixture_bits=None):
    return _manifest_content(private_root, root, kernel_bases, fixture_bits)


def _historical_fixture_manifest(private_root, root, kernel_bases, fixture_bits=None):
    """Only the historical v1 mutation self-test constructs unprepared fixtures."""
    return _manifest_content(private_root, root, kernel_bases, fixture_bits, historical_fixture=True)


def write_manifest(private_root, root, kernel_bases=None, fixture_bits=None):
    paths = frozen_paths(private_root)
    check([(not paths["manifest"].exists() and not paths["manifest"].is_symlink(),
            "execution manifest already exists")])
    manifest = build_manifest(private_root, root, kernel_bases or {}, fixture_bits)
    bind_manifest(manifest, root)
    serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    # The manifest admits execution: publish it only after required state exists.
    (paths["campaign"] / "state.json").write_text(json.dumps({
        "schema": CAMPAIGN_SCHEMA,
        "manifest_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "state": "frozen", "row_count": 0,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    stream = paths["manifest"].open("x", encoding="utf-8")
    try:
        with stream:
            stream.write(serialized)
    except OSError:
        # Exclusive creation succeeded; only this newly created file is ours.
        paths["manifest"].unlink()
        raise
    return manifest


# --------------------------------------------------------------------------
# Manifest binding
# --------------------------------------------------------------------------


def bind_manifest(manifest, root):
    """Recompute every frozen claim. Nothing here trusts the manifest text."""
    constants = source_constants(root)
    inventory = production_inventory(root)
    paths = frozen_paths(get(manifest, "private_root", default=""))
    check([(manifest.get("schema") in (MANIFEST_SCHEMA, HISTORICAL_MANIFEST_SCHEMA),
            "execution manifest schema differs")])
    if manifest["schema"] == MANIFEST_SCHEMA:
        check([(manifest.get("prepared_dependencies") == prepared_binding(paths["private_root"], root),
                "frozen prepared dependency binding differs")])

    source_path = Path(get(manifest, "bpf_source", "canonical_path", default=""))
    canonical = (root / "crates/ebpf/src/main.rs").resolve(strict=True)
    check(
        [
            (source_path == canonical, f"BPF source is not the canonical {canonical}"),
            (
                get(manifest, "bpf_source", "sha256") == sha256_file(canonical),
                "frozen BPF source digest no longer matches the candidate",
            ),
        ]
    )

    for key, path in (
        ("bpf_object", paths["bpf_object"]),
        ("bpf_inventory", paths["bpf_inventory"]),
        ("runner", paths["runner"]),
    ):
        check(
            [
                (get(manifest, key, "path") == str(path), f"{key} is not the frozen input path"),
                (
                    get(manifest, key, "sha256") == sha256_file(path),
                    f"frozen {key} digest no longer matches the bytes under the private root",
                ),
            ]
        )

    object_manifest = json.loads(paths["bpf_inventory"].read_text())
    check(
        [
            (
                object_manifest.get("schema") == OBJECT_SCHEMA,
                "frozen BPF inventory is not a live-discovery object manifest",
            ),
            (
                sorted(get(object_manifest, "expected", "inventory", "programs", default=[]))
                == inventory["programs"],
                "frozen BPF inventory programs differ from the production inventory",
            ),
            (
                sorted(get(object_manifest, "expected", "inventory", "maps", default={}))
                == inventory["maps"],
                "frozen BPF inventory maps differ from the production inventory",
            ),
        ]
    )

    check(
        [
            (
                manifest.get("validators") == {
                    name: sha256_file(root / name)
                    for name in (VALIDATORS if manifest["schema"] == MANIFEST_SCHEMA
                                 else HISTORICAL_VALIDATORS)
                },
                "a frozen validator changed after the freeze",
            ),
            (
                get(manifest, "inventory", "maps") == inventory["maps"],
                "frozen production map inventory differs",
            ),
            (
                get(manifest, "inventory", "programs") == inventory["programs"],
                "frozen production program inventory differs",
            ),
            (
                get(manifest, "cookie", "context_ids") == constants["context_ids"],
                "frozen loader context-id count differs from the product source",
            ),
            (
                get(manifest, "cookie", "absent_sentinel") == constants["absent_sentinel"],
                "frozen absent-state cookie sentinel differs from the product source",
            ),
            (
                get(manifest, "cookie", "present_bit") == constants["present_bit"]
                and get(manifest, "cookie", "shift") == constants["shift"],
                "frozen present-state cookie encoding differs from the product source",
            ),
            (
                get(manifest, "cookie", "delta_min") == constants["delta_min"]
                and get(manifest, "cookie", "delta_max") == constants["delta_max"],
                "frozen signed state-delta boundaries differ from the product source",
            ),
            (
                get(manifest, "function_ip", "helper") == constants["function_ip_helper"],
                "frozen function-IP helper differs from the product source",
            ),
            (
                get(manifest, "function_ip", "fallback") == constants["function_ip_fallback"],
                "frozen x86-64 function-IP fallback differs from the product source",
            ),
            (
                manifest.get("r_state_offset")
                == constants["r_state_offsets"].get(
                    get(manifest, "loader", "interpreter", "abi")
                ),
                "frozen r_state offset differs from the pinned interpreter ABI",
            ),
            (
                manifest.get("ab_four_map_oracle") == list(AB_FOUR_MAP_ORACLE),
                "the recorded A/B four-map oracle was rewritten",
            ),
            (
                get(manifest, "privacy", "allowlist_sha256")
                == sha256_file(root / "docs/privacy/allowlist-v1.md"),
                "frozen privacy allowlist digest differs",
            ),
        ]
    )

    fixtures = manifest.get("fixtures", {})
    toolchain = fixtures.get("toolchain", {})
    check(
        [
            (
                fixtures.get("sources") == {name: sha256_file(root / name) for name in FIXTURE_SOURCES},
                "a frozen fixture source changed after the freeze",
            ),
            (toolchain.get("cflags") == CFLAGS, "frozen fixture cflags differ"),
            (
                toolchain.get("shared_ldflags") == SHARED_LDFLAGS,
                "frozen shared-library link flags differ",
            ),
            (toolchain.get("driver_ldflags") == DRIVER_LDFLAGS, "frozen driver link flags differ"),
            (
                bool(toolchain.get("cc_version")) and bool(toolchain.get("ld_version")),
                "frozen compiler/linker identity is missing",
            ),
            (
                sorted(fixtures.get("outputs", {})) == sorted(FIXTURE_OUTPUTS),
                "frozen fixture output set differs",
            ),
            (
                sorted(fixtures.get("commands", {})) == sorted(FIXTURE_OUTPUTS),
                "one exact build command per frozen fixture output is required",
            ),
        ]
    )
    command_widths = set()
    for name, output in fixtures["outputs"].items():
        command_widths.add(
            tuple(arg for arg in fixtures["commands"][name] if arg in ("-m32", "-m64"))
        )
        command = " ".join(fixtures["commands"][name])
        needed = SHARED_LDFLAGS if name.endswith(".so") else DRIVER_LDFLAGS
        check(
            [
                (
                    output.get("path") == str(paths["fixtures"] / name),
                    f"fixture {name} is not at its frozen path",
                ),
                (
                    output.get("sha256") == sha256_file(paths["fixtures"] / name),
                    f"frozen fixture {name} digest no longer matches its bytes",
                ),
                (CFLAGS in command, f"fixture {name} was not built with the frozen cflags"),
                (needed in command, f"fixture {name} was not linked with the frozen link flags"),
            ]
        )
    check(
        [
            (
                len(command_widths) == 1
                and next(iter(command_widths)) in ((), ("-m32",), ("-m64",)),
                "frozen fixture compiler widths differ",
            )
        ]
    )
    exported = fixtures["outputs"][PROVIDERS["exported"]]["sha256"]
    hidden = fixtures["outputs"][PROVIDERS["hidden"]]["sha256"]
    check(
        [
            (exported != hidden, "exported and hidden provider bytes are identical"),
            (fixtures.get("providers") == PROVIDERS, "frozen provider byte identities differ"),
            (fixtures.get("drivers") == DRIVERS, "frozen driver load-kind mapping differs"),
        ]
    )

    loader = manifest.get("loader", {})
    interpreter = loader.get("interpreter", {})
    companion = loader.get("companion_libc", {})
    fixture_elfs = {
        name: elf_facts(
            paths["fixtures"] / name,
            symbols=("C_GetFunctionList",) if name == "provider-exported.so" else (),
        )
        for name in FIXTURE_OUTPUTS
    }
    width_flags = next(iter(command_widths))
    if width_flags:
        expected_abi = "linux-ilp32" if width_flags == ("-m32",) else "linux-lp64"
        check(
            [
                (
                    {facts["abi"] for facts in fixture_elfs.values()} == {expected_abi},
                    "frozen fixture bytes differ from their compiler width",
                )
            ]
        )
    driver_elf = fixture_elfs["driver-needed-exported"]
    interpreter_elf = elf_facts(
        interpreter.get("path", ""), symbols=(get(manifest, "hooks", "debug_state", "symbol"),)
    )
    provider_elf = fixture_elfs[PROVIDERS["exported"]]
    check(
        [
            (
                interpreter.get("dt_needed_driver_interp") == driver_elf["interpreter"],
                "the frozen DT_NEEDED driver's PT_INTERP is not the pinned interpreter",
            ),
            (
                interpreter.get("path") == driver_elf["interpreter"],
                "the pinned interpreter is not the one the frozen driver will actually use",
            ),
            (
                interpreter.get("sha256") == interpreter_elf["sha256"],
                "the pinned interpreter bytes changed after the freeze",
            ),
            (
                (
                    interpreter.get("elf_class"),
                    interpreter.get("machine"),
                    interpreter.get("abi"),
                    manifest.get("r_state_offset"),
                )
                == (
                    interpreter_elf["elf_class"],
                    interpreter_elf["machine"],
                    interpreter_elf["abi"],
                    interpreter_elf["r_state_offset"],
                ),
                "the pinned interpreter ABI or r_state layout changed after the freeze",
            ),
            (
                interpreter.get("rtld_audit_31986_fixed")
                == (glibc_release(interpreter.get("libc_version")) >= GLIBC_31986_FIXED_FROM),
                "the interpreter's glibc 31986 rtld-audit disposition is misdeclared",
            ),
            (
                companion.get("sha256") == sha256_file(companion.get("path", "")),
                "the pinned companion libc bytes changed after the freeze",
            ),
            (
                companion.get("rtld_audit_31986_fixed")
                == (glibc_release(companion.get("libc_version")) >= GLIBC_31986_FIXED_FROM),
                "the companion libc's glibc 31986 rtld-audit disposition is misdeclared",
            ),
            (
                companion.get("fallback_symbol") == FALLBACK_SYMBOL
                and companion.get("fallback_offset")
                == elf_facts(companion.get("path", ""), symbols=(FALLBACK_SYMBOL,))["symbols"][
                    FALLBACK_SYMBOL
                ]["file_offset"],
                "the reviewed dlopen_return fallback offset is not the pinned companion libc's",
            ),
            (bool(loader.get("provenance")), "loader identity source/tool provenance is missing"),
            (
                len(
                    {
                        *(facts["abi"] for facts in fixture_elfs.values()),
                        interpreter_elf["abi"],
                        elf_facts(companion.get("path", ""))["abi"],
                    }
                )
                == 1,
                "the frozen driver, provider, interpreter, and companion libc ABIs differ",
            ),
        ]
    )

    hooks = manifest.get("hooks", {})
    symbol = get(hooks, "debug_state", "symbol", default="")
    check(
        [
            (
                get(hooks, "debug_state", "file_offset")
                == interpreter_elf["symbols"][symbol]["file_offset"],
                "the pinned debug-state hook file offset is not the one in the pinned interpreter",
            ),
            (
                get(hooks, "export", "file_offset")
                == provider_elf["symbols"]["C_GetFunctionList"]["file_offset"],
                "the pinned export hook file offset is not the one in the frozen provider",
            ),
            (
                get(hooks, "export", "symbol") == "C_GetFunctionList",
                "the export hook symbol identity differs",
            ),
        ]
    )

    surfaces = manifest.get("surfaces", {})
    targets = [name for surface in surfaces.values() for name in surface.get("targets", [])]
    markers = [
        marker
        for surface in surfaces.values()
        for marker in (surface.get("constructor_marker"), surface.get("application_marker"))
    ]
    check(
        [
            (sorted(surfaces) == sorted(SURFACE_TARGETS), "the three standard surfaces differ"),
            (len(set(targets)) == len(targets), "surface target sets overlap"),
            (
                set(targets) <= set(inventory["programs"]),
                "a surface target is not a production program",
            ),
            (len(set(markers)) == len(markers), "constructor/application markers are not distinct"),
        ]
    )
    for surface, entry in surfaces.items():
        check(
            [
                (entry.get("targets") == SURFACE_TARGETS[surface], f"{surface} target set differs"),
                (
                    entry.get("constructor_marker") == f"{MARKER_PREFIX} ctor {surface}",
                    f"{surface} constructor marker differs",
                ),
                (
                    entry.get("application_marker") == f"{MARKER_PREFIX} app {surface}",
                    f"{surface} application marker differs",
                ),
            ]
        )

    kernels = manifest.get("kernels", [])
    names = [kernel.get("name") for kernel in kernels]
    check(
        [
            (len(kernels) == 3, "the campaign is frozen against exactly three kernels"),
            (len(set(names)) == 3, "the three frozen kernels do not have distinct names"),
            (
                all(kernel.get("release_prefix") for kernel in kernels),
                "a frozen kernel has no release prefix",
            ),
            (
                len({kernel.get("release_prefix") for kernel in kernels}) == 3,
                "the three frozen kernels do not have distinct release prefixes",
            ),
            (
                all(get(kernel, "base", "source") for kernel in kernels),
                "a frozen kernel has no base identity",
            ),
        ]
    )

    for name, lane in manifest.get("lanes", {}).items():
        check(
            [
                (
                    lane.get("driver") in FIXTURE_OUTPUTS,
                    f"lane {name} names a driver that is not a frozen fixture",
                ),
                (
                    all(
                        not argument.startswith("{") or argument in PROVIDER_REFERENCES
                        for argument in lane.get("argv", [])
                    ),
                    f"lane {name} names a provider that is not a frozen byte identity",
                ),
                (
                    set(lane.get("env", {})) <= set(FIXTURE_ENV_KNOBS),
                    f"lane {name} sets an undeclared fixture knob",
                ),
                (
                    lane.get("markers") in MARKER_EXPECTATIONS,
                    f"lane {name} declares an unknown marker expectation",
                ),
            ]
        )

    campaign = manifest.get("campaign", {})
    check(
        [
            (
                sorted(manifest.get("lanes", {})) == sorted(LANES),
                "the frozen fixture lane set differs",
            ),
            (manifest.get("lanes") == LANES, "a frozen fixture lane invocation differs"),
            (campaign.get("root") == str(paths["campaign"]), "campaign root is not the frozen path"),
            (campaign.get("load_kinds") == list(LOAD_KINDS), "frozen load kinds differ"),
            (campaign.get("table_kinds") == list(TABLE_KINDS), "frozen table kinds differ"),
            (campaign.get("pause_policies") == list(PAUSE_POLICIES), "frozen pause policies differ"),
            (
                campaign.get("children_per_row") == CHILDREN_PER_ROW,
                "frozen children per row differ",
            ),
            (
                campaign.get("primary_attempts") == 720,
                "the frozen primary grid is not the amendment's 720 attempts",
            ),
            (
                campaign.get("fallback_attempts") == FALLBACK_PER_KERNEL * len(kernels),
                "the frozen forced dlopen_return attempt count differs",
            ),
        ]
    )
    check(
        [
            (bool(manifest.get("caps")), "frozen capability set is missing"),
            (
                isinstance(get(manifest, "deadlines", "attempt_seconds"), int)
                and isinstance(get(manifest, "deadlines", "campaign_seconds"), int),
                "frozen deadlines are missing",
            ),
            (
                get(manifest, "topology", "cold_boot") is not None
                and get(manifest, "topology", "containers") is not None,
                "frozen cold-boot/container topology is missing",
            ),
        ]
    )
    return manifest


# --------------------------------------------------------------------------
# Preflight report
# --------------------------------------------------------------------------


def validate_preflight(report, manifest):
    cookie = manifest["cookie"]
    kernels = {kernel["name"]: kernel for kernel in manifest["kernels"]}
    kernel = report.get("kernel")
    outcomes = report.get("outcomes", {})
    short = report.get("short_circuit", {})
    check(
        [
            (report.get("schema") == PREFLIGHT_SCHEMA, "preflight schema differs"),
            (
                report.get("manifest_sha256") == manifest["__digest__"],
                "preflight report was not produced under this execution manifest",
            ),
            (kernel in kernels, f"preflight kernel {kernel!r} is not a frozen kernel"),
            (
                str(report.get("kernel_release", "")).startswith(
                    kernels.get(kernel, {}).get("release_prefix", "\0")
                ),
                "preflight kernel release does not match the frozen release prefix",
            ),
            (
                sorted(report.get("programs_accepted", [])) == manifest["inventory"]["programs"],
                "the preflight did not accept exactly every production program",
            ),
            (
                sorted(report.get("context_ids", [])) == list(range(cookie["context_ids"])),
                f"the preflight did not exercise all {cookie['context_ids']} context ids",
            ),
            (
                get(report, "cookie_boundaries", "absent") == cookie["absent_sentinel"],
                "the absent-state cookie boundary differs",
            ),
            (
                get(report, "cookie_boundaries", "present") == cookie["present_bit"],
                "the present-state cookie boundary differs",
            ),
            (
                get(report, "cookie_boundaries", "delta_min") == cookie["delta_min"]
                and get(report, "cookie_boundaries", "delta_max") == cookie["delta_max"],
                "the signed state-delta boundaries differ",
            ),
            (
                sorted(short) == ["aya_no_cookie", "zero_cookie"],
                "both the zero-cookie and Aya no-cookie short-circuits are required",
            ),
        ]
    )
    for name, observed in short.items():
        check(
            [
                (
                    observed.get("returned") == "before_registry_ip_state",
                    f"the {name} short-circuit did not return before registry/IP/state work",
                ),
                (
                    observed.get("registry_reads") == 0
                    and observed.get("ip_reads") == 0
                    and observed.get("state_reads") == 0,
                    f"the {name} short-circuit still performed registry/IP/state work",
                ),
            ]
        )
    check(
        [
            (
                get(report, "function_ip", "helper") == manifest["function_ip"]["helper"],
                "the preflight did not resolve the function IP through the frozen helper",
            ),
            (
                get(report, "function_ip", "helper_matches_hook") is True,
                "the exact function-IP helper result did not match the pinned hook",
            ),
            (
                get(report, "function_ip", "fallback") == manifest["function_ip"]["fallback"],
                "the preflight fallback IP source is not the frozen x86-64 one",
            ),
            (
                get(report, "function_ip", "fallback_matches_hook") is True,
                "the x86-64 fallback IP arithmetic did not match the pinned hook",
            ),
            (
                get(report, "load_bias", "pt_interp") == manifest["loader"]["interpreter"]["path"],
                "the preflight PT_INTERP is not the pinned interpreter",
            ),
            (
                get(report, "load_bias", "hook_ip")
                == get(report, "load_bias", "base")
                + manifest["hooks"]["debug_state"]["vaddr"],
                "the load-bias hook IP is not base plus the pinned hook vaddr",
            ),
            (
                get(report, "load_bias", "r_state_offset") == manifest["r_state_offset"],
                "the preflight r_state offset is not the pinned interpreter ABI's loader layout",
            ),
            (
                get(report, "lifecycle", "tombstoned") == get(report, "lifecycle", "attached")
                and get(report, "lifecycle", "attached", default=0) > 0,
                "every attached preflight context must be tombstoned",
            ),
            (
                get(report, "lifecycle", "drained") == get(report, "lifecycle", "tombstoned"),
                "every tombstoned preflight context must be drained",
            ),
            (
                get(report, "lifecycle", "residual") == 0,
                "the preflight left a residual loader context",
            ),
            (report.get("privacy") == "clean", "the preflight privacy scan is not clean"),
            (
                sorted(outcomes) == sorted(PREFLIGHT_OUTCOMES),
                "the preflight did not report exactly the five required outcomes",
            ),
            (
                len(set(map(json.dumps, outcomes.values()))) == len(PREFLIGHT_OUTCOMES),
                "the five preflight outcomes are not distinct",
            ),
        ]
    )
    return kernel


# --------------------------------------------------------------------------
# Campaign rows
# --------------------------------------------------------------------------


def row_key(row):
    if row.get("attempt") == "fallback":
        return f"{row.get('kernel')}-fallback-{row.get('child')}"
    return (
        f"{row.get('kernel')}-{row.get('load_kind')}-{row.get('tables')}-"
        f"{row.get('pause')}-{row.get('child')}"
    )


def expected_row_keys(manifest):
    keys = set()
    for kernel in manifest["kernels"]:
        for load_kind in LOAD_KINDS:
            for tables in TABLE_KINDS:
                for pause in PAUSE_POLICIES:
                    for child in range(CHILDREN_PER_ROW):
                        keys.add(f"{kernel['name']}-{load_kind}-{tables}-{pause}-{child}")
        for child in range(FALLBACK_PER_KERNEL):
            keys.add(f"{kernel['name']}-fallback-{child}")
    return keys


def validate_lifecycle(row, manifest, label):
    """Production lifecycle oracle: the complete product inventory, tombstone
    and drain for every context, and no residual observer resource. Distinct
    from the isolated A/B spike's four-map oracle by construction."""
    lifecycle = row.get("lifecycle", {})
    observed = sorted(lifecycle.get("maps_observed", []))
    check(
        [
            (
                observed != sorted(AB_FOUR_MAP_ORACLE),
                f"{label}: the A/B spike's four-map oracle is not the production lifecycle oracle",
            ),
            (
                observed == manifest["inventory"]["maps"],
                f"{label}: lifecycle did not cover the complete production map inventory",
            ),
            (lifecycle.get("maps_after") == [], f"{label}: observer BPF maps outlived the run"),
            (lifecycle.get("links_after") == [], f"{label}: observer BPF links outlived the run"),
            (lifecycle.get("pins_after") == 0, f"{label}: pinned objects outlived the run"),
            (
                lifecycle.get("loader_contexts_tombstoned")
                == lifecycle.get("loader_contexts_allocated"),
                f"{label}: an allocated loader context was never tombstoned",
            ),
            (
                lifecycle.get("loader_contexts_drained")
                == lifecycle.get("loader_contexts_tombstoned"),
                f"{label}: a tombstoned loader context was never drained",
            ),
            (
                lifecycle.get("loader_contexts_after") == 0,
                f"{label}: a loader context outlived the run",
            ),
            (
                lifecycle.get("slots_active_after") == 0,
                f"{label}: the exited workload left active slots",
            ),
            (
                lifecycle.get("views_after") == 0,
                f"{label}: the exited workload left active process views",
            ),
        ]
    )


def validate_row(row, manifest, label):
    kernels = {kernel["name"]: kernel for kernel in manifest["kernels"]}
    kernel = kernels.get(row.get("kernel"), {})
    surfaces = manifest["surfaces"]
    fallback = row.get("attempt") == "fallback"
    check(
        [
            (row.get("schema") == ROW_SCHEMA, f"{label}: row schema differs"),
            (
                row.get("manifest_sha256") == manifest["__digest__"],
                f"{label}: row was not produced under this execution manifest",
            ),
            (row.get("kernel") in kernels, f"{label}: row kernel is not a frozen kernel"),
            (
                str(row.get("kernel_release", "")).startswith(
                    kernel.get("release_prefix", "\0")
                ),
                f"{label}: row kernel release does not match the frozen release prefix",
            ),
            (
                row.get("base_sha256") == kernel.get("base", {}).get("sha256")
                if kernel.get("base", {}).get("sha256")
                # No retained base was hashed at freeze time, so the identity is
                # pinned by this campaign's own rows (agreement is checked once
                # per kernel across the whole campaign below).
                else bool(re.fullmatch(r"[0-9a-f]{64}", str(row.get("base_sha256")))),
                f"{label}: row base identity is not the frozen retained base",
            ),
            (row.get("lane") in manifest["lanes"], f"{label}: row lane is not a frozen lane"),
            (row.get("load_kind") in LOAD_KINDS, f"{label}: row load kind is not frozen"),
            (row.get("tables") in TABLE_KINDS, f"{label}: row table kind is not frozen"),
            (row.get("pause") in PAUSE_POLICIES, f"{label}: row pause policy is not frozen"),
            (
                isinstance(row.get("child"), int) and 0 <= row["child"] < CHILDREN_PER_ROW,
                f"{label}: row child index is outside the frozen 20",
            ),
            (
                # Mixed, missing, timed-out, replaced, lifecycle-failed,
                # privacy-failed and unclassified rows are campaign non-PASS,
                # and so is any other classification that is not a pass.
                row.get("outcome") == "pass",
                f"{label}: row outcome {row.get('outcome')!r} is campaign non-PASS",
            ),
            (
                row.get("initial_set_capture") == "none",
                f"{label}: initial-set capture must be none",
            ),
            (row.get("completeness") == "PARTIAL", f"{label}: completeness must stay PARTIAL"),
            (
                get(row, "privacy", "scan") == "clean",
                f"{label}: the row's privacy scan is not clean",
            ),
            (
                get(row, "privacy", "allowlist_sha256") == manifest["privacy"]["allowlist_sha256"],
                f"{label}: the row was scanned against a different privacy allowlist",
            ),
            (
                row.get("libc") in (
                    manifest["loader"]["interpreter"]["libc_version"],
                    manifest["loader"]["companion_libc"]["libc_version"],
                ),
                f"{label}: the row's libc identity is not a pinned one",
            ),
            (
                not (
                    row.get("audit_workaround_applied")
                    and glibc_release(row.get("libc")) >= GLIBC_31986_FIXED_FROM
                ),
                f"{label}: a glibc 2.41+ row claimed the pre-31986 rtld-audit workaround",
            ),
        ]
    )

    for surface, expected in surfaces.items():
        observed = get(row, "surfaces", surface, default=None)
        check([(observed is not None, f"{label}: surface {surface} was not exercised")])
        check(
            [
                (
                    observed.get("application_marker") is True,
                    f"{label}: {surface} produced no application marker",
                ),
                (
                    observed.get("targets_attached") == expected["targets"],
                    f"{label}: {surface} did not attach its frozen target set",
                ),
                (
                    observed.get("constructor_marker") is (not fallback),
                    f"{label}: {surface} constructor-marker coverage contradicts the attempt kind",
                ),
            ]
        )

    windows = row.get("windows", {})
    if fallback:
        check(
            [
                (row.get("load_kind") == "dlopen", f"{label}: a fallback row is a dlopen row"),
                (row.get("pause") == "never", f"{label}: a fallback row runs under pause never"),
                (row.get("timing") == "none", f"{label}: a fallback row's timing must be none"),
                (
                    get(row, "fallback", "reason") in FALLBACK_REASONS,
                    f"{label}: forced dlopen_return needs an absent/unresolved/unsafe hook",
                ),
                (
                    get(row, "fallback", "companion_libc_offset")
                    == manifest["loader"]["companion_libc"]["fallback_offset"],
                    f"{label}: the fallback used an offset the pinned companion libc did not supply",
                ),
                (
                    get(row, "fallback", "post_return_call") is True,
                    f"{label}: a fallback row proves the explicit post-return call",
                ),
                (
                    get(row, "fallback", "constructor_coverage") is False
                    and get(row, "fallback", "dt_needed_coverage") is False,
                    f"{label}: a fallback row claimed constructor or DT_NEEDED coverage",
                ),
            ]
        )
    else:
        check(
            [
                ("fallback" not in row, f"{label}: a primary row activated the fallback"),
                (
                    row.get("timing") == "unproven",
                    f"{label}: attach-first success does not upgrade timing beyond unproven",
                ),
            ]
        )

    if row.get("pause") == "never":
        check(
            [
                (
                    get(row, "owner", "pause_owner") is None,
                    f"{label}: a never row must take no pause owner",
                ),
                (
                    get(row, "owner", "signals") == 0,
                    f"{label}: a never row must send no signal",
                ),
                (
                    windows.get("observed") == 0,
                    f"{label}: a never row must open no pause window",
                ),
                (
                    row.get("attachment") in ("bounded", "unavailable"),
                    f"{label}: a never row needs eventual bounded attachment where available",
                ),
            ]
        )
    elif row.get("pause") in ("auto", "always"):
        missed = windows.get("missed")
        check(
            [
                (
                    windows.get("closed") == windows.get("observed"),
                    f"{label}: an {row['pause']} row must close every observed window safely",
                ),
                (
                    windows.get("sticky_partial") is not True,
                    f"{label}: sticky partial with rearming disabled makes this row non-PASS",
                ),
                (
                    windows.get("rearming") == "enabled",
                    f"{label}: rearming was disabled for an {row['pause']} row",
                ),
            ]
        )
        if row.get("pause") == "auto":
            check(
                [
                    (missed == 0, f"{label}: an auto row missed a pause window"),
                    (row.get("command_status") == 0, f"{label}: an auto row's command failed"),
                ]
            )
        else:
            check(
                [
                    (
                        (missed == 0 and row.get("command_status") == 0)
                        or (
                            missed > 0
                            and row.get("cleanup") == "safe"
                            and row.get("command_status") != 0
                        ),
                        f"{label}: an always row must fail the command after safe cleanup for a "
                        "missed window",
                    ),
                ]
            )

    validate_lifecycle(row, manifest, label)


def validate_campaign(campaign_root, manifest):
    campaign_root = Path(campaign_root)
    check(
        [
            (
                str(campaign_root) == manifest["campaign"]["root"],
                "campaign root is not the frozen campaign path",
            )
        ]
    )
    state = json.loads((campaign_root / "state.json").read_text())
    rows = sorted((campaign_root / "rows").glob("*.json"))
    reports = sorted((campaign_root / "preflight").glob("*.json"))
    check(
        [
            (state.get("schema") == CAMPAIGN_SCHEMA, "campaign state schema differs"),
            (
                state.get("manifest_sha256") == manifest["__digest__"],
                "campaign state is bound to a different execution manifest",
            ),
            (
                state.get("state") in ("frozen", "running", "complete"),
                f"unknown campaign state {state.get('state')!r}",
            ),
        ]
    )

    if state["state"] == "frozen":
        check(
            [
                (
                    not rows and not reports,
                    "a frozen campaign has attempted nothing; found rows or preflight reports",
                )
            ]
        )
        return "frozen: 0 attempts, awaiting privileged execution"

    kernels = {kernel["name"] for kernel in manifest["kernels"]}
    seen = {}
    for path in rows:
        row = json.loads(path.read_text())
        label = path.name
        key = row_key(row)
        check(
            [
                (path.name == f"{key}.json", f"{label}: row file name is not its own identity"),
                (key not in seen, f"{label}: duplicate campaign row {key}"),
            ]
        )
        seen[key] = row
        validate_row(row, manifest, label)

    for name in {row["kernel"] for row in seen.values() if "kernel" in row}:
        identities = {row["base_sha256"] for row in seen.values() if row.get("kernel") == name}
        check(
            [
                (
                    len(identities) == 1,
                    f"kernel {name} ran on more than one base identity: {sorted(identities)}",
                )
            ]
        )

    preflight_kernels = set()
    for path in reports:
        preflight_kernels.add(validate_preflight(json.loads(path.read_text()), manifest))

    expected = expected_row_keys(manifest)
    if state["state"] == "running":
        check([(set(seen) <= expected, "a running campaign holds an unplanned row")])
        fail(f"campaign INCOMPLETE: {len(seen)}/{len(expected)} attempts recorded")

    check(
        [
            (set(seen) == expected, "the complete campaign is not the exact frozen attempt grid"),
            (
                preflight_kernels == kernels,
                "a complete campaign needs one accepted preflight report per frozen kernel",
            ),
            (
                state.get("row_count") == len(seen),
                "the campaign state row count disagrees with the recorded rows",
            ),
        ]
    )
    return f"complete: {len(seen)} attempts, {len(preflight_kernels)} kernels PASS"


def load_manifest(path):
    raw = Path(path).read_bytes()
    manifest = json.loads(raw)
    manifest["__digest__"] = sha256_bytes(raw)
    return manifest


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def _reject(action, label):
    try:
        action()
    except (RuntimeError, ValueError, KeyError, TypeError, OSError):
        return
    raise AssertionError(f"mutation accepted: {label}")


def _patch(document, path, value):
    mutated = copy.deepcopy(document)
    cursor = mutated
    for key in path[:-1]:
        cursor = cursor[key]
    if value is _DROP:
        cursor.pop(path[-1], None)
    else:
        cursor[path[-1]] = value
    return mutated


class _Drop:
    pass


_DROP = _Drop()


def build_fixtures(root, fixtures, fixture_bits=None, *, execute=True):
    """Build the frozen fixtures with the exact frozen commands.

    One implementation, used by both the freeze and the self-test, so the
    commands hashed into the manifest are the commands that ran."""
    fixtures.mkdir(parents=True, exist_ok=True)
    provider = str(root / FIXTURE_SOURCES[0])
    driver = str(root / FIXTURE_SOURCES[1])
    compiler = ["gcc"] + ([] if fixture_bits is None else [f"-m{fixture_bits}"])
    commands = {}
    for tables, name in PROVIDERS.items():
        commands[name] = (
            compiler
            + CFLAGS.split()
            + [f"-DP11SCOPE_EXPORT_TABLES={1 if tables == 'exported' else 0}"]
            + SHARED_LDFLAGS.split()
            + ["-o", str(fixtures / name), provider]
        )
    for tables, name in PROVIDERS.items():
        commands[f"driver-needed-{tables}"] = (
            compiler
            + CFLAGS.split()
            + ["-DP11SCOPE_DRIVER_NEEDED=1", "-o", str(fixtures / f"driver-needed-{tables}"), driver]
            + [str(fixtures / name)]
            + DRIVER_LDFLAGS.split()
        )
    commands["driver-dlopen"] = (
        compiler
        + CFLAGS.split()
        + ["-o", str(fixtures / "driver-dlopen"), driver]
        + DRIVER_LDFLAGS.split()
    )
    if execute:
        for name in FIXTURE_OUTPUTS:
            subprocess.run(commands[name], check=True)
    return commands


def create_private_root(private_root):
    paths = frozen_paths(private_root)
    check([(paths["private_root"].is_absolute(), "private root must be absolute")])
    paths["private_root"].mkdir(mode=0o700, parents=True)
    paths["frozen"].mkdir(mode=0o700)
    paths["dependencies"].mkdir(mode=0o700)
    (paths["campaign"] / "rows").mkdir(mode=0o700, parents=True)
    (paths["campaign"] / "preflight").mkdir(mode=0o700)
    return paths


def prepare_private_root(root, private_root, bpf_object=None, runner=None):
    """Lay out one mode-0700 private root and its frozen inputs.

    The self-test passes stand-in bytes for the two artifacts a full product
    build produces; the real freeze passes the built object and runner. Both
    are bound by digest only, so both paths exercise the same code.
    """
    paths = create_private_root(private_root)
    if bpf_object is None:
        paths["bpf_object"].write_bytes(b"self-test stand-in for the product BPF object\n")
        paths["runner"].write_bytes(b"self-test stand-in for the product runner\n")
    else:
        shutil.copyfile(bpf_object, paths["bpf_object"])
        shutil.copyfile(runner, paths["runner"])

    object_checker = runpy.run_path(
        str(root / "scripts/check-live-discovery-object.py"), run_name="live_discovery_evidence"
    )
    source_path = (root / "crates/ebpf/src/main.rs").resolve(strict=True)
    paths["bpf_inventory"].write_text(
        json.dumps(
            object_checker["test_manifest"](source_path, "default", source_path.read_text()),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    return paths


def _good_preflight(manifest, kernel):
    return {
        "schema": PREFLIGHT_SCHEMA,
        "manifest_sha256": manifest["__digest__"],
        "kernel": kernel["name"],
        "kernel_release": kernel["release_prefix"] + "0-generic",
        "programs_accepted": list(manifest["inventory"]["programs"]),
        "context_ids": list(range(manifest["cookie"]["context_ids"])),
        "cookie_boundaries": {
            "absent": manifest["cookie"]["absent_sentinel"],
            "present": manifest["cookie"]["present_bit"],
            "delta_min": manifest["cookie"]["delta_min"],
            "delta_max": manifest["cookie"]["delta_max"],
        },
        "short_circuit": {
            name: {
                "returned": "before_registry_ip_state",
                "registry_reads": 0,
                "ip_reads": 0,
                "state_reads": 0,
            }
            for name in ("zero_cookie", "aya_no_cookie")
        },
        "function_ip": {
            "helper": manifest["function_ip"]["helper"],
            "helper_matches_hook": True,
            "fallback": manifest["function_ip"]["fallback"],
            "fallback_matches_hook": True,
        },
        "load_bias": {
            "pt_interp": manifest["loader"]["interpreter"]["path"],
            "base": 0x7F0000000000,
            "hook_ip": 0x7F0000000000 + manifest["hooks"]["debug_state"]["vaddr"],
            "r_state_offset": manifest["r_state_offset"],
        },
        "lifecycle": {"attached": 3, "tombstoned": 3, "drained": 3, "residual": 0},
        "privacy": "clean",
        "outcomes": {
            "capacity": "registry_full",
            "stale": "generation_retired",
            "generation": "regenerated",
            "identity": "identity_changed",
            "state_read": "bounded_read_failed",
        },
    }


def _good_row(manifest, kernel, load_kind, tables, pause, child, fallback=False):
    row = {
        "schema": ROW_SCHEMA,
        "manifest_sha256": manifest["__digest__"],
        "attempt": "fallback" if fallback else "primary",
        "kernel": kernel["name"],
        "kernel_release": kernel["release_prefix"] + "0-generic",
        "base_sha256": kernel["base"]["sha256"] or sha256_bytes(kernel["name"].encode()),
        "libc": manifest["loader"]["interpreter"]["libc_version"],
        "audit_workaround_applied": False,
        "lane": "late-dlopen-provider" if load_kind == "dlopen" else "initial-set-provider",
        "load_kind": load_kind,
        "tables": tables,
        "pause": pause,
        "child": child,
        "outcome": "pass",
        "surfaces": {
            surface: {
                "constructor_marker": not fallback,
                "application_marker": True,
                "targets_attached": list(entry["targets"]),
            }
            for surface, entry in manifest["surfaces"].items()
        },
        "attachment": "bounded",
        "owner": {"pause_owner": None, "signals": 0},
        "windows": {
            "observed": 0,
            "closed": 0,
            "missed": 0,
            "sticky_partial": False,
            "rearming": "enabled",
        },
        "command_status": 0,
        "cleanup": "safe",
        "timing": "none" if fallback else "unproven",
        "initial_set_capture": "none",
        "completeness": "PARTIAL",
        "privacy": {
            "scan": "clean",
            "allowlist_sha256": manifest["privacy"]["allowlist_sha256"],
        },
        "lifecycle": {
            "maps_observed": list(manifest["inventory"]["maps"]),
            "maps_after": [],
            "links_after": [],
            "pins_after": 0,
            "loader_contexts_allocated": 2,
            "loader_contexts_tombstoned": 2,
            "loader_contexts_drained": 2,
            "loader_contexts_after": 0,
            "slots_active_after": 0,
            "views_after": 0,
        },
    }
    if pause in ("auto", "always"):
        row["owner"] = {"pause_owner": "owned-child", "signals": 1}
        row["windows"] = {
            "observed": 2,
            "closed": 2,
            "missed": 0,
            "sticky_partial": False,
            "rearming": "enabled",
        }
    if fallback:
        row["fallback"] = {
            "reason": "hook_absent",
            "companion_libc_offset": manifest["loader"]["companion_libc"]["fallback_offset"],
            "post_return_call": True,
            "constructor_coverage": False,
            "dt_needed_coverage": False,
        }
    return row


def _write_campaign(paths, manifest, state):
    rows = paths["campaign"] / "rows"
    preflight = paths["campaign"] / "preflight"
    for path in list(rows.glob("*.json")) + list(preflight.glob("*.json")):
        path.unlink()
    count = 0
    if state == "complete":
        for kernel in manifest["kernels"]:
            for load_kind in LOAD_KINDS:
                for tables in TABLE_KINDS:
                    for pause in PAUSE_POLICIES:
                        for child in range(CHILDREN_PER_ROW):
                            row = _good_row(manifest, kernel, load_kind, tables, pause, child)
                            (rows / f"{row_key(row)}.json").write_text(json.dumps(row))
                            count += 1
            for child in range(FALLBACK_PER_KERNEL):
                row = _good_row(manifest, kernel, "dlopen", "exported", "never", child, True)
                (rows / f"{row_key(row)}.json").write_text(json.dumps(row))
                count += 1
            report = _good_preflight(manifest, kernel)
            (preflight / f"{kernel['name']}.json").write_text(json.dumps(report))
    (paths["campaign"] / "state.json").write_text(
        json.dumps(
            {
                "schema": CAMPAIGN_SCHEMA,
                "manifest_sha256": manifest["__digest__"],
                "state": state,
                "row_count": count,
            }
        )
    )


def self_test():
    # Current publication/admission is exercised with selected controlled tools.
    # The original ELF/campaign mutation cases below retain explicit historical
    # v1 fixture documents; no normal writer or --run admits those documents.
    subprocess.run([
        sys.executable, "-m", "unittest", "discover",
        "-s", str(repo_root() / "tests/python"),
        "-p", "test_live_freeze_prepared_dependencies.py",
    ], check=True)
    root = repo_root()
    if shutil.which("gcc") is None:
        fail("--self-test builds the frozen fixtures and needs gcc")
    engine_source = (root / "src/discovery/engine.rs").read_text()
    for label, mutation in [
        ("LP64 loader state offset", engine_source.replace("ElfAbi::Lp64 => 24", "ElfAbi::Lp64 => 16", 1)),
        (
            "ILP32 loader state offset",
            engine_source.replace("ElfAbi::Ilp32 => 12", "ElfAbi::Ilp32 => 16", 1),
        ),
    ]:
        _reject(lambda mutation=mutation: source_constants(root, mutation), label)
    with tempfile.TemporaryDirectory(prefix="p11scope-live-discovery-selftest-") as temporary:
        elf32_source = Path(temporary) / "elf32.c"
        elf32_path = Path(temporary) / "elf32"
        elf32_source.write_text("int main(void) { return 0; }\n")
        subprocess.run(
            ["gcc", "-m32", "-o", str(elf32_path), str(elf32_source)],
            check=True,
        )
        elf32 = elf_facts(elf32_path)
        if (elf32["elf_class"], elf32["machine"], elf32["abi"], elf32["r_state_offset"]) != (
            1,
            3,
            "linux-ilp32",
            12,
        ):
            raise AssertionError(f"unexpected ELF32 facts: {elf32}")
        libc32_bytes = companion_libc_path(elf32_path).read_bytes()
        libc32_header = struct.unpack_from("<HHIIIIIHHHHHH", libc32_bytes, 16)
        shoff, shentsize, shnum = libc32_header[5], libc32_header[10], libc32_header[11]
        libc32_sections = [
            struct.unpack_from("<IIIIIIIIII", libc32_bytes, shoff + index * shentsize)
            for index in range(shnum)
        ]
        version_index = next(
            index for index, section in enumerate(libc32_sections) if section[1] == 0x6FFFFFFF
        )
        version = libc32_sections[version_index]
        malformed_version = Path(temporary) / "malformed-versym"
        for label, field, value in (
            ("truncated symbol versions", 5, 2),
            ("odd symbol-version size", 5, version[5] - 1),
            ("wrong symbol-version entry size", 9, 4),
            ("out-of-file symbol versions", 4, len(libc32_bytes)),
            ("invalid symbol-version association", 6, shnum),
            ("non-dynamic symbol-version association", 6, 0),
        ):
            changed = bytearray(libc32_bytes)
            fields = list(version)
            fields[field] = value
            struct.pack_into("<IIIIIIIIII", changed, shoff + version_index * shentsize, *fields)
            malformed_version.write_bytes(changed)
            _reject(lambda: elf_facts(malformed_version, ("dlopen",)), label)
        changed = bytearray(libc32_bytes)
        duplicate_index = next(
            index for index, section in enumerate(libc32_sections) if section[1] == 7
        )
        struct.pack_into("<IIIIIIIIII", changed, shoff + duplicate_index * shentsize, *version)
        malformed_version.write_bytes(changed)
        _reject(lambda: elf_facts(malformed_version, ("dlopen",)), "duplicate symbol versions")
        print("ELF32 symbol-version bounds and unique dynamic-symbol association: OK")

        malformed = Path(temporary) / "malformed-elf32"
        malformed.write_bytes(elf32_path.read_bytes()[:20])
        _reject(lambda: elf_facts(malformed), "truncated ELF32 header")
        elf32_bytes = bytearray(elf32_path.read_bytes())
        header = struct.unpack_from("<HHIIIIIHHHHHH", elf32_bytes, 16)
        phoff, phentsize, phnum = header[4], header[8], header[9]
        programs = [
            list(struct.unpack_from("<IIIIIIII", elf32_bytes, phoff + index * phentsize))
            for index in range(phnum)
        ]
        load_index = next(index for index, program in enumerate(programs) if program[0] == 1)
        interp_index = next(index for index, program in enumerate(programs) if program[0] == 3)

        oversized = Path(temporary) / "oversized-load"
        oversized_bytes = bytearray(elf32_bytes)
        load = programs[load_index]
        load[4] = load[5] + 1
        struct.pack_into("<IIIIIIII", oversized_bytes, phoff + load_index * phentsize, *load)
        oversized.write_bytes(oversized_bytes)
        _reject(lambda: elf_facts(oversized), "PT_LOAD file size exceeds memory size")

        out_of_bounds = Path(temporary) / "out-of-bounds-load"
        out_of_bounds_bytes = bytearray(elf32_bytes)
        load = programs[load_index]
        load[1], load[4], load[5] = len(out_of_bounds_bytes), 1, max(load[5], 1)
        struct.pack_into("<IIIIIIII", out_of_bounds_bytes, phoff + load_index * phentsize, *load)
        out_of_bounds.write_bytes(out_of_bounds_bytes)
        _reject(lambda: elf_facts(out_of_bounds), "PT_LOAD file range beyond EOF")

        loader_path = Path(elf32["interpreter"])
        loader_bytes = bytearray(loader_path.read_bytes())
        loader_header = struct.unpack_from("<HHIIIIIHHHHHH", loader_bytes, 16)
        loader_phoff, loader_phentsize, loader_phnum = (
            loader_header[4],
            loader_header[8],
            loader_header[9],
        )
        loader_programs = [
            list(
                struct.unpack_from(
                    "<IIIIIIII", loader_bytes, loader_phoff + index * loader_phentsize
                )
            )
            for index in range(loader_phnum)
        ]
        loader_load_index = next(
            index for index, program in enumerate(loader_programs) if program[0] == 1
        )
        loader_load = loader_programs[loader_load_index]
        loader_load[4] = len(loader_bytes) - loader_load[1] + 1
        loader_load[5] = max(loader_load[5], loader_load[4])
        struct.pack_into(
            "<IIIIIIII",
            loader_bytes,
            loader_phoff + loader_load_index * loader_phentsize,
            *loader_load,
        )
        malformed_loader = Path(temporary) / "loader-filesz-beyond-eof"
        malformed_loader.write_bytes(loader_bytes)
        _reject(
            lambda: elf_facts(malformed_loader, symbols=(DEBUG_STATE_SYMBOL,)),
            "real ELF32 loader PT_LOAD file range beyond EOF",
        )

        unterminated = Path(temporary) / "unterminated-interpreter"
        unterminated_bytes = bytearray(elf32_bytes)
        interp = programs[interp_index]
        unterminated_bytes[interp[1] + interp[4] - 1] = ord("X")
        unterminated.write_bytes(unterminated_bytes)
        _reject(lambda: elf_facts(unterminated), "PT_INTERP missing trailing NUL")
        x32 = Path(temporary) / "x32-elf"
        x32_bytes = bytearray(elf32_path.read_bytes())
        struct.pack_into("<H", x32_bytes, 18, 62)
        x32.write_bytes(x32_bytes)
        _reject(lambda: elf_facts(x32), "ELF32 with EM_X86_64")
        foreign = Path(temporary) / "foreign-elf"
        foreign_bytes = bytearray(elf32_path.read_bytes())
        struct.pack_into("<H", foreign_bytes, 18, 40)
        foreign.write_bytes(foreign_bytes)
        _reject(lambda: elf_facts(foreign), "foreign ELF machine")
        print("ELF32 layout, source offsets, and malformed/x32/foreign refusals: OK")

        width_manifests = {}
        for bits, abi in ((32, "linux-ilp32"), (64, "linux-lp64")):
            width_root = Path(temporary) / f"private-{bits}"
            width_paths = prepare_private_root(root, width_root)
            width_paths["manifest"].write_text(json.dumps(
                _historical_fixture_manifest(width_root, root, {}, bits)
            ))
            width_manifest = load_manifest(width_paths["manifest"])
            bind_manifest(width_manifest, root)
            fixture_abis = {
                elf_facts(output["path"])["abi"]
                for output in width_manifest["fixtures"]["outputs"].values()
            }
            if fixture_abis != {abi}:
                raise AssertionError(f"unexpected {bits}-bit fixture ABIs: {fixture_abis}")
            width_manifests[bits] = width_manifest

        wrong_width_command = copy.deepcopy(width_manifests[32])
        command = wrong_width_command["fixtures"]["commands"]["provider-hidden.so"]
        command[command.index("-m32")] = "-m64"
        _reject(
            lambda: bind_manifest(wrong_width_command, root),
            "mixed fixture compiler widths",
        )

        mixed = copy.deepcopy(width_manifests[32])
        mixed_output = mixed["fixtures"]["outputs"]["provider-hidden.so"]
        source = Path(width_manifests[64]["fixtures"]["outputs"]["provider-hidden.so"]["path"])
        destination = Path(mixed_output["path"])
        shutil.copyfile(source, destination)
        mixed_output["sha256"] = sha256_file(destination)
        _reject(lambda: bind_manifest(mixed, root), "mixed fixture ABIs")
        print("explicit 32/64-bit fixture freezes and mixed-ABI refusal: OK")

        private_root = Path(temporary) / "private"
        paths = prepare_private_root(root, private_root)
        paths["manifest"].write_text(json.dumps(
            _historical_fixture_manifest(private_root, root, {})
        ))
        manifest = load_manifest(paths["manifest"])
        bind_manifest(manifest, root)
        print("historical v1 frozen manifest binding: OK")

        outputs = manifest["fixtures"]["outputs"]
        if outputs["provider-exported.so"]["sha256"] == outputs["provider-hidden.so"]["sha256"]:
            raise AssertionError("the exported and hidden provider builds produced one identity")
        print("exported/hidden provider byte identities differ: OK")

        for label, mutation in [
            ("manifest schema", _patch(manifest, ["schema"], "other/v1")),
            ("BPF source digest", _patch(manifest, ["bpf_source", "sha256"], "0" * 64)),
            (
                "noncanonical BPF source",
                _patch(manifest, ["bpf_source", "canonical_path"], "/elsewhere/main.rs"),
            ),
            ("BPF object digest", _patch(manifest, ["bpf_object", "sha256"], "0" * 64)),
            ("BPF object path", _patch(manifest, ["bpf_object", "path"], "/tmp/guessed-object")),
            ("BPF inventory digest", _patch(manifest, ["bpf_inventory", "sha256"], "0" * 64)),
            ("runner digest", _patch(manifest, ["runner", "sha256"], "0" * 64)),
            (
                "validator digest",
                _patch(manifest, ["validators", VALIDATORS[0]], "0" * 64),
            ),
            (
                "production map inventory",
                _patch(manifest, ["inventory", "maps"], manifest["inventory"]["maps"][:4]),
            ),
            (
                "production program inventory",
                _patch(manifest, ["inventory", "programs"], manifest["inventory"]["programs"][:3]),
            ),
            ("cookie context ids", _patch(manifest, ["cookie", "context_ids"], 128)),
            ("cookie absent sentinel", _patch(manifest, ["cookie", "absent_sentinel"], 2)),
            ("cookie present bit", _patch(manifest, ["cookie", "present_bit"], 1 << 9)),
            ("signed delta bound", _patch(manifest, ["cookie", "delta_max"], (1 << 54))),
            ("cookie state shift", _patch(manifest, ["cookie", "shift"], 8)),
            ("function-IP helper", _patch(manifest, ["function_ip", "helper"], "bpf_get_stackid")),
            (
                "x86-64 function-IP fallback",
                _patch(manifest, ["function_ip", "fallback"], "pt_regs.rsp"),
            ),
            ("r_state offset", _patch(manifest, ["r_state_offset"], 16)),
            ("A/B four-map oracle record", _patch(manifest, ["ab_four_map_oracle"], ["DISCOVERY"])),
            (
                "privacy allowlist digest",
                _patch(manifest, ["privacy", "allowlist_sha256"], "0" * 64),
            ),
            (
                "fixture source digest",
                _patch(manifest, ["fixtures", "sources", FIXTURE_SOURCES[0]], "0" * 64),
            ),
            (
                "frozen cflags",
                _patch(manifest, ["fixtures", "toolchain", "cflags"], "-std=c11 -O2"),
            ),
            (
                "frozen shared link flags",
                _patch(manifest, ["fixtures", "toolchain", "shared_ldflags"], "-shared"),
            ),
            (
                "frozen driver link flags",
                _patch(manifest, ["fixtures", "toolchain", "driver_ldflags"], "-ldl"),
            ),
            (
                "compiler identity",
                _patch(manifest, ["fixtures", "toolchain", "cc_version"], ""),
            ),
            (
                "fixture output digest",
                _patch(
                    manifest,
                    ["fixtures", "outputs", "provider-hidden.so", "sha256"],
                    "0" * 64,
                ),
            ),
            (
                "fixture build command flags",
                _patch(
                    manifest,
                    ["fixtures", "commands", "provider-exported.so"],
                    ["gcc", "-O2", "-shared", "-o", "provider-exported.so"],
                ),
            ),
            (
                "interpreter identity",
                _patch(manifest, ["loader", "interpreter", "sha256"], "0" * 64),
            ),
            (
                "interpreter ABI",
                _patch(manifest, ["loader", "interpreter", "abi"], "linux-ilp32"),
            ),
            (
                "interpreter is the driver's PT_INTERP",
                _patch(
                    manifest,
                    ["loader", "interpreter", "dt_needed_driver_interp"],
                    "/lib64/other-loader.so",
                ),
            ),
            (
                "glibc 31986 disposition",
                _patch(
                    manifest,
                    ["loader", "interpreter", "rtld_audit_31986_fixed"],
                    not manifest["loader"]["interpreter"]["rtld_audit_31986_fixed"],
                ),
            ),
            (
                "companion libc identity",
                _patch(manifest, ["loader", "companion_libc", "sha256"], "0" * 64),
            ),
            (
                "reviewed fallback offset",
                _patch(manifest, ["loader", "companion_libc", "fallback_offset"], 0),
            ),
            ("loader provenance", _patch(manifest, ["loader", "provenance"], {})),
            (
                "pinned debug-state hook offset",
                _patch(manifest, ["hooks", "debug_state", "file_offset"], 1),
            ),
            (
                "pinned export hook offset",
                _patch(manifest, ["hooks", "export", "file_offset"], 1),
            ),
            (
                "surface target set",
                _patch(
                    manifest,
                    ["surfaces", "C_GetInterface", "targets"],
                    ["task_newtask", "sched_process_exit"],
                ),
            ),
            (
                "overlapping surface target sets",
                _patch(
                    manifest,
                    ["surfaces", "C_GetInterface", "targets"],
                    ["function_list_entry", "function_list_return"],
                ),
            ),
            (
                "surface constructor marker",
                _patch(manifest, ["surfaces", "C_GetInterface", "constructor_marker"], "x"),
            ),
            (
                "surface application marker",
                _patch(
                    manifest,
                    ["surfaces", "C_GetInterfaceList", "application_marker"],
                    manifest["surfaces"]["C_GetInterfaceList"]["constructor_marker"],
                ),
            ),
            (
                "frozen lane set",
                _patch(manifest, ["lanes"], {k: v for k, v in LANES.items() if k != "zero-modules"}),
            ),
            (
                "frozen lane invocation",
                _patch(manifest, ["lanes", "two-providers", "argv"], ["dlopen", "{exported}"]),
            ),
            (
                "frozen lane driver",
                _patch(manifest, ["lanes", "zero-modules", "driver"], "driver-unfrozen"),
            ),
            (
                "frozen lane provider identity",
                _patch(
                    manifest,
                    ["lanes", "two-providers", "argv"],
                    ["dlopen", "{exported}", "{third}"],
                ),
            ),
            (
                "frozen fixture knob",
                _patch(
                    manifest,
                    ["lanes", "zero-modules", "env"],
                    {"P11SCOPE_FIXTURE_UNKNOWN": "1"},
                ),
            ),
            (
                "frozen marker expectation",
                _patch(manifest, ["lanes", "zero-modules", "markers"], "maybe"),
            ),
            ("frozen kernel count", _patch(manifest, ["kernels"], manifest["kernels"][:2])),
            (
                "distinct kernel release prefixes",
                _patch(manifest, ["kernels", 1, "release_prefix"], "5.15."),
            ),
            ("kernel base identity", _patch(manifest, ["kernels", 0, "base"], {})),
            ("frozen 480-attempt grid", _patch(manifest, ["campaign", "primary_attempts"], 160)),
            (
                "frozen fallback attempts",
                _patch(manifest, ["campaign", "fallback_attempts"], 0),
            ),
            ("frozen children per row", _patch(manifest, ["campaign", "children_per_row"], 10)),
            ("frozen campaign root", _patch(manifest, ["campaign", "root"], "/tmp/guessed")),
            ("frozen caps", _patch(manifest, ["caps"], [])),
            ("frozen deadlines", _patch(manifest, ["deadlines", "attempt_seconds"], None)),
            ("frozen topology", _patch(manifest, ["topology", "cold_boot"], _DROP)),
        ]:
            _reject(lambda mutation=mutation: bind_manifest(mutation, root), label)
        print(f"execution manifest mutations rejected: OK ({len(manifest)} frozen groups)")

        _write_campaign(paths, manifest, "frozen")
        validate_campaign(paths["campaign"], manifest)
        _reject(
            lambda: validate_campaign(paths["campaign"], _patch(manifest, ["__digest__"], "0" * 64)),
            "campaign bound to another manifest",
        )
        (paths["campaign"] / "rows" / "jammy-dlopen-exported-never-0.json").write_text(
            json.dumps(_good_row(manifest, manifest["kernels"][0], "dlopen", "exported", "never", 0))
        )
        _reject(
            lambda: validate_campaign(paths["campaign"], manifest),
            "row recorded before the campaign left the frozen state",
        )

        _write_campaign(paths, manifest, "running")
        (paths["campaign"] / "rows" / "jammy-dlopen-exported-never-0.json").write_text(
            json.dumps(_good_row(manifest, manifest["kernels"][0], "dlopen", "exported", "never", 0))
        )
        _reject(
            lambda: validate_campaign(paths["campaign"], manifest),
            "partial campaign reported as PASS",
        )

        _write_campaign(paths, manifest, "complete")
        print(f"campaign PASS: {validate_campaign(paths['campaign'], manifest)}")

        rows = paths["campaign"] / "rows"
        complete = json.loads((paths["campaign"] / "state.json").read_text())

        def with_rows(changes, state=None):
            def action():
                originals = {}
                for name, replacement in changes.items():
                    path = rows / name
                    originals[path] = path.read_text() if path.exists() else None
                    if replacement is _DROP:
                        path.unlink()
                    else:
                        path.write_text(json.dumps(replacement))
                state_path = paths["campaign"] / "state.json"
                original_state = state_path.read_text()
                if state is not None:
                    state_path.write_text(json.dumps(state))
                try:
                    validate_campaign(paths["campaign"], manifest)
                finally:
                    state_path.write_text(original_state)
                    for path, text in originals.items():
                        if text is None:
                            path.unlink()
                        else:
                            path.write_text(text)

            return action

        never = _good_row(manifest, manifest["kernels"][0], "dlopen", "exported", "never", 0)
        auto = _good_row(manifest, manifest["kernels"][0], "dlopen", "exported", "auto", 0)
        always = _good_row(manifest, manifest["kernels"][0], "dlopen", "exported", "always", 0)
        fallback = _good_row(
            manifest, manifest["kernels"][0], "dlopen", "exported", "never", 0, True
        )
        never_name = "jammy-dlopen-exported-never-0.json"
        auto_name = "jammy-dlopen-exported-auto-0.json"
        always_name = "jammy-dlopen-exported-always-0.json"
        fallback_name = "jammy-fallback-0.json"

        row_mutations = [
            ("missing row", {never_name: _DROP}),
            ("row count disagreement", {}, {**complete, "row_count": complete["row_count"] - 1}),
            ("duplicate row under a second file name", {"jammy-copy.json": never}),
            (
                "child index outside the frozen 20",
                {"jammy-dlopen-exported-never-99.json": _patch(never, ["child"], 99)},
            ),
            ("row schema", {never_name: _patch(never, ["schema"], "other/v1")}),
            (
                "row manifest binding",
                {never_name: _patch(never, ["manifest_sha256"], "0" * 64)},
            ),
            (
                "row kernel",
                {"focal-dlopen-exported-never-0.json": _patch(never, ["kernel"], "focal")},
            ),
            (
                "row kernel release prefix",
                {never_name: _patch(never, ["kernel_release"], "6.8.0-generic")},
            ),
            ("row base identity", {never_name: _patch(never, ["base_sha256"], "not-a-digest")}),
            (
                "one base identity per kernel",
                {never_name: _patch(never, ["base_sha256"], "2" * 64)},
            ),
            ("row lane", {never_name: _patch(never, ["lane"], "undeclared-lane")}),
            ("row outcome mixed", {never_name: _patch(never, ["outcome"], "mixed")}),
            ("row outcome unclassified", {never_name: _patch(never, ["outcome"], "unclassified")}),
            (
                "initial-set capture",
                {never_name: _patch(never, ["initial_set_capture"], "partial")},
            ),
            ("completeness", {never_name: _patch(never, ["completeness"], "COMPLETE")}),
            ("privacy scan", {never_name: _patch(never, ["privacy", "scan"], "leak")}),
            (
                "privacy allowlist",
                {never_name: _patch(never, ["privacy", "allowlist_sha256"], "0" * 64)},
            ),
            ("pinned libc identity", {never_name: _patch(never, ["libc"], "2.31")}),
            (
                "surface coverage",
                {never_name: _patch(never, ["surfaces", "C_GetInterface"], _DROP)},
            ),
            (
                "application marker",
                {
                    never_name: _patch(
                        never, ["surfaces", "C_GetInterfaceList", "application_marker"], False
                    )
                },
            ),
            (
                "constructor marker",
                {
                    never_name: _patch(
                        never, ["surfaces", "C_GetFunctionList", "constructor_marker"], False
                    )
                },
            ),
            (
                "surface target set",
                {
                    never_name: _patch(
                        never, ["surfaces", "C_GetInterface", "targets_attached"], ["p11_entry"]
                    )
                },
            ),
            ("primary timing", {never_name: _patch(never, ["timing"], "proven")}),
            ("never row owner", {never_name: _patch(never, ["owner", "pause_owner"], "child")}),
            ("never row signal", {never_name: _patch(never, ["owner", "signals"], 1)}),
            ("never row window", {never_name: _patch(never, ["windows", "observed"], 1)}),
            ("never row attachment", {never_name: _patch(never, ["attachment"], "unknown")}),
            ("auto row missed window", {auto_name: _patch(auto, ["windows", "missed"], 1)}),
            (
                "auto row unclosed window",
                {auto_name: _patch(auto, ["windows", "closed"], 1)},
            ),
            (
                "auto row sticky partial",
                {auto_name: _patch(auto, ["windows", "sticky_partial"], True)},
            ),
            (
                "auto row rearming disabled",
                {auto_name: _patch(auto, ["windows", "rearming"], "disabled")},
            ),
            ("auto row command failure", {auto_name: _patch(auto, ["command_status"], 1)}),
            (
                "always row missed window without command failure",
                {always_name: _patch(always, ["windows", "missed"], 1)},
            ),
            (
                "always row missed window without safe cleanup",
                {
                    always_name: _patch(
                        _patch(_patch(always, ["windows", "missed"], 1), ["command_status"], 1),
                        ["cleanup"],
                        "unsafe",
                    )
                },
            ),
            (
                "fallback reason",
                {fallback_name: _patch(fallback, ["fallback", "reason"], "preferred")},
            ),
            (
                "fallback offset provenance",
                {fallback_name: _patch(fallback, ["fallback", "companion_libc_offset"], 8)},
            ),
            (
                "fallback post-return call",
                {fallback_name: _patch(fallback, ["fallback", "post_return_call"], False)},
            ),
            (
                "fallback constructor coverage",
                {fallback_name: _patch(fallback, ["fallback", "constructor_coverage"], True)},
            ),
            (
                "fallback DT_NEEDED coverage",
                {fallback_name: _patch(fallback, ["fallback", "dt_needed_coverage"], True)},
            ),
            ("fallback timing", {fallback_name: _patch(fallback, ["timing"], "unproven")}),
            (
                "fallback constructor marker",
                {
                    fallback_name: _patch(
                        fallback, ["surfaces", "C_GetFunctionList", "constructor_marker"], True
                    )
                },
            ),
            (
                "primary row activating the fallback",
                {never_name: {**never, "fallback": fallback["fallback"]}},
            ),
            (
                "A/B four-map lifecycle oracle",
                {
                    never_name: _patch(
                        never, ["lifecycle", "maps_observed"], list(AB_FOUR_MAP_ORACLE)
                    )
                },
            ),
            (
                "incomplete production map inventory",
                {
                    never_name: _patch(
                        never,
                        ["lifecycle", "maps_observed"],
                        manifest["inventory"]["maps"][:-1],
                    )
                },
            ),
            (
                "residual observer maps",
                {never_name: _patch(never, ["lifecycle", "maps_after"], ["EVENTS"])},
            ),
            (
                "residual observer links",
                {never_name: _patch(never, ["lifecycle", "links_after"], ["dl_debug_state"])},
            ),
            ("residual pins", {never_name: _patch(never, ["lifecycle", "pins_after"], 1)}),
            (
                "untombstoned loader context",
                {never_name: _patch(never, ["lifecycle", "loader_contexts_tombstoned"], 1)},
            ),
            (
                "undrained loader context",
                {never_name: _patch(never, ["lifecycle", "loader_contexts_drained"], 1)},
            ),
            (
                "residual loader context",
                {never_name: _patch(never, ["lifecycle", "loader_contexts_after"], 1)},
            ),
            (
                "residual active slots",
                {never_name: _patch(never, ["lifecycle", "slots_active_after"], 1)},
            ),
            (
                "residual process views",
                {never_name: _patch(never, ["lifecycle", "views_after"], 1)},
            ),
        ]
        for mutation in row_mutations:
            label, changes = mutation[0], mutation[1]
            state = mutation[2] if len(mutation) > 2 else None
            _reject(with_rows(changes, state), label)

        # The rtld-audit workaround rule only applies on a glibc 2.41+ pin, so
        # this lane runs against a manifest pinned there (bug 31986 is fixed
        # from 2.41; a row claiming the workaround on it is contradictory).
        pinned_241 = _patch(manifest, ["loader", "companion_libc", "libc_version"], "2.41")
        _reject(
            lambda: validate_row(
                _patch(_patch(never, ["libc"], "2.41"), ["audit_workaround_applied"], True),
                pinned_241,
                "glibc-2.41",
            ),
            "glibc 2.41+ audit workaround",
        )
        validate_row(_patch(never, ["libc"], "2.41"), pinned_241, "glibc-2.41")
        print(f"campaign row mutations rejected: OK ({len(row_mutations) + 1} lanes)")

        preflight = _good_preflight(manifest, manifest["kernels"][0])
        validate_preflight(preflight, manifest)
        preflight_mutations = [
            ("preflight schema", _patch(preflight, ["schema"], "other/v1")),
            ("preflight manifest binding", _patch(preflight, ["manifest_sha256"], "0" * 64)),
            ("preflight kernel", _patch(preflight, ["kernel"], "focal")),
            ("preflight kernel release", _patch(preflight, ["kernel_release"], "6.8.0")),
            (
                "accepted production programs",
                _patch(preflight, ["programs_accepted"], manifest["inventory"]["programs"][:-1]),
            ),
            ("256 context ids", _patch(preflight, ["context_ids"], list(range(255)))),
            ("absent cookie boundary", _patch(preflight, ["cookie_boundaries", "absent"], 2)),
            ("present cookie boundary", _patch(preflight, ["cookie_boundaries", "present"], 1)),
            (
                "signed delta boundary",
                _patch(preflight, ["cookie_boundaries", "delta_min"], 0),
            ),
            (
                "zero-cookie short circuit",
                _patch(preflight, ["short_circuit", "zero_cookie", "registry_reads"], 1),
            ),
            (
                "zero-cookie return point",
                _patch(preflight, ["short_circuit", "zero_cookie", "returned"], "after_state"),
            ),
            (
                "Aya no-cookie short circuit",
                _patch(preflight, ["short_circuit", "aya_no_cookie", "state_reads"], 1),
            ),
            (
                "missing Aya no-cookie lane",
                _patch(preflight, ["short_circuit", "aya_no_cookie"], _DROP),
            ),
            (
                "exact function IP",
                _patch(preflight, ["function_ip", "helper_matches_hook"], False),
            ),
            (
                "x86-64 fallback arithmetic",
                _patch(preflight, ["function_ip", "fallback_matches_hook"], False),
            ),
            (
                "fallback IP source",
                _patch(preflight, ["function_ip", "fallback"], "pt_regs.rsp"),
            ),
            ("PT_INTERP", _patch(preflight, ["load_bias", "pt_interp"], "/lib64/other.so")),
            ("load bias", _patch(preflight, ["load_bias", "base"], 0)),
            ("target r_state field", _patch(preflight, ["load_bias", "r_state_offset"], 16)),
            ("preflight tombstone", _patch(preflight, ["lifecycle", "tombstoned"], 2)),
            ("preflight drain", _patch(preflight, ["lifecycle", "drained"], 2)),
            ("preflight residual context", _patch(preflight, ["lifecycle", "residual"], 1)),
            ("preflight privacy", _patch(preflight, ["privacy"], "unscanned")),
            (
                "five distinct outcomes",
                _patch(preflight, ["outcomes", "stale"], "registry_full"),
            ),
            ("missing outcome", _patch(preflight, ["outcomes", "identity"], _DROP)),
        ]
        for label, mutation in preflight_mutations:
            _reject(
                lambda mutation=mutation: validate_preflight(mutation, manifest),
                label,
            )
        print(f"preflight PASS-list mutations rejected: OK ({len(preflight_mutations)} lanes)")
    print("check-live-discovery-evidence self-test: OK")


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--create-root", action="store_true")
    parser.add_argument("--populate-root", action="store_true")
    parser.add_argument("--build-fixtures", action="store_true")
    parser.add_argument("--bpf-object", type=Path)
    parser.add_argument("--runner", type=Path)
    parser.add_argument("--require-prepared-dependencies", action="store_true")
    parser.add_argument("--private-root", type=Path)
    parser.add_argument("--fixture-bits", type=int, choices=(32, 64))
    parser.add_argument(
        "--kernel-base",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="retained overlay base to hash into the frozen kernel identity",
    )
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--preflight", type=Path)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = repo_root()
    check([(not args.require_prepared_dependencies or args.manifest is not None,
            "--require-prepared-dependencies requires --manifest")])
    setup = [args.create_root, args.populate_root, args.build_fixtures]
    if any(setup):
        check([(sum(setup) == 1 and args.private_root is not None
                and not any((args.self_test, args.write_manifest, args.manifest,
                             args.campaign, args.preflight, args.kernel_base,
                             args.require_prepared_dependencies)),
                "private root setup takes exactly one mode and --private-root")])
        check([(args.populate_root or (args.bpf_object is None and args.runner is None),
                "--bpf-object and --runner require --populate-root"),
               (args.build_fixtures or args.fixture_bits is None,
                "--fixture-bits requires --build-fixtures or --write-manifest")])
        paths = frozen_paths(args.private_root)
        if args.create_root:
            create_private_root(args.private_root)
        elif args.populate_root:
            check([(args.bpf_object is not None and args.runner is not None,
                    "populate-root requires --bpf-object and --runner")])
            shutil.copyfile(args.bpf_object, paths["bpf_object"])
            shutil.copyfile(args.runner, paths["runner"])
        else:
            build_fixtures(root, paths["fixtures"], args.fixture_bits)
        return
    check([(args.bpf_object is None and args.runner is None,
            "--bpf-object and --runner require --populate-root")])
    if args.self_test:
        if args.write_manifest or args.kernel_base or any(
            value is not None
            for value in (
                args.private_root,
                args.fixture_bits,
                args.campaign,
                args.preflight,
                args.manifest,
            )
        ):
            fail("--self-test accepts no other arguments")
        self_test()
        return

    if args.write_manifest:
        if args.private_root is None or any(
            value is not None for value in (args.campaign, args.preflight, args.manifest)
        ):
            fail(
                "manifest mode requires --write-manifest --private-root "
                "with optional --fixture-bits"
            )
        bases = {}
        for entry in args.kernel_base:
            name, _, path = entry.partition("=")
            if name not in {n for n, _, _ in FROZEN_KERNELS} or not path:
                fail(f"--kernel-base expects one of {[n for n, _, _ in FROZEN_KERNELS]}=PATH")
            bases[name] = Path(path).resolve(strict=True)
        manifest = write_manifest(args.private_root, root, bases, args.fixture_bits)
        print(f"froze execution manifest {frozen_paths(args.private_root)['manifest']}")
        print(
            f"  {manifest['campaign']['primary_attempts']} primary + "
            f"{manifest['campaign']['fallback_attempts']} forced dlopen_return attempts"
        )
        return

    if (
        args.manifest is None
        or args.private_root is not None
        or args.fixture_bits is not None
        or args.kernel_base
    ):
        fail("check mode requires --manifest with at most one of --campaign/--preflight")
    if args.campaign is not None and args.preflight is not None:
        fail("check mode takes --campaign or --preflight, not both")
    manifest = load_manifest(args.manifest)
    if args.require_prepared_dependencies:
        check([(manifest.get("schema") == MANIFEST_SCHEMA,
                "prepared v2 execution manifest required; historical v1 cannot run")])
        check([(args.manifest.is_absolute()
                and args.manifest == frozen_paths(get(manifest, "private_root", default=""))["manifest"],
                "requested execution manifest path differs from its frozen private root")])
    bind_manifest(manifest, root)
    if args.campaign is None and args.preflight is None:
        # Bind-only: every frozen input still matches, before anything runs.
        print(f"live discovery execution manifest: {args.manifest} binds every frozen input")
        return
    if args.preflight is not None:
        kernel = validate_preflight(json.loads(args.preflight.read_text()), manifest)
        print(f"live discovery preflight: kernel={kernel} canonical PASS list OK")
        return
    print(f"live discovery campaign: {validate_campaign(args.campaign, manifest)}")


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        RuntimeError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        print(f"check-live-discovery-evidence: {error}", file=sys.stderr)
        sys.exit(1)
