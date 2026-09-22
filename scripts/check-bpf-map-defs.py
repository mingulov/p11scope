#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inspect exact map/program policy inventory in a freshly built BPF ELF."""

from pathlib import Path
import contextlib
import io
import json
import re
import struct
import subprocess
import sys
import tempfile


MAP_FIELDS = ("type", "key_size", "value_size", "max_entries", "flags", "id", "pinning")
MAP_DEFINITION_SIZE = 28


def elf_records(path):
    symbols = subprocess.run(
        ["llvm-readelf", "-sW", path], capture_output=True, text=True, check=True
    ).stdout
    sections = subprocess.run(
        ["llvm-readelf", "-SW", path], capture_output=True, text=True, check=True
    ).stdout
    records = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        try:
            value, size = int(fields[1], 16), int(fields[2])
        except ValueError:
            continue
        records.append((value, size, fields[3], fields[4], fields[5], fields[6], fields[7]))
    indices = {
        match.group(2): int(match.group(1))
        for line in sections.splitlines()
        if (match := re.match(r"\s*\[\s*(\d+)\]\s+(\S+)", line))
    }
    return records, indices


def checked_slice(data, offset, size, label):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise RuntimeError(f"{label} out of bounds")
    return data[offset:offset + size]


def string_at(data, offset):
    if offset >= len(data):
        raise RuntimeError("invalid string reference")
    end = data.find(b"\0", offset)
    if end < 0:
        raise RuntimeError("unterminated string")
    try:
        return data[offset:end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("invalid string encoding") from error


class Elf:
    """Bounded ELF64/BPF metadata used to cross-check LLVM and BTF relocation facts."""
    def __init__(self, data):
        header = checked_slice(data, 0, 64, "ELF header")
        if header[:7] != b"\x7fELF\x02\x01\x01":
            raise RuntimeError("unsupported ELF schema/endian (requires ELF64 little endian)")
        if struct.unpack_from("<HHI", header, 16) != (1, 247, 1):
            raise RuntimeError("unsupported ELF type/machine/version")
        offset = struct.unpack_from("<Q", header, 40)[0]
        ehsize, _, _, stride, count, names_index = struct.unpack_from("<6H", header, 52)
        if ehsize != 64 or stride != 64 or not count or not 0 < names_index < count:
            raise RuntimeError("unsupported ELF section schema")
        table = checked_slice(data, offset, count * stride, "ELF sections")
        headers = [struct.unpack_from("<IIQQQQIIQQ", table, i * stride) for i in range(count)]
        names = headers[names_index]
        if names[1] != 3:
            raise RuntimeError("ELF section names are not STRTAB")
        strings = checked_slice(data, names[4], names[5], "ELF section names")
        self.sections = {}
        self.indices = {}
        for index, row in enumerate(headers):
            name = string_at(strings, row[0])
            if index == 0:
                continue
            if not name or name in self.sections:
                raise RuntimeError(f"duplicate or empty ELF section {name!r}")
            body = b"" if row[1] == 8 else checked_slice(data, row[4], row[5], name)
            self.sections[name] = (row, body)
            self.indices[name] = index
        symtabs = [name for name, (row, _) in self.sections.items() if row[1] == 2]
        if symtabs != [".symtab"]:
            raise RuntimeError("requires exactly one .symtab")
        row, body = self.sections[".symtab"]
        if row[9] != 24 or len(body) % 24 or not 0 < row[6] < count:
            raise RuntimeError("invalid ELF symbol table")
        strings_row = headers[row[6]]
        if strings_row[1] != 3:
            raise RuntimeError("ELF symbol names are not STRTAB")
        strings = checked_slice(data, strings_row[4], strings_row[5], "symbol strings")
        self.symbols = []
        self.records = []
        kinds = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}
        binds = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
        for pos in range(0, len(body), 24):
            no, info, other, section, value, size = struct.unpack_from("<IBBHQQ", body, pos)
            name = string_at(strings, no)
            self.symbols.append((name, info, other, section, value, size))
            if section < 0xff00 and section >= count:
                raise RuntimeError("ELF symbol section out of bounds")
            if info & 15 == 3 and not name and section < count:
                name = string_at(checked_slice(data, names[4], names[5], "section names"), headers[section][0])
            if not name:
                continue
            sec = {0: "UND", 0xfff1: "ABS", 0xfff2: "COM"}.get(section, str(section))
            self.records.append((value, size, kinds.get(info & 15, str(info & 15)),
                                 binds.get(info >> 4, str(info >> 4)),
                                 ("DEFAULT", "INTERNAL", "HIDDEN", "PROTECTED")[other & 3], sec, name))


class Btf:
    def __init__(self, data):
        header = checked_slice(data, 0, 24, "BTF header")
        magic, version, flags, hlen, toff, tlen, soff, slen = struct.unpack("<HBBIIIII", header)
        if (magic, version, flags, hlen, toff) != (0xeb9f, 1, 0, 24, 0):
            raise RuntimeError("unsupported BTF schema/endian")
        if soff != tlen or hlen + soff + slen != len(data):
            raise RuntimeError("invalid BTF section lengths")
        self.strings = checked_slice(data, hlen + soff, slen, "BTF strings")
        if not self.strings or self.strings[0] or self.strings[-1]:
            raise RuntimeError("invalid BTF strings")
        raw = checked_slice(data, hlen, tlen, "BTF types")
        self.types = [None]
        pos = 0
        while pos < len(raw):
            no, info, value = struct.unpack("<III", checked_slice(raw, pos, 12, "BTF type"))
            kind, vlen, kflag = (info >> 24) & 31, info & 65535, info >> 31
            if info & 0x60ff0000:
                raise RuntimeError("invalid BTF type info")
            sizes = {1: 4, 2: 0, 3: 12, 4: vlen * 12, 5: vlen * 12,
                     6: vlen * 8, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0,
                     12: 0, 13: vlen * 8, 14: 4, 15: vlen * 12,
                     16: 0, 17: 4, 18: 0, 19: vlen * 12}
            if kflag and kind not in (4, 5, 6, 7, 19):
                raise RuntimeError("invalid BTF kind flag")
            if kind not in sizes:
                raise RuntimeError(f"unsupported BTF kind {kind}")
            if kind not in (4, 5, 6, 12, 13, 15, 19) and vlen:
                raise RuntimeError("invalid BTF vlen")
            extra = checked_slice(raw, pos + 12, sizes[kind], "BTF payload")
            words = struct.unpack(f"<{len(extra)//4}I", extra)
            self.types.append((kind, string_at(self.strings, no), value, vlen, kflag, words, hlen + pos))
            pos += 12 + sizes[kind]
        named_vars, datasecs = set(), set()
        for kind, name, value, vlen, _, words, _ in self.types[1:]:
            if kind in (14, 15):
                names = named_vars if kind == 14 else datasecs
                if not name or name in names:
                    raise RuntimeError("duplicate/empty BTF VAR or DATASEC name")
                names.add(name)
            if kind == 14 and words[0] > 2 or kind == 12 and vlen > 2:
                raise RuntimeError("invalid BTF linkage")
            refs = []
            if kind in (2, 8, 9, 10, 11, 12, 13, 14, 17, 18):
                refs.append(value)
            if kind == 3:
                refs.extend(words[:2])
            if kind in (4, 5):
                refs.extend(words[1::3])
            if kind == 15:
                refs.extend(words[::3])
            if kind == 13:
                refs.extend(words[1::2])
            if any(ref >= len(self.types) for ref in refs):
                raise RuntimeError("invalid BTF type reference")
            if kind in (4, 5, 6, 13, 19):
                step = 3 if kind in (4, 5, 19) else 2
                member_names = [string_at(self.strings, x) for x in words[::step]]
                named = [name for name in member_names if name]
                if len(named) != len(set(named)):
                    raise RuntimeError("duplicate BTF member name")

    def resolve(self, ref):
        seen = set()
        while ref and ref < len(self.types):
            if ref in seen or len(seen) >= 64:
                raise RuntimeError("BTF type resolution cycle/depth")
            seen.add(ref)
            node = self.types[ref]
            if node[0] not in (8, 9, 10, 11, 18):
                if node[0] == 1:
                    encoding = node[5][0]
                    offset, width = (encoding >> 16) & 255, encoding & 255
                    if (encoding & 0xf800ff00 or node[2] not in (1, 2, 4, 8, 16)
                            or not width or offset + width > node[2] * 8):
                        raise RuntimeError("invalid BTF INT encoding/size bounds")
                return node
            ref = node[2]
        raise RuntimeError("invalid BTF type reference/void")

    def size(self, ref, seen=()):
        if ref in seen or len(seen) >= 64:
            raise RuntimeError("BTF size resolution cycle/depth")
        node = self.resolve(ref)
        kind, _, value, _, _, words, _ = node
        if kind in (1, 4, 5, 6, 16, 19):
            size = value
            if kind in (4, 5):
                for i in range(node[3]):
                    _, member_ref, offset = words[i*3:i*3+3]
                    width = offset >> 24 if node[4] else 0
                    offset = offset & 0xffffff if node[4] else offset
                    member_size = self.size(member_ref, seen + (ref,)) * 8
                    if offset + (width or member_size) > size * 8 or width > member_size:
                        raise RuntimeError("BTF value member bounds")
        elif kind == 3:
            if self.resolve(words[1])[0] != 1:
                raise RuntimeError("invalid BTF array index")
            size = self.size(words[0], seen + (ref,)) * words[2]
        elif kind == 2:
            size = 8
        else:
            raise RuntimeError(f"unsupported BTF sized type {kind}")
        if not 0 < size <= 0xffffffff:
            raise RuntimeError("BTF size out of range")
        return size

    def map_definition(self, ref):
        kind, _, size, count, flag, members, _ = self.resolve(ref)
        if kind != 4 or flag or size != count * 8:
            raise RuntimeError("unsupported BTF map struct layout")
        fields = {}
        for i in range(count):
            name, ref, offset = members[i*3:i*3+3]
            name = string_at(self.strings, name)
            if name in fields:
                raise RuntimeError("duplicate BTF map member")
            if name not in {"type", "key", "value", "key_size", "value_size", "max_entries", "map_flags"}:
                raise RuntimeError(f"unknown BTF map member {name!r}")
            pointer = self.resolve(ref)
            if offset != i * 64 or pointer[0] != 2:
                raise RuntimeError("unsupported BTF map member layout")
            if name in ("key", "value"):
                fields[name] = self.size(pointer[2])
            else:
                array = self.resolve(pointer[2])
                if array[0] != 3 or self.resolve(array[5][0])[0] != 1 or self.resolve(array[5][1])[0] != 1:
                    raise RuntimeError("unsupported BTF map integer encoding")
                fields[name] = array[5][2]
        if "type" not in fields or any(x in fields and x + "_size" in fields for x in ("key", "value")):
            raise RuntimeError("missing/conflicting BTF map fields")
        return map_def(fields["type"], fields.get("key", fields.get("key_size", 0)),
                       fields.get("value", fields.get("value_size", 0)),
                       fields.get("max_entries", 0), fields.get("map_flags", 0)), size


def decode_btf_maps(elf):
    if ".BTF" not in elf.sections:
        raise RuntimeError("native .maps missing .BTF")
    btf = Btf(elf.sections[".BTF"][1])
    sections = [n for n in btf.types[1:] if n[0] == 15 and n[1] == ".maps"]
    if len(sections) != 1:
        raise RuntimeError("missing/duplicate .maps BTF DATASEC")
    _, _, size, count, flag, entries, position = sections[0]
    row, raw = elf.sections[".maps"]
    if row[1] != 1 or flag or size not in (0, len(raw)) or not raw or any(raw):
        raise RuntimeError("unsupported native map section size/content")
    objects = {}
    for name, info, other, section, offset, size in elf.symbols:
        if section != elf.indices[".maps"] or info & 15 == 3:
            continue
        if info not in (1, 0x11) or other != 0 or not name or name in objects:
            raise RuntimeError("duplicate/unsupported native map symbol")
        objects[name] = (offset, size)
    maps, offsets, vars_seen = {}, set(), set()
    cursor = 0
    for i in sorted(range(count), key=lambda i: entries[i*3+1]):
        ref, offset, size = entries[i*3:i*3+3]
        node = btf.resolve(ref)
        if node[0] != 14 or node[5][0] not in (0, 1) or ref in vars_seen:
            raise RuntimeError("invalid/duplicate native BTF VAR")
        vars_seen.add(ref)
        name = node[1]
        if not name or name in maps or objects.get(name) != (offset, size):
            raise RuntimeError(f"native VAR/symbol mismatch or duplicate: {name}")
        definition, struct_size = btf.map_definition(node[2])
        if offset != cursor or offset % 8 or size != struct_size or size > len(raw) - offset:
            raise RuntimeError("native map bounds/coverage mismatch")
        cursor += size
        maps[name] = definition
        offsets.add(position + 12 + i * 12 + 4)
    if cursor != len(raw) or set(maps) != set(objects):
        raise RuntimeError("native map incomplete coverage/extra symbol")
    # Every native VAR has exactly one DATASEC owner, including VARs omitted
    # from the selected DATASEC but still named by a native ELF symbol.
    for ref, node in enumerate(btf.types[1:], 1):
        if node[0] == 14 and node[1] in objects and ref not in vars_seen:
            raise RuntimeError("extra native BTF VAR")
        if node[0] == 15 and node[1] != ".maps" and any(x in vars_seen for x in node[5][::3]):
            raise RuntimeError("native VAR appears in multiple DATASECs")
    # Relocations from *any* section can overwrite native type metadata.
    # Admit only DATASEC VAR-offset destinations and the two emitted forms:
    # a zero-base section symbol or an exact OBJECT symbol plus its addend.
    destinations = {}
    for node in btf.types[1:]:
        if node[0] != 15:
            continue
        section_name = node[1]
        if section_name not in elf.sections:
            raise RuntimeError("BTF relocation DATASEC missing ELF section")
        section_row, section_data = elf.sections[section_name]
        if section_row[1] != 1 or node[2] not in (0, len(section_data)):
            raise RuntimeError("unsupported BTF relocation DATASEC size/type")
        for i in range(node[3]):
            ref, addend, size = node[5][i*3:i*3+3]
            var = btf.resolve(ref)
            if var[0] != 14:
                raise RuntimeError("BTF relocation DATASEC entry is not VAR")
            matches = [symbol for symbol in elf.symbols
                       if symbol[0] == var[1] and symbol[1] in (1, 0x11)
                       and symbol[2] == 0 and symbol[3] == elf.indices[section_name]]
            if len(matches) != 1 or matches[0][5] != size:
                raise RuntimeError("BTF relocation VAR/symbol mismatch")
            actual = matches[0]
            if actual[4] + size > len(section_data):
                raise RuntimeError("BTF relocation VAR out of bounds")
            destinations[node[6] + 16 + i * 12] = (actual, addend)
    found = set()
    for name, (rel, data) in elf.sections.items():
        if rel[1] not in (4, 9) or rel[7] != elf.indices[".BTF"]:
            continue
        if name != ".rel.BTF" or rel[1] != 9 or rel[9] != 16 or len(data) % 16 or rel[6] != elf.indices[".symtab"]:
            raise RuntimeError("unsupported BTF relocation section")
        seen = set()
        for pos in range(0, len(data), 16):
            offset, info = struct.unpack_from("<QQ", data, pos)
            if offset in seen or offset + 4 > len(elf.sections[".BTF"][1]) or info >> 32 >= len(elf.symbols):
                raise RuntimeError("invalid/duplicate BTF relocation")
            seen.add(offset)
            symbol = elf.symbols[info >> 32]
            if offset not in destinations or info & 0xffffffff != 4:
                raise RuntimeError("unsupported BTF relocation destination/kind")
            actual, addend = destinations[offset]
            section_symbol = symbol[1] == 3 and symbol[2] == 0 and symbol[4:] == (0, 0)
            if (symbol[3] != actual[3] or not (section_symbol or symbol == actual)
                    or addend + symbol[4] != actual[4]):
                raise RuntimeError("unsupported BTF relocation symbol/addend")
            native = symbol[3] == elf.indices[".maps"]
            if offset in offsets or native:
                if offset not in offsets or symbol[1] != 3 or symbol[2] != 0 or not native or symbol[4] != 0 or symbol[5] != 0 or info & 0xffffffff != 4:
                    raise RuntimeError("unsupported native BTF relocation")
                found.add(offset)
    if found != offsets:
        raise RuntimeError("missing native BTF relocation")
    return maps


def decode_map_definitions(records, section, data):
    objects = sorted(
        (offset, size, name)
        for offset, size, kind, _, _, symbol_section, name in records
        if kind == "OBJECT" and symbol_section == str(section)
    )
    maps = {}
    cursor = 0
    for offset, size, name in objects:
        if name in maps:
            raise RuntimeError(f"duplicate map symbol name {name}")
        if size != MAP_DEFINITION_SIZE:
            raise RuntimeError(f"{name} map definition size is {size}, expected 28")
        if offset % 4:
            raise RuntimeError(f"misaligned map definition for {name}: offset {offset}")
        if offset != cursor:
            raise RuntimeError(
                f"non-contiguous map definitions before {name}: offset {offset}, expected {cursor}"
            )
        if offset + size > len(data):
            raise RuntimeError(f"truncated map definition for {name}")
        maps[name] = dict(zip(MAP_FIELDS, struct.unpack_from("<7I", data, offset)))
        cursor += size
    if cursor != len(data):
        raise RuntimeError(f"maps section has {len(data) - cursor} trailing bytes")
    return maps


REQUIRED_GLOBAL_HELPERS = frozenset({
    "p11_link_current_identity", "p11_link_emit_fork", "p11_link_fork_allowed",
})
REQUIRED_GLOBAL_OWNER_HELPERS = frozenset({"p11_owner_reserve", "p11_owner_refund"})
REQUIRED_GLOBAL_SCALAR_HELPERS = frozenset({"p11_read_ia32_arg"})
REQUIRED_LOCAL_OWNER_HELPERS = frozenset({
    "p11_owner_cleanup", "p11_owner_start_get",
    "p11_owner_start_insert", "p11_owner_start_remove", "p11_owner_discovery_get",
    "p11_owner_discovery_insert", "p11_owner_discovery_remove",
})
REQUIRED_LOCAL_ROOT_HELPERS = frozenset({
    "p11_root_propagate_thread", "p11_root_current_tag", "p11_root_current_exit",
})
OPTIONAL_LOCAL_OWNER_HELPERS = frozenset({"p11_owner_healthy"})
EXACT_PROGRAM_SECTIONS = {
    "task_newtask": "tp_btf/task_newtask",
    "sched_process_exec": "raw_tp/sched_process_exec",
    "sched_process_exit": "raw_tp/sched_process_exit",
}

DIAGNOSTIC_GLOBAL_HELPERS = frozenset({"p11_decode_params", "p11_walk_template"})


def validate_private_helpers(elf, prefix, required, optional, label,
                             global_helpers=frozenset(), required_map=None, inventory=False):
    """Verify exact native helper linkage, metadata, calls and map boundaries.

    Pointer-taking owner APIs stay LOCAL/STATIC; only the supplied scalar owner
    boundaries may be GLOBAL. Healthy alone may disappear after inlining. Do
    not retain dummy bodies or admit arbitrary clones/attachment targets.
    """
    owners = [s for s in elf.symbols if s[0].startswith(prefix)]
    production = any(s[0] in EXACT_PROGRAM_SECTIONS or s[0] in REQUIRED_GLOBAL_HELPERS
                     for s in elf.symbols)
    if not owners and not production:
        return
    allowed = required | optional | global_helpers
    names = [s[0] for s in owners]
    if len(names) != len(set(names)):
        raise RuntimeError(f"duplicate {label} helper symbol")
    if set(names) - allowed:
        raise RuntimeError(f"unexpected {label} helper or clone")
    if missing := required - set(names):
        raise RuntimeError(f"missing required {label} helpers: {sorted(missing)}")
    if missing := global_helpers - set(names):
        raise RuntimeError(f"missing required global {label} helpers: {sorted(missing)}")
    for name, info, other, section, value, size in owners:
        expected = 0x12 if name in global_helpers else 2
        linkage = "GLOBAL" if name in global_helpers else "LOCAL"
        if info != expected or other != 0 or section != elf.indices.get(".text"):
            raise RuntimeError(f"{label} helper {name} must be {linkage} DEFAULT FUNC in .text")
        if not size or value % 8 or size % 8 or value + size > len(elf.sections[".text"][1]):
            raise RuntimeError(f"{label} helper {name} has invalid/empty body")
    for name, location in EXACT_PROGRAM_SECTIONS.items():
        if inventory and name == "task_newtask":
            continue
        matches = [s for s in elf.symbols if s[0] == name]
        if (len(matches) != 1 or matches[0][1] != 0x12 or matches[0][2] != 0
                or matches[0][3] != elf.indices.get(location)):
            raise RuntimeError(f"missing/unclassified required program {name} in {location}")
    if ".BTF" not in elf.sections or ".BTF.ext" not in elf.sections:
        raise RuntimeError(f"{label} helpers require BTF FUNC and function info")
    btf = Btf(elf.sections[".BTF"][1])
    functions = {}
    for ident, node in enumerate(btf.types[1:], 1):
        if node[0] == 12 and node[1].startswith(prefix):
            if node[1] in functions:
                raise RuntimeError(f"duplicate {label} BTF FUNC")
            functions[node[1]] = ident
    if set(functions) != set(names):
        raise RuntimeError(f"{label} helper ELF/BTF FUNC association mismatch")
    for name, ident in functions.items():
        node = btf.types[ident]
        expected_linkage = 1 if name in global_helpers else 0
        if node[3] != expected_linkage:
            linkage = "GLOBAL" if name in global_helpers else "STATIC"
            raise RuntimeError(f"{label} helper {name} requires {linkage} BTF linkage")
        if not node[2] or btf.types[node[2]][0] != 13:
            raise RuntimeError(f"{label} helper {name} requires FUNC_PROTO")
        if name in global_helpers:
            proto = btf.types[node[2]]
            scalar = btf.resolve(proto[2])
            if proto[3] or proto[5] or scalar[0] != 1 or scalar[2] != 4:
                raise RuntimeError(
                    f"{label} helper {name} requires a no-argument scalar FUNC_PROTO"
                )
    ext = elf.sections[".BTF.ext"][1]
    magic, version, flags, hlen, off, length = struct.unpack(
        "<HBBIII", checked_slice(ext, 0, 16, "BTF.ext function info header"))
    if (magic, version, flags, hlen) != (0xeb9f, 1, 0, 32):
        raise RuntimeError("unsupported BTF.ext function info header")
    raw = checked_slice(ext, hlen + off, length, "BTF.ext function info")
    stride, = struct.unpack("<I", checked_slice(raw, 0, 4, "function info stride"))
    if stride != 8:
        raise RuntimeError("unsupported function info stride")
    info_relocs = {}
    for row, relocation_data in elf.sections.values():
        if row[1] != 9 or row[7] != elf.indices[".BTF.ext"]:
            continue
        if row[9] != 16 or len(relocation_data) % 16:
            raise RuntimeError("invalid function info relocations")
        for at in range(0, len(relocation_data), 16):
            address, info = struct.unpack_from("<QQ", relocation_data, at)
            if address in info_relocs or info >> 32 >= len(elf.symbols):
                raise RuntimeError("invalid/duplicate function info relocation")
            info_relocs[address] = (info & 0xffffffff, elf.symbols[info >> 32])
    pos, found = 4, {}
    by_name = {s[0]: s for s in owners}
    while pos < len(raw):
        sec_name, count = struct.unpack("<II", checked_slice(raw, pos, 8, "function info section"))
        section = string_at(btf.strings, sec_name)
        if section not in elf.indices:
            raise RuntimeError("function info section missing")
        pos += 8
        for _ in range(count):
            record_offset = hlen + off + pos
            address, ident = struct.unpack("<II", checked_slice(raw, pos, stride, "function info record"))
            pos += stride
            if not 0 < ident < len(btf.types) or btf.types[ident][0] != 12:
                raise RuntimeError("function info must reference BTF FUNC")
            name = btf.types[ident][1]
            if name in by_name:
                sym = by_name[name]
                if name in found or elf.indices[section] != sym[3] or address != sym[4]:
                    raise RuntimeError(f"{label} helper {name} function info mismatch/duplicate")
                relocation = info_relocs.get(record_offset)
                if (not relocation or relocation[0] != 4 or relocation[1][1] != 3
                        or relocation[1][3] != sym[3] or relocation[1][4] != 0):
                    raise RuntimeError(f"{label} helper {name} function info relocation mismatch")
                found[name] = ident
    if found != functions:
        raise RuntimeError(f"{label} helper function info missing/mismatched")

    # Resolve actual BPF-to-BPF calls, including section-symbol relocations.
    bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[5] and s[3]}
    relocs = {}
    for row, raw in elf.sections.values():
        if row[1] != 9 or row[7] not in {key[0] for key in bodies}:
            continue
        if row[9] != 16 or len(raw) % 16:
            raise RuntimeError(f"invalid {label} call relocation table")
        for pos in range(0, len(raw), 16):
            address, info = struct.unpack_from("<QQ", raw, pos)
            if info >> 32 >= len(elf.symbols) or (row[7], address) in relocs:
                raise RuntimeError(f"invalid/duplicate {label} call relocation")
            relocs[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])
    sections = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
    edges = {key: set() for key in bodies}
    for key, sym in bodies.items():
        section, start = key
        raw = checked_slice(sections.get(section, b""), start, sym[5], "function body")
        for pos in range(0, len(raw), 8):
            op, reg, _, imm = struct.unpack("<BBhi", checked_slice(raw, pos, 8, "BPF instruction"))
            if op != 0x85 or reg != 0x10:
                continue
            relocation = relocs.get((section, start + pos))
            if relocation:
                kind, target = relocation
                if kind != 10:
                    raise RuntimeError(f"invalid {label} BPF call relocation kind")
                dest = (target[3], target[4] + (imm + 1) * 8)
            else:
                dest = (section, start + pos + (imm + 1) * 8)
            if dest not in bodies:
                raise RuntimeError(f"unresolved BPF call in {label} object")
            edges[key].add(dest)
    reachable, todo = set(), [key for key, sym in bodies.items()
                             if sym[1] >> 4 == 1 and key[0] != elf.indices.get(".text")]
    while todo:
        key = todo.pop()
        if key not in reachable:
            reachable.add(key)
            todo.extend(edges[key])
    for name, _, _, section, start, _ in owners:
        if name in required | global_helpers and (section, start) not in reachable:
            raise RuntimeError(f"{label} helper {name} has no reachable call boundary")
    if required_map and global_helpers:
        map_symbols = [symbol for symbol in elf.symbols if symbol[0] == required_map]
        if (len(map_symbols) != 1 or map_symbols[0][1] not in (1, 0x11)
                or map_symbols[0][2] != 0
                or map_symbols[0][3] != elf.indices.get(".maps")
                or map_symbols[0][5] != 32):
            raise RuntimeError(f"{label} helpers require exact {required_map} map symbol")
        map_symbol = map_symbols[0]
        for name, _, _, section, start, size in owners:
            if name not in global_helpers:
                continue
            body_relocations = []
            for (rel_section, address), (kind, target) in relocs.items():
                if rel_section == section and start <= address < start + size:
                    body_relocations.append((address, kind, target))
            map_relocations = []
            for address, kind, target in body_relocations:
                instruction = checked_slice(sections[section], address, 8, "map relocation instruction")
                imm = struct.unpack_from("<i", instruction, 4)[0]
                direct = target == map_symbol and imm == 0
                section_relative = (target[1:] == (3, 0, map_symbol[3], 0, 0)
                                    and imm == map_symbol[4])
                if kind == 1 and instruction[0] == 0x18 and (direct or section_relative):
                    map_relocations.append((address, kind, target))
            if len(map_relocations) != 1:
                raise RuntimeError(
                    f"{label} helper {name} requires one exact {required_map} relocation"
                )


def validate_owner_helpers(elf, inventory=False):
    exported = (REQUIRED_GLOBAL_OWNER_HELPERS
                if any(symbol[0] == "OWNER_CTL" for symbol in elf.symbols)
                else frozenset())
    required = (REQUIRED_LOCAL_OWNER_HELPERS - {"p11_owner_start_get", "p11_owner_start_insert", "p11_owner_start_remove"}
                if inventory else REQUIRED_LOCAL_OWNER_HELPERS)
    validate_private_helpers(elf, "p11_owner_", required,
                             OPTIONAL_LOCAL_OWNER_HELPERS, "owner", exported, "OWNER_CTL", inventory=inventory)


def validate_ia32_span_paths(graph, entry, guard, rejected, read, updates, exits):
    """Prove guard dominance and sentinel return on every rejected path.

    Both raw-ELF and disassembly callers supply their own decoded CFG and r0
    writes. An omitted update preserves r0; None is an unknown value. This
    deliberately does not infer success from a comparison's mere presence.
    """
    guard_values = set()

    def walk(pending, rejection):
        visited, returned = set(), False
        while pending:
            pc, result, ancestors = pending.pop()
            if pc not in graph or pc in ancestors:
                raise RuntimeError("ia32 reader span path escapes body or cycles")
            if pc == read:
                reason = "rejection reaches user read" if rejection else "read bypasses guard"
                raise RuntimeError("ia32 reader span " + reason)
            if not rejection and pc == guard:
                guard_values.add(result)
                continue
            if (pc, result) in visited:
                continue
            visited.add((pc, result))
            result = updates.get(pc, result)
            if pc in exits:
                if rejection and result != 1 << 32:
                    raise RuntimeError("ia32 reader span rejection must return failure sentinel")
                returned = True
                continue
            if not graph[pc]:
                raise RuntimeError("ia32 reader span path has no return")
            pending.extend((target, result, ancestors | {pc}) for target in graph[pc])
        return returned

    walk([(entry, None, frozenset())], False)
    if not guard_values:
        raise RuntimeError("ia32 reader span guard is unreachable")
    if not walk([(rejected, value, frozenset()) for value in guard_values], True):
        raise RuntimeError("ia32 reader span rejection has no sentinel return")


def validate_ia32_raw_span(insns, read):
    """Decode the reader's raw instruction edges without fixed instruction PCs."""
    guards = [pc for pc, (op, reg, _, _) in enumerate(insns[:read])
              if (op, reg) == (0x2d, 0x13)]
    if len(guards) != 1:
        raise RuntimeError("ia32 reader requires one full-width address span guard")
    graph, updates, exits = {}, {}, set()
    pc = 0
    while pc < len(insns):
        op, reg, offset, imm = insns[pc]
        size = 2 if op == 0x18 else 1
        if size == 2 and (pc + 1 >= len(insns) or insns[pc + 1][0] != 0):
            raise RuntimeError("ia32 reader span has malformed wide immediate")
        if op == 0x95:
            graph[pc] = []
            exits.add(pc)
        elif op == 0x05:
            graph[pc] = [pc + 1 + offset]
        elif op & 7 in (5, 6) and op != 0x85:
            graph[pc] = [pc + 1, pc + 1 + offset]
        else:
            graph[pc] = [pc + size]
        if op == 0x85:
            updates[pc] = None
        elif reg & 15 == 0 and op & 7 in (0, 1, 4, 7):
            if op == 0x18:
                updates[pc] = (imm & 0xffffffff) | ((insns[pc + 1][3] & 0xffffffff) << 32)
            elif op in (0xb4, 0xb7):
                updates[pc] = imm & ((1 << (32 if op == 0xb4 else 64)) - 1)
            else:
                updates[pc] = None
        pc += size
    guard = guards[0]
    validate_ia32_span_paths(graph, 0, guard, guard + 1 + insns[guard][2], read, updates, exits)


def validate_ia32_reader(elf, inventory=False):
    """Verify the scalar-only ia32 user-read boundary and one reachable call."""
    selected = [symbol for symbol in elf.symbols if symbol[0] == "p11_read_ia32_arg"]
    production = any(symbol[0] == "p11_entry" for symbol in elf.symbols)
    if not selected and not production:
        return
    if len(selected) != 1:
        raise RuntimeError("missing/duplicate ia32 scalar reader")
    symbol = selected[0]
    if (symbol[1] != 0x12 or symbol[2] != 0
            or symbol[3] != elf.indices.get(".text")):
        raise RuntimeError("ia32 reader must be GLOBAL DEFAULT FUNC in .text")
    if (not symbol[5] or symbol[4] % 8 or symbol[5] % 8
            or symbol[4] + symbol[5] > len(elf.sections[".text"][1])):
        raise RuntimeError("ia32 reader has invalid/empty body")
    if ".BTF" not in elf.sections or ".BTF.ext" not in elf.sections:
        raise RuntimeError("ia32 reader requires BTF and BTF.ext")
    btf = Btf(elf.sections[".BTF"][1])
    functions = [
        (ident, node) for ident, node in enumerate(btf.types)
        if node and node[:2] == (12, "p11_read_ia32_arg")
    ]
    if len(functions) != 1:
        raise RuntimeError("ia32 reader requires one BTF FUNC")
    func_id, func = functions[0]
    if func[3] != 1:
        raise RuntimeError("ia32 reader requires GLOBAL BTF linkage")
    if not func[2] or btf.types[func[2]][0] != 13:
        raise RuntimeError("ia32 reader requires FUNC_PROTO")
    proto = btf.types[func[2]]
    if proto[3] != 2 or len(proto[5]) != 4:
        raise RuntimeError("ia32 reader requires exactly two scalar arguments")

    def unsigned_int(ref, size):
        node = btf.resolve(ref)
        return (node[0] == 1 and node[2] == size
                and node[5][0] >> 24 == 0 and node[5][0] & 0xffff == size * 8)

    if not unsigned_int(proto[2], 8):
        raise RuntimeError("ia32 reader return must be scalar u64")
    if not unsigned_int(proto[5][1], 8):
        raise RuntimeError("ia32 reader stack-pointer argument must be scalar u64")
    if not unsigned_int(proto[5][3], 4):
        raise RuntimeError("ia32 reader index must be scalar u32")

    ext = elf.sections[".BTF.ext"][1]
    magic, version, flags, hlen, off, length = struct.unpack(
        "<HBBIII", checked_slice(ext, 0, 16, "BTF.ext function info header"))
    if (magic, version, flags, hlen) != (0xeb9f, 1, 0, 32):
        raise RuntimeError("unsupported BTF.ext function info header")
    raw = checked_slice(ext, hlen + off, length, "BTF.ext function info")
    stride, = struct.unpack("<I", checked_slice(raw, 0, 4, "function info stride"))
    if stride != 8:
        raise RuntimeError("unsupported function info stride")
    info_relocs = {}
    for row, relocations in elf.sections.values():
        if row[1] != 9 or row[7] != elf.indices[".BTF.ext"]:
            continue
        for pos in range(0, len(relocations), 16):
            address, info = struct.unpack_from("<QQ", relocations, pos)
            info_relocs[address] = (info & 0xffffffff, elf.symbols[info >> 32])
    pos, records = 4, []
    while pos < len(raw):
        section_name, count = struct.unpack(
            "<II", checked_slice(raw, pos, 8, "function info section"))
        section = string_at(btf.strings, section_name)
        pos += 8
        for _ in range(count):
            record = hlen + off + pos
            address, ident = struct.unpack(
                "<II", checked_slice(raw, pos, stride, "function info record"))
            pos += stride
            if ident == func_id:
                records.append((section, address, info_relocs.get(record)))
    if len(records) != 1:
        raise RuntimeError("ia32 reader BTF.ext function info missing/duplicate")
    section, address, relocation = records[0]
    if (section != ".text" or address != symbol[4] or not relocation
            or relocation[0] != 4 or relocation[1][1] != 3
            or relocation[1][3] != symbol[3] or relocation[1][4] != 0):
        raise RuntimeError("ia32 reader BTF.ext function info relocation mismatch")

    text = elf.sections[".text"][1]
    body = checked_slice(text, symbol[4], symbol[5], "ia32 reader body")
    insns = [struct.unpack_from("<BBhi", body, pos) for pos in range(0, len(body), 8)]
    reads = [i for i, (op, reg, _, imm) in enumerate(insns)
             if (op, reg, imm) == (0x85, 0, 112)]
    if len(reads) != 1:
        raise RuntimeError("ia32 reader requires exactly one user read")
    read = reads[0]
    width = next(
        (imm for op, reg, _, imm in reversed(insns[:read])
         if op in (0xb4, 0xb7) and reg & 15 == 2),
        None,
    )
    if width != 4:
        raise RuntimeError("ia32 reader requires an exact four-byte user read")
    if not any(op in (0x25, 0x26) and imm == 6 for op, _, _, imm in insns[:read]):
        raise RuntimeError("ia32 reader must reject index above six before the read")
    scale = next((index for index, (op, _, _, imm) in enumerate(insns[:read])
                  if op == 0x67 and imm == 2), None)
    return_address = next(
        (index for index, (op, _, _, imm) in enumerate(insns[:read])
         if op == 0x07 and imm == 4 and scale is not None and index > scale),
        None,
    )
    if scale is None or return_address is None:
        raise RuntimeError("ia32 reader requires exact (index + 1) * 4 slot/address semantics")
    normalized = any(op == 0xbc for op, _, _, _ in insns[:read])
    normalized |= any(
        op == 0x67 and imm == 32 and index + 1 < read
        and insns[index + 1][0] == 0x77
        and insns[index + 1][1] == reg and insns[index + 1][3] == 32
        for index, (op, reg, _, imm) in enumerate(insns[:read])
    )
    if not normalized:
        raise RuntimeError("ia32 reader must normalize the stack pointer to low 32 bits")
    span_limit = any(
        op == 0x18 and imm == -4 and index + 1 < read
        and insns[index + 1][0] == 0 and insns[index + 1][3] == 0
        for index, (op, _, _, imm) in enumerate(insns[:read])
    )
    span_check = any(op in (0x2d, 0x2e) for op, _, _, _ in insns[:read])
    if not span_limit or not span_check:
        raise RuntimeError("ia32 reader must prove the complete four-byte address span")
    validate_ia32_raw_span(insns, read)
    sentinel_words = [
        insns[index + 1][3]
        for index, (op, _, _, imm) in enumerate(insns)
        if op == 0x18 and imm == 0 and index + 1 < len(insns)
        and insns[index + 1][0] == 0 and insns[index + 1][3] != 0
    ]
    sentinel = bool(sentinel_words) and all(high == 1 for high in sentinel_words)
    sentinel |= any(
        op == 0x67 and imm == 32
        and any(previous[0] == 0xb7 and previous[3] == 1 for previous in insns[:index])
        for index, (op, _, _, imm) in enumerate(insns)
    )
    if not sentinel:
        raise RuntimeError("ia32 reader requires the exact 1<<32 failure sentinel")
    if not any(op == 0x61 for op, _, _, _ in insns[read + 1:]):
        raise RuntimeError("ia32 reader must zero-extend the four-byte result")

    bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[5] and s[3]}
    target = (symbol[3], symbol[4])
    call_relocations = {}
    for row, relocations in elf.sections.values():
        if row[1] != 9 or row[7] not in {key[0] for key in bodies}:
            continue
        for pos in range(0, len(relocations), 16):
            address, info = struct.unpack_from("<QQ", relocations, pos)
            call_relocations[row[7], address] = (
                info & 0xffffffff, elf.symbols[info >> 32]
            )
    edges = {key: set() for key in bodies}
    for (section_index, start), caller in bodies.items():
        section = next(raw for name, (_, raw) in elf.sections.items()
                       if elf.indices[name] == section_index)
        code = checked_slice(section, start, caller[5], "ia32 reader caller")
        for pos in range(0, len(code), 8):
            op, reg, _, imm = struct.unpack_from("<BBhi", code, pos)
            if (op, reg) == (0x85, 0x10):
                relocation = call_relocations.get((section_index, start + pos))
                if relocation and relocation[0] == 10:
                    destination = (
                        relocation[1][3],
                        relocation[1][4] + (imm + 1) * 8,
                    )
                elif relocation:
                    destination = None
                else:
                    destination = (section_index, start + pos + (imm + 1) * 8)
                if destination in bodies:
                    edges[section_index, start].add(destination)
    root_name = ("function_list_entry" if inventory else "p11_entry_ia32"
                 if any(candidate[0] == "p11_entry_ia32" for candidate in elf.symbols)
                 else "p11_entry")
    roots = [candidate for candidate in elf.symbols if candidate[0] == root_name]
    if len(roots) != 1:
        raise RuntimeError(f"ia32 reader requires exact {root_name} entry root")
    if (roots[0][1] != 0x12 or roots[0][2] != 0
            or roots[0][3] != elf.indices.get("uprobe")):
        raise RuntimeError(f"ia32 reader requires {root_name} GLOBAL DEFAULT uprobe root")
    root = (roots[0][3], roots[0][4])
    reachable, todo = set(), [root]
    while todo:
        candidate = todo.pop()
        if candidate not in reachable:
            reachable.add(candidate)
            todo.extend(edges.get(candidate, ()))
    if target not in reachable:
        raise RuntimeError(f"ia32 reader requires {root_name} entry-root reachable call")

def validate_root_helpers(elf):
    validate_private_helpers(elf, "p11_root_", REQUIRED_LOCAL_ROOT_HELPERS,
                             frozenset(), "root")

def validate_inventory_usage_transition(elf, root, relocations):
    """Pin the supported load/fast-path/CAS lowering, not a general interpreter."""
    body = checked_slice(elf.sections["uprobe"][1], root[4], root[5], "usage root")
    instructions = [struct.unpack_from("<BBhi", body, i) for i in range(0, len(body), 8)]
    atomic = [i for i, (op, _, _, imm) in enumerate(instructions) if op == 0xdb and imm == 0xf1]
    if len(atomic) != 1 or atomic[0] < 10:
        raise RuntimeError("usage requires one conditional atomic compare-exchange")
    at = atomic[0]
    usage = relocations.get((root[3], root[4] + (at - 10) * 8))
    if (not usage or usage[0] != 1 or usage[1][0] != "USAGE"
            or instructions[at - 10][0] != 0x18
            or instructions[at - 8] != (0x85, 0, 0, 1)
            or instructions[at - 7][0:2] != (0x15, 0)
            or instructions[at - 7][3] != 0):
        raise RuntimeError("usage CAS requires the exact checked USAGE lookup")
    load, positive, zero = instructions[at - 6:at - 3]
    register = load[1] & 15
    # R0 must retain the lookup pointer until the later pointer copy.
    if (not 1 <= register <= 9 or load != (0x79, register, 0, 0)
            or positive[0:2] != (0x15, register)
            or positive[3] != 1 or zero[0:2] != (0x55, register) or zero[3] != 0
            or at - 4 + 1 + zero[2] <= at):
        raise RuntimeError("usage needs aligned u64 load and exact one/zero guards")
    replacement, pointer, expected = instructions[at - 3:at]
    replacement_register, pointer_register = replacement[1], pointer[1]
    # Replacement must preserve R0; its pointer copy must preserve replacement.
    # Neither operand may alias R0, which is then overwritten with expected zero.
    if (replacement != (0xb7, replacement_register, 0, 1)
            or not 1 <= replacement_register <= 9
            or pointer != (0xbf, pointer_register, 0, 0)
            or not 1 <= pointer_register <= 9
            or replacement_register == pointer_register
            or expected != (0xb7, 0, 0, 0)
            or instructions[at] != (0xdb, replacement_register << 4 | pointer_register, 0, 0xf1)):
        raise RuntimeError("usage atomic operation must compare zero and write one to the same cell")
    # The already-positive path must reach exit without any map write, helper,
    # or CAS. Only a zero return and forward jumps may remain in this lowering.
    cursor, visited = at - 5 + 1 + positive[2], set()
    while 0 <= cursor < len(instructions) and cursor not in visited:
        visited.add(cursor)
        instruction = instructions[cursor]
        if instruction == (0x95, 0, 0, 0):
            return
        if instruction == (0xb7, 0, 0, 0):
            cursor += 1
        elif instruction[0:2] == (0x05, 0) and instruction[2] > 0 and instruction[3] == 0:
            cursor += instruction[2] + 1
        else:
            break
    raise RuntimeError("usage already-one path must return without a write or atomic operation")


def validate_inventory_scope_prefix(elf, root, relocations):
    """Prove caller refusal for the supported emitted Option<ScopeAuth> ABI.

    This is a fail-closed lowering contract, not a general BPF interpreter or
    a proof of scope_auth's PID/cgroup/config semantics. The first six
    instructions must call the actual local scope_auth with a stack result,
    then test that result's discriminator. Refusal may only return zero.
    """
    body = checked_slice(elf.sections["uprobe"][1], root[4], root[5], "usage root")
    if len(body) % 8 or len(body) < 6 * 8:
        raise RuntimeError("inventory authorization requires an aligned entry prefix")
    instructions = [struct.unpack_from("<BBhi", body, i) for i in range(0, len(body), 8)]
    # No branch, payload access or map operation can precede authorization.
    # R6 preserves the original probe context; R1 is the 32-byte sret frame.
    if instructions[:3] != [(0xbf, 0x16, 0, 0), (0xbf, 0xa1, 0, 0), (0x07, 1, 0, -32)]:
        raise RuntimeError("inventory authorization requires the checked stack-result prefix")
    call = instructions[3]
    relocation = relocations.get((root[3], root[4] + 3 * 8))
    auth = [s for s in elf.symbols if s[0].endswith("10scope_auth")]
    if (len(auth) != 1 or auth[0][1:3] != (2, 0)
            or auth[0][3] != elf.indices.get(".text") or not auth[0][5]
            or call[:3] != (0x85, 0x10, 0)
            or not relocation or relocation[0] != 10
            or (relocation[1][3], relocation[1][4] + (call[3] + 1) * 8) != auth[0][3:5]):
        raise RuntimeError("inventory authorization must call the actual local scope_auth")
    guard = instructions[5]
    if (instructions[4] != (0x79, 0xa1, -32, 0)
            or guard[:2] != (0x15, 1) or guard[3] != 0 or guard[2] <= 0):
        raise RuntimeError("inventory authorization must reject the returned zero discriminator")
    # The complete false path has no helper, map access, write, or alternative
    # successor. Do not accept a branch merely because it targets some exit.
    cursor, zeroed, visited = 6 + guard[2], False, set()
    while 0 <= cursor < len(instructions) and cursor not in visited:
        visited.add(cursor)
        instruction = instructions[cursor]
        if instruction == (0x95, 0, 0, 0) and zeroed:
            return
        if instruction == (0xb7, 0, 0, 0):
            zeroed = True
            cursor += 1
        elif instruction[:2] == (0x05, 0) and instruction[2] > 0 and instruction[3] == 0:
            cursor += 1 + instruction[2]
        else:
            break
    raise RuntimeError("inventory authorization refusal must return without collection")


def validate_inventory_entry_reachability(elf):
    """Bounded call graph plus entry authorization/usage lowering contracts.

    Ordinary usage roots may only look up scope/config/use maps and call the
    four scalar/scope helpers below. Discovery's legitimate user reads are
    checked separately and are not reachable from these roots. The caller
    authorization proof is limited to validate_inventory_scope_prefix's ABI.
    """
    bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[5] and s[3]}
    sections = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
    relocations = {}
    for row, raw in elf.sections.values():
        if row[1] == 9 and row[7] in {key[0] for key in bodies}:
            for offset in range(0, len(raw), 16):
                address, info = struct.unpack_from("<QQ", raw, offset)
                relocations[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])
    allowed_maps = {"CONFIG", "PID_FILTER", "CGROUP_FILTER", "OWNER_CTL", "EVIDENCE",
                    "USAGE", "USAGE_CONFIG", "USAGE_EVIDENCE"}
    reports = {}
    for name in ("p11_usage_entry_lp64", "p11_usage_entry_ia32"):
        roots = [s for s in elf.symbols if s[0] == name]
        if len(roots) != 1 or roots[0][1:3] != (0x12, 0) or roots[0][3] != elf.indices.get("uprobe"):
            raise RuntimeError(f"inventory requires exact GLOBAL DEFAULT uprobe {name}")
        validate_inventory_scope_prefix(elf, roots[0], relocations)
        validate_inventory_usage_transition(elf, roots[0], relocations)
        todo, seen = [(roots[0][3], roots[0][4])], set()
        helpers, maps, compare_exchanges = set(), set(), 0
        while todo:
            key = todo.pop()
            if key in seen:
                continue
            if key not in bodies:
                raise RuntimeError("inventory entry has unresolved function call")
            seen.add(key)
            symbol = bodies[key]
            body = checked_slice(sections[key[0]], key[1], symbol[5], "inventory entry function")
            for offset in range(0, len(body), 8):
                op, registers, _, immediate = struct.unpack_from("<BBhi", body, offset)
                relocation = relocations.get((key[0], key[1] + offset))
                if op == 0x18 and relocation:
                    target = relocation[1]
                    map_name = target[0]
                    if target[1] & 15 == 3:  # Native LOCAL map: section plus LDDW addend.
                        high = struct.unpack_from("<I", body, offset + 12)[0]
                        address = target[4] + (immediate & 0xffffffff) + (high << 32)
                        matches = [candidate[0] for candidate in elf.symbols
                                   if candidate[1] & 15 == 1 and candidate[3] == target[3]
                                   and candidate[4] == address]
                        map_name = matches[0] if len(matches) == 1 else ""
                    if relocation[0] != 1 or map_name not in allowed_maps:
                        raise RuntimeError(f"inventory entry reaches forbidden map/global {map_name!r}")
                    # Authorization executes before its result can be checked.
                    # It and its callees may not collect Inventory state. The
                    # supported lowering keeps usage work in the entry root.
                    if key != (roots[0][3], roots[0][4]) and map_name.startswith("USAGE"):
                        raise RuntimeError("inventory authorization callee reaches usage state")
                    maps.add(map_name)
                if op == 0x85:
                    if registers == 0:
                        if immediate not in {1, 14, 37, 174}:
                            raise RuntimeError(f"inventory entry reaches forbidden helper {immediate}")
                        helpers.add(immediate)
                    elif registers == 0x10:
                        if relocation and relocation[0] == 10:
                            todo.append((relocation[1][3], relocation[1][4] + (immediate + 1) * 8))
                        elif relocation:
                            raise RuntimeError("inventory entry has unknown call relocation")
                        else:
                            todo.append((key[0], key[1] + offset + (immediate + 1) * 8))
                    else:
                        raise RuntimeError("inventory entry has unsupported call kind")
                if op == 0xdb and immediate == 0xf1:
                    compare_exchanges += 1
        required_maps = {"CONFIG", "OWNER_CTL", "USAGE", "USAGE_CONFIG", "USAGE_EVIDENCE"}
        if not required_maps <= maps or not {1, 14, 174} <= helpers:
            raise RuntimeError(f"inventory entry missing scope/config/use dependencies: {name}")
        if not compare_exchanges:
            raise RuntimeError(f"inventory entry missing atomic compare-exchange: {name}")
        reports[name] = {"functions": len(seen), "maps": sorted(maps),
                         "helpers": sorted(helpers), "compare_exchanges": compare_exchanges}
    return reports


def validate_inventory_caller_entry_reachability(elf):
    """Separate caller-flavor graph; never broaden the global-only allowlist.

    This checks exact native linkage and reachable map/helper boundaries. The
    caller object integration test additionally executes bounded ordinary-entry
    bytecode cases with explicit scope and native-identity boundary results; it
    does not treat graph reachability alone as an authorization proof.
    """
    bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[5] and s[3]}
    sections = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
    relocations = {}
    for row, raw in elf.sections.values():
        if row[1] == 9 and row[7] in {key[0] for key in bodies}:
            for offset in range(0, len(raw), 16):
                address, info = struct.unpack_from("<QQ", raw, offset)
                relocations[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])
    identity = [s for s in elf.symbols if s[0] == "p11_link_current_identity"]
    auth = [s for s in elf.symbols if s[0].endswith("10scope_auth")]
    if (len(identity) != 1 or identity[0][1:3] != (0x12, 0)
            or identity[0][3] != elf.indices.get(".text") or not identity[0][5]
            or len(auth) != 1 or auth[0][1:3] != (2, 0)
            or auth[0][3] != elf.indices.get(".text") or not auth[0][5]):
        raise RuntimeError("caller inventory requires exact native identity and local scope boundaries")
    btf = Btf(elf.sections[".BTF"][1])
    functions = [node for node in btf.types[1:]
                 if node[0] == 12 and node[1] == "p11_link_current_identity"]
    if len(functions) != 1 or functions[0][3] != 1:
        raise RuntimeError("caller identity requires one GLOBAL BTF function")
    proto = btf.types[functions[0][2]]
    if proto[0] != 13 or proto[3] != 1 or len(proto[5]) != 2:
        raise RuntimeError("caller identity requires one exact output pointer")
    result, pointer = btf.resolve(proto[2]), btf.resolve(proto[5][1])
    if (result[0] != 1 or result[2] != 4 or pointer[0] != 2
            or btf.resolve(pointer[2])[0:3] != (4, "image_identity", 16)):
        raise RuntimeError("caller identity native ABI differs")
    scope_maps = {"CONFIG", "PID_FILTER", "CGROUP_FILTER", "OWNER_CTL", "EVIDENCE"}
    caller_maps = {"USAGE", "USAGE_CONFIG", "USAGE_EVIDENCE", "ENDPOINT_OBJECT",
                   "CALLER_USE", "CALLER_EVIDENCE", "TASK_COOKIE", "COOKIE_CTL"}

    def walk(start, allowed_maps, allowed_helpers):
        todo, seen, maps, helpers, atomic = [start], set(), set(), set(), 0
        while todo:
            key = todo.pop()
            if key in seen:
                continue
            if key not in bodies:
                raise RuntimeError("caller inventory has an unresolved call")
            seen.add(key)
            symbol = bodies[key]
            body = checked_slice(sections[key[0]], key[1], symbol[5], "caller entry function")
            for offset in range(0, len(body), 8):
                op, registers, _, immediate = struct.unpack_from("<BBhi", body, offset)
                relocation = relocations.get((key[0], key[1] + offset))
                if op == 0x18 and relocation:
                    target = relocation[1]
                    map_name = target[0]
                    if target[1] & 15 == 3:
                        high = struct.unpack_from("<I", body, offset + 12)[0]
                        address = target[4] + (immediate & 0xffffffff) + (high << 32)
                        matches = [candidate[0] for candidate in elf.symbols
                                   if candidate[1] & 15 == 1 and candidate[3] == target[3]
                                   and candidate[4] == address]
                        map_name = matches[0] if len(matches) == 1 else ""
                    if relocation[0] != 1 or map_name not in allowed_maps:
                        raise RuntimeError(f"caller inventory reaches forbidden map/global {map_name!r}")
                    maps.add(map_name)
                if op == 0x85:
                    if registers == 0:
                        if immediate not in allowed_helpers:
                            raise RuntimeError(f"caller inventory reaches forbidden helper {immediate}")
                        helpers.add(immediate)
                    elif registers == 0x10:
                        if relocation and relocation[0] == 10:
                            todo.append((relocation[1][3], relocation[1][4] + (immediate + 1) * 8))
                        elif relocation:
                            raise RuntimeError("caller inventory has unknown call relocation")
                        else:
                            todo.append((key[0], key[1] + offset + (immediate + 1) * 8))
                    else:
                        raise RuntimeError("caller inventory has unsupported call kind")
                if op == 0xdb and immediate == 0xf1:
                    atomic += 1
        return seen, maps, helpers, atomic

    # Scope must not allocate an identity or inspect/mutate inventory evidence.
    walk(auth[0][3:5], scope_maps, {1, 14, 37})
    identity_seen, identity_maps, identity_helpers, _ = walk(
        identity[0][3:5], {"TASK_COOKIE", "COOKIE_CTL"}, {1, 156, 158})
    if (identity_maps != {"TASK_COOKIE", "COOKIE_CTL"}
            or identity_helpers != {1, 156, 158} or len(identity_seen) != 1):
        raise RuntimeError("caller native identity requires the single exact core domain")
    reports = {}
    for name in ("p11_usage_entry_lp64", "p11_usage_entry_ia32"):
        roots = [s for s in elf.symbols if s[0] == name]
        if len(roots) != 1 or roots[0][1:3] != (0x12, 0) or roots[0][3] != elf.indices.get("uprobe"):
            raise RuntimeError(f"caller inventory requires exact GLOBAL DEFAULT uprobe {name}")
        seen, maps, helpers, atomic = walk(
            roots[0][3:5], scope_maps | caller_maps, {1, 2, 5, 14, 37, 156, 158, 174})
        if (not {identity[0][3:5], auth[0][3:5]} <= seen or not caller_maps <= maps
                or not {1, 2, 5, 14, 156, 158, 174} <= helpers or not atomic):
            raise RuntimeError(f"caller inventory missing real scope/use/identity/pair dependencies: {name}")
        reports[name] = {"functions": len(seen), "maps": sorted(maps),
                         "helpers": sorted(helpers), "compare_exchanges": atomic}
    return reports


def inspect(path, allowed_text_globals=frozenset(), *, variant="default"):
    if variant not in FROZEN_INVENTORY:
        raise RuntimeError(f"unknown object variant {variant!r}")
    inventory = variant.startswith("inventory")
    callers = variant.startswith("inventory-callers")
    elf = Elf(Path(path).read_bytes())
    records, sections = elf_records(path)
    if records != elf.records or {name: index for name, index in sections.items() if index} != elf.indices:
        raise RuntimeError("LLVM/raw ELF metadata mismatch")
    if "maps" not in sections and ".maps" not in sections:
        raise RuntimeError(f"{path} has no maps section")
    maps = {}
    if "maps" in sections:
        if elf.sections["maps"][0][1] != 1:
            raise RuntimeError("unsupported legacy maps section type")
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "maps.bin"
            subprocess.run(["llvm-objcopy", "--dump-section", f"maps={raw}", path], check=True)
            data = raw.read_bytes()
        if data != elf.sections["maps"][1]:
            raise RuntimeError("LLVM/raw legacy section mismatch")
        maps = decode_map_definitions(records, sections["maps"], data)
    if ".maps" in sections:
        native = decode_btf_maps(elf)
        if maps.keys() & native.keys():
            raise RuntimeError("cross-section duplicate map names")
        maps.update(native)
    elif ".BTF" in sections:
        btf = Btf(elf.sections[".BTF"][1])
        if any(node[0] == 15 and node[1] == ".maps" for node in btf.types[1:]):
            raise RuntimeError("native BTF DATASEC missing ELF .maps section")
    validate_ia32_reader(elf, inventory)
    validate_owner_helpers(elf, inventory)
    if not inventory:
        validate_root_helpers(elf)
    elif callers:
        validate_inventory_caller_entry_reachability(elf)
    else:
        validate_inventory_entry_reachability(elf)
    image_helpers = (frozenset({"p11_link_current_identity"}) if callers else
                     frozenset() if inventory else REQUIRED_GLOBAL_HELPERS)
    return maps, classify(records, sections, allowed_text_globals | image_helpers
                          | REQUIRED_GLOBAL_OWNER_HELPERS | REQUIRED_GLOBAL_SCALAR_HELPERS,
                          inventory=inventory), {
        record[-1] for record in records
    }


def classify(records, sections, allowed_text_globals=frozenset(), *, inventory=False):
    """Return the object's BPF program names, refusing what cannot be classified.

    A program emitted under an attach type the whitelist does not name (`raw_tp/`,
    `kprobe/`, `fentry/`, `lsm/`, `uprobe.s`, ...) lands in an unlisted section.
    Silently skipping it would leave the frozen program count intact while the
    object gained a program, so an unclassified *defined* global function is an
    error. Symbols with a non-numeric section index (`UND`, `ABS` — a kfunc extern
    appears this way) are neither counted nor refused, as they were before.

    Compiler mem* helpers are admitted only as unique GLOBAL HIDDEN functions
    in .text; they cannot carry an unclassified program through another section.
    """
    by_index = {index: name for name, index in sections.items()}
    programs, helpers, seen = set(), set(), set()
    for _, _, kind, bind, visibility, section, name in records:
        if kind != "FUNC" or not section.isdigit():
            continue
        location = by_index.get(int(section), section)
        if bind == "LOCAL":
            if location != ".text":
                raise RuntimeError(f"unclassified local function {name} in {location}")
            continue
        if name in seen:
            raise RuntimeError(f"duplicate global function {name}")
        seen.add(name)
        if (visibility == "HIDDEN" and bind == "GLOBAL" and location == ".text"
                and name in {"memcpy", "memset", "memmove", "memcmp", "bcmp"}):
            continue
        exact = EXACT_PROGRAM_SECTIONS.get(name)
        if bind != "GLOBAL" or visibility != "DEFAULT":
            raise RuntimeError(f"unclassified global function {name} in {location}")
        if name in (REQUIRED_GLOBAL_HELPERS | REQUIRED_GLOBAL_OWNER_HELPERS
                    | REQUIRED_GLOBAL_SCALAR_HELPERS | DIAGNOSTIC_GLOBAL_HELPERS):
            if name in allowed_text_globals and location == ".text":
                helpers.add(name)
                continue
        elif exact:
            if location == exact:
                programs.add(name)
                continue
        elif location in {"uprobe", "uretprobe"} or location.startswith("tracepoint/"):
            programs.add(name)
            continue
        raise RuntimeError(f"global functions in unclassified sections: {name} in {location}")
    # Generic fixtures need no production helpers. A production hook or helper
    # selects the complete exact export contract, independent of program counts.
    if not inventory and (programs & EXACT_PROGRAM_SECTIONS.keys() or helpers & REQUIRED_GLOBAL_HELPERS):
        missing = REQUIRED_GLOBAL_HELPERS - helpers
        if missing:
            raise RuntimeError(f"missing required .text helpers: {sorted(missing)}")
    return programs


def definitions(path):
    return inspect(path)[0]


def map_def(map_type, key, value, maximum, flags=0):
    return dict(zip(MAP_FIELDS, (map_type, key, value, maximum, flags, 0, 0)))


SAFE_MAPS = {
    name: map_def(*values)
    for name, values in {
        "ASYNC_FUNCTIONS": (1, 32, 4, 128, 128),
        "CGROUP_FILTER": (8, 4, 4, 1),
        "CONFIG": (2, 4, 8, 2, 128),
        "COUNTERS": (6, 4, 8, 5),
        "DISCOVERY": (27, 0, 0, 65_536),
        "DISCOVERY_STATE": (1, 24, 24, 64),
        # 4 MiB since the F1 repair (was 262144): the default ring must
        # absorb scheduling jitter at unpaced burst rates. Tracks
        # ebpf-common RING_BYTES; change both together.
        "EVENTS": (27, 0, 0, 4_194_304),
        "EVIDENCE": (6, 4, 8, 9),
        "MECH_SHAPE": (1, 8, 4, 1_024, 128),
        "PAUSE_PIDS": (1, 16, 8, 1),
        "PID_FILTER": (1, 4, 8, 1_024, 128),
        "RV_COUNTS": (5, 16, 8, 4_096),
        "DESCRIPTORS": (2, 4, 18, 105, 128),
        "START": (1, 16, 288, 16_384),
        "TASK_COOKIE": (29, 4, 8, 0, 1),
        "COOKIE_CTL": (2, 4, 40, 1),
        "THREAD_OWNER": (29, 4, 544, 0, 1),
        "OWNER_CTL": (2, 4, 56, 1),
        "ROOT_AFFILIATION": (29, 4, 8, 0, 1),
        "ROOT_CTL": (2, 4, 64, 1),
        "STATS": (6, 4, 296, 512),
        "TAIL_CALLS": (3, 4, 4, 2),
    }.items()
}
UNSAFE_MAPS = SAFE_MAPS | {
    "ATTR_BOOL_BITS": map_def(1, 4, 4, 16, 128),
}
SAFE_PROGRAMS = {
    "p11_entry",
    "p11_return",
    "task_newtask",
    "dl_debug_state",
    "function_list_entry",
    "function_list_return",
    "interface_list_entry",
    "interface_list_return",
    "interface_list_worker",
    "interface_entry",
    "interface_return",
    "sched_process_exec",
    "sched_process_exit",
}
UNSAFE_PROGRAMS = SAFE_PROGRAMS | {
    "p11_entry_ia32",
    "p11_entry_template", "p11_entry_template_pair",
    "p11_entry_template_second", "p11_entry_template_types",
}


INVENTORY_MAPS = {name: SAFE_MAPS[name] for name in (
    "CONFIG", "PID_FILTER", "CGROUP_FILTER", "TAIL_CALLS", "EVIDENCE", "COUNTERS",
    "DISCOVERY", "DISCOVERY_STATE", "THREAD_OWNER", "OWNER_CTL",
)} | {
    "USAGE": map_def(2, 4, 8, 1),
    "USAGE_CONFIG": map_def(2, 4, 8, 1, 128),
    "USAGE_EVIDENCE": map_def(6, 4, 8, 3),
}
INVENTORY_PROGRAMS = (SAFE_PROGRAMS - {"p11_entry", "p11_return", "task_newtask"}) | {
    "p11_usage_entry_lp64", "p11_usage_entry_ia32",
}
INVENTORY_FORBIDDEN_MAPS = {
    "STATS", "START", "RV_COUNTS", "EVENTS", "DESCRIPTORS", "MECH_SHAPE",
    "ASYNC_FUNCTIONS", "ATTR_BOOL_BITS", "PAUSE_PIDS", "TASK_COOKIE", "COOKIE_CTL",
    "ROOT_AFFILIATION", "ROOT_CTL",
}
INVENTORY_CALLER_MAPS = INVENTORY_MAPS | {
    "ENDPOINT_OBJECT": map_def(2, 4, 8, 1, 128),
    "CALLER_USE": map_def(1, 24, 32, 1),
    "CALLER_EVIDENCE": map_def(6, 4, 8, 4),
    "TASK_COOKIE": SAFE_MAPS["TASK_COOKIE"],
    "COOKIE_CTL": SAFE_MAPS["COOKIE_CTL"],
}

FROZEN_INVENTORY = {
    "inventory": (INVENTORY_MAPS, INVENTORY_PROGRAMS),
    "inventory-small-discovery": (INVENTORY_MAPS | {"DISCOVERY": map_def(27, 0, 0, 4096)}, INVENTORY_PROGRAMS),
    "inventory-callers": (INVENTORY_CALLER_MAPS, INVENTORY_PROGRAMS),
    "inventory-callers-small-discovery": (INVENTORY_CALLER_MAPS | {"DISCOVERY": map_def(27, 0, 0, 4096)}, INVENTORY_PROGRAMS),
    "default": (SAFE_MAPS, SAFE_PROGRAMS),
    "diagnostic": (UNSAFE_MAPS, UNSAFE_PROGRAMS),
}


# Per-variant private decoder freeze:
# (global params?, global full-template?, local params count, local full walker
# count, local types-only walker count).
# The diagnostic object carries two ABI-specialized local implementations under
# each global boundary, plus two ABI-specialized local types-only walkers.
FROZEN_SYMBOLS = {
    "inventory": (False, False, 0, 0, 0),
    "inventory-small-discovery": (False, False, 0, 0, 0),
    "inventory-callers": (False, False, 0, 0, 0),
    "inventory-callers-small-discovery": (False, False, 0, 0, 0),
    "default": (False, False, 0, 0, 0),
    "diagnostic": (True, True, 2, 2, 2),
}


def validate_inventory(variant, maps, programs, symbols):
    """Compare ONE object's maps and programs against the frozen `variant` inventory.

    A mismatch prints every differing map name and field to stderr first, so a
    stale freeze is diagnosable from the failing lane's log alone.
    """
    frozen_maps, frozen_programs = FROZEN_INVENTORY[variant]
    if maps != frozen_maps:
        for name in sorted(maps.keys() - frozen_maps.keys()):
            print(f"map added: {name}", file=sys.stderr)
        for name in sorted(frozen_maps.keys() - maps.keys()):
            print(f"map removed: {name}", file=sys.stderr)
        for name in sorted(maps.keys() & frozen_maps.keys()):
            for field in MAP_FIELDS:
                got, want = maps[name][field], frozen_maps[name][field]
                if got != want:
                    print(f"{name}.{field}: object={got} frozen={want}", file=sys.stderr)
        raise RuntimeError(f"{variant} map inventory differs")
    if programs != frozen_programs:
        for name in sorted(programs - frozen_programs):
            print(f"program added: {name}", file=sys.stderr)
        for name in sorted(frozen_programs - programs):
            print(f"program removed: {name}", file=sys.stderr)
        raise RuntimeError(f"{variant} program inventory differs")
    inventory = variant.startswith("inventory")
    callers = variant.startswith("inventory-callers")
    if inventory:
        allowed = {"TASK_COOKIE", "COOKIE_CTL", "p11_link_current_identity"} if callers else set()
        forbidden = {name for name in symbols if name not in allowed and
                     (name in INVENTORY_FORBIDDEN_MAPS
                      or name.startswith(("p11_owner_start_", "p11_link_", "p11_root_")))}
        if forbidden:
            raise RuntimeError(f"inventory contains forbidden detailed symbols: {sorted(forbidden)}")
    required_helpers = (REQUIRED_GLOBAL_OWNER_HELPERS | REQUIRED_GLOBAL_SCALAR_HELPERS
                        if inventory else REQUIRED_GLOBAL_HELPERS)
    if callers:
        required_helpers |= {"p11_link_current_identity"}
    missing_helpers = required_helpers - symbols
    if missing_helpers:
        raise RuntimeError(f"missing required .text helpers: {sorted(missing_helpers)}")
    found = (
        "p11_decode_params" in symbols,
        "p11_walk_template" in symbols,
        sum("decode_params" in name for name in symbols if name != "p11_decode_params"),
        sum("walk_template_impl" in name for name in symbols),
        sum("walk_template_types" in name for name in symbols),
    )
    if found != FROZEN_SYMBOLS[variant]:
        print(
            f"global_params={found[0]} global_template={found[1]} "
            f"local_params={found[2]} local_full={found[3]} local_types={found[4]} "
            f"frozen={FROZEN_SYMBOLS[variant]}",
            file=sys.stderr,
        )
        raise RuntimeError(f"{variant} decoder symbol inventory differs")


def validate_policy_inventory(safe, unsafe):
    validate_inventory("default", *safe)
    validate_inventory("diagnostic", *unsafe)


def self_test():
    assert SAFE_MAPS["DISCOVERY"] == map_def(27, 0, 0, 65_536)
    assert SAFE_MAPS["DISCOVERY_STATE"] == map_def(1, 24, 24, 64)
    assert SAFE_MAPS["COUNTERS"] == map_def(6, 4, 8, 5)
    assert SAFE_MAPS["PAUSE_PIDS"] == map_def(1, 16, 8, 1)
    assert SAFE_MAPS["PID_FILTER"] == map_def(1, 4, 8, 1_024, 128)
    assert SAFE_MAPS["EVIDENCE"] == map_def(6, 4, 8, 9)
    assert len(SAFE_MAPS) == 22
    assert len(UNSAFE_MAPS) == 23
    assert len(SAFE_PROGRAMS) == 13
    assert len(UNSAFE_PROGRAMS) == 18
    good = (SAFE_MAPS, SAFE_PROGRAMS, {"p11_entry"} | REQUIRED_GLOBAL_HELPERS)
    diagnostic = (
        UNSAFE_MAPS,
        UNSAFE_PROGRAMS,
        {
            "p11_decode_params",
            "p11_walk_template",
            "decode_params-0",
            "decode_params-1",
            "walk_template_impl-0",
            "walk_template_impl-1",
            "walk_template_types-0",
            "walk_template_types-1",
        } | REQUIRED_GLOBAL_HELPERS,
    )
    validate_policy_inventory(good, diagnostic)

    def rejected(check, *arguments):
        if check is validate_inventory:
            *prefix, symbols = arguments
            arguments = (*prefix, symbols | REQUIRED_GLOBAL_HELPERS)
        errors = io.StringIO()
        try:
            with contextlib.redirect_stderr(errors):
                check(*arguments)
        except RuntimeError:
            return errors.getvalue().splitlines()
        raise AssertionError(f"{check.__name__} accepted {arguments!r}")

    assert rejected(
        validate_policy_inventory, (UNSAFE_MAPS, SAFE_PROGRAMS, {"decode_params"}), diagnostic
    ) == ["map added: ATTR_BOOL_BITS"]
    # Each variant is compared against ITS OWN freeze, not the other one's.
    assert rejected(validate_inventory, "diagnostic", SAFE_MAPS, SAFE_PROGRAMS, set()) == [
        "map removed: ATTR_BOOL_BITS"
    ]
    assert rejected(validate_inventory, "default", UNSAFE_MAPS, UNSAFE_PROGRAMS, set()) == [
        "map added: ATTR_BOOL_BITS"
    ]
    # A one-field drift names exactly that field, nothing else (the W3 CONFIG
    # shape: same maps, one max_entries apart).
    frozen = SAFE_MAPS["CONFIG"]["max_entries"]
    drifted = SAFE_MAPS | {"CONFIG": SAFE_MAPS["CONFIG"] | {"max_entries": frozen + 1}}
    assert rejected(validate_inventory, "default", drifted, SAFE_PROGRAMS, set()) == [
        f"CONFIG.max_entries: object={frozen + 1} frozen={frozen}"
    ]
    # A program entering or leaving the object is named, not just counted.
    assert rejected(
        validate_inventory, "default", SAFE_MAPS, SAFE_PROGRAMS | {"p11_extra"}, {"p11_entry"}
    ) == ["program added: p11_extra"]
    assert rejected(
        validate_inventory, "default", SAFE_MAPS, SAFE_PROGRAMS - {"p11_entry"}, {"p11_entry"}
    ) == ["program removed: p11_entry"]
    # A decoder symbol reaching the shipped object is refused even when its maps
    # and programs are untouched -- the drift class `--inventory` alone would miss.
    assert rejected(
        validate_inventory, "default", SAFE_MAPS, SAFE_PROGRAMS, {"p11_entry", "decode_params"}
    ) == [
        "global_params=False global_template=False local_params=1 local_full=0 local_types=0 "
        "frozen=(False, False, 0, 0, 0)"
    ]
    assert rejected(
        validate_inventory,
        "default",
        SAFE_MAPS,
        SAFE_PROGRAMS,
        {"p11_entry", "p11_decode_params"},
    ) == [
        "global_params=True global_template=False local_params=0 local_full=0 local_types=0 "
        "frozen=(False, False, 0, 0, 0)"
    ]
    assert rejected(validate_inventory, "diagnostic", UNSAFE_MAPS, UNSAFE_PROGRAMS, set()) == [
        "global_params=False global_template=False local_params=0 local_full=0 local_types=0 "
        "frozen=(True, True, 2, 2, 2)"
    ]
    # The unclassified-section refusal, which no real object can exercise.
    sections = {".text": 1, "uprobe": 2, "raw_tp/sched_process_exit": 3}
    func = lambda section, name: (0, 0, "FUNC", "GLOBAL", "DEFAULT", str(section), name)
    assert classify([func(2, "p11_entry")], sections) == {"p11_entry"}
    for section, name in [(3, "extra_raw"), (1, "stray_text")]:
        try:
            classify([func(2, "p11_entry"), func(section, name)], sections)
        except RuntimeError as error:
            assert name in str(error), error
        else:
            raise AssertionError(f"unclassified {name} accepted")
    assert classify(
        [func(2, "p11_entry")] + [func(1, name) for name in DIAGNOSTIC_GLOBAL_HELPERS],
        sections,
        DIAGNOSTIC_GLOBAL_HELPERS,
    ) == {"p11_entry"}
    for helper in DIAGNOSTIC_GLOBAL_HELPERS:
        for section, name in [
            (1, helper),
            (1, f"{helper}_extra"),
            (3, helper),
        ]:
            allowed = DIAGNOSTIC_GLOBAL_HELPERS if (section, name) != (1, helper) else set()
            try:
                classify([func(2, "p11_entry"), func(section, name)], sections, allowed)
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"non-diagnostic or inexact global helper {name} accepted")
    # mem* helpers are GLOBAL HIDDEN, so the visibility filter already excludes
    # them; the name carries no exemption of its own.
    assert classify([(0, 0, "FUNC", "GLOBAL", "HIDDEN", "1", "memcpy")], sections) == set()
    try:
        classify([func(1, "memcpy")], sections)
    except RuntimeError:
        pass
    else:
        raise AssertionError("a GLOBAL DEFAULT memcpy was exempted by name")
    print("unclassified program sections rejected: OK")
    record = (0, 28, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE")
    data = struct.pack("<7I", 1, 4, 8, 1, 0, 0, 0)
    assert decode_map_definitions([record], 9, data)["ONE"]["value_size"] == 8
    mutations = [
        ([(0, 28, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE"), record], data * 2),
        ([(0, 24, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE")], data),
        ([(2, 28, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE")], b"\0\0" + data),
        ([(0, 28, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE")], data[:-1]),
        ([record], data + b"\0"),
    ]
    for records, raw in mutations:
        try:
            decode_map_definitions(records, 9, raw)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"malformed map definitions accepted: {records!r}")
    print("malformed map definitions rejected: OK")
    print("check-bpf-map-defs self-test: OK")
    print("policy inventory self-test: OK")


def usage():
    return (
        f"usage: {sys.argv[0]} BPF_ELF MAP=MAX_ENTRIES [...] | "
        "--inventory VARIANT BPF_ELF (default, diagnostic, inventory[-small-discovery], "
        "inventory-callers[-small-discovery]) | "
        "--policy-inventory DEFAULT_ELF DIAGNOSTIC_ELF | --json BPF_ELF | --self-test"
    )


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if sys.argv[1:2] == ["--json"]:
        if len(sys.argv) != 3:
            raise SystemExit(usage())
        maps, programs, symbols = inspect(sys.argv[2], DIAGNOSTIC_GLOBAL_HELPERS)
        print(json.dumps({"maps": maps, "programs": sorted(programs), "symbols": sorted(symbols)}, sort_keys=True))
        return
    if sys.argv[1:2] == ["--inventory"]:
        if len(sys.argv) != 4:
            raise SystemExit(usage())
        variant, path = sys.argv[2], sys.argv[3]
        if variant not in FROZEN_INVENTORY:
            raise RuntimeError(f"unknown inventory variant {variant!r}")
        # Permit only the two exact exported decoder names through section
        # classification; the per-variant symbol freeze below still rejects
        # either helper in a default object. This lets the cross-variant
        # negative control reach the requested inventory comparison.
        maps, programs, symbols = inspect(path, DIAGNOSTIC_GLOBAL_HELPERS, variant=variant)
        validate_inventory(variant, maps, programs, symbols)
        print(f"inventory {variant}: maps={len(maps)} programs={len(programs)} OK")
        return
    if sys.argv[1:2] == ["--policy-inventory"]:
        if len(sys.argv) != 4:
            raise SystemExit(usage())
        safe = inspect(sys.argv[2])
        unsafe = inspect(sys.argv[3], DIAGNOSTIC_GLOBAL_HELPERS)
        validate_policy_inventory(safe, unsafe)
        print(
            f"policy inventory: default maps={len(safe[0])} programs={len(safe[1])}; "
            f"diagnostic maps={len(unsafe[0])} programs={len(unsafe[1])} OK"
        )
        return
    if len(sys.argv) < 3:
        raise SystemExit(usage())
    path = sys.argv[1]
    expected = dict(item.split("=", 1) for item in sys.argv[2:])
    actual = definitions(path)
    for name, value in expected.items():
        if name not in actual:
            raise RuntimeError(f"{name} has no map definition in {path}")
        want, got = int(value, 0), actual[name]["max_entries"]
        if got != want:
            raise RuntimeError(f"{path}: {name}.max_entries={got}, expected {want}")
        print(f"{path}: {name}.max_entries={got} OK")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"check-bpf-map-defs: {error}", file=sys.stderr)
        sys.exit(1)
