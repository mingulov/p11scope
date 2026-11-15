#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Write a getter-only p11scope manifest for an ELF file that embeds a provider.

`p11scope-discover` loads its target with dlopen, so it cannot describe a
program that has a PKCS#11 provider statically linked in. This helper
needs no loading: it reads the file's own symbol table (`.symtab`, else
`.dynsym`), finds each requested getter (`C_GetFunctionList`,
`C_GetInterface`, `C_GetInterfaceList`), converts its virtual address to
a file offset through the executable PT_LOAD segment that holds it, and
writes a `p11scope-manifest/5` document that names only those getters
plus the file's identity (SHA-256 and GNU build-id).

The observer then hooks each getter's return and reads the function
table it hands out at run time; nothing about the table is trusted from
this file. The file must still be byte-identical at capture time (the
observer re-hashes it and refuses a changed file).

Usage:
  getter-manifest.py BINARY -o MANIFEST [--getter NAME]...

Without --getter, every standard getter the symbol table defines is
written. Exit 0 on success, 1 when a requested getter is missing or lies
outside every executable segment, 2 on usage or ELF errors.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

SCHEMA = "p11scope-manifest/5"
GETTERS = ("C_GetFunctionList", "C_GetInterfaceList", "C_GetInterface")
PT_LOAD = 1
PT_NOTE = 4
PF_X = 1
SHT_SYMTAB = 2
SHT_DYNSYM = 11
STT_FUNC = 2
SHN_UNDEF = 0
NT_GNU_BUILD_ID = 3


class ElfError(Exception):
    pass


class Elf:
    """The few ELF facts the manifest needs, from bytes already read."""

    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ElfError("not an ELF file")
        klass, encoding = data[4], data[5]
        if klass not in (1, 2) or encoding != 1:
            raise ElfError("only little-endian ELF32/ELF64 is supported")
        self.data = data
        self.is64 = klass == 2
        if self.is64:
            (self.phoff, self.shoff) = struct.unpack_from("<QQ", data, 0x20)
            (self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = struct.unpack_from("<HHHHH", data, 0x36)
        else:
            (self.phoff, self.shoff) = struct.unpack_from("<II", data, 0x1c)
            (self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = struct.unpack_from("<HHHHH", data, 0x2a)

    def segments(self):
        for index in range(self.phnum):
            at = self.phoff + index * self.phentsize
            if self.is64:
                (kind, flags, offset, vaddr, _paddr, filesz,
                 _memsz, _align) = struct.unpack_from("<IIQQQQQQ", self.data, at)
            else:
                (kind, offset, vaddr, _paddr, filesz, _memsz, flags,
                 _align) = struct.unpack_from("<IIIIIIII", self.data, at)
            yield kind, flags, offset, vaddr, filesz

    def sections(self):
        for index in range(self.shnum):
            at = self.shoff + index * self.shentsize
            if self.is64:
                (name, kind, _flags, _addr, offset, size, link, _info,
                 _align, entsize) = struct.unpack_from("<IIQQQQIIQQ", self.data, at)
            else:
                (name, kind, _flags, _addr, offset, size, link, _info,
                 _align, entsize) = struct.unpack_from("<IIIIIIIIII", self.data, at)
            yield {"name": name, "kind": kind, "offset": offset, "size": size,
                   "link": link, "entsize": entsize}

    def symbols(self, kind):
        """(name, value, type) for each defined symbol of the table kind."""
        sections = list(self.sections())
        for section in sections:
            if section["kind"] != kind or not section["entsize"]:
                continue
            strtab = sections[section["link"]]
            for at in range(section["offset"], section["offset"] + section["size"],
                            section["entsize"]):
                if self.is64:
                    (name, info, _other, shndx, value,
                     _size) = struct.unpack_from("<IBBHQQ", self.data, at)
                else:
                    (name, value, _size, info, _other,
                     shndx) = struct.unpack_from("<IIIBBH", self.data, at)
                if shndx == SHN_UNDEF:
                    continue
                start = strtab["offset"] + name
                end = self.data.index(b"\0", start)
                yield self.data[start:end].decode("utf-8", "replace"), value, info & 0xF

    def getter_symbols(self):
        """The standard getters' addresses: .symtab first, then .dynsym."""
        found = {}
        for table in (SHT_SYMTAB, SHT_DYNSYM):
            for name, value, kind in self.symbols(table):
                if name in GETTERS and kind == STT_FUNC and name not in found:
                    found[name] = value
        return found

    def file_offset(self, vaddr):
        """The file offset of vaddr inside an executable PT_LOAD, else None."""
        for kind, flags, offset, start, filesz in self.segments():
            if kind == PT_LOAD and flags & PF_X and start <= vaddr < start + filesz:
                return vaddr - start + offset
        return None

    def build_id(self):
        for kind, _flags, offset, _vaddr, filesz in self.segments():
            if kind != PT_NOTE:
                continue
            at, end = offset, offset + filesz
            while at + 12 <= end:
                namesz, descsz, note_type = struct.unpack_from("<III", self.data, at)
                name_at = at + 12
                desc_at = name_at + ((namesz + 3) & ~3)
                if (note_type == NT_GNU_BUILD_ID
                        and self.data[name_at:name_at + namesz] == b"GNU\0"):
                    return self.data[desc_at:desc_at + descsz].hex()
                at = desc_at + ((descsz + 3) & ~3)
        return None


def identity(data, elf):
    sha256 = hashlib.sha256(data).hexdigest()
    build_id = elf.build_id()
    if build_id:
        return {"kind": "gnu_build_id", "value": build_id, "sha256": sha256,
                "reusable": True, "note": None}
    return {"kind": "sha256", "value": sha256, "sha256": sha256,
            "reusable": True, "note": None}


def manifest(path, requested):
    """(manifest, problems) for the absolute path; problems name misses."""
    data = path.read_bytes()
    info = os.stat(path)
    elf = Elf(data)
    symbols = elf.getter_symbols()
    names = list(requested) if requested else [name for name in GETTERS if name in symbols]
    problems = []
    getters = []
    for name in names:
        if name not in symbols:
            problems.append(f"{name} is not defined in the symbol table")
            continue
        offset = elf.file_offset(symbols[name])
        if offset is None:
            problems.append(f"{name} lies outside every executable segment")
            continue
        getters.append({"name": name,
                        "resolution": {"status": "resolved", "object": 0,
                                       "file_offset": offset}})
    if not getters and not problems:
        problems.append("the symbol table defines no standard getter")
    ident = identity(data, elf)
    document = {
        "schema": SCHEMA,
        "module_path": str(path),
        "objects": [{"id": 0, "path": str(path), "identity": ident}],
        # The observer resolves its own device domain for the held file;
        # st_dev here is only this pass's stabilization fact.
        "provenance_objects": [{
            "path": str(path),
            "device_major": os.major(info.st_dev),
            "device_minor": os.minor(info.st_dev),
            "inode": info.st_ino,
            "identity": ident,
        }],
        # Nothing is enumerated or walked here: the getters say where the
        # tables come from, and the observer reads them live.
        "interface_list": {"status": "absent"},
        "surfaces": [],
        "vendor_interfaces": [],
        "alias_groups": [],
        "selection_evidence": {"acquisition": "export_absent", "queries": [],
                               "tables": [], "selection_truncated": False},
        "getters": getters,
    }
    return document, problems


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--getter", action="append", choices=GETTERS, default=[])
    args = parser.parse_args(argv)
    path = Path(args.binary).resolve()
    if len(set(args.getter)) != len(args.getter):
        print("getter-manifest: a getter was named twice", file=sys.stderr)
        return 2
    try:
        document, problems = manifest(path, args.getter)
    except (OSError, ElfError, struct.error, ValueError) as error:
        print(f"getter-manifest: {path}: {error}", file=sys.stderr)
        return 2
    if problems:
        for problem in problems:
            print(f"getter-manifest: {path}: {problem}", file=sys.stderr)
        return 1
    Path(args.output).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    names = ", ".join(getter["name"] for getter in document["getters"])
    print(f"getter-manifest: wrote {args.output} ({names})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
