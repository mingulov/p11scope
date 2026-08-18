#!/usr/bin/env python3
import hashlib
import json
import os
import struct
import sys

if len(sys.argv) < 5 or (len(sys.argv) - 2) % 3:
    raise SystemExit("usage: elf_meta.py OUTPUT_JSON ROLE PATH SYMBOL [ROLE PATH SYMBOL ...]")

def metadata(path, symbol):
    path = os.path.realpath(path)
    st = os.stat(path)
    with open(path, "rb") as f:
        blob = f.read()
    ident = blob[:16]
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise SystemExit("need little-endian ELF64: " + path)
    hdr = struct.unpack_from("<HHIQQQIHHHHHH", blob, 16)
    phoff, shoff = hdr[4], hdr[5]
    phentsize, phnum = hdr[8], hdr[9]
    shentsize, shnum = hdr[10], hdr[11]
    loads = []
    for i in range(phnum):
        p = struct.unpack_from("<IIQQQQQQ", blob, phoff + i * phentsize)
        if p[0] == 1:
            loads.append({"offset": p[2], "vaddr": p[3], "filesz": p[5], "memsz": p[6]})
    sections = [struct.unpack_from("<IIQQQQIIQQ", blob, shoff + i * shentsize) for i in range(shnum)]
    dyn = next((s for s in sections if s[1] == 11), None)
    if dyn is None:
        raise SystemExit("no SHT_DYNSYM: " + path)
    strings = sections[dyn[6]]
    strtab = blob[strings[4]:strings[4] + strings[5]]
    found = []
    for off in range(dyn[4], dyn[4] + dyn[5], dyn[9]):
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", blob, off)
        end = strtab.find(b"\0", st_name)
        name = strtab[st_name:end].decode("utf-8", "replace")
        if name == symbol:
            found.append((st_value, st_size, st_info, st_other))
    if len(found) != 1:
        raise SystemExit("expected one dynsym %r in %s, got %d" % (symbol, path, len(found)))
    value, size, info, other = found[0]
    return {
        "path": path,
        "dev": st.st_dev,
        "inode": st.st_ino,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "loads": loads,
        "symbol": {"name": symbol, "value": value, "size": size, "info": info, "other": other},
    }

out = {}
for i in range(2, len(sys.argv), 3):
    role, path, symbol = sys.argv[i:i + 3]
    if role in out:
        raise SystemExit("duplicate role: " + role)
    out[role] = metadata(path, symbol)
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(out, f, sort_keys=True, separators=(",", ":"))
    f.write("\n")
