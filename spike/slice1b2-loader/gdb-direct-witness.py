import gdb
import json
import os
import struct

FAMILY = os.environ["SPIKE_FAMILY"]
RDEBUG_R_STATE_OFFSET = 24
with open(os.environ["SPIKE_META"], encoding="utf-8") as f:
    META = json.load(f)

seen_dlopen = False
seen_add = False
decisive_done = False
ctor_seen = False
classification = "BLOCKED"

def out(s):
    gdb.write(s + "\n")

def maps(pid):
    rows = []
    with open("/proc/%d/maps" % pid, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split(maxsplit=5)
            if len(parts) < 5:
                continue
            start, end = (int(x, 16) for x in parts[0].split("-"))
            major, minor = (int(x, 16) for x in parts[3].split(":"))
            rows.append({
                "start": start, "end": end, "perms": parts[1], "offset": int(parts[2], 16),
                "dev": os.makedev(major, minor), "dev_text": parts[3], "inode": int(parts[4]),
                "path": parts[5] if len(parts) == 6 else "",
            })
    return rows

def binding(pid, role):
    obj = META[role]
    symbol = obj["symbol"]["value"]
    candidates = [m for m in maps(pid) if m["path"] == obj["path"] and m["dev"] == obj["dev"] and m["inode"] == obj["inode"]]
    if not candidates:
        return None, "path=%s dev=%d inode=%d maps=no-exact-match" % (obj["path"], obj["dev"], obj["inode"])
    for m in candidates:
        for p in obj["loads"]:
            base = m["start"] - (p["vaddr"] + m["offset"] - p["offset"])
            address = base + symbol
            if m["start"] <= address < m["end"]:
                detail = (
                    "path=%s dev=%s/%d inode=%d/%d map=[0x%x-0x%x) map_offset=0x%x "
                    "p_offset=0x%x p_vaddr=0x%x bias=0x%x symbol=0x%x address=0x%x"
                    % (obj["path"], m["dev_text"], obj["dev"], m["inode"], obj["inode"], m["start"], m["end"], m["offset"],
                       p["offset"], p["vaddr"], base, symbol, address)
                )
                return (address, detail), None
    return None, "path=%s dev=%d inode=%d maps=exact-but-no-PT_LOAD-address" % (obj["path"], obj["dev"], obj["inode"])

def read_memory(pid, address, size):
    fd = os.open("/proc/%d/mem" % pid, os.O_RDONLY)
    try:
        value = os.pread(fd, size, address)
    finally:
        os.close(fd)
    if len(value) != size:
        raise RuntimeError("short read %d/%d" % (len(value), size))
    return value

def r_state(pid):
    bound, reason = binding(pid, "loader")
    if bound is None:
        return None, "BLOCKED " + reason
    address, detail = bound
    try:
        state = struct.unpack("i", read_memory(pid, address + RDEBUG_R_STATE_OFFSET, 4))[0]
    except Exception as exc:
        return None, "BLOCKED %s read_error=%r" % (detail, exc)
    return state, "DIRECT_RSTATE %s r_state_offset=%d r_state_address=0x%x value=%d" % (
        detail, RDEBUG_R_STATE_OFFSET, address + RDEBUG_R_STATE_OFFSET, state)

def direct_witness(pid):
    dso, dso_reason = binding(pid, "dso")
    libc, libc_reason = binding(pid, "libc")
    if dso is None or libc is None:
        return "BLOCKED", "dso={}; libc={}".format(dso_reason if dso is None else dso[1], libc_reason if libc is None else libc[1])
    dso_address, dso_detail = dso
    libc_address, libc_detail = libc
    try:
        actual = struct.unpack("<Q", read_memory(pid, dso_address, 8))[0]
        expected = libc_address
    except Exception as exc:
        return "BLOCKED", "dso={}; libc={}; read_error={!r}".format(dso_detail, libc_detail, exc)
    detail = "dso={}; libc={}; actual=0x{:x} expected=0x{:x}".format(dso_detail, libc_detail, actual, expected)
    if actual == 0:
        return "FAIL_ZERO", detail
    if actual != expected:
        return "FAIL_UNEQUAL", detail
    return "PASS_EQUAL", detail

class DlopenBreakpoint(gdb.Breakpoint):
    def stop(self):
        global seen_dlopen
        seen_dlopen = True
        out("GDB_DLOPEN_ENTRY")
        return False

class LoaderBreakpoint(gdb.Breakpoint):
    def stop(self):
        global seen_add, decisive_done, classification
        pid = gdb.selected_inferior().pid
        witness, detail = direct_witness(pid)
        if FAMILY == "glibc":
            state, state_detail = r_state(pid)
            out("GDB_LOADER family=glibc phase=%s %s witness=%s %s" %
                ("AFTER_DLOPEN_ENTRY" if seen_dlopen else "INITIAL_LINK_SET", state_detail, witness, detail))
            if seen_dlopen and not decisive_done:
                if state == 1:
                    seen_add = True
                    out("GDB_GLIBC_POST_DLOPEN_RT_ADD")
                elif state == 0 and seen_add:
                    decisive_done = True
                    classification = {"PASS_EQUAL": "PASS", "FAIL_ZERO": "FAIL", "FAIL_UNEQUAL": "FAIL"}.get(witness, "BLOCKED")
                    out("GDB_GLIBC_DECISIVE_FIRST_RT_CONSISTENT classification=%s witness=%s" % (classification, witness))
        else:
            out("GDB_LOADER family=musl phase=%s witness=%s %s" %
                ("AFTER_DLOPEN_ENTRY" if seen_dlopen else "INITIAL_LINK_SET", witness, detail))
            if seen_dlopen and not decisive_done and witness == "PASS_EQUAL":
                decisive_done = True
                classification = "PASS"
                out("GDB_MUSL_USABLE_DIRECT_EQUAL")
        return False

class CtorBreakpoint(gdb.Breakpoint):
    def stop(self):
        global ctor_seen, classification
        ctor_seen = True
        pid = gdb.selected_inferior().pid
        witness, detail = direct_witness(pid)
        out("GDB_CTOR direct_witness=%s %s" % (witness, detail))
        if not decisive_done:
            classification = "BLOCKED"
            out("GDB_CTOR_WITHOUT_DECISIVE_HIT")
        elif FAMILY == "musl" and classification != "PASS":
            classification = "BLOCKED"
        return False

gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
DlopenBreakpoint("dlopen")
LoaderBreakpoint("_dl_debug_state")
CtorBreakpoint("fixture_ctor_marker")
gdb.execute("run")
if not seen_dlopen or not ctor_seen or not decisive_done:
    classification = "BLOCKED"
out("GDB_FINAL_CLASSIFICATION=%s seen_dlopen=%s seen_add=%s decisive_done=%s ctor_seen=%s" %
    (classification, seen_dlopen, seen_add, decisive_done, ctor_seen))
