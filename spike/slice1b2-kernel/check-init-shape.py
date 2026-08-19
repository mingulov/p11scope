#!/usr/bin/env python3
"""Semantic initializer guard for the 896-byte DiscoveryRecord (corrective design §4.2).
Scope: emit_discovery, from `call bpf_ringbuf_reserve` (helper 131, r2 == 896) until exactly 112
distinct aligned u64 zero stores have covered record offsets 0..888. Sound because the region must be
straight-line: after the reserve and its single null-check branch, any branch, jump or call before
the 112th store is FAIL, so every path that reaches a record use ran all 112 stores. Duplicate stores
are FAIL. Base-register agnostic (aliases, +=, u64 spills/reloads). Unrelated memset/back edges
elsewhere in the ELF are not checked. Exit 0 PASS, 1 FAIL."""
import re, subprocess, sys

def fail(msg):
    sys.exit(f"FAIL: {msg}")

def normalized_pause_region(lines):
    region, after_cas = [], False
    for line in lines:
        instruction = re.sub(r"^[0-9a-f]+:\s+", "", line.strip())
        instruction = re.sub(r"\s+", " ", instruction)
        instruction = re.sub(r"goto [+-]0x[0-9a-f]+(?: <[^>]+>)?", "goto TARGET", instruction)
        instruction = re.sub(
            r"(\*\(u(?:8|16|32|64) \*\)\(r\d+ [+-] (?:0x[0-9a-f]+|-?\d+)\) = )w(\d+)$",
            r"\1r\2",
            instruction,
        )
        if "cmpxchg_64" in instruction:
            after_cas = True
        if after_cas:
            region.append(instruction)
    return region

PAUSE_POST_CAS_FINGERPRINT = [
    "r0 = cmpxchg_64(r1 + 0x0, r0, r3)",
    "if r0 == 0x1 goto TARGET",
    "r2 = 0x0",
    "r2 &= 0x1",
    "if r2 != 0x0 goto TARGET",
    "r9 = -0x8000000000000000 ll",
    "call 0x5",
    "goto TARGET",
    "*(u32 *)(r10 - 0x10) = r9",
    "r2 = r10",
    "r2 += -0x10",
    "r1 = 0x0 ll",
    "R_BPF_64_64 COUNTERS",
    "call 0x1",
    "if r0 == 0x0 goto TARGET",
    "r1 = *(u64 *)(r0 + 0x0)",
    "r1 += 0x1",
    "*(u64 *)(r0 + 0x0) = r1",
    "goto TARGET",
    "call 0x5",
    "*(u64 *)(r10 - 0x18) = r0",
    "r1 = 0x13",
    "call 0x6d",
    "r9 = r0",
    "r0 = *(u64 *)(r10 - 0x18)",
    "*(u8 *)(r8 + 0x18) = r7",
    "*(u64 *)(r8 + 0x10) = r9",
    "*(u64 *)(r8 + 0x8) = r6",
    "*(u64 *)(r8 + 0x0) = r0",
    "r1 = r8",
    "r2 = 0x0",
    "call 0x84",
    "r0 = 0x0",
    "exit",
]

def pause_fingerprint_matches(lines):
    return normalized_pause_region(lines) == PAUSE_POST_CAS_FINGERPRINT

def pause_fingerprint_self_test():
    def normalize(lines):
        return pause_fingerprint_matches(
            [f"{index:04x}: {line}" for index, line in enumerate(lines)]
        )

    nightly = list(PAUSE_POST_CAS_FINGERPRINT)
    nightly[8] = "*(u32 *)(r10 - 0x10) = w9"
    nightly[25] = "*(u8 *)(r8 + 0x18) = w7"
    if not normalize(nightly):
        fail("pause store-register aliases were rejected")
    for old, new in [
        ("r2 &= 0x1", "w2 &= 0x1"),
        ("*(u32 *)(r10 - 0x10) = w9", "*(u16 *)(r10 - 0x10) = w9"),
        ("*(u32 *)(r10 - 0x10) = w9", "*(u32 *)(r10 - 0x10) = w8"),
    ]:
        mutated = list(nightly)
        mutated[mutated.index(old)] = new
        if normalize(mutated):
            fail("pause semantic mutation was accepted")

def pause_source_guard(path):
    source = open(path, encoding="utf-8").read()
    signal = source[source.index("pub fn signal_return("):source.index("pub fn late_hit(")]
    cas = signal.index("core::intrinsics::atomic_cxchg")
    submit = signal.index("entry.submit(0);")
    region = signal[cas:submit]
    if "STOP_SIGNAL_DELAY_POLLS" in source or re.search(r"\b(?:while|loop|for)\b", region):
        fail("pause winner path has a post-CAS loop or delay")
    winner = re.search(
        r"if won \{\s*let hook_ts_ns = helpers::bpf_ktime_get_ns\(\);\s*"
        r"let send_signal_rc = helpers::bpf_send_signal\(19\) as i64;\s*"
        r"\(hook_ts_ns, send_signal_rc\)\s*\} else \{",
        region,
    )
    helpers_after_cas = re.findall(r"helpers::([A-Za-z_][A-Za-z0-9_]*)", region)
    if (
        not winner
        or helpers_after_cas != [
            "bpf_ktime_get_ns",
            "bpf_send_signal",
            "bpf_ktime_get_ns",
        ]
    ):
        fail("pause winner must read ktime immediately before one SIGSTOP helper")
    tuple_start = signal.index("let (hook_ts_ns, send_signal_rc) = unsafe {")
    before_tuple = re.sub(r"//[^\n]*|\s+", "", signal[cas:tuple_start])
    if not before_tuple.endswith("None=>false,};"):
        fail("pause winner has a post-CAS forward sequence")
    straight_line = re.sub(
        r"//[^\n]*|\s+",
        "",
        signal[tuple_start:submit + len("entry.submit(0);")],
    )
    expected_straight_line = (
        "let(hook_ts_ns,send_signal_rc)=unsafe{ifwon{"
        "lethook_ts_ns=helpers::bpf_ktime_get_ns();"
        "letsend_signal_rc=helpers::bpf_send_signal(19)asi64;"
        "(hook_ts_ns,send_signal_rc)}else{"
        "(helpers::bpf_ktime_get_ns(),COALESCED_NO_HELPER,)}};"
        "unsafe{"
        "core::ptr::write(core::ptr::addr_of_mut!((*raw).hook_ts_ns),hook_ts_ns);"
        "core::ptr::write(core::ptr::addr_of_mut!((*raw).pid_tgid),pid_tgid);"
        "core::ptr::write(core::ptr::addr_of_mut!((*raw).send_signal_rc),send_signal_rc);"
        "core::ptr::write(core::ptr::addr_of_mut!((*raw).case_id),case_id);"
        "}entry.submit(0);"
    )
    if straight_line != expected_straight_line:
        fail("pause winner must use the exact straight-line clock/signal/store/submit path")

if len(sys.argv) >= 2 and sys.argv[1] == "--pause-source-only":
    if len(sys.argv) != 3:
        sys.exit("usage: check-init-shape.py --pause-source-only SOURCE")
    pause_source_guard(sys.argv[2])
    print("PASS: pause source has reserve/init/CAS/ktime/send/submit without a post-CAS loop")
    raise SystemExit(0)

if len(sys.argv) == 2 and sys.argv[1] == "--pause-fingerprint-self-test":
    pause_fingerprint_self_test()
    print("PASS: pause store aliases accepted; ALU, width, and source mutations rejected")
    raise SystemExit(0)

obj = sys.argv[1]
objdump = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "llvm-objdump"
pause_source = None
if "--pause-source" in sys.argv:
    pause_index = sys.argv.index("--pause-source")
    if pause_index + 1 >= len(sys.argv) or pause_index + 2 != len(sys.argv):
        sys.exit("usage: check-init-shape.py OBJECT [OBJDUMP] [--pause-source SOURCE]")
    pause_source = sys.argv[pause_index + 1]
out = subprocess.run([objdump, "-dr", "--no-show-raw-insn", obj], capture_output=True, text=True, check=True).stdout
m = re.search(r"^[0-9a-f]+ <\S*emit_discovery>:\n", out, re.M)      # symbol may be mangled
if not m:
    sys.exit("FAIL: emit_discovery not found")
lines = out[m.end():].split("\n\n", 1)[0].splitlines()

RELOC = re.compile(r"^\s*[0-9a-f]{16}:\s+R_BPF_\S+\s+(\S+)")
NUM = r"(?:0x[0-9a-f]+|-?\d+)"
STORE = re.compile(rf"\*\((u8|u16|u32|u64) \*\)\((r\d+) ([+-]) ({NUM})\) = (r\d+|{NUM})$")
LOAD = re.compile(rf"(r\d+) = \*\((u8|u16|u32|u64) \*\)\((r\d+) ([+-]) ({NUM})\)$")
NEEDED = set(range(0, 896, 8))
val = lambda s: int(s, 0)
off = lambda sign, n: val(n) if sign == "+" else -val(n)


regs, spills, zero, done = {}, {}, set(), set()   # reg->record offset; stack slot->record offset; zero regs; zeroed offsets
stores, null_check_seen = 0, False
in_region, pending_r2 = False, None
for i, line in enumerate(lines):
    if (r := RELOC.match(line)):
        if in_region and r.group(1) == "memset":
            fail("memset relocation inside the initializer region")
        continue
    ins = line.split(":", 1)[1].strip() if ":" in line else line.strip()
    ins = re.sub(r" <\S+>$", "", ins)                                # strip branch target symbol
    if not in_region:                                                # before the reserve: only track zero registers
        if (m := re.fullmatch(rf"r2 = ({NUM})", ins)):
            pending_r2 = val(m.group(1))
        if re.fullmatch(r"call (0x83|131)", ins) and pending_r2 == 896:  # bpf_ringbuf_reserve of the 896-byte record
            in_region, regs, spills, done, stores, null_check_seen = True, {"r0": 0}, {}, set(), 0, False
            zero -= {"r0", "r1", "r2", "r3", "r4", "r5"}                  # caller-saved; r6-r9 facts survive the call
            continue
        if (m := re.fullmatch(r"(r\d+) = (0x0|0)( ll)?", ins)):
            zero.add(m.group(1))
        elif ins.startswith("call"):
            zero -= {"r0", "r1", "r2", "r3", "r4", "r5"}
        elif (m := re.match(r"(r\d+) ", ins)) and not ins.startswith("if "):
            zero.discard(m.group(1))
        continue
    if (m := re.fullmatch(r"(r\d+) = (r\d+)", ins)) and m.group(2) in regs:
        regs[m.group(1)] = regs[m.group(2)]; zero.discard(m.group(1)); continue
    if (m := re.fullmatch(rf"(r\d+) \+= ({NUM})", ins)) and m.group(1) in regs:
        regs[m.group(1)] += val(m.group(2)); continue
    if (m := re.fullmatch(r"(r\d+) = (0x0|0)( ll)?", ins)):
        zero.add(m.group(1)); regs.pop(m.group(1), None); continue
    if (m := STORE.fullmatch(ins)):
        width, base, sign, n, v = m.groups()
        if base == "r10" and v in regs:
            if width != "u64":
                fail(f"narrow spill of a record alias: {ins}")
            spills[off(sign, n)] = regs[v]; continue                # u64 spill of an alias
        if base in regs:
            o = regs[base] + off(sign, n)
            if width == "u64" and (v in zero or (not v.startswith("r") and val(v) == 0)):
                if o in done:
                    fail(f"duplicate zero store at record offset {o}: {ins}")
                done.add(o); stores += 1
            else:
                fail(f"non-zero or narrow record store before initialization complete: {ins}")
            if done >= NEEDED and stores == 112:
                break                                              # region complete: exactly 112 distinct stores
        continue
    if (m := LOAD.fullmatch(ins)):
        dst, width, base, sign, n = m.groups()
        if base == "r10" and off(sign, n) in spills:
            if width != "u64":
                fail(f"narrow reload of a record alias: {ins}")
            regs[dst] = spills[off(sign, n)]; zero.discard(dst); continue
        if base in regs:
            fail(f"record load before initialization complete: {ins}")
        regs.pop(dst, None); zero.discard(dst); continue
    if ins.startswith("call"):
        target = lines[i + 1] if i + 1 < len(lines) else ""
        rr = RELOC.match(target)
        if rr and rr.group(1) == "memset":
            fail("memset relocation inside the initializer region")
        fail(f"call before the initializer completed: {ins}")
    if (m := re.fullmatch(r"if (r\d+) == (0x0|0) goto \+\S+", ins)) and m.group(1) in regs and not null_check_seen and not done:
        null_check_seen = True; continue                           # the single reserve-failure branch
    if ins.startswith("if ") or ins.startswith("goto"):
        fail(f"branch inside the initializer region (region must be straight-line): {ins}")
    if (m := re.match(r"(r\d+) ", ins)):                            # any other definition kills the alias/zero fact
        regs.pop(m.group(1), None); zero.discard(m.group(1))
else:
    if in_region:
        fail(f"initializer incomplete: {len(done)}/112 offsets; missing {sorted(NEEDED - done)[:6]}…")
    fail("no 896-byte bpf_ringbuf_reserve found in emit_discovery")

if pause_source is not None:
    pause_source_guard(pause_source)
    signal_match = re.search(r"^[0-9a-f]+ <\S*signal_return>:\n", out, re.M)
    if not signal_match:
        fail("signal_return not found")
    signal_lines = out[signal_match.end():].split("\n\n", 1)[0]
    if signal_lines.count("cmpxchg_64") != 1:
        fail("signal_return must contain exactly one cmpxchg_64")
    if re.search(r"\bgoto -", signal_lines):
        fail("signal_return has a backward edge")
    if not pause_fingerprint_matches(signal_lines.splitlines()):
        fail("signal_return post-CAS instruction fingerprint changed")
print("PASS: 112 aligned u64 zero stores at record offsets 0..888 before any record use; no memset / back edge in the region")
