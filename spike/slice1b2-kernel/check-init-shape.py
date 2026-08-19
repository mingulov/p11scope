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
    if not winner or region.count("helpers::bpf_send_signal(19)") != 1:
        fail("pause winner must read ktime immediately before one SIGSTOP helper")
    winner_helpers = re.findall(r"helpers::([A-Za-z_][A-Za-z0-9_]*)", winner.group(0))
    if winner_helpers != ["bpf_ktime_get_ns", "bpf_send_signal"]:
        fail("pause winner path has an unapproved helper")

if len(sys.argv) >= 2 and sys.argv[1] == "--pause-source-only":
    if len(sys.argv) != 3:
        sys.exit("usage: check-init-shape.py --pause-source-only SOURCE")
    pause_source_guard(sys.argv[2])
    print("PASS: pause source has reserve/init/CAS/ktime/send/submit without a post-CAS loop")
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
    calls_after_cas = signal_lines[signal_lines.index("cmpxchg_64"):]
    call_ids = re.findall(r"\bcall (0x[0-9a-f]+|[0-9]+)", calls_after_cas)
    # `0x1` is map_lookup_elem on the nonwinner/missing-authorization loss
    # branch.  The source guard above is path-specific for the winner; this
    # object guard freezes the shared codegen facts (no back edge, one CAS,
    # one send helper, one terminal submit) without rejecting that fallback.
    allowed_calls = {"0x1", "1", "0x5", "5", "0x6d", "109", "0x84", "132"}
    if any(call not in allowed_calls for call in call_ids):
        fail(f"unapproved helper after pause CAS: {call_ids}")
    if sum(call in {"0x6d", "109"} for call in call_ids) != 1:
        fail("signal_return must contain exactly one bpf_send_signal helper")
    if sum(call in {"0x84", "132"} for call in call_ids) != 1:
        fail("signal_return must terminate in exactly one ringbuf submit helper")
print("PASS: 112 aligned u64 zero stores at record offsets 0..888 before any record use; no memset / back edge in the region")
