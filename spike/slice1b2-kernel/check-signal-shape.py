#!/usr/bin/env python3
"""Structural no-delay guard for signal_return (Gate B pause protocol).
Scope: the <signal_return> program, from the single owner CAS (`cmpxchg_64`) to
the single `bpf_send_signal` helper call (UAPI helper 109). Proves the winner
cannot execute any loop, poll, or delay between the owner CAS and the stop
request:
  1. exactly one cmpxchg_64 (the ARMED -> REQUESTED owner CAS);
  2. exactly one bpf_send_signal call, after the CAS;
  3. no backward branch anywhere in the instruction window between them, so
     the region is a DAG and no path from the CAS to the request can loop
     (every busy-wait/poll shape needs a backward edge);
  4. the window holds at most 32 instructions, bounding every possible path
     between the CAS and the request to a straight-line run far too short to
     delay a stop request;
  5. the nearest call before the request is the bpf_ktime_get_ns timestamp.
Sibling paths that linearly interleave (the coalesced loser, the ring-loss
counter) are inside the window but never lengthen the winner path: they are
acyclic and bounded by the same window. Unrelated code elsewhere in the ELF is
not checked. Exit 0 PASS, 1 FAIL."""
import re
import subprocess
import sys

obj = sys.argv[1]
objdump = sys.argv[2] if len(sys.argv) > 2 else "llvm-objdump"
out = subprocess.run(
    [objdump, "-d", "--no-show-raw-insn", obj], capture_output=True, text=True, check=True
).stdout
m = re.search(r"^[0-9a-f]+ <\S*signal_return>:\n", out, re.M)
if not m:
    sys.exit("FAIL: signal_return not found")
lines = out[m.end() :].split("\n\n", 1)[0].splitlines()
insns = []
for line in lines:
    if ":" not in line:
        continue
    ins = line.split(":", 1)[1].strip()
    ins = re.sub(r"\s*#.*$", "", ins)  # strip trailing comments
    ins = re.sub(r" <\S+>$", "", ins)  # strip branch target symbols
    if ins:
        insns.append(ins)


def fail(msg):
    sys.exit(f"FAIL: {msg}")


KTIME = re.compile(r"call (0x5|5)$")
SEND = re.compile(r"call (0x6d|109)$")  # bpf_send_signal is UAPI helper 109
cas_idx = [i for i, ins in enumerate(insns) if "cmpxchg_64" in ins]
if len(cas_idx) != 1:
    fail(f"expected exactly one cmpxchg_64, found {len(cas_idx)}")
send_idx = [i for i, ins in enumerate(insns) if SEND.fullmatch(ins)]
if len(send_idx) != 1:
    fail(f"expected exactly one bpf_send_signal call, found {len(send_idx)}")
cas, send = cas_idx[0], send_idx[0]
if send <= cas:
    fail("bpf_send_signal must be called after the CAS")
window = insns[cas + 1 : send]
if len(window) > 32:
    fail(f"delay-shaped window: {len(window)} instructions between CAS and send_signal")
for ins in window:
    if re.search(r"\bgoto[l]?\s+-\d+|\bcall\s+-\d+", ins):
        fail(f"backward branch (loop/poll shape) between CAS and send_signal: {ins}")
nearest_call = next((ins for ins in reversed(insns[:send]) if ins.startswith("call")), None)
if not KTIME.fullmatch(nearest_call or ""):
    fail(f"the nearest call before the stop request is not the ktime timestamp: {nearest_call}")
print(
    "PASS: one CAS and one bpf_send_signal; "
    f"{len(window)}-instruction acyclic window between them, ktime timestamp "
    "immediately before the request"
)
