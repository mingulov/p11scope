# Phase 0 spike findings — 2026-08-10

Executed on: Linux 7.0.0-28-generic x86-64, bpftrace v0.20.2, SoftHSM2 2.6.1,
Docker 29.6.2 (storage driver **overlay2**), clang 18, host glibc 2.39,
container `ubuntu:24.04` (glibc 2.39).

## Results

| Check | Result |
| --- | --- |
| 68/68 entries resolved on stripped SoftHSM2 | **PASS** (0 UNRESOLVED) |
| Helper vaddrs == `nm -D` oracle (4 sampled) | **PASS** (all 4 exact) |
| Host capture == ground truth (stripped, attach-first) | **PASS** (`ALL COUNTS MATCH`) |
| CK_RV via uretprobe (C_Digest → CKR_OK ×50) | **PASS** |
| Container capture from host, attach-before-run | **PASS** |
| Second container observed w/o re-attach (2× / 1× / 0×) | **PASS — exactly 2×** |

## Evidence

**Discovery.** `discover` resolved all 68 v2.40 table entries to file offsets
for both the system SoftHSM2 and a `strip --strip-all` copy (`nm` → "no
symbols"). Sampled offsets matched the `nm -D` oracle exactly:
`C_Initialize 0x265e0`, `C_Digest 0x27130`, `C_Sign 0x272c0`,
`C_GenerateRandom 0x27a60`.

**Host capture (stripped provider, attach before run).** 136 probes
(68 uprobe + 68 uretprobe) attached by file offset only, before the harness
started. Captured counts vs ground truth — all exact:

```
C_Initialize 1 · C_GetInfo 3 · C_GetSlotList 1 · C_OpenSession 10
C_DigestInit 50 · C_Digest 50 · C_GenerateRandom 100 · C_CloseSession 10
C_Finalize 1        (+ C_GetFunctionList 1, deliberately unasserted)
@rv[C_Digest, 0]: 50   @rv[C_GenerateRandom, 0]: 100   → CK_RV capture works
```

**Container + shared inode.** Probes attached from the host via
`/proc/<pid>/root/...` to spike1's provider. spike1's harness ran (captured),
then **spike2 was started from the same image and its harness ran with no
re-attachment** — all counts came out exactly double. Direct mechanism
evidence: the provider `.so` has the **same inode `51969427` on different
devices** (dev 69 vs 105), i.e. two distinct overlay merged mounts sharing one
lower-layer inode.

## Notes and deviations

- **offset-vs-vaddr: still NOT settled**, exactly as the plan predicted.
  SoftHSM2's executable LOAD segment has `p_offset == p_vaddr`, so both
  columns are numerically identical and either interpretation attaches. Phase 1
  must pin this explicitly for **aya** (`UProbe::attach` takes a file offset).
  No non-PIE control was run.
- **`/proc/<pid>/root` requires root** — confirmed empirically (denied as the
  normal user, readable under `sudo`). This validates the documented privilege
  requirement rather than contradicting it.
- `timeout -s INT` was used to end captures rather than signalling the
  backgrounded `sudo` pid; simpler and deterministic. `bpftrace` exits 124 that
  way but still flushes its maps correctly.
- The `+8` `CK_FUNCTION_LIST` pointer offset worked for SoftHSM2, as documented
  — this remains an empirical property of this provider, **not** a general fact
  (canonical headers use `#pragma pack(cryptoki,1)`). The product must derive
  the offset from proxy-ng's `offset_of!` tables — **with the precondition
  that those tables describe the helper's own build target only**
  (cryptoki-sys ships pregenerated per-target bindings; only the Windows MSVC
  and generic variants are packed). This is sound because discovery dlopens
  the provider into the helper's own process, so helper ABI == provider ABI
  by construction; a class-mismatched provider fails at `dlopen` and must be
  reported as unsupported, never re-derived from foreign-ABI guesses.
- Not covered by this spike (unchanged from plan): PKCS#11 3.x interface
  discovery (SoftHSM2 2.6 is a 2.40 module), kind/Knative orchestration
  (Phase 4), aliased/non-file-backed pointer handling (SoftHSM2 has none).

## Decision

**Proceed to Phase 1: YES.**

The decisive experiment succeeded in full: an isolated helper obtained a
stripped provider's function table, mapped internal pointers to stable file
offsets, probes attached before the workload ran with no module substitution,
and every controlled call was captured — on the host and across a container
mount-namespace boundary. The shared-image-layer property, which the Knative
scale-from-zero story depends on, is confirmed on overlay2.

**Design-spec amendment required:** the cross-container inode-sharing claim can
be upgraded from "hypothesis to validate" to "validated on overlay2 (Phase 0)",
keeping the storage-driver qualifier.
