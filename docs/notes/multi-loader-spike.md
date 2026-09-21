<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Task 2.1: loader comparison spike (survey + measurements + decision)

**Date:** 2026-09-19 · **Branch:** `task-2.1/loader-spike` · **Time-boxed spike.**
**Kernel:** `7.0.0-31-generic` (x86_64, supports `uprobe_multi`) · **Toolchain:** Rust 1.88 ·
**BPF objects:** built from this worktree (`27b26da`), default 508 KiB / feature 712 KiB.

## Decision

**Proceed with Candidate A (narrow Aya backport).** Reject Candidate B's full raw
loader; borrow only its link-UAPI layout plus `bisect_attach` (vendored unwired
as `crates/bpf-multi/`).

| Check | Singles (136 links) | Multi (2 links) | Rule |
|---|---|---|---|
| Attach fds (68 offsets, entry+return) | 136 | 2 (**68x**) | >=5x PASS |
| Attach ms, default object (3 runs) | 73.9–90.8 | 4.2–9.2 (~12x) | — |
| Attach ms, feature object (3 runs) | 38.9–220.9 | 5.8–10.0 (~14x) | — |
| Events (68 fns x 3 reps, STATS) | 204 entered / 204 returned | **identical** | PASS |

All 8 firing runs (default + feature, singles + multi, 3 reps each) report exactly
204 entered / 204 returned. Raw-fd cleanup verified: BTF rejection +0 fds,
empty-offsets / cookie-mismatch / bad-path failures leak 0 fds.

## Candidate A: narrow Aya backport (WINNER)

**Lead verified via network (GitHub API + patch fetch), cargo stayed offline:**

- Aya PR #1417 "aya: add multi-uprobe attach support" by `swananan`: state
  `closed`, `merged_at 2026-07-31T18:12:53Z`, merge commit `5c1a79e0bdc36e77`,
  38 files, +1615/−255. Closes issue #992.
- Content: `uprobe.multi`/`uretprobe.multi` section parsing (`aya-obj`), `AttachMode`
  (Single/Multi/Unknown), load with `BPF_TRACE_UPROBE_MULTI` (48), raw
  `bpf_link_create_uprobe_multi` (`aya/src/sys/bpf.rs`), batched symbol resolution,
  per-point cookies, `ProbeLinkInner` One/Many links, Unknown-mode fallback
  (multi first, singles on `MultiLinkNotSupported`/EINVAL), pid mapping
  (AllProcesses→0, CallingProcess→real pid, OneProcess→pid).

**Fit on pinned Aya 0.14 (no assumption):**

- `third-party/sources.json` pins `aya =0.14.0` + `aya-obj =0.3.0` (revision 1,
  3 + 2 ordered patches); `[patch.crates-io]` selects
  `third-party/src/aya-0.14.0-p1/` (+ `aya-obj-0.3.0-p1/`); trees are ignored,
  manifest + patches tracked; `scripts/prepare-dependencies.py --offline`
  validates receipts (exit 0 in this worktree).
- The `src/programs/mod.rs:~700` attach-type hook EXISTS in 0.14:
  `load_program_with_attach_type(prog_type, expected_attach_type, data)` is
  already used by cgroup/tcx programs; `UProbe::load` is the only uprobe
  caller still hardcoded to `load_program_without_attach_type`.
- Zero bindings changes needed: `aya-obj` 0.3.0 generated bindings already carry
  `BPF_TRACE_UPROBE_MULTI = 48`, `BPF_LINK_TYPE_UPROBE_MULTI = 12`,
  `BPF_F_UPROBE_MULTI_RETURN = 1`, and the full `uprobe_multi` `bpf_attr` member
  (path/offsets/ref_ctr_offsets/cookies/cnt/flags/pid).
- Production backport scope is therefore narrow: section parsing for multi twins
  (`aya-obj`), load-flag selection (`aya`), link creation + fallback (`aya`).
  Full PR symbol batching is NOT needed (p11scope attaches `AbsoluteOffset` only).
  No eBPF source changes (plain `#[uprobe]` sections work once loaded with 48).

**Spike backport (`/tmp` only, NOT in repo):** copied vendored Aya to
`/tmp/p11-multi-spike/aya-multi`, applied ~120 lines (link-create args + helper
in `sys/bpf.rs`; `load_multi()` + absolute-offset `attach_multi()` + 2 error
variants in `programs/uprobe.rs`). Compiles clean on 1.88 against patched
`aya-obj` (map-relocation fix retained). It loads the REAL objects with
`expected_attach_type=48` for `p11_entry`/`p11_return` (all other programs normal),
retaining ELF/BTF/relocation/map sharing, frozen CONFIG, and tail-call fd
plumbing (`TAIL_CALLS[0]=worker` always, `[1]=template_second` for feature).

## Candidate B: vendored raw helper (REJECTED as loader, BORROWED as layout)

**osslscope (`/home/user/src/m/osslscope-ws`, read-only):**

- `ossl-bpf-sys` v1.0.0 (`crates/bpf-sys/src/lib.rs`, 306 lines, `libc`-only):
  raw `map_create` (raw dims + name), `prog_load_kprobe` (hardcodes
  `expected_attach_type=48`), `link_create_uprobe_multi` /
  `link_create_uretprobe_multi` (member-flags at attr offset 52, asserted 64 B),
  `map_update_elem`, debug-only `token_create`. Zero aya coupling. Production
  since 1.0.0; sibling-measured 504 probes: multi 17.8 ms / 8 fds vs singles
  109 ms / 511 fds / 46 s teardown (their numbers, not ours).
- `src/loader.rs` (1033 lines, goblin): pure `prepare()` + caps `load()`.
  Fail-closed shape gate REJECTS the real p11scope objects on at least five
  counts (verified by running the gate in `/tmp` against both objects):
  `.BTF`/`.BTF.ext` forbidden (p11scope: 35 KiB + 53 KiB default, larger
  feature); only `R_BPF_64_64`/`R_BPF_64_32` relocs (p11scope: 200+ relocs incl.
  BTF/CO-RE); only legacy 28 B `maps` defs (p11scope also has `.maps` BTF task
  storage: `OWNER_CTL`, `COOKIE_CTL`, `TASK_COOKIE`, `THREAD_OWNER`,
  `ROOT_AFFILIATION`, `ROOT_CTL`); only uprobe/uretprobe/`.text` (p11scope has
  `raw_tp/*`, `tp_btf/task_newtask` needing vmlinux BTF); no `ProgramArray` /
  tail-call publishing, no BTF program load (`func_info`/`line_info`).
  Supporting p11scope would reimplement `aya-obj` — large, risky, duplicate
  maintenance. Spike result: both objects rejected (`frozen shape forbids .BTF`)
  with +0 fds.
- `src/plan.rs`: `attach_group` leaf + `bisect_attach` (generic, ≤2n−1 attempts;
  EPERM/EACCES fail-fast whole-slice; EINVAL-class incl. RHEL 524 bisects).
  Ported into the vendored helper (see below).

**kryprobe (`/home/user/src/m/kryprobe-ws`, read-only):** 64-slot (`COUNT_SLOTS`)
Pid-only spine (`spine.rs` `#[uprobe(multi)]`), userspace fan-out per pid,
`pid=0` refusal, 6.12 floor, Unreleased skeleton. Wrong shape for p11scope
(512 slots, AllProcesses + in-BPF `PID_FILTER`, 5.15 floor with fallback).
Ideas only (generation cookies, receipts); no code vendored.

## Spike method (`/tmp`, real objects only)

- **Objects:** `p11scope-ebpf-default` (519,472 B, 13 programs, BTF+BTF.ext,
  ~200 relocs) and `p11scope-ebpf-feature` (728,328 B, 18 programs incl. all 5
  unsafe entry variants). Sections: `.text`, `uprobe`, `uretprobe`,
  `raw_tp/*`, `tp_btf/task_newtask`, `maps` (16 legacy defs) + `.maps` (6 BTF
  maps), `license`, `.BTF`, `.BTF.ext`. A trivial counting program was NEVER
  used as load input.
- **Fixture:** `/tmp/p11-multi-spike/fixture/libfixture.so` (68 exported
  `fixture_fn_*`, file offsets `0x2100–0x2530` in executable LOAD) + `caller`
  (dlopen, calls all 68, N reps). Offsets file checked into the spike dir.
- **Harness:** `/tmp/p11-multi-spike/harness` (Rust 1.88, `--offline`, patched
  Aya path dep + patched `aya-obj` via `[patch.crates-io]` + worktree
  `ebpf-common` read-only). Per run: `EbpfLoader` with vmlinux BTF (all maps
  shared), load 13/18 programs (multi runs: `p11_entry`/`p11_return` via
  `load_multi`), minimal aggregate policy (`CONFIG=SYSTEM|AGGREGATE`, valid per
  `valid_config`; `OWNER_CTL.limit=THREAD_OWNER_LIMIT`), **freeze CONFIG**
  (`BPF_MAP_FREEZE`), publish tail calls (worker id + optional second id
  recorded), attach (singles: 68+68 `AbsoluteOffset` + `attach_cookie(slot,0)`;
  multi: 1 entry + 1 return link, `pid=0`), time with `Instant`, count fds via
  `/proc/self/fd`, run caller (3 reps), read back `STATS` entered/returned
  summed over 68 slots x all CPUs. Aggregate mode keeps STATS exact without
  identity/DESCRIPTOR setup (identity-gated sections return after counting).
- **Failure drills:** raw-prepare gate on both objects; multi `attach_multi`
  with empty offsets, cookie-length mismatch, nonexistent path — fd delta
  asserted after each.

## Measurements (kernel 7.0.0-31, `sudo`, reps=3 → 204 calls expected)

| Run | Attach ms | fd before→after (delta) | entered | returned | tail ids |
|---|---|---|---|---|---|
| singles/default #1 | 39.94 | 40→176 (136) | 204 | 204 | worker only |
| singles/default #2–4 | 88.60 / 90.76 / 73.86 | 136 | 204 | 204 | worker only |
| multi/default #1 | 3.52 | 40→42 (2) | 204 | 204 | worker only |
| multi/default #2–4 | 4.15 / 7.72 / 9.19 | 2 | 204 | 204 | worker only |
| singles/feature #1 | 209.83 | 46→182 (136) | 204 | 204 | worker + second |
| singles/feature #2–4 | 66.08 / 220.91 / 38.89 | 136 | 204 | 204 | worker + second |
| multi/feature #1 | 6.67 | 46→48 (2) | 204 | 204 | worker + second |
| multi/feature #2–4 | 9.96 / 5.77 / 7.02 | 2 | 204 | 204 | worker + second |
| raw-prepare default/feature | — | +0 / +0 | — | — | rejected: `.BTF` |
| fd-cleanup (empty/mismatch/badpath) | — | 0 / 0 / 0 leaks | — | — | all rejected |

Singles attach time is noisy (39–221 ms, perf-event contention); multi is stable
(3.5–10 ms). fd deltas are exact in all 16 firing runs. Detach cost was not
re-timed here (sibling data: 46 s singles teardown vs instant multi drop);
Task 2.2 re-times teardown on the reference desktop.

## Recommendation for Task 2.2 (mixed loading + regrouped attach)

1. **Backport (third-party revision bump p1→p2):** `aya-obj` multi-section
   parsing for `p11_entry`/`p11_return` twins + `aya` load-flag selection and
   multi link creation with Unknown-mode fallback, following PR #1417 minus
   symbol batching. Keep `third-party/sources.json` recipe, hashes, export
   closure, license attribution, offline resolution, and the ring-reader +
   map-relocation corrections.
2. **Wire `crates/bpf-multi/`:** add its `Cargo.toml` (`libc`-only), workspace
   member, and root path dependency; use it for multi link creation or retire
   it if the backported `UProbe::attach` covers all call sites (spike proves
   both compositions load the same bytes; 2.2 picks one, not both).
3. **Dual-path:** functional probe → multi on 6.6+ (policy floor per sibling
   data: 6.9+, plus the process-scoped pid-filter probe from Aya PR #1696
   once reviewed), today's singles otherwise (5.15 floor + qualified RHEL
   backports). `pid=0` + in-BPF `PID_FILTER` for `Scope::Pid` under multi.
4. **Regroup + registry + oracles** per `FULL-multi.md` reuse sketch steps 1–2,
   4–7 (map-freeze ordering, `PublishTailCalls` fd plumbing,
   `RegisteredLink::MultiUProbe`, `"multi"` mechanism value + goldens, doctor
   self-link row). Group retirement is explicit rebuild (plan Task 2.3).

## Deviations recorded

- **No `Cargo.toml` / workspace wiring for `crates/bpf-multi/`:** vendored
  sources only (`src/lib.rs`). Wiring is reserved for Task 2.2 to avoid
  conflicts with parallel workers (per task brief).
- **Helper is link-only, not full `ossl-bpf-sys`:** `prog_load`/`map_create`/
  `prepare` are rejected for BTF objects (proven above); loading stays in
  backported Aya. The helper carries link creation, `bisect_attach`, and errno
  classification with dual attribution (ossl UAPI + Aya #1417 semantics).
- **Backport patch itself deferred to Task 2.2** as a `third-party/` revision
  bump: patching tracked `third-party/` files would violate this task's
  NEW-only constraint and collide with parallel workers. The `/tmp` spike
  backport is throwaway; 2.2 authors the real patch with RED-then-GREEN tests.
