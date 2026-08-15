# Productization slice 1 — discovery and trust — design

**Date:** 2026-08-15
**Status:** Approved in discussion (owner); revised twice after external review
(2026-08-15: blockers and clarifications in §4.1, §4.3, §4.4, §4.5, §4.7, §4.9, §4.12,
§4.13; second pass: shared attach targets, pause authority/generation ownership,
live-discovery loss evidence, consistency edits; third pass: pausing limited to `run`
children, no fresh-pidfd recovery, semantic-state purge on module ambiguity). Slice 1a
approved for planning; Slice 1b pending reviewer confirmation of the third pass
**Input:** `docs/notes/2026-08-15-architecture-and-gap-analysis.md` (§3–§5, Addendum A1–A7)
**Supersedes for discovery/attach authorization:**
`docs/superpowers/plans/2026-08-13-manifest-provenance.md` (the lease/provenance/hardened
lane is removed by this design), the discovery/attach parts of
`2026-08-12-v0.1-corrective-release-design.md`, and the "Architecture" section of
`2026-08-10-pkcs11-scope-design.md`. The privacy model
(`2026-08-13-safe-and-unvalidated-metadata-design.md`) is unchanged by this slice; its
extension (safe params) is slice 2.
**Follow-on slices:** 2 = capture quality (ring/epoll, budgets, safe params, per-module
profile sections, filters, snapshots); 3 = structure/DRY refactor, docs consolidation, full
CI matrix; then AArch64/32-bit. In `docs/superpowers/plans/ROADMAP.md` these are
"Productization Slice 1a/1b/2/3" (the historical "Phase 1a/1b" names remain in use there);
updating the ROADMAP is the first documentation task of plan 1a.

## 1. Goal

Make `p11scope` usable as a product on ordinary hosts and clusters:

- discover a target's PKCS#11 function tables **without executing provider code** and
  without copying anything into or out of containers;
- attach with the **minimum privileges uprobes need** (`CAP_BPF`+`CAP_PERFMON`, or
  `CAP_SYS_ADMIN` where `perf_event_paranoid ≥ 3`; `CAP_SYS_PTRACE` for cross-uid targets
  and for same-uid memory scans under Yama `ptrace_scope ≥ 1`) — no `CAP_LEASE`, no
  root-owned sibling helper, no sysctl, no static binary;
- keep the observer honest: every report names how the tables were found
  (`discovery`), how the provider identity was pinned (`authority`), and any window in
  which calls could have been missed (`attach_gap_ms`, `pause`);
- add the three operator commands the review found missing: `run -- cmd`, `inspect --pid`,
  `doctor`;
- remove the lease/provenance/hardened-oracle lane (≈5.8k product lines) and its
  operational requirements, recording in history that it existed and was removed
  deliberately.

Non-goals for this slice: per-module `mechanisms`/`sessions` sections in the profile
(slice 2; this slice keys state per module — §4.13 — and records per-module `functions[]`),
safe-policy params/templates (slice 2), ring/epoll and budget fixes (slice 2), module
refactor of `attach.rs`/evidence plumbing (slice 3), AArch64/32-bit, `uprobe_multi`,
cgroup-freezer pause, manifest catalog tooling.

## 2. Decisions carried in from the review (fixed)

| Topic | Decision |
| --- | --- |
| Discovery, default | memory scan of the target's mappings + loader hook for future loads; export hooks as cross-check / dynamic-table fallback |
| Helper | `p11scope-discover` stays a standalone offline tool ("executes provider code"); the observer never invokes it; `--manifest` accepted, verified by SHA-256 |
| Static relocation scan of files | not now |
| Race between table hand-out and attach | pause is **`run`-child-only**: the observer's own child (its PID cannot be recycled before the observer reaps it) is armed before its exec barrier is released and stopped by `bpf_send_signal(SIGSTOP)` at loader/export hooks; external `--pid`/`--cgroup` discovery never pauses and reports `attach_gap_ms`; `--pause auto\|never\|always` (`always` outside `run` is refused) |
| Hook registry | built-in `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`, `NSC_GetFunctionList`, `FC_GetFunctionList`; `--hook-symbol NAME[:functionlist\|interfacelist\|interface]` adds names (default ABI `functionlist`) |
| Shared attach targets | attach key is `{pinned object identity, offset}` across modules; a target claimed by ≥2 modules is attached once, module-ambiguous, count-only for state, PARTIAL (§4.7) |
| Live-discovery loss | own evidence counters (`discovery_ring_loss`, `discovery_state_failures`, `discovery_truncated`), never merged with call-event loss; nonzero → PARTIAL (§4.3) |
| Provider identity | pinned fd (opened via `/proc/<pid>/root/<path>`, identity-checked against `maps`); SHA-256 **once** at attach; `fstat` `(ino, size, ctime)` compared every frame and at end → `provider_changed`; no re-hash |
| Manifest input | trusted operator input, structurally validated, labelled `manifest`, corroborated by scan/live when possible; uncorroborated at end → PARTIAL |
| Frozen policy vs later modules | semantics move into a capture-independent frozen `DESCRIPTORS` table selected by the attach cookie; slots are dynamic data-map indices (§4.7) |
| Multi-module state | `(process, module, session)` keys land in slice 1b (§4.13); per-module JSON sections in slice 2 |
| Old authorization lane | removed now (leases, provenance rediscovery, hardened oracle, glibc staging, supervisor fork, `--provenance-module`, `--trusted-workload`, helper ownership rules, `suid_dumpable`, `/run/p11scope`, exit 78) — restorable from git; commit message says so |
| Kernel | upstream 5.15 feature baseline; runtime probes authoritative; newer features (uprobe_multi 6.6, bounded-spin pause) feature-probed later, never required |
| CI | GitHub Actions: unprivileged checks on every push + `sudo` BPF e2e job on `ubuntu-24.04`; root gates also runnable locally by one command; text-grep contract tests deleted with the lane |
| Schema | `pkcs11-scope/observed-profile/v2` (nothing published yet) |
| Slicing | one spec (this), two plans: **1a** trust simplification, **1b** discovery engine + commands |

## 3. Architecture

```
                 ┌────────────── p11scope (observer, capability-only or root) ──────────────┐
 targets         │  cli.rs ── CaptureArgs (one parser)                                       │
 --pid N         │     │                                                                     │
 --cgroup C      │     ▼                                                                     │
 run -- cmd      │  discovery::Engine                                                        │
                 │   ├─ sources: initial sweep(/proc), exec/fork events, loader-hook events, │
                 │   │           export-hook events, --manifest files, periodic sweep       │
                 │   ├─ scan.rs      maps → PKCS#11 objects → CK_FUNCTION_LIST/CK_INTERFACE  │
                 │   ├─ elf.rs       .dynsym lookup (hook registry), symbol → file offset    │
                 │   ├─ pause.rs     SIGSTOP/SIGCONT guard (adaptive)                        │
                 │   └─ identity.rs  pinned fd, sha256 once, fstat pin, provider_changed     │
                 │     │  Module{dev,ino,path,identity} + tables → plan::AttachPlan (per module)
                 │     ▼                                                                     │
                 │  attach::Session (BPF object load, policy publish/freeze, probes)          │
                 │     │  + discovery programs: dl_debug_state uprobe, export entry/return,   │
                 │     │    sched_process_exec (cgroup/run scope), existing fork tracepoint   │
                 │     ▼                                                                     │
                 │  events::Drain ─▶ semantics/process/trace/render (unchanged)  ─▶ output    │
                 │  doctor.rs / inspect.rs / run.rs                                          │
                 └────────────────────────────────────────────────────────────────────────────┘
 p11scope-discover (offline, optional): dlopen provider → manifest v4 (unchanged crate)
```

Data flow for one module: *event or sweep names a pid* → `scan.rs` reads
`/proc/<pid>/maps`, opens each candidate object via `/proc/<pid>/map_files/<range>` (fallback
`/proc/<pid>/root/<path>`), checks its `.dynsym` for a hook-registry symbol, reads the object's
non-executable mappings through `/proc/<pid>/mem`, finds tables, converts pointers to file
offsets → `Module` record (dedupe key `(dev, ino)`) → `identity.rs` pins the fd and hashes →
`plan::build` per module → `Session::attach_module` (probes are inode-wide, scoped in BPF by
pid/cgroup as today) → if the pid is paused, `SIGCONT`. Every module's discovery outcome is
recorded in evidence.

## 4. Components

### 4.1 `discovery::scan` — memory table scan (new)

Input: pid, optional module path hints (`--module`), hook registry. Steps:

1. Parse `/proc/<pid>/maps` (reuse `p11scope_manifest::maps::parse_maps`). Group mappings by
   `(dev, ino)`; keep file-backed groups that have at least one `r-x` mapping.
2. Candidate filter: if `--module` hints exist, only groups whose path matches a hint (after
   `/proc/<pid>/root` normalisation) or whose inode equals the hint's inode; otherwise every
   group whose ELF `.dynsym` exports a hook-registry symbol (`elf.rs`, `object` crate, read
   through the pinned fd). Non-ELF, ELFCLASS32, or foreign-arch objects are recorded as
   `skipped: {reason}` (32-bit counting mode is a later slice).
3. Read the candidate group's non-executable mappings (`r--`, `rw-`) via `pread` on
   `/proc/<pid>/mem` (bounded: 64 MiB per object, 512 MiB total; larger → `skipped:
   too_large`). `mem` requires `PTRACE_MODE_ATTACH` access (§4.9); when it is unavailable the
   scan is reported as `unavailable: ptrace` and discovery relies on the hooks (§4.3), whose
   table reads happen in BPF and need no `/proc` access.
4. Table detection over 8-byte words against the **whole executable mapping snapshot of the
   process** (not just the candidate's own mappings — wrapper providers keep the table in one
   object and the functions in another, as the `lazy_wrapper` fixture and manifest v4
   `objects[]` already model): a word `w` with `w & !0xffff == 0`, `major = w & 0xff ∈ {2,3}`,
   `minor = (w >> 8) & 0xff` plausible (2.x: 0..=40; 3.x: 0..=2), followed by `N` words that
   each fall inside a **file-backed `r-x` mapping of any object** in the snapshot, where `N` =
   67 (2.00), 68 (2.01–2.40), 92 (3.0/3.1), 104 (3.2) by version. Record every match;
   overlapping matches keep the longest. Also detect `CK_INTERFACE` arrays: consecutive
   `{name_ptr, table_ptr, flags}` triples where `name_ptr` reads as a NUL-terminated string
   ≤ 64 bytes and `table_ptr` is a detected table or a pointer into a non-executable mapping;
   name `"PKCS 11"` → standard, else vendor (present, undecoded), matching today's
   `surfaces`/`vendor_interfaces` evidence. Non-file-backed pointers → `skipped` entries.
   Acceptance criteria for the detector (measurable, §5): every table in the fixture matrix
   (2.00/2.40/3.0/3.2, alias, vendor-interface, lazy-wrapper) is found with offsets equal to
   `p11scope-discover`'s, and zero false positives on the fixtures plus the host's SoftHSM2,
   OpenSC, NSS softokn (`NSC_`+`FC_`) and p11-kit proxy where installed.
5. Pointer → object + offset: `offset = ptr - mapping.start + mapping.file_offset` for the
   executable mapping containing `ptr` (`crates/discover/src/maps.rs::resolve`, moved into
   `manifest::maps` so both binaries share it). Three identities are kept apart, exactly as
   manifest v4 does: the **table-owning object** (the "module" for reporting), each **object
   supplying entry points**, and the **(object, offset)** each uprobe is attached to. Every
   attach object is pinned and hashed (§4.5) individually.
6. Output: `Module { id: ModuleId, key: (dev,ino), path, sha256, tables: Vec<Table{version,
   source: scan, entries: [(object, offset, names)]}>, interfaces, skipped }`, feeding the
   existing `plan::build` (alias grouping, `entries_seen`, surfaces) unchanged in semantics.
   `ModuleId` is a capture-local index; the stable identity in output is
   `{dev, ino, sha256, path}` (§4.8).

Cost: reading a few hundred KB–MB and a linear word scan — milliseconds. Idempotent; a
module already attached (same `(dev,ino)`, same table set) is not re-attached; a new table set
on a known inode is reported as `tables_changed` evidence and attached additively.

### 4.2 `discovery::elf` (new, small)

`exports(fd) -> Vec<String>` restricted to the registry names; `symbol_offset(fd, name) ->
Option<u64>` (dynsym value → file offset via program headers) for the loader hook and export
hooks. Uses the `object` crate already in `p11scope-manifest`. Refuses non-x86-64/ELFCLASS64
with a named reason (this slice), so foreign objects are skipped, not misread.

### 4.3 Loader hook and export hooks (BPF + userspace)

BPF programs added to `crates/ebpf`. Discovery records are written to a separate small ring
buffer `DISCOVERY` (64 KiB) using `RingBuf::reserve` (records up to ~1 KiB are filled in map
memory, never on the BPF stack). Pointer values in these records are internal and never
rendered.

- `dl_debug_state` (uprobe, entry) attached to the target's `ld.so` inode at the exported
  `_dl_debug_state` offset (glibc; musl `_dl_debug_state` verified in a spike task, fallback:
  `dlopen` return in libc). Body: scope check → record `{kind: LOADER, pid, tid}` → if
  `CONFIG.PAUSE` and pid ∈ `PAUSE_PIDS` (only ever the `run` child, §4.4) →
  `rc = bpf_send_signal(SIGSTOP)`, and `stop_requested = (rc == 0)` is stored in the record
  (`rc == 0` only means the request was accepted; the whole-group confirmation in §4.4 is
  what makes a pause).
- Export hooks, attached per PKCS#11 object at each hook-registry symbol found, with one
  entry/return pair **per ABI** (the three exports do not share a signature):
  - `C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pp)` (also `NSC_`/`FC_` variants): entry
    stashes `arg0`; return: only if `rv == CKR_OK`, read `*pp` → table pointer → read the
    version word and `N` pointers (`N` by version, ≤ 104) with `bpf_probe_read_user` into the
    reserved record `{kind: FUNCTION_LIST, symbol_id, pid, tid, table_ptr, version, n, ptrs[]}`.
  - `C_GetInterfaceList(CK_INTERFACE_PTR list, CK_ULONG_PTR count)`: entry stashes `arg0` and
    `arg1`; return: ignore the sizing idiom (`list == NULL`) and any `rv != CKR_OK`
    (including `CKR_BUFFER_TOO_SMALL`); otherwise read `*count` bounded to 16, then up to 16
    `CK_INTERFACE{name_ptr, table_ptr, flags}` triples, classify the name (≤ 32 bytes read on
    the BPF stack, compared, discarded) and, for `exact_standard` entries, read the table
    (version + `N` pointers) → one record per interface `{kind: INTERFACE, index,
    name_class, flags, table…}`.
  - `C_GetInterface(name, pVersion, CK_INTERFACE_PTR_PTR ppInterface, flags)`: entry stashes
    `arg2`; return: only if `rv == CKR_OK`, read `*ppInterface` → one `INTERFACE` record as
    above.
  Interface names are classified in BPF and only the class is emitted (`exact_standard`
  = `"PKCS 11"`, `other`, `null`, `unreadable`); the bytes are never persisted or rendered
  in capture output, matching the privacy allowlist. (`inspect` and manifests, which are
  discovery tools rather than capture output, keep the lossy name as `p11scope-discover`
  does today.) `--hook-symbol NAME` binds a name to the `functionlist` ABI unless suffixed
  `:interfacelist` or `:interface`.
  Read failures increment `discovery_read_failures` and produce a record with `n = 0`.
  Independent evidence for the live path (nonzero → PARTIAL, never merged with the call-event
  loss counter): `discovery_ring_loss` (`RingBuf::reserve` failed), `discovery_state_failures`
  (entry-state insert failed or an entry was overwritten before its return), and
  `discovery_truncated` (interface count above 16, table longer than the record, or a record
  that userspace could not decode). Optional pause as for the loader hook.
- `sched_process_exec` (tracepoint) for `--cgroup` and `run` scopes: record `{kind: EXEC,
  pid}`; pauses **only** in `run` scope (the child of `run`), never in cgroup scope (busy pods
  must not be stalled per exec).
- `sched_process_exit` (tracepoint): when the exiting task is a thread-group leader
  (`pid == tgid`), delete its `PAUSE_PIDS` entry in BPF. This is cleanup only; the
  correctness boundary against PID reuse is that `PAUSE_PIDS` only ever contains the
  observer's own un-reaped `run` child (§4.4).

Userspace handling (`discovery::Engine::on_event`), every per-pid action guarded by the pid's
pinned identity (§4.5; PID reuse aborts the action):

- `EXEC`: read `/proc/<pid>/exe`'s `PT_INTERP` (via `/proc/<pid>/root`), pin that `ld.so`
  inode; if not yet hooked, attach `dl_debug_state` there (once per inode). In `run` scope,
  then resume.
- `LOADER`: if `_r_debug` is resolvable **and** `mem` is accessible, read `r_state` and act
  only on `RT_CONSISTENT`; otherwise scan on every hit (RT_ADD hits find nothing because
  unrelocated tables do not match). Scan the pid; attach new modules; resume if paused.
- `FUNCTION_LIST` / `INTERFACE`: build the table from the record (no `/proc/<pid>/mem`
  needed), resolve pointers against a fresh `maps` snapshot, cross-check against the scan
  result for that object when one exists: agreement → `corroborated`; a table not found by
  scan (dynamically built, or scan unavailable) is attached and labelled `source: live`;
  disagreement (same object, different offsets) attaches the union and forces `PARTIAL` with
  `discovery_conflicts += 1`.
- Periodic sweep (every tick, cheap): any in-scope pid not yet scanned gets scanned when
  `mem` is accessible; in-scope pids come from the `--pid` (only that pid; PID scope does not
  follow forks), from `cgroup.procs` of the target cgroup and its descendants at start plus
  fork/exec events for cgroup scope, and from the child for `run`. This self-heals the
  exec-time window in cgroup scope where the loader hook was armed late.

Uprobes on `ld.so`/`libc` are inode-wide: every process on the host using that loader takes
the trap on library-load events while the observer runs (estimated ~1–3 µs each, to be
measured; scope-filtered first). Documented in usage as the one host-wide effect.

### 4.4 `discovery::pause` — `run`-child-only stop/continue

Why `run`-child-only: a numeric PID returns to the allocator when the process is reaped,
regardless of pidfds held, so any table keyed by an external pid can name a recycled process
between the observer's checks and the hook's `SIGSTOP`; and resuming "that pid" afterwards
could resume an unrelated process that was legitimately stopped. The one process whose PID
cannot be recycled behind the observer's back is its own child, because only the observer
reaps it. Automatic pausing is therefore limited to `run` children in this slice; external
`--pid`/`--cgroup` discovery never pauses and reports `attach_gap_ms`. (A BPF-checked
generation token would generalise this later; not in scope.)

- Arming (`run` only): the child is forked, put in its own session, and held at its
  pre-exec barrier; the parent inserts the child pid into `PAUSE_PIDS`, proves resume
  authority once (`pidfd_send_signal(pidfd, 0)`; the child has the observer's credentials, so
  this only fails under exotic LSM policy — then `run` refuses to arm and continues unpaused,
  reporting it), and only then releases the barrier. `--pause auto` = pause the `run` child,
  nothing else; `always` outside `run` is refused with a named reason; `never` arms nothing.
- BPF side: at the child's exec event and at loader/export hooks, `stop_requested =
  (bpf_send_signal(SIGSTOP) == 0)` (a rejected request — task exiting — is reported as such).
  `SIGSTOP` is delivered before the discovering thread executes its next user instruction;
  other threads stop at their next return to user mode.
- Userspace ownership: on each `stop_requested` record for the child it (1) confirms the whole
  thread group is stopped (`/proc/<pid>/task/*/stat` state `T`, bounded wait 100 ms) — only
  then the pause counts as `paused` and a claimed zero gap requires all probes attached before
  resume; otherwise `pause: partial` with the measured gap; (2) after attach, resumes exactly
  once through the pidfd it already holds. There is no "fresh pidfd" recovery path. A `Drop`
  guard resumes any outstanding stop on every error path and on Ctrl-C/SIGTERM.
- Accepted and documented: a third party stopping the child inside the window (our `SIGCONT`
  resumes it — standard signals neither queue nor count); an observer `SIGKILL` inside the
  ~ms window leaves the child stopped; `doctor` lists in-scope processes in state `T` whose
  stop is unexplained.
- Timing: `attach_gap_ms` = hook-event timestamp → last probe attached, per module; initial and
  periodic scans record `scan_ms` and `attached_at_ms` (relative to capture start) per module,
  so a mid-run attach shows when observation began even though calls before it are simply
  outside the window.

### 4.5 `identity` — pinned provider identity (replaces reuse/provenance)

- Process pinning: every per-pid action (scan, `root` walk, resume) uses the pid's pinned
  identity — `pidfd_open` when available (existing `process.rs` logic), else
  `/proc/<pid>/stat` start time; a mismatch means PID reuse and the action is dropped with an
  evidence note.
- Object pinning: open the object through `/proc/<pid>/root/<path>` (primary; needs only
  `PTRACE_MODE_READ`); `/proc/<pid>/map_files/<start>-<end>` is used only when the observer has
  `CAP_CHECKPOINT_RESTORE`/`CAP_SYS_ADMIN` (its `get_link` requires it). In both cases the
  opened fd's identity is compared with the mapping's `(dev, ino)` via the existing
  `mapping_file_key` translation (fdinfo/mountinfo, so overlay/btrfs device numbers match);
  a mismatch means the path was retargeted and the object is `skipped: identity_mismatch`.
  Keep the fd for the capture, `fstat` → `(dev, ino, size, ctime, mtime)`, SHA-256 once, GNU
  build-id if present. Attach through `/proc/self/fd/N` (existing mechanism).
- Every frame and at end: `fstat` again; any change in `(ino, size, ctime)` →
  `provider_changed: true` and `PARTIAL` (`ctime` is not settable from userspace).
- Evidence: `authority: "hash-pinned"` (the only value this slice emits).

### 4.6 CLI (`cli.rs`, one parser; `main.rs` thin)

```
p11scope profile [--pid N | --cgroup PATH] [--module PATH]... [--manifest FILE]...
                 [--mode profile|metrics] [--duration 30s|5m|1h] [-o FILE]
                 [--hook-symbol NAME[:abi]]... [--unsafe-unvalidated-metadata]
p11scope trace   [same scope/discovery options] [--duration] [-o FILE]
p11scope run     [profile options except scope] [--trace] [--pause auto|never|always]
                 [--kill-on-timeout] -- CMD ARGS...
p11scope inspect --pid N [--module PATH]... [--json]
p11scope doctor  [--pid N] [--module PATH] [--cgroup PATH]
p11scope-discover ...   (unchanged standalone tool)
```

- `--module` is optional; without it every PKCS#11-looking object in scope is discovered.
- `--duration` accepts bare seconds (compat) and `s|m|h` suffixes.
- Ctrl-C and `SIGTERM` both end a capture cleanly (same flag).
- Removed: `--provenance-module`, `--trusted-workload`, `p11scope discover` subcommand,
  exit code 78.
- `run`: fork; child `setsid()` then `raise(SIGSTOP)` before `exec` (the barrier); parent
  records the pid, publishes PID scope, arms `PAUSE_PIDS` and the exec tracepoint (§4.4),
  releases the barrier; at the child's `exec` event the BPF side stops it again so the loader
  hook can be armed on its `ld.so` before any library loads (§4.3). Lifecycle: the capture ends when the child exits (reaped by `run` with `waitpid`);
  `run` then finalises and exits with the child's status (signal → 128+n; exec failure →
  127 with the OS error). If `--duration` elapses first, the capture finalises and the child
  keeps running (`child_still_running: true` in evidence) unless `--kill-on-timeout` (SIGTERM
  to the child's process group, then SIGKILL after 5 s). SIGINT/SIGTERM received by `run` are
  forwarded to the child's process group and `run` finalises when the child exits (a second
  Ctrl-C sends SIGKILL). Scope is the child pid only: forks/children of the child are not
  observed in this slice (PID scope semantics unchanged); documented, `--cgroup` remains the
  answer for forking workloads.
- `inspect`: runs the scan only (no BPF, no pause), prints modules, tables (version, count,
  aliases), interfaces, identity; needs `maps`/`mem` access to the target (§4.9): same-uid
  targets when the ptrace policy permits, otherwise `CAP_SYS_PTRACE`.
- `doctor`: table of checks and a verdict per lane: kernel release, BTF, lockdown state,
  `kernel.perf_event_paranoid`, `kernel.yama.ptrace_scope`, effective capabilities, BPF map
  create probe, uprobe `perf_event_open` probe on the observer's own libc, `/proc/<pid>/maps`
  (READ) and `/proc/<pid>/mem` (ATTACH) access separately (if `--pid`), cgroup path readable
  (if `--cgroup`), `_dl_debug_state` resolvable in the target's loader, `bpf_send_signal`
  availability, ring-buffer/attach-cookie/`uprobe_multi` feature probes, stopped in-scope
  processes; prints which discovery methods (scan / live) and lanes are available and exits
  non-zero if the requested lane is unavailable. No BPF program stays loaded after `doctor`.

### 4.7 Attach engine changes (`attach.rs`) — immutable semantics, dynamic slots

The safe-metadata design requires every policy map to be published and frozen before any
probe attaches, and no control-map mutation afterwards. Today `SLOT_SEMANTICS` is an
`Array<SlotSemantics>` indexed by attach slot and frozen at start, which is incompatible with
attaching modules discovered later. Resolution — move semantics out of the per-slot map and
into the attach cookie:

- `DESCRIPTORS`: `Array<SlotSemantics>` with a fixed, capture-independent content — one entry
  per published function name (104) plus `COUNT_ONLY` (index 0) — published, read back and
  frozen at start exactly like today's policy maps. It never changes; every possible descriptor
  a slot could carry is already in it (an alias slot uses the shared descriptor when every
  name agrees, else `COUNT_ONLY`, decided in userspace at discovery time as today).
- Attach cookie = `slot_index (low 32) | descriptor_index (high 32)`. BPF derives `slot` for
  `STATS`/`RV_COUNTS`/`START`/`Event` and `DESCRIPTORS[descriptor_index]` for semantics; an
  out-of-range descriptor index falls back to `COUNT_ONLY` (fail closed).
- The global attachment key is `{pinned object identity (dev, ino, sha256), offset}`,
  across modules. Slot indices are allocated monotonically per new attachment key from a
  single space of `MAX_SLOTS` (512) — indices into dynamic data maps only, so allocating them
  after the freeze mutates no control map. Overflow → `modules_skipped` with a reason, never
  truncation. Capacity note: 512 slots ≈ four modules of 104 unique offsets (proxy + backend
  fits); a gate exercises proxy + provider in one process; raising `MAX_SLOTS` is a later knob.
- Shared targets: each attachment records `module_ids[]`. When a second module claims an
  already-attached `{object, offset}`, it is **not** attached again (no double counting); the
  userspace slot→module table marks the slot `module_ambiguous`, the semantic layer ignores
  its future events, and — because events already routed through that slot may have belonged
  to either module — **all semantic state of both affected modules is purged for every
  process** at the transition (`state_reconciliations` counts the purge; sessions/ops/pending/
  auth state restart empty; aggregate `functions[]` counts are unaffected and carry both
  module ids); `module_ambiguous += 1`, PARTIAL. No call-stack or return-address heuristic.
  Regression tests: two fixture tables sharing one target; semantic events through the shared
  slot *before* the second module is discovered, then no stale state remains.
- `Session::start` loads the object and publishes/freezes policy once; `attach_module(plan)`
  is then called per discovered module and `attach_loader_hook(ld_so_fd, offset)` /
  `attach_export_hooks(fd, [(symbol, offset)])` per loader/object.
- `CONFIG` gains a `PAUSE` bit (published and frozen). `PAUSE_PIDS` (pid → 1) lists pids a
  hook may stop; it must stay writable after attach because pids appear later, so it is an
  ordinary (unfrozen) map that never influences capture policy — only whether a hook may send
  `SIGSTOP`. `ASYNC_FUNCTIONS`, `MECH_SHAPE` and the rest are unchanged (static, frozen).
- Slot → module and slot → names are userspace-only tables in the plan; `Event.slot` keeps its
  meaning.

### 4.8 Evidence and schema v2

Additions to the evidence object (both profile and metrics documents; trace `EVIDENCE` line):

| Field | Meaning |
| --- | --- |
| `authority` | `"hash-pinned"` |
| `discovery[]` | per module: `{module: {dev, ino, sha256, path, build_id}, objects: [{dev, ino, sha256, path}], sources: [scan\|live\|manifest], corroborated, tables: [{version, entries, source}], interfaces, skipped[], scan_ms, attached_at_ms, attach_gap_ms}` |
| `discovery_conflicts` | scan vs export-hook disagreement count (forces PARTIAL) |
| `discovery_uncorroborated` | manifest-sourced tables never corroborated by scan/live by capture end (forces PARTIAL) |
| `discovery_read_failures` | BPF-side table reads that failed |
| `discovery_ring_loss` | `DISCOVERY` ring reservations that failed (forces PARTIAL) |
| `discovery_state_failures` | export entry-state insert failures/overwrites (forces PARTIAL) |
| `discovery_truncated` | live records truncated or undecodable (forces PARTIAL) |
| `module_ambiguous` | attach targets shared by ≥2 modules (forces PARTIAL) |
| `attach_gap_ms` | max over modules of hook-event→attached; `null` when no live event occurred |
| `pause` | `sigstop` (confirmed whole-group stop, `run` only) / `partial` / `none` |
| `provider_changed` | any pinned object's `(ino,size,ctime)` changed (forces PARTIAL) |
| `modules_skipped` | modules not attached for capacity or unsupported class |
| `child_still_running` | `run` only: `--duration` elapsed with the child alive |

`functions[]` items gain `module: {dev, ino, sha256}` (the stable module identity; `path`
lives in `discovery[]`). `capture.module` becomes `capture.modules[]`.
Schema ids: `pkcs11-scope/observed-profile/v2` and `pkcs11-scope/observed-profile/v2-metrics`.
`docs/schema/observed-profile-v1.md` → `-v2.md` with a migration section; v1.4 → v2 is a
breaking rename of `capture.module` and the evidence additions; the removed evidence fields
are those tied to the deleted lane (none of the capture-quality counters change).

### 4.9 Privileges and process access

- BPF: `CAP_BPF`+`CAP_PERFMON` (or `CAP_SYS_ADMIN` where `perf_event_paranoid ≥ 3`).
- `/proc/<pid>/maps`, `/proc/<pid>/exe`, `/proc/<pid>/root/<path>`: `PTRACE_MODE_READ` — the
  same uid (and a dumpable target) or `CAP_SYS_PTRACE`; not subject to Yama.
- `/proc/<pid>/mem` (memory scan, `_r_debug` read): `PTRACE_MODE_ATTACH` — additionally
  subject to `kernel.yama.ptrace_scope`: `0` same uid; `1` (Ubuntu/Debian default) only
  descendants of the observer (the `run` child qualifies) unless `CAP_SYS_PTRACE` or the
  target called `PR_SET_PTRACER`; `2` `CAP_SYS_PTRACE` only; `3` never. When unavailable, the
  scan is reported `unavailable: ptrace` and discovery relies on the loader/export hooks,
  whose table reads run in BPF and need no `/proc` access.
- `/proc/<pid>/map_files/*`: `CAP_CHECKPOINT_RESTORE`/`CAP_SYS_ADMIN`; optional, never
  required.
- `--cgroup`: read access to the cgroup directory and `cgroup.procs`.
- Pause/resume (`run` child only): `SIGSTOP` is sent by the kernel helper; the resume
  `pidfd_send_signal(SIGCONT)` needs kill permission, which the observer has over its own
  child (same credentials); proven once before arming (§4.4). No `CAP_KILL` is required in
  this slice because external targets are never paused.
- `doctor` demonstrates each of these per target. The privilege table in `docs/usage.md` is
  re-measured by a gate (`capsh` rows on the CI runner and on the development host, with
  `ptrace_scope` recorded) as part of 1b and stated as measured there.

### 4.10 Error handling

- Discovery failures are evidence, not fatal: unreadable object → `skipped`; no tables in a
  module → `discovery[].tables = []` with `note`; scan finds nothing at all and no manifest →
  capture proceeds with hooks armed and `discovery: pending`, live frame says so; on exit with
  zero modules the report is still written (`PARTIAL`, `attach_gap_ms: null`).
- BPF load/attach failures keep today's actionable hints; per-slot attach failures remain
  non-fatal.
- Live-discovery loss (`discovery_ring_loss`, `discovery_state_failures`,
  `discovery_truncated`) is evidence, forces PARTIAL, and is surfaced on the live frame; it is
  never folded into the call-event `event_loss`.
- Pause guard: any error after a `SIGSTOP` resumes the pid before propagating.
- `run`: child exec failure → exit 127 with the OS error; child killed by signal → mirror.

### 4.11 Deletions (plan 1a)

Code: `src/verify.rs` (everything except manifest read/size caps and the atomic temp+rename
output publish, which move to small dedicated modules; the SIGINT/SIGTERM stop flag stays in
`main.rs`), `src/oracle.rs`,
`src/discover_cmd.rs` (subcommand removed; the `discover` binary is unchanged),
`crates/manifest/src/identity.rs::inspect_elf_loader` and the loader-graph validator,
`crates/discover/src/main.rs` `suid_dumpable` requirement (the helper still drops privileges
when root; the exact-0 sysctl check goes). Tests: `tests/lease_break.rs`,
`tests/provenance_lease_break.rs`, `tests/cli_discover.rs`, the lane-specific parts of
`tests/reuse.rs` and `tests/release_contracts.rs` (text-grep tests deleted; behavioural ones
kept or rewritten). Scripts: `scripts/trusted-p11scope.sh` (replaced by plain `sudo` staging
helpers in `scripts/lib.sh`), `scripts/attach-pod.sh` (rewritten in 1b on the new CLI),
`scripts/container-authority.py`; every gate/matrix script updated to the new CLI. Docs: the
provenance/lease sections of README/usage/allowlist/CHANGELOG rewritten in 1b's final task
(the ROADMAP is updated as Task 1 of plan 1a, see §7); the removed design is referenced as
history.

Commit message of the deletion: "remove lease/provenance/hardened lane (kept in history:
see docs/notes/2026-08-15-architecture-and-gap-analysis.md A5/A7)".

### 4.12 Manifest trust and corroboration

`--manifest FILE` is **trusted operator input**, like any command-line argument: SHA-256 binds
the provider bytes but does not authenticate the manifest's name→offset assertions. The
observer validates structure (schema v4, sizes, every offset inside an executable segment of
the pinned object, `sha256` equal to the pinned object's), labels the source `manifest`, and
corroborates automatically whenever the object is mapped in scope (scan or a live export
record). Corroboration mismatch → `discovery_conflicts` (union attached, PARTIAL). A
manifest-sourced table that was never corroborated by capture end → `discovery_uncorroborated`
and PARTIAL: the observer cannot rule out that the offsets did not describe the live table. A
manifest whose `sha256` does not match is ignored for that object with an evidence note; it is
fatal only when it was the sole discovery source and nothing else found tables.

### 4.13 Multi-module state (moved into slice 1b)

Two modules in one process (proxy + backend, NSS + vendor) can hand out numerically equal
session handles, so semantic state keyed by `(process, session)` would collide. In this slice
the semantic keys become `SessionKey { process: ProcessKey, module: ModuleId, handle }` (module
derived in userspace from `Event.slot` → module), including `active_ops`, `find_active`,
`inherited_ambiguous`, `pending`/`detached` and fork inheritance. Aggregate output stays
combined in v2 with a `modules[]` list; per-module sections of `mechanisms`/`sessions` are
slice 2. A unit test opens the same handle value in two modules and proves the states do not
interact.

## 5. Testing and CI

Unprivileged (`cargo test`):

- `scan.rs`: dlopen the existing fixture providers (`crates/discover/tests/fixture/*.c`:
  2.00/2.40/3.0/3.2 tables, alias, vendor interfaces) into the test process and scan
  `/proc/self/mem` — expected tables/offsets equal the values `p11scope-discover` computes for
  the same fixture (oracle already exists). Negative: non-ELF, ELFCLASS32, table-less object,
  overlapping candidates, oversized mapping.
- `scan.rs` cross-object: the `lazy_wrapper` fixture (table in the wrapper, functions in the
  backend) resolves to two attach objects with the wrapper as the module.
- Export-hook ABI: userspace decoding of `FUNCTION_LIST`/`INTERFACE` records from fixtures
  covering the `C_GetInterfaceList` sizing idiom, `CKR_BUFFER_TOO_SMALL`, `C_GetInterface`
  output at `arg2`, bounded counts.
- Multi-module: two fixture modules with colliding session handles → independent state; two
  fixture tables sharing one `{object, offset}` → attached once, `module_ambiguous`, PARTIAL;
  semantic events through the shared slot before the second module appears → state purged,
  none stale.
- Discovery loss counters: forced `reserve` failure (tiny `DISCOVERY` ring feature),
  entry-state overwrite, >16 interfaces → each counter, PARTIAL.
- `elf.rs`: registry lookup and symbol→offset on fixtures and on the host's own `ld.so`/`libc`.
- `identity.rs`: fstat pin change detection (touch/`utimensat` cannot hide ctime), manifest
  sha256 match/mismatch.
- `pause.rs`: `run`-child-only arming (external pids never enter `PAUSE_PIDS`); resume
  authority probe before releasing the barrier; resume exactly once through the held pidfd;
  `stop_requested` vs confirmed `paused`; guard resumes on drop; whole-group stop
  confirmation; `--pause always` refused outside `run`.
- Descriptor table: `DESCRIPTORS` content is capture-independent and matches `kinds`; cookie
  encode/decode; out-of-range descriptor → `COUNT_ONLY`.
- `cli.rs`: every flag/duration suffix; removed flags rejected with hints.
- `doctor`: rendering from a fixed probe result set.
- `run`: spawns a fixture that reports its session id and stop/continue.

Root gates (local `just gates`, and CI):

- e2e (existing `verify-attach-e2e.sh` on new CLI): manifest-free `--pid` attach to a running
  SoftHSM2 harness (scan path), exact counts; `run -- harness` (live path with pause) exact
  counts incl. the first `C_Initialize`; `run --pause never` and plain `--pid` show
  `attach_gap_ms > 0` and the known missed count; proxy + provider in one process (p11-kit proxy over SoftHSM2 where
  installed, else two fixture modules) attached and attributed separately within the slot
  ceiling; Yama `ptrace_scope=1` lane: same-uid non-descendant target → scan `unavailable:
  ptrace`, live hooks still discover; canaries, induced gaps, matrix scripts updated
  (docker/kind on new CLI; Knative manual); privilege rows re-measured with `capsh`.
- CI: `.github/workflows/ci.yml` — job 1 unprivileged (fmt, check, clippy, test, `--locked`,
  Rust 1.88 + nightly for the eBPF object); job 2 `ubuntu-24.04` with `sudo` (SoftHSM2 from
  apt) running the e2e and canary gates. Hosted-runner kernels are not contractual and are
  recorded per run; the multi-kernel qemu matrix and kind lanes are slice 3 and spike-gated
  (nested virtualization on hosted runners is not guaranteed; a self-hosted runner is the
  fallback).

## 6. Spikes inside plan 1b (must be answered before the dependent tasks)

1. `_dl_debug_state` on musl `libc.so`: exported? If not, hook `dlopen` return in musl libc.
2. glibc `dl_open_worker`: confirm RT_CONSISTENT is signalled after relocation and before
   constructors on the pinned glibc versions (2.35, 2.39); confirm reading `_r_debug.r_state`
   through `/proc/<pid>/mem`.
3. `bpf_send_signal(SIGSTOP)` from a uretprobe on the target's return path: measure the gap
   (event → attached) with single-attach on 5.15/6.8; confirm the discovering thread does not
   execute user code before stopping.
4. `/proc/<pid>/root/<path>` + `mapping_file_key` identity check on overlay2/btrfs (the
   primary object-open path); `map_files` only when `CAP_CHECKPOINT_RESTORE`/`CAP_SYS_ADMIN`.
5. `RingBuf::reserve` of a ~1 KiB discovery record and bounded `bpf_probe_read_user` loops
   (104 pointers, 16 interfaces) pass the verifier on 5.15 and 6.8.
6. Yama `ptrace_scope=1`: confirm `maps` readable and `mem` refused for a same-uid
   non-descendant, and that live hooks still discover the table (BPF-side reads).

## 7. Plans

- **Productization Slice 1a — trust simplification (first):** Task 1 = ROADMAP update
  (new "Productization Slice 1a/1b/2/3" entries, old lane marked removed, per `AGENTS.md`'s
  source-of-truth rule); then deletions of §4.11; `identity.rs` (pinned fd,
  sha256 once, fstat pin) replacing `check_reuse`; manifest as optional input; CLI cleanup
  (`cli.rs`, remove flags, `--duration` suffixes, SIGTERM); scripts on the new CLI; CI
  skeleton (job 1 + e2e job); ROADMAP/CHANGELOG entries. Outcome: today's behaviour with
  `--manifest` and the minimum privileges, ~6k fewer lines, green gates.
- **Productization Slice 1b — discovery engine and commands:** `scan.rs`, `elf.rs`, BPF hooks, `pause.rs`,
  `Engine`, `attach_module`, `inspect`, `doctor`, `run`, schema v2 evidence, docs rewrite,
  privilege re-measurement, spikes §6.

## 8. Acceptance

- `sudo -E capsh --caps="cap_bpf,cap_perfmon,cap_sys_ptrace+eip" -- -c "p11scope profile --pid <softhsm-app>"`
  attaches without a manifest, without a helper, and reports exact counts (`CAP_SYS_ADMIN`
  instead on `perf_event_paranoid=4` hosts) — measured, in the privilege gate.
- `p11scope run -- ./harness` captures every call including `C_Initialize` with
  `attach_gap_ms` recorded and `pause: sigstop`.
- `p11scope inspect --pid` lists the same tables `p11scope-discover` computes for SoftHSM2.
- Docker and kind rows pass on the new CLI with nothing copied into the container.
- `doctor` explains every unavailable lane on a host lacking a capability.
- Proxy + backend in one process are attached and reported as two modules with independent
  session state; a shared attach target is counted once and marked `module_ambiguous`.
- External `--pid`/`--cgroup` targets are never paused; `--pause always` outside `run` is
  refused; a `run` child is paused and resumed exactly once per discovery event.
- A same-uid target under Yama `ptrace_scope=1` is still discovered live; `doctor` explains
  why the scan is unavailable.
- The old lane is gone; `git log` records why; unprivileged suite + CI green.

## 9. Owner requirements (as stated, 2026-08-15)

- The MVP works; the next phase is productization.
- It must be usable with **reduced capabilities**, preferably the minimum — at least function
  calls/RVs/latency — reporting what is available rather than refusing.
- **No vendor code executed by default**: dlopen of a provider may run license checks, take
  exclusive device/token locks, rewrite configuration, open network connections. The helper
  is acceptable only as an explicit, optional, offline tool.
- Proxies (p11-kit or any other) are ordinary PKCS#11 modules to be observed, not a case to
  warn about; if the backends are on the same machine they should be observable too.
- Newer kernels are acceptable *if genuinely needed*; the product is "for the future".
- 32-bit targets and other architectures/ABIs would be nice.
- Heuristics that are too complex for now (file relocation scan) are out; the memory scan
  is worth trying, enabled by default, otherwise wait.
- SIGSTOP mitigation is fine "if SIGSTOP is really needed".
- Re-hashing looked unnecessary — find a simpler mechanism (→ §4.5, §10.3).

## 10. Rationale and alternatives considered

### 10.1 Why not the helper by default (and why it stays as an offline tool)

The helper answered the discovery race by producing offsets before the app starts, but the
previous design treated its output as untrusted input, which pulled in provenance
rediscovery, closure leases and a supervisor. This design instead treats a manifest as
trusted operator input that is structurally validated and corroborated when possible
(§4.12). Beyond that cost it (a) executes provider constructors on a machine that may not
be the target's, (b) in containers must run inside the container's filesystem view with a
matching libc (copy-in or `setns`+`execveat`), and (c) can resolve a table the app never
uses (NSS softokn `NSC_` vs `FC_`). Kept as an *offline* generator of portable manifests
(SHA-256/build-id keyed; a future "manifest catalog" per vendor package version follows from
this at zero cost) because that use is legitimate on a build machine.

### 10.2 Why memory scan + loader hook, and what was rejected

- **Static `CK_FUNCTION_LIST` in memory** is the observed norm in the providers examined
  (SoftHSM2, OpenSC, NSS softokn `NSC_`/`FC_`, p11-kit proxy/rpc, YubiHSM, Kryoptic; vendor
  HSM libraries are C and expected to match — verified per provider as they are met): version
  word + 68/92/104 code pointers is a strong signature; the measurable criteria are in §4.1
  (all fixture tables found, zero false positives on fixtures and the installed real
  providers). It needs `PTRACE_MODE_ATTACH` access to `/proc/<pid>/mem` (§4.9), works
  inside containers and for 32-bit words. Vendor extensions appear either after the standard
  prefix (ignored) or as `CK_INTERFACE` entries with non-standard names (recorded,
  undecoded).
- **Loader breakpoint `_dl_debug_state`** is the mechanism debuggers use; the working
  hypothesis (spike §6.2) is that it fires after relocation and before constructors for both
  the initial link set and every `dlopen`, so it would catch DT_NEEDED providers and lazily
  loaded ones alike, without hooking `dlopen` in a libc whose identity is unknown until a
  process exists. If the spike disproves the ordering, the fallback is `dlopen` return in
  libc plus the export hooks.
- **Export hooks** (`C_GetFunctionList` …) alone were the first idea; they cannot see a table
  handed out before the observer started, so they became the cross-check and the fallback for
  dynamically built tables.
- Rejected: **file relocation scan** (`R_*_RELATIVE` runs in `.data.rel.ro`) — needs ELF
  relocation parsing, more heuristics, no advantage over the live-memory scan;
  **decoding `C_GetFunctionList`'s `lea`** — compiler/provider specific;
  **`dlopen`-hook-only discovery** — misses DT_NEEDED providers and needs per-libc hooking;
  **hooking only the three standard exports** — misses NSS FIPS (`FC_`) tables.

### 10.3 Why `fstat` pinning instead of re-hashing or leases

What we hold is an fd pinning the *inode*. A package upgrade creates a new inode: the observed
process keeps the old one mapped (our probes and fd are on it — nothing changes for the
observation), and new processes load the new inode, which the live path discovers as a new
module. Only an in-place write to the same inode matters. The kernel already records that:
`ctime` changes on every write and cannot be set from userspace, so `fstat` on the pinned fd
comparing `(ino, size, ctime)` is O(1), free, and robust against non-root writers. Uprobed
pages are private copies per process, so an in-place write cannot move a breakpoint; and
in-place modification of a mapped `.so` is a broken deployment in any case. Read leases were
the only stronger primitive and are the reason `CAP_LEASE` was needed; they were removed with
the lane. SHA-256 is computed once at attach for identity (report, manifest matching).

### 10.4 Hook inventory, safety, cost

Beyond the per-function entry/return probes (unchanged; ~3.3 µs per observed call measured
on SoftHSM2), this design adds three hook kinds (costs below are estimates until the 1b
gate measures them): `_dl_debug_state` (empty function that
exists for debuggers; fires on library load/unload only), export uretprobes (fire once per
module initialisation), `sched_process_exec` (cgroup/`run` scope; ~100 ns per exec). All are
scope-filtered first thing in BPF. Uprobes bind to inodes, so hooking a shared `ld.so` traps
every process on the host on library-load events for the observer's lifetime — ~1–3 µs each,
out-of-scope processes return immediately; documented in usage as the one host-wide effect.

### 10.5 Pause mechanism alternatives

- `bpf_send_signal(SIGSTOP)` (chosen, `run` child only): delivered before the discovering
  thread's next user instruction; a zero gap is claimed only under the confirmed whole-group
  stop of §4.4. Limited to the observer's own child because a numeric PID of any external
  target can be recycled between arming and the hook, and a resume could then hit an
  unrelated (possibly legitimately stopped) process; a BPF-checked generation token would be
  needed to extend it, and is deferred. The child runs in its own session so job control is
  not affected.
- cgroup v2 freezer: invisible to job control but needs write access to the cgroup, freezes
  every process in it, and leaves a userspace-latency window; kept as a possible later option
  for cgroup scope.
- Bounded busy-wait inside the uretprobe until userspace signals "attached": no signal, no
  stopped-forever risk, but only viable when attach is sub-millisecond (`uprobe_multi`,
  kernel 6.6+) because of the BPF instruction budget; noted as a 6.6+ improvement.
- No pause: simplest; the first calls (often `C_Initialize`) may be unobserved; kept as
  `--pause never` with the gap reported.
- Accepted residual risk of the chosen mechanism: an observer `SIGKILL` between `SIGSTOP`
  and `SIGCONT` (a window of milliseconds) leaves the target stopped; a `Drop` guard covers
  every other exit path, `doctor` reports unexplained stopped in-scope processes.

### 10.6 Why remove the old lane instead of keeping it behind a flag

5.8k product lines (as large as the observer), a maintenance and test burden for a property
(`integrity of statistics against a hostile observed workload`) that the docs already
conceded cannot be closed for same-uid targets, cgroup scope, or malicious providers, and
whose payoff under the `allowlisted` policy is misattributed counts, not secrets. Git history
keeps it; the deletion commit names the reason and the note (`A5`/`A7`).

## 11. Security model of the default lanes

Protected by construction: PID/cgroup scoping in BPF before any argument read; the
`allowlisted` capture policy (unchanged: pointer-derived bytes reach output only by finite
published equality); provider identity pinned by fd + SHA-256 + `fstat` change detection;
discovery reads target memory either through `/proc/<pid>/mem` under `ptrace_may_access`
(scan) or with bounded `bpf_probe_read_user` in the export hooks (live), never both
persisted: pointer values and interface-name bytes never appear in capture output; no
provider code executed by the observer; outputs published atomically.

Accepted residual risks (documented in usage): a workload that rewrites its provider in
place after attach may cause misattributed statistics, missed calls (probes stay at offsets
whose instructions no longer exist in pages mapped afterwards) or disruption of the target
itself until `provider_changed` flags it; a
malicious native provider is code inside the target and outside the semantic guarantee (as
before); an observer killed inside a pause window leaves the target stopped.

Privilege floor of the default lanes: `CAP_BPF`+`CAP_PERFMON` (or `CAP_SYS_ADMIN` where
`perf_event_paranoid ≥ 3`); `CAP_SYS_PTRACE` for cross-uid `/proc/<pid>` access and for
same-uid memory scans under Yama `ptrace_scope ≥ 1`; nothing else (pausing is limited to
the observer's own `run` child, so no `CAP_KILL` is needed). Any grant beyond that (`CAP_LEASE`, root-owned staging, sysctl
changes) is no longer required.

## 12. Platform basis for the kernel decision

| Distribution | Kernel | 5.15 base | uprobe_multi (6.6) |
| --- | --- | --- | --- |
| Ubuntu 22.04 / 24.04 | 5.15 / 6.8 | ✔ / ✔ | ✘ / ✔ |
| Debian 12 / 13 | 6.1 / 6.12 | ✔ | ✘ / ✔ |
| RHEL 9 / 10 | 5.14 (+backports) / 6.12 | by feature probe / ✔ | ✘ / ✔ |
| Fedora 43 | 6.17 | ✔ | ✔ |
| Amazon Linux 2023 | 6.1 / 6.12 | ✔ | ✘ / ✔ |
| SLES 15 SP6 / 16 | 6.4 / 6.12 | ✔ | ✘ / ✔ |

Hence: **upstream 5.15 feature baseline; runtime probes are authoritative** — `doctor`
probes features (attach cookies, `bpf_send_signal`, ring buffer, `uprobe_multi`) rather than
comparing versions, which is what makes a backport kernel such as RHEL 9's 5.14 supportable;
a higher hard floor would exclude Ubuntu 22.04, Debian 12, AL2023-6.1 and RHEL 9 for an
optimisation.

## 13. CI on GitHub — findings

GitHub-hosted `ubuntu-22.04`/`ubuntu-24.04` runners are full VMs with passwordless `sudo`;
their images (and kernels, 6.5–6.11 at the time of writing) are updated regularly and are
not contractual, so each CI run records `uname -r`. BPF and uprobes work there directly,
which is how aya, cilium/ebpf, bcc and tracee run their privileged tests. SoftHSM2 is
installable from apt; Docker is present; kind is installable (`helm/kind-action`).
Multi-kernel coverage (5.15/6.1/6.6/6.12) with qemu-based actions (`cilium/little-vm-helper`,
`vimto`, `libbpf/ci`) depends on nested virtualization, which hosted runners do not
guarantee — slice 3, spike-gated, self-hosted runner as fallback. Knative remains a
manual/nightly lane. Capability-only rows (`capsh`) run on the hosted runner, so the
privilege table can be re-measured in CI.

## 14. Decisions already taken for later slices (recorded so they are not lost)

- Slice 2 — extend the safe (`allowlisted`) policy: RSA-PSS/GCM parameters and template
  attribute *types* read only after `CKR_OK`/`CKR_PENDING`, only when the registry shape
  length matches, and emitted only when every value is a member of a finite published set
  (hash alg ∈ mechanism registry, MGF ∈ `CKG_*`, lengths bounded, attribute types ∈ `CKA_*`);
  policy booleans stay diagnostic-only.
- Slice 2 — per-module `mechanisms`/`sessions` sections in the profile JSON (the state key
  itself is `(process, module, session)` from slice 1b, §4.13).
- Slice 2 — ring/epoll wait, larger default ring, compact `Event` for the safe policy,
  refund of the semantic key budget, trace filters/JSONL, periodic snapshots.
- Slice 3 — module split of `attach.rs`/evidence plumbing, `serde(flatten)` evidence, typed
  `Profile` types, script consolidation, single doc, multi-kernel CI, text-grep tests gone.
- Then — AArch64 (argument accessor abstraction), 32-bit counting mode, `uprobe_multi`
  fast attach and bounded-spin pause, cgroup-freezer pause option, manifest catalog.
