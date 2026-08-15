# Productization slice 1 — discovery and trust — design

**Date:** 2026-08-15
**Status:** Approved in discussion (owner), pending written-spec review
**Input:** `docs/notes/2026-08-15-architecture-and-gap-analysis.md` (§3–§5, Addendum A1–A7)
**Supersedes for discovery/attach authorization:**
`docs/superpowers/plans/2026-08-13-manifest-provenance.md` (the lease/provenance/hardened
lane is removed by this design), the discovery/attach parts of
`2026-08-12-v0.1-corrective-release-design.md`, and the "Architecture" section of
`2026-08-10-pkcs11-scope-design.md`. The privacy model
(`2026-08-13-safe-and-unvalidated-metadata-design.md`) is unchanged by this slice; its
extension (safe params) is slice 2.
**Follow-on slices:** 2 = capture quality (ring/epoll, budgets, safe params, multi-module
state, SIGTERM already here, filters, snapshots); 3 = structure/DRY refactor, docs
consolidation, full CI matrix; then AArch64/32-bit.

## 1. Goal

Make `p11scope` usable as a product on ordinary hosts and clusters:

- discover a target's PKCS#11 function tables **without executing provider code** and
  without copying anything into or out of containers;
- attach with the **minimum privileges uprobes need** (`CAP_BPF`+`CAP_PERFMON`, or
  `CAP_SYS_ADMIN` where `perf_event_paranoid ≥ 3`; `CAP_SYS_PTRACE` for cross-uid
  targets) — no `CAP_LEASE`, no root-owned sibling helper, no sysctl, no static binary;
- keep the observer honest: every report names how the tables were found
  (`discovery`), how the provider identity was pinned (`authority`), and any window in
  which calls could have been missed (`attach_gap_ms`, `pause`);
- add the three operator commands the review found missing: `run -- cmd`, `inspect --pid`,
  `doctor`;
- remove the lease/provenance/hardened-oracle lane (≈5.8k product lines) and its
  operational requirements, recording in history that it existed and was removed
  deliberately.

Non-goals for this slice: multi-module *state* attribution (slice 2; this slice records
per-module `functions[]` only), safe-policy params/templates (slice 2), ring/epoll and
budget fixes (slice 2), module refactor of `attach.rs`/evidence plumbing (slice 3),
AArch64/32-bit, `uprobe_multi`, cgroup-freezer pause, manifest catalog tooling.

## 2. Decisions carried in from the review (fixed)

| Topic | Decision |
| --- | --- |
| Discovery, default | memory scan of the target's mappings + loader hook for future loads; export hooks as cross-check / dynamic-table fallback |
| Helper | `p11scope-discover` stays a standalone offline tool ("executes provider code"); the observer never invokes it; `--manifest` accepted, verified by SHA-256 |
| Static relocation scan of files | not now |
| Race between table hand-out and attach | adaptive pause: `bpf_send_signal(SIGSTOP)` unless the target has a controlling tty; `run` always pauses (own session); `--pause auto|never|always`; gap always reported |
| Hook registry | built-in `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`, `NSC_GetFunctionList`, `FC_GetFunctionList`; `--hook-symbol NAME` adds names |
| Provider identity | pinned fd; SHA-256 **once** at attach; `fstat` `(ino, size, ctime)` compared every frame and at end → `provider_changed`; no re-hash |
| Old authorization lane | removed now (leases, provenance rediscovery, hardened oracle, glibc staging, supervisor fork, `--provenance-module`, `--trusted-workload`, helper ownership rules, `suid_dumpable`, `/run/p11scope`, exit 78) — restorable from git; commit message says so |
| Kernel | floor 5.15; newer features (uprobe_multi 6.6, bounded-spin pause) feature-probed later, never required |
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
3. Read the group's non-executable mappings (`r--`, `rw-`) via `pread` on `/proc/<pid>/mem`
   (bounded: 64 MiB per object, 512 MiB total; larger → `skipped: too_large`).
4. Table detection over 8-byte words: a word `w` with `w & !0xffff == 0`,
   `major = w & 0xff ∈ {2,3}`, `minor = (w >> 8) & 0xff` plausible (2.x: 0..=40; 3.x: 0..=2),
   followed by `N` words each inside one of the group's `r-x` mapping ranges, where `N` = 67
   (2.00), 68 (2.01–2.40), 92 (3.0/3.1), 104 (3.2) by version. Record every match; overlapping
   matches keep the longest. Also detect `CK_INTERFACE` arrays: consecutive
   `{name_ptr, table_ptr, flags}` triples where `name_ptr` reads as a NUL-terminated string
   ≤ 64 bytes and `table_ptr` is a detected table or a pointer into a non-executable mapping;
   name `"PKCS 11"` → standard, else vendor (present, undecoded), matching today's
   `surfaces`/`vendor_interfaces` evidence.
5. Pointer → offset: `offset = ptr - mapping.start + mapping.file_offset` for the executable
   mapping containing `ptr` (`crates/discover/src/maps.rs::resolve` logic, moved into
   `manifest::maps` so both binaries share it). Non-file-backed pointers → `skipped`.
6. Output: `Module { key: (dev,ino), path, tables: Vec<Table{version, source: scan, entries}>,
   interfaces, skipped }`, feeding the existing `plan::build` (alias grouping, `entries_seen`,
   surfaces) unchanged in semantics.

Cost: reading a few hundred KB–MB and a linear word scan — milliseconds. Idempotent; a
module already attached (same `(dev,ino)`, same table set) is not re-attached; a new table set
on a known inode is reported as `tables_changed` evidence and attached additively.

### 4.2 `discovery::elf` (new, small)

`exports(fd) -> Vec<String>` restricted to the registry names; `symbol_offset(fd, name) ->
Option<u64>` (dynsym value → file offset via program headers) for the loader hook and export
hooks. Uses the `object` crate already in `p11scope-manifest`. Refuses non-x86-64/ELFCLASS64
with a named reason (this slice), so foreign objects are skipped, not misread.

### 4.3 Loader hook and export hooks (BPF + userspace)

BPF programs added to `crates/ebpf`:

- `dl_debug_state` (uprobe, entry) attached to the target's `ld.so` inode at the exported
  `_dl_debug_state` offset (glibc; musl `_dl_debug_state` verified in a spike task, fallback:
  `dlopen` return in libc). Body: scope check → emit `DiscoveryEvent{kind: LOADER, pid, tid}`
  → if `CONFIG.PAUSE` and pid not tty-attached (userspace pre-decides per pid via a
  `PAUSE_PIDS` map) → `bpf_send_signal(SIGSTOP)`.
- `export_entry` / `export_return` (uprobe/uretprobe) attached per PKCS#11 object at each
  registry symbol found: entry stashes `arg0` (`ppFunctionList` / `pInterfacesList` /
  `ppInterface`) keyed by tid in a small map; return reads exactly one pointer-sized word from
  it (`bpf_probe_read_user`) and emits `DiscoveryEvent{kind: EXPORT, symbol_id, pid, tid,
  table_ptr, count?}`; optional pause as above. Pointer values are internal (never rendered).
- `sched_process_exec` (tracepoint) for `--cgroup` and `run` scopes: emits
  `DiscoveryEvent{kind: EXEC, pid}`; pauses **only** in `run` scope (the child of `run`), never
  in cgroup scope (busy pods must not be stalled per exec).

Userspace handling (`discovery::Engine::on_event`):

- `EXEC`: read `/proc/<pid>/exe`'s `PT_INTERP` (via `/proc/<pid>/root`), pin that `ld.so`
  inode; if not yet hooked, attach `dl_debug_state` there (once per inode). In `run` scope,
  then `SIGCONT`.
- `LOADER`: if `_r_debug` is resolvable, read `r_state` from `/proc/<pid>/mem`; on
  `RT_CONSISTENT` (or when unresolvable) run the scan for that pid; attach new modules;
  `SIGCONT` if paused. RT_ADD hits are ignored (unrelocated tables would not match anyway).
- `EXPORT`: read the table at `table_ptr` (`scan.rs` table reader over `/proc/<pid>/mem`) and
  cross-check against the scan result for that object; agreement is recorded; a table not
  found by scan (dynamically built) is attached from the export result and labelled
  `source: live`; disagreement (same object, different offsets) attaches the union and forces
  `PARTIAL` with `discovery_conflicts += 1`.
- Periodic sweep (every tick, cheap): any in-scope pid (from `/proc` for `--pid` and its
  known children, from fork/exec events for cgroup scope) not yet scanned gets scanned; this
  self-heals the exec-time window in cgroup scope where the loader hook was armed late.

Uprobes on `ld.so`/`libc` are inode-wide: every process on the host using that loader takes
the trap on library-load events while the observer runs (~1–3 µs each, scope-filtered
first). Documented in usage as the one host-wide effect.

### 4.4 `discovery::pause` — adaptive stop/continue

- Decision per pid: `auto` → pause unless `/proc/<pid>/stat` `tty_nr != 0` (a process under
  an interactive shell's job control would be reported as `Stopped`); `run` children are
  started in their own session (`setsid`) so they always qualify; `never`/`always` override.
- The BPF side sends `SIGSTOP` synchronously at the hook return, so the discovering thread
  cannot execute the next user instruction before stopping. Userspace performs the scan/attach
  and sends `SIGCONT` through the pidfd. A `Drop` guard resumes every paused pid on any error
  path and on Ctrl-C/SIGTERM; a paused-pid list is also flushed at exit. Residual risk: an
  observer `SIGKILL` inside the ~ms window leaves the target stopped — documented; `doctor`
  lists in-scope processes in state `T` whose stop is unexplained.
- Every pause/attach records `attach_gap_ms` (time from hook event to last probe attached);
  a `never` run records the same number as the unobserved window.

### 4.5 `identity` — pinned provider identity (replaces reuse/provenance)

- Open the object through `/proc/<pid>/map_files/<start>-<end>` (fallback
  `/proc/<pid>/root/<path>`), keep the fd for the capture, `fstat` → `(dev, ino, size,
  ctime, mtime)`, SHA-256 once, GNU build-id if present. Attach through `/proc/self/fd/N`
  (existing mechanism).
- Every frame and at end: `fstat` again; any change in `(ino, size, ctime)` →
  `provider_changed: true` and `PARTIAL` (`ctime` is not settable from userspace).
- `--manifest FILE`: parsed as today (v4), each object's `sha256` must equal the pinned
  object's hash → its tables are used with `source: manifest`; mismatch → the manifest is
  ignored for that object with an evidence note (never fatal when live/scan can proceed;
  fatal only if the manifest was the sole discovery source and nothing else found tables).
- Evidence: `authority: "hash-pinned"` (the only value this slice emits).

### 4.6 CLI (`cli.rs`, one parser; `main.rs` thin)

```
p11scope profile [--pid N | --cgroup PATH] [--module PATH]... [--manifest FILE]...
                 [--mode profile|metrics] [--duration 30s|5m|1h] [-o FILE]
                 [--pause auto|never|always] [--hook-symbol NAME]... [--unsafe-unvalidated-metadata]
p11scope trace   [same scope/discovery/pause options] [--duration] [-o FILE]
p11scope run     [profile options except scope] [--trace] -- CMD ARGS...
p11scope inspect --pid N [--module PATH]... [--json]
p11scope doctor  [--pid N] [--module PATH] [--cgroup PATH]
p11scope-discover ...   (unchanged standalone tool)
```

- `--module` is optional; without it every PKCS#11-looking object in scope is discovered.
- `--duration` accepts bare seconds (compat) and `s|m|h` suffixes.
- Ctrl-C and `SIGTERM` both end a capture cleanly (same flag).
- Removed: `--provenance-module`, `--trusted-workload`, `p11scope discover` subcommand,
  exit code 78.
- `run`: fork; child `setsid()` then `raise(SIGSTOP)` before `exec`; parent records the pid,
  publishes PID scope, arms the exec tracepoint, `SIGCONT`s; at the child's `exec` event the
  BPF side stops it again so the loader hook can be armed on its `ld.so` before any library
  loads (§4.3); the capture ends when the child exits or `--duration` elapses, and `run`
  exits with the child's status (signal → 128+n). Forks of the child are not followed in
  this slice (PID scope semantics unchanged); documented.
- `inspect`: runs the scan only (no BPF, no pause), prints modules, tables (version, count,
  aliases), interfaces, identity; unprivileged for same-uid targets.
- `doctor`: table of checks and a verdict per lane: kernel release, BTF, lockdown state,
  `kernel.perf_event_paranoid`, effective capabilities, BPF map create probe, uprobe
  `perf_event_open` probe on the observer's own libc, `/proc/<pid>/{maps,mem}` access (if
  `--pid`), cgroup path readable (if `--cgroup`), `_dl_debug_state` resolvable in the
  target's loader, `bpf_send_signal` availability, stopped in-scope processes; exits non-zero
  if the requested lane is unavailable. No BPF program stays loaded after `doctor`.

### 4.7 Attach engine changes (`attach.rs`, minimal in this slice)

- `Session::start` no longer takes a single plan; it loads the object and publishes policy
  once, then `attach_module(plan)` can be called repeatedly (per discovered module) and
  `attach_discovery_hooks(ld_so_fd, offset)` / `attach_export_hooks(fd, offsets)`.
- Slot ids remain a single global space (`MAX_SLOTS 512`) across modules; per-module slot
  ranges are recorded so `functions[]` can be grouped by module. `MAX_SLOTS` overflow →
  refuse further modules with evidence (`modules_skipped`), never truncate.
- `CONFIG` gains a `PAUSE` bit (published and frozen like the other policy bits). A
  `PAUSE_PIDS` hash map (pid → 1) lists pids a hook may stop; it must stay writable after
  attach because pids appear later, so it is an ordinary (unfrozen) map that never
  influences capture policy — only whether a hook may send `SIGSTOP`.

### 4.8 Evidence and schema v2

Additions to the evidence object (both profile and metrics documents; trace `EVIDENCE` line):

| Field | Meaning |
| --- | --- |
| `authority` | `"hash-pinned"` |
| `discovery[]` | per module: `{path, dev, ino, sha256, build_id, sources: [scan\|live\|manifest], tables: [{version, entries, source}], interfaces, skipped[]}` |
| `discovery_conflicts` | scan vs export-hook disagreement count (forces PARTIAL) |
| `attach_gap_ms` | max over modules of hook-event→attached; `null` when no live event occurred (pure pre-start manifest attach) |
| `pause` | `sigstop` / `none` / `mixed` |
| `provider_changed` | any pinned object's `(ino,size,ctime)` changed (forces PARTIAL) |
| `modules_skipped` | modules not attached for capacity or unsupported class |

`functions[]` items gain `module: {path, ino}`. `capture.module` becomes `capture.modules[]`.
Schema ids: `pkcs11-scope/observed-profile/v2` and `pkcs11-scope/observed-profile/v2-metrics`.
`docs/schema/observed-profile-v1.md` → `-v2.md` with a migration section; v1.4 → v2 is a
breaking rename of `capture.module` and the evidence additions; the removed evidence fields
are those tied to the deleted lane (none of the capture-quality counters change).

### 4.9 Privileges

Default lanes need: `CAP_BPF`+`CAP_PERFMON` (or `CAP_SYS_ADMIN` where
`perf_event_paranoid ≥ 3`), read access to `/proc/<pid>/{maps,mem,map_files}` (same-uid, or
`CAP_SYS_PTRACE`), read access to the cgroup directory for `--cgroup`. `doctor` demonstrates
each. The privilege table in `docs/usage.md` is re-measured by a gate (`capsh` rows) as part
of 1b and stated as measured on that host.

### 4.10 Error handling

- Discovery failures are evidence, not fatal: unreadable object → `skipped`; no tables in a
  module → `discovery[].tables = []` with `note`; scan finds nothing at all and no manifest →
  capture proceeds with hooks armed and `discovery: pending`, live frame says so; on exit with
  zero modules the report is still written (`PARTIAL`, `attach_gap_ms: null`).
- BPF load/attach failures keep today's actionable hints; per-slot attach failures remain
  non-fatal.
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
provenance/lease sections of README/usage/allowlist/CHANGELOG/ROADMAP rewritten in 1b's
final task; the removed design is referenced as history.

Commit message of the deletion: "remove lease/provenance/hardened lane (kept in history:
see docs/notes/2026-08-15-architecture-and-gap-analysis.md A5/A7)".

## 5. Testing and CI

Unprivileged (`cargo test`):

- `scan.rs`: dlopen the existing fixture providers (`crates/discover/tests/fixture/*.c`:
  2.00/2.40/3.0/3.2 tables, alias, vendor interfaces) into the test process and scan
  `/proc/self/mem` — expected tables/offsets equal the values `p11scope-discover` computes for
  the same fixture (oracle already exists). Negative: non-ELF, ELFCLASS32, table-less object,
  overlapping candidates, oversized mapping.
- `elf.rs`: registry lookup and symbol→offset on fixtures and on the host's own `ld.so`/`libc`.
- `identity.rs`: fstat pin change detection (touch/`utimensat` cannot hide ctime), manifest
  sha256 match/mismatch.
- `pause.rs`: decision from `/proc/<pid>/stat` fixtures; guard resumes on drop.
- `cli.rs`: every flag/duration suffix; removed flags rejected with hints.
- `doctor`: rendering from a fixed probe result set.
- `run`: spawns a fixture that reports its session id and stop/continue.

Root gates (local `just gates`, and CI):

- e2e (existing `verify-attach-e2e.sh` on new CLI): manifest-free `--pid` attach to a running
  SoftHSM2 harness (scan path), exact counts; `run -- harness` (live path with pause) exact
  counts incl. the first `C_Initialize`; `--pause never` shows `attach_gap_ms > 0` and the
  known missed count; canaries, induced gaps, matrix scripts updated (docker/kind on new
  CLI; Knative manual); privilege rows re-measured with `capsh`.
- CI: `.github/workflows/ci.yml` — job 1 unprivileged (fmt, check, clippy, test, `--locked`,
  Rust 1.88 + nightly for the eBPF object); job 2 `ubuntu-24.04` with `sudo` (SoftHSM2 from
  apt) running the e2e and canary gates. Multi-kernel qemu matrix and kind lanes are slice 3.

## 6. Spikes inside plan 1b (must be answered before the dependent tasks)

1. `_dl_debug_state` on musl `libc.so`: exported? If not, hook `dlopen` return in musl libc.
2. glibc `dl_open_worker`: confirm RT_CONSISTENT is signalled after relocation and before
   constructors on the pinned glibc versions (2.35, 2.39); confirm reading `_r_debug.r_state`
   through `/proc/<pid>/mem`.
3. `bpf_send_signal(SIGSTOP)` from a uretprobe on the target's return path: measure the gap
   (event → attached) with single-attach on 5.15/6.8; confirm the discovering thread does not
   execute user code before stopping.
4. `map_files` open permission on the CI kernel (ptrace-read suffices since 4.3) — fallback
   `/proc/<pid>/root/<path>` when it fails.

## 7. Plans

- **1a — trust simplification (first):** deletions of §4.11; `identity.rs` (pinned fd,
  sha256 once, fstat pin) replacing `check_reuse`; manifest as optional input; CLI cleanup
  (`cli.rs`, remove flags, `--duration` suffixes, SIGTERM); scripts on the new CLI; CI
  skeleton (job 1 + e2e job); ROADMAP/CHANGELOG entries. Outcome: today's behaviour with
  `--manifest` and the minimum privileges, ~6k fewer lines, green gates.
- **1b — discovery engine and commands:** `scan.rs`, `elf.rs`, BPF hooks, `pause.rs`,
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

The helper answered the discovery race by producing offsets before the app starts, but its
output is untrusted input, which pulled in provenance rediscovery, closure leases and a
supervisor. Beyond that cost it (a) executes provider constructors on a machine that may not
be the target's, (b) in containers must run inside the container's filesystem view with a
matching libc (copy-in or `setns`+`execveat`), and (c) can resolve a table the app never
uses (NSS softokn `NSC_` vs `FC_`). Kept as an *offline* generator of portable manifests
(SHA-256/build-id keyed; a future "manifest catalog" per vendor package version follows from
this at zero cost) because that use is legitimate on a build machine.

### 10.2 Why memory scan + loader hook, and what was rejected

- **Static `CK_FUNCTION_LIST` in memory** is universal in practice (SoftHSM, OpenSC, NSS
  softokn `NSC_`/`FC_`, p11-kit proxy/rpc, YubiHSM, Kryoptic, vendor HSM libraries):
  version word + 68/92/104 code pointers is a signature with essentially no false positives,
  needs only `/proc/<pid>/mem` read access (already required for `maps`), works inside
  containers and for 32-bit words. Vendor extensions appear either after the standard prefix
  (ignored) or as `CK_INTERFACE` entries with non-standard names (recorded, undecoded).
- **Loader breakpoint `_dl_debug_state`** is the mechanism debuggers use; it fires after
  relocation and before constructors for both the initial link set and every `dlopen`, so it
  catches DT_NEEDED providers and lazily loaded ones alike, without hooking `dlopen` in a
  libc whose identity is unknown until a process exists.
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
on SoftHSM2), this design adds three hook kinds: `_dl_debug_state` (empty function that
exists for debuggers; fires on library load/unload only), export uretprobes (fire once per
module initialisation), `sched_process_exec` (cgroup/`run` scope; ~100 ns per exec). All are
scope-filtered first thing in BPF. Uprobes bind to inodes, so hooking a shared `ld.so` traps
every process on the host on library-load events for the observer's lifetime — ~1–3 µs each,
out-of-scope processes return immediately; documented in usage as the one host-wide effect.

### 10.5 Pause mechanism alternatives

- `bpf_send_signal(SIGSTOP)` (chosen): synchronous with the discovering thread's return to
  user mode — deterministic zero-gap; visible to job-control parents (interactive shells show
  `Stopped`), hence adaptive (no controlling tty → pause; `run` gets its own session).
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
discovery reads target memory only through `/proc/<pid>/mem` under `ptrace_may_access`;
discovery pointer values never appear in output; no provider code executed by the observer;
outputs published atomically.

Accepted residual risks (documented in usage): a workload that rewrites its provider in
place after attach may cause misattributed statistics until `provider_changed` flags it; a
malicious native provider is code inside the target and outside the semantic guarantee (as
before); an observer killed inside a pause window leaves the target stopped.

Privilege floor of the default lanes: `CAP_BPF`+`CAP_PERFMON` (or `CAP_SYS_ADMIN` where
`perf_event_paranoid ≥ 3`); `CAP_SYS_PTRACE` for cross-uid `/proc/<pid>` access; nothing
else. Any grant beyond that (`CAP_LEASE`, root-owned staging, sysctl changes) is no longer
required.

## 12. Platform basis for the kernel decision

| Distribution | Kernel | 5.15 base | uprobe_multi (6.6) |
| --- | --- | --- | --- |
| Ubuntu 22.04 / 24.04 | 5.15 / 6.8 | ✔ / ✔ | ✘ / ✔ |
| Debian 12 / 13 | 6.1 / 6.12 | ✔ | ✘ / ✔ |
| RHEL 9 / 10 | 5.14 (+backports) / 6.12 | by feature probe / ✔ | ✘ / ✔ |
| Fedora 43 | 6.17 | ✔ | ✔ |
| Amazon Linux 2023 | 6.1 / 6.12 | ✔ | ✘ / ✔ |
| SLES 15 SP6 / 16 | 6.4 / 6.12 | ✔ | ✘ / ✔ |

Hence: base 5.15, `doctor` probes features (attach cookies, `bpf_send_signal`, ring buffer,
`uprobe_multi`) rather than comparing versions; a higher hard floor would exclude
Ubuntu 22.04, Debian 12, AL2023-6.1 and RHEL 9 for an optimisation.

## 13. CI on GitHub — findings

GitHub-hosted `ubuntu-22.04`/`ubuntu-24.04` runners are full VMs (kernels 6.5–6.11) with
passwordless `sudo`; BPF and uprobes work there directly, which is how aya, cilium/ebpf, bcc
and tracee run their privileged tests. SoftHSM2 is installable from apt; Docker is present;
kind is installable (`helm/kind-action`). Multi-kernel coverage (5.15/6.1/6.6/6.12) is done
with qemu-based actions (`cilium/little-vm-helper`, `vimto`, `libbpf/ci`) — slice 3.
Knative remains a manual/nightly lane. Capability-only rows (`capsh`) can run on the hosted
runner too, so the privilege table can be re-measured in CI.

## 14. Decisions already taken for later slices (recorded so they are not lost)

- Slice 2 — extend the safe (`allowlisted`) policy: RSA-PSS/GCM parameters and template
  attribute *types* read only after `CKR_OK`/`CKR_PENDING`, only when the registry shape
  length matches, and emitted only when every value is a member of a finite published set
  (hash alg ∈ mechanism registry, MGF ∈ `CKG_*`, lengths bounded, attribute types ∈ `CKA_*`);
  policy booleans stay diagnostic-only.
- Slice 2 — semantic state keyed by `(process, module, session)`; profile JSON gains
  `modules[]`; one run observes every module in scope (proxy → backend attribution).
- Slice 2 — ring/epoll wait, larger default ring, compact `Event` for the safe policy,
  refund of the semantic key budget, trace filters/JSONL, periodic snapshots.
- Slice 3 — module split of `attach.rs`/evidence plumbing, `serde(flatten)` evidence, typed
  `Profile` types, script consolidation, single doc, multi-kernel CI, text-grep tests gone.
- Then — AArch64 (argument accessor abstraction), 32-bit counting mode, `uprobe_multi`
  fast attach and bounded-spin pause, cgroup-freezer pause option, manifest catalog.
