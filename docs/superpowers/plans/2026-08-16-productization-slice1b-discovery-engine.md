# Productization Slice 1b — Discovery Engine and Commands — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `p11scope profile|trace --pid N` (and `--cgroup`, and the new `run -- cmd`) discovers a
target's PKCS#11 function tables **without a manifest and without executing provider code** —
memory scan of the target's mappings + loader/export hooks with a `run`-child-only pause — and the
operator gets `inspect`, `doctor`, per-module attribution and schema v2 evidence that says how every
table was found.

**Architecture:** Discovery becomes a `discovery::Engine` fed by five sources (initial `/proc`
sweep, exec events, loader-hook events, export-hook events, `--manifest` files) that produces
`Module` records shaped as today's manifest v4 (`p11scope_manifest::manifest::Manifest`), so the
existing `plan::build` → slots pipeline is reused unchanged. The attach engine gains dynamic slots
(semantics move from the per-slot `SLOT_SEMANTICS` map into a capture-independent frozen
`DESCRIPTORS` table selected through the attach cookie) so modules can be attached after the
policy freeze; a `SlotTable` keyed by `{pinned object identity, offset}` is shared across modules.
The BPF object gains a `DISCOVERY` ring, `dl_debug_state`/export/exec/exit programs and a
`PAUSE_PIDS` map that only ever holds the observer's own `run` child. Semantic state is keyed
`(process, module, handle)`. New commands `run`, `inspect`, `doctor` live in their own modules;
`main.rs` stays thin.

**Tech Stack:** Rust 1.88, edition 2024, aya 0.14 / aya-ebpf 0.2.1 (nightly for the BPF object),
`object` 0.39 (already locked, added to the root crate), `libloading` 0.8 (root dev-dependency,
already locked via `p11scope-discover`), `libc`, `signal-hook`, POSIX `sh` gate scripts, Python 3
evidence checker, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`
— §2 decisions, §3, §4.1–§4.4, §4.5 (pid/object pinning), §4.6–§4.10, §4.12, §4.13, §5, §6, §7
"Productization Slice 1b", §8 acceptance, §11. The spec's third review pass is treated as
authoritative (its status line says "1b pending reviewer confirmation of the third pass"; the owner
directed execution on 2026-08-16). Two deliberate deviations from the spec's field names are
recorded in Task 15 (`functions[].modules[]` list instead of a singular `module`, and top-level
`surfaces`/`interface_list` moving under `discovery[]`); both are documented in the schema note.

**Also folded in (Slice 1a follow-ups, `ROADMAP.md` + 1a ledger):** re-measure the `--cgroup`
capability minimum (`verify-fork-scope.sh` over-grants `CAP_LEASE`) — Task 20; one privileged
`--cgroup` smoke after the `_cgroup_file` removal — Task 20 (canary matrix + docker lane run under
root gates); the root `p11scope-discover` dev-dependency is **kept and used** (it is the scan
oracle in Task 6; the "prune" follow-up is resolved by use, recorded in Task 22); stale
`capture_aborted`/lease vocabulary — Task 15; `authority: "hash-pinned"` with schema v2 — Task 15;
`CaptureArgs.kind` unused — Task 13.

## Global Constraints

- Rust 1.88, edition 2024, Linux x86-64 first (`CLAUDE.md`). Kernel: upstream 5.15 feature
  baseline, runtime probes authoritative (spec §2, §12); nothing newer than 5.15 is *required*.
- All four checks green at every commit: `cargo +1.88 fmt --all -- --check`,
  `cargo +1.88 check --locked --workspace --all-targets`,
  `cargo +1.88 test --locked --workspace --all-targets`,
  `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`.
- Do not track generated output. **Privileged or container experiments (anything under `sudo`,
  docker, kind, capsh rows, the root spikes) require explicit owner approval** — the executor asks
  the owner once, up front, for blanket approval of the root gates listed in Tasks 11, 20, 21 and
  23; without it they are recorded UNRUN, never green. Every script change is still verified with
  `sh -n` and, where present, `--self-test`. GitHub CI e2e is recorded PENDING until an observed
  run passes.
- Privacy allowlist (`docs/privacy/allowlist-v1.md`): the capture-field inventory is unchanged.
  Discovery adds *no* capture fields: pointer values in `DiscoveryRecord` and interface-name bytes
  read in BPF are internal, never rendered in capture output (spec §4.3, §11); `inspect` (a
  discovery tool, not capture output) may print lossy interface names as `p11scope-discover` does.
- Dependencies: only crates already in `Cargo.lock` (`object`, `libloading`); no `clap`. When a
  dependency edge is added, run `cargo +1.88 check --workspace` once **without** `--locked` to
  update `Cargo.lock`, commit the lock with that task, and confirm no version changed
  (`git diff Cargo.lock` shows only the new edge).
- Manifest schema stays `p11scope-manifest/4`. Profile schema becomes
  `pkcs11-scope/observed-profile/v2` and `…/v2-metrics` (Task 15) — nothing v1.x is published.
- No new BPF program may read process memory outside the bounded reads in Task 10; every table
  read is `bpf_probe_read_user`/`_buf` with a compile-time bound (104 pointers, 16 interfaces,
  8-byte name prefix).
- Ordering is load-bearing: the tree must build and the unprivileged suite must pass after **every**
  task. The manifest path keeps working throughout (Task 8 keeps `--manifest` attached through the
  new `SlotTable`; Task 14 makes it optional).
- Branch: `productization/slice1b` in a worktree (superpowers:using-git-worktrees), base `main`
  at `3b7c067`. Ledger: `.superpowers/sdd/2026-08-16-productization-slice1b-discovery-engine/`.
- Suggested executor per task (subagent-driven-development dispatch): **opus** for Tasks 5, 6, 8,
  9, 10, 12, 14, 16 (detector, dynamic slots, BPF, engine, capture loops, `run`); **sonnet** for
  Tasks 1–4, 7, 11, 13, 15, 17–23 (mechanical moves, parsers, docs, scripts) unless a review sends
  a task back, in which case redo it on opus.

---

## File map

| Path | Action | Responsibility after 1b |
| --- | --- | --- |
| `crates/manifest/src/maps.rs` | modify | + `MappedPath`, `Resolved`, `resolve`, `mapped_path`, `map_key` (moved from the discover crate) |
| `crates/manifest/src/builder.rs` | create (feature `identify`) | `ObjectTable`, `resolve_values`, `alias_groups`, `validated_file_identity` — table → manifest records, shared by helper and observer |
| `crates/discover/src/maps.rs` | modify | re-export only |
| `crates/discover/src/discover.rs` | modify | uses `builder`; behaviour unchanged (its tests are the guard) |
| `crates/discover/tests/fixture/version_matrix.c` | modify | `-DSTATIC_INTERFACES=1` variant: a static `CK_INTERFACE[]` array in the provider |
| `Cargo.toml` (root) | modify | + `object` dependency, + `libloading` dev-dependency |
| `src/discovery/mod.rs` | modify | `identity`, `elf`, `procfs`, `registry`, `scan`, `pause`, `engine`; `pub type ModuleId = u32` |
| `src/discovery/elf.rs` | create | `supported`, `exports`, `symbol_vaddr`, `interpreter` (dynsym / PT_INTERP via `object`) |
| `src/discovery/procfs.rs` | create | `ProcessRef`, `read_maps`, `ProcMem`, `open_mapped_object`, `root_opener`, `thread_states`, `cgroup_procs`, `ProcError` |
| `src/discovery/registry.rs` | create | hook-symbol registry (`HookAbi`, `HookSymbol`, `builtin`, `parse_hook_symbol`) |
| `src/discovery/scan.rs` | create | memory table scan → `Manifest`-shaped `ScannedModule`s |
| `src/discovery/identity.rs` | modify | `pin_objects_with(opener)`, `PinnedObjects::identity/build_id` |
| `src/discovery/pause.rs` | create | `PauseMode`, `PauseGuard` (run-child-only stop confirmation, resume-once, Drop guard), pidfd helpers |
| `src/discovery/engine.rs` | create | `Source`, `Module`, `Engine` (sources → modules → attach; corroboration; timings; evidence) |
| `src/slots.rs` | create | `AttachKey`, `LiveSlot`, `SlotTable::merge` (dynamic capture-wide slot table, shared targets, capacity) |
| `crates/ebpf-common/src/lib.rs` | modify | `MAX_DESCRIPTORS`, `cookie_encode/decode`, `FLAG_PAUSE`, `DiscoveryRecord`, `ExportEntry`, discovery evidence cells, `small-discovery-ring` feature |
| `crates/ebpf/src/main.rs` | modify | `DESCRIPTORS` (replaces `SLOT_SEMANTICS`), cookie split, `DISCOVERY` ring, `EXPORT_STATE`, `PAUSE_PIDS`, programs `dl_debug_state`, `export_entry`, `export_return`, `sched_process_exec`, `sched_process_exit` |
| `crates/ebpf/Cargo.toml`, `build.rs` (root) | modify | `small-discovery-ring` feature / `P11SCOPE_SMALL_DISCOVERY_RING` env |
| `src/attach.rs` | modify | `Session::start(scope, policy, options)`, `attach_module`, `attach_loader_hook`, `attach_export_hooks`, `arm_pause`/`disarm_pause`, `discovery_ring_fd`, extended detach; DESCRIPTORS publish/freeze |
| `src/plan.rs` | modify | `Slot.descriptor`; `build` unchanged otherwise (per-module plan) |
| `src/kinds.rs` | modify | `descriptor_table()` (105 entries), `descriptor_index(names)` |
| `src/events.rs` | modify | `DiscoveryDrain` |
| `src/metrics.rs` | modify | reads from `SlotTable`; `SlotReport.module_ids/ambiguous`; discovery kernel evidence |
| `src/semantics.rs` | modify | `SessionKey {process, module, handle}`, `sync_slots`, `purge_modules`, module-aware pseudonyms |
| `src/trace.rs` | modify | `Tracer` owns slot names, `sync_slots`; EVIDENCE line = schema v2 evidence; `capture_aborted` removed |
| `src/render.rs` | modify | schema v2: `Evidence` discovery fields, `functions[].modules[]`, `capture.modules[]`, `authority` |
| `src/cli.rs` | rewrite | subcommands `profile`, `trace`, `run`, `inspect`, `doctor`; `--module`, `--manifest` (optional, repeatable), `--hook-symbol`, `--pause`, `--kill-on-timeout`, `--trace`, `--json` |
| `src/main.rs` | modify | dispatch; capture loops on `Engine`/`SlotTable`; `run`/`inspect`/`doctor` dispatch |
| `src/run.rs` | create | fork/barrier/exec child, pause arming, lifecycle, exit status |
| `src/inspect.rs` | create | `inspect --pid` (scan only) text/JSON |
| `src/doctor.rs` | create | probes, table, verdict, exit code |
| `src/lib.rs` | modify | module list |
| `tests/common/mod.rs` | create | fixture builder shared by root integration tests |
| `tests/discovery_scan.rs`, `tests/discovery_engine.rs`, `tests/pause.rs`, `tests/run_cmd.rs`, `tests/cli_commands.rs` | create | integration tests named in the tasks |
| `tests/artifact_contracts.rs` | modify | map inventory (`DESCRIPTORS`, `PAUSE_PIDS`, `DISCOVERY`, `EXPORT_STATE`), evidence checker self-test, script list |
| `tests/manifest_pinning.rs` | modify | `pin_objects_with` |
| `spike/harness.c` | modify | optional second go-file gate after `dlopen`+`C_GetFunctionList` |
| `scripts/check-capture-evidence.py` | modify | schema v2, per-module shape, discovery counters, new lanes |
| `scripts/verify-attach-e2e.sh` | modify | lanes: scan `--pid`, `run` (pause), `run --pause never`, Yama `ptrace_scope=1`, proxy+provider |
| `scripts/verify-canaries.sh`, `scripts/verify-induced-gaps.sh`, `scripts/bench-overhead.sh`, `scripts/build-release.sh` | modify | manifest-free CLI where the lane's point is discovery; `--manifest` kept where it is only transport |
| `scripts/matrix/*.sh`, `scripts/lib.sh` | modify | docker/shared-layer/kind/knative on `--cgroup` without copying anything in; `discover_copied_provider`/`rewrite_container_manifest` deleted; fork-scope capsh rows re-measured incl. `--cgroup` minimum |
| `scripts/attach-pod.sh` | create | pod → cgroup path → `p11scope profile --cgroup` (≈40 lines) |
| `scripts/gates.sh` | modify | new lanes |
| `.github/workflows/ci.yml` | modify | e2e lanes, `capsh` privilege rows, kernel recorded |
| `docs/schema/observed-profile-v2.md` | create | v2 schema + v1.4 → v2 migration |
| `docs/usage.md`, `README.md`, `CHANGELOG.md`, `docs/privacy/allowlist-v1.md`, `docs/superpowers/plans/ROADMAP.md`, `docs/notes/2026-08-16-slice1b-spikes.md`, `docs/notes/phase4-privileges.md` | modify/create | docs rewrite, measured privileges, spikes, status |

## Shared interfaces (every task's implementer reads this block)

```rust
// crates/manifest/src/maps.rs — after Task 2
pub enum MappedPath { Usable(PathBuf), Unusable { reason: String } }
pub enum Resolved { File { path: MappedPath, raw_path: Vec<u8>, file_offset: u64, device: Device, inode: u64, permissions: [u8; 4] }, Anonymous, Unmapped }
pub fn resolve(maps: &[MapEntry], vaddr: u64) -> Resolved;
pub fn map_key(entry: &MapEntry) -> MappingFileKey;      // (device.major, device.minor, inode)

// crates/manifest/src/builder.rs (feature identify) — after Task 2
pub type Opener<'a> = &'a dyn Fn(&Path) -> Result<File, String>;
pub fn open_direct(path: &Path) -> Result<File, String>;  // == identity::open_object
pub struct ObjectTable;                                     // module object id 0 + approved keys
impl ObjectTable {
    pub fn new(module_path: PathBuf, module_key: MappingFileKey, identity: ObjectIdentity, approved: Option<BTreeSet<MappingFileKey>>) -> Self;
    pub fn resolve(&mut self, path: MappedPath, raw_path: Vec<u8>, file_offset: u64, key: MappingFileKey, opener: Opener) -> Resolution;
    pub fn into_records(self) -> Vec<ObjectRecord>;
}
pub fn resolve_values(values: Vec<(&'static str, usize)>, maps: &[MapEntry], objects: &mut ObjectTable, opener: Opener) -> Vec<FunctionRecord>;
pub fn alias_groups(surfaces: &[SurfaceRecord]) -> Vec<AliasGroup>;
pub fn validated_file_identity(path: &Path, file: &File, expected: MappingFileKey) -> Result<ObjectIdentity, String>;
pub fn manifest_version(v: cryptoki_sys::CK_VERSION) -> Version;   // NOTE: builder takes (u8,u8), see Task 2

// src/discovery/mod.rs
pub type ModuleId = u32;

// src/discovery/elf.rs — Task 3
pub fn supported(file: &File) -> Result<(), String>;                       // ELF64 little-endian x86-64, else named reason
pub fn exports(file: &File, wanted: &[&str]) -> Result<Vec<String>, String>; // defined FUNC dynsyms among `wanted`
pub fn symbol_vaddr(file: &File, name: &str) -> Result<Option<u64>, String>; // st_value of a defined dynsym (link-time vaddr)
pub fn interpreter(file: &File) -> Result<Option<String>, String>;         // PT_INTERP path

// src/discovery/procfs.rs — Task 4
pub enum ProcError { Gone, Denied(String), Other(String) }
pub struct ProcessRef { pub pid: u32, pub start_time: u64 }
impl ProcessRef { pub fn open(pid: u32) -> Result<Self, ProcError>; pub fn still_same(&self) -> bool; }
pub fn read_maps(pid: u32) -> Result<Vec<MapEntry>, ProcError>;
pub struct ProcMem;                                                       // /proc/<pid>/mem, pread only
impl ProcMem { pub fn open(pid: u32) -> Result<Self, ProcError>; pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, ProcError>; pub fn read_cstr(&self, addr: u64, cap: usize) -> Result<Option<Vec<u8>>, ProcError>; }
pub fn open_mapped_object(pid: u32, entry: &MapEntry) -> Result<File, String>; // /proc/<pid>/root/<path>, identity == map_key(entry)
pub fn root_opener(pid: u32) -> impl Fn(&Path) -> Result<File, String>;
pub fn interpreter_of(pid: u32) -> Result<Option<(String, File)>, ProcError>; // PT_INTERP of /proc/<pid>/exe opened via root
pub fn thread_states(pid: u32) -> Result<Vec<u8>, ProcError>;               // stat state byte per task
pub fn cgroup_procs(dir: &Path) -> std::io::Result<Vec<u32>>;              // dir + descendants
pub fn load_bias(maps: &[MapEntry], key: MappingFileKey) -> Option<u64>;   // start of the mapping with file_offset 0

// src/discovery/registry.rs — Task 3
pub enum HookAbi { FunctionList = 0, InterfaceList = 1, Interface = 2 }
pub struct HookSymbol { pub name: String, pub abi: HookAbi }
pub fn builtin() -> Vec<HookSymbol>;                       // C_GetFunctionList, C_GetInterfaceList, C_GetInterface, NSC_GetFunctionList, FC_GetFunctionList
pub fn parse_hook_symbol(s: &str) -> Result<HookSymbol, String>;   // "NAME[:functionlist|interfacelist|interface]"
pub fn registry(extra: &[HookSymbol]) -> Vec<HookSymbol>;   // builtin + extra, first definition wins; index == hook_id

// src/discovery/scan.rs — Task 5
pub struct ScanOptions<'a> { pub module_hints: &'a [PathBuf], pub registry: &'a [HookSymbol] }
pub enum MemAccess { Available, Unavailable(String) }
pub struct ScannedModule { pub key: MappingFileKey, pub path: String, pub identity: ObjectIdentity, pub file: File, pub exports: Vec<String>, pub manifest: Manifest }
pub struct SkippedObject { pub path: String, pub reason: String }
pub struct ScanReport { pub modules: Vec<ScannedModule>, pub skipped: Vec<SkippedObject>, pub mem: MemAccess }
pub fn scan_pid(pid: u32, opts: &ScanOptions<'_>) -> Result<ScanReport, ProcError>;
pub struct TableHit { pub addr: u64, pub version: (u8, u8), pub n: usize }
pub fn detect_tables(words: &[u64], base: u64, exec: &[(u64, u64)]) -> Vec<TableHit>;   // pure detector
pub fn table_len(version: (u8, u8)) -> Option<usize>;      // 67 / 68 / 92 / 104 / None (major ∉ {2,3})

// src/discovery/identity.rs — Task 4 additions
pub fn pin_objects_with(m: &Manifest, opener: Opener<'_>) -> Result<PinnedObjects, Vec<String>>;
impl PinnedObjects { pub fn identity(&self, path: &str) -> Option<(MappingFileKey, String)>; pub fn build_id(&self, path: &str) -> Option<String>; pub fn file(&self, path: &str) -> Option<&File>; }

// src/slots.rs — Task 8
pub struct AttachKey { pub object: MappingFileKey, pub sha256: String, pub file_offset: u64 }
pub struct LiveSlot { pub index: u32, pub key: AttachKey, pub object: String, pub names: Vec<String>, pub aliased: bool, pub semantics: SlotSemantics, pub descriptor: u32, pub fork_safe: bool, pub module_ids: Vec<ModuleId>, pub ambiguous: bool }
pub struct Merge { pub new: Vec<u32>, pub shared: Vec<u32>, pub skipped: Vec<(String, u64, String)> }
pub struct SlotTable { pub slots: Vec<LiveSlot> }
impl SlotTable { pub fn new() -> Self; pub fn merge(&mut self, module_id: ModuleId, plan: &AttachPlan, identity: &dyn Fn(&str) -> Option<(MappingFileKey, String)>) -> Merge; pub fn module_of(&self, slot: u32) -> Option<ModuleId>; }

// src/attach.rs — Tasks 8, 10
pub struct SessionOptions { pub pause: bool, pub exec_hook: bool }
pub struct AttachOutcome { pub attached: usize, pub failures: Vec<(u32, String)>, pub merge: Merge }
impl Session {
    pub fn start(scope: &Scope, policy: CapturePolicy, options: SessionOptions) -> Result<Self>;
    pub fn attach_module(&mut self, table: &mut SlotTable, module_id: ModuleId, plan: &AttachPlan, objects: &PinnedObjects) -> AttachOutcome;
    pub fn attach_loader_hook(&mut self, ld_so: &File) -> Result<()>;
    pub fn attach_export_hooks(&mut self, object: &File, hooks: &[(u32, HookAbi)]) -> Vec<String>;
    pub fn arm_pause(&mut self, pid: u32) -> Result<()>;
    pub fn disarm_pause(&mut self, pid: u32) -> Result<()>;
    pub fn discovery_ring_fd(&self) -> Result<OwnedFd>;
    pub fn detach_producers(&mut self) -> Result<()>;
    pub fn attach_failures(&self) -> &[(u32, String)];
    pub fn attached_probes(&self) -> usize;
}

// src/events.rs — Task 10
pub struct DiscoveryDrain<'a>;
impl<'a> DiscoveryDrain<'a> { pub fn new(ebpf: &'a mut Ebpf) -> Result<Self>; pub fn poll(&mut self, f: impl FnMut(DiscoveryRecord)); pub fn malformed(&self) -> u64; }

// src/discovery/pause.rs — Task 11
pub enum PauseMode { Auto, Never, Always }
pub fn parse_pause(s: &str) -> Result<PauseMode, String>;
pub enum PauseOutcome { Confirmed, Partial }
pub struct PauseGuard;   // owns the run child's pidfd; resume-once; Drop resumes an outstanding stop
impl PauseGuard { pub fn new(pid: u32, pidfd: OwnedFd) -> Self; pub fn prove_authority(&self) -> std::io::Result<()>; pub fn note_stop_requested(&mut self); pub fn outstanding(&self) -> bool; pub fn confirm_stopped(&self, timeout: Duration) -> PauseOutcome; pub fn resume(&mut self) -> std::io::Result<()>; }
pub fn pidfd_open(pid: u32) -> std::io::Result<OwnedFd>;
pub fn pidfd_send_signal(fd: &OwnedFd, sig: i32) -> std::io::Result<()>;

// src/discovery/engine.rs — Task 12
pub enum Source { Scan, Live, Manifest }
pub struct Module { pub id: ModuleId, pub key: MappingFileKey, pub path: String, pub sha256: String, pub build_id: Option<String>, pub sources: BTreeSet<Source>, pub corroborated: bool, pub manifest: Manifest, pub plan: AttachPlan, pub pinned: PinnedObjects, pub scan_ms: Option<u64>, pub attached_at_ms: Option<u64>, pub attach_gap_ms: Option<u64>, pub notes: Vec<String> }
pub enum EngineScope { Pid(u32), Cgroup(PathBuf), RunChild(u32) }
pub struct EngineConfig { pub scope: EngineScope, pub module_hints: Vec<PathBuf>, pub manifests: Vec<PathBuf>, pub registry: Vec<HookSymbol>, pub pause: Option<PauseGuard> }
pub struct TickChanges { pub new_slots: Vec<u32>, pub ambiguous: Vec<(u32, Vec<ModuleId>)> }
pub struct DiscoveryEvidence { /* per §4.8: modules[], conflicts, uncorroborated, module_ambiguous, attach_gap_ms, pause, modules_skipped, pending, notes */ }
pub struct Engine;
impl Engine {
    pub fn new(config: EngineConfig) -> Result<Self>;
    pub fn start(&mut self, session: &mut Session, table: &mut SlotTable) -> Result<TickChanges>;  // manifests, initial sweep, loader hooks
    pub fn tick(&mut self, session: &mut Session, table: &mut SlotTable) -> Result<TickChanges>;   // drain DISCOVERY, handle, sweep, resume
    pub fn wait(&self, timeout: Duration);                                                          // poll(2) on the DISCOVERY ring fd
    pub fn evidence(&self, table: &SlotTable) -> DiscoveryEvidence;
    pub fn finish(&mut self) -> DiscoveryEvidence;                                                  // marks uncorroborated manifest tables
    pub fn modules(&self) -> &[Module];
}

// src/semantics.rs — Task 9
pub struct SessionKey { pub process: ProcessKey, pub module: ModuleId, pub handle: u64 }
impl State { pub fn sync_slots(&mut self, table: &SlotTable); pub fn purge_modules(&mut self, modules: &[ModuleId]) -> u64; pub fn session_pseudonym_process(&self, process: ProcessKey, module: ModuleId, raw: u64) -> Option<u64>; }

// src/trace.rs — Task 8
impl Tracer { pub fn new(table: &SlotTable) -> Self; pub fn sync_slots(&mut self, table: &SlotTable); }
```

---

### Task 1: Spikes — the unprivileged half, recorded in a note

**Files:**
- Create: `docs/notes/2026-08-16-slice1b-spikes.md`

**Interfaces:** none (a research task). Consumes spec §6.

- [ ] **Step 1: Spike 1 — musl `_dl_debug_state`.** Without root or docker: `mkdir -p /tmp/claude-1000/-home-user-src-m-pkcs11-scope/*/scratchpad/musl 2>/dev/null; cd <scratchpad>/musl && apt-get download musl && dpkg -x musl_*.deb x && llvm-readelf --dyn-syms x/usr/lib/x86_64-linux-musl/libc.so | grep -E '_dl_debug_state|__dl_debug_state'`. Expected: `_dl_debug_state` present as a defined `FUNC` (musl `ldso/dynlink.c`: `void __dl_debug_state(void) {}` + `weak_alias(__dl_debug_state, _dl_debug_state)`). Record symbol name, binding, and that musl's dynamic loader *is* `libc.so` (so `PT_INTERP` = `/lib/ld-musl-x86_64.so.1`, a symlink to `libc.so`). If absent, record the fallback (`dlopen` return in libc) as the required path.

- [ ] **Step 2: Spike 2 — glibc ordering.** Confirm from the pinned glibc versions (2.35, 2.39) that `RT_CONSISTENT` + `_dl_debug_state()` runs after relocation and before constructors, for both the initial link set (`elf/rtld.c`, `dl_main`: `r->r_state = RT_CONSISTENT; _dl_debug_state ();` precedes `_dl_init`) and `dlopen` (`elf/dl-open.c`, `dl_open_worker`: "Notify the debugger all new objects have been relocated" precedes `_dl_init (new, …)`). Sources: `apt-get source glibc` if `deb-src` is enabled, else `curl -sL https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=elf/dl-open.c;hb=refs/tags/glibc-2.39`. Then confirm empirically with gdb on this host (`gdb -batch -ex 'break _dl_debug_state' -ex run -ex 'print _r_debug.r_state' -ex 'print done_ctor' -ex continue … --args ./dlopen-fixture`) using a tiny fixture whose constructor sets a global `done_ctor = 1`: at the `RT_CONSISTENT` hit for the fixture, `done_ctor` must still be 0. Record the observed sequence (RT_ADD, RT_CONSISTENT, then constructor).

- [ ] **Step 3: Spike 2b — reading `_r_debug.r_state` through `/proc/<pid>/mem`.** In-process check: `_r_debug` is a defined dynsym of the host `ld-linux-x86-64.so.2` (`llvm-readelf --dyn-syms /lib64/ld-linux-x86-64.so.2 | grep ' _r_debug'`); `struct r_debug { int r_version; struct link_map *r_map; ElfW(Addr) r_brk; enum r_state; ElfW(Addr) r_ldbase; }` → `r_state` is the 4-byte field at offset 24 on x86-64. Record: vaddr = load bias of ld.so (start of the mapping whose file offset is 0) + `st_value`; value read via `pread(/proc/self/mem)` equals `RT_CONSISTENT` (0) at rest. This is what Task 12 uses.

- [ ] **Step 4: Spike 6 (unprivileged half) — Yama `ptrace_scope=1`.** On this host (`cat /proc/sys/kernel/yama/ptrace_scope` = 1): start `sleep 30 &` (a same-uid, non-descendant-of-the-reader process when read from a *different* shell/subprocess: use `setsid sleep 30 &` so it is not our descendant); confirm `cat /proc/$PID/maps` succeeds and `dd if=/proc/$PID/mem bs=8 count=1 skip=<mapped addr/8>` fails with `EPERM`/`EIO`; confirm the same `mem` read succeeds on a direct child (`sleep 30 &` from the same shell). Record the exact errno for both — Task 4 maps it to `MemAccess::Unavailable("ptrace: …")`.

- [ ] **Step 5: Record the root-only spikes as UNRUN.** Spikes 3 (`bpf_send_signal(SIGSTOP)` gap measurement), 4 (`/proc/<pid>/root` + `mapping_file_key` on overlay2/btrfs), 5 (verifier acceptance of the discovery programs on 5.15/6.8) and the live half of 6 are answered in Task 11 (root spike, owner-approved) or Task 23 (root gates); write each as `UNRUN — Task 11/23` with the exact command that will answer it. Note the host has no 5.15 kernel: 5.15 acceptance is CI-runner-kernel-recorded + feature-probed, never asserted from this host.

- [ ] **Step 6: Commit** `git add docs/notes/2026-08-16-slice1b-spikes.md && git commit -m "docs: slice 1b spikes — musl _dl_debug_state, glibc RT_CONSISTENT ordering, _r_debug read, Yama scope 1 (unprivileged half)"`.

---

### Task 2: Shared table builder — move `resolve`/`ObjectTable`/`alias_groups` into `p11scope-manifest`

**Files:**
- Modify: `crates/manifest/src/maps.rs` (append `MappedPath`, `Resolved`, `resolve`, `mapped_path`, `map_key` from `crates/discover/src/maps.rs`)
- Create: `crates/manifest/src/builder.rs`
- Modify: `crates/manifest/src/lib.rs` (`#[cfg(feature = "identify")] pub mod builder;`), `crates/manifest/Cargo.toml` (`cryptoki-sys` not needed — builder takes `(u8, u8)`)
- Modify: `crates/discover/src/maps.rs` → `pub use p11scope_manifest::maps::{Device, MapEntry, MappedPath, Resolved, parse_maps, resolve};`
- Modify: `crates/discover/src/discover.rs` (delete `ObjectTable`, `resolve_values`, `alias_groups`, `validated_file_identity`, `validated_identity`, `unusable_file`, `manifest_version`, `map_key`, `file_key`; import from `builder`; `ObjectKey` → `MappingFileKey`)
- Test: existing `crates/discover/tests/*.rs` (unchanged, they are the guard) + `crates/manifest/tests/identity.rs` gets `resolve` tests moved from `crates/discover/src/maps.rs`

**Interfaces:**
- Produces: the `maps`/`builder` items in *Shared interfaces*.

- [ ] **Step 1: Move `resolve` and friends.** Cut lines 6–67 of `crates/discover/src/maps.rs` (`MappedPath`, `Resolved`, `mapped_path`, `resolve`) into `crates/manifest/src/maps.rs` (make `mapped_path` `pub`); add `pub fn map_key(entry: &MapEntry) -> MappingFileKey { MappingFileKey { device_major: entry.device.major, device_minor: entry.device.minor, inode: entry.inode } }` (`MappingFileKey` is `#[cfg(feature = "identify")]` today — lift the cfg from the struct so it is always available; keep `mapping_file_key()` under the feature). Move the `#[cfg(test)]` block of the discover `maps.rs` along with it. Leave `crates/discover/src/maps.rs` as the one-line re-export.

- [ ] **Step 2: Run the discover crate tests to see they still pass:** `cargo +1.88 test --locked -p p11scope-discover -p p11scope-manifest` → PASS.

- [ ] **Step 3: Create `crates/manifest/src/builder.rs`** by moving from `discover.rs`: `ObjectTable` (fields `module_key`, `approved: Option<BTreeSet<MappingFileKey>>` — `None` = every key approved, which is what the scan needs since it has no "before/after dlopen" split; `Some(set)` keeps the helper's behaviour), `resolve_values`, `alias_groups`, `validated_file_identity`, `unusable_file`, `manifest_version(major, minor)`. Every open goes through the `Opener` parameter; `open_direct` = `identity::open_object`. Signatures exactly as in *Shared interfaces*. `ObjectTable::resolve` (previously reading `MAX_OBJECTS = 512`) keeps the cap as `pub const MAX_OBJECTS: usize = 512`.

- [ ] **Step 4: Rewire `discover.rs`** to `use p11scope_manifest::builder::{ObjectTable, resolve_values, alias_groups, validated_file_identity, open_direct, MAX_OBJECTS}` and pass `&open_direct` as the opener everywhere; `ObjectKey` → `MappingFileKey`; `file_key(file)` → `identity::mapping_file_key(file)`. `provenance_objects` (dead lane, still serialised as `[]`): keep the function but it may stay in `discover.rs`.

- [ ] **Step 5: Run everything:** `cargo +1.88 fmt --all && cargo +1.88 test --locked --workspace --all-targets` → PASS (the discover fixture/version-matrix/lazy-dependency/softhsm tests prove behaviour is unchanged). `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings` → clean.

- [ ] **Step 6: Commit** `git commit -am "manifest: builder — ObjectTable/resolve_values/alias_groups and maps::resolve shared by the helper and the observer"`.

---

### Task 3: `discovery::elf` and `discovery::registry`

**Files:**
- Modify: `Cargo.toml` (root): `[dependencies] object = { version = "0.39", default-features = false, features = ["read", "elf"] }` (the same crate/version `p11scope-manifest` already locks — check `grep -A2 'name = "object"' Cargo.lock`)
- Create: `src/discovery/elf.rs`, `src/discovery/registry.rs`
- Modify: `src/discovery/mod.rs`: `pub mod elf; pub mod registry; pub type ModuleId = u32;`
- Test: unit tests inside both files (fixtures: the host's own `ld-linux-x86-64.so.2`, `libc.so.6`, `std::env::current_exe()`, and a gcc-built `crates/discover/tests/fixture/version_matrix.c`)

**Interfaces:**
- Produces: `elf::{supported, exports, symbol_vaddr, interpreter}`, `registry::{HookAbi, HookSymbol, builtin, parse_hook_symbol, registry}`.

- [ ] **Step 1: Write the failing tests** (`src/discovery/elf.rs`, `#[cfg(test)]`):

```rust
#[test]
fn host_loader_exports_dl_debug_state_and_r_debug() {
    let ld = std::fs::File::open("/lib64/ld-linux-x86-64.so.2").unwrap();
    assert_eq!(supported(&ld), Ok(()));
    assert_eq!(exports(&ld, &["_dl_debug_state", "nope"]).unwrap(), vec!["_dl_debug_state"]);
    assert!(symbol_vaddr(&ld, "_r_debug").unwrap().is_some());
    assert_eq!(symbol_vaddr(&ld, "definitely_absent").unwrap(), None);
}
#[test]
fn own_executable_names_its_interpreter() {
    let exe = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(interpreter(&exe).unwrap().as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
    let ld = std::fs::File::open("/lib64/ld-linux-x86-64.so.2").unwrap();
    assert_eq!(interpreter(&ld).unwrap(), None);
}
#[test]
fn non_elf_and_foreign_class_are_refused_with_a_reason() {
    let dir = tempfile::tempdir().unwrap();
    let text = dir.path().join("x.txt"); std::fs::write(&text, b"hello").unwrap();
    assert!(supported(&std::fs::File::open(&text).unwrap()).unwrap_err().contains("not an ELF"));
    // A hand-made ELFCLASS32 header (52 bytes) is enough for the class check.
    let mut hdr = vec![0u8; 52]; hdr[..4].copy_from_slice(b"\x7fELF"); hdr[4] = 1; hdr[5] = 1; hdr[16] = 3; hdr[18] = 3;
    let f32 = dir.path().join("x32.so"); std::fs::write(&f32, &hdr).unwrap();
    assert!(supported(&std::fs::File::open(&f32).unwrap()).unwrap_err().contains("ELFCLASS32"));
}
#[test]
fn fixture_exports_only_the_registry_names_it_defines() {
    // gcc -shared -fPIC -o $TMP/vm.so crates/discover/tests/fixture/version_matrix.c
    let out = std::env::temp_dir().join(format!("p11scope-elf-{}.so", std::process::id()));
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/crates/discover/tests/fixture/version_matrix.c");
    assert!(std::process::Command::new("gcc").args(["-shared", "-fPIC", "-o"]).arg(&out).arg(src).status().unwrap().success());
    let f = std::fs::File::open(&out).unwrap();
    let names = crate::discovery::registry::builtin().into_iter().map(|h| h.name).collect::<Vec<_>>();
    let wanted: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_eq!(exports(&f, &wanted).unwrap(), vec!["C_GetFunctionList", "C_GetInterfaceList", "C_GetInterface"]);
    std::fs::remove_file(out).unwrap();
}
```

and in `registry.rs`:

```rust
#[test]
fn builtin_registry_order_and_parsing() {
    let b = builtin();
    assert_eq!(b.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), ["C_GetFunctionList", "C_GetInterfaceList", "C_GetInterface", "NSC_GetFunctionList", "FC_GetFunctionList"]);
    assert_eq!(b[1].abi, HookAbi::InterfaceList); assert_eq!(b[2].abi, HookAbi::Interface); assert_eq!(b[4].abi, HookAbi::FunctionList);
    assert_eq!(parse_hook_symbol("X_GetFunctionList").unwrap(), HookSymbol { name: "X_GetFunctionList".into(), abi: HookAbi::FunctionList });
    assert_eq!(parse_hook_symbol("Y:interfacelist").unwrap().abi, HookAbi::InterfaceList);
    assert!(parse_hook_symbol("Y:bogus").unwrap_err().contains("abi"));
    assert!(parse_hook_symbol("").is_err());
    let r = registry(&[parse_hook_symbol("C_GetFunctionList:interface").unwrap(), parse_hook_symbol("Z").unwrap()]);
    assert_eq!(r.len(), 6); assert_eq!(r[0].abi, HookAbi::FunctionList, "builtin wins"); assert_eq!(r[5].name, "Z");
}
```

- [ ] **Step 2: Run to see them fail:** `cargo +1.88 test --locked -p p11scope discovery::elf discovery::registry` → compile error (modules missing).

- [ ] **Step 3: Implement `elf.rs`** with `object::read::elf::ElfFile64<Endianness>`: read the whole file with the existing `p11scope_manifest::identity` byte cap pattern (`MAX_OBJECT_BYTES` guard, `read_at` loop, or `std::fs::read` on `/proc/self/fd/N`); `supported`: `object::FileKind::parse` must be `Elf64`, `e_machine == EM_X86_64`, little-endian → else `Err("not an ELF object")` / `Err("ELFCLASS32 object (32-bit targets are a later slice)")` / `Err(format!("foreign machine {:#x}", m))`. `exports`: iterate `file.dynamic_symbols()`, keep `is_definition() && kind() == SymbolKind::Text` (FUNC) whose name ∈ `wanted`, in `wanted` order. `symbol_vaddr`: dynamic symbol by name → `address()`. `interpreter`: `file.elf_program_headers()` find `p_type == PT_INTERP`, read `p_offset..p_offset+p_filesz`, strip trailing NUL. Add `object` to root `Cargo.toml`, run `cargo +1.88 check --workspace` (no `--locked`) once, confirm `git diff Cargo.lock` only adds the `object` edge to `p11scope`.

- [ ] **Step 4: Implement `registry.rs`** (`HookAbi` `#[repr(u32)]` with `as_u32()`/`from_u32()`; `parse_hook_symbol` splits on the *last* `:`, lowercases the suffix, rejects empty names, names containing whitespace, or an unknown ABI with `"--hook-symbol: unknown abi {s:?} (functionlist|interfacelist|interface)"`).

- [ ] **Step 5: Run tests:** `cargo +1.88 test --locked -p p11scope discovery::` → PASS. Four checks green.

- [ ] **Step 6: Commit** `git commit -am "discovery: elf (dynsym exports, symbol vaddr, PT_INTERP) and hook-symbol registry"`.

---

### Task 4: `discovery::procfs` + pinning through `/proc/<pid>/root`

**Files:**
- Create: `src/discovery/procfs.rs`
- Modify: `src/discovery/identity.rs` (`pin_objects_with`, `identity`, `build_id`, `file`; `pin_manifest_objects` = `pin_objects_with(m, &open_direct)`), `src/discovery/mod.rs`
- Modify: `tests/manifest_pinning.rs` (one new test for `pin_objects_with` with a custom opener)
- Test: unit tests in `procfs.rs` on `self` and on a spawned child

**Interfaces:**
- Consumes: `p11scope_manifest::maps::{parse_maps, map_key}`, `identity::mapping_file_key`, `builder::validated_file_identity`.
- Produces: everything under `// src/discovery/procfs.rs` and the `identity.rs` additions in *Shared interfaces*.

- [ ] **Step 1: Failing tests** (`procfs.rs`):

```rust
#[test]
fn self_maps_mem_and_root_open_agree_on_identity() {
    let me = std::process::id();
    let p = ProcessRef::open(me).unwrap(); assert!(p.still_same());
    let maps = read_maps(me).unwrap();
    let exe = std::env::current_exe().unwrap();
    let entry = maps.iter().find(|m| m.permissions[2] == b'x' && m.raw_path.as_deref() == Some(exe.as_os_str().as_encoded_bytes())).