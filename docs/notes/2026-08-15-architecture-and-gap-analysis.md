# pkcs11-scope — architecture review and gap analysis

**Date:** 2026-08-15 · **Tree:** `main` @ `f35c04e` (clean) · **Scope:** internal
architecture (KISS/DRY/YAGNI, maintainability, extensibility, reliability), spec-vs-tree
gap analysis for a PKCS#11 workload observer, and — as a separate part — the
privilege/capability model and reduced-capability operation.

Method: every product source file was read end to end (28.8k lines Rust across 5
crates, 6.2k lines of gate scripts, ~14k lines of specs/plans/notes). Findings cite
`file:line` on this tree. Nothing was changed; this is a report.

---

## 0. TL;DR

1. **The observer core is sound and unusually honest.** Discovery-by-offset,
   fail-closed BPF policy publication, count-authority-in-maps, evidence-not-guess —
   the ideas are right and the eBPF side is carefully bounded.
2. **The authorization/provenance layer has outgrown the product.** `verify.rs` +
   `discover_cmd.rs` + `oracle.rs` = **5.8k product lines — as large as the entire observer
   (6.0k) — 9.3k of the 17.2k lines in `src/` with their in-file tests** — defending
   against a *hostile observed workload* forging what the observer counts — a threat whose
   payoff (misattributed statistics; pointer reads already contained by `allowlisted`) is
   small, while its cost is huge: `CAP_LEASE`, a root-owned sibling helper, a global
   `suid_dumpable=0` sysctl toggle, glibc-only runtime staging in `/run/p11scope`, a
   supervisor/worker fork, exit 78, and 441-line staging shell just to run the binary.
   This is the #1 KISS violation and the #1 reason the tool cannot run with reduced
   capabilities today.
3. **The default build cannot serve the migration use case.** Under the default
   `allowlisted` policy `mechanisms[].params` is always `null` and `templates` always
   empty (`render.rs:710-713,775-779`); rejected `*Init` mechanisms are not attributed. The
   spec's G2 acceptance table (RSA-PSS hash/MGF/salt, GCM lengths, requested attributes for
   `pkcs11-lab`) is only met by the `unsafe-unvalidated-metadata` build that the release
   artifact deliberately excludes.
4. **Two throughput ceilings undermine the flagship "long-running profile" mode:** a
   256 KiB ring polled every 1 s (~900 events/s before loss, `ebpf-common:436`,
   `main.rs:504`) and a monotonic, never-refunded 16 384 semantic-key budget
   (`semantics.rs:1044-1058`) that permanently degrades after ~16k session opens.
5. **Privilege model is all-or-nothing.** There is no tier below "helper root-owned +
   read leases (ownership or `CAP_LEASE`) + BPF (`CAP_SYS_ADMIN` on Ubuntu) [+
   `CAP_SYS_PTRACE` for containers]". A `--trusted-workload` run still requires leases;
   lease failure is fatal (`verify.rs:1418,1502`). Section 4 proposes a 4-tier ladder in
   which "just count function calls/RVs/latency" needs only BPF capabilities.
6. **DRY debt is mechanical and large:** the 40-field `Evidence` struct is hand-copied
   through six layers; ~14 near-identical map verify/publish blocks; two `LeaseMonitor`
   impls; `capget` shims duplicated across crates; arg parsing duplicated per subcommand;
   three time formatters; three (dev,ino) key types.
7. **Test/doc process debt:** invariants asserted by grepping source text and shell-script
   text (`main.rs:1037-1075`, `tests/release_contracts.rs`), 6.2k lines of sudo-only gate
   scripts and **no CI**; the "current contract" is spread across five overlapping specs
   with mutual "superseded" notes; gate evidence lives in an ignored `.superpowers/sdd/`.
8. **Simple use cases missing:** run-a-command (`--cmd`, in the spec), "which provider does
   PID N use", preflight/`doctor`, trace filters, JSONL trace, periodic snapshots/checkpoints,
   `SIGTERM` clean stop, ring/limits knobs, profile diff/merge, first-class container path.

---

## 1. What the tree is

| Part | Lines | Role |
| --- | ---: | --- |
| `src/` (root crate `p11scope`) | 17 176 | CLI, attach engine, semantics, render, provenance/lease/supervisor |
| `crates/discover` | 1 739 | unprivileged dlopen helper (`p11scope-discover`) |
| `crates/manifest` | 983 | manifest v4 schema + identity/maps/ELF-loader validator |
| `crates/ebpf` + `ebpf-common` | 1 533 | BPF programs + shared ABI |
| `tests/` + crate tests | ~5 500 | 342 `#[test]`s |
| `scripts/` | 6 183 | gates (sudo/docker/kind), release build, canaries |
| `docs/superpowers` specs+plans | 10 618 | 6 specs, 12 plans |

Built in five days (120 commits, 2026-08-10 → 08-14). The last two days added ~9k lines of
authorization code in response to a review that escalated the threat model.

Product-code split by concern (excluding tests inside files):

- observer proper (`attach, events, metrics, scope, plan, kinds, shapes, semantics,
  process, trace, render, main`) ≈ 6.0k product lines;
- authorization/provenance/lease/supervisor (`verify 2.4k, discover_cmd 1.5k,
  oracle 1.8k`) ≈ **5.8k product lines** (9.3k with their in-file tests) — as large as the
  observer it protects, written in the last two of the five days.

---

## 2. Internal architecture

### 2.1 As-is layering

```
p11scope-discover (unprivileged, dlopen)  ──manifest v4──▶  p11scope (privileged)
                                                              │
   main.rs ── cmd_profile / cmd_trace ── load_plan ─────────▶ verify::check_reuse
                                          │                   discover_cmd::select_oracle ─▶ oracle::select
                                          │                   discover_cmd::rediscover_stable (helper exec, leases)
                                          │                   verify::check_provenance
                                          ▼
                              verify::supervise_capture (fork; supervisor keeps leases)
                                          │ worker
                                          ▼
                       attach::Session::start ── scope::publish, shapes::publish (map freeze), aya load/attach
                                          │
                     events::Drain ─▶ semantics::State + process::Tracker ─▶ render / trace
                                          │
                              metrics::read (STATS/RV_COUNTS/EVIDENCE) ─▶ render::Evidence.verdict()
```

### 2.2 Strengths (keep these)

- Fail-closed policy: one `CONFIG` word with exactly one scope bit and one policy bit
  (`ebpf-common:148-178`), every control map shape-checked, published, read back and
  frozen before attach (`attach.rs:302-443`).
- Aggregate maps are the count authority; the event stream only adds semantics — the
  right decision, and documented (`schema:26-35`).
- The helper isolation (separate process, privilege drop, `/proc/self/mem` bounded reads,
  16 MiB output cap, 30 s deadline) is the correct shape for running vendor code.
- Manifest schema is typed serde with tagged enums; exact-string schema dispatch.
- Evidence counters exist for every silent-failure class the team could think of.

### 2.3 Structural problems, ranked

**P1 — Authorization layer dwarfs and entangles the product.**
`verify.rs` (2 561 l) glues ≥6 concerns: manifest size/shape limits, reuse checks,
provenance comparison, `LeaseMonitor` (twice: `1400-1445` and `1490-1530`, near-identical),
signal blocking/signalfd, fork supervisor with a 4-byte control protocol
(`READY/GO/DONE/FAILED`, `992-995`), atomic output publication, terminal abort record.
`oracle.rs` (3 331 l, `pub(crate)`) decides "hardened vs trusted" by reading the observer's
own ELF interpreter, `/proc/self/status` uids, `uid_map`, PID 1's user namespace and the
target's status (`oracle.rs:294-355, 357-450`), then stages a glibc runtime closure into
`/run/p11scope` (`oracle.rs:16-19`; hard-coded `/lib64/ld-linux-x86-64.so.2`,
`/usr/lib/x86_64-linux-gnu`, `/usr/lib64` — Debian/Fedora only; Alpine/NixOS never
qualify). `discover_cmd.rs` (3 447 l) mixes the `discover` subcommand, helper trust
(`114-131`), bounded output, closure leasing, an 8-pass stabilization retry
(`25`), and inline C fixture sources in its tests (`1629+`). It still carries
**23** `#[allow(dead_code, reason = "… awaiting C3.3B wiring")]` attributes
(`discover_cmd.rs:144,365,656,725,887-1021`; `oracle.rs:89,95,150,164,1764,1769,1805,1815`;
`verify.rs:1542`) — stripping all of them still passes `cargo +1.88 check`, so the "seam" is
wired and the annotations are stale. The trusted-workload lane is a *second full
implementation* of the helper runner and stabilization loop, not the hardened one minus
checks (`rediscover_from_open_helper_with_timeout 1283-1383` vs `run_hardened_pass
1022-1273` (252 lines); `stabilize 474-503` vs `stabilize_hardened 505-548`) — ~250
duplicated lines. `oracle::PreparedGlibc` holds `&mut discover_cmd::ClosureLeases`
(`oracle.rs:1734-1737`) while `discover_cmd` re-exports `oracle::OracleSelection` and wraps
`oracle::select` — a module cycle held together by `RawFd` plumbing (`helper_fd()`,
`loader_fd()`, `runtime_fds()`, linear `ClosureLeases::file(fd)` lookups,
`discover_cmd.rs:308-336`). `main.rs:173-201` performs six revalidations in a row, one of
them redundant (`select` already revalidates at `oracle.rs:437`).

Why this matters beyond size: (a) `--cgroup` — the container headline — can *never* use
hardened mode (`oracle.rs:300-303`) so it is always a "trusted workload" lane anyway;
(b) the docs concede same-uid targets and malicious providers are out of the model; (c)
under `allowlisted` policy a forged offset yields contained scalars, not secrets. The
residual protected property is *integrity of statistics against a hostile target* — a
property `pkcs11-lab` cannot rely on anyway ("absence means not observed"). Recommend:
keep **identity pinning** (open by path → fstat → SHA-256 → attach on that inode → re-hash
at end → `provider_changed` evidence) as the default; make leases and hardened oracle an
opt-in `--authorization=leased` lane. That is a ~10× reduction of this layer.

**P2 — `main.rs` orchestrates by copy-paste.** `cmd_profile` (`341-411`) and `cmd_trace`
(`598-666`) repeat the same hand-rolled flag loop; `capture_profile` (`414-585`) and
`capture_trace` (`668-810`) repeat the loop shape with `objects.ensure_stable()` sprinkled
5–6× each (`466,505,528,548,577`). `evidence_for` (`933-1004`) takes 7 args and builds a
40-field literal. The tick order invariant is enforced by a test that greps `main.rs`
source text with `rfind` (`1037-1075`) — a maintainability smell that signals the API
should encode the order (`Session::finish(self) -> Terminal`).

**P3 — `attach.rs` is a grab-bag with cycles.** It owns `Scope`, `CapturePolicy`, raw
`bpf(2)` shims and `Session`; `scope.rs:4,73` and `shapes.rs:81` import back into
`attach` (`attach ↔ scope`, `attach ↔ shapes`). `Session.ebpf` is `pub` (`attach.rs:185`)
so `metrics.rs:36,104` and `main.rs:445,879` reach into the map layer. `Session::start_inner`
is 165 lines with two near-identical attach loops (`606-630` vs `641-666`).
`policy_map_data` and the type trio belong in a leaf `policy.rs`.

**P4 — Evidence plumbing is hand-copied through six layers.** `SemanticEvidence`
(`semantics.rs:776-789`), `KernelEvidence` (`metrics.rs:91-100`), `TrackingEvidence`
(`process.rs:12-16`) are re-flattened field by field into `render::Evidence` (`render.rs:10-93`)
by `main.rs:943-1001`; `verdict()` re-lists 31 fields (`render.rs:115-146`); `live()`
re-lists them twice (`225-238`, `248-323`); tests repeat 40-field literals
(`render.rs:838-881`, `trace.rs:406-447`); `trace::evidence_line` serialises → parses →
adds 5 keys → re-serialises and re-forces PARTIAL (`trace.rs:177-196`). Adding one counter
is ~8 edits. `#[serde(flatten)]` of the three source structs plus a
`[(name, value, gates_completeness)]` table would delete ~300 lines.

**P5 — Verdict semantics have been made vacuous.** `mark_terminal_drain_unproven` forces
every written profile to `PARTIAL` (`render.rs:157-159`), so the top-level
`COMPLETE/PARTIAL` no longer distinguishes a clean run from a lossy one; consumers must
re-implement `scripts/check-capture-evidence.py: terminal_capture_is_clean` in Python.
Also `in_flight_at_end == 0` is required for COMPLETE (`render.rs:118`) although the spec
called in-flight "distinct from event loss" (an app blocked in `C_WaitForSlotEvent` is
always PARTIAL). Put `final_drain_proven: false` and `gap_free: true` in the JSON and let
the verdict mean something.

**P6 — Hybrid JSON construction.** Top level via `serde_json::json!` (`render.rs:433-441,
781-807`), sections via typed `*Out` mirror structs that only add `_hex` strings
(`SessionsOut 610-619`, `TemplateOut 576-608`, `CgroupOut 655-677`, `MechanismOut 701-757`),
`params` untyped `Value` (`468-511`), schema ids as literals (`434, 782`). No `Profile`
Rust type equals the schema; `pkcs11-lab` cannot share types. `render::json` is the
*metrics* document (misnamed).

**P7 — Hot-path costs that will show at node scale.**
`has_process_state` linearly scans six maps after *every* event (`semantics.rs:1851-1867`,
called at `main.rs:452,897`) → O(N²) per capture; `Tracker::identify` does a `poll()` or
`/proc/<pid>/stat` read per event (`process.rs:66-70`) and one `poll` per pidfd per tick
(`124-140`); `SlotMeta` with `Vec<String>` cloned per event (`semantics.rs:1117,1456`);
`Tracer` linear `slots.iter().find` + `join("|")` per event (`trace.rs:26-32,274`);
`scope::label` walks all of `/sys/fs/cgroup` once per cgroup id at report time
(`render.rs:656-662`, `scope.rs:32-52`).

**P8 — Ring transport is polled, small, and carries dead payload.** `RING_BYTES=256 KiB`
(`ebpf-common:436`), `Event`=288 B of which 128 B are `attr_types[8]`+`attr_types1[8]`
that the default policy never fills; profile sleeps 1 s (`main.rs:504`), trace 200 ms
(`753`); no `epoll`/blocking wait on the ring fd. Sustained > ~900 calls/s in profile mode
loses events → PARTIAL and degraded `mechanisms/sessions/logins/cgroups`. The stale comment
"holds ~2700 events" (`ebpf-common:431`) shows the number was not re-derived after the
struct grew. `CallStart` 272 B + `Event` 288 B on a 512 B BPF stack in `p11_return`
(`crates/ebpf/src/main.rs:653`) verifies only because LLVM elides — one added field breaks
the verifier.

**P9 — Semantic key budget is monotonic.** `admit()` (`semantics.rs:1044-1058`) never
refunds; `MAX_STATE_KEYS=16_384` (`881`). Open/close-per-request workloads exhaust it in
16k requests; thereafter opens are refused, mechanism attribution collapses,
`semantic_state_drops` grows, verdict PARTIAL forever. The `ponytail:` comment
(`1042-1043`) names the ceiling; it is too low for `--duration 1h`.

**P10 — Reliability nits.** `SIGTERM` is reset to `SIG_DFL` in the worker
(`verify.rs:741`) while only `SIGINT` sets the stop flag (`main.rs:54`), so `systemd stop`,
`timeout`, `kubectl delete` produce no `-o` report; return-probe attached but entry-probe
failed leaves an orphan return probe counted as attached (`attach.rs:615-617,654`);
`Session::start` appends the "unsupported environment" hint to *every* error including
plan-validation errors (`attach.rs:504-505`); `decode_params` silently returns on an
unknown `ulParameterLen` (`crates/ebpf/src/main.rs:170`); fork tracepoint read failure
returns 0 without evidence (`789-790`); `Tracker::new` silently raises `RLIMIT_NOFILE`
(`process.rs:46,196-216`); `apply_auth` clears every active op on any successful
login/logout (`semantics.rs:1385-1409`) — over-conservative and attach-time dependent.

**P11 — Build reproducibility.** `build.rs` shells out to a **floating** `cargo +nightly`
(`build.rs:57`; `crates/ebpf/rust-toolchain.toml` says `channel = "nightly"` unpinned and is
bypassed by `+nightly` anyway); no pre-flight for `nightly`/`rust-src`/`bpf-linker` → opaque
panic; `RUSTFLAGS` leaks into the BPF build (only `RUSTC*` removed, `87-88`). A nightly
regression breaks all four project checks at once.

### 2.4 Ponytail audit (over-engineering, biggest cut first)

```
yagni:  hardened oracle mode + glibc staging + supervisor fork as *default*; keep as opt-in lane.        [src/oracle.rs, src/verify.rs:800-1000, src/discover_cmd.rs:605-625]
delete: 23 stale #[allow(dead_code, "awaiting C3.3B wiring")] (cargo check passes without them).          [src/discover_cmd.rs:144,365,656,725,887-1021; src/oracle.rs:89-1815; src/verify.rs:1542]
shrink: two helper runners + two stabilization loops → one runner parameterised by mode (~-250 lines).      [src/discover_cmd.rs:474-548, 1022-1273, 1283-1383]
shrink: 3 pidfd_open, 2 socketpair/packet protocols, 3 "dup above stdio", 2 validate_protected_directory. [src/verify.rs:1178-1233; src/process.rs:218; src/oracle.rs:453,831,2177,2190; src/discover_cmd.rs:378,917-998]
shrink: 14 map verify/publish blocks → expect_map()/publish_exact_hash().                                 [src/attach.rs:302-443, src/scope.rs:73-160, src/shapes.rs:81-105]
shrink: two LeaseMonitor impls → one.                                                                     [src/verify.rs:1400-1445, 1490-1530]
shrink: cmd_profile/cmd_trace + capture_profile/capture_trace → one arg struct, one loop, one Session::finish. [src/main.rs:341-810]
shrink: Evidence hand-flattening → serde(flatten) + gate table.                                           [src/render.rs:10-160, src/main.rs:933-1004]
delete: *Out mirror structs → derive Serialize on semantics types.                                        [src/render.rs:576-677, 701-769]
delete: SkippedOut (== plan::Skipped).                                                                    [src/render.rs:95-99]
delete: test-only public entry points State::observe/new, Tracer::on_event, Default for Tracker.          [src/semantics.rs:986,1093,1811; src/trace.rs:254; src/process.rs:190]
stdlib: error_chain() == format!("{:#}", anyhow::Error::new(e)).                                          [src/attach.rs:221-240]
stdlib: ProcessMemory::read_exact / read_object_bytes == FileExt::read_exact_at.                          [crates/discover/src/discover.rs:350-369, crates/manifest/src/identity.rs:455-463]
native: CKF_*/CkRv/CkUserType literals already in pkcs11-proxy-ng-types.                                  [src/semantics.rs:842-860,1309,1387; src/trace.rs:69-73]
shrink: 4 program-name lists → one const.                                                                 [src/attach.rs:207-211,242-257,563-574,631-640]
shrink: 3 (dev,ino) key types → one.                                                                      [crates/manifest maps.rs Device, identity.rs MappingFileKey, crates/discover ObjectKey]
shrink: capget/CapHeader/CapData shims duplicated across crates.                                          [src/discover_cmd.rs:76-93, crates/discover/src/main.rs:96-136]
shrink: 3 time formatters → 1.                                                                             [src/render.rs:170, src/trace.rs:126, src/main.rs:1008]
shrink: 4 pid-extraction helpers → Event::pid() in ebpf-common.                                            [src/semantics.rs:883, src/trace.rs:20, src/main.rs:290,312]
delete: Session._config, PublishedScope.config, _cgroup_file (never read).                                [src/attach.rs:190-191,674; src/scope.rs:56-62]
delete: CARGO_CFG_TARGET_ENDIAN → bpfeb branch (x86-64-first tool).                                       [build.rs:48-51]
delete: serde(default) provenance_objects — schema string is refused first.                                [crates/manifest/src/manifest.rs:23]
yagni:  ObjectIdentity{kind,value,sha256,reusable,note} → enum; two fields derivable.                      [crates/manifest/src/identity.rs]
shrink: magic literals: 0x204 (CKR_PENDING) ×2, 68, 512-as-MAX_OBJECTS, arg-index 6 ×3, BPF cmd 22/1.     [crates/ebpf/src/main.rs:677,716; crates/discover/src/discover.rs:578; src/verify.rs:22; src/attach.rs:59,110,293]
delete: dist/ binaries + spike/work token files are ignored ✔ (nothing tracked)                            [—]
```
`net: ≈ -6 000 lines product code possible (mostly authorization lane → opt-in), 0 deps.`

### 2.5 Naming / domain clarity

- "slot" is overloaded everywhere: attach slot (`MAX_SLOTS`, `Event.slot`, `StartKey.slot`)
  vs PKCS#11 `CK_SLOT_ID` (`Event.slot_id`, `SessionInfo.slot`). Rename attach slot →
  `probe`.
- "oracle" means three things: `oracle.rs` (process/mapping authority), the discovery
  helper ("discovery oracle helper", `discover_cmd.rs:119`), and `pkcs11-check` ground
  truth (`verify-oracle.sh`).
- `kinds.rs` contains descriptors, not kinds; `render::json` is the metrics document;
  `detach_producers` unloads; `orphan_ops` vs `async_orphans`; `sessions.closed` vs
  `unmatched_closes`.
- `MechStat.calls/latency` mixes `*Init` (µs) and `C_Sign` (ms) into one histogram
  (`semantics.rs:1192,1264`) — per-mechanism p99 is bimodal and does not answer "is the
  provider slow?" (spec worked example).

### 2.6 Extensibility risks

- x86-64 baked in without `#[cfg]` guards: `arg_u64` 7th arg from `rsp+8`
  (`crates/ebpf/src/main.rs:317-324`), LP64 struct offsets (`151,173,238`), glibc x86-64
  paths (`oracle.rs:16-18`); a non-x86 build compiles and misbehaves. AArch64 is "first
  post-v1 item" — add a compile-time refusal now.
- Only two decodable param shapes (`shapes.rs:25-31`), no registry config path
  (`MechanismRegistry::load(None)` at `attach.rs:532`, `main.rs:270`) — vendor mechanisms
  cannot be approved at runtime despite `shapes.rs:1-6` claiming config handles them.
- Hard limits without knobs: `MAX_SLOTS 512`, `START_ENTRIES 16 384`, `RV_ENTRIES 4 096`
  (512 slots × 8 RVs saturates), `MAX_MECH_SHAPES 1 024`, `PID_FILTER 1 024` (but exactly
  one pid is ever inserted), `CGROUP_FILTER 1`, `MAX_ATTRS 8`, `MAX_TRACKED 16 384`,
  `RING_BYTES 256 KiB`.
- `--pid` does not follow forks: fork tracepoint only for cgroup scope (`attach.rs:595`),
  `PID_FILTER` frozen with one entry (`scope.rs:110`) — a forking daemon under `--pid`
  is silently partial (the design chose cgroup for that; the CLI does not warn).
- Event ABI has no version/magic; host trusts `len == size_of::<Event>()`
  (`events.rs:16`) — fine while the object is embedded, fragile the day it is pinned or
  shipped separately.

### 2.7 Test and process architecture

- **342 Rust tests, all unprivileged; zero load BPF.** Live/BPF behaviour is covered only
  by 15 sudo-only shell gates (docker/kind/kn/pkcs11-check for the matrix) that nothing
  chains except `build-release.sh` (partially). No CI, no Makefile/justfile/xtask, no
  prerequisite list (gcc, python3, llvm tools, softhsm2, sudo). README/usage contain no
  build instructions.
- **`tests/release_contracts.rs` (1 785 l) is mostly a text-grepping linter.** ~30 of 45
  tests assert on the *source text* of scripts, Rust files or docs
  (`release_contracts.rs:1702-1762` requires `crates/ebpf/src/main.rs` to contain
  `"count.min(u32::MAX as u64) as u32"` and ≥7 `checked_add(`; `:141-176` requires scripts
  to contain `create_trusted_exec_dir`; `:1774-1785` requires `discover.rs` to contain
  `"permissions[2] != b'x'"`). Others slice C/shell out of heredocs and execute it
  (`:1170-1203`, `:679-742`). Rename, reformat or refactor → red; real regression that keeps
  the substring → green. The doc-pin test checks README for stale `v1.3` but not
  `usage.md`, which is stale.
- A **939-line Python program lives inside a shell heredoc** (`scripts/verify-canaries.sh:19-958`),
  plus 121 lines of C in `verify-induced-gaps.sh:254-375` and 131 lines of Python in
  `matrix/verify-oracle.sh` — not lintable, importable or unit-testable.
- SoftHSM token bootstrap copy-pasted 6×; three near-identical `matrix/Dockerfile*`;
  unpinned `cargo build` (no `+1.88 --locked`) in `bench-overhead.sh:50`,
  `matrix/verify-oracle.sh:85`, `matrix/verify-fork-scope.sh:68`.
- Gate evidence the ROADMAP cites (`.superpowers/sdd/...task-7-report.md`) is git-ignored
  (`.superpowers/sdd/.gitignore` = `*`): the repo's own claims point at files not in the repo.

### 2.8 Documentation architecture

There is no single authoritative spec. `AGENTS.md → ROADMAP.md → design spec (2026-08-10)`
which declares itself superseded by the safe-metadata design + provenance plan; the
corrective design (971 l) is amended by the safe-metadata design; both "current" specs
still read `Status: … implementation pending`. Completed-phase plans keep 22–62 unchecked
`- [ ]` boxes each. A reader must merge ROADMAP + 2 specs + 1 plan + the schema doc to know
the contract. Public docs contradict each other on shipped state:

| Topic | Says A | Says B |
| --- | --- | --- |
| Schema id | `usage.md:461` "current: v1.3" | README:135, schema:5, `render.rs:782` v1.4 |
| Terminal verdict | `usage.md:195,207` real output "→ COMPLETE" | `usage.md:391`, CHANGELOG:52 "always PARTIAL" |
| Provenance/lease status | `usage.md:171-184` "not a release proof… must be rerun after that implementation" | README:157-171, CHANGELOG:37-47 implemented and rerun |
| Safe policy status | `allowlist-v1.md:93-108,120-124` "until the safe policy is implemented… still open work" | CHANGELOG:14-24 implemented, maps frozen |
| Release status | CHANGELOG:77 "v0.1.0 — First release… artifacts built and verified" | README:13 unreleased, `git tag` empty |
| `CAP_LEASE` | README/usage add it (inherited, not measured) | CHANGELOG "Unreleased" never records it |
| Attach-failure example | `usage.md:289` "0/136 attach attempts failed" | `main.rs:231-238` prints `failures/total` — cannot be 0 there |

`docs/notes/info.md` (578 l) is a first-person LLM transcript kept as "extended
rationale"; `docs/notes/naming.md` is an empty tracked file.

---

## 3. Spec / intent gap analysis

### 3.1 Promised in the specs, not in the tree

| Promise | Where promised | State |
| --- | --- | --- |
| `--cmd 'myapp …'` launch-and-observe | outputs spec:23, design spec "v1 scope" | absent (`grep -- --cmd src` → nothing) |
| `p11scope discover --pid N` (discover in that process's mount view) | outputs spec:20 | absent; helper has no `--pid`; container path is `docker cp` + `attach-pod.sh` |
| Multiple `--module`/manifests per process (NSS + vendor, p11-kit fan-out); "schema and state machine multi-module from day one" | design spec "Known topologies" | single `--manifest`; state key has no module dimension |
| p11-kit-proxy detection/warning | design spec | removed as false claim; still nothing (`rg p11-kit src crates` → 0) |
| Non-`overlay2` storage driver "detected and reported rather than assumed" | design spec | no detection (`grep overlay src` → comments only) |
| Trace: caller stack ID / instruction pointer | design spec capture-mode table, info.md | absent |
| Trace: `key=K3` object-handle pseudonyms; `[CKA_VALUE]` on `C_GetAttributeValue` lines | outputs spec:63-69 | `Event` has no object-handle field; attribute types aggregate only |
| Live view `Mechanisms:` / `Errors: … (last …)` / `Sessions:` lines | outputs spec:48-50 | `render::live` prints function table + evidence only |
| `attributes.requested_types` / `sensitive_denied`; `templates[].mechanism/calls`; `concurrency.sign_ops_peak` | outputs spec:103-111 | absent (`TemplateStat` has neither; `active_ops.len()` never surfaced) |
| Per-mechanism latency that answers "is the provider slow?" | outputs spec:133-135 | histogram mixes `*Init` and op calls |
| Trace "explicit sampling and rate limits" | info.md, design spec | none; no `--sample`, no filter |
| G2 acceptance: RSA-PSS/GCM param combos + requested attributes for `pkcs11-lab` joins | design spec "Profile schema requirements" | **only in the `unsafe-unvalidated-metadata` build**; default artifact emits `params: null`, `templates: []` |
| Kernel-version runtime check | usage.md:255 says "does not runtime-check" | true; hint text only |
| Names in JSON (`CKU_USER`, `CKM_*`) | outputs spec:95-100 | numeric ids only; trace names 2 mechanisms (`trace.rs:47-55`) |

### 3.2 Simple use cases that are missing (ranked by operator value ÷ effort)

1. **`p11scope run -- <cmd> [args]`** (the spec's `--cmd`): create a transient cgroup
   (or use `--pid` on a stopped child: `fork`, `SIGSTOP`, attach, `SIGCONT`), attach *before*
   the first call, exit with the child's status, write the report. Today a short-lived CLI
   (`pkcs11-tool`, `openssl` with the pkcs11 provider, a batch signer) cannot be observed
   at all: by the time you have a PID it is gone. ~150 lines.
2. **`p11scope doctor` / preflight** (see §4): report kernel, BTF, lockdown,
   `perf_event_paranoid`, effective caps, lease-ability of a given file, `/proc/<pid>/root`
   reachability, helper install state → "modes available on this host". Every eBPF tool
   ships one; here it is more important because the failure modes are so many.
3. **`p11scope inspect --pid N`**: list executable mappings that export
   `C_GetFunctionList`/`C_GetInterfaceList` (read `/proc/N/maps`, `object` crate on each
   file) → "this process uses `/usr/lib/…/libsofthsm2.so` and `p11-kit-proxy.so`". Answers
   the first operator question; also gives the p11-kit warning for free. Unprivileged for
   same-uid, `CAP_SYS_PTRACE` otherwise. ~100 lines on top of `manifest::maps`.
4. **`SIGTERM` = clean stop.** Register the same flag for `SIGTERM` (`main.rs:54`); today
   `systemd stop`, `timeout`, `kubectl delete` lose the report.
5. **Trace filters and machine format:** `--function C_Sign,C_SignInit`, `--only-errors`,
   `--session N`, `--min-duration 1ms`, `--format jsonl`. A busy app's trace is unusable
   without them and unparseable without JSONL. Kernel-side function filter also cuts ring
   pressure.
6. **Periodic snapshots / checkpoints:** `--snapshot-every 60s` writes the current
   profile (atomically) so a 1-hour capture that dies at minute 59 still yields data, and
   so operators get a time series (calls/s per interval, error bursts). Today the JSON is
   published only on normal completion.
7. **Knobs for the ceilings:** `--ring-size 8M`, `--max-inflight`, `--max-sessions`;
   default ring 256 KiB is tiny for a tracer (8–64 MiB is normal), and today the operator's
   only signal is `event_loss` after the fact.
8. **`--duration 30s|15m|1h`** — the spec's own examples use suffixes; the CLI takes bare
   seconds.
9. **Profile post-processing:** `p11scope report show|diff|merge` — merge N pod captures
   into one profile, diff before/after migration, pretty-print. `pkcs11-lab` assesses; it
   does not need to also be the only reader.
10. **First-class container path:** `p11scope discover --pid <hostpid> --module <path>`
    running the helper via `setns` into the target's mount/pid ns as an unprivileged uid
    (the observer already holds `CAP_SYS_ADMIN`), then attaching to the inode opened via
    `/proc/<pid>/root`. Removes `docker cp`, path rewriting, and the "byte-identical safe copy
    of the provider directory" requirement that `attach-pod.sh` exists to satisfy.
11. **Ctrl-C during authorization**: SIGINT/SIGTERM are blocked from `CaptureSignals::block`
    through the whole `load_plan` (up to 8×30 s helper passes) and the helper is in its own
    pgrp — the operator cannot abort; the pending SIGINT later yields an empty exit-0 report.
12. **`--pid` warning when the target forks** (or a `--follow-forks` that switches to the
    child's cgroup) — today silently partial.
13. **Prometheus/OpenMetrics text output for `--mode metrics`** — a mode named "metrics"
    designed for "long captures" has no scrapeable output.
14. **AArch64** — the roadmap's first post-v1 item; today the code compiles for it and
    misreads the 7th argument.

### 3.3 Deeper gaps for this class of tool

- **The default build has stopped serving migration assessment.** `allowlisted` was chosen
  to contain hostile pointer aliasing; the price is that the *only* consumer of the profile
  format (`pkcs11-lab`) receives `params: null` and empty templates from the release
  artifact. The design's own G2 table is not met by the shipped policy. Options: (a) ship
  the feature build as a second, clearly labelled artifact; (b) make the safe policy
  richer for *trusted* targets: read RSA-PSS/GCM params and template attribute *types* only
  after `CKR_OK` and only for registry-known shapes (same "provider accepted it" gate the
  mechanism id already uses) — pointer-derived scalars, no buffer bytes, contained by shape
  length equality; (c) accept the gap and say so in README ("migration params require the
  diagnostic build").
- **Rejected requests are invisible under `allowlisted`.** "The app asked for CKM_X and
  the provider said `CKR_MECHANISM_INVALID`" is precisely the migration signal; the safe
  policy attributes mechanisms only after `CKR_OK/CKR_PENDING`.
- **Throughput.** ~900 events/s (profile) before loss with default sizes; `verify-canaries`
  and the overhead note already show 99% loss at 1M calls/s. Aggregate counts survive, but
  every semantic section degrades and the verdict is PARTIAL — for the workloads (network
  HSM at a few k ops/s) the tool is aimed at. Fixes are cheap: `epoll` on the ring fd,
  8 MiB default, compact `Event` for the safe policy (drop the 128 B of template arrays
  the policy never fills), and kernel-side function filters.
- **State budget** (P9) — long captures on session-per-request workloads.
- **Operational friction is disproportionate.** To run the binary at all under `sudo` you
  must: stage both binaries as a root-owned sibling pair (`sudo ./target/release/p11scope`
  is refused: helper owner uid ≠ 0), set the *system-wide* `fs.suid_dumpable` sysctl to
  exactly `0` (`crates/discover/src/main.rs:64-79`; Ubuntu default is 2 which is equally
  safe against non-root ptrace and would avoid the toggle), have `CAP_LEASE` on every
  object in the closure including root-owned `libc.so.6` and `ld-linux`, and pass
  `--trusted-workload` for every `--cgroup` run and every non-uid-0 observer. None of this
  is on the usage page's privilege table.
- **Hardened mode is practically narrow and its refusals are silent.** It requires
  `--pid`, a *static root-owned* observer (a `cargo build` binary is dynamic → never
  eligible, `oracle.rs:305-309`), a target with `NoNewPrivs=1`, zero caps and no root uid in
  any thread (`oracle.rs:275-292,712-773` — plain shells, most systemd units, default Docker
  fail), an empty `/etc/ld.so.preload` (EDR agents break it, `1294-1315`), a Debian/Fedora
  libc layout (`16-18`), a provider readable by `nobody` (`crates/discover/src/main.rs:80-81`),
  and two *identical* full task-set snapshots (`264-266,775-782` — JVM/Go/thread-pool churn
  intermittently refuses). Under `--trusted-workload` the ineligibility reason is dropped
  (`oracle.rs:349-353,445-448`), including "target PID does not exist". The hardened parent
  never verifies the child's post-drop `Uid/Cap*/NoNewPrivs` at READY although it holds the
  dir fd and `parse_status` exists. `mapping_file_key` re-parses `/proc/self/mountinfo` on
  every call (`identity.rs:119-157`), dozens of times per revalidation — seconds per attach on
  a node with 10k mounts. Up to 8 × 30 s stabilization passes run with no progress output.
- **Verdict is vacuous** (P5) — a consumer cannot tell a clean run from a lossy one from
  `completeness` alone.
- **Docs drift** (2.8) — three-way inconsistent on shipped state.

---

## 4. Required capabilities and reduced-capability operation

### 4.1 What is required today (in run order)

| Step | Needs | Failure | Where |
| --- | --- | --- | --- |
| Manifest + object open (`/proc/<pid>/root/…` for containers) | read access; **`CAP_SYS_PTRACE`** for cross-uid `/proc/<pid>/root` | fatal | `verify.rs:2298-2306` |
| Read lease on every manifest object | file ownership **or `CAP_LEASE`**; no writer; FS supports leases | **fatal** | `verify.rs:1414-1431,2308` |
| Oracle mode | hardened only if `--pid`, observer static + root-owned + all uids 0 + init userns + target non-root/no caps/`NoNewPrivs`; else **`--trusted-workload` required** | fatal | `oracle.rs:294-355` |
| Helper | sibling `p11scope-discover`, regular, exec, not g/o-writable, **root-owned if observer has euid 0 or *any* effective cap** | fatal | `discover_cmd.rs:76-130` |
| Helper run as root | **`fs.suid_dumpable == 0` system-wide**; drops to `SUDO_UID` or 65534 | fatal | `crates/discover/src/main.rs:64-79` |
| Provenance closure lease (module + helper + `ld-linux` + `libc` + deps) | ownership or **`CAP_LEASE`** on root-owned system libs ⇒ effectively root/`CAP_LEASE` on every host | fatal / exit 78 on break | `discover_cmd.rs:200-212,268-297`, `verify.rs:1493-1507` |
| Hardened mode | `geteuid()==0`, `/run/p11scope` staging, glibc x86-64 paths | fatal | `oracle.rs:16-19,1832-1843` |
| Output dir | ancestors root/euid-owned, sticky if g/o-writable, no symlinks | fatal | `verify.rs:491-546` |
| BPF maps/programs | `CAP_BPF` (+`CAP_PERFMON`) or `CAP_SYS_ADMIN`; BTF; no lockdown | fatal, exit 1 + hint | `attach.rs:494-577` |
| `--cgroup` | open cgroup dir; fork tracepoint | fatal | `scope.rs:116-132`, `attach.rs:580-589` |
| Per-slot uprobe `perf_event_open` | `CAP_PERFMON`/`CAP_SYS_ADMIN`; Ubuntu `perf_event_paranoid=4` ⇒ `CAP_SYS_ADMIN` | **reported, continues** (`attached_probes: 0`, PARTIAL, exit 0) | `attach.rs:614-664` |
| Supervisor | `fork`, `pidfd_open` (≥5.3), `PR_SET_PDEATHSIG` | fatal | `verify.rs:825-857` |

Answer to "will it work with reduced capabilities?": **no, not below the full set.** The
only degraded path is per-slot attach failure. `--mode metrics` walks the identical
authorization path (`main.rs:336-405 → load_plan → Session::start`); it saves the ring drain
and the fork tracepoint, nothing in privileges. `--trusted-workload` relaxes only the
hardened-oracle eligibility, not leases, helper ownership, provenance or output rules.
Because the provenance closure leases root-owned `libc.so.6`/`ld-linux`/helper, a
non-root observer needs `CAP_LEASE` even when it owns the provider file. The measured
privilege table (`phase4-privileges.md`) predates all of this and `verify-fork-scope.sh:213-215`
runs its capability row without `--trusted-workload`, which `oracle.rs:322-345` now refuses
— it is stale, not merely "not rerun".

### 4.2 Proposed capability ladder (graceful degradation)

Every tier is labelled in the output (`evidence.authority`, `evidence.tier`) so a lower
tier can never be mistaken for a higher one — the same discipline already used for
`privacy_mode`.

| Tier | Privileges | What you get | What you lose (stated in evidence) |
| --- | --- | --- | --- |
| **T0 unprivileged** | none (same-uid `/proc` for `inspect`) | `discover` (manifest), `inspect --pid` (which providers a process maps, p11-kit warning), `doctor` (what tiers this host allows), `report show/diff/merge` | no live capture |
| **T1 counting** | `CAP_BPF`+`CAP_PERFMON` (or `CAP_SYS_ADMIN` where `perf_event_paranoid≥3`); read access to the provider file | `metrics` and `profile`/`trace` under `allowlisted` on `--pid`/`--cgroup`/`run`: function counts, RVs, latency, in-flight, sessions/logins/approved mechanisms. Provider identity pinned by open→fstat→SHA-256 on the inode, re-hashed at end and periodically; `authority: "hash-pinned"` | no lease continuity proof (a same-inode writer between hashes is undetectable — reported as `provider_changed` if seen at re-hash); helper trust = same-uid or root-owned, whichever applies; no fork supervisor |
| **T2 containers** | T1 + `CAP_SYS_PTRACE` (+`CAP_SYS_ADMIN` for `setns` discovery) | cross-uid `/proc/<pid>/root`, `--cgroup` on pods, in-namespace discovery | same as T1 |
| **T3 leased** | T2 + `CAP_LEASE` (or root) | today's behaviour: closure leases, lease-break teardown, exit 78; `authority: "leased"` | — |
| **T4 hardened** | root uid 0, static observer, init userns, `--pid` only | today's hardened oracle (`authority: "hardened"`) | — |

Concretely, T1 = "just understand the function calls": it needs no `CAP_LEASE`, no
root-owned helper, no sysctl, no supervisor fork, and it should be the **default** for
`--trusted-workload` runs (which every container run already is). Code touchpoints to
make leases/provenance advisory: `verify.rs:1414-1431,1433-1447,1376-1400,2308-2311`
(lease → optional, record `leased: bool`), `main.rs:173-201` + `discover_cmd.rs:200-330`
(provenance pass optional / advisory), `verify.rs:809-957` (skip fork when nothing is
leased; keep atomic publish), `render.rs`/`trace.rs` evidence (add `authority`),
`crates/discover/src/main.rs:64-79` (accept `suid_dumpable ∈ {0,2}` — 2 already denies
non-root ptrace).

### 4.3 Preflight (`p11scope doctor`) — the missing piece for "understand what is available"

One unprivileged-safe command that prints a table and exits non-zero if the requested tier
is unavailable:

```
kernel 7.0.0-28-generic (floor 5.15) ........ ok
BTF /sys/kernel/btf/vmlinux ................. ok
lockdown ..................................... none
kernel.perf_event_paranoid ................... 4   → uprobes need CAP_SYS_ADMIN on this host
effective caps ............................... CAP_BPF CAP_PERFMON            (missing: CAP_SYS_ADMIN)
BPF map create (probe) ....................... ok
uprobe perf_event_open (probe on own libc) ... EACCES → tier T1 unavailable, tier T0 only
/proc/<pid>/root reachable ................... n/a (no --pid)
F_SETLEASE on <module> ....................... EACCES (not owner, no CAP_LEASE) → tier T3 unavailable
helper /usr/local/bin/p11scope-discover ...... found, root-owned, 0755
fs.suid_dumpable ............................. 2
verdict: T0 available; T1 needs CAP_SYS_ADMIN (perf_event_paranoid=4)
```

It reuses checks that already exist (`attach.rs` hint logic, `has_effective_privilege`,
`LeaseMonitor::acquire`, `validate_helper_metadata`) — ~200 lines, no new deps.

### 4.4 Minimum set, per tier, on a stock kernel (to be measured, not asserted)

- T1: `CAP_BPF` + `CAP_PERFMON` (upstream ≥5.8) — **`CAP_SYS_ADMIN` on Ubuntu/hardened
  hosts** (`perf_event_paranoid=4`, already measured); read/`mmap` on the provider file.
- T2: + `CAP_SYS_PTRACE` (`ptrace_may_access` on `/proc/<pid>/root`); `CAP_SYS_ADMIN` if
  discovery uses `setns`.
- T3: + `CAP_LEASE` (global capability; not grantable inside a user namespace).
- T4: uid 0.

---

## 5. Recommended plan (priority order; each item independently shippable)

**Now — cheap, high value (each ≤ 1 day):**

1. `SIGTERM` → same stop flag as `SIGINT` (`main.rs:54`); unblock operator signals during
   the authorization phase or forward them to the helper pgrp.
2. Ring transport: `epoll`/`poll` on the ring fd instead of `sleep(1s)`; `RING_BYTES` 8 MiB
   default + `--ring-size`; compact `Event` for the safe policy (drop the two 64 B template
   arrays it never fills). Fix the "~2700 events" comment by computing it in a test.
3. Refund the semantic key budget on removal (`semantics.rs:1044-1058`); index
   `has_process_state`/`retire_process` with `BTreeMap::range` on the `ProcessKey` prefix.
4. Evaluate accepting `fs.suid_dumpable ∈ {0,2}` (`crates/discover/src/main.rs:64-79`):
   2 = `SUID_DUMP_ROOT` already denies non-root ptrace and `PR_SET_DUMPABLE(0)` is
   re-applied right after the transition (`main.rs:179,190`); if that holds, delete the
   system-wide sysctl toggling from 9 scripts.
5. Strip the 23 stale `dead_code` allows; log the hardened-ineligibility reason under
   `--trusted-workload`; verify child post-drop status at READY.
6. Fix the doc drift table in §2.8 (usage.md v1.3, COMPLETE examples, allowlist "still
   open", CHANGELOG "First release", CAP_LEASE); state plainly that every `--cgroup` run
   and every non-uid-0 observer needs `--trusted-workload`, and that closure leases need
   `CAP_LEASE` on root-owned libc.

**Next — the two big design corrections (1–2 weeks):**

7. **Capability ladder (§4.2) + `p11scope doctor` (§4.3).** Make lease acquisition and
   the provenance pass optional/advisory in `--trusted-workload` (default for that flag),
   record `evidence.authority`, skip the fork supervisor when nothing is leased (keep
   atomic publish). This is what makes "count function calls with `CAP_BPF+CAP_PERFMON`"
   possible and shrinks the authorization layer to an opt-in `--authorization=leased|hardened`
   lane. Then re-measure the minimum caps per tier (`verify-fork-scope.sh` is stale).
8. **Restore the migration payload for trusted targets** (§3.3 first bullet): either ship
   the diagnostic build as a labelled second artifact, or extend the safe policy with
   post-`CKR_OK` shape-length-gated RSA-PSS/GCM params and template attribute types.
   Decide explicitly; document which artifact serves `pkcs11-lab`.

**Then — structure (mechanical, low risk, ~-6k lines):**

9. Split `verify.rs` → `supervise.rs`, `output.rs`, `lease.rs`, `verify.rs`; split
   `oracle.rs`/`discover_cmd.rs` into `authority/{select,target,procfs,loader_chain,
   alias_dir}` and `discover/{leases,stabilize,pass,cli}`; one helper runner and one
   stabilization loop; shared `linux_creds`/`sys` module for capget/pidfd/socketpair/openat
   shims (both binaries already depend on `p11scope-manifest`); rename `oracle` →
   `authority`, attach "slot" → "probe".
10. Leaf `policy.rs` for `Scope`/`CapturePolicy`/`policy_map_data`; make `Session.ebpf`
    private with `Session::finish(self) -> Terminal`; delete the source-grep ordering test.
    `expect_map()`/`publish_exact_hash()` helpers; one `ENTRY_PROGRAMS` const; capacities as
    `ebpf-common` consts.
11. Evidence: `#[serde(flatten)]` the three source structs into one `Evidence`; a
    `[(name, value, gates_completeness)]` table drives `verdict()`, `live()` and the schema
    doc; add `final_drain_proven` and `gap_free` fields so `completeness` means something
    again; typed `Profile`/`MetricsProfile` structs equal to the schema (share with
    `pkcs11-lab`).
12. `main.rs`: one `CaptureArgs` parser (or `clap`/`lexopt` — one dep, -200 lines), one
    capture loop parameterised by sink, `--duration` with suffixes.
13. Tests/process: replace source-text asserts in `release_contracts.rs` with behavioural
    tests or delete; move the heredoc Python/C into `scripts/lib/*.py`, `scripts/fixtures/*.c`;
    a `justfile`/`make check|gates|matrix`; a GitHub Actions job for the unprivileged suite
    plus a self-hosted (or `act`) runner for the root gates; pin nightly by date in
    `rust-toolchain.toml` and honour it from `build.rs`; pre-flight nightly/rust-src/
    bpf-linker with an actionable message.
14. Docs: one `docs/spec.md` (current contract, ~300 lines) that the superseded specs point
    to; move `docs/notes/info.md` to `docs/history/`; delete `naming.md`; track gate reports
    (or stop citing them).

**Later — features from §3.2:** `run -- cmd`, `inspect --pid`, trace filters/JSONL,
snapshots, `report diff|merge`, in-namespace discovery, `--follow-forks`, OpenMetrics for
`metrics`, `#[cfg(target_arch)]` refusal until AArch64 lands.

---

## Appendix A — per-module notes (condensed)

| Module | Lines (prod/test) | Verdict | Top issue |
| --- | --- | --- | --- |
| `attach.rs` | 723/281 | sound, grab-bag | cycles with scope/shapes; 165-line `start_inner`; 14 dup map blocks |
| `events.rs` | 55/69 | clean | polled, not waited |
| `metrics.rs` | 137/26 | clean | reaches `session.ebpf` |
| `scope.rs` | 168/74 | ok | two concerns; `label` walks cgroupfs per id |
| `plan.rs` | 210/222 | clean leaf | `Result<(), String>` outlier |
| `kinds.rs` | 338/70 | ok table | misnamed; 250-line match |
| `shapes.rs` | 109/134 | ok | doc claims config path that doesn't exist |
| `semantics.rs` | 1 912/690 | thorough | monotonic budget; O(N²) scans; per-event clones |
| `process.rs` | 257/48 | ok | per-event syscalls; hidden `RLIMIT_NOFILE` raise |
| `trace.rs` | 279/299 | ok | JSON round-trip as enum; per-event slot scan |
| `render.rs` | 810/947 | correct, hybrid | 40-field hand-copied Evidence; `*Out` mirrors; vacuous verdict |
| `main.rs` | 1 028/308 | copy-paste orchestration | dup arg loops/capture loops; source-grep test |
| `verify.rs` | 2 409/152 | hardened, mis-named | 6 concerns; 2 lease monitors; Ctrl-C blocked in auth |
| `discover_cmd.rs` | 1 548/1 899 | hardened, tangled | 10 concerns; two runners; stale allows |
| `oracle.rs` | 1 846/1 485 | hardened, narrow | 9 concerns; glibc/x86-64 hard-coded; silent downgrade |
| `crates/discover` | 1 739 | good shape | 6 functions >80 lines; `read_exact_at` reimplemented |
| `crates/manifest` | 983 | good | `inspect_elf_loader` (300 l) belongs to the host crate |
| `crates/ebpf*` | 1 533 | careful | 560 B of structs on a 512 B stack; no ABI version; `0x204` literals |
| `build.rs` | 96 | fragile | floating nightly; no pre-flight; RUSTFLAGS leak |

---

## Addendum — productization Q&A (2026-08-15, same day)

Owner's position after the review: the MVP works; next phase is productization. Four
questions were raised; the answers are recorded here so the later plan starts from them.

### A1. Why a dlopen helper at all — can't eBPF discover the table live?

Yes. Every provider must export `C_GetFunctionList` (2.x) and, for 3.x,
`C_GetInterfaceList`/`C_GetInterface`; `strip` never removes `.dynsym`, so those three
symbols are always attachable by name in any provider file. A **uretprobe on those exports
in the target process** sees the table the application *actually* receives
(`*ppFunctionList` → `CK_VERSION` + 68/92/104 pointers; `CK_INTERFACE{pInterfaceName,
pFunctionList, flags}` for 3.x, incl. vendor interfaces recorded by name). Userspace maps
each pointer to `(inode, file offset)` with `/proc/<pid>/maps` and attaches the per-function
probes to that inode. Nothing has to leave the container: the file is opened through
`/proc/<pid>/root/<path>` (or the layer path on the host); uprobes bind to the inode either
way — this is the same property the shared-layer/Knative rows already rely on.

Why the tree does it differently: the design chose "attach before the first call" as a
hard property, and live discovery has a race — the app may call `C_Initialize` microseconds
after receiving the table, before userspace has attached. Running vendor code in an
unprivileged helper gave a table *before* the app starts, at the cost of a manifest, and the
manifest is untrusted input, which is what dragged in provenance → leases → supervisor. So
the helper is a simplification of the *race*, not a limitation of eBPF.

The race can be closed without a helper: the return probe calls `bpf_send_signal(SIGSTOP)`
(kernel ≥5.3; uprobe programs run in process context) at the instant the table is handed
back; userspace resolves pointers, attaches (probes are inode-wide, so they cover the stopped
process immediately), then `SIGCONT`. One pause of ~10–50 ms per *first* process per module;
later processes on the same inode are already covered. That is interference-by-pause, not
by modification — state it honestly in evidence (`attach: "live-stop"`).

Already-running processes that obtained the table long ago: (a) hook anyway and wait — many
apps call `C_GetFunctionList` again on re-init, p11-kit calls it per backend; (b) static
scan of the file: a static `CK_FUNCTION_LIST` initializer is a run of ≥67 `R_*_RELATIVE`
relocations in `.data.rel.ro`/`.data` preceded by the version bytes, whose addends are the
link-time addresses → file offsets, no execution needed (heuristic; validate against the
live table when it appears; report `PARTIAL` until then); (c) keep the dlopen helper as an
optional third path for providers whose tables are built at runtime.

Consequences: no manifest as authority, no `--provenance-module`, no helper ownership rules,
no `suid_dumpable`, no closure leases, no safe-copy of provider directories, and the
NSS-softokn "decoy table" problem disappears because the table comes from the observed
process itself. Different ABIs are handled uniformly (the version header gives the table
length; the interface name gives standard vs vendor). What stays: uprobes by inode+offset,
the BPF programs, the semantic state machine, the evidence model.

### A2. Minimum privileges — can it be made to work with a small set?

Yes, once discovery is live/static (A1) the floor is only what uprobes themselves need:

- `CAP_BPF` + `CAP_PERFMON` on stock kernels (`perf_event_open` for a uprobe requires
  `perfmon_capable()`); **`CAP_SYS_ADMIN` on hosts with `kernel.perf_event_paranoid ≥ 3`**
  (Ubuntu's 4 — already measured here). There is no privilege-free way to place a uprobe;
  the alternatives (LD_PRELOAD/LD_AUDIT, ptrace) are interposition or heavy and are out of
  the product's principle.
- read access to `/proc/<pid>/maps` and `/proc/<pid>/root/…`: free for same-uid targets,
  `CAP_SYS_PTRACE` for cross-uid (containers/pods). `CAP_SYS_ADMIN` only if discovery uses
  `setns`.
- nothing else: no `CAP_LEASE`, no root-owned helper, no sysctl, no `/run/p11scope`, no
  static observer binary. Leases/hardened become the opt-in T3/T4 lanes (report §4.2), and
  `p11scope doctor` tells the operator which tier the host allows before anything is loaded.
- Security settings that can still block: `perf_event_paranoid` (above), kernel lockdown in
  confidentiality mode, missing BTF for the object, `unprivileged_bpf_disabled` is
  irrelevant with `CAP_BPF`. Yama `ptrace_scope=1` does not affect `/proc/<pid>/maps` reads.

### A3. "Improve everything"

Agreed; report §5 is the seed for the productization plan (cheap fixes → the two design
corrections → structure → features). Planning is a separate step.

### A4. Why single out p11-kit?

It should not be. `p11-kit-proxy.so` (or any proxy/wrapper) is itself a PKCS#11 module with
its own function table; scoping it is legitimate and shows what the app asks of the proxy.
If the real providers are on the same machine, p11-kit `dlopen`s them into the *same*
process, so they can be scoped in the same run — and the two layers together give
proxy-vs-backend latency and error attribution, which is more useful than a warning. The
right product stance is **automatic multi-module discovery**: hook `dlopen` (glibc ≥2.34:
`libc.so.6`; older: `libdl.so.2`; musl: `libc.so`) or the loader's `_dl_debug_state`
breakpoint, diff `/proc/<pid>/maps` on each event, and for every new object exporting
`C_GetFunctionList`/`C_GetInterfaceList` attach the A1 return probes — no `--module` needed,
every layer (app → proxy → backend, JVM SunPKCS11, Go/Rust bindings) attributed under a
`(process, module, session)` key as the original design intended. The remaining
p11-kit-specific caveat is `p11-kit-remote`/`server`, where the backend runs in another
process — that process is simply another attach target.

### A5. Decision (2026-08-15) — discovery paths and trust model for productization

Clarification first: the "race" exists only for live discovery. On the current
helper/manifest path offsets come from the helper's dlopen and are independent of the target
process; uprobes are armed on the file, so a running process can be attached mid-run with no
race — calls before attach are simply outside the window (`orphan_ops` etc. are
informational). Live discovery learns the offsets from the target's own
`C_GetFunctionList`/`C_GetInterface*` call, so it needs that call to happen after the export
hook is in place; it cannot attach mid-run to a process that obtained its table earlier.

Decided:

1. **Two first-class discovery paths, one probe engine, chosen automatically.**
   - *Live* — default when the target has not loaded the module yet (`run -- cmd`,
     `--cgroup`, `--pid` with a later `dlopen`, new pods/Knative): exec/`dlopen` hooks find
     objects exporting `C_GetFunctionList`/`C_GetInterfaceList`; uretprobes on those exports
     yield the table; `bpf_send_signal(SIGSTOP)` at that return closes the attach race
     (`--no-pause` opts out; the window is then reported in evidence). No helper, nothing
     copied into containers.
   - *Offline/manifest* — `p11scope-discover` is kept as a first-class path, default for
     mid-run attach to a process that already loaded the module, and for operators who want
     a reusable manifest. Verification is what manifest v4 already carries: SHA-256 of the
     file the observer opens vs the manifest, re-hash at end → `provider_changed`. No fresh
     rediscovery, no closure leases, no root-owned helper, no `suid_dumpable`, no static
     observer required.
   - Static relocation scan: not now.
2. **Leases / hardened oracle become an explicit opt-in lane** (`--authorization=leased|hardened`),
   not the default; the supervisor fork runs only when something is leased.
3. **Output always names the lane**: `discovery: live|manifest`, `authority:
   hash-pinned|leased|hardened`, plus `privacy_mode` as today.
4. Privilege floor for the default lanes: `CAP_BPF`+`CAP_PERFMON` (or `CAP_SYS_ADMIN` where
   `perf_event_paranoid ≥ 3`) + `CAP_SYS_PTRACE` for cross-uid `/proc/<pid>` access;
   `p11scope doctor` reports which lanes the host allows.
5. Proxies (p11-kit or any other) are ordinary modules; multi-module attribution per
   `(process, module, session)` is a productization goal, not a warning.

### A6. Gap analysis of the discovery approaches (2026-08-15)

Manifest path in containers: the helper must run inside the container's filesystem view with
a matching libc (glibc/musl builds exist) — today by copying it in; better by `setns` into the
target's mount namespace and `execveat` of the right helper from a host fd — and container
paths map back through `/proc/<pid>/root`. Not native-only, but heavier. The module must be
named; `inspect --pid` answers that for a running process, image/config for a future one.

Live path in two steps: **v1** — operator names the module (as today), offsets come from the
target's own `C_GetFunctionList`/`C_GetInterface*` (no helper, no libc matching, nothing
copied); **v2** — automatic module discovery via exec/`dlopen` hooks, no `--module`.

| Capability | Manifest/helper | Live v1 (`--module`) | Live v2 (auto) |
| --- | --- | --- | --- |
| Attach before first call | ✔ no race | ✔ with pause | ✔ with pause |
| Mid-run attach, module already loaded | ✔ | ✘ until app reloads | ✘ |
| Containers/pods | helper in container's libc world + path mapping | `/proc/<pid>/{maps,root}` only | same |
| Module unknown to operator | ✘ (`inspect --pid` for running procs) | ✘ | ✔ |
| Multi-module / proxies | one manifest per module | one `--module` per module | ✔ all layers |
| Provider file replaced (new inode) | re-discover | ✔ on next `dlopen` | ✔ |
| Non-standard exports (NSS `NSC_/FC_`) | dlopen may pick the wrong table | export-name registry | same |
| Runs vendor code outside the app | yes, sandboxed | no | no |
| Result portable across machines | ✔ SHA-256/build-id | n/a | n/a |
| Privileges | BPF caps + `/proc` access | same | same |
| Kernel | ≥5.15 | + `bpf_send_signal` (≥5.3) | + `sched_process_exec` |
| Static-linked provider, 32-bit target | ✘ | ✘ | ✘ |

Missed so far, now recorded:

- **SIGSTOP is visible to job control** (interactive shell shows `Stopped`, resumes the app
  as a background job). Pause only when the target has no job-control parent (`tpgid`);
  otherwise `--no-pause` with an `attach_gap_ms` evidence field; for cgroup scope the cgroup
  v2 freezer is an invisible userspace-triggered alternative. Design it, don't assume it.
- **Manifest catalog**: manifests are SHA-256/build-id keyed, so they can be pre-generated
  per vendor package version and looked up from the mapped object's identity — mid-run
  attach with no helper on the node and no race. Falls out of manifest v4 for free.
- **Probes are on function code, not on the table** — how the app obtained the pointer
  (table, `dlsym`, wrapper) does not matter. State as a guarantee.
- **Identity = mapped inode, not path** (package upgrade during capture leaves the process on
  the old, deleted inode): hash the fd you attached, re-hash that fd.
- **Kernel floor by feature probe, not version** (RHEL 9 = 5.14 + backports); cgroup v1
  hosts lose `--cgroup`, keep `--pid`.
- **Export-name registry** for hooks (`C_GetFunctionList`, `C_GetInterfaceList`,
  `C_GetInterface`, `NSC_*`, `FC_*`, configurable).
- **Accepted residual risk** with leases opt-in: in-place rewrite of a mapped provider after
  hashing → misattributed statistics, surfaced by periodic re-hash as `provider_changed`.
  Document as accepted for the default lanes.
- **Still open**: params/templates under the safe policy (§3.3) — unchanged by this choice.
- Later: daemon mode with pinned links; event sampling for high-rate workloads.
