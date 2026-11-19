<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Admission refactor: four single owners for identity, pass budget, retry/lifecycle, binding

Status: design (spark lane, phase 1). Base: dev `c2a180a71`.
Branch: `task/v072-admission-refactor`.

Owner rule (2026-11-19, binding): a bug that can only be fixed
properly by refactoring/modularization is refactored NOW as the fix
— target v0.7.2 if green by the Friday cut, else v0.7.3. Not deferred
to 0.8.0, not patched path by path. This design is written under that
rule: it supersedes the Opus tier-3 recommendation to defer the
structural work to 0.8.0
(`tmp/muse-jobs/opus-rv-wip-admission-family.review.md`), while taking
that review's root-cause analysis, file:line evidence, overlap table
and four-owner split as the design's factual input — together with the
four lane branches as idea/test inputs (not patches):

- `task/v072-flood-admission` (the v0.7.1 counting-stop regression),
- `task/v072-inventory-admission-race`,
- `task/v072-admission-scale` bug 2 (bug 1 ships separately),
- `task/v072-runtree-nowitness` residual.

Parallel inputs (read when they land; never edit their branches):
`task/v072-flood-bisect` (names the regressing commit) and
`task/v072-admission-scale-bug1` (the small bug-1 fix).

## 1. The one structural rule

All four lanes patch one rule. When one process's library cannot be
proven — the process died, a time/work budget ran out, the kernel
identity check was inconclusive — the file is marked suspect for EVERY
process for the whole capture: `reject_observation` inserts the raw
maps key into the key-global, capture-lifetime `rejected_keys` set
(`src/discovery/identity.rs:1422`, `:3618` `reject_key`, `:3660`
`reject_observation`, enforced at `insert_entry_with_aliases` `:3384`,
replayed across sets at `absorb` `:1806-1808`), the merge filter drops
the key, views retire, probes detach, coverage drops and counting
stops. The same rule is also the only guard against binding through
another process's pin: `id_for_scanned` (`:3250`) resolves through the
aggregate `raw_to_id` map, whose `RawObjectInstance` omits the view
id, so dropping the key-global rejection without per-view proof lets a
view whose own pin was refused bind through a peer's identical raw
(codex fix3 F1). Retry/terminal meaning travels as free text re-parsed
by substring at each consumer (`engine.rs:8521`
`scan_pins_waited_only_for_reserve`, `:8560` `..._for_budget`,
`scan.rs:6123` `names_capture_budget_stop`), and each consumer
recognises only the old handle-budget wait subtype — so every lane's
per-path relaxation reopens the fence on the next path, exactly the
pattern every codex round followed.

The fix order is therefore: (i) per-view proof owned at one resolver,
(ii) a typed pin outcome, (iii) only then stop key-global rejection
for unproven observations and transient waits. Key-global rejection
survives for exactly one fact: a PROVEN collision (two different files
under one raw maps key — real on btrfs, where maps shows the
superblock device and inode numbers are per-subvolume).

## 2. Four owners, one seam each

Each owner is a module with exactly one public seam. All entry points
(§7) funnel through the owning seam; the invariant is enforced there
once, and per-path guards at call sites are deleted, not duplicated.

| # | Owner | Module | One public seam |
|---|-------|--------|-----------------|
| 1 | Identity | `src/discovery/identity.rs` (+ `identity_outcome.rs`) | `PinOutcome` + `id_for_scanned` with per-view proof |
| 2 | Pass budget | `src/discovery/scan_pass.rs` (new) | `ScanPassOwner::charge/renew/resume` |
| 3 | Retry/lifecycle | `src/discovery/retry.rs` (new) | `RefreshQueue` + `RetirementProof` gate |
| 4 | Caller binding/admission | `src/discovery/native_binding.rs` + coordinator seams | `bind_with_proof` per publication route |

Sequencing: owner 1 first (everything else keys off the typed
outcome), then owner 2 (the retry owner needs the pass cursor), then
owner 3, then owner 4. Each owner lands as: move code into the owner,
enforce the invariant there once, table-driven test over every entry
point (RED first on `c2a180a71` where the behaviour is a bug), full
lib green, then commit. Ideas and test shapes come from the four lane
branches; their per-path patches do not get ported (§8 lists the dead
ones).

## 3. Owner 1 — identity: typed outcome + per-view proof

### 3.1 The seam

```rust
/// One pin attempt's authoritative outcome. Produced only by the
/// identity owner (`pin_scanned_object` and the manifest/pre-arm
/// constructors); consumed by every binder, queue and gap renderer.
pub(crate) enum PinOutcome {
    /// The view proved this file. Carries the view-owned proof the
    /// binder consumes (raw + entry id). Physical sharing is fine:
    /// two views proving the same raw each own the same tuple.
    Proven { raw: RawObjectInstance, id: PinnedObjectId },
    /// Nothing was proven about the file for this view (death,
    /// unreadable identity, inconclusive probe). Per-view missing
    /// evidence: files a named skip, never a key rejection.
    Unproven { cause: UnprovenCause },
    /// Retryable stop with a named retry owner. Files a named
    /// in-progress gap and parks the exact work on that owner's
    /// queue (§5). Never a key rejection.
    Wait { cause: WaitCause, retry: RetryOwner },
    /// The view died mid-pin. Missing evidence, not a suspicious
    /// file (lane-4 `Gone` idea, typed). Files a named skip.
    Gone { evidence: ExitEvidence },
    /// Two different files proven under one raw key. The ONLY
    /// outcome that inserts `rejected_keys`. Carries the collision
    /// proof so absorb can replay it unconditionally (§3.4).
    Collision { key: ObjectKey, proof: CollisionProof },
}
```

`UnprovenCause`, `WaitCause`, `RetryOwner`, `ExitEvidence` and
`CollisionProof` are closed enums, not strings. Today's `PinFailure`
(`identity.rs:9816`: `Refused(String)` vs handle-only `Wait`) becomes
this five-way outcome; every `From<String>`/`From<&str>` catch-all
that silently maps unknown failures to refusal is deleted — each
failure site names its cause or the code does not compile.

### 3.2 Per-view proof at one resolver

`id_for_scanned` (`identity.rs:3250`) is the single enforcement
point: it resolves a scanned raw only when the module's own view owns
that raw in `raw_ownership`, else returns `None` with the existing
named proof skip. All production resolvers funnel through it:

- `bind_scanned_modules` / `bind_scanned_modules_strict` (already do),
- manifest fallback matching (`scanned_replacement`, `scan_view`,
  `retarget_to_pins`, `scanned_targets_without`),
- `alias_scanned_module_under` (hearsay ownership for
  `RUN_LEARNED_VIEW_ID` becomes a named, twin-covered exception or is
  re-proved — no silent aggregate write),
- `scanned_rebind::resolve_normalized` (staged; if it goes live it
  goes through the same gate).

Ownership stops being a side table written in ~10 places and becomes
a value the pin produces (`Proven`) and the binder consumes. Fixture
ownership follows production: fixtures that insert entries without
`raw_ownership` are updated to record what production records (the
fix6 B1b question is settled by the owner rule — the refactor IS the
fix, so fixtures move with the invariant; no fixture edit changes an
assertion's meaning, only its staging).

### 3.3 What changes behaviourally

- Death, budget stops and inconclusive identity file named skips for
  the affected view and never reject the key. Proven peers keep
  counting; the refused view's modules bind nothing through the peer
  (§3.2 fence).
- Proven collisions still reject the key globally, with the ambiguity
  row exactly as today. `insert_entry_with_aliases` keeps its
  `rejected_keys` check; `reject_observation` is deleted and its two
  call sites (`record_scanned_candidate`, `absorb`) route through the
  typed outcome instead.
- The pre-copy-up carve-outs (`has_pre_copy_up_for_key`, the absorb
  plain-pin guards) collapse into the outcome: a proven pre is
  `Proven`; an unproven sibling is `Unproven` and cannot nuke it.

### 3.4 Absorb

`absorb` replays `Collision` evidence unconditionally (with the same
entry-removing routing refusal as a cross-partition collision) and
propagates the marker; `Unproven`/`Wait`/`Gone` evidence never
creates or replays a key rejection; `Proven` entries merge by the
existing physical-identity predicate. This closes L1-1 (the
lane-introduced `absorbing_carried_rejection_spares_the_proven_pre`
failure), L1-2/lane-2 F4 (collision suppression by the kept-pin
guard) and fix3 F1 (fresh key rejection dropped, then merge binds
through the peer) in one place.

## 4. Owner 2 — per-pass budget: one ScanPassOwner, resume cursor

### 4.1 The seam

```rust
/// The single owner of per-pass work and I/O budgets and of the
/// resume cursor for every scope and mode. All scanning — Detailed
/// (legacy + I/O), Inventory windows, the cgroup inventory scan,
/// whole-file hashing — charges here and retries through here.
impl ScanPassOwner {
    pub(crate) fn charge_work(&mut self, units: u64) -> ChargeOutcome;
    pub(crate) fn charge_io(&mut self, bytes: u64) -> ChargeOutcome;
    /// End of pass: renew per-pass allowances, keep the cursor.
    pub(crate) fn end_pass(&mut self) -> Renewed;
    /// Resume cursor: what the next pass continues (pid/member
    /// position, hash offset for whole-file reads, owed re-sight
    /// rows). Never restarts finished work from zero.
    pub(crate) fn cursor(&self) -> &ResumeCursor;
}
```

Owner rule (binding): per-pass bound, resume next pass, never a
constant raise. One budget owner for all scopes — Detailed I/O's
capture-lifetime cumulative `attempted_io_bytes` (`scan.rs:1209`,
`:1905`) becomes a per-pass allowance with a resume cursor, ending
L1-5 (I/O ceiling as capture-lifetime terminal stop). Whole-file
hashing carries its offset across passes (closes L3-2 starvation and
codex runtree F1: a file larger than one window resumes, never
restarts at offset 0 forever). Inventory windows and the cgroup
inventory scan charge the same owner instead of their own ad-hoc
windows. While work is in progress across passes, the owner files one
named in-progress gap (deduped, finite vocabulary — the fix4 B4
renderer projection for the work ceiling is the template; no new
captured values, no schema widening beyond the closed reason enum).

### 4.2 Cursor, not tiering

Lane-3 bug-1's fresh-first tiering (`order_scan_pids_fresh_first`,
`truncated_member_pids`) is the 0.7.x approximation; under this owner
it becomes a cursor: never-attempted members first, then cut-short
retries from their cursor position, then examined. The bug-1 lane's
RED twins (ordering + cut-short freshness) are adopted as the cursor
contract. The perpetual-cut-short starvation case (L3-2) is closed by
cursor rotation, with its own twin.

## 5. Owner 3 — retry/lifecycle: one queue, one retirement gate

### 5.1 The seam

```rust
/// Bounded refresh queue with defer-not-drop overflow and a bounded
/// per-pass relief scan. Overflow defers (re-queues behind the
/// cursor), never drops with `mark_live_loss`.
pub(crate) struct RefreshQueue; // MAX_PENDING_REFRESH stays 256
```

```rust
/// The only way to retire a view. Retryable outcomes are
/// unrepresentable as proof: the type system, not a substring,
/// keeps a `Wait` out of retirement.
pub(crate) enum RetirementProof { Exited, OperatorRemoval, IdentityChanged }
pub(crate) fn retire_view_only_if_proven_gone(view: ProcessViewId, proof: RetirementProof);
```

### 5.2 Contents

- Refresh queue: `request_refresh` serial semantics fixed once —
  consumed re-queues renew (fresh serial + renewal stamp, so
  completion drops exactly the snapshot set) while retry
  re-queues stay idempotent signals (the exec re-arm protocol
  pins prepared serials — retries must not churn them); a
  matched exit reclaims only ownerless entries whose every stamp
  predates it (lane-2 `renewed_ns` fix a8f9cc27b, adopted in the
  fixed form); overflow defers with an unfinished row instead of
  dropping as loss (the pass cursor retries the member).
  `refresh_requested` moves into `RefreshQueue`; the fair-queue
  relief scan is bounded per pass (L1-6: one 256-examination
  sweep per pass, never per arrival; caps stay 256 so #136/#137
  stay green).
- Loader-slot reuse: slots recycle past 256 with a post-reuse
  stale-record proof at the ordinary hit boundary (lane-2 F5 / codex
  fix1 F6 — the terminal-state gate + drain barrier + kernel invalid
  flag, qualified by a real-seam test, or the narrower
  retirement/drain proof with its ruling). The 257th-arm stale
  refusal is demonstrated, not staged in the token adapter.
- Retirement: all 13 `remove_view` / `replace_view_pins` /
  `prune_view_pins_to_modules` engine call sites route through the
  proof gate. `RescanFailed` is NOT proof (only the three closed
  constructors are); a failed rescan keeps the committed pins and a
  named gap. This settles fix6 B2a conservatively: leak-then-prove
  beats retire-then-lose.

## 6. Owner 4 — caller binding/admission

### 6.1 The seam

Pre-admission row binding, seed base, re-sight scheduling, setup
classification on every publication route, epoch fences — one owner
for the rule "which program called my token", covering lane 2, lane-3
bug 2 and the lane-4 vng whole-wave residual. Public seam: the binder
admits a row only with proof current at bind time:

- read-time and late sightings are separate representations; an
  unstamped late answer is insufficient authority (lane-2 fix4 F1
  design, adopted);
- re-sight is an owed-work queue with a bounded per-pass allowance
  and explicit incomplete outcome, driven through stage/stop
  (lane-2 fix4 F2 design, adopted);
- setup classification is computed from the attach-set resolution on
  ALL THREE publication routes (pre-arm, ordinary lowering, prepared
  cgroup commit — lane-2 fix4 F3 design, adopted); the seed base
  ("the first call is the uncounted seed") is proven by setup-endpoint
  evidence, never by timing alone;
- epoch/fence recovery under churn uses the same-carrier resume with
  anchor-split staging (lane-3 bug-2 design, adopted) WITHOUT the
  fail-open generation waiver (L3-1: `None` generation means unknown
  and fails closed);
- the lane-4 vng residual (workers live ~16 ms vs ~550 ms admission)
  is addressed by admission-before-witness ordering plus the owed
  re-sight queue — no BPF membership-cache architecture in this
  design; if the 50/50 vng cell still misses whole waves after
  owners 1–4, that remainder goes back to the owner as an
  architecture-vs-ruling decision, not another per-path patch.

## 7. Entry-point → owner map

Every entry point funnels through its owner's seam. The table names
the current code location on `c2a180a71` and the owning seam after the
refactor.

### Identity (owner 1)

| Entry point | Today | After |
|---|---|---|
| Scan pin file path | `record_scanned_candidate` `identity.rs:9887` | produces `PinOutcome` |
| Manifest / pre-arm pins | `identity.rs` manifest constructors | produce `PinOutcome` |
| Fresh-set absorb | `absorb` `:1773`, `fresh_pins_reprove` `:1854` | replays `Collision` only |
| Live candidate bind | `bind_scanned_modules*` `:10053/:10072` | via proof-checked `id_for_scanned` |
| Startup rebuild | `engine.rs` `rebuild_discovered` | modules pre-proven, bind via seam |
| Snapshot | `scan_reconciled_snapshot` | same |
| Loader union / replacement merges | `engine.rs` loader paths | fresh facts limited to fresh proofs |
| Loader export attachment | `candidate_timing_keys`, `collect_dynamic_export_work` | derived from proof-qualified list |
| Live publication apply | `engine.rs` publication paths | proof-checked before shared apply |
| Manifest fallback matching | `scanned_replacement`, `scan_view`, `retarget_to_pins` | via proof-checked `id_for_scanned` |
| Run-learned aliasing | `alias_scanned_module_under` | named exception or re-proof |

### Pass budget (owner 2)

| Entry point | Today | After |
|---|---|---|
| Detailed work charging | `scan.rs` work budget, sticky stop | `ScanPassOwner::charge_work` + `end_pass` renewal |
| Detailed I/O charging | capture-lifetime `attempted_io_bytes` | per-pass allowance + cursor |
| Maps snapshot / mountinfo reads | `read_maps_with_limits`, `read_mountinfo_with` | charge through owner |
| Whole-file hashing | restart-at-0 `crates/manifest/src/identity.rs:283` | offset cursor across passes |
| Inventory windows | own window API | charge through owner |
| Cgroup inventory scan | shared control hook | charge through owner |
| Newcomer scan order | `select_fresh_first_candidates` `engine.rs:9032` | cursor tiers (never/cut-short/examined) |
| Cut-short freshness | `note_applied_scan_tasks` coord `:11040` | cursor, not freshness set |

### Retry/lifecycle (owner 3)

| Entry point | Today | After |
|---|---|---|
| Refresh requests | `request_refresh`, `refresh_requested`, serials | `RefreshQueue` (defer-not-drop) |
| Tick completion | `complete_refresh_requests` | consumes deferred set from one place |
| Retained refresh (both phases) | per-path wait fences | typed `Wait` defers, `Proven` replaces |
| Loader fallback / RT_ADD / RT_CONSISTENT | per-path stamp restore | `with_renewable_restore` helper |
| Due loader scans | `service_pending_loader_scans` | restore-on-`Wait`, settle on terminal |
| Survivor acquisition | `scan.rs` cold-survivor path | `Wait` propagates as incomplete, not `Err` |
| Retirement (all 13 sites) | `remove_view` etc. + `pending_retirements` | `retire_view_only_if_proven_gone` gate |
| Loader slot table | 256, fail-closed exhausted gap | recycling + post-reuse stale proof |

### Binding/admission (owner 4)

| Entry point | Today | After |
|---|---|---|
| Native witness bind | `native_binding.rs` Rule 3 | late-bind iff provably clean window |
| Re-sight | full-queue walks | owed-work queue, bounded, explicit incomplete |
| Seed base | timing-gated base 1 | setup-evidence base |
| Setup classification | pre-arm + ordinary routes only | all three routes incl. prepared cgroup |
| Epoch/fence recovery | stock wait-forever | same-carrier resume + anchor split |
| Stop-stage continuation | discards incomplete | drives owed work to resolve-or-account |

## 8. Dead per-path patches (NOT ported)

These lane-branch patches encode the old shape and die with it; their
test ideas live on in the owners' tables (§9).

- Lane-1 `has_kept_pin_for_key` / lane-2 `has_kept_plain_pin_for_key`
  absorb guards → replaced by `Collision`-only replay (§3.4).
- Lane-1 fix4/fix5 `proved_modules_for_view` pre-filters (6 sites) →
  replaced by proof-checked `id_for_scanned` (§3.2).
- Lane-1 `per-site refused_or_wait` + `probe` parameter threading →
  replaced by `PinOutcome` production (§3.1).
- Lane-1 queue raises 256→4096 (`scheduler.rs`) → dead; caps stay,
  overflow defers (§5.2).
- Lane-1 fix6/fix7 refresh serial + deferred-pid per-path wiring →
  replaced by `RefreshQueue` (§5.2).
- Lane-4 `pin_scanned_object_inner` wrapper + substring budget
  classifier → replaced by `PinOutcome` + `ScanPassOwner` (§3.1, §4).
- Lane-4 `IO_CEILING as Wait` vs lane-1 `IO_CEILING as terminal` →
  both dead; the pass owner classifies per-pass-renewable vs terminal
  (§4.1).
- Lane-2 `AbsorbOutcome::slot_matches` + `note_setup_endpoints(plan,
  absorbed)` two-route form → replaced by three-route classification
  (§6).
- Lane-2 `proven_collision_keys` marker set → replaced by
  `CollisionProof` carried in the outcome (§3.1, §3.4).
- Lane-3 `scan_generation_matches_caller` fail-open waiver + stale-held
  waiver → dead; unknown fails closed (§6).
- Lane-3 `order_scan_pids_fresh_first` + `truncated_member_pids`
  tiering → becomes the cursor (§4.2; twins adopted).
- All `debug:` / `P11SCOPE_FIX1_EVLOG` commits on lane 4 → never ported.
- Substring classifiers (`names_transient_pin_failure`,
  `scan_pins_waited_only_*`, `names_capture_budget_stop` as
  retry/terminal deciders) → dead as deciders; the typed outcome
  decides. (String matching may survive inside gap rendering only.)

## 9. Test plan (per owner, RED first on c2a180a71)

Each owner ships ONE table-driven test over its entry points × fault
classes, with N/A cells marked explicitly (fix6 B3: no vacuous
cells). Each cell that names a bug is RED on `c2a180a71` first, then
green. Full lib green before each owner commits.

- Owner 1 table: entry points (scan pin, manifest pin, absorb,
  live bind, startup, snapshot, loader union, loader replacement,
  loader export, live publication, fallback matching) × faults
  (foreign pin proof, death mid-pin, budget stop, inconclusive
  probe, proven collision). Proven-collision cells stay rejected
  (no behaviour change); death/budget/inconclusive cells flip from
  key-rejected to named-skip + peer-kept; foreign-proof cells bind
  nothing through the peer on EVERY consumer (closes codex fix3 F1,
  fix4 B1, fix5 F2/F3 as instances).
- Owner 2 table: scopes (Detailed legacy, Detailed I/O, Inventory,
  cgroup inventory, whole-file hash) × stops (work ceiling, I/O
  ceiling, collection stop, zero cap). A tripped nonzero work
  ceiling renews next pass with a fresh allowance, a counted
  exhaustion and cursor resume; clean passes accumulate spend;
  collection stop and zero cap never admit; deadlines clear at
  their own batch end; Detailed I/O renews silently per pass
  with hash-offset resume (L1-5 ends). No constant moves
  (ruling 11:38, no capture-lifetime sticky work ceiling).
- Owner 3 table: queues (refresh, loader fallback, RT_ADD,
  RT_CONSISTENT, survivor acquisition) × outcomes (`Wait`, `Gone`,
  genuine failure, exit proof). `Wait` never retires, never drops;
  retirement needs a closed proof; slot reuse refuses stale records.
- Owner 4 table: publication routes (pre-arm, ordinary, prepared
  cgroup) × row timings (setup-first, ordinary-first, pre-admission
  clean window, pre-admission exec). Exact counts per route; no
  wrong-attribution (successor never credited with the old
  process's calls).

Adopted twins (re-cut onto the new seams, assertions intact):
lane-1 fix7 invariant twins, lane-2 fix4 F1–F4 twins (incl.
`absorbing_a_fresh_internal_collision_rejects_despite_a_retained_plain_pin`),
lane-3 bug-1 ordering + cut-short twins, lane-4 `Gone` twins
(strengthened: assert `Gone`, not merely "not Refused").

## 10. Acceptance mapping

- Flood cell exact (v0.7.1 fails, this passes): owners 1+2+3.
- Regress (a) 1 GiB profile, (b) newcomer flood, (d) ext4 two-view
  at fixed ≥800 children: owners 1+2+3; (c) inventory stream:
  owner 4. Counting never stops, no unnamed loss.
- Pressure #136/#137: owner 3 (caps stay 256, overflow defers).
- Admission 500/1000 newcomers: owners 2+4 (cursor + owed re-sight).
- Run-tree waves ×50 on vng 6.12: owners 1+3, remainder per §6.
- Inventory `--cgroup` finds a large provider (haskoki cell):
  owners 1+4 (strict bind + three-route classification).
- Full privileged campaign on fedora: all owners.
- 20-minute soak recording `attempted_io_bytes`: owner 2 headroom
  proof (L1-5 disclosure until the per-pass I/O owner lands).

## 11. Constraints

- v0.7.x behaviour/wire/JSON/privacy unchanged except the fixed
  bugs. `docs/privacy/allowlist-v1.md` byte-identical (verified per
  commit). No new captured fields, payloads, keys, PINs or raw
  provider data. No BPF/wire/ABI changes. Schema changes, if any,
  are confined to the closed gap-reason enum with producer, docs
  and checker together (fix4 B4 template).
- Missing observations stay unknown; refusals, loss, incomplete
  inventory and PARTIAL coverage reported honestly. No fail-open
  authority change without an explicit owner ruling.
- Commits by Denis Mingulov <denis@mingulov.com>, `<area>:`
  subjects, no trailers, no amend, no rebase. Cargo via
  `muse/bin/p11-lock`. `TMPDIR` private 0700, `umask 022`,
  `CARGO_BUILD_JOBS=2`.

## 12. Open questions (settled by brief or owner rule; recorded here)

- Q1 (fix6 B1b, fixtures): fixtures move with the invariant —
  settled by the owner rule (the refactor IS the fix). Assertion
  meanings unchanged; staging only.
- Q2 (fix6 B2a, `RescanFailed` as proof): NO — only `Exited`,
  `OperatorRemoval`, `IdentityChanged` retire. Conservative,
  fail-closed.
- Q3 (fix6 B1c, loader metadata hearsay arm): goes through the
  same proof-checked seam; if retained ownership covers it, it
  passes, else it files the named skip. No silent exception.
- Q4 (L3-2 starvation): closed by cursor rotation (§4.2).
- Q5 (fix6 B3, one table vs three): one table per owner with
  explicit N/A cells (§9).
- Q6 (bisect/bug1 inputs): if the bisect names a narrow regressing
  commit, owner 1's table gains that commit's behaviour as a cell;
  the narrow undo does NOT ship separately — it is subsumed by the
  refactor. If bug-1's fix lands first on its branch, its twins are
  adopted as the cursor contract (§4.2).
