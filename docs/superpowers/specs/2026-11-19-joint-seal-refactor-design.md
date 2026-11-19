<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Joint seal refactor: per-session recovery ownership (design)

Status: design (phase 1 of task/v072-joint-seal-refactor).
Base: `dev` `c2a180a71` ("fix: stage length outcomes for pending capture
construction"). Branch: `task/v072-joint-seal-refactor`.

Owner rule (2026-11-19, binding): a bug that can only be fixed properly
by refactoring is refactored NOW (v0.7.2 if green by the Friday cut,
else v0.7.3), not deferred.

Prior art (read, not edited): `task/v072-joint-watchdog-continue` at
`d083388d2` with the Tier-2 review
`codex62-rv-v072-joint-watchdog-continue.review.md` (CHANGES REQUIRED,
2 blocking) and the fix1 report
`spark-v072-joint-watchdog-continue-fix1.report.md` (BLOCKED, RED twins
for both blocking findings). That lane's fix2 round (interim
whole-stream-dispose-counted ruling) was still running when this spec
was written; its landed commits (`f9ae18402`, `66be33cf8`, `d083388d2`)
were read via git. This refactor supersedes that interim fallback: once
this lands, no stream-wide watchdog fallback is needed. Integration
order is the integrator's call.

## 1. Problem

In per-caller key tracking (Joint) one stuck caller invalidates healthy
sessions. Three defects, one root cause (recovery has no per-session
ownership):

1. Whole-frame + every feed + every domain + open-table wipe. A
   running re-arm (`LiveJointMachine::rearm_after_running_refusal`,
   `src/inventory/semantics/joint/machine.rs:1776`) hands off the
   whole frame (`take_abandoned_frame` +
   `abandon_unfinished_joint_publication`), calls
   `drop_abandoned_joint_staged` (every retained feed, barrier `None`,
   `src/discovery/caller_registry/instance_input.rs:3053`), then
   `break_stream_after_running_abandon`. The next Idle collect runs
   `void_ingest_break_inner` (`src/semantics_objects/journal.rs:3011`)
   → `fence_void` (every domain, `:7065`) + `void_staged` (whole open
   table, `:7330`). A healthy session B with an open destroy loses its
   BEGIN; B's later END taints B's image fail-closed (correct rule,
   wrong scope). Even without a destroy, B's pre-fence authority is
   lost. The seal stalls as `BoundNotReady`/`Retry` (spend-then-refund,
   net zero, `joint_audit.rs:2047-2056`), pinning the frame cursor
   behind the stuck consumer.
2. Recovery scans unboundedly. The driver leaves the budgeted commit
   poll to re-arm synchronously; feed scan, per-head
   `observe_with_effects` + ledger/loss accounting, and the
   full-domain journal effects pass are uncharged, violating INV-2
   (64 units/credit, owner 2026-11-13: binds scans that read/compute).
3. The late birth funnel can stall behind a stuck member. The
   seal/delivery consumer cursor (`joint_audit.rs:1681-2091`) visits
   consumers strictly in order; a stuck consumer pins the cursor, so
   healthy members' seals — and the births they consume — never run,
   the frame never completes, and (on this base) the audit trip then
   holds the lane, ending the funnel for everyone. A second, still
   unroot-caused late stall (leg4: no rows after minute ~19 with no
   voids/trips) needs funnel instrumentation, not speculation.

Out of scope for the mechanism, in scope for the contract:
void-taint granularity redesign stays out (taint keeps its fail-closed
rule; only its blast radius shrinks because healthy BEGINs survive),
and the leg4-type stall gets instrumentation + a per-member progress
bound, with soak forensics if it reproduces.

## 2. Goals and non-goals

Goals:

- G1. A stuck caller taints only its own session: disposal, fence,
  void wipe and taint are scoped to the stuck set; healthy sessions
  keep staged proof, mode, fence state and authority, and their key
  rows stay exact.
- G2. One owner for the watchdog: `LiveJointMachine` owns trip latch,
  stuck-set derivation, park, scoped recovery, re-arm gate and
  disclosure as one lifecycle.
- G3. Recovery is bounded: per-session discard by bulk free with a
  counted named gap (no per-head work), O(1) bookkeeping per affected
  feed. Any future per-head preservation goes through 64-unit strided
  cursors charged to the machine budget.
- G4. The birth funnel never stalls behind a stuck member: parked
  consumers no longer pin the cursor; births for healthy members flow
  past them; any member without progress across the watchdog bound is
  parked with a named gap.
- G5. The lane never stops on a running audit trip: audit trips take
  the same scoped recovery + re-arm (this subsumes the
  watchdog-continue behavior change, localized). Finish trips still
  refuse re-arm (terminal; unchanged).

Non-goals:

- N1. No per-key taint fallback (that redesign stays a seal-lane
  follow-up). Stranded destroys inside the stuck session still taint
  the stuck session's own image — fail-closed, now correctly scoped.
- N2. No mid-run provider attach, no admission-race fixes.
- N3. No wire/JSON schema change. Gap subjects are unchanged; reason
  texts change only where behavior changes (fixes), staying truthful.
- N4. No new capture: `docs/privacy/allowlist-v1.md` stays
  byte-identical. Userspace-only refactor.

## 3. Design

### 3.1 Session identity and the stuck set

A Joint session is one frame consumer: a `JointFeedTarget` (feed id)
plus its caller binding, journal domain and image
(`(task_cookie, exec_id)`). At trip/re-arm time the watchdog owner
derives the stuck set from the abandoned frame's consumer targets:

- feeds: the frame consumers' feed ids;
- domains: their `ObjectDomain`s;
- images: their caller bindings' images.

Scoping is per level, by that level's own identity (verified
against code before implementation):

- feeds scope by feed id (`JointFeedTarget`): always separable,
  even same-PID/same-image;
- domains scope by full `JournalDomainKey`
  (`domain_tag/caller/cookie/exec/router`,
  `src/semantics_objects/journal.rs:394`): same-PID files differ
  by router, so they separate;
- open-table entries scope by attribution: entries converted for
  (`converted_for`), or attributable only to, stuck keys wipe;
  entries attributable to a healthy live key stay;
- image taint (`tainted_images`) stays per-image (fail-closed):
  same-image sessions share taint fate. This is residual R1: the
  stuck session must avoid destroy-overlap for full same-image
  preservation (the RED test and the soak do); cross-image healthy
  sessions are fully preserved regardless.

Shared identity means shared fate at that level, never silent
splitting; everything else is preserved bit-for-bit.

### 3.2 Per-session seal ownership: park, then advance

New frame operation `park_stuck_consumer`, driven only by the watchdog
owner when the running bound fires:

1. Take the cursor consumer's pending seal failure (the real failure —
   `BoundNotReady`, `Retry`, held — never invented).
2. Deliver it once as terminal scoped loss through the existing
   failure-delivery path (`deliver_joint_failure`) with retry
   disabled, scoped to `SealFailureScope::AffectedDomains(stuck
   domains)`. The feed degrades exactly as it would under a fenced
   void today (fallback/S1 rows + counted loss + named gap).
3. Mark the consumer `LossDelivered` (existing variant: degraded with
   counted loss — no new state) and advance the cursor past it via the
   existing skip logic.
4. Repeat for further stuck consumers up to the bound; healthy
   consumers seal and deliver normally between parks.

If no consumer can progress, the frame is abandoned (scoped, §3.4) and
the lane re-arms. If the whole stuck set is the whole frame, behavior
reduces to today's abandon — correctly, with per-session counts.

### 3.3 One watchdog owner

`LiveJointMachine` owns the full lifecycle: trip latches (existing),
stuck-set derivation (§3.1, new), park (§3.2, new), scoped recovery
(§3.4, new), the re-arm gate extended to audit trips (G5), and
disclosure (existing gaps + extended counts). The driver
(`hold_joint_commit_lane_and_publish`,
`src/inventory/mod.rs:5094`) keeps only its single trigger call. The
Idle void consumes the break scope the owner recorded instead of
re-deriving stream-wide scope. The exit hold
(`hold_joint_lane_for_exit`, `src/inventory/mod.rs:4236`) keeps full
terminal abandon — the lane stops there, so full scope is correct.

### 3.4 Per-session journal ownership: scoped breaks, not stream breaks

Two break kinds, distinguished by what was lost:

- Ingest-side breaks (non-contiguous cuts, legacy ingest): a stream
  position is genuinely missing, which is stream-wide. These keep the
  existing stream-wide void (`void_ingest_break_inner` unchanged).
- Watchdog/re-arm breaks: one quantum's unsealed history is abandoned
  while the stream position is intact. These record a SCOPED break
  (stuck set, §3.1) and the Idle void consumes it with:
  - `fence_void_scoped`: raise `void_fence` and record
    `outcome_lost` only for stuck domains' keys;
  - `void_staged_scoped`: wipe open entries, refused entries and
    claims only for stuck images; `void_wiped` and derived-absence
    notes cover only those;
  - per-domain void cuts for births: scoped breaks must NOT raise the
    global `voided_through` (healthy births below the cut keep
    answering); stuck-identity births check their domain's cut.
    (Exact birth-cut check site to verify in implementation.)
  - `drop_abandoned_joint_staged_scoped`: dispose only stuck-set
    feeds (see §3.5).

Fail-closed destroy is preserved with narrowed scope: a stranded
destroy inside the stuck session still promotes to taint its own
image; healthy BEGINs survive the scoped wipe, so healthy destroys
match and never taint.

### 3.5 Bounded recovery: per-session discard with a counted named gap

Scoped recovery discards the stuck set's staged queues by bulk free:
no reduction, no replay, no per-head ledger contact. Per feed: O(1)
bookkeeping (depth read once, frontier jump, disposed-history count)
plus the queue's bulk free; one bulk ledger release for the stuck
set's staged charges (new, mirroring the existing `release_all_h8open`
shape). Under INV-2 as amended by the owner (2026-11-13), a
memory-only bulk free bounded by product limits is not a finding, so
the 64-unit bound holds at any staged depth. Each feed's depth counts
as disposed history; the re-arm gap names the discarded total, the
stuck feed count and the per-key-unknown attribution. Live reducers,
S1 counts and minted associations are untouched; feed modes still
fall back on the fenced void delivery.

Contract for the future: if per-head preservation ever returns, it
goes through explicit feed/payload/domain cursors in 64-unit strides
charged through the machine's normal budget, yielding with custody
intact — never as synchronous uncharged work.

### 3.6 Birth funnel: no head-of-line blocking

Verified already non-blocking and kept: `claim_next` skips
unclaimable entries (retain-as-plain-S1 with named cause,
`joint.rs:1063-1134`); birth re-offers are per-key bounded (3/key +
observed-keys cap, `instances.rs:1147-1192`).

New:

- Seal-side birth consumption (`SelectedBirth` lookup per consumer)
  proceeds past parked consumers via cursor advance (§3.2): healthy
  members' births flow while the stuck member is degraded.
- Per-member progress bound: any funnel member (claim, stage, birth,
  seal consumer) with no progress across the watchdog bound is parked
  with a named gap. No member waits on another member's progress.
- Instrumentation: timestamped per-member birth outcomes
  (admitted/deferred/refused + reason + age) so a soak can root-cause
  any leg4-type stall instead of guessing. If the leg4 signature
  reproduces (no late rows, no voids/trips), the owning birth lane
  gets evidence, not speculation.

## 4. Entry-point table (normative for the table-driven test)

Every entry point that can reach recovery/void, and its scoped
behavior. One table-driven test drives all rows; each row pins exact
healthy-preserved counts, exact stuck-loss counts, the named gap, and
lane liveness past recovery.

| # | Entry point | Trigger | Scoped behavior |
|---|-------------|---------|-----------------|
| E1 | Running transient re-arm (`rearm_after_running_refusal` via `hold_joint_commit_lane_and_publish`) | `Unavailable` at Auditing/Audited, no finish trip | Park stuck consumers; scoped feed dispose + scoped break; lane re-arms; healthy feeds/domains/images bit-identical |
| E2 | Running audit-trip re-arm (NEW: G5) | Audit no-progress bound fires | Same scoped recovery as E1, then re-arm; trip cleared; healthy sessions preserved; new callers join |
| E3 | Idle ingest-break void (`void_ingest_break` at Idle collect) | `stream_broken` from ingest side | Stream-wide void ONLY for genuine ingest breaks; watchdog breaks consume the recorded scope (E1/E2 never re-widen here) |
| E4 | Exit hold (`hold_joint_lane_for_exit`) | Lane stops | Full terminal abandon UNCHANGED (correct at stop); pins no over-scoping regression in the other direction |
| E5 | Finish no-progress trip | Finish bound fires | Re-arm still refused (`WatchdogTripped`); hold discloses; UNCHANGED |
| E6 | Seal cursor park (§3.2) | Watchdog bound with stuck cursor consumer | Cursor advances past degraded consumer; later healthy consumers seal/deliver in the same frame |
| E7 | Birth funnel past stuck member (§3.6) | Stuck member + healthy births | Healthy births decided/consumed; stuck member parked with named gap; re-offer bounds kept |

E4/E5 are no-change guard rows: the refactor must not alter terminal
behavior while localizing running recovery.

## 5. Gaps, wire and schema

- Gap subjects unchanged (notably `RUNNING_REARM_SUBJECT`). Reason
  texts change only where behavior changes: the re-arm reason names
  the scoped discard (`discarded {calls} staged calls from {feeds}
  feeds of the stuck session; per-key attribution unknown for those
  calls`) and drops the stream-wide "lose per-key rows for the rest
  of the run" claim for healthy sessions (false after this lands).
- The audit-trip gap text on this base (`the semantic lane stops`)
  becomes truthful for the continuing path (`abandoning the stuck
  frame`; the hold path keeps its stopped wording when a re-arm is
  actually refused).
- No new gap identity fields: caller/module/PID stay `None` on these
  gaps, as today. No schema, wire or JSON shape change.

## 6. Privacy

No new capture, no new read, no new retention: allowlist-v1 stays
byte-identical (verified by diff). Userspace-only change; no BPF, no
manifest, no profile-schema touch.

## 7. Acceptance

- Table-driven test over E1–E7 (RED first, then GREEN), plus affected
  neighbors, full lib green, `fmt --check`, strict `clippy`,
  allowlist-v1 byte-identical, `git diff --check` clean.
- Soak on fedora, 20 min, with a forced stuck caller: healthy
  callers' key rows exact, the stuck caller's loss counted under the
  named gap, the lane never stops.
- No existing assertion edited without a ruling (common-rules
  lessons): any behavior-change assertion updates are listed for
  ruling with before/after semantics.

## 8. Risks and residuals

- R1. Same-PID files sharing a domain/image degrade together by the
  conservative closure (§3.1). Counted, disclosed, fail-closed — but
  coarser than per-feed. Per-key invalidation would narrow it
  further (seal-lane follow-up, N1).
- R2. The leg4-type late stall (no voids/trips) has an unknown cause;
  this design bounds and instruments the funnel (§3.6) but claims no
  root-cause fix for it. Soak forensics decide.
- R3. Birth-cut check site for per-domain void cuts must be verified
  during implementation (§3.4); if births cannot scope cleanly, the
  fallback is the global cut with a documented residual (healthy
  births below the cut refuse loudly, never silently).
- R4. This supersedes the watchdog-continue interim fallback; the two
  lanes must not both land. Integration order is the integrator's
  call; this spec records the supersession explicitly.
