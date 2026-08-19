# Slice 1b-2 no-busy-wait pause amendment

**Date:** 2026-08-19

**Status:** Independently approved for production planning on the Slice 1b-1
base below; production implementation requires a separately reviewed plan

**Exact source base:** `5f3bd607032057f8d04ced55fcb27ba185193416`

## 1. Scope and authority

This document narrowly amends the pause state machine and Gate B campaign in
`2026-08-18-slice1b2-corrective-live-discovery-design.md`. It supersedes that
design's one-owner wording in §5.2-§5.7, private Gate B evidence in §6.1,
the one-winner-only campaign predicate in §6.2, the matching acceptance
criterion in §12, and the rejection of every repeated `SIGSTOP` in §13.
All other corrective-design requirements remain binding.

The amendment records the later owner-directed no-busy-wait A/B protocol. It
does not:

- promote or cherry-pick the research spike;
- claim the retained 120/120 campaign is safe or promotable;
- change the 100 ms per-cycle deadline, one-millisecond sampling cadence,
  exact task-set/all-`T` confirmation, or original-pidfd-only rule;
- authorize external-target pause, a numeric-PID signal fallback, a fresh
  pidfd, a busy-wait, an adaptive deadline, or a signal resend within one
  cycle;
- change `DiscoveryRecord`, public evidence fields, privacy, schema, loader
  qualification, dynamic-slot semantics, or any capture limit; or
- authorize production implementation before this amendment and the resulting
  production plan pass independent review.

## 2. Binding evidence and disposition

The following retained inputs are immutable:

| Artifact | SHA-256 or identity | Binding fact |
| --- | --- | --- |
| `slice1b2-gates-STATE.md` at research HEAD `7f42ad71257cdb64d292b0523733eec65cd039f3` | campaign state | The owner-directed protocol permits outcome A (one accepted cycle with a coalesced sibling) and outcome B (a deferred sibling claims a pre-armed second cycle), with no BPF delay or polling. |
| Frozen source/bundle commit | `0b63350771391e2cdc0a8ffc30b5a763f590ef2b` | The sealed runner/fixture/validator identity used by the retained campaign. |
| Private campaign `EVIDENCE.sha256` | `e95aac331ccde295d8e387c973ca5008345b6ccfc8da78393cdff2da14e4158c` | All 373 entries verify; 120/120 frozen-oracle results were outcome B on Jammy 5.15 and Noble 6.8. |
| Controller review | `aa73dfcbdf49bb0a699594566b0378860dcf561766c7db955e392817651a5738` | **CAMPAIGN PASS / PROMOTION BLOCKED**: owner-2 cleanup and outcome-A deadline defects, plus written-oracle mismatch. |
| Independent review | `59b3186171330e845134b97bf22bc51077d2ef8f7b4d8d261e5b91d974c0d489` | Confirms both Critical defects and requires a new bundle and six-lane campaign. |

The retained campaign proves only that the exact frozen two-cycle research
implementation completed its frozen oracle on those 120 children. It remains
pre-fix evidence. Neither its PASS label nor its observed outcome-B frequency
authorizes product pause.

## 3. State model

### 3.1 Coordinator and authorization

One `run` child generation has one userspace `PauseCoordinator`. It owns the
original pidfd, pinned process generation, expected task set, pause policy,
aggregate counters, and the finite lifecycle of every accepted stop cycle.
There is never more than one accepted stop cycle at a time.

`PAUSE_PIDS` has one value for that exact child generation:

- absent: no hook may request a stop;
- `ARMED`: the next eligible hook may atomically begin one cycle;
- `REQUESTED`: one hook won the cycle; later hooks submit coalesced records and
  never call the signal helper.

The map state is authorization, not a second pidfd or a second child owner.
While the current accepted cycle remains stopped, userspace may replace its
`REQUESTED` value with one successor `ARMED` value immediately before the
current cycle's resume. This is the only permitted overlap: one accepted stop
cycle plus one not-yet-consumed successor authorization, both owned by the
same coordinator and original pidfd.

The exact task set is confirmed all-`T` before successor installation, so no
target hook can consume that successor before userspace's original-pidfd
resume succeeds. A successor record or `REQUESTED` observation before that
resume returns success is an invariant/lifecycle failure; it is never accepted
as cycle 2.

The coordinator disarms before child kill/reap or any failure that prevents a
successor cycle. Teardown first detaches every pause-capable link, then drains
its already-submitted records, then reads/removes the authorization. A decoded
accepted request, a remaining `REQUESTED` value, a malformed/lost record after
authorization consumption, or an otherwise unresolved transition requires a
protective original-pidfd `SIGCONT` before kill/reap. A stale generation never
consumes or inherits an authorization.

### 3.2 BPF order

Every eligible hook performs this exact order:

1. validate scope, generation token, and attach cookie/key;
2. reserve its complete discovery record; reservation failure increments the
   exact loss counter and consumes no authorization;
3. initialize every helper-independent byte;
4. atomically compare/exchange `ARMED -> REQUESTED`;
5. if it won, take `hook_ts_ns` immediately before one
   `bpf_send_signal(SIGSTOP)` and store the signed return; otherwise take its
   timestamp and store the finite coalesced/no-helper status;
6. finish initialization and submit.

There is no loop, poll, delay, or scheduler yield from the authorization CAS
through terminal record submission. The winner path has only its one clock
read, one signal helper, straight-line record stores, and terminal ring submit;
the coalesced path has only its clock read, straight-line stores, and terminal
submit. Each accepted cycle makes one signal-helper call. A successor cycle
may make its own single call only after the previous cycle's safe
pre-arm/resume transition.

### 3.3 Accepted-stop ownership

After userspace decodes and validates an exact-generation winner record with
`send_signal_rc == 0`, it marks the child as possibly stopped **before** any
clock read, cancellation check, `/proc` sample, marker read, ring drain,
attachment, or other fallible action. Cleanup therefore makes exactly one
original-pidfd `SIGCONT` attempt for every accepted request, even when stop
confirmation later times out or cancellation wins.

The mark is cleared only after that cycle's original-pidfd resume succeeds and
no successor authorization can already have stopped the child. When userspace
pre-arms a successor before the current resume, the guard remains
conservatively `may_be_stopped` across that resume and the bounded successor
record acquisition. A cancellation or timeout in that interval cannot bypass
cleanup merely because the successor record has not yet been decoded.

If a successor record reports an accepted request, the guard retains that
mark before its first fallible action. If it reports a rejected helper request,
userspace may clear the successor mark after the authorization is removed. If
the successor result is missing, malformed, lost, or otherwise unresolved,
cleanup removes the authorization and makes one protective original-pidfd
`SIGCONT` attempt before kill/reap. This protective attempt is a lifecycle
failure path, not a confirmed pause or normal counter contribution. A failed
resume is never retried through a new pidfd or numeric PID.

The coordinator keeps one private lifecycle ledger per authorization epoch:

```text
authorization_consumed
accepted_request
accepted_cycle_resume_attempted
accepted_cycle_resume_rc
successor_installed
successor_resolution = none|unconsumed|accepted|rejected|unresolved
successor_protective_resume_attempted
```

The epoch is userspace-only and is not added to a map, record, or public
output. An accepted-cycle resume is attempted at most once and is never
retried after failure. One additional protective `SIGCONT` is permitted only
when the accepted-cycle resume succeeded, a successor was installed, and that
successor remains unresolved; it is recorded separately, attempted at most
once, and forces lifecycle failure rather than normal pause accounting.

### 3.4 Rejected requests

A winner record with a real negative helper return consumed its authorization
but did not establish a stop. Userspace removes the corresponding `REQUESTED`
value, drains until the winner-relative 100 ms deadline and one empty read
without claiming stopped-set closure, and records the attempt as
non-confirmed. Every same-epoch coalesced, missing, malformed, or lost record
is assigned exactly once to that failed attempt. Explicit `auto` disables
further pause arming for that child and remains sticky partial; live discovery
may continue unpaused. Explicit `always` disarms and returns its required
failure after ordinary owned-child cleanup. It sends no `SIGCONT` solely for a
proved rejected helper request; an unresolved successor transition still
follows the protective cleanup rule above.

## 4. Per-cycle causal closure

Each winner defines one checked absolute deadline:

```text
cycle_deadline_ns = winner.hook_ts_ns + 100_000_000
```

Every record assigned to the cycle must have a valid same-domain timestamp no
later than that deadline. Userspace checks the monotonic clock **before**
dequeueing a new ring item, checks it again immediately after dequeue/decode,
and validates the item's timestamp before accepting it. Both observed `now`
values and the record timestamp must be no later than the same deadline. A wait
begun before the deadline but completed after it is late even when the record
carries an older timestamp; dequeue order does not forgive it.

Drain-to-empty while the exact task set is stopped is the cycle boundary. No
public or private cycle ID is added to the record. A record observed after that
closure belongs only to a later authorization; it cannot be moved backward to
complete the closed cycle.

When a coalesced record arrives before its winner, its timestamp supplies only
a provisional `coalesced.hook_ts_ns + 100 ms` wait bound. After the winner
arrives, the winner-relative deadline is canonical and every record is checked
against it. Overflow, future timestamps, clock mismatch, late records,
duplicates, unknown status, malformed records, relevant loss, or an
unaccounted record makes the cycle non-confirmable.

The existing safety predicates remain per cycle:

1. one exact-generation accepted winner;
2. two consecutive exact-set/all-`T` samples at least 1 ms apart and no later
   than the cycle deadline;
3. drain-to-empty with every assigned record valid;
4. no protected marker before attachment;
5. every attach key known to that cycle attached while stopped;
6. a third exact-set/all-`T` sample, absent marker, and empty queue immediately
   before the transition; and
7. exactly one successful resume through the original pidfd, followed by the
   expected lifecycle/marker result.

No signal is resent inside a cycle. No later cycle repairs a failed earlier
cycle.

## 5. Exclusive outcome branches

### 5.1 Outcome A: coalesced sibling

Outcome A is one accepted cycle:

- exactly one winner/helper call;
- exactly one coalesced/no-helper sibling record for the Gate B two-hook
  fixture;
- both distinct fixture case IDs and attach sets in the frozen cycle;
- both attach sets complete before one resume; and
- exactly one confirmed cycle and original-pidfd resume.

The coalesced record may arrive before or after the winner, but both must pass
the winner-relative causal closure. A focused deterministic producer test
must exercise this branch even if the concurrent kernel campaign schedules
only outcome B.

### 5.2 Outcome B: deferred sibling

Outcome B is two sequential accepted cycles. It is used only when the first
cycle reaches stopped drain closure with exactly one of the Gate B fixture's
two predeclared case IDs:

1. cycle 1 attaches that case's complete set and satisfies every pre-resume
   predicate;
2. while the child remains exact-set/all-`T`, userspace closes cycle 1's
   `REQUESTED` authorization and installs one successor `ARMED` value;
3. userspace rechecks the task set, marker, and queue, then resumes cycle 1
   exactly once through the original pidfd while retaining the conservative
   successor-stop cleanup guard;
4. the deferred sibling hook must submit the other case ID, win the successor
   authorization, and make its own accepted stop request before its caller's
   post-return marker;
5. userspace marks the accepted second stop immediately, then independently
   confirms, drains, attaches, samples, and resumes cycle 2 under its own
   winner-relative 100 ms deadline; and
6. both links detach, the authorization map is absent at exit, and the child
   exits/reaps cleanly.

No successor hook can run between steps 2 and 3 because the exact task set
remains stopped. Observing successor consumption before the step-3 resume
returns success is a lifecycle FAIL followed by non-short-circuiting cleanup.

Failure to install or later remove the successor authorization, failure to
observe the known second fixture case, any marker before its own attach set,
or any second-cycle failure makes the Gate B child FAIL after safe cleanup.
It is never rewritten as outcome A.

The private Gate B runner waits for the successor record only until the first
of: that record, either post-return marker, child exit, cancellation, or the
existing five-second ring-liveness bound. Only the exact record is success.
The five-second bound does not extend the second cycle's safety window: after
the record arrives, its winner timestamp starts the unchanged 100 ms deadline.

### 5.3 Product use

Production uses the same coordinator and cycle rules, but it never invents an
expected record. While pause protection remains enabled, each received live
event is either assigned to the current cycle or begins a successor cycle.
Only a fully successful current cycle may keep one successor authorization
armed while explicit `auto|always` live protection remains enabled. A failed
`auto` cycle disables further arming for that child. An event received while
the coordinator is intentionally unarmed, an authorization transition fails,
or a relevant record is lost creates an unprotected live window: sticky
`PARTIAL` for `auto`, required failure for `always` after safe cleanup.

Outcome A protects every key present in one causal drain. Outcome B protects a
deferred event in its own later cycle. Neither branch claims that an unseen
event never existed. A module's first live-required key remains complete only
when its exact cycle attached the complete eventual required set before that
cycle's resume; otherwise the existing live-window completeness rule forces
`PARTIAL`.

## 6. Counters, gaps, and cancellation

One consumed authorization with a winner record begins one `pause_attempt`,
whether the helper request is accepted or rejected. A coalesced record belongs
to that attempt. Outcome A therefore has one accepted attempt; outcome B has
two. Each attempt contributes exactly once to `pause_confirmed` or, for
explicit `auto` after safe cleanup, `pause_partial`; a rejected helper cannot
confirm. Standalone unarmed/lost protection events retain the corrective
design's one-partial-attempt accounting.

An observed `REQUESTED` value, or loss/malformedness known to occur after one
authorization epoch was consumed, creates exactly one unresolved owner
attempt even when no usable winner record survives. Under `auto` it contributes
one sticky partial attempt after protective cleanup; under `always` it is one
required failure. The same failure is not counted again as a standalone loss.
A reservation loss that left `ARMED` unconsumed remains the separate
standalone partial attempt defined by the corrective design.

For every normal result:

```text
pause_confirmed + pause_partial == pause_attempts
```

The existing `none|sigstop|partial` lattice is unchanged. Outcome B can render
`sigstop` only when both attempts confirm and neither is partial. A later
confirmed cycle never hides an earlier partial cycle.

Attach-gap ownership is unchanged: each module starts at its earliest causal
live event and ends after its last required successful attachment. A second
cycle does not reset or shorten an earlier gap. Relevant record loss keeps the
gap `null` and forces `PARTIAL`.

An ordinary non-lifecycle `auto` cycle failure, including a rejected-helper
failure under §3.4, removes that cycle's authorization, completes any
ledger-authorized resume, drains/decodes through the old cycle's bounded
closure plus one empty read, and records one sticky partial attempt. It
disables further pause arming for that child: a later record remains
unprotected live-discovery evidence and cannot be assigned to a fresh pause
epoch. This path does not detach the session's other live-discovery links.

On cancellation, teardown, or lifecycle error, cleanup is an idempotent,
non-short-circuiting progression. It blocks re-entry, attempts every
pause-capable link detach,
performs the bounded drain/decode, reads and removes the authorization, applies
the lifecycle ledger's required accepted-cycle or successor-protective resume,
and performs the already-owned kill/reap when requested. Every failure is
retained, but detach, drain, map, or decode failure cannot return before the
resume obligation is attempted. A failed accepted-cycle resume is not retried
as a protective successor resume. Only after every safe step has been
attempted does cleanup return the accumulated lifecycle error. A second
cancellation signal cannot re-enter or bypass this progression.

## 7. Amended Gate B evidence and campaign

The private timing record may carry at most two ordered cycle summaries. Each
summary contains only the existing finite aggregate timing/sample fields,
case IDs, record counts/status classes, attach counts, resume result, and
marker/lifecycle booleans. It contains no raw PID/TID/task set, address,
cookie, signal record, or path.

The validator recomputes one and only one branch:

- **A:** one winner, one coalesced record, one helper call, one cycle, one
  resume, both case IDs/attach sets complete;
- **B:** two winners, zero coalesced records, two helper calls, two ordered
  cycles, two resumes, one distinct case/attach set per cycle.

Mixed, surplus, duplicate, missing, unattributed, or contradictory shapes are
FAIL. Both branches retain all timing, stopped-set, drain, attachment, marker,
detach, exit, reap, counter, privacy, provenance, and cleanup predicates.
There is no required runtime quota for A versus B. A deterministic focused
test covers A; the concurrent campaign reports the observed branch per child
without rerun-until-branch selection.

After the two known Critical defects are fixed, freeze a new source archive,
manifest, BPF, runner, fixture, validator, execution manifest, and hashes.
Run exactly three fresh cold-boot KVM lanes with 20 children on Jammy 5.15 and
three on Noble 6.8. Run every predeclared lane regardless of an earlier
semantic FAIL unless host/lifecycle safety requires stopping. There are no
replacement lanes or reruns.

Promotion requires 120/120 children independently recompute as exactly A or B,
zero verifier/runtime/oracle/timeout/privacy/provenance/cleanup failure, and a
new independent source/evidence review. The retained `0b63350` campaign remains
linked as pre-fix evidence and contributes zero promotion attempts.

Any BPF, runner, fixture, lifecycle, deadline helper, record, validator,
oracle, timeout, or cap change creates another campaign identity.
The parent corrective design's dependency rule remains binding: any changed
A/B dependency also reruns the structural initializer guard and the exact
two-kernel Gate A oracle on the same final bytes before the six Gate B lanes.

## 8. Required RED/GREEN boundaries

Before implementation, focused old-behavior REDs must demonstrate that the
current implementation is wrong because:

1. cancellation and confirmation timeout after accepted owner-2 request skip
   the required cleanup resume;
2. cancellation after successor pre-arm/resume but before its record decode
   can bypass successor-stop cleanup;
3. a successor record consumed before the prior original-pidfd resume succeeds
   can be accepted as cycle 2;
4. a rejected helper can leave `REQUESTED`, rearm the child, send an
   unnecessary `SIGCONT`, or miscount its bounded record set;
5. an ordinary failed `auto` epoch can publish fresh `ARMED` and attribute a
   late old-epoch record to the new authorization;
6. winner-first plus a late coalesced record is accepted;
7. a dequeue begun before the deadline returns after it and accepts an older
   record timestamp;
8. Rust and Python validators disagree with or fail to enforce the amended A/B
   shapes; and
9. the structural guard rejects any loop/poll/delay from authorization CAS
   through terminal record submission, including after the signal helper.

GREEN requires:

- immediate accepted-stop marking before every fallible edge for every cycle;
- one canonical winner-relative deadline used by wait, drain, Rust oracle,
  Python validator, and serialized evidence, with local-clock checks both
  before and after dequeue/decode;
- failure-injection tests for cancellation, timeout, map-transition failure,
  resume failure, detach failure, drain/decode failure, map read/removal
  failure, and cleanup re-entry; each proves cleanup continues to the one
  ledger-authorized resume and then reports every accumulated error;
- explicit ledger tests that reject an accepted-cycle resume retry, permit at
  most one successor-protective resume only after a successful prior-cycle
  resume, and assign a consumed-but-undecodable authorization exactly one
  attempt;
- a pre-resume exclusion test proving successor consumption cannot become
  cycle 2 before the prior resume succeeds;
- rejected-helper tests proving 100 ms bounded drain plus one empty read,
  authorization removal, zero `SIGCONT`, exactly one partial `auto` attempt,
  no later `ARMED` publication through the general failure path, and a named
  `always` failure;
- a generic failed-`auto` test proving bounded old-epoch closure, sticky
  partial accounting, no later `ARMED`, and no reassignment of a delayed
  old-epoch record;
- exhaustive finite A/B mutation tests, including timestamp boundary,
  overflow, reversed arrival, duplicates, missing/surplus records, wrong case,
  marker, task-set, queue, attach, resume, and lifecycle contradictions;
- a campaign-blocking source/disassembly guard over every pause-control branch
  from authorization CAS through terminal submit, allowing only the one clock
  read, the winner's one signal helper, straight-line stores, and terminal ring
  submit; and
- all existing spike and root unprivileged gates before review/freeze.

## 9. Acceptance criteria

This amendment is ready for production planning only when independent review
confirms:

- at most one accepted stop cycle and one successor authorization exist for
  one owned child generation;
- reservation precedes CAS, timestamp immediately precedes the sole per-cycle
  signal helper, and no busy-wait or resend exists;
- every accepted stop is marked before a fallible edge and receives exactly
  one original-pidfd resume attempt on every exit path;
- cleanup never short-circuits before its ledger-authorized resume, never
  retries a failed accepted-cycle resume, and permits only the distinct single
  successor-protective resume for an unresolved installed successor;
- every cycle has one winner-relative 100 ms causal closure applied before and
  after dequeue/decode as well as to the record timestamp;
- outcome A and B are mutually exclusive, finite, and preserve attachment,
  marker, task-set, queue, detach, exit, reap, counter, and privacy safety;
- successor authorization is installed only while the current child remains
  confirmed stopped, is removed on failure/teardown, and cannot survive PID
  generation change;
- successor consumption before the prior resume succeeds is rejected as a
  lifecycle invariant failure;
- a failed `auto` epoch disables pause rearming for that child, so a delayed
  old-epoch record cannot cross into a fresh authorization;
- the guard remains conservatively stop-capable from successor pre-arm through
  bounded record resolution, and teardown uses detach, drain, authorization
  removal, and protective resume ordering before kill/reap;
- product completeness never infers an unseen event or treats a later cycle as
  repairing an earlier unprotected window;
- public evidence and the privacy allowlist remain unchanged by this private
  protocol amendment; and
- the old campaign stays immutable and a new full six-lane campaign is
  mandatory.
