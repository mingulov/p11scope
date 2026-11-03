<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Packet 6.15 K0 contract — selected-endpoint detail from the broad counter

**Status:** current contract for `--select-endpoint` (K0), implemented in
`src/metrics/selected_detail_driver.rs` and the `capture_profile` metrics
selection path in `src/run.rs`. User-facing wording lives in `docs/usage.md`
and `docs/known-limitations.md`.

For `--mode metrics --counter-mode <m> --select-endpoint <FUNCTION>`, the
detail is the selected slot's own per-mode cells from the **broad** session's
counter banks between a selection-time read and the close read. No child
Session, no second BPF object, no scan pass, no baseline walk, no manifest
attestation, no new kernel read, no argument reads. `docs/privacy/allowlist-v1.md`
stays byte-identical (choice A: metrics never reads call arguments).

## 1. Selection-time read: when and what

In `capture_profile` before the capture loop, `run_metrics_selection_stage`
resolves the name against the live broad `Counters` plan: exactly one slot
(zero ⇒ `endpoint_unknown`, two or more ⇒ `promotion_endpoint_ambiguous`,
never first-match; an aliased slot resolves as its whole group) and one live
original (`Scope::Pid` only, pinned with pidfd + start-time + liveness).
On success the stage records the selection (no refusal yet) and K0 opens:

- one `read_bound` over the broad Counters plan from the broad session's own
  banks (same binding, same mode, same limits, same pool reserver as the
  broad tick reads), observed once through a dedicated `CounterCollector`
  (`Initial`, installs the baseline);
- one snapshot of the broad session's exec-witness facts (`LifecycleFacts`:
  `latest_exec`, `greatest_break_ns`, `fault_serial`).

Owned `run` without comparable kernel/userspace monotonic clock
origins (K0-3 fallback, `clock_origins_comparable`) refuses up front
as `promotion_scope_unsupported` and opens no window: the child's own
startup exec could not be bounded by the selection stamp. A `--pid`
target needs no stamp, so its window opens without one.

A failed selection-time read records the mapped adapter word immediately
(`quarantined`, `budget`, `broad_not_counter`, else `broad_plan_topology`,
the existing `read_stage_refusal` precedent) and opens no window. Unreadable witness
facts, or a session with no PID witness, at open ⇒ `broad_plan_topology`
(no provable window can open on this broad).

## 2. Scopes: `--pid` and owned-`run` only

`--cgroup` and `--system` keep today's named refusal
(`promotion_scope_unsupported`) and get no detail. Why: they name no single
original, and the exec witness (`PidLifecycleTap`) exists only for
`UProbeScope::OneProcess`, which only `Scope::Pid` builds. Owned-`run`
passes `Scope::Pid(child)`, so it resolves exactly like `--pid`.

## 3. Window bounds

`[selection read, close read]`, both `read_bound` acquisitions on the broad
banks under the broad collection generation. The selection read runs before
the first loop tick; the close read runs in `run_terminal` right after the
broad terminal read succeeds (broad-first: existing broad error behavior is
unchanged), while banks are still live (detach is post-publication).
The close witness facts are snapshotted before stop-gate quiescence
(quiescence invalidates the PID lifecycle tap, so no later read is
possible). The witness covers the loop-frame drains; the shutdown tail —
discovery records staged during quiescence plus the terminal drain up to
Q, which bypass the terminal tap — is scanned PID-matched for an EXEC, a
leader exit or a tap fault of the selected caller (already-read records,
no new capture, no argument reads). The window is clean only when
quiescence was proven (`quiesced.is_some()`) and no post-quiescence
discovery record was consumed blind (`post_q_discovery` false); otherwise
the witness may have missed an exec and the detail voids with
`broad_stopping`. The quiesce-error path also voids with `broad_stopping`
(no provable close boundary). Accepted-read seqs are 1 (selection) and 2
(close) per the read-seq rule.

## 4. Cells per `--counter-mode`

Via the existing `render_detail_rows` / `render_cell_row` (unchanged): counts
rows carry entered/returned/errors + `rv_counts` only; timestamps rows add
`total_ns`/`max_ns`; latency rows add `buckets`. The detail row for the slot
equals the aggregate bracket's row for that slot over the same window: the
same `CounterDeltas` interval, filtered to the selected slot. `rv_counts`
always renders (possibly empty).

## 5. What voids the detail (checked in this order, first hit wins)

1. Unclean close boundary ⇒ `broad_stopping` (quiescence unproven, post-Q
   discovery consumed blind, the quiesce-error path, or real discovery
   truncation growing inside the window — the total minus the
   exit-ended scan count, including a terminal drain that stopped at
   its allowance).
2. The slot's retirement: the close plan no longer publishes the selected
   slot index with the identical `{object, file_offset}` key ⇒
   `not_published` (the word's documented meaning covers retired rows).
3. Exec of the selected caller in the window, via the broad exec witness
   over the loop-frame drains plus a PID-matched scan of the shutdown
   tail (quiescence-staged + terminal-drained records up to Q; no new
   capture, no argument reads):
   - close facts unreadable, `fault_serial` moved, or discovery ring
     loss, state failures or bounded-read failures growing inside the
     window ⇒ `promotion_caller_changed` (fail closed: continuity
     unprovable);
   - `latest_exec` moved with a hook timestamp at or after the
     selection read's monotonic **start** stamp (`started_ns`; strictly
     before it is outside the window and is ignored, a tie voids; the
     read's bounds encompass its component reads, so an exec inside the
     read could split old- and new-image calls; zero still voids), or
     an in-window tail EXEC, or a tail fault (malformed tail, outer or
     nested) ⇒ `promotion_caller_changed`;
   - a leader exit (`greatest_break_ns` moved or a tail exit) ends the
     window cleanly and renders: the counter bank's probes are bound to
     the original task, so a PID reuse cannot add counts. A
     zero-timestamp exit still voids as `promotion_caller_changed`.
     Live cells: a `--pid` target exiting in the window renders the
     calls before the exit, and so does an owned `run` child that
     exits a few seconds after loading. Exit-ended loader-scan
     truncations and exit-caused loader rejects (a zero-state scan
     that never completed, a hook address that no longer maps, a
     late record bound to the ended origin; counted apart as
     exit-only) do not void: step 1 compares the total minus that
     count, so the immediate-exit shape renders whenever its loader
     fallout is exit-only. Other loader rejects still count as real
     truncation and void as `broad_stopping`, so an immediate exit
     may still void intermittently (about 1 in 10 local runs); the
     delayed-exit cell pins the deterministic shape.
4. Capture loss/overflow in the window, via the close read and the
   collector: failed close read ⇒ `quarantined` / `budget` / else
   `broad_plan_topology`; collector `Unavailable` (saturated, contended,
   regressed, fold overflow) or `GenerationChanged` ⇒ `broad_plan_topology`.
   (Producer saturation, contention and kernel-evidence loss latch inside
   `CounterRead::validate`, so the collector is the loss detector; no
   separate loss check exists.) A torn window — any row whose `rv_counts`
   sum differs from its `returned` delta, because a call completed between
   the read's return-value pass and its slot-stats pass — also refuses as
   `broad_plan_topology`, checked over every windowed row before the slot
   filter; on a busy `--pid` target this can withhold most windows.

Any void records the named refusal on the selection record; `lineage`,
`aggregate` and `detail` stay absent and `events` stays empty. The main
report's aggregate alone carries the capture (schema wording, unchanged).

## 6. Rendered shape and gap vocabulary

Success renders, under the existing additive `selected_detail` envelope:
`selection` (endpoint, slot, file_offset, names, no refusal, never any
process identity), `events: []`, `aggregate` (`render_aggregate_bracket`
over the window, seqs 1→2) and `detail` (`render_detail_rows` filtered to
the one slot, `detail_generation` = the broad collection generation: the
cells are the broad's own). `lineage` is absent in K0 (no request/view/marks
exist to join). A zero-call window renders explicit zero rows plus the
aggregate: measured zeros over a proven window, never absence. All refusal
words are pre-existing (`endpoint_unknown`, `promotion_endpoint_ambiguous`,
`promotion_scope_unsupported`, `promotion_caller_changed`,
`promotion_caller_retired`, `not_published`, `quarantined`, `budget`,
`broad_not_counter`, `broad_plan_topology`, `broad_stopping`); absence stays
unknown, never zero.
`bundle_unavailable` is retired from production (pre-K0 seam word; kept in
the schema vocabulary so old reports still validate).

## 7. `--json` / `-o` / text parity

`profile`/`run` have no `--json` flag: the JSON report is the `-o` document,
which carries the full envelope iff `--select-endpoint` was given (detail or
named refusal; without the flag the envelope is absent entirely). Text
(stdout live frames) is unchanged: whole-capture aggregate rows only. Parity
means: (a) detail cells equal the aggregate bracket's cells for the selected
slot over the same window (same interval, same mode fields, no combined
total); (b) envelope presence ⟺ flag presence; (c) text aggregate rows and
the windowed detail derive from the same banks (no separate totals). No
`render.rs` change.

## 8. Pool (one charge)

K0 adds no counter object, no `CounterSpec`, no terminal reserve, no custody
precharge, no bank stage, no BPF object, no new pool and no new reservation
object. Both K0 reads charge the Engine's existing counter pool through
`engine.counter_reserver()` exactly like broad tick reads; the single held
selection-time read (one read-sized charge, ~rows × row bytes, sub-MiB at
512 slots) is the one additional held charge for the window, released when
the window closes. No N4-style double/triple charge exists: there is no
gate envelope, no child spec and no child stage.

## 9. Production seams (owned files + one minimal neighbor)

- `src/metrics/selected_detail_driver.rs`: K0 window open/close over
  injected reads + facts (twins) and thin production wrappers doing
  `read_bound`; ledger detail/aggregate setters.
- `src/run.rs` metrics selection path only: open before the loop, snapshot
  close facts before quiescence (the tap goes terminal in
  `quiesce_terminal`), collect the shutdown tail, close in
  `run_terminal` after the broad terminal read, void on the
  quiesce-error path.
- Neighbor (controller review): `src/attach.rs` gains a read-only
  `Session::pid_lifecycle_facts()` accessor plus a `LifecycleFacts`
  re-export (~12 lines, beside the other status readers, outside the WU-2
  start/factory and WU-5 binding regions). No other read path exists:
  `pid_lifecycle` is a private field, `facts()` is `pub(super)`, and no
  published evidence carries the witness. No `selected_detail.rs`,
  `counter_*.rs`, BPF, native, or `build.rs` change.
- P1a mailbox (`eb619780`, `e007aae0`, `d4bd3bda`): not needed by K0 (no
  promoter/lifecycle/mailbox in this path); left untouched. Its two
  `allow(dead_code)` entries (`SelectedEndpointReceipt::new`,
  `Promoter::request_with_endpoint`) exist for the now-dropped P1b mint and
  should be retired, with the mailbox code itself, in a follow-up.
