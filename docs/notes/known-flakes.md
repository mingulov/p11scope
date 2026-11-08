<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Environmental test failure signatures

These signatures were recorded in September 2026 and identify cases that
have failed intermittently under parallel suite load. Some also failed in
isolation. They are diagnostic history, not evidence that a new failure is
harmless or that the current revision passes. The
[quarantine mapping](test-quarantine.md) names the exact maintained selectors.

## Triage protocol

1. Preserve the original failed run, source revision, build profile, test
   binary, host load and error text. Do not replace a red result with a later
   green log.
2. Run the exact failing selector serially with the same binary/profile.
   Use the private disk-backed `TMPDIR` described in
   [contributor verification](../../CONTRIBUTING.md#verification). For a new
   build, use the pinned repository wrapper and prepared dependencies.
3. Compare a pristine baseline when the cause is ambiguous. A matching
   failure can establish that the regression predates the change, but a
   pass in isolation alone does not establish the cause.
4. Match the actual mechanism to the signature. Retain assertion strength,
   test inventory and bounded deadlines. Fix a demonstrated causal race;
   do not increase budgets merely to make a run green.

## Recorded signatures

| Exact selector | Target | Signature |
| --- | --- | --- |
| `lane13_evidence_finalizes_only_after_owned_cleanup` | `artifact_contracts` | Readiness/deadline race: `setup-ready-timeout`, original exited before return, or a decoy still live. This is a long-running fixture; a “running for over 60 seconds” notice alone is not failure. |
| `metadata_canary_matrix` | `artifact_contracts` | Rotating canary subtest errors under load, including `test_json_acquisition_deadline_includes_exit_after_pipe_eof` with a missing `eof-child.pid`. Preserve the failed native subtest and pidfile/custody evidence. |
| `stopped_canary_capture_lifecycle` | `artifact_contracts` | `test_owned_missing_capture` expected a phase deadline but received a readiness `CustodyError` and custody-close `CleanupError`s. Preserve both the original failure and cleanup outcome. |
| `native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup` | `artifact_contracts` | Rotating `RecordedLauncherTests` deadline, acknowledgement and cleanup failures; `pidfd-open-gone` after a recorded-launch deadline is one recorded form. |
| `actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines` | library | `Instant::now() < reap_deadline + Duration::from_millis(100)` exceeded under parallel load. The deadline is the contract; an isolated pass does not justify renewing it. |
| `release_seal_denies_the_caller_path_to_every_reached_command` | `artifact_contracts` | Missing `sealed-environment` artifacts, empty output where `sudo` was expected, and related Cargo-home/sysroot closure failures in the same run. |
| `signal_settlement_observes_second_sigint_during_fallback_term_grace` | library | Signal settlement returns `Err(Deadline)` while coordinating SIGINT/SIGTERM across threads. Retain the signal and cleanup sequence when investigating. |

The quarantine lane runs these selectors once, serially, after any failed
check job (`lint`, `audit`, `tests`, a `contracts-N` shard or `scripts`).
It is supporting evidence only: a green quarantine result
never makes the failed workflow pass.

## Live-cell signatures

These failures come from Docker live cells
(`scripts/docker-*-e2e.sh` with `scripts/container-cells-oracle.py`),
not from the Cargo suites, so they carry no test selector or
quarantine entry. The triage protocol above still applies: preserve
the failed evidence directory, rerun the exact cell serially, compare
a pristine-base run with the same selector, and match the mechanism
before calling a rerun green.

### `D1-span-flip-race` (D1 shared-layer cell, span loss gate)

- Signature: the span-kernel evidence carries a pid-less
  `maps attribution` gap,
  `processes mapping pinned provider objects were not attributed to
  them: N identity_mismatch ...` with repeats=P (observed N=2,
  P in 8..13), and the exact span gate
  (`assert not has_identity_loss(span_kernel["gaps"])`,
  `identity loss in span`) refuses it.
- Mechanism: the overlay collapse direction inverts between span
  passes (both `(98 -> 82)` and `(82 -> 98)` collapse gaps in one
  span, that order); a fraction of inverted spans also lose per-process
  attribution for pinned providers. Not yet shown to predate the
  lane: no base span has tripped, and the lane touches the
  admission path (`identity.rs` pair admission, attach-set `by_raw`
  routing), so a lane contribution is not ruled out. In every trip
  the copy-up branches are cold — `anchor_not_installed`,
  0 `pre_copy_up` markers, 0 witness-proven rows, 0 refused lower
  candidates — which bounds but does not settle the question.
- Rates (2026-11-07, dev Docker,
  `--iters-a 400 --iters-b 250 --duration 30 --span 90`): tip
  Saturday-morning 3/7 spans trip (all 7 invert); tip
  Saturday-evening 0/2 (stable direction); base Saturday 0/14
  spans trip, 3/14 invert (evening base 0/8, stable, exact parity
  with tip-evening). The R2 base spans r2-r14 ran the release
  observer (only r1 ran debug); the trip tally is exact.
- Base-hit status: A/B COMPLETE 2026-11-08 (interleaved tip/base
  release runs on the quiet fedora host, same harness fix, 10 each,
  no stop: zero trips on both lineages). All 20 spans collapse
  single-direction `[(B,A)]`; the flip did not reproduce on the quiet
  host for either lineage, so the inversion stays bound to the
  dev-morning conditions and is still not shown to predate the lane.
  Base totals 0/24 trips (R2 0/14 + R3 A/B 0/10). The batch verdicts
  differ for two separate reasons, neither a loss trip: base drops
  B-pre's new-module span edge 10/10 (`original_file_unproven`: the
  witness proved another file) while tip keeps it 10/10; an entries
  race (`watched_no_use` with 0 entries on B2's edge while the span
  profile counts 6x250) fails tip 3/10 in R3 A/B (base B2 edges read
  the same state structurally — no pair — not the race; see
  `D1-span-b2-entries-race`). Both need their own records.
- Disposition: named flake; the span gate stays exact. A rerun that
  trips must be preserved and retried serially, never averaged away.
  Future work (out of scope): collapse-order determinism across span
  passes.

### `D1-span-base-drops-stale-edge` (R3 A/B, base pre-lane behavior)

- Signature: base span-kernel edges B-pre to the old module only;
  the new-module edge is missing and the span gate refuses
  (`B-pre stale edge`, got None). B-pre carries
  `original_file_unproven: the kernel witness proved another file`.
- Mechanism: base 5fd133239 predates the lane's lower-file join;
  B-pre keeps the pre-lane `original_file_unproven` gap, so the
  lane-written span gate refuses on base by construction —
  expected, not a flake or regression. R3 A/B: base 0/10 keep the
  edge, tip 10/10 keep it. Recorded so a future base rerun is
  judged against this systematic difference, not averaged with tip.
- Disposition: documents the pre-lane base behavior; no gate change.

### `D1-span-b2-entries-race` (tip-only; R3 A/B 3/10, R6 1/20; root-caused and fixed in R7)

- Signature: B2's span-kernel edge shows `watched_no_use` with 0
  entries (observed across the whole span) while the span profile
  counts the full 6x250 fresh ledger on the same module; the span
  gate wants `not_attached` and refuses.
- Mechanism: joint same-pass fresh admission (root-caused R7), not a
  torn digest. The twin-start scan (pass 6) sometimes observes the
  pre AND the plain side of the pair in ONE pass under the empty key
  0:84; each resolves Fresh-by-content (by_raw empty, so the
  pair-proof gate never runs) and both admit — B2's mapping gets
  endpoints and the edge attaches mid-span. Passes that land pre in
  pass 6 refuse the plain side from pass 7 on
  (blocked-no-companion, same digest). This explains every R6
  discriminator (shared first_seen, refusal-free 68-endpoint
  admission, same final sha256, module-wide flip). The torn-digest
  lead is refuted: production hash sites reject digests whose pin
  changed mid-hash, T1-tight shows 0/50000 same-tick stable pins on
  the D1 stack, a product-faithful `cat`-shape race shows zero torn
  full-size reads, and no digest besides 8453e1 appears in any
  campaign. (R3 A/B: tip 3/10; base B2 edges read the same state
  10/10 but structurally — no pair — not the race.) Pass timing
  identical to passing runs (B2 ready at passes 6,7; ledger at 8,9).
  R5 analysis of the R3 `ab-spans` narrows it: on the tripped tips
  (3,4,6) all three edges on B2's module (B-pre, twin, B2) are
  `watched_no_use`, while on passing tips all three are
  `not_attached` — the flip is module-wide, not B2-specific. R6 adds
  B2/twin ledger start/end monotonic stamps to `facts.log`, and the
  oracle now proves calls-before-watch on every trip (refusal
  message).
- R6 measurement (quiet fedora, exclusive lane, tip `03f8182c4`,
  R3 A/B flags): 1/20 trips (run-10; combined with R3: 4/30).
  Run-10's oracle message proves calls-before-watch (B2's ledger
  ended 10.4 s before the edge's `since_ns`; the twin's 10.3 s):
  the refused 0 counts are honest output, not missed observations.
  Two discriminators hold 30/30 (R3 10 + R6 20): trips have one
  shared edge `first_seen` (joint split-discovery admission) while
  passes have two, and trips carry a refusal-free module admission
  (68 endpoints, no reasons) while passes disclose a later
  "no proven companion" refusal. A scratch attach-set experiment
  (not committed) shows a mid-copy divergent digest would admit a
  companion and that same-digest pairs refuse in both plan orders,
  but the live premises (a torn mid-copy hash; the lower pin
  equaling the pre-copy-up merged pin) and the link to B2's
  arrival timing are unproven. Next: capture per-pass attach
  verdicts for the pair module on a tripped run.
- R7 fix and measurement (quiet fedora, exclusive lane, R3 A/B
  flags): before (diagnostic build `051a165c9`): 5/20 FAIL, all 5
  with a surviving pass-6 joint fresh on 0:84 (runs 8, 11, 15-17)
  and none of the 15 PASS runs with one — 5/5 joint trips, 0/15
  otherwise. Fix: post-resolve joint arbitration refuses the plain
  side exactly like sequential passes do, whichever plan order it
  resolved in, recalling its premature fresh note (`c71cc3b98`),
  with same-key verdict merging so the admission stands beside the
  disclosed refusal (`4a7cb54b1`; arbitration alone regressed
  after-1 to module-refused, so the two ship together). After
  (complete fix `4a7cb54b1`): 10/20 runs drew a joint landing and
  all 10 arbitrated (pass 6: one fresh pre=y plus
  blocked-no-companion pre=n, module admitted with 68 endpoints) —
  0/10 joint trips, 19/20 PASS; the one FAIL is the unrelated
  in-place-truncation shape below. Joint detection is fresh pre=y
  plus blocked-no-companion pre=n in one pass: the arbitration
  recalls the plain fresh note, so a surviving-note detector is
  blind to handled joints by construction.
- Disposition: fixed and live-verified; the span gate stays exact.
  The R6 D1 blocker is closed. Remaining joint corner (pre-existing,
  out of scope, never observed): divergent digests with no pre/plain
  split admitted jointly stay both-Fresh and converge next pass via
  the changed mark.

### `D1-after-5-in-place-truncation` (counted known issue; 1/20 in the R7 after-campaign)

- Signature: the oracle's single-module assert finds TWO records with
  B's key — m3 admitted 8453e1 plus a stale m2 `unresolved`,
  identity sha null, `unloaded_observed`. Unique across all R7 D1
  evidence: gaps `not parseable as an ELF object: Could not read
  file magic` (c245) and `module has no comparable pinned identity`
  (c226, c245). m2 (0:84) is seen at a single instant, one pass
  after m1's last sighting and one pass before m3; its pass-6 joint
  landing arbitrates normally, so this FAIL is not a joint trip.
- Mechanism: the pass-5 scan read B's merged path while the harness
  rewrote the file in place (`cp` then `cat /tmp/p > "$p"`
  truncates the upper copy and refills it,
  `scripts/docker-shared-layer-e2e.sh:1142`). That pass's object had
  no digest, so the attach set never judged it; the fix acts from
  pass 6, so it can neither cause nor prevent this. Product output
  is honest: the record stays unresolved, the gaps are disclosed,
  its edges are single-instant, and nothing attaches.
- Disposition: counted campaign FAIL, shipped as a known issue. The
  harness rewrite stays as is (a real in-place rewrite shape); the
  product follow-up (fold an undigested record into the same-key
  digested record) is 0.7.x work. Do not loosen the oracle.
