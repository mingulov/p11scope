<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T2 capacity-feasibility receipt (2026-09-26)

Finish-plan Task 2 box 5 input to the capacity consensus. This receipt
feeds evidence; it does not fork the T7 decision
(`docs/qualification/capacity-decision-T7.md`): identity A selected,
appended segments as the growth hypothesis, live cells L-T7-7..L-T7-10
still owed. Scope: ordinary evidence only, produced unprivileged at T2
BASE (`7b92cdd`) plus the T2 stack.

## T2 feasibility evidence bearing on capacity

- First-use cold start is feasible with no ambient credentials
  (`tests/t2_cold_start.rs` 6/6, `system-first-use.md` T2-C1/C6): the
  capacity live cells need no credential or state-directory fixture
  beyond privilege itself.
- Extra-strict refusal (`doctor --extra-strict`) is the machine-readable
  qualification gate for those cells: any Warn/Fail lane row refuses
  with named rows (L-T2-3 expects exit 0 on a fully capable host).
- Authoritative observer phase stamps (`phase_mono_ns`) are now emitted
  by both capture loops and accepted by the oracle, schema, and measure
  harness: soak/capacity runs can attribute tick latency to
  attach/loop-start/loop-end instead of FD estimates.
- Deep-freeze long-run detector (`src/longrun.rs`, 11 unit tests):
  tick-over-budget (1,895 ms forced-sweep max), stall gap (10 s bound),
  and first-drain loss splits (ramp-up vs steady state). Pure and
  soak-ready; loop wiring + soak validation are controller-owned
  (L-T2-4 in the T2 report).

## Dated findings

| ID | Date | Finding |
|---|---|---|
| T2-F1 | 2026-09-26 | FEASIBLE: T2's ordinary half of the capacity evidence (cold start, extra-strict gate, phase stamps, detector) is implemented and green. No capacity-feasibility blocker found in T2 scope. |
| T2-F2 | 2026-09-26 | BLOCKED (owned elsewhere): T2-C5's ungated never-seen transient is an accepted-boundary proposal pending live cell L-T2-2; capacity cells that churn short-lived lifetimes inherit that boundary until the finish review decides. |
| T2-F3 | 2026-09-26 | OPEN: the 6530 dense byte envelope and paired RV/caller growth stay live-only (T7 open uncertainties 1-2); T2 adds no new evidence for or against. |

## Consensus input

T2 concurs with the T7 record and adds no competing design: the
long-run failure modes that could hide behind a passing capture
verdict (slow ticks, drain stalls, ramp-up loss) now have a named
detector with fixed thresholds, so the capacity live cells can cite
`p11scope: longrun:` lines as their long-runtime evidence.
