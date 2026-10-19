<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# G26 runbook — preserve accepted H0/H1/H2 foundations through integration

Rerun existing tests at affected integration boundaries; do NOT reimplement
completed milestones. Base `fabbb0a4`; enumerate exact names on the
converged candidate (names drift; zero-match proves nothing).

## Enumeration-first commands (from the product root)

```sh
export TMPDIR=/var/tmp/p11scope-ws-tmp CARGO_BUILD_JOBS=2
# 1. List, then confirm each expected name exists exactly once:
mise exec -- ./scripts/cargo.sh +1.98.1 test --locked --lib -- --list 2>/dev/null | grep -E "refresh_|retained_fairness|full_image|audit_before_route|pending_stop" | sort | uniq -c | sort -rn | head -40
# 2. Run each confirmed full name exactly:
mise exec -- ./scripts/cargo.sh +1.98.1 test --locked --lib <full::test::name> -- --exact --nocapture
```

## What to enumerate (catalogue map at base)

- H0 (`src/semantic_capture.rs`, full-image/audit/stop tests): nonempty
  full-image positive; same-cookie successor vs permanent task death;
  foreign domain, old fence, fault overflow, audit-before-route;
  pending stop once. H0's historical four live cells keep original scope.
- H1 (engine/instance refresh + retained/newcomer fairness): the eight
  existing `refresh_*`/retained-fairness tests named in the H1 plan —
  new/same-PID refresh, first-seen age, unique serials, failed-clock
  ordering, retained/newcomer attempts. NOTE: the catalogue's
  `src/scheduler.rs` path does not exist at base; enumerate the live
  paths (`src/discovery/engine_tests.rs`,
  `src/discovery/instances_tests.rs`) instead and record the mapping.
- H2 (identity/projection/diff incl. `src/s1_tests.rs`,
  `inventory_diff/{compare_tests,input_tests}.rs`): separate equal
  handles/router IDs, idempotent registration, unchanged physical
  totals, unknown unrouted inputs, capacity refusal, redacted equal
  consumer projections.
- Failure twins to keep green alongside: restamped old proof, cleared
  newer request on older completion, reused exhausted serial, double-fed
  instance call in physical totals; healthy-sibling assertions rule out
  blanket refusal.

## Triggers and recording

- T2/T3/T5/T7 changes trigger affected H0/H1/H2 controls; H5 service and
  H3 installed acceptance stay separate rows.
- Record per row: implemented test names, command/selection, source SHA,
  execution layer, positive population, refusal/mutation result,
  remaining limitation. No blanket H0-H3 DONE label.
