# Fault-Race CI Failure Report: v060 RC1

**Generated**: 2026-11-06 11:30:23 UTC
**Status**: ✅ success
**Version**: v060 RC1 (e2fd74b67) → task/v060-fault-race
**Workflow**: bugs
**Phase**: verification
**Branch**: task/v060-fault-race (from task/v060-rc 40808c51e)
**CI Run**: 42181206640 (`tmp/ci/v060/rc`, `ci.yml`, job `tests`)

---

## Executive Summary

The RC1 `tests` failure (`competing_fault_writers_never_reopen_an_exhausted_era`,
2 of 3 writers succeeded, expected exactly 1) is a stale test assertion, not a
production bug. The raise contract changed in d845e4be0 — a CAS lost to another
raiser now succeeds with the winner's value instead of retrying — but the
competing-writers test still asserted the old exactly-one-winner behavior. The
fix updates the test to the current contract. No production code changed.

## Root Cause

`raise_fault_with_won` (src/attach/instance.rs) returns `Ok(current, false)`
when its compare-and-swap loses to a raiser that already moved the cell past
the value read (`Err(current) if current > seen`). This piggyback success is
intentional: a raise only needs the generation to advance, and it avoids a
retry storm under BPF/userspace contention. It is pinned by
`a_raise_lost_to_other_raisers_still_succeeds` and consumed via the `won` flag
by the hook-miss audit (3ff6021be), which counts only swaps a raise won itself
when naming a miss era.

With the cell at `MAX-1` and three racing writers:

- the CAS winner reports `Ok((MAX, true))`;
- each loser that loaded `MAX-1` reports `Ok((MAX, false))` without touching
  the cell, instead of retrying into exhaustion as the pre-d845e4be0 code did;
- only a writer that loads `MAX` after the win attempts `MAX → MAX+1`, refuses,
  and installs the sentinel.

So the `Ok` count is 1–3 depending on interleaving (CI saw 2; local sampling
saw mostly 2, sometimes 3), and the settled cell is `MAX` or `MAX+1`. The test
asserted exactly 1 success and cell `== MAX+1`, i.e. the superseded
retry-then-exhaust contract from 24bd92330. History (`git log -S`):

- 24bd92330 introduced the cell with retry-on-loss and the exactly-one test;
- d845e4be0 changed loss to immediate piggyback success (test not updated);
- 3ff6021be added the `won` flag the fix now asserts on.

Two writers both reporting `Ok(MAX)` is therefore correct behavior: both
observed the generation advance to `MAX`; the era is never reopened (the cell
only moves `MAX-1 → MAX → MAX+1`, reported values are always `MAX`).

## Fix

Test-only change in `fault_raise_tests::competing_fault_writers_…`
(src/attach/instance.rs). Writers now call `raise_fault_cell_won` and the test
asserts the deterministic consequences of the current contract:

- exactly one `Ok((_, true))` — only one CAS `MAX-1 → MAX` can win;
- every `Ok` reports `u32::MAX` — no unrepresentable generation is ever
  returned as raised;
- the settled cell is `MAX` or `MAX+1` — never wrapped or reopened;
- one further `raise_fault_cell` refuses and the cell is then exactly `MAX+1`
  (from `MAX` it installs the sentinel while refusing; from the sentinel it
  refuses without moving).

## Verification

Focused module `attach::instance::fault_raise_tests`: 7/7 pass after the fix.
`fmt --all -- --check` clean; `clippy -p p11scope --lib --tests` exit 0.

Stress counts for the fixed test (binary
`target/debug/deps/p11scope-137965aaa147a734`):

| Run | Result |
| --- | --- |
| Before fix, serial `--exact` × 2000 | pass=375 fail=1625 |
| Before fix, failure shape (60-sample) | all at the count assert; Ok-count 2 (mostly) or 3 |
| After fix, serial `--exact` × 2000 | pass=2000 fail=0 |
| After fix, `taskset -c 0` × 500 | pass=500 fail=0 |
| After fix, 12-way parallel × 500 (loaded host) | 500 PASS, 0 FAIL |

No retry-until-green, no timeouts added. The stress script is a throwaway probe
(`/tmp/stress-fault-race.sh`, not committed); the updated in-repo test is the
regression coverage.
