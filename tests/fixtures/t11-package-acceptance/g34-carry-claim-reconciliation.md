<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# G34 runbook — carry, selector, measurement-oracle, claim-policy reconciliation

Account for 433 source-qualified occurrences, 147 public ledger rows and
43 U/G groups WITHOUT treating them as distinct fresh defects. Base
`fabbb0a4`.

## Policy inputs (frozen routing inputs, not verdicts)

- `tests/fixtures/system-qualification/closure-ledger.json`: 147 finding
  policies (stable ids, dispositions, task owners, required checks).
- `tests/fixtures/system-qualification/system-deferred-gates.json`: 43
  gate groups incl. two explicitly optional groups.
- `tests/fixtures/system-qualification/system-test-manifest.json`: 214-cell
  register, every cell `NOT_RUN`; seven cells retain registered selectors.
- `tests/fixtures/system-qualification/system-bounded-scope.json`: 80 IN /
  122 OUT with reason, owning campaign, move-IN condition. STATUS at base:
  `proposed-for-owner-approval`. No cell moves IN without a catalog edit
  plus owner approval; placeholder-kernel cells stay required for
  system-product (bounded OUT comes only from this catalog, never from
  metadata inference).
- Guide: `docs/qualification/system-test-manifest.md` (`STRUCTURE_VALID`
  vs a qualified claim). Ledger bindings: `ledger_sha256`,
  `deferred_sha256`, `bounded_scope_sha256` inside the manifest.

## Exact commands (from the product root)

```sh
# Structure + mutation checks (unprivileged, T1 first):
python3 -I tests/python/test_system_test_manifest.py -v
python3 -I scripts/verify-system-test-manifest.py --help 2>&1 | head -30
python3 -I scripts/run-python-suites.py test_system_test_manifest.py test_release_matrix_contract.py test_bench_count_overhead.py
python3 -I scripts/run-python-suites.py --check   # before every remote push

# M2 validity spine (G34 repairs are prerequisites to T10 interpretation):
python3 -I tests/python/test_bench_count_overhead.py -v
```

## What exists vs what is missing

- EXISTS: `bounded_claim_cannot_pass_full_system_product` (in
  `test_system_test_manifest.py`), `count_overhead_rejects_missing_counts_and_rounds`
  (in `test_bench_count_overhead.py`).
- MISSING: `required_positive_rejects_skipped_selector`. G34 requires a
  test proving missing/duplicate/zero-match/ignored/refusal cells FAIL a
  positive-required row (a skipped selector must never pass). Owner:
  tooling lane (D); specify exact skipped-selector fixtures (deleted cell,
  refusal promoted to positive, shortened soak, `None == None` count
  exactness, omitted rounds / scrambled ABBA, demotion bounds failing
  open, one disabled registered suite / ignored-live selector) and keep
  registration in the same patch if a new suite file is added.
- Live reconciliation checklist: reviewed exact membership for full
  system-product vs any owner-approved bounded claim (30m alone never
  qualifies a full 4h/24h claim); replace concrete-matrix placeholders
  before positive acceptance; reconcile obsolete U-01/U-21 archive
  requirements under AGENTS while retaining product integrity;
  A:DR-T3A-9/10 demotion anchors/bounds/malformed subjects; A:DR-T3A-13
  real non-null independent count denominators, intended cells, >=10
  paired M2 rounds, ABBA labels; A:DR-T3A-14 synchronized fixture go/stop;
  inventory all current ignored bodies and Lane13 BPF assertions; preserve
  fixed G13 kernel enumeration, DR-55 child cleanup, F-62 registration.
