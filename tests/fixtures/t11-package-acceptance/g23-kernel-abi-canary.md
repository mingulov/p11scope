<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# G23 runbook — kernel, ABI and complete canary release intersection

Final affected-object acceptance, not H7-relative parity. Base
`fabbb0a4`; re-verify selectors on the converged candidate.

## What exists

- Canary gate: `scripts/verify-canaries.sh` (G3 hostile pointer aliases,
  `--self-test` for hermetic checks), `scripts/check-canary-evidence.py`,
  `scripts/check-capture-evidence.py`, suites `test_canary_evidence.py`
  (32+64 target bits), `test_canary_object.py`, `test_canary_workload.py`,
  `test_task_storage_canary.py`, `test_stopped_canary_capture.py`.
- `test_image_map_flag_validation_preserves_protection` EXISTS in
  `tests/python/test_stopped_canary_capture.py` (G23's first proposed test).
- ia32: `scripts/matrix/verify-ia32-compat.sh`,
  `scripts/matrix/ia32-compat-harness.c`,
  `scripts/matrix/ia32-compat-trace-exec.c`, `test_ia32_automatic_exec.py`,
  `test_ia32_lifecycle.py`.
- Release matrix: `scripts/qualify-release-matrix.sh` (+ `--self-test`,
  `--preflight`, `--dry-run`), `scripts/release-matrix-contract.py`,
  `docs/qualification/release-matrix.md`, 62-test
  `tests/python/test_release_matrix_contract.py`.
- Registered lanes: 5.15.221, 6.1.188, 6.6.157, Ubuntu 6.8.0-142-generic,
  6.12.111, 7.2.6, host. Dev-host vng caches hold all of these plus
  extras (checked 2026-10-19; recheck before the campaign).

## Exact commands (from the product root)

```sh
# Hermetic checker behavior only (no guest, no privilege):
scripts/qualify-release-matrix.sh --self-test
scripts/qualify-release-matrix.sh --dry-run
python3 -I scripts/release-matrix-contract.py --plan --lane 6.1.188
scripts/verify-canaries.sh --self-test

# Host readiness before any guest lane:
scripts/qualify-release-matrix.sh --preflight

# Per-kernel campaign (privileged lane, one guest at a time, internal flock;
# DO NOT wrap in an outer flock of /var/tmp/p11scope-ws-tmp/privileged.lock):
TMPDIR=/var/tmp/p11scope-ws-tmp scripts/qualify-release-matrix.sh --rev <CANDIDATE_SHA>
TMPDIR=/var/tmp/p11scope-ws-tmp scripts/qualify-release-matrix.sh --bin-dir <DIR> --rev <CANDIDATE_SHA> --kernels "v5.15.221 v6.1.188"

# ia32 compat cell and uretprobe/seccomp probe selection:
scripts/matrix/verify-ia32-compat.sh --help 2>&1 | head -30   # confirm CLI first
scripts/matrix/verify-uretprobe-seccomp.sh                     # RESULT: verdict or unknown
```

## Expected artifacts

- `OUT_BASE/<rev>/summary.md` under `/var/tmp/p11scope-ws-tmp/rc-qualify/`
  plus raw per-kernel logs; sealed `contract.json` per stage with
  `guest_exit: 0` and `evidence_sha256`.
- Judge verdicts per row id; `identity:5.15-denied` is currently
  `nonqualifying`/`unready` (see gap 1) and must NOT be read as PASS.
- Canary scanner positive controls must still detect the seeded forbidden
  neighbor; zero-call runs and unsupported/UNRUN rows never qualify.

## Gaps for live T11 (owning lanes, not this prep)

1. `privileged_identity_515_denial_is_disclosed` does NOT exist. G23
   requires an executable native-suite test proving real identity denial /
   fallback on 5.15; the contract today hard-codes the unready row at
   `scripts/release-matrix-contract.py` near `identity:5.15-denied`.
   Owner: native/identity lane (B); needs exact `--list` curation first.
2. Complete all affected live canary paths after the checker is corrected;
   existing canary self-tests do not substitute for full live completion.
   Select exact affected cells from the platform plans; missing hosts stay
   open or need an explicit owner scope decision.
3. Nonempty ia32 operations/attributes plus refusal controls (not idle
   attach); live seccomp/namespace/overlay checks affected by source
   changes must be re-selected after T2/T5/T6 stabilize.
