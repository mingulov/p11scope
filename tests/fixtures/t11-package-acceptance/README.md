<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T11 package/claims/carries acceptance preparation (lane D)

PREPARATION ONLY. New disjoint files, no production behavior changes, no
shared-file edits, no runner registrations. Live T11 acceptance runs on the
converged candidate under the controller; this directory only surveys the
current state, records per-gate runbooks with exact commands, and names the
gaps the live campaign must still close.

- Base: `fabbb0a4` (`fabbb0a481c332c5f588fa3db793e65c0c20d121`),
  branch `prep/v040-t11-package`, worktree `.worktrees/v040-t11prep`.
- Scope: T11 installed/package/claims/carries, gates
  G23/G25/G26/G32/G33/G34. Gate text is authoritative in the
  regression catalogue
  (`docs/superpowers/plans/2026-10-15-v040-regression-test-plan.md` in the
  private planning checkout); task text in Task 11 of the release
  completion plan. Product paths below are relative to the product root.
  All product paths below are relative to the product checkout.
- Self-check: `sh tests/fixtures/t11-package-acceptance/check.sh`
  (read-only, no Cargo, no privilege, no network).

## File index

| File | Contents |
| --- | --- |
| `g23-kernel-abi-canary.md` | Kernel/ABI/canary runbook: lanes, canary tools, missing 5.15 denial selector |
| `g25-ci-package-recipient.md` | CI/package/recipient/docs runbook: jobs, build/package/export, doc freshness |
| `g26-foundations.md` | H0/H1/H2 preservation runbook: enumeration-first rerun list |
| `g32-policy-safety-stop.md` | Policy/safety/privilege/stop/sink runbook: matrix, freeze, seccomp, E17 |
| `g33-providers-browsers-deployment.md` | Providers/browsers/deployment runbook: matrix scripts, browser gap, guest gate |
| `g34-carry-claim-reconciliation.md` | Carry/selector/claim-policy runbook: manifest, ledger, bounded scope |
| `carry-coverage-matrix.md` | Carry families x gate x producer x status x live need |
| `package-recipient-checklist.md` | Clean-recipient verification checklist with exact commands |
| `check.sh` | Isolated drift check over every referenced path/command |

## Gap survey summary (at base)

Explained per gate in its runbook; the load-bearing gaps are:

1. **G23:** `privileged_identity_515_denial_is_disclosed` does not exist.
   `scripts/release-matrix-contract.py` still judges `identity:5.15-denied`
   as `nonqualifying`/`unready` with "no real executable guest refusal
   selector". Full live completion of affected canary paths is open.
   (`test_image_map_flag_validation_preserves_protection` EXISTS in
   `tests/python/test_stopped_canary_capture.py`.)
2. **G25:** `test_release_recipient_uses_selected_binary` does not exist.
   `RELEASING.md` still walks through v0.2.0; `CHANGELOG.md` has no
   `## [Unreleased]` v0.4 section. BPF baseline reconciliation
   (`e2961e08` CI vs `ca3a181` runbook) is a live-candidate step.
3. **G26:** no new tests needed, but the catalogue names
   `src/scheduler.rs`, which does not exist at base (rerun list must be
   re-enumerated; see runbook). Rerun triggers on T2/T3/T5/T7 changes.
4. **G32:** E17 ring x sink x stage matrix and valid freeze EPERM pairs
   need exact enumeration on the candidate; privmin/helper-sandbox/license
   and parked-platform owner decisions need explicit reconciliation.
   G21 root-owned FAIL persists on the operator lane (separate lane).
5. **G33:** no Firefox/NSS or Chrome application check exists anywhere
   in the product checkout (only incidental unit-test path strings). The packaged 7.0 guest
   12-cell public-command gate exists only as host-side generated-guest
   coverage in `test_release_matrix_contract.py`. Advertised-kernel/
   backport/SELinux claim membership needs the owner scope decision.
6. **G34:** `required_positive_rejects_skipped_selector` does not exist.
   (`count_overhead_rejects_missing_counts_and_rounds` and
   `bounded_claim_cannot_pass_full_system_product` EXIST.)
   `system-bounded-scope.json` is still `proposed-for-owner-approval`.
   Whole-plan D/C/A + R/E/F reconciliation is a live manual step.

Missing proposed tests belong to owning lanes (A/B/D) with registration in
the same patch; this prep lane specifies them exactly but implements none.

## What live T11 acceptance still needs

Hosts: dev host (packaging, recipient, unprivileged gates), quiet
BPF-capable host for privileged qualification, vng guests
(5.15.221/6.1.188/6.6.157/6.8.0-142/6.12.111/7.2.6 + host lane; kernel
caches present on the dev host), Fedora for compatible cells, container
hosts for Docker/kind/Knative lanes, musl host/container for the musl
helper smoke. Full Stage5 stays owner-manual.

Artifacts: frozen candidate SHA, green exact-SHA CI run URL, release
receipt (`facts.log` with `terminal_status`/`checker_status` 0), four
versioned tarballs + top-level `RELEASE.json` + `SHA256SUMS`, source
export, per-lane evidence with binary SHA-256 bindings, executed-cell
register (never zero-match/skipped-as-pass).

Order: T1/G34 oracle-validity repairs first; converge T4-T9; freeze
candidate; exact-SHA CI; privileged/source qualification; build/package;
recipient verification; installed artifact-specific qualification on
`work/dist/` bytes; carry/claim reconciliation; T12 review. Any later
source change restarts affected gates on the new SHA.
