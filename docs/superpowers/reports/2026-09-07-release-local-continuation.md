<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Initial release continuation — local qualification

The owner resumed the initial-release goal on 2026-09-07, authorizing execution,
testing and privileged work, while excluding tagging, pushing and publication.
**Run CI tests locally.** This instruction supersedes the hosted-run acceptance
requirement in the release PRD and W4/W8 charter for this goal. It does not waive
the actual tests, runtime qualification, receipt, bundle or independent review.

The owner subsequently permitted deferring support for different target ABIs.
The initial release is x86-64 host/target; W7 is follow-up work, not an initial
release gate. A small fix making the existing ELF refusal truthful continues.

## Verified starting point

`main` was `25c43358e595dc31094b90e8f2700a42b82309fd`. Existing changes under
`.codex/` belong to the owner and are preserved. Continuation work uses the
isolated `hardening/release-local` branch at `.claude/worktrees/w7-ia32`
(the directory was created before the ABI deferral).

Fresh local results on that starting source:

| Check | Result |
| --- | --- |
| `cargo +1.88 fmt --all -- --check` | PASS |
| `cargo +1.88 check --locked --workspace --all-targets` | PASS |
| `cargo +1.88 test --locked --workspace --all-targets` | PASS: 1,105 tests across 22 test binaries, zero failed/ignored |
| `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings` | PASS |
| Every `--self-test` step in `.github/workflows/ci.yml` | PASS: 20 steps |
| Diagnostic `frozen_policy_inventory_matches_embedded_object` test | PASS: exactly one test; 17 maps, 17 programs |
| `scripts/verify-inspect-doctor.sh` | PASS |
| `scripts/verify-attach-e2e.sh` | PASS on default temporary-root rerun: scan and manifest lanes, 136/136 probes each, both lane oracles passed |

Private logs are retained under
`/home/user/src/m/p11scope-ws/incoming/2026-09-07-release-local/`.
The first attach attempt used that directory as the capture output
root, but `/home/user/src` is group-writable. The output guard correctly refused
it. Runtime output must first use the lane's private temporary directory and
then be copied into durable custody; ancestor permissions are not weakened.

## Remaining acceptance work

This is a gap inventory, not a release acceptance receipt. Earlier runtime
results do not qualify a later candidate.

| Requirement | Current evidence and next gate |
| --- | --- |
| W1/W3 fixes and final independent review | Existing fixes are integrated; final program-wide review-to-zero remains required |
| Local CI equivalent | Baseline rows above; rerun against the final integrated candidate |
| ia32 observation on x86-64 | Deferred by owner; retain truthful unsupported-ABI refusal |
| Rate/loss oracle | Existing induced-gap lane proves nonzero loss, but does not establish the required generator/STATS/raw-CALL equality and exact-loss comparison |
| Combined lifecycle oracle | Required fork/exec/dlopen/calls/dlclose/path-replacement/reload/retirement scenario has no verified combined implementation |
| Docker/kind/Knative and proxy stack | Existing scripts need final-candidate execution; a proxy lane SKIP with exit zero is not qualification |
| Runtime security artifacts | W5 seccomp profile and SELinux policy artifacts and their verification remain required |
| Kernel/distro matrix | Execute final candidate on required x86-64 cells; preserve exact kernels and actual PASS/FAIL/UNRUN results |
| Storage custody | Retain new evidence in `p11scope-ws`; verify final bundle and referenced evidence closure |
| Public claims and Lane 14 receipt | Final documentation truth pass and literal release-capture receipt remain required |
| Ready-to-publish bundle | Build, checksum, freshly extract and verify; publication stays excluded |

## Deferred ABI design evidence

Independent read-only review checked the charter against the starting source.
The planner is `src/plan.rs`, not `src/discovery/plan.rs`. ELF ABI admission
must check class, machine and little-endian encoding together, rejecting x32
and foreign architectures. Native `pkcs11_module` field offsets and pointer
reads cannot be applied directly to ia32 bytes.

Static cookies may reserve bit 63 only after masking it from the descriptor.
Export cookies, full-width selection IDs, and signed loader-delta cookies are
different domains; that tag must never be added indiscriminately. ia32 return
values must be zero-extended from the low 32 bits before error/RV accounting.
ABI authority belongs to each exact pinned attach target, including dependency
objects, rather than to the table publisher or a process-wide cached guess.

Close the misleading owned-command ELF diagnostic while retaining the current
ELF32 refusal. Future W7 implementation must be coherent across scan and
capture: merely accepting ELF32 is unsafe. Its previous minimum scope deferred
ia32 loader/export/selection paths, so it did not establish full ia32 live
compatibility. Reconsider that split when W7 resumes: a width-aware loader
state-field offset may be simpler than a separate export lifecycle.

Continue with the two product oracles, W5/W6 qualification and W8 assembly.
The initial-release goal stays active under the owner's amended ABI scope.
