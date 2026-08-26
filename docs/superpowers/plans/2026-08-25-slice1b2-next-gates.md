# Slice 1b-2 Gate Closure and Runtime Campaign Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Land the already-reviewed Slice 1b-2 fix6 documentation/validator delta, close the remaining gate-contract and runtime evidence gaps, and reach a fresh, independently reviewed runtime campaign without overstating UNRUN or artifact-only evidence.

**Architecture:** Keep production Rust/BPF/privacy/schema behavior frozen during the next gate round. First land the exact five-file reviewed delta at the current implementation tip. Then express the already-specified lane-13 contract directly—manifest-only discovery plus exactly one shared-overlay uncertainty and zero unavailable-discovery records—and run fresh current-tip evidence with durable resolved-input identities. Historical A/B attribution remains an optional diagnostic, not a prerequisite for present product acceptance. Wire the capability-tier validator into the existing gate/CI contract, obtain an independent Sol review, and only then create a new frozen-input root for the serial 9.2d campaign. VM campaign work remains a separate privileged/non-production stage.

**Tech Stack:** Rust 1.88, edition 2024, Linux x86-64-first; Bash gate scripts; Python artifact-contract checks; Docker/Kind/Knative where already authorized; KVM/VM/sudo only at the separately authorized campaign stage.

## Global Constraints

- Work only in `/home/user/src/m/pkcs11-scope/.claude/worktrees/slice1b2-finish`.
- Preserve unrelated tracked edits, `.codex/`, `docs/privacy/allowlist-v1.md`, historical r2 evidence, and generated-output boundaries.
- Do not update the public README status until the later Task 10 closeout and exact-tip CI evidence.
- Do not touch production Rust, BPF, privacy policy, schema, or allowlist files during the gate round.
- Do not push, tag, publish, or run unapproved privileged/container/VM experiments.
- Treat missing capabilities, missing harnesses, missing VM inputs, and blocked workflows as UNRUN or blocked; never as a no-findings or product-pass claim.
- Use Luna for narrow searches and focused checks, Terra for one contained implementation only if needed, and Sol xhigh for architecture/failure-path review and independent review. Keep one writer per overlapping file set and start review only after that writer stops.

## Task 1: Land the exact reviewed fix6 delta

- [x] Historical prerequisite completed: the exact reviewed five-file fix6
  delta was landed additively as `cb089b0fe2975abbe2f0684bec8a558e05c75ba5`;
  current Task 4 HEAD `24af62031c609cf546797d96fc20517d13f1f292`
  descends from it. The following bullets record the completed procedure and
  must not be re-executed against the stale `2494fa9` premise.
- [x] Reconfirm branch, then-HEAD `2494fa9`, worktree status, and the exact five tracked files currently modified:
  - `docs/notes/phase4-privileges.md`
  - `docs/notes/phase5-unsupported.md`
  - `docs/superpowers/plans/ROADMAP.md`
  - `docs/usage.md`
  - `scripts/verify-capability-tier.sh`
- [x] Review the complete diff and verify that `.codex/` and unrelated edits are untouched.
- [x] Run the repository checks required by `AGENTS.md`:

```
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

- [x] Run `scripts/verify-capability-tier.sh --self-test`, shell syntax checks, and `git diff --check`.
- [x] Create one local commit containing only this exact reviewed five-file delta. Do not push.

## Task 2: Refresh the continuation record

- [x] Replace the stale ignored `NEXT-SESSION-HANDOFF.md` with the current HEAD, completed fix5b/fix5c/fix6 status, the five-file landing result, and the next gate-round resume point.
- [x] Append the landing and gate brief to `.superpowers/sdd/2026-08-19-slice1b2-production/progress.md` without rewriting historical 9.2c evidence.
- [x] Record that the current root-backed attach and owned healthy-run evidence is artifact-only for planning until the next fresh gate round; do not promote it to final campaign evidence.

## Task 3: Close the historical discriminator and select the current-product path

- [x] Capture fresh, read-only identity for Docker, Kind, Knative, and shared-layer inputs and compare it with the 9.2c record.
- [x] Classify the historical discriminator `UNVERIFIABLE`: the old record lacks material node/runtime/release/tool identities, so no current control can establish an unchanged historical environment.
- [x] Reject the unfinished generic A/B controller as disproportionate execution authority; retain it only as ignored, superseded design evidence.
- [x] Select the exact current-tip oracle path for present product acceptance. Historical A/B remains an optional fresh, content-addressed diagnostic only if later causal attribution is required; no current-tip result may be described as proof that `cb089b0` changed `1bd16e0`.

## Task 4: Run the verify-then-amend gate round

- [ ] Runtime sequencing amendment: after D2 source review and unprivileged
  verification, independently review and create one additive Task 4 gate-input
  commit before invoking lane 13. Runtime evidence must consume that immutable
  committed tree and record equal start/end commit, tree, cleanliness, and input
  ledgers. Never amend, rebase, squash, or replace the evidenced commit; any
  correction is a new additive commit and requires fresh Task 4 evidence.
- [ ] Test-first, add one exact lane-13 checker mode that composes manifest-only discovery with exactly one shared-overlay uncertainty. It must reject zero or duplicate overlay records, every unavailable-discovery record, every other skip, and all existing counter/shape/call/lifecycle failures.
- [ ] Before runtime, independently review the checker, the single lane-13 invocation change, and its artifact contract. Do not change production Rust/BPF/privacy/schema/allowlist behavior.
- [ ] For each external lane, durably record the bytes and resolved identities actually consumed: release files, base/workload/node/component image IDs and available digests, provider SHA-256/build ID, exact gate/helper/HEAD identities, tool versions, kernel, Docker daemon/storage driver, timestamps, and cleanup/quiescence. A result without this record is invalid, not PASS. This is current-environment-qualified evidence, not a frozen campaign or causal A/B claim.
- [ ] Use a fresh evidence root and the exact authorized lane commands. Run serially in this order: lane 02, lane 07, lane 09, lane 10, lane 11, lane 13, lane 14, then the lane-16 shape spot check.
- [ ] Preserve cleanup and quiescence evidence for every lane. Record public skips exactly once where the lane contract requires them.
- [ ] Amend only fresh, reproduced mismatches:
  - lane 07 manifest-only versus scanned classification, if the new evidence reconfirms it;
  - one bounded shared-overlay uncertainty in lane 13 only if it is genuinely shared and matches lane 09;
  - stale hard-coded `uncorroborated=1` assumptions in lanes 10, 11, 13, and 14, replacing them with measured relationship assertions;
  - the `verify-oracle.sh:291` oracle defect, if reproduced;
  - the healthy owned-run pause classification from partial to `sigstop`, while retaining legitimate profile PARTIAL status;
  - cross-gate consistency errors.
- [ ] In lane 13, any unavailable-discovery record is a product failure: preserve its internal attribution and fix the present mount/pinning path rather than widening the oracle. Only the exact one-overlay/zero-unavailable shape may pass as `PARTIAL`.
- [ ] Do not broaden a gate based on a single unexplained row, changed external identity, or blocked privileged lane.

## Task 5: Integrate the capability-tier validator into the contract

- [ ] Add `scripts/verify-capability-tier.sh --self-test` to the existing unprivileged validator lane in `scripts/gates.sh` and `.github/workflows/ci.yml`.
- [ ] Add the live capability-tier invocation to the root gate at the established privileged boundary; retain the script’s exact SYS_ADMIN and BPF/PERFMON predicates and negative self-tests.
- [ ] Add the script to the shell syntax and gate-contract coverage in `tests/artifact_contracts.rs`.
- [ ] Keep generated capability artifacts out of Git and do not alter the privacy allowlist.
- [ ] Re-run formatting, locked check, locked tests, locked clippy, all affected self-tests, and `git diff --check`.

## Task 6: Obtain independent review and land the gate-only change

- [ ] Stop the single writer before requesting review.
- [ ] Ask Sol at xhigh effort to review the fresh evidence, lane13 discriminator, every gate amendment, and the capability integration against the roadmap and stop conditions.
- [ ] Resolve only evidence-backed review findings; if review identifies a production Rust/BPF/privacy/schema defect, stop and return to the appropriate product plan instead of hiding it in gate logic.
- [ ] Preserve the additive Task 4 gate-input commit exactly as evidenced. After
  Task 4 evidence review, implement/review Task 5 capability-validator wiring in
  one separate additive gate-only commit. Task 4 evidence does not validate the
  later combined HEAD.
- [ ] Record exact commit, evidence root, commands, skips, cleanup result, and review outcome in the continuation ledger.

## Task 7: Create a fresh frozen-input root

- [ ] Only after the gate-only commit and Sol review, create a new root; never reuse r2:

```
bash scripts/verify-live-discovery-preflight.sh --freeze \
  /home/user/.local/state/p11scope/slice1b2-production-r3 \
  jammy=/home/user/p11scope-vm-bases/jammy/jammy-server-cloudimg-amd64.img \
  noble=/home/user/p11scope-vm-bases/noble/noble-server-cloudimg-amd64.img
```

- [ ] Validate frozen inputs and the BPF object/inventory using the existing scripts:

```
eval "$(bash scripts/verify-live-discovery-preflight.sh --frozen-inputs /home/user/.local/state/p11scope/slice1b2-production-r3)"
python3 scripts/check-live-discovery-object.py --source "$BPF_SOURCE" --object "$BPF_OBJECT" --manifest "$BPF_INVENTORY"
python3 scripts/check-live-discovery-evidence.py --self-test
bash scripts/verify-live-discovery-preflight.sh --self-test
```

- [ ] Confirm the frozen campaign begins at zero attempts, and record source commit plus hashes for modified Step 2 scripts that are not fully frozen by the execution manifest.

## Task 8: Run 9.2d, then advance only on clean evidence

- [ ] Run the 9.2d sequence serially: 02, 07, 09, 10, 11, 13, then the lane-16 shape spot check, using the frozen binary/gate commit and a fresh evidence directory.
- [ ] Require one explainable owned-run public skip where specified, healthy `sigstop` pause, no unexplained variance, cleanup/quiescence, and no residue.
- [ ] Stop on an unexplained row, a second owned skip, candidate changes after freeze, lost quiescence, or cleanup residue. Classify missing infrastructure as UNRUN/blocked.
- [ ] After an explainable 9.2d result, build the privileged non-production `frozen/preflight-harness` and run the 9.3 campaign: 480 primary plus 40 forced-fallback VM attempts on Jammy 5.15 and Noble 6.8. Missing KVM, sudo, base hashes, or harness is UNRUN/blocked.

## Task 9: Independent closeout and Task 10

- [ ] Have an independent reviewer recompute the evidence and perform the whole-slice security/correctness review for 9.4.
- [ ] Re-run exact-tip CI and verify all public/private artifact contracts.
- [ ] Only then perform the Task 10 multi-artifact closeout and update public status. Local merge is the final in-scope integration action; push/tag/publication remain out of scope unless separately authorized.
- [ ] Keep the deferred direct `Session::start` to `Engine::start_session_with` integration seam deferred unless fresh gate evidence contradicts behavior or a production seam is independently required.

## Completion evidence

- Current branch and commit IDs, clean/expected worktree status, and preserved `.codex/` state.
- Fresh lane results with exact evidence roots, image/input identities, skips, cleanup/quiescence, and UNRUN/blocked classifications.
- Gate-only diff and independent Sol review result.
- Fresh r3 frozen-input manifest, object validation, 9.2d board, 9.3 campaign result, 9.4 review, and exact-tip CI output.
- No claim of release, publication, or final support until Task 10’s gates are actually complete.
