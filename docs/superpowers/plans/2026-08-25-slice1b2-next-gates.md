# Slice 1b-2 Gate Closure and Runtime Campaign Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Land the already-reviewed Slice 1b-2 fix6 documentation/validator delta, close the remaining gate-contract and runtime evidence gaps, and reach a fresh, independently reviewed runtime campaign without overstating UNRUN or artifact-only evidence.

**Architecture:** Keep production Rust/BPF/privacy/schema behavior frozen during the next gate round. First land the exact five-file reviewed delta at the current implementation tip. Then express the already-specified Lane 13 contract directly—manifest-only discovery plus exactly one shared-overlay uncertainty and zero unavailable-discovery records—and run fresh current-tip evidence with durable resolved-input identities for the remaining applicable Task 4 lanes. The zero-unavailable PASS rule is Lane 13-only and applies only to a topology proposed for supported acceptance. Lane 13 instead uses its receipt-bound attempt-6 pre-r3 history and runs exactly once as the frozen-candidate 9.2d negative control; no current-tip Lane 13 evidence is sought. Historical A/B attribution remains an optional diagnostic, not a prerequisite for present product acceptance. Wire the capability-tier validator into the existing gate/CI contract, obtain an independent Sol review, and only then create a new frozen-input root for the serial 9.2d campaign. VM campaign work remains a separate privileged/non-production stage.

**Topology scope amendment (2026-08-27, Task 4):** The historical Lane 13
checker/invocation work is complete at its exact committed identities:
checker/lifecycle commit `34357b5dda71c670250dd3ab336b29c801120d5b`
(tree `ae3346e4b8e137f430f010d0937bcf186cfcff39`) and final invocation/contract
commit `fd3d08ad9bd2f58508eda1ee4a50882c0633d850` (tree
`0decc4dee974707468b5758107fb055c30d44d7d`). The checker and invocation are
not re-run or amended here, and Lane 13's zero-unavailable PASS oracle is
unchanged: that Lane 13-only PASS applies only to a topology proposed for
supported acceptance. Retain
the evidenced Knative shared-inode capture for the exact preattached provider:
`136/136` probes and expected cold-pod calls. The dated attempt-6 exclusion is
bound to immutable input receipt
`/home/user/.local/state/p11scope/task4-lane13-a2fd9ee-20260826T2135EEST/facts.log`
with SHA-256
`b96cbed6cbc2963dab2c5963b5c52f6378d9bef313479b83a56c259df79b94f3`, exact
HEAD `a2fd9ee8eddfaff34b3fb6b65267688b5a90aa03`, and tree
`f90e2dfe8dbd0a211f9e32055a37ff7320080b88`. It binds the lane
command/script ledger, Kind/Knative releases/images, provider hash/build ID,
kernel/storage, node/workload identities, and clean start/end. In that
reproduced Knative node-wide retained-view topology, full late-provider
discovery is `UNSUPPORTED/NON-PASS`; its exact one-overlay/one-unavailable
result is evaluated only as a required negative control, never by the
zero-unavailable PASS oracle. Attempt 6 is completed pre-r3 history: no further
Task 4 Lane 13 rerun. Future negative-control classification permits
only candidate and gate identity may differ from attempt 6, and only when each
exactly equals the independently reviewed pre-run r3 manifest. Every other
external topology field from the receipt must match attempt 6; any mismatch
stops as UNRUN/review before outcome classification and never inherits the
exclusion from outcome alone. Lane 13 runs once in 9.2d as
the frozen-candidate negative control: any different public shape, additional
gap, or lifecycle/input/cleanup failure stops the campaign. Remaining applicable
Task 4 lanes and r3 may proceed only after this additive amendment is
independently reviewed and committed; Lane 13 PASS is not an unlock condition.
The Gate Closure Task 5 capability-validator integration is complete through
exact commit `7a0c1eddac0b0b81340206ac742884ca2f31f691`;
`scripts/verify-capability-tier.sh` exited 0 at that exact tree without
changing Lane 13. README/usage wording remains reserved for Task 10. This
amendment changes no design spec, production Rust/BPF/privacy/schema/allowlist,
or procfs/mmap/eBPF fallback behavior.

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
- [x] Select the exact current-tip oracle path for the remaining applicable lanes. Lane 13 uses its receipt-bound attempt-6 history and the single frozen-candidate 9.2d negative-control run instead. Historical A/B remains an optional fresh, content-addressed diagnostic only if later causal attribution is required; no current-tip result may be described as proof that `cb089b0` changed `1bd16e0`.

## Task 4: Run the verify-then-amend gate round

- [x] Historical runtime sequencing, checker, and invocation work is complete
  at the exact committed identities recorded in the topology amendment above.
  Its immutable evidence recorded equal start/end commit, tree, cleanliness,
  and input ledgers; no further Task 4 Lane 13 rerun is authorized here.
- [x] Historical checker/invocation scope is complete: the manifest-only
  discovery plus exactly one shared-overlay uncertainty mode rejects zero or
  duplicate overlay records, every unavailable-discovery record, every other
  skip, and all existing counter/shape/call/lifecycle failures. The
  zero-unavailable PASS oracle remains only for a topology proposed for
  supported acceptance and is not used for the dated exclusion.
- [x] Historical independent review covered the checker, the single Lane 13
  invocation, and its artifact contract. Do not change production
  Rust/BPF/privacy/schema/allowlist behavior.
- [ ] For each external lane, durably record the bytes and resolved identities actually consumed: release files, base/workload/node/component image IDs and available digests, provider SHA-256/build ID, exact gate/helper/HEAD identities, tool versions, kernel, Docker daemon/storage driver, timestamps, and cleanup/quiescence. A result without this record is invalid, not PASS. This is current-environment-qualified evidence, not a frozen campaign or causal A/B claim.
- [ ] Use a fresh evidence root and the exact authorized lane commands. Run
  the remaining applicable Task 4 lanes serially in this order: lane 02, lane
  07, lane 09, lane 10, lane 11, lane 14, then the lane-16 shape spot check;
  Lane 13 has completed its pre-r3 negative history and is not rerun here.
- [ ] Preserve cleanup and quiescence evidence for every lane. Record public skips exactly once where the lane contract requires them.
- [ ] Amend only fresh, reproduced mismatches:
  - lane 07 manifest-only versus scanned classification, if the new evidence reconfirms it;
  - no Lane 13 oracle amendment: its receipt-bound exclusion is a historical
    negative control, not a supported-acceptance PASS result;
  - stale hard-coded `uncorroborated=1` assumptions in lanes 10, 11, and 14, replacing them with measured relationship assertions;
  - the `verify-oracle.sh:291` oracle defect, if reproduced;
  - the healthy owned-run pause classification from partial to `sigstop`, while retaining legitimate profile PARTIAL status;
  - cross-gate consistency errors.
- [ ] For a Lane 13 topology proposed for supported acceptance, any
  unavailable-discovery record is a product failure: preserve its internal
  attribution and fix the present mount/pinning path rather than widening the
  oracle. This applies only to that Lane 13 topology and is outside the
  owned-run contract. The receipt-bound attempt-6 topology is evaluated only
  as the required `UNSUPPORTED/NON-PASS` negative control; its expected
  unavailable record is not submitted to the PASS oracle and does not
  authorize a product fix or oracle widening. Only that Lane 13 topology's
  exact one-overlay/zero-unavailable shape may pass as `PARTIAL`.
- [ ] A successful owned run requires exactly one sanitized public
  `{"name":"discovery subject","reason":"discovery unavailable"}` timing-proof
  projection. That projection is authorized only by the exact frozen owned-run
  context, expected row cardinality, and full lane oracle. Zero, a second, or
  an outside-context projection is `NON-PASS`; it is not a generic discovery
  result and cannot be borrowed across lanes.
- [ ] Lane 02 has exactly six attempts:
  `(initial-set|dlopen) × (never|auto|always)`. Each Cartesian tuple is one
  distinct invocation and one row; ungated controls are excluded. A successful
  row exits zero with 68 table entries/slots, 136/136 entry-and-return probes,
  the exact deterministic fixture counts, positive function counts equal to
  the tracked `spike/expected.txt` plus exactly one bootstrap
  `C_GetFunctionList`, matching the current `validate_clean_metrics` count
  relation, zero event loss/ambiguity/in-flight residue, exactly one
  authorized sanitized public timing-proof projection, and no unavailable-
  loader strategy. `never` is `none/0/0/0`; `auto|always` is `sigstop` with
  `pause_attempts = pause_confirmed >= 1` and `pause_partial = 0`. An `always`
  safe refusal is containment-correct, but its row and the Lane 02 lane are
  `NON-PASS`, produce no capture document, and still require complete
  cleanup/quiescence evidence.
- [ ] Lane 16 has exactly two independent shape checks: one `never` and one
  `auto`. Each row must exit zero with 68 table entries, 68 slots, 136/136
  entry-and-return probes, exactly one authorized sanitized public timing-proof
  projection, zero event loss and zero discovery-loss counters, zero ambiguity,
  in-flight work, and residue. These listed predicates are the complete current
  Task 4 shape oracle; no existing checker mode is claimed. The one authorized
  sanitized timing-proof projection is not one of those counters. `never` is
  `none/0/0/0`; `auto` is `sigstop` with
  `pause_attempts = pause_confirmed >= 1` and `pause_partial = 0`. Lane 02's
  deterministic fixture counts do not apply. No historical workload total
  (including `200000`), `G3`, `136175`, call, timing, median, or performance
  threshold is an acceptance predicate.
- [x] Preserve the checker/oracle unchanged while retaining the completed
  receipt-bound attempt-6 node-wide retained-view late-provider result as the
  required `UNSUPPORTED/NON-PASS` negative control: one overlay plus one
  unavailable is not a pass or an oracle amendment. The retained
  preattached-provider Knative evidence remains `136/136` probes with expected
  cold-pod calls; no further Task 4 Lane 13 run occurs.
- [ ] Do not broaden a gate based on a single unexplained row, changed external identity, or blocked privileged lane.

## Task 5: Integrate the capability-tier validator into the contract

**Status (2026-08-27): COMPLETE through
`7a0c1eddac0b0b81340206ac742884ca2f31f691`.** The implementation commit
`a1774d6` wires the validator in the local gate, hosted CI, and artifact
contracts. The live `scripts/verify-capability-tier.sh` gate exited 0 at the
exact commit/tree above with the expected measured rows; this does not change
the Lane 13 `UNSUPPORTED/NON-PASS` disposition or unlock r3.

- [x] Add `scripts/verify-capability-tier.sh --self-test` to the existing unprivileged validator lane in `scripts/gates.sh` and `.github/workflows/ci.yml`.
- [x] Add the live capability-tier invocation to the root gate at the established privileged boundary; retain the script’s exact SYS_ADMIN and BPF/PERFMON predicates and negative self-tests.
- [x] Add the script to the shell syntax and gate-contract coverage in `tests/artifact_contracts.rs`.
- [x] Keep generated capability artifacts out of Git and do not alter the privacy allowlist.
- [x] Re-run formatting, locked check, locked tests, locked clippy, all affected self-tests, and `git diff --check`.

## Task 6: Obtain independent review and land the gate-only change

- [ ] Stop the single writer before requesting review.
- [ ] Ask Sol at xhigh effort to review the fresh evidence, lane13 discriminator, every gate amendment, and the capability integration against the roadmap and stop conditions.
- [ ] Resolve only evidence-backed review findings; if review identifies a production Rust/BPF/privacy/schema defect, stop and return to the appropriate product plan instead of hiding it in gate logic.
- [ ] Preserve the additive Task 4 gate-input commit exactly as evidenced, and
  independently review and commit this topology amendment before remaining
  applicable Task 4 lanes and r3. Gate Closure Task 5 capability-validator
  integration is already complete at the exact base above in its separate
  gate-only commit; its live result does not validate Lane 13 or unlock r3.
- [ ] Record exact commit, evidence root, commands, skips, cleanup result, and review outcome in the continuation ledger.

## Task 7: Create a fresh frozen-input root

- [ ] Only after this amendment and the remaining applicable Task 4 gate-input
  review are independently complete and committed, with the required Sol review,
  create a new root; Task 5's completed capability commit does not itself unlock
  r3. Never reuse r2:

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

- [ ] Run the 9.2d sequence serially once, with exactly one gate run for each
  of 02, 07, 09, 10, 11, and 14, exactly six Lane 02 rows, exactly one
  frozen-candidate Lane 13 negative-control run, and exactly two Lane 16 shape
  checks (one `never`, one `auto`): 02, 07, 09, 10, 11, 13, 14, 16. Lane 13
  is the required frozen-candidate negative control: the receipt-defined
  reproduced exact late-provider topology must retain one overlay plus one
  unavailable and be classified `UNSUPPORTED/NON-PASS`; this expected scoped
  result is recorded and does not stop otherwise applicable lanes. It is not
  evaluated by the Lane 13 zero-unavailable PASS oracle, and is not a PASS or
  unlock condition. Any receipt-input mismatch, different public shape, added
  gap, or lifecycle/input/cleanup failure stops the campaign as UNRUN/review or
  NON-PASS as applicable.
- [ ] Require `none/0/0/0` for every successful `never` row. Require `sigstop`
  only on successful pause-enabled (`auto|always`) rows, with
  `pause_attempts = pause_confirmed >= 1` and `pause_partial = 0`. Require
  exactly one authorized sanitized public
  `{"name":"discovery subject","reason":"discovery unavailable"}`
  projection for every successful owned run. Stop on a zero, second, or
  outside-context projection, and preserve cleanup/quiescence evidence with no
  residue.
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
