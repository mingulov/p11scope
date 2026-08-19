# slice1b2-gates work state (updated after each task)

Location: worktree `/home/user/src/m/pkcs11-scope/.claude/worktrees/slice1b2-gates`, branch `spike/slice1b2-gates`.
This file is the durable progress record for the no-busy-wait Gate B task. Update it after every task; commit it with the task's changes.

## Binding directive (abbreviated)

Work ONLY in this worktree. Goal: no-busy-wait Gate B pause protocol (old winner ran 50k ktime polls before SIGSTOP). Two validated outcomes (A one-owner/both records; B deferred second hook wins owner 2). Hard FAILs: ring loss, unaccounted records, owner-map failure, incomplete stop, 100 ms deadline, wrong pidfd, extra resume, residual stopped task, marker before its own attach set. Never rerun until passing. Structural guard: no loop/poll/delay between CAS and timestamp/SIGSTOP. Workflow: REDs → unprivileged tests → independent review → freeze ONE bundle → VM lock → 3 cold boots x 20 children on jammy 5.15 + 3 on noble 6.8 (KVM via `sg kvm`), serialized, all predeclared lanes run regardless of earlier FAIL → honest PASS/FAIL/TIMEOUT → VM cleanup verification → evidence to `/home/user/src/m/p11scope-ws/incoming/slice1b2-no-delay-gateb-2026-08-19/` (dir 0700, files 0600; do NOT touch canonical manifest) → report + hashes → STOP for controller review. No merge/push/release/production edits.

## Commits

- `fca3c52` — initial no-busy-wait implementation (BPF ktime→send only; fixture minimal two-hook + barriers; runner two-outcome protocol; check-signal-shape.py DAG guard; validator; 55 tests green; all repo gates green).
- `ef94acd` — review round 1 fixes: pause_owners=1 assignment (outcome A could never pass), re-mark before resume 2 after confirmed stop 2 (outcome B could never pass; one resume per owned stop), winners!=1 → explicit surplus, counter_delta + failure-path ring-loss export, validator owners∈{0,1,2} + first-confirmable-pair parity, gotol regex. 60 spike tests green, repo gates green.
- Round 2 fixes (this commit, name TBD): honest partial-attach evidence (protocol_tail_completed flag gates cleanup-time recompute of signal/late_attach_accepted from actual link counts), validator accepts honest failure combinations for failing records only (detached-without-full-accept, empty samples_2 with owners=2, resume attempts up to 3 = resume-2 errno + cleanup resume), check-signal-shape.py catches backward `call -N` (bpf-to-bpf), classification tests rewritten production-faithful (5 shapes incl. child_release, deferred-timeout, stop2-unconfirmed, cancelled-mid-sampling, resume2-errno), shape-guard synthetic test covers backward-call. All REDs witnessed first. 60 spike tests + full repo gates green.

## Review history

### Round 1 (subagent review of fca3c52) — fixed in ef94acd
- Critical: missing re-mark before resume 2 → outcome B always failed. FIXED.
- Extra Critical found during verification: `pause_owners = 1` never assigned → outcome A always failed. FIXED.
- Important: honest failure shapes classified as malformed (64). Partially fixed in ef94acd, refined in round 2.
- Minor 3/4/5/6 (gotol regex, first-confirmable-pair, failure-path counters, winners==2) all FIXED.

### Round 2 (delta review of ef94acd) — verdict "No, with fixes" → ALL FIXED (see commits above)
- CONFIRMED GOOD: re-mark placement lifecycle-safe on every path (one cleanup resume + SIGKILL via original pidfd, no double-resume, no stopped-child leak); pause_owners=1 single-site; first_confirmable_pair exact parity; failure-path counters sound.
- Critical 1 late_attach_accepted vs late_link_detached mismatch → FIXED (cleanup-time recompute).
- Important 2 owners==2 empty samples_2 (mid-sampling cancellation) → FIXED (failing records only).
- Important 3 fabricated test flags → FIXED (production-faithful shapes).
- Minor 4 attempts=3 → FIXED (bound {0,1,2,3}, oracle still requires exactly 2 for B-pass).
- Minor 5 backward call -N → FIXED (regex + synthetic test case).

## Workflow position

DONE: implementation (fca3c52) → review 1 → fixes (ef94acd) → review 2 → REDs → round-2 fixes → 60 spike tests + all repo gates green → commit (this).
NEXT: (optional quick round-3 delta review) → freeze bundle (`build-bpf` + `build-fixture` + `freeze-execution`, record hashes) → VM lock → campaigns: 3× gate-b-lane jammy + 3× noble, 20 children each, KVM via `sg kvm`, serialized, all lanes run regardless of FAIL → VM cleanup verification (listeners, backing images, free space) → evidence to /home/user/src/m/p11scope-ws/incoming/slice1b2-no-delay-gateb-2026-08-19/ (0700/0600) → report + exact hashes → STOP for controller review.

## Key run.sh interfaces (verified)

- `build-fixture OUT`, `build-bpf NEW_OUT` (clean HEAD required; runs check-init-shape.py + check-signal-shape.py).
- `freeze-execution SOURCE_BUILD NEW_BUNDLE` (6-file bundle).
- `gate-b-lane LANE BUNDLE NEW_RUN_DIR NEW_EXPORT_DIR` (lane=bundle-jammy|bundle-noble etc.; internally --runs 20; fresh overlay per invocation = cold boot; flock-serialized; validates bundle + export).
- `P11SCOPE_SPIKE_ACCEL=kvm` via `sg kvm -c '...'` (prior Gate B identity was KVM). VM lock: /tmp/p11scope-slice1b2-spike-vm.lock (inside run.sh lane functions).
- VM bases: /tmp/p11scope-slice1b2-vms/{jammy,noble/. Evidence target: /home/user/src/m/p11scope-ws/incoming/slice1b2-no-delay-gateb-2026-08-19/ (create 0700; files 0600).

## Check commands

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
bash -n spike/slice1b2-kernel/run.sh
```

## Environment

Rust 1.88.0 (+nightly for ebpf build), QEMU 8.2.2, `sg kvm -c` works (kvm group), user uid=1000. 16G free on / (watch overlays). Spike tests: currently 60 (will grow with round-2 tests).
