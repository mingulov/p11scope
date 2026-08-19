# slice1b2-gates work state (updated after each task)

Location: worktree `/home/user/src/m/pkcs11-scope/.claude/worktrees/slice1b2-gates`, branch `spike/slice1b2-gates`.
This file is the durable progress record for the no-busy-wait Gate B task. Update it after every task; commit it with the task's changes.

## Binding directive (abbreviated)

Work ONLY in this worktree. Goal: no-busy-wait Gate B pause protocol (old winner ran 50k ktime polls before SIGSTOP). Two validated outcomes (A one-owner/both records; B deferred second hook wins owner 2). Hard FAILs: ring loss, unaccounted records, owner-map failure, incomplete stop, 100 ms deadline, wrong pidfd, extra resume, residual stopped task, marker before its own attach set. Never rerun until passing. Structural guard: no loop/poll/delay between CAS and timestamp/SIGSTOP. Workflow: REDs → unprivileged tests → independent review → freeze ONE bundle → VM lock → 3 cold boots x 20 children on jammy 5.15 + 3 on noble 6.8 (KVM via `sg kvm`), serialized, all predeclared lanes run regardless of earlier FAIL → honest PASS/FAIL/TIMEOUT → VM cleanup verification → evidence to `/home/user/src/m/p11scope-ws/incoming/slice1b2-no-delay-gateb-2026-08-19/` (dir 0700, files 0600; do NOT touch canonical manifest) → report + hashes → STOP for controller review. No merge/push/release/production edits.

## Commits

- `fca3c52` — initial no-busy-wait implementation (BPF ktime→send only; fixture minimal two-hook + barriers; runner two-outcome protocol; check-signal-shape.py DAG guard; validator; 55 tests green; all repo gates green).
- `ef94acd` — review round 1 fixes: pause_owners=1 assignment (outcome A could never pass), re-mark before resume 2 after confirmed stop 2 (outcome B could never pass; one resume per owned stop), winners!=1 → explicit surplus, counter_delta + failure-path ring-loss export, validator owners∈{0,1,2} + first-confirmable-pair parity, gotol regex. 60 spike tests green, repo gates green.
- Round 2 fixes (cd9bfec): honest partial-attach evidence (protocol_tail_completed flag gates cleanup-time recompute of signal/late_attach_accepted from actual link counts), validator accepts honest failure combinations for failing records only, check-signal-shape.py catches backward `call -N`, classification tests production-faithful (5 shapes). REDs witnessed. 60 tests + gates green.
- Round 3 fixes (this commit): recompute guard `late_attach_attempts > 0` (vacuous 0==0 recompute exported accepted=true/attempts=0 → malformed 64 for every pre-drain failure), owners==1 resume-errno symmetry (attempts {1,2}, attempts==2 ⇒ rc==-1), new classification shapes resume1-errno + pre-drain-timeout, freeze test pins the guard. REDs witnessed. 60 tests + gates green.

## Review history

### Round 1 (subagent review of fca3c52) — fixed in ef94acd
- Critical: missing re-mark before resume 2 → outcome B always failed. FIXED.
- Extra Critical found during verification: `pause_owners = 1` never assigned → outcome A always failed. FIXED.
- Important: honest failure shapes classified as malformed (64). Partially fixed in ef94acd, refined in round 2.
- Minor 3/4/5/6 (gotol regex, first-confirmable-pair, failure-path counters, winners==2) all FIXED.

### Round 2 (delta review of ef94acd) — ALL FIXED in cd9bfec
- CONFIRMED GOOD: re-mark placement lifecycle-safe on every path; pause_owners=1 single-site; first_confirmable_pair parity; failure-path counters sound.
- Critical 1 late_attach_accepted/late_link_detached mismatch → FIXED. Important 2 owners==2 empty samples_2 → FIXED. Important 3 fabricated test flags → FIXED. Minor 4 attempts=3 → FIXED. Minor 5 backward call -N → FIXED.

### Round 3 (delta review of cd9bfec) — ALL FIXED (this commit)
- CONFIRMED GOOD: flag placement exactly right (single assignment at true success tail end); recompute idempotent on post-assignment failures; relaxations soundly scoped to failing records (oracle preserves all strictness); shape-guard correct, no false positives; commit scope clean.
- Critical C1: vacuous recompute (attempts=0/required=0/attached=0 → accepted=true → 64) for pre-drain failures → FIXED (guard + pre-drain-timeout witness + freeze pin).
- Important I2: outcome-A resume errno (attempts=2, rc=-1) rejected by owners==1 branch → FIXED (validator symmetry + resume1-errno witness).
- Minor M3 (resume2_errno test flag unfaithful but harmless — both values validate), M4 (STATE.md typo) — noted.

## Workflow position

DONE: implementation → review 1 → fixes → review 2 → fixes → review 3 → fixes → all tests/gates green → commit (this).
NEXT: freeze bundle (`build-bpf` + `build-fixture` + `freeze-execution`, record hashes) → VM lock → campaigns: 3× gate-b-lane jammy + 3× noble, 20 children each, KVM via `sg kvm`, serialized, all lanes run regardless of FAIL → VM cleanup verification (listeners, backing images, free space) → evidence to /home/user/src/m/p11scope-ws/incoming/slice1b2-no-delay-gateb-2026-08-19/ (0700/0600) → report + exact hashes → STOP for controller review.

## Key run.sh interfaces (verified)

- `build-fixture OUT`, `build-bpf NEW_OUT` (clean HEAD required; runs check-init-shape.py + check-signal-shape.py).
- `freeze-execution SOURCE_BUILD NEW_BUNDLE` (6-file bundle).
- `gate-b-lane LANE BUNDLE NEW_RUN_DIR NEW_EXPORT_DIR` (lane=bundle-jammy|bundle-noble etc.; internally --runs 20; fresh overlay per invocation = cold boot; flock-serialized; validates bundle + export).
- `P11SCOPE_SPIKE_ACCEL=kvm` via `sg kvm -c '...'` (prior Gate B identity was KVM). VM lock: /tmp/p11scope-slice1b2-spike-vm.lock (inside run.sh lane functions).
- VM bases: /tmp/p11scope-slice1b2-vms/{jammy,noble}/. Evidence target: /home/user/src/m/p11scope-ws/incoming/slice1b2-no-delay-gateb-2026-08-19/ (create 0700; files 0600).

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
