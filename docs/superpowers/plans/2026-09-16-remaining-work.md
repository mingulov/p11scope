<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Remaining work plan — green suite, signal-exit message, Kryoptic churn (2026-09-16)

## Goal

Finish the three "not done" items from the 2026-09-15 session: a fully green
`cargo test --lib` suite on host, a truthful signal-exit message instead of the
pause-refusal text, and a scored, evidence-backed diagnosis of Kryoptic
discovery-under-churn (phantom tables) with a fix proposal — plus an explicit
cgroup-v2 preflight row in `doctor` so v1 hosts fail loudly instead of with a
raw kernel BPF error (user-added 2026-09-15).

## Success Criteria

- `cargo test --lib` passes 828/828 on host, with no assertion weakened to get
  there; every fixed failure names its root cause (product boundary bug with a
  regression test, or test-environment assumption with a hermetic fixture).
- A SIGTERM-mid-pause `run` exit reports interruption, not refusal; pinned by a
  failing-first test.
- Kryoptic churn research delivers: a repeatability baseline (settled vs churn,
  Kryoptic vs SoftHSM control), a false-positive census of Rust `.rodata`
  decodes, a stability-scoring definition, and a ranked fix proposal. A product
  fix is explicitly out of scope for this plan; it gets its own approval.
- `doctor` reports a cgroup-version row: PASS on unified hierarchy, FAIL with
  "cgroup v2 required" text on v1/hybrid hosts; pinned by unit tests that do
  not need privileges (pure hierarchy detection).

## Context And Current Facts

- Prior session (notes/2026-09-15-provider-qual-live-capture.md): pkcs11-check
  `fetch-data` wired in with vector verdicts on 3 providers (AES-KW and EdDSA
  acceptance findings, SoftHSM brainpool crashes); Gap-1 settle resume-first
  fix with 2 RED→GREEN unit tests (`resume_if_stopped`, `src/run.rs`).
- Full `--lib` suite today: 818 pass, 10 fail — 8× `discovery::engine` stale/
  fallback tests, 1× `duration_and_forwarded_signals_have_one_owned_cleanup_route`,
  1× `path_absolute_shebang_...` (passes in isolation, parallel-load flake).
- The 8 engine failures share one signature: fixtures made by copying `/bin/sh`
  fail pinning with `provider.so+0x4000 is outside every executable ELF segment`
  for all 68 functions at the same offset (`src/discovery/identity.rs:1167`,
  ranges in `crates/manifest/src/identity.rs:71`, containment itself correct:
  `start <= offset < end`). Fixtures are built with unpinned
  `gcc -shared -fPIC` (`src/discovery/engine.rs:16595,16620`); host is
  gcc 15.2.0 AND `/bin/sh` → dash whose R-X LOAD starts at file offset
  exactly 0x4000 (`readelf` verified). Prior "gcc-15" attribution is
  unproven; dash-boundary vs synthetic-offset vs ranges-construction are all
  live hypotheses — the debug unit settles this, it does not assume it.
- `duration_...` fails isolated (`wait_for(10ms)` → `Exited(1)`); the failing
  path (`spawn`/`release`/`wait_for`) is untouched by recent edits, and
  `/bin/sleep` here is a coreutils-shim symlink — environment suspect, not code.
- Signal-exit text lives at `src/run.rs:1531-1532` ("required pause protection
  could not be completed ... refused rather than capturing unpaused") and fires
  on SIGTERM-mid-pause exits (observed host E2E twice), which is false: the run
  captured, then was interrupted.
- Kryoptic churn: `run --pause always` against a dlopen-loop driver on the
  Fedora guest exits 1 with `0/0 probes attached` (guest `~/pause2b.log`);
  reclassified in the note — the refusal is designed and test-pinned
  (`explicit_always_refuses_rather_than_completing_unpaused`), so the defect is
  one layer down (no usable table discovered under churn). Related: Rust
  `.rodata` false-positive decodes, `event_loss` under-reporting pressure.
- Guests live: Fedora (2246) and Jammy (2247) KVM lanes with qual tokens/PINs
  recorded in the provider-qual note; host has full caps + debugfs/tracefs.

## Constraints And Non-goals

- No tag/push/publish/release; never remove `/etc/sudoers.d/p11scope-session`
  (standing constraints). No commits unless separately asked.
- Do NOT weaken test assertions to green the suite; do NOT "fix" the
  pause-always refusal (designed behavior).
- Out of scope: NSS suite (blocked on pkcs11-check 0.1.9, external), D-state
  detach wedge (kernel-side; resume-first mitigation already landed), Kryoptic
  stability-scoring as a shipped feature (only the scoring *definition* is in
  scope here), any product-code change for churn (proposal only).
- `cargo build` strips file caps: re-apply `setcap
  cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+eip`
  after every rebuild before live runs.

## Key Decisions

1. **Order: message → suite → churn.** Message is small/safe/host-local;
   suite debug is bounded host work; churn is open-ended guest research.
   Each unit lands independently; churn never blocks the other two.
2. **Green-suite rule: diagnose before touching.** Each failure gets a root
   cause first (systematic-debugging, already loaded). If the cause is a
   product boundary bug (e.g. identity ranges), fix product with TDD. If it is
   a test-environment assumption (e.g. `/bin/sh` layout), make the fixture
   hermetic — never relax the asserted contract.
3. **Churn is research, not a fix.** It ends in a scored baseline + ranked
   proposal under a fresh approval gate, because the fix surface (discovery
   engine + BPF) is the highest-risk code in the tree.
4. **No new harness abstractions.** Reuse `gcc` fixture builds in tests,
   existing `scripts/check-live-discovery-*.py` helpers, and the guest lanes
   as-is.

## Recommended Approach

Unit 1 (message): branch the run.rs:1531 error path on the already-tracked
signal state (`signals.interrupted()` at the finish site): signalled exits
report interruption naming the signal; genuine always-refusals keep the
current text. Pinned by a failing-first test at the message-construction
level (extract helper if needed for testability — test seam only, no behavior
change beyond the text).

Unit 2 (suite): per-failure-group diagnosis with a reproducer-first loop:
(a) the 8 engine failures — settle dash-boundary vs synthetic-offset vs
ranges hypotheses with `readelf` + a minimal fixture matrix, then apply
Decision 2; (b) the duration failure — probe the `spawn`/`release`/`wait_for`
path under this host's coreutils-shim `/bin/sleep` (strace-level if needed),
expecting an environment-specific cause; (c) the shebang flake — 10× isolated
vs 3× full-suite runs to confirm load-flakiness, then harden the timing
assumption (deadline, not contract).

Unit 3 (churn): guest-side measurement protocol — repeated settled scans vs
dlopen-churn scans on Kryoptic with SoftHSM as control; per-run table/slot
capture to committed evidence; false-positive census keyed by section
(`.rodata` vs text); stability score defined as slot persistence across N
runs; `event_loss` counter audit against tracefs ground truth (the
fixture-BPF-zero vs tracefs-fires technique from the qual). Deliverable is the
baseline + census + proposal, not code.

## Work Plan

1. **Signal-exit message** (implementation, ~1h)
   Surface: `src/run.rs` finish error path (~1531), `SignalState`.
   - Failing-first test: signalled finish reports interruption (names signal),
     un-signalled always-refusal keeps current text.
   - Minimal branch on `signals.interrupted()`; verify existing refusal test
     still passes unchanged.
2. **Engine 8: diagnose pinning failures** (debugging, diagnosis-bound)
   Surface: `src/discovery/identity.rs:1167`,
   `crates/manifest/src/identity.rs:71`, engine tests ~23896+.
   - Reproducer: single failing test; `readelf` matrix over fixture variants.
   - Apply Key Decision 2 (product fix with regression test, or hermetic
     fixture). All 8 must go green from one root cause or explicitly split.
3. **Duration env failure** (debugging, ~0.5d)
   Surface: `OwnedChild::spawn`/`release`/`wait_for`, host `/bin/sleep` shim.
   - Diagnose exit-code-1-within-10ms; fix or hermeticize per Decision 2.
4. **Shebang flake** (debugging, ~0.5d)
   - Confirm load-flake (isolated vs full-suite matrix); harden timing
     assumption only; contract assertions untouched.
5. **Suite green gate**: full `cargo test --lib` 828/828 on host, twice.
6. **Doctor cgroup-v2 preflight row** (implementation, ~1h)
   Surface: `src/doctor.rs` `probe()` + `cgroup_check` (~855).
   - New `cgroup_version_check()` row following the existing `Check`/`Status`
     pattern: detect unified hierarchy (`/sys/fs/cgroup/cgroup.controllers`
     present, or `/proc/self/cgroup` `0::/` entry); PASS on v2, FAIL naming
     "cgroup v2 required" otherwise.
   - Failing-first unit tests in `doctor.rs` test module with injected paths
     (no privileges needed); existing doctor tests unchanged-green.
   - Order: runs with Unit 1 (small/safe/host-local), before the suite gate.
7. **Churn baseline + census** (research, ~2–4d guest work)
   Corpus: Fedora guest, libkryoptic + SoftHSM control, dlopen-loop driver
   pattern (already on guest: `~/kryo-loop.c`).
   - Protocol: M settled scans + N churn scans per provider; capture
     tables/slots/counters per run to `evidence/` (new dir, MANIFESTed).
   - Census: false-positive decodes by ELF section; `event_loss` vs tracefs
     ground truth on the fixture control.
   - Deliverable: stability-score definition + ranked fix proposal; stop for
     approval before any engine/BPF change.

## Validation Plan

- Unit 1: new test RED→GREEN; `explicit_always_refuses_rather_than_
  completing_unpaused` unchanged-green; live E2E (host file-caps binary +
  loop workload, SIGTERM mid-pause) shows interruption text.
- Units 2–4: each target test GREEN; `cargo test --lib` full suite 828/828
  twice; the final diff is reviewed hunk by hunk — assertions may only gain
  specificity, never relax (note: `p11scope/src` is git-ignored in this
  workspace, so review the working-tree diff directly, not `git status`).
- Unit 6: new row RED→GREEN; `doctor` full output on this host shows the
  PASS row; no existing doctor row changes meaning.
- Unit 7: evidence bundle with per-run captures + MANIFEST sha256 clean;
  SoftHSM control behaves as predicted (clean settled + churn scans);
  proposal names falsified alternatives, not just the winner.
- Highest-risk validation: Unit 2's choice between product fix and fixture
  fix — a wrong call either weakens a security check or bakes in toolchain
  dependence. It requires the readelf evidence, not judgment.

## Risks / Rollback

- Identity-ranges product fix (if chosen) touches a trust check: keep the
  change boundary-exact (off-by-one only, with a boundary regression test at
  exactly segment start/end); rollback is revert-one-hunk.
- Guest churn runs are disruptive by nature (SIGSTOP/SIGKILL churn, BPF
  attach): confined to the Fedora lane, qual tokens/PINs already recorded;
  kill strays and verify no T-state leftovers after each run

## Outcomes — Unit 7 (churn research COMPLETE 2026-09-15, proposal only, no code)

Baseline (quiescent kryoptic holder, `profile --pid`): 316 attached /
158 slots / 4 tables / 98 names — identical across 6 runs: 3 settled +
mode-1 (1 GFL call) + mode-2 (30 GFL calls, pidfile-verified) + mode-3
(30× true open→close→unload cycles, profiled during post-churn hold).
SoftHSM control: 0/0 (Fedora 2.7 runtime-built table; Jammy 2.6.1 decodes
— version-dependent boundary, already recorded). Evidence:
`evidence/churn-2026-09-15/` + guest `~/mode-{1,2,3}.json`.

Churn (run path, observed DURING 30× dlopen/dlclose cycling, loader
hits=2208 vs settled 0): 954/954/996 attached, 5 tables, same 98 names.

Root cause (mechanism, data + source): per-pass scan re-decodes the
same-shaped tables under DISTINCT `(PinnedObjectId, file_offset)` keys
across reconciles — phantom flicker on Rust `.rodata` plus
runtime-built tables whose offsets are unstable per construction.
`AttachKey` is `(object, file_offset)` (`plan.rs:214`); the merge is
same-key-merge else retire (`plan.rs:613-700`); retired slots stay in
the vec; `ev.slots = plan.slots.len()` (`render.rs:2238`) counts them.
Result: reported slots ≈ N× single-pass, N ≈ reconciles (~3).
Smoking gun: EXACTLY 3.00× slots on 97/98 names with identical name
sets (no new functionality — same tables counted thrice); outlier
`C_GetFunctionList` 9v2 = export-hook + provisional + scan stacking.
`ObjectKey=(dev,ino)` is reload-stable, so pins correctly merge — the
instability is one layer up, in per-pass table offsets.

Falsified: GFL call-count (mode-2 → 316); no-unload worry (old loop DID
fully unload each iteration — sequential open/close nests nothing);
absolute-address keying (source shows file-offset keying); pure
run-to-run variance (settled 6/6 identical; NSS 426v424 shows only mild
±0.5% phantom flicker, not 3×). Two script bugs burned along the way
(dead-pid profiles from a hold-less loop, subshell-pid capture) — the
mode-1/2/3 rerun used pidfile-verified pids and `kill -0` checks.

Stability-score definition (to ship as a feature, not in this unit):
per-capture `stability = active_slots / allocated_slots`
(`slot_by_key.len() / slots.len()` — both already in memory);
per-name `persistence = passes_present / passes_total` (needs a new
pass-membership record per slot); render active/retired split in
`Evidence` + first-seen/last-seen pass on `discovery[].tables[]`.

Ranked fix proposal: (1) render-only: report active vs retired + the
score, no behavior change; (2) cross-generation slot dedup by (file
identity, file_offset, name-set-hash), last-writer-wins, keep
pass-count; (3) address corroboration across reconciles (same struct
addr in a still-mapped region = same table); (4) long-term: count only
GFL-corroborated tables (needs run-path hooks). STOP for approval
before any engine change. DONE 2026-09-15: `event_loss` vs tracefs
audit — counter proven EXACT (entered-drained == reported, 73567/73567
at N=100k; aggregates exact under loss; tracefs 20000/20000 cross-check;
metrics-mode always-0 now documented in usage.md). No code fix needed;
full numbers in the live-capture note item 2 UPDATE.
  (`ps -eo stat` sweep).
- Flake-hunting can spiral: timebox Unit 4 to 0.5d; if unconverged, record
  as known-flake with evidence instead of hardening blindly.
- Rollback for all code units: each is a small isolated diff; revert cleanly.

## Outcomes — K8s deliverable (COMPLETE 2026-09-15, verified on kind)

Shipped `p11scope/deploy/k8s/` (namespace, ServiceAccount, least-privilege
Role+Binding for pods get/list, DaemonSet, test holder), both Dockerfiles,
`scripts/k8s-profile-entry.sh` (in-cluster API resolution + cgroup find +
exec profile, with `--self-test` incl. a pretty-JSON parse regression
test), and committed Gate K1 e2e `scripts/verify-k8s-attach.sh` (kind-only
guard, ctr-based image load, RBAC can-i check, capture oracle, cleanup).
Proven on kind-p11scope (k8s v1.34, kernel 7.0.0-31): 136/136 probes, 68
slots on the holder's preloaded libsofthsm2, `ALL OK` three times
(ubuntu/python3, ubuntu/jq-slim, alpine/static final). Caps settled by
doctor evidence: BPF/PERFMON insufficient at `perf_event_paranoid=4`
(uprobe EPERM) → added SYS_ADMIN, doctor then `verdict: capture
available`. Images, final: observer = musl-static binary
(`static-pie linked`, 6.9 MB, pure-Rust deps + aya made it work first
try) on `alpine:3.24` (34.6 MB total); holder = `ubuntu:26.04` for the
2031 support window, `softhsm2` build-asserted there (162 MB,
test-only). Superseded: ubuntu:24.04 + jq cut (140 MB); distroless
analyzed but not implemented (needs a full entry-point rewrite for no
size win over Alpine). Full rationale + Alpine re-pin maintenance note
in `deploy/k8s/README.md`.

## Outcomes — spike hygiene (COMPLETE 2026-09-15)

`spike/slice1b2-{kernel,loader,loader-bpf,loader-host}` (Slice 1b-2
experiments, executed by nothing — no script/test/workspace member
references them; superseded by `src/discovery/`) moved to
`preserved/2026-09-15-spike-slice1b2/` with a README.txt, following the
existing preserved/ convention. `spike/README.md` now documents what
stays (live G1 fixtures `harness.c`/`expected.txt`, `discover.c` index
reference, `Dockerfile`, `aya-offset-pin` evidence) and where the
bundle went. One live comment updated
(`tests/fixtures/live-discovery-provider.c`); historical plan prose
intentionally untouched. Workspace members verified unchanged.

## Open Questions

None — all remaining unknowns above are execution-time diagnoses with named
first probes, not plan-level choices.
