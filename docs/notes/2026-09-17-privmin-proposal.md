# Privilege-minimization proposal (ranked) — 2026-09-19

Branch `fix/privmin-research`. Research-only: this note proposes; it changes
no product code. **STOP for approval before any product change.**

Inputs: Task 1 re-measured matrix (`docs/notes/phase4-privileges.md`,
2026-09-18 section; `task-1-report.md`) and Task 2 hypothesis verdicts
(`task-2-report.md`). Report paths below are relative to
`.superpowers/sdd/2026-09-17-privmin-research/`.

## Verdicts consumed (with mandatory qualifications)

- H1 file-caps minimal set: **REFUTED** — `{cap_sys_admin,cap_sys_ptrace}`
  reproduces the full-5 outcome; `cap_bpf`/`cap_perfmon`/`cap_dac_read_search`
  redundant given `cap_sys_admin` (task-2-report.md §H1).
- H2 per-command tiers: **PROVEN on intended tiers; literal readout stuck at
  T0 (bug)** — `inspect` works at T0/unpriv, `run` completes at bpf-level
  but attaches 0/136 until admin, `profile`/`trace` need admin
  (task-2-report.md §H2). Never quote without the bug.
- H3 paranoid interaction: **REFUTED** — paranoid 2, 1, 0, -1 all leave
  bpf+perfmon at 0/136 (task-2-report.md §H3).
- H4 helper seccomp posture: **PROVEN on tested paths only (29/37 lane
  scripts `--help`-parity only)** — 61-syscall allowlist, full success-path
  parity for 9 helpers; not full-function proof for the other 29
  (task-2-report.md §H4). Never quote a bare PROVEN.
- H5 root-only lanes: **PROVEN (classification)** — 21/21 lanes run: 5 pass
  with host root, 4 pass without it, 3 blocked by script bugs, 3 version-drift +
  1 unpriv-by-design (lane16), 4 env-blocked at `-o` write, 1 env-unrunnable; needs partly
  inferred from lane privilege gates + Task 1 unpriv baselines
  (task-2-report.md §H5). Never quote without the inference scope.
- Task 1 caveats carried forward: kernel moved 7.0.0-28 → 7.0.0-31 and kind
  v0.29.0 → v0.33.0 since the historical rows, so cross-kernel comparisons
  are host-specific (task-1-report.md:119-122); unpriv-failure map names
  changed per lane (`CONFIG` → `DESCRIPTORS`/`COUNTERS`/… — same EPERM root
  cause; task-1-report.md:125-127); Task 1 minor (c) `...`-truncations in
  measured texts still open-deferred (progress.md).

H1's minimum and H3's refutation are measured on 7.0.0-31-generic only; the
Fedora 6.19 five-cap set may still be minimal there (task-2-report.md:397-400).

## Ranked reductions (evidence strength × risk reduction)

### 1. Fix the doctor tier-readout bug (enables everything tier-based)

- What to change: `capability_tier()` looks up `row_ok("uprobe attach
  (self)")` (`src/doctor.rs:1018`) but the emitted row is `"uprobe attach
  (own libc)"` (`src/doctor.rs:519,530`), so `host_attach` is false in every
  real run. Align the lookup with the row name (or vice versa) and update
  the unit tests, which still use `(self)` and so pass while every real run
  misreports.
- Measured proof: every literal tier line reads `T0 offline (target
  assessed)` at ALL ladder levels including root-with-all-rows-ok
  (task-2-report.md:96-107); `git log -S` roots the rename in `cbb3502`;
  H5 confirms the live consequence (`verify-capability-tier.sh` sysadmin
  row: `assessed: expected T1, got T0`; task-2-report.md:253). Task 1's
  unpriv T0 row (:193) is unaffected — T0 is correct there.
- What could regress: real `doctor` output changes where tiers were earned
  (T0 → T1/T4); any consumer asserting literal T0 breaks — that is the fix
  working, but tier-gated automation must expect the corrected values.
- Suggested verification: `doctor --pid` at each H2 ladder level
  (unpriv/bpf/admin/adminptrace/root) shows intended T0/T0/T1/T4/T4; full
  `verify-capability-tier.sh` passes its live sysadmin row.

### 2. Reduce the file-caps host minimum from 5 caps to `{cap_sys_admin, cap_sys_ptrace}`

- What to change: wherever a file-caps (or ambient-caps) deployment grants
  the historical five (`cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_ptrace,
  cap_dac_read_search`), grant `{cap_sys_admin,cap_sys_ptrace}` instead.
- Measured proof: full-5 baseline vs `{admin,ptrace}` — both exit 0,
  136/136, 0 failures, uncorroborated 0 (task-2-report.md:69-83); each
  member proven necessary (minus-admin → 0/136; minus-ptrace →
  uncorroborated 1); single-drop bisection shows bpf/perfmon/dac removals
  each identical to baseline (task-2-report.md:56-66). Task 1's file-caps
  row is UNRUN with the single-cap hypothesis recorded as unmeasured
  (phase4-privileges.md:200) — H1 supersedes that hypothesis, it does not
  confirm it.
- What could regress: on other kernels the dropped caps may be load-bearing
  (Fedora 6.19 caveat above); `{admin}`-alone deployments lose scan
  corroboration (offsets attached uncorroborated).
- Suggested verification: file-caps probe (`setcap` on a private binary
  copy, per task-2-report.md:44-47) on each target kernel; rerun
  `lane-receipt-lane16.sh` with `{admin,ptrace}` file caps on the observer
  as the end-to-end proof (it is unprivileged-by-design yet needs a passing
  `run` — task-2-report.md:389-393).

### 3. Document and consume per-command privilege floors

- What to change (docs + invocation guidance, no code): `inspect --pid`
  works at T0/unpriv (degraded until ptrace, full at adminptrace);
  `profile`/`trace` need admin (T1 intended; corroborated at
  adminptrace/T4); `run` completes provider-less at bpf-level/T0 but needs
  T1 to attach. Root adds nothing over adminptrace for attach.
- Measured proof: H2 command matrix with unpriv-vs-minimal before/after
  docs per command (task-2-report.md:126-157); ladder rows
  (task-2-report.md:112-119). Consistent with Task 1 unpriv baselines
  (profile/run exit 1 at BPF map create; task-1-report.md:42-71).
- What could regress: callers that run everything as root see no change;
  callers that newly drop privilege per this table could hit the
  T1→T4 ladder jump (T2/T3 unobserved — lifecycle+scope read ok as soon as
  host attach works; task-2-report.md:120-122) or the ptrace-without-BPF
  gap (no tier rung for it; task-2-report.md:128-132).
- Suggested verification: re-run the H2 command matrix after the item-1
  tier fix and assert literal tiers match intended; add the floors to
  `docs/usage.md` only once the tier readout is truthful.

### 4. Adopt the 61-syscall seccomp allowlist for offline helpers (gated on wider coverage)

- What to change: ship the evidence-built allowlist (`h4/union2.txt`;
  launcher `h4/seccomp-run2.c`: `PR_SET_NO_NEW_PRIVS` + classic-BPF,
  default `SECCOMP_RET_ERRNO|EPERM`) for `p11scope-discover` and lane
  scripts — initially opt-in, enforced only after the coverage gate below.
- Measured proof: v2 sweep 37/37 byte-identical filtered vs unfiltered;
  full success-path parity (exit 0 + byte-identical output) for 9 helpers
  (discover + tier oracle on real args, 7 oracles on `--self-test`);
  socket→EPERM negative control proves the filter live
  (task-2-report.md:186-231). Qualification restated: the other 29 lane
  scripts have `--help`-parity only — not full-function proof.
- What could regress: untested paths in those 29 oracles (full input
  matrices) could break under the filter; the v1→v2 tempfile miss
  (`getpid`/`unlink`/`mkdir`/…) is the shape of that risk.
- Suggested verification: extend success-path coverage to the remaining 29
  oracles' full input matrices (open work per task-2-report.md:225-227);
  enforce only when every helper has a real-args byte-identical pair.
  (Incidental: discover itself already calls `capset`/`setresuid` — it
  self-restricts; worth a look alongside.)

### 5. Repair the pre-privilege lane blockers and checkout hygiene (validation prerequisites)

- What to change: (a) `verify-fork-scope.sh:342` tokendir doubling
  (`$PWD/$WORK/tokens` when `$WORK` is absolute — receipt mode can never
  pass); (b) live-discovery `--freeze` never writes `bpf-inventory.json`
  (`check-live-discovery-evidence.py:2857-2862` never calls
  `prepare_private_root`, :1913); (c) item-1 tier-name bug (breaks the
  capability-tier lane live); (d) `/home/user/src` group-writability, which
  env-blocks `-o` writes for docker/kind-pod/knative/proxy-stack lanes
  (`chmod g-w` or a clean checkout path — deliberately not done
  unilaterally, outside the work area).
- Measured proof: H5 lane table with verbatim failures per lane
  (task-2-report.md:249-271); counts (task-2-report.md:273-283). All three
  script bugs fail identically with or without root.
- What could regress: lane evidence goldens that captured the buggy
  behavior (e.g. tier expectations) need updating alongside; the `-o`
  trust check itself (`src/output.rs:401`, `mode & 0o022 && !sticky`) is
  working as designed — changing the checkout, not the check, is the fix.
- Suggested verification: rerun each repaired lane to green; note
  version-drift reds (receipt-lane02 skip counts, ia32 `bpftrace -kk`,
  shared-layer cgroup layout) are not privilege findings either way
  (task-2-report.md:401-404).

## Falsified alternatives (do not pursue)

- **H1's 5-cap minimality** — REFUTED: bpf/perfmon/dac redundant given
  admin on this kernel (task-2-report.md §H1). Do not standardize the 5-cap
  set as minimal.
- **H3's paranoid lever** — REFUTED to -1: no `perf_event_paranoid` level
  drops the `CAP_SYS_ADMIN` need for uprobe attach here
  (task-2-report.md:169-184). Do not propose sysctl relaxation as a
  minimization lever; `docs/usage.md` keeps its `CAP_SYS_ADMIN` wording
  for uprobes (task-2-report.md:394-396).
- **`CAP_BPF`+`CAP_PERFMON` suffices for attach** — refuted: 0/136 with 68
  `perf_event_open` EPERM failures at bpf level, before and after paranoid
  changes (task-2-report.md:171-175; Task 1 UNRUN row phase4-privileges.md:196).
- **`{cap_sys_admin}` alone fully suffices** — refuted for corroborated
  attach: 136/136 but uncorroborated 1 without ptrace
  (task-2-report.md:72); **`{cap_sys_ptrace}` alone** — refuted: NO-DOC,
  map-create EPERM (task-2-report.md:73).
- **Blanket "lanes need root"** — refuted as a blanket claim: 4 lanes pass
  without host root (inspect-doctor fully unprivileged, provider-matrix
  doc-driven, discover-containers and k8s-attach needing only
  docker/cluster; task-2-report.md:273-276) — with H5's inference-scope
  qualification above.

## usage.md disposition

`docs/usage.md` "Privileges, per environment" was compared cell-by-cell
against the Task 1 2026-09-18 re-measurements and left untouched: every
measured unprivileged cell matches the current text and every privileged
cell is UNRUN (details in task-3-report.md). No product change follows
from this proposal without approval.
