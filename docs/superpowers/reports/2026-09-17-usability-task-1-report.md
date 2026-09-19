<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Task 1 report: journey trials (2026-09-17 usability pass)

Plan: `docs/superpowers/plans/2026-09-17-usability-pass.md`, Task 1.
Branch: `fix/usability-pass`. Baseline: no behavior change in this task.
Trials executed 2026-09-17/18 (UTC) on kernel 7.0.0-31-generic, unprivileged
(no caps), `TMPDIR=/var/tmp/p11scope-ws-tmp`, `cargo +1.88 --locked --offline`.

## 1. Baseline re-verification (B1–B7)

All seven controller-recon rows confirmed; deviations noted inline.

| # | Probe | Observed (verbatim head + exit) | Match |
|---|-------|--------------------------------|-------|
| B1 | `p11scope --help` | global `usage:` + notes, exit 0 | yes, but see F2: 0 bytes on stdout, all 2372 on stderr |
| B2 | `p11scope profile --help` | byte-identical to B1 (`cmp` clean), exit 0 | yes — see F1 |
| B3 | no args / bad subcommand | `missing subcommand` / `unknown subcommand: frobnicate` + usage, exit 2 | yes |
| B4 | `--version` | stdout exactly `p11scope 0.1.0\n`, stderr empty, exit 0 | yes |
| B5 | bad `--pid` | `p11scope: --pid 99999999: cannot pin pid 99999999: no pidfd and no /proc/99999999/stat`, exit 1 | yes |
| B6 | unprivileged `doctor` | 26 stdout rows (ok/warn/FAIL/n/a) + `capability tier: T0 offline (target unassessed)` + `verdict: capture unavailable; run capture not eligible (none)`, exit **1** | yes; exit recorded = 1. See F3: verdict lacks trailing `\n` |
| B7 | unprivileged `run -- true` | `p11scope: discovery: 0 module(s), …` then `p11scope: starting attach session: hint: …: loading BPF object … Operation not permitted (os error 1)`, exit 1 | yes |

Raw captures: `/var/tmp/p11scope-ws-tmp/usability-t1-probes.txt` (B1–B7),
`/var/tmp/p11scope-ws-tmp/usability-t1-journeys.txt` (J1–J4).

## 2. Journey evidence (J1–J6)

- **J1 fresh eyes — FRICTION.** `--help`, `profile --help`, `doctor --help`
  (and `trace`/`run`/`inspect --help`, all verified) print the same global
  usage: `profile --help` mentions `p11scope trace` and `p11scope inspect`;
  there is no per-subcommand section (F1). Exit-0 help is stderr-only, so
  `p11scope --help | grep …` sees nothing (F2). `help <sub>` is not an alias
  (`unknown subcommand: help`, exit 2).
- **J2 unprivileged — mixed.** `doctor` rows + verdict are good (B6).
  `profile --pid <own-sleep> --duration 1` refuses in 5 lines ending with
  `run \`p11scope inspect --pid …\` or \`p11scope doctor --pid …\` to see why`
  (good) but the attach block is one ~600-char line listing five possible
  causes without saying which applies or pointing at `doctor` (F7).
  `run -- /bin/true` refuses the same way (B7). `inspect --pid <own-sleep>`
  is already good: exit 0, names `ptrace_scope=0`/descendant/`CAP_SYS_PTRACE`
  fixes verbatim (PASS, pinned).
- **J3 wrong target — mixed.** Nonexistent and exited pids produce the
  identical `cannot pin pid N: no pidfd and no /proc/N/stat` (exit 1), so a
  typo and a race read the same, with unexplained `pidfd` jargon (F6).
  `doctor --pid 99999999` is already good: per-row `ENOENT` FAILs + specific
  verdict (PASS). `run -- script.sh` is already good:
  `owned command must be an ELF executable: …; invoke scripts through an
  interpreter`, exit 1 (PASS, pinned).
- **J4 bad flags — mostly PASS.** `--duration banana`, `--ring-bytes 0`
  (`size "0" outside 4K..64M`), `--mode frobnicate`, `trace --duration
  banana` all name the flag + usage, exit 2. Two gaps: `run /bin/true`
  (missing `--`) reports only `unknown argument: /bin/true`, never naming
  the separator (F4); the `--mode` error line never lists valid values
  inline (they appear only in the appended usage; F5, minor).
- **J5 offline build docs — PASS with one gap.** In a scratch copy
  (`git archive HEAD` → `/var/tmp/p11scope-ws-tmp/ux-j5-tree`; worktree
  untouched), the README offline path works verbatim: place the two pinned
  `.crate` archives in `third-party/archives/`, then
  `mise exec -- ./scripts/cargo.sh +1.88 build --locked --offline` finishes
  clean (`Finished dev profile in 1m 07s`). Gap: the README never names the
  archives — the trial derived `aya-0.14.0.crate` + `aya-obj-0.3.0.crate`
  from `third-party/sources.json` (F8). `docs/build-offline.md` is
  export-tarball-only (no tarball exists for a checkout user); it was
  reviewed, not executed, and is out of scope for a checkout trial.
  (`mise install` was not re-run: the pinned toolchain is already installed;
  `mise exec` used it with no network.)
- **J6 K8s docs — partial (light-touch).** A kind cluster already exists
  (`kind-p11scope` is the current context), so the doc was followed as far
  as is safe on a shared, heavily loaded host: all six manifests pass
  `kubectl apply --dry-run=client` (no cluster mutation), and every
  referenced file exists (`Dockerfile.observer/holder`, `daemonset.yaml`,
  `k8s-profile-entry.sh`, `verify-k8s-attach.sh`, `attach-pod.sh`). Gap: the
  manual flow addresses `p11scope/deploy/…`, which fails from the repo root —
  the required cwd (parent of the checkout) is never stated, so a
  fresh-clone user's first command fails (F9). The heavy steps (release
  build, docker builds, image load, apply, exec capture) are **UNRUN** by
  kind-gating judgment: shared cluster + loaded host; the committed Gate K1
  e2e (`verify-k8s-attach.sh`) remains the proven path.

## 3. FRICTION list

| # | Journey | Verbatim core | Why a real user stalls | Pinned in | Fix task |
|---|---------|---------------|------------------------|-----------|----------|
| F1 | J1 | `<sub> --help` ≡ global usage (`cmp` identical) | cannot learn one subcommand; 60-line dump for `doctor --help` | `b2_…`, `j1_…` (equality) | Task 2 |
| F2 | J1 | `--help`: stdout 0 bytes, stderr 2372, exit 0 | `… \| less/grep` shows nothing; breaks the exit-0/stdout convention | `b1_…`, `b2_…` (`stdout.is_empty`) | Task 2 |
| F3 | J2 | doctor stdout ends `…not eligible (none)` (no `\n`, xxd-verified) | shell prompt mangles onto the verdict line | `b6_…` (`!ends_with('\n')`) | Task 3 |
| F4 | J4 | `run /bin/true` → `unknown argument: /bin/true`, exit 2 | the fix is the missing `--`, which the message never names | `j4_run_without_separator_…` | Task 3 |
| F5 | J4 | `--mode: invalid value "frobnicate"` (first line; minor) | valid values only in appended usage, unlike `--ring-bytes`' inline range | `j4_bad_flag_values_…` (first-line pin) | Task 3 |
| F6 | J3 | nonexistent ≡ exited pid: `cannot pin pid N: no pidfd and no /proc/N/stat` | typo vs race indistinguishable; `pidfd` jargon, no next step | `j3_…_share_one_pin_message` (normalized equality) | Task 3 |
| F7 | J2 | `starting attach session: hint: this usually means … (five causes, one line) … See docs/notes/phase5-unsupported.md …` | user must guess which of five causes applies; never points at `p11scope doctor`, which knows | `b7_…` (`!contains("p11scope doctor")`) | Task 3 |
| F8 | J5 | README: "place the exact archives in `third-party/archives/`" (names absent) | user must reverse-engineer `aya-0.14.0.crate` + `aya-obj-0.3.0.crate` from sources.json | `j5_…` (`!contains("aya-0.14.0.crate")`) | Task 4 |
| F9 | J6 | k8s README manual flow: `docker build -f p11scope/deploy/Dockerfile.observer … p11scope` | fails from repo root (`No such file`); required cwd unstated | `j6_…` (prefix pin + referenced-file existence) | Task 4 |

Explicit non-frictions (PASS, pinned so they cannot regress silently):
`inspect` guidance (J2), `doctor --pid` ENOENT rows (J3), script-target
refusal (J3), flag-naming usage errors (J4a/b/e), B3/B4/B5, J5 verbatim build,
J6 manifest validity.

## 4. Gates

- New tests: `tests/ux_journeys.rs`, 16 tests — **GREEN** standalone
  (`cargo +1.88 test --locked --offline --test ux_journeys`: 16 passed,
  0 failed, ~7s). Environment-dependent refusals branch on the observer's
  own `doctor` verdict, so they stay green on capture-capable hosts too.
- `cargo +1.88 fmt --all -- --check`: clean.
- `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings`: clean.
- Every cargo command ran with `TMPDIR=/var/tmp/p11scope-ws-tmp`.
- No behavior change; no sudo/network/new deps/push. J5 ran in a scratch
  copy (worktree `git status` shows only the two new files).

## 5. Full-suite attempt (once, per brief)

- Command: `TMPDIR=/var/tmp/p11scope-ws-tmp cargo +1.88 test --locked --offline --workspace --all-targets`
- Full log: `/var/tmp/p11scope-ws-tmp/usability-t1-suite.log`
- Result: **RED, exit 101** — lib unittests 1052 passed / 0 failed;
  `artifact_contracts`: 115 passed, **4 failed** (cargo stopped scheduling
  further binaries after it, so `ux_journeys` did not execute in-suite;
  it is green standalone per §4). All four failures are in
  `tests/artifact_contracts.rs`, untouched by this task — for controller
  triage, not looping per brief:
  1. `metadata_canary_matrix` — canary self-test `FileNotFoundError: …/eof-child.pid` (timing/load-shaped).
  2. `build_offline_contracts_hold` — `fatal: write error: Disk quota exceeded` / `error: index-pack died` (environmental; shared scratch under sibling load).
  3. `lane13_evidence_finalizes_only_after_owned_cleanup` — lane-13 timing assertion.
  4. `native_helper_suite_recorded_launcher_…` — `recorded launch deadline expired` ×3 (load timing).
- No test was weakened. Stray-process check after the run: no `sleep 287*`
  survivors from this task's probes.
