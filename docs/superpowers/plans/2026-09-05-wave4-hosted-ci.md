# Wave 4 — Hosted CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:subagent-driven-development` task by task. Each production task
> starts with a failing test, makes the smallest root-cause change, runs focused
> tests, then runs the four canonical Rust 1.88 gates before commit. Use only one
> Cargo-heavy command at a time against the shared target directory. **Never
> push anywhere except `ci/w4-hosted`, which carries the owner's blanket
> approval (2026-09-05) for W4 iteration and the W8 re-run. `origin/main`,
> tags, and releases stay individually gated — never push those.**

**Goal:** Widen the existing, already-proven hosted pipeline
(`.github/workflows/ci.yml`, byte-identical on `origin/main`, hosted run
`31935749796` succeeded 2026-08-16) to the W4 scope — four canonical gates +
every unprivileged validator self-test + the two container-less e2e lanes —
with privileged/container lanes recorded `UNRUN` visibly in the log and job
summary; close the release-blocking stale frozen BPF map inventory at its root
cause (no gate compared the freeze to a built object); make the repo safe to
push (tracked ignore rules for agent state and root build outputs); obtain one
complete hosted run on a CI test branch and record it honestly.

**Architecture:** Reuse the existing single-job pipeline, the existing
`--self-test` idiom of every lane script, the existing Rust artifact-contract
tests that pin `ci.yml` and `scripts/gates.sh` text, and the existing
`embedded_map_definitions()` helper that already reads the embedded BPF
object in `cargo test`. The frozen inventory (`scripts/check-bpf-map-defs.py`)
stays the single source of truth; the new check compares it against the real
embedded object inside the canonical `cargo test` gate, so local and hosted
gates catch drift identically. `UNRUN` visibility is a verbatim lane list in
the log and `$GITHUB_STEP_SUMMARY`, derived and pinned by a Rust test so it
cannot rot. No cache, no badge, no junit producer, no new dependency.

**Tech stack:** Rust 1.88 / edition 2024, GitHub Actions `ubuntu-24.04`
(non-root `runner` user with passwordless sudo, `gh` preinstalled; `ci.yml`
already installs `llvm`, `jq`, `gcc`, `python3`, `softhsm2`, bpf-linker and the
pinned nightly). `actions/checkout@v4` already; add `actions/upload-artifact@v4`.

**Authorities:**

- [W4 charter, corrected 2026-09-05](2026-09-01-release-wave-charters.md#w4)
- [release PRD §9](../specs/2026-09-01-p11scope-release-prd.md)
- [owner requirements §6](../specs/2026-09-01-release-requirements-and-goal.md)
- [ROADMAP execution protocol](ROADMAP.md#agent-execution-protocol-all-waves)
- `CLAUDE.md` (four gates; privileged/container runs owner-gated; allowlist v1)

## Global constraints

- Preserve `docs/privacy/allowlist-v1.md` byte-for-byte. W4 touches no capture
  output, schema, or BPF program logic — only a stale freeze constant.
- Preserve Rust 1.88, the pinned `nightly-2026-05-20`, bpf-linker 0.10.4, Aya
  0.14.0, and the lockfile (`--locked` everywhere; no `Cargo.lock` change).
- Branch: `hardening/wave4-hosted-ci` off `main` `9383707`; one commit per
  task; merge to `main` only after review-to-zero; then push **only**
  `main:ci/w4-hosted` (Task 6). `origin/main` stays `a2a2644`.
- Owner-gated (never autonomous): any push to `origin/main`, any tag, any
  release, any privileged/container run, any cache or CI-host change that
  implies accounts or spend. Pushes to `ci/w4-hosted` are **pre-approved**
  (see the decisions block below) — announce each one, do not re-ask. The
  runner has root; do **not** widen hosted scope to privileged lanes beyond
  `verify-attach-e2e.sh` — that is a scope decision for the owner, not this
  wave.
- **Owner decisions recorded 2026-09-05 — settled; do not re-open:**
  - *Push cadence:* BLANKET approval for pushes to the `ci/w4-hosted` branch
    specifically. W4 may iterate and W8 may re-run without asking each time.
    `origin/main`, tags, and releases remain individually gated.
  - *Hosted self-test scope:* hosted CI runs **every** validator self-test via
    the mechanical rule in Task 3 — all 20 self-test-capable scripts except
    `scripts/gates.sh`, the local entry point that only invokes the others —
    not just the 7 wired today. Same root-cause logic as the `CONFIG` fix:
    prefer a rule that cannot silently drift over an enumerated list.
  - *Log archival:* keep the Task 5 `actions: read` job-token approach, not a
    `tee` wrapper. Pass 2 confirmed `actions: read` suffices and that `tee`
    would force re-pinning every lane line.
  - *Still open (owner question, Task 7 honesty item 4):* the `Cargo.toml`
    `repository` URL vs the actual remote name.
- Honest evidence only: privileged/container lanes are `UNRUN` hosted, named
  verbatim; a green step never implies a lane ran (`verify-capability-tier.sh`
  prints `UNRUN:` and exits 0 — visibility must come from log/summary text).
- `act` is absent and is not an evidence path. YAML validity is proven only by
  the hosted run, so every `ci.yml` edit mirrors an existing line shape and is
  reviewed line by line before each push.
- Any `ci.yml` edit updates its pinning tests in `tests/artifact_contracts.rs`
  in the same task (`production_bpf_toolchain_is_frozen` at ~:5708 and
  `every_gate_script_self_tests_its_own_validator` at ~:7477, which pins the
  block marker `# Unprivileged validator self-tests:` at `ci.yml:24`, one
  `- run: <script> --self-test` line per gate, and exactly one capability-tier
  self-test line inside that block).
- **`ci.yml:24` is byte-frozen.** `every_gate_script_self_tests_its_own_validator`
  splits on the literal `      # Unprivileged validator self-tests:` at
  `tests/artifact_contracts.rs:7493`, through `between()` (`:12-20`), which
  **panics** — not fails cleanly — when a marker is missing. Any comment
  rewording in that block edits only the continuation lines `ci.yml:25-26`.
- **Four operator docs are pinned too**, by a test this plan's Task 7 must not
  break: `operator_docs_preserve_semantic_authority_limits`
  (`tests/artifact_contracts.rs:5597`). Whitespace-normalized and lowercased it
  requires — `README.md`: `exact-tip runtime qualification` + `pending`, and
  `previous frozen mvp passed` + `w3 tip` + `remain pending`; `docs/usage.md`:
  `exact-tip runtime qualification` + `pending`, `runtime qualification` +
  `remain pending`, `frozen pre-w3 candidate`, `not been repeated on the w3
  tip`; `CHANGELOG.md`: `exact-tip ci` + `pending`, the literal
  "Public `run`, owned-child live discovery", `unreleased`;
  `docs/superpowers/plans/ROADMAP.md`: `exact-tip CI` (case-sensitive, via the
  non-lowercased arm), `exact-tip ci` + `pending`, `ci remains pending` + `no
  release or security-clearance claim applies yet`. Live text lives at
  `README.md:239`, `docs/usage.md:496-498`, `CHANGELOG.md:10`,
  `ROADMAP.md:411` and `:466-467` — i.e. Task 7 rewrites sentences this test
  pins, so it reruns the test before its canonical gates.
- Durable output only in `pkcs11-scope` and `p11scope-ws`; hosted-run evidence
  (text) is committed in `p11scope-ws`.

## Task 0: Verified anchors (pass 2 over this plan)

**Files:**

- Create: this plan
- Modify: nothing else

Planning-time anchors (2026-09-05, local `main` = `9383707`, tree
`a14876e0c48103bc391aa745f79b7a1f86de9c1c`; `origin/main` remote-tracking =
`a2a2644`, tree `1bbe21f1735b1c7a9d27ca08e2ed8faef2023948`, unfetched since
2026-08-21; remote `git@github.com:mingulov/p11scope.git`; `gh` authenticated
as `mingulov`):

- Stale freeze: `scripts/check-bpf-map-defs.py:103` pins
  `"CONFIG": (2, 4, 8, 1, 128)`; `crates/ebpf/src/main.rs:57` declares
  `Array::with_max_entries(2, BPF_F_RDONLY_PROG)`; `validate_policy_inventory`
  at `:143` compares two objects only in `--policy-inventory` mode.
- The Rust side already knew the truth and never compared it to the freeze:
  `tests/artifact_contracts.rs:4692` asserts
  `embedded_map_definitions()["CONFIG"][3] == 2`; the helper at `:647` writes
  `p11scope::EBPF_OBJECT` (`src/lib.rs:29`) to a temp file and reads it with
  `llvm-readelf`/`llvm-objcopy` — so llvm tools are already a `cargo test`
  prerequisite locally and in CI.
- Hosted-full lanes today: `ci.yml:34-35` (`verify-inspect-doctor.sh`,
  unprivileged; `verify-attach-e2e.sh`, uses `sudo` at `:178`, passed hosted).
- Self-test-capable scripts (20): `scripts/{attach-pod,build-release,gates,
  verify-attach-e2e,verify-canaries,verify-capability-tier,
  verify-discover-containers,verify-induced-gaps,verify-inspect-doctor,
  verify-live-discovery-preflight,verify-task4-lane02,verify-task4-lane16}.sh`,
  `scripts/{check-bpf-map-defs,check-capture-evidence,
  check-live-discovery-evidence,check-live-discovery-object,
  dump-owned-bpf-maps}.py`, `scripts/matrix/verify-{fork-scope,oracle,
  shared-layer}.sh`. Their `--self-test` dependencies, verified by running all
  12 hosted candidates as the non-root user (all exit 0, in seconds):
  **11 are pure Python/shell model checks** with no sudo, docker, cargo, or
  bpftool call. **`verify-task4-lane02.sh` is the exception** and needs more
  than that: it compiles with `gcc` (`:287`, `:290`, `:291`) against the
  tracked `spike/harness.c`, reads the result with `readelf` (`:293`), and runs
  the compiled binary under `timeout 5` (`:298`). All three are available
  hosted — `ci.yml:18` installs `gcc`, and `binutils` (`readelf`) and
  `coreutils` (`timeout`) are preinstalled on `ubuntu-24.04`. It also
  **depends on the runner being non-root**: its `--self-test` (`:437-441`)
  re-invokes its own body with `RUSTFLAGS` set and requires exit 77 from the
  inherited-variable refusal (`:686-690`, `exit 77` on `:689`), and
  `require_non_root_caller` (`scripts/lib.sh:11-16`) runs first at `:469`,
  before that exit-77 path. The GitHub runner is the non-root `runner` user, so
  this holds — but it is a precondition to state, not a property of the script.
- Privileged verify lanes (non-comment `sudo`/`docker`/`kind` line, 15):
  `scripts/verify-{attach-e2e,canaries,capability-tier,discover-containers,
  induced-gaps,live-discovery-preflight,task4-lane02,task4-lane16}.sh` and
  `scripts/matrix/verify-{docker,fork-scope,kind-pod,knative,oracle,
  proxy-stack,shared-layer}.sh`.
- Hygiene: `.gitignore` has `/.superpowers/sdd/` only; `.claude/` is ignored
  solely by `.git/info/exclude`; `p11scope`/`p11scope-discover` at the root
  are not ignored (blob `cd3d946…` "p11scope" entered history in `c495caa`,
  2026-08-10). `.codex/` is tracked (agent role configs) — leave it.
  `Cargo.toml:7`, `crates/manifest/Cargo.toml:7`, `crates/discover/Cargo.toml:7`
  say `repository = ".../pkcs11-scope"`; the remote is `.../p11scope.git`.

- [ ] Dispatch independent read-only verifiers over every file:line and
  behavioral claim above and in Tasks 1–7; adjudicate; fold corrections into
  this plan and commit before Task 1.
- [ ] Read-only remote re-verification is allowed here (`git fetch origin`
  updates only the remote-tracking ref; it is not a push): confirm
  `origin/main` is still `a2a2644` and a strict ancestor of local `main`, and
  that `refs/heads/ci/w4-hosted` does not exist. If either differs, stop and
  report to the owner before any further step.

Commit: `docs: plan wave 4 hosted CI`

## Task 1: Pre-push repository hygiene

**Files:**

- Modify: `.gitignore`
- Modify: `tests/artifact_contracts.rs`

Must land before any push. Nothing in `.claude/` or `.superpowers/` may ever be
publishable by a repo rule that does not travel with the repo.

- [ ] RED: `tracked_ignore_rules_cover_agent_state_and_root_binaries` runs
  `git check-ignore -v <path>` for `.claude/worktrees/x`, `.superpowers/x`
  (not under `sdd/`), `p11scope`, and `p11scope-discover`, and asserts each
  line's source is `.gitignore` (format `source:line:pattern<TAB>path`). Today
  the first resolves to `.git/info/exclude` and the other three are not
  ignored at all. Also assert `git ls-files` returns nothing under `.claude/`
  or `.superpowers/`.
- [ ] GREEN: add `/.claude/`, `/.superpowers/`, `/p11scope`,
  `/p11scope-discover` to `.gitignore`; drop the now-redundant
  `/.superpowers/sdd/` line unless a test pins it (`grep -rn superpowers tests/`
  first). Do not touch `.git/info/exclude`.
- [ ] Do **not** change `Cargo.toml:7` in this task. Record the
  `pkcs11-scope` vs `p11scope.git` mismatch as an OWNER QUESTION in the wave
  report (Task 7): fix all three `repository` fields only if the owner
  confirms the public repository name; GitHub redirects renamed repos, which
  cannot be verified offline.
- [ ] Focused checks:
  `cargo +1.88 test --locked --test artifact_contracts tracked_ignore_rules`,
  `git status --porcelain --ignored | grep -E '^!! (\.claude|\.superpowers)/'`
  shows both directories ignored; then four canonical gates; commit.

Commit: `chore: ignore agent state and root build outputs by tracked rules`

## Task 2: Frozen BPF inventory compared against the built object

**Files:**

- Modify: `scripts/check-bpf-map-defs.py`
- Modify: `tests/artifact_contracts.rs`
- Modify: `.github/workflows/ci.yml`

Release-blocking (charter): `--policy-inventory` fails on any built object,
which breaks `scripts/verify-canaries.sh` (G3), `scripts/verify-induced-gaps.sh`,
and `scripts/build-release.sh` (Lane 14). Verified drift: exactly
`CONFIG.max_entries 1 → 2` (W3 `02eedbd`), no map added or removed. Root
cause: the freeze was only ever checked against itself (`--self-test`), never
against an object, in any gate that actually runs.

- [ ] Add the checker mode first so the RED test fails for the right reason:
  `--inventory {default|diagnostic} BPF_ELF` validates ONE object's maps and
  programs against `SAFE_*` or `UNSAFE_*` (split `validate_policy_inventory`
  into a per-object `validate_inventory(variant, maps, programs, symbols)`
  reused by `--policy-inventory`, which keeps the cross-object decoder-symbol
  checks). On mismatch print a field-level diff — maps added, maps removed,
  and every `NAME.field: object=X frozen=Y` — before raising
  `default map inventory differs`. Extend `self_test()`: a default inventory
  labelled `diagnostic` is rejected (missing `ATTR_BOOL_BITS`), a diagnostic
  inventory labelled `default` is rejected, and a one-field mutation reports
  exactly `CONFIG.max_entries`. These three cases land before any Rust RED test
  exists, so keep them honest test-first: **confirm each new `self_test()` case
  actually fails against a deliberately mutated model** (temporarily break
  `validate_inventory` — e.g. drop the variant check, drop the per-field diff —
  and see the case fail) **before wiring it in**; a case that passes against a
  broken model is not a check.
- [ ] RED: `frozen_policy_inventory_matches_embedded_object` in
  `tests/artifact_contracts.rs`: write `p11scope::EBPF_OBJECT` to a temp file
  (same shape as `embedded_map_definitions()`), run
  `python3 -I scripts/check-bpf-map-defs.py --inventory <variant> <file>`
  with `<variant>` = `diagnostic` when
  `cfg!(feature = "unsafe-unvalidated-metadata")` else `default`, and assert
  success plus the printed `inventory <variant>: maps=N programs=M OK` line
  (16/13 default, 17/17 diagnostic). It fails today with the one-line diff
  `CONFIG.max_entries: object=2 frozen=1`. Record that output verbatim for
  the report — it is the proof of "exactly one drift".
- [ ] GREEN: `"CONFIG": (2, 4, 8, 2, 128)`. No other constant changes.
- [ ] RED: `hosted_pipeline_checks_the_diagnostic_inventory` asserts `ci.yml`
  contains the exact line
  `- run: cargo +1.88 test --locked --features unsafe-unvalidated-metadata --test artifact_contracts -- frozen_policy_inventory_matches_embedded_object`
  after the clippy gate line and before the `uname -r` line. (The default
  object is covered by the ordinary `cargo test` gate for free; only the
  diagnostic object needs its own hosted step. Do not run the whole
  `artifact_contracts` target under the feature — `immutable_policy_maps`
  correctly asserts `ATTR_BOOL_BITS` is absent from the default object.)
- [ ] GREEN: add that line to `ci.yml`. Re-run the two existing `ci.yml`
  pinning tests; the line sits outside the `# Unprivileged validator
  self-tests:` block, so they must stay green unchanged.
- [ ] Unprivileged end-to-end proof of the repaired `--policy-inventory`
  path (this is what the three blocked lanes call): build the two objects the
  way `scripts/verify-canaries.sh:1760-1763` does (the two
  `cargo +1.88 build … --target-dir` invocations), into a private temp root
  (`cargo +1.88 build --locked --release --workspace --target-dir "$W/default-build"`
  and the same with `--features unsafe-unvalidated-metadata` into
  `feature-build`), then resolve the two objects and call the checker the way
  `scripts/verify-canaries.sh:1774-1780` does (glob, uniqueness assertion, then
  `--policy-inventory`):
  `python3 -I scripts/check-bpf-map-defs.py --policy-inventory "$W"/default-build/release/build/p11scope-*/out/p11scope-ebpf "$W"/feature-build/release/build/p11scope-*/out/p11scope-ebpf`
  prints `policy inventory: default maps=16 programs=13; diagnostic maps=17 programs=17 OK`.
  Cargo-heavy: run serially. The privileged lanes themselves stay `UNRUN`.
- [ ] Focused checks:
  `cargo +1.88 test --locked --test artifact_contracts frozen_policy_inventory`,
  `cargo +1.88 test --locked --features unsafe-unvalidated-metadata --test artifact_contracts -- frozen_policy_inventory_matches_embedded_object`,
  `python3 -I scripts/check-bpf-map-defs.py --self-test`,
  `sh scripts/verify-induced-gaps.sh --self-test`,
  `cargo +1.88 test --locked --test artifact_contracts dynamic_task_newtask_offsets`;
  then four canonical gates; commit.

Commit: `fix: compare the frozen BPF inventory against the built object`

## Task 3: Widen the hosted lane set to every unprivileged self-test

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `tests/artifact_contracts.rs`

Charter scope: the unprivileged suite runs hosted. Today CI runs 7 of the 20
`--self-test` modes (`ci.yml:27-33`); `scripts/gates.sh` runs 8 (`:8-14` — the
seven-gate loop plus `check-live-discovery-evidence.py`). Excluding
`scripts/gates.sh` itself, that leaves **12 missing** hosted. The owner settled
this scope on 2026-09-05: every self-test runs hosted, by a mechanical rule, so
a future lane cannot be added without its hosted self-test.

- [ ] RED: `hosted_pipeline_runs_every_unprivileged_self_test` walks
  `scripts/` and `scripts/matrix/` for `*.sh`/`*.py` whose text contains
  `--self-test`, excluding `scripts/gates.sh` (local root entry point; it
  only invokes others' self-tests), `scripts/lib.sh`, `scripts/cleanup-traps.sh`,
  and `scripts/fixtures/`. For each it requires a trimmed `ci.yml` line equal
  to `- run: <path> --self-test` (sh) or `- run: python3 <path> --self-test`
  (py). Fails today for 12 scripts: `attach-pod.sh`, `build-release.sh`,
  `check-bpf-map-defs.py`, `check-capture-evidence.py`,
  `check-live-discovery-object.py`, `dump-owned-bpf-maps.py`,
  `verify-canaries.sh`, `verify-task4-lane02.sh`, `verify-task4-lane16.sh`,
  `matrix/verify-{fork-scope,oracle,shared-layer}.sh`.
- [ ] Before GREEN, run each of the 12 locally as the non-root user with no
  sudo cached (`sudo -k`) and record exit 0 and its `... self-test: OK` line;
  a self-test that needs privilege is a defect to report, not to wire in.
- [ ] GREEN: add the 12 lines inside the existing block, i.e. between
  `# Unprivileged validator self-tests:` (`ci.yml:24`) and the terminator line
  `- run: python3 scripts/check-live-discovery-evidence.py --self-test`, which
  stays last so `every_gate_script_self_tests_its_own_validator` keeps its
  block boundaries and its "exactly one capability-tier self-test" count.
  Rewrite **only the continuation lines `ci.yml:25-26`** to the W4 truth (every
  self-test-capable script, unprivileged; the live lanes follow). The line-24
  prefix `      # Unprivileged validator self-tests:` — six leading spaces,
  trailing colon — is **byte-frozen**: it is the split literal at
  `tests/artifact_contracts.rs:7493`, and `between()` panics rather than fails
  if it moves. Keep `scripts/verify-inspect-doctor.sh` and
  `scripts/verify-attach-e2e.sh` full runs unchanged.
- [ ] Focused checks:
  `cargo +1.88 test --locked --test artifact_contracts hosted_pipeline_runs_every`,
  `cargo +1.88 test --locked --test artifact_contracts every_gate_script_self_tests_its_own_validator`;
  then four canonical gates; commit.

Commit: `ci: run every unprivileged validator self-test hosted`

## Task 4: Honest UNRUN reporting in the log and the job summary

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `tests/artifact_contracts.rs`

- [ ] RED: `hosted_pipeline_names_every_unrun_privileged_lane` derives the
  privileged set = `scripts/verify-*.sh` ∪ `scripts/matrix/verify-*.sh` with a
  non-comment line containing the word `sudo`, `docker`, or `kind`; the
  hosted-full set = `ci.yml` lines `- run: scripts/<verify-…>.sh` with no
  argument; expected `UNRUN` = privileged − hosted-full (today 14 lanes; only
  `verify-attach-e2e.sh` is subtracted). It extracts the `ci.yml` block
  between the comment markers `# UNRUN lanes begin` and `# UNRUN lanes end`,
  then — **collecting `scripts/…` tokens ONLY from lines whose trimmed text
  starts with the literal prefix `UNRUN: `** — asserts set equality against
  that expected set. This prefix filter is load-bearing, not a detail: the
  GREEN block also carries a `hosted:` line naming
  `scripts/verify-inspect-doctor.sh` and `scripts/verify-attach-e2e.sh`, whose
  tokens are inside the markers but deliberately outside the `UNRUN` set — a
  naive "every `scripts/…` token in the block" collector can never reach set
  equality. It further asserts that every lane line carries that `UNRUN: `
  prefix (the `verify-capability-tier.sh` idiom), that the block appends to
  `$GITHUB_STEP_SUMMARY`, and that the block is the **first step after
  `- uses: actions/checkout@v4`**, so it reaches the log even when a later step
  fails. Fails today: no block.
- [ ] GREEN: one `run: |` step (`shell: bash`) placed **immediately after
  `- uses: actions/checkout@v4` (`ci.yml:12`)**, not after `uname -r`. Placing
  it after `ci.yml:23` would put it behind all four cargo gates, so a failing
  `cargo test` would suppress the `UNRUN` list entirely — the opposite of the
  stated rationale. Everything it needs (`git`, `$GITHUB_SHA`, `$RUNNER_TEMP`,
  `$GITHUB_STEP_SUMMARY`) exists straight after checkout. It is delimited by
  the two markers and writes to `$RUNNER_TEMP/lanes.txt`: one
  `commit $GITHUB_SHA tree $(git rev-parse 'HEAD^{tree}')` line, one `hosted:`
  line naming the four gates, "every --self-test",
  `scripts/verify-inspect-doctor.sh` and `scripts/verify-attach-e2e.sh`, and
  one line per lane, verbatim paths, in one of two forms chosen by the same
  derivation the test uses — whether `ci.yml` runs that script's `--self-test`:
  `UNRUN: <path> (privileged/container lane body UNRUN hosted; its unprivileged
  self-test ran above; local run needs owner approval)` for the 10 lanes that
  have one after Task 3, and
  `UNRUN: <path> (privileged/container lane body UNRUN hosted; no self-test;
  local run needs owner approval)` for the 4 `matrix/verify-{docker,kind-pod,
  knative,proxy-stack}.sh` lanes that do not. A flat "lane UNRUN" label would
  be misleading after Task 3 — 10 of these 14 scripts *do* execute hosted, just
  not their lane bodies — and that misleading-label failure mode is exactly
  what the charter targets. `cat` the file to stdout and append it inside a
  fenced code block to `$GITHUB_STEP_SUMMARY`. Comment: a passing self-test
  exercises a lane's oracle model, never the lane; a green job never implies
  these ran; the list is derived and pinned by the Rust test.
- [ ] Focused checks:
  `cargo +1.88 test --locked --test artifact_contracts hosted_pipeline_names_every_unrun`;
  run the step body locally with `GITHUB_STEP_SUMMARY=$(mktemp)` and
  `GITHUB_SHA=$(git rev-parse HEAD)` and eyeball both outputs; then four
  canonical gates; commit.

Commit: `ci: name every unrun privileged lane in the log and job summary`

## Task 5: Run-log retention

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `tests/artifact_contracts.rs`

A step cannot read its own job's log, and wrapping every lane line in a `tee`
would break the exact-line pins. The lazy, faithful option is a second job
that downloads the finished job log through the Actions API and uploads it.
**Settled by the owner 2026-09-05:** keep this `actions: read` token approach —
pass 2 confirmed `actions: read` suffices for the two `gh api` calls and that a
`tee` wrapper would force re-pinning every lane line. Not an open question.

- [ ] RED: `hosted_pipeline_retains_the_job_log` asserts `ci.yml` has a job
  `archive-log` with `needs: checks-and-e2e`, `if: always()`, a job-level
  `permissions:` block granting only `actions: read` (the top-level
  `permissions: contents: read` stays as is and `checks-and-e2e` gains no
  permission), a step using `actions/upload-artifact@v4` with
  `if-no-files-found: error` and `retention-days: 90`, and a fetch of
  `actions/jobs/<id>/logs`. Fails today: single job.
- [ ] GREEN: the job (`runs-on: ubuntu-24.04`, `env: GH_TOKEN: ${{ github.token }}`):
  `gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/jobs" --jq '.jobs[] | select(.name == "checks-and-e2e") | .id'`
  → `gh api "repos/$GITHUB_REPOSITORY/actions/jobs/$JOB_ID/logs" > "$RUNNER_TEMP/checks-and-e2e.log"`
  → upload as artifact `checks-and-e2e-log`. **Wrap the log fetch in a bounded
  retry — 3 attempts, `sleep 5` between them, fail after the third** — because
  `…/jobs/<id>/logs` can return 404 for a short window right after the job
  completes, while the log is still being finalized. Note in a comment that
  this endpoint answers **302 to blob storage** and `gh api` follows it: a 302
  in a verbose trace is the success path, not a failure, so a reviewer does not
  misread it. No cache is added anywhere (charter: "honest" is trivially true
  today and must stay so).
- [ ] Focused checks:
  `cargo +1.88 test --locked --test artifact_contracts hosted_pipeline_retains`;
  the two `gh api` calls cannot be exercised locally against a live run —
  their first real execution is Task 6, which is why this task is reviewed
  line by line before the push; then four canonical gates; commit.

Commit: `ci: retain the hosted job log as a run artifact`

## Task 6: Review-to-zero, merge, the branch push, the hosted run, exit evidence

**OWNER-GATED throughout.** No commit in `pkcs11-scope` from this task; its
output is the evidence directory in `p11scope-ws` and the inputs to Task 7.

**Files:**

- Create: `/home/user/src/m/p11scope-ws/evidence/<execution date>-w4-hosted-ci/`
  (`run.json`, `run.log`, `summary.txt`, `tree.txt`, `artifact/` listing,
  `MANIFEST.sha256`) — text only, committed in `p11scope-ws`.

- [ ] Review-to-zero **before** the push so the pushed tip is the reviewed
  tip: Sol correctness/security lane (includes the YAML, the token permission
  widening in Task 5, and the ignore rules) and Luna test-quality/regression
  lane over the full `main..hardening/wave4-hosted-ci` diff; batch accepted
  fixes TDD-style; repeat with fresh agents until a cycle accepts zero.
- [ ] `superpowers:finishing-a-development-branch`: merge to `main` locally;
  rerun all four gates on merged `main`; record the tip `T_code` and
  `git rev-parse T_code^{tree}`.
- [ ] Pre-push audit (read-only): working tree clean; `git fetch origin` and
  confirm `origin/main` = `a2a2644` and `git merge-base --is-ancestor origin/main main`;
  `git ls-remote --heads origin ci/w4-hosted` empty;
  `git ls-files | grep -E '^(\.claude|\.superpowers)/'` empty;
  `git rev-list --objects origin/main..main | git cat-file --batch-check='%(objecttype) %(objectsize) %(rest)' | awk '$1=="blob" && $2>1000000'`
  lists every >1 MB blob about to become public (expected: none — show the
  owner regardless);
  `git diff origin/main..main | grep -nE 'BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE|ghp_|AKIA'`
  empty. Anything unexpected → stop, report, no push.
- [ ] **Pre-approved push (owner blanket approval, 2026-09-05, for
  `ci/w4-hosted` only):** `git push origin main:ci/w4-hosted`. Announce it, do
  not re-ask; run it once, record the UTC time and the pushed SHA. This
  publishes W3+ content on a visible non-default branch; `origin/main` is
  untouched and stays individually gated, as do tags and releases. The
  pre-push audit above is still mandatory — blanket approval covers the
  destination, not skipping the checks.
- [ ] Watch: `gh run list --branch ci/w4-hosted --commit <sha> --json databaseId,status,conclusion,url`
  then `gh run watch <id>`; on completion
  `gh run view <id> --json databaseId,url,conclusion,headSha,headBranch,createdAt,updatedAt,jobs > run.json`,
  `gh run view <id> --log > run.log`, extract the `UNRUN lanes` block into
  `summary.txt`, `gh run download <id> -n checks-and-e2e-log -D artifact/`
  (proves the Task 5 artifact exists), and
  `gh api repos/mingulov/p11scope/git/commits/<sha> --jq .tree.sha` alongside
  the local `git rev-parse <sha>^{tree}` into `tree.txt`; both must equal
  `T_code`'s tree. `sha256sum` every file into `MANIFEST.sha256`; commit in
  `p11scope-ws`.
- [ ] If `conclusion` ≠ `success`: triage from `run.log`; every fix is a new
  TDD task on the wave branch, re-reviewed, merged, and re-pushed to
  `ci/w4-hosted` under the same blanket approval — announce each repeated push
  and re-run the pre-push audit, but do not stop to ask. Keep every run's
  record (`run-1/`, `run-2/`, …); never overwrite or delete an earlier run's
  evidence.
- [ ] Exit evidence for the report: run URL and ID, `success`, head SHA,
  tree hash (remote and local, equal), the verbatim `UNRUN:` lines from the
  log, the artifact name/ID, the runner kernel line, and the pipeline's own
  `inventory diagnostic: … OK` and `policy inventory` outputs.

**Known limitation, decided here:** Task 7's report commit is docs-only and
lands after the run, so the W4-closing tip `T_close` = `T_code` + docs. The
charter's "tree hash matching local main's W4-closing tip" is satisfied for
`T_code`, with `git diff --stat T_code T_close` in the report proving the
delta is `docs/` only. An exact-`T_close` hosted run needs one more push to
`ci/w4-hosted`, which the blanket approval already covers — take it if it is
cheap, announce it, and record it as `run-2/`; W8 re-runs on the final tip
regardless.

## Task 7: W4 closeout report and honesty section

**Files:**

- Create: `docs/superpowers/reports/<execution date>-wave4-hosted-ci-closure.md`
- Modify: `docs/superpowers/plans/ROADMAP.md` — W4 table row gains
  `[plan](2026-09-05-wave4-hosted-ci.md) / [closure](../reports/…)`; a
  W4-gate paragraph next to the W3 one; the `:371` "canary suite is green
  locally, not in CI" bullet restated to its final scope; a one-line dated
  note under the historical sentence at `:126-127` (it begins "The remaining
  caveat is unchanged and structural:" on `:126`; the fragment "because this
  repo still has no CI pipeline" is on `:127`) rather than a rewrite of dated
  history.
- Modify: `docs/superpowers/plans/2026-09-01-release-wave-charters.md` — W4
  exit-evidence pointer only.
- Modify: `README.md:239` ("No remote exact-tip CI … is claimed") and
  `docs/usage.md:496-498` ("Exact-tip runtime qualification, CI, complete
  packaging, publication, and release remain pending") — one-sentence truth
  edits naming the branch, SHA, and hosted scope; the full truth pass stays W8.
- Modify: `CHANGELOG.md` only if its `Unreleased` convention requires a line.
- Modify: this plan — tick the boxes; record commits.

**All four of those documents are pinned** by
`operator_docs_preserve_semantic_authority_limits`
(`tests/artifact_contracts.rs:5597`) — see the required phrases in Global
constraints. The `docs/usage.md` sentence being edited here *is* the pinned
one, so the edit must keep `exact-tip runtime qualification` + `pending` and
`runtime qualification` + `remain pending` intact (adding what now *is* true
about hosted CI, not deleting what stays pending). Same for the `ROADMAP.md`
case-sensitive `exact-tip CI` token.

- [ ] Report sections, mirroring the W3 closure: Outcome; Verification (four
  gates with test counts on `T_code` and on `T_close`; the focused tests by
  name); the frozen-inventory defect record (verbatim one-line diff, root
  cause, the gate that now catches it locally and hosted); Hosted run
  evidence table (run URL/ID, conclusion, SHA, tree hash local = remote,
  kernel, artifact, `p11scope-ws` path + manifest hash); the `UNRUN` lane
  list verbatim from the log (14 lanes, or whatever the pinned test derived);
  Runtime evidence boundary (privileged/container/VM rows `UNRUN`, never
  inherited).
- [ ] Honesty section, explicit: (1) **no default-branch status** —
  `origin/main` stays `a2a2644`; no badge; status is per branch/commit;
  (2) the `ci/w4-hosted` push **publishes W3+ content** on a visible
  non-default branch — "stale main" hides it from the default view only, is
  not a privacy control, and W1/W2 were already public; (3) `.codex/` agent
  role configs are tracked and public — noted, not changed; (4) the
  `Cargo.toml` `repository` mismatch — OWNER QUESTION, still open; (5) the
  `T_code` vs `T_close` tree-hash limitation and the optional re-push;
  (6) push approval — **settled 2026-09-05**: blanket owner approval for
  `ci/w4-hosted` (W4 iteration and the W8 re-run), `origin/main`/tags/releases
  still individually gated; state how many pushes were actually made;
  (7) **"privileged lanes stay local by design" is not literally true** —
  `scripts/verify-attach-e2e.sh` uses `sudo` (`:178`) and *does* run hosted in
  full, on the runner's passwordless root. The derivation subtracts it
  correctly (privileged 15 − 1 hosted = 14 `UNRUN`), but the charter sentence
  overstates; say plainly that one privileged lane runs hosted and the other
  14 do not.
- [ ] Requirements-spec §6 "CI runs the suite hosted, not only locally" and
  the PRD §9 item 2 verdict ("Four canonical gates green on `main`; hosted CI
  runs the suite" — PRD §9 at `:217` is a plain numbered list with no
  sub-headings, so cite it as "§9 item 2", never "§9.2"), argued with the
  corrected charter's criteria and filled
  from Task 6 evidence: **MET** when one hosted run of the current pipeline
  (four gates + every unprivileged self-test + the two container-less lanes +
  both inventory checks) completed with `success` on `T_code` with the
  `UNRUN` list visible in log and summary and the log archived; privileged
  lanes being local-by-design is inside the charter's definition of "the
  suite", so their absence does not downgrade the verdict, but the residue is
  listed verbatim. **PARTIALLY MET** when the run succeeded but the artifact
  or archive step failed, or the run's tree differs from `T_code` by more
  than the docs-only delta. **UNMET** when no hosted run of the current
  pipeline completed (`success` on an older pipeline is not evidence). Never
  treat a dormant pipeline as satisfying the bullet.
- [ ] **After the doc edits and before the canonical gates**, run
  `cargo +1.88 test --locked --test artifact_contracts operator_docs_preserve`.
  This is the one red gate a docs-only task can land: it pins `README.md`,
  `docs/usage.md`, `CHANGELOG.md` and `ROADMAP.md`, all four of which this task
  edits. Catch it here, not in the final gate run.
- [ ] Four canonical gates on `T_close`; commit on `main`.

Commit: `docs: close wave 4 hosted CI`

## Canonical gates

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

## Execution order

1. Task 0 — pass-2 anchor verification; read-only remote re-check.
2. Task 1 — tracked ignore rules (before anything is pushable).
3. Task 2 — frozen inventory vs built object; `CONFIG` fix; diagnostic CI step.
4. Task 3 — every unprivileged self-test hosted.
5. Task 4 — `UNRUN` lanes in log and summary.
6. Task 5 — job-log artifact.
7. Task 6 — review-to-zero, merge, pre-approved push to `ci/w4-hosted`, run,
   evidence into `p11scope-ws`.
8. Task 7 — closure report, honesty section, §6 / PRD §9 item 2 verdict.

## What W4 does NOT cover

- Running any privileged, container, kind, Knative, VM, or proxy-stack lane
  hosted or locally (all `UNRUN`; W5/W6/W8 and owner approval).
- A default-branch badge, a cache, junit output, or a CI-host change.
- Reconciling `origin/main` (`a2a2644`) with local `main` — W8's publication
  runbook; the "not ready" checkpoint `6fa7fb3` stays public in deep history.
- The README/usage full truth pass (W8) beyond the two sentences above.
- The load-only kernel matrix in CI (W6) and ia32 targets (W7).
- The `Cargo.toml` `repository` URL, tracked `.codex/` configs, VM key
  rotation, and any history rewrite for the 2026-08-10 binary blob.
- `act` or any local dry-run of the workflow; a W8 re-run on the final tip.
