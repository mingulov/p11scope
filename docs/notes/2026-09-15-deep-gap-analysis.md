<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Deep gap analysis — p11scope (2026-09-15)

Sources: 12-agent workflow (guest `event_loss` audit + remaining-work sweep,
7-POV review, critic, gap follow-up, synthesis) + parent verification of every
load-bearing claim below against the tree + the inline `event_loss` audit that
ran in parallel. Status tags: VERIFIED (parent read the code and confirms
mechanism), SHAPE-CONFIRMED (cited code matches; impact as stated),
CHILD-REPORTED (workflow finding carried with cites, not parent-checked).

The workflow's independent `event_loss` audit (N=200000: 17633+182367=200000)
agrees with the inline audit (N=100000: entered-drained == reported exactly):
the loss counter is accurate; details in the live-capture note item 2 UPDATE.

## Load-bearing

### HI-1 — `expect` aborts capture on churned view [VERIFIED]
`src/discovery/engine.rs:10832`: `scan_inventory_views` does
`.position(...).expect("inventory view remains retained")`. Provenance: the
second call site (:11254) scans `refreshed_ok`, which gains ids from
`loader_registry.context(*context_id).spec.view` (:11170-11177) — external to
`self.views`, guarded only by `!removed`. The sibling lookup (:11178-11185)
uses `if let Some` (fails soft), proving the author knew the view can be
absent — yet the id is inserted unconditionally and :11254 expects presence.
A stale loader context (view retired while the context lingers) panics the
whole capture: no PARTIAL, potentially no JSON. (First call site :11061 is
safe: set derives from `self.views` and nothing mutates it in between.)
Fix: filter `refreshed_ok` to retained views (skip + PARTIAL), plus a
host-side repro test that desyncs loader-context/view first.

### HI-2 — ASYNC_GET_ID drops pending before open-check [VERIFIED]
`src/semantics.rs:2003-2010`: `pending.remove(&key)` runs BEFORE the
`self.open` check; a session missing from `open` drops the op as
`async_target_failures`. The completion path (`apply_completed`, :1634) does
NOT require `open`, and BPF ringbuf gives no cross-CPU time order — so a
session-close committing ahead of an in-flight async completion (different
CPUs) strands a completable op. Rare but real. Fix: check `open` before
removing (or reinsert on failure). Safe under all orderings.

## Medium (ranked)

### MED — DaemonSet privilege posture [VERIFIED, severity: posture note]
`deploy/k8s/daemonset.yaml`: hostPID + SYS_ADMIN + Unconfined seccomp is
node-root by design for ANY such agent; the child frames it as RCE, which
overstates (no untrusted input reaches the pod — operator-triggered exec
only). Keep as a documented posture: add the gated-variant note + Localhost
seccomp profile + read-only root fs where possible. Not a bug; a hardening
backlog item. (File is new this session; rationale lives in
`deploy/k8s/README.md`.)

### MED — cgroup scope follows symlinks [VERIFIED, downgraded to LOW]
`src/scope.rs:17-30`: `File::open(path)` follows symlinks; no NOFOLLOW/openat2.
Downgraded: the path comes from the operator's own CLI at the same privilege
as the observer — self-inflicted scope confusion, no trust boundary crossed.
Hygiene fix when touched: openat2 NO_SYMLINKS (pattern exists at
`output.rs:317`).

### MED — forward_signal without reap check [SHAPE-VERIFIED, LOW-MED]
`src/run.rs:1359` (via :712): `ensure_active_generation` checks generation,
not liveness; an already-exited child yields ESRCH from `signal_group`, and
`?` converts a clean child exit into a run error on the signal path —
possibly losing the final JSON. Fix: `wait_ready(ZERO)` first, mirroring
`terminate_with_grace` (:733). Needs a repro test (signal vs exited-child
race) to confirm JSON loss before ranking higher.

### MED — identity replace drops without claim scrub [SHAPE-CONFIRMED]
`src/discovery/identity.rs:434-436` (`replace_view_pins`): retains
`raw_to_id`/`by_id` by surviving raws without consulting `ownership` claims,
unlike `remove_view` (:495-539) which computes unowned-from-claims. Dangling
claim ids are a logic use-after-drop (not memory). Needs a claim-consumer
audit to rank impact; fix direction (mirror `remove_view`) is safe.

### MED — BPF CAS+SIGSTOP wrong-proc residual [CHILD-REPORTED]
`crates/ebpf/src/main.rs:344-358`: compare-and-swap + SIGSTOP lifecycle race
leaves a wrong-process window under PID reuse. Child asks for lifecycle fuzz
over PID reuse. Carried; parent did not verify the window.

### MED — clone-per-fork stall [CHILD-REPORTED]
`src/semantics.rs:2346`: `active_ops.clone()` per fork per session can stall
into PARTIAL under fork storms. Fix: hoist the clone. Carried; needs a
fork-storm benchmark to size the impact.

### MED — dump-owned-bpf-maps TOCTOU [CHILD-REPORTED]
`scripts/dump-owned-bpf-maps.py:64-75`: root O_TRUNC + chown without NOFOLLOW
(0700 WORK dir is self-only, bounding it). Fix: O_NOFOLLOW|O_EXCL + fchown.
Carried.

## KISS / DRY (user-flagged lenses)

### HIGH — capture_profile vs capture_trace duplication [PLAUSIBLE]
`src/run.rs:2018` (256 lines) vs `:2274` (307 lines) + parallel drains
`:2581/:2608/:2636`. Two near-parallel capture loops + drain families.
Fix: one `capture_tick` driver parameterized by sink. Parent confirmed the
parallel structure exists; line-level duplication ratio not measured —
measure before scheduling (a 60%+ overlap justifies the refactor).

### HIGH — engine.rs decomposition [CHILD-REPORTED]
26.5k-line `engine.rs`: split proposed at :10933/:1256/:8291; god functions
scan :1215 + pause :698; single-impl traits to collapse; source-scraping
tests at :12972 to move onto ScriptedSession. The file size is the codebase's
largest KISS liability; the split points are the child's, carried as a
refactor plan, not verified line by line.

### WINS — small safe dedups [CHILD-REPORTED]
Rejection-helper x7 (`engine.rs:8305`), combine x6 (`run.rs:1431` →
`also_failed`), stale `allow`s (`pause.rs:1`, `engine.rs:11741`), marker
constructions x4 (:1252), `check_unchanged` x7. Low-risk cleanup batch.

### MED — render Evidence table-driven + script oracles [CHILD-REPORTED]
`render.rs` Evidence construction (:381) + `live()` (:706) to table-driven;
scripts duplicate product logic (canaries :512, counts, self_tests) → one
shared oracle. Carried.

## Docs / tests / release

### MED-docs — CLI/docs drift [CHILD-REPORTED]
usage/README omit exit codes + 7 flags + 5 hooks; discover absolute-only
(:432); `run --max-events` undocumented; attach-pod scan-once vs USAGE :119.
Carried; each item is checkable in minutes and should gate the next docs pass.

### HIGH-rel — dist/p11scope stale [CHILD-REPORTED, credible]
Child ran it: only profile/trace/discover, needs --manifest. Fix: rebuild
via `build-release.sh` or drop the artifact. Carried — verify by running
before acting (one command).

### LOW batch [CHILD-REPORTED]
loader.rs:225 + plan.rs:747 caps→PARTIAL; `u64 +=` → `saturating_add`;
scan.rs:876 propagate reason; doctor.rs:1012 run-capture clause; SUDO_UID
trust; test-only PIN1234 argv (observer never reads PINs); attach-pod
jsonpath fails closed (:121); env-quote breakout. Fix directions from the
child: loginuid/file-PINs/`jq --arg`/`%q`. Carried as hygiene.

## Open / omitted scope (honest boundaries)

- OPEN (child): Gap5 fixture-BPF-zero (`render.rs:423`, driver); U4
  `/bin/sh` template (`run.rs:3461`, :2922, :3475). Not parent-checked.
- CLOSED (child, agrees with session state): U1/U2/U3/U6 done-unrecorded;
  Gap2b/3/4 closed; U7 churn + K8s complete; unsafe-audit + doctor tiers
  sound. The remaining-work sweep found no live work: record-only.
- Omitted: pkcs11-check/NSS provider behavior (external repo); kernel D-state
  wedge (kernel-side, product mitigation shipped); synthesis `unresolved[]`
  text did not survive transport — only the 23 findings above were
  recovered, so child-declared unknowns are NOT represented here. Treat any
  finding marked otherwise than VERIFIED as needing a confirmation read
  before scheduling a fix.
- Parent did not re-verify LOWs, the engine-split line numbers, or the
  docs-drift item list; all are carried with cites for follow-up.

## Recommended next actions (ranked)

1. HI-1 repro test + filter fix (capture-abort panic).
2. HI-2 peek-before-remove (small, safe under all orderings).
3. `dist/` rebuild-or-drop decision (one command to verify).
4. forward_signal reap check + race test.
5. `--ring-bytes` / `--drain-interval-ms` knobs (user-asked; bursts vs rate).
6. KISS batch: capture_tick driver (after overlap measure), WINS dedups.
7. Docs-drift pass gated on the item list.
8. engine.rs split plan (largest, last).

## Resolutions — 2026-09-16 session [PARENT-VERIFIED]

Every item below was confirmed by a fresh read; fixes are TDD (RED first)
with the full gates green after each batch (`cargo +1.88 test --locked
--lib`, `--test artifact_contracts`, `clippy --locked --all-targets`,
`fmt --all -- --check`).

### KISS HIGH — capture loops: measured, capture_tick REJECTED

Normalized unique-line overlap of the two loop bodies is ~20% (26 shared
lines, ~12 substantive), far below this doc's 60% refactor gate. Each guard
is already one shared function; the residue is call sequencing with
mode-specific steps interleaved. Loops stay separate; `run.rs`
`capture_loops_keep_guard_parity` pins the shared guard order so a guard
added to one loop must be considered for the other.

### KISS HIGH — engine.rs: tests extracted (26584 → 12352 lines)

Over half the file was the inline `#[cfg(test)] mod tests`. Moved
verbatim to `src/discovery/engine_tests.rs` via `#[path]` (module path
`crate::discovery::engine::tests` unchanged, so the three `run.rs` test
users are unaffected). Pre-move audit: all six `include_str!` scrapers
slice markers that live in non-test code, and the one whole-file
`.contains` needle does too — verified before cutting. Full lib suite
green after the move (852 at the time). The deeper domain split stays a
plan, not a debt: the file is now one domain, not two files glued together.

### WINS batch: 4 fixed, 1 rejected with reason

- Rejection-helper: 6 convertible sites →
  `Engine::reject_unattributed_selection` (+ new behavior test); the 7th
  site keeps its silent variant (no binding id exists there).
- combine x4 → `also_failed` core; all four user-visible messages kept
  byte-identical (+ message-shape test).
- Stale allows: 5 engine.rs allows confirmed stale and removed. `pause.rs:1`
  was load-bearing, not stale — replaced by 6 targeted allows on the
  test-only constructors/accessors (each use verified in the pause tests).
- `check_unchanged` x5 → `Engine::check_pinned_unchanged`; the bool discard
  is correct (evidence reads the sticky flag via `provider_changed`).
- marker x4 (`marker_never_seen`): REJECTED — a documented temporary stub
  ("swap for the real read" when the Gate-B probe lands); abstracting it
  now would create merge debt at the swap.

Collateral caught by the gates: `clippy::io_other_error` on session-added
`symlink_loud_error` (fixed to `Error::other`), and four
`artifact_contracts` scraper markers updated to track the renames (loop
order marker, form-agnostic test-module split, MED-5 `open_cgroup_dir` +
`RESOLVE_NO_SYMLINKS` — the last a pre-existing break from MED-5's scope
edit that no contracts run had covered since).

### MED render: live() table-driven, DONE

The ~20 gap `if`-push blocks plus their hand-relisted 19-term gate are now
fragment tables; the gate derives from the same fragments, so a new gap
cannot be added without surfacing. Exact byte order preserved
(discovery-first, pinned by test). Fixed one real quirk the refactor
exposed: a lone "process trackers" line rendered `·  ℹ` (double space).
Guarded by a 40-case gate pin (every counter alone must surface, every
`state_gaps` summand must feed the aggregate). The `:381` cite is the
`Evidence` struct itself — a serde contract, not refactorable; `live()`
was the actionable half.

### MED script oracle: measured, REJECTED

No def-level duplication across the three checkers (only `main`/`self_test`
share names, with per-domain bodies). Canary validation is already
table-driven (`validate_canary` lanes dict); `verify-canaries.sh` delegates
to `check-capture-evidence.py`; the runpy-oracle pattern already exists
(`production_inventory` ← `check-bpf-map-defs.py`). Residual overlap is a
2-line `fail()` — a shared module would add import machinery (scripts also
run under `python3 -I`) to save nothing.

### LOW batch: 3 fixed, 5 verified sound

- `u64 +=` → `saturating_add`: 51 published-counter sites converted
  (events/metrics/process/render/semantics/engine/identity/scan/
  attribution), RED-tested via `malformed` saturation at `u64::MAX`.
  Rule: published/event-driven accumulators saturate; bounded
  locals/indices keep `+=` so a debug overflow still signals a logic bug.
- doctor run-capture clause: `verdict()` gated the exit code on "run
  initial-set capture" but `verdict_line` never rendered it (latent
  exit-1-beside-"capture available"). Clause added + test; `verdict()` doc
  now lists all five lanes. External review (fable) then caught a real bug
  in the new clause: its catch-all mapped the probe's always-on
  `Warn("none")` ("never eligible") to "run capture available" — a newly
  introduced false statement under a `warn none` row. Fixed with a dedicated
  `Warn → "run capture not eligible ({detail})"` arm + test; sibling clauses
  audited (their probes never emit Warn, so their catch-alls are safe).
- attach-pod jsonpath: a CLI-provided container was validated but a
  cluster-fetched one flowed straight into the filter (proven fail-open by
  a stub-kubectl RED test serving `x"]}.foo`). Fetched names now pass
  `valid_name`; stub-based fetch tests added to `--self-test`.
- loader/plan caps: already wired — loader truncation accumulates into
  `discovery_truncated` → PARTIAL (each link tested); plan over-capacity is
  a loud tested refusal, not a silent truncation (PARTIAL-degradation would
  under-report).
- scan reason: the `None` collapse is documented on `read_name`, unreadable
  names are tracked downstream (`PrivateSelectionName::Unreadable`), and
  budget exhaustion propagates separately (`io_exhausted`). No consumer for
  a finer reason; no change.
- SUDO_UID: both parsers validate digits/non-root/account-exists with tests;
  added `u32::MAX`/empty/whitespace spoof pins. A loginuid cross-check was
  considered and rejected (unset loginuid in containers would break
  legitimate use).
- PIN argv: test-only throwaway tokens in `mktemp` stores; `softhsm2-util
  --init-token` has no pin-file option; observer handles only RV codes,
  never PIN values. Accepted practice, no change.
- env-quote: no finding — all env passing is quoted or allowlisted; every
  `eval` in `build-release.sh` operates on script-fixed word lists.

### Docs-drift: fixed, zero active flags undocumented

`usage.md` gained: 6 missing flags (`--max-events` incl. `run --trace`
inheritance, `--hook-symbol`, `run --trace`, `--kill-on-timeout`,
`inspect --json`, `--allow-uretprobe-on-confined-target`), the 5 built-in
hooks + ABI suffixes, an exit-codes section (0/1/2 + run passthrough +
doctor/inspect), and the discover absolute-path requirement.
`--provenance-module`/`--trusted-workload` are removed flags (correctly
absent). attach-pod scan-once matches usage guidance. Re-ran the CLI↔docs
diff: clean.

### HIGH-rel dist: DROPPED

`./dist/p11scope --help` confirmed stale (profile/trace/discover only,
mandatory `--manifest`). `dist/` is gitignored build output referenced only
by its builder — removed; rebuild is `scripts/build-release.sh`.

### OPEN: U4 no-finding, Gap5 unconfirmed

- U4 (`/bin/sh` template): all cites point into test modules; production
  code has zero shell-outs. Test fixtures only. No finding.
- Gap5 (fixture-BPF-zero): the cite is an `Evidence` struct field and no
  "driver" component exists; the most plausible reading (zero-evidence →
  COMPLETE) is explicitly guarded (`discovery_complete` requires nonempty
  modules + slots) and documented. No defect found after direct reads —
  carried as unconfirmed per this doc's own transport-loss clause, not as a
  scheduled fix.
