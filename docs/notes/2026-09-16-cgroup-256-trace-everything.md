# Cgroup 256 discovery limit + trace-everything use case — research record

Date: 2026-09-16. Status: research + measurements complete, implementation
pending. Branch: `refactor/extraction-rename` (worktree
`.worktrees/refactor-extraction-rename`), baseline green (1145 passed,
0 failed, exact CI invocation).

## Question

`p11scope profile --cgroup /sys/fs/cgroup` (trace everything, find all
PKCS#11 providers — e.g. a running Firefox) attaches 0 probes. Is the 256
process cap the cause, and what should replace it?

## Answer: three ceilings share one constant, and a fourth binds first

`MAX_SCAN_PIDS = 256` ([src/discovery/engine.rs:2785](../../src/discovery/engine.rs))
does triple duty, all unmeasured (born in `7aaeb2e`, empty commit message):

1. Initial scan takes the lowest 256 pids
   ([engine.rs:3325](../../src/discovery/engine.rs)). The pid list IS sorted
   ([engine.rs:3217](../../src/discovery/engine.rs)), so this is
   deterministic — but biased against exactly the target: a just-started app
   has a HIGH pid and is never scanned.
2. Live `refresh_inventory` re-applies `take(256)` every tick (~1/s, confirmed
   by 12 re-emissions in a 12s capture)
   ([engine.rs:11002](../../src/discovery/engine.rs)). Steady state diffs
   against known views (cheap); every new generation burns a view ID.
3. View-ID space refuses at 256 and IDs are monotonic, never reused
   ([engine.rs:6175](../../src/discovery/engine.rs)) — i.e. 256
   process-generations per capture LIFETIME. Churn-heavy cgroups exhaust it
   mid-capture with few live procs.

The ceiling that binds FIRST is the shared table budget: `CaptureWorkBudget`
([src/discovery/scan.rs:65](../../src/discovery/scan.rs)) allows 512 table
candidates / 53,248 entries PER CAPTURE across all procs. The
`--features skip-attribution` build proved the kill chain on this box: every
GNOME proc maps libp11-kit, each decoding dozens of multiplexed 104-entry
tables → `capture table decode ceiling reached (512 candidates…)` → every
later decode refused. After that: cross-namespace same-path-different-bytes
(container vs host SoftHSM) trips the ambiguity drop ([engine.rs:4349](
../../src/discovery/engine.rs)), and live loader arming fails 145× across
256 views. No deadline is involved (`apply_discovery_batch` passes
`deadline: None`). The 256 cap is also UNDOCUMENTED (`docs/usage.md` never
mentions it).

## Measured numbers

- Root capture, ~192 procs (under cap): scan **15.5s, 0 slots, 0 probes**,
  PARTIAL (`/tmp/256-base.json`, root-owned).
- Control `profile --pid 3039` (gsd-smartcard): **172ms, 136 slots,
  272 probes**, both modules decoded. The multi-proc context destroys
  discovery, not the per-proc path.
- Scale test, 550 procs + planted unique high-pid provider
  (`LD_PRELOAD=/tmp/uniq-p11.so`): over-cap skip published, planted provider
  MISSED (`uniq_found=False`), scan 13.4s. Pre-fix proof; rerun post-fix.
- NSS/SoftOKN (the Firefox case): ctypes `NSS_InitReadWrite` subject maps
  softokn; `inspect` fully decodes it (tables 3.0/3.2/2.40, 92/104/68
  entries, 6 interfaces, 156ms). Decode machinery handles NSS. Headless
  Firefox itself exits rc=1 in this env (profile/env issue), so the browser
  binary was not exercised — only its provider library.

## How to check Firefox today

```sh
pgrep -a firefox
sudo p11scope inspect --pid <firefox-pid>
sudo p11scope profile --pid <firefox-pid> --duration 30s -o ff.json
```

Trace-everything cannot find it instead until the fix below lands (high pid
+ exhausted shared budget).

## Implementation proposal (accepted direction, not yet built)

- A. Decode each unique provider ONCE: dedup table decoding by object
  identity (sha256); stop burning shared candidates re-decoding the same
  libp11-kit in 100 procs.
- B. Cap: measured raise + `--max-scan-pids` flag + docs; free view IDs on
  retirement (or widen ID space past scan cap).
- C. Two-phase scan: cheap maps-only sweep over ALL pids, deep-scan unique
  candidates — makes "trace everything" literal.
- D. Merge: same-path-different-bytes across namespaces should attach per
  identity, not ambiguous-drop — but the no-misattribution guarantee at
  engine.rs:4349 must be preserved; needs care.
- E. Loader arming at scale (145× failure): follow-up after A–C, likely
  churn-window driven.

## Probe inventory (re-runnable)

Persistent copies: `/home/user/src/m/p11scope-ws/probes-256/` (originals
were `/tmp/*.py`, may not survive reboot):

- `scale-probe.py` — 150 sleepers + 1 unique `LD_PRELOAD` provider, cgroup
  capture, asserts over-cap skip; post-fix proof = `uniq_found=True`.
- `nss-probe.py` + `nss-subject.py` — ctypes NSS_Init subject, `inspect`
  decode check (the Firefox-provider proof).
- `scan-sweep.sh` — per-pid `inspect` sweep (cost distribution; needs a full
  rerun — first attempt died to SIGPIPE).
- `ff-probe.py` — headless-Firefox attempt (currently rc=1, kept for retry).

Evidence JSON from this session: `/tmp/256-base.json`, `/tmp/256-attr.json`,
`/tmp/256-pid.json`, `/tmp/256-scale.json` (+ `.stderr` siblings) — all
root-owned, all in /tmp: re-run rather than rely.

## Resume checklist (post-restart)

- Worktree: `/home/user/src/m/p11scope-ws/p11scope/.worktrees/refactor-extraction-rename`,
  branch `refactor/extraction-rename`, this file committed there. Main is
  clean and untouched.
- NOTE: worktree `target/debug/p11scope` is currently the
  `--features skip-attribution` build. Rebuild plain
  (`cargo +1.88 build --locked --bin p11scope`) before timing runs.
- Pending queue, in order:
  1. Implement A–C (+ tests), pre/post measure with `scale-probe.py`.
  2. Python extraction: 10 oracle blocks → sibling `.py` + `--help` per lane.
  3. Dedupe checker importlib driver; rename `tests/python/` (holds `.c`).
  4. Rename task4→receipt, TASK5→unprefixed, lane files (CI + pins in sync).
  5. Meta-tests: `py_compile` all `scripts/*.py` + heredoc size cap.
  6. Rust 1.98 read-only probe (check/clippy/test, migration cost).
  7. Full gates + behavior-identical proof, then merge review.
- KEEP as decided: Task-N/F5/W3/W8 comments, G-gates/G-lanes (document the
  two namespaces), lane numbers, csf_*, S-stages; historical docs verbatim.
