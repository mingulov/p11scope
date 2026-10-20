<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Soak vehicle: system-scope-soak.sh

`scripts/system-scope-soak.sh` runs the acceptance manifest's `soak.*`
cells. `soak.1800s` (30 minutes of continuous owned workload against the
installed artifact) is required for the bounded release claim; the
4h/24h endurance cells stay out of bounded with full-endurance reasons.
Policy and the manifest-side oracle live in
`scripts/verify-system-test-manifest.py`; this vehicle produces the
`continuous-owned-workload` receipt that policy consumes.

## Shape of a run

One long pid-scope metrics capture, reusing the system-scope harness
(`system-scope-owned.sh`, `system-scope-sample.py`,
`system-scope-ts.py`, `system-scope-receipt.py`,
`system-scope-workload.c`, `system-scope-measure.py`):

- The installed observer (`--installed`, with `p11scope-discover`
  alongside) is pinned by SHA-256 before the run, copied into the
  evidence directory, and re-pinned after it.
- The owned workload fires paced `C_GenerateRandom` calls across the
  whole window, printing one `EPOCH` line per epoch plus the usual
  `TRUTH`/`BURST` lines. Pid scope is deliberate: only per-PID capture
  gives the exact generated==observed denominator a soak gate can check.
- The sampler records observer CPU/RSS/fds at 20 Hz across the window.
- `system-scope-measure.py` joins truth to the observer report into
  `record.json`; `system-scope-soak-oracle.py` evaluates the seven gates
  into `verdict.json` and, on a live PASS, writes the execution receipt
  (`p11scope/test-execution/v1`, `observed_behavior`
  `continuous-owned-workload`) the manifest execution copy consumes.

The manifest row's `command` is the runner's exact argv (recorded in
`run.json` as `harness_argv`); the observer argv rides along as the
receipt's `observer_command`. Seeded selectors are
`soak.{1800,14400,86400}s::continuous-owned-workload`.

## Gates

Evaluated by `scripts/system-scope-soak-oracle.py --evidence-dir DIR
--out-verdict verdict.json [--out-receipt receipt.json]`. Every gate is
fail-closed and proven red-green by the oracle's `--self-test` battery
(synthetic evidence, including a receipt round-trip through the real
acceptance verifier) and by dry-run trials:

| Gate | What it checks |
| --- | --- |
| `duration` | Receipt window covers `require_duration_s` (1800 at qualification). |
| `installed_identity` | Installed bytes identical pre-run, post-run and in evidence (live only). |
| `ownership` | Mapping receipt pins the exact workload generation; provider copy rehashes. |
| `workload_continuity` | Every epoch fired with exact counts on increasing stamps spanning the window. |
| `loss_accounting` | Pid exactness (observed == truth) with a complete loss-counter universe. |
| `resource_accounting` | Sampler trace spans the window without stalls; peaks recorded. |
| `clean_exit` | Observer, sampler and workload all exited 0 with no timeout or signal. |

Nonzero loss counters pass when counts reconcile exactly: they are
recorded in the verdict detail as accounted loss, never silent loss.

## Live 30-minute qualification

Build and install the candidate first, free the cargo lane, then run
under the privileged lock (never nested inside
`qualify-release-matrix.sh` or any other lane):

```sh
flock /var/tmp/p11scope-ws-tmp/privileged.lock \
  scripts/system-scope-soak.sh --cell soak.1800s \
    --installed /opt/p11scope/bin/p11scope \
    --work /var/tmp/p11scope-ws-tmp/soak-1800s-qual
```

Defaults cover the cell: horizon 1800, require-duration 1800, 30
epochs of 60 s, 570 calls per epoch at 100 ms pace (1710 s of paced
calls, inside the 85%..97% tuning window the runner enforces). The
tracked tree must be clean (the receipt pins revision and tree); the
runner refuses when the cargo lane is busy at start, and the controller
keeps heavy builds off the host until the window closes. Exit 0 means
all seven gates passed and `receipt.json` is written; anything else
names its red gates and writes no qualifying receipt.

## Dry-run trials

`--dry-run --observer-stub scripts/fixtures/soak-observer-stub.py`
replaces the installed observer with an unprivileged stub (no sudo, no
locks taken, own labeled manifest, no cargo lane needed). The stub
sleeps the horizon and echoes workload TRUTH back as observed counts
(labeled `dry-run-loopback`); the verdict FAILs by construction on
`installed_identity` (and usually `ownership`), while the other gates
prove the launch/sample/join/report plumbing on real timestamps over
short horizons:

```sh
scripts/system-scope-soak.sh --cell soak.1800s --dry-run \
  --observer-stub scripts/fixtures/soak-observer-stub.py \
  --horizon 8 --epoch-s 2 --epoch-calls 5 --pace-us 350000 \
  --work /var/tmp/p11scope-ws-tmp/soak-trial-green
```

`--stub-arg` forwards extra stub argv for red-leg trials
(`--loopback-corrupt drop-counter|wrong-count`, `--exit-code N`,
`--no-report`), recorded verbatim in `run.json`. `--require-duration`
above the horizon proves the duration gate fails. The dry-run shape
receipt (`receipt.dryrun.json`) carries the non-qualifying behavior
label, so the verifier must reject it for the cell; that rejection is
part of the battery. A dry-run never qualifies, whatever its gates say.
