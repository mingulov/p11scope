<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System-scope measurement harness

`scripts/system-scope-measure.sh` runs controlled PID and system captures
against an owned deterministic SoftHSM workload. It retains the workload's
independent counts, provider and observer identities, capture evidence and
resource samples. This is a qualification harness, not a performance or
all-provider coverage guarantee.

The runner uses `system-scope-workload.c`, `system-scope-sample.py`,
`system-scope-ts.py`, `system-scope-receipt.py` and
`system-scope-measure.py` under `scripts/`. The
[multi-wrapper fixture](../../tests/fixtures/multi-wrapper/README.md)
supplies separate ground truth for wrapper-coverage experiments.

## Running a declared condition

Invoke the runner from a non-root shell only when privileged experiments
are authorized. It requires working noninteractive sudo, GCC, Python 3,
`timeout`, `softhsm2-util`, and the SoftHSM module at the path checked by the
script. It prepares a private provider inode and private observer copies,
retains physical file/mapping receipts, and supervises the actual workload,
observer and helper process generations. A new condition must use a safe
private output directory and must not overlap unrelated BPF experiments.

| Option | Purpose |
| --- | --- |
| `--scope pid\|system\|both` | Compare one owned PID with system discovery. PID runs use a manifest and late mapping; system runs use early mapping without a manifest. `map_early` records the distinction. |
| `--mode metrics\|profile\|trace\|both\|all` | `both` means metrics and profile; `all` also includes trace. |
| `--duration`, `--n-calls`, `--pace-us`, `--seed` | Declare the capture bound and workload. Pacing is nominal; use measured burst times and completed counts for achieved rate. |
| `--ring-bytes`, `--drain-interval-ms` | Record capture tuning without treating larger buffers as proof of coverage. |
| `--sink file\|discard\|slow-pipe`, `--sink-rate-kbps` | Compare ordinary stdout, discarded output and a throttled reader. The separate trace `-o` stream remains an evidence source. |
| `--profile release\|debug`, `--binary`, `--no-build` | Select a declared build or use prepared observer/discover binaries. |
| `--work` | Select the private run directory. The observer's output-ancestor checks still apply. |

A requested duration must leave room for setup and the complete measured
burst. If the burst lies outside the actual capture loop, retain an INVALID
result rather than interpreting matching totals as a valid window. Redirect
runner output to a file; do not pipe it to an early-closing consumer such as
`head`.

## Workload and release gate

The two-phase workload records `TRUTH_PREGO` for setup calls and a separate
`TRUTH` for the post-go calls. A `BURST go_ns=... end_ns=...` record bounds the
ordinary-call burst on the monotonic clock. Keep pre-go calls out of the
captured-work denominator. A successful workload completes exactly the declared
number of `C_GenerateRandom` calls plus its recorded teardown/setup calls;
the precise truth depends on early versus late mapping.

For a frame-producing capture with retained stdout, the runner waits for
the discovery marker and first live frame before releasing the workload.
Trace and discarded/non-frame outputs use weaker marker/settle gates,
including an FD-plateau heuristic for system scope. These gates decide when
to attempt the workload; they do not establish acceptance afterward.

Window acceptance requires authoritative observer attach/loop-start/end
stamps and containment of the independent burst within the actual loop.
Missing or contradictory clocks fail. External FD and phase estimates are
retained as approximations, not replacements for those stamps. See the
[first-use contract](../qualification/first-use-contract.md).

## Records and oracle authority

Each condition produces `record.json` using schema
`p11scope/system-scope-measurement/v1` and `summary.txt`; the matrix collects
its conditions in `matrix.json`. Preserve the raw report or trace, stderr
markers, workload ledger, mapping receipts and resource samples alongside
those summaries. Records include:

- exact commands, revision/cleanliness, binary/provider identities, kernel,
  CPU topology, configuration, workload seed and actual burst clocks;
- phase clocks and estimates with their method warnings;
- completeness, every recognized loss counter, attach failures,
  in-flight calls, admitted/refused providers, tables and slots;
- workload truth, observed counts and separate physical attribution;
- observer CPU, RSS, FD and thread samples, with sampling/load context;
- `window`, `event_path` and scheduling evidence for timing, owned-workload
  authority and loss accounting.

`window.observer_phase_authority` and `window.owned_workload_authority` are
independent requirements. Exact global totals do not prove the owned
workload was captured: unrelated system traffic can supply those counts.
Positive truth, matching process generation, complete physical mapping
receipts and attributable module rows are required. Missing module identity,
foreign-only activity and an unattributed trace sum fail owned-window
qualification.

The strict trace parser recognizes the stream's CAPTURE, call, LOST,
TRUNCATED, COUNT_EVIDENCE and EVIDENCE records. Its loss check requires
`stats_returned - raw_calls == event_loss == last LOST`. Kernel aggregate
counts provide a denominator distinct from delivered call lines; neither
aggregate equality nor a valid loss identity supplies missing ownership.
Metrics has no CALL stream and some profile-only fields are unavailable;
records retain that distinction.

## Limits and regression controls

BPF load may be folded into an external attachment estimate, and the 20 Hz
resource sampler cannot resolve exact kernel phase boundaries. Concurrent
builds or VMs contaminate performance samples. Record host load and actual
achieved work; do not turn a noisy point or an idle attachment count into a
throughput, first-use or provider-completeness claim.

A PID capture can end when its target exits before the requested duration.
Detach, terminal drain, output publication and process cleanup are separate
phases. Preserve capture/detach loss shares and cleanup failures. A terminal
report does not by itself prove callback quiescence or resource release.

Ordinary parser/oracle controls include
`tests/python/test_loss_share_measure.py` and
`tests/python/test_measure_e03.py`. They test invalid clocks, ownership,
foreign traffic and loss accounting without running a privileged capture.
Passing them establishes parser behavior; native capture and installed
artifact qualification require their own owned executions and receipts.
