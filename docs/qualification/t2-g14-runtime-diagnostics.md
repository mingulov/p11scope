<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T2 / G-14: public runtime measurements

## Small PID/profile baseline, 2026-09-26

Source `9ff64356e1ba49ac0c67197a0027f1196ab1e250`, tree
`3624fd944940b0786e4e40dfdd77c244ae077eff`, default release build,
kernel `7.0.0-31-generic`. This is a public-command diagnostic comparison,
not completion of G-14, system-scale qualification or a performance claim.

The owned driver used a fresh private SoftHSM inode, its independent call
ledger and a live mapping/generation receipt. The first rendered frame
released the workload. It issued 100 `C_GenerateRandom` calls at a requested
1000us pacing interval, plus six setup/teardown calls. The observer ended
on target exit before its requested 16s maximum.

| Fact | Observed result |
| --- | --- |
| Owned calls | 106/106, exact named counts and physical module attribution |
| Window authority | Actual attach/loop-start/end timestamps; owned burst contained; receipt checks pass |
| Actual loop duration | 2.193186431s |
| Reported event/discovery loss | 0 / 0 |
| Diagnostic completed ticks | 966 |
| Diagnostic maximum service tick / drain gap | 28ms / 30ms, rounded up |
| Existing report drain-gap field | 29ms, existing rounding preserved |
| Final verdict | PARTIAL / concrete_gap |
| Terminal drain proven | false |
| Cleanup | Four supervisors settled; observer reports 5/5 links released; no unexplained typed census changes |

Two kernel-typed cgroup-device policy changes occurred on the host and are
retained separately. No host object was deleted. The diagnostic line was
delivered once and reported no detector finding; this does not override the
capture verdict. This short PID run does not exercise a sustained system
scan or establish the 1895ms forced-sweep bound.

## Why the verdict remains partial

The original small PID comparison also captured all 106 calls. The new
result reproduces its loader coverage gap with stronger measurement-window
acceptance. At this revision:

- `Engine::loader_discovery` in `src/discovery/engine.rs` classifies a bound
  loader context as `unproven`; no qualified timing catalog is implemented.
- The report contains one unproven dlopen context, three loader hits and
  no confirmed pause. `evidence_for` in `src/run.rs` derives an unprotected
  live window from those facts.
- Those discovery predicates prevent completeness in `src/render.rs`.
  Terminal drain certainty is a separate, still unproven property.

This points to safe discovery/timing protection in T5/T6. Exact counts in a
GO-gated fixture do not establish that arbitrary first calls are captured.
The required repair must provide the missing mechanism and evidence; a
label change or silent scope reduction cannot close the gate.

The older run-mode burst overflow is a separate open case: its 20000-call
ungated workload lost up to 7521 of 20006 events before the first drain.
Passing this gated, paced profile baseline does not repair that failure.

## Other predeclared mode comparisons at the same pin

| Cell | Counts | Measurement window | Diagnostic maximum tick / event-drain gap |
| --- | --- | --- | --- |
| PID/profile, unpaced 20000-call gated burst | 20006/20006; reported event loss 0 | Valid observer clocks and physical attribution | 30ms / 30ms |
| PID/metrics, paced 100-call burst | 106/106; no EVENTS stream | Valid observer clocks and physical attribution | 41ms / not sampled |
| PID/trace, paced 100-call burst | 106 delivered lines; loss crosscheck passes, reported loss 0 | Observer clocks valid; owned attribution invalid because trace lacks physical module rows | 26ms / 27ms |

All three returned normally with four settled supervisors and unchanged
typed map/program/link censuses. The burst ran after KryProbe released the
shared lane, in a new directory; the earlier NOT_RUN lease refusal remains.
Trace's matching aggregate count is diagnostic only. Its attribution check
correctly refuses to qualify the owned window.

The metrics run exposed a new diagnostic defect: `max gap 0ms` was printed
although this mode takes no event-drain samples. Missing interval data must
be `n/a`; an actually sampled zero interval must stay zero. Two ordinary
controls reproduced the defect in the detector and capture integration,
while the measured-zero control already passed. The repair now passes the
18 affected default/wide controls, the complete default workspace suite
(1618 library tests, 45 privileged ignored; 139 artifact tests and the other
workspace suites), formatting and strict Clippy in both profiles. A fresh
live metrics comparison is still required; the original native output is
preserved unchanged.

The first full attempt exposed a separate timing-sensitive harness defect:
a deadline expiring inside process-identity checks was sanitized into a
generic custody error. Two deterministic regressions reproduced that
failure. `f066e48` preserves a typed timeout while keeping arbitrary error
text private; the original negative readiness cases and the complete fresh
workspace run then passed. Neither timeout budgets nor acceptance
assertions were relaxed. The failed full run remains part of the evidence.

## Custody and remaining work

Workspace evidence root:
`/home/user/src/m/p11scope-ws/preserved/evidence-roots/product-finish-20260926/t2-g14/`.

- `historical/`: 21 old raw inputs/reports, copied and hash-verified;
  original paths and SHA256s are in `preservation.json`.
- `pins-r2/`: 29 frozen artifacts, including both release binaries, source
  archive, compiler receipt, helpers and kernel/BTF identity. The Detailed
  BPF object is embedded in the public executable. Both Inventory objects
  were compiled but are absent from it; the receipt records that distinction.
- `pins/`: preserved incomplete first freeze, whose controller incorrectly
  required private Inventory objects in the public executable. No live
  body ran from that incomplete freeze.
- `receipt-root/`: the real-child mapping-receipt test passed with privilege,
  one body and no skip. The ordinary run's permission-based skip is retained.
- `live/pid-profile-small/`: command, all raw artifacts, supervisor receipts,
  typed before/after censuses and analysis. `bundle-files.json` seals them.
- `live/pid-profile-burst/`: NOT_RUN lease refusal. KryProbe owned the shared
  BPF lane; this is not a measurement failure or an executed test.
- `live/pid-profile-burst-lease2/`, `live/pid-metrics-small/` and
  `live/pid-trace-small/`: the three subsequent comparisons, each with its
  own 55-file sealed bundle and original raw output.

The missing-gap diagnostic repair still needs its focused live check. The
five gated/ungated first-use classes, seven transition facts, safe
pre-execution comparison, run-mode overflow repair and supported-boundary
G-14 green result also remain open. See the [original requirements](t2-first-use-requirements.md)
and [resource pilot](system-resource-pilot.md).
