<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# First-use evidence contract

First-use qualification asks whether the observer captured an independently
proven first provider call. Loading a module, finding a table, attaching a
probe, or publishing a report does not prove that call was observed. This
contract defines the required comparisons; it is not a claim that every case
is supported. Current release scope and qualification are recorded in the
[changelog](../../CHANGELOG.md#qualification-of-this-release), and `--system`
remains a preview.

## Required workload comparisons

Exercise each physical/lifetime class in both forms:

| Class | Distinction the comparison must retain |
| --- | --- |
| Previously covered physical inode | Determine whether retained file probes cover a later first call. |
| New inode with equal bytes | Equal hashes do not establish prior attachment to the new physical object. |
| Never-seen provider | Measure acquisition and attachment without assuming earlier observer knowledge. |
| Late heap publication | Keep table publication separate from file mapping and a periodic scan. |
| Short-lived mount namespace | Retain independently verified physical custody even after the namespace exits. |

The gated form explicitly waits for the observer's successful attachment
notification before releasing the ordinary call. The ungated form executes
`load -> verify table -> one ordinary API call -> unload/exit` without an
observer readiness wait. Retain an independent workload ledger and physical
file identity in both forms. A post-call receipt may extend residency; that
extension must be visible and must not be mistaken for pre-call coverage.

Use the [owned workload fixture](system-first-use-fixture.md) and
[observer test adapter](system-first-use-observer.md) with an independent
oracle. Compare an uninstrumented public command as well: test metadata
collection can alter scheduling. Ordinary fixture or cold-start tests do not
substitute for the gated/ungated native matrix.

## Independent transition facts

Record separate facts and clocks for object known, mapped, publication
returned, scan complete, attach complete, entry executed and entry observed.
Preserve missing facts as unavailable. Later publication, discovery or
attachment cannot reconstruct an earlier observed entry.

A workload's object stat is not observer knowledge. Its post-`dlopen` mapping
observation is not an exact kernel VMA creation time. A post-attach timestamp
is an upper bound on link activation. Keep provider-body truth, publication
return, observer sampling and kernel event clocks distinct, with their
actual source and uncertainty.

## Capture-window and workload authority

An accepted measurement needs complete, ordered observer attach/start/end
stamps inside the observer process lifetime, a recognized successful end
reason, and containment of the independent workload burst within the actual
capture-loop interval. Frame-gated runs also validate the release timestamp.
Use `loop_end - loop_start` for the capture interval; FD plateaus and other
external timing estimates remain diagnostics.

`window.observer_phase_authority` records this check. Missing, partial,
malformed, contradictory, pre-loop and post-loop timestamps invalidate the
window. Valid timing alone does not establish complete capture.

`window.owned_workload_authority` separately requires positive workload
truth and activity attributable to its receipt. A PID capture must bind the
selected PID to its recorded generation and complete mapping receipt; its
physical module rows must exactly match workload counts. Equal aggregate
`counts_match` is a diagnostic, not ownership. Foreign traffic, admission
without calls, empty truth and an unattributed trace total cannot qualify an
owned first-use window. Trace aggregate counts alone lack physical module
attribution for this check.

The measurement parser and its regression controls live in
`scripts/system-scope-measure.py`, `tests/python/test_measure_e03.py`, and
`tests/python/test_loss_share_measure.py`. The
[measurement guide](../testing/system-scope-measurement.md) explains their
record and oracle boundaries.

## Feasibility and interference

Compare retained file probes for a known object with any proposed safe
pre-execution mechanism for a new object. Measure target interference
explicitly. This contract does not authorize adding ptrace stops, provider
interposition, observer-initiated provider calls, or application changes.

An unsupported first-use case requires a minimal repeatable counterexample
and an explicit supported boundary or separately approved mediation design.
An ungated miss is not a passing all-provider result. Missing evidence or an
unresolved material feasibility decision cannot become a release pass by
changing its label.

Capacity and latency comparisons follow the
[resource measurement protocol](system-resource-pilot.md). Derive capacity
from the measured resource census and reserve. Include low occupancy with
more than 16,384 sequential lifetimes and scan-only bursts; neither a test
point such as 576 endpoints nor a harness timeout defines a product limit.

## Runtime diagnostics and cold start

The capture loop's long-run diagnostic separates completed service-tick
work from deliberate readiness waits and terminal work. The historical
1,895 ms threshold is a diagnostic bound, not a latency guarantee. Rounded
milliseconds preserve the boundary: 1,895 ms is within it and one additional
nanosecond exceeds it. Keep early and steady loss samples separate.

The observer attempts a `p11scope: longrun:` stderr line at loop end. Missing
completed ticks or counter reads produce `unavailable`; metrics reports its
absent event stream as `n/a`. Delivery is best effort, so an absent line is
not a clean result. These diagnostics do not change capture verdicts or the
report schema.

`tests/t2_cold_start.rs` checks help/version and honest refusals without
ambient credentials or user state, including an empty environment and an
unusable temporary-directory setting. These are startup controls. They do
not prove first-call coverage, privilege availability, or provider behavior.
