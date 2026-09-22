<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Production coverage and performance review, 2026-09-22

Status: measured baseline failures and source review; changes and qualification
remain in progress. This report does not qualify the release or complete H.

Inspected source: `7dee8b32ff811b3ab30ee46ac4719b73ca7e4e49`, tree
`c35c0a0b2b22094e688bfe4fb7f130a77ce8c3c1`. Frozen observer SHA-256:
`66d1818e687feac609004febab1bc39611b29aff76ebd49a30e8d2d829957c8f`.
Raw campaign evidence lives at
`/var/tmp/p11scope-ws-tmp/full-system-20260922.FbcpaT` on this workstation.

## Requirements retained

The goal covers real full-system capture across providers, browsers, users,
namespaces, and long runtimes with low measured overhead. The clarified minimum
is a brief inventory of all used providers, backed by observed execution.
Missing a supported exercised provider fails acceptance. Mapping, table
discovery, publication, attachment and endpoint execution are distinct facts.
Providers loaded later must be reached. Unload/exit/reload must release live
resources, retain history and preserve probes still needed by other mappers.

The user questioned 512 endpoints but did not prescribe another number.
Changing that constant is not an acceptance criterion. Neither filters,
heuristic selection nor sampled/rotating attachment can establish all-provider
coverage. Detailed metrics, profile and trace remain within the broader goal.
Existing argument and output privacy boundaries remain controlling.

## Fresh baseline

Host: Linux 7.0.0-31, 12 possible CPUs. A real privileged doctor run passed its
BPF and seccomp/uretprobe self-probes. Deferred program IDs seen immediately
after exit disappeared on the settled read; this did not establish a leak.

An unfiltered system metrics capture allocated 478/512 endpoints and installed
956 entry/return probes. Four additional physical objects were refused whole:
trust (68 endpoints), a second SoftHSM object (68), snap p11-kit (92), and
Firefox snap softokn (68). The admitted SoftHSM pathname did not identify the
workload's physical object: different mounts exposed distinct device/inode
pairs. Library names alone cannot join workload truth to capture evidence.

A private-token SoftHSM workload produced this controlled comparison:

| Cell | Independent post-GO truth | All observed calls | Discovery loss |
|---|---:|---:|---:|
| PID, manifest supplied | 1006 | 1006 | 0 |
| System, no provider hints | 1002 | 0 | 684 |

The system cell again allocated 478 endpoints and spilled 60 table candidates.
Zero CALL-ring loss did not establish coverage. All terminal reports remained
PARTIAL, including the exact-count PID cell, because drain is unproven.

The existing measurement producer also omitted the live workload mapping/pin
receipt required by its reader. Thus positive system attribution was not yet
qualified. The harness returning zero only meant it produced artifacts.
Repair must use a private physical provider copy and a receipt from the live,
gated target, not a later pathname stat or unrelated host-library totals.

One system run took roughly 5.6 s discovery, 14.9 s load/attach, 8 s capture and
6.7 s detach, with about 25.9 s observer CPU and 272 MB peak RSS. These are one
run's externally derived phase estimates, not a performance distribution or SLO.

An owned Fedora 44 VM reproduced the admission problem independently of the
host's discovery-ring overflow. The guest ran kernel 6.19.10-300.fc44.x86_64,
glibc 2.43-8 and NSS 3.129.0. Chrome for Testing 153.0.8010.52 retained its
sandbox, used a private NSS database, and connected only to an owned loopback
server requiring a generated client certificate. The server recorded five
successful, non-resumed TLS connections during the attached system capture.

The same frozen observer again allocated 478/512 endpoints and refused
`/usr/lib64/libsoftokn3.so` because its 68 endpoints did not fit. Both discovery
and CALL-ring loss were zero. The report's 108 positive calls belonged to the
physical p11-kit trust object, across three unnamed rows; they do not establish
NSS coverage. The browser/server ledger proves application work, not an exact
PKCS#11 call denominator or an independently pinned softokn execution receipt.
Artifacts are in `browser-vm/artifacts/browser-system-baseline/` and
`browser-vm/artifacts/system-baseline-driver.json` under the evidence directory.
This is a functional admission experiment, not a timing benchmark.

## Independent reviews and cross-checks

An Astra Max source review covered discovery/admission, lifecycle, event
scheduling, capacity and semantic attribution. The user additionally requested
Claude Code. Installed CLI 2.1.278 ran `claude -p --model fable --effort xhigh`
with Read/Grep/Glob only, no custom hooks/MCP, and a 20-minute process deadline.
It returned successfully in 635 seconds as `claude-fable-5-1`. Prompt, argv,
raw response, result metadata and SHA are in `claude-review/` under the evidence
directory. Its review is advisory; source and runtime claims were checked.

Verified decision inputs:

- `src/plan.rs` admits per physical object in sequence, then spends up to four
  heuristic tables within that object before considering the next one. The
  physical endpoint budget applies across all objects and never reuses retired
  slot IDs. Capacity is consequently a lifetime bound under object churn.
- `src/discovery/engine.rs` still gates extra pool recognition through the
  fixture-specific `p11scope_fixed64` path. Production broad coverage must be
  generic across validated physical targets.
- `Session::discovery_dequeue` reconstructs Aya's DISCOVERY RingBuf for each
  record/empty poll. EVENTS already has a retained owned consumer. Retaining
  DISCOVERY is a narrow optimization; it does not fix synchronous scan/attach
  stalls or loss by itself.
- `capture_tick_with` runs discovery before CALL draining. Some transactions
  can still run substantial work synchronously. Incremental inventory work
  does not establish that every loader/refresh path obeys that work bound.
- `queue_polling_rescans` selects only retained exploratory views. Provider-
  bearing views rely on event-driven refresh; after lost/unavailable hints,
  reconciliation must cover those views as well. With no free or evictable
  view at the retained-view cap, newcomer exploration can also stop.
- Aggregate metrics still stores START state and performs return/RV/latency
  work. `SlotStats` is 296 bytes per endpoint per possible CPU. Native task
  cleanup independently checks/scans the 512-slot universe. Enlarging only
  STATS or the Rust constant is not a coherent detailed-mode change.
- `src/capacity.rs` is a userspace model, not a kernel sparse implementation.
  Its sparse formula omits the CPU multiplier and must not justify a per-CPU
  hash conversion. Sparse allocation has its own insertion/race/failure cost.

Corrections to the Claude review:

1. Its assertion that the baseline p11-kit object had a published table is
   false: the recorded object had **64 heuristic tables and zero published
   tables**. A one-table-per-object proposal may fit more objects numerically,
   but loses other potentially used endpoints. It is not a coverage repair.
2. Calling the wrapper pool dormant is unproven. Pre-published tables can be
   used later without another observed factory return. Physical endpoint use
   must not be substituted with assumed leaf-only provider use.
3. A returned detach call is not the project's established end-to-end producer
   quiescence proof. Reuse needs precise backend synchronization, generations,
   pending START/return/async handling and historical accounting. The current
   renderer deliberately keeps `drain_proven=false`.
4. Attach cookies are fixed attachment metadata. Promotion cannot simply flip
   an existing cookie: it needs a validated routing-map or attachment transition
   protocol, with no duplicate counts and no stale return attribution.
5. Multi-attach can reduce registration/control costs, but a tenfold improvement
   was a hypothesis, not a result. Record the actual backend and measure it.
6. Browser handshakes are evidence of application work, not an exact PKCS#11
   call denominator. Foreign calls and shared implementation targets must not
   satisfy an owned-workload acceptance gate.

## Direction and sequencing

First repair measurement receipts and retain the discovery reader as separate
reviewed patches. Neither patch alone resolves the observed admission loss.
Measure their effect before attributing any speedup or coverage improvement.

For broad brief inventory, use a compact entry-use contract with its own
resource budget. It should avoid ordinary-call START, return, latency and RV
work and avoid allocating unused detailed maps. Scope checks must precede every
update. Monotonic positive usage and current liveness are separate: an unload
must not erase use, and a shared target must survive one mapper's departure.

Generic validated endpoint admission, fair/resumable discovery, and durable
gap accounting are required alongside compact capture. Merely adding an
inventory renderer or increasing an array leaves the missed-provider problem.
The first implementation must not quietly classify mapped candidates as used,
or attribute a shared physical hit to every logical publisher.

Detailed modes retain their current meaning. Their scale work requires a
budgeted statistics design and cleanup proportional to owned active START
entries, not the endpoint universe. Optional selective detail is useful, but
does not complete broad detailed-mode coverage. Slot reuse remains separately
gated on its lifecycle proof.

Required experiments include real browser client-certificate operations,
multiple physical provider instances, scoped and excluded tenants, late loads,
unload/reload, one of two sharers unloading, replaced paths, dlmopen instances,
pre-published dormant targets, process/provider churn, capacity boundaries,
discovery loss, output backpressure and shutdown. Each run pins observer bytes,
records actual backend and map/link resources, and compares independent owned
truth through a live physical receipt. Missing evidence remains unknown.

## Upstream checks

NSS's loader prefers `NSC_GetInterface`/`FC_GetInterface` internally before
falling back to FunctionList. The current built-in hook registry includes the
FunctionList variants but omits these Interface variants. Qualify them with the
existing explicit-hook mechanism before changing defaults. Source:
[NSS loader](https://raw.githubusercontent.com/nss-dev/nss/master/lib/pk11wrap/pk11load.c).

Current upstream Linux separates uprobe unregister from its synchronization
helper and synchronizes callback readers. That informs backend investigation;
it does not establish all deployed kernel paths or this observer's semantic
drain contract. Source:
[uprobe implementation](https://raw.githubusercontent.com/torvalds/linux/master/kernel/events/uprobes.c).

Chrome for Testing and Chromium use different Linux policy directories. Owned
VM client-certificate tests use a local CA, an isolated NSS database and a
local auto-selection policy, without disabling browser sandboxing. Sources:
[policy locations](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/enterprise/policies.md),
[client certificate selection](https://chromeenterprise.google/policies/auto-select-certificate-for-urls/).

Upstream links are moving references, not proof about installed browser or
kernel binaries. Qualification records the installed versions separately.
