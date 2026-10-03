<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# `p11scope/inventory-events/v1`: observation-event stream

Appendable JSONL companions to the [`p11scope/inventory/v1` snapshot](inventory-v1.md):
one JSON object per line, for external observability/monitoring to consume
and forward. Emitted by `p11scope inventory --event-log <f.jsonl>`
(classic and `--dashboard` paths alike).

Consumers dispatch on the exact per-line `schema` string
(`p11scope/inventory-events/v1`). A new schema id means a new contract.
Within v1, additive evolution only — new optional fields, new `kind`
values behind explicit documentation — never a changed meaning.

## Envelope

Every line carries the same envelope plus its `kind`-specific `event`:

```json
{"schema": "p11scope/inventory-events/v1", "seq": 0, "at_ns": 987654321,
 "kind": "started", "event": {"scope": "pid:4242", "...": "..."}}
```

- `seq`: zero-based per-run sequence. Contiguous across rotations while
  every file is retained; retention evictions account exact seq ranges
  in `retention_evicted` events (see below), never silently.
- `at_ns`: `CLOCK_MONOTONIC` nanoseconds, the capture clock.
- `kind`: one of the values below.

## Event kinds

- `started`: `{scope, clock: {basis, unit}, started_ns, limits:
  {callers, modules, edges, endpoints, inventory_endpoints,
  inventory_attach_modules, semantic_state, retained_history}}`.
  First event of every run. `inventory_endpoints` and
  `inventory_attach_modules` (additive within v1) are the run's
  Inventory attach-set limits (`budgets.inventory_endpoints.limit`,
  `budgets.inventory_attach_modules.limit`).
- `caller_event`: one caller-incarnation turnover —
  `{event: admitted, caller}`, `{event: exited, caller, reason}`,
  `{event: exec_retired, old, new}`, `{event: reused, old, new}`, or
  `{event: admit_failed, pid, reason, budget}` where `budget` is
  `{resource, limit, requested}` or null (the same budget shape
  snapshot gaps carry).
- `gap_recorded`: `{index, caller, module, pid, subject, reason,
  budget}` — a snapshot `gaps[]` entry minus `repeats`, plus its
  ordinal `index` (equal to its snapshot `gaps[]` index): gap identity
  only. Gap identity fields equal the snapshot's; `repeats` rides
  `gap_repeated`. Emitted once per distinct gap, on its first
  occurrence, in `gaps[]` order.
- `gap_repeated`: `{index, repeats}` — the gap with that `index` now
  stands at `repeats` (cumulative, integer >= 2). `index` joins on the
  `gap_recorded` of the same `index`, so a consumer reading lines
  independently, or after rotation, resolves it explicitly. Mid-run it
  is emitted only when a gap's count crosses a power of two (2, 4, 8, …),
  so a steady recurring gap costs O(log passes) lines per run and the
  stream goes quiet; mid-run values are lower bounds. One exact flush of
  every gap whose count differs from its last emitted value is written
  just before `ended` on every clean termination, so the last
  `gap_repeated` per index (1 if none) equals the snapshot's
  `gaps[].repeats`. A stream without `ended` was cut short (an
  error exit, or a signal on the non-dashboard path); its last
  values are lower bounds.
- `pass_committed`: `{pass, scanned, maps_matched, native_callers,
  scan_callers, totals: {callers, modules, edges}, new_gaps,
  suppressed_delta, gaps_suppressed}` — what the pass scanned and what
  it cost. `scanned` counts the members observed (deep-scanned plus
  maps-matched); `maps_matched` counts those past the deep-scan cap
  attributed by exact maps identity (see `inventory-v1.md`). A native
  run's stop commits once more after its last pass (the terminal witness
  reads, the final lifecycle drain, the binder's finish): that commit's
  incarnation events and gaps precede one more `pass_committed` with the
  additive `final: true`, the last pass's `pass` number and zero scan
  counts, so `new_gaps` still sums to every streamed gap. Absent `final`
  means a scan pass.
  Every `pass_committed` also carries `unbound_rows`: the native
  witness rows staged since the previous marker that bound to no caller
  incarnation, as `[{module, reason, rows}]` in (module, reason) order —
  the per-pass delta of the snapshot's `modules[].unbound_use.reasons`
  (`reason` is an unbound code such as `no_live_caller` or
  `before_admission`). It never names a pid. At most 256 entries are
  listed; the rows of the rest are summed in `unbound_rows_truncated`
  (0 when nothing was cut). A scan-lane run always reads `[]` and 0.
- `caller_observed` / `module_observed` / `edge_observed`: full
  snapshot record shapes (test/sync emission; production emits
  incrementally instead). `edge_observed` adds the three derived
  presentation states `presence`, `capture`, `activity` — computed
  from the same model the dashboard renders, never new capture. Its
  `entries` object is the snapshot's verbatim, including the additive
  `entries.coverage` (see `inventory-v1.md`). `capture` is `armed`
  (usage actually covered: counted, witnessed, or watched), `scan
  only` (a live mapping no usage producer instruments), `refused`,
  `retired`, `coverage lost` (the reason is in
  `entries.coverage`), or `watch ended` (a `watched_no_use` frozen
  when native capture stopped or its scope custody was lost before
  stop: `until_ns` is set, so the watch is a fact about
  `since_ns..until_ns` only, never `armed`). `activity` is `recently
  observed`, `operation initialized / in flight`, `used (recency
  unknown)` (witnessed use), `quiet` (only under a loss-free count or
  an ongoing watch — a fact), `unknown (lossy)`, `not covered`
  (nothing covers the edge's usage), or `unknown` (no live mapping, or
  a watch that ended: its interval stays in `entries.coverage`). The
  dashboard shows a watch that ended as `entries ?`.
- `snapshot`: `{scope, passes, budgets, gaps_suppressed}` (test/sync
  emission marker).
- `rotated`: `{prior_file, prior_events, prior_bytes, rotation_seq}` —
  the new file's first line after every rotation. The boundary is
  explicit: the named prior file exists with exactly `prior_events`
  lines until retention evicts it (accounted in turn).
- `retention_evicted`: `{evicted_file, evicted_events, evicted_bytes,
  covered_events, covered_bytes, reason}` — the oldest rotation was
  deleted past the file bound. `evicted_events`/`evicted_bytes` are
  the deleted file's own lines/bytes; `covered_events`/`covered_bytes`
  re-cover the earlier evictions its inner records had covered, so the
  chain stays exact however deep it runs: retained lines plus
  accounted (direct + covered) always equal emitted.
- `ended`: `{ended_ns, passes, budgets, gaps_suppressed, stream:
  {rotations, evicted_events, evicted_bytes}}` — terminal marker with
  final budgets plus stream accounting.

## Transport and rotation

File transport: `--event-log <f.jsonl>` truncates/creates the live
file per run (each run owns its stream). Size rotation at
`--event-rotate-bytes` (default 1 MiB, plain or `K`/`M` suffixed):
when the next line would overflow, the live file syncs, renames to
`<f.jsonl>.<N>` (sequence continues past any prior run's files, never
colliding), and a fresh live file opens with its `rotated` marker.
Retention keeps the live file plus `--event-max-files - 1` rotations
(default 5 total); older files delete only with their
`retention_evicted` record in the live file.

Writes flush per event (SIGKILL-safe at the OS level) and sync on
rotation and `ended`. A mid-run stream failure (full disk, lost file)
is a hard run error, never a silent truncation.

## Privacy and loss accounting

Privacy bounds and loss accounting apply EXACTLY as to snapshots:
caller/module payloads carry exactly the snapshot caller/module keys;
edge payloads add only the three derived states; gap payloads equal
snapshot gaps' identity fields (`repeats` replays from `gap_repeated`); no new capture exists anywhere in the stream. Gap
retention (`gaps_suppressed`) and budget refusals mirror the snapshot
document pass for pass.

## Example (abridged)

```json
{"schema": "p11scope/inventory-events/v1", "seq": 0, "at_ns": 100, "kind": "started",
 "event": {"scope": "pid:4242", "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
           "started_ns": 100, "limits": {"callers": 4096, "modules": 4096, "edges": 32768,
           "endpoints": 1048576, "inventory_endpoints": 4096,
           "inventory_attach_modules": 4096, "semantic_state": 32768,
           "retained_history": 1024}}}
{"schema": "p11scope/inventory-events/v1", "seq": 1, "at_ns": 110, "kind": "caller_event",
 "event": {"event": "admitted", "caller": "c0"}}
{"schema": "p11scope/inventory-events/v1", "seq": 2, "at_ns": 110, "kind": "pass_committed",
 "event": {"pass": 0, "scanned": 1, "maps_matched": 0, "native_callers": 0, "scan_callers": 1,
           "totals": {"callers": 1, "modules": 1, "edges": 1}, "new_gaps": 1,
           "suppressed_delta": 0, "gaps_suppressed": 0}}
```
