<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# `p11scope/inventory/v1`: module/caller inventory

Answers "which module is used by whom" for one scope (`--pid` or
`--system`) over one snapshot pass or a `--duration` observation window.
Emitted by `p11scope inventory [--json | -o <out.json>]`.

Consumers must dispatch on the exact `schema` string
(`p11scope/inventory/v1`). There is no semver-style compatibility:
a new schema id means a new contract. Within v1, additive evolution
only — new optional fields, new enum labels behind explicit gaps —
never a changed meaning for an existing field.

## Clock and units

- `clock.basis` is always `CLOCK_MONOTONIC`; `clock.unit` is always `ns`.
  Every `*_ns` timestamp is nanoseconds on that clock.
- Caller `start_time` is raw `/proc/<pid>/stat` starttime in
  `start_time_unit` (`clock_ticks_since_boot`), for incarnation
  comparison only — never wall time.
- Entry `cap` is `18446744073709551615` (`u64::MAX`): counts saturate
  there and set `saturated`; they never wrap.

## Model

- `callers[]`: one record per caller *incarnation* — one (pid,
  start-time) generation running one executable image. `id` (`c0`,
  `c1`, …) is stable for the capture, minted monotonically, never
  reused: PID reuse and exec retire the old incarnation (evidence
  retained) and mint a new one. `image.authority` is `native_exact`
  (BPF task-cookie/exec-ID identity) or `scan_pinned` (pidfd/start-time
  pin with exe-identity exec detection); `exec_observed` is false when
  the exe identity was unreadable and exec changes were undetectable.
  `lifecycle` is `mapped`, `exited`, `exec_retired`, or `unknown`
  (with `lifecycle_reason` whenever the state is not plainly mapped).
- `modules[]`: one record per distinct physical module instance,
  keyed by (device, inode, SHA-256) — never by path. Two callers
  mapping different objects at the same path are distinct records;
  the path list is an attribute. `admission` carries the scan-only
  verdict (`admitted`, `refused`, `unresolved`) with class, endpoint
  count, and reasons, plus the scan-only note: manifest corroboration
  was not consulted. `lifecycle` is `mapped`, `unloaded` (a complete
  rescan proved it gone; sticky in `unloaded_observed` even across a
  reload), or `unknown` (no live mapping evidence remains).
- `edges[]`: one record per (caller incarnation, module instance)
  pair. `mapping` is scan evidence (state `mapped`, `ended`, or
  `uncertain`, with first/last seen and an interruption count of
  observed mapped→absent→mapped transitions). `entries` is usage
  evidence from observed entries only: cumulative `count` plus
  first/last seen, an in-flight flag, and `observation` —
  `observed`, `unknown (not admitted)`, or `unknown (usage
  observation unavailable)`. A zero count with an `unknown`
  observation is not a fact about usage; a caller with zero observed
  entries is "mapped, quiet", never "active". Recency ("active now")
  is last-seen plus in-flight state, never a sticky bit.
- `gaps[]`: every explicit coverage loss — unadmitted members,
  unreadable pids, deferred scans, unknown identities — with subject
  and reason. Absence from the document is never evidence of
  absence; `gaps_suppressed` counts gaps dropped past the bound.
  A gap that records a budget refusal carries `budget` with the
  `resource`, its `limit`, and the `requested` occupancy; every other
  gap carries `budget: null`.
- `budgets`: every budgeted resource with its own limit, occupancy
  source, and loss counter — `callers`, `modules` (physical module
  instances), `edges` (caller relationships), `endpoints` (the
  retained attach-endpoint census: the sum of admitted per-module
  endpoint counts), `counters` (per-edge entry counts: the `cap`
  plus `observed_edges` and `saturated_edges`), `semantic_state`
  (`limit`, `occupied`, and `status`; capture stays withheld, so
  `occupied` is always 0 and every edge's `semantics` column reads
  `unknown (semantic capture withheld)`, never an invented state),
  and `retained_history` (`limit`, `retained`, `suppressed` — the gap
  retention cap and its eviction marker). Refusal never erases
  retained evidence: over-budget members are dropped with a named
  gap while catalog entries and previously observed use stay.

## Example (abridged)

```json
{
  "schema": "p11scope/inventory/v1",
  "scope": "pid:4242",
  "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
  "observation": {"started_ns": 100, "ended_ns": 200, "passes": 1, "usage_feed": false},
  "budgets": {
    "callers": {"limit": 4096, "occupied": 1, "refused": 0},
    "modules": {"limit": 4096, "occupied": 1, "refused": 0},
    "edges": {"limit": 32768, "occupied": 1, "refused": 0},
    "endpoints": {"limit": 1048576, "occupied": 68, "refused": 0},
    "counters": {"cap": 18446744073709551615, "observed_edges": 0, "saturated_edges": 0},
    "semantic_state": {"limit": 32768, "occupied": 0, "status": "withheld", "unknown_edges": 1},
    "retained_history": {"limit": 1024, "retained": 1, "suppressed": 0}
  },
  "callers": [
    {
      "id": "c0", "pid": 4242, "start_time": 987654, "start_time_unit": "clock_ticks_since_boot",
      "incarnation": 0,
      "image": {"authority": "scan_pinned", "task_cookie": null, "exec_id": null,
                "exe": {"dev": 8, "ino": 12345, "mtime_secs": 1700000000, "mtime_nanos": 0, "path": "/tmp/driver"},
                "exec_observed": true},
      "lifecycle": "mapped", "lifecycle_reason": null,
      "first_seen_ns": 110, "last_seen_ns": 190, "retired": false
    }
  ],
  "modules": [
    {
      "id": "m0", "paths": ["/tmp/prov.so"],
      "identity": {"device": {"major": 8, "minor": 1}, "inode": 23456,
                  "sha256": "abc…", "build_id": null, "source": "mountinfo"},
      "admission": {"state": "admitted", "class": "exact", "endpoints": 68, "reasons": [],
                   "note": "scan-only admission: manifest corroboration was not consulted"},
      "lifecycle": "mapped", "unloaded_observed": false
    }
  ],
  "edges": [
    {
      "caller": "c0", "module": "m0",
      "mapping": {"state": "mapped", "reason": null, "first_seen_ns": 110, "last_seen_ns": 190, "interruptions": 0},
      "entries": {"count": 0, "saturated": false, "cap": 18446744073709551615,
                 "first_seen_ns": null, "last_seen_ns": null, "in_flight": false,
                 "observation": "unknown (usage observation unavailable)"},
      "semantics": "unknown (semantic capture withheld)"
    }
  ],
  "gaps": [
    {"caller": null, "module": null, "pid": null,
     "subject": "exact image authority unavailable",
     "reason": "no BPF image identity; scan-lane incarnations by pidfd/start-time with exe-identity exec detection",
     "budget": null}
  ],
  "gaps_suppressed": 0
}
```
