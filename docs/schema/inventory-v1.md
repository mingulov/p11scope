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
  Boundary: the key is file identity, not load-instance authority —
  a same-file double-load (two loader mappings of one file, notably
  a `dlmopen` private-namespace double-load whose objects own
  distinct PKCS#11 session namespaces) merges into one record and
  one edge per caller, joining the instances' session namespaces
  with no marking gap. For `dlopen` in one namespace the merge is
  correct (same file → same loaded object → one session namespace);
  the `dlmopen` case is S2 scope (instance authority — see
  `docs/notes/s2-instance-authority.md`).
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
- `edges[].semantics` (S1): the per-edge semantic summary label —
  `observed` iff the edge holds at least one mechanism or operation
  claim, otherwise the reason no claim exists:
  `unknown (semantic capture withheld)` (no semantic feed ever
  observed this edge — the scan lane alone), `unknown
  (unauthoritative module)`, `unknown (ambiguous descriptor)`
  (aliased/ambiguous producing descriptors),
  `unknown (count-only slot)` (count-only or unrecognized producing
  slots), or `unknown (no operation evidence)` (an authorized feed
  observed only lifecycle traffic, failed `Init`s, or orphan calls
  that establish no claim). Unsupported or ambiguous semantics
  render `unknown`, never invented.
- `edges[].mechanisms` (S1, `null` when no mechanism was
  attributed): one row per attributed mechanism id, sorted by id,
  each with exactly these keys: `mechanism` (the verbatim `u64` id —
  vendor ids survive unchanged), `mechanism_hex` (`0x…`), `name`
  (the registered `CKM_*` name, or `null` for vendor/unregistered
  ids — never guessed), `operations` (sorted operation categories
  this id was seen initializing, from the `*Init` function names:
  `sign`, `encrypt`, …, `message_sign`, …, `generate_key`, …),
  `calls` (API calls attributed to this id), `errors` (attributed
  calls with `rv != CKR_OK`), `last_seen_ns` (last attributed call),
  and `evidence` with `functions` (sorted verbatim function names
  that established claims here), `returns` (sorted `{rv, rv_hex,
  name}` rows — `name` is the registered `CKR_*` name or `null`),
  and `truncated` (true when a provenance set hit its bound and
  stopped growing). A mechanism label never implies more than the
  label: `CKM_AES_GCM` carries no key size, `CKM_RSA_PKCS_PSS`
  carries no size or parameters, `CKM_ECDSA` carries no curve —
  there are no size/curve/parameter keys in S1 output.
- `edges[].operations` (S1, `null` when the edge holds no claims):
  the per-edge operation aggregates with exactly these keys:
  `calls` (authorized calls with semantic content),
  `started` (`*Init`-created operations plus completed-direct
  calls — an OK `*Init` with an unreadable mechanism still creates
  its operation with the mechanism unknown, contributing no
  `mechanisms` row), `completed`/`cancelled`/`failed`/`unknown` (explicit end
  states — completed ⟺ ended by an `OK` return; cancelled ⟺ ended
  by cancel, replacement, or scope end; failed ⟺ ended by an error
  return; unknown ⟺ invalidated by loss, retirement, or a
  contradicted model — never silently completed, never silently
  dropped), `orphans` (calls/completions unattributable to a
  tracked operation — unknown-origin evidence, never invented
  joins), `dropped` (keys refused past the per-edge bounds),
  `last_seen_ns`, `active` (live machines as sorted
  `{category, state, count}` rows; `state` is `initialized` or
  `in_progress`), and `evidence` (small ambiguity counters:
  `state_reconciliations`, `session_cancel_ambiguities`,
  `session_cancel_unknown_flags`, `operation_state_imports`,
  `auth_state_ambiguities`, `semantic_capture_failures`,
  `async_duplicates`, `async_evictions`, `unmatched_closes`).
  API-call counts and operation counts are separate counters: a
  retry loop is N calls, one operation. "Right now" stays three
  distinct facts — recent call (`entries.last_seen_ns`), operation
  initialized (`operations.active`), API call in flight
  (`entries.in_flight`) — never merged. Raw session handles are
  never serialized; only per-edge aggregates leave the reducer.
  Completions apply on the completing session only, so a
  cross-session async completion orphans rather than joining
  across sessions; fork-inherited sessions read as
  unknown-origin on the child's edge. Capture-loss boundaries,
  retired edges, and uncertain mappings end affected operations
  as `unknown` (the `semantic capture loss` gap names pass-wide
  loss); per-edge bound overflows refuse with `dropped` plus the
  budget `refused` counter, never by evicting retained facts
  (async pending/detached records are the one oldest-evicted
  exception, counted in `async_evictions`).
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
  (`limit`, `occupied`, `status`, `unknown_edges`, and `refused`;
  `status` is `withheld` while no edge holds semantic state — the
  scan lane alone, where `occupied` is 0 and every edge reads
  `unknown (semantic capture withheld)` — and `observed` once the
  semantic feed materializes any; `unknown_edges` counts the edges
  lacking semantic claims; `refused` counts semantic keys refused
  past budget — materializations past `limit` (each also a named
  budget gap) plus per-edge keys past the S1 bounds),
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
    "semantic_state": {"limit": 32768, "occupied": 0, "status": "withheld", "unknown_edges": 1, "refused": 0},
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
      "semantics": "unknown (semantic capture withheld)",
      "mechanisms": null,
      "operations": null
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

An observed edge (S1, abridged to the semantic keys) carries the
label plus the mechanism rows and operation aggregates:

```json
{
  "caller": "c0", "module": "m0",
  "semantics": "observed",
  "mechanisms": [
    {"mechanism": 4225, "mechanism_hex": "0x1081", "name": "CKM_AES_ECB",
     "operations": ["encrypt"], "calls": 3, "errors": 0, "last_seen_ns": 190,
     "evidence": {"functions": ["C_EncryptInit", "C_EncryptUpdate"],
                 "returns": [{"rv": 0, "rv_hex": "0x0", "name": "CKR_OK"}],
                 "truncated": false}}
  ],
  "operations": {
    "calls": 3, "started": 1, "completed": 0, "cancelled": 0,
    "failed": 0, "unknown": 0, "orphans": 0, "dropped": 0,
    "last_seen_ns": 190,
    "active": [{"category": "encrypt", "state": "in_progress", "count": 1}],
    "evidence": {"state_reconciliations": 0, "session_cancel_ambiguities": 0,
               "session_cancel_unknown_flags": 0, "operation_state_imports": 0,
               "auth_state_ambiguities": 0, "semantic_capture_failures": 0,
               "async_duplicates": 0, "async_evictions": 0, "unmatched_closes": 0}
  }
}
```
