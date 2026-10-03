<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# `p11scope/inventory/v1`: module/caller inventory

Answers "which module is used by whom" for one scope (`--pid` or
`--system`) over one snapshot pass or a `--duration` observation window.
Emitted by `p11scope inventory [--json | -o <out.json>]`.

Consumers must dispatch on the exact `schema` string
(`p11scope/inventory/v1`). There is no semver-style compatibility:
a new schema id means a new contract. Within v1, additive evolution
only — new optional fields and new enum labels, each documented here
(a label this document does not list must be read as unknown) —
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
  Under `--system`, every process with attributable mappings registers
  as a caller on every pass, whatever `--max-scan-pids` is: a process
  the deep-scan cap left unselected registers when its `/proc/<pid>/maps`
  shows, by exact `(device, inode)`, a provider object a deep scan of
  another process pinned in the same pass (a *maps match*, below). The
  cap bounds only how many processes are deep-scanned, i.e. the
  discovery of objects no process seen so far maps. A collected member's
  mappings project onto a caller only when its generation joins the
  incarnation reconcile holds for the pid: equal start times (both
  present), and for a maps match equal exe identities (both present; a
  deep scan refuses only when both were read and differ). Members that
  fail the join are not projected (their existing edges read
  `uncertain`) and are counted in one `caller generation join refused`
  gap per pass by category (`generation_changed`, `exec_changed`,
  `confirm_unreadable`).
- `modules[]`: one record per distinct physical module instance,
  keyed by (device, inode, SHA-256) — never by path. Two callers
  mapping different objects at the same path are distinct records;
  the path list is an attribute. `admission` carries the scan-only
  verdict (`admitted`, `refused`, `unresolved`) with class, endpoint
  count, and reasons, plus the scan-only note: manifest corroboration
  was not consulted. The run's attach set is the only admission
  source: `admitted` means the attach set holds the module's
  endpoints for this run. An object the attach set never judged (no
  comparable pin or digest) never reads `admitted` — the catalog's own
  admission is not taken over: it reads `unresolved` (or the
  catalog's `refused`, since nothing attaches either way) with a
  reason saying the attach set did not judge it. Within that one
  source the verdict only rises (`unresolved` < `refused` <
  `admitted`) and never falls back, so a module the attach set admits
  after a first refusal reads `admitted` — an instrumented module never
  reads `refused`; a lower later verdict is not applied but is
  disclosed in `reasons` (deduplicated, at most 8 entries).
  `admission.history` (additive within v1) lists each rise as
  `{from, to, at_ns}` in order (`[]` while the first verdict stands, at
  most two entries), and each rise is also a `module admission changed`
  gap. The verdict is judged against the Inventory
  endpoint budget (4096 endpoints), not the 512-slot detailed ceiling
  `inspect --system` reports, so the two can disagree either way: an
  object `inspect` refuses can read `admitted` here, and one it admits
  can read `refused` here. Each pass lowers under that budget with the
  same shared-scope reserve `inspect` applies (uncorroborated providers
  — unlinked heuristic tables, proxy closure arrays — take at most 3072
  of the 4096), and endpoints admitted earlier in the run stay counted
  for the whole run: an endpoint ID is never reused, so a module can be
  refused once earlier modules hold the budget. Refusals by the run's
  attach set — the run-lifetime endpoint or module-record budget, an
  object that could not be resolved or retained, and a module whose
  object changed identity since its endpoints were taken — are also
  recorded in `gaps[]` (`inventory attach set refused module`, or
  `inventory attach target changed identity`), once per module and
  refusal kind (bounded: past the bound one `inventory attach set
  refusal gaps bounded` gap is recorded and later refusals live in
  their verdicts only); a refusal by one pass's lowering reads `refused` with
  its reason and no gap.
  `lifecycle` is `mapped`, `unloaded` (a complete rescan proved it
  gone; sticky in `unloaded_observed` even across a reload), or
  `unknown` (no live mapping evidence remains).
  Boundary: the key is file identity, not load-instance authority —
  a same-file double-load (two loader mappings of one file, notably
  a `dlmopen` private-namespace double-load whose objects own
  distinct PKCS#11 session namespaces) merges into one record and
  one edge per caller. When the scan evidence shows the double load
  (duplicate executable file-offset coverage in the caller's
  process), the edge latches: its semantics read `unknown (same-file
  double-load)`, its calls establish no claim, and the `same-file
  double-load detected` gap names it; without that evidence the
  merge carries no marking. For `dlopen` in one namespace the merge
  is correct (same file → same loaded object → one session
  namespace); per-instance separation for `dlmopen` is S2 scope
  (instance authority — see `docs/notes/s2-instance-authority.md`).
- `edges[]`: one record per (caller incarnation, module instance)
  pair. `mapping` is scan evidence (state `mapped`, `ended`, or
  `uncertain`, with first/last seen and an interruption count of
  observed mapped→absent→mapped transitions). `mapping.evidence` says
  how the latest mapping observation was established: `deep_scan` (a
  deep scan of the caller decoded it) or `maps_match` (the caller's
  maps, re-read under a pidfd/start-time pin with its exe identity
  unchanged across the read, show the object by exact `(device, inode)`
  while the object a deep scan pinned this pass is held open — the
  caller itself was not decoded). Absence is authoritative (`ended`)
  only after a complete deep scan of the live caller: a module missing
  from a maps match reads `uncertain`. A maps match never comes from a
  ` (deleted)` mapping, an overlay-collapsed or aliased key, a rejected
  key, or a filesystem whose inode numbers are not unique (FUSE,
  network filesystems). `entries` is usage
  evidence from observed entries only: cumulative `count` plus
  first/last seen, an in-flight flag, and `observation` —
  `observed`, `unknown (not admitted)`, `unknown (usage observation
  unavailable)`, `unknown (count unavailable; use witnessed)`, or
  `unknown (usage observation lossy)`. A zero count with an `unknown`
  observation is not a fact about usage; a caller with zero observed
  entries is "mapped, quiet", never "active". Recency ("active now")
  is last-seen plus in-flight state, never a sticky bit; last-seen
  comes only from counted entries.
- `edges[].entries.coverage` (additive within v1): what this edge's
  usage columns can claim, per edge — never a run-wide flag. Always
  the seven keys `{state, since_ns, until_ns, first_ns, lossy, reason, detail}`
  (`null` where a key does not apply: `lossy` is a boolean only for
  `counted`). `state` is:
  - `counted`: a counting feed (actual call observations) covers the
    edge since `since_ns`; `count` and `last_seen_ns` are meaningful.
    `lossy: true` means records were lost: a positive count is a lower
    bound and a zero reads `unknown (usage observation lossy)`.
  - `witnessed`: use was witnessed (first at `first_ns`) but nothing
    counts it — `count` stays 0 for old consumers, `observation` reads
    `unknown (count unavailable; use witnessed)`, and the dashboard
    activity reads `used (recency unknown)`, never quiet.
  - `watched_no_use`: every endpoint of the module is attached for
    this caller since `since_ns` with clean health, and no use was
    seen: the zero is a fact (`observation` `observed`). `since_ns`
    never precedes the last health regression's detecting read (a
    watch noted later starts there). `until_ns` is `null` while the
    native capture runs; when it stops, every watch ends at the last
    witness read that proved clean health and held scope custody, and
    `since_ns..until_ns` stays a frozen fact (a watch no clean read
    proved reads `unknown`/`loss` instead). The watched interval also
    ends when the edge does — caller retirement or a complete-absence
    unload (`mapping.state` `ended`, `mapping.last_seen_ns`); the state
    then reads as the frozen fact for that interval.
  - `unknown`: nothing can be claimed; `reason` is one of
    `scan_only` (no native usage producer runs — every edge of a
    scan-only run), `not_admitted`, `not_attached`, `attach_failed`,
    `identity_unavailable`, `capacity_limited` (`detail` names the
    resource), `loss` (`detail` says what was lost), or
    `retired_before_coverage`.
  A zero reads `observed` only under `watched_no_use` or a loss-free
  `counted`. Positive coverage (`counted` entries, `witnessed`) is
  monotonic history: it survives loss, caller retirement, and module
  unload. A global health regression (a native identity, pair, or
  usage evidence counter rising) demotes every `watched_no_use`
  interval that reaches past the last clean read before the rise to
  `unknown`/`loss`, and is recorded as a `usage coverage health
  regression` gap. The demoted interval stays demoted; a new interval
  may start only from the read that detected the rise. The demotion is
  conservative: it also demotes edges whose watched interval had
  already ended (retired callers, unloaded modules) before the
  regression, because the failure cannot be localized in time per
  edge; only an interval frozen at capture stop before the rise
  stands. Coverage notes that cannot apply are gaps, once per (caller,
  module): `usage coverage without mapping evidence` (no such edge)
  and `coverage for an unadmitted module` (a counting or watch note
  for a module not `admitted`; its usage stays unknown). `observation.usage_feed` is
  a derived summary: true iff at least one edge holds non-`unknown`
  coverage.
- `edges[].semantics` (S1): the per-edge semantic summary label —
  `observed` iff the edge holds at least one mechanism or operation
  claim, otherwise the reason no claim exists:
  `unknown (semantic capture withheld)` (no semantic feed ever
  observed this edge — the scan lane alone), `unknown
  (unauthoritative module)`, `unknown (ambiguous descriptor)`
  (aliased/ambiguous producing descriptors),
  `unknown (count-only slot)` (count-only or unrecognized producing
  slots), `unknown (no operation evidence)` (an authorized feed
  observed only lifecycle traffic, failed `Init`s, or orphan calls
  that establish no claim), or `unknown (same-file double-load)`
  (scan evidence shows the object loaded twice in the caller's
  process — duplicate executable file-offset coverage — so no
  observed call can attribute to one instance and every call voids;
  the `same-file double-load detected` gap names the edge).
  Unsupported or ambiguous semantics render `unknown`, never
  invented.
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
  retired edges, uncertain mappings, and same-file double-load
  detection end affected operations as `unknown` (the
  `semantic capture loss` gap names pass-wide loss; the
  `same-file double-load detected` gap names double-loaded edges);
  per-edge bound overflows refuse with `dropped` plus the
  budget `refused` counter, never by evicting retained facts
  (async pending/detached records are the one oldest-evicted
  exception, counted in `async_evictions`).
- `gaps[]`: every explicit coverage loss — unadmitted members,
  unreadable pids, deferred scans, unknown identities — with subject
  and reason. Past the deep-scan cap, a pass records `discovery capped`
  only when something stayed unexamined: "`N` processes in scope; `D`
  deep-scanned by provider rarity (limit `L`); `M` attributed to
  pinned provider objects by exact maps identity; `U` processes map
  `K` shared objects no deep scan examined and may use undiscovered
  providers" (plus how many processes had no maps snapshot). When
  nothing stayed unexamined and nothing was lost, the same subject
  reads "attribution complete: …" instead — a note, not a loss.
  `maps attribution` gaps count attribution losses by category
  (`generation_changed`, `exec_changed`, `confirm_unreadable`,
  `deleted_mapping`, `object_changed`, `key_rejected`,
  `inode_not_unique`, `budget`) and name a matched caller that also
  maps shared objects no deep scan examined; an object whose sweep
  matching was refused (non-unique inodes) or dropped (it changed
  after the confirmation reads) is a gap under its path. Admission
  failures record one `caller admission failed` gap per pass and kind:
  a single failure keeps its pid and exact reason; several aggregate
  with a count (`N admissions refused this pass: caller budget
  exhausted…` with the budget, or `N pids could not be admitted this
  pass; first: pid P: …`). Absence from the document is never evidence of
  absence; `gaps_suppressed` counts gaps dropped past the bound.
  A gap that records a budget refusal carries `budget` with the
  `resource`, its `limit`, and the `requested` occupancy; every other
  gap carries `budget: null`. Run-lifetime admission refusals name the
  `inventory_endpoints` or `inventory_attach_modules` resource.
- `budgets`: every budgeted resource with its own limit, occupancy
  source, and loss counter — `callers`, `modules` (physical module
  instances), `edges` (caller relationships), `endpoints` (the
  retained attach-endpoint census: the sum of admitted per-module
  endpoint counts), `inventory_endpoints` (additive within v1:
  `{limit, occupied}` — the run's Inventory attach set, whose
  capture-lifetime endpoint budget the admission verdicts are judged
  against, and the endpoints it holds; IDs are never reused, so
  occupancy only grows, and its refusals are the
  `inventory_endpoints`/`inventory_attach_modules` budget gaps;
  `refused` counts per-pass module refusals on that budget, so one
  module refused on every pass counts once per pass),
  `inventory_attach_modules` (additive within v1: `{limit, occupied,
  refused}` — the attach set's module records, capped at its endpoint
  budget, with per-pass refusals on that cap),
  `counters` (per-edge entry counts: the `cap`
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
  retention cap and its eviction marker; `limit` is the `--max-gaps`
  bound, 1024 unless the operator overrode it). Refusal never erases
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
    "inventory_endpoints": {"limit": 4096, "occupied": 68, "refused": 0},
    "inventory_attach_modules": {"limit": 4096, "occupied": 1, "refused": 0},
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
                   "note": "scan-only admission: manifest corroboration was not consulted",
                   "history": []},
      "lifecycle": "mapped", "unloaded_observed": false
    }
  ],
  "edges": [
    {
      "caller": "c0", "module": "m0",
      "mapping": {"state": "mapped", "reason": null, "first_seen_ns": 110, "last_seen_ns": 190, "interruptions": 0},
      "entries": {"count": 0, "saturated": false, "cap": 18446744073709551615,
                 "first_seen_ns": null, "last_seen_ns": null, "in_flight": false,
                 "observation": "unknown (usage observation unavailable)",
                 "coverage": {"state": "unknown", "since_ns": null, "until_ns": null, "first_ns": null,
                              "lossy": null, "reason": "scan_only", "detail": null}},
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
