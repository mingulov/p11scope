<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Scanned-module merge ownership

Status: binding model for the Mode-B merge-ownership repair. Base:
`task/v080-modeb-bpf` at `55be66b9e`. All line anchors are at that
revision unless a later commit is named. The holdback, terminal-entry,
and executable-matrix additions anchor at `13a841fed`; the
sealed-authority, discarded-candidate, and exact-grant additions
anchor at `0592b9235`.

Three tier-2 review rounds found one blocker class: retired views
regaining claims, and interface links surviving an address change
(fresh layout proof combined with old-address authority). Per-path
suppression sets derived from pin state cannot converge: every new
path re-derives them, and the object-wide derivation cannot see
per-view retirement. This spec states the ownership model once;
Step 2 enforces it at the single grant sites (types/constructors),
never per path.

## 1. Definitions

- **View**: one process generation under a `ProcessViewId`. The engine
  lists live views in `Engine::views`; a candidate lists its currency
  in `LiveCandidate::views` (`src/discovery/engine.rs:5076`).
- **Claim**: an entry in `PinnedObjects::ownership` under a view
  (`src/discovery/identity.rs:1325,1388`): `tables`, `targets`, `pins`.
  A claim says "this live view's bound modules need these objects".
- **Resolvability**: presence in `by_id`/`raw_to_id` (the pin opens and
  compares). Resolvability without claims is the carried shape: the
  object stays usable, nobody owns it.
- **Carried ids** (`carried_ids`, `identity.rs:2699`): objects
  resolvable but claimed by NO view. An OBJECT-liveness predicate. It
  answers "which objects have no owner", never "which views are
  retired". Allowed consumers: purge sparing
  (`replace_view_pins_inner`, `prune_view_pins_to_modules`) and the
  stale-retirement keep set. BANNED for claim derivation: an object
  with a live co-owner is absent from it, so any suppression derived
  from it resurrects the retired co-owner's view.
- **Mapping**: one observed instance of a table at a runtime `address`
  in one view generation. Addresses are generation-local
  (`scan.rs:2661-2664`); only the scan that read the mapping may speak
  for it.
- **Row identity**: a `ScannedTable` matched across scans by normalized
  content — `same_table_redecode` (`engine.rs:12198`: static both
  sides, equal file offset/version/walk/entries/holes/unpinned) — or by
  full equality including address (`scan.rs:2697-2712`).
- **Link**: `ScannedInterface.table` (`scan.rs:2728-2745`), a row index
  into the module's CURRENT table vector. The scan sets it by absolute
  function-list pointer, so a link observed against mapping M is valid
  only while its row shows M's address. The planner trusts the bare
  index (`table_evidence_score`, `scan.rs:3144-3146`; the
  `"interface linkage"` grant leg, `src/plan.rs:8440-8441`).
- **Layout proof**: per-mapping decode verdicts — `extension_impossible`
  (3.x wider layouts refuted, `scan.rs:2680-2694`), the module's
  `tables_scan_finished` contribution, `live_return` provenance, export
  agreement. Read by the semantic-eligibility and version gates
  (`plan.rs:8102,8289`) and the grant legs (`plan.rs:8434-8458`).
- **Interface authority**: `score.linked` — an `exact_standard`
  interface linked to the row. Only the standard interface implies the
  standard layout (U-15, `scan.rs:3138-3143`).

## 2. View states and the ONLY allowed transitions

| State | Meaning | Claims | Pins | Currency |
| --- | --- | --- | --- | --- |
| LIVE | Generation current: listed in `Engine::views`, admitted/fresh this tick, or declined-retained | Owns (binder files) | Owned | Member (declined leave post-build) |
| CARRIED | Generation ended but modules ride for still-attached objects; supplies exact attached targets | ZERO, always | Resolvable, claimless | Excluded (see deviation D2) |
| RETIRED | Terminal: generation ended AND modules no longer ride (dropped, purged, or never carried) | ZERO, always | May be gone | Never a member |

Allowed transitions:

- LIVE → LIVE (refresh, rescan, replay with no retirement).
- LIVE → CARRIED (removal/retirement WITH carry: removed view, or
  conservative retirement in an owned run, for a still-attached
  object).
- LIVE → RETIRED (removal WITHOUT carry: pid scope, non-owned run,
  refused/unpublished source, purge of unneeded ids).
- CARRIED → CARRIED (rides another tick/replay; stays claimless).
- CARRIED → RETIRED (carry ends: object detached, module dropped,
  stale retirement of redundant carry, purge of unneeded ids).
- RETIRED → (nothing). Retired is terminal.

FORBIDDEN: CARRIED → LIVE-under-the-old-view (re-claim: filing claims
under a carried view, whatever the pin state); RETIRED → anything; any
transition that files a claim under a non-LIVE view. A live co-owner's
claims on a SHARED pin change nothing about the carried view: the
co-owner keeps its claims, the carried view keeps none, and the shared
pin stays resolvable for both. Suppression is per-VIEW (retirement
provenance), never per-OBJECT (claimed-ness of the pin).

A new generation reusing an old numeric view id would be a DIFFERENT
view (LIVE), not a resurrection — but reuse while the previous
generation's rows still ride is forbidden: recycled-ID holdback at
allocation (`allocate_view_id_inner`, `engine.rs:15877`) keeps a
numeric ID unavailable for admission while any committed carried row
still uses it, so within one assembly a numeric view id names one
generation (deviation D1, enforced). Held IDs stay on the free list
and become available again on their own once the last carried row
retires; with every free ID held, allocation mints fresh or defers at
capacity exactly as on exhaustion. The Inventory allocator
(`reserve_owner`) mints without recycling, so it needs no holdback.

## 3. Claim authority

ONLY LIVE views own claims. Every rebuild declares its tick events;
ONE constructor derives the authority:

```text
authority = ((engine live views ∪ tick-fresh views) − tick-retired views) ∪ declined views
```

- `engine live views` = `Engine::views` ids at assembly time (still
  lists views this tick retires: `removed` is computed FROM it at
  `engine.rs:32609-32646` and the list mutates only after apply at
  `:33534,:33707` — hence the subtraction).
- `tick-fresh views` = admitted newcomers (inventory only) and the
  scanned/observed owner a path keeps (loader, lowering, export scan,
  reconciliation). A newcomer is unlisted but LIVE.
- `tick-retired views` = this tick's removals (inventory `removed`,
  conservative `retirements`, scoped-release owner). Subtraction wins
  over live-listing: a still-listed retiring view is CARRIED-or-worse,
  never an owner.
- `declined views` = stale views with no accepted removal decision
  (`engine.rs:33127-33140`): retained view, contexts, claims, slots.
  Declined wins over retired (a declined view is explicitly
  re-authorized; post-build it leaves currency at `:33432` but keeps
  pins/modules/claims).

Enforcement, in one place:

1. The binder — the ONE site that grants claims
   (`bind_scanned_modules`, `identity.rs:10163-10173`) — files claims
   for a bound module if and only if its view is authorized. Carried
   modules still bind (their exact attached targets ride into the
   plan); they file nothing. A `ClaimAuthority` value built by the
   single constructor travels into the binder; no caller reconstructs
   suppression from pin state.
2. The same authority scrubs the candidate pin set after the bind
   (`drop_view_claims` per unauthorized ridden view): pre-existing
   entries a caller forgot to remove, and stale entries filed by the
   pre-fix bug, converge to claimless instead of persisting.
3. `dead_module_views`, the per-site `claimless` derivations (including
   both `already_carried` conjuncts at `engine.rs:18526-18538` and
   `:30815-30829`), and the `claimless` binder-adjacent parameters are
   deleted. Entry points declare tick events (small explicit inputs),
   never suppression sets.

Selection claims (`SelectionClaimKey.view`) are already per-view and
drop stale views at retirement (`engine.rs:20700-20704`); unchanged.

## 4. Link binding

A link is bound to a (row identity, mapping address) PAIR, not to a
bare index and not to a bare address. The merge carries that pairing
in its lowering type until final indices are known:

- Lowering validates: an incoming association lands on a destination
  row ONLY if that row still shows the incoming mapping's address.
  A superseded mapping (a later incoming row rewrote the destination
  address within the same union) keeps its interface metadata as
  UNLINKED history (`table = None`); it never points at another
  mapping's row.
- Any address change in a merge re-derives or drops the link:
  remap unions unlink retained associations on the rewritten row
  (history stays reportable); fresh associations attach solely through
  the validated incoming map. Exact (same-address) unions keep links:
  both sides describe one mapping.
- The planner's trust (`score.linked` ⇒ grant leg) is therefore sound
  by construction: a surviving `Some(index)` always names a row
  showing the mapping the scan linked.

## 5. One-mapping rule

Layout proof and interface authority granted for one row must come
from ONE mapping:

- Same-address union: monotonic OR of proof flags (both sides describe
  the same mapping; `PartialEq` already ignores `extension_impossible`
  so a later proof-less re-decode cannot clear an earlier proof —
  clearing happens only by complete-scan replacement).
- Address-changing union: the union takes the FRESH decode's proof
  verdict (never carries proof the fresh mapping lacks) AND drops the
  retained links (never carries authority the fresh mapping lacks).
  Fresh proof + fresh link may grant; fresh proof + old link, like old
  proof + fresh link, grants nothing — each side alone must stand, and
  neither borrows the other's mapping.
- `live_return`/`manifest_supported` ORs are unchanged (observation
  flags, not mapping verdicts); `double_loaded`/`same_file_loads` keep
  their maximum rules; finished-ness keeps its AND-plus-no-new-static
  rule (`engine.rs:12232-12259`).

## 6. Dedup rule

Interface records are keyed `(index, name_class, flags, table)` — the
key the merge already interns incoming records by
(`engine.rs:12371-12385`). Unlinking coalesces: an invalidated
association merges (names fill in) with an equivalent unlinked record
instead of appending a duplicate. Repeated remaps therefore keep ONE
current link (when the fresh mapping links) plus ONE history record
per distinct metadata; interface history grows with distinct metadata
only, never with remap count. The unlink sites (remap arm, typed-live
opaque unlink) share ONE unlink-and-coalesce helper.

## 7. Entry points

### 7.1 Rebuilds (all funnel `live_candidate_with_pending, engine.rs:17902`)

| # | Entry point | Merge? | Tick-fresh | Tick-retired | Carried input |
| --- | --- | --- | --- | --- | --- |
| E1 | `inventory_candidate` (`:30588`; First/Final builds, newcomer-isolation trials) | YES: refreshed + newcomer scans union via `merge_scanned_module` (`:30773,:30779`) | admitted newcomers | `removed`-now | newly removed + previously carried ride; claimless by complement |
| E2 | `conservative_candidate` (`:18455`, via `replay_pending_conservative` `:28227`) | NO: rides committed | {} | `retirements` | retiring + previously carried ride; claimless by complement |
| E3 | `loader_candidate` (`:18281`, loader assembly `:18370-18398`) | NO: rides committed | {scanned view} | {} | committed carried ride; claimless by complement |
| E4 | `apply_pinned_lowered_module` (`:21174`, lowering) | YES: lowered module (`:21199`) | {observed view} | {} | committed carried ride; claimless by complement |
| E5 | `process_validated_loader_scan` (`:21960-22102`, export/loader scan) | YES: found modules (`:21960,:21965,:22043,:22054,:22086`) | {scanned view} | {} | committed carried ride; claimless by complement |
| E6 | `apply_learned_staging` (`:23464`, learned staging) | NO: rides committed | {} | {} | committed carried ride; claimless by complement |
| E7 | `process_selection_record_inner` (`:24342-24357`, selection claim) | NO: rides committed | {} | {} | committed carried ride; claimless by complement |
| E8 | `release_scoped_owner` (`inventory.rs:650`) | NO: ridden modules exclude the owner (`:670-675`) | {} | {owner} (declared; moot — its modules do not ride) | retained carried ride; claimless by complement |
| E9 | `prepare_inventory_reconciliation` (`inventory.rs:~1050-1114`) | YES: reconciliation facts (`:1106`) | {owner id} | {} | retained carried ride; claimless by complement |

E1–E9 declare tick events; the choke point derives authority (§3) and
binds/scans once. The test-only `live_candidate` (`:17824-17843`,
`#[cfg(test)]`, zero production callers) keeps authority-all so unit
harnesses bind freely; production coverage comes from E1–E9.

### 7.1a Terminal rebind (E13)

| # | Entry point | Merge? | Tick-fresh | Tick-retired | Carried input |
| --- | --- | --- | --- | --- | --- |
| E13 | terminal Finish rebind (`step_graph_rebind_auth` + `step_graph_rebind`, `engine.rs:35373,35469`) | NO: rebinds the sealed raw copy of committed modules minus selection-retired (`graph_module_retained`) | {} | selection-retired (`pending_retirements`) | committed carried ride; the cursor files claims only for authorized views |

E13's authority is the same set as the §3 constructor with no
newcomers and no declined views at Finish (live views minus the
selection-retired set), but it is built once — not once per credit —
by the RebindAuth phase: a strided walk over the live views (at most
one stride of inserts or removals per credit) under the graph epoch
and a reservation taken up front
(`ClaimAuthority::storage_bound`, `identity.rs:10128`), sealed before
the first Rebind credit. Every Rebind credit then reuses the sealed
set with no scan, so one credit never visits more than one stride of
authority items no matter how many views ride. The cursor's three
claim phases (`ClaimTables`/`ClaimModule`/`ClaimEntries`,
`identity.rs:6935+`) file only for authorized views; denied rows still
reconcile (their exact attached targets ride into the terminal plan)
and still advance one table/entry per credit, so the bounded
per-credit work is unchanged. Measure/grow/reset are untouched: they
preserve pre-existing (manifest, pre-arm) ownership, never file. The
terminal install then swaps the rebound pins/modules/plan into
committed state exactly as before.

### 7.2 Binds without carry (fresh scans only — authority-all honest)

- E10 `rebuild_discovered` (`engine.rs:11069`, bind `:11390`):
  initial aggregate rebuild; no carried modules exist yet.
- E11 `scan_reconciled_snapshot` (`:39696`, bind `:39704`):
  current scan inputs rebound into a FRESH aggregate; read-only
  snapshot, no committed state rides.
- E12 `inspect_system` aggregation (`inspect_system.rs:2039`):
  per-member fresh scans into a fresh aggregate; offline inspection,
  outside the capture pipeline.

### 7.3 Pin custody (never grants claims; preserves carried resolvability)

- `remove_view_except` (`identity.rs:2739`): drops one view's claims,
  purges ids left unowned except the carry keep set. Shared pins with
  a live co-owner stay via retained claims/raws, not via the keep set.
- `replace_view_pins*` (`:2177-2313`): drops the view's entry first,
  absorbs incoming, restores only `claims_for`; `carried_ids` spares
  resolvable-but-claimless ids from the purge (object-liveness use —
  allowed).
- `prune_view_pins_to_modules` (`:2326`): same carried sparing.
- `drop_view_claims` (`:2805`): removes one view's entry, never pins,
  raws, or another view's claims. After Step 2 its only production
  caller is the central scrub.
- `absorb`: merges pin sets; files no claims.

### 7.4 Stale retirement (`retire_stale_candidate_sources, engine.rs:20654`)

- Claimless-object carried modules survive (keep set from
  `carried_ids`, `:20677-20689`).
- A carried module for a LIVE-co-owned object retires as REDUNDANT
  (the live owner's module covers the object); this ends the carry,
  it never re-claims.
- Claimed/unpublished sources drop (U-07). Selection claims/bindings
  for stale views drop per-view (`:20665-20704`).

### 7.5 Explicitly out of scope (not scanned-module merging)

- `merge_current` / `merge_and_project_capture_facts` (`:3210,:17611`):
  capture-facts evidence merge (publication history).
- `merge_object_summaries` / `merge_discovered_module` (`:3973,:3992`):
  render-side publication summaries.
- `bind_plan_module_ids`, `bind_exec`, `bind_pending_corroboration`,
  `bind_fallback_proof` (`:3044,:4172,:10333,:10844`): plan/exec/
  corroboration binding; they file no ownership claims.

## 8. Recorded deviations (NOT changed by this model)

- D1 View-id reuse: ENFORCED by recycled-ID holdback (see §2). A
  recycled numeric id can never alias a committed carried row within
  one assembly: the id is unavailable for admission until its last
  carried row retires. No per-row generation marking is needed while
  the holdback stands; if the holdback is ever relaxed, the merge
  (which matches on the numeric view id), the binder, and the scrub
  must all become generation-qualified first.
- D2 Previously-carried currency: newly retired views leave
  `candidate.views`; previously carried views still enter it (preserved
  fix3 behavior; the stale-refusal follow-up owns it). Ownership
  (claims) is terminal regardless of currency membership.
- D3 No capture change: no new fields, payloads, keys, or PINs
  (allowlists v1/v2 intact); no schema change; no BPF/wire/ABI change.
  The merge only changes WHO may own a claim and WHICH mapping a
  link/proof speaks for.

## 9. Test contract

One table-driven suite over entry points × invariants:

- Dimensions: EVERY assembly entry point E1–E9 (plus E10–E12
  authority-all controls) × {retired view with a live co-owner
  sharing a pin, address change mid-merge, repeated remap, carried
  provider}.
- Each case asserts: surviving exact slots, live-owner claims intact,
  retired-owner claims absent, carried pins resolvable, links valid
  per §4, proof/linkage from one mapping per §5, interface history
  bounded per §6.
- Non-vacuity: every case FAILS on the base `55be66b9e` at its
  predicted assert (RED-first, committed before the fix), and every
  case passes after. Shared-pin resurrection, cross-mapping linkage,
  and unlinked-row accumulation each have a dedicated failing assert.
- Entry outcomes are executable from one case table
  (`merge_ownership_entry_outcomes_follow_the_case_table`,
  `engine_tests.rs:95635`): E1/E2/E4/E5/E6/E7 × {carried→refused at
  the currency check with the generation marker witnessed,
  healthy→committed with no refusal}, except E5's healthy cell,
  which is the empty-scan control (the rescan runs — its memory-scan
  attempt is witnessed — and honestly commits nothing because the
  harness stages no found modules). The committing E5 positive is
  `late_provider_loader_rescans_keep_stable_slots`
  (`engine_tests.rs:52124`), which rescans a real dlopen'd provider
  through the same entry. E7 runs through the production
  selection entry with the session's scripted table read; E7 carried
  inputs use real-file shared pins (overlay pins fabricate metadata
  and trip the live assessment's `check_unchanged`). E3/E8/E9 are named
  in the table (E3 build boundary, E8/E9 committing inventory-harness
  tests). The E4–E7 carried cells also observe the discarded
  candidate at the pre-mutation apply seam: the carried view owns
  nothing, exactly the expected owners hold entries, and every
  non-carried row's grant is exact. The terminal E13 gate has its
  cursor regression
  (`scanned_rebind_cursor_denies_carried_views_but_reconciles_their_rows`,
  `identity.rs:19036`) and its graph-entry bound regression
  (`terminal_rebind_authority_credit_stays_bounded_over_many_live_views`,
  `engine_tests.rs:76407`); view-id holdback has its admission regression
  (`merge_ownership_e1_reused_view_id_holds_while_carried_row_rides`,
  `engine_tests.rs:93751`); E11 has its snapshot control
  (`merge_ownership_e11_snapshot_binds_fresh_views_with_claims`,
  `engine_tests.rs:94887`), asserting each bound row's exact table
  object, (object, offset) targets and pins; E10/E12 name their
  real-entry controls in the matrix comment, with E12's populated
  controls (`aimed_inventory_capture_admits_heuristic_module_first_come`
  and `bind_collection_populated_member_files_exact_derived_claims`,
  `inspect_system.rs:8581,8596`) asserting admission and exact derived
  claims. D2 refusal guards assert the currency-check marker
  (`mo_generation_markers`), so an early return fails instead
  of passing.
