# `C_GetInterface` selection-evidence design

**Date:** 2026-09-02 (Europe/Helsinki)
**Status:** owner-approved W3 direction; implementation begins only after the
schema and privacy wording below pass delegated review to zero
**Base:** `main@a2a264456bc0c30d3c30e727c85507940a90b75f`

## 1. Decision

W3 records `C_GetInterface` requests and outcomes as bounded **selection
evidence**, separate from the caller-independent function-table inventory.
Selection may supply count-only attach targets under the narrow authority rule
in section 7; it never creates an inventory surface, interface, alias, or
`fork_safe` fact.

Reuse the existing discovery hook registry, state map, ring buffer, process-view
lifecycle, table decoder, loss counters, and render path. Add no ring buffer,
dependency, selection-policy engine, or provider fallback logic.

This slice includes:

- live observation of built-in and custom `HookAbi::Interface` hooks;
- a fixed ten-query offline helper matrix;
- exact matching against the inventory without merging into it;
- selection-scoped count-only attachment when the exact authority rule holds;
- versioned manifest, observed-profile, and privacy contracts; and
- coverage and loss evidence that makes a missed call explicit.

Tracepoint offsets, opened-file identity, capability tiers, diagnostics, and
`uprobe_multi` remain later W3 slices.

## 2. Existing defect

The BPF entry program currently retains only `ppInterface`. The return program
emits kind 4 only for `CKR_OK`; userspace lowers kind 4 through the generic
export-table path and merges it into discovered interfaces and surfaces.
Requests and failures disappear, while a parameter-dependent selection result
is presented as caller-independent inventory. The offline helper explicitly
never calls `C_GetInterface`.

The fix is at that shared boundary: kind 4 becomes selection-only. Every
`HookAbi::Interface`, including custom hook symbols, follows the same rule.
`lower_export_record` accepts function-list and interface-list records only and
explicitly rejects kind 4. A separate selection reducer may attach an
authorized unmatched table, but may not mutate discovery inventory.

## 3. Live evidence contract

The entry program captures only bounded classifications and scalars:

- requested name: `null`, `exact_standard`, `other`, or `unreadable`;
- requested version: `null`, `unreadable`, `v2_40`, `v3_0`, `v3_1`, `v3_2`,
  or `other`;
- requested flags: the full-width `CK_FLAGS` scalar; and
- the private `ppInterface` address needed by the matching return.

Name bytes enter neither BPF state nor output. The BPF program performs one
bounded read sufficient to compare exactly with `"PKCS 11\0"`, then stores only
the class. It reads only the two-byte `CK_VERSION`, never bytes beyond it.
Pointers remain private transport inputs.

The return program emits one structurally validated kind-4 record for every
matched entry, including nonzero `CK_RV`. On `CKR_OK`, it also reads the returned
`CK_INTERFACE` and classifies:

- returned name with the same four name classes;
- returned table version with the same finite version classes;
- returned flags as a full-width scalar; and
- the returned table privately, using the existing bounded known-layout table
  reader only when section 7 permits it.

A nonzero return value is an observed outcome, not a discovery error. A
`CKR_OK` result with a null or unreadable `ppInterface`, interface, table, name,
or version is retained as an outcome with the appropriate class and read-loss
evidence; it is never upgraded to authority.

The shared `StartState` and `DiscoveryRecord` layouts may grow only enough to
carry these fields. Their C layout, zeroed reserved bytes, map value size, and
record-size validator receive compile-time and round-trip tests. A recursive
same-thread call that loses the no-overwrite state race increments
`discovery_state_failures`, removes no ambiguity by guessing, and forces
`PARTIAL`.

The attach cookie becomes a private per-attachment binding id, not merely a
global hook-symbol id. Binding ids are monotonically allocated, unique for the
whole capture, and never reused after retirement. Exhaustion refuses the new
attachment and forces `PARTIAL`; a delayed record for a retired id is rejected
rather than resolved against another binding. Userspace retains the binding
`{hook_id, abi, ProcessView, generation, hook-owner object, loader context}` and
validates it before attributing a record. `module` is always the index of that
hook-owner provider in `capture.modules[]`; it is never inferred from the
returned table mapping. A missing, retired, or disagreeing binding records no
authority and forces `PARTIAL`. This is required even when two providers expose
the same symbol in one process, and applies equally to custom interface hooks.

## 4. Coverage is per provider and retained binding

Every exact configured `HookAbi::Interface` binding, built-in or custom, has an
internal state for its retained `ProcessView` and generation: observed,
silently covered, or silently uncovered. The public state collapses all such
bindings for one `capture.modules[]` provider without exposing process identity:

- `observed`: at least one binding was observed and no silent binding was
  uncovered;
- `observed_uncovered`: at least one binding was observed and at least one
  other binding was silently uncovered;
- `absent_covered`: no binding was observed and every silent binding was
  covered; or
- `absent_uncovered`: no binding was observed and at least one silent binding
  was uncovered.

`absent_covered` is allowed only for either:

1. an owned `run` initial set whose pre-exec/constructor protection was
   confirmed before the provider could execute; or
2. a newly loaded provider whose qualified loader window was confirmed stopped
   until the selection hook was installed.

Command mode alone is never proof. An already-running `--pid` or `--cgroup`
target has a preattach window and therefore reports `absent_uncovered` unless a
call is later observed. An unqualified loader window, partial pause, process
generation change, selection truncation, ring loss, state failure, bounded-read
failure, malformed record, or unresolved provider attribution also makes an
otherwise silent provider `absent_uncovered` and forces `PARTIAL`.

The base tree has no populated timing-catalog proof for either covered case.
Therefore this slice reports a silent `run` provider as `absent_uncovered` too;
`absent_covered` is pinned at unit level through the engine's proof input but is
not claimed from a live call site until a later timing slice supplies that
proof. `observed_uncovered` and `absent_uncovered` force `PARTIAL`.

An exact pinned ELF proof that the export is absent is recorded separately in
`export_absent[]` only when no exact configured interface binding exists for
that provider. An entry is `{module, required}`. `required=false` is permitted
only when exact caller-independent inventory establishes a legacy 2.x provider;
it is not a coverage loss and does not force `PARTIAL`. `required=true` means
exact inventory establishes Cryptoki 3.x, whose missing standard export forces
`PARTIAL`. A provider whose export or binding status cannot be proved is a
selection-capable unresolved provider with `absent_uncovered`, not an
`export_absent` entry. The two sets are disjoint. Any capture-global selection
loss whose producer cannot be attributed changes each silent binding to
uncovered; a provider already observed becomes `observed_uncovered`, while a
fully silent provider becomes `absent_uncovered`. It never erases an observed
tuple or creates a guessed provider attribution.

## 5. Bounded aggregation

Profile output and terminal trace evidence aggregate identical tuples with a
count. Trace mode emits no per-call selection line. At most 16 distinct tuples
are retained across one capture. A seventeenth distinct tuple is not inserted;
`selection_truncated` becomes `true` and the verdict becomes `PARTIAL`.

A tuple consists of the exact fields below. Unknown fields are rejected.

| Field | JSON type and bound |
| --- | --- |
| `module` | unsigned 32-bit index into `capture.modules[]` |
| `request.name` | `null`, `exact_standard`, `other`, or `unreadable` |
| `request.version` | `null`, `unreadable`, `v2_40`, `v3_0`, `v3_1`, `v3_2`, or `other` |
| `request.flags` | unsigned 64-bit integer |
| `rv` | unsigned 64-bit integer |
| `result` | `null` when no readable result exists, otherwise an object with the same finite `name`/`version` classes and unsigned 64-bit `flags` |
| `table_match` | boolean, true exactly when `inventory_matches` is nonempty |
| `inventory_matches` | sorted unique array of at most 16 `{surface: u16, name_agrees: boolean, version_agrees: boolean}` objects; `surface` indexes `evidence.discovery[module].tables[]` for that provider |
| `authority` | `inventory`, `selection_count_only`, or `none` |
| `count` | saturating unsigned 64-bit integer, at least 1 |

`result=null` distinguishes a nonzero return or unreadable result from a
provider that returned readable zero-valued fields. More than 16 exact
inventory matches sets `selection_truncated`, retains the first 16 in numeric
order, and forces `PARTIAL`. At most 512 provider/export-status entries are
serialized; each module index is unique and less than
`capture.modules.len()`. Overflow is truncation and `PARTIAL`.

No tuple contains a PID, TID, address, pointer, raw name, arbitrary byte string,
or provider error text. Counters saturate rather than wrap.

## 6. Exact table matching

Name or version agreement never establishes a table match.

For live evidence, an `inventory_matches[]` entry exists only when the returned
`pFunctionList` address equals a `ScannedTable.address` that is published as a
caller-independent legacy or interface surface in
`evidence.discovery[module].tables[]` and:

- came from the memory scan, `C_GetFunctionList`, or a kind-2
  `C_GetInterfaceList` record;
- belongs to the same `ProcessView` and retained process generation;
- resolves through the same fresh maps snapshot to the same module device and
  inode; and
- remains stable through selection reduction.

For offline evidence, an inventory match exists only when the returned
`pFunctionList` pointer equals one of the helper's own caller-independent
legacy or interface surfaces from the same loaded provider instance. The
manifest records that entry's ordinal in `surfaces[]`, not either pointer. The
live and offline ordinals are bounded by their referenced array lengths. All
matches are retained in sorted order so shared-address aliases remain explicit;
a scanned table without a published caller-independent surface is unmatched.

Each match's `name_agrees` and `version_agrees` booleans are derived after the
exact table match. They expose a provider inconsistency but never widen a match.
An unmatched result is explicit and forces `PARTIAL`.

## 7. Open design ruling: authority of selection-only tables

This document closes the charter's open ruling as follows.

An exact inventory match uses the inventory's existing authority. It adds no
new table, surface, alias, or function identity.

An unmatched live result may authorize a **selection-scoped count-only** table
only when all of these hold:

- request and returned names are `exact_standard`;
- the returned version is one of 3.0, 3.1, or 3.2 with a known table layout;
- the table and every function pointer resolve inside the same retained
  process generation and exact pinned hook-owner provider module object;
- the provider, maps snapshot, and pin remain stable through attach; and
- no selection read, state, transport, attribution, or truncation loss applies.

An unmatched offline result has the same name/layout requirements and is
eligible only under manifest-v5 attestation for the exact provider identity
already enforced by manifest pinning. Its returned table and every function
pointer must resolve to file offsets inside that exact pinned provider module
object. Anonymous, dependency-object, outside-module, unstable, or unresolved
pointers are retained only as a finite helper failure and authorize nothing.

The resulting function identities may be probed and counted so real calls are
not missed, but `semantic_authorized` is always `false`, semantic argument
decoders are disabled, and the capture is `PARTIAL`. `null`, `other`, or
`unreadable` names; 2.40, `other`, null, or unreadable versions; unstable or
unmatched objects; and helper failures authorize nothing.

Selection-only targets appear only in selection evidence and the aggregate
function rows they count. They do not contribute to
`evidence.discovery[].tables`, `.interfaces`, `surfaces`, `interface_list`,
`vendor_interfaces`, aliases, or slot-level `fork_safe` conclusions.

Their decoded non-null function occurrences contribute to `table_entries`
under the existing exact-occurrence deduplication rule. A target whose exact
`{object, file_offset}` already has a planned or attached slot is linked to that
slot and is never attached again; it contributes no new `slots`,
`attached_probes`, or aggregate function row. A new target contributes one
slot and, after successful attachment, two probes exactly as existing slots do.
Thus selection cannot double-count a call or break the existing
`table_entries`/`slots`/`attached_probes` relationships.

They are source-tagged slots keyed by
`{ProcessView, generation, loader context, hook-owner object, selected object,
function name, file offset}`. They enter the existing candidate
preflight/apply/rollback transaction but remain outside `CaptureHistory`'s
inventory collections. Unload, exec, generation loss, loader-context
retirement, and terminal cleanup retire their links and authority. No
selection link is attached directly outside that transaction.

## 8. Offline helper matrix

The helper resolves `C_GetInterface` inside the requested module and performs
queries before `C_Initialize` (which the helper continues not to call).
The raw ABI adapter stays in `p11scope-discover` and uses its existing direct
`cryptoki-sys` and `libloading` dependencies. It performs one call exactly as
requested and contains no fallback/selection policy. The pinned external
`pkcs11-module` facts crate and its Git revision do not change for this slice.

Acquisition has exactly three outer states:

- `export_absent`: zero calls;
- `export_outside_module`: zero calls and the export is refused; or
- `queried`: exactly ten calls.

The ten calls are the Cartesian product of these five numbered selectors:

0. name `NULL`, version `NULL`;
1. name `"PKCS 11"`, version `NULL`;
2. name `"PKCS 11"`, version 3.0;
3. name `"PKCS 11"`, version 3.1;
4. name `"PKCS 11"`, version 3.2;

with flags `0` and `CKF_INTERFACE_FORK_SAFE` (`1`). No adaptive retry,
fallback, or vendor query is added.

Each call records its request and `CK_RV`. A nonzero `CK_RV` is a normal query
outcome. After `CKR_OK`, inability to read, classify, match, or safely walk the
returned structure is `helper_failure` on that outcome, not an acquisition
error and not an invented failure return. Returned pointers never enter the
manifest. Request flags are exactly `0` or `1`; returned flags remain an
unmasked full-width scalar, including unknown provider bits.

## 9. Versioned schemas

### 9.1 Offline manifest

The helper emits only `p11scope-manifest/5`. The top-level
`selection_evidence` object is a sibling of `surfaces`, `interface_list`, and
`vendor_interfaces`. Unknown fields are rejected.

| Field | JSON type and bound |
| --- | --- |
| `acquisition` | `export_absent`, `export_outside_module`, or `queried` |
| `queries` | array of exactly 0 entries for the first two acquisition states or exactly 10 entries for `queried` |
| `tables` | array of at most 10 selection-only table records |
| `selection_truncated` | boolean; true exactly when more than 16 exact aliases were available to a query |

Each query has:

- `selector`: integer 0 through 4, unique when paired with request flags;
- `request`: finite name/version classes plus flags exactly `0` or `1`;
- `rv`: unsigned 64-bit integer;
- `result`: `null`, or finite returned name/version classes plus unmasked
  unsigned 64-bit flags;
- `inventory_matches`: sorted unique array of at most 16 `surface` indices into
  `surfaces[]`, each less than that array's length, with separate name/version
  agreement booleans;
- `selection_table`: `null` or an integer 0 through 9 referencing
  `tables[].id`;
- `authority`: `inventory`, `selection_count_only`, or `none`; and
- `helper_failure`: `null` or one of `null_output`, `unreadable_interface`,
  `unreadable_name`, `unreadable_version`, `unreadable_table`,
  `outside_provider`, `unresolved_function`, or `provider_changed`.

For `queried`, the array contains each selector/flag pair exactly once in
selector order with flags `0` then `1`. For either zero-call acquisition,
`tables` is empty and `selection_truncated` is false.

For nonzero `rv`, `result`, `selection_table`, and `helper_failure` are null,
`inventory_matches` is empty, and authority is `none`. For `CKR_OK`, a readable
but unsupported or unmatched result may also have authority `none` without a
helper failure. Authority is `inventory` exactly when matches are nonempty and
`selection_table` is null; it is `selection_count_only` exactly when matches
are empty and `selection_table` is nonnull. `helper_failure` is nonnull only
when post-success inspection could not produce a readable result or safe
authority decision; whenever `helper_failure` is nonnull, authority is `none`.
More than 16 exact aliases retains the first 16 in surface order, sets
`selection_truncated`, and forces `PARTIAL`. A table record has a unique integer
id, a 3.0/3.1/3.2 version, a `full` walk outcome, at most 104 existing
`FunctionRecord` values, and `semantic_authorized: false`. Every resolution
must name an existing manifest object and an offset inside the exact provider
module object; selection tables may not name dependency objects. No table or
function pointer is serialized. Every table is referenced by at least one
`CKR_OK` query with `authority=selection_count_only`, null `helper_failure`, and
matching `selection_table`; orphan or merely known-prefix tables are rejected,
and only reachable tables enter attachment planning.

Manifest v4 is intentionally rejected after W3, not silently upgraded. It
cannot prove whether the matrix ran, so a mechanical default would fabricate
evidence. Migration is to rerun the v5 helper against the same exact provider;
there is no JSON-only converter because the missing queries require provider
execution. All repository fixtures, scripts, validators, examples, and
consumers that require exact v4 are updated atomically with the schema change.
Structural validation pins every field, bound, matrix key, cross-reference,
and inventory-separation invariant above with positive and mutation tests.

### 9.2 Capture output

Profile output advances from the current
`pkcs11-scope/observed-profile/v2` contract to
`pkcs11-scope/observed-profile/v3`. The change is intentionally breaking for
exact-dispatch consumers: all v2 fields keep their names and meanings, while
v3 adds `evidence.interface_selection`; consumers must dispatch on v3 before
reading it. Repository scripts, fixtures, examples, docs, and schema pins move
in the same implementation task. There is no claim that v2 was unpublished.

Metrics output remains `pkcs11-scope/observed-profile/v2-metrics` because its
shape and no-argument-read contract do not change. Profile and terminal trace
evidence add `evidence.interface_selection`:

```json
{
  "providers": [
    {"module": 0, "coverage": "observed"}
  ],
  "export_absent": [],
  "tuples": [],
  "selection_truncated": false
}
```

`providers` contains unique selection-capable or unresolved module
ordinals with one of the four section-4 coverage values. It includes every
module with an exact configured built-in or custom `HookAbi::Interface`
binding, plus an unresolved module only as `absent_uncovered`. `export_absent`
contains sorted unique `{module, required}` records backed by exact pinned ELF
proof and is disjoint from `providers`; the two arrays contain at most 512
entries combined.
`tuples` is the at-most-16 array in
section 5. `selection_truncated` is a boolean. Every ordinal is less than
`capture.modules.len()`; duplicates, overlap, unknown fields, invalid enums,
bad result-null combinations, and inconsistent `table_match` are rejected by
exact JSON-shape and mutation tests.

Metrics remains aggregate-only, performs no selection argument reads for a
built-in or custom interface hook, and contains no `interface_selection`.
Trace mode emits the same bounded aggregate only in its terminal evidence;
individual trace lines do not contain selection arguments or results.

## 10. Privacy allowlist v2 wording

`docs/privacy/allowlist-v1.md` remains unchanged as historical policy.
Implementation creates `allowlist-v2.md`, carries forward v1, and changes only
the following contract:

- **Function identity:** add a third source, an exact-standard
  selection-scoped live/offline table. Live authority is bound to one retained
  per-attachment producer binding, process generation, loader context, and
  exact hook-owner/provider object; offline authority is bound to manifest-v5
  attestation and exact provider-module object offsets. It is count-only,
  always `semantic_authorized=false`, never inventory, and forces `PARTIAL`.
- **Interface selection:** allow the four finite name classes, seven finite
  version classes, full-width request/result flags and `CK_RV`, three agreement
  booleans, three finite authority classes, four finite coverage classes,
  bounded module/surface/table/selector indices, finite acquisition,
  export-required, and helper-failure classifications, bounded counts, and
  live/offline truncation booleans. Exact target name bytes are compared in BPF
  and discarded; nonmatching bytes become `other`. No name bytes, pointer,
  address, PID/TID, or provider-controlled error string is output.

The existing prohibition that interface name bytes are not capture output
remains true. The allowlist revision authorizes finite classifications, not
names.

## 11. Error and verdict rules

The existing discovery loss counters remain the single owners for ring,
state, and bounded-read failures. Selection does not add shadow copies.
`discovery_ring_loss`, `discovery_state_failures`, and
`discovery_read_failures` retain their existing producer ownership. A
selection transport record rejected for ABI shape, producer binding, or
bounded userspace reduction increments `discovery_truncated` exactly once.
The call-event `malformed_records` counter is unrelated and is not incremented.

Any of these forces `PARTIAL`: `absent_uncovered`, `observed_uncovered`, a
required missing export, unmatched successful table,
`authority == selection_count_only`, live or offline `selection_truncated`,
helper failure, selection read/state/ring/malformed loss, process-generation
instability, or an outcome
whose provider cannot be attributed exactly. The renderer validates that every
loss that should affect completeness actually changes the consumer verdict.
An unattributable global selection loss changes every silent binding to
uncovered and makes the capture globally `PARTIAL`; observed providers keep
their observed tuples and become `observed_uncovered` when another binding is
silent. One table-driven
profile/terminal-trace test covers each cause and proves no double counting.

## 12. Acceptance tests

Implementation proceeds TDD and must leave these runnable pins:

1. kind 4, including a custom interface hook, changes no discovery surface,
   interface count, alias group, table inventory, or `fork_safe` fact;
2. request/result name and version classes, flags, `CK_RV`, and nonzero failure
   outcomes round-trip through the transport validator;
3. unknown/unterminated/aliased name bytes yield only `other` or `unreadable`,
   and secret canaries do not appear in maps or output; an aliased buffer whose
   exact bytes are `PKCS 11\0` is necessarily `exact_standard`, but those bytes
   are still discarded;
4. live exact matching requires address, view, generation, device, and inode;
   name/version agreement alone fails; all exact inventory matches are sorted
   and retained, including shared-address aliases;
5. only exact-standard known-layout unmatched results gain count-only targets,
   with semantic decoding disabled and `PARTIAL`; anonymous, dependency,
   outside-provider, unstable, and unresolved offline closures are refused;
6. `observed` and `absent_uncovered` are pinned at live call sites, including
   actual silent `--pid` and `run` cases; `absent_covered` is pinned through the
   engine proof input; two retained views sharing one provider produce
   `observed_uncovered`; exact legacy `export_absent` is non-loss, while a
   required 3.x missing export is `PARTIAL`;
7. the seventeenth distinct tuple sets `selection_truncated` and `PARTIAL`;
8. recursive no-overwrite state failure is counted and forces `PARTIAL`;
9. absent/outside helper exports make zero calls; queried makes exactly ten;
   nonzero `CK_RV` stays an outcome and post-success unreadability becomes
   `helper_failure`; unknown returned flag bits round-trip unmasked;
10. offline pointer equality selects a manifest surface; name/version equality
    without pointer equality does not;
11. manifest v5 accepts only the fixed matrix and v4 is rejected precisely;
    exact JSON mutation tests pin every enum, bound, result-null relation,
    object/offset reference, orphan-table refusal, full-walk requirement,
    seventeenth-alias truncation, and inventory-separation rule;
12. two providers with the same built-in or custom hook symbol are attributed
    by their private attachment bindings, including a returned table outside
    the hook owner that is refused authority; binding ids never reuse, and a
    delayed record after retirement is rejected;
13. an unmatched selection-only table enters the existing transactional attach
    path, reuses rather than duplicates an existing `{object, file_offset}`
    slot, then unload/exec/generation retirement detaches its new links without
    changing inventory, double-counting, or leaking rollback state;
14. profile v3 and terminal trace expose the bounded aggregate; metrics reads
    no selection arguments for built-in or custom hooks; no trace line emits
    raw selection data; every selection loss owner has a loss-to-verdict test;
15. every repository v2-profile/v4-manifest exact pin is migrated or retained
    only where explicitly historical, and README/helper module documentation
    truthfully states that the explicit offline helper now makes the ten calls;
    and
16. the canonical Rust 1.88 gates pass, followed by independent security and
    test-quality review to zero.

Privileged runtime, VM, and container lanes remain `UNRUN` unless separately
approved. Their absence is not represented as a pass.
