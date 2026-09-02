# `C_GetInterface` selection-evidence design

**Date:** 2026-09-02 (Europe/Helsinki)  
**Status:** proposed W3 design; implementation requires owner approval of this
document, including the schema and privacy wording below  
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

## 4. Coverage is per provider

Every provider in the final capture has exactly one selection coverage state:

- `observed`: at least one valid selection tuple was received;
- `absent_covered`: no tuple was received, and the observer proves it installed
  the hook before that provider could execute selection in this generation;
- `absent_uncovered`: no tuple was received and the proof above is unavailable.

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

## 5. Bounded aggregation

Profile output and terminal trace evidence aggregate identical tuples with a
count. Trace mode emits no per-call selection line. At most 16 distinct tuples
are retained across one capture. A seventeenth distinct tuple is not inserted;
`selection_truncated` becomes `true` and the verdict becomes `PARTIAL`.

A tuple consists of:

- provider ordinal;
- request name class, version class, and flags;
- `CK_RV`;
- result name class, version class, and flags when readable;
- `table_match`, `name_agrees`, and `version_agrees`; and
- authority class (`inventory`, `selection_count_only`, or `none`).

No tuple contains a PID, TID, address, pointer, raw name, arbitrary byte string,
or provider error text. Counters saturate rather than wrap.

## 6. Exact table matching

Name or version agreement never establishes a table match.

For live evidence, `table_match=true` only when the returned `pFunctionList`
address equals a `ScannedTable.address` that:

- came from the memory scan or a kind-2 `C_GetInterfaceList` record;
- belongs to the same `ProcessView` and retained process generation;
- resolves through the same fresh maps snapshot to the same module device and
  inode; and
- remains stable through selection reduction.

For offline evidence, `table_match=true` only when the returned
`pFunctionList` pointer equals one of the helper's own `C_GetInterfaceList`
entries from the same loaded provider instance. The manifest records the
matched inventory surface index, not either pointer.

`name_agrees` and `version_agrees` are separate booleans derived after an exact
table match. They expose a provider inconsistency but never widen a match.
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
  process generation and exact provider/object identities used by that view;
- the provider, maps snapshot, and pin remain stable through attach; and
- no selection read, state, transport, attribution, or truncation loss applies.

An unmatched offline result has the same name/layout requirements and is
eligible only under manifest-v5 attestation for the exact provider identity
and object closure already enforced by manifest pinning.

The resulting function identities may be probed and counted so real calls are
not missed, but `semantic_authorized` is always `false`, semantic argument
decoders are disabled, and the capture is `PARTIAL`. `null`, `other`, or
`unreadable` names; 2.40, `other`, null, or unreadable versions; unstable or
unmatched objects; and helper failures authorize nothing.

Selection-only targets appear only in selection evidence and the aggregate
function rows they count. They do not contribute to
`evidence.discovery[].tables`, `.interfaces`, `surfaces`, `interface_list`,
`vendor_interfaces`, aliases, or slot-level `fork_safe` conclusions.

## 8. Offline helper matrix

The helper resolves `C_GetInterface` inside the requested module and performs
queries before `C_Initialize` (which the helper continues not to call).

Acquisition has exactly three outer states:

- `export_absent`: zero calls;
- `export_outside_module`: zero calls and the export is refused; or
- `queried`: exactly ten calls.

The ten calls are the Cartesian product of these five selectors:

1. name `NULL`, version `NULL`;
2. name `"PKCS 11"`, version `NULL`;
3. name `"PKCS 11"`, version 3.0;
4. name `"PKCS 11"`, version 3.1;
5. name `"PKCS 11"`, version 3.2;

with flags `0` and `CKF_INTERFACE_FORK_SAFE` (`1`). No adaptive retry,
fallback, or vendor query is added.

Each call records its request and `CK_RV`. A nonzero `CK_RV` is a normal query
outcome. After `CKR_OK`, inability to read, classify, match, or safely walk the
returned structure is `helper_failure` on that outcome, not an acquisition
error and not an invented failure return. Returned pointers never enter the
manifest.

## 9. Versioned schemas

### 9.1 Offline manifest

The helper emits only `p11scope-manifest/5`. The top-level
`selection_evidence` object is a sibling of `surfaces`, `interface_list`, and
`vendor_interfaces`, with:

- `acquisition`: one of the three states in section 8;
- `queries`: exactly 0 or 10 bounded request/outcome records;
- `selection_truncated`: always `false` for the fixed matrix; and
- optional selection-scoped count-only function records under section 7.

Manifest v4 is rejected, not silently upgraded. It cannot represent whether
the matrix ran, so treating a missing field as an empty successful matrix would
fabricate evidence. The product is unreleased; operators regenerate the helper
artifact with the same exact provider. Structural validation requires the
exact schema id, exact query count per acquisition state, unique matrix keys,
finite enums, zero unknown flags in the helper matrix, bounded indices, and no
selection record in inventory fields.

### 9.2 Capture output

Profile output advances to `pkcs11-scope/observed-profile/v3` and metrics to
`pkcs11-scope/observed-profile/v3-metrics`. Profile and terminal trace evidence
add `evidence.interface_selection`:

```json
{
  "providers": [
    {"module": 0, "coverage": "observed"}
  ],
  "tuples": [],
  "selection_truncated": false
}
```

The real tuple shape is the finite contract in section 5. Metrics remains
aggregate-only, performs no selection argument reads, and its metrics schema
does not contain `interface_selection`. No v2 document is emitted after this
change; v2 remains documented as the previous local, unreleased contract.

## 10. Privacy allowlist v2 wording

`docs/privacy/allowlist-v1.md` remains unchanged as historical policy.
Implementation creates `allowlist-v2.md`, carries forward v1, and changes only
the following contract:

- **Function identity:** add a third source, an exact-standard
  selection-scoped live/offline table. Live authority is bound to one retained
  process generation and exact object identities; offline authority is bound
  to manifest-v5 attestation and exact provider identity. It is count-only,
  always `semantic_authorized=false`, never inventory, and forces `PARTIAL`.
- **Interface selection:** allow the four finite name classes, seven finite
  version classes, full-width request/result flags and `CK_RV`, three agreement
  booleans, three finite authority classes, per-provider coverage, bounded
  counts, and one truncation boolean. Exact target name bytes are compared in
  BPF and discarded; nonmatching bytes become `other`. No name bytes, pointer,
  address, PID/TID, or provider-controlled error string is output.

The existing prohibition that interface name bytes are not capture output
remains true. The allowlist revision authorizes finite classifications, not
names.

## 11. Error and verdict rules

The existing discovery loss counters remain the single owners for ring,
state, and bounded-read failures. Selection does not add shadow copies. A
selection record rejected for transport ABI increments malformed evidence;
one refused during bounded userspace reduction increments the existing
discovery truncation/loss owner exactly once.

Any of these forces `PARTIAL`: `absent_uncovered`, unmatched successful table,
selection-scoped authority, `selection_truncated`, helper failure, selection
read/state/ring/malformed loss, process-generation instability, or an outcome
whose provider cannot be attributed exactly. The renderer validates that every
loss that should affect completeness actually changes the consumer verdict.

## 12. Acceptance tests

Implementation proceeds TDD and must leave these runnable pins:

1. kind 4, including a custom interface hook, changes no discovery surface,
   interface count, alias group, table inventory, or `fork_safe` fact;
2. request/result name and version classes, flags, `CK_RV`, and nonzero failure
   outcomes round-trip through the transport validator;
3. unknown/unterminated/aliased name bytes yield only `other` or `unreadable`,
   and secret canaries do not appear in maps or output;
4. live exact matching requires address, view, generation, device, and inode;
   name/version agreement alone fails;
5. only exact-standard known-layout unmatched results gain count-only targets,
   with semantic decoding disabled and `PARTIAL`;
6. `observed`, `absent_covered`, and `absent_uncovered` are pinned at live call
   sites, including an actual `--pid`/unprotected refusal;
7. the seventeenth distinct tuple sets `selection_truncated` and `PARTIAL`;
8. recursive no-overwrite state failure is counted and forces `PARTIAL`;
9. absent/outside helper exports make zero calls; queried makes exactly ten;
   nonzero `CK_RV` stays an outcome and post-success unreadability becomes
   `helper_failure`;
10. offline pointer equality selects an inventory index; name/version equality
    without pointer equality does not;
11. manifest v5 accepts only the fixed matrix and v4 is rejected precisely;
12. profile v3 and terminal trace expose the bounded aggregate, metrics reads
    no arguments, and no trace line emits raw selection data; and
13. the canonical Rust 1.88 gates pass, followed by independent security and
    test-quality review to zero.

Privileged runtime, VM, and container lanes remain `UNRUN` unless separately
approved. Their absence is not represented as a pass.

