<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
**1. THE FIX — bracket acquisition, decoding, and publication**

**Recommendation:** add the maps-A/maps-B bracket to `scan_process_view`, reject unvalidated memory results, and record the refusal as discovery loss. This is the primary correctness fix.

This report is based on read-only source inspection. **Verified** means read in the current checkout; **proposed** identifies design decisions; **inferred** identifies consequences not demonstrated by a new run. Your measured defect is accepted. No repository files were modified, and no tests or live captures were run.

**Verified:** the reference implementation reads maps A, checks the complete table fits its containing mapping, collects every non-null function pointer, decodes, reads maps B, compares full `MapEntry` values, and checks the retained generation. See [engine.rs:8783](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8783). `MapEntry` equality covers start, end, file offset, all permission bytes, device, inode, and raw pathname—not merely object identity. See [maps.rs:42](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:42).

**Proposed acquisition shape:**

```text
read complete maps A through retained ProcessView
build charged index A
discover objects; read ELF and permitted target memory
decode into private pending module results + mapping dependencies

read complete maps B through the same ProcessView
build charged index B
validate dependencies and final generation

publish only validated results
publish explicit skips for rejected or unvalidated results
```

Keep results private until validation finishes. In particular, nothing rejected may reach pinning, reconciliation, attach planning, selection inventory, or cumulative capture history. History retains scan occurrences, so validating after publication would be too late. See [engine.rs:1459](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:1459).

The precise dependencies are:

| Dependency | Required validation |
|---|---|
| **Complete table span** | Use the selected target ABI and decoded prefix length. Check overflow and that `[table_address, table_end)` fits the original readable mapping. Require that entire `MapEntry` to remain identical in B. Checking only the version word without checking the span is insufficient. |
| **Every decoded non-null function pointer** | Require `index_b.containing(pointer) == index_a.containing(pointer)`, with a real mapping present. Preserve the decoder’s executable, file-backed, usable-path requirements. Include pointers into dependencies, not just the provider. |
| **Null function slots** | Validate the bytes containing the slot through the table-span check. Do not resolve address zero. Retain the existing canonical null-slot evidence. |
| **Scanned data mappings** | Validate every mapping whose snapshot was searched, including mappings that yielded no table. This catches the supplied large-span-to-split-VMAs transition and prevents an empty result from passing through an empty validation loop. |
| **Accepted interface descriptor** | Validate its complete ABI-sized descriptor span. Its table pointer must reference a retained, validated table. |
| **Interface-name reads** | Validate the mapping and bounded interval actually read, including read-ahead bytes. Preserve the existing same-object, readable-page and 64-byte restrictions. Null or deliberately unread names remain classified without additional dereferencing. |
| **Module inventory** | Validate the mappings used to establish the module’s mapped identity and ownership. A module base alone is insufficient; this path does not derive its authority from one base address. |

The existing [exact_table_addresses helper, scan.rs:615](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:615) already extracts the necessary non-null pointers. Extract them from the **same captured bytes that were decoded**. `ScannedEntry` retains file offsets, not raw pointers, so attempting to reconstruct the dependencies afterward would be the wrong design.

Use a private sidecar beside pending results for addresses, spans, and references to mappings in A. Do not add runtime addresses to public capture output. Full mapping equality plus a checked contained span avoids per-byte validation.

For a negative “no table found” result, also compare the provider’s searched data-mapping set between A and B. Newly added provider data mappings must not disappear behind an unchanged old mapping.

**Failure policy: recorded partial, without an internal retry loop.**

- A changed dependency rejects that module’s entire pending memory result: tables and interfaces together. This avoids dangling interface table indices and partially trusted tables.
- Independently validated modules remain usable. File/ELF inventory may remain only where its own mapping dependencies validated.
- Missing, malformed, truncated, overlapping, or budget-limited maps B cannot validate anything. Reject all pending memory results covered by that missing bracket.
- Incomplete maps A is not authority for a complete memory scan.
- A generation change after acquisition begins rejects the pending results and records the failed attempt.
- Do not relabel these failures as “no function table was found.”

Use distinct internal reasons, for example:

```text
memory scan refused: mapping changed during acquisition
memory scan refused: final mapping validation unavailable
```

The existing public representation can remain:

```json
{"name":"discovery subject","reason":"discovery unavailable"}
```

**Verified:** that representation belongs in `evidence.skipped` and forces `PARTIAL`; detailed reasons remain diagnostic. See [render.rs:554](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/render.rs:554).

The distinct internal reason matters: [engine.rs:3521](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:3521) currently suppresses “not mapped” and “no function table found” gaps after later attachment. A failed mapping bracket must survive that suppression, including when a manifest supplies all attach slots.

There is one necessary propagation change:

- Save scan skips in `scan_and_pin` **before** fallible pinning.
- Change `scan_retained_view` to return counters alongside its success/error result, so callers absorb losses even when pinning fails.
- Preserve these explicit acquisition losses through normal-exit handling.

**Verified:** skips are currently saved after pinning at [engine.rs:3275](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:3275), and pinning can fail on an exited generation even with no modules at [identity.rs:1364](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/identity.rs:1364).

All second-snapshot I/O, indexing, comparisons, and any subsequent attempt must consume the existing capture budget. Exhausting the allowance before B means refusal, not permission to publish A’s results.

**Limit:** this establishes the requested mapping-stability bracket. It does not establish an atomic memory snapshot, detect an identical unmap/remap between snapshots, or prove that application initialization has completed.

**2. THE RT_ADD QUESTION — a separate scheduling fix**

**Recommendation: both fixes, in separate patches.** Consult `r_state` to defer memory scanning during reported `RT_ADD`/`RT_DELETE`, while retaining the bracket as the authority for every scan.

An `r_state` filter cannot replace the bracket:

- Initial scans, `inspect`, and inventory refreshes do not depend on this loader-record branch.
- The event’s state describes hook time; userspace processes the record later.
- `RT_CONSISTENT` is not proof that PKCS#11 tables have been initialized.
- Unrelated mapping changes remain possible.

**Verified:** BPF stores `r_state` in `record.announced_count` at [main.rs:1452](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/ebpf/src/main.rs:1452). Userspace unconditionally calls `scan_retained_view` at [engine.rs:8038](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8038).

There is an important encoding limitation: BPF initializes `r_state` to zero and leaves it zero for absent state or a failed state read. Read failures increment a separate counter. Therefore **zero alone is not proof of a successful RT_CONSISTENT observation**. See [main.rs:1423](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/ebpf/src/main.rs:1423).

The smallest safe scheduling change can use the existing encoding:

| Record | Proposed action |
|---|---|
| `announced_count == 1` or `2` | Account and validate the event; mark memory discovery pending for that exact view/context. Defer the memory scan. |
| Zero | Treat it as another opportunity for a bracketed scan, not as initialization or timing proof. |
| Invalid context/state record | Preserve existing rejection and loss reporting. |
| Pending work without a subsequent completion opportunity | Make one fallback attempt on the next independent discovery tick, using fresh maps and the same budget. If it cannot complete, record unresolved discovery loss. |

Keep pending work bounded and keyed by **view plus loader context**, never PID alone. Coalesce duplicate requests. A fallback must not replay the original record and spend producer-counter authority twice.

Process every loader event and retain safely validated opportunities to arm standard export hooks. **Do not put an early return around the whole loader handler.** Those hooks may be the only way to observe tables handed out later.

On exit, context retirement, cancellation, budget exhaustion, or shutdown, settle pending work explicitly. Neither waiting forever nor forgetting the pending scan is acceptable. A paused target must be released through the existing pause policy; waiting for loader progress while retaining its stop would prevent completion.

No BPF record-layout change is required if zero is only a scheduling opportunity. If the implementation instead wants an authoritative “state successfully read as consistent” condition, it must add an explicit validity indication and update the private transport validator; the current encoding cannot support that claim.

**Verified specification interaction:** the existing [corrective design §7.1](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/docs/superpowers/specs/2026-08-18-slice1b2-corrective-live-discovery-design.md:538) explicitly requires every accepted hit to run the bounded memory scan. Deferring that operation is a deliberate amendment to that requirement. Preserve every-hit accounting and export discovery; change the memory-scan scheduling requirement explicitly.

**3. INTERACTION WITH NORMAL-EXIT SELECTION LOSS**

**The two correctness fixes are logically independent. Neither requires the other to be implemented first.** If landing serially, I recommend the scan bracket first, because it prevents unvalidated inventory from entering shared history.

**Verified:**

- Ordinary selection attribution requires a live matching view at [engine.rs:8406](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8406).
- The later inventory assessment independently requires liveness at [engine.rs:8503](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8503).
- An existing terminal-authority test already preserves a successful selection as an unmatched fact after view loss: [engine.rs:20005](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:20005).

The normal-exit fix should distinguish:

1. **Authority to retain the already captured selection fact.**
2. **Authority to inspect current memory, match live inventory, or attach new targets.**

For an otherwise attributable record whose retained original process has provably exited, preserve the bounded request/result tuple and count. When live assessment is unavailable, retain empty inventory matches, `SelectionAuthority::None`, and the explicit stable-assessment loss. Do not read `/proc/<pid>/mem` or create a selection-only attachment after exit.

Do not weaken `still_the_same()` globally or simply remove the attribution conjunct. Keep binding, context, attachment identity, retirement, and generation ownership checks. `original_exited()` alone is not proof that an arbitrary record belongs to that generation; reuse and delayed-record cases remain mandatory negatives.

**Verified separation from the supplied metrics lanes:** aggregate policy creates no selection bindings, as tested at [engine.rs:18202](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:18202). Fixing selection retention therefore cannot substitute for fixing the owned-metrics scan defect.

**4. BLAST RADIUS AND FROZEN EXPECTATIONS**

These are current-source locations, not future patch line numbers.

**Verified caller inventory:**

| Entry point | Every direct caller found |
|---|---|
| `scan_process_view` | [scan.rs:1393](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1393); [engine.rs:3264](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:3264); [inspect.rs:297](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/inspect.rs:297). |
| `scan_and_pin` | `engine.rs:3357` initial discovery; `6712` retained-view wrapper; tests at `25910`, `25913`. |
| `scan_retained_view` | `engine.rs:8038` loader event; `10950` retained inventory refresh; `11207` new-view admission. |
| `scan_pid` | `scan.rs:1787,1808`; [discovery_scan.rs:77](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/tests/discovery_scan.rs:77), also `646,676,726,735,783,816,846,895,997`; [manifest_pinning.rs:1814](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/tests/manifest_pinning.rs:1814). |
| `process_loader_record` | `engine.rs:10757`, through the ordinary/terminal discovery dispatcher. |
| Selection processing | `engine.rs:8335` test wrapper, `8344` session wrapper, `10751` dispatcher. The reference reader is also exposed through `EngineSession` at `1909/1983` and the scripted implementation at `12206`. |

**Proposed patch and regression sites:**

| File and location | Work |
|---|---|
| [scan.rs:1398](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1398) | Stage results, acquire B, validate, finalize or record refusal. Add dependency collection around table decoding at `632/772`, interface decoding at `905`, and name reads at `1032`. Reuse helpers at `606/615/1348/1379`. |
| [engine.rs:3257](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:3257) | Preserve losses before pinning; carry counters through retained-scan errors at `6705`; update all three callers above. |
| [engine.rs:7903](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:7903) | Separate loader accounting/export work from deferred memory scanning. Service pending work through discovery batches at `11719`; settle it in retirement/terminal handling at `10217/10389`. |
| [engine.rs:8357](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8357) | Separate normal-exit factual attribution from live assessment and attachment authority. |
| [inspect.rs:285](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/inspect.rs:285) | Verify refusal diagnostics survive its scan/pin path. No new public capture fields are required. |
| `scan.rs` tests at `1736,1773,1872,1976,2033,2074,2122,2186,2367,2603` | Extend bracket, ABI, budget, name-boundary, identity, and index-construction coverage. Update source assertions if helper extraction changes their markers. |
| `tests/discovery_scan.rs` tests at `105,144,232,280,451,481,529,580,705,756,832,886,990` | Preserve stable decoding and inventory behavior; revise budget calibrations to include final maps validation. |
| `engine.rs:25886` | Its scan/hash budget calculation currently budgets one maps snapshot per scan. Recalibrate it explicitly. |
| `engine.rs` tests at `20005,20400,20465,20537,16626,21627,21664,26176` | Extend terminal facts, mapping rejection, loader scheduling, exact-once ownership, and loss-publication tests. |
| [render.rs:2465](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/render.rs:2465), also `3918` | Add refusal cases to finite-output and independently-partial tests. Existing generic public reason can remain unchanged. |
| [check-capture-evidence.py:185](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/scripts/check-capture-evidence.py:185), also `205,1572,1582,1607,1724,1728,2357` | Separate synchronized scanned expectations from owned startup expectations; add dedicated refusal mutations. |
| [test_canary_evidence.py:69](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/tests/python/test_canary_evidence.py:69), also `2744` | Update the synthetic owned document and its exact acceptance/rejection assertions together. |
| [verify-canaries.sh:341](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/scripts/verify-canaries.sh:341) | Keep the owned production lane; add or distinguish the synchronized acquisition control needed to qualify exact scanned-table expectations. |

The stable mapping comparator, reference selection reader, and privacy allowlist need no behavioral change. BPF transport files need changes only if adding authoritative state-read validity; that larger alternative also touches [ebpf-common validation:643](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/ebpf-common/src/lib.rs:643) and the object checker at [check-live-discovery-object.py:841](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/scripts/check-live-discovery-object.py:841).

**What should the constants be?**

**Keep `988/104/208` as the acceptance target for the unchanged, fully covered manifest workload. Do not normalize the defect by changing it to `990/106/212`.**

For the existing **initialized, stable scanned control**, retain these expectations unless a new controlled measurement disproves them:

```python
VERSION_SHAPE_SCANNED = (
    988, 104, 208, VERSION_SURFACES_SCANNED, 1, "ok"
)

VERSION_TABLES_SCANNED = VERSION_TABLES_MANIFEST_ONLY + Counter({
    ("scan", (2, 40), 68): 2,
    ("scan", (3, 0), 92): 1,
})
```

The existing IA32 counterpart adds one 3.1/92 table and one 3.2/104 table: five scan tables.

**Verified:** the constants’ comments explicitly describe initialization before attach at [check-capture-evidence.py:166](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/scripts/check-capture-evidence.py:166). The owned lanes instead start the workload through `run --pause never`. Its tables are filled by provider calls: [version_matrix.c:114](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/tests/fixture/version_matrix.c:114). The workload calls that initialization after `dlopen` and before READY: [canary_workload.c:623](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/scripts/fixtures/canary_workload.c:623).

Consequently:

- **Deterministic invariant after the bracket:** no accepted scan contribution may depend on a mapping that changed across its acquisition.
- **Deterministic controlled result:** stable, initialized bytes and mappings produce the same decoded inventory.
- **Not established by either proposed fix alone:** one exact owned-lane scan-table count regardless of whether processing precedes or follows initialization.

I cannot honestly assign a new exact owned `VERSION_TABLES_*` value from source inspection. Zero must not become the expected answer merely because rejecting the race can produce zero. Nor should the checker accept `{0,3,6}` indiscriminately.

The owned lanes need their own qualified acquisition contract and synchronized measurement before freezing that count. Keep unresolved/refused acquisitions as explicit failing qualification cases. Dedicated mutation lanes may require their additional loss records; the normal canary’s current “exactly one skip” rule must not be broadly relaxed.

Also, **verified:** public `"scan"` table provenance includes lowered export records as well as memory scans—see [engine.rs:4848](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:4848). A public table count alone cannot identify which acquisition route produced it.

**5. MUTATION LANES — REQUIRED RED CASES**

These are proposed tests, not executed results.

| Lane | Mutation and required assertion | Placement |
|---|---|---|
| **Missing bracket — decisive RED** | Feed maps A containing one large readable file-backed data span; return plausible complete table bytes; supply maps B splitting that span while generation remains unchanged. Require zero accepted tables/interfaces from the affected module and an explicit refusal skip. Removing the production B-read/validation must make this test fail. | Production acquisition seam exercised from `scan.rs:1731`; companion integration case in `tests/discovery_scan.rs`. |
| **Function target remap** | Keep table memory unchanged; change a decoded pointer’s target mapping offset, inode, device, permissions, bounds, or path in B. Include a pointer into a dependency. Require rejection. This kills a table-address-only implementation. | `scan.rs` bracket tests. |
| **Span-end mutation** | Keep the table start mapped but split/truncate its containing mapping before the final slot. Exercise LP64 and ILP32. Require rejection even when all pointer values look valid. | Beside `scan.rs:1872` and `2367`. |
| **Empty-result mutation** | Return no decoded table, but change the provider data mapping set. Require mapping instability evidence; no vacuous “all addresses matched” success. | `scan.rs` orchestration tests. |
| **Interface dependency mutation** | Keep the table valid; remap the descriptor or bounded name-read mapping. Require rejection of the module’s pending memory result. Assert no additional name dereference or name output. | Beside `scan.rs:2074/2122`; retain `tests/discovery_scan.rs:280`. |
| **Unavailable B** | Inject open/read error, malformed maps, overlap, byte/entry ceiling, work exhaustion, deadline, and generation loss. Require no unvalidated publication and the actual refusal category. | Beside `scan.rs:2603`, plus engine propagation tests. |
| **Lost refusal evidence** | Produce a bracket refusal, then fail pinning through proven exit. Require the refusal in retained capture evidence. Add a valid manifest or later successful scan and verify the refusal is not erased by `scan_gap_this_capture_attached`. | `engine.rs`, beside `26176`; render coverage at `2465/3918`. |
| **RT_ADD deferral** | Dispatch an authenticated ADD record through the real batch route. Assert event accounting occurs, no memory scan occurs immediately, and bounded work is pending. A subsequent opportunity services it once. | Beside `engine.rs:20465`. |
| **Missing completion** | Supply ADD with no subsequent completion record. Advance a fake discovery tick; require one bounded fallback or explicit unresolved loss. Cover exit, retirement, budget exhaustion, and duplicate ADDs. | Engine batch/terminal tests near `20537/16626`. |
| **Zero is not proof** | Exercise absent state and read-failure zero. Require no relocation-ready, protected-window, or completeness claim based on zero. | Loader engine tests; transport tests if adding validity metadata. |
| **Normal-exit selection** | Queue an otherwise valid ordinary selection record, prove original exit before dispatch, retain the tuple/count with no live authority. Assert no table read or attachment. The current liveness conjunct must make this test RED. | Beside `engine.rs:20005`, using the ordinary batch route. |
| **Attribution negatives** | Wrong binding, wrong view/context, PID reuse, unknown exit status, retired unauthorized binding, and replay. Require rejection or exact-once handling; none may inherit normal-exit factual authority. | Existing selection/terminal attribution tests at `18633/21664`. |
| **Frozen-oracle mutations** | Remove the required refusal record; add rejected tables; change 988/104/208; collapse two distinct losses that sanitize identically. Require rejection. Also prove each unmutated fixture passes. | `check-capture-evidence.py:self_test` and `test_canary_evidence.py:2744`. |

Use an injected I/O seam in the **actual scan orchestration**, recording the sequence `maps A → memory/name reads → maps B → final generation → publication`. Testing only a standalone comparator would not prove that production calls it.

Include a positive control where only an unrelated VMA changes: validated provider results should survive. Include a stable initialized control for both ABIs. After implementation, run the repository’s prescribed fmt, check, test, and clippy commands; qualifying the frozen owned counts additionally requires controlled live evidence.


