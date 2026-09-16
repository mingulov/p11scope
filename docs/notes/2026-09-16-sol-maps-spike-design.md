**VERIFIED:** Read-only audit of `961a65c`. No repository files changed; no Cargo commands or Rust tests ran. `VERIFIED` below means source inspected or a check executed; `INFERRED` marks conclusions and proposed changes.

**1. Every caller**

**VERIFIED:** There are **21 calls to the free `maps::resolve` function** and **24 calls to `MapIndex::new`**, including tests. The discover crate re-exports the manifest implementation at [crates/discover/src/maps.rs:5](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/maps.rs:5).

Production calls to the free resolver:

| Caller — VERIFIED | Current handling of `Unmapped` — VERIFIED | Required distinction — INFERRED |
|---|---|---|
| `provenance_objects`, [crates/discover/src/discover.rs:181](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:181) | Wildcard returns “file-backed executable mapping … has no usable absolute path.” | Same refusal decision, but report invalid snapshot rather than a pathname finding. |
| `module_export`, [crates/discover/src/discover.rs:273](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:273) | Filter returns `false`, removing the export. This can become “resolved outside the requested module” at [discover.rs:552](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:552). | Invalid observation must not become export absence or an outside-module finding. |
| `loaded_module_key`, [crates/discover/src/discover.rs:294](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:294) | `if let File` does nothing; after all exports, returns the exact error at line 311. | Return a maps-validation error immediately. |
| `selection_resolve_values`, [crates/discover/src/discover.rs:1129](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1129) | Returns `SelectionFailure::UnresolvedFunction`. | Invalid snapshot must become an observation refusal, not a function classification. |
| `selection_table_for`, [crates/discover/src/discover.rs:1178](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1178) | `let File … else` returns `SelectionFailure::OutsideProvider`. | Invalid snapshot must not establish that the table lies outside the provider. |
| `resolve_values`, [crates/discover/src/discover.rs:1525](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1525) | Produces manifest `Resolution::Unmapped`. | Refuse acquisition before producing function records from invalid maps. |

**VERIFIED:** An important reachability qualification: the initial maps snapshot passes through `loaded_module_key` at [discover.rs:70](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:70), before `module_export` and ordinary table processing. An overlapping initial snapshot therefore aborts there. The table above describes each function’s local behavior; it does **not** establish that this particular overlap reaches a successfully published manifest containing `Resolution::Unmapped`.

Production constructor calls:

| Construction site — VERIFIED | Current failure handling — VERIFIED | Does it need different semantics? — INFERRED |
|---|---|---|
| Free resolver, [crates/manifest/src/maps.rs:262](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:262) | `None` becomes `Resolved::Unmapped`. | **Yes.** This erases the distinction. |
| `index_maps_or_refuse`, [src/discovery/scan.rs:1384](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1384) | Returns `"reversed or overlapping /proc/<pid>/maps intervals"`. | No decision change: already explicitly refuses. |
| `selection_mapping_bracket`, [src/discovery/engine.rs:694](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:694) | Invalid A returns `Err(())`, before resolution. | No: already distinguishes failed assessment from a valid negative. |
| Same bracket, [src/discovery/engine.rs:698](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:698) | Invalid B returns `Err(())`. | No: already refuses publication of the assessment. |
| `assess_target_readability`, [src/doctor.rs:726](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/doctor.rs:726) | Returns `"maps invalid"`; rendered as `Status::Fail` at [doctor.rs:809](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/doctor.rs:809). | No: the diagnostic already says the observation failed. |

**VERIFIED:** For completeness, the indexed lookup callers behave as follows. They cannot receive an index rejected for ordering or overlap, because construction precedes their calls.

| Indexed lookup sites — VERIFIED | Current `Unmapped` behavior — VERIFIED |
|---|---|
| [src/discovery/scan.rs:657](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:657) | Leaves the candidate’s optional table file offset as `None`. |
| [src/discovery/scan.rs:684](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:684) | Rejects the candidate with `Ok(None)`. |
| [src/discovery/scan.rs:718](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:718) | `unreachable!`: identical pointers were already validated against the same immutable index. |
| [src/discovery/scan.rs:1681](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1681) | Skips that entry while finding a group’s pathname evidence. |
| [src/discovery/engine.rs:696](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:696) | Returns the resolution only after the bracket succeeds. A valid absent mapping produces no inventory match at [engine.rs:8613](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8613); bracket failure sets assessment loss at [engine.rs:8655](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8655). |
| [src/discovery/engine.rs:4795](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:4795), [engine.rs:4840](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:4840) | Rejects export lowering with `Ok(None)`; the caller records live loss at [engine.rs:7910](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:7910). |
| `usable_path`, [src/discovery/engine.rs:4955](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:4955) | Returns `None`. Its snapshot consumers explicitly refuse when no usable mapping remains at [engine.rs:5160](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:5160) and [engine.rs:5183](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:5183). |
| [src/doctor.rs:744](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/doctor.rs:744) | Returns `"executable identity unavailable"`. |
| Wrapper [crates/manifest/src/maps.rs:262](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:262); test [maps.rs:425](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:425) | Wrapper forwards the indexed answer; test asserts a genuine gap is `Unmapped`. |

**INFERRED:** These indexed consumers legitimately do not need a malformed-snapshot variant at every lookup, provided construction remains an explicit failure boundary. They still need their existing refusal/loss propagation.

Test calls to the free resolver:

| Sites — VERIFIED | Current negative behavior — VERIFIED | Needed treatment — INFERRED |
|---|---|---|
| `resolves_with_segment_offset_arithmetic`, [crates/manifest/src/maps.rs:309, :320](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:309) | Equality assertions fail. | Explicitly require successful resolution. |
| `classifies_anonymous_and_unmapped`, [crates/manifest/src/maps.rs:335, :336, :337, :338](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:335) | First two assertions reject `Unmapped`; last two expect it. | Last two must expect a **successful** absent lookup, distinct from error. |
| `unusable_file_paths_remain_file_evidence`, [crates/manifest/src/maps.rs:357](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:357) | Panics in `let … else`. | Explicit successful snapshot resolution before pathname assertions. |
| Helper `timing_key`, [src/discovery/engine.rs:12820](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:12820) | Skips mapping; eventually fails “three executable objects” assertion. | Fail setup with the maps error. |
| Helper `loaded_seed_provider`, [src/discovery/engine.rs:17186](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:17186) | No match; retries within 200 polls, then `expect` fails. | May explicitly retry invalid acquisition under that same poll budget; do not classify it as absence. |
| `two_view_selection_claims_retire_independently`, [src/discovery/engine.rs:18159](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:18159) | Same 200-poll behavior. | Same explicit acquisition-error treatment. |
| `c_get_interface_selection_exact_match_keeps_inventory_aliases`, [src/discovery/engine.rs:19901](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:19901) | `unreachable!`. | Report setup error directly. |
| Helper `child_provider_modules`, [src/discovery/engine.rs:21344](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:21344) | Skips entries; retries 200 times, then panics. | Explicitly distinguish invalid acquisition within the existing polling policy. |
| `exact_loader_pin_is_view_owned_but_not_a_provider_module`, [src/discovery/engine.rs:23539](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:23539) | Skips entry; final dependency `expect` fails. | Fail setup with the maps error. |
| Helper `self_export_fixture`, [src/discovery/engine.rs:24523](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:24523) | Predicate is false; data-mapping `expect` fails. | Fail setup with the maps error. |
| `engine_lowers_export_table_owner_and_prefix`, [src/discovery/engine.rs:24718](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:24718) | Same data-mapping failure. | Same treatment. |

Remaining constructor calls, all in tests:

| Sites — VERIFIED | Current construction-failure behavior — VERIFIED |
|---|---|
| [crates/manifest/src/maps.rs:381, :395](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:381) | Explicitly asserts `None` for unsorted and overlapping input. |
| [crates/manifest/src/maps.rs:417](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:417) | `unwrap`; invalid fixture panics. |
| [src/discovery/scan.rs:2712](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2712), [scan.rs:2754](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2754), [scan.rs:2783](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2783), [scan.rs:2816](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2816), [scan.rs:2873](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2873) | Each uses `unwrap`; invalid fixture panics. |
| [src/discovery/scan.rs:2918](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2918), [scan.rs:2962](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2962), [scan.rs:3138](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:3138), [scan.rs:3233](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:3233), [scan.rs:3265](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:3265) | Each uses `unwrap`; invalid fixture panics. |
| [src/discovery/engine.rs:23284](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:23284), [engine.rs:23457](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:23457), [engine.rs:23488, :23498](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:23488) | Each uses `unwrap`; invalid fixture panics. |
| [src/discovery/engine.rs:24566](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:24566), [engine.rs:24752](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:24752) | Each explicitly expects a kernel-ordered snapshot. |

**INFERRED:** These positive constructor tests can retain `unwrap`/`expect`: they already fail on unreadable setup. The two rejection assertions must change from `is_none()` to the appropriate error assertions. Construction itself does not return `Unmapped`.

**2. Shape of the fix**

**INFERRED — recommendation:** Use a **fallible raw-snapshot API**, with an explicitly validated index for repeated lookups:

```rust
MapIndex::new(&[MapEntry])
    -> Result<MapIndex<'_>, InvalidMapSnapshot>;

maps::resolve(&[MapEntry], u64)
    -> Result<Resolved, InvalidMapSnapshot>;

MapIndex::resolve(&self, u64)
    -> Resolved;
```

**INFERRED:** Reserve `Ok(Resolved::Unmapped)` for absence in an accepted snapshot. Constructor errors should distinguish invalid ranges, ordering/overlap, and any other condition preventing reliable indexed resolution.

**VERIFIED:** Adding only `Resolved::Indeterminate` would leave the wildcard branches at [discover.rs:195](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:195) and [discover.rs:275](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:275), the `if let` at [discover.rs:289](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:289), and the `let … else` at [discover.rs:1173](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1173) selecting their existing negative branches.

**INFERRED:** Changing the free function’s return type forces **all 21 existing free-function calls in this inventory** to change: their enum patterns or equality expectations no longer match the return type. Changing only the constructor’s return type would be insufficient if the wrapper still supplied `Unmapped` on failure.

**INFERRED:** Migrate the offline helper by constructing indexes at acquisition boundaries and passing `&MapIndex` through its internal resolution functions:

- Validate before using the pre-load snapshot’s keys, the post-acquisition snapshot, and the final provenance snapshot: current boundaries are [discover.rs:50](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:50), [discover.rs:69](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:69), and [discover.rs:138](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:138).
- Let acquisition failure propagate through the existing top-level `Result<Manifest, String>`. This avoids adding a manifest resolution variant merely to publish records from an invalid snapshot.
- Validate **both** offline selection snapshots inside `selection_bracket`, before accepting its result. Pass a validated index to the resolution callback. Never substitute an empty slice for failed acquisition.
- Use the existing selection-bracket refusal category, `ProviderChanged`, for failed maps validation, consistent with its current treatment of maps acquisition failure at [discover.rs:815](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:815). This reports failed assessment instead of `OutsideProvider` or `UnresolvedFunction`.

**VERIFIED:** There is one additional condition relevant to the promised API contract: offset overflow currently also returns `Unmapped` at [crates/manifest/src/maps.rs:244](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:244).

**INFERRED:** To keep indexed resolution infallible and make `Unmapped` mean absence, validate representability of each absolute-file mapping’s last-byte offset during construction:

```text
file_offset + (end - start - 1)
```

Then remove the overflow-to-`Unmapped` fallback. This is an explicit adjacent contract correction, **not evidence about the recorded failure**.

**INFERRED — acceptance gate:** Reject migrations using `.unwrap_or(Resolved::Unmapped)`, `.ok()` followed by absence handling, or `if let Ok(File …)` with an unreported error fallthrough. Types force existing callers to change; they cannot prevent a developer deliberately recreating the collapse. Validate once per accepted snapshot, preserving the live path’s charged index reuse.

**3. Is the rejection predicate right?**

**VERIFIED:** `parse_maps` preserves line order and performs no sorting or cross-entry overlap validation at [crates/manifest/src/maps.rs:55](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:55). It rejects an individually empty/inverted range at [maps.rs:103](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:103).

**VERIFIED:** The production construction paths therefore do **not** independently guarantee sorted input:

| Source path — VERIFIED | Ordering treatment — VERIFIED |
|---|---|
| Offline helper’s pre-load, acquisition, final, and selection reads: [discover.rs:50](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:50), [discover.rs:69](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:69), [discover.rs:138](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:138), [discover.rs:1213](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1213) | Parse bytes in received order. |
| Passive scan acquisition, [src/discovery/scan.rs:1578](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1578) | Parses received order; subsequent index construction rejects invalid order. |
| Live engine reader, [src/discovery/scan.rs:1372](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1372), used at [engine.rs:6575](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:6575) | Same. |
| Doctor, [src/doctor.rs:725](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/doctor.rs:725) | Same. |
| Public constructor and injected bracket callbacks, [maps.rs:190](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:190), [engine.rs:689](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:689) | Accept arbitrary slices/vectors; validation is essential. |

**VERIFIED:** The positive scan constructor fixtures are single intervals or explicitly ordered adjacent intervals; the engine synthetic constructor fixtures are explicitly ordered vectors/generated sequences. The manifest fixture itself is unsorted at [maps.rs:269](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:269), and resolver tests deliberately call `sorted_fixture` at [maps.rs:371](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:371). Its rejection test deliberately swaps entries at [maps.rs:380](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:380).

**INFERRED — mathematical conclusion:** The predicate does **not** rely on an unchecked sorting assumption. With each interval satisfying `start < end`, acceptance requires:

```text
start[i] < end[i] <= start[i + 1]
```

That proves increasing starts and non-overlap. An adjacent descending pair necessarily fails. The predicate is right for validating ordered, disjoint, half-open intervals; an unsorted input is rejected, not incorrectly binary-searched.

**VERIFIED:** A read-only Python enumeration checked this equivalence for all **16,276** sequences of length zero through three over endpoints zero through four. It passed. This checked the predicate algebra, not Rust execution.

**INFERRED:** Reject the **whole snapshot** for a bad pair. Sorting, dropping conflicting entries, or resolving only an unaffected-looking region cannot establish which mappings were missed or stale. Passing this structural check also does not prove a snapshot was temporally coherent.

**INFERRED — retry decision:** The correctness patch should retain **one acquisition attempt and explicit refusal**, with no hidden resolver retry. A resolver owns borrowed data, not the process view, memory-read sequence, or budget.

**INFERRED:** If availability retries are subsequently authorized, the acquisition owner must own them:

- Offline discovery: the maps-acquisition operation owns a bounded reread before dependent observations begin.
- Scan/selection: the transaction owns any restarted observation; retrying only B must not validate memory decoded against a rejected A.
- A concrete policy could allow **two total attempts**, charging both to the same byte/work/deadline allowances and retaining a failed-bracket occurrence. Do not reset budgets or replay provider acquisition calls automatically.

**4. Interaction with P-2**

**VERIFIED:** The passive scan already protects against this specific malformed-snapshot collapse:

- A is acquired and indexed before scanning at [src/discovery/scan.rs:1623](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1623). Failure returns an explicit initial-validation refusal.
- B is acquired and indexed at [scan.rs:1918](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1918).
- Dependencies are checked against B, including searched data for empty-table results at [scan.rs:1498](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1498).
- Failed closing validation records an explicit reason and clears pending modules at [scan.rs:1951](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:1951).

**VERIFIED:** `read_selection_table` now starts at [src/discovery/engine.rs:8870](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8870). It indexes A, bounds the complete table span, decodes against A, indexes B, compares the table/function mappings, and checks generation before returning at [engine.rs:8925](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8925). Errors become assessment loss at [engine.rs:8734](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8734).

**INFERRED:** The proposed API fix **composes with P-2**. Structural validation answers whether one snapshot is usable; the bracket checks whether dependencies remain unchanged across the observation. Neither replaces the other. The scan path is already safe from **invalid index construction being interpreted as `Unmapped`**.

**VERIFIED:** The exposed production callers are the offline helper’s six free-resolver sites. Its selection bracket is different from the live bracket:

- `stable_selection_maps` parses but does not construct an index at [discover.rs:1213](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1213).
- `selection_maps_unchanged` compares only absolute-file mappings at [discover.rs:789](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:789).
- `selection_bracket` does not validate interval structure at [discover.rs:812](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:812).

**INFERRED:** Therefore, unchanged file mappings plus an anonymous overlap in A can pass the offline bracket’s comparison while making resolution return `Unmapped`. That can preserve `OutsideProvider` or `UnresolvedFunction` as the result. An invalid B containing only additional anonymous conflicts can likewise escape that comparison. Both snapshots need structural validation before acceptance.

**VERIFIED:** There is already duplicated construction in the live inventory-assessment path: its callback invokes `index_maps_or_refuse` at [engine.rs:8607](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:8607), and `selection_mapping_bracket` constructs again at lines 694/698.

**INFERRED:** That existing duplication is not this defect. Preserve error propagation and avoid expanding this patch into a separate budget/performance refactor.

**5. Blast radius and mutation lanes**

**INFERRED:** The following are proposed edits and RED cases, not tests executed during this audit. New tests have no existing line numbers; the cited locations identify their production seams or neighboring tests.

| Owned lane | Existing tests/helpers requiring edits; proposed RED coverage |
|---|---|
| **Manifest API:** `crates/manifest/src/maps.rs` | Adapt `resolves_with_segment_offset_arithmetic` at [maps.rs:306](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:306), `classifies_anonymous_and_unmapped` at [maps.rs:333](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:333), and `unusable_file_paths_remain_file_evidence` at [maps.rs:342](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:342). Extend `map_index_requires_sorted_non_overlapping_intervals` at [maps.rs:378](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:378). Add error-versus-absence cases beside the gap tests at [maps.rs:399](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:399). |
| **Offline acquisition:** `crates/discover/src/discover.rs` and its `maps.rs` re-export | Add deterministic caller regressions through `loaded_module_key` at [discover.rs:279](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:279), and the acquisition seam that validates before it. Extend bracket tests at [discover.rs:1776](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1776), [discover.rs:1793](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1793), and [discover.rs:1821](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1821). Add selection refusal tests covering both `selection_table_for` and `selection_resolve_values`. |
| **Passive scan:** `src/discovery/scan.rs` | Adapt the constructor error translation at line 1384. Extend `p2_bracket_incomplete_a_never_scans` at [scan.rs:2401](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2401) with invalid intervals, and `p2_bracket_unavailable_b` at [scan.rs:2352](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2352) with explicit unsorted/inverted cases. Its overlap case already exists. |
| **Live engine and test setup:** `src/discovery/engine.rs` | Adapt the eight free-resolver test/helper sites inventoried in §1: helpers at lines **12807, 17097, 21331, 24508**; tests at **18108, 19891, 23525, 24701**. Adapt constructor error translation at 694/698. Extend `selection_assessment_rejects_remap_view_loss_and_pin_change` at [engine.rs:20559](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:20559) to distinguish valid absence from invalid A/B. |
| **Doctor:** `src/doctor.rs` | Mechanical `Option`-to-`Result` error translation at line 726. Existing behavior remains `"maps invalid"`; no new doctor test is required for that unchanged decision. |

**VERIFIED:** The existing offline “synthetic remap” fixture sets `start = 0x3000` but leaves `end = 0x2000` at [discover.rs:1786](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:1786).

**INFERRED:** Update its end as well, so it continues testing two individually valid but changed snapshots. Otherwise new structural validation would make it pass for the wrong reason.

**INFERRED — mandatory RED cases:**

1. **Core distinction:** A valid gap returns `Ok(Unmapped)`; an overlapping snapshot returns `Err`, both for an address inside an otherwise valid mapping and for an address outside every listed interval. Include an unrelated anonymous overlapping pair so the test proves whole-snapshot refusal.
2. **Ordering/range controls:** Descending disjoint entries, equal starts, empty/inverted ranges fail. Valid adjacency, gaps, exclusive ends, anonymous mappings, and unusable file paths retain their meanings.
3. **Arithmetic contract:** File-offset overflow is an error, never `Unmapped`; the greatest representable valid offset succeeds.
4. **Exact caller diagnostic:** Supply known acquisition export addresses and invalid maps. The acquisition must report maps validation failure, **not** the line-311 message. A valid snapshot missing those addresses must still produce the existing no-matching-export error. Include a valid matching-provider control.
5. **No bypass through empty work:** Invalid acquisition must fail even if exports are absent or all table pointers are null. Validation cannot depend on the first non-null lookup.
6. **Offline bracket:** Invalid A, invalid B, and identical invalid A/B must refuse. Include unchanged file entries with anonymous overlap. Neither `OutsideProvider` nor `UnresolvedFunction` may represent this failure. Valid absence retains those existing classifications where appropriate.
7. **P-2 composition:** Invalid A prevents memory scanning; invalid B removes pending results and retains the explicit validation-refusal occurrence. Stable input and valid unrelated VMA churn still succeed.
8. **Live distinction:** A valid bracket with the address absent yields successful absence; an invalid snapshot yields failed assessment. Verify the downstream assessment-loss branch, not merely an empty inventory-match vector.

**INFERRED — mutation checks:** The RED tests must fail if someone restores error-to-`Unmapped`, discards errors with `.ok()`, sorts/drops invalid entries, or removes validation of either offline bracket snapshot. Positive controls must fail if the implementation simply refuses everything.

**VERIFIED:** Relevant existing preservation gates are:

- Indexed genuine-absence candidate rejection: [src/discovery/scan.rs:3132](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:3132).
- Stable/unrelated-churn P-2 controls for both widths: [scan.rs:2534](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2534).
- One-index source contract: [scan.rs:2574](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/scan.rs:2574).
- Charged index reuse: [src/discovery/engine.rs:23400](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/src/discovery/engine.rs:23400).

**INFERRED:** These gates and the remaining positive constructor tests listed in §1 need verification, not automatic source edits. Keep `version_matrix` unchanged and rerun [crates/discover/tests/version_matrix.rs:40](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/tests/version_matrix.rs:40) as a regression check; it should not become the nondeterministic RED oracle.

**INFERRED:** Land the shared API first, then integrate the disjoint file lanes. Preserve the privacy allowlist and existing schemas. The controller retains ownership of serialized workspace-wide gates.

**6. Verdict on the `version_matrix` failure**

**INFERRED — YES, this path can produce that exact error string.**

**VERIFIED:** The source chain is:

```text
version_matrix.rs:63
  discover(&provider).unwrap()

discover.rs:67–70
  read /proc/self/maps
  parse_maps
  loaded_module_key(...)

discover.rs:285–294
  resolve each available acquisition export

maps.rs:262
  rejected index -> Unmapped

discover.rs:289–311
  no File branch succeeds
  -> "no module acquisition export maps to the requested file identity"
```

Sources: [version_matrix.rs:63](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/tests/version_matrix.rs:63), [discover.rs:67](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:67), [discover.rs:285](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:285), [maps.rs:262](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/manifest/src/maps.rs:262).

**INFERRED — attribution remains CANNOT DETERMINE.** No failing snapshot or trace from the recorded occurrence was available in this audit.

**VERIFIED:** The fixture performs the cited mapping operations, but its `fill()` runs inside acquisition at [version_matrix.c:130](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/tests/fixture/version_matrix.c:130), and those acquisition calls precede the relevant maps read at [discover.rs:63](/home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/w7-ia32/crates/discover/src/discover.rs:63).

**INFERRED:** Those same-thread initialization operations alone therefore do not prove churn overlapped this read. The connection is possible and explicit in the control flow, but the observed failure’s cause remains unproven. **The fix is warranted independently: invalid observation must remain distinguishable from observed absence.**
