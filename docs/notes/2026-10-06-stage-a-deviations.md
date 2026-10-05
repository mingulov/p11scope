<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Stage A deviations from `task3-mechanism-decision.md`

Recorded 2026-10-06 by Task 1b-fix (branch `v030-stage-a`, base `e421f9a`).
Each entry: what the spec (§, v2026-10-02) says, what the lane implements,
and why. Nothing here weakens the join rule (§1): every deviation keeps or
strengthens fail-closed routing, and each is pinned by the cited gate.

## D1. `copy_vma` coverage is a fexit hook, not fentry

- Spec §1.3 lists a fentry hook on `copy_vma` alongside `uprobe_mmap` /
  `uprobe_munmap`.
- Implemented: `p11_inst_vma_copy` attaches at
  `fexit/copy_vma` (`crates/ebpf/native/instance_epoch.c:384`,
  `src/attach/instance.rs:47-51`). Rationale: the fentry context cannot see
  the new VMA (it does not exist yet at function entry); the fexit context
  carries the new VMA pointer, which is what the hook localizes.
- Pinned by: `privileged_instance_routing_separates_reload_sibling_and_mutation`
  (copy hook run count ≥ 1 on `mremap`) and
  `privileged_instance_mremap_dontunmap_keeps_both_and_renews` (exactly 1 on a
  pure `MREMAP_DONTUNMAP`).

## D2. `inst_stamp` is inlined at the entry probe

- Spec §1.2 describes stamping as a helper the entry path calls.
- Implemented: stamping is inlined into `p11_instance_entry` (called from the
  uprobe entry path in `crates/ebpf/src/main.rs` before `store_start`); there
  is no separate `inst_stamp` program. Same inputs, same 16-byte stamp ABI
  (`crates/ebpf-common/src/lib.rs:1378`, `native/instance_epoch.h`).
- Pinned by: every routing gate (stamps must match scans or calls stay
  unknown), and the host harness (`tests/fixtures/instance-epoch/helper_tests.c`).

## D3. The entry half lives in LRU `INSTANCE_START`, handed to the `EventRecord` tail

- Spec §1.2 records the entry half in `START` and §1.5 hands the stamp pair
  through the event.
- Implemented: the entry half is recorded in a dedicated LRU map
  `INSTANCE_START` (`INST_START_ENTRIES`, `native/instance_epoch.h`), and the
  return half is consumed into the private `continuity` tail of the
  `EventRecord` (`crates/ebpf-common/src/lib.rs:1404`) in place. Rationale:
  `START` rows are owned-start lifecycle state (abandon paths, small-state
  capacity 1); a dedicated LRU gives the entry half independent eviction
  semantics (eviction → `NO_TASK` → `Unstamped`, never a join).
- Pinned by: the BEGIN-loss host-harness case, the checked arithmetic at the
  router, and live by
  `privileged_instance_small_state_lru_eviction_never_joins` (48,043
  `Unstamped` / 3,207 joins at `LRU=1`, zero false joins).

## D4. `WATCHED_FILES` keys come from kernel-observed calibration, not `stat`

- Spec §1.4 derives file keys from `stat` (`st_dev`/`st_ino`) with a
  self-check.
- Implemented: `InstanceTracking::watch` calibrates each object
  (`src/attach/instance.rs:329`): it maps one page in the observer, asserts
  the hooks record exactly that mapping, and takes the kernel-observed
  `(s_dev, i_ino)` as the key. Rationale: `stat` and the kernel's
  `s_dev`/`i_ino` disagree on stacked filesystems (btrfs/overlay anon dev);
  the kernel-observed key cannot disagree with the hook path by
  construction. Colliding `/proc/<pid>/maps` keys are still disambiguated
  by `map_files` identity at scan time.
- Pinned by: `stable_scan_requires_calibrated_keys_and_rejects_path_aliases`,
  `colliding_maps_keys_are_confirmed_by_map_files_identity`, and live by
  `privileged_instance_routing_on_btrfs_tmpdir`.

## D5. Extra maps beyond the spec's table

- Spec §1 names the epoch, watched-file, and start maps.
- Implemented additions: `INSTANCE_GEN` (fault/sticky/attach cells,
  `crates/ebpf-common/src/lib.rs:1351`), per-hook BPF stats consumed via
  `instance_hook_stats` (recursion-miss audit input), and the
  small-state-shrunk `INSTANCE_START` (§D3). All are witness-private:
  allowlist-v3 carries them, allowlist-v1 is byte-identical.
- Pinned by: the artifact contracts (map defs) and the miss-latch unit pins
  (`a_recursion_miss_increase_without_a_raise_latches_the_era`).

## D6 (review N1). Coverage-fault latch is per-(process, file), not a global generation

- Spec §1.7 raises a global fault generation on a coverage fault (a range
  appearing at unchanged epochs).
- Implemented: the latch is per `(cookie, file)` key (`faulted` in
  `src/discovery/instances.rs`): the faulted key refuses every later call
  with `CoverageFault`, while other keys keep routing. The global fault
  generation still exists and still ends every incarnation on hook-program
  misses and sticky conditions — the two refusal axes are orthogonal.
- No-false-join argument: a coverage fault on key K1 says "K1's ranges
  changed without K1's epochs moving" (a per-file hook gap). K2's cells and
  ranges are independent state: a skipped hook invocation for F1 cannot move
  or stale K2's epochs (a *detected* skip raises the global fault anyway).
  So refusing exactly K1 preserves every sound K2 join and refuses every
  unsound K1 join — strictly more availability than §1.7 with the same
  join soundness. (F3 bounds the `faulted` set; an evicted fault degrades
  its key to `Pending`/`Unobserved`, never a join.)
- Pinned by: `a_range_appearing_at_unchanged_epochs_is_a_sticky_coverage_fault`
  and `faulted_registry_eviction_degrades_late_calls_to_unobserved`.
