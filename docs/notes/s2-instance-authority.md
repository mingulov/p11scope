<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# S2 carry: module load-instance authority (from S1/F7b)

Carried from S1 fix round 2 (finding F7b, path (3): documented
boundary with proof). The S1 boundary pin is
`s1_tests::d2_same_file_double_load_merges_boundary_for_s2` — S2
MUST replace it with a separation regression; the pin fails the
moment instance authority exists, by design.

## The boundary

Module identity below S2 is file identity: `(device, inode,
SHA-256)` (`ModuleKey::Physical`). A same-file double-load — two
loader mappings of one file in one process — carries one key and
merges into one module and one edge per caller, joining the
instances' numeric session handles in one reducer namespace with no
marking gap. For `dlopen` in one namespace the merge is CORRECT
(same file → same loaded object → one PKCS#11 session namespace).
The blind case is a `dlmopen` private-namespace double-load:
distinct loaded objects with distinct session namespaces and an
identical file, invisible at every layer S1 can see:

- scan (`discovery/scan.rs::candidate_groups`): mappings group by
  `(device, inode)`; one `ScannedModule` per group. `MapEntry`
  addresses never survive `ObjectKey::of`.
- identity (`discovery/identity.rs::insert_entry_with_aliases`):
  same-file observations pin to one object on equal identity.
- observation (`attach.rs::slot_attach_point`): uprobes attach by
  `(path, absolute file offset)` — one probe fires for every
  same-file mapping. `Event` (`crates/ebpf-common`) carries no
  mapping discriminator (`ImageIdentity` is task-level).
- feed (`SemanticCall`, `observe_semantic`): no instance field;
  routing is by `(caller, ModuleKey)`.
- registry (`apply_mapping`): same-key notes merge into one
  module/edge; a second same-key note is indistinguishable from a
  re-scan of the first.

R0 doctrine binds the framing: a pathname/hash alone cannot prove a
semantic module instance. S1's standing constraints (no new capture
field, no BPF/decoder change, no allowlist edit) forbid building the
missing evidence inside S1 — hence this carry.

## What S2 must build

1. **Scan instance detection.** Distinguish one load's segments from
   two loads of one file: within a `(caller, key)` candidate group,
   duplicate executable file-offset coverage (two `r-x` mappings of
   the same file range) evidences two loads. Mint a per-`(caller,
   key)` instance id at detection time and plumb it through
   `ScannedModule` → engine/catalog → `ModuleInfo` → registry.
   Generation-local runtime addresses must never persist as
   identity (see `ScannedTable::file_offset` docs); match instances
   across passes by mapping-set continuity within a live process
   view, and say explicitly what happens on remap (re-detection with
   a named gap beats silent re-keying).
2. **Registry instance dimension.** `ModuleKey` stays file identity;
   the edge keying gains the instance (`(caller, key, instance)`),
   so same-key distinct-instance notes create sibling modules/edges
   instead of merging. Re-scans stay idempotent per instance.
   `dlopen`-same-namespace double-loads MUST still merge (same
   object — the loader returns the same handle); the detector from
   (1) is what tells the cases apart, never a pathname.
3. **Per-call instance attribution.** The BPF `Event` needs an
   entry-IP (or equivalent mapping discriminator) — a NEW capture
   field requiring an allowlist amendment and privacy review — plus
   a userspace mapping join (entry IP → live instance via the
   process maps snapshot). `SemanticCall` gains the routed instance
   and `observe_semantic` routes by `(caller, key, instance)`.
   Calls unattributable to an instance (missed maps, raced remap)
   orphan with a NAMED gap — never join a guessed instance.
4. **Per-instance session namespaces.** Reducer state (S1's
   per-edge maps, S2's session/object registries) keys by
   `(instance, session handle)`; overlapping numeric handles on two
   instances of one file never join. Cross-instance async
   completion orphans, mirroring the cross-session rule.
5. **Schema evolution (additive, v1-compatible).** Instance ids on
   the affected `modules[]`/`edges[]` records plus the named
   unattributable-instance gap; single-instance files render
   exactly as today (no new required fields for the common case).

## Acceptance

- The S1 boundary pin is REPLACED by a same-file double-load
  regression with overlapping session handles asserting separation:
  two modules/edges, each edge holding exactly its own instance's
  mechanism rows and operations, zero cross-instance orphans.
- A companion regression pins the unattributable path: calls the
  mapping join cannot attribute orphan with the named gap.
- Entry-IP capture ships behind the allowlist amendment with the
  privacy canaries re-run green.

## Open questions for S2

- Instance continuity across passes: mapping-set continuity vs
  loader-event tracking (the `dl_debug_state` hook exists for
  dynamic attach — can it witness load/unload generations?).
- Join cost: per-call maps lookup vs cached range tables, and the
  staleness window each implies for the unattributable gap rate.
- Whether the detector (1) should also fire on non-executable
  duplicate coverage (data-only double mappings carry no call
  surface but still split session namespaces at the loader level).
