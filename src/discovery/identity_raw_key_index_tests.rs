//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>

//! The per-object raw-key query (`raw_keys_for`, `object_matches_key`)
//! against the linear scan it replaces. The scan stays here as the
//! oracle; every twin warms the query first, mutates, then queries again,
//! so a stale cached answer fails the comparison.

use super::test_fixture::{PATH, SHA, manifest_pin, overlay, pin_set, record_scan_ownership};
use super::*;

/// The linear scan the query must equal: every raw filed under `id` plus
/// the entry's own raw, sorted and deduplicated.
fn scan_raw_keys(pins: &PinnedObjects, id: PinnedObjectId) -> Vec<ObjectKey> {
    let mut keys: Vec<ObjectKey> = pins
        .raw_to_id
        .iter()
        .filter(|(_, owner)| **owner == id)
        .map(|(raw, _)| raw.key)
        .collect();
    if let Some(entry) = pins.by_id.get(&id) {
        keys.push(entry.raw.key);
    }
    keys.sort();
    keys.dedup();
    keys
}

fn scan_matches(pins: &PinnedObjects, id: PinnedObjectId, key: ObjectKey) -> bool {
    let hit = |candidate: &ObjectKey| {
        candidate.device.major == key.device.major
            && candidate.device.minor == key.device.minor
            && candidate.inode == key.inode
    };
    scan_raw_keys(pins, id).iter().any(hit)
        || pins
            .by_id
            .get(&id)
            .is_some_and(|entry| entry.probed_maps_key.as_ref().is_some_and(hit))
}

/// Every id the set has ever minted (retired ones included: a stale
/// answer for a retired object is the failure this guards), every id it
/// currently files, and ids it has never minted.
fn query_ids(pins: &PinnedObjects) -> BTreeSet<PinnedObjectId> {
    (0..pins.next_id.saturating_add(3))
        .map(PinnedObjectId)
        .chain(pins.by_id.keys().copied())
        .chain(pins.raw_to_id.values().copied())
        .collect()
}

/// Every key the set mentions anywhere, plus one it never mentions.
fn query_keys(pins: &PinnedObjects) -> BTreeSet<ObjectKey> {
    pins.raw_to_id
        .keys()
        .map(|raw| raw.key)
        .chain(pins.by_id.values().map(|entry| entry.raw.key))
        .chain(
            pins.by_id
                .values()
                .filter_map(|entry| entry.probed_maps_key),
        )
        .chain([overlay(999)])
        .collect()
}

/// Runs the whole query surface and compares it with the oracle.
fn assert_agrees(pins: &PinnedObjects, context: &str) {
    let keys = query_keys(pins);
    for id in query_ids(pins) {
        assert_eq!(
            pins.raw_keys_for(id),
            scan_raw_keys(pins, id),
            "{context}: raw_keys_for({id:?})"
        );
        for key in &keys {
            assert_eq!(
                pins.object_matches_key(id, key.device.major, key.device.minor, key.inode),
                scan_matches(pins, id, *key),
                "{context}: object_matches_key({id:?}, {key:?})"
            );
        }
    }
}

fn distinct_keys(count: u64) -> Vec<(ObjectKey, &'static str, i64)> {
    (1..=count).map(|minor| (overlay(minor), SHA, 1)).collect()
}

/// A batch of queries with no mutation in between costs at most one walk
/// of the raw map, however many objects and keys it asks about.
#[test]
fn raw_key_queries_walk_the_raw_map_at_most_once_per_clean_batch() {
    let pins = pin_set(&distinct_keys(16), true);
    assert_eq!(pins.by_id.len(), 16, "sixteen distinct objects");
    let keys = query_keys(&pins);
    raw_key_scan_count::reset();
    for _ in 0..3 {
        for id in query_ids(&pins) {
            let _ = pins.raw_keys_for(id);
            for key in &keys {
                let _ = pins.object_matches_key(id, key.device.major, key.device.minor, key.inode);
            }
        }
    }
    assert!(
        raw_key_scan_count::get() <= 1,
        "a clean batch walked the raw map {} times",
        raw_key_scan_count::get()
    );
}

/// A mutation of the raw map costs exactly one more walk on the next batch,
/// and the batch after it is free again.
#[test]
fn raw_key_queries_rewalk_once_after_a_raw_map_mutation() {
    let mut pins = pin_set(&distinct_keys(8), true);
    assert_agrees(&pins, "warm");
    assert!(pins.absorb(pin_set(&distinct_keys(12), true)).is_empty());
    raw_key_scan_count::reset();
    assert_agrees(&pins, "after absorb");
    assert_agrees(&pins, "second batch");
    assert_eq!(raw_key_scan_count::get(), 1, "one rebuild, then reuse");
}

/// Warm, mutate, query: each pin-set mutation that files, refiles or
/// retires raws (or edits the entry's own raw or probe key) must be
/// visible to the very next query.
#[test]
fn raw_key_queries_match_the_scan_after_every_mutation() {
    let mut pins = pin_set(&distinct_keys(4), true);
    for minor in 1..=4 {
        record_scan_ownership(&mut pins, ProcessViewId(minor as u32), overlay(minor), PATH);
    }
    assert_agrees(&pins, "built");

    // Absorb a manifest pin for a new key: a second raw source.
    assert!(pins.absorb(manifest_pin(overlay(41), SHA, 1)).is_empty());
    assert_agrees(&pins, "manifest absorbed");

    // Re-key the manifest raw onto a probed maps key.
    let manifest = pins.id_for_manifest(overlay(41), PATH).unwrap();
    pins.refile_manifest_raw_onto_maps_key(manifest, overlay(21), PATH);
    assert!(pins.raw_keys_for(manifest).contains(&overlay(21)));
    assert_agrees(&pins, "manifest re-keyed");

    // Retire one view: its raw goes, other views stay.
    assert!(pins.remove_view(ProcessViewId(2)).is_some());
    assert_agrees(&pins, "view retired");

    // A probe key edited on the entry alone (no raw-map change).
    let first = *pins.by_id.keys().next().unwrap();
    pins.by_id.get_mut(&first).unwrap().probed_maps_key = Some(overlay(77));
    assert!(pins.object_matches_key(first, 0, 77, super::test_fixture::INODE));
    assert_agrees(&pins, "probe key set");

    // The entry's own raw re-keyed without touching the raw map: the union
    // arm reads it live.
    pins.by_id.get_mut(&first).unwrap().raw.key = overlay(88);
    assert!(pins.raw_keys_for(first).contains(&overlay(88)));
    assert_agrees(&pins, "entry raw re-keyed");

    // A conflicting identity under an existing key rejects the group.
    let conflicting = pin_set(&[(overlay(3), "c0ffee00", 9)], true);
    let _ = pins.absorb(conflicting);
    assert_agrees(&pins, "conflict absorbed");

    // Claims reset: no raw change, still consistent.
    pins.reset_scan_pin_claims();
    assert_agrees(&pins, "claims reset");

    // Retire every remaining view.
    for minor in 1..=4 {
        let _ = pins.remove_view(ProcessViewId(minor as u32));
    }
    assert_agrees(&pins, "all views retired");
}

/// A clone shares no cached answer with its source: mutating either side
/// leaves the other's queries equal to its own scan.
#[test]
fn raw_key_queries_stay_per_copy_across_clone() {
    let mut source = pin_set(&distinct_keys(6), true);
    for minor in 1..=6 {
        record_scan_ownership(
            &mut source,
            ProcessViewId(minor as u32),
            overlay(minor),
            PATH,
        );
    }
    assert_agrees(&source, "warm source");
    let mut copy = source.clone();
    assert_agrees(&copy, "warm copy");
    assert!(copy.remove_view(ProcessViewId(3)).is_some());
    assert_agrees(&copy, "copy view retired");
    assert_agrees(&source, "source after copy retirement");
    assert!(copy.absorb(manifest_pin(overlay(41), SHA, 1)).is_empty());
    assert_agrees(&copy, "copy mutated");
    assert_agrees(&source, "source after copy mutation");
    assert!(source.absorb(pin_set(&distinct_keys(9), true)).is_empty());
    assert_agrees(&source, "source mutated");
    assert_agrees(&copy, "copy after source mutation");

    // A clone of a never-queried set.
    let cold = pin_set(&distinct_keys(3), true).clone();
    assert_agrees(&cold, "cold clone");
}

/// The raw map emptied in place (the reclaim path) and refilled.
#[test]
fn raw_key_queries_match_the_scan_after_the_raw_map_is_drained() {
    let mut pins = pin_set(&distinct_keys(5), true);
    assert_agrees(&pins, "warm");
    let _ = pins.raw_to_id.pop_first();
    assert_agrees(&pins, "one raw popped");
    drop(std::mem::take(&mut pins.raw_to_id));
    assert_agrees(&pins, "raw map taken");
    assert!(pins.absorb(pin_set(&distinct_keys(2), true)).is_empty());
    assert_agrees(&pins, "refilled");
}

/// One object under two keys: a pre-6.8 overlay split, whose manifest
/// alias the self-mapping probe refiles onto the scan pin, then the scan
/// view retires while the manifest keeps the object.
#[test]
fn raw_key_queries_track_split_aliases_of_one_object() {
    use super::test_fixture::{FakeSelfMappingProbe, backing_file, reback, split_scan_pin};
    let dir = tempfile::tempdir().unwrap();
    let file = backing_file(&dir, "provider.so");
    let maps_key = overlay(21);
    let fd_key = overlay(41);
    let mut pins = split_scan_pin(maps_key, fd_key, SHA, 1);
    reback(&mut pins, &file);
    record_scan_ownership(&mut pins, ProcessViewId(21), maps_key, PATH);
    assert_agrees(&pins, "scan pin");
    let mut manifest = manifest_pin(fd_key, SHA, 1);
    reback(&mut manifest, &file);
    assert!(pins.absorb(manifest).is_empty());
    assert_agrees(&pins, "manifest absorbed");
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let probe = FakeSelfMappingProbe::new(true, Some(maps_key));
    pins.refile_split_manifest_alias(maps_key, PATH, &mut budget, &probe);
    assert_agrees(&pins, "manifest alias refiled");
    let _ = pins.remove_view(ProcessViewId(21));
    assert_agrees(&pins, "scan view retired");
}

/// The keyed per-object summary equals the linear find over `pinned()`
/// it replaces at the coordinator and subset call sites, for every id the
/// set has minted (retired ones included) and ids it never minted.
#[test]
fn summary_matches_the_linear_pinned_find_for_every_id() {
    let fields = |pin: PinnedSummary<'_>| {
        (
            pin.id,
            pin.key,
            pin.path.to_string(),
            pin.sha256.to_string(),
            pin.build_id.map(str::to_string),
            pin.identity_source,
            pin.note.map(str::to_string),
            pin.pre_copy_up,
        )
    };
    let mut pins = pin_set(&distinct_keys(5), true);
    for minor in 1..=5 {
        record_scan_ownership(&mut pins, ProcessViewId(minor as u32), overlay(minor), PATH);
    }
    assert!(pins.absorb(manifest_pin(overlay(41), SHA, 1)).is_empty());
    let _ = pins.remove_view(ProcessViewId(2));
    for id in query_ids(&pins) {
        assert_eq!(
            pins.summary(id).map(fields),
            pins.pinned().find(|pin| pin.id == id).map(fields),
            "summary({id:?})"
        );
    }
    assert!(
        pins.summary(PinnedObjectId(1)).is_none(),
        "retired id has no summary"
    );
    assert!(
        pins.summary(PinnedObjectId(0)).is_some(),
        "live id has a summary"
    );
}

/// `replace_view_pins_without_claims` preserve means preserve: a preserved
/// id stays resolvable even when the view recorded ownership claims
/// without raw mappings (like `remove_view_except`, the generational
/// carry's other half), while the view's own claims still drop.
#[test]
fn replace_view_pins_preserve_survives_without_raw_ownership() {
    let mut pins = pin_set(&distinct_keys(2), true);
    let kept = PinnedObjectId(0);
    let dropped = PinnedObjectId(1);
    // Claims without raw mappings (no `record_scan_ownership` call).
    for id in [kept, dropped] {
        pins.ownership
            .entry(ProcessViewId(1))
            .or_default()
            .pins
            .push(id);
    }
    assert!(pins.summary(kept).is_some(), "fixture pins resolve");
    assert!(pins.summary(dropped).is_some(), "fixture pins resolve");
    pins.replace_view_pins_without_claims(ProcessViewId(1), PinnedObjects::empty(), &[kept]);
    assert!(
        pins.summary(kept).is_some(),
        "the preserved id stays resolvable without raw ownership"
    );
    assert!(
        pins.summary(dropped).is_none(),
        "the unpreserved id still drops"
    );
    assert!(
        pins.view_claims(ProcessViewId(1)).is_none(),
        "the view's own claims still drop"
    );
}

/// `prune_view_pins_to_modules` preserve means preserve: a preserved id
/// survives the global purge even with no ownership anywhere (like
/// except-kept pins after a conservative replay).
#[test]
fn prune_view_pins_to_modules_preserve_survives_global_purge() {
    let entries = distinct_keys(2);
    let mut pins = pin_set(&entries, true);
    let kept = PinnedObjectId(0);
    let dropped = PinnedObjectId(1);
    record_scan_ownership(&mut pins, ProcessViewId(1), entries[0].0, PATH);
    record_scan_ownership(&mut pins, ProcessViewId(2), entries[1].0, PATH);
    // View 1 retires carried: resolvable, claimless.
    pins.remove_view_except(ProcessViewId(1), &BTreeSet::from([kept]));
    assert!(pins.summary(kept).is_some(), "carried stays resolvable");
    assert!(pins.summary(dropped).is_some(), "fixture pins resolve");
    pins.prune_view_pins_to_modules(ProcessViewId(2), &[], &[kept]);
    assert!(
        pins.summary(kept).is_some(),
        "the purge spares carried coverage"
    );
    assert!(
        pins.summary(dropped).is_none(),
        "the pruned view's pins still drop"
    );
}

/// Global purges spare carried coverage: ids that stay resolvable
/// without ownership claims anywhere (the except-carry shape) survive
/// another view's replace, while fully dropped ids stay dropped.
#[test]
fn global_purge_spares_resolvable_but_claimless_ids() {
    let entries = distinct_keys(3);
    let mut pins = pin_set(&entries, true);
    let kept = PinnedObjectId(0);
    let owned = PinnedObjectId(1);
    let doomed = PinnedObjectId(2);
    record_scan_ownership(&mut pins, ProcessViewId(1), entries[0].0, PATH);
    record_scan_ownership(&mut pins, ProcessViewId(2), entries[1].0, PATH);
    record_scan_ownership(&mut pins, ProcessViewId(3), entries[2].0, PATH);
    // View 1 retires carried: resolvable, claimless.
    pins.remove_view_except(ProcessViewId(1), &BTreeSet::from([kept]));
    assert!(pins.summary(kept).is_some(), "carried stays resolvable");
    assert!(
        pins.view_claims(ProcessViewId(1)).is_none(),
        "carried drops its claims"
    );
    // An unrelated view's empty replace globally purges.
    pins.replace_view_pins(ProcessViewId(3), PinnedObjects::empty(), &[]);
    assert!(
        pins.summary(kept).is_some(),
        "the purge spares carried coverage"
    );
    assert!(
        pins.summary(owned).is_some(),
        "claimed pins survive the purge"
    );
    assert!(
        pins.summary(doomed).is_none(),
        "the replaced view's pins still drop"
    );
}

/// `replace_view_pins_with_claims_for` splits the sets: every preserved
/// id stays resolvable, but only `claims_for` restore ownership claims.
#[test]
fn replace_view_pins_with_claims_for_splits_resolve_and_claims() {
    let entries = distinct_keys(3);
    let mut pins = pin_set(&entries, true);
    let loader = PinnedObjectId(0);
    let carried = PinnedObjectId(1);
    let dropped = PinnedObjectId(2);
    for (key, _, _) in &entries {
        record_scan_ownership(&mut pins, ProcessViewId(1), *key, PATH);
    }
    pins.replace_view_pins_with_claims_for(
        ProcessViewId(1),
        PinnedObjects::empty(),
        &[loader, carried],
        &[loader],
    );
    assert!(pins.summary(loader).is_some(), "loader stays resolvable");
    assert!(pins.summary(carried).is_some(), "carried stays resolvable");
    assert!(pins.summary(dropped).is_none(), "other still drops");
    let claims = pins
        .view_claims(ProcessViewId(1))
        .expect("the view keeps claims");
    assert!(
        claims.pins.contains(&loader),
        "the loader id restores its claim"
    );
    assert!(
        !claims.pins.contains(&carried),
        "the carried id stays merely resolvable"
    );
}

/// A refused pin observation is skipped, never a group rejection: the
/// failed raw is scrubbed, committed entries stand, and the failure is
/// recorded as a skip.
#[test]
fn pin_failure_scrubs_without_group_rejection() {
    let entries = distinct_keys(2);
    let mut pins = pin_set(&entries, true);
    record_scan_ownership(&mut pins, ProcessViewId(1), entries[0].0, PATH);
    record_scan_ownership(&mut pins, ProcessViewId(2), entries[1].0, PATH);
    let filed = pins.raw_to_id.keys().next().unwrap().clone();
    let raw = RawObjectInstance {
        path: "/unfiled.so".to_string(),
        ..filed
    };
    let mut skipped = Vec::new();
    record_scanned_candidate(
        &mut pins,
        ProcessViewId(3),
        raw.clone(),
        Err(PinFailure::Refused("TEST refused".to_string())),
        &mut skipped,
        false,
    );
    assert!(!pins.rejects(raw.key), "pin failure never group-rejects");
    assert!(
        pins.summary(PinnedObjectId(0)).is_some(),
        "committed entries stand"
    );
    assert!(
        pins.summary(PinnedObjectId(1)).is_some(),
        "committed entries stand"
    );
    assert!(!skipped.is_empty(), "the failure is still recorded");
}

/// Two views refusing one key in the same store pair into ambiguity —
/// without group-rejecting it. A lone refusal marks only itself.
#[test]
fn same_store_refusal_pair_publishes_ambiguity_without_rejection() {
    let source = pin_set(&distinct_keys(1), true);
    let raw = source.by_id.values().next().unwrap().raw.clone();
    let mut pins = PinnedObjects::empty();
    let mut skipped = Vec::new();
    record_scanned_candidate(
        &mut pins,
        ProcessViewId(1),
        raw.clone(),
        Err(PinFailure::Refused("TEST refused one".to_string())),
        &mut skipped,
        false,
    );
    assert!(
        pins.ambiguous_keys.is_empty(),
        "a lone refusal publishes no ambiguity"
    );
    record_scanned_candidate(
        &mut pins,
        ProcessViewId(2),
        raw.clone(),
        Err(PinFailure::Refused("TEST refused two".to_string())),
        &mut skipped,
        false,
    );
    assert!(
        pins.ambiguous_keys.contains(&raw.key),
        "the paired refusal publishes ambiguity"
    );
    assert!(
        !pins.rejects(raw.key),
        "paired refusals never group-reject the key"
    );
}

/// Refusals pair across stores at absorb: two single-refusal scans of
/// one key publish ambiguity when the second absorbs — the
/// cross-store twin of the same-store pairing above.
#[test]
fn absorb_pairs_refusals_across_stores_into_ambiguity() {
    let source = pin_set(&distinct_keys(1), true);
    let raw = source.by_id.values().next().unwrap().raw.clone();
    let mut first = PinnedObjects::empty();
    let mut skipped = Vec::new();
    record_scanned_candidate(
        &mut first,
        ProcessViewId(1),
        raw.clone(),
        Err(PinFailure::Refused("TEST refused one".to_string())),
        &mut skipped,
        false,
    );
    let mut second = PinnedObjects::empty();
    record_scanned_candidate(
        &mut second,
        ProcessViewId(2),
        raw.clone(),
        Err(PinFailure::Refused("TEST refused two".to_string())),
        &mut skipped,
        false,
    );
    assert!(
        first.ambiguous_keys.is_empty(),
        "one refusal alone publishes no ambiguity"
    );
    skipped.extend(first.absorb(second));
    assert!(
        first.ambiguous_keys.contains(&raw.key),
        "absorb pairs the cross-store refusals"
    );
    assert!(
        !first.rejects(raw.key),
        "paired refusals never group-reject the key"
    );
}

/// A view that refused a key contradicts itself by filing it after:
/// the filing group-rejects like the reverse order, so the pairing
/// is order-free — with a named counted gap, never silence.
#[test]
fn file_after_refuse_group_rejects_with_a_contradiction_gap() {
    let source = pin_set(&distinct_keys(1), true);
    let entry = source.by_id.values().next().unwrap().clone();
    let raw = entry.raw.clone();
    let mut pins = PinnedObjects::empty();
    let mut skipped = Vec::new();
    record_scanned_candidate(
        &mut pins,
        ProcessViewId(1),
        raw.clone(),
        Err(PinFailure::Refused("TEST refused".to_string())),
        &mut skipped,
        false,
    );
    record_scanned_candidate(
        &mut pins,
        ProcessViewId(1),
        raw.clone(),
        Ok(entry),
        &mut skipped,
        false,
    );
    assert!(
        pins.rejects(raw.key),
        "filing after refusing group-rejects the key"
    );
    assert!(
        pins.ambiguous_keys.contains(&raw.key),
        "the contradiction publishes ambiguity"
    );
    assert!(
        skipped
            .iter()
            .any(|skip| skip.reason.contains("contradicts filed")),
        "the contradiction leaves a named gap: {skipped:?}"
    );
}
