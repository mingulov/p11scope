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
