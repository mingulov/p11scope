//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! v072 carried-view-ids fix3/fix4/fix5: killing tests for the blocking
//! review classes (absence-proof walk arm, table-specific interface
//! coverage, INV-2 charging, watch continuation, pin reclaim), the fix4
//! follow-ups (stable cross-store custody, table identity, paced
//! retirement, post-filter reclaim, clause-level co-owners) and the fix5
//! follow-ups (committing-target remap, newcomer direct-child staging,
//! skip-pop charging, reject/bind pacing, stage-failure loss, unhashed
//! staged keys, version/walk conjuncts). Each test fails when its guard
//! is removed; see the lane reports' site tables and sweeps.

use super::*;

/// Seeds one attached overlay provider, exits its view under a pending
/// newcomer mark so the carrier commits, then drains the mark. Returns
/// the engine and the carried object. The caller owns the scope after
/// this (seed runs on System).
fn fix3_seed_carrier(key_minor: u64) -> (Engine, PinnedObjectId) {
    let key = overlay_key(key_minor);
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let id_r = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_r = ProcessView::open(id_r, me).unwrap();
    let mut module = overlay_module(key);
    module.view = id_r;
    let mut pins = overlay_view_pin(&module, 6300 + key_minor, OVERLAY_SHA, 1, false);
    record_scan_ownership(&mut pins, id_r, key, &module.path);
    pins.prove_scanned_entries_for_test(std::slice::from_ref(&module));
    let seed = engine
        .inventory_candidate(
            &empty,
            &[],
            &[(view_r, vec![module], pins)],
            Vec::new(),
            &empty,
        )
        .unwrap();
    engine.plan = seed.plan;
    engine.pinned = seed.pinned;
    engine.modules = seed.modules;
    engine.views.push(ProcessView::open(id_r, me).unwrap());
    let object = engine
        .modules
        .iter()
        .find(|module| module.scanned.view == id_r)
        .expect("the seed row commits")
        .object;
    engine
        .newcomer_first_seen
        .insert(424200 + key_minor as u32, None);
    let removed = engine
        .inventory_candidate(&BTreeSet::from([id_r]), &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = removed.plan;
    engine.pinned = removed.pinned;
    engine.modules = removed.modules;
    engine.views.retain(|view| view.id() != id_r);
    engine.release_view_id(id_r);
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "the carrier commits under the pending mark"
    );
    engine
        .newcomer_first_seen
        .remove(&(424200 + key_minor as u32));
    assert!(
        engine.newcomer_first_seen.is_empty(),
        "no timing mark remains"
    );
    assert!(engine.refresh_requested.is_empty(), "no refresh waits");
    assert!(engine.held_back.is_empty(), "no held-back retry waits");
    assert!(
        engine.views.len() < engine.max_scan_pids,
        "view capacity is spare"
    );
    (engine, object)
}

#[test]
fn carried_fix3_incomplete_scope_walk_keeps_carrier() {
    // F1 ordinary-tick twins: a cgroup walk that omits a member outside
    // the observer's PID namespace (a `0` row) keeps every carrier even
    // when every listed member is serviced — absence over a partial
    // member set never proves. The walk's skip files as the named gap.
    // Rewriting the listing complete resumes detach on the next tick.
    let (mut engine, object) = fix3_seed_carrier(901);
    let me = std::process::id();
    // One admitted rowless view keeps the scope non-empty without
    // contributing rows: the carrier's object has no live mapper.
    let dir = tempfile::tempdir().expect("a scope directory");
    std::fs::write(dir.path().join("cgroup.procs"), format!("{me}\n0\n"))
        .expect("a cgroup.procs with an invisible member");
    engine.scope = crate::scope::cgroup(dir.path()).expect("open scope directory");
    let id_p = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_p, me).unwrap());
    engine.plan_rebuild_stable = true;
    refresh_inventory_once(&mut engine);
    assert!(
        !engine.last_scope_walk_complete,
        "the tick stashes the partial walk"
    );
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "a partial walk keeps the carrier behind its invisible mapper"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "the riding carrier's pin stays while its row rides"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason.contains("listed as 0")
                || skip
                    .reason
                    .contains("outside this observer's PID namespace")
        }),
        "the invisible member files as a named gap: {:?}",
        engine.counters.object_skips
    );
    // Control: the same tick over a complete walk resumes detach.
    std::fs::write(dir.path().join("cgroup.procs"), format!("{me}\n"))
        .expect("a complete cgroup.procs");
    engine.plan_rebuild_stable = true;
    refresh_inventory_once(&mut engine);
    assert!(
        engine.last_scope_walk_complete,
        "the complete walk stashes true"
    );
    assert!(
        engine.modules.iter().all(|module| {
            module.scanned.view != Engine::CARRIED_VIEW_ID || module.object != object
        }),
        "detach resumes on the first complete, serviced walk"
    );
}

#[test]
fn carried_fix3_replay_partial_walk_keeps_carrier() {
    // F1 replay twins: the conservative replay's own scope walk carries
    // the same completeness verdict — a partial walk keeps every
    // carrier, files its skips as the named gap (the replay builds no
    // tick `skipped` vec), and a later complete replay resumes detach.
    let (mut engine, object) = fix3_seed_carrier(902);
    let me = std::process::id();
    engine.owned_run_pid = Some(me);
    let dir = tempfile::tempdir().expect("a scope directory");
    std::fs::write(dir.path().join("cgroup.procs"), format!("{me}\n0\n"))
        .expect("a cgroup.procs with an invisible member");
    engine.scope = crate::scope::cgroup(dir.path()).expect("open scope directory");
    let id_p = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_p, me).unwrap());
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();
    engine.replay_pending_conservative(&mut session, &mut additions, &mut pending);
    assert!(
        !engine.last_scope_walk_complete,
        "the replay stashes the partial walk"
    );
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "a partial replay walk keeps the carrier"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason.contains("listed as 0")
                || skip
                    .reason
                    .contains("outside this observer's PID namespace")
        }),
        "the replay files the invisible member as a named gap: {:?}",
        engine.counters.object_skips
    );
    // Control: a complete replay resumes detach.
    std::fs::write(dir.path().join("cgroup.procs"), format!("{me}\n"))
        .expect("a complete cgroup.procs");
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();
    engine.replay_pending_conservative(&mut session, &mut additions, &mut pending);
    assert!(
        engine.last_scope_walk_complete,
        "the complete replay stashes true"
    );
    assert!(
        engine.modules.iter().all(|module| {
            module.scanned.view != Engine::CARRIED_VIEW_ID || module.object != object
        }),
        "a complete replay resumes detach"
    );
}

/// Builds a two-table module sharing `key`'s file: tables[0] is A
/// (`C_Initialize`), tables[1] is B (`C_Finalize`, same version and
/// walk, disjoint entries), with one interface linked to `link`.
fn fix3_two_table_module(key: ObjectKey, link: Option<usize>) -> ScannedModule {
    let mut module = overlay_module(key);
    module.tables.push(ScannedTable {
        version: (2, 40),
        walk: "full",
        entries: vec![ScannedEntry {
            name: "C_Finalize",
            object: key,
            object_path: OVERLAY_PATH.into(),
            file_offset: 0x1100,
        }],
        null_entries: vec![],
        unpinned: vec![],
        address: 0x7100,
        file_offset: Some(0x100),
        live_return: false,
        manifest_supported: false,
        extension_impossible: false,
    });
    module.interfaces = vec![ScannedInterface {
        index: 0,
        name_class: "exact_standard",
        name_lossy: None,
        name_private: None,
        flags: 0,
        table: link,
    }];
    module
}

#[test]
fn carried_fix3_interface_coverage_requires_exact_table_link() {
    // F2 predicate unit: a carrier interface linked to table A is
    // covered only by a live interface with the same identity whose
    // own linked table covers A. Exact and reordered-index covers
    // pass; a redirected link, a dangling carrier link and a dangling
    // live link all fail closed.
    let key = overlay_key(910);
    let carrier = fix3_two_table_module(key, Some(0));
    // Exact: same order, same link.
    let live_exact = fix3_two_table_module(key, Some(0));
    assert!(
        super::carrier_covered_by_live(&carrier, &[&live_exact]),
        "an exact table link covers"
    );
    // Reordered: live tables [B, A], interface follows A to index 1.
    let mut live_reordered = fix3_two_table_module(key, Some(1));
    live_reordered.tables.swap(0, 1);
    assert!(
        super::carrier_covered_by_live(&carrier, &[&live_reordered]),
        "a legitimate index reorder still covers (identity is by content)"
    );
    // Redirected: live links the same interface to B instead of A.
    let live_redirected = fix3_two_table_module(key, Some(1));
    assert!(
        !super::carrier_covered_by_live(&carrier, &[&live_redirected]),
        "a link redirected to a different table never covers the carrier's table"
    );
    // Dangling carrier link: names no table, nothing covers it.
    let carrier_dangling = fix3_two_table_module(key, Some(7));
    assert!(
        !super::carrier_covered_by_live(&carrier_dangling, &[&live_exact]),
        "a dangling carrier link fails closed"
    );
    // Dangling live link: covers nothing.
    let live_dangling = fix3_two_table_module(key, Some(7));
    assert!(
        !super::carrier_covered_by_live(&carrier, &[&live_dangling]),
        "a dangling live link covers nothing"
    );
    // Unlinked carrier interface: presence alone still suffices.
    let mut carrier_unlinked = fix3_two_table_module(key, None);
    carrier_unlinked.interfaces[0].table = None;
    assert!(
        super::carrier_covered_by_live(&carrier_unlinked, &[&live_exact]),
        "an unlinked carrier interface needs presence only"
    );
}

#[test]
fn carried_fix3_normalize_keeps_redirected_table_link() {
    // F2 normalize integration: a riding carrier drops when a live row
    // covers its exact table link (exact and reordered), but rides on
    // when the live row links the same interface to a different table
    // — even though both tables' raw entry sets are present. Absence
    // stays false throughout so only coverage decides.
    let key = overlay_key(911);
    for (name, link, expect_drop) in
        [("exact", Some(0), true), ("redirected", Some(1), false)].iter()
    {
        let mut carrier = fix3_two_table_module(key, Some(0));
        carrier.view = Engine::CARRIED_VIEW_ID;
        let live_view = ProcessViewId(710);
        let mut live = fix3_two_table_module(key, *link);
        live.view = live_view;
        let mut pins = overlay_view_pin(&live, 7100, OVERLAY_SHA, 1, false);
        record_scan_ownership(&mut pins, live_view, key, &live.path);
        let mut raw = vec![carrier, live];
        let mut dropped = 0u64;
        super::normalize_carried_modules(
            &mut raw,
            &pins,
            &BTreeSet::new(),
            &BTreeSet::from([live_view]),
            false,
            &mut dropped,
        );
        let kept = raw
            .iter()
            .any(|module| module.view == Engine::CARRIED_VIEW_ID);
        assert_eq!(
            !kept, *expect_drop,
            "normalize {name} link: carrier drops={expect_drop}"
        );
    }
    // Reordered twin: live tables [B, A] with the interface following
    // A to index 1 still covers.
    let mut carrier = fix3_two_table_module(key, Some(0));
    carrier.view = Engine::CARRIED_VIEW_ID;
    let live_view = ProcessViewId(711);
    let mut live = fix3_two_table_module(key, Some(1));
    live.tables.swap(0, 1);
    live.view = live_view;
    let mut pins = overlay_view_pin(&live, 7101, OVERLAY_SHA, 1, false);
    record_scan_ownership(&mut pins, live_view, key, &live.path);
    let mut raw = vec![carrier, live];
    let mut dropped = 0u64;
    super::normalize_carried_modules(
        &mut raw,
        &pins,
        &BTreeSet::new(),
        &BTreeSet::from([live_view]),
        false,
        &mut dropped,
    );
    assert!(
        raw.iter()
            .all(|module| module.view != Engine::CARRIED_VIEW_ID),
        "normalize reordered link: the carrier drops"
    );
}

#[test]
fn carried_fix3_quiet_mirror_keeps_redirected_table_link() {
    // F2 mirror integration: committed state with a carrier plus a live
    // row linking the same interface to a different table does not
    // read as droppable; fixing the link in place (exact cover) flips
    // the mirror. The commit path itself exercises normalize (the
    // redirected carrier survives the commit below).
    let key = overlay_key(912);
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    // Seed the carrier with the two-table shape.
    let id_r = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_r = ProcessView::open(id_r, me).unwrap();
    let mut seed_module = fix3_two_table_module(key, Some(0));
    seed_module.view = id_r;
    let mut seed_pins = overlay_view_pin(&seed_module, 7200, OVERLAY_SHA, 1, false);
    record_scan_ownership(&mut seed_pins, id_r, key, &seed_module.path);
    seed_pins.prove_scanned_entries_for_test(std::slice::from_ref(&seed_module));
    let seed = engine
        .inventory_candidate(
            &empty,
            &[],
            &[(view_r, vec![seed_module], seed_pins)],
            Vec::new(),
            &empty,
        )
        .unwrap();
    engine.plan = seed.plan;
    engine.pinned = seed.pinned;
    engine.modules = seed.modules;
    engine.views.push(ProcessView::open(id_r, me).unwrap());
    let object = engine
        .modules
        .iter()
        .find(|module| module.scanned.view == id_r)
        .expect("the seed row commits")
        .object;
    engine.newcomer_first_seen.insert(424300, None);
    let removed = engine
        .inventory_candidate(&BTreeSet::from([id_r]), &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = removed.plan;
    engine.pinned = removed.pinned;
    engine.modules = removed.modules;
    engine.views.retain(|view| view.id() != id_r);
    engine.release_view_id(id_r);
    engine.newcomer_first_seen.remove(&424300);
    // Admit a live successor mapping the same file but linking the
    // interface to table B (redirected).
    let id_l = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_l = ProcessView::open(id_l, me).unwrap();
    let mut live_module = fix3_two_table_module(key, Some(1));
    live_module.view = id_l;
    let mut live_pins = overlay_view_pin(&live_module, 7201, OVERLAY_SHA, 1, false);
    record_scan_ownership(&mut live_pins, id_l, key, &live_module.path);
    live_pins.prove_scanned_entries_for_test(std::slice::from_ref(&live_module));
    let admitted = engine
        .inventory_candidate(
            &empty,
            &[],
            &[(view_l, vec![live_module], live_pins)],
            Vec::new(),
            &empty,
        )
        .unwrap();
    engine.plan = admitted.plan;
    engine.pinned = admitted.pinned;
    engine.modules = admitted.modules;
    engine.views.push(ProcessView::open(id_l, me).unwrap());
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "the redirected carrier survives the commit (normalize keeps it)"
    );
    assert!(
        !engine.carried_rows_would_drop(),
        "the quiet mirror keeps a redirected table link"
    );
    // Control: pointing the committed live link at the covering table
    // flips the mirror (direct committed-state edit, cache cleared via
    // the commit seam's refresh).
    for module in engine.modules.iter_mut() {
        if module.scanned.view == id_l {
            module.scanned.interfaces[0].table = Some(0);
        }
    }
    engine.refresh_held_view_ids();
    assert!(
        engine.carried_rows_would_drop(),
        "an exact committed link reads as droppable"
    );
}

#[test]
fn carried_fix3_quiet_checks_cache_carrier_verdict() {
    // F3a: repeated quiet checks over unchanged inputs pay one full
    // scan and hit the cache after; any input change (marks, walk,
    // commit epoch) recomputes exactly once.
    let (mut engine, object) = fix3_seed_carrier(920);
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "the carrier commits"
    );
    // Droppable (absence proven): three checks, one computation.
    assert!(
        engine.carried_rows_would_drop(),
        "the carrier reads droppable"
    );
    assert!(engine.carried_rows_would_drop(), "repeat check still drops");
    assert!(engine.carried_rows_would_drop(), "third check still drops");
    assert_eq!(
        engine.carried_drop_computations_for_test, 1,
        "one full scan for three identical checks"
    );
    assert_eq!(engine.carried_drop_cache_hits_for_test, 2, "two cache hits");
    // A new arrival mark flips the verdict and recomputes once.
    engine.newcomer_first_seen.insert(424400, None);
    assert!(
        !engine.carried_rows_would_drop(),
        "a waiting mark keeps the carrier"
    );
    assert_eq!(
        engine.carried_drop_computations_for_test, 2,
        "the changed input recomputes"
    );
    assert!(
        !engine.carried_rows_would_drop(),
        "the kept verdict caches too"
    );
    assert_eq!(
        engine.carried_drop_cache_hits_for_test, 3,
        "third hit on the kept verdict"
    );
    // A partial walk flips the verdict and recomputes once.
    engine.newcomer_first_seen.remove(&424400);
    engine.last_scope_walk_complete = false;
    assert!(
        !engine.carried_rows_would_drop(),
        "a partial walk keeps the carrier"
    );
    assert_eq!(
        engine.carried_drop_computations_for_test, 3,
        "the walk flip recomputes"
    );
    // Walk-only flip back (marks stay empty): the key must qualify
    // the walk bit, or this hits stale and keeps wrongly.
    engine.last_scope_walk_complete = true;
    assert!(engine.carried_rows_would_drop(), "the walk heals");
    assert_eq!(
        engine.carried_drop_computations_for_test, 4,
        "the walk-only flip recomputes"
    );
    // A new commit epoch invalidates: refresh, then the next check
    // recomputes even though the tick signals match.
    engine.refresh_held_view_ids();
    assert!(engine.carried_rows_would_drop(), "still droppable");
    assert_eq!(
        engine.carried_drop_computations_for_test, 5,
        "the commit epoch recomputes"
    );
}

#[test]
fn carried_fix3_cached_commit_skips_held_rebuild() {
    // F3b: committing a candidate that clones the rows unchanged skips
    // the O(M+R) named/held rebuild (the sets stay exact via
    // incremental release/allocate maintenance); a full rebuild
    // refreshes as before.
    let (mut engine, _object) = fix3_seed_carrier(921);
    engine.plan_rebuild_stable = true;
    // Quiet the carrier so the unchanged path is taken: a waiting mark
    // keeps it (mirror false), and the empty candidate clones rows.
    engine.newcomer_first_seen.insert(424401, None);
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let cached = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    assert!(
        cached.modules_unchanged,
        "the quiet candidate clones rows unchanged"
    );
    assert!(
        !cached.built_by_full_rebuild || cached.modules_unchanged,
        "cached shape"
    );
    let named_before = engine.named_view_ids.clone();
    let held_before = engine.held_view_ids.clone();
    let mut additions = true;
    let outcome = engine
        .apply_candidate(
            &mut ScriptedSession::default(),
            cached,
            &mut additions,
            false,
            &[],
        )
        .unwrap();
    assert_eq!(
        outcome.disposition,
        ApplyDisposition::Accepted,
        "the cached candidate commits"
    );
    assert_eq!(
        engine.held_refresh_skipped_for_test, 1,
        "the cached commit skips the rebuild"
    );
    assert_eq!(
        engine.named_view_ids, named_before,
        "the named set stays exact without a rebuild"
    );
    assert_eq!(
        engine.held_view_ids, held_before,
        "the held set stays exact without a rebuild"
    );
    // Control: a forced full rebuild refreshes (no skip).
    engine.set_disable_empty_tick_fast_path_for_test(true);
    let full = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    assert!(
        !full.modules_unchanged,
        "the forced candidate rebuilds rows"
    );
    let mut additions = true;
    engine
        .apply_candidate(
            &mut ScriptedSession::default(),
            full,
            &mut additions,
            false,
            &[],
        )
        .unwrap();
    assert_eq!(
        engine.held_refresh_skipped_for_test, 1,
        "the full commit refreshes (no additional skip)"
    );
}

#[test]
fn carried_fix3_owned_learn_charges_naming_and_staging() {
    // F3c: every loader naming happens under a stride credit (64 per
    // apply); the 65th proof names and stages on the next apply.
    // Naming, staging attempts, file probes and closes (cap refuses)
    // are counted independently.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let mut pins = PinnedObjects::empty();
    for index in 0..PROOFS {
        let backing = dir.path().join(format!("libprov{index}.so"));
        std::fs::write(&backing, format!("p11scope-fixture:provider-bytes-{index}"))
            .expect("write backing");
        let sha = format!("{:064x}", 0xcd0000u64 + index as u64);
        let skips = pins.absorb(real_scan_pin(&backing, None, 400, &sha));
        assert!(skips.is_empty(), "{skips:?}");
    }
    let objects: Vec<PinnedObjectId> = pins.pinned().map(|pin| pin.id).collect();
    assert_eq!(objects.len(), PROOFS, "every backing file pins distinctly");
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 7,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    // A descendant prover, not the run child itself (the child's own
    // files need no learning and skip): the owned pid is arbitrary
    // here, the proving view is live.
    engine.owned_run_pid = Some(424242);
    engine.next_view_id = 100;
    let prover = ProcessView::open(ProcessViewId(0), me).expect("own view opens");
    engine.views.push(prover);
    // Unnamed live proofs: naming must happen under credit, via the
    // committed proving view. Tableless modules isolate file-staging
    // pacing from the run-learned table harvest (which refuses past
    // its own cap into the same counter).
    let mut proofs = Vec::with_capacity(PROOFS);
    for (index, object) in objects.iter().enumerate() {
        let key = overlay_key(9300 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = ProcessViewId(0);
        proofs.push(OwnedLearnProof {
            view: ProcessViewId(0),
            path: dir
                .path()
                .join(format!("libprov{index}.so"))
                .to_string_lossy()
                .into_owned(),
            object: *object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], None);
    assert_eq!(
        engine.owned_learn_naming_for_test,
        super::GRAPH_STRIDE as u64,
        "the first apply names exactly one stride"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        super::GRAPH_STRIDE as u64,
        "the first apply attempts exactly one stride"
    );
    assert_eq!(
        engine.owned_learn_file_probes_for_test,
        super::GRAPH_STRIDE as u64,
        "every attempt reaches its file"
    );
    assert_eq!(
        engine.pending_learned.len(),
        crate::fanotify::LEARNED_FILES_PER_CAPTURE_CAP,
        "staging fills to its cap"
    );
    assert_eq!(
        engine.learned_cap_skipped(),
        (super::GRAPH_STRIDE - crate::fanotify::LEARNED_FILES_PER_CAPTURE_CAP) as u64,
        "the paced stride refuses past the cap (each refusal closes its file)"
    );
    // Second apply names and settles the deferred proof.
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], None);
    assert_eq!(
        engine.owned_learn_naming_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "the deferred proof names exactly once"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "the deferred proof attempts exactly once"
    );
    assert_eq!(
        engine.learned_cap_skipped(),
        (super::GRAPH_STRIDE + 1 - crate::fanotify::LEARNED_FILES_PER_CAPTURE_CAP) as u64,
        "the deferred proof refuses exactly once"
    );
}

#[test]
fn carried_fix3_apply_producer_gates_naming_on_owned_runs() {
    // F3c producer gate: the live apply path builds no proofs and
    // names nothing outside owned runs; the same candidate under an
    // owned run names one stride through the real apply.
    const MODULES: usize = super::GRAPH_STRIDE + 1;
    let me = std::process::id();
    // Returns the candidate plus its newcomer view (retained so the
    // owned apply can prove through it as an extra view).
    let build_candidate = |engine: &mut Engine| {
        let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
        let id_v = engine.allocate_view_id_for_newcomer(me).unwrap();
        let view_v = ProcessView::open(id_v, me).unwrap();
        let mut modules = Vec::with_capacity(MODULES);
        let mut pins = PinnedObjects::empty();
        for index in 0..MODULES {
            let key = overlay_key(9400 + index as u64);
            let mut module = overlay_module(key);
            module.view = id_v;
            let mpins = overlay_view_pin(&module, 7400 + index as u64, OVERLAY_SHA, 1, false);
            let skips = pins.absorb(mpins);
            assert!(skips.is_empty(), "{skips:?}");
            record_scan_ownership(&mut pins, id_v, key, &module.path);
            pins.prove_scanned_entries_for_test(std::slice::from_ref(&module));
            modules.push(module);
        }
        let candidate = engine
            .inventory_candidate(&empty, &[], &[(view_v, modules, pins)], Vec::new(), &empty)
            .unwrap();
        // Reopen the newcomer view for the apply's extra views (the
        // candidate borrowed it; the id still names the same live pid).
        (candidate, ProcessView::open(id_v, me).unwrap())
    };
    // Outside owned runs: the apply names nothing. Extra views are
    // passed (as in production) so only the owned-run gate — not the
    // proven-view check — can explain zero builds.
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    let (candidate, view_v) = build_candidate(&mut engine);
    let mut additions = true;
    engine
        .apply_candidate(
            &mut ScriptedSession::default(),
            candidate,
            &mut additions,
            false,
            &[&view_v],
        )
        .unwrap();
    assert_eq!(
        engine.owned_learn_naming_for_test, 0,
        "no naming outside owned runs"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 0,
        "no staging outside owned runs"
    );
    assert_eq!(
        engine.owned_learn_proofs_built_for_test, 0,
        "the producer builds nothing outside owned runs"
    );
    // Under an owned run the same shape names one stride.
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 8,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    let (candidate, view_v) = build_candidate(&mut engine);
    let mut additions = true;
    engine
        .apply_candidate(
            &mut ScriptedSession::default(),
            candidate,
            &mut additions,
            false,
            &[&view_v],
        )
        .unwrap();
    assert_eq!(
        engine.owned_learn_naming_for_test,
        super::GRAPH_STRIDE as u64,
        "the owned apply names one stride"
    );
    assert_eq!(
        engine.owned_learn_proofs_built_for_test, MODULES as u64,
        "the owned producer builds every eligible shell (naming paces the rest)"
    );
}

#[test]
fn carried_fix3_watch_backlog_drains_after_member_exit() {
    // F4: one watch batch over the stride queues its paced-out proof
    // with the proving pin; after the member exits, a later drain
    // names (finite unknown) and settles proof 65 without another
    // scan of the PID — nothing is lost with the local vector.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let mut pins = PinnedObjects::empty();
    for index in 0..PROOFS {
        let backing = dir.path().join(format!("libprov{index}.so"));
        std::fs::write(&backing, format!("p11scope-fixture:provider-bytes-{index}"))
            .expect("write backing");
        let sha = format!("{:064x}", 0xde0000u64 + index as u64);
        let skips = pins.absorb(real_scan_pin(&backing, None, 400, &sha));
        assert!(skips.is_empty(), "{skips:?}");
    }
    let objects: Vec<PinnedObjectId> = pins.pinned().map(|pin| pin.id).collect();
    assert_eq!(objects.len(), PROOFS, "every backing file pins distinctly");
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 9,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    // A short-lived member proves the batch, then exits before the
    // next round.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a watch member");
    let member = child.id();
    let watch_id = engine.allocate_view_id().unwrap();
    let watch_view = ProcessView::open(watch_id, member).expect("the member view opens");
    let mut proofs = Vec::with_capacity(PROOFS);
    for (index, object) in objects.iter().enumerate() {
        let key = overlay_key(9500 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = watch_id;
        proofs.push(OwnedLearnProof {
            view: watch_id,
            path: dir
                .path()
                .join(format!("libprov{index}.so"))
                .to_string_lossy()
                .into_owned(),
            object: *object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], Some(&watch_view));
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        super::GRAPH_STRIDE as u64,
        "the batch attempts one stride"
    );
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out proof queues with its pin"
    );
    assert_eq!(
        engine.learned_cap_skipped(),
        (super::GRAPH_STRIDE - crate::fanotify::LEARNED_FILES_PER_CAPTURE_CAP) as u64,
        "only the paced stride refuses at the file cap"
    );
    // The member exits before the next round; the queued proof stays.
    child.kill().expect("the member exits");
    child.wait().expect("the member reaps");
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the exit takes no queued proof"
    );
    // A later drain settles proof 65 with no new scan: no new proofs,
    // only the backlog.
    let drain_pins = pins.clone();
    let mut drain_pins = drain_pins;
    engine.learn_owned_proofs_with_views(&mut drain_pins, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain settles the backlog"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "proof 65 attempts exactly once, on the drain"
    );
    assert_eq!(
        engine.learned_cap_skipped(),
        (super::GRAPH_STRIDE + 1 - crate::fanotify::LEARNED_FILES_PER_CAPTURE_CAP) as u64,
        "proof 65 refuses exactly once at the full cap (counted, not lost)"
    );
}

#[test]
fn carried_fix3_watch_backlog_refuses_loudly_when_full() {
    // F4 bound: past 128 queued proofs the excess refuses with counted
    // loss instead of queueing unboundedly (or vanishing silently).
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 10,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    let view = ProcessView::open(ProcessViewId(60), me).expect("own view opens");
    let key = overlay_key(9600);
    let mut module = super::owned_proof_module_without_tables(key);
    module.view = ProcessViewId(60);
    let pins = overlay_view_pin(&module, 9601, OVERLAY_SHA, 1, false);
    let object = pins
        .id_for_scanned(&module, module.key, &module.path)
        .expect("the fixture pin resolves");
    let proof = OwnedLearnProof {
        view: ProcessViewId(60),
        path: OVERLAY_PATH.into(),
        object,
        loader_exe: None,
        loader_unknown_reason: None,
        module,
    };
    assert_eq!(
        super::OWNED_LEARN_DEFERRED_CAP,
        128,
        "the backlog bound is two strides, pinned absolutely"
    );
    for _ in 0..super::OWNED_LEARN_DEFERRED_CAP {
        engine.defer_owned_learn_proof(&proof, &view, &pins);
    }
    assert_eq!(
        engine.owned_learn_deferred.len(),
        128,
        "the backlog fills to 128"
    );
    let skipped_before = engine.learned_cap_skipped();
    engine.defer_owned_learn_proof(&proof, &view, &pins);
    assert_eq!(
        engine.owned_learn_deferred.len(),
        128,
        "the 129th proof queues nowhere"
    );
    assert_eq!(
        engine.learned_cap_skipped(),
        skipped_before + 1,
        "the excess refuses with counted loss"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.reason.contains("deferred backlog is full") }),
        "the refusal names the backlog: {:?}",
        engine.counters.object_skips
    );
}

#[test]
fn carried_fix3_quiet_detach_reclaims_unowned_pin() {
    // F5 last-owner: a quiet tick that retires the final carrier row
    // for an otherwise unowned provider reclaims its pin (no
    // claimless open file survives in the store).
    let (mut engine, object) = fix3_seed_carrier(930);
    assert!(
        engine.pinned.summary(object).is_some(),
        "the pin commits with the carrier"
    );
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    engine.plan_rebuild_stable = true;
    let quiet = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = quiet.plan;
    engine.pinned = quiet.pinned;
    engine.modules = quiet.modules;
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the last row retires"
    );
    assert!(
        engine.pinned.summary(object).is_none(),
        "the carrier-only pin is reclaimed (no claimless file survives)"
    );
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test, 1,
        "exactly one pin reclaims"
    );
}

#[test]
fn carried_fix3_shared_live_row_survives_carrier_detach() {
    // F5 shared-owner: when a live row maps the same file, the
    // redundant carrier drops but the pin survives for the live row.
    let key = overlay_key(931);
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let id_r = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_r = ProcessView::open(id_r, me).unwrap();
    let mut module = overlay_module(key);
    module.view = id_r;
    let mut pins = overlay_view_pin(&module, 7500, OVERLAY_SHA, 1, false);
    record_scan_ownership(&mut pins, id_r, key, &module.path);
    pins.prove_scanned_entries_for_test(std::slice::from_ref(&module));
    let seed = engine
        .inventory_candidate(
            &empty,
            &[],
            &[(view_r, vec![module], pins)],
            Vec::new(),
            &empty,
        )
        .unwrap();
    engine.plan = seed.plan;
    engine.pinned = seed.pinned;
    engine.modules = seed.modules;
    engine.views.push(ProcessView::open(id_r, me).unwrap());
    let object = engine
        .modules
        .iter()
        .find(|module| module.scanned.view == id_r)
        .expect("the seed row commits")
        .object;
    // A live successor maps the same file before R exits.
    let id_l = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_l = ProcessView::open(id_l, me).unwrap();
    let mut live_module = overlay_module(key);
    live_module.view = id_l;
    let mut live_pins = overlay_view_pin(&live_module, 7501, OVERLAY_SHA, 1, false);
    record_scan_ownership(&mut live_pins, id_l, key, &live_module.path);
    live_pins.prove_scanned_entries_for_test(std::slice::from_ref(&live_module));
    let joined = engine
        .inventory_candidate(
            &empty,
            &[],
            &[(view_l, vec![live_module], live_pins)],
            Vec::new(),
            &empty,
        )
        .unwrap();
    engine.plan = joined.plan;
    engine.pinned = joined.pinned;
    engine.modules = joined.modules;
    engine.views.push(ProcessView::open(id_l, me).unwrap());
    // R exits; its row carries one tick, then drops as redundant
    // (the live row covers the same single-table shape).
    let exited = engine
        .inventory_candidate(&BTreeSet::from([id_r]), &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = exited.plan;
    engine.pinned = exited.pinned;
    engine.modules = exited.modules;
    engine.views.retain(|view| view.id() != id_r);
    engine.release_view_id(id_r);
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "the carrier rides its exit tick beside the live row"
    );
    engine.plan_rebuild_stable = true;
    let settled = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = settled.plan;
    engine.pinned = settled.pinned;
    engine.modules = settled.modules;
    assert!(
        engine.modules.iter().all(|module| {
            module.scanned.view != Engine::CARRIED_VIEW_ID || module.object != object
        }),
        "the redundant carrier drops"
    );
    assert!(
        engine
            .modules
            .iter()
            .any(|module| { module.scanned.view == id_l && module.object == object }),
        "the live row survives"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "the shared pin survives for the live row"
    );
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test, 0,
        "no pin reclaims while a live row maps the file"
    );
}

#[test]
fn carried_fix3_churn_and_replay_retirements_reclaim_pins() {
    // F5 path twins: moduleless churn beside a droppable carrier, and
    // a conservative replay over one, both retire the last row and
    // reclaim its carrier-only pin through their own assembly call.
    // Empty-churn phase: a rowless view exits beside the carrier.
    let (mut engine, object) = fix3_seed_carrier(932);
    let me = std::process::id();
    let id_b = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_b, me).unwrap());
    engine.plan_rebuild_stable = true;
    let churned = engine
        .inventory_candidate(
            &BTreeSet::from([id_b]),
            &[],
            &[],
            Vec::new(),
            &BTreeSet::new(),
        )
        .unwrap();
    engine.plan = churned.plan;
    engine.pinned = churned.pinned;
    engine.modules = churned.modules;
    engine.views.retain(|view| view.id() != id_b);
    engine.release_view_id(id_b);
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "empty churn retires the last row"
    );
    assert!(
        engine.pinned.summary(object).is_none(),
        "empty churn reclaims the carrier-only pin"
    );
    // Replay phase: a conservative replay over a riding carrier.
    let (mut engine, object) = fix3_seed_carrier(933);
    engine.owned_run_pid = Some(me);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();
    engine.replay_pending_conservative(&mut session, &mut additions, &mut pending);
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the replay retires the last row"
    );
    assert!(
        engine.pinned.summary(object).is_none(),
        "the replay reclaims the carrier-only pin"
    );
}

#[test]
fn carried_fix3_non_row_coowners_survive_carrier_detach() {
    // F5 co-owner guards: claims/raw aliases, selection claims,
    // tables and bindings, manifest fallbacks and prearm witnesses
    // each keep a rowless carrier-only pin. Each phase seeds a fresh
    // carrier, adds one co-owner kind, then runs the quiet detach
    // that would otherwise reclaim.
    let me = std::process::id();
    let detach_quietly = |engine: &mut Engine| {
        let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
        engine.plan_rebuild_stable = true;
        let quiet = engine
            .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
            .unwrap();
        engine.plan = quiet.plan;
        engine.pinned = quiet.pinned;
        engine.modules = quiet.modules;
    };
    // Claims + raw aliases: a rowless live view records ownership of
    // the carrier's file (claims and aliases together, as production
    // always files them).
    let (mut engine, object) = fix3_seed_carrier(934);
    let key = overlay_key(934);
    let id_c = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_c, me).unwrap());
    record_scan_ownership(&mut engine.pinned, id_c, key, OVERLAY_PATH);
    detach_quietly(&mut engine);
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the row still retires"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "claims/raw aliases keep the pin"
    );
    // Selection binding.
    let (mut engine, object) = fix3_seed_carrier(935);
    let id_v = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_v, me).unwrap());
    let context = LoaderContextId::view_owned(1).unwrap();
    engine.selection_bindings.insert(
        77,
        SelectionBindingFact {
            id: 77,
            context,
            view: ProcessViewId(id_v.0),
            object,
            file_offset: 0,
            hook_id: 0,
            abi: HookAbi::Interface,
            attached: true,
            retired: false,
            provider: plan::ModuleId(0),
            observed: false,
            coverage: SelectionCoverageState::Uncovered,
        },
    );
    detach_quietly(&mut engine);
    assert!(
        engine.pinned.summary(object).is_some(),
        "a selection binding keeps the pin"
    );
    // Selection claim + table.
    let (mut engine, object) = fix3_seed_carrier(936);
    let provider = engine
        .pinned
        .owned_timing_key(object)
        .expect("the carrier object has a timing key");
    let id_w = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_w, me).unwrap());
    engine.selection_claims.insert(
        SelectionClaimKey {
            binding_id: 1,
            view: id_w,
            context: 0,
            hook_owner: object,
            provider: provider.clone(),
            selected_object: object,
            table_file_offset: 0,
            version: SelectionVersionClass::V3_0,
            flags: 0,
            name: "C_Initialize",
            file_offset: 0,
        },
        SelectionClaim {
            target: plan::AttachKey {
                object,
                file_offset: 0,
            },
            object_path: OVERLAY_PATH.into(),
        },
    );
    engine.selection_tables.insert(
        SelectionTableKey {
            view: id_w,
            provider,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        },
        SelectionTableFact {
            object,
            file_offset: 0,
            targets: Vec::new(),
        },
    );
    detach_quietly(&mut engine);
    assert!(
        engine.pinned.summary(object).is_some(),
        "selection claims/tables keep the pin"
    );
    // Manifest fallback.
    let (mut engine, object) = fix3_seed_carrier(937);
    engine.counters.manifest_fallbacks.push(ManifestFallback {
        manifest: 0,
        object: 0,
        reason: ManifestStaleReason::IdentityMismatch,
        replacement: object,
        proof: BoundFallbackProof {
            module: object,
            tables: Vec::new(),
            required_targets: BTreeMap::new(),
        },
    });
    detach_quietly(&mut engine);
    assert!(
        engine.pinned.summary(object).is_some(),
        "a manifest fallback keeps the pin"
    );
    // Prearm witness.
    let (mut engine, object) = fix3_seed_carrier(938);
    let witness_pin =
        crate::discovery::identity::pin_of(&File::open("/dev/null").unwrap()).unwrap();
    engine.prearm_witness = Some(BTreeMap::from([(
        object,
        WitnessProof {
            verdict: crate::attach::prearm_witness::FileVerdict::Clear,
            active_ns: 0,
            scope_start_ns: None,
            walk_started_ns: 0,
            fd_dev: 0,
            fd_ino: 0,
            pin: witness_pin,
        },
    )]));
    detach_quietly(&mut engine);
    assert!(
        engine.pinned.summary(object).is_some(),
        "a prearm witness keeps the pin"
    );
}

#[test]
fn carried_fix4_table_coverage_requires_stable_offset() {
    // F2 identity: a live table covers a carrier table only with the
    // same stable file offset and at least the carrier's extension
    // evidence. Identical decoded content at a different offset is a
    // different table: retiring on it would drop the carrier's table
    // evidence and re-attribute its interface. Likewise a carrier
    // proof that extension is impossible is lost when a live table
    // without that proof covers.
    let key = overlay_key(970);
    let carrier = fix3_two_table_module(key, Some(0));
    // Same content, table A at a different offset: never covers.
    let mut live_moved = fix3_two_table_module(key, Some(0));
    live_moved.tables[0].file_offset = Some(0x5000);
    assert!(
        !super::carrier_covered_by_live(&carrier, &[&live_moved]),
        "identical content at a different offset never covers the carrier's table"
    );
    // Carrier proved extension impossible, live did not: never covers.
    let mut carrier_proven = fix3_two_table_module(key, Some(0));
    carrier_proven.tables[0].extension_impossible = true;
    let live_unproven = fix3_two_table_module(key, Some(0));
    assert!(
        !super::carrier_covered_by_live(&carrier_proven, &[&live_unproven]),
        "a live table without the carrier's extension proof never covers"
    );
    // Identity unavailable on exactly one side: fail closed.
    let mut live_mixed = fix3_two_table_module(key, Some(0));
    live_mixed.tables[0].file_offset = None;
    assert!(
        !super::carrier_covered_by_live(&carrier, &[&live_mixed]),
        "a table whose identity is unavailable on one side never covers"
    );
    // Controls: an identical table still covers; extra live
    // evidence never hurts; and two unattributable identical tables
    // cover (their publication is observably equivalent, so covering
    // is not an open verdict).
    let live_exact = fix3_two_table_module(key, Some(0));
    assert!(
        super::carrier_covered_by_live(&carrier, &[&live_exact]),
        "an identical table covers"
    );
    let mut live_proven = fix3_two_table_module(key, Some(0));
    live_proven.tables[0].extension_impossible = true;
    assert!(
        super::carrier_covered_by_live(&carrier, &[&live_proven]),
        "a live table with more extension evidence still covers"
    );
    let mut carrier_none = fix3_two_table_module(key, Some(0));
    let mut live_none = fix3_two_table_module(key, Some(0));
    carrier_none.tables[0].file_offset = None;
    carrier_none.tables[1].file_offset = None;
    live_none.tables[0].file_offset = None;
    live_none.tables[1].file_offset = None;
    assert!(
        super::carrier_covered_by_live(&carrier_none, &[&live_none]),
        "two unattributable identical tables cover"
    );
    // Superset: a live table preserving everything plus more still
    // covers (and pins argument order: swapping the compared tables
    // flips this verdict).
    let mut live_super = fix3_two_table_module(key, Some(0));
    live_super.tables[0].entries.push(ScannedEntry {
        name: "C_Extra",
        object: key,
        object_path: OVERLAY_PATH.into(),
        file_offset: 0x1200,
    });
    assert!(
        super::carrier_covered_by_live(&carrier, &[&live_super]),
        "a live table preserving a superset still covers"
    );
}

#[test]
fn carried_fix4_table_coverage_flags_are_asymmetric() {
    // F2 conjuncts: every table-cover conjunct beyond entries is
    // direction-sensitive. A carrier flag/evidence the live table
    // lacks keeps the carrier; extra live evidence never hurts.
    // This pins the conjuncts an argument swap or a dropped arm
    // would silently change under symmetric fixtures.
    let key = overlay_key(969);
    // live_return: carrier-proved, live-heuristic keeps; reversed covers.
    let mut carrier_live = fix3_two_table_module(key, Some(0));
    carrier_live.tables[0].live_return = true;
    let live_heuristic = fix3_two_table_module(key, Some(0));
    assert!(
        !super::carrier_covered_by_live(&carrier_live, &[&live_heuristic]),
        "a live table without the carrier's live-return proof never covers"
    );
    let carrier_heuristic = fix3_two_table_module(key, Some(0));
    let mut live_proved = fix3_two_table_module(key, Some(0));
    live_proved.tables[0].live_return = true;
    assert!(
        super::carrier_covered_by_live(&carrier_heuristic, &[&live_proved]),
        "a live table with more live-return evidence still covers"
    );
    // manifest_supported: same asymmetry.
    let mut carrier_manifest = fix3_two_table_module(key, Some(0));
    carrier_manifest.tables[0].manifest_supported = true;
    assert!(
        !super::carrier_covered_by_live(&carrier_manifest, &[&live_heuristic]),
        "a live table without the carrier's manifest proof never covers"
    );
    let mut live_manifest = fix3_two_table_module(key, Some(0));
    live_manifest.tables[0].manifest_supported = true;
    assert!(
        super::carrier_covered_by_live(&carrier_heuristic, &[&live_manifest]),
        "a live table with more manifest evidence still covers"
    );
    // NULL holes: a carrier hole the live table lacks keeps.
    let mut carrier_hole = fix3_two_table_module(key, Some(0));
    carrier_hole.tables[0].null_entries = vec!["C_GetSlotList"];
    assert!(
        !super::carrier_covered_by_live(&carrier_hole, &[&live_heuristic]),
        "a live table without the carrier's NULL hole never covers"
    );
    // Unpinned records: same asymmetry.
    let mut carrier_unpinned = fix3_two_table_module(key, Some(0));
    carrier_unpinned.tables[0].unpinned = vec![Skipped {
        subject: "C_GetSlotList".into(),
        reason: "fixture unpinned record".into(),
    }];
    assert!(
        !super::carrier_covered_by_live(&carrier_unpinned, &[&live_heuristic]),
        "a live table without the carrier's unpinned record never covers"
    );
}

#[test]
fn carried_fix4_normalize_keeps_unproven_table_identity() {
    // F2 normalize integration: a riding carrier drops on an exact
    // table link but rides when the live row's table sits at a
    // different offset or lacks the carrier's extension proof, even
    // though the decoded contents match. Absence stays false so only
    // coverage decides.
    let key = overlay_key(971);
    for (name, shape, expect_drop) in [
        ("exact", 0u8, true),
        ("moved-offset", 1, false),
        ("lost-extension", 2, false),
    ]
    .iter()
    {
        let mut carrier = fix3_two_table_module(key, Some(0));
        if *shape == 2 {
            carrier.tables[0].extension_impossible = true;
        }
        carrier.view = Engine::CARRIED_VIEW_ID;
        let live_view = ProcessViewId(720 + (*shape as u32));
        let mut live = fix3_two_table_module(key, Some(0));
        if *shape == 1 {
            live.tables[0].file_offset = Some(0x5000);
        }
        live.view = live_view;
        let mut pins = overlay_view_pin(&live, 7600 + (*shape as u64), OVERLAY_SHA, 1, false);
        record_scan_ownership(&mut pins, live_view, key, &live.path);
        let mut raw = vec![carrier, live];
        let mut dropped = 0u64;
        super::normalize_carried_modules(
            &mut raw,
            &pins,
            &BTreeSet::new(),
            &BTreeSet::from([live_view]),
            false,
            &mut dropped,
        );
        let kept = raw
            .iter()
            .any(|module| module.view == Engine::CARRIED_VIEW_ID);
        assert_eq!(
            !kept, *expect_drop,
            "normalize {name} link: carrier drops={expect_drop}"
        );
    }
}

/// Seeds a two-table carrier for the fix4 mirror twins: the seed row
/// commits, its view exits under a pending mark, and the carrier
/// commits. Returns the engine and the carried object.
fn fix4_seed_two_table_carrier(key_minor: u64, mark: u32) -> (Engine, PinnedObjectId) {
    let key = overlay_key(key_minor);
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let id_r = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_r = ProcessView::open(id_r, me).unwrap();
    let mut seed_module = fix3_two_table_module(key, Some(0));
    seed_module.view = id_r;
    let mut seed_pins = overlay_view_pin(&seed_module, 7200 + key_minor, OVERLAY_SHA, 1, false);
    record_scan_ownership(&mut seed_pins, id_r, key, &seed_module.path);
    seed_pins.prove_scanned_entries_for_test(std::slice::from_ref(&seed_module));
    let seed = engine
        .inventory_candidate(
            &empty,
            &[],
            &[(view_r, vec![seed_module], seed_pins)],
            Vec::new(),
            &empty,
        )
        .unwrap();
    engine.plan = seed.plan;
    engine.pinned = seed.pinned;
    engine.modules = seed.modules;
    engine.views.push(ProcessView::open(id_r, me).unwrap());
    let object = engine
        .modules
        .iter()
        .find(|module| module.scanned.view == id_r)
        .expect("the seed row commits")
        .object;
    engine.newcomer_first_seen.insert(mark, None);
    let removed = engine
        .inventory_candidate(&BTreeSet::from([id_r]), &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = removed.plan;
    engine.pinned = removed.pinned;
    engine.modules = removed.modules;
    engine.views.retain(|view| view.id() != id_r);
    engine.release_view_id(id_r);
    engine.newcomer_first_seen.remove(&mark);
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "the carrier commits under the pending mark"
    );
    (engine, object)
}

/// Admits a live successor mapping `key`'s file with `shape` applied
/// to its two-table module, and commits. Returns the live view.
fn fix4_admit_two_table_successor(
    engine: &mut Engine,
    key: ObjectKey,
    shape: impl FnOnce(&mut ScannedModule),
) -> ProcessViewId {
    let me = std::process::id();
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let id_l = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_l = ProcessView::open(id_l, me).unwrap();
    let mut live_module = fix3_two_table_module(key, Some(0));
    shape(&mut live_module);
    live_module.view = id_l;
    let mut live_pins =
        overlay_view_pin(&live_module, 7210 + key.device.minor, OVERLAY_SHA, 1, false);
    record_scan_ownership(&mut live_pins, id_l, key, &live_module.path);
    live_pins.prove_scanned_entries_for_test(std::slice::from_ref(&live_module));
    let admitted = engine
        .inventory_candidate(
            &empty,
            &[],
            &[(view_l, vec![live_module], live_pins)],
            Vec::new(),
            &empty,
        )
        .unwrap();
    engine.plan = admitted.plan;
    engine.pinned = admitted.pinned;
    engine.modules = admitted.modules;
    engine.views.push(ProcessView::open(id_l, me).unwrap());
    id_l
}

#[test]
fn carried_fix4_quiet_mirror_keeps_redirected_table_offset() {
    // F2 mirror integration: a live successor whose table A decodes
    // identically but at a different offset does not retire the
    // carrier (normalize keeps it through the commit, and the quiet
    // mirror agrees); restoring the committed offset flips the
    // mirror to droppable.
    let key = overlay_key(972);
    let (mut engine, object) = fix4_seed_two_table_carrier(972, 424310);
    let id_l = fix4_admit_two_table_successor(&mut engine, key, |live| {
        live.tables[0].file_offset = Some(0x5000);
    });
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "the offset-moved carrier survives the commit (normalize keeps it)"
    );
    assert!(
        !engine.carried_rows_would_drop(),
        "the quiet mirror keeps an offset-moved table link"
    );
    for module in engine.modules.iter_mut() {
        if module.scanned.view == id_l {
            module.scanned.tables[0].file_offset = Some(0);
        }
    }
    engine.refresh_held_view_ids();
    assert!(
        engine.carried_rows_would_drop(),
        "an exact committed offset reads as droppable"
    );
}

#[test]
fn carried_fix4_quiet_mirror_keeps_unproven_extension() {
    // F2 mirror integration: a live successor whose table A decodes
    // identically but without the carrier's extension-impossible
    // proof does not retire the carrier; restoring the proof on the
    // committed live row flips the mirror to droppable.
    let key = overlay_key(973);
    let (mut engine, object) = fix4_seed_two_table_carrier(973, 424311);
    for module in engine.modules.iter_mut() {
        if module.scanned.view == Engine::CARRIED_VIEW_ID {
            module.scanned.tables[0].extension_impossible = true;
        }
    }
    let id_l = fix4_admit_two_table_successor(&mut engine, key, |_live| {});
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == Engine::CARRIED_VIEW_ID && module.object == object
        }),
        "the extension-proven carrier survives the commit (normalize keeps it)"
    );
    assert!(
        !engine.carried_rows_would_drop(),
        "the quiet mirror keeps a table link that lost the extension proof"
    );
    for module in engine.modules.iter_mut() {
        if module.scanned.view == id_l {
            module.scanned.tables[0].extension_impossible = true;
        }
    }
    engine.refresh_held_view_ids();
    assert!(
        engine.carried_rows_would_drop(),
        "a matching committed extension proof reads as droppable"
    );
}

#[test]
fn carried_fix4_deferred_drain_uses_proving_store() {
    // F1 custody: a deferred watch proof carries its proving scan's
    // file custody, not a bare store-local id. Draining against a
    // different store whose colliding numeric ids name different
    // files stages the proven file and never the drain store's
    // colliding file.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    use std::os::unix::fs::MetadataExt as _;
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let mut pins = PinnedObjects::empty();
    for index in 0..PROOFS {
        let backing = dir.path().join(format!("libprov{index}.so"));
        std::fs::write(&backing, format!("p11scope-fixture:provider-bytes-{index}"))
            .expect("write backing");
        let sha = format!("{:064x}", 0xdf0000u64 + index as u64);
        let skips = pins.absorb(real_scan_pin(&backing, None, 400, &sha));
        assert!(skips.is_empty(), "{skips:?}");
    }
    let objects: Vec<PinnedObjectId> = pins.pinned().map(|pin| pin.id).collect();
    assert_eq!(objects.len(), PROOFS, "every backing file pins distinctly");
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 19,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a watch member");
    let member = child.id();
    let watch_id = engine.allocate_view_id().unwrap();
    let watch_view = ProcessView::open(watch_id, member).expect("the member view opens");
    let mut proofs = Vec::with_capacity(PROOFS);
    for (index, object) in objects.iter().enumerate() {
        let key = overlay_key(9800 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = watch_id;
        proofs.push(OwnedLearnProof {
            view: watch_id,
            path: dir
                .path()
                .join(format!("libprov{index}.so"))
                .to_string_lossy()
                .into_owned(),
            object: *object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], Some(&watch_view));
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        super::GRAPH_STRIDE as u64,
        "the batch attempts one stride"
    );
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out proof queues with its pin"
    );
    child.kill().expect("the member exits");
    child.wait().expect("the member reaps");
    // A different store whose fresh numeric ids collide with the
    // proving scan's but name different files.
    let dir_b = tempfile::tempdir().expect("colliding backing dir");
    let mut store_b = PinnedObjects::empty();
    for index in 0..PROOFS {
        let backing = dir_b.path().join(format!("other{index}.so"));
        std::fs::write(
            &backing,
            format!("p11scope-fixture:unrelated-bytes-{index}"),
        )
        .expect("write backing");
        let sha = format!("{:064x}", 0xbe0000u64 + index as u64);
        let skips = store_b.absorb(real_scan_pin(&backing, None, 400, &sha));
        assert!(skips.is_empty(), "{skips:?}");
    }
    let colliding: BTreeSet<(u64, u64)> = store_b
        .pinned()
        .map(|pin| {
            let file = store_b.file_for(pin.id).expect("a colliding file");
            let meta = file.metadata().expect("stat the colliding file");
            (meta.dev(), meta.ino())
        })
        .collect();
    assert_eq!(colliding.len(), PROOFS, "every colliding file is distinct");
    // Cap space for the drain: the batch's pendings already proved
    // their files, so the drain stages proof 65 observably.
    engine.pending_learned.clear();
    engine.learn_owned_proofs_with_views(&mut store_b, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain settles the backlog"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "proof 65 attempts exactly once, on the drain"
    );
    assert_eq!(engine.pending_learned.len(), 1, "the drain stages proof 65");
    let staged = &engine.pending_learned[0];
    assert!(
        !colliding.contains(&(staged.dev, staged.ino)),
        "the drain never stages the drain store's colliding file: {:?}",
        (staged.dev, staged.ino),
    );
    let right = std::fs::metadata(dir.path().join(format!("libprov{}.so", PROOFS - 1)))
        .expect("stat the proven backing");
    assert_eq!(
        (staged.dev, staged.ino),
        (right.dev(), right.ino()),
        "the drain stages the proven file"
    );
}

#[test]
fn carried_fix4_deferred_drain_harvests_from_proving_store() {
    // F1 harvest: a deferred proof's decoded tables harvest from the
    // proving scan's pins (absorbed and aliased under the reserved
    // run-learned owner), and its file stages, even when the drain
    // store is empty. Neither half consults the drain store's
    // unrelated ids.
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 27,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a watch member");
    let member = child.id();
    let watch_id = engine.allocate_view_id().unwrap();
    let watch_view = ProcessView::open(watch_id, member).expect("the member view opens");
    // One scan store for all proofs; only proof 65 keeps its
    // decoded table, so the drain's harvest is exactly observable.
    let mut pins = PinnedObjects::empty();
    let mut proofs = Vec::with_capacity(PROOFS);
    for index in 0..PROOFS {
        let key = overlay_key(9860 + index as u64);
        let mut module = overlay_module(key);
        module.view = watch_id;
        let mpins = overlay_view_pin(&module, 8300 + index as u64, OVERLAY_SHA, 1, false);
        let skips = pins.absorb(mpins);
        assert!(skips.is_empty(), "{skips:?}");
        let object = pins
            .id_for_scanned(&module, module.key, &module.path)
            .expect("the scan resolves its own module");
        if index + 1 < PROOFS {
            module.tables.clear();
            module.interfaces.clear();
            module.exports.clear();
        }
        proofs.push(OwnedLearnProof {
            view: watch_id,
            path: module.path.clone(),
            object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], Some(&watch_view));
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out proof queues with its pin"
    );
    child.kill().expect("the member exits");
    child.wait().expect("the member reaps");
    // Cap space for the drain: the batch's single /dev/null staging
    // drops so proof 65's own staging is observable.
    engine.pending_learned.clear();
    let mut scratch = PinnedObjects::empty();
    engine.learn_owned_proofs_with_views(&mut scratch, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain settles the backlog"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "proof 65 attempts exactly once, on the drain"
    );
    assert_eq!(
        engine.pending_learned.len(),
        1,
        "proof 65's file stages from the proving store"
    );
    assert_eq!(
        engine.run_learned_modules.len(),
        1,
        "proof 65's tables harvest exactly once"
    );
    // The union joins the committed set under the reserved owner with
    // its bindable pins: later applies resolve the same objects.
    let harvested = &proofs[PROOFS - 1].module;
    assert!(
        engine
            .pinned
            .module_aliased_under(harvested, Engine::RUN_LEARNED_VIEW_ID),
        "the harvested tables keep their bindable pins across the proving view's exit"
    );
}

#[test]
fn carried_fix4_staged_key_ignores_store_local_ids() {
    // F1 key: the already-staged proof set keys on stable file
    // identity (digest plus the raw observation), never on a
    // store-local numeric id. The same file re-proven under a
    // different id skips duplicate file work, while a different file
    // under a colliding id never falsely skips.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let backing_f = dir.path().join("libsame.so");
    std::fs::write(&backing_f, "p11scope-fixture:shared-provider-bytes").expect("write backing");
    let backing_d = dir.path().join("libdecoy.so");
    std::fs::write(&backing_d, "p11scope-fixture:decoy-bytes").expect("write backing");
    let backing_g = dir.path().join("libother.so");
    std::fs::write(&backing_g, "p11scope-fixture:other-provider-bytes").expect("write backing");
    let sha_f = "f1".repeat(32);
    let sha_d = "dc".repeat(32);
    let sha_g = "07".repeat(32);
    let mut store_a = real_scan_pin(&backing_f, None, 400, &sha_f);
    let pin_f = store_a.pinned().next().expect("one pin");
    assert_eq!(pin_f.id, PinnedObjectId(0), "store A mints id 0");
    let mut store_b = PinnedObjects::empty();
    assert!(
        store_b
            .absorb(real_scan_pin(&backing_d, None, 400, &sha_d))
            .is_empty()
    );
    assert!(
        store_b
            .absorb(real_scan_pin(&backing_f, None, 400, &sha_f))
            .is_empty()
    );
    let id_f_in_b = store_b
        .pinned()
        .find(|pin| pin.sha256 == sha_f)
        .expect("the same file pins in store B")
        .id;
    assert_eq!(
        id_f_in_b,
        PinnedObjectId(1),
        "store B names the same file id 1"
    );
    let mut store_c = real_scan_pin(&backing_g, None, 400, &sha_g);
    assert_eq!(
        store_c.pinned().next().expect("one pin").id,
        PinnedObjectId(0),
        "store C collides with store A's id 0 for a different file"
    );
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 21,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(424242);
    engine.next_view_id = 100;
    engine
        .views
        .push(ProcessView::open(ProcessViewId(0), me).expect("own view opens"));
    let mut module = super::owned_proof_module_without_tables(pin_f.key);
    module.view = ProcessViewId(0);
    // Same file, store A id 0: stages.
    let proof_a = OwnedLearnProof {
        view: ProcessViewId(0),
        path: backing_f.to_string_lossy().into_owned(),
        object: PinnedObjectId(0),
        loader_exe: None,
        loader_unknown_reason: None,
        module: module.clone(),
    };
    engine.learn_owned_proofs_with_views(&mut store_a, &[proof_a], &[], None);
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 1,
        "the first proof attempts"
    );
    assert_eq!(
        engine.owned_learn_file_probes_for_test, 1,
        "the first proof reaches its file"
    );
    assert_eq!(engine.pending_learned.len(), 1, "the first proof stages");
    // Same file, same observation, store B id 1: skips before any
    // file work (no duplicate dup/stat across stores).
    let proof_b = OwnedLearnProof {
        view: ProcessViewId(0),
        path: backing_f.to_string_lossy().into_owned(),
        object: id_f_in_b,
        loader_exe: None,
        loader_unknown_reason: None,
        module: module.clone(),
    };
    engine.learn_owned_proofs_with_views(&mut store_b, &[proof_b], &[], None);
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 1,
        "the re-proven file attempts nothing more"
    );
    assert_eq!(
        engine.owned_learn_file_probes_for_test, 1,
        "the re-proven file repeats no file work"
    );
    assert_eq!(
        engine.pending_learned.len(),
        1,
        "the re-proven file stages nothing more"
    );
    // Different file under the colliding id 0 with the same raw
    // observation (the overlay-alias shape): never falsely skips.
    let proof_c = OwnedLearnProof {
        view: ProcessViewId(0),
        path: backing_g.to_string_lossy().into_owned(),
        object: PinnedObjectId(0),
        loader_exe: None,
        loader_unknown_reason: None,
        module,
    };
    engine.learn_owned_proofs_with_views(&mut store_c, &[proof_c], &[], None);
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 2,
        "the colliding different file attempts"
    );
    assert_eq!(
        engine.owned_learn_file_probes_for_test, 2,
        "the colliding different file reaches its own file"
    );
    assert_eq!(
        engine.pending_learned.len(),
        2,
        "the colliding different file stages"
    );
}

#[test]
fn carried_fix4_deferred_drop_uses_proving_generation() {
    // F1 generation: the backlog drain drops a deferred proof as a
    // direct-child proof only when the proving generation was the
    // owned child, never when the proving view's recycled numeric id
    // now names the owned child. The drained proof still names the
    // dead proving generation (finite unknown) through its stashed
    // pin, never the recycled id's new exe.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let mut pins = PinnedObjects::empty();
    for index in 0..PROOFS {
        let backing = dir.path().join(format!("libprov{index}.so"));
        std::fs::write(&backing, format!("p11scope-fixture:provider-bytes-{index}"))
            .expect("write backing");
        let sha = format!("{:064x}", 0xd60000u64 + index as u64);
        let skips = pins.absorb(real_scan_pin(&backing, None, 400, &sha));
        assert!(skips.is_empty(), "{skips:?}");
    }
    let objects: Vec<PinnedObjectId> = pins.pinned().map(|pin| pin.id).collect();
    assert_eq!(objects.len(), PROOFS, "every backing file pins distinctly");
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 25,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a watch member");
    let member = child.id();
    let watch_id = engine.allocate_view_id().unwrap();
    let watch_view = ProcessView::open(watch_id, member).expect("the member view opens");
    let mut proofs = Vec::with_capacity(PROOFS);
    for (index, object) in objects.iter().enumerate() {
        let key = overlay_key(9820 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = watch_id;
        proofs.push(OwnedLearnProof {
            view: watch_id,
            path: dir
                .path()
                .join(format!("libprov{index}.so"))
                .to_string_lossy()
                .into_owned(),
            object: *object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], Some(&watch_view));
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out proof queues with its pin"
    );
    child.kill().expect("the member exits");
    child.wait().expect("the member reaps");
    // The watch id recycles to the owned child itself before the
    // drain: the numeric id now names the direct child, but the
    // proving generation was the exited member.
    engine.release_view_id(watch_id);
    let reused = engine.allocate_view_id_for_newcomer(me).unwrap();
    assert_eq!(
        reused, watch_id,
        "the freed watch id recycles to the next admission"
    );
    engine
        .views
        .push(ProcessView::open(reused, me).expect("the owned child view opens"));
    engine.pending_learned.clear();
    engine.learn_owned_proofs_with_views(&mut pins, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain settles the backlog"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "proof 65 attempts on the drain (a recycled id never drops it)"
    );
    assert_eq!(
        engine.pending_learned.len(),
        1,
        "proof 65 stages on the drain"
    );
    let staged = &engine.pending_learned[0];
    assert!(
        staged.loader_exe.is_none() && staged.loader_unknown_reason.is_some(),
        "the drained proof names the dead proving generation, never the recycled id's exe: {:?} {:?}",
        staged.loader_exe,
        staged.loader_unknown_reason,
    );
}

#[test]
fn carried_fix4_deferred_gap_uses_proving_retention() {
    // F1 retention: a deferred proof stages with the proving view's
    // retention taken at defer time (a transient watch view is never
    // retained), never recomputed from the recycled numeric id. A
    // transient prover's staging owes the first-use row even when
    // its id now names a retained live view.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let mut pins = PinnedObjects::empty();
    for index in 0..PROOFS {
        let backing = dir.path().join(format!("libprov{index}.so"));
        std::fs::write(&backing, format!("p11scope-fixture:provider-bytes-{index}"))
            .expect("write backing");
        let sha = format!("{:064x}", 0xd70000u64 + index as u64);
        let skips = pins.absorb(real_scan_pin(&backing, None, 400, &sha));
        assert!(skips.is_empty(), "{skips:?}");
    }
    let objects: Vec<PinnedObjectId> = pins.pinned().map(|pin| pin.id).collect();
    assert_eq!(objects.len(), PROOFS, "every backing file pins distinctly");
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 26,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a watch member");
    let member = child.id();
    let watch_id = engine.allocate_view_id().unwrap();
    let watch_view = ProcessView::open(watch_id, member).expect("the member view opens");
    let mut proofs = Vec::with_capacity(PROOFS);
    for (index, object) in objects.iter().enumerate() {
        let key = overlay_key(9830 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = watch_id;
        proofs.push(OwnedLearnProof {
            view: watch_id,
            path: dir
                .path()
                .join(format!("libprov{index}.so"))
                .to_string_lossy()
                .into_owned(),
            object: *object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], Some(&watch_view));
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out proof queues with its pin"
    );
    child.kill().expect("the member exits");
    child.wait().expect("the member reaps");
    // The watch id recycles to a live retained view (not the owned
    // child, which would take the direct-child arm instead).
    let mut sleeper = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a live successor");
    let successor = sleeper.id();
    engine.release_view_id(watch_id);
    let reused = engine.allocate_view_id_for_newcomer(successor).unwrap();
    assert_eq!(
        reused, watch_id,
        "the freed watch id recycles to the next admission"
    );
    engine
        .views
        .push(ProcessView::open(reused, successor).expect("the successor view opens"));
    engine.pending_learned.clear();
    engine.learn_owned_proofs_with_views(&mut pins, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain settles the backlog"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "proof 65 attempts on the drain"
    );
    assert_eq!(
        engine.pending_learned.len(),
        1,
        "proof 65 stages on the drain"
    );
    assert!(
        !engine.pending_learned[0].proving_retained,
        "a transient prover's staging owes the first-use row despite the recycled id"
    );
    sleeper.kill().expect("the successor exits");
    sleeper.wait().expect("the successor reaps");
}

#[test]
fn carried_fix4_stale_newcomer_queues_paced_proofs() {
    // F4 continuation: apply-path proofs whose rows never commit
    // queue with stable custody instead of vanishing. A short-lived
    // newcomer mapping 65 providers exits before its apply commits:
    // the apply goes stale, the 65th proof queues, and a later drain
    // with no scan store at all still settles it.
    const MODULES: usize = super::GRAPH_STRIDE + 1;
    let me = std::process::id();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a short-lived newcomer");
    let newcomer = child.id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 22,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let id_v = engine.allocate_view_id_for_newcomer(newcomer).unwrap();
    let view_v = ProcessView::open(id_v, newcomer).unwrap();
    let mut modules = Vec::with_capacity(MODULES);
    let mut pins = PinnedObjects::empty();
    for index in 0..MODULES {
        let key = overlay_key(9900 + index as u64);
        let mut module = overlay_module(key);
        module.view = id_v;
        let mpins = overlay_view_pin(&module, 7900 + index as u64, OVERLAY_SHA, 1, false);
        let skips = pins.absorb(mpins);
        assert!(skips.is_empty(), "{skips:?}");
        record_scan_ownership(&mut pins, id_v, key, &module.path);
        pins.prove_scanned_entries_for_test(std::slice::from_ref(&module));
        modules.push(module);
    }
    // The newcomer array stays caller-owned so the dead view still
    // borrows for the apply's extra views after the exit.
    let new_views = [(view_v, modules, pins)];
    let candidate = engine
        .inventory_candidate(&empty, &[], &new_views, Vec::new(), &empty)
        .unwrap();
    child.kill().expect("the newcomer exits");
    child.wait().expect("the newcomer reaps");
    let mut additions = true;
    let outcome = engine
        .apply_candidate(
            &mut ScriptedSession::default(),
            candidate,
            &mut additions,
            false,
            &[&new_views[0].0],
        )
        .unwrap();
    assert!(
        outcome.stale_views.contains(&id_v),
        "the exited newcomer makes the apply stale"
    );
    assert!(
        engine
            .modules
            .iter()
            .all(|module| module.scanned.view != id_v),
        "the stale apply commits no newcomer row"
    );
    assert_eq!(
        engine.owned_learn_proofs_built_for_test, MODULES as u64,
        "the stale apply still builds every eligible shell"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        super::GRAPH_STRIDE as u64,
        "the stale apply attempts one stride"
    );
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out newcomer proof queues (its rows never commit)"
    );
    // A later drain with no scan store at all still settles it: the
    // queued proof carries its own custody.
    let mut scratch = PinnedObjects::empty();
    engine.learn_owned_proofs_with_views(&mut scratch, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain settles the queued newcomer proof"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "proof 65 attempts exactly once, on the drain"
    );
}

#[test]
fn carried_fix4_preflight_failure_queues_paced_proofs() {
    // F4 continuation: the same queueing holds when a target
    // preflight (not staleness) refuses the apply after learning
    // paced out: the newcomer rows never commit, so the paced-out
    // proof queues instead of vanishing.
    const MODULES: usize = super::GRAPH_STRIDE + 1;
    let me = std::process::id();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a newcomer");
    let newcomer = child.id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 23,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let id_v = engine.allocate_view_id_for_newcomer(newcomer).unwrap();
    let view_v = ProcessView::open(id_v, newcomer).unwrap();
    let mut modules = Vec::with_capacity(MODULES);
    let mut pins = PinnedObjects::empty();
    for index in 0..MODULES {
        let key = overlay_key(9950 + index as u64);
        let mut module = overlay_module(key);
        module.view = id_v;
        let mpins = overlay_view_pin(&module, 7950 + index as u64, OVERLAY_SHA, 1, false);
        let skips = pins.absorb(mpins);
        assert!(skips.is_empty(), "{skips:?}");
        record_scan_ownership(&mut pins, id_v, key, &module.path);
        pins.prove_scanned_entries_for_test(std::slice::from_ref(&module));
        modules.push(module);
    }
    let new_views = [(view_v, modules, pins)];
    let candidate = engine
        .inventory_candidate(&empty, &[], &new_views, Vec::new(), &empty)
        .unwrap();
    let mut additions = true;
    let outcome = engine
        .apply_candidate(
            &mut ScriptedSession::refusing_preflight(),
            candidate,
            &mut additions,
            false,
            &[&new_views[0].0],
        )
        .unwrap();
    assert!(
        outcome.stale_views.is_empty(),
        "the live newcomer keeps the apply current"
    );
    assert!(
        engine
            .modules
            .iter()
            .all(|module| module.scanned.view != id_v),
        "the refused apply commits no newcomer row"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        super::GRAPH_STRIDE as u64,
        "the refused apply attempts one stride"
    );
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out newcomer proof queues (its rows never commit)"
    );
    child.kill().expect("the newcomer exits");
    child.wait().expect("the newcomer reaps");
}

#[test]
fn carried_fix4_paced_proof_without_prover_refuses_loudly() {
    // F4 accounting: a paced-out proof whose proving view is gone
    // from committed and newcomer views (so no pin can carry it)
    // refuses loudly with counted loss and a named gap instead of
    // vanishing silently past the stride.
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 28,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let mut pins = PinnedObjects::empty();
    let mut proofs = Vec::with_capacity(PROOFS);
    for index in 0..PROOFS {
        let key = overlay_key(9870 + index as u64);
        let mut module = overlay_module(key);
        module.view = ProcessViewId(300 + index as u32);
        let mpins = overlay_view_pin(&module, 8310 + index as u64, OVERLAY_SHA, 1, false);
        let skips = pins.absorb(mpins);
        assert!(skips.is_empty(), "{skips:?}");
        let object = pins
            .id_for_scanned(&module, module.key, &module.path)
            .expect("the scan resolves its own module");
        proofs.push(OwnedLearnProof {
            view: ProcessViewId(300 + index as u32),
            path: module.path.clone(),
            object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    // No committed or newcomer view proves anything: all 65 views
    // are gone, so every proof paces out without custody.
    let loss_before = engine.learned_event_loss_for_test();
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], None);
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        super::GRAPH_STRIDE as u64,
        "the batch attempts one stride"
    );
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "a viewless proof queues nowhere"
    );
    assert_eq!(
        engine.learned_event_loss_for_test(),
        loss_before + 1,
        "the paced-out viewless proof refuses with counted loss"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.reason.contains("proving view is gone") }),
        "the refusal names the gone prover: {:?}",
        engine.counters.object_skips,
    );
}

#[test]
fn carried_fix4_shutdown_drains_owned_backlog() {
    // F4 terminal: capture end settles the watch backlog instead of
    // dropping it silently. Proof 65 (a real provider .so, so the
    // end-of-capture flush stages it for real) queues past the
    // stride, its member exits, and shutdown drains it: the file
    // stages with its honest first-use row.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let c = dir.path().join("prompt.c");
    let so = dir.path().join(format!("libprov{}.so", PROOFS - 1));
    std::fs::write(
        &c,
        "unsigned long C_GetFunctionList(void **out){ (void)out; return 5; }\n",
    )
    .expect("write prompt source");
    assert!(
        std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&so)
            .arg(&c)
            .status()
            .expect("run gcc")
            .success(),
        "the prompt fixture must compile"
    );
    let mut pins = PinnedObjects::empty();
    for index in 0..PROOFS {
        let backing = dir.path().join(format!("libprov{index}.so"));
        if index + 1 < PROOFS {
            std::fs::write(&backing, format!("p11scope-fixture:provider-bytes-{index}"))
                .expect("write backing");
        }
        let sha = format!("{:064x}", 0xd80000u64 + index as u64);
        let skips = pins.absorb(real_scan_pin(&backing, None, 400, &sha));
        assert!(skips.is_empty(), "{skips:?}");
    }
    let objects: Vec<PinnedObjectId> = pins.pinned().map(|pin| pin.id).collect();
    assert_eq!(objects.len(), PROOFS, "every backing file pins distinctly");
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 24,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a watch member");
    let member = child.id();
    let watch_id = engine.allocate_view_id().unwrap();
    let watch_view = ProcessView::open(watch_id, member).expect("the member view opens");
    let mut proofs = Vec::with_capacity(PROOFS);
    for (index, object) in objects.iter().enumerate() {
        let key = overlay_key(9980 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = watch_id;
        proofs.push(OwnedLearnProof {
            view: watch_id,
            path: dir
                .path()
                .join(format!("libprov{index}.so"))
                .to_string_lossy()
                .into_owned(),
            object: *object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], Some(&watch_view));
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out proof queues with its pin"
    );
    child.kill().expect("the member exits");
    child.wait().expect("the member reaps");
    // The batch's pendings already proved their files; the shutdown
    // drain stages proof 65 into the end-of-capture flush.
    engine.pending_learned.clear();
    engine.shutdown_file_learning();
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "capture end settles the watch backlog"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "proof 65 attempts exactly once, at capture end"
    );
    assert_eq!(
        engine.learned_staged_files_for_test(),
        1,
        "proof 65's provider stages at capture end"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.reason == crate::render::LEARNED_FIRST_RUN_REASON }),
        "the transient prover's staging files its honest first-use row: {:?}",
        engine.counters.object_skips,
    );
}

#[test]
fn carried_fix4_carrier_retirement_paces_sixty_four_per_assembly() {
    // F5 pacing: one assembly retires at most one stride of carriers,
    // however many accumulated while absence was unproven. 65
    // distinct-file carriers retire over two ticks (64, then the
    // last), the riding carrier keeps its pin, the quiet mirror
    // stays off the fast path until the last drops, and nothing
    // resurrects.
    const CARRIERS: usize = super::GRAPH_STRIDE + 1;
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let id_v = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_v = ProcessView::open(id_v, me).unwrap();
    let mut modules = Vec::with_capacity(CARRIERS);
    let mut pins = PinnedObjects::empty();
    for index in 0..CARRIERS {
        let key = overlay_key(9130 + index as u64);
        let mut module = overlay_module(key);
        module.view = id_v;
        let mpins = overlay_view_pin(&module, 8100 + index as u64, OVERLAY_SHA, 1, false);
        let skips = pins.absorb(mpins);
        assert!(skips.is_empty(), "{skips:?}");
        record_scan_ownership(&mut pins, id_v, key, &module.path);
        pins.prove_scanned_entries_for_test(std::slice::from_ref(&module));
        modules.push(module);
    }
    let seed = engine
        .inventory_candidate(&empty, &[], &[(view_v, modules, pins)], Vec::new(), &empty)
        .unwrap();
    engine.plan = seed.plan;
    engine.pinned = seed.pinned;
    engine.modules = seed.modules;
    engine.views.push(ProcessView::open(id_v, me).unwrap());
    assert_eq!(engine.modules.len(), CARRIERS, "all carriers seed");
    // Exit: all 65 ride as newly carried (no retirement on the exit
    // tick itself).
    let exited = engine
        .inventory_candidate(&BTreeSet::from([id_v]), &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = exited.plan;
    engine.pinned = exited.pinned;
    engine.modules = exited.modules;
    engine.views.retain(|view| view.id() != id_v);
    engine.release_view_id(id_v);
    assert_eq!(
        engine
            .modules
            .iter()
            .filter(|module| module.scanned.view == Engine::CARRIED_VIEW_ID)
            .count(),
        CARRIERS,
        "all carriers ride their exit tick"
    );
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test, 0,
        "no pin reclaims on the exit tick"
    );
    let objects: BTreeSet<PinnedObjectId> =
        engine.modules.iter().map(|module| module.object).collect();
    assert_eq!(objects.len(), CARRIERS, "distinct files pin distinctly");
    // Weak shares of every carrier file (downgraded without cloning,
    // so the handles themselves keep nothing alive): reclaim must
    // drop the last strong share of each retired file.
    let weaks: Vec<std::sync::Weak<std::fs::File>> = objects
        .iter()
        .map(|id| {
            engine
                .pinned
                .weak_file_for_test(*id)
                .expect("every carrier file shares")
        })
        .collect();
    // Tick 1: one stride retires, one rides.
    engine.plan_rebuild_stable = true;
    let tick1 = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick1.plan;
    engine.pinned = tick1.pinned;
    engine.modules = tick1.modules;
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test,
        super::GRAPH_STRIDE as u64,
        "one assembly reclaims one stride"
    );
    assert_eq!(
        weaks.iter().filter(|weak| weak.upgrade().is_none()).count(),
        super::GRAPH_STRIDE,
        "one stride of files loses its last share (closes ride the commit)"
    );
    assert_eq!(
        engine
            .modules
            .iter()
            .filter(|module| module.scanned.view == Engine::CARRIED_VIEW_ID)
            .count(),
        1,
        "one carrier rides for the next tick"
    );
    let riding = engine
        .modules
        .iter()
        .find(|module| module.scanned.view == Engine::CARRIED_VIEW_ID)
        .expect("the riding carrier")
        .object;
    assert!(
        engine.pinned.summary(riding).is_some(),
        "the riding carrier keeps its pin"
    );
    assert!(
        engine.carried_rows_would_drop(),
        "the mirror stays off the fast path while a carrier rides droppable"
    );
    // Tick 2: the last retires, nothing resurrects.
    engine.plan_rebuild_stable = true;
    let tick2 = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick2.plan;
    engine.pinned = tick2.pinned;
    engine.modules = tick2.modules;
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test, CARRIERS as u64,
        "eventual full reclaim"
    );
    assert!(
        engine
            .modules
            .iter()
            .all(|module| module.scanned.view != Engine::CARRIED_VIEW_ID),
        "no carrier rides forever"
    );
    assert!(
        objects
            .iter()
            .all(|id| engine.pinned.summary(*id).is_none()),
        "no retired pin resurrects"
    );
    assert!(
        weaks.iter().all(|weak| weak.upgrade().is_none()),
        "every retired file loses its last share"
    );
}

#[test]
fn carried_fix4_rejected_carrier_reclaims_pin() {
    // F5 row-loss arms: a carrier that survives normalization but
    // loses its row to the rejection filter still reclaims its
    // carrier-only pin (reclamation reads the final surviving row
    // set, not the normalize-time set). A live claim on the same
    // path keeps the pin.
    let target = overlay_key(9799);
    // Main: the rejected carrier's pin reclaims.
    let (mut engine, object) = fix3_seed_carrier(974);
    for module in engine.modules.iter_mut() {
        if module.scanned.view == Engine::CARRIED_VIEW_ID {
            module.scanned.tables[0].entries[0].object = target;
        }
    }
    engine
        .pinned
        .reapply_rejected_keys(&BTreeSet::from([target]));
    // Absence stays unproven so normalization keeps the row and only
    // the rejection filter drops it; the full rebuild runs past the
    // keep-verdict fast path.
    engine.newcomer_first_seen.insert(424310, None);
    engine.set_disable_empty_tick_fast_path_for_test(true);
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    engine.plan_rebuild_stable = true;
    let tick = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick.plan;
    engine.pinned = tick.pinned;
    engine.modules = tick.modules;
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the rejected carrier row drops"
    );
    assert!(
        engine.pinned.summary(object).is_none(),
        "the rejected carrier's pin reclaims (post-filter retirement)"
    );
    // Shared control: a live claim keeps the pin on the same path.
    let (mut engine, object) = fix3_seed_carrier(975);
    for module in engine.modules.iter_mut() {
        if module.scanned.view == Engine::CARRIED_VIEW_ID {
            module.scanned.tables[0].entries[0].object = target;
        }
    }
    engine
        .pinned
        .reapply_rejected_keys(&BTreeSet::from([target]));
    engine.newcomer_first_seen.insert(424311, None);
    engine.set_disable_empty_tick_fast_path_for_test(true);
    let me = std::process::id();
    let id_c = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_c, me).unwrap());
    record_scan_ownership(&mut engine.pinned, id_c, overlay_key(975), OVERLAY_PATH);
    engine.plan_rebuild_stable = true;
    let tick = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick.plan;
    engine.pinned = tick.pinned;
    engine.modules = tick.modules;
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the rejected carrier row drops under the claim too"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "a live claim keeps the rejected carrier's pin"
    );
}

#[test]
fn carried_fix4_loader_rebuild_reclaims_rejected_carrier() {
    // F5 every builder: the loader assembly takes the same
    // post-filter retirement path as the inventory and replay
    // assemblies. A riding carrier rejected on a loader rebuild
    // (cache cold, so the full bind path runs) reclaims its
    // carrier-only pin.
    let target = overlay_key(9798);
    let (mut engine, object) = fix3_seed_carrier(978);
    for module in engine.modules.iter_mut() {
        if module.scanned.view == Engine::CARRIED_VIEW_ID {
            module.scanned.tables[0].entries[0].object = target;
        }
    }
    engine
        .pinned
        .reapply_rejected_keys(&BTreeSet::from([target]));
    let me = std::process::id();
    let id_s = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_s, me).unwrap());
    let loader_key = overlay_key(9797);
    let loader_module = overlay_module(loader_key);
    let loader_pins = overlay_view_pin(&loader_module, 8320, OVERLAY_SHA, 1, false);
    let local_loader = loader_pins
        .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        .expect("the loader pin resolves");
    assert!(
        engine.loader_plan_cache.is_none(),
        "the cold loader cache forces the full bind path"
    );
    let (candidate, loader) = engine
        .loader_candidate(id_s, &loader_module, &loader_pins, local_loader, Vec::new())
        .unwrap();
    assert!(loader.is_some(), "the exact loader pin survives");
    assert!(
        candidate.loader_plan_proof.is_none(),
        "the cold rebuild takes the full path (no cache-hit bypass)"
    );
    assert!(
        candidate
            .modules
            .iter()
            .all(|module| module.object != object),
        "the rejected carrier row drops on the loader path"
    );
    engine.plan = candidate.plan;
    engine.pinned = candidate.pinned;
    engine.modules = candidate.modules;
    assert!(
        engine.pinned.summary(object).is_none(),
        "the rejected carrier's pin reclaims on the loader path"
    );
}

#[test]
fn carried_fix4_bind_dropped_carrier_reclaims_pin() {
    // F5 row-loss arms: a carrier that survives normalization but
    // loses its row to strict binding still reclaims its
    // carrier-only pin. A live claim on the same path keeps the pin.
    // Main: the bind-dropped carrier's pin reclaims.
    let (mut engine, object) = fix3_seed_carrier(976);
    for module in engine.modules.iter_mut() {
        if module.scanned.view == Engine::CARRIED_VIEW_ID {
            module.scanned.decoder_abi = Some(p11scope_manifest::elf::ElfAbi::Ilp32);
        }
    }
    engine.newcomer_first_seen.insert(424312, None);
    engine.set_disable_empty_tick_fast_path_for_test(true);
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    engine.plan_rebuild_stable = true;
    let tick = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick.plan;
    engine.pinned = tick.pinned;
    engine.modules = tick.modules;
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the bind-dropped carrier row drops"
    );
    assert!(
        engine.pinned.summary(object).is_none(),
        "the bind-dropped carrier's pin reclaims (post-bind retirement)"
    );
    // Shared control: a live claim keeps the pin on the same path.
    let (mut engine, object) = fix3_seed_carrier(977);
    for module in engine.modules.iter_mut() {
        if module.scanned.view == Engine::CARRIED_VIEW_ID {
            module.scanned.decoder_abi = Some(p11scope_manifest::elf::ElfAbi::Ilp32);
        }
    }
    engine.newcomer_first_seen.insert(424313, None);
    engine.set_disable_empty_tick_fast_path_for_test(true);
    let me = std::process::id();
    let id_c = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_c, me).unwrap());
    record_scan_ownership(&mut engine.pinned, id_c, overlay_key(977), OVERLAY_PATH);
    engine.plan_rebuild_stable = true;
    let tick = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick.plan;
    engine.pinned = tick.pinned;
    engine.modules = tick.modules;
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the bind-dropped carrier row drops under the claim too"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "a live claim keeps the bind-dropped carrier's pin"
    );
}

#[test]
fn carried_fix4_loader_cache_hit_skips_held_rebuild() {
    // F3b flag: the loader-plan cache-hit candidate (the second
    // `true` builder beside the quiet-unchanged path) clones rows
    // unchanged: committing it skips the named/held rebuild with
    // exact sets.
    let fixture = super::LoaderPlanningFixture::new();
    let mut engine = fixture.engine();
    assert_eq!(
        engine.held_refresh_skipped_for_test, 0,
        "the warmup takes the full path"
    );
    let (candidate, _) = fixture.candidate(&mut engine, false);
    assert!(
        candidate.loader_plan_proof.is_some(),
        "the candidate takes the cache-hit branch"
    );
    assert!(
        candidate.modules_unchanged,
        "the cache-hit candidate clones rows unchanged"
    );
    assert_eq!(
        candidate.modules, engine.modules,
        "the clone carries the committed rows"
    );
    let named_before = engine.named_view_ids.clone();
    let held_before = engine.held_view_ids.clone();
    let outcome = super::apply_loader_planning_candidate(&mut engine, candidate);
    assert_eq!(
        outcome.disposition,
        ApplyDisposition::Accepted,
        "the cache-hit candidate commits"
    );
    assert_eq!(
        engine.held_refresh_skipped_for_test, 1,
        "the cache-hit commit skips the rebuild"
    );
    assert_eq!(
        engine.named_view_ids, named_before,
        "the named set stays exact without a rebuild"
    );
    assert_eq!(
        engine.held_view_ids, held_before,
        "the held set stays exact without a rebuild"
    );
}

#[test]
fn carried_fix4_coowner_clauses_keep_pins_independently() {
    // F5 clause-level guards: each co-owner clause keeps a rowless
    // carrier-only pin on its own — a selection claim through its
    // hook-owner leg alone, through its selected-object leg alone, a
    // selection table alone, a prearm watch alone (no witness), and
    // a raw alias alone (claims scrubbed). Each phase seeds a fresh
    // carrier, installs exactly one co-owner kind, then runs the
    // quiet detach that would otherwise reclaim.
    let me = std::process::id();
    let detach_quietly = |engine: &mut Engine| {
        let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
        engine.plan_rebuild_stable = true;
        let quiet = engine
            .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
            .unwrap();
        engine.plan = quiet.plan;
        engine.pinned = quiet.pinned;
        engine.modules = quiet.modules;
    };
    // Selection claim, hook-owner leg only.
    let (mut engine, object) = fix3_seed_carrier(981);
    let provider = engine
        .pinned
        .owned_timing_key(object)
        .expect("the carrier object has a timing key");
    let id_w = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_w, me).unwrap());
    engine.selection_claims.insert(
        SelectionClaimKey {
            binding_id: 424242,
            view: id_w,
            context: 0,
            hook_owner: object,
            provider: provider.clone(),
            selected_object: PinnedObjectId(999991),
            table_file_offset: 0,
            version: SelectionVersionClass::V3_0,
            flags: 0,
            name: "C_Initialize",
            file_offset: 0,
        },
        SelectionClaim {
            target: plan::AttachKey {
                object,
                file_offset: 0,
            },
            object_path: OVERLAY_PATH.into(),
        },
    );
    detach_quietly(&mut engine);
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the row still retires"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "a hook-owner-only selection claim keeps the pin"
    );
    // Selection claim, selected-object leg only.
    let (mut engine, object) = fix3_seed_carrier(982);
    let provider = engine
        .pinned
        .owned_timing_key(object)
        .expect("the carrier object has a timing key");
    let id_w = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_w, me).unwrap());
    engine.selection_claims.insert(
        SelectionClaimKey {
            binding_id: 424243,
            view: id_w,
            context: 0,
            hook_owner: PinnedObjectId(999992),
            provider,
            selected_object: object,
            table_file_offset: 0,
            version: SelectionVersionClass::V3_0,
            flags: 0,
            name: "C_Initialize",
            file_offset: 0,
        },
        SelectionClaim {
            target: plan::AttachKey {
                object,
                file_offset: 0,
            },
            object_path: OVERLAY_PATH.into(),
        },
    );
    detach_quietly(&mut engine);
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the row still retires"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "a selected-object-only selection claim keeps the pin"
    );
    // Selection table only (no claim, no binding).
    let (mut engine, object) = fix3_seed_carrier(983);
    let provider = engine
        .pinned
        .owned_timing_key(object)
        .expect("the carrier object has a timing key");
    let id_w = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_w, me).unwrap());
    engine.selection_tables.insert(
        SelectionTableKey {
            view: id_w,
            provider,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        },
        SelectionTableFact {
            object,
            file_offset: 0,
            targets: Vec::new(),
        },
    );
    detach_quietly(&mut engine);
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the row still retires"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "a selection-table-only reference keeps the pin"
    );
    // Prearm watch only (no witness).
    let (mut engine, object) = fix3_seed_carrier(984);
    engine.prearm.install_watch_for_test(
        object,
        crate::prearm_module::PrearmWatch::new(BTreeSet::new()),
    );
    detach_quietly(&mut engine);
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the row still retires"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "a prearm-watch-only reference keeps the pin"
    );
    // Raw alias only: ownership recorded, then claims scrubbed while
    // the alias stays (the post-scrub shape).
    let (mut engine, object) = fix3_seed_carrier(985);
    let key = overlay_key(985);
    let id_c = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine.views.push(ProcessView::open(id_c, me).unwrap());
    record_scan_ownership(&mut engine.pinned, id_c, key, OVERLAY_PATH);
    engine.pinned.drop_view_claims(id_c);
    detach_quietly(&mut engine);
    assert!(
        engine.modules.iter().all(|module| module.object != object),
        "the row still retires"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "a raw-alias-only reference keeps the pin"
    );
}

#[test]
fn carried_fix4_deferred_owned_child_skips_drain() {
    // The drain pops a deferred proof whose proving generation was
    // the owned child itself without consuming an attempt or staging
    // anything (its scan-owned slots persist, so its files need no
    // learning) — judged from the defer-time snapshot.
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 29,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let child_id = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine
        .views
        .push(ProcessView::open(child_id, me).expect("the owned child view opens"));
    let child_view = ProcessView::open(child_id, me).expect("the proving view opens");
    let key = overlay_key(9990);
    let mut module = super::owned_proof_module_without_tables(key);
    module.view = child_id;
    let pins = overlay_view_pin(&module, 8400, OVERLAY_SHA, 1, false);
    let object = pins
        .id_for_scanned(&module, module.key, &module.path)
        .expect("the fixture pin resolves");
    let proof = OwnedLearnProof {
        view: child_id,
        path: OVERLAY_PATH.into(),
        object,
        loader_exe: None,
        loader_unknown_reason: None,
        module,
    };
    engine.defer_owned_learn_proof(&proof, &child_view, &pins);
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the owned-child proof queues (the drain skips it, the queue does not judge)"
    );
    let mut scratch = PinnedObjects::empty();
    engine.learn_owned_proofs_with_views(&mut scratch, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain pops the direct-child proof"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 0,
        "the direct-child proof consumes no attempt"
    );
    assert!(
        engine.pending_learned.is_empty(),
        "the direct-child proof stages nothing"
    );
}

#[test]
fn carried_fix4_defer_without_proving_file_refuses_loudly() {
    // Deferral refuses a proof its source store cannot resolve (no
    // file to stash): counted loss plus a named gap, nothing queued.
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 30,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    let view = ProcessView::open(ProcessViewId(61), me).expect("own view opens");
    let key = overlay_key(9991);
    let mut module = super::owned_proof_module_without_tables(key);
    module.view = ProcessViewId(61);
    let pins = PinnedObjects::empty();
    let proof = OwnedLearnProof {
        view: ProcessViewId(61),
        path: OVERLAY_PATH.into(),
        object: PinnedObjectId(4242),
        loader_exe: None,
        loader_unknown_reason: None,
        module,
    };
    let loss_before = engine.learned_event_loss_for_test();
    engine.defer_owned_learn_proof(&proof, &view, &pins);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "nothing queues without a proving file"
    );
    assert_eq!(
        engine.learned_event_loss_for_test(),
        loss_before + 1,
        "the refusal carries counted loss"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("named no proving file")),
        "the refusal names the missing file: {:?}",
        engine.counters.object_skips,
    );
}

#[test]
fn carried_fix4_drain_without_proving_file_refuses_loudly() {
    // The drain refuses a queued entry whose stash holds no proving
    // file (hand-built here by wiping a real entry's stash; defer
    // refuses these first): counted loss plus a named gap, popped
    // without consuming an attempt. The prover is not the owned
    // child, so the direct-child skip cannot mask the refusal.
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 31,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(424242);
    engine.next_view_id = 100;
    let view = ProcessView::open(ProcessViewId(62), me).expect("own view opens");
    let key = overlay_key(9992);
    let mut module = super::owned_proof_module_without_tables(key);
    module.view = ProcessViewId(62);
    let pins = overlay_view_pin(&module, 8401, OVERLAY_SHA, 1, false);
    let object = pins
        .id_for_scanned(&module, module.key, &module.path)
        .expect("the fixture pin resolves");
    let proof = OwnedLearnProof {
        view: ProcessViewId(62),
        path: OVERLAY_PATH.into(),
        object,
        loader_exe: None,
        loader_unknown_reason: None,
        module,
    };
    engine.defer_owned_learn_proof(&proof, &view, &pins);
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the real proof queues"
    );
    engine.owned_learn_deferred[0].scan_pins = std::rc::Rc::new(PinnedObjects::empty());
    let loss_before = engine.learned_event_loss_for_test();
    let mut scratch = PinnedObjects::empty();
    engine.learn_owned_proofs_with_views(&mut scratch, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain pops the unresolvable entry"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 0,
        "no attempt is consumed"
    );
    assert_eq!(
        engine.learned_event_loss_for_test(),
        loss_before + 1,
        "the refusal carries counted loss"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("named no proving file")),
        "the refusal names the missing file: {:?}",
        engine.counters.object_skips,
    );
    assert!(
        engine.pending_learned.is_empty(),
        "nothing stages without a proving file"
    );
}

#[test]
fn carried_fix4_deferred_stage_without_file_refuses_loudly() {
    // Defense in depth: staging a deferred entry directly with no
    // proving file in its stash refuses loudly (the drain gates
    // this first; a direct caller still cannot stage or silence it).
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 33,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let view = ProcessView::open(ProcessViewId(63), me).expect("own view opens");
    let key = overlay_key(9996);
    let mut module = super::owned_proof_module_without_tables(key);
    module.view = ProcessViewId(63);
    let pins = overlay_view_pin(&module, 8402, OVERLAY_SHA, 1, false);
    let object = pins
        .id_for_scanned(&module, module.key, &module.path)
        .expect("the fixture pin resolves");
    let proof = OwnedLearnProof {
        view: ProcessViewId(63),
        path: OVERLAY_PATH.into(),
        object,
        loader_exe: None,
        loader_unknown_reason: None,
        module,
    };
    engine.defer_owned_learn_proof(&proof, &view, &pins);
    let mut entry = engine
        .owned_learn_deferred
        .pop_front()
        .expect("the real proof queues");
    entry.scan_pins = std::rc::Rc::new(PinnedObjects::empty());
    let key = super::owned_learn_key(&entry.scan_pins, &entry.proof);
    let loss_before = engine.learned_event_loss_for_test();
    let mut scratch = PinnedObjects::empty();
    engine.stage_deferred_owned_learn_proof(
        &mut scratch,
        &entry,
        None,
        Some(crate::fanotify::LOADER_EXE_UNREADABLE_REASON),
        key,
    );
    assert_eq!(
        engine.learned_event_loss_for_test(),
        loss_before + 1,
        "the refusal carries counted loss"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("named no proving file")),
        "the refusal names the missing file: {:?}",
        engine.counters.object_skips,
    );
    assert!(
        engine.pending_learned.is_empty(),
        "nothing stages without a proving file"
    );
}

#[test]
fn carried_fix4_watch_producer_builds_unnamed_shells() {
    // The factored watch construction: table/interface-bearing
    // modules resolving here build unnamed shells; modules with no
    // tables or interfaces, and unresolvable modules, build nothing.
    let key = overlay_key(9993);
    let view = ProcessViewId(70);
    let mut module = overlay_module(key);
    module.view = view;
    let pins = overlay_view_pin(&module, 8403, OVERLAY_SHA, 1, false);
    let shells = super::build_owned_learn_proofs(std::slice::from_ref(&module), &pins, view);
    assert_eq!(shells.len(), 1, "one eligible module builds one shell");
    assert!(
        shells[0].loader_exe.is_none() && shells[0].loader_unknown_reason.is_none(),
        "shells build unnamed"
    );
    assert_eq!(shells[0].view, view, "the shell names its proving view");
    assert_eq!(
        shells[0].path, module.path,
        "the shell carries the scanned spelling"
    );
    assert!(
        pins.file_for(shells[0].object).is_some(),
        "the shell resolves its file"
    );
    let mut empty = overlay_module(key);
    empty.view = view;
    empty.tables.clear();
    empty.interfaces.clear();
    let shells = super::build_owned_learn_proofs(std::slice::from_ref(&empty), &pins, view);
    assert!(
        shells.is_empty(),
        "a module with no tables or interfaces builds nothing"
    );
    let nopins = PinnedObjects::empty();
    let shells = super::build_owned_learn_proofs(std::slice::from_ref(&module), &nopins, view);
    assert!(shells.is_empty(), "an unresolvable module builds nothing");
}

#[test]
fn carried_fix4_watch_shells_name_under_credit() {
    // Shells from the factored construction name exactly once each
    // in the consumer (no producer naming): naming equals attempts.
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 32,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(424242);
    engine.next_view_id = 100;
    engine
        .views
        .push(ProcessView::open(ProcessViewId(0), me).expect("own view opens"));
    let mut modules = Vec::new();
    let mut pins = PinnedObjects::empty();
    for index in 0..3 {
        let key = overlay_key(9994 + index);
        let mut module = overlay_module(key);
        module.view = ProcessViewId(0);
        let mpins = overlay_view_pin(&module, 8410 + index, OVERLAY_SHA, 1, false);
        let skips = pins.absorb(mpins);
        assert!(skips.is_empty(), "{skips:?}");
        modules.push(module);
    }
    let shells = super::build_owned_learn_proofs(&modules, &pins, ProcessViewId(0));
    assert_eq!(shells.len(), 3, "three eligible modules build three shells");
    engine.learn_owned_proofs_with_views(&mut pins, &shells, &[], None);
    assert_eq!(
        engine.owned_learn_naming_for_test, 3,
        "every shell names exactly once, under credit"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 3,
        "every shell attempts exactly once"
    );
}

#[test]
fn carried_fix5_commit_keeps_deferred_harvest_aliases() {
    // hg-1 remap: a deferred proof's harvest aliases must land in the
    // committing target (which the commit installs), not just in the
    // committed set. Drain proof 65 into an empty target, install the
    // target the way a commit does, and the harvested tables must keep
    // their bindable pins; otherwise the commit wipes the absorb while
    // `run_learned_modules` retains unbindable tables.
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 34,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a watch member");
    let member = child.id();
    let watch_id = engine.allocate_view_id().unwrap();
    let watch_view = ProcessView::open(watch_id, member).expect("the member view opens");
    let mut pins = PinnedObjects::empty();
    let mut proofs = Vec::with_capacity(PROOFS);
    for index in 0..PROOFS {
        let key = overlay_key(9860 + index as u64);
        let mut module = overlay_module(key);
        module.view = watch_id;
        let mpins = overlay_view_pin(&module, 8300 + index as u64, OVERLAY_SHA, 1, false);
        let skips = pins.absorb(mpins);
        assert!(skips.is_empty(), "{skips:?}");
        let object = pins
            .id_for_scanned(&module, module.key, &module.path)
            .expect("the scan resolves its own module");
        if index + 1 < PROOFS {
            module.tables.clear();
            module.interfaces.clear();
            module.exports.clear();
        }
        proofs.push(OwnedLearnProof {
            view: watch_id,
            path: module.path.clone(),
            object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], Some(&watch_view));
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out proof queues with its pin"
    );
    child.kill().expect("the member exits");
    child.wait().expect("the member reaps");
    engine.pending_learned.clear();
    let mut scratch = PinnedObjects::empty();
    engine.learn_owned_proofs_with_views(&mut scratch, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain settles the backlog"
    );
    let harvested = &proofs[PROOFS - 1].module;
    assert!(
        engine
            .pinned
            .module_aliased_under(harvested, Engine::RUN_LEARNED_VIEW_ID),
        "control: the harvest aliases land in the committed set"
    );
    // The commit installs the draining target wholesale: the absorbed
    // proving pins must survive that install, not just the drain.
    engine.pinned = scratch;
    assert_eq!(
        engine.run_learned_modules.len(),
        1,
        "proof 65's tables union exactly once"
    );
    assert!(
        engine
            .pinned
            .module_aliased_under(harvested, Engine::RUN_LEARNED_VIEW_ID),
        "the installed target keeps the harvested tables' bindable pins"
    );
}

#[test]
fn carried_fix5_conflicting_target_refuses_harvest_tables() {
    // hg-1 conflict: when the draining target already maps the proof's
    // raw observation to a different physical file (same maps key and
    // path, different digest), the harvest must not alias the old
    // proof's tables against the target's different file. The tables
    // refuse loudly with a named gap (the file itself still stages, as
    // on the replaced-generation path), and nothing unions.
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 35,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(424242);
    engine.next_view_id = 100;
    let view_id = ProcessViewId(64);
    let view = ProcessView::open(view_id, me).expect("own view opens");
    let key = overlay_key(9993);
    let mut module = overlay_module(key);
    module.view = view_id;
    assert!(
        !module.tables.is_empty(),
        "the proof carries tables to harvest"
    );
    let sha_old = "aa".repeat(32);
    let sha_new = "bb".repeat(32);
    let source = overlay_view_pin(&module, 8403, &sha_old, 1, false);
    let object = source
        .id_for_scanned(&module, module.key, &module.path)
        .expect("the fixture pin resolves");
    let proof = OwnedLearnProof {
        view: view_id,
        path: OVERLAY_PATH.into(),
        object,
        loader_exe: None,
        loader_unknown_reason: None,
        module: module.clone(),
    };
    engine.defer_owned_learn_proof(&proof, &view, &source);
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the proof queues with its custody"
    );
    // The draining target maps the same raw observation to a different
    // generation's bytes: aliasing there would bind old tables to a
    // new file.
    let target = overlay_view_pin(&module, 8404, &sha_new, 1, false);
    let target_object = target
        .id_for_scanned(&module, module.key, &module.path)
        .expect("the target resolves the same raw");
    assert_eq!(
        target.summary(target_object).expect("target digest").sha256,
        sha_new,
        "control: the target really holds different bytes at the same raw"
    );
    assert_eq!(
        source.summary(object).expect("source digest").sha256,
        sha_old,
        "control: the stash really holds the old bytes"
    );
    let mut scratch_target = target;
    engine.learn_owned_proofs_with_views(&mut scratch_target, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain pops the conflicting entry"
    );
    assert!(
        !scratch_target.module_aliased_under(&module, Engine::RUN_LEARNED_VIEW_ID),
        "no alias files against the target's different file"
    );
    assert!(
        engine.run_learned_modules.is_empty(),
        "conflicting tables never union"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("conflict")),
        "the refusal names the identity conflict: {:?}",
        engine.counters.object_skips,
    );
    assert_eq!(
        engine.pending_learned.len(),
        1,
        "the proving file itself still stages (tables-only refusal)"
    );
    assert_eq!(
        engine.learned_event_loss_for_test(),
        0,
        "a tables-only refusal files a gap, not event loss (replaced-generation precedent)"
    );
}

#[test]
fn carried_fix5_newcomer_direct_child_stages_on_drain() {
    // hg-2 skip gate: the drain skips a deferred direct-child proof
    // only when the defer-time snapshot proves the prover retained
    // (its scan-owned slots persist, so its files need no learning).
    // A newcomer owned-child proof — paced out before its rows commit
    // — must stage under credit instead of vanishing silently when
    // its rows never commit.
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 36,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let child_id = engine.allocate_view_id_for_newcomer(me).unwrap();
    // Unlike the retained-child twin, the newcomer view never
    // commits: its rows may never exist.
    let child_view = ProcessView::open(child_id, me).expect("the proving view opens");
    let key = overlay_key(9995);
    let mut module = super::owned_proof_module_without_tables(key);
    module.view = child_id;
    let pins = overlay_view_pin(&module, 8405, OVERLAY_SHA, 1, false);
    let object = pins
        .id_for_scanned(&module, module.key, &module.path)
        .expect("the fixture pin resolves");
    let proof = OwnedLearnProof {
        view: child_id,
        path: OVERLAY_PATH.into(),
        object,
        loader_exe: None,
        loader_unknown_reason: None,
        module,
    };
    engine.defer_owned_learn_proof(&proof, &child_view, &pins);
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the newcomer proof queues"
    );
    assert!(
        engine.owned_learn_deferred[0].is_direct_child,
        "control: the pid snapshot marks the owned child"
    );
    assert!(
        !engine.owned_learn_deferred[0].proving_retained,
        "control: the retention snapshot marks the newcomer uncommitted"
    );
    let mut scratch = PinnedObjects::empty();
    engine.learn_owned_proofs_with_views(&mut scratch, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the drain pops the newcomer proof"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 1,
        "the uncommitted direct-child proof attempts under credit (never silently skipped)"
    );
    assert_eq!(
        engine.pending_learned.len(),
        1,
        "the uncommitted direct-child proof stages its file"
    );
}

#[test]
fn carried_fix5_newcomer_direct_child_stages_at_shutdown() {
    // hg-2 terminal: the capture-end drain stages a newcomer
    // owned-child proof too. Same shape as the shutdown twin (a real
    // provider .so through the end-of-capture flush), but the paced-out
    // prover is the owned child itself before its first commit.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    const PROOFS: usize = super::GRAPH_STRIDE + 1;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let c = dir.path().join("prompt.c");
    let so = dir.path().join(format!("libprov{}.so", PROOFS - 1));
    std::fs::write(
        &c,
        "unsigned long C_GetFunctionList(void **out){ (void)out; return 5; }\n",
    )
    .expect("write prompt source");
    assert!(
        std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&so)
            .arg(&c)
            .status()
            .expect("run gcc")
            .success(),
        "the prompt fixture must compile"
    );
    let mut pins = PinnedObjects::empty();
    for index in 0..PROOFS {
        let backing = dir.path().join(format!("libprov{index}.so"));
        if index + 1 < PROOFS {
            std::fs::write(&backing, format!("p11scope-fixture:provider-bytes-{index}"))
                .expect("write backing");
        }
        let sha = format!("{:064x}", 0xd80000u64 + index as u64);
        let skips = pins.absorb(real_scan_pin(&backing, None, 400, &sha));
        assert!(skips.is_empty(), "{skips:?}");
    }
    let objects: Vec<PinnedObjectId> = pins.pinned().map(|pin| pin.id).collect();
    assert_eq!(objects.len(), PROOFS, "every backing file pins distinctly");
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 37,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    // The owned child itself, scanned before its first commit: a
    // newcomer view the fresh loop does not skip (it is not retained).
    let watch_id = engine.allocate_view_id().unwrap();
    let watch_view = ProcessView::open(watch_id, me).expect("the owned-child view opens");
    let mut proofs = Vec::with_capacity(PROOFS);
    for (index, object) in objects.iter().enumerate() {
        let key = overlay_key(9980 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = watch_id;
        proofs.push(OwnedLearnProof {
            view: watch_id,
            path: dir
                .path()
                .join(format!("libprov{index}.so"))
                .to_string_lossy()
                .into_owned(),
            object: *object,
            loader_exe: None,
            loader_unknown_reason: None,
            module,
        });
    }
    engine.learn_owned_proofs_with_views(&mut pins, &proofs, &[], Some(&watch_view));
    assert_eq!(
        engine.owned_learn_deferred.len(),
        1,
        "the paced-out proof queues with its pin"
    );
    assert!(
        engine.owned_learn_deferred[0].is_direct_child,
        "control: the queued proof snapshots the owned child"
    );
    engine.pending_learned.clear();
    engine.shutdown_file_learning();
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "capture end settles the newcomer backlog"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test,
        (super::GRAPH_STRIDE + 1) as u64,
        "proof 65 attempts exactly once, at capture end"
    );
    assert_eq!(
        engine.learned_staged_files_for_test(),
        1,
        "proof 65's provider stages at capture end"
    );
}

#[test]
fn carried_fix5_backlog_skip_pops_pace_one_stride_per_apply() {
    // sr-sr F1 charging: every backlog pop consumes one stride unit —
    // the terminal skip arms (direct-child, unresolvable,
    // already-staged) included. Popping an entry drops its proving pin
    // and stashed files, so uncharged pops close fds outside INV-2.
    // A full 128-entry backlog of terminal entries (all three arms)
    // drains 64 per apply over two applies, attempts nothing, and the
    // popped files lose their last share exactly as popped.
    const CHILD: usize = 44;
    const UNRESOLVABLE: usize = 42;
    const STAGED: usize = 42;
    const TOTAL: usize = CHILD + UNRESOLVABLE + STAGED;
    assert_eq!(TOTAL, super::OWNED_LEARN_DEFERRED_CAP);
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 38,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    engine.next_view_id = 100;
    let child_id = engine.allocate_view_id_for_newcomer(me).unwrap();
    engine
        .views
        .push(ProcessView::open(child_id, me).expect("the owned child view opens"));
    let child_view = ProcessView::open(child_id, me).expect("the proving view opens");
    let mut member = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a descendant member");
    let descendant = member.id();
    let other_id = engine.allocate_view_id_for_newcomer(descendant).unwrap();
    let other_view = ProcessView::open(other_id, descendant).expect("the descendant view opens");
    // Retained direct-child entries: skipped AND charged.
    for index in 0..CHILD {
        let key = overlay_key(6000 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = child_id;
        let source = overlay_view_pin(&module, 6100 + index as u64, OVERLAY_SHA, 1, false);
        let object = source
            .id_for_scanned(&module, module.key, &module.path)
            .expect("the fixture pin resolves");
        engine.defer_owned_learn_proof(
            &OwnedLearnProof {
                view: child_id,
                path: OVERLAY_PATH.into(),
                object,
                loader_exe: None,
                loader_unknown_reason: None,
                module,
            },
            &child_view,
            &source,
        );
    }
    // Unresolvable entries: the stash holds a file, but the proof
    // names a dangling id (hand-built, like the wiped-stash twin), so
    // the drain refuses each with counted loss — and still charges.
    for index in 0..UNRESOLVABLE {
        let key = overlay_key(6200 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = other_id;
        let source = overlay_view_pin(&module, 6300 + index as u64, OVERLAY_SHA, 1, false);
        let object = source
            .id_for_scanned(&module, module.key, &module.path)
            .expect("the fixture pin resolves");
        engine.defer_owned_learn_proof(
            &OwnedLearnProof {
                view: other_id,
                path: OVERLAY_PATH.into(),
                object,
                loader_exe: None,
                loader_unknown_reason: None,
                module,
            },
            &other_view,
            &source,
        );
        engine
            .owned_learn_deferred
            .back_mut()
            .expect("just queued")
            .proof
            .object = PinnedObjectId(990000 + index as u32);
    }
    // Already-staged entries: terminal keys, table-less modules (no
    // harvest), still charged per pop.
    for index in 0..STAGED {
        let key = overlay_key(6400 + index as u64);
        let mut module = super::owned_proof_module_without_tables(key);
        module.view = other_id;
        let source = overlay_view_pin(&module, 6500 + index as u64, OVERLAY_SHA, 1, false);
        let object = source
            .id_for_scanned(&module, module.key, &module.path)
            .expect("the fixture pin resolves");
        engine.defer_owned_learn_proof(
            &OwnedLearnProof {
                view: other_id,
                path: OVERLAY_PATH.into(),
                object,
                loader_exe: None,
                loader_unknown_reason: None,
                module,
            },
            &other_view,
            &source,
        );
        let back = engine.owned_learn_deferred.back().expect("just queued");
        let staged_key = super::owned_learn_key(&back.scan_pins, &back.proof)
            .expect("the hashed fixture proofs key");
        engine.owned_learned_staged.insert(staged_key);
    }
    assert_eq!(
        engine.owned_learn_deferred.len(),
        TOTAL,
        "all three terminal arms queue to the cap"
    );
    // Weak shares of every stashed file (sources dropped above, so
    // each stash is the last share): pops must pace the closes.
    let weaks: Vec<std::sync::Weak<std::fs::File>> = engine
        .owned_learn_deferred
        .iter()
        .map(|entry| {
            // Unresolvable entries name a dangling id; their stash
            // file is the queue's only other object.
            let id = entry
                .scan_pins
                .file_for(entry.proof.object)
                .map(|_| entry.proof.object)
                .or_else(|| entry.scan_pins.pinned().next().map(|pin| pin.id))
                .expect("every stash holds its file");
            entry
                .scan_pins
                .weak_file_for_test(id)
                .expect("every stashed file shares")
        })
        .collect();
    assert_eq!(weaks.len(), TOTAL, "every entry stashes a distinct file");
    let mut scratch = PinnedObjects::empty();
    engine.learn_owned_proofs_with_views(&mut scratch, &[], &[], None);
    assert_eq!(
        engine.owned_learn_deferred.len(),
        TOTAL - super::GRAPH_STRIDE,
        "one apply pops exactly one stride of terminal entries"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 0,
        "terminal pops attempt nothing"
    );
    assert_eq!(
        weaks.iter().filter(|weak| weak.upgrade().is_none()).count(),
        super::GRAPH_STRIDE,
        "one stride of popped files loses its last share"
    );
    engine.learn_owned_proofs_with_views(&mut scratch, &[], &[], None);
    assert!(
        engine.owned_learn_deferred.is_empty(),
        "the second apply settles the remainder"
    );
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 0,
        "still no stage attempt after the full drain"
    );
    assert!(
        weaks.iter().all(|weak| weak.upgrade().is_none()),
        "every popped file loses its last share"
    );
    assert_eq!(
        engine.learned_event_loss_for_test(),
        UNRESOLVABLE as u64,
        "each unresolvable pop refuses loudly with counted loss"
    );
    assert!(
        engine.pending_learned.is_empty(),
        "terminal entries stage nothing"
    );
    member.kill().expect("the member exits");
    member.wait().expect("the member reaps");
}

/// Seeds 65 distinct-file carriers and exits their view, so all ride
/// as carriers (T11 shape). Returns the engine and the carried
/// objects; the caller applies its own row-loss arm.
fn fix5_seed_sixty_five_carriers() -> (Engine, BTreeSet<PinnedObjectId>) {
    const CARRIERS: usize = super::GRAPH_STRIDE + 1;
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    let id_v = engine.allocate_view_id_for_newcomer(me).unwrap();
    let view_v = ProcessView::open(id_v, me).unwrap();
    let mut modules = Vec::with_capacity(CARRIERS);
    let mut pins = PinnedObjects::empty();
    for index in 0..CARRIERS {
        let key = overlay_key(9130 + index as u64);
        let mut module = overlay_module(key);
        module.view = id_v;
        let mpins = overlay_view_pin(&module, 8100 + index as u64, OVERLAY_SHA, 1, false);
        let skips = pins.absorb(mpins);
        assert!(skips.is_empty(), "{skips:?}");
        record_scan_ownership(&mut pins, id_v, key, &module.path);
        pins.prove_scanned_entries_for_test(std::slice::from_ref(&module));
        modules.push(module);
    }
    let seed = engine
        .inventory_candidate(&empty, &[], &[(view_v, modules, pins)], Vec::new(), &empty)
        .unwrap();
    engine.plan = seed.plan;
    engine.pinned = seed.pinned;
    engine.modules = seed.modules;
    engine.views.push(ProcessView::open(id_v, me).unwrap());
    assert_eq!(engine.modules.len(), CARRIERS, "all carriers seed");
    let exited = engine
        .inventory_candidate(&BTreeSet::from([id_v]), &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = exited.plan;
    engine.pinned = exited.pinned;
    engine.modules = exited.modules;
    engine.views.retain(|view| view.id() != id_v);
    engine.release_view_id(id_v);
    assert_eq!(
        engine
            .modules
            .iter()
            .filter(|module| module.scanned.view == Engine::CARRIED_VIEW_ID)
            .count(),
        CARRIERS,
        "all carriers ride their exit tick"
    );
    let objects: BTreeSet<PinnedObjectId> =
        engine.modules.iter().map(|module| module.object).collect();
    assert_eq!(objects.len(), CARRIERS, "distinct files pin distinctly");
    (engine, objects)
}

#[test]
fn carried_fix5_rejected_carriers_pace_sixty_four_per_rebuild() {
    // hg-4/spark-F1 pacing: the rejection filter can drop every
    // carrier row in one rebuild, but pin reclaim still paces at one
    // stride per rebuild across all row-loss arms (not just
    // normalize). 65 rejected carriers reclaim 64 on the first
    // rebuild and the last on the next quiet rebuild — which must run
    // the full path (pending reclaim defeats the quiet fast path).
    const CARRIERS: usize = super::GRAPH_STRIDE + 1;
    let (mut engine, objects) = fix5_seed_sixty_five_carriers();
    // Distinct rejected entry keys per carrier (shared keys could
    // merge carriers before the filter runs).
    let mut targets = BTreeSet::new();
    for (index, module) in engine.modules.iter_mut().enumerate() {
        if module.scanned.view == Engine::CARRIED_VIEW_ID {
            let target = overlay_key(9700 + index as u64);
            module.scanned.tables[0].entries[0].object = target;
            targets.insert(target);
        }
    }
    assert_eq!(
        targets.len(),
        CARRIERS,
        "every carrier names its own reject"
    );
    engine.pinned.reapply_rejected_keys(&targets);
    // Absence stays unproven so normalization keeps every row and
    // only the rejection filter drops them.
    engine.newcomer_first_seen.insert(424310, None);
    engine.set_disable_empty_tick_fast_path_for_test(true);
    let weaks: Vec<std::sync::Weak<std::fs::File>> = objects
        .iter()
        .map(|id| {
            engine
                .pinned
                .weak_file_for_test(*id)
                .expect("every carrier file shares")
        })
        .collect();
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    engine.plan_rebuild_stable = true;
    let tick1 = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick1.plan;
    engine.pinned = tick1.pinned;
    engine.modules = tick1.modules;
    assert!(
        engine
            .modules
            .iter()
            .all(|module| !objects.contains(&module.object)),
        "the rejection filter drops every carrier row at once"
    );
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test,
        super::GRAPH_STRIDE as u64,
        "one rebuild reclaims one stride of rejected pins"
    );
    assert_eq!(
        weaks.iter().filter(|weak| weak.upgrade().is_none()).count(),
        super::GRAPH_STRIDE,
        "one stride of rejected files loses its last share"
    );
    assert_eq!(
        objects
            .iter()
            .filter(|id| engine.pinned.summary(**id).is_some())
            .count(),
        1,
        "one rejected pin rolls over to the next rebuild"
    );
    // The next quiet rebuild drains the rollover through the
    // ordinary fast-path gate (re-enabled here): pending reclaim
    // must defeat it, or the pin stalls forever.
    engine.set_disable_empty_tick_fast_path_for_test(false);
    engine.plan_rebuild_stable = true;
    let tick2 = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick2.plan;
    engine.pinned = tick2.pinned;
    engine.modules = tick2.modules;
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test, CARRIERS as u64,
        "eventual full reclaim of rejected pins"
    );
    assert!(
        objects
            .iter()
            .all(|id| engine.pinned.summary(*id).is_none()),
        "no rejected pin stalls past its rollover rebuild"
    );
    assert!(
        weaks.iter().all(|weak| weak.upgrade().is_none()),
        "every rejected file loses its last share"
    );
}

#[test]
fn carried_fix5_bind_dropped_carriers_pace_sixty_four_per_rebuild() {
    // hg-4/spark-F1 pacing, binding arm: carriers that survive
    // normalization but fail strict binding reclaim at the same
    // one-stride-per-rebuild pace with rollover.
    const CARRIERS: usize = super::GRAPH_STRIDE + 1;
    let (mut engine, objects) = fix5_seed_sixty_five_carriers();
    for module in engine.modules.iter_mut() {
        if module.scanned.view == Engine::CARRIED_VIEW_ID {
            module.scanned.decoder_abi = Some(p11scope_manifest::elf::ElfAbi::Ilp32);
        }
    }
    engine.newcomer_first_seen.insert(424312, None);
    engine.set_disable_empty_tick_fast_path_for_test(true);
    let weaks: Vec<std::sync::Weak<std::fs::File>> = objects
        .iter()
        .map(|id| {
            engine
                .pinned
                .weak_file_for_test(*id)
                .expect("every carrier file shares")
        })
        .collect();
    let empty: BTreeSet<ProcessViewId> = BTreeSet::new();
    engine.plan_rebuild_stable = true;
    let tick1 = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick1.plan;
    engine.pinned = tick1.pinned;
    engine.modules = tick1.modules;
    assert!(
        engine
            .modules
            .iter()
            .all(|module| !objects.contains(&module.object)),
        "strict binding drops every carrier row at once"
    );
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test,
        super::GRAPH_STRIDE as u64,
        "one rebuild reclaims one stride of bind-dropped pins"
    );
    assert_eq!(
        weaks.iter().filter(|weak| weak.upgrade().is_none()).count(),
        super::GRAPH_STRIDE,
        "one stride of bind-dropped files loses its last share"
    );
    engine.set_disable_empty_tick_fast_path_for_test(false);
    engine.plan_rebuild_stable = true;
    let tick2 = engine
        .inventory_candidate(&empty, &[], &[], Vec::new(), &empty)
        .unwrap();
    engine.plan = tick2.plan;
    engine.pinned = tick2.pinned;
    engine.modules = tick2.modules;
    assert_eq!(
        engine.carrier_pins_reclaimed_for_test, CARRIERS as u64,
        "eventual full reclaim of bind-dropped pins"
    );
    assert!(
        objects
            .iter()
            .all(|id| engine.pinned.summary(*id).is_none()),
        "no bind-dropped pin stalls past its rollover rebuild"
    );
    assert!(
        weaks.iter().all(|weak| weak.upgrade().is_none()),
        "every bind-dropped file loses its last share"
    );
}

#[test]
fn carried_fix5_unhashed_generations_never_skip_staging() {
    // spark-F2/sr-sr-F3 fail-closed: the already-staged set keys on
    // the proving digest, so an empty digest must bypass the set
    // (consult and record), never share one "" key. Two unhashed
    // generations at one locus (same mount namespace, maps key and
    // path after inode reuse) each attempt their file work; the
    // second never false-skips on the first's key.
    use crate::discovery::identity::test_fixture::real_scan_pin;
    let dir = tempfile::tempdir().expect("learned backing dir");
    let gen1 = dir.path().join("libgen.so.1");
    let gen2 = dir.path().join("libgen.so.2");
    std::fs::write(&gen1, "p11scope-fixture:generation-one-bytes").expect("write gen1");
    std::fs::write(&gen2, "p11scope-fixture:generation-two-bytes").expect("write gen2");
    // Same staged locus (mount namespace, maps key, path), different
    // files, both unhashed: the inode-reuse shape with no digest to
    // tell generations apart. The pins keep their own per-file maps
    // keys (the staged key reads the module's locus, not the pin's).
    let locus = overlay_key(9996);
    let mut store = real_scan_pin(&gen1, None, 400, "");
    let skips = store.absorb(real_scan_pin(&gen2, None, 400, ""));
    assert!(skips.is_empty(), "{skips:?}");
    let ids: Vec<PinnedObjectId> = store.pinned().map(|pin| pin.id).collect();
    assert_eq!(ids.len(), 2, "both generations pin distinctly");
    let me = std::process::id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 39,
        path: "/".into(),
        dir: Arc::new(File::open("/").expect("open root dir")),
    };
    engine.owned_run_pid = Some(me);
    let make_proof = |object: PinnedObjectId| {
        let mut module = super::owned_proof_module_without_tables(locus);
        module.view = ProcessViewId(0);
        module.path = "/locus/libgen.so".into();
        OwnedLearnProof {
            view: ProcessViewId(0),
            path: "/locus/libgen.so".into(),
            object,
            loader_exe: None,
            loader_unknown_reason: Some(crate::fanotify::LOADER_EXE_UNREADABLE_REASON),
            module,
        }
    };
    let proofs = vec![make_proof(ids[0]), make_proof(ids[1])];
    engine.learn_owned_proofs_with_views(&mut store, &proofs, &[], None);
    assert_eq!(
        engine.owned_learn_stage_attempts_for_test, 2,
        "both unhashed generations attempt (no false skip)"
    );
    assert_eq!(
        engine.owned_learn_file_probes_for_test, 2,
        "both unhashed generations reach their file"
    );
    assert_eq!(
        engine.pending_learned.len(),
        2,
        "both unhashed generations stage (distinct identities)"
    );
    assert!(
        engine
            .owned_learned_staged
            .iter()
            .all(|key| !key.0.is_empty()),
        "no empty-digest key is ever recorded"
    );
}

#[test]
fn carried_fix5_table_coverage_requires_version_and_walk() {
    // hg-6 conjuncts: table cover requires the same version and the
    // same walk, exactly like the offset arm. A version or walk
    // mismatch in either direction keeps the carrier; only an exact
    // match covers.
    let key = overlay_key(968);
    let carrier = fix3_two_table_module(key, Some(0));
    // Version mismatch either way: never covers.
    let mut live_newer = fix3_two_table_module(key, Some(0));
    live_newer.tables[0].version = (2, 41);
    assert!(
        !super::carrier_covered_by_live(&carrier, &[&live_newer]),
        "a live table at a different version never covers"
    );
    let mut carrier_newer = fix3_two_table_module(key, Some(0));
    carrier_newer.tables[0].version = (2, 41);
    let live_stock = fix3_two_table_module(key, Some(0));
    assert!(
        !super::carrier_covered_by_live(&carrier_newer, &[&live_stock]),
        "a carrier version the live table lacks never covers"
    );
    // Walk mismatch either way: never covers.
    let mut live_rescan = fix3_two_table_module(key, Some(0));
    live_rescan.tables[0].walk = "exports-only";
    assert!(
        !super::carrier_covered_by_live(&carrier, &[&live_rescan]),
        "a live table from a different walk never covers"
    );
    let mut carrier_rescan = fix3_two_table_module(key, Some(0));
    carrier_rescan.tables[0].walk = "exports-only";
    assert!(
        !super::carrier_covered_by_live(&carrier_rescan, &[&live_stock]),
        "a carrier walk the live table lacks never covers"
    );
    // Control: the exact table still covers.
    assert!(
        super::carrier_covered_by_live(&carrier, &[&live_stock]),
        "an identical table covers"
    );
}
