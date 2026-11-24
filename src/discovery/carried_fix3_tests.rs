//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! v072 carried-view-ids fix3: killing tests for the five blocking review
//! classes (absence-proof walk arm, table-specific interface coverage,
//! INV-2 charging, watch continuation, pin reclaim). Each test fails when
//! its guard is removed; see the lane report's site tables and sweep.

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
    let proof = OwnedLearnProof {
        view: ProcessViewId(60),
        path: OVERLAY_PATH.into(),
        object: PinnedObjectId(4242),
        loader_exe: None,
        loader_unknown_reason: None,
        module,
    };
    for _ in 0..super::OWNED_LEARN_DEFERRED_CAP {
        engine.defer_owned_learn_proof(&proof, &view);
    }
    assert_eq!(
        engine.owned_learn_deferred.len(),
        super::OWNED_LEARN_DEFERRED_CAP,
        "the backlog fills to its cap"
    );
    let skipped_before = engine.learned_cap_skipped();
    engine.defer_owned_learn_proof(&proof, &view);
    assert_eq!(
        engine.owned_learn_deferred.len(),
        super::OWNED_LEARN_DEFERRED_CAP,
        "past the cap nothing more queues"
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
